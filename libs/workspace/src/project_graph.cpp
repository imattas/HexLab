#include "hexlab/workspace/project_graph.hpp"
#include "hexlab/workspace/project_analysis.hpp"
#include "hexlab/workspace/navigation.hpp"
#include <algorithm>
namespace hexlab {
namespace {
bool usable(const ProjectSnapshot &project) {
    return project.state && project.functions && project.references && project.derived_key &&
           (project.status == DerivedStatus::fresh || project.status == DerivedStatus::incomplete);
}
std::optional<FunctionId> owner(const FunctionSnapshot &facts, Address at, std::stop_token stop) {
    for (auto &function : facts.functions) {
        if (stop.stop_requested())
            return {};
        if (function->entry == at)
            return function->id;
    }
    for (auto &block : facts.blocks) {
        if (stop.stop_requested())
            return {};
        if (block->owners.empty() || block->begin.space != at.space || block->begin.offset > at.offset)
            continue;
        for (auto &fact : block->instructions) {
            const auto &instruction = fact->instruction;
            if (instruction.address.space == at.space && instruction.address.offset <= at.offset &&
                at.offset - instruction.address.offset < instruction.length)
                return *std::min_element(block->owners.begin(), block->owners.end());
        }
    }
    return {};
}
} // namespace
bool project_graph_current(const ProjectSnapshot &project, const ProjectGraph &graph) {
    if (!usable(project) || !graph.model || !graph.layout)
        return false;
    auto source = project_analysis_key(project, project.analysis_options);
    return source && project.derived_key == source.value() && graph.model->source_key == source.value() &&
           graph.model->presentation_revision == project.state->revisions.edit &&
           graph.layout->model_key == graph.model->key;
}
Result<ProjectGraph> make_project_graph(const ProjectSnapshot &project, GraphKind kind,
                                        std::optional<Location> selection, const GraphOptions &options,
                                        std::stop_token stop) {
    try {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "Graph request canceled"};
        if (!usable(project))
            return Error{ErrorCode::conflict, "Wait for current graph facts"};
        auto source = project_analysis_key(project, project.analysis_options);
        if (!source)
            return source.error();
        if (project.derived_key != source.value() || project.functions->key != source.value() ||
            project.references->key() != source.value())
            return Error{ErrorCode::conflict, "Graph facts belong to another source revision"};
        std::optional<FunctionId> function;
        if (kind == GraphKind::function_cfg || kind == GraphKind::function_calls) {
            if (!selection || !std::holds_alternative<Address>(*selection))
                return Error{ErrorCode::invalid_argument, "Select a virtual address in a recovered function"};
            function = owner(*project.functions, std::get<Address>(*selection), stop);
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "Graph request canceled"};
            if (!function)
                return Error{ErrorCode::invalid_argument, "No recovered function owns this location"};
        }
        GraphLabels labels;
        if (project.loaded && project.loaded->image->layout().x86_profile)
            labels.location_formatter = [image = project.loaded->image](Location value) {
                return format_location(value, image.get());
            };
        labels.revision = project.state->revisions.edit;
        labels.overrides.reserve(project.state->user->annotations.size());
        for (auto &annotation : project.state->user->annotations) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "Graph request canceled"};
            labels.overrides.push_back({annotation.location, annotation.name, annotation.comment});
        }
        auto model = build_graph(*project.functions, *project.references, kind, function, options, labels, stop);
        if (!model)
            return model.error();
        auto layout = layout_graph(*model.value(), options, stop);
        if (!layout)
            return layout.error();
        return ProjectGraph{std::move(model.value()), std::move(layout.value())};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Insufficient memory for graph presentation"};
    }
}
} // namespace hexlab
