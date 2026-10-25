#include "session_controller.hpp"
#include "hexlab/workspace/project_analysis.hpp"
#include "project_testing.hpp"
namespace hexlab::desktop {
Result<bool> SessionController::request_graph(DocumentId id, std::optional<Location> selection, GraphKind kind,
                                              std::size_t call_depth) {
    auto project = manager_->project(id);
    if (!project)
        return Error{ErrorCode::invalid_argument, "The document is closed"};
    auto key = project_analysis_key(*project, project->analysis_options);
    if (!key)
        return key.error();
    auto old = graphs_.find(id.value);
    if (old != graphs_.end() && old->second.key == key.value() &&
        old->second.presentation == project->state->revisions.edit && old->second.kind == kind &&
        old->second.selection == selection && old->second.call_depth == call_depth)
        return false;
    // A location change inside the displayed function only changes selection.
    // This scans bounded displayed nodes and inspects extents, never decodes.
    if (old != graphs_.end() && old->second.kind == kind && old->second.call_depth == call_depth && old->second.cached &&
        project_graph_current(*project, *old->second.cached)) {
        bool contains = kind == GraphKind::image_calls;
        if (selection)
            for (auto &node : old->second.cached->model->nodes) {
                if (node.selection == selection) {
                    contains = true;
                    break;
                }
                auto address = std::get_if<Address>(&*selection);
                if (!address || !node.block || node.block->instructions.empty())
                    continue;
                auto &begin = node.block->begin;
                auto &last = node.block->instructions.back()->instruction;
                if (address->space == begin.space && address->offset >= begin.offset &&
                    (address->offset < last.address.offset || address->offset - last.address.offset < last.length)) {
                    contains = true;
                    break;
                }
            }
        if (contains) {
            old->second.selection = selection;
            old->second.pending = false;
            old->second.job.reset();
            old->second.reason.clear();
            return false;
        }
    }
    GraphJob request;
    request.key = key.value();
    request.presentation = project->state->revisions.edit;
    request.selection = selection;
    request.kind = kind;
    request.call_depth = call_depth;
    if (old != graphs_.end() && old->second.kind == kind && old->second.cached &&
        project_graph_current(*project, *old->second.cached))
        request.cached = old->second.cached;
    graphs_.insert_or_assign(id.value, std::move(request));
    return true;
}
std::shared_ptr<const ProjectGraph> SessionController::graph_result(DocumentId id) const {
    auto found = graphs_.find(id.value);
    return found == graphs_.end() ? nullptr : found->second.cached;
}
GraphKind SessionController::graph_kind(DocumentId id) const {
    auto found = graphs_.find(id.value);
    return found == graphs_.end() ? GraphKind::function_cfg : found->second.kind;
}
std::size_t SessionController::graph_call_depth(DocumentId id) const {
    auto found = graphs_.find(id.value);
    return found == graphs_.end() ? 1 : found->second.call_depth;
}
bool SessionController::graph_pending(DocumentId id) const {
    auto found = graphs_.find(id.value);
    return found != graphs_.end() && found->second.pending;
}
wxString SessionController::graph_reason(DocumentId id) const {
    auto found = graphs_.find(id.value);
    return found == graphs_.end() ? wxString{} : wxString::FromUTF8(found->second.reason);
}
bool SessionController::graph_busy(DocumentId id) const {
    auto found = graphs_.find(id.value);
    return found != graphs_.end() && found->second.job &&
           found->second.job->result.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready;
}
bool SessionController::poll_graph() {
    bool changed = false;
    for (auto it = graphs_.begin(); it != graphs_.end();) {
        DocumentId id{it->first};
        auto project = manager_->project(id);
        auto actor = manager_->actor(id);
        if (!project || !actor) {
            it = graphs_.erase(it);
            continue;
        }
        auto &request = it->second;
        auto key = project_analysis_key(*project, project->analysis_options);
        if (!key || key.value() != request.key || project->state->revisions.edit != request.presentation) {
            request.job.reset();
            request.cached.reset();
            request.pending = bool(key);
            if (key)
                request.key = key.value();
            request.presentation = project->state->revisions.edit;
            request.reason = "Graph source changed";
            ++it;
            changed = true;
            continue;
        }
        if (!request.pending) {
            ++it;
            continue;
        }
        if (!request.job) {
            if (project->status == DerivedStatus::pending || project->status == DerivedStatus::stale ||
                listing_busy(id) || search_pending(id)) {
                ++it;
                continue;
            }
            auto session = actor->view().session;
            auto source = request.key;
            auto kind = request.kind;
            auto call_depth = request.call_depth;
            auto selection = request.selection;
            auto submitted = pool_->submit(
                session, source, AnalysisPriority::normal,
                [project, session, source, kind, selection, call_depth](std::stop_token stop) -> Result<AnalysisPayload> {
                    workspace_testing::actor_checkpoint(
                        {session, workspace_testing::ActorPhase::graph_started, 0, source});
                    GraphOptions options;
                    options.call_depth = call_depth;
                    auto graph = make_project_graph(*project, kind, selection, options, stop);
                    if (!graph)
                        return graph.error();
                    workspace_testing::actor_checkpoint(
                        {session, workspace_testing::ActorPhase::graph_computed, 0, source});
                    return AnalysisPayload{std::make_shared<const ProjectGraph>(std::move(graph.value()))};
                },
                request.presentation, AnalysisWorkKind::read_only);
            if (!submitted) {
                if (submitted.error().code == ErrorCode::busy) {
                    ++it;
                    continue;
                }
                request.pending = false;
                request.reason = submitted.error().message;
                changed = true;
                ++it;
                continue;
            }
            request.job = std::move(submitted.value());
        }
        if (request.job->result.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
            ++it;
            continue;
        }
        auto completed = std::move(*request.job);
        request.job.reset();
        request.pending = false;
        changed = true;
        if (completed.ticket.session != actor->view().session || completed.ticket.source != request.key ||
            completed.ticket.presentation_revision != request.presentation) {
            request.cached.reset();
            request.reason = "Retired graph completion";
            ++it;
            continue;
        }
        auto &result = completed.result.get();
        if (!result) {
            request.cached.reset();
            request.reason = result.error().message;
            ++it;
            continue;
        }
        auto payload = std::get_if<std::shared_ptr<const ProjectGraph>>(&result.value());
        if (!payload || !*payload || !project_graph_current(*project, **payload)) {
            request.cached.reset();
            request.reason = "Retired graph geometry";
            ++it;
            continue;
        }
        request.cached = *payload;
        request.reason.clear();
        ++it;
    }
    return changed;
}
} // namespace hexlab::desktop
