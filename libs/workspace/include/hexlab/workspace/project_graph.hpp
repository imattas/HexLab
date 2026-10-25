#pragma once
#include "hexlab/workspace/project.hpp"
#include "hexlab/analysis/graph.hpp"
namespace hexlab {
struct ProjectGraph {
    std::shared_ptr<const GraphModel> model;
    std::shared_ptr<const GraphLayout> layout;
};
// Immutable worker service. No SQL connection, window, or mutable session is used.
HEXLAB_WORKSPACE_EXPORT Result<ProjectGraph>
make_project_graph(const ProjectSnapshot &, GraphKind, std::optional<Location>, const GraphOptions &, std::stop_token);
HEXLAB_WORKSPACE_EXPORT bool project_graph_current(const ProjectSnapshot &, const ProjectGraph &);
} // namespace hexlab
