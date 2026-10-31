#pragma once
#include "hexlab/analysis/references.hpp"
#include <functional>
namespace hexlab {
struct GraphNodeId {std::uint64_t value=0;auto operator<=>(const GraphNodeId&)const=default;};
struct GraphEdgeId {std::uint64_t value=0;auto operator<=>(const GraphEdgeId&)const=default;};
enum class GraphKind {function_cfg,image_calls,function_calls};
enum class GraphNodeKind {block,function,external,unresolved,boundary};
enum class GraphEdgeKind {fallthrough,conditional_true,conditional_false,jump,call,tail_candidate,call_continuation,unresolved,delay_slot,conditional_call};
struct GraphOptions {
    std::size_t node_budget=1000,edge_budget=10000,preview_lines=16;
    // Function call neighborhoods expand callers and callees by this many
    // resolved function-to-function hops, bounded to 32. Image-wide call
    // graphs ignore it.
    std::size_t call_depth=1;
    double node_width=280,line_height=18,rank_gap=100,node_gap=40,edge_gap=16;
};
struct GraphLabelOverride {Location location;std::string name,comment;};
struct GraphLabels {
    std::uint64_t revision=0;
    std::vector<GraphLabelOverride> overrides;
    // Optional worker-side formatting of ordinary block/function locations.
    // Explicit user names still win; unresolved and external labels retain their kind.
    std::function<std::string(Location)> location_formatter;
};
struct GraphNode {
    GraphNodeId id;GraphNodeKind kind=GraphNodeKind::boundary;std::string label,comment;
    double width=280,height=60;std::size_t preview_lines=16,omitted_comment_bytes=0;
    std::optional<Location> selection;std::optional<ExternalIdentity> external;
    std::shared_ptr<const BasicBlock> block;std::shared_ptr<const FunctionRecord> function;
};
struct GraphEdge {
    GraphEdgeId id;GraphNodeId source,target;GraphEdgeKind kind=GraphEdgeKind::fallthrough;
    std::optional<ReferenceId> reference;std::optional<Location> selection,target_location;bool boundary=false;
};
struct GraphModel {
    GraphKind kind=GraphKind::function_cfg;std::optional<FunctionId> function;
    std::vector<GraphNode> nodes;std::vector<GraphEdge> edges;
    bool complete=true;std::uint64_t omitted_nodes=0,omitted_edges=0,presentation_revision=0;
    std::optional<AnalysisKey> source_key;Sha256Digest key{};
};
struct GraphPoint {double x=0,y=0;bool operator==(const GraphPoint&)const=default;};
struct GraphRect {double x=0,y=0,width=0,height=0;bool operator==(const GraphRect&)const=default;};
struct NodePlacement {GraphNodeId node;GraphRect bounds;bool operator==(const NodePlacement&)const=default;};
struct EdgeRoute {GraphEdgeId edge;std::vector<GraphPoint> points;bool operator==(const EdgeRoute&)const=default;};
struct GraphLayout {
    std::vector<NodePlacement> positions;std::vector<EdgeRoute> routes;
    std::vector<std::vector<GraphNodeId>> components;GraphRect bounds;
    Sha256Digest model_key{},key{};
};
HEXLAB_ANALYSIS_EXPORT Result<std::shared_ptr<const GraphModel>> build_graph(const FunctionSnapshot&,const ReferenceIndex&,GraphKind,std::optional<FunctionId>,const GraphOptions&,const GraphLabels&,std::stop_token);
HEXLAB_ANALYSIS_EXPORT Result<std::shared_ptr<const GraphLayout>> layout_graph(const GraphModel&,const GraphOptions&,std::stop_token);
HEXLAB_ANALYSIS_EXPORT Result<std::string> export_graph_json(const GraphModel&,std::stop_token={});
HEXLAB_ANALYSIS_EXPORT Result<std::string> export_graph_json(const GraphModel&,const GraphLayout&,std::stop_token={});
HEXLAB_ANALYSIS_EXPORT Result<std::string> export_graph_dot(const GraphModel&,std::stop_token={});
}
