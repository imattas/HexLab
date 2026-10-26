#pragma once
#include "hexlab/workspace/project_graph.hpp"
#include <wx/panel.h>
#include <functional>
#include <map>
#include <set>
namespace hexlab::desktop {
using GraphHit = std::variant<GraphNodeId, GraphEdgeId>;
enum class GraphContextAction { rename, comment, bookmark };
class GraphCanvas final : public wxPanel {
  public:
    explicit GraphCanvas(wxWindow *);
    bool set_graph(std::shared_ptr<const ProjectGraph>);
    std::shared_ptr<const ProjectGraph> graph() const { return graph_; }
    wxPoint to_client(GraphPoint) const;
    GraphPoint to_model(wxPoint) const;
    std::optional<GraphHit> hit_test(wxPoint) const;
    std::size_t visible_nodes() const;
    wxString focus_description() const;
    bool focus_node(GraphNodeId, bool navigate_to_location = true);
    // Cycles the graph-local node focus and navigates linked views when the
    // focused node has a location. A rejected address leaves graph focus intact.
    bool move_node(bool next);
    void reveal_selection();
    void fit();
    void reset_layout();
    void pan_by(wxPoint);
    void zoom_by(double, wxPoint);
    void select(std::optional<Location>);
    std::size_t selected_node_count() const { return selected_nodes_.size(); }
    // Returns false when the source graph is stale or the destination was
    // rejected. Follow actions must not use the listing's prior selection.
    std::function<bool(Location)> navigate;
    std::function<void(Location, GraphContextAction)> context_action;
    std::function<bool(Location, GraphContextAction)> context_action_available;
    // Follow the exact graph instruction, independently of the asynchronously
    // rendered listing row. The receiver validates the captured graph source.
    std::function<void(std::shared_ptr<const ProjectGraph>, Address)> follow_instruction;
    std::function<void()> focus_changed;

  private:
    struct IndexedBounds { GraphRect bounds; std::size_t index = 0; };
    std::shared_ptr<const ProjectGraph> graph_;
    std::map<GraphNodeId, const GraphNode *> nodes_;
    std::map<GraphEdgeId, const GraphEdge *> edges_;
    std::map<GraphNodeId, std::vector<GraphEdgeId>> outgoing_edges_, incoming_edges_;
    std::map<GraphNodeId, std::size_t> position_by_node_;
    // Layouts remain immutable worker results. These copies hold view-local
    // user placements while a graph is open.
    std::vector<NodePlacement> placements_;
    std::vector<EdgeRoute> routes_;
    std::vector<IndexedBounds> positions_by_x_, routes_by_x_;
    std::vector<const GraphNode *> navigation_nodes_;
    std::vector<GraphNodeId> node_navigation_order_;
    std::optional<GraphHit> hit_;
    std::optional<Location> selection_;
    // Graph-local multi-selection is capped so large call graphs stay cheap
    // to paint and interact with. The linked listing still has one primary
    // location, matching the existing navigation contract.
    static constexpr std::size_t max_selected_nodes_ = 256;
    std::set<GraphNodeId> selected_nodes_;
    std::optional<GraphNodeId> selection_anchor_;
    bool edge_focus_incoming_ = false;
    double scale_ = 1;
    GraphPoint origin_{24, 24};
    bool dragging_ = false;
    bool node_dragging_ = false, node_drag_moved_ = false;
    std::optional<GraphNodeId> drag_node_;
    wxPoint node_drag_start_;
    GraphPoint node_drag_origin_;
    bool reveal_pending_ = false;
    wxPoint last_;
    bool visible(GraphRect) const;
    GraphRect viewport() const;
    std::vector<std::size_t> indexed_candidates(const std::vector<IndexedBounds> &, GraphRect) const;
    std::optional<std::size_t> instruction_index(const GraphNode &) const;
    struct InstructionRows {
        int y = 0, line = 0;
        std::size_t first = 0, count = 0;
    };
    InstructionRows instruction_rows(const GraphNode &, GraphRect) const;
    void move_instruction(bool next);
    void follow_focused_node();
    std::optional<GraphNodeId> focused_node() const;
    void move_graph(bool forward);
    void cycle_edges(bool next);
    void follow_edge(GraphEdgeId, bool forward);
    void reveal_node(GraphNodeId);
    void rebuild_geometry_indexes();
    wxString persisted_layout_key() const;
    void restore_persisted_layout();
    void persist_layout() const;
    void move_dragged_node(wxPoint);
    void select_node_range(GraphNodeId, bool extend, bool toggle);
    void activate(wxPoint, bool follow);
    void show_context_menu(wxPoint);
    void paint(wxPaintEvent &);
};
} // namespace hexlab::desktop
