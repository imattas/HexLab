#pragma once
#include "graph_canvas.hpp"
#include <wx/choice.h>
#include <wx/button.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <wx/listctrl.h>
#include <vector>
namespace hexlab::desktop {
class GraphView final : public wxPanel {
  public:
    explicit GraphView(wxWindow *);
    void update(const ProjectSnapshot *, std::optional<Location>, GraphKind, std::size_t call_depth,
                std::shared_ptr<const ProjectGraph>, bool, const wxString &);
    std::function<void(GraphKind, std::size_t)> kind_changed;
    std::function<void(std::shared_ptr<const ProjectGraph>, Location, bool pseudocode)> show_source;
    GraphCanvas *canvas;

  private:
    wxChoice *kind_;
    wxChoice *call_depth_;
    wxStaticText *status_;
    wxButton *show_listing_, *show_pseudocode_;
    wxStaticText *search_status_;
    wxTextCtrl *search_;
    std::optional<Sha256Digest> search_graph_key_;
    wxString search_query_;
    std::vector<GraphNodeId> search_matches_;
    std::size_t search_index_ = 0;
    wxString status_base_;
    wxPanel *items_panel_;
    wxListCtrl *items_;
    wxTextCtrl *item_details_;
    std::shared_ptr<const ProjectGraph> items_graph_;
    std::vector<GraphHit> item_rows_;
    std::map<GraphHit, long> item_row_by_id_;
    std::set<GraphNodeId> items_selected_nodes_;
    std::optional<GraphHit> items_focus_;
    bool updating_items_ = false;
    void show_items();
    void refresh_items();
    void refresh_status();
    void find_node(int direction, bool restart);
};
} // namespace hexlab::desktop
