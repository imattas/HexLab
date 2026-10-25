#pragma once
#include "graph_canvas.hpp"
#include <wx/choice.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <vector>
namespace hexlab::desktop {
class GraphView final : public wxPanel {
  public:
    explicit GraphView(wxWindow *);
    void update(const ProjectSnapshot *, std::optional<Location>, GraphKind, std::size_t call_depth,
                std::shared_ptr<const ProjectGraph>, bool, const wxString &);
    std::function<void(GraphKind, std::size_t)> kind_changed;
    GraphCanvas *canvas;

  private:
    wxChoice *kind_;
    wxChoice *call_depth_;
    wxStaticText *status_;
    wxStaticText *search_status_;
    wxTextCtrl *search_;
    std::optional<Sha256Digest> search_graph_key_;
    wxString search_query_;
    std::vector<GraphNodeId> search_matches_;
    std::size_t search_index_ = 0;
    wxString status_base_;
    void refresh_status();
    void find_node(int direction, bool restart);
};
} // namespace hexlab::desktop
