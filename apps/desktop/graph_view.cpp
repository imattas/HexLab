#include "graph_view.hpp"
#include "data_views.hpp"
#include <wx/button.h>
#include <wx/sizer.h>
#include "hexlab/loaders/loaded_image.hpp"
#include <algorithm>
namespace hexlab::desktop {
GraphView::GraphView(wxWindow *parent) : wxPanel(parent) {
    SetName("graph-view");
    const int pad = FromDIP(4);
    auto *stack = new wxBoxSizer(wxVERTICAL);
    auto *bar = new wxBoxSizer(wxHORIZONTAL);
    wxArrayString choices;
    choices.Add("Function control flow");
    choices.Add("Image calls");
    choices.Add("Function callers and callees");
    kind_ = new wxChoice(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, choices);
    kind_->SetName("graph-kind");
    kind_->SetSelection(0);
    bar->Add(kind_, 0, wxALL, pad);
    wxArrayString depths;
    depths.Add("Call depth 1");
    depths.Add("Call depth 2");
    depths.Add("Call depth 3");
    call_depth_ = new wxChoice(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, depths);
    call_depth_->SetName("graph-call-depth");
    call_depth_->SetSelection(0);
    call_depth_->SetToolTip("Expand the selected function's caller and callee neighborhood.");
    bar->Add(call_depth_, 0, wxALL, pad);
    search_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
    search_->SetName("graph-node-search");
    search_->SetHint("Find node by name, comment, or address");
    bar->Add(search_, 1, wxALIGN_CENTER_VERTICAL | wxALL, pad);
    auto *find = new wxButton(this, wxID_ANY, "Find");
    find->SetName("graph-node-find");
    auto *find_previous = new wxButton(this, wxID_ANY, "Previous");
    find_previous->SetName("graph-node-find-previous");
    auto *find_next = new wxButton(this, wxID_ANY, "Next");
    find_next->SetName("graph-node-find-next");
    bar->Add(find, 0, wxALL, pad);
    bar->Add(find_previous, 0, wxALL, pad);
    bar->Add(find_next, 0, wxALL, pad);
    auto *previous_node = new wxButton(this, wxID_ANY, "Prev node");
    previous_node->SetName("graph-node-previous");
    previous_node->SetToolTip("Focus the previous graph node and navigate linked views when it has an address.");
    auto *next_node = new wxButton(this, wxID_ANY, "Next node");
    next_node->SetName("graph-node-next");
    next_node->SetToolTip("Focus the next graph node and navigate linked views when it has an address.");
    bar->Add(previous_node, 0, wxALL, pad);
    bar->Add(next_node, 0, wxALL, pad);
    search_status_ = new wxStaticText(this, wxID_ANY, "");
    search_status_->SetName("graph-node-search-status");
    bar->Add(search_status_, 0, wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT, pad);
    auto *fit = new wxButton(this, wxID_ANY, "Fit");
    fit->SetName("graph-fit");
    bar->Add(fit, 0, wxALL, pad);
    auto *reset_layout = new wxButton(this, wxID_ANY, "Reset layout");
    reset_layout->SetName("graph-layout-reset");
    reset_layout->SetToolTip("Discard saved node positions and restore the automatic graph layout.");
    bar->Add(reset_layout, 0, wxALL, pad);
    auto *zoom_in = new wxButton(this, wxID_ANY, "+");
    auto *zoom_out = new wxButton(this, wxID_ANY, "-");
    zoom_in->SetName("graph-zoom-in");
    zoom_out->SetName("graph-zoom-out");
    zoom_in->SetToolTip("Zoom in on the graph.");
    zoom_out->SetToolTip("Zoom out on the graph.");
    bar->Add(zoom_in, 0, wxALL, pad);
    bar->Add(zoom_out, 0, wxALL, pad);
    canvas = new GraphCanvas(this);
    canvas->SetToolTip("Find searches graph node names, comments, and addresses. Click an instruction to select it. Up/Down: previous/next instruction; "
                       "Ctrl+Left/Right: select or follow predecessor/successor; Ctrl+Up/Down: cycle branch edges. "
                       "Ctrl-click toggles graph nodes; Shift-click selects a range (up to 256 nodes). "
                       "Enter or double click: follow target. Shift+Up/Down or Left/Right: pan. Home: fit.");
    status_ = new wxStaticText(this, wxID_ANY, "Select a recovered function");
    status_->SetName("graph-status");
    stack->Add(bar, 0, wxEXPAND);
    stack->Add(canvas, 1, wxEXPAND);
    stack->Add(status_, 0, wxALL, pad);
    SetSizer(stack);
    canvas->focus_changed = [this] { refresh_status(); };
    find->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { find_node(1, true); });
    find_previous->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { find_node(-1, false); });
    find_next->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { find_node(1, false); });
    previous_node->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { (void)canvas->move_node(false); });
    next_node->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { (void)canvas->move_node(true); });
    search_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent &) { find_node(1, true); });
    fit->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { canvas->fit(); });
    reset_layout->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { canvas->reset_layout(); });
    zoom_in->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        auto s = canvas->GetClientSize();
        canvas->zoom_by(1.2, {s.x / 2, s.y / 2});
    });
    zoom_out->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        auto s = canvas->GetClientSize();
        canvas->zoom_by(1. / 1.2, {s.x / 2, s.y / 2});
    });
    kind_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) {
        if (kind_changed)
            kind_changed(kind_->GetSelection() == 0 ? GraphKind::function_cfg
                          : kind_->GetSelection() == 1 ? GraphKind::image_calls : GraphKind::function_calls,
                          static_cast<std::size_t>(call_depth_->GetSelection() + 1));
    });
    call_depth_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) {
        if (kind_changed && kind_->GetSelection() == 2)
            kind_changed(GraphKind::function_calls, static_cast<std::size_t>(call_depth_->GetSelection() + 1));
    });
}
void GraphView::find_node(int direction, bool restart) {
    const auto graph = canvas->graph();
    auto query = search_->GetValue().Lower().Trim(true).Trim(false);
    if (query.empty()) {
        search_status_->SetLabel("Enter a search term");
        return;
    }
    if (!graph || !graph->model) {
        search_status_->SetLabel("No current graph");
        return;
    }
    const auto changed = restart || query != search_query_ || !search_graph_key_ ||
                         *search_graph_key_ != graph->model->key;
    if (changed) {
        search_matches_.clear();
        for (const auto &node : graph->model->nodes) {
            wxString searchable = wxString::FromUTF8(node.label);
            searchable += " ";
            searchable += wxString::FromUTF8(node.comment);
            if (node.selection) {
                searchable += " ";
                searchable += location_text(*node.selection);
            }
            if (searchable.Lower().Find(query) != wxNOT_FOUND)
                search_matches_.push_back(node.id);
        }
        search_query_ = query;
        search_graph_key_ = graph->model->key;
        search_index_ = direction < 0 && !search_matches_.empty() ? search_matches_.size() - 1 : 0;
    } else if (!search_matches_.empty()) {
        search_index_ = (search_index_ + search_matches_.size() + (direction < 0 ? search_matches_.size() - 1 : 1)) %
                        search_matches_.size();
    }
    if (search_matches_.empty()) {
        search_status_->SetLabel("No matching graph nodes");
        return;
    }
    search_status_->SetLabel(wxString::Format("%zu/%zu", search_index_ + 1, search_matches_.size()));
    canvas->focus_node(search_matches_[search_index_]);
}
void GraphView::refresh_status() {
    auto label = status_base_;
    const auto focus = canvas->focus_description();
    if (!focus.empty()) {
        if (!label.empty()) label += "; ";
        label += focus;
    }
    if (canvas->selected_node_count() > 1)
        label += wxString::Format("; %zu graph nodes selected", canvas->selected_node_count());
    status_->SetLabel(label);
}
void GraphView::update(const ProjectSnapshot *project, std::optional<Location> selection, GraphKind kind,
                       std::size_t call_depth,
                       std::shared_ptr<const ProjectGraph> graph, bool pending, const wxString &reason) {
    kind_->SetSelection(kind == GraphKind::function_cfg ? 0 : kind == GraphKind::image_calls ? 1 : 2);
    call_depth_->SetSelection(static_cast<int>(std::clamp<std::size_t>(call_depth, 1, 3) - 1));
    kind_->Enable(project != nullptr);
    call_depth_->Enable(project != nullptr && kind == GraphKind::function_calls);
    if (!project || (graph && !project_graph_current(*project, *graph)))
        graph.reset();
    const auto next_search_key = graph ? std::optional<Sha256Digest>{graph->model->key} : std::nullopt;
    if (search_graph_key_ != next_search_key) {
        search_graph_key_.reset();
        search_matches_.clear();
        search_status_->SetLabel("");
    }
    canvas->set_graph(graph);
    if (selection && std::holds_alternative<FileOffset>(*selection) && project && project->loaded && project->loaded->image) {
        const auto address = project->loaded->image->to_address(std::get<FileOffset>(*selection));
        if (address) selection = address.value();
    }
    canvas->select(selection);
    wxString label = pending ? wxString("Building graph...") : reason;
    if (!pending && graph) {
        label = (reason.empty() ? wxString{} : reason + "; ") +
                wxString::Format("%zu nodes, %zu edges", graph->model->nodes.size(), graph->model->edges.size());
        if (!graph->model->complete)
            label += "; partial topology";
    }
    if (label.empty())
        label = "Select a recovered function";
    status_base_ = label;
    refresh_status();
}
} // namespace hexlab::desktop
