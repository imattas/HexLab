#include "graph_view.hpp"
#include "data_views.hpp"
#include <wx/button.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/sizer.h>
#include "hexlab/loaders/loaded_image.hpp"
#include <algorithm>
#include <array>
namespace hexlab::desktop {
namespace {
constexpr std::array<std::size_t, 7> call_depth_values{1, 2, 3, 4, 8, 16, 32};
int call_depth_selection(std::size_t depth) {
    const auto found = std::lower_bound(call_depth_values.begin(), call_depth_values.end(), depth);
    if (found == call_depth_values.begin()) return 0;
    if (found == call_depth_values.end()) return static_cast<int>(call_depth_values.size() - 1);
    const auto upper = static_cast<std::size_t>(found - call_depth_values.begin());
    const auto lower = upper - 1;
    return static_cast<int>(depth - call_depth_values[lower] <= call_depth_values[upper] - depth
        ? lower : upper);
}
}
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
    for (const auto depth : call_depth_values)
        depths.Add(wxString::Format("Call depth %zu", depth));
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
    auto *graph_items = new wxButton(this, wxID_ANY, "Graph items");
    graph_items->SetName("graph-items-show");
    graph_items->SetToolTip("Show the accessible node and edge list. F6 moves between this list and the canvas.");
    bar->Add(graph_items, 0, wxALL, pad);
    copy_graph_json_ = new wxButton(this, wxID_ANY, "Copy graph JSON");
    copy_graph_json_->SetName("graph-copy-json");
    copy_graph_json_->SetToolTip("Copy the current graph model as bounded versioned JSON.");
    copy_graph_json_->Disable();
    bar->Add(copy_graph_json_, 0, wxALL, pad);
    canvas = new GraphCanvas(this);
    canvas->SetToolTip("Find searches graph node names, comments, and addresses. Click an instruction to select it. Up/Down: previous/next instruction; "
                       "Ctrl+Left/Right: select or follow predecessor/successor; Ctrl+Up/Down: cycle branch edges. "
                       "Ctrl-click toggles graph nodes; Shift-click selects a range (up to 256 nodes). "
                       "Enter or double click: follow target. Shift+Up/Down or Left/Right: pan. Home: fit. F6: graph items list.");
    items_panel_ = new wxPanel(this);
    auto *items_stack = new wxBoxSizer(wxVERTICAL);
    items_stack->Add(new wxStaticText(items_panel_, wxID_ANY,
        "Graph items: arrows select; Enter follows; F6 or Escape returns to canvas. Tab reaches item details and source actions."),
        0, wxALL, pad);
    items_stack->Add(new wxStaticText(items_panel_, wxID_ANY, "Graph nodes and edges"), 0, wxLEFT | wxRIGHT, pad);
    items_ = new wxListCtrl(items_panel_, wxID_ANY, wxDefaultPosition, wxSize(-1, FromDIP(130)),
                            wxLC_REPORT | wxLC_SINGLE_SEL);
    items_->SetName("graph-items");
    items_->InsertColumn(0, "Node or edge", wxLIST_FORMAT_LEFT, FromDIP(700));
    items_->InsertColumn(1, "Graph state", wxLIST_FORMAT_LEFT, FromDIP(180));
    items_stack->Add(items_, 1, wxEXPAND | wxLEFT | wxRIGHT, pad);
    items_stack->Add(new wxStaticText(items_panel_, wxID_ANY, "Focused graph item details"), 0, wxLEFT | wxRIGHT, pad);
    item_details_ = new wxTextCtrl(items_panel_, wxID_ANY, "No current graph", wxDefaultPosition,
                                  wxSize(-1, FromDIP(64)), wxTE_MULTILINE | wxTE_READONLY);
    item_details_->SetName("graph-item-details");
    items_stack->Add(item_details_, 0, wxEXPAND | wxALL, pad);
    items_panel_->SetSizer(items_stack);
    items_panel_->Hide();
    status_ = new wxStaticText(this, wxID_ANY, "Select a recovered function");
    status_->SetName("graph-status");
    auto *source_bar = new wxBoxSizer(wxHORIZONTAL);
    show_listing_ = new wxButton(this, wxID_ANY, "Show listing");
    show_listing_->SetName("graph-show-listing");
    show_listing_->Enable(false);
    show_listing_->SetToolTip("Open the listing at the selected graph source address without following its target.");
    show_pseudocode_ = new wxButton(this, wxID_ANY, "Show pseudocode");
    show_pseudocode_->SetName("graph-show-pseudocode");
    show_pseudocode_->Enable(false);
    show_pseudocode_->SetToolTip("Open pseudocode at the selected graph source address without following its target.");
    source_bar->Add(show_listing_, 0, wxALL, pad);
    source_bar->Add(show_pseudocode_, 0, wxALL, pad);
    source_bar->Add(status_, 1, wxALIGN_CENTER_VERTICAL | wxALL, pad);
    stack->Add(bar, 0, wxEXPAND);
    stack->Add(canvas, 1, wxEXPAND);
    stack->Add(items_panel_, 0, wxEXPAND);
    stack->Add(source_bar, 0, wxEXPAND);
    SetSizer(stack);
    canvas->focus_changed = [this] { refresh_status(); };
    canvas->focus_items = [this] { show_items(); };
    graph_items->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (!items_panel_->IsShown()) show_items();
        else {
            items_panel_->Hide();
            Layout();
            canvas->SetFocus();
        }
    });
    copy_graph_json_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_graph_json(); });
    items_->Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &event) {
        const auto row = event.GetIndex();
        if (!updating_items_ && row >= 0 && static_cast<std::size_t>(row) < item_rows_.size()) {
            const auto item = item_rows_[static_cast<std::size_t>(row)];
            (void)canvas->focus_item(item);
        }
    });
    items_->Bind(wxEVT_LIST_ITEM_ACTIVATED, [this](wxListEvent &) { canvas->activate_focused_item(); });
    items_panel_->Bind(wxEVT_CHAR_HOOK, [this](wxKeyEvent &event) {
        if (event.GetKeyCode() == WXK_F6 || event.GetKeyCode() == WXK_ESCAPE) canvas->SetFocus();
        else event.Skip();
    });
    const auto open_source = [this](bool pseudocode) {
        const auto location = canvas->source_location();
        if (location && show_source) show_source(canvas->graph(), *location, pseudocode);
    };
    show_listing_->Bind(wxEVT_BUTTON, [open_source](wxCommandEvent &) { open_source(false); });
    show_pseudocode_->Bind(wxEVT_BUTTON, [open_source](wxCommandEvent &) { open_source(true); });
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
                          call_depth_values[static_cast<std::size_t>(std::clamp(call_depth_->GetSelection(), 0,
                              static_cast<int>(call_depth_values.size() - 1)))]);
    });
    call_depth_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) {
        if (kind_changed && kind_->GetSelection() == 2)
            kind_changed(GraphKind::function_calls, call_depth_values[static_cast<std::size_t>(std::clamp(
                call_depth_->GetSelection(), 0, static_cast<int>(call_depth_values.size() - 1)))]);
    });
}
void GraphView::show_items() {
    items_panel_->Show();
    Layout();
    refresh_items();
    items_->SetFocus();
}
void GraphView::refresh_items() {
    // Defer native row creation until requested. The canvas can keep its
    // viewport and keyboard model, and background refreshes never steal focus.
    if (!items_panel_->IsShown()) return;
    updating_items_ = true;
    const auto graph = canvas->graph();
    const auto focus = canvas->focused_item();
    const std::set<GraphNodeId> empty_selection;
    const auto &selected = graph ? canvas->selected_node_ids() : empty_selection;
    if (items_graph_ != graph) {
        items_->Freeze();
        items_->DeleteAllItems();
        item_rows_.clear();
        item_row_by_id_.clear();
        items_focus_.reset();
        items_selected_nodes_.clear();
        items_graph_ = graph;
        const auto add = [this](GraphHit item) {
            auto description = canvas->item_description(item);
            description.Replace("\r", " ");
            description.Replace("\n", " ");
            const auto row = items_->InsertItem(items_->GetItemCount(), description);
            item_rows_.push_back(item);
            item_row_by_id_.emplace(item, row);
        };
        if (graph) {
            for (const auto &node : graph->model->nodes) add(GraphHit{node.id});
            for (const auto &edge : graph->model->edges) add(GraphHit{edge.id});
        }
        items_->Thaw();
    }
    const auto update_state = [&](GraphHit item) {
        const auto found = item_row_by_id_.find(item);
        if (found == item_row_by_id_.end()) return;
        const bool focused = focus && *focus == item;
        const auto *node = std::get_if<GraphNodeId>(&item);
        wxString state = focused ? "Focused" : "";
        if (node && selected.contains(*node)) state += state.empty() ? "Graph selected" : "; graph selected";
        items_->SetItem(found->second, 1, state);
        items_->SetItemState(found->second, focused ? wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED : 0,
                             wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
    };
    if (items_focus_) update_state(*items_focus_);
    for (const auto id : items_selected_nodes_)
        if (!selected.contains(id)) update_state(GraphHit{id});
    for (const auto id : selected)
        if (!items_selected_nodes_.contains(id)) update_state(GraphHit{id});
    if (focus) {
        update_state(*focus);
        if (const auto found = item_row_by_id_.find(*focus); found != item_row_by_id_.end())
            items_->EnsureVisible(found->second);
    }
    items_selected_nodes_ = selected;
    items_focus_ = focus;
    auto details = status_base_.empty() ? wxString("No current graph") : status_base_;
    if (focus) details += "\n" + canvas->item_description(*focus);
    if (const auto location = canvas->source_location()) details += "\nSelected source: " + location_text(*location);
    details += wxString::Format("\n%zu graph nodes selected", selected.size());
    if (item_details_->GetValue() != details) item_details_->ChangeValue(details);
    updating_items_ = false;
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
    const auto location = canvas->source_location();
    show_listing_->Enable(location.has_value());
    show_pseudocode_->Enable(location && std::holds_alternative<Address>(*location));
    if (location) label += "; source " + location_text(*location);
    status_->SetLabel(label);
    refresh_items();
}
void GraphView::copy_graph_json() {
    const auto graph = canvas->graph();
    if (!graph || !graph->model) {
        status_->SetLabel("No current graph to copy.");
        return;
    }
    auto exported = graph->layout
        ? export_graph_json(*graph->model, *graph->layout)
        : export_graph_json(*graph->model);
    if (!exported) {
        status_->SetLabel("Graph JSON export failed: " + wxString::FromUTF8(exported.error().message));
        return;
    }
    constexpr std::size_t clipboard_limit = 4 * 1024 * 1024;
    if (exported.value().size() > clipboard_limit) {
        status_->SetLabel("Graph JSON exceeds the 4 MiB clipboard limit; reduce graph scope and copy again.");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        status_->SetLabel("The system clipboard is unavailable.");
        return;
    }
    const auto byte_count = exported.value().size();
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(
        wxString::FromUTF8(exported.value().data(), exported.value().size())));
    wxTheClipboard->Close();
    status_->SetLabel(copied
        ? wxString::Format("Copied %llu bytes of graph JSON.", static_cast<unsigned long long>(byte_count))
        : wxString("Could not copy graph JSON to the clipboard."));
}
void GraphView::update(const ProjectSnapshot *project, std::optional<Location> selection, GraphKind kind,
                       std::size_t call_depth,
                       std::shared_ptr<const ProjectGraph> graph, bool pending, const wxString &reason) {
    kind_->SetSelection(kind == GraphKind::function_cfg ? 0 : kind == GraphKind::image_calls ? 1 : 2);
    call_depth_->SetSelection(call_depth_selection(std::clamp<std::size_t>(call_depth, 1, 32)));
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
    copy_graph_json_->Enable(graph && graph->model);
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
