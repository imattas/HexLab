#include "call_site_browser.hpp"
#include "project_view.hpp"
#include "hexlab/types/types.hpp"
#include <wx/button.h>
#include <wx/choice.h>
#include <wx/dialog.h>
#include <wx/listctrl.h>
#include <wx/msgdlg.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <algorithm>
#include <array>
#include <map>
#include <limits>
#include <iterator>
#include <tuple>

namespace hexlab::desktop {
namespace {
bool contains(const FunctionRecord &function, Address address) {
    if (function.entry == address) return true;
    return std::any_of(function.chunks.begin(), function.chunks.end(), [&](const auto &chunk) {
        return chunk.begin.space == address.space && address.offset >= chunk.begin.offset &&
               address.offset - chunk.begin.offset < chunk.size;
    });
}
wxString named_address(const ProjectSnapshot &project, Address address) {
    auto name = preview_text(presentation_name(project, Location{address}), 180);
    const auto location = location_text(address);
    return name.empty() ? location : name + " (" + location + ")";
}
wxString prototype(const ProjectSnapshot &project, std::optional<Address> address) {
    const auto *assignment = address ? type_assignment(project, *address) : nullptr;
    const auto *definition = assignment ? type_definition(project, assignment->type_id) : nullptr;
    return definition && definition->type
        ? preview_text(definition->name, 180) + ": " + preview_text(types::format(*definition->type), 512)
        : wxString("No assigned prototype");
}
} // namespace

std::optional<CallSiteNavigation> browse_call_sites(
    wxWindow *parent, std::shared_ptr<const ProjectSnapshot> project, Address selection,
    std::optional<Address> function_entry) {
    if (!project || !project->loaded || !project->loaded->image || !project->functions ||
        !project->derived_key || project->functions->key != project->derived_key ||
        (project->status != DerivedStatus::fresh && project->status != DerivedStatus::incomplete)) {
        wxMessageBox("Call inspection requires current function analysis.", "Inspect calls", wxOK, parent);
        return {};
    }
    // Keep the UI bounded on hostile or unusually large snapshots. A limit is
    // always disclosed; an incomplete index cannot establish unique ownership.
    constexpr std::size_t function_limit = 100000, chunk_limit = 262144, call_scan_limit = 1000000, row_limit = 4096;
    if (project->functions->functions.size() > function_limit) {
        wxMessageBox("Call inspection is limited to snapshots with 100,000 functions.", "Inspect calls", wxOK, parent);
        return {};
    }
    std::map<std::uint64_t, const FunctionRecord *> functions;
    const FunctionRecord *selected_function = nullptr;
    bool ambiguous = false;
    std::size_t chunks = 0;
    for (const auto &candidate : project->functions->functions) {
        if (!candidate) continue;
        if (candidate->chunks.size() > chunk_limit - chunks) {
            wxMessageBox("Call inspection is limited to snapshots with 262,144 function chunks.", "Inspect calls", wxOK, parent);
            return {};
        }
        chunks += candidate->chunks.size();
        functions.emplace(candidate->id.value, candidate.get());
        const bool match = function_entry ? candidate->entry == *function_entry : contains(*candidate, selection);
        if (!match) continue;
        if (selected_function) ambiguous = true;
        selected_function = candidate.get();
    }
    if (!selected_function || ambiguous || (function_entry && !contains(*selected_function, selection))) {
        wxMessageBox(ambiguous ? "The selection has multiple function owners. Open a specific function in the decompiler first."
                               : "Select an instruction in a recovered function first.",
                     "Inspect calls", wxOK, parent);
        return {};
    }
    // Merge the selected function's ranges once instead of checking every
    // chunk for each incoming call. Use inclusive ends to retain UINT64_MAX.
    using RangeKey = std::pair<std::uint32_t, std::uint64_t>;
    std::map<RangeKey, std::uint64_t> target_ranges;
    for (const auto &chunk : selected_function->chunks) {
        if (!chunk.size) continue;
        const auto last = chunk.begin.offset + std::min(chunk.size - 1,
            std::numeric_limits<std::uint64_t>::max() - chunk.begin.offset);
        auto [found, inserted] = target_ranges.emplace(RangeKey{chunk.begin.space.value, chunk.begin.offset}, last);
        if (!inserted) found->second = std::max(found->second, last);
    }
    for (auto it = target_ranges.begin(); it != target_ranges.end();) {
        auto next = std::next(it);
        if (next != target_ranges.end() && next->first.first == it->first.first && next->first.second <= it->second) {
            it->second = std::max(it->second, next->second);
            target_ranges.erase(next);
        } else it = next;
    }
    const auto targets_function = [&](Address address) {
        if (address == selected_function->entry) return true;
        auto after = target_ranges.upper_bound({address.space.value, address.offset});
        if (after == target_ranges.begin()) return false;
        const auto &range = *std::prev(after);
        return range.first.first == address.space.value && address.offset <= range.second;
    };
    struct Row {
        Address source;
        std::optional<Address> caller, target, callee;
        wxString direction, kind, caller_name, target_name, signature;
    };
    std::vector<Row> rows;
    bool limited = false;
    const auto count = std::min(call_scan_limit, project->functions->calls.size());
    for (std::size_t index = 0; index < count; ++index) {
        const auto &call = project->functions->calls[index];
        const bool outgoing = call.owner == selected_function->id;
        const bool incoming = call.callee == selected_function->id ||
            (call.target && targets_function(*call.target));
        if (!outgoing && !incoming) continue;
        if (rows.size() == row_limit) { limited = true; break; }
        Row row{call.source, {}, call.target, {}, outgoing ? "Outgoing" : "Incoming",
                call.tail_candidate ? "Tail candidate" : "Call", {}, {}, {}};
        if (outgoing && incoming) row.direction = "Recursive";
        if (const auto owner = functions.find(call.owner.value); owner != functions.end()) row.caller = owner->second->entry;
        if (call.callee)
            if (const auto callee = functions.find(call.callee->value); callee != functions.end()) row.callee = callee->second->entry;
        if (!row.target) row.target = row.callee;
        row.caller_name = row.caller ? named_address(*project, *row.caller) : wxString("Unknown owner");
        if (call.external_target) {
            const auto &external = *call.external_target;
            row.target_name = preview_text(external.library, 160) + "!" +
                (external.name ? preview_text(*external.name, 160)
                               : wxString::Format("#%u", external.ordinal.value_or(0)));
            if (external.wasm_function_index)
                row.target_name += wxString::Format(" [wasm function %u]", *external.wasm_function_index);
            row.kind += " / external";
        } else row.target_name = row.target ? named_address(*project, *row.target) : wxString("Unresolved indirect target");
        row.signature = prototype(*project, row.callee ? row.callee : row.target);
        rows.push_back(std::move(row));
    }
    limited = limited || count < project->functions->calls.size();
    std::stable_sort(rows.begin(), rows.end(), [](const Row &a, const Row &b) {
        return std::tie(a.source.space.value, a.source.offset, a.direction) <
               std::tie(b.source.space.value, b.source.offset, b.direction);
    });

    wxDialog dialog(parent, wxID_ANY, "Calls: " + named_address(*project, selected_function->entry),
                    wxDefaultPosition, parent->FromDIP(wxSize(1080, 640)), wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);
    dialog.SetName("call-site-browser");
    auto *layout = new wxBoxSizer(wxVERTICAL);
    auto *controls = new wxBoxSizer(wxHORIZONTAL);
    auto *direction = new wxChoice(&dialog, wxID_ANY);
    direction->Append("All call sites"); direction->Append("Outgoing calls"); direction->Append("Incoming calls");
    direction->SetSelection(0);
    direction->SetName("call-site-direction");
    auto *filter = new wxTextCtrl(&dialog, wxID_ANY);
    filter->SetName("call-site-filter");
    filter->SetHint("Filter caller, target, address, or assigned prototype");
    filter->SetMaxLength(256);
    controls->Add(direction, 0, wxRIGHT, dialog.FromDIP(8));
    controls->Add(filter, 1, wxEXPAND);
    layout->Add(controls, 0, wxEXPAND | wxALL, dialog.FromDIP(8));
    auto *table = new wxListCtrl(&dialog, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                               wxLC_REPORT | wxLC_SINGLE_SEL | wxLC_HRULES);
    table->SetName("call-site-results");
    const char *columns[] = {"Direction", "Call instruction", "Caller", "Target", "Kind", "Assigned prototype"};
    const int widths[] = {90, 150, 210, 230, 140, 230};
    for (int column = 0; column < 6; ++column)
        table->InsertColumn(column, columns[column], wxLIST_FORMAT_LEFT, dialog.FromDIP(widths[column]));
    layout->Add(table, 1, wxEXPAND | wxLEFT | wxRIGHT, dialog.FromDIP(8));
    auto *detail = new wxTextCtrl(&dialog, wxID_ANY, {}, wxDefaultPosition, dialog.FromDIP(wxSize(-1, 100)),
                                  wxTE_MULTILINE | wxTE_READONLY);
    detail->SetName("call-site-detail");
    layout->Add(detail, 0, wxEXPAND | wxALL, dialog.FromDIP(8));
    auto *status = new wxStaticText(&dialog, wxID_ANY, {});
    layout->Add(status, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, dialog.FromDIP(8));
    auto *actions = new wxBoxSizer(wxHORIZONTAL);
    auto *target_actions = new wxBoxSizer(wxHORIZONTAL);
    auto *listing = new wxButton(&dialog, wxID_ANY, "Call listing");
    auto *graph = new wxButton(&dialog, wxID_ANY, "Caller CFG");
    auto *caller_code = new wxButton(&dialog, wxID_ANY, "Caller pseudocode");
    auto *callee_code = new wxButton(&dialog, wxID_ANY, "Callee pseudocode");
    auto *references = new wxButton(&dialog, wxID_ANY, "Target xrefs");
    auto *evidence = new wxButton(&dialog, wxID_ANY, "Call evidence");
    auto *types = new wxButton(&dialog, wxID_ANY, "Target prototype");
    const std::array<wxButton *, 7> buttons{listing, graph, caller_code, evidence, callee_code, references, types};
    const char *names[] = {"call-site-listing", "call-site-cfg", "call-site-caller-pseudocode", "call-site-evidence",
                           "call-site-callee-pseudocode", "call-site-xrefs", "call-site-prototype"};
    for (std::size_t i = 0; i < buttons.size(); ++i) {
        buttons[i]->SetName(names[i]);
        (i < 4 ? actions : target_actions)->Add(buttons[i], 0, wxRIGHT, dialog.FromDIP(4));
    }
    target_actions->AddStretchSpacer();
    target_actions->Add(new wxButton(&dialog, wxID_CANCEL, "Close"));
    layout->Add(actions, 0, wxEXPAND | wxALL, dialog.FromDIP(8));
    layout->Add(target_actions, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, dialog.FromDIP(8));
    dialog.SetSizer(layout);
    dialog.SetMinSize(dialog.FromDIP(wxSize(900, 420)));
    std::vector<std::size_t> visible;
    bool rebuilding = false;
    const auto selected = [&]() -> const Row * {
        const auto row = table->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        return row >= 0 && static_cast<std::size_t>(row) < visible.size() ? &rows[visible[row]] : nullptr;
    };
    const auto update_actions = [&] {
        const auto *row = selected();
        listing->Enable(row != nullptr);
        evidence->Enable(row != nullptr);
        graph->Enable(row && row->caller.has_value());
        caller_code->Enable(row && row->caller.has_value());
        callee_code->Enable(row && row->callee.has_value());
        references->Enable(row && row->target.has_value());
        types->Enable(row && row->target.has_value());
        detail->ChangeValue(row ? "Call instruction: " + location_text(row->source) + "\nCaller: " + row->caller_name +
            "\nTarget: " + row->target_name + "\n" + row->signature +
            (!row->callee ? "\nNo recovered callee body. Inspect the call instruction and its outgoing references for evidence." : "")
            : wxString("No matching call site. This browser uses recovered function call facts; it does not infer targets from pseudocode text."));
    };
    const auto reload = [&] {
        rebuilding = true;
        const auto *previous = selected();
        table->Freeze(); table->DeleteAllItems(); visible.clear();
        const auto query = filter->GetValue().Lower();
        long reveal = -1;
        for (std::size_t index = 0; index < rows.size(); ++index) {
            const auto &row = rows[index];
            const auto scope = direction->GetSelection();
            if ((scope == 1 && row.direction == "Incoming") || (scope == 2 && row.direction == "Outgoing")) continue;
            const auto address = location_text(row.source);
            if (!query.empty() && (address + " " + row.caller_name + " " + row.target_name + " " + row.signature).Lower().Find(query) == wxNOT_FOUND) continue;
            const auto item = table->InsertItem(table->GetItemCount(), row.direction);
            table->SetItem(item, 1, address); table->SetItem(item, 2, row.caller_name);
            table->SetItem(item, 3, row.target_name); table->SetItem(item, 4, row.kind); table->SetItem(item, 5, row.signature);
            visible.push_back(index);
            if (&row == previous || (!previous && row.source == selection && reveal < 0)) reveal = item;
        }
        if (reveal < 0 && !visible.empty()) reveal = 0;
        if (reveal >= 0) {
            table->SetItemState(reveal, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED,
                                wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
            table->EnsureVisible(reveal);
        }
        table->Thaw(); rebuilding = false;
        status->SetLabel(wxString::Format("%zu visible / %zu call sites", visible.size(), rows.size()) +
            (limited ? " - limit reached (1,000,000 calls scanned / 4,096 rows); some calls are omitted." : "") +
            (project->status == DerivedStatus::incomplete || !project->functions->complete ? " - analysis is incomplete." : ""));
        update_actions();
    };
    std::optional<CallSiteNavigation> result;
    const auto choose = [&](CallSiteDestination destination, bool target) {
        const auto *row = selected();
        if (!row) return;
        auto address = target ? (destination == CallSiteDestination::pseudocode || destination == CallSiteDestination::prototype
                                  ? (row->callee ? row->callee : row->target) : row->target)
                              : std::optional<Address>{row->source};
        if (!address) return;
        result = CallSiteNavigation{*address, destination};
        dialog.EndModal(wxID_OK);
    };
    listing->Bind(wxEVT_BUTTON, [&](wxCommandEvent &) { choose(CallSiteDestination::listing, false); });
    graph->Bind(wxEVT_BUTTON, [&](wxCommandEvent &) { choose(CallSiteDestination::graph, false); });
    caller_code->Bind(wxEVT_BUTTON, [&](wxCommandEvent &) { choose(CallSiteDestination::pseudocode, false); });
    callee_code->Bind(wxEVT_BUTTON, [&](wxCommandEvent &) { choose(CallSiteDestination::pseudocode, true); });
    references->Bind(wxEVT_BUTTON, [&](wxCommandEvent &) { choose(CallSiteDestination::references, true); });
    evidence->Bind(wxEVT_BUTTON, [&](wxCommandEvent &) { choose(CallSiteDestination::call_evidence, false); });
    types->Bind(wxEVT_BUTTON, [&](wxCommandEvent &) { choose(CallSiteDestination::prototype, true); });
    table->Bind(wxEVT_LIST_ITEM_ACTIVATED, [&](wxListEvent &) { choose(CallSiteDestination::listing, false); });
    table->Bind(wxEVT_LIST_ITEM_SELECTED, [&](wxListEvent &) { if (!rebuilding) update_actions(); });
    table->Bind(wxEVT_LIST_ITEM_DESELECTED, [&](wxListEvent &) { if (!rebuilding) update_actions(); });
    filter->Bind(wxEVT_TEXT, [&](wxCommandEvent &) { reload(); });
    direction->Bind(wxEVT_CHOICE, [&](wxCommandEvent &) { reload(); });
    reload(); table->SetFocus();
    dialog.ShowModal();
    return result;
}
} // namespace hexlab::desktop
