#include "function_browser.hpp"
#include "data_views.hpp"
#include "project_view.hpp"
#include <wx/button.h>
#include <wx/choice.h>
#include <wx/dialog.h>
#include <wx/msgdlg.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <algorithm>
#include <array>
#include <map>
#include <tuple>

namespace hexlab::desktop {
namespace {
wxString stop_name(FunctionStopReason reason) {
    switch (reason) {
    case FunctionStopReason::ret: return "return";
    case FunctionStopReason::trap: return "trap";
    case FunctionStopReason::unsupported: return "unsupported instruction";
    case FunctionStopReason::invalid: return "invalid instruction";
    case FunctionStopReason::truncated: return "truncated bytes";
    case FunctionStopReason::unmapped: return "unmapped address";
    case FunctionStopReason::uninitialized: return "uninitialized bytes";
    case FunctionStopReason::non_executable: return "non-executable bytes";
    case FunctionStopReason::manual_data: return "manual data";
    case FunctionStopReason::overlap: return "overlap";
    case FunctionStopReason::indirect: return "unresolved indirect flow";
    case FunctionStopReason::budget: return "analysis budget";
    case FunctionStopReason::target_overflow: return "target overflow";
    case FunctionStopReason::chunk_boundary: return "chunk boundary";
    case FunctionStopReason::tail_candidate: return "tail candidate";
    case FunctionStopReason::elf_relocation: return "ELF relocation";
    case FunctionStopReason::macho_relocation: return "Mach-O relocation";
    case FunctionStopReason::macho_dyld: return "Mach-O dyld";
    case FunctionStopReason::image_exclusion: return "image exclusion";
    }
    return "stop";
}
struct Row {
    std::shared_ptr<const FunctionRecord> function;
    wxString name, search;
    std::size_t outgoing = 0, unresolved = 0;
};
struct Evidence { Address address; wxString kind, detail; };
}

std::optional<FunctionNavigation> browse_functions(
    wxWindow *parent, std::shared_ptr<const ProjectSnapshot> project, std::optional<Address> selection) {
    if (!project || !project->loaded || !project->loaded->image || !project->functions ||
        !project->derived_key || project->functions->key != project->derived_key ||
        (project->status != DerivedStatus::fresh && project->status != DerivedStatus::incomplete)) return {};
    // Refuse an oversized index rather than presenting incomplete call counts as exact.
    constexpr std::size_t function_limit = 50000, call_limit = 1000000, evidence_limit = 4096;
    const auto snapshot = project->functions;
    if (snapshot->functions.size() > function_limit || snapshot->calls.size() > call_limit) {
        wxMessageBox("Function Workbench supports at most 50,000 functions and 1,000,000 recovered calls. "
                     "Use the docked Functions filter for larger snapshots.", "Function Workbench", wxOK, parent);
        return {};
    }
    std::map<std::uint64_t, std::pair<std::size_t, std::size_t>> call_counts;
    for (const auto &call : snapshot->calls) {
        auto &counts = call_counts[call.owner.value];
        ++counts.first;
        if (!call.target && !call.external_target) ++counts.second;
    }
    std::vector<Row> rows;
    rows.reserve(snapshot->functions.size());
    std::size_t name_characters = 0;
    constexpr std::size_t name_character_limit = 8 * 1024 * 1024;
    for (const auto &function : snapshot->functions) {
        if (!function) continue;
        Row row;
        row.function = function;
        row.name = preview_text(presentation_name(*project, function->entry), 2048);
        if (row.name.empty()) row.name = "(unnamed)";
        if (row.name.length() > name_character_limit - name_characters) {
            wxMessageBox("Function names exceed the workbench's 8 Mi character index limit. "
                         "Use the docked Functions filter for this snapshot.", "Function Workbench", wxOK, parent);
            return {};
        }
        name_characters += row.name.length();
        // Bound searchable names separately from display strings.
        row.search = row.name.Left(2048).Lower() + " " + location_text(function->entry).Lower();
        const auto counts = call_counts.find(function->id.value);
        if (counts != call_counts.end()) std::tie(row.outgoing, row.unresolved) = counts->second;
        rows.push_back(std::move(row));
    }
    wxDialog dialog(parent, wxID_ANY, "Function Workbench", wxDefaultPosition, wxDefaultSize,
                    wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);
    dialog.SetName("function-workbench");
    auto *layout = new wxBoxSizer(wxVERTICAL);
    auto *filters = new wxBoxSizer(wxHORIZONTAL);
    auto *query = new wxTextCtrl(&dialog, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
    query->SetName("function-workbench-query");
    query->SetHint("Filter by function name or address"); query->SetMaxLength(2048);
    auto *scope = new wxChoice(&dialog, wxID_ANY);
    for (auto label : {"All functions", "Partial functions", "Complete functions", "Thunks", "Unresolved calls"})
        scope->Append(label);
    scope->SetSelection(0); scope->SetName("function-workbench-scope");
    filters->Add(query, 1, wxRIGHT, 8); filters->Add(scope, 0);
    layout->Add(filters, 0, wxEXPAND | wxALL, 8);
    auto *status = new wxStaticText(&dialog, wxID_ANY, {});
    layout->Add(status, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);
    auto *table = new VirtualTable(&dialog, "function-workbench-functions",
        {"Entry", "Name", "Blocks", "Chunks", "Calls", "Unresolved", "State"});
    table->SetColumnWidth(0, dialog.FromDIP(145)); table->SetColumnWidth(1, dialog.FromDIP(260));
    layout->Add(table, 2, wxEXPAND | wxLEFT | wxRIGHT, 8);
    auto *detail = new wxTextCtrl(&dialog, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize,
                                  wxTE_READONLY | wxTE_MULTILINE);
    detail->SetName("function-workbench-summary");
    detail->SetMinSize(dialog.FromDIP(wxSize(-1, 70)));
    layout->Add(detail, 0, wxEXPAND | wxALL, 8);
    layout->Add(new wxStaticText(&dialog, wxID_ANY,
        "Chunks and recovery stops: select evidence to open its address; function actions use the entry."),
        0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);
    auto *evidence = new VirtualTable(&dialog, "function-workbench-evidence", {"Address", "Kind", "Evidence"});
    evidence->SetColumnWidth(0, dialog.FromDIP(145)); evidence->SetColumnWidth(1, dialog.FromDIP(190));
    evidence->SetColumnWidth(2, dialog.FromDIP(520));
    layout->Add(evidence, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);
    auto *actions = new wxBoxSizer(wxHORIZONTAL);
    std::array<wxButton *, 6> buttons{};
    const std::array<const char *, 6> labels{"Open listing", "Function graph", "Pseudocode", "Incoming refs", "Inspect calls", "Open evidence"};
    for (std::size_t i = 0; i < labels.size(); ++i) {
        buttons[i] = new wxButton(&dialog, wxID_ANY, labels[i]);
        actions->Add(buttons[i], 0, wxRIGHT, 4); buttons[i]->Enable(false);
    }
    layout->Add(actions, 0, wxALL, 8);
    layout->Add(dialog.CreateButtonSizer(wxCANCEL), 0, wxALIGN_RIGHT | wxLEFT | wxRIGHT | wxBOTTOM, 8);
    dialog.SetSizer(layout); dialog.SetMinSize(dialog.FromDIP(wxSize(900, 600)));
    dialog.SetSize(dialog.FromDIP(wxSize(1080, 780))); dialog.CentreOnParent();
    std::vector<std::size_t> visible;
    std::vector<Evidence> evidence_rows;
    std::optional<Address> selected_entry;
    // Prefer an exact entry. Otherwise preselect only a uniquely owned cursor
    // range; shared chunks never silently choose an arbitrary function owner.
    if (selection) {
        for (const auto &row : rows)
            if (row.function->entry == *selection) { selected_entry = *selection; break; }
        if (!selected_entry) {
            std::size_t chunks_examined = 0;
            bool ambiguous = false, capped = false;
            for (const auto &row : rows) {
                bool owns = false;
                for (const auto &chunk : row.function->chunks) {
                    if (++chunks_examined > 262144) { capped = true; break; }
                    if (chunk.begin.space == selection->space && selection->offset >= chunk.begin.offset &&
                        selection->offset - chunk.begin.offset < chunk.size) owns = true;
                }
                if (capped) break;
                if (owns) {
                    if (selected_entry) { ambiguous = true; break; }
                    selected_entry = row.function->entry;
                }
            }
            if (ambiguous || capped) selected_entry.reset();
        }
    }
    int sort_column = 0;
    bool ascending = true;
    std::optional<FunctionNavigation> result;
    const auto selected_row = [&]() -> const Row * {
        const auto index = table->selected_row();
        return index && *index < visible.size() ? &rows[visible[*index]] : nullptr;
    };
    const auto update_detail = [&] {
        evidence_rows.clear();
        const auto *row = selected_row();
        for (auto *button : buttons) button->Enable(row != nullptr);
        buttons[5]->Enable(false);
        if (!row) { detail->ChangeValue("Select a function to inspect its recovery evidence."); }
        else {
            const auto &function = *row->function;
            selected_entry = function.entry;
            detail->ChangeValue(row->name + "\n" + location_text(function.entry) +
                wxString::Format(" | %zu blocks | %zu chunks | %zu recovered calls (%zu unresolved) | ",
                    function.blocks.size(), function.chunks.size(), row->outgoing, row->unresolved) +
                (function.complete ? "complete" : "partial") + (function.thunk ? " | thunk" : "") +
                (function.chunks.size() + function.stops.size() > evidence_limit
                    ? "\nEvidence limited to the first 4,096 chunk/stop records." : ""));
            for (const auto &chunk : function.chunks) {
                if (evidence_rows.size() == evidence_limit) break;
                evidence_rows.push_back({chunk.begin, "Chunk", wxString::Format("%llu bytes; %zu blocks",
                    static_cast<unsigned long long>(chunk.size), chunk.blocks.size())});
            }
            for (const auto &stop : function.stops) {
                if (evidence_rows.size() == evidence_limit) break;
                evidence_rows.push_back({stop.address, stop_name(stop.reason), preview_text(stop.detail, 4096)});
            }
        }
        evidence->populate(evidence_rows.size(), [&](std::size_t index, int column) {
            if (index >= evidence_rows.size()) return wxString{};
            const auto &row = evidence_rows[index];
            return column == 0 ? location_text(row.address) : column == 1 ? row.kind : row.detail;
        });
        evidence->clear_selection();
    };
    std::vector<std::size_t> order;
    order.reserve(rows.size());
    for (std::size_t i = 0; i < rows.size(); ++i) order.push_back(i);
    const auto sort_rows = [&] {
        std::sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) {
            const auto &left = rows[a], &right = rows[b];
            int compare = 0;
            const auto number = [](auto a, auto b) { return a < b ? -1 : a > b ? 1 : 0; };
            switch (sort_column) {
            case 1: compare = left.name.CmpNoCase(right.name); break;
            case 2: compare = number(left.function->blocks.size(), right.function->blocks.size()); break;
            case 3: compare = number(left.function->chunks.size(), right.function->chunks.size()); break;
            case 4: compare = number(left.outgoing, right.outgoing); break;
            case 5: compare = number(left.unresolved, right.unresolved); break;
            case 6: compare = number(std::pair{left.function->complete, left.function->thunk},
                                    std::pair{right.function->complete, right.function->thunk}); break;
            }
            if (!compare) compare = number(std::pair{left.function->entry.space.value, left.function->entry.offset},
                                          std::pair{right.function->entry.space.value, right.function->entry.offset});
            if (!compare) compare = number(a, b);
            return ascending ? compare < 0 : compare > 0;
        });
    };
    const auto render = [&] {
        if (const auto *row = selected_row()) selected_entry = row->function->entry;
        visible.clear();
        const auto needle = query->GetValue().Lower().Trim(true).Trim(false);
        for (const auto i : order) {
            const auto &row = rows[i]; const auto &function = *row.function;
            if ((!needle.empty() && row.search.Find(needle) == wxNOT_FOUND) ||
                (scope->GetSelection() == 1 && function.complete) ||
                (scope->GetSelection() == 2 && !function.complete) ||
                (scope->GetSelection() == 3 && !function.thunk) ||
                (scope->GetSelection() == 4 && !row.unresolved)) continue;
            visible.push_back(i);
        }
        table->populate(visible.size(), [&](std::size_t index, int column) {
            if (index >= visible.size()) return wxString{};
            const auto &row = rows[visible[index]]; const auto &function = *row.function;
            switch (column) {
            case 0: return location_text(function.entry);
            case 1: return row.name;
            case 2: return wxString::Format("%zu", function.blocks.size());
            case 3: return wxString::Format("%zu", function.chunks.size());
            case 4: return wxString::Format("%zu", row.outgoing);
            case 5: return wxString::Format("%zu", row.unresolved);
            default: return wxString(function.complete ? "complete" : "partial") + (function.thunk ? " / thunk" : "");
            }
        });
        table->clear_selection();
        for (std::size_t index = 0; index < visible.size(); ++index)
            if (selected_entry && rows[visible[index]].function->entry == *selected_entry) {
                table->select_row(index); break;
            }
        status->SetLabel(wxString::Format("%zu of %zu recovered functions | click a column to sort | ", visible.size(), rows.size()) +
            (snapshot->complete ? "analysis complete" : "analysis incomplete; counts describe recovered evidence"));
        update_detail();
    };
    const auto choose = [&](FunctionDestination destination, bool use_evidence) {
        const auto *row = selected_row(); if (!row) return;
        auto address = row->function->entry;
        if (use_evidence) {
            const auto index = evidence->selected_row();
            if (!index || *index >= evidence_rows.size()) return;
            address = evidence_rows[*index].address;
        }
        result = FunctionNavigation{row->function->entry, address, destination};
        dialog.EndModal(wxID_OK);
    };
    for (std::size_t i = 0; i < 5; ++i)
        buttons[i]->Bind(wxEVT_BUTTON, [&, i](wxCommandEvent &) { choose(static_cast<FunctionDestination>(i), false); });
    buttons[5]->Bind(wxEVT_BUTTON, [&](wxCommandEvent &) { choose(FunctionDestination::listing, true); });
    table->activate = [&](std::size_t) { update_detail(); };
    table->Bind(wxEVT_LIST_ITEM_ACTIVATED, [&](wxListEvent &) { choose(FunctionDestination::listing, false); });
    evidence->activate = [&](std::size_t) { buttons[5]->Enable(evidence->selected_row().has_value()); };
    evidence->Bind(wxEVT_LIST_ITEM_ACTIVATED, [&](wxListEvent &) { choose(FunctionDestination::listing, true); });
    table->Bind(wxEVT_LIST_ITEM_SELECTED, [&](wxListEvent &) { update_detail(); });
    evidence->Bind(wxEVT_LIST_ITEM_SELECTED, [&](wxListEvent &) { buttons[5]->Enable(evidence->selected_row().has_value()); });
    table->Bind(wxEVT_LIST_COL_CLICK, [&](wxListEvent &event) {
        if (sort_column == event.GetColumn()) ascending = !ascending;
        else { sort_column = event.GetColumn(); ascending = true; }
        sort_rows(); render();
    });
    query->Bind(wxEVT_TEXT, [&](wxCommandEvent &) { render(); });
    query->Bind(wxEVT_TEXT_ENTER, [&](wxCommandEvent &) { table->SetFocus(); });
    scope->Bind(wxEVT_CHOICE, [&](wxCommandEvent &) { render(); });
    sort_rows(); render(); query->SetFocus();
    const auto outcome = dialog.ShowModal();
    // Destroy controls while their event handlers and virtual-table models still
    // have live captures. No native teardown can consult expired local vectors.
    table->populate(0, {}); evidence->populate(0, {});
    dialog.DestroyChildren();
    if (outcome != wxID_OK) return {};
    return result;
}
}
