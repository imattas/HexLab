#include "analysis_issues_view.hpp"

#include "project_view.hpp"
#include "hexlab/analysis/functions.hpp"
#include "hexlab/image/file_publication.hpp"

#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/filedlg.h>
#include <wx/msgdlg.h>
#include <wx/sizer.h>

#include <algorithm>
#include <array>
#include <iterator>
#include <span>
#include <string_view>
#include <utility>

namespace hexlab::desktop {
namespace {
wxString stop_name(FunctionStopReason reason) {
    switch (reason) {
    case FunctionStopReason::ret: return "return";
    case FunctionStopReason::trap: return "trap";
    case FunctionStopReason::unsupported: return "unsupported instruction";
    case FunctionStopReason::invalid: return "invalid instruction";
    case FunctionStopReason::truncated: return "truncated instruction";
    case FunctionStopReason::unmapped: return "unmapped address";
    case FunctionStopReason::uninitialized: return "uninitialized bytes";
    case FunctionStopReason::non_executable: return "non-executable target";
    case FunctionStopReason::manual_data: return "marked as data";
    case FunctionStopReason::overlap: return "overlapping function";
    case FunctionStopReason::indirect: return "unresolved indirect flow";
    case FunctionStopReason::budget: return "analysis budget reached";
    case FunctionStopReason::target_overflow: return "target overflow";
    case FunctionStopReason::chunk_boundary: return "chunk boundary";
    case FunctionStopReason::tail_candidate: return "tail-call candidate";
    case FunctionStopReason::elf_relocation: return "ELF relocation target";
    case FunctionStopReason::macho_relocation: return "Mach-O relocation target";
    case FunctionStopReason::macho_dyld: return "Mach-O dyld target";
    case FunctionStopReason::image_exclusion: return "excluded image region";
    }
    return "unknown stop";
}

bool ordinary_stop(FunctionStopReason reason) {
    return reason == FunctionStopReason::ret || reason == FunctionStopReason::trap;
}

bool address_less(Address left, Address right) {
    if (left.space.value != right.space.value)
        return left.space.value < right.space.value;
    return left.offset < right.offset;
}

wxString severity_text(DiagnosticSeverity severity) {
    switch (severity) {
    case DiagnosticSeverity::info: return "Info";
    case DiagnosticSeverity::warning: return "Warning";
    case DiagnosticSeverity::error: return "Error";
    }
    return "Diagnostic";
}

wxString tsv_field(wxString value) {
    value.Replace("\\", "\\\\");
    value.Replace("\t", "\\t");
    value.Replace("\r", "\\r");
    value.Replace("\n", "\\n");
    return value;
}
} // namespace

AnalysisIssuesView::AnalysisIssuesView(wxWindow *parent) : wxPanel(parent) {
    auto *layout = new wxBoxSizer(wxVERTICAL);
    auto *controls = new wxBoxSizer(wxHORIZONTAL);
    filter_ = new wxChoice(this, wxID_ANY);
    filter_->SetName("analysis-issues-filter");
    filter_->Append("All findings");
    filter_->Append("Function stops");
    filter_->Append("Candidates");
    filter_->Append("Overlaps");
    filter_->Append("Loader diagnostics");
    filter_->Append("Type import diagnostics");
    filter_->Append("Decompiler diagnostics");
    filter_->SetSelection(0);
    severity_ = new wxChoice(this, wxID_ANY);
    severity_->SetName("analysis-issues-severity");
    severity_->Append("All severities");
    severity_->Append("Errors");
    severity_->Append("Warnings");
    severity_->Append("Info");
    severity_->SetSelection(0);
    search_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
    search_->SetName("analysis-issues-search");
    search_->SetHint("Filter findings by address or detail");
    status_ = new wxStaticText(this, wxID_ANY, "No analysis findings loaded.");
    selection_detail_ = new wxStaticText(this, wxID_ANY, "Select a finding to inspect its related locations.",
                                         wxDefaultPosition, wxDefaultSize, wxST_ELLIPSIZE_END);
    selection_detail_->SetName("analysis-issue-selection");
    auto *scope_bar = new wxBoxSizer(wxHORIZONTAL);
    scope_context_ = new wxStaticText(this, wxID_ANY, "All recovered functions", wxDefaultPosition,
                                     wxDefaultSize, wxST_ELLIPSIZE_END);
    scope_context_->SetName("analysis-issues-scope-context");
    scope_cursor_ = new wxButton(this, wxID_ANY, "Scope to cursor function");
    scope_cursor_->SetName("analysis-issues-scope-cursor");
    scope_cursor_->SetToolTip("Pin findings to the uniquely recovered function at the current listing or graph cursor.");
    scope_all_ = new wxButton(this, wxID_ANY, "All functions");
    scope_all_->SetName("analysis-issues-scope-all");
    scope_bar->Add(scope_context_, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(6));
    scope_bar->Add(scope_cursor_, 0, wxRIGHT, FromDIP(4));
    scope_bar->Add(scope_all_, 0);
    auto *actions = new wxBoxSizer(wxHORIZONTAL);
    previous_ = new wxButton(this, wxID_ANY, "Previous");
    previous_->SetName("analysis-issue-previous");
    previous_->SetToolTip("Select and navigate to the previous visible finding (Alt+Up in this pane).");
    next_ = new wxButton(this, wxID_ANY, "Next");
    next_->SetName("analysis-issue-next");
    next_->SetToolTip("Select and navigate to the next visible finding (Alt+Down in this pane).");
    go_related_ = new wxButton(this, wxID_ANY, "Go to related");
    go_related_->SetName("analysis-issue-go-related");
    go_function_ = new wxButton(this, wxID_ANY, "Go to function");
    go_function_->SetName("analysis-issue-go-function");
    copy_issue_ = new wxButton(this, wxID_ANY, "Copy finding");
    copy_issue_->SetName("analysis-issue-copy");
    export_ = new wxButton(this, wxID_ANY, "Export visible TSV...");
    export_->SetName("analysis-issues-export");
    go_related_->Enable(false);
    go_function_->Enable(false);
    copy_issue_->Enable(false);
    export_->Enable(false);
    previous_->Enable(false);
    next_->Enable(false);
    scope_cursor_->Enable(false);
    scope_all_->Enable(false);
    table_ = new VirtualTable(this, "analysis-issues", {"Finding", "Severity", "Address", "Related", "Function", "Details"});
    table_->SetColumnWidth(0, FromDIP(140));
    table_->SetColumnWidth(1, FromDIP(86));
    table_->SetColumnWidth(2, FromDIP(130));
    table_->SetColumnWidth(3, FromDIP(130));
    table_->SetColumnWidth(4, FromDIP(130));
    table_->SetColumnWidth(5, FromDIP(360));
    detail_ = new wxTextCtrl(this, wxID_ANY, "Select a finding to inspect its details.", wxDefaultPosition,
                             FromDIP(wxSize(-1, 115)), wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    detail_->SetName("analysis-issue-details");
    detail_->SetToolTip("Finding details and related locations. Select text here to copy an excerpt.");

    controls->Add(filter_, 0, wxEXPAND | wxRIGHT, FromDIP(6));
    controls->Add(severity_, 0, wxEXPAND | wxRIGHT, FromDIP(6));
    controls->Add(search_, 1, wxEXPAND);
    actions->Add(previous_, 0, wxRIGHT, FromDIP(4));
    actions->Add(next_, 0, wxRIGHT, FromDIP(6));
    actions->Add(selection_detail_, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(6));
    actions->Add(go_related_, 0, wxRIGHT, FromDIP(4));
    actions->Add(go_function_, 0, wxRIGHT, FromDIP(4));
    actions->Add(copy_issue_, 0);
    actions->Add(export_, 0, wxLEFT, FromDIP(4));
    layout->Add(controls, 0, wxEXPAND | wxALL, FromDIP(5));
    layout->Add(scope_bar, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(5));
    layout->Add(status_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(5));
    layout->Add(actions, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(5));
    layout->Add(table_, 1, wxEXPAND);
    layout->Add(detail_, 0, wxEXPAND | wxALL, FromDIP(5));
    SetSizer(layout);

    filter_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) { render(); remember_preference(); });
    severity_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) { render(); remember_preference(); });
    search_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) { render(); remember_preference(); });
    search_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent &) { step(true); });
    table_->activate = [this](std::size_t row) { activate_row(row); };
    previous_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { step(false); });
    next_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { step(true); });
    scope_cursor_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { scope_to_cursor(); });
    scope_all_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        scope_entry_.reset();
        scope_error_.clear();
        rebuild_scope();
        render();
        remember_preference();
    });
    Bind(wxEVT_CHAR_HOOK, [this](wxKeyEvent &event) {
        if (event.AltDown() && !event.ControlDown() && !event.ShiftDown() &&
            (event.GetKeyCode() == WXK_UP || event.GetKeyCode() == WXK_DOWN)) {
            step(event.GetKeyCode() == WXK_DOWN);
            return;
        }
        if (event.ControlDown() && !event.AltDown() && !event.ShiftDown() && event.GetKeyCode() == 'L') {
            search_->SetFocus();
            search_->SelectAll();
            return;
        }
        event.Skip();
    });
    go_related_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        const auto *row = selected_issue();
        if (row && row->related && navigate)
            navigate(Location{*row->related});
    });
    go_function_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        const auto *row = selected_issue();
        if (row && row->function_entry && navigate)
            navigate(Location{*row->function_entry});
    });
    copy_issue_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        const auto *row = selected_issue();
        if (!row || !wxTheClipboard || !wxTheClipboard->Open())
            return;
        const auto report = finding_text(*row);
        const auto encoded = report.ToUTF8();
        const auto bounded = encoded.data()
            ? preview_text(std::string_view(encoded.data(), encoded.length()), 65536)
            : wxString{};
        wxTheClipboard->SetData(new wxTextDataObject(bounded));
        wxTheClipboard->Close();
    });
    export_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { export_visible(); });
}

void AnalysisIssuesView::update(std::shared_ptr<const ProjectSnapshot> project) {
    update({}, std::move(project), {}, {});
}

void AnalysisIssuesView::update(std::optional<DocumentId> document, std::shared_ptr<const ProjectSnapshot> project,
                                std::optional<Location> cursor,
                                std::shared_ptr<const DocumentSnapshot> document_snapshot) {
    if (document_snapshot && (!document || document_snapshot->id != *document)) {
        // Tab selection and snapshot publication can cross during a refresh.
        // Never attribute one document's diagnostics to another tab.
        document_snapshot.reset();
        project.reset();
    }
    const bool changed_document = document_ != document;
    if (!changed_document && project_ == project && document_snapshot_ == document_snapshot && cursor_ == cursor)
        return;
    if (changed_document) {
        remember_preference();
        document_ = document;
        Preference preference;
        if (document_) {
            const auto found = preferences_.find(document_->value);
            if (found != preferences_.end()) preference = found->second;
        }
        filter_->SetSelection(std::clamp(preference.filter, 0, 6));
        severity_->SetSelection(std::clamp(preference.severity, 0, 3));
        search_->ChangeValue(preference.query);
        scope_entry_ = preference.function;
        selection_key_ = std::move(preference.selected);
        scope_error_.clear();
    }
    const auto *incoming = project && project->functions ? project->functions.get() : nullptr;
    const auto *incoming_loader = project && project->loaded ? project->loaded.get() : nullptr;
    const bool same_source = !changed_document && source_ == incoming && loader_source_ == incoming_loader &&
                             document_snapshot_ == document_snapshot;
    const bool same_project = project_ == project;
    project_ = std::move(project);
    document_snapshot_ = std::move(document_snapshot);
    cursor_ = cursor;
    if (!same_source) {
        source_ = incoming;
        loader_source_ = incoming_loader;
        scope_error_.clear();
        rebuild_scope();
        rebuild();
    } else if (changed_document) {
        rebuild();
    } else if (!same_project) {
        render();
    } else {
        update_scope_context();
    }
}

const Image *AnalysisIssuesView::active_image() const noexcept {
    if (project_ && project_->loaded) return project_->loaded->image.get();
    return document_snapshot_ ? document_snapshot_->image.get() : nullptr;
}

void AnalysisIssuesView::retain_documents(std::span<const DocumentInfo> documents) {
    if (document_ && std::none_of(documents.begin(), documents.end(), [this](const auto &document) {
            return document.id == *document_;
        })) {
        document_.reset();
        document_snapshot_.reset();
        project_.reset();
        source_ = nullptr;
        loader_source_ = nullptr;
        cursor_.reset();
        selection_key_.reset();
        scope_entry_.reset();
        scope_ranges_.clear();
        scope_available_ = false;
        scope_partial_ = false;
        scope_error_.clear();
        filter_->SetSelection(0);
        severity_->SetSelection(0);
        search_->ChangeValue({});
        rows_.clear();
        capped_ = false;
        render();
    }
    std::erase_if(preferences_, [&](const auto &item) {
        return std::none_of(documents.begin(), documents.end(), [&](const auto &document) {
            return document.id.value == item.first;
        });
    });
    std::erase_if(type_diagnostics_, [&](const auto &item) {
        return std::none_of(documents.begin(), documents.end(), [&](const auto &document) { return document.id.value == item.first; });
    });
    std::erase_if(decompiler_diagnostics_, [&](const auto &item) {
        return std::none_of(documents.begin(), documents.end(), [&](const auto &document) { return document.id.value == item.first; });
    });
}

void AnalysisIssuesView::set_type_diagnostics(std::optional<DocumentId> document,
                                              std::vector<AnalysisIssueDiagnostic> diagnostics) {
    if (!document) return;
    if (diagnostics.empty()) type_diagnostics_.erase(document->value);
    else type_diagnostics_.insert_or_assign(document->value, std::move(diagnostics));
    if (document_ == document) rebuild();
}

void AnalysisIssuesView::set_decompiler_diagnostics(std::optional<DocumentId> document,
                                                    std::vector<AnalysisIssueDiagnostic> diagnostics) {
    if (!document) return;
    if (diagnostics.empty()) decompiler_diagnostics_.erase(document->value);
    else decompiler_diagnostics_.insert_or_assign(document->value, std::move(diagnostics));
    if (document_ == document) rebuild();
}

void AnalysisIssuesView::remember_preference() {
    if (!document_) return;
    preferences_[document_->value] = {filter_->GetSelection(), severity_->GetSelection(), search_->GetValue(),
                                      scope_entry_, selection_key_};
}

void AnalysisIssuesView::rebuild_scope() {
    scope_ranges_.clear();
    scope_available_ = false;
    scope_partial_ = false;
    if (!scope_entry_ || !project_ || !project_->functions) return;
    const FunctionRecord *selected = nullptr;
    const auto &functions = project_->functions->functions;
    const auto limit = std::min(functions.size(), max_functions_scanned);
    for (std::size_t index = 0; index < limit; ++index) {
        if (!functions[index] || functions[index]->entry != *scope_entry_) continue;
        if (selected) { scope_partial_ = true; return; }
        selected = functions[index].get();
    }
    if (!selected || functions.size() > limit) { scope_partial_ = functions.size() > limit; return; }
    scope_available_ = true;
    const auto chunks = std::min(selected->chunks.size(), max_chunks_scanned);
    scope_partial_ = selected->chunks.size() > chunks;
    for (std::size_t index = 0; index < chunks; ++index) {
        const auto &chunk = selected->chunks[index];
        if (!chunk.size) continue;
        if (!AddressRange::create(chunk.begin, chunk.size)) { scope_partial_ = true; continue; }
        scope_ranges_.push_back({chunk.begin, chunk.size});
    }
    std::sort(scope_ranges_.begin(), scope_ranges_.end(), [](const ScopeRange &left, const ScopeRange &right) {
        return address_less(left.begin, right.begin);
    });
    std::vector<ScopeRange> merged;
    for (const auto &range : scope_ranges_) {
        if (!merged.empty() && merged.back().begin.space == range.begin.space &&
            range.begin.offset <= merged.back().begin.offset + merged.back().size) {
            auto &last = merged.back();
            last.size = std::max(last.begin.offset + last.size, range.begin.offset + range.size) - last.begin.offset;
        } else merged.push_back(range);
    }
    scope_ranges_ = std::move(merged);
}

bool AnalysisIssuesView::scope_contains(Address address) const {
    if (!scope_entry_ || !scope_available_) return false;
    if (address == *scope_entry_) return true;
    const auto after = std::upper_bound(scope_ranges_.begin(), scope_ranges_.end(), address,
        [](Address at, const ScopeRange &range) { return address_less(at, range.begin); });
    if (after == scope_ranges_.begin()) return false;
    const auto &range = *std::prev(after);
    return address.space == range.begin.space && address.offset >= range.begin.offset &&
           address.offset - range.begin.offset < range.size;
}

bool AnalysisIssuesView::matches_scope(const Row &row) const {
    if (!scope_entry_) return true;
    if (!scope_available_) return false;
    return row.function_entry == scope_entry_ || (row.address && scope_contains(*row.address)) ||
           (row.related && scope_contains(*row.related));
}

void AnalysisIssuesView::scope_to_cursor() {
    scope_error_.clear();
    std::optional<Address> address;
    if (cursor_) {
        if (const auto *at = std::get_if<Address>(&*cursor_)) address = *at;
        else if (project_ && project_->loaded && project_->loaded->image) {
            const auto mapped = project_->loaded->image->to_address(std::get<FileOffset>(*cursor_));
            if (mapped) address = mapped.value();
        }
    }
    if (!address || !project_ || !project_->functions) {
        scope_error_ = "Select a mapped address in a recovered function first.";
        update_scope_context();
        return;
    }
    const auto &functions = project_->functions->functions;
    const FunctionRecord *owner = nullptr;
    std::size_t chunks_scanned = 0;
    bool bounded = functions.size() > max_functions_scanned;
    for (std::size_t index = 0; index < std::min(functions.size(), max_functions_scanned); ++index) {
        const auto &function = functions[index];
        if (!function) continue;
        bool contains = function->entry == *address;
        if (!contains) for (const auto &chunk : function->chunks) {
            if (++chunks_scanned > max_chunks_scanned) { bounded = true; break; }
            if (chunk.size && !AddressRange::create(chunk.begin, chunk.size)) { bounded = true; break; }
            if (chunk.begin.space == address->space && address->offset >= chunk.begin.offset &&
                address->offset - chunk.begin.offset < chunk.size) { contains = true; break; }
        }
        if (bounded) break;
        if (!contains) continue;
        if (owner) {
            scope_error_ = "Cursor has overlapping function owners; choose another location.";
            update_scope_context();
            return;
        }
        owner = function.get();
    }
    if (bounded || !owner) {
        scope_error_ = bounded ? "Function lookup is incomplete or reached its view limit; scope was not changed."
                               : "No recovered function contains the cursor; scope was not changed.";
        update_scope_context();
        return;
    }
    scope_entry_ = owner->entry;
    rebuild_scope();
    render();
    remember_preference();
}

void AnalysisIssuesView::update_scope_context() {
    const auto *image = active_image();
    wxString label = "All recovered functions";
    if (scope_entry_) {
        label = "Pinned function: " + location_text(*scope_entry_, image);
        if (project_) {
            const auto name = presentation_name(*project_, Location{*scope_entry_});
            if (!name.empty()) label += " (" + preview_text(name, 100) + ")";
        }
        if (!scope_available_) label += "; function is unavailable in the bounded recovery snapshot";
        else if (scope_partial_) label += "; function chunk coverage is partial";
    }
    if (!scope_error_.empty()) label += "; " + scope_error_;
    scope_context_->SetLabel(label);
    scope_context_->SetToolTip(label);
    scope_cursor_->Enable(cursor_.has_value() && project_ && project_->functions);
    scope_all_->Enable(scope_entry_.has_value());
}

wxString AnalysisIssuesView::kind_text(Kind kind) const {
    switch (kind) {
    case Kind::function_stop: return "Function stop";
    case Kind::candidate: return "Entry candidate";
    case Kind::overlap: return "Conflict";
    case Kind::incomplete_function: return "Incomplete function";
    case Kind::loader_diagnostic: return "Loader diagnostic";
    case Kind::type_import_diagnostic: return "Type import diagnostic";
    case Kind::decompiler_diagnostic: return "Decompiler diagnostic";
    }
    return "Finding";
}

void AnalysisIssuesView::rebuild() {
    rows_.clear();
    capped_ = false;
    if (!project_ && !document_snapshot_) {
        render();
        return;
    }

    const auto *snapshot = project_ ? project_->functions.get() : nullptr;
    const auto *loaded = project_ ? project_->loaded.get() : nullptr;
    // The immutable loaded image belongs to this exact project snapshot, so it
    // takes precedence over durable diagnostics from the preceding revision.
    // Durable rows provide a fallback when the project has no loaded image.
    const auto *file_diagnostics = !project_ && document_snapshot_ ? &document_snapshot_->diagnostics : nullptr;
    const auto *durable_loader = project_ && project_->state ? &project_->state->loader_diagnostics : nullptr;
    const auto *durable_runtime = project_ && project_->state ? &project_->state->runtime_relocation_diagnostics : nullptr;
    const auto *durable_type_import = project_ && project_->state ? &project_->state->type_import_diagnostics : nullptr;
    const auto *loader_items = loaded ? &loaded->diagnostics : durable_loader;
    const auto *runtime_items = loaded ? &loaded->runtime_relocation_diagnostics : durable_runtime;
    const auto diagnostic_count = project_
        ? std::min(max_loader_rows, loader_items ? loader_items->size() : 0) +
              std::min(max_loader_rows, runtime_items ? runtime_items->size() : 0)
        : file_diagnostics ? std::min(max_loader_rows, file_diagnostics->size()) : 0;
    const auto active_type = document_ && type_diagnostics_.contains(document_->value) ? &type_diagnostics_.at(document_->value) : nullptr;
    const auto active_decompiler = document_ && decompiler_diagnostics_.contains(document_->value) ? &decompiler_diagnostics_.at(document_->value) : nullptr;
    const auto durable_type_count = !active_type && durable_type_import ? durable_type_import->size() : 0;
    const auto producer_count = std::min(max_loader_rows, active_type ? active_type->size() : durable_type_count) +
                                std::min(max_loader_rows, active_decompiler ? active_decompiler->size() : 0);
    const auto diagnostic_total = diagnostic_count + producer_count;
    const bool diagnostic_source_truncated = project_
        ? (loader_items && loader_items->size() > max_loader_rows) || (runtime_items && runtime_items->size() > max_loader_rows)
        : file_diagnostics && file_diagnostics->size() > max_loader_rows;
    const bool producer_source_truncated = (active_type && active_type->size() > max_loader_rows) ||
                                           (!active_type && durable_type_import && durable_type_import->size() > max_loader_rows) ||
                                           (active_decompiler && active_decompiler->size() > max_loader_rows);
    const auto diagnostic_budget = std::min(max_loader_rows * 4, diagnostic_total);
    const auto function_row_limit = max_rows - diagnostic_budget;
    bool function_capped = false;
    auto add_function = [this, &function_capped, function_row_limit](Row row) {
        if (rows_.size() >= function_row_limit) {
            function_capped = true;
            return false;
        }
        rows_.push_back(std::move(row));
        return true;
    };

    const auto function_count = snapshot ? std::min(snapshot->functions.size(), max_functions_scanned) : 0;
    for (std::size_t index = 0; index < function_count && !function_capped; ++index) {
        const auto &function = snapshot->functions[index];
        if (!function)
            continue;
        if (!function->complete &&
            !add_function({Kind::incomplete_function, function->entry, {}, function->entry,
                  "Function recovery did not reach a complete boundary."}))
            break;
        for (const auto &stop : function->stops) {
            if (ordinary_stop(stop.reason))
                continue;
            if (!add_function({Kind::function_stop, stop.address, function->entry, function->entry,
                      stop_name(stop.reason) + (stop.detail.empty() ? wxString{} : ": " + text(stop.detail))}))
                break;
        }
    }
    if (snapshot && snapshot->functions.size() > function_count)
        function_capped = true;

    if (snapshot) for (const auto &conflict : snapshot->conflicts) {
        if (function_capped)
            break;
        const auto kind = conflict.kind == FunctionConflictKind::instruction_overlap
                              ? "Instruction overlap" : "Decision overlap";
        if (!add_function({Kind::overlap, conflict.first, conflict.second, {},
                  text(kind) + (conflict.detail.empty() ? wxString{} : ": " + text(conflict.detail))}))
            break;
    }
    if (snapshot) for (const auto &candidate : snapshot->candidates) {
        if (function_capped)
            break;
        auto detail = stop_name(candidate.reason);
        if (!candidate.detail.empty())
            detail += ": " + text(candidate.detail);
        if (candidate.source)
            detail += " (from " + location_text(*candidate.source, project_->loaded ? project_->loaded->image.get() : nullptr) + ")";
        if (!add_function({Kind::candidate, candidate.entry, candidate.source, candidate.entry, std::move(detail)}))
            break;
    }

    std::size_t diagnostic_rows = 0;
    auto add_diagnostics = [&](const std::vector<Diagnostic> &diagnostics, std::string_view source) {
        for (const auto &diagnostic : diagnostics) {
            if (diagnostic_rows >= diagnostic_budget) break;
            wxString detail = text(source) + " " + severity_text(diagnostic.severity) + ": " +
                              preview_text(diagnostic.message, 4096);
            if (rows_.size() >= max_rows) break;
            Row row{Kind::loader_diagnostic, diagnostic.location, {}, {}, std::move(detail)};
            row.severity = diagnostic.severity;
            rows_.push_back(std::move(row));
            ++diagnostic_rows;
        }
    };
    if (project_) {
        if (loader_items) add_diagnostics(*loader_items, "Loader");
        if (runtime_items) add_diagnostics(*runtime_items, "Runtime relocation");
        if (!active_type && durable_type_import) {
            for (std::size_t i = 0; i < std::min(max_loader_rows, durable_type_import->size()) && diagnostic_rows < diagnostic_budget; ++i) {
                const auto &item = (*durable_type_import)[i];
                wxString detail = text(item.source) + " " + severity_text(item.severity) + ": " + preview_text(item.message, 4096);
                Row row{Kind::type_import_diagnostic, item.location, {}, item.function_entry, std::move(detail)};
                row.severity = item.severity;
                rows_.push_back(std::move(row));
                ++diagnostic_rows;
            }
        }
    } else if (file_diagnostics) {
        add_diagnostics(*file_diagnostics, "File inspection");
    }
    const auto add_producer = [&](const std::vector<AnalysisIssueDiagnostic> *items, Kind kind) {
        if (!items) return;
        for (std::size_t i = 0; i < std::min(max_loader_rows, items->size()) && diagnostic_rows < diagnostic_budget; ++i) {
            const auto &item = (*items)[i];
            wxString detail = text(item.source) + " " + severity_text(item.severity) + ": " + preview_text(item.message, 4096);
            Row row{kind, item.address, {}, item.function_entry, std::move(detail)};
            row.severity = item.severity;
            rows_.push_back(std::move(row));
            ++diagnostic_rows;
        }
    };
    add_producer(active_type, Kind::type_import_diagnostic);
    add_producer(active_decompiler, Kind::decompiler_diagnostic);
    capped_ = function_capped || diagnostic_rows < diagnostic_total || diagnostic_source_truncated || producer_source_truncated;

    std::stable_sort(rows_.begin(), rows_.end(), [](const Row &left, const Row &right) {
        if (left.address && right.address) {
            if (address_less(*left.address, *right.address)) return true;
            if (address_less(*right.address, *left.address)) return false;
        } else if (left.address != right.address) {
            return !left.address;
        }
        return static_cast<int>(left.kind) < static_cast<int>(right.kind);
    });
    render();
}

wxString AnalysisIssuesView::cell(std::size_t row, int column) const {
    const auto &item = rows_[row];
    const auto *image = active_image();
    switch (column) {
    case 0: return kind_text(item.kind);
    case 1: return severity_text(item.severity);
    case 2: return item.address ? location_text(*item.address, image) : wxString{};
    case 3: return item.related ? location_text(*item.related, image) : wxString{};
    case 4: return item.function_entry ? location_text(*item.function_entry, image) : wxString{};
    default: {
        const auto encoded = item.detail.ToUTF8();
        return encoded.data() ? preview_text(std::string_view(encoded.data(), encoded.length()), 768) : wxString{};
    }
    }
}

wxString AnalysisIssuesView::export_text() const {
    wxString result = "# HexLab analysis findings (TSV; escaped backslash, tab, CR and LF)\n";
    result += "# Rows\t" + wxString::Format("%llu visible / %llu loaded",
        static_cast<unsigned long long>(visible_rows_.size()),
        static_cast<unsigned long long>(rows_.size())) + "\n";
    result += "# Filter\t" + tsv_field(filter_->GetStringSelection()) + "\n";
    result += "# Severity\t" + tsv_field(severity_->GetStringSelection()) + "\n";
    result += "# Search\t" + tsv_field(search_->GetValue()) + "\n";
    result += "# Scope\t" + tsv_field(scope_entry_
        ? "Function " + location_text(*scope_entry_, active_image())
        : wxString("All recovered functions")) + "\n";
    if (scope_entry_ && (!scope_available_ || scope_partial_))
        result += "# Scope coverage\tFunction is unavailable or chunk coverage is partial\n";
    if (capped_)
        result += "# Coverage\tCapped at 20,000 findings and 100,000 functions\n";
    result += "finding\tseverity\taddress\trelated\tfunction\tdetails\n";
    for (const auto index : visible_rows_) {
        const auto &item = rows_[index];
        const std::array<wxString, 6> fields{kind_text(item.kind), severity_text(item.severity), cell(index, 2),
                                             cell(index, 3), cell(index, 4), item.detail};
        for (std::size_t column = 0; column < fields.size(); ++column) {
            if (column) result += '\t';
            result += tsv_field(fields[column]);
        }
        result += '\n';
    }
    return result;
}

void AnalysisIssuesView::export_visible() {
    // File-only documents do not carry protected source paths in this view.
    if (visible_rows_.empty() || !project_)
        return;
    // Capture the current filtered rows before the modal picker is shown.
    const auto output = export_text();
    const auto protected_paths = project_ ? project_->protected_paths : std::vector<std::filesystem::path>{};
    wxFileDialog dialog(this, "Export visible analysis findings", "", "analysis-findings.tsv",
                        "TSV files (*.tsv)|*.tsv|All files (*.*)|*.*", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    if (dialog.ShowModal() != wxID_OK)
        return;
    auto publication = FilePublication::create(std::filesystem::path(dialog.GetPath().ToStdWstring()),
                                               ExistingFilePolicy::replace, protected_paths, {});
    if (!publication) {
        wxMessageBox(text(publication.error().message), "Export analysis findings", wxOK | wxICON_ERROR, this);
        return;
    }
    const auto encoded = output.utf8_str();
    const auto written = publication.value()->append(std::as_bytes(std::span(encoded.data(), encoded.length())));
    if (!written) {
        wxMessageBox(text(written.error().message), "Export analysis findings", wxOK | wxICON_ERROR, this);
        return;
    }
    const auto published = publication.value()->publish();
    if (!published)
        wxMessageBox(text(published.error().message), "Export analysis findings", wxOK | wxICON_ERROR, this);
}

void AnalysisIssuesView::render() {
    visible_rows_.clear();
    const auto selected_filter = filter_ ? filter_->GetSelection() : 0;
    const auto selected_severity = severity_ ? severity_->GetSelection() : 0;
    auto query = search_ ? search_->GetValue() : wxString{};
    query.MakeLower();
    for (std::size_t index = 0; index < rows_.size(); ++index) {
        if (!matches_scope(rows_[index])) continue;
        const auto kind = rows_[index].kind;
        if (selected_filter == 1 && kind != Kind::function_stop && kind != Kind::incomplete_function)
            continue;
        if (selected_filter == 2 && kind != Kind::candidate)
            continue;
        if (selected_filter == 3 && kind != Kind::overlap)
            continue;
        if (selected_filter == 4 && kind != Kind::loader_diagnostic)
            continue;
        if (selected_filter == 5 && kind != Kind::type_import_diagnostic) continue;
        if (selected_filter == 6 && kind != Kind::decompiler_diagnostic) continue;
        if ((selected_severity == 1 && rows_[index].severity != DiagnosticSeverity::error) ||
            (selected_severity == 2 && rows_[index].severity != DiagnosticSeverity::warning) ||
            (selected_severity == 3 && rows_[index].severity != DiagnosticSeverity::info))
            continue;
        if (!query.empty()) {
            wxString aggregate = kind_text(kind) + " " +
                                 severity_text(rows_[index].severity) + " " +
                                 (rows_[index].address ? location_text(*rows_[index].address)
                                                       : wxString("not location-specific")) + " " +
                                 (rows_[index].related ? location_text(Location{*rows_[index].related}) : wxString{}) + " " +
                                 (rows_[index].function_entry ? location_text(Location{*rows_[index].function_entry}) : wxString{}) + " " +
                                 rows_[index].detail;
            aggregate.MakeLower();
            if (aggregate.Find(query) == wxNOT_FOUND)
                continue;
        }
        visible_rows_.push_back(index);
    }

    table_->populate(visible_rows_.size(), [this](std::size_t row, int column) {
        return row < visible_rows_.size() ? cell(visible_rows_[row], column) : wxString{};
    });
    if (selection_key_) {
        const auto found = std::find_if(visible_rows_.begin(), visible_rows_.end(), [this](std::size_t index) {
            return rows_[index] == *selection_key_;
        });
        if (found != visible_rows_.end())
            table_->select_row(static_cast<std::size_t>(std::distance(visible_rows_.begin(), found)));
    }
    table_->activate = [this](std::size_t row) { activate_row(row); };
    update_selection();
    update_scope_context();
    if (!project_ && !document_snapshot_) {
        status_->SetLabel("No document is selected.");
    } else if (project_ && !project_->functions && rows_.empty()) {
        status_->SetLabel("No derived function analysis is available for this document.");
    } else {
        wxString status = wxString::Format("%llu findings shown",
                                           static_cast<unsigned long long>(visible_rows_.size()));
        if (visible_rows_.size() != rows_.size())
            status += wxString::Format(" of %llu", static_cast<unsigned long long>(rows_.size()));
        if (scope_entry_) status += "; pinned function scope";
        if (capped_)
            status += "; view bounded to 20,000 findings (at most 2,048 each from loader, runtime relocation, type import, and decompiler) and 100,000 functions";
        if (project_ && project_->functions && !project_->functions->complete)
            status += "; function analysis is incomplete";
        if (project_ && project_->status == DerivedStatus::incomplete)
            status += "; analysis is partial";
        else if (project_ && project_->status == DerivedStatus::pending)
            status += "; analysis is pending";
        if (project_ && !project_->reason.empty())
            status += "; " + preview_text(project_->reason, 180);
        if (scope_entry_ && std::any_of(rows_.begin(), rows_.end(), [](const Row &row) {
                return (row.kind == Kind::loader_diagnostic || row.kind == Kind::type_import_diagnostic ||
                        row.kind == Kind::decompiler_diagnostic) && !row.address;
            }))
            status += "; unlocated diagnostics are hidden by function scope";
        status_->SetLabel(status);
    }
    export_->Enable(project_ && !visible_rows_.empty());
}

void AnalysisIssuesView::activate_row(std::size_t visible) {
    if (visible >= visible_rows_.size()) return;
    const auto index = visible_rows_[visible];
    if (index >= rows_.size()) return;
    selection_key_ = rows_[index];
    const auto destination = rows_[index].address;
    update_selection();
    remember_preference();
    // Navigation can synchronously publish another snapshot and rebuild rows.
    if (destination && navigate) navigate(Location{*destination});
}

void AnalysisIssuesView::step(bool forward) {
    if (visible_rows_.empty()) return;
    const auto current = table_->selected_row();
    std::size_t next = forward ? 0 : visible_rows_.size() - 1;
    if (current && *current < visible_rows_.size()) {
        if ((forward && *current + 1 == visible_rows_.size()) || (!forward && *current == 0)) return;
        next = forward ? *current + 1 : *current - 1;
    }
    table_->select_row(next);
    activate_row(next);
}

wxString AnalysisIssuesView::finding_text(const Row &row) const {
    const auto *image = active_image();
    wxString report = kind_text(row.kind) + "\nSeverity: " + severity_text(row.severity) + "\nAddress: " +
                      (row.address ? location_text(*row.address, image) : wxString("not location-specific"));
    if (row.related) report += "\nRelated: " + location_text(*row.related, image);
    if (row.function_entry) {
        report += "\nFunction: " + location_text(*row.function_entry, image);
        if (project_) {
            const auto name = presentation_name(*project_, Location{*row.function_entry});
            if (!name.empty()) report += " (" + preview_text(name, 256) + ")";
        }
    }
    const auto encoded = row.detail.ToUTF8();
    report += "\nDetails: " + (encoded.data()
        ? preview_text(std::string_view(encoded.data(), encoded.length()), 65536) : wxString{});
    return report;
}

const AnalysisIssuesView::Row *AnalysisIssuesView::selected_issue() const {
    const auto selected = table_ ? table_->selected_row() : std::nullopt;
    if (!selected || *selected >= visible_rows_.size())
        return nullptr;
    const auto row = visible_rows_[*selected];
    return row < rows_.size() ? &rows_[row] : nullptr;
}

void AnalysisIssuesView::update_selection() {
    const auto *row = selected_issue();
    const auto selected = table_ ? table_->selected_row() : std::nullopt;
    previous_->Enable(!visible_rows_.empty() && (!selected || *selected > 0));
    next_->Enable(!visible_rows_.empty() && (!selected || *selected + 1 < visible_rows_.size()));
    if (!row) {
        selection_detail_->SetLabel("Select a finding to inspect its related locations.");
        selection_detail_->SetToolTip(wxString{});
        go_related_->Enable(false);
        go_function_->Enable(false);
        copy_issue_->Enable(false);
        export_->Enable(project_ && !visible_rows_.empty());
        detail_->ChangeValue("Select a finding to inspect its details. Previous/Next follow the filtered findings; Alt+Up/Down also work within this pane.");
        return;
    }
    const auto *image = active_image();
    wxString detail = kind_text(row->kind) + " at " +
                      (row->address ? location_text(*row->address, image) : wxString("no address")) + ": " + row->detail;
    const auto position = selected ? *selected + 1 : 0;
    selection_detail_->SetLabel(wxString::Format("%llu / %llu: ", static_cast<unsigned long long>(position),
        static_cast<unsigned long long>(visible_rows_.size())) + kind_text(row->kind));
    selection_detail_->SetToolTip(detail.Left(1024));
    const auto report = finding_text(*row);
    if (detail_->GetValue() != report) detail_->ChangeValue(report);
    go_related_->Enable(row->related.has_value());
    go_function_->Enable(row->function_entry.has_value());
    copy_issue_->Enable(true);
    export_->Enable(project_ && !visible_rows_.empty());
}

} // namespace hexlab::desktop
