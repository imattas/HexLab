#include "analysis_issues_view.hpp"

#include "project_view.hpp"
#include "hexlab/analysis/functions.hpp"
#include "hexlab/image/file_publication.hpp"
#include "hexlab/image/file_storage.hpp"
#include "hexlab/workspace/project_analysis.hpp"

#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/filedlg.h>
#include <wx/msgdlg.h>
#include <wx/sizer.h>

#include <algorithm>
#include <array>
#include <iterator>
#include <span>
#include <string>
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

std::string import_identity(const AnalysisKey &key) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string identity;
    identity.reserve(80);
    for (const auto byte : key.input.sha256) {
        const auto value = std::to_integer<unsigned char>(byte);
        identity.push_back(hex[value >> 4]);
        identity.push_back(hex[value & 15]);
    }
    identity += ":" + std::to_string(key.input.size) + ":" + std::to_string(key.byte_revision) +
                ":" + std::to_string(key.decision_revision);
    for (const auto byte : key.recipe_fingerprint) identity.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    for (const auto byte : key.engine_fingerprint) identity.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    return identity;
}

wxString import_identity_label(const AnalysisKey &key) {
    static constexpr char hex[] = "0123456789abcdef";
    wxString digest;
    for (std::size_t i = 0; i < 6; ++i) {
        const auto value = std::to_integer<unsigned char>(key.input.sha256[i]);
        digest += wxString::Format("%c%c", hex[value >> 4], hex[value & 15]);
    }
    return wxString::Format("%s (bytes %llu, revision %llu/%llu)", digest,
        static_cast<unsigned long long>(key.input.size),
        static_cast<unsigned long long>(key.byte_revision),
        static_cast<unsigned long long>(key.decision_revision));
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

std::string json_quote(std::string_view value) {
    constexpr char hex[] = "0123456789abcdef";
    std::string output;
    output.reserve(value.size() + 2);
    output.push_back('"');
    for (const auto byte : value) {
        const auto c = static_cast<unsigned char>(byte);
        switch (c) {
        case '"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\b': output += "\\b"; break;
        case '\f': output += "\\f"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (c < 0x20) {
                output += "\\u00";
                output.push_back(hex[c >> 4]);
                output.push_back(hex[c & 15]);
            } else output.push_back(static_cast<char>(c));
        }
    }
    output.push_back('"');
    return output;
}

std::string utf8_text(const wxString &value) {
    const auto encoded = value.utf8_str();
    return encoded.data() ? std::string(encoded.data(), encoded.length()) : std::string{};
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
    filter_->Append("Runtime relocation diagnostics");
    filter_->Append("File inspection diagnostics");
    filter_->Append("Analysis and string diagnostics");
    filter_->Append("Stale diagnostic reports");
    filter_->SetToolTip("Limit findings to diagnostics whose stored source identity does not match the active analysis.");
    filter_->SetSelection(0);
    severity_ = new wxChoice(this, wxID_ANY);
    severity_->SetName("analysis-issues-severity");
    severity_->Append("All severities");
    severity_->Append("Errors");
    severity_->Append("Warnings");
    severity_->Append("Info");
    severity_->SetSelection(0);
    review_filter_ = new wxChoice(this, wxID_ANY);
    review_filter_->SetName("analysis-issues-review-filter");
    review_filter_->Append("All review states");
    review_filter_->Append("Open only");
    review_filter_->Append("Reviewed only");
    review_filter_->Append("Needs attention (open errors/warnings)");
    review_filter_->SetToolTip("Show unresolved errors and warnings; combine with category, search and function scope.");
    review_filter_->SetSelection(0);
    location_filter_ = new wxChoice(this, wxID_ANY);
    location_filter_->SetName("analysis-issues-location-filter");
    location_filter_->Append("All locations");
    location_filter_->Append("Has a location");
    location_filter_->Append("No location");
    location_filter_->Append("Primary address");
    location_filter_->Append("Related address");
    location_filter_->Append("Function entry");
    location_filter_->SetToolTip("Filter by primary address, related address, or owning-function entry; the original any-location and no-location filters remain available.");
    location_filter_->SetSelection(0);
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
    copy_issue_json_ = new wxButton(this, wxID_ANY, "Copy finding JSON");
    copy_issue_json_->SetName("analysis-issue-copy-json");
    copy_issue_json_->SetToolTip("Copy the selected finding as one versioned JSON record.");
    copy_visible_ = new wxButton(this, wxID_ANY, "Copy visible TSV");
    copy_visible_->SetName("analysis-issues-copy-visible");
    copy_visible_->SetToolTip("Copy up to 128 currently visible findings as TSV, including file-only documents.");
    copy_visible_json_ = new wxButton(this, wxID_ANY, "Copy visible JSON");
    copy_visible_json_->SetName("analysis-issues-copy-visible-json");
    copy_visible_json_->SetToolTip("Copy up to 128 currently visible findings as versioned JSON.");
    mark_reviewed_ = new wxButton(this, wxID_ANY, "Mark reviewed");
    mark_reviewed_->SetName("analysis-issue-review-toggle");
    review_visible_ = new wxButton(this, wxID_ANY, "Review visible");
    review_visible_->SetName("analysis-issues-review-visible");
    review_visible_->SetToolTip("Mark every currently filtered and scoped finding as reviewed.");
    reopen_visible_ = new wxButton(this, wxID_ANY, "Reopen visible");
    reopen_visible_->SetName("analysis-issues-reopen-visible");
    reopen_visible_->SetToolTip("Reopen every currently filtered and scoped finding.");
    export_ = new wxButton(this, wxID_ANY, "Export visible TSV...");
    export_->SetName("analysis-issues-export");
    go_related_->Enable(false);
    go_function_->Enable(false);
    copy_issue_->Enable(false);
    copy_issue_json_->Enable(false);
    copy_visible_->Enable(false);
    copy_visible_json_->Enable(false);
    mark_reviewed_->Enable(false);
    review_visible_->Enable(false);
    reopen_visible_->Enable(false);
    export_->Enable(false);
    previous_->Enable(false);
    next_->Enable(false);
    scope_cursor_->Enable(false);
    scope_all_->Enable(false);
    table_ = new VirtualTable(this, "analysis-issues", {"Finding", "Severity", "Review", "Address", "Related", "Function", "Details"});
    table_->SetColumnWidth(0, FromDIP(140));
    table_->SetColumnWidth(1, FromDIP(86));
    table_->SetColumnWidth(2, FromDIP(90));
    table_->SetColumnWidth(3, FromDIP(130));
    table_->SetColumnWidth(4, FromDIP(130));
    table_->SetColumnWidth(5, FromDIP(130));
    table_->SetColumnWidth(6, FromDIP(360));
    detail_ = new wxTextCtrl(this, wxID_ANY, "Select a finding to inspect its details.", wxDefaultPosition,
                             FromDIP(wxSize(-1, 115)), wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    detail_->SetName("analysis-issue-details");
    detail_->SetToolTip("Finding details and related locations. Select text here to copy an excerpt.");

    controls->Add(filter_, 0, wxEXPAND | wxRIGHT, FromDIP(6));
    controls->Add(severity_, 0, wxEXPAND | wxRIGHT, FromDIP(6));
    controls->Add(review_filter_, 0, wxEXPAND | wxRIGHT, FromDIP(6));
    controls->Add(location_filter_, 0, wxEXPAND | wxRIGHT, FromDIP(6));
    controls->Add(search_, 1, wxEXPAND);
    actions->Add(previous_, 0, wxRIGHT, FromDIP(4));
    actions->Add(next_, 0, wxRIGHT, FromDIP(6));
    actions->Add(selection_detail_, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(6));
    actions->Add(go_related_, 0, wxRIGHT, FromDIP(4));
    actions->Add(go_function_, 0, wxRIGHT, FromDIP(4));
    actions->Add(copy_issue_, 0);
    actions->Add(copy_issue_json_, 0, wxLEFT, FromDIP(4));
    actions->Add(copy_visible_, 0, wxLEFT, FromDIP(4));
    actions->Add(copy_visible_json_, 0, wxLEFT, FromDIP(4));
    actions->Add(mark_reviewed_, 0, wxLEFT, FromDIP(4));
    actions->Add(review_visible_, 0, wxLEFT, FromDIP(4));
    actions->Add(reopen_visible_, 0, wxLEFT, FromDIP(4));
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
    review_filter_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) { render(); remember_preference(); });
    location_filter_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) { render(); remember_preference(); });
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
    copy_issue_json_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_issue_json(); });
    mark_reviewed_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { toggle_reviewed(); });
    review_visible_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { set_visible_reviewed(true); });
    reopen_visible_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { set_visible_reviewed(false); });
    export_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { export_visible(); });
    copy_visible_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_visible(); });
    copy_visible_json_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_visible_json(); });
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
        filter_->SetSelection(std::clamp(preference.filter, 0, 10));
        severity_->SetSelection(std::clamp(preference.severity, 0, 3));
        review_filter_->SetSelection(std::clamp(preference.review_filter, 0, 3));
        location_filter_->SetSelection(std::clamp(preference.location_filter, 0, 5));
        search_->ChangeValue(preference.query);
        scope_entry_ = preference.function;
        selection_key_ = std::move(preference.selected);
        if (preference.reviewed) reviewed_ = std::move(preference.reviewed);
        else {
            reviewed_ = std::make_shared<std::unordered_set<std::string>>();
            if (project && project->state)
                reviewed_->insert(project->state->reviewed_analysis_issue_keys.begin(),
                                  project->state->reviewed_analysis_issue_keys.end());
        }
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
        review_filter_->SetSelection(0);
        location_filter_->SetSelection(0);
        search_->ChangeValue({});
        if (reviewed_) reviewed_->clear();
        rows_.clear();
        row_review_keys_.clear();
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
    preferences_[document_->value] = {filter_->GetSelection(), severity_->GetSelection(), review_filter_->GetSelection(),
                                      location_filter_->GetSelection(),
                                      search_->GetValue(), scope_entry_, selection_key_, reviewed_};
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
    case Kind::runtime_relocation_diagnostic: return "Runtime relocation diagnostic";
    case Kind::file_inspection_diagnostic: return "File inspection diagnostic";
    case Kind::file_analysis_diagnostic: return "Analysis/string diagnostic";
    case Kind::type_import_diagnostic: return "Type import diagnostic";
    case Kind::decompiler_diagnostic: return "Decompiler diagnostic";
    case Kind::minidump_context_diagnostic: return "Minidump context diagnostic";
    }
    return "Finding";
}

void AnalysisIssuesView::rebuild() {
    rows_.clear();
    row_review_keys_.clear();
    capped_ = false;
    if (!project_ && !document_snapshot_) {
        render();
        return;
    }

    const auto *snapshot = project_ ? project_->functions.get() : nullptr;
    const auto *loaded = project_ ? project_->loaded.get() : nullptr;
    // A preceding derived key can survive byte edits while reanalysis is
    // pending. Compare loader findings to this snapshot's actual source key.
    std::optional<AnalysisKey> current_loader_key;
    if(project_ && loaded){auto key=project_analysis_key(*project_,project_->analysis_options);if(key)current_loader_key=key.value();}
    // The immutable loaded image belongs to this exact project snapshot, so it
    // takes precedence over durable diagnostics from the preceding revision.
    // Durable rows provide a fallback when the project has no loaded image.
    const auto *file_diagnostics = !project_ && document_snapshot_ ? &document_snapshot_->diagnostics : nullptr;
    const auto *file_analysis = !project_ && document_snapshot_ && document_snapshot_->analysis
                                    ? &document_snapshot_->analysis->diagnostics : nullptr;
    const auto *file_analysis_strings = !project_ && document_snapshot_ && document_snapshot_->analysis
                                    ? &document_snapshot_->analysis->strings.diagnostics : nullptr;
    const auto *file_inspection_strings = !project_ && document_snapshot_
                                    ? &document_snapshot_->inspection_strings.diagnostics : nullptr;
    const auto *durable_loader = project_ && project_->state ? &project_->state->loader_diagnostics : nullptr;
    const auto *durable_runtime = project_ && project_->state ? &project_->state->runtime_relocation_diagnostics : nullptr;
    const auto *durable_type_import = project_ && project_->state ? &project_->state->type_import_diagnostics : nullptr;
    const auto *project_string_diagnostics = project_ && project_->strings ? &project_->strings->diagnostics : nullptr;
    const auto *loader_items = loaded ? &loaded->diagnostics : durable_loader;
    const auto *runtime_items = loaded ? &loaded->runtime_relocation_diagnostics : durable_runtime;
    const auto diagnostic_count = project_
        ? std::min(max_loader_rows, loader_items ? loader_items->size() : 0) +
              std::min(max_loader_rows, runtime_items ? runtime_items->size() : 0) +
              std::min(max_loader_rows, project_string_diagnostics ? project_string_diagnostics->size() : 0)
        : (file_diagnostics ? std::min(max_loader_rows, file_diagnostics->size()) : 0) +
          (file_analysis ? std::min(max_loader_rows, file_analysis->size()) : 0) +
          (file_analysis_strings ? std::min(max_loader_rows, file_analysis_strings->size()) : 0) +
          (file_inspection_strings ? std::min(max_loader_rows, file_inspection_strings->size()) : 0);
    const auto active_type = document_ && type_diagnostics_.contains(document_->value) ? &type_diagnostics_.at(document_->value) : nullptr;
    const auto active_decompiler = document_ && decompiler_diagnostics_.contains(document_->value) ? &decompiler_diagnostics_.at(document_->value) : nullptr;
    const auto durable_type_count = !active_type && durable_type_import ? std::count_if(durable_type_import->begin(), durable_type_import->end(), [](const auto &item){return item.source!="Decompiler" && item.source!="Minidump register context";}) : 0;
    const auto durable_context_count = durable_type_import ? std::count_if(durable_type_import->begin(),durable_type_import->end(),[](const auto& item){return item.source=="Minidump register context";}) : 0;
    const auto current_decompiler_function = active_decompiler && !active_decompiler->empty() ? active_decompiler->front().function_entry : std::optional<Address>{};
    const auto is_superseded_decompiler = [&](const auto &item) { return active_decompiler && item.source=="Decompiler" && current_decompiler_function && item.function_entry==current_decompiler_function && item.source_key && project_ && project_->derived_key && *item.source_key==*project_->derived_key; };
    const auto durable_decompiler_count = durable_type_import ? std::count_if(durable_type_import->begin(), durable_type_import->end(), [&](const auto &item){return item.source=="Decompiler"&&!is_superseded_decompiler(item);}) : 0;
    const auto producer_count = std::min(max_loader_rows, active_type ? active_type->size() : durable_type_count) +
                                std::min(max_loader_rows, active_decompiler ? active_decompiler->size() : durable_decompiler_count);
    const auto diagnostic_total = diagnostic_count + producer_count + std::min(max_loader_rows,static_cast<std::size_t>(durable_context_count));
    const bool diagnostic_source_truncated = project_
        ? (loader_items && loader_items->size() > max_loader_rows) || (runtime_items && runtime_items->size() > max_loader_rows) ||
          (project_string_diagnostics && project_string_diagnostics->size() > max_loader_rows)
        : (file_diagnostics && file_diagnostics->size() > max_loader_rows) ||
          (file_analysis && file_analysis->size() > max_loader_rows) ||
          (file_analysis_strings && file_analysis_strings->size() > max_loader_rows) ||
          (file_inspection_strings && file_inspection_strings->size() > max_loader_rows);
    const bool producer_source_truncated = (active_type && active_type->size() > max_loader_rows) ||
                                           durable_type_count > max_loader_rows || durable_context_count > max_loader_rows ||
                                           (active_decompiler && active_decompiler->size() > max_loader_rows) || durable_decompiler_count > max_loader_rows;
    const auto diagnostic_budget = std::min(max_loader_rows * 5, diagnostic_total);
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
    auto add_diagnostics = [&](const std::vector<Diagnostic> &diagnostics, std::string_view source, Kind kind) {
        std::size_t emitted=0;
        for (const auto &diagnostic : diagnostics) {
            if (emitted >= max_loader_rows || diagnostic_rows >= diagnostic_budget) break;
            wxString detail = text(source) + " " + severity_text(diagnostic.severity) + ": " +
                              preview_text(diagnostic.message, 4096);
            if (rows_.size() >= max_rows) break;
            Row row{kind, diagnostic.location, {}, {}, std::move(detail)};
            row.severity = diagnostic.severity;
            rows_.push_back(std::move(row));
            ++diagnostic_rows;++emitted;
        }
    };
    if (project_) {
        if (loader_items) add_diagnostics(*loader_items, "Loader", Kind::loader_diagnostic);
        if (runtime_items) add_diagnostics(*runtime_items, "Runtime relocation", Kind::runtime_relocation_diagnostic);
        if (project_string_diagnostics) {
            const bool current = project_->derived_key && current_loader_key &&
                                 *project_->derived_key == *current_loader_key;
            const auto identity = project_->derived_key ? import_identity(*project_->derived_key) : std::string{};
            std::size_t emitted = 0;
            for (const auto &diagnostic : *project_string_diagnostics) {
                if (emitted >= max_loader_rows || diagnostic_rows >= diagnostic_budget) break;
                wxString detail = "Project string scan " + severity_text(diagnostic.severity) + ": " +
                                  preview_text(diagnostic.message, 4096);
                Row row{Kind::file_analysis_diagnostic, diagnostic.location, {}, {}, std::move(detail)};
                row.severity = diagnostic.severity;
                row.stale_import = !current;
                if (!identity.empty()) {
                    row.source_identity = identity;
                    row.source_label = import_identity_label(*project_->derived_key);
                } else {
                    row.source_label = "Source key unavailable; this report is kept ungrouped.";
                }
                rows_.push_back(std::move(row));
                ++diagnostic_rows;
                ++emitted;
            }
        }
        if (!active_type && durable_type_import) {
            std::size_t emitted=0;
            for (const auto &item : *durable_type_import) {
                if (item.source=="Decompiler" || item.source=="Minidump register context" || emitted>=max_loader_rows || diagnostic_rows>=diagnostic_budget) continue;
                wxString detail = text(item.source) + " " + severity_text(item.severity) + ": " + preview_text(item.message, 4096);
                Row row{Kind::type_import_diagnostic, item.location, {}, item.function_entry, std::move(detail)};
                row.severity = item.severity;
                row.stale_import = !item.source_key || !project_->derived_key || *item.source_key != *project_->derived_key;
                if (item.source_key) {
                    row.source_identity = import_identity(*item.source_key);
                    row.source_label = import_identity_label(*item.source_key);
                } else {
                    row.source_label = "Source key unavailable; this report is kept ungrouped.";
                }
                rows_.push_back(std::move(row));
                ++diagnostic_rows;++emitted;
            }
        }
        if (durable_type_import) {
            std::size_t contexts=0;
            for(const auto& item:*durable_type_import){
                if(item.source!="Minidump register context" || contexts>=max_loader_rows || diagnostic_rows>=diagnostic_budget)continue;
                wxString detail=text(item.source)+" "+severity_text(item.severity)+": "+preview_text(item.message,4096);
                Row row{Kind::minidump_context_diagnostic,{}, {}, {},std::move(detail)};
                row.severity=item.severity;
                row.stale_import=!item.source_key||!current_loader_key||*item.source_key!=*current_loader_key;
                if(item.source_key){row.source_identity=import_identity(*item.source_key);row.source_label=import_identity_label(*item.source_key);}
                else row.source_label="Source key unavailable; this report is kept ungrouped.";
                rows_.push_back(std::move(row));++contexts;++diagnostic_rows;
            }
            std::size_t emitted=0;
            for (const auto &item : *durable_type_import) {
                if (item.source!="Decompiler" || is_superseded_decompiler(item) || emitted>=max_loader_rows || diagnostic_rows>=diagnostic_budget) continue;
                wxString detail=text(item.source)+" "+severity_text(item.severity)+": "+preview_text(item.message,4096);
                Row row{Kind::decompiler_diagnostic,item.location,{},item.function_entry,std::move(detail)};
                row.severity=item.severity;
                row.stale_import=!item.source_key||!project_->derived_key||*item.source_key!=*project_->derived_key;
                if(item.source_key){row.source_identity=import_identity(*item.source_key);row.source_label=import_identity_label(*item.source_key);}
                else row.source_label="Source key unavailable; this report is kept ungrouped.";
                rows_.push_back(std::move(row));++diagnostic_rows;++emitted;
            }
        }
    } else if (file_diagnostics) {
        add_diagnostics(*file_diagnostics, "File inspection", Kind::file_inspection_diagnostic);
    }
    if (!project_) {
        if (file_analysis) add_diagnostics(*file_analysis, "Code analysis", Kind::file_analysis_diagnostic);
        if (file_analysis_strings) add_diagnostics(*file_analysis_strings, "Analysis string scan", Kind::file_analysis_diagnostic);
        if (file_inspection_strings) add_diagnostics(*file_inspection_strings, "Inspection string scan", Kind::file_analysis_diagnostic);
    }
    const auto add_producer = [&](const std::vector<AnalysisIssueDiagnostic> *items, Kind kind) {
        if (!items) return;
        for (std::size_t i = 0; i < std::min(max_loader_rows, items->size()) && diagnostic_rows < diagnostic_budget; ++i) {
            const auto &item = (*items)[i];
            wxString detail = text(item.source) + " " + severity_text(item.severity) + ": " + preview_text(item.message, 4096);
            Row row{kind, item.address, {}, item.function_entry, std::move(detail)};
            row.severity = item.severity;
            if (kind == Kind::type_import_diagnostic || kind == Kind::decompiler_diagnostic) {
                row.stale_import = !item.source_key || !project_ || !project_->derived_key || *item.source_key != *project_->derived_key;
                if (item.source_key) {
                    row.source_identity = import_identity(*item.source_key);
                    row.source_label = import_identity_label(*item.source_key);
                } else {
                    row.source_label = "Source key unavailable; this report is kept ungrouped.";
                }
            }
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
    std::map<std::string, std::size_t, std::less<>> review_key_counts;
    for (const auto &row : rows_) ++review_key_counts[review_key(row)];
    std::map<std::string, std::uint64_t, std::less<>> review_key_occurrences;
    for (auto &row : rows_) {
        const auto key = review_key(row);
        if (review_key_counts[key] > 1)
            row.duplicate_ordinal = ++review_key_occurrences[key];
    }
    row_review_keys_.reserve(rows_.size());
    for (const auto &row : rows_) row_review_keys_.push_back(review_key(row));
    if (reviewed_) {
        const auto previous_count = reviewed_->size();
        std::unordered_set<std::string> current_keys(row_review_keys_.begin(), row_review_keys_.end());
        std::erase_if(*reviewed_, [&](const std::string &key) { return !current_keys.contains(key); });
        if (reviewed_->size() != previous_count && reviewed_changed) {
            std::vector<std::string> keys(reviewed_->begin(), reviewed_->end());
            std::sort(keys.begin(), keys.end());
            reviewed_changed(std::move(keys));
        }
    }
    render();
}

wxString AnalysisIssuesView::cell(std::size_t row, int column) const {
    const auto &item = rows_[row];
    const auto *image = active_image();
    switch (column) {
    case 0: return kind_text(item.kind);
    case 1: return severity_text(item.severity);
    case 2: return reviewed_ && row < row_review_keys_.size() && reviewed_->contains(row_review_keys_[row])
                        ? "Reviewed" : "Open";
    case 3: return item.address ? location_text(*item.address, image) : wxString{};
    case 4: return item.related ? location_text(*item.related, image) : wxString{};
    case 5: return item.function_entry ? location_text(*item.function_entry, image) : wxString{};
    default: {
        const auto encoded = item.detail.ToUTF8();
        wxString detail = encoded.data() ? preview_text(std::string_view(encoded.data(), encoded.length()), 768) : wxString{};
        if (item.kind == Kind::type_import_diagnostic)
            detail = (item.stale_import
                ? (item.source_identity.empty() ? "STALE IMPORT REPORT (source key unavailable; ungrouped) — " : "STALE IMPORT REPORT — ")
                : "Current import report — ") + detail;
        if (item.kind == Kind::minidump_context_diagnostic)
            detail = (item.stale_import
                ? (item.source_identity.empty() ? "STALE LOADER REPORT (source key unavailable; ungrouped) — " : "STALE LOADER REPORT — ")
                : "Current loader report — ") + detail;
        if (item.kind == Kind::decompiler_diagnostic)
            detail = (item.stale_import
                ? (item.source_identity.empty() ? "STALE DECOMPILER REPORT (source key unavailable; ungrouped) — " : "STALE DECOMPILER REPORT — ")
                : "Current decompiler report — ") + detail;
        return detail;
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
    result += "# Review state\t" + tsv_field(review_filter_->GetStringSelection()) + "\n";
    result += "# Location\t" + tsv_field(location_filter_->GetStringSelection()) + "\n";
    result += "# Search\t" + tsv_field(search_->GetValue()) + "\n";
    result += "# Scope\t" + tsv_field(scope_entry_
        ? "Function " + location_text(*scope_entry_, active_image())
        : wxString("All recovered functions")) + "\n";
    if (scope_entry_ && (!scope_available_ || scope_partial_))
        result += "# Scope coverage\tFunction is unavailable or chunk coverage is partial\n";
    if (capped_)
        result += "# Coverage\tCapped at 20,000 findings and 100,000 functions\n";
    result += "finding\tseverity\treview\taddress\trelated\tfunction\tdetails\n";
    for (const auto index : visible_rows_) {
        const auto &item = rows_[index];
        const std::array<wxString, 7> fields{kind_text(item.kind), severity_text(item.severity), cell(index, 2),
                                             cell(index, 3), cell(index, 4), cell(index, 5), cell(index, 6)};
        for (std::size_t column = 0; column < fields.size(); ++column) {
            if (column) result += '\t';
            result += tsv_field(fields[column]);
        }
        result += '\n';
    }
    return result;
}

std::optional<std::string> AnalysisIssuesView::export_json_text(std::size_t row_limit,
                                                                std::size_t output_limit) const {
    std::string output;
    const auto append = [&](std::string_view value) {
        if (value.size() > output_limit - output.size()) return false;
        output.append(value);
        return true;
    };
    const auto quoted = [&](const wxString &value) {
        return json_quote(utf8_text(value));
    };
    const auto append_quoted = [&](std::string_view key, const wxString &value, bool comma = true) {
        return append(comma ? "," : "") && append(json_quote(key)) && append(":") && append(quoted(value));
    };
    if (!append("{\"schema\":\"hexlab.analysis-findings\",\"version\":1,\"scope\":{"))
        return {};
    if (!append_quoted("filter", filter_->GetStringSelection(), false) ||
        !append_quoted("severity", severity_->GetStringSelection(), true) ||
        !append_quoted("review", review_filter_->GetStringSelection(), true) ||
        !append_quoted("location", location_filter_->GetStringSelection(), true) ||
        !append_quoted("search", preview_text(utf8_text(search_->GetValue()), 4096), true) ||
        !append(",\"function\":")) return {};
    if (scope_entry_) {
        if (!append(json_quote(utf8_text(location_text(*scope_entry_, active_image()))))) return {};
    } else if (!append("null")) return {};
    const auto copied_rows = std::min(row_limit, visible_rows_.size());
    if (!append(std::string(",\"scope_partial\":") + (scope_entry_ && (!scope_available_ || scope_partial_) ? "true" : "false") +
                ",\"capped\":" + (capped_ ? "true" : "false") +
                ",\"visible_rows\":" + std::to_string(visible_rows_.size()) +
                ",\"copied_rows\":" + std::to_string(copied_rows) +
                ",\"rows_truncated\":" + (copied_rows < visible_rows_.size() ? "true" : "false") +
                "},\"rows\":[")) return {};

    bool first_row = true;
    for (std::size_t visible = 0; visible < copied_rows; ++visible) {
        const auto index = visible_rows_[visible];
        if (index >= rows_.size()) return {};
        const auto &row = rows_[index];
        if (!first_row && !append(",")) return {};
        first_row = false;
        if (!append("{") || !append_quoted("finding", kind_text(row.kind), false) ||
            !append_quoted("severity", severity_text(row.severity)) ||
            !append(std::string(",\"reviewed\":") + (is_reviewed(row) ? "true" : "false"))) return {};
        const auto append_location = [&](std::string_view key, const std::optional<Address> &address) {
            if (!append(",") || !append(json_quote(key)) || !append(":")) return false;
            return address ? append(json_quote(utf8_text(location_text(*address, active_image())))) : append("null");
        };
        if (!append_location("address", row.address) || !append_location("related", row.related) ||
            !append_location("function", row.function_entry)) return {};
        if (!append(std::string(",\"source_current\":") +
                    (row.source_identity.empty() ? "null" : row.stale_import ? "false" : "true")) ||
            !append(",\"source_identity\":")) return {};
        if (row.source_identity.empty()) {
            if (!append("null")) return {};
        } else if (!append(json_quote(row.source_identity))) return {};
        if (!append(",\"source_label\":")) return {};
        if (row.source_label.empty()) {
            if (!append("null")) return {};
        } else if (!append(json_quote(utf8_text(row.source_label)))) return {};
        const auto details = preview_text(utf8_text(row.detail), 4096);
        if (!append(",\"details\":") || !append(json_quote(utf8_text(details))) || !append("}")) return {};
    }
    if (!append("]}\n")) return {};
    return output;
}

void AnalysisIssuesView::export_visible() {
    if (visible_rows_.empty())
        return;
    const auto export_document = document_;
    const auto export_project = project_;
    const auto export_document_snapshot = document_snapshot_;
    auto protected_paths = export_project ? export_project->protected_paths : std::vector<std::filesystem::path>{};
    if (!export_project && export_document_snapshot) {
        if (const auto file = std::dynamic_pointer_cast<const FileStorage>(export_document_snapshot->input_storage))
            protected_paths.push_back(file->backing_path());
    }
    wxFileDialog dialog(this, "Export visible analysis findings", "", "analysis-findings.tsv",
                        "TSV files (*.tsv)|*.tsv|JSON files (*.json)|*.json|All files (*.*)|*.*",
                        wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    if (dialog.ShowModal() != wxID_OK)
        return;
    // Snapshot publication and tab changes can occur while the native save
    // dialog is open. Do not write a report for a view that is no longer active.
    if (document_ != export_document || project_ != export_project ||
        document_snapshot_ != export_document_snapshot) {
        wxMessageBox("The active document or analysis changed while the save dialog was open. "
                     "No findings were exported; review the current findings and try again.",
                     "Export analysis findings", wxOK | wxICON_WARNING, this);
        return;
    }
    std::string encoded;
    if (dialog.GetFilterIndex() == 1) {
        const auto json = export_json_text();
        if (!json) {
            wxMessageBox("The visible JSON report exceeds the 16 MiB export limit.",
                         "Export analysis findings", wxOK | wxICON_WARNING, this);
            return;
        }
        encoded = *json;
    } else {
        encoded = utf8_text(export_text());
    }
    auto output_path = std::filesystem::path(dialog.GetPath().ToStdWstring());
    output_path.replace_extension(dialog.GetFilterIndex() == 1 ? ".json" : ".tsv");
    auto publication = FilePublication::create(std::move(output_path), ExistingFilePolicy::replace,
                                               protected_paths, {});
    if (!publication) {
        wxMessageBox(text(publication.error().message), "Export analysis findings", wxOK | wxICON_ERROR, this);
        return;
    }
    const auto written = publication.value()->append(std::as_bytes(std::span(encoded.data(), encoded.size())));
    if (!written) {
        wxMessageBox(text(written.error().message), "Export analysis findings", wxOK | wxICON_ERROR, this);
        return;
    }
    const auto published = publication.value()->publish();
    if (!published)
        wxMessageBox(text(published.error().message), "Export analysis findings", wxOK | wxICON_ERROR, this);
}

void AnalysisIssuesView::copy_visible() {
    if (visible_rows_.empty()) return;
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        status_->SetLabel("Could not open the clipboard; no findings were copied.");
        return;
    }
    constexpr std::size_t clipboard_row_limit = 128;
    const auto count = std::min(visible_rows_.size(), clipboard_row_limit);
    wxString output = "# HexLab analysis findings (TSV; escaped backslash, tab, CR and LF)\n";
    output += "# Rows\t" + wxString::Format("%llu copied / %llu visible / %llu loaded",
        static_cast<unsigned long long>(count),
        static_cast<unsigned long long>(visible_rows_.size()),
        static_cast<unsigned long long>(rows_.size())) + "\n";
    output += "# Filter\t" + tsv_field(filter_->GetStringSelection()) + "\n";
    output += "# Severity\t" + tsv_field(severity_->GetStringSelection()) + "\n";
    output += "# Review state\t" + tsv_field(review_filter_->GetStringSelection()) + "\n";
    output += "# Location\t" + tsv_field(location_filter_->GetStringSelection()) + "\n";
    output += "# Search\t" + tsv_field(search_->GetValue()) + "\n";
    output += "# Scope\t" + tsv_field(scope_entry_
        ? "Function " + location_text(*scope_entry_, active_image())
        : wxString("All recovered functions")) + "\n";
    if (count < visible_rows_.size())
        output += "# Coverage\tClipboard bounded to the first 128 visible findings; narrow filters to copy another page\n";
    output += "finding\tseverity\treview\taddress\trelated\tfunction\tdetails\n";
    for (std::size_t visible = 0; visible < count; ++visible) {
        const auto index = visible_rows_[visible];
        const auto &item = rows_[index];
        const std::array<wxString, 7> fields{kind_text(item.kind), severity_text(item.severity), cell(index, 2),
            cell(index, 3), cell(index, 4), cell(index, 5), cell(index, 6)};
        for (std::size_t column = 0; column < fields.size(); ++column) {
            if (column) output += '\t';
            output += tsv_field(fields[column]);
        }
        output += '\n';
    }
    const auto copied = wxTheClipboard->SetData(new wxTextDataObject(output));
    wxTheClipboard->Close();
    if (copied)
        status_->SetLabel(wxString::Format("Copied %llu of %llu visible findings as TSV%s",
            static_cast<unsigned long long>(count),
            static_cast<unsigned long long>(visible_rows_.size()),
            count < visible_rows_.size() ? " (clipboard cap reached)" : ""));
    else
        status_->SetLabel("The clipboard rejected the findings report.");
}

void AnalysisIssuesView::copy_visible_json() {
    if (visible_rows_.empty()) return;
    constexpr std::size_t clipboard_row_limit = 128;
    constexpr std::size_t clipboard_byte_limit = 1024 * 1024;
    const auto output = export_json_text(clipboard_row_limit, clipboard_byte_limit);
    if (!output) {
        status_->SetLabel("The visible JSON report exceeds the 1 MiB clipboard limit; narrow the filters.");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        status_->SetLabel("Could not open the clipboard; no findings were copied.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(output->c_str())));
    wxTheClipboard->Close();
    if (copied) {
        const auto count = std::min(clipboard_row_limit, visible_rows_.size());
        status_->SetLabel(wxString::Format("Copied %llu of %llu visible findings as JSON%s",
            static_cast<unsigned long long>(count),
            static_cast<unsigned long long>(visible_rows_.size()),
            count < visible_rows_.size() ? " (clipboard row cap reached)" : ""));
    } else {
        status_->SetLabel("The clipboard rejected the findings report.");
    }
}

void AnalysisIssuesView::copy_issue_json() {
    const auto *row = selected_issue();
    if (!row) return;
    constexpr std::size_t clipboard_limit = 64 * 1024;
    std::string output;
    const auto append = [&](std::string_view value) {
        if (value.size() > clipboard_limit - output.size()) return false;
        output.append(value);
        return true;
    };
    const auto append_location = [&](std::string_view key, const std::optional<Address> &address) {
        if (!append(",") || !append(json_quote(key)) || !append(":")) return false;
        return address ? append(json_quote(utf8_text(location_text(*address, active_image())))) : append("null");
    };
    const auto details = preview_text(utf8_text(row->detail), 4096);
    static constexpr char hex[] = "0123456789abcdef";
    std::string source_identity_hex;
    source_identity_hex.reserve(row->source_identity.size() * 2);
    for (const unsigned char byte : row->source_identity) {
        source_identity_hex.push_back(hex[byte >> 4]);
        source_identity_hex.push_back(hex[byte & 0x0f]);
    }
    const bool serialized = append("{\"schema\":\"hexlab.analysis-finding\",\"version\":1,\"finding\":{") &&
        append("\"kind\":") && append(json_quote(utf8_text(kind_text(row->kind)))) &&
        append(",\"severity\":") && append(json_quote(utf8_text(severity_text(row->severity)))) &&
        append(std::string(",\"reviewed\":") + (is_reviewed(*row) ? "true" : "false")) &&
        append_location("address", row->address) && append_location("related", row->related) &&
        append_location("function", row->function_entry) &&
        append(std::string(",\"source_current\":") +
            (row->source_identity.empty() ? "null" : row->stale_import ? "false" : "true")) &&
        append(",\"source_identity_hex\":") &&
        append(row->source_identity.empty() ? "null" : json_quote(source_identity_hex)) &&
        append(",\"source_label\":") &&
        append(row->source_label.empty() ? "null" : json_quote(utf8_text(row->source_label))) &&
        append(",\"details\":") && append(json_quote(utf8_text(details))) && append("}}\n");
    if (!serialized) {
        status_->SetLabel("Selected finding JSON exceeds the 64 KiB clipboard limit; no data was copied.");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        status_->SetLabel("Could not open the clipboard; no finding JSON was copied.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(output.c_str())));
    wxTheClipboard->Close();
    status_->SetLabel(copied ? "Copied one finding as hexlab.analysis-finding.v1 JSON." :
                              "Could not copy finding JSON to the clipboard.");
}

void AnalysisIssuesView::render() {
    visible_rows_.clear();
    const auto selected_filter = filter_ ? filter_->GetSelection() : 0;
    const auto selected_severity = severity_ ? severity_->GetSelection() : 0;
    const auto selected_review_filter = review_filter_ ? review_filter_->GetSelection() : 0;
    const auto selected_location_filter = location_filter_ ? location_filter_->GetSelection() : 0;
    auto query = search_ ? search_->GetValue() : wxString{};
    query.MakeLower();
    for (std::size_t index = 0; index < rows_.size(); ++index) {
        if (!matches_scope(rows_[index])) continue;
        const bool reviewed = reviewed_ && index < row_review_keys_.size() &&
                              reviewed_->contains(row_review_keys_[index]);
        if ((selected_review_filter == 1 && reviewed) || (selected_review_filter == 2 && !reviewed))
            continue;
        if (selected_review_filter == 3 && (reviewed || rows_[index].severity == DiagnosticSeverity::info))
            continue;
        const auto &location_row = rows_[index];
        const bool has_location = location_row.address || location_row.related || location_row.function_entry;
        if (selected_location_filter == 1 && !has_location) continue;
        if (selected_location_filter == 2 && has_location) continue;
        if (selected_location_filter == 3 && !location_row.address) continue;
        if (selected_location_filter == 4 && !location_row.related) continue;
        if (selected_location_filter == 5 && !location_row.function_entry) continue;
        const auto kind = rows_[index].kind;
        if (selected_filter == 1 && kind != Kind::function_stop && kind != Kind::incomplete_function)
            continue;
        if (selected_filter == 2 && kind != Kind::candidate)
            continue;
        if (selected_filter == 3 && kind != Kind::overlap)
            continue;
        const bool any_loader_diagnostic = kind == Kind::loader_diagnostic ||
                                           kind == Kind::minidump_context_diagnostic ||
                                           kind == Kind::runtime_relocation_diagnostic ||
                                           kind == Kind::file_inspection_diagnostic;
        if (selected_filter == 4 && !any_loader_diagnostic) continue;
        if (selected_filter == 5 && kind != Kind::type_import_diagnostic) continue;
        if (selected_filter == 6 && kind != Kind::decompiler_diagnostic) continue;
        if (selected_filter == 7 && kind != Kind::runtime_relocation_diagnostic) continue;
        if (selected_filter == 8 && kind != Kind::file_inspection_diagnostic) continue;
        if (selected_filter == 9 && kind != Kind::file_analysis_diagnostic) continue;
        if (selected_filter == 10 && !rows_[index].stale_import) continue;
        if ((selected_severity == 1 && rows_[index].severity != DiagnosticSeverity::error) ||
            (selected_severity == 2 && rows_[index].severity != DiagnosticSeverity::warning) ||
            (selected_severity == 3 && rows_[index].severity != DiagnosticSeverity::info))
            continue;
        if (!query.empty()) {
            wxString aggregate = kind_text(kind) + " " +
                                 severity_text(rows_[index].severity) + " " +
                                 (reviewed ? wxString("Reviewed") : wxString("Open")) + " " +
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
        else
            table_->clear_selection();
    } else {
        table_->clear_selection();
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
        if (location_filter_ && location_filter_->GetSelection() != 0)
            status += "; " + location_filter_->GetStringSelection();
        std::size_t errors = 0, warnings = 0, info = 0, reviewed = 0;
        for (const auto index : visible_rows_) {
            if (reviewed_ && index < row_review_keys_.size() && reviewed_->contains(row_review_keys_[index]))
                ++reviewed;
            switch (rows_[index].severity) {
            case DiagnosticSeverity::error: ++errors; break;
            case DiagnosticSeverity::warning: ++warnings; break;
            case DiagnosticSeverity::info: ++info; break;
            }
        }
        status += wxString::Format("; %llu errors, %llu warnings, %llu info",
                                   static_cast<unsigned long long>(errors),
                                   static_cast<unsigned long long>(warnings),
                                   static_cast<unsigned long long>(info));
        status += wxString::Format("; %llu reviewed, %llu open",
                                   static_cast<unsigned long long>(reviewed),
                                   static_cast<unsigned long long>(visible_rows_.size() - reviewed));
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
                return (row.kind == Kind::loader_diagnostic || row.kind == Kind::minidump_context_diagnostic || row.kind == Kind::type_import_diagnostic ||
                        row.kind == Kind::decompiler_diagnostic || row.kind == Kind::file_analysis_diagnostic) && !row.address;
            }))
            status += "; unlocated diagnostics are hidden by function scope";
        status_->SetLabel(status);
    }
    export_->Enable(!visible_rows_.empty());
    copy_visible_->Enable(!visible_rows_.empty());
    copy_visible_json_->Enable(!visible_rows_.empty());
    std::size_t open_count = 0, reviewed_count = 0;
    for (const auto index : visible_rows_) {
        const bool reviewed = reviewed_ && index < row_review_keys_.size() &&
                              reviewed_->contains(row_review_keys_[index]);
        reviewed ? ++reviewed_count : ++open_count;
    }
    review_visible_->Enable(open_count != 0);
    reopen_visible_->Enable(reviewed_count != 0);
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

std::string AnalysisIssuesView::review_key(const Row &row) {
    std::string key;
    const auto number = [&key](std::uint64_t value) {
        for (unsigned shift = 0; shift < 64; shift += 8)
            key.push_back(static_cast<char>((value >> shift) & 0xff));
    };
    const auto address = [&key, &number](const std::optional<Address> &value) {
        key.push_back(value ? '\1' : '\0');
        if (value) {
            number(value->space.value);
            number(value->offset);
        }
    };
    key.push_back(static_cast<char>(row.kind));
    key.push_back(static_cast<char>(row.severity));
    address(row.address);
    address(row.related);
    address(row.function_entry);
    const auto encoded = row.detail.ToUTF8();
    number(encoded.data() ? encoded.length() : 0);
    if (encoded.data()) key.append(encoded.data(), encoded.length());
    if (!row.source_identity.empty()) {
        key.push_back('\xfe');
        number(row.source_identity.size());
        key += row.source_identity;
    } else if (row.stale_import) {
        // Missing-key rows cannot be assigned to a source snapshot. Namespace
        // them separately so old review marks never inherit a fabricated match.
        key.append("\xfdsource-key-unavailable");
    }
    if (row.duplicate_ordinal != 0) {
        key.push_back('\xff');
        number(row.duplicate_ordinal);
    }
    return key;
}

bool AnalysisIssuesView::is_reviewed(const Row &row) const {
    return reviewed_ && reviewed_->contains(review_key(row));
}

void AnalysisIssuesView::toggle_reviewed() {
    const auto *row = selected_issue();
    if (!row) return;
    if (!reviewed_)
        reviewed_ = std::make_shared<std::unordered_set<std::string>>();
    const auto key = review_key(*row);
    if (reviewed_->contains(key)) {
        reviewed_->erase(key);
    } else {
        if (reviewed_->size() >= max_rows) {
            wxMessageBox("The per-document review list reached its 20,000-finding limit. Close and reopen the document to start a fresh review session.",
                         "Analysis issue review", wxOK | wxICON_WARNING, this);
            return;
        }
        reviewed_->insert(key);
    }
    selection_key_ = *row;
    render();
    remember_preference();
    if (reviewed_changed && project_ && project_->mode != database::ProjectMode::read_only) {
        std::vector<std::string> keys(reviewed_->begin(), reviewed_->end());
        std::sort(keys.begin(), keys.end());
        reviewed_changed(std::move(keys));
    }
}

void AnalysisIssuesView::set_visible_reviewed(bool reviewed) {
    if (visible_rows_.empty()) return;
    if (!reviewed_)
        reviewed_ = std::make_shared<std::unordered_set<std::string>>();

    std::unordered_set<std::string> additions;
    if (reviewed) {
        additions.reserve(visible_rows_.size());
        for (const auto index : visible_rows_) {
            if (index >= row_review_keys_.size()) continue;
            const auto &key = row_review_keys_[index];
            if (!reviewed_->contains(key)) additions.insert(key);
        }
        if (reviewed_->size() + additions.size() > max_rows) {
            wxMessageBox("Reviewing the visible findings would exceed the 20,000-finding per-document review limit. Narrow the filters and try again.",
                         "Analysis issue review", wxOK | wxICON_WARNING, this);
            return;
        }
    }

    bool changed = false;
    if (reviewed) {
        for (const auto &key : additions) changed = reviewed_->insert(key).second || changed;
    } else {
        for (const auto index : visible_rows_) {
            if (index < row_review_keys_.size())
                changed = reviewed_->erase(row_review_keys_[index]) != 0 || changed;
        }
    }
    if (!changed) return;

    render();
    remember_preference();
    if (reviewed_changed && project_ && project_->mode != database::ProjectMode::read_only) {
        std::vector<std::string> keys(reviewed_->begin(), reviewed_->end());
        std::sort(keys.begin(), keys.end());
        reviewed_changed(std::move(keys));
    }
}

wxString AnalysisIssuesView::finding_text(const Row &row) const {
    const auto *image = active_image();
    wxString report = kind_text(row.kind) + "\nSeverity: " + severity_text(row.severity) + "\nAddress: " +
                      (row.address ? location_text(*row.address, image) : wxString("not location-specific"));
    report += "\nReview: " + wxString(is_reviewed(row) ? "Reviewed" : "Open");
    if (row.kind == Kind::type_import_diagnostic || row.kind == Kind::decompiler_diagnostic || row.kind == Kind::minidump_context_diagnostic) {
        report += row.source_identity.empty() && row.stale_import
            ? "\nDiagnostic source identity: unavailable; this finding is ungrouped"
            : row.stale_import ? "\nDiagnostic source identity: stale" : "\nDiagnostic source identity: current";
        if (!row.source_label.empty()) report += "\nDiagnostic source: " + row.source_label;
    }
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
        copy_issue_json_->Enable(false);
        mark_reviewed_->Enable(false);
        export_->Enable(!visible_rows_.empty());
        detail_->ChangeValue("Select a finding to inspect its details. Previous/Next follow the filtered findings; Alt+Up/Down also work within this pane.");
        return;
    }
    const auto *image = active_image();
    wxString detail = kind_text(row->kind) + " (" +
                      wxString(is_reviewed(*row) ? "reviewed" : "open") + ") at " +
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
    copy_issue_json_->Enable(true);
    mark_reviewed_->SetLabel(is_reviewed(*row) ? "Reopen finding" : "Mark reviewed");
    mark_reviewed_->Enable(true);
    export_->Enable(!visible_rows_.empty());
}

} // namespace hexlab::desktop
