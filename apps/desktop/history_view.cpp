#include "history_view.hpp"
#include "project_view.hpp"
#include "hexlab/image/file_publication.hpp"

#include <wx/sizer.h>
#include <wx/listctrl.h>
#include <wx/checkbox.h>
#include <wx/dialog.h>
#include <wx/filedlg.h>
#include <wx/msgdlg.h>
#include <wx/textctrl.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>

#include <algorithm>
#include <chrono>
#include <charconv>
#include <future>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <thread>

namespace hexlab::desktop {
namespace {
constexpr std::size_t history_page_size = 256;
constexpr std::size_t preview_step_budget = database::history_preview_step_limit;
constexpr std::size_t preview_payload_budget = database::history_preview_payload_limit;

wxString hex_value(std::uint64_t value) {
    return wxString::Format("0x%llx", static_cast<unsigned long long>(value));
}

wxString change_text(const database::HistoryEntry& entry) {
    if (entry.byte_change && entry.decision_change) return "bytes, decisions";
    if (entry.byte_change) return "bytes";
    if (entry.decision_change) return "decisions";
    return "metadata";
}

wxString path_text(const std::filesystem::path& path) {
    const auto encoded = path.generic_u8string();
    return text(std::string_view(reinterpret_cast<const char*>(encoded.data()), encoded.size()));
}

std::string json_quote(std::string_view value) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string output;
    output.reserve(value.size() + 2);
    output.push_back('"');
    for (const unsigned char byte : value) {
        switch (byte) {
        case '"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\b': output += "\\b"; break;
        case '\f': output += "\\f"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (byte < 0x20) {
                output += "\\u00";
                output.push_back(hex[byte >> 4]);
                output.push_back(hex[byte & 0xf]);
            } else output.push_back(static_cast<char>(byte));
        }
    }
    output.push_back('"');
    return output;
}
}

HistoryView::HistoryView(wxWindow* parent) : wxPanel(parent), timer_(this) {
    auto* root = new wxBoxSizer(wxVERTICAL);
    root->Add(new wxStaticText(this, wxID_ANY,
        "Durable undo/redo history. Selecting a step opens a read-only projection and never changes the live project."),
        0, wxEXPAND | wxALL, FromDIP(5));

    auto* controls = new wxBoxSizer(wxHORIZONTAL);
    refresh_ = new wxButton(this, wxID_ANY, "Refresh history");
    next_page_ = new wxButton(this, wxID_ANY, "Load next page");
    initial_state_ = new wxButton(this, wxID_ANY, "Preview initial state");
    compare_previous_ = new wxButton(this, wxID_ANY, "Compare with previous step");
    compare_current_ = new wxButton(this, wxID_ANY, "Compare with current project");
    audit_ = new wxButton(this, wxID_ANY, "Audit history");
    copy_audit_ = new wxButton(this, wxID_ANY, "Copy audit result");
    copy_audit_json_ = new wxButton(this, wxID_ANY, "Copy audit JSON");
    save_audit_ = new wxButton(this, wxID_ANY, "Save audit report...");
    refresh_->SetName("history-refresh");
    next_page_->SetName("history-next-page");
    initial_state_->SetName("history-preview-initial");
    compare_previous_->SetName("history-compare-previous");
    compare_current_->SetName("history-compare-current");
    audit_->SetName("history-audit");
    copy_audit_->SetName("history-copy-audit");
    copy_audit_json_->SetName("history-copy-audit-json");
    save_audit_->SetName("history-save-audit");
    next_page_->Enable(false);
    controls->Add(refresh_, 0, wxRIGHT, FromDIP(4));
    controls->Add(next_page_, 0, wxRIGHT, FromDIP(4));
    controls->Add(initial_state_, 0);
    controls->Add(compare_previous_, 0, wxLEFT, FromDIP(4));
    controls->Add(compare_current_, 0, wxLEFT, FromDIP(4));
    controls->Add(audit_, 0, wxLEFT, FromDIP(4));
    controls->Add(copy_audit_, 0, wxLEFT, FromDIP(4));
    controls->Add(copy_audit_json_, 0, wxLEFT, FromDIP(4));
    controls->Add(save_audit_, 0, wxLEFT, FromDIP(4));
    compare_previous_->Enable(false);
    compare_current_->Enable(false);
    audit_->Enable(false);
    copy_audit_->Enable(false);
    copy_audit_json_->Enable(false);
    save_audit_->Enable(false);
    root->Add(controls, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(5));
    verify_audit_replay_ = new wxCheckBox(this, wxID_ANY, "Verify applied branch replay after structural audit");
    verify_audit_replay_->SetName("history-audit-verify-replay");
    verify_audit_replay_->SetToolTip(
        "Read-only: reverse the current applied history to step zero and require empty user state. "
        "Limited to 4096 applied steps and 64 MiB; redo-only steps receive structural audit only.");
    verify_audit_replay_->Enable(false);
    root->Add(verify_audit_replay_, 0, wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(5));

    status_ = new wxStaticText(this, wxID_ANY, "Open a project to inspect its history.");
    status_->SetName("history-status");
    root->Add(status_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(5));
    source_status_ = new wxStaticText(this, wxID_ANY, "Current source integrity: not checked.");
    source_status_->SetName("history-source-integrity-status");
    source_status_->SetToolTip("Read-only check of the recorded external source against the input size and SHA-256 pinned in this project. Limited to 256 MiB.");
    root->Add(source_status_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(5));

    auto* filter_row = new wxBoxSizer(wxHORIZONTAL);
    filter_row->Add(new wxStaticText(this, wxID_ANY, "Filter loaded steps:"), 0,
                    wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(5));
    history_filter_ = new wxTextCtrl(this, wxID_ANY, wxEmptyString, wxDefaultPosition,
                                     wxDefaultSize, wxTE_PROCESS_ENTER);
    history_filter_->SetName("history-filter");
    history_filter_->SetHint("step, group, bytes, decisions, metadata, applied, redo");
    filter_row->Add(history_filter_, 1, wxEXPAND);
    history_filter_status_ = new wxStaticText(this, wxID_ANY, "0 loaded");
    history_filter_status_->SetName("history-filter-status");
    filter_row->Add(history_filter_status_, 0, wxALIGN_CENTER_VERTICAL | wxLEFT, FromDIP(5));
    root->Add(filter_row, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(5));

    auto* save_controls = new wxBoxSizer(wxHORIZONTAL);
    save_copy_ = new wxButton(this, wxID_ANY, "Save selected step as project...");
    open_copy_ = new wxButton(this, wxID_ANY, "Open saved project");
    cancel_save_ = new wxButton(this, wxID_ANY, "Cancel recovered copy");
    save_copy_->SetName("history-save-copy");
    open_copy_->SetName("history-open-saved-copy");
    cancel_save_->SetName("history-cancel-save");
    save_copy_->Enable(false);
    open_copy_->Enable(false);
    cancel_save_->Enable(false);
    save_controls->Add(save_copy_, 0, wxRIGHT, FromDIP(4));
    save_controls->Add(open_copy_, 0, wxRIGHT, FromDIP(4));
    save_controls->Add(cancel_save_, 0);
    root->Add(save_controls, 0, wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(5));
    save_status_ = new wxStaticText(this, wxID_ANY,
        "Select a step in a saved project to save an independent recovered copy.");
    save_status_->SetName("history-save-status");
    root->Add(save_status_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(5));

    entries_ = new VirtualTable(this, "history-entries", {"Step", "Group", "Changes", "State"});
    entries_->SetColumnWidth(0, FromDIP(82));
    entries_->SetColumnWidth(1, FromDIP(82));
    entries_->SetColumnWidth(2, FromDIP(150));
    root->Add(entries_, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(5));

    preview_status_ = new wxStaticText(this, wxID_ANY, "Select a history step to preview it.");
    preview_status_->SetName("history-preview-status");
    root->Add(preview_status_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(5));
    preview_items_ = new VirtualTable(this, "history-preview-state", {"Kind", "Historical location", "Name / ID", "Details"});
    preview_items_->SetColumnWidth(0, FromDIP(105));
    preview_items_->SetColumnWidth(1, FromDIP(145));
    preview_items_->SetColumnWidth(2, FromDIP(170));
    navigate_patch_ = new wxButton(this, wxID_ANY, "Jump to selected historical location in the current document");
    navigate_patch_->SetName("history-navigate-item");
    navigate_patch_->Enable(false);
    auto* preview_controls = new wxBoxSizer(wxHORIZONTAL);
    preview_controls->Add(navigate_patch_, 0, wxALL, FromDIP(3));
    root->Add(preview_items_, 1, wxEXPAND | wxLEFT | wxRIGHT, FromDIP(5));
    root->Add(preview_controls, 0, wxALIGN_RIGHT | wxBOTTOM, FromDIP(4));
    SetSizer(root);

    refresh_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (!actor_) return;
        cancel_pending();
        audit_in_progress_ = false;
        audit_resume_available_ = false;
        audit_structural_complete_ = false;
        audit_source_identity_check_ = database::HistorySourceIdentityCheck::not_checked;
        update_source_status();
        verify_audit_replay_->Enable(true);
        audit_next_after_step_ = 0;
        audit_->SetLabel("Audit history");
        audit_report_.clear();
        copy_audit_->Enable(false);
        copy_audit_json_->Enable(false);
        save_audit_->Enable(false);
        rows_.clear();
        page_.reset();
        preview_.reset();
        comparison_base_.reset();
        comparison_current_.reset();
        selected_step_.reset();
        selected_preview_row_.reset();
        render_entries();
        render_preview();
        request_page(0);
    });
    next_page_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (page_ && page_->has_more && !pending_ && !audit_in_progress_) request_page(page_->next_after_step);
    });
    initial_state_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { request_preview(0); });
    compare_previous_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { compare_with_previous(); });
    compare_current_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { compare_with_current(); });
    audit_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (audit_in_progress_) stop_audit();
        else begin_audit();
    });
    copy_audit_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (audit_report_.empty()) return;
        if (!wxTheClipboard || !wxTheClipboard->Open()) {
            status_->SetLabel("The system clipboard is unavailable; the saved audit result is still available.");
            return;
        }
        const bool copied = wxTheClipboard->SetData(new wxTextDataObject(audit_report_));
        wxTheClipboard->Close();
        status_->SetLabel(copied ? "Copied the last history audit result to the clipboard."
                                 : "Could not copy the last history audit result.");
    });
    copy_audit_json_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { copy_audit_json(); });
    save_audit_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (audit_report_.empty() || !project_ || !project_->state) return;
        const auto captured_actor = actor_;
        const auto captured_project = project_;
        const auto captured_uuid = project_->state->uuid;
        const auto captured_edit = expected_edit_;
        const auto captured_result = audit_report_;
        const auto captured_cursor = page_ ? page_->history_cursor : 0;
        const auto captured_count = page_ ? page_->history_count : 0;
        const bool captured_replay = audit_verify_replay_;
        const auto actor_view = captured_actor ? std::optional<ActorView>{captured_actor->view()} : std::nullopt;
        const auto captured_project_path = actor_view ? actor_view->project_path : std::nullopt;
        auto protected_paths = captured_project->protected_paths;
        if (captured_project_path)
            protected_paths.push_back(*captured_project_path);

        std::string report = "HexLab project history audit report\n";
        report += "project_uuid: ";
        constexpr char hex[] = "0123456789abcdef";
        for (const auto byte : captured_uuid) {
            const auto value = std::to_integer<unsigned char>(byte);
            report.push_back(hex[value >> 4]);
            report.push_back(hex[value & 0x0f]);
        }
        report += "\nedit_revision: " + std::to_string(captured_edit);
        report += "\nhistory_cursor: " + std::to_string(captured_cursor);
        report += "\nhistory_count: " + std::to_string(captured_count);
        report += "\napplied_branch_replay_requested: ";
        report += captured_replay ? "true\n" : "false\n";
        report += "result: ";
        const auto encoded = captured_result.ToUTF8();
        if (encoded) report.append(encoded.data(), encoded.length());
        report.push_back('\n');
        if (report.size() > 16 * 1024) {
            status_->SetLabel("Audit report exceeds the 16 KiB export limit; no file was written.");
            return;
        }

        wxFileDialog dialog(this, "Save history audit report", wxEmptyString,
            "history-audit.txt", "Text report (*.txt)|*.txt",
            wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
        if (dialog.ShowModal() != wxID_OK) return;

        const auto current_view = captured_actor ? std::optional<ActorView>{captured_actor->view()} : std::nullopt;
        const bool same_project = actor_ == captured_actor && project_ == captured_project &&
            expected_edit_ == captured_edit && project_ && project_->state &&
            project_->state->uuid == captured_uuid && audit_report_ == captured_result && current_view &&
            page_ && page_->history_cursor == captured_cursor && page_->history_count == captured_count &&
            audit_verify_replay_ == captured_replay &&
            current_view->project_path == captured_project_path && current_view->snapshot &&
            current_view->snapshot->state && current_view->snapshot->state->uuid == captured_uuid &&
            current_view->snapshot->state->revisions.edit == captured_edit;
        if (!same_project) {
            status_->SetLabel("The project or audit result changed while the save dialog was open; no report was written.");
            return;
        }

        auto publication = FilePublication::create(std::filesystem::path(dialog.GetPath().ToStdWstring()),
            ExistingFilePolicy::replace, protected_paths, {});
        if (!publication) {
            status_->SetLabel("Could not save the audit report: " + text(publication.error().message));
            return;
        }
        const auto written = publication.value()->append(std::as_bytes(std::span(report.data(), report.size())));
        if (!written) {
            status_->SetLabel("Could not save the audit report: " + text(written.error().message));
            return;
        }
        const auto published = publication.value()->publish();
        if (!published) {
            status_->SetLabel("Could not save the audit report: " + text(published.error().message));
            return;
        }
        status_->SetLabel(wxString("Saved audit report: ") + dialog.GetPath());
    });
    save_copy_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { save_selected_history(); });
    open_copy_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (saved_copy_path_ && open_project) open_project(*saved_copy_path_);
    });
    cancel_save_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (!history_save_) return;
        history_save_->cancellation.request_stop();
        cancel_save_->Enable(false);
        save_status_->SetLabel("Canceling recovered copy; waiting for the publication result...");
    });
    entries_->Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent&) {
        if (audit_in_progress_) return;
        const auto row = entries_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        if (row < 0 || static_cast<std::size_t>(row) >= visible_history_rows_.size()) return;
        selected_step_ = rows_[visible_history_rows_[static_cast<std::size_t>(row)]].step;
        comparison_base_.reset();
        comparison_current_.reset();
        compare_previous_->Enable(*selected_step_ > 0);
        compare_current_->Enable(bool(project_) && !pending_ && !audit_in_progress_);
        request_preview(*selected_step_);
    });
    history_filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent&) { render_entries(); });
    preview_items_->Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent&) {
        const auto row = preview_items_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        if (row < 0 || static_cast<std::size_t>(row) >= preview_rows_.size() ||
            !preview_rows_[static_cast<std::size_t>(row)].target) {
            selected_preview_row_.reset();
        } else {
            selected_preview_row_ = static_cast<std::size_t>(row);
        }
        navigate_patch_->Enable(selected_preview_row_.has_value());
    });
    navigate_patch_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (!selected_preview_row_ || *selected_preview_row_ >= preview_rows_.size() || !navigate) return;
        const auto& target = preview_rows_[*selected_preview_row_].target;
        if (target) navigate(*target);
    });
    Bind(wxEVT_TIMER, [this](wxTimerEvent&) { poll(); }, timer_.GetId());
    timer_.Start(35);
}

HistoryView::~HistoryView() {
    timer_.Stop();
    cancel_pending();
    if (history_save_) history_save_->cancellation.request_stop();
}

void HistoryView::update(std::optional<DocumentId> id, std::shared_ptr<ProjectActor> actor,
                         std::shared_ptr<const ProjectSnapshot> project) {
    if (!project || !project->state || !actor) {
        const bool had_project = bool(actor_) || bool(project_);
        cancel_pending();
        actor_.reset();
        project_.reset();
        document_id_.reset();
        saved_copy_path_.reset();
        expected_edit_ = 0;
        rows_.clear();
        page_.reset();
        preview_.reset();
        comparison_base_.reset();
        comparison_current_.reset();
        selected_step_.reset();
        selected_preview_row_.reset();
        audit_in_progress_ = false;
        audit_resume_available_ = false;
        audit_structural_complete_ = false;
        audit_source_identity_check_ = database::HistorySourceIdentityCheck::not_checked;
        update_source_status();
        verify_audit_replay_->Enable(false);
        audit_verified_ = 0;
        audit_bytes_ = 0;
        audit_next_after_step_ = 0;
        audit_report_.clear();
        copy_audit_->Enable(false);
        copy_audit_json_->Enable(false);
        save_audit_->Enable(false);
        if (had_project) {
            status_->SetLabel("Open a project to inspect its history.");
            preview_status_->SetLabel("Select a history step to preview it.");
            render_entries();
            render_preview();
        }
        next_page_->Enable(false);
        initial_state_->Enable(false);
        compare_previous_->Enable(false);
        compare_current_->Enable(false);
        audit_->Enable(false);
        audit_->SetLabel("Audit history");
        refresh_->Enable(false);
        open_copy_->Enable(false);
        return;
    }

    const auto edit_revision = project->state->revisions.edit;
    const bool changed = document_id_ != id || actor_ != actor ||
        !project_ || project_->state->uuid != project->state->uuid ||
        expected_edit_ != edit_revision;
    project_ = std::move(project);
    if (!changed) return;
    saved_copy_path_.reset();
    open_copy_->Enable(false);

    cancel_pending();
    actor_ = std::move(actor);
    document_id_ = id;
    expected_edit_ = edit_revision;
    rows_.clear();
    page_.reset();
    preview_.reset();
    comparison_base_.reset();
    comparison_current_.reset();
    selected_step_.reset();
    selected_preview_row_.reset();
    audit_in_progress_ = false;
    audit_resume_available_ = false;
    audit_structural_complete_ = false;
    audit_source_identity_check_ = database::HistorySourceIdentityCheck::not_checked;
    update_source_status();
    verify_audit_replay_->Enable(true);
    audit_verified_ = 0;
    audit_bytes_ = 0;
    audit_next_after_step_ = 0;
    audit_report_.clear();
    copy_audit_->Enable(false);
    copy_audit_json_->Enable(false);
    save_audit_->Enable(false);
    status_->SetLabel("Loading durable project history…");
    preview_status_->SetLabel("Select a history step to preview it.");
    refresh_->Enable(true);
    initial_state_->Enable(true);
    compare_previous_->Enable(false);
    compare_current_->Enable(false);
    audit_->Enable(false);
    audit_->SetLabel("Audit history");
    copy_audit_->Enable(false);
    copy_audit_json_->Enable(false);
    save_audit_->Enable(false);
    render_entries();
    render_preview();
    request_page(0);
}

void HistoryView::cancel_pending() {
    if (!pending_) return;
    if (actor_) actor_->cancel_operation(pending_->id);
    pending_.reset();
}

void HistoryView::request_page(std::uint64_t after_step) {
    if (!actor_ || pending_) return;
    pending_kind_ = PendingKind::page;
    auto submission = actor_->history_page(expected_edit_, after_step, history_page_size);
    if (!submission) { show_error(submission.error()); return; }
    pending_expected_edit_ = expected_edit_;
    pending_ = std::move(submission.value());
    status_->SetLabel("Loading durable project history…");
    next_page_->Enable(false);
}

void HistoryView::begin_audit() {
    if (!actor_ || !page_ || audit_in_progress_) return;
    cancel_pending();
    if (!audit_resume_available_) {
        audit_verified_ = 0;
        audit_bytes_ = 0;
        audit_next_after_step_ = 0;
        audit_structural_complete_ = false;
        audit_source_identity_check_ = database::HistorySourceIdentityCheck::not_checked;
        update_source_status();
        audit_verify_replay_ = verify_audit_replay_->GetValue();
    }
    audit_in_progress_ = true;
    audit_resume_available_ = false;
    audit_report_.clear();
    copy_audit_->Enable(false);
    copy_audit_json_->Enable(false);
    save_audit_->Enable(false);
    verify_audit_replay_->Enable(false);
    audit_->SetLabel("Pause audit");
    next_page_->Enable(false);
    initial_state_->Enable(false);
    compare_previous_->Enable(false);
    compare_current_->Enable(false);
    status_->SetLabel("Starting read-only history audit…");
    if (audit_structural_complete_ && audit_verify_replay_) request_audit_replay();
    else request_audit_page(audit_next_after_step_);
}

void HistoryView::stop_audit() {
    if (!audit_in_progress_) return;
    cancel_pending();
    audit_in_progress_ = false;
    audit_resume_available_ = true;
    audit_->SetLabel("Resume audit");
    next_page_->Enable(page_ && page_->has_more);
    initial_state_->Enable(bool(actor_));
    compare_previous_->Enable(selected_step_ && *selected_step_ > 0);
    compare_current_->Enable(selected_step_.has_value());
    record_audit_result(wxString::Format("Audit paused after %llu of %llu steps (%llu delta bytes verified); resume continues after step %llu.%s",
        static_cast<unsigned long long>(audit_verified_),
        static_cast<unsigned long long>(page_ ? page_->history_count : 0),
        static_cast<unsigned long long>(audit_bytes_),
        static_cast<unsigned long long>(audit_next_after_step_),
        audit_structural_complete_ ? " Structural audit passed; applied-branch replay is not complete." : ""));
}

void HistoryView::record_audit_result(const wxString& report) {
    constexpr std::size_t maximum_report_characters = 4096;
    wxString complete_report = report;
    const auto append_source_check = [&](const wxString& detail) {
        if (!complete_report.empty()) complete_report += "\n";
        complete_report += "Current external source check: ";
        complete_report += detail;
    };
    switch (audit_source_identity_check_) {
    case database::HistorySourceIdentityCheck::not_checked:
        append_source_check("not performed (the first audit page did not complete).");
        break;
    case database::HistorySourceIdentityCheck::no_recorded_path:
        append_source_check("no recorded source path is available.");
        break;
    case database::HistorySourceIdentityCheck::unavailable:
        append_source_check("the recorded source path is unavailable or unreadable.");
        break;
    case database::HistorySourceIdentityCheck::over_limit:
        append_source_check("not performed because the source exceeds the 256 MiB check limit.");
        break;
    case database::HistorySourceIdentityCheck::size_mismatch:
        append_source_check("mismatch: current file size differs from the project's pinned input size.");
        break;
    case database::HistorySourceIdentityCheck::digest_mismatch:
        append_source_check("mismatch: current file SHA-256 differs from the project's pinned input.");
        break;
    case database::HistorySourceIdentityCheck::matches:
        append_source_check("current bytes matched the project's pinned input size and SHA-256 when read. This does not establish historical source integrity.");
        break;
    }
    audit_report_ = complete_report.length() <= maximum_report_characters
        ? complete_report : complete_report.Left(maximum_report_characters);
    copy_audit_->Enable(!audit_report_.empty());
    copy_audit_json_->Enable(!audit_report_.empty());
    save_audit_->Enable(!audit_report_.empty() && project_ && project_->state);
    verify_audit_replay_->Enable(bool(actor_) && !audit_in_progress_ && !audit_resume_available_);
    status_->SetLabel(audit_report_);
}

void HistoryView::update_source_status() {
    wxString detail;
    switch (audit_source_identity_check_) {
    case database::HistorySourceIdentityCheck::not_checked:
        detail = "not checked yet (checked on the first completed audit page)"; break;
    case database::HistorySourceIdentityCheck::no_recorded_path:
        detail = "no recorded source path is available"; break;
    case database::HistorySourceIdentityCheck::unavailable:
        detail = "recorded source is unavailable or unreadable"; break;
    case database::HistorySourceIdentityCheck::over_limit:
        detail = "not checked because the source exceeds 256 MiB"; break;
    case database::HistorySourceIdentityCheck::size_mismatch:
        detail = "mismatch: current size differs from the pinned input"; break;
    case database::HistorySourceIdentityCheck::digest_mismatch:
        detail = "mismatch: current SHA-256 differs from the pinned input"; break;
    case database::HistorySourceIdentityCheck::matches:
        detail = "matches pinned size and SHA-256 for bytes read now"; break;
    }
    source_status_->SetLabel("Current source integrity: " + detail + ".");
}

void HistoryView::copy_audit_json() {
    if (audit_report_.empty()) return;
    constexpr std::size_t clipboard_limit = 64 * 1024;
    const auto report_buffer = audit_report_.utf8_str();
    const std::string summary = report_buffer.data()
        ? std::string(report_buffer.data(), report_buffer.length()) : std::string{};
    const auto source_check = [&]() -> std::string_view {
        switch (audit_source_identity_check_) {
        case database::HistorySourceIdentityCheck::not_checked: return "not_checked";
        case database::HistorySourceIdentityCheck::no_recorded_path: return "no_recorded_path";
        case database::HistorySourceIdentityCheck::unavailable: return "unavailable";
        case database::HistorySourceIdentityCheck::over_limit: return "over_limit";
        case database::HistorySourceIdentityCheck::size_mismatch: return "size_mismatch";
        case database::HistorySourceIdentityCheck::digest_mismatch: return "digest_mismatch";
        case database::HistorySourceIdentityCheck::matches: return "matches";
        }
        return "unknown";
    };
    std::string output = "{\"schema\":\"hexlab.history-audit.v1\",\"project_uuid\":";
    if (project_ && project_->state) {
        constexpr char digits[] = "0123456789abcdef";
        std::string uuid;
        uuid.reserve(project_->state->uuid.size() * 2);
        for (const auto byte : project_->state->uuid) {
            const auto value = std::to_integer<unsigned>(byte);
            uuid.push_back(digits[value >> 4]);
            uuid.push_back(digits[value & 0xf]);
        }
        output += json_quote(uuid);
    } else output += "null";
    output += ",\"edit_revision\":" + std::to_string(expected_edit_);
    output += ",\"history_cursor\":" + std::to_string(page_ ? page_->history_cursor : 0);
    output += ",\"history_count\":" + std::to_string(page_ ? page_->history_count : 0);
    output += ",\"state\":" + json_quote(audit_in_progress_ ? "running" :
        audit_resume_available_ ? "paused" : "reported");
    output += ",\"structural_complete\":" + std::string(audit_structural_complete_ ? "true" : "false");
    output += ",\"applied_branch_replay_requested\":" + std::string(audit_verify_replay_ ? "true" : "false");
    output += ",\"verified_steps\":" + std::to_string(audit_verified_);
    output += ",\"verified_delta_bytes\":" + std::to_string(audit_bytes_);
    output += ",\"next_after_step\":" + std::to_string(audit_next_after_step_);
    output += ",\"source_identity_check\":" + json_quote(source_check());
    output += ",\"summary\":" + json_quote(summary) + "}";
    if (output.size() > clipboard_limit) {
        status_->SetLabel("History audit JSON exceeds the 64 KiB clipboard limit; no data was copied.");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        status_->SetLabel("The system clipboard is unavailable; the saved audit result is still available.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(
        wxString::FromUTF8(output.data(), output.size())));
    wxTheClipboard->Close();
    status_->SetLabel(copied ? "Copied hexlab.history-audit.v1 JSON to the clipboard."
                             : "Could not copy history audit JSON.");
}

void HistoryView::request_audit_page(std::uint64_t after_step) {
    if (!actor_ || !audit_in_progress_ || pending_) return;
    pending_kind_ = PendingKind::audit;
    auto submission = actor_->audit_history(expected_edit_, after_step);
    if (!submission) {
        audit_in_progress_ = false;
        audit_resume_available_ = audit_next_after_step_ > 0;
        audit_->SetLabel(audit_resume_available_ ? "Resume audit" : "Audit history");
        initial_state_->Enable(bool(actor_));
        compare_previous_->Enable(selected_step_ && *selected_step_ > 0);
        compare_current_->Enable(selected_step_.has_value());
        record_audit_result(wxString::Format("Audit stopped after %llu of %llu steps: %s",
            static_cast<unsigned long long>(audit_verified_),
            static_cast<unsigned long long>(page_ ? page_->history_count : 0),
            text(submission.error().message)));
        return;
    }
    pending_expected_edit_ = expected_edit_;
    pending_ = std::move(submission.value());
    status_->SetLabel(wxString::Format("Auditing durable history: %llu of %llu steps verified…",
        static_cast<unsigned long long>(audit_verified_),
        static_cast<unsigned long long>(page_ ? page_->history_count : 0)));
}

void HistoryView::request_audit_replay() {
    if (!actor_ || !audit_in_progress_ || pending_ || !audit_structural_complete_) return;
    pending_kind_ = PendingKind::audit_replay;
    auto submission = actor_->preview_history_at(expected_edit_, 0,
        database::HistoryPreviewLimits{preview_step_budget, preview_payload_budget});
    if (!submission) {
        audit_in_progress_ = false;
        audit_resume_available_ = true;
        audit_->SetLabel("Resume audit");
        next_page_->Enable(page_ && page_->has_more);
        initial_state_->Enable(bool(actor_));
        compare_previous_->Enable(selected_step_ && *selected_step_ > 0);
        compare_current_->Enable(selected_step_.has_value());
        record_audit_result("Structural audit passed; applied-branch replay could not start: " +
                            text(submission.error().message));
        return;
    }
    pending_expected_edit_ = expected_edit_;
    pending_ = std::move(submission.value());
    status_->SetLabel("Structural audit passed; verifying applied-branch replay to empty step zero (4096 steps / 64 MiB)...");
}

void HistoryView::request_preview(std::uint64_t step) {
    if (!actor_ || audit_in_progress_) return;
    comparison_base_.reset();
    comparison_current_.reset();
    if (pending_) {
        if (pending_kind_ == PendingKind::page) return;
        cancel_pending();
    }
    selected_step_ = step;
    preview_.reset();
    selected_preview_row_.reset();
    render_preview();
    pending_kind_ = PendingKind::preview;
    auto submission = actor_->preview_history_at(expected_edit_, step,
        database::HistoryPreviewLimits{preview_step_budget, preview_payload_budget});
    if (!submission) { show_error(submission.error()); return; }
    pending_expected_edit_ = expected_edit_;
    pending_ = std::move(submission.value());
    preview_status_->SetLabel(wxString::Format("Reconstructing read-only step %llu…",
        static_cast<unsigned long long>(step)));
    navigate_patch_->Enable(false);
}

void HistoryView::compare_with_previous() {
    if (!actor_ || audit_in_progress_ || !selected_step_ || *selected_step_ == 0 || pending_) return;
    comparison_base_.reset();
    comparison_current_.reset();
    preview_.reset();
    pending_kind_ = PendingKind::comparison_base;
    auto submission = actor_->preview_history_at(expected_edit_, *selected_step_ - 1,
        database::HistoryPreviewLimits{preview_step_budget, preview_payload_budget});
    if (!submission) { show_error(submission.error()); return; }
    pending_expected_edit_ = expected_edit_;
    pending_ = std::move(submission.value());
    preview_status_->SetLabel(wxString::Format("Loading step %llu to compare with step %llu…",
        static_cast<unsigned long long>(*selected_step_ - 1),
        static_cast<unsigned long long>(*selected_step_)));
    render_preview();
}

void HistoryView::compare_with_current() {
    if (!actor_ || !project_ || !project_->state || audit_in_progress_ || !selected_step_ || pending_)
        return;
    comparison_base_.reset();
    comparison_current_ = project_->state;
    comparison_current_edit_ = expected_edit_;
    preview_.reset();
    selected_preview_row_.reset();
    pending_kind_ = PendingKind::comparison_current;
    auto submission = actor_->preview_history_at(expected_edit_, *selected_step_,
        database::HistoryPreviewLimits{preview_step_budget, preview_payload_budget});
    if (!submission) {
        comparison_current_.reset();
        show_error(submission.error());
        return;
    }
    pending_expected_edit_ = expected_edit_;
    pending_ = std::move(submission.value());
    preview_status_->SetLabel(wxString::Format("Loading step %llu to compare with current project at edit %llu...",
        static_cast<unsigned long long>(*selected_step_),
        static_cast<unsigned long long>(comparison_current_edit_)));
    render_preview();
}

void HistoryView::update_save_controls() {
    const auto view = actor_ ? std::optional<ActorView>{actor_->view()} : std::nullopt;
    save_copy_->Enable(view && view->project_path && !view->untitled && !view->closing &&
        selected_step_.has_value() && !pending_ && !audit_in_progress_ && !history_save_);
    cancel_save_->Enable(history_save_ && !history_save_->cancellation.stop_requested());
}

void HistoryView::save_selected_history() {
    if (!actor_ || !project_ || !selected_step_ || pending_ || audit_in_progress_ || history_save_) return;
    const auto view = actor_->view();
    if (!view.project_path || view.untitled || view.closing) {
        save_status_->SetLabel("Save the current project before saving a recovered copy.");
        return;
    }
    const auto source = *view.project_path;
    saved_copy_path_.reset();
    open_copy_->Enable(false);
    const auto uuid = project_->state->uuid;
    const auto step = *selected_step_;
    std::optional<std::uint64_t> expected = expected_edit_;

    wxDialog options(this, wxID_ANY, "Save recovered project", wxDefaultPosition,
                     wxDefaultSize, wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);
    auto* layout = new wxBoxSizer(wxVERTICAL);
    auto* description = new wxStaticText(&options, wxID_ANY,
        wxString::Format("Save step %llu from ", static_cast<unsigned long long>(step)) +
        path_text(source) + "\nThe source stays open and unchanged. The copy retains undo/redo history.");
    description->Wrap(FromDIP(540));
    layout->Add(description, 0, wxEXPAND | wxALL, FromDIP(10));
    auto* guard = new wxCheckBox(&options, wxID_ANY, "Require this source edit revision:");
    guard->SetName("history-save-revision-guard");
    guard->SetValue(true);
    auto* revision = new wxTextCtrl(&options, wxID_ANY,
        wxString::Format("%llu", static_cast<unsigned long long>(*expected)));
    revision->SetName("history-save-expected-edit");
    layout->Add(guard, 0, wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(10));
    layout->Add(revision, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(10));
    auto* explanation = new wxStaticText(&options, wxID_ANY,
        "Keep the guard checked to save the revision you inspected. Without it, the copy uses the "
        "revision observed when its source opens. Replay is limited to 4096 steps and 64 MiB.");
    explanation->Wrap(FromDIP(540));
    layout->Add(explanation, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(10));
    layout->Add(options.CreateSeparatedButtonSizer(wxOK | wxCANCEL), 0, wxEXPAND | wxALL, FromDIP(10));
    options.SetSizerAndFit(layout);
    guard->Bind(wxEVT_CHECKBOX, [guard, revision](wxCommandEvent&) { revision->Enable(guard->GetValue()); });
    options.Bind(wxEVT_BUTTON, [&](wxCommandEvent&) {
        expected.reset();
        if (guard->GetValue()) {
            const auto value = revision->GetValue().ToStdString();
            std::uint64_t parsed = 0;
            const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
            if (error != std::errc{} || end != value.data() + value.size()) {
                wxMessageBox("Enter an unsigned decimal edit revision.", "Invalid edit revision", wxOK | wxICON_ERROR, &options);
                revision->SetFocus();
                return;
            }
            expected = parsed;
        }
        options.EndModal(wxID_OK);
    }, wxID_OK);
    if (options.ShowModal() != wxID_OK) return;

    const auto filename = path_text(source.stem()) +
        wxString::Format("-step-%llu.hxproj", static_cast<unsigned long long>(step));
    wxFileDialog destination(this, "Save recovered project", path_text(source.parent_path()), filename,
        "HexLab projects (*.hxproj)|*.hxproj", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    if (destination.ShowModal() != wxID_OK) return;
    const std::filesystem::path output(destination.GetPath().ToStdWstring());
    std::error_code file_error;
    const bool replace = std::filesystem::exists(output, file_error);
    if (file_error) {
        save_status_->SetLabel("Could not inspect recovered-copy destination: " + text(file_error.message()));
        return;
    }

    try {
        auto work = std::make_shared<HistorySaveWork>();
        work->source = source;
        work->uuid = uuid;
        work->step = step;
        // The worker owns all native state and never accesses a window. Closing
        // the History page requests cancellation without waiting on the GUI thread.
        std::thread([work, source, output, uuid, step, expected, replace] {
            auto save = [&]() -> Result<database::SavedProject> {
                const auto stop = work->cancellation.get_token();
                auto opened = database::ProjectStore::open(source, database::ProjectMode::read_only, stop);
                if (!opened) return opened.error();
                auto snapshot = opened.value()->snapshot();
                if (!snapshot) return snapshot.error();
                if (snapshot.value()->uuid != uuid)
                    return Error{ErrorCode::conflict, "The source path now belongs to a different project; refresh history."};
                return opened.value()->save_history_as(expected.value_or(snapshot.value()->revisions.edit), step,
                    database::HistoryPreviewLimits{preview_step_budget, preview_payload_budget}, output,
                    replace ? database::ReplacePolicy::replace_existing : database::ReplacePolicy::fail_if_exists, stop);
            };
            try { work->completion.set_value(save()); }
            catch (const std::bad_alloc&) {
                work->completion.set_value(Error{ErrorCode::resource_limit, "Cannot allocate historical project copy"});
            } catch (const std::exception& error) {
                work->completion.set_value(Error{ErrorCode::io, error.what()});
            } catch (...) {
                work->completion.set_value(Error{ErrorCode::io, "Unexpected failure saving recovered project"});
            }
        }).detach();
        history_save_ = std::move(work);
        save_status_->SetLabel(wxString::Format("Saving recovered step %llu from ",
            static_cast<unsigned long long>(step)) + path_text(source) + "...");
        save_status_->Wrap(std::max(FromDIP(280), GetClientSize().GetWidth() - FromDIP(10)));
        Layout();
        update_save_controls();
    } catch (const std::exception& error) {
        save_status_->SetLabel("Could not start recovered copy: " + text(error.what()));
    }
}

void HistoryView::poll_history_save() {
    if (!history_save_ || history_save_->result.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) return;
    const auto step = history_save_->step;
    const auto source = history_save_->source;
    const auto uuid = history_save_->uuid;
    auto result = history_save_->result.get();
    history_save_.reset();
    if (result) {
        const auto current = actor_ ? std::optional<ActorView>{actor_->view()} : std::nullopt;
        if (current && current->project_path && *current->project_path == source &&
            project_ && project_->state && project_->state->uuid == uuid) {
            saved_copy_path_ = result.value().path;
            open_copy_->Enable(static_cast<bool>(open_project));
        }
        save_status_->SetLabel(wxString::Format("Recovered step %llu from ", static_cast<unsigned long long>(step)) +
            path_text(source.filename()) + " saved to " + path_text(result.value().path) +
            (saved_copy_path_ ? ". Choose Open saved project to inspect it. Source unchanged; undo/redo retained."
                               : ". Source unchanged; undo/redo retained."));
    } else {
        const auto prefix = result.error().code == ErrorCode::canceled ? "Recovered copy canceled: " : "Recovered copy failed: ";
        save_status_->SetLabel(wxString(prefix) + text(result.error().message));
    }
    save_status_->Wrap(std::max(FromDIP(280), GetClientSize().GetWidth() - FromDIP(10)));
    update_save_controls();
    Layout();
}

void HistoryView::show_error(const Error& error) {
    if (pending_kind_ == PendingKind::page) status_->SetLabel(text(error.message));
    else preview_status_->SetLabel(text(error.message));
}

void HistoryView::poll() {
    poll_history_save();
    update_save_controls();
    if (!pending_ || pending_->result.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) return;
    const auto kind = pending_kind_;
    const auto expected = pending_expected_edit_;
    auto result = pending_->result.get();
    pending_.reset();
    if (expected != expected_edit_) return;
    if (!result) {
        if (kind == PendingKind::audit || kind == PendingKind::audit_replay) {
            audit_in_progress_ = false;
            const bool conflict = result.error().code == ErrorCode::conflict;
            audit_resume_available_ = !conflict && (audit_structural_complete_ || audit_next_after_step_ > 0);
            if (conflict) { audit_structural_complete_ = false; audit_next_after_step_ = 0; }
            audit_->SetLabel(audit_resume_available_ ? "Resume audit" : "Audit history");
            initial_state_->Enable(bool(actor_));
            compare_previous_->Enable(selected_step_ && *selected_step_ > 0);
            compare_current_->Enable(selected_step_.has_value());
            record_audit_result(wxString::Format("%s stopped at edit %llu after %llu of %llu structural steps (%llu delta bytes): %s",
                kind == PendingKind::audit_replay ? "Applied-branch replay" : "Audit",
                static_cast<unsigned long long>(expected_edit_),
                static_cast<unsigned long long>(audit_verified_),
                static_cast<unsigned long long>(page_ ? page_->history_count : 0),
                static_cast<unsigned long long>(audit_bytes_), text(result.error().message)));
        } else {
            if (kind == PendingKind::comparison_current)
                comparison_current_.reset();
            show_error(result.error());
        }
        next_page_->Enable(page_ && page_->has_more);
        return;
    }
    if (kind == PendingKind::page) {
        if (!result.value().history_page) {
            status_->SetLabel("History page query returned no page.");
            return;
        }
        const auto& received = *result.value().history_page;
        if (!project_ || received.uuid != project_->state->uuid ||
            received.source_revisions.edit != expected_edit_) {
            status_->SetLabel("Project identity or revision changed; refresh history.");
            return;
        }
        if (!page_) {
            page_ = received;
            rows_ = received.entries;
        } else {
            page_->source_revisions = received.source_revisions;
            page_->history_cursor = received.history_cursor;
            page_->history_count = received.history_count;
            page_->next_after_step = received.next_after_step;
            page_->has_more = received.has_more;
            rows_.insert(rows_.end(), received.entries.begin(), received.entries.end());
        }
        status_->SetLabel(wxString::Format("%llu steps recorded; current history cursor is %llu; showing %llu entries.",
            static_cast<unsigned long long>(page_->history_count),
            static_cast<unsigned long long>(page_->history_cursor),
            static_cast<unsigned long long>(rows_.size())));
        next_page_->Enable(page_->has_more);
        render_entries();
        audit_->Enable(true);
        return;
    }

    if (kind == PendingKind::audit) {
        if (!result.value().history_audit) {
            audit_in_progress_ = false;
            audit_resume_available_ = audit_next_after_step_ > 0;
            audit_->SetLabel(audit_resume_available_ ? "Resume audit" : "Audit history");
            initial_state_->Enable(bool(actor_));
            record_audit_result("History audit returned no report.");
            return;
        }
        const auto& received = *result.value().history_audit;
        if (!project_ || received.uuid != project_->state->uuid ||
            received.source_revisions.edit != expected_edit_) {
            audit_in_progress_ = false;
            audit_resume_available_ = false;
            audit_structural_complete_ = false;
            audit_next_after_step_ = 0;
            audit_->SetLabel("Audit history");
            initial_state_->Enable(bool(actor_));
            record_audit_result("Project identity or revision changed; restart the history audit.");
            return;
        }
        if (received.source_identity_check != database::HistorySourceIdentityCheck::not_checked) {
            audit_source_identity_check_ = received.source_identity_check;
            update_source_status();
        }
        audit_verified_ += received.entries_verified;
        audit_bytes_ += received.delta_bytes;
        if (page_) {
            page_->history_count = received.history_count;
            page_->history_cursor = received.history_cursor;
        }
        if (received.has_more) {
            audit_next_after_step_ = received.next_after_step;
            status_->SetLabel(wxString::Format("Auditing durable history: %llu of %llu steps verified (%llu delta bytes)…",
                static_cast<unsigned long long>(audit_verified_),
                static_cast<unsigned long long>(received.history_count),
                static_cast<unsigned long long>(audit_bytes_)));
            request_audit_page(received.next_after_step);
        } else {
            audit_next_after_step_ = received.next_after_step;
            audit_structural_complete_ = true;
            if (audit_verify_replay_) {
                request_audit_replay();
                return;
            }
            audit_in_progress_ = false;
            audit_resume_available_ = false;
            audit_->SetLabel("Audit history");
            next_page_->Enable(page_ && page_->has_more);
            initial_state_->Enable(bool(actor_));
            compare_previous_->Enable(selected_step_ && *selected_step_ > 0);
            compare_current_->Enable(selected_step_.has_value());
            record_audit_result(wxString::Format("History audit passed: %llu of %llu steps verified; %llu delta bytes checked; cursor %llu.",
                static_cast<unsigned long long>(audit_verified_),
                static_cast<unsigned long long>(received.history_count),
                static_cast<unsigned long long>(audit_bytes_),
                static_cast<unsigned long long>(received.history_cursor)));
        }
        return;
    }

    if (kind == PendingKind::audit_replay) {
        audit_in_progress_ = false;
        audit_resume_available_ = false;
        audit_->SetLabel("Audit history");
        next_page_->Enable(page_ && page_->has_more);
        initial_state_->Enable(bool(actor_));
        compare_previous_->Enable(selected_step_ && *selected_step_ > 0);
        compare_current_->Enable(selected_step_.has_value());
        if (!result.value().history_preview) {
            record_audit_result("Structural audit passed; applied-branch replay failed: no projection was returned.");
            return;
        }
        const auto& replay = *result.value().history_preview;
        if (!project_ || !page_ || replay.uuid != project_->state->uuid ||
            replay.source_revisions.edit != expected_edit_ || replay.source_cursor != page_->history_cursor ||
            replay.history_count != page_->history_count || replay.target_step != 0) {
            audit_structural_complete_ = false;
            audit_next_after_step_ = 0;
            record_audit_result("Project identity, revision or history cursor changed; restart the audit and replay verification.");
            return;
        }
        if (!replay.user || *replay.user != database::UserState{}) {
            record_audit_result("Structural audit passed; applied-branch replay FAILED: step zero did not reconstruct empty user state.");
            return;
        }
        record_audit_result(wxString::Format(
            "History audit and applied-branch replay passed at edit %llu: %llu of %llu structural steps, %llu audit delta bytes; "
            "reversed %llu applied steps (%llu replay delta bytes) to empty step zero. Redo-only steps were not replayed.",
            static_cast<unsigned long long>(expected_edit_), static_cast<unsigned long long>(audit_verified_),
            static_cast<unsigned long long>(replay.history_count), static_cast<unsigned long long>(audit_bytes_),
            static_cast<unsigned long long>(replay.replayed_steps), static_cast<unsigned long long>(replay.delta_bytes)));
        return;
    }

    if (!result.value().history_preview) {
        if (kind == PendingKind::comparison_current)
            comparison_current_.reset();
        preview_status_->SetLabel("History preview query returned no projection.");
        return;
    }
    auto received_preview = std::move(result.value().history_preview);
    if (kind == PendingKind::comparison_base) {
        if (!project_ || received_preview->uuid != project_->state->uuid ||
            received_preview->source_revisions.edit != expected_edit_ || !received_preview->user || !selected_step_) {
            preview_status_->SetLabel("Could not compare history steps because the project changed.");
            return;
        }
        comparison_base_ = std::move(received_preview);
        pending_kind_ = PendingKind::preview;
        auto submission = actor_->preview_history_at(expected_edit_, *selected_step_,
            database::HistoryPreviewLimits{preview_step_budget, preview_payload_budget});
        if (!submission) { comparison_base_.reset(); show_error(submission.error()); return; }
        pending_expected_edit_ = expected_edit_;
        pending_ = std::move(submission.value());
        preview_status_->SetLabel("Loading selected step to compare…");
        return;
    }
    if (kind == PendingKind::comparison_current &&
        (!comparison_current_ || !project_ || !project_->state ||
         comparison_current_->uuid != project_->state->uuid ||
         comparison_current_->revisions.edit != comparison_current_edit_ ||
         project_->state->revisions.edit != comparison_current_edit_ ||
         received_preview->uuid != comparison_current_->uuid ||
         received_preview->source_revisions.edit != comparison_current_edit_)) {
        comparison_current_.reset();
        preview_status_->SetLabel("Project identity or edit revision changed; refresh the selected step and compare again.");
        return;
    }
    preview_ = std::move(received_preview);
    if (!project_ || preview_->uuid != project_->state->uuid ||
        preview_->source_revisions.edit != expected_edit_) {
        preview_.reset();
        preview_status_->SetLabel("Project identity or revision changed; refresh the selected history step.");
        return;
    }
    if (!preview_->user) {
        preview_status_->SetLabel("Historical projection contains no user state.");
        return;
    }
    selected_preview_row_.reset();
    render_preview();
}

void HistoryView::render_entries() {
    entries_->clear_selection();
    visible_history_rows_.clear();
    const auto query = history_filter_->GetValue().Lower();
    for (std::size_t i = 0; i < rows_.size(); ++i) {
        const auto& entry = rows_[i];
        const auto searchable = wxString::Format("%llu %llu ",
            static_cast<unsigned long long>(entry.step),
            static_cast<unsigned long long>(entry.group_id)) + change_text(entry) +
            (entry.applied ? " Applied" : " Redo");
        if (query.empty() || searchable.Lower().Find(query) != wxNOT_FOUND)
            visible_history_rows_.push_back(i);
    }
    entries_->populate(visible_history_rows_.size(), [this](std::size_t row, int column) {
        const auto& entry = rows_[visible_history_rows_[row]];
        switch (column) {
        case 0: return wxString::Format("%llu", static_cast<unsigned long long>(entry.step));
        case 1: return wxString::Format("%llu", static_cast<unsigned long long>(entry.group_id));
        case 2: return change_text(entry);
        default: return entry.applied ? wxString("Applied") : wxString("Redo");
        }
    });
    history_filter_status_->SetLabel(query.empty()
        ? wxString::Format("%llu loaded", static_cast<unsigned long long>(rows_.size()))
        : wxString::Format("%llu / %llu match", static_cast<unsigned long long>(visible_history_rows_.size()),
                           static_cast<unsigned long long>(rows_.size())));
    if (rows_.empty() && page_ && page_->history_count == 0)
        status_->SetLabel("This project has no durable history entries.");
}

void HistoryView::render_preview() {
    preview_items_->clear_selection();
    navigate_patch_->Enable(false);
    if (!preview_ || !preview_->user) {
        preview_rows_.clear();
        preview_items_->populate(0, {});
        selected_preview_row_.reset();
        if (!selected_step_) preview_status_->SetLabel("Select a history step to preview it.");
        return;
    }
    const auto& state = *preview_->user;
    const auto* image = project_ && project_->loaded && project_->loaded->image
        ? project_->loaded->image.get() : nullptr;
    auto add = [&](wxString category, std::optional<Location> location, wxString name, wxString details) {
        PreviewItem row;
        row.category = std::move(category);
        row.location = location ? location_text(*location, image) : wxString("—");
        row.name = std::move(name);
        row.details = std::move(details);
        row.target = std::move(location);
        preview_rows_.push_back(std::move(row));
    };
    preview_rows_.clear();
    preview_rows_.reserve(state.annotations.size() + state.bookmarks.size() + state.breakpoints.size() + state.types.size() +
        state.type_assignments.size() + state.decisions.functions.size() + state.decisions.regions.size() +
        state.decisions.references.size() + state.debug_variables.size() + state.patches.size() + 10);
    for (const auto& row : state.annotations)
        add("Annotation", row.location, text(row.name), preview_text(row.comment, 256));
    for (const auto& row : state.bookmarks)
        add("Bookmark", row.location, text(row.label), "");
    for (const auto& row : state.types) {
        const auto name = text(row.name);
        const auto details = row.type ? text(types::format(*row.type)) : wxString("unavailable type");
        add("Type", {}, name, details);
    }
    for (const auto& row : state.type_assignments)
        add("Type assignment", row.location, hex_value(row.type_id), "type ID");
    for (const auto& row : state.decisions.functions)
        add("Function decision", Location{row.entry}, hex_value(row.id),
            wxString(row.suppressed ? "suppressed" : "enabled") + wxString::Format("; %llu chunks",
                static_cast<unsigned long long>(row.chunks.size())));
    for (const auto& row : state.decisions.regions)
        add("Region decision", Location{row.begin}, hex_value(row.id),
            wxString::Format("%llu bytes; kind %u", static_cast<unsigned long long>(row.size),
                static_cast<unsigned>(row.kind)));
    for (const auto& row : state.decisions.references)
        add("User reference", row.source, location_text(row.target, image),
            wxString::Format("kind %u", static_cast<unsigned>(row.kind)));
    for (const auto& row : state.debug_variables) {
        wxString details = row.is_parameter ? "parameter" : "local";
        if (row.type_id) { details += "; type "; details += hex_value(*row.type_id); }
        if (row.address) { details += "; location "; details += hex_value(*row.address); }
        add("Debug variable", Location{row.function_entry}, text(row.name), details);
    }
    for (const auto& row : state.patches) {
        const auto count = std::min<std::size_t>(row.replacement.size(), 16);
        auto bytes = hex_bytes(std::span<const std::byte>(row.replacement).first(count));
        if (count < row.replacement.size()) bytes += " …";
        auto details = wxString::Format("%llu bytes; ",
            static_cast<unsigned long long>(row.replacement.size())) + bytes;
        add("Patch", Location{row.begin}, "", details);
    }
    preview_status_->SetLabel(wxString::Format(
        "Read-only step %llu (cursor %llu of %llu); replayed %llu steps, %llu delta bytes. "
        "%llu annotations, %llu bookmarks, %llu breakpoints, %llu types, %llu assignments, %llu function records, "
        "%llu regions, %llu references, %llu debug variables, %llu patches.",
        static_cast<unsigned long long>(preview_->target_step),
        static_cast<unsigned long long>(preview_->source_cursor),
        static_cast<unsigned long long>(preview_->history_count),
        static_cast<unsigned long long>(preview_->replayed_steps),
        static_cast<unsigned long long>(preview_->delta_bytes),
        static_cast<unsigned long long>(state.annotations.size()),
        static_cast<unsigned long long>(state.bookmarks.size()),
        static_cast<unsigned long long>(state.breakpoints.size()),
        static_cast<unsigned long long>(state.types.size()),
        static_cast<unsigned long long>(state.type_assignments.size()),
        static_cast<unsigned long long>(state.decisions.functions.size()),
        static_cast<unsigned long long>(state.decisions.regions.size()),
        static_cast<unsigned long long>(state.decisions.references.size()),
        static_cast<unsigned long long>(state.debug_variables.size()),
        static_cast<unsigned long long>(state.patches.size())));
    const auto *comparison_state = comparison_base_ && comparison_base_->user
        ? comparison_base_->user.get()
        : comparison_current_ && comparison_current_->user ? comparison_current_->user.get() : nullptr;
    if (comparison_state) {
        const auto& before = *comparison_state;
        constexpr std::size_t max_detail_rows = 512;
        std::size_t detail_rows = 0;
        bool details_truncated = false;
        auto add_detail = [&](const wxString& category, std::optional<Location> location,
                              const wxString& name, std::uint64_t id, const wxString& change,
                              const wxString& detail) {
            if (detail_rows >= max_detail_rows) { details_truncated = true; return; }
            ++detail_rows;
            add("History " + category + " " + change, std::move(location), name,
                "id=" + hex_value(id) + "; " + detail);
        };
        auto append_details = [&](const auto& old_rows, const auto& new_rows,
                                  const wxString& category, auto describe,
                                  auto row_location, auto row_name) {
            using Rows = std::decay_t<decltype(old_rows)>;
            using Row = typename Rows::value_type;
            std::map<std::uint64_t, const Row*> old_by_id;
            std::map<std::uint64_t, const Row*> new_by_id;
            for (const auto& row : old_rows) old_by_id.emplace(row.id, &row);
            for (const auto& row : new_rows) new_by_id.emplace(row.id, &row);
            for (const auto& [id, old_row] : old_by_id) {
                const auto current = new_by_id.find(id);
                if (current == new_by_id.end()) {
                    add_detail(category, row_location(*old_row), row_name(*old_row), id,
                        "removed", describe(*old_row));
                } else if (!(*current->second == *old_row)) {
                    add_detail(category, row_location(*current->second), row_name(*current->second), id,
                        "changed",
                        "before: " + describe(*old_row) + "; after: " + describe(*current->second));
                }
            }
            for (const auto& [id, new_row] : new_by_id)
                if (!old_by_id.contains(id)) add_detail(category, row_location(*new_row), row_name(*new_row), id,
                    "added", describe(*new_row));
        };
        append_details(before.annotations, state.annotations, "annotation", [](const auto& row) {
            return "name=" + preview_text(row.name, 128) + "; comment=" + preview_text(row.comment, 256);
        }, [](const auto& row) { return std::optional<Location>{row.location}; },
           [](const auto& row) { return preview_text(row.name, 128); });
        append_details(before.bookmarks, state.bookmarks, "bookmark", [](const auto& row) {
            return "label=" + preview_text(row.label, 160);
        }, [](const auto& row) { return std::optional<Location>{row.location}; },
           [](const auto& row) { return preview_text(row.label, 128); });
        append_details(before.breakpoints, state.breakpoints, "breakpoint", [](const auto& row) {
            return wxString(row.enabled ? "enabled" : "disabled") +
                wxString::Format("; kind %u; size %u; ignore %llu; hit %llu; logpoint %s; condition=%s; message=%s",
                    static_cast<unsigned>(row.kind), static_cast<unsigned>(row.size),
                    static_cast<unsigned long long>(row.ignore_count), static_cast<unsigned long long>(row.hit_count),
                    row.logpoint ? "yes" : "no", preview_text(row.condition, 192), preview_text(row.log_message, 192));
        }, [](const auto& row) { return std::optional<Location>{Location{row.address}}; },
           [](const auto&) { return wxString{}; });
        append_details(before.types, state.types, "type", [](const auto& row) {
            return "declaration kind " + wxString::Format("%u", static_cast<unsigned>(row.declaration_kind)) +
                "; " + (row.type ? preview_text(types::format(*row.type), 384) : wxString("unavailable type"));
        }, [](const auto&) { return std::optional<Location>{}; },
           [](const auto& row) { return preview_text(row.name, 128); });
        append_details(before.type_assignments, state.type_assignments, "type assignment", [](const auto& row) {
            return "type=" + hex_value(row.type_id);
        }, [](const auto& row) { return std::optional<Location>{row.location}; },
           [](const auto& row) { return hex_value(row.type_id); });
        append_details(before.decisions.functions, state.decisions.functions, "function decision", [](const auto& row) {
            return wxString(row.suppressed ? "suppressed" : "enabled") + wxString::Format("; %llu chunks",
                static_cast<unsigned long long>(row.chunks.size()));
        }, [](const auto& row) { return std::optional<Location>{Location{row.entry}}; },
           [](const auto& row) { return hex_value(row.id); });
        append_details(before.decisions.regions, state.decisions.regions, "region", [](const auto& row) {
            return wxString::Format("%llu bytes; kind %u", static_cast<unsigned long long>(row.size),
                static_cast<unsigned>(row.kind));
        }, [](const auto& row) { return std::optional<Location>{Location{row.begin}}; },
           [](const auto& row) { return hex_value(row.id); });
        append_details(before.decisions.references, state.decisions.references, "user reference", [image](const auto& row) {
            return "target=" + location_text(row.target, image) +
                wxString::Format("; kind %u", static_cast<unsigned>(row.kind));
        }, [](const auto& row) { return std::optional<Location>{row.source}; },
           [image](const auto& row) { return location_text(row.target, image); });
        append_details(before.debug_variables, state.debug_variables, "debug variable", [](const auto& row) {
            wxString detail = row.is_parameter ? "parameter" : "local";
            if (row.type_id) detail += "; type " + hex_value(*row.type_id);
            if (row.address) detail += "; address " + hex_value(*row.address);
            detail += wxString::Format("; scope 0x%llx; location ranges %llu",
                static_cast<unsigned long long>(row.scope_offset),
                static_cast<unsigned long long>(row.location_ranges.size()));
            return detail;
        }, [](const auto& row) { return std::optional<Location>{Location{row.function_entry}}; },
           [](const auto& row) { return preview_text(row.name, 128); });
        struct ChangeCounts { std::size_t added=0, removed=0, changed=0; };
        auto count_changes = [](const auto& old_rows, const auto& new_rows, auto key) {
            ChangeCounts counts;
            using Row = typename std::decay_t<decltype(old_rows)>::value_type;
            using Key = std::decay_t<decltype(key(std::declval<const Row&>()))>;
            std::map<Key, const Row*> old_by_key;
            std::map<Key, const Row*> new_by_key;
            for (const auto& old_row : old_rows) {
                old_by_key.emplace(key(old_row), &old_row);
            }
            for (const auto& new_row : new_rows) {
                new_by_key.emplace(key(new_row), &new_row);
            }
            for (const auto& [identity, old_row] : old_by_key) {
                const auto current = new_by_key.find(identity);
                if (current == new_by_key.end()) ++counts.removed;
                else if (!(*current->second == *old_row)) ++counts.changed;
            }
            for (const auto& [identity, new_row] : new_by_key) {
                (void)new_row;
                if (!old_by_key.contains(identity)) ++counts.added;
            }
            return counts;
        };
        const auto by_id = [](const auto& row) { return row.id; };
        const auto annotations = count_changes(before.annotations, state.annotations, by_id);
        const auto bookmarks = count_changes(before.bookmarks, state.bookmarks, by_id);
        const auto breakpoints = count_changes(before.breakpoints, state.breakpoints, by_id);
        const auto types = count_changes(before.types, state.types, by_id);
        const auto assignments = count_changes(before.type_assignments, state.type_assignments, by_id);
        const auto functions = count_changes(before.decisions.functions, state.decisions.functions, by_id);
        const auto regions = count_changes(before.decisions.regions, state.decisions.regions, by_id);
        const auto references = count_changes(before.decisions.references, state.decisions.references, by_id);
        const auto debug_variables = count_changes(before.debug_variables, state.debug_variables, by_id);
        struct PatchGroup {
            std::vector<const PatchSpan*> before;
            std::vector<const PatchSpan*> after;
        };
        std::map<std::uint64_t, PatchGroup> patch_groups;
        for (const auto& patch : before.patches) patch_groups[patch.begin.value].before.push_back(&patch);
        for (const auto& patch : state.patches) patch_groups[patch.begin.value].after.push_back(&patch);
        const auto patch_less = [](const PatchSpan* left, const PatchSpan* right) {
            if (left->original != right->original)
                return std::lexicographical_compare(left->original.begin(), left->original.end(),
                    right->original.begin(), right->original.end());
            return std::lexicographical_compare(left->replacement.begin(), left->replacement.end(),
                right->replacement.begin(), right->replacement.end());
        };
        ChangeCounts patches;
        for (auto& [offset, group] : patch_groups) {
            (void)offset;
            std::sort(group.before.begin(), group.before.end(), patch_less);
            std::sort(group.after.begin(), group.after.end(), patch_less);
            std::size_t old_index = 0, new_index = 0;
            std::size_t unmatched_old = 0, unmatched_new = 0;
            while (old_index < group.before.size() && new_index < group.after.size()) {
                if (*group.before[old_index] == *group.after[new_index]) {
                    ++old_index;
                    ++new_index;
                } else if (patch_less(group.before[old_index], group.after[new_index])) {
                    ++unmatched_old;
                    ++old_index;
                } else {
                    ++unmatched_new;
                    ++new_index;
                }
            }
            unmatched_old += group.before.size() - old_index;
            unmatched_new += group.after.size() - new_index;
            const auto changed = std::min(unmatched_old, unmatched_new);
            patches.changed += changed;
            patches.removed += unmatched_old - changed;
            patches.added += unmatched_new - changed;
        }
        const auto add_summary = [&](const wxString& name, const ChangeCounts& counts) {
            add("Change summary", {}, name, wxString::Format("+%llu / -%llu / ~%llu",
                static_cast<unsigned long long>(counts.added),
                static_cast<unsigned long long>(counts.removed),
                static_cast<unsigned long long>(counts.changed)));
        };
        add_summary("Annotations", annotations);
        add_summary("Bookmarks", bookmarks);
        add_summary("Breakpoints", breakpoints);
        add_summary("Types", types);
        add_summary("Type assignments", assignments);
        add_summary("Function decisions", functions);
        add_summary("Regions", regions);
        add_summary("User references", references);
        add_summary("Debug variables", debug_variables);
        add_summary("Patches", patches);
        if (details_truncated)
            add("History delta", {}, "Additional row changes omitted",
                wxString::Format("The detailed comparison reached its %llu-row display limit.",
                    static_cast<unsigned long long>(max_detail_rows)));
        const auto comparison_target = comparison_current_
            ? wxString::Format("current project edit %llu", static_cast<unsigned long long>(comparison_current_edit_))
            : wxString::Format("step %llu", static_cast<unsigned long long>(comparison_base_->target_step));
        preview_status_->SetLabel(wxString::Format(
            "Step %llu compared with %s. Detailed rows show additions, removals, and edits; collection totals remain summarized below. Displayed detail is capped at %llu rows.",
            static_cast<unsigned long long>(preview_->target_step), comparison_target,
            static_cast<unsigned long long>(max_detail_rows)));
    }
    preview_items_->populate(preview_rows_.size(), [this](std::size_t row, int column) {
        const auto& item = preview_rows_[row];
        switch (column) {
        case 0: return item.category;
        case 1: return item.location;
        case 2: return item.name;
        default: return item.details;
        }
    });
}

} // namespace hexlab::desktop
