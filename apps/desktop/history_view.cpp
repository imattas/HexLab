#include "history_view.hpp"
#include "project_view.hpp"

#include <wx/sizer.h>
#include <wx/listctrl.h>
#include <wx/checkbox.h>
#include <wx/dialog.h>
#include <wx/filedlg.h>
#include <wx/msgdlg.h>
#include <wx/textctrl.h>

#include <algorithm>
#include <chrono>
#include <charconv>
#include <future>
#include <span>
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
    audit_ = new wxButton(this, wxID_ANY, "Audit history");
    refresh_->SetName("history-refresh");
    next_page_->SetName("history-next-page");
    initial_state_->SetName("history-preview-initial");
    compare_previous_->SetName("history-compare-previous");
    audit_->SetName("history-audit");
    next_page_->Enable(false);
    controls->Add(refresh_, 0, wxRIGHT, FromDIP(4));
    controls->Add(next_page_, 0, wxRIGHT, FromDIP(4));
    controls->Add(initial_state_, 0);
    controls->Add(compare_previous_, 0, wxLEFT, FromDIP(4));
    controls->Add(audit_, 0, wxLEFT, FromDIP(4));
    compare_previous_->Enable(false);
    audit_->Enable(false);
    root->Add(controls, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(5));

    status_ = new wxStaticText(this, wxID_ANY, "Open a project to inspect its history.");
    status_->SetName("history-status");
    root->Add(status_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(5));

    auto* save_controls = new wxBoxSizer(wxHORIZONTAL);
    save_copy_ = new wxButton(this, wxID_ANY, "Save selected step as project...");
    cancel_save_ = new wxButton(this, wxID_ANY, "Cancel recovered copy");
    save_copy_->SetName("history-save-copy");
    cancel_save_->SetName("history-cancel-save");
    save_copy_->Enable(false);
    cancel_save_->Enable(false);
    save_controls->Add(save_copy_, 0, wxRIGHT, FromDIP(4));
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
        audit_->SetLabel("Audit history");
        rows_.clear();
        page_.reset();
        preview_.reset();
        comparison_base_.reset();
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
    audit_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (audit_in_progress_) stop_audit();
        else begin_audit();
    });
    save_copy_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) { save_selected_history(); });
    cancel_save_->Bind(wxEVT_BUTTON, [this](wxCommandEvent&) {
        if (!history_save_) return;
        history_save_->cancellation.request_stop();
        cancel_save_->Enable(false);
        save_status_->SetLabel("Canceling recovered copy; waiting for the publication result...");
    });
    entries_->Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent&) {
        if (audit_in_progress_) return;
        const auto row = entries_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        if (row < 0 || static_cast<std::size_t>(row) >= rows_.size()) return;
        selected_step_ = rows_[static_cast<std::size_t>(row)].step;
        comparison_base_.reset();
        compare_previous_->Enable(*selected_step_ > 0);
        request_preview(*selected_step_);
    });
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
        expected_edit_ = 0;
        rows_.clear();
        page_.reset();
        preview_.reset();
        comparison_base_.reset();
        selected_step_.reset();
        selected_preview_row_.reset();
        audit_in_progress_ = false;
        audit_verified_ = 0;
        audit_bytes_ = 0;
        if (had_project) {
            status_->SetLabel("Open a project to inspect its history.");
            preview_status_->SetLabel("Select a history step to preview it.");
            render_entries();
            render_preview();
        }
        next_page_->Enable(false);
        initial_state_->Enable(false);
        compare_previous_->Enable(false);
        audit_->Enable(false);
        audit_->SetLabel("Audit history");
        refresh_->Enable(false);
        return;
    }

    const auto edit_revision = project->state->revisions.edit;
    const bool changed = document_id_ != id || actor_ != actor ||
        !project_ || project_->state->uuid != project->state->uuid ||
        expected_edit_ != edit_revision;
    project_ = std::move(project);
    if (!changed) return;

    cancel_pending();
    actor_ = std::move(actor);
    document_id_ = id;
    expected_edit_ = edit_revision;
    rows_.clear();
    page_.reset();
    preview_.reset();
    comparison_base_.reset();
    selected_step_.reset();
    selected_preview_row_.reset();
    audit_in_progress_ = false;
    audit_verified_ = 0;
    audit_bytes_ = 0;
    status_->SetLabel("Loading durable project history…");
    preview_status_->SetLabel("Select a history step to preview it.");
    refresh_->Enable(true);
    initial_state_->Enable(true);
    compare_previous_->Enable(false);
    audit_->Enable(false);
    audit_->SetLabel("Audit history");
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
    audit_in_progress_ = true;
    audit_verified_ = 0;
    audit_bytes_ = 0;
    audit_->SetLabel("Cancel audit");
    next_page_->Enable(false);
    initial_state_->Enable(false);
    compare_previous_->Enable(false);
    status_->SetLabel("Starting read-only history audit…");
    request_audit_page(0);
}

void HistoryView::stop_audit() {
    if (!audit_in_progress_) return;
    cancel_pending();
    audit_in_progress_ = false;
    audit_->SetLabel("Audit history");
    next_page_->Enable(page_ && page_->has_more);
    initial_state_->Enable(bool(actor_));
    compare_previous_->Enable(selected_step_ && *selected_step_ > 0);
    status_->SetLabel(wxString::Format("Audit canceled after %llu of %llu steps (%llu delta bytes verified).",
        static_cast<unsigned long long>(audit_verified_),
        static_cast<unsigned long long>(page_ ? page_->history_count : 0),
        static_cast<unsigned long long>(audit_bytes_)));
}

void HistoryView::request_audit_page(std::uint64_t after_step) {
    if (!actor_ || !audit_in_progress_ || pending_) return;
    pending_kind_ = PendingKind::audit;
    auto submission = actor_->audit_history(expected_edit_, after_step);
    if (!submission) {
        audit_in_progress_ = false;
        audit_->SetLabel("Audit history");
        initial_state_->Enable(bool(actor_));
        compare_previous_->Enable(selected_step_ && *selected_step_ > 0);
        status_->SetLabel(wxString::Format("Audit stopped after %llu of %llu steps: %s",
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

void HistoryView::request_preview(std::uint64_t step) {
    if (!actor_ || audit_in_progress_) return;
    comparison_base_.reset();
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
    auto result = history_save_->result.get();
    history_save_.reset();
    if (result) {
        save_status_->SetLabel(wxString::Format("Recovered step %llu from ", static_cast<unsigned long long>(step)) +
            path_text(source.filename()) + " saved to " + path_text(result.value().path) +
            ". Open this independent project with File > Open Project. Source unchanged; undo/redo retained.");
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
        if (kind == PendingKind::audit) {
            audit_in_progress_ = false;
            audit_->SetLabel("Audit history");
            initial_state_->Enable(bool(actor_));
            compare_previous_->Enable(selected_step_ && *selected_step_ > 0);
            status_->SetLabel(wxString::Format("Audit stopped after %llu of %llu steps (%llu delta bytes): %s",
                static_cast<unsigned long long>(audit_verified_),
                static_cast<unsigned long long>(page_ ? page_->history_count : 0),
                static_cast<unsigned long long>(audit_bytes_), text(result.error().message)));
        } else {
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
            audit_->SetLabel("Audit history");
            initial_state_->Enable(bool(actor_));
            status_->SetLabel("History audit returned no report.");
            return;
        }
        const auto& received = *result.value().history_audit;
        if (!project_ || received.uuid != project_->state->uuid ||
            received.source_revisions.edit != expected_edit_) {
            audit_in_progress_ = false;
            audit_->SetLabel("Audit history");
            initial_state_->Enable(bool(actor_));
            status_->SetLabel("Project identity or revision changed; restart the history audit.");
            return;
        }
        audit_verified_ += received.entries_verified;
        audit_bytes_ += received.delta_bytes;
        if (page_) {
            page_->history_count = received.history_count;
            page_->history_cursor = received.history_cursor;
        }
        if (received.has_more) {
            status_->SetLabel(wxString::Format("Auditing durable history: %llu of %llu steps verified (%llu delta bytes)…",
                static_cast<unsigned long long>(audit_verified_),
                static_cast<unsigned long long>(received.history_count),
                static_cast<unsigned long long>(audit_bytes_)));
            request_audit_page(received.next_after_step);
        } else {
            audit_in_progress_ = false;
            audit_->SetLabel("Audit history");
            next_page_->Enable(page_ && page_->has_more);
            initial_state_->Enable(bool(actor_));
            compare_previous_->Enable(selected_step_ && *selected_step_ > 0);
            status_->SetLabel(wxString::Format("History audit passed: %llu of %llu steps verified; %llu delta bytes checked; cursor %llu.",
                static_cast<unsigned long long>(audit_verified_),
                static_cast<unsigned long long>(received.history_count),
                static_cast<unsigned long long>(audit_bytes_),
                static_cast<unsigned long long>(received.history_cursor)));
        }
        return;
    }

    if (!result.value().history_preview) {
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
    entries_->populate(rows_.size(), [this](std::size_t row, int column) {
        const auto& entry = rows_[row];
        switch (column) {
        case 0: return wxString::Format("%llu", static_cast<unsigned long long>(entry.step));
        case 1: return wxString::Format("%llu", static_cast<unsigned long long>(entry.group_id));
        case 2: return change_text(entry);
        default: return entry.applied ? wxString("Applied") : wxString("Redo");
        }
    });
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
    preview_rows_.reserve(state.annotations.size() + state.bookmarks.size() + state.types.size() +
        state.type_assignments.size() + state.decisions.functions.size() + state.decisions.regions.size() +
        state.decisions.references.size() + state.debug_variables.size() + state.patches.size());
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
        "%llu annotations, %llu bookmarks, %llu types, %llu assignments, %llu function records, "
        "%llu regions, %llu references, %llu debug variables, %llu patches.",
        static_cast<unsigned long long>(preview_->target_step),
        static_cast<unsigned long long>(preview_->source_cursor),
        static_cast<unsigned long long>(preview_->history_count),
        static_cast<unsigned long long>(preview_->replayed_steps),
        static_cast<unsigned long long>(preview_->delta_bytes),
        static_cast<unsigned long long>(state.annotations.size()),
        static_cast<unsigned long long>(state.bookmarks.size()),
        static_cast<unsigned long long>(state.types.size()),
        static_cast<unsigned long long>(state.type_assignments.size()),
        static_cast<unsigned long long>(state.decisions.functions.size()),
        static_cast<unsigned long long>(state.decisions.regions.size()),
        static_cast<unsigned long long>(state.decisions.references.size()),
        static_cast<unsigned long long>(state.debug_variables.size()),
        static_cast<unsigned long long>(state.patches.size())));
    preview_items_->populate(preview_rows_.size(), [this](std::size_t row, int column) {
        const auto& item = preview_rows_[row];
        switch (column) {
        case 0: return item.category;
        case 1: return item.location;
        case 2: return item.name;
        default: return item.details;
        }
    });
    if (comparison_base_ && comparison_base_->user) {
        const auto& before = *comparison_base_->user;
        struct ChangeCounts { std::size_t added=0, removed=0, changed=0; };
        auto count_changes = [](const auto& old_rows, const auto& new_rows) {
            ChangeCounts counts;
            for (const auto& old_row : old_rows) {
                const auto current = std::find_if(new_rows.begin(), new_rows.end(), [&](const auto& row) { return row.id == old_row.id; });
                if (current == new_rows.end()) ++counts.removed;
                else if (!(*current == old_row)) ++counts.changed;
            }
            for (const auto& new_row : new_rows)
                if (std::none_of(old_rows.begin(), old_rows.end(), [&](const auto& row) { return row.id == new_row.id; })) ++counts.added;
            return counts;
        };
        const auto annotations = count_changes(before.annotations, state.annotations);
        const auto bookmarks = count_changes(before.bookmarks, state.bookmarks);
        const auto types = count_changes(before.types, state.types);
        const auto assignments = count_changes(before.type_assignments, state.type_assignments);
        preview_status_->SetLabel(wxString::Format(
            "Step %llu compared with %llu: annotations +%llu/-%llu/~%llu, bookmarks +%llu/-%llu/~%llu, types +%llu/-%llu/~%llu, assignments +%llu/-%llu/~%llu. Rows show selected-step state.",
            static_cast<unsigned long long>(preview_->target_step),
            static_cast<unsigned long long>(comparison_base_->target_step),
            static_cast<unsigned long long>(annotations.added), static_cast<unsigned long long>(annotations.removed), static_cast<unsigned long long>(annotations.changed),
            static_cast<unsigned long long>(bookmarks.added), static_cast<unsigned long long>(bookmarks.removed), static_cast<unsigned long long>(bookmarks.changed),
            static_cast<unsigned long long>(types.added), static_cast<unsigned long long>(types.removed), static_cast<unsigned long long>(types.changed),
            static_cast<unsigned long long>(assignments.added), static_cast<unsigned long long>(assignments.removed), static_cast<unsigned long long>(assignments.changed)));
    }
}

} // namespace hexlab::desktop
