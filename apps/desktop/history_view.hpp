#pragma once

#include "data_views.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/project_actor.hpp"
#include <wx/button.h>
#include <wx/checkbox.h>
#include <wx/stattext.h>
#include <wx/timer.h>
#include <wx/textctrl.h>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <stop_token>
#include <vector>

namespace hexlab::desktop {

class HistoryView final : public wxPanel {
public:
    explicit HistoryView(wxWindow*);
    ~HistoryView() override;
    void update(std::optional<DocumentId>, std::shared_ptr<ProjectActor>,
                std::shared_ptr<const ProjectSnapshot>);
    std::function<void(Location)> navigate;
    std::function<void(std::filesystem::path)> open_project;

private:
    enum class PendingKind { page, preview, comparison_base, comparison_current, audit, audit_replay };
    struct PreviewItem {
        wxString category, location, name, details;
        std::optional<Location> target;
    };
    void cancel_pending();
    void request_page(std::uint64_t after_step);
    void request_preview(std::uint64_t step);
    void request_audit_page(std::uint64_t after_step);
    void request_audit_replay();
    void begin_audit();
    void stop_audit();
    void record_audit_result(const wxString&);
    void set_audit_status(const wxString&);
    void update_source_status();
    void copy_audit_json();
    void compare_with_previous();
    void compare_with_current();
    void save_selected_history();
    void poll_history_save();
    void update_save_controls();
    void poll();
    void render_entries();
    void render_preview();
    void show_error(const Error&);

    wxTimer timer_;
    VirtualTable* entries_ = nullptr;
    VirtualTable* preview_items_ = nullptr;
    wxStaticText* status_ = nullptr;
    wxStaticText* source_status_ = nullptr;
    wxStaticText* audit_status_ = nullptr;
    wxStaticText* preview_status_ = nullptr;
    wxTextCtrl* history_filter_ = nullptr;
    wxStaticText* history_filter_status_ = nullptr;
    wxButton* refresh_ = nullptr;
    wxButton* next_page_ = nullptr;
    wxButton* initial_state_ = nullptr;
    wxButton* compare_previous_ = nullptr;
    wxButton* compare_current_ = nullptr;
    wxButton* audit_ = nullptr;
    wxButton* copy_audit_ = nullptr;
    wxButton* copy_audit_json_ = nullptr;
    wxButton* save_audit_ = nullptr;
    wxCheckBox* verify_audit_replay_ = nullptr;
    wxButton* navigate_patch_ = nullptr;
    wxButton* save_copy_ = nullptr;
    wxButton* open_copy_ = nullptr;
    wxButton* cancel_save_ = nullptr;
    wxStaticText* save_status_ = nullptr;
    struct HistorySaveWork {
        std::stop_source cancellation;
        std::promise<Result<database::SavedProject>> completion;
        std::future<Result<database::SavedProject>> result = completion.get_future();
        std::filesystem::path source;
        database::ProjectUuid uuid{};
        std::uint64_t step = 0;
    };
    std::shared_ptr<HistorySaveWork> history_save_;
    std::optional<std::filesystem::path> saved_copy_path_;
    std::shared_ptr<ProjectActor> actor_;
    std::shared_ptr<const ProjectSnapshot> project_;
    std::optional<DocumentId> document_id_;
    std::uint64_t expected_edit_ = 0;
    std::vector<database::HistoryEntry> rows_;
    std::vector<std::size_t> visible_history_rows_;
    std::optional<database::HistoryPage> page_;
    std::optional<database::HistoryPreview> preview_;
    std::optional<database::HistoryPreview> comparison_base_;
    std::shared_ptr<const database::ProjectState> comparison_current_;
    std::uint64_t comparison_current_edit_ = 0;
    std::optional<ProjectSubmission> pending_;
    PendingKind pending_kind_ = PendingKind::page;
    std::uint64_t pending_expected_edit_ = 0;
    std::optional<std::uint64_t> selected_step_;
    std::vector<PreviewItem> preview_rows_;
    std::optional<std::size_t> selected_preview_row_;
    bool audit_in_progress_ = false;
    bool audit_resume_available_ = false;
    bool audit_verify_replay_ = false;
    bool audit_structural_complete_ = false;
    database::HistorySourceIdentityCheck audit_source_identity_check_ =
        database::HistorySourceIdentityCheck::not_checked;
    std::size_t audit_verified_ = 0;
    std::size_t audit_bytes_ = 0;
    std::uint64_t audit_next_after_step_ = 0;
    wxString audit_report_;
};

} // namespace hexlab::desktop
