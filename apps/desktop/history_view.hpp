#pragma once

#include "data_views.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/workspace/project_actor.hpp"
#include <wx/button.h>
#include <wx/stattext.h>
#include <wx/timer.h>
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

private:
    enum class PendingKind { page, preview, comparison_base, audit };
    struct PreviewItem {
        wxString category, location, name, details;
        std::optional<Location> target;
    };
    void cancel_pending();
    void request_page(std::uint64_t after_step);
    void request_preview(std::uint64_t step);
    void request_audit_page(std::uint64_t after_step);
    void begin_audit();
    void stop_audit();
    void compare_with_previous();
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
    wxStaticText* preview_status_ = nullptr;
    wxButton* refresh_ = nullptr;
    wxButton* next_page_ = nullptr;
    wxButton* initial_state_ = nullptr;
    wxButton* compare_previous_ = nullptr;
    wxButton* audit_ = nullptr;
    wxButton* navigate_patch_ = nullptr;
    wxButton* save_copy_ = nullptr;
    wxButton* cancel_save_ = nullptr;
    wxStaticText* save_status_ = nullptr;
    struct HistorySaveWork {
        std::stop_source cancellation;
        std::promise<Result<database::SavedProject>> completion;
        std::future<Result<database::SavedProject>> result = completion.get_future();
        std::filesystem::path source;
        std::uint64_t step = 0;
    };
    std::shared_ptr<HistorySaveWork> history_save_;
    std::shared_ptr<ProjectActor> actor_;
    std::shared_ptr<const ProjectSnapshot> project_;
    std::optional<DocumentId> document_id_;
    std::uint64_t expected_edit_ = 0;
    std::vector<database::HistoryEntry> rows_;
    std::optional<database::HistoryPage> page_;
    std::optional<database::HistoryPreview> preview_;
    std::optional<database::HistoryPreview> comparison_base_;
    std::optional<ProjectSubmission> pending_;
    PendingKind pending_kind_ = PendingKind::page;
    std::uint64_t pending_expected_edit_ = 0;
    std::optional<std::uint64_t> selected_step_;
    std::vector<PreviewItem> preview_rows_;
    std::optional<std::size_t> selected_preview_row_;
    bool audit_in_progress_ = false;
    std::size_t audit_verified_ = 0;
    std::size_t audit_bytes_ = 0;
};

} // namespace hexlab::desktop
