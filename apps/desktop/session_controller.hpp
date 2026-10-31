#pragma once
#include "hexlab/workspace/document_manager.hpp"
#include "hexlab/database/project_state.hpp"
#include <wx/timer.h>
#include <filesystem>
#include <chrono>
#include <map>
#include <future>
#include <cstdint>
#include <optional>
#include <stop_token>
#include <variant>
#include <vector>
#include "hexlab/workspace/listing.hpp"
#include "hexlab/workspace/project_graph.hpp"
namespace hexlab::desktop {
struct AutomaticBackupOptions {
    bool enabled = false;
    int interval_minutes = 15;
    std::size_t retain = 5;
};
enum class SourceArchiveAction : std::uint8_t { create, rotate, list, prune, verify, restore };
class SessionController final : public wxEvtHandler {
  public:
    explicit SessionController(std::function<void()> changed);
    ~SessionController() override;
    void open(OpenRequest);
    void open_project(std::filesystem::path, database::ProjectMode = database::ProjectMode::read_write,
                      AnalysisOptions = {});
    void cancel();
    void cancel_analyses();
    void wait_for_analysis_workers();
    void close();
    void close(DocumentId);
    void close_all();
    void activate(DocumentId);
    Result<ProjectOperationId> execute(DocumentId, ProjectCommand);
    Result<ProjectOperationId> undo(DocumentId);
    Result<ProjectOperationId> redo(DocumentId);
    Result<ProjectOperationId> reanalyze(DocumentId);
    Result<ProjectOperationId> reanalyze(DocumentId, AnalysisOptions);
    Result<ProjectOperationId> save(DocumentId);
    Result<ProjectOperationId> save_as(DocumentId, std::filesystem::path, bool replace = false);
    Result<ProjectOperationId> backup_to(DocumentId, std::filesystem::path, bool replace = false);
    Result<bool> rotate_backups(DocumentId, std::size_t retain = 5);
    Result<bool> list_backups(DocumentId);
    Result<bool> prune_backups(DocumentId, std::size_t retain);
    Result<bool> manage_source_archive(DocumentId, SourceArchiveAction, std::filesystem::path = {},
                                       std::size_t retain = 5, std::filesystem::path output = {});
    bool source_archive_pending() const { return source_archive_job_.has_value(); }
    void cancel_source_archive();
    bool backup_pending(DocumentId) const;
    AutomaticBackupOptions automatic_backup_options() const { return automatic_backup_options_; }
    Result<bool> configure_automatic_backups(AutomaticBackupOptions);
    wxString automatic_backup_status() const;
    void cancel_automatic_backups();
    void restart_automatic_backup_schedule();
    Result<bool> restore_backup(std::filesystem::path source, std::filesystem::path destination,
                                bool replace = false, AnalysisOptions = {});
    Result<bool> restore_recovery(std::filesystem::path source, std::filesystem::path destination,
                                  bool replace = false, AnalysisOptions = {});
    Result<bool> restore_backup_in_place(std::filesystem::path source, std::filesystem::path target,
                                         AnalysisOptions = {});
    Result<bool> restore_recovery_in_place(std::filesystem::path source, std::filesystem::path target,
                                           AnalysisOptions = {});
    Result<ProjectOperationId> export_binary(DocumentId, std::filesystem::path, bool replace = false);
    Result<bool> find(DocumentId, SearchQuery, const SearchLimits & = {});
    Result<bool> find_all(SearchQuery, const SearchLimits & = {});
    Result<bool> more_results_all();
    bool all_search_scope() const { return all_search_scope_; }
    void set_all_search_scope(bool value) { all_search_scope_ = value; }
    bool all_search_pending() const;
    Result<bool> more_results(DocumentId, bool follow = false);
    Result<bool> find_next(DocumentId);
    Result<bool> find_previous(DocumentId);
    Result<bool> find_next_all(DocumentId);
    Result<bool> find_previous_all(DocumentId);
    bool search_pending(DocumentId) const;
    bool read_pending(DocumentId) const;
    Result<bool> request_graph(DocumentId, std::optional<Location>, GraphKind, std::size_t call_depth = 1);
    std::shared_ptr<const ProjectGraph> graph_result(DocumentId) const;
    GraphKind graph_kind(DocumentId) const;
    std::size_t graph_call_depth(DocumentId) const;
    bool graph_pending(DocumentId) const;
    wxString graph_reason(DocumentId) const;
    wxString search_reason(DocumentId) const;
    Result<bool> request_listing(std::shared_ptr<const DocumentSnapshot>, Location);
    std::function<void(DocumentId, Location, const ListingPage &)> listing_ready;
    std::function<void(DocumentId, const wxString &)> message;
    std::function<void(std::filesystem::path, database::ProjectMode, Error,
                       Result<std::vector<database::ProjectRecoveryCandidate>>)> recovery_candidates_ready;
    Workspace &state() { return manager_->active_workspace(); }
    DocumentManager &documents() { return *manager_; }

  private:
    enum class BackupManagementKind : std::uint8_t { rotate, list, prune };
    std::shared_ptr<AnalysisPool> pool_;
    std::unique_ptr<DocumentManager> manager_;
    wxTimer timer_{this};
    std::function<void()> changed_;
    std::map<std::uint64_t, std::vector<ProjectSubmission>> receipts_;
    struct PendingProjectOpen { std::filesystem::path path; database::ProjectMode mode; };
    std::map<std::uint64_t, PendingProjectOpen> pending_project_opens_;
    struct RecoveryScan {
        std::filesystem::path failed_path;
        database::ProjectMode mode;
        Error open_error;
        std::shared_ptr<std::stop_source> cancellation;
        std::future<Result<database::ProjectRecoveryScan>> result;
    };
    std::vector<RecoveryScan> recovery_scans_;
    struct BackupRestore {
        AnalysisOptions options;
        std::shared_ptr<std::stop_source> cancellation;
        std::future<Result<database::SavedProject>> result;
        bool in_place = false;
    };
    std::optional<BackupRestore> backup_restore_;
    using BackupManagementResult = std::variant<database::BackupRotationResult, database::BackupListing,
                                                database::BackupPruneResult>;
    struct BackupManagement {
        DocumentId document;
        std::filesystem::path source_path;
        std::shared_ptr<std::stop_source> cancellation;
        std::future<Result<BackupManagementResult>> result;
        bool automatic = false;
        std::uint64_t schedule_generation = 0;
    };
    std::vector<BackupManagement> backup_management_;
    using SourceArchiveResult = std::variant<database::SourceArchiveResult, database::SourceArchiveRotationResult,
        database::SourceArchiveListing, database::SourceArchivePruneResult, database::SourceArchiveVerification,
        database::SourceArchiveRestore>;
    struct SourceArchiveJob {
        DocumentId document;
        std::filesystem::path project_path;
        std::shared_ptr<std::stop_source> cancellation;
        std::future<Result<SourceArchiveResult>> result;
    };
    std::optional<SourceArchiveJob> source_archive_job_;
    Result<bool> start_backup_management(DocumentId, BackupManagementKind, std::size_t, bool automatic = false);
    struct AutomaticBackupState {
        std::filesystem::path path;
        std::chrono::steady_clock::time_point due;
        wxString status;
        bool paused = false;
    };
    AutomaticBackupOptions automatic_backup_options_;
    std::map<std::uint64_t, AutomaticBackupState> automatic_backups_;
    std::chrono::steady_clock::time_point next_backup_poll_{};
    std::uint64_t backup_schedule_generation_ = 0;
    void load_automatic_backup_options();
    bool poll_automatic_backups();
    void scan_recovery_candidates(std::filesystem::path, database::ProjectMode, Error);
    Result<ProjectOperationId> observe(DocumentId, std::function<Result<ProjectSubmission>(ProjectActor &)>,
                                       bool watch_write = true);
    void poll();
    struct SearchJob {
        AnalysisKey key;
        SearchQuery query;
        SearchLimits limits;
        std::optional<SearchCursor> cursor;
        std::optional<AnalysisSubmission> job;
        bool pending = true, follow = true;
        std::string reason;
    };
    std::map<std::uint64_t, SearchJob> searches_;
    bool all_search_scope_ = false;
    bool poll_search();
    struct ListingJob {
        AnalysisKey key;
        Location begin;
        std::shared_ptr<const DocumentSnapshot> document;
        std::optional<AnalysisSubmission> job;
        std::shared_ptr<const ListingResult> cached;
        bool pending = true, suspended = false;
    };
    std::map<std::uint64_t, ListingJob> listings_;
    bool poll_listing();
    bool listing_busy(DocumentId) const;
    struct GraphJob {
        AnalysisKey key;
        std::uint64_t presentation = 0;
        GraphKind kind = GraphKind::function_cfg;
        std::size_t call_depth = 1;
        std::optional<Location> selection;
        std::optional<AnalysisSubmission> job;
        std::shared_ptr<const ProjectGraph> cached;
        bool pending = true;
        std::string reason;
    };
    std::map<std::uint64_t, GraphJob> graphs_;
    bool graph_busy(DocumentId) const;
    bool poll_graph();
};
} // namespace hexlab::desktop
