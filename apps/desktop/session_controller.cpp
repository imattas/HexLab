#include "session_controller.hpp"
#include "hexlab/core/sha256.hpp"
#include <wx/config.h>
#include <algorithm>
#include <chrono>
#include <new>
#include <string>
#include <system_error>
#include <type_traits>
namespace hexlab::desktop {
namespace {
template <class T> T take(Result<T> result) {
    if (!result)
        throw std::runtime_error(result.error().message);
    return std::move(result.value());
}
bool aliases_open_project(const DocumentManager &manager, const std::filesystem::path &candidate) {
    std::error_code error;
    const auto normalized_candidate = std::filesystem::absolute(candidate, error).lexically_normal();
    if (error)
        return false;
    for (const auto &document : manager.documents()) {
        if (!document.path)
            continue;
        if (document.path->lexically_normal() == normalized_candidate)
            return true;
        error.clear();
        if (std::filesystem::equivalent(*document.path, candidate, error) && !error)
            return true;
    }
    return false;
}
PoolLimits configured_pool_limits() {
    PoolLimits limits;
    long workers = static_cast<long>(limits.max_workers);
    if (auto *config = wxConfigBase::Get())
        config->Read("/Analysis/Workers", &workers, workers);
    if (workers >= 1 && workers <= 16)
        limits.max_workers = static_cast<std::size_t>(workers);
    return limits;
}
} // namespace
SessionController::SessionController(std::function<void()> changed)
    : pool_(std::make_shared<AnalysisPool>(configured_pool_limits())), manager_(take(DocumentManager::create(pool_))),
      changed_(std::move(changed)) {
    load_automatic_backup_options();
    Bind(wxEVT_TIMER, [this](wxTimerEvent &) { poll(); });
    timer_.Start(25);
}
SessionController::~SessionController() {
    timer_.Stop();
    if (backup_restore_)
        backup_restore_->cancellation->request_stop();
    if (backup_restore_ && backup_restore_->result.valid())
        backup_restore_->result.wait();
    backup_restore_.reset();
    for (auto &job : backup_management_)
        job.cancellation->request_stop();
    if (source_archive_job_) source_archive_job_->cancellation->request_stop();
    if (source_archive_job_ && source_archive_job_->result.valid()) source_archive_job_->result.wait();
    source_archive_job_.reset();
    for (auto &job : backup_management_)
        if (job.result.valid())
            job.result.wait();
    backup_management_.clear();
    for (auto &scan : recovery_scans_)
        scan.cancellation->request_stop();
    for (auto &scan : recovery_scans_)
        if (scan.result.valid())
            scan.result.wait();
    recovery_scans_.clear();
    manager_.reset();
    pool_.reset();
}
void SessionController::open(OpenRequest request) {
    auto opened = manager_->import_binary(std::move(request));
    if (!opened)
        manager_->report_error(opened.error());
    changed_();
}
void SessionController::open_project(std::filesystem::path path, database::ProjectMode mode, AnalysisOptions options) {
    auto tracked_path = path;
    auto opened = manager_->open_project(std::move(path), mode, options);
    if (!opened)
        manager_->report_error(opened.error());
    else
        pending_project_opens_.insert_or_assign(opened.value().value,
                                                  PendingProjectOpen{std::move(tracked_path), mode});
    changed_();
}
void SessionController::scan_recovery_candidates(std::filesystem::path failed_path,
                                                 database::ProjectMode mode, Error open_error) {
    if (recovery_scans_.size() >= 1)
        return;
    auto directory = failed_path.parent_path();
    if (directory.empty()) {
        std::error_code error;
        directory = std::filesystem::current_path(error);
        if (error)
            return;
    }
    try {
        auto cancellation = std::make_shared<std::stop_source>();
        const auto token = cancellation->get_token();
        auto result = std::async(std::launch::async, [directory = std::move(directory), token] {
            return database::ProjectStore::inspect_recovery_directory(directory, token);
        });
        recovery_scans_.push_back({std::move(failed_path), mode, std::move(open_error),
                                   std::move(cancellation), std::move(result)});
    } catch (const std::system_error &) {
        // Project-open failure remains visible in the Output pane if a worker cannot be started.
    } catch (const std::bad_alloc &) {
        // Recovery discovery is optional; keep the original open error visible.
    }
}
void SessionController::cancel() {
    if (auto id = manager_->active_document()) {
        if (source_archive_job_ && source_archive_job_->document == *id)
            source_archive_job_->cancellation->request_stop();
        for (auto &job : backup_management_)
            if (job.document == *id)
                job.cancellation->request_stop();
        if (auto actor = manager_->actor(*id))
            actor->cancel_analysis();
        if (auto found = graphs_.find(id->value); found != graphs_.end()) {
            found->second.pending = false;
            found->second.job.reset();
            found->second.reason = "Canceled";
        }
        if (auto found = searches_.find(id->value); found != searches_.end()) {
            found->second.pending = false;
            found->second.job.reset();
            found->second.reason = "Canceled";
        }
        if (auto found = listings_.find(id->value); found != listings_.end()) {
            found->second.pending = false;
            found->second.job.reset();
            found->second.suspended = true;
        }
    }
    manager_->cancel_open();
    for (auto it = pending_project_opens_.begin(); it != pending_project_opens_.end();) {
        if (!manager_->actor({it->first}))
            it = pending_project_opens_.erase(it);
        else
            ++it;
    }
    changed_();
}
void SessionController::cancel_analyses() {
    for (const auto &document : manager_->documents())
        if (auto actor = manager_->actor(document.id))
            actor->cancel_analysis();
    for (auto &[id, job] : graphs_) {
        (void)id;
        job.pending = false;
        job.job.reset();
        job.cached.reset();
        job.reason = "Plugin set changed; refreshing analysis";
    }
    listings_.clear();
    changed_();
}
void SessionController::wait_for_analysis_workers() {
    for (const auto &document : manager_->documents())
        if (auto actor = manager_->actor(document.id))
            actor->cancel_analysis_and_wait();
}
bool SessionController::read_pending(DocumentId id) const {
    auto found = listings_.find(id.value);
    return graph_pending(id) || search_pending(id) || (found != listings_.end() && found->second.pending);
}
void SessionController::close() {
    if (auto id = manager_->active_document()) {
        close(*id);
        return;
    }
    changed_();
}
void SessionController::close(DocumentId id) {
    for (auto &job : backup_management_)
        if (job.document == id)
            job.cancellation->request_stop();
    if (source_archive_job_ && source_archive_job_->document == id)
        source_archive_job_->cancellation->request_stop();
    automatic_backups_.erase(id.value);
    pending_project_opens_.erase(id.value);
    auto result = manager_->close(id);
    if (!result)
        manager_->report_error(result.error());
    changed_();
}
void SessionController::close_all() {
    for (auto &job : backup_management_)
        job.cancellation->request_stop();
    if (source_archive_job_) source_archive_job_->cancellation->request_stop();
    automatic_backups_.clear();
    pending_project_opens_.clear();
    manager_->close_all();
    changed_();
}
void SessionController::activate(DocumentId id) {
    auto result = manager_->activate(id);
    if (result)
        changed_();
}
Result<ProjectOperationId> SessionController::observe(DocumentId id,
                                                      std::function<Result<ProjectSubmission>(ProjectActor &)> submit,
                                                      bool watch_write) {
    auto actor = manager_->actor(id);
    if (!actor)
        return Error{ErrorCode::invalid_argument, "The original document is closed"};
    auto &records = receipts_[id.value];
    if (records.size() >= 128)
        return Error{ErrorCode::resource_limit, "Wait for pending document operations"};
    records.reserve(128);
    auto submitted = submit(*actor);
    if (!submitted)
        return submitted.error();
    auto operation = std::move(submitted.value());
    auto result = operation.id;
    if (watch_write) {
        auto watched = manager_->watch(id, operation);
        (void)watched;
    }
    records.push_back(std::move(operation));
    changed_();
    return result;
}
Result<ProjectOperationId> SessionController::execute(DocumentId id, ProjectCommand command) {
    return observe(
        id, [command = std::move(command)](ProjectActor &actor) mutable { return actor.execute(std::move(command)); });
}
Result<ProjectOperationId> SessionController::undo(DocumentId id) {
    return observe(id, [](ProjectActor &actor) { return actor.undo(); });
}
Result<ProjectOperationId> SessionController::redo(DocumentId id) {
    return observe(id, [](ProjectActor &actor) { return actor.redo(); });
}
Result<ProjectOperationId> SessionController::reanalyze(DocumentId id) {
    listings_.erase(id.value);
    if (auto found = graphs_.find(id.value); found != graphs_.end()) {
        found->second.pending = true;
        found->second.job.reset();
        found->second.cached.reset();
    }
    return observe(id, [](ProjectActor &actor) { return actor.ready(true); }, false);
}
Result<ProjectOperationId> SessionController::reanalyze(DocumentId id, AnalysisOptions options) {
    listings_.erase(id.value);
    if (auto found = graphs_.find(id.value); found != graphs_.end()) {
        found->second.pending = true;
        found->second.job.reset();
        found->second.cached.reset();
    }
    auto actor = manager_->actor(id);
    if (!actor)
        return Error{ErrorCode::invalid_argument, "The original document is closed"};
    actor->cancel_analysis();
    return observe(id, [options = std::move(options)](ProjectActor &writer) mutable {
        return writer.reanalyze(std::move(options));
    }, false);
}
Result<ProjectOperationId> SessionController::save(DocumentId id) {
    return observe(id, [](ProjectActor &actor) { return actor.save(); });
}
Result<ProjectOperationId> SessionController::save_as(DocumentId id, std::filesystem::path path, bool replace) {
    return observe(id, [path = std::move(path), replace](ProjectActor &actor) {
        return actor.save_as(path, replace ? database::ReplacePolicy::replace_existing
                                           : database::ReplacePolicy::fail_if_exists);
    });
}
Result<ProjectOperationId> SessionController::backup_to(DocumentId id, std::filesystem::path path, bool replace) {
    if (aliases_open_project(*manager_, path))
        return Error{ErrorCode::conflict, "Backup destination is already open as a project"};
    return observe(id, [path = std::move(path), replace](ProjectActor &actor) {
        return actor.backup_to(path, replace ? database::ReplacePolicy::replace_existing
                                             : database::ReplacePolicy::fail_if_exists);
    }, false);
}
Result<bool> SessionController::start_backup_management(DocumentId id, BackupManagementKind kind,
                                                        std::size_t retain, bool automatic) {
    auto &jobs = backup_management_;
    if (std::any_of(jobs.begin(), jobs.end(), [id](const auto &job) { return job.document == id; }))
        return Error{ErrorCode::busy, "Wait for the current backup operation to finish"};
    std::optional<std::filesystem::path> path;
    for (const auto &document : documents().documents())
        if (document.id == id)
            path = document.path;
    if (!path)
        return Error{ErrorCode::unsupported, "Save the project before managing rotated backups"};
    const auto project = manager_->project(id);
    if (!project || !project->state)
        return Error{ErrorCode::busy, "Wait for the project to finish opening"};
    const auto expected_uuid = project->state->uuid;
    if ((kind == BackupManagementKind::rotate || kind == BackupManagementKind::prune) &&
        (retain == 0 || retain > 32))
        return Error{ErrorCode::invalid_argument, "Backup retention must be from 1 through 32"};
    try {
        auto base_name = path->stem().native();
        base_name += std::filesystem::path("-backups").native();
        base_name += path->extension().native();
        auto backup_base = path->parent_path() / std::filesystem::path(std::move(base_name));
        auto cancellation = std::make_shared<std::stop_source>();
        const auto token = cancellation->get_token();
        auto result = std::async(std::launch::async,
            [path = *path, base = std::move(backup_base), kind, retain, token, expected_uuid]()
                -> Result<BackupManagementResult> {
                auto opened = database::ProjectStore::open(path, database::ProjectMode::read_only, token);
                if (!opened)
                    return opened.error();
                auto snapshot = opened.value()->snapshot();
                if (!snapshot)
                    return snapshot.error();
                if (snapshot.value()->uuid != expected_uuid)
                    return Error{ErrorCode::conflict, "Backup source was replaced by a different project"};
                if (kind == BackupManagementKind::rotate) {
                    auto value = opened.value()->backup_to_rotating(base, retain, token);
                    if (!value)
                        return value.error();
                    return BackupManagementResult{std::move(value.value())};
                }
                if (kind == BackupManagementKind::list) {
                    auto value = opened.value()->list_rotated_backups(base, token);
                    if (!value)
                        return value.error();
                    return BackupManagementResult{std::move(value.value())};
                }
                auto value = opened.value()->prune_rotated_backups(base, retain, token);
                if (!value)
                    return value.error();
                return BackupManagementResult{std::move(value.value())};
            });
        jobs.push_back({id, *path, std::move(cancellation), std::move(result), automatic,
                       backup_schedule_generation_});
        return true;
    } catch (const std::system_error &error) {
        return Error{ErrorCode::resource_limit, error.what()};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot start backup management"};
    }
}
Result<bool> SessionController::rotate_backups(DocumentId id, std::size_t retain) {
    return start_backup_management(id, BackupManagementKind::rotate, retain);
}
Result<bool> SessionController::list_backups(DocumentId id) {
    return start_backup_management(id, BackupManagementKind::list, 0);
}
Result<bool> SessionController::prune_backups(DocumentId id, std::size_t retain) {
    return start_backup_management(id, BackupManagementKind::prune, retain);
}
void SessionController::cancel_source_archive() {
    if (source_archive_job_) source_archive_job_->cancellation->request_stop();
}
Result<bool> SessionController::manage_source_archive(DocumentId id, SourceArchiveAction action,
                                                       std::filesystem::path selected_path,
                                                       std::size_t retain) {
    if (source_archive_job_)
        return Error{ErrorCode::busy, "Wait for the current source archive operation to finish"};
    std::optional<std::filesystem::path> project_path;
    for (const auto &document : manager_->documents())
        if (document.id == id) project_path = document.path;
    if (!project_path)
        return Error{ErrorCode::unsupported, "Save the project before managing external source archives"};
    const auto project = manager_->project(id);
    if (!project || !project->state)
        return Error{ErrorCode::busy, "Wait for the project to finish opening"};
    if ((action == SourceArchiveAction::create || action == SourceArchiveAction::verify) && selected_path.empty())
        return Error{ErrorCode::invalid_argument, "Choose a source archive path"};
    if ((action == SourceArchiveAction::rotate || action == SourceArchiveAction::prune) &&
        (retain == 0 || retain > 32))
        return Error{ErrorCode::invalid_argument, "Source archive retention must be from 1 through 32"};
    auto base_path = [&] {
        auto name = project_path->stem().native();
        name += std::filesystem::path("-source-archives").native();
        name += project_path->extension().native();
        return project_path->parent_path() / std::filesystem::path(std::move(name));
    }();
    try {
        auto cancellation = std::make_shared<std::stop_source>();
        const auto token = cancellation->get_token();
        const auto expected_uuid = project->state->uuid;
        auto result = std::async(std::launch::async,
            [path = *project_path, base = std::move(base_path), selected = std::move(selected_path),
             action, retain, token, expected_uuid]() -> Result<SourceArchiveResult> {
                auto opened = database::ProjectStore::open(path, database::ProjectMode::read_only, token);
                if (!opened) return opened.error();
                auto snapshot = opened.value()->snapshot();
                if (!snapshot) return snapshot.error();
                if (snapshot.value()->uuid != expected_uuid)
                    return Error{ErrorCode::conflict, "Project source was replaced by a different project"};
                const auto options = database::SourceArchiveOptions{};
                switch (action) {
                case SourceArchiveAction::create: {
                    auto value = opened.value()->archive_external_source(selected, options, token);
                    if (!value) return value.error();
                    return SourceArchiveResult{std::move(value.value())};
                }
                case SourceArchiveAction::rotate: {
                    auto value = opened.value()->archive_external_source_rotating(base, retain, options, token);
                    if (!value) return value.error();
                    return SourceArchiveResult{std::move(value.value())};
                }
                case SourceArchiveAction::list: {
                    auto value = opened.value()->list_rotated_source_archives(base, options.max_bytes, token);
                    if (!value) return value.error();
                    return SourceArchiveResult{std::move(value.value())};
                }
                case SourceArchiveAction::prune: {
                    auto value = opened.value()->prune_rotated_source_archives(base, retain, options.max_bytes, token);
                    if (!value) return value.error();
                    return SourceArchiveResult{std::move(value.value())};
                }
                case SourceArchiveAction::verify: {
                    auto value = opened.value()->verify_source_archive(selected, options.max_bytes, token);
                    if (!value) return value.error();
                    return SourceArchiveResult{std::move(value.value())};
                }
                }
                return Error{ErrorCode::invalid_argument, "Unknown source archive operation"};
            });
        source_archive_job_.emplace(SourceArchiveJob{id, *project_path, std::move(cancellation), std::move(result)});
        changed_();
        return true;
    } catch (const std::system_error &error) {
        return Error{ErrorCode::resource_limit, error.what()};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot start source archive operation"};
    }
}
Result<bool> SessionController::restore_backup(std::filesystem::path source, std::filesystem::path destination,
                                               bool replace, AnalysisOptions options) {
    if (backup_restore_)
        return Error{ErrorCode::busy, "A backup restore is already running"};
    if (source.empty() || destination.empty())
        return Error{ErrorCode::invalid_argument, "Choose both a backup and a destination project"};
    if (aliases_open_project(*manager_, destination))
        return Error{ErrorCode::conflict, "Restore destination is already open as a project"};
    try {
        auto cancellation = std::make_shared<std::stop_source>();
        const auto token = cancellation->get_token();
        auto result = std::async(std::launch::async,
            [source = std::move(source), destination = std::move(destination), replace, token]()
                -> Result<database::SavedProject> {
                auto backup = database::ProjectStore::open(source, database::ProjectMode::read_only, token);
                if (!backup)
                    return backup.error();
                return backup.value()->save_as(destination, replace ? database::ReplacePolicy::replace_existing
                                                                   : database::ReplacePolicy::fail_if_exists,
                                               token);
            });
        backup_restore_.emplace(BackupRestore{std::move(options), std::move(cancellation), std::move(result)});
        changed_();
        return true;
    } catch (const std::system_error &error) {
        return Error{ErrorCode::resource_limit, error.what()};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot start backup restore"};
    }
}
Result<bool> SessionController::restore_recovery(std::filesystem::path source, std::filesystem::path destination,
                                                 bool replace, AnalysisOptions options) {
    if (backup_restore_)
        return Error{ErrorCode::busy, "A project restore is already running"};
    if (source.empty() || destination.empty())
        return Error{ErrorCode::invalid_argument, "Choose both a recovery artifact and a destination project"};
    if (aliases_open_project(*manager_, destination))
        return Error{ErrorCode::conflict, "Restore destination is already open as a project"};
    try {
        auto cancellation = std::make_shared<std::stop_source>();
        const auto token = cancellation->get_token();
        auto result = std::async(std::launch::async,
            [source = std::move(source), destination = std::move(destination), replace, token]()
                -> Result<database::SavedProject> {
                std::error_code error;
                const auto absolute_source = std::filesystem::absolute(source, error).lexically_normal();
                if (error) return Error{ErrorCode::io, "Cannot resolve recovery artifact path: " + error.message()};
                auto candidates = database::ProjectStore::discover_recovery_candidates(absolute_source.parent_path(), token);
                if (!candidates) return candidates.error();
                const auto found = std::find_if(candidates.value().begin(), candidates.value().end(),
                    [&](const database::ProjectRecoveryCandidate &candidate) {
                        std::error_code candidate_error;
                        const auto candidate_path = std::filesystem::absolute(candidate.path, candidate_error).lexically_normal();
                        return !candidate_error && candidate_path == absolute_source;
                    });
                if (found == candidates.value().end())
                    return Error{ErrorCode::invalid_argument, "Selected file is not a fully validated HexLab recovery artifact"};
                return database::ProjectStore::recover_candidate(*found, destination,
                    replace ? database::ReplacePolicy::replace_existing : database::ReplacePolicy::fail_if_exists, token);
            });
        backup_restore_.emplace(BackupRestore{std::move(options), std::move(cancellation), std::move(result)});
        changed_();
        return true;
    } catch (const std::system_error &error) {
        return Error{ErrorCode::resource_limit, error.what()};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot start recovery artifact restore"};
    }
}
Result<bool> SessionController::restore_backup_in_place(std::filesystem::path source,
                                                        std::filesystem::path target,
                                                        AnalysisOptions options) {
    if (backup_restore_)
        return Error{ErrorCode::busy, "A backup restore is already running"};
    if (source.empty() || target.empty())
        return Error{ErrorCode::invalid_argument, "Choose both a backup and a target project"};
    if (aliases_open_project(*manager_, target))
        return Error{ErrorCode::conflict, "Close every open view of the target project before restoring it in place"};
    if (aliases_open_project(*manager_, source))
        return Error{ErrorCode::conflict, "Close the backup project before restoring it in place"};
    try {
        auto cancellation = std::make_shared<std::stop_source>();
        const auto token = cancellation->get_token();
        auto result = std::async(std::launch::async,
            [source = std::move(source), target = std::move(target), token]()
                -> Result<database::SavedProject> {
                return database::ProjectStore::restore_backup_in_place(source, target, token);
            });
        backup_restore_.emplace(BackupRestore{std::move(options), std::move(cancellation), std::move(result), true});
        changed_();
        return true;
    } catch (const std::system_error &error) {
        return Error{ErrorCode::resource_limit, error.what()};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot start in-place backup restore"};
    }
}
Result<bool> SessionController::restore_recovery_in_place(std::filesystem::path source,
                                                          std::filesystem::path target,
                                                          AnalysisOptions options) {
    if (backup_restore_)
        return Error{ErrorCode::busy, "A project restore is already running"};
    if (source.empty() || target.empty())
        return Error{ErrorCode::invalid_argument, "Choose both a recovery artifact and a target project"};
    if (aliases_open_project(*manager_, target))
        return Error{ErrorCode::conflict, "Close every open view of the target project before restoring it in place"};
    if (aliases_open_project(*manager_, source))
        return Error{ErrorCode::conflict, "Close the recovery artifact if it is open as a project"};
    try {
        auto cancellation = std::make_shared<std::stop_source>();
        const auto token = cancellation->get_token();
        auto result = std::async(std::launch::async,
            [source = std::move(source), target = std::move(target), token]()
                -> Result<database::SavedProject> {
                std::error_code error;
                const auto absolute_source = std::filesystem::absolute(source, error).lexically_normal();
                if (error) return Error{ErrorCode::io, "Cannot resolve recovery artifact path: " + error.message()};
                auto candidates = database::ProjectStore::discover_recovery_candidates(
                    absolute_source.parent_path(), token);
                if (!candidates) return candidates.error();
                const auto found = std::find_if(candidates.value().begin(), candidates.value().end(),
                    [&](const database::ProjectRecoveryCandidate &candidate) {
                        if (candidate.kind != database::RecoveryArtifactKind::previous_version) return false;
                        std::error_code candidate_error;
                        const auto candidate_path = std::filesystem::absolute(candidate.path, candidate_error).lexically_normal();
                        return !candidate_error && candidate_path == absolute_source;
                    });
                if (found == candidates.value().end())
                    return Error{ErrorCode::invalid_argument,
                                 "Selected file is not a fully validated retained previous-version artifact"};
                return database::ProjectStore::recover_candidate_in_place(*found, target, token);
            });
        backup_restore_.emplace(BackupRestore{std::move(options), std::move(cancellation), std::move(result), true});
        changed_();
        return true;
    } catch (const std::system_error &error) {
        return Error{ErrorCode::resource_limit, error.what()};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot start recovery artifact restore"};
    }
}
Result<ProjectOperationId> SessionController::export_binary(DocumentId id, std::filesystem::path path, bool replace) {
    return observe(id, [path = std::move(path), replace](ProjectActor &actor) {
        return actor.export_binary(path, replace ? database::ReplacePolicy::replace_existing
                                                 : database::ReplacePolicy::fail_if_exists);
    });
}
void SessionController::poll() {
    auto result = manager_->poll();
    if (!result)
        manager_->report_error(result.error());
    bool changed = !result || result.value() || state().opening();
    const auto open_error = state().last_error();
    if (open_error && open_error->code != ErrorCode::canceled) {
        for (auto it = pending_project_opens_.rbegin(); it != pending_project_opens_.rend(); ++it) {
            if (!manager_->actor({it->first})) {
                scan_recovery_candidates(it->second.path, it->second.mode, *open_error);
                break;
            }
        }
    }
    const auto documents = manager_->documents();
    for (auto it = pending_project_opens_.begin(); it != pending_project_opens_.end();) {
        const DocumentId id{it->first};
        if (!manager_->actor(id)) {
            it = pending_project_opens_.erase(it);
            continue;
        }
        const auto document = std::find_if(documents.begin(), documents.end(),
                                           [&](const auto &entry) { return entry.id == id; });
        if (document != documents.end() && document->save_state != DocumentSaveState::opening)
            it = pending_project_opens_.erase(it);
        else
            ++it;
    }
    for (auto it = recovery_scans_.begin(); it != recovery_scans_.end();) {
        if (it->result.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
            ++it;
            continue;
        }
        auto scan = it->result.get();
        auto failed_path = std::move(it->failed_path);
        const auto mode = it->mode;
        auto failure_detail = std::move(it->open_error);
        it = recovery_scans_.erase(it);
        changed = true;
        if (recovery_candidates_ready) {
            if (!scan) {
                recovery_candidates_ready(std::move(failed_path), mode, std::move(failure_detail), scan.error());
                continue;
            }
            auto &report = scan.value();
            failure_detail.message += "\n\nRecovery scan: " + std::to_string(report.visited_entries) +
                " directory entries, " + std::to_string(report.matching_names) + " recovery-name candidates, " +
                std::to_string(report.rejected_entries) + " rejected.";
            if (!report.complete)
                failure_detail.message += " The scan reached a safety limit; the candidate list may be incomplete.";
            const auto shown = std::min<std::size_t>(report.issues.size(), 8);
            if (shown) {
                failure_detail.message += "\nRejected recovery artifacts:";
                for (std::size_t index = 0; index < shown; ++index) {
                    const auto &issue = report.issues[index];
                    failure_detail.message += "\n  " + issue.name + ": " + issue.reason;
                }
            }
            const auto omitted = report.omitted_issues + report.issues.size() - shown;
            if (omitted)
                failure_detail.message += "\n  ... " + std::to_string(omitted) + " more diagnostics omitted.";
            recovery_candidates_ready(std::move(failed_path), mode, std::move(failure_detail),
                                      std::move(report.candidates));
        }
    }
    if (backup_restore_ && backup_restore_->result.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
        auto restored = [&]() -> Result<database::SavedProject> {
            try {
                return backup_restore_->result.get();
            } catch (const std::bad_alloc &) {
                return Error{ErrorCode::resource_limit, "Backup restore ran out of memory"};
            } catch (const std::exception &error) {
                return Error{ErrorCode::io, error.what()};
            } catch (...) {
                return Error{ErrorCode::io, "Unknown backup restore failure"};
            }
        }();
        auto options = std::move(backup_restore_->options);
        const bool in_place = backup_restore_->in_place;
        backup_restore_.reset();
        if (!restored) {
            manager_->report_error(restored.error());
        } else {
            auto opened = manager_->open_project(restored.value().path, database::ProjectMode::read_write, options);
            if (!opened)
                manager_->report_error(opened.error());
            else if (message)
                message(opened.value(), (in_place ? "Restored backup in place: " : "Restored backup as a new project: ") +
                                         wxString(restored.value().path.wstring()));
        }
        changed = true;
    }
    for (auto it = backup_management_.begin(); it != backup_management_.end();) {
        if (it->result.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
            ++it;
            continue;
        }
        Result<BackupManagementResult> result = Error{ErrorCode::io, "Backup management failed"};
        try {
            result = it->result.get();
        } catch (const std::bad_alloc &) {
            result = Error{ErrorCode::resource_limit, "Backup management ran out of memory"};
        } catch (const std::exception &error) {
            result = Error{ErrorCode::io, error.what()};
        } catch (...) {
            result = Error{ErrorCode::io, "Unknown backup management failure"};
        }
        const auto document = it->document;
        const auto source_path = it->source_path;
        const bool automatic = it->automatic;
        const auto schedule_generation = it->schedule_generation;
        it = backup_management_.erase(it);
        changed = true;
        // Closing or Save As may have changed the document while the worker ran.
        // Consume its future without attaching an old result to the new document.
        const auto live_documents = manager_->documents();
        if (std::none_of(live_documents.begin(), live_documents.end(), [&](const auto &entry) {
                return entry.id == document && entry.path && *entry.path == source_path;
            }))
            continue;
        if (automatic && schedule_generation == backup_schedule_generation_) {
            const auto found = automatic_backups_.find(document.value);
            if (found != automatic_backups_.end() && found->second.path == source_path) {
                auto &state = found->second;
                state.due = std::chrono::steady_clock::now() +
                            std::chrono::minutes(automatic_backup_options_.interval_minutes);
                if (!result)
                    state.status = result.error().code == ErrorCode::canceled ? wxString("Last backup canceled.")
                        : "Last backup failed: " + wxString::FromUTF8(result.error().message);
                else if (const auto *rotation = std::get_if<database::BackupRotationResult>(&result.value())) {
                    // An unattended retry must not grow an unprunable directory forever.
                    state.paused = !rotation->retention_satisfied;
                    state.status = "Last backup: " + wxString(rotation->backup.path.filename().wstring()) +
                        (rotation->retention_satisfied ? wxString(". Retention satisfied.")
                            : wxString(". Retention incomplete; schedule paused. Review backup generations, then restart the schedule."));
                }
            }
        }
        if (!result) {
            if (automatic) {
                if (message)
                    message(document, "Automatic project backup: " + wxString::FromUTF8(result.error().message));
            } else
                manager_->report_error(document, result.error());
            continue;
        }
        if (!message)
            continue;
        std::visit([&](const auto &value) {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, database::BackupRotationResult>) {
                message(document, wxString(automatic ? "Created automatic project backup: " : "Created rotated backup: ") +
                    wxString(value.backup.path.wstring()) +
                    wxString::Format(" (%zu older generations removed%s).", value.removed_generations,
                    value.retention_satisfied ? "" : automatic && schedule_generation == backup_schedule_generation_
                        ? "; retention incomplete; automatic schedule paused for review"
                        : "; retention limit was not fully met"));
            } else if constexpr (std::is_same_v<T, database::BackupListing>) {
                wxString summary = wxString::Format("Rotated backups (%zu listed%s):\n", value.backups.size(),
                    value.complete ? "" : ", scan incomplete");
                for (const auto &row : value.backups)
                    summary += wxString(row.backup.path.filename().wstring()) + "\n";
                if (value.backups.empty())
                    summary += "No rotated backups found.";
                message(document, std::move(summary));
            } else {
                message(document, wxString::Format("Pruned %zu rotated backups; %zu remain%s.", value.removed,
                    value.remaining, value.retention_satisfied ? "" : " (retention limit was not fully met)"));
            }
        }, result.value());
    }
    if (source_archive_job_ && source_archive_job_->result.wait_for(std::chrono::milliseconds(0)) ==
                                   std::future_status::ready) {
        Result<SourceArchiveResult> result = Error{ErrorCode::io, "Source archive operation failed"};
        try { result = source_archive_job_->result.get(); }
        catch (const std::bad_alloc &) { result = Error{ErrorCode::resource_limit, "Source archive operation ran out of memory"}; }
        catch (const std::exception &error) { result = Error{ErrorCode::io, error.what()}; }
        catch (...) { result = Error{ErrorCode::io, "Unknown source archive failure"}; }
        const auto document = source_archive_job_->document;
        const auto path = source_archive_job_->project_path;
        source_archive_job_.reset();
        changed = true;
        const auto live_documents = manager_->documents();
        if (std::none_of(live_documents.begin(), live_documents.end(), [&](const auto &entry) {
                return entry.id == document && entry.path && *entry.path == path;
            })) {
            // The worker's result belongs to a closed or replaced project path.
        } else if (!result) {
            if (result.error().code == ErrorCode::canceled) {
                if (message) message(document, "Source archive operation canceled; completed file changes, if any, were retained.");
            } else manager_->report_error(document, result.error());
        } else if (message) {
            std::visit([&](const auto &value) {
                using T = std::decay_t<decltype(value)>;
                if constexpr (std::is_same_v<T, database::SourceArchiveResult>) {
                    message(document, "Archived external source to " + wxString(value.path.wstring()) +
                        wxString::Format(" (%llu bytes; project provenance unchanged).",
                            static_cast<unsigned long long>(value.input.size)));
                } else if constexpr (std::is_same_v<T, database::SourceArchiveRotationResult>) {
                    message(document, "Created rotated source archive " + wxString(value.archive.path.wstring()) +
                        wxString::Format(" (%llu bytes; %zu older generations removed%s).",
                            static_cast<unsigned long long>(value.archive.input.size), value.removed_generations,
                            value.retention_satisfied ? "" : "; retention incomplete, existing files preserved"));
                } else if constexpr (std::is_same_v<T, database::SourceArchiveListing>) {
                    wxString summary = wxString::Format("Validated source archives (%zu listed%s):\n",
                        value.archives.size(), value.complete ? "" : "; scan incomplete");
                    for (const auto &row : value.archives)
                        summary += wxString(row.archive.path.filename().wstring()) +
                            wxString::Format(" (%llu bytes)\n", static_cast<unsigned long long>(row.archive.bytes_verified));
                    if (value.archives.empty()) summary += "No matching validated source archives found.";
                    message(document, std::move(summary));
                } else if constexpr (std::is_same_v<T, database::SourceArchivePruneResult>) {
                    message(document, wxString::Format("Pruned %zu source archives; %zu remain%s.", value.removed,
                        value.remaining, value.retention_satisfied ? "" : " (retention incomplete; files preserved)"));
                } else {
                    message(document, "Verified source archive " + wxString(value.path.wstring()) +
                        wxString::Format(" (%llu bytes; SHA-256 matches embedded input).",
                            static_cast<unsigned long long>(value.bytes_verified)));
                }
            }, result.value());
        }
    }
    for (auto document = receipts_.begin(); document != receipts_.end();) {
        DocumentId id{document->first};
        auto actor = manager_->actor(id);
        if (!actor) {
            document = receipts_.erase(document);
            continue;
        }
        auto &records = document->second;
        for (auto it = records.begin(); it != records.end();) {
            if (it->result.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
                ++it;
                continue;
            }
            if (it->session == actor->view().session) {
                const auto &reply = it->result.get();
                if (!reply)
                    manager_->report_error(id, reply.error());
                else {
                    auto &value = reply.value();
                    if (!value.adopted && value.adoption_error)
                        manager_->report_error(id, *value.adoption_error);
                    if (message && value.saved)
                        message(id, (value.kind == ProjectOperationKind::backup ? wxString("Created project backup: ")
                                                                                : wxString("Saved project: ")) +
                                        wxString(value.saved->path.wstring()) +
                                        (value.kind == ProjectOperationKind::backup || value.adopted
                                             ? wxString{}
                                             : wxString(" (copy saved; current document was not switched)")));
                    if (message && value.exported)
                        message(id, wxString::Format("Exported %llu bytes SHA256=",
                                                     static_cast<unsigned long long>(value.exported->bytes)) +
                                        wxString::FromUTF8(digest_hex(value.exported->sha256)) + ". " +
                                        wxString::FromUTF8(value.exported->caveat));
                }
            }
            it = records.erase(it);
            changed = true;
        }
        if (records.empty())
            document = receipts_.erase(document);
        else
            ++document;
    }
    changed = poll_listing() || changed;
    changed = poll_search() || changed;
    changed = poll_graph() || changed;
    changed = poll_automatic_backups() || changed;
    if (changed)
        changed_();
}
} // namespace hexlab::desktop
