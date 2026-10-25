#include "session_controller.hpp"
#include "hexlab/core/sha256.hpp"
#include <algorithm>
#include <chrono>
#include <new>
#include <system_error>
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
} // namespace
SessionController::SessionController(std::function<void()> changed)
    : pool_(std::make_shared<AnalysisPool>()), manager_(take(DocumentManager::create(pool_))),
      changed_(std::move(changed)) {
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
            return database::ProjectStore::discover_recovery_candidates(directory, token);
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
    pending_project_opens_.erase(id.value);
    auto result = manager_->close(id);
    if (!result)
        manager_->report_error(result.error());
    changed_();
}
void SessionController::close_all() {
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
        auto candidates = it->result.get();
        auto failed_path = std::move(it->failed_path);
        const auto mode = it->mode;
        auto failure_detail = std::move(it->open_error);
        it = recovery_scans_.erase(it);
        changed = true;
        if (recovery_candidates_ready)
            recovery_candidates_ready(std::move(failed_path), mode, std::move(failure_detail), std::move(candidates));
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
        backup_restore_.reset();
        if (!restored) {
            manager_->report_error(restored.error());
        } else {
            auto opened = manager_->open_project(restored.value().path, database::ProjectMode::read_write, options);
            if (!opened)
                manager_->report_error(opened.error());
            else if (message)
                message(opened.value(), "Restored backup as a new project: " + wxString(restored.value().path.wstring()));
        }
        changed = true;
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
    if (changed)
        changed_();
}
} // namespace hexlab::desktop
