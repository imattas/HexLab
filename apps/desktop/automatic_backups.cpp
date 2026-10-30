#include "session_controller.hpp"
#include <wx/config.h>
#include <algorithm>

namespace hexlab::desktop {
bool SessionController::backup_pending(DocumentId id) const {
    return std::any_of(backup_management_.begin(), backup_management_.end(), [id](const auto &job) {
        return job.document == id;
    });
}

void SessionController::load_automatic_backup_options() {
    auto *config = wxConfigBase::Get();
    if (!config)
        return;
    bool enabled = false;
    long interval = 15, retain = 5;
    config->Read("/ProjectBackups/Enabled", &enabled, false);
    config->Read("/ProjectBackups/IntervalMinutes", &interval, 15);
    config->Read("/ProjectBackups/Retain", &retain, 5);
    // Invalid persisted values never silently enable a destructive retention policy.
    if (interval < 5 || interval > 1440 || retain < 1 || retain > 32)
        return;
    automatic_backup_options_ = {enabled, static_cast<int>(interval), static_cast<std::size_t>(retain)};
}

Result<bool> SessionController::configure_automatic_backups(AutomaticBackupOptions options) {
    if (options.interval_minutes < 5 || options.interval_minutes > 1440 || options.retain < 1 || options.retain > 32)
        return Error{ErrorCode::invalid_argument, "Use a backup interval from 5 through 1440 minutes and retention from 1 through 32"};
    auto *config = wxConfigBase::Get();
    if (!config || !config->Write("/ProjectBackups/IntervalMinutes", static_cast<long>(options.interval_minutes)) ||
        !config->Write("/ProjectBackups/Retain", static_cast<long>(options.retain)) ||
        !config->Write("/ProjectBackups/Enabled", options.enabled) || !config->Flush())
        return Error{ErrorCode::io, "Cannot save automatic project backup preferences"};
    if (options.enabled == automatic_backup_options_.enabled &&
        options.interval_minutes == automatic_backup_options_.interval_minutes &&
        options.retain == automatic_backup_options_.retain)
        return true;
    automatic_backup_options_ = options;
    restart_automatic_backup_schedule();
    return true;
}

void SessionController::restart_automatic_backup_schedule() {
    cancel_automatic_backups();
    ++backup_schedule_generation_;
    automatic_backups_.clear();
    next_backup_poll_ = {};
    (void)poll_automatic_backups();
    changed_();
}

void SessionController::cancel_automatic_backups() {
    const auto due = std::chrono::steady_clock::now() +
                     std::chrono::minutes(automatic_backup_options_.interval_minutes);
    for (auto &job : backup_management_)
        if (job.automatic) {
            job.cancellation->request_stop();
            if (auto found = automatic_backups_.find(job.document.value); found != automatic_backups_.end()) {
                found->second.due = due;
                found->second.status = "Cancellation requested; waiting for the worker to stop.";
            }
        }
}

bool SessionController::poll_automatic_backups() {
    const auto now = std::chrono::steady_clock::now();
    if (now < next_backup_poll_)
        return false;
    next_backup_poll_ = now + std::chrono::seconds(1);
    const auto entries = manager_->documents();
    bool changed = false;
    // Cancel closed/replaced paths without destroying a running future on the UI thread.
    for (auto &job : backup_management_)
        if (job.automatic && std::none_of(entries.begin(), entries.end(), [&](const auto &entry) {
                return entry.id == job.document && entry.path && *entry.path == job.source_path && !entry.readonly;
            }))
            job.cancellation->request_stop();
    for (auto it = automatic_backups_.begin(); it != automatic_backups_.end();) {
        const auto found = std::find_if(entries.begin(), entries.end(), [&](const auto &entry) {
            return entry.id.value == it->first && entry.path && *entry.path == it->second.path && !entry.readonly;
        });
        if (!automatic_backup_options_.enabled || found == entries.end()) {
            it = automatic_backups_.erase(it);
            changed = true;
        } else
            ++it;
    }
    if (!automatic_backup_options_.enabled)
        return changed;
    for (const auto &entry : entries) {
        if (!entry.path || entry.readonly || entry.save_state == DocumentSaveState::opening)
            continue;
        auto [position, inserted] = automatic_backups_.try_emplace(entry.id.value,
            AutomaticBackupState{*entry.path, now + std::chrono::minutes(automatic_backup_options_.interval_minutes),
                                 "Waiting for the first scheduled backup."});
        changed = inserted || changed;
        auto &state = position->second;
        if (state.paused)
            continue;
        if (state.due > now)
            continue;
        // At most one scheduled copy/validation/prune job runs across all tabs.
        // Do not compete with manual backup management or a restore.
        if (!backup_management_.empty() || backup_restore_) {
            const wxString status = "Due; waiting for another backup operation.";
            changed = changed || state.status != status;
            state.status = status;
            continue;
        }
        const auto actor = manager_->actor(entry.id);
        if (!actor || actor->view().pending_operations || entry.save_state == DocumentSaveState::saving) {
            const wxString status = "Due; waiting for pending project operations.";
            changed = changed || state.status != status;
            state.status = status;
            continue;
        }
        const auto started = start_backup_management(entry.id, BackupManagementKind::rotate,
                                                      automatic_backup_options_.retain, true);
        // Failed launch is retried after a full interval, avoiding a 25ms error loop.
        state.due = now + std::chrono::minutes(automatic_backup_options_.interval_minutes);
        state.status = started ? wxString("Automatic backup running.")
            : "Cannot start automatic backup: " + wxString::FromUTF8(started.error().message);
        if (message)
            message(entry.id, state.status);
        changed = true;
    }
    return changed;
}

wxString SessionController::automatic_backup_status() const {
    wxString status = automatic_backup_options_.enabled ? "Automatic project backups are enabled.\n"
                                                       : "Automatic project backups are disabled.\n";
    status += "Only saved, writable projects are scheduled while HexLab is running.\n";
    const auto now = std::chrono::steady_clock::now();
    for (const auto &entry : manager_->documents()) {
        status += "\n" + (entry.path ? wxString(entry.path->filename().wstring()) : wxString("Untitled")) + ": ";
        if (!entry.path) {
            status += "Save this project to enable backups.\n";
            continue;
        }
        if (entry.readonly) {
            status += "Read-only; not scheduled.\n";
            continue;
        }
        const auto running = std::find_if(backup_management_.begin(), backup_management_.end(), [&](const auto &job) {
            return job.automatic && job.document == entry.id;
        });
        if (running != backup_management_.end()) {
            status += running->cancellation->stop_requested() ? "Cancellation requested.\n" : "Backup running.\n";
            continue;
        }
        const auto found = automatic_backups_.find(entry.id.value);
        if (found == automatic_backups_.end()) {
            status += automatic_backup_options_.enabled ? "Waiting for project readiness.\n" : "Disabled.\n";
            continue;
        }
        status += found->second.status + "\n";
        if (found->second.paused)
            continue;
        const auto seconds = std::max<std::int64_t>(0,
            std::chrono::duration_cast<std::chrono::seconds>(found->second.due - now).count());
        status += seconds ? wxString::Format("Next attempt in %lld min %lld sec.\n",
                                             static_cast<long long>(seconds / 60), static_cast<long long>(seconds % 60))
                          : wxString("Next attempt is due.\n");
    }
    return status;
}
} // namespace hexlab::desktop
