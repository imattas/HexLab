# Desktop project backups

The File menu provides **Create Project Backup...** for a saved project and
**Restore Backup as New Project...** or **Restore Backup In Place...** for an
existing `.hxproj` backup. The File menu also offers **Restore Recovery
Artifact as New Project...** for validated interrupted-save and retained
previous-version artifacts.

Creating a backup runs through the active project's serialized writer. The
writer publishes a validated SQLite online backup atomically, keeps the
project UUID and edit history, and rebases relative input provenance for the
backup directory. Choosing an existing destination asks before replacement;
the database layer refuses destinations that alias the project, its input, or
live/unrecovered SQLite journal data. The active project remains open and
unchanged.

Restoring asks for the backup and a destination. The backup is opened read-only,
validated, and copied through the database Save As path. The result receives a
new project UUID, is opened as a new writable document, and leaves the backup
unchanged. Publication is atomic; a failed validation or copy does not replace
the destination. Restore work runs off the UI thread and only one restore may
run at a time.

In-place restore asks for the backup and existing target, then shows a
destructive-operation confirmation before starting. Both files must have the
same project UUID. Close every open view of the backup and target first; the UI
rejects paths that are open in the current application. Restore runs off the UI
thread, retains the replaced target as a recovery artifact, and reopens the
restored project when it completes.

## Restoring a recovery artifact as a new project

Choose **File > Restore Recovery Artifact as New Project...**, select the
artifact, then choose a destination `.hxproj`. Validation and publication run on
a worker. The application discovers the selected file as a recovery candidate
in its containing directory and performs the full recovery validation again
before publishing. The recovered project gets a fresh UUID, keeps its validated
state and history, and leaves the source artifact intact. Existing destinations
use the normal overwrite prompt.

This accepts only complete HexLab recovery artifacts that pass ordinary
project and retained-history validation. It does not salvage corrupt or partial
SQLite databases or replay an orphan WAL.

An unsaved, untitled document must be saved before it can be backed up. The
restore commands do not rotate or retain older backup generations.

## Rotating backups in the desktop

The File menu also provides **Create Rotated Backup...**, **List Rotated Backups**,
and **Prune Rotated Backups...** for any saved project. These commands use a
sibling base name ending in `-backups` (for example,
`sample-backups.hxproj`); timestamped generations are stored beside the project
and the base file itself is not overwritten. Rotation and pruning ask for a
retention count from 1 through 32, and pruning confirms before it removes older
validated generations.

Backup scanning, validation, copying, and pruning run on a worker thread. The
result is reported in the project message log; listing shows each validated
filename and marks an incomplete bounded scan. The existing restore command
can open any listed generation as a new project.

## Automatic backup schedule

Choose **File > Automatic Project Backups...** to enable scheduled backups for
all saved, writable projects. The schedule is off by default. Its interval
defaults to 15 minutes (allowed range: 5–1440 minutes) and its retention count
defaults to 5 generations (allowed range: 1–32). Preferences are saved in the
desktop configuration and apply to future sessions. Invalid persisted ranges
leave scheduling disabled.

The dialog shows each open project's current state, time until its next
attempt, last backup filename, or latest failure. Status refreshes while the
dialog is open. Completed backups, errors, and incomplete retention warnings
also appear in the project's message log. The status history and countdowns
are session-local; the backup files persist on disk.

Each eligible project waits a full interval after opening, first Save As,
or a settings change. Only one scheduled backup job runs at a time, and due
jobs wait for pending project operations, manual rotation/listing/pruning,
or a restore. Each copy opens its own read-only connection on a worker
thread, checks that the source still has the expected project UUID, and uses
SQLite's consistent online backup. It includes committed edits and history
without changing the open project. Edits committed after the snapshot are
captured by a later attempt. Attempts run periodically even if there are no
new edits; a failed attempt is retried after a full interval rather than in
a tight error loop. The next interval begins when a worker finishes.

Automatic backups share the sibling `-backups` base and validated generation
set with manual rotated backups. The configured count applies to that shared
set. Rotation publishes and validates the new copy before removing older
same-UUID generations. Directory and history validation budgets still apply:
an incomplete scan, cancellation, or deletion failure can leave extra files,
and the dialog/log reports that retention was not fully met. The configured
count is a retention target, not an unconditional disk-space quota.
When rotation reports incomplete retention, that project's schedule pauses
so unattended retries cannot keep adding generations to an unprunable
directory. Review the warning and existing generations, then use **Restart
Schedule** to start fresh countdowns for all eligible projects using the
currently saved settings. Reopening the project or changing the schedule's
settings also clears this session-local pause.

**Cancel Running Automatic Backups** requests cancellation of current
scheduled work. **File > Cancel Background Work** also cancels backup
management for the active project. An attempt canceled before publication
waits another full interval before retrying. A published generation with
incomplete retention follows the pause/review behavior above.
Disabling scheduling or changing its settings
cancels the old scheduled work. Closing a project cancels its backup worker
and removes its schedule; Save As cancels the old path's worker and starts
a new interval for the adopted path. Results for closed or replaced paths
are consumed without being attached to another project. Shutdown requests
cancellation and joins remaining backup workers. Cancellation is cooperative:
a backup already published remains a usable generation, and pruning may
already have removed some validated older generations.

Untitled and read-only projects are not scheduled. Scheduling requires
HexLab to be running; missed intervals coalesce into one due attempt per
project after resume. Projects reopened after restart wait a fresh interval.
External source files are not copied or independently rotated by this
schedule; embedded input and rebased provenance follow the existing project
backup format. Explicit source archives are available through the CLI/library
[archive-source workflow](project-backup.md#explicit-external-source-archives).
Source archival/retention remains outside this automatic desktop schedule.

## External source archives

For a saved project with a recorded external input, the File menu provides
**Archive External Source...**, **Create Rotated Source Archive...**, **List Rotated
Source Archives**, **Prune Rotated Source Archives...**, and **Verify Source
Archive...**. These operations reopen the saved project read-only on a worker and
check its UUID against the open project before acting. Direct archive creation
asks for a new destination and never replaces an existing file. Rotated files
use a sibling `-source-archives` base; retention is limited to 1 through 32.
Pruning requires confirmation and removes only matching archives that pass
embedded-input verification. Listing reports only validated files and marks a
bounded scan incomplete; incomplete retention does not imply the target count
was met.

The database API has cooperative cancellation but no progress callback, so the
desktop reports that work is running and exposes **Cancel Source Archive Work**
and **File > Cancel Background Work**. Cancellation is checked during streaming
and validation. A completed atomic archive remains if cancellation arrives
after publication. Archive copying and validation use the API's 256 MiB default
byte cap (maximum configurable library cap: 1 GiB); the desktop uses the
default. Each operation leaves project bytes and source provenance unchanged.
