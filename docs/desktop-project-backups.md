# Desktop project backups

The File menu provides **Create Project Backup...** for a saved project and
**Restore Backup as New Project...** for an existing `.hxproj` backup.

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

An unsaved, untitled document must be saved before it can be backed up. The
restore command does not rotate or retain older backup generations, and it
does not restore in place.

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
