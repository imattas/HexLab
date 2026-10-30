# Project backups

The desktop also offers an opt-in recurring backup schedule with persistent
interval/retention preferences, live status, and cancellation. See
[Desktop project backups](desktop-project-backups.md#automatic-backup-schedule).

`ProjectStore::backup_to(destination, policy, stop)` writes a consistent copy
of an open project without changing the source store. The backup retains the
project UUID, revisions, embedded input, user rows, history and derived-cache
records. `save_as()` remains the operation for creating an independent project
with a new UUID.

The CLI exposes the same operation without opening the desktop:

```text
hexlab_cli project backup sample.hxproj --output backups/sample.hxproj
```

Use `--replace` to atomically replace an existing backup after validation.

To recover a backup into a separate working project, use:

```text
hexlab_cli project backup restore backups/sample.hxproj --output work/sample-restored.hxproj
```

Restore opens and validates the backup, then publishes an independent copy with
a new UUID. The backup remains unchanged. This lets the restored project and
the original project be open at the same time without triggering the duplicate
project lease policy. `--replace` selects atomic replacement if the output
already exists; it does not modify the backup.

Recovery of a discovered interrupted-save or previous-version artifact verifies
the staged copy's complete forward/inverse history audit before publishing it.
In-place restore applies the same check to its staged copy. These recovery
paths stop without publication if history is corrupt or exceeds the verifier's
65,536-entry/512 MiB budget; they do not attempt to reconstruct arbitrary
damaged databases.

For a rotating set, pass a stable base filename. HexLab creates timestamped
siblings such as `sample.backup-017...-<random-token>.hxproj`; the base file
itself is not overwritten. Listing validates candidates against the open
project UUID. Pruning retains the newest requested count and removes only
siblings for that UUID whose schema, embedded input, patches, and complete
forward/inverse history audit validate. Scans are bounded to 8,192 directory
entries, 64 candidates, 1 GiB of candidate bytes, 65,536 history entries, and
512 MiB of history payload across the scan. An incomplete scan or history audit
performs no pruning and reports incomplete retention.

Each listed generation also carries the exact file size and SHA-256 captured
around its full validation. Before either `prune` or `rotate` removes a listed
generation, it checks that the path is still a regular file with that same
size and digest. If the file changed or cannot be rechecked, it is kept and
retention is reported incomplete. This catches replacements made between the
listing and deletion passes. Deletion is still a filesystem path operation, so
an unrelated process racing the final check and unlink is outside this
protection.

```text
hexlab_cli project backup rotate sample.hxproj --base backups/sample.hxproj --retain 8
hexlab_cli project backup list sample.hxproj --base backups/sample.hxproj --json
hexlab_cli project backup prune sample.hxproj --base backups/sample.hxproj --retain 8
```

Rotation publishes the new backup, fully validates the bounded candidate set,
then prunes older entries. This keeps the just-created generation even when
its timestamp ties an existing generation. If candidate validation, directory
scanning, or deletion is incomplete, extra backups may remain and the command
returns exit code 3. Listing returns exit 3 when the bounded scan or history
audit is incomplete.

Restore into an existing project in place with:

```text
hexlab_cli project backup restore-in-place backups/sample.backup-...hxproj --target sample.hxproj
```

The backup and target must share the same project UUID. The restore acquires the
project lease, checks the target revisions again after acquiring it, validates
the staged SQLite copy and atomically publishes it at the existing path. The
target UUID and backup history are preserved; reopen the project afterward.
Close all project connections first, including read-only/collaborative peers.
The prior target is retained as a `.hexlab-previous-*.tmp` recovery artifact.

The implementation uses SQLite's online backup API, so committed WAL content
is included in one coherent snapshot. Before publication, it validates the
copied schema and state, reads and hashes all embedded input chunks, and checks
the saved patches against that input. It also audits the staged copy's complete
forward/inverse history within the verifier limits of 65,536 entries and 512
MiB; corrupt or over-budget history prevents publication. If source provenance
points to an external binary, its relative path is recalculated from the backup
directory.

Applications can also validate an existing backup with
`ProjectStore::verify_backup(path, max_history_steps, max_history_delta_bytes,
stop)`. Opening the backup read-only checks its schema, embedded input chunks,
and patch ranges. The verifier then audits bounded pages of forward/inverse
history deltas and their change metadata. Its result reports the number of
history entries and delta bytes checked; `history_complete` is false when the
caller-supplied budget ends before the retained history does. Budgets are
limited to 65,536 entries and 512 MiB of history payload per call, and the
operation supports cancellation. This is useful for an explicit pre-restore
integrity check without changing the backup.

The CLI exposes that check without opening or modifying a project:

```text
hexlab_cli project backup verify backup.hxproj
hexlab_cli project backup verify backup.hxproj --max-history-steps 2048 --max-history-bytes 67108864 --json
```

By default, verification allows up to 65,536 history steps and 512 MiB of
history delta data. A successful complete check exits 0. If the requested
budget ends while retained history remains, the command reports the verified
counts, emits `history_complete: false` in JSON, and exits 3 so automation can
distinguish a bounded partial audit from a complete verification. Structural,
input, patch, or history validation errors fail the command. The operation is
read-only; it does not repair, checkpoint, or rewrite the backup.

When a project backup and its separately archived original input are being
transferred together, `verify-bundle` checks both artifacts in one command.
It audits the backup history, opens the backup read-only, and hashes the
external archive against the original input bytes embedded in that backup. It
also confirms the project UUID and embedded input identity are unchanged
between the history audit and the source check:

```text
hexlab_cli project backup verify-bundle backup.hxproj --archive sample-original.bin --json
```

`--max-history-steps`, `--max-history-bytes`, and `--max-source-bytes` use the
same bounds as the standalone verification commands. JSON reports the project
UUID, history completeness and counts, plus the verified archive path, byte
count, and SHA-256. A budget-limited history audit returns exit code 3;
invalid artifacts or a backup whose identity/input changed between audit and
source check fail the command. This is a verification convenience for separate
artifacts; the directory bundle API below coordinates publication when one
portable restore point is required.

The output is built in a uniquely reserved staging database beside the target,
checkpointed, closed, and then atomically published using the selected
`ReplacePolicy`. `fail_if_exists` cannot overwrite a file that appears during
the operation. Replacing an existing project uses the existing publication
guard and retains the old complete file as a `.hexlab-previous-*.tmp` recovery
artifact. Nonempty destination WAL data, orphan journal companions, open
destinations, or a destination that aliases the project or its source binary
are rejected.

Library callers can opt into an external-source consistency policy with the
four-argument overload:

```cpp
ProjectBackupOptions options;
options.external_source = ExternalSourcePolicy::require_matching_input;
auto backup = store.backup_to(path, ReplacePolicy::fail_if_exists, stop, options);
```

`require_matching_input` resolves the source path recorded by the project,
then checks its size and SHA-256 against the input embedded in the SQLite
snapshot before publishing the backup. A missing path, read failure, size
mismatch, or digest mismatch aborts publication; the default
`preserve_provenance` mode retains the existing behavior. This policy verifies
the referenced file but does not copy it. The source can still be
modified by another process during or after verification, so the check is a
consistency guard rather than a filesystem snapshot or lock.

Cancellation or validation failure before publication leaves the destination
unchanged and removes the owned staging database and its journal companions.
The backup preserves the UUID intentionally; opening it while the source
project is already open can trigger the existing duplicate-project lease
policy. Restoring a standalone backup to a new path creates a new UUID. The
standalone SQLite backup operation does not copy an external source binary;
`backup_bundle_to` is the coordinated directory workflow described above.

## Project/source directory bundles

Applications that need one portable restore point can call
`ProjectStore::backup_bundle_to(directory, source_options, stop)`. It creates a
new directory containing `project.hxproj` and `source.bin`, verifies that the
source bytes match the original input embedded in the project snapshot, and
rewrites the bundled project's relative source provenance to `source.bin`.
Publication renames the completed staging directory into place; the destination
must not already exist and its parent directory must already exist. Projects
without a readable external source matching the embedded input cannot be
bundled. Source copying uses the same 1 GiB maximum and configurable default
256 MiB budget as standalone source archives.

`ProjectStore::restore_bundle_to(bundle_directory, destination_directory,
max_source_bytes, stop)` copies both members into a staging directory, verifies
the project's complete bounded history and the source file's size and SHA-256,
then publishes the pair together. The restored
project retains the backup UUID and history, and its relative source path points
to the restored `source.bin`. The destination must be a new directory under an
existing parent. Restore bounds the SQLite project member to 8 GiB and the
source member to 1 GiB. This bundles file bytes only; permissions, alternate
streams, symbol sidecars, and other neighboring files are not included.

```cpp
auto bundle = store.backup_bundle_to("backups/sample.hxbundle", source_options, stop);
auto restored = ProjectStore::restore_bundle_to(
    bundle.value().path, "restored/sample", source_options.max_bytes, stop);
```

The CLI publishes and restores these directory bundles with:

```text
hexlab_cli project backup create-bundle sample.hxproj --output backups/sample.hxbundle --json
hexlab_cli project backup restore-bundle backups/sample.hxbundle --output restored/sample --max-source-bytes 536870912 --json
```

Both commands require a new output directory under an existing parent, reject
`--replace`, and accept the same source byte budget as `archive-source`. JSON
reports the published directory, project path and UUID, source path, byte count,
and SHA-256. Bundle restore preserves the original project UUID; close the
original project before opening the restored project. Separate-project restore
with `backup restore` remains available when a new UUID is required.

Creation archives the external source selected by the saved database snapshot,
so a later provenance update in the open project cannot select a different
source. Restore copies only the two fixed member names into an unpublished
directory, validates the staged database and source together, and normalizes
the staged provenance to `source.bin`. It does not open or rewrite the input
bundle. A source project with any WAL, SHM, or rollback-journal companion is
rejected: close and checkpoint it before retrying. This avoids restoring a main
database file while silently losing committed WAL contents. Copying uses a
1 MiB buffer, checks cancellation between chunks, and rejects short reads or
member size changes. The complete history audit remains limited to 65,536
entries and 512 MiB of delta payload.

Before publication, the staged database is checkpointed and changed to SQLite
DELETE journal mode. The finished pair has no journal companions and can be
verified from read-only media; opening it for editing enables WAL as usual.

Publication uses a native atomic directory rename that refuses replacement,
including a destination created concurrently. Platforms without that primitive
fail without publishing. The workflow verifies the copied bytes but does not
lock the original bundle against concurrent modification or promise power-loss
durability for every filesystem. Failed validation or cancellation removes the
owned unpublished directory. Recurring bundle scheduling remains unsupported.

## Explicit external source archives

`project backup archive-source` makes an independent, verified copy of the
external source referenced by a project:

```text
hexlab_cli project backup archive-source sample.hxproj --output archives/sample-original.bin
hexlab_cli project backup archive-source sample.hxproj --output archives/sample-original.bin --max-source-bytes 536870912 --json
```

The destination directory must already exist, and the destination must be new.
There is no `--replace` option. Existing files, aliases of the source/project or
their protected paths, and database journal companions are rejected. Choose a
different destination for another archive. This command opens the project
read-only and does not modify the source, project UUID, history, or provenance.
JSON output reports the archive/source paths, project UUID, copied byte count,
and SHA-256; success is reported only after atomic publication.

The library exposes the same operation:

```cpp
SourceArchiveOptions options; // 256 MiB by default
options.max_bytes = 512ull * 1024 * 1024;
auto archive = store.archive_external_source(path, options, stop);
```

The archive uses the provenance and original-input identity from one coherent
SQLite read transaction, rejects an unexpected project UUID/input identity,
and resolves relative provenance from the current project directory. A regular
external file must exist and match the embedded original input's size and
SHA-256. Missing, edited, or unreadable sources fail; the operation does not
silently substitute embedded or effective patched bytes. A project with patches
therefore archives its original source only when that external file still
matches the original input. An absent provenance path also fails.

`--max-source-bytes`/`SourceArchiveOptions::max_bytes` accepts 1 byte through
1 GiB, with a 256 MiB default. The original input size is checked against the
budget before source copying or output staging. Empty inputs are supported.
Copying uses at most a 1 MiB owned data buffer, checks cancellation between
chunks, and hashes exactly the same chunks written to the unpublished file.
It also rechecks the source path's size after reading. Short reads, a size or
digest mismatch, cancellation before publication, and output errors leave the
destination unpublished and discard the owned staging file. Publication uses
the existing same-directory flush/rename safeguards and rejects a destination
that appears during the copy.

This is an archive of matching bytes, not a filesystem snapshot: on systems
that permit concurrent writes the source may change during or after copying.
The completed archive's bytes still match the recorded original input identity;
the check does not promise that the external source remains unchanged. File
metadata, permissions, alternate data streams, sidecar symbols, and directory
trees are not archived. Standalone SQLite backups and source archives remain
separate publications. Use `create-bundle` when both files must be published
as one directory.

#### Rotating external source archives

The CLI and database API can create timestamped siblings and retain a bounded
number of generations. CLI workflows are:

```text
hexlab_cli project backup rotate-source sample.hxproj --base archives/sample-original.bin --retain 8
hexlab_cli project backup list-source sample.hxproj --base archives/sample-original.bin --json
hexlab_cli project backup prune-source sample.hxproj --base archives/sample-original.bin --retain 8 --json
hexlab_cli project backup verify-source sample.hxproj --archive archives/sample-original.source-archive-...bin --json
```

`rotate-source` creates a new archive and attempts retention. `list-source`
fully verifies each listed generation. `prune-source` deletes old generations
only when the bounded scan and all candidate validations complete. All commands
accept `--max-source-bytes` from 1 byte to 1 GiB; the default is 256 MiB.
`rotate-source` and `prune-source` accept `--retain` from 1 to 32, default 5.
They print text by default and support `--json`. Incomplete bounded scans retain
all candidates and return exit code 3; successful verification or retention
returns 0.

The corresponding database API is:

```cpp
auto result = store.archive_external_source_rotating(
    "archives/sample-original.bin", 8, options, stop);
auto listing = store.list_rotated_source_archives(
    "archives/sample-original.bin", options.max_bytes, stop);
auto pruned = store.prune_rotated_source_archives(
    "archives/sample-original.bin", 8, options.max_bytes, stop);
```

Each generated file has the form
`sample-original.source-archive-<13-digit-Unix-ms>-<random-token>.bin`.
Rotation publishes a newly verified archive, then lists candidates and checks
each against the project's embedded input size and SHA-256. It prunes only
after a complete scan and successful validation of every candidate; incomplete
scans, corrupt candidates, cancellation, or a changed candidate leave files in
place and report that retention was not satisfied. Listing and pruning inspect
at most 8,192 directory entries and 64 candidate files, and hash at most 1 GiB
cumulatively per operation. A requested per-file budget must be 1 byte through
1 GiB. Retention is limited to 1 through 32 generations. A new generation's
timestamp advances past previously validated generations if the wall clock
ties or moves backward.

The CLI and database API do not provide desktop controls for source archives.
Project-database rotation and source-archive rotation remain independent.
OS-level scheduling while HexLab is closed remains unsupported.

### Verify an archived source copy

After transferring a source archive, verify it against the original input bytes
embedded in the project without resolving or reading the original provenance
path:

```text
hexlab_cli project backup verify-source sample.hxproj --archive archives/sample-original.bin --json
```

The command opens the project read-only, checks the archive is a regular file,
then streams it in 1 MiB chunks under the configured byte cap and compares both
its size and SHA-256 with the embedded input identity. It does not alter project
state or provenance. A mismatch, short read, cancellation, or size change fails
verification. JSON success contains the project UUID, archive path, byte count,
and digest. The API is `ProjectStore::verify_source_archive()`.

To restore the verified bytes as a new external file without opening the
original provenance path, use:

```text
hexlab_cli project backup restore-source sample.hxproj --archive archives/sample-original.bin --output restored/sample-original.bin --json
```

The project must still record the same embedded input identity. Restore streams
the archive through an unpublished same-directory staging file, checks its
size and SHA-256 against the project while copying, and publishes only after
the checks succeed. The destination must be new; project/database/source
aliases are rejected, and the archive remains untouched. The operation does
not update project provenance or patch state. Its byte budget and cancellation
behavior match `verify-source`; the API is
`ProjectStore::restore_source_archive()`.

## Rejected recovery-candidate diagnostics

The database API `ProjectStore::inspect_recovery_directory()` returns the same fully validated candidates used by normal recovery discovery plus a bounded diagnostic summary for files whose names match HexLab staging-artifact patterns but fail validation. It reports visited and matching entry counts, rejection totals, up to 64 filename/reason examples, and the number of omitted examples. The scan remains read-only, examines at most 8,192 directory entries, and accepts at most 256 candidates. If either cap is reached, the report marks `complete=false` and provides the validated candidate prefix plus the count of matching names omitted after the candidate cap. `discover_recovery_candidates()` remains available and returns only validated candidates, but reports a resource-limit error for an incomplete scan.
