# Project backups

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

For a rotating set, pass a stable base filename. HexLab creates timestamped
siblings such as `sample.backup-017...-<random-token>.hxproj`; the base file
itself is not overwritten. Listing validates candidates against the open
project UUID. Pruning retains the newest requested count and removes only
siblings for that UUID whose schema, embedded input, patches, and complete
forward/inverse history audit validate. Scans are bounded to 8,192 directory
entries, 64 candidates, 1 GiB of candidate bytes, 65,536 history entries, and
512 MiB of history payload across the scan. An incomplete scan or history audit
performs no pruning and reports incomplete retention.

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
the saved patches against that input. If source provenance points to an
external binary, its relative path is recalculated from the backup directory.

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

The output is built in a uniquely reserved staging database beside the target,
checkpointed, closed, and then atomically published using the selected
`ReplacePolicy`. `fail_if_exists` cannot overwrite a file that appears during
the operation. Replacing an existing project uses the existing publication
guard and retains the old complete file as a `.hexlab-previous-*.tmp` recovery
artifact. Nonempty destination WAL data, orphan journal companions, open
destinations, or a destination that aliases the project or its source binary
are rejected.

Cancellation or validation failure before publication leaves the destination
unchanged and removes the owned staging database and its journal companions.
The backup preserves the UUID intentionally; opening it while the source
project is already open can trigger the existing duplicate-project lease
policy. Restoring to a new path creates a new UUID. Backup workflows do not
copy an external source binary.
