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

The implementation uses SQLite's online backup API, so committed WAL content
is included in one coherent snapshot. Before publication, it validates the
copied schema and state, reads and hashes all embedded input chunks, and checks
the saved patches against that input. If source provenance points to an
external binary, its relative path is recalculated from the backup directory.

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
policy. Restoring to a new path creates a new UUID. This workflow does not
rotate backups, restore a file in place, or copy an external source binary.
