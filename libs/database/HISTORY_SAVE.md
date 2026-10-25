# Saving a historical project

`ProjectStore::save_history_as(expected_edit, target_step, limits, destination,
policy, stop)` saves a usable independent project at an exact durable history
step. Use it to recover an earlier annotation, type, analysis decision, or patch
state without moving the source project's cursor or discarding subsequent work.
The resulting file can be opened normally alongside the source project.

```cpp
auto source = ProjectStore::open(source_path, ProjectMode::read_only, stop);
if (!source) return source.error();
auto current = source.value()->snapshot();
if (!current) return current.error();
auto recovered = source.value()->save_history_as(
    current.value()->revisions.edit,
    target_step,
    HistoryPreviewLimits{},
    recovered_path,
    ReplacePolicy::fail_if_exists,
    stop);
```

The target can be zero, a step on the redo branch, or a step inside a command
group. The copied project retains the complete command log, including commands
after the requested step, and its history cursor points at exactly the requested
step. Ordinary undo/redo retains the existing command grouping behavior. A new
edit in the copied project truncates its redo branch in the usual way; the
source history remains intact.

Every copy receives a fresh project UUID. Embedded original input, recipe,
provenance, entity IDs, and the allocation cursor are preserved. Entity IDs
allocated after the requested historical step remain reserved: recovery never
reuses a previous ID. The copy's edit revision advances once if its cursor moves.
Byte and analysis-decision revisions advance when the resulting patches or
decisions differ from the copied source state, just as for ordinary undo/redo.
These revisions are monotonic source identities, not reconstructed historical
revision numbers. Saving the current cursor changes only the UUID and rebased
provenance. Cached analysis remains governed by the usual revision keys.

Breakpoint hit counts are runtime metadata, not historical user commands. The
same replay rules as exact-step preview apply; saving an older step does not
reconstruct historical hit counts. Collaboration conflict records are copied
as by ordinary Save As; they describe the copied source history, not a newly
performed collaboration merge.

## Consistency and limits

The operation first creates a coherent SQLite online backup in a private staging
file. Both the `expected_edit` check and replay operate on that copied snapshot.
A concurrent source writer can continue after the backup snapshot is complete;
the published copy still represents the revision that was checked. If the
copied revision differs from `expected_edit`, the operation reports `conflict`
and publishes nothing. This works for read-only, read-write, and collaborative
sources without refreshing the source store's in-memory snapshot.

Replay shares the exact-step preview decoder and application implementation.
Expected-before values, patch preconditions, stable IDs, cross-entity references,
canonical ordering, and intermediate serialized user-state sizes are validated.
Only the interval between the copied cursor and requested step is replayed.
Unused history payloads are retained rather than independently audited; callers
that need a complete payload audit should run `audit_history` first.

`HistoryPreviewLimits` defaults to 256 steps and 16 MiB of aggregate directional
delta payload. Hard ceilings are 4096 steps and 64 MiB. Limits above the ceilings
return `invalid_argument`; a replay that exceeds an accepted budget returns
`resource_limit`. Saving the current cursor needs no replay steps or delta bytes,
so `{0, 0}` is sufficient. These budgets govern replay, not the size of embedded
input or the SQLite backup. Source and intermediate user states retain their
existing canonical codec limits.

The copied source schema is validated before changes. Historical copies of
supported older read-only projects migrate only the staging copy to the current
schema. After replay the complete copied state and schema are validated, all
embedded input is read and hashed, and the resulting patches are checked against
the embedded original bytes. Relative provenance is rebased to the output
directory; no external source binary is copied or modified.

## Publication and recovery

The final file uses the same publication path as Save As. It is checkpointed
and closed before publication. `fail_if_exists` cannot overwrite a destination
that appears during the operation. `replace_existing` requires a replaceable
destination and retains the previous complete file as a recovery artifact.
The retained file uses the `.hexlab-previous-*.tmp` recovery naming convention
on Windows and POSIX. POSIX replacement requires hard-link support in the output
directory; if the old file cannot be retained, publication fails before replacing
the destination. Recovery artifacts remain until the caller removes them.
On POSIX, staging data is explicitly flushed before publication. Replacement
also flushes the retained old inode before synchronizing its recovery link's
directory, then replaces the destination and synchronizes the directory again.
The destination, staging file and retained link must be regular files with
matching device/inode identities; symlink destinations are rejected. Inode
identities and journal companions are rechecked before the final namespace
operation. An empty regular WAL is the only permitted existing replacement
companion; orphaned WAL, SHM and rollback-journal entries block a new destination,
including dangling companion symlinks.

Once replacement is attempted, an error retains the old recovery inode and any
remaining staging file because filesystem I/O errors can leave the final name's
outcome uncertain. A post-publication directory-sync error reports that the file
was published with durability unconfirmed; it does not blindly rename the old
inode back over the destination. When a new destination was linked successfully,
failure to unlink the staging name still reaches directory synchronization and
reports the cleanup error afterward. Inspect the destination and recovery
candidates after these errors before retrying. POSIX locks are advisory and
identity rechecks are not an atomic compare-and-replace operation; concurrent
noncooperating namespace changes or directory moves remain outside this
publication contract.
These POSIX durability changes have source-review evidence only; no builds or
tests were run. A POSIX build and filesystem fault-injection checks remain
required to verify the publication and recovery paths at runtime.
Source project files and journal companions, extracted input, and original
provenance paths are protected against aliasing. Protection includes paths read
from the actual copied snapshot when a collaborative source connection has a
stale in-memory snapshot.

Cancellation, stale revisions, invalid target steps, replay corruption, exhausted
budgets, validation failure, and I/O failure before the final publication attempt
leave the source and existing destination unchanged. Owned staging files are cleaned up on ordinary
failure. A process interruption can leave a fully formed staging file that the
existing recovery-candidate scanner can validate and recover. The operation does
not adopt the output as the caller's open project; open the returned `SavedProject`
path to continue working in it.

The CLI exposes this operation as `project history save <source> --step N
--output <destination>`. Its optional `--expected-edit` can pin a previous
preview's source revision. See [the CLI workflow](../../docs/project-history-save-cli.md).

No schema version or history codec change is introduced by this API. Other
history workflows can call it after obtaining an exact-step preview; pass the
preview's `source_revisions.edit` to keep publication pinned to the state the
user inspected.
