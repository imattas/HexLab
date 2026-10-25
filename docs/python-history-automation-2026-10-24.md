# Read-only history automation

The native automation bridge and embedded Python API expose durable history
metadata and exact-step state previews. This supports reviewing what a script
changed, inspecting an undone or intermediate grouped command, comparing type
definitions across steps, and reading old patched bytes without moving the
live project's undo cursor. The implementation uses the existing database
history readers; it does not change the schema or the command model.

## Listing durable commands

```python
import hexlab

with hexlab.Project.open("sample.hxproj") as project:
    first = project.history(count=32)
    print(first.project_uuid, first.source_revisions, first.history_cursor)
    for command in first.entries:
        print(command)
    if first.next is not None:
        second = project.history(after_step=first.next, count=32,
                                 expected_revision=first.source_revisions["edit"])
    for command in project.iter_history(page_size=256):
        print(command["step"], command["group_id"], command["applied"])
```

`Project.history(after_step=0, count=256, expected_revision=None, cancel=None)`
returns a detached `HistoryPage`. The exclusive step cursor starts at zero;
the returned `next` is `None` at the end. Counts must be from 1 through 1024.
Rows are in ascending step order and include:

| Field | Meaning |
| --- | --- |
| `step` | Exact durable command position |
| `group_id` | Existing undo/redo command group; zero is ungrouped |
| `byte_change`, `decision_change` | Stored command effect flags |
| `applied` | Whether this step is at or before the current durable cursor |

Redo entries remain visible. The page identifies the project UUID as 32 lowercase
hexadecimal digits and includes `source_revisions` (`edit`, `bytes`, `decisions`),
`history_cursor`, and `history_count`. No names, authors, timestamps, or changed
entity lists are fabricated because those fields are not stored.

If omitted, `expected_revision` uses the live owner's snapshot edit revision.
Pass the first page's edit revision into later requests to retain one generation.
`iter_history()` does this automatically. A changed durable revision raises
`hexlab.Error` with conflict code 8. Rows already yielded by an iterator remain
valid observations, but a failed iteration does not represent a complete listing.
Reopen the project and restart the listing after an external writer changes it;
history inspection does not refresh or replace the live session snapshot.

## Previewing exact states

```python
with hexlab.Project.open("sample.hxproj") as project:
    original = project.preview_history(0)
    with project.preview_history(3, max_steps=512) as old:
        print(old.snapshot())
        for annotation in old.iter_annotations(page_size=128):
            print(annotation["location"], annotation["name"], annotation["comment"])
        for definition in old.iter_types():
            print(definition["id"], definition["name"], definition["type"])
        print(old.read(hexlab.FileOffset(0), 16))

# The projection retains its input/user-state ownership independently.
print(original.read(hexlab.FileOffset(0), 16))
original.close()
```

`Project.preview_history(target_step, max_steps=256,
max_delta_bytes=16777216, expected_revision=None, cancel=None)` returns an
independent `HistoricalState`. Step zero, redo positions, and positions inside
a command group are supported. This is an exact step preview; ordinary live
`undo()` and `redo()` retain their group-based behavior.

The historical owner exposes the following bounded tables. Each accepts
`start=0, count=256` with counts in 1 through 4096, plus a matching `iter_*`
method accepting `page_size`. Past-end offsets return an empty page. No table
is silently cut off at the live snapshot's annotation/bookmark preview limit.

| Method | Detached record contents |
| --- | --- |
| `annotations()` | Entity ID, typed location, name, comment |
| `bookmarks()` | Entity ID, typed location, label |
| `types()` | Stable ID, name, recursive `TypeSpec`, declaration kind, optional DWARF origin |
| `type_assignments()` | Entity ID, typed location, referenced type ID |
| `patches()` | Canonical file-offset `begin` and changed-byte `size` |
| `regions()` | Decision ID, typed begin, size, `code`/`data` kind |
| `function_decisions()` | Decision ID, entry, suppressed flag, explicit chunk count |
| `function_chunks(decision_id)` | Independently paged explicit begin/size ranges |
| `user_references()` | Entity ID, typed source/target, symbolic reference kind |

`snapshot()` returns identity, source revisions/cursor, exact target step,
durable history count, replayed-step and delta-byte work counters, input size,
and counts for the projected tables. It also discloses the historical debug
variable count, although detailed debug variable records are currently available
only through the native retained metadata. Counts describe the projected state.
The source revisions identify the durable source used for replay; they are
not reconstructed historical revision numbers.

`read(FileOffset(offset), count)` reads effective bytes at the target step, capped
at 1 MiB per call. The projection validates canonical patch original-byte
preconditions against the embedded original and retains an immutable overlay.
Virtual-address reads and historical analysis are deliberately absent: patches
can change loader mappings, and the live mapping is not substituted for an old
one. Historical state has no mutation, adoption, or undo/redo operation. Close
it explicitly or use its context manager to release retained state/input.

## Budgets, cancellation, and consistency

Preview can replay at most 4096 steps and read at most 64 MiB of directional
delta payload; defaults are 256 steps and 16 MiB. Zero budgets are accepted,
for example when previewing the current cursor. A request that exceeds an
accepted replay budget fails with resource-limit code 7 and produces no partial
projection. Source and intermediate user states retain the database's canonical
64 MiB serialized-state and record limits. These limits are not a total process
memory cap: decoded state, replay temporaries, typed values, and the validated
patch overlay can coexist. A page count bounds rows, not the recursive size of
an individual type graph.

Both operations work on read-only projects and check live project thread
ownership. Native operations release the Python GIL while reading/replaying, so
another thread can cancel a `hexlab.CancellationToken`. Pass it as `cancel=`;
the desktop console's cancellation token is used when available and no explicit
token is given. Cancellation raises `hexlab.AnalysisCancelled`. SQL/replay work
checks cancellation cooperatively. Overlay validation is bounded by the
project-state limits and completes its current operation before the next stop
check; it is not forcibly interrupted.

Metadata listing does not validate delta payload integrity. Preview validates
the directional deltas traversed to reach its target and validates the resulting
patch overlay; it is not a complete history audit. Reads use a coherent durable
SQLite snapshot, but do not lock out a writer after that snapshot begins. Once
created, a historical owner is independent of later live edits and does not
query SQLite again. It may outlive the live project.

Native clients include `hexlab/automation/api.hpp`. `Project::history()` returns
`database::HistoryPage`; `Project::preview_history()` returns a retained
`shared_ptr<const HistoricalState>`. Its `metadata()` includes the existing
immutable `database::HistoryPreview`, and table/read methods expose the same
bounded results without CPython.

The runnable example is `libs/automation/examples/inspect_history.py`:

```powershell
hexlab_python inspect_history.py sample.hxproj --count 32 --preview 3 --read-offset 0
```

Implementation and validation are scoped to automation. No tests were added or
run for this change, as requested for the current development session. Build
evidence and platform limitations are recorded in the task handoff.
