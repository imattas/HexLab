# Read-only project history

Exact historical states can also be published as independent editable projects
with `ProjectStore::save_history_as`. The source remains unchanged, the copied
project retains its complete undo/redo history, and the requested step can be
inside a group or on the redo branch. See [Saving a historical project](HISTORY_SAVE.md)
for consistency, replay limits, revision semantics, and publication guarantees.

## Save As and backup destination safety

Publication refuses to replace or create a project at a path with an adjacent
SQLite rollback journal (`-journal`). The journal can contain the only recoverable
copy of a destination database, so treating it as harmless scratch could discard
committed or in-flight edits. The check applies on Windows and POSIX, both before
staging and at final publication; WAL and shared-memory companions keep their
existing recovery checks. Resolve the destination database through SQLite first,
or choose a clean destination path.

## Creation and publication durability

New projects are initialized in a uniquely reserved `.hexlab-save-*.tmp` file
beside the requested destination. Schema creation commits and checkpoints that
staging database before the file is published. The final path is therefore
either absent or names a complete initialized project after an interruption;
an interrupted staging file is discoverable by the existing recovery-candidate
scanner and can be discarded if it is incomplete. Publication uses an
atomic no-replace operation for `fail_if_exists`, so a competing creator cannot
be overwritten between an existence check and the final publish. The project
connection is reopened against the published path before `create` returns.

The destination directory must already exist and be writable. A crash after
publication but before the caller receives the returned handle leaves a valid
project at the requested path. Recovery discovery remains bounded and only
returns candidates that pass existing schema and embedded-input validation;
it does not automatically promote staging files.

`ProjectStore::history_page(expected_edit, after_step, limit, stop)` returns
durable command metadata in ascending step order. Start with `after_step = 0`,
then pass the returned `next_after_step` while `has_more` is true. Steps are
exclusive page cursors; a cursor equal to `history_count` returns an empty page.
The page includes the project UUID, source revisions, durable cursor/count, and
each step's group ID, byte-change flag, decision-change flag, and applied status.
Redo steps remain visible with `applied = false`. Group zero means an ungrouped
command; adjacent nonzero equal IDs retain their existing undo/redo grouping.

Pages require a limit of 1 through 1024. They read only the project header,
the highest history key through the primary-key index, and the requested rows;
they never read user-state rows or delta blobs. This keeps a page lookup
proportional to the page size instead of rescanning the entire history table.
Returned rows are checked for valid flags, decodable fixed-width fields, and
step continuity from the exclusive cursor. Sequential paging detects a gap
when it reaches that gap. A caller that starts after an earlier corrupt gap
does not audit the skipped prefix; use exact-step preview or reopen validation
when a full history audit is needed. History remains capped at 100,000 rows.
Metadata listing does not validate payload integrity. Command names,
timestamps, authors, and changed entity lists are not stored and are not
fabricated.

`ProjectStore::preview_history_at(expected_edit, target_step, limits, stop)`
projects immutable `UserState` at exactly the requested durable step. Step zero
is supported, as are redo positions and positions inside a command group. The
projection traverses forward or inverse deltas from the current durable cursor;
it does not replay from an assumed empty state. The existing undo/redo projection
API retains its group-based behavior and mutation-oriented revision semantics.

The result identifies the UUID, source revisions, source cursor, target step,
durable count, replayed steps, and serialized delta bytes read. Source revisions
describe the durable snapshot used for projection; they are not historical
revision numbers. No historical entity allocation cursor, derived analysis,
patched image, or reconstructed `ProjectState` is returned.

Preview defaults to 256 replay steps and 16 MiB of aggregate directional delta
payload. Callers may lower these limits, including zero, or raise them to hard
ceilings of 4096 steps and 64 MiB. Oversized requested limits are
`invalid_argument`; exceeding an accepted replay budget is `resource_limit`.
Budgets do not produce partial previews. Each delta retains the existing 64 MiB
codec and 1 MiB chunk limits; chunks are checked against the remaining aggregate
budget before copying from SQLite. The source and each intermediate projected
state must encode within the canonical 64 MiB user-state payload budget, with
the existing record and field limits. These are serialized-size and work limits,
not a total process-memory cap. Decoded state, delta objects, state copies, and
temporary encodings can coexist in memory.

Replay uses the same typed delta decoder and application path as durable
undo/redo: expected-before values, stable entity IDs, patch preconditions,
canonical sorting, cross-entity references, and user-state validation are
preserved. Patch extents must fit the embedded input. Preview does not read or
materialize embedded input, reverify original patch bytes, or independently audit
the unused opposite-direction payloads. A malformed traversed delta or failed
precondition fails the whole request.

`ProjectStore::audit_history(expected_edit, after_step, limits, stop)` checks
both encoded directions for a bounded page of history entries. It verifies
step continuity, metadata flag values, and group IDs; it checks payload chunk
ordinals and sizes, decodes each forward and inverse delta, and confirms that
the inverse is the canonical inverse of the forward delta. It also confirms
that each row's byte-change and decision-change flags agree with the actual
patch and analysis-decision changes in its forward delta. A mismatch reports
an integrity error instead of returning misleading history metadata. Continue with `next_after_step` while
`has_more` is true, retaining the same `expected_edit`; a revision conflict
means the audit must restart against a fresh snapshot. The result reports the
project identity, source revisions, history cursor/count, number of entries
verified, and aggregate delta bytes read.

Audit pages accept up to 4096 entries and 128 MiB of combined forward and
inverse payload data. The defaults are 256 entries and 16 MiB. If a page would
exceed its payload budget, it fails without returning a partial page; callers
can retry from the same cursor with a larger accepted budget. An empty page is
valid when `max_steps` is zero. Auditing checks the stored payload structure
and inverse pairing, but does not replay all commands against the current user
state or prove that the current state equals the history cursor. Use exact-step
preview to validate replay preconditions for a bounded interval.

Both operations work in read-only, read-write, and collaborative mode. They use
a deferred SQLite read transaction and pin all reads to one durable snapshot.
`expected_edit` must match that snapshot; otherwise the result is `conflict`.
Keep the same edit revision across pages and refresh/restart listing on conflict.
A concurrent writer may commit after the snapshot begins; the returned source
revision still identifies the coherent snapshot that was read. Neither operation
updates the in-memory store snapshot, revisions, history cursor, rows, caches, or
schema. Transaction cleanup also runs after cancellation and failures. Stop
tokens are observed by SQL reads and between replay steps; a single bounded
codec/application operation can finish before cancellation is observed.

The CLI history audit can optionally request `--verify-replay`. After every
history page has been audited from step zero through the end, it asks the
read-only preview path to reverse the applied branch from the durable cursor
to step zero and requires the projected user state to be empty. This checks
that the active history branch's preconditions line up with the stored current
user state. The verification is capped at 4,096 applied steps and 64 MiB of
delta payload; it is not run for a partial paginated audit. Redo-only branch
entries remain covered by the ordinary forward/inverse structure audit, but
are not replayed. The operation performs no writes or schema changes.

No schema or persisted codec version changes are required. Existing read-only
legacy project schemas remain readable through the existing version-aware state
loader. Debug MSVC source compilation passed with the existing
`agent-db-build/libs/database/hexlab_database.vcxproj` `ClCompile` target. No
library linking or tests were performed, and no tests were added.
