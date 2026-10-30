# Whole-history semantic verification

`ProjectStore::verify_history_replay(expected_edit, limits, stop)` verifies the
meaning of the complete retained undo/redo log against the current durable user
state. It complements `audit_history`, which checks bounded pages of encoded
payloads without applying them.

```cpp
auto snapshot = store->snapshot();
if (!snapshot) return snapshot.error();
hexlab::database::HistoryReplayLimits limits;
auto verification = store->verify_history_replay(
    snapshot.value()->revisions.edit, limits, stop);
if (!verification) return verification.error();
// Success verifies both the applied commands and the retained redo branch.
const auto& report = verification.value();
```

The verifier opens one deferred read transaction. The requested edit revision
must match its coherent SQLite snapshot, and the UUID and embedded input
identity must still match the open store. Concurrent commits after that snapshot
begins do not change the verification result. Returned source revisions describe
the verified snapshot; they are not historical revision numbers.

Verification performs these checks in order:

1. Validate the history header, sequence extent, typed metadata and orphan
   payload keys, then load the bounded current user state.
2. Re-extract and SHA-256 verify the embedded original input within the same
   read transaction, using a locally owned temporary backing. No external
   provenance path is opened.
3. Apply inverse commands from the current cursor to step zero, requiring an
   empty undoable user state at the root.
4. Apply forward commands from zero through the complete retained history,
   including every redo command. At the durable cursor, require the replayed
   user state to equal the stored current state.

Every traversed step decodes both payload directions, validates chunk ordinals,
sizes and SQL storage types, and requires the inverse to equal the canonical
inverse of the forward delta. Replay shares the durable undo/redo application
path, including expected-before values, stable IDs, sorting, entity references,
field bounds and collection validation. A replay precondition mismatch is an
integrity error; a stale requested edit revision is a conflict.
Forward creations must use increasing stable IDs below the durable allocation
cursor; gaps left by discarded redo branches are allowed, but reuse is rejected.

Byte-change and decision-change flags are checked against the actual before and
after replayed collections. Each projected state must fit the canonical 64 MiB
user-state budget. Every projected patch must stay within the verified original
input and contain exactly matching original bytes. This detects a structurally
valid historical patch with an invented original payload, even on the redo
branch.

Success returns UUID, source revisions, input identity, durable cursor/count,
rewound and forward step counts, combined directional delta bytes read,
embedded input bytes verified, cumulative validation bytes and historical patch
bytes verified. Every success covers the entire retained history. A budget
failure, cancellation or integrity error returns no partial proof and does not
change the store's in-memory snapshot or input backing.

## Work limits

| Budget | Default | Maximum |
| --- | --- | --- |
| Applied rewind plus full forward transitions | 4,096 | 200,000 |
| Combined forward/inverse delta bytes read | 64 MiB | 512 MiB |
| Embedded original input | 256 MiB | 1 GiB |
| Cumulative serialized state and original-patch validation bytes | 256 MiB | 4 GiB |

For a cursor of 12 and a retained count of 20, verification needs 32 transitions.
Applied entries' two payloads are read once during rewind and again during the
forward pass. Both reads count toward the aggregate delta budget. State
validation counts the current state and every intermediate state, plus every
original-patch byte compared in that pass. The input extraction also uses the
existing current-patch validation path. Zero budgets are accepted; work that
requires those budgets fails with `resource_limit`. Limits above the hard
maximum fail with `invalid_argument`.

These are serialized-data and work limits, not a process-memory cap. A bounded
state encoding, decoded payload pair, projected user state, original state and
invalidation-comparison collections can coexist in memory. One state encoding
can finish before its cumulative size is charged. Cancellation is checked by
SQLite, between steps, between entity changes, and between historical patches;
a bounded codec or individual validation operation may finish first.

## Scope and remaining limits

The API works in read-only, ordinary writable and collaborative sessions without
migration, user edits, revision changes, cache writes or adopted projections.
Its local input temporary is cleaned up on return. Runtime breakpoint hit counts
are excluded by the existing breakpoint equality contract; diagnostic metadata,
preferences, derived analysis and the collaboration inbox are outside undoable
user state and are not reconstructed.

The database API is exposed through `project history verify` and the optional
`history audit --verify-history` stage; see the
[CLI report and budget documentation](project-history-verification-cli.md).
Desktop history audits retain their current structural/applied-branch behavior.
There is no resumable semantic verification token, repair operation,
authentication guarantee, damaged-database
reconstruction or power-loss claim. A valid, consistently rewritten database and
history can pass; this verifies internal consistency rather than authorship.

Validation: focused Windows Debug `hexlab_database` build; no tests requested
or run. Runtime behavior and cross-platform builds remain unverified.
