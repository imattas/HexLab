# Project history semantic verification CLI

`hexlab_cli project history verify <project.hxproj>` opens a project read-only
and verifies the entire retained undo/redo history against its current durable
user state and embedded original input. It calls the bounded
[`ProjectStore::verify_history_replay` API](project-history-semantic-verification.md)
directly, without starting analysis or adopting a historical state.

```text
hexlab_cli project history verify sample.hxproj
hexlab_cli project history verify sample.hxproj --expected-edit 17 --json
hexlab_cli project history verify sample.hxproj --replay-steps 20000 --replay-bytes 134217728 --json
hexlab_cli project history audit sample.hxproj --verify-history --json
```

The verifier rewinds applied commands to an empty step zero, then replays every
retained command through the redo branch. At the durable cursor it compares the
reconstructed user state with the stored state. It checks both payload
directions, their inverse pairing, expected-before values, monotonic entity
allocations, actual byte/decision invalidation flags and cross-entity validity.
It also re-extracts and SHA-256 verifies the embedded input and checks every
historical patch's original bytes against it. The external provenance path is
not required or read by this semantic verification step.

If omitted, `--expected-edit` captures the revision at read-only open. An
explicit value must match. The database pins semantic verification to one
coherent read transaction and rejects a changed project identity or edit
revision. The source revisions in a successful report describe that snapshot;
they are not historical revision numbers.
The CLI also requires the returned identity, revision tuple and durable
cursor/count to agree with its opening snapshot and any completed structural
audit before it prints a verified result.

## Budgets

Both standalone verification and `history audit --verify-history` accept:

| Option | Default | Accepted range |
| --- | --- | --- |
| `--replay-steps` | 4,096 | 0..200,000 |
| `--replay-bytes` | 67,108,864 | 0..536,870,912 |
| `--replay-input-bytes` | 268,435,456 | 0..1,073,741,824 |
| `--replay-validation-bytes` | 268,435,456 | 0..4,294,967,296 |

Transitions count the applied rewind plus the complete forward pass: cursor 12
with 20 retained commands needs 32 transitions. The delta budget counts both
payload directions on every traversal. The validation budget counts canonical
state encodings and the historical original-patch bytes compared. Per-state
codec bounds remain in force. These replay budgets are independent of structural
audit pagination budgets. Supplying replay budgets to an audit requires
`--verify-history`; they are rejected as inapplicable on other commands.

## Reports and exit status

Text output identifies the project, edit revision and durable cursor/count. A
successful result includes rewind/forward steps and delta, input, validation
and original-patch byte counters.

Standalone `--json` emits schema `hexlab.project-history-verification.v1`,
`schema_version: 1`, top-level `status`, project UUID, expected edit and durable
cursor/count. Its `semantic_verification` object contains:

- `status`: `verified` or `budget_limited`.
- `complete`: true only when every retained command was verified.
- `limits`: the four requested work limits.
- `report`: the complete database report, or null if verification did not
  finish. The complete report includes source revisions, input identity,
  history cursor/count and all work counters.
- `diagnostic`: null on success, otherwise the bounded-work failure reason.

Exit 0 means the full verification succeeded. Exit 3 means a resource/work
budget prevented completion: no partial proof or resumable semantic cursor is
returned. Increase the corresponding limit and retry the whole verification.
An underlying per-record allocation/codec limit can also produce exit 3 and
may require reducing the project payload rather than raising a CLI limit.
Integrity, revision-conflict and I/O failures exit 1 with an error on stderr;
invalid options exit 2. Those failures do not emit a successful JSON report.

## Composing with structural audits

`history audit --verify-history` keeps existing paginated structural auditing
and invokes the same semantic verifier only after the requested structural
range completes. JSON uses audit schema version 3, adds `structural_complete`
and appends the same `semantic_verification` object. A partial structural scan reports semantic
`status: not_run`, `complete: false` and `report: null`. Resume structural
pages using the existing expected-edit/cursor pair; the semantic step always
checks the entire retained log, including when the final structural request
starts from a nonzero resume cursor.

If structural auditing completes but semantic replay hits a budget, overall
audit `status` is `partial` and exit status is 3, even though `has_more` is
false. The nested semantic status identifies the incomplete work. Run the
standalone `history verify` command with the same expected edit and larger
replay budgets to avoid repeating already completed structural pages.

The existing `--verify-replay` option keeps its earlier applied-branch rewind
behavior and limits. `--verify-input` continues to verify the recorded external
source file. Neither is implicitly enabled by `--verify-history`; requesting
them together runs each requested check. Audits without `--verify-history`
retain their existing JSON schema versions and exit behavior.

There is no repair, history editing, authenticity guarantee or semantic resume
token. Runtime breakpoint hit counts, diagnostics, preferences, collaboration
inbox rows and derived analysis remain outside undoable user-state replay.
The database API remains unchanged by this CLI integration.

Validation is a focused Windows Debug CLI build with testing disabled. No tests
or runtime CLI invocations were requested or run.
