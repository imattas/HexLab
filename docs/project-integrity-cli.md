# Read-only project integrity check

Run a bounded SQLite integrity and foreign-key check without opening the
project for writing:

```powershell
hexlab_cli project integrity .\projects\sample.hxproj --json
hexlab_cli project integrity .\projects\sample.hxproj --verify-history --json
```

The command opens a read-only `ProjectStore`, captures its edit revision, and
calls `ProjectStore::check_integrity` against a deferred SQLite read snapshot.
If the edit revision changed before the check could pin its snapshot, the
operation returns a conflict instead of reporting a result for a different
project state. The operation does not repair or rewrite the project.

Add `--verify-history` to include bounded whole-history semantic replay. This
also verifies the embedded original input, inverse/forward command payloads,
and historical patches against that input across both the applied and redo
branches. The option accepts `--replay-steps`, `--replay-bytes`,
`--replay-input-bytes`, and `--replay-validation-bytes`, with the same limits as
[whole-history semantic verification](project-history-semantic-verification.md).
Both checks are read-only. A history verification error prevents a combined
success report.

The default issue limit is 64. `--max-issues` accepts 1 through 256; if more
issues exist than the requested limit, the report is incomplete and the command
returns exit code 3. A consistent, complete report returns 0. Inconsistent or
incomplete reports return 3; open, IO, cancellation, and revision conflicts use
the normal CLI error exit status. The command cannot repair damaged databases.
Without `--verify-history`, it does not replace embedded-input or history
checks.

JSON uses `schema_version: 1` without history verification and
`schema_version: 2` with `--verify-history`; both use
`operation: "project-integrity"`. It includes
the project UUID, checked edit/byte/decision revisions, `consistent`,
`complete`, the selected issue cap, and bounded issue strings. Text output shows
the same identity and revisions and lists each retained issue. Version 2 adds a
`history_verification` object with the verified cursor/count, replay counts,
and embedded-input, delta, state-validation, and patch-byte totals.
