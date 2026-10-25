# Save a historical project

Recover an earlier project state into a separate, editable project:

```powershell
hexlab_cli project history save sample.hxproj --step 12 --output recovered.hxproj
```

The source opens read-only and stays unchanged. The output has a new project
UUID and opens at exactly step 12. It retains the embedded binary, all durable
annotations, types, analysis decisions and patches at that step, and the complete
undo/redo log. Commands after step 12 remain available through redo. The target
may also be zero, a redo position, or a position inside a command group. Ordinary
undo/redo continues to respect command grouping.

Preview first when choosing a recovery point:

```powershell
hexlab_cli project history preview sample.hxproj --step 12 --json
hexlab_cli project history save sample.hxproj --step 12 --output recovered.hxproj --expected-edit 42
```

Replace `42` with the preview report's `source_edit`. `--expected-edit` prevents
saving a different source revision if another writer edits the project between
preview and save. Without it, save pins the source revision observed when the
command opens the project. A revision mismatch fails without publishing a file.
Preview's exit status 3 means a successful preview of a different cursor; the
save command returns 0 after successful publication, including when saving an
earlier step.

`--output` and `--step` are required. An existing output is refused unless
`--replace` is supplied. Replacement uses checked atomic publication and retains
the previous complete destination as a recovery artifact. The source project,
its SQLite companions, and the original binary cannot be used as the output.
The resulting project and the original can be open together because their
UUIDs differ.

Replay defaults to 256 steps and 16 MiB of aggregate directional history payload.
Use `--max-steps N` and `--max-bytes N` to choose budgets up to 4096 steps and
67108864 bytes. Accepted budgets can be zero when saving the current cursor.
Exceeding a budget fails the whole operation and leaves an existing output
unchanged; no partial result is published. These budgets limit replay work,
not embedded binary size. Saved patches are checked against the embedded
original, and the embedded input is hashed before publication.

Use `--json` for a schema-versioned publication receipt:

```powershell
hexlab_cli project history save sample.hxproj --step 0 --output clean.hxproj --json
```

The JSON object reports `schema_version` (1), `source_uuid`, `source_edit`,
`target_step`, the absolute output `path`, and the new `project_uuid`. It is
emitted only after publication succeeds. Paths and UUIDs are JSON strings;
revisions and steps are unsigned numbers.

The copied project retains its source allocation cursor, so IDs allocated after
the requested step are never reused. Revisions advance monotonically when the
copied cursor moves; they are not historical revision numbers. Breakpoint hit
counts are runtime metadata and are not reconstructed historically. The
operation replays only the interval needed to reach the requested step; use
[history audit](project-history-audit.md) to independently check all history
payloads. See [historical save guarantees](../libs/database/HISTORY_SAVE.md) for database API
details and [project recovery](project-recovery-cli.md) for interrupted-save
artifacts.
