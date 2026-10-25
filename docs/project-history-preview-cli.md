# Project history preview CLI

`hexlab_cli project history preview <project.hxproj> --step N` reconstructs the user state at the exact durable history step `N`. It opens the project read-only and does not change the history cursor, edit revision, or project state. The report shows the source edit revision, current cursor, selected step, replay work, and counts for annotations, bookmarks, breakpoints, code/data regions, function decisions, references, types, type assignments, debug variables, and patch spans/bytes in both the current and reconstructed states.

Use `--json` for a schema-versioned machine-readable summary. `--max-steps` and `--max-bytes` tune the bounded replay budget; the accepted limits are 4,096 steps and 64 MiB of history payload. A limit error does not return a partial preview. Exit status 0 means the selected step is the current cursor; status 3 means the exact preview succeeded but the selected state differs from the current cursor. Invalid steps and revision conflicts are reported as errors.

```powershell
hexlab_cli project history preview sample.hxproj --step 12
hexlab_cli project history preview sample.hxproj --step 0 --json
```

The summary reports record counts and patch byte totals, not a row-by-row semantic diff. For payload integrity checks and resumable history scanning, see [Project history audit](project-history-audit.md).

To continue working from a selected historical state, use
`hexlab_cli project history save sample.hxproj --step 12 --output recovered.hxproj`.
Pass the preview's `source_edit` as `--expected-edit` to reject source changes
between preview and publication. The source remains unchanged and the independent
output retains all undo/redo history. See [Save a historical project](project-history-save-cli.md).
