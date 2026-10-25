# Project exchange import CLI

`hexlab_cli project exchange import` can preview and report the workspace's portable metadata import plan before committing it:

```powershell
hexlab_cli project exchange import sample.hxproj --input review.hxex --dry-run
hexlab_cli project exchange import sample.hxproj --input review.hxex --conflict replace --dry-run --json
hexlab_cli project exchange import sample.hxproj --input review.hxex --conflict skip --json
```

The dry run opens the destination read-only and never changes the project. It parses and validates the exchange bundle, asks the same planner used by a real import to resolve conflicts, and reports how many records would be imported or skipped. A dry run with the default `fail` policy still lists the complete conflict set by planning with `skip`, then sets `would_fail` when a conflict exists. A real import with `fail` retains the existing all-or-nothing failure behavior.

`--json` emits schema version 1 with an `applied` flag, `would_fail`, planned per-kind counts, and conflict rows. Each row includes its record kind, destination location, optional related location for references, and resolution (`kept_existing`, `imported`, or `preserved_both`). At most 1,000 conflict rows are emitted; `omitted_conflicts` gives the number left out. Human-readable output uses the same ordering and cap. Conflict rows follow the exchange planner's deterministic order.

The bundle remains bound to identical original input bytes. Import uses the existing project history command path for writes; this CLI addition does not alter the portable exchange format or merge policy.
