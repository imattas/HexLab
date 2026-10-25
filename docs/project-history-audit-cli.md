# Project history audit CLI

`hexlab_cli project history audit <project.hxproj>` performs a read-only,
page-bounded structural audit of the durable undo/redo log. It does not open the
project in the analysis actor or change its history.

```text
hexlab_cli project history audit sample.hxproj
hexlab_cli project history audit sample.hxproj --page-steps 512 --page-bytes 33554432
hexlab_cli project history audit sample.hxproj --max-pages 4 --json
hexlab_cli project history audit sample.hxproj --expected-edit 17 --after-step 2048 --json
```

The first invocation captures the current edit revision and pins every page to
that revision. If a collaborative writer changes the project while pages are
being read, the audit stops with a revision conflict. To resume a partial audit,
pass both the reported `expected_edit` and `next_after_step` values. A cursor
without an explicit revision is rejected so a later run cannot silently audit a
different history snapshot.

`--page-steps` accepts 1 through 4096 entries (default 256). `--page-bytes`
accepts 1 through 128 MiB of combined forward/inverse payload bytes per page
(default 16 MiB). `--max-pages` accepts 1 through 4096 pages (default 4096).
`--total-bytes` caps the whole invocation at 4 GiB (default 512 MiB). Every
entry is checked for sequence continuity and metadata validity; both encoded
delta directions are decoded and the inverse is compared with the inverse of
the forward delta.

Text mode writes progress for the first and each 32nd page to stderr, plus a
final summary to stdout. `--json` writes one JSON object to stdout with `schema_version`,
`status`, project UUID, expected/source edit revisions, history cursor/count,
starting and next step cursors, page/entry/byte totals, `has_more`, and whether
an entry exceeded the remaining page/whole-run byte budget. Increase the
corresponding byte budget before resuming that page. The command exits 0 when the requested
history range is complete, 3 when another page can be resumed, and 1 on I/O,
integrity, or revision errors. Invalid options exit 2.

The report verifies history payload structure and inverse pairing. It does not
replay every command or prove the current project state equals its history
cursor; use bounded exact-step history preview for replay validation.
