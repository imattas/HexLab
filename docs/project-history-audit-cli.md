# Project history audit CLI

`hexlab_cli project history audit <project.hxproj>` performs a read-only,
page-bounded structural audit of the durable undo/redo log. It does not open the
project in the analysis actor or change its history.

```text
hexlab_cli project history audit sample.hxproj
hexlab_cli project history audit sample.hxproj --page-steps 512 --page-bytes 33554432
hexlab_cli project history audit sample.hxproj --max-pages 4 --json
hexlab_cli project history audit sample.hxproj --expected-edit 17 --after-step 2048 --json
hexlab_cli project history audit sample.hxproj --verify-input --json
hexlab_cli project history audit sample.hxproj --verify-history --json
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

The base report verifies history payload structure and inverse pairing.
`--verify-history` additionally runs bounded semantic verification after all
requested structural pages complete: rewind to an empty root, forward replay
through every redo command, durable cursor agreement and historical original
patch checks against verified embedded input. It adds audit JSON schema version
3 and a `semantic_verification` object with `verified`, `budget_limited` or
`not_run` status. Overall status stays partial and exit status is 3 if semantic
verification was requested but did not finish, including when structural
`has_more` is false. The standalone `project history verify` command can run that
step independently. See [semantic verification CLI](project-history-verification-cli.md)
for its four separate replay budgets, report fields and retry behavior.

`--verify-input` additionally resolves the external source path recorded in the
project provenance, checks its size, and hashes it with SHA-256 against the
embedded input identity. A relative provenance path is resolved beside the
project file. Missing provenance, unreadable input, size changes, or digest
mismatches are reported as errors; the command does not modify the project.
Text output reports the verified path. JSON uses schema version 2 when this
option is present and includes `input_verification` with status, path, size,
and digest. This checks the currently reachable source file; it does not
validate unrelated files or history recovery artifacts.
