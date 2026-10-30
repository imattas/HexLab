# Revision-pinned Python edit batches

`Project.apply_batch()` stages multiple different project commands and commits
all valid commands as one history step. A validation error, stale edit revision,
read-only project, or cancellation before commit leaves every staged command
unapplied.

Capture `project.snapshot()["edit_revision"]` before planning and pass it as
`expected_revision`. The native project command path checks the revision before
commit; SQLite's revision compare-and-swap also rejects changes from another
project owner. The result is the usual detached project snapshot dictionary.

Supported operation tuples are:

```python
("rename", location, name)
("comment", location, text)
("bookmark", location, label, remove_bool)
("patch", location, bytes_like_payload)
("code" | "data", Address, size)
("function", Address)
("suppress_function", Address, suppressed_bool)
("reference", source, target, kind, remove_bool)
("chunks", function_entry, [(chunk_entry, size), ...])
("type_assignment", Address, type_id, remove_bool)
("update_type", type_id, name, TypeSpec)
("breakpoint", Address, breakpoint_kind, size, enabled, remove, condition,
             logpoint, log_message, ignore_count)
```

Locations for names, comments, bookmarks, patches, and reference endpoints use
`Address` or `FileOffset`. Code/data, function, chunks, assignments, and saved
breakpoints require virtual `Address` values. Reference kinds are `code`,
`data`, `call`, `jump`, `read`, `write`, and `address`; saved breakpoint kinds
are `software`, `hardware`, `execute`, `read`, `write`, and `access`. The normal
workspace validator enforces mapped ranges, type IDs, chunk ownership,
breakpoint identity, and command-specific constraints against the projected
state after earlier operations in the same batch.

The batch has limits of 4,096 commands, 16 MiB of text, 16 MiB of patch bytes,
1 MiB per patch, 65,536 total function chunks, and 262,144 type nodes. The
Python wrapper bounds the input iterator and validates operation shapes before
entering native code. Native validation and commit run without holding the GIL
and accept an optional `CancellationToken`:

```python
cancel = hexlab.CancellationToken()
revision = project.snapshot()["edit_revision"]
project.apply_batch(
    [("rename", entry, "entry_main"),
     ("comment", entry, "Validated by the import script.")],
    expected_revision=revision,
    cancel=cancel,
)
```

`Project.apply_annotations()` remains convenient for manifests containing only
names, comments, and bookmarks. Its existing input format supports
`merge="replace"` (the default) or `merge="preserve"`. Preserve mode fills only
empty names/comments and absent bookmarks, ignores clear/removal requests, and
does not replace a name already used in the same address space. It plans
against the complete native project state and refuses to merge if more than
65,536 existing annotations or more than 65,536 existing bookmarks exist,
because omitted rows cannot safely be treated as absent. Incoming batches are
limited to 4096 rows/fields and 16 MiB of supplied text.
Pass `expected_revision` to pin that snapshot; if all requested fields are
already populated, preserve mode returns the unchanged snapshot without adding
a history step. Pass `return_report=True` to receive the resulting snapshot,
per-field `applied` and `skipped` counts, the pinned `expected_revision`, the
`result_revision`, `planned_edits`, and `committed` instead of the snapshot
alone. `committed` is true only when the result revision differs from the
expected revision; a preserve-mode no-op reports the same revisions and false.
The counts are per requested name/comment/bookmark field; preserve mode
counts empty values, attempted removals, occupied values, and names already in
use elsewhere as skipped. It also reserves fields accepted earlier in the same
preserve batch, so duplicate incoming names/bookmarks are skipped consistently
without mutating the detached snapshot used for the report. The default return
value remains the snapshot. Use
`Project.apply_batch()` for references, types, patches,
regions, functions, and other mixed project edits.

`Project.export_annotations_json(path)` writes a stable versioned manifest of
the current names, comments, and bookmarks. It is limited to 4096 annotation
and bookmark rows and 16 MiB, and publishes through a sibling temporary file
without replacing an existing destination. The export records the source edit
revision and uses explicit `va` or `file` location objects. For example:

```python
project.export_annotations_json("labels.json")
project.import_annotations_json(
    "labels.json",
    expected_revision=project.snapshot()["edit_revision"],
    merge="preserve",
)
```

`Project.export_annotations_csv(path)` writes the same bounded snapshot as
UTF-8 CSV with `location_kind,space,offset,name,comment,bookmark` columns.
It combines annotations and bookmarks by location, uses hexadecimal offsets,
checks the edit revision before publishing, and atomically creates the target
without replacing an existing file. Both exporters reject snapshots above
4096 annotation or bookmark rows and outputs above 16 MiB. The CLI helper can
produce this CSV with `hexlab_python import_annotations.py project.hxproj
labels.csv --export`; the output can then be imported through its normal CSV
mode as one revision-pinned atomic annotation batch.

The same CSV format can be imported directly through
`Project.import_annotations_csv(path, expected_revision=..., merge=...)`:

```python
revision = project.snapshot()["edit_revision"]
report = project.import_annotations_csv(
    "labels.csv", expected_revision=revision, merge="preserve",
    return_report=True,
)
```

The reader accepts a UTF-8 or UTF-8-with-BOM file up to 16 MiB and 4096 data
rows. Its strict CSV header requires `location_kind` and `offset`, allows
`space`, `name`, `comment`, and `bookmark`, and rejects duplicate/unknown
columns, malformed quoting, incomplete locations, and rows with no annotation
fields. Decimal and prefixed integer addresses are accepted. Parsed rows use
the same revision-pinned, bounded, cancellable atomic batch as
`apply_annotations`; CSV parsing itself checks cancellation between rows.
An empty data section is a no-op that still validates an explicitly supplied
revision. The existing example importer remains available for command-line
workflows.

`Project.import_annotations_json()` rejects duplicate JSON keys, unsupported
versions, unknown fields, invalid locations, oversized input, and more than
4096 rows before it calls the same atomic annotation batch path. An omitted
`expected_revision` pins the target project's current revision when the batch
is planned; pass it explicitly when the caller needs a previously captured
revision. An empty manifest is a no-op. Cancellation is checked while parsing
and by the native validation/commit path.

The `examples/import_annotations.py` command-line importer accepts both the
versioned manifest produced by `export_annotations_json()` and the older
plain row-array format. It keeps its `--merge replace|preserve` behavior for
either input shape.

For large manifests, `apply_annotations(..., cancel=token)` accepts the same
`CancellationToken` as `apply_batch()`. It checks cancellation while validating
rows and the native projected-state validation checks again before commit. A
canceled import raises `AnalysisCancelled` and does not commit any annotation
changes. When called from the automation console, its current cancellation
token is used if `cancel` is omitted.
