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
does not replace a name already used in the same address space. It reads a
complete project snapshot and refuses to merge if more than 4096 annotations
or bookmarks exist, because omitted rows cannot safely be treated as absent.
Pass `expected_revision` to pin that snapshot; if all requested fields are
already populated, preserve mode returns the unchanged snapshot without adding
a history step. Use `Project.apply_batch()` for references, types, patches,
regions, functions, and other mixed project edits.
