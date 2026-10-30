# Atomic annotation imports

`Project::import_annotations` is the native SDK entry point for importing names,
comments, and bookmarks. Python `Project.apply_annotations`, JSON imports, CSV
imports, and `examples/import_annotations.py` use this service. Merge decisions
read the complete native user state instead of Python's 4096-row snapshot preview.

The service accepts 1–4096 rows, at most 4096 supplied fields in total, and at
most 16 MiB of incoming UTF-8 text. Limits count fields that preserve mode would
skip. Names and bookmark labels have the database's 512-byte limit; comments
have its 1 MiB limit. All supplied text passes canonical database UTF-8 and
control-character validation before merge planning, including skipped fields.
Names require virtual addresses. Comments and bookmarks support virtual and
file-offset locations. Rows with no fields are rejected.

```python
with hexlab.Project.open("sample.hxproj", readonly=False) as project:
    revision = project.snapshot()["edit_revision"]
    report = project.apply_annotations(
        [{"location": hexlab.Address(0, 0x401000),
          "name": "entry_main", "comment": "Reviewed entry", "bookmark": "review"},
         {"location": hexlab.FileOffset(0x20), "comment": "Header field"}],
        expected_revision=revision, merge="preserve", return_report=True)
    print(report["applied"], report["skipped"], report["committed"])
```

The SDK exposes the same contract with `AnnotationImportRow`,
`AnnotationBookmarkImport`, `AnnotationMerge`, and `AnnotationImportResult`:

```cpp
std::vector<hexlab::automation::AnnotationImportRow> rows{
    {hexlab::Address{{0}, 0x401000}, std::string("entry_main"),
     std::string("Reviewed entry"), hexlab::automation::AnnotationBookmarkImport{"review", false}},
    {hexlab::FileOffset{0x20}, {}, std::string("Header field"), {}}
};
auto result = project->import_annotations(rows,
    hexlab::automation::AnnotationMerge::preserve, 0, expected_edit_revision);
if (!result) { /* report result.error(); no partial import was committed */ }
```

Replace mode applies fields in input order. Omitted fields are untouched; empty
names/comments clear fields, and a Python `None` bookmark or native `remove=true`
removes a bookmark. Removing an absent bookmark is invalid. Duplicate fields in
replace mode follow ordered command semantics, so a later value wins if every
intermediate command is valid. Name conflicts are validated against projected
state; clear or move an existing name before assigning it elsewhere. A replace
batch with no net changes is rejected by the workspace batch contract.

Preserve mode fills only empty names/comments and absent bookmarks. It skips
empty strings, bookmark removals, occupied fields, and names already used at a
different address in the same address space. The first accepted value for each
field wins, including repeated locations within the same import. Existing-state
planning permits up to 65,536 annotations and 65,536 bookmarks, with cancellation
checks during indexing. Larger tables fail with `resource_limit`; rows are never
silently truncated. Skipped fields do not become native edits; their locations
are not checked for mapping unless another selected edit targets them. A fully
skipped import returns the unchanged snapshot without adding a history step.

The optional expected revision rejects a stale manifest before planning. When
omitted, the service pins its current native snapshot revision. Selected edits
are validated together against projected state and committed through one
database transaction and one persistent history step. Invalid locations, invalid
text, duplicate-name conflicts, cancellation, read-only writes, and stale
revisions leave the entire import unapplied. A successful import supports normal
undo/redo and remains present when the project is reopened. Caller group values
use the project's ordinary history grouping semantics.

The result contains `snapshot`, `expected_revision`, `result_revision`, `applied`,
`skipped`, and `committed`. Counts refer to fields: applied counts planned native
edits, including a field that may be unchanged within an otherwise changing
batch. Python also returns `planned_edits` as an alias for applied. This service
is synchronous and thread-affine; validation of large existing tables can be
expensive, so UI hosts should use their normal automation worker thread.

The existing JSON/CSV manifest schema remains version 1. Use the example for a
complete bounded file import:

```text
hexlab_python import_annotations.py sample.hxproj labels.json --merge preserve
hexlab_python import_annotations.py sample.hxproj labels.csv --format csv --merge replace
```

CSV blank annotation cells omit fields; JSON/native rows can express clearing
and bookmark removal. The example rejects contradictory duplicate manifest
fields before importing and reports native applied/skipped counts. File parsing
and native planning finish before the single project commit. Cancellation is
cooperative before that commit; cancellation arriving after a successful commit
cannot roll it back.
