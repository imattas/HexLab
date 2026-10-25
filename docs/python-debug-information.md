# Python debug-information workbench

The automation API can preview and import the loader's symbol names or supported
ELF DWARF information, then inspect the persisted local and parameter evidence.
It uses the existing workspace `ImportSymbols` and `ImportDwarfInfo` commands,
including their conflict handling, validation, history and durable commit rules.

```python
import hexlab

with hexlab.Project.open("sample.hxproj", readonly=False) as project:
    preview = project.preview_debug_import("dwarf")
    print(preview)
    if preview.ready:
        project.import_debug_info("dwarf", expected_revision=preview.edit_revision)
        project.analyze()
    else:
        print(preview.reason)

    for variable in project.iter_debug_variables():
        print(variable.function_entry, variable.name, variable.type_id,
              variable.is_parameter, variable.cfa_offset, variable.origin)
```

`preview_debug_import(kind="dwarf", cancel=None)` also works on read-only owners,
including the desktop console's `project`. It validates a detached hypothetical
edit without changing state, entity allocation, history, or the owner's access
mode. Its frozen `DebugImportPreview` reports:

| Field | Meaning |
| --- | --- |
| `kind` | `"symbols"` or `"dwarf"` |
| `project_uuid`, `edit_revision` | Identity and edit generation of the previewed project |
| `ready` | The native validator produced an applicable delta |
| `readonly` | Whether this owner must be reopened writable before committing |
| `reason`, `error_code` | Native validation diagnostic and ErrorCode ordinal when `ready` is false; otherwise empty and `None` |
| `changes` | Total row changes in the projected native delta |
| `annotations`, `types`, `type_assignments`, `functions`, `variables` | Row changes in each category, including updates to existing rows |

`ready` describes the data and does not grant write permission. Unsupported
DWARF sources and imports with no new applicable information return a non-ready
preview. Invalid kind arguments and cancellation raise exceptions. Inspect
`image_info()["metadata_complete"]` separately when source completeness matters;
the preview counts the information the loader actually recovered.

`import_debug_info(kind="dwarf", expected_revision=None, group=0, cancel=None)`
commits one normal command. `"symbols"` imports the native loader's importable
names, preserving existing names and skipping duplicate names according to the
workspace rules. `"dwarf"` imports supported ELF DWARF named types, symbol names,
function decisions, prototypes, type assignments, and scoped local/parameter
records. It retains the existing validator's rules for type conflicts, mapped
addresses and usable instruction boundaries. This is the native ELF DWARF import;
it does not search for or attach additional PDB or DWARF companion files.

Pass the preview's revision only to an import of that same project and kind.
A different edit revision raises `hexlab.Error` with conflict code 8 before
submission, and the normal store commit detects a concurrent writer. Omitting
the revision captures this owner's current edit revision. A read-only import
raises the normal read-only error (code 9). Preview and commit validate
independently; a preview is a detached report, not a reservation of a future
transaction. Ordinary undo/redo applies, and the command's `group` has the same
history meaning as other automation edits. Successful commands are already
durable. Call `analyze()` after imports that invalidate derived facts before
querying functions or decompiling.

Both operations accept `CancellationToken` and use the current desktop console
token by default. Native work releases the Python GIL. Cancellation is checked
before and after preview validation and during result accounting; existing
native import-validation loops can delay observing a stop request. Commit
cancellation follows the workspace transaction contract.

## Persisted variable inspection

`debug_variables(function_entry=None, start=0, count=256,
expected_revision=None, cancel=None)` returns frozen
`DebugVariableInfo` summaries. `function_entry` is an exact typed function entry,
not an interior-address ownership lookup. Omit it to page all persisted variables.
The page offset counts rows after filtering. Each row contains:

- `id`, `function_entry`, `name`, optional project `type_id`, and `is_parameter`.
- `scope_offset`, optional absolute `address`, and optional signed `cfa_offset`.
- `origin`: a detached dictionary with `source_id`, `section`, `unit_offset`,
  `record_offset`, and `record_size`.
- `expression_size`, `operation_count`, and `location_range_count`, disclosing the
  sizes of the independently queried nested evidence.

The `address` and PC range bounds retain the native debug record's unsigned
offsets. `None` means absent; zero is a valid address or CFA offset. A `type_id`
refers to `project.types()` records and may be absent when no compatible named
project definition exists. These are recorded source-debug locations; they do
not evaluate a process's current registers, memory, or runtime variable value.

| Method | Result |
| --- | --- |
| `debug_location_ranges(variable_id, start=0, count=256)` | `DebugLocationRangeInfo(begin, end, expression_size, operation_count)` rows; PC ranges are half-open |
| `debug_location_operations(variable_id, range_index=None, start=0, count=256)` | Detached operation dictionaries for the default expression or one location-list range |
| `read_debug_expression(variable_id, offset, count, range_index=None)` | Exact stored expression bytes; at most 1 MiB per call |
| `iter_debug_variables(function_entry=None, page_size=256)` | All matching variable summaries |
| `iter_debug_location_ranges(variable_id, page_size=256)` | All ranges in stored order |
| `iter_debug_location_operations(variable_id, range_index=None, page_size=256)` | All operations from the selected expression |

Optional arguments following the primary method arguments are keyword-only.
Every inspection method and iterator in the table also accepts
`expected_revision=None` and `cancel=None`. An explicit revision must match the
owner snapshot used by the native read; a mismatch returns native conflict code
8 for individual reads, or `ProjectChangedDuringQuery` for an iterator. Use one
revision for related variable summaries, range indexes, operations and expression
chunks to avoid combining evidence from different edits. Omitting it uses the
current owner snapshot for an individual read, or pins an iterator when iteration
begins. These checks do not poll or refresh external writers.

`cancel` accepts a `CancellationToken` and defaults to the desktop console token.
Native inspection releases the GIL and checks cancellation while searching
variables, skipping filtered rows, and copying page/expression results. A canceled
read raises `AnalysisCancelled` and returns no partial page or byte string.
Iterators also check cancellation before yielding each row.

Page counts and page sizes are 1..4096. Past-end page offsets return empty lists.
Unknown variable IDs or range indexes raise native invalid-argument errors
(code 2); expression reads outside the selected expression raise out-of-bounds
(code 1). Zero-length reads at the end of an expression are allowed.

The default expression and a range's expression are distinct evidence. Pass
`range_index=0` to select the first range rather than the default. Operation
dictionaries retain the native numeric `kind`, `unsigned_operand`,
`signed_operand`, `second_unsigned_operand`, and `expression_offset`. Kind values
follow `hexlab::symbols::LocationOperationKind`; they are not DWARF opcode bytes.
The raw expression preserves original bytes, including operations whose richer
structure is not represented by the persisted operation table.

```python
with hexlab.Project.open("sample.hxproj") as project:
    revision = project.snapshot()["edit_revision"]
    for variable in project.iter_debug_variables(expected_revision=revision):
        ranges = project.iter_debug_location_ranges(variable.id, expected_revision=revision)
        for index, pc_range in enumerate(ranges):
            print(variable.name, hex(pc_range.begin), hex(pc_range.end))
            for operation in project.iter_debug_location_operations(
                    variable.id, range_index=index, expected_revision=revision):
                print(operation)
            # Stream long expressions instead of allocating an unbounded read.
            for offset in range(0, pc_range.expression_size, 65536):
                data = project.read_debug_expression(
                    variable.id, offset, min(65536, pc_range.expression_size - offset),
                    range_index=index, expected_revision=revision)
                print(data.hex())
```

These queries read durable user state, so they work with stale analysis or a
missing loader mapping and do not implicitly reanalyze. Returned values remain
detached after edits. Retain IDs and range indexes only for the observed edit
generation; undo/redo can remove records or change location tables. Iterators
check this owner's edit revision before each yielded row, between pages and
after the last page, raising
`ProjectChangedDuringQuery` if it changes. They do not refresh an independently
changed project owner or lock a project against edits. Native owners retain the
normal creating-thread restriction.

Run `share/hexlab/examples/python/debug_information.py sample.hxproj` to print a
read-only preview and persisted variable summaries. Add `--kind symbols` for a
symbol-name preview. `--apply` explicitly opens writable, imports the previewed
command, and reanalyzes. `--locations` also prints every location range and
decoded operation, with all related reads pinned to one edit revision.
Native clients use `Project::preview_debug_import`,
`import_debug_info`, `debug_variables`, `debug_location_ranges`,
`debug_location_operations`, and `read_debug_expression` without enabling Python.
The C++ evidence-read methods append optional expected-revision and stop-token
arguments after their existing paging/range arguments. Rebuild native consumers
against the updated automation DLL when adopting these signatures.
