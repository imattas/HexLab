# Python automation v1

`hexlab_python script.py [arguments...]` executes trusted Python against the same
project store, command validation, analysis engine and persistent history as the
CLI/native application. With no script, it opens an interactive Python console.
`import hexlab` is available in this embedded interpreter. It is not installed
into a system Python and does not shell out to the CLI.

The runner accepts Python script, command, and module modes:

```powershell
hexlab_python analyze.py sample.hxproj --summary
hexlab_python -c "import hexlab; print(hexlab.API_VERSION)"
hexlab_python -m package.tool sample.hxproj
hexlab_python --help
```

Script arguments are exposed through `sys.argv` after the script path. In
`-c` mode, `sys.argv[0]` is `-c` and following arguments remain available; in
`-m` mode, the module name and following arguments are preserved, with module
execution delegated to Python's `runpy`. The current working directory is added
to the import path for command and module mode, matching Python's usual local
script workflow. With no arguments, the runner opens its interactive console.

The native `hexlab::automation::Project` bridge always builds when its library is
included. CPython discovery and linking occur only with
`HEXLAB_ENABLE_PYTHON_AUTOMATION=ON` (default OFF). The eight existing engine DLLs
remain independent of Python. The new runner links CPython; Python itself is not
vendored or redistributed by this change. Use a matching architecture CPython
3.10+ development installation and make its shared runtime discoverable when
launching the runner. Windows Debug links the installed release CPython library;
Python objects are allocated/freed by Python, and no host CRT FILE pointer crosses
that boundary. Other operating systems have not been executed for this subsystem.

The [debug-information workbench](python-debug-information.md) adds read-only
symbol/DWARF import previews, revision-pinned imports through the native workspace
commands, and bounded inspection of persisted local/parameter locations and raw
debug expressions.

The `Project.function_signature_catalog()` and
`Project.recognize_function_signatures()` methods expose bounded masked-byte
catalog creation and recovered-entry recognition. Catalog creation takes an
ordered list of 1..4096 recovered function IDs and returns the portable text
catalog; recognition consumes that text and reports candidates and ambiguity
without changing names. Both calls accept `expected_revision` and `cancel`, and
raise `ProjectChangedDuringQuery` if the project changes while the operation is
running. Prefix options default to 128 bytes and eight exact bytes, with the
native hard cap of 256 bytes. Recognition uses the native signature-work limits
and caps catalog input at 64 MiB.

## Build and test

Normal integrated build (after `add_subdirectory(automation)` following workspace
in `libs/CMakeLists.txt`):

```powershell
cmake -S . -B out/build/windows-desktop -DHEXLAB_ENABLE_PYTHON_AUTOMATION=ON
cmake --build out/build/windows-desktop --config Debug --target hexlab_python hexlab_automation_tests
ctest --test-dir out/build/windows-desktop -C Debug -R '^automation_' --output-on-failure
```

The subsystem also supports an isolated build against a complete, current HexLab
source build. Every public header consumer must match that build's DLL ABI:

```powershell
cmake -S libs/automation -B out/build/automation -DHEXLAB_ENGINE_BUILD=G:/HexLab/out/build/windows-desktop -DHEXLAB_DEBUGGER_BUILD=G:/HexLab/out/build/windows-desktop -DHEXLAB_ENABLE_PYTHON_AUTOMATION=ON
cmake --build out/build/automation --config Debug
$env:PATH='G:\HexLab\out\build\windows-desktop\bin\Debug;'+$env:PATH
ctest --test-dir out/build/automation -C Debug --output-on-failure
```

Use a separate build directory with the Python option OFF to verify the native
bridge without finding Python. Standalone build imports engine targets and does
not rebuild their DLLs; do not combine old binaries with new source headers.
The generated export header follows the existing HexLab installation layout.
The runner, bridge, public headers, this document and
`share/hexlab/examples/python/annotate.py` install with the normal CMake package.
The Python facade is embedded in the executable, so a neighboring `.py` file
cannot silently replace that API.

## Public API

`hexlab.API_VERSION == 1`. Creation/open methods accept `api_version=1`; unknown
versions fail. This is a versioned **source API** and Python data contract, not a
cross-toolchain binary C++ ABI. Rebuild native consumers after public value type
changes, as with the rest of HexLab. The plugin SDK keeps its independent
allocator-neutral C ABI and lifecycle; no Python objects cross that boundary.

```python
import hexlab

with hexlab.Project.open("sample.hxproj", readonly=False) as project:
    entry = project.snapshot()["entries"][0]
    print(project.read(entry, 8))
    print(project.function_at(entry))
    for instruction in project.instructions(count=16):
        print(instruction["address"], instruction["text"])
    project.comment(entry, "reviewed by script", group=1)
    project.bookmark(entry, "review", group=1)
    project.undo()     # both edits share the normal persistent command group
    project.redo()
    project.patch(entry, b"\xcc", expected_revision=project.snapshot()["edit_revision"])
    project.export_binary("patched.bin")  # refuses an existing destination
    summary = project.export_analysis_json("analysis.json", page_size=1024)
    print(summary["function_count"], summary["instruction_count"], summary["reference_count"])
```

Create a reusable normalized fingerprint catalog from a selected function
batch. The selection order is preserved, and the whole operation fails if any
ID is duplicated, stale, or cannot be fingerprinted:

```python
from pathlib import Path

metadata = project.snapshot()
if metadata["function_count"] > 4096:
    raise ValueError("select no more than 4096 functions")
ids = [row["id"] for row in project.iter_functions(max_rows=4096)]
catalog_text = project.function_fingerprint_catalog(
    ids, "internal library release 4",
    expected_revision=metadata["edit_revision"],
)
Path("library.fingerprint").write_text(catalog_text, encoding="utf-8")
```

The returned text uses the existing normalized fingerprint catalog v1 format.
The API caps selections at 4096 IDs, validates per-function instruction/block
and token-byte options, and raises `ProjectChangedDuringQuery` if the project
changes during extraction. Supplying `expected_revision` also rejects an edit
that happened before its snapshot was captured. The cancel argument accepts a
`CancellationToken`.

Named type graphs are editable through `TypeSpec`, a detached Python value DSL
that maps to HexLab's validated native type model. Member offsets, aggregate
size and alignment are explicit; recursive aggregates use a named reference so
the graph remains finite. For example:

```python
u32 = hexlab.TypeSpec.integer("u32", 4, alignment=4)
node = hexlab.TypeSpec.structure("Node", [
    ("value", u32, 0),
    ("next", hexlab.TypeSpec.pointer(hexlab.TypeSpec.named_reference("Node"), 8, alignment=8), 8),
], size=16, alignment=8)
type_id = project.define_type("Node", node)
project.assign_type(entry, type_id)

vec4i = hexlab.TypeSpec.vector(u32, 4, alignment=16)
```

`TypeSpec` also provides constructors for void, boolean, floating point,
homogeneous vectors, pointer, array, union, enumeration and function types.
Vector lanes must be integer or floating scalars and have an explicit count
and alignment. Enumeration entries are
`(name, value)` pairs; function parameters are `(name, TypeSpec)` pairs;
aggregate members may include bit width and bit offset after their byte offset.
Function types preserve the ABI calling convention in their detached type
description and persistent history. `TypeSpec.function(..., convention=...)`
accepts `platform_default`, `c_decl`, `stdcall`, `fastcall`, `thiscall`,
`vectorcall`, `sysv_abi`, `ms_abi`, and `aapcs64`; the default is
`platform_default`. This records the declared convention in the type model but
does not change recovered function analysis or assign arguments to ABI locations.
`snapshot()["types"]` contains `{id, name, type}` rows and
`snapshot()["type_assignments"]` contains `{location, type_id}` rows. These
records are immutable Python descriptions detached from the native project.
`update_type` preserves the existing identity, and assignment removal plus all
type edits use ordinary persistent command history and grouped undo/redo.

For example, `share/hexlab/examples/python/prototype.py` writes a prototype
with an explicit convention and assigns it to an address in a writable project:

```powershell
hexlab_python share/hexlab/examples/python/prototype.py sample.hxproj 0 0x401000 sysv_abi
```

Analysis queries include bounded `functions`, `instructions`, `strings`, and
`references` pages. `segments()` returns the loaded image's mapped ranges with
their address-space coordinates, virtual size, initialized file extent, and
read/write/execute permissions. It is available for mapped formats and reports
an unsupported error for file-only projects. `export_analysis_json` includes
all segments in its version-1 document. `search_bytes("48 8? ?? C3")` accepts
two-nibble octets where either nibble may be `?`, so `?F`, `A?`, and `??` are
wildcards at the nibble or full-byte level. `search_text("name",
encoding="utf8")`, and `search_immediate("42", width=8)` search effective project
bytes or current decoded instruction facts. Each returns a `SearchPage` with typed
locations, file provenance, completion state, and an opaque continuation cursor.
Pass `page.next` back as `cursor` to continue. Cursors are bound to the source
revision and query; edits invalidate prior continuations. Immediate search
requires current decoded facts, so call `analyze()` after edits that make analysis
stale. Pages are capped at 4096 results and the native candidate/comparison
budgets keep work bounded. Pass a `CancellationToken` as `cancel=` to any search
method to interrupt the native scan; cancellation raises `AnalysisCancelled` and
does not return a partial page. `source_complete` distinguishes a completed scan
from a complete decoded instruction source.

Each Python string record includes a `script_hint` alongside its encoding name.
The hint classifies the retained UTF-8 preview (at most 256 Unicode scalars) into
a coarse script family such as Latin, Cyrillic, Greek, Hebrew, Arabic, Thai, Han,
Kana, Hangul, or Other. Multiple recognized families produce `Mixed`; text with
no recognized letters, or malformed UTF-8, produces `unknown`. This is a display
hint rather than language, locale, or source-encoding detection.

Pass `start=FileOffset(offset)` to begin from an inclusive file offset or
`start=Address(space, offset)` to begin from a mapped virtual address. Address
starts require unique file-backed bytes; immediate searches also use the
address to select among instructions sharing a file offset. The first page
starts there without wrapping. Continuation cursors carry their own position;
iterators apply `start` only to the first page.

`search_text()` and `iter_search_text()` accept `case_sensitive=False` to fold
ASCII `A`–`Z` while matching. Other encoded bytes remain exact; this does not
perform Unicode case folding.

For full searches, `iter_search_bytes()`, `iter_search_text()`, and
`iter_search_immediate()` follow revision-bound cursors and yield matches
without collecting the full result set. Each accepts `page_size` (1..4096),
optional `max_rows`, and `cancel`. A source edit between pages raises
`ProjectChangedDuringQuery`; reaching `max_rows` intentionally stops early.
Keep the page methods when you need each `SearchPage`'s scan counters or
completion metadata.

`image_info()` reports whether an image is mapped, loader format/machine/base/
size/header metadata, metadata completeness, architecture and execution-mode
enum values, entry addresses, address-space count, and segment count. Use
`segments()` for the bounded ranges and permissions. `annotations()`, `types()`,
and `type_assignments()` page the durable database rows that are shown only as a
bounded preview in `snapshot()`. The corresponding `iter_annotations()`,
`iter_types()`, and `iter_type_assignments()` methods stream full tables. Names
and comments are returned by `presentation(location)` and changed with
`rename()` and `comment()`; type definitions and assignments use `define_type()`,
`update_type()`, and `assign_type()`. These edits go through the normal validated
project command path and persistent grouped history.

`addresses_for_file_offset(offset)` returns every initialized virtual alias
for a source file byte in stable address order. An empty list means the byte
has no virtual backing. This makes aliased file bytes queryable without
treating valid multiple mappings as an ambiguity error.

For ELF inputs, `elf_dynamic_entries(start=0, count=256)` pages the loader's
decoded dynamic-table entries. Each row carries its source section (when
section-backed), table file offset and mapped address, entry index, signed tag,
raw value, and optional decoded string value. `iter_elf_dynamic_entries()`
streams multiple tables in loader order through bounded pages. Non-ELF images
and ELF images without dynamic tables return an empty page. This is descriptive
loader metadata: it does not resolve symbols or apply relocations. Use the
loader-specific ELF metadata tools when full symbol or relocation records are
needed.

For PE images, `pe_imports(start=0, count=256)` and `pe_exports(start=0,
count=256)` expose the bounded loader tables. Import rows preserve library,
name or ordinal, thunk and IAT addresses, and whether the row is a delay import.
Export rows retain ordinal, optional name, mapped address, and forwarder.
Ordinal-only exports and forwarders remain distinct rows; an absent mapped
address is returned as `None`. Non-PE images return empty pages. The
`iter_pe_imports()` and `iter_pe_exports()` helpers page through the tables
without accumulating native query results in a single call.

`references(location)` returns outgoing code and data xrefs;
`incoming_references()` and `all_references()` provide reverse and global pages.
`outgoing_references_range(address, size)` pages source xrefs for a nonempty
half-open virtual-address range; its iterator pins all pages to one workspace
capture and supports cancellation.
Rows retain typed address or file-offset endpoints, reference kind, and external
or unresolved target provenance. Like function and instruction enumeration,
xref queries require fresh or incomplete current derived analysis; call
`analyze()` after an edit invalidates those facts. Page calls are synchronous
and thread-affine. Long analysis, search, export, history replay, and graph walks
retain their existing cancellation paths.

For scripts that need a complete table walk, `iter_functions()`,
`iter_instructions()`, `iter_segments()`, `iter_strings()`, `iter_annotations()`,
`iter_types()`, `iter_type_assignments()`, `iter_references(location)`,
`iter_incoming_references(location)`, `iter_outgoing_references_range(address, size)`,
and `iter_all_references()` yield rows page by page instead of retaining the whole
table in memory. Each accepts `page_size` from 1 through 4096 (default 256).
They use the same native page queries and stale-analysis checks as the explicit
page methods. General workspace iterators now capture one immutable workspace
when iteration starts, so source edits or replacement analysis cannot mix pages.
They also accept `max_rows=None` and `cancel=None`: a non-negative `max_rows`
caps the yielded rows (zero yields none), and a `CancellationToken` is checked
between pages and before each row. Omitted cancellation uses the desktop console
token. Stack-slot, block, and block-instruction iterators follow the same rules.
Cancellation raises `AnalysisCancelled`; native page construction remains
synchronous and may finish before cancellation is observed.

`iter_references(location)` and `iter_incoming_references(location)` provide the
same bounded, cancellable traversal for one xref source or destination. They pin
one workspace capture for the full generator lifetime, so a patch or reanalysis
cannot mix reference generations between pages. The incoming form follows its
native `ReferencePage` cursor and returns only the reference rows.

`capture(expected_revision=None, cancel=None)` returns an independent read-only
`Project` owner for consistent reads across different tables and byte chunks.
It retains the exact immutable state, image mapping, effective patched bytes,
loader-backed names, types, function/CFG facts, references, strings and stack
facts observed at capture time. Later source edits, analysis refreshes, or closing
the source owner do not alter it. Its `snapshot()["readonly"]` is true. It remains
bound to the creating thread and can be closed separately or used with `with`.
The optional revision guard checks the owner's edit revision, reporting conflict
code 8 on mismatch; it does not select a historical analysis generation. Holding
the capture itself pins the precise analysis generation, even when analysis
changes without an edit-revision change.

```python
with project.capture(expected_revision=project.snapshot()["edit_revision"]) as reader:
    for function in reader.iter_functions(max_rows=1000):
        print(function["entry"], reader.presentation(function["entry"])["name"])
        for block in reader.iter_function_blocks(function["entry"]):
            for instruction in reader.iter_block_instructions(block["id"]):
                print(instruction["address"], instruction["text"])
```

Use one explicit capture when passing function or block IDs between related
queries. Independently started live iterators each capture at their first
iteration, so they may represent different generations. Captures share immutable
engine data and copy workspace metadata; they retain those objects and their
owned input storage until released. Partially consumed generators likewise retain
their capture until exhausted or closed. Row limits cap row counts, not nested
type graphs, function chunks, or individual string sizes. Those still obey their
native model/decoder limits. `snapshot()` keeps its existing bounded table
previews rather than becoming an unbounded enumeration.

An explicit single-page query on the live owner still reads that owner's current
snapshot, and consecutive live calls do not pin a generation. C++ clients use
`Project::capture(expected_revision, stop)` and the returned owner's existing
read APIs. Neither capture nor pagination refreshes changes made by another
process. Edits, undo/redo, `analyze`, `save`, and `save_as` are refused on a capture
with read-only code 9. Durable `history` and `preview_history` queries require the
live owner and return unsupported code 4 on a capture: the database command log
is not retained in a workspace snapshot. Existing live history queries instead
use their explicit edit-revision guard. Search and patched-binary export can
operate on captures; a captured stale analysis stays stale and must be refreshed
on the live source before taking a new capture. Archive symbol metadata belongs
to its separate read-only archive owner; member byte reads are not a workspace
capture and do not promise isolation from external changes to that archive file.

`Project.audit_history(after_step=0, max_steps=256,
max_delta_bytes=16*1024*1024, expected_revision=None, cancel=None)` verifies one
bounded durable-history page without changing the project. It returns a
`HistoryAuditPage` with the verified row count, delta bytes, source revisions,
and `next_after_step`/`has_more` continuation state. Audit checks database-defined
metadata, payload extents, and inverse pairing; it does not prove that the
external input file is intact or recover arbitrary corrupt history. Like other
durable history queries, this requires the live owner and is unsupported on a
workspace capture.

`iter_history_audit(page_steps=256, page_bytes=16*1024*1024,
max_pages=4096, total_bytes=512*1024*1024, ...)` yields pages while pinning the
first page's edit revision. Cancellation uses the normal history cancellation
token path. Page limits are at most 4096 entries/128 MiB; the iterator's total
byte budget is an aggregate cap across returned pages. If the iterator stops
with `has_more`, resume from that page's `next_after_step` and
`source_revisions['edit']`. A budget smaller than the next stored delta can
produce a native resource-limit error; raise the budget and retry from the same
cursor.

`read(location, count, cancel=None)` retains its one-MiB per-call bound. Native
reads release the GIL and check the token before and after the storage operation;
the underlying bounded storage read is not interrupted midway. Use a capture
when streaming several related chunks. `open`, `create`, `create_raw`, and
`create_profile` also accept `cancel=None`, release the GIL for native loading,
input import and initial analysis, and pass the token into those operations.
Cancellation raises `AnalysisCancelled`. A canceled creation can leave a valid
initialized project at the requested path if creation had already published;
the API does not silently remove it. `analyze(cancel=...)` remains synchronous,
uses the existing native cancellation path, and does not create a user-history
edit. Captures retain their earlier facts when a live analysis job completes.

`call_graph(address, max_functions=1024, max_edges=16384,
max_instructions=1000000, cancel=None)` walks direct calls reachable from the
function containing `address`. It follows only decoded call instructions and
their indexed call references, returns detached function nodes and source/target
edges, and includes named external calls. Indirect or unresolved calls and calls
whose targets are outside recovered functions are counted and make the graph
incomplete. Reaching a traversal limit returns a partial result with
`truncated_reason` set to the limit name; reaching an unknown call leaves that
field empty but sets `complete` false. Limits are validated before traversal.
Cancellation is checked between block, instruction, and xref pages. The walk
uses one captured workspace, so a source edit or reanalysis cannot mix generations.
The method requires current analysis and never modifies project history.

Native consumers use the corresponding
`automation::Project::call_graph(Address, GraphOptions, stop_token)` operation.
It returns the shared `GraphModel` type with graph nodes, call/reference edges,
omission counts, and a completeness flag; `GraphOptions::call_depth`,
`node_budget`, and `edge_budget` bound the neighborhood. It resolves the
selected function from the supplied address and rejects shared-tail ambiguity
so callers can use `function_owners()` to choose an exact function entry. The
same core graph builder powers the CLI and desktop graph views.

Python also exposes that native graph model directly as
`call_graph_model(address, call_depth=1, node_budget=1000,
edge_budget=10000, cancel=None)`. It returns the native graph JSON schema as a
detached dictionary (including typed node and edge records, `complete`, and
omission counts). The depth range is 1..4, node budget 1..1,000,000, and edge
budget 1..4,000,000. Cancellation is passed into both native graph collection
and serialization. Use this API when the shared native `GraphModel` semantics
are needed; the existing Python `call_graph()` remains an instruction-bounded
reachable-call report with its own result shape and limits.

```python
entry = hexlab.Address(0, 0x401000)
graph = project.call_graph(entry, max_functions=256, max_edges=4096)
print(graph["complete"], len(graph["nodes"]), len(graph["edges"]))
for edge in graph["edges"]:
    print(edge["caller"], edge["source"], edge["target_function"] or edge["target"])

token = hexlab.CancellationToken()
model = project.call_graph_model(entry, call_depth=2, node_budget=512,
                                 edge_budget=4096, cancel=token)
print(model["complete"], model["omitted_nodes"], model["omitted_edges"])
```

`export_analysis_json(path, page_size=4096, cancel=None, progress=None,
include_cfg=False)` is the
headless batch workflow: refresh current analysis, enumerate functions,
instructions, mapped segments, references, and strings, then publish one UTF-8
JSON report. The default schema is versioned by `schema_version: 1` and
`api_version: 1`;
the ordered top-level tables are stable, row-object keys are serialized in sorted
order, instruction bytes use lowercase hexadecimal in `bytes_hex`, and virtual
addresses/file offsets retain explicit typed objects. References include
decoded xrefs, imports, relocations, fixups, and user-authored edges when present.
Rows are fetched and written a page at a time, so the export does not collect all
tables in memory. `page_size` must be from 1 through 4096. All report pages use
one captured workspace taken after refresh. Calling the exporter on an explicit
capture skips refresh and exports only that capture's existing facts.

The report is staged in a temporary sibling file and linked into place only after
successful completion; the destination is exclusive and a failed/canceled run
leaves no partial report. Read-only projects can run analysis and export without
changing user history. `cancel` may be a zero-argument predicate, checked before
analysis and between native page operations, or a thread-safe
`hexlab.CancellationToken`. A token passes its native stop request into analysis,
and the runner releases the GIL while native analysis runs so another Python
thread can call `token.cancel()`. Cancellation raises `hexlab.AnalysisCancelled`.
`progress(stage, completed, total)` receives
`analysis`, `functions`, `instructions`, `segments`, `references`, and `strings`
stage updates; callback exceptions propagate and prevent publication. Setting
`include_cfg=True` opts into schema version 2, which preserves every version-1
table and appends `blocks` and `block_successors`. Each block includes its owning
`function_entry`; each edge includes its `block_id` and owning `function_entry`.
Block IDs are meaningful only within the captured analysis and are not stable
across reanalysis. CFG rows are streamed through bounded pages and report
progress under the `blocks` and `block_successors` stage names. The exporter
checks edit, byte, and decision revisions around page reads and before publication;
an edit during collection raises `ProjectChangedDuringExport` and discards the
temporary report. Cancellation from a plain predicate is cooperative between native
operations; use a cancellation token to interrupt the analysis itself. The return value includes the absolute
output path, schema version, table counts, and encoded byte size. The report
reflects the captured rows and does not lock the project against
edits from another process. Atomic publication requires hard-link support on the
destination filesystem; unsupported filesystems fail without publishing a partial
report.

Locations are explicitly `Address(space, offset)` or `FileOffset(offset)`; bare
integers do not silently choose a domain. `logical(selector, offset)` resolves
only declared profile bindings. Aliases retain distinct logical identities while
patches share canonical input bytes. `create_profile(project, input, profile)`
uses the shared bounded profile reader and persists the complete mapping recipe.
`create_raw(project, input, mode="x86-64", base=0x1000, space=0, entry=None)`
supports flat32/64. `create(project, input, format="auto")` supports image loaders
(`auto`, `pe`, `elf`, `macho`); inspect archives separately with `Archive.open`.
Creation refuses an existing project path. Input is embedded, so source-missing
reopen uses the durable project bytes.

`Archive.open(path)` provides read-only inspection of Unix ar archives. It exposes
archive diagnostics and symbol-index status, pages members and indexed symbols,
and reads regular member data in checked chunks (at most 1 MiB per call). Special
index members remain visible in metadata but cannot be read as object contents.
This API does not extract members or create a project from one.

```python
with hexlab.Archive.open("libsample.a") as archive:
    print(archive.summary())
    for member in archive.iter_members():
        print(member.index, member.name, member.size, member.kind)
        if member.kind == "regular":
            header = archive.read_member(member.index, 0, min(member.size, 64))
```

The native API is `hexlab::automation::Archive`: open it on the consuming
thread, page `members()` and `symbols()`, then call `read_member(index, offset,
count)` to retrieve no more than 1 MiB. The owner retains the archive backing
storage and enforces thread affinity on every query.

Methods:

| Operation | Contract |
|---|---|
| `snapshot()` | Detached metadata, revision/history counters, entries, status/reason, first4096 annotations/bookmarks and their total counts |
| `capture(expected_revision=None, cancel=None)` | Independent read-only owner retaining one exact workspace generation |
| `read(location, count, cancel=None)` | Effective bytes; max1MiB; complete checked range; logical mapping or canonical file coordinates; cancellable before/after native storage reads |
| `functions(start=0, count=256)` | Detached function identity, entry, completion and chunks; max4096 rows |
| `function_at(address)` | Current-analysis lookup for the function entry/chunk containing an address; returns `None` when no function owns it |
| `decompile(address)` | Lift the containing recovered function through SSA, integer simplification, dead-code cleanup, stack-local recovery and structured pseudocode formatting |
| `instructions(start=0, count=256)` | Detached address, bytes, text, mode, numeric `flow` and stable textual `flow_name`, and encoded direct target; max4096 rows |
| `iter_functions(page_size=256)`, `iter_instructions(page_size=256)` | Stream complete function/instruction tables a bounded page at a time |
| `call_graph(address, max_functions=1024, max_edges=16384, max_instructions=1000000, cancel=None)` | Bounded reachable direct-call graph from one captured workspace, with external edges, unresolved-call accounting and cancellation |
| `iter_segments(page_size=256)`, `iter_strings(page_size=256)`, `iter_all_references(page_size=256)` | Stream mapped segments, scanned strings, or all indexed references a bounded page at a time |
| `addresses_for_file_offset(offset)` | Resolve every initialized virtual alias of one source byte; unmapped offsets return an empty list |
| `pe_imports(start=0, count=256)`, `iter_pe_imports(page_size=256)` | Read PE import names/ordinals, thunk/IAT addresses, and delay-load status; non-PE projects return no rows |
| `pe_exports(start=0, count=256)`, `iter_pe_exports(page_size=256)` | Read PE export ordinals, optional mapped names/addresses, and forwarders; non-PE projects return no rows |
| `elf_dynamic_entries(start=0, count=256)`, `iter_elf_dynamic_entries(page_size=256)` | Read ELF dynamic-table entries and optional decoded string values; non-ELF projects return no rows |
| `references(location, start=0, count=256)` | Outgoing source/kind and typed location, external or unresolved target; includes numeric `kind` and stable textual `kind_name`; max4096 rows |
| `incoming_references(location, start=0, count=256)` | Bounded references targeting a typed address or file offset, with total count and next offset for paging; max4096 rows |
| `incoming_references_range(address, size, start=0, count=256)`, `iter_incoming_references_range(address, size, page_size=256, max_rows=None, cancel=None)` | Bounded virtual target-range xrefs and snapshot-pinned streaming; matches target/association addresses inside a nonempty half-open range |
| `outgoing_references_range(address, size, start=0, count=256)`, `iter_outgoing_references_range(address, size, page_size=256, max_rows=None, cancel=None)` | Bounded virtual source-range xrefs and snapshot-pinned streaming; includes all reference kinds in source-address order |
| `all_references(start=0, count=256)` | Page every current reference-index row, including non-instruction sources; max4096 rows |
| `search_bytes(pattern, cursor=None, max_results=256, cancel=None, start=None)` | Paged masked search over effective bytes; optional `start` is a `FileOffset` or mapped `Address`; supports cancellation |
| `search_text(text, encoding="utf8", case_sensitive=True, cursor=None, max_results=256, cancel=None, start=None)` | Paged encoded-text search over effective bytes; optional ASCII-only case folding and typed start location |
| `iter_search_bytes(pattern, page_size=256, max_rows=None, cancel=None, start=None)`, `iter_search_text(text, encoding="utf8", case_sensitive=True, page_size=256, max_rows=None, cancel=None, start=None)`, `iter_search_immediate(value, width=64, signed=False, page_size=256, max_rows=None, cancel=None, start=None)` | Yield byte/text/immediate matches across revision-bound pages; apply start only to the first page |
| `search_immediate(value, width=64, signed=False, cursor=None, max_results=256, cancel=None, start=None)` | Paged immediate-operand search over current decoded facts; optional mapped address start disambiguates aliases |
| `rename`, `comment`, `bookmark`, `patch` | Validated normal commands; optional `group=0`; patch max1MiB and optional `expected_revision` compare against the snapshot's edit revision |
| `define_code`, `define_data`, `define_function`, `suppress_function` | Normal decision validation; instruction boundaries enforced |
| `set_function_chunks(entry, [(Address,size), ...])` | Explicit chunk command, max4096 ranges |
| `set_reference(source, target, kind="data", remove=False)` | Normal user reference command; kinds code/data/call/jump/read/write/address |
| `TypeSpec.*(...)`, `define_type(name, spec)`, `update_type(id, name, spec)`, `assign_type(address, id, remove=False)` | Build validated recursive types, persist/edit definitions and assign them at mapped addresses |
| `Archive.open(path)`, `archive.summary`, `archive.members(...)`, `archive.symbols(...)`, `archive.read_member(index, offset, count)` | Read-only archive metadata and bounded regular-member data; Python also provides page and byte iterators |
| `undo()`, `redo()`, `analyze(...)` | Existing history/reanalysis semantics; analyze accepts bounded budgets, a progress callback, and cancellation; mutations return detached snapshot metadata |
| `save()` | Checkpoint current project; each successful command is already durable |
| `save_as(path)` | Write an independent copy; keep this object bound to its original project |
| `export_binary(path)` | Original input layout plus canonical patches; refuse existing/protected destinations |
| `close()` / context manager | Release this independent project owner |

Byte patches may pass `expected_revision=project.snapshot()["edit_revision"]` to
guard against applying work prepared from an older project snapshot. A mismatch
raises `hexlab.Error` with conflict code 8 before the patch is submitted; SQLite
revision CAS still catches a concurrent writer racing after the check. Omitting
the argument uses this object's current edit revision. `function_at(address)`
requires current derived analysis and returns the recovered function whose entry
or chunk owns that address; otherwise it returns `None`.

Bytes or decisions may invalidate derived facts. After such edits, call
`analyze()` before querying functions/instructions/references; stale queries raise
an error instead of returning older facts. Snapshot status is the native
DerivedStatus ordinal (fresh0, pending1, stale2, incomplete3, file_only4).
Instructions' `target` is the encoding's optional direct address; use references
for loader-linked, far, external and unresolved control targets. No runtime
register/segment state is fabricated. Reference kind and execution mode values
are native enum ordinals and are not string guesses.

`Project.analyze(...)` accepts optional `instruction_budget` (max 50,000,000),
`function_budget` (1,000,000), `block_budget` (10,000,000),
`membership_budget` (100,000,000), `string_budget` (10,000,000),
`string_scan_work_budget` (500,000,000), and `min_string_characters` (64).
Each supplied value must be a positive integer within its documented cap;
omitted values preserve the current configuration. `progress(stage, completed,
total)` receives bounded native function-recovery updates with stages
`instruction-discovery` and `complete`. The callback runs while the native
analysis has released the GIL, so other Python threads can request cancellation.
Return `False` to stop and raise `hexlab.AnalysisCancelled`; return `None` or
another truthy value to continue. If the callback raises, its original exception
propagates and analysis stops. Progress callbacks are call-scoped and are not
retained by the project after `analyze` returns. This brings configurable
function-recovery budgets and progress reporting to Python; custom semantic
decoder injection remains a native C++ API capability.

```python
def report(stage, completed, total):
    print(stage, completed, "/", total)
    return True

project.analyze(instruction_budget=2_000_000, function_budget=200_000,
                progress=report)
```

`incoming_references(target)` exposes the reverse-reference index directly, so
scripts can answer â€œwhat calls or accesses this location?â€ without scanning each
instruction and querying its outgoing edges. It returns a `ReferencePage` with
`references`, total matching row count, and `next`; continue with
`incoming_references(target, start=page.next)` until `next is None`. Results
retain the native reference kind and source location. The query requires current
derived analysis and rejects stale projects.

`incoming_references_range(address, size)` and
`iter_incoming_references_range(address, size)` extend the same query to a
half-open virtual-address range. They match references whose numeric target or
resolved association falls within `[address, address + size)`, including
references to interior bytes of a data object. A row matching both indexes is
returned once, in stable reference-index order. The page API returns the same
`ReferencePage` shape; the iterator pins all pages to one captured generation
and supports bounded page size, an optional row cap, and cancellation. The
range must be nonempty and must not overflow the address space. This mirrors the
native incoming-range query; file-offset and mapped-file range variants are
not exposed by the Python automation API.

`outgoing_references_range(address, size)` and
`iter_outgoing_references_range(address, size)` query sources in that same
half-open virtual range. They preserve reference kind and typed targets,
including external and unresolved records, and page in source-address order.
The iterator keeps one immutable project capture for its lifetime. The native
automation API exposes the same operation as
`Project::outgoing_references_range(Address, size, start, count)`; the query
requires current derived analysis and rejects empty or overflowing ranges.

## Function graph inspection

`function_blocks(address, start=0, count=256)` returns the blocks owned by the
function containing a typed virtual address, including addresses inside a
function chunk. Rows contain `id`, `begin`, `instruction_count`,
`successor_count`, `presentation`, and optional `stop`. The presentation holds
the effective project `name`, `comment`, `user_name`, and `orphaned` flags;
`presentation(location)` provides the same lookup at any typed location.
Names reflect user annotations, loader symbols, and the normal generated-name
fallback. Presentation remains available when derived analysis is stale.

Each block has independently paged `block_instructions(block_id, start=0,
count=256)` and `block_successors(block_id, start=0, count=256)` tables, so a
large block never silently truncates its nested instructions or outgoing edges.
Instruction rows use the same format as `instructions()`. Successors contain
`source`, optional `target`, optional destination `block` identity, and a named
`kind`: `fallthrough`, `conditional_true`, `conditional_false`, `jump`,
`call_continuation`, `unresolved`, or `delay_slot`. A target outside the recovered
graph can have an address without a block; an unresolved target can be `None`.
Terminal blocks can have no successors. Stop evidence contains `address`, the
native reason's symbolic name (for example `ret`, `trap`, `indirect`, or
`budget`), and diagnostic `detail`. It does not turn an incomplete function into
a complete one: inspect `function_at(address)["complete"]` as well.

```python
with hexlab.Project.open("sample.hxproj") as project:
    entry = project.snapshot()["entries"][0]
    print(project.presentation(entry))
    for block in project.iter_function_blocks(entry, page_size=128):
        print(block["begin"], block["presentation"], block["stop"])
        for instruction in project.iter_block_instructions(block["id"]):
            print(instruction["address"], instruction["text"])
        for edge in project.iter_block_successors(block["id"]):
            print(edge["kind"], edge["target"], edge["block"])
```

All three page methods require counts from 1 through 4096. Their matching
`iter_*` methods accept `page_size` in that range. Past-end offsets return an
empty page; an unknown function or block raises `hexlab.Error` with invalid
argument code 2. Function rows now also report `block_count` and `thunk`.
Graph queries require current analysis, obey the project's owner thread, and
reject stale facts after byte or analysis-decision edits. Call `analyze()` and
fetch block identities again after such changes. Block ids are analysis
identities, not durable handles or revision-bound continuation tokens; walking
a graph does not lock it against edits. Returned rows and names/comments are
detached values and retain their observed contents after subsequent commands.
Annotation changes use the same grouped undo/redo and persistence as other edits.

Run `share/hexlab/examples/python/function_graph.py project.hxproj 0 0x1000`
through `hexlab_python` for a read-only graph listing. Native clients use the
matching `Project::function_blocks`, `block_instructions`, `block_successors`,
and `presentation` methods without enabling Python. Focused `automation_graph`
and `automation_python_graph` tests use a real conditional-branch project to
verify block ownership, page boundaries, exact CFG targets, stop evidence,
annotation history, stale/unknown queries, thread ownership, and read-only
reopen; the Python test also executes the installed-layout example source.

## Programmatic decompilation

`Project.decompile(address)` accepts an address at a recovered function entry,
inside one of its blocks, or inside a recovered chunk. It runs the common
typed-IR pipeline on the immutable current analysis snapshot: lift, SSA, constant
and identity simplification, dead-code elimination, stack-local recovery, and
structured formatting. The native C++ `Project::decompile` returns the same
detached result shape as Python's frozen `Decompilation` value:
`entry`, `text`, `complete`, `used_fallback`, `fallback_reason`, and
`diagnostics`. Addresses without a recovered function raise `hexlab.Error`.

The formatter emits structured C-like output when the supported control-flow
shape can be represented; otherwise `used_fallback` and `fallback_reason`
describe the conservative label/goto rendering. `complete` reflects both the
recovered function and the freshness of analysis. This API does not mutate the
project or claim ABI prototypes: inferred types and calling conventions remain
limited by the existing lifter and type-recovery evidence. Re-run `analyze()`
after edits before querying pseudocode.

```python
with hexlab.Project.open("sample.hxproj") as project:
    project.analyze()
    result = project.decompile(hexlab.Address(0, 0x401000))
    print(result.text)
    if result.used_fallback:
        print("Structured formatting fallback:", result.fallback_reason)
```

The `automation_api` C++ and `automation_python` integration tests use a real raw
project to verify entry resolution, detached output, and rejection outside a
recovered function.

`hexlab.Error` derives from RuntimeError and includes `.code` (native ErrorCode
ordinal) and the original diagnostic. Conversion failures use normal Python
TypeError/OverflowError/ValueError. Readonly opens default to true; mutation fails
with ErrorCode read_only9. Invalid page/read limits fail; stale facts/wrong-thread
use fail with conflict8. Script failures print normal tracebacks and return
nonzero. Script arguments, UTF-8 source encoding, Unicode Windows paths and local
module imports are preserved.

## Debugger automation

`hexlab.DebuggerSession.native()` exposes the host native debugger and the
GDB-remote backend through the same session object. Scripts can launch or attach
to a process, connect to a remote target, wait for stop events, inspect threads,
modules, memory regions and registers, read/write bounded memory, and manage
breakpoints. `processes()` returns the backend's bounded process snapshot before
an explicit `attach(pid)`. `terminate()` permanently terminates the selected
target when the backend supports it; `detach()` and context-manager cleanup leave
the target running. A session belongs to its creating thread and can be used as
a context manager.

```python
with hexlab.DebuggerSession.native() as debugger:
    process = debugger.launch("./sample", ["--version"])
    event = debugger.wait_event(timeout_ms=5000)
    print(process, event["kind"], hex(event["address"]))
    print(debugger.threads())
    print(debugger.thread_run_states())
    debugger.resume_threads(event["sequence"], [
        hexlab.ThreadResumeAction(event["thread"], hexlab.ThreadResumeKind.CONTINUE)
    ])
```

Every event must be explicitly acknowledged with `continue_event(sequence)` or
`single_step(sequence)` before waiting for another. Use `interrupt()` to request
a stop while the process runs. `connect_remote(host, port)` selects GDB Remote
Serial Protocol, and the context manager detaches an active target on close.
For a connected extended-remote session, `launch(executable, arguments,
working_directory=..., environment=...)` can start a new remote inferior.
`environment` is an ordered sequence of `(name, value)` changes; use `None` to
unset a target variable and `""` to set it to an empty value. It is bounded to
256 unique changes, 64 KiB total UTF-8 name/value data, 4096 bytes per name,
and 16 KiB per value. Native launch rejects nonempty environment changes.
Feature advertisement, packet-size, reset, working-directory, and acknowledged
exit requirements remain enforced by the GDB RSP client. The CLI currently has
no interactive GDB RSP client surface.

For a server that negotiated multiprocess extended-remote, use `processes()`
to list inferiors, `attach_remote_process(pid)` to select a different listed
inferior, and `detach_remote_process(pid)` to detach a secondary inferior while
keeping the selected one. Selecting another inferior replaces the session's
active process and pending stop event. The worker exposes both operations under
the same names and requires its current stop event to be acknowledged before
switching.
`thread_run_states()` returns an immutable tuple of `ThreadRunState(thread_id,
state)` rows, where state is a `ThreadState` enum with `RUNNING`, `STOPPED`,
`EXITED`, and `UNKNOWN` values.
Thread IDs are scoped to their debugger session. `resume_threads(sequence,
actions)` applies an atomic schedule of `ThreadResumeAction(thread_id, kind)`
records; `kind` is a `ThreadResumeKind` enum with `CONTINUE`, `STEP`, or `STOP`
(`STOP` means keep that thread stopped). The sequence must identify the currently pending stop event, and IDs
must come from this session's current thread observation. Schedules are bounded
to 4096 distinct threads and must continue or step at least one. Stale sequences,
unknown IDs, and backend-unsupported schedules raise `hexlab.Error`; no fallback
to a process-wide resume is performed. State snapshots can contain `unknown`
when the backend cannot safely observe a thread's state.
Memory reads and writes are limited to 1 MiB per call; event waits are limited
to ten minutes. Process launch, attach, remote connection, and event waits release
the CPython GIL while native debugger work runs, so other Python threads can make
progress during startup or a wait. Session operations still belong to the thread
that created the session. The API does not silently resume a target or install
Python-side event callbacks. Backend capability differences are reported as
`hexlab.Error`.

`DebuggerWorker` provides asynchronous, cross-thread control when caller threads
must not own or block on the session. It creates `DebuggerSession` on a private
worker thread, pumps stop events there, and returns detached event dictionaries
through `get_event(timeout=...)`. Operations are submitted by name and return a
`DebuggerJob`; call `job.result(timeout)` to retrieve the result or exception.
`iter_events(poll_interval=0.1, max_events=None, cancel=None)` yields detached
events as they arrive, stops when the worker exits or the optional event cap is
reached, and checks its cancellation token between bounded queue waits. The
poll interval is limited to 10 ms..10 s; cancellation does not discard events
already removed from the queue. `debugger.status` returns a detached
`DebuggerWorkerStatus` snapshot with `ready`, `closing`, `stopped`, and `failed`
lifecycle flags; failure type; active job ID; queued job/input/event counts;
and the pending stop sequence. It is safe to inspect from a controller thread
and never calls into the debug backend. Counters are point-in-time observations
and can change immediately, so use them for orchestration and diagnostics rather
than capacity reservations.
For example:

```python
with hexlab.DebuggerWorker() as debugger:
    process = debugger.submit("launch", "./sample", ["--version"]).result(10)
    event = debugger.get_event(timeout=10)
    print(process["architecture"], event["sequence"], event["kind"])
    print(debugger.status)
    debugger.submit("continue_event", event["sequence"]).result(5)
```

Allowed operation names are `state`, `processes`, `launch`, `attach`,
`connect_remote`, `attach_remote_process`, `detach_remote_process`,
`continue_event`, `single_step`, `interrupt`, `terminate`,
`detach`, `read_memory`, `write_memory`, `evaluate_expression`,
`search_memory`, `threads`, `thread_run_states`, `resume_threads`, `modules`,
`memory_regions`, `registers`, `write_registers`, `breakpoints`,
`add_breakpoint`, `remove_breakpoint`, `enable_breakpoint`,
`set_breakpoint_ignore_count`, `set_breakpoint_condition`, and
`set_breakpoint_logpoint`. Each job snapshots scalar, sequence, mapping, and
byte inputs at submission, with a 16 MiB and 65,536-value limit. The command
queue defaults to 32 jobs and accepts at most 256, with shared 64 MiB and
262,144-value queued-input budgets. The event queue defaults to 128 and accepts
at most 256. If the event queue fills, polling pauses and no stop event is
discarded while the worker remains active. An explicit `close()` can abandon
an event still waiting to enter a full queue as it detaches the target. The
worker records the current event sequence and rejects acknowledgements for any
stale or different sequence; the backend still checks thread ownership and
schedule support.

`job.cancel()` cancels queued jobs or requests cooperative cancellation for a
running `search_memory` job. Other in-flight debugger operations do not accept
cancellation. `close()` requests prompt cancellation of the event pump, cancels
queued work, detaches an active session on its owner thread, and joins for up to
the configured timeout (five seconds by default); it returns `False` if an
in-flight non-cancellable native operation has not returned yet. Retrying
`close()` continues the join. Use the context manager and explicitly drain events;
it does not auto-continue a stopped target. Multiple event consumers share the
queue, so each event is delivered to only one consumer.

`evaluate_expression(thread_id, expression)` evaluates the bounded register and
memory expression language against a stopped thread and returns an unsigned
64-bit result. Expressions are limited to 256 UTF-8 bytes; register names and
available memory reads depend on the selected architecture/backend. This call
does not change target state.

`search_memory(pattern, ...)` searches the backend's current readable memory map
without writing to the target. Patterns use whitespace-separated bytes and
nibble wildcards (for example, `"48 8B ?? A?"`). Optional `ranges` are
`(start, length)` tuples; `writable` and `executable` select matching map
permissions. `alignment`, `chunk_size`, byte/comparison budgets, result and
read-failure limits bound the scan. The defaults are 64 MiB each for requested
bytes and comparisons, a 64 KiB read chunk and 4,096 results. A cancellation
token can stop work between backend reads and comparisons. The returned mapping
includes `completion`, `complete`, `matches`, `failures`, and work counters; a
canceled, capped, or partially failed scan retains its collected rows and names
the completion state instead of presenting the partial result as complete. A
running process can mutate memory during a scan, so results are not an atomic
snapshot. Hard limits are 1 GiB each for bytes and comparisons, 4,096 ranges,
4,096 pattern bytes, a 1 MiB read chunk and 65,536 matches; zero or wrapping
ranges and zero work limits are rejected.

`breakpoints()` returns each runtime record's identifier, address, kind,
enabled state, size, hit count, ignore count, condition, logpoint flag, and
literal log message. `set_breakpoint_ignore_count(id, count)`,
`set_breakpoint_condition(id, expression)`, and
`set_breakpoint_logpoint(id, enabled=True, message="")` configure those rules
for the current session. Ignore thresholds and rule strings persist only when
the desktop saves them to an active project; runtime hit counts reset when a
breakpoint is applied to a new session. Conditions use the bounded register
expression subset documented in `debugger-breakpoint-workflow.md`. Log text is
literal and capped at 1024 UTF-8 bytes; each returned event message is capped
at 4096 bytes, and oversized multi-breakpoint events stop with a diagnostic
instead of being auto-continued.

The focused Python check verifies session creation, idle-state reporting,
rejection of event waits without a running target, and closed-session behavior.
The debugger backend's separate platform and RSP tests cover process lifecycle,
event acknowledgement, memory/register access, and remote protocol behavior.

## Ownership and current limits

Each project and its SQLite store belong to the thread that opened them. Use and
close the project on that thread; do not transfer a live owner to another thread.
Most native calls are synchronous and retain the GIL. Debugger launch, attach,
remote connection, and event waits release it for the duration of those bounded
calls; `DebuggerWorker` supplies the separate asynchronous debugger command and
event queue. Project and archive
owners remain bound to their creating thread. Native C++ operations accept stop
tokens where underlying work supports cancellation. Python scripts are ordinary
trusted programs; there is no sandbox or forced timeout. `hexlab_python` remains
a headless runner; the optional wx console is documented below.

Python receives detached bounded query records. The C++ API additionally exposes
retained immutable ProjectSnapshot values and accepts every ProjectCommand,
including types. The Python API uses detached `TypeSpec` values for named
definitions and address assignments instead of exposing native type graph
pointers. Python returns detached decompilation results rather than mutable IR
objects. Archive metadata and bounded regular-member reads are available in C++
and Python. `Archive.extract_member(index, destination, max_bytes=...,
chunk_size=..., cancel=...)` streams a regular member into a temporary file
beside the destination, then publishes it without replacing an existing path.
A read failure or cancellation removes the temporary file; byte and chunk
limits bound extraction work. Project creation directly from an archive member,
archive writing, and event subscriptions remain unbound.
Large snapshot annotation/bookmark arrays are intentionally truncated to4096;
their explicit total counts disclose that limit. Scripts have no implicit
transaction; each ordinary mutator persists as its own history step.
`apply_annotations()` and `apply_batch()` explicitly group validated commands
into one atomic history step; see [revision-pinned edit batches](python-automation-batches.md).

Focused Windows Debug verification: standalone native API and embedded Python
project tests plus console subprocess contracts pass. Tests use actual temporary
projects and engine DLLs, verifying typed spaces, aliases, readonly source-missing
reopen, immutable observations, commands/chunks/references, grouped undo/redo,
exact patched export, stale fact rejection, Unicode and thread-affinity errors.
The optional-OFF build and parent integrated/full-suite gate are recorded by the
task delivery report; these checks do not claim complete automation coverage.

`Project.import_types` captures the project edit revision before it prepares destination IDs. The native planner rejects a changed revision and attaches exact before-rows to planned replacements, so later layout, origin, or declaration-role edits cannot be overwritten by a stale import. Direct C++ `PortableTypeDefinition` callers can provide `expected_existing` for the same optimistic content check; leaving it empty retains the legacy explicit replacement contract.

## Desktop console

Configure with `-DHEXLAB_ENABLE_PYTHON_AUTOMATION=ON` to add the dockable
`View > Python Console` pane to the wxWidgets desktop. It uses the same
embedded CPython runtime and automation facade as `hexlab_python`. Enter a
multiline Python block and press **Ctrl+Enter** or **Run**. The interpreter
keeps its namespace between submissions, displays a final expression result,
and supports `import hexlab` as in scripts.

When the active tab is a saved project, the console opens a read-only
automation handle on its project file and exposes it as `project`. This is the last saved snapshot; save edits in the desktop to refresh it. The handle
belongs to the console's worker thread. It follows the active saved project
when tabs change, and reopens its read-only handle when the saved project or
derived-analysis generation changes. It becomes `None` when there is no saved
project. Project edits must go through the desktop; the console handle cannot
commit changes.
The console does not attach to unsaved, in-memory binary imports.

Python execution runs away from the wx event thread. The **Cancel** button
raises `KeyboardInterrupt` at Python trace points and requests the active
command's native cancellation token. Calls to `project.analyze()`,
`project.export_analysis_json()`, `project.save()`, `project.save_as()`, and
`project.export_binary()` use that token by default. The checkpoint, copy, and
binary-export bindings release the GIL around native work, allowing other
Python threads to run while SQLite or the image writer is busy. Headless
scripts can also pass `cancel=hexlab.CancellationToken()` explicitly. A
requested native cancellation raises `hexlab.AnalysisCancelled`. Cancellable
`DebuggerSession.wait_event()` calls poll in slices of at most 50 ms. A script
can retain an old token safely, but it only controls the command that created
it. Closing the frame requests both forms of cancellation and joins the worker
before releasing the project handle.

Cancellation is cooperative. Python code that does not reach trace points,
non-cancellable native or filesystem operations, and Python finalizers may
delay cancellation or shutdown until they return. Each input is limited to 1 MiB, pending commands to 32, captured output
to 256 KiB per command, and visible history to 256 Ki characters. Python
remains trusted code with the process's normal filesystem and operating-system
permissions; output and command limits are resource bounds, not a security
sandbox. Scripts that create non-daemon Python threads must stop and join them
themselves before closing the console; CPython finalization can wait indefinitely
for a non-daemon thread that never exits.


## Atomic annotation batch imports

Scripts can apply up to 4096 names, comments, and bookmark edits through one `ProjectSession` batch. The native layer validates each command against the preceding projected state and commits the combined delta as one durable history step; a failure leaves the project unchanged. Pass the edit revision captured while building a manifest so stale work fails with a conflict before commit. `apply_annotations(rows, group=..., expected_revision=..., merge="replace")` accepts dictionaries containing `location` and any of `name`, `comment`, or `bookmark`; `bookmark=None` removes the existing bookmark. Names require virtual addresses, while comments and bookmarks may use virtual addresses or file offsets. `merge="preserve"` fills only empty names/comments and absent bookmarks using a complete snapshot, with a 4096-row ceiling; it leaves a populated value intact, skips clear/removal requests, preserves names already used at another address in the same space, and creates no history step if nothing changes. The batch's combined text is capped at 16 MiB.

`libs/automation/examples/import_annotations.py` imports the versioned JSON envelope, legacy JSON array, or bounded CSV manifest. Before opening the project for editing, it reports all conflicting repeated assignments to the same name, comment, or bookmark at one location, with both manifest row indices. Repeated non-empty names assigned to different virtual addresses in one address space are reported the same way. Any manifest conflict aborts before a project is opened, so the manifest cannot silently overwrite its own earlier values. `--merge replace` (the default) applies manifest values over existing project fields, subject to native batch validation. `--merge preserve` fills only empty name/comment fields and absent bookmarks, and skips attempted replacements/removals while reporting how many fields it skipped. It also preserves a name already used elsewhere in the same address space. Preserve mode uses the bounded project snapshot; it refuses projects with more than 4096 existing annotations or bookmarks rather than making decisions from truncated data. The same helper exports that snapshot as CSV with `--export`, for example:

```text
hexlab_python import_annotations.py project.hxproj labels.csv --export
```

`Project.export_annotations_csv(path)` combines annotations and bookmarks at each location into `location_kind,space,offset,name,comment,bookmark` columns. It writes UTF-8 with hexadecimal offsets and atomically creates the destination only if it does not already exist. The exporter pins a complete snapshot, checks the source edit revision again before publishing, and follows the same 4096-row and 16 MiB bounds as JSON export. Example:

```json
[
  {"location":{"va":{"space":0,"offset":"0x401000"}},"name":"entry","comment":"reviewed","bookmark":"review"},
  {"location":{"file_offset":"0x220"},"comment":"string table"}
]
```

Run it with `hexlab_python import_annotations.py project.hxproj annotations.json --merge preserve` to fill gaps without replacing existing notes. The helper pins the filtered import to the project's current edit revision and saves after a successful one-step import. Invalid commands and replace-mode conflicts are rejected by native batch validation; the batch remains atomic and makes no partial edits. A preserve import with no fields to add exits without creating a history step.

CSV may be selected explicitly with `--format csv` or inferred from a `.csv`
suffix. Its header requires `location_kind,offset`, accepts optional `space`,
and accepts any subset of `name,comment,bookmark`; unknown or duplicate columns
are rejected. A data row uses `location_kind=va` with a `space`, or
`location_kind=file` with `space` blank. Offsets and spaces accept decimal or
base-prefixed unsigned 64-bit integers. Empty annotation cells are omitted, so
CSV imports cannot clear names/comments or remove bookmarks; omit a column to
leave that field untouched. CSV is strict UTF-8 (an optional BOM is accepted),
bounded to 16 MiB and 4096 rows, and feeds the same duplicate-conflict checks,
revision-pinned native validation, and one-step atomic commit as JSON.

For mixed project commands, use `Project.apply_batch()` to combine annotations,
patches, code/data definitions, function/chunk decisions, user references,
type assignments/type updates, and saved breakpoints in one revision-pinned
operation. Its operation tuples, resource limits, and cancellation behavior are
documented in [python-automation-batches.md](python-automation-batches.md).

## Project recovery discovery

`Project.inspect_recovery_directory(directory, cancel=None)` performs the
same read-only, bounded validation used by the project recovery CLI. It returns
`candidates` for complete HexLab `.hexlab-save-*.tmp` and
`.hexlab-previous-*.tmp` artifacts whose project data and retained history
pass validation, plus `issues` with bounded filename/reason diagnostics for
matching artifacts that were rejected. Scan counts include `visited_entries`,
`matching_names`, `rejected_entries`, and `omitted_issues`. Each candidate has
its path, UUID, kind, and edit/byte/decision revisions captured at discovery.
The result includes `complete` and `omitted_candidates`; if either the
8,192-entry or 256-name cap is reached, the returned prefix is explicitly
incomplete. The stricter `discover_recovery_candidates()` call fails with a
resource-limit error instead of silently returning a prefix.
Restore one displayed candidate as a separate project with
`Project.restore_recovery_artifact(artifact, output, replace=False, cancel=None)`.
The operation rescans the containing directory, refuses an incomplete scan,
revalidates the selected file's exact identity and history before publication,
and returns the output path and fresh project UUID. The recovery source remains
unchanged. `replace=True` opts into the database layer's checked replacement
path. The scan and restore do not repair arbitrary damaged databases.

`share/hexlab/examples/python/restore_recovery.py` lists candidates and restores
the one selected with `--index`:

```powershell
hexlab_python share/hexlab/examples/python/restore_recovery.py .\projects .\recovered.hxproj --index 0
```

The example refuses an incomplete scan. It prints candidate kinds, UUIDs and
revision triples before restoring; rerun it with the desired index to select a
different artifact. Cancellation raises `AnalysisCancelled` when requested
during discovery or publication.

Scans examine at most 8,192 directory entries and 256 matching names, retain
at most 64 diagnostics, and verify retained history within a shared budget of
65,536 steps and 512 MiB. Cancellation raises `AnalysisCancelled` when the
provided token is requested during scanning.

## Project backups

`Project.backup_to(path, replace=False, cancel=None)` creates a consistent
project restore point without rebinding the open owner. It refuses to replace
an existing destination unless `replace=True`; the returned dictionary has
`path` and the preserved project `uuid`. `backup_to_rotating(base, retain=5)`
creates a timestamped generation and prunes older generations. Its result
contains the new `backup`, `removed_generations`, and `retention_satisfied`.
`list_rotated_backups(base)` returns `backups` (each with `backup` and
`created_unix_ms`) and a `complete` flag. `prune_rotated_backups(base,
retain=...)` returns `remaining`, `removed`, and `retention_satisfied`.

Backup, listing, and pruning methods accept an optional `CancellationToken`;
the console's active token is used when omitted. A canceled operation raises
`AnalysisCancelled`. To replace a project's database from a backup, close every
owner for the target first, call
`Project.restore_backup_in_place(backup, target, api_version=API_VERSION)`, then
reopen the target so its workspace snapshot reflects the restored database.
Restore preserves the backup project UUID and history.

For projects with an external source file, `archive_external_source(path,
max_bytes=256*1024*1024, cancel=None)` creates a bounded source archive.
`verify_source_archive(path, max_bytes=1024*1024*1024, cancel=None)` checks the
archive against this project's UUID and input identity. Its result reports the
archive path, UUID, input size, and verified byte count.
`restore_source_archive(archive, output, max_bytes=..., cancel=None)` writes
the verified input to a new path without changing project provenance. These
methods accept cancellation tokens; configurable work is capped at 1 GiB.
