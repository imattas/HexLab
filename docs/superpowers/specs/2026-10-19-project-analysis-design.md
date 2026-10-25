# HexLab project persistence and interactive analysis design

## Goal and review status

Implement stage 3 of the approved full application architecture: durable analysis projects, functions and references, control-flow and call graphs, names and comments, user code/data decisions, undo/redo, byte patches, export and incremental reanalysis. Keep the C++20/wxWidgets monorepo, separate tools, shared engine DLLs and original analysis engines. The full destination remains an IDA-class reverse engineering suite; finishing this stage does not finish that goal.

Status: the user approved this specification and gave standing authorization to continue all remaining design and implementation stages without further approval checkpoints. Native execution remains the established preference. Write and self-review the implementation plan, then execute it; preserve test and independent-review gates without asking for repeated permission.

The intended workflow is concrete: import a binary, inspect functions and references, navigate its graph, rename and comment, patch bytes, undo/redo, save a project, close it, reopen it with the same facts and edits, and export a separate patched binary. Multiple open documents keep independent selections, histories, jobs and projects. Loading a file or project never executes an input.

## Existing state and necessary changes

Stage 2 provides stable read-only file mappings, checked raw/PE images, original scalar x86-64 decoding, entry-seeded reachability, string candidates, a CLI and synchronized wx views. Its document revision currently doubles as an open-job generation; those meanings must separate before editing. Analysis reads original storage directly in some paths, so adding patches only to a display buffer would be incorrect. Functions are currently entry/direct-call candidates, not recovered function bodies.

The current desktop owns one controller and one document. Extend that model to multiple sessions and extract command routing from `MainFrame::Impl`; keep the working pane names, native selection fixes, compact layout and floating-pane teardown behavior. Replace enabled-but-unavailable document commands with update-UI state and useful prerequisite text. Preserve all stage 2 checks.

## Storage approaches and selected direction

1. **SQLite project storage, recommended:** use transactions, indexed records and explicit schema migrations, with HexLab-owned models and command semantics. SQLite is ordinary persistence infrastructure under the approved interpretation of from scratch. It does not replace decoding, analysis or graph algorithms.
2. **Original binary journal and snapshot store:** avoids a database dependency but makes atomic recovery, migrations, indices and compaction part of our implementation. That work does not improve reverse engineering capabilities directly.
3. **Embedded key/value storage:** provides transactional records but still requires more application indexing and migration machinery for addresses, references and history.

Select SQLite. The official [application-file guidance](https://www.sqlite.org/whentouse.html), [transaction contract](https://www.sqlite.org/lang_transaction.html), [WAL documentation](https://www.sqlite.org/wal.html) and [atomic-commit description](https://www.sqlite.org/atomiccommit.html) inform this choice. Use a pinned official amalgamation, exact source hash and upstream notices chosen in the implementation plan. Vendor that dependency so subsequent headless builds remain disconnected. Do not add a database server or a network requirement.

Build `hexlab_database.dll` and a separately built SQLite runtime DLL; install their import libraries, required development headers and notices through the existing distribution. Public HexLab headers expose application types and PImpl handles, without SQLite handles. Internal C++ DLLs continue to share the same compiler/runtime; the future native plugin ABI remains separate.

## Component boundaries

| Component | Owns | Dependencies |
| --- | --- | --- |
| core | Checked identifiers, revision values, streaming SHA-256 and canonical scalar encodings | Standard library and platform primitives |
| image | Immutable byte-source interface, original/effective file reads, patch overlays and virtual mapping | core |
| loaders | Parse an effective byte source and record metadata dependencies | core, image |
| processors | Exact instruction facts including modifiers and operand effects | core |
| analysis | Decode dependencies, functions/chunks, blocks, references, invalidation and graph models | core, image, processors |
| database | Project schema, migrations, input chunks, transactions, query paging and history persistence | core, image, analysis models, private SQLite runtime |
| workspace | Project sessions, user commands, async orchestration, document navigation and command availability | Engines above |
| desktop | Document tabs, dialogs, list views and graph canvas | workspace, wxWidgets |
| cli | Project creation, editing, inspection and export using the same commands | workspace |

Keep the dependency graph acyclic: analysis does not issue SQL or depend on the database implementation. Database serialization consumes explicit analysis models. The workspace layer coordinates persistence and analysis. Graph layout remains wx-free; the desktop paints the resulting model. Add focused files as behavior arrives rather than empty directories or stub targets.

## Project format and input ownership

Use `.hxproj` as an original SQLite-based project format with an application identifier, schema version, project UUID, engine-cache versions and explicit input/import recipe. Do not imply IDA database compatibility. A project initially contains one input image; multiple images are opened as independent documents/projects. Future module collections can extend the schema without conflating document ownership.

Projects are self-contained: store original input bytes in chunks of at most 1 MiB, the complete import recipe, byte size and streaming SHA-256 identity. This includes bytes outside mapped segments and raw-loader architecture/mode/base/permissions/entry. Never serialize a C++ object, pointer, filesystem handle or STL container representation directly. Input hashes identify bytes; they are not authenticity signatures.

Creating or opening a project verifies the input stream incrementally with cancellation and bounded memory. A reopened project materializes its embedded original into an application-owned temporary backing file, verifies its size/hash, and opens the existing stable read-only mapping. The backing file lives until the last image/view/job lease is released; closing a window cannot delete backing still used by another snapshot. Extraction is disk-backed and never duplicates the entire input in a vector. Cancellation removes only temporary files owned by that operation. This design trades extra disk space and extraction time for self-contained projects and mapped analysis reads; measure both before making performance claims.

The original external path is provenance, not a requirement for reopening. Preserve its native encoding with an explicit platform/encoding tag and a project-relative alternative where possible. Relinking an external original or exporting against an external source requires matching size and SHA-256; equal names/timestamps are insufficient. Detect partial, missing, duplicate, oversized and out-of-order input chunks before publishing a loaded session.

Use unsigned 64-bit addresses/file offsets end to end. Encode unsigned offsets as fixed eight-byte big-endian blobs in SQLite, indexed together with the address-space ID, rather than truncating into signed SQL integers. Domain IDs have explicit checked ranges. Every persisted location records whether it is an address or a file offset; an overlay location never gains a fabricated virtual address.

## Transactions, saving and recovery

Use one serialized project writer running outside the GUI thread. Each command transaction atomically updates the authoritative user state, history cursor, revision counters and invalidation markers. Only publish an accepted snapshot after commit succeeds. A failed write, busy timeout, cancellation before commit or disk error preserves the preceding committed state. Analysis jobs submit proposals; they never write project state directly.

Use local-file WAL mode with foreign keys and full synchronous durability settings. Configure a two-second busy timeout and cancellation for long SQL operations. The application must check actual SQLite return codes and active journal mode. WAL/shm companion files are normal live database state; raw file copying is not Save As. Use SQLite's backup operation into a temporary destination followed by checked publication of a complete destination. Save As gets a new project UUID and leaves the source project untouched. Read-only opens perform no schema migration, checkpoint or derived-record update; SQLite's normal WAL coordination and temporary input materialization are distinct from modifying project data. If recovery requires unavailable write permissions, return a clear diagnostic instead of bypassing the journal.

An imported binary begins as an untitled session with the same command/history semantics. Save Project first persists that session and embeds the input. Thereafter accepted edits are transactionally saved; File > Save flushes outstanding commands and requests a checkpoint, and status distinguishes unsaved, saving, saved and failed. A first save uses a temporary destination in the target directory and publishes it only when complete. Existing targets require an explicit replace action; cancellation cannot overwrite them.

Persist schema versions and migrate transactionally. A failed migration rolls back without advancing the version; newer schemas open with an unsupported-version diagnostic and no mutation. Validate the application identifier and expected table/record shapes. Bound counts, blobs, text and decoded cache payloads before allocation. Disable loadable SQLite extensions and do not execute SQL taken from project fields. Use prepared statements for all user data.

Keep one editable owner per project UUID in the application; opening it again activates that document. A platform lease identifies another editable process and offers read-only viewing. SQLite transactions and compare-and-swap revision checks remain the integrity mechanism if aliases or processes bypass that advisory lease. Read-only sessions expose inspection/export queries and disable mutating commands. Crash recovery must retain every fully committed command and none of an incomplete transaction; test process termination at transaction checkpoints rather than assuming WAL configuration proves this.

## Revision and snapshot model

Separate these identities:

- A document/session ID and epoch prevent completion delivery into a closed or replaced session.
- A monotonically increasing edit revision changes after every accepted command, including undo and redo.
- A byte revision changes when effective bytes change.
- A configuration/decision revision changes when mode, code/data or function decisions change.
- A derived analysis key records input identity, byte/decision revisions, loader recipe and engine-cache versions.

Snapshots are immutable and share unchanged byte overlays, analysis facts and annotation collections. Renaming a symbol does not copy a million decoded instructions. Worker proposals carry session epoch and all source keys they read. The serialized owner rejects stale proposals atomically; an analysis completion may never restore an earlier annotation set. Closing cancels jobs, invalidates the epoch and releases the writer after queued operations reach a defined terminal state. No worker captures a window.

Cache instructions, typed operands/modifiers, stop reasons, functions, chunks, blocks, references and string records with their derivation keys and provenance. Validate caches on load. Incompatible engine-cache versions trigger recomputation while preserving input and user decisions. Distinguish fresh, pending, stale and incomplete derived facts in both tools. Never show old graph edges or instruction text as current after a byte edit.

## Effective bytes and patches

Introduce a byte-source interface beneath loaders and images. Read-only file storage remains a concrete implementation. All consumers must read the selected immutable effective source, including instruction fetch, string scanning, metadata parsing, bytes views, hashing of exports and file-offset access. Audit direct `storage()->read_at` paths so a patched display cannot coexist with analysis of original bytes.

Store patches canonically by original file offset, with checked original bytes, effective replacement bytes and provenance. Edits are same-length; insertion/deletion and rebuilding executable structures are later capabilities. A patch may use a mapped virtual address only when every selected byte has a definite file backing; zero fill and gaps have no exportable original bytes. File-offset edits can cover overlays and headers. Overlapping edits normalize to one effective value per offset; reverting to the original removes the overlay entry while history remains undoable. A file offset shared by multiple virtual mappings changes all aliases.

Preserve original file bytes permanently. Export streams the embedded original plus the selected overlay to a separate temporary output and atomically publishes the completed file. Reject destinations that alias the original input, live project, its backing or runtime working files, including equivalent paths/file identities. Explicit replacement of a different existing output is a normal user command. Failure leaves the existing destination unchanged. Copy permissions only where meaningful; do not claim to rebuild PE checksums or cryptographic signatures. Report that existing signatures may no longer validate after a patch.

Record file ranges read by the loader. Patches intersecting loader metadata invalidate that metadata and, where applicable, the mapping. Reparse the effective source. If edited headers no longer form a valid image, retain the project and patches in a clearly labeled file-only state: file offsets/bytes and undo/export remain available; virtual navigation, function analysis and graphs are disabled until a valid mapping returns. This is not automatic raw-format loading. Address annotations whose mappings disappear remain stored and visibly orphaned; never silently relocate them.

## Function discovery and block models

Seed analysis from executable entries, mapped code exports, direct call targets and explicit user-defined functions/code. Record seed kind and source revision. PE unwind information and broader format/ISA metadata remain subsequent work; their current absence must stay explicit. An arbitrary branch target is a block leader, not automatically a new function.

Build basic blocks from exact decoded instruction starts, branch targets, entry seeds and continuation leaders. Terminators are return, trap, direct/indirect jump, conditional branch and explicit analysis stops. Calls record call edges and their possible continuation without absorbing the callee into the caller. Unknown instructions, ambiguous overlaps, unmapped targets, manual data boundaries and unresolved indirect flow terminate the applicable path with a reason. Do not invent an instruction size to continue analysis.

A function owns an entry and a set of noncontiguous chunks/blocks, not the entire numeric range to the next symbol. Shared tails have explicit multiple ownership. Jumps into another established function entry can be represented as tail-call candidates with evidence; unresolved ownership remains labeled. Conflicting decode streams or entries inside existing instruction extents produce a conflict record and incomplete analysis, not silent overwrite. Keep stable IDs for unchanged facts.

User commands can define code/data, define a function at a valid instruction boundary, adjust explicit function chunks and suppress an automatic function entry. Validate ranges and instruction boundaries atomically. Explicit code may override a loader's non-executable permission when the bytes are initialized and the CPU mode is supported; that user decision is recorded. Defining data prevents automatic traversal through that range. Suppression persists across reanalysis and is undoable. Invalid or unsupported decisions return actionable errors without partial edits.

The Functions pane displays recovered functions with entry/name, chunk count and completeness/provenance. Keep unresolved candidates separate. Function selection and graph/listing selection use the same document navigation service and history.

## References and graph navigation

Store incoming/outgoing references with source instruction, operand index, target address or external identity, reference kind, access kind and provenance. Cover direct call/jump/conditional edges, concrete RIP/EIP-relative and absolute memory addresses, LEA address uses, explicit user references and import-slot associations. Unknown register-dependent expressions remain unresolved; integer immediates do not become proven pointers merely because their values fall inside an image. Read/write/address and code-flow references remain distinguishable.

Import-slot calls can identify a named imported symbol without pretending to know the external runtime address. Reference lists are paged and indexed by typed source/target locations. A selection or double-click navigates to the appropriate source/target, and status explains unresolved or external destinations. Renaming updates presentation through symbol IDs without rewriting decode facts.

Add wx-free control-flow and image call-graph models with deterministic IDs. An original layout algorithm condenses cycles for placement, layers the resulting components, places nodes deterministically and routes edges with explicit ports. Preserve self-loops, parallel conditional edges, shared chunks and unresolved/external stubs. Never draw a guessed target as a resolved node.

The graph canvas supports pan, zoom, fit, block selection, follow edge, back/forward and cross-navigation to listing and references. Selected blocks show actual instructions and names/comments. Layout runs off the GUI thread and is cancellable/revision-tagged. Node/edge budgets produce an explicit partial view and boundary stubs with omitted counts; users can raise limits. Painting culls offscreen nodes rather than formatting the complete image on each repaint. Large-graph performance remains measured evidence, not an assumed property.

## Commands, annotations and undo/redo

Define typed application commands in workspace services; desktop and CLI use the same validation and transaction path. This stage includes rename/clear name, set/clear comment, bookmarks, define code/data/function/chunks, suppress function, explicit reference edits and byte patches. Commands expose availability and a prerequisite reason so menus do not silently do nothing on the welcome screen, read-only projects, stale graphs or invalid locations.

Include bounded byte-pattern, literal-text and immediate-value search, as required by the existing stage-3 capability inventory. Byte patterns use hexadecimal octets and `??` wildcards; text search selects explicit ASCII, UTF-8 or UTF-16LE encoding. Search the effective input, carry matches across read chunks and retain the canonical file offset for every match. Attach a virtual address only when the entire match maps contiguously and uniquely; aliases and virtual gaps cannot manufacture an address range. Immediate search queries decoded operands, not arbitrary integer-looking bytes: the user selects 8/16/32/64-bit width and signed or unsigned input interpretation; validate the entered value in that range, then match normalized bits only against operands with the same effective width. Thus a sign-extended -1 at width 64 is distinct from an 8-bit 0xFF operand. Results are paged with a configurable budget and cancellation; Find Next/Previous and result selection use normal document history. GUI and CLI call the same search service.

Locations remain typed. Address names are scoped to an image/address space; file-offset comments/bookmarks support overlays. User names are printable UTF-8 of at most 512 bytes without NUL/newline. Explicit names must be unique in their address space with case-sensitive comparison; a conflicting rename fails atomically and reports the existing location. Comments are UTF-8 of at most 1 MiB with multiline support and no embedded NUL. Empty values clear an annotation. Names/comments are presented as text, never as formatting markup or executable expressions. User overrides take precedence over automatic symbols; clearing an override restores the automatic presentation. Automatically generated labels use deterministic disambiguation rather than displacing a user name.

Each successful user command stores versioned forward/inverse data and its grouping ID in the same transaction as the state change. Large patch history uses chunked payloads instead of one unbounded allocation. Undo and redo are new monotonic revisions and persist across reopen. A new edit after undo removes that redo branch atomically. Failed commands, analysis cache refreshes, navigation and UI layout changes do not enter the user undo stack. Multi-byte patches and a grouped annotation operation undo as one user action. Validate inverse preconditions; a conflict cannot partially undo a command.

## Incremental analysis and job scheduling

Record dependencies for instruction byte extents, function/block membership, reference derivation, metadata reads and string scan ranges. After a patch or definition change, invalidate the intersecting facts and their dependent closure. Re-decode affected functions/blocks, remove stale outgoing references, discover newly introduced targets and update affected callers/ownership as needed. Preserve unrelated annotations and unchanged decoded fact identities. Name/comment changes update presentation without re-decoding bytes.

String invalidation accounts for runs crossing a patch or chunk boundary, UTF-16 alignment/surrogates and changed terminators; a fixed small neighborhood is not sufficient for an arbitrarily long run. Extend rescans to established boundaries or explicitly invalidate the affected scan range. Loader/mode/engine changes may require a full rebuild, reported with the reason. Conservative fallback is permitted when the dependency closure cannot be proven narrower, but the ordinary local-code-patch fixture must demonstrate real incremental reuse.

Use a bounded shared analysis pool, initially two workers, with per-document cancellation and replaceable pending work. A project writer is separate from those workers. Foreground open/navigation work has priority over speculative analysis. Cap queues and result retention; never accumulate one full snapshot for every canceled edit. No detached threads. Close/cancel tests must prove completion rejection and worker ownership without relying on arbitrary sleeps.

## Desktop and CLI workflows

Add document tabs above the existing Disassembly/Bytes/Graph views. Each tab owns a session, project identity, selection/history, analysis state and undo stack. The docked functions, references, symbols, metadata and Output panes project the active document. Switching tabs must not deliver another document's selection or completion. Closing a tab cancels its work; closing the frame joins/releases every owned service before child-window destruction. AUI layout remains a window concern, not a project transaction.

Add Open Project, Save Project, Save As, Rename, Comment, Bookmark, Define Code/Data/Function, Function Chunks, References, Patch Bytes, Export Patched Binary, Undo and Redo. Dialogs show the active target and validate through shared services. Bytes and listing text indicate modified data and stale/incomplete analysis. Graph and reference panes expose real facts only. Preserve usable keyboard routes and inspect normal and compact layouts without claiming an unperformed accessibility/high-DPI audit.

Add Find/Find Next/Find Previous and a result pane for the shared byte/text/immediate search commands. Search state belongs to its document; switching tabs cannot apply another document's query or result selection.

Extend the CLI with `project create`, `project inspect`, `project rename`, `project comment`, `project define`, `project patch`, `project undo`, `project redo` and `project export`, plus functions/references/graph queries. A read-only project inspect must not mutate caches or take the editable lease. Define graph export as versioned JSON and DOT generated from the actual graph model, with correct escaping. This is an early shared command surface, not the later complete scripting SDK. Keep legacy inspect/disassemble behavior and documented exit codes; distinguish stale/incomplete results and conflicts in diagnostics.

## Verification and acceptance

Use original raw/PE fixtures and self-authored source corpora. Tests must prove effects through independent stored bytes, literal expected addresses and reopened application state, not only serialization round trips of self-generated expectations.

1. Persist/reopen empty, ordinary and multichunk inputs; original bytes and hashes match, raw recipes survive, and projects reopen after the external original is moved or absent.
2. Verify SHA-256 against independent published vectors and a toolchain/platform oracle; cover incremental boundaries and cancellation. Verify unsigned addresses above `INT64_MAX`, typed locations, Unicode paths and embedded NUL rejection in text.
3. Reject wrong application IDs, truncated/corrupt projects, newer schema versions, invalid counts/chunks/cache payloads and hash mismatches without mutating the source project.
4. Kill a test helper before, during and after transaction commit and first-save publication. Reopen and verify exactly the committed state, history cursor and input ownership. Failed migration/Save As/export preserves original files and destinations.
5. Exercise readonly projects, a second editable process, busy/readonly/disk-write errors, revision conflicts and cancellation. SQL failures never acknowledge an unsaved edit as committed.
6. Pin function chunks and block boundaries for loops, diamonds, direct calls, tail candidates, shared tails, unreachable embedded data, manual exclusions, overlapping decode conflicts, missing returns and unresolved indirect jumps.
7. Pin incoming/outgoing call, branch, read, write and address references; import-slot associations are distinct from external runtime targets. Large immediates remain nonreferences without evidence.
8. Check graph topology separately from rendering: cycles, self-loops, parallel edges, external stubs, deterministic layout, cancellation and explicit node/edge budget boundaries. Test graph JSON/DOT escaping with hostile labels.
9. Rename/comment/bookmark/code-data/function/reference edits survive save/reopen; automatic reanalysis preserves them. Undo/redo survives reopen, groups changes, branches correctly after undo and leaves state intact on failed preconditions.
10. Patch a direct branch, an instruction length, a string terminator, aliased bytes, metadata and a header. Every effective-byte consumer agrees. Reject exportable VA patches into zero fill/gaps; support file overlays. Invalid headers enter file-only state and undo restores mapping.
11. A local code patch demonstrably reuses an unrelated function's decode facts while updating the affected CFG, callers and reference index. Name/comment edits perform no decode. Metadata/mode changes report full invalidation when required.
12. Stream export and compare every byte with a separately built expected output; original input/project remain unchanged. Check equivalent-path/file-identity destinations and existing-output failure handling.
13. Open two documents, edit/analyze both, switch tabs, navigate references/graphs, undo only one, close one while its work runs and keep the other responsive. Deliver out-of-order results deterministically to verify epoch/revision rejection.
14. In real wx tests, create/save/reopen a project, select a function/block/reference, rename/comment, patch/undo/redo/export and verify listing/bytes/graph synchronization and clipboard selection. Retain existing floating-pane/reset/close regressions and verify disabled commands with no document.
15. Run all existing and new Debug desktop and Release headless checks. Prove a fresh disconnected headless build with vendored SQLite and no wx acquisition. Install into a fresh stage-3 directory and verify GUI/CLI/database/SQLite dependencies, notices, project workflows and actual rendered normal/compact views.
16. Verify exact/masked byte matches and encoded literal text across chunk/segment/overlay boundaries, signed and unsigned immediate queries, effective patches, result paging/budgets, cancellation and independent per-document search state. Results must navigate to the actual matching location.

Update the capability inventory by verified variant; do not promote functions, references, recovery or incremental analysis based on a compiling interface. Record independent review findings and regression fixes. Stage acceptance requires the complete import/edit/save/reopen/navigate/patch/export workflow through shared services in both tools, plus crash/revision/lifecycle evidence.

## Boundaries and full-goal continuity

This stage does not claim complete function recovery for unresolved code, dynamic targets or unsupported instruction families. Type/ABI services, PE unwind/debug information, ELF/Mach-O, broader processors, semantic IR/decompilation, live debugging, full automation/plugin SDK and platform delivery remain required later stages. Input bytes, provenance, cache versions, command records and graph identities are designed to support those stages without pretending they exist now.

The current repository remains on the existing unborn `feat/foundation` branch with Git identity unset. Preserve all current source and evidence; do not invent identity, push, merge or discard files. This design can be reviewed as a local file before any implementation begins.
