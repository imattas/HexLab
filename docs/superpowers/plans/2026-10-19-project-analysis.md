# HexLab Project and Interactive Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans task by task. Native execution is the preserved preference; one independent whole-stage review follows implementation. The user approved the specification and explicitly removed future approval checkpoints. Do not stop between design, plan, implementation or verification to request approval.

**Goal:** Deliver self-contained transactional projects and the complete shared import/edit/analyze/navigate/save/reopen/patch/export workflow, including functions, references, graphs, search and isolated documents.

**Architecture:** Immutable byte sources and overlays feed the same loaders/analysis in both frontends. SQL persists input, user state/history and versioned derived facts; one project actor serializes writes and rejects stale analysis proposals. A bounded shared pool performs analysis/layout/search while wx views consume immutable projections.

**Tech Stack:** Existing C++20/CMake/MSVC x64/wxWidgets DLL build; original hashing/analysis/layout/command services; vendored SQLite 3.54.1 as a separate runtime DLL. Existing test harness and MASM fixtures remain; no new test framework.

**Spec:** [Approved project-analysis specification](../specs/2026-10-19-project-analysis-design.md), under the approved full application architecture. This stage is not full-goal completion.

## Global Constraints

- Preserve original input bytes, public typed addresses/file offsets and all existing decoder/loader/GUI regressions. Loading never executes an input.
- Input chunks are at most 1 MiB; names at most 512 UTF-8 bytes; comments at most 1 MiB. No embedded NUL in annotations. Names are case-sensitive and unique within an address space.
- SQLite uses WAL, foreign keys, full synchronous settings and a two-second busy timeout; check actual results. Read-only queries do not migrate, checkpoint or update derived records.
- Unsigned offsets use exactly eight big-endian bytes in SQL. Schema/application/cache identifiers are validated before allocation or publication.
- One writer per project actor; session epochs, edit/byte/decision revisions and engine keys are separate. Two shared analysis workers initially; bounded queues/results; no detached threads or worker window access.
- Same-length patches only; zero fill/gaps have no exportable file backing. Header edits may enter explicit file-only state, retaining undo/export. Never silently reinterpret a broken PE as raw.
- Stream hash/import/export with cancellation and bounded buffers. Save As uses SQLite backup; publication uses a temporary same-directory destination, with explicit replacement policy and file-identity checks.
- Use the existing unborn `feat/foundation` workspace. Git identity is unset: preserve source, do not invent identity or discard work. Commit steps apply only when an existing identity becomes available; record verification in this plan's ledger meanwhile.
- Native execution and standing authorization supersede skill approval/handoff prompts. Keep substantive specifications/plans/tests/reviews; no new approval questions.

## Review Focus

1. A project must reopen after its external input disappears; every cache view/job must retain its temporary mapped backing until its last lease ends. Task 7 tests deletion/reopen and delayed view release.
2. Patches must affect loader, decoder, strings, searches and export consistently, including aliases/header corruption. Tasks 2-3, 12-13 and 20 check the full path.
3. A late analysis/save completion must not overwrite a newer annotation or another document. Tasks 6, 14 and 17 deliver deterministic reversed completions.
4. Failed SQL, interrupted saves and output aliasing must preserve committed state and existing files. Tasks 4, 6-7 and 12 use fault seams/process termination, not sleep-based guesses.
5. New names/comments, graph labels and pattern inputs can contain hostile Unicode/text and large counts. Tasks 5, 10-11 and 15 test bounds/escaping before GUI integration.

## Files and dependency map

Extend `libs/core` with SHA-256 and canonical encodings/locations; `libs/image` with byte storage, read sets, immutable patches and owned backing leases; `libs/loaders` with explicit recipes/effective loading. Add `third_party/sqlite` and `libs/database` with separate connection/schema/input/state/history/cache/backup files. Extend `libs/analysis` with decisions, function/block models, references, graphs, invalidation and search. Add focused workspace project/command/pool/session services. Split desktop commands/document tabs/graph canvas from the existing frame; split CLI project parsing from legacy commands. Tests remain focused per component and actual workflow.

Ruling: the database may depend on loader recipe value types in addition to analysis models. That adds an acyclic database-to-loaders edge and avoids duplicating raw/PE import options in the persistence schema. Analysis still never depends on SQL. Cost if wrong: recipe serialization can later move to a neutral model header.

## Task 1: Hashing and canonical identity primitives

**Files:** `libs/core/include/hexlab/core/{sha256,encoding,location}.hpp`, `libs/core/src/{sha256,encoding}.cpp`, core/test CMake, `tests/identity_tests.cpp`, workspace `navigation.hpp`.

**Interfaces:** `Sha256Digest = std::array<std::byte,32>`; exported `Sha256::update(span<const byte>) -> Result<uint64_t>` returns total bytes, `digest() const noexcept -> Sha256Digest`, `bytes() const noexcept -> uint64_t`; `digest_hex(const Sha256Digest&) -> string`; `encode_u64(uint64_t) noexcept -> array<byte,8>`; `decode_u64(span<const byte>) -> Result<uint64_t>`. Move the existing `Location = variant<Address,FileOffset>` to core, retaining workspace inclusion compatibility.

- [ ] Write `identity` tests first: empty/abc/multiblock/million-a SHA-256 vectors, split every boundary around 55/56/63/64/65 bytes, binary 00..FF, repeatable nonmutating digest and updates after taking a digest. Pin unsigned encoding of 0, `0x8000000000000000` and `UINT64_MAX`; reject lengths other than eight. Compare a generated file hash with Windows `Get-FileHash` in a CMake integration check.
- [ ] Build/run red: `cmake --build --preset windows-headless`; expect missing identity interfaces. Implement original SHA-256 compression/padding with checked bit-length limits and canonical endian helpers; preserve state on overflow.
- [ ] Run `ctest --preset windows-headless --output-on-failure`; expect identity and every previous test green. Record evidence; commit if configured.

## Task 2: Byte storage, immutable overlays and read dependencies

**Files:** image `byte_storage.hpp`, `patches.hpp`, `read_set.hpp`, `src/{byte_storage,patches,read_set}.cpp`; existing file storage/image files; `tests/overlay_tests.cpp`.

**Interfaces:** abstract exported `ByteStorage::size() const noexcept`, `read_at(FileOffset,size_t) const -> Result<ByteView>` and virtual destructor. `ByteView` owns `shared_ptr<const void> owner` plus byte span so concrete storage or an owned cross-chunk buffer can retain bytes. `FileStorage` implements ByteStorage. `Image::create/storage` consume/return shared const ByteStorage. `PatchSpan {FileOffset begin; vector<byte> original,replacement;}`; `PatchSet` is immutable, canonical and nonoverlapping. `make_overlay(shared_ptr<const ByteStorage>,span<const PatchSpan>) -> Result<shared_ptr<const ByteStorage>>`; `hash_source(const ByteStorage&,stop_token) -> Result<Sha256Digest>`. `ReadSet` normalizes checked file ranges; `TrackingStorage` delegates bytes and records actual reads.

- [ ] Add red tests for untouched original bytes, adjacent/overlapping edits, original-byte mismatch, revert, aliases, empty reads, overflow, zero-copy lifetime, cross-span buffers after source destruction and canceled chunked hashing. Validate normalized dependency union/intersection with endpoint cases.
- [ ] Implement storage polymorphism and overlay reads without copying whole inputs. Keep raw FileStorage mapping behavior. Run all headless tests; expect green, including old mapping lifetime/zero-fill cases. Commit/ledger.

## Task 3: Effective loader recipes and shared import path

**Files:** loaders `recipe.hpp`, `src/recipe.cpp`; raw/PE/detection internals; analysis instruction/string reads; workspace document/listing paths; `tests/effective_input_tests.cpp`.

**Interfaces:** `LoadRecipe {Format format; optional<RawOptions> raw;}` with automatic resolution only at initial import; `encode_recipe(const LoadRecipe&) -> Result<vector<byte>>`, `decode_recipe(span<const byte>) -> Result<LoadRecipe>` use versioned canonical fields. `load_image(shared_ptr<const ByteStorage>,const LoadRecipe&,stop_token) -> Result<LoadedImage>`; LoadedImage gains normalized metadata ReadSet. Existing path-based OpenRequest remains a frontend convenience.

- [ ] Red fixtures patch code, a string, an import and a PE header; assert decoding/strings/metadata/effective bytes agree while original file remains unchanged. Round-trip literal recipe fixtures, reject unknown enum/version/trailing bytes; pin raw uint64 bases and empty input.
- [ ] Generalize every direct storage consumer to ByteStorage. Track metadata reads separately from later analysis reads. An invalid effective header returns a loader error; retain file-only handling for the workspace task rather than fabricating an Image.
- [ ] Build and run headless plus original desktop regression suites; expect all green. Audit `rg 'storage\(\).*read_at|FileStorage' libs` for remaining original-only bypasses; account for legitimate file-opening boundaries. Commit/ledger.

## Task 4: Pinned SQLite runtime and checked connection layer

**Files:** `third_party/sqlite/{sqlite3.c,sqlite3.h,sqlite3ext.h,NOTICE,provenance.json}`, `cmake/SQLite.cmake`, `libs/database/{CMakeLists.txt,include/hexlab/database/connection.hpp,src/connection.cpp}`, root/libs CMake, `tests/sqlite_tests.cpp`.

**Pin:** official `https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip`, SHA3-256 `92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30`, independently calculated SHA-256 `0a9c8e34352dad46006aa82836d5383bff9dc6bc9ce5a60553c05aa30e6ad1f9`. Archive already downloaded to `out` and matched the publisher hash during planning. Vendor only required amalgamation headers/source and upstream dedication, unchanged; record source/date/hashes. Build `hexlab_sqlite3` SHARED with SQLite C exports, thread safety, load extensions omitted, no configure-time network.

**Interfaces:** database-private checked `Connection`, `Statement`, `Transaction` RAII; exported `database_build_info() -> DatabaseBuildInfo` reports actual version/runtime settings. Append conflict/read_only/busy/integrity ErrorCode values without changing old ordinals. All SQL parameters use bound values; cancellation/progress and 2000 ms timeout are explicit.

- [ ] Write red tests for installed runtime/version, UTF-16 Windows paths, prepared text/blob values, rollback after failure, busy/read-only/cancellation and actual WAL/foreign-key/full-synchronous settings. Fault seam is private to the database tests, not an environment-variable behavior in the application.
- [ ] Implement/build the two DLL targets and test connection wrapper; verify version is exactly 3.54.1, extension loading unavailable and no wx imports. Full headless suite green; commit/ledger.

## Task 5: Project schema and bounded canonical records

**Files:** database `project_state.hpp`, `schema.hpp`, `codec.hpp`, `src/{schema,codec,project_state}.cpp`; analysis `decisions.hpp`; `tests/project_schema_tests.cpp`.

**Interfaces:** `ProjectUuid` is 16 bytes; `ProjectRevisions {uint64_t edit,bytes,decisions;}`; `InputIdentity {uint64_t size; Sha256Digest sha256;}`. `UserState` stores typed annotations/bookmarks, code/data regions, function/chunk decisions, explicit references and immutable patches. `AnalysisKey` contains byte/decision revisions plus recipe/engine fingerprints. `ProjectState` retains UUID, recipe, identity, revisions and shared immutable user state. `ProjectStore::create/open(path,mode,stop)` returns a store; `snapshot() -> Result<shared_ptr<const ProjectState>>`. Application ID `0x48584C42`, schema version 1; a tested v0 fixture supplies the first transactional migration.

- [ ] Red tests independently inspect SQL scalars/blobs: eight-byte high unsigned addresses, location tags, 16-byte UUID, SHA size, UTF-8/name/comment bounds, duplicate names, unknown IDs/versions, malformed vectors and rollback of interrupted migration. Never deserialize C++ memory layouts.
- [ ] Implement normalized schema and bounded versioned field codecs. User-state entities have stable checked IDs, unique keys and foreign keys; input chunks/history/derived caches have separate tables. Validate schema identity before reading records. Newer/invalid projects never mutate.
- [ ] Run schema and full headless suite; expect green. Commit/ledger.

## Task 6: Atomic state deltas and persistent undo/redo

**Files:** database `transaction.hpp`, `history.hpp`, `src/{transaction,history}.cpp`; `tests/project_history_tests.cpp`, `tests/project_crash_helper.cpp`, `tests/project_crash_tests.cmake`.

**Interfaces:** `StateDelta` contains typed changes with expected previous values; `CommitAck {ProjectRevisions revisions; uint64_t history_cursor;}`. `ProjectStore::commit(expected_edit,const StateDelta&,group_id,stop) -> Result<CommitAck>`, `undo(expected_edit,stop)`, `redo(expected_edit,stop)`. Persist inverse/forward deltas and cursor in the same transaction; revisions are monotonically increasing even on undo/redo.

- [ ] Red tests rename/comment/patch groups, failed inverse preconditions, stale CAS, redo truncation after a new edit, reopen history, immutable preceding snapshots and read-only errors. A helper signals exact transaction checkpoints over a pipe; terminate before/during/after commit and verify literal expected durable state on reopen.
- [ ] Implement writer-serialized delta application and reversible bounded/chunked payloads. Inject commit/write/migration errors through a test-only connection seam; no acknowledged change before SQL commit. Analysis/navigation updates are excluded from undo.
- [ ] Run history/crash tests and full suite; expect committed states only and zero partial edits. Commit/ledger.

## Task 7: Embedded inputs, leases, save and backup

**Files:** database `input.hpp`, `backup.hpp`, `src/{input,backup,lease_win}.cpp`; image owned-backing lease support; `tests/project_input_tests.cpp`, crash helper additions.

**Interfaces:** `ProjectStore::import_input(const ByteStorage&,const LoadRecipe&,NativePath,stop)`, `materialize_input(stop) -> Result<shared_ptr<const ByteStorage>>`, `save_as(path,ReplacePolicy,stop)`. `ReplacePolicy {fail_if_exists,replace_existing}`. `ProjectLease` owns editable project UUID/process scope; duplicate project opens can report readonly. A unique temporary-file owner is retained by FileStorage until native mapping/handles close before cleanup.

- [ ] Red tests empty/multichunk input, original removed after close, Unicode native provenance, missing/duplicate/out-of-order/oversized chunks, corrupted hash, temporary-file lifetime after document close, canceled extraction, readonly input reopening and duplicate-process lease. Verify size/hash independently from embedded SQL chunks.
- [ ] Implement <=1 MiB import/extraction buffers and original SHA validation; persist recipe/path encodings. Use SQLite backup into a same-directory temporary destination; Save As changes UUID. File-identity aliases, canceled first save and interrupted publication preserve existing destinations.
- [ ] Run input/crash tests, verify complete reopen without external original and explicit readonly behavior. Commit/ledger.

## Task 8: Functions, chunks, blocks and provenance

**Files:** analysis `functions.hpp`, `dependencies.hpp`, `src/{functions,blocks,dependencies}.cpp`; `tests/function_tests.cpp`.

**Interfaces:** `FunctionId`, `BlockId` stable checked IDs; `FunctionRecord {id,entry,chunks,blocks,seeds,complete}`, `BasicBlock {id,begin,instructions,successors,stop}` and `FunctionSnapshot {functions,blocks,conflicts,dependencies,complete}`. `recover_functions(const Image&,const ImageMetadata&,const AnalysisDecisions&,const AnalysisOptions&,stop) -> Result<shared_ptr<const FunctionSnapshot>>` consumes original decoder facts, not formatted assembly.

- [ ] Red literal fixtures pin call-vs-branch seeds, loop/diamond leaders, shared/noncontiguous tails, tail-call candidates, overlaps inside instructions, suppressed entries, explicit data, forced initialized non-executable code, unsupported/truncated paths and cancellation/budgets.
- [ ] Implement original graph walk/partition with explicit ownership/conflicts; do not guess function ends from the next symbol. Record exact read/ownership dependencies and keep unknown flow explicit. Functions share immutable instruction facts where unchanged.
- [ ] Run function and full suites; expect literal graph/chunk identities and no fabricated reachability. Commit/ledger.

## Task 9: Typed reference indexes

**Files:** analysis `references.hpp`, `src/references.cpp`; `tests/reference_tests.cpp`; database cache codec additions.

**Interfaces:** `Reference {id,source,operand_index,target_or_external,kind,access,provenance}`; `ReferenceIndex::incoming/outgoing(Location,PageRequest) -> ReferencePage`; `derive_references(const FunctionSnapshot&,const ImageMetadata&,const AnalysisDecisions&,stop) -> Result<shared_ptr<const ReferenceIndex>>`.

- [ ] Red tests pin direct flow, LEA/read/write/read-write memory operands, FS/GS unresolved memory, imported IAT associations, unresolved expressions, user references, repeated targets and paged counts. Large immediates are not automatically pointers; ignored LEA segment bases retain the corrected decoder behavior.
- [ ] Implement deterministic indexed references and versioned bounded serialization. Persist/restore cache with engine/input keys; incompatible/corrupt caches are discarded with a recompute reason, never user-state loss.
- [ ] Run reference/cache and full suites; expect exact incoming/outgoing edges. Commit/ledger.

## Task 10: Graph models, deterministic layout and export

**Files:** analysis `graph.hpp`, `src/{graph,graph_layout,graph_export}.cpp`; `tests/graph_tests.cpp`.

**Interfaces:** `GraphKind {function_cfg,image_calls}`, `GraphModel {nodes,edges,complete,omitted_counts,key}`, `GraphLayout {positions,routes,bounds,key}`; `build_graph(...)`, `layout_graph(const GraphModel&,GraphOptions,stop)` return checked results; `export_graph_json/dot(const GraphModel&) -> Result<string>`.

- [ ] Red tests self-loops, SCC cycles, parallel conditional edges, shared chunks, imports and unresolved stubs; repeated layout identical, finite coordinates, explicit budget boundaries and canceled layout. Hostile quote/newline/Unicode labels produce parseable JSON and escaped DOT.
- [ ] Implement original SCC condensation/layering/stable ordering/edge ports; cap graph nodes/edges explicitly and keep boundary stubs. Layout is wx-free and version-tagged. No external graph/analysis engine.
- [ ] Run graph and full suites; inspect a generated original-fixture graph artifact. Commit/ledger.

## Task 11: Shared validated application commands

**Files:** workspace `commands.hpp`, `project.hpp`, `src/{commands,command_validation,project}.cpp`; `tests/project_command_tests.cpp`.

**Interfaces:** `ProjectCommand = variant<Rename,Comment,Bookmark,DefineRegion,DefineFunction,SetFunctionChunks,SuppressFunction,SetReference,PatchBytes>`; `CommandAvailability {bool enabled;string reason;}`; `validate_command(const ProjectSnapshot&,const ProjectCommand&) -> Result<StateDelta>`. `ProjectSnapshot` retains ProjectState, effective bytes, optional loaded image/metadata, derived facts and explicit fresh/pending/stale/incomplete/file-only state. `ProjectSession::execute/undo/redo` delegates serialized commits, not GUI edits.

- [ ] Red tests name conflicts/limits, multiline comments and clearing overrides, automatic-label fallback, orphaned annotations, code/data boundaries, chunk overlap rules, suppressed entries and grouped patches. Failed commands leave SQL/history/revisions unchanged; missing/read-only/stale prerequisites expose reasons.
- [ ] Implement typed validation and immutable projections. Header parse failure retains file-only bytes/undo/export and disables address/function/graph actions. Annotation-only edits share existing decode snapshot pointers.
- [ ] Run commands and full suites; expect actual reopened edits via store APIs. Commit/ledger.

## Task 12: Checked streaming patch export

**Files:** workspace `export.hpp`, `src/export.cpp`; image file-identity/publication helpers; `tests/patch_export_tests.cpp`.

**Interfaces:** `export_patched(const ProjectSnapshot&,path,ReplacePolicy,stop) -> Result<ExportReceipt>`; receipt records byte count/digest/revision and signature/checksum caveat. Exports stream the original plus overlay, not a mutable original path.

- [ ] Red independent expected-file comparisons cover overlays, aliases, multichunk edits, empty files, original-byte reverts, canceled writes, zero-fill/gap VA rejection and output aliases (equivalent path/hardlink/project/backing). Existing destination survives failures.
- [ ] Implement same-directory temporary output and checked atomic publication using explicit replace policy, with owned cleanup and file-identity checks. Do not rebuild PE signatures/checksums silently.
- [ ] Run export/full suites and independently hash outputs. Commit/ledger.

## Task 13: Dependency-directed incremental reanalysis

**Files:** analysis `incremental.hpp`, `src/incremental.cpp`; workspace project orchestration; `tests/incremental_tests.cpp`.

**Interfaces:** `InvalidationPlan {byte_ranges,functions,reference_sources,string_ranges,metadata_invalid,full_reason}`; `plan_invalidation(old_snapshot,StateDelta)`; `reanalyze(old_snapshot,effective_source,plan,key,stop) -> Result<DerivedProposal>`. Proposal carries exactly its source key; stable unaffected facts are shared.

- [ ] Red tests patch branch target/length and shared tails, discover new callees/remove old xrefs, preserve an unrelated function pointer/ID, avoid decode on annotation edits, rescan long strings across changed terminators/UTF-16 boundaries and reject stale metadata. Header/mode/engine changes explicitly justify full invalidation.
- [ ] Implement closure-based invalidation and reference removal/rebuild; metadata reads select reparse. Conservative fallback records its reason but cannot replace actual reuse in the ordinary two-function fixture.
- [ ] Run incremental/full suites and inspect counters/fact identity rather than runtime-only timing assertions. Commit/ledger.

## Task 14: Serialized actors and bounded shared job pool

**Files:** workspace `project_actor.hpp`, `analysis_pool.hpp`, `src/{project_actor,analysis_pool}.cpp`; `tests/project_jobs_tests.cpp`.

**Interfaces:** actor async commands/open/save return operation IDs and typed completions; immutable `SessionKey {document,epoch}` plus analysis key gates all commits/publications. A two-worker `AnalysisPool` queues keyed tasks with stop tokens; each document retains at most one replaceable pending task and latest unread completion. GUI polls immutable completions; CLI can await them.

- [ ] Red deterministic barriers reverse patch/rename/save/analysis completions, close/reopen a project with the same path, cancel while queued/running, saturate queues and destroy while jobs hold input leases. Another document's task cannot consume a completion.
- [ ] Implement no worker-window captures and no joins under a mutex needed by workers. Project connection/writes live on the actor thread; pool workers only read snapshots and produce proposals. Handle terminal errors explicitly.
- [ ] Run job/full suites with finite test deadlines; expect no leaked workers/leases and current annotations retained. Commit/ledger.

## Task 15: Effective byte/text/immediate search

**Files:** analysis `search.hpp`, `src/search.cpp`; workspace search state; `tests/search_tests.cpp`.

**Interfaces:** `SearchQuery = variant<BytePattern,TextQuery,ImmediateQuery>`; `SearchCursor`, `SearchPage` with canonical file offsets, optional valid contiguous mappings and continuation token/key. `search(const ProjectSnapshot&,query,cursor,limits,stop)` returns a bounded page. Octets/`??`, explicit ASCII/UTF-8/UTF-16LE and exact effective-width immediate normalization follow the spec.

- [ ] Red fixtures cover chunk-spanning/overlapping matches, all-wildcard budget, invalid patterns/encodings, Unicode/surrogates, virtual gaps/aliases, patched bytes and -1 width 64 versus FF width 8. Continuation cannot skip/duplicate matches or continue against another revision.
- [ ] Implement bounded streaming search and typed operand search. Find Next/Previous uses per-document history/query state; no whole-input formatting/copies.
- [ ] Run search/full suites; expect literal locations and correct canceled/incomplete status. Commit/ledger.

## Task 16: Project CLI through the shared services

**Files:** CLI `project_commands.hpp/cpp`, legacy command routing; `tests/project_cli_tests.cmake`, fixture generator additions.

**Interfaces:** `project create/inspect/rename/comment/bookmark/define/reference/patch/undo/redo/export/functions/references/graph/search` parse Unicode paths and route ProjectSession/actor operations. Explicit width/location/replace/readonly options are documented. Legacy inspect/disassemble remains compatible.

- [ ] Write red process tests for create/edit/save/reopen/undo/redo/export/search/graph. Inspect raw SQL/output bytes independently and check readonly queries preserve database logical state, annotation escaping, missing sources, conflicts and unsupported caches. Keep exit 0/1/2/3 semantics, adding explicit diagnostics for conflicts.
- [ ] Implement argument and output handling in focused files. Emit functions/references/graphs from typed models with stale/partial labels, never inferred display text.
- [ ] Run CLI and full Debug/Release headless suites; expect original tests preserved and both tools' model facts agree. Commit/ledger.

## Task 17: Multiple isolated desktop sessions

**Files:** desktop `session_controller.hpp/cpp`, `document_tabs.hpp/cpp`, frame/controller refactor; workspace document manager; `tests/desktop_project_tests.cpp`.

**Interfaces:** `DocumentManager` maps document IDs/project UUIDs to sessions; active projection/selection/history is explicit. `SessionController` owns UI polling and actor handles, not the writer connection. Existing MainFrame OpenDocument/Navigate test-facing normal APIs remain routed to the active document.

- [ ] Red wx tests open two projects, switch active tabs, navigate/close one, deliver late completions, activate duplicate UUID and show readonly external ownership. Assert pane data and selection belong to the current tab; every worker joins before windows disappear.
- [ ] Implement outer document tabs above listing/bytes/graph; retain AUI pane names, compact mode and original smoke tests. No parsing/SQL in event handlers. Preserve unsaved/saving/saved/error states.
- [ ] Run full desktop suite with genuine state assertions; commit/ledger.

## Task 18: Desktop project commands, annotations and search

**Files:** desktop `project_actions.hpp/cpp`, `edit_dialogs.hpp/cpp`, `search_view.hpp/cpp`, listing/bytes metadata adapters; desktop project tests.

**Interfaces:** command routing uses shared `CommandAvailability` and ProjectCommand, including actual menu update-UI reasons. Dialogs submit to actor and publish only committed results. Per-document search results and navigation are retained.

- [ ] Red event-loop tests create/save/reopen, rename/comment/bookmark, code/data/function decisions, patch/undo/redo/export, search/page/find next/previous and clipboard selected rows. Check invalid/read-only/no-document actions are disabled and failed edits preserve old text/bytes.
- [ ] Implement dialogs/tool actions and projections; show patch/stale/incomplete/orphaned state. Keep SQL/decoding off GUI handlers and do not expose internal operation IDs in product flows.
- [ ] Run desktop/full suites; capture actual normal and compact rendered workflows. Commit/ledger.

## Task 19: Interactive graph and reference views

**Files:** desktop `graph_canvas.hpp/cpp`, `reference_view.hpp/cpp`, function view adapters; desktop project tests.

**Interfaces:** graph canvas consumes GraphModel/Layout snapshots plus current selection; emits typed Navigate/follow/reference commands. Pan/zoom/fit/select operate on model coordinates; async layouts are epoch/revision checked. Function/call graph choice is per document.

- [ ] Red GUI tests select a nonfirst block/edge/call/reference and assert listing/bytes/history synchronization, rename reflow, patched CFG refresh, stale-layout rejection, partial graph labels and offscreen culling. No hit test may use another graph revision's coordinates.
- [ ] Implement original wx canvas rendering with selected block instruction/name/comment text and unresolved stubs; bounded virtual reference lists. Retain metadata/listing selection guarantees.
- [ ] Run desktop suite and inspect generated/captured graphs against literal expected topology. Commit/ledger.

## Task 20: Installed workflows, recovery evidence and final review

**Files:** install tests/rules, docs/project-analysis-validation.md, capability/reference inventory, build docs and this plan ledger.

- [ ] Run complete Debug desktop and Release headless suites; fresh `project-analysis-offline` build must have vendored SQLite and no wx `_deps`. Verify all sixteen spec acceptance classes have actual named checks/results.
- [ ] Install into fresh `out/install/ProjectAnalysisDebug`; require database/SQLite/other engine DLLs, import libs, headers, schema docs/notices. Check dumpbin: engines free of wx, GUI/CLI share services, no system SQLite dependency. Run installed create/edit/reopen/navigation/graph/patch/export and crash helper checks; capture/inspect actual installed GUI.
- [ ] Perform one fresh independent read-only whole-stage review as required by Native execution. Re-grade by practical impact; fix material findings with failing regressions and whole-suite green. Record any deferred minors and unverified platforms/performance honestly.
- [ ] Update states only from evidence, preserve source/ledger if commits remain unavailable and leave the full goal active. Continue subsequent approved-architecture stages under standing authorization; do not request another approval checkpoint.

## Self-review and execution handoff

Spec coverage: byte identity/storage tasks 1-3/7/12; transactions/recovery 4-7; facts/graphs/references 8-10; user commands/history 6/11; incremental jobs 13-14; search 15; CLI 16; isolated desktop/edit/graph 17-19; acceptance/install/review 20. All five Review Focus cases map to explicit red tests above. File-only patch state, readonly ownership, input independence, persistent undo and unsigned SQL encoding have dedicated owners. Types/decompiler/debugger/SDK/platform expansion remain full-goal work after this stage.

The user has removed further approval checkpoints. Begin Native execution immediately after plan self-review, with a per-task ledger and genuine failing tests before implementation.
