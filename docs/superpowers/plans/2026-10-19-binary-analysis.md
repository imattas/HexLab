# HexLab Binary Analysis Implementation Plan

Status: user approved this plan; tasks 1-11 executed Native. The independent review's two material findings were fixed with regression tests. [Validation](../../binary-analysis-validation.md) records passing checks and the deferred minor. The checklists below preserve the original execution instructions; the plan ledger records completion evidence. Full application development continues beyond this stage.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Native execution is the preserved user preference.

**Goal:** Open raw and PE images, decode and analyze x86-64 code using original engines, and inspect real results in the CLI and synchronized desktop views.

**Architecture:** Add shared image, loader, processor, analysis and workspace libraries to the existing monorepo. Both applications consume the same immutable document snapshots; parsing and decoding stay outside wxWidgets. GUI background jobs publish through revision-checked main-thread state transitions.

**Tech Stack:** Existing C++20/CMake build, MSVC Windows x64, wxWidgets 3.2.12 DLLs, Windows read-only file mappings, standard-library threads/stop tokens, CTest. No new third-party production engine or test framework.

**Spec:** [Approved binary-analysis specification](../specs/2026-10-19-binary-analysis-design.md), under [the approved full application architecture](../specs/2026-10-19-hexlab-design.md).

## Global Constraints

- “Preserve C++20, wxWidgets, separate GUI/CLI tools, shared engine DLLs and the user's monorepo requirement.”
- “No engine library depends on wxWidgets.”
- “Input bytes remain immutable; patch overlays are a later required stage.”
- “Never allocate `SizeOfImage` merely because a header requests it.”
- “Do not silently fall back from a failed PE parse to raw analysis.”
- “Do not guess an unknown instruction length or continue proven code flow across an instruction whose extent is unknown.”
- “Failures leave the prior document and navigation unchanged.”
- “Paths are passed as data, never shell commands.”
- Preserve all four foundation desktop tests/checks and headless builds without wx dependency acquisition.
- Internal DLL consumers use the same compiler/runtime. This stage does not claim a stable external plugin ABI.
- Windows is the verified delivery host for this stage; other host backends remain required future work, explicitly unverified.
- Git author identity is currently unavailable. Continue preserving source and ledger evidence; never fabricate identity or mark a skipped commit as created.

## Review Focus

- A file modified or truncated while being analyzed must not turn borrowed spans into unsafe memory; task 1 verifies the Windows sharing contract and view lifetime.
- A valid RVA and the same integer used as a file offset must resolve differently; task 3 fixtures force this distinction.
- Unsupported instruction encodings must not manufacture a one-byte instruction or reachable fallthrough; tasks 5–6 pin status and analysis termination.
- A file open that fails or completes after cancellation/replacement must not erase the previous document; task 7 exercises ticket ordering and document identity.
- Closing a frame during analysis and resetting recently closed floating panes must preserve lifetime safety; task 10 retains the original regression and checks worker shutdown.

## Shared Vocabulary and Execution Rules

Use namespace `hexlab` and the existing `Result<T>`, `Error`, `Address`, `FileOffset` and checked arithmetic contracts. Extend `ErrorCode` with `io`, `unsupported`, `malformed`, `canceled`, and `resource_limit` without changing existing enum values. Error messages include enough file/field/address context to identify the failed operation.

Public library headers use generated `HEXLAB_<COMPONENT>_EXPORT` declarations on out-of-line functions. Avoid exporting STL-bearing classes wholesale; follow the core reader's per-method exports or a private implementation. Every new shared target installs its runtime, import library and public/generated headers like `hexlab_core`.

CTest component names are `image`, `loaders`, `processors`, `analysis`, `workspace`, and `cli_binary`; GUI integration adds `desktop_binary_smoke`. Existing `core`, `cli`, `desktop_smoke`, and `desktop_floating_smoke` remain. Each component test binary uses named checks active in Release. Factor the current tiny runner into `tests/support/checks.hpp` when the second test binary needs it, preserving existing checks.

For every task, first write its named behavioral tests with literal expectations, run them and record the expected missing-implementation failure, then implement and run the full available headless suite. Commands are `cmake --preset windows-headless`, `cmake --build --preset windows-headless`, and `ctest --preset windows-headless --output-on-failure`. Expected final output is exit 0 and `100% tests passed`, never merely a successful configure. Build and run desktop tests at the GUI tasks and final verification. Commit after a green task if identity becomes available; otherwise ledger the task and skipped commit.

## File Map

| Component | Public headers | Source and tests |
| --- | --- | --- |
| Image | `libs/image/include/hexlab/image/{file_storage,image,metadata}.hpp` | `libs/image/src/{file_storage_win,image}.cpp`, `tests/image_tests.cpp` |
| Loaders | `libs/loaders/include/hexlab/loaders/{loader,raw,pe}.hpp` | `libs/loaders/src/{detect,raw,pe_headers,pe_imports,pe_exports,pe_relocations}.cpp`, `tests/loader_tests.cpp` |
| Processors | `libs/processors/include/hexlab/processors/{instruction,decoder,format}.hpp` | `libs/processors/src/{x64_prefixes,x64_operands,x64_decode,format}.cpp`, `tests/processor_tests.cpp` |
| Analysis | `libs/analysis/include/hexlab/analysis/{analysis,strings}.hpp` | `libs/analysis/src/{reachable,strings}.cpp`, `tests/analysis_tests.cpp` |
| Workspace | `libs/workspace/include/hexlab/workspace/{document,workspace,navigation}.hpp` | `libs/workspace/src/{document,workspace,navigation}.cpp`, `tests/workspace_tests.cpp` |
| CLI | `apps/cli/{main,commands}.cpp`, `apps/cli/commands.hpp` | `tests/cli_binary_tests.cmake` |
| Desktop | `apps/desktop/{document_controller,listing_view,bytes_view,metadata_views,raw_dialog,jump_dialog}.{hpp,cpp}` | Extend `main_frame` and `app`; `tests/desktop_binary_smoke.cmake` |
| Fixtures | `tests/support/{fixture_files,pe_fixture,code_fixture}.hpp` | `tests/fixture_generator.cpp`, generated files under build-tree `fixtures/` |
| Build and evidence | Per-library `CMakeLists.txt`, `libs/CMakeLists.txt`, app and test CMake files | Extend install tests, capability inventory and building docs; create `docs/binary-analysis-validation.md` and `docs/x64-coverage.csv` |

Create each path when its task supplies working content; brace groups above denote separate files, not literal filenames. Private x64 parse state and table declarations belong in `libs/processors/src/x64_internal.hpp`. Private checked PE readers belong in `libs/loaders/src/pe_internal.hpp`.

## Task 1 Stable Storage and Checked Image Mappings

**Files:** Image component above, core `result.hpp`, library/test CMake, test support runner and `tests/image_tests.cpp`.

**Consumes:** Existing checked address/reader APIs.

**Produces:**

- `struct ByteView { std::shared_ptr<const FileStorage> owner; std::span<const std::byte> bytes; };`.
- `class FileStorage` with exported destructor, `static Result<std::shared_ptr<const FileStorage>> open(const std::filesystem::path&)`, `std::uint64_t size() const noexcept`, and `Result<ByteView> read_at(FileOffset, std::size_t) const`. Hide native handles behind a private implementation; copying the storage object is disabled.
- `struct Rva { std::uint32_t value; };`, `enum class Architecture { unknown, x86, x86_64, arm, arm64 };`, `enum class ExecutionMode { unknown, x86_16, x86_32, x86_64 };`.
- `struct AddressSpace { AddressSpaceId id; std::uint8_t width_bits; std::uint8_t unit_bytes; ByteOrder order; };` and `struct Segment { std::string name; Address begin; std::uint64_t size; FileOffset file_begin; std::uint64_t file_size; bool readable, writable, executable; };`.
- `struct ImageLayout { AddressSpace space; Architecture architecture; ExecutionMode mode; std::vector<Segment> segments; std::vector<Address> entries; };`.
- `class Image` with `static Result<std::shared_ptr<const Image>> create(std::shared_ptr<const FileStorage>, ImageLayout)`, const layout/storage accessors, `Result<std::vector<std::byte>> read(Address, std::size_t) const`, `Result<FileOffset> to_file_offset(Address) const`, and `Result<Address> to_address(FileOffset) const`. Borrowing is limited to `FileStorage`; composed virtual reads return bounded owned bytes.

- [ ] Write actual temp-file fixtures for empty input and bytes `11 22 33 44`. Assert empty zero read succeeds; reading offset 4/count 1 fails; offset UINT64_MAX/count 2 fails; retaining a `ByteView` keeps bytes alive after releasing the caller's storage pointer. Attempt write/truncate access with a second Windows handle while storage is open: it must fail sharing access, then succeed after the final view is released. Directories and absent paths produce `io` diagnostics.
- [ ] Write mapping cases with segment VA `0x1000`, file offset 1, file length 2, virtual size 4. Expect virtual bytes `22 33 00 00`; reverse mapping `0x1001 → 2`; zero-fill VA `0x1002` has no file offset; another address space and a gap fail. Add overflow, overlapping virtual ownership, out-of-file backing and adjacent-segment read cases with literal byte arrays. An aliased file offset returns an ambiguity diagnostic rather than arbitrary reverse mapping.
- [ ] Run the image test target before implementation; expect missing image/storage symbols, not an unrelated compiler/SDK failure.
- [ ] Implement the Windows backend with `CreateFileW`, read-only sharing, `CreateFileMappingW`, `MapViewOfFile`, RAII and checked representability. Skip native mapping for an empty file. Reject an unsupported host backend explicitly rather than claim it is verified. Return bounded diagnostics for mapping failures. Implement layout validation and read composition without image-sized allocation.
- [ ] Run `image` and the whole headless suite; require all checks green. Add/install the first new DLL and its headers. Record task evidence.

## Task 2 Raw Images and Format Detection

**Files:** Loader API/raw/detection files, loader CMake, `tests/loader_tests.cpp`, `tests/support/fixture_files.hpp`.

**Consumes:** Task 1 storage, image and architecture types.

**Produces:** `enum class Format { automatic, raw, pe };`, `enum class DetectedFormat { unknown, pe_candidate };`, `Result<DetectedFormat> detect_format(const FileStorage&)`; `struct RawOptions { Architecture architecture; ExecutionMode mode; Address base; bool readable, writable, executable; std::optional<Address> entry; };`; `Result<std::shared_ptr<const Image>> load_raw(std::shared_ptr<const FileStorage>, const RawOptions&, std::stop_token)`.

- [ ] Assert raw `{90 C3}` at VA `0x4000` maps exactly, has explicit x86-64 mode, and accepts entry `0x4000`; entry `0x4002`, mismatched space, base overflow and missing/unsupported mode fail with context. Empty raw input is inspectable and has no entry. Cancellation before/during work returns `canceled`.
- [ ] Test detection of ordinary bytes, one-byte `M`, two-byte `MZ`, and a complete `MZ`/PE fixture. A recognizable truncated candidate must reach the PE parser and fail there, never become an implicit raw success. Detection must preserve storage I/O errors through its `Result<DetectedFormat>` return type.
- [ ] Observe RED, implement raw/detection behavior, then run loader plus full headless tests. Publish `hexlab_loaders` with the task 1 packaging conventions.

## Task 3 PE Headers and Virtual Layout

**Files:** `pe.hpp`, `pe_headers.cpp`, `pe_internal.hpp`, `metadata.hpp`, PE fixture builder and loader tests.

**Consumes:** Checked storage/image construction, `Rva`, format detection.

**Produces:** Image metadata records shared across engines: `ImportSymbol` (library, optional name/ordinal, thunk/IAT addresses), `ExportSymbol` (ordinal, optional name/address/forwarder), `Relocation` (type and address), `Directory` (index, numeric location, size and file-offset flag), `Diagnostic` (severity/message/optional location), and `ImageMetadata` (format, machine, subsystem, preferred base, sections, directories, imports, exports, relocations). Define records in the image metadata header, without loader dependencies.

`struct LoadedImage { std::shared_ptr<const Image> image; ImageMetadata metadata; std::vector<Diagnostic> diagnostics; bool metadata_complete; };` and `Result<LoadedImage> load_pe(std::shared_ptr<const FileStorage>, std::stop_token)`.

- [ ] Build original PE32/PE32+ fixture writers with explicit little-endian integer writes at specified file offsets; tests must never use the production parser to compute expected layout. The baseline PE32+ fixture has image base `0x140000000`, `.text` RVA `0x1000`, file position `0x200`, entry RVA `0x1000`, initialized bytes `90 C3`, and a larger zero-filled section tail. Assert entry VA `0x140001000`, file mapping `0x200`, and distinguish file offset `0x1000` from RVA `0x1000`.
- [ ] Add required-header rejection cases: truncated DOS/COFF/optional/section headers, huge `e_lfanew`, absent PE signature, optional-magic/machine mismatch, overflowing image-base+RVA, impossible header/section ranges, virtual overlaps and an entry into a gap. Add raw-size larger than virtual-size padding and virtual-size larger than raw-size zero-fill fixtures. PE32 x86 loads metadata but retains x86 mode and does not request x86-64 analysis.
- [ ] Observe RED. Implement explicit offset reads through checked helpers, map validated headers separately, map section extent `max(VirtualSize, SizeOfRawData)` within declared image bounds, and retain original section declarations. Record all available directory headers; index 4 uses file offsets. Do not allocate a buffer of `SizeOfImage`.
- [ ] Run all loader/core/image tests and the full suite. A minimally parsed PE must have `metadata_complete=false` until the next task supplies the supported optional metadata traversals and statuses.

## Task 4 PE Imports Exports and Relocations

**Files:** `pe_imports.cpp`, `pe_exports.cpp`, `pe_relocations.cpp`, shared PE helpers, metadata records/tests/fixtures.

**Consumes:** Task 3 mapped PE image, directory descriptions and shared metadata records.

**Produces:** `Result<std::size_t> read_imports(const Image&, const Directory&, bool pe64, ImageMetadata&, std::stop_token)`, `Result<std::size_t> read_exports(const Image&, const Directory&, ImageMetadata&, std::stop_token)`, and `Result<std::size_t> read_relocations(const Image&, const Directory&, ImageMetadata&, std::stop_token)`. Return the parsed record count or a diagnostic error; the top-level loader converts optional-metadata errors into warnings and incomplete status. Parsing into temporary vectors prevents corrupt partial records escaping as valid entries.

- [ ] Fixture expectations include one imported name `FixtureFn` from `fixture.dll`, ordinal import 7, PE32 versus PE32+ thunk widths, exported name `entry`, ordinal-only export and forwarded string `other.Target`. Assert exact IAT/thunk/address mappings. Include a base-relocation block with one DIR64 entry at `.text+0x10` and ABSOLUTE padding; retain records without mutating bytes.
- [ ] Add missing/unterminated import descriptor, invalid name RVA, missing name terminator, oversized export counts, forwarder range failure, export ordinal-index overflow, relocation block shorter than its header, odd relocation block payload, cycle/repeated-table reference, and certificate file-offset cases. All traversals are bounded by validated mapped ranges and observe cancellation. Required headers remain hard failures; optional-directory failures preserve a usable image with warnings and `metadata_complete=false`.
- [ ] Observe RED, implement each traversal, then run the whole headless suite. Mark only supported directory contents implemented; unparsed delay/resource/TLS/debug/exception content remains recorded and explicitly unsupported in inventory.

## Task 5 Original x86-64 Decode and Formatting

**Files:** Processor headers/sources/private parse state, processor CMake, `tests/processor_tests.cpp`, `tests/support/code_fixture.hpp`, `docs/x64-coverage.csv`.

**Consumes:** Address, byte spans and explicit x86-64 mode; no image or loader dependency.

**Produces:** `enum class DecodeStatus { decoded, unsupported, invalid, truncated };`, `enum class FlowKind { fallthrough, call, conditional_branch, jump, ret, trap };`, typed `RegisterOperand`, `MemoryOperand`, `ImmediateOperand`, `RelativeOperand`, and `using Operand = std::variant<...>`.

Register identity uses a bank/index plus width and high-byte flag; memory operands retain address width, optional segment/base/index, scale, signed displacement and instruction-pointer-relative flag. An `Instruction` stores address, exact byte array/length, stable opcode enum, typed operands, explicit/implicit register reads/writes, flow, and optional direct target. `DecodeResult` stores status, optional instruction and diagnostic reason. `DecodeResult decode_x64(std::span<const std::byte>, Address)` never claims a length on unknown encodings. `std::string format_instruction(const Instruction&)` renders Intel syntax separately from facts.

Implement table-driven opcode families in separate RED→GREEN batches inside this task. The required first coverage manifest is:

| Family | Forms to implement and fixture independently |
| --- | --- |
| Moves/addressing | `88–8B`, `B0–BF`, `C6/C7 /0`, `8D`, `0F B6/B7/BE/BF`, `63` |
| Stack | `50–5F`, `68`, `6A`, `FF /6`, `8F /0`, `C9` |
| Arithmetic/logical | ADD/OR/ADC/SBB/AND/SUB/XOR/CMP base families `00–3D` where defined; groups `80/81/83`; TEST `84/85/A8/A9`, `F6/F7 /0`; INC/DEC `FE/FF /0,/1`; NOT/NEG `F6/F7 /2,/3`; IMUL `69/6B/0F AF` |
| Shifts/rotates | Defined `C0/C1/D0–D3` group forms with immediate, one and CL counts |
| Control flow | `E8/E9/EB`, `70–7F`, `0F 80–8F`, `FF /2,/4`, `C2/C3`, `CC` |
| Padding/landing | `90`, `0F 1F /0`, `F3 0F 1E FA` |

- [ ] Start with literal fixtures: `48 89 E5` → `mov rbp, rsp`, length 3; `4D 8B 4C 24 08` → R9 load from R12+8, length 5; `48 8D 05 10 00 00 00` at `0x1000` → RIP-based effective address `0x1017`; `E8 FB FF FF FF` at `0x1000` → direct call `0x1000`; `EB FE` → self-loop; `40 88 E0` uses SPL whereas unprefixed byte register index 4 denotes AH. Assert facts, not formatting alone.
- [ ] For every enabled form, add width, ModR/M register/memory, REX, SIB/index/base, displacement and immediate fixtures as applicable. Verify signed immediates and all three branch widths used here. Include indirect call/jump, RET cleanup, register/flags effects and a non-executable unknown-data fixture. For each multibyte fixture, truncated prefixes of it must not decode successfully unless independently valid shorter instructions.
- [ ] Reject invalid LOCK use, illegal operand forms and instruction length beyond 15 bytes. Label unimplemented prefix maps/forms unsupported, not invalid by convenience. Test operand/address overrides and prefix ordering; do not enable a form until Intel-reference rules and fixtures agree. Direct-target arithmetic outside the address model preserves a diagnostic and unresolved target without unchecked wrapping.
- [ ] Cross-check selected fixture bytes with MSVC assembler/disassembler tooling; production code must not invoke an external disassembler. Add evidence per form to `docs/x64-coverage.csv`; list remaining extensions as absent, not verified architecture coverage.
- [ ] Run processors and the whole headless suite for each family batch; preserve previously passing forms. Install the processor DLL and headers.

## Task 6 Reachable Code and String Discovery

**Files:** Analysis headers/sources/CMake, `tests/analysis_tests.cpp`, code/string fixture builders.

**Consumes:** Immutable `Image`, `decode_x64`, typed operands and control-flow facts.

**Produces:** `struct AnalysisOptions { std::size_t min_string_characters = 4; std::size_t instruction_budget = 1000000; std::size_t string_budget = 1000000; };`, `AnalysisSnapshot` containing reachable instructions, edges, unresolved/termination diagnostics, entry/target candidates, strings and completeness. `Result<AnalysisSnapshot> analyze(const Image&, const AnalysisOptions&, std::stop_token)`; `struct StringScan { std::vector<StringRecord> records; std::vector<Diagnostic> diagnostics; bool complete; };` and `Result<StringScan> find_strings(const Image&, const AnalysisOptions&, std::stop_token)`. `StringRecord` retains encoding, preview, full byte/character lengths, file offset, optional mapped address and terminated flag; previews contain at most 256 Unicode characters independently of complete string extents. Budget exhaustion retains collected records with an explicit incomplete status.

- [ ] Pin exact visited-address sets for a self-loop, branch diamond, call target plus fallthrough, unreachable embedded bytes and an indirect jump. Unsupported/truncated instructions terminate that path without creating fake fallthrough. Validate executable mapping before following a seed; a branch into zero-fill or data is an explicit termination, not arbitrary function discovery. A reached budget produces an incomplete result with a resource diagnostic, not a complete success.
- [ ] Pin ASCII and UTF-16LE strings of length 3 versus default 4, valid/invalid surrogate pairs, terminator versus range-end flags, overlays without VAs, chunk splits and gaps. Deduplicate by encoding/file start rather than silently dropping ASCII/UTF-16 interpretations. Scan initialized input ranges; do not invent strings from zero-fill. Large strings retain extent and bounded preview rather than building multi-gigabyte UI text.
- [ ] Observe RED, implement worklist traversal and chunked string scanning, check stop tokens in bounded loops, then run the full headless suite. Budgets are configurable and shown as incomplete analysis in both frontends. Full function boundaries and xrefs remain later-stage capabilities.

## Task 7 Immutable Documents and Transactional Navigation

**Files:** Workspace headers/sources/CMake, `tests/workspace_tests.cpp`.

**Consumes:** Raw/PE load results and analysis services.

**Produces:** `struct DocumentId { std::uint64_t value; };`, `struct OpenTicket { DocumentId document; std::uint64_t generation; };`, equality comparable; `OpenRequest` (path, format, optional raw options, analysis options); `DocumentSnapshot` (id, revision, image, metadata, diagnostics, optional analysis, metadata completeness); `using Location = std::variant<Address, FileOffset>`. Analysis completeness stays in its analysis result; optional metadata warnings alone do not mean instruction decoding failed.

`Result<std::shared_ptr<const DocumentSnapshot>> load_document(const OpenRequest&, OpenTicket, std::stop_token)` is the common synchronous job body used by the CLI and GUI workers. `Workspace` provides `OpenTicket begin_open()`, `bool finish_open(OpenTicket, Result<std::shared_ptr<const DocumentSnapshot>>)`, `void cancel_open()`, `void close_document()`, `std::shared_ptr<const DocumentSnapshot> current() const`, `std::optional<Error> last_error() const`, `std::optional<Location> selection() const`, `Result<Location> navigate(Location)`, `Result<Location> back()` and `Result<Location> forward()`. State-changing calls belong to the owning thread. Stale completions or mismatched snapshot/ticket identities return false; successful matching completion clears the old history. Preserve the last failed-open diagnostic for the caller without replacing `current()`.

- [ ] Tests load real fixtures and assert a failed replacement keeps the prior id/selection/history; completing request A after newer B cannot replace B; cancel/close invalidates a pending ticket; an old document's history never navigates into its replacement. Verify file offset navigation into an unmapped overlay succeeds only in file-offset mode and has no fabricated VA. Invalid VA navigation leaves selection/history intact. Back/forward and navigate-after-back follow normal history behavior.
- [ ] Observe RED. Implement the reducer and common load job, using only the engines from prior tasks. Keep job execution separate from the owning-thread workspace state so tests can deliver real outcomes in a controlled order without mocked parser behavior. Run workspace and the whole suite.

## Task 8 Real CLI Inspection and Disassembly

**Files:** CLI command parser/handlers, native entry path handling, `tests/fixture_generator.cpp`, `tests/cli_binary_tests.cmake`, app/test CMake.

**Consumes:** Task 7 `OpenRequest`, common load job and snapshot. The CLI never reparses PE structures or uses an independent decoder.

**Produces:** `int run_cli(std::span<const std::wstring_view> arguments, std::ostream& out, std::ostream& err)` on Windows, invoked from `wmain`; keep filesystem paths Unicode through `std::filesystem::path`. Numeric/option parsing helpers stay private. Command grammar and status codes are exactly the approved spec: inspection 0, argument 2, I/O/format/unsupported-analysis 1, incomplete decoding 3.

- [ ] Preserve existing help/version/error tests. Add inspect/disassemble fixtures asserting image base `0x140000000`, entry `0x140001000`, section mapping, named/ordinal imports, export forwarder, and literal decoded entry instructions. Unknown/truncated code must be reported with status 3; unsupported machine disassembly status 1. Metadata-only inspection with optional warnings remains status 0. Build `hexlab_fixture_generator` from test-only original writers and invoke it from the integration script before executing commands; fixture generation cannot depend on production parsing to compute expected bytes.
- [ ] Add paths with spaces and non-ASCII characters; missing files, raw mode missing architecture/base, missing option values, conflicting duplicates, incompatible raw options, unsigned overflow, trailing address junk and decimal/hex address cases. No process launch or `LoadLibrary` occurs for input files; fixtures may deliberately contain invalid executable content beyond structures being inspected.
- [ ] Observe RED, implement Unicode CLI parsing and rendering over workspace snapshots, register `cli_binary` with actual executable/fixture paths, then run all headless tests in Debug and Release. Installed CLI dependencies must include the new engine DLLs rather than an independent static engine copy.

## Task 9 Asynchronous Desktop Open and Real Inspection Views

**Files:** Desktop controller, listing/bytes/metadata views, raw dialog and main-frame integration; app CMake; view-model tests under `tests/workspace_tests.cpp` or a separate wx-free `tests/view_model_tests.cpp` if needed.

**Consumes:** Workspace state and immutable snapshots. Background workers call `load_document` and never access windows.

**Produces:** `DocumentController` owns `Workspace`, a worker service with stop sources and a shared completion mailbox. A wx timer/event on the main thread drains ticket-tagged outcomes and calls `finish_open`; worker callbacks never capture `MainFrame*`. Closing/canceling invalidates tickets immediately, requests stop, and keeps job/storage ownership alive until workers finish. No detached thread or window access from workers. Joining cannot hold a lock needed by a worker to finish.

`ListingView` and `BytesView` expose `set_document(std::shared_ptr<const DocumentSnapshot>)` and `select(Location)`, with explicit clear behavior. Metadata views take the same snapshot. Use virtual list controls and page rows around the current location; never preformat every byte of a large input. Undecoded data rows remain labeled as data, not reachable instructions.

- [ ] Add a real Open command and explicit raw-mode dialog with x86-64 architecture/mode, base and optional entry. Successful open replaces the welcome center with Disassembly/Bytes tabs; failures preserve the old document. Show progress/cancel without blocking repaint or docking. Populate Segments/Strings/Imports/Exports from snapshot facts and label entry/target candidates accurately.
- [ ] Write view-model tests before implementation for file-backed bytes, zero-fill, gaps, overlay file locations, page boundaries and incomplete instruction rows. Selection adapters must feed one shared `Location`; do not maintain independent byte/listing addresses that can drift.
- [ ] Implement the controller and views in small files. Preserve AUI pane names and teardown fixes where practical; update the saved default perspective after adding real metadata panes. Destroy/cancel the controller before GUI children and keep completion mailboxes independent of frame lifetime.
- [ ] Build desktop and run the original core/CLI/docking/floating tests plus new component tests. Establish actual fixture-backed rendering before marking any view verified.

## Task 10 Desktop Navigation Copy and Lifecycle Integration

**Files:** Jump dialog, main frame/controller command routing, `tests/desktop_binary_smoke.cmake`, narrowly scoped test driver code under `tests/desktop/` linked to real desktop components.

**Consumes:** `Workspace::navigate/back/forward`, typed operands, snapshot-backed views and background controller.

**Produces:** Working Jump, Follow Target, Back, Forward, Copy Address, Copy Bytes and Copy Text commands. The jump dialog explicitly selects virtual-address or file-offset mode and uses the same checked numeric parser rules as the CLI. Put the pure address parser in `hexlab_workspace` if both frontends need it; do not duplicate it.

- [ ] GUI integration opens the PE fixture and verifies selected entry `0x140001000` maps to file `0x200` and bytes `90 C3`; navigates a separate branch fixture, follows its direct target, goes back, selects a known string, and verifies byte selection. Invalid jump keeps selection; copying returns the exact selected fixture bytes/text through the clipboard command.
- [ ] Add cancellation and close-during-work scenarios, rapid A→B open with reversed completions, failed replacement, empty raw input and raw validation errors. Use real fixtures/jobs and deterministic ticket reduction tests for ordering rather than timing-dependent sleeps. Every test-owned frame closes and every worker is joined by its owner.
- [ ] Exercise recently closed floating-pane reset and shutdown with panes floating while a document is active. Retain the original foundation regression unchanged. Run `desktop_binary_smoke` with a 60-second test timeout on an interactive host; require genuine state assertions and nonzero exit on failure.
- [ ] Capture and inspect actual installed-app screenshots of PE disassembly/bytes, strings/imports and a malformed-input diagnostic. Verify labels, addresses and diagnostic text are readable at normal and smaller sizes; record any unproven keyboard/high-DPI behavior accurately.

## Task 11 Installed Suite Verification and Coverage Evidence

**Files:** Install rules across new libraries, `tests/install_tests.cmake`, build/validation docs, capabilities and x64 form inventory.

**Consumes:** All prior working components.

- [ ] Extend install tests to require all five new engine DLLs, their import libraries/generated headers, and successful installed inspect/disassemble commands against generated fixtures. Verify GUI runtime dependencies with `dumpbin /dependents`; no engine library may depend on wxWidgets. Install into a fresh `out/install/BinaryAnalysisDebug` staging path so stale DLLs cannot mask missing install rules.
- [ ] Run `cmake --build --preset windows-desktop --parallel 4` and `ctest --preset windows-desktop --output-on-failure`; run the complete Release headless suite; reconfigure a fresh disconnected GUI-free tree and prove no wx `_deps` acquisition. Re-run installed GUI load/navigation/floating scenarios. Compare each command's exit/output with its expected result and record evidence.
- [ ] Update capability rows by verified format/ISA form and workflow. Keep PE unparsed directories, incomplete x86-64 extensions, function discovery, persistent projects, graphing, types, decompilation, debugging and SDK gaps explicit. Never turn a verified scalar subset into a fully verified processor family.
- [ ] Write `docs/binary-analysis-validation.md` with the actual test counts, corpus/fixture provenance, screenshots, dependency evidence, coverage boundaries and remaining full-goal work. Perform the required independent final read-only review under Native execution, address material findings with regression tests, and record unaddressed limitations honestly. Preserve files if commits remain unavailable.

## Self Review and Handoff

All approved stage 2 sections have owners: immutable images task 1; raw/detection task 2; PE and metadata tasks 3–4; original decoder task 5; entry analysis/strings task 6; transactional document/navigation task 7; shared CLI task 8; background desktop/views task 9; interactions and lifecycle task 10; complete regression/install/coverage evidence task 11. The five Review Focus cases are assigned explicit tests above. Existing foundation contracts and full-application scope are preserved.

Execution remained Native under the user's approval of this written plan. All stage tasks and final verification are implemented; see the linked validation report for current boundaries. No additional approvals were requested between tasks.
