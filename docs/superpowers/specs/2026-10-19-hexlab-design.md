# HexLab C++ reverse engineering application design

## Goal and review status

Build an original desktop reverse engineering application in C++ with wxWidgets, with the full functional breadth of IDA Pro as the destination. The scope includes interactive disassembly, analysis databases, types, graphs, decompilation, debugging, automation, processor and loader modules, and extensibility. A working early milestone does not satisfy the full goal.

Status: architecture approved by the user on 2026-10-19. Foundation and binary-analysis stages are implemented; [foundation validation](../../foundation-validation.md) and [binary-analysis validation](../../binary-analysis-validation.md) record evidence and limitations. The full application remains in development. The working name is HexLab, matching the workspace. Windows is the first build host; Linux and macOS remain delivery targets.

Approved interpretation of “from scratch”: implement the application and its analysis, decoding, lifting, and decompilation engines in this repository. Use wxWidgets for the GUI and ordinary infrastructure libraries where appropriate. Do not substitute an embedded existing reverse engineering application for the engine. Existing tools may be independent test oracles.

Functional equivalence is the goal; reproducing proprietary implementation details, branding, or undocumented database internals is unnecessary. Native analysis is local and usable offline. IDA database and plugin binary compatibility would be separate compatibility work; portable import and export are included.

## Architecture options

| Approach | Benefits | Costs |
| --- | --- | --- |
| Original modular C++ engine with wxWidgets, selected | Own the whole analysis model and meet the from-scratch request; support UI and CLI from one core | Decoder coverage, semantics, decompiler quality, and debugger support require substantial implementation |
| Original UI and analysis orchestration with third-party decoder engines | Earlier instruction coverage | A key engine component would not be from scratch; semantics and decompilation still need work |
| Frontend around another reverse engineering suite | Earlier breadth through existing functionality | Does not fulfill the requested original implementation |

Proceed with the first approach. Infrastructure dependencies are wxWidgets, the C++ standard library, operating system APIs, and provisionally SQLite for transactional persistence. Python embedding is optional at build time. Every dependency needs a pinned version and recorded license before introduction.

## Full scope and completion evidence

Maintain a capability inventory with separate states for absent, partial, implemented, and verified. Record processor modes, instruction extensions, file variants, debugger targets, and host platforms separately. A registry entry or enabled menu is insufficient evidence of support.

| Area | Required behavior | Evidence required for completion |
| --- | --- | --- |
| Binary loading | Raw images, executables, relocatable objects, libraries, firmware containers, managed bytecode; sections, symbols, imports, exports, relocations, overlays and multiple address spaces | Valid and malformed fixtures for every advertised format and variant; file offset and virtual address mapping tests |
| Processors | Broad processor family coverage matching the reviewed reference inventory, including endian, execution mode and extension variants | Encoding fixtures, mode transitions, invalid instruction handling, assembler or independent decoder comparisons |
| Interactive analysis | Instructions, data, functions, chunks, stack frames, strings, switch recovery, call graph, code and data references, signatures and incremental reanalysis | Known-answer binaries, editable analysis scenarios, unresolved target preservation and persistence tests |
| Types and symbols | Primitive and compound types, enums, unions, arrays, function prototypes, calling conventions, local variables, headers, PDB and DWARF | ABI fixtures, recursive type tests, debug information imports and edit propagation checks |
| Desktop workspace | Dockable synchronized disassembly, bytes, pseudocode, control flow, calls, functions, names, strings, segments, types, imports, exports, output and debugger views | Automated navigation scenarios and manual inspection of packaged builds on every host |
| Search and editing | Address navigation, history, bookmarks, byte and text search, immediate search, rename, comments, code/data conversion, patching and export | Repeatable edit and undo scenarios, search fixtures and exact patch byte comparisons |
| Decompilation | Machine semantics, intermediate representation, data flow, type recovery, expression simplification, control flow structuring and editable C-like pseudocode | Per-instruction semantics tests, execution equivalence tests and compiled source corpora across advertised architectures |
| Debugging | Local and remote process control, software and hardware breakpoints, stepping, threads, modules, registers, memory, exceptions, attach and detach | Real debuggee scenarios for each advertised target; correct cleanup after normal exit and failure |
| Automation | Headless analysis, versioned exports, scripting console, Python API, C++ SDK, loader and processor extensions | Same results from GUI and CLI, script fixtures and separately built SDK example modules |
| Recognition and advanced analysis | Library recognition, reusable signatures, binary comparison, deobfuscation passes and shareable analysis metadata | Positive and negative corpora, false match reporting and transformation equivalence checks |
| Shared workflows | Portable analysis exchange, change history, merge conflicts and collaboration capability | Independent client round trips and conflicting concurrent edit scenarios |
| Delivery | Recoverable databases, installers, documentation, accessibility, reproducible builds and supported platform matrix | Fresh-machine installation, migration, interrupted-save recovery, keyboard workflows and release validation |

The coverage baseline is the official IDA product documentation and its processor/format specification, reviewed on 2026-10-19. Before claiming broad equivalence, expand every reference capability into the inventory and verify it individually. Do not interpret this table as a complete enumeration of all processor and format variants. Features discovered during that inventory remain within the full goal.

References: [IDA product capabilities](https://hex-rays.com/ida-pro), [processor reference](https://docs.hex-rays.com/core/disassembler/specification/supported-processors.md), [extension interfaces](https://cpp.docs.hex-rays.com/), and [wxWidgets overview](https://wxwidgets.org/about/). These establish product categories and toolkit suitability; the architecture below is an original proposal.

## Component boundaries

Use C++20 and CMake. Keep wxWidgets types out of the analysis engine. Public interfaces use explicit error results, stable identifiers, cancellation and documented ownership. The desktop and headless applications call the same services.

| Component | Responsibility | Depends on |
| --- | --- | --- |
| core | Addresses, bounded byte readers, checked arithmetic, diagnostics, identifiers and cancellation | C++ standard library |
| image | Immutable input bytes, segments, address spaces, mappings and patch overlays | core |
| loaders | Format detection and validated conversion into images | image, loader API |
| processors | Instruction decode, operands, register descriptions, control flow and semantic lifting | core, processor API |
| database | Transactions, schema migrations, snapshots, metadata and change history | core, persistence backend |
| analysis | Function discovery, reference resolution, work scheduling, signatures and invalidation | image, processors, database, types |
| types | ABI descriptions, type graphs, stack layouts and debug symbol import | core, database |
| ir | Typed bit-vector operations, memory effects, basic blocks and SSA | core |
| decompiler | Lifting orchestration, optimization, variable recovery, structuring and source maps | ir, analysis, types |
| debugger | Common session model, target backends, process events and live memory overlays | core, image, database |
| automation | Commands, exports, scripting and versioned extension API | application services |
| desktop | wxWidgets presentation, docking, navigation and user interaction | application services |
| cli | Batch import, analysis, inspection and export | application services |

User-directed monorepo layout: `apps/desktop/`, `apps/cli/`, `apps/debug-server/`, `libs/core/`, `libs/image/`, `libs/loaders/`, `libs/processors/`, `libs/database/`, `libs/analysis/`, `libs/types/`, `libs/ir/`, `libs/decompiler/`, `libs/debugger/`, `libs/automation/`, `plugins/`, `sdk/`, `resources/`, `scripts/`, `tests/`, `fixtures/`, `cmake/`, and `docs/`. Each library owns its headers, sources and CMake target. Create directories when they receive implemented content.

### Monorepo distribution

The user explicitly requires a multi-file tool suite rather than a standalone executable. Build the analysis components as shared libraries (DLLs on Windows), with GUI, CLI and future debugger-server tools as separate executables. Link wxWidgets dynamically. Keep application services reusable across tools and extension modules; do not embed all engine code in each executable.

Install runtime executables and required DLLs together under `bin/` on Windows, link libraries under `lib/`, public development headers under `include/`, and documentation and supporting data under `share/hexlab/`. Add processor, loader and debugger modules to a versioned plugin directory when implemented. The native plugin C ABI remains separate from internal C++ DLL interfaces; all internal C++ components in a release use a consistent compiler and runtime.

## Address and image model

An address contains an address-space identifier and a 64-bit offset. The space carries width, addressable unit size and byte order. Validate all additions, multiplications, indexing and conversions before accessing bytes. Half-open ranges define ownership; file offsets and virtual addresses are different types.

An image contains file-backed ranges, zero-filled ranges and unmapped gaps. Mapping an address to input bytes can fail. Raw loading requires explicit architecture, execution mode and base address. Unknown formats are reported as unknown and may be opened through the raw loader with those parameters.

Input bytes stay immutable. Patches form a versioned overlay with original bytes, replacement bytes and mapped file locations. Analysis reads the selected overlay revision; export explicitly chooses an output file. Memory snapshots from a debugger form a separate overlay and never silently become file patches.

## Analysis database and scheduling

Persist input identity, segments, decode facts, functions, references, types, comments, names, patches, bookmarks and user decisions. Keep facts from automatic analysis distinct from explicit user overrides. Every derived fact records provenance and the input revision that produced it.

Use one serialized transaction writer and immutable read snapshots. Workers submit proposed results with their source revision; discard or recompute stale results. Dependency records invalidate affected instructions, functions, references and pseudocode when bytes, execution mode, signatures or types change. Preserve unrelated user edits.

Jobs are incremental, bounded and cancellable. Entry points, exports, symbols, unwind information and user commands seed discovery. Decoders return explicit invalid or truncated results. Indirect branches remain unresolved until evidence supports targets; a guessed target is labeled with provenance rather than asserted as certain.

Version database schemas and make migrations transactional. Store input hashes and allow relinking only after identity verification. Support crash recovery and export of user annotations independently from derived caches. Never advertise proprietary IDA database support through a filename extension alone.

## Desktop interaction

Use wxWidgets native controls, docking through wxAUI, virtualized lists, and custom rendered listing and graph canvases. A shared navigation service coordinates the selected address, function, history and active document. View models expose paged data from snapshots; views do not perform file parsing or analysis.

Default layout has functions and symbols on the left, tabbed listing/graph/pseudocode in the center, contextual references and types on the right, and output/tasks at the bottom. Bytes and debugger panels can dock or float. Multiple documents have isolated databases, jobs and histories.

Core interactions include address jump, follow operand, return in history, cross-reference selection, rename, comment, define code/data, function boundaries, type assignment and patch edit. Command routing provides the same operation to menus, shortcuts, scripting and undo/redo. Disabled commands explain their actual prerequisite; placeholder panels must never present fabricated analysis.

Worker notifications reach the main thread as revision-tagged events. Closing a document cancels its jobs and prevents callbacks from accessing destroyed views. Preserve keyboard access, high DPI layout, font scaling, selection contrast and configurable shortcuts.

## Decoder and decompiler implementation

Begin the original decoder with x86-64, followed by x86 modes and ARM/AArch64, while keeping the full processor inventory open. Each processor supplies decode results, instruction length, typed operands, register access, execution mode transitions, branch behavior and semantic lifting. Formatting is separate from decode facts.

The IR explicitly models bit widths, endianness, arithmetic flags, memory, calls, exceptions and architecture-specific side effects. Lift instructions into basic blocks, construct control flow and SSA, propagate constants and types, eliminate dead expressions conservatively, recover variables and structure control flow. Emit pseudocode with source-to-instruction mappings so comments, names and navigation remain synchronized.

Represent unknown semantics and unresolved calls explicitly. Retain unstructured control flow where structuring cannot preserve behavior. Never treat a list of mnemonics wrapped in a C function as a completed decompiler. Test lifting before enabling an optimization that consumes its results.

## Debugger and extension contracts

Debugging uses an explicit disconnected, launching, stopped, running, exited and failed state machine. Backend capabilities declare hardware breakpoints, register sets, stepping and remote features. The first backend targets Windows x64; later backends cover the agreed platform matrix and remote targets.

Only debugger commands launch or attach to a process. File loading never executes the input. Model image rebasing and module lifetimes so a stopped address resolves against the correct runtime image. Restore replaced breakpoint bytes and distinguish owned debuggees from attached processes during detach and failure cleanup.

Expose a versioned C ABI at dynamic module boundaries, with size/version fields and explicit allocation ownership. C++ wrappers provide ergonomic SDK access without relying on a shared STL ABI. Modules declare loader, processor, analysis, debugger or UI capabilities. Python exposes the same transactional commands and snapshot queries; GUI objects remain confined to the main thread.

## Implementation sequence

Each stage needs a focused specification, implementation plan and evidence of its acceptance checks. Later stages remain required even when the earlier application is usable.

1. Establish CMake targets, reproducible wxWidgets provisioning, a real desktop window, headless entry point, checked address primitives and a meaningful test harness.
2. Implement raw and PE loading, original x86-64 decoding, mapped listing and bytes views, strings, entry-point analysis and address navigation. Display unsupported instructions accurately.
3. Add transactional project persistence, functions, references, graph navigation, renaming, comments, undo/redo, patch export and incremental reanalysis.
4. Expand x86 execution modes, implement ELF and Mach-O, ARM/AArch64, type and ABI services, PDB/DWARF import and reusable signatures.
5. Implement the semantic IR and decompiler end to end; verify source corpora and expand instruction semantics and optimization coverage.
6. Deliver Windows debugging, remote protocol support and additional operating system backends with real process-control integration tests.
7. Deliver native SDK, Python automation, headless exports, extension examples and user documentation. Move command API stabilization earlier where previous stages require it.
8. Expand the full processor, loader, decompiler and debugger matrices; deliver advanced recognition, deobfuscation, analysis exchange, comparison and collaboration workflows.
9. Complete platform packaging, performance measurement, recovery testing, accessibility checks and the full capability audit. Address every remaining partial or unverified required feature before completion.

## Validation and release criteria

Use self-authored source and binary fixtures with known expected results. Unit tests cover range validation, malformed headers, instruction boundaries, semantic effects, graph invariants and transaction behavior. Integration tests cover open/analyze/edit/save/reopen/export, cancellation, revision invalidation and process control. Use fuzzing for parsers and decoders, differential checks against independent tools where available, and execution-based checks for decompiler transformations.

Keep GUI tests focused on real workflows and inspect actual rendered packaged builds. Measure import time, analysis time, memory, listing scroll behavior and cancellation latency on documented corpora and hardware before setting release performance thresholds. Large files must use bounded paging rather than duplicate whole images in every view.

Full completion requires all required capability inventory entries to be verified, no unsupported advertised combinations, passing release checks on each supported host, documented limitations, and evidence that the decompiler and debugger perform their advertised operations. A compiling skeleton, screenshots, stubs and narrow tests cannot prove full equivalence.

## Workspace evidence

The workspace was empty when inspected on 2026-10-19. Git 2.55.0 and CMake 4.4.4 are available. Visual Studio Build Tools 2022 is installed at `C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools`; the MSVC 14.44.35207 x64 compiler and Windows SDK 10.0.26100.0 were used to validate the foundation. wxWidgets 3.2.12 was built as shared libraries. The Visual Studio generator locates the compiler even though `cl` is not on the shell PATH.

## Review decision

The user approved the architecture with “APPROVED” on 2026-10-19 and subsequently approved the foundation implementation plan. During implementation the user explicitly required the monorepo and shared-library distribution described above. This approval preserves the full scope; individual capability states remain in the inventory.
