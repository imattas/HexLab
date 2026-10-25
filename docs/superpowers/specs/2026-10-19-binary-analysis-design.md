# HexLab binary loading and disassembly design

## Purpose and status

Deliver stage 2 of the [approved full application architecture](2026-10-19-hexlab-design.md): open real binaries, inspect their mapped contents and metadata, decode x86-64 instructions with an original engine, discover strings, analyze entry-point control flow, and navigate synchronized disassembly and bytes views. The complete IDA-style application remains the goal. Later database, graph, type, decompiler, debugger and SDK stages are still required.

Status: subsystem specification approved by the user on 2026-10-19. The existing foundation and its four desktop tests pass; loaders, image mappings and processor engines do not yet exist. Preserve C++20, wxWidgets, separate GUI/CLI tools, shared engine DLLs and the user's monorepo requirement. Continue Native execution after the required plan review. Do not reopen already-settled toolkit or engine ownership choices.

## Architecture choice

| Approach | Consequence | Decision |
| --- | --- | --- |
| Shared image, loader, processor, analysis and workspace libraries used by both tools | Testable engines and one interpretation of bytes across GUI and CLI; supports later tools and modules | Selected, consistent with the approved monorepo |
| Parse and decode inside the GUI and reproduce it in the CLI | Duplicated state, inconsistent results and no reusable engine boundary | Reject |
| Wrap an existing disassembler or use third-party decoder output as the engine | Reduces original implementation work but contradicts the approved from-scratch interpretation | Reject; independent tools may still validate fixtures |

New targets are `hexlab_image`, `hexlab_loaders`, `hexlab_processors`, `hexlab_analysis` and `hexlab_workspace`, each a shared library with generated export declarations. `hexlab::image`, `hexlab::loaders`, `hexlab::processors`, `hexlab::analysis` and `hexlab::workspace` are build aliases. Add each target when its first working implementation and tests are introduced.

Dependency direction is core → image → loaders; core → processors; image/processors → analysis; loaders/analysis → workspace; workspace → GUI and CLI. Here arrows point from prerequisite to consumer. No engine library depends on wxWidgets. File-format parsers never invoke a process loader, execute entry points or load a target DLL into HexLab.

Each library owns `include/hexlab/<component>/`, `src/` and a `CMakeLists.txt` under `libs/<component>/`. Desktop view models and views stay in `apps/desktop/`; CLI command parsing stays in `apps/cli/`. Extend `tests/` with fixture builders and component/integration tests. Install new engine DLLs, import libraries and headers alongside the existing suite.

## Immutable input and address mappings

Introduce an owning `FileStorage` abstraction exposing `size()` and bounded `read_at(FileOffset, count)` operations. Use read-only OS file mappings so a large file does not require a second full in-memory copy. On Windows hold the input with a sharing policy that prevents concurrent writes and truncation for the storage lifetime; fail opening if that stable access cannot be acquired. A future host without enforceable stable mappings must use an owned stable snapshot or bounded checked reads rather than dereferencing a concurrently truncatable mapping. An open storage object owns its file and mapping handles. Returned views retain shared storage ownership so no asynchronous task can outlive its bytes. Handle an empty file without creating an invalid zero-length OS mapping. Surface inaccessible files, directories and mapping failures as diagnostics.

An `Image` is an immutable snapshot containing storage, an address space, segments, entry points, metadata and format diagnostics. A segment records virtual start/size, file start/backed length, name and read/write/execute permissions. Represent file offsets, RVAs and virtual addresses distinctly; convert through checked image helpers rather than interchangeable integers.

Mapped reads resolve file-backed bytes and explicit zero-filled tails. Unmapped gaps fail. A read crossing adjacent compatible segments may be composed into a caller-sized buffer; a borrowed span never pretends zero-filled or discontiguous bytes are contiguous input. Never allocate `SizeOfImage` merely because a header requests it. Resolve every request with existing checked arithmetic and half-open range rules, including address-space identity.

Reject overlapping virtual segment ownership with a format diagnostic instead of silently selecting the first section. File-backed overlap may be reported as aliasing but does not change virtual ownership. Keep overlay bytes accessible by file offset even when they have no virtual mapping. Input bytes remain immutable; patch overlays are a later required stage.

## Raw loading

Raw loading requires explicit architecture, execution mode and base address. The first supported decoding mode is x86-64; a raw image has one byte-addressed little-endian space and one file-backed segment. Permissions and an optional entry address are caller options. An entry address must be in the mapped range. An empty raw image is valid for inspection but has no executable entry point.

Do not silently fall back from a failed PE parse to raw analysis. Unknown files require the user to select raw mode and its parameters. Automatic format detection returns supported PE, unknown, or recognized-but-invalid diagnostics. A truncated `MZ`/`PE` candidate is a parsing failure rather than evidence that a file is valid raw machine code.

## PE loading and metadata

Implement separate PE32 and PE32+ header paths with a shared checked reader. Validate signatures, header offsets, optional-header size, directory availability, section-table extent, raw ranges, virtual ranges and entry-point arithmetic before building an image. Preserve the declared machine and subsystem; only AMD64 PE32+ receives automatic x86-64 decoding in this stage. Other recognized machines remain inspectable with an explicit unsupported-analysis status.

The [Microsoft PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) defines the authoritative header layout and distinctions between file positions and RVAs. Use its section sizes to distinguish initialized bytes and zero-filled memory. Treat the certificate directory as a file-position special case. These format facts do not justify trusting malformed offsets or allocating image-sized memory.

For this inspection model, map each section over `max(VirtualSize, SizeOfRawData)` bytes after validating the extent against the declared image and neighboring mappings. Map `SizeOfRawData` initialized bytes and synthesize only the remaining virtual tail. Preserve raw alignment padding as identifiable input bytes, not an automatic code seed. Map validated headers separately at the image base. Retain section declarations in metadata so later format compatibility work can refine this policy without losing original facts.

Expose sections, image base, entry point, imports, exports, relocation records and the available directory list. Imported symbols retain library, name or ordinal and thunk/IAT locations. Exports retain ordinals, optional names and forwarder strings. Relocations retain type and page offset without applying mutations to the immutable input. Headers, sections and unmapped overlays remain distinguishable in the UI.

Every string and table traversal has a validated range and bounded termination condition. Detect cycles, missing terminators, count multiplication overflow, unterminated names, invalid thunk width and references into gaps. Malformed required image structures reject the image; malformed optional metadata produces a bounded diagnostic and a partial-metadata status without inventing entries. Delay imports, resources, exceptions, TLS callbacks, debug directories and less common variants remain inventory entries until their parsing is implemented and verified. An available directory header alone is not support for its contents.

## Original x86-64 decoder

Build the decoder from encoding tables and explicit parsing of prefixes, opcode maps, ModR/M, SIB, displacements and immediates. The [Intel instruction-set reference](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) is authoritative for each enabled form. Keep instruction recognition, typed operand construction and presentation separate. Do not derive success from a plausible mnemonic string.

A decode request contains an address, mode and up to 15 mapped instruction bytes. The result distinguishes decoded, unsupported, invalid and truncated. A decoded instruction has an exact length, original bytes, opcode identity, typed operands, register reads/writes and control-flow category. Register operands retain width and identity; memory operands retain address width, base/index/scale, signed displacement and RIP-relative information; immediates retain encoded width, signedness and effective value.

The first verified instruction forms cover common integer/control-flow work: register and immediate moves, register/memory moves, LEA, push/pop, integer arithmetic and comparisons, bitwise operations, shifts, direct and indirect calls/jumps, conditional branches, returns, NOP and INT3. Implement each form only with exact prefix, width and operand rules and independent encoding fixtures. Track forms individually in a decoder coverage table. Full x86-64 extension coverage remains required; initial scalar coverage must not be advertised as complete architecture support.

Handle REX register extensions and byte-register differences, operand/address size overrides, sign extension, displacement widths and next-instruction-relative branch targets. Validate branch-target arithmetic instead of wrapping addresses. Preserve indirect targets as unresolved expressions. Invalid prefix combinations and unsupported VEX/EVEX/other forms have explicit statuses. Do not guess an unknown instruction length or continue proven code flow across an instruction whose extent is unknown.

The listing may display undecoded input as byte-data rows so users can inspect all bytes. Those rows are not instructions or evidence of reachable code. Manual navigation can request decoding at another address without retroactively asserting that the previous unknown opcode was one byte long.

## Entry analysis and strings

The analysis engine takes immutable images and a decoder interface. Seed the first reachable-code pass from validated executable entry points and direct call targets. Follow direct conditional branch targets and fallthroughs; stop at unconditional transfer, return, invalid/truncated/unsupported instruction, unmapped memory or unresolved indirect transfer. Bound work by unique visited addresses and cancellation. Do not linearly disassemble arbitrary data and call every row reachable.

Record visited instructions, direct edges, unresolved edges and termination reasons. Calls preserve their fallthrough and record a separate target candidate; they do not imply exact function boundaries or stack frames. Those capabilities remain stage 3/4 requirements. Exports and symbols can be exposed as candidates without claiming complete function discovery.

Find printable ASCII and Unicode strings in strict UTF-8, UTF-16LE/BE and UTF-32LE/BE with a configurable minimum length, default four Unicode scalar values. Record encoding, byte length, file offset and mapped address when one exists. A candidate must not span an unmapped hole or acquire fabricated bytes from another range. Preserve deterministic results across chunk boundaries; distinguish terminated strings from runs ending at a range boundary. Unicode handling rejects malformed encodings, invalid scalar values and unpaired UTF-16 surrogates. Scanning is cancellable and does not duplicate a full file to render strings. UTF-8 candidates containing only ASCII are represented by the ASCII pass to avoid duplicates.

Analysis snapshots include document identity and revision. A job cannot publish into a newer image, a different active document or a destroyed frame. Check cancellation during file/table traversal, string scanning and reachable-code work; closing a document releases results after workers have stopped using its storage.

## Shared workspace services

`hexlab_workspace` owns document lifecycle and composes loaders, processors and analysis through services. The GUI and CLI use the same open options, diagnostics and snapshot model. This avoids a second PE parser or an independent decoder in the command-line frontend.

Opening is transactional at the document level: retain the existing document while a new input is loading; replace it only after a usable snapshot is ready. Failures leave the prior document and navigation unchanged. Navigation uses image addresses with a distinct file-offset entry mode and checks mappings before updating selection. History stores document identity and addresses and never resolves an old entry into a replacement image.

Allow one active document in this stage while keeping document identifiers and immutable state suitable for multiple tabs later. This is a delivery sequence, not removal of the approved multi-document requirement. Keep long-running work off the GUI thread and send ownership-safe, revision-tagged completion events to wxWidgets.

## CLI behavior

Preserve `--help`, `--version` and status 2 for argument errors. Add `hexlab_cli inspect <path>` for deterministic metadata, sections, imports, exports and diagnostics. Add `hexlab_cli disassemble <path>` for validated AMD64 PE entry analysis. Raw commands require `--format raw --arch x86-64 --base <address>`; accept an optional `--entry <address>`.

Accept hexadecimal addresses with `0x` and decimal addresses without it. Reject overflow, trailing junk, missing values, duplicate conflicting options and raw-only options used with an incompatible format. Paths are passed as data, never shell commands. Use the native Unicode path on Windows and test spaces/non-ASCII filenames. Keep human-readable output stable enough for tests but reserve a versioned structured export format for the automation stage.

Successful inspection returns 0, argument errors return 2, and I/O/format/unsupported-analysis failures return 1 with diagnostics on stderr. If decode coverage is incomplete, report unsupported sites and return a distinct analysis-incomplete result (status 3), rather than claiming complete disassembly. A valid metadata inspection with optional metadata warnings returns 0 and includes those warnings.

## Desktop behavior

Add a working File > Open command, recent-file-ready path handling and a raw options dialog when explicitly selecting raw loading. Show progress and a cancel action during load/analysis; disable document-dependent actions while no snapshot is active. Do not block repainting or pane movement on table parsing.

Replace the empty center with a tabbed Disassembly and Bytes workspace. Listings are virtualized/paged, with columns for address, original bytes, mnemonic/operands and analysis status. Keep the Functions pane honest: show validated entry/target candidates with an explicit candidate label until function discovery exists. Add Segments, Strings, Imports and Exports views populated from the image snapshot.

Selecting a segment, string, import/export location or listing row navigates the shared selection and updates the bytes view. Provide address jump, follow direct operand target, back and forward history. Distinguish a virtual address from a file offset in the jump UI. An unmapped location shows a diagnostic rather than selecting unrelated bytes. Keep the current AUI pane-reset and floating-close regression behavior intact.

Copy selected addresses/bytes/text through real commands. Opening the same file must not execute it. A failed open preserves the current loaded document. A stale background result after cancel/reopen/close must be discarded. Render and inspect actual fixture-backed views before claiming the GUI path works.

## Validation and acceptance

Use original fixture builders with literal expected values; do not download executable samples or run unknown inputs. Generate minimal raw, PE32 and PE32+ files with known entry points, section mappings, initialized/zero-filled regions, imports by name/ordinal, export forwarders and relocations. Keep malformed variants for each important boundary.

Required component checks cover empty input, truncated signatures/headers/tables, overflowing virtual/file ranges, overlapping virtual sections, raw alignment padding, zero-fill boundaries, metadata gaps, missing terminators, cyclic references, oversized counts and certificate file offsets. Fixtures must distinguish a valid file position from the same integer interpreted as an RVA.

Decoder tests pin bytes, exact lengths, operand widths/identities, signed values, displacement addressing, RIP-relative targets, high registers, byte-register behavior and control flow for every enabled form. Add truncated variants of multibyte fixtures, repeated prefixes, the architectural length limit and unknown opcode maps. Cross-check selected assembled fixtures using the installed toolchain or another independent decoder; the production engine remains original.

Analysis tests include a loop, a branch diamond, a direct call with fallthrough, unreachable embedded data, an indirect jump and unsupported/truncated code. Expected visited addresses and termination reasons are literal fixture expectations. String tests cover chunk splits, range boundaries, UTF-16 surrogate validity and cancellation. Workspace tests cover failed replacement and stale completion rejection.

CLI integration opens the same fixtures and compares engine facts with GUI-facing workspace snapshots. GUI tests open a fixture, navigate to entry, follow a target, return in history, select a string and verify synchronized bytes, cancel/reopen a document, reset floating panes and close during work. Inspect actual screenshots for readable addresses, untruncated diagnostic text and useful pane layout.

Run the existing foundation tests plus all new component/CLI/GUI tests in Debug and headless Release. Install the expanded suite into a fresh staging path and verify its DLL dependencies and launches. Keep build artifacts and fixtures distinct from installed runtime data. Record verified instruction and format variants in `docs/capabilities.csv`; leave unimplemented variants partial or absent.

Stage 2 acceptance requires actual mapped raw/PE inspection and original decoding in both frontends, meaningful error handling, navigation and synchronized bytes, verified background cancellation/lifetime behavior, all regression tests passing, and evidence from the installed suite. Stage 2 success does not complete the full application goal.

## Review handoff

Status: the user approved this specification and its detailed implementation plan. This stage is implemented; [validation](../../binary-analysis-validation.md) records evidence and remaining limits. The full application goal remains active.

The user approved this focused specification with “approved” on 2026-10-19. Write the detailed implementation plan against it and preserve the existing Native execution preference. Review that concrete plan before product implementation.
