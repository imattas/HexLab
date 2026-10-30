# Project CLI

PE and ELF inputs are detected automatically. `--format elf` selects checked ELF parsing explicitly for inspect/disassemble and project creation. ELF relocatable objects preserve section domains: `va:<section-index>:<offset>` distinguishes equal offsets in different allocated sections. Use the indexes shown by inspection. For an object with `.text` at section 1:

```powershell
./hexlab_cli.exe inspect object.o --format elf
./hexlab_cli.exe project create object.hxproj --input object.o --format elf
./hexlab_cli.exe project rename object.hxproj --at va:1:0 --name entry_point
./hexlab_cli.exe project references object.hxproj --at va:1:0 --direction outgoing
```

Inspection retains symbol-table identities, known/unavailable counts, declared dynamic libraries and raw relocation provenance. Runtime-dependent relationships remain unresolved; source bytes are preserved. See [ELF validation](elf-analysis-validation.md) for supported cases and limits.

ELF files that use DWARF v5 supplementary type references can take an explicitly selected DWP package during inspection or project creation:

```powershell
./hexlab_cli.exe inspect app --dwarf-supplementary-package app.debug
./hexlab_cli.exe project create app.hxproj --input app --dwarf-supplementary-package app.debug
```

The selected path is persisted in the project load recipe. The loader validates the `.debug_sup` checksum and package type index; it never follows a filename from DWARF metadata. See [DWARF v5 import](dwarf-v5-import.md) for the supported subset.

Segmented raw inputs use `--format raw --profile mapping.profile`; see [x86 profiles](x86-profiles.md). Project commands accept `seg:<selector>:<offset>` with hexadecimal coordinates resolved against the embedded profile. Domain identity remains separate from canonical file offsets.

Portable types, source origins, and symbolic assignments can be exchanged with `project types export/import`; `project types verify` checks a bundle without opening a project. `project types export-header` writes supported definitions as an atomic C11 header and rejects existing outputs unless `--replace` is supplied. HXTL v6 file-offset assignments require an exact binary size and SHA-256 match; on mismatch or older bundles without that identity, definitions still import while assignments are skipped. Virtual-address assignments also require matching source and recipe identity. See [type libraries](type-library.md) for identity and conflict options.

ARM/Thumb raw inputs use `--format raw --arm-profile mapping.profile`. The profile
declares physical code/data ranges and entry state; it replaces `--arch`, `--base`
and `--entry`, and cannot be combined with `--profile`. Both `inspect` and
`project create` accept it. Saved projects embed its canonical declarations and
retain them without the external profile file. Virtual domain coordinates use
`va:<domain>:<offset>`. Automatic ARM analysis remains incomplete; mapped manual
decoding and project annotations/patches/history are available. See
[ARM validation and profile grammar](arm-validation.md).

`hexlab_cli project --help` lists the persistent-project commands. A project embeds its original input and can reopen after that external file disappears. Queries open read-only; edits commit through the same project service used by desktop integration.

`hexlab_cli project integrity sample.hxproj --json` performs a bounded,
read-only SQLite integrity and foreign-key check against one revision-pinned
snapshot. See [project integrity CLI](project-integrity-cli.md) for output,
limits, and exit codes.

`hexlab_cli project schema sample.hxproj --json` checks the SQLite application
identifier and schema version in one read-only snapshot. It reports schemas
this build can read, newer schemas, and invalid or unreadable files without
opening the project for edits or applying migrations. Exit status 3 means the
stored schema is newer than this build; status 1 means the file is invalid or
unreadable. The JSON report includes stored/current versions and whether a
writable open would migrate a supported older schema.

Run `hexlab_cli project history audit sample.hxproj --verify-replay` to verify
the stored forward/inverse history payloads and replay the currently applied
branch backwards to the empty initial user state. Replay verification is
bounded to 4,096 applied steps and 64 MiB of delta payload; exceeding either
limit returns the corresponding resource-limit error. It is skipped when the
paginated audit is partial, and resumed audits must start from step zero when
this option is selected. JSON output uses schema version 2 when replay
verification is requested and includes `replay_verified`.

`hexlab_cli project history verify sample.hxproj --json` performs bounded
whole-history semantic verification, including every redo command, durable
cursor agreement and historical patch originals against verified embedded
input. `history audit --verify-history` runs that same check after structural
pagination completes. Semantic replay has separate `--replay-*` budgets; exit
3 means those budgets prevented a complete result. See
[history semantic verification CLI](project-history-verification-cli.md).

Inspect a reconstructed historical state without changing the project with
`hexlab_cli project history preview sample.hxproj --step 12`. The bounded
preview reports current and target record counts in text or `--json` form;
status 3 indicates the preview succeeded at a cursor other than the current
one. See [Project history preview CLI](project-history-preview-cli.md).

Publish an independent editable project at an exact history step with
`hexlab_cli project history save sample.hxproj --step 12 --output recovered.hxproj`.
The source stays unchanged and the output retains the complete undo/redo log.
Pass `--expected-edit` from a previous preview to pin the source revision, and
use `--replace` only when replacing an existing output is intended. See
[Save a historical project](project-history-save-cli.md).

Inspect validated interrupted saves and retained prior versions with
`hexlab_cli project recovery list <directory-or-project-path> [--json]`.
Passing a project path scans its containing directory, which is useful after
an open failure. Restore a listed
artifact to an independent project copy with
`hexlab_cli project recovery restore <artifact.tmp> --output <project.hxproj>`;
an existing output requires `--replace`. Discovery is read-only, restore
revalidates the artifact and publishes via the checked Save As path, and the
original artifact is retained. See [Project recovery CLI](project-recovery-cli.md).

Compare two automatically detected images without opening the desktop:

```powershell
./hexlab_cli.exe compare old.exe new.exe --limit 200
```

The command prints byte and region totals plus changed, added, and removed file-backed ranges. Recognized file-backed ELF/Mach-O relocation and fixup fields and x86/x64 PE base relocations are masked automatically; the ignored-byte total appears in text and JSON output. Mask discovery is bounded to one million fields and honors cancellation. `--window <bytes>` and `--anchor <bytes>` configure bounded insertion/deletion resynchronization. Region identity comes from segment name and occurrence; the command does not run function analysis. See [binary comparison](binary-comparison.md) and [relocation-aware comparison](binary-comparison-relocation-masks.md) for matching rules and limits.

From the build's `bin/Debug` directory:

```powershell
./hexlab_cli.exe project create sample.hxproj --input sample.exe
./hexlab_cli.exe project inspect sample.hxproj
./hexlab_cli.exe project rename sample.hxproj --at va:0x140001000 --name entry_point
./hexlab_cli.exe project comment sample.hxproj --at va:0x140001000 --text 'Check this call'
./hexlab_cli.exe project bookmark sample.hxproj --at va:0x140001000 --label entry
./hexlab_cli.exe project functions sample.hxproj
./hexlab_cli.exe project stack sample.hxproj --at va:0x140001000
./hexlab_cli.exe project decompile sample.hxproj --at va:0x140001000
./hexlab_cli.exe project decompile sample.hxproj --at va:0x140001000 --json
./hexlab_cli.exe project methods sample.hxproj
./hexlab_cli.exe project references sample.hxproj --at va:0x140001000 --direction outgoing
./hexlab_cli.exe project graph sample.hxproj --kind cfg --at va:0x140001000 --format json
./hexlab_cli.exe project graph sample.hxproj --kind function-calls --at va:0x140001000 --depth 2 --format dot
```

`project graph --kind function-calls` emits the caller/callee neighborhood around
the function owning `--at`. `--depth` expands both directions by 1 to 4 resolved
function-to-function hops; `--node-budget` and `--edge-budget` bound output and
report omitted graph content. Use `--format json` or `--format dot`; the existing
`--kind call` remains the image-wide call graph.

`project functions sample.hxproj --json` emits one
`hexlab.project-functions.v1` object for headless tooling. Each function row
contains its stable ID, typed entry location, current display name, completeness
and thunk flags, block count, and chunk ranges. The top-level completeness and
omitted-function count distinguish a complete catalog from bounded/partial
recovery. Text output is unchanged; JSON returns exit code 0 only when the
catalog and project analysis are complete, otherwise 3.

For a library catalog in FLAIR's text `.pat` format, `project flirt` matches
the loaded image's architecture and mode against recovered function entries:

```powershell
./hexlab_cli.exe project flirt sample.hxproj --definitions runtime.pat --provenance "vendor runtime 1.2"
```

The query prints candidate names, ambiguity, and bounded matching work. It
opens the project read-only and leaves naming decisions to an explicit edit.
See [signature catalogs](signatures.md) for supported records and limits.

To persist the source-bound candidate evidence without applying names, use
`project flirt-apply` with the same options. Inspect it later with
`project recognition-evidence --kind flirt`; this action requires a writable
project and does not modify user names or comments.

For PE files with CLR metadata, `project methods` rebuilds the MethodDef catalog from the embedded input and prints each method token, RVA, name, CIL status, generic arities, generic parameter flags, constraint tokens, and decoded instruction stream. `project managed-types` lists TypeDef tokens, full names, generic arities, parameter flags, and constraint tokens. These queries work after reopening the project and after the original input file is removed. Constraint tokens remain metadata identities; their names and semantic validity are not resolved. Method states make unsupported and malformed bodies explicit.

`project stack` reports conservative stack-relative slots for a recovered function entry. Offsets are relative to SP at entry, and each row includes access addresses plus read/write classification and `incoming_argument_abi`. Outgoing provenance reports the source instruction kind/address and consuming call address. x86-32 rows identify incoming argument slots at `+4` and above and exact outgoing push/call provenance when a contiguous push sequence is followed by a call and matching caller cleanup. The same outgoing provenance is retained for x86-64 when PE/ELF/Mach-O metadata selects an ABI and a contiguous push sequence is followed by a call and immediate matching `ADD RSP,N`; reserved stack areas and stores into preallocated outgoing slots are not attributed. AArch64 rows identify incoming stack argument locations at `+0` and above only when read through a tracked stack base; direct write-only SP-relative stores preceding a same-block direct `BL` retain source/call provenance. x86-64 uses image format as a default: PE selects Windows x64 (`+40` and above, after return address and 32-byte shadow space), while ELF and Mach-O select SysV AMD64 (`+8` and above). ELF64 MIPS with generic SysV/Linux OSABI metadata and no N32 or conflicting ABI selector classifies reads at `+0` and above as MIPS N64 overflow arguments after its eight register argument slots. These incoming classifications require reads. Raw/unknown formats and per-function ABI overrides remain unclassified/unsupported. A partial function or ambiguous stack depth returns exit status 3 while retaining slots that could be placed safely.

`project decompile <project> --at va:<entry>` opens the saved project read-only,
requires current complete or explicitly partial function analysis, and prints
typed pseudocode for the recovered function that begins at that exact virtual
address. It uses the project's embedded input, selected loader recipe, current
patches, and recovered function snapshot. The query is bounded to 100,000 blocks,
1,000,000 total recovered blocks in the snapshot, and 1,000,000 instructions in
the selected function. Missing entries, stale analysis, or budget overflow are
reported without changing project state. Exit status 3 marks partial function
or function-analysis coverage. Only the selected entry is decompiled; there is
no project-wide pseudocode dump.

`--json` emits one `hexlab.project-decompile.v1` object containing the entry,
complete/partial status, typed pseudocode (or structured fallback text and its
reason and fallback status), instruction totals, and instruction-origin rows
with address, stable instruction ID, and formatted source instruction. The origin array is capped at
100,000 rows and reports its omitted count and completeness; all decompile work
remains bounded by the same function, block, and instruction limits. Text mode
is unchanged. JSON returns the same exit status: 0 for complete and 3 for
partial analysis; query and decompilation errors keep their existing CLI status.
The object fields are `entry`, `analysis_status`, `partial`,
`pseudocode_format`, `fallback`, `structured_fallback_used`, `fallback_reason`,
`pseudocode`, `instruction_count`, `lifted_instruction_count`, `origin_rows`,
`omitted_origin_rows`, and `origin_rows_complete`.

Raw inputs require an explicit mapping. Choose `--arch x86-32` for flat 32-bit coordinates, `--arch x86-64` for long mode, `--arch 6502` for the NMOS 6502 decoder subset, or `--arch rv32` / `--arch rv64` for the base RISC-V integer subsets. The 32-bit base, entry and complete mapped extent must fit its address domain; 6502 coordinates are limited to 16 bits. Empty inputs still require a valid base:

```powershell
./hexlab_cli.exe project create code.hxproj --input code.bin --format raw --arch x86-64 --base 0x1000
./hexlab_cli.exe project define code.hxproj --at va:0x1000 --kind function
./hexlab_cli.exe project patch code.hxproj --at file:0 --bytes 'CC 90'
./hexlab_cli.exe project undo code.hxproj
./hexlab_cli.exe project redo code.hxproj
./hexlab_cli.exe project export code.hxproj --output patched.bin
./hexlab_cli.exe project save-as code.hxproj --output investigation.hxproj
```

Manual function entries can be reset to automatic recovery without deleting the
history record. `project undefine <project> --at va:<entry> --kind function`
removes the persisted function override as one undoable project command. See
[manual function-boundary management](function-boundary-management.md) for
entry, chunk, suppression, and reset behavior.

Patches replace existing initialized bytes without changing input length. Export writes the original plus the current overlay; it does not rebuild signatures or format checksums. Export and Save As require `--replace` for an existing destination, and protect known original/project paths and file aliases. Save As creates a new project UUID. Each accepted edit is durable; `save` checkpoints the current project.

Locations explicitly distinguish virtual addresses (`va:0x1000`) from canonical file offsets (`file:0`). Nonzero address spaces use `va:<space>:<address>`. Numeric arguments accept decimal or `0x` hexadecimal. Names/comments are Unicode arguments; textual reports escape controls, backslashes and nonASCII UTF-8 bytes. Graph JSON and DOT go to stdout and retain their own checked escaping.

Search uses the effective patched bytes and current decoded operands:

```powershell
./hexlab_cli.exe project search code.hxproj --kind bytes --pattern '48 8B ?? A? ?F' --limit 100
./hexlab_cli.exe project search code.hxproj --kind bytes --pattern '48 8B ?? A? ?F' --limit 100 --json
./hexlab_cli.exe project search code.hxproj --kind bytes --pattern '48 8B ??' --start va:0x401000
./hexlab_cli.exe project search code.hxproj --kind text --text HELLO --encoding utf16le
./hexlab_cli.exe project search code.hxproj --kind text --text hello --encoding utf8 --ignore-ascii-case
./hexlab_cli.exe project search code.hxproj --kind immediate --value -1 --width 64 --signed
```

Text encoding is explicit. `--ignore-ascii-case` folds ASCII `A`–`Z` only; non-ASCII encoded bytes remain exact. Immediate queries require width 8, 16, 32 or 64 and default to unsigned interpretation. A sign-extended 64-bit `-1` differs from an 8-bit `255` operand. Byte/text results carry canonical file offsets and attach an address only for a unique contiguous mapping. Immediate results identify the operand and preserve separate file ranges for instructions whose backing is split.

Pass `--start file:<offset>` to begin at an inclusive file offset, or `--start va:<address>` to begin at a mapped virtual address. For a virtual-address start, the query must map to unique file-backed bytes; immediate search also uses the address to choose among instructions that alias the same file offset. The first page starts there without wrapping. Continuation cursors already carry their next position and take precedence over `--start`.

A bounded search page can finish before the input ends. Pass the printed `Continuation` value back with `--cursor` and the same query/options. A changed byte/decision revision, recipe or analysis configuration rejects that continuation. `--candidate-budget` limits scan work; `--limit` limits returned hits. Reference paging uses `--offset` and `--limit`. Partial decoded facts remain explicitly partial even when their search page is exhausted.

`project search --json` emits one `hexlab.project-search.v1` object. File offsets and addresses are hexadecimal strings, unavailable addresses and operands are JSON `null`, disjoint immediate backing is retained in `file_ranges`, and `next` contains the continuation token for the next bounded page. `complete` reports whether the page exhausted the query; `source_complete` independently reports whether the analyzed input facts were complete. The command retains exit code 3 for an incomplete page or source.

Exit status is 0 for success, 1 for IO/unsupported/read-only/conflict errors, 2 for invalid arguments, and 3 for partial analysis or another result page. `--instruction-budget` and `--string-budget` select analysis bounds. Broader instruction sets and formats remain under development; see [instruction coverage](x64-coverage.csv) and [capabilities](capabilities.csv).

For machine-readable live image disassembly, use `hexlab_cli disassemble <path> --json`. The `hexlab.disassembly.v1` object contains the input path, complete/partial analysis status, and ordered instruction rows with formatted address, encoded bytes, rendered instruction, and control-flow kind. Add `--show-strings` to include bounded discovered string rows. A partial analysis returns exit status 3; complete analysis returns 0. JSON mode emits one object to stdout, while diagnostics remain on stderr. The current JSON option applies only to `disassemble` (not `inspect` or `decompile`).
