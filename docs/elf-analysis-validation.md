# ELF analysis and delivery validation

This stage adds original C++ ELF32/ELF64 loading, static analysis and persistent
CLI/wxWidgets workflows to the multi-tool/shared-DLL suite. The full IDA-class
objective remains active; completing this ELF stage does not complete that objective.

## Observed implementation

REL allocated sections retain separate section address domains. EXEC/DYN use
declared PT_LOAD virtual addresses, initialized file backing and zero-filled BSS.
Original bytes are never relocated in place. Symbol and relocation namespaces,
REL/RELA addends, dynamic strings and supported hash bounds retain their source.
PT_NOTE and PT_GNU_PROPERTY records retain program/file provenance, note type,
name and raw description bytes; SHT_NOTE views are included for relocatable
objects and deduplicated by exact note file offset. GNU property type 5 entries
are decoded with ELF-class alignment and target byte order. Every property's
type, raw payload and source offsets survive, including unknown types; exact
four-byte values are also exposed as integers. The known x86
`GNU_PROPERTY_X86_FEATURE_1_AND`, `GNU_PROPERTY_X86_ISA_1_NEEDED`,
`GNU_PROPERTY_X86_ISA_1_USED`, and AArch64
`GNU_PROPERTY_AARCH64_FEATURE_1_AND` properties must have exactly four data
bytes; unknown property types retain their bounded payload without type-specific
size assumptions. The CLI identifies x86 FEATURE_1_AND IBT/SHSTK bits,
x86 ISA_1_NEEDED/USED baseline/v2/v3/v4 bits, and AArch64 FEATURE_1_AND
BTI/PAC/GCS bits while showing unknown bits and bounded raw prefixes. These are
file compatibility claims, not proof that instructions or the runtime actually
enforce them.
Malformed extents and incomplete property headers are rejected within the
bounded metadata budget. Existing ELF32/ELF64 fixtures include GNU build IDs.
PT_LOAD access flags retain their ELF meaning during image normalization: PF_X,
PF_W and PF_R independently set executable, writable and readable permissions.
Allocated sections with a declared alignment greater than one must have an
aligned virtual address; section alignment values must also remain zero, one,
or a power of two. This rejects malformed loaded-section metadata without
inventing file-offset alignment rules for nonallocated debug sections.
The ELF image tests exercise all eight combinations for ELF32/ELF64 in both byte
orders; the existing R|X-only fixtures would not expose an accidental R/X swap.
Unknown symbol counts, CPU/endian contexts, relocations and runtime-dependent
relationships remain explicit rather than inferred from arbitrary scans or host
libraries. Full DWARF/types, runtime dynamic linking, core dumps, more machine
psABIs and Linux/macOS delivery remain future work.

Dynamic string metadata retains bounded `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`,
`DT_RUNPATH`, `DT_CONFIG`, `DT_DEPAUDIT`, `DT_AUDIT`, `DT_AUXILIARY`, and
`DT_FILTER` values from the validated dynamic string table. Repeated dependency,
filter, and audit entries preserve their original order. The CLI labels these
rows, but does not search paths, load filtees, read configuration files, or run
audit callbacks; see [ELF dynamic string tags](elf-dynamic-string-tags.md).

The CLI accepts `--format auto|pe|elf|raw`. `inspect`, `disassemble` and persistent
`project create` share the loader/recipe services. Native Symbols and ELF metadata
tabs use immutable worker results; symbol record and dynamic-row indexes avoid
GUI I/O, parsing, SQL, decoding and full-table scans. Undefined symbols navigate
to their canonical original file record. Source-bound references drive Follow.
Native Jump accepts `va:domain:offset` from an initial file view; numeric offsets
retain the selected domain. Invalid or overflowed domains preserve selection.

## Evidence recorded so far

- Frontend checkpoint: headless Debug 70/70, Release 70/70 and desktop 83/83 in
  `out/elf-task6-full-{debug,release,desktop}.log`.
- `elf_oracle` compares 38 authored and freshly compiled/linked inputs against
  observed LLVM 23.1.3; source, hashes, exact tool invocations, output hashes and
  per-input limitations are recorded in `tests/fixtures/elf_oracle/` and generated
  `elf-oracle/<configuration>/report.json`. Inputs are never executed. Six forged
  semantic projections, malformed input and a missing tool must fail. The local
  tool hashes are observed binary identities, not publisher verification.
- Genuine old derived formats 1–4 and a captured format-5 payload from the prior
  arithmetic engine are retained byte-for-byte. The current engine misses the
  genuine old key and rejects an old payload forged under a new key, recomputes
  readonly from embedded original bytes and preserves UUID/user state/history.

## Observed delivery gates

| Gate | Result | Evidence under `out/` |
| --- | --- | --- |
| Headless Debug / Release | 71/71 each | `elf-final-debug-tests.log`, `elf-final-release-tests.log` |
| Desktop after qualified-domain Jump fix | 84/84 | `elf-final-desktop-tests.log` |
| Fresh disconnected headless Debug | 71/71; no dependency-fetch directory | `elf-final-offline-tests.log` |
| Fresh production Release | `BUILD_TESTING=OFF`; all eight engines exclude GUI/oracle imports and private test exports | `elf-final-production-build.log`, `elf-final-production-boundary.json` |
| Production workflows | ELF, PE/raw and segmented CLI; original ELF differential oracle | `elf-task7-production-*.log` |
| Production CPU checks | x64 LEA 6, native x86 51, x86-16 emulator agreement 37 | `elf-task7-production-*-cpu.log` |
| Installed public SDK | External consumer built only against installed headers/import libraries; all eight DLL paths verified | `elf-final-sdk.log` |
| Installed ELF | Ten focused engine/project targets; 38 independent oracle inputs; CLI workflows | `elf-final-installed-tests.log` |
| Installed regressions | Segmented workflows, CPU agreement and 100 old-cache/history checks | `elf-final-installed-segmented.log` |
| Actual installed application | ELF32/64, qualified REL domain Jump, PE32 and segmented x86-16; engine/wx paths and own-window captures | `elf-task7-installed-rel64-green.log`, `elf-task7-installed-*.log` |
| Installed native workflow | Actual controls, edits/history/export/reopen, mixed tabs, held late completion and qualified Jump | `elf-final-installed-native.log` |

The multi-file developer bundle is `out/install/ElfDebug`. Its runtime includes
the native application, CLI, eight engine/runtime DLLs and wxWidgets DLLs; public
headers/import libraries and dependency notices are installed alongside them.
The Debug bundle supports development/validation; the separate production
Release build excludes private test hooks. Windows x64 is the validated host.
Existing ProjectAnalysisDebug, X86ModeDebug and SegmentedDebug installations are
preserved.

Installed file hashes are recorded in `validation/install-inventory.json` within
the bundle; engine and application binaries match the accepted build. One fresh
independent whole-stage review found three material defects. Each has a failing
regression followed by a passing fix, with the full suites above green.
The overall IDA-class goal remains active.

Retained static relocations in linked EXEC/DYN files preserve their raw records;
they do not reapply the linked instruction bytes as an original REL addend.
Nonallocated debug relocation fields use checked section/file coordinates, with
no invented virtual mappings. The compiler matrix covers debug EXEC/DYN with
and without retained relocations. Persistent source binding/cache supports ELF
section domains under a 32 MiB domain-table budget and the existing 64 MiB
payload budget; 4,095/4,096/4,100-domain boundary and source-missing cache reopen
checks pass. A compiler-generated 4,100-function object also passes persistent
production CLI analysis and source-missing reopen. The engine fingerprint was
advanced so old derived results recompute without altering user history.

Post-review evidence: `out/elf-final-fixes-red.log`,
`out/elf-final-fixes-green.log`, `out/elf-final-compiler-projects.log`,
`out/elf-final-production-oracle.log` and
`out/elf-final-actual-retained-debug64.log`. The installed actual application
opens the previously rejected debug executable and renders mapped code, with
all runtime paths verified and own-window captures inspected.

For AArch64 ELF64, relocation metadata now classifies ABS16/32/64, PREL16/32/64,
COPY, GLOB_DAT, JUMP_SLOT, RELATIVE, the common DTPMOD/DTPREL/TPREL TLS data
relocations, TLSDESC, IRELATIVE, CALL26 and JUMP26. Field widths are checked
against the target section, symbol indexes retain their linked-table validation,
and RELA addends retain their signed encoded value. This is descriptive metadata:
the loader does not evaluate relocation formulas, resolve runtime libraries,
decode instruction-field encodings, or apply patches. AArch64 instruction
relocations beyond CALL26/JUMP26 and other architecture ABIs remain unsupported.

Remaining validation limits include worst-case fuzz/performance and allocation
failure campaigns, malformed UTF-8 native-name rendering, other hosts and LLVM
publisher authenticity. Runtime linking and later full-goal capabilities remain
outstanding, rather than being claimed by this stage.
