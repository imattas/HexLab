# HexLab 0.1.0

HexLab 0.1.0 is the first public development release. Download platform
packages from the [GitHub release page](https://github.com/imattas/HexLab/releases/tag/v0.1.0).
This release makes the current workbench installable and reviewable; it is an
early-stage reverse-engineering tool, not feature-complete IDA Pro parity.

See [the changelog](CHANGELOG.md) for release highlights and known limits.

A C++20 and wxWidgets reverse-engineering suite under development. Its shared engines and desktop/headless CLI handle raw images, PE, ELF, Mach-O, Windows minidumps, firmware, managed metadata, and archives; processor coverage includes x86-16/32/64 (including selected x87 and SSE2/scalar SIMD slices), A32/Thumb, AArch64, PowerPC PPC32/PPC64 integer and selected scalar floating-point instructions, MIPS32/MIPS64 little-endian subsets, and RV64I/M/C subsets. Projects persist analysis facts, annotations, type definitions and assignments, histories, bookmarks, and derived caches. Analysis includes function/control-flow and call graphs, cross-references, UTF-8/16/32 string candidates, stack slots, switch tables, bounded versioned multi-entry signature catalogs with explicit ambiguous matches, CFG-aware binary comparison, and exact binary export. ABI classification covers recursive aggregates for SysV AMD64, Windows x64, and x86 cdecl; the application also has bounded DWARF v4/v5 and PDB import with decoded location expressions and persistent DWARF parameters/locals, a typed decompiler with register SSA, conservative C-like structuring, and editable names/types for uniquely mapped pseudocode values; native Win32/Linux x86-64 debugging plus GDB Remote Serial Protocol over TCP with target XML register descriptions and selected Linux AVX-512 registers; bounded live-context unwinding for PE AMD64/ARM64 and runtime evaluation of linked Mach-O compact-unwind recipes; and a versioned plugin ABI with loaded-plugin capability dependency checks.

The desktop provides synchronized disassembly, bytes, graph, and partial pseudocode views; metadata and reference panes; search/navigation; editing and project workflows; debugger controls; plugin management; an Analysis Issues triage page; and a Types & Symbols browser. The type editor creates and edits pointers, arrays, enums, and function prototypes in addition to integer and structure definitions. The CLI provides consistent project backups and read-only exchange previews; Python exposes recovered stack-frame and local-slot data. This remains a partial implementation: many instruction variants, formats, ABI rules, debugger targets, source-level decompilation, and extension points are still incomplete. See the [capability inventory](docs/capabilities.csv) for the measured scope.

See [building](docs/building.md), the [capability inventory](docs/capabilities.csv), the [approved architecture](docs/superpowers/specs/2026-10-19-hexlab-design.md), and [project-stage validation](docs/project-analysis-validation.md).

The monorepo separates `apps/desktop`, `apps/cli`, and `apps/debug-server`, with shared core, image, loader, processor, type, analysis, database, workspace, debugger, plugin and decompiler libraries. SQLite is a separate vendored DLL. The desktop, CLI, and debugger server use the shared engines; the desktop also uses wxWidgets DLLs.

```text
bin/                 GUI, CLI, debugger server, engine/runtime DLLs and wxWidgets DLLs
lib/                 Engine import libraries
include/hexlab/      Public development headers
share/hexlab/        Documentation and dependency licenses
```

```powershell
cmake --preset windows-headless
cmake --build --preset windows-headless
ctest --preset windows-headless
./out/build/windows-headless/bin/Debug/hexlab_cli.exe inspect path/to/program.exe
./out/build/windows-headless/bin/Debug/hexlab_cli.exe project --help
```

Linux and macOS headless presets are also provided; each builds the CLI and test suite with the host C++ toolchain:

```sh
cmake --preset linux-headless # or macos-headless
cmake --build --preset linux-headless --target hexlab_cli # or macos-headless
ctest --preset linux-headless # or macos-headless
```

The desktop provides independent binary/project tabs, Disassembly/Bytes/Graph pages, metadata/reference panes, navigation/history, clipboard actions, Find/Next/Previous, committed names/comments/bookmarks, code/data/function decisions, patches, undo/redo, Save As and checked export. File > Open Project opens saved databases; another editable process produces visible readonly ownership. Dialogs and both tools use shared validated commands. Background work uses per-document actors and a bounded two-worker pool.

Graph views support node/edge selection, follow, pan, anchored zoom, Fit and per-document CFG/call choices. Unsupported, partial, stale and file-only states remain explicit. Corrupting a header preserves effective file bytes and retained orphan annotations; undo can restore mapping. Unknown instruction forms remain stops. Raw profiles provide segmented x86 contexts. ELF objects preserve distinct section domains; native Jump accepts qualified addresses such as `va:1:0x0`.

The current developer install is `out/install/ElfDebug`; install the complete directory, including DLLs and other files. Earlier installation baselines are retained. See the [ELF validation](docs/elf-analysis-validation.md), [project CLI](docs/project-cli.md), [storage/schema guide](docs/project-format.md), [instruction coverage](docs/x64-coverage.csv) and [reference requirements baseline](docs/reference-coverage.md).

See [x86-32 validation](docs/x86-32-validation.md) for explicit mode selection, cache compatibility and selected independent Win32 execution evidence.
