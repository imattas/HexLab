# Changelog

## 0.1.1 — 2026-10-31

### Improved

- Dockable Ghidra-inspired workspace with a dedicated decompiler pane beside
  the listing, separate Functions and Symbols navigation, and independent
  metadata and output panes. Existing saved view IDs remain compatible.
- Graph canvas pans by dragging empty space with the left mouse button;
  middle-button panning and node movement remain available.
- CLI help is grouped and easier to scan. The new `hexdump` command prints
  address, hexadecimal, and ASCII columns with bounded `--offset`, `--length`,
  and `--width` options.
- Name search checks and sorting can be canceled during large searches, and
  ambiguous exact-name matches are returned in bounded pages.
- Fixed desktop startup initialization order so the String browser callback is
  installed only after the view exists, and corrected Objective-C metadata
  control parenting.

## 0.1.0 — 2026-10-31

First public HexLab release. This version packages the current C++20 analysis
engines, wxWidgets desktop application, command-line tools, and debugger server.

### Included

- Desktop workbench for binary and project tabs, synchronized disassembly,
  byte, graph, and pseudocode views, metadata/reference panes, search,
  navigation, annotations, patches, types, and plugin management.
- CLI workflows for image inspection, disassembly, decompilation, project
  operations, dependency reports, comparison, and binary export.
- Loaders and metadata support for common PE, ELF, Mach-O, COFF, archive,
  firmware, managed-code, WebAssembly, and minidump formats, with bounded
  parsing and explicit diagnostics for unsupported input.
- Processor and analysis engines for selected x86, ARM/AArch64, PowerPC, MIPS,
  RISC-V, MOS 6502, WebAssembly, JVM, and DEX instruction subsets; function,
  reference, string, switch, stack, and signature analysis.
- A conservative typed decompiler, persisted project annotations and history,
  a native plugin SDK, Python automation, native x86-64 debugging, and a GDB
  Remote Serial Protocol client.
- Relocatable Windows, Linux, and macOS packages with third-party notices and
  SHA-256 sidecars.

### Known limits

HexLab is an early development release. The capability inventory lists the
measured support and remaining work; many instruction variants, binary format
details, ABI rules, decompiler constructs, debugger targets, and desktop
workflows remain partial. Decompiled output is conservative and may leave
unsupported semantics explicit or incomplete.

The Windows ZIP includes HexLab and non-system runtime DLLs but requires the
matching Microsoft Visual C++ 2022 Redistributable. Python automation uses a
host Python runtime. Linux and macOS packages are built and smoke-checked by
their native CI runners, but CI does not launch the GUI. The packages are
multi-file installations; they are not standalone executables.
