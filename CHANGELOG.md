# Changelog

## 0.1.0 — 2026-10-30

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
