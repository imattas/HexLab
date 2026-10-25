# Analysis, Types, and DWARF Work Plan

## Goal

Advance three distinct engine subsystems toward the approved full IDA-scale destination: control-flow/switch analysis, the shared type model and ABI layout, and DWARF debug-information import.

## Constraints

- Preserve the original C++20 monorepo and wxWidgets product scope.
- Do not launch, focus, or interact with the desktop application; it is open on the user's second monitor.
- Preserve the active common decompiler work. Do not edit `libs/decompiler/src/decompiler.cpp`, `docs/decompiler-structuring.md`, or active decompiler tests.
- Each workstream owns its subsystem implementation and focused documentation; no edits to the shared plan, capability ledger, CMake/build lists, or tests by agents.
- Do not add or run tests. Compile changed components without linking over DLLs loaded by the open application.
- Keep all parsing and analysis bounded, cancellable, provenance-aware, and explicit about unsupported cases.

## Independent Workstreams

1. **Control-flow and switch analysis** — improve the analysis path end to end across supported architecture-neutral evidence; avoid architecture-specific patches that bypass shared control-flow invariants.
2. **Type model and layout** — advance the common type representation and ABI layout behavior in a way that preserves serialization and existing imported types.
3. **DWARF import** — extend the ELF/DWARF reader and importer as one coherent debug-information workflow with exact contribution bounds and reference validation.
4. **ELF static linking** — continue the library-linking engine by allocating ELF `SHN_COMMON` symbols into merged writable zero-fill storage with correct precedence over weak definitions and under strong definitions.

## Integration

- Review changed code, data bounds, compatibility, and support documentation.
- Compile the affected component sources and record any loaded-module link constraint.
- Update capability evidence only after review.
- The full IDA-scale objective remains active after this wave.

## Wave Progress

- Switch analysis added a bounded local AArch64 compare/branch proof for two common switch-table guards and instruction-fact cancellation/budget checks. General dominance and range analysis remain future work.
- The shared type model now preserves const/volatile/restrict qualifiers through version 8 serialization and layout. ABI classification and Python `TypeSpec` round-tripping unwrap or preserve the qualified node. Importers still need broader qualifier population.
- DWARF v5 type-unit `ref_sig8` dependencies resolve forward references across units before importing the referring unit; cycles and missing signatures are rejected.
- ELF static linking now merges `SHN_COMMON` into `.bss`, coalesces max size/alignment, and applies strong/common/weak precedence. The archive symbol summarizer already recognizes nonzero `st_shndx` common rows as providers for member selection.
- Source compilation was invoked for loaders, types, analysis, and automation in the Windows Debug solution. MSVC emitted existing DLL-interface/conversion warnings; no tests or desktop relinks were performed.
