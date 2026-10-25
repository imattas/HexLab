# Analysis, Symbols, and Recovery Expansion Plan

> **For agentic workers:** Use the subsystem assignment in the wave spec; each task has independent file ownership.

**Goal:** Add bounded split-type cross-unit DWARF resolution, stronger signed switch-range proofs, and live evaluation for supported PDB local fragments.

**Architecture:** Preserve each subsystem's existing API and add evidence only inside its current analysis pipeline. Any unsupported or ambiguous input falls back to the existing conservative result or explicit diagnostic.

**Tech Stack:** C++20, CMake, MSVC Debug targets, existing HexLab loader/analysis/debugger models.

**Spec:** `docs/superpowers/specs/2026-10-28-analysis-symbols-recovery-wave.md`

## Global Constraints

- Keep parsing, proof, reads, result counts, and allocations bounded and cancellation-aware where APIs already support cancellation.
- Reject malformed or ambiguous evidence; never guess a type target, switch bound, register mapping, or parent value.
- Preserve existing C++/wxWidgets architecture and public persistence compatibility.
- Do not read, write, clean, or build `out/`.
- Do not add or run tests; compile affected Debug targets and review source paths.
- Keep subsystem ownership separate; root owns capability ledger and integration.

## Review Focus

- Forward and cyclic DWARF dependencies must not resolve to a wrong unit or expose incomplete imports.
- Switch bounds must be proven across all known incoming paths, with exact signedness and width semantics.
- PDB fragment reads must not overflow parent/type extents or use an unavailable register/memory source.

### Task 1: Forward cross-unit DWARF references

**Files:** `libs/symbols/include/hexlab/symbols/`, `libs/symbols/src/dwarf.cpp`, `libs/loaders/src/elf_dwarf.cpp`, and `docs/dwarf-v5-import.md`; focused Debug builds of `hexlab_symbols` and `hexlab_loaders`.

- [x] Inspect current unit indexing and dependency ordering; ordinary forward CU/TU references are already supported. Add a bounded package-level shared identity map and resolve uniquely identified `DW_FORM_ref_sig8` references across split type-unit contributions using TU-index signatures.
- [x] Preserve explicit malformed/unsupported diagnostics for ambiguous, cyclic, missing, or non-type targets; update the DWARF capability documentation.
- [x] Compile `hexlab_symbols` and `hexlab_loaders` Debug; do not run tests.

### Task 2: Signed switch-range proofs

**Files:** `libs/analysis/src/switches.cpp`, `docs/switch-analysis-validation.md`; focused Debug build of `hexlab_analysis`.

- [x] Inspect existing guard graph and typed compare/branch semantics; add a bounded proof for a concrete signed/normalized range pattern supported by decoded instruction facts.
- [x] Require exact selector width, signedness, known incoming edges, unchanged selector, and checked bound arithmetic; ambiguous paths keep the current partial verified-prefix behavior.
- [x] Document the accepted shape and limits; compile `hexlab_analysis` Debug; do not run tests.

### Task 3: PDB subfield and indirect local evaluation

**Files:** `libs/types/include/hexlab/types/pdb.hpp`, `libs/types/src/pdb.cpp`, `libs/image/include/hexlab/image/pe_metadata.hpp`, `libs/loaders/src/pdb_lines.cpp`, `apps/desktop/debugger_locals.cpp`, and `docs/debugger-pdb-locals.md`; focused Debug builds of affected targets.

- [x] Preserve CodeView subfield-kind and parent-offset/spill/indirect fields and unique aggregate field extents through PE metadata transfer; inspect range selection, register mapping, value sizing, and debugger memory callbacks; evaluate a subfield only when exactly one resolved member at that offset has a bounded known type size.
- [x] Bounds-check offsets and memory reads, keep unavailable or malformed values explicit, and document supported fragment semantics.
- [x] Compile `hexlab_desktop_components` Debug; do not run tests or launch the GUI.

### Integration

- [x] Review each subsystem diff against the shared constraints and ensure no overlapping source ownership.
- [x] Compile the integrated `hexlab_desktop_components` Debug target if focused builds are insufficient.
- [x] Update `docs/capabilities.csv` only for source/build-supported claims and confirm `out/` remains untouched.


**Integration evidence:** `cmake --build switch-desktop-build --target hexlab_desktop_components --config Debug --parallel 1` completed successfully (2026-10-29). The integrated target compiled and linked the DWARF package resolver, signed switch proof, PDB fragment metadata/evaluator, and desktop components. No tests were added or run; `out/` was left untouched.
