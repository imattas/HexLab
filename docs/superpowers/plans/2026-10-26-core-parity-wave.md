# Core Parity Expansion Implementation Plan

> **For agentic workers:** Use isolated worktrees and implement one independent subsystem task each. Do not add or run tests in this wave.

**Goal:** Advance native pseudocode structuring, PDB type import, and graph-to-analysis navigation as three substantial independent parts of the ongoing HexLab reverse-engineering workbench.

**Architecture:** Reuse existing bounded CFG/SSA validation in the decompiler, existing CodeView graph and type-library import paths, and immutable project graph models with stale-location checks. Unsupported or ambiguous inputs keep conservative fallback behavior.

**Tech Stack:** C++20, existing HexLab decompiler/types/desktop libraries, CMake, Windows Debug builds.

**Spec:** `docs/superpowers/specs/2026-10-26-core-parity-wave.md`

## Global Constraints

- Do not add or run tests; compile affected Debug targets only.
- Do not access, clean, or build `out/`.
- Keep the work headless; do not launch the desktop.
- Preserve cancellation, resource bounds, provenance, deterministic behavior, and conservative fallback.
- Do not add third-party dependencies.
- The root agent owns `docs/capabilities.csv`, integrated builds, and the push.

## Review Focus

- Decompiler joins require exact CFG predecessor coverage and must not duplicate blocks or misplace parallel phi copies.
- PDB import must retain exact type-server namespace ownership, reject malformed/ambiguous records, and avoid inventing layouts.
- Graph navigation must validate the current graph revision and target ownership before changing global selection.
- UI callbacks must not retain stale pointers across document closure or asynchronous reanalysis.

## Tasks

### Task 1: Native decompiler structuring

**Ownership:** `libs/decompiler/src/decompiler.cpp`, focused decompiler documentation, and no other subsystem.

- [x] Read `docs/capabilities.csv` and the structuring implementation; identified explicit-preheader post-tested loops with loop-carried SSA phis.
- [x] Implemented bounded recognition, exact edge/phi validation, and conservative fallback for ambiguous forms.
- [x] Documented limits; isolated Windows Debug `hexlab_decompiler` build passed.

### Task 2: PDB type import

**Ownership:** `libs/types/src/pdb.cpp`, `libs/types/src/pdb_import.cpp`, their public PDB/type headers, and focused PDB/type documentation.

- [x] Read the PDB/type capability entries; selected `LF_BINTERFACE` interface base subobjects.
- [x] Carried the leaf through bounded parse, type graph references, type-server remapping, and type import with source provenance.
- [x] Documented malformed/unsupported cases; isolated Windows Debug `hexlab_types` build passed.

### Task 3: Graph cross-view workflow

**Ownership:** `apps/desktop/graph_canvas.*`, `apps/desktop/graph_view.*`, tightly coupled main-frame wiring only when needed, and focused graph documentation.

- [x] Inspected graph callbacks; graph follow previously used the asynchronously rendered listing row instead of the focused graph instruction.
- [x] Graph follow now carries the exact instruction and graph snapshot and checks active document/image/revision plus reference and endpoint ownership.
- [x] Documented Enter/double-click behavior; MSVC Debug compiled graph canvas, graph view, and main frame translation units. No GUI launched.

### Integration

- [x] Reviewed all three diffs; independent task reviews approved all three tasks.
- [ ] Compile integrated Windows Debug CLI and desktop component targets serially where wxWidgets is available; graph translation units were compiled independently because configured wx source resides under prohibited `out/`.
- [x] Update capability evidence, commit the integration record, and push `feat/foundation`.
