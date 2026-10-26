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

- [ ] Read `docs/capabilities.csv` and the structuring implementation; identify one high-impact native CFG/SSA shape currently falling back.
- [ ] Implement bounded recognition and exact edge/phi validation for that shape; preserve the existing fallback for ambiguous forms.
- [ ] Document the new accepted shape and remaining limits; compile `hexlab_decompiler` Debug or the changed object plus integrated CLI if dependencies prevent the standalone target.

### Task 2: PDB type import

**Ownership:** `libs/types/src/pdb.cpp`, `libs/types/src/pdb_import.cpp`, their public PDB/type headers, and focused PDB/type documentation.

- [ ] Read the PDB/type capability entries and identify one common unsupported CodeView record path with a user-visible type-library outcome.
- [ ] Carry it from bounded parse/graph validation through type import, preserving type-server namespace and provenance.
- [ ] Document unsupported and malformed cases; compile `hexlab_types` Debug.

### Task 3: Graph cross-view workflow

**Ownership:** `apps/desktop/graph_canvas.*`, `apps/desktop/graph_view.*`, tightly coupled main-frame wiring only when needed, and focused graph documentation.

- [ ] Inspect graph focus/selection callbacks and linked listing/pseudocode navigation; identify one high-impact synchronization gap.
- [ ] Implement the workflow with stale graph and location validation and without mutating immutable graph facts.
- [ ] Document keyboard/mouse behavior and compile the affected desktop components Debug; do not launch the GUI.

### Integration

- [ ] Review all diffs for bounds, exact provenance, stale-state handling, and fallback behavior.
- [ ] Compile integrated Windows Debug CLI and desktop component targets serially where wxWidgets is available.
- [ ] Update capability evidence, commit the integration record, and push `feat/foundation`.
