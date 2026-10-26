# PE FH3 Exception Planner Bounds Plan

> **For agentic workers:** Use the isolated PE worktree; limit changes to planner input validation and its docs.

**Goal:** Bound and validate every public metadata collection traversed by `plan_pe_fh3_exception`.

**Architecture:** Add planner-local caps and validate sorted IP rows, owning function extents, state indices, and referenced code/data addresses before producing cleanup and catch candidates.

**Tech Stack:** C++20, HexLab image/CLI libraries, MSVC Debug.

**Spec:** `docs/superpowers/specs/2026-10-25-pe-fh3-planner-bounds.md`

## Global Constraints

- Preserve advisory results and never invoke target code.
- Do not add or run tests; compile affected Debug targets and inspect source paths.
- Leave `out/` untouched; do not launch the desktop.

## Review Focus

- Unsorted/duplicate/out-of-function IP-state rows must not reach `upper_bound` or select a misleading state.
- Excessive unwind, try, handler, or IP rows must stop before unbounded traversal/allocation.
- Malformed predecessor/state/address references must return explicit diagnostics.

## Task 1: Revalidate caller-owned planner inputs

**Files:** `libs/image/src/pe_unwind.cpp`, `docs/pe-exception-directory.md`.

- [x] Inspect the FH3 planner's assumptions against parser guarantees and public metadata structs.
- [x] Add documented count caps and validate ordered, function-owned IP rows and all state/handler references before planning.
- [x] Preserve ambiguous/candidate dispositions when serialized ordering cannot prove runtime selection.
- [x] Compile the affected Debug image target; do not run tests. The broader CLI dependency build was stopped after the image target completed.

## Integration

- [x] Review parser-produced and caller-constructed metadata flows.
- [x] Root updates `docs/capabilities.csv` with exact implementation and build evidence.

**Integration evidence:** `hexlab_image` Debug build passed after the final planner changes. No tests were added or run; `out/` was untouched.
