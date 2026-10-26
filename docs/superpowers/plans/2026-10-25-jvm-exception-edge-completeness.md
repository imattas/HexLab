# JVM Exception Edge Completeness Plan

> **For agentic workers:** Use the isolated JVM worktree; keep changes limited to exception edge completeness and its docs.

**Goal:** Prevent incomplete JVM exceptional CFGs and throw-site sets from being presented as complete decompilation facts.

**Architecture:** Keep analysis as the source of bounded CFG edges and make the lifter consume only complete exception coverage. Keep throw-capable opcode classification consistent between analysis and lifting.

**Tech Stack:** C++20, HexLab analysis/decompiler libraries, MSVC Debug.

**Spec:** `docs/superpowers/specs/2026-10-25-jvm-exception-edge-completeness.md`

## Global Constraints

- Preserve bounded resource use and method-local address spaces.
- Do not add or run tests; compile affected Debug targets and inspect source paths.
- Leave `out/` untouched; do not launch the desktop.

## Review Focus

- A method exceeding the exceptional-edge row cap must be rejected or explicitly incomplete, never silently decompiled with missing handlers.
- Analysis and lifting must agree on resolution/bootstrap-capable constant-pool loads.
- Handler order and distinct catch clauses must remain intact.

## Task 1: Complete and consistent throw-site evidence

**Files:** `libs/analysis/src/functions.cpp`, `libs/decompiler/src/jvm_lifting.cpp`, `docs/jvm-analysis.md`.

- [x] Inspect the current throwing-opcode predicates and exception scan cap.
- [x] Synchronize classification for `ldc`, `ldc_w`, and `ldc2_w`, preserving conservative handling for unknown constants.
- [x] Ensure incomplete/capped exception-edge coverage is surfaced to the lifter as an explicit failure or incomplete result, including ambiguous ownership paths.
- [x] Compile `hexlab_analysis` Debug and decompiler Debug `ClCompile`; do not run tests.

## Integration

- [x] Review the complete flow from class-file exception rows through CFG construction and lifting.
- [x] Root updates `docs/capabilities.csv` with the exact implementation and build evidence.

**Integration evidence:** `hexlab_analysis` Debug build completed successfully, including the modified function-recovery source. Serial MSBuild `ClCompile` of `hexlab_decompiler` completed successfully, including the JVM lifter. Existing MSVC warnings remain. No tests were added or run; `out/` was untouched.
