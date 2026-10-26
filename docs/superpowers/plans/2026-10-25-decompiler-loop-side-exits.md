# Decompiler Loop Side Exits Plan

> **For agentic workers:** Use the isolated decompiler worktree; do not edit analysis or desktop files.

**Goal:** Structure one additional reducible loop side-exit pattern with exact CFG/SSA validation.

**Architecture:** Extend the existing loop-region recognizer and emitter in `decompiler.cpp`; only emit a structured loop after proving unique ownership, complete edge coverage, and exact phi predecessor sets. Unsupported shapes retain current fallback.

**Tech Stack:** C++20, HexLab decompiler library, MSVC Debug.

**Spec:** `docs/superpowers/specs/2026-10-25-decompiler-loop-side-exits.md`

## Global Constraints

- Preserve CFG semantics, side effects, and simultaneous SSA updates.
- Do not add or run tests; compile the affected Debug target and inspect source paths.
- Leave `out/` untouched; do not launch the desktop.

## Review Focus

- Multiple exits must not emit shared cleanup more than once or move it onto the wrong path.
- Phi copies must execute only on their actual predecessor edges and preserve simultaneous values.
- Block ownership and all unresolved/extra edges must be validated under existing bounds.

## Task 1: Add a bounded loop side-exit recognizer

**Files:** `libs/decompiler/src/decompiler.cpp`, `docs/decompiler-structuring.md`.

- [ ] Inspect existing pre-tested and post-tested recognizers to select the smallest common unsupported side-exit shape.
- [ ] Recognize only that explicit shape; validate exact CFG ownership, exit joins, and register/memory phis under current limits.
- [ ] Emit parallel phi copies on original edges and preserve existing fallback for other shapes.
- [ ] Compile the Debug decompiler target; do not run tests.

## Integration

- [ ] Review the complete CFG coverage and side-effect ordering for the accepted shape.
- [ ] Root updates `docs/capabilities.csv` with exact implementation and build evidence.
