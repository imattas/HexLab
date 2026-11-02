# Multi-Pack Header Expansion Plan

**Goal:** Expand compound template arguments that zip multiple bound parameter packs of the same length.

**Architecture:** Identify all unqualified bound packs in one expansion pattern, require equal lengths, and parse one substituted pattern per index. Keep substitutions local to the nested parser so outer bindings remain unchanged.

**Files:** `libs/types/src/header_import.cpp`, `docs/capabilities.csv`, this spec and plan.

## Tasks

- [x] Generalize one-element pattern substitution to bind all pack elements at an index.
- [x] Detect participating packs, reject unequal lengths, and emit zipped expanded arguments under existing limits.
- [x] Update capability evidence and record unsupported nested ellipses.
- [x] Build Windows `hexlab_types`/`hexlab_cli` and WSL Clang `hexlab_types` with tests disabled; `git diff --check` passed.
