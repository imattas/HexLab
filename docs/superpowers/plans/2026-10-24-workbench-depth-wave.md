# Workbench depth wave implementation plan

> **For agentic workers:** Use independent subsystem ownership. No tests may be added or run; compile-only verification is handled by the root after integration.

**Goal:** Advance three major user workflows: managed exception control flow, persistent Mach-O exception metadata, and desktop Python automation.

**Architecture:** Extend the existing lifted CIL exceptional CFG, expose source-backed Mach-O LSDA records in the project metadata view, and embed the existing Python API in a dockable wx console using a background interpreter worker and read-only active-project facade.

**Tech Stack:** C++20, wxWidgets, SQLite project storage, optional CPython embedding.

**Spec:** `docs/superpowers/specs/2026-10-24-workbench-depth-wave.md`

## Global Constraints

- Do not add or run tests.
- Do not touch `out/`.
- Preserve project schema/codec compatibility with a versioned migration when required.
- Keep parsers/evaluators bounded and report unsupported or malformed cases explicitly.
- Root owns `docs/capabilities.csv`, this plan, the integrated Debug build, and final review.

## Review Focus

- Nested, overlapping, malformed, or cross-boundary CIL filter/fault ranges must fail closed or retain explicit incomplete output.
- Mach-O LSDA references, action chains, and type-table pointers must not outlive validated image bounds or lose source provenance during persistence.
- Python exceptions, cancellation, closing the active project, and output flooding must not block or access destroyed wx/project state.
- Optional Python-disabled builds must remain supported.
- Existing project files must still open without fabricated LSDA/Python state.

## Tasks

### Task 1: Managed CIL filter and fault control flow

Status: complete; independent source review found no remaining issues.

**Files:** `libs/decompiler/src/cil_lifting.cpp`, `libs/loaders/src/cil.cpp` only if opcode decode is needed, `docs/managed-cil-exception-regions.md`.

Implement bounded filter-region boundaries, `endfilter` result routing in clause order, and fault handlers on exceptional unwind only. Preserve existing catch/finally continuation semantics, opaque type matching, and explicit incomplete status. Reject ambiguous region nesting and invalid `endfilter` placement. Do not claim runtime assignability or exact throwability.

### Task 2: Mach-O LSDA metadata and UI

Status: complete; independent review fixes were applied and re-reviewed clean. Project durability is source-backed through retained input bytes; no duplicate SQLite cache was added.

**Files:** `libs/image/include/hexlab/image/macho_metadata.hpp`, `libs/loaders/src/macho_commands.cpp`, `libs/workspace/include/hexlab/workspace/macho_presentation.hpp`, `libs/workspace/src/presentation.cpp`, `apps/desktop/macho_view.*`, `docs/macho-eh-frame.md`.

Reuse LSDA/personality records reconstructed from the project's retained source image on reopen; do not duplicate derived metadata in SQLite. Add UI rows for per-function LSDA, landing pads, action chains, personality resolution, and type-info references, retaining source provenance. Do not execute personality code or infer C++ catch behavior.

### Task 3: Desktop Python console

Implementation and independent code review are complete; the native cancellation finding was fixed and re-reviewed. Python-disabled Debug and Python-enabled Release desktop builds passed. Python-enabled Debug linking is unsupported by this installed release-only CPython package (`_ITERATOR_DEBUG_LEVEL` and CRT mismatch). Remaining limit: shutdown may wait for blocking native/filesystem calls and script-created non-daemon Python threads.

**Files:** `apps/desktop/CMakeLists.txt`, desktop frame/pane implementation, `libs/automation/src/python_module.cpp`, `libs/automation/python/hexlab.py`, `docs/python-automation.md`.

Add an optional wx console that runs Python in a dedicated worker, attaches a read-only automation project facade to the active saved project, supports multiline input, cancellation on shutdown, and bounded output. Preserve Python-disabled builds and avoid opening a second writable project session.

### Root integration

**Task 3 review note:** The reviewer confirmed stop-source ownership, analysis/export cancellation, and 50 ms debugger-wait polling. A docs-only finding was addressed: non-daemon Python threads may keep CPython finalization waiting until they exit.

**Ruling:** Source-backed loader metadata already survives project reopen because the project retains the original image bytes and reparses them. A duplicate SQLite LSDA cache is rejected as redundant derived state with additional migration risk.


Reconcile documentation installs and the three capability rows, scan touched sources, and confirm `out/` has no status changes. Leave this plan active if any subtask is incomplete.
