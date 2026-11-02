# Debugger Patch Batch UI Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline. No subagents or tests per task authorization.

**Goal:** Expose recoverable batch patches and guarded undo in the desktop debugger.
**Architecture:** Modal grid editor queues guarded mutations onto the existing inspection worker and returns reports through lifetime/generation-checked UI callbacks.
**Tech Stack:** C++20, wxWidgets, DebugSession.
**Spec:** docs/superpowers/specs/2026-11-02-debugger-patch-batch-ui-design.md

## Global Constraints
No tests, CI, push, root-worktree edits, or artifact deletion. Preserve the existing single-range write flow. Core limits are 256 ranges and 1 MiB.

## Review Focus
- Changed attachment or stop while queued: reject before writes and discard stale completion.
- Cancel before/during writes: retain rollback detail and leave event pending.
- Expected mismatch: report no writes and keep prior guarded undo.
- Incomplete rollback: show uncertain rows and snapshots, clear obsolete undo.
- Dialog close/destruction: prohibit close while running and cancel at owner destruction.

### Task 1: Implement modal batch workflow
**Files:** apps/desktop/debugger_view.cpp/.hpp
**Interfaces:** DebugSession::apply_memory_patches and restore_memory_patches; InspectionState worker/backend_mutex and generation tokens.
- [x] Add editor state, row parsing, apply/undo/cancel controls and report formatting.
- [x] Queue the operation with session/stop guards, lifetime-safe completion, and cancellation.
- [x] Reset attachment-scoped state and pause event polling while batch is running.

### Task 2: Verify and document
- [x] Build windows-desktop with BUILD_TESTING=OFF.
- [x] Review complete diff and core contract coverage, document workflow/limits and build evidence.
- [x] Commit only scoped source and documentation; preserve output artifacts.


## Validation and handoff

- Native managed worktree creation was delayed; authorized fallback used the ignored `.worktrees/debugger-patch-batch-ui` directory, branch `codex/debugger-patch-batch-ui`, base `b88335752eeae14722880f18f00127829bb99d16`.
- Configured successfully with `cmake --preset windows-desktop -DBUILD_TESTING=OFF -DFETCHCONTENT_SOURCE_DIR_WXWIDGETS=G:/HexLab/out/build/windows-desktop/_deps/wxwidgets-src`.
- Initial `cmake --build --preset windows-desktop --target hexlab --parallel 4` compiled the changed debugger view but failed at existing `session_listing.cpp` with MSVC C1128 (COFF section limit).
- Retried successfully using the compiler environment `_CL_=/bigobj` and the same build command. Exit 0; `out/build/windows-desktop/bin/Debug/hexlab.exe` linked. This workaround changes only the invocation, not repository CMake files. Existing exported-STL/deprecation/signedness warnings remain.
- `git diff --check` passed. Reviewed row parsing, overlap/overflow bounds, cancellation, report states, retained undo/redo, worker serialization, modal lifetime and generation invalidation inline. No additional agents, tests, GitHub CI or pushes were used, per authorization.
- Windows supplies the relevant desktop compile/link validation, so WSL/headless builds were not necessary and were not attempted.
- Runtime debugger interactions remain unexercised. The editor intentionally excludes main-window actions while open; backend calls may only be canceled between calls, and reports/editor drafts exist only for the current attachment/application lifetime. Full reports may be several MiB at the core byte limit.
- The source, build logs and output artifacts are preserved; no cleanup is performed. Parent-owned capability ledger is untouched.
