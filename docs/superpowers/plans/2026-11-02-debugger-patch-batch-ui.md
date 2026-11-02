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
- [ ] Add editor state, row parsing, apply/undo/cancel controls and report formatting.
- [ ] Queue the operation with session/stop guards, lifetime-safe completion, and cancellation.
- [ ] Reset attachment-scoped state and pause event polling while batch is running.

### Task 2: Verify and document
- [ ] Build windows-desktop with BUILD_TESTING=OFF.
- [ ] Review complete diff and core contract coverage, document workflow/limits and build evidence.
- [ ] Commit only scoped source and documentation; preserve output artifacts.
