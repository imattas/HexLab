# Graph Edge Navigation Implementation Plan

> **For agentic workers:** Use independent subsystem ownership. Compile only; do not add or run tests.

**Goal:** Add keyboard-first predecessor/successor navigation to the graph canvas with branch-edge focus and useful status feedback.

**Architecture:** Build deterministic incoming/outgoing adjacency maps once in `GraphCanvas::set_graph`. Reuse the existing `GraphHit` state to highlight selected nodes and edges, while `GraphView` derives status from the canvas focus. Preserve existing mouse and unmodified keyboard behavior.

**Tech Stack:** C++20, wxWidgets, existing immutable `ProjectGraph` model.

**Spec:** `docs/superpowers/specs/2026-10-27-graph-edge-navigation.md`

## Global Constraints

- Do not add or run tests; root owns compile-only verification.
- Do not touch `out/` or the shared build tree.
- Do not modify graph models, persistent project data, or MainFrame/plugin bridge files.

## Review Focus

- Graph replacement clears invalid focus and rebuilds indexes without stale edge pointers.
- Branch alternatives use deterministic order and stay within outgoing/incoming adjacency.
- Edges with no target location remain focusable but do not cause invalid navigation.
- Existing arrow, Shift+arrow, Enter, mouse, and selection behavior remain compatible.
- Status strings safely format unresolved/external nodes and absent endpoints.

## Task 1: Indexed focus and keyboard traversal

**Files:** `apps/desktop/graph_canvas.hpp/.cpp`, `apps/desktop/graph_view.hpp/.cpp`, `docs/graph-view.md`, scoped SDD files.

- [x] Inspect graph model, canvas hit-testing, current shortcuts, and existing graph documentation.
- [x] Add incoming/outgoing edge indexes built once by `set_graph`; sort by semantic kind and stable endpoint/ID keys.
- [x] Implement Ctrl+Left/Right edge selection/follow and Ctrl+Up/Down sibling edge cycling using existing `GraphHit` highlights.
- [x] Add canvas focus description for node/edge and render it in the existing graph status label.
- [x] Document shortcuts, edge-without-location behavior, and ordering stability limits.
- [ ] Review pointer invalidation and graph replacement; root compiles `hexlab_desktop_components` Debug. No tests.
