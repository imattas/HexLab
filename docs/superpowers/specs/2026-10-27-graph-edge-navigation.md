# Edge-Aware Graph Keyboard Navigation

## Intent

Make CFG and call graph traversal usable from the keyboard. The graph canvas already supports indexed hit testing and click navigation, but arrow keys only pan or move through instructions; users cannot follow control-flow edges without returning to the mouse.

## Goals

- Give graph nodes and edges a stable keyboard focus derived from semantic graph IDs and deterministic adjacency order.
- Preserve existing instruction stepping, panning, mouse selection, and Enter behavior.
- Let users select and follow predecessor/successor edges, including cycling alternatives at branch nodes.
- Show the focused node/edge kind in the graph status bar.
- Keep navigation bounded by graph model size and avoid full graph scans for each key press.

## Non-goals

- No graph model, layout, persistence, or analysis changes.
- No automatic layout changes, minimap, or graph editing.
- No changes to existing click behavior or instruction order.
- No tests may be added or run under the active task constraint; root owns compile-only verification.

## Approaches

1. Recompute adjacent edges by scanning every edge on each key press. Simple, but repeated navigation cost grows with the full graph size.
2. Build stable incoming/outgoing adjacency indexes when a graph is installed. This adds small per-canvas storage, makes each key action proportional to local degree, and centralizes deterministic edge order. Chosen.
3. Replace arrow shortcuts with a full graph command palette. More discoverable, but changes established key behavior and requires wider UI work.

## Design

`GraphCanvas::set_graph` builds incoming and outgoing edge-ID vectors keyed by node ID, sorted deterministically by semantic edge-kind priority and then target/source location and edge ID. The current graph focus is represented by the existing optional `GraphHit`: a focused edge anchors branch cycling; otherwise the current node comes from a focused node or the node matching the selected address.

Ctrl+Right selects the first/next outgoing edge from a node, then follows the selected edge to its target on a subsequent Ctrl+Right. Ctrl+Left mirrors this for incoming edges. Ctrl+Up/Ctrl+Down cycle sibling candidates around the focused edge without navigating. Enter continues to follow a focused edge or selected node. Edge navigation prefers `target_location`/`selection` and falls back to the adjacent node's selection. Missing candidates do nothing. Ctrl+navigation is limited to graph focus; existing unmodified arrows continue their previous panning/instruction behavior.

GraphView status reports the focused edge kind and endpoints, or the focused node label, along with existing node/edge counts and partial-topology state. New status text is bounded from the model's already-bounded labels.

## Limits

The canvas does not synthesize control-flow semantics for unresolved edges. Edges without navigable locations remain focusable and are identified by status, but following them only changes focus. Determinism follows the immutable model IDs and edge kinds for a given model revision; IDs are not claimed stable across revisions.
