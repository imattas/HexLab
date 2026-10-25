# Graph node multi-selection

CFG and call graph nodes support a bounded, graph-local multi-selection.

- Click a node to make it the sole graph selection.
- Ctrl-click (Cmd-click on macOS) toggles a node in the selection.
- Shift-click selects the inclusive range from the last selection anchor in graph navigation order. Ctrl+Shift-click adds that range to the current selection.
- Selection is capped at 256 nodes. The status line reports the selected count when more than one node is selected.

The focused node remains the navigation target. Selecting a node continues to navigate the linked listing, bytes, and other location-aware views through the existing single-location selection contract. A graph selection remains local to the graph and does not alter analysis results or saved node placements. Node positions continue to persist independently of selection.
