# Graph View Navigation

The desktop graph canvas supports mouse selection and keyboard traversal. Select a block or function node, then use **Ctrl+Right** to focus its first outgoing edge or **Ctrl+Left** to focus its first incoming edge. Press the same direction again to follow the focused edge to its adjacent node. The graph view highlights the focused edge and shows its kind and endpoints in the status line.

At a node with multiple outgoing edges, **Ctrl+Up** and **Ctrl+Down** cycle the candidate edges before following. Candidates have deterministic order for the current immutable graph model: conditional-true, conditional-false, fallthrough, jump, call, continuation, tail candidate, delay slot, then unresolved; ties use endpoint location and graph IDs. Incoming candidates use the same order.

Following a focused edge also pans the canvas just enough to bring its destination
node into view when it is offscreen. This keeps keyboard traversal visible across
large graphs while preserving the current zoom and the rest of the viewport.

Press **Enter** to follow a focused edge or selected node. Unmodified Up/Down still move through instructions. Left/Right still pan; Shift+Up/Down still pan vertically; Home fits the graph. Mouse drag, click, wheel zoom, and the Fit/zoom controls are unchanged.

Edges without a destination location remain focusable and visible. Following them moves graph focus to the neighboring node when that node exists, but does not invent an image address. The ordering is stable for one graph model revision; identifiers may change after reanalysis.

The graph toolbar has a case-insensitive **Find** field that searches node names,
comments, and rendered addresses in the current CFG or call graph. **Find** starts
at the first match; **Previous** and **Next** cycle through the current results.
The selected match is centered in the canvas, highlighted, and navigated to in
the listing when it has an address. External or unresolved nodes without an
image location can still be found and focused. Results are rebuilt when the
query or graph model changes.

The **Prev node** and **Next node** controls, or **Shift+Tab** and **Tab** while
the canvas has focus, cycle every placed node in row-major layout order. The
graph focus stays on the chosen node while a node with a unique location also
updates the linked listing and other location-following views. If navigation
rejects an address because the current graph revision is stale or ownership is
ambiguous, the graph-local focus remains available so the user can continue
through the graph without changing the global location.

Drag a node with the left mouse button to arrange the current graph for easier
inspection. Connected edge endpoints follow the moved node, and hit testing,
instruction selection, and node traversal use the adjusted positions. These
placements are local to the open canvas: requesting a different graph model or
revising the analysis restores the generated layout. The underlying graph model
remains immutable, so movement does not edit analysis facts or project history.

In **Function callers and callees** mode, the **Call depth** control expands the
selected function's known caller/callee neighborhood by one, two, or three
resolved function edges. The setting is retained for the current document while
switching graph modes; the image-wide graph and CFG ignore it. The analysis API
supports depths through four, subject to the same graph node and edge budgets.
