# Desktop graph workbench

The graph canvas shares the active location with the other analysis views. When
the listing or pseudocode view changes the selected address, the canvas focuses
the matching graph node and reveals it. For instruction addresses inside a
basic block, the containing block receives focus. Exact node locations take
precedence, which keeps function, boundary, and unresolved nodes addressable in
graphs that contain them. Graph search and node navigation continue to work
across every node kind, including nodes without a navigable address.

**Graph items** opens a native, keyboard-accessible list of every current node
and edge, including off-screen and addressless items. **F6** opens the list from
the canvas; F6 or Escape returns to the canvas. The canvas retains its existing
Tab/Shift+Tab node traversal. In the list, ordinary Tab moves to the read-only
item details and source actions, so keyboard users can leave graph traversal.
The Graph items button also hides the list when it is open.

Each row describes the node kind, stable graph ID, full label, location and
comment, or the edge kind and both endpoints with source and target locations
when present. Native row selection follows graph focus; the Graph state column
separately marks the canvas's graph-local multi-selection. Item details expose
the full description, current source address, graph status and selection count
in a read-only text control suitable for screen-reader review and copying.
Canvas clicks, graph searches, branch traversal and linked-view selection update
the list without moving keyboard focus. Arrow keys in the list focus an item
and synchronize its source through the same stale-graph guard; Enter follows
the focused node/instruction or edge using the existing graph follow behavior.
Opening the list preserves the current selection. A replacement or cleared
graph replaces or clears its rows, and partial graph status remains visible in
the details. The native list and text controls provide an accessible alternative
to the painted canvas; live assistive-technology validation remains outstanding.

Selecting a graph node or instruction still navigates the linked views through
the existing stale-graph guard. Unresolved external identities without a
location remain graph-local because they have no image address to navigate to.

**Show listing** and **Show pseudocode** open the respective workspace tab at
the focused graph source. A selected instruction uses its exact address; a
node header uses the node location; a focused edge uses its source location.
The status line shows that source, including its address-space ID. These
actions select the source without following its branch or call target.
Addressless nodes disable both actions. Pseudocode requires a virtual address;
when no recovered function owns the address, its existing unavailable-state
message explains why no source can be rendered.

Single clicks, graph search, Tab/Shift+Tab node traversal, and Up/Down instruction
traversal synchronize the listing and pseudocode while keeping the graph tab
and keyboard focus. Pseudocode selects the matching instruction in its address
table and reveals its source-origin line when one exists. The explicit Show
actions switch tabs. Returning to the graph retains its selected node or edge,
zoom, and layout while the graph model remains current. Nodes sharing a source
address keep their distinct graph focus, including after a background refresh;
the multi-selection range anchor is also preserved.

Selection synchronization captures the immutable source graph and validates
the active document, displayed document revision, image identity, controller
graph result, and project analysis revision before changing the global location.
Only locations present in that graph can synchronize. Address-space IDs remain
part of every comparison and image navigation, so matching numeric offsets in
different image domains do not alias. Rejected or unmapped sources leave the
linked views at their prior location and report the reason in Output.

**Enter** follows the selected instruction in the focused block, using that
instruction's exact address and the current graph facts. Double-clicking an
instruction uses the same path. This remains correct while a linked listing
page is still loading: the listing's previous instruction is never used as the
follow source. A node without a selected instruction navigates only to its own
location; a node without a location stays graph-local. A focused edge retains
its existing destination-follow behavior.

Instruction follow checks that the active document and graph are still current
before resolving a target. Only current, instruction-backed control-flow
references with unique executable source and destination ownership can be
followed. Stale facts, ambiguous targets, and missing targets do not fall back
to another instruction. When the current instruction has no resolved target,
its source remains selected in the linked views and the Output pane explains
why no target was followed. These operations do not alter graph facts.
