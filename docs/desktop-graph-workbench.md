# Desktop graph workbench

The graph canvas shares the active location with the other analysis views. When
the listing or pseudocode view changes the selected address, the canvas focuses
the matching graph node and reveals it. For instruction addresses inside a
basic block, the containing block receives focus. Exact node locations take
precedence, which keeps function, boundary, and unresolved nodes addressable in
graphs that contain them. Graph search and node navigation continue to work
across every node kind, including nodes without a navigable address.

Selecting a graph node or instruction still navigates the linked views through
the existing stale-graph guard. Unresolved external identities without a
location remain graph-local because they have no image address to navigate to.

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
