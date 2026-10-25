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
