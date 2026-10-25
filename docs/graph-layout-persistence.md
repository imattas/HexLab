# Graph layout persistence

The desktop graph canvas saves manually dragged node positions in the user's
wxWidgets configuration. A saved layout is keyed by the graph model SHA-256,
so different graph kinds and analysis revisions keep separate placements.
Switching views or closing and reopening the application restores positions
for the exact same graph model.

Use **Reset layout** to discard the saved positions for the current graph and
return to the generated layout. **Fit** remains available to frame the current
positions after moving nodes.

The settings record is versioned and bounded to 8,192 nodes and 1 MiB. It stores
node IDs and fixed-point coordinates, and restores only when every current node
has exactly one valid saved position. Malformed, oversized, incomplete, or
stale settings are ignored; the generated layout remains usable. Node width,
height, and edge routing remain generated from the current graph, with edge
endpoints following manually moved nodes.
