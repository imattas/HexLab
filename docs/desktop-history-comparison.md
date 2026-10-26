# Desktop history step comparison

The History page can compare a selected durable edit step with the immediately preceding step. Select a history row and choose **Compare with previous step**. HexLab reconstructs both read-only states through the project actor, then appends a **Change summary** row for every durable user-state collection: annotations, bookmarks, breakpoints, named types, type assignments, function decisions, regions, user references, debug variables, and patches. Each row shows added, removed, and modified counts. Entities match by their stable ID; patches match by their starting file offset.

The normal table continues to show the selected step's full historical projection, followed by the comparison summary rows. Navigation still targets entries from that selected-step state; summary rows have no navigation target.

The comparison is bounded by the same history replay step and payload budgets as ordinary previews. Entities use stable IDs. Patches are grouped by starting file offset, identical rows at the same offset match first, and remaining same-offset rows count as edits; this handles repeated starts without collapsing rows. Patch rows do not display a byte-by-byte diff.
