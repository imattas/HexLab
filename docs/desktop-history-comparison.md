# Desktop history step comparison

The History page can compare a selected durable edit step with the immediately preceding step. Select a history row and choose **Compare with previous step**. HexLab reconstructs both read-only states through the project actor, then appends a **Change summary** row for every durable user-state collection: annotations, bookmarks, breakpoints, named types, type assignments, function decisions, regions, user references, debug variables, and patches. Each row shows added, removed, and modified counts. Entities match by their stable ID; patches match by their starting file offset.

The normal table continues to show the selected step's full historical projection. Before the collection totals, the comparison adds one row for each added, removed, or changed entity in annotations, bookmarks, breakpoints, named types, type assignments, function decisions, regions, user references, and debug variables. A detail row shows its stable ID, the entity's relevant location or name, and a bounded before/after description for edits. Patch spans remain represented by their collection-level totals because they have no stable row ID. At most 512 detail rows are displayed; if more changes exist, an explicit row reports that the remainder was omitted. Navigation still targets entries from the selected-step state; comparison rows have no navigation target.

The comparison is bounded by the same history replay step and payload budgets as ordinary previews. Entities use stable IDs. Patches are grouped by starting file offset, identical rows at the same offset match first, and remaining same-offset rows count as edits; this handles repeated starts without collapsing rows. Patch rows do not display a byte-by-byte diff.

Choose **Compare with current project** to compare the selected historical step against the live project's immutable state captured at the current edit revision. It uses the same collection totals, stable entity matching, and 512-row detail cap as the previous-step comparison. The result is discarded if the selected-step preview or current project identity/edit revision no longer matches the captured context. This comparison is read-only; use **Save selected step as project...** below to continue from a historical state without replacing the current project.

To continue from a selected historical state, choose **Save selected step as
project...**. HexLab reconstructs that exact step into a separate project with a
fresh UUID, retaining its undo/redo history while leaving the source open and
unchanged. The save dialog defaults beside the source; the revision guard is
enabled by default so publication fails if the source changed after preview.
After publication, **Open saved project** opens the independent copy directly.
The button is available only while the saved copy still belongs to the current
History-page project context. Replay is bounded to 4,096 steps and 64 MiB of
history payload; exceeding either bound fails without publishing a partial
project. Saving the current cursor is also allowed.
