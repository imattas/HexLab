# Desktop history step comparison

The History page can compare a selected durable edit step with the immediately preceding step. Select a history row and choose **Compare with previous step**. HexLab reconstructs both read-only states through the project actor, then reports added, removed, and modified counts for annotations, bookmarks, named types, and type assignments. The normal table continues to show the selected step's full historical projection, and navigation still targets that selected-step state.

The comparison uses stable entity IDs. It is bounded by the same history replay step and payload budgets as ordinary previews. Changes to function/region decisions, user references, debug variables, and patch contents are not yet included in the comparison counts.
