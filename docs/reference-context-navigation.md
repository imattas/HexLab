# Reference endpoint context

The References page shows context beside each source and target. For mapped locations the endpoint context includes the persisted or imported name, an exact-address comment when present, the containing recovered function (with an offset from its entry), and the mapped image segment. File-offset endpoints resolve their segment through the segment's file-backed range; external or unresolved targets keep their target description and show `-` for endpoint context.

Use **Navigate → Incoming References** (`Ctrl+Shift+X`) or **Outgoing References** (`Ctrl+Alt+X`) to open references for the current selection. The listing context menu offers the same operations for the row under the pointer, or the selected row when opened with the keyboard. Opening this menu or a reference set leaves the workspace address and history unchanged. When an interior-byte selection falls inside a decoded instruction in the current listing page, the query uses that instruction's start without changing the selected byte. Other address and file-offset queries keep their original domain.

These commands open the References page with **Pin context** enabled. The origin label identifies the queried location. Clicking an incoming row navigates to its source; clicking an outgoing row navigates to its resolved target, or to its source when the target is external or unresolved. With the context pinned, navigation updates the listing, bytes, and other context views while preserving the reference origin, direction, page, and selected reference. Use **Go to source** or **Go to target** to visit either endpoint of the selected reference, and **Go to origin** to return to the queried location. Target navigation is disabled for external and unresolved targets; no numeric destination is invented. These navigation actions use the ordinary Back/Forward history.

Clear **Pin context** to resume following the current workspace selection. Pin state, direction, page position, and selected reference belong to each open document independently. Switching documents restores that document's browsing context; closing a document removes its retained reference state. Pinned contexts are session-only and are not saved in the analysis project.

Pinning retains a location, not an obsolete analysis snapshot. Project updates refresh the query from the current immutable reference index. Pending or unavailable analysis clears the navigable rows, and the pane reports the analysis state. If a refreshed page is now empty, browsing returns to its first page; a selected reference is restored only when its identity still exists on that page. Queries remain bounded to 256 rows and use the existing indexed snapshot service; the new actions perform no decoding, file loading, or analysis on the GUI thread.

ELF references derived from a validated primary vtable slot are labeled **ELF vtable slot**. Only slots with one validated executable target produce these address references; unresolved, ambiguous, null, and non-executable slots remain absent.

Validation for this increment is limited to source-only MSVC compilation. No tests, linking, or GUI interaction were performed; keyboard delivery, native menu layout, and runtime multi-document browsing still require later interactive verification.


## Relation details

Selecting a row shows a bounded relation inspector below the table. It presents the stable reference identity, endpoints, kind, operand access and index, instruction or user identity, association, and provenance origin counts. Dataflow producer instruction IDs are capped at 16 in the display, with the remaining count summarized. The inspector follows the selected row as pages and analysis snapshots refresh; when no selected reference remains, it clears rather than showing stale metadata. Existing source, target, origin, and row navigation remain available.
