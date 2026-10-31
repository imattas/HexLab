# Reference endpoint context

The References page shows context beside each source and target. For mapped locations the endpoint context includes the persisted or imported name, an exact-address comment when present, the containing recovered function (with an offset from its entry), and the mapped image segment. File-offset endpoints resolve their segment through the segment's file-backed range; external or unresolved targets keep their target description and show `-` for endpoint context.

When an endpoint belongs to a recovered function, its context may also show
`calls` and `called by` summaries. These use only resolved `call` references
from the current, key-matched reference index; indirect calls without a proven
address are omitted. A relationship is shown only when its address maps to an
executable image segment and resolves to a recovered function. The inspection
is bounded to eight function chunks, 128 indexed references per direction and
chunk, and six displayed functions per direction. Context summaries group
callers and callees by function and report multiple call sites. The caller and
callee chooser retains each distinct function/call-site pair, so separate
calls to the same function remain individually navigable. Consequently, large
functions or incomplete reference pages can have omitted relationships; this
is a compact context hint, not a complete call graph.

Use **Navigate → Incoming References** (`Ctrl+Shift+X`) or **Outgoing References** (`Ctrl+Alt+X`) to open references for the current selection. The listing context menu offers the same operations for the row under the pointer, or the selected row when opened with the keyboard. Opening this menu or a reference set leaves the workspace address and history unchanged. When an interior-byte selection falls inside a decoded instruction in the current listing page, the query uses that instruction's start without changing the selected byte. Other address and file-offset queries keep their original domain.

These commands open the References page with **Pin context** enabled. The origin label identifies the queried location. Clicking an incoming row navigates to its source; clicking an outgoing row navigates to its resolved target, or to its source when the target is external or unresolved. With the context pinned, navigation updates the listing, bytes, and other context views while preserving the reference origin, direction, page, and selected reference. Use **Go to source** or **Go to target** to visit either endpoint of the selected reference, and **Go to origin** to return to the queried location. Target navigation is disabled for external and unresolved targets; no numeric destination is invented. These navigation actions use the ordinary Back/Forward history.

Clear **Pin context** to resume following the current workspace selection. Pin state, direction, page position, and selected reference belong to each open document independently. Switching documents restores that document's browsing context; closing a document removes its retained reference state. Pinned contexts are session-only and are not saved in the analysis project.

Pinning retains a location, not an obsolete analysis snapshot. Project updates refresh the query from the current immutable reference index. Pending or unavailable analysis clears the navigable rows, and the pane reports the analysis state. If a refreshed page is now empty, browsing returns to its first page; a selected reference is restored only when its identity still exists on that page. Queries remain bounded to 256 rows and use the existing indexed snapshot service; the new actions perform no decoding, file loading, or analysis on the GUI thread.

Use **Filter page** to narrow the currently displayed reference page by a
case-insensitive substring. It searches all visible row fields, including
source, target, kind, evidence, association, and endpoint context. The status
line reports the number of matches on the page and the total query count.
Filtering does not alter the underlying query or page offset; use Previous or
Next to inspect other pages.

ELF references derived from a validated primary vtable slot are labeled **ELF vtable slot**. Only slots with one validated executable target produce these address references; unresolved, ambiguous, null, and non-executable slots remain absent.

Validation for this increment is limited to source-only MSVC compilation. No tests, linking, or GUI interaction were performed; keyboard delivery, native menu layout, and runtime multi-document browsing still require later interactive verification.


## Relation details

Selecting a row shows a bounded relation inspector below the table. It presents the stable reference identity, endpoints, kind, operand access and index, instruction or user identity, association, and provenance origin counts. Dataflow producer instruction IDs are capped at 16 in the display, with the remaining count summarized. The inspector follows the selected row as pages and analysis snapshots refresh; when no selected reference remains, it clears rather than showing stale metadata. Existing source, target, origin, and row navigation remain available.

Choose **Copy selected TSV** to copy the selected reference as field/value rows
for the document ID, stable reference ID, source, target, kind, and the current
bounded relation-inspector details. Tabs, line breaks, carriage returns,
backslashes, and other control bytes are escaped. The 64 KiB clipboard cap
rejects oversized or invalid UTF-8 output; copying uses the retained reference
page and does not issue a new query or navigate either endpoint.
