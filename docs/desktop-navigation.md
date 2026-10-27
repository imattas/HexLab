# Desktop navigation

The pseudocode workbench supports document-owned caret state, address selection,
SSA definition navigation, and bounded source occurrence browsing. See
[pseudocode and SSA navigation](desktop-pseudocode-navigation.md).

Use **Jump…** (`G`) to navigate by virtual address, file offset, segmented
address, bookmark, annotation name, or function name. Name matching is
case-insensitive. If multiple names resolve to the same location, they count
as one destination. If a name resolves to different locations, HexLab presents
a chooser showing each matching name and formatted location; choosing an entry
navigates there, while canceling leaves the current selection unchanged.

The named-navigation candidate model used by **Jump** also accepts address-bearing image
symbols: PE imports resolve to their IAT slots, PE exports and PDB symbols
resolve to their virtual addresses, and defined ELF and Mach-O symbols resolve
to their image addresses. ELF names imported from DWARF subprogram DIEs are
also candidates when they retain at least one concrete code range, which makes
functions in stripped ELF files reachable by name. Unresolved or addressless
records are omitted;
ordinal imports and exports use labels such as `ordinal 7`. Repeated records
for one name and address produce one choice, while the same name at distinct
addresses remains ambiguous and opens the destination chooser. Headless tests
exercise the same metadata-to-candidate and resolver helpers used by the Jump
command. Exact matching is case-insensitive. If no exact name matches, **Jump**
offers a case-insensitive substring suggestion list for queries of at least two
characters. Suggestions are sorted deterministically, duplicate destinations
are collapsed, and choosing one is required before navigation; at most 128
distinct destinations are shown. Numeric addresses and displacement expressions
keep their normal parsing priority. Named locations and numeric addresses also
accept a checked signed displacement, for example `entry+0x20`,
`0x401000+0x20`, or `bookmark-4`.
The Jump dialog exposes loaded
segments as `section:.text` and `segment:.text`; adding a nonnegative offset
such as `section:.text+0x20` navigates only when the destination remains inside
that segment's mapped extent. Address arithmetic rejects overflow and
underflow. Ambiguities are resolved after applying the displacement, so aliases
that land at one address remain a single destination. A
`va:` prefix continues to force numeric virtual-address parsing when a name
happens to look like an address.

## Graph navigation

Selecting an instruction in a function graph moves the shared selection to
that instruction in the listing, pseudocode instruction list, and reference
view. Up and Down traverse recovered instructions and blocks; the bounded
block preview scrolls to keep the selected instruction visible. Enter or
double-click follows a selected instruction's target, and Back returns to the
previous selection. File-offset selections are resolved through the loaded
image mapping before graph navigation. Unresolved call nodes are not part of
the instruction cursor order.

Graph clicks, instruction traversal, edge following, and node focus route
through the same workspace navigation history as listing and pseudocode
navigation. Back and Forward restore the exact saved location and resynchronize
the listing, graph, references, and pseudocode source caret. Pseudocode source
lines navigate only when they carry an explicit instruction-origin marker;
synthetic lines remain unmapped. Before a graph action navigates, the desktop
checks that the displayed graph still matches the active project's source and
presentation revisions. A stale graph action is rejected, and a rejected
action cannot trigger Follow using the listing's previous selection.

The graph canvas indexes node and routed-edge bounds by horizontal position
when a graph changes. Painting and hit testing first query the visible canvas
range, then preserve layout order for overlapping nodes and edge selection.
This keeps routine redraw and pointer interaction proportional to nearby graph
content instead of scanning every node and route in a large graph.

Right-clicking a graph node opens actions for its exact displayed location:
copy the node label or location, navigate to that location, rename addressable
nodes, add a comment, or toggle a bookmark. Right-clicking an edge offers its
description, target navigation, and location comment/bookmark actions. Nodes
without an address still support copying their label. Annotation actions pass
through the normal project action pipeline, so its revision checks, undo
history, and read-only rules still apply.

## Disassembly and bytes navigation

The listing and bytes panes share the main document selection. Selecting a byte
row navigates to its first byte; Left and Right in the bytes pane move the
selection one byte at a time. The selected byte is bracketed in the hex column,
and the listing keeps the containing instruction or data row selected when the
cursor is inside that row. When navigation lands in the middle of an instruction
already present in recovered analysis, the listing opens on that instruction's
start while retaining the exact byte as the active selection. Address and file
offset selections correlate through the loaded image mapping; ambiguous or
unmapped conversions do not invent a correspondence. Project actions continue
to use the exact active selection, including selections inside an instruction.

## Function list actions

The docked **Functions** browser shows recovered function address, presentation
name, block count, and completeness. Its filter matches names and formatted
addresses as you type. Clicking a column header sorts the list; clicking a row
navigates to that function entry. Filtering and sorting affect only the browser
view and do not change analysis order or saved project state.

In an editable project, right-click a recovered function row to navigate to
its entry and open function-specific project actions. The menu provides
rename, comment, and bookmark commands for the selected entry, plus the
existing define-function, chunk, and suppression commands. These commands use
the same project action validation and edit history as the Edit menu, so
read-only projects keep the actions disabled and successful changes remain
undoable. On the keyboard, open the context menu for the selected function row
to use the same commands.

## Cross-document address history

Back and Forward use a bounded main-frame history (up to 512 address selections) across open documents. A history destination retains its document ID, immutable document revision, project UUID/revision tuple when available, and address or file offset. Replaying a destination activates its owning tab before restoring the location. Closed documents, replacement document snapshots, changed project identities/revisions, and unmapped locations are skipped as stale entries. New navigation after Back truncates the forward branch. Name Jump continues to present a destination chooser whenever an exact name resolves to multiple distinct locations; substring suggestions also require an explicit destination choice.

Two history entries are distinct when their document or project revision identity changes, even if the selected address is the same. A failed navigation does not add the previous selection to history.


## Browsing address history

Use **Navigate > Browse History...** to choose any retained address selection directly. The list is chronological, marks the current history position with *, and labels each entry with its open document name when available. Choosing an entry activates its owning document and restores the exact address or file offset. Closed documents, changed immutable document revisions, changed project identities or revisions, and unmapped destinations are rejected with a status message. Canceling the chooser leaves the current selection unchanged. The chooser covers the same bounded history used by Back and Forward (up to 512 entries).
