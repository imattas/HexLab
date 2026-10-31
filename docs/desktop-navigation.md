# Desktop navigation

The pseudocode workbench supports document-owned caret state, address selection,
SSA definition navigation, and bounded source occurrence browsing. See
[pseudocode and SSA navigation](desktop-pseudocode-navigation.md).

Use **Jumpâ€¦** (`G`) to navigate by virtual address, file offset, segmented
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
functions in stripped ELF files reachable by name. Named DWARF alternate
entry points with a direct `DW_AT_low_pc` are also candidates at that exact
address; they do not claim a function range. Unresolved or addressless records
are omitted;
ordinal imports and exports use labels such as `ordinal 7`. The Jump candidate
set includes both stored names and supported demangled C++ spellings for image
symbols, so readable names such as `Widget::open(int)` can reach a destination
whose file symbol is mangled. Raw spellings remain searchable, and alias
spellings at one address collapse to one destination. Repeated records
for one name and address produce one choice, while the same name at distinct
addresses remains ambiguous and opens the destination chooser. Headless tests
exercise the same metadata-to-candidate and resolver helpers used by the Jump
command. Exact matching is case-insensitive. If no exact name matches, **Jump**
offers a case-insensitive substring suggestion list for queries of at least two
characters. Suggestions are sorted deterministically, duplicate destinations
are collapsed, and choosing one is required before navigation. The suggestion
chooser searches the original captured name sources again after each text
refinement, with a short typing delay. A narrower query can therefore find
destinations excluded from an earlier capped result set. It displays at most
4096 distinct destinations per query and reports truncation. Numeric addresses
and displacement expressions keep their normal parsing priority. Named
locations and numeric addresses also accept a checked signed displacement,
for example `entry+0x20`, `0x401000+0x20`, or `bookmark-4`.
Current-document and cross-document refinement run on background workers, so
searching large captured name sets does not hold the wx event loop. Current
document Jump captures its symbols, annotations, bookmarks, recovered functions,
and sections as immutable search inputs before the chooser opens; the worker
retains those inputs even if the dialog closes. While a query is being scanned,
the old result list is cleared and navigation is disabled. Rapid refinements
are coalesced to the newest query; completed results are accepted only for their
matching query generation. Cross-document workers likewise own immutable
captured project snapshots, and every chosen destination is checked against the
live document session and project snapshot before navigation. Search caps still
apply, so large source sets can report partial results and benefit from a
narrower scope or query. When a newer cross-document refinement arrives, the
active worker checks a cancellation token while traversing captured names and
stops early; it then scans only the newest queued refinement. A worker may
finish its current bounded match or ranking operation before noticing
cancellation.
The Jump dialog exposes loaded
segments as `section:.text` and `segment:.text`; adding a nonnegative offset
such as `section:.text+0x20` navigates only when the destination remains inside
that segment's mapped extent. Address arithmetic rejects overflow and
underflow. Ambiguities are resolved after applying the displacement, so aliases
that land at one address remain a single destination. A
`va:` prefix continues to force numeric virtual-address parsing when a name
happens to look like an address.

The suggestion chooser offers **All name sources**, **Image symbols**,
**Annotation names**, **Bookmarks**, **Recovered functions**, and **Sections /
segments** scopes. Its **Contains**, **Starts with**, and **Exact name** modes
are case-insensitive. Contains and Starts with need at least two characters;
Exact name accepts one. A nonnumeric name miss opens the chooser even when
the first query has no matches, allowing a typo or scope to be corrected
without reopening Jump. One-character misses start in Exact name mode.
Refinements search literal names; signed displacement expressions continue
to be resolved in the original Jump dialog.

The **Bookmarks** metadata page filters bookmark rows as you type, matching
the formatted address or label without regard to case. The state terms
`mapped` and `orphaned` filter by whether the saved location still belongs to
the current image. The counter reports visible and total bookmarks. Filtering
only changes the table projection; it does not edit the project. Row actions
and address navigation resolve through the visible-to-bookmark index map, so
filtering cannot apply a command to a different underlying bookmark.
Navigation uses the displayed document snapshot and is rejected if the active
project revision has changed. Rename and remove likewise require the displayed
project snapshot to still be current.

Results collapse duplicate destinations within the chosen scope, then sort by
name and location. A broad query stops once the result limit and an additional
distinct destination are found; it does not promise the alphabetically first
4096 names across the entire document. Narrow the query or select a source
scope to find another destination. Duplicate tracking uses a bounded ordered
location set, avoiding repeated scans of every accepted destination for each
matching alias.

The selected destination's full name and formatted address/file offset appear
in a read-only preview. Up/Down from the query moves the highlighted result;
Enter follows a sole result, or focuses the result list when there are several.
Enter in the list or **Go to selected** follows that explicit selection.
Typing clears the old result selection and disables navigation until the new
query runs, so Enter cannot follow a destination from earlier text. Escape or
Cancel leaves the workspace selection unchanged. All searches use the
document snapshot captured when Jump opened; navigation rechecks the active
document and project revision before applying the chosen destination.
Use **Copy selected destination** to copy the selected candidate's full name
and formatted destination without navigating or changing the selection. The
UTF-8 clipboard text is limited to 8 KiB; clipboard failures and oversized
destinations are reported in the chooser status.

Scope and match controls are local to the chooser. The current document's Jump
suggestions also offer **Fuzzy (ranked)**. This optional mode first ranks
case-insensitive exact names, then prefixes, substrings, and finally ordered
character abbreviations: `opfl` can match `OpenFile`. It does not infer spelling
corrections or reorder query characters. Normal Jump exact/numeric/displacement
resolution and the three literal suggestion modes keep their existing behavior;
ranking never navigates automatically without the usual explicit selection.

Within each match class, compact abbreviation spans, earlier matches, and shorter
names rank first; case-folded/original names and full locations break ties
deterministically. Aliases at one destination keep their best-ranked name.
The search retains the best 4096 distinct destinations encountered across its
bounded scan, rather than stopping at the first 4096 matches. Refinement scans
the captured source vectors again, so a later, better match can replace an
earlier candidate. Each fuzzy query accepts 2..256 characters and examines at
most 50,000 records, 2 Mi characters, and 2 Mi character comparisons. Names
over 2048 characters are omitted. The result list labels source/comparison
budget exhaustion, omitted oversized names, and destination-cap truncation;
ranked results are best within the scanned sources, not a global index.
These budgets govern matching over the existing captured name sources, not
background indexing or eager source collection performed when Jump opens.
Narrow the source scope when a broad fuzzy query is partial.

The chooser remembers its source scope and match mode in the per-user desktop
configuration. If Jump opens without an explicit query, it also restores the
last query. **Reset search** clears the query and restores **All name sources**
and **Contains**; closing the chooser saves those values for the next opening.
Current-document literal name results are loaded in pages of at most 256.
**More results** continues from the next stable position in the same
case-insensitively sorted, deduplicated result set; each page is searched on
the existing background worker. A literal search examines at most 200,000
source records per request and labels partial results if that bound is reached.
Changing the query, scope, or mode cancels pending work and discards stale
pages. Source vectors are still collected synchronously when Jump opens, so a
very large document can pause during collection. Paging covers captured
current-document names only; it does not add a persistent index, background
source collection, or searches of unopened projects. Fuzzy ranking remains
bounded to its first 4,096 destinations and does not expose additional pages.

## Search names across open documents

Choose **Navigate > Search Names in Open Documents...** (`Ctrl+Shift+G`) to
search loaded tabs without first activating a target document. This separate
literal-name workflow offers the same name-source scopes and case-insensitive
Contains, Starts with, and Exact name modes as Jump suggestions. Contains and
Starts with require two characters; Exact name accepts one. Queries are limited
to 256 characters, including in the existing suggestions chooser. Numeric
addresses and signed displacements continue to use the ordinary Jump dialog.

The chooser captures up to 128 loaded project snapshots in open-tab order.
Opening/unavailable documents and documents beyond that cap are omitted with
a partial-search message. Image symbols include address-bearing imports,
exports, defined ELF/Mach-O symbols, concrete DWARF subprograms and alternate
entry points, and PDB symbols.
Project annotation names, bookmark labels, current or explicitly incomplete
recovered-function names, and `section:`/`segment:` names are also available.
Unmapped destinations and addressless records are omitted; pending/stale
recovered-function data is not presented as current. Incomplete metadata or
function analysis is labeled partial.

Each refinement scans the captured sources again after the existing 120 ms
typing delay. Per query, at most 200,000 source records and 16 MiB of source
name bytes are examined; names exceeding 2,048 UTF-8 bytes are omitted and
reported as partial. These bounds apply before name conversion and result
construction. At most 4,096 distinct document/location destinations are shown;
finding another match stops the scan and reports the result cap. Scan-budget
and omitted-data warnings are separate from a complete zero-match result.
Narrow the query to reduce result overflow, or choose a name-source scope to
avoid exhausting the scan budget. There is no background or persistent index.

Every row and destination preview includes its document label and unique
session-local document number. Equal addresses in different documents remain
separate choices; aliases within one document collapse by full location,
including address-space ID and file-offset versus virtual-address kind.
Accepted candidates are ordered by case-folded name, original name, document
number, and location. Capped results are the first accepted destinations in
source traversal order, sorted for display, not a promise of the globally first
alphabetical matches.

Typing invalidates the old results immediately. Enter/double-click/Go to
selected follows an explicit selection; Cancel leaves all cursors and tabs
unchanged. Before navigation, HexLab verifies that the selected document is
still open with the captured session identity and exact immutable project
snapshot. A changed, replaced, or closed target is rejected with a retry message.
The exact address/file offset is validated before activating the document; a
successful result selects Disassembly or Bytes and enters the shared
Back/Forward history with its originating document and view. Searches do not
follow a same-address result in whichever tab happens to be active.

The cross-document chooser also offers **Fuzzy (ranked)**. It ranks exact
names, prefixes, substrings, then ordered-character abbreviations, while
keeping aliases at one document/location under their best-ranked name. Fuzzy
search examines at most 50,000 records, 2 MiB of names, and 2 Mi character
comparisons per query; it keeps the best 4,096 distinct destinations across
the scanned sources. Budget exhaustion, omitted oversized names, stale or
unavailable data, and result truncation are labeled partial. Ranked results
are best within the captured sources and bounded scan, not a global index.
The capability remains partial: saved query preferences, background
indexing, and searches of unopened projects remain unsupported. Reopen the
chooser to include newly opened tabs or newer analysis publications.

**Navigate > Previous Function** and **Next Function** move to the nearest
recovered function entry before or after the current mapped address, within
the same address space. The commands are enabled only while project function
analysis is current or explicitly incomplete. They do not wrap at either end;
the current selection and all synchronized panes remain unchanged when no
adjacent recovered function exists.

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

## Name search preferences

Jump name search remembers the last query (up to 256 characters), source scope, and match mode in the desktop configuration. An explicit query supplied by the current Jump action takes precedence; otherwise the chooser restores the last query. Invalid or unavailable saved modes and scopes are ignored, and cross-document search keeps fuzzy matching unavailable.

## Browsing image entry locations

Use **Navigate > Browse Image Entries...** to choose a format-declared entry
location in the active image. The list includes mapped image entries such as
native executable entry points and method or start-function entries exposed by
managed and WebAssembly loaders. Duplicate addresses are collapsed and choices
are sorted by address-space number and offset. Selecting one navigates through
the normal workspace path, so the destination is synchronized across panes and
recorded in Back/Forward history.

The chooser scans at most 100,000 source entries and displays at most 4,096
unique locations. Its prompt reports either bound when reached. The entries come
from the immutable image snapshot; if the active document changes while the
chooser is open, the selection is rejected and the chooser must be reopened.
