# Address-synchronized context tables

When the active selection changes, HexLab now highlights matching context rows
without changing the selected metadata tab or moving the listing. The segment
containing an address or file offset is selected; exact matching rows are
selected in the function candidates, symbol, string, import, export,
annotation, bookmark, and type-assignment tables. ELF and Mach-O symbols also
match their retained file-record offsets when they do not have a mapped
address. File offsets are mapped through the active image when the mapping is
unique and image backing is the same storage used by the Bytes view, so
the corresponding address-backed metadata can be highlighted too.

Activating a row still navigates to that row's destination. That navigation
updates the listing and bytes panes and highlights the related context rows in
turn. The References page follows the active selection when unpinned. Its
**Pin context** option retains a document's reference origin while endpoint
navigation updates the listing and context tables; the listing's reference
commands open a pinned query without moving the selection. See
[reference browsing](reference-context-navigation.md).

The row synchronization is exact for imports, exports, strings, annotations,
bookmarks, symbols, and type assignments; it does not infer that nearby
metadata belongs to the selected instruction. Selecting an address inside a
segment highlights its containing segment, and selecting a file offset inside
a file-backed segment highlights that segment. The view does not switch
metadata tabs automatically, preserving the reader's current context.
Address-to-segment synchronization uses the image's canonical address map, so
cursor changes resolve the containing segment through the same lookup used by
disassembly and workspace navigation. Exact metadata-row indexes remain keyed
by the full address space and offset; filtering affects only which matching
row can be highlighted, not which segment owns the current mapped address.

The Segments page has a case-insensitive filter over its displayed address,
name, size, permissions, backing offset, and file-backed byte count. Filtered
activation still navigates to the original segment row. Cursor synchronization
keeps its source-row mapping, so selecting a matching row follows the cursor;
when the containing segment is hidden, the context bar reports that state and
**Reveal cursor row** clears only the Segments filter before highlighting it.
The filter is capped at 2,048 characters and persists in desktop configuration.
Filtering and visible-row navigation inspect at most the first 65,536 segments;
the row count labels this cap when the image has more segments. No segment is
invented for unmapped addresses, and the existing original/effective source
versus decoded image-backing distinction remains in force.

The Imports and Exports pages have case-insensitive filters over the displayed
address, library, name, ordinal, and forwarder fields. Their row counts show
the visible and total entries. Context selection synchronizes only rows still
visible under the filter; clearing it restores all entries without changing
the active listing location.

The Strings page reports whether the shared cursor maps to a discovered string,
whether that string is visible under the current text/facet filters, or whether
no string is known at that byte. When a matching row is hidden, **Reveal cursor
string** clears the string filters and selects the matching row without moving
the shared cursor. Ambiguous string encodings keep the currently selected
interpretation when it contains the cursor; otherwise the first discovered
containing record is used. A partial string scan is identified when no match is
known, so absence is not presented as exhaustive. Cursor-to-string matching
requires a verified file offset; unmapped addresses do not select a nearby row.

## Cursor context in Imports, Exports, and Segments

Each context bar offers **Pin summary** for comparison while browsing elsewhere
in the same document. Pinning retains that bar's current document/location and
description, including visible/hidden-match and partial-index warnings, in a
read-only summary capped at 8192 characters. The listing cursor and metadata
table highlights continue to follow navigation; this pins only the summary,
not the table query or a project edit. A pinned bar says that cursor actions
are paused. **Reveal cursor row**, **Show address**, and **Show file offset**
remain disabled until unpinning, so they cannot act on an old cursor under the
existing ownership checks. Unpinning immediately shows the latest cursor
summary and restores only the actions valid for that cursor.

Use **Copy summary** to copy the exact visible live or pinned text, including
its document/location, match state, partial-index warnings, and mapping notes.
The action is available for image-backed cursor selections and pinned
summaries; it does not change the active location or unpin the bar.

Pins are independent for Imports, Exports, and Segments. A document switch,
closure, replacement, or new immutable project/document publication clears the
affected pin rather than carrying a result into another snapshot. Pins are
session-only and do not save project or preference data. Pinning does not
expand hidden-match indexing: the 65,536-source-row caps and incomplete-data
labels below still apply, and a frozen summary is not a fresh metadata query.

The Imports and Exports pages now show the owning document number and shared
cursor location, followed by one of three states: an exact matching row is
visible, a matching row is hidden by this page's filter, or no exact match is
known in the indexed metadata. A hidden match enables **Reveal cursor row**.
This explicit action clears only that page's filter and highlights the matching
row. It does not navigate, change the cursor, select another metadata page, or
clear another page's filter. Ordinary cursor movement continues to respect the
filter. Import/export queries are limited to 2,048 characters.

The hidden-match lookup builds an address index once per immutable document
snapshot, using at most the first 65,536 import source rows and first 65,536
export source rows. Full address-space IDs participate in the key. Coverage
beyond either cap is labeled partial; the absence of an indexed match is not
reported as exhaustive. A matching row already visible through the ordinary
filter can still be recognized beyond the index cap. Incomplete loader metadata
is labeled separately. This bounded index does not change the existing import
or export row collection/filtering limits and does not resolve addressless
forwarders or infer relationships between an instruction and its called import.

Imports, Exports, and Segments also offer **Show address** and **Show file
offset** for the shared cursor. These select its exact mapped address in
Disassembly or source-file offset in Bytes. No nearby address or segment start
is substituted. An unmapped file position, ambiguous file-to-address mapping,
or zero-filled virtual location disables the unavailable counterpart action.
The actions do not depend on a matching import/export row: they describe the
shared cursor and remain useful while a table is filtered or empty.

The binary-information segment table remains the **Segments** page. It now
displays the backing offset and file-backed byte count alongside virtual start,
virtual size, name, and permissions. Its context bar identifies the containing
segment without moving the cursor. Zero-backed segments are labeled as such.
For decoded input formats where image storage differs from the original/effective
source storage used in Bytes (for example Intel HEX or S-record), offsets are
explicitly labeled **image backing**. Automatic context synchronization and
counterpart navigation do not treat these decoded offsets as original source
positions; no original-text mapping is invented.

Each toolbar action carries the exact immutable source document snapshot and
cursor from which it was rendered. Immediately before revealing or navigating,
the desktop rechecks the active document ID, current snapshot and project
snapshot, current cursor, and window-close state. A stale action is canceled
with an Output message. Closing or replacing the document clears the context
bars and cached index; another tab with the same address cannot inherit an old
action's destination. Table highlighting remains programmatic and does not
trigger row activation or a navigation loop.

Import/export filter text for project documents is persisted in the local desktop
configuration under the owning project's UUID. The same project's documents
restore the pair after restart, and projects keep separate pairs. These local
preferences are not written into project databases or exported with a project.
Standalone documents continue to use the desktop-wide startup seed and the
session-only per-document cache. Each value is capped at the same 2,048-character
limit as the filter controls; invalid over-limit stored values are ignored.

This remains partial context support. Hidden-match coverage is bounded, and
only the existing first exact row/containing segment is highlighted when aliases
overlap. Filter preferences are local to the desktop profile rather than
portable project data; context bars have no portable preference store, and
cross-view inferred call relationships and original-text mappings for decoded
inputs remain outside this slice.
