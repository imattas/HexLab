# Address-synchronized context tables

When the active selection changes, HexLab now highlights matching context rows
without changing the selected metadata tab or moving the listing. The segment
containing an address or file offset is selected; exact matching rows are
selected in the function candidates, symbol, string, import, export,
annotation, bookmark, and type-assignment tables. ELF and Mach-O symbols also
match their retained file-record offsets when they do not have a mapped
address. File offsets are mapped through the active image where possible, so
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
