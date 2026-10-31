# Desktop source view

The Binary notebook includes a **Source** page. When the current address has a
PE/PDB, ELF/DWARF, or Mach-O/DWARF line mapping, the page displays the mapped
local source file with up to twenty surrounding lines on either side. The
current source line is selected as disassembly navigation changes. Selecting
a mapped source line navigates back to its address in the disassembly.
From Pseudocode, **Open Source at Origin** selects the matching source line for
the current instruction-origin annotation and switches to this page. It is
available only when the active document has a single unambiguous source mapping
for that origin; stale document/project revisions cancel the action. See
[Pseudocode to Source navigation](pseudocode-source-origin.md).

Use **Find in source file** with **Find previous** or **Find next** to search the
entire currently selected source file. The bounded read, decode, and match scan
run in a background worker so the desktop remains responsive. While a scan is
running, search and source editing controls are disabled; navigating to another
address or document requests cancellation. A completion is applied only to the
same immutable document snapshot, source path, query, case mode, and selected
address that started it, so stale matches are discarded. The worker reads in
64 KiB chunks, checks file size and modification time before and after the
scan, and responds to cancellation between chunks and during line processing.
Matching is case-sensitive by default;
enable **Ignore ASCII case** to fold only `A` through `Z`, while non-ASCII UTF-8
bytes still match exactly. The mode is retained per open document in the Source
page. Search wraps at the file boundaries. Repeated Find next/previous commands visit additional
occurrences on the same line before moving to another line, then wrap among
occurrences in that line as well as across the file. A match outside the current
excerpt recenters the excerpt on that line, including lines without a debug
mapping. The search selects and
reveals the match without editing the source file. The view rereads the file
through the same local-path checks, with a 64 MiB full-file search limit.
The status reports the current occurrence number and total non-overlapping
matches in the complete file, along with the source line and mapped address
when available.
Files above that bound retain mapped excerpt browsing while search is disabled.
Editing has a separate 1 MiB limit. Search reads and decodes the whole file
within its bound, so a reported no-match means the complete file was scanned.
A match recenters the excerpt and refreshes the mapped-address table for that
source line in the active address space. The status reports the line and mapped
address when available, or explicitly says the line has no machine-address
mapping. Files above the search bound report unavailable coverage rather than
returning a partial-search result.

Use **Load full file** to replace the mapped window with the complete source
file for browsing. Loading and decoding run in a background worker and share
the 64 MiB full-file limit used by source search. The button changes to
**Cancel load** while work is in progress; navigating to another address or
document also requests cancellation. Results are applied only while the same
document snapshot, source path, and selected address remain active. Selecting
a mapped line in the complete file navigates to its machine address. **Show
mapped excerpt** returns to the bounded mapped window. The complete view is
read-only; source editing retains its separate 1 MiB limit. **Copy excerpt**
rejects complete-file contents above the 1 MiB clipboard limit before making
an encoded copy.

After the worker validates the UTF-8 text, the UI appends it in 256 KiB
UTF-8-boundary chunks on successive timer events. This keeps conversion and
text-control updates bounded per UI event while retaining the 64 MiB file cap.
**Cancel load** remains available during this rendering phase; canceling drops
the partial text and restores the mapped excerpt. Each chunk is discarded if
the document, project revision, source path, or selected address has changed.

Full-file reads and decoding run off the UI thread. Navigation and document
changes request cancellation; the result is applied only if the selected path,
address, document revision, and project edit/byte/decision revision still match
the captured values.
Files above the 64 MiB full-file/search bound remain browsable through the
bounded, cancellable source pages instead of being assembled into one large
desktop text control. Excerpt, page, search, and full-file worker results all
carry the same document and project revision identity, so a result from an older
project publication cannot replace the current source view.

Choose **Edit source** to switch from the mapped excerpt to the complete file
in a writable editor. Editing is available for valid UTF-8 files and
BOM-marked UTF-16LE/UTF-16BE files. Saving preserves the original encoding,
byte-order mark, and mixed LF/CRLF line endings by output line index. Each
edited line ending uses the original terminator recorded at that same line
index when one exists; lines beyond the original newline sequence use the
dominant original style, with LF on a tie. Inserting or deleting lines shifts
text relative to this positional rule; line-ending identity is not matched by
text content. Malformed UTF-8 or UTF-16
remains view-only. The 1 MiB limit applies to the encoded file after editing.
**Save** writes through a temporary sibling file and atomically replaces the selected local
file. The replacement retains Windows file
ACLs through `ReplaceFile`; on POSIX it preserves owner, group, and mode, and
refuses files with extended attributes because it cannot preserve them safely.
Before saving, the view rereads the
original path and refuses the write if its bytes changed since editing began.
Use **Discard edits** to reload the on-disk contents. Leaving the file or
document prompts to save, discard, or cancel. This edits only the source file;
it does not change project analysis or debug mappings, which may no longer
match after edits.

The source page lists every source path present in the document's line table.
Use **Filter source files** to narrow the picker by a case-insensitive match
against the full debug path, then choose a path to inspect its first mapped line, or the closest preceding line
for the current address when that file has a mapping in the same address space.
The filter only changes the visible picker entries; it does not alter line
mappings. Address navigation clears a filter that hides the current mapped
file, selects that file in the picker, and keeps source-line clicks navigating
to the corresponding machine address.

The source-file filter and last displayed source path are remembered while
switching among open documents in this Source page. The per-document state is
session-only and bounded to 32 document IDs; the filter is capped at 2,048
characters. Returning to an open document restores its query and preferred
file when that path still appears in the document's line table. A missing path
falls back to the first visible source file.

Source paths come from the binary's debug information and are treated only as
informational local file paths. The view rejects Windows network shares and
device namespace paths (including canonical targets reached through a local
alias), requires a regular file, and limits the path to 32 KiB. It does not
fetch, execute, or build source. Missing files, rejected paths, out-of-range
line numbers, and paused source scans are reported in
the page rather than silently showing unrelated content. The debug format does not always provide an exact end address for a
line, so address selection uses the nearest preceding source row in the same
address space; this is a best-effort mapping for optimized code and gaps.

Excerpt loading streams toward at most twenty lines after the requested line,
using a 64 KiB read buffer and at most a 64 MiB scan window per action. Each
window now runs in a cancellable background worker; the source page reports
progress state without blocking address navigation, and applies a result only
while its document snapshot and latest line request remain current. A newer
line request cancels the previous window and runs after that worker has stopped.
Cancellation is checked at least once per 64 KiB of input. A small
BOM probe identifies encoding at each open. The total file size is not capped
for excerpt browsing. When a requested line lies beyond the current window,
the page reports the byte/line reached and enables **Continue source scan**.
Each click seeks to the saved position and scans another bounded window,
allowing mapped lines beyond the original 64 MiB prefix to become available
without rescanning that prefix. There is no automatic continuation or complete
line index; sparse checkpoints support bounded page navigation. Navigating to another line/file or changing the document discards
the checkpoint, so continuing is always an explicit action for the current
request. Full-file loading/search remain capped at 64 MiB.

For a source file larger than 64 MiB, the mapped excerpt remains available and
the Source page adds **Previous page** and **Next page**. Each page displays at
most 41 decoded lines and never puts the complete large file in the text
control. The view records a sparse byte offset every 4,096 lines while it
scans; no more than 262,144 offsets are retained for a source file. Page reads
seek to the nearest earlier checkpoint and use the same 64 MiB per-action
window, Unicode validation, cancellation, size/modification-time checks, and explicit
**Continue source scan** behavior as mapped excerpts. If a page lies farther
than one window from its checkpoint, continuation remains explicit. A size or
modification-time change invalidates its checkpoints. These checks do not lock
out a concurrent writer. Search above 64 MiB remains unavailable
rather than reporting a result from only one page; editing remains capped at
1 MiB. The source path and line number stay visible, and clicking a line with a
debug mapping continues to navigate to its machine address.

The checkpoint is saved only between complete Unicode scalars, including
UTF-16 surrogate pairs. It retains the current line number and partial excerpt
with at most 41 lines and the existing 1 MiB decoded UTF-8 text budget; long
skipped lines still allocate no line buffers. A displayed line or combined
excerpt exceeding that budget remains unavailable. Continuation verifies the
canonical path, encoding/BOM, file size and modification time against its
checkpoint. Size/mtime changes during each window also reject the read. The
checkpoint belongs to the exact captured document snapshot; a changed project
publication or document cannot receive an older continuation's result. These
checks do not lock a source file against an active external writer. No source
or project bytes are changed by scanning. Full-file search is bounded at 64 MiB;
editing remains bounded at 1 MiB.

Source text with a UTF-8 BOM is displayed without the marker. UTF-16LE and
UTF-16BE files are decoded when they have the matching byte-order mark; invalid
surrogate pairs and odd-length UTF-16 files are reported as unavailable. Files
without a BOM are treated as UTF-8.
The scanned prefix is validated as UTF-8 or BOM-marked UTF-16; malformed
sequences in that prefix are reported as unavailable. Bytes after the excerpt
are not decoded, although odd total byte lengths of BOM-marked UTF-16 files
are rejected before scanning.

When a source line has several distinct machine addresses, **Previous address**
and **Next address** move through those mappings in address order. The selected
address stays synchronized with disassembly, bytes, pseudocode, and the graph.
The source-line table is grouped by address space and source path when the
document is attached. Address changes inspect only the active address space;
source-file browsing, line navigation, mapping previews, and line-map export
inspect only the selected path. The original row order within each group is
retained, including overlapping inline scopes, so indexing changes lookup cost
without changing which mapping is selected or how ambiguity is reported.
Selecting a different visible source line starts at its first mapped address in
the active address space.

Use **Copy location** to copy the currently focused visible line as its full
debug source path and line number. When the line has a machine-address mapping
in the displayed address space, the copied text also includes that address
space and address. This works for mapped lines and unmapped lines found by
source search; it does not modify source or project data.

Use **Copy line text** to copy the focused visible source line without its
line-number gutter. It copies the displayed excerpt text, including for an
unmapped line found by search, and rejects lines larger than 64 KiB.

Use **Copy excerpt** to copy the currently displayed source window as UTF-8,
prefixed with the source path and first-to-last visible line numbers. The text is
copied as displayed, including the line-number gutter, and is available for a
mapped excerpt or an excerpt loaded by search. Editing mode disables the action.
The combined header and excerpt must fit within 1 MiB; oversized text is not
copied partially.

The mapped-instruction table retains distinct source origins even when they
point to the same machine address. Each row shows the debug-info source column,
inline depth and scope, current instruction text when available, mapping state,
and saved project software-breakpoint status. This makes overlapping inline
records visible instead of merging them into one address row.

Use **Copy line map** to copy the focused line's source-mapping rows as TSV,
including path, line and column, address space, inline depth and scope, and
current instruction text when available. Duplicate machine addresses are kept
when their source origins differ. The export is limited to 4,096 origin rows
and 1 MiB; the status line reports rows omitted by those bounds. Tabs and line
breaks in source paths or scopes are escaped, and an unmapped line produces no
clipboard update.
Select a row and use **Toggle project breakpoint** to add or remove the saved
breakpoint at that address. With no table row selected, the currently selected
line mapping is used. Double-clicking a mapped row navigates to that address.
The action is available only for a writable project and is rejected if the
document snapshot shown by the Source page is no longer the active snapshot.
The table's state column also reports when its instruction listing is stale
for the current project byte or decision revision, or when project analysis is
unavailable. Source-line records remain visible for navigation, but the view
does not present an instruction from an older project revision as current.
# PDB source revision checks

When a PDB supplies a C13 source checksum, the Source view can compare the selected local file against it with **Check PDB revision**. The check is opt-in, read-only, runs in the background, and reads at most 64 MiB. HexLab currently compares PDB checksum kind 3 (SHA-256) only. Conflicting checksums for the same path, other checksum kinds, and files that cannot be read within the size bound are reported as unavailable. The view checks file size and modification time before and after hashing and discards results if the document or selected source path changes. A match establishes that the file bytes match the checksum recorded in the PDB; it does not authenticate who produced the PDB.
