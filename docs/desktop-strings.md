# Desktop string browser

The Metadata notebook's Strings page filters discovered strings by preview text, mapped address or file offset, encoding, and its project or standalone comment. Matching is case-insensitive substring search. The split view shows the selected string's incoming references and supports bounded paging; activating a string navigates to its data, while activating a reference navigates to its source.

The selected string's original bytes are shown as hexadecimal in a separate
read-only preview, limited to the first 64 bytes. The table's encoding and byte
length identify how to interpret that sequence; longer strings are marked as
truncated in the preview. Bytes are read from the active image snapshot and are
never changed by this view.
Use **Copy byte preview as hex** to copy those exact displayed bytes as a
contiguous uppercase hexadecimal string. This copies at most 64 bytes; longer
strings report that the copied data is only the preview. It does not include
the preview's address, encoding, or truncation marker and does not modify the
source bytes.
Use **Copy preview text** for the selected row's decoded text as plain text.
String previews contain at most 256 characters; longer strings report that
the clipboard received only the truncated preview. This action does not change
the source bytes or string annotations.
Use **Copy preview as JSON string** to copy the selected row's decoded preview
as one quoted JSON string. Quotes, backslashes, and control characters are
escaped, and the output is checked as UTF-8 before it reaches the clipboard.
The copy is limited to 64 KiB and fails without copying partial output when it
is too large or the clipboard is unavailable. It uses the displayed preview,
which contains at most 256 characters; longer strings report that the JSON
string contains only the truncated preview. This action does not modify source
bytes or string annotations.

The filter bar also provides exact encoding, mapped/file-only, and
terminated/unterminated selections. These combine with the text search and
inclusive minimum/maximum **source byte lengths** and **decoded character
counts**; they do not change the underlying scanner or reinterpret bytes.
Bounds accept unsigned decimal integers through 18,446,744,073,709,551,615.
Blank minimum means zero and blank maximum means no limit. Invalid, overflowing,
or reversed byte or character bounds show an error and no matching rows;
**Export all CSV...** remains available.

The summary reports visible versus discovered counts and labels incomplete
scans, so a zero-match filter is distinguishable from exhaustive discovery.
The table now also exposes character length and termination state. Choose
discovery order, ascending file offset, shortest/longest byte length,
longest character length, or ascending text. Numeric sorts use the record's
64-bit values; text order compares the UTF-8 previews, with discovery order
breaking ties. Sorting retains the selected record when it remains visible
and keeps its byte preview and references attached to that record.
**Export filtered CSV...** follows the same combined filters and display
order; **Export all CSV...** retains discovery order and ignores these
controls. Filtering and sorting operate on discovered records in memory;
they do not launch another analysis pass.

**Reset filters** clears the search and facets, removes byte and character
bounds, and restores discovery order. Navigation to a string outside the visible set
clears the search and filter facets to reveal it while retaining the selected sort.
When different encodings overlap the same bytes, navigation first keeps the
selected visible interpretation, then prefers another visible candidate;
it only clears filters when every containing string is hidden. View controls
are retained per document and do not edit project data. Standalone documents
can keep bounded local string comments in desktop session preferences; these
remain separate from project annotations. String rewriting/reclassification
remains outside this browser.

Incoming references use the current project `ReferenceIndex`. Mapped strings query the file range together with virtual aliases; strings without a mapped address query the file range directly. Results are paged in groups of 128. **Copy page as TSV** copies the current bounded page with a header and one row per reference, including the destination string address and preview, source, kind, and operand. Use the paging buttons to copy another page; **Export filtered CSV...** and **Export all CSV...** remain available for complete file exports. Stale and pending analysis does not show old reference rows, and incomplete analysis is labeled. Standalone documents without a project reference index still support string filtering and navigation, but cannot browse references.

For project documents, the string table shows the comment attached to each string location. Select a row and choose **Comment selected string...** to create or edit its persistent project comment. For standalone binary documents, the same action edits a local workspace note associated with the exact input identity and string selection; notes never change source bytes or create project annotations. Each note is limited to 4 KiB, with at most 2,048 notes, 1 MiB total text and 2 MiB serialized note data per input. The desktop flushes notes to per-user configuration when they are added or removed, keyed by the input size, content digest, and loader recipe rather than the tab's current session position. It retains notes for at most 16 distinct inputs; with two bounded slots per input, the note data is capped at about 64 MiB plus configuration metadata. Opening the same input with the same loader recipe restores its notes. Notes are not embedded into the input or shared with another user profile. The session snapshot also retains its bounded copy for compatibility with existing workspace state.

Standalone notes can move between user profiles through **Export standalone notes...** and **Import standalone notes...**. The versioned UTF-8 text file carries a digest of the input size, content, and loader recipe, plus each string-selection fingerprint and hex-encoded note. Export publishes through a same-directory temporary and protects the source and project paths. Import requires the same input and recipe, validates the full bounded file and each note before changing local preferences, and merges notes in one save; matching existing notes are replaced. A note only appears when a discovered string later matches its byte revision, offset, encoding, lengths, termination, and preview digest, so notes for undiscovered strings remain dormant instead of being discarded. Notes are capped at 4 MiB per transfer, 2,048 records, 4 KiB per note, 1 MiB total text, and 2 MiB serialized note data. This makes notes portable without making them part of the binary or a saved project.

**Copy selected row** copies the selected visible row as one tab-separated record containing address or file offset, preview text, encoding, byte length, character length, termination state, and comment, in table-column order. Press **Ctrl+C** while the strings table has focus to invoke the same action. Tabs, line breaks, and control bytes in fields are escaped so the copied row stays on one line. The browser reports clipboard availability and copy results; copying does not modify the string or its source bytes.

**Export filtered CSV...** writes the current filtered string set, independent of selection. **Export all CSV...** writes every discovered string and ignores the current filter. Each CSV row contains the string address (when mapped), file offset, encoding, byte and character lengths, termination state, preview text, the project or standalone comment (blank when unannotated), and an incoming-reference source/kind/operand when available. Strings with no incoming references still receive a row. Strings with references receive one row per reference, so a string with multiple sources is repeated with its comment. Both exports walk the same mapped-alias-aware index queries in bounded pages of 128 and write incrementally through protected file publication; neither accumulates the full export in memory. Standalone, stale, pending, file-only, or otherwise unavailable reference data is represented in `reference_status` instead of being presented as an empty reference set. Incomplete string or reference analysis is labeled partial, including strings with no indexed incoming references. CSV fields are quoted and quote characters escaped; output is UTF-8 with CRLF records.

Each export uses the immutable document snapshot captured when the export action
starts. After the save dialog closes, the browser checks that the same snapshot
is still active before opening the destination. If a tab switch or snapshot
publication replaced it while the dialog was open, export is canceled with a
retry prompt so the file cannot silently contain strings from an older view.

## Per-document preferences and session restoration

Each open document retains its text query, exact encoding/mapping/termination
facets, minimum/maximum byte and character fields, sort order, and selected
string when switching tabs or receiving a newer analysis snapshot. A new document starts with default
controls instead of inheriting the previous tab's filter. The text query is limited
to 2,048 characters. Invalid byte- or character-range text is retained as
entered and continues to display the corresponding range error; restoration
never silently broadens it.

Saved projects store these preferences in the project's namespaced UI preference
table, outside annotations and undo history. The `view.strings.v1` payload is
versioned and bounded; schema 3 restores the character bounds and accepts schema
2 with unrestricted character bounds. Project preference keys are limited to 128 bytes, values
to 16 KiB, and each project may contain at most 128 preferences totaling 1 MiB.
Standalone binary tabs continue to store preferences in local desktop session
configuration alongside their path, recipe, and cursor. Standalone string notes
are stored in that same versioned per-document record. Version-1 preference
groups remain readable with no comments and are rewritten in the current format
when the workspace saves. Each note is tied to the input digest/size, recipe,
byte revision, and string offset/encoding/length/preview fingerprint; an identity
mismatch or changed string does not inherit an old note. Project comments remain
on the project database path and are not migrated into the local note store.
Documents the workspace
cannot reopen cannot restore preferences. Encoding, mapping, termination, sort,
field lengths, and identity/selection tokens are validated on restore. Numeric
bounds are validated when filtering; invalid values remain visible and produce
an empty result with an error. Malformed or unsupported payloads use defaults.

Preferences are applied only after the loaded document's original input size and
SHA-256 and encoded load recipe match the saved identity. Saved project entries
also require the same project UUID; standalone imports receive a new UUID on
reopening, so their session identity uses input and recipe instead. Replacing a
file or project at the same path therefore does not apply another document's
Strings settings. An identity mismatch is reported on the Strings page.

Selection restoration compares source offset, encoding, byte/character lengths,
termination, source-byte revision, and a SHA-256 of the preview. It never restores
a table row number or chooses a nearby string. The matching record must still be
visible under the saved filter. A changed or hidden selection is dropped with a
status message; a pending/stale analysis can retain the key until a current scan
arrives. No reference page or source byte buffer is persisted. A restored row
opens its byte preview and the first page of current references without changing
the workspace cursor. Interim loading cursors and unchanged context refreshes do
not clear saved filters; subsequent navigation to a different location retains
the existing reveal-hidden-string behavior.

This remains a partial browser. String rewriting/reclassification and broader string
editing remain unsupported. Crash recovery
of unsaved UI changes and persistence for non-reopenable plugin or archive-member
sessions are outside this slice.

When an incoming-reference row is selected, use **Copy selected reference** or press **Ctrl+C** with the references table focused to copy a TSV record containing the destination string address, its preview text, reference source, reference kind, and operand index. Control characters are escaped so the record stays on one line. The command requires a current selected reference row and does not change navigation or project data.

**Export full bytes...** writes the selected string's original byte range to a
binary file, including any terminator included in the detected record. It reads
the captured input snapshot in 64 KiB chunks and caps one export at 64 MiB.
The destination is published atomically; project files and file-backed input
images are protected from being replaced. If the document or selected record
changes while the save dialog is open, the export is canceled. This exports
bytes as stored and does not decode, rewrite, or reclassify the string.
