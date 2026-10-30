# Desktop search

Use **Edit → Find** to search the active document. Enable **Search all open
documents** to run the same byte-pattern, text, or immediate query against every
open document that has an analyzed project. Each document keeps its own paged
search history and source revision; the Search pane combines the pages and adds
a document column so results remain attributable.

The Find dialog now restores its most recently accepted setup and offers a
**Recent searches** picker. A setup contains the byte/text/immediate query,
text encoding and case-sensitivity, immediate width/signedness, and page
result/position budgets.
Selecting a recent setup only fills the editable controls; **OK** still
validates and submits a new search through the ordinary background workflow.
All-open-document and start-from-selection choices are not restored from
history, so a remembered query does not silently broaden its scope or reuse an
old origin.

Recent setups are stored in local desktop configuration when available, newest
first, with duplicate setups collapsed. Storage is bounded to 16 records and
4096 UTF-8 bytes per query. Larger valid queries still run but are not remembered.
Persisted records are versioned and revalidated for query syntax, encoding,
case sensitivity, width, signedness, and page-budget bounds before appearing in
the picker;
malformed records are ignored. For literal text searches, **Case-sensitive text
search** defaults on. Text encoding choices include ASCII, UTF encodings, and
Windows-1252. Turning case sensitivity off applies ASCII letter folding while
retaining exact matches for non-ASCII encoded characters; it does not perform
Unicode case-folding or normalization. The option is disabled for
byte-pattern and immediate searches. Recent text searches remember this
choice. **Forget selected** removes one setup while leaving the current editable
query intact. **Clear recent** explicitly removes the entire stored list. Cancel does not add or
reorder setups; an explicit Clear recent remains effective after cancellation.
Accepting a query after clearing records it again if it fits the storage cap.

Only query configuration is remembered. Document IDs, source revisions,
selected results, result pages, and continuation cursors are never persisted
by this feature. Running/restored requests retain the existing snapshot identity,
stale-result rejection, and cancellation behavior. Reopening Find or restoring
a setup does not resume an earlier background search automatically.

Select a combined result to activate its document and navigate to the matched
file offset or instruction. **More results** requests the next available page
for every document with a continuation. Closing a document removes its rows;
editing a source invalidates only that document's cached matches. Search work
continues on the analysis pool, not the GUI thread.

With all-open-documents search active, **Find Next** advances through the
active document's loaded results, then checks the other open searchable
documents in tab order. It loads the next page of the first document that has
more results and follows its first new match. **Find Previous** moves backward
through loaded results and then checks other documents in reverse tab order,
starting at the last loaded result in an unvisited document. If no other
loaded result is available while a search page is pending, Find Next and Find
Previous report that they are waiting; use the command again after the page
completes. Single-document
search keeps its existing per-document Find Next/Previous behavior.

Literal text searches encode their UTF-8 input as ASCII, UTF-8, UTF-16LE,
UTF-16BE, UTF-32LE, or UTF-32BE. UTF-16 queries encode supplementary Unicode
characters as surrogate pairs; UTF-32 queries encode each Unicode scalar in the
selected byte order. The project CLI supports the same encodings through
`--kind text --text <literal> --encoding <encoding>`.

The desktop Find dialog accepts two-character byte-pattern octets with either
hex digits or `?`
wildcards in each nibble. For example, `48 8B ?? A? ?F` matches exact bytes,
any byte, a high-nibble prefix, and a low-nibble suffix. The project CLI uses
the same syntax.

Find can start at the current selection and scan forward. A file-offset
selection starts at that inclusive byte offset. A virtual-address selection
must map uniquely to file-backed bytes; immediate search starts at the selected
instruction address, ordered after any earlier instruction that aliases the
same file offset. The option applies to
the active document only, so enabling it disables all-open-documents search.
It does not wrap to the beginning. Without the option, Find keeps its existing
whole-input start position.

The optional **Exclusive end file offset** bounds a search to the half-open
range `[start, end)`. It applies to byte, text, and immediate queries; immediate
search includes only decoded instructions whose file start is before the end.
The end is exclusive, so a byte match must fit completely before it. An end
beyond a document's size is clipped to that document, which lets the same bound
be used with all-open-documents search. The field is per run and is not stored
with recent query setups. A start after the bound is rejected. Continuation
pages retain the original bound and source revision.

The Search pane supports triage of the results already loaded into history:

- **Filter loaded results** applies a case-insensitive substring filter to the
  displayed document, file offset, virtual address, byte size, operand index,
  and history result number. It searches metadata; use Find to search file
  contents. **Clear** restores all loaded rows. The filter remains in effect
  when more pages arrive or the active document changes.
- **Previous visible** and **Next visible** navigate only the filtered loaded
  rows, without wrapping or requesting another page. Each row retains its
  original document and history index. The **History result** column numbers
  matches from 1 within each document, so filtering never renumbers history.
  Edit's Find Next/Previous commands continue to follow the full search history.
  A selection hidden by the filter is restored when it becomes visible again.
- Selecting a row shows hexadecimal and printable ASCII for up to **64 effective
  source bytes**, reading at most 64 backing ranges. Nonprintable bytes appear as dots.
  The preview reads only the selected result, never every result while filtering
  or exporting. Immediate hits show the instruction's backing ranges in
  instruction order; separate file offsets identify disjoint backing. A source
  revision mismatch or unavailable range is reported explicitly. Effective
  input is used even when a loader's decoded image backing differs from its
  original source representation.
- **Copy filtered TSV** and **Export filtered TSV** include all visible loaded
  rows, the filter, loaded/visible counts, coverage, document IDs, original
  history result numbers, and byte/decision revisions. An empty filtered set
  can be copied or exported after a search starts. Text fields escape backslash,
  tab, CR, and LF as `\\`, `\t`, `\r`, and `\n`; lines beginning with `#` contain
  report metadata. Files use UTF-8. Export snapshots the report before opening
  the save dialog and publishes it through a same-directory temporary file.
  Open projects, their sidecars, and source paths in the search scope are
  protected from export replacement.

The status and exported coverage summarize every document in the current
search scope: complete documents, pending searches, documents with more input
remaining, partial decoded sources, and documents without a loaded page. An
empty scope is reported as having no searchable documents. A zero-row filter
means no **loaded metadata** matched; more pages can still contain matches.
Partial decoded immediate searches remain partial even when their last page
has no continuation. **More results** remains available for eligible documents
while other documents are pending.

The original GUI search workflow is covered by `tests/desktop_search_tests.cpp`, including
single-document paging/history, asynchronous cancellation and stale-source
rejection, and combined multi-document result selection.
