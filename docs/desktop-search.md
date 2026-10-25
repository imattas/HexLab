# Desktop search

Use **Edit → Find** to search the active document. Enable **Search all open
documents** to run the same byte-pattern, text, or immediate query against every
open document that has an analyzed project. Each document keeps its own paged
search history and source revision; the Search pane combines the pages and adds
a document column so results remain attributable.

Select a combined result to activate its document and navigate to the matched
file offset or instruction. **More results** requests the next available page
for every document with a continuation. Closing a document removes its rows;
editing a source invalidates only that document's cached matches. Search work
continues on the analysis pool, not the GUI thread.

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
