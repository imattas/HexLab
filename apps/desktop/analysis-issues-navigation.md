# Reviewing analysis findings

The Metadata notebook's **Analysis issues** page provides a review queue for
incomplete functions, unusual recovery stops, entry candidates and overlaps.
The kind, severity and review-state selectors plus the text filter narrow the loaded findings
without starting analysis or changing project decisions. The severity column
keeps producer-reported error, warning and info levels visible in the queue; the
severity filter combines with the kind filter, review state, search and function scope.
The review-state selector shows all, open-only, or reviewed-only findings. Its
**Needs attention (open errors/warnings)** preset skips reviewed findings and
info-level diagnostics, leaving unresolved errors and warnings in the queue.
It combines with category, severity, search and function scope, and is recorded
in TSV/JSON export metadata like the other review-state choices.
The kind selector separates runtime relocation and file-inspection diagnostics
from the general loader diagnostic queue. **Loader diagnostics** keeps the full
diagnostic set together; the two additional choices isolate each source class
when a binary reports many unrelated loader findings.
The status line breaks the visible queue down into error, warning, and info
counts, so the current filter and function scope show their severity mix at a
glance.

Select a row to navigate the linked listing, bytes and graph views. **Previous**
and **Next** move through the visible queue and navigate to each finding's
address. They stop at either end instead of wrapping. With no visible selection,
Next starts at the first finding and Previous starts at the last. Within this
page, **Alt+Up/Down** perform the same actions, **Ctrl+L** focuses and selects the
filter text, and Enter in the filter advances to the next visible finding.
**Go to related** and **Go to function** retain their separate endpoints.

Use **Mark reviewed** on a selected finding to close it in the current document's
queue; **Reopen finding** returns it to the open queue. Review status appears in
the table, details, copied report, and TSV export. The status line reports visible
reviewed/open counts with the severity counts.

**Review visible** marks the full current filtered and scoped queue as reviewed;
**Reopen visible** reopens that same visible set. Both actions are bounded by
the view's 20,000-row cap. Bulk review checks the per-document 20,000-key limit
before changing anything, so an oversized selection is left untouched and the
message recommends narrowing the filters. The actions only change review state;
they do not alter analysis results or project decisions.

The details box below the table shows the finding's severity, address, related
location, function name and diagnostic text. Function-recovery findings use the
view's warning default; loader, type-import and decompiler diagnostics retain
the severity supplied by their producer. Unlike the abbreviated table cell, it shows
up to 64 KiB of diagnostic text, with the existing preview truncation marker when
needed. Text can be selected and copied directly; **Copy finding** copies a
report bounded to 64 KiB. **Export visible TSV** retains the original diagnostic
fields and records the current filter and scope.
**Copy visible TSV** copies the current queue for projects and file-only
documents, up to 128 visible rows. Its header reports copied, visible and loaded
counts and active filters/scope; if more rows match, it marks the cap and you can narrow the filters to
copy another subset. TSV control characters are escaped, and detail cells use
the same 768-character preview as the table.

## Pinning a function

Place the cursor in a recovered function, then choose **Scope to cursor
function**. An address cursor is used directly; a file-offset cursor must map
successfully through the image's existing address mapper. The function is pinned
by entry address. Following a finding or related target outside that function
does not change the pin. **All functions** restores the full loaded queue.

The scope includes findings explicitly associated with that function and
findings whose primary or related address falls in its recovered chunks. This
includes candidates discovered from the function and overlaps touching either
endpoint. Address spaces remain distinct. Chunk ranges use checked endpoints,
are sorted and merged, and support binary-search containment. A cursor with
multiple recovered owners, an unmapped cursor, or an incomplete bounded owner
lookup leaves the current scope unchanged and explains why.

Kind filter, severity filter, query, pinned function and selected finding are remembered
independently for each open document for the lifetime of the desktop session.
Reviewed findings are also remembered per open document, up to 20,000 findings.
The mark follows the complete finding identity across refreshes and is discarded
when a finding disappears or changes. Closing the document clears its review
state. These marks are session-only and do not modify project decisions or
persisted diagnostics.
Closing a document releases its state. A refresh restores a selection only when
the same finding kind, addresses, function association and diagnostic text remain
present. A removed or filtered finding leaves the table unselected; its old row
number never silently selects another finding. Clearing a filter can reveal the
remembered finding again. Selection restoration does not navigate.

## Coverage and limits

Scoping filters the existing capped collection; it does not rescan all analysis
or imply that a function has no findings outside that collection. The page
collects at most 20,000 findings from at most 100,000 recovered functions, and the
status and TSV header report collection limits and partial analysis. Owner
lookup additionally inspects at most 100,000 chunks. A function pin rebuilds at
most 100,000 chunk ranges and reports partial coverage if ranges are omitted or
invalid. If a pinned function disappears or becomes ambiguous after analysis,
the pin remains visible with an unavailable message and an empty queue until
the user changes or clears it.

The latest completed type-import report is stored as project metadata for
writable projects and survives reopening; it is replaced by the next completed
header or PDB import. Read-only and file-only tabs keep their report only while
open. This does not write analysis decisions or persist view preferences. GUI
and runtime verification remain separate from this navigation description.
