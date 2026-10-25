# Reviewing analysis findings

The Metadata notebook's **Analysis issues** page provides a review queue for
incomplete functions, unusual recovery stops, entry candidates and overlaps.
The kind selector and text filter narrow the loaded findings without starting
analysis or changing project decisions.

Select a row to navigate the linked listing, bytes and graph views. **Previous**
and **Next** move through the visible queue and navigate to each finding's
address. They stop at either end instead of wrapping. With no visible selection,
Next starts at the first finding and Previous starts at the last. Within this
page, **Alt+Up/Down** perform the same actions, **Ctrl+L** focuses and selects the
filter text, and Enter in the filter advances to the next visible finding.
**Go to related** and **Go to function** retain their separate endpoints.

The details box below the table shows the finding's address, related location,
function name and diagnostic text. Unlike the abbreviated table cell, it shows
up to 64 KiB of diagnostic text, with the existing preview truncation marker when
needed. Text can be selected and copied directly; **Copy finding** copies a
report bounded to 64 KiB. **Export visible TSV** retains the original diagnostic
fields and records the current filter and scope.

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

Kind filter, query, pinned function and selected finding are remembered
independently for each open document for the lifetime of the desktop session.
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

This workflow changes desktop presentation and navigation only. It does not
write analysis decisions or persist preferences in project databases. GUI and
runtime verification remain follow-up work; this implementation was reviewed
without opening the desktop or running tests.
