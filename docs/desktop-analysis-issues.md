# Desktop Analysis Issues

The Binary metadata notebook has an **Analysis issues** page for reviewing
function recovery output. It lists non-normal function stops, incomplete
function boundaries, unconfirmed entry candidates, and overlapping function
or decision records. Each row includes its address, related address when
available, owning function, and the analysis detail. Selecting a row navigates
the disassembly to its primary address. The selection strip shows the finding
summary and provides separate actions to navigate to its related address or
owning function. Use **Copy finding** to copy the issue kind and all available
addresses with the full bounded detail for a report or project note.

Use the category selector and text filter to narrow the list; the filter checks
the primary, related, and owning-function addresses as well as the finding
detail. Filtering preserves the selected finding while it remains visible.
Function stops with ordinary `ret` and `trap` endings are omitted. The **Loader
diagnostics** category also lists bounded diagnostics already attached to the
loaded image, including runtime-relocation diagnostics. Addressed diagnostics
can be navigated like other findings; diagnostics without an address remain
visible and are marked as not location-specific. A function scope includes
addressed diagnostics within that function's chunks and hides unlocated loader
diagnostics, which the status line reports.

The view reads immutable project and loader snapshots and does not edit
analysis decisions. It caps the combined list at 20,000 findings, admits up to
2,048 loader diagnostics so function findings cannot crowd them out, and scans
at most 100,000 functions; the status line reports when those limits truncate
the view and whether analysis is partial.

This page exposes facts already produced by function recovery and image
loading. It does not re-run analysis, classify every candidate as a defect, or
resolve conflicts; use the normal project edit commands after navigating to a
finding when an analysis decision needs changing.
