# Desktop Analysis Issues

The Binary metadata notebook has an **Analysis issues** page for reviewing
function recovery output and load diagnostics. For projects it lists non-normal function stops, incomplete
function boundaries, unconfirmed entry candidates, and overlapping function
or decision records. A binary opened without a project still shows the loader
and inspection diagnostics retained by its immutable document snapshot. The
page also receives transient diagnostics from C header and PDB type imports
and from the decompiler. Each row includes its address, related address when
available, owning function, and the analysis detail. Selecting a row navigates
the disassembly to its primary address. The selection strip shows the finding
summary and provides separate actions to navigate to its related address or
owning function. Use **Copy finding** to copy the issue kind and all available
addresses with the full bounded detail for a report or project note.

Use the category selector and text filter to narrow the list; the filter checks
the primary, related, and owning-function addresses as well as the finding
detail. Filtering preserves the selected finding while it remains visible.
Function stops with ordinary `ret` and `trap` endings are omitted. The diagnostic
categories list bounded loader/runtime-relocation diagnostics, file-only load
and inspection messages, header/PDB import messages, and decompiler lifting messages. Addressed diagnostics
can be navigated like other findings; diagnostics without an address remain
visible and are marked as not location-specific. Decompiler messages are scoped
to the selected function entry, without assigning an instruction address the
producer does not provide. PDB data-symbol diagnostics use a mapped address only
when the selected PDB uniquely matches the loaded PE. A function scope includes
addressed diagnostics within that function's chunks and function-associated
decompiler diagnostics, and hides unlocated diagnostics, which the status line reports.

The view reads immutable project or file-only document snapshots and does not edit
analysis decisions. It shows diagnostics from the snapshot's loaded image when one
is available, and falls back to persisted findings when no image is loaded. This
keeps findings aligned with edited or restored project bytes even before a newly
loaded diagnostic set is written to the project. Project loader and runtime-relocation
diagnostics are stored with the project in schema v12 and are replaced together in
one transaction only after a complete loader pass succeeds. A failed or canceled
load leaves the last completed set intact. The latest completed C-header/PDB
type-import report is stored with writable projects in schema v13, outside user
edit history, and replaced atomically when another import completes. Read-only
and file-only documents keep import reports only for the open document.
Decompiler findings remain transient and scoped to the selected function. It caps the combined list at 20,000 findings, admits up to
2,048 rows per diagnostic source (loader, runtime relocation, type import, and
decompiler) within the combined cap, and scans at most 100,000 functions; the status line reports when those limits truncate
the view and whether analysis is partial.

Type-import rows remain until the next completed header or PDB import replaces
them; canceling an import leaves the last completed result visible. Writable
project reports survive closing and reopening the project. Decompiler rows
reflect the current pseudocode render and clear when no recovered function
is selected. Transient type-import rows and decompiler rows are scoped to an open
document. A file-only tab has no recovered-function scope; its addressed
diagnostics still navigate within that binary. TSV export is available for
projects, whose protected paths prevent overwriting the source. Transient UI
results are kept per open document and are not persisted. Debugger output has no structured
diagnostic model and is not included. The page does not re-run analysis,
classify every candidate as a defect, or resolve conflicts; use the normal
project edit commands after navigating to a finding when an analysis decision
needs changing.
