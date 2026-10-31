# Desktop Analysis Issues

The Binary metadata notebook has an **Analysis issues** page for reviewing
function recovery output and load diagnostics. For projects it lists non-normal function stops, incomplete
function boundaries, unconfirmed entry candidates, and overlapping function
or decision records. A binary opened without a project still shows the loader,
inspection, code-analysis, and analysis-time and inspection-time string-scan
diagnostics retained by its immutable document snapshot. Project snapshots also contribute diagnostics from
their derived string scan. Project string-scan rows use the project's derived
analysis identity for review marks and show as stale when that identity does
not match the current project input. These rows retain producer severity and
location. Project review marks use the derived analysis identity; file-only
findings disappear when the tab closes because they have no project database.
page also receives transient diagnostics from C header and PDB type imports
and from the decompiler. Each row includes its severity, address, related address when
available, owning function, and the analysis detail. Selecting a row navigates
the disassembly to its primary address. The selection strip shows the finding
summary and provides separate actions to navigate to its related address or
owning function. Use **Copy finding** to copy the issue kind, severity and all
available addresses with the full bounded detail for a report or project note.
Use **Copy finding JSON** to copy only the selected row as a versioned
`hexlab.analysis-finding.v1` JSON object. It includes kind, severity, review
state, available locations, bounded details, and source identity/currentness
when the producer supplies them; the opaque source identity is hex encoded so
the clipboard output is always valid UTF-8 JSON. The clipboard record is capped at 64 KiB and
details at 4,096 UTF-8 bytes; oversized records are rejected with a status
message. This is separate from **Export visible**, which captures a filtered
set of findings to a file.
**Copy visible TSV** copies the current filtered and scoped queue for either a
project or a file-only document. It includes at most the first 128 visible rows,
states the copied/visible/loaded counts and active filters/scope, escapes TSV control characters, and
adds a coverage line when the clipboard cap is reached. Narrow the filters to
copy a later subset. The table's detail preview (up to 768 characters) is used;
**Copy finding** remains available for the selected row's longer detail.
**Copy visible JSON** copies the same filtered/scoped queue in the
`hexlab.analysis-findings` JSON format. It includes at most 128 rows and 1 MiB,
and records the visible/copied row counts plus an explicit truncation flag so a
consumer can distinguish a complete selection from the clipboard page. Narrow
the filters to copy another page; **Export visible** remains available for a
larger bounded file report.

**Export visible** offers TSV and schema-versioned JSON for the same filtered
and scoped rows, including file-only documents. JSON carries finding kind,
severity, review state, locations, bounded details, and diagnostic source
identity when available. It preserves UTF-8 and escapes JSON control bytes.
JSON publication is limited to 16 MiB; an oversized view is rejected before
the destination file is created. Both formats use the normal protected-path
check for project inputs.

Use the category, severity and review-state selectors together with the text
filter to narrow the list; severity and review state appear as table columns and
combine with category, search and function scope. The review-state selector
shows all, open-only, or reviewed-only findings, plus **Needs attention (open
errors/warnings)** to isolate unresolved errors and warnings while skipping
info-level rows. This preset combines with the other filters and scope and is
recorded in exports. The text filter checks
the primary, related, and owning-function addresses as well as the finding
detail. Filtering preserves the selected finding while it remains visible.
The location selector can keep all rows, only rows with any location, or only
rows without one. It can also isolate rows with a primary address, a related
address, or an owning-function entry. These filters compose with the other
filters, are remembered per open document, and are recorded in TSV and JSON
export scope metadata. A function-associated decompiler row counts as located
at its function entry even when its producer supplies no instruction address.
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

Function-recovery rows use the view's warning default. Loader, type-import and
decompiler diagnostic rows retain their producer-reported info, warning or error
severity. Severity and review state are included in copied finding reports and
TSV export.

Use **Mark reviewed** and **Reopen finding** to track triage. The status line
reports visible reviewed and open counts. Writable projects store review marks
in the project database outside undo history, capped at 20,000 findings. The
marks survive closing and reopening a project and are cleared when the finding
identity disappears or changes. Read-only projects and file-only tabs keep marks
for the open session. Review marks do not change analysis decisions.
When a snapshot contains identical findings more than once, the view assigns
each occurrence its own deterministic review identity, so marking one duplicate
reviewed does not mark every matching row. If that duplicate set changes in a
later snapshot, its ambiguous occurrence marks are discarded.

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
Decompiler findings from a completed pseudocode render are stored with writable
projects using the existing diagnostic rows, outside user edit history. A refresh
replaces rows for that analysis key and function entry, so repeating a render is
idempotent. The full analysis key is retained for stale/current labeling and review
identity; messages without instruction locations remain tied to their function
entry. At most 2,048 decompiler rows are retained per project. Read-only, untitled,
and file-only documents keep decompiler messages only for the open document.

Successful writable-project attachment also persists the minidump decoder's
per-context register diagnostics, using the existing schema v15 diagnostic rows.
These include unsupported/truncated groups, XSTATE limitations and compatible
layout selections that otherwise remain nested in session metadata. The reserved
`Minidump register context` family is replaced atomically after a successful
minidump load; a failed or canceled replacement retains the preceding family.
Header/PDB imports and decompiler updates preserve it. A later successful
minidump attachment with no context messages clears the preceding report.
The report retains exact decoder messages with bounded thread-record index/id
or exception-thread id, plus context RVA and size. These file offsets are
provenance only: the view assigns no virtual address or owning function.
Severity uses the diagnostic warning default because these decoder messages
have no individual severity. Collection scans at most 65,536 thread records
and stores at most 2,048 rows / 4 MiB, with 64 KiB per message; a reserved final
row explicitly identifies incomplete coverage when a bound is reached.

Minidump context rows appear in the **Loader diagnostics** category, independently
of transient import reports. Their complete analysis key participates in review
identity. A key that differs from the current snapshot's computed source key, or has no current
counterpart, displays **STALE LOADER REPORT** in the table; copied/exported
details also identify stale source identity. Editing bytes/options does not silently relabel the previous report as
current; a successful reattachment collects a replacement. Read-only projects
display previously stored rows but do not persist a fresh report. File-only
documents retain their existing aggregate loader messages; this integration
does not persist or list nested per-context messages there.

The view caps the combined list at 20,000 findings, admits up to
2,048 rows per diagnostic source (loader, runtime relocation, type import, and
decompiler, plus minidump contexts) within the combined cap, and scans at most 100,000 functions; the status line reports when those limits truncate
the view and whether analysis is partial.

Type-import rows remain until the next completed header or PDB import replaces
them; canceling an import leaves the last completed result visible. Writable
project reports survive closing and reopening the project. Issue review marks
are stored in schema v14. Imported diagnostic source identities are stored in
schema v15 with the complete analysis key (input digest and size, byte and
decision revisions, recipe fingerprint, and engine fingerprint). On reopen,
the view compares that key with the current project snapshot. A report without
a key, or whose key differs, is labeled stale or unavailable; its review marks
are isolated from reports tied to another analysis identity. The details show
the input digest prefix, size, and revisions for triage. Decompiler rows reflect
the latest stored render per function and analysis source; the active pseudocode
render takes precedence for that function. Transient type-import rows remain
scoped to an open document. A file-only tab has no recovered-function scope; its addressed
diagnostics still navigate within that binary. TSV and JSON export are available
for projects and file-only documents. Project-protected paths prevent overwriting
project inputs. For file-only documents, export protects the backing path from
the captured document snapshot. Export captures
the visible rows and active filters before the save dialog opens, then checks
that the same document, project snapshot, and file-only document snapshot are
still active before writing. If they changed while the dialog was open, export
is canceled with a retry prompt so a report from an older view is not saved by
mistake. Publication uses the shared atomic file path. Debugger output has no structured
diagnostic model and is not included. The page does not re-run analysis,
classify every candidate as a defect, or resolve conflicts; use the normal
project edit commands after navigating to a finding when an analysis decision
needs changing.

Diagnostic rows with no stored source key, including legacy imported rows,
remain visible as stale, with a source label stating that the key is unavailable
and the row is ungrouped. The view does not guess a key from message text,
address, or the current snapshot. Their exported `source_identity` and
`source_current` fields remain `null`; review identity is namespaced so these
rows cannot inherit marks from a report tied to a known source snapshot.
Duplicate rows remain separate and use occurrence discriminators; a changed
duplicate set drops ambiguous marks.

Use **Stale diagnostic reports** in the category selector to isolate diagnostics whose source identity is missing or differs from the active analysis. This includes loader, project string-scan, type-import, decompiler, and minidump reports; the category combines with severity, review state, search, and function scope like the other filters.
