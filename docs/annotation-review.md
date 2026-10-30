# Review saved names and comments

Use **Edit > Review Names and Comments...** to inspect the active project's
saved annotation rows. The dialog shows 512 rows per page, with location, saved
name, and saved comment. Previous/Next page changes only the review page;
it does not move the listing cursor. Ctrl/Shift selects multiple rows on the
current page. Page changes clear the selection. The filter applies a
case-insensitive substring search to location, saved name, and comment within
the current page; the match count is shown in the status line. Filtering clears
the current selection, and clear/copy actions use only visible selected rows.
Enable **Search all rows** and choose **Search all now** to scan the first
100,000 saved annotation rows across page boundaries. Results remain paged at
512 rows; the status line identifies when the scan cap omits later rows. A
changed query is applied when **Search all now** is chosen.

Rows preview at most 128 UTF-8 name bytes and 160 comment bytes. Selecting a row
shows a larger preview capped at 512 name bytes and 4096 comment bytes, with
truncation marked and UTF-8 character boundaries preserved. This is a view of
saved fields, so automatic/generated names and type assignments are not offered
as annotation rows. Read-only projects can be reviewed but cannot be cleared.

Choose **Copy selected TSV** to copy all selected rows on the current page with
their complete location, saved name, and comment. Tabs, quotes, and line breaks
are quoted so the output remains three columns when pasted into a spreadsheet.
The clipboard payload is capped at 4 MiB; oversized selections are rejected
without copying a partial export. Copying is available for read-only projects
and does not change project state.

Choose **Assign type to selected addresses...** to assign one existing project
type to selected rows whose locations are virtual addresses. Rows at file
offsets cannot receive address type assignments, so the action is disabled when
the selection includes one. The chooser previews up to three current and
proposed assignments and counts assignments that will be replaced; rows already
using the chosen type are skipped. The action affects only selected rows on the
visible result page, with a maximum of 512 rows. It creates one
revision-checked, undoable project batch. Annotations without a saved name or
comment are not rows in this review and remain editable through the Types &
Symbols assignment page.

Choose **Replace selected comments...** or **Replace selected names...** to
replace literal text in the selected field on the visible result page. The
search text is non-empty and case-sensitive; replacement text may be empty to
remove matches. Every non-overlapping occurrence is replaced. The confirmation
previews before/after values for up to three changed rows and reports the full
row and occurrence counts. In Search all mode, only selected rows on the
currently visible page are affected. Find/replacement text is limited to 1 MiB
each; the total source fields scanned and total replacement fields are each
capped at 4 MiB. An over-limit plan is rejected before any edits are submitted.
Applying the plan creates one revision-checked, undoable project batch.
Name replacements that conflict with another saved name are rejected by normal
rename validation; the whole batch remains unapplied. Canceling the confirmation
leaves the project unchanged.

Choose **Clear saved names**, **Clear saved comments**, or both, then **Clear
selected fields...**. The final review reports the exact count of nonempty
saved names/comments that would be cleared. Canceling or closing the review
does not edit the project. Empty fields produce no redundant commands. Clearing
a name restores ordinary automatic naming; clearing a comment removes its
saved text. Types, bookmarks, references, and binary bytes are unchanged.

The selected page and every command retain the captured project snapshot,
document/actor session, AnalysisKey, and edit revision. A changed active
document, reopened/replaced actor, or changed immutable project publication
rejects the review and asks for it to be reopened. The writer rechecks the
captured snapshot identity, AnalysisKey and expected edit revision immediately before running the batch,
so a queued edit cannot silently change its target after UI review. The normal
database revision check also rejects intervening external commits.

At most 512 rows produce 1024 name/comment commands. The existing atomic
workspace batch validates all selected changes before committing one undoable
history change. A failed validation leaves the whole batch unapplied; Undo
restores the cleared fields together. Submission runs on the ordinary project
actor and its cancellation/error-publication path. No annotations are mutated
while paging or previewing.

Type assignments remain address scoped and are not annotation rows. In the
disassembly listing, an address row with an assignment now shows the assigned
project type name in a `[type: ...]` suffix. This makes assignments visible
while browsing code; the Types & Symbols and typed-data views remain the place
to inspect fields and change assignments.

The workspace `ProjectActor::execute_batch_at_revision` operation accepts
1..4096 commands with an explicit captured snapshot, source key and edit
revision; existing `execute_batch` behavior remains available. The reviewer
can assign one existing type to selected address rows; defining types and
inspecting assigned layouts remain in Types & Symbols and the typed-data view.
CLI project commands and Python `apply_annotations()`/
`apply_batch()` remain available for scripted rename/comment batches.
