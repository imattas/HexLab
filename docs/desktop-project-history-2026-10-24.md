# Desktop project history

The Binary Metadata pane includes a History page for saved and untitled
projects. It lists durable history entries in ascending step order, shows the
group, whether bytes or analysis decisions changed, and whether the entry is
currently applied or available to redo. History is loaded in bounded pages;
use **Load next page** to continue through large projects.

Selecting a row reconstructs that exact step as a separate read-only
projection. **Preview initial state** inspects step zero. The preview displays
historical annotations, bookmarks, types, type assignments, function and
region decisions, user references, debug variables, and patch spans. It does
not call undo or redo and does not replace the active project snapshot. A
selected historical location can be navigated in the current document; the
listing and byte panes continue to show the current live state.

History reads are submitted to the project actor and pinned to the displayed
edit revision. If the project changes while a request is pending, the result
is discarded or reported as a revision conflict; refresh the page to read the
new revision. Exact-step reconstruction is bounded to 4096 history steps and
64 MiB of delta payload. A farther or larger projection reports the database
limit error while the durable entry remains visible in the page.

Select a history row and choose **Save selected step as project...** to recover
that state into a separate project file. **Preview initial state** selects step
zero, which can also be saved. The source must already be a saved project;
untitled projects can still be previewed, but need to be saved first. Read-only
projects can create recovered copies.

The recovery dialog identifies the source and selected step. Its checked
**Require this source edit revision** guard defaults to the displayed revision;
leave it checked to save the state you inspected, or enter another unsigned
decimal revision explicitly. Clearing the guard uses the source revision
observed when the background worker opens the source. The actual copied
snapshot must match that revision, so a concurrent edit can still produce a
conflict. Choose an output path in the save dialog; replacing an existing file
requires its normal overwrite confirmation.

Saving runs on a separate read-only source connection and leaves the active
project, its cursor, and its history unchanged. The worker also verifies the
source UUID before saving, rejecting a source path replaced by another project.
The output receives a new UUID, retains the complete undo/redo log and stable-ID
allocation, and opens at the selected exact step, including redo steps and
positions inside command groups. Replay uses the same 4096-step and 64 MiB
limits as the preview. Native publication protects the source and original
input paths, validates embedded input, and retains a replaced destination as a
recovery artifact.

**Cancel recovered copy** requests cancellation. The status waits for the
operation's result because cancellation can arrive after publication has already
succeeded. Errors show the native reason, including stale revisions, invalid
steps, exhausted budgets and destination failures. Success identifies the saved
path; use **File > Open Project...** to open it independently. Switching documents
does not retarget an in-progress copy, and its completion still identifies the
original source. Closing the History view requests cancellation without blocking
the UI or letting the worker access destroyed windows.

See [historical save guarantees](../libs/database/HISTORY_SAVE.md) for exact
revision, validation and publication semantics.
