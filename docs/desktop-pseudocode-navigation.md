# Pseudocode origin navigation

Selecting a pseudocode source line that carries an instruction origin moves the active document selection to that address. The disassembly listing selects and reveals the matching instruction; the CFG canvas selects the containing block, highlights the instruction row when available, and pans it into view. The same reveal action runs when the selected origin is already the workspace selection. When a graph is being rebuilt, its canvas retains the reveal request and applies it when a current graph becomes available.

Origin navigation carries the document ID and workspace document revision used to render the pseudocode, plus the project UUID and edit/byte/decision revisions. The main frame checks those values against the active workspace and current project before moving the shared selection. A closed, replaced, inactive, or revised document cancels the navigation and reports that the origin is stale. Pseudocode generated from an untitled workspace uses the workspace document ID/revision guard without project revisions.

Navigation is address-backed only: pseudocode rows without a validated instruction-origin annotation do not move the listing or graph. The CFG can reveal only addresses represented by its current graph; missing nodes remain selected as workspace locations and are revealed if a later graph contains them.

Unique register SSA variables collect their defining instruction and all instructions that read that exact version, including register inputs, memory base/index operands, and nested expressions. Their UI identities include the owning function entry, defining instruction address, and destination register, so unrelated earlier definitions do not renumber them and overlapping function views do not share an identity. Merge (phi) values include the owning function entry, join block address, and destination register, and collect their block-entry definition plus all reads of the merged version. A value can be renamed or commented when its function ownership and identity are unique and it does not collide with the function entry. Shared-origin and function-entry collisions remain read-only. Type assignments continue to use the existing address-keyed project model.

A selected unique SSA variable can also have a comment. Variable renames and
comments are stored as project edits scoped by the stable owning function ID,
the value's definition address, its SSA/phi identity, and the exact analysis
source key. The source key records input identity, byte and decision revisions,
recipe and engine fingerprints, and an optional external-input fingerprint.
The project database persists these rows and the project history records each
change as one undo/redo step. Clearing both fields removes only that scoped
edit. Existing edits remain stored through replacement or reanalysis; when the
analysis source key changes they become dormant and are not shown or applied.
An edit can be re-created under the new key after the new analysis is current.
Address-only annotations are not used as a fallback for variable names or
comments, so overlapping functions and stale local annotations cannot alias a
scoped variable edit.

Use **Ctrl+F** while the pseudocode pane is focused to search the currently rendered function. Search is a literal, case-sensitive match by default, wraps at either end, and selects/reveals each result; Enter and the Previous/Next buttons move between matches, while Shift+Enter moves backward. Enable **Whole word** to require identifier boundaries around the match; letters, digits, underscore, and non-ASCII characters count as identifier characters. **Escape** returns focus to the pseudocode. The query is limited to 256 characters and the scan to the first 1 MiB of rendered text. Selecting a result with a mapped instruction origin follows the normal document/project revision guard, so a stale render cannot navigate the active workspace. Search only reads the rendered pseudocode and does not change project state.

With the pseudocode pane focused, **F3** finds the next occurrence of the current query and **Shift+F3** finds the previous one. **F2** renames the uniquely selected editable variable using the same project command as the Rename button; ambiguous, shared-origin, function-entry, and read-only selections are not renamed.

The SSA variable **Previous occurrence** and **Next occurrence** controls also
select and reveal the instruction line for each mapped use. They use the same
document and project revision guard as source selection; occurrences without a
validated origin remain selectable in pseudocode without moving the listing or
graph.

Use **Copy selected variable** in the Variables table to copy a field/value TSV
summary from the current rendered function: document and function identity,
display name and token, definition address, displayed type and comment, edit
availability, and up to 256 access-site addresses. Additional access sites are
reported as omitted. Control bytes are escaped and the complete clipboard text
is limited to 64 KiB; oversized or invalid UTF-8 output is rejected. Copying
uses the current rendered metadata and does not reanalyze or edit the project.

**List matches...** opens a result chooser for the same literal,
case-sensitive query and Whole word option. It lists up to 512 nonoverlapping
matches from the first 1,048,576 rendered characters. The chooser shows the
one-based source line, verified instruction origin or **Unmapped source**, and
up to 180 context characters around each occurrence. A limit warning means
more results may exist; refine the query to narrow them. Synthetic declarations
and other unmapped source lines remain searchable without invented addresses.

Choose **Reveal selected match** or activate a result to select the exact
occurrence in the pseudocode pane. Mapped occurrences follow the usual
document/project revision guard into the listing and graph; unmapped
occurrences remain in pseudocode. Match positions are converted through the
native text control's line/column API so source line endings do not shift the
selection on Windows. The chooser retains the render serial, document ID, and
rendered document revision; a new render or document switch while it is open
cancels the result and asks the user to list matches again. Canceling leaves
the source selection unchanged. The result list does not edit project data.

Enable **All functions** and choose **List matches...** to search generated
pseudocode for recovered functions in the current project snapshot. The search
uses the same literal, case-sensitive and optional Whole word rules as the
current-function search. Results show the owning function name and entry, the
line in that function's generated pseudocode, and matching context. Choosing a
result opens the owning function and selects that exact query occurrence when
the query text survives rendering. If local/type substitutions changed the
line text, it selects the corresponding rendered source line instead. A line
with a validated instruction origin also reveals that instruction in the
listing and graph under the normal document/project revision guard; an
unmapped line remains selected in pseudocode. The pending reveal retains the
query, whole-word mode, source line, and occurrence number, then rematches it
in the new render. It is discarded if document/project identity changes, the
requested function does not render, or its source line is unavailable.

Cross-function search is bounded to 256 functions, 5,000 instructions per
function, 50,000 instructions total, 4,194,304 generated characters, and 512
matches. Oversized functions are skipped, and the result summary reports when
the search hit a cap or skipped functions. The search reads the immutable
analysis snapshot and does not edit project data. Previous/Next continue to
search only the function currently shown.

Stable project identities for every SSA/phi value, arbitrary source editing,
and complete control-flow structuring and ABI/type coverage remain outside the
currently supported workflow.
The pseudocode pane has dedicated **A-**, **A+**, and **Reset** controls for its
text size. The range is bounded to 6–32 points, and changing it affects only
the rendered view; it does not alter the generated pseudocode or project data.

SSA and phi identities are deterministic, function-scoped presentation keys based on defining provenance rather than SSA version numbers. This preserves selection across reanalysis when the function/value provenance is unchanged. Persisted name and comment edits also require an exact matching analysis source key; the presentation identity does not promise that a value survives CFG changes, different inputs, or changed analysis fingerprints. Phi values with shared/ambiguous origins or function-entry collisions remain read-only.

The instruction pane's **Previous function** and **Next function** controls navigate
between recovered function entries in address-space/address order. They stay
disabled at the ends of the current analysis snapshot and use the normal
document/project revision guard. Returning to a function restores its saved
pseudocode and variable selection when the same analysis key is still active.

## Scoped pseudocode edits

Pseudocode variable names, comments, and manual type assignments are persisted by stable function ID, definition address, SSA or phi identity, and exact analysis source key. When the analysis source changes, the edits remain stored but dormant; they become active again only when the exact source key returns. A scoped type assignment takes display precedence over legacy address-based assignments, which remain a fallback for older project data. Clearing a scoped type preserves that variable's name and comment.
