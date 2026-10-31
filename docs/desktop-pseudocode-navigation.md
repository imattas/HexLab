# Pseudocode origin navigation

Selecting a pseudocode source line that carries an instruction origin moves the active document selection to that address. The disassembly listing selects and reveals the matching instruction; the CFG canvas selects the containing block, highlights the instruction row when available, and pans it into view. The same reveal action runs when the selected origin is already the workspace selection. When a graph is being rebuilt, its canvas retains the reveal request and applies it when a current graph becomes available.

Origin navigation carries the document ID and workspace document revision used to render the pseudocode, plus the project UUID and edit/byte/decision revisions. The main frame checks those values against the active workspace and current project before moving the shared selection. A closed, replaced, inactive, or revised document cancels the navigation and reports that the origin is stale. Pseudocode generated from an untitled workspace uses the workspace document ID/revision guard without project revisions.

Navigation is address-backed only: pseudocode rows without a validated instruction-origin annotation do not move the listing or graph. The CFG can reveal only addresses represented by its current graph; missing nodes remain selected as workspace locations and are revealed if a later graph contains them.

Stack-local renames and type assignments apply to every recovered access site for that slot in one project command. Unique register SSA variables also collect their defining instruction and all instructions that read that exact version, including register inputs, memory base/index operands, and nested expressions. Merge (phi) values use a stable identity derived from the block entry and destination register, and collect their block-entry definition plus all reads of the merged version. They can be renamed or assigned a type when every collected address is unique to that SSA value and the value does not collide with the function entry. Renames and type assignments apply to those sites atomically. The underlying name annotations and type assignments remain address-keyed, so existing project files and history can replay the edits without a schema change. Each command accepts at most 4,096 distinct access sites; larger variables remain visible but read-only. Shared-origin and function-entry collisions remain read-only. Undo and redo restore the complete edit as one history step.

A selected unique SSA variable can also have a comment stored at its definition
address. The Variables table shows that definition comment, and editing or
clearing it uses the existing address annotation command so it persists with
the project and participates in undo/redo. The comment is attached to the
instruction address and is not duplicated at every read site; shared-origin
and phi-only values remain read-only.

Use **Ctrl+F** while the pseudocode pane is focused to search the currently rendered function. Search is a literal, case-sensitive match by default, wraps at either end, and selects/reveals each result; Enter and the Previous/Next buttons move between matches, while Shift+Enter moves backward. Enable **Whole word** to require identifier boundaries around the match; letters, digits, underscore, and non-ASCII characters count as identifier characters. **Escape** returns focus to the pseudocode. The query is limited to 256 characters and the scan to the first 1 MiB of rendered text. Selecting a result with a mapped instruction origin follows the normal document/project revision guard, so a stale render cannot navigate the active workspace. Search only reads the rendered pseudocode and does not change project state.

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

Phi destinations shown in the Variables table use a deterministic UI identity made from the join block address and destination register. This keeps a selected phi value recognizable when the same analysis snapshot is refreshed, without adding project records or changing the project format. Selection recovery is scoped to the snapshot's AnalysisKey (input identity, byte and decision revisions, and analysis fingerprints); snapshots without a key recover selection only when the same in-memory snapshot is reused. The identity can change when the CFG changes, and it does not identify a phi across different inputs or analysis revisions. Phi values remain read-only because their block-entry address cannot safely identify a persisted annotation.
