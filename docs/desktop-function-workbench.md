# Desktop Function Workbench

Open **Navigate > Function Workbench** (`Ctrl+Alt+F`), use the button in the
Functions dock, or use the function context menu. This workbench turns recovered
function evidence into a triage and navigation workflow without changing project
files or workspace session formats.

Start with **Partial functions** to find incomplete recovery, or **Unresolved
calls** to investigate functions with call records lacking both a concrete target
and an external identity. Other scopes show all functions, complete functions,
or thunks. A case-insensitive name/address query combines with the scope.
Click column headers to sort by entry, presentation name, block count, chunk
count, recovered call count, unresolved call count, or recovery state. Counts
refer to the captured recovered snapshot, including tail-candidate call records;
they are not a claim that every runtime call has been discovered. Incomplete
snapshot status is displayed above the table.

The current listing cursor preselects an exact entry or a uniquely owned chunk
when ownership can be proven within 262,144 chunk checks. Ambiguous or oversized
range searches leave selection empty.

Selecting a function displays its summary, chunks, and recovery stops. Chunk
rows show their start, byte extent, and block count. Stop rows show the exact
address, reason, and available detail, including unsupported instructions,
indirect flow, overlaps, mapping restrictions, and recovery budgets. Selection
alone does not move the workspace cursor. Filtering and sorting retain selection
by full address-space/entry identity when the entry is still visible. If a
filter removes it, actions are disabled until another row is selected.

Use **Open listing**, **Function graph**, **Pseudocode**, **Incoming refs**, or
**Inspect calls** to continue analysis at the function entry. Inspect calls opens
the existing call-site browser with the explicit function owner, avoiding
ambiguous range ownership. Select a chunk or stop and use **Open evidence** to
navigate directly to that evidence address. Normal mapping checks still apply;
unmapped stop addresses can be refused. Double-clicking/activating a function
or evidence row opens its listing. Enter in the query focuses the function list.
Cancel leaves workspace navigation unchanged. Successful navigation uses the
normal desktop history path.

The workbench requires current fresh or incomplete project function analysis
with a matching derived key. It retains an immutable project snapshot while
open. Following a result validates the active document, revision, image and
project snapshot; a tab switch, project change, or reanalysis during the modal
chooser cancels the action with a status message. It remains usable in read-only
projects because it does not submit edits.

The index accepts at most 50,000 function records and 1,000,000 call records;
larger snapshots receive an explanatory message and can still use the docked
Functions browser. A selected function displays at most 4,096 chunk/stop rows,
with truncation disclosed in its summary. Names/search text are bounded at
2,048 characters, the total indexed names at 8 Mi characters, and stop detail at
4,096 characters. An oversized name index is refused with an explanatory message. These synchronous bounded
indexes are transient; filters, sorting, and workbench selection are not saved.
There is no new session/project schema or release/CI workflow.

Validation for this change started an isolated Windows/MSVC 19.44 Debug
`hexlab` build with `BUILD_TESTING=OFF`. Core, types, symbols, processors, image,
analysis, loaders, database and decompiler targets completed; workspace compilation
was still active at handoff. The desktop target has not yet been verified.
No tests are added or run. The Ubuntu 24.04 WSL/Clang 18
configuration found GTK3, but the fresh wxWidgets configuration was stopped
before completion because of its duration; Linux compilation is unverified.
Interactive GUI behavior remains subject to manual host verification.
