# Pseudocode origin navigation

Selecting a pseudocode source line that carries an instruction origin moves the active document selection to that address. The disassembly listing selects and reveals the matching instruction; the CFG canvas selects the containing block, highlights the instruction row when available, and pans it into view. The same reveal action runs when the selected origin is already the workspace selection. When a graph is being rebuilt, its canvas retains the reveal request and applies it when a current graph becomes available.

Origin navigation carries the document ID and workspace document revision used to render the pseudocode, plus the project UUID and edit/byte/decision revisions. The main frame checks those values against the active workspace and current project before moving the shared selection. A closed, replaced, inactive, or revised document cancels the navigation and reports that the origin is stale. Pseudocode generated from an untitled workspace uses the workspace document ID/revision guard without project revisions.

Navigation is address-backed only: pseudocode rows without a validated instruction-origin annotation do not move the listing or graph. The CFG can reveal only addresses represented by its current graph; missing nodes remain selected as workspace locations and are revealed if a later graph contains them.
