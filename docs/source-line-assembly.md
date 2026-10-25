# Source line and disassembly navigation

The desktop Source page pairs the selected source line with the machine
instructions mapped to that line. The upper pane shows bounded local source
context. The lower pane lists unique mapped addresses, formatted instructions
when the active analysis has a current instruction fact, and an explicit state
when the mapping has no matching instruction or analysis is unavailable.

Select a source line to navigate to its first mapped address. Activate an entry
in the instruction list to navigate directly to that address in the disassembly,
bytes, graph, and pseudocode views. The existing Previous address and Next
address controls cycle through the machine addresses for the selected line.

The list is bounded to 4,096 mapped addresses per line. Project instruction
facts are used only when their byte and analysis-decision revisions match the
current project; otherwise the view does not present stale assembly as current.
Source files continue to use the existing bounded, local-file-only reader.
