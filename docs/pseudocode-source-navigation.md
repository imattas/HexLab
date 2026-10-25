# Pseudocode source navigation

The desktop pseudocode pane maps source lines back to their machine instruction
only when the rendered line contains the formatter's explicit `// 0x...`
instruction-origin marker and that address belongs to the recovered function.
Moving the caret or selecting text on such a line navigates the active document
to that instruction through the existing workspace navigation path. The normal
workspace history therefore records a changed pseudocode destination, and
Back/Forward continues to use the same navigation history as the other panes.

When the disassembly/listing selection changes, the pseudocode pane selects the
corresponding instruction row and scrolls the source view to its origin line.
An existing text selection on that same line is preserved so variable
definition/use navigation remains usable.

Synthetic declarations, control-flow headers, phi-copy lines, and other source
lines without a verified instruction origin do not navigate. Address inference
from nearby statements is intentionally avoided. Multiple pseudocode statements
may share an instruction origin; they resolve to the same machine instruction.
