# Source line breakpoints

The Source page can add or remove a durable software breakpoint at the selected
source line. Select a line with one or more mapped addresses, then choose
**Toggle project breakpoint**. The current mapped address selected by the
Previous/Next address controls is used. The breakpoint is stored in the active
project and can be installed into a debugger target with **Apply Project** in
the Debugger pane.

The command is available for writable projects. A standalone binary has no
project database in which to save the breakpoint. The line must have usable
DWARF or PDB source mapping metadata; the source text itself is not required to
be available for the breakpoint operation.
