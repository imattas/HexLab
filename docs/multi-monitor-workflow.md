# Multi-monitor workbench layout

The View menu can move a dockable pane to the next attached display. The
disassembly, graph, and pseudocode pages move together as the central workspace;
the Functions, Symbols, Binary Metadata, Debugger, and Output panes can move
independently. Repeating the command for a floating pane cycles it through the
available displays.

The destination is the display after the pane's current display in the wxWidgets
display order, wrapping to the first display. HexLab centers the floating pane
in that display's usable area and sizes it to roughly four fifths of the available
width and height. The move command is disabled when only one display is
available. The window manager remains in control of final placement if a display
is disconnected during the move.

Use **View > Dock Floating Panes** to return floating workbench panes to their
configured dock positions. **View > Reset Layout** restores the original full
layout. Navigation and document state remain owned by the same main frame, so
moving a pane does not create another project or analysis session.
