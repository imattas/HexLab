# Desktop keyboard and accessibility foundations

The virtual listing, bytes, references, search results, type/symbol tables and
other `VirtualTable` users expose a keyboard-use hint: arrows and Page Up/Page
Down move through rows, and Enter or double-click activates the selected row.
The reference view supports Alt+Left/Alt+Right to page through references and
Ctrl+Home to return to its current origin. The search view supports Alt+Up and
Alt+Down to move to the previous or next visible result. Ctrl+L focuses and
selects the loaded-results filter from anywhere in the search panel. The filter
description explains the searchable metadata and that only loaded results are
considered. Result actions, the page status, the preview, and search-dialog
validation/value fields now have descriptive tooltips. Both keyboard navigation
paths use the same actions as their on-screen buttons, so selection, page state
and document navigation remain synchronized.

Search-dialog and search-panel spacing now uses `FromDIP`; graph and reference
toolbars do as well. Major tables and controls have stable wx window names,
and the graph zoom, reference endpoint, paging and origin controls have
descriptive tooltips. Debugger and type/symbol panes already used `FromDIP`
for their layout metrics and stable control names, so this pass leaves their
behavior intact.

## Workspace navigation and display recovery

The View menu includes **Focus Workspace Pane** entries for the disassembly /
graph / pseudocode workspace, functions, symbols, binary metadata, debugger,
output, and (when enabled) the Python console. Each entry has a direct
`Ctrl+Alt+F1` through `Ctrl+Alt+F7` shortcut. Choosing one reveals the pane,
updates docking, and moves focus to the first visible control that accepts
keyboard focus. This provides a predictable way to return to a pane after
rearranging the workspace. Pane roots also have descriptive wx window names so
accessibility bridges have useful context for the main workspace regions.

Saved frame geometry is matched to the display with the greatest overlap. If a
monitor was disconnected, the frame is placed on the nearest available display;
its size is constrained to that display's work area and its position is clamped
so the whole frame can be reached. Existing adaptive layout behavior continues
to reposition metadata and output panes when the usable frame width is narrow,
with its width threshold and pane dimensions scaled through `FromDIP`. Pane
movement centers each floating pane in the target display's client area.

The status and validation controls retain the platform's default text and
background colors; the search view adds no color-only state encoding, so the
host high-contrast theme remains in control. Search controls are created in a
top-to-bottom tab order (page status/actions, filter/clear, result actions,
results, preview); dialog labels precede their associated inputs.

This remains a focused keyboard and scaling improvement, not a completed
accessibility audit. Screen-reader announcements, keyboard focus order after
restoring arbitrary user perspectives, high-contrast themes, and multi-monitor
DPI transitions still need validation on supported desktop platforms. Native
list controls still depend on wxWidgets and the host accessibility bridge for
row and column announcements. Tooltip text is exposed as help by supported
wxWidgets/native accessibility bridges; exact screen-reader announcement
behavior varies by wxWidgets version and platform.
