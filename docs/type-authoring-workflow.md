# Type authoring in the desktop workbench

The **Types & Symbols** view supports project-owned integer, pointer, array,
enumeration, function-prototype, structure, and union definitions. Select a
definition and use **Edit selected type** to replace its definition while
retaining its project identity. Aggregate member entries use
`member_name type_name byte_offset` for structures and
`member_name type_name` for unions. Enumeration values accept decimal or
`0x`-prefixed hexadecimal integers. Function prototypes select a return type,
then accept one `parameter_name type_name` entry per line and a variadic flag.

To apply a definition, select an address in the listing or graph, select its
type row, then press **Assign selected type**. The selected definition is
assigned directly. If no type row is selected, **Assign type to selection**
opens the type chooser. Reapplying the type already at that address is a
no-op. The command is committed through the project controller, so the current
listing and pseudocode refresh from the new project snapshot. Assignments are
project data and survive closing and reopening the project.
