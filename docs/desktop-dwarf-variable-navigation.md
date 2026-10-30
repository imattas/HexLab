# Desktop DWARF variable navigation

The Types & Symbols **Variables** page shows imported DWARF parameters and
locals, their owning function, type, scope, and decoded location metadata.
Select a row to inspect its source and location expression. Use **Go to owning
function** to move the shared desktop selection to that variable's function
entry; the disassembly, bytes, pseudocode, and location-scoped views then follow
the normal document navigation flow.

When the selected variable has DWARF location-list ranges, the details identify
the range active at the current selection only when its address space matches
the variable's owning function. **Go to active location range** navigates to
the executable beginning of that active range; when the current selection is
outside every range, it uses the first range whose beginning maps to executable
image bytes. The action is disabled when no range start is mapped executable.
Navigation uses the current document/project snapshot checks and updates the
disassembly and pseudocode panes through ordinary workspace selection.

The owning-function action navigates to the function entry, not to a register
or stack value. Location expressions remain inspection metadata and are not
evaluated into a runtime address. Variables without a valid owning function
address are not expected from the imported debug-symbol model.
