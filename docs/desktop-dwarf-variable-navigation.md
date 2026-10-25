# Desktop DWARF variable navigation

The Types & Symbols **Variables** page shows imported DWARF parameters and
locals, their owning function, type, scope, and decoded location metadata.
Select a row to inspect its source and location expression. Use **Go to owning
function** to move the shared desktop selection to that variable's function
entry; the disassembly, bytes, pseudocode, and location-scoped views then follow
the normal document navigation flow.

This action navigates to the function entry, not to a register or stack value.
Location expressions and PC ranges remain inspection metadata and are not
evaluated into a runtime address. Variables without a valid owning function
address are not expected from the imported debug-symbol model.
