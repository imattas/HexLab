# Live PDB locals in the debugger

For a PE image with a uniquely matched PDB, the debugger can display CodeView
locals and parameters from the bound PDB metadata. A row is shown only when a
CodeView defrange covers the selected frame's current PC and the PC is outside
that range's gap list. The table reads the selected frame's live registers and
uses the debugger memory reader for memory-backed locations.

Currently evaluated locations are AMD64 and x86 register values,
frame-pointer-relative memory (RBP/EBP), and register-relative memory using
AMD64/x86 CodeView register identifiers. `S_DEFRANGE_REGISTER_REL_INDIR` is
evaluated when its parent and UDT offsets are zero and the spilled-member flag
is clear: the selected register plus
the signed frame displacement identifies a pointer slot, the debugger reads
one architecture-width pointer there, then reads exactly the local's known
type size at the pointee. `S_DEFRANGE_SUBFIELD_REGISTER` resolves the parent
aggregate's expanded CodeView field list and reads the exact field type size
from the register when exactly one non-inherited data field begins at the
recorded parent offset. The field and all sibling data member extents must be
known, fit within the parent, and not overlap. Missing field lists, unions,
inherited layouts, duplicate offsets, unresolved member sizes, and overlapping
fields remain unavailable; field-list evaluation is capped at 4096 entries.
Spilled-member ranges and nonzero-offset indirect
fragments also remain unavailable because their parent/pointee member extent
is not established by the current safe path. The evaluator does not infer a
fragment size from the register width or consume the remainder of the parent
as if it were a member.

Register or memory values remain unavailable when their required register or
type size is unknown, the register is absent, the type exceeds the 256-byte
preview bound, an address calculation overflows, or memory cannot be read in
full. PE section coordinates are validated against the image section extent
before they are translated. Rows without a live range are omitted;
unsupported CodeView register identifiers are not guessed. PDB rows duplicate
a DWARF row only when no same-name, same-kind DWARF row is already available.

Scalar previews are bounded to 256 bytes. Small values are displayed as
scalars and wider values as bytes. Register-backed wide values require enough
bytes from the debugger for the complete type.
