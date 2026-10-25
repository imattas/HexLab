# Global data type evidence

The desktop pseudocode view can now annotate a statically addressed global
access when the project has enough independent evidence to identify it. This
slice currently applies to PE images with bound PDB data symbols.

For each lifted function instruction, the view looks for an absolute memory
operand with a known, byte-aligned width. It then requires all of the following:

- Exactly one non-procedure PDB symbol with a valid identifier maps to the
  operand's loaded image address.
- A project type assignment exists at that exact address, and its declared
  size equals the access width.
- The reference index has an outgoing memory read or write from that exact
  instruction to the same target address.
- When the PDB data symbol resolves to a retained TPI type record, that type's
  size and normalized name also agree with the project assignment. IPI-indexed
  data symbols are skipped because their index is not in the TPI namespace.

When these checks agree, pseudocode adds an inline comment such as
`/* global g_count : uint32_t */` to the instruction row. The PDB address has
already been translated from its section coordinates into the loaded PE image
address, so rebased images use the same identity as lifted operands and xrefs.
The reference-index cross-check ensures that this is an observed memory
access, not an address mention or relocation by itself. Existing user type
assignments remain the source of the rendered type; the workflow does not
invent or persist a type assignment.

This first slice does not label dynamic-base accesses, interior structure
fields, array elements, pointer-chased globals, indirect references whose
target cannot be resolved, ambiguous symbols, or accesses whose width differs
from the assigned type size. It also does not derive primitive PDB types from
raw CodeView indexes. PDB symbols without a project type assignment can still
be reviewed in the PE symbol view but are not given a pseudocode type.
