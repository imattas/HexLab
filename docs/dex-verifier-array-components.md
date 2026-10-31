# DEX array verifier component checks

The bounded DEX register type-flow tracks an in-image reference descriptor when
one is available. For `aget`/`aput` instructions (`0x44`–`0x51`), it uses that
descriptor only when the reference has a valid type ID in the DEX type table.

For a known descriptor, the verifier rejects a known non-array reference and
checks the immediate component against the opcode: `aget`/`aput` use `I` or `F`,
`-wide` uses `J` or `D`, `-object` uses an object or array descriptor, and the
boolean, byte, char, and short forms use `Z`, `B`, `C`, and `S`. This handles
multidimensional arrays by treating the immediate component as an array
reference, retaining its remaining descriptor depth.

Object and wide loads retain the component descriptor in register type-flow,
including the distinction between `J` and `D`. Stores check the corresponding
primitive or wide type. `aput-object` requires a reference value and an
object/array component, but leaves compatibility between concrete reference
classes to runtime array-store checking (`ArrayStoreException`).

The existing conservative behavior remains for null, unknown, and references
whose descriptor identity is not available: category checks still apply, while
no component-specific conclusion is made. The verifier does not infer facts
from external class hierarchies. Component mismatches proven by an in-image
descriptor report the method index, code-item file offset, instruction code-unit
offset, and opcode; malformed or absent type IDs are not dereferenced.

These checks run inside the existing bounded, cancellable verifier worklist and
add no unbounded hierarchy traversal.
