# DEX array verifier component checks

The bounded DEX register type-flow tracks an in-image reference descriptor when
one is available. For `aget`/`aput` instructions (`0x44`–`0x51`), it uses that
descriptor only when the reference has a valid type ID in the DEX type table.

For a known descriptor, the verifier rejects a known non-array reference and
checks the immediate component against every array load/store opcode:

| Load / store | Opcodes | Allowed immediate component |
| --- | --- | --- |
| `aget` / `aput` | `0x44` / `0x4b` | `I` or `F` |
| `aget-wide` / `aput-wide` | `0x45` / `0x4c` | `J` or `D` |
| `aget-object` / `aput-object` | `0x46` / `0x4d` | Object (`L...;`) or array (`[...]`) |
| `aget-boolean` / `aput-boolean` | `0x47` / `0x4e` | `Z` |
| `aget-byte` / `aput-byte` | `0x48` / `0x4f` | `B` |
| `aget-char` / `aput-char` | `0x49` / `0x50` | `C` |
| `aget-short` / `aput-short` | `0x4a` / `0x51` | `S` |

This handles
multidimensional arrays by treating the immediate component as an array
reference, retaining its remaining descriptor depth.

Known loads retain the component category in register type-flow, including
the distinction between `I` and `F`, and between the `J` and `D` register pairs.
Object loads retain the exact immediate component descriptor when it has its
own entry in the DEX type table; otherwise they retain a reference category
without inventing a type ID. Stores check the corresponding
primitive or wide type. `aput-object` requires a reference value and an
object/array component, but leaves compatibility between concrete reference
classes to runtime array-store checking (`ArrayStoreException`).

The existing conservative behavior remains for null, unknown, and references
whose descriptor identity is not available: category checks still apply, while
no component-specific conclusion is made. Shared `aget` loads use the existing
polymorphic scalar category, admitting either integer or float consumers;
shared `aput` accepts either integer or float values. Unknown `-wide` loads
retain an untyped wide pair and stores admit either long or double pairs.
Object fallback loads retain an untyped reference, and object stores still
require a reference-compatible value (including null). The verifier does not infer facts
from external class hierarchies. Component mismatches proven by an in-image
descriptor report the method index, code-item file offset, instruction code-unit
offset, and opcode; malformed or absent type IDs are not dereferenced.

These checks run inside the existing bounded, cancellable verifier worklist and
add no unbounded hierarchy traversal.

Scope excludes runtime null, bounds, and concrete array-store checks, and does
not extend component validation to `array-length`, `fill-array-data`, or
`filled-new-array`. Verification for this wave is compilation of the existing
Windows Debug `hexlab_loaders` target; no tests are added or run.
