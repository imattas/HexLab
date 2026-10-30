# Dalvik register lifting

HexLab lifts a deliberately small DEX method subset into the shared decompiler
IR. The generic `lift_function` entry point dispatches DEX functions to
`lift_dex_function`, so callers and the CLI use the same implementation.

Supported instructions are 32-bit register moves (`move`, `move/from16`,
`move/16`), integer constants (`const/4`, `const/16`, `const`), 32-bit integer
register arithmetic (add, subtract, multiply, bitwise operations, and shifts),
wide register moves (`move-wide` forms), signed `const-wide` encodings
(`/16`, `/32`, `/64`, and `/high16`), 64-bit add/subtract/multiply/bitwise
operations and shifts, and `return-wide`, plus `return-void`, `return`,
`goto` forms, and the six two-register and six zero-comparison conditional
branches. `const/high16` retains its exact 32-bit immediate bit pattern.
Single- and double-precision add/subtract/multiply/divide/remainder lift in
both three-register and `/2addr` encodings; double operands use the checked
`vN`/`vN+1` pair model shared by wide DEX values. `cmpl-float`, `cmpg-float`,
`cmpl-double`, `cmpg-double`, and `cmp-long` preserve typed inputs and write
their int32 compare results through named intrinsics; `cmpl`/`cmpg` retain the
NaN bias in the operation name. Integer
`lit16` and `lit8` add, reverse subtract, multiply, bitwise, and shift forms
lift with signed immediate handling; shift counts are masked to five bits.
The compare-result intrinsic can feed the existing conditional branches.

Integer signed divide/remainder operations (int and long, three-register,
`/2addr`, and literal forms) produce typed arithmetic values and add a
method-relative `may_trap` edge for `java.lang.ArithmeticException` when the
divisor is zero. DEX integer division's minimum-value divided by negative one
case remains a normal wrapped result. Floating constants are kept
as exact bit patterns until a typed use provides floating context. It also
lifts `iget`/`iput`, `sget`/`sput`, array loads/stores and `array-length`, the five
invoke kinds and their `/range` forms, `move-result` variants, `new-instance`,
`new-array`, `filled-new-array`, and `filled-new-array/range` as conservative
memory-effect intrinsics. Filled-array instructions retain their type index and
all encoded source registers. When descriptor metadata is available, the type
index must name an array descriptor; each one-word element operand is typed as
its array component (including references, int/float, and narrow primitive
register values). `long[]` and `double[]` are rejected because the encoded
filled-array forms provide one register word per element, as specified by the
[Android Dalvik bytecode reference](https://source.android.com/docs/core/runtime/dalvik-bytecode).
Without descriptor
metadata, operands remain unknown 32-bit words. When `move-result-object`
immediately follows in the same basic block, its destination is linked as an
unknown 32-bit reference output of the allocation intrinsic; its array
descriptor is not propagated to later uses. `move-result` and `move-result-wide`
after a filled-array instruction are rejected as malformed. `fill-array-data` retains
the checked method-relative payload target and array reference as an opaque
memory write; the array-data payload
contents, element width, and range effects are not yet imported into the lifter.
Object moves/returns,
string/class constants, casts, instance tests, monitor operations, throws, and
`move-exception` are described in [Dalvik object-operation lifting](dex-object-lifting.md).
Packed and sparse
switches use a validated, method-relative data payload to populate a complete
case/default dispatch in the lifted CFG. Each lifted
instruction keeps its original method-relative address and analysis instruction
ID as provenance. Branch targets stay in their method-relative address space.

The common IR register operand stores the full 16-bit DEX virtual-register
index. Wide values use a 64-bit IR operand based at vN and occupy the Dalvik
pair vN/vN+1; v65535 cannot begin a pair because its second slot would exceed
the operand index. When matching `DexMetadata` code-item metadata is available
for the method address space, lifting also checks every decoded register
operand against that method's declared `register_count`; a wide operand must
fit both register words. This catches out-of-range operands across the whole
recovered method, including blocks reached through branches.
If metadata has no matching method code row, method-specific upper bounds
remain unchecked. Wide shifts take a 32-bit count register and mask it to six
bits. Field reads/writes (`iget`/`iput` and `sget`/`sput`), array
loads/stores, and `array-length` lower to memory-effect intrinsics. Standard
field forms use retained field descriptors when metadata is supplied: int/float,
long/double, object/array, boolean, byte, char, and short values receive their
descriptor-specific IR type, and descriptor types incompatible with the
encoded opcode variant are rejected as malformed. Without metadata, the opcode
variant determines the conservative type. Array element types and optimized
volatile field offsets remain unresolved. `new-instance` and `new-array`
produce unknown references and an unknown memory effect.

Optimized ODEX `return-void-barrier` (`0xf1`) lifts as a void return. The
shared IR has no separate representation for the runtime barrier, so lifting
preserves its control-flow termination without modeling that scheduling detail.

Optimized DEX `iget`/`iput`/`sget`/`sput` volatile variants (`0xe3`–`0xeb`)
lift to the corresponding field memory intrinsic with a `_volatile` name and
the correct narrow, wide, or object value kind. Their reads and writes are
retained, but the common IR has no explicit volatile memory-ordering primitive;
the name preserves the distinction for later consumers. Field offsets remain
unresolved table indexes.

The five invoke kinds and their `/range` forms lower to call-like intrinsics
that read every encoded argument register and conservatively invalidate memory.
The loader retains each prototype's parameter and return type IDs and each
method ID's prototype index. With matching metadata, invocation operands are
typed from their descriptors: references are pointers, floating types retain
their width, primitive integer widths and signedness are retained, and wide
arguments use a single 64-bit register operand based at the low register. The
loader and lifter require each wide pair to be adjacent and ordered in the
encoded argument list. If descriptor metadata is unavailable, operands remain
unknown 32-bit words. A method-index invoke followed immediately in the same basic
block by the matching `move-result`, `move-result-wide`, or
`move-result-object` now writes a descriptor-typed unknown call output to the destination
register; the result-copy instruction becomes a no-op in the lifted IR. The
`filled-new-array` family also links an immediately following
`move-result-object` to its unknown array-reference output. Element operands
use the retained array component type where available, but later uses of the
result do not retain a concrete array descriptor.
Polymorphic calls use their encoded prototype index, and custom calls use the
method-type value from a retained call-site array when available. Known void
or incompatible return variants, unrelated non-invoke predecessors, noncontiguous
addresses, and block-split result copies fail closed. If return metadata is
unavailable, the move-result destination remains an unknown value. This DEX
subset does not yet resolve method or field identifiers to display names, model
exceptions precisely, or distinguish static initialization and allocation
effects. Unknown effects are preserved instead of inventing values.
Literals outside the implemented constant forms, exception handlers, and all
other unmodeled opcodes still return `ErrorCode::unsupported` with the method-relative
instruction address. It does not produce a partial function when an instruction
has unknown effects.

DEX 038+ `invoke-polymorphic` (including `/range`) and `invoke-custom` (including
`/range`) are decoded as calls. Polymorphic instructions retain both the method
and prototype indexes; custom instructions retain the call-site index. Their
encoded argument words use descriptor-derived types when retained call-site
prototype metadata is available, and the call-like intrinsic invalidates
memory. Custom-call result shapes are resolved
from the retained call-site method type when that metadata is present. When prototype metadata is
available, invocation lifting checks the encoded register-word count against the prototype's
parameter word count, including the implicit receiver for non-static and polymorphic calls;
`long` and `double` parameters count as two words and must use adjacent ordered
register pairs. A mismatch is rejected as malformed instead of producing a
misleading call intrinsic. DEX 039+ `const-method-handle` and
`const-method-type` decode and lift as unknown reference constants while
preserving the method-handle or prototype index. The bytecode decoder does not
currently validate that the file version permits these opcodes, and the
analysis layer does not resolve call-site arrays or method handles to names.
The loader now retains each type descriptor once and keeps prototype return and
parameter type-ID references in encoded order; wide parameters still occupy two
register words. Invocation arguments now retain descriptor types, but their
values are not checked against a whole-method register type lattice. Result
linkage uses retained return types
and is limited to immediate same-block move-result pairs. These opcode
encodings follow the [Android Dalvik bytecode reference](https://source.android.google.cn/docs/core/runtime/dalvik-bytecode?hl=en).

Five-register 35c, 35mi, 35ms, and 45cc forms take their fifth argument from
the encoded `G` nibble. Decoding and typed register effects use that nibble
directly; the adjacent `A` nibble is only the argument-word count. This follows
the [Android instruction format reference](https://source.android.com/docs/core/runtime/instruction-formats).

Function and block boundaries come from the existing analysis snapshot. This
first slice does not independently verify Dalvik register typing, reconstruct
exception edges, prove verifier invariants, or structure arbitrary cyclic CFGs.
Packed and sparse switch payloads are bounded to 1,024 cases; sparse keys must
be strictly increasing, and every case target must resolve to a block in the
recovered method. Disassembly previews at most 64 entries and reports the exact
omitted count. The payload bytes participate in instruction dependencies,
so edits to a switch table invalidate its derived CFG. Malformed, unbacked, or
over-budget payloads preserve only the switch's default fallthrough and mark
analysis incomplete.
