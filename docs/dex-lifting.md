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
`goto` forms, and the six
two-register and six zero-comparison conditional branches. It also lifts
`iget`/`iput`, `sget`/`sput`, array loads/stores and `array-length`, the five
invoke kinds and their `/range` forms, `move-result` variants, `new-instance`,
and `new-array` as conservative memory-effect intrinsics. Object moves/returns,
string/class constants, casts, instance tests, monitor operations, throws, and
`move-exception` are described in [Dalvik object-operation lifting](dex-object-lifting.md).
Packed and sparse
switches use a validated, method-relative data payload to populate a complete
case/default dispatch in the lifted CFG. Each lifted
instruction keeps its original method-relative address and analysis instruction
ID as provenance. Branch targets stay in their method-relative address space.

The common IR currently keys register operands with an 8-bit index, while DEX
register IDs are 16-bit. The lifter reports an explicit unsupported error when
an instruction in this subset references a register above v255. Wide values
use a 64-bit IR operand based at vN and occupy the Dalvik pair vN/vN+1; v255
cannot begin a pair, so wide instructions using v255 are rejected. Pair bounds
are checked against this IR key range. The function snapshot does not carry
the method's declared register count, so upper method-specific bounds cannot
be independently checked here. Wide shifts take a 32-bit count register and
mask it to six bits. Field reads/writes (`iget`/`iput` and `sget`/`sput`), array
loads/stores, and `array-length` lower to memory-effect intrinsics. The opcode's
wide/object/boolean/byte/char/short variant is retained, while field descriptors
and array element types remain unknown. `new-instance` and `new-array` produce
unknown references and an unknown memory effect.

The five invoke kinds and their `/range` forms lower to call-like intrinsics
that read every encoded argument register and conservatively invalidate memory.
`move-result`, `move-result-wide`, and `move-result-object` define an explicit
unknown value. This DEX subset does not yet resolve method/field identifiers to
names or descriptors, link invoke results to call signatures, model exceptions,
or distinguish static initialization and allocation effects. Unknown effects
are preserved instead of inventing signatures or values. Signed
division/remainder (whose exception behavior is not modeled), literals outside
the implemented constant forms, exception handlers, and all other unmodeled
opcodes still return `ErrorCode::unsupported` with the method-relative
instruction address. It does not produce a partial function when an instruction
has unknown effects.

Function and block boundaries come from the existing analysis snapshot. This
first slice does not independently verify Dalvik register typing, reconstruct
exception edges, prove verifier invariants, or structure arbitrary cyclic CFGs.
Packed and sparse switch payloads are bounded to 64 cases; sparse keys must be
strictly increasing, and every case target must resolve to a block in the
recovered method. The payload bytes participate in instruction dependencies,
so edits to a switch table invalidate its derived CFG. Malformed, unbacked, or
over-budget payloads preserve only the switch's default fallthrough and mark
analysis incomplete.
