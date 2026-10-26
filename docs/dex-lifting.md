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

The lifter still rejects integer divide/remainder opcodes because their
divide-by-zero exception edges are not modeled. Floating constants are kept
as exact bit patterns until a typed use provides floating context. It also
lifts `iget`/`iput`, `sget`/`sput`, array loads/stores and `array-length`, the five
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

DEX 038+ `invoke-polymorphic` (including `/range`) and `invoke-custom` (including
`/range`) are decoded as calls. Polymorphic instructions retain both the method
and prototype indexes; custom instructions retain the call-site index. Their
encoded argument words are lifted as unknown 32-bit register reads, and the
call-like intrinsic invalidates memory. DEX 039+ `const-method-handle` and
`const-method-type` decode and lift as unknown reference constants while
preserving the method-handle or prototype index. The bytecode decoder does not
currently validate that the file version permits these opcodes, and the
analysis layer does not resolve call-site arrays, method handles, prototypes,
or descriptors. Register arguments therefore do not have recovered types or a
linked return value; `move-result` remains an independent unknown value. These
opcode encodings follow the [Android Dalvik bytecode reference](https://source.android.google.cn/docs/core/runtime/dalvik-bytecode?hl=en).

Function and block boundaries come from the existing analysis snapshot. This
first slice does not independently verify Dalvik register typing, reconstruct
exception edges, prove verifier invariants, or structure arbitrary cyclic CFGs.
Packed and sparse switch payloads are bounded to 64 cases; sparse keys must be
strictly increasing, and every case target must resolve to a block in the
recovered method. The payload bytes participate in instruction dependencies,
so edits to a switch table invalidate its derived CFG. Malformed, unbacked, or
over-budget payloads preserve only the switch's default fallthrough and mark
analysis incomplete.
