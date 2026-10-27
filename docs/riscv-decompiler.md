# RISC-V decompiler lifting

The shared decompiler lifter accepts generic RV32 and RV64 instructions produced by the processor dispatcher. Register operands render as `x0` through `x31`; reads from `x0` become the integer constant zero, and writes to `x0` are discarded.

The currently lifted scalar subset includes LUI/AUIPC, ADDI/ADD/SUB, immediate and register bitwise operations, shifts, signed and unsigned set-less-than, RV64 word arithmetic, conditional integer branches, and integer loads/stores. Byte and halfword loads extend to XLEN according to their signed or unsigned opcode. RV64 word arithmetic truncates its inputs and result to 32 bits, then sign-extends the result to 64 bits. Shift amounts are masked to the architectural XLEN or word width.

RV32M and RV64M arithmetic is preserved as explicit pseudocode operations such as `mulhsu(x10, x11)` and `divuw(x10, x11)`. When SSA propagation makes both inputs constant, the decompiler calls the processor library's `evaluate_riscv_m_operation` implementation to fold the exact architectural result, including division-by-zero behavior and RV64 word sign extension.

F/D scalar instructions enter the shared pipeline with a distinct floating value type. FLW/FLD produce typed memory reads and FSW/FSD produce typed stores. Arithmetic, FMA, comparisons, classification, moves, and conversions retain named typed intrinsics; their decoded FPR/GPR outputs and `fflags` effects participate in SSA. Rounding mode remains available on the generic instruction for analysis and assembly formatting.

Scalar FCVT conversions additionally carry explicit parallel output formulas.
W/WU and L/LU inputs retain signedness and 32/64-bit width; an RV64 W/WU
integer source is truncated to its low word. Float-to-W/WU results are explicitly
sign-extended to XLEN, including the unsigned WU variants. FCLASS.S/D produce
a ten-bit class mask zero-extended to XLEN and do not touch FCSR. Integer output
types are recovered independently of the floating result and status outputs.

Each rounding-sensitive FCVT formula consumes either its encoded static
rounding mode or the pre-instruction three-bit `frm` value for `rm=111`.
FCVT.D.S and exact FCVT.D.W/WU still validate and retain the encoded `rm`
field, but have no semantic `frm` dependency or rounding operand. Reserved
static modes 101/110 and RV32 L/LU forms remain invalid. The dynamic mode is
not evaluated or assumed to contain a legal value.

Conversions that may raise exceptions read the old five-bit `fflags` and write
`old_fflags | raised_flags` in parallel with their value result. Raised flags
remain symbolic and are bounded to NV/NX for float-to-integer, NX for rounded
integer-to-float, NV/OF/UF/NX for FCVT.S.D, and NV for FCVT.D.S. FCVT.D.W/WU
are exact and preserve `fflags` without a status write. A destination of x0
discards only the integer result; possible status effects remain. The intrinsic
retains architectural clipping and NaN semantics without evaluating host C++
casts or inventing a floating exception trap.

The Zfa `FCVTMOD.W.D` conversion is decoded only for its fixed-RTZ encoding
(`rs2=8`, `rm=RTZ`) and lifted as a typed opaque conversion. Its 32-bit signed
modular result is sign-extended to XLEN, while its NV/NX effects accumulate
into `fflags` like `FCVT.W.D`. The intrinsic keeps modulo-2^32 behavior visible
to downstream analysis, including the specified zero result for NaN and
infinity; it remains opaque and the lifter does not calculate conversion
values or flags.
Zfa `FROUND.S/D` and `FROUNDNX.S/D` use the FCVT.S.D/FCVT.D.S encoding
families with `rs2=4/5`, respectively. They preserve the S/D source and
destination types, validate and retain `rm`, and use `frm` only for `rm=111`.
The typed intrinsics preserve round-to-integral behavior; symbolic accrued
flags are bounded to NV for FROUND and NV/NX for FROUNDNX. Exact values,
signaling-NaN detection, and whether an input changes after rounding remain
unevaluated.

Zfa `FLI.S` and `FLI.D` decode the complete five-bit immediate selector table
from the FMV encoding with `rs2=1`. The selector is retained as an immediate,
not a fictitious GPR dependency. Lifting maps each selector to its exact IEEE
binary32 or binary64 bit pattern, including the format-specific minimum normal,
positive infinity, and canonical quiet NaN. FLI writes only its FPR destination
and does not read or update `frm` or `fflags`. FLI.H/Q and the remaining Zfa
rounding/minimum families remain unsupported.

Encodings and effects follow the official
[F extension](https://docs.riscv.org/reference/isa/v20260120/unpriv/f-st-ext.html),
[D extension](https://docs.riscv.org/reference/isa/v20260120/unpriv/d-st-ext.html),
[Zfa extension](https://docs.riscv.org/reference/isa/v20260120/unpriv/zfa.html),
and [RV32/64G listings](https://docs.riscv.org/reference/isa/v20260120/unpriv/rv-32-64g.html).
All forms use OP-FP `0x53`. FCVT integer destinations use funct7 `0x60/0x61`
(S/D source), integer sources use `0x68/0x69` (S/D destination), and rs2
`0/1/2/3` selects W/WU/L/LU. FCVT.S.D uses funct7 `0x20`, rs2=1;
FCVT.D.S uses `0x21`, rs2=0. FCLASS.S/D use funct7 `0x70/0x71`, rs2=0,
funct3=1. W/WU and S/D precision conversions work at either XLEN; L/LU
forms require RV64. Zfa `FCVTMOD.W.D` is also accepted on RV32/RV64 when D
is available; its encoding uses funct7 `0x61`, rs2=8, and the sole legal rm
value RTZ (1).

Floating-result intrinsics carry an explicit 32- or 64-bit result type into type recovery. Only FPR destinations receive that floating fact; integer results and `fflags` remain separate effects.

The decoded RVV integer elementwise families share one explicit opcode-to-effect
route covering 90 forms:

| Family | Retained forms |
| --- | --- |
| Add/subtract | `vadd.vv/vx/vi`, `vsub.vv/vx`, `vrsub.vx/vi` |
| Bitwise | `vand`, `vor`, `vxor` in `.vv/.vx/.vi` |
| Shifts | `vsll`, `vsrl`, `vsra` in `.vv/.vx/.vi` |
| Min/max | `vminu`, `vmin`, `vmaxu`, `vmax` in `.vv/.vx` |
| Multiply | `vmul`, `vmulh`, `vmulhu`, `vmulhsu` in `.vv/.vx` |
| Multiply-accumulate | `vmacc`, `vnmsac`, `vmadd`, `vnmsub` in `.vv/.vx` |
| Widening multiply-accumulate | `vwmaccu`, `vwmacc`, `vwmaccsu` in `.vv/.vx`; `vwmaccus.vx` |
| Widening multiply | `vwmulu`, `vwmulsu`, `vwmul` in `.vv/.vx` |
| Divide/remainder | `vdivu`, `vdiv`, `vremu`, `vrem` in `.vv/.vx` |
| Comparisons | `vmseq/vmsne` in `.vv/.vx/.vi`; `vmsltu/vmslt` in `.vv/.vx`; `vmsleu/vmsle` in `.vv/.vx/.vi`; `vmsgtu/vmsgt` in `.vx/.vi` |

These remain named, memory-free intrinsics with the decoder's source order and
complete register-write list. Vector results carry an opaque vector `ValueType`
with unknown total width and lane shape. Comparison results instead identify
boolean mask bits (`element_kind=boolean`, `element_bits=1`) while total width
and lane count remain unknown. A predicate mask is not a scalar boolean and is
not assigned a fixed-size mask layout.

Masked operations explicitly read the predicate value of `v0`. Decoded
`vl`/`vtype`/`vstart` dependencies remain scalar inputs, and the decoded `vstart`
write remains a separate scalar effect. The old vector destination is retained
for prestart, masked-off and undisturbed tail lanes. Predicate and old-destination
roles remain separate even when `v0` is also an explicit data source or the
destination; repeated configuration-read records are collapsed. All inputs are
pre-instruction SSA reads and all decoded outputs receive their own SSA versions.
Vector result typing applies only to vector-register outputs, so `vstart` cannot
accidentally acquire the data or predicate destination's vector type.

The single-width multiply-accumulate/subtract forms retain the pre-instruction
destination as an explicit vector input because their destination is destructive.
The widening multiply-accumulate forms retain the same dependency and carry
distinct opcode names. Their result remains an opaque vector here: the generic
instruction does not carry the active SEW or LMUL needed to prove a concrete
2*SEW lane shape or a legal destination register group.
The non-accumulating widening multiply forms keep their signedness in distinct
intrinsics and do not read the old destination as a multiply input. Destination
preservation is still represented for masked or undisturbed lanes.
The names distinguish accumulation into the old destination (`vmacc`,
`vnmsac`) from multiplication using the old destination (`vmadd`, `vnmsub`).
The lifter preserves their architectural input dependencies without lowering
them to scalar arithmetic or assuming a runtime SEW.

No lane evaluation is performed by the lifter. The mnemonic retains signedness,
high-half multiply variants, reverse-subtract operand semantics, and unsigned
shift-immediate forms without converting them into scalar arithmetic. Runtime
SEW, LMUL, VLEN, active length, register grouping, policy choices and vector
divide edge cases remain opaque here. Unsupported/reserved operand forms are
not added. Existing processor opcode IDs remain stable; the widening forms
append IDs without changing project serialization formats.

This is effect-preserving lifting rather than an IEEE-754 evaluator: it does not calculate floating results, choose dynamic `frm`, or derive precise exception flags. The physical FPR bank is 64 bits wide, with S values typed at 32 bits; RV64F NaN-boxing is not modeled. Atomic and privileged instruction decompilation remain outside this slice. Compressed integer instructions use the same lifter only when the decoder normalizes them to one of the listed scalar opcodes.

The processor semantics API separately evaluates bit-exact vector floating classification, sign-injection, min/max, and comparison families for SEW 32/64. Classification returns the ten IEEE-754 classes as a SEW-wide bit field; the other evaluable operations accept already-unboxed scalar FPR element bits, apply active-lane and old-destination rules, and report accrued exception bits. Single-width fused multiply-add/subtract VV/VF forms are represented by named floating-vector intrinsics that preserve `frm`, `fflags`, masked `v0`, and old `vd` dependencies; lane evaluation remains unsupported because the helper has no rounding-mode input and does not compute exact fused exception flags. Unary `vfsqrt.v`, `vfrsqrt7.v`, and `vfrec7.v` are lifted as typed vector intrinsics: square root carries `frm`/`fflags`, reciprocal-square-root estimate carries `fflags`, and reciprocal estimate carries `frm`/`fflags` for its rounding-dependent overflow behavior. Exact square-root and estimate lane values are not calculated. The generic lifter remains an opaque effect record because dynamic SEW, VLEN, and mask/tail policies are not carried into typed lane expressions.

The RVV gather/slide subset (`vrgather.vv/vx/vi`, `vslideup.vx/vi`, and
`vslidedown.vx/vi`) is represented as named intrinsics with explicit source
operands, destination writes, masked `v0` reads, and implicit vector
configuration dependencies. The lift intentionally leaves lane selection and
runtime group constraints opaque because `VLEN`, `LMUL`, `SEW`, and `vl` are
not statically carried by the instruction IR.

RVV `vsetvli`, `vsetivli`, and `vsetvl` configuration forms are also named
intrinsics. Their AVL/vtype operands, implicit configuration reads, and
`vl`/`vtype`/`vstart` writes are preserved. Vector result operations include
the prior destination register as an input so masked-off, prestart, slide-up,
and undisturbed tail lanes remain represented as dependencies. The lifter
does not statically evaluate vtype, determine implementation VLEN, or model
the `vta`/`vma` agnostic choice.

The scalar Zba forms `sh1add`, `sh2add`, `sh3add`, `add.uw`, their supported
`.uw` shift-and-add variants, and `slli.uw` lift to typed shift, zero-extension,
and addition expressions. The shift amount and 32-bit truncation are explicit;
the lifter does not treat an unknown register index as a constant address.

Focused validation is provided by `decompiler_riscv_lifting`; it exercises RV64 scalar and M operations, x0 semantics, signed and unsigned byte loads, branch predicates, SSA versions, constant M folding, signed RV64 word results, and typed F/D effects.
