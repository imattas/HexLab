# RISC-V decompiler lifting

The shared decompiler lifter accepts generic RV32 and RV64 instructions produced by the processor dispatcher. Register operands render as `x0` through `x31`; reads from `x0` become the integer constant zero, and writes to `x0` are discarded.

The currently lifted scalar subset includes LUI/AUIPC, ADDI/ADD/SUB, immediate and register bitwise operations, shifts, signed and unsigned set-less-than, RV64 word arithmetic, conditional integer branches, and integer loads/stores. Byte and halfword loads extend to XLEN according to their signed or unsigned opcode. RV64 word arithmetic truncates its inputs and result to 32 bits, then sign-extends the result to 64 bits. Shift amounts are masked to the architectural XLEN or word width.

RV32M and RV64M arithmetic is preserved as explicit pseudocode operations such as `mulhsu(x10, x11)` and `divuw(x10, x11)`. When SSA propagation makes both inputs constant, the decompiler calls the processor library's `evaluate_riscv_m_operation` implementation to fold the exact architectural result, including division-by-zero behavior and RV64 word sign extension.

F/D scalar instructions enter the shared pipeline with a distinct floating value type. FLW/FLD produce typed memory reads and FSW/FSD produce typed stores. Arithmetic, FMA, comparisons, classification, moves, and conversions retain named typed intrinsics; their decoded FPR/GPR outputs and `fflags` effects participate in SSA. Rounding mode remains available on the generic instruction for analysis and assembly formatting.

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
