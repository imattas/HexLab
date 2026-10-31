# RISC-V `FCVTMOD.W.D` semantic slice

`evaluate_riscv_fcvtmod_w_d` evaluates Zfa `FCVTMOD.W.D` from the raw
binary64 source bits. It truncates toward zero, takes the low 32 bits of the
unbounded two's-complement result, and sign-extends that word to the result
value. NaNs and infinities produce zero.

The helper computes NX and NV from the encoded exponent and significand, so it
does not depend on host floating-point rounding mode or invoke an out-of-range
floating-to-integer cast. The exception flags match `FCVT.W.D`; NV takes
precedence over NX for out-of-range results. The caller merges the returned
`fflags_set` bits into the architectural sticky flags. RV32 and RV64 are
accepted; other XLEN values return no result.

This models only this operation. It does not model F-register NaN boxing,
register state, other conversion opcodes, or sticky-flag updates. The typed
decompiler lift preserves the conversion as an explicit operation, and constant
propagation folds its value and `fflags` result through this same evaluator
when the source bits are known. Sticky flags remain an explicit OR with the
prior `fflags` value. The behavior
follows the [RISC-V Zfa specification, §25.1.4](https://docs.riscv.org/reference/isa/unpriv/zfa.html).
