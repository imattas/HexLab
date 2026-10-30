# AArch64 integer multiply-accumulate subset

The A64 decoder supports the W/X integer `MADD` and `MSUB` data-processing
three-source forms. It retains `Rd`, `Rn`, `Rm`, and `Ra` in operand order,
publishes register read/write effects, and rejects encodings outside the
recognized fixed-bit pattern. The operation width comes from `sf`: W forms
produce 32-bit values with the architecture's normal zeroing of the upper X
register bits, while X forms produce 64-bit values. The lifted W-form write
defines both the W result and an explicit zero-extended X result so later X
register reads see the architectural value in SSA.

Formatting uses the architectural aliases `MUL` for `MADD` with `Ra = WZR/XZR`
and `MNEG` for `MSUB` with that accumulator. Other forms remain `MADD` or
`MSUB`.

Decompilation lowers the operation to a width-typed expression:

    madd: Ra + (Rn * Rm)
    msub: Ra - (Rn * Rm)

Zero-register sources become typed zero constants, and writes to WZR/XZR are
discarded. These expressions use fixed-width integer types in the existing
typed SSA pipeline.

`evaluate_a64_multiply_accumulate_instruction` evaluates decoded W/X `MADD`
and `MSUB`. It follows decoder operand order (Rn, Rm, Ra), computes
`Rn * Rm + Ra` or `Ra - Rn * Rm`, and wraps at the operation width. W results
are returned zero-extended. WZR/XZR inputs contribute zero; writes to WZR/XZR
remain discarded by the architectural register model.

The helper validates the decoded GPR operands and effects but does not sample
register state or commit results. These instructions do not update NZCV;
timing and execution of surrounding instructions remain outside this helper.

This slice does not support signed or unsigned high-half multiply, long
multiply, division, conditional-select operations, or saturating arithmetic.
Successful decoding of this family does not imply broader AArch64 ISA support.
