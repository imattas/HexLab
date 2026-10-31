# RVV reciprocal estimate semantics

The processor floating-vector evaluator implements the `vfrec7.v` and
`vfrsqrt7.v` common-case lookup tables for SEW=32 and SEW=64. The 128-entry
tables are transcribed from the [RISC-V Vector Specification table sources](https://github.com/riscvarchive/riscv-v-spec/blob/master/vfrec7.adoc)
and [`vfrsqrt7.adoc`](https://github.com/riscvarchive/riscv-v-spec/blob/master/vfrsqrt7.adoc).
Inputs are raw IEEE element bits; subnormal inputs are normalized with integer
bit operations. Exceptional values and active-lane `fflags` follow RVV §§13.9–13.10.

Callers evaluating `vfrec7.v` must provide the current valid `frm` (0 through
4) in `RiscvVectorFloatingOperands::frm`, because overflow results depend on
rounding mode. `vfrsqrt7.v` is independent of rounding mode. Masked, pre-start,
and tail lanes retain their supplied old-destination values.
