# RISC-V vector integer reductions

`evaluate_riscv_vector_integer_operation` evaluates the unmasked RVV integer
reduction family `vredsum`, `vredand`, `vredor`, `vredxor`, `vredmin[u]`, and
`vredmax[u]` for supported SEW values from 8 through 64 bits. `vs1[0]` is the
initial scalar accumulator; active `vs2` lanes below `vl` are folded in
increasing lane order. Addition wraps to SEW, and signed min/max compare the
SEW-width two's-complement lane values. `vstart` must be zero, matching the
reduction restart restriction. With `vl=0`, the seed is returned unchanged.

Only destination lane zero is updated; other lanes preserve the caller's old
destination because this configuration does not carry tail-agnostic policy.
The evaluator rejects masked configurations, uses caller-supplied lane spans,
and does not model register-group state or dispatch decoded instructions.

## Floating-point reductions

The decoder also recognizes the RVV 1.0 single-width floating reductions
`vfredusum.vs`, `vfredosum.vs`, `vfredmin.vs`, and `vfredmax.vs`. They retain
the three vector operands, optional `v0` mask, `vl`/`vtype`/`vstart` state,
and the `frm` and sticky `fflags` dependencies required by floating-point
arithmetic. The bounded floating evaluator currently evaluates only the
minimum and maximum reductions. It does not evaluate either sum form: exact
ordered sums require scalar rounding at every addition, while unordered sums
allow a deterministic reduction tree with per-node rounding. A host floating
operation cannot stand in for those architectural rules or exception flags.

The widening forms `vfwredusum.vs` and `vfwredosum.vs` are decoded and formatted
as well. Their vector operands and floating control dependencies are retained,
and they lower to named typed intrinsics. They widen SEW elements to a double-
width accumulator, but are not concretely evaluated. The supported static
decoder does not carry the live SEW setting, so it cannot validate the
runtime-required FP32-to-FP64 configuration; wider FP formats and half
precision remain unsupported.

The opcode assignments follow the RVV OPFVV encoding table: funct6 `110001`
for `vfwredusum` and `110011` for `vfwredosum`. Reduction instructions require
`vstart=0`; automatic analysis records the `vstart` dependency, while runtime
validation remains with the caller. See the [RISC-V Vector specification,
Sections 14.3–14.4 and the OP-V instruction table](https://github.com/riscvarchive/riscv-v-spec/blob/master/v-spec.adoc).
