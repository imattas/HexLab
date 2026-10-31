# RISC-V vector integer reductions

`evaluate_riscv_vector_integer_operation` evaluates the RVV integer
reduction family `vredsum`, `vredand`, `vredor`, `vredxor`, `vredmin[u]`, and
`vredmax[u]` for supported SEW values from 8 through 64 bits. `vs1[0]` is the
initial scalar accumulator; active `vs2` lanes below `vl` are folded in
increasing lane order. Addition wraps to SEW, and signed min/max compare the
SEW-width two's-complement lane values. `vstart` must be zero, matching the
reduction restart restriction. With `vl=0`, the seed is returned unchanged.

Only destination lane zero is updated; other lanes preserve the caller's old
destination because this configuration does not carry tail-agnostic policy.
The evaluator supports caller-supplied predicate bytes for masked reductions,
uses caller-supplied lane spans, and does not model register-group state or
dispatch decoded instructions.

## Floating-point reductions

The decoder also recognizes the RVV 1.0 single-width floating reductions
`vfredusum.vs`, `vfredosum.vs`, `vfredmin.vs`, and `vfredmax.vs`. The floating
evaluator now evaluates both sum forms for binary32 and binary64 using raw-bit
addition, all five RISC-V rounding modes, signaling-NaN and invalid-operation
flags, overflow selection, inexact and tininess-after-rounding flags. It folds
active elements in increasing lane order from `vs1[0]`; `vfredusum` uses the
ordered implementation, which is a permitted implementation of the unordered
instruction. Masked-off lanes do not affect the result or flags. `vstart` must
be zero, and with no active lanes the seed is copied unchanged. Other lanes
preserve the caller's old destination because this configuration does not
carry tail-agnostic policy. Host floating arithmetic is not used.

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
Sections 14.3–14.4 and the OP-V instruction table](https://docs.riscv.org/reference/isa/extensions/vector/_attachments/riscv-v-spec.pdf).
