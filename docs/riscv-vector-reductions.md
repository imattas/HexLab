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
