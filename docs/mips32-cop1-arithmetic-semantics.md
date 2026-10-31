# MIPS32 single-precision COP1 arithmetic semantics

`evaluate_mips32_arithmetic_s` evaluates finite binary32 `ADD.S`, `SUB.S`, and
`MUL.S` operands from their raw FPR bit patterns. It returns the rounded result,
FCSR Cause/Flag update, enabled-exception state, and whether the destination is
written. The rounding mode comes from FCSR.RM. When FCSR.FS is set, subnormal
inputs are flushed to signed zero and tiny outputs are flushed to zero, with
the corresponding Inexact and Underflow indications.

Addition and subtraction require the exact binary64 intermediate to retain
both operand significands. The bounded evaluator returns no result when the
top-bit exponents differ by more than 29. It also returns no result for NaN or
infinite operands; callers should preserve those operations as unsupported
effects rather than assume host floating-point propagation matches MIPS.
`evaluate_mips32_arithmetic_s_instruction` additionally checks the decoded
FPR/FCSR read and write facts before evaluating `ADD.S`, `SUB.S`, or `MUL.S`.

This does not model double-precision arithmetic, signaling NaN behavior,
floating-point traps beyond destination suppression, or exact COP1 exception
delivery. Other COP1 arithmetic continues to lift as typed intrinsics.
