# AArch64 RBIT and REV evaluation

`evaluate_a64_bit_operation_instruction` evaluates decoded W/X `RBIT`,
`REV16`, `REV`, and X-only `REV32` from a caller-supplied GPR value. `RBIT`
reverses all bits; the REV forms reverse bytes within 16-bit, 32-bit, or
whole-register groups. W results are zero-extended, and WZR/XZR sources are
treated as zero.

The helper validates the decoded operand widths and register effects. It does
not sample or commit registers or model timing. Other bit-manipulation and
SIMD forms are outside this evaluator.
