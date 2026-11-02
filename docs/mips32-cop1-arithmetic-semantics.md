# MIPS32 COP1 arithmetic semantics

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

`evaluate_mips32_arithmetic_d` covers binary64 `ADD.D`, `SUB.D`, `MUL.D`,
`DIV.D`, and `SQRT.D`, including NaNs and infinities. Square root computes an integer radicand and
remainder, then rounds without host floating point; negative finite input
returns the canonical quiet NaN and raises Invalid, while signed zero is
preserved. Addition/subtraction preserve their exact aligned significands;
multiplication retains the full 106-bit product; division generates a rounded
53-bit quotient while carrying the exact remainder through normal and
subnormal rounding. Square root uses the same four FCSR.RM modes and marks
Inexact when its exact root is not representable. All four FCSR.RM modes,
gradual underflow, overflow results,
and Inexact/Underflow/Overflow Cause and Flag bits are modeled. Division by
zero raises Divide-by-Zero for a nonzero numerator; zero divided by zero
produces the canonical quiet NaN and raises Invalid. Finite zero numerators
preserve the operation's sign. If FCSR.FS is set, subnormal inputs are replaced
by signed zero. Tiny nonzero results are detected before rounding, flushed to
signed zero, and raise Underflow plus Inexact, including values that otherwise
round to the minimum normal value. This follows the MIPS32 Release 6.01 FS
behavior; the decoder does not select an ISA revision. Enabled exceptions
update Cause and suppress the destination write; unenabled exceptions accrue
sticky Flags.

NaN results are canonical quiet NaNs; signaling NaN inputs raise Invalid.
Infinity addition/subtraction, multiplication, and division follow the IEEE
invalid cases (`+Inf + -Inf`, `Inf * 0`, `Inf / Inf`, and `0 / 0`) and preserve
the operation sign where the result is infinite or zero. Positive infinity
square-roots to itself; negative infinity raises Invalid.

`evaluate_mips32_arithmetic_d_instruction` also validates the MIPS32 context,
exact register/FCSR effects, and even-numbered FPR pairs for every D-format
source and destination, including unary `SQRT.D`. The decompiler applies the same even-pair restriction to D-format
loads/stores, moves, comparisons, arithmetic, and conversions. This bounded
model assumes the paired 32-bit FPR view; it does not infer runtime Status.FR.

Exact COP1 exception delivery and the runtime FR=1 register view remain
unsupported. Those instructions retain typed but unknown effects in
decompilation.
