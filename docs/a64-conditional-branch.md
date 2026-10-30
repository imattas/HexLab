# AArch64 conditional branches

`evaluate_a64_conditional_branch_instruction` evaluates decoded `B.cond` from
caller-supplied NZCV flags. It implements EQ/NE, CS/CC, MI/PL, VS/VC, HI/LS,
GE/LT, and GT/LE conditions using the architectural flag relationships.

The adapter validates A64 mode, conditional flow, condition code, relative
target, operand access, and the decoded NZCV read effect. Encoded AL/NV forms
are decoded as unconditional flow and are not accepted here. The result is
only the taken predicate; branch transfer and state updates remain
caller-owned.
