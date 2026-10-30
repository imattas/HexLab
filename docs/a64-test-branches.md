# AArch64 zero and bit-test branches

`evaluate_a64_test_branch_instruction` evaluates decoded `CBZ`, `CBNZ`,
`TBZ`, and `TBNZ` predicates from a caller-supplied register value. It respects
the decoded W/X width; W-source values are truncated to 32 bits. `TBZ` and
`TBNZ` use the checked immediate bit index, and register 31 is treated as the
architectural zero register.

The adapter validates A64 mode, conditional-flow metadata, direct relative
target, operand/access shape, test-bit range, and GPR read effects. It returns
only the taken predicate; branch transfer and state updates remain the
caller's responsibility.
