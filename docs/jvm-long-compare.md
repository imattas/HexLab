# JVM long comparison

`evaluate_jvm_long_compare_instruction` evaluates a decoded `lcmp` from the
two raw 64-bit long stack values. It interprets each value as a signed Java
`long` and returns exactly `-1`, `0`, or `1` according to their ordering.

The adapter validates JVM context, the `lcmp` mnemonic/opcode, operand-free
one-byte instruction shape, fallthrough flow, and absence of memory effects.
It does not update the operand stack or perform a following branch; callers
own stack sampling and state changes.
