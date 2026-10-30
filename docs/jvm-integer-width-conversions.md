# JVM integer width conversions

`evaluate_jvm_integer_width_conversion_instruction` evaluates decoded `i2l`
and `l2i` instructions using raw JVM stack bits. `i2l` sign-extends the low
32-bit int to a 64-bit long. `l2i` discards the high 32 bits and returns the
remaining int bit pattern zero-extended in the helper's 64-bit result.

The helper validates the operand-free, one-byte JVM instruction form. It does
not pop or push the operand stack or update method state; stack sampling and
commit remain caller-owned. Floating-point conversions and verifier checks are
not included.
