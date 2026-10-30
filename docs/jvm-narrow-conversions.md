# JVM narrow integer conversions

`evaluate_jvm_narrow_conversion_instruction` evaluates decoded `i2b`, `i2c`,
and `i2s` from a 32-bit JVM int value. `i2b` and `i2s` truncate to 8 or 16
bits and sign-extend back to 32 bits; `i2c` truncates to 16 bits and zero-
extends. The result is returned as an exact 32-bit bit pattern.

The helper validates the operand-free one-byte bytecode form. It does not
change the operand stack, sample runtime values, or verify class methods.

The decompiler lifts the same three opcodes as typed 32-bit stack expressions:
`i2b` uses sign extension from bit 7, `i2c` uses zero extension from bit 15,
and `i2s` uses sign extension from bit 15. Each consumes one JVM int and
produces one JVM int. The class-file loader validates instruction boundaries
and the processor decodes the standard one-byte forms before lifting; method
verification and execution are not implied. Other numeric conversions retain
their existing lowering and are outside this change.
