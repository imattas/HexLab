# JVM array length

`evaluate_jvm_arraylength_instruction` evaluates a decoded `arraylength` from
caller-supplied reference nullness and array length. A null reference produces
an explicit `null_pointer_trap` result for the JVM `NullPointerException`
edge. A non-null array returns its nonnegative `int` length.

The adapter validates JVM context, opcode and mnemonic, one-byte operand-free
instruction shape, fallthrough flow, and absence of memory effects. It rejects
lengths above `INT32_MAX`, since a Java array length is a nonnegative `int`.
The caller owns reference/array sampling, operand-stack updates, and exception
dispatch; no array storage is read by this evaluator.
