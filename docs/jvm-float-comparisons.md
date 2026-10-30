# JVM floating-point comparison evaluation

`evaluate_jvm_float_compare_instruction` evaluates the operand-free JVM
`fcmpl`, `fcmpg`, `dcmpl`, and `dcmpg` bytecodes from raw binary32/binary64
encodings. It returns the JVM int result `-1`, `0`, or `1`; both signed zeros
compare equal, and NaN produces `-1` for the `*cmpl` forms or `1` for
`*cmpg`. The implementation compares IEEE sign, exponent, and fraction fields
directly without host floating-point operations.

The helper validates the decoded bytecode shape but does not pop/push JVM
stack values, perform verification, or execute class methods. Binary32 inputs
must have their upper 32 bits clear; value sampling and stack updates remain
caller-owned.
