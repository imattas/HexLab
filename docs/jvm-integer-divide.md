# JVM integer divide and remainder evaluation

`evaluate_jvm_integer_divide_instruction` evaluates decoded `idiv`, `irem`,
`ldiv`, and `lrem` from raw 32- or 64-bit stack operand patterns. Signed
division truncates toward zero; remainder follows the dividend's sign. A zero
divisor is returned as an explicit `divide_by_zero` trap result. The JVM-defined
minimum-value divided by negative one case wraps to the minimum value, while
its remainder is zero; the helper avoids host signed-overflow behavior.

The adapter validates the operand-free bytecode shape and returns the result
width. It does not pop/push stack values, dispatch the exception edge, verify
method code, or execute the class; value sampling and state updates remain
caller-owned.
