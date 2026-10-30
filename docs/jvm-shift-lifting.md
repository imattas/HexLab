# JVM shift instruction lifting

The JVM typed lifter supports `ishl`, `lshl`, `ishr`, `lshr`, `iushr`, and
`lushr`. Each instruction pops an `int` shift distance followed by its `int` or
`long` value and pushes a result of the value's type. Before constructing the
shift expression, lifting masks the distance with `31` for `int` operations or
`63` for `long` operations, matching the low five or six bits used by the JVM.

Arithmetic right shifts (`ishr` and `lshr`) retain signed operands; logical
right shifts (`iushr` and `lushr`) retain the distinct `ushr` operation so the
sign bit is shifted in as zero. The masking is explicit in common IR, so
downstream consumers do not need to infer JVM-specific shift-count rules.

`evaluate_jvm_shift_instruction` also evaluates a decoded shift from raw value
and distance bits. It applies the same five-/six-bit count mask, returns a
zero-extended 32-bit result for `i*` operations, and fills high bits from the
sign bit for arithmetic right shifts. The helper validates that the input is
one of the six operand-free JVM shift bytecodes. Stack pops and pushes and
runtime value sampling remain caller-owned.

The broader `evaluate_jvm_integer_arithmetic_instruction` helper also accepts
these six shift instructions. Supply the value as `lhs_bits` and the JVM int
distance as `rhs_bits`; `ishl`/`lshl` shift left, `ishr`/`lshr` replicate the
sign bit, and `iushr`/`lushr` shift in zeroes. The helper masks counts to five
bits for int values and six bits for long values, even when the supplied
distance has other high bits set. This same helper evaluates wrapping add,
subtract, multiply, negate, and/or/xor operations; all results are raw stack
bit patterns, with int results zero-extended to 64 bits.

This covers scalar bytecode shift semantics only. It does not add whole-method
bytecode verification or claim execution of class code.
