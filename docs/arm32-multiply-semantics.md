# A32 multiply semantics

`evaluate_arm32_multiply_instruction` evaluates decoded `MUL`, `MLA`, and
`MLS` with 32-bit wraparound. MUL returns the low word of `Rm * Rs`; MLA adds
the accumulator modulo 2^32; MLS subtracts the product from the accumulator.
Record forms update N/Z from the result and preserve incoming C/V.

The adapter validates A32 register operands and decoded flag effects. The
caller supplies the source values and incoming NZCV, handles any ARM condition
predicate, and commits the result. Long multiply forms are not included.
