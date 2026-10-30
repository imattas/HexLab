# DEX integer unary semantics

`evaluate_dex_integer_unary` evaluates decoded `neg-int`, `not-int`,
`neg-long`, and `not-long` from a caller-supplied raw vreg value. Negation wraps
modulo 2^32 or 2^64; complement inverts every bit at the operation width. The
adapter validates the DEX typed-vreg operand widths and component-slot read
and write effects, including wide-pair bounds.

The helper returns the destination bit pattern and width. It does not read or
write the vreg file or update verifier/type state. Floating negation and other
DEX arithmetic forms are outside this helper.
