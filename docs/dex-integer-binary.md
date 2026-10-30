# DEX integer binary arithmetic

`evaluate_dex_integer_binary` evaluates DEX `add`, `sub`, `mul`, `and`, `or`,
and `xor` for `int` and `long` forms, including `/2addr`. It validates the
decoded vreg operand widths and component-slot read/write effects. Results
wrap modulo 2^32 or 2^64, and the returned width distinguishes int from long.

`evaluate_dex_integer_divide` separately evaluates register-form `div-int`,
`rem-int`, `div-long`, and `rem-long`, including `/2addr`. Its result carries
the 32- or 64-bit result width and either a wrapped result or an explicit
`divide_by_zero` indication. Signed division truncates toward zero and the
remainder follows the dividend's sign. The minimum signed value divided by
negative one returns the minimum value; its remainder is zero. The helper
validates the encoded opcode/register fields, operand shape, vreg widths, and
exact component-slot read/write coverage. Literal division/remainder forms are unsupported.
The caller remains responsible for dispatching the arithmetic-exception edge,
sampling vregs, and committing the destination.

Neither helper covers shifts, literal arithmetic, floating arithmetic,
vreg sampling, or verifier/type-state updates. Callers provide source values
and commit the destination.
