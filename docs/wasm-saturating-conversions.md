# WebAssembly scalar saturating conversions

`evaluate_wasm_saturating_float_to_integer` evaluates the decoded scalar
`i32.trunc_sat_f32_s`, `i32.trunc_sat_f32_u`, `i32.trunc_sat_f64_s`,
`i32.trunc_sat_f64_u`, and corresponding `i64` instructions. The input is a raw
IEEE-754 bit pattern, and the result contains the integer's raw bit pattern and
width, plus flags identifying NaN input and range saturation.

Finite values truncate toward zero. NaN produces zero. Positive overflow
clamps to the signed maximum or unsigned maximum; negative overflow clamps to
the signed minimum or unsigned zero. Infinities follow the same range clamps.
Negative fractions between -1 and zero convert to unsigned zero by truncation
without being marked saturated. Signed and unsigned output bits are returned
in the low 32 or 64 bits, respectively.

The evaluator accepts only fallthrough scalar conversion instructions with an
`0xfc` prefix and no explicit operands or memory effects. It does not model
floating-point exception state, SIMD conversions, non-saturating trapping
conversions, or execution of the surrounding operand stack.
