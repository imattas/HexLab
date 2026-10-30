# WebAssembly floating-point sign operations

`evaluate_wasm_float_sign_operation` evaluates decoded `f32.abs`, `f32.neg`,
`f32.copysign`, and their `f64` forms using raw IEEE bit patterns. It clears,
toggles, or copies the sign bit directly, preserving every other bit,
including NaN payloads. For `f32`, the result is zero-extended to 64 bits.

The helper validates the one-byte, operand-free scalar instruction form. The
caller supplies stack operand bits (`rhs_bits` is used by `copysign`) and
performs stack updates. Arithmetic rounding, NaN canonicalization, and other
floating-point operations are outside this helper.
