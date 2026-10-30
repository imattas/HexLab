# WebAssembly floating-point comparisons

`evaluate_wasm_float_comparison` evaluates the decoded f32/f64 `eq`, `ne`,
`lt`, `gt`, `le`, and `ge` operations from raw IEEE-754 bit patterns. It
returns the WebAssembly boolean as an i32 `0` or `1`. Signed zero compares
equal; any NaN makes the ordered comparisons false and `ne` true.

The helper validates an operand-free decoded core instruction with fallthrough
flow and no memory effects. f32 inputs are truncated to 32 bits. It does not
raise host floating-point exceptions or handle stack state; the caller supplies
and commits the values.
