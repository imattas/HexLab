# WebAssembly integer bitwise operations

`evaluate_wasm_integer_bitwise` evaluates i32/i64 `and`, `or`, `xor`, `shl`,
`shr_s`, `shr_u`, `rotl`, and `rotr` from raw operand-stack bit patterns.
Results are masked to their declared width. Shift and rotate counts use the
low five bits for i32 and low six bits for i64, as required by WebAssembly.
Signed right shift uses explicit sign fill without relying on the host's
behavior for right-shifting negative signed values.

The helper accepts only operand-free decoded core instructions with
fallthrough flow and no memory effects. The caller supplies both stack values
and commits the result. It does not handle comparisons, conversions, or stack
state.
