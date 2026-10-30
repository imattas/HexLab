# WebAssembly integer comparisons

`evaluate_wasm_integer_comparison` evaluates i32/i64 `eqz`, equality and
inequality, and signed/unsigned less-than, greater-than, less-or-equal, and
greater-or-equal operations. It returns the WebAssembly boolean as an i32 value
(`0` or `1`). Inputs are truncated to the comparison width before evaluation.

The helper accepts operand-free decoded core instructions with fallthrough
flow and no memory effects. Signed comparisons interpret the width-limited
bits as two's-complement i32/i64 values. The caller supplies stack values and
handles stack updates; floating comparisons and branch transfer are outside
this helper.
