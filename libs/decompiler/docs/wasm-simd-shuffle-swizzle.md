# WebAssembly SIMD shuffle and swizzle lifting

The typed Wasm lifter accepts `i8x16.shuffle` and `i8x16.swizzle`.

`i8x16.shuffle` pops its two `v128` inputs in Wasm stack order and emits a
typed 128-bit binary expression. The operation name retains all sixteen
validated selectors in lane order (`0` through `31`), so each output byte's
source vector and source lane remain explicit in deterministic pseudocode.
Malformed selector counts or values fail closed.

`i8x16.swizzle` pops the index vector and source vector and emits a typed
`wasm_i8x16_swizzle(source, indices)` expression. The runtime rule, including
zeroing lanes whose unsigned selector is outside `0..15`, remains represented
by that named Wasm operation; it is not simplified as generic integer-vector
arithmetic.

Both operations preserve the validated instruction's stack effect: two
`v128` operands are replaced by one `v128` result. Other SIMD operators remain
subject to the lifter's existing support boundaries.
