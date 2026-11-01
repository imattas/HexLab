# WebAssembly SIMD signed dot product

The standard SIMD `i32x4.dot_i16x8_s` instruction is decoded, validated, and
lifted as a typed two-vector operation. Each result lane is the signed sum of
two adjacent signed 16-bit lane products. The result is four 32-bit lanes;
the pair sum wraps at 32 bits and no cross-pair accumulation occurs. This
matches the [WebAssembly Core Specification](https://www.w3.org/TR/wasm-core/).

The function-body validator requires two `v128` inputs and produces one
`v128`. The lifter records the exact signed `i32x4` result shape, which keeps
later typed stack joins from treating the result as an arbitrary vector. The
portable scalar evaluator computes the four lane-pair dot products using
explicit little-endian lane reads and writes, with a 64-bit intermediate for
the signed products before reducing the pair sum to 32 result bits.

This operation is distinct from the relaxed SIMD dot-product variants, whose
rounding or saturation behavior is not interchangeable with this instruction.
The decoded relaxed variants remain governed by their separate named
intrinsics.
