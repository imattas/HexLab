# WebAssembly SIMD logical semantics

`evaluate_wasm_simd_logical_instruction` evaluates the decoded SIMD bitwise family `v128.not`, `v128.and`, `v128.andnot`, `v128.or`, `v128.xor`, `v128.bitselect`, and `v128.any_true`.

Vectors are raw 16-byte values in decoder byte order. The logical operations apply independently to each byte, preserving all 128 bits without lane reinterpretation. `andnot` computes `lhs & ~rhs`; `bitselect` selects each bit from `lhs` when the corresponding selector bit is set and from `rhs` otherwise. `any_true` returns scalar 1 if any input bit is set and 0 otherwise. Callers provide operands from the WebAssembly stack and commit the returned vector or scalar themselves.

The evaluator accepts only the corresponding two-byte decoded `0xfd` SIMD instruction shape with no explicit operands or memory effects. Other SIMD operations, SIMD memory access, and stack updates are not modeled here.
