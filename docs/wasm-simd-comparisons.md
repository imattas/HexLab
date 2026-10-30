# WebAssembly SIMD comparisons

`evaluate_wasm_simd_comparison_instruction` in
`hexlab/processors/wasm_simd_comparison.hpp` evaluates decoded standard SIMD
comparisons over raw little-endian `v128` bytes. It covers signed and unsigned
i8x16, i16x8, and i32x4 predicates; signed i64x2 predicates; and all six
f32x4/f64x2 comparison predicates.

Each true lane becomes all one bits at that lane width, and each false lane
becomes zero, matching the WebAssembly mask representation. Integer signedness
is explicit and does not depend on host byte order or signed overflow. Floating
comparisons follow IEEE value comparisons: equality and ordering are false for
NaN, while `ne` is true. The evaluator validates instruction context, opcode
bytes, decoded mnemonic, and absence of unrelated operands or memory effects
before producing a result.

The helper is a concrete semantics API. It does not execute an entire Wasm
module or change the decompiler's symbolic stack behavior; lifting preserves the
exact comparison mnemonic as a typed vector operation.
