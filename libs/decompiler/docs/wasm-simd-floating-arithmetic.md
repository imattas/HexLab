# WebAssembly SIMD floating arithmetic

The typed Wasm lifter supports the decoded `f32x4` and `f64x2` floating SIMD
unary and binary arithmetic operators. Each result remains a typed `v128`
expression with the exact Wasm operation name, keeping lane width and Wasm
floating-point behavior visible without treating the vector as one scalar.

Unary operators supported:

- `f32x4.ceil`, `floor`, `trunc`, `nearest`, `abs`, `neg`, `sqrt`
- `f64x2.ceil`, `floor`, `trunc`, `nearest`, `abs`, `neg`, `sqrt`

Binary operators supported:

- `f32x4` and `f64x2`: `add`, `sub`, `mul`, `div`, `min`, `max`, `pmin`, `pmax`

The validation and emission passes both require the decoder's exact opcode
mnemonic and no unexpected immediate operands. Unary operations consume one
`v128`; binary operations consume two `v128` values in Wasm stack order; both
produce one `v128`.

These operations are preserved as named typed expressions. The lifter does
not scalarize lanes or apply host floating-point constant folding, so NaN,
signed-zero, and pseudo-min/max details remain governed by the named Wasm
operation. Other decoded floating SIMD forms, including conversions and
relaxed operators, remain unsupported unless handled by a separate lifting
case.
