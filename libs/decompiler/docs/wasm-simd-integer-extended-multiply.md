# WebAssembly SIMD integer extended multiply

The typed Wasm lifter accepts all twelve decoded SIMD extended-multiply
operators:

- `i16x8.extmul_{low,high}_i8x16_{s,u}`
- `i32x4.extmul_{low,high}_i16x8_{s,u}`
- `i64x2.extmul_{low,high}_i32x4_{s,u}`

Each operation consumes two `v128` stack values in Wasm operand order and
produces one `v128`. The typed binary expression retains the exact decoded
operation name, preserving source lane half and signedness. The operation
remains a lane-aware Wasm intrinsic expression; it is not lowered into generic
128-bit multiplication, which would lose lane boundaries and extension rules.

Both the validation and emission passes require the decoder's exact opcode
mnemonic and an empty immediate-operand list. Unsupported or inconsistent
records fail closed. Other decoded SIMD forms not handled by the lifter remain
unsupported and use the existing structured fallback.
