# WebAssembly SIMD lane extract and replace semantics

`evaluate_wasm_simd_lane_instruction` handles the decoded `extract_lane` and
`replace_lane` forms for i8x16, i16x8, i32x4, i64x2, f32x4, and f64x2. It
validates the SIMD subopcode and decoded lane immediate, then reads or updates
the selected lane in the raw 16-byte vector. Lane bytes use WebAssembly's
little-endian ordering. Integer i8/i16 signed extracts sign-extend to an i32
bit pattern; unsigned extracts zero-extend. The other integer extracts return
their lane-width bit pattern. Floating extracts and replacements preserve raw
f32/f64 payload bits without host floating-point operations.

For a replacement, the caller supplies the scalar operand and the evaluator
copies its low 8, 16, 32, or 64 bits into the selected lane, preserving all
other vector bytes. For an extraction, the result marks a scalar result and
reports its 32- or 64-bit width. The helper operates on caller-supplied values;
it does not validate WebAssembly stack types, execute instructions, or model
SIMD arithmetic or memory access.
