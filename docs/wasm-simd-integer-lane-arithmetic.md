# WebAssembly SIMD integer lane arithmetic

The decoder, module validator, and typed function lifter share an explicit
34-opcode table for integer SIMD binary arithmetic:

- Wrapping add and subtract for i8x16, i16x8, i32x4, and i64x2.
- Signed and unsigned saturating add and subtract for i8x16 and i16x8.
- Wrapping multiplication for i16x8, i32x4, and i64x2.
- Signed and unsigned minimum and maximum for i8x16, i16x8, and i32x4.
- Unsigned rounded average for i8x16 and i16x8.
- Signed saturating rounded Q15 multiplication, `i16x8.q15mulr_sat_s` (`0xfd 0x82 0x01`).

These instructions have no binary immediates, memory effects, explicit register
operands, or control-flow effects. The formatter emits their canonical mnemonic.
Each consumes two v128 stack values, with the right operand on top, and produces
one v128 value. Module validation and both typed lifting passes enforce that
signature. Lifting retains the exact Wasm mnemonic in a binary expression with
an opaque v128 result: using generic 128-bit arithmetic would incorrectly permit
carries between lanes. Other unsupported SIMD instructions still cause module
validation to report unsupported; this does not enable every SIMD module.

`evaluate_wasm_simd_integer_binary_instruction` in `wasm_semantics.hpp` provides
concrete, deterministic evaluation for the same family. It accepts raw 16-byte
vectors, splits them into little-endian lanes, and returns the raw result without
mutating the caller's operand stack. Unsigned arithmetic implements modulo
wrapping without host signed overflow. Saturation clamps to the signed or unsigned
lane bounds. Rounded average computes `(a + b + 1) / 2`; Q15 multiplication computes
the saturating arithmetic shift of `a * b + 16384` by 15, including the
`-32768 * -32768` result of 32767. The helper validates instruction context,
bounded u32 subopcode LEB encoding, exact mnemonic, absence of extra bytes or
operands, and absence of memory effects. Valid padded LEB encodings are accepted.

The helper is an explicit processor semantics API. The symbolic evaluator does
not automatically execute or fold these named vector expressions. Narrowing,
widening, dot products, pairwise operations, and relaxed SIMD remain outside this
arithmetic slice.

Opcode assignments and arithmetic behavior follow the official
[SIMD binary encoding](https://github.com/WebAssembly/simd/blob/main/proposals/simd/BinarySIMD.md)
and [SIMD operation semantics](https://github.com/WebAssembly/simd/blob/main/proposals/simd/SIMD.md).
