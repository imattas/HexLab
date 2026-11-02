# WebAssembly SIMD integer unary operations

The decoder accepts the integer vector unary operators `abs`, `neg`, and
`all_true`/`bitmask` for i8x16, i16x8, i32x4, and i64x2, plus `popcnt` for
i8x16. Reserved selectors such as the unassigned i16x8/i32x4/i64x2 population
count encodings remain unsupported. These instructions have no immediate,
memory, or control-flow effect. The module validator and typed lifter consume
one v128 and preserve the exact operation as a named SIMD intrinsic; reductions
produce i32.

`evaluate_wasm_simd_integer_unary_instruction` evaluates a validated decoded
instruction from raw little-endian v128 bytes. `abs` and `neg` operate within
each lane and wrap at the lane width, so the most-negative signed value remains
its own bit pattern after absolute value. `popcnt` counts set bits per byte.
`all_true` returns 1 exactly when every lane is nonzero, otherwise 0. `bitmask`
packs each lane's most-significant bit into the corresponding low scalar bit.
The API reports either a vector result or an i32 result and does not mutate an
operand stack.

The evaluator checks Wasm32 context, SIMD prefix and bounded subopcode LEB,
canonical decoded mnemonic, no extra bytes or operands, and no memory effects.
It rejects all selectors outside this explicit family. This concrete helper
does not fold the symbolic lifted intrinsic.

Opcode assignment and behavior follow the official
[SIMD binary encoding](https://github.com/WebAssembly/simd/blob/main/proposals/simd/BinarySIMD.md)
and [SIMD operation semantics](https://github.com/WebAssembly/simd/blob/main/proposals/simd/SIMD.md).
