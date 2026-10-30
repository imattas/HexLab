# WebAssembly SIMD instruction decoding

The processor decoder recognizes SIMD prefix `0xfd` and decodes the MVP
`i8x16.shuffle`, `i8x16.swizzle`, scalar splats, and all lane extract/replace
instructions for i8, i16, i32, i64, f32, and f64 vectors. Shuffle retains its
16 lane selectors as byte immediates and rejects any selector outside the two
input vectors (0 through 31). Scalar lane operations retain one lane immediate
and reject lane numbers outside the selected vector width. Splat and swizzle
have no encoded immediate.

The decoder also recognizes a broad integer SIMD arithmetic family: lane shifts;
minimum/maximum, unsigned rounded average and multiplication; signed/unsigned
narrowing and widening; pairwise extension-add; signed/unsigned extended
multiply; i32-by-i16 dot product; and i64 lane comparisons. These opcodes use
an explicit table, so unassigned SIMD subopcodes remain unsupported. Arithmetic
operations have no immediates; malformed/truncated subopcode LEBs still fail
through the common strict decoder.

Typed function lifting covers the decoded SIMD comparisons at subopcodes
`0x23..0x4c` and `0xd6..0xdb`. Each consumes two `v128` operands and produces a
`v128` lane mask. The exact decoded mnemonic is retained in the typed
expression, preserving lane width, comparison kind, and signedness. The
standalone semantics helper in `wasm_simd_comparison.hpp` evaluates integer and
floating-point lanes to all-one/zero masks; it does not scalarize a vector mask.

Floating-point SIMD decoding covers the existing f32x4/f64x2 comparisons and
binary arithmetic, plus unary ceil/floor/trunc/nearest/abs/neg/sqrt operations
and the MVP numeric conversion family: demote/promote, signed/unsigned i32
conversion, and saturating float-to-i32 conversion with zeroing variants. These
forms carry no immediates. Reserved gaps remain unsupported, and conversion
semantics are represented by their exact mnemonic rather than executed here.

The finalized Relaxed SIMD opcode range `0x100` through `0x113` is also decoded
by exact opcode: relaxed swizzle, relaxed float-to-integer truncations, fused
multiply-add and negative multiply-add, lane-select, min/max, Q15 rounded
multiply, and the two relaxed dot-product forms. The reserved range after
`0x113` remains unsupported. These instructions have no extra binary
immediates. Their names identify operations whose results may be
implementation-defined under the proposal; decoding does not claim a specific
runtime result, and the typed lifter does not yet execute these operations.

This also corrects lane-opcode numbering: SIMD subopcodes are unsigned LEB128
values, and the lane operations occupy `0x15` through `0x22`; the preceding
`0x0f` through `0x14` opcodes are splats. Truncated immediates fail as truncated
instructions, invalid lane values fail as invalid instructions, and valid
instructions remain subject to the decoder's 32-byte maximum instruction
length.

The implementation follows the official
[WebAssembly SIMD binary encoding](https://github.com/WebAssembly/simd/blob/main/proposals/simd/BinarySIMD.md).
Relaxed operation names and finalized opcodes follow the official
[WebAssembly Relaxed SIMD proposal](https://github.com/WebAssembly/relaxed-simd/blob/main/proposals/relaxed-simd/Overview.md).
Other SIMD operations remain unsupported unless explicitly listed in the
decoder's implementation.

## Vector bitwise operations in typed lifting

The Wasm typed lifter handles `v128.not`, `v128.and`, `v128.andnot`,
`v128.or`, `v128.xor`, `v128.bitselect`, and `v128.any_true`. The bitwise
forms operate on the complete 128-bit vector value and preserve the Wasm
operand order. `v128.andnot` is expressed as `left & ~right`; `v128.bitselect`
uses its third stack operand as a per-bit mask, selecting the first vector's
bit when the mask bit is one and the second vector's bit otherwise. Their
results have typed `v128` values. `v128.any_true` produces a typed `i32`
predicate indicating whether any input bit is nonzero.

Stack-shape validation and expression lifting cover the same seven opcodes.
These helpers do not add execution to the symbolic evaluator. Integer lane
binary arithmetic and vector comparisons have concrete semantics helpers; see
[integer lane arithmetic](wasm-simd-integer-lane-arithmetic.md) and
[SIMD comparisons](wasm-simd-comparisons.md). Other SIMD arithmetic operations
still require their own typed lifting.
