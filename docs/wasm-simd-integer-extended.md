# WebAssembly SIMD extended integer transforms

`evaluate_wasm_simd_integer_extended_instruction` gives concrete results for
the 32 core integer SIMD transforms already recognized by the decoder and typed
lifter:

- Signed and unsigned saturating narrow from i16 to i8 and i32 to i16.
- Signed and unsigned pairwise extended addition from i8 to i16 and i16 to i32.
- Low/high signed and unsigned extension from i8 to i16, i16 to i32, and i32
  to i64.
- Low/high signed and unsigned extended multiplication for the same three
  source lane widths.

All vectors use explicit little-endian lane reads and writes. Narrowing
preserves operand order: lanes from the lower stack operand precede lanes from
the top operand. Both narrow forms interpret source lanes as signed values;
the `_s` form clamps to the signed destination range, while `_u` clamps to
zero through the unsigned maximum. Pairwise addition combines adjacent lanes
within its single input before extending the result. Low/high forms choose the
first or second half of source lanes, respectively. Signed and unsigned
extended multiplication extends each selected operand before multiplying;
the destination width holds the full product.

The evaluator requires a valid Wasm32 SIMD instruction, exact canonical
mnemonic and subopcode, no extra instruction bytes/operands or memory effects,
and exactly the expected operand count. Unsupported selectors and reserved
opcodes remain unevaluated. Lifting still preserves these operations as named
intrinsics; this helper does not execute or fold them inside symbolic SSA.

The base binary arithmetic and comparison helpers remain separate. Relaxed
SIMD is not included because several of its results are intentionally
implementation-defined.

Opcode mappings and lane behavior follow the official
[SIMD binary encoding](https://github.com/WebAssembly/simd/blob/main/proposals/simd/BinarySIMD.md)
and [SIMD operation semantics](https://github.com/WebAssembly/simd/blob/main/proposals/simd/SIMD.md).
