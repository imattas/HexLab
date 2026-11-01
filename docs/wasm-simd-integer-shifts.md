# WebAssembly SIMD integer lane shifts

The standard integer SIMD shift family has twelve operators: left shift,
signed right shift, and unsigned right shift for i8x16, i16x8, i32x4, and
i64x2. The shared opcode metadata in `wasm_simd_shift.hpp` supplies each
operator's encoded subopcode, lane width, operation, decoded mnemonic, and
typed-lifter intrinsic name. The processor decoder and decompiler use this
metadata so their accepted operator sets stay aligned.

`evaluate_wasm_simd_integer_shift_instruction` in `wasm_semantics.hpp`
evaluates a raw 16-byte vector with a 32-bit shift count. WebAssembly masks
that count by lane width minus one. Left shifts wrap within each lane; unsigned
right shifts zero-fill; signed right shifts replicate the sign bit without
relying on implementation-defined signed host shifts. Lane loads and stores
use explicit little-endian byte assembly. The evaluator checks the decoded
instruction context, bounded subopcode encoding, exact mnemonic, and absence
of unrelated operands and memory effects before returning a result.

Typed lifting preserves the named shift intrinsic with an opaque v128 result,
consuming a v128 followed by an i32 count. It does not lower lane shifts to a
generic 128-bit shift, which would cross lane boundaries. Unsupported SIMD
operators continue to fail closed.
