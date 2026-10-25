# AArch64 bitfield decode and lifting

The A64 scalar decoder now recognizes `UBFM` and `SBFM` in W and X forms. It records the destination, source, `immr`, and `imms`, plus register read/write effects, and rejects out-of-range bounds. `BFM` remains unsupported and returns no decoded semantics.

Formatting recognizes the common aliases `LSL`, `LSR`, `ASR`, `UBFX`, and `SBFX`. Other bounds retain the architectural `UBFM` or `SBFM` mnemonic. The alias is presentation only; the decoded opcode and immediate operands preserve the underlying instruction.

The decompiler lowers both operations to width-typed bitvector expressions: rotate right by `immr`, mask through `imms`, and for `SBFM`, sign extend the selected top bit through an arithmetic shift. This covers wrapped bitfields, zero-register inputs, and destination writes; writes to XZR are discarded by the existing register model. The expression remains composed of shifts, OR, AND, and arithmetic right shift so it can pass through existing SSA and pseudocode formatting.

This is a focused scalar subset. It does not cover `BFM` and its `BFC`/`BFXIL` aliases, scalar SIMD/FP, or AArch64 system instructions. Decoder coverage remains partial and does not imply broad ISA equivalence.
