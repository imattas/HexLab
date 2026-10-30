# AArch64 bitfield decode and lifting

The A64 scalar decoder recognizes `UBFM`, `SBFM`, and `BFM` in W and X forms. It records the destination, source, `immr`, and `imms`, plus register read/write effects, and rejects out-of-range bounds.

Formatting recognizes the common aliases `LSL`, `LSR`, `ASR`, `UBFX`, and `SBFX`. Other bounds retain the architectural `UBFM` or `SBFM` mnemonic. The alias is presentation only; the decoded opcode and immediate operands preserve the underlying instruction.

The decompiler lowers these operations to width-typed bitvector expressions. This covers wrapped bitfields, zero-register inputs, and destination writes; writes to XZR are discarded by the existing register model. The expression remains composed of shifts, OR, AND, and arithmetic right shift so it can pass through existing SSA and pseudocode formatting.

`evaluate_a64_bitfield_instruction` evaluates decoded W/X `UBFM`, `SBFM`, and
`BFM` with caller-supplied source and prior-destination values. It validates
operand/access shapes and immediate bounds, applies the architectural rotate
and masks, zero-extends W results, and uses the prior destination only for
`BFM`. It does not fetch register state or model the discarded result of a
zero-register destination; callers own state sampling and commit.

This remains a focused scalar subset. Alias presentation for `BFM`-family
forms, scalar SIMD/FP, and AArch64 system instructions are not covered here.
Decoder coverage remains partial and does not imply broad ISA equivalence.
