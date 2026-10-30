# AArch64 AdvSIMD integer semantics

`evaluate_a64_simd_integer_instruction` evaluates the decoder's three-register vector `ADD`, `SUB`, `AND`, `ORR`, and `EOR` subset. Add/subtract lanes wrap modulo their element width for 8-, 16-, 32-, and 64-bit elements. Logical forms apply across the active vector bytes.

Inputs and output are 16-byte architectural vector bit patterns indexed by increasing bit significance, with byte 0 holding bits 7:0. For 64-bit vector forms, only the low eight input bytes participate and the output upper half is zeroed, matching the decoder's full V-register write effect. The helper validates the decoded operands, vector shape, and register effects; it does not read or commit vector registers. Floating-point operations, min/max, saturating arithmetic, and other AdvSIMD forms are outside this slice.
