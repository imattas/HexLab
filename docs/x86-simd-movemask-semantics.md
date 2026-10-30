# x86 SIMD movemask semantics

`evaluate_x86_simd_movemask` evaluates register-source `PMOVMSKB`,
`VPMOVMSKB`, `VMOVMSKPS`, and `VMOVMSKPD` instructions decoded in x86-64 mode.
It validates the decoded source and destination register widths and packs each
lane's sign bit into the corresponding low bit of a 32-bit scalar result.

`PMOVMSKB` accepts the decoded 128-bit XMM form and extracts bit 7 from each
byte. The VEX forms accept decoded XMM or YMM sources: `VPMOVMSKB` extracts
each byte's bit 7, `VMOVMSKPS` extracts each 32-bit lane's bit 31, and
`VMOVMSKPD` extracts each 64-bit lane's bit 63. Source bytes are supplied in
architectural order, with byte zero least significant. The result reports
vector width and lane width; its mask contains only the low 16 or 32 bits
corresponding to the selected vector width.

These decoded forms require a register source, so the helper does not fetch
memory operands. It returns the destination bit pattern only; instruction
execution and architectural register writeback remain caller-owned.
