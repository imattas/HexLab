# Thumb-2 wide immediate moves

The Thumb decoder recognizes the 32-bit `MOVW` and `MOVT` encodings with a
16-bit immediate split across the two instruction halfwords. Both forms write
an explicitly named general-purpose destination. `MOVT` also reads that
destination because it replaces only bits 31:16 and preserves bits 15:0;
`MOVW` starts from no old-register value. The formatter prints the ordinary
`movw Rd, #imm16` and `movt Rd, #imm16` forms.

This slice rejects SP and PC destinations and reserved second-halfword
encodings. It does not claim value lifting, relocation handling, or broader
Thumb-2 data-processing coverage.
