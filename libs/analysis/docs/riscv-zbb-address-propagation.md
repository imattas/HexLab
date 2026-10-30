# RISC-V Zbb extension reference propagation

Register-derived address analysis evaluates decoded RV32/RV64 `sext.b`,
`sext.h`, and `zext.h` instructions when their source register contains a
known address constant. The sign-extension operations interpret the low 8 or
16 bits as signed values and extend to XLEN; `zext.h` retains the low 16 bits.
The resulting value remains in the current instruction's address space.

The pass publishes a reference only when the computed result identifies
mapped, readable image bytes. The reference is attached to the source-register
operand of the extension instruction, and producer provenance follows the
source value when available. Writes to the destination invalidate its previous
tracked value even when the source is unknown. The architectural zero register
is treated as a known zero input.

This is constant propagation over the observed register value, not a claim
about a pointer type or source-language intent. Other Zbb operations, vector
operations, values merged from disagreeing control-flow paths, and references
to unmapped values are not recovered by this increment.
