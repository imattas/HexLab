# AArch64 inverted logical reference propagation

The A64 shifted-register logical encodings with the inversion bit set decode as
`BIC`, `ORN`, `EON`, or `BICS`. The reference analyzer propagates a W/X value
only when the destination and both inputs have validated register effects and
both source values are known in the instruction's address space. It evaluates
the encoded LSL, LSR, ASR, or ROR before inverting the second source, then
applies the operation at the destination width. W writes zero-extend to 64 bits.

`BICS` also updates the same-block NZCV fact: N and Z come from the result and
C/V are zero. This lets a following supported conditional select use the new
flags. An unknown flag input or another unsupported flag writer clears that
fact. Only exact results that map to the image emit an immediate reference;
other results can continue through supported address arithmetic or memory
loads.

The decoder preserves the four operations as distinct opcode identities.
Logical-immediate encodings remain `AND`/`ORR`/`EOR`/`ANDS`; inversion here is
specific to the shifted-register encoding. No SIMD/FP form, SP operand, unknown
register input, or memory effect is inferred.
