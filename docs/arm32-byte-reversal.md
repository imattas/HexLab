# A32 byte and bit reversal

The A32 decoder recognizes the ARMv6 scalar REV family: `REV` reverses the four bytes in a 32-bit word, `REV16` reverses bytes independently within each halfword, `REVSH` reverses the low halfword's bytes and sign-extends that halfword, and `RBIT` reverses all 32 bits. These instructions do not change APSR.

The decoder records the destination as a write operand and the source as a read operand, with matching GPR read/write effects. The A32 condition field is retained by the common decoder and formatter, so ordinary conditional forms remain predicated. Encodings naming PC as either register are rejected because those operands are architecturally unpredictable for these forms. Other media/DSP encodings and all Thumb encodings remain outside this slice.
