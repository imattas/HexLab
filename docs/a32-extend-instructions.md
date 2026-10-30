# A32 byte and halfword extension

The original A32 decoder recognizes ARMv6 `SXTB`, `SXTH`, `UXTB`, `UXTH`,
`SXTAB`, `SXTAH`, `UXTAB`, and `UXTAH`. It validates the fixed opcode fields,
rejects PC as the destination or shifted source, retains the A32 predicate,
and represents the optional base and rotated source as typed operands with
register read/write effects. The encoded rotation is restricted by the
instruction format to 0, 8, 16, or 24 bits.

These are decode facts only. The common pseudocode lifter does not yet lower
the extension and add operations, and corresponding Thumb encodings are not
added by this slice.
