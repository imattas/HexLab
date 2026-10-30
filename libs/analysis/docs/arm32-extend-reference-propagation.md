# A32 and Thumb byte/halfword extension references

Register reference analysis propagates known 32-bit address constants through
the decoded `SXTB`, `SXTH`, `UXTB`, and `UXTH` instructions in A32 and Thumb.
It also handles A32 `SXTAB`, `SXTAH`, `UXTAB`, and `UXTAH` by adding the
extended byte or halfword to the tracked base register with 32-bit wraparound.
When A32 supplies a rotated source operand, the decoded rotate is applied
before selecting the low byte or halfword.

The pass follows the decoder's operand form and register widths, and applies
the result only when the instruction is known to execute under its A32
predicate. References are emitted only if the computed value names mapped,
readable image bytes. A recognized destination write with an unknown source or
accumulate base invalidates its prior tracked value.

This records an address value observed from instruction dataflow; it does not
infer pointer types or source-language intent. Packed `SXTB16`/`UXTB16`, their
accumulate forms, arbitrary multi-instruction transforms, and ambiguous
predicated paths are not covered by this increment.
