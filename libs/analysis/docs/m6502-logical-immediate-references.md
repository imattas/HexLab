# MOS6502 immediate logical reference propagation

The block-local MOS6502 address tracker preserves a known accumulator value
through immediate `AND`, `ORA`, and `EOR` instructions. The decoder's exact
8-bit immediate is applied with ordinary 8-bit bitwise semantics, and the
logical instruction becomes the latest value producer. This lets later `TAX`
or `TAY` transfers carry the transformed value into indexed-memory reference
resolution.

This tracks only the accumulator data result. It makes no N/Z/V/C status-flag
claim, and does not evaluate memory-source logical operations, ADC/SBC,
cross-block register constants, or unknown incoming accumulator values.
