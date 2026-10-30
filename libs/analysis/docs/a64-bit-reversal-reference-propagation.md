# AArch64 bit and byte reversal references

Register reference analysis applies the decoded AArch64 `RBIT`, `REV16`,
`REV32`, and `REV` data transforms to a tracked 32- or 64-bit register value.
`REV16` reverses bytes within each halfword, `REV32` reverses bytes within
each 32-bit lane of an X register, and `REV` reverses bytes across the
destination width. `RBIT` reverses the complete destination-width bit string.

The decoder's register widths and zero-register identity are honored. `REV32`
is accepted only for its 64-bit form. Destination writes invalidate previous
tracked values, including when the source is unknown. A reference is emitted
only if the transformed result identifies mapped, readable image bytes.

This is fixed-width data propagation and does not assign pointer type or
endianness intent. Other bitfield and SIMD reversal forms, unknown source
values, and unmapped results remain outside this increment.
