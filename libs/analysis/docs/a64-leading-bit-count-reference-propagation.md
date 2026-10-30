# AArch64 leading-bit count references

Register reference analysis propagates exact `CLZ` and `CLS` results from a
known 32-bit W-register or 64-bit X-register value. W-register results are
zero-extended, and `WZR`/`XZR` sources are treated as zero. `CLZ` returns the
number of leading zero bits; `CLS` counts redundant sign bits while excluding
the sign bit itself.

The destination's previous fact is invalidated before a result is recorded.
An immediate target fact is emitted only when the computed count is a mapped
image address. This records fixed-width arithmetic evidence; it does not infer
that the result is a pointer. Unknown source values and unmapped counts remain
unresolved.
