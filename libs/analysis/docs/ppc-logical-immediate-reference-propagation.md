# PowerPC logical-immediate reference propagation

Register reference analysis propagates a tracked PowerPC address constant
through `ORI`, `ORIS`, `XORI`, `XORIS`, `ANDI.`, and `ANDIS.`. The immediate is
used as represented by the decoder; for the `*IS` instructions it is already
shifted into the upper halfword. Results wrap to the active 32- or 64-bit GPR
width.

An xref is emitted only when the resulting value identifies mapped, readable
image bytes. The analysis tracks the integer GPR result and does not infer
pointer type or source-language meaning. `ANDI.`/`ANDIS.` update CR0 in the
architecture, but this propagation makes no condition-register or flag claim.
Unknown source registers, memory-derived values, and other logical-immediate
operations remain unresolved.
