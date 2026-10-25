# PE AMD64 chained function chunks

AMD64 exception-directory rows provide initialized code ranges and reference
their `UNWIND_INFO`. A row whose unwind record contains `UNW_FLAG_CHAININFO`
may describe a discontiguous fragment sharing another row's unwind state.

Function recovery now links that fragment to its primary range when the chained
tuple exactly matches another parsed exception-directory row's begin RVA, end
RVA, and unwind-info RVA. The fragment range becomes an additional metadata
chunk on the primary entry. Flow ownership can therefore continue through the
fragment while remaining bounded to the validated ranges. The fragment row does
not create its own unwind-seeded function entry.

If the tuple does not exactly identify a parsed primary row, recovery keeps the
fragment as an independent range/root. Explicit user-defined function chunks
still take precedence over metadata chunks. This implementation only merges
AMD64 exception-directory evidence; it does not infer fragments from symbols,
code layout, or linker naming conventions. A separate symbol or user root at a
fragment address can still establish its own function record.
