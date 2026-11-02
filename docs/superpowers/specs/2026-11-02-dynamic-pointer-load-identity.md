# Dynamic pointer-load identity

Pointer-typed loads from the same exact pointer-relative source byte range and
the same whole-memory SSA version may share pointer provenance. Exactness means
the bounded dynamic source range spans exactly the load width; wider intervals
remain opaque because matching envelopes do not prove matching runtime
addresses. The source base must already have a proven pointer root. Distinct
roots remain may-alias, and memory versions continue to guard intervening
writes. External mutation and volatile/device memory remain unmodeled.
