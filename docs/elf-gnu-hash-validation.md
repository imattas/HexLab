# ELF GNU hash consistency checks

When a dynamic table provides `DT_GNU_HASH`, HexLab already uses its bucket
chains to derive a bounded dynamic-symbol count. It now also validates the
hash metadata against the names in the corresponding dynamic symbol table.
For each indexed symbol, the loader checks the GNU hash value, selected
bucket, and both required bloom-filter bits. Bucket chains must not overlap,
escape the counted symbol range, or leave indexed symbols uncovered.

These checks run for stripped dynamic tables and for a section-backed
`SHT_DYNSYM` alias. The ordinary ELF32/ELF64 and byte-order handling is shared
with the existing loader. All memory reads remain bounded by mapped initialized
image data, the existing symbol count limit, metadata budget, and cancellation
checks.

This validates internal consistency; it does not accelerate symbol lookup or
establish that the bloom filter has no false positives. Images that contain
only a SysV hash table keep the existing SysV bounds and chain validation.
