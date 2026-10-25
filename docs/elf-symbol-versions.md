# ELF GNU symbol versions

HexLab associates GNU symbol-version indexes with the exact ELF symbol rows
they describe. It parses `SHT_GNU_versym`, `SHT_GNU_verdef`, and
`SHT_GNU_verneed` when section headers are available, and also follows
`DT_VERSYM`, `DT_VERDEF`/`DT_VERDEFNUM`, and
`DT_VERNEED`/`DT_VERNEEDNUM` virtual addresses for stripped images. The
dynamic path uses the matching bounded dynamic symbol table and its
`DT_STRTAB`/`DT_STRSZ`; it does not infer symbol counts from the version data.

The parser supports ELF32 and ELF64 in either byte order. Each `ElfSymbol`
retains its base name separately from the 15-bit version index, the hidden
bit, the resolved version name, and the required library name for versioned
imports. CLI symbol rows show these fields without folding them into the base
symbol name.

Definition and requirement record counts are capped at 65,536. Each auxiliary
chain must match its declared count and terminate at the final record. String
indexes, virtual-address arithmetic, mapped initialized extents, dynamic
symbol counts, and aggregate metadata allocations are checked against the
loader's existing limits. Section and dynamic descriptions of the same
symbol version must agree. Malformed or conflicting version metadata is
reported as malformed ELF metadata instead of being guessed.

Versioned symbol identities are currently inspection metadata. The loader
does not use version constraints to select a shared-library implementation,
perform dynamic linking, or rewrite symbol names in the project database.
