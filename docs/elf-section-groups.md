# ELF relocatable section groups

For `ET_REL` inputs, the loader decodes each `SHT_GROUP` section into its raw
flags, signature symbol-table/index/name, and ordered member-section indexes.
It checks the four-byte word layout, symbol-table link and signature bounds,
member indexes, `SHF_GROUP` flags, duplicate membership, and that every section
marked `SHF_GROUP` appears in one group. The metadata is exposed through
`ElfMetadata::section_groups` and printed by `hexlab_cli inspect`.

This is inspection support. The loader does not perform COMDAT duplicate
selection, discard groups based on signature equivalence, resolve linker
selection policies, or apply relocation changes associated with selected or
discarded members. Unknown group flag bits are retained as raw metadata.
Malformed group relationships reject the ELF load rather than silently
presenting an incomplete membership map.
