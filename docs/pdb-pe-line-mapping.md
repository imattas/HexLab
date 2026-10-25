# Mapping PDB C13 lines to PE addresses

`attach_pdb_source_lines` in `hexlab/loaders/pdb_lines.hpp` connects an
explicitly parsed `types::PdbDatabase` and `types::PdbSourceLineTable` to a
loaded PE image. It imports rows only when exactly one PE RSDS CodeView record
has the same GUID and age as PDB stream 1. A missing, mismatched, or ambiguous
identity returns zero and leaves existing PE source rows unchanged; paths are
never used as an identity fallback.

CodeView section ordinals are one-based and index the PE section table in file
order. The parser retains both `reloc_offset`, the contribution start, and
`section_offset`, the row address (`reloc_offset + line_offset`). A row receives
an address only if the contribution range starting at `reloc_offset` fits
within `max(VirtualSize, SizeOfRawData)`, the row offset lies inside that
contribution and section, its RVA fits within `SizeOfImage`, and adding the
selected runtime base does not overflow. The address uses the image's address-space ID and
`LoadedImage::load_base` when present, otherwise the preferred image base.
Rows that pass PDB identity matching but fail section/range checks are retained
with their source path, checksum, line/column data, section coordinate, module,
object, and subsection provenance, and have no mapped address.

This operation associates data supplied by the caller; it does not locate or
open the PDB path from the PE debug record. Parse and validate the PDB with the
types API first, then pass the parsed database and C13 table explicitly.

`attach_pdb_inline_sites` applies the same unique GUID+age gate to inline scopes
and joins `PdbLocalTable::inline_sites` to C13 inlinee/file identities. Explicit
code ranges must fit their outer procedure, the PE section and image extent,
and the selected base without overflow before receiving an address. Missing
source identities keep the scope and code range inspectable with unavailable
source text. Rebinding clears old inline metadata before reading the new PDB.

The PE **PDB inline scopes** tab previews up to 4096 scope/range rows, including
module/site/parent identities, inlinee IPI index, source start line, and explicit
unsupported states. Activating a mapped range navigates to its start. The Source
view includes up to 250,000 combined rows when adding inline ranges and selects
the deepest containing inline range; equal-depth competing scopes are reported
as ambiguous. Inline attribution never continues past its explicit range end.
Existing source-file access restrictions and the 1 MiB display limit apply.
