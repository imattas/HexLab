# ELF DWARF macro metadata

ELF loading recognizes `.debug_macinfo` and `.zdebug_macinfo` legacy streams,
plus `.debug_macro` and `.debug_macro.dwo` sections in raw,
ELF `SHF_COMPRESSED` zlib, and GNU `.zdebug_macro` naming forms, retaining
bounded DWARF v5 macro units in `ElfMetadata`.
Each v5 unit records its section identity, unit/file offsets, version, DWARF32/64
offset width, and optional line-table offset. Legacy macinfo contributions have
no version/header, so they are represented with version and offset width zero.
Operations retain section
coordinates and their decoded operands for inline `define`/`undef`, file-stack
markers, string-table-offset and string-index variants, and ordinary or
supplementary macro-unit imports.
Macro text is preserved as raw bytes in a string; external string references
remain offsets or indices and retain whether they refer to the supplementary
object. Those strings are not resolved.

Compressed sections use the existing bounded ELF DWARF zlib decoder, including
header size, declared expansion size, exact stream consumption, and checksum
validation. Both stored and expanded bytes count against the shared 64 MiB
metadata budget. For compressed units, unit/record `section_offset` values are
coordinates in the expanded section; `file_offset` identifies the stored
section anchor because the inflater does not retain per-byte compressed-stream
provenance. The unit's `compressed` bit distinguishes this case. Uncompressed
`file_offset` values continue to point to the exact source bytes.

Unit lengths, version, flags, offset width, optional line offset, and optional
opcode-operand table are checked before operations are read. The parser checks
ULEB128 overflow and truncation, NUL termination, the end-of-unit terminator,
import targets at exact unit boundaries, cancellation, and the shared 64 MiB
metadata budget. A section is published only after all its units and imports
validate. Standard units may coexist in one section.

Legacy macinfo define/undef, file-stack entries, and vendor-extension
constant/string operands are decoded. Legacy streams carry no lengths, so each
contribution must terminate with opcode zero; truncation and unknown opcodes
fail the ELF metadata parse. Standard DWARF v5 macro opcodes retain their
decoded fields. Vendor-defined v5 opcodes with opcode-table descriptions are
retained with their opcode, operand form, section-relative source offset, and
decoded operand. Supported forms include fixed-width data and flags,
ULEB/SLEB, inline strings, blocks, `strp`/`strp_sup`/`line_strp`/`sec_offset`,
`strx` and `strx1..4`, and `data16`. Inline block operands are capped at 64 KiB
each and all operand storage shares the existing 64 MiB metadata budget. The
CLI previews at most 256 vendor records and 512 operands, and displays at most
32 bytes of each block. This is structural retention only; vendor-specific
macro semantics are not inferred. Resolving
`strp`/`strx`/supplementary text, supplementary import linking, ordinary import
expansion (though ordinary import targets are checked against unit boundaries
within their source section), and applying macro
definitions to source files remain unsupported. Macro rows do not alter symbol,
type, or source-line identity.

The v5 opcode and unit layouts follow section 6.3.1 and table 7.28 in the
[DWARF Version 5 standard](https://dwarfstd.org/doc/DWARF5.pdf); the legacy
records follow section 6.3.1 in the [DWARF Version 4 standard](https://dwarfstd.org/doc/DWARF4.pdf).
