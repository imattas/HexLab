# PDB CodeView C13 source lines

`parse_pdb_source_lines` imports CodeView C13 string-table (`DEBUG_S_STRINGTABLE`),
file-checksum (`DEBUG_S_FILECHKSMS`), and line (`DEBUG_S_LINES`) subsections from
DBI module streams. It resolves line file IDs to paths and preserves the checksum
kind and bytes, line number and end-line delta, optional start/end columns,
statement flag, module and object names, module index, and subsection provenance.

An address is always represented by the CodeView section number and its
section-relative offset (`RelocOffset + line offset`). The parser does not turn
this into an RVA; a later PE section-mapping step must match the PDB section
number to the corresponding image section. Contribution and line-block extents
are returned separately. C13 line records have no DWARF-style end-sequence
marker, so `end_sequence` remains false rather than guessing a terminal row.

The parser checks DBI and module stream extents, C13 subsection headers and
padding, checksum record alignment, filename references, line-block sizes,
integer overflow, cancellation, and limits (32 MiB C13 data and 65,536
subsections per module, 65,535 files per module, 2 million source rows and
256 MiB estimated output per PDB, and bounded names/paths). When
module C13 rows refer to the PDB-wide string table, `/names` is resolved through
the PDB info stream's named-stream map. Unknown C13 subsection kinds are skipped
by their validated lengths. Inlinee-lines, frame-data, and other C13 records are
not interpreted.

The layout follows LLVM's published [CodeView line subsection structures](https://llvm.org/doxygen/DebugLinesSubsection_8h_source.html),
[checksum entry parsing](https://llvm.org/doxygen/DebugChecksumsSubsection_8cpp_source.html),
and [PDB named-stream map specification](https://llvm.org/docs/PDB/PdbStream.html#named-stream-map).
No third-party parser implementation is embedded in HexLab.
