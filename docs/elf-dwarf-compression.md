# Compressed ELF DWARF sections

The ELF loader expands DWARF sections encoded with either the standard
`SHF_COMPRESSED` section flag (`Elf32_Chdr` / `Elf64_Chdr`) or the GNU
`.zdebug_*` convention. Both formats currently accept the zlib/DEFLATE
algorithm. GNU names are matched to their ordinary `.debug_*` names, so
compressed info, abbreviation, string, indexed-table, line, and DWP sections
flow through the same import paths as uncompressed data. Declaring both a
standard and GNU alias for one logical section is rejected as a duplicate.

The loader validates the compression header, ELF byte order, reserved word,
algorithm identifier, alignment, GNU `ZLIB` marker, declared expanded size,
and exact DEFLATE stream extent. Inflation runs in 64 KiB input and 32 KiB
output windows and checks cancellation between decoder calls. Trailing
compressed bytes, truncated streams, wrong output sizes, unsupported
algorithms, malformed headers, and `SHT_NOBITS` sections fail closed. The
compressed section and expanded bytes
are charged to the existing shared 64 MiB ELF metadata budget before
allocation. The existing logical DWARF section identity and offsets remain the
source provenance presented to DWARF import; compressed-byte-to-DWARF-offset
mapping is not available.

Relocations in debug sections are not applied. The lower-level symbols APIs
continue to accept already materialized section bytes and do not perform ELF
section decompression themselves.
