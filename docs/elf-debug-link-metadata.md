# ELF debug-link metadata

The ELF metadata catalog recognizes `.gnu_debuglink` and
`.gnu_debugaltlink` sections without opening or searching for referenced files.
Rows preserve the section index and file offset so consumers can trace each
record to its source.

`.gnu_debuglink` records require a terminated filename, zero padding to the
four-byte CRC boundary, and exactly one 32-bit CRC in the file's byte order.
`.gnu_debugaltlink` records require a terminated filename followed by a
bounded nonempty build-ID byte sequence. Names are capped at 4 KiB and
alternate build IDs at 4 KiB; malformed extents are omitted with diagnostics.

The CRC and build ID are metadata for matching debug artifacts. HexLab does
not verify the CRC, resolve paths, or load the referenced files. This avoids
turning untrusted object metadata into filesystem access.
