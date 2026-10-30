# GNU ELF HWCAP notes

The ELF note reader recognizes `NT_GNU_HWCAP` (2) with owner `GNU` in the
existing program/section note ranges. It decodes the descriptor's 32-bit entry
count and mask using the ELF byte order, then reads each one-byte bit index and
NUL-terminated capability name. The model retains enabled state derived from
the mask and file offsets for the note descriptor, entry byte, and name.

The parser caps entries at 4,096 per note, each name at 4,096 bytes, and the
aggregate copied names at 1 MiB. Truncated headers, invalid bit indexes,
unterminated/empty names, over-budget records, and trailing descriptor bytes
are rejected. CLI output caps notes, entries per note, and displayed name
prefixes independently.

Names are preserved as metadata labels. The parser does not verify that the
running CPU supports an advertised feature or apply a hardware capability to
the image.
