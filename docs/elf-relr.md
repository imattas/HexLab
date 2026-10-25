# ELF packed relative relocations

HexLab recognizes `SHT_RELR` sections and the `DT_RELR`, `DT_RELRSZ`, and
`DT_RELRENT` dynamic tags. It requires the table entry width to match the ELF
word size, bounds the encoded table and expanded relocation count, and reads
values in the file's byte order. `ET_REL` is rejected because the ABI reserves
RELR for `ET_EXEC` and `ET_DYN`.

Even entries are direct word-aligned relocation target addresses. Odd entries
are bitmaps relative to the cursor established by the preceding direct entry;
each set bit expands to a word-sized relative relocation, then the cursor
advances by the bitmap's covered span. Targets must be strictly increasing,
word-aligned, mapped, and large enough for a pointer-sized field. Bitmap entries
before any direct address, duplicate or out-of-order targets, incomplete tag
triples, invalid widths, and address overflow are rejected.

Expanded `ElfRelocation` records retain their section or dynamic-table source,
source record file offset and entry index, target address, implicit addend,
pointer width, and base-relative semantic kind. A dynamic table that aliases a
matching `SHT_RELR` section reuses the same parsed relocation table. RELR is
processed before ordinary `DT_REL`/`DT_RELA` tables, as required by the generic
ABI. When an architecture's ordinary `RELATIVE` type is known, that type is
retained in the record; otherwise the semantic kind is still available and
relocation metadata is marked incomplete.

The runtime relocation application path applies the universal RELR `B + A`
formula for ELF32 and ELF64 `ET_DYN` images in either byte order. It samples
and writes pointer-sized fields in file byte order and rejects ELF32 results
outside the 32-bit address domain. The separate ordinary REL/RELA runtime
subset remains little-endian ELF64 x86-64/AArch64, and symbol-slot relocations
remain unsupported for other profiles.

The section and dynamic-tag requirements follow the [ELF gABI section header
and dynamic-linking definitions](https://gabi.xinuos.com/elf/03-sheader.html).
