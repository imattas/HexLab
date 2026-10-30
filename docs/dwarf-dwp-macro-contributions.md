# ELF DWP macro contribution lookup

`read_elf_dwp_macro_contribution` extracts one indexed `DW_SECT_MACRO`
contribution from an explicitly selected ELF DWP package. The caller supplies
the index kind and key: a CU index uses the split DWO ID, while a TU index uses
the type-unit signature. Package index version 2 uses section ID 8 and version
5 uses ID 7; both select `.debug_macro.dwo`. Legacy v2 `DW_SECT_MACINFO` is
outside this API. The returned value owns the contribution bytes and shared
`.debug_str.dwo` / `.debug_line_str.dwo` tables, and records the package-level
contribution offset for provenance.

The loader validates the ELF relocatable container, parses the selected
bounded CU/TU index, requires one matching row and a nonempty macro
contribution, checks the contribution range against the containing section,
and applies the ELF DWARF relocations already supported by the loader before
slicing. The byte budget covers ELF metadata, source sections, and returned
copies; the default and hard maximum is 64 MiB. Cancellation is checked during table
and index processing.

This API only extracts bytes. HexLab does not yet interpret macro opcodes,
expand imports, or merge macro tables into `ImportResult`. The caller remains
responsible for selecting the package and verifying its identity against the
application; the API never follows a path stored in DWARF. Unsupported
relocations into compressed sections, unsupported compression algorithms,
non-relocatable packages, or absent/empty
indexed macro contributions fail closed. The package contribution IDs and
offsets follow [DWARF 5 package file section identifiers](https://dwarfstd.org/doc/DWARF5.pdf).
