# ELF DWP line contribution lookup

`read_elf_dwp_line_contribution` extracts one `DW_SECT_LINE` contribution
(package-index section ID 4) from an explicitly selected ELF DWP package. The
caller supplies the index kind and key: a CU index uses the split DWO ID, while
a TU index uses the type-unit signature. The returned value owns the line
contribution bytes and the package's shared `.debug_str.dwo` and
`.debug_line_str.dwo` tables, and records the index version, section ID, key,
and package-relative contribution offset.

The loader validates the ELF relocatable container, reads the bounded selected
CU/TU index, requires one matching row and a nonempty line contribution, and
checks its extent against `.debug_line.dwo`. It applies only the ELF DWARF
relocations already supported by the loader before slicing. The byte budget
covers metadata, source sections, shared strings, and returned copies; the
default and hard maximum is 64 MiB. Cancellation is checked during table and
index processing and relocation application.

This API extracts bytes only. It does not parse line programs, associate a
contribution with a compile unit, resolve file paths, or merge source rows into
`ImportResult`. The caller selects the package and verifies its identity; the
API never follows a path stored in DWARF. Unsupported relocations,
non-relocatable packages, or absent/empty indexed line contributions fail
closed. Package contribution IDs and offsets follow
[DWARF 5 package file section identifiers](https://dwarfstd.org/doc/DWARF5.pdf).
