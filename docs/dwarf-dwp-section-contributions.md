# Indexed ELF DWP section contributions

`read_elf_dwp_section_contribution` extracts one caller-selected CU or TU
contribution from an explicitly selected ELF DWP package. The key is the CU
DWO ID for the CU index or the type signature for the TU index. The caller
selects the package and remains responsible for associating it with the
expected input; no DWARF-stored path is followed.

The section ID is interpreted using the selected index version. Version 2
supports IDs 1/2/3/4/5/6/7/8 for `.debug_info.dwo`, `.debug_types.dwo`,
`.debug_abbrev.dwo`, `.debug_line.dwo`, `.debug_loc.dwo`,
`.debug_str_offsets.dwo`, `.debug_macinfo.dwo`, and `.debug_macro.dwo`.
Version 5 supports IDs 1/3/4/5/6/7/8/9 for `.debug_info.dwo`,
`.debug_abbrev.dwo`, `.debug_line.dwo`, `.debug_loclists.dwo`,
`.debug_str_offsets.dwo`, `.debug_macro.dwo`, `.debug_rnglists.dwo`, and
`.debug_addr.dwo`. A section ID absent from the selected index or not defined
for its version is rejected. The result carries the package index version,
section ID, and package-section offset, plus the selected bytes and shared
`.debug_str.dwo` and `.debug_line_str.dwo` tables.

The reader validates the ELF relocatable container, package index, unique
selected key, contribution row and range. Supported DWARF relocations are
applied to the containing section and shared string sections before extracting
the contribution. The byte budget covers ELF tables, complete source sections,
and returned copies, with a maximum of 64 MiB. Cancellation is checked while
reading tables and scanning index rows. Empty/missing contributions, unsupported
section IDs or index versions, unsupported compression/relocations, and
malformed ranges fail closed.

This is a byte extraction API, not a complete DWP importer. It does not
interpret contribution-relative offsets, parse DIEs or list entries, merge
contributions into an ELF image, or resolve supplementary references. Callers
must select the correct package index kind and key. The section-ID mapping
follows DWARF 5 package-file section identifiers.
