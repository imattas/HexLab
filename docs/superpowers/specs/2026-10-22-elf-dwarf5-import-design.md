# ELF DWARF v5 Type and Prototype Import

## Intent and boundary

Extend HexLab's existing bounded ELF `.debug_info` importer from DWARF v4 to a practical, conservative DWARF v5 subset. The primary user-visible result is that ordinary v5 compilation units can contribute named types, function prototypes, symbol names/ranges, parameter records, and source provenance through the existing import model. The work remains independent of wxWidgets and does not attempt to implement the full DWARF standard.

The ELF loader continues to treat debug metadata as optional: malformed or unsupported DWARF produces a metadata diagnostic while the executable remains loadable. Existing v4 inputs retain their current behavior. The importer continues to reject unsupported type layouts and never evaluates location expressions.

## Design

Add an ELF/DWARF v5 section bundle to the symbols API containing `.debug_info`, `.debug_abbrev`, `.debug_str`, `.debug_str_offsets`, and `.debug_addr`, with a version-aware entry point. Keep `import_dwarf_v4` as a compatibility wrapper. Parse the v5 unit header (`unit_type`, address size, abbreviation offset and the bounded type/skeleton header fields needed to advance safely); ordinary compile units are supported, while type/split/supplementary units remain explicitly unsupported. Preserve little-endian ELF-only handling at the ELF boundary.

The v5 decoder adds common fixed-width and indexed forms used by compiler output: `DW_FORM_implicit_const`, `DW_FORM_strp`, `DW_FORM_line_strp` only when the supplied line-string section exists, `DW_FORM_strx` and its 1/2/3/4-byte variants, `DW_FORM_addrx` and its variants, and `DW_FORM_ref4`/`ref8`/`ref_udata` unit-relative references. Indexed forms are represented unresolved while DIEs are read, then resolved from the CU's root `DW_AT_str_offsets_base` and `DW_AT_addr_base`, validating contribution headers, entry widths, arithmetic, index bounds, and string termination before publication. Existing records and type resolution are reused.

The existing line parser already supports DWARF v5 line-table descriptor formats and is integrated independently by the ELF loader. This step will preserve that path and add focused fixture coverage for a v5 line unit when possible without broadening line-table APIs or conflating line data with DIE parsing.

## Error and resource behavior

Every section and contribution remains bounded by the existing ELF metadata budget. Malformed headers, table extents, forms, strings, and references return structured errors; unsupported unit kinds/forms remain `unsupported`. ELF loading retains its current best-effort behavior and emits diagnostics. Cancellation checks and existing caps remain in force. Results are only attached after a complete successful import, so a malformed unit cannot publish a partial type graph.

## Verification

Generated tests cover v5 headers, inline and indexed names, base type/subprogram/prototype references, line-table v5 compatibility, malformed/truncated contribution headers, out-of-range indices, unterminated strings, unsupported unit types, and the existing v4 regressions. Focused symbol and ELF-image suites run from an isolated build directory. The root integrator owns shared CMake/test registration, README, and capability-ledger updates.

## Explicit exclusions

Cross-unit and supplementary references, split DWARF, type units, relocations, compressed sections, big-endian DIE forms, location/range lists, full indexed address semantics beyond direct address attributes, macros, and the wider DWARF type vocabulary are not part of this increment. No third-party source is copied; implementation follows the DWARF format and repository-local abstractions.
