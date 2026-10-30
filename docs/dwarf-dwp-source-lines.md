# ELF DWP source-line rows

`parse_elf_dwp_line_contribution` consumes one explicit
`ElfDwpLineContribution` and returns bounded address/file/line rows. The caller
supplies the target address size (4 or 8) and byte order. Parsing delegates to
the existing DWARF v2-v5 line-program importer, including its supported v5
directory/file forms and shared `.debug_str.dwo` / `.debug_line_str.dwo`
references. Unsupported versions, forms, opcodes, malformed tables, or an
address-size mismatch fail closed.

Each row retains the DWP key/index provenance, package contribution offset,
line-unit index/version, address, raw file-table name, directory index, line,
column, and end-sequence marker. Filenames are not joined with directory names
or compilation directories, paths are not resolved, and rows are not
associated with a compile unit or rebased into an image. Consumers must supply
the correct address size and byte order for the contribution.

The importer defaults to at most one million rows and a 64 MiB aggregate bound
for contribution/shared-string input and emitted row records. Callers may lower
these limits; raising them above those hard ceilings is rejected. Cancellation
is checked by the line parser and while flattening rows. This is a source-line
lookup primitive, not full DWP/DWARF source-path integration.
