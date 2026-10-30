# Mach-O chained bind resolution

`resolve_macho_chained_binds` resolves import-address relationships for parsed
`LC_DYLD_CHAINED_FIXUPS` bind pointers when the caller already has an explicit
address for each parsed import row. The caller supplies an address span in
`MachOMetadata::chained_imports` order; a missing optional address stays
unresolved, while an explicit zero is a valid supplied address.

Each result identifies the original pointer row and import row, retains the
caller-supplied import address, and reports the checked sum of the import
addend and pointer-encoded addend. Overflow in the addend sum or address
arithmetic is reported per row without wrapping. Invalid source interpretations,
incomplete import rows, and mismatched pointer/import namespaces are not
resolved. Work is bounded by the one-million pointer/import row limits and
honors cancellation.

This is an explicit-address operation, not a library searcher or dynamic
loader. It does not find dependent images, interpret install names or reexports,
select among duplicate symbols, apply fixup bytes, or validate code signatures
and publisher trust. An absent weak import is still reported as missing until
the caller explicitly supplies its zero fallback or another selected address.
For authenticated binds the reported address is pre-PAC and still requires a
runtime signing context; no usable signed pointer is fabricated.
