# DWARF split-package type catalogs

`make_dwarf_package_catalog_type_signature_resolver()` links type-unit signatures
across a bounded set of explicitly selected DWP packages. Each catalog entry
contains its parsed TU index, borrowed section views and string tables, a stable
`source_id`, and an `identity_verified` attestation from the caller. The caller
keeps all backing buffers alive for the resolver's lifetime.

This fills the case where a type-unit in one selected package references a
signature contributed by another selected package. The resolver builds one
signature-to-package map, then uses that same resolver while importing each
contribution. Successful types are cached; active-signature cycles, missing
signatures, and signatures found in more than one selected package return
explicit diagnostics. A duplicate is treated as ambiguous even if the DWARF
signature is intended to describe an equivalent type; the importer does not
choose a package by enumeration order.

The catalog accepts 1 to 64 packages and at most 1,000,000 total indexed type
signatures. Every index must be a type-unit index and every package must have a
unique non-empty source ID and verified identity. Per-resolution contribution
bytes, encoded type bytes, request count, and cancellation continue to use
`DwarfPackageTypeResolutionLimits` and the supplied stop token. The resolver
selects by exact signature membership, not filename similarity.

Package discovery stays with the caller. A safe integration enumerates only
approved companion locations, canonicalizes and bounds the candidates, parses
the DWP index and sections, and verifies the candidate against the binary's
build ID or `.debug_sup` checksum before setting `identity_verified`. The
resolver never opens `DW_AT_dwo_name`, `DW_AT_comp_dir`, `.debug_sup` filenames,
or package paths itself. This keeps untrusted DIE strings from becoming file
access instructions.

ELF import can combine its explicitly selected external, embedded, and
checksum-verified supplementary DWP type indexes when signatures have one
owner. This allows nested signature chains to cross packages while preserving
the same shared request, byte, and cycle budget. If a signature appears in
more than one candidate package, ELF import keeps its existing exact-membership
precedence behavior and skips the cross-package catalog rather than choosing a
duplicate definition by package order.

The catalog does not change the supported DWARF forms. It resolves type-unit
signature references only; unresolved non-type cross-unit references, missing
or ambiguous package identities, compressed or relocated sections, and forms
not handled by the bounded importer remain unsupported. A selected package
whose checksum or build identity does not match must not be added to the
catalog.
