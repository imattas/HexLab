# DWARF supplementary type references

ELF import resolves `DW_FORM_ref_sup4` and `DW_FORM_ref_sup8` type references
through `ElfLoadOptions::dwarf_supplementary_package`. Both forms encode an
absolute `.debug_info.dwo` offset in the explicitly selected supplementary
object; their 4-byte and 8-byte widths are independent of the referring unit's
DWARF32/DWARF64 format. The application must carry a version-5 `.debug_sup`
descriptor with `is_supplementary=0` and a nonempty checksum. The selected ELF
must have the same class and byte order, and its supplementary `.debug_sup`
descriptor must carry the exact matching checksum. No embedded filename is
opened.

The selected package may contain a version-5 CU index, a version-5 TU index,
or both. A CU-only package is sufficient for a reference to an imported type
DIE in a split compile unit. The loader checks all indexed INFO ranges across
both indexes and requires exactly one owner for the requested offset. Missing
owners, overlapping CU/TU ranges, and duplicate owners fail closed, even if the
definitions would have equivalent types. Offsets in other selected external or
embedded packages are never candidates for a supplementary offset.

CU targets use the existing bounded cross-contribution DIE resolver. It checks
the complete unit extent, version-5 header, address size, indexed DWO ID and
exact imported DIE offset. CU contributions accept DWARF32 and DWARF64 unit
headers; index tables remain 32-bit. The loader also checks the returned
contribution signature, section base, size and relative DIE offset against the
uniquely selected row, and accepts only a type summary. The application import
keeps its referring DIE's source origin; a supplementary offset is never
reinterpreted as a local DIE offset or a global offset across package files.

CU-to-CU `DW_FORM_ref_addr` type dependencies can resolve recursively within
this same supplementary package under the CU resolver's cycle, cache, request
and byte limits. CU targets needing an external `DW_FORM_ref_sig8` resolver,
supplementary chains from the target package, non-type supplementary DIE
references, and version-2/GNU DWARF4 package indexes remain unsupported here.
The DIE importer remains little-endian. Split compile units using indexed
strings still require an explicit `DW_AT_str_offsets_base`; this path does not
synthesize a base from another unit. The existing TU-target path remains
limited to DWARF32 version-5 type or
split-type contributions; its indexed type-signature dependencies retain their
existing support. Cross-package signature catalogs are separate from
supplementary offset selection.

Package sections and decoded index tables share the configured supplementary
byte budget (64 MiB by default). The CU resolver uses the remaining byte budget
and at most `min(configured_requests, 4096)` requests. The importer additionally
checks its shared supplementary request and reported-byte/encoded-type budgets
for both forms, including cached resolutions. Cancellation and failed imports
publish no partial import result. Automatic discovery, supplementary package
relocations, and unsupported type/location/range forms remain explicit limits.
