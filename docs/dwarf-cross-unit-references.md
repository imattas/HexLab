# DWARF cross-unit absolute references

DWARF 5's [split-object errata](https://dwarfstd.org/errata-dwarf5.html)
(issue 181003.1) excludes symbolic section references such as
`DW_FORM_ref_addr` from `.dwo` files. HexLab's package-offset handling below
is a bounded compatibility path for producer extensions; it is not a claim
that such references are standard split-DWARF.

`make_dwarf_package_catalog_cross_contribution_die_resolver()` resolves
`DW_FORM_ref_addr` references against a caller-selected catalog of CU-indexed
DWO/DWP sources. Each catalog entry must have a unique, non-empty `source_id`,
a parsed compile-unit index, and a caller attestation that the package identity
was verified against the selected binary or debug identity.

The importer passes its current `DwarfSections::source_id` together with the
absolute `.debug_info` section offset. The catalog first selects exactly that
source identity, then requires the offset to belong to exactly one indexed
INFO contribution and an imported type, subprogram, or variable DIE at that precise
offset. It does not treat offsets as globally unique across DWP files. Missing
sources, missing offsets, overlapping contributions, unsupported target DIEs,
and malformed index/contribution bounds return explicit errors.

The catalog is limited to 1..64 explicitly selected CU-indexed packages.
Existing package resolver limits cap each resolver's requests and examined
bytes; the importing `DwarfSections` also enforces its per-import request and
byte budget. The caller retains all index, section and string buffers and owns
package discovery and identity verification. No path from a DIE is opened.

Supported contribution form: DWARF v5 CU-indexed DWO/DWP INFO contribution
`DW_SECT_INFO` (section ID 1), with the package-index parser's supported v5
layout. Legacy single-index resolver support remains available, including its
existing v2 CU-index layout behavior. This API does not resolve cross-unit
references from arbitrary standalone objects or infer package identity from
filenames.

For an ELF-selected or embedded DWP with both CU and TU indexes, the loader
also supplies that package's bounded TU-index signature resolver to its
cross-contribution CU resolver. Thus a `DW_FORM_ref_addr` target in another
CU can have a type graph containing `DW_FORM_ref_sig8` references to type units
in the same package. TU-index membership, unit-header signature, contribution
bounds, and the type DIE offset are checked before a type is returned. A
missing signature or unsupported target fails the import without publishing
partial results. The returned cross-contribution summary retains the target
CU's index signature and section-relative DIE offset; the nested TU type is a
type pointer and does not carry a separate TU-origin record in that summary.
The CU and TU resolvers each retain their own request, byte,
cache, cancellation, and cycle limits; they do not treat package offsets as
identities in another file. TU-to-CU dependencies through this particular
composition, external-package signatures in the target CU, and supplementary
package composition remain unsupported.
