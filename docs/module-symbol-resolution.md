# Supplied PE module symbol resolution

`hexlab_cli modules <binary>...` reports dependency names and now resolves
individual PE imports against explicitly supplied files. A provider file must
have the same case-insensitive leaf name as the import library. This mirrors
the Windows module-name lookup rule and keeps the result grounded in the files
the user supplied.

Named imports are matched byte-for-byte against export names; names are
case-sensitive. Ordinal imports match the export ordinal. A unique concrete
export reports its provider path, preferred virtual address, and ordinal.
Forwarded exports are followed only when the named forwarder module is present
among the explicitly supplied files. Each forwarded provider hop is checked
against the importing image's concrete PE machine and PE32/PE32+ class; a
cross-ABI forwarder terminates as unsupported instead of resolving to an
incompatible final export. Both `MODULE.symbol` and
`MODULE.#ordinal` targets are supported, including module names with a `.dll`
suffix. The walk is limited to 32 hops, detects repeated module/symbol pairs,
and preserves ambiguity and missing-provider results instead of choosing a
candidate.

For an import's initial provider, same-name files are first filtered by PE
format and the importing image's known machine/class. Only compatible PE files
can make the provider ambiguous. If same-name files exist but none is usable,
the report identifies either the non-PE format or the first deterministic ABI
mismatch; incompatible alternatives do not obscure a unique compatible file.

The same PE ABI classifier filters supplied-file dependency-graph providers,
so a DLL with the right name but a known incompatible machine or PE32/PE32+
class is not shown as the graph target. Unknown machine IDs remain eligible.

This pass resolves only directly supplied PE modules and modules reached by
their explicit export-forwarder strings. It does not query the host loader,
search system directories, recursively load ordinary transitive dependencies,
apply API-set or side-by-side redirection. Before accepting an export provider,
the resolver rejects concrete COFF machine-ID and PE32/PE32+ optional-header
mismatches. Unknown machine IDs remain open because the metadata does not
establish incompatibility. ARM64EC/ARM64X mixed-module compatibility is not
inferred from the machine field alone. Non-PE import metadata continues to appear in the existing
dependency inventory but does not receive PE symbol matching.
At most 100,000 imports per PE module are printed; additional rows are counted
in an omission notice.

ELF graph mode can now populate the supplied candidate set through explicit
sysroot filesystem discovery. It retains canonical file identities and search
provenance, applies the existing ELF compatibility filter before a discovered
module enters the graph, and recursively follows only unambiguous providers.
See [discovery policy and limits](cli-module-dependencies.md#opt-in-elf-filesystem-discovery).
The symbol report still does not claim dynamic-loader link-map precedence,
relocation application or TLS/IFUNC execution semantics.
