# Supplied PE module symbol resolution

`hexlab_cli modules <binary>...` reports dependency names and now resolves
individual PE imports against explicitly supplied files. A provider file must
have the same case-insensitive leaf name as the import library. This mirrors
the Windows module-name lookup rule and keeps the result grounded in the files
the user supplied.

Named imports are matched byte-for-byte against export names; names are
case-sensitive. Ordinal imports match the export ordinal. A unique concrete
export reports its provider path, preferred virtual address, and ordinal.
Forwarded exports are reported with their forwarder string and are not followed
through inferred aliases. Missing modules, missing exports, duplicate provider
files, duplicate matches, non-PE providers, and malformed import identities are
reported separately instead of being guessed.

This pass resolves only directly supplied PE modules. It does not query the
host loader, search system directories, recursively load transitive
dependencies, apply API-set or side-by-side redirection, validate architecture
compatibility, or follow forwarders. Non-PE import metadata continues to appear
in the existing dependency inventory but does not receive PE symbol matching.
At most 100,000 imports per PE module are printed; additional rows are counted
in an omission notice.
