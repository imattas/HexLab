# Supplied Mach-O module symbol resolution

`hexlab_cli modules <binary>...` now reports Mach-O dyld bind names after the
dependency inventory and PE/ELF import reports. It groups classic bind fixups
and chained imports by symbol, library ordinal, and weak-import state, and
counts their bind sites.

Positive ordinals must identify one parsed dylib load command. Its install-name
basename must match exactly one supplied Mach-O file basename (case-insensitive,
consistent with the module inventory). Ordinal zero is resolved against the
importer itself. The special main-executable ordinal is considered only when
exactly one supplied Mach-O image is an executable. Other special lookup
ordinals remain unresolved because they depend on dyld's process-wide lookup
rules.

The selected provider slice must have the same CPU type as the importer. Symbol
names match byte-for-byte against the provider's dyld export trie. A unique
regular export reports its preferred address. Missing and duplicate exports,
missing or ambiguous providers, architecture mismatches, and reexports are
reported explicitly. Reexports and forwarded names are not followed.

This is a bounded metadata match, not a runtime loader simulation. It does not
apply slides or bind addresses, follow `@rpath`/`@loader_path` search rules,
resolve flat or weak lookup namespaces, validate CPU subtypes/ABI compatibility,
or apply symbol interposition. Only metadata already parsed for the explicitly
selected slices is considered; each import identity is capped at 100,000 and
each section reports whether dyld metadata was complete.
