# ELF dependency manifest resolution

`resolve_elf_needed_libraries` turns validated `DT_NEEDED` metadata into an
ordered resolution report against a manifest supplied by the caller. Each
manifest row has one canonical library name and zero or more aliases. Names
are compared exactly and case-sensitively. The input's dependency order is
preserved, while repeated `DT_NEEDED` names are reported once.

Each report row is `resolved`, `missing`, or `ambiguous`. A resolved row
contains its index into the original manifest. An ambiguous row retains the
sorted manifest indexes that claimed the name; the resolver never silently
chooses one. The limits bound the number of dependency names, manifest rows,
total manifest spellings, and bytes per declared name. Cancellation is checked while scanning metadata
and the manifest.

The helper only reads already validated ELF metadata and caller-owned strings.
It does not interpret `$ORIGIN`, normalize paths, search directories, open a
dependency, or execute loader policy. Callers remain responsible for choosing
and validating the manifest's backing libraries before resolving symbols.
