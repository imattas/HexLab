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

An opt-in overload accepts an `ElfLibrarySearchContext` and manifest rows may
then include an explicit candidate `path`. It selects `DT_RUNPATH` when that
tag is present; otherwise it uses `DT_RPATH`. Direct dependencies are checked
in the encoded directory order, and the first directory containing a
name/alias-matching candidate wins. Multiple supplied providers in that
directory remain ambiguous. Candidates without paths cannot satisfy a
search-path match. If neither dynamic tag is present, exact-name manifest
resolution is retained.

Only `$ORIGIN` and `${ORIGIN}` are expanded, using the directory of the
explicit absolute importer path in the context. The operation uses bounded,
lexically normalized ELF-style slash paths and performs no filesystem access.
Malformed/empty entries, unsupported variables, relative importer/provider
paths, and configured path/entry limit excesses are reported. `DT_RUNPATH`
applies only to this importer's direct `DT_NEEDED` rows; it is not inherited by
children. In accordance with the documented precedence rule, `DT_RPATH` is
ignored whenever `DT_RUNPATH` exists. The result retains whether a match came
from RPATH or RUNPATH and the winning directory.

This is deliberately an offline candidate-order model, not a system loader:
`LD_LIBRARY_PATH`, secure-execution rules, loader caches, default directories,
hardware-capability directories, symlink traversal, namespaces, and actual
file validation are not modeled. It never opens candidate paths or chooses
among duplicate supplied providers.
