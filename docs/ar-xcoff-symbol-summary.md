# Bounded XCOFF32/64 archive symbol summaries

`summarize_coff_ar_member` recognizes XCOFF32 and XCOFF64 relocatable objects
inside an archive and supplies their external symbol names to the existing
fixed-point archive member selector. The parsers check their respective file
headers, section tables, symbol-table extent, string-table size, per-name termination, auxiliary
symbol row counts, and configured metadata/section/symbol/name limits before
returning a summary.

The summary currently considers `C_EXT` entries. A positive section number or
an absolute section number (-1) is a definition; an undefined external with a
nonzero value is treated as common;
and an undefined external with a zero value becomes an unresolved reference.
Repeated names are de-duplicated, and a definition in the same member removes
an undefined reference of the same name. `C_WEAKEXT` records and other storage
classes are omitted so they cannot pull an archive member based on ambiguous
weak-resolution policy.

This is symbol selection metadata only. It does not resolve XCOFF relocations,
combine csects, interpret auxiliary records beyond their row counts, or link
XCOFF objects. XCOFF32 names can be inline or string-table entries; XCOFF64
names come from its string table. Alternate `.debug`-section symbol names are
not handled. Both parsers reject optional-header objects and F_EXEC images.
Archive-level AIX symbol index parsing remains a separate mechanism.

For structural metadata beyond the strong-symbol selection summary, use the
[XCOFF32 object inventory](xcoff32-object-inventory.md) or the
[XCOFF64 object inventory](xcoff64-object-inventory.md). The XCOFF32 inspector
retains bounded section and primary-symbol metadata but does not decode or
apply relocation rows. XCOFF linking remains unsupported.
