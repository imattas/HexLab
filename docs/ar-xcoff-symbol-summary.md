# Bounded XCOFF64 archive symbol summaries

`summarize_coff_ar_member` recognizes XCOFF64 relocatable objects inside an
archive and supplies their external symbol names to the existing fixed-point
archive member selector. The parser checks the XCOFF64 file header, section
table, symbol-table extent, string-table size, per-name termination, auxiliary
symbol row counts, and configured metadata/section/symbol/name limits before
returning a summary.

The summary currently considers `C_EXT` entries. A nonzero section number is a
definition; an undefined external with a nonzero value is treated as common;
and an undefined external with a zero value becomes an unresolved reference.
Repeated names are de-duplicated, and a definition in the same member removes
an undefined reference of the same name. `C_WEAKEXT` records and other storage
classes are omitted so they cannot pull an archive member based on ambiguous
weak-resolution policy.

This is symbol selection metadata only. It does not resolve XCOFF relocations,
combine csects, interpret auxiliary records beyond their row counts, or link
XCOFF objects. XCOFF32 is explicitly unsupported. The summarized names come
from the XCOFF64 string table; alternate `.debug`-section symbol names are not
handled. Archive-level AIX symbol index parsing remains a separate mechanism.
