# PE COFF symbol tables

`read_pe_coff_symbols(const LoadedImage&, std::stop_token)` reads the optional
COFF symbol table referenced by the PE COFF header. The result is separate
from ordinary PE imports and exports because the COFF table is stored outside
the mapped image and is commonly absent from release binaries.

Each primary symbol includes its short or string-table name, value, signed
section number, type, storage class, raw symbol index, and source file offset.
Auxiliary 18-byte records are retained with their owning primary symbol, so
the iterator correctly skips them without losing the original records.
Section-relative values are mapped to an RVA only when the section number is
valid and the value is inside the section's virtual/raw extent.

The parser validates the header, record-array extent, string-table extent,
long-name offsets and terminators, and auxiliary counts. It caps the symbol
record count at one million, primary symbols at 262,144, the string table and
aggregate decoded name bytes at 16 MiB, and a single name at 64 KiB. Cancellation
is checked while traversing symbols. A missing table returns an empty result.

For external/static symbols with the COFF function-derived type, the first
auxiliary record is decoded as a function definition only when its nonzero
`TotalSize` lies wholly inside the symbol's executable, file-backed section.
The resulting size and auxiliary-record file offset flow into PE metadata,
the bounded CLI summary, and desktop COFF symbols table. Malformed or
non-executable extents remain available as raw auxiliary bytes and are not
presented as function ranges. `IMAGE_SYM_CLASS_WEAK_EXTERNAL` symbols require
exactly one auxiliary record. The reader exposes its `TagIndex`, fallback
symbol name, and search characteristic (`NOLIBRARY`, `LIBRARY`, `ALIAS`, or
`ANTI_DEPENDENCY`) after validating that the index selects another primary
symbol record rather than an auxiliary record or itself. Unknown search
characteristics and invalid fallback indices reject the COFF symbol table.
This reports the COFF relationship; it does not perform weak-symbol library
search or object-file linking. Other auxiliary variants, including section
definitions, remain opaque. This does not synthesize object-file function
boundaries or load external object files or PDBs.
