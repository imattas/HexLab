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

This reader preserves auxiliary data as bytes; it does not decode each COFF
auxiliary record variant or synthesize function boundaries. It also does not
load external object files or PDBs.
