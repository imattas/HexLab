# PE inspection in CLI and desktop

Project `inspect` and ordinary CLI `inspect` print the PE optional-header data
directory table as deterministic `#index rva|file:location size=...` rows. The
table is limited to the 16 standard PE directory slots. Parsed bound imports
are printed with their module timestamp and source file offset; forwarder
references are indented beneath the owning module and retain their own source
offset and timestamp. Absent bound-import data produces no section.
The CLI also summarizes parsed PE debug-directory records; see
[reproducibility and extended DLL-characteristic records](pe-debug-repro-characteristics.md)
for type 16/type 20 payload handling.

The PE optional-header checksum field is retained with its file offset and
compared with a streaming checksum calculation over the input. The calculation
zeroes the checksum field, folds little-endian 16-bit words, and adds the file
length. The CLI reports the stored value and status (`matches`, `mismatch`,
`unset`, or `not-checked-limit`). Inputs above 512 MiB retain the stored field
but skip calculation. A checksum mismatch is a warning and does not prevent
mapping; this checksum is not an Authenticode signature or trust check. The PE
field and Windows validation use are described in Microsoft's
[`IMAGE_OPTIONAL_HEADER`](https://learn.microsoft.com/windows/win32/debug/pe-format#optional-header-windows-specific-fields-image-only)
documentation; the calculation is exposed by
[`CheckSumMappedFile`](https://learn.microsoft.com/windows/win32/api/imagehlp/nf-imagehlp-checksummappedfile).

Section mapping rejects ambiguous layouts before publishing an image: each
nonempty section's virtual extent must be disjoint from the header mapping and
other sections, and each nonempty raw range must fit the input and be disjoint
from the headers and other section data. This avoids silently choosing which
section supplies bytes when malformed images describe overlapping mappings.

The Global Ptr directory entry (index 8) is retained as an RVA when present.
Its `Size` field must be zero; the CLI reports its RVA and preferred-base VA.
HexLab does not initialize an architecture's global-pointer register or
interpret architecture-specific small-data addressing.

When the COFF header supplies both a symbol-table file offset and a nonzero
record count, the loader parses the bounded COFF symbol table and following
string table. Primary symbols retain their name, raw value, section number,
type, storage class, auxiliary-record count, and source file offset. A symbol
gets a navigable image address only when its positive section number exists
and its value falls inside that section's mapped extent. For an external or
static function-typed symbol, the first auxiliary record contributes a
function size only when the range is nonempty and wholly inside the executable,
file-backed section; CLI output includes that size and the auxiliary record's
file offset. The CLI and desktop COFF symbols table show validated function
sizes. Weak external auxiliary records are decoded through the loader API as
described in [PE COFF symbol tables](../libs/loaders/docs/pe-coff-symbols.md);
section-definition auxiliary records on static, null-typed, zero-valued section
symbols with exactly one auxiliary row are decoded as well. The metadata keeps
the declared section length, relocation and line-number counts, COMDAT checksum,
associated section index (including its high word), raw selection value, and
auxiliary-record file offset. CLI output labels the standard COMDAT selection
values while preserving unknown values numerically. This is descriptive
metadata; it does not perform COMDAT selection or linking. Other auxiliary
variants remain opaque. Field layout and COMDAT selection values follow
Microsoft's [PE/COFF format reference](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#auxiliary-format-5-section-definitions).
The symbol record count
is limited to one million, primary symbols to
262,144, the string table and aggregate decoded names to 16 MiB, and each
name to 65,536 bytes. CLI output and the
desktop **COFF symbols** page display up to 4,096 rows; activating a row goes
to its mapped address or, when unresolved, its file record. Most linked images
omit this table. Malformed or oversized symbol metadata marks PE metadata
partial and adds a diagnostic while preserving the already mapped image;
other PE metadata and explicit rebasing continue through their normal paths.
COFF bigobj and auxiliary-record-specific semantics are not decoded.

When exception metadata is present, CLI inspection prints bounded AMD64 and
ARM64 runtime-function rows with source file offsets. AMD64 handler payloads
identify their handler and payload RVA; decoded FH3 summaries include state,
try-block, IP-map, and exception-specification counts, while FH4 summaries
include header flags, IP states, unwind rows, try blocks, catch targets, and
diagnostics. Per-row FH3/FH4 records retain their source offsets in the output.
The flattened exception output is capped at 1,024 rows, and each existing
loader metadata budget and malformed/unsupported status still applies. This is
inspection only: CLI output does not dispatch exceptions or run handler code.

PE debug directory entries are retained in `ImageMetadata::pe->debug_directories`
for every recognized debug type. Each row contains timestamp, version, type,
payload size, RVA, raw file offset, directory-entry source spans, and payload
file spans. Unknown debug payload formats remain opaque and are not copied.
RSDS CodeView records expose the GUID, age, and PDB path; NB10 records expose
their legacy signature, timestamp, age, and path. Both are retained in
`codeview` and printed by CLI inspection. PDB binding requires the exact RSDS
GUID+age identity; NB10 fields are not compared as a GUID. Invalid payload
locations make PE metadata partial while leaving the mapped image available.

`IMAGE_DEBUG_TYPE_PDB_CHECKSUM` payloads retain their bounded printable-ASCII
algorithm name, digest bytes, and payload provenance in `pdb_checksums`. A
caller-selected local PDB is checked against every retained SHA256 digest
before parsing or binding; any mismatch rejects that candidate. Other
algorithm names are preserved for inspection but are not verified. The CLI
shows the algorithm, digest, source offset, and local verification result.

Recognized POGO (`IMAGE_DEBUG_TYPE_POGO`) payloads additionally expose their
LTCG/PGU signature and bounded code/data block names, RVAs, sizes, and source
provenance; see [PE POGO debug records](pe-pogo.md).

The desktop metadata notebook adds a **PE** page with separate virtual tables
for data directories, bound-import records, load configuration, and
certificate-table records. Directory activation navigates
to the mapped RVA or file offset. Bound module and forwarder rows navigate to
the first file span of their source descriptor. The view caps its flattened
bound-import display at 4,096 rows and uses virtual list rendering so large
tables do not allocate one widget per record.

The **Certificates** page lists parsed `WIN_CERTIFICATE` headers and the raw
payload file spans from the Security directory. Certificate payloads remain
opaque; HexLab does not verify Authenticode signatures or trust chains.

The PE **Load config** page summarizes the PE32 SafeSEH table and lists each
validated handler RVA with the file offset that supplied its entry. Selecting a
handler navigates to its mapped address. PE32+ load-config records do not have
SafeSEH fields; malformed or out-of-image handler tables make PE metadata
partial instead of presenting unvalidated rows.

Directory locations and bound-import records are read from the immutable
`ImageMetadata` attached to the opened project snapshot. The UI does not
reparse the input bytes or duplicate the parser's records.
