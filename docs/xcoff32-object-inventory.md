# Bounded XCOFF32 object inventory

`inspect_xcoff32_object` in `hexlab/loaders/xcoff32.hpp` inventories big-endian
AIX relocatable objects with magic `0x01df`. Callers can inspect an archive
member without copying its payload by passing the storage returned by
`open_ar_member`. The public API complements the existing XCOFF32 archive
symbol summary and [XCOFF64 inventory](xcoff64-object-inventory.md). Ordinary
relocation records are retained as metadata by the CLI inspect command.

The result retains file flags, timestamp, symbol-slot count and table offset,
string-table byte size, and the 40-byte section headers' names, flags, addresses,
sizes, file offsets and relocation/line counts. Primary symbol rows retain their
original slot, value, section number, raw type, storage class and auxiliary count.
Names are decoded for C_EXT, C_HIDEXT, C_WEAKEXT and C_STAT, from either the
eight-byte inline field or the string table. A zero string offset represents an
empty name. Other classes' names remain absent because they may use debug data.
Auxiliary slots are skipped after checking their declared extent.

Reads, retained record storage and decoded names share a configurable metadata
budget (256 MiB by default). Limits also bound section count (4096), symbol slots
(one million) and each decoded name (4096 bytes). Name scans stop at that limit.
The reader checks cancellation before and after storage reads and during section
and symbol traversal, checks complete reads and table extents, and maps allocation
failures to resource-limit errors. The string table may be absent when names are
inline; when present, empty tables (size at most four bytes) are accepted. It
checks ordinary 10-byte relocation and 6-byte line-number table extents. Ordinary
10-byte relocation rows are decoded into virtual address, zero-based symbol
slot, raw `r_rsize`/`r_rtype` bytes and record file offset. A one-million-row
aggregate limit bounds retained relocations, in addition to the shared 256 MiB
metadata budget. The decoder checks cancellation, complete table extents,
symbol-slot range and primary-slot membership (auxiliary slots are rejected),
that each address is within the section relative to `s_paddr`, and ascending
address order. The CLI displays each validated row with its section byte offset,
symbol name when available, raw type and known name, bit width, signed flag and
instruction-modified flag. This is metadata display only; no relocation is
applied. Line-number rows remain extent-checked only. Section
type flags determine whether raw data is BSS/TBSS; names are only metadata.
A zero raw-data pointer denotes absent raw data, including in a nonempty section.

The subset rejects executable (`F_EXEC`) objects, optional headers, deleted
section headers and overflow sections/count sentinels. Loader-section payloads
and their embedded loader relocation tables remain uninterpreted. Line-number
rows are extent-checked only. It does not
validate overlap between payload tables, decode auxiliary csect records,
interpret csect relocation semantics or relocation arithmetic, decode line
records, resolve symbols beyond displaying names for validated slots, apply
relocations, or produce linked output. No runtime tests were
added or run for this slice. This is
partial structural inspection, not full XCOFF support or verification of
archive linking capability.

`load_xcoff32_executable` provides a separate linked-image slice for big-endian
XCOFF32 executables with `F_EXEC` and the standard 72-byte AIX auxiliary
header. It maps `STYP_TEXT`, `STYP_DATA`, `STYP_BSS`, `STYP_TDATA`, and
`STYP_TBSS` by each section's declared virtual address. Initialized sections
map their exact file-backed extent; BSS/TBSS map as zero-fill. The auxiliary
header entry must point into initialized executable text. A loader section is
extent checked but uninterpreted, and makes metadata explicitly incomplete
with a diagnostic. Loader relocations, import binding, AIX TOC initialization,
other section types, and process runtime behavior remain unsupported. This is
a mapped linked image for static inspection, not an AIX execution environment.
Automatic open detects `F_EXEC` XCOFF32 files and routes them through this
loader; relocatable objects are separately identified and rejected with an
object-specific message. AIX archive magic is detected first and continues to
use the archive member workflow. CLI image commands also accept
`--format xcoff32` for an explicit selection.

Record layouts and section/name rules follow IBM's [AIX XCOFF object file
format](https://www.ibm.com/docs/en/aix/7.3.0?topic=formats-xcoff-object-file-format)
and LLVM's [XCOFF object structures](https://llvm.org/doxygen/XCOFFObjectFile_8h_source.html).
