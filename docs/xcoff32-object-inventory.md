# Bounded XCOFF32 object inventory

`inspect_xcoff32_object` in `hexlab/loaders/xcoff32.hpp` inventories big-endian
AIX relocatable objects with magic `0x01df`. Callers can inspect an archive
member without copying its payload by passing the storage returned by
`open_ar_member`. The public API complements the existing XCOFF32 archive
symbol summary and [XCOFF64 inventory](xcoff64-object-inventory.md); it is not
wired into the CLI relocation audit.

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
failures to resource-limit errors. It checks ordinary 10-byte relocation and
6-byte line-number table extents without reading or decoding the rows. Section
type flags determine whether raw data is BSS/TBSS; names are only metadata.
A zero raw-data pointer denotes absent raw data, including in a nonempty section.

The subset rejects executable (`F_EXEC`) objects, optional headers, deleted
section headers, overflow sections/count sentinels, and loader relocation rows.
It does not validate overlap between payload tables, decode auxiliary csect
records, validate relocation symbol targets or arithmetic, decode line records,
resolve symbols, apply relocations, or produce linked output. No runtime tests
were added or run for this slice; the production loader target was compiled.
This is partial structural inspection, not full XCOFF support or verification
of archive linking capability.

Record layouts and section/name rules follow IBM's [AIX XCOFF object file
format](https://www.ibm.com/docs/en/aix/7.3.0?topic=formats-xcoff-object-file-format)
and LLVM's [XCOFF object structures](https://llvm.org/doxygen/XCOFFObjectFile_8h_source.html).
