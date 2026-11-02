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
checks ordinary 10-byte relocation and 6-byte line-number table extents.
XCOFF32 `STYP_OVRFLO` headers are resolved by their one-based target section
number independent of header order. For paired `0xffff` primary counts, the
true relocation count in the overflow header's `s_paddr` is accepted, bounded,
and used to validate and decode the primary section's relocation rows. The
overflow record must match the primary relocation and line-table offsets and
must report zero line-number rows; line-number overflow remains unsupported.
Orphaned, duplicate, mismatched, or over-budget overflow headers are rejected.
The expanded relocation count is exposed as a 32-bit value in the result.
Ordinary 10-byte relocation rows are decoded into virtual address, zero-based symbol
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
section headers and line-number overflow. Loader-section payloads
and their embedded loader relocation tables remain uninterpreted. Line-number
rows are extent-checked only. It does not validate overlap between payload
tables, decode auxiliary csect or line records, implement csect linking,
archive member selection, or external library binding.

`load_xcoff32_relocatable` maps common `STYP_TEXT`, `STYP_DATA`, `STYP_BSS`,
`STYP_TDATA`, and `STYP_TBSS` sections into deterministic synthetic 32-bit
addresses beginning at `0x10000`, page-aligning each nonempty section.
Initialized bytes are copied into bounded owned storage and BSS/TBSS are
zero-filled. Section permissions reflect text versus writable data. No entry
point is inferred. Defined symbols in mapped sections and absolute symbols are
resolved; external/common or unsupported-section targets remain unresolved
diagnostics. The loader applies only full-byte `R_POS`, `R_NEG`, and `R_REL`
fields of 8, 16, or 32 bits with checked field range. `R_REF` is validated but
has no patch. Instruction-modified fields, bit fields, TOC/TLS, and other
relocation kinds remain unapplied and mark metadata incomplete. This is an
analysis view, not an AIX link: csect alignment, TOC setup, archive extraction,
import libraries and runtime binding are not implemented.

Automatic open now routes both executable and relocatable XCOFF32 inputs to the
format loader. `hexlab_cli inspect object.o` (or
`hexlab_cli inspect object.o --format xcoff32`) maps supported sections for
normal image inspection and disassembly. Structural inventory remains
available through `hexlab_cli xcoff32 inspect object.o`. The normal project
workflow can import the same object with
`hexlab_cli project create object.hxproj --input object.o`; subsequent project
inspection and disassembly commands operate on the synthetic mapped view.

`load_xcoff32_executable` provides a separate linked-image slice for big-endian
XCOFF32 executables with `F_EXEC` and the standard 72-byte AIX auxiliary
header. It maps `STYP_TEXT`, `STYP_DATA`, `STYP_BSS`, `STYP_TDATA`, and
`STYP_TBSS` by each section's declared virtual address. Initialized sections
map their exact file-backed extent; BSS/TBSS map as zero-fill. The auxiliary
header entry and entry section must identify initialized executable text. When
present, the loader section's version, symbol table, relocation table, import
file ID strings, and symbol name strings are bounded and decoded. Exported
loader symbols are retained in generic export metadata; their `ordinal` field
contains the corresponding XCOFF loader symbol reference index (`row + 3`).
The implicit section references use separate indexes and are not export rows.
Imported symbols are identified by `l_smtype` and their import file ID, then
reported as unresolved diagnostics. Loader relocation rows validate the
section, virtual address, and implicit/explicit symbol index, then each is
reported as unapplied. Diagnostics expand at most 64 imports and 128 loader
relocations, with a count for the remainder. No external AIX library resolver
is provided, so imports cannot be bound and loader relocations are never
applied. The auxiliary header TOC anchor and section are checked and surfaced
as an informational diagnostic; HexLab does not initialize the PowerPC `r2`
register or emulate AIX process startup. Other section types remain unsupported.
This is a mapped linked image for static inspection, not an AIX execution
environment.
Automatic open detects `F_EXEC` XCOFF32 files and routes them through this
loader. AIX archive magic is detected first and continues to
use the archive member workflow. CLI image commands also accept
`--format xcoff32` for an explicit selection.

Record layouts and section/name rules follow IBM's [AIX XCOFF object file
format](https://www.ibm.com/docs/en/aix/7.3.0?topic=formats-xcoff-object-file-format),
including its `.loader` table definitions. The fixed record layouts are also
cross-checked against LLVM's [XCOFF object structures](https://llvm.org/doxygen/XCOFFObjectFile_8h_source.html).
