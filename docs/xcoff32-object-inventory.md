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
(one million), aggregate line-number rows (one million, `max_line_numbers`), and
each decoded name (4096 bytes). Name scans stop at that limit.
The reader checks cancellation before and after storage reads and during section
and symbol traversal, checks complete reads and table extents, and maps allocation
failures to resource-limit errors. The string table may be absent when names are
inline; when present, empty tables (size at most four bytes) are accepted. It
checks ordinary 10-byte relocation and 6-byte line-number table extents.
XCOFF32 `STYP_OVRFLO` headers are resolved by their one-based target section
number independent of header order. For paired `0xffff` primary counts, the
true counts in `s_paddr` and `s_vaddr` replace both primary counts. This accepts
line-only overflow, relocation-only overflow, and overflow in both tables,
including a true count of exactly 65,535. At least one table must exceed 65,534.
Both overflow target fields must identify the same primary section, with matching
table offsets and zero overflow-header size/data pointer. Missing, duplicate,
orphaned, mismatched, truncated and over-limit records are rejected before table
decoding. Both expanded counts are exposed as 32-bit values; line-number rows
remain extent-checked only. Overflow headers retain their original section slots
and do not become image mappings, so symbol section numbers keep their meaning.
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

The subset rejects executable (`F_EXEC`) objects, optional headers and deleted
section headers. Loader-section payloads
and their embedded loader relocation tables remain uninterpreted. Line-number
rows are extent-checked only. It does not validate overlap between payload
tables or decode line records. Csect auxiliary records are decoded by the
relocatable loader as described below; archive member selection and external
library binding remain unsupported.

`load_xcoff32_relocatable` maps common `STYP_TEXT`, `STYP_DATA`, `STYP_BSS`,
`STYP_TDATA`, and `STYP_TBSS` sections into deterministic synthetic 32-bit
addresses beginning at `0x10000`, aligning each nonempty section to at least a
page and to the strongest csect alignment declared within it. The final
auxiliary record for C_EXT, C_WEAKEXT, and C_HIDEXT symbols is decoded for
csect length, alignment, type, and storage-mapping class. Defining csects must
fit within their section, and their original section-relative offsets must
satisfy declared alignment. The loader preserves the input section/csect order
and offsets; it does not reorder csects, merge sections, implement archive
selection, or perform AIX's full link-edit layout.
Initialized bytes are copied into bounded owned storage and BSS/TBSS are
zero-filled. Section permissions reflect text versus writable data. No entry
point is inferred. Defined symbols in mapped sections and absolute symbols are
resolved. Undefined external references bind by exact name to a unique
definition in the same object; duplicate strong definitions and ambiguous
weak-only definitions remain unresolved. No archive extraction or external
library binding is performed. The loader applies checked full-field 8-, 16-,
and 32-bit `R_POS`, `R_NEG`, and `R_REL` relocations, plus data-field `R_TOC`
displacements relative to a unique `XMC_TC0` csect anchor. `R_REF` is validated
but has no patch. Instruction-modified fields, bit fields, TOC instruction
encodings, TLS, and other relocation kinds remain unapplied and mark metadata
incomplete. This is an analysis view, not a complete AIX link: csects are not
reordered, archive members and libraries are not selected, and runtime
binding/startup are not implemented.

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

## 2026-11-02 overflow validation scope

The overflow resolver uses separate pending/resolved state instead of treating
65,535 as a marker after expansion. Ordinary and expanded table counts share
aggregate limits and checked 64-bit extent calculations. Relocation rows still
validate primary symbol-slot membership, section-relative addresses and order.
The primary/overflow pointer equality checks follow IBM's [AIX 7.1 overflow
header definition](https://www.ibm.com/docs/en/aix/7.1.0?topic=formats-xcoff-object-file-format),
which requires both `s_relptr` and `s_lnnoptr` to match the primary header.
The new line-row limit also applies to ordinary counts across all sections.
Windows Debug (MSVC 19.44) and Ubuntu 24.04 WSL Debug (Clang 18.1.3)
`hexlab_loaders` builds passed with `BUILD_TESTING=OFF`; no tests or GitHub CI
ran. WSL built an ext4 snapshot of the isolated checkout after Windows-mounted
source reads stalled; SHA-256 hashes of both changed C++ files matched.
Linked-executable overflow sections, source-line decoding, overlapping-table
validation, archive/library binding and full AIX linking remain unsupported.
