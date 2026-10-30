# Windows Minidump analysis

HexLab recognizes the `MDMP` signature during automatic format detection and
opens a durable `minidump` load recipe. The loader maps captured process memory
at its recorded virtual addresses, so ordinary disassembly and byte views can
inspect memory captured by the dump.

The loader reads the bounded stream directory and supports standard
`SystemInfo`, `MemoryList`, `Memory64List`, `MemoryInfoList`, `ModuleList`,
`ThreadList` and `ThreadExList`, `ThreadNames`, `HandleData`, `UnloadedModuleList`, and `Exception`
streams.
The optional `TokenStream` (type 19) validates its extensible list and per-token
record sizes, retaining token IDs, handle values, record/payload file offsets,
and payload lengths. Token payload bytes remain opaque because they carry
security-token data with OS-specific interpretation; the CLI reports only
bounded structural metadata. List sizes and retained records share the parser's
64 MiB metadata budget. See the Windows SDK `MINIDUMP_TOKEN_INFO_LIST` and
`MINIDUMP_TOKEN_INFO_HEADER` definitions for field layout.
The optional `CommentStreamA` and `CommentStreamW` streams (10 and 11) are
retained with their original stream type, declared size, file offset, and up to
4,096 source bytes. Larger payloads keep the original extent plus a bounded
prefix and mark metadata incomplete. The CLI prints a 64-byte hex preview.
For `CommentStreamW`, it also prints decoded UTF-8 when the captured prefix is
complete UTF-16LE with valid surrogate pairs. A malformed or odd-length prefix
keeps its raw bytes, omits decoded text, and adds a diagnostic; a valid prefix
of a larger truncated stream is shown with the existing truncation marker.
`CommentStreamA` remains raw because its ANSI code page is unspecified.
Application-specific suffixes remain opaque. CLI output marks decoded text as
truncated when only a prefix was captured. Each standard comment stream may
appear at most once. The stream meanings follow Microsoft's
[`MINIDUMP_STREAM_TYPE`](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidump_stream_type)
enumeration.
Breakpad Linux streams `MD_LINUX_CPU_INFO` (0x47670003), `MD_LINUX_LSB_RELEASE`
(0x47670005), `MD_LINUX_CMD_LINE` (0x47670006), `MD_LINUX_ENVIRON` (0x47670007),
and `MD_LINUX_MAPS` (0x47670009) retain a byte-for-byte prefix of at most 1 MiB
per stream, with declared size and source file offset. The CLI shows an escaped
96-byte preview; NUL separators and platform-specific content are preserved.
Oversized streams are marked truncated. `MD_LINUX_MAPS` additionally parses
valid `/proc/<pid>/maps` lines into virtual start/end, permissions, file offset,
device major/minor, inode, optional raw path, and line source offset. Rows are
bounded to 131,072 and 4,096 bytes per line, and must be sorted without
overlapping ranges. Invalid lines are skipped while the original bytes remain
available and the map list is marked incomplete. These entries describe
captured process mappings only; they do not create or alter minidump memory
regions or permissions. Breakpad Linux `auxv` (0x47670008) is retained
byte-for-byte and decoded as native-width type/value pairs for x86/ARM
(4-byte words) and AMD64/ARM64 (8-byte words). Each decoded pair keeps its
file offset. A valid list ends with the zero `AT_NULL` type/value pair;
malformed, unterminated, truncated, over-limit, or architecture-ambiguous
lists remain inspectable as raw bytes and are marked incomplete. Auxiliary
vector type numbers and values are reported as raw hexadecimal values because
their meanings are architecture-specific and can include process addresses.
DSO-debug streams remain opaque.
The stream IDs follow Breakpad's
[`minidump_format.h`](https://chromium.googlesource.com/chromiumos/platform/google-breakpad/+/9ebdd71b16596258703a7fcda5f9afc887f09972/src/google_breakpad/common/minidump_format.h).
`ThreadExList` retains each thread's backing-store virtual address, size, and
file RVA, with overflow and file-extent validation. The CLI and desktop thread
inspector expose this descriptor; its bytes are not independently mapped into
the image.
`SystemInfo` also retains processor level/revision, Windows product type,
version/build/platform/suite values, the bounded service-pack string, and the
24 architecture-specific CPU-info bytes with their source offset. For Intel
x86 and AMD64 architecture values, the loader additionally decodes the
documented x86 union as a 12-byte vendor ID, CPUID leaf-1 EAX version and EDX
feature words, and the AMD extended-feature word. These fields keep their
source offset and are also retained in the raw byte array. Feature words remain
raw bitfields; the AMD word is not treated as valid only for a particular vendor
and no capability claims are inferred. Other architecture union layouts remain
raw because their interpretation differs. The CLI shows a bounded escaped
vendor ID and hexadecimal words. See Microsoft's
[`MINIDUMP_SYSTEM_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_system_info)
definition for the field meanings.
The optional `HandleData` stream accepts the 32-byte and 40-byte descriptor
layouts, validates the header/table sizes and reserved fields, and retains
handle values, attributes, granted access, counts, optional type/object names,
and descriptor/string provenance. Version-2 object-information RVAs are
retained after validating their initial header extent; object-specific chains
and payload semantics remain opaque. The CLI prints at most 256 rows. See
Microsoft's [`MINIDUMP_HANDLE_DATA_STREAM`](https://learn.microsoft.com/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_handle_data_stream),
[`MINIDUMP_HANDLE_DESCRIPTOR`](https://learn.microsoft.com/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_handle_descriptor),
and [`MINIDUMP_HANDLE_DESCRIPTOR_2`](https://learn.microsoft.com/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_handle_descriptor_2)
definitions for field meanings.
Module and thread names are decoded from bounded UTF-16 strings. Their retained
UTF-8 byte lengths, rather than only their on-disk UTF-16 lengths, are charged
to the shared metadata budget before the output string is allocated. Unloaded module
records retain image base, size, checksum, timestamp, name, and source file
offset; they describe modules that were unloaded before capture and are not
mapped into the captured image. Their header and extensible entry size are
validated and bounded. Thread-name rows retain their source
record and string offsets and are matched by thread ID. Thread IDs must be
nonzero and unique within `ThreadList`; thread-name IDs must also be nonzero
and unique within `ThreadNames`. Name rows without a matching thread context
remain in metadata and are not attached to another thread. Duplicate standard
`ThreadNames` streams are rejected.
An exception context is retained independently of the thread context; neither
is substituted for the other.

The optional `MiscInfo` stream exposes the base process ID and process timing
fields. `Flags1` gates each field group: the process ID bit controls the ID,
the process-times bit controls creation, user, and kernel times, and the
processor-power bit controls the five `MINIDUMP_MISC_INFO_2` fields. The power
group is decoded only when the declared stream prefix reaches all five 32-bit
values (offsets 24 through 40); partial groups add a diagnostic and expose no
power values. The parser copies at most the 44-byte recognized prefix into its
shared metadata budget and leaves the original stream available in the raw
directory. The API retains the declared stream size and each field's exact
file offset. Clock values are reported in MHz; idle states remain raw SDK
values. Times remain the raw 32-bit seconds values defined by Windows. CLI
output prints available values and field provenance; the desktop Minidump
summary also shows process ID and current processor frequency when present.
These fields are independent of the later MiscInfo5 XSTATE feature map. See Microsoft's
[`MINIDUMP_MISC_INFO_2`](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_misc_info_2)
definition for field meanings and validity flags.
See Microsoft's [`MINIDUMP_MISC_INFO`](https://learn.microsoft.com/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_misc_info)
definition for field and flag semantics.

The optional `ThreadInfoList` stream (type 17) retains raw dump flags/error and
exit status, creation/exit/kernel/user times, thread start address, affinity,
and each record's source offset. Times remain the raw 100-nanosecond values in
the Windows structure. Entry IDs must be nonzero and unique; extensible header
and record sizes are bounded to 4 KiB, records to 65,536, and retained rows
share the 64 MiB metadata budget. The CLI prints at most 256 rows. The thread
info table remains independent from `ThreadList` and `ThreadNames`; no join or
thread-state inference is made. Unknown dump flag bits remain visible as raw
metadata. See Microsoft's
[`MINIDUMP_THREAD_INFO_LIST`](https://learn.microsoft.com/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_thread_info_list)
and [`MINIDUMP_THREAD_INFO`](https://learn.microsoft.com/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_thread_info)
definitions for field and flag semantics.

Module CodeView records recognize bounded RSDS and NB10 identities. RSDS
retains the 16-byte PDB GUID and age; NB10 retains its timestamp and age. Both
retain the NUL-terminated PDB path as raw bytes because the format does not
identify a character encoding. The path is capped at 4,096 bytes, charged to
the metadata budget, and shown in the CLI module summary. Unknown CodeView
signatures remain opaque through the original record RVA and size.

Each `ModuleList` row also retains its fixed 13-DWORD `VS_FIXEDFILEINFO` value
and the source file offset. The CLI presents file and product version tuples
only when the signature is `0xFEEF04BD`; records with another signature remain
available as raw version fields but are labelled unrecognized. This uses the
fixed 52-byte field already contained in each validated 108-byte module row,
so it adds no separate RVA reads or unbounded string handling.

Local Minidump PDB sidecars can be supplied explicitly or found beside the dump
and in up to 16 caller-provided search directories. Search is bounded to 128
distinct files. Module CodeView records are matched only by an exact RSDS
GUID+age; NB10 timestamps are not treated as PDB identities. One global PDB may
bind every module row with the same exact identity. Bound module metadata records
the selected path, binding state, diagnostic, symbol count and bounded DBI
symbol rows. Symbol offsets remain section-relative because Minidump module
records do not contain the original PE section table. A missing or mismatched
sidecar is never presented as a match, and a truncated search is reported.
Selected candidate paths are persisted in the durable recipe so reopening the
project does not silently rerank adjacent files. The CLI and Minidump desktop
view show each module's binding state and retained symbol count.

Thread and exception register contexts use the SystemInfo architecture and
require a matching architecture family in `ContextFlags`. Unknown architectures
and mismatches retain raw evidence and diagnostics without guessing registers.
Each requested register group needs its complete meaningful byte range;
truncated groups are omitted while complete independent groups remain available.
The supported fixed little-endian Windows CONTEXT layouts are:

| Architecture | Captured register groups |
| --- | --- |
| x86 | Control (`ebp`, `eip`, `esp`, segments and flags), integer, segments, debug, legacy x87, and extended FXSAVE x87/XMM0-7/MXCSR. Extended storage takes precedence when both floating layouts are present. |
| AMD64 | Control (`rsp`, `rip`, segments and flags), integer, segments, debug, and fixed x87/XMM0-15/MXCSR floating storage. Both top-level and FXSAVE MXCSR copies are retained. When `CONTEXT_XSTATE` and the two 64-bit XSAVE bitmap fields are present, `xstate_bv` and `xcomp_bv` expose the in-use and compacted-layout bitmaps; only those 16 header bytes are required for these fields. In compacted format, an in-use non-legacy component missing from `xcomp_bv` marks the context partial; payloads remain opaque because compacted offsets and alignment cannot be established from the available feature map. With a validated MiscInfo5 map, AVX feature 2 decodes its 16 YMM upper 128-bit halves as `ymm0_hi` through `ymm15_hi` in standard layout. AVX-512 features 5, 6 and 7 decode K0-K7, the upper 256-bit portions of ZMM0-ZMM15, and ZMM16-ZMM31 as source-backed 64-bit or 128-bit rows; 128-bit chunks preserve their source bytes without synthesizing full ZMM values. Component tails remain opaque. Other non-legacy components remain opaque 16-byte chunks except CET user state (feature 11), whose two 64-bit values are decoded as `ia32_u_cet` and `ia32_pl3_ssp`. Classic AMX features 17/18 retain validated palette 0/1 configuration and palette 1 tile storage; see [AMX bounds](minidump-amx-state.md). |
| ARM32 | Control (`sp`, `lr`, `pc`, `cpsr`), integer R0-12, FPSCR and D0-31/Q0-15 aliases, and fixed breakpoint/watchpoint registers. |
| ARM64 | Control (`x29`, `x30`, `sp`, `pc`, `cpsr`), integer X0-28 with X18 retained only when explicitly requested by its separate flag, full or low/high partial NEON V-register storage, FPCR/FPSR when the low/full group is available, and fixed breakpoint/watchpoint registers. |
| Breakpad ARM64 (`processor_architecture=0x8003`) | Its packed legacy layout and 64-bit ContextFlags are decoded separately: integer/control group includes X0-X30, SP, PC and CPSR; floating group includes FPSR, FPCR and V0-V31. |

The CLI summaries and desktop context table label `0x8003` as **Breakpad
ARM64**, matching the separate packed-context decoder. This remains distinct
from Microsoft's ARM64 `SystemInfo` architecture value 12.

Public `MinidumpContext` metadata records decoded, partial, not-captured,
unsupported-architecture, architecture-mismatch, or malformed status; raw flags;
requested/decoded group masks; independent validity fields; source RVA and
original size; byte order; and a bounded captured prefix. Registers retain bit
width, exact little-endian bytes and absolute file offsets. The scalar `value`
is meaningful only through 64 bits; wider values use the byte vector. Raw x87
storage is retained without interpreting the floating value or stack tag state.
AMD64 FXSAVE error/data pointer fields are exposed as raw 64-bit storage slots
without inferring their execution-mode-dependent selector/pointer meaning.
ARM D/Q aliases share source bytes. Thread and exception records retain their
own file offsets as well as their original context descriptors. Missing
zero-size contexts remain absent. Nonempty null or out-of-file context extents
reject the input; in-range incomplete layouts remain inspectable with status
and diagnostics. Context issues also mark overall metadata incomplete.

Context reads retain at most 716 bytes for x86, 416 for ARM32, 1,232 fixed bytes
for AMD64 plus a 64 KiB bounded XSTATE extension when available,
912 for Microsoft ARM64, 796 for Breakpad ARM64, and 64 for unknown architectures. The full advertised source
extent is validated even when only a prefix is decoded. Decoding is capped at
4,096 contexts; later descriptors retain source extents with a global diagnostic.
Context allocations, register bytes and strings are charged to the 64 MiB
metadata budget. Stream, thread, memory and module counts remain independently
bounded. Thread/context processing checks cancellation between records. The CLI
summary lists at most 256 threads and modules, includes captured thread names,
prints wide register values from their captured bytes, and reports parsed PDB
identity metadata.

The legacy ARM64 layout follows the Breakpad `MDRawContextARM64_Old` format,
also described as `CONTEXT_ARM64_OLD` by [minidump-common](https://docs.rs/minidump-common/latest/minidump_common/format/struct.CONTEXT_ARM64_OLD.html).

When `MemoryInfoList` is present, captured regions are split at protection
boundaries and retain read, write, and execute permissions. If protection data
is absent, mapped bytes receive provisional read/write/execute permissions so
code remains inspectable, and metadata is marked incomplete. Known
permissions are granted only for `MEM_COMMIT` ranges; reserved or free ranges
remain mapped for captured-byte inspection but carry no read, write, or execute
access. `PAGE_NOACCESS` and `PAGE_GUARD` also suppress all access bits. The
captured region metadata also retains the allocation base and allocation
protection from each matching memory-information row; uncovered regions leave
those fields unavailable. These allocation fields are preserved as supplied and
do not affect the effective access permissions calculated from the row's current
state and protection. The
architecture map recognizes x86, AMD64, ARM, and ARM64. x86, AMD64 and ARM64
receive their corresponding decode modes; ARM remains mode-unknown because
module records do not establish ARM versus Thumb state. A mapped exception
address becomes the image entry.

AVX feature 2 stores the upper 128 bits of YMM0-YMM15 and is decoded as
`ymmN_hi` rows with per-register source offsets. The fixed XMM fields provide
the corresponding low halves, but HexLab does not synthesize combined 256-bit
YMM values. Component tails remain opaque. AVX-512 XSTATE features 5-7 use the
standard component layout: feature 5 retains K0-K7 as 64-bit rows; feature 6
retains each ZMM0-ZMM15 upper 256-bit portion as two source-backed 128-bit
rows; feature 7 retains ZMM16-ZMM31 as four 128-bit rows each. Required
component sizes are checked against 64, 512, and 1,024 bytes respectively, and
any extension tail remains opaque. The context model cannot represent a single
256- or 512-bit register row, so these parts are not combined with the fixed
XMM fields or AVX upper halves. No AVX-512 execution state semantics or CPU
feature checks are inferred. CET user-state feature 11 uses Microsoft's 16-byte
[`XSAVE_CET_U_FORMAT`](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/ns-wdm-_xsave_cet_u_format)
(the `IA32_U_CET` and `IA32_PL3_SSP` values); the registers preserve their
original eight-byte source ranges. `xstate_bv` reports which components are in use, while bit 63
of `xcomp_bv` identifies compacted layout. In compacted layout, an in-use
non-legacy component must also be present in the `xcomp_bv` component mask; an
inconsistent pair is retained with a diagnostic and partial context status.
HexLab does not infer compacted payload offsets or alignment from the standard
feature map, so it omits compacted component payloads. Legacy floating-point and SSE feature
IDs 0â€“1 remain in the fixed AMD64 context fields. Context XSTATE components
are included only when the MiscInfo5 feature table validates and the checked
XSAVE-relative range (`256 + feature offset`) is present in the original
context extent and the corresponding XSTATE_BV bit marks the component in use.
Classic AMX features 17/18 additionally decode structurally validated palette
0/1 TILECFG and palette 1 tile storage into source-backed rows. Exact component
sizes and disjoint extended-component ranges are required; unknown palettes or
missing configuration leave tile data opaque. See [AMX state bounds](minidump-amx-state.md)
for the supported layout, retained field widths and display limits.
Protection-key feature 9 decodes the exact eight-byte PKRU component into its
32-bit register and a separate four-byte reserved row, retaining both source
ranges. Other PKRU sizes remain opaque and mark the context partial. Component
9's PKRU identity follows Intel's [XSAVE feature-state definition](https://cdrdv2-public.intel.com/671436/253665-sdm-vol-1.pdf).
Unknown feature IDs are preserved. CET supervisor state (feature 12), ARM scalable state,
ARM64EC alternate context layouts,
WOW64 context-family substitution, architecture inference from bytes, and other
processor layouts are unsupported. Unsupported group flags yield a partial
context while preserving supported groups and original source extents; extended
state beyond the fixed prefix is not copied. No live register restoration,
stack reconstruction, unloaded-module reconstruction, matching PDB fetching,
or recovery of memory omitted from the dump is performed. Other Windows
processor architectures remain metadata without an instruction decoder.

## Desktop context inspection

`HandleOperationListStream` (18) additionally retains bounded Application
Verifier handle operations and up to 32 captured return-address slots per
record, with fixed-width decoding, source extents and bounded CLI reporting.
See [handle operation traces](minidump-handle-operations.md) for validation,
extension handling, resource limits and the distinction from live stack frames.

**Binary Metadata > Minidump** shows separate exception and thread context rows,
including each captured thread name when the dump supplies one.
The exception row is first and remains independent from the matching thread's
context. Rows show context status, architecture, source file RVA/size,
requested/decoded group masks, and stack or exception address. Missing contexts
and descriptors left undecoded by the loader's context limit remain explicit.
Other file formats show an empty Minidump page.

Selecting a context fills **Registers** and **Context bytes and provenance**.
Registers show bit width, scalar or wide hexadecimal value, exact captured bytes
in file order, source file offset, and an available mapped address. The details
page shows raw ContextFlags, independent group validity, record/context offsets,
thread stack/TEB or exception fields, diagnostics, and an offset-labelled dump
of the retained context prefix. Register values are hexadecimal storage values;
wide/vector/x87 contents are not interpreted as floating-point numbers.

Navigation uses explicit buttons. **Go to mapped register** supports captured
instruction, stack, frame and link registers only when their architecture/group
is valid and their exact value maps to captured image bytes. **Go to register
bytes** and **Go to context bytes** open validated original dump-file offsets.
**Go to stack / exception address** uses the selected record's mapped address.
No pointer-tag stripping, Thumb-bit normalization, memory fetching, live register
restoration or stack unwinding is performed. A disabled button means that the
required captured/mapped evidence is unavailable.

On AMD64 or ARM64 SystemInfo dumps, the loader also recognizes the fixed
716-byte x86 CONTEXT layout when its ContextFlags identify x86, and decodes it
as a WOW64-compatible context instead of treating the system architecture as
the thread's register layout. For ARM64 SystemInfo, a fixed 1,232-byte AMD64
CONTEXT with the AMD64 ContextFlags family at the documented AMD64 offset is
decoded using AMD64 register offsets. This context representation can be used
for either ARM64EC execution or x64 emulation; the minidump context alone does
not distinguish those modes, so the loader labels it only AMD64-compatible.
For variable-sized AMD64 contexts on ARM64 (including extended-state layouts),
the loader retains the prefix and reports an architecture ambiguity rather
than guessing a layout. These checks use bounded context prefixes and leave
SystemInfo's reported architecture unchanged. The ABI distinction follows Microsoft's
[ARM64EC context mapping](https://learn.microsoft.com/en-us/windows/arm/arm64ec-abi)
and [WOW64_CONTEXT layout](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-wow64_context).

The page uses virtual rows for at most 65,536 threads plus the exception, shows
at most 128 registers per context and 16 bytes per register (all currently
supported register widths), and displays at most 1,232 prefix bytes. Context
notes are capped at 32 and dump notes at 16, each at 1,024 bytes; omitted content
is labelled. Document switches clear selection and navigation targets. This
view was source-reviewed without GUI execution or tests; desktop compilation
remains a separate integration check.

## Breakpad assertion information

The Breakpad-specific AssertionInfo stream (`0x47670002`) is decoded as a
bounded fixed-layout record. The loader requires the 776-byte prefix containing
three fixed 128-code-unit UTF-16 strings (expression, function, and file), a
32-bit source line, and a 32-bit assertion type. Each string is converted to
UTF-8 with malformed surrogate sequences replaced, and retained output bytes
count against the shared metadata budget. Any trailing extension bytes remain
available through the raw stream directory. The model records the stream file
offset; the three strings and numeric fields use the documented offsets within
that record. CLI and desktop summaries show the assertion text, location, and
raw type. Known Breakpad types 0 through 2 are labeled; unknown type values are
kept without interpretation. Layout and type definitions follow Breakpad's
[minidump format header](https://chromium.googlesource.com/breakpad/breakpad/+/master/src/google_breakpad/common/minidump_format.h).

## Process VM counters

ProcessVmCountersStream (22) is decoded for revisions 1 and 2. The loader validates the complete fixed prefix for that revision, preserves the original stream file offset and declared extent, and retains page-fault count plus the revision's documented 64-bit counters. Revision 2 flags are retained without assigning meaning to unknown bits. Unknown revisions remain available through the raw stream directory and produce a diagnostic; this keeps unsupported extensions from blocking access to the rest of the dump. CLI output is limited to the fixed counter set and labels the byte-valued counters. The stream ID and field layouts follow Microsoft's [minidump stream enumeration](https://learn.microsoft.com/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidump_stream_type) and the `MINIDUMP_PROCESS_VM_COUNTERS_1` / `_2` structures.

## System memory information

SystemMemoryInfoStream (21) revision 1 exposes its revision flags and `MINIDUMP_SYSTEM_BASIC_INFORMATION` prefix: timer resolution, page size, physical-page bounds/count, allocation granularity, user address range, active processor affinity, and processor count. If the declared extent contains the complete `MINIDUMP_SYSTEM_FILECACHE_INFORMATION` group, its fixed cache-size, page-fault, and working-set fields are retained. Top-level flag `0x0001` specifically marks `TransitionRePurposeCount` valid; the count is not presented as meaningful when that flag is clear. Flag `0x0002` declares the four `MINIDUMP_SYSTEM_BASIC_PERFORMANCE_INFORMATION` page counters valid and requires the complete group extent before they are decoded. The file-cache group uses its SDK-defined 4-byte padding before 64-bit working-set values. A 4096-byte stream bound and metadata budget apply; unknown flag bits are preserved but do not imply additional decoded fields. The parser retains stream provenance. Unsupported revisions remain in the stream directory with a diagnostic. CLI reports present groups and the desktop Minidump summary continues to show core physical-memory values. The stream number follows Microsoft's [minidump stream enumeration](https://learn.microsoft.com/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidump_stream_type); field ordering and validity flags follow the Windows SDK's `MINIDUMP_SYSTEM_MEMORY_INFO_1` and nested `MINIDUMP_SYSTEM_FILECACHE_INFORMATION` / `MINIDUMP_SYSTEM_BASIC_PERFORMANCE_INFORMATION` definitions. Other `PerfInfo` counters are not decoded.

## Function table stream

The optional FunctionTableStream (13) now exposes its bounded header and generic
function-table descriptors: minimum/maximum address, relative-address base,
entry count, and exact file offsets for the generic descriptor, native
platform descriptor, and function-entry array. The loader validates descriptor
sizes, alignment padding, address ordering, entry extents, and the complete
stream bounds. It caps header and descriptor sizes at 4 KiB and retains at most
65,536 generic table rows under the shared metadata budget. Native descriptors
and function entries remain source-backed and opaque because their layouts
depend on the operating system and processor; HexLab does not interpret them
for stack unwinding yet. CLI output shows at most 128 tables and marks omitted
rows. The field meanings and stream ordering follow Microsoft's
[`MINIDUMP_FUNCTION_TABLE_STREAM`](https://learn.microsoft.com/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_function_table_stream)
and [`MINIDUMP_FUNCTION_TABLE_DESCRIPTOR`](https://learn.microsoft.com/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_function_table_descriptor) definitions.
