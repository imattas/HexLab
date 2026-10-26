# Windows Minidump analysis

HexLab recognizes the `MDMP` signature during automatic format detection and
opens a durable `minidump` load recipe. The loader maps captured process memory
at its recorded virtual addresses, so ordinary disassembly and byte views can
inspect memory captured by the dump.

The loader reads the bounded stream directory and supports standard
`SystemInfo`, `MemoryList`, `Memory64List`, `MemoryInfoList`, `ModuleList`,
`ThreadList`, `ThreadNames`, `UnloadedModuleList`, and `Exception` streams.
Module and thread names are decoded from bounded UTF-16 strings. Unloaded module
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

Thread and exception register contexts use the SystemInfo architecture and
require a matching architecture family in `ContextFlags`. Unknown architectures
and mismatches retain raw evidence and diagnostics without guessing registers.
Each requested register group needs its complete meaningful byte range;
truncated groups are omitted while complete independent groups remain available.
The supported fixed little-endian Windows CONTEXT layouts are:

| Architecture | Captured register groups |
| --- | --- |
| x86 | Control (`ebp`, `eip`, `esp`, segments and flags), integer, segments, debug, legacy x87, and extended FXSAVE x87/XMM0-7/MXCSR. Extended storage takes precedence when both floating layouts are present. |
| AMD64 | Control (`rsp`, `rip`, segments and flags), integer, segments, debug, and fixed x87/XMM0-15/MXCSR floating storage. Both top-level and FXSAVE MXCSR copies are retained. |
| ARM32 | Control (`sp`, `lr`, `pc`, `cpsr`), integer R0-12, FPSCR and D0-31/Q0-15 aliases, and fixed breakpoint/watchpoint registers. |
| ARM64 | Control (`x29`, `x30`, `sp`, `pc`, `cpsr`), integer X0-28 with X18 retained only when explicitly requested by its separate flag, full or low/high partial NEON V-register storage, FPCR/FPSR when the low/full group is available, and fixed breakpoint/watchpoint registers. |
| Breakpad ARM64 (`processor_architecture=0x8003`) | Its packed legacy layout and 64-bit ContextFlags are decoded separately: integer/control group includes X0-X30, SP, PC and CPSR; floating group includes FPSR, FPCR and V0-V31. |

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

Context reads retain at most 716 bytes for x86, 416 for ARM32, 1,232 for AMD64,
912 for Microsoft ARM64, 796 for Breakpad ARM64, and 64 for unknown architectures. The full advertised source
extent is validated even when only a prefix is decoded. Decoding is capped at
4,096 contexts; later descriptors retain source extents with a global diagnostic.
Context allocations, register bytes and strings are charged to the 64 MiB
metadata budget. Stream, thread, memory and module counts remain independently
bounded. Thread/context processing checks cancellation between records. The CLI
summary lists at most 256 threads, includes captured names when available, and
prints wide register values from their captured bytes.

The legacy ARM64 layout follows the Breakpad `MDRawContextARM64_Old` format,
also described as `CONTEXT_ARM64_OLD` by [minidump-common](https://docs.rs/minidump-common/latest/minidump_common/format/struct.CONTEXT_ARM64_OLD.html).

When `MemoryInfoList` is present, captured regions are split at protection
boundaries and retain read, write, and execute permissions. If protection data
is absent, mapped bytes receive provisional read/write/execute permissions so
code remains inspectable, and metadata is marked incomplete. The architecture
map recognizes x86, AMD64, ARM, and ARM64. x86, AMD64 and ARM64 receive their
corresponding decode modes; ARM remains mode-unknown because module records do
not establish ARM versus Thumb state. A mapped exception address becomes the
image entry.

XSTATE/AVX/AVX-512, CET, ARM scalable state, ARM64EC alternate context layouts,
WOW64 context-family substitution, architecture inference from bytes, and other
processor layouts are unsupported. Unsupported group flags yield a partial
context while preserving supported groups and original source extents; extended
state beyond the fixed prefix is not copied. No live register restoration,
stack reconstruction, unloaded-module reconstruction, matching PDB fetching,
or recovery of memory omitted from the dump is performed. Other Windows
processor architectures remain metadata without an instruction decoder.

## Desktop context inspection

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

The page uses virtual rows for at most 65,536 threads plus the exception, shows
at most 128 registers per context and 16 bytes per register (all currently
supported register widths), and displays at most 1,232 prefix bytes. Context
notes are capped at 32 and dump notes at 16, each at 1,024 bytes; omitted content
is labelled. Document switches clear selection and navigation targets. This
view was source-reviewed without GUI execution or tests; desktop compilation
remains a separate integration check.
