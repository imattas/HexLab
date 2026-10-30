# PE load configuration

The PE loader parses the Load Configuration data directory (index 10) for
PE32 and PE32+ images. `ImageMetadata::pe->load_configuration` retains the
declared structure size, version fields, security-cookie RVA, and the Guard CF
check, dispatch, and function-table RVAs when those fields are present in the
declared structure. These pointer values are normalized from preferred-base
VAs. The loader also retains the Guard XFG check, dispatch, and table-dispatch
helper RVAs, the CastGuard failure-mode pointer, and the Guard memcpy pointer.
Each is decoded only when its full pointer-width field lies within the
declared structure and is zero or maps to initialized image data. The size,
version, GuardFlags, cookie pointer, Guard CF table pointer, and table count
retain their file source offsets. The table count and flags are retained even
when the table is empty; nonempty table records are read only after validating
the complete RVA extent and the one-million-entry budget.

When the declared size covers the complete 12-byte
`IMAGE_LOAD_CONFIG_CODE_INTEGRITY` record, HexLab preserves its raw flags,
catalog identifier, catalog offset, reserved value, and source span for PE32
and PE32+. The CLI inspection report displays these fields and their source
file offset. The record is descriptive metadata only: HexLab does not resolve
the catalog offset, validate a catalog, or make a signature or trust decision.

The supported Guard CF subset reads table entries as a 32-bit function RVA
plus the metadata byte count encoded in the high nibble of `GuardFlags`. The
address-taken IAT, long-jump target, and EH-continuation tables are retained as
sorted 32-bit RVA rows with per-entry file provenance. IAT slots must map to
initialized image bytes; long-jump and EH-continuation targets must map to
initialized executable bytes. All tables are bounded by the image extent and
the one-million-record loader budget. Malformed table content produces a
warning and marks PE metadata incomplete.
When GFIDS entries have optional metadata, the loader names the currently
defined first-byte flags `FID_SUPPRESSED` (0x1) and `EXPORT_SUPPRESSED` (0x2)
in CLI output. It retains the raw metadata bytes and unknown bits. Extra bytes
beyond the first flag byte remain opaque. The loader reports these attributes;
it does not apply CFG policy or infer OS runtime behavior from them.
The versioned Guard RF helper fields (`GuardRFFailureRoutine`, its function
pointer, and `GuardRFVerifyStackPointerFunctionPointer`) are retained as
normalized RVAs when their complete pointer fields are present and nonzero.
`EnclaveConfigurationPointer` and `VolatileMetadataPointer` are retained the
same way. These values must resolve to initialized image bytes. The
`HotPatchTableOffset` scalar is retained with its source span when present;
HexLab does not interpret it as a file or RVA offset, nor decode the enclave,
volatile-metadata, or Guard RF structures it points to.
The CLI `inspect` metadata report prints normalized RVAs for the supported
cookie, Guard CF, XFG, CastGuard, Guard memcpy, Guard RF, enclave, and
volatile-metadata pointers, and prints the hot-patch table offset. It also
prints Guard CF, address-taken IAT, long-jump, and EH-continuation rows. Table
rows include file provenance where available and each table has a 4096-row
display cap.

Versioned fields are read only when their complete fixed-width fields lie
within the structure's declared size. The parser materializes at most the
known prefix (192 bytes for PE32, 320 bytes for PE32+), records the declared
size, and ignores any unknown future tail without allocating or interpreting
it.
This is metadata inspection: HexLab does not enforce CFG, XFG, or
EH-continuation policy, nor simulate all Windows loader decisions. Dynamic
value relocations are parsed and supported ARM64X transformations are exposed
as a separate image view; see [PE dynamic value relocations](pe-dynamic-value-relocations.md).
Load-configuration code-integrity catalog fields are raw metadata and do not
validate Authenticode signatures or establish publisher trust.
Guard RF tables and fields without an explicit representation remain opaque. Field offsets follow the Windows
`IMAGE_LOAD_CONFIG_DIRECTORY32/64` definitions in [Microsoft's PE load
configuration reference](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_load_config_directory64).

For PE32+ images, HexLab also reads a present `CHPEMetadataPointer` from the
load configuration and decodes version 1/2 CHPE headers plus their bounded
code map. Each row retains its original file provenance and is validated as a
sorted, non-overlapping range of initialized executable image bytes. The CLI
labels ranges as ARM64, ARM64EC, or AMD64 and prints their RVA and length.
The loader builds an `ImageExecutionProfile` from validated CHPE ranges, so
analysis selects x64 decoding for AMD64 ranges and A64 decoding for ARM64 and
ARM64EC ranges. Unknown CHPE versions and reserved range tags remain explicit
loader diagnostics. Field and range layouts follow
[LLVM's COFF CHPE metadata definition](https://codebrowser.dev/llvm/llvm/include/llvm/Object/COFF.h.html#736)
and [Microsoft's ARM64EC documentation](https://learn.microsoft.com/en-us/windows/arm/arm64ec).

Literal PE32 and PE32+ fixtures in `tests/loader_tests.cpp` cover cookie
normalization, Guard CF table stride metadata, executable target mapping, and
source spans.
