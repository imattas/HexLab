# UEFI PI firmware-volume inventory

## Design note

HexLab already parses Intel HEX and Motorola S-record text as sparse addressable records. UEFI firmware images instead contain binary firmware volumes with flat FFS file records, so the inventory stays a metadata parser over the original byte span. It recognizes PI revision-2 firmware volumes embedded at arbitrary offsets, including nested volumes contained in an outer volume's file data, validates bounded headers and FFS2/FFS3 block maps, then walks aligned FFS headers and reports file GUIDs, kinds, sizes, states, and payload offsets. Each reported offset is absolute within the original input. It does not copy or map file payloads into synthetic segments. This makes the inventory useful for inspecting firmware blobs while avoiding unsupported assumptions about CPU mapping, capsule layout, or section semantics.

The parser caps source bytes, number of volumes (including nested ones), total number of files, total number of sections, and nested section depth, and accepts a stop token. The scanner continues through the enclosing FV's bytes after recording it so a complete nested FV can be independently validated and inventoried. The CLI renders at most 4,096 file entries and 16,384 section entries while retaining full inventory counts. FFS state bytes are normalized for the volume erase polarity and exposed both raw and as a disposition (`construction`, `header-valid`, `data-valid`, `marked-for-update`, `deleted`, `header-invalid`, or `unrecognized`). Reserved state bits must match erase polarity. Section parsing and data-checksum validation are performed only when the data-valid state is set and the file is neither deleted nor header-invalid; incomplete, deleted, and invalid files remain listed with their offsets and state but their payload is left uninterpreted. A marked-for-update file with valid data is still parsed, since its data-valid state is complete.

Each file also reports the required data-start alignment decoded from the FFS alignment attribute (1 byte through 16 MiB). The parser checks the data offset relative to the beginning of the firmware volume, as required by PI, and reports `alignment=not-valid` plus a file diagnostic when the recorded placement violates that requirement. The file and its section inventory remain visible for forensic inspection.

FFS_PAD files are identified explicitly. For a data-valid pad file, the parser checks that its entire data area still matches the FV erase polarity and skips interpreting those erased bytes as sections. Aligned gaps after files and the trailing free-space extent are inventoried with FV-relative offsets and sizes, and each is checked byte-for-byte against erase polarity. Short non-erased tails and non-erased padding/free space are retained as layout diagnostics instead of being treated as valid free space. CLI output caps free-space rows at 8,192 and layout diagnostics at 4,096 per scan, with omitted counts.

The parser also handles standard and extended PI section headers, records offsets and parent/depth provenance, and inventories nested sections inside `EFI_SECTION_COMPRESSION` when the type is `EFI_NOT_COMPRESSED`, standard EFI compression type `1`, or the bounded legacy Tiano type `2` compatibility form decodes successfully. Decoded children use decoded-stream-relative offsets; they are never presented as original file offsets. Invalid, truncated, unsupported, or over-limit compressed streams remain opaque with declared size and algorithm recorded. See [bounded UEFI compression](uefi-standard-compression.md) for the decoder and exact limits. GUID-defined sections retain their GUID, data offset, attributes, and payload range. The standard EDK II CRC32 guided-section GUID (`FC1BCDB0-7D31-49AA-936A-A4600D9DD083`) is recognized: its appended 32-bit CRC is checked against the bytes beginning at `DataOffset`, and a valid payload is traversed as a nested section stream only when `PROCESSING_REQUIRED` is clear. CRC mismatch, cancellation, and byte-budget exhaustion keep a CRC32 payload opaque. For any GUID whose `PROCESSING_REQUIRED` bit is clear, PI defines the bytes at `DataOffset` as directly retrievable nested sections, including GUIDs this parser does not otherwise recognize. EDK II Tiano, LZMA, LZMAF86, and Brotli custom-decompression GUIDs are recognized when processing is required. Their bounded decoders inventory the resulting section stream with decompressed-stream offsets; malformed payloads remain opaque with a diagnostic. Brotli's wrapper and limits are described in [Brotli guided sections](uefi-brotli-compression.md). Unknown processing-required GUID payloads remain opaque. CRC work is capped at 64 MiB cumulatively per input by default. `EFI_SECTION_DISPOSABLE` payloads are parsed as nested sections when structurally valid, but preserved as opaque metadata if their implementation-specific contents do not form a valid stream. No payload is executed or mapped, and malformed section streams are reported on their containing FFS file without hiding the file or volume. Authenticated capsule headers and nested-volume extraction remain outside this slice.

The volume, file, state, section, compression, and GUID-defined section layouts follow the [UEFI PI Specification 1.10, Firmware Storage Code Definitions](https://uefi.org/specs/PI/1.10/V3_Code_Definitions.html) and the [TianoCore EDK II PI volume definitions](https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Pi/PiFirmwareVolume.h). The CRC32 GUID and header placement follow [EDK II's GUID declaration](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/MdeModulePkg.dec), [section generator](https://github.com/tianocore/edk2/blob/master/BaseTools/Source/C/GenSec/GenSec.c), and [CRC32 extraction library](https://github.com/tianocore/edk2/tree/master/MdeModulePkg/Library/DxeCrc32GuidedSectionExtractLib). Section offsets point into the original input file; a section's payload range excludes its common header and, for compression or GUID-defined sections, the corresponding section-specific header.

Firmware-volume extended headers are now parsed when `ExtHeaderOffset` is nonzero. The parser validates four-byte alignment, placement after the block-map terminator, bounded header size, and each following variable-length extension entry. The volume retains its optional FV-name GUID and raw entry type, size, and volume-relative payload range; unknown entry types are preserved without interpretation. Zero-filled header alignment tail bytes are accepted. The entry count is capped at 65,536 in addition to the existing header-size bound. The CLI summary renders the optional name GUID and extension-entry type, size, volume-relative offset, and payload range. Output is capped at 8,192 extension entries with an omitted count; the parser retains its independent 65,536-entry bound.

DXE, PEI, and MM dependency-expression sections (`0x13`, `0x1b`, and `0x1c`)
receive bounded bytecode validation. The parser checks GUID operand extents,
stack underflow and final depth, final `END`, and PI ordering rules for
`BEFORE`, `AFTER`, and `SOR`; it records instruction/GUID counts and maximum
stack depth. At most 4,096 instructions are examined per section. Invalid or
over-limit expressions remain available as section payloads with a diagnostic.
The library also exposes `evaluate_uefi_depex`, which evaluates the boolean
stack opcodes against a caller-supplied complete set of installed protocol/PPI
GUIDs: a `PUSH` succeeds when its GUID is present, `TRUE`/`FALSE` push constants,
and `NOT`, `AND`, and `OR` apply the PI stack rules. `BEFORE` and `AFTER` return
an explicit ordering-required status without a boolean. PI defines `SOR` as a
no-op for boolean evaluation; the result retains its `schedule_on_request` bit
and returns a dispatch-context status with the computed boolean. The expression is limited
to 4,096 instructions and the availability set to 4,096 GUIDs; GUID values use
the same EFI wire-byte order as the section. Empty validated expressions
evaluate as satisfied. This API reports only a boolean result for the supplied
environment: it does not discover protocol installations, schedule modules, or
dispatch code. Opcode semantics and encodings follow the [PI 1.8 DXE dependency-expression instruction set](https://uefi.org/specs/PI/1.8/V2_DXE_Dispatcher.html)
and [PEI dependency-expression instruction set](https://uefi.org/specs/PI/1.8/V1_PEI_Foundation.html).

`plan_uefi_driver_dispatch` adds a caller-driven ordering recommendation for
DXE and UEFI driver FFS file types (`0x05`-`0x07`). Validated DXE DEPEX bytes
are retained on their section records; each plan entry points back to its FFS
file index and the DEPEX section indices that contributed to its result. The
caller supplies the installed protocol GUID set. Boolean DEPEX expressions use
the evaluator above, while `BEFORE` and `AFTER` create file-GUID ordering
constraints; a stable topological sort returns the ready file indices. Missing
protocol operands are listed as provenance on each entry (they may be
non-blocking when an expression uses `OR` or `NOT`). Missing order targets,
invalid expressions, false dependencies, non-data-valid FFS files, and cycles
are reported explicitly in per-file dispositions and diagnostics. Non-driver
files are present in the entry list as `non_driver` and never enter the order.

This is a recommendation for one supplied snapshot, not a DXE dispatcher: it
does not discover protocols produced by drivers, iterate as those drivers
install protocols, apply PEI/MM dependencies, implement `SOR` scheduling, or
execute code. The order only covers `BEFORE`/`AFTER` constraints that point at
other driver file GUIDs in the same volume. Callers must refresh the available
protocol set and plan again as dispatch progresses.

The parser recognizes the EDK II DXE APRIORI file name GUID. It retains the
ordered GUID array only when the file is a data-valid freeform FFS file with
exactly one top-level RAW section, an integral number of GUID entries, no
duplicates, and at most 4,096 entries. Missing, duplicate, malformed, or
checksum-invalid APRIORI files remain inventoried with a diagnostic. The CLI
prints the parsed list under a global 512-GUID output cap. In
`plan_uefi_driver_dispatch`, the APRIORI list is a stable tie-break preference
among currently dependency-ready DXE/UEFI drivers; it does not override a
DEPEX or `BEFORE`/`AFTER` constraint, make a blocked driver ready, or execute a
module. This keeps the result a conservative static recommendation rather
than claiming to emulate the firmware dispatcher. The file shape and list
semantics follow the [EDK II Build Specification, APRIORI files](https://github.com/tianocore-docs/edk2-BuildSpecification/blob/main/2_design_discussion/26_creating_efi_images.md#269-apriori-files),
and the DXE APRIORI filename GUID follows [EDK II `Apriori.h`](https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Guid/Apriori.h).

`plan_uefi_pei_dispatch` separately evaluates PEI DEPEX for PEIM (`0x06`) and
combined PEIM/DXE (`0x08`) files against a caller-supplied PPI GUID set. It
returns one row per FFS file, records the source section index and missing PPI
GUIDs, and lists currently ready PEIMs in firmware-volume file order. Files
outside those types are `non_driver`; files without PEI DEPEX are ready when
their FFS state is data-valid or marked-for-update. Multiple PEI DEPEX
sections, invalid section metadata, non-dispatchable FFS states, and unsatisfied
expressions remain explicit in each row. This is a readiness snapshot: it does
not infer PPI installations from PEIM code, iterate PEI dispatch rounds, load
modules, or execute firmware. DXE/MM ordering and dispatch-context opcodes are
not part of the PEI plan.

`plan_uefi_mm_dispatch` evaluates MM DEPEX sections (`0x1c`) for MM drivers
(`0x0a`), combined MM/DXE drivers (`0x0c`), and standalone MM drivers (`0x0e`)
against a caller-supplied set of installed protocol GUIDs. The caller should
provide the union of applicable UEFI and MM protocol databases because PI MM
DEPEX can reference either. It returns one row per FFS file, records matching
section indices and missing GUID operands, and lists currently ready MM drivers
in file order. MM core (`0x0d`) and standalone MM core (`0x0f`) files are not
treated as dispatched drivers. No MM DEPEX section means ready only when the
FFS file is in a dispatchable data-valid state. Multiple or invalid MM DEPEX
sections, unavailable protocols, non-dispatchable files, and ordering or
dispatch-context expressions remain explicit in each row. The API is a
readiness snapshot; it does not execute or load modules, infer protocol
installation effects, model the MM Foundation scheduler, or claim runtime MM
isolation. File type and dependency-section IDs follow PI's [firmware file
definitions](https://uefi.org/specs/PI/1.10/V3_Code_Definitions.html) and the
EDK II [`PiFirmwareFile.h`](https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Pi/PiFirmwareFile.h).

`plan_uefi_pei_protocol_discovery` provides bounded iterative PEI readiness
planning when a caller has explicit per-PEIM PPI-effect assumptions. It selects
one currently ready PEIM in source order, applies only that file's assumed new
PPI GUIDs, and reevaluates DEPEX for the next round. This supports fixed-point
analysis of dependencies that become ready after earlier assumed installations;
it does not infer PPI effects from executable code or claim to emulate full PEI
dispatch policy. See [static protocol-effect planning](uefi-protocol-discovery-plan.md).

For PEI volumes, a valid PI `APRIORI` file is parsed as a bounded GUID list and
used to order matching ready PEIMs ahead of remaining files in the dispatch
plan. Unknown or duplicate GUIDs are reported; unresolved entries do not
invent a dispatch target. If no usable APRIORI order applies, the planner keeps
its existing FFS order. This remains a static plan driven by caller-supplied
PPI effects, not PEI execution.

## CLI

Callers can also build a bounded iterative recommendation from explicitly
assumed per-driver protocol effects using `plan_uefi_protocol_discovery`.
See [static protocol-effect planning](uefi-protocol-discovery-plan.md) for
provenance, fixed-point/limit statuses and conservative ordering behavior.
It does not execute drivers or report observed protocol installations.

```text
hexlab_cli firmware inspect image.fd --format uefi
```

The command scans for valid PI firmware volumes, prints each volume's file offset, length, file-system GUID, revision, and verified header checksum, then lists each FFS file and its section tree. Section rows include type, offset space, total and payload sizes, depth, parent index, and applicable compression or GUID-defined metadata. File-space offsets are relative to the input file; decoded-space offsets are relative to the decompressed stream. Unsupported file-system GUIDs or invalid volume candidates are skipped during scanning; malformed section streams are shown as per-file diagnostics. The command reports an error if no valid FFS2/FFS3 volume is found.
