# Firmware record formats

`hexlab::firmware` turns Intel HEX and Motorola S-record text into bounded, address-sorted data segments. Each segment keeps its source line and record index, so clients can link displayed bytes and diagnostics back to the input file. The parser does not guess a CPU or apply a target-specific memory map. The separate loader adapter builds a sparse image while preserving those record boundaries.

Intel HEX supports data (00), EOF (01), extended segment address (02), start segment address (03), extended linear address (04), and start linear address (05) records. It verifies each byte checksum, requires a well-formed EOF record, and rejects any later nonblank record.

Motorola S-record supports S0 headers, S1/S2/S3 data, S5/S6 data-record counts, and matching S9/S8/S7 termination records. It validates byte counts and one's-complement checksums, validates an optional data-record count, requires a termination record, and rejects records after termination. The unique optional S0 payload is retained as raw metadata with its source line and record index, must precede data/count records, and is never emitted as memory. A count record must follow all data records; subsequent data records are rejected rather than invalidating the declared count.

Intel HEX permits at most one type-03/type-05 start-address record. Duplicate start metadata is rejected instead of silently replacing the earlier entry point.

Both parsers reject overlapping data records, malformed/unsupported record types, out-of-bound addresses, and configured record/data limits. `ParseOptions` defaults to at most 512 MiB of data, addresses through `0xffffffff`, and four million records. A `std::stop_token` supports cancellation between records. Errors include a one-based source line when a line is available and use the shared `ErrorCode` taxonomy.

The parser deliberately retains each input data record as one `DataSegment`, sorted by address. Adjacent records are not merged, preserving their individual provenance. Empty data records are validated but do not create a segment.
# Firmware files in the CLI and image model

Intel HEX and Motorola S-record parsing is available through the loader adapter and CLI:

```text
hexlab_cli firmware inspect firmware.hex --format ihex
hexlab_cli firmware inspect firmware.s19 --format srec
```

S-record inspection also reports the retained S0 payload as hexadecimal bytes with its source line and record index. The regular sparse-segment report and start-address warnings continue to come from the loader adapter.

The adapter keeps records at their target addresses as separate sparse image segments; it does not fill address gaps with synthetic bytes. The packed in-memory backing store is an implementation detail. Each record retains its source line, record index, packed backing offset, target address, and length in firmware metadata. A declared start address appears as an image entry only when it is covered by data; otherwise it remains in metadata with a warning. Firmware record files do not identify a CPU, so this inspection workflow leaves architecture and execution mode unknown and does not claim disassembly support.

Firmware can also be imported into self-contained projects with an explicit format:

```text
hexlab_cli project create firmware.hxproj --input firmware.hex --format ihex
hexlab_cli project create firmware.hxproj --input firmware.s19 --format srec
hexlab_cli project inspect firmware.hxproj
```

Projects embed the original record text, its hash, and the selected format. Reopening reparses that text without the external file, restoring sparse bytes, record provenance, target-address names/comments, and history. Firmware recipes use the exact three-byte encodings `05 00 08` (Intel HEX) and `05 00 09` (S-record); extra bytes and unknown tags are rejected. This does not require a project schema migration. Durable firmware text is limited to 1 GiB before requesting a source view, in addition to the parser's existing data/address/record limits.

File locations, byte searches, patches, and exports refer to the original text. Memory locations refer to decoded firmware data. A decoded memory byte has no single source-file byte, so previews omit a source offset and virtual-location project exchange remains unavailable. Virtual-address byte patches are supported when the full range is initialized and covered by firmware data records: the project updates each affected record's data and checksum in the original text, preserving the other record text, record ordering, headers, count/start records, and line endings. A single patch may cross adjacent records but cannot cross an address gap or touch more than 65,536 records. The update is same-length and is stored in normal project patch history, so undo/redo and export use the regenerated valid record text. File-offset text patches remain available and are reparsed; malformed edits leave the project in file-only state until a valid text edit or undo restores the mapping. Processor selection, instruction analysis, and automatic format detection remain outside this workflow.

UEFI PI firmware volumes embedded in binary images can be listed as FFS2/FFS3 files with `hexlab_cli firmware inspect <path> --format uefi`. A contiguous EFI Firmware Management Protocol capsule can be inventoried with `hexlab_cli firmware inspect <path> --format uefi-capsule`; the report includes versioned payload descriptors and source offsets without extracting or executing payloads. See [UEFI firmware-volume inventory](uefi-firmware-volume.md) and [UEFI FMP capsule metadata](../libs/firmware/docs/uefi-fmp-capsule.md).
