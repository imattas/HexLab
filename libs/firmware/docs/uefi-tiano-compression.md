# UEFI Tiano compression

The firmware-volume scanner decodes both `EFI_STANDARD_COMPRESSION` (type 1)
and Tiano LZHUF compression (type 2) inside `EFI_SECTION_COMPRESSION` sections.
Both formats share the bounded block and Huffman decoder. Tiano uses the
5-bit position-code count (`PBIT=5`); standard EFI uses `PBIT=4`. The parser
keeps the section opaque with a diagnostic when its preamble, Huffman tables,
bitstream, match distance, or output extent is invalid.

The decoder preserves the existing limits for compressed input, per-section
output, cumulative output, active nested output, and total decode work. Decoded
bytes exist only in a temporary buffer while nested section rows are collected.
If the decoded payload is not a valid section stream, child rows are discarded
and the parent remains opaque. Source and decompressed offsets remain distinct.

This covers the Tiano type-2 algorithm selected by `TianoDecompress` in
TianoCore EDK II `BaseTools/Source/C/Common/Decompress.c`; the implementation
shares HexLab's checked decoder and changes only the position-code width. The
upstream BSD-2-Clause-Patent notice is retained in
[`EDK2-LICENSE.txt`](../EDK2-LICENSE.txt), installed with the firmware library.
See [EDK II Decompress.c](https://github.com/tianocore/edk2/blob/master/BaseTools/Source/C/Common/Decompress.c)
and the [UEFI PI firmware-storage definitions](https://uefi.org/specs/PI/1.10/V3_Code_Definitions.html).

## LZMA guided sections

The scanner also decodes the EDK II LZMA custom-decompression GUID
(`EE4E5898-3914-4259-9D6E-DC7BD79403CF`) when the GUID-defined section marks
processing as required. Its payload uses the EDK II wrapper: five LZMA
properties bytes, an eight-byte little-endian uncompressed size, and the raw
LZMA stream. The declared output size is checked before allocation, and the
SDK's incremental decoder writes through 64 KiB chunks. The dictionary is
limited to 16 MiB, decoder allocations to 32 MiB, and decoded bytes use the
existing per-section, cumulative, active-output, and total-work limits.
Cancellation is checked between output chunks. Nested section rows are kept
only if the decoded bytes form a valid section stream.

LZMAF86 (`D42AE6BD-1352-4BFB-909A-CA72A6EAE889`) uses the same wrapper and
decoder, followed by EDK II's x86 BCJ converter. The converter is length
preserving, carries its look-ahead state across 64 KiB chunks, consumes one
additional work unit per output byte, and checks cancellation between chunks.
The LZMAF86 GUID is decoded independently from the standard LZMA GUID. The
vendored decoder and converter are from EDK II's LZMA SDK 19.00; their source
headers identify Igor Pavlov's code as public domain. Source provenance and
the exact upstream revision are recorded in
`../../../third_party/uefi_lzma/NOTICE.md`.

GUID-defined sections with `EFI_GUIDED_SECTION_PROCESSING_REQUIRED` clear are
traversed from their `DataOffset` as ordinary nested section streams, as
specified by PI. The GUID, attributes, and payload bounds remain available on
the parent section. If processing is required, the payload stays opaque and is
marked `processing_required`; no extraction protocol is inferred for other
GUIDs. The recognized CRC32, Tiano, LZMA, and LZMAF86 handlers are described
above. This parser does not load PE/TE images, execute compressed code, or
extract sections to disk.
