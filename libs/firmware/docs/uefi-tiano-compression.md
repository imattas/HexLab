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

The Tiano custom GUID-defined decompression protocol is separate and remains
opaque. This parser does not load PE/TE images, execute compressed code, or
extract sections to disk.
