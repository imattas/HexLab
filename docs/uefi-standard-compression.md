# Bounded UEFI standard compression

`EFI_SECTION_COMPRESSION` sections with compression type `1` are decoded using
the standard EFI LZHUF/Huffman format. The parser validates the 8-byte stream
preamble, requires its compressed extent to exactly match the section payload,
and requires its declared output size to match the section header. It builds
canonical Huffman codebooks from checked lengths and reads bits only inside the
declared compressed extent. Truncated tables and bitstreams, invalid match
distances, and output-length overruns leave the section opaque with a
diagnostic.

Successfully decoded bytes are held only in a bounded temporary buffer while
the parser inventories the child section stream. Child rows use the
`decompressed` offset space and link to their parent compression section;
their offsets are not file offsets. The original compressed section retains
its file offset and reports `decompression=decoded`. If the decoded bytes do
not form a valid section stream, no child rows are kept and the compressed
parent remains opaque with a diagnostic.

Default limits are 16 MiB of compressed section payload including its preamble,
64 MiB output per section, 128 MiB cumulative decoded output, 64 MiB of active
nested decoded buffers, 256 MiB of decoder work units, and at most 65,536
Huffman blocks per stream. Work units account for input bits, Huffman/table
work, and output bytes. Exceeding a limit leaves that section opaque. The
outer parser still caps input at 512 MiB, section count at one million, and
nested section depth at eight.

Only EFI standard compression type `1` is supported. Tiano custom compression
in GUID-defined sections, unknown compression types, compressed payload
execution, PE/TE image loading, and extraction to disk remain unsupported.

The decoder structure is adapted from TianoCore EDK II
`BaseTools/Source/C/Common/Decompress.c` (Intel copyright, BSD-2-Clause-Patent).
The license text is retained in
[`libs/firmware/EDK2-LICENSE.txt`](../libs/firmware/EDK2-LICENSE.txt).
Format details follow the [UEFI PI Specification 1.9, Firmware Storage
Formats](https://uefi.org/sites/default/files/resources/UEFI_PI_Spec_Final_Draft_1.9.pdf).
