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

The PI specification defines only `EFI_NOT_COMPRESSED` (0) and
`EFI_STANDARD_COMPRESSION` (1) for this section. HexLab also accepts the legacy
Tiano LZHUF variant as compression type `2` in an `EFI_SECTION_COMPRESSION`
section. It uses the same bounded decoder with Tiano's five-bit position
alphabet and is an implementation compatibility extension, not a PI-defined
compression type.

The EDK II Tiano custom-decompression GUID
(`A31280AD-481E-41B6-95E8-127F4C984779`) is also recognized on
`EFI_SECTION_GUID_DEFINED` sections with `PROCESSING_REQUIRED` set. Its payload
uses the same 8-byte compressed/output size preamble and bounded type-2 Tiano
decoder. Successfully decoded bytes are used only to inventory a nested
section stream; child offsets are relative to the decompressed stream. A
malformed stream, budget limit, or invalid nested section stream keeps the
guided payload opaque with a diagnostic. EDK II also defines the LZMA custom
decompression GUID (`EE4E5898-3914-4259-9D6E-DC7BD79403CF`) and the LZMA x86
converter GUID (`D42AE6BD-1352-4BFB-909A-CA72A6EAE889`). Those
processing-required payloads remain opaque: this build has no bounded LZMA
decoder dependency, and their format is not treated as interchangeable with
the Tiano LZHUF stream. For any GUID-defined section whose
`PROCESSING_REQUIRED` attribute is clear, PI permits direct retrieval of the
payload as nested sections; the parser inventories that stream without
interpreting the GUID-specific encoding. Other unknown processing-required
GUIDs, unknown compression types, compressed payload execution, PE/TE image
loading, and extraction to disk remain unsupported.

The decoder structure is adapted from TianoCore EDK II
`BaseTools/Source/C/Common/Decompress.c` (Intel copyright, BSD-2-Clause-Patent).
The license text is retained in
[`libs/firmware/EDK2-LICENSE.txt`](../libs/firmware/EDK2-LICENSE.txt).
Format details follow the [UEFI PI Specification 1.9, Firmware Storage
Formats](https://uefi.org/sites/default/files/resources/UEFI_PI_Spec_Final_Draft_1.9.pdf).
The PI specification's compression-type values are also listed in
[TianoCore's section definitions](https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Pi/PiFirmwareFile.h); the Tiano type-2 compatibility decoder is based on the distinct
[Tiano compression routine](https://github.com/tianocore/edk2/blob/master/BaseTools/Source/C/TianoCompress/TianoCompress.c).
The custom-decompression GUID and handler behavior follow EDK II's
[MdePkg declaration](https://github.com/tianocore/edk2/blob/master/MdePkg/MdePkg.dec)
and [Tiano guided-section handler](https://github.com/tianocore/edk2/blob/master/MdePkg/Library/BaseUefiDecompressLib/BaseUefiTianoCustomDecompressLib.c).
The LZMA and LZMAF86 GUIDs follow EDK II's [LZMA decompression GUID declarations](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Include/Guid/LzmaDecompress.h); both processing-required payloads are decoded under bounded output, dictionary, work, and active-memory limits, with the x86 branch filter applied for LZMAF86. EDK II's Brotli custom-decompression GUID is also supported; its wrapper, allocator cap, and limits are described in [Brotli guided sections](uefi-brotli-compression.md).
