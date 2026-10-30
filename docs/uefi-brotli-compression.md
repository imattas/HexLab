# Bounded UEFI Brotli guided sections

HexLab recognizes EDK II's Brotli custom-decompression GUID
(`3D532050-5CDA-4FD0-879E-0F7F630D5AFB`) when
`EFI_SECTION_GUID_DEFINED.PROCESSING_REQUIRED` is set. The 16-byte wrapper is
an unsigned little-endian 64-bit decoded size followed by an unsigned
little-endian 64-bit decoder scratch size; the remaining bytes are a Brotli
stream. The decoded size must fit the section and cumulative output limits.
The stream must consume the entire payload and produce exactly the declared
number of bytes. The result is used only as a nested section stream. Its child
offsets refer to that decoded stream, and invalid children cause the child
inventory to be rolled back while retaining an opaque parent and diagnostic.

The wrapper's scratch declaration must be nonzero and at most 32 MiB. HexLab
uses a custom Brotli allocator capped by that declaration and the same 32 MiB
ceiling. Output is bounded by the configured per-section limit (64 MiB by
default), total decoded output (128 MiB), active decoded buffers (64 MiB), and
decode work (256 MiB units by default). Decode work charges compressed input
bytes plus eight units per output byte. Decoding is streamed in 64 KiB steps
with cancellation checks. Truncated streams, trailing compressed data,
allocation failures, output-size mismatches, cancellation, and budget failures
leave the GUID-defined payload opaque with a diagnostic. These limits bound
HexLab's input, output, and decoder allocations; they do not validate firmware
authenticity or execute any decoded content.

The decoder-only C sources and public headers are vendored from Google Brotli
v1.2.1, commit `db24a98aed38a16de78cc05ca15cdd8dc2a0d92d`, under the MIT
license. The source subset and local build changes are recorded in
[`third_party/brotli_decoder/provenance.json`](../third_party/brotli_decoder/provenance.json).
The GUID and 16-byte wrapper follow EDK II's
[`MdeModulePkg.dec`](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/MdeModulePkg.dec)
and [Brotli custom guided-section handler](https://github.com/tianocore/edk2/tree/master/MdeModulePkg/Library/BrotliCustomDecompressLib).
