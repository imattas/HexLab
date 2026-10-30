# PE reproducibility and extended DLL-characteristic records

The PE debug-directory parser recognizes two additional record types.

`IMAGE_DEBUG_TYPE_REPRO` (type 16) marks the image as reproducible. An empty
payload retains the marker without a hash. A nonempty payload must contain a
four-byte little-endian hash length followed by exactly that many opaque hash
bytes; payloads are limited to 4 KiB. HexLab retains the complete hash and its
source file range but does not infer the hash algorithm or recompute the value.

`IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS` (type 20) is accepted as one
little-endian DWORD. The CLI reports the raw flags and decodes the currently
documented CET shadow-stack compatibility bit (`0x0001`) and forward-edge CFI
compatibility bit (`0x0040`); all other bits remain visible as an unknown-bit
mask. Each parsed value retains provenance to its debug payload. The parser
does not verify CET/CFI instrumentation or assert operating-system enforcement.

The CLI prints up to 256 debug-directory records. Reproducibility hashes are
stored fully but only the first 64 bytes are printed, with the full size shown
when truncated. This metadata is advisory and does not validate Authenticode
signatures, signed digests, timestamp chains, revocation, catalogs, or publisher
trust.

These record meanings and the reproducible payload layout follow Microsoft's
[PE format debug-directory documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type).
