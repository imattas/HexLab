# Mach-O chained-fixup bounds and resolution

The loader decodes chained fixup imports, segment starts, page chains and
pointer records for supported little-endian 32-bit and 64-bit Mach-O images
when the pointer format's field width matches the selected slice. It retains
raw pointer words and the source file/address coordinates. Rebase targets and
bind imports are exposed through the existing Mach-O dyld resolver; pointer
authentication remains metadata and is not applied. Kernel-cache formats 8
and 11 retain their encoded target information but stay unresolved without
the shared-cache base-pointer table. ARM64e userland24 format 12 uses a
24-bit import index and an 8-byte chain stride. ARM64e shared-cache format
13 retains its 34-bit cache-relative target and authentication fields, but
stays unresolved without the shared-cache base. ARM64e kernel format 7 uses
an 8-byte pointer field and 4-byte chain stride; its unauthenticated targets
are interpreted as offsets from the preferred image header. Authenticated
pointers retain their PAC metadata and remain unresolved by the runtime
resolver. Resolvable unauthenticated format-7 rebases and bind metadata flow
through the same resolver and persisted-provenance checks as formats 1, 9,
and 12.

ARM64e firmware format 10 stores 8-byte words with a 4-byte chain stride.
Unauthenticated targets are VM addresses and use the existing direct-target
resolver path; bind fields retain the standard ARM64e import/addend encoding.
Authenticated target and diversity/key metadata are preserved, while runtime
resolution reports authenticated pointers as unresolved because PAC is not
applied. Apple defines these field semantics; Ghidra's current implementation
was used as a secondary format/stride cross-check.

For standard ARM64e authenticated words (formats 1, 7, 9, 10, and 12), the
parser preserves the 32-bit authenticated rebase runtime offset or bind import
ordinal separately from the 16-bit diversity, address-diversity bit, and
two-bit key. The key values are retained as encoded: 0/1/2/3 correspond to
IA/IB/DA/DB. Format 12 bind ordinals are 24 bits; other standard ARM64e bind
ordinals are 16 bits. The reserved bits after each ordinal are checked, and
authenticated binds do not acquire an addend from the unauthenticated addend
field. An authenticated rebase remains a raw image-relative offset; the
runtime resolver deliberately does not turn it into a usable pointer because
it cannot produce or validate a PAC.

ARM64e segmented format 14 stores an 8-byte field with a 4-byte chain stride.
The parser retains the lower 32-bit target payload (4-bit segment index plus
28-bit segment offset), the 12-bit next field, and authenticated diversity,
address-diversity, and key fields. It leaves every format-14 row incomplete
because this loader has no segmented-address table, so no target address is
assembled or resolved. The current Ghidra implementation does not enumerate
format 14; Apple's header is the format authority for this decode.

The 32-bit cache (format 4) and firmware (format 5) pointer formats retain
their bounded 30-bit/2-bit and 26-bit/6-bit target/next fields respectively,
and follow their 4-byte-stride chains. Format 4 is cache-relative and remains
unresolved without a cache mapping context. Apple defines format 5's 26-bit
target as a VM address, so the parser records it as a direct target without
adding an invented base. The current resolver does not yet resolve format 5.
These formats are accepted only in 32-bit slices.

The parser applies these hard limits before allocating symbol strings or
following chain records:

* 1,000,000 chained imports and 1,000,000 decoded pointer rows per image.
* 65,535 pages per segment-start record (the on-disk page-count field limit).
* 64 KiB per imported symbol name and 16 MiB of imported symbol bytes per
  chained-fixup stream.
* Pointer fields must fit wholly inside both their mapped segment and their
  declared fixup page. Multi-start entries must terminate within the bounded
  segment-start record.

The fixed chained header, import table, symbol pool, starts-in-image offset
array, and each segment-start record are also checked as disjoint bounded
ranges. Import/symbol ranges are checked when their encodings are recognized;
unsupported import encodings remain incomplete and are not interpreted.

Uncompressed and zlib-compressed symbol pools are decoded. Compressed pool
expansion is capped at 16 MiB per stream, each imported name at 64 KiB, and
the entire compressed input must be consumed with no trailing bytes. Names
decoded from compressed data retain their import record provenance but have
no direct file offset. Unsupported import/symbol encodings, unsupported
pointer formats, malformed extents, and targets that require unavailable
runtime state leave the stream incomplete or fail parsing when the input is
structurally malformed. No guessed target base is attempted.

Format reference: [Apple dyld chained fixup definitions](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h).
