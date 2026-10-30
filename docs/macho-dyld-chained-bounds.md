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

CLI and desktop chain-pointer views label the encoded authentication key as
IA, IB, DA, or DB and show its numeric encoding, diversity value, and
address-diversity bit. These labels describe stored metadata only; they do not
indicate that the pointer's PAC was checked or applied.

Authenticated ARM64e bind pointers also retain their chained import association
in dyld reference provenance: library ordinal, imported symbol, weak-import
flag, combined addend, and import-row identity remain available even though the
resolution reason stays `authenticated`. This association identifies the
encoded binding only; it does not resolve the runtime target or validate/apply
PAC. Persisted provenance accepts this binding only when its original pointer
is both authenticated and a bind.

ARM64e segmented format 14 stores an 8-byte field with a 4-byte chain stride.
The parser retains the lower 32-bit target payload (4-bit segment index plus
28-bit segment offset), the 12-bit next field, and authenticated diversity,
address-diversity, and key fields. It leaves every format-14 row incomplete
because this loader has no segmented-address table, so no target address is
assembled or resolved. Chain traversal advances by four bytes per `next`
unit even though each pointer occupies eight bytes; overlapping pointer words
are retained but marked incomplete by the normal overlap check. The current
Ghidra implementation does not enumerate format 14; Apple's header is the
format authority for this decode.

The 32-bit cache (format 4) and firmware (format 5) pointer formats retain
their bounded 30-bit/2-bit and 26-bit/6-bit target/next fields respectively,
and follow their 4-byte-stride chains. Format 4 is cache-relative and remains
unresolved without a cache mapping context. Apple defines format 5's 26-bit
target as a VM address. The resolver returns it directly when it maps into the
selected image; otherwise it reports an unmapped target. It does not invent a
base or widen the encoded 26-bit target. These formats are accepted only in
32-bit slices.

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

For `DYLD_CHAINED_PTR_ARM64E_SEGMENTED` (format 14), the retained 4-bit target
segment index and 28-bit segment-relative offset produce an additional target
VM address only when the index names a parsed segment, the offset is within its
declared memory size, checked base addition succeeds, and the resulting address
maps in the image. Encrypted fixup bytes are not interpreted. The packed target
and authentication fields remain authoritative source data; this derivation does
not strip or validate pointer authentication and does not make the containing
fixup stream complete. Format 14's bit layout follows Apple's
[`fixup-chains.h`](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h).

Format reference: [Apple dyld chained fixup definitions](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h).

The firmware `__TEXT,__chain_starts` section is also retained as an indexed
table of raw 32-bit offsets. Apple's `fixup-chains.h` defines its header as a
pointer format, a start count, and one offset per chain; the expected formats
are 32_FIRMWARE (5) and ARM64E_KERNEL (7). Apple's `ld64` documentation
describes the offsets as file offsets by default, or VM offsets from `__TEXT`
when the section uses the VM-offset flag. The loader resolves the first pointer
location only when the declared coordinate maps unambiguously inside the
selected image and the pointer word is fully file-backed. Unknown formats,
coordinate flags, and raw offsets are preserved as incomplete rows. These
section records now drive bounded chain traversal and conservative target
resolution for supported little-endian firmware images; see
[firmware chain traversal](macho-firmware-chains.md). Unknown or incomplete
start rows remain inventory-only.

Sources: [Apple dyld `fixup-chains.h`](https://raw.githubusercontent.com/apple-oss-distributions/dyld/main/include/mach-o/fixup-chains.h)
and [Apple ld64 manual](https://github.com/apple-oss-distributions/ld64/blob/main/doc/man/man1/ld.1).
