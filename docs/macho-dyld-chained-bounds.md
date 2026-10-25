# Mach-O chained-fixup bounds and resolution

The loader decodes chained fixup imports, segment starts, page chains and
pointer records for supported little-endian 64-bit Mach-O images. It retains
raw pointer words and the source file/address coordinates. Rebase targets and
bind imports are exposed through the existing Mach-O dyld resolver; pointer
authentication remains metadata and is not applied. Kernel-cache formats 8
and 11 retain their encoded target information but stay unresolved without
the shared-cache base-pointer table.

The parser applies these hard limits before allocating symbol strings or
following chain records:

* 1,000,000 chained imports and 1,000,000 decoded pointer rows per image.
* 65,535 pages per segment-start record (the on-disk page-count field limit).
* 64 KiB per imported symbol name and 16 MiB of imported symbol bytes per
  chained-fixup stream.
* Pointer fields must fit wholly inside both their mapped segment and their
  declared fixup page. Multi-start entries must terminate within the bounded
  segment-start record.

Compressed symbol pools, unsupported import/symbol encodings, unsupported
pointer formats, malformed extents, and targets that require unavailable
runtime state leave the stream incomplete or fail parsing when the input is
structurally malformed. No decompression or guessed target base is attempted.

Format reference: [Apple dyld chained fixup definitions](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h).
