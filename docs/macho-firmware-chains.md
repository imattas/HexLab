# Mach-O firmware chain traversal

The loader follows `__TEXT,__chain_starts` records for little-endian linked
32-bit `DYLD_CHAINED_PTR_32_FIRMWARE` (5) and 64-bit
`DYLD_CHAINED_PTR_ARM64E_KERNEL` (7) images. The existing start-row inventory
continues to retain each raw offset, section/index identity, coordinate flag
and source record offset. File-offset coordinates are relative to the selected
slice; VM-offset coordinates are relative to its unique `__TEXT` segment.

`MachOMetadata::firmware_chained_pointers` now exposes the walked nodes.
`MachOFirmwareChainedPointer::chain_start_row` indexes the original start row;
`node_index` retains the traversal order. Each node preserves its source VM/file
location, exact word, field width, next/stride values, target payload and
authentication/bind metadata. These nodes have their own namespace and do not
claim an `LC_DYLD_CHAINED_FIXUPS` header or import table. Source bytes are
reparsed when the image is reopened.

`MachOChainStartOffset::first_pointer_row` identifies its first decoded node,
and `pointer_count` gives its total decoded nodes. Physical-file-order processing
can interleave rows from different chains, so callers select all nodes using
`chain_start_row`; the count is not a contiguous vector extent. `chain_complete`
means the chain reached a zero next field without a structural failure. The
existing start-row `complete` flag still describes the start declaration and
coordinate mapping. A complete traversal does not imply that every target can
be resolved.

With file-offset start coordinates, unauthenticated format-5 targets use their
direct 26-bit VM address; format-7 targets combine the 43-bit payload and
retained high byte, then apply the canonical mapped Mach-O header address.
With VM-offset coordinates, both formats' rebase payloads are offsets from the
unique `__TEXT` segment base, matching the linker option's documented semantics.
Start offsets may locate pointers in any mapped segment, including `__DATA`;
they are not constrained to the `__TEXT` segment's own extent. All base
arithmetic checks overflow. A
`target_address` is published only when the resulting address maps in the
selected image. Missing anchors, overflow and unmapped targets retain the raw
payload without a resolved address. Authenticated and bind nodes retain their
metadata and remain unresolved: no PAC is stripped, applied or validated, and
no runtime binding or library lookup is performed.

Both formats advance in four-byte units, while format 7 occupies an eight-byte
word. The same four-byte stride correction applies to formats 7 and 10 in the
existing `LC_DYLD_CHAINED_FIXUPS` walker, matching the original-word checks in
persisted dyld provenance. Every firmware node must remain within its starting
mapped segment and selected slice, and its entire field must have contiguous
file backing. A priority queue reads fields in physical file order. Duplicate,
converging and overlapping firmware chains invalidate the affected nodes and
chain completion flags. Ciphertext is retained as an incomplete raw word and
is never interpreted as a next link. Unbacked fields and invalid next extents
stop traversal and mark dyld metadata incomplete.

Firmware and load-command chained pointers share a 1,000,000-node limit. All
queued work, decoded nodes and overlap indexes charge the loader's cumulative
64 MiB metadata budget; cancellation is checked between records. No source
bytes are patched. These firmware nodes currently expose loader metadata;
the analysis dyld slot resolver and persisted dyld-reference provenance still
consume the existing load-command chains only. Shared-cache targets, segmented
address tables, unknown coordinate flags and other firmware pointer formats
remain unsupported.

The layouts and stride rules follow
[Apple's dyld fixup-chain definitions](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h)
and the pointer-format implementations in
[Apple's ChainedFixups.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/ChainedFixups.cpp).
The VM-offset coordinate and target rules are documented in
[Apple's ld64 manual](https://github.com/apple-oss-distributions/ld64/blob/main/doc/man/man1/ld-classic.1).
