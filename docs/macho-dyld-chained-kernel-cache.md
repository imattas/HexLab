# Mach-O chained kernel-cache pointer records

The chained-fixup loader recognizes `DYLD_CHAINED_PTR_64_KERNEL_CACHE` (format 8) and `DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE` (format 11) in 64-bit little-endian images. It follows their page chains using the format-specific stride (4 bytes for format 8, 1 byte for format 11), validates each pointer field against its segment and page, and retains the raw word, 30-bit target payload, two-bit cache level, next-link distance, and authentication metadata with original file/address provenance. Callers can supply the four cache-level bases to `resolve_macho_chained_external_targets`; it computes `basePointers[cacheLevel] + target` with overflow and encoding checks.

The same resolver accepts format 4 (`DYLD_CHAINED_PTR_32_CACHE`) using the caller-supplied `shared_cache_base`. This 32-bit chain stores a 30-bit target offset and a two-bit next distance; the resolver returns the checked sum of the supplied cache base and that target. It does not infer a cache base from the Mach-O image or validate cache membership.

It also recognizes `DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE` (format 13). Its 8-byte-stride chains retain the 34-bit shared-cache target offset, 11-bit next distance, and either the high byte or the diversity, address-diversity and IA/DA key fields. Nonzero reserved bits in unauthenticated words mark the row incomplete. A caller-supplied shared-cache base resolves unauthenticated offsets and preserves the encoded high byte; source file and mapped-address provenance remain available.

Formats 8 and 11 compute a target from `basePointers[cacheLevel] + target`. Format 4 computes `shared_cache_base + target`. The loader does not discover a dyld shared-cache base-pointer table or model cache membership, so it marks each decoded pointer and containing fixup stream incomplete. The explicit resolver accepts caller-supplied bases, and `hexlab_cli macho chained-targets` reports derived addresses separately from the Mach-O image address space. These addresses are not emitted as normal image cross-references. Authentication is recorded as metadata and is never applied.

Format 13 offsets are relative to the shared cache rather than this Mach-O image. The loader likewise marks them incomplete; the explicit resolver computes a separate cache address when the caller supplies the base. Authenticated rows report only the computed pre-PAC address, which is not a usable signed pointer.

The CLI syntax is `macho chained-targets <image> [--shared-cache-base <address>] [--cache-level-base <0..3> <address>]...`; addresses accept decimal or `0x` hexadecimal input. The API and CLI report unresolved rows when a required base is absent and reject reserved encodings, encrypted or overlapping source fields, and address overflow. The external-base operation is bounded to at most one million pointer rows and outputs at most 1,024 CLI rows. It does not discover cache files, establish that the supplied base belongs to the selected image, load cache subimages, apply cache slide formats, create runtime pointers, or apply/validate PAC. Kernel-cache containers and other cache metadata remain unsupported.

Format references: [Apple dyld chained fixup definitions](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h) and [Apple kernel documentation for `dyld_chained_ptr_64_kernel_cache_rebase`](https://developer.apple.com/documentation/kernel/dyld_chained_ptr_64_kernel_cache_rebase).

## Preferred-image-base offset rebases

Formats 6 (`DYLD_CHAINED_PTR_64_OFFSET`), 9 (`DYLD_CHAINED_PTR_ARM64E_USERLAND`),
7 (`DYLD_CHAINED_PTR_ARM64E_KERNEL`), and 12 (`DYLD_CHAINED_PTR_ARM64E_USERLAND24`) now resolve complete,
unauthenticated rebases against the lowest mapped segment address in the
preferred image. The decoded target and high-byte fields are retained
separately; a target address is published only when the assembled address is
inside a mapped segment and backed by plaintext file data. This does not apply
a load slide, resolve binds, interpret authenticated targets, validate PAC, or
guess kernel/shared-cache bases. Authenticated rebases retain their target,
diversity, address-diversity and key metadata but remain without a resolved
address until a runtime authentication context is supplied.

Format 7 uses the ARM64E kernel encoding with a four-byte chain stride; Apple
defines its unauthenticated target as a VM offset. This in-image resolution
only applies when the offset produces a mapped, plaintext address in the
preferred image. It does not supply an external kernel or shared-cache base.

Format references: [Apple dyld chained-fixup definitions](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h).

## In-image vmaddr chained rebases

For unencrypted, complete, unauthenticated, non-bind rebases in pointer formats 1 (ARM64E), 2 (64), 3 (32), 5 (32 firmware), and 10 (ARM64E firmware), the loader now combines the encoded high byte with the target payload and records a resolved target address only when it falls inside a mapped image segment. The raw word and encoded fields remain available. This does not apply authentication or resolve image-relative, shared-cache-relative, cache-base-dependent, or segmented targets; encrypted bytes and malformed/reserved encodings remain unresolved.

Format references: [Apple dyld chained fixup definitions](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h) and [Apple kernel documentation for `dyld_chained_ptr_64_kernel_cache_rebase`](https://developer.apple.com/documentation/kernel/dyld_chained_ptr_64_kernel_cache_rebase).
