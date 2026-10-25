# Mach-O chained kernel-cache pointer records

The chained-fixup loader recognizes `DYLD_CHAINED_PTR_64_KERNEL_CACHE` (format 8) and `DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE` (format 11) in 64-bit little-endian images. It follows their page chains using the format-specific stride (4 bytes for format 8, 1 byte for format 11), validates each pointer field against its segment and page, and retains the raw word, 30-bit target payload, next-link distance, and authentication metadata with the original file/address provenance.

These formats compute a target from `basePointers[cacheLevel] + target`. This loader does not yet load a dyld shared-cache base-pointer table or model cache membership, so it deliberately marks each decoded pointer and containing fixup stream incomplete. The raw cache-level field remains available in the original word; such a target is never presented as a resolved image address or emitted as a normal cross-reference. Authentication is recorded as metadata and is never applied.

This support is structural parsing only. Chained starts in kernel-cache containers, cache subimages, cache slide formats, target-base resolution, and authentication remain outside this feature.

Format reference: [Apple dyld chained fixup definitions](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h).
