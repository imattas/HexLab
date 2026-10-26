# Mach-O chained kernel-cache pointer records

The chained-fixup loader recognizes `DYLD_CHAINED_PTR_64_KERNEL_CACHE` (format 8) and `DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE` (format 11) in 64-bit little-endian images. It follows their page chains using the format-specific stride (4 bytes for format 8, 1 byte for format 11), validates each pointer field against its segment and page, and retains the raw word, 30-bit target payload, next-link distance, and authentication metadata with the original file/address provenance.

It also recognizes `DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE` (format 13). Its 8-byte-stride chains retain the 34-bit shared-cache target offset, 11-bit next distance, and either the high byte or the diversity, address-diversity and IA/DA key fields. The reserved bits stay in the raw word. Source file and mapped-address provenance are retained.

Formats 8 and 11 compute a target from `basePointers[cacheLevel] + target`. This loader does not yet load a dyld shared-cache base-pointer table or model cache membership, so it deliberately marks each decoded pointer and containing fixup stream incomplete. The raw cache-level field remains available in the original word; such a target is never presented as a resolved image address or emitted as a normal cross-reference. Authentication is recorded as metadata and is never applied.

Format 13 offsets are relative to the shared cache rather than this Mach-O image. The loader likewise marks them incomplete and never converts them to image addresses without a shared-cache base. Authentication remains metadata.

This support is structural parsing only. Chained starts in kernel-cache containers, cache subimages, cache slide formats, target-base resolution, and authentication remain outside this feature.

Format reference: [Apple dyld chained fixup definitions](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h).
