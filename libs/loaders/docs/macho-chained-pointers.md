# Mach-O chained fixup pointer formats

The loader decodes the chained pointer formats defined by Apple's
`mach-o/fixup-chains.h` with per-record field bounds and provenance. Pointer
words are read only when every byte maps contiguously into the selected image;
encrypted words retain their raw value but are not interpreted as chain links
or addresses. Unknown formats and truncated chain fields remain incomplete.

| Format | Name | Decoded behavior |
| ---: | --- | --- |
| 1 | `ARM64E` | Bind/rebase fields, signed bind addends, and PAC key/diversity metadata. Unauthenticated VM-address rebases may resolve in-image. |
| 2 | `64` | Bind/rebase fields, unsigned 8-bit bind addend, high byte, and VM-address target. |
| 3 | `32` | Bind/rebase fields, unsigned 6-bit addend, and `max_valid_pointer` scalar restoration. |
| 4 | `32_CACHE` | 30-bit shared-cache-relative target and 2-bit chain step; target stays unresolved until a caller supplies the shared-cache base. |
| 5 | `32_FIRMWARE` | Firmware VM-address target and chain step. |
| 6 | `64_OFFSET` | Image-relative offset, bind fields, and high byte. |
| 7 | `ARM64E_KERNEL` | Offset target, signed bind addend, and PAC metadata; authenticated values are not materialized. |
| 8 | `64_KERNEL_CACHE` | Cache-level target, authentication metadata, and chain step; remains unresolved without cache bases. |
| 9 | `ARM64E_USERLAND` | Offset target, signed bind addend, and PAC metadata. |
| 10 | `ARM64E_FIRMWARE` | VM-address target, signed bind addend, and PAC metadata. |
| 11 | `X86_64_KERNEL_CACHE` | Cache-level target, authentication metadata, and byte chain step; remains unresolved without cache bases. |
| 12 | `ARM64E_USERLAND24` | Like format 9, with a 24-bit import ordinal. |
| 13 | `ARM64E_SHARED_CACHE` | Shared-cache-relative target and the format's A/IA/DA authentication key encoding; remains unresolved without a cache base. |
| 14 | `ARM64E_SEGMENTED` | Packed segment index/offset target and 4-byte chain stride. Valid records are complete; target addresses are populated only when the segment index and offset map into the image. |

Authenticated records preserve the encoded target and available key,
diversity, and address-diversity fields. The loader does not authenticate,
sign, or strip pointer authentication codes: those operations require runtime
keys or signing context. Cache-relative formats likewise preserve their base
kind and encoded target without guessing an unavailable shared-cache/kernel
base. For format 14, unauthenticated records with nonzero reserved bits are
retained but marked incomplete; authenticated records interpret the same bits
as PAC metadata.

Format 4 can be resolved with `resolve_macho_chained_external_targets` when a
caller supplies `shared_cache_base`. The result is the base plus the encoded
30-bit target, with overflow checked and the chain's original file/address
provenance retained. The CLI exposes it through `macho chained-targets
<image> --shared-cache-base <address>`. This does not discover a cache file or
verify that the supplied base is the cache containing the image.

The wire layouts and format names follow Apple's
[`fixup-chains.h`](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h).
