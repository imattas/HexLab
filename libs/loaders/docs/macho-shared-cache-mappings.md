# Mach-O dyld shared-cache mapping inventory

`inspect_macho_shared_cache_mappings` reads the little-endian `dyld_v1` magic,
the legacy `dyld_cache_header` mapping-table prefix, and bounded
`dyld_cache_mapping_info` rows. It validates the printable architecture
suffix, table bounds, nonzero VM/file extents, checked address arithmetic,
mapping protection bits, and nonoverlapping VM ranges. The parser sorts its
result by unslid VM address. It reads only the mapping table and does not
materialize cache contents.

`macho_shared_cache_file_offset` translates a nonempty VM range only when the
whole range lies inside one mapping. A range that crosses mappings is rejected
because its file-backed bytes may not be contiguous. This is enough to inspect
mapped bytes in a single cache file when a caller already has that file; it
does not combine split-cache companions or apply slide information.

The inspection is capped at 65,536 mappings and 4 MiB of table metadata by
default, and accepts caller cancellation. It does not parse image path tables,
subcache UUIDs, symbols, local symbols, code signatures, slide-info formats,
or chained fixups. For chained pointer base resolution, continue to supply
explicit cache bases to `resolve_macho_chained_external_targets`.

Format references: [Apple dyld shared-cache format](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h).
