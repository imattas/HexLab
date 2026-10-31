#pragma once

#include "hexlab/image/byte_storage.hpp"
#include "hexlab/loaders/loaders_export.hpp"
#include <cstddef>
#include <cstdint>
#include <stop_token>
#include <string>
#include <vector>

namespace hexlab {

struct MachOSharedCacheMapping {
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    std::uint64_t file_offset = 0;
    std::uint32_t max_protection = 0;
    std::uint32_t initial_protection = 0;
    bool operator==(const MachOSharedCacheMapping &) const = default;
};

struct MachOSharedCacheInfo {
    std::string magic;
    std::vector<MachOSharedCacheMapping> mappings;
};

struct MachOSharedCacheLimits {
    std::uint32_t max_mappings = 65'536;
    std::uint64_t max_metadata_bytes = 4 * 1024 * 1024;
};

// Inspects the legacy mapping table in one little-endian dyld_v1 shared-cache
// file. Split-cache companions and cache contents are not loaded or rewritten.
HEXLAB_LOADERS_EXPORT Result<MachOSharedCacheInfo> inspect_macho_shared_cache_mappings(
    const ByteStorage &, std::stop_token = {}, MachOSharedCacheLimits = {});

// Maps a complete non-empty VM-address range wholly inside one cache mapping.
// Cross-mapping ranges are rejected because their file extents need not be
// contiguous.
HEXLAB_LOADERS_EXPORT Result<FileOffset> macho_shared_cache_file_offset(
    const MachOSharedCacheInfo &, std::uint64_t address, std::uint64_t size);

} // namespace hexlab
