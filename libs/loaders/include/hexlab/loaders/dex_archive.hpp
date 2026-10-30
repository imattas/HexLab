#pragma once

#include "hexlab/loaders/dex.hpp"
#include "hexlab/loaders/jar.hpp"

namespace hexlab {

struct DexArchiveLimits {
    JarLimits zip{};
    std::size_t max_dex_members = 256;
    std::uint64_t max_total_dex_bytes = 512ULL * 1024 * 1024;
};

// One loaded DEX image from an Android APK. DEX 041 can contribute more than
// one logical member for a single ZIP entry; logical_member_index disambiguates
// those while the ZIP fields retain physical APK provenance.
struct DexArchiveImage {
    std::string entry_name;
    std::uint32_t archive_entry_index = 0, logical_member_index = 0;
    std::uint64_t data_offset = 0, compressed_size = 0, uncompressed_size = 0;
    std::uint32_t crc32 = 0;
    std::uint16_t compression_method = 0;
    LoadedImage loaded;
};

// Loads canonical Android multidex APK entries (`classes.dex`, then
// `classes2.dex`, etc.) using the bounded ZIP reader and the ordinary DEX
// parser. APK entry order is normalized by the numeric suffix.
HEXLAB_LOADERS_EXPORT Result<std::vector<DexArchiveImage>> load_android_dex_archive(
    const ByteStorage &, std::stop_token = {}, DexArchiveLimits = {});

} // namespace hexlab
