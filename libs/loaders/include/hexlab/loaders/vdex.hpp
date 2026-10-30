#pragma once
#include "hexlab/core/result.hpp"
#include "hexlab/image/byte_storage.hpp"
#include "hexlab/loaders/loaders_export.hpp"
#include <cstddef>
#include <cstdint>
#include <stop_token>
#include <vector>

namespace hexlab {
struct AndroidVdexSection {
    std::uint32_t kind = 0;
    FileOffset file_offset{};
    std::uint32_t size = 0;
};
struct AndroidVdexDexMember {
    std::uint32_t index = 0;
    FileOffset header_file_offset{};
    std::uint32_t file_size = 0;
    std::uint32_t header_checksum = 0;
    std::uint32_t vdex_checksum = 0;
    std::uint32_t version = 0;
    bool checksum_fields_match = false;
};
struct AndroidVdexInventory {
    std::uint32_t version = 27;
    FileOffset file_size{};
    std::vector<AndroidVdexSection> sections;
    std::vector<AndroidVdexDexMember> dex_members;
    std::uint32_t dex_checksum_count = 0;
    bool dex_section_present = false;
};
struct AndroidVdexLimits {
    std::uint64_t max_input_bytes = 512ULL * 1024 * 1024;
    std::uint32_t max_dex_files = 65'536;
};

// Inventories the sectioned VDEX 027 container and its optional concatenated
// DEX 035-040 members. Verifier and type-lookup data remain opaque.
HEXLAB_LOADERS_EXPORT Result<AndroidVdexInventory> inspect_android_vdex_027(
    const ByteStorage &, std::stop_token = {}, AndroidVdexLimits = {});
} // namespace hexlab
