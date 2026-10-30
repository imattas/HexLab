#pragma once

#include "hexlab/image/byte_storage.hpp"
#include "hexlab/loaders/loaders_export.hpp"
#include "hexlab/core/result.hpp"
#include <cstddef>
#include <cstdint>
#include <stop_token>
#include <vector>

namespace hexlab {

struct ApkSigningBlockPair {
    std::uint32_t id = 0;
    std::uint64_t file_offset = 0;
    std::vector<std::byte> value;
};

struct ApkSigningBlock {
    bool present = false;
    std::uint64_t central_directory_offset = 0;
    std::uint64_t block_offset = 0;
    std::uint64_t block_size = 0;
    std::vector<ApkSigningBlockPair> pairs;
};

struct ApkSigningBlockLimits {
    std::uint64_t max_block_bytes = 64ULL * 1024 * 1024;
    std::uint64_t max_pair_value_bytes = 64ULL * 1024 * 1024;
    std::size_t max_pairs = 4096;
};

// Locates an APK Signing Block using the ZIP EOCD central-directory offset,
// validates the mirrored size/footer and pair framing, and preserves pair
// values without interpreting or verifying signature schemes.
HEXLAB_LOADERS_EXPORT Result<ApkSigningBlock> inspect_apk_signing_block(
    const ByteStorage &, std::stop_token = {}, ApkSigningBlockLimits = {});

} // namespace hexlab
