#pragma once

#include "hexlab/image/byte_storage.hpp"
#include "hexlab/loaders/loaded_image.hpp"
#include <array>
#include <stop_token>
#include <vector>

namespace hexlab {

struct DexContainerMember {
    std::uint32_t header_offset = 0;
    std::uint32_t logical_file_size = 0;
    std::array<std::byte, 20> signature{};
    std::uint32_t checksum = 0;
    bool operator==(const DexContainerMember &) const = default;
};

// Enumerates sequential DEX 041 logical headers in a physical container.
// Structural inventory only: load_dex still performs full parsing and
// currently accepts single-member 041 inputs.
HEXLAB_LOADERS_EXPORT Result<std::vector<DexContainerMember>>
inspect_dex041_container(const ByteStorage &, std::stop_token = {});

} // namespace hexlab
