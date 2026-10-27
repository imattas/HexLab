#pragma once
#include "hexlab/image/minidump_metadata.hpp"
#include <span>
#include <vector>

namespace hexlab::minidump_detail {
struct XstateFeatureInfo {
    std::uint8_t index = 0;
    std::uint32_t offset = 0, size = 0;
};
std::size_t context_prefix_size(std::uint16_t architecture);
MinidumpContext decode_context(std::uint16_t architecture, std::span<const std::byte> bytes,
                              std::uint32_t source_rva, std::uint32_t source_size,
                              std::uint32_t xstate_context_size = 0,
                              std::span<const XstateFeatureInfo> xstate_features = {});
}
