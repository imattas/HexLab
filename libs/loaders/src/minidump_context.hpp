#pragma once
#include "hexlab/image/minidump_metadata.hpp"
#include <span>

namespace hexlab::minidump_detail {
std::size_t context_prefix_size(std::uint16_t architecture);
MinidumpContext decode_context(std::uint16_t architecture, std::span<const std::byte> bytes,
                              std::uint32_t source_rva, std::uint32_t source_size);
}
