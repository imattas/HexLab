#pragma once
#include "hexlab/core/core_export.hpp"
#include "hexlab/core/result.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
namespace hexlab {
HEXLAB_CORE_EXPORT std::array<std::byte,8> encode_u64(std::uint64_t) noexcept;
HEXLAB_CORE_EXPORT Result<std::uint64_t> decode_u64(std::span<const std::byte>);
}
