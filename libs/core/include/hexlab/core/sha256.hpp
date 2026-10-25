#pragma once
#include "hexlab/core/core_export.hpp"
#include "hexlab/core/result.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace hexlab {
using Sha256Digest=std::array<std::byte,32>;
class Sha256 {
public:
    HEXLAB_CORE_EXPORT Result<std::uint64_t> update(std::span<const std::byte>);
    HEXLAB_CORE_EXPORT Sha256Digest digest() const noexcept;
    std::uint64_t bytes() const noexcept{return total_;}
private:
    void compress(const std::byte*) noexcept;
    std::array<std::uint32_t,8> state_{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    std::array<std::byte,64> tail_{};
    std::size_t used_=0;
    std::uint64_t total_=0;
};
HEXLAB_CORE_EXPORT std::string digest_hex(const Sha256Digest&);
}
