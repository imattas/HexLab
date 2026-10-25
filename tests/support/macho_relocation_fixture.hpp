#pragma once
#include "macho_symbol_fixture.hpp"
namespace hexlab_test::macho_fixture {
inline constexpr std::size_t relocations_at = 3072;
inline void relocation(std::vector<std::byte> &data, bool big, std::uint32_t index, std::uint32_t offset,
                       std::uint32_t target, std::uint8_t type, std::uint8_t length, bool pc, bool external) {
    put(data, relocations_at + index * 8, offset, 4, big);
    const auto info = big ? (target << 8) | (std::uint32_t(pc) << 7) | (std::uint32_t(length) << 5) |
                                (std::uint32_t(external) << 4) | type
                          : target | (std::uint32_t(pc) << 24) | (std::uint32_t(length) << 25) |
                                (std::uint32_t(external) << 27) | (std::uint32_t(type) << 28);
    put(data, relocations_at + index * 8 + 4, info, 4, big);
}
inline void relocation_count(std::vector<std::byte> &data, bool wide, bool big, std::uint32_t count,
                             std::uint32_t ordinal = 1) {
    const auto section = (wide ? 32u : 28u) + (wide ? 72u : 56u) + (ordinal - 1) * (wide ? 80u : 68u);
    put(data, section + (wide ? 56 : 48), relocations_at, 4, big);
    put(data, section + (wide ? 60 : 52), count, 4, big);
}
inline std::vector<std::byte> relocated(bool wide, bool big = false) {
    auto data = symbols(wide, big);
    relocation_count(data, wide, big, 1);
    relocation(data, big, 0, 1, 1, wide ? 2 : 0, 2, true, true);
    data[768] = std::byte{0xe8};
    put(data, 769, wide ? 0 : 0xfffffefb, 4, big);
    data[773] = std::byte{0xc3};
    return data;
}
} // namespace hexlab_test::macho_fixture
