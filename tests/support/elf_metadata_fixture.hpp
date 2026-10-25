#pragma once
#include "elf_fixture.hpp"
namespace hexlab_test::elf_metadata_fixture {
using namespace elf_fixture;
inline constexpr std::size_t symbols_at = 1024, strings_at = 1536, relocations_at = 1792;
inline void links(std::vector<std::byte> &data, bool wide, bool big, std::size_t index, std::uint32_t link,
                  std::uint32_t info, std::uint64_t stride) {
    const auto at = 512 + index * (wide ? 64 : 40);
    put(data, at + (wide ? 40 : 24), link, 4, big);
    put(data, at + (wide ? 44 : 28), info, 4, big);
    put(data, at + (wide ? 56 : 36), stride, wide ? 8 : 4, big);
}
inline void symbol(std::vector<std::byte> &data, bool wide, bool big, std::size_t i, std::uint32_t name,
                   std::uint8_t info, std::uint16_t section_index, std::uint64_t value, std::uint64_t size) {
    const auto at = symbols_at + i * (wide ? 24 : 16);
    put(data, at, name, 4, big);
    put(data, at + (wide ? 4 : 12), info, 1);
    put(data, at + (wide ? 6 : 14), section_index, 2, big);
    put(data, at + (wide ? 8 : 4), value, wide ? 8 : 4, big);
    put(data, at + (wide ? 16 : 8), size, wide ? 8 : 4, big);
}
inline void relocation(std::vector<std::byte> &data, bool wide, bool rela, bool big, std::size_t index,
                       std::uint64_t offset, std::uint32_t type, std::uint32_t sym, std::uint64_t addend = 0) {
    const auto stride = wide ? (rela ? 24 : 16) : (rela ? 12 : 8);
    const auto word = wide ? 8u : 4u;
    const auto at = relocations_at + index * stride;
    put(data, at, offset, word, big);
    put(data, at + word, wide ? (std::uint64_t{sym} << 32) | type : (std::uint64_t{sym} << 8) | type, word, big);
    if (rela)
        put(data, at + 2 * word, addend, word, big);
}
inline std::vector<std::byte> relocatable(bool wide, bool rela, bool big = false) {
    auto data = object(wide, big);
    data.resize(4096);
    section(data, wide, 1, 1, 1, 6, 0, 256, 32, 16, big);
    section(data, wide, 2, 7, 1, 6, 0, 320, 4, 16, big);
    data[320] = std::byte{0x90};
    data[321] = std::byte{0xc3};
    constexpr std::string_view names("\0callee\0external\0tls\0abs\0", 25);
    for (std::size_t i = 0; i < names.size(); ++i)
        data[strings_at + i] = std::byte(names[i]);
    symbol(data, wide, big, 1, 1, 0x12, 2, 0, 2);
    symbol(data, wide, big, 2, 8, 0x12, 0, 0, 0);
    symbol(data, wide, big, 3, 17, 0x16, 3, 0, 4);
    symbol(data, wide, big, 4, 21, 0x10, 0xfff1, 0x1234, 0);
    section(data, wide, 5, 0, 2, 0, 0, symbols_at, 5 * (wide ? 24 : 16), wide ? 8 : 4, big);
    links(data, wide, big, 5, 6, 1, wide ? 24 : 16);
    section(data, wide, 6, 0, 3, 0, 0, strings_at, names.size(), 1, big);
    const auto stride = wide ? (rela ? 24 : 16) : (rela ? 12 : 8);
    section(data, wide, 7, 0, rela ? 4 : 9, 0, 0, relocations_at, 6 * stride, wide ? 8 : 4, big);
    links(data, wide, big, 7, 5, 1, stride);
    relocation(data, wide, rela, big, 0, 1, 2, 1, UINT64_MAX - 3);
    relocation(data, wide, rela, big, 1, 8, 1, 1, wide ? UINT64_C(0x8000000000000000) : 0x80000000);
    relocation(data, wide, rela, big, 2, 20, wide ? 0x12345678 : 254, 2, 17);
    relocation(data, wide, rela, big, 3, 24, 8, 0, 0);
    relocation(data, wide, rela, big, 4, wide ? UINT64_MAX : UINT32_MAX, 0, 0, 0);
    relocation(data, wide, rela, big, 5, 16, 4, 2, UINT64_MAX - 3);
    data[256] = std::byte{0xe8};
    put(data, 257, 0xfffffffc, 4, big);
    data[261] = std::byte{0xc3};
    put(data, 264, wide ? UINT64_C(0x8000000000000000) : 0x80000000, wide ? 8 : 4, big);
    put(data, 272, 0xfffffffc, 4, big);
    put(data, 280, 0, wide ? 8 : 4, big);
    return data;
}
} // namespace hexlab_test::elf_metadata_fixture
