#pragma once
#include "macho_fixture.hpp"
namespace hexlab_test::macho_fixture {
inline constexpr std::size_t symbols_at = 1536, strings_at = 2048;
inline std::size_t symtab_command(bool wide) {
    return (wide ? 32u : 28u) + (wide ? 72u : 56u) + 3 * (wide ? 80u : 68u);
}
inline void symbol(std::vector<std::byte> &data, bool wide, bool big, std::uint32_t index, std::uint32_t string,
                   std::uint8_t type, std::uint8_t section, std::uint16_t descriptor, std::uint64_t value) {
    const auto at = symbols_at + index * (wide ? 16 : 12);
    put(data, at, string, 4, big);
    put(data, at + 4, type, 1, big);
    put(data, at + 5, section, 1, big);
    put(data, at + 6, descriptor, 2, big);
    put(data, at + 8, value, wide ? 8 : 4, big);
}
inline std::vector<std::byte> symbols(bool wide, bool big = false, bool object = true) {
    auto data = mapped(wide, big, object);
    data.resize(4096);
    const auto command = symtab_command(wide);
    const auto header = wide ? 32u : 28u;
    put(data, 16, 2, 4, big);
    put(data, 20, command - header + 24, 4, big);
    put(data, 24, object ? 0x2000 : 0x2080, 4, big);
    put(data, command, 2, 4, big);
    put(data, command + 4, 24, 4, big);
    put(data, command + 8, symbols_at, 4, big);
    put(data, command + 12, 9, 4, big);
    put(data, command + 16, strings_at, 4, big);
    put(data, command + 20, 64, 4, big);
    const std::string names("\0_same\0_external\0_absolute\0_common\0_alias\0_debug\0\xff\x01\0_weak\0", 58);
    for (std::size_t i = 0; i < names.size(); ++i)
        data[strings_at + i] = std::byte(names[i]);
    const auto base = object ? UINT64_C(0x100) : wide ? UINT64_C(0x100000000) : UINT64_C(0x1000);
    symbol(data, wide, big, 0, 1, 0x0f, 1, 0, base);
    symbol(data, wide, big, 1, 1, 0x0f, 2, 0, object ? base : base + 8);
    symbol(data, wide, big, 2, 7, 0x01, 0, 0x0340, 0);
    symbol(data, wide, big, 3, 17, 0x03, 0, 0, wide ? UINT64_C(0xfedcba9876543210) : UINT64_C(0x76543210));
    symbol(data, wide, big, 4, 27, 0x01, 0, 0x0300, 64);
    symbol(data, wide, big, 5, 35, 0x0b, 0, 0, 1);
    symbol(data, wide, big, 6, 42, 0x64, 1, 0, base);
    symbol(data, wide, big, 7, 49, 0x0f, 3, 0, base + 17);
    symbol(data, wide, big, 8, 52, 0x1f, 1, 0x0280, base + 2);
    data[770] = std::byte{0xc3};
    return data;
}
} // namespace hexlab_test::macho_fixture
