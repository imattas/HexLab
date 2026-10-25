#pragma once
#include "macho_symbol_fixture.hpp"
namespace hexlab_test::macho_fixture {
inline std::uint32_t field32(const std::vector<std::byte> &data, std::size_t at, bool big = false) {
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4; ++i)
        value |= std::to_integer<std::uint32_t>(data[at + i]) << ((big ? 3 - i : i) * 8);
    return value;
}
inline std::size_t append_command(std::vector<std::byte> &data, bool wide, bool big, std::uint32_t type,
                                  std::uint32_t size) {
    const auto old = field32(data, 20, big);
    const auto at = (wide ? 32u : 28u) + old;
    put(data, 16, field32(data, 16, big) + 1, 4, big);
    put(data, 20, old + size, 4, big);
    put(data, at, type, 4, big);
    put(data, at + 4, size, 4, big);
    return at;
}
inline std::vector<std::byte> dyld(bool wide, bool big = false) {
    auto data = symbols(wide, big, false);
    const auto library = append_command(data, wide, big, 0xc, 32);
    put(data, library + 8, 24, 4, big);
    name(data, library + 24, "libOne");
    append_command(data, wide, big, 0x80000022, 48);
    return data;
}
inline std::size_t dyld_command(bool wide) { return symtab_command(wide) + 24 + 32; }
inline void stream(std::vector<std::byte> &data, bool wide, bool big, std::uint32_t kind,
                   std::initializer_list<unsigned> values) {
    const auto at = 2600 + kind * 100;
    put(data, dyld_command(wide) + 8 + kind * 8, at, 4, big);
    put(data, dyld_command(wide) + 12 + kind * 8, values.size(), 4, big);
    std::size_t index = 0;
    for (const auto value : values)
        data[at + index++] = std::byte(value);
}
} // namespace hexlab_test::macho_fixture
