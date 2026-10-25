#pragma once
#include "elf_metadata_fixture.hpp"
namespace hexlab_test::elf_metadata_fixture {
inline std::vector<std::byte> retained(bool wide, bool rela, bool debug = false, std::uint16_t type = 2) {
    auto data = relocatable(wide, rela);
    put(data, 16, type, 2);
    constexpr std::uint64_t base = 0x400000;
    program(data, wide, 0, 1, 256, base, 6, 6, 5, 1);
    program(data, wide, 1, 1, 320, base + 6, 16, 16, 5, 1);
    put(data, 24, base, wide ? 8 : 4);
    section(data, wide, 1, 1, 1, 6, base, 256, 6, 1);
    section(data, wide, 2, 7, 1, 6, base + 6, 320, 16, 1);
    symbol(data, wide, false, 1, 1, 0x12, 2, base + 6, 16);
    // The linked displacement is1; the original addend was -4.
    put(data, 257, 1, 4);
    for (std::size_t i = 320; i < 335; ++i)
        data[i] = std::byte{0x90};
    data[335] = std::byte{0xc3};
    const auto stride = (rela ? 3u : 2u) * (wide ? 8u : 4u);
    section(data, wide, 7, 0, rela ? 4 : 9, 0, 0, relocations_at, stride, 4);
    links(data, wide, false, 7, 5, debug ? 3 : 1, stride);
    if (debug)
        section(data, wide, 3, 0, 1, 0, 0, 2048, 32, 1);
    relocation(data, wide, rela, false, 0, debug ? 8 : base + 1, debug ? 1 : 2, 1, UINT64_MAX - 3);
    return data;
}
inline std::vector<std::byte> many_domains(std::uint32_t count) {
    auto data = base(true, false, 1);
    data.resize(512 + (std::size_t(count) + 1) * 64);
    section(data, true, 0, 0, 0, 0, 0, 0, 0);
    data[256] = std::byte{0xc3};
    for (std::uint32_t index = 1; index <= count; ++index)
        section(data, true, index, 0, 1, 6, 0, 256, 1);
    return data;
}
} // namespace hexlab_test::elf_metadata_fixture
