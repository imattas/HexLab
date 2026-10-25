#pragma once
#include "elf_metadata_fixture.hpp"
namespace hexlab_test::elf_dynamic_symbol_fixture {
using namespace elf_metadata_fixture;
inline constexpr std::size_t dynamic_at = 1536, sym = 2048, str = 1024, sysv = 4096, gnu = 4352, indices = 4608;
inline void tag(std::vector<std::byte> &data, bool wide, bool big, std::size_t index, std::uint64_t type,
                std::uint64_t value) {
    const auto word = wide ? 8u : 4u;
    put(data, dynamic_at + 2 * word * index, type, word, big);
    put(data, dynamic_at + 2 * word * index + word, value, word, big);
}
// mode0=explicit size,1=SysV,2=GNU,3=both hashes,4=unbounded,5=all bounds.
inline std::vector<std::byte> fixture(bool wide, bool big = false, unsigned mode = 0, bool sections = false,
                                      std::uint64_t stride = 0) {
    auto data = base(wide, big, 3);
    data.resize(8192);
    const auto address = wide ? UINT64_C(0x100000000) : UINT64_C(0x10000);
    if (!stride)
        stride = wide ? 24 : 16;
    program(data, wide, 0, 1, 0, address, data.size(), data.size(), 5, 4096, big);
    const std::vector<std::pair<std::uint64_t, std::uint64_t>> basic{
        {5, address + str}, {10, 18}, {6, address + sym}, {11, stride}};
    std::size_t count = 0;
    for (auto [type, value] : basic)
        tag(data, wide, big, count++, type, value);
    if (mode == 0 || mode == 5)
        tag(data, wide, big, count++, 39, 3 * stride);
    if (mode == 1 || mode == 3 || mode == 5)
        tag(data, wide, big, count++, 4, address + sysv);
    if (mode == 2 || mode == 3 || mode == 5)
        tag(data, wide, big, count++, 0x6ffffef5, address + gnu);
    tag(data, wide, big, count++, 0, 0);
    program(data, wide, 1, 2, dynamic_at, address + dynamic_at, count * (wide ? 16 : 8), count * (wide ? 16 : 8), 6,
            wide ? 8 : 4, big);
    constexpr std::string_view names("\0defined\0external\0", 18);
    for (std::size_t i = 0; i < names.size(); ++i)
        data[str + i] = std::byte(names[i]);
    for (std::size_t i = 1; i < 3; ++i) {
        const auto at = sym + i * stride;
        put(data, at, i == 1 ? 1 : 9, 4, big);
        put(data, at + (wide ? 4 : 12), 0x12, 1);
        put(data, at + (wide ? 6 : 14), i == 1 ? 12 : 0, 2, big);
        put(data, at + (wide ? 8 : 4), i == 1 ? address + 256 : 0, wide ? 8 : 4, big);
        put(data, at + (wide ? 16 : 8), i == 1 ? 2 : 0, wide ? 8 : 4, big);
    }
    data[256] = std::byte{0x90};
    data[257] = std::byte{0xc3};
    put(data, sysv, 1, 4, big);
    put(data, sysv + 4, 3, 4, big);
    put(data, sysv + 8, 1, 4, big);
    put(data, sysv + 16, 2, 4, big);
    put(data, gnu, 1, 4, big);
    put(data, gnu + 4, 1, 4, big);
    put(data, gnu + 8, 1, 4, big);
    put(data, gnu + 12, wide ? 6 : 5, 4, big);
    put(data, gnu + 16, wide ? UINT64_MAX : UINT32_MAX, wide ? 8 : 4, big);
    const auto buckets = gnu + 16 + (wide ? 8 : 4);
    put(data, buckets, 1, 4, big);
    put(data, buckets + 4, 0x088998d4, 4, big);
    put(data, buckets + 8, 0xdcf33929, 4, big);
    if (sections) {
        auto headers = base(wide, big, 3);
        headers.resize(2048);
        section(headers, wide, 0, 0, 0, 0, 0, 0, 0, 0, big);
        section(headers, wide, 1, 0, 11, 2, address + sym, sym, 3 * stride, wide ? 8 : 4, big);
        links(headers, wide, big, 1, 2, 1, stride);
        section(headers, wide, 2, 0, 3, 2, address + str, str, 18, 1, big);
        section(headers, wide, 3, 0, 6, 3, address + dynamic_at, dynamic_at, count * (wide ? 16 : 8), wide ? 8 : 4,
                big);
        links(headers, wide, big, 3, 2, 0, wide ? 16 : 8);
        // A real executable section backs the defined symbol's declared index.
        section(headers, wide, 12, 0, 1, 6, address + 256, 256, 2, 1, big);
        std::copy_n(headers.begin() + 512, 13 * (wide ? 64 : 40), data.begin() + 6144);
        put(data, wide ? 40 : 32, 6144, wide ? 8 : 4, big);
        put(data, wide ? 58 : 46, wide ? 64 : 40, 2, big);
        put(data, wide ? 60 : 48, 13, 2, big);
    }
    return data;
}
} // namespace hexlab_test::elf_dynamic_symbol_fixture
