#pragma once
#include "macho_dyld_fixture.hpp"
namespace hexlab_test::macho_fixture {
inline constexpr std::uint32_t chains_at = 3000;
inline std::vector<std::byte> chained(bool wide = true, std::uint16_t pointer_format = 2,
                                      std::uint32_t import_format = 1) {
    auto data = dyld(wide);
    const auto header = wide ? 32u : 28u;
    const auto base = wide ? UINT64_C(0x100000000) : UINT64_C(0x1000);
    segment(data, wide, false, header, base - 768, 4096, 0, 4096, 7, 0, 3);
    const auto bss = header + (wide ? 72u : 56u) + 2 * (wide ? 80u : 68u);
    put(data, bss + (wide ? 48 : 40), 784, 4, false);
    put(data, bss + (wide ? 64 : 56), 0, 4, false);
    const auto command = append_command(data, wide, false, 0x80000034, 16);
    put(data, command + 8, chains_at, 4, false);
    put(data, command + 12, 96, 4, false);
    put(data, chains_at + 4, 28, 4, false);
    put(data, chains_at + 8, 64, 4, false);
    put(data, chains_at + 12, 80, 4, false);
    put(data, chains_at + 16, 1, 4, false);
    put(data, chains_at + 20, import_format, 4, false);
    put(data, chains_at + 28, 1, 4, false);
    put(data, chains_at + 32, 8, 4, false);
    put(data, chains_at + 36, 24, 4, false);
    put(data, chains_at + 40, 4096, 2, false);
    put(data, chains_at + 42, pointer_format, 2, false);
    put(data, chains_at + 52, 0x3ffffff, 4, false);
    put(data, chains_at + 56, 1, 2, false);
    put(data, chains_at + 58, 768, 2, false);
    put(data, chains_at + 64, import_format == 3 ? UINT64_C(0x1fffe) : UINT64_C(0x101), import_format == 3 ? 8 : 4,
        false);
    if (import_format == 2)
        put(data, chains_at + 68, UINT32_C(0xfffffffd), 4, false);
    if (import_format == 3)
        put(data, chains_at + 72, UINT64_MAX - 6, 8, false);
    for (std::size_t i = 0; i < 5; ++i)
        data[chains_at + 80 + i] = std::byte("_ext"[i]);
    if (pointer_format == 3) {
        put(data, 768, (UINT64_C(1) << 26) | (base + 8), 4, false);
        put(data, 772, (UINT64_C(1) << 31) | (UINT64_C(63) << 20), 4, false);
    } else {
        put(data, 768, (UINT64_C(2) << 51) | (pointer_format == 6 ? 776 : base + 8), 8, false);
        put(data, 776, (UINT64_C(1) << 63) | (UINT64_C(255) << 24), 8, false);
    }
    return data;
}
inline void compress_chained_symbol_pool(std::vector<std::byte> &data) {
    // The compressed pool occupies the tail of the declared fixups payload;
    // the zlib stream expands to the same NUL-terminated `_ext` name.
    put(data, chains_at + 12, 80, 4, false);
    put(data, chains_at + 24, 1, 4, false);
    put(data, dyld_command(true) + 48 + 12, 93, 4, false);
    constexpr unsigned compressed[]{120, 156, 139, 79, 173, 40, 97, 0, 0, 5, 196, 1, 177};
    for (std::size_t i = 0; i < sizeof(compressed) / sizeof(compressed[0]); ++i)
        data[chains_at + 80 + i] = std::byte(compressed[i]);
}
} // namespace hexlab_test::macho_fixture
