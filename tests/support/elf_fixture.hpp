#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>
namespace hexlab_test::elf_fixture {
inline void put(std::vector<std::byte> &data, std::size_t at, std::uint64_t value, std::size_t n, bool big = false) {
    for (std::size_t i = 0; i < n; ++i)
        data.at(at + i) = std::byte(value >> (8 * (big ? n - 1 - i : i)));
}
inline std::uint16_t count(const std::vector<std::byte> &data, std::size_t at, bool big) {
    const auto a = std::to_integer<std::uint16_t>(data.at(at));
    const auto b = std::to_integer<std::uint16_t>(data.at(at + 1));
    return static_cast<std::uint16_t>(big ? (a << 8) | b : a | (b << 8));
}
inline std::vector<std::byte> base(bool wide, bool big = false, std::uint16_t type = 2) {
    std::vector<std::byte> data(1024);
    data[0] = std::byte{0x7f};
    data[1] = std::byte{'E'};
    data[2] = std::byte{'L'};
    data[3] = std::byte{'F'};
    data[4] = std::byte(wide ? 2 : 1);
    data[5] = std::byte(big ? 2 : 1);
    data[6] = std::byte{1};
    put(data, 16, type, 2, big);
    put(data, 18, wide ? 62 : 3, 2, big);
    put(data, 20, 1, 4, big);
    put(data, wide ? 52 : 40, wide ? 64 : 52, 2, big);
    return data;
}
inline void program(std::vector<std::byte> &data, bool wide, std::size_t index, std::uint32_t type,
                    std::uint64_t offset, std::uint64_t address, std::uint64_t file_size, std::uint64_t memory_size,
                    std::uint32_t flags = 5, std::uint64_t alignment = 1, bool big = false) {
    const auto at = (wide ? 64 : 52) + index * (wide ? 56 : 32);
    put(data, wide ? 32 : 28, wide ? 64 : 52, wide ? 8 : 4, big);
    put(data, wide ? 54 : 42, wide ? 56 : 32, 2, big);
    put(data, wide ? 56 : 44, std::max<std::size_t>(index + 1, count(data, wide ? 56 : 44, big)), 2, big);
    put(data, at, type, 4, big);
    if (wide) {
        put(data, at + 4, flags, 4, big);
        put(data, at + 8, offset, 8, big);
        put(data, at + 16, address, 8, big);
        put(data, at + 32, file_size, 8, big);
        put(data, at + 40, memory_size, 8, big);
        put(data, at + 48, alignment, 8, big);
    } else {
        put(data, at + 4, offset, 4, big);
        put(data, at + 8, address, 4, big);
        put(data, at + 16, file_size, 4, big);
        put(data, at + 20, memory_size, 4, big);
        put(data, at + 24, flags, 4, big);
        put(data, at + 28, alignment, 4, big);
    }
}
inline void section(std::vector<std::byte> &data, bool wide, std::size_t index, std::uint32_t name, std::uint32_t type,
                    std::uint64_t flags, std::uint64_t address, std::uint64_t offset, std::uint64_t size,
                    std::uint64_t alignment = 1, bool big = false) {
    const auto at = 512 + index * (wide ? 64 : 40);
    put(data, wide ? 40 : 32, 512, wide ? 8 : 4, big);
    put(data, wide ? 58 : 46, wide ? 64 : 40, 2, big);
    put(data, wide ? 60 : 48, std::max<std::size_t>(index + 1, count(data, wide ? 60 : 48, big)), 2, big);
    put(data, at, name, 4, big);
    put(data, at + 4, type, 4, big);
    put(data, at + 8, flags, wide ? 8 : 4, big);
    put(data, at + (wide ? 16 : 12), address, wide ? 8 : 4, big);
    put(data, at + (wide ? 24 : 16), offset, wide ? 8 : 4, big);
    put(data, at + (wide ? 32 : 20), size, wide ? 8 : 4, big);
    put(data, at + (wide ? 48 : 32), alignment, wide ? 8 : 4, big);
}
inline std::vector<std::byte> executable(bool wide, bool big = false) {
    auto data = base(wide, big);
    put(data, 24, 0x400000, wide ? 8 : 4, big);
    program(data, wide, 0, 1, 256, 0x400000, 4, 16, 5, 256, big);
    data[256] = std::byte{0x90};
    data[257] = std::byte{0xc3};
    data[258] = std::byte{0x11};
    data[259] = std::byte{0x22};
    return data;
}
inline std::vector<std::byte> object(bool wide, bool big = false) {
    auto data = base(wide, big, 1);
    section(data, wide, 0, 0, 0, 0, 0, 0, 0, 0, big);
    section(data, wide, 1, 1, 1, 6, 0, 256, 4, 16, big);
    section(data, wide, 2, 7, 1, 6, 0, 272, 4, 16, big);
    section(data, wide, 3, 14, 8, 3, 0, 0xffff, 8, 8, big);
    section(data, wide, 4, 19, 3, 0, 0, 384, 29, 1, big);
    put(data, wide ? 62 : 50, 4, 2, big);
    constexpr std::string_view names("\0.text\0.other\0.bss\0.shstrtab\0", 29);
    for (std::size_t i = 0; i < names.size(); ++i)
        data[384 + i] = std::byte(names[i]);
    data[256] = std::byte{0x90};
    data[257] = std::byte{0xc3};
    data[272] = std::byte{0x40};
    data[273] = std::byte{0xc3};
    return data;
}
} // namespace hexlab_test::elf_fixture
