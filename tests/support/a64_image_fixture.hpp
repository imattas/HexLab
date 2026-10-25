#pragma once
#include "pe_fixture.hpp"
#include "elf_fixture.hpp"
#include "macho_fixture.hpp"
namespace hexlab_test::a64_fixture {
inline std::vector<std::byte> program() {
    std::vector<std::byte> result(32);
    const unsigned words[]{0x94000004, 0xd503201f, 0xd65f03c0, 0xd4200000, 0x10000040, 0xd61f0060, 0, 0};
    for (unsigned n = 0; n < 8; ++n)
        hexlab_test::put(result, n * 4, words[n], 4);
    return result;
}
inline std::vector<std::byte> pe() {
    auto result = pe_fixture(true);
    hexlab_test::put(result, 0x84, 0xaa64, 2);
    const auto code = program();
    std::copy(code.begin(), code.end(), result.begin() + 512);
    return result;
}
inline std::vector<std::byte> elf() {
    auto result = elf_fixture::executable(true);
    elf_fixture::put(result, 18, 183, 2);
    elf_fixture::program(result, true, 0, 1, 256, 0x400000, 32, 32, 5, 256);
    const auto code = program();
    std::copy(code.begin(), code.end(), result.begin() + 256);
    return result;
}
inline std::vector<std::byte> macho() {
    auto result = macho_fixture::thin(true, false);
    result.resize(4096);
    macho_fixture::put(result, 4, 0x0100000c, 4, false);
    macho_fixture::put(result, 12, 2, 4, false);
    macho_fixture::put(result, 16, 2, 4, false);
    macho_fixture::put(result, 20, 96, 4, false);
    macho_fixture::segment(result, true, false, 32, UINT64_C(0x100000000), 4096, 0, 4096, 5);
    macho_fixture::put(result, 104, 0x80000028, 4, false);
    macho_fixture::put(result, 108, 24, 4, false);
    macho_fixture::put(result, 112, 768, 8, false);
    macho_fixture::put(result, 120, 0, 8, false);
    const auto code = program();
    std::copy(code.begin(), code.end(), result.begin() + 768);
    return result;
}
} // namespace hexlab_test::a64_fixture
