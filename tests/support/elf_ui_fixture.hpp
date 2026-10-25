#pragma once
#include "elf_metadata_fixture.hpp"
#include "elf_dynamic_symbol_fixture.hpp"
namespace hexlab_test::elf_ui_fixture {
inline std::vector<std::byte> object(bool wide) {
    using namespace elf_metadata_fixture;
    auto data = relocatable(wide, true);
    constexpr std::string_view caller("caller\0", 7);
    for (std::size_t i = 0; i < caller.size(); ++i)
        data[strings_at + 25 + i] = std::byte(caller[i]);
    section(data, wide, 6, 0, 3, 0, 0, strings_at, 32, 1);
    symbol(data, wide, false, 4, 25, 0x12, 1, 0, 6);
    section(data, wide, 1, 1, 1, 6, 0, 256, 6, 16);
    section(data, wide, 7, 0, 4, 0, 0, relocations_at, wide ? 24 : 12, wide ? 8 : 4);
    return data;
}
inline std::vector<std::byte> dynamic(bool wide, bool executable = false, bool big = false) {
    namespace dyn = elf_dynamic_symbol_fixture;
    using namespace elf_fixture;
    auto data = dyn::fixture(wide, big, 3);
    const auto base_address = wide ? UINT64_C(0x100000000) : UINT64_C(0x10000);
    put(data, 16, executable ? 2 : 3, 2, big);
    put(data, 24, base_address + 256, wide ? 8 : 4, big);
    constexpr std::string_view names("libfixture.so\0fixture.so\0$ORIGIN\0", 33);
    for (std::size_t i = 0; i < names.size(); ++i)
        data[dyn::str + 18 + i] = std::byte(names[i]);
    dyn::tag(data, wide, big, 1, 10, 18 + names.size());
    dyn::tag(data, wide, big, 6, 1, 18);
    dyn::tag(data, wide, big, 7, 14, 32);
    dyn::tag(data, wide, big, 8, 29, 43);
    dyn::tag(data, wide, big, 9, 0, 0);
    program(data, wide, 1, 2, dyn::dynamic_at, base_address + dyn::dynamic_at, 10 * (wide ? 16 : 8),
            10 * (wide ? 16 : 8), 6, wide ? 8 : 4, big);
    return data;
}
} // namespace hexlab_test::elf_ui_fixture
