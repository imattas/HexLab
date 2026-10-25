#include <string>
#include "support/macho_chained_fixture.hpp"
#include "support/macho_relocation_fixture.hpp"
#include "support/fixture_files.hpp"
#include "support/test_entrypoint.hpp"
#include <iostream>
using namespace hexlab_test;
using namespace hexlab_test::macho_fixture;
std::vector<std::byte> symbol_universal(bool wide, bool big) {
    const auto a = symbols(false), b = symbols(true);
    std::vector<std::byte> data(12288);
    put(data, 0, wide ? 0xcafebabf : 0xcafebabe, 4, big);
    put(data, 4, 2, 4, big);
    for (unsigned i = 0; i < 2; ++i) {
        const auto at = 8 + i * (wide ? 32 : 20);
        put(data, at, i ? 0x01000007 : 7, 4, big);
        put(data, at + 4, 0x80000003, 4, big);
        put(data, at + 8, i ? 8192 : 4096, wide ? 8 : 4, big);
        put(data, at + (wide ? 16 : 12), 4096, wide ? 8 : 4, big);
        put(data, at + (wide ? 24 : 16), 12, 4, big);
    }
    std::copy(a.begin(), a.end(), data.begin() + 4096);
    std::copy(b.begin(), b.end(), data.begin() + 8192);
    return data;
}
std::vector<std::byte> classic() {
    auto data = dyld(true);
    segment(data, true, false, 32, UINT64_C(0x100000000) - 768, 4096, 0, 4096, 7, 0, 3);
    put(data, 32 + 72 + 160 + 48, 784, 4, false);
    put(data, 32 + 72 + 160 + 64, 0, 4, false);
    stream(data, true, false, 0, {0x11, 0x20, 0x80, 6, 0x51, 0});
    stream(data, true, false, 1, {0x11, 0x40, '_', 'e', 'x', 't', 0, 0x70, 0x88, 6, 0x90, 0});
    stream(data, true, false, 4, {0, 1, '_', 'a', 'p', 'i', 0, 8, 3, 0, 0x80, 8, 0});
    put(data, 768, UINT64_C(0x100000008), 8, false);
    return data;
}
int HEXLAB_TEST_MAIN(int argc, hexlab_test_arg_char **argv) {
    if (argc != 2)
        return 2;
    try {
        const std::filesystem::path root = hexlab_test_path(argv[1]);
        for (bool wide : {false, true}) {
            const auto suffix = wide ? "64" : "32";
            write_file(root / (std::string("object") + suffix + ".o"), symbols(wide));
            write_file(root / (std::string("linked") + suffix + ".macho"), symbols(wide, false, false));
            auto call = relocated(wide);
            put(call, symtab_command(wide) + 12, 3, 4, false);
            write_file(root / (std::string("call") + suffix + ".o"), call);
            relocation(call, false, 0, 1, 2, wide ? 2 : 0, 2, true, true);
            write_file(root / (std::string("undefined-call") + suffix + ".o"), call);
        }
        write_file(root / "fat32.macho", symbol_universal(false, true));
        write_file(root / "fat64-swapped.macho", symbol_universal(true, false));
        write_file(root / "classic64.macho", classic());
        write_file(root / "chained64.macho", chained());
        write_file(root / "big64.macho", symbols(true, true));
        auto protected_image = classic();
        const auto crypt = append_command(protected_image, true, false, 0x2c, 24);
        put(protected_image, crypt + 8, 1024, 4, false);
        put(protected_image, crypt + 12, 8, 4, false);
        put(protected_image, crypt + 16, 1, 4, false);
        const auto dice = append_command(protected_image, true, false, 0x29, 16);
        put(protected_image, dice + 8, 3500, 4, false);
        put(protected_image, dice + 12, 8, 4, false);
        put(protected_image, 3500, 1040, 4, false);
        put(protected_image, 3504, 4, 2, false);
        put(protected_image, 3506, 1, 2, false);
        const auto sig = append_command(protected_image, true, false, 0x1d, 16);
        put(protected_image, sig + 8, 3600, 4, false);
        put(protected_image, sig + 12, 16, 4, false);
        write_file(root / "protected64.macho", protected_image);
        write_file(root / "bad.macho", bytes({0xcf, 0xfa, 0xed, 0xfe}));
        write_file(root / std::filesystem::path(L"unicode \u00e9 macho.o"), symbols(true));
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
