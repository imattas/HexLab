#include <filesystem>
#include <fstream>
#include "support/test_entrypoint.hpp"
int HEXLAB_TEST_MAIN(int argc, hexlab_test_arg_char **argv) {
    if (argc != 2)
        return 2;
    const std::filesystem::path root = hexlab_test_path(argv[1]);
    std::filesystem::create_directories(root);
    std::ofstream out(root / L"a64.bin", std::ios::binary);
    const unsigned words[]{0x94000004, 0xd503201f, 0xd65f03c0, 0xd4200000, 0x10000040, 0xd61f0060, 0, 0};
    for (auto word : words)
        for (unsigned n = 0; n < 4; ++n)
            out.put(static_cast<char>(word >> (8 * n)));
    return out ? 0 : 1;
}
