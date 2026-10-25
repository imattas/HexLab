#include "support/fixture_files.hpp"
#include <filesystem>

int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    const std::filesystem::path root(argv[1]);
    const auto fixture = hexlab_test::bytes({
        0x66, 0x0f, 0xfe, 0xc1,       // paddd xmm0, xmm1
        0xf3, 0x0f, 0x6f, 0x10,       // movdqu xmm2, [rax]
        0xf2, 0x0f, 0x58, 0xdc,       // addsd xmm3, xmm4
        0xf3, 0x0f, 0x10, 0xee,       // movss xmm5, xmm6
        0x66, 0x0f, 0x76, 0xc7,       // pcmpeqd xmm0, xmm7
        0xc3                           // ret
    });
    hexlab_test::write_file(root / "x64-simd.bin", fixture);
    return 0;
}
