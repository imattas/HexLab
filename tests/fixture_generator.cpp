#include "support/elf_ui_fixture.hpp"
#include "support/pe_fixture.hpp"
#include "support/test_entrypoint.hpp"
#include <algorithm>
#include <iostream>
using namespace hexlab_test;
static std::vector<std::byte> simple_ar() {
    std::vector<std::byte> result;
    auto append = [&](std::string_view text) { for (unsigned char c : text) result.push_back(std::byte(c)); };
    append("!<arch>\n");
    auto member = [&](std::string_view name, std::span<const std::byte> data) {
        std::string header(60, ' ');
        auto field = [&](std::size_t at, std::size_t width, std::string value) { value.resize(width, ' '); std::copy_n(value.begin(), width, header.begin() + at); };
        field(0,16,std::string(name)+"/"); field(16,12,"0"); field(28,6,"0"); field(34,6,"0"); field(40,8,"100644"); field(48,10,std::to_string(data.size()));
        header[58]='`'; header[59]='\n'; append(header);
        result.insert(result.end(), data.begin(), data.end());
        if(data.size() & 1) result.push_back(std::byte('\n'));
    };
    auto elf = elf_ui_fixture::object(false);
    member("one.o", elf); member("two.o", elf);
    return result;
}
static std::vector<std::byte> managed_pe_fixture() {
    auto data = pe_fixture(); data.resize(0xa00);
    put(data, 0x86, 2, 2); put(data, 0xd0, 0x3000, 4);
    put_text(data, 0x1b0, ".rdata"); put(data, 0x1b8, 0x600, 4); put(data, 0x1bc, 0x2000, 4);
    put(data, 0x1c0, 0x600, 4); put(data, 0x1c4, 0x400, 4); put(data, 0x1d4, 0x40000040, 4);
    put(data, 0x108 + 14 * 8, 0x2200, 4); put(data, 0x108 + 14 * 8 + 4, 72, 4);
    put(data, 0x600, 72, 4); put(data, 0x604, 2, 2); put(data, 0x606, 5, 2);
    put(data, 0x608, 0x2300, 4); put(data, 0x60c, 0, 4); put(data, 0x610, 1, 4); put(data, 0x614, 0x06000001, 4);
    std::vector<std::byte> tables;
    auto u16 = [&](std::uint16_t v) { tables.push_back(std::byte(v)); tables.push_back(std::byte(v >> 8)); };
    auto u32 = [&](std::uint32_t v) { for (unsigned i=0;i<4;++i) tables.push_back(std::byte(v >> (8*i))); };
    auto u64 = [&](std::uint64_t v) { for (unsigned i=0;i<8;++i) tables.push_back(std::byte(v >> (8*i))); };
    u32(0); tables.push_back(std::byte{2}); tables.push_back(std::byte{0}); tables.push_back(std::byte{0}); tables.push_back(std::byte{1});
    u64((1ull << 0) | (1ull << 6)); u64(0); u32(1); u32(1);
    for (int i=0;i<5;++i) u16(0); // Module row
    u32(0x2500); u16(0); u16(0x16); u16(1); u16(1); u16(1); // MethodDef Run(): void()
    std::vector<std::byte> strings{std::byte{0},std::byte{'R'},std::byte{'u'},std::byte{'n'},std::byte{0}};
    while (strings.size() % 4)
        strings.push_back(std::byte{0});
    std::vector<std::byte> blobs{std::byte{0},std::byte{3},std::byte{0},std::byte{0},std::byte{1}}; // void Run()
    std::vector<std::byte> root;
    auto ru16 = [&](std::uint16_t v) { root.push_back(std::byte(v)); root.push_back(std::byte(v >> 8)); };
    auto ru32 = [&](std::uint32_t v) { for (unsigned i=0;i<4;++i) root.push_back(std::byte(v >> (8*i))); };
    auto patch32 = [&](std::size_t p,std::uint32_t v) { for(unsigned i=0;i<4;++i) root[p+i]=std::byte(v>>(8*i)); };
    ru32(0x424a5342); ru16(1); ru16(1); ru32(0); ru32(4); root.insert(root.end(),{std::byte{'v'},std::byte{'4'},std::byte{0},std::byte{0}}); ru16(0); ru16(3);
    const auto table_header=root.size(); ru32(0); ru32(static_cast<std::uint32_t>(tables.size())); root.insert(root.end(),{std::byte{'#'},std::byte{'~'},std::byte{0},std::byte{0}});
    const auto strings_header=root.size(); ru32(0); ru32(static_cast<std::uint32_t>(strings.size())); root.insert(root.end(),{std::byte{'#'},std::byte{'S'},std::byte{'t'},std::byte{'r'},std::byte{'i'},std::byte{'n'},std::byte{'g'},std::byte{'s'},std::byte{0},std::byte{0},std::byte{0},std::byte{0}});
    const auto blob_header=root.size(); ru32(0); ru32(static_cast<std::uint32_t>(blobs.size())); root.insert(root.end(),{std::byte{'#'},std::byte{'B'},std::byte{'l'},std::byte{'o'},std::byte{'b'},std::byte{0},std::byte{0},std::byte{0}});
    const auto tables_offset=static_cast<std::uint32_t>(root.size()); const auto strings_offset=tables_offset+static_cast<std::uint32_t>(tables.size()); const auto blobs_offset=strings_offset+static_cast<std::uint32_t>(strings.size());
    patch32(table_header,tables_offset); patch32(strings_header,strings_offset); patch32(blob_header,blobs_offset); root.insert(root.end(),tables.begin(),tables.end()); root.insert(root.end(),strings.begin(),strings.end()); root.insert(root.end(),blobs.begin(),blobs.end());
    put(data,0x610,1,4); put(data,0x60c,static_cast<std::uint32_t>(root.size()),4);
    std::copy(root.begin(),root.end(),data.begin()+0x700); data[0x900]=std::byte{0x06}; data[0x901]=std::byte{0x2a};
    return data;
}
int HEXLAB_TEST_MAIN(int argc, hexlab_test_arg_char **argv) {
    if (argc != 2)
        return 2;
    try {
        const std::filesystem::path root = hexlab_test_path(argv[1]);
        for (bool wide : {false, true}) {
            const auto suffix = wide ? "64" : "32";
            write_file(root / (std::string("object") + suffix + ".o"), elf_ui_fixture::object(wide));
            write_file(root / (std::string("shared") + suffix + ".so"), elf_ui_fixture::dynamic(wide));
            write_file(root / (std::string("exec") + suffix + ".elf"), elf_ui_fixture::dynamic(wide, true));
        }
        write_file(root / "big64.elf", elf_ui_fixture::dynamic(true, false, true));
        auto rvc = elf_ui_fixture::dynamic(true, true);
        put(rvc, 18, 243, 2); // EM_RISCV
        put(rvc, 48, 1, 4);   // EF_RISCV_RVC
        rvc[256] = std::byte{0x01}; rvc[257] = std::byte{0x00}; // c.nop
        rvc[258] = std::byte{0x02}; rvc[259] = std::byte{0x90}; // c.ebreak
        write_file(root / "rv64c.elf", rvc);
        write_file(root / "unbounded64.so", elf_dynamic_symbol_fixture::fixture(true, false, 4));
        write_file(root / "bad.elf", bytes({0x7f, 0x45, 0x4c, 0x46}));
        write_file(root / "minimal64.exe", pe_fixture());
        write_file(root / "minimal32.exe", pe_fixture(false));
        auto arm = pe_fixture();
        put(arm, 0x84, 0xaa64, 2);
        write_file(root / "minimalarm64.exe", arm);
        write_file(root / "metadata64.exe", pe_metadata_fixture());
        write_file(root / "managed.exe", managed_pe_fixture());
        write_file(root / "bound-import64.exe", pe_bound_import_fixture());
        auto partial = pe_metadata_fixture();
        put(partial, 0x40c, 0x1800, 4);
        write_file(root / "partial64.exe", partial);
        write_file(root / "bad.exe", bytes({'M', 'Z'}));
        write_file(root / "raw.bin", bytes({0x90, 0xc3, 'H', 'E', 'L', 'L', 'O', 0}));
        write_file(root / "signature-function.bin", bytes({0xe8, 0x0b, 0, 0, 0,
            0x48, 0x8d, 0x05, 0x04, 0, 0, 0, 0x83, 0xc0, 1, 0xc3, 0xc3}));
        write_file(root / "stack.bin", bytes({0x48, 0x83, 0xec, 0x20, 0x89, 0x44, 0x24, 0x10, 0xc3}));
        write_file(root / "stack-lea.bin", bytes({0x48, 0x8d, 0x6c, 0x24, 0x10,
                                                   0x48, 0x8d, 0x45, 0xe0,
                                                   0x48, 0x89, 0x45, 0xe0,
                                                   0x48, 0x8d, 0x65, 0xf0,
                                                   0x48, 0x8b, 0x44, 0x24, 0xf0, 0xc3}));
        write_file(root / "objects.a", simple_ar());
        std::vector<std::byte> switches(0x118, std::byte{0x90});
        const auto dispatch = bytes({0xff, 0x24, 0xc5, 0x00, 0x11, 0x00, 0x00});
        std::copy(dispatch.begin(), dispatch.end(), switches.begin());
        switches[0x10] = switches[0x20] = std::byte{0xc3};
        auto pointer = [&](std::size_t at, std::uint64_t value) {
            for (unsigned i = 0; i < 8; ++i)
                switches[at + i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
        };
        pointer(0x100, 0x1010);
        pointer(0x108, 0x1020);
        pointer(0x110, UINT64_MAX);
        write_file(root / "switches.bin", switches);
        std::vector<std::byte> register_switches(0x118, std::byte{0x90});
        const auto register_dispatch = bytes({0x48, 0x8d, 0x15, 0xf9, 0x00, 0x00, 0x00,
                                              0xff, 0x24, 0xc2});
        std::copy(register_dispatch.begin(), register_dispatch.end(), register_switches.begin());
        register_switches[0x10] = register_switches[0x20] = std::byte{0xc3};
        auto register_pointer = [&](std::size_t at, std::uint64_t value) {
            for (unsigned i = 0; i < 8; ++i)
                register_switches[at + i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
        };
        register_pointer(0x100, 0x1010);
        register_pointer(0x108, 0x1020);
        register_pointer(0x110, UINT64_MAX);
        write_file(root / "switches-register-base.bin", register_switches);
        const auto guarded_dispatch = bytes({0x48, 0x83, 0xf8, 0x01, 0x77, 0x2a,
                                             0xff, 0x24, 0xc5, 0x00, 0x11, 0x00, 0x00});
        std::copy(guarded_dispatch.begin(), guarded_dispatch.end(), switches.begin());
        switches[0x30] = std::byte{0xc3};
        write_file(root / "switches-guarded.bin", switches);
        auto segmented = bytes({0x9a, 0, 0, 0x10, 0, 0xc3});
        segmented.resize(16, std::byte{0x90});
        auto callee = bytes({0xb8, 0x78, 0x56, 0x34, 0x12, 0x66, 0xcb});
        segmented.insert(segmented.end(), callee.begin(), callee.end());
        write_file(root / "segmented-far.bin", segmented);
        write_file(root / "immediates.bin", bytes({0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xb0, 0xff, 0xc3}));
        write_file(root / "unsupported.bin", bytes({0xc5, 0xf8, 0x77, 0xc3}));
        write_file(root / "truncated.bin", bytes({0xe8, 1}));
        write_file(root / std::filesystem::path(L"unicode \u00e9 sample.exe"), pe_fixture());
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
