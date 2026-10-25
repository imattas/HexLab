#include "hexlab/loaders/macho.hpp"
#include "hexlab/loaders/macho_unwind.hpp"
#include "hexlab/analysis/functions.hpp"
#include "hexlab/analysis/macho_dyld.hpp"
#include "support/macho_symbol_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::macho_fixture;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
Result<LoadedImage> load(std::vector<std::byte> data) {
    return load_macho(std::make_shared<MemoryStorage>(std::move(data)), {}, {});
}
std::size_t append(std::vector<std::byte> &data, bool wide, std::uint32_t type, std::uint32_t size) {
    std::uint64_t old = 0, count = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        old |= std::to_integer<std::uint64_t>(data[20 + i]) << (8 * i);
        count |= std::to_integer<std::uint64_t>(data[16 + i]) << (8 * i);
    }
    const auto at = (wide ? 32 : 28) + old;
    put(data, 16, count + 1, 4, false);
    put(data, 20, old + size, 4, false);
    put(data, at, type, 4, false);
    put(data, at + 4, size, 4, false);
    return static_cast<std::size_t>(at);
}
void library(std::vector<std::byte> &data, bool wide, std::uint32_t type, std::string_view name) {
    const auto at = append(data, wide, type, 32);
    put(data, at + 8, 24, 4, false);
    put(data, at + 12, 0x12345678, 4, false);
    put(data, at + 16, 0x10002, 4, false);
    put(data, at + 20, 0x10000, 4, false);
    for (std::size_t i = 0; i < name.size(); ++i)
        data[at + 24 + i] = std::byte(name[i]);
}
void header_backing(std::vector<std::byte> &data, bool wide) {
    const auto at = wide ? 32u : 28u;
    const auto code = wide ? UINT64_C(0x100000000) : UINT64_C(0x1000);
    segment(data, wide, false, at, code - 768, 800, 0, 784, 7, 0, 3);
}
void commands() {
    for (bool wide : {false, true}) {
        auto data = hexlab_test::macho_fixture::symbols(wide, false, false);
        header_backing(data, wide);
        put(data, symtab_command(wide) + 12, 0, 4,
            false); // Stripped names; entry/function-start roots must stand alone.
        library(data, wide, 0xc, "libA");
        library(data, wide, 0xd, "self");
        library(data, wide, 0x80000018, "libB");
        const auto path = append(data, wide, 0x8000001c, 24);
        put(data, path + 8, 12, 4, false);
        const std::string text = "@loader";
        for (std::size_t i = 0; i < text.size(); ++i)
            data[path + 12 + i] = std::byte(text[i]);
        const auto main = append(data, wide, 0x80000028, 24);
        put(data, main + 8, 768, 8, false);
        put(data, main + 16, 0x100000, 8, false);
        const auto starts = append(data, wide, 0x26, 16);
        put(data, starts + 8, 3072, 4, false);
        put(data, starts + 12, 4, 4, false);
        data[3072] = std::byte{0x80};
        data[3073] = std::byte{0x06};
        data[3074] = std::byte{8};
        data[3075] = std::byte{0};
        auto loaded = take(load(data));
        const auto &m = *loaded.metadata.macho;
        const auto base = wide ? UINT64_C(0x100000000) : UINT64_C(0x1000);
        check(m.libraries.size() == 3 && m.libraries[0].ordinal == 1 && !m.libraries[1].ordinal &&
                  m.libraries[2].ordinal == 2 && m.libraries[0].name == "libA" &&
                  m.libraries[2].command == 0x80000018 && m.libraries[0].timestamp == 0x12345678,
              "dylib ordinal order excludes ID commands and preserves command kind/version/name");
        check(m.paths.size() == 1 && m.paths[0].name == "@loader",
              "rpath remains a raw command string without host expansion");
        check(m.entries.size() == 1 && m.entries[0].value == 768 && m.entries[0].stack_size == 0x100000 &&
                  m.entries[0].address == Address{{0}, base} &&
                  loaded.image->layout().entries == std::vector<Address>{Address{{0}, base}},
              "LC_MAIN uses mapped Mach header plus VM offset and records original stack declaration");
        check(m.function_starts.size() == 2 && m.function_starts[0].delta == 768 &&
                  m.function_starts[0].address == Address{{0}, base} &&
                  m.function_starts[1].address == Address{{0}, base + 8} &&
                  m.function_starts[0].record_file_offset == 3072,
              "ULEB function starts retain delta record provenance and initialized executable addresses");
        check(loaded.metadata_reads.intersects({3072}, 3).value(), "function-start stream is a metadata dependency");
        const auto recovered = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
        check(std::any_of(recovered->functions.begin(), recovered->functions.end(),
                          [&](const auto &function) { return function->entry == Address{{0}, base + 8}; }),
              "function-start declarations seed recovery independently of a symbol table or the process entry");
        auto bad = data;
        put(bad, path + 8, 4, 4, false);
        check(!load(bad), "command strings cannot point into fixed fields");
        bad = data;
        std::fill(bad.begin() + path + 12, bad.begin() + path + 24, std::byte{'a'});
        check(!load(bad), "unterminated command string is bounded by command size");
        bad = data;
        put(bad, starts + 8, 4095, 4, false);
        check(!load(bad), "linkedit blob cannot exceed selected slice");
        bad = data;
        std::fill(bad.begin() + 3072, bad.begin() + 3076, std::byte{0x80});
        check(!load(bad), "unterminated ULEB sequence fails");
        bad = data;
        put(bad, starts + 12, 11, 4, false);
        std::fill(bad.begin() + 3072, bad.begin() + 3082, std::byte{0xff});
        bad[3082] = std::byte{0};
        check(!load(bad), "ULEB overflow fails without a wrapped function address");
        bad = data;
        put(bad, main + 8, 4096, 8, false);
        auto missing = take(load(bad));
        check(!missing.metadata_complete && !missing.metadata.macho->entries[0].address &&
                  missing.image->layout().entries.empty(),
              "unmapped entry remains an explicit raw declaration without rejecting inspectable image");
    }
}
void compact_unwind_roots() {
    auto data = mapped(true);
    // Expand the initialized __TEXT range and turn the third section into a
    // compact-unwind payload. Keep the section table otherwise literal.
    const std::size_t seg = 32, section = 32 + 72 + 2 * 80;
    const auto base = UINT64_C(0x100000000);
    put(data, seg + 32, 800, 8, false);
    put(data, seg + 48, 112, 8, false);
    put(data, section, 0, 16, false);
    for (std::size_t i = 0; i < 13; ++i) data[section + i] = std::byte("__unwind_info"[i]);
    put(data, section + 32, base + 16, 8, false);
    put(data, section + 40, 80, 8, false);
    put(data, section + 48, 784, 4, false);
    put(data, section + 64, 0, 4, false);
    put(data, 784, 1, 4, false);  // version
    put(data, 788, 28, 4, false); // common encodings
    put(data, 792, 1, 4, false);
    put(data, 796, 32, 4, false); // personalities
    put(data, 804, 32, 4, false); // index
    put(data, 808, 2, 4, false);
    put(data, 812, 0x12345678, 4, false);
    put(data, 816, 0, 4, false); // first function offset from __TEXT
    put(data, 820, 56, 4, false);  // second-level page
    put(data, 824, 0, 4, false);
    put(data, 828, 0x100, 4, false); // sentinel
    put(data, 832, 0, 4, false);
    put(data, 836, 0, 4, false);
    put(data, 840, 3, 4, false); // compressed page
    put(data, 844, 12, 2, false);
    put(data, 846, 2, 2, false);
    put(data, 848, 0, 2, false); // no page-local encodings
    put(data, 852, 0, 4, false);
    put(data, 856, 8, 4, false);
    auto loaded = take(load(data));
    const auto &m = *loaded.metadata.macho;
    check(m.compact_unwind_functions.size() == 2 &&
              m.compact_unwind_functions[0].address == Address{{0}, base} &&
              m.compact_unwind_functions[0].encoding == 0x12345678 &&
              m.compact_unwind_functions[1].address == Address{{0}, base + 8} &&
              loaded.metadata_reads.intersects({840}, 24).value(),
          "compact unwind entries preserve encodings and seed mapped function starts");
    const auto roots = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
    check(std::any_of(roots->functions.begin(), roots->functions.end(),
                      [&](const auto &function) { return function->entry == Address{{0}, base + 8}; }),
          "compact unwind function entries reach the existing recovery root model");

    auto arm = data;
    put(arm, 4, 0x0100000c, 4, false);
    put(arm, 840, 2, 4, false); // regular second-level page
    put(arm, 844, 8, 2, false);
    put(arm, 846, 2, 2, false);
    put(arm, 848, 0, 4, false);
    put(arm, 852, 0xaabbccdd, 4, false);
    put(arm, 856, 8, 4, false);
    put(arm, 860, 0x11223344, 4, false);
    auto arm_loaded = take(load(arm));
    const auto &arm_functions = arm_loaded.metadata.macho->compact_unwind_functions;
    check(arm_functions.size() == 2 && arm_functions[0].address == Address{{0}, base} &&
              arm_functions[0].encoding == 0xaabbccdd && arm_functions[1].encoding == 0x11223344,
          "arm64 regular compact-unwind pages preserve opaque encodings and function roots");
    auto malformed = arm;
    put(malformed, 784, 2, 4, false);
    check(!load(malformed), "unsupported compact-unwind versions are rejected");
    malformed = arm;
    put(malformed, 840, 99, 4, false);
    check(!load(malformed), "unknown compact-unwind page kinds are rejected");
    malformed = data;
    put(malformed, 784 + 40, 64, 8, false);
    check(!load(malformed), "compact-unwind page records cannot cross their section extent");
    malformed = data;
    put(malformed, 852, 0x200, 4, false);
    check(!load(malformed), "compact-unwind entries cannot exceed their index sentinel");
}
void eh_frame_roots() {
    auto data = mapped(true);
    const std::size_t seg = 32, section = 32 + 72 + 2 * 80;
    const auto base = UINT64_C(0x100000000);
    put(data, seg + 32, 880, 8, false);
    put(data, seg + 48, 112, 8, false);
    put(data, section, 0, 16, false);
    const std::string section_name = "__eh_frame";
    for (std::size_t i = 0; i < section_name.size(); ++i) data[section + i] = std::byte(section_name[i]);
    put(data, section + 32, base + 16, 8, false);
    put(data, section + 40, 48, 8, false);
    put(data, section + 48, 784, 4, false);
    put(data, section + 64, 0, 4, false);
    // zR CIE with pcrel/sdata4 initial locations, followed by one bounded FDE.
    put(data, 784, 16, 4, false);
    put(data, 788, 0, 4, false);
    data[792] = std::byte{1}; data[793] = std::byte{'z'}; data[794] = std::byte{'R'}; data[795] = std::byte{0};
    data[796] = std::byte{1}; data[797] = std::byte{0x78}; data[798] = std::byte{16};
    data[799] = std::byte{1}; data[800] = std::byte{0x1b};
    data[801] = std::byte{0x0c}; data[802] = std::byte{7}; data[803] = std::byte{8}; // CFA = RSP + 8
    put(data, 804, 17, 4, false);
    put(data, 808, 24, 4, false); // backward distance from this CIE-pointer field
    put(data, 812, static_cast<std::uint32_t>(-4), 4, false); // target base+40 from field VA base+44
    put(data, 816, 4, 4, false);
    data[820] = std::byte{0}; // FDE augmentation length
    data[821] = std::byte{0x90}; data[822] = std::byte{1}; // RIP at CFA-8
    data[823] = std::byte{0x86}; data[824] = std::byte{2}; // RBP at CFA-16
    data[825] = std::byte{0}; // terminator
    auto loaded = take(load(data));
    const auto &m = *loaded.metadata.macho;
    check(m.eh_frame_functions.size() == 1 && m.eh_frame_functions[0].address == Address{{0}, base + 40} &&
              m.eh_frame_functions[0].size == 4 && m.eh_frame_functions[0].cie_instructions.size() == 3 &&
              m.eh_frame_functions[0].instructions.size() == 4,
          "bounded zR eh_frame FDE records recover executable function roots");
    const auto encoded_fixture = [&](std::uint8_t encoding, const std::vector<std::uint8_t> &initial,
                                     const std::vector<std::uint8_t> &range) {
        auto encoded = data;
        encoded[800] = std::byte{encoding};
        const auto body_length = static_cast<std::uint32_t>(4 + initial.size() + range.size() + 1 + 4);
        put(encoded, 804, body_length, 4, false);
        std::size_t cursor = 812;
        for (const auto byte : initial) encoded[cursor++] = std::byte{byte};
        for (const auto byte : range) encoded[cursor++] = std::byte{byte};
        encoded[cursor++] = std::byte{0}; // empty FDE augmentation
        for (const auto byte : {0x90, 1, 0x86, 2}) encoded[cursor++] = std::byte{static_cast<unsigned char>(byte)};
        for (unsigned i = 0; i < 4; ++i) encoded[cursor + i] = std::byte{0}; // four-byte record terminator
        put(encoded, section + 40, cursor - 784 + 4, 8, false); // include the four-byte zero terminator
        return encoded;
    };
    const auto fixed_little = [](std::uint64_t value, unsigned width) {
        std::vector<std::uint8_t> bytes;
        for (unsigned i = 0; i < width; ++i) bytes.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
        return bytes;
    };
    auto sdata8 = load(encoded_fixture(0x1c, fixed_little(UINT64_C(0xfffffffffffffffc), 8),
                                       fixed_little(4, 8)));
    check(sdata8 && sdata8.value().metadata.macho->eh_frame_functions.size() == 1 &&
              sdata8.value().metadata.macho->eh_frame_functions[0].address == Address{{0}, base + 40} &&
              sdata8.value().metadata.macho->eh_frame_functions[0].pointer_encoding == 0x1c,
          "pcrel/sdata8 FDE locations and their source encoding are retained");
    auto absolute = load(encoded_fixture(0x00, fixed_little(base + 40, 8), fixed_little(4, 8)));
    check(absolute && absolute.value().metadata.macho->eh_frame_functions.size() == 1 &&
              absolute.value().metadata.macho->eh_frame_functions[0].address == Address{{0}, base + 40} &&
              absolute.value().metadata.macho->eh_frame_functions[0].pointer_encoding == 0,
          "absolute absptr FDE locations produce the same bounded function root");
    auto native_signed = load(encoded_fixture(0x08, fixed_little(base + 40, 8), fixed_little(4, 8)));
    check(native_signed && native_signed.value().metadata.macho->eh_frame_functions.size() == 1 &&
              native_signed.value().metadata.macho->eh_frame_functions[0].address == Address{{0}, base + 40} &&
              native_signed.value().metadata.macho->eh_frame_functions[0].pointer_encoding == 0x08,
          "native signed pointer FDE locations retain their encoding");
    const auto uleb = [](std::uint64_t value) {
        std::vector<std::uint8_t> bytes;
        do { auto byte = static_cast<std::uint8_t>(value & 0x7f); value >>= 7; if (value) byte |= 0x80; bytes.push_back(byte); } while (value);
        return bytes;
    };
    auto variable_width = load(encoded_fixture(0x01, uleb(base + 40), uleb(4)));
    check(variable_width && variable_width.value().metadata.macho->eh_frame_functions.size() == 1 &&
              variable_width.value().metadata.macho->eh_frame_functions[0].address == Address{{0}, base + 40},
          "absolute ULEB128 FDE locations and ranges are decoded within their record");
    const auto runtime = evaluate_macho_unwind(m, {{0}, base + 40}, {{MachOUnwindRegister::x86_64_rsp, 0x3000}},
        [](std::uint64_t at, std::uint8_t width) -> std::optional<std::uint64_t> {
            if (width != 8) return std::nullopt;
            if (at == 0x3000) return 0xfeed;
            if (at == 0x2ff8) return 0xbeef;
            return std::nullopt;
        });
    check(runtime && runtime.value().caller.at(MachOUnwindRegister::x86_64_rip) == 0xfeed &&
              runtime.value().caller.at(MachOUnwindRegister::x86_64_rbp) == 0xbeef,
          "parsed FDE CFI instructions are consumed by the runtime unwinder");
    const auto roots = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
    check(std::any_of(roots->functions.begin(), roots->functions.end(),
                      [&](const auto &function) { return function->entry == Address{{0}, base + 40}; }),
          "eh_frame FDE starts reach function recovery");
    auto malformed = data;
    put(malformed, 804, 0xffff, 4, false);
    check(!load(malformed), "eh_frame FDE extent cannot cross its section boundary");
    malformed = data;
    put(malformed, 804, 12, 4, false); // record ends immediately after the FDE range, without z-augmentation length
    put(malformed, section + 40, 36, 8, false); // terminate the section at this record, isolating the omitted length
    check(!load(malformed), "z-augmented eh_frame FDE requires an augmentation length even when no payload follows");
    malformed = data;
    std::move_backward(malformed.begin() + 804, malformed.end() - 9, malformed.end());
    put(malformed, section + 40, 57, 8, false);
    put(malformed, 784, 25, 4, false); // extend CIE over an intentionally over-wide data-alignment SLEB
    for (std::size_t i = 797; i < 806; ++i) malformed[i] = std::byte{0x80};
    malformed[806] = std::byte{0x02}; // tenth SLEB byte has payload bits beyond signed 64-bit width
    malformed[807] = std::byte{1}; // version-1 return register
    malformed[808] = std::byte{1}; malformed[809] = std::byte{0x1b}; // zR augmentation
    malformed[810] = std::byte{0x0c}; malformed[811] = std::byte{7}; malformed[812] = std::byte{8};
    put(malformed, 813, 17, 4, false);
    put(malformed, 817, 29, 4, false); // relocated backward CIE pointer
    put(malformed, 821, static_cast<std::uint32_t>(-13), 4, false); // preserve base+40 PC-relative target
    check(!load(malformed), "eh_frame CIE rejects an overflowing tenth SLEB byte");
}
void thread_entries() {
    for (bool wide : {false, true}) {
        auto data = mapped(wide);
        data.resize(4096);
        header_backing(data, wide);
        const auto count = wide ? 42u : 16u, size = 16 + 4 * count;
        const auto at = append(data, wide, 5, size);
        put(data, at + 8, wide ? 4 : 1, 4, false);
        put(data, at + 12, count, 4, false);
        const auto base = wide ? UINT64_C(0x100000000) : UINT64_C(0x1000);
        put(data, at + 16 + (wide ? 16 * 8 : 10 * 4), base, wide ? 8 : 4, false);
        auto loaded = take(load(data));
        check(loaded.metadata.macho->entries[0].flavor == (wide ? 4u : 1u) &&
                  loaded.metadata.macho->entries[0].value == base &&
                  loaded.image->layout().entries == std::vector<Address>{Address{{0}, base}},
              "legacy x86 thread entry reads the exact flavor PC field");
        auto unknown = data;
        put(unknown, at + 8, 99, 4, false);
        auto result = take(load(unknown));
        check(!result.metadata_complete && !result.metadata.macho->entries[0].value &&
                  result.image->layout().entries.empty(),
              "unsupported thread flavor retains source identity but does not guess PC");
        auto bad = data;
        put(bad, at + 12, count + 1, 4, false);
        check(!load(bad), "thread state count cannot cross command extent");
        const auto main = append(data, wide, 0x80000028, 24);
        put(data, main + 8, 776, 8, false);
        result = take(load(data));
        check(result.metadata.macho->entries_conflict && !result.metadata_complete &&
                  result.image->layout().entries.empty(),
              "conflicting mapped entry declarations remain explicit without choosing a process root");
        auto unanchored = mapped(wide);
        unanchored.resize(4096);
        const auto guessed = append(unanchored, wide, 0x80000028, 24);
        put(unanchored, guessed + 8, 768, 8, false);
        result = take(load(unanchored));
        check(!result.metadata.macho->entries[0].address && result.image->layout().entries.empty(),
              "LC_MAIN cannot guess a header-relative VM base from unrelated file-backed code");
    }
}
void indirect_tables() {
    for (bool wide : {false, true}) {
        auto data = hexlab_test::macho_fixture::symbols(wide);
        const auto at = append(data, wide, 0xb, 80);
        put(data, at + 16, 0, 4, false);
        put(data, at + 20, 2, 4, false); // External definitions0..2.
        put(data, at + 24, 2, 4, false);
        put(data, at + 28, 1, 4, false); // Undefined2..3.
        put(data, at + 56, 3072, 4, false);
        put(data, at + 60, 3, 4, false);
        put(data, 3072, 0, 4, false);
        put(data, 3076, 0x80000000, 4, false);
        put(data, 3080, 0xc0000000, 4, false);
        auto loaded = take(load(data));
        const auto &table = loaded.metadata.macho->dynamic_symbol_tables[0];
        check(table.symbol_table == 1 &&
                  table.indirect_symbols == std::vector<std::uint32_t>{0, 0x80000000, 0xc0000000},
              "indirect symbols preserve exact nlist namespace and local/absolute markers");
        auto bad = data;
        put(bad, at + 28, 10, 4, false);
        check(!load(bad), "dynamic symbol groups stay within nlist table");
        bad = data;
        put(bad, 3072, 9, 4, false);
        check(!load(bad), "indirect nlist index cannot exceed declared symbol table");
    }
}
void complete_header_anchors() {
    for (bool wide : {false, true})
        for (bool big : {false, true})
            for (bool fat : {false, true})
                for (unsigned shape = 0; shape < 5; ++shape) {
                    // Full, truncated, discontiguous, later-byte alias, compatible split.
                    const bool valid = shape == 0 || shape == 4;
                    auto data = thin(wide, big);
                    data.resize(1024);
                    const auto header = wide ? 32u : 28u, stride = wide ? 72u : 56u;
                    const bool extra = shape >= 2;
                    const auto segments = extra ? 3u : 2u;
                    put(data, 12, 2, 4, big);
                    put(data, 16, segments + 2, 4, big);
                    put(data, 20, segments * stride + 40, 4, big);
                    segment(data, wide, big, header, 0x1000,
                            shape == 1                 ? 1
                            : shape == 2 || shape == 4 ? 16
                                                       : header,
                            0,
                            shape == 1                 ? 1
                            : shape == 2 || shape == 4 ? 16
                                                       : header,
                            1);
                    segment(data, wide, big, header + stride, 0x2000, 16, 512, 16, 5);
                    if (extra)
                        segment(data, wide, big, header + 2 * stride, shape == 4 ? 0x1010 : 0x3000, header - 16, 16,
                                header - 16, 1);
                    const auto main = header + segments * stride;
                    put(data, main, 0x80000028, 4, big);
                    put(data, main + 4, 24, 4, big);
                    put(data, main + 8, 0x1000, 8, big);
                    put(data, main + 16, 0, 8, big);
                    const auto exports = main + 24;
                    put(data, exports, 0x80000033, 4, big);
                    put(data, exports + 4, 16, 4, big);
                    put(data, exports + 8, 768, 4, big);
                    put(data, exports + 12, 11, 4, big);
                    const unsigned trie[] = {0, 1, '_', 'f', 0, 6, 3, 0, 0x80, 0x20, 0};
                    for (unsigned i = 0; i < 11; ++i)
                        data[768 + i] = std::byte(trie[i]);
                    data[512] = std::byte{0xc3};
                    MachOOptions options;
                    const auto source_bias = fat ? 8192u : 0u;
                    if (fat) {
                        std::vector<std::byte> container(12288);
                        put(container, 0, 0xcafebabe, 4, true);
                        put(container, 4, 2, 4, true);
                        for (unsigned i = 0; i < 2; ++i) {
                            const auto at = 8 + i * 20;
                            put(container, at, wide ? 0x01000007 : 7, 4, true);
                            put(container, at + 4, 0x80000003, 4, true);
                            put(container, at + 8, 4096 + i * 4096, 4, true);
                            put(container, at + 12, data.size(), 4, true);
                            put(container, at + 16, 12, 4, true);
                            std::copy(data.begin(), data.end(), container.begin() + 4096 + i * 4096);
                        }
                        data = std::move(container);
                        options.slice_index = 1;
                    }
                    const auto loaded = take(load_macho(std::make_shared<MemoryStorage>(std::move(data)), options, {}));
                    const auto &m = *loaded.metadata.macho;
                    check(m.entries.size() == 1 && m.entries[0].value == 0x1000 &&
                              m.entries[0].record_file_offset == source_bias + main &&
                              m.entries[0].address.has_value() == valid &&
                              loaded.image->layout().entries.size() == (valid ? 1u : 0u),
                          "entry requires complete unique contiguous fixed-header mapping; raw declaration retained");
                    check(m.dyld_exports.size() == 1 && m.dyld_exports[0].value == 0x1000 &&
                              m.dyld_exports[0].record_file_offset == source_bias + 774 &&
                              m.dyld_exports[0].address.has_value() == valid && (valid || !loaded.metadata_complete),
                          "export cannot invent a header-relative address from partial or ambiguous backing");
                    const auto resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
                    check(resolver.preferred_header().has_value() == valid,
                          "loader entries/exports and public dyld resolver agree on fixed-header authority");
                    if (!big) {
                        const auto functions = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
                        check(functions->functions.size() == (valid ? 1u : 0u),
                              "invalid header anchor cannot seed false automatic functions");
                    }
                }
}
} // namespace
int main() {
    return run([] {
        commands();
        compact_unwind_roots();
        eh_frame_roots();
        thread_entries();
        indirect_tables();
        complete_header_anchors();
    });
}
