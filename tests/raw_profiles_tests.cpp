#include "hexlab/loaders/x86_raw_profile.hpp"
#include "hexlab/loaders/recipe.hpp"
#include "hexlab/processors/decoder.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
using namespace hexlab;
using namespace hexlab_test;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
X86RawProfile real_profile() {
    return {X86ImageEnvironment::real386,
            A20Policy::enabled,
            0x10010,
            {{1}, 0x10},
            {},
            {{{1}, 0x1000, true, "text", {}}, {{2}, 0x1001, false, "data", {}}}};
}
X86RawProfile protected_profile() {
    X86RawProfile p{X86ImageEnvironment::protected386, A20Policy::enabled, 0x10000, {{1}, 0}, std::uint16_t{0x10}, {}};
    p.domains = {
        {{1}, 8, true, "text", X86SegmentDescriptor{0x10000, 0xffff, true, true, true, false, false, false, false, 0}},
        {{2},
         0x10,
         false,
         "stack",
         X86SegmentDescriptor{0x20000, 0xffff, true, false, true, true, false, true, false, 0}}};
    return p;
}
void codec_tests() {
    const std::string literal =
        "hexlab-x86-profile 1\nenvironment real386\na20 enabled\nload 0x10010\nentry 1 0x10\nstack none\ndomains "
        "2\ndomain 1 0x1000 code \"text\" real\ndomain 2 0x1001 data \"data\" real\n";
    auto p = take(parse_x86_profile(literal));
    check(p == real_profile(), "literal profile declares load position and separate logical domains");
    check(take(format_x86_profile(p)) == literal, "profile has a literal stable canonical UTF8 encoding");
    auto unsorted = p;
    std::swap(unsorted.domains[0], unsorted.domains[1]);
    check(take(format_x86_profile(unsorted)) == literal, "canonical profile sorts by stable domain id");
    auto unicode = p;
    unicode.domains[0].name = "text \xce\xbb \\\"";
    auto encoded = take(format_x86_profile(unicode));
    check(take(parse_x86_profile(encoded)) == unicode, "quoted UTF8 names and escaped quotes/backslashes roundtrip");
    auto pm = protected_profile();
    check(take(parse_x86_profile(take(format_x86_profile(pm)))) == pm,
          "protected descriptors and SS selector roundtrip");
    auto raw = take(make_x86_raw_options(p));
    check(raw.architecture == Architecture::x86 && raw.mode == ExecutionMode::x86_16 && raw.base == Address{{1}, 0} &&
              raw.entry == p.entry && raw.x86_profile == p,
          "normalized raw options contain the complete profile");
    auto recipe = take(encode_recipe({Format::raw, raw}));
    check(recipe.size() == literal.size() + 7 && recipe[0] == std::byte{2} && recipe[1] == std::byte{0} &&
              recipe[2] == std::byte{3} &&
              std::string(reinterpret_cast<const char *>(recipe.data() + 7), recipe.size() - 7) == literal,
          "segmented recipe v2 embeds canonical profile rather than external path");
    auto restored = take(decode_recipe(recipe));
    check(restored.raw && restored.raw->x86_profile == p && take(encode_recipe(restored)) == recipe,
          "segmented recipe roundtrip");
    for (std::size_t n = 0; n < recipe.size(); ++n)
        check(!decode_recipe(std::span(recipe).first(n)), "all truncated segmented recipes fail");
    auto trailing = recipe;
    trailing.push_back(std::byte{0});
    check(!decode_recipe(trailing), "segmented recipe rejects trailing bytes");
    auto noncanonical = recipe;
    noncanonical.push_back(std::byte{'#'});
    const auto length = static_cast<std::uint32_t>(noncanonical.size() - 7);
    for (unsigned i = 0; i != 4; ++i)
        noncanonical[3 + i] = static_cast<std::byte>((length >> (24 - i * 8)) & 0xff);
    check(bool(parse_x86_profile(literal + "#")) && !decode_recipe(noncanonical),
          "human comments are accepted but embedded durable recipe must be canonical");
    auto bad_raw = raw;
    bad_raw.mode = ExecutionMode::x86_32;
    check(!encode_recipe({Format::raw, bad_raw}), "profile recipe cannot contradict its entry context");
    FixtureFile file(std::as_bytes(std::span(literal)));
    check(take(read_x86_profile(file.path, {})) == p, "shared bounded profile file reader");
    std::stop_source stop;
    stop.request_stop();
    check(!read_x86_profile(file.path, stop.get_token()), "profile file reader honors cancellation");
}
void mapping_tests() {
    RawOptions m6502{Architecture::mos6502, ExecutionMode::m6502, {{9}, 0x8000}, true, true, true,
                    Address{{9}, 0x8000}, {}, {}};
    auto m6502_image = take(load_raw(std::make_shared<MemoryStorage>(bytes({0xa9, 0x42, 0x60})), m6502, {}));
    check(m6502_image->decode_context() == DecodeContext{Architecture::mos6502, ExecutionMode::m6502, ByteOrder::little} &&
              m6502_image->layout().space.width_bits == 16 &&
              decode_instruction(m6502_image->decode_context(), m6502_image->read({{9}, 0x8000}, 2).value(),
                                 {{9}, 0x8000}).instruction.has_value(),
          "raw MOS 6502 selection creates a 16-bit mapped image with executable entry decoding");
    auto bad_m6502 = m6502;
    bad_m6502.base.offset = 0x10000;
    check(!validate_raw_coordinates(bad_m6502), "raw MOS 6502 mapping rejects coordinates beyond its address width");
    RawOptions rv32{Architecture::riscv32, ExecutionMode::rv32, {{0}, 0x1000}, true, false, true,
                    Address{{0}, 0x1000}, {}, {}};
    auto rv32_image = take(load_raw(std::make_shared<MemoryStorage>(bytes({0x93, 0x00, 0x50, 0x00})), rv32, {}));
    check(rv32_image->layout().space.width_bits == 32 && rv32_image->decode_context() ==
              DecodeContext{Architecture::riscv32, ExecutionMode::rv32, ByteOrder::little} &&
              decode_instruction(rv32_image->decode_context(), bytes({0x93, 0x00, 0x50, 0x00}), {{0}, 0x1000}).instruction,
          "raw RV32I mapping creates a 32-bit executable image");
    rv32.base.offset = UINT32_MAX + UINT64_C(1);
    check(!validate_raw_coordinates(rv32), "raw RV32I mapping rejects coordinates beyond its address width");
    auto p = real_profile();
    auto raw = take(make_x86_raw_options(p));
    auto storage = std::make_shared<MemoryStorage>(bytes({0x90, 0xc3, 0x11, 0x22}));
    auto image = take(load_raw(storage, raw, {}));
    check(image->layout().entries == std::vector<Address>{p.entry} &&
              image->decode_context() ==
                  DecodeContext{Architecture::x86, ExecutionMode::x86_16, ByteOrder::little, 16, true},
          "real entry context remains segmented16");
    check(image->read({{1}, 0x10}, 2).value() == bytes({0x90, 0xc3}) &&
              image->read({{2}, 0}, 2).value() == bytes({0x90, 0xc3}),
          "logical selector aliases read identical initialized bytes");
    check(image->to_file_offset({{1}, 0x11}).value() == FileOffset{1} && !image->to_address({1}),
          "alias reverse navigation remains ambiguous");
    check(image->context_at({{2}, 0}).value().mode == ExecutionMode::unknown,
          "data domain never guesses code bitness from an alias");
    check(!image->read({{1}, 0xf}, 1) && !image->read({{1}, 0x14}, 1),
          "raw profile does not invent uninitialized memory");
    auto pm = protected_profile();
    auto protected_image = take(load_raw(storage, take(make_x86_raw_options(pm)), {}));
    check(protected_image->decode_context() ==
              DecodeContext{Architecture::x86, ExecutionMode::x86_16, ByteOrder::little, 32, true},
          "protected CS.D0 and SS.B1 are independent authoritative attributes");
    check(!protected_image->segment_at({{2}, 0}) && protected_image->space({2}),
          "unbacked declared data domain retains identity");
    pm.domains[0].descriptor->default_big = true;
    auto code32 = take(load_raw(storage, take(make_x86_raw_options(pm)), {}));
    check(code32->decode_context() ==
              DecodeContext{Architecture::x86, ExecutionMode::x86_32, ByteOrder::little, 32, true},
          "protected CS.D1 retains segmented32 rather than flat assumptions");
    pm = protected_profile();
    pm.input_load_address = 0;
    pm.entry.offset = 16;
    pm.domains[0].descriptor->base = 0xfffffff0;
    pm.domains[0].descriptor->effective_limit = UINT32_MAX;
    auto wrap = take(load_raw(storage, take(make_x86_raw_options(pm)), {}));
    check(wrap->to_file_offset({{1}, 16}).value() == FileOffset{0} &&
              wrap->read({{1}, 16}, 2).value() == bytes({0x90, 0xc3}),
          "protected linear32 wrap maps to its actual backing intersection");
    pm = protected_profile();
    pm.input_load_address = 0x12000;
    pm.domains[0].descriptor->base = 0x12000;
    pm.domains[1].descriptor->base = 0x10000;
    pm.domains[1].descriptor->effective_limit = 0x1fff;
    pm.domains[1].descriptor->expand_down = true;
    pm.domains[1].descriptor->default_big = false;
    auto down = take(load_raw(storage, take(make_x86_raw_options(pm)), {}));
    check(down->to_file_offset({{2}, 0x2000}).value() == FileOffset{0} &&
              down->read({{2}, 0x2000}, 2).value() == bytes({0x90, 0xc3}) && !down->read({{2}, 0x1fff}, 1) &&
              !down->read({{2}, 0x10000}, 1),
          "expand-down data maps initialized backing above the exclusive limit within SS.B bound");
    p = real_profile();
    p.a20 = A20Policy::disabled;
    p.input_load_address = 0;
    p.entry = {{1}, 0};
    p.domains = {{{1}, 0xffff, true, "wrap", {}}};
    auto data = std::vector<std::byte>(0x100000);
    data[0xfffff] = std::byte{0xaa};
    data[0] = std::byte{0xbb};
    auto a20 = take(load_raw(std::make_shared<MemoryStorage>(std::move(data)), take(make_x86_raw_options(p)), {}));
    check(a20->read({{1}, 15}, 2).value() == bytes({0xaa, 0xbb}) &&
              a20->to_file_offset({{1}, 16}).value() == FileOffset{0},
          "real A20 wrap yields adjacent logical segments with split canonical backing");
    auto no_entry = p;
    no_entry.input_load_address = 0x20000;
    check(!load_raw(storage, take(make_x86_raw_options(no_entry)), {}),
          "entry must have initialized executable backing");
    p = real_profile();
    p.input_load_address = UINT32_MAX;
    check(!load_raw(storage, take(make_x86_raw_options(p)), {}), "physical input extent cannot overflow32 bits");
}
void invalid_tests() {
    auto p = real_profile();
    auto bad = p;
    bad.domains.push_back(bad.domains[0]);
    check(!validate_x86_profile(bad), "duplicate domain or selector rejected");
    bad = p;
    bad.entry.space = {99};
    check(!validate_x86_profile(bad), "unknown entry domain rejected");
    bad = p;
    bad.entry = {{2}, 0};
    check(!validate_x86_profile(bad), "data domain cannot be active CS");
    bad = p;
    bad.entry.offset = 0x10000;
    check(!validate_x86_profile(bad), "real entry respects64KiB limit");
    bad = p;
    bad.domains[0].name = std::string(257, 'x');
    check(!validate_x86_profile(bad), "domain name bound");
    bad = p;
    bad.domains[0].name = "\xc0\x80";
    check(!validate_x86_profile(bad), "overlong UTF8 rejected");
    bad = p;
    bad.domains[0].descriptor = X86SegmentDescriptor{};
    check(!validate_x86_profile(bad), "real domain cannot contain protected descriptor");
    bad = protected_profile();
    bad.stack_selector.reset();
    check(!validate_x86_profile(bad), "protected stack attribute must be declared");
    bad = protected_profile();
    bad.domains[1].descriptor->writable = false;
    check(!validate_x86_profile(bad), "SS must be writable data");
    bad = protected_profile();
    bad.domains[0].descriptor->effective_limit = 0x100001;
    check(!validate_x86_profile(bad), "unrepresentable granular descriptor limit rejected");
    bad = protected_profile();
    bad.domains[0].selector = 0;
    check(!validate_x86_profile(bad), "protected null CS rejected");
    const auto text = take(format_x86_profile(p));
    for (auto invalid : {std::string{}, std::string("hexlab-x86-profile 99\n"), text + "load 1\n", text + "unknown 1\n",
                         std::string("\xc0\x80") + text, std::string(1024 * 1024 + 1, 'x')})
        check(!parse_x86_profile(invalid), "bounded profile parser rejects unknown/duplicate/version/UTF8 cases");
    auto mismatch = text;
    auto at = mismatch.find("domains 2");
    mismatch.replace(at, 9, "domains 3");
    check(!parse_x86_profile(mismatch), "declared domain count detects missing records");
    auto long_count = text;
    at = long_count.find("domains 2");
    long_count.replace(at, 9, "domains 4294967295");
    check(!parse_x86_profile(long_count), "domain count bounded before allocation");
    auto pmtext = take(format_x86_profile(protected_profile()));
    pmtext.replace(pmtext.find("domains 2"), 9, "domains 3");
    for (auto field : {std::string("domain 3 0x18 code \"bad\" 0000000000820000\n"),
                       std::string("domain 3 0x18 code \"bad\" ffff0000009aa000\n")}) {
        auto rejected = parse_x86_profile(pmtext + field);
        check(!rejected && rejected.error().code == ErrorCode::unsupported,
              "system/long descriptors cannot enter a profile");
    }
}
} // namespace
int main() {
    return run([] {
        codec_tests();
        mapping_tests();
        invalid_tests();
    });
}
