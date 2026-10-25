#include "hexlab/loaders/elf.hpp"
#include "hexlab/loaders/elf_unwind.hpp"
#include "hexlab/analysis/analysis.hpp"
#include "hexlab/analysis/functions.hpp"
#include "support/elf_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/fixture_files.hpp"
#include "support/checks.hpp"
#include <array>
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::elf_fixture;
namespace {
Result<LoadedImage> load(const std::vector<std::byte> &data) {
    return load_elf(std::make_shared<MemoryStorage>(data), {});
}
std::vector<std::byte> executable_with_lines() {
    auto data=executable(true,false);data.resize(2048);
    constexpr std::string_view names("\0.text\0.debug_line\0.shstrtab\0",29);
    for(std::size_t i=0;i<names.size();++i)data[900+i]=std::byte(names[i]);
    auto section_at=[&](std::size_t i,std::uint32_t name,std::uint32_t type,std::uint64_t flags,std::uint64_t address,std::uint64_t offset,std::uint64_t size){const auto a=512+i*64;put(data,a,name,4);put(data,a+4,type,4);put(data,a+8,flags,8);put(data,a+16,address,8);put(data,a+24,offset,8);put(data,a+32,size,8);put(data,a+48,1,8);};
    section_at(1,1,1,6,0x400000,256,16);
    std::vector<std::uint8_t> line;auto u32=[&](std::uint32_t n){for(unsigned i=0;i<4;++i)line.push_back((n>>(8*i))&255);};u32(0);const auto unit=line.size();line.insert(line.end(),{4,0});u32(0);const auto header=line.size();line.insert(line.end(),{1,1,1,0xfb,14,13});for(int i=0;i<12;++i)line.push_back(i==1?0:1);line.push_back(0);line.insert(line.end(),{'s','r','c','.','c',0,0,0,0,0});const auto hsize=static_cast<std::uint32_t>(line.size()-header);for(unsigned i=0;i<4;++i)line[unit+2+i]=(hsize>>(i*8))&255;line.insert(line.end(),{0,9,2});for(unsigned i=0;i<8;++i)line.push_back(i==2?0x40:0);
    line.insert(line.end(),{1,0,1,1});const auto length=static_cast<std::uint32_t>(line.size()-4);for(unsigned i=0;i<4;++i)line[i]=(length>>(i*8))&255;
    for(std::size_t i=0;i<line.size();++i)data[1000+i]=std::byte(line[i]);
    section_at(2,7,1,0,0,1000,line.size());section_at(3,18,3,0,0,900,names.size());
    put(data,40,512,8);put(data,58,64,2);put(data,60,4,2);put(data,62,3,2);
    return data;
}
std::vector<std::byte> executable_with_dwarf_info(bool malformed = false, bool v5 = false) {
    auto data = executable(true, false);
    data.resize(1800);
    constexpr std::string_view names("\0.text\0.debug_info\0.debug_abbrev\0.debug_str\0.shstrtab\0", 54);
    for (std::size_t i = 0; i < names.size(); ++i) data[900 + i] = std::byte(names[i]);
    const auto section_at = [&](std::size_t i, std::uint32_t name, std::uint32_t type, std::uint64_t flags,
                                std::uint64_t address, std::uint64_t offset, std::uint64_t size) {
        const auto a = 512 + i * 64;
        put(data, a, name, 4); put(data, a + 4, type, 4); put(data, a + 8, flags, 8);
        put(data, a + 16, address, 8); put(data, a + 24, offset, 8); put(data, a + 32, size, 8);
        put(data, a + 48, 1, 8);
    };
    std::vector<std::uint8_t> abbrev;
    const auto uleb = [&](std::vector<std::uint8_t>& out, std::uint64_t value) {
        do { auto b = static_cast<std::uint8_t>(value & 0x7f); value >>= 7; if (value) b |= 0x80; out.push_back(b); } while (value);
    };
    const auto string = [](std::vector<std::uint8_t>& out, std::string_view value) {
        for (char c : value) out.push_back(static_cast<std::uint8_t>(c)); out.push_back(0);
    };
    // CU(name, children), base_type(name,size,encoding), subprogram(name,low_pc,high_pc).
    uleb(abbrev,1); uleb(abbrev,0x11); abbrev.push_back(1); uleb(abbrev,3); uleb(abbrev,8); uleb(abbrev,0); uleb(abbrev,0);
    uleb(abbrev,2); uleb(abbrev,0x24); abbrev.push_back(0); uleb(abbrev,3); uleb(abbrev,8);
    uleb(abbrev,0x0b); uleb(abbrev,0x0b); uleb(abbrev,0x3e); uleb(abbrev,0x0b); uleb(abbrev,0); uleb(abbrev,0);
    uleb(abbrev,3); uleb(abbrev,0x2e); abbrev.push_back(0); uleb(abbrev,3); uleb(abbrev,8);
    uleb(abbrev,0x11); uleb(abbrev,1); uleb(abbrev,0x12); uleb(abbrev,6); uleb(abbrev,0); uleb(abbrev,0); uleb(abbrev,0);
    std::vector<std::uint8_t> info(4);
    const auto append = [&](std::uint64_t value, unsigned size) { for (unsigned i=0;i<size;++i) info.push_back(static_cast<std::uint8_t>(value>>(8*i))); };
    if(v5){append(5,2);info.push_back(1);info.push_back(8);append(0,4);}else{append(4,2);append(0,4);info.push_back(8);} uleb(info,1); string(info,"sample.c");
    uleb(info,2); string(info,"int"); info.push_back(4); info.push_back(5);
    uleb(info,3); string(info,"entry"); append(0x400000,8); append(2,4); uleb(info,0);
    const auto length = static_cast<std::uint32_t>(info.size()-4);
    for (unsigned i=0;i<4;++i) info[i]=static_cast<std::uint8_t>(length>>(8*i));
    if (malformed) info.pop_back();
    for (std::size_t i=0;i<info.size();++i) data[1000+i]=std::byte(info[i]);
    for (std::size_t i=0;i<abbrev.size();++i) data[1200+i]=std::byte(abbrev[i]);
    constexpr std::string_view strings("sample.c\0int\0entry\0", 19);
    for (std::size_t i=0;i<strings.size();++i) data[1400+i]=std::byte(strings[i]);
    section_at(1,1,1,6,0x400000,256,16); section_at(2,7,1,0,0,1000,info.size());
    section_at(3,19,1,0,0,1200,abbrev.size()); section_at(4,33,3,0,0,1400,strings.size());
    section_at(5,44,3,0,0,900,names.size());
    put(data,40,512,8); put(data,58,64,2); put(data,60,6,2); put(data,62,5,2);
    return data;
}
void dwarf_debug_info_rows() {
    auto loaded = load(executable_with_dwarf_info());
    check(loaded && loaded.value().metadata.elf && loaded.value().metadata.elf->dwarf_info.has_value(),
          "ELF loader retains parsed DWARF v4 project-import records");
    if (loaded && loaded.value().metadata.elf && loaded.value().metadata.elf->dwarf_info) {
        const auto &debug = *loaded.value().metadata.elf->dwarf_info;
        check(debug.symbols.size() == 1 && debug.symbols.front().name == "entry" &&
                  debug.symbols.front().address == 0x400000 && debug.symbols.front().type &&
                  debug.symbols.front().type->kind() == types::Kind::function,
              "DWARF function, address, and prototype survive ELF loading");
        check(debug.types.size() == 1 && debug.types.front().source_name == "int" &&
                  debug.types.front().type->size() == 4,
              "DWARF named type graph survives ELF loading");
    }
    auto malformed = load(executable_with_dwarf_info(true));
    check(malformed && !malformed.value().metadata_complete && malformed.value().metadata.elf &&
              !malformed.value().metadata.elf->dwarf_info && !malformed.value().diagnostics.empty(),
          "malformed DWARF is diagnosed without preventing ELF loading");
    auto v5=load(executable_with_dwarf_info(false,true));
    check(v5&&v5.value().metadata.elf&&v5.value().metadata.elf->dwarf_info&&
              v5.value().metadata.elf->dwarf_info->symbols.size()==1&&
              v5.value().metadata.elf->dwarf_info->symbols.front().name=="entry"&&
              v5.value().metadata.elf->dwarf_info->types.size()==1,
          "ELF v5 compile unit feeds names, prototype, and named type into the existing import records");
    auto malformed_v5=load(executable_with_dwarf_info(true,true));
    check(malformed_v5&&!malformed_v5.value().metadata_complete&&malformed_v5.value().metadata.elf&&
              !malformed_v5.value().metadata.elf->dwarf_info,
          "malformed DWARF v5 leaves ELF loadable without publishing a partial import");
}
std::vector<std::byte> executable_with_unwind(bool wide = true, std::uint16_t machine = 62) {
    auto data = executable(wide, false);
    data.resize(2048);
    // Two tiny x86-64 functions. The second is not reachable from the entry.
    data[258] = std::byte{0x90};
    data[259] = std::byte{0xc3};
    // Keep all metadata and code file-backed through one simple PT_LOAD.
    program(data, wide, 0, 1, 256, 0x400000, 1200, 1200, 5, 256);
    put(data, 18, machine, 2);
    constexpr std::string_view names("\0.text\0.eh_frame\0.shstrtab\0", 27);
    for (std::size_t i = 0; i < names.size(); ++i)
        data[1100 + i] = std::byte(names[i]);
    auto section_at = [&](std::size_t i, std::uint32_t name, std::uint32_t type, std::uint64_t flags,
                          std::uint64_t address, std::uint64_t offset, std::uint64_t size) {
        const auto a = 512 + i * (wide ? 64 : 40);
        put(data, a, name, 4); put(data, a + 4, type, 4); put(data, a + 8, flags, wide ? 8 : 4);
        put(data, a + (wide ? 16 : 12), address, wide ? 8 : 4);
        put(data, a + (wide ? 24 : 16), offset, wide ? 8 : 4);
        put(data, a + (wide ? 32 : 20), size, wide ? 8 : 4);
        put(data, a + (wide ? 48 : 32), 1, wide ? 8 : 4);
    };
    // CIE: version 1, "zR", code alignment 1, data alignment -8,
    // return register 16, and pcrel|sdata4 FDE pointers.
    const std::array<std::uint8_t, 17> cie{13,0,0,0, 0,0,0,0, 1,'z','R',0, 1,0x78,16,1,0x1b};
    std::copy(cie.begin(), cie.end(), reinterpret_cast<std::uint8_t *>(data.data() + 1024));
    std::vector<std::uint8_t> fde{13,0,0,0};
    const std::uint32_t cie_pointer = 21; // Back from this field to the CIE record start at section offset 0.
    for (unsigned i = 0; i < 4; ++i) fde.push_back(static_cast<std::uint8_t>(cie_pointer >> (8 * i)));
    const std::int32_t delta = static_cast<std::int32_t>(0x400002 - (0x400300 + 25));
    for (unsigned i = 0; i < 4; ++i) fde.push_back(static_cast<std::uint8_t>(static_cast<std::uint32_t>(delta) >> (8 * i)));
    fde.insert(fde.end(), {2,0,0,0, 0}); // two-byte range and empty FDE augmentation
    std::copy(fde.begin(), fde.end(), reinterpret_cast<std::uint8_t *>(data.data() + 1041));
    data[1058] = std::byte{0}; data[1059] = std::byte{0}; data[1060] = std::byte{0}; data[1061] = std::byte{0};
    section_at(1, 1, 1, 6, 0x400000, 256, 16);
    section_at(2, 7, 1, 2, 0x400300, 1024, 38);
    section_at(3, 17, 3, 0, 0, 1100, names.size());
    put(data, wide ? 40 : 32, 512, wide ? 8 : 4);
    put(data, wide ? 58 : 46, wide ? 64 : 40, 2);
    put(data, wide ? 60 : 48, 4, 2); put(data, wide ? 62 : 50, 3, 2);
    return data;
}
void dwarf_source_rows() {
    auto loaded=load(executable_with_lines());
    check(loaded&&loaded.value().metadata.elf&&loaded.value().metadata.elf->source_lines.size()==2,
          "ELF loader retains DWARF source rows in ELF metadata");
    if(loaded&&loaded.value().metadata.elf){const auto&rows=loaded.value().metadata.elf->source_lines;check(rows[0].address==Address{{0},0x400000}&&rows[0].file=="src.c"&&rows[0].line==1,"DWARF address, file, and line survive ELF loading");check(rows.back().end_sequence,"DWARF end-sequence row survives ELF loading");}
}
void eh_frame_function_roots() {
    auto loaded = load(executable_with_unwind());
    check(bool(loaded), "bounded .eh_frame fixture loads");
    if (!loaded) return;
    check(loaded.value().metadata.elf && loaded.value().metadata.elf->unwind_ranges.size() == 1,
          "ELF loader retains one validated FDE code range");
    if (loaded.value().metadata.elf && !loaded.value().metadata.elf->unwind_ranges.empty()) {
        const auto &range = loaded.value().metadata.elf->unwind_ranges.front();
        check(range.section == 2 && range.file_offset == 1041 && range.record_size == 17 &&
                  range.begin == Address{{0}, 0x400002} && range.size == 2,
              "FDE metadata exposes exact function bounds and source-byte provenance");
    }
    check(loaded.value().metadata.elf && loaded.value().metadata.elf->eh_frame_functions.size() == 1 &&
              loaded.value().metadata.elf->eh_frame_functions.front().code_alignment == 1 &&
              loaded.value().metadata.elf->eh_frame_functions.front().data_alignment == -8 &&
              loaded.value().metadata.elf->eh_frame_functions.front().return_register == 16,
          "ELF x86-64 FDE metadata retains CIE factors and return register for live CFI evaluation");
    auto functions = recover_functions(*loaded.value().image, loaded.value().metadata, {}, {}, {});
    check(bool(functions), "function recovery consumes ELF unwind evidence");
    if (functions) {
        check(std::any_of(functions.value()->functions.begin(), functions.value()->functions.end(),
                          [](const auto &function) { return function->entry == Address{{0}, 0x400002}; }),
              "validated .eh_frame FDE establishes otherwise unreachable function root");
        const auto found = std::find_if(functions.value()->functions.begin(), functions.value()->functions.end(),
                                        [](const auto &function) { return function->entry == Address{{0}, 0x400002}; });
        check(found != functions.value()->functions.end() &&
                  std::any_of((*found)->seeds.begin(), (*found)->seeds.end(),
                              [](const auto &seed) {
                                  return seed.kind == FunctionSeedKind::unwind && seed.unwind_evidence ==
                                             FunctionSeedUnwindEvidence{2, 1041, 17};
                              }),
              "unwind-established function retains its exact FDE provenance");
    }

    auto truncated_personality = executable_with_unwind();
    truncated_personality[1034] = std::byte{'P'}; // The fixture omits the required encoded personality pointer.
    auto partial = load(truncated_personality);
    check(partial && !partial.value().metadata_complete && partial.value().metadata.elf->unwind_ranges.empty() &&
              std::any_of(partial.value().diagnostics.begin(), partial.value().diagnostics.end(),
                          [](const auto &diagnostic) { return diagnostic.message.find(".eh_frame") != std::string::npos; }),
          "a truncated CIE personality payload is rejected with an explicit diagnostic");

    auto escaping = executable_with_unwind();
    escaping[1054] = std::byte{0x08}; // Expand the FDE range beyond initialized executable bytes.
    partial = load(escaping);
    check(partial && !partial.value().metadata_complete && partial.value().metadata.elf->unwind_ranges.empty(),
          "FDE ranges escaping initialized executable bytes are rejected atomically");

    const std::array<std::pair<bool, std::uint16_t>, 7> architectures{{
        {false, static_cast<std::uint16_t>(3)}, {true, static_cast<std::uint16_t>(62)},
        {false, static_cast<std::uint16_t>(40)}, {true, static_cast<std::uint16_t>(183)},
        {false, static_cast<std::uint16_t>(8)}, {false, static_cast<std::uint16_t>(243)},
        {true, static_cast<std::uint16_t>(243)}}};
    for (const auto [wide, machine] : architectures) {
        auto architecture = load(executable_with_unwind(wide, machine));
        check(architecture && architecture.value().metadata.elf->unwind_ranges.size() == 1 &&
                  std::none_of(architecture.value().diagnostics.begin(), architecture.value().diagnostics.end(),
                               [](const auto &diagnostic) { return diagnostic.message.find("unwind information unavailable") != std::string::npos; }),
              ("common .eh_frame pointer decoding works for machine/class " + std::to_string(machine) + "/" +
               (wide ? "64" : "32")).c_str());
    }
}
void elf_live_cfi() {
    ElfMetadata metadata;
    metadata.header.is_64 = true;
    metadata.header.machine = 62;
    ElfEhFrameFunction fde;
    fde.section = 2; fde.file_offset = 0x240; fde.begin = {{0}, 0x1000}; fde.size = 0x40;
    fde.code_alignment = 1; fde.data_alignment = -8; fde.return_register = 16;
    fde.cie_instructions = {std::byte{0x0c}, std::byte{7}, std::byte{8}}; // CFA = RSP + 8
    fde.instructions = {std::byte{0x90}, std::byte{1}}; // RIP = CFA - 8
    metadata.eh_frame_functions.push_back(fde);
    const auto result = evaluate_elf_unwind(metadata, {{0}, 0x1008}, {{7, 0x3000}},
        [](std::uint64_t at, std::uint8_t width) -> std::optional<std::uint64_t> {
            if (at == 0x3000 && width == 8) return 0xfeed;
            return std::nullopt;
        });
    check(result && result.value().cfa == 0x3008 && result.value().caller.at(16) == 0xfeed &&
              result.value().caller.at(7) == 0x3008 && result.value().function.offset == 0x1000 &&
              result.value().record_file_offset == 0x240,
          "ELF x86-64 FDE evaluator restores return PC, caller SP, CFA, and FDE provenance");
    auto unsupported = metadata;
    unsupported.eh_frame_functions.front().instructions = {std::byte{0x1c}};
    const auto rejected = evaluate_elf_unwind(unsupported, {{0}, 0x1008}, {{7, 0x3000}},
        [](std::uint64_t, std::uint8_t) -> std::optional<std::uint64_t> { return 1; });
    check(!rejected && rejected.error().code == ErrorCode::unsupported,
          "unsupported ELF CFI instruction returns an explicit unsupported state");
    auto oversized = metadata;
    oversized.eh_frame_functions.front().instructions.resize(1024 * 1024 - 2, std::byte{0});
    const auto bounded = evaluate_elf_unwind(oversized, {{0}, 0x1008}, {{7, 0x3000}},
        [](std::uint64_t, std::uint8_t) -> std::optional<std::uint64_t> { return 1; });
    check(!bounded && bounded.error().code == ErrorCode::resource_limit,
          "ELF CFI interpreter bounds combined CIE and FDE program bytes");
    auto at_limit = metadata;
    at_limit.eh_frame_functions.front().instructions.resize(1024 * 1024 - 3, std::byte{0});
    const auto accepted = evaluate_elf_unwind(at_limit, {{0}, 0x1008}, {{7, 0x3000}, {16, 0xfeed}},
        [](std::uint64_t at, std::uint8_t width) -> std::optional<std::uint64_t> {
            if (at == 0x3000 && width == 8) return 0xfeed;
            return std::nullopt;
        });
    check(accepted && accepted.value().caller.at(16) == 0xfeed,
          "ELF CFI program exactly at its combined byte limit remains evaluable");
}
void mappings() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            auto data = executable(wide, big);
            auto result = load(data);
            check(bool(result), "ELF32/64 little/big executable maps declared PT_LOAD");
            if (!result)
                continue;
            const auto &loaded = result.value();
            const auto &image = *loaded.image;
            check(loaded.metadata.elf && loaded.metadata.elf->header.is_64 == wide &&
                      loaded.metadata.elf->programs.size() == 1,
                  "full ELF-specific header and program record retained");
            check(loaded.metadata.format == (wide ? "ELF64" : "ELF32") && loaded.metadata.preferred_base == 0x400000 &&
                      loaded.metadata.image_size == 16,
                  "native ELF metadata does not invent PE RVA sections");
            check(image.layout().space.width_bits == (wide ? 64 : 32) &&
                      image.layout().space.order == (big ? ByteOrder::big : ByteOrder::little),
                  "container width and byte order preserved");
            check(image.decode_context().mode == (big    ? ExecutionMode::unknown
                                                  : wide ? ExecutionMode::x86_64
                                                         : ExecutionMode::x86_32),
                  "only supported machine/class/endian combination selects decoder mode");
            const auto decoded = decode_at(image, {{0}, 0x400000});
            if (big) {
                const auto analyzed = analyze(image, {}, {});
                check(!decoded && decoded.error().code == ErrorCode::unsupported && !analyzed &&
                          analyzed.error().code == ErrorCode::unsupported,
                      "unsupported ELF byte order never decodes or analyzes with a guessed mode");
            } else {
                check(decoded && decoded.value().instruction &&
                          decoded.value().instruction->context.mode ==
                              (wide ? ExecutionMode::x86_64 : ExecutionMode::x86_32),
                      "ELF mapping reaches original decoder with authoritative context");
            }
            check(image.layout().entries == std::vector<Address>{{{0}, 0x400000}},
                  "declared initialized executable entry retained");
            check(image.read({{0}, 0x400000}, 4).value() == bytes({0x90, 0xc3, 0x11, 0x22}),
                  "file-backed bytes preserve provenance");
            check(image.read({{0}, 0x400004}, 12).value() == std::vector<std::byte>(12),
                  "BSS remainder reads zero without file backing");
            check(!image.to_file_offset({{0}, 0x400004}) && image.to_file_offset({{0}, 0x400003}).value().value == 259,
                  "uninitialized memory never becomes a file patch coordinate");
            check(!image.read({{0}, 0x400010}, 1), "gap remains unmapped");
            check(loaded.metadata_reads.intersects({24}, wide ? 8 : 4).value() &&
                      loaded.metadata_reads.intersects({wide ? 64u : 52u}, wide ? 56 : 32).value() &&
                      !loaded.metadata_reads.intersects({256}, 4).value(),
                  "metadata dependencies include headers/table and exclude unparsed code");
            auto dyn = data;
            put(dyn, 16, 3, 2, big);
            check(load(dyn).value().image->to_file_offset({{0}, 0x400003}).value().value == 259,
                  "DYN retains declared coordinates without ASLR guess");
            auto noentry = data;
            put(noentry, 24, 0, wide ? 8 : 4, big);
            check(load(noentry).value().image->layout().entries.empty(), "entry0 is absent rather than invented root");
            auto badentry = data;
            put(badentry, 24, 0x400008, wide ? 8 : 4, big);
            auto partial = load(badentry);
            check(partial && partial.value().image->layout().entries.empty() && !partial.value().diagnostics.empty(),
                  "uninitialized entry diagnosed without fabricated executable seed");
            auto bad = data;
            program(bad, wide, 0, 1, 256, 0x400000, 17, 16, 5, 256, big);
            check(!load(bad), "file size exceeding memory size rejected");
            bad = data;
            program(bad, wide, 0, 1, 1020, 0x400000, 8, 16, 5, 1, big);
            check(!load(bad), "PT_LOAD backing must fit source");
            bad = data;
            program(bad, wide, 0, 1, 256, 0x400000, 4, 16, 5, 3, big);
            check(!load(bad), "alignment must be power of two");
            bad = data;
            program(bad, wide, 0, 1, 257, 0x400000, 4, 16, 5, 256, big);
            check(!load(bad), "alignment requires file/virtual congruence");
            bad = data;
            program(bad, wide, 0, 1, 256, wide ? UINT64_MAX - 4 : 0xfffffffc, 4, 16, 5, 1, big);
            check(!load(bad), "mapping overflow and32-bit domain extent checked");
            auto unknown = data;
            put(unknown, 18, 0xbeef, 2, big);
            const auto unknown_image = load(unknown).value().image;
            check(unknown_image->decode_context().mode == ExecutionMode::unknown,
                  "unknown machine stays inspectable with unknown mode");
            const auto unknown_analysis = analyze(*unknown_image, {}, {});
            check(!unknown_analysis && unknown_analysis.error().code == ErrorCode::unsupported,
                  "unknown ELF machine yields honest unsupported analysis");
        }
}
void load_permissions() {
    // ELF PF_X/PF_W/PF_R are bits 0/1/2. Keep each bit independently
    // observable because the common R|X fixture cannot reveal an R/X swap.
    for (bool wide : {false, true}) {
        for (bool big : {false, true}) {
            for (std::uint32_t flags = 0; flags < 8; ++flags) {
                auto data = executable(wide, big);
                program(data, wide, 0, 1, 256, 0x400000, 4, 16, flags, 256, big);
                auto result = load(data);
                check(bool(result), "ELF PT_LOAD permission combination maps");
                if (!result || result.value().image->layout().segments.empty())
                    continue;
                const auto &segment = result.value().image->layout().segments.front();
                check(segment.executable == bool(flags & 1) && segment.writable == bool(flags & 2) &&
                          segment.readable == bool(flags & 4),
                      "ELF PF_X/PF_W/PF_R map to executable/writable/readable independently");
            }
        }
    }
}
void mips32_machine_context() {
    auto data = executable(false, false);
    put(data, 18, 8, 2); // EM_MIPS
    program(data, false, 0, 1, 256, 0x400000, 16, 16, 5, 256, false);
    const std::array<std::uint8_t, 16> mips_code{0x01,0x00,0x00,0x10, 0xff,0xff,0x08,0x24,
                                                  0x08,0x00,0xe0,0x03, 0x00,0x00,0x00,0x00};
    for (std::size_t i = 0; i < mips_code.size(); ++i) data[256 + i] = std::byte{mips_code[i]};
    auto loaded = load(data);
    check(loaded && loaded.value().image->decode_context() == DecodeContext{Architecture::mips32, ExecutionMode::mips32, ByteOrder::little},
          "ELF32 little-endian EM_MIPS selects MIPS32 context");
    if (loaded) {
        auto decoded = decode_at(*loaded.value().image, {{0},0x400000});
        check(decoded && decoded.value().instruction && decoded.value().instruction->opcode == Opcode::mips_beq,
              "ELF MIPS entry reaches the MIPS32 decoder");
        auto analyzed = analyze(*loaded.value().image, {}, {});
        check(analyzed && analyzed.value().instructions.size() == 4 &&
                  std::any_of(analyzed.value().edges.begin(), analyzed.value().edges.end(),
                              [](const auto &edge) { return edge.kind == EdgeKind::delay_slot; }),
              "ELF MIPS analysis traverses branch/return delay slots through explicit edges");
    }
    data = executable(false, true);
    put(data, 18, 8, 2, true);
    program(data, false, 0, 1, 256, 0x400000, 16, 16, 5, 256, true);
    const std::array<std::uint8_t, 16> big_mips_code{0x10,0x00,0x00,0x01, 0x24,0x08,0xff,0xff,
                                                     0x03,0xe0,0x00,0x08, 0x00,0x00,0x00,0x00};
    for (std::size_t i = 0; i < big_mips_code.size(); ++i) data[256 + i] = std::byte{big_mips_code[i]};
    auto big = load(data);
    check(big && big.value().image->decode_context().architecture == Architecture::mips32 &&
              big.value().image->decode_context() == DecodeContext{Architecture::mips32, ExecutionMode::mips32, ByteOrder::big},
          "ELF32 big-endian EM_MIPS selects the MIPS32 big-endian context");
    if (big) {
        auto decoded = decode_at(*big.value().image, {{0},0x400000});
        check(decoded && decoded.value().instruction && decoded.value().instruction->opcode == Opcode::mips_beq &&
                  decoded.value().instruction->direct_target == Address{{0},0x400008},
              "ELF big-endian MIPS entry decodes branch displacement and target");
    }
}
void mips64_machine_context() {
    auto data = executable(true, false);
    put(data, 18, 8, 2); // EM_MIPS
    program(data, true, 0, 1, 256, 0x400000, 16, 16, 5, 256, false);
    const std::array<std::uint8_t, 16> code{0xf8,0xff,0x88,0x64, 0xf8,0xff,0xa8,0xdf,
                                            0x08,0x00,0xe0,0x03, 0x00,0x00,0x00,0x00};
    for (std::size_t i = 0; i < code.size(); ++i) data[256 + i] = std::byte{code[i]};
    const auto loaded = load(data);
    check(loaded && loaded.value().image->decode_context() ==
                        DecodeContext{Architecture::mips64, ExecutionMode::mips64, ByteOrder::little},
          "ELF64 little-endian EM_MIPS selects MIPS64 context");
    if (loaded) {
        const auto decoded = decode_at(*loaded.value().image, {{0}, 0x400000});
        check(decoded && decoded.value().instruction && decoded.value().instruction->opcode == Opcode::mips64_daddiu &&
                  decoded.value().instruction->operands.size() == 3,
              "ELF64 MIPS entry reaches the MIPS64 decoder");
    }
    data = executable(true, true);
    put(data, 18, 8, 2, true); // EM_MIPS in a big-endian ELF64 header.
    program(data, true, 0, 1, 256, 0x400000, 16, 16, 5, 256, true);
    const std::array<std::uint8_t, 16> big_code{0x64,0x88,0xff,0xf8, 0xdf,0xb0,0x00,0x20,
                                                0x03,0xe0,0x00,0x08, 0x00,0x00,0x00,0x00};
    for (std::size_t i = 0; i < big_code.size(); ++i) data[256 + i] = std::byte{big_code[i]};
    const auto big = load(data);
    check(big && big.value().image->decode_context() ==
                    DecodeContext{Architecture::mips64, ExecutionMode::mips64, ByteOrder::big},
          "ELF64 big-endian EM_MIPS selects the MIPS64 decoder context");
    if (big) {
        const auto decoded = decode_at(*big.value().image, {{0}, 0x400000});
        check(decoded && decoded.value().instruction && decoded.value().instruction->opcode == Opcode::mips64_daddiu &&
                  decoded.value().instruction->context.order == ByteOrder::big,
              "ELF64 big-endian MIPS entry reaches the MIPS64 decoder");
    }
}
void overlap() {
    auto data = executable(true);
    program(data, true, 0, 1, 256, 0x400000, 16, 24, 5);
    program(data, true, 1, 1, 260, 0x400004, 8, 8, 6);
    auto result = load(data);
    check(bool(result), "compatible PT_LOAD overlap normalizes identical backing");
    if (result) {
        const auto &image = *result.value().image;
        check(image.segment_at({{0}, 0x400004})->writable && image.segment_at({{0}, 0x400004})->executable &&
                  !image.segment_at({{0}, 0x400000})->writable,
              "overlap permission union limited to actual intersection");
        check(image.to_file_offset({{0}, 0x400007}).value().value == 263,
              "normalized overlap retains original file coordinate");
    }
    program(data, true, 1, 1, 272, 0x400004, 8, 8, 6);
    check(!load(data), "conflicting PT_LOAD backing rejected without choosing bytes");
    data = executable(true);
    program(data, true, 1, 1, 272, 0x400004, 4, 4, 6);
    check(!load(data), "zero-fill versus initialized overlap rejected");
    data = executable(true);
    program(data, true, 1, 1, 0, 0x400008, 0, 8, 6);
    check(bool(load(data)), "two zero-filled overlapping spans are compatible");
}
void objects() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            auto data = object(wide, big);
            auto result = load(data);
            check(bool(result), "REL maps allocated sections in declared section domains");
            if (!result)
                continue;
            const auto &loaded = result.value();
            const auto &image = *loaded.image;
            check(loaded.metadata.elf && loaded.metadata.elf->sections.size() == 5 &&
                      loaded.metadata.elf->sections[1].name == ".text" &&
                      loaded.metadata.elf->sections[2].name == ".other",
                  "section names and full metadata retained");
            check(image.layout().entries.empty() && image.layout().segments.size() == 3,
                  "REL has no fabricated linked entry or metadata mappings");
            check(image.read({{1}, 0}, 2).value() == bytes({0x90, 0xc3}) &&
                      image.read({{2}, 0}, 2).value() == bytes({0x40, 0xc3}),
                  "equal offsets in two object sections preserve distinct bytes");
            check(image.to_address({256}).value() == Address{{1}, 0} &&
                      image.to_address({272}).value() == Address{{2}, 0},
                  "canonical file mapping returns actual section identity");
            check(image.read({{3}, 0}, 8).value() == std::vector<std::byte>(8) && !image.to_file_offset({{3}, 0}),
                  "NOBITS section has no phantom file extent even with large conceptual offset");
            check(loaded.metadata_reads.intersects({384}, 29).value(),
                  "section strings contribute metadata dependencies");
            auto bad = data;
            section(bad, wide, 1, 99, 1, 6, 0, 256, 4, 16, big);
            check(!load(bad), "section-name offset bounded");
            bad = data;
            bad[384] = std::byte{'x'};
            check(!load(bad), "section-name string table starts with the empty string");
            bad = data;
            bad[412] = std::byte{'x'};
            check(!load(bad), "unterminated section name rejected");
            bad = data;
            section(bad, wide, 1, 1, 1, 6, 0, 1020, 8, 16, big);
            check(!load(bad), "initialized section backing bounded");
            bad = data;
            section(bad, wide, 1, 1, 1, 6, 0, 256, 4, 3, big);
            check(!load(bad), "REL section alignment validated");
            auto compressed = data;
            section(compressed, wide, 1, 1, 1, 0x806, 0, 256, 4, 16, big);
            auto partial = load(compressed);
            check(partial && !partial.value().metadata_complete && !partial.value().image->segment_at({{1}, 0}),
                  "compressed executable section is diagnosed and never decoded as ordinary bytes");
        }
}
class Sparse final : public ByteStorage {
  public:
    std::vector<std::byte> prefix = executable(true);
    mutable std::size_t reads = 0, largest = 0;
    std::stop_source *cancel = nullptr;
    std::size_t cancel_at = 0;
    std::uint64_t size() const noexcept override { return UINT64_C(0x200000000); }
    Result<ByteView> read_at(FileOffset at, std::size_t n) const override {
        ++reads;
        largest = std::max(largest, n);
        if (cancel && reads == cancel_at)
            cancel->request_stop();
        if (at.value < prefix.size())
            return MemoryStorage(prefix).read_at(at, n);
        if (at.value > size() || n > size() - at.value)
            return Error{ErrorCode::out_of_bounds, "Sparse fixture extent"};
        return MemoryStorage(std::vector<std::byte>(n, std::byte{0x5a})).read_at({0}, n);
    }
};
void wide_and_sparse() {
    auto sparse = std::make_shared<Sparse>();
    program(sparse->prefix, true, 0, 1, UINT64_C(0x100000100), UINT64_C(0x140000000), 4, 16, 5, 256);
    put(sparse->prefix, 24, UINT64_C(0x140000000), 8);
    auto result = load_elf(sparse, {});
    check(result && result.value().metadata.preferred_base == UINT64_C(0x140000000) &&
              result.value().metadata.elf->programs[0].offset == UINT64_C(0x100000100),
          "ELF64 virtual/file coordinates do not truncate to PE RVA widths");
    check(sparse->largest <= 64 && sparse->reads <= 4,
          "sparse multi-gigabyte ELF input parsed without whole-file reads");
    if (result)
        check(result.value().image->read({{0}, UINT64_C(0x140000000)}, 1).value() == bytes({0x5a}) &&
                  result.value().image->to_file_offset({{0}, UINT64_C(0x140000000)}).value().value ==
                      UINT64_C(0x100000100),
              "large initialized coordinates retain exact canonical backing");
    auto data = object(true);
    section(data, true, 3, 14, 8, 3, 0, UINT64_MAX, UINT64_C(0x100000010), 8);
    result = load(data);
    check(result && result.value().metadata.elf->sections[3].size == UINT64_C(0x100000010) &&
              result.value().image->read({{3}, UINT64_C(0x100000008)}, 8).value() == std::vector<std::byte>(8),
          "large ELF64 NOBITS section stays sparse and full width");
    std::stop_source stop;
    sparse->reads = 0;
    sparse->cancel = &stop;
    sparse->cancel_at = 3;
    result = load_elf(sparse, stop.get_token());
    check(!result && result.error().code == ErrorCode::canceled,
          "cancellation during program-table read publishes no image");
}
void cancellation() {
    check(!load_elf({}, {}), "null ELF storage rejected");
    std::stop_source stop;
    stop.request_stop();
    const auto result = load_elf(std::make_shared<MemoryStorage>(executable(true)), stop.get_token());
    check(!result && result.error().code == ErrorCode::canceled, "canceled load publishes no partial image");
}
void metadata_budget() {
    // Fill the remaining metadata budget with an otherwise valid string table.
    // The compressed-section diagnostic must also fit the same bounded result.
    constexpr std::size_t limit = 64 * 1024 * 1024;
    const auto string_bytes = limit - 3 * sizeof(ElfSection);
    auto data = base(true, false, 1);
    data.resize(1024 + string_bytes);
    section(data, true, 0, 0, 0, 0, 0, 0, 0, 0);
    section(data, true, 1, 0, 1, 0x800, 0, 0, 0, 1);
    section(data, true, 2, 0, 3, 0, 0, 1024, string_bytes, 1);
    put(data, 62, 2, 2);
    const auto result = load_elf(std::make_shared<MemoryStorage>(std::move(data)), {});
    check(!result && result.error().code == ErrorCode::resource_limit,
          "retained diagnostics share the bounded metadata accounting budget");
    data = base(true, false, 1);
    section(data, true, 0, 0, 0, 0, 0, 0, 0, 0);
    section(data, true, 1, 0, 3, 0, 0, UINT64_MAX, 0, 1);
    put(data, 62, 1, 2);
    check(bool(load(data)), "empty string table with only empty names requires no backing read");
}
void notes() {
    for (bool wide : {false, true}) {
        auto data = executable(wide);
        // A standard GNU build-id note: namesz=4, descsz=4, type=NT_GNU_BUILD_ID.
        put(data, 320, 4, 4);
        put(data, 324, 4, 4);
        put(data, 328, 3, 4);
        data[332] = std::byte{'G'};
        data[333] = std::byte{'N'};
        data[334] = std::byte{'U'};
        data[335] = std::byte{0};
        data[336] = std::byte{0x12};
        data[337] = std::byte{0x34};
        data[338] = std::byte{0x56};
        data[339] = std::byte{0x78};
        program(data, wide, 1, 4, 320, 0, 20, 20, 4, 4);
        auto result = load(data);
        check(result && result.value().metadata.elf->notes.size() == 1,
              "PT_NOTE records are retained as ELF metadata");
        if (result && !result.value().metadata.elf->notes.empty()) {
            const auto &note = result.value().metadata.elf->notes.front();
            check(note.program == 1 && note.file_offset == 320 && note.name == "GNU" && note.type == 3 &&
                      note.description == bytes({0x12, 0x34, 0x56, 0x78}),
                  "GNU build-id note preserves exact identity bytes and provenance");
        }
        auto malformed = data;
        put(malformed, 324, 0x100, 4);
        check(!load(malformed), "PT_NOTE payload cannot escape its declared program extent");
        malformed = data;
        put(malformed, 320, 0, 4);
        check(!load(malformed), "PT_NOTE cannot contain an unparseable trailing fragment");
    }
}
} // namespace
int main() {
    return run([] {
        mappings();
        load_permissions();
        dwarf_debug_info_rows();
        dwarf_source_rows();
        eh_frame_function_roots();
        elf_live_cfi();
        mips32_machine_context();
        mips64_machine_context();
        overlap();
        objects();
        wide_and_sparse();
        cancellation();
        metadata_budget();
        notes();
    });
}
