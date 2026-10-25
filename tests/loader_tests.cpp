#include "hexlab/loaders/raw.hpp"
#include "hexlab/loaders/loader.hpp"
#include "hexlab/loaders/pe.hpp"
#include "hexlab/loaders/pdb_lines.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/pe_fixture.hpp"
#include <algorithm>
#include <stop_token>
#include "hexlab/types/pdb.hpp"
#include <fstream>
using namespace hexlab;
using namespace hexlab_test;

void raw_tests() {
    FixtureFile fixture(bytes({0x90,0xc3}));
    auto storage=FileStorage::open(fixture.path).value();
    RawOptions options{Architecture::x86_64,ExecutionMode::x86_64,{{0},0x4000},true,false,true,Address{{0},0x4000}};
    auto loaded=load_raw(storage,options,{}).value();
    check(loaded->read({{0},0x4000},2).value()==bytes({0x90,0xc3}), "raw bytes mapped at explicit base");
    check(loaded->layout().entries==std::vector<Address>{{{0},0x4000}}, "raw entry validated");
    options.entry=Address{{0},0x4002}; check(!load_raw(storage,options,{}), "raw end is not entry");
    options.entry=Address{{1},0x4000}; check(!load_raw(storage,options,{}), "raw other-space entry rejected");
    options.entry.reset(); options.base.offset=UINT64_MAX;
    check(!load_raw(storage,options,{}), "raw base overflow rejected");
    options.base.offset=0x4000; options.mode=ExecutionMode::unknown;
    check(load_raw(storage,options,{}).error().code==ErrorCode::unsupported, "raw mode must be explicit supported mode");
    options.mode=ExecutionMode::x86_64;
    FixtureFile empty({});
    check(load_raw(FileStorage::open(empty.path).value(),options,{}).value()->layout().entries.empty(), "empty raw has no entry");
    std::stop_source stop; stop.request_stop();
    check(load_raw(storage,options,stop.get_token()).error().code==ErrorCode::canceled, "raw cancellation");
}
void detection_tests() {
    FixtureFile raw(bytes({0x90,0xc3})), one(bytes({0x4d})), mz(bytes({0x4d,0x5a})), empty({});
    check(detect_format(*FileStorage::open(raw.path).value()).value()==DetectedFormat::unknown,"ordinary bytes unknown");
    check(detect_format(*FileStorage::open(one.path).value()).value()==DetectedFormat::unknown,"one-byte prefix not PE signature");
    check(detect_format(*FileStorage::open(mz.path).value()).value()==DetectedFormat::pe_candidate,"truncated MZ stays PE candidate");
    check(detect_format(*FileStorage::open(empty.path).value()).value()==DetectedFormat::unknown,"empty format unknown");
}
Result<LoadedImage> parse_pe(const std::vector<std::byte>& data) {
    FixtureFile file(data);
    return load_pe(FileStorage::open(file.path).value(),{});
}
void pe_header_tests() {
    auto data=pe_fixture();
    FixtureFile file(data);
    auto loaded=load_pe(FileStorage::open(file.path).value(),{}).value();
    check(loaded.image->layout().entries==std::vector<Address>{{{0},0x140001000ULL}},"PE entry RVA relocated to preferred VA");
    check(loaded.metadata.preferred_base==0x140000000ULL && loaded.metadata.machine==0x8664,"PE64 machine and base");
    check(loaded.image->to_file_offset({{0},0x140001000ULL}).value()==FileOffset{0x200},"PE RVA is not file offset");
    check(!loaded.image->to_address({0x1000}),"same numeric file offset is outside input");
    check(loaded.image->read({{0},0x140001200ULL},2).value()==bytes({0,0}),"PE virtual zero fill");
    check(loaded.metadata.sections.size()==1 && loaded.metadata.directories.size()==16,"section and directory metadata");
    const auto pe32=parse_pe(pe_fixture(false)).value();
    check(pe32.image->layout().mode==ExecutionMode::x86_32 && pe32.metadata.preferred_base==0x400000,"PE32 preserves x86 mode");
    data=pe_fixture(); put(data,0x188+8,1,4);
    check(parse_pe(data).value().image->read({{0},0x140001001ULL},1).value()==bytes({0xc3}),"raw alignment padding remains mapped");
    for (std::size_t length : {0u,2u,0x83u,0x97u,0x187u,0x1afu}) {
        data=pe_fixture(); data.resize(length); check(!parse_pe(data),"truncated PE required structures rejected");
    }
    data=pe_fixture(); put(data,0x3c,0xffffffff,4); check(!parse_pe(data),"oversized e_lfanew rejected");
    data=pe_fixture(); data[0x80]=std::byte{0}; check(!parse_pe(data),"invalid PE signature rejected");
    data=pe_fixture(); put(data,0x98,0x10b,2); check(!parse_pe(data),"machine optional magic mismatch");
    data=pe_fixture(); put(data,0xb0,UINT64_MAX-0x100,8); check(!parse_pe(data),"PE image base overflow rejected");
    data=pe_fixture(); put(data,0x188+20,0xfffffe00,4); check(!parse_pe(data),"PE raw extent outside input");
    data=pe_fixture(); put(data,0xa8,0x800,4); check(!parse_pe(data),"entry into unmapped gap rejected");
    data=pe_fixture(); put(data,0x86,2,2); put_text(data,0x1b0,".bad");
    put(data,0x1b8,0x200,4);put(data,0x1bc,0x1000,4); check(!parse_pe(data),"overlapping PE virtual sections rejected");
    data=pe_fixture(); put(data,0x104,100,4); check(!parse_pe(data),"directory count exceeds optional header");
    std::stop_source stop;stop.request_stop();
    check(load_pe(FileStorage::open(file.path).value(),stop.get_token()).error().code==ErrorCode::canceled,"PE loading cancellation");
}
void pe_metadata_tests() {
    for (bool pe64:{true,false}) {
        auto loaded=parse_pe(pe_metadata_fixture(pe64)).value();
        const auto base=pe64?0x140000000ULL:0x400000ULL;
        const auto width=pe64?8u:4u;
        check(loaded.metadata.imports.size()==2,"PE named and ordinal import count");
        if (loaded.metadata.imports.size()==2) {
            const auto& a=loaded.metadata.imports[0];const auto& b=loaded.metadata.imports[1];
            check(a.library=="fixture.dll" && a.name=="FixtureFn" && !a.ordinal,"named import metadata");
            check(b.ordinal==7 && !b.name && b.iat.offset==base+(pe64?0x2068:0x2064),"ordinal import and thunk width");
            check(a.thunk.offset==base+0x2040 && a.iat.offset==base+0x2060,"import table addresses");
        }
        check(loaded.metadata.exports.size()==3,"PE export count");
        if (loaded.metadata.exports.size()==3) {
            check(loaded.metadata.exports[0].name=="entry" && loaded.metadata.exports[0].address==Address{{0},base+0x1000},"named export VA");
            check(loaded.metadata.exports[1].forwarder=="other.Target" && !loaded.metadata.exports[1].address,"export forwarder not code");
            check(loaded.metadata.exports[2].ordinal==3 && !loaded.metadata.exports[2].name,"ordinal-only export");
        }
        check(loaded.metadata.relocations.size()==1,"relocation padding not treated as a fixup");
        if (!loaded.metadata.relocations.empty()) {
            const auto& fixup=loaded.metadata.relocations[0];
            check(fixup.type==(pe64?10:3) && fixup.address.offset==base+0x1010 && fixup.offset==0x10,"relocation type and page offset");
        }
        check(loaded.metadata_complete,"supported optional metadata complete");
        check(loaded.metadata.pe.has_value(),"PE-specific provenance is available");
        if (loaded.metadata.pe) {
            const auto& pe=*loaded.metadata.pe;
            check(pe.imports.size()==loaded.metadata.imports.size() && pe.exports.size()==loaded.metadata.exports.size() &&
                  pe.relocations.size()==loaded.metadata.relocations.size(),"PE provenance aligns with parsed records");
            if (!pe.imports.empty()) {
                check(pe.imports[0].descriptor.spans==std::vector<PeSourceSpan>{{{0x400},20}},"import descriptor source bytes");
                check(pe.imports[0].lookup_thunk==std::vector<PeSourceSpan>{{{0x440},width}},"lookup thunk source bytes");
                check(pe.imports[0].iat_thunk==std::vector<PeSourceSpan>{{{0x460},width}},"IAT source bytes");
                check(pe.imports[0].symbol_name==std::optional<std::vector<PeSourceSpan>>{{{{0x492},10}}},"import symbol string source bytes");
            }
            if (!pe.exports.empty()) {
                check(pe.exports[0].address_table.spans==std::vector<PeSourceSpan>{{{0x640},4}},"export address row source bytes");
                check(pe.exports[0].name==std::optional<std::vector<PeSourceSpan>>{{{{0x670},6}}},"export name source bytes");
            }
            if (!pe.relocations.empty()) {
                check(pe.relocations[0].block_header.spans==std::vector<PeSourceSpan>{{{0x800},8}},"relocation block header source bytes");
                check(pe.relocations[0].entry.spans==std::vector<PeSourceSpan>{{{0x808},2}},"relocation entry source bytes");
            }
        }
    }
    auto partial=[](std::vector<std::byte> data,const char* message) {
        auto result=parse_pe(data);
        check(result.has_value() && !result.value().metadata_complete && !result.value().diagnostics.empty(),message);
    };
    auto data=pe_metadata_fixture();put(data,0x114,20,4);partial(data,"missing import descriptor terminator");
    data=pe_metadata_fixture();put(data,0x40c,0x1800,4);partial(data,"import name in gap");
    data=pe_metadata_fixture();put(data,0x40c,0x25fc,4);put_text(data,0x9fc,"xxxx");partial(data,"unterminated library name");
    data=pe_metadata_fixture();put(data,0x440,0x100000000ULL,8);partial(data,"64-bit name thunk must fit RVA");
    data=pe_metadata_fixture();put(data,0x440,0x8001000000000007ULL,8);partial(data,"ordinal reserved bits rejected");
    data=pe_metadata_fixture();put(data,0x400,0x2000,4);partial(data,"self-referencing thunk structure bounded");
    data=pe_metadata_fixture();put(data,0x614,0xffffffff,4);partial(data,"oversized export count");
    data=pe_metadata_fixture();put(data,0x668,8,2);partial(data,"export ordinal index out of range");
    data=pe_metadata_fixture();put(data,0x644,0x22fc,4);put_text(data,0x6fc,"XXXX");partial(data,"forwarder terminator cannot exceed directory");
    data=pe_metadata_fixture();put(data,0x804,6,4);partial(data,"undersized relocation block");
    data=pe_metadata_fixture();put(data,0x804,11,4);partial(data,"odd relocation payload");
    data=pe_metadata_fixture();put(data,0x130,0x2202,4);partial(data,"relocation block alignment is checked");
    data=pe_metadata_fixture(false);put(data,0x808,0xa010,2);partial(data,"PE32 rejects DIR64 relocation type");
    data=pe_metadata_fixture(false);put(data,0x804,10,4);put(data,0x808,0x4010,2);partial(data,"PE32 HIGHADJ requires a paired addend word");
    data=pe_metadata_fixture();put(data,0x808,0x4010,2);put(data,0x80a,0x1234,2);partial(data,"x64 rejects x86 HIGHADJ relocation");
    data=pe_metadata_fixture();put(data,0x808,0xafff,2);partial(data,"relocation target in image gap rejected");
    data=pe_metadata_fixture();data.resize(0xa10);put(data,0x128,0xa00,4);put(data,0x12c,16,4);
    auto certificate=parse_pe(data).value();
    check(certificate.metadata.directories[4].file_offset && certificate.metadata.directories[4].location==0xa00,"certificate uses file position");
    check(!certificate.image->to_address({0xa00}),"certificate overlay not virtually mapped");
    data=pe_metadata_fixture();data.resize(0x1600);put(data,0x86,3,2);put(data,0xd0,0x4000,4);
    put(data,0x1b8,0x1000,4);put(data,0x1c0,0x1000,4);
    put_text(data,0x1d8,".tail");put(data,0x1e0,0x200,4);put(data,0x1e4,0x3000,4);
    put(data,0x1e8,0x200,4);put(data,0x1ec,0x1400,4);put(data,0x1fc,0x40000040,4);
    put(data,0x400,0x2ff8,4);put(data,0x13f8,0x2090,8);
    const auto crossing=parse_pe(data).value();
    check(crossing.metadata.imports.size()==1,"thunk terminator may cross adjacent initialized sections");
}
void pe_resource_tests() {
    auto data=pe_metadata_fixture();
    const auto dirs=0x108u;
    put(data,dirs+16,0x2300,4);put(data,dirs+20,0x100,4);
    // Root: named type "RCDATA" -> ID 10 -> language 1033 -> data entry.
    put(data,0x700+12,1,2);put(data,0x700+14,0,2);
    put(data,0x710,0x800000a0,4);put(data,0x714,0x80000040,4);
    put(data,0x740+14,1,2);put(data,0x750,10,4);put(data,0x754,0x80000060,4);
    put(data,0x760+14,1,2);put(data,0x770,1033,4);put(data,0x774,0x90,4);
    put(data,0x790,0x2100,4);put(data,0x794,4,4);put(data,0x798,65001,4);
    put(data,0x7a0,6,2);for(std::size_t i=0;i<6;++i) put(data,0x7a2+i*2,"RCDATA"[i],2);
    auto parsed=parse_pe(data);
    check(parsed && parsed.value().metadata_complete && parsed.value().metadata.pe->resources.size()==1,
          "PE resource directory walks named type/name and language levels");
    if(parsed && !parsed.value().metadata.pe->resources.empty()) {
        const auto &resource=parsed.value().metadata.pe->resources[0];
        check(resource.type.name=="RCDATA" && resource.name.id==10 && resource.language.id==1033,
              "PE resource identifiers preserve names and numeric IDs");
        check(resource.data_rva==0x2100 && resource.size==4 && resource.code_page==65001,
              "PE resource payload metadata parsed");
    }
    auto partial=[](std::vector<std::byte> image,const char *why) {
        auto result=parse_pe(image);
        check(result && !result.value().metadata_complete && !result.value().diagnostics.empty(),why);
    };
    put(data,0x714,0x80000000,4); partial(data,"PE resource directory cycles are rejected");
    data=pe_metadata_fixture();put(data,dirs+16,0x2300,4);put(data,dirs+20,0x100,4);
    put(data,0x700+14,1,2);put(data,0x710,0x800000ff,4);
    partial(data,"PE resource child offsets cannot escape declared directory");
    data=pe_metadata_fixture();put(data,dirs+16,0x2300,4);put(data,dirs+20,0x100,4);
    put(data,0x700+14,1,2);put(data,0x710,10,4);put(data,0x714,0x80000040,4);
    put(data,0x740+14,1,2);put(data,0x750,11,4);put(data,0x754,0x80000060,4);
    put(data,0x760+14,1,2);put(data,0x770,1033,4);put(data,0x774,0x90,4);
    put(data,0x790,0x2fff,4);put(data,0x794,8,4);
    partial(data,"PE resource payload range cannot exceed mapped image");
}
void pe_load_configuration_tests() {
    for (const bool pe64 : {false, true}) {
        auto data = pe_metadata_fixture(pe64);
        const auto dirs = pe64 ? 0x108u : 0xf8u;
        const auto width = pe64 ? 8u : 4u;
        const auto config_size = pe64 ? 148u : 92u;
        const auto cookie_offset = pe64 ? 88u : 60u;
        const auto table_offset = pe64 ? 128u : 80u;
        const auto count_offset = pe64 ? 136u : 84u;
        const auto flags_offset = pe64 ? 144u : 88u;
        put(data, dirs + 10 * 8, 0x2300, 4); put(data, dirs + 10 * 8 + 4, config_size, 4);
        put(data, 0x700, config_size, 4); put(data, 0x704, 0x12345678, 4);
        put(data, 0x708, 2, 2); put(data, 0x70a, 1, 2);
        const auto base = pe64 ? 0x140000000ULL : 0x400000ULL;
        put(data, 0x700 + cookie_offset, base + 0x20a0, width);
        put(data, 0x700 + table_offset, base + 0x2340, width);
        put(data, 0x700 + count_offset, 1, width);
        put(data, 0x700 + flags_offset, 0x10000000u | 0x100u, 4); // one metadata byte per function
        put(data, 0x740, 0x1000, 4); data[0x744] = std::byte{0x5a};
        FixtureFile fixture(data);
        const auto loaded = load_pe(FileStorage::open(fixture.path).value(), {}).value();
        check(loaded.metadata_complete && loaded.metadata.pe->load_configuration.has_value(),
              "PE32/PE32+ load configuration is parsed");
        if (!loaded.metadata.pe->load_configuration) continue;
        const auto& config = *loaded.metadata.pe->load_configuration;
        check(config.declared_size == config_size && config.timestamp == 0x12345678 &&
                  config.security_cookie_rva == std::optional<std::uint64_t>{0x20a0} &&
                  config.guard_function_table_rva == std::optional<std::uint64_t>{0x2340} &&
                  config.guard_functions.size() == 1 && config.guard_functions[0].rva == 0x1000 &&
                  config.guard_functions[0].metadata == std::vector<std::byte>{std::byte{0x5a}},
              "cookie and versioned Guard CF table fields are normalized and retained");
        check(config.directory_source->spans[0].offset.value == 0x700 &&
                  config.security_cookie_source->spans[0].offset.value == 0x700 + cookie_offset &&
                  config.guard_functions[0].source.spans[0].offset.value == 0x740,
              "load configuration and Guard CF records retain file provenance");
    }
}

void pe_tls_tests() {
    for (const bool pe64 : {true, false}) {
        auto data = pe_metadata_fixture(pe64);
        const auto base = pe64 ? UINT64_C(0x140000000) : UINT64_C(0x400000);
        const auto dir = (pe64 ? 0x108u : 0xf8u) + 9 * 8;
        const auto width = pe64 ? 8u : 4u;
        put(data, dir, 0x2300, 4); put(data, dir + 4, pe64 ? 40 : 24, 4);
        put(data, 0x700, base + 0x2080, width); put(data, 0x700 + width, base + 0x2088, width);
        put(data, 0x700 + 2 * width, base + 0x20a0, width);
        put(data, 0x700 + 3 * width, base + 0x2380, width);
        put(data, 0x700 + 4 * width, 12, 4); put(data, 0x700 + 4 * width + 4, 0x100000, 4);
        put(data, 0x780, base + 0x1000, width); put(data, 0x780 + width, base + 0x1010, width);
        put(data, 0x780 + 2 * width, 0, width);
        auto result = parse_pe(data);
        check(result && result.value().metadata_complete && result.value().metadata.pe->tls.has_value(),
              "PE32/PE32+ TLS directory is parsed");
        if (result && result.value().metadata.pe->tls) {
            const auto& tls = *result.value().metadata.pe->tls;
            check(tls.template_rva == 0x2080 && tls.template_size == 8 && tls.index_rva == 0x20a0 &&
                      tls.callbacks_rva == 0x2380 && tls.zero_fill == 12 && tls.characteristics == 0x100000,
                  "TLS VAs are normalized to stable image RVAs and scalar fields retained");
            check(tls.callbacks.size() == 2 && tls.callbacks[0].rva == 0x1000 && tls.callbacks[1].rva == 0x1010,
                  "TLS callbacks are retained in order until the null terminator");
            check(tls.directory.spans[0].offset.value == 0x700 &&
                      tls.callbacks[0].source.spans[0].offset.value == 0x780 &&
                      tls.callback_terminator->spans[0].offset.value == 0x780 + 2 * width,
                  "TLS records retain source provenance including callback-array terminator");
        }
    }
    const auto partial = [](std::vector<std::byte> data, const char* name) {
        const auto result = parse_pe(data);
        check(result && !result.value().metadata_complete, name);
    };
    auto data = pe_metadata_fixture();
    constexpr std::size_t tls_dir = 0x108 + 9 * 8;
    put(data, tls_dir, 0x2300, 4); put(data, tls_dir + 4, 39, 4);
    partial(data, "truncated TLS directory is reported as partial metadata");
    data = pe_metadata_fixture();
    put(data, tls_dir, 0x2300, 4); put(data, tls_dir + 4, 40, 4); put(data, 0x718, 0x140003000, 8);
    partial(data, "TLS callback array outside initialized image is rejected");
    data = pe_metadata_fixture();
    put(data, tls_dir, 0x2300, 4); put(data, tls_dir + 4, 40, 4);
    put(data, 0x718, 0x140002380, 8); put(data, 0x780, 0x140003000, 8);
    partial(data, "TLS callback outside executable image bytes is rejected");
}
void pe_rebase_tests() {
    auto data = pe_metadata_fixture();
    constexpr std::uint64_t preferred = 0x140000000ULL, load_base = preferred + 0x100000;
    put(data, 0x210, preferred + 0x1234, 8);
    FixtureFile file(data);
    const auto load_result = load_pe_at_base(FileStorage::open(file.path).value(), load_base, {});
    if (!load_result) throw std::runtime_error("DIR64 rebase: " + load_result.error().message);
    const auto loaded = load_result.value();
    check(loaded.image->layout().segments.front().begin.offset == load_base &&
              loaded.image->layout().entries == std::vector<Address>{{{0}, load_base + 0x1000}} &&
              loaded.metadata.preferred_base == preferred && loaded.load_base == load_base,
          "PE maps at the requested base while retaining preferred-base metadata");
    check(loaded.image->read({{0}, load_base + 0x1010}, 8).value() == bytes({0x34, 0x12, 0x10, 0x40, 0x01, 0, 0, 0}) &&
              loaded.metadata.relocations[0].address == Address{{0}, load_base + 0x1010} &&
              loaded.metadata.imports[0].iat == Address{{0}, load_base + 0x2060},
          "DIR64 relocation is applied to mapped bytes and metadata addresses follow the new base");
    const auto source_storage = FileStorage::open(file.path).value();
    const auto source_view = source_storage->read_at({0x210}, 8).value();
    const auto source_bytes = source_view.bytes;
    const auto original_bytes = bytes({0x34, 0x12, 0x00, 0x40, 0x01, 0, 0, 0});
    check(std::equal(source_bytes.begin(), source_bytes.end(), original_bytes.begin(), original_bytes.end()),
          "rebasing uses an overlay and leaves source file bytes unchanged");

    data = pe_metadata_fixture();
    put(data, 0x108 + 9 * 8, 0x2300, 4); put(data, 0x108 + 9 * 8 + 4, 40, 4);
    put(data, 0x700, preferred + 0x2080, 8); put(data, 0x708, preferred + 0x2088, 8);
    put(data, 0x710, preferred + 0x20a0, 8); put(data, 0x718, preferred + 0x2380, 8);
    put(data, 0x780, preferred + 0x1000, 8); put(data, 0x788, 0, 8);
    FixtureFile tls_file(data);
    const auto rebased_tls = load_pe_at_base(FileStorage::open(tls_file.path).value(), load_base, {});
    check(rebased_tls && rebased_tls.value().metadata.pe->tls->callbacks[0].rva == 0x1000 &&
              rebased_tls.value().metadata.pe->tls->template_rva == 0x2080,
          "TLS metadata uses stable RVAs after image rebasing");

    data = pe_metadata_fixture(false);
    constexpr std::uint32_t preferred32 = 0x400000, load32 = preferred32 + 0x12345;
    put(data, 0x808, 0x3010, 2); // IMAGE_REL_BASED_HIGHLOW
    put(data, 0x210, preferred32 + 0x3456, 4);
    FixtureFile file32(data);
    const auto load32_result = load_pe_at_base(FileStorage::open(file32.path).value(), load32, {});
    if (!load32_result) throw std::runtime_error("HIGHLOW rebase: " + load32_result.error().message);
    const auto loaded32 = load32_result.value();
    check(loaded32.image->read({{0}, load32 + 0x1010}, 4).value() == bytes({0x9b, 0x57, 0x41, 0x00}),
          "HIGHLOW applies the complete modulo-32 base delta");
    data = pe_metadata_fixture(false); put(data, 0x808, 0x3010, 2); put(data, 0x210, preferred32 + 0x3456, 4);
    FixtureFile down_file(data);
    constexpr std::uint32_t lower_base = preferred32 - 0x1000;
    const auto lower = load_pe_at_base(FileStorage::open(down_file.path).value(), lower_base, {});
    if (!lower) throw std::runtime_error("negative HIGHLOW delta: " + lower.error().message);
    check(lower.value().image->read({{0}, lower_base + 0x1010}, 4).value() == bytes({0x56, 0x24, 0x40, 0x00}),
          "HIGHLOW applies a negative base delta without signed-overflow hazards");

    data = pe_metadata_fixture(false);
    put(data, 0x808, 0x4010, 2); // IMAGE_REL_BASED_HIGHADJ
    put(data, 0x80a, 0xf234, 2); // signed low-half addend, not another relocation
    put(data, 0x210, 0x1234, 2);
    FixtureFile highadj_file(data);
    constexpr std::uint32_t highadj_base = preferred32 + 0x12345;
    const auto highadj_result = load_pe_at_base(FileStorage::open(highadj_file.path).value(), highadj_base, {});
    if (!highadj_result) throw std::runtime_error("HIGHADJ rebase: " + highadj_result.error().message);
    const auto highadj = highadj_result.value();
    check(highadj.image->read({{0}, highadj_base + 0x1010}, 2).value() == bytes({0x35, 0x12}) &&
              highadj.metadata.relocations.size() == 1 && highadj.metadata.relocations[0].type == 4 &&
              highadj.metadata.pe->relocations[0].highadj_addend == static_cast<std::int16_t>(0xf234) &&
              highadj.metadata.pe->relocations[0].addend_entry->spans == std::vector<PeSourceSpan>{{{0x80a}, 2}},
          "HIGHADJ combines the signed paired addend and rounded delta, preserving pair provenance");

    data = pe_metadata_fixture(false);
    put(data, 0x808, 0x1010, 2); // IMAGE_REL_BASED_HIGH
    put(data, 0x80a, 0x2012, 2); // IMAGE_REL_BASED_LOW
    put(data, 0x210, 0x1234, 2); put(data, 0x212, 0x5678, 2);
    FixtureFile split_file(data);
    constexpr std::uint32_t split_base = preferred32 + 0x12345;
    const auto split_result = load_pe_at_base(FileStorage::open(split_file.path).value(), split_base, {});
    if (!split_result) throw std::runtime_error("HIGH/LOW rebase: " + split_result.error().message);
    const auto split = split_result.value();
    check(split.image->read({{0}, split_base + 0x1010}, 4).value() == bytes({0x35, 0x12, 0xbd, 0x79}) &&
              split.metadata.relocations.size() == 2,
          "HIGH and LOW apply their respective halves of an arbitrary 32-bit base delta");

    data = pe_metadata_fixture(false);
    put(data, 0x84, 0x1c0, 2); put(data, 0x808, 0x5010, 2);
    put(data, 0x210, 0xe3050678, 4); put(data, 0x214, 0xe3410234, 4);
    FixtureFile arm_file(data);
    constexpr std::uint32_t arm_base = preferred32 + 0x1000;
    const auto arm_result = load_pe_at_base(FileStorage::open(arm_file.path).value(), arm_base, {});
    if (!arm_result) throw std::runtime_error("ARM_MOV32 rebase: " + arm_result.error().message);
    const auto arm = arm_result.value();
    check(arm.image->read({{0}, arm_base + 0x1010}, 8).value() ==
              bytes({0x78, 0x06, 0x06, 0xe3, 0x34, 0x02, 0x41, 0xe3}),
          "ARM_MOV32 adjusts the immediate in a validated A32 MOVW/MOVT pair");

    data = pe_metadata_fixture(false);
    put(data, 0x84, 0x1c4, 2); put(data, 0x808, 0x7010, 2);
    put(data, 0x210, 0x6078f245, 4); put(data, 0x214, 0x2034f2c1, 4);
    FixtureFile thumb_file(data);
    const auto thumb_result = load_pe_at_base(FileStorage::open(thumb_file.path).value(), arm_base, {});
    if (!thumb_result) throw std::runtime_error("THUMB_MOV32 rebase: " + thumb_result.error().message);
    const auto thumb = thumb_result.value();
    check(thumb.image->read({{0}, arm_base + 0x1010}, 8).value() ==
              bytes({0x46, 0xf2, 0x78, 0x60, 0xc1, 0xf2, 0x34, 0x20}),
          "THUMB_MOV32 adjusts packed immediates in a validated Thumb MOVW/MOVT pair");

    data = pe_metadata_fixture(); put(data, 0x808, 0x3010, 2); put(data, 0x210, 0xfffffff0, 4);
    FixtureFile wide32_file(data);
    constexpr std::uint64_t wide32_base = preferred + 0x40;
    const auto wide32_result = load_pe_at_base(FileStorage::open(wide32_file.path).value(), wide32_base, {});
    if (!wide32_result) throw std::runtime_error("PE32+ HIGHLOW rebase: " + wide32_result.error().message);
    const auto wide32 = wide32_result.value();
    check(wide32.image->read({{0}, wide32_base + 0x1010}, 4).value() == bytes({0x30, 0x00, 0x00, 0x00}),
          "PE32+ HIGHLOW retains its defined modulo-32 arithmetic");

    data = pe_metadata_fixture();
    put(data, 0x84, 0xaa64, 2); put(data, 0x808, 0xa010, 2);
    put(data, 0x210, preferred + 0x4567, 8);
    FixtureFile arm64_file(data);
    const auto arm64 = load_pe_at_base(FileStorage::open(arm64_file.path).value(), load_base, {});
    if (!arm64) throw std::runtime_error("ARM64 DIR64 rebase: " + arm64.error().message);
    check(arm64.value().image->layout().mode == ExecutionMode::a64 &&
              arm64.value().image->read({{0}, load_base + 0x1010}, 8).value() ==
                  bytes({0x67, 0x45, 0x10, 0x40, 0x01, 0, 0, 0}),
          "ARM64 DIR64 applies while preserving A64 image context");

    auto malformed = pe_metadata_fixture(); put(malformed, 0x800, 0x2000, 4); put(malformed, 0x808, 0xaffc, 2);
    FixtureFile malformed_file(malformed);
    const auto partial = load_pe(FileStorage::open(malformed_file.path).value(), std::stop_token{});
    check(partial && !partial.value().metadata_complete && partial.value().image,
          "malformed relocation blocks preserve the mapped image as partial metadata");
    const auto rejected_rebase = load_pe_at_base(FileStorage::open(malformed_file.path).value(), load_base, {});
    check(!rejected_rebase && rejected_rebase.error().code == ErrorCode::unsupported,
          "a wide relocation crossing its 4-KiB block page cannot be applied during requested rebasing");
    data = pe_metadata_fixture(false); put(data, 0x84, 0x1c0, 2); put(data, 0x808, 0x5010, 2);
    put(data, 0x210, 0xe1a00000, 4); put(data, 0x214, 0xe3410234, 4);
    FixtureFile invalid_arm_pair(data);
    const auto invalid_pair_rebase = load_pe_at_base(FileStorage::open(invalid_arm_pair.path).value(), arm_base, {});
    check(!invalid_pair_rebase && invalid_pair_rebase.error().code == ErrorCode::unsupported,
          "ARM_MOV32 refuses to patch a non-MOVW/MOVT instruction pair");
    auto no_relocations = pe_fixture();
    check(!load_pe_at_base(FileStorage::open(FixtureFile(no_relocations).path).value(), load_base, {}),
          "rebasing without a relocation directory is rejected");
}
void pe_delay_import_tests() {
    for (bool pe64 : {true, false}) {
        const auto loaded = parse_pe(pe_delay_import_fixture(pe64)).value();
        check(loaded.metadata.imports.size() == 4, "delay imports append to ordinary imports");
        if (loaded.metadata.imports.size() == 4) {
            const auto &name = loaded.metadata.imports[2];
            const auto &ordinal = loaded.metadata.imports[3];
            const auto base = pe64 ? 0x140000000ULL : 0x400000ULL;
            check(name.delay_load && name.library == "delay.dll" && name.name == "DelayedFn" && !name.ordinal,
                  "delay import by name metadata");
            check(ordinal.delay_load && ordinal.library == "delay.dll" && ordinal.ordinal == 9 && !ordinal.name,
                  "delay import by ordinal metadata");
            check(name.thunk.offset == base + 0x2440 && name.iat.offset == base + 0x2460,
                  "delay import lookup and IAT addresses");
        }
        check(loaded.metadata.pe && loaded.metadata.pe->imports.size() == 4,
              "delay import provenance aligns with import records");
        if (loaded.metadata.pe && loaded.metadata.pe->imports.size() == 4) {
            const auto &source = loaded.metadata.pe->imports[2];
            check(source.delay_load && source.descriptor.spans == std::vector<PeSourceSpan>{{{0x700}, 32}},
                  "delay import descriptor source span");
            check(source.lookup_thunk == std::vector<PeSourceSpan>{{{0x840}, pe64 ? 8u : 4u}},
                  "delay import lookup thunk provenance");
        }
    }
    const auto old_pe = parse_pe(pe_delay_import_fixture(false, false)).value();
    check(old_pe.metadata.imports.size() == 4 && old_pe.metadata.imports[2].name == "DelayedFn",
          "legacy VA-form PE32 delay import descriptors");

    auto partial = [](std::vector<std::byte> data, const char *message) {
        const auto result = parse_pe(data);
        check(result && !result.value().metadata_complete && !result.value().diagnostics.empty(), message);
    };
    auto data = pe_delay_import_fixture();
    put(data, 0x72c, 0, 4); // only one descriptor-sized directory; no null descriptor follows
    put(data, 0x174, 32, 4);
    partial(data, "delay import descriptor terminator must be directory-bounded");
    data = pe_delay_import_fixture(); put(data, 0x700, 3, 4);
    partial(data, "reserved delay import attributes rejected");
    data = pe_delay_import_fixture(); put(data, 0x704, 0x1800, 4);
    partial(data, "delay import library in unmapped gap rejected");
    data = pe_delay_import_fixture(); put(data, 0x840, 0x100000000ULL, 8);
    partial(data, "delay import name thunk must be an RVA");
}
void pe_codeview_tests() {
    for(bool pe64:{true,false}) {
        const auto loaded=parse_pe(pe_codeview_fixture(pe64)).value();
        check(loaded.metadata_complete,"CodeView debug directory is understood");
        check(loaded.metadata.pe && loaded.metadata.pe->codeview.size()==1,"PE publishes its PDB identity");
        if(loaded.metadata.pe && loaded.metadata.pe->codeview.size()==1) {
            const auto &record=loaded.metadata.pe->codeview.front();
            check(record.age==7 && record.path=="C:\\symbols\\sample.pdb","CodeView age and path");
            bool guid_ok=true;
            for(std::size_t i=0;i<16;++i)guid_ok=guid_ok && record.guid[i]==static_cast<std::byte>(i+1);
            check(guid_ok,"CodeView GUID bytes");
            check(record.directory_entry.spans==std::vector<PeSourceSpan>{{{0x700},28}} &&
                  record.record==std::vector<PeSourceSpan>{{{0x720},46}},
                  "CodeView source provenance");
        }
    }
    auto malformed=pe_codeview_fixture();
    put(malformed,0x718,0xffffffff,4);
    const auto result=parse_pe(malformed);
    check(result && !result.value().metadata_complete,"out-of-file CodeView payload is partial metadata");
    auto mixed=pe_codeview_fixture();
    const auto dirs=0x108u;
    put(mixed,0x718,0x780,4); // move RSDS payload beyond the expanded table
    for(std::size_t i=0;i<64;++i) mixed[0x780+i]=mixed[0x720+i];
    put(mixed,dirs+6*8+4,56,4);
    put(mixed,0x700+28+4,0x10203040,4);
    put(mixed,0x700+28+8,0x0102,2); put(mixed,0x700+28+10,0x0304,2);
    put(mixed,0x700+28+12,12,4); // IMAGE_DEBUG_TYPE_CLSID
    put(mixed,0x700+28+16,8,4); put(mixed,0x700+28+20,0x2350,4); put(mixed,0x700+28+24,0x750,4);
    const auto all=parse_pe(mixed).value();
    check(all.metadata.pe && all.metadata.pe->debug_directories.size()==2,
          "PE retains recognized and opaque debug directory entries");
    if(all.metadata.pe && all.metadata.pe->debug_directories.size()==2) {
        const auto &entry=all.metadata.pe->debug_directories[1];
        check(entry.type==12 && entry.timestamp==0x10203040 && entry.major_version==0x0102 &&
              entry.minor_version==0x0304 && entry.data_size==8 && entry.data_rva==0x2350 &&
              entry.raw_offset==0x750 && entry.entry.spans==std::vector<PeSourceSpan>{{{0x71c},28}} &&
              entry.raw_data==std::vector<PeSourceSpan>{{{0x750},8}},
              "opaque PE debug entry fields and source provenance");
    }
}

void pe_pdb_source_line_tests() {
    using namespace hexlab::types;
    auto loaded = parse_pe(pe_codeview_fixture()).value();
    PdbDatabase pdb;
    pdb.info.age = 7;
    for (std::size_t i=0;i<pdb.info.guid.size();++i) pdb.info.guid[i]=static_cast<std::byte>(i+1);
    PdbSourceLineTable table;
    PdbSourceLine valid;
    valid.source_path="src/main.cpp"; valid.source_file_id=12; valid.checksum_kind=1;
    valid.checksum={std::byte{0xaa},std::byte{0xbb}}; valid.section=1;
    valid.reloc_offset=0x10; valid.section_offset=0x10; valid.contribution_size=0x20; valid.block_size=32;
    valid.line=10; valid.end_line=12; valid.start_column=2; valid.end_column=8;
    valid.has_columns=true; valid.is_statement=true; valid.module_name="main";
    valid.object_name="main.obj"; valid.module_index=3; valid.subsection_offset=0x180;
    table.lines.push_back(valid);
    auto out_of_bounds=valid; out_of_bounds.reloc_offset=0x2f0; out_of_bounds.section_offset=0x2f0; out_of_bounds.contribution_size=0x20;
    table.lines.push_back(out_of_bounds);
    auto bad_section=valid; bad_section.section=3;
    table.lines.push_back(bad_section);
    auto near_end=valid; near_end.reloc_offset=0x2e0; near_end.section_offset=0x2ff;
    table.lines.push_back(near_end);
    const auto imported=attach_pdb_source_lines(loaded,pdb,table);
    check(imported && imported.value()==4,"matching PDB C13 rows import to PE metadata");
    if(imported && loaded.metadata.pe && loaded.metadata.pe->source_lines.size()==4) {
        const auto &rows=loaded.metadata.pe->source_lines;
        check(rows[0].address==Address{{0},0x140001010ULL} && rows[0].source_path=="src/main.cpp" &&
              rows[0].checksum==valid.checksum && rows[0].line==10 && rows[0].section==1 &&
              rows[0].module_name=="main" && rows[0].subsection_offset==0x180,
              "matched row maps one-based section offset and preserves C13 provenance");
        check(!rows[1].address && !rows[2].address,
              "out-of-contribution and nonexistent section rows stay unmapped");
        check(rows[3].address==Address{{0},0x1400012ffULL} && rows[3].reloc_offset==0x2e0,
              "line row near contribution end maps from its row offset while contribution bounds start at RelocOffset");
    }

    auto mismatched=loaded;
    mismatched.metadata.pe->source_lines.clear();
    pdb.info.age++;
    const auto mismatch=attach_pdb_source_lines(mismatched,pdb,table);
    check(mismatch && mismatch.value()==0 && mismatched.metadata.pe->source_lines.empty(),
          "PDB age mismatch imports no rows");
    pdb.info.age--;
    mismatched.metadata.pe->codeview.push_back(mismatched.metadata.pe->codeview.front());
    const auto ambiguous=attach_pdb_source_lines(mismatched,pdb,table);
    check(ambiguous && ambiguous.value()==0 && mismatched.metadata.pe->source_lines.empty(),
          "duplicate matching CodeView identities are treated as ambiguous");

    auto overflow=loaded;
    overflow.load_base=UINT64_MAX;
    const auto overflow_result=attach_pdb_source_lines(overflow,pdb,table);
    check(overflow_result && overflow.metadata.pe->source_lines.size()==4 &&
          !overflow.metadata.pe->source_lines.front().address,
          "runtime base overflow preserves source row without a guessed address");

    auto raw_extent=loaded;
    raw_extent.metadata.sections[0].virtual_size=0;
    auto raw_end=valid; raw_end.reloc_offset=0x1ff; raw_end.section_offset=0x1ff; raw_end.contribution_size=1;
    PdbSourceLineTable raw_table; raw_table.lines.push_back(raw_end);
    const auto raw_mapped=attach_pdb_source_lines(raw_extent,pdb,raw_table);
    check(raw_mapped && raw_extent.metadata.pe->source_lines.front().address==Address{{0},0x1400011ffULL},
          "zero virtual size uses the section raw extent, matching the PE mapping contract");

    PdbLocalTable local_table;
    PdbLocalSymbol parameter;
    parameter.name = "arg"; parameter.procedure_name = "entry"; parameter.type_index = 0x74;
    parameter.parameter = true; parameter.procedure_section = 1; parameter.procedure_section_offset = 0x20;
    parameter.procedure_size = 0x40; parameter.module_name = "main.cpp"; parameter.object_name = "main.obj";
    PdbLocalLiveRange local_range; local_range.location_kind = PdbLocalLocationKind::register_value;
    local_range.register_id = 17; local_range.section = 1; local_range.section_offset = 0x24; local_range.size = 8;
    local_range.gaps.push_back({2, 1}); parameter.live_ranges.push_back(local_range);
    local_table.locals.push_back(parameter);
    const auto attached_locals = attach_pdb_locals(loaded, pdb, local_table);
    check(attached_locals && attached_locals.value() == 1 && loaded.metadata.pe->pdb_locals.size() == 1 &&
          loaded.metadata.pe->pdb_locals[0].name == "arg" && loaded.metadata.pe->pdb_locals[0].parameter &&
          loaded.metadata.pe->pdb_locals[0].type_index == 0x74 &&
          loaded.metadata.pe->pdb_locals[0].procedure_address == Address{{0}, 0x140001020ULL} &&
          loaded.metadata.pe->pdb_locals[0].live_ranges.size() == 1 &&
          loaded.metadata.pe->pdb_locals[0].live_ranges[0].register_id == 17 &&
          loaded.metadata.pe->pdb_locals[0].live_ranges[0].gaps.size() == 1 &&
          loaded.metadata.pe->pdb_locals[0].object_name == "main.obj",
          "matching PDB locals attach with type, parameter, provenance, and bounded procedure address");
    auto invalid_local = parameter;
    invalid_local.procedure_section = 9;
    PdbLocalTable invalid_local_table; invalid_local_table.locals.push_back(invalid_local);
    const auto invalid_local_result = attach_pdb_locals(loaded, pdb, invalid_local_table);
    check(invalid_local_result && !loaded.metadata.pe->pdb_locals[0].procedure_address,
          "local rows with invalid procedure sections remain available without guessed addresses");
}
void pe_local_pdb_binding_tests() {
    auto loaded = parse_pe(pe_codeview_fixture()).value();
    FixtureFile missing(bytes({0x01}));
    std::error_code ignored;
    std::filesystem::remove(missing.path, ignored);
    auto absent = bind_local_pe_pdb(loaded, missing.path);
    check(absent && !absent.value() && loaded.metadata.pe->pdb_status == PePdbStatus::missing,
          "a missing local PDB is reported without failing PE loading");
    {
        std::ofstream output(missing.path, std::ios::binary);
        const char malformed[] = "not a PDB";
        output.write(malformed, sizeof(malformed) - 1);
    }
    auto malformed = bind_local_pe_pdb(loaded, missing.path);
    check(malformed && !malformed.value() && loaded.metadata.pe->pdb_status == PePdbStatus::malformed,
          "a malformed local PDB is reported without attaching rows");
    std::vector<std::byte> pdb(7 * 512);
    constexpr char magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0";
    for (std::size_t i = 0; i < sizeof(magic) - 1; ++i) pdb[i] = std::byte(magic[i]);
    auto put_pdb = [&](std::size_t at, std::uint64_t value, std::size_t width) {
        for (std::size_t i = 0; i < width; ++i) pdb.at(at + i) = std::byte((value >> (8 * i)) & 0xff);
    };
    put_pdb(32,512,4); put_pdb(36,1,4); put_pdb(40,7,4); put_pdb(44,32,4); put_pdb(52,2,4);
    put_pdb(2*512,3,4); put_pdb(3*512,4,4); put_pdb(3*512+4,0xffffffff,4);
    put_pdb(3*512+8,28,4); put_pdb(3*512+12,56,4); put_pdb(3*512+16,64,4);
    put_pdb(3*512+20,4,4); put_pdb(3*512+24,5,4); put_pdb(3*512+28,6,4);
    put_pdb(4*512,20000404,4); put_pdb(4*512+4,0x12345678,4); put_pdb(4*512+8,7,4);
    for (std::size_t i = 0; i < 16; ++i) pdb[4*512+12+i] = std::byte(0xf0+i); // Valid MSF, mismatched GUID.
    put_pdb(5*512,20040203,4); put_pdb(5*512+4,56,4); put_pdb(5*512+8,0x1000,4); put_pdb(5*512+12,0x1000,4);
    {
        std::ofstream output(missing.path, std::ios::binary);
        output.write(reinterpret_cast<const char *>(pdb.data()), static_cast<std::streamsize>(pdb.size()));
    }
    auto mismatch = bind_local_pe_pdb(loaded, missing.path);
    check(mismatch && !mismatch.value() && loaded.metadata.pe->pdb_status == PePdbStatus::mismatch &&
          loaded.metadata.pe->source_lines.empty(), "a valid PDB with a different GUID is rejected");
    std::filesystem::remove(missing.path, ignored);
}
void pe_bound_import_tests() {
    for (bool pe64 : {true, false}) {
        const auto loaded = parse_pe(pe_bound_import_fixture(pe64)).value();
        check(loaded.metadata_complete, "bound import directory is parsed completely");
        check(loaded.metadata.pe && loaded.metadata.pe->bound_imports.size() == 1,
              "PE publishes one bound-import descriptor");
        if (loaded.metadata.pe && loaded.metadata.pe->bound_imports.size() == 1) {
            const auto &bound = loaded.metadata.pe->bound_imports.front();
            check(bound.timestamp == 0x12345678 && bound.library == "fixture.dll",
                  "bound-import timestamp and library name");
            check(bound.forwarders.size() == 1 && bound.forwarders[0].timestamp == 0x87654321 &&
                  bound.forwarders[0].library == "fwd.dll", "bound forwarder reference");
            check(bound.descriptor.spans == std::vector<PeSourceSpan>{{{0x700}, 8}} &&
                  bound.library_name == std::vector<PeSourceSpan>{{{0x730}, 12}} &&
                  bound.forwarders[0].descriptor.spans == std::vector<PeSourceSpan>{{{0x708}, 8}} &&
                  bound.forwarders[0].library_name == std::vector<PeSourceSpan>{{{0x73c}, 8}},
                  "bound import and forwarder source provenance");
        }
    }
    auto partial = [](std::vector<std::byte> data, const char *message) {
        const auto result = parse_pe(data);
        check(result && !result.value().metadata_complete && !result.value().diagnostics.empty(), message);
    };
    auto data = pe_bound_import_fixture(); put(data, 0x704, 0xffff, 2);
    partial(data, "bound module name offset outside directory rejected");
    data = pe_bound_import_fixture(); put(data, 0x706, 0xffff, 2);
    partial(data, "truncated bound forwarder-reference array rejected");
    data = pe_bound_import_fixture(); put(data, 0x70e, 1, 2);
    partial(data, "reserved bound forwarder field rejected");
    data = pe_bound_import_fixture(); put(data, 0x164, 8, 4);
    partial(data, "bound descriptor terminator must fit in directory");
    data = pe_bound_import_fixture();
    for (std::size_t i = 0x730; i < 0x744; ++i) data[i] = std::byte{'X'};
    partial(data, "bound module name must terminate inside directory");
}
int main() { return run([] {raw_tests();detection_tests();pe_header_tests();pe_metadata_tests();pe_resource_tests();pe_load_configuration_tests();pe_tls_tests();pe_rebase_tests();pe_delay_import_tests();pe_codeview_tests();pe_pdb_source_line_tests();pe_local_pdb_binding_tests();pe_bound_import_tests();}); }

