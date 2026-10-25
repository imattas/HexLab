#include "hexlab/loaders/macho.hpp"
#include "hexlab/analysis/analysis.hpp"
#include "support/macho_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::macho_fixture;
namespace {
Result<LoadedImage> load(std::vector<std::byte> bytes, const MachOOptions &options = {}) {
    return load_macho(std::make_shared<MemoryStorage>(std::move(bytes)), options, {});
}
void mappings() {
    for (bool wide : {false, true})
        for (bool big : {false, true})
            for (bool object : {false, true}) {
                auto result = load(mapped(wide, big, object));
                check(bool(result), "Mach-O32/64 objects and linked mappings load in both byte orders");
                if (!result)
                    continue;
                const auto &loaded = result.value();
                const auto &metadata = *loaded.metadata.macho;
                const auto base = wide ? UINT64_C(0x100000000) : UINT64_C(0x1000);
                check(metadata.selected_slice == 0 && metadata.segments.size() == 1 && metadata.sections.size() == 3 &&
                          metadata.sections[0].ordinal == 1 && metadata.sections[0].address == (object ? 0x100 : base),
                      "raw segments and nonzero/equal section origins retained with one-based ordinals");
                const Address code{object ? AddressSpaceId{1} : AddressSpaceId{0}, object ? 0 : base};
                check(loaded.image->to_file_offset(code).value() == FileOffset{768} &&
                          loaded.image->read(code, 2).value() == bytes({0x90, 0xc3}),
                      "canonical initialized backing follows correct linked VA or section domain");
                const Address bss{object ? AddressSpaceId{3} : AddressSpaceId{0}, object ? 0 : base + 16};
                check(loaded.image->read(bss, 16).value() == std::vector<std::byte>(16) &&
                          !loaded.image->to_file_offset(bss) && !metadata.sections[2].file_offset,
                      "zero-fill section does not invent bytes at its raw nonsensical file offset");
                if (object)
                    check(loaded.image->to_file_offset({{2}, 0}).value() == FileOffset{776} &&
                              loaded.image->layout().domains.size() == 3,
                          "equal-valued object section addresses remain independently mapped domains");
                check(loaded.image->decode_context().mode == (big    ? ExecutionMode::unknown
                                                              : wide ? ExecutionMode::x86_64
                                                                     : ExecutionMode::x86_32),
                      "unsupported byte order preserves machine context without x86 decoding");
                check(loaded.metadata_reads.intersects({0}, wide ? 32 : 28).value() &&
                          !loaded.metadata_reads.intersects({768}, 8).value(),
                      "interpreted headers are metadata dependencies while ordinary code bytes are not");
            }
}
void dwarf_source_lines() {
    for(bool wide:{false,true})for(bool big:{false,true}){
        auto loaded=load(mapped_with_dwarf_lines(wide,big,false));check(loaded&&loaded.value().metadata.macho->source_lines.size()==2,"Mach-O linked image imports DWARF line rows in both classes and byte orders");if(!big)check(loaded&&loaded.value().metadata_complete,"non-mapped S_ATTR_DEBUG section does not make supported linked metadata incomplete");
        if(loaded&&loaded.value().metadata.macho&&loaded.value().metadata.macho->source_lines.size()==2){const auto&rows=loaded.value().metadata.macho->source_lines;const auto base=wide?UINT64_C(0x100000000):UINT64_C(0x1000);check(rows[0].source_section==4&&rows[0].source_file_offset==FileOffset{800}&&rows[0].selected_slice==0,"Mach-O source row retains selected-slice and section/file provenance");check(rows[0].raw_address==base&&rows[0].address==Address{{0},base}&&rows[0].file=="src.c"&&rows[0].line==1,"linked Mach-O maps DWARF row only through its unique declared section range");check(rows.back().end_sequence,"Mach-O DWARF end-sequence marker retained");}
    }
    auto object=load(mapped_with_dwarf_lines(true,false,true));check(object&&object.value().metadata.macho->source_lines.size()==2&&!object.value().metadata.macho->source_lines[0].address&&object.value().metadata.macho->source_lines[0].raw_address==0x100,"Mach-O object source rows preserve raw addresses without an unsupported relocation guess");
    auto malformed=load(mapped_with_dwarf_lines(true,false,false,true));check(malformed&&!malformed.value().metadata_complete&&malformed.value().metadata.macho->source_lines.empty()&&!malformed.value().diagnostics.empty(),"malformed Mach-O DWARF is diagnosed while the binary remains loadable");
    auto out_of_slice=mapped_with_dwarf_lines(true);put(out_of_slice,32+72+3*80+48,2040,4,false);check(!load(std::move(out_of_slice)),"Mach-O DWARF section bytes cannot cross the selected slice boundary");
}
void selection() {
    auto data = mapped_fat();
    auto preferred = load(data);
    check(preferred && preferred.value().metadata.macho->selected_slice == 1 &&
              preferred.value().image->to_file_offset({{0}, UINT64_C(0x100000000)}).value() == FileOffset{2816},
          "universal default chooses supported x64 with absolute outer-container backing");
    auto first = load(data, MachOOptions{0});
    check(first && first.value().metadata.macho->selected_slice == 0 &&
              first.value().image->to_file_offset({{0}, 0x1000}).value() == FileOffset{1792},
          "explicit nondefault universal slice selects its context and original container coordinates");
    check(!load(data, MachOOptions{2}) && !load(mapped(true), MachOOptions{1}), "explicit slice index is bounded");
    // The selected slice declares a field inside the outer file but outside itself.
    put(data, 1024 + 28 + 32, 1000, 4, false);
    put(data, 1024 + 28 + 36, 32, 4, false);
    check(!load(data, MachOOptions{0}), "segment backing cannot cross from selected slice into neighboring bytes");
}
void special_segments() {
    for (bool wide : {false, true}) {
        auto data = mapped(wide);
        const auto header = wide ? 32u : 28u;
        const auto base = wide ? UINT64_C(0x100000000) : UINT64_C(0x1000);
        put(data, header + (wide ? 68 : 52), 1, 4, false);
        auto high = load(data);
        check(high && !high.value().metadata_complete && !high.value().diagnostics.empty(),
              "section declarations disagreeing with SG_HIGHVM backing are explicit partial metadata");
        check(high && high.value().image->read({{0}, base}, 16).value() == std::vector<std::byte>(16) &&
                  !high.value().image->to_file_offset({{0}, base}) &&
                  high.value().image->to_file_offset({{0}, base + 16}).value() == FileOffset{768},
              "SG_HIGHVM places initialized backing high and leaves low addresses zero-filled");
        data = mapped(wide);
        put(data, header + (wide ? 60 : 44), 0, 4, false);
        name(data, header + 8, "__PAGEZERO");
        auto zero = load(data);
        check(zero && !zero.value().image->segment_at({{0}, base}),
              "no-access reservation does not become readable/executable mapped zero memory");
        for (auto type : {0xcu, 0x12u}) {
            data = mapped(wide, false, true);
            const auto first = header + (wide ? 72 : 56), stride = wide ? 80u : 68u;
            put(data, first + 2 * stride + (wide ? 64 : 56), type, 4, false);
            auto bss = load(data);
            check(bss && !bss.value().image->to_file_offset({{3}, 0}),
                  "gigabyte and thread-local zero-fill section types do not read raw file offsets");
        }
        data = mapped(wide);
        put(data, 4, 0x0200000c, 4, false);
        auto unknown = load(data);
        check(unknown && unknown.value().metadata.macho->container.slices[0].header.cpu_type == 0x0200000c &&
                  unknown.value().image->decode_context().mode == ExecutionMode::unknown &&
                  !unknown.value().metadata_complete,
              "full32-bit unsupported CPU identity stays inspectable without a fabricated x86 context");
    }
}
void overlaps_and_malformed() {
    for (bool wide : {false, true}) {
        auto data = mapped(wide);
        const auto header = wide ? 32u : 28u;
        const auto original = (wide ? 72u : 56u) + 3 * (wide ? 80u : 68u);
        const auto extra = wide ? 72u : 56u;
        const auto base = wide ? UINT64_C(0x100000000) : UINT64_C(0x1000);
        put(data, 16, 2, 4, false);
        put(data, 20, original + extra, 4, false);
        segment(data, wide, false, header + original, base + 8, 8, 776, 8, 1);
        auto compatible = load(data);
        check(compatible && compatible.value().image->to_file_offset({{0}, base + 8}).value() == FileOffset{776},
              "compatible overlapping declarations retain one canonical initialized backing");
        segment(data, wide, false, header + original, base + 8, 8, 800, 8, 1);
        check(!load(data), "conflicting initialized aliases fail instead of choosing arbitrary backing");
        segment(data, wide, false, header + original, base + 8, 8, 0, 0, 1);
        check(!load(data), "initialized versus zero-fill overlap is not silently merged");
        data = mapped(wide);
        put(data, header + (wide ? 64 : 48), UINT32_MAX, 4, false);
        check(!load(data), "section count is checked before array allocation or read");
        data = mapped(wide);
        put(data, header + (wide ? 48 : 36), 33, wide ? 8 : 4, false);
        check(!load(data), "linked file bytes cannot exceed memory extent");
        data = mapped(wide);
        put(data, header + 24, UINT64_MAX - 15, wide ? 8 : 4, false);
        check(!load(data), "segment VA extent cannot overflow address width");
    }
    check(!load_macho({}, {}, {}), "null source is a checked invalid argument");
    std::stop_source stop;
    stop.request_stop();
    auto canceled = load_macho(std::make_shared<MemoryStorage>(mapped(true)), {}, stop.get_token());
    check(!canceled && canceled.error().code == ErrorCode::canceled, "pre-canceled image loading stops before reads");
}
} // namespace
int main() {
    return run([] {
        mappings();
        dwarf_source_lines();
        selection();
        special_segments();
        overlaps_and_malformed();
    });
}
