#include "hexlab/loaders/macho.hpp"
#include "support/macho_relocation_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::macho_fixture;
namespace {
template <class T> T take(Result<T> r) {
    if (!r)
        throw std::runtime_error(r.error().message);
    return std::move(r.value());
}
Result<LoadedImage> load(std::vector<std::byte> data) {
    return load_macho(std::make_shared<MemoryStorage>(std::move(data)), {}, {});
}
void records() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            const auto data = relocated(wide, big);
            auto loaded = take(load(data));
            const auto &m = *loaded.metadata.macho;
            check(m.relocations.size() == 1 && m.relocation_tables.size() == 1,
                  "original normal relocation array parsed");
            if (m.relocations.size() != 1)
                continue;
            const auto &r = m.relocations[0];
            const auto &t = m.relocation_tables[0];
            check(r.index == 0 && r.table == 0 && t.kind == MachORelocationSource::section && t.owner == 1 &&
                      t.offset == FileOffset{relocations_at} && r.record_file_offset == relocations_at &&
                      r.symbol_table == 1 && r.symbol_number == 1,
                  "relocation table/record/section/symbol namespace identities retained");
            check(r.offset == 1 && r.type == (wide ? 2 : 0) && r.length == 2 && r.field_size == 4 && r.pc_relative &&
                      r.external && !r.scattered && !r.retained && r.place == Address{{1}, 1} &&
                      r.file_place == FileOffset{769} && r.encoded_value == (wide ? UINT64_C(0) : UINT64_C(0xfffffefb)),
                  "bitfields use declared endian layout and preserve original encoded field bits");
            check(loaded.metadata_reads.intersects({relocations_at}, 8).value() &&
                      loaded.metadata_reads.intersects({769}, 4).value() &&
                      !loaded.metadata_reads.intersects({768}, 1).value(),
                  "only interpreted record/field bytes become metadata dependencies");
            const auto original = take(loaded.image->storage()->read_at({0}, data.size()));
            check(std::equal(original.bytes.begin(), original.bytes.end(), data.begin()),
                  "loader never applies a relocation to input bytes");
            auto bad = data;
            relocation(bad, big, 0, 1, 9, wide ? 2 : 0, 2, true, true);
            check(!load(bad), "external symbol index stays inside nlist namespace");
            bad = data;
            relocation(bad, big, 0, 7, 1, wide ? 2 : 0, 2, true, true);
            check(!load(bad), "field extent stays inside target section");
            bad = data;
            relocation_count(bad, wide, big, UINT32_MAX);
            check(!load(bad), "relocation count checked before allocation or read");
            bad = data;
            relocation(bad, big, 0, 0, 99, 0, 2, false, false);
            check(!load(bad), "local section ordinal cannot exceed section table");
            auto local = data;
            relocation(local, big, 0, 1, 2, wide ? 1 : 0, 2, true, false);
            auto value = take(load(local));
            check(value.metadata.macho->relocations[0].symbol_number == 2 &&
                      !value.metadata.macho->relocations[0].external,
                  "local section identity is distinct from nlist index");
            auto bss = data;
            relocation_count(bss, wide, big, 0);
            relocation_count(bss, wide, big, 1, 3);
            relocation(bss, big, 0, 0, 1, 0, wide ? 3 : 2, false, true);
            value = take(load(bss));
            check(value.metadata.macho->relocations[0].place == Address{{3}, 0} &&
                      !value.metadata.macho->relocations[0].file_place &&
                      value.metadata.macho->relocations[0].encoded_value == 0,
                  "zero-filled relocation field has zero bits without phantom file backing");
        }
}
void pairs() {
    for (bool big : {false, true}) {
        auto data = relocated(true, big);
        relocation_count(data, true, big, 2);
        relocation(data, big, 0, 0, 0, 5, 3, false, true);
        relocation(data, big, 1, 0, 8, 0, 3, false, true);
        put(data, 768, 10, 8, big);
        auto loaded = take(load(data));
        const auto &r = loaded.metadata.macho->relocations;
        check(r.size() == 2 && r[0].kind == MachORelocationKind::subtractor && r[0].pair == 1 && r[1].pair == 0 &&
                  r[1].auxiliary && r[0].encoded_value == 10 && !r[1].encoded_value,
              "x64 subtractor pair preserves two raw records and one actual field");
        auto bad = data;
        relocation_count(bad, true, big, 1);
        check(!load(bad), "dangling subtractor cannot invent missing minuend");
        bad = data;
        relocation(bad, big, 1, 1, 8, 0, 3, false, true);
        check(!load(bad), "subtractor companion must describe the same field");
        data = relocated(false, big);
        relocation_count(data, false, big, 2);
        put(data, relocations_at, 0xa2000004, 4, big);
        put(data, relocations_at + 4, 0x100, 4, big);
        put(data, relocations_at + 8, 0xa1ffffff, 4, big);
        put(data, relocations_at + 12, 0x102, 4, big);
        loaded = take(load(data));
        const auto &s = loaded.metadata.macho->relocations;
        check(
            s[0].scattered && s[0].type == 2 && s[0].value == 0x100 && s[0].offset == 4 && s[0].pair == 1 &&
                s[1].auxiliary && s[1].value == 0x102 && !s[1].place && !s[1].file_place,
            "scattered section difference retains pair payload without interpreting its address bits as another field");
        bad = data;
        relocation_count(bad, false, big, 1);
        check(!load(bad), "scattered difference requires pair record");
        data = relocated(false, big);
        relocation(data, big, 0, 0, 0, 1, 2, false, false);
        check(!load(data), "orphan generic pair is rejected before mapping payload address");
    }
}
void linked_and_unknown() {
    for (bool wide : {false, true}) {
        auto data = macho_fixture::symbols(wide, false, false);
        relocation_count(data, wide, false, 1);
        relocation(data, false, 0, 1, 1, wide ? 2 : 0, 2, true, true);
        put(data, 769, 3, 4, false);
        auto loaded = take(load(data));
        const auto &r = loaded.metadata.macho->relocations[0];
        check(r.retained && !r.encoded_value && !loaded.metadata_reads.intersects({769}, 4).value(),
              "retained linked static field is not sampled as an unapplied addend");
        const auto section = (wide ? 32u + 72u : 28u + 56u);
        put(data, section + (wide ? 64u : 56u), 0x02000000, 4, false);
        loaded = take(load(data));
        const auto &debug = loaded.metadata.macho->relocations[0];
        check(debug.retained && !debug.place && debug.file_place == FileOffset{769} && !debug.encoded_value,
              "linked debug relocation keeps file coordinates despite aliasing mapped virtual addresses");
        for (const auto protection : {0u, 8u}) {
            auto alias = macho_fixture::symbols(wide, false, false);
            relocation_count(alias, wide, false, 1);
            relocation(alias, false, 0, 1, 1, wide ? 2 : 0, 2, true, true);
            const auto extra = symtab_command(wide) + 24;
            segment(alias, wide, false, extra, wide ? UINT64_C(0x100000000) : UINT64_C(0x1000), 32, 768, 16, 7);
            put(alias, (wide ? 32 : 28) + (wide ? 60 : 44), protection, 4, false);
            put(alias, 16, 3, 4, false);
            put(alias, 20, extra + (wide ? 72 : 56) - (wide ? 32 : 28), 4, false);
            const auto mapped = take(load(alias));
            const auto &record = mapped.metadata.macho->relocations[0];
            check(!record.place && record.file_place == FileOffset{769},
                  "section in segment without known access cannot borrow an unrelated alias mapping");
        }
    }
    auto data = relocated(true);
    put(data, 4, 0x0100000c, 4, false);
    relocation_count(data, true, false, 2);
    relocation(data, false, 0, 1, 0xffffff, 10, 2, false, false);
    relocation(data, false, 1, 1, 1, 2, 2, true, true);
    auto loaded = take(load(data));
    check(loaded.metadata.macho->relocations[0].kind == MachORelocationKind::addend &&
              loaded.metadata.macho->relocations[0].auxiliary && !loaded.metadata.macho->relocations[0].place &&
              !loaded.metadata.macho->relocations_complete,
          "ARM64 ADDEND payload is not misread as an out-of-range section or x86 addend");
}
void fat_bounds() {
    auto inner = relocated(true);
    std::vector<std::byte> data(12288);
    put(data, 0, 0xcafebabe, 4, true);
    put(data, 4, 1, 4, true);
    put(data, 8, 0x01000007, 4, true);
    put(data, 12, 0x80000003, 4, true);
    put(data, 16, 4096, 4, true);
    put(data, 20, 4096, 4, true);
    put(data, 24, 12, 4, true);
    std::copy(inner.begin(), inner.end(), data.begin() + 4096);
    auto loaded = take(load(data));
    check(loaded.metadata.macho->relocations[0].record_file_offset == 4096 + relocations_at &&
              loaded.metadata.macho->relocations[0].file_place == FileOffset{4096 + 769},
          "universal relocation records and fields use outer-container coordinates");
    const auto section = 4096 + 32 + 72;
    put(data, section + 56, 4090, 4, false);
    check(!load(data), "relocation table cannot escape selected slice despite available outer bytes");
}
void classic_runtime() {
    auto data = macho_fixture::symbols(true, false, false);
    const auto second = symtab_command(true) + 24;
    segment(data, true, false, second, UINT64_C(0x100001000), 8, 1024, 8, 3);
    put(data, 32 + 60, 5, 4, false);
    const auto dynamic = second + 72;
    put(data, dynamic, 0xb, 4, false);
    put(data, dynamic + 4, 80, 4, false);
    put(data, dynamic + 64, relocations_at, 4, false);
    put(data, dynamic + 68, 1, 4, false);
    put(data, 16, 4, 4, false);
    put(data, 20, dynamic + 80 - 32, 4, false);
    relocation(data, false, 0, 0xfffff000, 1, 0, 3, false, true);
    const auto loaded = load(data);
    check(bool(loaded), "negative classic x64 relocation offset may identify memory before first writable segment");
    if (!loaded)
        return;
    const auto &row = loaded.value().metadata.macho->relocations[0];
    check(row.raw_address == 0xfffff000 && !row.scattered && row.place == Address{{0}, UINT64_C(0x100000000)} &&
              row.file_place == FileOffset{768} && !row.retained,
          "classic x64 base uses first writable segment and signed r_address without losing original word");
    relocation(data, false, 0, 0, 1, 0, 3, false, true);
    const auto zero = take(load(data));
    check(zero.metadata.macho->relocations[0].place == Address{{0}, UINT64_C(0x100001000)} &&
              zero.metadata.macho->relocations[0].file_place == FileOffset{1024},
          "zero runtime offset uses writable segment rather than first segment");
}
} // namespace
int main() {
    return run([] {
        records();
        pairs();
        linked_and_unknown();
        fat_bounds();
        classic_runtime();
    });
}
