#include "hexlab/loaders/elf.hpp"
#include "support/elf_metadata_fixture.hpp"
#include "support/elf_retained_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include <limits>
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::elf_metadata_fixture;
namespace {
Result<LoadedImage> load(std::vector<std::byte> data) {
    return load_elf(std::make_shared<MemoryStorage>(std::move(data)), {});
}
void records() {
    for (bool wide : {false, true})
        for (bool rela : {false, true})
            for (bool big : {false, true}) {
                const auto data = relocatable(wide, rela, big);
                auto result = load(data);
                check(bool(result), "literal ELF32/64 REL/RELA both endian parsed");
                if (!result)
                    continue;
                const auto &elf = *result.value().metadata.elf;
                const auto &rows = elf.relocations;
                check(rows.size() == 6, "original relocation rows retained without applying patches");
                check(rows[0].source.section == 7u && rows[0].source.file_offset == relocations_at &&
                          rows[0].index == 0 && rows[0].symbol_table && rows[0].symbol_table->section == 5u &&
                          rows[0].symbol_table->file_offset == symbols_at && rows[0].symbol_index == 1,
                      "relocation table and symbol provenance preserve actual section/file identities");
                check(rows[0].offset == 1 && rows[0].type == 2 && rows[0].kind == ElfRelocationKind::pc_relative &&
                          rows[0].field_size == UINT64_C(4) && rows[0].place == Address{{1}, 1} &&
                          rows[0].file_place == FileOffset{257} && rows[0].addend == -4 &&
                          rows[0].explicit_addend == rela,
                      "PC-relative place and signed addend use declared section domain");
                check(rows[1].kind == ElfRelocationKind::absolute && rows[1].field_size == (wide ? 8u : 4u) &&
                          rows[1].addend == (wide ? INT64_MIN : INT32_MIN),
                      "signed absolute addend retains full encoded width");
                check(rows[2].type == (wide ? 0x12345678u : 254u) && rows[2].kind == ElfRelocationKind::unknown &&
                          !rows[2].field_size && (rela ? rows[2].addend == 17 : !rows[2].addend),
                      "unknown relocation type remains full-width and does not guess implicit storage");
                check(rows[3].kind == ElfRelocationKind::base_relative && rows[3].symbol_index == 0 &&
                          rows[3].place == Address{{1}, 24},
                      "base-relative row remains symbolic without invented runtime base");
                check(rows[4].kind == ElfRelocationKind::none && !rows[4].place && !rows[4].file_place,
                      "NONE relocation preserves raw offset without inventing a field");
                check(rows[5].kind == ElfRelocationKind::plt_relative && rows[5].symbol_index == 2 &&
                          rows[5].addend == -4,
                      "PLT relocation remains distinct from a direct symbol address");
                check(!result.value().metadata_complete && !elf.relocations_complete,
                      "unknown relocation semantics remain explicitly partial");
                const auto published = result.value().image->storage()->read_at({0}, data.size()).value();
                check(std::equal(published.bytes.begin(), published.bytes.end(), data.begin(), data.end()) &&
                          result.value().image->read({{1}, 0}, 6).value() ==
                              std::vector<std::byte>(data.begin() + 256, data.begin() + 262),
                      "loader never links or mutates initialized bytes");
                check(result.value()
                              .metadata_reads
                              .intersects({relocations_at}, 6 * (wide ? (rela ? 24 : 16) : (rela ? 12 : 8)))
                              .value() &&
                          (rela ? !result.value().metadata_reads.intersects({257}, 4).value()
                                : result.value().metadata_reads.intersects({257}, 4).value()),
                      "relocation table and only actual implicit addend bytes enter metadata dependencies");
            }
}
void aarch64_common_relocations() {
    auto data = relocatable(true, true);
    put(data, 18, std::uint16_t{183}, 2);
    relocation(data, true, true, false, 0, 1, 257, 1, UINT64_MAX - 3);
    relocation(data, true, true, false, 1, 8, 261, 2, UINT64_MAX - 3);
    relocation(data, true, true, false, 2, 20, 1025, 1, 0);
    relocation(data, true, true, false, 3, 24, 1026, 2, 0);
    relocation(data, true, true, false, 4, 0, 1027, 0, 0);
    relocation(data, true, true, false, 5, 16, 1036, 0, 0);
    const auto result = load(std::move(data));
    check(bool(result), "AArch64 common ELF64 relocations parse");
    if (!result)
        return;
    const auto &rows = result.value().metadata.elf->relocations;
    check(rows[0].kind == ElfRelocationKind::absolute && rows[0].field_size == 8 && rows[0].addend == -4,
          "AArch64 ABS64 has full-width field and signed addend");
    check(rows[1].kind == ElfRelocationKind::pc_relative && rows[1].field_size == 4 && rows[1].addend == -4,
          "AArch64 PREL32 records field width and signed addend");
    check(rows[2].kind == ElfRelocationKind::global_data && rows[2].field_size == 8 && rows[2].symbol_index_validated,
          "AArch64 GLOB_DAT retains symbol-table validation");
    check(rows[3].kind == ElfRelocationKind::jump_slot && rows[3].field_size == 8 && rows[3].symbol_index_validated,
          "AArch64 JUMP_SLOT retains symbol-table validation");
    check(rows[4].kind == ElfRelocationKind::base_relative && rows[4].field_size == 8 &&
              rows[5].kind == ElfRelocationKind::ifunc && rows[5].field_size == 8 &&
              result.value().metadata.elf->relocations_complete,
          "AArch64 RELATIVE and IRELATIVE are typed without inventing runtime values");
    auto bad = relocatable(true, true);
    put(bad, 18, std::uint16_t{183}, 2);
    relocation(bad, true, true, false, 0, 24, 1035, 1, 0);
    check(!load(std::move(bad)), "AArch64 TLSDESC pair must fit wholly inside its target section");
}
void malformed() {
    for (bool wide : {false, true})
        for (bool rela : {false, true}) {
            const auto data = relocatable(wide, rela);
            const auto stride = wide ? (rela ? 24 : 16) : (rela ? 12 : 8);
            auto bad = data;
            links(bad, wide, false, 7, 99, 1, stride);
            check(!load(bad), "relocation symbol table link bounded");
            bad = data;
            links(bad, wide, false, 7, 6, 1, stride);
            check(!load(bad), "relocation link must target a symbol table");
            bad = data;
            links(bad, wide, false, 7, 5, 99, stride);
            check(!load(bad), "relocatable target section bounded");
            bad = data;
            links(bad, wide, false, 7, 5, 0, stride);
            check(!load(bad), "relocatable relocation needs an actual target section");
            bad = data;
            links(bad, wide, false, 7, 5, 1, stride - 1);
            check(!load(bad), "relocation stride cannot truncate required fields");
            bad = data;
            section(bad, wide, 7, 0, rela ? 4 : 9, 0, 0, relocations_at, 6 * stride - 1, 8);
            check(!load(bad), "relocation table requires whole records");
            bad = data;
            relocation(bad, wide, rela, false, 0, 1, 2, 99, UINT64_MAX - 3);
            check(!load(bad), "relocation symbol index bounded by linked table");
            bad = data;
            relocation(bad, wide, rela, false, 0, 30, 2, 1, UINT64_MAX - 3);
            check(!load(bad), "relocation field must fit declared target section");
            bad = data;
            relocation(bad, wide, rela, false, 3, 24, 8, 1, 0);
            check(!load(bad), "base-relative relocation cannot claim nonzero symbol");
            bad = data;
            links(bad, wide, false, 7, 0, 1, stride);
            check(!load(bad), "symbolic relocation cannot omit its symbol table");
        }
}
void special_places() {
    for (bool wide : {false, true}) {
        const auto stride = wide ? 16 : 8;
        auto data = relocatable(wide, false);
        section(data, wide, 7, 0, 9, 0, 0, relocations_at, stride, 8);
        links(data, wide, false, 7, 5, 3, stride);
        auto result = load(data);
        check(result && result.value().metadata.elf->relocations[0].place == Address{{3}, 1} &&
                  !result.value().metadata.elf->relocations[0].file_place &&
                  result.value().metadata.elf->relocations[0].addend == 0,
              "REL implicit addend in NOBITS is zero without phantom file I/O");
        data = relocatable(wide, false);
        section(data, wide, 1, 1, 1, 0, 0, 256, 32, 1);
        section(data, wide, 7, 0, 9, 0, 0, relocations_at, stride, 8);
        links(data, wide, false, 7, 5, 1, stride);
        result = load(data);
        check(result && !result.value().metadata.elf->relocations[0].place &&
                  result.value().metadata.elf->relocations[0].file_place == FileOffset{257} &&
                  result.value().metadata.elf->relocations[0].addend == -4,
              "nonallocated section relocation keeps canonical file place without inventing a mapped domain");
        data = relocatable(wide, false);
        relocation(data, wide, false, false, 0, 8, wide ? 16 : 14, 3);
        result = load(data);
        check(result && result.value().metadata.elf->relocations[0].kind == ElfRelocationKind::tls &&
                  result.value().metadata.elf->relocations[0].field_size == (wide ? 8u : 4u) &&
                  !result.value().metadata.elf->relocations[0].addend,
              "TLS field remains typed without guessed TLS base or implicit formula");
        if (!wide) {
            data = relocatable(false, false);
            relocation(data, false, false, false, 0, 1, 11, 1);
            result = load(data);
            check(result && result.value().metadata.elf->relocations[0].kind == ElfRelocationKind::plt_absolute &&
                      result.value().metadata.elf->relocations[0].field_size == 4u,
                  "absolute PLT relocation must not be mislabeled as a GOT formula");
        }
    }
}
void virtual_places() {
    for (bool wide : {false, true}) {
        auto data = relocatable(wide, false);
        const auto stride = wide ? 16 : 8;
        put(data, 16, 3, 2);
        program(data, wide, 0, 1, 0, 0, 4096, 4608, 5, 1);
        section(data, wide, 1, 1, 1, 6, 256, 256, 32, 1);
        section(data, wide, 2, 7, 1, 6, 320, 320, 4, 1);
        section(data, wide, 3, 14, 8, 3, 4096, 0xffff, 8, 1);
        symbol(data, wide, false, 1, 1, 0x12, 2, 320, 2);
        section(data, wide, 7, 0, 9, 0, 0, relocations_at, stride, 8);
        links(data, wide, false, 7, 5, 0, stride);
        relocation(data, wide, false, false, 0, 257, 2, 1);
        auto result = load(data);
        check(result && result.value().metadata.elf->relocations[0].place == Address{{0}, 257} &&
                  result.value().metadata.elf->relocations[0].file_place == FileOffset{257} &&
                  result.value().metadata.elf->relocations[0].addend == -4,
              "DYN relocation offset is a virtual address independent of section-relative syntax");
        program(data, wide, 0, 1, 0, 0, 259, 259, 5, 1);
        program(data, wide, 1, 1, 3000, 259, 2, 2, 5, 1);
        program(data, wide, 2, 1, 261, 261, 4096 - 261, 4096 - 261, 5, 1);
        data[3000] = std::byte{0xff};
        data[3001] = std::byte{0xff};
        result = load(data);
        check(result && result.value().metadata.elf->relocations[0].addend == -4 &&
                  !result.value().metadata.elf->relocations[0].file_place &&
                  result.value().metadata_reads.intersects({3000}, 2).value(),
              "implicit addend spans discontiguous backing without claiming one file patch coordinate");
    }
}
void retained_places() {
    for (bool wide : {false, true})
        for (bool rela : {false, true})
            for (auto type : {2, 3}) {
                auto linked = load(retained(wide, rela, false, type));
                check(linked && (rela || !linked.value().metadata.elf->relocations[0].addend),
                      "retained linked REL field is not the original implicit addend");
                auto debug = load(retained(wide, rela, true, type));
                check(debug && !debug.value().metadata.elf->relocations[0].place &&
                          debug.value().metadata.elf->relocations[0].file_place == FileOffset{2056},
                      "linked nonallocated debug relocations retain checked file coordinates without a VA");
            }
}
} // namespace
int main() {
    return run([] {
        records();
        aarch64_common_relocations();
        malformed();
        special_places();
        virtual_places();
        retained_places();
    });
}
