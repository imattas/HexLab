#include "hexlab/loaders/elf.hpp"
#include "hexlab/image/patches.hpp"
#include "support/elf_dynamic_symbol_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::elf_dynamic_symbol_fixture;
namespace {
constexpr std::size_t rel = 5000, slot = 7600, relative = 7616;
std::uint64_t read_word(std::span<const std::byte> bytes) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i)
        value |= std::to_integer<std::uint64_t>(bytes[i]) << (i * 8);
    return value;
}
std::uint64_t base_address(bool wide) { return wide ? UINT64_C(0x100000000) : UINT64_C(0x10000); }
std::size_t first_null(const std::vector<std::byte> &data, bool wide) {
    const auto word = wide ? 8u : 4u;
    for (std::size_t i = 0; i < 32; ++i)
        if (std::all_of(data.begin() + dynamic_at + 2 * word * i, data.begin() + dynamic_at + 2 * word * i + word,
                        [](std::byte b) { return b == std::byte{0}; }))
            return i;
    throw std::runtime_error("Fixture missing NULL");
}
std::vector<std::byte> fixture(bool wide, bool rela, bool big = false, bool sections = false, unsigned mode = 0) {
    auto data = elf_dynamic_symbol_fixture::fixture(wide, big, mode, sections);
    const auto address = base_address(wide);
    const auto word = wide ? 8u : 4u;
    const auto stride = (rela ? 3u : 2u) * word;
    const auto start = first_null(data, wide);
    tag(data, wide, big, start, rela ? 7 : 17, address + rel);
    tag(data, wide, big, start + 1, rela ? 8 : 18, 2 * stride);
    tag(data, wide, big, start + 2, rela ? 9 : 19, stride);
    tag(data, wide, big, start + 3, 23, address + rel + stride);
    tag(data, wide, big, start + 4, 2, stride);
    tag(data, wide, big, start + 5, 20, rela ? 7 : 17);
    tag(data, wide, big, start + 6, 0, 0);
    program(data, wide, 1, 2, dynamic_at, address + dynamic_at, (start + 7) * 2 * word, (start + 7) * 2 * word, 6, word,
            big);
    put(data, rel, address + relative, word, big);
    put(data, rel + word, 8, word, big);
    if (rela)
        put(data, rel + 2 * word, UINT64_MAX - 15, word, big);
    put(data, rel + stride, address + slot, word, big);
    put(data, rel + stride + word, wide ? (UINT64_C(2) << 32) | 7 : (2 << 8) | 7, word, big);
    if (rela)
        put(data, rel + stride + 2 * word, 0, word, big);
    put(data, relative, UINT64_MAX - 15, word, big);
    if (sections) {
        // Extend the relocated section-header table without overwriting payloads.
        auto headers = base(wide, big, 3);
        headers.resize(2048);
        section(headers, wide, 13, 0, rela ? 4 : 9, 2, address + rel, rel, 2 * stride, word, big);
        links(headers, wide, big, 13, 1, 0, stride);
        const auto shsize = wide ? 64 : 40;
        std::copy_n(headers.begin() + 512 + 13 * shsize, shsize, data.begin() + 6144 + 13 * shsize);
        put(data, wide ? 60 : 48, 14, 2, big);
        // Dynamic section itself describes the expanded array.
        put(data, 6144 + 3 * shsize + (wide ? 32 : 20), (start + 7) * 2 * word, word, big);
    }
    return data;
}
Result<LoadedImage> load(std::vector<std::byte> data) {
    return load_elf(std::make_shared<MemoryStorage>(std::move(data)), {});
}
void declared_padding_extent() {
    for (bool wide : {false, true})
        for (bool rela : {false, true})
            for (bool big : {false, true}) {
                const auto address = base_address(wide);
                const auto word = wide ? 8u : 4u;
                const auto minimum = (rela ? 3u : 2u) * word, stride = minimum + 8;
                auto original = fixture(wide, rela, big);
                const auto start = first_null(elf_dynamic_symbol_fixture::fixture(wide, big), wide);
                const std::vector<std::byte> second(original.begin() + rel + minimum,
                                                    original.begin() + rel + 2 * minimum);
                std::copy(second.begin(), second.end(), original.begin() + rel + stride);
                tag(original, wide, big, start + 1, rela ? 8 : 18, 2 * stride);
                tag(original, wide, big, start + 2, rela ? 9 : 19, stride);
                tag(original, wide, big, start + 3, 23, address + rel + stride);
                // Keep referenced fields initialized while isolating the array's final padding.
                put(original, rel, address + 4016, word, big);
                put(original, rel + stride, address + 4000, word, big);
                put(original, 4016, UINT64_MAX - 15, word, big);
                const auto end_fields = rel + stride + minimum;
                check(bool(load(original)), "padded dynamic REL/RELA table preserves its actual declared stride");
                for (bool zero_fill : {false, true}) {
                    auto data = original;
                    program(data, wide, 0, 1, 0, address, end_fields, end_fields + (zero_fill ? 8 : 0), 5, 1, big);
                    check(!load(data),
                          "entire dynamic relocation extent, including ignored padding, must have initialized backing");
                }
                auto data = original;
                std::copy_n(data.begin() + end_fields, 8, data.begin() + 6000);
                program(data, wide, 0, 1, 0, address, end_fields, end_fields, 5, 1, big);
                program(data, wide, 2, 1, 6000, address + end_fields, 8, 8, 4, 1, big);
                const auto result = load(data);
                check(result && result.value().metadata.elf->relocations.size() == 2 &&
                          result.value().metadata.elf->relocations[0].addend == -16,
                      "dynamic relocation padding can span canonical mappings without changing record/addend identity");
                if (result)
                    check(!result.value().metadata_reads.intersects({6000}, 8).value(),
                          "relocation padding validation does not parse unknown extension bytes");
            }
}
void records() {
    for (bool wide : {false, true})
        for (bool rela : {false, true})
            for (bool big : {false, true})
                for (bool sections : {false, true}) {
                    const auto data = fixture(wide, rela, big, sections);
                    auto result = load(data);
                    check(bool(result), "dynamic REL/RELA/JMPREL parse32/64 both endian with/without sections");
                    if (!result)
                        continue;
                    const auto &elf = *result.value().metadata.elf;
                    const auto stride = (rela ? 3u : 2u) * (wide ? 8u : 4u);
                    check(elf.relocations.size() == 2,
                          "overlapping dynamic/section sources do not duplicate authoritative relocation rows");
                    if (elf.relocations.size() != 2)
                        continue;
                    check(elf.relocations[0].kind == ElfRelocationKind::base_relative &&
                              elf.relocations[0].addend == -16 &&
                              elf.relocations[0].place == Address{{0}, base_address(wide) + relative},
                          "relative relocation preserves signed addend without choosing runtime base");
                    check(elf.relocations[1].kind == ElfRelocationKind::jump_slot &&
                              elf.relocations[1].symbol_index == 2 && elf.relocations[1].symbol_index_validated &&
                              elf.relocations[1].symbol_table &&
                              elf.relocations[1].place == Address{{0}, base_address(wide) + slot},
                          "dynamic jump slot binds validated symbol provenance and actual place");
                    check(elf.relocation_tables.size() == 2 &&
                              elf.relocation_tables[0].rows == std::vector<std::uint64_t>{0, 1} &&
                              elf.relocation_tables[1].rows == std::vector<std::uint64_t>{1},
                          "table aliases retain individual row-index mappings");
                    check(elf.dynamic_tables[0].relocation_tables.size() == 2 &&
                              elf.dynamic_tables[0].relocation_tables[0].tag == (rela ? 7 : 17) &&
                              elf.dynamic_tables[0].relocation_tables[1].tag == 23,
                          "general and PLT table roles retain their original dynamic tags");
                    check(elf.relocations[1].record_file_offset == rel + stride && elf.relocations_complete &&
                              elf.dynamic_complete && result.value().metadata_complete == !big,
                          "canonical entry location and explicit completeness stay consistent");
                    const auto original = result.value().image->storage()->read_at({0}, data.size()).value();
                    check(std::equal(original.bytes.begin(), original.bytes.end(), data.begin(), data.end()),
                          "dynamic relocation metadata never applies a linker or modifies original bytes");
                }
}
void malformed_and_unavailable() {
    for (bool wide : {false, true})
        for (bool rela : {false, true}) {
            const auto data = fixture(wide, rela);
            const auto start = first_null(elf_dynamic_symbol_fixture::fixture(wide), wide);
            const auto word = wide ? 8u : 4u, stride = (rela ? 3u : 2u) * word;
            auto bad = data;
            tag(bad, wide, false, start + 2, rela ? 9 : 19, stride - 1);
            check(!load(bad), "dynamic relocation entry size cannot truncate fields");
            bad = data;
            tag(bad, wide, false, start + 1, rela ? 8 : 18, 2 * stride - 1);
            check(!load(bad), "dynamic relocation extent requires whole entries");
            bad = data;
            tag(bad, wide, false, start + 5, 20, 13);
            check(!load(bad), "PLTREL must select REL or RELA");
            bad = data;
            tag(bad, wide, false, start + 4, 21, 0);
            check(!load(bad), "JMPREL requires bounded PLTRELSZ");
            bad = data;
            put(bad, rel + stride + word, wide ? (UINT64_C(99) << 32) | 7 : (99 << 8) | 7, word);
            check(!load(bad), "dynamic relocation symbol index bounded");
            bad = data;
            put(bad, rel, base_address(wide) + 8192, word);
            check(!load(bad), "dynamic relocation place cannot lie outside loaded memory");
            auto unknown = load(fixture(wide, rela, false, false, 4));
            check(unknown && unknown.value().metadata.elf->relocations.size() == 2 &&
                      !unknown.value().metadata.elf->relocations[1].symbol_index_validated &&
                      unknown.value().metadata.elf->relocations[1].symbol_table &&
                      !unknown.value().metadata.elf->relocations_complete,
                  "unbounded symbol table preserves raw relocation identity without inventing validation or target");
        }
}
std::vector<std::byte> runtime_fixture(std::uint32_t relocation_type = 8, std::uint32_t symbol_index = 0,
                                       std::uint64_t target = 3000, std::uint64_t addend = 0x1234) {
    using namespace hexlab_test::elf_fixture;
    auto data = base(true, false, 3);
    data.resize(4096);
    put(data, 24, 0x1000, 8); // e_entry
    program(data, true, 0, 1, 0, 0x1000, 4096, 4096, 7, 4096);
    // PT_DYNAMIC points to one bounded RELA table in the file-backed load.
    program(data, true, 1, 2, 1024, 0x1400, 64, 64, 6, 8);
    put(data, 64 + 56, 2, 2); // e_phnum
    const auto tag = [&](std::size_t index, std::uint64_t kind, std::uint64_t value) {
        put(data, 1024 + index * 16, kind, 8);
        put(data, 1032 + index * 16, value, 8);
    };
    tag(0, 7, 0x1000 + 2048); // DT_RELA
    tag(1, 8, 24);   // DT_RELASZ
    tag(2, 9, 24);   // DT_RELAENT
    tag(3, 0, 0);
    put(data, 2048, 0x1000 + target, 8);
    put(data, 2056, (std::uint64_t{symbol_index} << 32) | relocation_type, 8);
    put(data, 2064, addend, 8);
    return data;
}
void runtime_relative_application() {
    constexpr std::uint64_t bias = 0x7000000000;
    auto source = runtime_fixture();
    auto storage = std::make_shared<MemoryStorage>(source);
    auto loaded = load_elf(storage, {});
    check(loaded && loaded.value().metadata.elf && loaded.value().metadata.elf->header.object_type == 3,
          "ET_DYN runtime relocation fixture loads as a shared image");
    if (!loaded) return;
    const auto applied = apply_elf_runtime_relocations(loaded.value(), bias);
    check(bool(applied), "bounded x86-64 ET_DYN relative relocation produces a runtime image");
    if (!applied) return;
    check(applied.value().load_bias == bias && applied.value().applied_indices == std::vector<std::uint64_t>{0} &&
              applied.value().skipped.empty(),
          "runtime relocation reports exact applied source indexes and no skips");
    const auto relocated = applied.value().image->read({{0}, bias + 0x1000 + 3000}, 8);
    check(relocated && read_word(relocated.value()) == bias + 0x1234,
          "R_X86_64_RELATIVE applies B+A at shifted runtime address");
    const auto entry = applied.value().image->layout().entries;
    check(entry.size() == 1 && entry[0] == Address{{0}, bias + 0x1000},
          "runtime image shifts executable entry with load bias");
    const auto original = loaded.value().image->read({{0}, 0x1000 + 3000}, 8);
    check(original && read_word(original.value()) == 0,
          "runtime relocation overlay leaves original mapped image bytes unchanged");
    auto original_storage = storage->read_at({2048}, 24);
    check(original_storage && std::equal(original_storage.value().bytes.begin(), original_storage.value().bytes.end(),
                                         source.begin() + 2048),
          "runtime relocation does not mutate original file bytes or relocation provenance");
}
void runtime_relocation_rejections() {
    constexpr std::uint64_t bias = 0x7000000000;
    for (const auto [case_id, reason] : {
             std::pair{0, "non-relative relocation"},
             std::pair{1, "relative relocation with symbol"},
             std::pair{2, "field extending past initialized load"}}) {
        auto loaded = load(runtime_fixture());
        check(bool(loaded), "unsupported runtime relocation remains inspectable");
        if (!loaded) continue;
        auto elf = *loaded.value().metadata.elf;
        auto &relocation = elf.relocations.at(0);
        if (case_id == 0) {
            relocation.type = 1;
            relocation.kind = ElfRelocationKind::absolute;
        } else if (case_id == 1)
            relocation.symbol_index = 1;
        else {
            relocation.place = Address{{0}, 0x1ffc};
            relocation.file_place = FileOffset{4092};
        }
        loaded.value().metadata.elf = std::move(elf);
        auto result = apply_elf_runtime_relocations(loaded.value(), bias);
        check(result && result.value().applied_indices.empty() && result.value().skipped.size() == 1,
              (std::string(reason) + " receives explicit unsupported diagnostic and no patch").c_str());
    }
    auto loaded = load(runtime_fixture());
    if (!loaded) return;
    auto wrong_type = loaded.value();
    auto metadata = *wrong_type.metadata.elf;
    metadata.header.object_type = 2;
    wrong_type.metadata.elf = std::move(metadata);
    check(!apply_elf_runtime_relocations(wrong_type, bias), "runtime relocation stage rejects ET_EXEC");

    loaded = load(runtime_fixture());
    check(bool(loaded), "runtime bounds fixture loads");
    if (!loaded) return;
    check(!apply_elf_runtime_relocations(loaded.value(), UINT64_MAX),
          "runtime load bias that overflows mapped address ranges is rejected");
    check(!apply_elf_runtime_relocations(loaded.value(), bias, {}, ElfRuntimeRelocationLimits{0}),
          "runtime relocation stage rejects a zero record budget");

    auto overlap = loaded.value();
    auto overlap_metadata = *overlap.metadata.elf;
    overlap_metadata.relocations.push_back(overlap_metadata.relocations.at(0));
    overlap_metadata.dynamic_tables.at(0).relocation_tables.at(0).table_index = 0;
    overlap_metadata.relocation_tables.at(0).rows.push_back(1);
    overlap.metadata.elf = std::move(overlap_metadata);
    auto overlap_result = apply_elf_runtime_relocations(overlap, bias);
    check(overlap_result && overlap_result.value().applied_indices.empty() &&
              overlap_result.value().skipped.size() == 2,
          "overlapping runtime relocation fields are both rejected without order-dependent patching");
}
} // namespace
int main() {
    return run([] {
        declared_padding_extent();
        records();
        malformed_and_unavailable();
        runtime_relative_application();
        runtime_relocation_rejections();
    });
}
