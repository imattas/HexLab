#include "hexlab/loaders/macho.hpp"
#include "hexlab/analysis/functions.hpp"
#include "support/macho_symbol_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::macho_fixture;
namespace {
template <class T> T take(Result<T> result) {
    if (!result)
        throw std::runtime_error(result.error().message);
    return std::move(result.value());
}
Result<LoadedImage> load(std::vector<std::byte> bytes) {
    return load_macho(std::make_shared<MemoryStorage>(std::move(bytes)), {}, {});
}
void records() {
    for (bool wide : {false, true})
        for (bool big : {false, true})
            for (bool object : {false, true}) {
                auto loaded = take(load(hexlab_test::macho_fixture::symbols(wide, big, object)));
                const auto &metadata = *loaded.metadata.macho;
                const auto &rows = metadata.symbols;
                check(rows.size() == 9 && metadata.symbol_tables.size() == 1, "all original nlist records retained");
                if (rows.size() != 9)
                    continue;
                const auto base = wide ? UINT64_C(0x100000000) : UINT64_C(0x1000);
                check(rows[0].table_command == 1 && rows[0].index == 0 && rows[0].string_index == 1 &&
                          rows[0].record_file_offset == symbols_at && rows[0].name == "_same" &&
                          rows[0].address ==
                              Address{object ? AddressSpaceId{1} : AddressSpaceId{0}, object ? 0 : base} &&
                          rows[1].address ==
                              Address{object ? AddressSpaceId{2} : AddressSpaceId{0}, object ? 0 : base + 8},
                      "nlist source namespace and equal/nonzero section origins retain distinct domain addresses");
                check(
                    rows[2].state == MachOSymbolState::undefined && !rows[2].address && rows[2].descriptor == 0x0340 &&
                        (object ? !rows[2].library_ordinal : rows[2].library_ordinal == 3),
                    "undefined weak symbol retains raw descriptor without treating object alignment as dylib ordinal");
                check(rows[3].state == MachOSymbolState::absolute && !rows[3].code &&
                          rows[3].value == (wide ? UINT64_C(0xfedcba9876543210) : UINT64_C(0x76543210)),
                      "absolute constants preserve full width without becoming function roots");
                check(rows[4].state == MachOSymbolState::common && !rows[4].address && !rows[4].library_ordinal &&
                          rows[5].state == MachOSymbolState::indirect && rows[5].indirect_name == "_same" &&
                          !rows[5].address,
                      "common allocations and indirect aliases remain symbolic rather than resolved addresses");
                check(rows[6].state == MachOSymbolState::debug && !rows[6].address &&
                          rows[7].name == std::string("\xff\x01", 2) && !rows[7].code && rows[8].type == 0x1f &&
                          rows[8].descriptor == 0x0280,
                      "STAB/private/weak/alternate bits and nonUTF8 raw names remain exact");
                check(metadata.symbol_tables[0].symbol_offset == FileOffset{symbols_at} &&
                          metadata.symbol_tables[0].string_offset == FileOffset{strings_at} &&
                          metadata.symbol_tables[0].stride == (wide ? 16u : 12u) &&
                          loaded.metadata_reads.intersects({strings_at}, 64).value() &&
                          !loaded.metadata_reads.intersects({768}, 3).value(),
                      "interpreted nlist/string tables track source dependencies without reading code as metadata");
                if (!big) {
                    const auto recovered = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
                    check(std::any_of(recovered->functions.begin(), recovered->functions.end(),
                                      [&](const auto &row) { return row->entry == rows[0].address; }),
                          "executable Mach-O symbol definitions seed shared recovery");
                    const auto coarse = take(analyze(*loaded.image, loaded.metadata, {}, {}));
                    check(std::any_of(coarse.instructions.begin(), coarse.instructions.end(),
                                      [&](const auto &row) { return row.address == rows[0].address; }),
                          "coarse analysis shares Mach-O symbol roots");
                }
            }
}
void states_and_bounds() {
    for (bool wide : {false, true}) {
        auto data = hexlab_test::macho_fixture::symbols(wide);
        const auto command = symtab_command(wide);
        const auto stride = wide ? 16u : 12u;
        auto bad = data;
        put(bad, symbols_at, 64, 4, false);
        check(!load(bad), "symbol string index must be inside declared string table");
        bad = data;
        put(bad, command + 20, 2, 4, false);
        check(!load(bad), "unterminated/out-of-range symbol string rejects malformed table");
        bad = data;
        put(bad, command + 12, UINT32_MAX, 4, false);
        check(!load(bad), "symbol count bounded before allocation or reads");
        bad = data;
        put(bad, command + 8, 4090, 4, false);
        check(!load(bad), "nlist array extent is bounded by selected source");
        bad = data;
        put(bad, symbols_at + 5, 4, 1, false);
        check(!load(bad), "N_SECT ordinal cannot exceed declared section count");
        bad = data;
        put(bad, symbols_at + 5 * stride + 8, UINT64_MAX, wide ? 8 : 4, false);
        check(!load(bad), "full-width indirect alias string index cannot truncate into the table");
        bad = data;
        put(bad, symbols_at + 8, 0xff, wide ? 8 : 4, false);
        auto below = take(load(bad));
        check(!below.metadata.macho->symbols[0].address && !below.metadata_complete,
              "object symbol below section origin remains raw with a partial diagnostic and no wrapped address");
        bad = data;
        put(bad, symbols_at + 4, 5, 1, false);
        auto unknown = take(load(bad));
        check(unknown.metadata.macho->symbols[0].state == MachOSymbolState::unknown && !unknown.metadata_complete,
              "unknown n_type stays inspectable without guessed definition semantics");
        bad = data;
        put(bad, symbols_at, 0, 4, false);
        bad[strings_at] = std::byte{'x'};
        auto zero = take(load(bad));
        check(zero.metadata.macho->symbols[0].name.empty(), "n_strx0 means empty independently of string-table byte0");
        bad = data;
        const auto section = (wide ? 32u : 28u) + (wide ? 72u : 56u) + 2 * (wide ? 80u : 68u);
        put(bad, section + (wide ? 64 : 56), 0x12, 4, false);
        auto tls = take(load(bad));
        check(!tls.metadata.macho->symbols[7].address && !tls.metadata.macho->symbols[7].code,
              "thread-local template symbol does not fabricate a process address");
    }
}
void fat_provenance() {
    auto inner = hexlab_test::macho_fixture::symbols(true);
    std::vector<std::byte> data(12288);
    put(data, 0, 0xcafebabe, 4, true);
    put(data, 4, 1, 4, true);
    put(data, 8, 0x01000007, 4, true);
    put(data, 12, 0x80000003, 4, true);
    put(data, 16, 4096, 4, true);
    put(data, 20, 4096, 4, true);
    put(data, 24, 12, 4, true);
    std::copy(inner.begin(), inner.end(), data.begin() + 4096);
    auto result = take(load(data));
    check(result.metadata.macho->symbols[0].record_file_offset == 4096 + symbols_at &&
              result.metadata.macho->symbol_tables[0].string_offset == FileOffset{4096 + strings_at},
          "universal symbol source positions are absolute outer-container coordinates");
    put(data, 4096 + symtab_command(true) + 8, 4090, 4, false);
    check(!load(data), "nlist table cannot cross slice boundary even when outer input has enough bytes");
}
} // namespace
int main() {
    return run([] {
        records();
        states_and_bounds();
        fat_provenance();
    });
}
