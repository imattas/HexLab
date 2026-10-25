#include "hexlab/loaders/elf.hpp"
#include "hexlab/analysis/functions.hpp"
#include "support/elf_dynamic_symbol_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include <iostream>
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::elf_dynamic_symbol_fixture;
namespace {
Result<LoadedImage> load(std::vector<std::byte> data) {
    return load_elf(std::make_shared<MemoryStorage>(std::move(data)), {});
}
void records() {
    for (bool wide : {false, true})
        for (bool big : {false, true})
            for (unsigned mode : {0u, 1u, 2u, 3u, 5u}) {
                auto result = load(fixture(wide, big, mode));
                check(bool(result), "bounded sectionless dynamic symbol table parsed");
                if (!result)
                    continue;
                const auto &elf = *result.value().metadata.elf;
                const auto address = wide ? UINT64_C(0x100000000) : UINT64_C(0x10000);
                check(elf.symbols.size() == 3 && elf.symbol_tables.size() == 1 &&
                          elf.symbol_tables[0].count == UINT64_C(3) && elf.symbol_tables[0].symbol_begin == UINT64_C(0),
                      "symbol count comes from explicit size/hash bounds without scanning adjacent data");
                if (elf.symbols.size() != 3)
                    continue;
                check(!elf.symbols[1].table && elf.symbols[1].table_offset == sym &&
                          elf.symbols[1].table_address == Address{{0}, address + sym} &&
                          elf.symbols[1].name == "defined" && elf.symbols[1].address == Address{{0}, address + 256},
                      "sectionless symbols retain real source and virtual identity without fake section0");
                check(elf.symbols[2].state == ElfSymbolState::undefined && !elf.symbols[2].address &&
                          elf.symbols[2].name == "external",
                      "undefined dynamic symbol stays unresolved");
                check(elf.dynamic_tables[0].symbol_table && !elf.dynamic_tables[0].symbol_table->section &&
                          elf.dynamic_complete && result.value().metadata_complete == !big,
                      "dynamic array binds its actual parsed symbol table");
                check(result.value().metadata_reads.intersects({sym}, 3 * (wide ? 24 : 16)).value(),
                      "dynamic symbol payload enters dependencies");
                if (!big)
                    check(recover_functions(*result.value().image, result.value().metadata, {}, {}, {})
                                  .value()
                                  ->functions.size() == 1,
                          "stripped dynamic FUNC definition seeds actual recovery");
            }
}
void unavailable_and_aliases() {
    for (bool wide : {false, true}) {
        auto result = load(fixture(wide, false, 4));
        check(result && result.value().metadata.elf->symbol_tables.size() == 1 &&
                  !result.value().metadata.elf->symbol_tables[0].count &&
                  !result.value().metadata.elf->symbol_tables[0].symbol_begin &&
                  result.value().metadata.elf->symbols.empty() && !result.value().metadata.elf->dynamic_complete,
              "missing symbol bounds remain explicitly unavailable instead of inventing a count");
        if (result)
            check(!result.value().metadata_reads.intersects({sym}, 1).value(),
                  "unbounded symbol table is never scanned");
        result = load(fixture(wide, false, 5, true));
        check(result && result.value().metadata.elf->symbols.size() == 3 &&
                  result.value().metadata.elf->symbol_tables.size() == 1 &&
                  result.value().metadata.elf->dynamic_tables[0].symbol_table->section == 1u,
              "matching section and dynamic symbol descriptions share one authoritative table");
        auto bad = fixture(wide, false, 5, true);
        const auto address = wide ? UINT64_C(0x100000000) : UINT64_C(0x10000);
        std::copy_n(bad.begin() + str, 18, bad.begin() + 1100);
        bad[1101] = std::byte{'X'};
        tag(bad, wide, false, 0, 5, address + 1100);
        check(!load(bad), "conflicting SHT and DT symbol-name provenance rejects silent selection");
    }
}
void gnu_symbol_versions() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            auto data = fixture(wide, big, 5, true);
            constexpr std::string_view more_names("VER_1\0GLIBC_2.0\0libc.so.6\0", 26);
            constexpr std::size_t names_at = str + 18;
            for (std::size_t i = 0; i < more_names.size(); ++i)
                data[names_at + i] = std::byte(more_names[i]);
            const auto strings_size = 18 + more_names.size();
            const auto address = wide ? UINT64_C(0x100000000) : UINT64_C(0x10000);
            tag(data, wide, big, 1, 10, strings_size);
            std::vector<std::byte> headers(data.begin() + 6144, data.end());
            headers.insert(headers.begin(), 512, std::byte{});
            section(headers, wide, 2, 0, 3, 2, address + str, str, strings_size, 1, big);
            section(headers, wide, 4, 0, 0x6fffffff, 0, 0, 5000, 6, 2, big);
            links(headers, wide, big, 4, 1, 0, 2);
            section(headers, wide, 5, 0, 0x6ffffffd, 0, 0, 5020, 28, 4, big);
            links(headers, wide, big, 5, 2, 0, 0);
            section(headers, wide, 6, 0, 0x6ffffffe, 0, 0, 5050, 32, 4, big);
            links(headers, wide, big, 6, 2, 0, 0);
            std::copy(headers.begin() + 512, headers.end(), data.begin() + 6144);
            const auto stride = wide ? 24u : 16u;
            put(data, 5000, 0, 2, big);
            put(data, 5002, 2, 2, big);
            put(data, 5004, 0x8003, 2, big);
            // Elf_Verdef and its single Verdaux name.
            put(data, 5020, 1, 2, big);
            put(data, 5024, 2, 2, big);
            put(data, 5026, 1, 2, big);
            put(data, 5032, 20, 4, big);
            put(data, 5040, 18, 4, big);
            // Elf_Verneed and one Vernaux requirement.
            put(data, 5050, 1, 2, big);
            put(data, 5052, 1, 2, big);
            put(data, 5054, 34, 4, big);
            put(data, 5058, 16, 4, big);
            put(data, 5072, 3, 2, big);
            put(data, 5074, 24, 4, big);
            check(stride != 0, "symbol record stride is nonzero");
            const auto result = load(std::move(data));
            if (!result)
                std::cerr << "GNU symbol versions wide=" << wide << " big=" << big << ": "
                          << result.error().message << '\n';
            check(bool(result), "GNU symbol version sections parse for ELF32/64 and byte order");
            if (!result)
                continue;
            const auto &symbols = result.value().metadata.elf->symbols;
            check(symbols.size() == 3 && symbols[0].version_index == 0 && symbols[1].version_index == 2 &&
                      symbols[1].version_name == "VER_1" && symbols[2].version_index == 3 &&
                      symbols[2].version_hidden && symbols[2].version_name == "GLIBC_2.0" &&
                      symbols[2].version_file == "libc.so.6" && symbols[1].name == "defined",
                  "GNU version index resolves definition and imported requirement without rewriting symbol names");
        }
}
void malformed() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            auto data = fixture(wide, big, 1);
            auto bad = data;
            put(bad, sysv + 4, 1000001, 4, big);
            auto limited = load(bad);
            check(!limited && limited.error().code == ErrorCode::resource_limit,
                  "SysV hash count limit before allocation");
            bad = data;
            put(bad, sysv + 8, 99, 4, big);
            check(!load(bad), "SysV bucket index bounded");
            bad = data;
            put(bad, sysv + 20, 1, 4, big);
            check(!load(bad), "cyclic SysV chains cannot claim valid count metadata");
            data = fixture(wide, big, 2);
            bad = data;
            put(bad, gnu + 8, 0, 4, big);
            check(!load(bad), "GNU bloom size cannot be zero");
            bad = data;
            put(bad, gnu + 8, 3, 4, big);
            check(!load(bad), "GNU bloom mask uses a power-of-two word count");
            bad = data;
            const auto buckets = gnu + 16 + (wide ? 8 : 4);
            put(bad, buckets, 1000001, 4, big);
            check(!load(bad), "GNU bucket symbol bound checked");
            bad = data;
            put(bad, buckets + 8, 0xdcf33928, 4, big);
            check(!load(bad), "unterminated GNU chain stops at actual initialized extent");
            data = fixture(wide, big, 3);
            bad = data;
            put(bad, sysv + 4, 4, 4, big);
            check(!load(bad), "independent hash counts must agree");
            data = fixture(wide, big, 0);
            bad = data;
            tag(bad, wide, big, 3, 11, 0);
            check(!load(bad), "dynamic symbol stride cannot be zero");
            bad = data;
            tag(bad, wide, big, 4, 39, (wide ? 24 : 16) * UINT64_C(1000001));
            limited = load(bad);
            check(!limited && limited.error().code == ErrorCode::resource_limit, "explicit symbol-size count bounded");
            bad = data;
            put(bad, sym + (wide ? 24 : 16), 999, 4, big);
            check(!load(bad), "dynamic symbol name offset bounded");
            bad = data;
            put(bad, sym, 1, 4, big);
            check(!load(bad), "dynamic first symbol must be the literal null record");
            bad = data;
            const auto address = wide ? UINT64_C(0x100000000) : UINT64_C(0x10000);
            tag(bad, wide, big, 2, 6, address + 8192);
            check(!load(bad), "dynamic symbol pointer cannot name unmapped memory");
            bad = data;
            program(bad, wide, 1, 2, dynamic_at, address + dynamic_at, 6 * (wide ? 16 : 8), wide ? 16 : 8, 6, 1, big);
            check(!load(bad), "dynamic file payload cannot exceed its declared memory extent");
        }
}
void alias_semantics() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            const auto address = wide ? UINT64_C(0x100000000) : UINT64_C(0x10000);
            const auto word = wide ? 8u : 4u;
            auto data = fixture(wide, big);
            std::copy_n(data.begin() + dynamic_at, 12 * word, data.begin() + 2800);
            program(data, wide, 2, 2, 2800, address + 2800, 12 * word, 12 * word, 6, word, big);
            auto result = load(data);
            check(result && result.value().metadata.elf->dynamic_tables.size() == 2 &&
                      result.value().metadata.elf->symbol_tables.size() == 1 &&
                      result.value().metadata.elf->symbols.size() == 3,
                  "separate dynamic arrays can share one consistent symbol interpretation");
            std::copy_n(data.begin() + str, 18, data.begin() + 3200);
            put(data, 2800 + word, address + 3200, word, big);
            data[3201] = std::byte{'X'};
            check(!load(data), "sectionless symbol aliases cannot silently select conflicting names");
            data = fixture(wide, big, 0, true);
            tag(data, wide, big, 5, 34, address + indices);
            tag(data, wide, big, 6, 0, 0);
            program(data, wide, 1, 2, dynamic_at, address + dynamic_at, 14 * word, 14 * word, 6, word, big);
            put(data, 6144 + 3 * (wide ? 64 : 40) + (wide ? 32 : 20), 14 * word, word, big);
            check(bool(load(data)), "matching section symbols accept zero unused dynamic SHNDX entries");
            put(data, indices + 4, 12, 4, big);
            check(!load(data),
                  "section alias must validate dynamic SHNDX instead of ignoring conflicting companion bytes");
        }
}
void split_and_stride() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            const auto address = wide ? UINT64_C(0x100000000) : UINT64_C(0x10000);
            const auto stride = (wide ? 24u : 16u) + 8;
            auto result = load(fixture(wide, big, 0, false, stride));
            check(result && result.value().metadata.elf->symbols.size() == 3 &&
                      result.value().metadata.elf->symbol_tables[0].stride == stride,
                  "declared symbol stride preserves padding without treating it as another record");
            auto data = fixture(wide, big);
            const auto extent = 3 * (wide ? 24u : 16u);
            std::copy_n(data.begin() + sym + 20, extent - 20, data.begin() + 6000);
            program(data, wide, 0, 1, 0, address, sym + 20, sym + 20, 5, 1, big);
            program(data, wide, 2, 1, 6000, address + sym + 20, extent - 20, extent - 20, 4, 1, big);
            result = load(data);
            check(result && result.value().metadata.elf->symbols.size() == 3 &&
                      result.value().metadata.elf->symbols[1].name == "defined",
                  "dynamic symbol records assemble across discontiguous initialized backing");
            if (result)
                check(result.value().metadata_reads.intersects({6000}, extent - 20).value() &&
                          !result.value().metadata_reads.intersects({sym + 20}, extent - 20).value(),
                      "split symbol dependencies use the canonical backing spans");
        }
}
void declared_padding_extent() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            const auto address = wide ? UINT64_C(0x100000000) : UINT64_C(0x10000);
            const auto minimum = wide ? 24u : 16u;
            const auto stride = minimum + 8;
            const auto end_fields = sym + 2 * stride + minimum;
            const auto original = fixture(wide, big, 0, false, stride);
            for (bool zero_fill : {false, true}) {
                auto data = original;
                program(data, wide, 0, 1, 0, address, end_fields, end_fields + (zero_fill ? 8 : 0), 5, 1, big);
                check(!load(data),
                      "entire declared dynamic symbol table, including final record padding, must be initialized");
            }
            auto data = original;
            std::copy_n(data.begin() + end_fields, 8, data.begin() + 6000);
            program(data, wide, 0, 1, 0, address, end_fields, end_fields, 5, 1, big);
            program(data, wide, 2, 1, 6000, address + end_fields, 8, 8, 4, 1, big);
            const auto result = load(data);
            check(result && result.value().metadata.elf->symbols.size() == 3,
                  "declared symbol padding may use discontiguous canonical initialized backing");
            if (result)
                check(!result.value().metadata_reads.intersects({6000}, 8).value(),
                      "uninterpreted padding is range-validated without inventing field reads or dependencies");
        }
}
class CancelStorage final : public ByteStorage {
    MemoryStorage source_{fixture(true, false, 5)};
    std::stop_source &stop_;
    std::uint64_t position_;

  public:
    CancelStorage(std::stop_source &stop, std::uint64_t position) : stop_(stop), position_(position) {}
    std::uint64_t size() const noexcept override { return source_.size(); }
    Result<ByteView> read_at(FileOffset at, std::size_t n) const override {
        if (at.value == position_)
            stop_.request_stop();
        return source_.read_at(at, n);
    }
};
void cancellation_and_indices() {
    for (auto position : {sysv + 8, gnu + 16, sym + 24}) {
        std::stop_source stop;
        auto storage = std::make_shared<CancelStorage>(stop, position);
        const auto result = load_elf(storage, stop.get_token());
        check(!result && result.error().code == ErrorCode::canceled,
              "canceling hash/symbol reads publishes no partial metadata");
        check(bool(load_elf(storage, {})), "dynamic symbol import retries cleanly after cancellation");
    }
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            const auto address = wide ? UINT64_C(0x100000000) : UINT64_C(0x10000);
            const auto word = wide ? 8u : 4u;
            auto data = fixture(wide, big);
            tag(data, wide, big, 5, 34, address + indices);
            tag(data, wide, big, 6, 0, 0);
            program(data, wide, 1, 2, dynamic_at, address + dynamic_at, 14 * word, 14 * word, 6, word, big);
            put(data, sym + (wide ? 24 : 16) + (wide ? 6 : 14), 0xffff, 2, big);
            put(data, indices + 4, 12, 4, big);
            auto result = load(data);
            check(result && result.value().metadata.elf->symbols[1].raw_section == 0xffff &&
                      result.value().metadata.elf->symbols[1].section_index == 12 &&
                      result.value().metadata.elf->symbols[1].address == Address{{0}, address + 256},
                  "sectionless SHNDX retains extended section identity while resolving a declared mapped value");
            data = fixture(wide, big, 2);
            const auto buckets = gnu + 16 + word;
            put(data, buckets, 0, 4, big);
            result = load(data);
            check(result && result.value().metadata.elf->symbol_tables[0].count == UINT64_C(1) &&
                      result.value().metadata.elf->symbols.size() == 1,
                  "empty GNU buckets bound only the declared unhashed symbol prefix without scanning chains");
        }
}
} // namespace
int main() {
    return run([] {
        records();
        gnu_symbol_versions();
        unavailable_and_aliases();
        malformed();
        alias_semantics();
        split_and_stride();
        declared_padding_extent();
        cancellation_and_indices();
    });
}
