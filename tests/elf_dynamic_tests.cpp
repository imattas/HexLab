#include "hexlab/loaders/elf.hpp"
#include "support/elf_metadata_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::elf_metadata_fixture;
namespace {
constexpr std::size_t dynamic_at = 1536, strings = 1024, interpreter = 384;
void tag(std::vector<std::byte> &data, bool wide, bool big, std::size_t index, std::uint64_t type,
         std::uint64_t value) {
    const auto n = wide ? 8u : 4u;
    put(data, dynamic_at + index * 2 * n, type, n, big);
    put(data, dynamic_at + index * 2 * n + n, value, n, big);
}
std::vector<std::byte> fixture(bool wide, bool big = false, bool sections = false) {
    auto data = base(wide, big, 3);
    data.resize(4096);
    const auto address = wide ? UINT64_C(0x100000000) : UINT64_C(0x10000);
    program(data, wide, 0, 1, 0, address, 4096, 4096, 5, 4096, big);
    program(data, wide, 1, 2, dynamic_at, address + dynamic_at, 6 * (wide ? 16 : 8), 6 * (wide ? 16 : 8), 6,
            wide ? 8 : 4, big);
    program(data, wide, 2, 3, interpreter, address + interpreter, 16, 16, 4, 1, big);
    constexpr std::string_view path("/lib/ld-test.so\0", 16), names("\0liba.so\0libb.so\0self.so\0", 25);
    for (std::size_t i = 0; i < path.size(); ++i)
        data[interpreter + i] = std::byte(path[i]);
    for (std::size_t i = 0; i < names.size(); ++i)
        data[strings + i] = std::byte(names[i]);
    tag(data, wide, big, 0, 5, address + strings);
    tag(data, wide, big, 1, 10, names.size());
    tag(data, wide, big, 2, 1, 1);
    tag(data, wide, big, 3, 1, 9);
    tag(data, wide, big, 4, 14, 17);
    tag(data, wide, big, 5, 0, 0);
    if (sections) {
        section(data, wide, 0, 0, 0, 0, 0, 0, 0, 0, big);
        section(data, wide, 1, 0, 6, 3, address + dynamic_at, dynamic_at, 6 * (wide ? 16 : 8), wide ? 8 : 4, big);
        links(data, wide, big, 1, 2, 0, wide ? 16 : 8);
        section(data, wide, 2, 0, 3, 2, address + strings, strings, 25, 1, big);
    }
    return data;
}
Result<LoadedImage> load(std::vector<std::byte> data) {
    return load_elf(std::make_shared<MemoryStorage>(std::move(data)), {});
}
void records() {
    for (bool wide : {false, true})
        for (bool big : {false, true})
            for (bool sections : {false, true}) {
                const auto data = fixture(wide, big, sections);
                auto result = load(data);
                check(bool(result), "sectionless/section-backed ELF32/64 dynamic arrays parse in declared endian");
                if (!result)
                    continue;
                const auto &elf = *result.value().metadata.elf;
                check(elf.interpreter && elf.interpreter->program == 2 && elf.interpreter->file_offset == interpreter &&
                          elf.interpreter->path == "/lib/ld-test.so",
                      "interpreter is bounded metadata without host path loading");
                check(elf.dynamic_tables.size() == 1 && elf.dynamic_tables[0].entries.size() == 6,
                      "section/program aliases do not duplicate one dynamic array");
                const auto &table = elf.dynamic_tables[0];
                const auto address = wide ? UINT64_C(0x100000000) : UINT64_C(0x10000);
                check(table.source.file_offset == dynamic_at &&
                          table.source.address == Address{{0}, address + dynamic_at} &&
                          (sections ? table.source.section == 1u : !table.source.section) && table.program == 1u,
                      "dynamic table provenance uses actual optional section and declared virtual/file positions");
                check(table.entries[2].tag == 1 && table.entries[2].string_value == "liba.so" &&
                          table.entries[3].string_value == "libb.so" && table.entries[4].tag == 14 &&
                          table.entries[4].string_value == "self.so",
                      "needed libraries retain relative order and SONAME meaning");
                check(elf.dynamic_complete && result.value().metadata_complete == !big,
                      "known parsed metadata is complete while unsupported decoder stays explicit");
                check(result.value().metadata_reads.intersects({dynamic_at}, 6 * (wide ? 16 : 8)).value() &&
                          result.value().metadata_reads.intersects({strings}, 25).value() &&
                          result.value().metadata_reads.intersects({interpreter}, 16).value(),
                      "dynamic records strings and interpreter enter metadata dependencies");
                auto unknown = data;
                tag(unknown, wide, big, 4, UINT64_MAX, 123);
                auto partial = load(unknown);
                check(partial && !partial.value().metadata_complete &&
                          !partial.value().metadata.elf->dynamic_complete &&
                          partial.value().metadata.elf->dynamic_tables[0].entries[4].tag == -1,
                      "unknown signed tags remain raw explicit partial metadata");
            }
}
void malformed() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            const auto data = fixture(wide, big);
            const auto address = wide ? UINT64_C(0x100000000) : UINT64_C(0x10000);
            auto bad = data;
            tag(bad, wide, big, 5, 1, 1);
            check(!load(bad), "dynamic array requires NULL within declared extent");
            bad = data;
            tag(bad, wide, big, 2, 5, address + strings);
            check(!load(bad), "known singleton dynamic tag cannot repeat");
            bad = data;
            tag(bad, wide, big, 2, 1, 999);
            check(!load(bad), "needed library string offset bounded");
            bad = data;
            tag(bad, wide, big, 0, 5, address + 5000);
            check(!load(bad), "dynamic string pointer cannot use unmapped memory");
            bad = data;
            program(bad, wide, 0, 1, 0, address, 4096, 8192, 5, 4096, big);
            tag(bad, wide, big, 0, 5, address + 5000);
            check(!load(bad), "dynamic metadata cannot invent strings from BSS zero fill");
            bad = data;
            tag(bad, wide, big, 1, 21, 0);
            check(!load(bad), "needed strings require an explicit bounded string-table extent");
            bad = data;
            bad[strings] = std::byte{'x'};
            check(!load(bad), "dynamic strings start with empty string");
            bad = data;
            bad[strings + 24] = std::byte{'x'};
            check(!load(bad), "dynamic strings require terminator within their extent");
            bad = data;
            bad[interpreter + 15] = std::byte{'x'};
            check(!load(bad), "interpreter must terminate within declared bytes");
            bad = data;
            program(bad, wide, 1, 2, dynamic_at, address + dynamic_at, 6 * (wide ? 16 : 8) - 1, 6 * (wide ? 16 : 8), 6,
                    1, big);
            check(!load(bad), "dynamic array requires complete records");
            bad = data;
            program(bad, wide, 0, 1, 0, address, dynamic_at + 1, dynamic_at + 1, 5, 1, big);
            check(!load(bad), "entire dynamic program array must be in initialized load mappings");
            bad = data;
            program(bad, wide, 0, 1, 0, address, dynamic_at + 1, 4096, 5, 1, big);
            check(!load(bad), "dynamic program tail cannot be read from file bytes beyond initialized memory");
            bad = data;
            tag(bad, wide, big, 1, 10, wide ? UINT64_MAX : UINT32_MAX);
            auto limited = load(bad);
            check(!limited && limited.error().code == ErrorCode::resource_limit,
                  "dynamic string bound is checked before allocation");
        }
}
void split_strings() {
    auto data = fixture(true);
    constexpr auto address = UINT64_C(0x100000000);
    std::copy_n(data.begin() + strings + 8, 17, data.begin() + 2048);
    program(data, true, 0, 1, 0, address, 1032, 1032, 5, 1);
    program(data, true, 1, 1, 2048, address + 1032, 17, 17, 4, 1);
    program(data, true, 2, 1, dynamic_at, address + dynamic_at, 96, 96, 6, 1);
    program(data, true, 3, 2, dynamic_at, address + dynamic_at, 96, 96, 6, 1);
    program(data, true, 4, 3, interpreter, address + interpreter, 16, 16, 4, 1);
    auto result = load(data);
    check(result && result.value().metadata.elf->dynamic_tables[0].entries[3].string_value == "libb.so",
          "sectionless dynamic strings assemble across discontiguous file backing without flattening gaps");
    if (result)
        check(result.value().metadata_reads.intersects({2048}, 17).value() &&
                  !result.value().metadata_reads.intersects({1032}, 17).value(),
              "split string dependencies retain actual canonical file spans");
}
class CancelStorage final : public ByteStorage {
    MemoryStorage source_{fixture(true)};
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
void cancellation() {
    for (auto position : {std::uint64_t{dynamic_at + 32}, std::uint64_t{strings}}) {
        std::stop_source stop;
        auto storage = std::make_shared<CancelStorage>(stop, position);
        const auto result = load_elf(storage, stop.get_token());
        check(!result && result.error().code == ErrorCode::canceled,
              "cancellation during dynamic records/strings publishes no image");
        check(bool(load_elf(storage, {})), "canceled dynamic import can retry without retained partial state");
    }
}
} // namespace
int main() {
    return run([] {
        records();
        malformed();
        split_strings();
        cancellation();
    });
}
