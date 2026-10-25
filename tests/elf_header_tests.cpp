#include "hexlab/loaders/elf.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include <algorithm>
#include <limits>
using namespace hexlab;
using namespace hexlab_test;
namespace {
void put(std::vector<std::byte> &data, std::size_t at, std::uint64_t value, std::size_t width, bool big = false) {
    for (std::size_t i = 0; i < width; ++i)
        data.at(at + i) = std::byte(value >> (8 * (big ? width - i - 1 : i)));
}
std::vector<std::byte> header(bool wide, bool big = false) {
    std::vector<std::byte> data(wide ? 64 : 52);
    data[0] = std::byte{0x7f};
    data[1] = std::byte{'E'};
    data[2] = std::byte{'L'};
    data[3] = std::byte{'F'};
    data[4] = std::byte(wide ? 2 : 1);
    data[5] = std::byte(big ? 2 : 1);
    data[6] = std::byte{1};
    data[7] = std::byte{3};
    data[8] = std::byte{0};
    data[15] = std::byte{0xa5};
    put(data, 16, 2, 2, big);
    put(data, 18, wide ? 62 : 3, 2, big);
    put(data, 20, 1, 4, big);
    put(data, 24, wide ? UINT64_C(0x123456789abcdef0) : 0x12345678, wide ? 8 : 4, big);
    put(data, wide ? 48 : 36, 0x89abcdef, 4, big);
    put(data, wide ? 52 : 40, wide ? 64 : 52, 2, big);
    return data;
}
Result<ElfHeader> parse(const std::vector<std::byte> &data) { return read_elf_header(MemoryStorage(data), {}); }
void basic() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            auto data = header(wide, big);
            auto value = parse(data);
            check(bool(value), "literal32/64 LE/BE ELF header accepts reserved padding");
            if (!value)
                continue;
            const auto &h = value.value();
            check(h.is_64 == wide && h.order == (big ? ByteOrder::big : ByteOrder::little) && h.object_type == 2 &&
                      h.machine == (wide ? 62 : 3) && h.version == 1 && h.flags == 0x89abcdef && h.os_abi == 3 &&
                      h.abi_version == 0,
                  "literal fields use declared endian and class rather than host ABI");
            check(h.entry == (wide ? UINT64_C(0x123456789abcdef0) : 0x12345678) && h.programs.count == 0 &&
                      h.sections.count == 0 && h.section_names == 0,
                  "64-bit entry preserved and absent tables distinct");
            for (std::size_t n = 0; n < data.size(); ++n)
                check(!parse(std::vector<std::byte>(data.begin(), data.begin() + n)),
                      "every fixed-header truncation fails");
            for (const auto [at, width] :
                 {std::pair<std::size_t, std::size_t>{16, 2}, {20, 4}, {wide ? 52u : 40u, 2}}) {
                auto bad = data;
                put(bad, at, 0, width, big);
                check(!parse(bad), "invalid type/version/header size rejected");
            }
            for (auto at : {0u, 1u, 2u, 3u, 4u, 5u, 6u}) {
                auto bad = data;
                bad[at] = std::byte{0};
                check(!parse(bad), "invalid magic/class/endian/ident version rejected");
            }
            auto unknown = data;
            put(unknown, 18, 0xbeef, 2, big);
            check(parse(unknown).value().machine == 0xbeef,
                  "unknown machine is retained without fabricated decoder context");
            for (auto type : {1u, 2u, 3u}) {
                auto valid = data;
                put(valid, 16, type, 2, big);
                check(parse(valid).value().object_type == type, "REL EXEC and DYN types retained distinctly");
            }
            for (auto at : {4u, 5u, 6u}) {
                auto bad = data;
                bad[at] = std::byte{3};
                check(!parse(bad), "unknown identification variant rejected");
            }
            auto bad = data;
            put(bad, wide ? 62 : 50, 1, 2, big);
            check(!parse(bad), "absent section table cannot own a names index");
        }
}
void tables() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            const std::size_t phoff = wide ? 32 : 28, shoff = wide ? 40 : 32, fields = wide ? 54 : 42;
            auto data = header(wide, big);
            data.resize(1024);
            put(data, phoff, 128, wide ? 8 : 4, big);
            put(data, fields, wide ? 64 : 40, 2, big);
            put(data, fields + 2, 2, 2, big);
            put(data, shoff, 512, wide ? 8 : 4, big);
            put(data, fields + 4, wide ? 80 : 48, 2, big);
            put(data, fields + 6, 3, 2, big);
            put(data, fields + 8, 2, 2, big);
            auto value = parse(data);
            check(bool(value), "larger record strides accepted with bounded table extents");
            if (value)
                check(value.value().programs == ElfTable{128, wide ? 64u : 40u, 2} &&
                          value.value().sections == ElfTable{512, wide ? 80u : 48u, 3} &&
                          value.value().section_names == 2,
                      "normalized table descriptors retain file offsets and stride/count");
            auto bad = data;
            put(bad, fields, wide ? 55 : 31, 2, big);
            check(!parse(bad), "short program stride rejected");
            bad = data;
            put(bad, fields + 4, wide ? 63 : 39, 2, big);
            check(!parse(bad), "short section stride rejected");
            bad = data;
            put(bad, fields + 8, 3, 2, big);
            check(!parse(bad), "section-name index must identify actual section");
            bad = data;
            put(bad, phoff, 1000, wide ? 8 : 4, big);
            check(!parse(bad), "program table cannot exceed source");
            bad = data;
            put(bad, shoff, 1000, wide ? 8 : 4, big);
            check(!parse(bad), "section table cannot exceed source");
            bad = data;
            put(bad, shoff, 0, wide ? 8 : 4, big);
            check(!parse(bad), "nonzero count without section offset rejected");
            bad = data;
            put(bad, phoff, 0, wide ? 8 : 4, big);
            check(!parse(bad), "nonzero count without program offset rejected");
            // Extended counts come from the null section, not from interpreting header0 as an absent table.
            put(data, fields + 2, 0xffff, 2, big);
            put(data, fields + 6, 0, 2, big);
            put(data, fields + 8, 0xffff, 2, big);
            put(data, 512 + (wide ? 32 : 20), 3, wide ? 8 : 4, big);
            put(data, 512 + (wide ? 40 : 24), 2, 4, big);
            put(data, 512 + (wide ? 44 : 28), 2, 4, big);
            value = parse(data);
            check(value && value.value().sections.count == 3 && value.value().programs.count == 2 &&
                      value.value().section_names == 2,
                  "all three extended header fields use class-specific null-section carriers");
            bad = data;
            put(bad, 516, 1, 4, big);
            check(!parse(bad), "extended carrier must be SHT_NULL");
            bad = data;
            put(bad, 512 + (wide ? 32 : 20), 0, wide ? 8 : 4, big);
            check(!parse(bad), "extended section count cannot be zero");
            bad = data;
            put(bad, 512 + (wide ? 32 : 20), 1048577, wide ? 8 : 4, big);
            auto limited = parse(bad);
            check(!limited && limited.error().code == ErrorCode::resource_limit,
                  "section count limit before allocation");
            bad = data;
            put(bad, 512 + (wide ? 44 : 28), 65537, 4, big);
            limited = parse(bad);
            check(!limited && limited.error().code == ErrorCode::resource_limit,
                  "program count limit before allocation");
            bad = data;
            put(bad, shoff, 0, wide ? 8 : 4, big);
            check(!parse(bad), "extended fields cannot use absent section0");
            bad = data;
            bad.resize(512 + (wide ? 63 : 39));
            check(!parse(bad), "truncated extended-count carrier rejected");
            if (wide) {
                bad = data;
                put(bad, shoff, UINT64_MAX - 16, 8, big);
                check(!parse(bad), "carrier file offset overflow fails");
            }
        }
}
class Probe final : public ByteStorage {
  public:
    mutable std::size_t reads = 0, largest = 0;
    std::stop_source *cancel = nullptr;
    bool short_view = false, io_failure = false;
    std::uint64_t extent = UINT64_MAX;
    std::vector<std::byte> data = header(true);
    std::uint64_t size() const noexcept override { return extent; }
    Result<ByteView> read_at(FileOffset at, std::size_t n) const override {
        ++reads;
        largest = std::max(largest, n);
        if (cancel)
            cancel->request_stop();
        if (io_failure)
            return Error{ErrorCode::io, "authored storage read failure"};
        if (short_view && n)
            --n;
        return MemoryStorage(data).read_at(at, n);
    }
};
void bounds() {
    Probe source;
    check(bool(read_elf_header(source, {})) && source.largest <= 64, "huge source never causes complete-file read");
    source.reads = 0;
    std::stop_source stop;
    stop.request_stop();
    auto value = read_elf_header(source, stop.get_token());
    check(!value && value.error().code == ErrorCode::canceled && source.reads == 0,
          "pre-canceled parse performs no I/O");
    put(source.data, 32, 128, 8);
    put(source.data, 54, 65535, 2);
    put(source.data, 56, 65534, 2);
    value = read_elf_header(source, {});
    check(!value && value.error().code == ErrorCode::resource_limit, "metadata extent budget before table-sized reads");
    source.data = header(true);
    put(source.data, 32, UINT64_MAX - 20, 8);
    put(source.data, 54, 56, 2);
    put(source.data, 56, 2, 2);
    check(!read_elf_header(source, {}), "overflowing table offset plus extent rejected on sparse storage");
    source.data = header(true);
    put(source.data, 32, 128, 8);
    put(source.data, 54, 600, 2);
    put(source.data, 56, 60000, 2);
    put(source.data, 40, UINT64_C(0x100000000), 8);
    put(source.data, 58, 600, 2);
    put(source.data, 60, 60000, 2);
    value = read_elf_header(source, {});
    check(!value && value.error().code == ErrorCode::resource_limit,
          "combined table extents obey one64MiB metadata budget");
    source.data = header(true);
    source.short_view = true;
    check(!read_elf_header(source, {}), "incomplete storage views rejected before integer access");
    source.short_view = false;
    source.io_failure = true;
    value = read_elf_header(source, {});
    check(!value && value.error().code == ErrorCode::io, "storage I/O error propagated without pretending valid input");
    source.io_failure = false;
    std::stop_source during;
    source.cancel = &during;
    value = read_elf_header(source, during.get_token());
    check(!value && value.error().code == ErrorCode::canceled, "cancellation arriving during storage read is observed");
}
} // namespace
int main() {
    return run([] {
        basic();
        tables();
        bounds();
    });
}
