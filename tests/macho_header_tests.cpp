#include "hexlab/loaders/macho.hpp"
#include "support/macho_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include <algorithm>
#include <tuple>
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::macho_fixture;
namespace {
Result<MachOContainer> inspect(std::vector<std::byte> data) {
    MemoryStorage source(std::move(data));
    return read_macho_container(source, {});
}
void thin_headers() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            const auto data = thin(wide, big);
            auto parsed = inspect(data);
            check(bool(parsed), "literal Mach-O32/64 LE/BE fixed headers and envelopes parse");
            if (!parsed)
                continue;
            const auto &container = parsed.value();
            check(!container.universal && container.slices.size() == 1, "thin input has one original whole-file slice");
            const auto &slice = container.slices[0];
            const auto &header = slice.header;
            check(slice.index == 0 && slice.offset == 0 && slice.size == data.size() && header.is_64 == wide &&
                      header.order == (big ? ByteOrder::big : ByteOrder::little),
                  "thin class/order/outer source extent remain exact");
            check(header.cpu_type == (wide ? 0x01000007u : 7u) && header.cpu_subtype == 0x80000003 &&
                      header.file_type == 1 && header.flags == 0x80002000 &&
                      header.reserved == 0,
                  "full32-bit CPU/subtype/type/flags values parse with a zero reserved field");
            check(header.command_count == 2 && header.command_bytes == 24 && header.commands.size() == 2 &&
                      header.commands[0].index == 0 && header.commands[0].command == 0x70000001 &&
                      header.commands[0].size == 8 && header.commands[0].file_offset == (wide ? 32u : 28u) &&
                      header.commands[1].file_offset == (wide ? 40u : 36u) && header.commands[1].size == 16,
                  "unknown command descriptors preserve raw command and absolute record offsets");
            auto empty = data;
            empty.resize(wide ? 32 : 28);
            put(empty, 16, 0, 4, big);
            put(empty, 20, 0, 4, big);
            check(bool(inspect(empty)), "empty load-command sequence is bounded and accepted");
        }
}
void universal_headers() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            auto parsed = inspect(universal(wide, big));
            check(bool(parsed), "literal FAT32/64 native/swapped containers parse");
            if (!parsed)
                continue;
            const auto &container = parsed.value();
            check(container.universal && container.fat_64 == wide &&
                      container.order == (big ? ByteOrder::big : ByteOrder::little) && container.slices.size() == 2,
                  "universal table class/order/count remain independent of inner headers");
            check(container.slices[0].offset == 256 && container.slices[1].offset == 512 &&
                      !container.slices[0].header.is_64 && container.slices[1].header.is_64 &&
                      container.slices[1].header.order == ByteOrder::big && container.slices[1].index == 1 &&
                      container.slices[1].header.commands[0].file_offset == 544 && container.slices[1].alignment == 8 &&
                      container.slices[1].reserved == 0,
                  "each slice has independent header context and outer-container command coordinates");
            if (wide) {
                auto bad = universal(wide, big);
                put(bad, 8 + 28, 1, 4, big);
                check(!inspect(bad), "nonzero FAT64 architecture reserved field is rejected");
            }
        }
}
void malformed() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            const auto data = thin(wide, big);
            for (std::size_t count = 0; count < data.size(); ++count)
                check(!inspect(std::vector<std::byte>(data.begin(), data.begin() + count)),
                      "every thin header/command truncation fails");
            const auto header = wide ? 32u : 28u;
            if (wide) {
                auto bad = data;
                put(bad, 28, 1, 4, big);
                const auto compatible = inspect(bad);
                check(compatible && compatible.value().slices[0].header.reserved == 1,
                      "nonzero Mach-O64 header reserved word is retained for historical-file compatibility");
            }
            for (auto [at, value] : {std::pair{0u, 0u},
                                     {16u, 65537u},
                                     {20u, 0xffffffffu},
                                     {header + 4, 0u},
                                     {header + 4, 4u},
                                     {header + 4, 10u},
                                     {header + 4, 32u},
                                     {16u, 1u},
                                     {16u, 3u}}) {
                auto bad = data;
                put(bad, at, value, 4, big);
                check(!inspect(bad), "invalid magic/count/extent/size/alignment/command accounting fails");
            }
            const auto fat = universal(wide, big);
            const auto stride = wide ? 32u : 20u;
            for (auto [at, value, width] : std::vector<std::tuple<std::size_t, std::uint64_t, std::size_t>>{
                     {4, 0, 4},
                     {4, 4097, 4},
                     {8, 12, 4},
                     {16, 0, wide ? 8u : 4u},
                     {16, 257, wide ? 8u : 4u},
                     {16, UINT64_MAX, wide ? 8u : 4u},
                     {8 + stride + 8, 256, wide ? 8u : 4u},
                     {8 + (wide ? 24u : 16u), 64, 4},
                     {8 + (wide ? 16u : 12u), 30, wide ? 8u : 4u}}) {
                auto bad = fat;
                put(bad, at, value, width, big);
                check(!inspect(bad), "universal count/CPU/offset/alignment/overlap/slice-contained envelope checked");
            }
            auto nested = fat;
            std::copy_n(fat.begin(), 8, nested.begin() + 256);
            check(!inspect(nested), "nested universal member cannot be treated as a thin slice");
            for (std::size_t count = 0; count < 8 + 2 * stride; ++count)
                check(!inspect(std::vector<std::byte>(fat.begin(), fat.begin() + count)),
                      "universal descriptor truncation fails before inner reads");
        }
}
class SparseStorage final : public ByteStorage {
  public:
    std::uint64_t extent;
    std::vector<std::pair<std::uint64_t, std::shared_ptr<const std::vector<std::byte>>>> parts;
    mutable std::size_t calls = 0, maximum = 0;
    std::stop_source *cancel = nullptr;
    bool short_read = false;
    explicit SparseStorage(std::uint64_t size) : extent(size) {}
    std::uint64_t size() const noexcept override { return extent; }
    Result<ByteView> read_at(FileOffset at, std::size_t count) const override {
        ++calls;
        maximum = std::max(maximum, count);
        if (cancel && calls == 2)
            cancel->request_stop();
        for (const auto &[offset, bytes] : parts)
            if (at.value >= offset && at.value - offset <= bytes->size() &&
                count <= bytes->size() - (at.value - offset))
                return ByteView{bytes, std::span(*bytes).subspan(static_cast<std::size_t>(at.value - offset),
                                                                 count - (short_read && count ? 1 : 0))};
        return Error{ErrorCode::out_of_bounds, "Unexpected sparse fixture read"};
    }
};
void sparse_and_cancellation() {
    constexpr auto offset = UINT64_C(0x100000100);
    auto header = thin(true, false);
    std::vector<std::byte> fat(40);
    put(fat, 0, 0xcafebabf, 4, true);
    put(fat, 4, 1, 4, true);
    put(fat, 8, 0x01000007, 4, true);
    put(fat, 12, 0x80000003, 4, true);
    put(fat, 16, offset, 8, true);
    put(fat, 24, header.size(), 8, true);
    put(fat, 32, 8, 4, true);
    SparseStorage source(offset + header.size());
    source.parts = {{0, std::make_shared<const std::vector<std::byte>>(fat)},
                    {offset, std::make_shared<const std::vector<std::byte>>(header)}};
    auto parsed = read_macho_container(source, {});
    check(parsed && parsed.value().slices[0].offset == offset &&
              parsed.value().slices[0].header.commands[0].file_offset == offset + 32 && source.maximum <= 32 &&
              source.calls < 20,
          "FAT64 offsets above4GiB read bounded records without materializing container or slice");
    std::stop_source stop;
    stop.request_stop();
    source.calls = 0;
    auto canceled = read_macho_container(source, stop.get_token());
    check(!canceled && canceled.error().code == ErrorCode::canceled && source.calls == 0,
          "pre-canceled parse performs no source reads");
    std::stop_source mid;
    source.cancel = &mid;
    canceled = read_macho_container(source, mid.get_token());
    check(!canceled && canceled.error().code == ErrorCode::canceled && source.calls == 2,
          "cancellation raised by storage read is observed before further records");
    source.cancel = nullptr;
    source.short_read = true;
    check(!read_macho_container(source, {}), "short successful storage views are rejected before scalar access");
}
} // namespace
int main() {
    return run([] {
        thin_headers();
        universal_headers();
        malformed();
        sparse_and_cancellation();
    });
}
