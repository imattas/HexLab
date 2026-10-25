#include "hexlab/loaders/macho.hpp"
#include "support/macho_dyld_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::macho_fixture;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
Result<LoadedImage> load(std::vector<std::byte> data) {
    return load_macho(std::make_shared<MemoryStorage>(std::move(data)), {}, {});
}
void basic() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            auto data = dyld(wide, big);
            stream(data, wide, big, 0, {0x11, 0x20, 0, 0x52, 0});
            stream(data, wide, big, 1, {0x11, 0x41, '_', 'e', 'x', 't', 0, 0x60, 0x7f, 0x70, 8, 0x90, 0});
            put(data, 776, UINT64_C(0x1122334455667788), wide ? 8 : 4, big);
            const auto loaded = take(load(data));
            const auto &m = *loaded.metadata.macho;
            check(m.dyld_streams.size() == 5 && m.dyld_fixups.size() == 3 && m.dyld_complete,
                  "original dyld_info declarations and repeated rebase/bind operations parsed");
            if (m.dyld_fixups.size() != 3)
                continue;
            const auto &bind = m.dyld_fixups[2];
            const auto base = wide ? UINT64_C(0x100000000) : UINT64_C(0x1000);
            check(
                m.dyld_fixups[0].segment_offset == 0 && m.dyld_fixups[1].segment_offset == (wide ? 8u : 4u) &&
                    bind.place == Address{{0}, base + 8} && bind.file_place == FileOffset{776} &&
                    bind.library_ordinal == 1 && bind.symbol == "_ext" && bind.symbol_flags == 1 && bind.addend == -1,
                "dyld state preserves pointer-width stepping, raw symbol/ordinal/addend and canonical field location");
            check(bind.encoded_value == (wide ? UINT64_C(0x1122334455667788) : UINT64_C(0x55667788)),
                  "original fixup field bits use target byte order without applying binding or rebasing");
            check(m.dyld_streams[1].offset == FileOffset{2700} && bind.stream == 1 && bind.record_file_offset == 2711 &&
                      loaded.metadata_reads.intersects({2700}, 13).value(),
                  "dyld source namespace and operation/stream absolute offsets bind metadata dependencies");
            auto bad = data;
            stream(bad, wide, big, 1, {0x12, 0x40, 'x', 0, 0x70, 0, 0x90, 0});
            check(!load(bad), "positive bind ordinal cannot exceed declared dependency list");
            bad = data;
            stream(bad, wide, big, 1, {0x11, 0x40, 'x', 0, 0x7f, 0, 0x90, 0});
            check(!load(bad), "bind segment ordinal stays within original segment command order");
            bad = data;
            stream(bad, wide, big, 0, {0x11, 0x20, 31, 0x51, 0});
            check(!load(bad), "rebase field cannot cross declared segment memory bounds");
            bad = data;
            stream(bad, wide, big, 1, {0x40, 'x', 0, 0x70, 0, 0x90, 0});
            check(!load(bad), "ordinary bind requires explicit ordinal state rather than guessing a host library");
            bad = data;
            stream(bad, wide, big, 0, {0x11, 0x20, 0, 0x51});
            check(!load(bad), "nonempty rebase stream must terminate rather than run into neighboring bytes");
        }
}
void malformed_and_partial() {
    auto data = dyld(true);
    stream(data, true, false, 1, {0x11, 0x40, 'x', 0, 0x70, 0x80});
    check(!load(data), "truncated ULEB does not escape stream bounds");
    stream(data, true, false, 1, {0x60, 0x80});
    check(!load(data), "truncated SLEB does not escape stream bounds");
    stream(data, true, false, 1, {0x40, 'x', 'x'});
    check(!load(data), "symbol string must terminate within its own stream");
    stream(data, true, false, 1, {0xd0, 1, 0xd1, 0});
    const auto loaded = take(load(data));
    check(!loaded.metadata.macho->dyld_complete && !loaded.metadata_complete &&
              loaded.metadata.macho->dyld_streams[1].offset == FileOffset{2700},
          "unimplemented threaded binds preserve bounded declaration and explicit partial state");
    stream(data, true, false, 0, {0x60, 0x80, 0x80, 0x80, 0x01, 0});
    const auto huge = load(data);
    check(!huge && huge.error().code == ErrorCode::resource_limit,
          "repeat count budget is enforced before allocation or expansion");
    stream(data, true, false, 0, {0x30, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02});
    check(!load(data), "tenth ULEB payload cannot overflow64 bits");
    stream(data, true, false, 0, {0});
    stream(data, true, false, 1, {0x60, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01});
    check(!load(data), "tenth SLEB payload cannot represent a value outside signed64 range");
}
void weak_lazy_and_steps() {
    for (bool wide : {false, true}) {
        auto data = dyld(wide);
        put(data, (wide ? 32u : 28u) + (wide ? 32u : 28u), 128, wide ? 8 : 4, false);
        stream(data, wide, false, 0, {0x11, 0x20, 0, 0x30, 0, 0x41, 0x51, 0x60, 1, 0x70, 0, 0x80, 1, 0, 0});
        stream(data, wide, false, 1,
               {0x20, 1, 0x40, 'x', 0, 0x52, 0x60, 0x7e, 0x70, 0, 0x80, 0, 0x90, 0xa0, 0, 0xb0, 0xc0, 1, 0, 0});
        stream(data, wide, false, 2, {0x48, '_', 'w', 0, 0x70, 0, 0x90, 0});
        stream(data, wide, false, 3,
               {0x11, 0x41, 'a', 0, 0x60, 0x7f, 0x70, 0, 0x90, 0, 0x30, 0x40, 'b', 0, 0x70, 8, 0x90, 0});
        auto loaded = take(load(data));
        const auto &m = *loaded.metadata.macho;
        check(m.dyld_fixups.size() == 11 && m.dyld_complete,
              "all classic rebase/bind address-step opcodes expand bounded fixups");
        check(m.dyld_fixups[4].type == 2 && m.dyld_fixups[4].field_size == 4 &&
                  m.dyld_fixups[5].segment_offset == (wide ? 8u : 4u) && m.dyld_fixups[4].addend == -2,
              "ABS32 uses a4-byte field while opcode stepping follows pointer width");
        check(!m.dyld_fixups[8].library_ordinal && m.dyld_fixups[8].symbol_flags == 8 &&
                  m.dyld_streams[m.dyld_fixups[8].stream].kind == MachODyldStreamKind::weak_bind,
              "weak stream preserves its own namespace without inventing an explicit library ordinal");
        check(m.dyld_fixups[9].addend == -1 && m.dyld_fixups[10].addend == 0 && m.dyld_fixups[10].symbol_flags == 0 &&
                  m.dyld_fixups[10].library_ordinal == 0,
              "each lazy entry resets symbol flags/addend/ordinal state before independent decoding");
        auto bad = data;
        stream(bad, wide, false, 3, {0x11, 0x40, 'a', 0, 0x70, 0, 0x90, 0, 0x90, 0});
        check(!load(bad), "lazy entry cannot inherit preceding entry's segment/symbol/library state");
        data = dyld(wide);
        stream(data, wide, false, 0, {0x11, 0x20, 16, 0x51, 0});
        loaded = take(load(data));
        check(!loaded.metadata.macho->dyld_fixups[0].file_place &&
                  loaded.metadata.macho->dyld_fixups[0].encoded_value == 0,
              "zero-filled runtime slot preserves zero bits without phantom source backing");
    }
}
class InterruptedStorage final : public ByteStorage {
    MemoryStorage inner_;
    std::stop_source &stop_;

  public:
    mutable bool reached = false;
    InterruptedStorage(std::vector<std::byte> data, std::stop_source &stop) : inner_(std::move(data)), stop_(stop) {}
    std::uint64_t size() const noexcept override { return inner_.size(); }
    Result<ByteView> read_at(FileOffset at, std::size_t size) const override {
        auto view = inner_.read_at(at, size);
        if (at.value == 2700) {
            reached = true;
            stop_.request_stop();
        }
        return view;
    }
};
void slice_and_cancellation() {
    auto inner = dyld(true);
    stream(inner, true, false, 1, {0x11, 0x40, 'x', 0, 0x70, 8, 0x90, 0});
    std::stop_source stop;
    auto interrupted = std::make_shared<InterruptedStorage>(inner, stop);
    const auto stopped = load_macho(interrupted, {}, stop.get_token());
    check(interrupted->reached && !stopped && stopped.error().code == ErrorCode::canceled,
          "cancellation during actual dyld stream I/O cannot publish partial metadata");
    std::vector<std::byte> fat(12288);
    put(fat, 0, 0xcafebabe, 4, true);
    put(fat, 4, 1, 4, true);
    put(fat, 8, 0x01000007, 4, true);
    put(fat, 12, 0x80000003, 4, true);
    put(fat, 16, 4096, 4, true);
    put(fat, 20, 4096, 4, true);
    put(fat, 24, 12, 4, true);
    std::copy(inner.begin(), inner.end(), fat.begin() + 4096);
    const auto loaded = take(load(fat));
    check(loaded.metadata.macho->dyld_streams[1].offset == FileOffset{6796} &&
              loaded.metadata.macho->dyld_fixups[0].file_place == FileOffset{4872},
          "universal dyld stream/field coordinates are absolute outer-container offsets");
    put(fat, 4096 + dyld_command(true) + 16, 4090, 4, false);
    put(fat, 4096 + dyld_command(true) + 20, 16, 4, false);
    check(!load(fat), "dyld stream cannot escape selected slice despite available outer bytes");
}
void exports() {
    auto data = dyld(true);
    segment(data, true, false, 32, UINT64_C(0x100000000) - 768, 800, 0, 784, 7, 0, 3);
    stream(data, true, false, 4, {0, 2, '_', 'f', 0, 10, '_', 'a', 0, 15, 3, 0, 0x88, 0x06, 0, 2, 2, 42, 0});
    const auto loaded = take(load(data));
    const auto &m = *loaded.metadata.macho;
    check(m.dyld_exports.size() == 2 && m.dyld_complete,
          "bounded export trie produces declared names and terminal records");
    if (m.dyld_exports.size() == 2) {
        check(m.dyld_exports[0].name == "_f" && m.dyld_exports[0].address == Address{{0}, UINT64_C(0x100000008)} &&
                  m.dyld_exports[0].record_file_offset == 3010 && m.dyld_exports[0].stream == 4,
              "regular export offsets use mapped Mach-header anchor and retain node source namespace");
        check(m.dyld_exports[1].name == "_a" && m.dyld_exports[1].flags == 2 && m.dyld_exports[1].value == 42 &&
                  !m.dyld_exports[1].address,
              "absolute export scalar cannot fabricate an unmapped image address");
    }
    stream(data, true, false, 4, {0, 1, '_', 'r', 0, 6, 4, 8, 1, 'x', 0, 0});
    auto reexport = take(load(data));
    check(reexport.metadata.macho->dyld_exports[0].library_ordinal == 1 &&
              reexport.metadata.macho->dyld_exports[0].import_name == "x" &&
              !reexport.metadata.macho->dyld_exports[0].address,
          "reexport owns dependency ordinal/import name without resolving a host module");
    stream(data, true, false, 4, {0, 1, 'x', 0, 0});
    check(!load(data), "cyclic export trie cannot recurse indefinitely");
    stream(data, true, false, 4, {0, 1, 'x', 0, 99});
    check(!load(data), "child trie offset cannot escape its own payload");
    stream(data, true, false, 4, {100, 0, 0});
    check(!load(data), "export terminal extent stays within payload");
    stream(data, true, false, 4, {2, 0, 1});
    check(!load(data), "export terminal still requires its bounded child-count byte");
    stream(data, true, false, 4, {0, 2, '_', 'a', 0, 10, '_', 'b', 0, 10, 3, 0, 0x88, 0x06, 0});
    const auto shared = take(load(data));
    check(shared.metadata.macho->dyld_exports.size() == 2 && shared.metadata.macho->dyld_complete &&
              shared.metadata.macho->dyld_exports[0].name == "_a" &&
              shared.metadata.macho->dyld_exports[1].name == "_b" &&
              shared.metadata.macho->dyld_exports[0].record_file_offset ==
                  shared.metadata.macho->dyld_exports[1].record_file_offset,
          "shared trie suffix nodes preserve separate names without being misclassified as cycles");
    stream(data, true, false, 4, {0, 1, '_', 's', 0, 6, 5, 0x10, 0x88, 0x06, 0x80, 0x06, 0});
    const auto resolver = take(load(data));
    check(resolver.metadata.macho->dyld_exports[0].address == Address{{0}, UINT64_C(0x100000008)} &&
              resolver.metadata.macho->dyld_exports[0].resolver_address == Address{{0}, UINT64_C(0x100000000)},
          "stub and resolver offsets are distinct static declarations; resolver is never executed");
    stream(data, true, false, 4, {0, 1, 't', 0, 5, 2, 1, 42, 0});
    const auto tls = take(load(data));
    check(tls.metadata.macho->dyld_complete && tls.metadata.macho->dyld_exports[0].value == 42 &&
              !tls.metadata.macho->dyld_exports[0].address,
          "thread-local export offset is never a process address");
    stream(data, true, false, 4, {0, 1, 'u', 0, 5, 1, 0x20, 0});
    const auto unknown = take(load(data));
    check(!unknown.metadata.macho->dyld_complete && unknown.metadata.macho->dyld_exports[0].flags == 0x20 &&
              !unknown.metadata.macho->dyld_exports[0].address,
          "unknown export flags preserve raw source and explicit partial semantics");
}
void deep_trie_and_linkedit() {
    constexpr std::size_t nodes = 2048, payload = nodes * 8;
    auto data = dyld(true);
    data.resize(3000 + payload);
    put(data, dyld_command(true) + 40, 3000, 4, false);
    put(data, dyld_command(true) + 44, payload, 4, false);
    for (std::size_t i = 0; i + 1 < nodes; ++i) {
        const auto at = 3000 + i * 8;
        data[at] = std::byte{0};
        data[at + 1] = std::byte{1};
        data[at + 2] = std::byte{'x'};
        auto child = (i + 1) * 8;
        auto cursor = at + 4;
        do {
            data[cursor++] = std::byte((child & 0x7f) | (child > 0x7f ? 0x80 : 0));
            child >>= 7;
        } while (child);
    }
    const auto terminal = 3000 + (nodes - 1) * 8;
    data[terminal] = std::byte{2};
    data[terminal + 1] = std::byte{2};
    data[terminal + 2] = std::byte{42};
    const auto loaded = take(load(data));
    check(loaded.metadata.macho->dyld_exports.size() == 1 &&
              loaded.metadata.macho->dyld_exports[0].name == std::string(nodes - 1, 'x'),
          "deep export paths use bounded iterative traversal rather than native recursion");
    data[terminal] = std::byte{0};
    data[terminal + 1] = std::byte{1};
    data[terminal + 2] = std::byte{'x'};
    data[terminal + 3] = data[terminal + 4] = std::byte{0};
    check(!load(data), "deep cycle is rejected at its source offset without exhausting native stack");
    data = dyld(true);
    const auto command = append_command(data, true, false, 0x80000033, 16);
    put(data, command + 8, 3000, 4, false);
    put(data, command + 12, 2, 4, false);
    const auto empty = take(load(data));
    check(empty.metadata.macho->dyld_streams.size() == 6 && empty.metadata.macho->dyld_exports.empty() &&
              empty.metadata.macho->dyld_streams[5].complete,
          "standalone LC_DYLD_EXPORTS_TRIE uses the same bounded parser as dyld_info exports");
}
} // namespace
int main() {
    return run([] {
        basic();
        malformed_and_partial();
        weak_lazy_and_steps();
        slice_and_cancellation();
        exports();
        deep_trie_and_linkedit();
    });
}
