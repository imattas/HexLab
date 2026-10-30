#include "hexlab/loaders/macho.hpp"
#include "support/macho_chained_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include <algorithm>
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
void generic() {
    for (const auto format : {2u, 6u, 3u}) {
        const bool wide = format != 3;
        for (const auto imports : {1u, 2u, 3u}) {
            const auto data = chained(wide, static_cast<std::uint16_t>(format), imports);
            const auto loaded = take(load(data));
            const auto &m = *loaded.metadata.macho;
            check(m.chained_headers.size() == 1 && m.chained_imports.size() == 1 && m.chained_starts.size() == 1 &&
                      m.chained_pointers.size() == 2 && m.dyld_complete,
                  "original chained header/imports/starts and bounded pointer walk parsed");
            if (m.chained_pointers.size() != 2)
                continue;
            const auto &symbol = m.chained_imports[0];
            check(symbol.index == 0 && symbol.header == 0 && symbol.record_file_offset == chains_at + 64 &&
                      symbol.name == "_ext" && symbol.weak_import &&
                      symbol.library_ordinal == (imports == 3 ? -2 : 1) &&
                      symbol.addend == (imports == 1   ? 0
                                        : imports == 2 ? -3
                                                       : -7),
                  "chained import forms preserve raw namespace, signed source addends and special ordinals");
            const auto &first = m.chained_pointers[0];
            const auto &second = m.chained_pointers[1];
            check(
                first.file_place == FileOffset{768} && !first.bind &&
                    first.target == (format == 6 ? 776
                                     : wide      ? UINT64_C(0x100000008)
                                                 : UINT64_C(0x1008)) &&
                    first.target_is_offset == (format == 6) && first.next == (wide ? 2 : 1) && second.bind &&
                    second.import_index == 0 && second.import_row == 0 && second.addend == (wide ? 255 : 63),
                "generic32/64 chains preserve unsigned embedded addends and separate absolute/relative rebase targets");
            auto bad = data;
            put(bad, chains_at + 32, 1000, 4, false);
            check(!load(bad), "segment-info offset cannot escape chain payload");
            bad = data;
            put(bad, chains_at + 58, 4095, 2, false);
            check(!load(bad), "pointer word cannot cross its declared chain page");
            bad = data;
            put(bad, wide ? 776 : 772, wide ? (UINT64_C(1) << 63) | 1 : (UINT64_C(1) << 31) | 1, wide ? 8 : 4, false);
            check(!load(bad), "pointer bind ordinal stays inside this header's import namespace");
            bad = data;
            put(bad, chains_at + 64, 2, imports == 3 ? 8 : 4, false);
            check(!load(bad), "positive import dependency ordinal stays inside linked library list");
        }
    }
}
void partial() {
    auto data = chained();
    constexpr std::array<std::uint8_t, 13> compressed_name{120, 156, 139, 79, 173, 40, 97,
                                                           0, 0, 5, 196, 1, 177};
    for (std::size_t i = 0; i < compressed_name.size(); ++i)
        data[chains_at + 80 + i] = std::byte{compressed_name[i]};
    put(data, dyld_command(true) + 48 + 12, 93, 4, false);
    put(data, chains_at + 24, 1, 4, false);
    const auto compressed = take(load(std::move(data)));
    check(compressed.metadata.macho->dyld_complete && compressed.metadata.macho->chained_imports[0].name == "_ext",
          "bounded zlib chained-import symbol pools decode their original symbol names");
    data = chained();
    put(data, chains_at + 42, 99, 2, false);
    const auto unknown = take(load(data));
    check(!unknown.metadata.macho->dyld_complete && unknown.metadata.macho->chained_pointers.empty() &&
              unknown.metadata.macho->chained_starts[0].pointer_format == 99,
          "unknown pointer format retains bounded page declarations without guessing layout");
}
void authenticated_and_multi() {
    for (const auto format : {1u, 9u, 12u}) {
        auto data = chained(true, static_cast<std::uint16_t>(format));
        put(data, 4, 0x0100000c, 4, false);
        put(data, 8, 2, 4, false);
        put(data, 768,
            (UINT64_C(1) << 63) | (UINT64_C(1) << 51) | (UINT64_C(1) << 49) | (UINT64_C(1) << 48) |
                (UINT64_C(0xbeef) << 32) | 776,
            8, false);
        put(data, 776, (UINT64_C(1) << 62) | (UINT64_C(0x7ffff) << 32), 8, false);
        const auto loaded = take(load(data));
        const auto &m = *loaded.metadata.macho;
        check(m.chained_pointers.size() == 2 && m.chained_pointers[0].authenticated &&
                  m.chained_pointers[0].target == 776 && m.chained_pointers[0].target_is_offset &&
                  m.chained_pointers[0].diversity == 0xbeef && m.chained_pointers[0].address_diversity &&
                  m.chained_pointers[0].key == 1 && m.chained_pointers[1].addend == -1 && m.chained_pointers[1].bind &&
                  loaded.metadata_complete && loaded.image->decode_context().mode == ExecutionMode::a64,
              "ARM64e metadata retains authentication and signed addend while the original scalar decoder is available");
    }
    auto data = chained(false, 3);
    put(data, chains_at + 36, 28, 4, false);
    put(data, chains_at + 58, 0x8001, 2, false);
    put(data, chains_at + 60, 768, 2, false);
    put(data, chains_at + 62, 0x8000 | 776, 2, false);
    put(data, 768, 0x1008, 4, false);
    put(data, 776, (UINT64_C(1) << 31) | (UINT64_C(3) << 20), 4, false);
    const auto loaded = take(load(data));
    check(loaded.metadata.macho->chained_pointers.size() == 2 &&
              loaded.metadata.macho->chained_pointers[0].chain_start_index == 1 &&
              loaded.metadata.macho->chained_pointers[1].chain_start_index == 2,
          "multi-start indexes address the original full page_start array, preserving each source list entry");
    put(data, chains_at + 58, 0x8000, 2, false);
    check(!load(data), "multi-start list cannot point back into primary page entries");
}
void malformed_and_scalar() {
    auto data = chained();
    const auto command = symtab_command(true) + 24 + 32 + 48;
    for (std::uint32_t size = 1; size < 28; ++size) {
        auto bad = data;
        put(bad, command + 12, size, 4, false);
        check(!load(bad), "every truncated chained fixed header fails within its own payload");
    }
    auto bad = data;
    put(bad, chains_at + 8, 95, 4, false);
    check(!load(bad), "import table extent cannot escape chained payload");
    bad = data;
    put(bad, chains_at + 64, (UINT64_C(100) << 9) | 1, 4, false);
    check(!load(bad), "chained import name offset stays within original symbol pool");
    bad = data;
    put(bad, chains_at + 16, UINT32_MAX, 4, false);
    const auto count = load(bad);
    check(!count && count.error().code == ErrorCode::resource_limit,
          "huge import count is rejected before allocation or iteration");
    bad = data;
    put(bad, chains_at + 44, 1, 8, false);
    check(!load(bad), "chained segment-relative base must agree with canonical mapped header/segment");
    bad = data;
    put(bad, 768, (UINT64_C(0xfff) << 51) | 1, 8, false);
    check(!load(bad), "next hop cannot escape declared chain page or segment");
    bad = data;
    put(bad, chains_at + 36, 22, 4, false);
    check(!load(bad), "declared page_count must fit the segment-start record");
    data = chained(false, 3);
    put(data, chains_at + 52, 0x1000, 4, false);
    put(data, 768, 0x3ffffff, 4, false);
    const auto scalar = take(load(data));
    const auto &row = scalar.metadata.macho->chained_pointers[0];
    const auto bias = (UINT64_C(0x4000000) + 0x1000) / 2;
    check(row.non_pointer && row.scalar_value == static_cast<std::uint32_t>(UINT64_C(0x3ffffff) - bias),
          "co-opted32-bit chain values retain restored scalar pattern instead of fabricated pointers");
    data = chained();
    put(data, 768, (UINT64_C(0xab) << 36) | 123, 8, false);
    const auto tagged = take(load(data));
    check(tagged.metadata.macho->chained_pointers[0].high8 == 0xab &&
              tagged.metadata.macho->chained_pointers[0].target == 123,
          "high-byte tag stays separate from unassembled target payload");
    data = chained();
    put(data, 768, 123, 4, false);
    put(data, 772, 0x80000, 8, false);
    const auto overlapping = take(load(data));
    check(overlapping.metadata.macho->chained_pointers.size() == 2 && !overlapping.metadata.macho->dyld_complete &&
              !overlapping.metadata.macho->chained_pointers[0].complete,
          "overlapping pointer words stay inspectable but cannot claim complete runtime fixup semantics");
}
void ordinal_boundaries() {
    constexpr std::uint32_t payload = 12288;
    auto original = chained();
    auto data = thin(true, false);
    put(data, 28, 0, 4, false);
    data.resize(16384);
    put(data, 16, 1, 4, false);
    put(data, 20, 72, 4, false);
    segment(data, true, false, 32, 0, data.size(), 0, data.size(), 7);
    for (std::uint32_t i = 0; i < 240; ++i) {
        const auto at = append_command(data, true, false, 0xc, 32);
        put(data, at + 8, 24, 4, false);
        data[at + 24] = std::byte{'L'};
    }
    const auto command = append_command(data, true, false, 0x80000034, 16);
    put(data, command + 8, payload, 4, false);
    put(data, command + 12, 96, 4, false);
    std::copy_n(original.begin() + chains_at, 96, data.begin() + payload);
    put(data, payload + 36, 28, 4, false);
    put(data, payload + 56, 3, 2, false);
    put(data, payload + 58, 0xffff, 2, false);
    put(data, payload + 60, 0xffff, 2, false);
    put(data, payload + 62, 0, 2, false);
    put(data, 8192, UINT64_C(1) << 63, 8, false);
    for (auto ordinal : {128u, 240u, 254u}) {
        put(data, payload + 64, ordinal, 4, false);
        const auto loaded = take(load(data));
        check(loaded.metadata.macho->chained_imports[0].library_ordinal ==
                  (ordinal == 254 ? -2 : static_cast<int>(ordinal)),
              "8-bit import ordinals128..240 stay positive while only reserved top15 values are special");
    }
}
void bind_resolution() {
    auto loaded = take(load(chained(true, 2, 2)));
    std::vector<std::optional<std::uint64_t>> import_addresses{UINT64_C(0x2000)};
    const auto resolved = take(resolve_macho_chained_binds(*loaded.metadata.macho, import_addresses));
    check(resolved.size() == 1 && resolved[0].pointer_index == 1 && resolved[0].import_row == 0 &&
              resolved[0].status == MachOChainedBindStatus::resolved &&
              resolved[0].import_address == UINT64_C(0x2000) && resolved[0].combined_addend == 252 &&
              resolved[0].target_address == UINT64_C(0x20fc) && !resolved[0].authentication_required,
          "caller-supplied import addresses resolve chained binds with checked combined addends");

    import_addresses[0].reset();
    const auto missing = take(resolve_macho_chained_binds(*loaded.metadata.macho, import_addresses));
    check(missing.size() == 1 && missing[0].status == MachOChainedBindStatus::missing_import_address &&
              !missing[0].target_address,
          "unprovided strong imports remain explicitly unresolved");
    import_addresses[0] = 0;
    const auto zero = take(resolve_macho_chained_binds(*loaded.metadata.macho, import_addresses));
    check(zero[0].status == MachOChainedBindStatus::resolved && zero[0].target_address == 252,
          "an explicit zero import address is distinct from a missing target");
    check(!resolve_macho_chained_binds(*loaded.metadata.macho, {}),
          "import-address namespace must match the parsed chained-import table");

    import_addresses[0] = UINT64_MAX - 2;
    const auto overflow = take(resolve_macho_chained_binds(*loaded.metadata.macho, import_addresses));
    check(overflow[0].status == MachOChainedBindStatus::overflow && !overflow[0].target_address,
          "positive chained addends cannot wrap an external import address");

    auto sum_overflow_bytes = chained(true, 2, 3);
    put(sum_overflow_bytes, chains_at + 72, INT64_MAX, 8, false);
    const auto sum_overflow_image = take(load(std::move(sum_overflow_bytes)));
    import_addresses[0] = UINT64_C(0x3000);
    const auto sum_overflow = take(resolve_macho_chained_binds(*sum_overflow_image.metadata.macho, import_addresses));
    check(sum_overflow[0].status == MachOChainedBindStatus::overflow && !sum_overflow[0].combined_addend &&
              !sum_overflow[0].target_address,
          "combined import and pointer addends cannot overflow signed64");

    const auto auth_pointer = (UINT64_C(1) << 63) | (UINT64_C(1) << 62) | (UINT64_C(1) << 49) |
                              (UINT64_C(1) << 48) | (UINT64_C(0xbeef) << 32);
    auto auth_bytes = chained(true, 9, 2);
    put(auth_bytes, 768, (UINT64_C(1) << 51) | 776, 8, false);
    put(auth_bytes, 776, auth_pointer, 8, false);
    loaded = take(load(std::move(auth_bytes)));
    import_addresses[0] = UINT64_C(0x3000);
    const auto authenticated = take(resolve_macho_chained_binds(*loaded.metadata.macho, import_addresses));
    check(authenticated.size() == 1 && authenticated[0].status == MachOChainedBindStatus::resolved &&
              authenticated[0].authentication_required && authenticated[0].combined_addend == -3 &&
              authenticated[0].target_address == UINT64_C(0x2ffd),
          "authenticated binds expose only the checked pre-PAC target and retain the signing requirement");
    import_addresses[0] = 2;
    const auto negative_overflow = take(resolve_macho_chained_binds(*loaded.metadata.macho, import_addresses));
    check(negative_overflow[0].status == MachOChainedBindStatus::overflow &&
              !negative_overflow[0].target_address,
          "negative chained addends cannot underflow a supplied import address");

    auto corrupt = *loaded.metadata.macho;
    corrupt.chained_pointers[1].import_row = 99;
    const auto invalid = take(resolve_macho_chained_binds(corrupt, import_addresses));
    check(invalid[0].status == MachOChainedBindStatus::invalid_encoding && !invalid[0].target_address,
          "invalid chained import row associations cannot resolve through caller input");
    std::stop_source canceled;
    canceled.request_stop();
    const auto stopped = resolve_macho_chained_binds(*loaded.metadata.macho, import_addresses, canceled.get_token());
    check(!stopped && stopped.error().code == ErrorCode::canceled,
          "chained bind traversal observes cancellation");
}
class ControlledStorage final : public ByteStorage {
    MemoryStorage inner_;
    std::stop_source &stop_;
    bool short_;

  public:
    mutable bool reached = false;
    ControlledStorage(std::vector<std::byte> data, std::stop_source &stop, bool short_read)
        : inner_(std::move(data)), stop_(stop), short_(short_read) {}
    std::uint64_t size() const noexcept override { return inner_.size(); }
    Result<ByteView> read_at(FileOffset at, std::size_t count) const override {
        if (at.value == 776 && count) {
            reached = true;
            if (short_)
                return inner_.read_at(at, count - 1);
            stop_.request_stop();
        }
        return inner_.read_at(at, count);
    }
};
void source_bounds_and_cancellation() {
    for (bool short_read : {false, true}) {
        std::stop_source stop;
        auto storage = std::make_shared<ControlledStorage>(chained(), stop, short_read);
        const auto loaded = load_macho(storage, {}, stop.get_token());
        check(storage->reached && !loaded && (short_read || loaded.error().code == ErrorCode::canceled),
              "cancellation and successful short reads during pointer traversal cannot publish partial metadata");
    }
    auto inner = chained();
    std::vector<std::byte> fat(12288);
    put(fat, 0, 0xcafebabe, 4, true);
    put(fat, 4, 1, 4, true);
    put(fat, 8, 0x01000007, 4, true);
    put(fat, 12, 0x80000003, 4, true);
    put(fat, 16, 4096, 4, true);
    put(fat, 20, 4096, 4, true);
    put(fat, 24, 12, 4, true);
    std::copy(inner.begin(), inner.end(), fat.begin() + 4096);
    const auto selected = take(load(fat));
    check(selected.metadata.macho->chained_headers[0].record_file_offset == 4096 + chains_at &&
              selected.metadata.macho->chained_imports[0].record_file_offset == 4096 + chains_at + 64 &&
              selected.metadata.macho->chained_pointers[0].file_place == FileOffset{4864},
          "chained headers, imports and pointer words preserve absolute outer-container source coordinates");
    put(fat, 4096 + symtab_command(true) + 24 + 32 + 48 + 8, 4090, 4, false);
    check(!load(fat), "chained payload cannot escape selected slice despite available outer bytes");
    auto data = chained();
    put(data, 32 + 32, 8192, 8, false);
    put(data, chains_at + 36, 26, 4, false);
    put(data, chains_at + 56, 2, 2, false);
    put(data, chains_at + 58, 0xffff, 2, false);
    put(data, chains_at + 60, 0, 2, false);
    const auto zero = take(load(data));
    check(zero.metadata.macho->chained_pointers.size() == 1 && zero.metadata.macho->chained_pointers[0].raw == 0 &&
              !zero.metadata.macho->chained_pointers[0].file_place,
          "declared zero-fill slots use canonical zero bits with no invented backing read");
    data = chained();
    put(data, chains_at + 20, 99, 4, false);
    const auto unknown_import = take(load(data));
    check(!unknown_import.metadata.macho->dyld_complete && unknown_import.metadata.macho->chained_imports.empty() &&
              unknown_import.metadata.macho->chained_pointers[1].import_index == 0 &&
              !unknown_import.metadata.macho->chained_pointers[1].import_row,
          "unknown import layout keeps raw bind ordinal without pretending a parsed import row exists");
}
} // namespace
int main() {
    return run([] {
        generic();
        partial();
        authenticated_and_multi();
        malformed_and_scalar();
        ordinal_boundaries();
        source_bounds_and_cancellation();
        bind_resolution();
    });
}
