#include "hexlab/analysis/macho_dyld.hpp"
#include "hexlab/loaders/macho.hpp"
#include "support/macho_chained_fixture.hpp"
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
LoadedImage load(std::vector<std::byte> data) {
    return take(load_macho(std::make_shared<MemoryStorage>(std::move(data)), {}, {}));
}
void chained_slots() {
    for (const auto format : {2u, 3u, 6u}) {
        const bool wide = format != 3;
        const auto base = wide ? UINT64_C(0x100000000) : UINT64_C(0x1000);
        const std::uint8_t width = wide ? 8 : 4;
        auto loaded = load(chained(wide, static_cast<std::uint16_t>(format), 2));
        auto resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
        const auto rebase = take(resolver.slot({{0}, base}, width, {}));
        check(rebase.reason == MachODyldResolutionReason::resolved && rebase.address == Address{{0}, base + 8} &&
                  rebase.origins == std::vector<MachODyldIdentity>{{MachODyldSource::chained, 0}},
              "preferred chained rebase uses original payload and mapped-header offset semantics");
        const auto bound = take(resolver.data({MachODyldSource::chained, 1}, {}));
        check(
            bound.reason == MachODyldResolutionReason::runtime_binding && !bound.address && bound.binding &&
                bound.binding->name == "_ext" && bound.binding->library_ordinal == 1 && bound.binding->weak_import &&
                bound.binding->addend == (wide ? 252 : 60) && bound.binding->import_row == 0,
            "chained import association owns exact namespace and combined signed/unsigned addend without host lookup");
        check(take(resolver.slot({{0}, base + 1}, width, {})).reason == MachODyldResolutionReason::ambiguous,
              "query crossing two original words is explicitly ambiguous");
        check(take(resolver.slot({{0}, base}, static_cast<std::uint8_t>(width - 1), {})).reason ==
                  MachODyldResolutionReason::field_mismatch,
              "partial pointer field cannot claim a complete static address");
        check(!take(resolver.slot({{0}, base + 24}, 4, {})).associated(),
              "ordinary bytes outside fixup slots have no dyld origin");
        check(!take(resolver.slot({{1}, base}, width, {})).associated(),
              "identical numeric offset in another domain cannot match linked dyld slots");
    }
}
void classic_slots() {
    for (bool wide : {false, true})
        for (bool big : {false, true}) {
            auto bytes = dyld(wide, big);
            const auto base = wide ? UINT64_C(0x100000000) : UINT64_C(0x1000);
            const std::uint8_t width = wide ? 8 : 4;
            stream(bytes, wide, big, 0, {0x11, 0x20, 0, 0x51, 0});
            stream(bytes, wide, big, 1, {0x11, 0x41, '_', 'x', 0, 0x60, 0x7d, 0x70, 8, 0x90, 0});
            put(bytes, 768, base + 8, width, big);
            auto loaded = load(bytes);
            const auto resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
            const auto rebase = take(resolver.data({MachODyldSource::classic, 0}, {}));
            check(rebase.address == Address{{0}, base + 8} && rebase.reason == MachODyldResolutionReason::resolved,
                  "classic pointer rebase preserves linked preferred VA in either byte order");
            const auto bound = take(resolver.slot({{0}, base + 8}, width, {}));
            check(bound.reason == MachODyldResolutionReason::runtime_binding && !bound.address && bound.binding &&
                      bound.binding->name == "_x" && bound.binding->library_ordinal == 1 &&
                      bound.binding->addend == -3 && bound.binding->weak_import && !bound.binding->import_row,
                  "classic bind state never masquerades as a chained import ordinal");
        }
}
void exact_namespaces_and_limits() {
    auto bytes = chained();
    // One classic declaration and one chained word own the same source bytes.
    stream(bytes, true, false, 0, {0x11, 0x20, 0x80, 0x06, 0x51, 0});
    auto loaded = load(bytes);
    auto resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
    const auto conflict = take(resolver.slot({{0}, UINT64_C(0x100000000)}, 8, {}));
    check(conflict.reason == MachODyldResolutionReason::ambiguous && !conflict.address &&
              conflict.origins ==
                  std::vector<MachODyldIdentity>{{MachODyldSource::classic, 0}, {MachODyldSource::chained, 0}},
          "equal row numbers in different dyld namespaces remain distinct ambiguous origins");
    resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {1024, 1}, {}));
    const auto many = resolver.slot({{0}, UINT64_C(0x100000000)}, 8, {});
    check(!many && many.error().code == ErrorCode::resource_limit,
          "match budget cannot silently drop competing fixup origins");
    resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {1, 4096}, {}));
    const auto exhausted = resolver.slot({{0}, UINT64_C(0x100000000)}, 8, {});
    check(!exhausted && exhausted.error().code == ErrorCode::resource_limit,
          "indexed lookup work is bounded independently of match count");
    std::stop_source canceled;
    canceled.request_stop();
    const auto stopped = MachODyldResolver::create(*loaded.image, loaded.metadata, canceled.get_token());
    check(!stopped && stopped.error().code == ErrorCode::canceled, "dyld index construction honors cancellation");
    const auto stopped_query = resolver.slot({{0}, UINT64_C(0x100000000)}, 8, canceled.get_token());
    check(!stopped_query && stopped_query.error().code == ErrorCode::canceled,
          "dyld queries honor cancellation before lookup");
    check(!resolver.slot({{0}, 0}, 0, {}) && !resolver.slot({{0}, UINT64_MAX - 3}, 8, {}),
          "query widths and arithmetic cannot wrap interval endpoints");
    check(!resolver.data({MachODyldSource::chained, 2}, {}) && !resolver.data({static_cast<MachODyldSource>(2), 0}, {}),
          "invalid source identities fail without crossing row vectors");
    loaded = load(chained());
    auto corrupt = loaded.metadata;
    corrupt.macho->chained_pointers[1].import_row = 1;
    check(!MachODyldResolver::create(*loaded.image, corrupt, {}),
          "chained import namespace is checked before dereferencing");
    corrupt = loaded.metadata;
    corrupt.macho->chained_pointers[0].file_place = FileOffset{769};
    check(!MachODyldResolver::create(*loaded.image, corrupt, {}), "source slot backing must match the canonical image");
    corrupt = loaded.metadata;
    corrupt.macho->chained_starts[0].segment_index = 9;
    check(!MachODyldResolver::create(*loaded.image, corrupt, {}),
          "raw segment namespace cannot index outside command metadata");
}
void partial_values_and_anchors() {
    constexpr auto base = UINT64_C(0x100000000);
    auto bytes = chained(true, 6);
    auto loaded = load(bytes);
    auto layout = loaded.image->layout();
    layout.segments = {{"headerless", {{0}, base}, 32, {768}, 32, true, true, true}};
    auto image = take(Image::create(loaded.image->storage(), layout));
    auto resolver = take(MachODyldResolver::create(*image, loaded.metadata, {}));
    check(take(resolver.data({MachODyldSource::chained, 0}, {})).reason == MachODyldResolutionReason::missing_anchor,
          "offset rebase never guesses a header load address from an arbitrary segment");
    layout = loaded.image->layout();
    layout.segments.push_back({"header-alias", {{0}, UINT64_C(0x200000000)}, 32, {0}, 32, true, false, false});
    image = take(Image::create(loaded.image->storage(), layout));
    resolver = take(MachODyldResolver::create(*image, loaded.metadata, {}));
    check(take(resolver.data({MachODyldSource::chained, 0}, {})).reason == MachODyldResolutionReason::missing_anchor,
          "ambiguous source header aliases cannot select a preferred-space base");
    bytes = chained(true, 2, 3);
    put(bytes, chains_at + 72, INT64_MAX, 8, false);
    loaded = load(bytes);
    resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
    check(take(resolver.data({MachODyldSource::chained, 1}, {})).reason == MachODyldResolutionReason::overflow,
          "combined import and embedded addends cannot overflow signed64");
    bytes = chained(false, 3);
    put(bytes, chains_at + 52, 0x1000, 4, false);
    put(bytes, 768, 0x2000, 4, false);
    loaded = load(bytes);
    resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
    const auto scalar = take(resolver.data({MachODyldSource::chained, 0}, {}));
    check(scalar.reason == MachODyldResolutionReason::non_pointer && scalar.constant && !scalar.address,
          "co-opted32 scalar never becomes a code or pointer address");
    bytes = chained();
    put(bytes, 768, base + 8 | (UINT64_C(0xab) << 36), 8, false);
    loaded = load(bytes);
    resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
    check(take(resolver.data({MachODyldSource::chained, 0}, {})).reason == MachODyldResolutionReason::unmapped_target,
          "high8 address bits cannot be discarded to fabricate an ordinary mapped pointer");
    for (const auto format : {1u, 9u, 12u}) {
        bytes = chained(true, static_cast<std::uint16_t>(format));
        put(bytes, 768, UINT64_C(1) << 63 | 8, 8, false);
        loaded = load(bytes);
        resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
        const auto auth = take(resolver.data({MachODyldSource::chained, 0}, {}));
        check(auth.reason == MachODyldResolutionReason::authenticated && !auth.address,
              "authenticated payload remains unresolved without inventing PAC/runtime semantics");
    }
    bytes = chained();
    put(bytes, 768, 123, 4, false);
    put(bytes, 772, 0x80000, 8, false);
    loaded = load(bytes);
    resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
    check(take(resolver.data({MachODyldSource::chained, 0}, {})).reason == MachODyldResolutionReason::ambiguous,
          "overlapping partial pointer words cannot resolve by row-order preference");
}
class CountingStorage final : public ByteStorage {
    MemoryStorage inner_;

  public:
    mutable std::size_t reads = 0;
    CountingStorage(std::vector<std::byte> bytes) : inner_(std::move(bytes)) {}
    std::uint64_t size() const noexcept override { return inner_.size(); }
    Result<ByteView> read_at(FileOffset offset, std::size_t size) const override {
        ++reads;
        return inner_.read_at(offset, size);
    }
};
void no_source_reapplication() {
    const auto source = std::make_shared<CountingStorage>(chained());
    const auto loaded = take(load_macho(source, {}, {}));
    const auto before = source->reads;
    const auto resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
    for (std::uint32_t i = 0; i < 100; ++i) {
        const auto result = take(resolver.data({MachODyldSource::chained, 0}, {}));
        if (!result.address)
            throw std::runtime_error("lost immutable rebase result");
    }
    check(source->reads == before, "dyld resolver never rereads or rewrites original pointer storage after parsing");
}
void other_layouts_and_partial_sources() {
    constexpr auto base = UINT64_C(0x100000000);
    for (const auto format : {1u, 9u, 12u}) {
        auto bytes = chained(true, static_cast<std::uint16_t>(format), 3);
        put(bytes, 768, format == 1 ? base + 8 : 776, 8, false);
        auto loaded = load(bytes);
        auto resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
        check(take(resolver.data({MachODyldSource::chained, 0}, {})).address == Address{{0}, base + 8},
              "unauthenticated ARM64e layouts distinguish raw VA from preferred header offsets");
        put(bytes, 768, UINT64_C(1) << 62 | (UINT64_C(0x7ffff) << 32), 8, false);
        loaded = load(bytes);
        resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
        auto bind = take(resolver.data({MachODyldSource::chained, 0}, {}));
        check(bind.reason == MachODyldResolutionReason::runtime_binding && bind.binding && bind.binding->addend == -8 &&
                  bind.binding->library_ordinal == -2 && !bind.address,
              "signed ARM64e embedded addend combines with signed64 import addend in its own namespace");
        put(bytes, chains_at + 72, UINT64_C(1) << 63, 8, false);
        loaded = load(bytes);
        resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
        check(take(resolver.data({MachODyldSource::chained, 0}, {})).reason == MachODyldResolutionReason::overflow,
              "negative combined addend overflow stays typed and unresolved");
    }
    auto bytes = chained();
    put(bytes, chains_at + 24, 1, 4, false);
    auto loaded = load(bytes);
    auto resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
    check(take(resolver.data({MachODyldSource::chained, 0}, {})).reason == MachODyldResolutionReason::resolved &&
              take(resolver.data({MachODyldSource::chained, 1}, {})).reason == MachODyldResolutionReason::unsupported,
          "compressed import names do not erase an independently complete rebase");
    bytes = chained(true, 6);
    put(bytes, 32 + 24, UINT64_MAX - 8192, 8, false);
    put(bytes, 768, 776 | (UINT64_C(0xff) << 36), 8, false);
    loaded = load(bytes);
    resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
    check(take(resolver.data({MachODyldSource::chained, 0}, {})).reason == MachODyldResolutionReason::overflow,
          "preferred header plus encoded high8 offset cannot wrap into a low mapping");
    bytes = dyld(true);
    stream(bytes, true, false, 2, {0x40, '_', 'w', 0, 0x70, 0, 0x90, 0});
    loaded = load(bytes);
    resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
    const auto weak = take(resolver.data({MachODyldSource::classic, 0}, {}));
    check(weak.reason == MachODyldResolutionReason::runtime_binding && weak.binding && !weak.binding->library_ordinal &&
              !weak.binding->weak_import,
          "weak coalescing stream without explicit ordinal never acquires a guessed library or weak-import flag");
    for (const auto type : {2u, 3u, 4u}) {
        bytes = dyld(true);
        stream(bytes, true, false, 0, {0x10 | type, 0x20, 0, 0x51, 0});
        loaded = load(bytes);
        resolver = take(MachODyldResolver::create(*loaded.image, loaded.metadata, {}));
        const auto value = take(resolver.data({MachODyldSource::classic, 0}, {}));
        check(!value.address && value.associated() && value.reason != MachODyldResolutionReason::resolved,
              "text and unknown classic fixup types do not use pointer rebase equations");
    }
    loaded = load(chained());
    auto invalid = loaded.metadata;
    invalid.macho->selected_slice = 1;
    check(!MachODyldResolver::create(*loaded.image, invalid, {}), "selected slice is checked before use");
    invalid = loaded.metadata;
    invalid.macho->container.slices[0].header.is_64 = false;
    resolver = take(MachODyldResolver::create(*loaded.image, invalid, {}));
    check(take(resolver.data({MachODyldSource::chained, 0}, {})).reason == MachODyldResolutionReason::unsupported,
          "pointer layout cannot override a contradictory selected image class");
    resolver = take(MachODyldResolver::create(*loaded.image, ImageMetadata{}, {}));
    check(!take(resolver.slot({{0}, base}, 8, {})).associated() && !resolver.data({MachODyldSource::classic, 0}, {}),
          "absent metadata never fabricates a dyld source");
}
} // namespace
int main() {
    return run([] {
        chained_slots();
        classic_slots();
        exact_namespaces_and_limits();
        partial_values_and_anchors();
        no_source_reapplication();
        other_layouts_and_partial_sources();
    });
}
