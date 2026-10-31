#include "hexlab/loaders/raw.hpp"
#include "hexlab/loaders/recipe.hpp"
#include "hexlab/loaders/pe.hpp"
#include "hexlab/loaders/elf.hpp"
#include "hexlab/loaders/macho.hpp"
#include "hexlab/analysis/functions.hpp"
#include "hexlab/analysis/references.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#include "support/a64_image_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
using namespace hexlab;
using namespace hexlab_test;
namespace {
template <class T> T take(Result<T> result) {
    if (!result)
        throw std::runtime_error(result.error().message);
    return std::move(result.value());
}
void facts(std::shared_ptr<const Image> source_image, const ImageMetadata &metadata, Address entry) {
    const auto &image = *source_image;
    check(image.decode_context().mode == ExecutionMode::a64, "compatible A64 image selects explicit decoder mode");
    if (image.decode_context().mode != ExecutionMode::a64)
        return;
    const auto coarse = analyze(image, metadata, {}, {});
    check(bool(coarse), "A64 coarse continuation is supported");
    if (!coarse)
        return;
    check(coarse.value().instructions.size() == 5, "A64 calls traverse callee and LR return continuation");
    const auto functions = recover_functions(image, metadata, {}, {}, {});
    check(bool(functions), "A64 function recovery uses shared engine");
    if (!functions)
        return;
    check(functions.value()->functions.size() == 2 && functions.value()->instructions.size() == 5,
          "ADR address does not become a false code root");
    const auto references = derive_references(image, *functions.value(), metadata, {}, {});
    check(bool(references), "A64 indirect register and address-only references validate");
    if (!references)
        return;
    bool call = false, address = false, indirect = false;
    for (const auto &ref : references.value()->all()) {
        const auto *target = std::get_if<Location>(&ref.target);
        if (ref.kind == ReferenceKind::call)
            call =
                ref.source == Location{entry} && target && *target == Location{Address{entry.space, entry.offset + 16}};
        if (ref.kind == ReferenceKind::memory_address)
            address = target && *target == Location{Address{entry.space, entry.offset + 24}};
        if (auto unresolved = std::get_if<UnresolvedTarget>(&ref.target))
            if (auto reg = std::get_if<RegisterOperand>(&unresolved->expression))
                indirect = reg->bank == RegisterBank::arm64_gpr && reg->index == 3;
    }
    check(call && address && indirect,
          "shared references distinguish direct code, ADR address and unknown BR register");
    const auto payload = take(encode_reference_index(*references.value(), {}));
    const auto roundtrip = take(decode_reference_index(payload, {}));
    check(roundtrip->all().size() == references.value()->all().size(),
          "A64 reference expressions round-trip canonically");
    AnalysisKey key;
    key.input = {image.storage()->size(), take(hash_source(*image.storage(), {}))};
    key.engine_fingerprint = function_engine_fingerprint();
    const auto derived =
        take(analyze_derived(source_image, std::make_shared<const ImageMetadata>(metadata), {}, {}, key, {}));
    const auto cache = take(encode_derived(derived, {}));
    check(take(decode_derived(cache, image, metadata, {}, {}, key, {})).functions->instructions.size() == 5,
          "A64 complete cache revalidates bytes, register banks and rooted model");
    auto forged = cache;
    forged[127] = std::byte(ExecutionMode::x86_64);
    Sha256 checksum;
    take(checksum.update(std::span(forged).first(forged.size() - 32)));
    const auto digest = checksum.digest();
    std::copy(digest.begin(), digest.end(), forged.end() - 32);
    check(!decode_derived(forged, image, metadata, {}, {}, key, {}),
          "checksum-valid A64 cache cannot replace source context with x86");
}
void raw() {
    const RawOptions options{Architecture::arm64, ExecutionMode::a64, {{7}, 0x1000}, true, false, true, {}};
    const auto encoded = encode_recipe({Format::raw, options});
    check(bool(encoded), "A64 raw recipe accepts explicit architecture/mode");
    if (encoded) {
        const auto decoded = take(decode_recipe(encoded.value()));
        check(decoded.raw && decoded.raw->architecture == Architecture::arm64 &&
                  decoded.raw->mode == ExecutionMode::a64,
              "A64 raw recipe preserves appended enum ordinals");
    }
    const auto image = load_raw(std::make_shared<MemoryStorage>(a64_fixture::program()), options, {});
    check(bool(image), "A64 raw input loads");
    if (image) {
        facts(image.value(), {}, options.base);
    }
    auto invalid = options;
    invalid.entry = Address{{7}, 0x1001};
    check(!validate_raw_coordinates(invalid), "explicit A64 raw entry alignment is validated");
    invalid = options;
    invalid.mode = ExecutionMode::thumb;
    check(!validate_raw_coordinates(invalid), "A64 cannot adopt Thumb mode");
}
void images() {
    const auto pe = take(load_pe(std::make_shared<MemoryStorage>(a64_fixture::pe()), {}));
    facts(pe.image, pe.metadata, {{0}, UINT64_C(0x140001000)});
    const auto elf = take(load_elf(std::make_shared<MemoryStorage>(a64_fixture::elf()), {}));
    facts(elf.image, elf.metadata, {{0}, 0x400000});
    const auto macho = take(load_macho(std::make_shared<MemoryStorage>(a64_fixture::macho()), {}, {}));
    facts(macho.image, macho.metadata, {{0}, UINT64_C(0x100000300)});
    std::vector<std::byte> fat(12288);
    macho_fixture::put(fat, 0, 0xcafebabe, 4, true);
    macho_fixture::put(fat, 4, 2, 4, true);
    for (unsigned n = 0; n < 2; ++n) {
        auto child = a64_fixture::macho();
        const auto cpu = n ? 0x0100000cu : 0x0200000cu;
        macho_fixture::put(child, 4, cpu, 4, false);
        const auto at = 8 + n * 20;
        macho_fixture::put(fat, at, cpu, 4, true);
        macho_fixture::put(fat, at + 4, 0x80000003, 4, true);
        macho_fixture::put(fat, at + 8, 4096 + n * 4096, 4, true);
        macho_fixture::put(fat, at + 12, 4096, 4, true);
        macho_fixture::put(fat, at + 16, 12, 4, true);
        std::copy(child.begin(), child.end(), fat.begin() + 4096 + n * 4096);
    }
    const auto selected = take(load_macho(std::make_shared<MemoryStorage>(std::move(fat)), {}, {}));
    check(selected.metadata.macho->selected_slice == 1 && selected.image->decode_context().mode == ExecutionMode::a64,
          "automatic universal selection ranks supported A64 above an unsupported ABI64_32 slice");
    for (bool big : {false, true}) {
        auto data = elf_fixture::executable(false, big);
        elf_fixture::put(data, 18, 183, 2, big);
        const auto unsupported = take(load_elf(std::make_shared<MemoryStorage>(std::move(data)), {}));
        check(!processor_capabilities(unsupported.image->decode_context()).can_decode,
              "incompatible A64 ELF class/order stays inspectable metadata");
    }
}
void windows() {
    const RawOptions options{Architecture::arm64, ExecutionMode::a64, {{7}, 0x1000}, true, false, true, {}};
    const auto original = take(load_raw(std::make_shared<MemoryStorage>(a64_fixture::program()), options, {}));
    AnalysisKey key;
    key.input = {original->storage()->size(), take(hash_source(*original->storage(), {}))};
    key.engine_fingerprint = function_engine_fingerprint();
    const auto derived = take(analyze_derived(original, std::make_shared<const ImageMetadata>(), {}, {}, key, {}));
    const auto payload = take(encode_derived(derived, {}));
    for (unsigned kind = 0; kind < 4; ++kind) {
        auto layout = original->layout();
        if (kind == 0)
            layout.code_exclusions.push_back({{{7}, 0x1002}, 1});
        if (kind == 1)
            layout.encrypted_ranges.push_back({{{7}, 0x1000}, 4});
        if (kind == 2)
            layout.segments = {{"first", {{7}, 0x1000}, 2, {0}, 2, true, false, true},
                               {"after-gap", {{7}, 0x1003}, 29, {3}, 29, true, false, true}};
        if (kind == 3)
            layout.segments[0].file_size = 2;
        const auto guarded = take(Image::create(original->storage(), std::move(layout)));
        const auto decoded = take(decode_at(*guarded, options.base));
        check(!decoded.instruction && decoded.status == DecodeStatus::truncated,
              "A64 instruction cannot straddle data, encryption, mapping gap or uninitialized backing");
        check(take(analyze(*guarded, {}, {})).instructions.empty() &&
                  take(recover_functions(*guarded, {}, {}, {}, {}))->instructions.empty(),
              "all A64 automatic recovery obeys the same hard instruction window");
        check(!decode_derived(payload, *guarded, {}, {}, {}, key, {}),
              "A64 cached facts cannot bypass changed mapping/exclusion policy");
    }
    auto layout = original->layout();
    layout.code_exclusions.push_back({{{7}, 0x1004}, 4});
    const auto exact = take(Image::create(original->storage(), std::move(layout)));
    check(take(decode_at(*exact, options.base)).instruction.has_value(),
          "A64 four-byte word ending exactly at data boundary remains decodable");
}
} // namespace
int main() {
    return run([] {
        auto source = std::make_shared<MemoryStorage>(bytes({0x1e, 0xff, 0x2f, 0x11})); // BXNE LR
        ImageLayout layout{{{0}, 32, 1, ByteOrder::little},
                           Architecture::arm,
                           ExecutionMode::a32,
                           {{"a32", {{0}, 0x1000}, 4, {0}, 4, true, false, true}},
                           {{{0}, 0x1000}}};
        const auto a32 = take(Image::create(source, std::move(layout)));
        check(take(decode_at(*a32, {{0}, 0x1000})).instruction.has_value(),
              "pure A32 decoding is available before state-aware automatic analysis");
        const auto coarse = analyze(*a32, {}, {});
        const auto functions = recover_functions(*a32, {}, {}, {}, {});
        check(coarse && !coarse.value().instructions.empty() && functions &&
                  !functions.value()->functions.empty(),
              "automatic A32 recovery models conditional returns and their continuation edge");
        auto thumb_source = std::make_shared<MemoryStorage>(bytes({0x70, 0x47}));
        ImageLayout thumb_layout{{{0}, 32, 1, ByteOrder::little},
                                 Architecture::arm,
                                 ExecutionMode::thumb,
                                 {{"thumb", {{0}, 0x1000}, 2, {0}, 2, true, false, true}},
                                 {{{0}, 0x1000}}};
        const auto thumb = take(Image::create(thumb_source, std::move(thumb_layout)));
        check(take(decode_at(*thumb, {{0}, 0x1000})).instruction.has_value(),
              "manual Thumb decoding remains available with unknown IT metadata");
        const auto thumb_analysis = analyze(*thumb, {}, {});
        const auto thumb_functions = recover_functions(*thumb, {}, {}, {}, {});
        check(thumb_analysis && thumb_analysis.value().instructions.empty() && thumb_functions &&
                  thumb_functions.value()->functions.empty() && !thumb_functions.value()->complete,
              "Thumb flow without source-backed clear IT state remains conservatively incomplete");
        raw();
        images();
        windows();
    });
}
