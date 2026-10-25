#include "hexlab/image/image.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include <algorithm>
#include <iostream>
#include <type_traits>
using namespace hexlab;
using namespace hexlab_test;
namespace {
template <class T> T take(Result<T> result) {
    if (!result)
        throw std::runtime_error(result.error().message);
    return std::move(result.value());
}
ImageLayout baseline() {
    ImageLayout layout{{{0}, 32, 1, ByteOrder::little},
                       Architecture::arm,
                       ExecutionMode::a32,
                       {{"text", {{0}, 0x1000}, 64, {0}, 64, true, false, true},
                        {"tail", {{0}, 0x1040}, 32, {64}, 16, true, false, false},
                        {"other", {{7}, 0x2000}, 16, {96}, 16, true, false, true}},
                       {{{0}, 0x1000}}};
    layout.domains.push_back(
        {{{7}, 32, 1, ByteOrder::little}, {Architecture::arm, ExecutionMode::thumb, ByteOrder::little}});
    return layout;
}
template <class Layout, class ImageType = Image> void contexts() {
    const auto storage = std::make_shared<MemoryStorage>(std::vector<std::byte>(128));
    const auto legacy = take(ImageType::create(storage, baseline()));
    check(digest_hex(take(legacy->mapping_fingerprint())) ==
              "3ad565c20d1bfd350f9b3936db8d0eaa3f67b424bccaa94ef2eba9e9a41cd6c0",
          "absent-profile mapping identity exactly matches observed genuine25 baseline");
    check(take(legacy->context_at({{0}, 0x1010})).mode == ExecutionMode::a32 &&
              legacy->code_window({{0}, 0x1000}, 128) == 128,
          "absent profile preserves whole-domain context and historical code windows");
    if constexpr (!requires(Layout layout) { layout.arm_profile; }) {
        check(false, "image must represent source-bound ARM/Thumb/data context ranges");
    } else {
        using Profile = typename decltype(Layout{}.arm_profile)::value_type;
        using Range = typename decltype(Profile{}.ranges)::value_type;
        using Root = typename decltype(Profile{}.roots)::value_type;
        using Source = typename decltype(Range{}.sources)::value_type;
        using Evidence = typename decltype(Source{}.evidence)::value_type;
        using Kind = decltype(Range{}.kind);
        using Origin = decltype(Source{}.kind);
        Source raw{Origin::raw_declaration, 0, 1, {}};
        Source mapping{Origin::elf_mapping_symbol, 3, 8, Evidence{{112}, 4}};
        Source function{Origin::elf_function_symbol, 3, 9, Evidence{{116}, 4}};
        Source override_source{Origin::user_override, 0, 2, {}};
        Layout layout = baseline();
        layout.arm_profile = Profile{
            {Range{{{0}, 0x1000}, 8, Kind::a32, {raw}}, Range{{{0}, 0x1008}, 8, Kind::thumb, {mapping}},
             Range{{{0}, 0x1010}, 4, Kind::data, {raw}}, Range{{{0}, 0x1014}, 4, Kind::unknown, {raw}},
             Range{{{0}, 0x1018}, 4, Kind::conflict, {raw, override_source}}, Range{{{0}, 0x1020}, 4, Kind::a32, {raw}},
             Range{{{0}, 0x1024}, 4, Kind::a32, {raw}}, Range{{{7}, 0x2000}, 8, Kind::thumb, {mapping}}},
            {Root{{{0}, 0x1000}, ExecutionMode::a32, false, {raw}},
             Root{{{0}, 0x1008}, ExecutionMode::thumb, true, {function}},
             Root{{{7}, 0x2000}, ExecutionMode::thumb, false, {mapping}}}};
        const auto image = take(ImageType::create(storage, layout));
        for (const auto [offset, mode] : {std::pair{0x1000u, ExecutionMode::a32},
                                          {0x1007u, ExecutionMode::a32},
                                          {0x1008u, ExecutionMode::thumb},
                                          {0x100fu, ExecutionMode::thumb},
                                          {0x1010u, ExecutionMode::unknown},
                                          {0x1014u, ExecutionMode::unknown},
                                          {0x101cu, ExecutionMode::unknown},
                                          {0x1028u, ExecutionMode::unknown}})
            check(take(image->context_at({{0}, offset})).mode == mode,
                  "per-address context follows declarations and never falls back through gaps or data");
        const auto conflict = image->context_at({{0}, 0x1018});
        check(!conflict && conflict.error().code == ErrorCode::conflict,
              "conflicting source declarations remain an explicit context conflict");
        check(take(image->context_at({{7}, 0x2000})).mode == ExecutionMode::thumb &&
                  take(image->context_at({{7}, 0x2008})).mode == ExecutionMode::unknown &&
                  !image->context_at({{8}, 0}) && !image->context_at({{0}, UINT64_C(0x100000000)}),
              "context profiles preserve address domains and width validation");
        check(image->code_window({{0}, 0x1000}, 128) == 8 && image->code_window({{0}, 0x100e}, 128) == 2 &&
                  image->code_window({{0}, 0x1020}, 128) == 4 && image->code_window({{0}, 0x1024}, 128) == 4,
              "code reads stop at mode boundaries and adjacent same-mode declaration boundaries");
        for (auto at : {0x1010u, 0x1014u, 0x1018u, 0x101cu, 0x1028u, 0x1100u})
            check(image->code_window({{0}, at}, 128) == 0,
                  "data, unknown, conflicting, uncovered and unmapped addresses provide no code window");
        check(image->plaintext_window({{0}, 0x1010}, 128) == 128 && take(image->read({{0}, 0x1010}, 4)).size() == 4,
              "code-state declarations do not suppress ordinary plaintext/data reads");
        check(image->arm_code_at({{0}, 0x1008})->sources == std::vector<Source>{mapping} &&
                  image->arm_code_at({{0}, 0x1018})->sources.size() == 2 && !image->arm_code_at({{0}, 0x101c}) &&
                  !image->arm_code_at({{6}, 0x1008}),
              "borrowed binary range lookup preserves origins and does not cross domains");
        const auto identity = take(image->mapping_fingerprint());
        check(identity != take(legacy->mapping_fingerprint()), "explicit context declarations enter mapping identity");
        auto reordered = layout;
        std::reverse(reordered.arm_profile->ranges.begin(), reordered.arm_profile->ranges.end());
        std::reverse(reordered.arm_profile->roots.begin(), reordered.arm_profile->roots.end());
        for (auto &range : reordered.arm_profile->ranges)
            std::reverse(range.sources.begin(), range.sources.end());
        check(take(take(ImageType::create(storage, reordered))->mapping_fingerprint()) == identity,
              "equivalent source ordering has a canonical mapping identity");
        const auto changed = [&](auto mutate, const char *message) {
            auto copy = layout;
            mutate(copy);
            check(take(take(ImageType::create(storage, std::move(copy)))->mapping_fingerprint()) != identity, message);
        };
        changed([](auto &l) { l.arm_profile->ranges[0].sources[0].record_index++; },
                "source record identity is hashed");
        changed([](auto &l) { l.arm_profile->ranges[1].sources[0].namespace_id++; }, "source namespace is hashed");
        changed([](auto &l) { l.arm_profile->ranges[1].sources[0].evidence->begin.value++; },
                "source evidence offset is hashed");
        changed([](auto &l) { l.arm_profile->ranges[1].sources[0].evidence->size++; },
                "source evidence size is hashed");
        changed([](auto &l) { l.arm_profile->roots[1].known_thumb_it_clear = false; }, "root IT-state claim is hashed");
        changed([](auto &l) { l.arm_profile->roots[1].sources[0].record_index++; }, "root source is hashed");
        changed([&](auto &l) { l.arm_profile->ranges[2].kind = Kind::unknown; }, "non-code state kind is hashed");
        changed(
            [](auto &l) {
                l.arm_profile->ranges.erase(l.arm_profile->ranges.begin() + 6);
                l.arm_profile->ranges[5].size = 8;
            },
            "hard same-mode declaration boundaries are hashed");
        auto empty = layout;
        empty.arm_profile = Profile{};
        const auto empty_image = take(ImageType::create(storage, empty));
        check(take(empty_image->context_at({{0}, 0x1000})).mode == ExecutionMode::unknown &&
                  empty_image->code_window({{0}, 0x1000}, 4) == 0 &&
                  take(empty_image->mapping_fingerprint()) != take(legacy->mapping_fingerprint()),
              "empty explicit profile differs from absent profile and supplies no inferred code");
        auto excluded = layout;
        excluded.code_exclusions.push_back({{{0}, 0x1004}, 2});
        excluded.encrypted_ranges.push_back({{{0}, 0x100c}, 2});
        const auto barrier = take(ImageType::create(storage, excluded));
        check(barrier->code_window({{0}, 0x1000}, 16) == 4 && barrier->code_window({{0}, 0x1004}, 16) == 0 &&
                  barrier->code_window({{0}, 0x1008}, 16) == 4 && barrier->code_window({{0}, 0x100c}, 16) == 0 &&
                  barrier->plaintext_window({{0}, 0x100c}, 2) == 0,
              "context windows compose with existing code and encryption barriers");
        const auto invalid = [&](auto mutate, const char *message) {
            auto copy = layout;
            mutate(copy);
            check(!ImageType::create(storage, std::move(copy)), message);
        };
        invalid([](auto &l) { l.arm_profile->ranges[0].size = 0; }, "zero-size context declaration rejected");
        invalid([](auto &l) { l.arm_profile->ranges[1].begin.offset = 0x1004; }, "overlapping declarations rejected");
        invalid([](auto &l) { l.arm_profile->ranges[0].begin.offset++; }, "misaligned A32 range rejected");
        invalid([](auto &l) { l.arm_profile->ranges[1].begin.offset++; }, "misaligned Thumb range rejected");
        invalid([](auto &l) { l.arm_profile->ranges[0].size = 6; }, "partial A32 range extent rejected");
        invalid([](auto &l) { l.arm_profile->ranges[1].size = 7; }, "partial Thumb range extent rejected");
        invalid([](auto &l) { l.arm_profile->ranges[0].size = UINT64_MAX; }, "overflowing range rejected");
        invalid([](auto &l) { l.arm_profile->ranges[0].begin.space = {6}; }, "undeclared range domain rejected");
        invalid([](auto &l) { l.arm_profile->ranges[0].begin.offset = 0x1100; }, "unmapped context range rejected");
        invalid([](auto &l) { l.arm_profile->ranges[0].begin.offset = 0x1040; },
                "code in non-executable mapping rejected");
        invalid(
            [](auto &l) {
                l.arm_profile->ranges[0].begin.offset = 0x104c;
                l.arm_profile->ranges[0].size = 8;
                l.segments[1].executable = true;
            },
            "code crossing into zero-fill rejected");
        invalid([](auto &l) { l.arm_profile->ranges[2].begin.offset = 0x1050; },
                "data declaration in zero-fill rejected");
        invalid(
            [](auto &l) {
                l.arm_profile->ranges[0].size = 68;
                l.arm_profile->ranges.erase(l.arm_profile->ranges.begin() + 1, l.arm_profile->ranges.end());
            },
            "context range crossing declared segment boundary rejected");
        invalid([&](auto &l) { l.arm_profile->ranges[0].kind = static_cast<Kind>(255); },
                "invalid state enum rejected");
        invalid([](auto &l) { l.arm_profile->ranges[0].sources.clear(); }, "unattributed range rejected");
        invalid([&](auto &l) { l.arm_profile->ranges[0].sources[0].kind = static_cast<Origin>(255); },
                "invalid source enum rejected");
        invalid([](auto &l) { l.arm_profile->ranges[1].sources[0].evidence.reset(); },
                "ELF declaration without file evidence rejected");
        invalid([](auto &l) { l.arm_profile->ranges[1].sources[0].evidence->size = 0; },
                "empty file evidence rejected");
        invalid([](auto &l) { l.arm_profile->ranges[1].sources[0].evidence->begin.value = 127; },
                "out-of-file evidence rejected");
        invalid([](auto &l) { l.arm_profile->ranges[1].sources[0].evidence->begin.value = UINT64_MAX; },
                "overflowing evidence rejected");
        invalid([](auto &l) { l.arm_profile->ranges[4].sources.resize(1); },
                "conflict needs multiple distinct origins");
        invalid([](auto &l) { l.space.width_bits = 64; }, "ARM32 profile in 64-bit primary domain rejected");
        invalid(
            [](auto &l) {
                l.domains[0].space.order = ByteOrder::big;
                l.domains[0].context.order = ByteOrder::big;
            },
            "big-endian secondary profile domain rejected");
        invalid([](auto &l) { l.domains[0].context.architecture = Architecture::x86; },
                "foreign profile domain rejected");
        invalid([](auto &l) { l.mode = ExecutionMode::a64; }, "foreign primary mode rejected");
        invalid([](auto &l) { l.segmented_memory = true; }, "segmented ARM context rejected");
        invalid([](auto &l) { l.stack_address_width = 32; }, "x86 stack override in ARM context rejected");
        invalid([](auto &l) { l.x86_profile.emplace(); }, "simultaneous ARM and x86 profiles rejected");
        invalid([](auto &l) { l.arm_profile->roots[1].at.offset++; }, "odd physical Thumb root rejected");
        invalid([](auto &l) { l.arm_profile->roots[1].at.offset = 0x1010; }, "data cannot be a code root");
        invalid([](auto &l) { l.arm_profile->roots[1].mode = ExecutionMode::a32; }, "root mode conflicts rejected");
        invalid([](auto &l) { l.arm_profile->roots[0].known_thumb_it_clear = true; },
                "A32 root cannot claim Thumb IT state");
        invalid([&](auto &l) { l.arm_profile->roots[1].sources = {mapping}; },
                "mapping marker alone cannot prove clear IT");
        invalid([](auto &l) { l.arm_profile->roots[1].sources.clear(); }, "unattributed root rejected");
        invalid([](auto &l) { l.arm_profile->roots.push_back(l.arm_profile->roots[0]); },
                "duplicate physical roots rejected");
        invalid([](auto &l) { l.code_exclusions.push_back({{{0}, 0x1008}, 2}); }, "excluded root rejected");
        invalid([](auto &l) { l.arm_profile->ranges.resize(1000001); }, "profile record count budget enforced");
        std::stop_source cancel;
        cancel.request_stop();
        const auto canceled = image->mapping_fingerprint(cancel.get_token());
        check(!canceled && canceled.error().code == ErrorCode::canceled, "profile mapping hash honors cancellation");
    }
}
} // namespace
int main() {
    return run([] { contexts<ImageLayout>(); });
}
