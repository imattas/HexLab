#include "hexlab/loaders/recipe.hpp"
#include "hexlab/workspace/open_recipe.hpp"
#include "hexlab/workspace/project.hpp"
#include "support/analysis_fixture.hpp"
#include "support/fixture_files.hpp"
#include "support/checks.hpp"
#include <algorithm>
#if __has_include("hexlab/loaders/arm_raw_profile.hpp")
#include "hexlab/loaders/arm_raw_profile.hpp"
#define ARM_RAW_PROFILE_AVAILABLE
#endif
using namespace hexlab;
using namespace hexlab_test;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
const std::string literal = "hexlab-arm-profile 1\nbase 7 0x1000\npermissions r-x\nentry 0x1008 thumb-clear\nranges 3\n"
                            "range 0x1000 0x8 a32\nrange 0x1008 0x4 thumb\nrange 0x100c 0x4 data\n";
std::vector<std::byte> recipe_bytes(std::string_view text) {
    std::vector<std::byte> result{std::byte{3}, std::byte{0}, std::byte{6}};
    for (auto shift : {24, 16, 8, 0})
        result.push_back(std::byte(text.size() >> shift));
    auto raw = std::as_bytes(std::span(text));
    result.insert(result.end(), raw.begin(), raw.end());
    return result;
}
void recipe_contract() {
    const auto restored = decode_recipe(recipe_bytes(literal));
    check(bool(restored), "literal recipe v3 kind6 embeds an authoritative durable ARM raw profile");
}
#ifdef ARM_RAW_PROFILE_AVAILABLE
std::vector<std::byte> code() {
    return bytes({0x00, 0x00, 0xa0, 0xe1, 0x1e, 0xff, 0x2f, 0xe1, 0x00, 0xbf, 0x70, 0x47, 0x11, 0x22, 0x33, 0x44});
}
void profiles() {
    const auto profile = take(parse_arm_profile(literal));
    check(profile.base == Address{{7}, 0x1000} && profile.entry && profile.entry->offset == 0x1008 &&
              profile.entry->mode == ExecutionMode::thumb && profile.entry->known_thumb_it_clear &&
              profile.ranges.size() == 3 && profile.ranges[2].kind == ArmCodeKind::data,
          "literal text retains physical coordinates, code/data states and explicit IT entry claim");
    check(take(format_arm_profile(profile)) == literal, "ARM profile has a stable literal canonical encoding");
    auto reordered = profile;
    std::reverse(reordered.ranges.begin(), reordered.ranges.end());
    check(take(format_arm_profile(reordered)) == literal,
          "canonical profile range order is independent of input order");
    auto human = std::string("\xef\xbb\xbf# note \xce\xbb\n") + literal + "# tail\n";
    check(take(parse_arm_profile(human)) == profile, "bounded UTF8 comments and BOM are accepted for human profiles");
    auto raw = take(make_arm_raw_options(profile));
    check(raw.architecture == Architecture::arm && raw.mode == ExecutionMode::unknown && raw.base == profile.base &&
              raw.entry == Address{{7}, 0x1008} && raw.arm_profile == profile && !raw.x86_profile,
          "raw options retain the complete profile without a global code mode assumption");
    const auto recipe = take(encode_recipe({Format::raw, raw}));
    check(recipe == recipe_bytes(literal), "ARM recipe embeds exact canonical text rather than an external file path");
    const auto restored = take(decode_recipe(recipe));
    check(restored.raw->arm_profile == profile && take(encode_recipe(restored)) == recipe,
          "complete ARM declaration recipe roundtrips");
    for (std::size_t n = 0; n < recipe.size(); ++n)
        check(!decode_recipe(std::span(recipe).first(n)), "every truncated ARM recipe is rejected");
    auto trailing = recipe;
    trailing.push_back(std::byte{0});
    check(!decode_recipe(trailing) && !decode_recipe(recipe_bytes(human)),
          "durable ARM recipe rejects trailing bytes and noncanonical human text");
    const auto invalid = [&](auto change, const char *message) {
        auto p = profile;
        change(p);
        check(!validate_arm_profile(p) && !format_arm_profile(p) && !make_arm_raw_options(p), message);
    };
    invalid([](auto &p) { p.ranges[1].begin = 0x1004; }, "overlapping raw declarations rejected");
    invalid([](auto &p) { p.ranges[0].begin++; }, "misaligned A32 range rejected");
    invalid([](auto &p) { p.ranges[1].size = 3; }, "partial Thumb unit rejected");
    invalid([](auto &p) { p.ranges[0].size = 0; }, "zero range extent rejected");
    invalid([](auto &p) { p.ranges[0].size = UINT64_MAX; }, "overflowing range extent rejected");
    invalid([](auto &p) { p.ranges[0].begin = 0xffc; }, "range before raw base rejected");
    invalid([](auto &p) { p.ranges[0].kind = ArmCodeKind::conflict; },
            "raw overlapping conflict must be resolved explicitly");
    invalid([](auto &p) { p.executable = false; }, "code declarations need executable mapping permission");
    invalid([](auto &p) { p.base.offset = UINT64_C(0x100000000); }, "raw base exceeds ARM32 domain rejected");
    invalid([](auto &p) { p.entry->offset++; }, "odd physical Thumb entry rejected");
    invalid([](auto &p) { p.entry->offset = 0x100c; }, "data entry rejected");
    invalid([](auto &p) { p.entry->mode = ExecutionMode::a32; }, "entry mode contradicting its range rejected");
    invalid([](auto &p) { p.entry = ArmRawEntry{0x1000, ExecutionMode::a32, true}; },
            "A32 entry cannot claim Thumb IT state");
    invalid([](auto &p) { p.ranges.resize(arm_profile_range_limit + 1); }, "raw range count budget enforced");
    for (auto bad :
         {"hexlab-arm-profile 2\n", "hexlab-arm-profile 1\n", "base 0 0\n", "hexlab-arm-profile 1\nbase 0 -1\n",
          "hexlab-arm-profile 1\nbase 0 0x100000000\n", "hexlab-arm-profile 1\nbase 0 0\nbase 0 0\n"})
        check(!parse_arm_profile(bad), "invalid version, missing fields and invalid unsigned numeric fields rejected");
    check(!parse_arm_profile(std::string(arm_profile_text_limit + 1, ' ')) &&
              !parse_arm_profile(literal + std::string(4097, ' ')) &&
              !parse_arm_profile(literal + std::string("\0", 1)) && !parse_arm_profile(literal + "unknown field\n"),
          "text, line, UTF8 and unknown field bounds enforced");
    std::stop_source stop;
    stop.request_stop();
    check(!parse_arm_profile(literal, stop.get_token()) && !format_arm_profile(profile, stop.get_token()) &&
              !validate_arm_profile(profile, stop.get_token()),
          "raw profile CPU operations honor cancellation");
    FixtureFile file(std::as_bytes(std::span(human)));
    check(take(read_arm_profile(file.path, {})) == profile && !read_arm_profile(file.path, stop.get_token()),
          "bounded raw profile file reader normalizes text and honors cancellation");
    auto storage = std::make_shared<MemoryStorage>(code());
    const auto image = take(load_raw(storage, raw, {}));
    check(image->layout().arm_profile && image->layout().entries == std::vector<Address>{{{7}, 0x1008}} &&
              take(image->context_at({{7}, 0x1000})).mode == ExecutionMode::a32 &&
              take(image->context_at({{7}, 0x1008})).mode == ExecutionMode::thumb &&
              image->code_window({{7}, 0x100c}, 4) == 0,
          "raw mapping uses authoritative physical range contexts");
    check(image->arm_code_at({{7}, 0x1008})->sources ==
                  std::vector<ArmContextSource>{{ArmContextSourceKind::raw_declaration, 0, 2, {}}} &&
              image->layout().arm_profile->roots[0].sources[0].record_index == 0 &&
              image->layout().arm_profile->roots[0].known_thumb_it_clear,
          "raw declaration identities come from canonical range ordinals and explicit entry");
    const auto a32 = take(decode_at(*image, {{7}, 0x1000})), thumb = take(decode_at(*image, {{7}, 0x1008}));
    check(a32.instruction && a32.instruction->context.mode == ExecutionMode::a32 && thumb.instruction &&
              thumb.instruction->context.mode == ExecutionMode::thumb,
          "manual shared decoding consumes the per-address A32/Thumb context");
    check(!load_raw(std::make_shared<MemoryStorage>(std::vector<std::byte>(8)), raw, {}),
          "raw source shorter than declared ranges rejected at mapping time");
    auto contradictory = raw;
    contradictory.base.offset++;
    check(!validate_raw_coordinates(contradictory) && !encode_recipe({Format::raw, contradictory}),
          "flat fields cannot contradict their embedded ARM profile");
    contradictory = raw;
    contradictory.x86_profile.emplace();
    check(!validate_raw_coordinates(contradictory), "simultaneous ARM and x86 profiles rejected");
    auto no_entry = profile;
    no_entry.entry.reset();
    no_entry.ranges.clear();
    const auto uncovered = take(load_raw(storage, take(make_arm_raw_options(no_entry)), {}));
    check(uncovered->layout().entries.empty() && uncovered->code_window({{7}, 0x1000}, 4) == 0,
          "empty explicit raw profile does not infer an entry or code from storage bytes");
}
void opening_and_project() {
    FixtureFile input(code()), profile_file(std::as_bytes(std::span(literal)));
    OpenRequest request;
    request.format = Format::raw;
    request.path = input.path;
    request.arm_profile_path = profile_file.path;
    const auto recipe = take(resolve_open_recipe(request, {}));
    check(recipe.raw && recipe.raw->arm_profile, "opening worker embeds parsed ARM declarations before import");
    auto bad = request;
    bad.x86_profile_path = profile_file.path;
    check(!resolve_open_recipe(bad, {}), "conflicting external profile intents rejected");
    bad = request;
    bad.raw = recipe.raw;
    check(!resolve_open_recipe(bad, {}), "flat and ARM-profile opening intents are mutually exclusive");
    bad = request;
    bad.format = Format::automatic;
    check(!resolve_open_recipe(bad, {}), "ARM profile requires explicit raw format");
    const auto path = std::filesystem::path(input.path.wstring() + L".armraw.hxproj");
    const auto copy_path = std::filesystem::path(input.path.wstring() + L".armraw-copy.hxproj");
    auto store = take(database::ProjectStore::create(path, {}));
    auto original = take(FileStorage::open(input.path));
    take(store->import_input(*original, recipe, input.path, {}));
    original.reset();
    auto session = take(ProjectSession::attach(store, {}, {}));
    check(session->snapshot()->functions &&
              session->snapshot()->functions->functions.size() == 1 &&
              session->snapshot()->functions->functions.front()->entry == Address{{7}, 0x1008},
          "source-backed Thumb-clear raw entry recovers its bounded project function");
    take(session->execute(Rename{Address{{7}, 0x1008}, "thumb_entry"}, 0, {}));
    const auto old_byte = code()[12];
    take(session->execute(PatchBytes{FileOffset{12}, {std::byte{0x55}}}, 0, {}));
    take(session->undo({}));
    take(session->refresh_analysis({}));
    check(take(session->snapshot()->loaded->image->read({{7}, 0x100c}, 1))[0] == old_byte,
          "raw-profile project patch undo restores bytes");
    take(session->redo({}));
    take(session->refresh_analysis({}));
    check(take(session->snapshot()->loaded->image->read({{7}, 0x100c}, 1))[0] == std::byte{0x55} &&
              presentation_name(*session->snapshot(), Address{{7}, 0x1008}) == "thumb_entry",
          "redo retains mode declarations and annotations");
    take(store->save_as(copy_path, database::ReplacePolicy::fail_if_exists, {}));
    const auto final_state = session->snapshot()->state;
    session.reset();
    store.reset();
    check(std::filesystem::remove(input.path) && std::filesystem::remove(profile_file.path),
          "owned external binary and profile removed before durable readonly reopen");
    store = take(database::ProjectStore::open(path, database::ProjectMode::read_only, {}));
    session = take(ProjectSession::attach(store, {}, {}));
    check(session->snapshot()->state->uuid == final_state->uuid &&
              session->snapshot()->state->history_cursor == final_state->history_cursor &&
              *session->snapshot()->state->user == *final_state->user &&
              session->snapshot()->loaded->image->layout().arm_profile &&
              take(session->snapshot()->loaded->image->context_at({{7}, 0x1008})).mode == ExecutionMode::thumb &&
              presentation_name(*session->snapshot(), Address{{7}, 0x1008}) == "thumb_entry",
          "source-missing readonly reopen preserves complete declarations, identity, history and annotations");
    session.reset();
    store.reset();
    auto copied = take(database::ProjectStore::open(copy_path, database::ProjectMode::read_only, {}));
    auto copied_session = take(ProjectSession::attach(copied, {}, {}));
    check(copied_session->snapshot()->state->uuid != final_state->uuid &&
              copied_session->snapshot()->loaded->image->layout().arm_profile &&
              take(copied_session->snapshot()->loaded->image->read({{7}, 0x100c}, 1))[0] == std::byte{0x55},
          "Save As retains effective bytes and durable profile with new project identity");
    copied_session.reset();
    copied.reset();
    std::error_code ignored;
    for (const auto &base : {path, copy_path})
        for (auto suffix : {L"", L"-wal", L"-shm"}) {
            auto item = base;
            item += suffix;
            std::filesystem::remove(item, ignored);
        }
}
#endif
} // namespace
int main() {
    return run([] {
        recipe_contract();
#ifdef ARM_RAW_PROFILE_AVAILABLE
        profiles();
        opening_and_project();
#endif
    });
}
