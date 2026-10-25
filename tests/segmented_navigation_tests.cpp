#include "hexlab/workspace/navigation.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/loaders/x86_raw_profile.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
using namespace hexlab;
using namespace hexlab_test;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
void coordinate_tests() {
    check(take(parse_x86_logical_address(L"1000:0010")) == X86LogicalAddress{0x1000, 0x10},
          "selector:offset uses conventional hexadecimal without decimal ambiguity");
    check(take(parse_x86_logical_address(L"0Xffff:0xFFFFFFFF")) == X86LogicalAddress{0xffff, UINT32_MAX},
          "explicit hexadecimal prefixes and full32-bit offset are accepted");
    for (auto text : {L"", L"1000", L":0", L"1000:", L"1000:0:0", L"10000:0", L"1:100000000", L"-1:0", L"1:+1", L"0x:0",
                      L"1000:0junk", L" 1000:0", L"1000:0 "})
        check(!parse_x86_logical_address(text), "malformed or oversized segmented coordinate is rejected");
    auto flat = memory_image(bytes({0x90, 0xc3}));
    check(format_location(Address{{0}, 0x1000}) == "0x1000" && format_location(Address{{7}, 0x1000}) == "va:7:0x1000" &&
              format_location(FileOffset{0xab}) == "file:0xAB",
          "generic labels retain flat spelling while exposing nonzero domain identity");
    check(!parse_segment_address(*flat, L"1000:0000"), "flat image cannot invent segment bindings");
}
X86RawProfile real_profile() {
    return {X86ImageEnvironment::real386,
            A20Policy::enabled,
            0x10000,
            {{7}, 0},
            {},
            {{{7}, 0x1000, true, "caller", {}}, {{2}, 0x1001, true, "callee", {}}}};
}
std::vector<std::byte> input_bytes() {
    auto input = bytes({0x9a, 0, 0, 0x01, 0x10, 0xc3});
    input.resize(16, std::byte{0x90});
    input.push_back(std::byte{0x90});
    input.push_back(std::byte{0xcb});
    return input;
}
void profile_tests() {
    auto p = real_profile();
    auto image = take(load_raw(std::make_shared<MemoryStorage>(input_bytes()), take(make_x86_raw_options(p)), {}));
    check(take(parse_segment_address(*image, L"1001:0000")) == Address{{2}, 0} &&
              format_location(Address{{7}, 0}, image.get()) == "1000:0000" &&
              format_location(Address{{2}, 0}, image.get()) == "1001:0000",
          "profile parsing and formatting distinguish logical aliases by declared selector");
    check(!parse_segment_address(*image, L"1234:0000") && !parse_segment_address(*image, L"1000:10000"),
          "unknown selectors and real-mode offsets beyond64KiB fail instead of wrapping");
    p.environment = X86ImageEnvironment::protected386;
    p.stack_selector = std::uint16_t{0x18};
    p.domains = {
        {{7}, 8, true, "16", X86SegmentDescriptor{0x10000, 0xffff, true, true, true, false, false, false, false, 0}},
        {{2}, 0x10, true, "32", X86SegmentDescriptor{0x10010, 0xffff, true, true, true, false, false, true, false, 0}},
        {{3}, 0x18, false, "stack", X86SegmentDescriptor{0, 0xffff, true, false, true, true, false, false, false, 0}}};
    image = take(load_raw(std::make_shared<MemoryStorage>(input_bytes()), take(make_x86_raw_options(p)), {}));
    check(format_location(Address{{7}, 0}, image.get()) == "0008:0000" &&
              format_location(Address{{2}, 0}, image.get()) == "0010:00000000" &&
              take(parse_segment_address(*image, L"0010:00000000")) == Address{{2}, 0},
          "protected labels use the selected code domain's offset width");
    check(!parse_segment_address(*image, L"0010:00010000"), "protected selector navigation respects declared limit");
}
void follow_tests() {
    FixtureFile marker(std::span<const std::byte>{});
    const std::filesystem::path path = marker.path.wstring() + L".navigation.hxproj";
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() {
            std::error_code ignored;
            for (auto suffix : {L"", L"-wal", L"-shm"}) {
                auto file = path;
                file += suffix;
                std::filesystem::remove(file, ignored);
            }
        }
    } cleanup{path};
    auto store = take(database::ProjectStore::create(path, {}));
    MemoryStorage source(input_bytes());
    take(store->import_input(source, {Format::raw, take(make_x86_raw_options(real_profile()))}, {}, {}));
    auto session = take(ProjectSession::attach(store, {}, {}));
    auto snapshot = session->snapshot();
    check(take(project_follow_target(*snapshot, {{7}, 0})) == Address{{2}, 0},
          "far Follow resolves the current decoded reference while pure decoder target stays symbolic");
    check(!take(project_follow_target(*snapshot, {{7}, 5})), "return has no invented follow target");
    auto stale = *snapshot;
    stale.status = DerivedStatus::stale;
    check(!project_follow_target(stale, {{7}, 0}), "stale reference facts cannot drive Follow");
    take(session->execute(PatchBytes{FileOffset{0}, bytes({0xcc})}, 0, {}));
    check(!project_follow_target(*session->snapshot(), {{7}, 0}), "byte edits disable old far Follow immediately");
}
} // namespace
int main() {
    return run([] {
        coordinate_tests();
        profile_tests();
        follow_tests();
    });
}
