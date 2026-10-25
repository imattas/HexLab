#include "hexlab/image/image.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
namespace {
ImageLayout layout() {
    ImageLayout l{{{7}, 64, 1, ByteOrder::little},
                  Architecture::x86_64,
                  ExecutionMode::x86_64,
                  {{"primary", {{7}, 0x1000}, 4, {0}, 4, true, false, true},
                   {"second", {{8}, 0x1000}, 4, {4}, 4, true, false, true},
                   {"adjacent", {{8}, 0x1004}, 2, {0}, 2, true, false, false},
                   {"first-numerically", {{2}, 0x1000}, 4, {0}, 4, true, false, false}},
                  {{{7}, 0x1000}, {{8}, 0x1000}}};
    l.domains.push_back(
        {{{8}, 32, 1, ByteOrder::little}, {Architecture::x86, ExecutionMode::x86_32, ByteOrder::little}});
    l.domains.push_back(
        {{{2}, 16, 1, ByteOrder::little}, {Architecture::x86, ExecutionMode::x86_16, ByteOrder::little}});
    return l;
}
void domains() {
    auto storage =
        std::make_shared<MemoryStorage>(std::vector<std::byte>{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
                                                               std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}});
    auto made = Image::create(storage, layout());
    check(made.has_value(), "repeated offsets across domains accepted");
    if (!made)
        return;
    const auto &image = *made.value();
    check(image.layout().segments.front().begin.space == AddressSpaceId{2}, "segments sort by domain then offset");
    check(image.space({7}) && image.space({7})->width_bits == 64 && image.space({8})->width_bits == 32 &&
              !image.space({99}),
          "domain lookup primary additional absent");
    check(image.context_at({{7}, 0x1000}).value() == image.decode_context(), "primary context compatibility");
    check(image.context_at({{8}, 0x1000}).value().mode == ExecutionMode::x86_32 &&
              image.context_at({{2}, 0x1000}).value().mode == ExecutionMode::x86_16,
          "per-domain execution mode");
    check(!image.context_at({{99}, 0}) && !image.context_at({{2}, 0x10000}),
          "context never inherits missing or out-of-domain address");
    check(image.read({{7}, 0x1000}, 1).value()[0] == std::byte{1} &&
              image.read({{8}, 0x1000}, 1).value()[0] == std::byte{5},
          "same offset different bytes");
    check(image.read({{8}, 0x1003}, 3).value() == std::vector<std::byte>{std::byte{8}, std::byte{1}, std::byte{2}},
          "adjacent read stays in its domain");
    check(!image.read({{7}, 0x1003}, 2), "adjacent mapping in another domain does not fill a gap");
    check(!image.read({{99}, 0}, 0), "empty read rejects undeclared domain");
    check(image.to_file_offset({{8}, 0x1001}).value() == FileOffset{5}, "domain file mapping");
    check(!image.to_address({0}), "aliased file position remains ambiguous across domains");
    check(image.to_address({5}).value() == Address{{8}, 0x1001}, "unique reverse mapping retains domain");
    auto bad = layout();
    bad.domains.push_back(bad.domains.front());
    check(!Image::create(storage, bad), "duplicate additional domain rejected");
    bad = layout();
    bad.domains.front().space.id = {7};
    check(!Image::create(storage, bad), "additional cannot shadow primary domain");
    bad = layout();
    bad.domains.front().context.order = ByteOrder::big;
    check(!Image::create(storage, bad), "domain context order must match space");
    bad = layout();
    bad.domains.front().space.unit_bytes = 2;
    check(!Image::create(storage, bad), "additional domain must be byte addressed");
    bad = layout();
    bad.segments[1].begin.space = {99};
    check(!Image::create(storage, bad), "undeclared segment domain rejected");
    bad = layout();
    bad.segments.push_back({"overlap", {{8}, 0x1001}, 1, {0}, 1, true, false, false});
    check(!Image::create(storage, bad), "overlap within domain rejected");
    bad = layout();
    bad.segments[3].begin.offset = 0xffff;
    check(!Image::create(storage, bad), "additional domain width enforced");
    bad = layout();
    bad.entries.push_back({{99}, 0x1000});
    check(!Image::create(storage, bad), "entry domain validated");
    auto primary = layout();
    primary.architecture = Architecture::x86;
    primary.mode = ExecutionMode::x86_32;
    primary.stack_address_width = 16;
    primary.segmented_memory = true;
    auto explicit_context = Image::create(storage, primary).value();
    check(explicit_context->decode_context() ==
                  DecodeContext{Architecture::x86, ExecutionMode::x86_32, ByteOrder::little, 16, true} &&
              explicit_context->context_at({{7}, 0x1000}).value() == explicit_context->decode_context(),
          "primary domain retains authoritative stack and memory attributes");
    auto digest = image.mapping_fingerprint({}).value();
    auto reordered = layout();
    std::reverse(reordered.segments.begin(), reordered.segments.end());
    check(Image::create(storage, reordered).value()->mapping_fingerprint({}).value() == digest,
          "mapping fingerprint normalizes segment ordering");
    auto changed = layout();
    changed.domains[0].context.segmented_memory = true;
    check(Image::create(storage, changed).value()->mapping_fingerprint({}).value() != digest,
          "mapping fingerprint binds nonprimary execution attributes");
    changed = layout();
    changed.segments[1].file_begin = {3};
    check(Image::create(storage, changed).value()->mapping_fingerprint({}).value() != digest,
          "mapping fingerprint binds canonical backing intersections");
    std::stop_source stopped;
    stopped.request_stop();
    check(!image.mapping_fingerprint(stopped.get_token()), "mapping fingerprint honors cancellation");
}
void segmented_queries() {
    auto storage = std::make_shared<MemoryStorage>(std::vector<std::byte>(32));
    ImageLayout l{
        {{1}, 16, 1, ByteOrder::little},
        Architecture::x86,
        ExecutionMode::x86_16,
        {{"a", {{1}, 0x10}, 16, {0}, 16, true, false, true}, {"alias", {{2}, 0}, 16, {0}, 16, true, false, true}},
        {{{1}, 0x10}}};
    l.domains = {{{{2}, 16, 1, ByteOrder::little}, {Architecture::x86, ExecutionMode::x86_16, ByteOrder::little}}};
    l.x86_profile =
        X86ImageProfile{X86ImageEnvironment::real386, A20Policy::disabled, {{{1}, 0x1000, {}}, {{2}, 0x1001, {}}}};
    auto made = Image::create(storage, l);
    check(made.has_value(), "real segmented image profile accepted");
    if (!made)
        return;
    const auto &image = *made.value();
    check(image.logical_address({{1}, 0x10}).value() == X86LogicalAddress{0x1000, 0x10}, "domain to selector offset");
    check(image.from_logical({0x1001, 0}).value() == Address{{2}, 0}, "selector offset to stable domain");
    check(!image.from_logical({0x1002, 0}) && !image.logical_address({{99}, 0}), "unknown selectors and domains fail");
    auto first = image.linear_spans({{1}, 0x10}, 16, X86SegmentAccess::execute).value();
    auto second = image.linear_spans({{2}, 0}, 16, X86SegmentAccess::execute).value();
    check(first == second && first.spans[0] == X86LinearSpan{{0x10010}, 16}, "domain aliases share linear span");
    check(image.physical_spans({{1}, 0x10}, 16).value().spans[0] == X86PhysicalSpan{{0x10010}, 16},
          "real physical span query");
    check(!image.linear_spans({{1}, 0xffff}, 2, X86SegmentAccess::read), "image translation checks complete span");
    check(!image.to_address({0}), "segmented aliases never pick arbitrary reverse address");
    auto bad = l;
    bad.x86_profile->bindings[1].selector = 0x1000;
    check(!Image::create(storage, bad), "duplicate profile selector rejected");
    bad = l;
    bad.x86_profile->bindings[1].space = {99};
    check(!Image::create(storage, bad), "profile binding must name declared domain");
    bad = l;
    bad.x86_profile->bindings.pop_back();
    check(!Image::create(storage, bad), "profile must bind every declared domain");
    bad = l;
    bad.x86_profile->environment = static_cast<X86ImageEnvironment>(99);
    check(!Image::create(storage, bad), "invalid profile environment rejected");
    bad = l;
    bad.x86_profile->a20 = static_cast<A20Policy>(99);
    check(!Image::create(storage, bad), "invalid profile A20 rejected");
    bad = l;
    bad.x86_profile->bindings[0].descriptor = X86SegmentDescriptor{};
    check(!Image::create(storage, bad), "real profile cannot contain protected descriptor");
    bad = l;
    bad.mode = ExecutionMode::x86_32;
    check(!Image::create(storage, bad), "real profile requires default16 context");
    bad = l;
    bad.domains[0].context.stack_address_width = 32;
    check(!Image::create(storage, bad), "real profile cannot declare an unreal32 stack address attribute");
    bad = l;
    bad.domains[0].context.stack_address_width = 8;
    check(!Image::create(storage, bad), "profile context rejects invalid explicit stack address width");

    l.segments.resize(1);
    l.domains.clear();
    l.entries = {{{1}, 0x10}};
    l.space.width_bits = 32;
    X86SegmentDescriptor descriptor{0xfffffff0, UINT32_MAX, true, true, true, false, false, false, false, 0};
    l.x86_profile = X86ImageProfile{X86ImageEnvironment::protected386, A20Policy::enabled, {{{1}, 8, descriptor}}};
    made = Image::create(storage, l);
    check(made.has_value(), "protected16 large offset domain accepted");
    if (!made)
        return;
    auto translated = made.value()->linear_spans({{1}, 0}, 32, X86SegmentAccess::execute);
    check(translated && translated.value().count == 2 && translated.value().spans[1] == X86LinearSpan{{0}, 16},
          "protected image retains linear wrap fragments");
    check(!made.value()->physical_spans({{1}, 0}, 1),
          "protected linear address not assumed physical without paging model");
    check(made.value()->from_logical({8, 0x10000}).has_value(), "D0 permits effective offset above64KiB if declared");
    bad = l;
    bad.x86_profile->bindings[0].descriptor.reset();
    check(!Image::create(storage, bad), "protected binding requires descriptor");
    bad = l;
    bad.x86_profile->bindings[0].descriptor->default_big = true;
    check(!Image::create(storage, bad), "protected code DB must match execution context");
    bad = l;
    bad.x86_profile->bindings[0].selector = 0;
    check(!Image::create(storage, bad), "protected null selector rejected");
    bad = l;
    bad.x86_profile->bindings[0].descriptor->effective_limit = 0x10;
    check(!Image::create(storage, bad), "profile validates complete mapped segment extent");
    auto rpl_alias = l;
    rpl_alias.domains.push_back(
        {{{2}, 32, 1, ByteOrder::little}, {Architecture::x86, ExecutionMode::x86_16, ByteOrder::little}});
    auto alias_segment = l.segments.front();
    alias_segment.begin.space = {2};
    rpl_alias.segments.push_back(alias_segment);
    rpl_alias.x86_profile->bindings.push_back({{2}, 9, descriptor});
    check(Image::create(storage, rpl_alias).has_value(), "RPL variants may share an identical descriptor");
    rpl_alias.x86_profile->bindings.back().descriptor->base = 0;
    check(!Image::create(storage, rpl_alias),
          "same GDT index with different RPL cannot declare conflicting descriptors");
}
} // namespace
int main() {
    return run([] {
        domains();
        segmented_queries();
    });
}
