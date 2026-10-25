#include "hexlab/core/x86_segments.hpp"
#include "hexlab/core/address.hpp"
#include "support/checks.hpp"
#include <array>
#include <limits>
#include <type_traits>

using namespace hexlab;
using hexlab_test::check;
static_assert(std::is_trivially_copyable_v<X86LogicalAddress>);
static_assert(std::is_trivially_copyable_v<X86LinearAddress>);
static_assert(std::is_trivially_copyable_v<X86PhysicalAddress>);
static_assert(!std::is_convertible_v<X86LinearAddress, FileOffset>);
static_assert(!std::is_convertible_v<X86PhysicalAddress, X86LinearAddress>);

namespace {
std::array<std::byte, 8> bytes(std::array<unsigned char, 8> raw) {
    std::array<std::byte, 8> result{};
    for (std::size_t i = 0; i < raw.size(); ++i)
        result[i] = std::byte{raw[i]};
    return result;
}
void real_mode() {
    auto a = x86_real_linear({0x1234, 0x5678}, 1);
    check(a && a.value().begin.value == 0x179b8 && a.value().size == 1, "real literal translation");
    const X86LogicalAddress first{0x1000, 0x10}, alias{0x1001, 0};
    check(first != alias && x86_real_linear(first, 1).value() == x86_real_linear(alias, 1).value(),
          "logical aliases retain separate identity");
    auto high = x86_real_physical({0xffff, 0xffff}, 1, A20Policy::enabled);
    check(high && high.value().count == 1 && high.value().spans[0].begin.value == 0x10ffef,
          "enabled A20 retains bit20");
    auto low = x86_real_physical({0xffff, 0xffff}, 1, A20Policy::disabled);
    check(low && low.value().spans[0].begin.value == 0xffef, "disabled A20 masks bit20");
    auto split = x86_real_physical({0xffff, 0xf}, 2, A20Policy::disabled);
    check(split && split.value().count == 2 && split.value().spans[0] == X86PhysicalSpan{{0xfffff}, 1} &&
              split.value().spans[1] == X86PhysicalSpan{{0}, 1},
          "physical wrap splits backing spans");
    check(x86_real_linear({0, 0xffff}, 1).has_value(), "last logical byte is valid");
    check(!x86_real_linear({0, 0xffff}, 2), "386 real word crossing segment limit fails");
    check(!x86_real_linear({0, 0x10000}, 0), "empty span requires valid logical point");
    check(x86_real_linear({0, 0}, 0x10000).has_value(), "complete 64KiB segment access");
    check(!x86_real_linear({0, 1}, 0x10000), "complete access must fit segment");
    check(!x86_real_linear({0, 1}, UINT64_MAX), "oversized access cannot overflow validation");
    check(x86_real_physical({0, 0}, 0, A20Policy::enabled).value().count == 0, "empty physical result");
    check(!x86_real_physical({0, 0}, 1, static_cast<A20Policy>(99)), "invalid A20 policy rejected");
    for (unsigned selector : {0u, 1u, 0x1234u, 0xffffu}) {
        for (unsigned offset : {0u, 1u, 0xfffeu, 0xffffu}) {
            auto point = x86_real_linear({static_cast<std::uint16_t>(selector), offset}, 1);
            check(point && point.value().begin.value == selector * 16u + offset, "selected real points");
        }
    }
}
void protected_mode() {
    const auto raw = bytes({0xff, 0xff, 0x00, 0x50, 0x34, 0x92, 0x40, 0x12});
    auto parsed = parse_x86_segment_descriptor(raw);
    check(parsed.has_value(), "parse exact eight-byte descriptor");
    if (!parsed)
        return;
    auto d = parsed.value();
    check(d.base == 0x12345000 && d.effective_limit == 0xffff && d.present && !d.executable && d.readable &&
              d.writable && !d.expand_down && d.default_big && !d.conforming && d.dpl == 0,
          "literal base limit access and DB");
    auto p = x86_protected_linear(d, {8, 0x123}, 2, X86SegmentAccess::read);
    check(p && p.value().count == 1 && p.value().spans[0] == X86LinearSpan{{0x12345123}, 2},
          "protected literal translation");
    check(!x86_protected_linear(d, {8, 0xffff}, 2, X86SegmentAccess::read), "protected complete access limit");
    check(x86_protected_linear(d, {8, 0xffff}, 0, X86SegmentAccess::read).value().count == 0,
          "empty protected span validates point");
    check(!x86_protected_linear(d, {8, 0x10000}, 0, X86SegmentAccess::read), "invalid empty protected point");
    for (std::uint16_t s = 0; s != 4; ++s)
        check(!x86_protected_linear(d, {s, 0}, 1, X86SegmentAccess::read), "null GDT selector rejected");
    check(x86_protected_linear(d, {4, 0}, 1, X86SegmentAccess::read).has_value(), "LDT index zero not null");
    check(!x86_protected_linear(d, {8, 0}, 1, X86SegmentAccess::execute), "data not executable");
    check(!x86_protected_linear(d, {8, 0}, UINT64_MAX, X86SegmentAccess::read), "protected length overflow rejected");
    check(!x86_protected_linear(d, {8, 0}, 1, static_cast<X86SegmentAccess>(99)), "invalid access rejected");
    d.present = false;
    check(!x86_protected_linear(d, {8, 0}, 0, X86SegmentAccess::read), "absent even for empty access");
    d = parsed.value();
    d.writable = false;
    check(!x86_protected_linear(d, {8, 0}, 1, X86SegmentAccess::write), "read-only data not writable");
    check(!x86_protected_linear(d, {8, 0}, 1, X86SegmentAccess::stack), "stack requires writable data");

    auto code = parse_x86_segment_descriptor(bytes({0xff, 0xff, 0, 0, 0, 0xfe, 0, 0}));
    check(code && code.value().executable && code.value().readable && code.value().conforming &&
              code.value().dpl == 3 && !code.value().default_big,
          "code conforming DPL literal");
    if (code) {
        check(x86_protected_linear(code.value(), {8, 0}, 1, X86SegmentAccess::execute).has_value(), "code execute");
        check(!x86_protected_linear(code.value(), {8, 0}, 1, X86SegmentAccess::write), "code not writable");
        check(!x86_protected_linear(code.value(), {8, 0}, 1, X86SegmentAccess::stack), "code not stack");
        auto execute_only = code.value();
        execute_only.readable = false;
        check(!x86_protected_linear(execute_only, {8, 0}, 1, X86SegmentAccess::read), "execute-only code not readable");
    }
    auto granular = parse_x86_segment_descriptor(bytes({0, 0, 0, 0, 0, 0x92, 0x80, 0}));
    check(granular && granular.value().effective_limit == 0xfff, "G expands zero limit to 4095");
    for (std::size_t n = 0; n < 8; ++n)
        check(!parse_x86_segment_descriptor(std::span(raw).first(n)), "truncated descriptor rejected");
    std::array<std::byte, 9> trailing{};
    check(!parse_x86_segment_descriptor(trailing), "extra descriptor bytes rejected");
    check(!parse_x86_segment_descriptor(bytes({0, 0, 0, 0, 0, 0x82, 0, 0})), "system descriptor unsupported");
    check(!parse_x86_segment_descriptor(bytes({0, 0, 0, 0, 0, 0x9a, 0x20, 0})), "long code unsupported");
    check(!parse_x86_segment_descriptor(bytes({0, 0, 0, 0, 0, 0x92, 0x20, 0})), "reserved data L rejected");

    auto down = parse_x86_segment_descriptor(bytes({0xff, 0x7f, 0, 0, 0, 0x96, 0, 0})).value();
    check(down.expand_down && !down.default_big, "expand-down16 literal");
    check(!x86_protected_linear(down, {8, 0x7fff}, 1, X86SegmentAccess::stack), "expand-down excludes limit");
    check(x86_protected_linear(down, {8, 0x8000}, 0x8000, X86SegmentAccess::stack).has_value(),
          "expand-down16 complete upper half");
    check(!x86_protected_linear(down, {8, 0xffff}, 2, X86SegmentAccess::stack), "expand-down16 upper bound");
    check(!x86_protected_linear(down, {8, 0x10000}, 0, X86SegmentAccess::stack), "expand-down16 invalid empty point");
    down.default_big = true;
    check(x86_protected_linear(down, {8, 0xfffffff0}, 16, X86SegmentAccess::stack).has_value(),
          "expand-down32 high access");
    check(!x86_protected_linear(down, {8, 0xfffffff0}, 17, X86SegmentAccess::stack), "expand-down32 upper bound");
    down.effective_limit = UINT32_MAX;
    check(!x86_protected_linear(down, {8, UINT32_MAX}, 0, X86SegmentAccess::read), "empty expand-down domain invalid");

    d = parsed.value();
    d.base = 0xfffffff0;
    d.effective_limit = UINT32_MAX;
    d.default_big = false;
    auto wrap = x86_protected_linear(d, {8, 0}, 32, X86SegmentAccess::read);
    check(wrap && wrap.value().count == 2 && wrap.value().spans[0] == X86LinearSpan{{0xfffffff0}, 16} &&
              wrap.value().spans[1] == X86LinearSpan{{0}, 16},
          "linear32 base addition wraps into two spans");
    check(x86_protected_linear(d, {8, 0x10000}, 1, X86SegmentAccess::read).has_value(),
          "DB0 does not truncate 32-bit effective offset");
    d.base = 0;
    auto full = x86_protected_linear(d, {8, 0}, UINT64_C(0x100000000), X86SegmentAccess::read);
    check(full && full.value().count == 1 && full.value().spans[0].size == UINT64_C(0x100000000),
          "full 4GiB domain span");
    check(!x86_protected_linear(d, {8, 1}, UINT64_C(0x100000000), X86SegmentAccess::read), "4GiB span offset overrun");
    d.dpl = 4;
    check(!x86_protected_linear(d, {8, 0}, 1, X86SegmentAccess::read), "invalid descriptor DPL rejected");
}
} // namespace
int main() {
    return hexlab_test::run([] {
        real_mode();
        protected_mode();
    });
}
