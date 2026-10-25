#include "hexlab/core/x86_segments.hpp"
#include <algorithm>
#include <limits>

namespace hexlab {
namespace {
bool valid_descriptor(const X86SegmentDescriptor &d) noexcept {
    if (d.dpl > 3)
        return false;
    if (d.executable)
        return !d.writable && !d.expand_down;
    return d.readable && !d.conforming;
}
} // namespace

Result<X86LinearSpan> x86_real_linear(X86LogicalAddress address, std::uint64_t size) {
    if (address.offset > 0xffff || size > UINT64_C(0x10000) - address.offset)
        return Error{ErrorCode::out_of_bounds, "Real-mode access exceeds the 386 segment limit"};
    return X86LinearSpan{{static_cast<std::uint32_t>(address.selector) * 16u + address.offset}, size};
}

Result<X86PhysicalTranslation> x86_real_physical(X86LogicalAddress address, std::uint64_t size, A20Policy policy) {
    if (policy != A20Policy::enabled && policy != A20Policy::disabled)
        return Error{ErrorCode::invalid_argument, "Invalid A20 policy"};
    auto linear = x86_real_linear(address, size);
    if (!linear)
        return linear.error();
    X86PhysicalTranslation result;
    if (!size)
        return result;
    if (policy == A20Policy::enabled) {
        result.spans[0] = {{linear.value().begin.value}, size};
        result.count = 1;
        return result;
    }
    const auto begin = linear.value().begin.value & 0xfffffu;
    const auto first = std::min(size, UINT64_C(0x100000) - begin);
    result.spans[0] = {{begin}, first};
    result.count = 1;
    if (first != size) {
        result.spans[1] = {{0}, size - first};
        result.count = 2;
    }
    return result;
}

Result<X86SegmentDescriptor> parse_x86_segment_descriptor(std::span<const std::byte> bytes) {
    if (bytes.size() != 8)
        return Error{ErrorCode::malformed, "A segment descriptor requires exactly eight bytes"};
    const auto u = [&](std::size_t i) { return std::to_integer<std::uint32_t>(bytes[i]); };
    const auto access = u(5), flags = u(6);
    if (!(access & 0x10u))
        return Error{ErrorCode::unsupported, "System and gate descriptors are unsupported"};
    const bool code = (access & 8u) != 0;
    if (flags & 0x20u)
        return Error{code ? ErrorCode::unsupported : ErrorCode::malformed,
                     code ? "Long code segments are unsupported" : "Reserved data descriptor L bit is set"};
    const auto raw_limit = u(0) | (u(1) << 8u) | ((flags & 0xfu) << 16u);
    X86SegmentDescriptor result;
    result.base = u(2) | (u(3) << 8u) | (u(4) << 16u) | (u(7) << 24u);
    result.effective_limit = (flags & 0x80u) ? (raw_limit << 12u) | 0xfffu : raw_limit;
    result.present = (access & 0x80u) != 0;
    result.executable = code;
    result.readable = !code || (access & 2u) != 0;
    result.writable = !code && (access & 2u) != 0;
    result.expand_down = !code && (access & 4u) != 0;
    result.default_big = (flags & 0x40u) != 0;
    result.conforming = code && (access & 4u) != 0;
    result.dpl = static_cast<std::uint8_t>((access >> 5u) & 3u);
    return result;
}

Result<X86LinearTranslation> x86_protected_linear(const X86SegmentDescriptor &d, X86LogicalAddress address,
                                                  std::uint64_t size, X86SegmentAccess access) {
    if (!valid_descriptor(d))
        return Error{ErrorCode::invalid_argument, "Inconsistent segment descriptor fields"};
    if ((address.selector & 0xfffcu) == 0)
        return Error{ErrorCode::invalid_argument, "Null GDT selector cannot address memory"};
    if (!d.present)
        return Error{ErrorCode::out_of_bounds, "Segment is not present"};
    bool permitted = false;
    switch (access) {
    case X86SegmentAccess::read:
        permitted = d.readable;
        break;
    case X86SegmentAccess::write:
        permitted = !d.executable && d.writable;
        break;
    case X86SegmentAccess::execute:
        permitted = d.executable;
        break;
    case X86SegmentAccess::stack:
        permitted = !d.executable && d.writable;
        break;
    default:
        return Error{ErrorCode::invalid_argument, "Invalid segment access kind"};
    }
    if (!permitted)
        return Error{ErrorCode::out_of_bounds, "Segment type does not permit this access"};
    const std::uint64_t upper = d.expand_down ? (d.default_big ? UINT32_MAX : 0xffffu) : d.effective_limit;
    const std::uint64_t lower = d.expand_down ? static_cast<std::uint64_t>(d.effective_limit) + 1u : 0u;
    if (address.offset < lower || address.offset > upper || size > upper - address.offset + 1u)
        return Error{ErrorCode::out_of_bounds, "Protected-mode access exceeds segment bounds"};
    X86LinearTranslation result;
    if (!size)
        return result;
    const auto begin = static_cast<std::uint32_t>(static_cast<std::uint64_t>(d.base) + address.offset);
    const auto first = std::min(size, UINT64_C(0x100000000) - begin);
    result.spans[0] = {{begin}, first};
    result.count = 1;
    if (first != size) {
        result.spans[1] = {{0}, size - first};
        result.count = 2;
    }
    return result;
}
} // namespace hexlab
