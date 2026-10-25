#pragma once
#include "hexlab/core/core_export.hpp"
#include "hexlab/core/result.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace hexlab {
// Coordinates are distinct from logical Address domains and file backing offsets.
struct X86LogicalAddress {
    std::uint16_t selector;
    std::uint32_t offset;
    bool operator==(const X86LogicalAddress &) const = default;
};
struct X86LinearAddress {
    std::uint32_t value;
    bool operator==(const X86LinearAddress &) const = default;
};
struct X86PhysicalAddress {
    std::uint32_t value;
    bool operator==(const X86PhysicalAddress &) const = default;
};
struct X86LinearSpan {
    X86LinearAddress begin;
    std::uint64_t size;
    bool operator==(const X86LinearSpan &) const = default;
};
struct X86PhysicalSpan {
    X86PhysicalAddress begin;
    std::uint64_t size;
    bool operator==(const X86PhysicalSpan &) const = default;
};
struct X86LinearTranslation {
    std::array<X86LinearSpan, 2> spans{};
    std::uint8_t count{};
    bool operator==(const X86LinearTranslation &) const = default;
};
struct X86PhysicalTranslation {
    std::array<X86PhysicalSpan, 2> spans{};
    std::uint8_t count{};
    bool operator==(const X86PhysicalTranslation &) const = default;
};
enum class A20Policy { enabled, disabled };

// 386-style real-mode limits: a complete access must fit offsets 0000..FFFF.
// Physical A20 wrapping is applied only after that logical validation.
HEXLAB_CORE_EXPORT Result<X86LinearSpan> x86_real_linear(X86LogicalAddress address, std::uint64_t size);
HEXLAB_CORE_EXPORT Result<X86PhysicalTranslation> x86_real_physical(X86LogicalAddress address, std::uint64_t size,
                                                                    A20Policy policy);

struct X86SegmentDescriptor {
    std::uint32_t base{};
    std::uint32_t effective_limit{};
    bool present{};
    bool executable{};
    bool readable{true};
    bool writable{};
    bool expand_down{};
    bool default_big{};
    bool conforming{};
    std::uint8_t dpl{};
    bool operator==(const X86SegmentDescriptor &) const = default;
};
enum class X86SegmentAccess { read, write, execute, stack };

// Exactly eight little-endian descriptor bytes. Only legacy code/data segments;
// system descriptors, gates and long-mode code are unsupported. Accessed/AVL
// bits do not affect this immutable address-translation model.
HEXLAB_CORE_EXPORT Result<X86SegmentDescriptor> parse_x86_segment_descriptor(std::span<const std::byte> bytes);

// Checks local type, presence and complete offset bounds. The descriptor must
// already have been selected from the profile's GDT/LDT. This does not implement
// CPL/RPL authorization, gate transitions, descriptor loading, paging or A20.
// D/B sets the expand-down upper bound; it does not truncate an effective offset.
// A valid empty access produces zero spans. Linear32 wrapping splits into two.
HEXLAB_CORE_EXPORT Result<X86LinearTranslation> x86_protected_linear(const X86SegmentDescriptor &descriptor,
                                                                     X86LogicalAddress address, std::uint64_t size,
                                                                     X86SegmentAccess access);
} // namespace hexlab
