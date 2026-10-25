#include "hexlab/image/image.hpp"
#include <algorithm>
#include <map>
#include <set>

namespace hexlab {
namespace {
const X86ImageBinding *binding(const ImageLayout &layout, AddressSpaceId space) noexcept {
    if (!layout.x86_profile)
        return nullptr;
    for (const auto &b : layout.x86_profile->bindings)
        if (b.space == space)
            return &b;
    return nullptr;
}
Result<bool> span_in_domain(const Image &image, Address address, std::uint64_t size) {
    auto context = image.context_at(address);
    if (!context)
        return context.error();
    const auto *space = image.space(address.space);
    if (space->width_bits < 64 && size > (UINT64_C(1) << space->width_bits) - address.offset)
        return Error{ErrorCode::out_of_bounds, "Translated access exceeds its logical domain"};
    return true;
}
} // namespace
Result<X86LogicalAddress> Image::logical_address(Address address) const {
    const auto *b = binding(layout_, address.space);
    if (!b)
        return Error{ErrorCode::unsupported, "Address domain has no declared x86 selector binding"};
    auto valid = span_in_domain(*this, address, 0);
    if (!valid)
        return valid.error();
    if (address.offset > UINT32_MAX)
        return Error{ErrorCode::out_of_bounds, "x86 logical offset exceeds32 bits"};
    X86LogicalAddress logical{b->selector, static_cast<std::uint32_t>(address.offset)};
    if (layout_.x86_profile->environment == X86ImageEnvironment::real386) {
        auto translated = x86_real_linear(logical, 0);
        if (!translated)
            return translated.error();
    } else {
        auto translated = x86_protected_linear(
            *b->descriptor, logical, 0, b->descriptor->executable ? X86SegmentAccess::execute : X86SegmentAccess::read);
        if (!translated)
            return translated.error();
    }
    return logical;
}
Result<Address> Image::from_logical(X86LogicalAddress logical) const {
    if (!layout_.x86_profile)
        return Error{ErrorCode::unsupported, "Image has no x86 selector profile"};
    for (const auto &b : layout_.x86_profile->bindings) {
        if (b.selector != logical.selector)
            continue;
        Address address{b.space, logical.offset};
        auto valid = logical_address(address);
        if (!valid)
            return valid.error();
        return address;
    }
    return Error{ErrorCode::out_of_bounds, "Selector is not declared in this image profile"};
}
Result<X86LinearTranslation> Image::linear_spans(Address address, std::uint64_t size, X86SegmentAccess access) const {
    auto valid = span_in_domain(*this, address, size);
    if (!valid)
        return valid.error();
    auto logical = logical_address(address);
    if (!logical)
        return logical.error();
    const auto *b = binding(layout_, address.space);
    if (layout_.x86_profile->environment == X86ImageEnvironment::protected386)
        return x86_protected_linear(*b->descriptor, logical.value(), size, access);
    if (access != X86SegmentAccess::read && access != X86SegmentAccess::write && access != X86SegmentAccess::execute &&
        access != X86SegmentAccess::stack)
        return Error{ErrorCode::invalid_argument, "Invalid segment access kind"};
    auto span = x86_real_linear(logical.value(), size);
    if (!span)
        return span.error();
    X86LinearTranslation result;
    if (size) {
        result.count = 1;
        result.spans[0] = span.value();
    }
    return result;
}
Result<X86PhysicalTranslation> Image::physical_spans(Address address, std::uint64_t size) const {
    auto valid = span_in_domain(*this, address, size);
    if (!valid)
        return valid.error();
    auto logical = logical_address(address);
    if (!logical)
        return logical.error();
    if (layout_.x86_profile->environment != X86ImageEnvironment::real386)
        return Error{ErrorCode::unsupported,
                     "Protected linear addresses require an explicit paging model for physical translation"};
    return x86_real_physical(logical.value(), size, layout_.x86_profile->a20);
}
Result<bool> Image::validate_profile() const {
    if (!layout_.x86_profile)
        return true;
    const auto &profile = *layout_.x86_profile;
    if ((profile.environment != X86ImageEnvironment::real386 &&
         profile.environment != X86ImageEnvironment::protected386) ||
        (profile.a20 != A20Policy::enabled && profile.a20 != A20Policy::disabled))
        return Error{ErrorCode::invalid_argument, "Invalid x86 image environment or A20 policy"};
    if (profile.bindings.size() > 4096 || profile.bindings.size() != layout_.domains.size() + 1)
        return Error{ErrorCode::invalid_argument,
                     "Segment profile must bind each image domain exactly once (maximum4096)"};
    std::set<std::uint32_t> spaces;
    std::set<std::uint16_t> selectors;
    std::map<std::uint16_t, X86SegmentDescriptor> descriptor_keys;
    for (const auto &b : profile.bindings) {
        const auto *domain = space(b.space);
        if (!domain || !spaces.insert(b.space.value).second || !selectors.insert(b.selector).second)
            return Error{ErrorCode::invalid_argument, "Invalid or duplicate segment-profile domain or selector"};
        if (domain->width_bits > 32 || domain->order != ByteOrder::little)
            return Error{ErrorCode::invalid_argument,
                         "Legacy segment domains require little-endian offsets of at most32 bits"};
        auto context = context_at({b.space, 0});
        if (!context || context.value().architecture != Architecture::x86 ||
            (context.value().mode != ExecutionMode::x86_16 && context.value().mode != ExecutionMode::x86_32 &&
             context.value().mode != ExecutionMode::unknown) ||
            (context.value().stack_address_width != 0 && context.value().stack_address_width != 16 &&
             context.value().stack_address_width != 32))
            return Error{ErrorCode::invalid_argument, "Legacy segment profile requires an x86-16 or x86-32 context"};
        if (profile.environment == X86ImageEnvironment::real386) {
            if (b.descriptor || domain->width_bits != 16 ||
                (context.value().mode != ExecutionMode::x86_16 && context.value().mode != ExecutionMode::unknown) ||
                context.value().stack_address_width == 32)
                return Error{ErrorCode::invalid_argument,
                             "386 real-mode profile requires16-bit domains without protected descriptors"};
        } else {
            if (!b.descriptor)
                return Error{ErrorCode::invalid_argument, "Protected binding requires a descriptor"};
            const auto &d = *b.descriptor;
            // RPL is part of a logical selector's identity, but does not choose
            // another GDT/LDT entry. Such aliases must describe the same entry.
            const auto key = static_cast<std::uint16_t>(b.selector & 0xfffcu);
            const auto [found, inserted] = descriptor_keys.emplace(key, d);
            if (!inserted && found->second != d)
                return Error{ErrorCode::invalid_argument, "Conflicting descriptors for the same GDT/LDT entry"};
            const auto first = d.expand_down ? static_cast<std::uint64_t>(d.effective_limit) + 1u : 0u;
            if (first > UINT32_MAX)
                return Error{ErrorCode::out_of_bounds, "Protected descriptor has an empty logical domain"};
            auto valid = x86_protected_linear(d, {b.selector, static_cast<std::uint32_t>(first)}, 0,
                                              d.executable ? X86SegmentAccess::execute : X86SegmentAccess::read);
            if (!valid)
                return valid.error();
            if (d.executable && (d.default_big != (context.value().mode == ExecutionMode::x86_32)))
                return Error{ErrorCode::invalid_argument, "Protected code default size differs from domain context"};
            if (d.executable && context.value().mode == ExecutionMode::unknown)
                return Error{ErrorCode::invalid_argument, "Executable descriptor has no declared code bitness"};
            if (d.executable && context.value().mode == ExecutionMode::x86_32 && !context.value().segmented_memory)
                return Error{ErrorCode::invalid_argument, "Protected32 context cannot use flat data assumptions"};
        }
    }
    if (profile.stack_selector) {
        const auto found = std::find_if(profile.bindings.begin(), profile.bindings.end(),
                                        [&](const auto &b) { return b.selector == *profile.stack_selector; });
        if (found == profile.bindings.end())
            return Error{ErrorCode::invalid_argument, "Declared SS selector has no profile binding"};
        if (profile.environment == X86ImageEnvironment::protected386) {
            if (found->descriptor->executable || !found->descriptor->writable)
                return Error{ErrorCode::invalid_argument, "Declared SS requires writable data"};
            const auto width = found->descriptor->default_big ? 32 : 16;
            for (const auto &b : profile.bindings) {
                if (!b.descriptor->executable)
                    continue;
                auto ctx = context_at({b.space, 0}).value();
                const auto actual =
                    ctx.stack_address_width ? ctx.stack_address_width : (ctx.mode == ExecutionMode::x86_16 ? 16 : 32);
                if (actual != width)
                    return Error{ErrorCode::invalid_argument, "Code context stack width differs from declared SS.B"};
            }
        }
    }
    for (const auto &segment : layout_.segments) {
        if (segment.executable && context_at(segment.begin).value().mode == ExecutionMode::unknown)
            return Error{ErrorCode::invalid_argument, "Data-only domain cannot contain executable mappings"};
        // Every declared mapped span must fit the descriptor and requested permissions.
        auto translated = linear_spans(segment.begin, segment.size, X86SegmentAccess::read);
        if (!segment.readable && segment.executable)
            translated = linear_spans(segment.begin, segment.size, X86SegmentAccess::execute);
        if (!translated)
            return translated.error();
        if (segment.writable) {
            translated = linear_spans(segment.begin, segment.size, X86SegmentAccess::write);
            if (!translated)
                return translated.error();
        }
        if (segment.executable) {
            translated = linear_spans(segment.begin, segment.size, X86SegmentAccess::execute);
            if (!translated)
                return translated.error();
        }
    }
    return true;
}
} // namespace hexlab
