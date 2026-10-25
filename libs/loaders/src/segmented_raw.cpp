#include "x86_profile_internal.hpp"
namespace hexlab::profile_detail {
Result<std::shared_ptr<const Image>> load_segmented(std::shared_ptr<const ByteStorage> storage, const X86RawProfile &p,
                                                    std::stop_token stop) {
    return guarded([&]() -> Result<std::shared_ptr<const Image>> {
        take(validate_x86_profile(p));
        const auto load_end = take(checked_add(p.input_load_address, storage->size()));
        require(load_end <= UINT64_C(0x100000000), "Segmented input load extent exceeds32 bits", ErrorCode::overflow);
        const auto &entry = *domain(p, p.entry.space);
        const auto primary = context(p, entry);
        ImageLayout layout{{p.entry.space,
                            static_cast<std::uint8_t>(p.environment == X86ImageEnvironment::real386 ? 16 : 32), 1,
                            ByteOrder::little},
                           Architecture::x86,
                           primary.mode,
                           {},
                           {p.entry}};
        layout.stack_address_width = primary.stack_address_width;
        layout.segmented_memory = true;
        layout.x86_profile = X86ImageProfile{p.environment, p.a20, {}};
        layout.x86_profile->input_load_address = p.input_load_address;
        layout.x86_profile->stack_selector = p.stack_selector;
        for (const auto &d : p.domains) {
            require(!stop.stop_requested(), "Segmented raw loading canceled", ErrorCode::canceled);
            if (d.space != p.entry.space)
                layout.domains.push_back({{d.space, layout.space.width_bits, 1, ByteOrder::little}, context(p, d)});
            layout.x86_profile->bindings.push_back({d.space, d.selector, d.descriptor});
            const auto append = [&](std::uint64_t logical, std::uint32_t position, std::uint64_t length) {
                const auto begin = std::max<std::uint64_t>(position, p.input_load_address);
                const auto end = std::min<std::uint64_t>(std::uint64_t(position) + length, load_end);
                if (begin >= end)
                    return;
                layout.segments.push_back({d.name,
                                           {d.space, logical + begin - position},
                                           end - begin,
                                           {begin - p.input_load_address},
                                           end - begin,
                                           !d.descriptor || d.descriptor->readable,
                                           d.descriptor ? d.descriptor->writable : !d.executable,
                                           d.executable});
            };
            if (p.environment == X86ImageEnvironment::real386) {
                auto translated = take(x86_real_physical({d.selector, 0}, 0x10000, p.a20));
                std::uint64_t logical = 0;
                for (unsigned i = 0; i < translated.count; ++i) {
                    const auto &span = translated.spans[i];
                    append(logical, span.begin.value, span.size);
                    logical += span.size;
                }
            } else {
                const auto &descriptor = *d.descriptor;
                const std::uint64_t lower = descriptor.expand_down ? std::uint64_t(descriptor.effective_limit) + 1 : 0;
                const std::uint64_t upper = descriptor.expand_down ? (descriptor.default_big ? UINT32_MAX : 0xffff)
                                                                   : descriptor.effective_limit;
                auto translated = take(
                    x86_protected_linear(descriptor, {d.selector, static_cast<std::uint32_t>(lower)}, upper - lower + 1,
                                         d.executable ? X86SegmentAccess::execute : X86SegmentAccess::read));
                auto logical = lower;
                for (unsigned i = 0; i < translated.count; ++i) {
                    const auto &span = translated.spans[i];
                    append(logical, span.begin.value, span.size);
                    logical += span.size;
                }
            }
        }
        return Image::create(std::move(storage), std::move(layout));
    });
}
} // namespace hexlab::profile_detail
