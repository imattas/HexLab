#include "x86_profile_internal.hpp"
#include <map>
#include <set>
namespace hexlab {
Result<bool> validate_x86_profile(const X86RawProfile &p) {
    return profile_detail::guarded([&]() -> Result<bool> {
        using namespace profile_detail;
        require(p.environment == X86ImageEnvironment::real386 || p.environment == X86ImageEnvironment::protected386,
                "Unknown x86 profile environment");
        require(p.a20 == A20Policy::enabled || p.a20 == A20Policy::disabled, "Unknown x86 profile A20 policy");
        require(!p.domains.empty() && p.domains.size() <= x86_profile_domain_limit,
                "Profile must declare1..4096 domains", ErrorCode::resource_limit);
        require(p.environment != X86ImageEnvironment::protected386 || p.a20 == A20Policy::enabled,
                "Protected linear profiles require enabled A20; physical paging is not modeled");
        std::set<std::uint32_t> spaces;
        std::set<std::uint16_t> selectors;
        std::map<std::uint16_t, X86SegmentDescriptor> descriptors;
        const X86RawDomain *entry = nullptr;
        const X86RawDomain *stack = nullptr;
        for (const auto &d : p.domains) {
            require(spaces.insert(d.space.value).second && selectors.insert(d.selector).second,
                    "Duplicate profile domain or selector");
            require(!d.name.empty() && d.name.size() <= 256 && utf8(d.name, true),
                    "Domain name must be valid UTF8 with1..256 bytes and no controls");
            if (d.space == p.entry.space)
                entry = &d;
            if (p.stack_selector && d.selector == *p.stack_selector)
                stack = &d;
            if (p.environment == X86ImageEnvironment::real386)
                require(!d.descriptor, "Real profile domain cannot contain a protected descriptor");
            else {
                require(d.descriptor.has_value(), "Protected domain requires a code/data descriptor");
                const auto &descriptor = *d.descriptor;
                require(d.executable == descriptor.executable, "Domain role differs from descriptor type");
                require(descriptor.effective_limit <= 0xfffff || (descriptor.effective_limit & 0xfff) == 0xfff,
                        "Descriptor effective limit cannot be represented with x86 granularity");
                const auto lower = descriptor.expand_down ? std::uint64_t(descriptor.effective_limit) + 1 : 0;
                require(lower <= UINT32_MAX, "Empty expand-down descriptor");
                take(x86_protected_linear(descriptor, {d.selector, static_cast<std::uint32_t>(lower)}, 0,
                                          d.executable ? X86SegmentAccess::execute : X86SegmentAccess::read));
                auto [found, inserted] =
                    descriptors.emplace(static_cast<std::uint16_t>(d.selector & 0xfffc), descriptor);
                require(inserted || found->second == descriptor, "Conflicting descriptors behind RPL aliases");
            }
        }
        require(entry && entry->executable, "Entry must name a declared code domain");
        require(p.entry.offset <= UINT32_MAX, "Entry offset exceeds32 bits");
        if (p.environment == X86ImageEnvironment::real386) {
            take(x86_real_linear({entry->selector, static_cast<std::uint32_t>(p.entry.offset)}, 0));
            require(!p.stack_selector || (stack && !stack->executable),
                    "Real stack selector must name a declared data domain");
        } else {
            require(p.stack_selector && stack && !stack->executable && stack->descriptor->writable,
                    "Protected SS must name writable declared data");
            const auto cpl = entry->selector & 3u;
            require(entry->descriptor->conforming ? entry->descriptor->dpl <= cpl : entry->descriptor->dpl == cpl,
                    "Entry CS selector and descriptor privilege attributes disagree");
            require(stack->descriptor->dpl == cpl && (*p.stack_selector & 3u) == cpl,
                    "Initial SS selector and descriptor must match entry CPL");
            take(x86_protected_linear(*entry->descriptor, {entry->selector, static_cast<std::uint32_t>(p.entry.offset)},
                                      0, X86SegmentAccess::execute));
        }
        return true;
    });
}
Result<RawOptions> make_x86_raw_options(X86RawProfile profile) {
    return profile_detail::guarded([&]() -> Result<RawOptions> {
        using namespace profile_detail;
        take(validate_x86_profile(profile));
        std::sort(profile.domains.begin(), profile.domains.end(),
                  [](const auto &a, const auto &b) { return a.space.value < b.space.value; });
        const auto &entry = *domain(profile, profile.entry.space);
        const auto ctx = context(profile, entry);
        RawOptions options{Architecture::x86,
                           ctx.mode,
                           {profile.entry.space, 0},
                           !entry.descriptor || entry.descriptor->readable,
                           false,
                           true,
                           profile.entry,
                           std::move(profile)};
        return options;
    });
}
Result<X86RawProfile> read_x86_profile(const std::filesystem::path &path, std::stop_token stop) {
    return profile_detail::guarded([&]() -> Result<X86RawProfile> {
        using namespace profile_detail;
        require(!stop.stop_requested(), "Profile reading canceled", ErrorCode::canceled);
        const auto storage = take(FileStorage::open(path));
        require(storage->size() <= x86_profile_text_limit, "Profile file exceeds1MiB", ErrorCode::resource_limit);
        auto bytes = take(storage->read_at({0}, static_cast<std::size_t>(storage->size())));
        require(bytes.bytes.size() == storage->size(), "Profile file returned a short read", ErrorCode::io);
        require(!stop.stop_requested(), "Profile reading canceled", ErrorCode::canceled);
        return parse_x86_profile({reinterpret_cast<const char *>(bytes.bytes.data()), bytes.bytes.size()});
    });
}
} // namespace hexlab
