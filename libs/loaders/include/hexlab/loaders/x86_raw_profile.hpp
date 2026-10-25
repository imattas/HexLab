#pragma once
#include "hexlab/loaders/loader.hpp"
#include <filesystem>
#include <optional>
#include <stop_token>
#include <string_view>

namespace hexlab {
inline constexpr std::size_t x86_profile_text_limit = 1024 * 1024, x86_profile_domain_limit = 4096;
struct X86RawDomain {
    AddressSpaceId space;
    std::uint16_t selector;
    bool executable;
    std::string name;
    std::optional<X86SegmentDescriptor> descriptor;
    bool operator==(const X86RawDomain &) const = default;
};
struct X86RawProfile {
    X86ImageEnvironment environment = X86ImageEnvironment::real386;
    A20Policy a20 = A20Policy::enabled;
    // Contiguous canonical input loaded at a real physical or protected linear
    // position. No paging or runtime DS/SS data-value inference is performed.
    std::uint32_t input_load_address = 0;
    Address entry{{0}, 0};
    std::optional<std::uint16_t> stack_selector;
    std::vector<X86RawDomain> domains;
    bool operator==(const X86RawProfile &) const = default;
};
HEXLAB_LOADERS_EXPORT Result<bool> validate_x86_profile(const X86RawProfile &);
HEXLAB_LOADERS_EXPORT Result<X86RawProfile> parse_x86_profile(std::string_view);
HEXLAB_LOADERS_EXPORT Result<std::string> format_x86_profile(const X86RawProfile &);
// Invoke on an I/O worker; frontends pass paths without parsing on GUI handlers.
HEXLAB_LOADERS_EXPORT Result<X86RawProfile> read_x86_profile(const std::filesystem::path &, std::stop_token);
} // namespace hexlab
