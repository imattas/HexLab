#pragma once
#include "hexlab/workspace/document.hpp"
#include "hexlab/core/location.hpp"
#include <string_view>
#include <string>
namespace hexlab {
HEXLAB_WORKSPACE_EXPORT Result<std::uint64_t> parse_address(std::wstring_view);
// Conventional hexadecimal selector:offset; each field may also use 0x.
HEXLAB_WORKSPACE_EXPORT Result<X86LogicalAddress> parse_x86_logical_address(std::wstring_view);
HEXLAB_WORKSPACE_EXPORT Result<Address> parse_segment_address(const Image &, std::wstring_view);
HEXLAB_WORKSPACE_EXPORT std::string format_location(Location, const Image * = nullptr);
// Lightweight current-source query; does not read bytes, decode, or hash recipes.
HEXLAB_WORKSPACE_EXPORT Result<std::optional<Address>> project_follow_target(const ProjectSnapshot &, Address);
}
