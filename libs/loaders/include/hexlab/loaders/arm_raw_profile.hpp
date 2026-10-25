#pragma once
#include "hexlab/loaders/loader.hpp"
#include <filesystem>
#include <stop_token>
#include <string_view>

namespace hexlab {
inline constexpr std::size_t arm_profile_text_limit = 1024 * 1024, arm_profile_range_limit = 16384;
struct ArmRawRange {
    std::uint32_t begin = 0;
    std::uint64_t size = 0;
    ArmCodeKind kind = ArmCodeKind::unknown;
    bool operator==(const ArmRawRange &) const = default;
};
struct ArmRawEntry {
    std::uint32_t offset = 0;
    ExecutionMode mode = ExecutionMode::unknown;
    bool known_thumb_it_clear = false;
    bool operator==(const ArmRawEntry &) const = default;
};
struct ArmRawProfile {
    Address base{{0}, 0};
    bool readable = true, writable = false, executable = true;
    std::optional<ArmRawEntry> entry;
    std::vector<ArmRawRange> ranges;
    bool operator==(const ArmRawProfile &) const = default;
};
HEXLAB_LOADERS_EXPORT Result<bool> validate_arm_profile(const ArmRawProfile &, std::stop_token = {});
HEXLAB_LOADERS_EXPORT Result<ArmRawProfile> parse_arm_profile(std::string_view, std::stop_token = {});
HEXLAB_LOADERS_EXPORT Result<std::string> format_arm_profile(const ArmRawProfile &, std::stop_token = {});
// Perform file I/O on the opening worker. The durable recipe embeds its contents.
HEXLAB_LOADERS_EXPORT Result<ArmRawProfile> read_arm_profile(const std::filesystem::path &, std::stop_token);
} // namespace hexlab
