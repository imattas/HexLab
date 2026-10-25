#include "x86_profile_internal.hpp"
#include <charconv>
#include <locale>
#include <sstream>

namespace hexlab {
namespace {
using profile_detail::require;
using profile_detail::take;
void canceled(std::stop_token stop) {
    require(!stop.stop_requested(), "ARM profile operation canceled", ErrorCode::canceled);
}
ArmRawProfile normalized(ArmRawProfile profile, std::stop_token stop) {
    canceled(stop);
    require(profile.base.offset <= UINT32_MAX, "ARM raw base exceeds32 bits");
    require(profile.ranges.size() <= arm_profile_range_limit, "ARM raw profile range budget exceeded",
            ErrorCode::resource_limit);
    std::sort(profile.ranges.begin(), profile.ranges.end(),
              [](const auto &a, const auto &b) { return a.begin < b.begin; });
    std::uint64_t previous_end = profile.base.offset;
    const ArmRawRange *entry_range = nullptr;
    for (const auto &range : profile.ranges) {
        canceled(stop);
        require(range.kind == ArmCodeKind::a32 || range.kind == ArmCodeKind::thumb || range.kind == ArmCodeKind::data ||
                    range.kind == ArmCodeKind::unknown,
                "Invalid or conflicting ARM raw range kind");
        require(range.size && range.begin >= previous_end && range.size <= UINT64_C(0x100000000) - range.begin,
                "Overlapping or out-of-domain ARM raw range");
        previous_end = range.begin + range.size;
        if (range.kind == ArmCodeKind::a32 || range.kind == ArmCodeKind::thumb) {
            const auto alignment = range.kind == ArmCodeKind::a32 ? 4u : 2u;
            require(profile.executable && !(range.begin % alignment) && !(range.size % alignment),
                    "ARM raw code needs executable permission and aligned complete units");
        }
        if (profile.entry && profile.entry->offset >= range.begin && profile.entry->offset < previous_end)
            entry_range = &range;
    }
    if (profile.entry) {
        const auto &entry = *profile.entry;
        const auto expected = entry_range && entry_range->kind == ArmCodeKind::a32     ? ExecutionMode::a32
                              : entry_range && entry_range->kind == ArmCodeKind::thumb ? ExecutionMode::thumb
                                                                                       : ExecutionMode::unknown;
        const auto alignment = entry.mode == ExecutionMode::a32 ? 4u : 2u;
        require((entry.mode == ExecutionMode::a32 || entry.mode == ExecutionMode::thumb) && entry.mode == expected &&
                    !(entry.offset % alignment) && entry_range->begin + entry_range->size - entry.offset >= alignment &&
                    (!entry.known_thumb_it_clear || entry.mode == ExecutionMode::thumb),
                "ARM raw entry contradicts its code range or IT state");
    }
    canceled(stop);
    return profile;
}
std::uint64_t number(std::string_view text, std::uint64_t maximum) {
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) {
        text.remove_prefix(2);
        base = 16;
    }
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, base);
    require(!text.empty() && parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && value <= maximum,
            "Invalid unsigned ARM profile integer", ErrorCode::malformed);
    return value;
}
std::vector<std::string_view> tokens(std::string_view line) {
    line = line.substr(0, line.find('#'));
    std::vector<std::string_view> result;
    while (!line.empty()) {
        const auto first = line.find_first_not_of(" \t\r");
        if (first == std::string_view::npos)
            break;
        line.remove_prefix(first);
        const auto end = line.find_first_of(" \t\r");
        result.push_back(line.substr(0, end));
        require(result.size() <= 4, "Too many ARM profile fields", ErrorCode::malformed);
        if (end == std::string_view::npos)
            break;
        line.remove_prefix(end);
    }
    return result;
}
const char *kind_text(ArmCodeKind kind) {
    switch (kind) {
    case ArmCodeKind::a32:
        return "a32";
    case ArmCodeKind::thumb:
        return "thumb";
    case ArmCodeKind::data:
        return "data";
    default:
        return "unknown";
    }
}
} // namespace
Result<bool> validate_arm_profile(const ArmRawProfile &profile, std::stop_token stop) {
    return profile_detail::guarded([&]() -> Result<bool> {
        (void)normalized(profile, stop);
        return true;
    });
}
Result<RawOptions> make_arm_raw_options(ArmRawProfile profile, std::stop_token stop) {
    return profile_detail::guarded([&]() -> Result<RawOptions> {
        profile = normalized(std::move(profile), stop);
        RawOptions raw{Architecture::arm, ExecutionMode::unknown, profile.base, profile.readable,
                       profile.writable,  profile.executable,     {},           {},
                       std::move(profile)};
        if (raw.arm_profile->entry)
            raw.entry = Address{raw.base.space, raw.arm_profile->entry->offset};
        return raw;
    });
}
Result<ArmRawProfile> parse_arm_profile(std::string_view input, std::stop_token stop) {
    return profile_detail::guarded([&]() -> Result<ArmRawProfile> {
        canceled(stop);
        require(input.size() <= arm_profile_text_limit, "ARM profile text exceeds1MiB", ErrorCode::resource_limit);
        require(profile_detail::utf8(input, false), "Invalid ARM profile UTF8 text", ErrorCode::malformed);
        if (input.starts_with("\xef\xbb\xbf"))
            input.remove_prefix(3);
        ArmRawProfile profile;
        bool header = false;
        unsigned fields = 0;
        std::size_t declared = 0;
        while (!input.empty()) {
            canceled(stop);
            const auto end = input.find('\n');
            const auto line = input.substr(0, end);
            input = end == std::string_view::npos ? std::string_view{} : input.substr(end + 1);
            require(line.size() <= 4096, "ARM profile line exceeds4096 bytes", ErrorCode::resource_limit);
            const auto row = tokens(line);
            if (row.empty())
                continue;
            if (!header) {
                require(row.size() == 2 && row[0] == "hexlab-arm-profile" && row[1] == "1",
                        "Unknown ARM profile version", ErrorCode::unsupported);
                header = true;
                continue;
            }
            const auto field = [&](unsigned bit, std::size_t count) {
                require(row.size() == count && !(fields & bit), "Duplicate or malformed ARM profile field",
                        ErrorCode::malformed);
                fields |= bit;
            };
            if (row[0] == "base") {
                field(1, 3);
                profile.base = {{static_cast<std::uint32_t>(number(row[1], UINT32_MAX))}, number(row[2], UINT32_MAX)};
            } else if (row[0] == "permissions") {
                field(2, 2);
                const auto p = row[1];
                require(p.size() == 3 && (p[0] == 'r' || p[0] == '-') && (p[1] == 'w' || p[1] == '-') &&
                            (p[2] == 'x' || p[2] == '-'),
                        "Invalid ARM raw permissions", ErrorCode::malformed);
                profile.readable = p[0] == 'r';
                profile.writable = p[1] == 'w';
                profile.executable = p[2] == 'x';
            } else if (row[0] == "entry") {
                require(!(fields & 4), "Duplicate ARM entry", ErrorCode::malformed);
                fields |= 4;
                if (row.size() == 2 && row[1] == "none")
                    continue;
                require(row.size() == 3 && (row[2] == "a32" || row[2] == "thumb-clear" || row[2] == "thumb-unknown"),
                        "Invalid ARM physical entry declaration", ErrorCode::malformed);
                profile.entry =
                    ArmRawEntry{static_cast<std::uint32_t>(number(row[1], UINT32_MAX)),
                                row[2] == "a32" ? ExecutionMode::a32 : ExecutionMode::thumb, row[2] == "thumb-clear"};
            } else if (row[0] == "ranges") {
                field(8, 2);
                declared = static_cast<std::size_t>(number(row[1], arm_profile_range_limit));
            } else if (row[0] == "range") {
                require(row.size() == 4 && (fields & 8) && profile.ranges.size() < declared,
                        "Invalid ARM range row/count", ErrorCode::malformed);
                require(row[3] == "a32" || row[3] == "thumb" || row[3] == "data" || row[3] == "unknown",
                        "Invalid ARM range kind", ErrorCode::malformed);
                profile.ranges.push_back({static_cast<std::uint32_t>(number(row[1], UINT32_MAX)),
                                          number(row[2], UINT64_C(0x100000000)),
                                          row[3] == "a32"     ? ArmCodeKind::a32
                                          : row[3] == "thumb" ? ArmCodeKind::thumb
                                          : row[3] == "data"  ? ArmCodeKind::data
                                                              : ArmCodeKind::unknown});
            } else
                require(false, "Unknown ARM profile field", ErrorCode::malformed);
        }
        require(header && fields == 15 && profile.ranges.size() == declared, "Incomplete ARM profile",
                ErrorCode::malformed);
        return normalized(std::move(profile), stop);
    });
}
Result<std::string> format_arm_profile(const ArmRawProfile &input, std::stop_token stop) {
    return profile_detail::guarded([&]() -> Result<std::string> {
        const auto profile = normalized(input, stop);
        std::ostringstream out;
        out.imbue(std::locale::classic());
        out << "hexlab-arm-profile 1\nbase " << profile.base.space.value << " 0x" << std::hex << profile.base.offset
            << "\npermissions " << (profile.readable ? 'r' : '-') << (profile.writable ? 'w' : '-')
            << (profile.executable ? 'x' : '-') << "\nentry ";
        if (!profile.entry)
            out << "none";
        else
            out << "0x" << profile.entry->offset << ' '
                << (profile.entry->mode == ExecutionMode::a32 ? "a32"
                    : profile.entry->known_thumb_it_clear     ? "thumb-clear"
                                                              : "thumb-unknown");
        out << "\nranges " << std::dec << profile.ranges.size() << '\n';
        for (const auto &range : profile.ranges) {
            canceled(stop);
            out << "range 0x" << std::hex << range.begin << " 0x" << range.size << ' ' << kind_text(range.kind) << '\n';
        }
        auto text = out.str();
        require(text.size() <= arm_profile_text_limit, "Canonical ARM profile exceeds1MiB", ErrorCode::resource_limit);
        return text;
    });
}
Result<ArmRawProfile> read_arm_profile(const std::filesystem::path &path, std::stop_token stop) {
    return profile_detail::guarded([&]() -> Result<ArmRawProfile> {
        canceled(stop);
        const auto storage = take(FileStorage::open(path));
        require(storage->size() <= arm_profile_text_limit, "ARM profile file exceeds1MiB", ErrorCode::resource_limit);
        const auto view = take(storage->read_at({0}, static_cast<std::size_t>(storage->size())));
        require(view.bytes.size() == storage->size(), "ARM profile file returned a short read", ErrorCode::io);
        canceled(stop);
        return parse_arm_profile({reinterpret_cast<const char *>(view.bytes.data()), view.bytes.size()}, stop);
    });
}
} // namespace hexlab
