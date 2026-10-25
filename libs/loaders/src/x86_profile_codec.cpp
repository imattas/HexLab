#include "x86_profile_internal.hpp"
#include <charconv>
#include <iomanip>
#include <locale>
#include <sstream>
namespace hexlab::profile_detail {
namespace {
std::vector<std::string> tokens(std::string_view line) {
    std::vector<std::string> out;
    std::size_t at = 0;
    while (at < line.size()) {
        while (at < line.size() && (line[at] == ' ' || line[at] == '\t' || line[at] == '\r'))
            ++at;
        if (at == line.size() || line[at] == '#')
            break;
        std::string token;
        if (line[at] == '"') {
            ++at;
            bool ended = false;
            while (at < line.size()) {
                auto c = line[at++];
                if (c == '"') {
                    ended = true;
                    break;
                }
                if (c == '\\') {
                    require(at < line.size(), "Truncated quoted escape", ErrorCode::malformed);
                    c = line[at++];
                    require(c == '\\' || c == '"', "Only quote and backslash escapes are supported",
                            ErrorCode::malformed);
                }
                token += c;
            }
            require(ended && (at == line.size() || line[at] == ' ' || line[at] == '\t' || line[at] == '\r' ||
                              line[at] == '#'),
                    "Malformed quoted token", ErrorCode::malformed);
        } else
            while (at < line.size() && line[at] != ' ' && line[at] != '\t' && line[at] != '\r' && line[at] != '#')
                token += line[at++];
        out.push_back(std::move(token));
        require(out.size() <= 8, "Too many profile fields", ErrorCode::malformed);
    }
    return out;
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
            "Invalid or out-of-range unsigned integer", ErrorCode::malformed);
    return value;
}
std::array<std::byte, 8> descriptor_bytes(const X86SegmentDescriptor &d) {
    const bool g = d.effective_limit > 0xfffff;
    const auto limit = g ? d.effective_limit >> 12 : d.effective_limit;
    return {std::byte(limit),
            std::byte(limit >> 8),
            std::byte(d.base),
            std::byte(d.base >> 8),
            std::byte(d.base >> 16),
            std::byte(0x10 | (d.present ? 0x80 : 0) | (unsigned(d.dpl) << 5) | (d.executable ? 8 : 0) |
                      ((d.executable ? d.readable : d.writable) ? 2 : 0) |
                      ((d.executable ? d.conforming : d.expand_down) ? 4 : 0)),
            std::byte(((limit >> 16) & 15) | (d.default_big ? 0x40 : 0) | (g ? 0x80 : 0)),
            std::byte(d.base >> 24)};
}
} // namespace
} // namespace hexlab::profile_detail
namespace hexlab {
Result<X86RawProfile> parse_x86_profile(std::string_view input) {
    return profile_detail::guarded([&]() -> Result<X86RawProfile> {
        using namespace profile_detail;
        require(input.size() <= x86_profile_text_limit, "Profile exceeds1MiB", ErrorCode::resource_limit);
        require(utf8(input, false), "Profile is not valid UTF8 text", ErrorCode::malformed);
        if (input.starts_with("\xef\xbb\xbf"))
            input.remove_prefix(3);
        X86RawProfile profile;
        bool header = false;
        unsigned fields = 0;
        std::size_t declared = 0, line_number = 0;
        while (!input.empty()) {
            ++line_number;
            const auto newline = input.find('\n');
            const auto line = input.substr(0, newline);
            input = newline == std::string_view::npos ? std::string_view{} : input.substr(newline + 1);
            try {
                require(line.size() <= 4096, "Profile line exceeds4096 bytes", ErrorCode::resource_limit);
                auto row = tokens(line);
                if (row.empty())
                    continue;
                if (!header) {
                    require(row.size() == 2 && row[0] == "hexlab-x86-profile" && row[1] == "1",
                            "Unknown profile version", ErrorCode::unsupported);
                    header = true;
                    continue;
                }
                const auto field = [&](unsigned bit, std::size_t count) {
                    require(row.size() == count && !(fields & bit), "Duplicate or malformed profile field",
                            ErrorCode::malformed);
                    fields |= bit;
                };
                if (row[0] == "environment") {
                    field(1, 2);
                    require(row[1] == "real386" || row[1] == "protected386", "Unknown environment",
                            ErrorCode::malformed);
                    profile.environment =
                        row[1] == "real386" ? X86ImageEnvironment::real386 : X86ImageEnvironment::protected386;
                } else if (row[0] == "a20") {
                    field(2, 2);
                    require(row[1] == "enabled" || row[1] == "disabled", "Unknown A20 policy", ErrorCode::malformed);
                    profile.a20 = row[1] == "enabled" ? A20Policy::enabled : A20Policy::disabled;
                } else if (row[0] == "load") {
                    field(4, 2);
                    profile.input_load_address = static_cast<std::uint32_t>(number(row[1], UINT32_MAX));
                } else if (row[0] == "entry") {
                    field(8, 3);
                    profile.entry = {{static_cast<std::uint32_t>(number(row[1], UINT32_MAX))},
                                     number(row[2], UINT32_MAX)};
                } else if (row[0] == "stack") {
                    field(16, 2);
                    if (row[1] != "none")
                        profile.stack_selector = static_cast<std::uint16_t>(number(row[1], UINT16_MAX));
                } else if (row[0] == "domains") {
                    field(32, 2);
                    declared = static_cast<std::size_t>(number(row[1], x86_profile_domain_limit));
                    require(declared != 0, "Empty domain table", ErrorCode::malformed);
                } else if (row[0] == "domain") {
                    require(row.size() == 6 && (fields & 32) && profile.domains.size() < declared,
                            "Invalid domain row or count", ErrorCode::malformed);
                    require(row[3] == "code" || row[3] == "data", "Unknown domain role", ErrorCode::malformed);
                    X86RawDomain d{{static_cast<std::uint32_t>(number(row[1], UINT32_MAX))},
                                   static_cast<std::uint16_t>(number(row[2], UINT16_MAX)),
                                   row[3] == "code",
                                   row[4],
                                   {}};
                    if (row[5] != "real") {
                        require(row[5].size() == 16, "Descriptor must contain exactly eight hexadecimal bytes",
                                ErrorCode::malformed);
                        std::array<std::byte, 8> raw{};
                        for (std::size_t i = 0; i < 8; ++i) {
                            unsigned value = 0;
                            const auto *start = row[5].data() + 2 * i;
                            const auto parsed = std::from_chars(start, start + 2, value, 16);
                            require(parsed.ec == std::errc{} && parsed.ptr == start + 2, "Invalid descriptor hex",
                                    ErrorCode::malformed);
                            raw[i] = std::byte(value);
                        }
                        d.descriptor = take(parse_x86_segment_descriptor(raw));
                    }
                    profile.domains.push_back(std::move(d));
                } else
                    require(false, "Unknown profile field", ErrorCode::malformed);
            } catch (const Failure &failure) {
                throw Failure{
                    {failure.error.code, "Profile line " + std::to_string(line_number) + ": " + failure.error.message}};
            }
        }
        require(header && fields == 63 && profile.domains.size() == declared,
                "Missing profile fields or domain records", ErrorCode::malformed);
        take(validate_x86_profile(profile));
        std::sort(profile.domains.begin(), profile.domains.end(),
                  [](const auto &a, const auto &b) { return a.space.value < b.space.value; });
        return profile;
    });
}
Result<std::string> format_x86_profile(const X86RawProfile &profile) {
    return profile_detail::guarded([&]() -> Result<std::string> {
        using namespace profile_detail;
        take(validate_x86_profile(profile));
        std::ostringstream out;
        out.imbue(std::locale::classic());
        out << "hexlab-x86-profile 1\nenvironment "
            << (profile.environment == X86ImageEnvironment::real386 ? "real386" : "protected386") << "\na20 "
            << (profile.a20 == A20Policy::enabled ? "enabled" : "disabled") << "\nload 0x" << std::hex
            << profile.input_load_address << "\nentry " << std::dec << profile.entry.space.value << " 0x" << std::hex
            << profile.entry.offset << "\nstack ";
        if (profile.stack_selector)
            out << "0x" << *profile.stack_selector;
        else
            out << "none";
        out << "\ndomains " << std::dec << profile.domains.size() << '\n';
        std::vector<const X86RawDomain *> domains;
        for (const auto &d : profile.domains)
            domains.push_back(&d);
        std::sort(domains.begin(), domains.end(), [](auto a, auto b) { return a->space.value < b->space.value; });
        for (const auto *d : domains) {
            out << "domain " << std::dec << d->space.value << " 0x" << std::hex << d->selector << ' '
                << (d->executable ? "code" : "data") << " \"";
            for (const auto c : d->name) {
                if (c == '\\' || c == '"')
                    out << '\\';
                out << c;
            }
            out << "\" ";
            if (d->descriptor)
                for (const auto b : descriptor_bytes(*d->descriptor))
                    out << std::setfill('0') << std::setw(2) << std::to_integer<unsigned>(b);
            else
                out << "real";
            out << '\n';
            require(out.tellp() <= static_cast<std::streamoff>(x86_profile_text_limit), "Canonical profile exceeds1MiB",
                    ErrorCode::resource_limit);
        }
        return out.str();
    });
}
} // namespace hexlab
