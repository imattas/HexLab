#include "hexlab/loaders/vdex.hpp"
#include <algorithm>
#include <array>
#include <new>
#include <span>
#include <string_view>
#include <utility>

namespace hexlab {
namespace {
Result<std::vector<std::byte>> read_bytes(const ByteStorage &storage, std::uint64_t offset, std::size_t size) {
    auto view = storage.read_at({offset}, size);
    if (!view) return view.error();
    return std::vector<std::byte>(view.value().bytes.begin(), view.value().bytes.end());
}
std::uint32_t le32(std::span<const std::byte> bytes, std::size_t offset) {
    return std::to_integer<std::uint32_t>(bytes[offset]) |
        (std::to_integer<std::uint32_t>(bytes[offset + 1]) << 8) |
        (std::to_integer<std::uint32_t>(bytes[offset + 2]) << 16) |
        (std::to_integer<std::uint32_t>(bytes[offset + 3]) << 24);
}
bool bytes_equal(std::span<const std::byte> bytes, std::size_t offset, std::string_view value) {
    return offset <= bytes.size() && value.size() <= bytes.size() - offset &&
        std::equal(value.begin(), value.end(), bytes.begin() + static_cast<std::ptrdiff_t>(offset),
            [](char a, std::byte b) { return static_cast<unsigned char>(a) == std::to_integer<unsigned char>(b); });
}
}

Result<AndroidVdexInventory> inspect_android_vdex_027(
        const ByteStorage &storage, std::stop_token stop, AndroidVdexLimits limits) {
    constexpr std::uint32_t header_size = 12;
    constexpr std::uint32_t section_header_size = 12;
    constexpr std::uint32_t section_count_expected = 4;
    constexpr std::uint32_t checksum_section = 0;
    constexpr std::uint32_t dex_section = 1;
    if (!limits.max_input_bytes || !limits.max_dex_files || limits.max_dex_files > 1'000'000)
        return Error{ErrorCode::invalid_argument, "VDEX limits are invalid"};
    if (storage.size() > limits.max_input_bytes)
        return Error{ErrorCode::resource_limit, "VDEX input exceeds configured byte limit"};
    if (storage.size() < header_size)
        return Error{ErrorCode::malformed, "VDEX header is truncated"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "VDEX inspection canceled"};
    auto header_read = read_bytes(storage, 0, header_size);
    if (!header_read) return header_read.error();
    const auto header = std::span<const std::byte>(header_read.value());
    if (!bytes_equal(header, 0, "vdex") || !bytes_equal(header, 4, "027\0"))
        return Error{ErrorCode::unsupported, "Only Android VDEX version 027 is supported"};
    const auto section_count = le32(header, 8);
    if (section_count != section_count_expected)
        return Error{ErrorCode::unsupported, "VDEX 027 must declare four section headers"};
    const auto table_end = std::uint64_t(header_size) + std::uint64_t(section_count) * section_header_size;
    if (table_end > storage.size()) return Error{ErrorCode::malformed, "VDEX section table exceeds input"};
    auto table_read = read_bytes(storage, header_size, section_count * section_header_size);
    if (!table_read) return table_read.error();
    const auto table = std::span<const std::byte>(table_read.value());
    try {
        AndroidVdexInventory result;
        result.file_size = {storage.size()};
        result.sections.reserve(section_count);
        std::array<bool, section_count_expected> seen{};
        std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
        ranges.reserve(section_count);
        for (std::uint32_t index = 0; index < section_count; ++index) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "VDEX inspection canceled"};
            const auto at = static_cast<std::size_t>(index) * section_header_size;
            AndroidVdexSection section;
            section.kind = le32(table, at);
            const auto offset = le32(table, at + 4);
            section.size = le32(table, at + 8);
            if (section.kind >= section_count_expected || seen[section.kind])
                return Error{ErrorCode::malformed, "VDEX section kind is unknown or duplicated"};
            seen[section.kind] = true;
            if (offset < table_end || offset > storage.size() || section.size > storage.size() - offset)
                return Error{ErrorCode::malformed, "VDEX section extent is outside the file"};
            section.file_offset = {offset};
            if (section.size) ranges.emplace_back(offset, std::uint64_t(offset) + section.size);
            result.sections.push_back(section);
        }
        if (!std::all_of(seen.begin(), seen.end(), [](bool value) { return value; }))
            return Error{ErrorCode::malformed, "VDEX section table omits a required section kind"};
        std::sort(ranges.begin(), ranges.end());
        for (std::size_t i = 1; i < ranges.size(); ++i)
            if (ranges[i - 1].second > ranges[i].first)
                return Error{ErrorCode::malformed, "VDEX sections overlap"};
        const auto section_for = [&](std::uint32_t kind) -> const AndroidVdexSection & {
            return *std::find_if(result.sections.begin(), result.sections.end(),
                [&](const AndroidVdexSection &section) { return section.kind == kind; });
        };
        const auto &checksums = section_for(checksum_section);
        if (checksums.size % 4)
            return Error{ErrorCode::malformed, "VDEX checksum section has a partial checksum word"};
        result.dex_checksum_count = checksums.size / 4;
        if (result.dex_checksum_count > limits.max_dex_files)
            return Error{ErrorCode::resource_limit, "VDEX DEX count exceeds configured limit"};
        const auto &dex = section_for(dex_section);
        result.dex_section_present = dex.size != 0;
        if (!result.dex_section_present) return result;
        if (!result.dex_checksum_count)
            return Error{ErrorCode::malformed, "VDEX has DEX bytes but no checksum entries"};
        auto checksum_bytes = read_bytes(storage, checksums.file_offset.value, checksums.size);
        if (!checksum_bytes) return checksum_bytes.error();
        std::uint64_t cursor = dex.file_offset.value;
        const auto dex_end = cursor + dex.size;
        result.dex_members.reserve(result.dex_checksum_count);
        for (std::uint32_t index = 0; index < result.dex_checksum_count; ++index) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "VDEX DEX member inspection canceled"};
            if ((cursor & 3u) != 0 || cursor > dex_end || 112 > dex_end - cursor)
                return Error{ErrorCode::malformed, "VDEX DEX member header is truncated or misaligned"};
            auto dex_header_read = read_bytes(storage, cursor, 112);
            if (!dex_header_read) return dex_header_read.error();
            const auto dex_header = std::span<const std::byte>(dex_header_read.value());
            if (!bytes_equal(dex_header, 0, "dex\n") || dex_header[7] != std::byte{0} ||
                (!bytes_equal(dex_header, 4, "035") && !bytes_equal(dex_header, 4, "036") &&
                 !bytes_equal(dex_header, 4, "037") && !bytes_equal(dex_header, 4, "038") &&
                 !bytes_equal(dex_header, 4, "039") && !bytes_equal(dex_header, 4, "040")))
                return Error{ErrorCode::unsupported, "VDEX contains a nonstandard or unsupported DEX version"};
            const auto size = le32(dex_header, 32);
            if (le32(dex_header, 36) != 0x70 || le32(dex_header, 40) != 0x12345678 ||
                size < 112 || size > dex_end - cursor)
                return Error{ErrorCode::malformed, "VDEX DEX header has invalid size or byte-order tag"};
            const auto checksums_span = std::span<const std::byte>(checksum_bytes.value());
            AndroidVdexDexMember member;
            member.index = index;
            member.header_file_offset = {cursor};
            member.file_size = size;
            member.header_checksum = le32(dex_header, 8);
            member.vdex_checksum = le32(checksums_span, std::size_t(index) * 4);
            member.version = static_cast<std::uint32_t>(
                (std::to_integer<unsigned>(dex_header[5]) - '0') * 10 +
                (std::to_integer<unsigned>(dex_header[6]) - '0'));
            member.checksum_fields_match = member.header_checksum == member.vdex_checksum;
            result.dex_members.push_back(member);
            const auto after = cursor + size;
            cursor = (after + 3u) & ~std::uint64_t{3};
            if (cursor > dex_end && index + 1 != result.dex_checksum_count)
                return Error{ErrorCode::malformed, "VDEX DEX alignment exceeds its section"};
        }
        if (cursor > dex_end || dex_end - cursor > 3)
            return Error{ErrorCode::malformed, "VDEX DEX section contains unparsed trailing bytes"};
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate VDEX inventory"};
    }
}
} // namespace hexlab
