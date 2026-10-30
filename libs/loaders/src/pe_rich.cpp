#include "pe_internal.hpp"

namespace hexlab {
Result<std::optional<PeRichHeader>> inspect_pe_rich_header(const ByteStorage &storage,
                                                            std::stop_token stop) try {
    using namespace pe_detail;
    canceled(stop);
    FileReader reader(storage);
    if (reader.integer<std::uint16_t>(0, "DOS signature") != 0x5a4d)
        return Error{ErrorCode::invalid_argument, "Input is not a PE DOS image"};
    const auto nt_offset = reader.integer<std::uint32_t>(0x3c, "e_lfanew");
    require(nt_offset >= 0x40 && nt_offset <= storage.size() && storage.size() - nt_offset >= 4,
            "PE e_lfanew exceeds the source file");
    require(reader.integer<std::uint32_t>(nt_offset, "PE signature") == 0x4550,
            "PE signature is invalid");

    constexpr std::uint32_t rich_signature = 0x68636952; // "Rich"
    constexpr std::uint32_t dans_signature = 0x536e6144; // "DanS"
    constexpr std::uint64_t dos_stub_begin = 0x40;
    constexpr std::uint64_t max_stub_scan_bytes = 1024 * 1024;
    constexpr std::size_t max_records = 4096;
    const auto scan_end = std::min<std::uint64_t>(nt_offset, dos_stub_begin + max_stub_scan_bytes);
    std::optional<std::uint64_t> rich_offset;
    for (std::uint64_t at = dos_stub_begin; at + 4 <= scan_end; at += 4) {
        canceled(stop);
        if (reader.integer<std::uint32_t>(at, "DOS stub") == rich_signature) {
            rich_offset = at;
            break;
        }
    }
    if (!rich_offset) {
        if (scan_end < nt_offset)
            return Error{ErrorCode::resource_limit, "PE DOS stub exceeds the Rich-header scan limit"};
        return std::optional<PeRichHeader>{};
    }
    require(*rich_offset + 8 <= nt_offset, "Rich marker/key exceeds DOS stub");
    const auto key = reader.integer<std::uint32_t>(*rich_offset + 4, "Rich XOR key");

    std::optional<std::uint64_t> dans_offset;
    for (auto at = *rich_offset; at >= dos_stub_begin + 4;) {
        canceled(stop);
        at -= 4;
        if ((reader.integer<std::uint32_t>(at, "encoded Rich data") ^ key) == dans_signature) {
            dans_offset = at;
            break;
        }
    }
    require(dans_offset.has_value(), "Rich header has no encoded DanS signature");
    require(*dans_offset + 16 <= *rich_offset, "Rich header DanS padding overlaps records");
    for (unsigned padding = 1; padding <= 3; ++padding)
        require((reader.integer<std::uint32_t>(*dans_offset + padding * 4, "Rich padding") ^ key) == 0,
                "Rich header DanS padding is not zero after decoding");
    const auto records_begin = *dans_offset + 16;
    const auto record_bytes = *rich_offset - records_begin;
    require(record_bytes % 8 == 0, "Rich header record table has a partial entry");
    const auto count = record_bytes / 8;
    require(count <= max_records, "Rich header record count exceeds parser limit", ErrorCode::resource_limit);

    PeRichHeader result;
    result.source_file_offset = {*dans_offset};
    result.byte_size = static_cast<std::uint32_t>(*rich_offset + 8 - *dans_offset);
    result.xor_key = key;
    result.records.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t index = 0; index < count; ++index) {
        canceled(stop);
        const auto at = records_begin + index * 8;
        result.records.push_back({
            reader.integer<std::uint32_t>(at, "Rich product id") ^ key,
            reader.integer<std::uint32_t>(at + 4, "Rich product count") ^ key});
    }
    return std::optional<PeRichHeader>{std::move(result)};
} catch (const pe_detail::Failure &failure) {
    return failure.error;
} catch (const std::bad_alloc &) {
    return Error{ErrorCode::resource_limit, "Cannot allocate PE Rich-header metadata"};
} catch (const std::length_error &) {
    return Error{ErrorCode::resource_limit, "PE Rich-header metadata exceeds memory limits"};
}
} // namespace hexlab
