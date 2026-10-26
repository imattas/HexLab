#include "hexlab/firmware/uefi_capsule.hpp"
#include <algorithm>
#include <limits>

namespace hexlab::firmware {
namespace {
std::uint8_t u8(std::span<const std::byte> b, std::size_t at) { return std::to_integer<std::uint8_t>(b[at]); }
std::uint16_t u16(std::span<const std::byte> b, std::size_t at) {
    return static_cast<std::uint16_t>(u8(b, at) | (std::uint16_t(u8(b, at + 1)) << 8));
}
std::uint32_t u32(std::span<const std::byte> b, std::size_t at) {
    return std::uint32_t(u16(b, at)) | (std::uint32_t(u16(b, at + 2)) << 16);
}
std::uint64_t u64(std::span<const std::byte> b, std::size_t at) {
    return std::uint64_t(u32(b, at)) | (std::uint64_t(u32(b, at + 4)) << 32);
}
constexpr std::array<std::uint8_t, 16> fmp_guid{
    0xed,0xd5,0xcb,0x6d,0x2d,0xe8,0x44,0x4c,0xbd,0xa1,0x71,0x94,0x19,0x9a,0xd9,0x2a};
Error malformed(const char *message) { return {ErrorCode::malformed, message}; }
}

Result<UefiCapsule> parse_uefi_fmp_capsule(std::span<const std::byte> bytes,
                                           UefiCapsuleParseOptions options, std::stop_token stop) {
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI capsule parsing canceled"};
    if (bytes.size() > options.max_input_bytes) return Error{ErrorCode::resource_limit, "UEFI capsule exceeds input-size limit"};
    if (bytes.size() < 28) return malformed("EFI capsule header is truncated");
    UefiCapsule result;
    for (std::size_t i = 0; i < 16; ++i) result.capsule_guid[i] = u8(bytes, i);
    if (result.capsule_guid != fmp_guid) return Error{ErrorCode::unsupported, "capsule GUID is not EFI FMP"};
    result.header_size = u32(bytes, 16);
    result.flags = u32(bytes, 20);
    result.image_size = u32(bytes, 24);
    if (result.header_size < 28 || result.header_size > result.image_size || result.image_size > bytes.size())
        return malformed("EFI capsule header or declared image size is inconsistent with the input");
    const std::size_t base = result.header_size;
    if (result.image_size - base < 8) return malformed("FMP capsule header is truncated");
    result.fmp_version = u32(bytes, base);
    result.embedded_driver_count = u16(bytes, base + 4);
    result.payload_count = u16(bytes, base + 6);
    if (result.fmp_version != 1) return Error{ErrorCode::unsupported, "unsupported FMP capsule header version"};
    const std::size_t count = std::size_t(result.embedded_driver_count) + result.payload_count;
    if (count > options.max_items) return Error{ErrorCode::resource_limit, "FMP capsule item count exceeds limit"};
    if (count > (std::numeric_limits<std::size_t>::max)() / 8 || 8 + count * 8 > result.image_size - base)
        return malformed("FMP item-offset list is truncated");
    const std::size_t data_start = 8 + count * 8;
    std::vector<std::uint64_t> offsets;
    offsets.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI capsule parsing canceled"};
        const auto offset = u64(bytes, base + 8 + i * 8);
        if (offset < data_start || offset >= result.image_size - base || (!offsets.empty() && offset <= offsets.back()))
            return malformed("FMP item offsets are out of range or not strictly ascending");
        offsets.push_back(offset);
    }
    result.items.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI capsule parsing canceled"};
        const std::uint64_t item_start = offsets[i];
        const std::uint64_t item_end = i + 1 < count ? offsets[i + 1] : result.image_size - base;
        UefiCapsuleItem item;
        item.file_offset = base + item_start;
        item.size = item_end - item_start;
        if (i < result.embedded_driver_count) {
            item.kind = UefiCapsuleItemKind::embedded_driver;
        } else {
            item.kind = UefiCapsuleItemKind::fmp_payload;
            if (item.size < 32) return malformed("FMP image header is truncated");
            const auto p = static_cast<std::size_t>(item.file_offset);
            item.image_header_version = u32(bytes, p);
            if (item.image_header_version < 1 || item.image_header_version > 3)
                return Error{ErrorCode::unsupported, "unsupported FMP image header version"};
            item.image_header_size = item.image_header_version == 1 ? 32 : item.image_header_version == 2 ? 40 : 48;
            if (item.size < item.image_header_size) return malformed("versioned FMP image header is truncated");
            for (std::size_t j = 0; j < 16; ++j) item.image_type_guid[j] = u8(bytes, p + 4 + j);
            item.image_index = u8(bytes, p + 20);
            item.update_image_size = u32(bytes, p + 24);
            item.vendor_code_size = u32(bytes, p + 28);
            if (item.image_header_version >= 2) item.hardware_instance = u64(bytes, p + 32);
            if (item.image_header_version >= 3) item.image_capsule_support = u64(bytes, p + 40);
            const std::uint64_t content_size = item.image_header_size + item.update_image_size + item.vendor_code_size;
            if (content_size != item.size) return malformed("FMP image and vendor-code sizes do not match item extent");
            item.payload_offset = item.file_offset + item.image_header_size;
            item.vendor_code_offset = item.payload_offset + item.update_image_size;
        }
        result.items.push_back(item);
    }
    return result;
}
} // namespace hexlab::firmware
