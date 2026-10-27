#include "hexlab/firmware/uefi_capsule.hpp"
#include "hexlab/firmware/uefi_volume.hpp"
#include <algorithm>
#include <limits>
#include <utility>

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
constexpr std::array<std::uint8_t, 16> json_guid{
    0xcd,0xf4,0xd6,0x67,0xb8,0xd6,0x73,0x45,0xbf,0x4a,0xde,0x5e,0x25,0x2d,0x61,0xae};
// EFI_CERT_TYPE_PKCS7_GUID as it appears in the little-endian UEFI structure.
constexpr std::array<std::uint8_t, 16> pkcs7_guid{
    0x9d,0xd2,0xaf,0x4a,0xdf,0x68,0xee,0x49,0x8a,0xa9,0x34,0x7d,0x37,0x56,0x65,0xa7};
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
    result.header_extension_size = result.header_size - 28;
    result.trailing_size = bytes.size() - result.image_size;
    // UEFI 2.10 §23.3.3 requires POPULATE_SYSTEM_TABLE to be clear for FMP
    // capsules. Keep the other capsule flags intact for metadata presentation.
    if (result.flags & 0x00020000u)
        return malformed("FMP capsule sets CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE");
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
    std::size_t embedded_volumes_used = 0;
    std::size_t embedded_files_used = 0;
    std::size_t embedded_sections_used = 0;
    std::size_t embedded_scans_used = 0;
    std::uint64_t embedded_decompressed_used = 0;
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
            if (u8(bytes, p + 21) != 0 || u8(bytes, p + 22) != 0 || u8(bytes, p + 23) != 0)
                return malformed("FMP image header reserved bytes are nonzero");
            item.update_image_size = u32(bytes, p + 24);
            item.vendor_code_size = u32(bytes, p + 28);
            if (item.image_header_version >= 2) item.hardware_instance = u64(bytes, p + 32);
            if (item.image_header_version >= 3) item.image_capsule_support = u64(bytes, p + 40);
            const std::uint64_t content_size = item.image_header_size + item.update_image_size + item.vendor_code_size;
            if (content_size != item.size) return malformed("FMP image and vendor-code sizes do not match item extent");
            item.payload_offset = item.file_offset + item.image_header_size;
            item.vendor_code_offset = item.payload_offset + item.update_image_size;

            // IMAGE_AUTHENTICATION_REQUIRED images start UpdateImage with
            // EFI_FIRMWARE_IMAGE_AUTHENTICATION (UINT64 count + a 24-byte
            // WIN_CERTIFICATE_UEFI_GUID header + PKCS#7 bytes). Recognize only
            // the specified certificate kind; other payloads stay opaque.
            if (item.update_image_size >= 32) {
                const auto auth = static_cast<std::size_t>(item.payload_offset);
                const auto certificate_size = u32(bytes, auth + 8);
                const bool is_pkcs7_auth = u16(bytes, auth + 12) == 0x0200 &&
                    u16(bytes, auth + 14) == 0x0ef1 &&
                    std::equal(pkcs7_guid.begin(), pkcs7_guid.end(),
                               reinterpret_cast<const std::uint8_t *>(bytes.data() + auth + 16));
                if (is_pkcs7_auth) {
                    if (certificate_size < 24 || certificate_size > item.update_image_size - 8)
                        return malformed("FMP authentication certificate extent is invalid");
                    item.authentication_present = true;
                    item.authentication_monotonic_count = u64(bytes, auth);
                    item.authentication_certificate_size = certificate_size;
                    std::copy_n(pkcs7_guid.begin(), pkcs7_guid.size(), item.authentication_certificate_guid.begin());
                    item.authentication_certificate_offset = item.payload_offset + 8;
                    item.authentication_certificate_data_offset = item.payload_offset + 32;
                    item.authentication_certificate_data_size = certificate_size - 24;
                    item.authentication_header_size = 8 + certificate_size;
                    item.payload_offset += item.authentication_header_size;
                }
            }

            const auto image_payload_size = std::uint64_t(item.update_image_size) - item.authentication_header_size;
            if (image_payload_size >= 56 && embedded_scans_used < options.max_embedded_payload_scans &&
                embedded_volumes_used < options.max_embedded_volumes &&
                embedded_files_used < options.max_embedded_files &&
                embedded_sections_used < options.max_embedded_sections &&
                embedded_decompressed_used < options.max_embedded_decompressed_bytes) {
                const auto scan_limit = options.max_embedded_decompressed_bytes / options.max_embedded_payload_scans;
                const auto payload = bytes.subspan(static_cast<std::size_t>(item.payload_offset),
                                                   static_cast<std::size_t>(image_payload_size));
                UefiVolumeParseOptions volume_options;
                volume_options.max_input_bytes = options.max_input_bytes;
                volume_options.max_volumes = options.max_embedded_volumes - embedded_volumes_used;
                volume_options.max_files = options.max_embedded_files - embedded_files_used;
                volume_options.max_sections = options.max_embedded_sections - embedded_sections_used;
                volume_options.max_total_decompressed_bytes = std::min(
                    scan_limit, options.max_embedded_decompressed_bytes - embedded_decompressed_used);
                ++embedded_scans_used;
                item.embedded_volume_scan_attempted = true;
                auto volumes = parse_uefi_firmware_volumes(payload, volume_options, stop);
                if (!volumes) {
                    if (volumes.error().code == ErrorCode::canceled) return volumes.error();
                    if (volumes.error().code != ErrorCode::unsupported) {
                        item.embedded_volume_scan_complete = false;
                        item.embedded_volume_diagnostic = volumes.error().message;
                    }
                } else {
                    for (const auto &volume : volumes.value()) {
                        std::size_t sections = 0;
                        std::uint64_t decompressed_bytes = 0;
                        for (const auto &file : volume.files) {
                            sections += file.sections.size();
                            for (const auto &section : file.sections) {
                                if (section.decompression_succeeded && section.uncompressed_size)
                                    decompressed_bytes += *section.uncompressed_size;
                            }
                        }
                        if (embedded_volumes_used == options.max_embedded_volumes ||
                            volume.files.size() > options.max_embedded_files - embedded_files_used ||
                            sections > options.max_embedded_sections - embedded_sections_used ||
                            decompressed_bytes > options.max_embedded_decompressed_bytes - embedded_decompressed_used) {
                            item.embedded_volume_scan_complete = false;
                            item.embedded_volume_diagnostic = "embedded firmware-volume inventory budget exceeded";
                            break;
                        }
                        UefiCapsuleEmbeddedVolume embedded;
                        embedded.file_offset = item.payload_offset + volume.file_offset;
                        embedded.size = volume.length;
                        embedded.file_system_guid = volume.file_system_guid;
                        embedded.revision = volume.revision;
                        embedded.file_count = volume.files.size();
                        embedded.section_count = sections;
                        embedded.decompressed_bytes = decompressed_bytes;
                        embedded.header_checksum_valid = volume.header_checksum_valid;
                        item.embedded_volumes.push_back(embedded);
                        ++embedded_volumes_used;
                        embedded_files_used += volume.files.size();
                        embedded_sections_used += sections;
                        embedded_decompressed_used += decompressed_bytes;
                    }
                }
            } else if (image_payload_size >= 56) {
                item.embedded_volume_scan_complete = false;
                item.embedded_volume_diagnostic = embedded_scans_used >= options.max_embedded_payload_scans
                    ? "embedded firmware-volume payload scan count limit reached"
                    : "embedded firmware-volume inventory budget exhausted";
            }
        }
        result.items.push_back(item);
    }
    return result;
}

Result<UefiCapsuleList> parse_uefi_fmp_capsule_list(
    std::span<const std::span<const std::byte>> capsules,
    UefiCapsuleParseOptions options, std::stop_token stop) {
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI capsule-list parsing canceled"};
    if (capsules.empty()) return malformed("FMP capsule list is empty");
    if (capsules.size() > options.max_capsules)
        return Error{ErrorCode::resource_limit, "FMP capsule count exceeds limit"};

    UefiCapsuleList result;
    result.capsules.reserve(capsules.size());
    std::size_t embedded_volumes_used = 0;
    std::size_t embedded_files_used = 0;
    std::size_t embedded_sections_used = 0;
    std::size_t embedded_scans_used = 0;
    std::uint64_t embedded_decompressed_used = 0;
    for (const auto capsule_bytes : capsules) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI capsule-list parsing canceled"};
        if (result.total_input_bytes > options.max_input_bytes ||
            capsule_bytes.size() > options.max_input_bytes - result.total_input_bytes)
            return Error{ErrorCode::resource_limit, "FMP capsule list exceeds cumulative input-size limit"};
        if (result.total_item_count > options.max_items)
            return Error{ErrorCode::resource_limit, "FMP capsule list exceeds cumulative item limit"};

        auto capsule_options = options;
        capsule_options.max_input_bytes = options.max_input_bytes - result.total_input_bytes;
        capsule_options.max_items = options.max_items - result.total_item_count;
        capsule_options.max_embedded_volumes = options.max_embedded_volumes - embedded_volumes_used;
        capsule_options.max_embedded_files = options.max_embedded_files - embedded_files_used;
        capsule_options.max_embedded_sections = options.max_embedded_sections - embedded_sections_used;
        capsule_options.max_embedded_payload_scans = options.max_embedded_payload_scans - embedded_scans_used;
        capsule_options.max_embedded_decompressed_bytes = options.max_embedded_decompressed_bytes - embedded_decompressed_used;
        auto parsed = parse_uefi_fmp_capsule(capsule_bytes, capsule_options, stop);
        if (!parsed) return parsed.error();
        if (result.capsules.empty()) {
            result.capsule_guid = parsed.value().capsule_guid;
        } else if (parsed.value().capsule_guid != result.capsule_guid) {
            return malformed("FMP capsule list contains differing capsule GUIDs");
        }
        result.total_input_bytes += capsule_bytes.size();
        result.total_item_count += parsed.value().items.size();
        for (const auto &item : parsed.value().items) {
            embedded_volumes_used += item.embedded_volumes.size();
            if (item.embedded_volume_scan_attempted) ++embedded_scans_used;
            for (const auto &volume : item.embedded_volumes) {
                embedded_files_used += volume.file_count;
                embedded_sections_used += volume.section_count;
                embedded_decompressed_used += volume.decompressed_bytes;
            }
        }
        result.capsules.push_back(std::move(parsed.value()));
    }
    return result;
}

Result<UefiJsonCapsule> parse_uefi_json_capsule(std::span<const std::byte> bytes,
                                               UefiCapsuleParseOptions options, std::stop_token stop) {
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI capsule parsing canceled"};
    if (bytes.size() > options.max_input_bytes) return Error{ErrorCode::resource_limit, "UEFI capsule exceeds input-size limit"};
    if (bytes.size() < 40) return malformed("EFI JSON capsule header is truncated");
    UefiJsonCapsule result;
    for (std::size_t i = 0; i < 16; ++i) result.capsule_guid[i] = u8(bytes, i);
    if (result.capsule_guid != json_guid) return Error{ErrorCode::unsupported, "capsule GUID is not EFI JSON"};
    result.header_size = u32(bytes, 16);
    result.flags = u32(bytes, 20);
    result.image_size = u32(bytes, 24);
    if (result.header_size < 28 || result.header_size > result.image_size || result.image_size > bytes.size())
        return malformed("EFI JSON capsule header or declared image size is inconsistent with the input");
    result.header_extension_size = result.header_size - 28;
    result.trailing_size = bytes.size() - result.image_size;
    if (result.flags & 0x00020000u)
        return malformed("JSON capsule sets CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE");
    if (std::uint64_t(result.header_size) + 12 > result.image_size)
        return malformed("EFI JSON capsule body header is truncated");
    const auto body = static_cast<std::size_t>(result.header_size);
    result.json_header_version = u32(bytes, body);
    result.capsule_id = u32(bytes, body + 4);
    result.payload_size = u32(bytes, body + 8);
    if (result.json_header_version != 1)
        return Error{ErrorCode::unsupported, "unsupported EFI JSON capsule header version"};
    if (result.payload_size == 0 || std::uint64_t(body) + 12 + result.payload_size != result.image_size)
        return malformed("EFI JSON capsule payload length does not match the declared capsule extent");
    result.payload_offset = body + 12;
    return result;
}
} // namespace hexlab::firmware
