#pragma once
#include "hexlab/core/result.hpp"
#include "hexlab/firmware/firmware_export.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

namespace hexlab::firmware {
enum class UefiCapsuleItemKind : std::uint8_t { embedded_driver, fmp_payload };
struct UefiCapsuleEmbeddedVolume {
    std::uint64_t file_offset = 0;
    std::uint64_t size = 0;
    std::array<std::uint8_t, 16> file_system_guid{};
    std::uint8_t revision = 0;
    std::size_t file_count = 0;
    std::size_t section_count = 0;
    std::uint64_t decompressed_bytes = 0;
    bool header_checksum_valid = false;
};
struct UefiCapsuleItem {
    UefiCapsuleItemKind kind = UefiCapsuleItemKind::embedded_driver;
    std::uint64_t file_offset = 0;
    std::uint64_t size = 0;
    std::uint32_t image_header_version = 0;
    std::array<std::uint8_t, 16> image_type_guid{};
    std::uint8_t image_index = 0;
    std::uint32_t update_image_size = 0;
    std::uint32_t vendor_code_size = 0;
    std::uint64_t image_header_size = 0;
    std::uint64_t payload_offset = 0;
    std::uint64_t vendor_code_offset = 0;
    std::uint64_t hardware_instance = 0;
    std::uint64_t image_capsule_support = 0;
    // Bounded PI firmware volumes discovered inside the update image payload.
    std::vector<UefiCapsuleEmbeddedVolume> embedded_volumes;
    bool embedded_volume_scan_attempted = false;
    bool embedded_volume_scan_complete = true;
    std::string embedded_volume_diagnostic;
};
struct UefiCapsule {
    std::array<std::uint8_t, 16> capsule_guid{};
    std::uint32_t header_size = 0;
    // Bytes between the fixed EFI_CAPSULE_HEADER and HeaderSize are retained
    // as an opaque extension. Offsets are relative to the capsule input.
    std::uint64_t header_extension_offset = 28;
    std::uint64_t header_extension_size = 0;
    std::uint32_t flags = 0;
    std::uint32_t image_size = 0;
    std::uint64_t trailing_size = 0;
    std::uint32_t fmp_version = 0;
    std::uint16_t embedded_driver_count = 0;
    std::uint16_t payload_count = 0;
    std::vector<UefiCapsuleItem> items;
};
struct UefiCapsuleList {
    std::array<std::uint8_t, 16> capsule_guid{};
    std::uint64_t total_input_bytes = 0;
    std::size_t total_item_count = 0;
    std::vector<UefiCapsule> capsules;
};
struct UefiJsonCapsule {
    std::array<std::uint8_t, 16> capsule_guid{};
    std::uint32_t header_size = 0;
    std::uint64_t header_extension_offset = 28;
    std::uint64_t header_extension_size = 0;
    std::uint32_t flags = 0;
    std::uint32_t image_size = 0;
    std::uint64_t trailing_size = 0;
    std::uint32_t json_header_version = 0;
    std::uint32_t capsule_id = 0;
    std::uint32_t payload_size = 0;
    std::uint64_t payload_offset = 0;
};
struct UefiCapsuleParseOptions {
    std::uint64_t max_input_bytes = 512ull * 1024 * 1024;
    std::size_t max_items = 4096;
    std::size_t max_capsules = 256;
    std::size_t max_embedded_volumes = 64;
    std::size_t max_embedded_files = 65536;
    std::size_t max_embedded_sections = 65536;
    std::size_t max_embedded_payload_scans = 64;
    std::uint64_t max_embedded_decompressed_bytes = 128ull * 1024 * 1024;
};
// Parses one contiguous EFI FMP capsule beginning at file offset zero. Payloads
// remain opaque; returned offsets are absolute offsets into the input file.
HEXLAB_FIRMWARE_EXPORT Result<UefiCapsule> parse_uefi_fmp_capsule(
    std::span<const std::byte> bytes, UefiCapsuleParseOptions options = {}, std::stop_token stop = {});
// Parses an EFI_CAPSULE_TABLE-style list of independent contiguous FMP capsule
// buffers. The input list is bounded cumulatively; payload offsets stay local
// to their respective capsule buffer.
HEXLAB_FIRMWARE_EXPORT Result<UefiCapsuleList> parse_uefi_fmp_capsule_list(
    std::span<const std::span<const std::byte>> capsules,
    UefiCapsuleParseOptions options = {}, std::stop_token stop = {});
// Parses the standard EFI JSON capsule envelope. The JSON payload remains opaque.
HEXLAB_FIRMWARE_EXPORT Result<UefiJsonCapsule> parse_uefi_json_capsule(
    std::span<const std::byte> bytes, UefiCapsuleParseOptions options = {}, std::stop_token stop = {});
} // namespace hexlab::firmware
