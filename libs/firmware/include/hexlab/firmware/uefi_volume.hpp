#pragma once
#include "hexlab/core/result.hpp"
#include "hexlab/firmware/firmware_export.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

namespace hexlab::firmware {
enum class UefiSectionDisposition : std::uint8_t {
    leaf,
    nested_sections,
    decompressed_sections,
    opaque_compressed,
    opaque_guid_defined,
    processing_required,
    malformed_nested_payload
};
enum class UefiSectionOffsetSpace : std::uint8_t { file, decompressed };
struct UefiFfsSection {
    // Offsets are absolute input offsets in `file` space and relative to the
    // decompressed stream in `decompressed` space. parent_index identifies
    // the section that owns a decompressed stream.
    std::uint64_t file_offset = 0;
    std::uint64_t size = 0;
    std::uint64_t header_size = 0;
    std::uint64_t payload_offset = 0;
    std::uint64_t payload_size = 0;
    std::uint8_t type = 0;
    std::uint32_t depth = 0;
    std::optional<std::size_t> parent_index;
    UefiSectionOffsetSpace offset_space = UefiSectionOffsetSpace::file;
    bool decompression_succeeded = false;
    UefiSectionDisposition disposition = UefiSectionDisposition::leaf;
    std::optional<std::uint32_t> uncompressed_size;
    std::optional<std::uint8_t> compression_type;
    std::optional<std::array<std::uint8_t, 16>> definition_guid;
    std::optional<std::uint16_t> definition_data_offset;
    std::optional<std::uint16_t> definition_attributes;
    std::optional<std::array<std::uint8_t, 16>> freeform_subtype_guid;
    std::optional<std::uint16_t> version_build;
    std::optional<std::u16string> ui_name;
    std::optional<std::u16string> version_text;
    std::string diagnostic;
};
struct UefiFfsFile {
    std::array<std::uint8_t, 16> name_guid{};
    std::uint64_t volume_offset = 0;
    std::uint64_t size = 0;
    std::uint64_t data_offset = 0;
    std::uint64_t data_size = 0;
    std::uint8_t type = 0;
    std::uint8_t attributes = 0;
    std::uint8_t state = 0;
    std::uint8_t header_size = 0;
    bool header_checksum_valid = false;
    // Present only when EFI_FILE_DATA_VALID is set in the normalized state.
    // FFS_ATTRIB_CHECKSUM selects the body checksum; otherwise the required
    // fixed checksum value is 0xAA.
    std::optional<bool> data_checksum_valid;
    std::vector<UefiFfsSection> sections;
    std::string section_diagnostic;
};
struct UefiFirmwareVolume {
    std::array<std::uint8_t, 16> file_system_guid{};
    std::uint64_t file_offset = 0;
    std::uint64_t length = 0;
    std::uint64_t attributes = 0;
    std::uint16_t header_length = 0;
    std::uint8_t revision = 0;
    bool header_checksum_valid = false;
    std::vector<UefiFfsFile> files;
};
struct UefiVolumeParseOptions {
    std::uint64_t max_input_bytes = 512ull * 1024 * 1024;
    std::size_t max_volumes = 256;
    std::size_t max_files = 1'000'000;
    std::size_t max_sections = 1'000'000;
    std::size_t max_section_depth = 8;
    std::uint64_t max_compressed_section_bytes = 16ull * 1024 * 1024;
    std::uint64_t max_decompressed_section_bytes = 64ull * 1024 * 1024;
    std::uint64_t max_total_decompressed_bytes = 128ull * 1024 * 1024;
    std::uint64_t max_active_decompressed_bytes = 64ull * 1024 * 1024;
    std::uint64_t max_decompression_work = 256ull * 1024 * 1024;
};
// Finds PI firmware volumes embedded at any file offset and inventories their
// FFS file headers and bounded section metadata. Standard EFI and Tiano
// compressed sections are decoded only into a bounded temporary buffer for
// child-section inventory. GUID-defined sections that do not require a
// processor are traversed as ordinary nested section streams; processor-
// required payloads remain opaque.
HEXLAB_FIRMWARE_EXPORT Result<std::vector<UefiFirmwareVolume>> parse_uefi_firmware_volumes(
    std::span<const std::byte> bytes, UefiVolumeParseOptions options = {}, std::stop_token stop = {});
HEXLAB_FIRMWARE_EXPORT std::string uefi_guid_string(const std::array<std::uint8_t, 16> &guid);
} // namespace hexlab::firmware
