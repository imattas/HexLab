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
enum class UefiCapsuleItemKind : std::uint8_t { embedded_driver, fmp_payload };
enum class UefiNestedCapsuleKind : std::uint8_t { fmp, json };
struct UefiNestedCapsule;
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
    // Optional EFI_FIRMWARE_IMAGE_AUTHENTICATION prefix at the beginning of
    // UpdateImage. Signature bytes are inventoried but never verified.
    bool authentication_present = false;
    std::uint64_t authentication_monotonic_count = 0;
    std::uint32_t authentication_certificate_size = 0;
    std::array<std::uint8_t, 16> authentication_certificate_guid{};
    std::uint64_t authentication_certificate_offset = 0;
    std::uint64_t authentication_certificate_data_offset = 0;
    std::uint64_t authentication_certificate_data_size = 0;
    std::uint64_t authentication_header_size = 0;
    // UpdateImage byte span covered by AuthInfo, after an optional dependency
    // expression. This identifies bytes; it does not verify the signature.
    std::uint64_t authentication_signed_image_offset = 0;
    std::uint64_t authentication_signed_image_size = 0;
    std::uint64_t payload_offset = 0;
    // When the image header advertises CAPSULE_SUPPORT_DEPENDENCY, this is
    // the validated prefix expression inside UpdateImage. The expression is
    // metadata only; its version predicates need caller-supplied state.
    bool dependency_expression_present = false;
    std::uint64_t dependency_expression_offset = 0, dependency_expression_size = 0;
    // Optional EDK II FMP_PAYLOAD_HEADER (MSS1) immediately inside UpdateImage.
    bool fmp_payload_header_present = false;
    std::uint64_t fmp_payload_header_offset = 0, fmp_payload_header_size = 0;
    std::uint32_t firmware_version = 0, lowest_supported_firmware_version = 0;
    std::uint64_t firmware_image_offset = 0;
    std::uint64_t vendor_code_offset = 0;
    std::uint64_t hardware_instance = 0;
    std::uint64_t image_capsule_support = 0;
    // Exact source byte for the v3 ImageCapsuleSupport field; zero for older
    // image-header versions.
    std::uint64_t image_capsule_support_offset = 0;
    bool capsule_support_authentication_advertised = false;
    bool capsule_support_dependency_advertised = false;
    std::uint64_t capsule_support_unrecognized_bits = 0;
    // A mismatch is advisory: the parser inventories the bytes but does not
    // reject a capsule based on firmware-specific update policy.
    bool capsule_support_authentication_mismatch = false;
    std::string capsule_support_authentication_diagnostic;
    // Bounded PI firmware volumes discovered inside an embedded driver item or
    // the update image payload. Offsets address the containing capsule buffer.
    std::vector<UefiCapsuleEmbeddedVolume> embedded_volumes;
    bool embedded_volume_scan_attempted = false;
    bool embedded_volume_scan_complete = true;
    std::string embedded_volume_diagnostic;
    // Nested capsules are recognized only when a known capsule GUID begins at
    // the item or payload start (after any recognized auth prefix). Offsets are
    // relative to this item.
    std::vector<UefiNestedCapsule> nested_capsules;
    bool nested_capsule_scan_attempted = false;
    bool nested_capsule_scan_complete = true;
    std::string nested_capsule_diagnostic;
};
struct UefiFmpSignerVerification {
    bool signature_valid = false;
    std::uint32_t provider_error = 0;
    bool operator==(const UefiFmpSignerVerification &) const = default;
};
struct UefiFmpAuthenticationVerification {
    std::vector<UefiFmpSignerVerification> signers;
};
// Verifies detached PKCS#7 signatures over MonotonicCount followed by the
// authenticated UpdateImage bytes using the Windows Crypt32 provider. It does
// not establish signer trust or enforce freshness/update policy.
HEXLAB_FIRMWARE_EXPORT Result<UefiFmpAuthenticationVerification> verify_uefi_fmp_authentication(
    std::span<const std::byte> capsule_bytes, const UefiCapsuleItem &, std::stop_token = {});

enum class UefiFmpDependencyResult : std::uint8_t { satisfied, unsatisfied, indeterminate };
struct UefiFmpImageVersion {
    std::array<std::uint8_t, 16> image_type_guid{};
    std::uint32_t version = 0;
};
struct UefiFmpInstalledImage {
    std::array<std::uint8_t, 16> image_type_guid{};
    std::uint32_t version = 0;
    // Missing floors keep the policy result indeterminate; zero is a valid floor.
    std::optional<std::uint32_t> lowest_supported_version;
};
enum class UefiFmpAntiRollbackResult : std::uint8_t { permitted, prevented, not_installed, indeterminate };
// Evaluate the update image's version against the installed image's declared
// rollback floor. This is advisory only and does not apply an update.
HEXLAB_FIRMWARE_EXPORT Result<UefiFmpAntiRollbackResult> evaluate_uefi_fmp_anti_rollback(
    const UefiCapsuleItem &update, std::span<const UefiFmpInstalledImage> installed_images,
    bool inventory_complete, std::stop_token stop = {});
// Evaluate a complete, bounded FMP dependency expression using caller-supplied
// current image versions. A missing GUID is unsatisfied only when the caller
// says its version inventory is complete; otherwise it is indeterminate.
HEXLAB_FIRMWARE_EXPORT Result<UefiFmpDependencyResult> evaluate_uefi_fmp_dependency_expression(
    std::span<const std::byte> expression, std::span<const UefiFmpImageVersion> versions,
    bool version_inventory_complete, std::stop_token stop = {});
struct UefiNestedCapsule {
    UefiNestedCapsuleKind kind = UefiNestedCapsuleKind::fmp;
    // size is the declared ImageSize; candidate_size is the available span in
    // the parent item, which can be larger when the nested input has trailing bytes.
    std::uint64_t item_relative_offset = 0, size = 0, candidate_size = 0, trailing_size = 0;
    std::array<std::uint8_t, 16> capsule_guid{};
    std::uint32_t header_size = 0, image_size = 0, flags = 0;
    std::uint32_t fmp_version = 0, json_header_version = 0, json_capsule_id = 0;
    std::vector<UefiCapsuleItem> items;
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
enum class UefiCapsuleListKind : std::uint8_t { fmp, json };
struct UefiCapsuleList {
    std::array<std::uint8_t, 16> capsule_guid{};
    std::uint64_t total_input_bytes = 0;
    std::size_t total_capsule_count = 0;
    std::size_t total_item_count = 0;
    UefiCapsuleListKind kind = UefiCapsuleListKind::fmp;
    std::vector<UefiCapsule> capsules;
    std::vector<UefiJsonCapsule> json_capsules;
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
    std::size_t max_nested_capsules = 64;
    std::size_t max_nested_depth = 4;
    std::uint64_t max_nested_bytes = 128ull * 1024 * 1024;
    std::uint64_t max_json_payload_bytes = 16ull * 1024 * 1024;
    std::size_t max_json_depth = 128;
};
enum class UefiCapsuleBlockKind : std::uint8_t { data, continuation, terminator };
struct UefiCapsuleCaptureRegion {
    std::uint64_t physical_base = 0;
    std::span<const std::byte> bytes;
};
struct UefiCapsuleBlock {
    UefiCapsuleBlockKind kind = UefiCapsuleBlockKind::data;
    std::uint64_t descriptor_physical_address = 0, descriptor_capture_offset = 0;
    std::uint64_t length = 0, target_physical_address = 0;
    // Input-region indexes for descriptor_capture_offset and data_capture_offset.
    std::size_t descriptor_region_index = 0, data_region_index = 0;
    // Data descriptors map [logical_offset, logical_offset + length) into
    // the original capture at data_capture_offset. Control entries have no data.
    std::uint64_t logical_offset = 0, data_capture_offset = 0;
};
struct UefiCapsuleScatterGatherOptions {
    std::size_t max_descriptors = 4096;
    std::uint64_t max_payload_bytes = 128ull * 1024 * 1024;
    UefiCapsuleParseOptions capsule;
};
struct UefiScatterGatherCapsule {
    std::uint64_t capture_physical_base = 0, descriptor_head = 0, payload_bytes = 0;
    std::vector<std::uint64_t> capture_region_bases;
    std::vector<UefiCapsuleBlock> blocks;
    // All capsule/item/embedded-volume offsets refer to the logical gathered
    // capsule, not the capture file. blocks preserves the source translation.
    UefiCapsule capsule;
};
struct UefiScatterGatherCapsuleList {
    std::uint64_t capture_physical_base = 0, descriptor_head = 0, payload_bytes = 0;
    std::vector<std::uint64_t> capture_region_bases;
    std::vector<UefiCapsuleBlock> blocks;
    // One offset per inventory.capsules row in the concatenated logical
    // stream. Capsule/item/FV offsets within each inventory row remain local
    // to that capsule; add its stream offset before translating through blocks.
    std::vector<std::uint64_t> capsule_logical_offsets;
    UefiCapsuleList inventory;
};
// Offline little-endian EFI_CAPSULE_BLOCK_DESCRIPTOR chain in one flat,
// explicitly based physical-memory capture. Exactly one persistent FMP capsule
// is supported; no live pointer dereferences or implicit address/file mapping.
HEXLAB_FIRMWARE_EXPORT Result<UefiScatterGatherCapsule> parse_uefi_fmp_scatter_gather(
    std::span<const std::byte> capture, std::uint64_t physical_base, std::uint64_t descriptor_head,
    UefiCapsuleScatterGatherOptions options = {}, std::stop_token stop = {});
// Offline persistent FMP capsules concatenated in descriptor traversal order.
// Each declared ImageSize delimits one capsule without padding or trailing
// bytes. Counts and all embedded/nested work share cumulative list budgets.
HEXLAB_FIRMWARE_EXPORT Result<UefiScatterGatherCapsuleList> parse_uefi_fmp_scatter_gather_list(
    std::span<const std::byte> capture, std::uint64_t physical_base, std::uint64_t descriptor_head,
    UefiCapsuleScatterGatherOptions options = {}, std::stop_token stop = {});
// Offline scatter/gather inventory from several sparse physical captures. Each
// descriptor and data extent must fit wholly inside one non-overlapping region.
// Returned block region indexes identify the corresponding input region; byte
// offsets remain local to that region. Region storage must remain stable while
// parsing runs. A one-capsule stream is returned as a one-entry list.
HEXLAB_FIRMWARE_EXPORT Result<UefiScatterGatherCapsuleList> parse_uefi_fmp_scatter_gather_regions(
    std::span<const UefiCapsuleCaptureRegion> regions, std::uint64_t descriptor_head,
    UefiCapsuleScatterGatherOptions options = {}, std::stop_token stop = {});
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
// Parses an EFI_CAPSULE_TABLE-style list of same-GUID FMP or JSON capsule
// buffers. Per-buffer offsets remain local to the corresponding input.
HEXLAB_FIRMWARE_EXPORT Result<UefiCapsuleList> parse_uefi_capsule_list(
    std::span<const std::span<const std::byte>> capsules,
    UefiCapsuleParseOptions options = {}, std::stop_token stop = {});
// Parses the standard EFI JSON capsule envelope and validates generic JSON syntax.
// The firmware-specific JSON schema remains opaque.
HEXLAB_FIRMWARE_EXPORT Result<UefiJsonCapsule> parse_uefi_json_capsule(
    std::span<const std::byte> bytes, UefiCapsuleParseOptions options = {}, std::stop_token stop = {});
} // namespace hexlab::firmware
