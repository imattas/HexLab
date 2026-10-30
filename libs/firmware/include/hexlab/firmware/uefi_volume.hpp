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
enum class UefiFfsFileDisposition : std::uint8_t {
    construction,
    header_valid,
    data_valid,
    marked_for_update,
    deleted,
    header_invalid,
    unrecognized_state
};
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
    std::optional<std::uint32_t> guided_crc32;
    std::optional<bool> guided_crc32_valid;
    std::optional<std::array<std::uint8_t, 16>> freeform_subtype_guid;
    std::optional<std::uint16_t> version_build;
    std::optional<std::u16string> ui_name;
    std::optional<std::u16string> version_text;
    std::optional<bool> depex_valid;
    std::uint32_t depex_instruction_count = 0, depex_guid_operand_count = 0, depex_max_stack_depth = 0;
    std::string depex_diagnostic;
    // Raw validated DEPEX bytecode, including END and optional leading SOR.
    // Retained so callers can evaluate it against their dispatch environment.
    std::vector<std::byte> depex_expression;
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
    UefiFfsFileDisposition disposition = UefiFfsFileDisposition::unrecognized_state;
    std::uint8_t header_size = 0;
    bool header_checksum_valid = false;
    // Required alignment for the beginning of file data, relative to the FV base.
    // PI FFS supports powers/values from 1 byte through 16 MiB.
    std::uint32_t data_alignment = 1;
    bool data_alignment_valid = true;
    bool pad_file = false;
    std::optional<bool> pad_data_erase_polarity_valid;
    // Present only when EFI_FILE_DATA_VALID is set in the normalized state.
    // FFS_ATTRIB_CHECKSUM selects the body checksum; otherwise the required
    // fixed checksum value is 0xAA.
    std::optional<bool> data_checksum_valid;
    std::vector<UefiFfsSection> sections;
    std::string section_diagnostic;
};
struct UefiFirmwareVolumeExtensionEntry {
    std::uint16_t type = 0;
    std::uint16_t size = 0;
    // Offsets are relative to the beginning of the containing firmware volume.
    std::uint64_t volume_offset = 0;
    std::uint64_t payload_offset = 0;
    std::uint64_t payload_size = 0;
};
struct UefiFirmwareVolumeFreeSpaceRegion {
    // Offset is relative to the beginning of the containing firmware volume.
    std::uint64_t volume_offset = 0;
    std::uint64_t size = 0;
    bool erase_polarity_valid = false;
};
struct UefiFirmwareVolumeBlockMapEntry {
    std::uint32_t block_count = 0;
    std::uint32_t block_size = 0;
};
enum class UefiDepexEvaluationStatus : std::uint8_t {
    evaluated,
    invalid_expression,
    input_limit_exceeded,
    ordering_required,
    sor_requires_dispatch_context
};
struct UefiDepexEvaluation {
    UefiDepexEvaluationStatus status = UefiDepexEvaluationStatus::invalid_expression;
    std::optional<bool> satisfied;
    bool schedule_on_request = false;
    std::uint32_t instructions_evaluated = 0;
    std::string diagnostic;
};
enum class UefiDriverDispatchDisposition : std::uint8_t {
    ordered_ready, blocked, ordering_unresolved, invalid_dependency, non_driver
};
struct UefiDriverDispatchEntry {
    std::size_t file_index = 0;
    std::vector<std::size_t> dependency_section_indices;
    UefiDriverDispatchDisposition disposition = UefiDriverDispatchDisposition::blocked;
    std::vector<std::array<std::uint8_t, 16>> missing_guids;
    std::string diagnostic;
};
struct UefiDriverDispatchPlan {
    // Stable recommendation order of ready files for the corresponding static
    // planner. Callers remain responsible for actual dispatch.
    std::vector<std::size_t> ordered_file_indices;
    std::vector<UefiDriverDispatchEntry> entries;
    bool apriori_file_present = false;
    std::string apriori_diagnostic;
};
struct UefiFirmwareVolume {
    std::array<std::uint8_t, 16> file_system_guid{};
    std::uint64_t file_offset = 0;
    std::uint64_t length = 0;
    std::uint64_t attributes = 0;
    std::uint16_t header_length = 0;
    std::uint8_t revision = 0;
    bool header_checksum_valid = false;
    // The bounded block-map rows as encoded in the FV header. The terminating
    // {0,0} row is represented by the end of this vector.
    std::vector<UefiFirmwareVolumeBlockMapEntry> block_map;
    std::vector<UefiFirmwareVolumeFreeSpaceRegion> free_space_regions;
    std::vector<std::string> layout_diagnostics;
    std::optional<std::array<std::uint8_t, 16>> extended_header_name_guid;
    std::optional<std::uint32_t> extended_header_size;
    std::vector<UefiFirmwareVolumeExtensionEntry> extension_entries;
    std::vector<UefiFfsFile> files;
    bool dxe_apriori_file_present = false;
    std::vector<std::array<std::uint8_t, 16>> dxe_apriori_file_guids;
    std::string dxe_apriori_diagnostic;
    bool pei_apriori_file_present = false;
    std::vector<std::array<std::uint8_t, 16>> pei_apriori_file_guids;
    std::string pei_apriori_diagnostic;
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
    std::uint64_t max_guided_crc_bytes = 64ull * 1024 * 1024;
};
// Caller assumptions, never protocol/PPI installations observed by this library.
struct UefiDriverProtocolEffect {
    std::size_t file_index = 0;
    std::vector<std::array<std::uint8_t, 16>> installed_guids;
    std::string provenance;
};
struct UefiProtocolDiscoveryStep {
    std::size_t round = 0, file_index = 0;
    std::array<std::uint8_t, 16> file_guid{};
    std::uint64_t file_header_offset = 0;
    // Indices address the selected file's original sections. Section offsets
    // keep their file/decompressed-space meaning and parent provenance there.
    std::vector<std::size_t> dependency_section_indices;
    std::vector<std::array<std::uint8_t, 16>> assumed_new_guids;
    std::string effect_provenance;
};
enum class UefiProtocolDiscoveryStatus : std::uint8_t { fixed_point, round_limit, work_limit };
struct UefiProtocolDiscoveryPlan {
    UefiProtocolDiscoveryStatus status = UefiProtocolDiscoveryStatus::fixed_point;
    std::uint64_t work_used = 0;
    std::vector<UefiProtocolDiscoveryStep> assumed_steps;
    std::vector<std::array<std::uint8_t, 16>> assumed_available_guids;
    std::vector<std::size_t> remaining_file_indices;
    // Populated only at a fixed point, from the final fully evaluated snapshot.
    std::vector<UefiDriverDispatchEntry> blocked_entries;
};
struct UefiProtocolDiscoveryOptions {
    std::size_t max_rounds = 256; // Caller may raise to at most 4096.
    std::uint64_t max_work = 64ull * 1024 * 1024; // Hard ceiling: 256 Mi work units.
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
// Evaluates the boolean DEPEX stack program against the caller's complete set
// of installed protocol/PPI GUIDs. Ordering and dispatch-context opcodes return
// explicit non-boolean statuses; this never dispatches a firmware module.
HEXLAB_FIRMWARE_EXPORT UefiDepexEvaluation evaluate_uefi_depex(
    std::span<const std::byte> expression, std::uint8_t section_type,
    std::span<const std::array<std::uint8_t, 16>> available_guids);
// Builds a non-executing dispatch recommendation for DXE/UEFI driver files
// (FFS types 0x05-0x07) using the supplied installed protocol GUID set.
HEXLAB_FIRMWARE_EXPORT UefiDriverDispatchPlan plan_uefi_driver_dispatch(
    const UefiFirmwareVolume &volume,
    std::span<const std::array<std::uint8_t, 16>> available_guids);
// Builds a non-executing source-order readiness plan for PEIM and combined
// PEIM/DXE files using their PEI DEPEX against a caller-supplied PPI GUID set.
// The result reuses UefiDriverDispatchPlan rows; no PEIM is loaded or run.
HEXLAB_FIRMWARE_EXPORT UefiDriverDispatchPlan plan_uefi_pei_dispatch(
    const UefiFirmwareVolume &volume,
    std::span<const std::array<std::uint8_t, 16>> available_ppi_guids);
// Builds a non-executing source-order readiness plan for MM, combined MM/DXE,
// and standalone MM driver files using their MM DEPEX and caller-supplied
// installed protocol GUIDs. MM core files are not treated as dispatched drivers.
HEXLAB_FIRMWARE_EXPORT UefiDriverDispatchPlan plan_uefi_mm_dispatch(
    const UefiFirmwareVolume &volume,
    std::span<const std::array<std::uint8_t, 16>> available_protocol_guids);
// Iterates a static same-volume plan with explicitly assumed per-driver
// protocol effects. Selects at most one driver per round, then reevaluates
// DEPEX; no code is loaded/executed and no installations are observed.
HEXLAB_FIRMWARE_EXPORT Result<UefiProtocolDiscoveryPlan> plan_uefi_protocol_discovery(
    const UefiFirmwareVolume &, std::span<const std::array<std::uint8_t, 16>> initially_available_guids,
    std::span<const UefiDriverProtocolEffect>, UefiProtocolDiscoveryOptions = {}, std::stop_token = {});
// Iterates PEI readiness in source order using explicitly assumed per-PEIM PPI
// effects. Uses the same bounded result shape; no PEIM is loaded or executed.
HEXLAB_FIRMWARE_EXPORT Result<UefiProtocolDiscoveryPlan> plan_uefi_pei_protocol_discovery(
    const UefiFirmwareVolume &, std::span<const std::array<std::uint8_t, 16>> initially_available_ppis,
    std::span<const UefiDriverProtocolEffect>, UefiProtocolDiscoveryOptions = {}, std::stop_token = {});
} // namespace hexlab::firmware
