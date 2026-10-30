#pragma once
#include "hexlab/core/result.hpp"
#include "hexlab/firmware/firmware_export.hpp"
#include <cstddef>
#include <cstdint>
#include <span>
#include <stop_token>
#include <vector>

namespace hexlab::firmware {
struct IntelMicrocodeSignature {
    std::uint64_t file_offset = 0;
    std::uint32_t processor_signature = 0;
    std::uint32_t processor_flags = 0;
    std::uint32_t checksum = 0;
    bool checksum_valid = false;
};
struct IntelMicrocodeUpdate {
    std::uint64_t file_offset = 0;
    std::uint32_t update_revision = 0;
    std::uint32_t date = 0;
    std::uint32_t processor_signature = 0;
    std::uint32_t checksum = 0;
    std::uint32_t loader_revision = 0;
    std::uint32_t processor_flags = 0;
    std::uint32_t data_size = 0;
    std::uint32_t total_size = 0;
    std::uint32_t effective_data_size = 0;
    std::uint32_t effective_total_size = 0;
    bool reserved_fields_zero = false;
    bool base_checksum_valid = false;
    bool extension_table_present = false;
    bool extension_reserved_fields_zero = false;
    bool extension_table_checksum_valid = false;
    std::vector<IntelMicrocodeSignature> extended_signatures;
};
struct IntelMicrocodeLimits {
    std::uint64_t max_input_bytes = 512ULL * 1024 * 1024;
    std::uint32_t max_update_bytes = 16U * 1024 * 1024;
    std::uint32_t max_extended_signatures = 1'000'000;
};

// Parses one Intel microcode update at a caller-selected file offset. Payload
// bytes are treated as opaque and are never loaded into a processor.
HEXLAB_FIRMWARE_EXPORT Result<IntelMicrocodeUpdate> parse_intel_microcode_update(
    std::span<const std::byte>, std::uint64_t file_offset, std::stop_token = {}, IntelMicrocodeLimits = {});
} // namespace hexlab::firmware
