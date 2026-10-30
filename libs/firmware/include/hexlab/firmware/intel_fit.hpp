#pragma once
#include "hexlab/core/result.hpp"
#include "hexlab/firmware/firmware_export.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stop_token>
#include <vector>

namespace hexlab::firmware {
struct IntelFitEntry {
    std::uint32_t index = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t address = 0;
    std::uint32_t size_units = 0; // FIT size field is in 16-byte units.
    std::uint16_t version = 0;
    std::uint8_t type = 0, reserved = 0, checksum = 0;
    bool checksum_valid = false;
};
struct IntelFitTable {
    std::uint64_t file_offset = 0, size_bytes = 0;
    std::uint16_t version = 0;
    std::uint32_t declared_entry_count = 0;
    std::optional<bool> table_checksum_valid;
    bool entry_types_ordered = true;
    std::vector<IntelFitEntry> entries;
};
struct IntelFitLimits {
    std::uint64_t max_input_bytes = 512ULL * 1024 * 1024;
    std::uint32_t max_entries = 1'000'000;
    std::uint64_t max_table_bytes = 16ULL * 1024 * 1024;
};

// Parses an Intel FIT table at a caller-selected file offset. No physical
// address-to-file mapping or FIT pointer discovery is assumed.
HEXLAB_FIRMWARE_EXPORT Result<IntelFitTable> parse_intel_fit(
    std::span<const std::byte>, std::uint64_t file_offset, std::stop_token = {}, IntelFitLimits = {});
} // namespace hexlab::firmware
