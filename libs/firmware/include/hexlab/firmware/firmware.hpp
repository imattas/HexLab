#pragma once
#include "hexlab/core/result.hpp"
#include "hexlab/firmware/firmware_export.hpp"
#include <cstddef>
#include <cstdint>
#include <stop_token>
#include <span>
#include <string_view>
#include <vector>

namespace hexlab::firmware {
enum class Format { intel_hex, motorola_s_record };
enum class Termination { eof, start_record };
struct RecordProvenance {
    std::size_t line = 0;
    std::size_t record_index = 0;
    bool operator==(const RecordProvenance &) const = default;
};
struct DataSegment {
    std::uint64_t address = 0;
    std::vector<std::byte> bytes;
    RecordProvenance provenance;
};
struct FirmwareImage {
    Format format = Format::intel_hex;
    std::vector<DataSegment> segments;
    // Raw S0 payload is metadata, not addressable data. Retain its provenance
    // so inspectors can report it without projecting it into image memory.
    std::vector<std::byte> s_record_header;
    RecordProvenance s_record_header_provenance;
    bool has_s_record_header = false;
    std::uint64_t total_data_bytes = 0;
    std::uint64_t data_record_count = 0;
    Termination termination = Termination::eof;
    std::uint64_t start_address = 0;
    bool has_start_address = false;
};
struct ParseOptions {
    std::uint64_t max_data_bytes = 512ull * 1024 * 1024;
    std::uint64_t max_address = 0xffffffffull;
    std::size_t max_records = 4'000'000;
};
// Record lines are one-based in provenance and diagnostics. Blank lines are ignored.
HEXLAB_FIRMWARE_EXPORT Result<FirmwareImage> parse_intel_hex(std::string_view text,
    ParseOptions options = {}, std::stop_token stop = {});
HEXLAB_FIRMWARE_EXPORT Result<FirmwareImage> parse_s_record(std::string_view text,
    ParseOptions options = {}, std::stop_token stop = {});
} // namespace hexlab::firmware
