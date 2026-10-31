#include "hexlab/database/journal_inspection.hpp"
#include <algorithm>
#include <array>
#include <fstream>
#include <span>
#include <vector>

namespace hexlab::database {
namespace {
std::uint32_t be32(std::span<const std::byte> bytes, std::size_t offset) {
    return (std::to_integer<std::uint32_t>(bytes[offset]) << 24) |
           (std::to_integer<std::uint32_t>(bytes[offset + 1]) << 16) |
           (std::to_integer<std::uint32_t>(bytes[offset + 2]) << 8) |
           std::to_integer<std::uint32_t>(bytes[offset + 3]);
}
std::uint32_t page_checksum(std::span<const std::byte> page, std::uint32_t nonce) {
    std::uint32_t checksum = nonce;
    for (std::int64_t offset = static_cast<std::int64_t>(page.size()) - 200; offset >= 0; offset -= 200)
        checksum += std::to_integer<std::uint8_t>(page[static_cast<std::size_t>(offset)]);
    return checksum;
}
}

Result<JournalInspection> inspect_rollback_journal(const std::filesystem::path& path,
        JournalInspectionLimits limits, std::stop_token stop) {
    if (path.empty() || limits.max_bytes < 64 || limits.max_bytes > journal_inspection_byte_limit ||
        !limits.max_records || limits.max_records > journal_inspection_record_limit)
        return Error{ErrorCode::invalid_argument, "Invalid rollback-journal path or byte/record limits"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Rollback-journal inspection canceled"};
    try {
        std::error_code error;
        if (!std::filesystem::is_regular_file(std::filesystem::symlink_status(path, error)) || error)
            return Error{ErrorCode::invalid_argument, "Rollback-journal inspection requires an existing regular file, not a symlink"};
        const auto file_size = std::filesystem::file_size(path);
        const auto modified = std::filesystem::last_write_time(path);
        std::ifstream input(path, std::ios::binary);
        if (!input) return Error{ErrorCode::io, "Cannot open rollback journal for read-only inspection"};
        JournalInspection result;
        result.file_bytes = file_size;
        std::array<std::byte, 28> header{};
        const auto header_bytes = static_cast<std::size_t>(std::min<std::uint64_t>(file_size, header.size()));
        if (header_bytes && !input.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header_bytes)))
            return Error{ErrorCode::io, "Cannot read rollback-journal header"};
        result.inspected_bytes = header_bytes;
        const auto finish = [&]() -> Result<JournalInspection> {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Rollback-journal inspection canceled"};
            if (std::filesystem::file_size(path) != file_size || std::filesystem::last_write_time(path) != modified)
                return Error{ErrorCode::conflict, "Rollback journal changed during inspection; inspect a stable offline copy"};
            std::array<std::byte, 28> current{};
            input.clear(); input.seekg(0);
            if (header_bytes && !input.read(reinterpret_cast<char*>(current.data()), static_cast<std::streamsize>(header_bytes)))
                return Error{ErrorCode::io, "Cannot recheck rollback-journal header"};
            result.inspected_bytes += header_bytes;
            if (current != header) return Error{ErrorCode::conflict, "Rollback-journal header changed during inspection"};
            return result;
        };
        if (file_size < header.size()) {
            result.stop_reason = file_size ? "truncated_header" : "empty";
            result.diagnostic = file_size ? "Rollback-journal header is shorter than 28 bytes" : "Empty file has no rollback-journal header or records";
            return finish();
        }
        constexpr std::array<std::byte, 8> magic{
            std::byte{0xd9}, std::byte{0xd5}, std::byte{0x05}, std::byte{0xf9},
            std::byte{0x20}, std::byte{0xa1}, std::byte{0x63}, std::byte{0xd7}};
        const auto bytes = std::span<const std::byte>(header);
        if (!std::equal(magic.begin(), magic.end(), header.begin())) {
            result.stop_reason = "invalid_header";
            result.diagnostic = "Rollback-journal magic is invalid; the journal may be committed or unrelated";
            return finish();
        }
        const auto raw_records = be32(bytes, 8);
        const auto nonce = be32(bytes, 12);
        result.initial_database_pages = be32(bytes, 16);
        result.sector_size = be32(bytes, 20);
        result.page_size = be32(bytes, 24);
        const auto valid_page_size = result.page_size >= 512 && result.page_size <= 65536 &&
            (result.page_size & (result.page_size - 1)) == 0;
        const auto valid_sector_size = result.sector_size >= 512 && result.sector_size <= 65536 &&
            (result.sector_size & (result.sector_size - 1)) == 0;
        if (!valid_page_size || !valid_sector_size) {
            result.stop_reason = "invalid_header";
            result.diagnostic = "Rollback-journal page or sector size is outside the supported power-of-two range";
            return finish();
        }
        result.header_valid = true;
        if (file_size < result.sector_size) {
            result.stop_reason = "truncated_header_sector";
            result.diagnostic = "File ends before the sector-padded journal header and first record area";
            return finish();
        }
        const std::uint64_t record_bytes = std::uint64_t{result.page_size} + 8;
        const auto available_area = file_size - result.sector_size;
        const auto available_records = available_area / record_bytes;
        const auto partial_record_bytes = available_area % record_bytes;
        const bool count_to_end = raw_records == UINT32_MAX;
        result.record_count_to_end = count_to_end;
        result.records_claimed = count_to_end ? available_records : raw_records;
        result.complete_records = count_to_end ? available_records : std::min<std::uint64_t>(raw_records, available_records);
        result.trailing_bytes = count_to_end ? partial_record_bytes :
            file_size - (std::uint64_t{result.sector_size} + result.complete_records * record_bytes);
        const auto records_to_inspect = std::min<std::uint64_t>(result.complete_records, limits.max_records);
        std::vector<std::byte> record(static_cast<std::size_t>(record_bytes));
        for (std::uint64_t index = 0; index < records_to_inspect; ++index) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Rollback-journal inspection canceled"};
            if (record_bytes > limits.max_bytes - result.inspected_bytes - header_bytes) {
                result.stop_reason = "byte_limit";
                result.diagnostic = "Inspection byte budget reached; later page records were not validated";
                return finish();
            }
            const auto offset = std::uint64_t{result.sector_size} + index * record_bytes;
            input.clear(); input.seekg(static_cast<std::streamoff>(offset));
            if (!input.read(reinterpret_cast<char*>(record.data()), static_cast<std::streamsize>(record.size())))
                return Error{ErrorCode::io, "Cannot read complete rollback-journal page record; source may have changed"};
            result.inspected_bytes += record_bytes;
            const auto row = std::span<const std::byte>(record);
            const auto page_number = be32(row, 0);
            if (!page_number || page_number == UINT32_MAX) {
                result.stop_reason = "page_number";
                result.diagnostic = "Record " + std::to_string(index + 1) + " has an invalid database page number";
                return finish();
            }
            const auto data = row.subspan(4, result.page_size);
            if (page_checksum(data, nonce) != be32(row, 4 + result.page_size)) {
                ++result.checksum_failures;
                result.stop_reason = "page_checksum";
                result.diagnostic = "Record " + std::to_string(index + 1) + " fails its nonce-based page checksum; later records were not validated";
                return finish();
            }
            ++result.valid_records;
        }
        if (records_to_inspect < result.complete_records) {
            result.stop_reason = "record_limit";
            result.diagnostic = "Inspection record budget reached; remaining records were not validated";
        } else if (result.complete_records < result.records_claimed) {
            result.stop_reason = "truncated_record";
            result.diagnostic = "Journal declares more page records than fit in the file";
        } else if (result.trailing_bytes) {
            result.stop_reason = count_to_end ? "truncated_record" : "uninspected_segment_data";
            result.diagnostic = count_to_end ? "File ends with a partial page record" :
                "Bytes follow the first declared segment; later segment headers are not inspected";
        } else {
            result.scan_complete = true;
            result.stop_reason = "first_segment_complete";
            result.diagnostic = "All declared page records in the first journal segment passed checksum validation; no rollback was attempted";
        }
        return finish();
    } catch (const std::bad_alloc&) {
        return Error{ErrorCode::resource_limit, "Rollback-journal inspection allocation failed"};
    } catch (const std::exception& exception) {
        return Error{ErrorCode::io, "Rollback-journal inspection failed: " + std::string(exception.what())};
    }
}
}
