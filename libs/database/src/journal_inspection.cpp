#include "hexlab/database/journal_inspection.hpp"
#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
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
        constexpr std::uint64_t segment_limit = 4096;
        constexpr std::array<std::byte, 8> journal_magic{
            std::byte{0xd9}, std::byte{0xd5}, std::byte{0x05}, std::byte{0xf9},
            std::byte{0x20}, std::byte{0xa1}, std::byte{0x63}, std::byte{0xd7}};
        const auto within_read_budget = [&](std::uint64_t bytes) {
            return result.inspected_bytes <= limits.max_bytes &&
                header_bytes <= limits.max_bytes - result.inspected_bytes &&
                bytes <= limits.max_bytes - result.inspected_bytes - header_bytes;
        };
        const auto read_at = [&](std::uint64_t offset, std::span<std::byte> destination) {
            if (offset > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max()) ||
                destination.size() > static_cast<std::uint64_t>(std::numeric_limits<std::streamsize>::max()))
                return false;
            input.clear();
            input.seekg(static_cast<std::streamoff>(offset));
            if (!input.read(reinterpret_cast<char*>(destination.data()), static_cast<std::streamsize>(destination.size())))
                return false;
            result.inspected_bytes += destination.size();
            return true;
        };
        std::array<std::byte, 28> segment_header = header;
        std::uint64_t segment_offset = 0;
        std::uint64_t inspected_records = 0;
        std::uint32_t first_sector = 0, first_page = 0;
        bool first_segment = true;
        for (std::uint64_t segment_index = 0; segment_index < segment_limit; ++segment_index) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Rollback-journal inspection canceled"};
            if (!first_segment) {
                if (file_size - segment_offset < segment_header.size()) {
                    result.trailing_bytes = file_size - segment_offset;
                    result.stop_reason = "truncated_segment_header";
                    result.diagnostic = "File ends before the next rollback-journal segment header is complete";
                    return finish();
                }
                if (!within_read_budget(segment_header.size())) {
                    result.stop_reason = "byte_limit";
                    result.diagnostic = "Inspection byte budget reached before the next segment header could be validated";
                    return finish();
                }
                if (!read_at(segment_offset, segment_header))
                    return Error{ErrorCode::io, "Cannot read the next rollback-journal segment header; source may have changed"};
                if (!std::equal(journal_magic.begin(), journal_magic.end(), segment_header.begin())) {
                    result.trailing_bytes = file_size - segment_offset;
                    result.stop_reason = "invalid_segment_header";
                    result.diagnostic = "Bytes follow a complete segment but do not begin with a valid rollback-journal header";
                    return finish();
                }
            }

            const auto segment_bytes = std::span<const std::byte>(segment_header);
            const auto raw_records = be32(segment_bytes, 8);
            const auto nonce = be32(segment_bytes, 12);
            const auto database_pages = be32(segment_bytes, 16);
            const auto sector_size = be32(segment_bytes, 20);
            const auto page_size = be32(segment_bytes, 24);
            const auto valid_page_size = page_size >= 512 && page_size <= 65536 && (page_size & (page_size - 1)) == 0;
            const auto valid_sector_size = sector_size >= 512 && sector_size <= 65536 && (sector_size & (sector_size - 1)) == 0;
            if (!valid_page_size || !valid_sector_size) {
                result.stop_reason = first_segment ? "invalid_header" : "invalid_segment_header";
                result.diagnostic = "Rollback-journal page or sector size is outside the supported power-of-two range";
                return finish();
            }
            if (first_segment) {
                first_sector = sector_size;
                first_page = page_size;
                result.initial_database_pages = database_pages;
                result.sector_size = sector_size;
                result.page_size = page_size;
                result.header_valid = true;
            } else if (sector_size != first_sector || page_size != first_page) {
                result.stop_reason = "inconsistent_segment_header";
                result.diagnostic = "Later rollback-journal segment changes the original page or sector size";
                return finish();
            }
            ++result.segments_seen;
            const std::uint64_t record_bytes = std::uint64_t{page_size} + 8;
            if (segment_offset > file_size || sector_size > file_size - segment_offset) {
                result.trailing_bytes = file_size - segment_offset;
                result.stop_reason = "truncated_header_sector";
                result.diagnostic = "File ends before a sector-padded journal segment header and record area";
                return finish();
            }
            const auto records_begin = segment_offset + sector_size;
            const auto available_area = file_size - records_begin;
            const auto available_records = available_area / record_bytes;
            const auto partial_record_bytes = available_area % record_bytes;
            const bool count_to_end = raw_records == UINT32_MAX;
            if (first_segment) result.record_count_to_end = count_to_end;
            const auto claimed = count_to_end ? available_records : raw_records;
            const auto complete = count_to_end ? available_records : std::min<std::uint64_t>(raw_records, available_records);
            result.records_claimed += claimed;
            result.complete_records += complete;
            const auto records_to_inspect = std::min<std::uint64_t>(complete, limits.max_records - inspected_records);
            if (record_bytes > std::numeric_limits<std::size_t>::max()) {
                result.stop_reason = "resource_limit";
                result.diagnostic = "Rollback-journal page record exceeds the addressable inspection buffer";
                return finish();
            }
            std::vector<std::byte> record(static_cast<std::size_t>(record_bytes));
            for (std::uint64_t index = 0; index < records_to_inspect; ++index) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Rollback-journal inspection canceled"};
                if (!within_read_budget(record_bytes)) {
                    result.stop_reason = "byte_limit";
                    result.diagnostic = "Inspection byte budget reached; later page records were not validated";
                    return finish();
                }
                if (!read_at(records_begin + index * record_bytes, record))
                    return Error{ErrorCode::io, "Cannot read complete rollback-journal page record; source may have changed"};
                const auto row = std::span<const std::byte>(record);
                const auto page_number = be32(row, 0);
                if (!page_number || page_number == UINT32_MAX) {
                    result.stop_reason = "page_number";
                    result.diagnostic = "Segment " + std::to_string(segment_index + 1) + ", record " +
                        std::to_string(index + 1) + " has an invalid database page number";
                    return finish();
                }
                const auto data = row.subspan(4, page_size);
                if (page_checksum(data, nonce) != be32(row, 4 + page_size)) {
                    ++result.checksum_failures;
                    result.stop_reason = "page_checksum";
                    result.diagnostic = "Segment " + std::to_string(segment_index + 1) + ", record " +
                        std::to_string(index + 1) + " fails its nonce-based page checksum; later records were not validated";
                    return finish();
                }
                ++result.valid_records;
                ++inspected_records;
            }
            result.trailing_bytes = count_to_end ? partial_record_bytes :
                file_size - (records_begin + complete * record_bytes);
            if (records_to_inspect < complete) {
                result.stop_reason = "record_limit";
                result.diagnostic = "Inspection record budget reached; later page records and segments were not validated";
                return finish();
            }
            if (complete < claimed) {
                result.stop_reason = "truncated_record";
                result.diagnostic = "A rollback-journal segment declares more page records than fit in the file";
                return finish();
            }
            ++result.segments_complete;
            if (count_to_end) {
                if (partial_record_bytes) {
                    result.stop_reason = "truncated_record";
                    result.diagnostic = "The final rollback-journal segment ends with a partial page record";
                } else {
                    result.scan_complete = true;
                    result.stop_reason = "all_segments_complete";
                    result.diagnostic = "All page records in the count-to-end rollback-journal segment passed checksum validation; no rollback was attempted";
                }
                return finish();
            }

            const auto records_end = records_begin + complete * record_bytes;
            const auto remainder = records_end % sector_size;
            const auto padding = remainder ? sector_size - remainder : 0;
            if (records_end > std::numeric_limits<std::uint64_t>::max() - padding) {
                result.stop_reason = "resource_limit";
                result.diagnostic = "Next rollback-journal segment offset overflows";
                return finish();
            }
            const auto next_segment = records_end + padding;
            if (next_segment >= file_size) {
                result.trailing_bytes = file_size - records_end;
                if (result.trailing_bytes) {
                    if (result.trailing_bytes > sector_size || result.trailing_bytes > std::numeric_limits<std::size_t>::max()) {
                        result.stop_reason = "uninspected_segment_data";
                        result.diagnostic = "Bytes after the final declared rollback-journal segment exceed one padding sector";
                        return finish();
                    }
                    std::vector<std::byte> padding_bytes(static_cast<std::size_t>(result.trailing_bytes));
                    if (!within_read_budget(result.trailing_bytes)) {
                        result.stop_reason = "byte_limit";
                        result.diagnostic = "Inspection byte budget reached while validating final segment padding";
                        return finish();
                    }
                    if (!read_at(records_end, padding_bytes))
                        return Error{ErrorCode::io, "Cannot read final rollback-journal segment padding; source may have changed"};
                    if (std::any_of(padding_bytes.begin(), padding_bytes.end(), [](std::byte b) { return b != std::byte{}; })) {
                        result.stop_reason = "uninspected_segment_data";
                        result.diagnostic = "Nonzero bytes follow the final declared rollback-journal segment";
                        return finish();
                    }
                }
                result.scan_complete = true;
                result.stop_reason = "all_segments_complete";
                result.diagnostic = "All declared rollback-journal segments passed checksum validation; no rollback was attempted";
                return finish();
            }
            if (padding) {
                std::vector<std::byte> padding_bytes(static_cast<std::size_t>(padding));
                if (!within_read_budget(padding)) {
                    result.stop_reason = "byte_limit";
                    result.diagnostic = "Inspection byte budget reached while validating inter-segment padding";
                    return finish();
                }
                if (!read_at(records_end, padding_bytes))
                    return Error{ErrorCode::io, "Cannot read inter-segment rollback-journal padding; source may have changed"};
                if (std::any_of(padding_bytes.begin(), padding_bytes.end(), [](std::byte b) { return b != std::byte{}; })) {
                    result.stop_reason = "invalid_segment_padding";
                    result.diagnostic = "Nonzero bytes occur between rollback-journal segments";
                    return finish();
                }
            }
            segment_offset = next_segment;
            first_segment = false;
        }
        result.stop_reason = "segment_limit";
        result.diagnostic = "Inspection reached the rollback-journal segment limit; later segments were not validated";
        return finish();
    } catch (const std::bad_alloc&) {
        return Error{ErrorCode::resource_limit, "Rollback-journal inspection allocation failed"};
    } catch (const std::exception& exception) {
        return Error{ErrorCode::io, "Rollback-journal inspection failed: " + std::string(exception.what())};
    }
}
}
