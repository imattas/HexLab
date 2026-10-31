#pragma once

#include "hexlab/core/result.hpp"
#include "hexlab/database/database_export.hpp"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stop_token>
#include <string>

namespace hexlab::database {
inline constexpr std::uint64_t journal_inspection_byte_limit = 64ull * 1024 * 1024;
inline constexpr std::size_t journal_inspection_record_limit = 65536;
struct JournalInspectionLimits {
    std::uint64_t max_bytes = journal_inspection_byte_limit;
    std::size_t max_records = 4096;
};
struct JournalInspection {
    std::uint64_t file_bytes = 0, inspected_bytes = 0, records_claimed = 0;
    std::uint64_t complete_records = 0, valid_records = 0, checksum_failures = 0;
    std::uint64_t trailing_bytes = 0;
    std::uint32_t initial_database_pages = 0, sector_size = 0, page_size = 0;
    bool header_valid = false, record_count_to_end = false, scan_complete = false;
    std::string stop_reason, diagnostic;
};
// Diagnostic only: reads one rollback-journal segment without opening SQLite,
// replaying pages, associating a base database, or publishing a project.
HEXLAB_DATABASE_EXPORT Result<JournalInspection> inspect_rollback_journal(
    const std::filesystem::path&, JournalInspectionLimits = {}, std::stop_token = {});
}
