#pragma once

#include "hexlab/core/result.hpp"
#include "hexlab/database/database_export.hpp"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stop_token>
#include <string>

namespace hexlab::database {
inline constexpr std::uint64_t wal_inspection_byte_limit = 64ull * 1024 * 1024;
inline constexpr std::size_t wal_inspection_frame_limit = 65536;
struct WalInspectionLimits {
    std::uint64_t max_bytes = wal_inspection_byte_limit;
    std::size_t max_frames = 4096;
};
struct WalInspection {
    std::uint64_t file_bytes = 0, inspected_bytes = 0, complete_frames = 0;
    std::uint64_t valid_frames = 0, commit_markers = 0, last_commit_frame = 0;
    std::uint64_t trailing_bytes = 0;
    std::uint32_t format_version = 0, page_size = 0, checkpoint_sequence = 0;
    std::uint32_t salt1 = 0, salt2 = 0, last_commit_pages = 0;
    bool header_valid = false, checksum_big_endian = false, scan_complete = false;
    // Stable diagnostic category plus a bounded, human-readable explanation.
    std::string stop_reason, diagnostic;
};
// Diagnostic only: reads this regular WAL file directly, never opens a SQLite
// connection, and never checkpoints, reconstructs, or publishes a project.
// A valid commit marker does not establish association with a base database.
HEXLAB_DATABASE_EXPORT Result<WalInspection> inspect_wal(
    const std::filesystem::path&, WalInspectionLimits = {}, std::stop_token = {});
}
