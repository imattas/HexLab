#include "hexlab/database/wal_inspection.hpp"
#include <algorithm>
#include <array>
#include <fstream>
#include <span>
#include <vector>

namespace hexlab::database {
namespace {
std::uint32_t word(std::span<const std::byte> bytes, bool big_endian = true) {
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4; ++i)
        value = (value << 8) | std::to_integer<unsigned>(bytes[big_endian ? i : 3 - i]);
    return value;
}
void checksum(std::span<const std::byte> bytes, bool big_endian,
              std::uint32_t& first, std::uint32_t& second) {
    for (std::size_t i = 0; i < bytes.size(); i += 8) {
        first += word(bytes.subspan(i, 4), big_endian) + second;
        second += word(bytes.subspan(i + 4, 4), big_endian) + first;
    }
}
}
Result<WalInspection> inspect_wal(const std::filesystem::path& path,
                                 WalInspectionLimits limits, std::stop_token stop) {
    if (path.empty() || limits.max_bytes < 64 || limits.max_bytes > wal_inspection_byte_limit ||
        !limits.max_frames || limits.max_frames > wal_inspection_frame_limit)
        return Error{ErrorCode::invalid_argument, "Invalid WAL inspection path or byte/frame limits"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "WAL inspection canceled"};
    try {
        std::error_code error;
        if (!std::filesystem::is_regular_file(std::filesystem::symlink_status(path, error)) || error)
            return Error{ErrorCode::invalid_argument, "WAL inspection requires an existing regular file, not a symlink"};
        const auto file_size = std::filesystem::file_size(path);
        const auto modified = std::filesystem::last_write_time(path);
        std::ifstream input(path, std::ios::binary);
        if (!input) return Error{ErrorCode::io, "Cannot open WAL for read-only inspection"};
        WalInspection result;
        result.file_bytes = file_size;
        std::array<std::byte, 32> header{};
        const auto header_bytes = static_cast<std::size_t>(std::min<std::uint64_t>(file_size, header.size()));
        if (header_bytes && !input.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header_bytes)))
            return Error{ErrorCode::io, "Cannot read WAL header"};
        result.inspected_bytes = header_bytes;
        const auto finish = [&]() -> Result<WalInspection> {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "WAL inspection canceled"};
            if (std::filesystem::file_size(path) != file_size || std::filesystem::last_write_time(path) != modified)
                return Error{ErrorCode::conflict, "WAL changed during inspection; inspect a stable offline copy"};
            std::array<std::byte, 32> current{};
            input.clear(); input.seekg(0);
            if (header_bytes && !input.read(reinterpret_cast<char*>(current.data()), static_cast<std::streamsize>(header_bytes)))
                return Error{ErrorCode::io, "Cannot recheck WAL header"};
            result.inspected_bytes += header_bytes;
            if (current != header)
                return Error{ErrorCode::conflict, "WAL header changed during inspection"};
            return result;
        };
        if (file_size < 32) {
            result.stop_reason = file_size ? "truncated_header" : "empty";
            result.diagnostic = file_size ? "WAL header is shorter than 32 bytes" : "Empty file has no WAL header or frames";
            return finish();
        }
        const auto bytes = std::span<const std::byte>(header);
        const auto magic = word(bytes.first(4));
        result.format_version = word(bytes.subspan(4, 4));
        result.page_size = word(bytes.subspan(8, 4));
        result.checkpoint_sequence = word(bytes.subspan(12, 4));
        result.salt1 = word(bytes.subspan(16, 4)); result.salt2 = word(bytes.subspan(20, 4));
        if ((magic != 0x377f0682u && magic != 0x377f0683u) || result.format_version != 3007000u ||
            result.page_size < 512 || result.page_size > 65536 || (result.page_size & (result.page_size - 1)) != 0) {
            result.stop_reason = "invalid_header";
            result.diagnostic = "Unrecognized WAL magic, format version, or page size";
            return finish();
        }
        result.checksum_big_endian = magic == 0x377f0683u;
        std::uint32_t first = 0, second = 0;
        checksum(bytes.first(24), result.checksum_big_endian, first, second);
        if (first != word(bytes.subspan(24, 4)) || second != word(bytes.subspan(28, 4))) {
            result.stop_reason = "header_checksum";
            result.diagnostic = "WAL header checksum does not match";
            return finish();
        }
        result.header_valid = true;
        const std::uint64_t frame_bytes = 24ull + result.page_size;
        result.complete_frames = (file_size - 32) / frame_bytes;
        result.trailing_bytes = (file_size - 32) % frame_bytes;
        std::vector<std::byte> storage(static_cast<std::size_t>(frame_bytes));
        const auto frame = std::span<const std::byte>(storage);
        for (std::uint64_t index = 0; index < result.complete_frames; ++index) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "WAL inspection canceled"};
            if (index >= limits.max_frames || frame_bytes > limits.max_bytes - result.inspected_bytes - header_bytes) {
                result.stop_reason = index >= limits.max_frames ? "frame_limit" : "byte_limit";
                result.diagnostic = "Inspection budget reached; remaining frames were not validated";
                return finish();
            }
            if (!input.read(reinterpret_cast<char*>(storage.data()), static_cast<std::streamsize>(storage.size())))
                return Error{ErrorCode::io, "Cannot read complete WAL frame; source may have changed"};
            result.inspected_bytes += frame_bytes;
            const auto page = word(frame.first(4)), database_pages = word(frame.subspan(4, 4));
            if (!page || page == UINT32_MAX || database_pages == UINT32_MAX ||
                word(frame.subspan(8, 4)) != result.salt1 || word(frame.subspan(12, 4)) != result.salt2) {
                result.stop_reason = "frame_header";
                result.diagnostic = "Frame " + std::to_string(index + 1) + " has invalid page fields or stale salts; later frames were not validated";
                return finish();
            }
            checksum(frame.first(8), result.checksum_big_endian, first, second);
            checksum(frame.subspan(24), result.checksum_big_endian, first, second);
            if (first != word(frame.subspan(16, 4)) || second != word(frame.subspan(20, 4))) {
                result.stop_reason = "frame_checksum";
                result.diagnostic = "Frame " + std::to_string(index + 1) + " fails its rolling checksum; later frames were not validated";
                return finish();
            }
            ++result.valid_frames;
            if (database_pages) {
                ++result.commit_markers;
                result.last_commit_frame = index + 1;
                result.last_commit_pages = database_pages;
            }
        }
        result.scan_complete = result.trailing_bytes == 0;
        result.stop_reason = result.scan_complete ? "complete" : "truncated_frame";
        result.diagnostic = result.scan_complete
            ? "All complete frames validated; commit markers are diagnostic only"
            : "File ends with an incomplete frame; complete preceding frames were validated";
        return finish();
    } catch (const std::bad_alloc&) {
        return Error{ErrorCode::resource_limit, "WAL inspection allocation failed"};
    } catch (const std::exception& error) {
        return Error{ErrorCode::io, "WAL inspection failed: " + std::string(error.what())};
    }
}
}
