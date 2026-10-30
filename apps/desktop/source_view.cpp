#include "source_view.hpp"

#include "hexlab/loaders/loaded_image.hpp"
#include "hexlab/workspace/project.hpp"
#include "hexlab/processors/format.hpp"
#include "hexlab/core/sha256.hpp"
#include "data_views.hpp"

#include <wx/button.h>
#include <wx/checkbox.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/msgdlg.h>
#include <wx/sizer.h>
#include <wx/splitter.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#ifdef _WIN32
#include <windows.h>
#else
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/xattr.h>
#endif
#endif

namespace hexlab::desktop {
struct SourceScanCheckpoint {
    std::filesystem::path path;
    std::filesystem::file_time_type modified;
    std::uintmax_t size = 0, offset = 0, bom_bytes = 0;
    std::int64_t line_number = 1, focus_line = 0;
    std::size_t retained_bytes = 0;
    std::vector<std::pair<std::int64_t, std::uintmax_t>> sparse_line_offsets;
    std::vector<std::string> lines;
    std::string line;
    bool utf16 = false, little_endian = false, line_started = false, pending = false;
};
namespace {
constexpr std::uintmax_t max_source_bytes = 1024u * 1024u;
constexpr std::uintmax_t max_source_search_bytes = 64u * 1024u * 1024u;
constexpr std::uintmax_t max_source_excerpt_scan_bytes = 64u * 1024u * 1024u;
constexpr std::int64_t context_lines = 20;
constexpr std::size_t max_source_path_bytes = 32u * 1024u;
constexpr std::size_t max_line_addresses = 4096;
constexpr std::size_t max_line_origins = 4096;
constexpr std::int64_t source_line_checkpoint_stride = 4096;
constexpr std::size_t max_source_line_checkpoints = 262144;
std::atomic_uint64_t source_temp_serial{0};

SourceRevisionStamp source_revision_stamp(const std::shared_ptr<const DocumentSnapshot> &document) {
    SourceRevisionStamp stamp;
    if (!document) return stamp;
    stamp.document = document->revision;
    if (document->project && document->project->state) {
        const auto &revision = document->project->state->revisions;
        stamp.has_project = true;
        stamp.project_edit = revision.edit;
        stamp.project_bytes = revision.bytes;
        stamp.project_decisions = revision.decisions;
    }
    return stamp;
}

bool replace_source_file(const std::filesystem::path &path, std::span<const std::byte> bytes,
                         std::string &failure) {
    auto temporary = path;
    temporary += std::filesystem::path(".hexlab-tmp-" + std::to_string(++source_temp_serial));
#ifdef _WIN32
    // ReplaceFile preserves the destination's ACL and file attributes.
    HANDLE output = ::CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                  FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (output == INVALID_HANDLE_VALUE) { failure = "Could not safely create a temporary source file"; return false; }
    std::size_t written = 0;
    while (written < bytes.size()) {
        const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - written, 1u << 20));
        DWORD count = 0;
        if (!::WriteFile(output, bytes.data() + written, chunk, &count, nullptr) || count == 0) break;
        written += count;
    }
    const bool complete = written == bytes.size() && ::FlushFileBuffers(output);
    ::CloseHandle(output);
    if (!complete) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        failure = "Could not write the temporary source file";
        return false;
    }
    if (!::ReplaceFileW(path.c_str(), temporary.c_str(), nullptr, REPLACEFILE_WRITE_THROUGH,
                        nullptr, nullptr)) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        failure = "Could not atomically replace the source file";
        return false;
    }
#else
    struct stat original {};
    if (::stat(path.c_str(), &original) != 0) {
        failure = "Could not inspect source file permissions";
        return false;
    }
#if defined(__linux__)
    const auto attributes_size = ::listxattr(path.c_str(), nullptr, 0);
    if (attributes_size < 0 || attributes_size > 0) {
        failure = "Source file has extended attributes that cannot be preserved safely";
        return false;
    }
#elif defined(__APPLE__)
    const auto attributes_size = ::listxattr(path.c_str(), nullptr, 0, 0);
    if (attributes_size < 0 || attributes_size > 0) {
        failure = "Source file has extended attributes that cannot be preserved safely";
        return false;
    }
#endif
    const int output = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (output < 0) { failure = "Could not safely create a temporary source file"; return false; }
    std::size_t written = 0;
    while (written < bytes.size()) {
        const auto count = ::write(output, bytes.data() + written, bytes.size() - written);
        if (count <= 0) break;
        written += static_cast<std::size_t>(count);
    }
    struct stat replacement {};
    const bool owner_preserved = ::fstat(output, &replacement) == 0 &&
        ((replacement.st_uid == original.st_uid && replacement.st_gid == original.st_gid) ||
         ::fchown(output, original.st_uid, original.st_gid) == 0);
    const bool mode_preserved = owner_preserved && ::fchmod(output, original.st_mode & 07777) == 0;
    const bool complete = written == bytes.size() && mode_preserved && ::fsync(output) == 0;
    ::close(output);
    if (!complete) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        failure = "Could not write the temporary source file";
        return false;
    }
    if (std::rename(temporary.c_str(), path.c_str()) != 0) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        failure = "Could not atomically replace the source file";
        return false;
    }
#endif
    return true;
}

std::optional<Address> address_for(const DocumentSnapshot &document, Location location) {
    if (const auto *address = std::get_if<Address>(&location))
        return *address;
    if (!document.image)
        return {};
    auto mapped = document.image->to_address(std::get<FileOffset>(location));
    return mapped ? std::optional<Address>(mapped.value()) : std::nullopt;
}

std::optional<std::filesystem::path> resolve_source(const std::filesystem::path &path,
                                                  std::optional<std::uintmax_t> limit, std::string &failure) {
    std::error_code error;
    const auto resolved = std::filesystem::canonical(path, error);
    if (error) {
        failure = "Source file is unavailable";
        return {};
    }
#ifdef _WIN32
    // Debug metadata is untrusted input. Do not let it trigger UNC or device
    // namespace access, including through a local symlink/junction target.
    const auto native = resolved.native();
    if (native.size() >= 2 && native[0] == L'\\' && native[1] == L'\\') {
        failure = "Network and device source paths are not opened";
        return {};
    }
#endif
    const auto status = std::filesystem::status(resolved, error);
    if (error || !std::filesystem::is_regular_file(status)) {
        failure = "Source file is unavailable";
        return {};
    }
    const auto size = std::filesystem::file_size(resolved, error);
    if (error) {
        failure = "Could not determine source file size";
        return {};
    }
    if (limit && size > *limit) {
        failure = *limit == max_source_bytes ? "Source file exceeds the 1 MiB search/edit limit"
                                            : "Source file exceeds the configured source limit";
        return {};
    }
    return resolved;
}

SourceRevisionCheckResult verify_pdb_source_sha256(const std::filesystem::path &path,
                                                    std::span<const std::byte> expected,
                                                    std::stop_token stop) {
    SourceRevisionCheckResult result;
    if (expected.size() != 32) {
        result.status = "PDB source revision check unavailable: SHA-256 checksum has the wrong size";
        return result;
    }
    std::string failure;
    const auto resolved = resolve_source(path, max_source_search_bytes, failure);
    if (!resolved) {
        result.status = "PDB source revision check unavailable: " + failure;
        return result;
    }
    std::error_code error;
    const auto size = std::filesystem::file_size(*resolved, error);
    if (error) {
        result.status = "PDB source revision check unavailable: could not determine source size";
        return result;
    }
    const auto modified = std::filesystem::last_write_time(*resolved, error);
    if (error) {
        result.status = "PDB source revision check unavailable: could not inspect source modification time";
        return result;
    }
    std::ifstream input(*resolved, std::ios::binary);
    if (!input) {
        result.status = "PDB source revision check unavailable: could not open source file";
        return result;
    }
    Sha256 hash;
    std::array<std::byte, 64u * 1024u> buffer{};
    std::uintmax_t consumed = 0;
    while (consumed < size) {
        if (stop.stop_requested()) {
            result.status = "PDB source revision check canceled";
            return result;
        }
        const auto amount = static_cast<std::size_t>(std::min<std::uintmax_t>(buffer.size(), size - consumed));
        input.read(reinterpret_cast<char *>(buffer.data()), static_cast<std::streamsize>(amount));
        const auto count = input.gcount();
        if (count <= 0 || static_cast<std::size_t>(count) != amount) {
            result.status = "PDB source revision check unavailable: source changed or could not be read";
            return result;
        }
        const auto updated = hash.update(std::span<const std::byte>(buffer).first(amount));
        if (!updated) {
            result.status = "PDB source revision check unavailable: SHA-256 update failed";
            return result;
        }
        consumed += amount;
    }
    if (stop.stop_requested()) {
        result.status = "PDB source revision check canceled";
        return result;
    }
    const auto current_size = std::filesystem::file_size(*resolved, error);
    if (error || current_size != size) {
        result.status = "PDB source revision check unavailable: source changed while hashing";
        return result;
    }
    const auto current_modified = std::filesystem::last_write_time(*resolved, error);
    if (error || current_modified != modified) {
        result.status = "PDB source revision check unavailable: source changed while hashing";
        return result;
    }
    const auto actual = hash.digest();
    if (std::equal(actual.begin(), actual.end(), expected.begin()))
        result.status = "PDB SHA-256 matches the current source file";
    else
        result.status = "PDB SHA-256 does not match the current source file; source revision may be stale";
    return result;
}

std::vector<std::byte> read_source(const std::filesystem::path &path, std::string &failure) {
    const auto resolved = resolve_source(path, max_source_bytes, failure);
    if (!resolved) return {};
    std::error_code error;
    const auto size = std::filesystem::file_size(*resolved, error);
    if (error || size > max_source_bytes) {
        failure = "Source file changed or exceeds the 1 MiB search/edit limit";
        return {};
    }
    std::ifstream input(*resolved, std::ios::binary);
    if (!input) {
        failure = "Could not open source file";
        return {};
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        const auto count = input.gcount();
        if (count != static_cast<std::streamsize>(bytes.size())) {
            failure = "Could not read source file";
            return {};
        }
        bytes.resize(static_cast<std::size_t>(count));
    }
    if (input.peek() != std::char_traits<char>::eof()) {
        failure = "Source file changed or exceeds the 1 MiB search/edit limit";
        return {};
    }
    return bytes;
}

std::vector<std::byte> read_source_search(const std::filesystem::path &path, std::stop_token stop,
                                         std::string &failure) {
    const auto resolved = resolve_source(path, max_source_search_bytes, failure);
    if (!resolved) {
        if (failure == "Source file exceeds the configured source limit")
            failure = "Source file exceeds the 64 MiB full-file search limit";
        return {};
    }
    std::error_code error;
    const auto size = std::filesystem::file_size(*resolved, error);
    if (error || size > max_source_search_bytes) {
        failure = "Source file changed or exceeds the 64 MiB full-file search limit";
        return {};
    }
    const auto modified = std::filesystem::last_write_time(*resolved, error);
    if (error) { failure = "Could not inspect source modification time"; return {}; }
    std::ifstream input(*resolved, std::ios::binary);
    if (!input) { failure = "Could not open source file"; return {}; }
    std::vector<std::byte> bytes;
    bytes.reserve(static_cast<std::size_t>(size));
    std::array<std::byte, 64u * 1024u> chunk{};
    while (bytes.size() < size) {
        if (stop.stop_requested()) {
            failure = "Source search canceled";
            return {};
        }
        const auto count = static_cast<std::size_t>(std::min<std::uintmax_t>(chunk.size(), size - bytes.size()));
        input.read(reinterpret_cast<char *>(chunk.data()), static_cast<std::streamsize>(count));
        const auto read = input.gcount();
        if (read != static_cast<std::streamsize>(count)) {
            failure = "Could not read source file";
            return {};
        }
        bytes.insert(bytes.end(), chunk.begin(), chunk.begin() + read);
    }
    if (input.peek() != std::char_traits<char>::eof()) {
        failure = "Source file changed or exceeds the 64 MiB full-file search limit";
        return {};
    }
    std::error_code final_size_error, final_modified_error;
    const auto final_size = std::filesystem::file_size(*resolved, final_size_error);
    const auto final_modified = std::filesystem::last_write_time(*resolved, final_modified_error);
    if (final_size_error || final_modified_error || final_size != size || final_modified != modified) {
        failure = "Source file changed during the full-file search";
        return {};
    }
    return bytes;
}

bool append_utf8(std::string &output, std::uint32_t value) {
    if (value <= 0x7f) output.push_back(static_cast<char>(value));
    else if (value <= 0x7ff) {
        output.push_back(static_cast<char>(0xc0 | (value >> 6)));
        output.push_back(static_cast<char>(0x80 | (value & 0x3f)));
    } else if (value <= 0xffff) {
        output.push_back(static_cast<char>(0xe0 | (value >> 12)));
        output.push_back(static_cast<char>(0x80 | ((value >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (value & 0x3f)));
    } else if (value <= 0x10ffff) {
        output.push_back(static_cast<char>(0xf0 | (value >> 18)));
        output.push_back(static_cast<char>(0x80 | ((value >> 12) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | ((value >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (value & 0x3f)));
    } else return false;
    return true;
}

bool append_utf16_unit(std::vector<std::byte> &output, std::uint16_t unit, bool little_endian) {
    if (output.size() > max_source_bytes - 2) return false;
    const auto first = static_cast<std::uint8_t>(unit & 0xff);
    const auto second = static_cast<std::uint8_t>(unit >> 8);
    output.push_back(static_cast<std::byte>(little_endian ? first : second));
    output.push_back(static_cast<std::byte>(little_endian ? second : first));
    return true;
}

bool append_utf16(std::string_view input, bool little_endian, std::vector<std::byte> &output) {
    std::size_t offset = 0;
    while (offset < input.size()) {
        const auto lead = static_cast<std::uint8_t>(input[offset++]);
        std::uint32_t scalar = 0;
        std::uint32_t minimum = 0;
        unsigned continuation_count = 0;
        if (lead <= 0x7f) scalar = lead;
        else if (lead >= 0xc2 && lead <= 0xdf) {
            scalar = lead & 0x1fu; minimum = 0x80; continuation_count = 1;
        } else if (lead >= 0xe0 && lead <= 0xef) {
            scalar = lead & 0x0fu; minimum = 0x800; continuation_count = 2;
        } else if (lead >= 0xf0 && lead <= 0xf4) {
            scalar = lead & 0x07u; minimum = 0x10000; continuation_count = 3;
        } else return false;
        if (continuation_count > input.size() - offset) return false;
        for (unsigned i = 0; i < continuation_count; ++i) {
            const auto continuation = static_cast<std::uint8_t>(input[offset++]);
            if ((continuation & 0xc0u) != 0x80u) return false;
            scalar = (scalar << 6) | (continuation & 0x3fu);
        }
        if (scalar < minimum || scalar > 0x10ffffu || (scalar >= 0xd800u && scalar <= 0xdfffu))
            return false;
        if (scalar <= 0xffffu) {
            if (!append_utf16_unit(output, static_cast<std::uint16_t>(scalar), little_endian)) return false;
        } else {
            scalar -= 0x10000u;
            if (!append_utf16_unit(output, static_cast<std::uint16_t>(0xd800u + (scalar >> 10)), little_endian) ||
                !append_utf16_unit(output, static_cast<std::uint16_t>(0xdc00u + (scalar & 0x3ffu)), little_endian))
                return false;
        }
    }
    return true;
}

std::optional<std::string> decode_source_text(std::span<const std::byte> bytes, std::string &failure,
                                              std::stop_token stop = {}) {
    const auto byte = [&](std::size_t index) { return std::to_integer<std::uint8_t>(bytes[index]); };
    if (bytes.size() >= 3 && byte(0) == 0xef && byte(1) == 0xbb && byte(2) == 0xbf)
        return std::string(reinterpret_cast<const char *>(bytes.data() + 3), bytes.size() - 3);
    const bool little_endian = bytes.size() >= 2 && byte(0) == 0xff && byte(1) == 0xfe;
    const bool big_endian = bytes.size() >= 2 && byte(0) == 0xfe && byte(1) == 0xff;
    if (!little_endian && !big_endian)
        return std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    if ((bytes.size() - 2) % 2 != 0) {
        failure = "UTF-16 source file has an odd byte length";
        return {};
    }
    std::string output;
    output.reserve(bytes.size());
    const auto unit = [&](std::size_t index) {
        return little_endian ? static_cast<std::uint16_t>(byte(index) | (byte(index + 1) << 8))
                             : static_cast<std::uint16_t>((byte(index) << 8) | byte(index + 1));
    };
    for (std::size_t at = 2; at < bytes.size(); at += 2) {
        if ((at & 0xffffu) == 0 && stop.stop_requested()) {
            failure = "Source search canceled";
            return {};
        }
        std::uint32_t scalar = unit(at);
        if (scalar >= 0xd800 && scalar <= 0xdbff) {
            if (at + 3 >= bytes.size()) {
                failure = "UTF-16 source file ends with an unpaired high surrogate";
                return {};
            }
            const auto low = unit(at + 2);
            if (low < 0xdc00 || low > 0xdfff) {
                failure = "UTF-16 source file contains an invalid surrogate pair";
                return {};
            }
            scalar = 0x10000 + ((scalar - 0xd800) << 10) + (low - 0xdc00);
            at += 2;
        } else if (scalar >= 0xdc00 && scalar <= 0xdfff) {
            failure = "UTF-16 source file contains an unpaired low surrogate";
            return {};
        }
        append_utf8(output, scalar);
    }
    return output;
}

bool valid_source_utf8(std::string_view text_value, std::stop_token stop) {
    std::size_t at = 0;
    while (at < text_value.size()) {
        if ((at & 0xffffu) == 0 && stop.stop_requested()) return false;
        const auto lead = static_cast<std::uint8_t>(text_value[at++]);
        if (lead <= 0x7f) continue;
        std::uint32_t scalar = 0, minimum = 0;
        unsigned continuation_count = 0;
        if (lead >= 0xc2 && lead <= 0xdf) { scalar = lead & 0x1fu; minimum = 0x80; continuation_count = 1; }
        else if (lead >= 0xe0 && lead <= 0xef) { scalar = lead & 0x0fu; minimum = 0x800; continuation_count = 2; }
        else if (lead >= 0xf0 && lead <= 0xf4) { scalar = lead & 0x07u; minimum = 0x10000; continuation_count = 3; }
        else return false;
        if (continuation_count > text_value.size() - at) return false;
        for (unsigned i = 0; i < continuation_count; ++i) {
            const auto continuation = static_cast<std::uint8_t>(text_value[at++]);
            if ((continuation & 0xc0u) != 0x80u) return false;
            scalar = (scalar << 6) | (continuation & 0x3fu);
        }
        if (scalar < minimum || scalar > 0x10ffffu || (scalar >= 0xd800u && scalar <= 0xdfffu)) return false;
    }
    return !stop.stop_requested();
}

SourceFileLoadResult load_source_file(const std::filesystem::path &path, std::stop_token stop) {
    SourceFileLoadResult result;
    auto bytes = read_source_search(path, stop, result.failure);
    if (!result.failure.empty()) {
        if (result.failure == "Source search canceled") result.failure = "Full-file source load canceled";
        return result;
    }
    auto decoded = decode_source_text(bytes, result.failure, stop);
    if (!decoded) {
        if (result.failure == "Source search canceled") result.failure = "Full-file source load canceled";
        return result;
    }
    if (!valid_source_utf8(*decoded, stop)) {
        result.failure = stop.stop_requested() ? "Full-file source load canceled" :
            "Source file contains malformed UTF-8";
        return result;
    }
    result.utf8_text = std::move(*decoded);
    return result;
}

struct SourceNewlineStyle {
    std::vector<bool> line_crlf;
    bool default_crlf = false;
};

SourceNewlineStyle inspect_newlines(std::string_view decoded) {
    SourceNewlineStyle result;
    std::size_t crlf_count = 0, lf_count = 0;
    for (std::size_t i = 0; i < decoded.size(); ++i) {
        if (decoded[i] != '\n') continue;
        const bool crlf = i > 0 && decoded[i - 1] == '\r';
        result.line_crlf.push_back(crlf);
        if (crlf) ++crlf_count;
        else ++lf_count;
    }
    // New lines beyond the captured pattern use the dominant original style;
    // ties deterministically use LF.
    result.default_crlf = crlf_count > lf_count;
    return result;
}

std::string apply_newlines(std::string_view edited, const SourceNewlineStyle &original) {
    std::string result;
    result.reserve(edited.size() + original.line_crlf.size());
    std::size_t line = 0;
    for (std::size_t i = 0; i < edited.size(); ++i) {
        if (edited[i] == '\r' && i + 1 < edited.size() && edited[i + 1] == '\n')
            continue; // wx text controls may return CRLF on some hosts.
        if (edited[i] != '\n') {
            result.push_back(edited[i]);
            continue;
        }
        const bool crlf = line < original.line_crlf.size()
            ? original.line_crlf[line] : original.default_crlf;
        if (crlf) result.push_back('\r');
        result.push_back('\n');
        ++line;
    }
    return result;
}

struct SourceExcerpt {
    std::int64_t first_line = 1;
    std::vector<std::string> lines;
    bool full_file_available = false;
};

// Scan one bounded seekable window toward the requested context. A checkpoint
// retains only decoder-safe position and the existing bounded excerpt text.
std::optional<SourceExcerpt> read_source_excerpt(const std::filesystem::path &path,
                                                std::int64_t focus_line, std::string &failure,
                                                SourceScanCheckpoint& checkpoint, bool resume,
                                                std::stop_token stop = {}) {
    checkpoint.pending = false;
    if (focus_line <= 0 || focus_line > std::numeric_limits<std::int64_t>::max() - context_lines) {
        failure = "Mapped source line is outside the available file";
        return {};
    }
    const auto resolved = resolve_source(path, {}, failure);
    if (!resolved) return {};
    std::error_code error;
    const auto size = std::filesystem::file_size(*resolved, error);
    if (error) {
        failure = "Could not determine source file size";
        return {};
    }
    const auto modified = std::filesystem::last_write_time(*resolved, error);
    if (error) { failure = "Could not inspect source modification time"; return {}; }
    std::ifstream input(*resolved, std::ios::binary);
    if (!input) { failure = "Could not open source file"; return {}; }
    unsigned char prefix[3]{};
    input.read(reinterpret_cast<char *>(prefix), 3);
    const auto prefix_size = input.gcount();
    if (input.bad()) { failure = "Could not read source file"; return {}; }
    const bool little_endian = prefix_size >= 2 && prefix[0] == 0xff && prefix[1] == 0xfe;
    const bool big_endian = prefix_size >= 2 && prefix[0] == 0xfe && prefix[1] == 0xff;
    const bool utf16 = little_endian || big_endian;
    const bool utf8_bom = prefix_size == 3 && prefix[0] == 0xef && prefix[1] == 0xbb && prefix[2] == 0xbf;
    const std::uintmax_t bom_bytes = utf16 ? 2 : utf8_bom ? 3 : 0;
    if (size < bom_bytes || (utf16 && (size - bom_bytes) % 2 != 0)) {
        failure = "UTF-16 source file has an odd byte length";
        return {};
    }
    if (resume && (checkpoint.path != *resolved || checkpoint.size != size || checkpoint.modified != modified ||
        checkpoint.focus_line != focus_line || checkpoint.utf16 != utf16 ||
        checkpoint.little_endian != little_endian || checkpoint.bom_bytes != bom_bytes)) {
        failure = "Source file or requested context changed; restart source navigation";
        return {};
    }
    if (!resume) {
        checkpoint = {};
        checkpoint.path = *resolved; checkpoint.size = size; checkpoint.modified = modified;
        checkpoint.focus_line = focus_line; checkpoint.utf16 = utf16;
        checkpoint.little_endian = little_endian; checkpoint.bom_bytes = bom_bytes;
        checkpoint.offset = bom_bytes;
        checkpoint.sparse_line_offsets.emplace_back(1, bom_bytes);
    }
    if (checkpoint.offset > size || checkpoint.offset > static_cast<std::uintmax_t>((std::numeric_limits<std::streamoff>::max)())) {
        failure = "Source scan position cannot be represented by the file reader";
        return {};
    }
    input.clear();
    input.seekg(static_cast<std::streamoff>(checkpoint.offset));
    if (!input) { failure = "Could not seek source file"; return {}; }
    std::uintmax_t consumed = checkpoint.offset;
    const auto scan_end = consumed + std::min(max_source_excerpt_scan_bytes, size - consumed);
    std::array<char, 64u * 1024u> buffer{};
    std::size_t buffer_offset = 0, buffer_size = 0;
    const auto read_byte = [&]() -> std::optional<std::uint8_t> {
        if ((consumed & 0xffffu) == 0 && stop.stop_requested()) {
            failure = "Source excerpt canceled";
            return {};
        }
        if (consumed == size) return {};
        if (consumed >= scan_end) {
            failure = "Source scan window exhausted";
            return {};
        }
        if (buffer_offset == buffer_size) {
            const auto scan_remaining = scan_end - consumed;
            const auto requested = static_cast<std::size_t>(std::min<std::uintmax_t>(
                buffer.size(), std::min(size - consumed, scan_remaining)));
            input.read(buffer.data(), static_cast<std::streamsize>(requested));
            if (input.gcount() != static_cast<std::streamsize>(requested)) {
                failure = "Source file changed or could not be read";
                return {};
            }
            buffer_offset = 0;
            buffer_size = requested;
        }
        ++consumed;
        return static_cast<std::uint8_t>(buffer[buffer_offset++]);
    };
    const auto read_unit = [&]() -> std::optional<std::uint16_t> {
        const auto first = read_byte(), second = read_byte();
        if (!first || !second) return {};
        return little_endian ? static_cast<std::uint16_t>(*first | (*second << 8))
                             : static_cast<std::uint16_t>((*first << 8) | *second);
    };
    SourceExcerpt excerpt;
    excerpt.full_file_available = size <= max_source_bytes;
    excerpt.first_line = std::max<std::int64_t>(1, focus_line - context_lines);
    excerpt.lines = std::move(checkpoint.lines);
    const auto last_line = focus_line + context_lines;
    std::int64_t line_number = checkpoint.line_number;
    std::size_t retained_bytes = checkpoint.retained_bytes;
    std::string line = std::move(checkpoint.line);
    bool line_started = checkpoint.line_started;
    bool paused = false;
    const auto finish_line = [&] {
        if (line_number >= excerpt.first_line) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            excerpt.lines.push_back(std::move(line));
            line.clear();
        }
        ++line_number;
        line_started = false;
        if (line_number > 1 && (line_number - 1) % source_line_checkpoint_stride == 0 &&
            checkpoint.sparse_line_offsets.size() < max_source_line_checkpoints)
            checkpoint.sparse_line_offsets.emplace_back(line_number, consumed);
    };
    while (consumed < size && line_number <= last_line) {
        // UTF-8 scalars and UTF-16 surrogate pairs consume at most four bytes.
        // Pause before decoding one, rather than saving a partial character.
        if (scan_end < size && scan_end - consumed < 4) { paused = true; break; }
        std::uint32_t scalar = 0;
        if (utf16) {
            const auto unit = read_unit();
            if (!unit) break;
            scalar = *unit;
            if (scalar >= 0xd800 && scalar <= 0xdbff) {
                const auto low = read_unit();
                if (!low || *low < 0xdc00 || *low > 0xdfff) {
                    failure = "UTF-16 source contains an invalid or truncated surrogate pair";
                    break;
                }
                scalar = 0x10000 + ((scalar - 0xd800) << 10) + (*low - 0xdc00);
            } else if (scalar >= 0xdc00 && scalar <= 0xdfff) {
                failure = "UTF-16 source contains an unpaired low surrogate";
                break;
            }
        } else {
            const auto lead = read_byte();
            if (!lead) break;
            unsigned count = 0;
            std::uint32_t minimum = 0;
            if (*lead <= 0x7f) scalar = *lead;
            else if (*lead >= 0xc2 && *lead <= 0xdf) { scalar = *lead & 0x1f; count = 1; minimum = 0x80; }
            else if (*lead >= 0xe0 && *lead <= 0xef) { scalar = *lead & 0x0f; count = 2; minimum = 0x800; }
            else if (*lead >= 0xf0 && *lead <= 0xf4) { scalar = *lead & 0x07; count = 3; minimum = 0x10000; }
            else { failure = "Source file contains malformed UTF-8"; break; }
            for (unsigned i = 0; i < count; ++i) {
                const auto continuation = read_byte();
                if (!continuation || (*continuation & 0xc0) != 0x80) {
                    failure = "Source file contains malformed or truncated UTF-8";
                    break;
                }
                scalar = (scalar << 6) | (*continuation & 0x3f);
            }
            if (!failure.empty()) break;
            if (scalar < minimum || scalar > 0x10ffff || (scalar >= 0xd800 && scalar <= 0xdfff)) {
                failure = "Source file contains malformed UTF-8";
                break;
            }
        }
        if (scalar == '\n') { finish_line(); continue; }
        line_started = true;
        if (line_number < excerpt.first_line) continue;
        const std::size_t encoded_size = scalar <= 0x7f ? 1 : scalar <= 0x7ff ? 2 : scalar <= 0xffff ? 3 : 4;
        if (encoded_size > max_source_bytes - retained_bytes) {
            failure = "Source excerpt exceeds the 1 MiB decoded-text limit";
            break;
        }
        append_utf8(line, scalar);
        retained_bytes += encoded_size;
    }
    if (!failure.empty()) return {};
    if (!paused && line_number <= last_line && (line_started || line_number == 1)) finish_line();
    const auto current_size = std::filesystem::file_size(*resolved, error);
    if (error || current_size != size) {
        failure = "Source file changed while reading the excerpt";
        return {};
    }
    const auto current_modified = std::filesystem::last_write_time(*resolved, error);
    if (error || current_modified != modified) {
        failure = "Source file changed while reading the excerpt";
        return {};
    }
    if (paused) {
        checkpoint.offset = consumed; checkpoint.line_number = line_number;
        checkpoint.retained_bytes = retained_bytes; checkpoint.line_started = line_started;
        checkpoint.lines = std::move(excerpt.lines); checkpoint.line = std::move(line);
        checkpoint.pending = true;
        failure = "Source scan paused at byte " + std::to_string(consumed) + ", line " +
            std::to_string(line_number) + "; choose Continue source scan to read the next window";
        return {};
    }
    if (focus_line - excerpt.first_line >= static_cast<std::int64_t>(excerpt.lines.size())) {
        failure = "Mapped source line is outside the available file";
        return {};
    }
    checkpoint.offset = consumed;
    checkpoint.line_number = line_number;
    checkpoint.focus_line = focus_line;
    checkpoint.retained_bytes = 0;
    checkpoint.line.clear();
    checkpoint.lines.clear();
    checkpoint.line_started = false;
    checkpoint.pending = consumed < size;
    return excerpt;
}

std::vector<std::string> split_lines(std::string_view bytes, std::stop_token stop = {}) {
    std::vector<std::string> lines;
    std::size_t begin = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if ((i & 0xffffu) == 0 && stop.stop_requested()) return {};
        if (bytes[i] != '\n') continue;
        std::size_t end = i;
        if (end > begin && bytes[end - 1] == '\r') --end;
        lines.emplace_back(bytes.data() + begin, end - begin);
        begin = i + 1;
    }
    if (begin < bytes.size() || lines.empty()) {
        std::size_t end = bytes.size();
        if (end > begin && bytes[end - 1] == '\r') --end;
        lines.emplace_back(bytes.data() + begin, end - begin);
    }
    return lines;
}

SourceSearchResult search_source_file(const std::filesystem::path &path, std::stop_token stop, std::string needle,
                                      bool ignore_ascii_case, bool next, std::int64_t start_line,
                                      std::optional<std::pair<std::int64_t, std::size_t>> cursor) {
    SourceSearchResult result;
    std::string failure;
    const auto bytes = read_source_search(path, stop, failure);
    if (!failure.empty()) {
        result.failure = std::move(failure);
        return result;
    }
    const auto decoded = decode_source_text(bytes, failure, stop);
    if (!decoded) {
        result.failure = std::move(failure);
        return result;
    }
    const auto fold_ascii = [](std::string value) {
        for (auto &byte : value)
            if (byte >= 'A' && byte <= 'Z') byte = static_cast<char>(byte + ('a' - 'A'));
        return value;
    };
    if (ignore_ascii_case) needle = fold_ascii(std::move(needle));
    const auto lines = split_lines(*decoded, stop);
    if (stop.stop_requested()) { result.failure = "Source search canceled"; return result; }
    if (lines.empty()) {
        result.failure = "Source file contains no searchable lines";
        return result;
    }
    const auto current_line = std::clamp<std::int64_t>(start_line, 1, static_cast<std::int64_t>(lines.size()));
    const auto current_index = static_cast<std::size_t>(current_line - 1);
    const auto folded_current = ignore_ascii_case ? fold_ascii(lines[current_index]) : std::string{};
    const auto &current_text = ignore_ascii_case ? folded_current : lines[current_index];
    std::optional<std::pair<std::int64_t, std::size_t>> match;
    if (cursor && cursor->first == current_line) {
        const auto current_offset = std::min(cursor->second, current_text.size());
        if (next && needle.size() <= current_text.size() - current_offset) {
            const auto found = current_text.find(needle, current_offset + needle.size());
            if (found != std::string::npos) match = std::pair{current_line, found};
        } else if (!next && current_offset > 0) {
            const auto found = current_text.rfind(needle, current_offset - 1);
            if (found != std::string::npos) match = std::pair{current_line, found};
        }
    }
    for (std::size_t step = 1; !match && step <= lines.size(); ++step) {
        if (stop.stop_requested()) { result.failure = "Source search canceled"; return result; }
        const auto offset = static_cast<std::int64_t>(step);
        const auto line_number = next
            ? 1 + ((current_line - 1 + offset) % static_cast<std::int64_t>(lines.size()))
            : 1 + ((current_line - 1 - offset % static_cast<std::int64_t>(lines.size()) +
                    static_cast<std::int64_t>(lines.size())) % static_cast<std::int64_t>(lines.size()));
        const auto line_index = static_cast<std::size_t>(line_number - 1);
        const auto folded_line = ignore_ascii_case ? fold_ascii(lines[line_index]) : std::string{};
        const auto &line = ignore_ascii_case ? folded_line : lines[line_index];
        const auto found = line.find(needle);
        if (found != std::string::npos) match = std::pair{line_number, found};
    }
    if (!match && cursor && cursor->first == current_line) {
        if (next && cursor->second > 0) {
            const auto found = current_text.find(needle);
            if (found != std::string::npos && found < cursor->second) match = std::pair{current_line, found};
        } else if (!next && cursor->second < current_text.size()) {
            const auto found = current_text.rfind(needle);
            if (found != std::string::npos && found > cursor->second) match = std::pair{current_line, found};
        }
    }
    if (!match) return result;

    const auto &matched_line = lines[static_cast<std::size_t>(match->first - 1)];
    for (std::size_t i = 0; i < match->second; ++i)
        if ((static_cast<unsigned char>(matched_line[i]) & 0xc0u) != 0x80u)
            ++result.character_offset;
    for (std::size_t line_index = 0; line_index < lines.size(); ++line_index) {
        if (stop.stop_requested()) { result.failure = "Source search canceled"; return result; }
        const auto folded_line = ignore_ascii_case ? fold_ascii(lines[line_index]) : std::string{};
        const auto &line = ignore_ascii_case ? folded_line : lines[line_index];
        std::size_t position = 0;
        while (position <= line.size()) {
            position = line.find(needle, position);
            if (position == std::string::npos) break;
            ++result.total_occurrences;
            if (line_index + 1 < static_cast<std::size_t>(match->first) ||
                (line_index + 1 == static_cast<std::size_t>(match->first) && position <= match->second))
                ++result.occurrence;
            position += needle.size();
        }
    }
    result.found = true;
    result.line = match->first;
    result.byte_offset = match->second;
    return result;
}

wxString display_path(const std::string &path) {
    return wxString::FromUTF8(path.data(), path.size());
}
std::string utf8(const wxString &value) {
    const auto encoded = value.utf8_str();
    return {encoded.data(), encoded.length()};
}

std::optional<std::filesystem::path> usable_path(const std::string &path) {
    if (path.empty() || path.size() > max_source_path_bytes || path.find('\0') != std::string::npos) return {};
    try {
        std::u8string encoded;
        encoded.reserve(path.size());
        for (const unsigned char value : path) encoded.push_back(static_cast<char8_t>(value));
        auto parsed = std::filesystem::path(std::move(encoded));
#ifdef _WIN32
        // Reject network shares and Win32 device namespace paths before any
        // filesystem operation. canonical() below catches local aliases too.
        const auto native = parsed.native();
        if (native.size() >= 2 && native[0] == L'\\' && native[1] == L'\\') return {};
#endif
        return parsed;
    } catch (...) {
        return {};
    }
}
} // namespace

SourceView::SourceView(wxWindow *parent)
    : wxPanel(parent), source_search_timer_(this), source_load_timer_(this), source_excerpt_timer_(this),
      source_revision_timer_(this) {
    auto *layout = new wxBoxSizer(wxVERTICAL);
    auto *navigation = new wxBoxSizer(wxHORIZONTAL);
    auto *search = new wxBoxSizer(wxHORIZONTAL);
    source_filter_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, FromDIP(wxSize(180, -1)));
    source_filter_->SetName("source-file-filter");
    source_filter_->SetHint("Filter source files");
    source_find_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, FromDIP(wxSize(220, -1)), wxTE_PROCESS_ENTER);
    source_find_->SetName("source-text-search");
    source_find_->SetHint("Find in source file");
    source_find_->SetMaxLength(2048);
    source_find_ignore_case_ = new wxCheckBox(this, wxID_ANY, "Ignore ASCII case");
    source_find_ignore_case_->SetName("source-find-ignore-ascii-case");
    source_find_ignore_case_->SetToolTip("Fold ASCII A-Z only; non-ASCII UTF-8 bytes must match exactly.");
    previous_match_ = new wxButton(this, wxID_ANY, "Find previous");
    previous_match_->SetName("source-find-previous");
    next_match_ = new wxButton(this, wxID_ANY, "Find next");
    next_match_->SetName("source-find-next");
    load_full_source_ = new wxButton(this, wxID_ANY, "Load full file");
    load_full_source_->SetName("source-load-full-file");
    load_full_source_->SetToolTip("Load and decode the selected source file in the background (maximum 64 MiB).");
    source_file_ = new wxChoice(this, wxID_ANY);
    source_file_->SetName("source-file-picker");
    source_file_->SetMinSize(FromDIP(wxSize(180, -1)));
    status_ = new wxStaticText(this, wxID_ANY, "No source line selected");
    previous_mapping_ = new wxButton(this, wxID_ANY, "Previous address");
    previous_mapping_->SetName("source-previous-address");
    previous_mapping_->SetToolTip("Move to the previous machine address mapped to this source line.");
    next_mapping_ = new wxButton(this, wxID_ANY, "Next address");
    next_mapping_->SetName("source-next-address");
    next_mapping_->SetToolTip("Move to the next machine address mapped to this source line.");
    toggle_breakpoint_ = new wxButton(this, wxID_ANY, "Toggle project breakpoint");
    toggle_breakpoint_->SetName("source-toggle-project-breakpoint");
    toggle_breakpoint_->SetToolTip("Add or remove a saved software breakpoint at the selected mapped address.");
    edit_source_ = new wxButton(this, wxID_ANY, "Edit source");
    edit_source_->SetName("source-edit");
    save_source_ = new wxButton(this, wxID_ANY, "Save");
    save_source_->SetName("source-save");
    discard_source_ = new wxButton(this, wxID_ANY, "Discard edits");
    discard_source_->SetName("source-discard-edits");
    continue_source_scan_ = new wxButton(this, wxID_ANY, "Continue source scan");
    continue_source_scan_->SetName("source-continue-scan");
    continue_source_scan_->SetToolTip("Read the next bounded window toward the requested source line.");
    continue_source_scan_->Enable(false);
    previous_source_page_ = new wxButton(this, wxID_ANY, "Previous page");
    previous_source_page_->SetName("source-previous-page");
    previous_source_page_->SetToolTip("Decode the previous bounded source page using the sparse line checkpoints.");
    previous_source_page_->Enable(false);
    next_source_page_ = new wxButton(this, wxID_ANY, "Next page");
    next_source_page_->SetName("source-next-page");
    next_source_page_->SetToolTip("Decode the next bounded source page without loading the complete file.");
    next_source_page_->Enable(false);
    copy_source_location_ = new wxButton(this, wxID_ANY, "Copy location");
    copy_source_location_->SetName("source-copy-location");
    copy_source_location_->SetToolTip("Copy the visible source path and line, with its mapped address when available.");
    copy_source_location_->Enable(false);
    copy_line_map_ = new wxButton(this, wxID_ANY, "Copy line map");
    copy_line_map_->SetName("source-copy-line-map");
    copy_line_map_->SetToolTip("Copy bounded source-origin rows with address, column, inline scope, and instruction text for the focused line as TSV.");
    copy_line_map_->Enable(false);
    copy_source_line_ = new wxButton(this, wxID_ANY, "Copy line text");
    copy_source_line_->SetName("source-copy-line-text");
    copy_source_line_->SetToolTip("Copy the focused visible source line without its line-number gutter.");
    copy_source_line_->Enable(false);
    copy_source_excerpt_ = new wxButton(this, wxID_ANY, "Copy excerpt");
    copy_source_excerpt_->SetName("source-copy-excerpt");
    copy_source_excerpt_->SetToolTip("Copy the displayed source excerpt as UTF-8 with its path and line range.");
    copy_source_excerpt_->Enable(false);
    check_source_revision_ = new wxButton(this, wxID_ANY, "Check PDB revision");
    check_source_revision_->SetName("source-check-pdb-revision");
    check_source_revision_->SetToolTip("Hash the selected source file and compare it with the PDB SHA-256 checksum (64 MiB limit). Read-only.");
    check_source_revision_->Enable(false);
    auto *source_splitter = new wxSplitterWindow(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                                                  wxSP_LIVE_UPDATE | wxSP_3D);
    source_ = new wxTextCtrl(source_splitter, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize,
                             wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP | wxTE_RICH2);
    source_->SetName("source-code-view");
    mapped_instructions_ = new VirtualTable(source_splitter, "source-line-instructions",
                                             {"Address", "Column", "Inline origin", "Instruction", "Mapping", "Project breakpoint"});
    mapped_instructions_->SetColumnWidth(0, FromDIP(130));
    mapped_instructions_->SetColumnWidth(1, FromDIP(72));
    mapped_instructions_->SetColumnWidth(2, FromDIP(220));
    mapped_instructions_->SetColumnWidth(3, FromDIP(420));
    mapped_instructions_->SetColumnWidth(4, FromDIP(135));
    mapped_instructions_->SetColumnWidth(5, FromDIP(150));
    source_splitter->SetMinimumPaneSize(FromDIP(72));
    source_splitter->SplitHorizontally(source_, mapped_instructions_, FromDIP(300));
    status_->SetName("source-code-status");
    navigation->Add(source_filter_, 0, wxALIGN_CENTER_VERTICAL | wxALL, FromDIP(4));
    navigation->Add(source_file_, 0, wxALIGN_CENTER_VERTICAL | wxALL, FromDIP(4));
    navigation->Add(status_, 1, wxALIGN_CENTER_VERTICAL | wxALL, FromDIP(4));
    navigation->Add(previous_mapping_, 0, wxALL, FromDIP(2));
    navigation->Add(next_mapping_, 0, wxALL, FromDIP(2));
    navigation->Add(toggle_breakpoint_, 0, wxALL, FromDIP(2));
    navigation->Add(edit_source_, 0, wxALL, FromDIP(2));
    navigation->Add(save_source_, 0, wxALL, FromDIP(2));
    navigation->Add(discard_source_, 0, wxALL, FromDIP(2));
    navigation->Add(copy_source_location_, 0, wxALL, FromDIP(2));
    navigation->Add(copy_line_map_, 0, wxALL, FromDIP(2));
    navigation->Add(check_source_revision_, 0, wxALL, FromDIP(2));
    search->Add(new wxStaticText(this, wxID_ANY, "Find in source file:"), 0, wxALIGN_CENTER_VERTICAL | wxALL, FromDIP(4));
    search->Add(source_find_, 0, wxALIGN_CENTER_VERTICAL | wxALL, FromDIP(2));
    search->Add(source_find_ignore_case_, 0, wxALIGN_CENTER_VERTICAL | wxALL, FromDIP(2));
    search->Add(previous_match_, 0, wxALL, FromDIP(2));
    search->Add(next_match_, 0, wxALL, FromDIP(2));
    search->Add(load_full_source_, 0, wxALL, FromDIP(2));
    search->Add(continue_source_scan_, 0, wxALL, FromDIP(2));
    search->Add(previous_source_page_, 0, wxALL, FromDIP(2));
    search->Add(next_source_page_, 0, wxALL, FromDIP(2));
    search->Add(copy_source_line_, 0, wxALL, FromDIP(2));
    search->Add(copy_source_excerpt_, 0, wxALL, FromDIP(2));
    layout->Add(navigation, 0, wxEXPAND);
    layout->Add(search, 0, wxEXPAND);
    layout->Add(source_splitter, 1, wxEXPAND);
    SetSizer(layout);
    source_->Bind(wxEVT_LEFT_UP, [this](wxMouseEvent &event) {
        event.Skip();
        select_source_line();
    });
    source_->Bind(wxEVT_KEY_UP, [this](wxKeyEvent &event) {
        event.Skip();
        select_source_line();
    });
    source_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) {
        if (!source_editing_) return;
        source_dirty_ = true;
        update_source_edit_controls();
    });
    edit_source_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { begin_source_edit(); });
    save_source_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { save_source_edit(); });
    discard_source_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { discard_source_edit(); });
    copy_source_excerpt_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_source_excerpt(); });
    check_source_revision_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { check_source_revision(); });
    continue_source_scan_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (!source_scan_ || !source_scan_->pending || !pending_source_row_ ||
            !source_scan_document_ || source_scan_document_ != document_) {
            render_unavailable("Source scan context changed; select the mapped source line again");
            return;
        }
        const auto row = *pending_source_row_;
        const auto page_navigation = pending_source_page_navigation_;
        render_source_row(row, pending_source_context_, pending_source_line_, true,
                          page_navigation);
    });
    previous_source_page_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { page_source(false); });
    next_source_page_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { page_source(true); });
    previous_mapping_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { navigate_line_mapping(false); });
    next_mapping_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { navigate_line_mapping(true); });
    previous_match_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { find_source_text(false); });
    next_match_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { find_source_text(true); });
    copy_source_location_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_source_location(); });
    copy_line_map_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_line_map(); });
    copy_source_line_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_source_line(); });
    source_find_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent &) { find_source_text(true); });
    Bind(wxEVT_TIMER, [this](wxTimerEvent &) { poll_source_search(); }, source_search_timer_.GetId());
    Bind(wxEVT_TIMER, [this](wxTimerEvent &) { poll_full_source_load(); }, source_load_timer_.GetId());
    Bind(wxEVT_TIMER, [this](wxTimerEvent &) { poll_source_excerpt(); }, source_excerpt_timer_.GetId());
    Bind(wxEVT_TIMER, [this](wxTimerEvent &) { poll_source_revision(); }, source_revision_timer_.GetId());
    load_full_source_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { load_or_cancel_full_source(); });
    source_find_ignore_case_->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent &) {
        source_match_.reset();
        source_match_query_.clear();
    });
    toggle_breakpoint_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        if (selected_line_addresses_.empty()) {
            status_->SetLabel("Select a source line with a mapped address first");
            return;
        }
        const auto selected = mapped_instructions_->selected_row();
        const auto index = selected && *selected < instruction_mappings_.size()
            ? *selected : std::min(selected_line_address_index_, selected_line_addresses_.size() - 1);
        const auto address = selected && *selected < instruction_mappings_.size()
            ? instruction_mappings_[*selected].address : selected_line_addresses_[index];
        if (toggle_project_breakpoint && document_ && toggle_project_breakpoint(document_, address)) {
            status_->SetLabel(wxString::Format("Project breakpoint toggled at 0x%llX",
                                               static_cast<unsigned long long>(address.offset)));
        } else
            status_->SetLabel("Could not update project breakpoint; check project mode and status");
    });
    mapped_instructions_->activate = [this](std::size_t row) {
        if (row < instruction_mappings_.size() && navigate)
            navigate(Location{instruction_mappings_[row].address});
    };
    source_filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) {
        constexpr std::size_t filter_limit = 2048;
        if (source_filter_->GetValue().length() > filter_limit) {
            source_filter_->ChangeValue(source_filter_->GetValue().Left(filter_limit));
            source_filter_->SetInsertionPointEnd();
        }
        refresh_file_choices();
    });
    source_file_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) {
        if (!document_ || source_file_->GetSelection() < 0) return;
        const auto index = static_cast<std::size_t>(source_file_->GetSelection());
        if (index >= visible_source_paths_.size()) return;
        const auto &path = visible_source_paths_[index];
        const SourceRow *selected = nullptr;
        bool ambiguous_inline = false;
        if (selection_address_)
            selected = source_row_for(*selection_address_, ambiguous_inline, &path);
        if (!selected) {
            const auto indexed = rows_by_path_.find(path);
            if (indexed != rows_by_path_.end() && !indexed->second.empty())
                selected = &rows_[indexed->second.front()];
        }
        if (selected) render_source_row(*selected, selection_address_.value_or(selected->address));
        else render_unavailable("No source mappings are available for this file");
    });
    update_mapping_controls();
    update_source_edit_controls();
}

SourceView::~SourceView() {
    source_search_timer_.Stop();
    if (source_search_running_) source_search_stop_.request_stop();
    if (source_search_future_.valid()) source_search_future_.wait();
    source_load_timer_.Stop();
    if (source_load_running_) source_load_stop_.request_stop();
    if (source_load_future_.valid()) source_load_future_.wait();
    source_excerpt_timer_.Stop();
    if (source_excerpt_running_) source_excerpt_stop_.request_stop();
    if (source_excerpt_future_.valid()) source_excerpt_future_.wait();
    source_revision_timer_.Stop();
    if (source_revision_running_) source_revision_stop_.request_stop();
    if (source_revision_future_.valid()) source_revision_future_.wait();
}

void SourceView::set_document(std::shared_ptr<const DocumentSnapshot> document) {
    if (!finish_source_edit()) return;
    if (source_search_running_) source_search_stop_.request_stop();
    if (source_load_running_) source_load_stop_.request_stop();
    if (source_excerpt_running_) source_excerpt_stop_.request_stop();
    if (source_revision_running_) source_revision_stop_.request_stop();
    full_file_display_ = false;
    if (document_) {
        BrowserState state{source_filter_->GetValue().Left(2048), rendered_path_,
                           source_find_ignore_case_->GetValue()};
        if (state.path.empty() && source_file_->GetSelection() >= 0) {
            const auto selected = static_cast<std::size_t>(source_file_->GetSelection());
            if (selected < visible_source_paths_.size()) state.path = visible_source_paths_[selected];
        }
        browser_states_.insert_or_assign(document_->id.value, std::move(state));
        while (browser_states_.size() > 32) {
            auto oldest = browser_states_.begin();
            if (oldest->first == document_->id.value && ++oldest == browser_states_.end()) break;
            browser_states_.erase(oldest);
        }
    }
    document_ = std::move(document);
    BrowserState browser_state;
    if (document_) {
        if (const auto saved = browser_states_.find(document_->id.value); saved != browser_states_.end())
            browser_state = saved->second;
    }
    source_match_.reset();
    source_match_query_.clear();
    source_match_path_.clear();
    source_scan_.reset(); source_scan_document_.reset(); pending_source_row_.reset();
    source_line_index_.reset(); source_page_path_.clear();
    pending_source_page_navigation_ = false;
    continue_source_scan_->Enable(false);
    rows_.clear();
    rows_by_space_.clear();
    rows_by_path_.clear();
    source_revision_evidence_by_path_.clear();
    source_paths_.clear();
    visible_source_paths_.clear();
    source_file_->Clear();
    source_filter_->ChangeValue(browser_state.filter);
    source_find_ignore_case_->SetValue(browser_state.ignore_ascii_case);
    visible_addresses_.clear();
    visible_lines_.clear();
    rendered_path_.clear();
    displayed_source_row_.reset();
    rendered_space_.reset();
    selection_address_.reset();
    selected_line_addresses_.clear();
    selected_line_address_index_ = 0;
    update_mapping_controls();
    if (!document_) {
        render_unavailable("No active document");
        return;
    }
    const ImageMetadata *metadata = &document_->metadata;
    if (document_->project && document_->project->loaded)
        metadata = &document_->project->loaded->metadata;
    if (metadata->pe) {
        for (const auto &row : metadata->pe->source_lines) {
            if (!row.source_path.empty() && row.checksum_kind != 0 && !row.checksum.empty()) {
                auto &evidence = source_revision_evidence_by_path_[row.source_path];
                if (evidence.checksum.empty()) {
                    evidence.checksum_kind = row.checksum_kind;
                    evidence.checksum = row.checksum;
                } else if (evidence.checksum_kind != row.checksum_kind || evidence.checksum != row.checksum) {
                    evidence.conflict = true;
                }
            }
            if (row.address && row.line > 0 && !row.source_path.empty())
                rows_.push_back({*row.address, row.source_path, row.line, row.start_column});
        }
        for (const auto &site : metadata->pe->pdb_inline_sites)
            for (const auto &range : site.ranges)
                if (rows_.size() < 250'000 && range.address && range.line && !range.source_path.empty())
                    rows_.push_back({*range.address, range.source_path, range.line, 0, range.size, site.depth,
                        "inlinee IPI " + std::to_string(site.inlinee_id) + ", module " + std::to_string(site.module_index) +
                        ", site " + std::to_string(site.record_offset)});
    }
    if (metadata->elf) {
        for (const auto &row : metadata->elf->source_lines)
            if (!row.end_sequence && row.line > 0 && !row.file.empty())
                rows_.push_back({row.address, row.file, row.line, row.column});
    }
    if (metadata->macho) {
        for (const auto &row : metadata->macho->source_lines)
            if (!row.end_sequence && row.address && row.line > 0 && !row.file.empty())
                rows_.push_back({*row.address, row.file, row.line, row.column});
    }
    if (metadata->dex) {
        constexpr std::size_t max_dex_source_rows = 250'000;
        for (const auto &method : metadata->dex->methods) {
            for (const auto &line : method.lines) {
                if (rows_.size() >= max_dex_source_rows) break;
                if (line.line == 0 || line.source_file.empty()) continue;
                const auto method_space = static_cast<std::uint32_t>(std::uint64_t{method.method_index} + 1);
                rows_.push_back({Address{AddressSpaceId{method_space}, line.address},
                                 line.source_file, line.line, 0, 0, 0,
                                 "DEX method #" + std::to_string(method.method_index)});
            }
            if (rows_.size() >= max_dex_source_rows) break;
        }
    }
    std::stable_sort(rows_.begin(), rows_.end(), [](const SourceRow &left, const SourceRow &right) {
        if (left.address.space.value != right.address.space.value)
            return left.address.space.value < right.address.space.value;
        if (left.address.offset != right.address.offset) return left.address.offset < right.address.offset;
        return left.line < right.line;
    });
    for (std::size_t index = 0; index < rows_.size(); ++index) {
        const auto &row = rows_[index];
        rows_by_space_[row.address.space.value].push_back(index);
        rows_by_path_[row.path].push_back(index);
    }
    source_paths_.reserve(rows_by_path_.size());
    for (const auto &[path, indices] : rows_by_path_) {
        (void)indices;
        source_paths_.push_back(path);
    }
    refresh_file_choices(browser_state.path.empty()
        ? (source_paths_.empty() ? std::string{} : source_paths_.front())
        : browser_state.path);
    render_unavailable(rows_.empty() ? "No usable source line mappings are available for this document"
                                     : "Navigate to an address with source information");
}

void SourceView::select(Location location) {
    if (!document_) return;
    if (source_search_running_) source_search_stop_.request_stop();
    if (source_load_running_) source_load_stop_.request_stop();
    if (rows_.empty()) {
        render_unavailable("No source line mappings are available");
        return;
    }
    auto address = address_for(*document_, location);
    if (!address) {
        render_unavailable("No source mapping at the current file offset");
        return;
    }
    selection_address_ = *address;
    bool ambiguous_inline = false;
    const auto *selected = source_row_for(*address, ambiguous_inline);
    if (ambiguous_inline) {
        render_unavailable("Multiple inline scopes overlap this address; inspect PE / PDB inline scopes");
        return;
    }
    if (!selected) {
        render_unavailable("No source mapping at the current address");
        return;
    }
    if (display_path(selected->path).Lower().Find(source_filter_->GetValue().Lower()) == wxNOT_FOUND)
        source_filter_->ChangeValue({});
    refresh_file_choices(selected->path);
    render_source_row(*selected, *address);
}

bool SourceView::has_source_mapping(const std::shared_ptr<const DocumentSnapshot> &document,
                                    Address address) const {
    if (!document || document_ != document) return false;
    bool ambiguous_inline = false;
    return source_row_for(address, ambiguous_inline) && !ambiguous_inline;
}

const SourceView::SourceRow *SourceView::source_row_for(Address address, bool &ambiguous_inline,
                                                        const std::string *path) const {
    const SourceRow *selected = nullptr;
    ambiguous_inline = false;
    const std::vector<std::size_t> *indices = nullptr;
    if (path) {
        const auto found = rows_by_path_.find(*path);
        if (found != rows_by_path_.end()) indices = &found->second;
    } else {
        const auto found = rows_by_space_.find(address.space.value);
        if (found != rows_by_space_.end()) indices = &found->second;
    }
    if (!indices) return nullptr;
    const auto begin = path
        ? std::lower_bound(indices->begin(), indices->end(), address.space.value,
            [&](std::size_t index, std::uint32_t space) {
                return rows_[index].address.space.value < space;
            })
        : indices->begin();
    const auto after = path
        ? std::upper_bound(indices->begin(), indices->end(), address,
            [&](Address value, std::size_t index) {
                const auto &row_address = rows_[index].address;
                return value.space.value < row_address.space.value ||
                    (value.space == row_address.space && value.offset < row_address.offset);
            })
        : std::upper_bound(indices->begin(), indices->end(), address.offset,
            [&](std::uint64_t offset, std::size_t index) {
                return offset < rows_[index].address.offset;
            });
    for (auto iterator = begin; iterator != after; ++iterator) {
        const auto &row = rows_[*iterator];
        if (row.address.space != address.space || row.address.offset > address.offset) continue;
        if (row.inline_size && address.offset - row.address.offset >= row.inline_size) continue;
        if (selected && row.inline_depth && row.inline_depth == selected->inline_depth &&
            (row.path != selected->path || row.line != selected->line || row.scope != selected->scope))
            ambiguous_inline = true;
        if (!selected || row.inline_depth > selected->inline_depth ||
            (row.inline_depth == selected->inline_depth && row.address.offset > selected->address.offset)) {
            if (!selected || row.inline_depth > selected->inline_depth) ambiguous_inline = false;
            selected = &row;
        }
    }
    return selected;
}

void SourceView::refresh_file_choices(const std::string &preferred_path) {
    std::string preserve = preferred_path;
    if (preserve.empty() && source_file_->GetSelection() >= 0) {
        const auto selected = static_cast<std::size_t>(source_file_->GetSelection());
        if (selected < visible_source_paths_.size()) preserve = visible_source_paths_[selected];
    }
    const auto filter = source_filter_->GetValue().Lower();
    visible_source_paths_.clear();
    source_file_->Clear();
    for (const auto &path : source_paths_)
        if (filter.empty() || display_path(path).Lower().Find(filter) != wxNOT_FOUND) {
            visible_source_paths_.push_back(path);
            source_file_->Append(display_path(path));
        }
    const auto found = std::find(visible_source_paths_.begin(), visible_source_paths_.end(), preserve);
    if (found != visible_source_paths_.end())
        source_file_->SetSelection(static_cast<int>(std::distance(visible_source_paths_.begin(), found)));
    else if (!visible_source_paths_.empty())
        source_file_->SetSelection(0);
}

void SourceView::render_source_row(const SourceRow &source_row, Address context_address) {
    render_source_row(source_row, context_address, source_row.line);
}

void SourceView::render_source_row(const SourceRow &source_row, Address context_address,
                                   std::int64_t focus_line, bool continue_scan, bool page_navigation) {
    if (!finish_source_edit()) return;
    if (source_revision_running_ && source_revision_path_ != source_row.path) {
        ++source_revision_generation_;
        source_revision_stop_.request_stop();
    }
    if (source_load_running_) source_load_stop_.request_stop();
    full_file_display_ = false;
    load_full_source_->SetLabel("Load full file");
    const auto requested_row = source_row;
    const auto *selected = &requested_row;
    if (source_pending_match_ &&
        (source_pending_match_->generation != source_excerpt_generation_ + 1 ||
         source_pending_match_->path != requested_row.path ||
         source_pending_match_->result.line != focus_line))
        source_pending_match_.reset();
    auto path = usable_path(selected->path);
    if (!path) {
        render_unavailable("Debug information contains an invalid source path");
        return;
    }
    const auto source_document = document_;
    auto checkpoint = continue_scan ? source_scan_ : std::make_shared<SourceScanCheckpoint>();
    bool resume = continue_scan;
    if (!checkpoint || (continue_scan && (source_scan_document_ != source_document || !checkpoint->pending))) {
        render_unavailable("Source scan context changed; select the mapped source line again");
        return;
    }
    if (continue_scan)
        checkpoint = std::make_shared<SourceScanCheckpoint>(*checkpoint);
    if (!continue_scan && source_line_index_) {
        std::error_code canonical_error;
        const auto canonical = std::filesystem::canonical(*path, canonical_error);
        if (!canonical_error && canonical == source_line_index_->path &&
            !source_line_index_->sparse_line_offsets.empty()) {
            const auto first_line = std::max<std::int64_t>(1, focus_line - context_lines);
            auto start = source_line_index_->sparse_line_offsets.begin();
            for (auto candidate = source_line_index_->sparse_line_offsets.begin();
                 candidate != source_line_index_->sparse_line_offsets.end() &&
                     candidate->first <= first_line; ++candidate)
                start = candidate;
            *checkpoint = *source_line_index_;
            const auto keep = std::upper_bound(checkpoint->sparse_line_offsets.begin(),
                checkpoint->sparse_line_offsets.end(), start->first,
                [](std::int64_t line, const auto &entry) { return line < entry.first; });
            checkpoint->sparse_line_offsets.erase(keep, checkpoint->sparse_line_offsets.end());
            checkpoint->line_number = start->first;
            checkpoint->offset = start->second;
            checkpoint->focus_line = focus_line;
            checkpoint->retained_bytes = 0;
            checkpoint->lines.clear();
            checkpoint->line.clear();
            checkpoint->line_started = false;
            checkpoint->pending = true;
            resume = true;
        }
    }
    continue_source_scan_->Enable(false);
    SourceExcerptRequest request{requested_row, context_address, focus_line, continue_scan,
                                 resume, page_navigation, source_document,
                                 source_revision_stamp(source_document),
                                 std::move(checkpoint),
                                 ++source_excerpt_generation_};
    if (source_excerpt_running_) {
        source_excerpt_stop_.request_stop();
        source_excerpt_queued_request_ = std::move(request);
        status_->SetLabel("Canceling the previous source scan before loading the selected line...");
        return;
    }
    start_source_excerpt(std::move(request));
}

void SourceView::start_source_excerpt(SourceExcerptRequest request) {
    if (request.document != document_ || request.revision != source_revision_stamp(document_) ||
        request.generation != source_excerpt_generation_) return;
    auto path = usable_path(request.row.path);
    if (!path) {
        render_unavailable("Debug information contains an invalid source path");
        return;
    }
    source_excerpt_stop_ = std::stop_source{};
    const auto stop = source_excerpt_stop_.get_token();
    const auto resume = request.resume;
    auto checkpoint = request.checkpoint;
    try {
        source_excerpt_future_ = std::async(std::launch::async,
            [path = *path, stop, checkpoint = std::move(checkpoint), focus = request.focus_line, resume]() mutable {
                SourceExcerptLoadResult result;
                result.checkpoint = checkpoint;
                const auto excerpt = read_source_excerpt(path, focus, result.failure, *checkpoint, resume, stop);
                if (excerpt) {
                    result.first_line = excerpt->first_line;
                    result.lines = excerpt->lines;
                    result.full_file_available = excerpt->full_file_available;
                }
                return result;
            });
    } catch (const std::exception &error) {
        render_unavailable("Could not start source excerpt scan: " + text(error.what()));
        return;
    }
    source_excerpt_active_request_ = std::move(request);
    source_excerpt_running_ = true;
    update_source_edit_controls();
    status_->SetLabel("Loading the mapped source excerpt in the background (64 MiB scan window)...");
    source_excerpt_timer_.Start(35);
}

void SourceView::poll_source_excerpt() {
    if (!source_excerpt_running_ || !source_excerpt_future_.valid() ||
        source_excerpt_future_.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
        return;
    SourceExcerptLoadResult result;
    try {
        result = source_excerpt_future_.get();
    } catch (const std::exception &error) {
        result.failure = error.what();
    } catch (...) {
        result.failure = "Unexpected source excerpt worker failure";
    }
    source_excerpt_timer_.Stop();
    source_excerpt_running_ = false;
    auto request = std::move(source_excerpt_active_request_);
    source_excerpt_active_request_.reset();
    if (source_excerpt_queued_request_) {
        auto queued = std::move(*source_excerpt_queued_request_);
        source_excerpt_queued_request_.reset();
        update_source_edit_controls();
        start_source_excerpt(std::move(queued));
        return;
    }
    update_source_edit_controls();
    if (!request || request->document != document_ ||
        request->revision != source_revision_stamp(document_) ||
        request->generation != source_excerpt_generation_)
        return;
    if (!result.failure.empty()) {
        const auto message = display_path(request->row.path) + ": " + text(result.failure);
        const auto checkpoint = result.checkpoint;
        render_unavailable(message);
        if (checkpoint && checkpoint->pending) {
            source_scan_ = checkpoint;
            source_scan_document_ = request->document;
            pending_source_row_ = request->row;
            pending_source_context_ = request->context;
            pending_source_line_ = request->focus_line;
            pending_source_page_navigation_ = request->page_navigation;
            continue_source_scan_->Enable(true);
        }
        return;
    }
    apply_source_excerpt(*request, std::move(result));
    apply_source_search_match(*request);
}

void SourceView::apply_source_excerpt(const SourceExcerptRequest &request,
                                     SourceExcerptLoadResult excerpt) {
    auto selected = request.row;
    const auto context_address = request.context;
    const auto focus_line = request.focus_line;
    if (request.page_navigation) {
        selected.line = focus_line;
        selected.address = context_address;
        selected.inline_size = 0;
        selected.inline_depth = 0;
        selected.scope.clear();
        if (const auto indexed = rows_by_path_.find(selected.path); indexed != rows_by_path_.end())
            for (const auto index : indexed->second) {
                const auto &candidate = rows_[index];
                if (candidate.address.space == context_address.space && candidate.line == focus_line) {
                    selected = candidate;
                    break;
                }
            }
    }
    const auto path = usable_path(selected.path);
    if (!path || document_ != request.document) return;
    source_scan_.reset(); source_scan_document_.reset(); pending_source_row_.reset();
    pending_source_page_navigation_ = false;
    if (source_page_path_ != selected.path) source_line_index_.reset();
    source_page_path_ = selected.path;
    source_line_index_ = excerpt.checkpoint;
    displayed_source_row_ = selected;
    copy_source_location_->Enable(true);
    displayed_context_ = context_address;
    source_full_file_available_ = excerpt.full_file_available;
    std::error_code source_size_error;
    const auto source_size = std::filesystem::file_size(*path, source_size_error);
    source_search_available_ = !source_size_error && source_size <= max_source_search_bytes;
    const auto selected_line = focus_line - 1;
    const auto first = excerpt.first_line - 1;
    const auto last = first + static_cast<std::int64_t>(excerpt.lines.size());
    wxString rendered;
    visible_addresses_.clear();
    visible_lines_.clear();
    rendered_path_ = selected.path;
    rendered_space_ = context_address.space;
    std::vector<std::optional<Address>> line_addresses(static_cast<std::size_t>(last - first));
    const auto path_index = rows_by_path_.find(selected.path);
    if (path_index != rows_by_path_.end()) for (const auto index : path_index->second) {
        const auto &row = rows_[index];
        if (row.path == selected.path && row.address.space == context_address.space && row.line > 0 &&
            row.line - 1 >= first && row.line - 1 < last) {
            auto &target = line_addresses[static_cast<std::size_t>(row.line - 1 - first)];
            if (!target || row.address.offset < target->offset) target = row.address;
        }
    }
    for (auto line = first; line < last; ++line) {
        if (!rendered.empty()) rendered += "\n";
        rendered += wxString::Format("%6lld  ", static_cast<long long>(line + 1));
        const auto &contents = excerpt.lines[static_cast<std::size_t>(line - first)];
        rendered += wxString::FromUTF8(contents.data(), contents.size());
        visible_addresses_.push_back(line_addresses[static_cast<std::size_t>(line - first)]);
        visible_lines_.push_back(line + 1);
    }
    updating_ = true;
    source_->ChangeValue(rendered);
    const auto visible_selected = selected_line - first;
    const long start = source_->XYToPosition(0, static_cast<long>(visible_selected));
    const long length = source_->GetLineLength(static_cast<long>(visible_selected));
    if (start >= 0 && length > 0) {
        source_->SetSelection(start, start + length);
        source_->ShowPosition(start);
    }
    updating_ = false;
    selected_line_addresses_.clear();
    bool line_addresses_truncated = false;
    std::set<std::pair<std::uint64_t, std::uint64_t>> seen_line_addresses;
    if (path_index != rows_by_path_.end()) for (const auto index : path_index->second) {
        const auto &row = rows_[index];
        if (row.path == selected.path && row.address.space == context_address.space && row.line == selected.line) {
            const auto key = std::pair{row.address.space.value, row.address.offset};
            if (seen_line_addresses.contains(key)) continue;
            if (seen_line_addresses.size() == max_line_addresses) {
                line_addresses_truncated = true;
                break;
            }
            seen_line_addresses.insert(key);
            selected_line_addresses_.push_back(row.address);
        }
    }
    selected_line_address_index_ = 0;
    for (std::size_t i = 0; i < selected_line_addresses_.size(); ++i)
        if (selected_line_addresses_[i].space == context_address.space &&
            selected_line_addresses_[i].offset <= context_address.offset)
            selected_line_address_index_ = i;
    update_mapping_controls();
    render_instruction_mappings(selected.path, selected.line, context_address.space);
    status_->SetLabel(display_path(selected.path) + wxString::Format(
        " — line %lld, address 0x%llX, %zu mapped addresses (%zu source-origin rows shown below)",
        static_cast<long long>(selected.line), static_cast<unsigned long long>(selected.address.offset),
        selected_line_addresses_.size(), instruction_mappings_.size()));
    if (instruction_mappings_truncated_)
        status_->SetLabel(status_->GetLabel() + "; mapped rows capped at 4096 distinct source origins");
    if (line_addresses_truncated)
        status_->SetLabel(status_->GetLabel() + "; additional unique addresses omitted by the 4096-address limit");
    if (!selected.scope.empty()) status_->SetLabel(status_->GetLabel() + " / " + text(selected.scope));
    if (!source_full_file_available_)
        status_->SetLabel(status_->GetLabel() + "; editing requires at most 1 MiB");
    if (!source_search_available_)
        status_->SetLabel(status_->GetLabel() + "; full-file search unavailable above 64 MiB");
    if (!visible_lines_.empty())
        status_->SetLabel(status_->GetLabel() + wxString::Format("; page lines %lld–%lld",
            static_cast<long long>(visible_lines_.front()), static_cast<long long>(visible_lines_.back())));
    if (selected_line_addresses_.empty())
        status_->SetLabel(status_->GetLabel() + "; this source line has no mapped machine address");
    update_source_edit_controls();
}

void SourceView::page_source(bool next) {
    if (source_excerpt_running_ || source_load_running_ || source_search_running_ || full_file_display_) {
        status_->SetLabel("Wait for the current source operation to finish before changing pages");
        return;
    }
    if (!document_ || !displayed_source_row_ || rendered_path_.empty() ||
        source_page_path_ != rendered_path_ || !source_line_index_ || visible_lines_.empty()) {
        status_->SetLabel("No indexed source page is available");
        return;
    }
    const auto current_first = visible_lines_.front();
    auto checkpoint = std::make_shared<SourceScanCheckpoint>(*source_line_index_);
    std::int64_t focus_line = 0;
    if (next) {
        if (!checkpoint->pending || checkpoint->offset >= checkpoint->size) {
            status_->SetLabel("End of source file");
            update_mapping_controls();
            return;
        }
        if (checkpoint->line_number <= 0 ||
            checkpoint->line_number > std::numeric_limits<std::int64_t>::max() - context_lines) {
            status_->SetLabel("Next source page line number exceeds the supported range");
            return;
        }
        focus_line = checkpoint->line_number + context_lines;
    } else {
        if (current_first <= 1) {
            status_->SetLabel("Beginning of source file");
            update_mapping_controls();
            return;
        }
        const auto desired_first = std::max<std::int64_t>(1, current_first - (context_lines * 2 + 1));
        if (checkpoint->sparse_line_offsets.empty()) {
            status_->SetLabel("No sparse line checkpoint is available for the previous page");
            return;
        }
        auto start = checkpoint->sparse_line_offsets.begin();
        for (auto candidate = checkpoint->sparse_line_offsets.begin();
             candidate != checkpoint->sparse_line_offsets.end() &&
                 candidate->first <= desired_first; ++candidate)
            start = candidate;
        const auto keep = std::upper_bound(checkpoint->sparse_line_offsets.begin(),
            checkpoint->sparse_line_offsets.end(), start->first,
            [](std::int64_t line, const auto &entry) { return line < entry.first; });
        checkpoint->sparse_line_offsets.erase(keep, checkpoint->sparse_line_offsets.end());
        checkpoint->line_number = start->first;
        checkpoint->offset = start->second;
        if (desired_first > std::numeric_limits<std::int64_t>::max() - context_lines) {
            status_->SetLabel("Previous source page line number exceeds the supported range");
            return;
        }
        focus_line = desired_first + context_lines;
    }
    checkpoint->focus_line = focus_line;
    checkpoint->retained_bytes = 0;
    checkpoint->lines.clear();
    checkpoint->line.clear();
    checkpoint->line_started = false;
    checkpoint->pending = true;
    SourceExcerptRequest request{*displayed_source_row_, displayed_context_, focus_line,
                                 false, true, true, document_, source_revision_stamp(document_),
                                 std::move(checkpoint),
                                 ++source_excerpt_generation_};
    start_source_excerpt(std::move(request));
}

void SourceView::render_instruction_mappings(const std::string &path, std::int64_t line,
                                             AddressSpaceId space) {
    instruction_mappings_.clear();
    instruction_mappings_truncated_ = false;
    if (!document_ || line <= 0) {
        mapped_instructions_->populate(0, [](std::size_t, int) { return wxString{}; });
        return;
    }
    std::vector<SourceRow> origins;
    std::set<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t, std::uint32_t, std::string>> seen_origins;
    bool origins_truncated = false;
    const auto path_index = rows_by_path_.find(path);
    if (path_index != rows_by_path_.end()) for (const auto index : path_index->second) {
        const auto &row = rows_[index];
        if (row.path == path && row.line == line && row.address.space == space) {
            const auto key = std::tuple{row.address.space.value, row.address.offset, row.column,
                                        row.inline_depth, row.scope};
            if (seen_origins.contains(key)) continue;
            if (origins.size() == max_line_origins) { origins_truncated = true; break; }
            seen_origins.insert(key);
            origins.push_back(row);
        }
    }

    const std::vector<Instruction> *analysis_instructions = nullptr;
    const std::vector<std::shared_ptr<const InstructionFact>> *project_instructions = nullptr;
    wxString project_listing_state;
    if (document_->project && document_->project->state) {
        const auto &project = *document_->project;
        if (!project.functions || !project.functions->key)
            project_listing_state = "project analysis unavailable";
        else if (project.functions->key->byte_revision != project.state->revisions.bytes)
            project_listing_state = "stale: project byte revision";
        else if (project.functions->key->decision_revision != project.state->revisions.decisions)
            project_listing_state = "stale: project decision revision";
        else
            project_instructions = &project.functions->instructions;
    } else if (!document_->project && document_->analysis)
        analysis_instructions = &document_->analysis->instructions;

    instruction_mappings_.reserve(origins.size());
    for (const auto &origin : origins) {
        const auto address = origin.address;
        wxString formatted;
        wxString state = "source mapping";
        if (project_instructions) {
            auto found = std::lower_bound(project_instructions->begin(), project_instructions->end(), address,
                [](const auto &fact, Address at) {
                    const auto &current = fact->instruction.address;
                    return current.space.value < at.space.value ||
                           (current.space == at.space && current.offset < at.offset);
                });
            if (found != project_instructions->end() && (*found)->instruction.address == address) {
                formatted = text(format_instruction((*found)->instruction));
                state = "instruction";
            }
        } else if (analysis_instructions) {
            auto found = std::lower_bound(analysis_instructions->begin(), analysis_instructions->end(), address,
                [](const Instruction &instruction, Address at) {
                    const auto current = instruction.address;
                    return current.space.value < at.space.value ||
                           (current.space == at.space && current.offset < at.offset);
                });
            if (found != analysis_instructions->end() && found->address == address) {
                formatted = text(format_instruction(*found));
                state = "instruction";
            }
        }
        if (formatted.empty()) {
            formatted = "No current instruction at this mapped address";
            if (!project_listing_state.empty())
                state = project_listing_state;
            else if (!project_instructions && !analysis_instructions)
                state = "listing unavailable";
        }
        instruction_mappings_.push_back({address, origin.column, origin.inline_depth, origin.scope,
                                         std::move(formatted), std::move(state)});
    }
    mapped_instructions_->populate(instruction_mappings_.size(), [this](std::size_t row, int column) {
        if (row >= instruction_mappings_.size()) return wxString{};
        const auto &item = instruction_mappings_[row];
        switch (column) {
        case 0: return wxString::Format("0x%llX", static_cast<unsigned long long>(item.address.offset));
        case 1: return item.source_column
            ? wxString::Format("%llu", static_cast<unsigned long long>(item.source_column)) : wxString::FromUTF8("—");
        case 2: {
            auto origin = wxString::Format("depth %u", item.inline_depth);
            if (!item.scope.empty()) origin += " / " + wxString::FromUTF8(item.scope.data(), item.scope.size());
            return origin;
        }
        case 3: return item.instruction;
        case 4: return item.state;
        default:
            if (document_ && document_->project && document_->project->state && document_->project->state->user) {
                const auto &saved = document_->project->state->user->breakpoints;
                const auto found = std::find_if(saved.begin(), saved.end(), [&](const auto &bp) {
                    return bp.address == item.address && bp.kind == database::ProjectBreakpointKind::software;
                });
                if (found != saved.end()) return found->enabled ? wxString("Enabled") : wxString("Disabled");
            }
            return wxString("—");
        }
    });
    mapped_instructions_->fit_columns({0, 1, 2, 3, 4, 5});
    instruction_mappings_truncated_ = origins_truncated;
}

void SourceView::select_source_line() {
    if (updating_ || source_editing_ || !navigate || rendered_path_.empty()) return;
    long x = 0, y = 0;
    if (!source_->PositionToXY(source_->GetInsertionPoint(), &x, &y) || y < 0) return;
    const auto line = focused_source_line();
    if (!line) return;
    std::set<std::uint64_t> candidate_offsets;
    const auto path_index = rows_by_path_.find(rendered_path_);
    if (path_index != rows_by_path_.end()) for (const auto index : path_index->second) {
        const auto &row = rows_[index];
        if (row.path == rendered_path_ && rendered_space_ && row.address.space == *rendered_space_ &&
            row.line == *line)
            candidate_offsets.insert(row.address.offset);
    }
    if (!candidate_offsets.empty())
        navigate(Location{Address{*rendered_space_, *candidate_offsets.begin()}});
}

std::optional<std::int64_t> SourceView::focused_source_line() const {
    long x = 0, y = 0;
    if (!source_ || !source_->PositionToXY(source_->GetInsertionPoint(), &x, &y) || y < 0) return {};
    if (full_file_display_) return static_cast<std::int64_t>(y) + 1;
    if (static_cast<std::size_t>(y) >= visible_lines_.size()) return {};
    return visible_lines_[static_cast<std::size_t>(y)];
}

void SourceView::navigate_line_mapping(bool next) {
    if (!navigate || selected_line_addresses_.empty()) return;
    if (next) {
        if (selected_line_address_index_ + 1 >= selected_line_addresses_.size()) return;
        ++selected_line_address_index_;
    } else {
        if (!selected_line_address_index_) return;
        --selected_line_address_index_;
    }
    navigate(Location{selected_line_addresses_[selected_line_address_index_]});
}

void SourceView::copy_source_location() {
    const auto line = focused_source_line();
    if (rendered_path_.empty() || !line) {
        status_->SetLabel("Select a visible source line to copy its location");
        return;
    }
    wxString value = wxString::FromUTF8(rendered_path_.data(), rendered_path_.size()) +
                     wxString::Format(":%lld", static_cast<long long>(*line));
    std::optional<Address> mapped_address;
    if (!full_file_display_) {
        long x = 0, y = 0;
        if (source_->PositionToXY(source_->GetInsertionPoint(), &x, &y) && y >= 0 &&
            static_cast<std::size_t>(y) < visible_addresses_.size())
            mapped_address = visible_addresses_[static_cast<std::size_t>(y)];
    }
    if (!mapped_address && rendered_space_)
        if (const auto path_index = rows_by_path_.find(rendered_path_); path_index != rows_by_path_.end())
        for (const auto index : path_index->second) {
            const auto &row = rows_[index];
            if (row.path == rendered_path_ && row.line == *line && row.address.space == *rendered_space_ &&
                (!mapped_address || row.address.offset < mapped_address->offset)) mapped_address = row.address;
        }
    if (mapped_address) value += wxString::Format(" [space %u: 0x%llX]", mapped_address->space.value,
                                                   static_cast<unsigned long long>(mapped_address->offset));
    if (!wxTheClipboard->Open()) {
        status_->SetLabel("Could not open the system clipboard");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(value));
    wxTheClipboard->Close();
    if (copied)
        status_->SetLabel(wxString("Copied source location: ") + value);
    else
        status_->SetLabel("Could not copy source location");
}

void SourceView::copy_line_map() {
    const auto line = focused_source_line();
    if (rendered_path_.empty() || !rendered_space_ || !line) {
        status_->SetLabel("Select a visible source line with mapped addresses first");
        return;
    }
    constexpr std::size_t byte_limit = 1024u * 1024u;
    std::string output = "source_path\tline\tcolumn\taddress_space\taddress\tinline_depth\tscope\tmapping\tinstruction\r\n";
    const auto escape_field = [](std::string_view value) {
        std::string escaped;
        escaped.reserve(value.size());
        for (const char character : value) {
            switch (character) {
            case '\\': escaped += "\\\\"; break;
            case '\t': escaped += "\\t"; break;
            case '\r': escaped += "\\r"; break;
            case '\n': escaped += "\\n"; break;
            default: escaped.push_back(character); break;
            }
        }
        return escaped;
    };
    const auto path = rendered_path_;
    std::set<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t, std::uint32_t, std::string>> seen;
    std::size_t copied = 0, omitted = 0;
    const auto path_index = rows_by_path_.find(path);
    if (path_index != rows_by_path_.end()) for (const auto index : path_index->second) {
        const auto &row = rows_[index];
        if (row.path != path || row.line != *line || row.address.space != *rendered_space_) continue;
        if (!seen.emplace(row.address.space.value, row.address.offset, row.column, row.inline_depth, row.scope).second) continue;
        if (copied >= max_line_origins) { ++omitted; continue; }
        const auto mapped = std::find_if(instruction_mappings_.begin(), instruction_mappings_.end(),
            [&](const InstructionMapping &item) { return item.address == row.address; });
        const std::string mapping_state = mapped == instruction_mappings_.end()
            ? std::string("source mapping") : escape_field(utf8(mapped->state));
        const std::string instruction = mapped == instruction_mappings_.end()
            ? std::string{} : escape_field(utf8(mapped->instruction));
        std::ostringstream address;
        address << "0x" << std::hex << std::uppercase << row.address.offset;
        std::string record = escape_field(path) + '\t' + std::to_string(*line) + '\t' +
            std::to_string(row.column) + '\t' + std::to_string(row.address.space.value) + '\t' +
            address.str() + '\t' + std::to_string(row.inline_depth) + '\t' + escape_field(row.scope) + '\t' +
            mapping_state + '\t' + instruction + "\r\n";
        if (record.size() > byte_limit - output.size()) {
            ++omitted;
            continue;
        }
        output += record;
        ++copied;
    }
    if (!copied) {
        status_->SetLabel("The focused source line has no mapped addresses");
        return;
    }
    if (!wxTheClipboard->Open()) {
        status_->SetLabel("Could not open the system clipboard");
        return;
    }
    const bool copied_to_clipboard = wxTheClipboard->SetData(new wxTextDataObject(
        wxString::FromUTF8(output.data(), output.size())));
    wxTheClipboard->Close();
    if (copied_to_clipboard) {
        auto message = wxString::Format("Copied %zu source mapping rows", copied);
        if (omitted) message += wxString::Format(" (%zu omitted by output limits)", omitted);
        status_->SetLabel(message + " as TSV");
    } else {
        status_->SetLabel("Could not copy the source line map");
    }
}

void SourceView::copy_source_line() {
    const auto line_number = focused_source_line();
    if (source_editing_ || rendered_path_.empty() || !line_number) {
        status_->SetLabel("Select a visible source line to copy its text");
        return;
    }
    long x = 0, y = 0;
    source_->PositionToXY(source_->GetInsertionPoint(), &x, &y);
    auto line = source_->GetLineText(y);
    if (!full_file_display_) {
        const auto gutter = wxString::Format("%6lld  ", static_cast<long long>(*line_number));
        if (line.StartsWith(gutter)) line.erase(0, gutter.length());
    }
    const auto encoded = line.ToUTF8();
    if (!encoded || encoded.length() > 64u * 1024u) {
        status_->SetLabel("The visible source line exceeds the 64 KiB clipboard limit");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        status_->SetLabel("Could not open the system clipboard");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(line));
    wxTheClipboard->Close();
    status_->SetLabel(copied ? "Copied focused source line text" : "Could not copy source line text");
}

void SourceView::copy_source_excerpt() {
    if (source_editing_ || rendered_path_.empty() || (!full_file_display_ && visible_lines_.empty())) {
        status_->SetLabel("No read-only source excerpt is available to copy");
        return;
    }
    constexpr std::size_t byte_limit = 1024u * 1024u;
    const auto escape_header = [](std::string_view value) {
        static constexpr char digits[] = "0123456789ABCDEF";
        std::string escaped;
        escaped.reserve(value.size());
        for (const unsigned char byte : value) {
            if (byte == '\\') escaped += "\\\\";
            else if (byte == '\t') escaped += "\\t";
            else if (byte == '\r') escaped += "\\r";
            else if (byte == '\n') escaped += "\\n";
            else if (byte < 0x20 || byte == 0x7f) {
                escaped += "\\x";
                escaped.push_back(digits[byte >> 4]);
                escaped.push_back(digits[byte & 0x0f]);
            } else escaped.push_back(static_cast<char>(byte));
        }
        return escaped;
    };
    if (full_file_display_ && static_cast<std::size_t>(source_->GetLastPosition()) > byte_limit) {
        status_->SetLabel("The complete source file exceeds the 1 MiB clipboard limit");
        return;
    }
    const auto contents = source_->GetValue().ToUTF8();
    if (!contents) {
        status_->SetLabel("Could not encode the visible source excerpt as UTF-8");
        return;
    }
    const auto line_count = source_->GetNumberOfLines();
    const auto first_line = full_file_display_ ? 1 : visible_lines_.front();
    const auto last_line = full_file_display_ ? static_cast<std::int64_t>(line_count) : visible_lines_.back();
    std::string output = "Source: " + escape_header(rendered_path_) + "\nLines: " +
        std::to_string(first_line) + "-" + std::to_string(last_line) + "\n\n";
    if (contents.length() > byte_limit || output.size() > byte_limit - contents.length()) {
        status_->SetLabel("The source excerpt exceeds the 1 MiB clipboard limit");
        return;
    }
    output.append(contents.data(), contents.length());
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        status_->SetLabel("Could not open the system clipboard");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(output.data(), output.size())));
    wxTheClipboard->Close();
    status_->SetLabel(copied ? "Copied the displayed source excerpt as UTF-8" :
                               "Could not copy the source excerpt");
}

void SourceView::find_source_text(bool next) {
    if (source_excerpt_running_) {
        status_->SetLabel("Wait for the mapped source excerpt scan to finish before searching");
        return;
    }
    if (source_load_running_) {
        status_->SetLabel("Wait for the full-file source load to finish or cancel it before searching");
        return;
    }
    if (source_search_running_) {
        status_->SetLabel("A source search is already running");
        return;
    }
    const auto query = source_find_->GetValue();
    if (query.empty()) {
        status_->SetLabel("Enter text to find in the source file");
        return;
    }
    if (rendered_path_.empty()) {
        status_->SetLabel("No source file is displayed");
        return;
    }
    auto path = usable_path(rendered_path_);
    if (!path) {
        status_->SetLabel("Source path is unavailable for search");
        return;
    }
    const auto query_utf8 = query.ToUTF8();
    if (!query_utf8) {
        status_->SetLabel("Search text could not be encoded as UTF-8");
        return;
    }
    std::string needle(query_utf8.data(), query_utf8.length());
    const bool ignore_ascii_case = source_find_ignore_case_->GetValue();
    auto query_key = needle;
    if (ignore_ascii_case)
        for (auto &byte : query_key)
            if (byte >= 'A' && byte <= 'Z') byte = static_cast<char>(byte + ('a' - 'A'));
    source_search_query_key_ = (ignore_ascii_case ? "ascii:" : "exact:") + query_key;

    source_search_start_line_ = focused_source_line().value_or(1);
    source_search_cursor_.reset();
    if (source_match_ && source_match_query_ == source_search_query_key_ &&
        source_match_path_ == rendered_path_) {
        source_search_cursor_ = source_match_;
        source_search_start_line_ = source_match_->first;
    }
    source_search_document_ = document_;
    source_search_stamp_ = source_revision_stamp(document_);
    source_search_path_ = rendered_path_;
    source_search_query_ = query;
    source_search_ignore_case_ = ignore_ascii_case;
    source_search_selection_ = selection_address_;
    source_search_stop_ = std::stop_source{};
    const auto stop = source_search_stop_.get_token();
    const auto search_path = *path;
    try {
        source_search_future_ = std::async(std::launch::async,
            [search_path, stop, needle = std::move(needle), ignore_ascii_case, next,
             start_line = source_search_start_line_, cursor = source_search_cursor_]() mutable {
                return search_source_file(search_path, stop, std::move(needle), ignore_ascii_case,
                                          next, start_line, cursor);
            });
    } catch (const std::exception &error) {
        source_search_document_.reset();
        status_->SetLabel("Could not start source search: " + text(error.what()));
        return;
    }
    source_search_running_ = true;
    update_source_edit_controls();
    source_->Enable(false);
    status_->SetLabel("Searching the selected source file in the background (64 MiB cap)...");
    source_search_timer_.Start(35);
}

void SourceView::poll_source_search() {
    if (!source_search_running_ || !source_search_future_.valid() ||
        source_search_future_.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
        return;
    SourceSearchResult result;
    try {
        result = source_search_future_.get();
    } catch (const std::exception &error) {
        result.failure = error.what();
    } catch (...) {
        result.failure = "Unexpected source search worker failure";
    }
    source_search_timer_.Stop();
    const bool stale = document_ != source_search_document_ ||
        source_search_stamp_ != source_revision_stamp(document_) || rendered_path_ != source_search_path_ ||
        source_find_->GetValue() != source_search_query_ ||
        source_find_ignore_case_->GetValue() != source_search_ignore_case_ ||
        selection_address_ != source_search_selection_;
    const auto search_path = source_search_path_;
    const auto query = source_search_query_;
    const auto query_key = source_search_query_key_;
    const auto ignore_ascii_case = source_search_ignore_case_;
    const auto selected_before = source_search_selection_;
    source_search_running_ = false;
    source_search_document_.reset();
    source_search_path_.clear();
    source_search_query_.clear();
    source_search_cursor_.reset();
    source_search_selection_.reset();
    source_->Enable(true);
    update_source_edit_controls();
    if (stale) {
        status_->SetLabel("Source search result discarded because the document or search context changed");
        return;
    }
    if (!result.failure.empty()) {
        status_->SetLabel("Could not search source file: " + text(result.failure));
        return;
    }
    if (!result.found) {
        status_->SetLabel(ignore_ascii_case
            ? "No match after a complete ASCII case-insensitive scan of the source file (search wraps)"
            : "No match after a complete, case-sensitive scan of the source file (search wraps)");
        return;
    }
    const auto mapping = std::find_if(rows_.begin(), rows_.end(), [&](const SourceRow &row) {
        return row.path == search_path && row.line == result.line &&
               (!rendered_space_ || row.address.space == *rendered_space_);
    });
    auto context = selected_before;
    if (!context && mapping != rows_.end()) context = mapping->address;
    SourceRow focus{};
    focus.path = search_path;
    focus.line = result.line;
    source_pending_match_ = SourcePendingMatch{result, query, search_path, query_key,
        source_excerpt_generation_ + 1};
    render_source_row(focus, context.value_or(Address{}), result.line);
}

void SourceView::apply_source_search_match(const SourceExcerptRequest &request) {
    if (!source_pending_match_ || source_pending_match_->generation != request.generation) return;
    const auto pending = std::move(*source_pending_match_);
    source_pending_match_.reset();
    const auto &result = pending.result;
    const auto &query = pending.query;
    const auto &query_key = pending.query_key;
    const auto &search_path = pending.path;
    long line_x = 0, line_y = 0;
    if (!source_->PositionToXY(source_->GetInsertionPoint(), &line_x, &line_y)) line_y = 0;
    const long start = source_->XYToPosition(0, line_y);
    if (start < 0 || start > std::numeric_limits<long>::max() - 8 ||
        result.character_offset > static_cast<std::size_t>(std::numeric_limits<long>::max() - start - 8) ||
        query.length() > std::numeric_limits<long>::max() - start - 8 - static_cast<long>(result.character_offset)) {
        status_->SetLabel("Source match position is too large to display");
        return;
    }
    const auto begin = start + 8 + static_cast<long>(result.character_offset);
    source_->SetSelection(begin, begin + static_cast<long>(query.length()));
    source_->ShowPosition(begin);
    source_->SetFocus();
    source_match_ = std::pair{result.line, result.byte_offset};
    source_match_query_ = query_key;
    source_match_path_ = search_path;
    const auto mapping = std::find_if(rows_.begin(), rows_.end(), [&](const SourceRow &row) {
        return row.path == search_path && row.line == result.line &&
               (!rendered_space_ || row.address.space == *rendered_space_);
    });
    if (mapping != rows_.end()) {
        status_->SetLabel(wxString::Format("Found occurrence %llu of %llu on line %lld; mapped to address space %u at 0x%llX",
            static_cast<unsigned long long>(result.occurrence), static_cast<unsigned long long>(result.total_occurrences),
            static_cast<long long>(result.line), mapping->address.space.value,
            static_cast<unsigned long long>(mapping->address.offset)));
    } else {
        status_->SetLabel(wxString::Format("Found occurrence %llu of %llu on line %lld; no machine address is mapped to this source line",
            static_cast<unsigned long long>(result.occurrence), static_cast<unsigned long long>(result.total_occurrences),
            static_cast<long long>(result.line)));
    }
}

void SourceView::check_source_revision() {
    if (source_revision_running_) {
        source_revision_stop_.request_stop();
        status_->SetLabel("Canceling PDB source revision check...");
        return;
    }
    if (!document_ || rendered_path_.empty()) return;
    const auto found = source_revision_evidence_by_path_.find(rendered_path_);
    if (found == source_revision_evidence_by_path_.end()) {
        status_->SetLabel("No PDB source checksum is available for this file");
        return;
    }
    if (found->second.conflict) {
        status_->SetLabel("PDB source checksums conflict for this path; revision cannot be checked safely");
        return;
    }
    if (found->second.checksum_kind != 3 || found->second.checksum.size() != 32) {
        status_->SetLabel("PDB source checksum is not a supported SHA-256 checksum");
        return;
    }
    const auto row = found->second;
    const auto path = rendered_path_;
    const auto document = document_;
    source_revision_stop_ = std::stop_source{};
    const auto stop = source_revision_stop_.get_token();
    ++source_revision_generation_;
    const auto generation = source_revision_generation_;
    try {
        source_revision_future_ = std::async(std::launch::async,
            [path, checksum = row.checksum, stop]() {
                const auto usable = usable_path(path);
                if (!usable)
                    return SourceRevisionCheckResult{"PDB source revision check unavailable: source path is invalid"};
                return verify_pdb_source_sha256(*usable, checksum, stop);
            });
    } catch (const std::exception &error) {
        status_->SetLabel("Could not start PDB source revision check: " + text(error.what()));
        return;
    }
    source_revision_running_ = true;
    source_revision_document_ = document;
    source_revision_stamp_ = source_revision_stamp(document);
    source_revision_path_ = path;
    source_revision_generation_ = generation;
    status_->SetLabel("Checking the PDB SHA-256 against the source file in the background (64 MiB cap)...");
    update_source_edit_controls();
    source_revision_timer_.Start(35);
}

void SourceView::poll_source_revision() {
    if (!source_revision_running_ || !source_revision_future_.valid() ||
        source_revision_future_.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
        return;
    SourceRevisionCheckResult result;
    try {
        result = source_revision_future_.get();
    } catch (const std::exception &error) {
        result.status = std::string("PDB source revision check failed: ") + error.what();
    } catch (...) {
        result.status = "PDB source revision check failed unexpectedly";
    }
    source_revision_timer_.Stop();
    const bool stale = source_revision_document_ != document_ ||
        source_revision_stamp_ != source_revision_stamp(document_) ||
        source_revision_path_ != rendered_path_;
    source_revision_running_ = false;
    source_revision_document_.reset();
    source_revision_path_.clear();
    update_source_edit_controls();
    if (!stale) status_->SetLabel(text(result.status));
}

void SourceView::update_mapping_controls() {
    const bool has_previous = !selected_line_addresses_.empty() && selected_line_address_index_ > 0;
    const bool has_next = !selected_line_addresses_.empty() &&
                          selected_line_address_index_ + 1 < selected_line_addresses_.size();
    if (previous_mapping_) previous_mapping_->Enable(has_previous);
    if (next_mapping_) next_mapping_->Enable(has_next);
    if (toggle_breakpoint_) toggle_breakpoint_->Enable(!selected_line_addresses_.empty());
    const bool page_context = !source_excerpt_running_ && !source_search_running_ && !source_load_running_ &&
        !source_editing_ && !full_file_display_ && !visible_lines_.empty() && source_line_index_ &&
        source_page_path_ == rendered_path_;
    if (previous_source_page_)
        previous_source_page_->Enable(page_context && visible_lines_.front() > 1);
    if (next_source_page_)
        next_source_page_->Enable(page_context && source_line_index_->pending &&
                                  source_line_index_->offset < source_line_index_->size);
}

void SourceView::load_or_cancel_full_source() {
    if (source_load_running_) {
        source_load_stop_.request_stop();
        status_->SetLabel("Canceling full-file source load...");
        return;
    }
    if (full_file_display_) {
        if (displayed_source_row_)
            render_source_row(*displayed_source_row_, displayed_context_);
        return;
    }
    if (source_editing_ || source_search_running_ || source_excerpt_running_ ||
        rendered_path_.empty() || !source_search_available_) return;
    auto path = usable_path(rendered_path_);
    if (!path) {
        status_->SetLabel("Source path is unavailable for full-file loading");
        return;
    }
    source_load_document_ = document_;
    source_load_stamp_ = source_revision_stamp(document_);
    source_load_path_ = rendered_path_;
    source_load_selection_ = selection_address_;
    source_load_stop_ = std::stop_source{};
    const auto stop = source_load_stop_.get_token();
    const auto load_path = *path;
    try {
        source_load_future_ = std::async(std::launch::async, [load_path, stop] {
            return load_source_file(load_path, stop);
        });
    } catch (const std::exception &error) {
        source_load_document_.reset();
        source_load_path_.clear();
        source_load_selection_.reset();
        status_->SetLabel("Could not start full-file source load: " + text(error.what()));
        return;
    }
    source_load_running_ = true;
    update_source_edit_controls();
    source_->Enable(false);
    status_->SetLabel("Loading and decoding the complete source file in the background (64 MiB cap)...");
    source_load_timer_.Start(35);
}

void SourceView::poll_full_source_load() {
    if (!source_load_running_ || !source_load_future_.valid() ||
        source_load_future_.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
        return;
    SourceFileLoadResult result;
    try {
        result = source_load_future_.get();
    } catch (const std::exception &error) {
        result.failure = error.what();
    } catch (...) {
        result.failure = "Unexpected full-file source load failure";
    }
    source_load_timer_.Stop();
    const bool stale = document_ != source_load_document_ ||
        source_load_stamp_ != source_revision_stamp(document_) || rendered_path_ != source_load_path_ ||
        selection_address_ != source_load_selection_;
    source_load_running_ = false;
    source_load_document_.reset();
    source_load_path_.clear();
    source_load_selection_.reset();
    source_->Enable(true);
    update_source_edit_controls();
    if (stale) return;
    if (!result.failure.empty()) {
        status_->SetLabel("Could not load full source file: " + text(result.failure));
        return;
    }
    const auto content = wxString::FromUTF8(result.utf8_text.data(), result.utf8_text.size());
    if (utf8(content) != result.utf8_text) {
        status_->SetLabel("Source file could not be represented safely by the desktop text control");
        return;
    }
    full_file_display_ = true;
    updating_ = true;
    source_->SetEditable(false);
    source_->ChangeValue(content);
    if (displayed_source_row_ && displayed_source_row_->line > 0 &&
        displayed_source_row_->line <= source_->GetNumberOfLines()) {
        const auto line = static_cast<long>(displayed_source_row_->line - 1);
        const auto start = source_->XYToPosition(0, line);
        const auto length = source_->GetLineLength(line);
        if (start >= 0 && length > 0) {
            source_->SetSelection(start, start + length);
            source_->ShowPosition(start);
        }
    }
    updating_ = false;
    update_source_edit_controls();
    status_->SetLabel(wxString::Format("Loaded complete source file: %s (%zu UTF-8 bytes)",
        display_path(rendered_path_), result.utf8_text.size()));
}

void SourceView::render_unavailable(const wxString &message) {
    if (!finish_source_edit()) return;
    if (source_load_running_) source_load_stop_.request_stop();
    if (source_excerpt_running_) source_excerpt_stop_.request_stop();
    source_excerpt_queued_request_.reset();
    source_pending_match_.reset();
    ++source_excerpt_generation_;
    source_line_index_.reset();
    source_page_path_.clear();
    full_file_display_ = false;
    load_full_source_->SetLabel("Load full file");
    source_scan_.reset(); source_scan_document_.reset(); pending_source_row_.reset();
    pending_source_page_navigation_ = false;
    continue_source_scan_->Enable(false);
    visible_addresses_.clear();
    visible_lines_.clear();
    rendered_path_.clear();
    source_full_file_available_ = false;
    source_search_available_ = false;
    displayed_source_row_.reset();
    copy_source_location_->Enable(false);
    copy_line_map_->Enable(false);
    copy_source_line_->Enable(false);
    rendered_space_.reset();
    selected_line_addresses_.clear();
    selected_line_address_index_ = 0;
    instruction_mappings_.clear();
    mapped_instructions_->populate(0, [](std::size_t, int) { return wxString{}; });
    update_mapping_controls();
    updating_ = true;
    source_->ChangeValue(message);
    source_->SetEditable(false);
    rendered_path_.clear();
    updating_ = false;
    status_->SetLabel(message);
    update_source_edit_controls();
}

void SourceView::update_source_edit_controls() {
    if (!edit_source_) return;
    const bool source_busy = source_search_running_ || source_load_running_ || source_excerpt_running_ || source_revision_running_;
    source_->Enable(!source_busy);
    edit_source_->Enable(!source_editing_ && !source_busy &&
                         !rendered_path_.empty() && source_full_file_available_);
    save_source_->Enable(source_editing_ && source_dirty_);
    discard_source_->Enable(source_editing_);
    edit_source_->SetLabel(source_dirty_ ? "Editing source *" : "Edit source");
    source_filter_->Enable(!source_editing_ && !source_busy);
    source_file_->Enable(!source_editing_ && !source_busy);
    source_find_->Enable(!source_editing_ && !source_busy && source_search_available_);
    source_find_ignore_case_->Enable(!source_editing_ && !source_busy && source_search_available_);
    previous_match_->Enable(!source_editing_ && !source_busy && source_search_available_);
    next_match_->Enable(!source_editing_ && !source_busy && source_search_available_);
    if (load_full_source_) {
        load_full_source_->SetLabel(source_load_running_ ? "Cancel load" :
                                    full_file_display_ ? "Show mapped excerpt" : "Load full file");
        load_full_source_->Enable(source_load_running_ ||
            (!source_editing_ && !source_search_running_ && !source_excerpt_running_ &&
             !rendered_path_.empty() && source_search_available_));
    }
    copy_source_location_->Enable(!source_editing_ && !source_busy && !rendered_path_.empty() && displayed_source_row_.has_value());
    copy_line_map_->Enable(!source_editing_ && !source_busy && !rendered_path_.empty());
    copy_source_line_->Enable(!source_editing_ && !source_busy && !rendered_path_.empty() &&
                              (full_file_display_ || !visible_lines_.empty()));
    copy_source_excerpt_->Enable(!source_editing_ && !source_busy && !rendered_path_.empty() &&
                                 (full_file_display_ || !visible_lines_.empty()));
    if (check_source_revision_) {
        const auto evidence = source_revision_evidence_by_path_.find(rendered_path_);
        const bool supported = evidence != source_revision_evidence_by_path_.end() &&
            !evidence->second.conflict && evidence->second.checksum_kind == 3 &&
            evidence->second.checksum.size() == 32;
        check_source_revision_->SetLabel(source_revision_running_ ? "Cancel revision check" : "Check PDB revision");
        check_source_revision_->Enable(source_revision_running_ || (!source_editing_ && !source_busy && supported));
    }
    if (previous_source_page_)
        previous_source_page_->Enable(!source_busy && !source_editing_ && !full_file_display_ &&
            !visible_lines_.empty() &&
            source_line_index_ && source_page_path_ == rendered_path_ && visible_lines_.front() > 1);
    if (next_source_page_)
        next_source_page_->Enable(!source_busy && !source_editing_ && !full_file_display_ &&
            !visible_lines_.empty() &&
            source_line_index_ && source_page_path_ == rendered_path_ &&
            source_line_index_->pending && source_line_index_->offset < source_line_index_->size);
}

bool SourceView::finish_source_edit() {
    if (!source_editing_) return true;
    if (!source_dirty_) { discard_source_edit(); return true; }
    const int choice = wxMessageBox("Save changes to the source file before continuing?",
        "Unsaved source edits", wxYES_NO | wxCANCEL | wxICON_QUESTION, this);
    if (choice == wxCANCEL) return false;
    if (choice == wxYES) {
        save_source_edit();
        return !source_editing_;
    }
    discard_source_edit();
    return true;
}

void SourceView::begin_source_edit() {
    if (rendered_path_.empty() || source_editing_) return;
    auto path = usable_path(rendered_path_);
    if (!path) return;
    std::string failure;
    auto bytes = read_source(*path, failure);
    if (!failure.empty()) { status_->SetLabel(text(failure)); return; }
    const bool bom = bytes.size() >= 3 && std::to_integer<unsigned char>(bytes[0]) == 0xef &&
        std::to_integer<unsigned char>(bytes[1]) == 0xbb && std::to_integer<unsigned char>(bytes[2]) == 0xbf;
    source_utf16_ = bytes.size() >= 2 &&
        ((std::to_integer<unsigned char>(bytes[0]) == 0xff &&
          std::to_integer<unsigned char>(bytes[1]) == 0xfe) ||
         (std::to_integer<unsigned char>(bytes[0]) == 0xfe &&
          std::to_integer<unsigned char>(bytes[1]) == 0xff));
    source_utf16_little_endian_ = !source_utf16_ || std::to_integer<unsigned char>(bytes[0]) == 0xff;
    const auto decoded = decode_source_text(bytes, failure);
    if (!decoded) { status_->SetLabel(text(failure)); return; }
    const auto candidate = wxString::FromUTF8(decoded->data(), decoded->size());
    if (utf8(candidate) != *decoded) {
        status_->SetLabel("Source is not valid UTF-8 and cannot be edited safely");
        return;
    }
    std::error_code canonical_error;
    editing_path_ = std::filesystem::canonical(*path, canonical_error);
    if (canonical_error) { status_->SetLabel("Source path changed before editing could begin"); return; }
    original_source_bytes_ = std::move(bytes);
    source_utf8_bom_ = bom;
    auto newline_style = inspect_newlines(*decoded);
    source_default_crlf_ = newline_style.default_crlf;
    source_line_endings_crlf_ = std::move(newline_style.line_crlf);
    source_editing_ = true;
    source_dirty_ = false;
    source_->SetEditable(true);
    source_->ChangeValue(candidate);
    source_->SetInsertionPointEnd();
    status_->SetLabel(source_utf16_
        ? (source_utf16_little_endian_ ? "Editing full UTF-16LE source file (1 MiB limit)"
                                       : "Editing full UTF-16BE source file (1 MiB limit)")
        : "Editing full UTF-8 source file (1 MiB limit)");
    update_source_edit_controls();
}

void SourceView::save_source_edit() {
    if (!source_editing_) return;
    std::string failure;
    const auto current = read_source(editing_path_, failure);
    if (!failure.empty() || current != original_source_bytes_) {
        status_->SetLabel("Source changed on disk; edits were not saved. Discard and reopen to review it.");
        return;
    }
    auto content = apply_newlines(utf8(source_->GetValue()),
                                  SourceNewlineStyle{source_line_endings_crlf_, source_default_crlf_});
    std::vector<std::byte> output;
    if (source_utf16_) {
        const auto estimate = content.size() >= max_source_bytes / 2
            ? static_cast<std::size_t>(max_source_bytes) : content.size() * 2 + 2;
        output.reserve(estimate);
        if (source_utf16_little_endian_) {
            output.push_back(std::byte{0xff}); output.push_back(std::byte{0xfe});
        } else {
            output.push_back(std::byte{0xfe}); output.push_back(std::byte{0xff});
        }
        if (!append_utf16(content, source_utf16_little_endian_, output)) {
            status_->SetLabel("Edited source is invalid UTF-8 or exceeds the 1 MiB encoded-file limit");
            return;
        }
    } else {
        const std::size_t prefix = source_utf8_bom_ ? 3 : 0;
        if (content.size() > max_source_bytes - prefix) {
            status_->SetLabel("Edited source exceeds the 1 MiB file limit");
            return;
        }
        output.reserve(content.size() + prefix);
        if (source_utf8_bom_) {
            output.push_back(std::byte{0xef}); output.push_back(std::byte{0xbb}); output.push_back(std::byte{0xbf});
        }
        for (const unsigned char value : content) output.push_back(static_cast<std::byte>(value));
    }
    if (!replace_source_file(editing_path_, output, failure)) {
        status_->SetLabel(text(failure));
        return;
    }
    original_source_bytes_ = std::move(output);
    source_editing_ = false;
    source_dirty_ = false;
    source_->SetEditable(false);
    update_source_edit_controls();
    if (displayed_source_row_) render_source_row(*displayed_source_row_, displayed_context_);
    status_->SetLabel("Source saved");
}

void SourceView::discard_source_edit() {
    if (!source_editing_) return;
    std::string failure;
    const auto bytes = read_source(editing_path_, failure);
    const auto decoded = failure.empty() ? decode_source_text(bytes, failure) : std::nullopt;
    source_editing_ = false;
    source_dirty_ = false;
    source_->SetEditable(false);
    update_source_edit_controls();
    if (decoded && displayed_source_row_)
        render_source_row(*displayed_source_row_, displayed_context_);
    else
        source_->ChangeValue("Source edits discarded; reload failed: " + text(failure));
    if (decoded) status_->SetLabel("Source edits discarded");
    else status_->SetLabel("Source edits discarded; reload failed: " + text(failure));
}
} // namespace hexlab::desktop
