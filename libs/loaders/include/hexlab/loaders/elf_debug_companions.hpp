#pragma once
#include "hexlab/loaders/elf.hpp"

namespace hexlab {
enum class ElfDebugCompanionSource {
    explicit_path, adjacent, adjacent_debug_directory, debug_directory, build_id_directory
};
enum class ElfDebugCompanionStatus {
    missing, not_regular, outside_directory, same_as_primary, io_error, too_large,
    invalid_elf, incompatible_elf, no_debug_metadata, missing_build_id, build_id_mismatch,
    checksum_mismatch, changed_during_read, matched
};
struct ElfDebugCompanionCandidate {
    std::filesystem::path path;
    std::optional<std::filesystem::path> canonical_path;
    ElfDebugCompanionSource source = ElfDebugCompanionSource::explicit_path;
    ElfDebugCompanionStatus status = ElfDebugCompanionStatus::missing;
    std::optional<std::uint64_t> file_size;
    std::optional<Sha256Digest> content_sha256;
    std::vector<std::byte> build_id;
    // Nonempty, file-backed section declarations, not parsed debug payloads.
    bool has_debug_info_sections = false, has_source_line_sections = false, has_static_symbol_tables = false;
    std::string diagnostic;
};
struct ElfDebugCompanionSearch {
    // Only these explicit paths and roots are inspected. No host debug-file
    // directories, environment, network service, or directory tree is read.
    std::vector<std::filesystem::path> candidates;
    std::vector<std::filesystem::path> debug_directories;
    // Optional filesystem root for the target namespace. Global debuglink
    // paths mirror the primary's parent relative to this canonical root.
    std::optional<std::filesystem::path> sysroot;
    std::size_t max_candidates = 128, max_directories = 16;
    std::size_t max_path_bytes = 32768, max_total_path_bytes = 1024 * 1024;
    std::uint64_t max_file_bytes = 512ULL * 1024 * 1024;
    std::uint64_t max_total_file_bytes = 1024ULL * 1024 * 1024;
};
struct ElfDebugCompanionReport {
    std::vector<ElfDebugCompanionCandidate> candidates;
    std::optional<std::size_t> selected;
    std::shared_ptr<const ByteStorage> selected_storage;
    std::uint64_t inspected_file_bytes = 0;
    bool complete = true;
    std::vector<std::string> diagnostics;
};
// Discovers GNU separate-debug companions from adjacent debuglink names and
// explicitly supplied debug roots (mirrored paths and .build-id layout).
// Canonical duplicates are inspected once. Every retained primary identity
// must agree: debuglink CRC and, when present, GNU build ID. More than one
// matched canonical file remains ambiguous. An incomplete search never selects
// a unique file. The returned storage/digest describe discovery-time content;
// consumers must revalidate if they later import from a mutable file.
HEXLAB_LOADERS_EXPORT Result<ElfDebugCompanionReport> discover_elf_debug_companions(
    const ElfMetadata &, const std::filesystem::path &primary_path,
    const ElfDebugCompanionSearch & = {}, std::stop_token = {});
} // namespace hexlab
