#pragma once
#include "hexlab/analysis/analysis_export.hpp"
#include "hexlab/image/elf_metadata.hpp"
#include "hexlab/image/macho_metadata.hpp"
#include <filesystem>
#include <memory>
#include <map>
#include <optional>
#include <stop_token>
#include <span>
#include <string>
#include <vector>

namespace hexlab {
enum class ElfDependencyPathSource {
    needed_path, runpath, rpath, inherited_rpath, explicit_directory, auxiliary_path, filter_path,
    glibc_cache, default_directory, environment_directory
};
struct ElfDependencyFileCandidate {
    std::filesystem::path path;
    ElfDependencyPathSource source = ElfDependencyPathSource::explicit_directory;
    std::optional<std::uint64_t> search_entry_file_offset;
};
struct ElfDependencyFileRow {
    enum class Kind { needed, auxiliary, filter } kind = Kind::needed;
    std::string name;
    std::uint64_t dynamic_entry_file_offset = 0;
    // Compatibility field for pre-kind consumers; zero for auxiliary/filter rows.
    std::uint64_t needed_entry_file_offset = 0;
    std::vector<ElfDependencyFileCandidate> candidates;
    std::size_t unsupported_paths = 0, escaped_paths = 0, filesystem_errors = 0;
};
struct ElfDependencyDiscoveryLimits {
    std::size_t dependency_rows = 100000, metadata_entries = 1000000;
    std::size_t name_bytes = 16 * 1024 * 1024, path_bytes = 16 * 1024 * 1024;
    std::size_t probes = 100000, candidates = 100000, search_directories = 128;
    std::size_t glibc_cache_bytes = 16 * 1024 * 1024, glibc_cache_entries = 100000;
    std::size_t glibc_cache_string_bytes = 16 * 1024 * 1024;
};
struct ElfGlibcCacheEntry {
    std::string name;
    std::filesystem::path path;
    std::uint32_t flags = 0, os_version = 0;
    std::uint64_t hwcap = 0;
};
struct ElfGlibcCacheSnapshot {
    std::filesystem::path sysroot;
    ByteOrder order = ByteOrder::little;
    std::vector<ElfGlibcCacheEntry> entries;
    std::map<std::string, std::vector<std::size_t>, std::less<>> entry_indices_by_name;
    std::size_t bytes = 0, string_bytes = 0, unsupported_formats = 0, unsupported_entries = 0;
    std::size_t filesystem_errors = 0;
};
// Reads only <sysroot>/etc/ld.so.cache after canonical containment checks.
// Unsupported cache formats/records are counted and never interpreted as hits.
HEXLAB_ANALYSIS_EXPORT Result<std::shared_ptr<const ElfGlibcCacheSnapshot>> read_elf_glibc_cache(
    const std::filesystem::path &sysroot, const ElfDependencyDiscoveryLimits & = {}, std::stop_token = {});
// Target-specific path substitutions are explicit because $LIB and $PLATFORM
// vary by target ABI and loader policy. target_working_directory is a host path
// naming a directory inside the supplied sysroot.
struct ElfDependencyPathContext {
    std::optional<std::filesystem::path> target_working_directory;
    std::string lib_token;
    std::string platform_token;
    // Caller-supplied target LD_LIBRARY_PATH entries, represented as host
    // paths beneath the explicit sysroot. The host environment is never read.
    std::vector<std::filesystem::path> environment_directories;
    // Explicit opt-ins. Cache and default sources are rooted beneath the
    // caller's sysroot; the host environment is never consulted.
    bool use_glibc_ld_so_cache = false;
    bool use_standard_default_directories = false;
    // Reuse a caller-preloaded cache while resolving multiple importers. Its
    // sysroot must match the function argument; candidate files are still
    // canonicalized and confined there.
    std::shared_ptr<const ElfGlibcCacheSnapshot> glibc_cache;
    std::vector<ElfDependencyFileCandidate> inherited_rpath;
    // Count of ancestor DT_RPATH entries that could not be interpreted. The
    // count propagates only through inherited RPATH; it is separate from the
    // resolved directory list so descendants can retain partial-search facts.
    std::size_t inherited_unsupported_rpath = 0;
};
struct ElfDependencyFileReport {
    std::vector<ElfDependencyFileRow> rows;
    // DT_RPATH entries declared by this object when it has no DT_RUNPATH;
    // callers pass these to descendants while preserving inherited entries.
    std::vector<ElfDependencyFileCandidate> inherited_rpath;
    // Cumulative unsupported inherited RPATH entries for descendant searches.
    // DT_RUNPATH does not propagate the current object's own unsupported
    // DT_RPATH entries, but ancestor RPATH evidence remains inherited.
    std::size_t inherited_unsupported_rpath = 0;
    std::size_t raw_dependency_rows = 0, metadata_entries = 0, name_bytes = 0;
    std::size_t path_bytes = 0, probes = 0, candidates = 0;
    std::size_t glibc_cache_bytes = 0, glibc_cache_entries = 0;
    std::size_t unsupported_cache_formats = 0, unsupported_cache_entries = 0;
    std::size_t cache_filesystem_errors = 0;
};
// Candidate inventory, not dynamic-loader precedence or execution. Absolute
// ELF paths are rooted in sysroot; ORIGIN paths use the canonical importer.
// Relative paths require an explicit target working directory. LIB/PLATFORM
// expansions use caller-supplied target values. Every retained candidate is a
// canonical regular file inside sysroot; ambiguous matches remain visible.
HEXLAB_ANALYSIS_EXPORT Result<ElfDependencyFileReport> discover_elf_dependency_files(
    const ElfMetadata &, const std::filesystem::path &importer,
    const std::filesystem::path &sysroot,
    std::span<const std::filesystem::path> explicit_directories = {},
    const ElfDependencyDiscoveryLimits & = {}, std::stop_token = {},
    const ElfDependencyPathContext & = {});

enum class MachODependencyPathSource { install_name, loader_path, executable_path, rpath };
struct MachORPathDirectory {
    std::filesystem::path path;
    std::uint64_t command_file_offset = 0;
};
struct MachODependencyPathContext {
    std::optional<std::filesystem::path> executable_path;
    // RPATH entries accumulated from the executable and dependency ancestors,
    // in dyld load order. The current image's entries are appended per report.
    std::vector<MachORPathDirectory> inherited_rpaths;
    std::size_t inherited_unsupported_rpaths = 0;
};
struct MachODependencyFileCandidate {
    std::filesystem::path path;
    MachODependencyPathSource source = MachODependencyPathSource::install_name;
    std::uint32_t load_command_index = 0;
    std::uint64_t load_command_file_offset = 0;
    std::optional<std::uint64_t> rpath_command_file_offset;
};
struct MachODependencyFileRow {
    std::string name;
    std::uint32_t load_command = 0, load_command_index = 0;
    std::uint64_t load_command_file_offset = 0;
    std::vector<MachODependencyFileCandidate> candidates;
    std::size_t unsupported_paths = 0, escaped_paths = 0, filesystem_errors = 0;
};
struct MachODependencyDiscoveryLimits {
    std::size_t dependency_rows = 100000, metadata_entries = 1000000;
    std::size_t name_bytes = 16 * 1024 * 1024, path_bytes = 16 * 1024 * 1024;
    std::size_t probes = 100000, candidates = 100000, rpaths = 128;
};
struct MachODependencyFileReport {
    std::vector<MachODependencyFileRow> rows;
    // Ancestor plus current-image LC_RPATH entries, in load order.
    std::vector<MachORPathDirectory> inherited_rpaths;
    std::size_t inherited_unsupported_rpaths = 0;
    std::size_t metadata_entries = 0, name_bytes = 0, path_bytes = 0;
    std::size_t probes = 0, candidates = 0;
};
// Bounded offline dyld path discovery. Only files whose canonical paths remain
// under the explicit sysroot are retained. The caller supplies the main
// executable path and inherited LC_RPATH context for recursive traversal.
HEXLAB_ANALYSIS_EXPORT Result<MachODependencyFileReport> discover_macho_dependency_files(
    const MachOMetadata &, const std::filesystem::path &importer,
    const std::filesystem::path &sysroot, const MachODependencyPathContext &,
    const MachODependencyDiscoveryLimits & = {}, std::stop_token = {});
}
