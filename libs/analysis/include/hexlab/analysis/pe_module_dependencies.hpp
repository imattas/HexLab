#pragma once

#include "hexlab/analysis/analysis_export.hpp"
#include "hexlab/core/result.hpp"
#include "hexlab/image/metadata.hpp"
#include <filesystem>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

namespace hexlab {

enum class PeModuleCompatibility { compatible, not_pe, machine_mismatch, optional_header_mismatch };

// Classifies whether a supplied PE image can provide imports to another PE
// image under the metadata available here. Unknown machine IDs are retained as
// compatible; ARM64EC/ARM64X interop requires additional loader metadata.
HEXLAB_ANALYSIS_EXPORT PeModuleCompatibility classify_pe_module_compatibility(
    const ImageMetadata &importer, const ImageMetadata &provider) noexcept;

enum class PeDependencyPathSource { importer_directory, explicit_directory, windows_system_directory, windows_wow64_system_directory, windows_directory };
enum class PeDependencyTargetBitness { unspecified, pe32, pe32_plus };

struct PeDependencyFileCandidate {
    std::filesystem::path path;
    PeDependencyPathSource source = PeDependencyPathSource::importer_directory;
    std::size_t precedence = 0;
};

struct PeDependencyFileRow {
    std::string name;
    std::vector<PeDependencyFileCandidate> candidates;
    // Lowest candidate precedence containing a file. Additional candidates
    // at this precedence remain ambiguous; later ranks are shadowed in this
    // bounded inventory view.
    std::optional<std::size_t> effective_precedence;
    bool eager_load = false, delay_load = false;
    std::size_t escaped_paths = 0;
    std::size_t filesystem_errors = 0;
};

struct PeDependencyDiscoveryLimits {
    std::size_t dependency_rows = 100000;
    std::size_t dependency_name_bytes = 4 * 1024 * 1024;
    std::size_t search_directories = 128;
    std::size_t directory_entries = 1'000'000;
    std::size_t candidates = 100000;
};

struct PeDependencyFileReport {
    std::vector<PeDependencyFileRow> rows;
    std::size_t directory_entries = 0;
    std::size_t candidates = 0;
    std::size_t dependency_name_bytes = 0;
};

// Enumerates the importer, caller-selected directories, and optionally the
// conventional Windows/System32 and Windows directories inside sysroot.
// Matching uses ASCII case folding (the common portable subset of Windows
// case-insensitive module names). When defaults are enabled, pe32 targets use
// Windows/SysWOW64 if present, falling back to System32; pe32_plus and
// unspecified targets use System32. Candidates are canonical regular files
// contained by sysroot. Precedence ranks preserve importer and explicit
// directory order; Windows defaults are appended after explicit directories.
// This is a bounded inventory and does not model the complete Windows loader.
HEXLAB_ANALYSIS_EXPORT Result<PeDependencyFileReport> discover_pe_dependency_files(
    std::span<const ImportSymbol> imported_symbols,
    const std::filesystem::path &importer,
    const std::filesystem::path &sysroot,
    std::span<const std::filesystem::path> explicit_directories = {},
    const PeDependencyDiscoveryLimits & = {}, std::stop_token = {},
    bool include_windows_defaults = false,
    PeDependencyTargetBitness target_bitness = PeDependencyTargetBitness::unspecified);
HEXLAB_ANALYSIS_EXPORT Result<PeDependencyFileReport> discover_pe_dependency_files(
    std::span<const std::string> imported_modules,
    const std::filesystem::path &importer,
    const std::filesystem::path &sysroot,
    std::span<const std::filesystem::path> explicit_directories = {},
    const PeDependencyDiscoveryLimits & = {}, std::stop_token = {},
    bool include_windows_defaults = false,
    PeDependencyTargetBitness target_bitness = PeDependencyTargetBitness::unspecified);

} // namespace hexlab
