#include "hexlab/analysis/pe_module_dependencies.hpp"
#include <algorithm>
#include <array>
#include <cwctype>
#include <map>
#include <new>
#include <set>
#include <stdexcept>
#include <string_view>

namespace hexlab {
PeModuleCompatibility classify_pe_module_compatibility(
    const ImageMetadata &importer, const ImageMetadata &provider) noexcept {
    const auto is_pe = [](const ImageMetadata &image) {
        return image.format == "PE32" || image.format == "PE32+";
    };
    if (!is_pe(importer) || !is_pe(provider)) return PeModuleCompatibility::not_pe;
    if (importer.machine && provider.machine && importer.machine != provider.machine)
        return PeModuleCompatibility::machine_mismatch;
    if (importer.format != provider.format) return PeModuleCompatibility::optional_header_mismatch;
    return PeModuleCompatibility::compatible;
}

namespace {
bool contained(const std::filesystem::path &path, const std::filesystem::path &root) {
    auto part = path.begin();
    for (const auto &root_part : root) {
        if (part == path.end()) return false;
#ifdef _WIN32
        auto left = part->wstring(), right = root_part.wstring();
        std::transform(left.begin(), left.end(), left.begin(), ::towlower);
        std::transform(right.begin(), right.end(), right.begin(), ::towlower);
        if (left != right) return false;
#else
        if (*part != root_part) return false;
#endif
        ++part;
    }
    return true;
}

bool ascii_leaf(std::string_view name) {
    if (name.empty() || name.size() > 32768 || name == "." || name == "..") return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return c >= 0x21 && c <= 0x7e && c != '/' && c != '\\' && c != ':';
    });
}

std::string folded(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
    });
    return value;
}

std::optional<std::string> ascii_filename(const std::filesystem::path &path) {
    const auto leaf = path.filename();
#ifdef _WIN32
    const auto &native = leaf.native();
    std::string result;
    result.reserve(native.size());
    for (const auto character : native) {
        if (character < 0x21 || character > 0x7e) return {};
        result.push_back(static_cast<char>(character));
    }
#else
    const auto &native = leaf.native();
    if (!std::all_of(native.begin(), native.end(), [](unsigned char c) { return c >= 0x21 && c <= 0x7e; }))
        return {};
    std::string result(native);
#endif
    return result;
}

std::string path_key(const std::filesystem::path &path) {
    const auto encoded = path.generic_u8string();
    std::string result(encoded.begin(), encoded.end());
#ifdef _WIN32
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
    });
#endif
    return result;
}
}

Result<PeDependencyFileReport> discover_pe_dependency_files(
    std::span<const std::string> imported_modules, const std::filesystem::path &importer,
    const std::filesystem::path &sysroot,
    std::span<const std::filesystem::path> explicit_directories,
    const PeDependencyDiscoveryLimits &limits, std::stop_token stop,
    bool include_windows_defaults, PeDependencyTargetBitness target_bitness) {
    try {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "PE dependency discovery canceled"};
        if (imported_modules.size() > limits.dependency_rows ||
            explicit_directories.size() + 1 + (include_windows_defaults ? 2 : 0) > limits.search_directories)
            return Error{ErrorCode::resource_limit, "PE dependency row or directory limit exceeded"};

        std::error_code ec;
        const auto root = std::filesystem::canonical(sysroot, ec);
        if (ec || !std::filesystem::is_directory(root, ec))
            return Error{ErrorCode::invalid_argument, "Dependency sysroot must be an existing directory"};
        const auto source = std::filesystem::canonical(importer, ec);
        if (ec || !contained(source, root) || !std::filesystem::is_regular_file(source, ec))
            return Error{ErrorCode::invalid_argument, "Dependency importer must be a regular file inside sysroot"};

        struct SearchDirectory { std::filesystem::path path; PeDependencyPathSource source; std::size_t precedence; };
        std::vector<SearchDirectory> directories{{source.parent_path(), PeDependencyPathSource::importer_directory, 0}};
        for (const auto &directory : explicit_directories) {
            const auto canonical = std::filesystem::canonical(directory, ec);
            if (ec || !contained(canonical, root) || !std::filesystem::is_directory(canonical, ec))
                return Error{ErrorCode::invalid_argument,
                    "Explicit PE dependency directory is outside sysroot or missing"};
            directories.push_back({canonical, PeDependencyPathSource::explicit_directory, directories.size()});
        }
        if (include_windows_defaults) {
            auto system_directory = root / "Windows" / "System32";
            auto system_source = PeDependencyPathSource::windows_system_directory;
            if (target_bitness == PeDependencyTargetBitness::pe32) {
                const auto wow64 = root / "Windows" / "SysWOW64";
                const auto wow64_canonical = std::filesystem::canonical(wow64, ec);
                if (!ec && contained(wow64_canonical, root) && std::filesystem::is_directory(wow64_canonical, ec)) {
                    system_directory = wow64;
                    system_source = PeDependencyPathSource::windows_wow64_system_directory;
                }
                ec.clear();
            }
            const std::array defaults = {
                std::pair{system_directory, system_source},
                std::pair{root / "Windows", PeDependencyPathSource::windows_directory}
            };
            for (const auto &[path, source_kind] : defaults) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "PE dependency discovery canceled"};
                const auto canonical = std::filesystem::canonical(path, ec);
                if (ec) { ec.clear(); continue; }
                if (!contained(canonical, root) || !std::filesystem::is_directory(canonical, ec)) {
                    ec.clear(); continue;
                }
                const auto key = path_key(canonical);
                if (std::any_of(directories.begin(), directories.end(), [&](const auto &entry) {
                        return path_key(entry.path) == key;
                    })) continue;
                directories.push_back({canonical, source_kind, directories.size()});
            }
        }

        PeDependencyFileReport report;
        std::set<std::string> seen_names;
        std::size_t total_name_bytes = 0;
        for (const auto &name : imported_modules) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "PE dependency discovery canceled"};
            if (!ascii_leaf(name))
                return Error{ErrorCode::invalid_argument, "PE import module must be a bounded ASCII leaf name"};
            if (name.size() > limits.dependency_name_bytes - total_name_bytes)
                return Error{ErrorCode::resource_limit, "PE dependency-name byte limit exceeded"};
            total_name_bytes += name.size();
            const auto folded_name = folded(name);
            if (!seen_names.insert(folded_name).second) continue;
            if (report.rows.size() >= limits.dependency_rows)
                return Error{ErrorCode::resource_limit, "PE dependency row limit exceeded"};
            report.rows.push_back({name});
            auto &row = report.rows.back();
            row.eager_load = true;
            std::set<std::string> seen_paths;
            for (const auto &directory : directories) {
                std::filesystem::directory_iterator it(directory.path, ec), end;
                if (ec) { ++row.filesystem_errors; ec.clear(); continue; }
                std::vector<std::pair<std::string, std::filesystem::path>> matching_paths;
                for (; it != end; it.increment(ec)) {
                    if (stop.stop_requested()) return Error{ErrorCode::canceled, "PE dependency discovery canceled"};
                    if (report.directory_entries >= limits.directory_entries)
                        return Error{ErrorCode::resource_limit, "PE dependency directory-entry limit exceeded"};
                    ++report.directory_entries;
                    if (ec) { ++row.filesystem_errors; ec.clear(); continue; }
                    const auto leaf = ascii_filename(it->path());
                    if (!leaf || folded(*leaf) != folded_name) continue;
                    if (matching_paths.size() >= limits.candidates)
                        return Error{ErrorCode::resource_limit, "PE dependency per-directory match limit exceeded"};
                    matching_paths.emplace_back(*leaf, it->path());
                }
                if (ec) { ++row.filesystem_errors; ec.clear(); }
                // Filesystem iteration order is unspecified. Sort exact ASCII
                // leaf spellings so case-colliding candidates at one search
                // rank have stable output and deduplication order.
                std::sort(matching_paths.begin(), matching_paths.end(), [](const auto &left, const auto &right) {
                    return left.first < right.first;
                });
                for (const auto &[leaf, candidate_path] : matching_paths) {
                    (void)leaf;
                    if (stop.stop_requested()) return Error{ErrorCode::canceled, "PE dependency discovery canceled"};
                    const auto canonical = std::filesystem::canonical(candidate_path, ec);
                    if (ec) { ++row.filesystem_errors; ec.clear(); continue; }
                    if (!contained(canonical, root)) { ++row.escaped_paths; continue; }
                    if (!std::filesystem::is_regular_file(canonical, ec)) {
                        if (ec) ++row.filesystem_errors;
                        ec.clear(); continue;
                    }
                    if (!seen_paths.insert(path_key(canonical)).second) continue;
                    if (report.candidates >= limits.candidates)
                        return Error{ErrorCode::resource_limit, "PE dependency candidate limit exceeded"};
                    ++report.candidates;
                    row.candidates.push_back({canonical, directory.source, directory.precedence});
                }
            }
            if (!row.candidates.empty()) {
                row.effective_precedence = std::min_element(row.candidates.begin(), row.candidates.end(),
                    [](const auto &left, const auto &right) { return left.precedence < right.precedence; })->precedence;
            }
        }
        report.dependency_name_bytes = total_name_bytes;
        return report;
    } catch (const std::filesystem::filesystem_error &error) {
        return Error{ErrorCode::io, std::string("PE dependency filesystem error: ") + error.what()};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate PE dependency discovery report"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "PE dependency discovery exceeds host limits"};
    }
}

Result<PeDependencyFileReport> discover_pe_dependency_files(
    std::span<const ImportSymbol> imported_symbols, const std::filesystem::path &importer,
    const std::filesystem::path &sysroot, std::span<const std::filesystem::path> explicit_directories,
    const PeDependencyDiscoveryLimits &limits, std::stop_token stop, bool include_windows_defaults,
    PeDependencyTargetBitness target_bitness) {
    if (imported_symbols.size() > limits.dependency_rows)
        return Error{ErrorCode::resource_limit, "PE dependency row limit exceeded"};
    std::vector<std::string> names;
    names.reserve(imported_symbols.size());
    for (const auto &symbol : imported_symbols) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "PE dependency discovery canceled"};
        names.push_back(symbol.library);
    }
    auto report = discover_pe_dependency_files(names, importer, sysroot, explicit_directories,
                                               limits, stop, include_windows_defaults, target_bitness);
    if (!report) return report.error();
    std::map<std::string, std::pair<bool, bool>> load_modes;
    for (const auto &symbol : imported_symbols) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "PE dependency discovery canceled"};
        auto &mode = load_modes[folded(symbol.library)];
        mode.first = mode.first || !symbol.delay_load;
        mode.second = mode.second || symbol.delay_load;
    }
    for (auto &row : report.value().rows) {
        const auto mode = load_modes.find(folded(row.name));
        row.eager_load = mode != load_modes.end() && mode->second.first;
        row.delay_load = mode != load_modes.end() && mode->second.second;
    }
    return report;
}

} // namespace hexlab
