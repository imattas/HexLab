#include "hexlab/loaders/elf.hpp"
#include <algorithm>
#include <map>
#include <set>
#include <string_view>

namespace hexlab {
Result<std::vector<ElfLibraryResolution>> resolve_elf_needed_libraries(
    const LoadedImage &loaded, std::span<const ElfLibraryManifestEntry> manifest,
    std::stop_token stop, ElfLibraryResolutionLimits limits) {
    if (!loaded.metadata.elf)
        return Error{ErrorCode::invalid_argument, "Dependency resolution requires ELF metadata"};
    if (limits.max_needed == 0 || limits.max_manifest_entries == 0 || limits.max_manifest_names == 0 ||
        limits.max_name_bytes == 0)
        return Error{ErrorCode::invalid_argument, "ELF dependency-resolution limits must be positive"};
    if (manifest.size() > limits.max_manifest_entries)
        return Error{ErrorCode::resource_limit, "ELF dependency manifest exceeds entry limit"};
    try {
        std::vector<std::string> needed;
        std::set<std::string, std::less<>> seen;
        for (const auto &table : loaded.metadata.elf->dynamic_tables) {
            for (const auto &entry : table.entries) {
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "ELF dependency resolution canceled"};
                if (entry.tag != 1) // DT_NEEDED
                    continue;
                if (!entry.string_value)
                    return Error{ErrorCode::malformed, "DT_NEEDED entry has no validated string"};
                if (entry.string_value->empty())
                    return Error{ErrorCode::malformed, "DT_NEEDED library name is empty"};
                if (entry.string_value->size() > limits.max_name_bytes)
                    return Error{ErrorCode::resource_limit, "DT_NEEDED library name exceeds limit"};
                if (seen.emplace(*entry.string_value).second) {
                    if (needed.size() == limits.max_needed)
                        return Error{ErrorCode::resource_limit, "ELF dependency count exceeds limit"};
                    needed.push_back(*entry.string_value);
                }
            }
        }

        // Index each manifest spelling once per entry. Repeating an alias in
        // one entry cannot manufacture ambiguity, while two entries claiming
        // the same spelling remain visible as a genuine ambiguous resolution.
        std::map<std::string, std::vector<std::size_t>, std::less<>> owners;
        std::size_t spelling_count = 0;
        for (std::size_t i = 0; i < manifest.size(); ++i) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "ELF dependency resolution canceled"};
            std::set<std::string, std::less<>> names;
            if (manifest[i].library_name.empty() || manifest[i].library_name.size() > limits.max_name_bytes)
                return Error{ErrorCode::invalid_argument, "Manifest library name is empty or exceeds limit"};
            names.insert(manifest[i].library_name);
            for (const auto &alias : manifest[i].aliases) {
                if (alias.empty() || alias.size() > limits.max_name_bytes)
                    return Error{ErrorCode::invalid_argument, "Manifest alias is empty or exceeds limit"};
                names.insert(alias);
            }
            if (names.size() > limits.max_manifest_names - spelling_count)
                return Error{ErrorCode::resource_limit, "ELF dependency manifest exceeds name limit"};
            spelling_count += names.size();
            for (const auto &name : names)
                owners[name].push_back(i);
        }

        std::vector<ElfLibraryResolution> result;
        result.reserve(needed.size());
        for (auto &name : needed) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "ELF dependency resolution canceled"};
            ElfLibraryResolution resolution;
            resolution.needed_name = std::move(name);
            if (const auto it = owners.find(resolution.needed_name); it != owners.end()) {
                resolution.candidates = it->second;
                if (it->second.size() == 1) {
                    resolution.state = ElfLibraryResolutionState::resolved;
                    resolution.manifest_index = it->second.front();
                } else {
                    resolution.state = ElfLibraryResolutionState::ambiguous;
                }
            }
            result.push_back(std::move(resolution));
        }
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate bounded ELF dependency-resolution data"};
    }
}

namespace {
Result<std::string> normalize_elf_path(std::string_view input, std::size_t limit, bool require_absolute) {
    if (input.empty() || input.size() > limit)
        return Error{input.empty() ? ErrorCode::malformed : ErrorCode::resource_limit,
                     "ELF search path is empty or exceeds path-byte limit"};
    if (input.find('\\') != std::string_view::npos || input.find('\0') != std::string_view::npos)
        return Error{ErrorCode::malformed, "ELF search path contains an invalid path separator or NUL"};
    const bool absolute = input.front() == '/';
    if (require_absolute && !absolute)
        return Error{ErrorCode::invalid_argument, "ELF importer and manifest paths must be absolute"};
    std::vector<std::string_view> components;
    std::size_t at = 0;
    while (at <= input.size()) {
        const auto end = input.find('/', at);
        const auto part = input.substr(at, end == std::string_view::npos ? input.size() - at : end - at);
        if (!part.empty() && part != ".") {
            if (part == "..") {
                if (components.empty()) {
                    if (!absolute)
                        components.push_back(part);
                } else if (components.back() == "..") {
                    if (!absolute) components.push_back(part);
                } else {
                    components.pop_back();
                }
            } else {
                components.push_back(part);
            }
        }
        if (end == std::string_view::npos) break;
        at = end + 1;
    }
    std::string result = absolute ? "/" : "";
    for (const auto part : components) {
        if (!result.empty() && result.back() != '/') result.push_back('/');
        result.append(part);
        if (result.size() > limit)
            return Error{ErrorCode::resource_limit, "Normalized ELF search path exceeds path-byte limit"};
    }
    if (result.empty()) result = ".";
    return result;
}

Result<std::vector<std::string>> elf_search_directories(std::string_view value,
                                                         std::string_view origin,
                                                         const ElfLibrarySearchContext &context) {
    std::vector<std::string> result;
    if (value.size() > context.max_path_bytes)
        return Error{ErrorCode::resource_limit, "ELF dynamic search path exceeds path-byte limit"};
    std::size_t at = 0;
    while (at <= value.size()) {
        if (result.size() == context.max_search_entries)
            return Error{ErrorCode::resource_limit, "ELF dynamic search path exceeds entry limit"};
        const auto end = value.find(':', at);
        const auto element = value.substr(at, end == std::string_view::npos ? value.size() - at : end - at);
        if (element.empty())
            return Error{ErrorCode::malformed, "Empty ELF search-path element is unsupported"};
        std::string expanded;
        for (std::size_t i = 0; i < element.size();) {
            if (element[i] != '$') {
                expanded.push_back(element[i++]);
            } else if (element.substr(i, 7) == "$ORIGIN" &&
                       (i + 7 == element.size() || element[i + 7] == '/')) {
                expanded.append(origin);
                i += 7;
            } else if (element.substr(i, 9) == "${ORIGIN}" &&
                       (i + 9 == element.size() || element[i + 9] == '/')) {
                expanded.append(origin);
                i += 9;
            } else {
                return Error{ErrorCode::malformed, "Unsupported or malformed ELF search-path token"};
            }
            if (expanded.size() > context.max_path_bytes)
                return Error{ErrorCode::resource_limit, "Expanded ELF search path exceeds path-byte limit"};
        }
        auto normalized = normalize_elf_path(expanded, context.max_path_bytes, true);
        if (!normalized) return normalized.error();
        result.push_back(std::move(normalized.value()));
        if (end == std::string_view::npos) break;
        at = end + 1;
    }
    return result;
}
} // namespace

Result<std::vector<ElfLibraryResolution>> resolve_elf_needed_libraries(
    const LoadedImage &loaded, std::span<const ElfLibraryManifestEntry> manifest,
    const ElfLibrarySearchContext &context, std::stop_token stop, ElfLibraryResolutionLimits limits) {
    if (context.max_search_entries == 0 || context.max_path_bytes == 0)
        return Error{ErrorCode::invalid_argument, "ELF search-path limits must be positive"};
    auto base = resolve_elf_needed_libraries(loaded, manifest, stop, limits);
    if (!base) return base.error();
    if (!loaded.metadata.elf)
        return Error{ErrorCode::invalid_argument, "Dependency resolution requires ELF metadata"};

    std::optional<std::string> rpath, runpath;
    bool has_rpath = false, has_runpath = false;
    for (const auto &table : loaded.metadata.elf->dynamic_tables) {
        for (const auto &entry : table.entries) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF dependency resolution canceled"};
            if (entry.tag != 15 && entry.tag != 29) continue;
            auto &present = entry.tag == 29 ? has_runpath : has_rpath;
            auto &value = entry.tag == 29 ? runpath : rpath;
            if (present)
                return Error{ErrorCode::malformed, "Multiple ELF RPATH/RUNPATH entries are unsupported"};
            if (!entry.string_value)
                return Error{ErrorCode::malformed, "ELF RPATH/RUNPATH has no validated string"};
            present = true;
            value = *entry.string_value;
        }
    }
    // Search order follows the loader's direct-dependency precedence for the
    // supplied sources: legacy RPATH (when RUNPATH is absent), caller-provided
    // LD_LIBRARY_PATH, then RUNPATH. System cache/default/hwcaps sources are
    // intentionally outside this offline manifest model.
    using SearchList = std::pair<ElfLibrarySearchSource, std::vector<std::string>>;
    std::vector<SearchList> search_lists;
    if (has_rpath && !has_runpath) {
        auto importer = normalize_elf_path(context.importer_path, context.max_path_bytes, true);
        if (!importer) return importer.error();
        const auto slash = importer.value().find_last_of('/');
        const auto origin = slash == 0 ? std::string("/") : importer.value().substr(0, slash);
        auto directories = elf_search_directories(*rpath, origin, context);
        if (!directories) return directories.error();
        search_lists.emplace_back(ElfLibrarySearchSource::rpath, std::move(directories.value()));
    }
    if (context.environment_search_paths.size() > context.max_search_entries)
        return Error{ErrorCode::resource_limit, "ELF environment search path exceeds entry limit"};
    if (!context.environment_search_paths.empty()) {
        std::vector<std::string> directories;
        directories.reserve(context.environment_search_paths.size());
        for (const auto &path : context.environment_search_paths) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "ELF dependency resolution canceled"};
            auto normalized = normalize_elf_path(path, context.max_path_bytes, true);
            if (!normalized) return normalized.error();
            directories.push_back(std::move(normalized.value()));
        }
        search_lists.emplace_back(ElfLibrarySearchSource::environment, std::move(directories));
    }
    if (has_runpath) {
        auto importer = normalize_elf_path(context.importer_path, context.max_path_bytes, true);
        if (!importer) return importer.error();
        const auto slash = importer.value().find_last_of('/');
        const auto origin = slash == 0 ? std::string("/") : importer.value().substr(0, slash);
        auto directories = elf_search_directories(*runpath, origin, context);
        if (!directories) return directories.error();
        search_lists.emplace_back(ElfLibrarySearchSource::runpath, std::move(directories.value()));
    }
    std::size_t total_search_entries = 0;
    for (const auto &[source, directories] : search_lists) {
        (void)source;
        if (directories.size() > context.max_search_entries - total_search_entries)
            return Error{ErrorCode::resource_limit, "ELF combined search paths exceed entry limit"};
        total_search_entries += directories.size();
    }
    if (search_lists.empty())
        return base; // No supplied search policy: retain exact-name behavior.

    std::vector<std::optional<std::string>> candidate_paths;
    candidate_paths.reserve(manifest.size());
    for (const auto &entry : manifest) {
        if (!entry.path) {
            candidate_paths.emplace_back();
            continue;
        }
        auto normalized = normalize_elf_path(*entry.path, context.max_path_bytes, true);
        if (!normalized) return normalized.error();
        candidate_paths.emplace_back(std::move(normalized.value()));
    }

    for (auto &resolution : base.value()) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF dependency resolution canceled"};
        // A slash makes DT_NEEDED a direct pathname request rather than a
        // library-name lookup. Keep the exact manifest result and do not
        // prepend RPATH/RUNPATH directories.
        if (resolution.needed_name.find('/') != std::string::npos)
            continue;
        const auto original = resolution.candidates;
        resolution.state = ElfLibraryResolutionState::missing;
        resolution.manifest_index.reset();
        resolution.candidates.clear();
        for (const auto &[source, directories] : search_lists) {
            resolution.source = source;
            for (const auto &directory : directories) {
                std::vector<std::size_t> matches;
                for (const auto index : original) {
                    if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF dependency resolution canceled"};
                    if (!candidate_paths[index]) continue;
                    const auto candidate_slash = candidate_paths[index]->find_last_of('/');
                    const auto candidate_directory = candidate_slash == 0 ? std::string("/") : candidate_paths[index]->substr(0, candidate_slash);
                    if (candidate_directory == directory) matches.push_back(index);
                }
                if (!matches.empty()) {
                    resolution.matched_directory = directory;
                    resolution.candidates = std::move(matches);
                    if (resolution.candidates.size() == 1) {
                        resolution.state = ElfLibraryResolutionState::resolved;
                        resolution.manifest_index = resolution.candidates.front();
                    } else {
                        resolution.state = ElfLibraryResolutionState::ambiguous;
                    }
                    break;
                }
            }
            if (resolution.state != ElfLibraryResolutionState::missing) break;
        }
    }
    return std::move(base.value());
}
} // namespace hexlab
