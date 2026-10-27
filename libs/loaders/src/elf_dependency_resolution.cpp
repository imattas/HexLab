#include "hexlab/loaders/elf.hpp"
#include <algorithm>
#include <map>
#include <set>

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
} // namespace hexlab
