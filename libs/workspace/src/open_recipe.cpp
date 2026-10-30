#include "hexlab/workspace/open_recipe.hpp"
#include "hexlab/loaders/x86_raw_profile.hpp"
#include "hexlab/loaders/recipe.hpp"
#include "hexlab/image/file_storage.hpp"
#include "hexlab/loaders/pdb_lines.hpp"
#include "hexlab/loaders/minidump.hpp"
#include <algorithm>
#include <vector>
namespace hexlab {
Result<LoadRecipe> resolve_open_recipe(const OpenRequest &request, std::stop_token stop) {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Opening canceled"};
    if (request.format != Format::automatic && request.format != Format::raw && request.format != Format::pe &&
        request.format != Format::elf && request.format != Format::macho &&
        request.format != Format::intel_hex && request.format != Format::s_record && request.format != Format::wasm && request.format != Format::dex && request.format != Format::jvm && request.format != Format::minidump)
        return Error{ErrorCode::invalid_argument, "Unknown requested input format"};
    if (request.macho && request.format != Format::macho && request.format != Format::automatic)
        return Error{ErrorCode::invalid_argument, "Slice options require Mach-O or automatic input format"};
    if (request.pe_runtime_architecture && request.format != Format::pe && request.format != Format::automatic)
        return Error{ErrorCode::invalid_argument, "PE runtime architecture selection requires PE or automatic input format"};
    if (request.dwarf_supplementary_package_path &&
        (request.format != Format::elf && request.format != Format::automatic))
        return Error{ErrorCode::invalid_argument, "DWARF supplementary packages require ELF or automatic input format"};
    if (request.dwarf_supplementary_package_path &&
        (request.pdb_path || !request.pdb_search_paths.empty()))
        return Error{ErrorCode::invalid_argument, "PE PDB and ELF DWARF supplementary options cannot be combined"};
    if ((request.pdb_path || !request.pdb_search_paths.empty()) && request.format != Format::pe &&
        request.format != Format::minidump && request.format != Format::automatic)
        return Error{ErrorCode::invalid_argument, "Local PDB options require PE, Minidump, or automatic input format"};
    if (request.format != Format::raw) {
        if (request.raw || request.x86_profile_path || request.arm_profile_path)
            return Error{ErrorCode::invalid_argument, "Raw mapping options require explicit raw format"};
        if ((request.format == Format::intel_hex || request.format == Format::s_record) &&
            (request.pdb_path || !request.pdb_search_paths.empty()))
            return Error{ErrorCode::invalid_argument, "Local PDB options require PE, Minidump, or automatic input format"};
        auto recipe = LoadRecipe{request.format, {}, request.macho};
        recipe.pe_runtime_architecture = request.pe_runtime_architecture;
        if (request.dwarf_supplementary_package_path) {
            const auto &path = *request.dwarf_supplementary_package_path;
            if (path.empty() || path.native().find(std::filesystem::path::value_type{}) != path.native().npos)
                return Error{ErrorCode::invalid_argument, "Invalid DWARF supplementary package path"};
            if (request.format == Format::elf) {
                std::error_code error;
                auto absolute = std::filesystem::absolute(path, error);
                if (error) return Error{ErrorCode::io, "Cannot resolve DWARF supplementary package path"};
                recipe.dwarf_supplementary_package_path = absolute.lexically_normal();
            } else {
                std::shared_ptr<const ByteStorage> storage = request.input_storage;
                if (!storage) {
                    auto opened = FileStorage::open(request.path);
                    if (!opened) return opened.error();
                    storage = std::move(opened.value());
                }
                auto detected = resolve_load_recipe(*storage, LoadRecipe{Format::automatic, {}}, stop);
                if (!detected) return detected.error();
                if (detected.value().format != Format::elf)
                    return Error{ErrorCode::invalid_argument, "DWARF supplementary package requires an ELF input"};
                recipe = std::move(detected.value());
                std::error_code error;
                auto absolute = std::filesystem::absolute(path, error);
                if (error) return Error{ErrorCode::io, "Cannot resolve DWARF supplementary package path"};
                recipe.dwarf_supplementary_package_path = absolute.lexically_normal();
            }
        }
        if (request.pdb_path && (request.pdb_path->empty() ||
            request.pdb_path->native().find(std::filesystem::path::value_type{}) != request.pdb_path->native().npos))
            return Error{ErrorCode::invalid_argument, "Invalid local PDB path"};
        if (request.pdb_search_paths.size() > 16)
            return Error{ErrorCode::resource_limit, "At most 16 local PDB search directories are allowed"};
        if (request.format == Format::pe || request.format == Format::automatic) {
            std::shared_ptr<const ByteStorage> storage = request.input_storage;
            if (!storage && !request.path.empty()) {
                auto opened = FileStorage::open(request.path);
                if (opened) storage = opened.value();
            }
            if (storage) {
                auto resolved = resolve_load_recipe(*storage, recipe, stop);
                if (resolved && resolved.value().format == Format::pe) {
                    recipe = resolved.value();
                    recipe.pe_runtime_architecture = request.pe_runtime_architecture;
                    auto pe = load_pe(storage, stop);
                    if (!pe) return pe.error();
                    std::vector<std::filesystem::path> names;
                    if (request.pdb_path) names.push_back(*request.pdb_path);
                    else {
                        for (const auto &identity : pe.value().metadata.pe->codeview) {
                            if (names.size() >= 32) break;
                            auto normalized = identity.path;
                            std::replace(normalized.begin(), normalized.end(), '\\', '/');
                            auto leaf = std::filesystem::path(normalized).filename();
                            if (!leaf.empty()) names.push_back(leaf);
                        }
                        if (names.size() < 32) names.push_back(request.path.stem().concat(".pdb"));
                    }
                    std::vector<std::filesystem::path> candidates;
                    if (request.pdb_path) candidates.push_back(*request.pdb_path);
                    else {
                        const auto binary_dir = request.path.parent_path();
                        for (const auto &name : names) candidates.push_back(binary_dir / name);
                        for (const auto &directory : request.pdb_search_paths)
                            for (const auto &name : names) candidates.push_back(directory / name);
                    }
                    std::optional<std::filesystem::path> selected;
                    std::optional<std::filesystem::path> first_existing;
                    for (const auto &candidate : candidates) {
                        std::error_code error;
                        if (std::filesystem::is_regular_file(candidate, error) && !error) {
                            const auto normalized = std::filesystem::absolute(candidate).lexically_normal();
                            if (request.pdb_path) { selected = normalized; break; }
                            if (!first_existing) first_existing = normalized;
                            auto trial = pe.value();
                            auto bound = bind_local_pe_pdb(trial, normalized, stop);
                            if (!bound && bound.error().code == ErrorCode::canceled) return bound.error();
                            if (trial.metadata.pe && trial.metadata.pe->pdb_status == PePdbStatus::matched) {
                                selected = normalized;
                                break;
                            }
                        }
                    }
                    if (!selected) selected = first_existing;
                    if (!selected && !candidates.empty())
                        selected = std::filesystem::absolute(candidates.front()).lexically_normal();
                    recipe.pdb_path = std::move(selected);
                } else if (request.pe_runtime_architecture && resolved &&
                           resolved.value().format != Format::pe) {
                    return Error{ErrorCode::invalid_argument,
                                 "PE runtime architecture selection requires a PE input"};
                }
            }
        }
        if (request.format == Format::minidump || request.format == Format::automatic) {
            std::shared_ptr<const ByteStorage> storage = request.input_storage;
            if (!storage && !request.path.empty()) {
                auto opened = FileStorage::open(request.path);
                if (opened) storage = opened.value();
            }
            if (storage) {
                auto resolved = resolve_load_recipe(*storage, recipe, stop);
                if (resolved && resolved.value().format == Format::minidump) {
                    recipe = std::move(resolved.value());
                    auto loaded = load_minidump(storage, stop);
                    if (!loaded) return loaded.error();
                    std::vector<MinidumpPdbCandidate> candidates;
                    std::vector<std::filesystem::path> paths;
                    bool search_truncated = false;
                    const auto add_candidate = [&](const std::filesystem::path &path) -> Result<bool> {
                        if (path.empty()) return true;
                        std::error_code error;
                        auto absolute = std::filesystem::absolute(path, error);
                        if (error) return true;
                        absolute = absolute.lexically_normal();
                        if (std::find(paths.begin(), paths.end(), absolute) != paths.end()) return true;
                        if (request.pdb_path && path == *request.pdb_path) {
                            paths.insert(paths.begin(), absolute);
                            return true;
                        }
                        if (request.pdb_path) return true;
                        if (std::filesystem::is_regular_file(absolute, error) && !error) {
                            if (paths.size() >= 128) search_truncated = true;
                            else paths.push_back(std::move(absolute));
                        }
                        return true;
                    };
                    if (request.pdb_path) {
                        auto result = add_candidate(*request.pdb_path);
                        if (!result) return result.error();
                    } else {
                        std::vector<std::filesystem::path> directories;
                        if (!request.path.empty()) directories.push_back(request.path.parent_path());
                        directories.insert(directories.end(), request.pdb_search_paths.begin(), request.pdb_search_paths.end());
                        std::vector<std::filesystem::path> names;
                        names.reserve(129);
                        for (const auto &module : loaded.value().metadata.minidump->modules) {
                            if (module.codeview_kind != "RSDS" || module.pdb_path.empty()) continue;
                            if (names.size() >= 128) { search_truncated = true; continue; }
                            std::string path = module.pdb_path;
                            std::replace(path.begin(), path.end(), '\\', '/');
                            const auto leaf = std::filesystem::u8path(path).filename();
                            if (!leaf.empty() && leaf != "." && leaf != "..") names.push_back(leaf);
                        }
                        if (names.size() < 128 && !request.path.empty()) names.push_back(request.path.stem().concat(".pdb"));
                        else if (!request.path.empty()) search_truncated = true;
                        for (const auto &directory : directories) {
                            for (const auto &name : names) {
                                auto result = add_candidate(directory / name);
                                if (!result) return result.error();
                            }
                        }
                    }
                    candidates.reserve(paths.size());
                    for (const auto &path : paths) candidates.push_back({std::nullopt, path});
                    if (!candidates.empty()) {
                        recipe.minidump_pdb_paths = std::move(paths);
                    }
                    recipe.minidump_pdb_search_truncated = search_truncated;
                } else if (request.format == Format::minidump && resolved &&
                           resolved.value().format != Format::minidump) {
                    return Error{ErrorCode::invalid_argument, "Minidump PDB options require a Minidump input"};
                }
            }
        }
        return recipe;
    }
    if (request.pdb_path || !request.pdb_search_paths.empty())
        return Error{ErrorCode::invalid_argument, "Local PDB options require PE, Minidump, or automatic input format"};
    if (unsigned(request.raw.has_value()) + unsigned(request.x86_profile_path.has_value()) +
            unsigned(request.arm_profile_path.has_value()) !=
        1)
        return Error{ErrorCode::invalid_argument, "Raw input requires either flat options or a profile file"};
    try {
        if (request.raw) {
            auto valid = validate_raw_coordinates(*request.raw);
            if (!valid)
                return valid.error();
            return LoadRecipe{Format::raw, request.raw};
        }
        const auto &path = request.arm_profile_path ? *request.arm_profile_path : *request.x86_profile_path;
        if (path.empty() || path.native().find(std::filesystem::path::value_type{}) != path.native().npos)
            return Error{ErrorCode::invalid_argument, "Invalid raw profile path"};
        if (request.arm_profile_path) {
            auto profile = read_arm_profile(path, stop);
            if (!profile)
                return profile.error();
            auto raw = make_arm_raw_options(std::move(profile.value()), stop);
            if (!raw)
                return raw.error();
            return LoadRecipe{Format::raw, std::move(raw.value())};
        }
        auto profile = read_x86_profile(path, stop);
        if (!profile)
            return profile.error();
        auto raw = make_x86_raw_options(profile.value());
        if (!raw)
            return raw.error();
        return LoadRecipe{Format::raw, std::move(raw.value())};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate opening recipe"};
    } catch (const std::filesystem::filesystem_error &error) {
        return Error{ErrorCode::io, error.what()};
    }
}
} // namespace hexlab
