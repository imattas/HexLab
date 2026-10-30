#include "hexlab/analysis/module_dependencies.hpp"
#include <algorithm>
#include <cwctype>
#include <limits>
#include <set>
#include <string_view>

namespace hexlab {
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
std::filesystem::path utf8_path(std::string_view text) {
    return std::filesystem::path(std::u8string(text.begin(), text.end()));
}
std::string identity(const std::filesystem::path &path) {
    auto value = path.generic_u8string();
    std::string result(value.begin(), value.end());
#ifdef _WIN32
    auto wide = path.generic_wstring();
    std::transform(wide.begin(), wide.end(), wide.begin(), ::towlower);
    value = std::filesystem::path(wide).generic_u8string();
    result.assign(value.begin(), value.end());
#endif
    return result;
}
}
Result<ElfDependencyFileReport> discover_elf_dependency_files(
    const ElfMetadata &metadata, const std::filesystem::path &importer,
    const std::filesystem::path &sysroot, std::span<const std::filesystem::path> explicit_directories,
    const ElfDependencyDiscoveryLimits &limits, std::stop_token stop,
    const ElfDependencyPathContext &context) {
    try {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF dependency discovery canceled"};
        if (explicit_directories.size() > limits.search_directories)
            return Error{ErrorCode::resource_limit, "ELF dependency search-directory limit exceeded"};
        std::error_code ec;
        const auto root = std::filesystem::canonical(sysroot, ec);
        if (ec || !std::filesystem::is_directory(root, ec))
            return Error{ErrorCode::invalid_argument, "Dependency sysroot must be an existing directory"};
        const auto source = std::filesystem::canonical(importer, ec);
        if (ec || !contained(source, root) || !std::filesystem::is_regular_file(source, ec))
            return Error{ErrorCode::invalid_argument, "Dependency importer must be a regular file inside sysroot"};
        std::optional<std::filesystem::path> target_working_directory;
        if (context.target_working_directory) {
            const auto directory = std::filesystem::canonical(*context.target_working_directory, ec);
            if (ec || !contained(directory, root) || !std::filesystem::is_directory(directory, ec))
                return Error{ErrorCode::invalid_argument,
                             "Target working directory must be an existing directory inside sysroot"};
            target_working_directory = directory;
        }
        const auto valid_token_value = [](std::string_view value) {
            return !value.empty() && value.size() <= 128 &&
                std::all_of(value.begin(), value.end(), [](unsigned char c) {
                    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                           (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '+';
                });
        };
        if ((!context.lib_token.empty() && !valid_token_value(context.lib_token)) ||
            (!context.platform_token.empty() && !valid_token_value(context.platform_token)))
            return Error{ErrorCode::invalid_argument,
                         "ELF $LIB and $PLATFORM substitutions must be bounded path-token values"};
        struct SearchPath {
            std::filesystem::path path;
            ElfDependencyPathSource source;
            std::optional<std::uint64_t> offset;
        };
        ElfDependencyFileReport report;
        std::vector<SearchPath> rpath, runpath, search;
        bool has_runpath = false;
        std::size_t unsupported_rpath = 0, unsupported_runpath = 0;
        const auto offset_of = [](const ElfDynamicTable &table, const ElfDynamicEntry &entry)
            -> std::optional<std::uint64_t> {
            if (!table.stride || table.size > UINT64_MAX - table.source.file_offset ||
                entry.index >= table.size / table.stride ||
                entry.index > (UINT64_MAX - table.source.file_offset) / table.stride) return {};
            return table.source.file_offset + entry.index * table.stride;
        };
        const auto account_name = [&](const std::string &text) {
            if (text.size() > 32768 || text.size() > limits.name_bytes - report.name_bytes) return false;
            report.name_bytes += text.size();
            return true;
        };
        const auto metadata_path = [&](std::string text, bool empty_means_cwd = false)
            -> std::optional<std::filesystem::path> {
            if (text.find('\0') != std::string::npos || text.find('\\') != std::string::npos ||
                text.find(':') != std::string::npos) return {};
            if (text.empty()) return empty_means_cwd ? target_working_directory : std::nullopt;
            // Validate token syntax before substitution. A canonical importer
            // path may itself contain '$'; those bytes are path data and must
            // not be mistaken for another unexpanded dynamic-string token.
            const auto supported_tokens_only = [](std::string_view value) {
                for (std::size_t position = 0; position < value.size();) {
                    if (value[position] != '$') { ++position; continue; }
                    constexpr std::string_view tokens[] = {
                        "$ORIGIN", "${ORIGIN}", "$LIB", "${LIB}", "$PLATFORM", "${PLATFORM}"
                    };
                    bool matched = false;
                    for (const auto token : tokens) {
                        if (value.substr(position).starts_with(token)) {
                            position += token.size();
                            matched = true;
                            break;
                        }
                    }
                    if (!matched) return false;
                }
                return true;
            };
            if (!supported_tokens_only(text)) return {};
            bool uses_origin = false;
            const auto replace_token = [&](std::string_view short_form, std::string_view long_form,
                                           std::string_view value) -> bool {
                for (const auto form : {short_form, long_form}) {
                    std::size_t position = 0;
                    while ((position = text.find(form, position)) != std::string::npos) {
                        if (value.empty()) return false;
                        text.replace(position, form.size(), value);
                        position += value.size();
                    }
                }
                return true;
            };
            const auto origin_path = source.parent_path().generic_u8string();
            const std::string origin(reinterpret_cast<const char *>(origin_path.data()), origin_path.size());
            uses_origin = text.find("$ORIGIN") != std::string::npos || text.find("${ORIGIN}") != std::string::npos;
            if (!replace_token("$LIB", "${LIB}", context.lib_token) ||
                !replace_token("$PLATFORM", "${PLATFORM}", context.platform_token) ||
                !replace_token("$ORIGIN", "${ORIGIN}", origin)) return {};
            const auto expanded = utf8_path(text);
            if (expanded.is_absolute()) {
                if (uses_origin) return expanded;
                return root / expanded.relative_path();
            }
            if (target_working_directory) return *target_working_directory / expanded;
            return {};
        };
        for (const auto &table : metadata.dynamic_tables) {
            for (const auto &entry : table.entries) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF dependency discovery canceled"};
                if (report.metadata_entries++ >= limits.metadata_entries)
                    return Error{ErrorCode::resource_limit, "ELF dependency metadata-entry limit exceeded"};
                constexpr std::uint64_t dt_auxiliary = 0x7ffffffd;
                constexpr std::uint64_t dt_filter = 0x7fffffff;
                if (entry.tag != 1 && entry.tag != 15 && entry.tag != 29 &&
                    entry.tag != dt_auxiliary && entry.tag != dt_filter) continue;
                if (!entry.string_value)
                    return Error{ErrorCode::malformed, "ELF dependency metadata is missing its string"};
                if (!account_name(*entry.string_value))
                    return Error{ErrorCode::resource_limit, "ELF dependency string exceeds its byte limit"};
                const auto offset = offset_of(table, entry);
                if (!offset) return Error{ErrorCode::malformed, "ELF dependency entry provenance overflows"};
                const auto &text = *entry.string_value;
                if (entry.tag == 1 || entry.tag == dt_auxiliary || entry.tag == dt_filter) {
                    if (report.raw_dependency_rows++ >= limits.dependency_rows)
                        return Error{ErrorCode::resource_limit, "ELF dependency row limit exceeded"};
                    // Preserve every declaration and its own source offset.
                    // Repeated names may be significant evidence in malformed
                    // or hand-authored dynamic tables.
                    ElfDependencyFileRow row;
                    row.kind = entry.tag == dt_auxiliary ? ElfDependencyFileRow::Kind::auxiliary
                              : entry.tag == dt_filter ? ElfDependencyFileRow::Kind::filter
                                                       : ElfDependencyFileRow::Kind::needed;
                    row.name = text;
                    row.dynamic_entry_file_offset = *offset;
                    if (row.kind == ElfDependencyFileRow::Kind::needed)
                        row.needed_entry_file_offset = *offset;
                    report.rows.push_back(std::move(row));
                } else {
                    if (entry.tag == 29) has_runpath = true;
                    auto &paths = entry.tag == 29 ? runpath : rpath;
                    for (std::size_t begin = 0;;) {
                        const auto end = text.find(':', begin);
                        const auto part = text.substr(begin, end == std::string::npos ? end : end - begin);
                        if (paths.size() >= limits.search_directories)
                            return Error{ErrorCode::resource_limit, "ELF dynamic search-directory limit exceeded"};
                        if (auto path = metadata_path(part, true))
                            paths.push_back({*path, entry.tag == 29 ? ElfDependencyPathSource::runpath
                                                                  : ElfDependencyPathSource::rpath, offset});
                        else ++(entry.tag == 29 ? unsupported_runpath : unsupported_rpath);
                        if (end == std::string::npos) break;
                        begin = end + 1;
                    }
                }
            }
        }
        if (!has_runpath) {
            report.inherited_rpath.reserve(rpath.size());
            for (const auto &directory : rpath)
                report.inherited_rpath.push_back({directory.path, ElfDependencyPathSource::rpath, directory.offset});
        }
        const auto applicable_unsupported = has_runpath ? unsupported_runpath : unsupported_rpath;
        const auto inherited_local_unsupported = has_runpath ? std::size_t{} : unsupported_rpath;
        const auto max_count = (std::numeric_limits<std::size_t>::max)();
        if (context.inherited_unsupported_rpath > max_count - applicable_unsupported ||
            context.inherited_unsupported_rpath > max_count - inherited_local_unsupported)
            return Error{ErrorCode::resource_limit, "ELF inherited unsupported-path count overflow"};
        report.inherited_unsupported_rpath = context.inherited_unsupported_rpath + inherited_local_unsupported;
        search = has_runpath ? std::move(runpath) : std::move(rpath);
        for (const auto &directory : context.inherited_rpath) {
            if (search.size() >= limits.search_directories)
                return Error{ErrorCode::resource_limit, "ELF combined search-directory limit exceeded"};
            if (!directory.path.is_absolute() || !contained(directory.path.lexically_normal(), root))
                return Error{ErrorCode::invalid_argument,
                             "Inherited DT_RPATH directories must remain inside the sysroot"};
            search.push_back({directory.path, ElfDependencyPathSource::inherited_rpath,
                              directory.search_entry_file_offset});
        }
        for (const auto &directory : explicit_directories) {
            if (search.size() >= limits.search_directories)
                return Error{ErrorCode::resource_limit, "ELF combined search-directory limit exceeded"};
            auto canonical = std::filesystem::canonical(directory, ec);
            if (ec || !contained(canonical, root) || !std::filesystem::is_directory(canonical, ec))
                return Error{ErrorCode::invalid_argument, "Explicit dependency search directory is outside sysroot or missing"};
            search.push_back({canonical, ElfDependencyPathSource::explicit_directory, {}});
        }
        for (auto &row : report.rows) {
            const bool uses_search_path = !row.name.empty() &&
                row.name.find('/') == std::string::npos && row.name.find('$') == std::string::npos;
            row.unsupported_paths = uses_search_path
                ? applicable_unsupported + context.inherited_unsupported_rpath : 0;
            std::vector<SearchPath> paths;
            if (row.name.find('/') != std::string::npos || row.name.find('$') != std::string::npos) {
                const auto source = row.kind == ElfDependencyFileRow::Kind::auxiliary
                    ? ElfDependencyPathSource::auxiliary_path
                    : row.kind == ElfDependencyFileRow::Kind::filter ? ElfDependencyPathSource::filter_path
                                                                      : ElfDependencyPathSource::needed_path;
                if (auto path = metadata_path(row.name)) paths.push_back({*path, source, {}});
                else ++row.unsupported_paths;
            } else if (row.name.empty() || row.name.find('\\') != std::string::npos ||
                       row.name.find(':') != std::string::npos || row.name.find('\0') != std::string::npos) {
                ++row.unsupported_paths;
            } else {
                for (const auto &directory : search) {
                    auto candidate = directory;
                    candidate.path /= utf8_path(row.name);
                    paths.push_back(std::move(candidate));
                }
            }
            std::set<std::string> seen;
            for (const auto &candidate : paths) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF dependency discovery canceled"};
                if (report.probes++ >= limits.probes)
                    return Error{ErrorCode::resource_limit, "ELF dependency path-probe limit exceeded"};
                const auto canonical = std::filesystem::canonical(candidate.path, ec);
                if (ec) {
                    if (ec != std::errc::no_such_file_or_directory && ec != std::errc::not_a_directory)
                        ++row.filesystem_errors;
                    ec.clear(); continue;
                }
                if (!contained(canonical, root)) { ++row.escaped_paths; continue; }
                if (!std::filesystem::is_regular_file(canonical, ec)) {
                    if (ec) ++row.filesystem_errors;
                    ec.clear(); continue;
                }
                const auto key = identity(canonical);
                if (!seen.insert(key).second) continue;
                if (report.candidates >= limits.candidates || key.size() > limits.path_bytes - report.path_bytes)
                    return Error{ErrorCode::resource_limit, "ELF dependency candidate/path-byte limit exceeded"};
                ++report.candidates;
                report.path_bytes += key.size();
                row.candidates.push_back({canonical, candidate.source, candidate.offset});
            }
        }
        return report;
    } catch (const std::filesystem::filesystem_error &error) {
        return Error{ErrorCode::io, std::string("ELF dependency filesystem error: ") + error.what()};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate ELF dependency discovery report"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "ELF dependency discovery exceeds host limits"};
    }
}

Result<MachODependencyFileReport> discover_macho_dependency_files(
    const MachOMetadata &metadata, const std::filesystem::path &importer,
    const std::filesystem::path &sysroot, const MachODependencyPathContext &context,
    const MachODependencyDiscoveryLimits &limits, std::stop_token stop) {
    try {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Mach-O dependency discovery canceled"};
        std::error_code ec;
        const auto root = std::filesystem::canonical(sysroot, ec);
        if (ec || !std::filesystem::is_directory(root, ec))
            return Error{ErrorCode::invalid_argument, "Dependency sysroot must be an existing directory"};
        const auto source = std::filesystem::canonical(importer, ec);
        if (ec || !contained(source, root) || !std::filesystem::is_regular_file(source, ec))
            return Error{ErrorCode::invalid_argument, "Mach-O importer must be a regular file inside sysroot"};
        std::optional<std::filesystem::path> executable;
        if (context.executable_path) {
            executable = std::filesystem::canonical(*context.executable_path, ec);
            if (ec || !contained(*executable, root) || !std::filesystem::is_regular_file(*executable, ec))
                return Error{ErrorCode::invalid_argument, "Mach-O executable must be a regular file inside sysroot"};
        }
        if (context.inherited_rpaths.size() > limits.rpaths)
            return Error{ErrorCode::resource_limit, "Mach-O inherited LC_RPATH limit exceeded"};
        if (context.inherited_unsupported_rpaths > limits.rpaths - context.inherited_rpaths.size())
            return Error{ErrorCode::resource_limit, "Mach-O inherited LC_RPATH limit exceeded"};
        for (const auto &rpath : context.inherited_rpaths)
            if (!rpath.path.is_absolute() || !contained(rpath.path.lexically_normal(), root))
                return Error{ErrorCode::invalid_argument, "Inherited Mach-O LC_RPATH escapes the sysroot"};

        constexpr std::uint32_t lc_load_dylib = 0x0000000c;
        constexpr std::uint32_t lc_load_weak_dylib = 0x80000018;
        constexpr std::uint32_t lc_reexport_dylib = 0x8000001f;
        constexpr std::uint32_t lc_load_upward_dylib = 0x80000023;
        constexpr std::uint32_t lc_rpath = 0x8000001c;
        MachODependencyFileReport report;
        report.inherited_rpaths = context.inherited_rpaths;
        report.inherited_unsupported_rpaths = context.inherited_unsupported_rpaths;
        std::size_t own_unsupported_rpaths = 0;
        const auto append_checked = [&](std::string_view text, std::size_t &counter, std::size_t cap) {
            if (text.size() > 32768 || text.size() > cap - counter) return false;
            counter += text.size();
            return true;
        };
        struct ExpandedPath { std::filesystem::path path; MachODependencyPathSource source; };
        const auto expand_path = [&](std::string_view text, bool allow_rpath,
                                     MachODependencyPathSource &path_source)
            -> std::optional<std::filesystem::path> {
            if (text.empty() || text.size() > 32768 || text.find('\0') != std::string_view::npos ||
                text.find('\\') != std::string_view::npos) return {};
            const auto replace_prefix = [&](std::string_view token, const std::filesystem::path &base,
                                            MachODependencyPathSource source_kind)
                -> std::optional<std::filesystem::path> {
                if (text != token && !(text.size() > token.size() && text.starts_with(token) &&
                                       text[token.size()] == '/')) return {};
                if (!base.is_absolute()) return {};
                auto suffix = text.size() == token.size() ? std::filesystem::path{} : utf8_path(text.substr(token.size() + 1));
                if (suffix.is_absolute()) return {};
                path_source = source_kind;
                return (base / suffix).lexically_normal();
            };
            if (text.starts_with("@loader_path"))
                return replace_prefix("@loader_path", source.parent_path(), MachODependencyPathSource::loader_path);
            if (text.starts_with("@executable_path")) {
                if (!executable) return {};
                return replace_prefix("@executable_path", executable->parent_path(), MachODependencyPathSource::executable_path);
            }
            if (text.starts_with("@rpath/")) {
                if (!allow_rpath) return {};
                return {};
            }
            if (text.front() == '@') return {};
            if (text.front() == '/') {
                path_source = MachODependencyPathSource::install_name;
                return (root / utf8_path(text).relative_path()).lexically_normal();
            }
            // Plain relative LC_RPATH values have process-CWD semantics which
            // are not guessed. Ordinary non-token install names are rooted in
            // the explicit sysroot as an offline image path.
            if (allow_rpath) return {};
            path_source = MachODependencyPathSource::install_name;
            return (root / utf8_path(text)).lexically_normal();
        };

        std::vector<MachORPathDirectory> own_rpaths;
        for (const auto &path : metadata.paths) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Mach-O dependency discovery canceled"};
            if (report.metadata_entries++ >= limits.metadata_entries)
                return Error{ErrorCode::resource_limit, "Mach-O dependency metadata-entry limit exceeded"};
            if (path.command != lc_rpath) continue;
            if (!append_checked(path.name, report.name_bytes, limits.name_bytes))
                return Error{ErrorCode::resource_limit, "Mach-O dependency-name byte limit exceeded"};
            if (own_rpaths.size() + context.inherited_rpaths.size() >= limits.rpaths)
                return Error{ErrorCode::resource_limit, "Mach-O LC_RPATH limit exceeded"};
            MachODependencyPathSource kind = MachODependencyPathSource::install_name;
            auto expanded = expand_path(path.name, false, kind);
            if (!expanded) { ++own_unsupported_rpaths; continue; }
            if (!expanded->is_absolute() || !contained(expanded->lexically_normal(), root)) {
                ++own_unsupported_rpaths;
                continue;
            }
            own_rpaths.push_back({*expanded, path.record_file_offset});
        }
        const auto max_count = (std::numeric_limits<std::size_t>::max)();
        if (report.inherited_unsupported_rpaths > max_count - own_unsupported_rpaths)
            return Error{ErrorCode::resource_limit, "Mach-O inherited unsupported-path count overflow"};
        report.inherited_unsupported_rpaths += own_unsupported_rpaths;
        report.inherited_rpaths.insert(report.inherited_rpaths.end(), own_rpaths.begin(), own_rpaths.end());

        for (const auto &library : metadata.libraries) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Mach-O dependency discovery canceled"};
            if (report.metadata_entries++ >= limits.metadata_entries)
                return Error{ErrorCode::resource_limit, "Mach-O dependency metadata-entry limit exceeded"};
            if (library.command != lc_load_dylib && library.command != lc_load_weak_dylib &&
                library.command != lc_reexport_dylib && library.command != lc_load_upward_dylib) continue;
            if (report.rows.size() >= limits.dependency_rows)
                return Error{ErrorCode::resource_limit, "Mach-O dependency row limit exceeded"};
            if (!append_checked(library.name, report.name_bytes, limits.name_bytes))
                return Error{ErrorCode::resource_limit, "Mach-O dependency-name byte limit exceeded"};
            MachODependencyFileRow row{library.name, library.command, library.command_index,
                                       library.record_file_offset};
            const auto name = std::string_view(library.name);
            if (name.starts_with("@rpath/")) {
                const auto suffix = utf8_path(name.substr(7));
                if (suffix.empty() || suffix.is_absolute() || report.inherited_rpaths.empty()) {
                    row.unsupported_paths += report.inherited_unsupported_rpaths + 1;
                } else {
                    row.unsupported_paths += report.inherited_unsupported_rpaths;
                    for (const auto &rpath : report.inherited_rpaths) {
                        if (row.candidates.size() >= limits.rpaths)
                            return Error{ErrorCode::resource_limit, "Mach-O per-import LC_RPATH probe limit exceeded"};
                        row.candidates.push_back({(rpath.path / suffix).lexically_normal(),
                            MachODependencyPathSource::rpath, library.command_index,
                            library.record_file_offset, rpath.command_file_offset});
                    }
                }
            } else {
                MachODependencyPathSource kind = MachODependencyPathSource::install_name;
                auto expanded = expand_path(name, false, kind);
                if (!expanded) ++row.unsupported_paths;
                else row.candidates.push_back({*expanded, kind, library.command_index,
                                               library.record_file_offset, {}});
            }
            // Canonicalize each exact candidate, retaining only regular files
            // inside the explicit root. No directory scan or host fallback is used.
            std::vector<MachODependencyFileCandidate> retained;
            std::set<std::string> seen;
            for (auto candidate : row.candidates) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Mach-O dependency discovery canceled"};
                if (!contained(candidate.path.lexically_normal(), root)) {
                    ++row.escaped_paths;
                    continue;
                }
                if (report.probes++ >= limits.probes)
                    return Error{ErrorCode::resource_limit, "Mach-O dependency path-probe limit exceeded"};
                const auto canonical = std::filesystem::canonical(candidate.path, ec);
                if (ec) {
                    if (ec != std::errc::no_such_file_or_directory && ec != std::errc::not_a_directory)
                        ++row.filesystem_errors;
                    ec.clear();
                    continue;
                }
                if (!contained(canonical, root)) { ++row.escaped_paths; continue; }
                if (!std::filesystem::is_regular_file(canonical, ec)) {
                    if (ec) ++row.filesystem_errors;
                    ec.clear();
                    continue;
                }
                const auto key = identity(canonical);
                if (!seen.insert(key).second) continue;
                if (report.candidates >= limits.candidates || key.size() > limits.path_bytes - report.path_bytes)
                    return Error{ErrorCode::resource_limit, "Mach-O dependency candidate/path-byte limit exceeded"};
                ++report.candidates;
                report.path_bytes += key.size();
                candidate.path = canonical;
                retained.push_back(std::move(candidate));
            }
            row.candidates = std::move(retained);
            report.rows.push_back(std::move(row));
        }
        return report;
    } catch (const std::filesystem::filesystem_error &error) {
        return Error{ErrorCode::io, std::string("Mach-O dependency filesystem error: ") + error.what()};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate Mach-O dependency discovery report"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Mach-O dependency discovery exceeds host limits"};
    }
}
}
