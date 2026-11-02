#include "elf_internal.hpp"
#include "hexlab/loaders/elf_debug_companions.hpp"
#include "hexlab/image/file_storage.hpp"
#include <algorithm>
#include <set>

namespace hexlab {
namespace {
bool contained(const std::filesystem::path &path, const std::filesystem::path &root) {
    auto p = path.begin();
    for (auto r = root.begin(); r != root.end(); ++r, ++p)
        if (p == path.end() || *p != *r) return false;
    return true;
}
std::string hex_id(std::span<const std::byte> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        const auto value = std::to_integer<unsigned>(byte);
        result.push_back(digits[value >> 4]);
        result.push_back(digits[value & 15]);
    }
    return result;
}
bool safe_altlink_relative_name(std::string_view name) {
    if (name.empty() || name.find_first_of(":\0", 0, 2) != std::string_view::npos ||
        name.front() == '/' || name.front() == '\\') return false;
    std::size_t begin = 0;
    while (begin < name.size()) {
        const auto end = name.find_first_of("/\\", begin);
        const auto length = (end == std::string_view::npos ? name.size() : end) - begin;
        const auto component = name.substr(begin, length);
        if (component.empty() || component == "." || component == "..") return false;
        if (end == std::string_view::npos) return true;
        begin = end + 1;
    }
    return false;
}
Result<std::vector<std::byte>> unique_build_id(const ElfMetadata &metadata, std::stop_token stop) {
    if (metadata.gnu_build_ids.size() > 4096)
        return Error{ErrorCode::resource_limit, "ELF debug-companion identity exceeds 4096 build-ID notes"};
    std::vector<std::byte> result;
    for (const auto &id : metadata.gnu_build_ids) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF debug-companion discovery canceled"};
        if (id.identifier.empty() || id.identifier.size() > 64)
            return Error{ErrorCode::unsupported, "GNU build ID must contain 1 through 64 bytes for companion discovery"};
        if (!result.empty() && result != id.identifier)
            return Error{ErrorCode::conflict, "ELF has conflicting GNU build IDs"};
        result = id.identifier;
    }
    return result;
}
struct Probe {
    std::filesystem::path path;
    std::optional<std::filesystem::path> root;
    ElfDebugCompanionSource source;
};
} // namespace

static Result<ElfDebugCompanionReport> discover_elf_debug_companions_impl(
    const ElfMetadata &primary, const std::filesystem::path &primary_path,
    const ElfDebugCompanionSearch &options, std::stop_token stop,
    std::optional<std::vector<std::byte>> identity_override = {},
    std::optional<std::string> filename_override = {}, bool altlink = false) {
    using namespace elf_detail;
    try {
        canceled(stop);
        require(options.max_candidates && options.max_candidates <= 4096 && options.max_directories &&
                options.max_directories <= 128 && options.max_path_bytes && options.max_total_path_bytes &&
                options.max_file_bytes && options.max_total_file_bytes,
                "Invalid ELF debug-companion discovery limits", ErrorCode::invalid_argument);
        require(options.candidates.size() <= options.max_candidates &&
                options.debug_directories.size() <= options.max_directories,
                "ELF debug-companion search exceeds candidate or directory count limit", ErrorCode::resource_limit);
        require(primary.header.object_type == 2 || primary.header.object_type == 3,
                "Separate-debug companion discovery requires an ELF executable or shared object",
                ErrorCode::unsupported);
        ElfDebugCompanionReport result;
        const auto build_id = identity_override ? std::move(*identity_override) : take(unique_build_id(primary, stop));
        require(primary.gnu_debug_links.size() <= 4096,
                "ELF debug-companion identity exceeds 4096 debuglinks", ErrorCode::resource_limit);
        const ElfGnuDebugLink *link = nullptr;
        for (const auto &value : primary.gnu_debug_links) {
            if (altlink) break;
            canceled(stop);
            require(value.filename.size() <= options.max_path_bytes,
                    "GNU debuglink filename exceeds path-byte limit", ErrorCode::resource_limit);
            if (link)
                require(link->filename == value.filename && link->crc32 == value.crc32,
                        "Primary ELF has conflicting GNU debuglink identities", ErrorCode::conflict);
            else link = &value;
        }
        const auto filename = filename_override ? filename_override :
            (link ? std::optional<std::string>{link->filename} : std::nullopt);
        if (!link && build_id.empty()) {
            result.diagnostics.push_back(altlink ? "Primary ELF has no GNU debugaltlink identity" :
                "Primary ELF has no GNU debuglink or GNU build-ID identity");
            return result;
        }
        if (filename) {
            require(filename->find_first_of(":\0", 0, 2) == std::string::npos,
                    "GNU debug companion filename contains a forbidden character", ErrorCode::malformed);
            const auto name = std::filesystem::path(std::u8string(filename->begin(), filename->end()));
            require(!name.empty() && !name.is_absolute() && !name.has_root_name() && !name.has_root_directory(),
                    "GNU debug companion filename must be a relative path", ErrorCode::malformed);
            std::size_t components = 0;
            for (const auto &component : name) {
                require(component != "." && component != "..",
                        "GNU debug companion filename escapes its containing directory", ErrorCode::malformed);
                ++components;
            }
            require(components && (altlink || components == 1), altlink ?
                    "GNU debugaltlink filename is empty" : "GNU debuglink filename is not a safe basename",
                    ErrorCode::malformed);
        }

        std::size_t path_bytes = 0;
        const auto count_path = [&](const std::filesystem::path &path) {
            require(!path.empty() && path.native().find(std::filesystem::path::value_type{}) == path.native().npos,
                    "Invalid ELF debug-companion path", ErrorCode::invalid_argument);
            require(path.native().size() <= options.max_path_bytes,
                    "ELF debug-companion native path exceeds limit", ErrorCode::resource_limit);
            const auto bytes = path.u8string().size();
            require(bytes <= options.max_path_bytes && path_bytes <= options.max_total_path_bytes &&
                    bytes <= options.max_total_path_bytes - path_bytes,
                    "ELF debug-companion paths exceed byte limit", ErrorCode::resource_limit);
            path_bytes += bytes;
        };
        count_path(primary_path);
        std::error_code ec;
        const auto primary_file = std::filesystem::canonical(primary_path, ec);
        require(!ec && std::filesystem::is_regular_file(primary_file, ec) && !ec,
                "Cannot canonicalize primary ELF regular file", ErrorCode::io);
        count_path(primary_file);
        const auto parent = primary_file.parent_path();
        auto mirrored_parent = parent.relative_path();
        if (options.sysroot) {
            count_path(*options.sysroot);
            const auto root = std::filesystem::canonical(*options.sysroot, ec);
            require(!ec && std::filesystem::is_directory(root, ec) && !ec,
                    "Cannot canonicalize ELF debug-companion sysroot", ErrorCode::invalid_argument);
            count_path(root);
            require(contained(primary_file, root), "Primary ELF is outside the selected sysroot", ErrorCode::invalid_argument);
            mirrored_parent = parent.lexically_relative(root);
        }
#ifdef _WIN32
        else if (filename && !options.debug_directories.empty() && !parent.root_name().empty()) {
            const auto drive = parent.root_name().native();
            require(drive.size() == 2 && drive[1] == L':' &&
                    ((drive[0] >= L'A' && drive[0] <= L'Z') || (drive[0] >= L'a' && drive[0] <= L'z')),
                    "A sysroot is required to mirror a UNC ELF input path", ErrorCode::unsupported);
            const wchar_t letter = drive[0] >= L'A' && drive[0] <= L'Z' ? wchar_t(drive[0] + (L'a' - L'A')) : drive[0];
            mirrored_parent = std::filesystem::path(std::wstring(1, letter)) / mirrored_parent;
        }
#endif
        std::vector<Probe> probes;
        std::set<std::filesystem::path> probe_names;
        const auto add_probe = [&](std::filesystem::path path, std::optional<std::filesystem::path> root,
                                   ElfDebugCompanionSource source) {
            path = path.lexically_normal();
            if (!probe_names.insert(path).second) return;
            require(probes.size() < options.max_candidates, "ELF debug-companion candidate limit exceeded",
                    ErrorCode::resource_limit);
            count_path(path);
            probes.push_back({std::move(path), std::move(root), source});
        };
        for (const auto &path : options.candidates) {
            canceled(stop);
            add_probe(path, {}, ElfDebugCompanionSource::explicit_path);
        }
        if (filename) {
            const auto name = std::filesystem::path(std::u8string(filename->begin(), filename->end()));
            add_probe(parent / name, parent, ElfDebugCompanionSource::adjacent);
            add_probe(parent / ".debug" / name, parent, ElfDebugCompanionSource::adjacent_debug_directory);
        }
        for (const auto &directory : options.debug_directories) {
            canceled(stop);
            count_path(directory);
            const auto root = std::filesystem::canonical(directory, ec);
            require(!ec && std::filesystem::is_directory(root, ec) && !ec,
                    "Cannot canonicalize an explicit ELF debug directory", ErrorCode::invalid_argument);
            count_path(root);
            if (build_id.size() >= 2) {
                const auto id = hex_id(build_id);
                add_probe(root / ".build-id" / id.substr(0, 2) / (id.substr(2) + ".debug"), root,
                          ElfDebugCompanionSource::build_id_directory);
            }
            if (filename) {
                const auto name = std::filesystem::path(std::u8string(filename->begin(), filename->end()));
                add_probe(root / mirrored_parent / name, root, ElfDebugCompanionSource::debug_directory);
            }
        }
        std::set<std::filesystem::path> inspected;
        std::shared_ptr<const ByteStorage> matched_storage;
        std::optional<std::size_t> matched_index;
        std::size_t match_count = 0;
        for (const auto &probe : probes) {
            canceled(stop);
            ElfDebugCompanionCandidate row;
            row.path = probe.path;
            row.source = probe.source;
            std::shared_ptr<const ByteStorage> observed;
            std::optional<Sha256Digest> before_hash;
            const auto fail = [&](ElfDebugCompanionStatus state, std::string message, bool incomplete = false) {
                if (observed && before_hash && !incomplete) {
                    const auto after = hash_source(*observed, stop);
                    if (!after) {
                        if (after.error().code == ErrorCode::canceled) throw Failure{after.error()};
                        state = ElfDebugCompanionStatus::io_error;
                        message = after.error().message;
                        incomplete = true;
                    } else if (after.value() != *before_hash) {
                        state = ElfDebugCompanionStatus::changed_during_read;
                        message = "Candidate changed during identity verification";
                        incomplete = true;
                    }
                }
                row.status = state;
                row.diagnostic = std::move(message);
                if (incomplete) result.complete = false;
                result.candidates.push_back(std::move(row));
            };
            const auto status = std::filesystem::status(probe.path, ec);
            if (ec == std::errc::no_such_file_or_directory || ec == std::errc::not_a_directory ||
                (!ec && !std::filesystem::exists(status))) {
                fail(ElfDebugCompanionStatus::missing, "Candidate path does not exist");
                continue;
            }
            if (ec) { fail(ElfDebugCompanionStatus::io_error, ec.message(), true); continue; }
            if (!std::filesystem::is_regular_file(status)) {
                fail(ElfDebugCompanionStatus::not_regular, "Candidate is not a regular file"); continue;
            }
            const auto path = std::filesystem::canonical(probe.path, ec);
            if (ec) { fail(ElfDebugCompanionStatus::io_error, ec.message(), true); continue; }
            count_path(path);
            row.canonical_path = path;
            if (probe.root && !contained(path, *probe.root)) {
                fail(ElfDebugCompanionStatus::outside_directory, "Candidate canonical path escapes its search directory", true);
                continue;
            }
            const bool same_file = path == primary_file || std::filesystem::equivalent(path, primary_file, ec);
            if (ec) { fail(ElfDebugCompanionStatus::io_error, ec.message(), true); continue; }
            if (same_file) {
                fail(ElfDebugCompanionStatus::same_as_primary, "Primary ELF cannot be its own debug companion"); continue;
            }
            if (!inspected.insert(path).second) continue;
            auto storage = FileStorage::open(path);
            if (!storage) { fail(ElfDebugCompanionStatus::io_error, storage.error().message, true); continue; }
            const auto size = storage.value()->size();
            row.file_size = size;
            if (size > options.max_file_bytes) {
                fail(ElfDebugCompanionStatus::too_large, "Candidate exceeds per-file byte limit", true); continue;
            }
            require(result.inspected_file_bytes <= options.max_total_file_bytes &&
                    size <= options.max_total_file_bytes - result.inspected_file_bytes,
                    "ELF debug-companion aggregate file-byte limit exceeded", ErrorCode::resource_limit);
            result.inspected_file_bytes += size;
            const auto before = hash_source(*storage.value(), stop);
            if (!before) {
                if (before.error().code == ErrorCode::canceled) return before.error();
                fail(ElfDebugCompanionStatus::io_error, before.error().message, true); continue;
            }
            observed = storage.value();
            before_hash = before.value();
            const auto header = read_elf_header(*storage.value(), stop);
            if (!header) {
                if (header.error().code == ErrorCode::canceled) return header.error();
                fail(ElfDebugCompanionStatus::invalid_elf, header.error().message,
                     header.error().code == ErrorCode::resource_limit || header.error().code == ErrorCode::io);
                continue;
            }
            const bool object_type_matches = header.value().object_type == primary.header.object_type ||
                (altlink && header.value().object_type == 1); // DWZ alternate files may be ET_REL.
            if (header.value().machine != primary.header.machine || header.value().is_64 != primary.header.is_64 ||
                header.value().order != primary.header.order || !object_type_matches ||
                header.value().flags != primary.header.flags || header.value().os_abi != primary.header.os_abi ||
                header.value().abi_version != primary.header.abi_version) {
                fail(ElfDebugCompanionStatus::incompatible_elf, "Candidate ELF header identity differs from the primary");
                continue;
            }
            ElfMetadata candidate;
            candidate.header = header.value();
            Budget budget;
            try { read_tables(*storage.value(), candidate, budget, stop); }
            catch (const Failure &failure) {
                if (failure.error.code == ErrorCode::canceled) return failure.error;
                fail(ElfDebugCompanionStatus::invalid_elf, failure.error.message,
                     failure.error.code == ErrorCode::resource_limit || failure.error.code == ErrorCode::io);
                continue;
            }
            for (const auto &section : candidate.sections) {
                canceled(stop);
                if (!section.size || section.type == 8) continue; // SHT_NOBITS carries no debug payload.
                row.has_debug_info_sections = row.has_debug_info_sections || section.name == ".debug_info" ||
                    section.name == ".zdebug_info" || section.name == ".debug_types" || section.name == ".zdebug_types";
                row.has_source_line_sections = row.has_source_line_sections || section.name == ".debug_line" ||
                    section.name == ".zdebug_line";
                row.has_static_symbol_tables = row.has_static_symbol_tables || section.type == 2; // SHT_SYMTAB
            }
            if (!row.has_debug_info_sections && !row.has_source_line_sections && !row.has_static_symbol_tables) {
                fail(ElfDebugCompanionStatus::no_debug_metadata,
                     "Candidate declares no file-backed DWARF info/line section or static symbol table");
                continue;
            }
            const auto candidate_id = unique_build_id(candidate, stop);
            if (!candidate_id) {
                if (candidate_id.error().code == ErrorCode::canceled) return candidate_id.error();
                fail(ElfDebugCompanionStatus::build_id_mismatch, candidate_id.error().message,
                     candidate_id.error().code == ErrorCode::resource_limit);
                continue;
            }
            row.build_id = candidate_id.value();
            if (!build_id.empty() && row.build_id.empty()) {
                fail(ElfDebugCompanionStatus::missing_build_id, altlink ?
                    "Candidate has no GNU build ID declared by .gnu_debugaltlink" :
                    "Candidate has no GNU build ID declared by the primary");
                continue;
            }
            if (!build_id.empty() && row.build_id != build_id) {
                fail(ElfDebugCompanionStatus::build_id_mismatch, altlink ?
                    "Candidate GNU build ID differs from .gnu_debugaltlink" :
                    "Candidate GNU build ID differs from the primary"); continue;
            }
            if (link) {
                const auto crc = verify_elf_gnu_debuglink_crc(*link, *storage.value(), stop, options.max_file_bytes);
                if (!crc) {
                    if (crc.error().code == ErrorCode::canceled) return crc.error();
                    fail(ElfDebugCompanionStatus::io_error, crc.error().message, true); continue;
                }
                if (!crc.value()) { fail(ElfDebugCompanionStatus::checksum_mismatch, "Candidate GNU debuglink CRC differs"); continue; }
            }
            const auto after = hash_source(*storage.value(), stop);
            if (!after) {
                if (after.error().code == ErrorCode::canceled) return after.error();
                fail(ElfDebugCompanionStatus::io_error, after.error().message, true); continue;
            }
            if (after.value() != before.value()) {
                fail(ElfDebugCompanionStatus::changed_during_read, "Candidate changed during identity verification", true); continue;
            }
            row.status = ElfDebugCompanionStatus::matched;
            row.content_sha256 = after.value();
            matched_index = result.candidates.size();
            matched_storage = storage.value();
            ++match_count;
            result.candidates.push_back(std::move(row));
        }
        if (result.complete && match_count == 1) {
            result.selected = matched_index;
            result.selected_storage = std::move(matched_storage);
        }
        if (match_count > 1) result.diagnostics.push_back(altlink ?
            "Multiple canonical files match the .gnu_debugaltlink identity" :
            "Multiple canonical files match the primary debug identities");
        if (!result.complete) result.diagnostics.push_back("Incomplete search: a unique companion was not selected");
        return result;
    } catch (const Failure &failure) { return failure.error; }
    catch (const std::filesystem::filesystem_error &error) { return Error{ErrorCode::io, error.what()}; }
    catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "Cannot allocate ELF debug-companion catalog"}; }
    catch (const std::length_error &) { return Error{ErrorCode::resource_limit, "ELF debug-companion catalog exceeds container limits"}; }
}

Result<ElfDebugCompanionReport> discover_elf_debug_companions(
    const ElfMetadata &primary, const std::filesystem::path &primary_path,
    const ElfDebugCompanionSearch &options, std::stop_token stop) {
    return discover_elf_debug_companions_impl(primary, primary_path, options, stop);
}

Result<ElfDebugCompanionReport> discover_elf_debug_alt_companions(
    const ElfMetadata &primary, const std::filesystem::path &primary_path,
    const ElfDebugCompanionSearch &options, std::stop_token stop) {
    if (primary.gnu_debug_altlinks.size() > 4096)
        return Error{ErrorCode::resource_limit, "ELF alternate debug identity exceeds 4096 .gnu_debugaltlink records"};
    const ElfGnuDebugAltLink *identity = nullptr;
    for (const auto &link : primary.gnu_debug_altlinks) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF alternate debug discovery canceled"};
        if (link.filename.size() > options.max_path_bytes)
            return Error{ErrorCode::resource_limit, "GNU debugaltlink filename exceeds path-byte limit"};
        if (link.build_id.empty() || link.build_id.size() > 64)
            return Error{ErrorCode::unsupported, "GNU debugaltlink build ID must contain 1 through 64 bytes"};
        if (identity && (identity->filename != link.filename || identity->build_id != link.build_id))
            return Error{ErrorCode::conflict, "Primary ELF has conflicting GNU debugaltlink identities"};
        identity = &link;
    }
    if (!identity) {
        ElfDebugCompanionReport result;
        result.diagnostics.push_back("Primary ELF has no GNU debugaltlink identity");
        return result;
    }
    const bool safe_filename = safe_altlink_relative_name(identity->filename);
    auto result = discover_elf_debug_companions_impl(primary, primary_path, options, stop,
        identity->build_id, safe_filename ? std::optional<std::string>{identity->filename} : std::nullopt, true);
    if (result && !safe_filename)
        result.value().diagnostics.push_back("Unsafe .gnu_debugaltlink filename was not followed; explicit candidates and build-ID paths were still checked");
    return result;
}
} // namespace hexlab
