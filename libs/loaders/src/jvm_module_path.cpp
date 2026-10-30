#include "hexlab/loaders/jvm_module_path.hpp"
#include "hexlab/image/file_storage.hpp"
#include <algorithm>
#include <charconv>
#include <cctype>
#include <deque>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string_view>
#include <system_error>

namespace hexlab {
namespace {
Error malformed(std::string message) { return {ErrorCode::malformed, std::move(message)}; }

Result<std::vector<JvmNestRelation>> link_nest_relations(
    std::span<const JvmMetadata> metadata, std::stop_token stop, std::size_t max_classes) {
    constexpr std::size_t max_relations = 100'000;
    constexpr std::size_t max_retained_bytes = 16 * 1024 * 1024;
    try {
        std::map<std::string, std::vector<std::size_t>, std::less<>> by_name;
        for (std::size_t index = 0; index < metadata.size(); ++index) {
            if ((index & 1023u) == 0 && stop.stop_requested())
                return Error{ErrorCode::canceled, "JVM nest linking canceled"};
            if (metadata[index].class_name.empty() || metadata[index].class_name == "module-info") continue;
            by_name[metadata[index].class_name].push_back(index);
            if (by_name.size() > max_classes)
                return Error{ErrorCode::resource_limit, "JVM nest linking class index exceeds configured limit"};
        }
        const auto package_of = [](std::string_view name) {
            const auto slash = name.rfind('/');
            return slash == std::string_view::npos ? std::string_view{} : name.substr(0, slash);
        };
        std::vector<JvmNestRelation> result;
        std::size_t retained_bytes = 0, work = 0;
        const auto charge_work = [&]() -> Result<bool> {
            if (work >= max_relations)
                return Error{ErrorCode::resource_limit, "JVM nest link work exceeds 100,000 visits"};
            ++work;
            if ((work & 255u) == 0 && stop.stop_requested())
                return Error{ErrorCode::canceled, "JVM nest linking canceled"};
            return true;
        };
        const auto append = [&](JvmNestRelation row) -> Result<bool> {
            if (result.size() >= max_relations)
                return Error{ErrorCode::resource_limit, "JVM nest links exceed 100,000 rows"};
            const auto cost = sizeof(JvmNestRelation) + row.source_class.size() + row.target_class.size();
            if (cost > max_retained_bytes - retained_bytes)
                return Error{ErrorCode::resource_limit, "JVM nest link metadata exceeds 16 MiB"};
            retained_bytes += cost;
            result.push_back(std::move(row));
            return true;
        };
        for (std::size_t source = 0; source < metadata.size(); ++source) {
            if ((source & 255u) == 0 && stop.stop_requested())
                return Error{ErrorCode::canceled, "JVM nest linking canceled"};
            const auto &item = metadata[source];
            if (item.class_name.empty() || item.class_name == "module-info") continue;
            if (item.nest_host_reference) {
                auto charged = charge_work(); if (!charged) return charged.error();
                const auto &reference = *item.nest_host_reference;
                JvmNestRelation row{JvmNestRelationKind::member_declares_host,
                    JvmNestRelationStatus::missing, item.class_name, reference.class_name,
                    source, std::nullopt, reference.reference_file_offset};
                const auto found = by_name.find(reference.class_name);
                if (found != by_name.end()) {
                    if (found->second.size() != 1) row.status = JvmNestRelationStatus::ambiguous;
                    else {
                        row.target_metadata_index = found->second.front();
                        const auto &host = metadata[*row.target_metadata_index];
                        if (package_of(item.class_name) != package_of(host.class_name))
                            row.status = JvmNestRelationStatus::cross_package;
                        else {
                            std::size_t memberships = 0;
                            for (const auto &listed_member : host.nest_members) {
                                auto scan_charged = charge_work(); if (!scan_charged) return scan_charged.error();
                                if (listed_member == item.class_name) ++memberships;
                            }
                            row.status = memberships == 1 ? JvmNestRelationStatus::resolved :
                                memberships > 1 ? JvmNestRelationStatus::ambiguous : JvmNestRelationStatus::not_reciprocal;
                        }
                    }
                }
                auto added = append(std::move(row)); if (!added) return added.error();
            }
            for (const auto &reference : item.nest_member_references) {
                auto charged = charge_work(); if (!charged) return charged.error();
                JvmNestRelation row{JvmNestRelationKind::host_declares_member,
                    JvmNestRelationStatus::missing, item.class_name, reference.class_name,
                    source, std::nullopt, reference.reference_file_offset};
                const auto found = by_name.find(reference.class_name);
                if (found != by_name.end()) {
                    if (found->second.size() != 1) row.status = JvmNestRelationStatus::ambiguous;
                    else {
                        row.target_metadata_index = found->second.front();
                        const auto &member = metadata[*row.target_metadata_index];
                        if (package_of(item.class_name) != package_of(member.class_name))
                            row.status = JvmNestRelationStatus::cross_package;
                        else row.status = member.nest_host == item.class_name
                            ? JvmNestRelationStatus::resolved : JvmNestRelationStatus::not_reciprocal;
                    }
                }
                auto added = append(std::move(row)); if (!added) return added.error();
            }
        }
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate bounded JVM nest-link metadata"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "JVM nest-link metadata exceeds container limits"};
    }
}

Result<JvmMetadata> load_metadata(std::shared_ptr<const ByteStorage> storage, std::stop_token stop) {
    auto loaded = load_jvm_class(std::move(storage), stop);
    if (!loaded) return loaded.error();
    if (!loaded.value().metadata.jvm) return malformed("loaded JVM path class has no JVM metadata");
    return std::move(*loaded.value().metadata.jvm);
}

Result<std::vector<std::byte>> read_file(const std::filesystem::path &path, std::uint64_t size,
                                         std::uint64_t limit, std::stop_token stop) {
    if (size > limit || size > std::numeric_limits<std::size_t>::max())
        return Error{ErrorCode::resource_limit, "JVM path file exceeds its configured byte limit"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "JVM path reading canceled"};
    auto file = FileStorage::open(path); if (!file) return file.error();
    if (file.value()->size() != size) return Error{ErrorCode::io, "JVM path file changed while being inventoried"};
    auto view = file.value()->read_at({0}, static_cast<std::size_t>(size)); if (!view) return view.error();
    if (view.value().bytes.size() != size) return Error{ErrorCode::io, "JVM path file returned an incomplete read"};
    return std::vector<std::byte>(view.value().bytes.begin(), view.value().bytes.end());
}

bool valid_service_name(std::string_view name) {
    if (name.empty() || name.front() == '.' || name.back() == '.') return false;
    bool segment_start = true;
    for (const unsigned char c : name) {
        if (c == '.') { if (segment_start) return false; segment_start = true; continue; }
        if (c < 0x80 && !(std::isalnum(c) || c == '_' || c == '$')) return false;
        segment_start = false;
    }
    return !segment_start;
}

Result<bool> add_service_file(std::span<const std::byte> bytes, std::string_view service,
                              JvmModule &unnamed, std::size_t &rows, const JvmModulePathLimits &limits) {
    if (!valid_service_name(service)) return malformed("classpath service descriptor has an invalid service name");
    JvmModuleProvide provide; provide.service.assign(service);
    std::replace(provide.service.begin(), provide.service.end(), '.', '/');
    std::string_view text(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    std::size_t at = 0;
    while (at <= text.size()) {
        const auto end = text.find_first_of("\r\n", at);
        auto line = text.substr(at, end == std::string_view::npos ? text.size() - at : end - at);
        const auto comment = line.find('#'); if (comment != std::string_view::npos) line = line.substr(0, comment);
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t' || line.front() == '\f')) line.remove_prefix(1);
        while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\f')) line.remove_suffix(1);
        if (!line.empty()) {
            if (!valid_service_name(line)) return malformed("classpath service descriptor contains an invalid provider name");
            if (rows >= limits.max_service_rows) return Error{ErrorCode::resource_limit, "JVM path workspace exceeds its service-row limit"};
            ++rows;
            provide.implementations.emplace_back(line);
            std::replace(provide.implementations.back().begin(), provide.implementations.back().end(), '.', '/');
        }
        if (end == std::string_view::npos) break;
        at = end + 1;
        if (text[end] == '\r' && at < text.size() && text[at] == '\n') ++at;
    }
    if (!provide.implementations.empty()) unnamed.provides.push_back(std::move(provide));
    return true;
}

std::string package_of(std::string_view name) {
    const auto slash = name.rfind('/'); return slash == std::string_view::npos ? std::string{} : std::string(name.substr(0, slash));
}

struct RootFiles { std::vector<std::filesystem::path> paths; };
Result<RootFiles> enumerate_directory(const std::filesystem::path &root, std::size_t max_files,
                                     std::stop_token stop) {
    std::error_code ec;
    const auto root_status = std::filesystem::symlink_status(root, ec);
    if (ec) return Error{ErrorCode::io, "cannot inspect JVM path root: " + ec.message()};
    if (std::filesystem::is_symlink(root_status)) return Error{ErrorCode::invalid_argument, "JVM path root cannot be a symlink"};
    if (!std::filesystem::is_directory(root_status)) return Error{ErrorCode::invalid_argument, "JVM path root is not a directory"};
    try {
        RootFiles result;
        std::filesystem::recursive_directory_iterator it(root, std::filesystem::directory_options::none, ec), end;
        if (ec) return Error{ErrorCode::io, "cannot enumerate JVM path root: " + ec.message()};
        while (it != end) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "JVM path enumeration canceled"};
            const auto status = it->symlink_status(ec);
            if (ec) return Error{ErrorCode::io, "cannot inspect JVM path entry: " + ec.message()};
            if (std::filesystem::is_symlink(status)) {
                it.disable_recursion_pending();
            } else if (std::filesystem::is_regular_file(status)) {
                if (result.paths.size() >= max_files) return Error{ErrorCode::resource_limit, "JVM path exceeds its file-count limit"};
                result.paths.push_back(it->path());
            }
            it.increment(ec);
            if (ec) return Error{ErrorCode::io, "cannot continue JVM path enumeration: " + ec.message()};
        }
        std::sort(result.paths.begin(), result.paths.end(), [&](const auto &a, const auto &b) {
            return a.lexically_relative(root).generic_string() < b.lexically_relative(root).generic_string();
        });
        return result;
    } catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "cannot allocate bounded JVM path inventory"}; }
}

Result<std::string> relative_name(const std::filesystem::path &root, const std::filesystem::path &path) {
    try {
        auto rel = path.lexically_relative(root).generic_string();
        if (rel.empty() || rel.starts_with("../") || rel == ".." || rel.find('\\') != std::string::npos)
            return malformed("JVM path entry is not a normalized relative path");
        return rel;
    } catch (...) { return malformed("cannot normalize JVM path entry"); }
}

Result<bool> account(std::uint64_t value, std::uint64_t &total, std::uint64_t limit, const char *what) {
    if (value > limit || total > limit - value)
        return Error{ErrorCode::resource_limit, std::string("JVM path workspace exceeds its ") + what + " byte limit"};
    total += value; return true;
}

bool ascii_equal_fold(std::string_view left, std::string_view right) {
    if (left.size() != right.size()) return false;
    for (std::size_t i = 0; i < left.size(); ++i)
        if (std::tolower(static_cast<unsigned char>(left[i])) !=
            std::tolower(static_cast<unsigned char>(right[i]))) return false;
    return true;
}

struct JarMainAttributes {
    bool multi_release = false;
    std::vector<std::string> class_path;
};

Result<JarMainAttributes> jar_main_attributes(const JarArchive &archive, const JvmModulePathLimits &limits,
                                              std::stop_token stop) {
    std::optional<std::size_t> manifest_index;
    for (std::size_t i = 0; i < archive.members.size(); ++i) {
        if (archive.members[i].directory || archive.members[i].name != "META-INF/MANIFEST.MF") continue;
        if (manifest_index) return malformed("JVM archive has duplicate main manifest entries");
        manifest_index = i;
    }
    if (!manifest_index) return JarMainAttributes{};
    const auto &member = archive.members[*manifest_index];
    if (member.uncompressed_size > limits.max_manifest_bytes)
        return Error{ErrorCode::resource_limit, "JVM archive manifest exceeds its configured byte limit"};
    auto bytes = extract_jar_member(archive, *manifest_index, stop, limits.archive);
    if (!bytes) return bytes.error();
    const std::string_view text(reinterpret_cast<const char *>(bytes.value().data()), bytes.value().size());
    if (text.find('\0') != std::string_view::npos) return malformed("JVM archive manifest contains NUL");
    JarMainAttributes result;
    bool saw_multi_release = false, saw_class_path = false;
    std::string logical_line;
    const auto finish_line = [&]() -> Result<bool> {
        if (logical_line.empty()) return true;
        const auto colon = logical_line.find(':');
        if (colon == std::string::npos || colon == 0 || colon + 1 >= logical_line.size() || logical_line[colon + 1] != ' ')
            return malformed("JVM archive manifest has a malformed main attribute");
        const auto key = std::string_view(logical_line).substr(0, colon);
        for (const unsigned char c : key)
            if (!(std::isalnum(c) || c == '-')) return malformed("JVM archive manifest has an invalid attribute name");
        const auto value = std::string_view(logical_line).substr(colon + 2);
        if (ascii_equal_fold(key, "Multi-Release")) {
            if (saw_multi_release) return malformed("JVM archive manifest repeats Multi-Release");
            saw_multi_release = true;
            if (ascii_equal_fold(value, "true")) result.multi_release = true;
            else if (!ascii_equal_fold(value, "false")) return malformed("JVM archive manifest has an invalid Multi-Release value");
        } else if (ascii_equal_fold(key, "Class-Path")) {
            if (saw_class_path) return malformed("JVM archive manifest repeats Class-Path");
            saw_class_path = true;
            std::size_t cursor = 0;
            while (cursor < value.size()) {
                while (cursor < value.size() && value[cursor] == ' ') ++cursor;
                if (cursor == value.size()) break;
                const auto end = value.find(' ', cursor);
                const auto token = value.substr(cursor, end == std::string_view::npos ? value.size() - cursor : end - cursor);
                if (token.empty() || token.size() > 4096 || result.class_path.size() >= limits.max_class_path_references)
                    return Error{ErrorCode::resource_limit, "JVM manifest Class-Path entries exceed configured limits"};
                result.class_path.emplace_back(token);
                cursor = end == std::string_view::npos ? value.size() : end + 1;
            }
        }
        logical_line.clear();
        return true;
    };
    bool main_section_ended = false;
    for (std::size_t at = 0; at <= text.size();) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "JVM archive manifest parsing canceled"};
        const auto end = text.find_first_of("\r\n", at);
        const auto line = text.substr(at, end == std::string_view::npos ? text.size() - at : end - at);
        if (line.size() > 72) return malformed("JVM archive manifest line exceeds 72 bytes");
        if (line.empty()) {
            auto done = finish_line(); if (!done) return done.error();
            main_section_ended = true;
            break;
        }
        if (line.front() == ' ') {
            if (logical_line.empty()) return malformed("JVM archive manifest has an orphan continuation line");
            logical_line.append(line.substr(1));
        } else {
            auto done = finish_line(); if (!done) return done.error();
            logical_line.assign(line);
        }
        if (end == std::string_view::npos) { at = text.size() + 1; break; }
        if (text[end] == '\r' && (end + 1 >= text.size() || text[end + 1] != '\n'))
            return malformed("JVM archive manifest uses a bare carriage return");
        at = end + (text[end] == '\r' ? 2 : 1);
    }
    if (!main_section_ended) {
        auto done = finish_line(); if (!done) return done.error();
    }
    return result;
}

Result<std::string> decode_class_path_uri(std::string_view token) {
    if (token.empty() || token.size() > 4096 || token.front() == '/' || token.front() == '\\' ||
        token.find(':') != std::string_view::npos || token.find('?') != std::string_view::npos ||
        token.find('#') != std::string_view::npos || token.find('\\') != std::string_view::npos)
        return Error{ErrorCode::unsupported, "JVM manifest Class-Path URI is not a supported relative file URL"};
    std::string decoded;
    decoded.reserve(token.size());
    const auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < token.size(); ++i) {
        if (token[i] != '%') { decoded.push_back(token[i]); continue; }
        if (i + 2 >= token.size() || hex(token[i + 1]) < 0 || hex(token[i + 2]) < 0)
            return malformed("JVM manifest Class-Path URI has an invalid percent escape");
        const auto value = static_cast<char>((hex(token[i + 1]) << 4) | hex(token[i + 2]));
        if (!value || value == '/' || value == '\\')
            return Error{ErrorCode::unsupported, "JVM manifest Class-Path URI uses an unsupported escaped separator"};
        decoded.push_back(value);
        i += 2;
    }
    std::filesystem::path path;
    try { path = std::filesystem::u8path(decoded); }
    catch (...) { return malformed("JVM manifest Class-Path URI is not valid UTF-8"); }
    if (path.empty() || path.is_absolute() || path.has_root_name() || path.has_root_directory())
        return Error{ErrorCode::unsupported, "JVM manifest Class-Path URI is not relative"};
    return decoded;
}

struct SelectedJarClass { std::size_t member_index = 0; std::string logical_path; std::optional<std::uint16_t> release; };

Result<std::vector<SelectedJarClass>> select_multi_release_classes(
        const JarArchive &archive, std::uint16_t target_release, std::size_t max_path_bytes,
        std::stop_token stop) {
    constexpr std::string_view prefix = "META-INF/versions/";
    struct Candidate { std::size_t member_index; std::uint16_t release; };
    std::map<std::string, Candidate, std::less<>> selected;
    std::map<std::pair<std::string, std::uint16_t>, std::size_t> version_entries;
    std::size_t path_bytes = 0;
    const auto account_path = [&](std::size_t bytes) -> bool {
        if (bytes > max_path_bytes || path_bytes > max_path_bytes - bytes) return false;
        path_bytes += bytes;
        return true;
    };
    for (std::size_t i = 0; i < archive.members.size(); ++i) {
        if ((i & 0xffu) == 0 && stop.stop_requested())
            return Error{ErrorCode::canceled, "JVM multi-release archive selection canceled"};
        const auto &member = archive.members[i];
        if (member.directory || !member.name.ends_with(".class")) continue;
        if (!std::string_view(member.name).starts_with(prefix)) {
            if (!account_path(member.name.size()))
                return Error{ErrorCode::resource_limit, "JVM multi-release path bytes exceed their limit"};
            if (!selected.emplace(member.name, Candidate{i, 0}).second)
                return malformed("multi-release JAR has duplicate base class paths");
            continue;
        }
        const auto rest = std::string_view(member.name).substr(prefix.size());
        const auto slash = rest.find('/');
        if (slash == std::string_view::npos || slash == 0 || slash + 1 >= rest.size())
            return malformed("multi-release JAR has a malformed versioned class path");
        const auto version_text = rest.substr(0, slash);
        if ((version_text.size() > 1 && version_text.front() == '0') ||
            !std::all_of(version_text.begin(), version_text.end(), [](unsigned char c) { return c >= '0' && c <= '9'; }))
            return malformed("multi-release JAR has a noncanonical version directory");
        unsigned version = 0;
        const auto [end, error] = std::from_chars(version_text.data(), version_text.data() + version_text.size(), version);
        if (error != std::errc{} || end != version_text.data() + version_text.size() || version < 9 || version > UINT16_MAX)
            return malformed("multi-release JAR has an unsupported version directory");
        const auto logical = rest.substr(slash + 1);
        if (logical.starts_with("META-INF/") || logical == "META-INF")
            return malformed("multi-release JAR versioned entry targets META-INF");
        const auto release = static_cast<std::uint16_t>(version);
        if (!account_path(logical.size()))
            return Error{ErrorCode::resource_limit, "JVM multi-release path bytes exceed their limit"};
        if (!version_entries.emplace(std::pair{std::string(logical), release}, i).second)
            return malformed("multi-release JAR has duplicate class paths at one version");
        if (release > target_release) continue;
        const auto found = selected.find(logical);
        if (found == selected.end()) {
            if (!account_path(logical.size()))
                return Error{ErrorCode::resource_limit, "JVM multi-release path bytes exceed their limit"};
            selected.emplace(std::string(logical), Candidate{i, release});
        } else if (found->second.release < release) {
            selected.insert_or_assign(std::string(logical), Candidate{i, release});
        }
    }
    std::vector<SelectedJarClass> result;
    result.reserve(selected.size());
    for (const auto &[logical, candidate] : selected) {
        if (!account_path(logical.size()))
            return Error{ErrorCode::resource_limit, "JVM multi-release path bytes exceed their limit"};
        result.push_back({candidate.member_index, logical,
                          candidate.release ? std::optional<std::uint16_t>(candidate.release) : std::nullopt});
    }
    return result;
}
} // namespace

Result<JvmModulePathWorkspace> link_jvm_path_workspace(std::span<const JvmPathRoot> roots,
        std::stop_token stop, JvmModulePathLimits limits) {
    if (!limits.max_roots || !limits.max_files || !limits.max_classes || !limits.max_file_bytes ||
        !limits.max_total_input_bytes || !limits.max_total_class_bytes || !limits.max_service_bytes ||
        !limits.max_service_rows || !limits.max_manifest_bytes || !limits.max_class_path_references ||
        !limits.max_class_path_uri_bytes || !limits.max_selection_path_bytes)
        return Error{ErrorCode::invalid_argument, "JVM path limits must be positive"};
    if (limits.target_release && *limits.target_release < 9)
        return Error{ErrorCode::invalid_argument, "Multi-release JAR target release must be at least 9"};
    if (roots.size() > limits.max_roots) return Error{ErrorCode::resource_limit, "JVM path exceeds its root-count limit"};
    try {
        JvmModulePathWorkspace output;
        output.roots.reserve(roots.size());
        std::vector<JvmMetadata> metadata;
        metadata.reserve(std::min(limits.max_classes, limits.max_files));
        std::vector<std::optional<std::size_t>> root_module_metadata(roots.size());
        std::vector<std::set<std::string>> root_packages(roots.size());
        std::vector<std::vector<std::string>> manifest_class_path(roots.size());
        std::optional<std::size_t> classpath_metadata_index;
        JvmModule unnamed;
        std::size_t total_files = 0, classes = 0, service_rows = 0;
        std::uint64_t total_input = 0, total_class_bytes = 0, service_bytes = 0;
        std::size_t versioned_path_bytes = 0, class_path_reference_count = 0, class_path_uri_bytes = 0;
        std::size_t class_path_class_path_bytes = 0;

        for (std::size_t ri = 0; ri < roots.size(); ++ri) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "JVM path linking canceled"};
            const auto &root = roots[ri];
            JvmPathRootResult root_result; root_result.path = root.path; root_result.kind = root.kind;
            std::error_code ec;
            const auto status = std::filesystem::symlink_status(root.path, ec);
            if (ec) return Error{ErrorCode::io, "cannot inspect JVM path root: " + ec.message()};
            if (std::filesystem::is_symlink(status)) return Error{ErrorCode::invalid_argument, "JVM path root cannot be a symlink"};
            const bool directory = std::filesystem::is_directory(status);
            if (!directory && !std::filesystem::is_regular_file(status))
                return Error{ErrorCode::invalid_argument, "JVM path root is neither a directory nor a regular archive"};
            if (directory && !root.archive_volumes.empty())
                return Error{ErrorCode::invalid_argument, "JVM split archive volumes cannot be attached to a directory root"};
            if (directory) {
                auto listing = enumerate_directory(root.path, limits.max_files - total_files, stop);
                if (!listing) return listing.error();
                root_result.files = listing.value().paths.size();
                total_files += root_result.files;
                std::vector<std::pair<std::string, std::filesystem::path>> files;
                files.reserve(listing.value().paths.size());
                for (const auto &path : listing.value().paths) {
                    auto rel = relative_name(root.path, path); if (!rel) return rel.error();
                    files.emplace_back(std::move(rel.value()), path);
                    const auto size = std::filesystem::file_size(path, ec);
                    if (ec) return Error{ErrorCode::io, "cannot get JVM path file size: " + ec.message()};
                    if (size > limits.max_file_bytes) return Error{ErrorCode::resource_limit, "JVM path file exceeds its configured byte limit"};
                    auto total = account(size, total_input, limits.max_total_input_bytes, "input"); if (!total) return total.error();
                }
                for (const auto &[rel, path] : files) {
                    if (stop.stop_requested()) return Error{ErrorCode::canceled, "JVM path loading canceled"};
                    const auto size = std::filesystem::file_size(path, ec);
                    if (ec) return Error{ErrorCode::io, "cannot get JVM path file size: " + ec.message()};
                    if (rel.ends_with(".class")) {
                        if (rel.starts_with("META-INF/versions/") || rel.ends_with("/module-info.class") ||
                            (rel == "module-info.class" && root.kind == JvmPathRootKind::class_path))
                            continue;
                        if (root_result.classes >= limits.max_classes - classes) return Error{ErrorCode::resource_limit, "JVM path exceeds its class-count limit"};
                        auto total = account(size, total_class_bytes, limits.max_total_class_bytes, "class"); if (!total) return total.error();
                        auto file = FileStorage::open(path); if (!file) return file.error();
                        if (file.value()->size() != size) return Error{ErrorCode::io, "JVM path class changed while being inventoried"};
                        auto row = load_metadata(file.value(), stop); if (!row) return row.error();
                        row.value().defining_loader = "jvm-path-root-" + std::to_string(ri);
                        if (rel == "module-info.class" && root.kind == JvmPathRootKind::module_path) {
                            if (!row.value().module) return malformed("module-info.class does not contain a Module attribute");
                            if (root_module_metadata[ri]) return malformed("JVM module-path root contains duplicate root module descriptors");
                            root_result.module_name = row.value().module->name;
                            root_module_metadata[ri] = metadata.size();
                        }
                        if (root.kind == JvmPathRootKind::class_path) {
                            if (row.value().class_name.size() > limits.max_selection_path_bytes ||
                                rel.size() > limits.max_selection_path_bytes - row.value().class_name.size())
                                return Error{ErrorCode::resource_limit, "JVM class-path definition paths exceed their byte limit"};
                            const auto path_bytes = row.value().class_name.size() + rel.size();
                            if (class_path_class_path_bytes > limits.max_selection_path_bytes - path_bytes)
                                return Error{ErrorCode::resource_limit, "JVM class-path definition paths exceed their byte limit"};
                            class_path_class_path_bytes += path_bytes;
                            const std::string_view expected_name(rel.data(), rel.size() - std::string_view(".class").size());
                            output.class_path_classes.push_back({ri, row.value().class_name, rel, std::nullopt,
                                0, size, row.value().class_name == expected_name, {}});
                        }
                        if (!row.value().module) root_packages[ri].insert(package_of(row.value().class_name));
                        metadata.push_back(std::move(row.value()));
                        ++classes; ++root_result.classes;
                    } else if (root.kind == JvmPathRootKind::class_path && rel.starts_with("META-INF/services/")) {
                        const auto service = std::string_view(rel).substr(std::string_view("META-INF/services/").size());
                        if (service.empty() || service.find('/') != std::string_view::npos) continue;
                        if (size > limits.max_service_bytes || service_bytes > limits.max_service_bytes - size)
                            return Error{ErrorCode::resource_limit, "JVM path workspace exceeds its service-file byte limit"};
                        service_bytes += size;
                        auto bytes = read_file(path, size, limits.max_service_bytes, stop); if (!bytes) return bytes.error();
                        auto added = add_service_file(bytes.value(), service, unnamed, service_rows, limits); if (!added) return added.error();
                    }
                }
            } else {
                const std::vector<std::filesystem::path> volume_paths = root.archive_volumes.empty()
                    ? std::vector<std::filesystem::path>{root.path} : root.archive_volumes;
                if (volume_paths.size() > limits.archive.max_volumes)
                    return Error{ErrorCode::resource_limit, "JVM split archive exceeds its configured volume limit"};
                if (!root.archive_volumes.empty()) {
                    const auto named_final = std::filesystem::absolute(root.path, ec).lexically_normal();
                    if (ec) return Error{ErrorCode::io, "cannot resolve JVM split archive final-volume path: " + ec.message()};
                    const auto supplied_final = std::filesystem::absolute(volume_paths.back(), ec).lexically_normal();
                    if (ec) return Error{ErrorCode::io, "cannot resolve JVM split archive volume path: " + ec.message()};
                    if (named_final != supplied_final)
                        return Error{ErrorCode::invalid_argument, "JVM split archive root path must name the final supplied volume"};
                }
                std::vector<std::shared_ptr<const ByteStorage>> archive_volumes;
                archive_volumes.reserve(volume_paths.size());
                for (const auto &volume_path : volume_paths) {
                    if (stop.stop_requested()) return Error{ErrorCode::canceled, "JVM split archive loading canceled"};
                    const auto volume_status = std::filesystem::symlink_status(volume_path, ec);
                    if (ec) return Error{ErrorCode::io, "cannot inspect JVM archive volume: " + ec.message()};
                    if (std::filesystem::is_symlink(volume_status) || !std::filesystem::is_regular_file(volume_status))
                        return Error{ErrorCode::invalid_argument, "JVM archive volumes must be regular non-symlink files"};
                    const auto size = std::filesystem::file_size(volume_path, ec);
                    if (ec) return Error{ErrorCode::io, "cannot get JVM archive volume size: " + ec.message()};
                    if (size > limits.max_file_bytes)
                        return Error{ErrorCode::resource_limit, "JVM archive volume exceeds its configured byte limit"};
                    auto total = account(size, total_input, limits.max_total_input_bytes, "input");
                    if (!total) return total.error();
                    auto file = FileStorage::open(volume_path); if (!file) return file.error();
                    if (file.value()->size() != size)
                        return Error{ErrorCode::io, "JVM archive volume changed while being inventoried"};
                    archive_volumes.push_back(std::move(file.value()));
                }
                if (total_files >= limits.max_files) return Error{ErrorCode::resource_limit, "JVM path exceeds its file-count limit"};
                auto jar_limits = limits.archive;
                jar_limits.max_archive_bytes = std::min(jar_limits.max_archive_bytes, limits.max_total_input_bytes);
                auto archive = read_jar_archive(archive_volumes, stop, jar_limits); if (!archive) return archive.error();
                if (archive.value().members.size() > limits.max_files - total_files) return Error{ErrorCode::resource_limit, "JVM path exceeds its file-count limit"};
                total_files += archive.value().members.size();
                root_result.files = static_cast<std::size_t>(std::count_if(archive.value().members.begin(), archive.value().members.end(),
                    [](const JarMember &member) { return !member.directory; }));
                std::optional<JarMainAttributes> main_attributes;
                if (root.kind == JvmPathRootKind::class_path || limits.target_release) {
                    auto parsed_manifest = jar_main_attributes(archive.value(), limits, stop);
                    if (!parsed_manifest) return parsed_manifest.error();
                    main_attributes = std::move(parsed_manifest.value());
                    if (root.kind == JvmPathRootKind::class_path) {
                        if (main_attributes->class_path.size() > limits.max_class_path_references - class_path_reference_count)
                            return Error{ErrorCode::resource_limit, "JVM manifest Class-Path references exceed their aggregate count limit"};
                        class_path_reference_count += main_attributes->class_path.size();
                        for (const auto &uri : main_attributes->class_path) {
                            if (uri.size() > limits.max_class_path_uri_bytes - class_path_uri_bytes)
                                return Error{ErrorCode::resource_limit, "JVM manifest Class-Path URIs exceed their aggregate byte limit"};
                            class_path_uri_bytes += uri.size();
                        }
                        manifest_class_path[ri] = main_attributes->class_path;
                    }
                }
                std::vector<SelectedJarClass> selected_classes;
                std::vector<const SelectedJarClass *> selected_by_member;
                if (limits.target_release && main_attributes) {
                    if (main_attributes->multi_release) {
                        root_result.multi_release_active = true;
                        auto selected = select_multi_release_classes(archive.value(), *limits.target_release,
                                                                     limits.max_selection_path_bytes, stop);
                        if (!selected) return selected.error();
                        selected_classes = std::move(selected.value());
                        selected_by_member.resize(archive.value().members.size());
                        for (const auto &item : selected_classes) {
                            if (item.member_index >= selected_by_member.size())
                                return malformed("multi-release class selection has an invalid archive member index");
                            selected_by_member[item.member_index] = &item;
                            if (!item.release) continue;
                            const auto &selected_member = archive.value().members[item.member_index];
                            if (item.logical_path.size() > limits.max_selection_path_bytes ||
                                selected_member.name.size() > limits.max_selection_path_bytes - item.logical_path.size())
                                return Error{ErrorCode::resource_limit, "JVM multi-release provenance paths exceed their limit"};
                            const auto path_bytes = item.logical_path.size() + selected_member.name.size();
                            if (versioned_path_bytes > limits.max_selection_path_bytes - path_bytes)
                                return Error{ErrorCode::resource_limit, "JVM multi-release provenance paths exceed their limit"};
                            versioned_path_bytes += path_bytes;
                            output.versioned_classes.push_back({ri, item.logical_path, selected_member.name, *item.release,
                                                                selected_member.data_offset, selected_member.uncompressed_size});
                            ++root_result.selected_versioned_classes;
                        }
                    }
                }
                for (std::size_t mi = 0; mi < archive.value().members.size(); ++mi) {
                    if (stop.stop_requested()) return Error{ErrorCode::canceled, "JVM archive inventory canceled"};
                    const auto &member = archive.value().members[mi];
                    if (member.directory) continue;
                    if (member.name.ends_with(".class")) {
                        std::string_view logical_path = member.name;
                        if (root_result.multi_release_active) {
                            if (mi >= selected_by_member.size() || !selected_by_member[mi]) continue;
                            logical_path = selected_by_member[mi]->logical_path;
                        } else if (member.name.starts_with("META-INF/versions/")) continue;
                        if (root_result.classes >= limits.max_classes - classes) return Error{ErrorCode::resource_limit, "JVM path exceeds its class-count limit"};
                        auto bytes = account(member.uncompressed_size, total_class_bytes, limits.max_total_class_bytes, "class"); if (!bytes) return bytes.error();
                        if (logical_path == "module-info.class" && root.kind == JvmPathRootKind::module_path) {
                            auto loaded = load_jvm_jar_class(archive.value(), mi, stop, jar_limits); if (!loaded) return loaded.error();
                            if (!loaded.value().metadata.jvm || !loaded.value().metadata.jvm->module) return malformed("module-info.class does not contain a Module attribute");
                            if (root_module_metadata[ri]) return malformed("JVM module-path archive contains duplicate root module descriptors");
                            auto row = std::move(*loaded.value().metadata.jvm); row.defining_loader = "jvm-path-root-" + std::to_string(ri);
                            root_result.module_name = row.module->name; root_module_metadata[ri] = metadata.size();
                            metadata.push_back(std::move(row));
                            continue;
                        }
                        if (logical_path == "module-info.class" || logical_path.ends_with("/module-info.class")) continue;
                        auto loaded = load_jvm_jar_class(archive.value(), mi, stop, jar_limits); if (!loaded) return loaded.error();
                        if (!loaded.value().metadata.jvm) return malformed("loaded JVM archive class has no JVM metadata");
                        auto row = std::move(*loaded.value().metadata.jvm); row.defining_loader = "jvm-path-root-" + std::to_string(ri);
                        if (root.kind == JvmPathRootKind::class_path) {
                            if (row.class_name.size() > limits.max_selection_path_bytes ||
                                logical_path.size() > limits.max_selection_path_bytes - row.class_name.size())
                                return Error{ErrorCode::resource_limit, "JVM class-path definition paths exceed their byte limit"};
                            const auto partial_bytes = row.class_name.size() + logical_path.size();
                            if (member.name.size() > limits.max_selection_path_bytes - partial_bytes)
                                return Error{ErrorCode::resource_limit, "JVM class-path definition paths exceed their byte limit"};
                            const auto path_bytes = partial_bytes + member.name.size();
                            if (class_path_class_path_bytes > limits.max_selection_path_bytes - path_bytes)
                                return Error{ErrorCode::resource_limit, "JVM class-path definition paths exceed their byte limit"};
                            class_path_class_path_bytes += path_bytes;
                            const std::string_view expected_name(logical_path.data(), logical_path.size() - std::string_view(".class").size());
                            output.class_path_classes.push_back({ri, row.class_name, std::string(logical_path), member.name,
                                member.data_offset, member.uncompressed_size, row.class_name == expected_name, {}});
                        }
                        root_packages[ri].insert(package_of(row.class_name));
                        metadata.push_back(std::move(row));
                        ++classes; ++root_result.classes;
                    } else if (root.kind == JvmPathRootKind::class_path && member.name.starts_with("META-INF/services/")) {
                        const auto service = std::string_view(member.name).substr(std::string_view("META-INF/services/").size());
                        if (service.empty() || service.find('/') != std::string_view::npos) continue;
                        if (member.uncompressed_size > limits.max_service_bytes || service_bytes > limits.max_service_bytes - member.uncompressed_size)
                            return Error{ErrorCode::resource_limit, "JVM path workspace exceeds its service-file byte limit"};
                        service_bytes += member.uncompressed_size;
                        auto bytes = extract_jar_member(archive.value(), mi, stop, jar_limits); if (!bytes) return bytes.error();
                        auto added = add_service_file(bytes.value(), service, unnamed, service_rows, limits); if (!added) return added.error();
                    }
                }
            }
            if (root.kind == JvmPathRootKind::module_path && !root_module_metadata[ri]) {
                root_result.status = JvmPathRootStatus::missing_module_descriptor;
            }
            output.roots.push_back(std::move(root_result));
        }

        const auto path_key = [](const std::filesystem::path &path) {
            const auto utf8 = path.generic_u8string();
            std::string key(reinterpret_cast<const char *>(utf8.data()), utf8.size());
#ifdef _WIN32
            std::transform(key.begin(), key.end(), key.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
#endif
            return key;
        };
        std::vector<std::string> root_path_keys(roots.size());
        for (std::size_t i = 0; i < roots.size(); ++i) {
            std::error_code ec;
            const auto absolute = std::filesystem::absolute(roots[i].path, ec);
            if (ec) return Error{ErrorCode::io, "cannot normalize JVM class-path root: " + ec.message()};
            root_path_keys[i] = path_key(absolute.lexically_normal());
        }
        std::vector<std::vector<std::size_t>> references_by_root(roots.size());
        std::vector<std::optional<std::size_t>> resolved_reference_targets;
        for (std::size_t source = 0; source < roots.size(); ++source) {
            if (roots[source].kind != JvmPathRootKind::class_path) continue;
            for (const auto &uri : manifest_class_path[source]) {
                JvmClassPathReference reference;
                reference.declaring_root_index = source;
                reference.uri = uri;
                auto relative = decode_class_path_uri(uri);
                if (!relative) {
                    reference.status = relative.error().code == ErrorCode::unsupported
                        ? JvmClassPathReferenceStatus::unsupported_uri
                        : JvmClassPathReferenceStatus::malformed_uri;
                } else {
                    const auto target_path = (roots[source].path.parent_path() /
                        std::filesystem::path(relative.value())).lexically_normal();
                    std::error_code ec;
                    const auto target_absolute = std::filesystem::absolute(target_path, ec);
                    if (ec) return Error{ErrorCode::io, "cannot resolve JVM manifest Class-Path URI: " + ec.message()};
                    const auto target_key = path_key(target_absolute.lexically_normal());
                    std::optional<std::size_t> match;
                    bool ambiguous = false;
                    for (std::size_t candidate = 0; candidate < roots.size(); ++candidate) {
                        if (roots[candidate].kind != JvmPathRootKind::class_path || root_path_keys[candidate] != target_key) continue;
                        if (match) { ambiguous = true; break; }
                        match = candidate;
                    }
                    if (ambiguous) reference.status = JvmClassPathReferenceStatus::ambiguous;
                    else if (match) {
                        reference.status = JvmClassPathReferenceStatus::resolved;
                        reference.target_root_index = *match;
                    } else reference.status = JvmClassPathReferenceStatus::not_supplied;
                }
                const auto reference_index = output.class_path_references.size();
                output.class_path_references.push_back(std::move(reference));
                references_by_root[source].push_back(reference_index);
                resolved_reference_targets.push_back(output.class_path_references.back().target_root_index);
            }
        }
        std::vector<bool> class_path_visited(roots.size(), false), class_path_active(roots.size(), false);
        std::function<Result<bool>(std::size_t)> append_class_path = [&](std::size_t root_index) -> Result<bool> {
            if (class_path_active[root_index]) return true;
            if (class_path_visited[root_index]) return true;
            class_path_active[root_index] = true;
            class_path_visited[root_index] = true;
            output.class_path_search_order.push_back(root_index);
            for (const auto reference_index : references_by_root[root_index]) {
                const auto target = resolved_reference_targets[reference_index];
                if (!target) continue;
                if (class_path_active[*target]) {
                    output.class_path_references[reference_index].status = JvmClassPathReferenceStatus::cycle;
                    continue;
                }
                auto appended = append_class_path(*target);
                if (!appended) return appended.error();
            }
            class_path_active[root_index] = false;
            return true;
        };
        for (std::size_t i = 0; i < roots.size(); ++i) {
            if (roots[i].kind != JvmPathRootKind::class_path) continue;
            auto appended = append_class_path(i);
            if (!appended) return appended.error();
        }

        // Path provenance establishes package ownership for classes in a module root.
        // Keep descriptor-declared packages and append only packages seen at that root.
        for (std::size_t ri = 0; ri < roots.size(); ++ri) {
            if (root_module_metadata[ri]) {
                auto &module_row = metadata[*root_module_metadata[ri]];
                for (const auto &package : root_packages[ri])
                    if (std::find(module_row.module_packages.begin(), module_row.module_packages.end(), package) == module_row.module_packages.end())
                        module_row.module_packages.push_back(package);
            }
        }
        bool has_classpath = std::any_of(roots.begin(), roots.end(), [](const auto &root) { return root.kind == JvmPathRootKind::class_path; });
        if (has_classpath) {
            std::set<std::string> names;
            for (const auto &item : metadata) if (item.module) names.insert(item.module->name);
            std::string synthetic_name = "hexlab.unnamed.classpath";
            for (std::size_t suffix = 1; names.contains(synthetic_name); ++suffix) synthetic_name = "hexlab.unnamed.classpath." + std::to_string(suffix);
            unnamed.name = synthetic_name;
            std::vector<std::string> classpath_packages;
            for (std::size_t ri = 0; ri < roots.size(); ++ri) if (roots[ri].kind == JvmPathRootKind::class_path)
                classpath_packages.insert(classpath_packages.end(), root_packages[ri].begin(), root_packages[ri].end());
            std::sort(classpath_packages.begin(), classpath_packages.end());
            classpath_packages.erase(std::unique(classpath_packages.begin(), classpath_packages.end()), classpath_packages.end());
            JvmMetadata synthetic; synthetic.class_name = "module-info"; synthetic.module = std::move(unnamed);
            synthetic.module_packages = std::move(classpath_packages);
            classpath_metadata_index = metadata.size(); metadata.push_back(std::move(synthetic));
        }
        auto nests = link_nest_relations(metadata, stop, limits.max_classes);
        if (!nests) return nests.error();
        output.nest_relations = std::move(nests.value());
        auto linked = link_jvm_metadata_workspace(metadata, stop, limits.linking); if (!linked) return linked.error();
        output.graph = std::move(linked.value());
        if (classpath_metadata_index) {
            const auto &synthetic_name = metadata[*classpath_metadata_index].module->name;
            for (std::size_t i = 0; i < output.graph.module_graph.modules.size(); ++i)
                if (output.graph.module_graph.modules[i].name == synthetic_name && !output.graph.module_graph.modules[i].duplicate_definition) {
                    output.unnamed_classpath_module = i; break;
                }
        }
        for (auto &definition : output.class_path_classes)
            definition.module_definition = output.unnamed_classpath_module;
        return output;
    } catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "cannot allocate bounded JVM path workspace"}; }
}

Result<JvmClassPathLookup> resolve_jvm_class_path_class(
        const JvmModulePathWorkspace &workspace, std::string_view binary_name) {
    if (binary_name.empty() || binary_name.size() > 4096 || binary_name.front() == '.' ||
        binary_name.back() == '.' || binary_name.find_first_of("/\\;[") != std::string_view::npos ||
        binary_name.find('\0') != std::string_view::npos)
        return Error{binary_name.size() > 4096 ? ErrorCode::resource_limit : ErrorCode::invalid_argument,
            "JVM class-path lookup requires a bounded Java binary class name"};
    try {
        std::string resource_path(binary_name);
        bool segment_start = true;
        for (auto &character : resource_path) {
            if (character == '.') {
                if (segment_start) return Error{ErrorCode::invalid_argument, "JVM class-path lookup name has an empty package segment"};
                character = '/';
                segment_start = true;
            } else {
                segment_start = false;
            }
        }
        if (segment_start) return Error{ErrorCode::invalid_argument, "JVM class-path lookup name has an empty class segment"};
        resource_path += ".class";
        JvmClassPathLookup result;
        result.requested_binary_name.assign(binary_name);
        for (const auto root_index : workspace.class_path_search_order) {
            if (root_index >= workspace.roots.size())
                return Error{ErrorCode::invalid_argument, "JVM class-path workspace has an invalid search-order root"};
            for (std::size_t index = 0; index < workspace.class_path_classes.size(); ++index) {
                const auto &definition = workspace.class_path_classes[index];
                if (definition.root_index >= workspace.roots.size())
                    return Error{ErrorCode::invalid_argument, "JVM class-path workspace has an invalid definition root"};
                if (definition.root_index != root_index || definition.resource_path != resource_path) continue;
                if (!result.selected_definition) {
                    result.selected_definition = index;
                    result.module_definition = definition.module_definition;
                    result.status = definition.class_name_matches_path
                        ? JvmClassPathLookupStatus::resolved : JvmClassPathLookupStatus::class_name_mismatch;
                } else {
                    result.shadowed_definitions.push_back(index);
                }
            }
        }
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate JVM class-path lookup result"};
    }
}

Result<JvmModuleConfiguration> resolve_jvm_module_configuration(
    const JvmModulePathWorkspace &workspace, std::span<const std::string_view> root_module_names,
    std::stop_token stop, std::size_t max_modules, std::size_t max_work) {
    const auto &graph = workspace.graph.module_graph;
    if (root_module_names.empty() || root_module_names.size() > 256 ||
        max_modules == 0 || max_modules > 4096 || max_work == 0 || max_work > 1'000'000)
        return Error{ErrorCode::invalid_argument, "JVM module configuration limits or root set are invalid"};
    try {
        std::vector<std::vector<std::size_t>> outgoing(graph.modules.size());
        std::size_t work = 0;
        for (std::size_t index = 0; index < graph.edges.size(); ++index) {
            if ((index & 1023u) == 0 && stop.stop_requested())
                return Error{ErrorCode::canceled, "JVM module configuration resolution canceled"};
            const auto &edge = graph.edges[index];
            if (edge.kind != JvmModuleLinkEdgeKind::requires_module) continue;
            if (edge.source_definition >= graph.modules.size())
                return malformed("JVM requires edge has an invalid source module index");
            outgoing[edge.source_definition].push_back(index);
            if (++work > max_work)
                return Error{ErrorCode::resource_limit, "JVM module configuration edge budget exceeded"};
        }

        JvmModuleConfiguration result;
        result.roots.reserve(root_module_names.size());
        std::vector<bool> selected(graph.modules.size());
        std::deque<std::size_t> pending;
        std::set<std::string_view> seen_names;
        for (const auto name : root_module_names) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "JVM module configuration resolution canceled"};
            if (name.empty() || name.size() > 4096 || name.find('\0') != std::string_view::npos ||
                !seen_names.insert(name).second)
                return Error{ErrorCode::invalid_argument, "JVM module configuration root name is empty, oversized, or duplicated"};
            JvmModuleConfigurationRoot root;
            root.name.assign(name);
            std::optional<std::size_t> match;
            std::size_t matches = 0;
            for (std::size_t index = 0; index < graph.modules.size(); ++index) {
                if ((index & 1023u) == 0 && stop.stop_requested())
                    return Error{ErrorCode::canceled, "JVM module root lookup canceled"};
                if (++work > max_work)
                    return Error{ErrorCode::resource_limit, "JVM module root lookup budget exceeded"};
                if (graph.modules[index].name != name) continue;
                match = index;
                ++matches;
            }
            if (!matches) {
                root.status = JvmModuleLinkStatus::missing;
                result.complete = false;
            } else if (matches != 1 || graph.modules[*match].duplicate_definition) {
                root.status = JvmModuleLinkStatus::duplicate_definition;
                result.complete = false;
            } else {
                root.status = JvmModuleLinkStatus::resolved;
                root.module_definition = *match;
                if (!selected[*match]) {
                    if (result.resolved_modules.size() >= max_modules)
                        return Error{ErrorCode::resource_limit, "JVM root module count exceeds configured module limit"};
                    selected[*match] = true;
                    pending.push_back(*match);
                    result.resolved_modules.push_back(*match);
                }
            }
            result.roots.push_back(std::move(root));
        }

        while (!pending.empty()) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "JVM module configuration resolution canceled"};
            const auto source = pending.front();
            pending.pop_front();
            for (const auto edge_index : outgoing[source]) {
                if (++work > max_work)
                    return Error{ErrorCode::resource_limit, "JVM module configuration work budget exceeded"};
                const auto &edge = graph.edges[edge_index];
                if (edge.status == JvmModuleLinkStatus::missing_optional) {
                    result.omitted_optional_edges.push_back(edge_index);
                    continue;
                }
                if (edge.status != JvmModuleLinkStatus::resolved || !edge.target_definition ||
                    *edge.target_definition >= graph.modules.size()) {
                    result.unresolved_required_edges.push_back(edge_index);
                    result.complete = false;
                    continue;
                }
                const auto target = *edge.target_definition;
                if (!selected[target]) {
                    if (result.resolved_modules.size() >= max_modules)
                        return Error{ErrorCode::resource_limit, "JVM resolved module count exceeds configured limit"};
                    selected[target] = true;
                    result.resolved_modules.push_back(target);
                    pending.push_back(target);
                }
            }
        }
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate bounded JVM module configuration"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "JVM module configuration exceeds container limits"};
    }
}
} // namespace hexlab
