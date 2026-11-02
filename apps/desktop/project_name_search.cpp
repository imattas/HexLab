#include "project_name_search.hpp"

#include "hexlab/analysis/references.hpp"
#include "hexlab/core/sha256.hpp"
#include "hexlab/database/project_state.hpp"
#include "hexlab/workspace/project_analysis.hpp"

#include <wx/stdpaths.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cwctype>
#include <fstream>
#include <map>
#include <set>
#include <span>
#include <thread>
#include <tuple>

namespace hexlab::desktop {
namespace {
constexpr std::array<std::byte, 8> cache_magic{
    std::byte{static_cast<std::uint8_t>('H')}, std::byte{static_cast<std::uint8_t>('L')},
    std::byte{static_cast<std::uint8_t>('N')}, std::byte{static_cast<std::uint8_t>('I')},
    std::byte{static_cast<std::uint8_t>('D')}, std::byte{static_cast<std::uint8_t>('X')},
    std::byte{static_cast<std::uint8_t>('1')}, std::byte{0}};
constexpr std::uint32_t cache_version = 2;
constexpr std::size_t cache_bytes_limit = 16u * 1024u * 1024u;
constexpr std::size_t record_limit = 50000;
constexpr std::size_t per_project_input_limit = 128u * 1024u * 1024u;
constexpr std::uint64_t aggregate_input_limit = 512u * 1024u * 1024u;
constexpr std::size_t project_limit = 256;
constexpr std::size_t directory_entry_limit = 4096;
constexpr std::size_t name_byte_limit = 2048;

void put_u8(std::vector<std::byte> &out, std::uint8_t value) { out.push_back(std::byte{value}); }
void put_u32(std::vector<std::byte> &out, std::uint32_t value) {
    for (unsigned shift = 0; shift != 32; shift += 8) out.push_back(std::byte{static_cast<std::uint8_t>(value >> shift)});
}
void put_u64(std::vector<std::byte> &out, std::uint64_t value) {
    for (unsigned shift = 0; shift != 64; shift += 8) out.push_back(std::byte{static_cast<std::uint8_t>(value >> shift)});
}
bool take_bytes(std::span<const std::byte> bytes, std::size_t &cursor, std::span<std::byte> output) {
    if (cursor > bytes.size() || output.size() > bytes.size() - cursor) return false;
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(cursor), output.size(), output.begin());
    cursor += output.size();
    return true;
}
bool take_u8(std::span<const std::byte> bytes, std::size_t &cursor, std::uint8_t &value) {
    if (cursor >= bytes.size()) return false;
    value = std::to_integer<std::uint8_t>(bytes[cursor++]);
    return true;
}
bool take_u32(std::span<const std::byte> bytes, std::size_t &cursor, std::uint32_t &value) {
    if (cursor > bytes.size() || bytes.size() - cursor < 4) return false;
    value = 0;
    for (unsigned shift = 0; shift != 32; shift += 8)
        value |= std::uint32_t{std::to_integer<std::uint8_t>(bytes[cursor++])} << shift;
    return true;
}
bool take_u64(std::span<const std::byte> bytes, std::size_t &cursor, std::uint64_t &value) {
    if (cursor > bytes.size() || bytes.size() - cursor < 8) return false;
    value = 0;
    for (unsigned shift = 0; shift != 64; shift += 8)
        value |= std::uint64_t{std::to_integer<std::uint8_t>(bytes[cursor++])} << shift;
    return true;
}
std::optional<Sha256Digest> digest(std::span<const std::byte> bytes) {
    Sha256 hash;
    if (!hash.update(bytes)) return {};
    return hash.digest();
}
std::filesystem::path cache_path(const std::filesystem::path &project,
                                 const database::ProjectUuid &uuid) {
    const auto root = std::filesystem::path(wxStandardPaths::Get().GetUserLocalDataDir().ToStdWstring()) /
                      L"ProjectNameIndex";
    const auto normalized = std::filesystem::absolute(project).lexically_normal().u8string();
    std::vector<std::byte> key;
    key.reserve(normalized.size() + uuid.size());
    for (const auto ch : normalized) key.push_back(std::byte{static_cast<std::uint8_t>(ch)});
    key.insert(key.end(), uuid.begin(), uuid.end());
    const auto key_hash = digest(key);
    return root / (key_hash ? wxString::FromUTF8(digest_hex(*key_hash)).ToStdWstring() + L".hlnx"
                            : std::wstring(L"invalid.hlnx"));
}
bool cache_identity_matches(const ProjectNameSource &source, const ProjectNameSource &cached) {
    return source.path == cached.path && source.uuid == cached.uuid && source.input == cached.input &&
           source.revisions == cached.revisions;
}

std::optional<ProjectNameSource> read_cache(const std::filesystem::path &path,
                                             const ProjectNameSource &identity) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || !std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status)) return {};
    const auto size = std::filesystem::file_size(path, error);
    if (error || size < 128 || size > cache_bytes_limit) return {};
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    std::ifstream file(path, std::ios::binary);
    if (!file || !file.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) return {};
    const auto payload_size = bytes.size() - 32;
    const auto expected_hash = digest(std::span(bytes).first(payload_size));
    if (!expected_hash || !std::equal(expected_hash->begin(), expected_hash->end(), bytes.begin() +
                                      static_cast<std::ptrdiff_t>(payload_size))) return {};
    std::size_t cursor = 0;
    std::array<std::byte, 8> magic{};
    std::uint32_t version = 0, count = 0;
    std::uint8_t has_external_fingerprint = 0, complete = 0;
    if (!take_bytes(bytes, cursor, magic) || magic != cache_magic || !take_u32(bytes, cursor, version) ||
        version != cache_version) return {};
    ProjectNameSource cached = identity;
    if (!take_bytes(bytes, cursor, cached.uuid) || !take_u64(bytes, cursor, cached.input.size) ||
        !take_bytes(bytes, cursor, cached.input.sha256) || !take_u64(bytes, cursor, cached.revisions.edit) ||
        !take_u64(bytes, cursor, cached.revisions.bytes) || !take_u64(bytes, cursor, cached.revisions.decisions) ||
        !take_u8(bytes, cursor, has_external_fingerprint) || has_external_fingerprint > 1) return {};
    if (has_external_fingerprint) {
        Sha256Digest fingerprint{};
        if (!take_bytes(bytes, cursor, fingerprint)) return {};
        cached.external_input_fingerprint = fingerprint;
    }
    if (!take_u8(bytes, cursor, complete) || complete > 1) return {};
    cached.complete = complete != 0;
    if (!take_u32(bytes, cursor, count) || count > record_limit) return {};
    if (cached.uuid != identity.uuid || cached.input != identity.input || cached.revisions != identity.revisions) return {};
    cached.records.reserve(count);
    for (std::uint32_t row = 0; row < count; ++row) {
        std::uint8_t scope = 0, kind = 0, reference = 0;
        std::uint32_t space = 0, name_size = 0;
        std::uint64_t offset = 0;
        if (!take_u8(bytes, cursor, scope) || scope > static_cast<std::uint8_t>(NamedLocationScope::sections) ||
            !take_u8(bytes, cursor, kind) || kind > 1 || !take_u8(bytes, cursor, reference) || reference > 1 ||
            !take_u32(bytes, cursor, space) ||
            !take_u64(bytes, cursor, offset) || !take_u32(bytes, cursor, name_size) ||
            name_size == 0 || name_size > name_byte_limit || cursor > payload_size ||
            name_size > payload_size - cursor) return {};
        std::string name(reinterpret_cast<const char *>(bytes.data() + cursor), name_size);
        cursor += name_size;
        Location location = kind == 0 ? Location{Address{AddressSpaceId{space}, offset}} : Location{FileOffset{offset}};
        cached.records.push_back({std::move(name), std::move(location), static_cast<NamedLocationScope>(scope), reference != 0});
    }
    if (cursor != payload_size || !cache_identity_matches(identity, cached)) return {};
    return cached;
}

void write_cache(const std::filesystem::path &path, const ProjectNameSource &source) {
    if (source.records.size() > record_limit) return;
    std::vector<std::byte> bytes;
    bytes.reserve(std::min<std::size_t>(cache_bytes_limit, 128 + source.records.size() * 64));
    bytes.insert(bytes.end(), cache_magic.begin(), cache_magic.end());
    put_u32(bytes, cache_version);
    bytes.insert(bytes.end(), source.uuid.begin(), source.uuid.end());
    put_u64(bytes, source.input.size);
    bytes.insert(bytes.end(), source.input.sha256.begin(), source.input.sha256.end());
    put_u64(bytes, source.revisions.edit);
    put_u64(bytes, source.revisions.bytes);
    put_u64(bytes, source.revisions.decisions);
    put_u8(bytes, source.external_input_fingerprint ? 1u : 0u);
    if (source.external_input_fingerprint)
        bytes.insert(bytes.end(), source.external_input_fingerprint->begin(),
                     source.external_input_fingerprint->end());
    put_u8(bytes, source.complete ? 1u : 0u);
    put_u32(bytes, static_cast<std::uint32_t>(source.records.size()));
    for (const auto &record : source.records) {
        if (bytes.size() >= cache_bytes_limit || record.name.empty() || record.name.size() > name_byte_limit) return;
        const auto *address = std::get_if<Address>(&record.location);
        put_u8(bytes, static_cast<std::uint8_t>(record.scope));
        put_u8(bytes, address ? 0u : 1u);
        put_u8(bytes, record.reference ? 1u : 0u);
        put_u32(bytes, address ? address->space.value : 0);
        put_u64(bytes, address ? address->offset : std::get<FileOffset>(record.location).value);
        put_u32(bytes, static_cast<std::uint32_t>(record.name.size()));
        for (const auto ch : record.name) bytes.push_back(std::byte{static_cast<std::uint8_t>(ch)});
    }
    const auto hash = digest(bytes);
    if (!hash || bytes.size() + hash->size() > cache_bytes_limit) return;
    bytes.insert(bytes.end(), hash->begin(), hash->end());
    std::error_code error;
    std::filesystem::create_directories(path.parent_path(), error);
    if (error) return;
    const auto temp = path.parent_path() / (path.filename().wstring() + L".tmp-" +
        std::to_wstring(std::chrono::high_resolution_clock::now().time_since_epoch().count()) + L"-" +
        std::to_wstring(std::hash<std::thread::id>{}(std::this_thread::get_id())));
    {
        std::ofstream file(temp, std::ios::binary | std::ios::trunc);
        if (!file || !file.write(reinterpret_cast<const char *>(bytes.data()),
                                 static_cast<std::streamsize>(bytes.size())) || !file.flush()) {
            file.close();
            std::filesystem::remove(temp, error);
            return;
        }
    }
    error.clear();
    std::filesystem::rename(temp, path, error);
    if (error) {
        error.clear();
        const auto status = std::filesystem::symlink_status(path, error);
        if (!error && std::filesystem::is_regular_file(status) && !std::filesystem::is_symlink(status)) {
            std::filesystem::remove(path, error);
            if (!error) std::filesystem::rename(temp, path, error);
        }
    }
    if (error) std::filesystem::remove(temp, error);
}

std::string ordinal_name(std::string_view prefix, std::uint64_t value) {
    return std::string(prefix) + std::to_string(value);
}

void collect_project_records(ProjectNameSource &source, const ProjectSnapshot &project,
                             database::ProjectStore &store, std::stop_token stop, bool &truncated) {
    const auto add = [&](NamedLocationScope scope, std::string_view name, Location location,
                         bool reference = false) {
        if (stop.stop_requested()) return false;
        if (name.empty() || name.size() > name_byte_limit || source.records.size() >= record_limit) {
            if (source.records.size() >= record_limit) truncated = true;
            return source.records.size() < record_limit;
        }
        source.records.push_back({std::string(name), std::move(location), scope, reference});
        return true;
    };
    if (project.loaded) {
        const auto &metadata = project.loaded->metadata;
        for (const auto &symbol : metadata.exports) {
            const auto name = symbol.name ? *symbol.name : ordinal_name("ordinal ", symbol.ordinal);
            if (symbol.address && !add(NamedLocationScope::symbols, name, *symbol.address)) return;
        }
        for (const auto &symbol : metadata.imports) {
            const auto name = symbol.name ? *symbol.name : symbol.ordinal
                ? ordinal_name("ordinal ", *symbol.ordinal) : std::string{};
            if (!name.empty() && !add(NamedLocationScope::symbols, name, symbol.iat)) return;
        }
        if (metadata.elf) {
            for (const auto &symbol : metadata.elf->symbols)
                if (symbol.address && symbol.state == ElfSymbolState::defined &&
                    !add(NamedLocationScope::symbols, symbol.name, *symbol.address)) return;
            if (metadata.elf->dwarf_info)
                for (const auto &symbol : metadata.elf->dwarf_info->symbols) {
                    if (symbol.kind == symbols::SymbolKind::entry_point) {
                        if (!add(NamedLocationScope::symbols, symbol.name,
                                 Address{project.loaded->image->layout().space.id, symbol.address})) return;
                    } else if (symbol.kind == symbols::SymbolKind::function && !symbol.ranges.empty()) {
                        if (!add(NamedLocationScope::symbols, symbol.name,
                                 Address{project.loaded->image->layout().space.id, symbol.ranges.front().begin})) return;
                    }
                }
        }
        if (metadata.macho) {
            for (const auto &symbol : metadata.macho->symbols)
                if (symbol.address && symbol.state == MachOSymbolState::defined &&
                    !add(NamedLocationScope::symbols, symbol.name, *symbol.address)) return;
            for (const auto &symbol : metadata.macho->dyld_exports)
                if (symbol.is_definition() && !add(NamedLocationScope::symbols, symbol.name, *symbol.address)) return;
        }
        if (metadata.pe)
            for (const auto &symbol : metadata.pe->pdb_symbols)
                if (symbol.address && !add(NamedLocationScope::symbols, symbol.name, *symbol.address)) return;
        for (const auto &segment : project.loaded->image->layout().segments) {
            if (segment.name.empty()) continue;
            if (!add(NamedLocationScope::sections, "section:" + segment.name, segment.begin) ||
                !add(NamedLocationScope::sections, "segment:" + segment.name, segment.begin)) return;
        }
    }
    if (project.state && project.state->user) {
        for (const auto &annotation : project.state->user->annotations)
            if (!add(NamedLocationScope::annotations, annotation.name, annotation.location)) return;
        for (const auto &bookmark : project.state->user->bookmarks)
            if (!add(NamedLocationScope::bookmarks, bookmark.label, bookmark.location)) return;
        for (const auto &function : project.state->user->decisions.functions) {
            const auto name = presentation_name(project, function.entry);
            if (!add(NamedLocationScope::functions, name, function.entry)) return;
        }
        // Use only references already persisted for this project analysis key;
        // indexing does not schedule a reference-analysis pass.
        if (project.loaded && project.loaded->image) {
            const auto key = project_analysis_key(project, project.analysis_options);
            if (key) {
                auto cached = store.load_reference_cache(key.value(), stop);
                if (cached && cached.value().status == database::CacheStatus::hit && cached.value().index) {
                    std::map<std::pair<std::uint32_t, std::uint64_t>, std::vector<std::string>> names;
                    for (const auto &record : source.records)
                        if (!record.reference && record.scope == NamedLocationScope::symbols)
                            if (const auto *address = std::get_if<Address>(&record.location))
                                names[{address->space.value, address->offset}].push_back(record.name);
                    for (const auto &reference : cached.value().index->all()) {
                        if (stop.stop_requested()) return;
                        const auto *target = std::get_if<Location>(&reference.target);
                        const auto *address = target ? std::get_if<Address>(target) : nullptr;
                        if (!address) continue;
                        const auto found = names.find({address->space.value, address->offset});
                        if (found == names.end()) continue;
                        for (const auto &name : found->second)
                            if (!add(NamedLocationScope::symbols, name + " [reference]", reference.source, true)) return;
                    }
                }
            }
        }
    }
    if (source.records.size() >= record_limit) truncated = true;
    std::stable_sort(source.records.begin(), source.records.end(), [](const auto &left, const auto &right) {
        const auto left_folded = wxString::FromUTF8(left.name).Lower();
        const auto right_folded = wxString::FromUTF8(right.name).Lower();
        if (left.scope != right.scope) return left.scope < right.scope;
        if (left_folded != right_folded) return left_folded < right_folded;
        if (left.name != right.name) return left.name < right.name;
        if (left.location.index() != right.location.index()) return left.location.index() < right.location.index();
        if (const auto *a = std::get_if<Address>(&left.location)) {
            const auto b = std::get<Address>(right.location);
            return std::tie(a->space.value, a->offset) < std::tie(b.space.value, b.offset);
        }
        return std::get<FileOffset>(left.location).value < std::get<FileOffset>(right.location).value;
    });
}

} // namespace

Result<ProjectFolderNameIndex> index_project_folder_names(
    const std::filesystem::path &folder, const std::atomic_bool *cancelled) {
    ProjectFolderNameIndex result;
    std::error_code error;
    result.folder = std::filesystem::absolute(folder, error).lexically_normal();
    if (error || !std::filesystem::is_directory(result.folder, error) || error)
        return Error{ErrorCode::invalid_argument, "Select an accessible folder of saved HexLab projects"};
    std::vector<std::filesystem::path> projects;
    std::size_t examined = 0;
    for (std::filesystem::directory_iterator it(result.folder,
             std::filesystem::directory_options::skip_permission_denied, error), end;
         !error && it != end; it.increment(error)) {
        if (cancelled && cancelled->load(std::memory_order_relaxed))
            return Error{ErrorCode::canceled, "Project name indexing canceled"};
        if (++examined > directory_entry_limit) {
            result.truncated = true;
            result.limitation = "folder scan stopped after 4,096 direct children";
            break;
        }
        const auto path = it->path();
        auto extension = path.extension().wstring();
        std::transform(extension.begin(), extension.end(), extension.begin(), towlower);
        if (extension != L".hxproj") continue;
        const auto status = it->symlink_status(error);
        if (error) { error.clear(); continue; }
        if (!std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status)) continue;
        projects.push_back(std::filesystem::absolute(path, error).lexically_normal());
        if (error) { error.clear(); projects.pop_back(); }
        if (projects.size() >= project_limit) {
            result.truncated = true;
            result.limitation = "folder scan stopped at the 256-project limit";
            break;
        }
    }
    std::sort(projects.begin(), projects.end());
    std::uint64_t total_input = 0;
    for (const auto &path : projects) {
        if (cancelled && cancelled->load(std::memory_order_relaxed))
            return Error{ErrorCode::canceled, "Project name indexing canceled"};
        std::stop_source operation_stop;
        std::jthread cancellation_bridge;
        if (cancelled) {
            cancellation_bridge = std::jthread([cancelled, &operation_stop](std::stop_token stop) {
                while (!stop.stop_requested()) {
                    if (cancelled->load(std::memory_order_relaxed)) {
                        operation_stop.request_stop();
                        return;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                }
            });
        }
        const auto stop = operation_stop.get_token();
        auto store = database::ProjectStore::open(path, database::ProjectMode::read_only, stop);
        if (!store) { if (cancellation_bridge.joinable()) cancellation_bridge.request_stop(); result.truncated = true; continue; }
        auto state = store.value()->snapshot();
        if (!state || state.value()->input.size > per_project_input_limit ||
            state.value()->input.size > aggregate_input_limit - std::min(total_input, aggregate_input_limit)) {
            if (cancellation_bridge.joinable()) cancellation_bridge.request_stop();
            result.truncated = true;
            if (result.limitation.empty()) result.limitation = "one or more projects exceeded the embedded-input scan budget";
            continue;
        }
        total_input += state.value()->input.size;
        ProjectNameSource identity{path, state.value()->uuid, state.value()->input,
                                   state.value()->revisions, {}, {}};
        const auto index_path = cache_path(path, identity.uuid);
        if (auto cached = read_cache(index_path, identity)) {
            result.projects.push_back(std::move(*cached));
            if (cancellation_bridge.joinable()) cancellation_bridge.request_stop();
            continue;
        }
        auto session = ProjectSession::attach_deferred(store.value(), AnalysisOptions{}, stop);
        if (!session) {
            if (cancellation_bridge.joinable()) cancellation_bridge.request_stop();
            if (session.error().code == ErrorCode::canceled)
                return session.error();
            result.truncated = true;
            if (result.limitation.empty()) result.limitation = "one or more projects could not be indexed from their embedded input";
            continue;
        }
        const auto snapshot = session.value()->snapshot();
        if (!snapshot || !snapshot->loaded || !snapshot->loaded->image) {
            if (cancellation_bridge.joinable()) cancellation_bridge.request_stop();
            result.truncated = true;
            if (result.limitation.empty()) result.limitation = "one or more projects have no loaded image metadata";
            continue;
        }
        identity.external_input_fingerprint = snapshot->loaded->external_input_fingerprint;
        identity.complete = snapshot->loaded->metadata_complete;
        bool source_truncated = false;
        collect_project_records(identity, *snapshot, *store.value(), stop, source_truncated);
        if (cancellation_bridge.joinable()) cancellation_bridge.request_stop();
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Project name indexing canceled"};
        if (source_truncated) {
            result.truncated = true;
            if (result.limitation.empty()) result.limitation = "a project reached the 50,000-name index limit";
        }
        if (!identity.complete) {
            result.truncated = true;
            if (result.limitation.empty()) result.limitation = "one or more projects have incomplete parsed metadata";
        }
        write_cache(index_path, identity);
        result.projects.push_back(std::move(identity));
    }
    if (error) {
        result.truncated = true;
        if (result.limitation.empty()) result.limitation = "folder enumeration was incomplete";
    }
    return result;
}

NamedLocationSearch search_project_folder_names(
    const ProjectFolderNameIndex &index, const wxString &query, NamedLocationScope scope,
    NamedLocationSearchMode mode, const std::atomic_bool *cancelled) {
    NamedLocationSearch result;
    if (mode == NamedLocationSearchMode::fuzzy || query.length() > 256) return result;
    auto needle = query;
    needle.Trim(true).Trim(false).MakeLower();
    if (needle.length() < (mode == NamedLocationSearchMode::exact ? 1u : 2u)) return result;
    constexpr std::size_t result_limit = 4096, record_budget = 200000, byte_budget = 16u * 1024u * 1024u;
    std::size_t examined = 0, bytes = 0;
    for (const auto &project : index.projects) {
        if (!project.complete) result.truncated = true;
        for (const auto &record : project.records) {
            if (cancelled && cancelled->load(std::memory_order_relaxed)) return result;
            if (++examined > record_budget || record.name.size() > byte_budget - bytes) {
                result.truncated = true;
                result.limitation = "partial search: query budget reached; narrow the name or folder scope";
                break;
            }
            bytes += record.name.size();
            if (scope != NamedLocationScope::all && scope != record.scope) continue;
            auto name = wxString::FromUTF8(record.name);
            const auto folded = name.Lower();
            const bool matches = mode == NamedLocationSearchMode::exact ? folded == needle
                : mode == NamedLocationSearchMode::prefix ? folded.StartsWith(needle)
                : folded.Find(needle) != wxNOT_FOUND;
            if (!matches) continue;
            NamedLocationCandidate candidate;
            candidate.name = std::move(name);
            candidate.location = record.location;
            candidate.project_path = project.path;
            candidate.project_uuid = project.uuid;
            candidate.project_input = project.input;
            result.candidates.push_back(std::move(candidate));
            if (result.candidates.size() > result_limit) {
                result.truncated = true;
                result.limitation = "showing the first 4,096 matching project locations";
                break;
            }
        }
        if (result.candidates.size() > result_limit || examined > record_budget || bytes >= byte_budget) break;
    }
    if (result.candidates.size() > result_limit) result.candidates.resize(result_limit);
    if (index.truncated) {
        result.truncated = true;
        if (!index.limitation.empty()) {
            if (!result.limitation.empty()) result.limitation += "; ";
            result.limitation += index.limitation;
        }
    }
    std::stable_sort(result.candidates.begin(), result.candidates.end(), [](const auto &left, const auto &right) {
        const auto left_name = left.name.Lower(), right_name = right.name.Lower();
        if (left_name != right_name) return left_name < right_name;
        if (left.name != right.name) return left.name < right.name;
        const auto left_path = left.project_path ? left.project_path->generic_string() : std::string{};
        const auto right_path = right.project_path ? right.project_path->generic_string() : std::string{};
        if (left_path != right_path) return left_path < right_path;
        if (left.location.index() != right.location.index()) return left.location.index() < right.location.index();
        if (const auto *address = std::get_if<Address>(&left.location)) {
            const auto other = std::get<Address>(right.location);
            return std::tie(address->space.value, address->offset) < std::tie(other.space.value, other.offset);
        }
        return std::get<FileOffset>(left.location).value < std::get<FileOffset>(right.location).value;
    });
    return result;
}

} // namespace hexlab::desktop
