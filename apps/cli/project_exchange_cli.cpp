#include "project_exchange_cli.hpp"
#include "hexlab/image/file_publication.hpp"
#include "hexlab/workspace/project_exchange.hpp"
#include <algorithm>
#include <span>
#include <fstream>

namespace hexlab::cli::project_detail {
namespace { constexpr std::uint64_t max_exchange_bytes = 16u * 1024u * 1024u; }
namespace {
Result<Sha256Digest> hash_original_range(const ByteStorage &storage, FileOffset offset, std::uint64_t size) {
    if (offset.value > storage.size() || size > storage.size() - offset.value)
        return Error{ErrorCode::invalid_argument, "Type assignment byte range is outside the source input"};
    Sha256 hash;
    for (std::uint64_t done = 0; done < size;) {
        const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(64u * 1024u, size - done));
        auto bytes = storage.read_at(FileOffset{offset.value + done}, count);
        if (!bytes) return bytes.error();
        if (bytes.value().bytes.size() != count)
            return Error{ErrorCode::io, "Type assignment source range read was incomplete"};
        auto updated = hash.update(bytes.value().bytes);
        if (!updated) return updated.error();
        done += count;
    }
    return hash.digest();
}
Result<std::optional<types::LibraryAssignment::SourceBytes>> assignment_source_bytes(
    const ProjectSnapshot &snapshot, Location location, const types::Type &type,
    std::uint64_t &remaining_budget) {
    const auto *file = std::get_if<FileOffset>(&location);
    if (!file || !type.size() || !*type.size() || *type.size() > remaining_budget || !snapshot.original)
        return std::optional<types::LibraryAssignment::SourceBytes>{};
    if (file->value > snapshot.original->size() || *type.size() > snapshot.original->size() - file->value)
        return std::optional<types::LibraryAssignment::SourceBytes>{};
    auto digest = hash_original_range(*snapshot.original, *file, *type.size());
    if (!digest) return digest.error();
    remaining_budget -= *type.size();
    return std::optional<types::LibraryAssignment::SourceBytes>{{*type.size(), digest.value()}};
}
Result<bool> assignment_source_bytes_match(const ProjectSnapshot &snapshot,
                                           const types::LibraryAssignment &assignment) {
    if (!assignment.source_bytes || !snapshot.original) return false;
    const auto *file = std::get_if<FileOffset>(&assignment.location);
    if (!file || file->value > snapshot.original->size() ||
        assignment.source_bytes->size > snapshot.original->size() - file->value) return false;
    auto digest = hash_original_range(*snapshot.original, *file, assignment.source_bytes->size);
    if (!digest) return digest.error();
    return digest.value() == assignment.source_bytes->sha256;
}
}
Result<bool> type_assignment_source_bytes_match(const ProjectSnapshot &snapshot,
                                                const types::LibraryAssignment &assignment) {
    return assignment_source_bytes_match(snapshot, assignment);
}
Result<std::vector<std::byte>> read_exchange_file(const std::filesystem::path &path) {
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if (error) return Error{ErrorCode::io, "Cannot inspect exchange file: " + error.message()};
    if (size > max_exchange_bytes) return Error{ErrorCode::resource_limit, "Exchange file exceeds 16 MiB limit"};
    std::ifstream file(path, std::ios::binary);
    if (!file) return Error{ErrorCode::io, "Cannot open exchange file"};
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    if (!bytes.empty()) file.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!file || file.gcount() != static_cast<std::streamsize>(bytes.size()))
        return Error{ErrorCode::io, "Cannot read complete exchange file"};
    return bytes;
}
Result<bool> write_exchange_file(const ProjectSnapshot &snapshot, const std::filesystem::path &path, bool replace) {
    auto bytes = export_project_exchange(snapshot, static_cast<std::size_t>(max_exchange_bytes));
    if (!bytes) return bytes.error();
    auto publication = FilePublication::create(path, replace ? ExistingFilePolicy::replace : ExistingFilePolicy::reject,
                                               snapshot.protected_paths, {});
    if (!publication) return publication.error();
    auto appended = publication.value()->append(bytes.value());
    if (!appended) return appended.error();
    if (appended.value() != bytes.value().size()) return Error{ErrorCode::io, "Exchange output write was incomplete"};
    return publication.value()->publish();
}
Result<bool> write_type_library_file(const ProjectSnapshot &snapshot, const std::filesystem::path &path, bool replace) {
    types::LibraryBundle bundle;
    for (const auto &row : snapshot.state->user->types) {
        types::LibraryEntry entry{row.name, row.type};
        if (row.origin) entry.origin = types::LibraryTypeOrigin{row.origin->source_id, row.origin->section,
            row.origin->unit_offset, row.origin->record_offset, row.origin->record_size};
        entry.declaration_kind = static_cast<types::LibraryDeclarationKind>(row.declaration_kind);
        bundle.entries.push_back(std::move(entry));
    }
    Sha256 recipe_hash;
    auto recipe = encode_recipe(snapshot.state->recipe);
    if (!recipe) return recipe.error();
    auto recipe_updated = recipe_hash.update(recipe.value());
    if (!recipe_updated) return recipe_updated.error();
    bundle.source_identity = types::LibrarySourceIdentity{snapshot.state->input.size, snapshot.state->input.sha256,
                                                           recipe_hash.digest()};
    bundle.file_offset_identity = types::LibraryBinaryIdentity{snapshot.state->input.size, snapshot.state->input.sha256};
    std::uint64_t witness_budget = 64u * 1024u * 1024u;
    for (const auto &assignment : snapshot.state->user->type_assignments) {
        auto found = std::find_if(snapshot.state->user->types.begin(), snapshot.state->user->types.end(),
            [&](const auto &row) { return row.id == assignment.type_id; });
        if (found == snapshot.state->user->types.end()) return Error{ErrorCode::integrity, "Type assignment refers to missing definition"};
        auto source_bytes = assignment_source_bytes(snapshot, assignment.location, *found->type, witness_budget);
        if (!source_bytes) return source_bytes.error();
        bundle.assignments.push_back({assignment.location, found->name, std::move(source_bytes.value())});
    }
    auto bytes = types::encode_library_bundle(bundle);
    if (!bytes) return bytes.error();
    auto publication = FilePublication::create(path, replace ? ExistingFilePolicy::replace : ExistingFilePolicy::reject,
                                               snapshot.protected_paths, {});
    if (!publication) return publication.error();
    auto appended = publication.value()->append(bytes.value());
    if (!appended) return appended.error();
    if (appended.value() != bytes.value().size()) return Error{ErrorCode::io, "Type library output write was incomplete"};
    return publication.value()->publish();
}
Result<bool> write_type_library_header(const ProjectSnapshot &snapshot, const std::filesystem::path &path, bool replace) {
    types::LibraryBundle bundle;
    bundle.entries.reserve(snapshot.state->user->types.size());
    for (const auto &row : snapshot.state->user->types) {
        types::LibraryEntry entry{row.name, row.type};
        entry.declaration_kind = static_cast<types::LibraryDeclarationKind>(row.declaration_kind);
        bundle.entries.push_back(std::move(entry));
    }
    auto header = types::render_library_c_header(bundle);
    if (!header) return header.error();
    const auto bytes = std::as_bytes(std::span(header.value().data(), header.value().size()));
    auto publication = FilePublication::create(path, replace ? ExistingFilePolicy::replace : ExistingFilePolicy::reject,
                                               snapshot.protected_paths, {});
    if (!publication) return publication.error();
    auto appended = publication.value()->append(bytes);
    if (!appended) return appended.error();
    if (appended.value() != bytes.size()) return Error{ErrorCode::io, "C header output write was incomplete"};
    return publication.value()->publish();
}
Result<types::LibraryBundle> read_type_library_file(const std::filesystem::path &path) {
    auto bytes = read_exchange_file(path);
    if (!bytes) return bytes.error();
    return types::decode_library_bundle(bytes.value());
}
} // namespace hexlab::cli::project_detail
