#pragma once
#include "hexlab/core/location.hpp"
#include "hexlab/core/sha256.hpp"
#include "hexlab/types/types.hpp"
#include <optional>
#include <set>

namespace hexlab::types {
// Portable type metadata deliberately uses symbolic names and source offsets,
// never destination-local project/type IDs.
struct LibraryTypeOrigin {
    std::string source_id, section;
    std::uint64_t unit_offset = 0, record_offset = 0, record_size = 0;
    bool operator==(const LibraryTypeOrigin &) const = default;
};
enum class LibraryDeclarationKind : std::uint8_t { type, object, function };
struct LibraryEntry {
    std::string name;
    TypePtr type;
    std::optional<LibraryTypeOrigin> origin;
    LibraryDeclarationKind declaration_kind = LibraryDeclarationKind::type;
};
struct LibrarySourceIdentity {
    std::uint64_t input_size = 0;
    Sha256Digest input_sha256{};
    Sha256Digest recipe_sha256{};
    bool operator==(const LibrarySourceIdentity &) const = default;
};
struct LibraryAssignment {
    Address location;
    std::string type_name;
    bool operator==(const LibraryAssignment &) const = default;
};
struct LibraryBundle {
    std::vector<LibraryEntry> entries;
    std::optional<LibrarySourceIdentity> source_identity;
    std::vector<LibraryAssignment> assignments;
};
HEXLAB_TYPES_EXPORT Result<std::vector<std::byte>> encode_library(std::span<const LibraryEntry>,
                                                                  std::size_t max_bytes = 16u * 1024u * 1024u);
HEXLAB_TYPES_EXPORT Result<std::vector<LibraryEntry>> decode_library(std::span<const std::byte>,
                                                                      std::size_t max_bytes = 16u * 1024u * 1024u);
HEXLAB_TYPES_EXPORT Result<std::vector<std::byte>> encode_library_bundle(
    const LibraryBundle &, std::size_t max_bytes = 16u * 1024u * 1024u);
HEXLAB_TYPES_EXPORT Result<LibraryBundle> decode_library_bundle(
    std::span<const std::byte>, std::size_t max_bytes = 16u * 1024u * 1024u);
// Validates every symbolic reference in a bundle against the combined set of
// bundled and destination definitions. Traversal is graph-aware and bounded;
// names compare exactly, matching the project type namespace.
HEXLAB_TYPES_EXPORT Result<std::size_t> validate_library_references(
    const LibraryBundle &, const std::set<std::string, std::less<>> &available_names,
    std::size_t max_type_nodes = 1'000'000);
}
