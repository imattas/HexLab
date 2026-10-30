#pragma once
#include "hexlab/core/location.hpp"
#include "hexlab/core/sha256.hpp"
#include "hexlab/types/types.hpp"
#include <functional>
#include <optional>
#include <set>
#include <span>
#include <string_view>

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
// HXTL v6 binds file-offset assignments directly to the original binary,
// independently of the loader recipe used to interpret it.
struct LibraryBinaryIdentity {
    std::uint64_t input_size = 0;
    Sha256Digest input_sha256{};
    bool operator==(const LibraryBinaryIdentity &) const = default;
};
struct LibraryAssignment {
    Location location;
    std::string type_name;
    struct SourceBytes {
        std::uint64_t size = 0;
        Sha256Digest sha256{};
        bool operator==(const SourceBytes &) const = default;
    };
    // Exported file-offset assignments may carry a digest of the original
    // bytes occupied by their type. This lets explicit cross-source imports
    // check that the destination offset still refers to matching content.
    std::optional<SourceBytes> source_bytes;
    bool operator==(const LibraryAssignment &) const = default;
};
struct LibraryBundle {
    std::vector<LibraryEntry> entries;
    std::optional<LibrarySourceIdentity> source_identity;
    std::optional<LibraryBinaryIdentity> file_offset_identity;
    std::vector<LibraryAssignment> assignments;
};
enum class LibraryAssignmentSkipReason : std::uint8_t {
    source_identity_mismatch,
    binary_identity_mismatch,
    source_byte_verifier_unavailable,
    source_bytes_mismatch
};
struct SkippedLibraryAssignment {
    LibraryAssignment assignment;
    LibraryAssignmentSkipReason reason = LibraryAssignmentSkipReason::source_identity_mismatch;
};
struct LibraryAssignmentSelection {
    std::vector<LibraryAssignment> applicable;
    std::vector<SkippedLibraryAssignment> skipped;
};
using LibraryAssignmentSourceVerifier = std::function<Result<bool>(
    FileOffset, const LibraryAssignment::SourceBytes &)>;
struct LibraryImportPlan {
    LibraryAssignmentSelection assignments;
    std::size_t validated_type_nodes = 0;
};
HEXLAB_TYPES_EXPORT Result<std::vector<std::byte>> encode_library(std::span<const LibraryEntry>,
                                                                  std::size_t max_bytes = 16u * 1024u * 1024u);
HEXLAB_TYPES_EXPORT Result<std::vector<LibraryEntry>> decode_library(std::span<const std::byte>,
                                                                      std::size_t max_bytes = 16u * 1024u * 1024u);
HEXLAB_TYPES_EXPORT Result<std::vector<std::byte>> encode_library_bundle(
    const LibraryBundle &, std::size_t max_bytes = 16u * 1024u * 1024u);
HEXLAB_TYPES_EXPORT Result<LibraryBundle> decode_library_bundle(
    std::span<const std::byte>, std::size_t max_bytes = 16u * 1024u * 1024u);
// Combines definition-only bundles for interoperability. Duplicate names are
// accepted only when their encoded type and declaration metadata match exactly;
// source-specific assignments are rejected rather than silently discarded.
HEXLAB_TYPES_EXPORT Result<std::vector<LibraryEntry>> merge_library_definitions(
    std::span<const LibraryBundle>, const std::set<std::string, std::less<>> &available_names = {},
    std::size_t max_type_nodes = 1'000'000);
// Renders a self-contained C11 header from bundle definitions. Symbolic
// references must resolve in the bundle; unsupported C/layout constructs fail
// closed. Source-specific assignments and origins are intentionally omitted.
HEXLAB_TYPES_EXPORT Result<std::string> render_library_c_header(
    const LibraryBundle &, std::string_view include_guard = "HEXLAB_PORTABLE_TYPES_H");
// Selects assignments whose location identity matches the destination. Address
// assignments require exact input and recipe identity; file offsets require
// the separate HXTL v6 binary identity. When a file-offset assignment carries
// a byte witness, a verifier must confirm it before that assignment is selected.
HEXLAB_TYPES_EXPORT Result<LibraryAssignmentSelection> select_library_assignments(
    const LibraryBundle &, const std::optional<LibrarySourceIdentity> &destination_source,
    const std::optional<LibraryBinaryIdentity> &destination_binary,
    const LibraryAssignmentSourceVerifier &verify_source_bytes = {});
// Preflights definitions and identity-eligible assignments together. It
// validates the complete symbolic type graph and confirms each selected
// assignment names a bundled or destination-provided type. It does not mutate
// project state or replace the caller's transactional import.
HEXLAB_TYPES_EXPORT Result<LibraryImportPlan> prepare_library_import(
    const LibraryBundle &, const std::set<std::string, std::less<>> &available_names,
    const std::optional<LibrarySourceIdentity> &destination_source,
    const std::optional<LibraryBinaryIdentity> &destination_binary,
    const LibraryAssignmentSourceVerifier &verify_source_bytes = {},
    std::size_t max_type_nodes = 1'000'000);
// Validates every symbolic reference in a bundle against the combined set of
// bundled and destination definitions. Traversal is graph-aware and bounded;
// names compare exactly, matching the project type namespace.
HEXLAB_TYPES_EXPORT Result<std::size_t> validate_library_references(
    const LibraryBundle &, const std::set<std::string, std::less<>> &available_names,
    std::size_t max_type_nodes = 1'000'000);
}
