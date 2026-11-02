#pragma once
#include "hexlab/image/byte_storage.hpp"
#include "hexlab/loaders/loaded_image.hpp"
#include "hexlab/image/macho_metadata.hpp"
#include "hexlab/loaders/loaders_export.hpp"
#include <cstddef>
#include <cstdint>
#include <array>
#include <optional>
#include <span>
#include <vector>
#include <stop_token>
#include <string>
namespace hexlab {
// Container/header/load-command envelope inspection only. Command payloads,
// image mappings, architecture support and linking are separate contracts.
HEXLAB_LOADERS_EXPORT Result<MachOContainer> read_macho_container(const ByteStorage &, std::stop_token);
struct MachOOptions {
    std::optional<std::uint32_t> slice_index;
    bool operator==(const MachOOptions &) const = default;
};
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_macho(std::shared_ptr<const ByteStorage>, const MachOOptions &,
                                                     std::stop_token);
struct MachOCodeDirectoryHashLimits {
    std::uint64_t max_code_bytes = 512ULL * 1024 * 1024;
    std::uint32_t max_code_slots = 1'000'000;
    std::uint32_t max_retained_mismatches = 128;
};
struct MachOCodeDirectoryHashVerification {
    std::uint32_t signature_index = 0, blob_index = 0;
    std::uint64_t code_limit = 0;
    std::uint32_t page_size = 0, code_slots = 0, verified_slots = 0;
    std::uint8_t hash_type = 0, hash_size = 0;
    std::uint64_t mismatch_count = 0;
    std::vector<std::uint32_t> mismatch_slots;
    bool matches = false;
};
// Verifies contiguous SHA-256 or truncated SHA-256 CodeDirectory code-page
// hashes for versions through 0x20300, including nonzero codeLimit64. Scatter
// layouts, CMS signatures and trust are not checked.
HEXLAB_LOADERS_EXPORT Result<MachOCodeDirectoryHashVerification> verify_macho_code_directory_hashes(
    const Image &, const ImageMetadata &, std::uint32_t signature_index, std::uint32_t blob_index,
    std::stop_token = {}, MachOCodeDirectoryHashLimits = {});
struct MachOChainedTargetBases {
    std::optional<std::uint64_t> shared_cache_base;
    std::array<std::optional<std::uint64_t>, 4> cache_level_bases{};
    // Half-open VM address ranges accepted as targets after base addition.
    struct Mapping { std::uint64_t address = 0, size = 0; bool operator==(const Mapping &) const = default; };
    // Optional validated VM ranges for checking externally based results.
    // An empty list retains the base-only behavior for that namespace.
    std::vector<Mapping> shared_cache_mappings;
    std::array<std::vector<Mapping>, 4> cache_level_mappings{};
};
enum class MachOChainedExternalTargetStatus : std::uint8_t {
    resolved, missing_base, invalid_encoding, overflow, outside_mapping
};
struct MachOChainedExternalTarget {
    std::size_t pointer_index = 0;
    MachOChainedExternalTargetStatus status = MachOChainedExternalTargetStatus::missing_base;
    MachOChainedTargetBaseKind base_kind = MachOChainedTargetBaseKind::shared_cache;
    std::optional<std::uint8_t> cache_level;
    std::optional<std::uint64_t> base_address, target_address;
    bool authentication_required = false;
};
struct MachOChainedTargetResolutionLimits {
    std::size_t max_pointer_rows = 1'000'000;
};
// Resolves format-4/13 shared-cache and format-8/11 kernel-cache-level rebase
// payloads against bases explicitly supplied by the caller. Optional caller
// mappings constrain the computed target to validated cache VM ranges.
// Authenticated results are pre-PAC addresses and are not usable signed pointers.
HEXLAB_LOADERS_EXPORT Result<std::vector<MachOChainedExternalTarget>> resolve_macho_chained_external_targets(
    const MachOMetadata &, const MachOChainedTargetBases &, std::stop_token = {},
    MachOChainedTargetResolutionLimits = {});

enum class MachOChainedBindStatus : std::uint8_t { resolved, missing_import_address, invalid_encoding, overflow };
struct MachOChainedBindTarget {
    std::size_t pointer_index = 0;
    std::uint32_t import_row = 0;
    MachOChainedBindStatus status = MachOChainedBindStatus::missing_import_address;
    std::optional<std::uint64_t> import_address, target_address;
    std::optional<std::int64_t> combined_addend;
    bool authentication_required = false;
};
struct MachOChainedBindResolutionLimits {
    std::size_t max_pointer_rows = 1'000'000;
};
// Resolves chained bind pointers from explicit per-import-row addresses. The
// address span must match metadata.chained_imports; null entries remain
// unresolved. Results include the checked sum of import and pointer addends.
// Authenticated binds return their pre-PAC address and still require runtime
// signing; this function never writes pointer bytes or validates trust.
HEXLAB_LOADERS_EXPORT Result<std::vector<MachOChainedBindTarget>> resolve_macho_chained_binds(
    const MachOMetadata &, std::span<const std::optional<std::uint64_t>> import_addresses,
    std::stop_token = {}, MachOChainedBindResolutionLimits = {});

enum class MachODyldBindStatus : std::uint8_t {
    resolved, missing_import, ambiguous_import, invalid_encoding, unsupported_type, overflow
};
struct MachODyldImportAddress {
    std::int32_t library_ordinal = 0;
    std::string symbol;
    std::uint64_t address = 0;
};
struct MachODyldBindTarget {
    std::size_t fixup_index = 0;
    std::uint32_t stream = 0, operation = 0, repeat_index = 0;
    std::uint64_t record_file_offset = 0;
    std::uint8_t type = 0, field_size = 0, symbol_flags = 0;
    std::int32_t library_ordinal = 0;
    std::string symbol;
    std::int64_t addend = 0;
    bool weak_import = false;
    std::optional<Address> place;
    std::optional<FileOffset> file_place;
    std::optional<std::uint64_t> import_address, target_address, value_to_write;
    MachODyldBindStatus status = MachODyldBindStatus::missing_import;
};
struct MachODyldBindResolutionLimits {
    std::size_t max_fixups = 1'000'000;
    std::size_t max_imports = 1'000'000;
    std::uint64_t max_symbol_bytes = 16 * 1024 * 1024;
    std::uint64_t max_result_bytes = 64 * 1024 * 1024;
};
// Computes classic dyld bind values from caller-supplied runtime symbol
// addresses, without mutating image bytes. PC-relative binds use the supplied
// image slide to compute their runtime place. Weak binds are inventory-only.
HEXLAB_LOADERS_EXPORT Result<std::vector<MachODyldBindTarget>> resolve_macho_dyld_binds(
    const MachOMetadata &, std::span<const MachODyldImportAddress>, std::uint64_t image_slide = 0,
    std::stop_token = {}, MachODyldBindResolutionLimits = {});

// Provider images are supplied by the caller. `source` records provenance
// (normally the selected file path); this resolver never searches host paths.
struct MachOTwoLevelProvider {
    std::uint32_t library_ordinal = 0;
    std::uint8_t sub_image_index = 0;
    std::string source;
    const MachOMetadata *metadata = nullptr;
};
enum class MachOTwoLevelStatus : std::uint8_t {
    resolved, missing_hint, unassociated_hint, non_two_level_image,
    special_library_ordinal, missing_library_ordinal, missing_provider, ambiguous_provider,
    missing_provider_tables, toc_index_out_of_range, module_index_out_of_range,
    invalid_provider_symbol, symbol_name_mismatch
};
struct MachOTwoLevelResolution {
    std::uint32_t hint_index = 0, library_ordinal = 0;
    std::uint8_t sub_image_index = 0;
    MachOTwoLevelStatus status = MachOTwoLevelStatus::missing_hint;
    std::optional<std::uint32_t> provider_symbol_index, provider_module_index;
    std::string provider_source;
};
struct MachOTwoLevelResolutionLimits { std::size_t max_rows = 1'000'000; };
// Resolves advisory two-level hints against caller-selected provider images
// using the provider TOC index. Runtime loading and rebinding are not performed.
HEXLAB_LOADERS_EXPORT Result<std::vector<MachOTwoLevelResolution>> resolve_macho_two_level_hints(
    const MachOMetadata &, std::span<const MachOTwoLevelProvider>, std::stop_token = {},
    MachOTwoLevelResolutionLimits = {});
} // namespace hexlab
