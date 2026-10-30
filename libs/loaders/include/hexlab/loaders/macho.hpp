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
    std::uint32_t code_limit = 0, page_size = 0, code_slots = 0, verified_slots = 0;
    std::uint8_t hash_type = 0, hash_size = 0;
    std::uint64_t mismatch_count = 0;
    std::vector<std::uint32_t> mismatch_slots;
    bool matches = false;
};
// Verifies SHA-256 or truncated SHA-256 CodeDirectory code-page hashes for one
// selected Mach-O CodeDirectory blob. CMS signatures and trust are not checked.
HEXLAB_LOADERS_EXPORT Result<MachOCodeDirectoryHashVerification> verify_macho_code_directory_hashes(
    const Image &, const ImageMetadata &, std::uint32_t signature_index, std::uint32_t blob_index,
    std::stop_token = {}, MachOCodeDirectoryHashLimits = {});
struct MachOChainedTargetBases {
    std::optional<std::uint64_t> shared_cache_base;
    std::array<std::optional<std::uint64_t>, 4> cache_level_bases{};
};
enum class MachOChainedExternalTargetStatus : std::uint8_t {
    resolved, missing_base, invalid_encoding, overflow
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
// payloads against bases explicitly supplied by the caller. Authenticated
// results are pre-PAC addresses and are not usable signed pointers.
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
} // namespace hexlab
