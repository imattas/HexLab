#pragma once
#include "hexlab/loaders/loader.hpp"
#include "hexlab/image/metadata.hpp"
#include "hexlab/image/read_set.hpp"
#include "hexlab/image/external_inputs.hpp"
#include <optional>
namespace hexlab {
struct LoadedImage {
    std::shared_ptr<const Image> image;
    ImageMetadata metadata;
    std::vector<Diagnostic> diagnostics;
    bool metadata_complete = false;
    ReadSet metadata_reads;
    // True only when the loader has certified that metadata_reads covers every
    // byte dependency in the primary input. An empty set is valid for formats
    // whose mapping comes entirely from the explicit load recipe.
    bool metadata_reads_complete = false;
    // Content identity for explicit auxiliary artifacts (currently local PDB
    // and caller-selected DWP) that contribute loader metadata outside the
    // primary input's ReadSet. It is folded into project analysis identity.
    std::optional<Sha256Digest> external_input_fingerprint;
    // False when a caller supplied an auxiliary resolver without a stable
    // identity. Consumers must rebuild rather than reuse derived results.
    bool external_inputs_certified = true;
    // PE runtime base when explicitly selected; otherwise absent for loaders
    // without a distinct runtime/preferred mapping choice.
    std::optional<std::uint64_t> load_base;
    // Optional ELF runtime view. The canonical image and metadata retain
    // link-time addresses; this view has load_bias applied and contains the
    // selected dynamic relocation patches.
    std::shared_ptr<const Image> runtime_image;
    std::optional<std::uint64_t> runtime_load_bias;
    bool runtime_relocations_complete = true;
    std::vector<std::uint64_t> runtime_relocations_applied;
    std::vector<Diagnostic> runtime_relocation_diagnostics;
    // Optional ARM64X transformed view containing the complete validated
    // fixup set. The canonical view is retained in pe_native_image.
    std::shared_ptr<const Image> pe_arm64x_image;
    // Base view before ARM64X conditional fixups; retained so clients can
    // select either process view even when `image` is already selected.
    std::shared_ptr<const Image> pe_native_image;
    std::optional<PeRuntimeArchitecture> pe_runtime_target;
    // Full-byte dependencies from explicitly declared callback input manifests.
    // Resolver-family prefixes keep equal caller names in separate namespaces.
    std::vector<ExternalInputDependency> external_input_dependencies;
};
} // namespace hexlab
