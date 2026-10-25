#pragma once
#include "hexlab/loaders/loader.hpp"
#include "hexlab/image/metadata.hpp"
#include "hexlab/image/read_set.hpp"
namespace hexlab {
struct LoadedImage {
    std::shared_ptr<const Image> image;
    ImageMetadata metadata;
    std::vector<Diagnostic> diagnostics;
    bool metadata_complete = false;
    ReadSet metadata_reads;
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
};
} // namespace hexlab
