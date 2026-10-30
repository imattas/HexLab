#pragma once
#include "hexlab/analysis/analysis.hpp"
#include "hexlab/loaders/pe.hpp"
#include "hexlab/loaders/raw.hpp"
#include "hexlab/loaders/macho.hpp"
#include "hexlab/loaders/recipe.hpp"
#include "hexlab/workspace/workspace_export.hpp"

namespace hexlab {
struct ProjectSnapshot;
struct DocumentId {std::uint64_t value;bool operator==(const DocumentId&) const = default;};
struct OpenTicket {DocumentId document;std::uint64_t generation;bool operator==(const OpenTicket&) const = default;};
struct OpenRequest {
    std::filesystem::path path;
    // Optional immutable input source for bounded subfiles (for example an ar member).
    // When present, workspace import uses this source instead of reopening path.
    std::shared_ptr<const ByteStorage> input_storage;
    // Logical source label persisted as provenance; defaults to path.
    std::optional<std::filesystem::path> source_path;
    Format format=Format::automatic;
    std::optional<RawOptions> raw;
    AnalysisOptions analysis_options;
    bool run_analysis=true;
    // Worker-resolved alternative to raw; the complete profile is embedded
    // in the resulting recipe before image creation or persistent import.
    std::optional<std::filesystem::path> x86_profile_path;
    std::optional<MachOOptions> macho;
    std::optional<PeRuntimeArchitecture> pe_runtime_architecture;
    std::optional<std::filesystem::path> arm_profile_path;
    // Local-only PDB binding overrides; search directories are consulted in
    // order after the PE directory. The resolved file path is persisted.
    std::optional<std::filesystem::path> pdb_path;
    std::vector<std::filesystem::path> pdb_search_paths;
    // Explicit supplementary ELF DWP package; never inferred from DWARF paths.
    std::optional<std::filesystem::path> dwarf_supplementary_package_path;
    // Exact previously resolved durable selection, used when reopening a
    // session whose image came from a plugin provider. When present, the
    // recipe is validated and used without probing for a replacement provider.
    std::optional<LoadRecipe> resolved_recipe;
};
struct DocumentSnapshot {
    DocumentId id{0};
    std::uint64_t revision=0;
    std::shared_ptr<const Image> image;
    // Original/effective source bytes may differ from decoded image backing
    // (Intel HEX and S-record store text, but map decoded record data).
    std::shared_ptr<const ByteStorage> input_storage;
    ImageMetadata metadata;
    std::vector<Diagnostic> diagnostics;
    std::optional<AnalysisSnapshot> analysis;
    std::shared_ptr<const ProjectSnapshot> project;
    StringScan inspection_strings;
    bool metadata_complete=true,analysis_requested=false;
    HEXLAB_WORKSPACE_EXPORT const StringScan& strings() const noexcept;
    HEXLAB_WORKSPACE_EXPORT const ImageMetadata& metadata_view() const noexcept;
    HEXLAB_WORKSPACE_EXPORT const ByteStorage& file_storage() const noexcept;
};
HEXLAB_WORKSPACE_EXPORT Result<std::shared_ptr<const DocumentSnapshot>> load_document(const OpenRequest&,OpenTicket,std::stop_token);
}
