#pragma once
#include "hexlab/workspace/commands.hpp"
#include "hexlab/analysis/incremental.hpp"
#include "hexlab/types/layout.hpp"
#include <mutex>
#include <span>
namespace hexlab {
struct ProjectAnalysis;
class ProjectPresentationIndex;
enum class DerivedStatus { fresh, pending, stale, incomplete, file_only };
struct ProjectSnapshot {
    std::shared_ptr<const database::ProjectState> state;
    std::shared_ptr<const ByteStorage> original, effective;
    std::shared_ptr<const LoadedImage> loaded;
    std::shared_ptr<const FunctionSnapshot> functions;
    std::shared_ptr<const ReferenceIndex> references;
    std::shared_ptr<const StringScan> strings;
    std::vector<FunctionStackRecord> stack_frames;
    std::vector<std::filesystem::path> protected_paths;
    std::shared_ptr<const AnalysisBasis> basis;
    ReadSet pending_byte_ranges;
    ReanalysisCounters last_reanalysis;
    std::string reanalysis_reason, string_rescan_reason;
    std::uint64_t loader_parses = 0;
    database::CacheStatus derived_cache_status = database::CacheStatus::absent;
    std::string derived_cache_reason;
    std::optional<AnalysisKey> derived_key;
    AnalysisOptions analysis_options;
    std::shared_ptr<const ProjectPresentationIndex> presentation;
    database::ProjectMode mode = database::ProjectMode::read_only;
    DerivedStatus status = DerivedStatus::pending;
    std::string reason;
};
struct LocationPresentation {
    std::string name, comment;
    bool user_name = false, orphaned = false;
};
struct SymbolCandidate {Address address;std::string name;};
HEXLAB_WORKSPACE_EXPORT std::vector<SymbolCandidate> importable_symbols(const ProjectSnapshot&);
HEXLAB_WORKSPACE_EXPORT const database::TypeDefinition *type_definition(const ProjectSnapshot&,std::uint64_t) noexcept;
HEXLAB_WORKSPACE_EXPORT Result<types::TypeLayout> calculate_type_layout(
    const ProjectSnapshot &, std::uint64_t type_id, types::Abi, types::LayoutOptions = {});
HEXLAB_WORKSPACE_EXPORT const database::TypeAssignment *type_assignment(const ProjectSnapshot&,Address) noexcept;
HEXLAB_WORKSPACE_EXPORT LocationPresentation presentation_at(const ProjectSnapshot &, Location);
HEXLAB_WORKSPACE_EXPORT std::string presentation_name(const ProjectSnapshot &, Location);
// Borrowed from the immutable snapshot. Retain that snapshot while using the result.
HEXLAB_WORKSPACE_EXPORT const database::Annotation *annotation_at(const ProjectSnapshot &, Location) noexcept;
// Worker-built indexes; returned pointers borrow the retained immutable snapshot.
struct ElfDynamicRow {
    const ElfDynamicTable *table;
    const ElfDynamicEntry *entry;
};
HEXLAB_WORKSPACE_EXPORT std::optional<FileOffset> elf_symbol_record_at(const ProjectSnapshot &, std::size_t) noexcept;
HEXLAB_WORKSPACE_EXPORT std::uint64_t elf_dynamic_row_count(const ProjectSnapshot &) noexcept;
HEXLAB_WORKSPACE_EXPORT std::optional<ElfDynamicRow> elf_dynamic_row_at(const ProjectSnapshot &,
                                                                        std::uint64_t) noexcept;
class ProjectSession {
  public:
    HEXLAB_WORKSPACE_EXPORT static Result<std::shared_ptr<ProjectSession>>
    attach(std::shared_ptr<database::ProjectStore>, const AnalysisOptions &, std::stop_token);
    HEXLAB_WORKSPACE_EXPORT static Result<std::shared_ptr<ProjectSession>>
    attach_deferred(std::shared_ptr<database::ProjectStore>, const AnalysisOptions &, std::stop_token);
    HEXLAB_WORKSPACE_EXPORT std::shared_ptr<const ProjectSnapshot> snapshot() const;
    HEXLAB_WORKSPACE_EXPORT Result<std::shared_ptr<const ProjectSnapshot>>
    set_analysis_options(const AnalysisOptions &);
    HEXLAB_WORKSPACE_EXPORT Result<std::shared_ptr<const ProjectSnapshot>>
    execute(const ProjectCommand &, std::uint64_t group, std::stop_token);
    HEXLAB_WORKSPACE_EXPORT Result<std::shared_ptr<const ProjectSnapshot>>
    execute_batch(const std::vector<ProjectCommand> &, std::uint64_t group, std::stop_token);
    HEXLAB_WORKSPACE_EXPORT Result<std::shared_ptr<const ProjectSnapshot>> undo(std::stop_token);
    HEXLAB_WORKSPACE_EXPORT Result<std::shared_ptr<const ProjectSnapshot>> redo(std::stop_token);
    HEXLAB_WORKSPACE_EXPORT Result<std::shared_ptr<const ProjectSnapshot>>
    persist_breakpoint_hit_counts(std::span<const database::BreakpointHitCount>,std::stop_token);
    HEXLAB_WORKSPACE_EXPORT Result<std::shared_ptr<const ProjectSnapshot>>
    replace_type_import_diagnostics(std::span<const database::TypeImportDiagnostic>,std::stop_token);
    HEXLAB_WORKSPACE_EXPORT Result<std::shared_ptr<const ProjectSnapshot>> refresh_analysis(std::stop_token);
    HEXLAB_WORKSPACE_EXPORT Result<std::shared_ptr<const ProjectSnapshot>> adopt_analysis(const ProjectAnalysis &,
                                                                                          std::stop_token);
    HEXLAB_WORKSPACE_EXPORT Result<std::shared_ptr<const ProjectSnapshot>> record_cache_result(const AnalysisKey &,
                                                                                               const Result<bool> &);
    HEXLAB_WORKSPACE_EXPORT Result<std::shared_ptr<const ProjectSnapshot>> mark_analysis_pending(const AnalysisKey &);
    HEXLAB_WORKSPACE_EXPORT Result<std::shared_ptr<const ProjectSnapshot>> report_analysis_error(const AnalysisKey &,
                                                                                                 const Error &);

  private:
    ProjectSession() = default;
    static Result<std::shared_ptr<ProjectSession>> attach_impl(std::shared_ptr<database::ProjectStore>,
                                                               const AnalysisOptions &, std::stop_token, bool);
    Result<std::shared_ptr<const ProjectSnapshot>> history(bool redo, std::stop_token);
    std::shared_ptr<database::ProjectStore> store_;
    AnalysisOptions options_;
    std::shared_ptr<const ProjectSnapshot> snapshot_;
    // Writer calls are serialized; readers can retain immutable snapshots.
    mutable std::mutex mutex_;
};
} // namespace hexlab
