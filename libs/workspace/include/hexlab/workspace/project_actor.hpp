#pragma once
#include "hexlab/workspace/analysis_pool.hpp"
#include "hexlab/workspace/project_analysis.hpp"
#include "hexlab/workspace/export.hpp"
#include "hexlab/analysis/signatures.hpp"
#include <string>
#include <vector>
namespace hexlab {
struct ProjectOperationId {std::uint64_t value=0;bool operator==(const ProjectOperationId&)const=default;};
enum class ProjectOperationKind {open_project,import_binary,command,undo,redo,save,save_as,backup,export_binary,analyze,persist_recognition,read_recognition,close,refresh_external,refresh_if_external,history_page,history_preview,persist_breakpoint_hits,persist_type_import_diagnostics,persist_decompiler_diagnostics,persist_reviewed_issues,history_audit,read_preference,write_preference};
struct ProjectReply {
    ProjectOperationKind kind;std::shared_ptr<const ProjectSnapshot> snapshot;
    std::optional<database::SavedProject> saved;std::optional<ExportReceipt> exported;
    std::optional<database::FunctionRecognitionCache> recognition_cache;
    std::optional<database::HistoryPage> history_page;
    std::optional<database::HistoryPreview> history_preview;
    std::optional<database::HistoryAuditPage> history_audit;
    std::optional<std::string> preference_value;
    bool adopted=true,closed=false;std::optional<Error> adoption_error;
};
struct ProjectSubmission {SessionKey session;ProjectOperationId id;std::shared_future<Result<ProjectReply>> result;};
struct ActorLimits {std::size_t max_operations=128;};
struct ActorView {
    SessionKey session;std::shared_ptr<const ProjectSnapshot> snapshot;
    std::optional<std::filesystem::path> project_path;
    std::uint64_t generation=0;std::size_t pending_operations=0;
    bool untitled=false,analysis_pending=false,closing=false;
};
class ProjectActor {
public:
    HEXLAB_WORKSPACE_EXPORT static Result<std::shared_ptr<ProjectActor>> create(SessionKey,std::shared_ptr<AnalysisPool>,ActorLimits={});
    HEXLAB_WORKSPACE_EXPORT ~ProjectActor();
    ProjectActor(const ProjectActor&)=delete;ProjectActor& operator=(const ProjectActor&)=delete;
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> open_project(std::filesystem::path,database::ProjectMode,const AnalysisOptions& = {});
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> import_binary(OpenRequest);
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> execute(ProjectCommand,std::uint64_t group=0);
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> execute_batch(std::vector<ProjectCommand>,std::uint64_t group=0);
    // Review-planned edits bind to both source identity and the exact edit
    // revision. Both are rechecked on the writer thread before validation.
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> execute_batch_at_revision(
        std::vector<ProjectCommand>,std::uint64_t expected_edit,AnalysisKey source_key,
        std::shared_ptr<const ProjectSnapshot> reviewed_snapshot,std::uint64_t group=0);
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> undo();
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> redo();
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> ready(bool force=false);
    // Stores a source-bound signature/fingerprint recognition cache after
    // validating every function ID and entry against the current analysis.
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> persist_function_recognition(FunctionRecognitionEvidence);
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> read_function_recognition(FunctionRecognitionKind);
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> persist_breakpoint_hit_counts(std::vector<database::BreakpointHitCount>);
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> replace_type_import_diagnostics(std::vector<database::TypeImportDiagnostic>);
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> upsert_decompiler_diagnostics(AnalysisKey,Address,std::vector<database::TypeImportDiagnostic>);
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> replace_reviewed_analysis_issue_keys(std::vector<std::string>);
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> read_preference(std::string key);
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> write_preference(std::string key,std::string value);
    // Read-only, revision-pinned durable history queries. The history preview
    // is never adopted into the live project session.
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> history_page(std::uint64_t expected_edit,
        std::uint64_t after_step,std::size_t limit=256);
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> preview_history_at(std::uint64_t expected_edit,
        std::uint64_t target_step,database::HistoryPreviewLimits={});
    // Read-only, revision-pinned audit of the durable history payloads.
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> audit_history(std::uint64_t expected_edit,
        std::uint64_t after_step,database::HistoryAuditLimits={});
    // Replace worker analysis options and schedule a full derived-analysis refresh.
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> reanalyze(AnalysisOptions);
    // Reopen a saved project's latest committed state after another connection
    // has changed it. All reads and publication stay on the actor writer thread.
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> refresh_external();
    // Check the persisted revision cheaply, then refresh only when another
    // process has committed a project-state change.
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> refresh_if_external();
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> save();
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> save_as(std::filesystem::path,database::ReplacePolicy);
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> backup_to(std::filesystem::path,database::ReplacePolicy);
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> export_binary(std::filesystem::path,database::ReplacePolicy);
    HEXLAB_WORKSPACE_EXPORT bool cancel_operation(ProjectOperationId);
    HEXLAB_WORKSPACE_EXPORT void cancel_analysis();
    HEXLAB_WORKSPACE_EXPORT void cancel_analysis_and_wait();
    HEXLAB_WORKSPACE_EXPORT Result<ProjectSubmission> close();
    HEXLAB_WORKSPACE_EXPORT ActorView view()const;
    HEXLAB_WORKSPACE_EXPORT std::optional<ActorView> take_event();
private:
    struct Impl;explicit ProjectActor(std::unique_ptr<Impl>);std::unique_ptr<Impl> impl_;
};
}
