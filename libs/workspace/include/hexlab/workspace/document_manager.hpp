#pragma once
#include "hexlab/workspace/project_actor.hpp"
#include "hexlab/workspace/search.hpp"
#include "hexlab/workspace/workspace.hpp"
namespace hexlab {
enum class DocumentSaveState {opening,untitled,saved,saving,error};
struct DocumentInfo {
    DocumentId id;SessionKey session;std::optional<database::ProjectUuid> uuid;
    std::optional<std::filesystem::path> path;DocumentSaveState save_state=DocumentSaveState::opening;
    bool analysis_pending=false,readonly=false;std::optional<Error> error;
};
// Owner-thread model. Actors own SQL; this model only polls immutable publications.
class DocumentManager {
public:
    HEXLAB_WORKSPACE_EXPORT static Result<std::unique_ptr<DocumentManager>> create(std::shared_ptr<AnalysisPool>,std::size_t max_documents=64);
    HEXLAB_WORKSPACE_EXPORT ~DocumentManager();
    HEXLAB_WORKSPACE_EXPORT Result<DocumentId> import_binary(OpenRequest);
    HEXLAB_WORKSPACE_EXPORT Result<DocumentId> open_project(std::filesystem::path,database::ProjectMode,const AnalysisOptions& = {});
    HEXLAB_WORKSPACE_EXPORT Result<bool> poll();
    HEXLAB_WORKSPACE_EXPORT void report_error(Error);
    HEXLAB_WORKSPACE_EXPORT void report_error(DocumentId,Error);
    HEXLAB_WORKSPACE_EXPORT Result<bool> activate(DocumentId);
    HEXLAB_WORKSPACE_EXPORT Result<Location> navigate(DocumentId,Location);
    HEXLAB_WORKSPACE_EXPORT Result<bool> close(DocumentId);
    // Apply a shared-project refresh to every open tab with the same project
    // UUID and underlying filesystem object.
    HEXLAB_WORKSPACE_EXPORT Result<bool> synchronize_external(const std::filesystem::path&,
                                                              const database::ProjectUuid&);
    HEXLAB_WORKSPACE_EXPORT Result<bool> refresh_external(const std::filesystem::path&,
                                                          const database::ProjectUuid&);
    HEXLAB_WORKSPACE_EXPORT void cancel_open();
    HEXLAB_WORKSPACE_EXPORT void close_all();
    HEXLAB_WORKSPACE_EXPORT Workspace& active_workspace();
    HEXLAB_WORKSPACE_EXPORT const Workspace& active_workspace()const;
    HEXLAB_WORKSPACE_EXPORT std::optional<DocumentId> active_document()const;
    HEXLAB_WORKSPACE_EXPORT std::vector<DocumentInfo> documents()const;
    HEXLAB_WORKSPACE_EXPORT std::shared_ptr<const ProjectSnapshot> project(DocumentId)const;
    HEXLAB_WORKSPACE_EXPORT std::shared_ptr<ProjectActor> actor(DocumentId)const;
    HEXLAB_WORKSPACE_EXPORT Result<ProjectOperationId> watch(DocumentId,Result<ProjectSubmission>);
    HEXLAB_WORKSPACE_EXPORT SearchHistory* search_history(DocumentId);
private:
    struct Impl;explicit DocumentManager(std::unique_ptr<Impl>);std::unique_ptr<Impl> impl_;
};
}
