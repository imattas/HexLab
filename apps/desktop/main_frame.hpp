#pragma once
#include <wx/aui/aui.h>
#include <wx/frame.h>
#include "hexlab/workspace/workspace.hpp"
#include "hexlab/workspace/document_manager.hpp"
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <utility>

namespace hexlab::plugins { class ModuleProvider; }
namespace hexlab::desktop {
inline constexpr int reset_layout_id = wxID_HIGHEST + 1;
enum Command {
    open_raw_id = reset_layout_id + 1,
    cancel_id,
    jump_id,
    follow_id,
    back_id,
    forward_id,
    browse_navigation_history_id,
    previous_marker_id,
    next_marker_id,
    previous_function_id,
    next_function_id,
    copy_address_id,
    copy_bytes_id,
    copy_text_id,
    next_page_id,
    analysis_options_id,
    open_project_id,
    type_symbols_id,
    pseudocode_id,
    debugger_panel_id,
    debugger_toggle_selection_bp_id,
    plugins_panel_id,
    compare_id,
    compare_open_projects_id,
    compare_cancel_id,
    open_compare_session_id,
    open_archive_id,
    collaboration_review_id,
    incoming_references_id,
    outgoing_references_id,
    flirt_apply_id,
    python_console_id
};
class MainFrame final : public wxFrame {
  public:
    explicit MainFrame(std::shared_ptr<plugins::ModuleProvider> plugin_provider = {});
    ~MainFrame() override;
    void ResetLayout();
    void OpenDocument(OpenRequest);
    void OpenProject(std::filesystem::path, database::ProjectMode = database::ProjectMode::read_write);
    void ActivateDocument(DocumentId);
    void CloseAllDocuments();
    DocumentManager &projects();
    Result<ProjectOperationId> ApplyProjectCommand(ProjectCommand);
    Result<ProjectOperationId> ApplyProjectCommandFor(DocumentId, ProjectCommand);
    Result<ProjectOperationId> SaveProjectAs(std::filesystem::path, bool replace = false);
    Result<ProjectOperationId> ExportBinary(std::filesystem::path, bool replace = false);
    Result<bool> Find(SearchQuery, const SearchLimits & = {}, bool all_documents = false);
    bool FindPending()const;
    void Navigate(Location);
    const Workspace &documents() const;
    std::optional<std::pair<std::filesystem::path, std::uint64_t>> ActiveSavedProjectBinding();

  private:
    struct Impl;
    void AdaptLayout();
    void RestoreDesktopState();
    void SaveDesktopState();
    void RestoreWorkspaceSession();
    void SaveWorkspaceSession();
    wxAuiManager docking_;
    wxString default_layout_;
    wxRect normal_frame_rect_;
    bool restoring_desktop_state_ = false;
    std::unique_ptr<Impl> impl_;
};
} // namespace hexlab::desktop
