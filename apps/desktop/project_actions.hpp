#pragma once
#include "session_controller.hpp"
#include <wx/frame.h>
#include <wx/menu.h>
namespace hexlab::desktop {
inline constexpr int project_action_first = wxID_HIGHEST + 100;
enum ProjectActionId {
    rename_id = project_action_first,
    comment_id,
    bookmark_id,
    code_id,
    data_id,
    function_id,
    chunks_id,
    suppress_id,
    reset_function_id,
    reference_id,
    patch_id,
    export_id,
    find_next_id,
    find_previous_id,
    reanalyze_id,
    exchange_export_id,
    exchange_import_id,
    patch_manager_id,
    backup_project_id,
    restore_backup_id,
    rotate_backups_id,
    list_backups_id,
    prune_backups_id,
    restore_backup_in_place_id
};
class ProjectActions {
  public:
    ProjectActions(wxFrame &, SessionController &, std::function<std::optional<Location>()> selection = {});
    ~ProjectActions();
    static void add_menus(wxMenu &file, wxMenu &edit);

  private:
    wxFrame &frame_;
    SessionController &controller_;
    std::function<std::optional<Location>()> selection_;
    void command(wxCommandEvent &);
    void update(wxUpdateUIEvent &);
};
} // namespace hexlab::desktop
