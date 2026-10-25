#include "project_actions.hpp"
#include "edit_dialogs.hpp"
#include "reference_dialog.hpp"
#include "data_views.hpp"
#include "search_view.hpp"
#include "hexlab/workspace/project_exchange.hpp"
#include <wx/aui/aui.h>
#include <wx/filedlg.h>
#include <wx/filename.h>
#include <wx/choicdlg.h>
#include <wx/msgdlg.h>
#include <wx/textdlg.h>
#include <wx/listctrl.h>
#include <wx/stattext.h>
#include <wx/sizer.h>
#include <wx/button.h>
#include <algorithm>
#include <fstream>
namespace hexlab::desktop {
namespace {
constexpr std::size_t max_exchange_bytes = 16u * 1024u * 1024u;
constexpr int actions[] = {wxID_SAVE,  wxID_SAVEAS,  wxID_UNDO,        wxID_REDO,   rename_id,
                           comment_id, bookmark_id,  code_id,          data_id,     function_id,
                           chunks_id,  suppress_id,  reset_function_id, reference_id, patch_id, export_id,
                           wxID_FIND,  find_next_id, find_previous_id, reanalyze_id,
                           exchange_export_id, exchange_import_id, patch_manager_id,
                           backup_project_id, restore_backup_id};
ProjectActionKind kind(int id) {
    switch (id) {
    case reanalyze_id:
        return ProjectActionKind::reanalyze;
    case wxID_SAVE:
        return ProjectActionKind::save;
    case wxID_SAVEAS:
        return ProjectActionKind::save_as;
    case wxID_UNDO:
        return ProjectActionKind::undo;
    case wxID_REDO:
        return ProjectActionKind::redo;
    case rename_id:
        return ProjectActionKind::rename;
    case comment_id:
        return ProjectActionKind::comment;
    case bookmark_id:
        return ProjectActionKind::bookmark;
    case code_id:
        return ProjectActionKind::define_code;
    case data_id:
        return ProjectActionKind::define_data;
    case function_id:
        return ProjectActionKind::define_function;
    case chunks_id:
        return ProjectActionKind::function_chunks;
    case suppress_id:
        return ProjectActionKind::suppress_function;
    case reset_function_id:
        return ProjectActionKind::reset_function;
    case reference_id:
        return ProjectActionKind::reference;
    case patch_id:
        return ProjectActionKind::patch;
    default:
        return ProjectActionKind::export_binary;
    }
}
std::string utf8(const wxString &value) {
    auto encoded = value.utf8_str();
    return {encoded.data(), encoded.length()};
}
wxString kind_name(ExchangeRecordKind kind) {
    switch (kind) { case ExchangeRecordKind::annotation:return "Annotations"; case ExchangeRecordKind::bookmark:return "Bookmarks"; case ExchangeRecordKind::reference:return "References"; case ExchangeRecordKind::region:return "Code/data regions"; case ExchangeRecordKind::function:return "Functions"; case ExchangeRecordKind::type_definition:return "Type definitions"; case ExchangeRecordKind::type_assignment:return "Type assignments"; case ExchangeRecordKind::debug_variable:return "Debug variables"; }
    return "Records";
}
Result<std::vector<std::byte>> read_exchange(const std::filesystem::path& path) {
    std::error_code error;auto size=std::filesystem::file_size(path,error);if(error)return Error{ErrorCode::io,"Cannot inspect exchange file: "+error.message()};
    if(size>max_exchange_bytes)return Error{ErrorCode::resource_limit,"Exchange file exceeds 16 MiB limit"};
    std::ifstream input(path,std::ios::binary);if(!input)return Error{ErrorCode::io,"Cannot open exchange file"};std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    if(size && !input.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(size)))return Error{ErrorCode::io,"Cannot read complete exchange file"};return bytes;
}
Result<bool> write_exchange(const ProjectSnapshot& project,const std::filesystem::path& path,bool replace) {
    std::error_code error;if(std::filesystem::exists(path,error)){if(error)return Error{ErrorCode::io,"Cannot inspect exchange destination: "+error.message()};if(!replace)return Error{ErrorCode::conflict,"Exchange destination already exists"};}
    auto bytes=export_project_exchange(project,max_exchange_bytes);if(!bytes)return bytes.error();std::ofstream output(path,std::ios::binary|std::ios::trunc);if(!output)return Error{ErrorCode::io,"Cannot create exchange file"};
    output.write(reinterpret_cast<const char*>(bytes.value().data()),static_cast<std::streamsize>(bytes.value().size()));if(!output)return Error{ErrorCode::io,"Cannot write complete exchange file"};return true;
}
wxString import_summary(const ExchangeImport& plan) {
    wxString result=wxString::Format("Ready to import %zu annotations, %zu bookmarks, %zu references, %zu regions, %zu functions, %zu type definitions, %zu type assignments, and %zu debug variables.\nSkipped identical records: %zu.\n\n",
      plan.annotations,plan.bookmarks,plan.references,plan.regions,plan.functions,plan.type_definitions,plan.type_assignments,plan.debug_variables,plan.skipped);
    if(plan.conflicts.empty())return result+"No conflicts.";
    result+=wxString::Format("Conflicts: %zu\n",plan.conflicts.size());std::map<std::pair<int,int>,std::size_t> counts;
    for(auto& conflict:plan.conflicts)counts[{static_cast<int>(conflict.kind),static_cast<int>(conflict.resolution)}]++;
    for(auto& [key,count]:counts){auto resolution=static_cast<ExchangeConflictResolution>(key.second);result+=wxString::Format("• %s: %zu (%s)\n",kind_name(static_cast<ExchangeRecordKind>(key.first)),count,resolution==ExchangeConflictResolution::imported?"incoming value will replace existing":resolution==ExchangeConflictResolution::preserved_both?"both references will be kept":"existing value will be kept");}
    result+="\nThe first conflicts are at:\n";for(std::size_t i=0;i<std::min<std::size_t>(plan.conflicts.size(),8);++i){auto& conflict=plan.conflicts[i];auto address=std::get_if<Address>(&conflict.location);result+=wxString::Format("• %s at %s\n",kind_name(conflict.kind),address ? wxString::Format("0x%llX",static_cast<unsigned long long>(address->offset)) : wxString("file location"));}
    if(plan.conflicts.size()>8)result+=wxString::Format("…and %zu more.\n",plan.conflicts.size()-8);return result;
}
void show_patch_manager(wxFrame &frame, SessionController &controller, DocumentId document,
                        std::shared_ptr<const ProjectSnapshot> project) {
    if (!project || !project->state || project->state->user->patches.empty()) return;
    const auto &patches = project->state->user->patches;
    constexpr std::size_t row_limit = 4096;
    const auto shown = std::min(patches.size(), row_limit);
    wxDialog dialog(&frame, wxID_ANY, "Patched byte ranges", wxDefaultPosition, wxDefaultSize,
                    wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);
    auto *layout = new wxBoxSizer(wxVERTICAL);
    auto *summary = new wxStaticText(&dialog, wxID_ANY,
        patches.size() > shown ? wxString::Format("%zu changed ranges (showing first %zu)", patches.size(), shown)
                               : wxString::Format("%zu changed ranges", patches.size()));
    layout->Add(summary, 0, wxALL, dialog.FromDIP(8));
    auto *list = new wxListCtrl(&dialog, wxID_ANY, wxDefaultPosition, dialog.FromDIP(wxSize(760, 300)),
                                wxLC_REPORT | wxLC_SINGLE_SEL | wxLC_HRULES | wxLC_VRULES);
    list->InsertColumn(0, "File offset", wxLIST_FORMAT_LEFT, dialog.FromDIP(145));
    list->InsertColumn(1, "Length", wxLIST_FORMAT_RIGHT, dialog.FromDIP(90));
    list->InsertColumn(2, "Original bytes", wxLIST_FORMAT_LEFT, dialog.FromDIP(240));
    list->InsertColumn(3, "Patched bytes", wxLIST_FORMAT_LEFT, dialog.FromDIP(240));
    const auto preview = [](std::span<const std::byte> bytes) {
        constexpr std::size_t preview_size = 24;
        auto result = hex_bytes(bytes.first(std::min(bytes.size(), preview_size)));
        if (bytes.size() > preview_size) result += " ...";
        return result;
    };
    for (std::size_t i = 0; i < shown; ++i) {
        const auto &span = patches[i];
        auto row = list->InsertItem(static_cast<long>(i), wxString::Format("0x%llX",
            static_cast<unsigned long long>(span.begin.value)));
        list->SetItem(row, 1, wxString::Format("%zu", span.replacement.size()));
        list->SetItem(row, 2, preview(span.original));
        list->SetItem(row, 3, preview(span.replacement));
    }
    layout->Add(list, 1, wxEXPAND | wxLEFT | wxRIGHT, dialog.FromDIP(8));
    auto *detail = new wxStaticText(&dialog, wxID_ANY, "Select a range to inspect its byte preview.");
    detail->Wrap(dialog.FromDIP(760));
    layout->Add(detail, 0, wxEXPAND | wxALL, dialog.FromDIP(8));
    auto *buttons = new wxBoxSizer(wxHORIZONTAL);
    auto *revert = new wxButton(&dialog, wxID_ANY, "Revert selected range");
    revert->Enable(false);
    auto *close = new wxButton(&dialog, wxID_CANCEL, "Close");
    buttons->Add(revert, 0, wxRIGHT, dialog.FromDIP(8));
    buttons->AddStretchSpacer();
    buttons->Add(close, 0);
    layout->Add(buttons, 0, wxEXPAND | wxALL, dialog.FromDIP(8));
    dialog.SetSizer(layout);
    dialog.SetSize(dialog.FromDIP(wxSize(820, 500)));
    dialog.CentreOnParent();
    const auto update_detail = [&]() {
        auto row = list->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        if (row < 0 || static_cast<std::size_t>(row) >= shown) {
            detail->SetLabel("Select a range to inspect its byte preview.");
            revert->Enable(false);
            return;
        }
        const auto &span = patches[static_cast<std::size_t>(row)];
        detail->SetLabel(wxString::Format("File offset 0x%llX, %zu bytes\nOriginal: %s\nPatched:  %s\nReverting creates a project history step; Undo restores this patch.",
            static_cast<unsigned long long>(span.begin.value), span.replacement.size(),
            preview(span.original), preview(span.replacement)));
        revert->Enable(project->mode == database::ProjectMode::read_write);
        dialog.Layout();
    };
    list->Bind(wxEVT_LIST_ITEM_SELECTED, [&](wxListEvent &) { update_detail(); });
    revert->Bind(wxEVT_BUTTON, [&](wxCommandEvent &) {
        auto row = list->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        if (row < 0 || static_cast<std::size_t>(row) >= shown) return;
        const auto &span = patches[static_cast<std::size_t>(row)];
        auto submitted = controller.execute(document,
            PatchBytes{Location{FileOffset{span.begin.value}}, span.original});
        if (!submitted) {
            controller.documents().report_error(document, submitted.error());
            return;
        }
        dialog.EndModal(wxID_OK);
    });
    if (shown) {
        list->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
        update_detail();
    }
    dialog.ShowModal();
}
} // namespace
ProjectActions::ProjectActions(wxFrame &frame, SessionController &controller,
                               std::function<std::optional<Location>()> selection)
    : frame_(frame), controller_(controller), selection_(std::move(selection)) {
    for (int id : actions) {
        frame_.Bind(wxEVT_MENU, &ProjectActions::command, this, id);
        frame_.Bind(wxEVT_UPDATE_UI, &ProjectActions::update, this, id);
    }
}
ProjectActions::~ProjectActions() {
    for (int id : actions) {
        frame_.Unbind(wxEVT_MENU, &ProjectActions::command, this, id);
        frame_.Unbind(wxEVT_UPDATE_UI, &ProjectActions::update, this, id);
    }
}
void ProjectActions::add_menus(wxMenu &file, wxMenu &edit) {
    auto position = file.GetMenuItemCount() - 2;
    file.InsertSeparator(position++);
    file.Insert(position++, wxID_SAVE, "&Save Project\tCtrl+S");
    file.Insert(position++, wxID_SAVEAS, "Save Project &As...\tCtrl+Shift+S");
    file.Insert(position++, backup_project_id, "Create Project &Backup...");
    file.Insert(position++, restore_backup_id, "Restore Backup as New Project...");
    file.Insert(position, export_id, "Export Patched &Binary...");
    file.InsertSeparator(position++);
    file.Insert(position++, exchange_export_id, "Export Project Metadata...");
    file.Insert(position, exchange_import_id, "Import Project Metadata...");
    edit.PrependSeparator();
    edit.Prepend(wxID_REDO, "&Redo\tCtrl+Y");
    edit.Prepend(wxID_UNDO, "&Undo\tCtrl+Z");
    edit.AppendSeparator();
    edit.Append(rename_id, "&Rename...\tN");
    edit.Append(comment_id, "&Comment...\t;");
    edit.Append(bookmark_id, "Toggle &Bookmark...");
    edit.Append(patch_id, "&Patch Bytes...");
    edit.Append(patch_manager_id, "Review/Revert Patches...");
    edit.AppendSeparator();
    edit.Append(code_id, "Define &Code...");
    edit.Append(data_id, "Define &Data...");
    edit.Append(function_id, "Define &Function");
    edit.Append(chunks_id, "Function Chunks...");
    edit.Append(suppress_id, "Toggle Function Suppression");
    edit.Append(reset_function_id, "Reset Function Override");
    edit.Append(reset_function_id, "Reset Function Override");
    edit.Append(reference_id, "Edit Explicit Reference...");
}
void ProjectActions::update(wxUpdateUIEvent &event) {
    auto id = controller_.documents().active_document();
    auto project = id ? controller_.documents().project(*id) : nullptr;
    if (event.GetId() == restore_backup_id) {
        event.Enable(true);
        return;
    }
    if (event.GetId() == backup_project_id) {
        bool saved = false;
        if (id)
            for (const auto &document : controller_.documents().documents())
                if (document.id == *id)
                    saved = document.path.has_value();
        event.Enable(id && saved && bool(controller_.documents().actor(*id)));
        return;
    }
    if (event.GetId() == patch_manager_id) {
        event.Enable(project && project->state && !project->state->user->patches.empty());
        return;
    }
    if(event.GetId()==exchange_export_id || event.GetId()==exchange_import_id){bool saved=false;if(id)for(auto& document:controller_.documents().documents())if(document.id==*id)saved=document.path.has_value();event.Enable(bool(project) && project->state && saved && project->mode==database::ProjectMode::read_write);return;}
    if (event.GetId() == find_next_id || event.GetId() == find_previous_id) {
        auto history = id ? controller_.documents().search_history(*id) : nullptr;
        bool enabled = false;
        if (history && !controller_.search_pending(*id)) {
            auto selected = history->selected_index();
            enabled =
                event.GetId() == find_previous_id
                    ? selected && *selected > 0
                    : history->size() > 0 && (!selected || *selected + 1 < history->size() || history->continuation());
        }
        event.Enable(enabled);
        return;
    }
    auto availability =
        action_availability(project.get(), event.GetId() == wxID_FIND ? ProjectActionKind::search : kind(event.GetId()),
                            selection_ ? selection_() : controller_.state().selection());
    event.Enable(availability.enabled);
    if (auto item = frame_.GetMenuBar()->FindItem(event.GetId()))
        item->SetHelp(availability.enabled ? wxString{} : text(availability.reason));
}
void ProjectActions::command(wxCommandEvent &event) {
    if (event.GetId() == restore_backup_id) {
        wxFileDialog source_dialog(&frame_, "Choose project backup", {}, {},
                                   "HexLab project backups (*.hxproj)|*.hxproj|All files (*.*)|*.*",
                                   wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (source_dialog.ShowModal() != wxID_OK)
            return;
        wxFileName source_name(source_dialog.GetPath());
        wxFileDialog destination_dialog(&frame_, "Restore backup as a new project", source_dialog.GetDirectory(),
                                        source_name.GetName() + "-restored.hxproj",
                                        "HexLab projects (*.hxproj)|*.hxproj|All files (*.*)|*.*",
                                        wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
        if (destination_dialog.ShowModal() != wxID_OK)
            return;
        auto active = controller_.documents().active_document();
        auto active_project = active ? controller_.documents().project(*active) : nullptr;
        const auto options = active_project ? active_project->analysis_options : AnalysisOptions{};
        std::error_code error;
        auto destination = std::filesystem::path(destination_dialog.GetPath().ToStdWstring());
        const bool replace = std::filesystem::exists(destination, error);
        if (error) {
            if (active)
                controller_.documents().report_error(*active, {ErrorCode::io, error.message()});
            else
                controller_.documents().report_error({ErrorCode::io, error.message()});
            return;
        }
        auto started = controller_.restore_backup(std::filesystem::path(source_dialog.GetPath().ToStdWstring()),
                                                  std::move(destination), replace, options);
        if (!started) {
            if (active)
                controller_.documents().report_error(*active, started.error());
            else
                controller_.documents().report_error(started.error());
            return;
        }
        if (active && controller_.message)
            controller_.message(*active, "Restoring backup into a new project...");
        return;
    }
    auto id = controller_.documents().active_document();
    if (!id)
        return;
    auto project = controller_.documents().project(*id);
    if (event.GetId() == backup_project_id) {
        std::optional<std::filesystem::path> current_path;
        for (const auto &document : controller_.documents().documents())
            if (document.id == *id)
                current_path = document.path;
        if (!current_path) {
            controller_.documents().report_error(*id, {ErrorCode::unsupported, "Save the project before creating a backup"});
            return;
        }
        const auto filename = current_path->stem().wstring() + L"-backup.hxproj";
        wxFileDialog dialog(&frame_, "Create project backup", wxString(current_path->parent_path().wstring()),
                            wxString(filename),
                            "HexLab project backups (*.hxproj)|*.hxproj|All files (*.*)|*.*",
                            wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
        if (dialog.ShowModal() != wxID_OK)
            return;
        auto path = std::filesystem::path(dialog.GetPath().ToStdWstring());
        std::error_code error;
        const bool replace = std::filesystem::exists(path, error);
        if (error) {
            controller_.documents().report_error(*id, {ErrorCode::io, error.message()});
            return;
        }
        auto submitted = controller_.backup_to(*id, std::move(path), replace);
        if (!submitted)
            controller_.documents().report_error(*id, submitted.error());
        else if (controller_.message)
            controller_.message(*id, "Creating a consistent project backup...");
        return;
    }
    if (event.GetId() == patch_manager_id) {
        show_patch_manager(frame_, controller_, *id, std::move(project));
        return;
    }
    if(event.GetId()==exchange_export_id){
        auto actor=controller_.documents().actor(*id);if(!actor || !project)return;
        if(actor->view().pending_operations){controller_.documents().report_error(*id,{ErrorCode::busy,"Wait for pending project operations before exporting metadata"});return;}
        wxFileDialog dialog(&frame_,"Export project metadata",{},"analysis.hxex","HexLab exchange files (*.hxex)|*.hxex|All files (*.*)|*.*",wxFD_SAVE|wxFD_OVERWRITE_PROMPT);
        if(dialog.ShowModal()!=wxID_OK)return;auto path=std::filesystem::path(dialog.GetPath().ToStdWstring());std::error_code error;bool replace=std::filesystem::exists(path,error);if(error){controller_.documents().report_error(*id,{ErrorCode::io,error.message()});return;}auto written=write_exchange(*project,path,replace);if(!written)controller_.documents().report_error(*id,written.error());return;
    }
    if(event.GetId()==exchange_import_id){
        auto actor=controller_.documents().actor(*id);if(!actor || !project)return;
        if(actor->view().pending_operations){controller_.documents().report_error(*id,{ErrorCode::busy,"Wait for pending project operations before importing metadata"});return;}
        wxFileDialog dialog(&frame_,"Import project metadata",{}, {},"HexLab exchange files (*.hxex)|*.hxex|All files (*.*)|*.*",wxFD_OPEN|wxFD_FILE_MUST_EXIST);if(dialog.ShowModal()!=wxID_OK)return;
        auto bytes=read_exchange(std::filesystem::path(dialog.GetPath().ToStdWstring()));if(!bytes){controller_.documents().report_error(*id,bytes.error());return;}
        wxArrayString policies;policies.Add("Fail on conflicts (default)");policies.Add("Skip conflicting incoming records");policies.Add("Replace conflicting destination records");wxSingleChoiceDialog choose(&frame_,"Choose how conflicting metadata should be handled.","Import conflict policy",policies);choose.SetSelection(0);if(choose.ShowModal()!=wxID_OK)return;
        auto policy=choose.GetSelection()==1?ExchangeConflictPolicy::skip:choose.GetSelection()==2?ExchangeConflictPolicy::replace:ExchangeConflictPolicy::fail;
        auto planned=import_project_exchange(*project,bytes.value(),policy,max_exchange_bytes);if(!planned){controller_.documents().report_error(*id,planned.error());return;}if(planned.value().commands.empty()){wxMessageBox(import_summary(planned.value()),"Project metadata import",wxOK|wxICON_INFORMATION,&frame_);return;}
        auto summary=import_summary(planned.value());if(wxMessageBox(summary+"\nApply all imported metadata as one project change?","Review project metadata import",wxYES_NO|wxICON_QUESTION,&frame_)!=wxYES)return;
        auto submitted=actor->execute_batch(std::move(planned.value().commands));if(!submitted){controller_.documents().report_error(*id,submitted.error());return;}auto watched=controller_.documents().watch(*id,std::move(submitted.value()));if(!watched)controller_.documents().report_error(*id,watched.error());return;
    }
    auto selection = selection_ ? selection_() : controller_.state().selection();
    auto accepted = [&](auto result) {
        if (!result)
            controller_.documents().report_error(*id, result.error());
    };
    if (event.GetId() == find_next_id) {
        accepted(controller_.find_next(*id));
        return;
    }
    if (event.GetId() == find_previous_id) {
        accepted(controller_.find_previous(*id));
        return;
    }
    auto availability = action_availability(
        project.get(), event.GetId() == wxID_FIND ? ProjectActionKind::search : kind(event.GetId()), selection);
    if (!availability.enabled) {
        controller_.documents().report_error(*id, {ErrorCode::invalid_argument, availability.reason});
        return;
    }
    if (event.GetId() == wxID_FIND) {
        auto request = find_dialog(&frame_);
        if (request) {
            if (request->start_from_selection) {
                if (!selection) {
                    controller_.documents().report_error(*id, {ErrorCode::invalid_argument,
                        "Select a file offset or mapped instruction before starting the search."});
                    return;
                }
                if (const auto *offset = std::get_if<FileOffset>(&*selection)) {
                    request->limits.start_offset = offset->value;
                } else if (project && project->loaded && project->loaded->image) {
                    const auto address = std::get<Address>(*selection);
                    auto offset = project->loaded->image->to_file_offset(address);
                    if (!offset) {
                        controller_.documents().report_error(*id, {ErrorCode::out_of_bounds,
                            "The selected address has no unique file-backed search offset."});
                        return;
                    }
                    request->limits.start_offset = offset.value().value;
                    request->limits.start_address = address;
                } else {
                    controller_.documents().report_error(*id, {ErrorCode::unsupported,
                        "The selected address cannot be mapped to this document's file bytes."});
                    return;
                }
            }
            controller_.set_all_search_scope(request->all_documents);
            if (request->all_documents)
                accepted(controller_.find_all(std::move(request->query), request->limits));
            else
                accepted(controller_.find(*id, std::move(request->query), request->limits));
            if (auto docking = wxAuiManager::GetManager(&frame_)) {
                docking->GetPane("search").Show();
                docking->Update();
            }
        }
        return;
    }
    if (event.GetId() == reanalyze_id) {
        accepted(controller_.reanalyze(*id));
        return;
    }
    if (event.GetId() == wxID_UNDO) {
        accepted(controller_.undo(*id));
        return;
    }
    if (event.GetId() == wxID_REDO) {
        accepted(controller_.redo(*id));
        return;
    }
    if (event.GetId() == wxID_SAVE || event.GetId() == wxID_SAVEAS || event.GetId() == export_id) {
        auto info = controller_.documents().documents();
        bool untitled = false;
        for (auto &entry : info)
            if (entry.id == *id)
                untitled = !entry.path;
        if (event.GetId() == wxID_SAVE && !untitled) {
            accepted(controller_.save(*id));
            return;
        }
        bool binary = event.GetId() == export_id;
        wxFileDialog dialog(
            &frame_, binary ? "Export patched binary" : "Save project", {}, binary ? "patched.bin" : "analysis.hxproj",
            binary ? "All files (*.*)|*.*" : "HexLab projects (*.hxproj)|*.hxproj", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
        if (dialog.ShowModal() != wxID_OK)
            return;
        std::filesystem::path path = dialog.GetPath().ToStdWstring();
        std::error_code error;
        bool replace = std::filesystem::exists(path, error);
        if (error) {
            controller_.documents().report_error(*id, {ErrorCode::io, error.message()});
            return;
        }
        accepted(binary ? controller_.export_binary(*id, std::move(path), replace)
                        : controller_.save_as(*id, std::move(path), replace));
        return;
    }
    if (!selection)
        return;
    auto location = *selection;
    std::optional<ProjectCommand> command;
    if (event.GetId() == rename_id || event.GetId() == comment_id) {
        bool rename = event.GetId() == rename_id;
        auto presentation = presentation_at(*project, location);
        command = edit_dialog(&frame_, rename ? "Rename location" : "Comment location",
                              rename ? "A unique name in this address space. Empty restores the automatic name."
                                     : "Comment for this location:",
                              text(rename ? presentation.name : presentation.comment), !rename,
                              [location, rename](const wxString &value) -> Result<ProjectCommand> {
                                  if (rename)
                                      return ProjectCommand{Rename{location, utf8(value)}};
                                  return ProjectCommand{Comment{location, utf8(value)}};
                              });
    } else if (event.GetId() == bookmark_id) {
        auto existing = std::find_if(project->state->user->bookmarks.begin(), project->state->user->bookmarks.end(),
                                     [&](auto &row) { return row.location == location; });
        if (existing != project->state->user->bookmarks.end())
            command = BookmarkCommand{location, {}, true};
        else
            command = edit_dialog(&frame_, "Bookmark location", "Bookmark label:", "", false,
                                  [location](const wxString &value) -> Result<ProjectCommand> {
                                      return ProjectCommand{BookmarkCommand{location, utf8(value), false}};
                                  });
    } else if (event.GetId() == patch_id) {
        command =
            edit_dialog(&frame_, "Patch bytes", "Replacement hex octets, separated by spaces (same input length):", "",
                        true, [location](const wxString &value) -> Result<ProjectCommand> {
                            auto bytes = parse_patch_text(value);
                            if (!bytes)
                                return bytes.error();
                            return ProjectCommand{PatchBytes{location, std::move(bytes.value())}};
                        });
    } else if (event.GetId() == code_id || event.GetId() == data_id) {
        auto begin = std::get<Address>(location);
        auto region_kind = event.GetId() == code_id ? RegionKind::code : RegionKind::data;
        command = edit_dialog(&frame_, region_kind == RegionKind::code ? "Define code" : "Define data",
                              "Range size in bytes (decimal or 0x hex):", "1", false,
                              [begin, region_kind](const wxString &value) -> Result<ProjectCommand> {
                                  auto size = parse_address(value.ToStdWstring());
                                  if (!size)
                                      return size.error();
                                  return ProjectCommand{DefineRegion{begin, size.value(), region_kind}};
                              });
    } else if (event.GetId() == function_id)
        command = DefineFunction{std::get<Address>(location)};
    else if (event.GetId() == chunks_id) {
        auto entry = std::get<Address>(location);
        wxString initial;
        for (auto &definition : project->state->user->decisions.functions)
            if (definition.entry == entry)
                for (auto &chunk : definition.chunks) {
                    if (!initial.empty())
                        initial += ", ";
                    initial += wxString::Format("0x%llX+0x%llX", static_cast<unsigned long long>(chunk.begin.offset),
                                                static_cast<unsigned long long>(chunk.size));
                }
        command = edit_dialog(&frame_, "Function chunks",
                              "address+size pairs, separated by commas. Empty clears explicit chunks.", initial, true,
                              [entry](const wxString &value) -> Result<ProjectCommand> {
                                  auto chunks = parse_chunk_text(value, entry.space);
                                  if (!chunks)
                                      return chunks.error();
                                  return ProjectCommand{SetFunctionChunks{entry, std::move(chunks.value())}};
                              });
    } else if (event.GetId() == suppress_id) {
        auto entry = std::get<Address>(location);
        bool suppressed = false;
        for (auto &definition : project->state->user->decisions.functions)
            if (definition.entry == entry)
                suppressed = definition.suppressed;
        command = SuppressFunction{entry, !suppressed};
    } else if (event.GetId() == reset_function_id) {
        command = ResetFunctionOverride{std::get<Address>(location)};
    } else if (event.GetId() == reference_id) {
        auto space = std::get_if<Address>(&location) ? std::get<Address>(location).space
                     : project->loaded               ? project->loaded->image->layout().space.id
                                                     : AddressSpaceId{0};
        command = reference_dialog(&frame_, location, space, project->loaded ? project->loaded->image : nullptr);
    }
    if (command)
        accepted(controller_.execute(*id, std::move(*command)));
}
} // namespace hexlab::desktop
