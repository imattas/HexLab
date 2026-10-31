#include "project_actions.hpp"
#include "edit_dialogs.hpp"
#include "reference_dialog.hpp"
#include "data_views.hpp"
#include "search_view.hpp"
#include "hexlab/image/file_publication.hpp"
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
#include <wx/numdlg.h>
#include <wx/checkbox.h>
#include <wx/clipbrd.h>
#include <wx/log.h>
#include <wx/spinctrl.h>
#include <wx/textctrl.h>
#include <algorithm>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
namespace hexlab::desktop {
namespace {
constexpr std::size_t max_exchange_bytes = 16u * 1024u * 1024u;
constexpr std::size_t max_annotation_tsv_bytes = 4u * 1024u * 1024u;
constexpr int actions[] = {wxID_SAVE,  wxID_SAVEAS,  wxID_UNDO,        wxID_REDO,   rename_id,
                           comment_id, bookmark_id,  code_id,          data_id,     function_id,
                           chunks_id,  suppress_id,  reset_function_id, reference_id, patch_id, export_id,
                           wxID_FIND,  find_next_id, find_previous_id, reanalyze_id,
                           exchange_export_id, exchange_import_id, patch_manager_id,
                           backup_project_id, restore_backup_id, rotate_backups_id, list_backups_id,
                           prune_backups_id, restore_backup_in_place_id, restore_recovery_in_place_id,
                           restore_recovery_id,
                           automatic_backups_id, archive_source_id,
                           rotate_source_archives_id, list_source_archives_id, prune_source_archives_id,
                           verify_source_archive_id, cancel_source_archive_id, annotation_review_id};
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
    switch (kind) { case ExchangeRecordKind::annotation:return "Annotations"; case ExchangeRecordKind::bookmark:return "Bookmarks"; case ExchangeRecordKind::reference:return "References"; case ExchangeRecordKind::region:return "Code/data regions"; case ExchangeRecordKind::function:return "Functions"; case ExchangeRecordKind::type_definition:return "Type definitions"; case ExchangeRecordKind::type_assignment:return "Type assignments"; case ExchangeRecordKind::debug_variable:return "Debug variables"; case ExchangeRecordKind::project_breakpoint:return "Project breakpoints"; case ExchangeRecordKind::patch:return "Byte patches"; }
    return "Records";
}
Result<std::vector<std::byte>> read_exchange(const std::filesystem::path& path) {
    std::error_code error;auto size=std::filesystem::file_size(path,error);if(error)return Error{ErrorCode::io,"Cannot inspect exchange file: "+error.message()};
    if(size>max_exchange_bytes)return Error{ErrorCode::resource_limit,"Exchange file exceeds 16 MiB limit"};
    std::ifstream input(path,std::ios::binary);if(!input)return Error{ErrorCode::io,"Cannot open exchange file"};std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    if(size && !input.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(size)))return Error{ErrorCode::io,"Cannot read complete exchange file"};return bytes;
}
Result<bool> write_exchange(const ProjectSnapshot& project,const std::filesystem::path& path,bool replace) {
    auto bytes=export_project_exchange(project,max_exchange_bytes);if(!bytes)return bytes.error();
    auto publication=FilePublication::create(path,replace?ExistingFilePolicy::replace:ExistingFilePolicy::reject,
                                             project.protected_paths,{});
    if(!publication)return publication.error();
    auto appended=publication.value()->append(bytes.value());if(!appended)return appended.error();
    if(appended.value()!=bytes.value().size())return Error{ErrorCode::io,"Exchange output write was incomplete"};
    return publication.value()->publish();
}
wxString import_summary(const ExchangeImport& plan) {
    wxString result=wxString::Format("Ready to import %zu annotations, %zu bookmarks, %zu references, %zu regions, %zu functions, %zu type definitions, %zu type assignments, %zu debug variables, %zu project breakpoints, and %zu byte patches.\nSkipped identical records or conflicting patch spans: %zu.\n\n",
      plan.annotations,plan.bookmarks,plan.references,plan.regions,plan.functions,plan.type_definitions,plan.type_assignments,plan.debug_variables,plan.project_breakpoints,plan.patches,plan.skipped);
    if(plan.conflicts.empty())return result+"No conflicts.";
    result+=wxString::Format("Conflicts: %zu\n",plan.conflicts.size());std::map<std::pair<int,int>,std::size_t> counts;
    for(auto& conflict:plan.conflicts)counts[{static_cast<int>(conflict.kind),static_cast<int>(conflict.resolution)}]++;
    for(auto& [key,count]:counts){auto resolution=static_cast<ExchangeConflictResolution>(key.second);result+=wxString::Format("• %s: %zu (%s)\n",kind_name(static_cast<ExchangeRecordKind>(key.first)),count,resolution==ExchangeConflictResolution::imported?"incoming value will replace existing":resolution==ExchangeConflictResolution::preserved_both?"both references will be kept":"existing value will be kept");}
    result+="\nThe first conflicts are at:\n";for(std::size_t i=0;i<std::min<std::size_t>(plan.conflicts.size(),8);++i){auto& conflict=plan.conflicts[i];auto address=std::get_if<Address>(&conflict.location);auto file=std::get_if<FileOffset>(&conflict.location);result+=wxString::Format("• %s at %s\n",kind_name(conflict.kind),address ? wxString::Format("0x%llX",static_cast<unsigned long long>(address->offset)) : file ? wxString::Format("file+0x%llX",static_cast<unsigned long long>(file->value)) : wxString("file location"));}
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
void show_annotation_review(wxFrame& frame, SessionController& controller, DocumentId document,
                            std::shared_ptr<const ProjectSnapshot> project) {
    if (!project || !project->state || !project->state->user) return;
    const auto actor = controller.documents().actor(document);
    const auto source_key = project_analysis_key(*project, project->analysis_options);
    const auto expected_edit = project->state->revisions.edit;
    const auto session = actor ? std::optional{actor->view().session} : std::nullopt;
    const bool writable = actor && source_key && project->mode != database::ProjectMode::read_only;
    const auto& annotations = project->state->user->annotations;
    constexpr std::size_t page_size = 512;
    std::size_t page_start = 0, page_count = 0;
    bool search_all_rows = false;
    std::vector<std::size_t> all_matches;
    constexpr std::size_t all_search_limit = 100000;
    wxDialog dialog(&frame, wxID_ANY, "Review Names and Comments", wxDefaultPosition, wxDefaultSize,
                    wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);
    auto* layout = new wxBoxSizer(wxVERTICAL);
    auto* status = new wxStaticText(&dialog, wxID_ANY, {});
    status->SetName("annotation-review-status");
    layout->Add(status, 0, wxEXPAND | wxALL, dialog.FromDIP(8));
    auto* filter = new wxTextCtrl(&dialog, wxID_ANY, {});
    filter->SetName("annotation-review-filter");
    filter->SetHint("Filter annotations by location, saved name, or comment");
    filter->SetToolTip("Case-insensitive substring filter over the current page, or over up to 100,000 rows when Search all rows is enabled.");
    layout->Add(filter, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, dialog.FromDIP(8));
    auto* search_all = new wxCheckBox(&dialog, wxID_ANY, "Search all rows (up to 100,000)");
    search_all->SetName("annotation-review-search-all");
    layout->Add(search_all, 0, wxLEFT | wxRIGHT | wxBOTTOM, dialog.FromDIP(8));
    auto* search = new wxButton(&dialog, wxID_ANY, "Search all now");
    search->SetName("annotation-review-search-all-now");
    search->Hide();
    layout->Add(search, 0, wxLEFT | wxRIGHT | wxBOTTOM, dialog.FromDIP(8));
    auto* list = new wxListCtrl(&dialog, wxID_ANY, wxDefaultPosition, dialog.FromDIP(wxSize(780, 320)),
                                wxLC_REPORT | wxLC_HRULES | wxLC_VRULES);
    list->SetName("annotation-review-rows");
    for (const auto* column : {"Location", "Saved name", "Saved comment"}) list->InsertColumn(list->GetColumnCount(), column);
    list->SetColumnWidth(0, dialog.FromDIP(200)); list->SetColumnWidth(1, dialog.FromDIP(230));
    list->SetColumnWidth(2, dialog.FromDIP(330));
    layout->Add(list, 1, wxEXPAND | wxLEFT | wxRIGHT, dialog.FromDIP(8));
    auto* preview = new wxTextCtrl(&dialog, wxID_ANY, {}, wxDefaultPosition, dialog.FromDIP(wxSize(-1, 100)),
                                   wxTE_READONLY | wxTE_MULTILINE);
    preview->SetName("annotation-review-preview");
    layout->Add(preview, 0, wxEXPAND | wxALL, dialog.FromDIP(8));
    auto* options = new wxBoxSizer(wxHORIZONTAL);
    auto* names = new wxCheckBox(&dialog, wxID_ANY, "Clear saved names"); names->SetValue(true);
    auto* comments = new wxCheckBox(&dialog, wxID_ANY, "Clear saved comments");
    names->Enable(writable); comments->Enable(writable);
    options->Add(names, 0, wxRIGHT, dialog.FromDIP(12)); options->Add(comments);
    layout->Add(options, 0, wxALL, dialog.FromDIP(8));
    auto* buttons = new wxBoxSizer(wxHORIZONTAL);
    auto* previous = new wxButton(&dialog, wxID_ANY, "Previous page");
    auto* next = new wxButton(&dialog, wxID_ANY, "Next page");
    auto* copy = new wxButton(&dialog, wxID_ANY, "Copy selected TSV");
    copy->SetName("annotation-review-copy-tsv"); copy->Enable(false);
    auto* replace = new wxButton(&dialog, wxID_ANY, "Replace selected comments...");
    replace->SetName("annotation-review-replace-comments"); replace->Enable(false);
    auto* replace_names = new wxButton(&dialog, wxID_ANY, "Replace selected names...");
    replace_names->SetName("annotation-review-replace-names"); replace_names->Enable(false);
    auto* assign_type = new wxButton(&dialog, wxID_ANY, "Assign type to selected addresses...");
    assign_type->SetName("annotation-review-assign-type");
    assign_type->SetToolTip("Assign one existing project type to selected rows with virtual addresses. File-offset rows cannot receive address assignments.");
    assign_type->Enable(false);
    auto* clear = new wxButton(&dialog, wxID_ANY, "Clear selected fields...");
    clear->SetName("annotation-review-clear"); clear->Enable(false);
    buttons->Add(previous, 0, wxRIGHT, dialog.FromDIP(4)); buttons->Add(next);
    buttons->AddStretchSpacer(); buttons->Add(assign_type, 0, wxRIGHT, dialog.FromDIP(8));
    buttons->Add(replace_names, 0, wxRIGHT, dialog.FromDIP(8));
    buttons->Add(replace, 0, wxRIGHT, dialog.FromDIP(8));
    buttons->Add(copy, 0, wxRIGHT, dialog.FromDIP(8));
    buttons->Add(clear, 0, wxRIGHT, dialog.FromDIP(8));
    buttons->Add(new wxButton(&dialog, wxID_CANCEL, "Close"));
    layout->Add(buttons, 0, wxEXPAND | wxALL, dialog.FromDIP(8));
    dialog.SetSizer(layout); dialog.SetSize(dialog.FromDIP(wxSize(1020, 600))); dialog.CentreOnParent();
    const auto clipped = [](std::string_view value, std::size_t limit) {
        auto count = std::min(value.size(), limit);
        while (count < value.size() && count && (static_cast<unsigned char>(value[count]) & 0xc0u) == 0x80u) --count;
        auto result = wxString::FromUTF8(value.data(), count);
        if (count < value.size()) result += " ... [truncated]";
        return result;
    };
    std::vector<std::size_t> visible_rows;
    const auto update_selection = [&] {
        const auto selected = list->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        replace->Enable(writable && selected >= 0);
        replace_names->Enable(writable && selected >= 0);
        copy->Enable(selected >= 0);
        clear->Enable(writable && selected >= 0 && (names->IsChecked() || comments->IsChecked()));
        bool has_selection = false, all_selected_are_addresses = true;
        for (long row_index = list->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED); row_index >= 0;
             row_index = list->GetNextItem(row_index, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED)) {
            has_selection = true;
            if (static_cast<std::size_t>(row_index) >= visible_rows.size() ||
                !std::holds_alternative<Address>(annotations[visible_rows[static_cast<std::size_t>(row_index)]].location)) {
                all_selected_are_addresses = false;
                break;
            }
        }
        assign_type->Enable(writable && has_selection && all_selected_are_addresses &&
            !project->state->user->types.empty());
        if (selected < 0 || static_cast<std::size_t>(selected) >= visible_rows.size()) {
            preview->ChangeValue("Select rows with Ctrl/Shift. Copy, name/comment replacement, and clear actions use only selected rows on the visible result page.");
            return;
        }
        const auto& row = annotations[visible_rows[static_cast<std::size_t>(selected)]];
        preview->ChangeValue(location_text(row.location, project->loaded ? project->loaded->image.get() : nullptr) +
            "\nSaved name: " + clipped(row.name, 512) + "\nSaved comment: " + clipped(row.comment, 4096));
    };
    const auto populate = [&] {
        list->DeleteAllItems();
        visible_rows.clear();
        const auto query = filter->GetValue().Lower();
        std::size_t result_count = 0;
        if (search_all_rows) {
            all_matches.clear();
            const auto scan_count = std::min(annotations.size(), all_search_limit);
            for (std::size_t index = 0; index < scan_count; ++index) {
                const auto& row = annotations[index];
                const auto location = location_text(row.location, project->loaded ? project->loaded->image.get() : nullptr);
                const auto searchable = location + " " + wxString::FromUTF8(row.name.data(), row.name.size()) + " " +
                    wxString::FromUTF8(row.comment.data(), row.comment.size());
                if (query.empty() || searchable.Lower().Find(query) != wxNOT_FOUND) all_matches.push_back(index);
            }
            result_count = all_matches.size();
            page_count = page_start < result_count ? std::min(page_size, result_count - page_start) : 0;
            for (std::size_t index = 0; index < page_count; ++index)
                visible_rows.push_back(all_matches[page_start + index]);
        } else {
            page_count = page_start < annotations.size() ? std::min(page_size, annotations.size() - page_start) : 0;
            for (std::size_t index = 0; index < page_count; ++index) {
                const auto row_index = page_start + index;
                const auto& row = annotations[row_index];
                const auto location = location_text(row.location, project->loaded ? project->loaded->image.get() : nullptr);
                const auto searchable = location + " " + wxString::FromUTF8(row.name.data(), row.name.size()) + " " +
                    wxString::FromUTF8(row.comment.data(), row.comment.size());
                if (!query.empty() && searchable.Lower().Find(query) == wxNOT_FOUND) continue;
                visible_rows.push_back(row_index);
            }
            result_count = annotations.size();
        }
        for (const auto row_index : visible_rows) {
            const auto& row = annotations[row_index];
            const auto location = location_text(row.location, project->loaded ? project->loaded->image.get() : nullptr);
            const auto item = list->InsertItem(list->GetItemCount(), location);
            list->SetItem(item, 1, clipped(row.name, 128));
            auto comment = clipped(row.comment, 160); comment.Replace("\r", "\\r"); comment.Replace("\n", "\\n");
            list->SetItem(item, 2, comment);
        }
        const auto range_start = page_start + (page_count ? 1 : 0);
        const auto range_end = page_start + page_count;
        auto status_text = wxString::Format("%zu matching rows shown (%zu-%zu of %zu); edit revision %llu",
            visible_rows.size(), range_start, range_end, search_all_rows ? result_count : annotations.size(),
            static_cast<unsigned long long>(expected_edit));
        if (search_all_rows && annotations.size() > all_search_limit) status_text += "; scan capped at 100,000";
        status->SetLabel(status_text + (writable ? wxString{} : wxString(" (review only)")));
        previous->Enable(page_start != 0); next->Enable(page_start + page_count < (search_all_rows ? result_count : annotations.size()));
        update_selection();
    };
    list->Bind(wxEVT_LIST_ITEM_SELECTED, [&](wxListEvent&) { update_selection(); });
    list->Bind(wxEVT_LIST_ITEM_DESELECTED, [&](wxListEvent&) { update_selection(); });
    filter->Bind(wxEVT_TEXT, [&](wxCommandEvent&) { if (!search_all_rows) { page_start = 0; populate(); } });
    search_all->Bind(wxEVT_CHECKBOX, [&](wxCommandEvent& event) {
        search_all_rows = event.IsChecked(); page_start = 0; search->Show(search_all_rows); layout->Layout(); populate();
    });
    search->Bind(wxEVT_BUTTON, [&](wxCommandEvent&) { page_start = 0; populate(); });
    names->Bind(wxEVT_CHECKBOX, [&](wxCommandEvent&) { update_selection(); });
    comments->Bind(wxEVT_CHECKBOX, [&](wxCommandEvent&) { update_selection(); });
    previous->Bind(wxEVT_BUTTON, [&](wxCommandEvent&) { if (page_start >= page_size) { page_start -= page_size; populate(); } });
    next->Bind(wxEVT_BUTTON, [&](wxCommandEvent&) { if (page_start + page_count < (search_all_rows ? all_matches.size() : annotations.size())) { page_start += page_size; populate(); } });
    copy->Bind(wxEVT_BUTTON, [&](wxCommandEvent&) {
        std::string output = "Location\tName\tComment\r\n";
        const auto append_literal = [&](std::string_view value) {
            if (value.size() > max_annotation_tsv_bytes - output.size()) return false;
            output.append(value);
            return true;
        };
        const auto append_field = [&](std::string_view value) {
            const bool quote = value.find_first_of("\t\r\n\"") != std::string_view::npos;
            const auto required = value.size() + (quote ? 2 : 0) +
                (quote ? static_cast<std::size_t>(std::count(value.begin(), value.end(), '"')) : 0);
            if (required > max_annotation_tsv_bytes - output.size()) return false;
            if (quote) output.push_back('"');
            for (const auto ch : value) {
                output.push_back(ch);
                if (quote && ch == '"') output.push_back('"');
            }
            if (quote) output.push_back('"');
            return true;
        };
        std::size_t copied = 0;
        for (long selected = list->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED); selected >= 0;
             selected = list->GetNextItem(selected, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED)) {
            if (static_cast<std::size_t>(selected) >= visible_rows.size()) continue;
            const auto& row = annotations[visible_rows[static_cast<std::size_t>(selected)]];
            const auto location = location_text(row.location, project->loaded ? project->loaded->image.get() : nullptr).utf8_str();
            if (copied && !append_literal("\r\n")) {
                preview->ChangeValue("TSV export exceeds the 4 MiB clipboard limit; nothing was copied."); return;
            }
            if (!append_field(std::string_view(location.data(), location.length()))) {
                preview->ChangeValue("TSV export exceeds the 4 MiB clipboard limit; nothing was copied."); return;
            }
            if (!append_literal("\t")) {
                preview->ChangeValue("TSV export exceeds the 4 MiB clipboard limit; nothing was copied."); return;
            }
            if (!append_field(row.name)) {
                preview->ChangeValue("TSV export exceeds the 4 MiB clipboard limit; nothing was copied."); return;
            }
            if (!append_literal("\t")) {
                preview->ChangeValue("TSV export exceeds the 4 MiB clipboard limit; nothing was copied."); return;
            }
            if (!append_field(row.comment)) {
                preview->ChangeValue("TSV export exceeds the 4 MiB clipboard limit; nothing was copied."); return;
            }
            ++copied;
        }
        if (!copied) { preview->ChangeValue("No selected rows to copy."); return; }
        wxLogNull quiet;
        if (!wxTheClipboard || !wxTheClipboard->Open()) {
            preview->ChangeValue("Clipboard is unavailable; nothing was copied."); return;
        }
        auto data = std::make_unique<wxTextDataObject>(wxString::FromUTF8(output.data(), output.size()));
        bool stored = wxTheClipboard->SetData(data.get());
        if (stored) data.release();
        if (stored) stored = wxTheClipboard->Flush();
        wxTheClipboard->Close();
        preview->ChangeValue(stored
            ? wxString::Format("Copied %zu selected annotation rows as TSV (%zu bytes).", copied, output.size())
            : wxString("Clipboard copy failed; project annotations were not changed."));
    });
    const auto replace_selected_text = [&](bool replace_name) {
        if (!writable || !session) return;
        const wxString field = replace_name ? "saved names" : "saved comments";
        const wxString action_title = replace_name ? "Replace selected names" : "Replace selected comments";
        wxTextEntryDialog find_dialog(&dialog, wxString("Literal text to find in selected ") + field + ":", action_title);
        if (find_dialog.ShowModal() != wxID_OK) return;
        const auto find_utf8 = find_dialog.GetValue().utf8_str();
        const std::string needle = find_utf8.length()
            ? std::string(find_utf8.data(), find_utf8.length()) : std::string{};
        if (needle.empty()) {
            preview->ChangeValue(wxString("Enter non-empty text to find; no ") + field + " were changed.");
            return;
        }
        if (needle.size() > 1024u * 1024u) {
            preview->ChangeValue(wxString("Find text exceeds the 1 MiB limit; no ") + field + " were changed.");
            return;
        }
        std::vector<std::size_t> prefix(needle.size());
        for (std::size_t index = 1, matched = 0; index < needle.size(); ++index) {
            while (matched && needle[index] != needle[matched]) matched = prefix[matched - 1];
            if (needle[index] == needle[matched]) ++matched;
            prefix[index] = matched;
        }
        wxTextEntryDialog replacement_dialog(&dialog, "Replacement text (empty removes the matched text):", action_title);
        if (replacement_dialog.ShowModal() != wxID_OK) return;
        const auto replacement_utf8 = replacement_dialog.GetValue().utf8_str();
        const std::string replacement_text = replacement_utf8.length()
            ? std::string(replacement_utf8.data(), replacement_utf8.length()) : std::string{};
        if (replacement_text.size() > 1024u * 1024u) {
            preview->ChangeValue(wxString("Replacement text exceeds the 1 MiB limit; no ") + field + " were changed.");
            return;
        }

        constexpr std::size_t max_replacement_batch_bytes = 4u * 1024u * 1024u;
        const auto replace_literal = [&](std::string_view source)
            -> std::optional<std::pair<std::string, std::size_t>> {
            std::string updated;
            std::size_t copied = 0, matched = 0, occurrences = 0;
            for (std::size_t index = 0; index < source.size(); ++index) {
                while (matched && source[index] != needle[matched]) matched = prefix[matched - 1];
                if (source[index] == needle[matched]) ++matched;
                if (matched != needle.size()) continue;
                const auto begin = index + 1 - needle.size();
                if (begin >= copied) {
                    const auto literal_size = begin - copied;
                    if (literal_size > max_replacement_batch_bytes - updated.size()) return {};
                    updated.append(source.data() + copied, literal_size);
                    if (replacement_text.size() > max_replacement_batch_bytes - updated.size()) return {};
                    updated += replacement_text;
                    copied = index + 1;
                    ++occurrences;
                    matched = 0;
                } else {
                    matched = prefix[matched - 1];
                }
            }
            const auto tail_size = source.size() - copied;
            if (tail_size > max_replacement_batch_bytes - updated.size()) return {};
            updated.append(source.data() + copied, tail_size);
            return std::pair{std::move(updated), occurrences};
        };
        std::vector<ProjectCommand> commands;
        wxString preview_samples;
        std::size_t scanned_bytes = 0, planned_bytes = 0, preview_rows = 0;
        std::size_t replaced_rows = 0, replaced_occurrences = 0;
        bool over_limit = false;
        for (long selected = list->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED); selected >= 0;
             selected = list->GetNextItem(selected, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED)) {
            if (static_cast<std::size_t>(selected) >= visible_rows.size()) continue;
            const auto& row = annotations[visible_rows[static_cast<std::size_t>(selected)]];
            const auto& source = replace_name ? row.name : row.comment;
            if (source.size() > max_replacement_batch_bytes - scanned_bytes) {
                over_limit = true;
                break;
            }
            scanned_bytes += source.size();
            auto replacement_plan = replace_literal(source);
            if (!replacement_plan) { over_limit = true; break; }
            auto updated = std::move(replacement_plan->first);
            const auto occurrences = replacement_plan->second;
            if (!occurrences || updated == source) continue;
            if (updated.size() > max_replacement_batch_bytes - planned_bytes) {
                over_limit = true;
                break;
            }
            planned_bytes += updated.size();
            if (preview_rows < 3) {
                auto before = clipped(source, 256);
                auto after = clipped(updated, 256);
                before.Replace("\r", "\\r"); before.Replace("\n", "\\n");
                after.Replace("\r", "\\r"); after.Replace("\n", "\\n");
                const auto where = location_text(row.location, project->loaded ? project->loaded->image.get() : nullptr);
                preview_samples += wxString::Format("At %s\nBefore: %s\nAfter:  %s\n\n", where, before, after);
                ++preview_rows;
            }
            if (replace_name) commands.emplace_back(Rename{row.location, std::move(updated)});
            else commands.emplace_back(Comment{row.location, std::move(updated)});
            ++replaced_rows;
            replaced_occurrences += occurrences;
        }
        if (over_limit) {
            preview->ChangeValue(wxString("Replacement plan exceeds the 4 MiB batch limit; no ") + field + " were changed.");
            return;
        }
        if (commands.empty()) {
            preview->ChangeValue(wxString("No selected ") + field + " would change.");
            return;
        }

        wxString confirmation = wxString::Format(
            "Replace %zu literal occurrence(s) in %zu selected %s?\n\n",
            replaced_occurrences, replaced_rows, replace_name ? "name(s)" : "comment(s)");
        confirmation += preview_samples;
        if (commands.size() > preview_rows)
            confirmation += wxString::Format("... and %zu more selected %s.\n\n", commands.size() - preview_rows,
                replace_name ? "name(s)" : "comment(s)");
        confirmation += "The replacement will be one undoable project change.";
        if (wxMessageBox(confirmation, replace_name ? "Review name replacement" : "Review comment replacement",
                         wxYES_NO | wxICON_QUESTION, &dialog) != wxYES) return;

        const auto current_actor = controller.documents().actor(document);
        const auto current = controller.documents().project(document);
        if (controller.documents().active_document() != std::optional{document} || current_actor != actor ||
            !current || current != project || actor->view().session != *session || actor->view().snapshot != project) {
            preview->ChangeValue("Project or document changed. Close this review and reopen it before applying changes.");
            return;
        }
        auto submitted = actor->execute_batch_at_revision(std::move(commands), expected_edit, source_key.value(), project);
        if (!submitted) { controller.documents().report_error(document, submitted.error()); return; }
        auto watched = controller.documents().watch(document, std::move(submitted.value()));
        if (!watched) { controller.documents().report_error(document, watched.error()); return; }
        dialog.EndModal(wxID_OK);
    };
    replace->Bind(wxEVT_BUTTON, [&](wxCommandEvent&) { replace_selected_text(false); });
    replace_names->Bind(wxEVT_BUTTON, [&](wxCommandEvent&) { replace_selected_text(true); });
    assign_type->Bind(wxEVT_BUTTON, [&](wxCommandEvent&) {
        if (!writable || !session || project->state->user->types.empty()) return;
        wxArrayString choices;
        for (const auto& definition : project->state->user->types)
            choices.Add(wxString::FromUTF8(definition.name));
        wxSingleChoiceDialog type_choice(&dialog, "Choose the type to assign to every selected address",
                                         "Assign type to selected addresses", choices);
        if (type_choice.ShowModal() != wxID_OK) return;
        const auto type_index = static_cast<std::size_t>(type_choice.GetSelection());
        if (type_index >= project->state->user->types.size()) return;
        const auto& chosen_type = project->state->user->types[type_index];
        std::vector<ProjectCommand> commands;
        wxString samples;
        std::size_t assigned = 0, replaced_count = 0, unchanged = 0;
        for (long selected = list->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED); selected >= 0;
             selected = list->GetNextItem(selected, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED)) {
            if (static_cast<std::size_t>(selected) >= visible_rows.size()) continue;
            const auto& row = annotations[visible_rows[static_cast<std::size_t>(selected)]];
            const auto* address = std::get_if<Address>(&row.location);
            if (!address) {
                preview->ChangeValue("Type assignments require virtual addresses. Clear the selection and choose only address rows.");
                return;
            }
            const auto current = std::find_if(project->state->user->type_assignments.begin(),
                project->state->user->type_assignments.end(), [&](const auto& item) {
                    return item.location == Location{*address};
                });
            if (current != project->state->user->type_assignments.end() && current->type_id == chosen_type.id) {
                ++unchanged;
                continue;
            }
            if (current != project->state->user->type_assignments.end()) ++replaced_count;
            if (commands.size() < 3) {
                wxString before = "unassigned";
                if (current != project->state->user->type_assignments.end()) {
                    const auto old_type = std::find_if(project->state->user->types.begin(), project->state->user->types.end(),
                        [&](const auto& definition) { return definition.id == current->type_id; });
                    before = old_type == project->state->user->types.end()
                        ? wxString::Format("<missing type %llu>", static_cast<unsigned long long>(current->type_id))
                        : wxString::FromUTF8(old_type->name);
                }
                samples += wxString::Format("At %s\nBefore: %s\nAfter:  %s\n\n",
                    location_text(row.location, project->loaded ? project->loaded->image.get() : nullptr),
                    before, wxString::FromUTF8(chosen_type.name));
            }
            commands.emplace_back(AssignType{*address, chosen_type.id, false});
            ++assigned;
        }
        if (commands.empty()) {
            preview->ChangeValue(wxString::Format("No assignments needed. %zu selected address(es) already use %s.",
                unchanged, wxString::FromUTF8(chosen_type.name)));
            return;
        }
        wxString confirmation = wxString::Format(
            "Assign %s to %zu selected address(es)?\nExisting assignments replaced: %zu. Unchanged: %zu.\n\n",
            wxString::FromUTF8(chosen_type.name), assigned, replaced_count, unchanged);
        confirmation += samples;
        if (assigned > 3) confirmation += wxString::Format("... and %zu more address(es).\n\n", assigned - 3);
        confirmation += "The assignments will be one undoable project change.";
        if (wxMessageBox(confirmation, "Review type assignments", wxYES_NO | wxICON_QUESTION, &dialog) != wxYES) return;
        const auto current_actor = controller.documents().actor(document);
        const auto current = controller.documents().project(document);
        if (controller.documents().active_document() != std::optional{document} || current_actor != actor ||
            !current || current != project || actor->view().session != *session || actor->view().snapshot != project) {
            preview->ChangeValue("Project or document changed. Close this review and reopen it before applying changes.");
            return;
        }
        auto submitted = actor->execute_batch_at_revision(std::move(commands), expected_edit, source_key.value(), project);
        if (!submitted) { controller.documents().report_error(document, submitted.error()); return; }
        auto watched = controller.documents().watch(document, std::move(submitted.value()));
        if (!watched) { controller.documents().report_error(document, watched.error()); return; }
        dialog.EndModal(wxID_OK);
    });
    clear->Bind(wxEVT_BUTTON, [&](wxCommandEvent&) {
        if (!writable || !session) return;
        std::vector<ProjectCommand> commands;
        std::size_t name_count = 0, comment_count = 0;
        for (long selected = list->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED); selected >= 0;
             selected = list->GetNextItem(selected, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED)) {
            if (static_cast<std::size_t>(selected) >= visible_rows.size()) continue;
            const auto& row = annotations[visible_rows[static_cast<std::size_t>(selected)]];
            if (names->IsChecked() && !row.name.empty()) { commands.emplace_back(Rename{row.location, {}}); ++name_count; }
            if (comments->IsChecked() && !row.comment.empty()) { commands.emplace_back(Comment{row.location, {}}); ++comment_count; }
        }
        if (commands.empty()) { preview->ChangeValue("No selected saved fields need clearing."); return; }
        const auto question = wxString::Format("Clear %zu saved names and %zu comments as one undoable project change?", name_count, comment_count);
        if (wxMessageBox(question, "Review annotation changes", wxYES_NO | wxICON_QUESTION, &dialog) != wxYES) return;
        const auto current_actor = controller.documents().actor(document);
        const auto current = controller.documents().project(document);
        if (controller.documents().active_document() != std::optional{document} || current_actor != actor ||
            !current || current != project || actor->view().session != *session || actor->view().snapshot != project) {
            preview->ChangeValue("Project or document changed. Close this review and reopen it before applying changes."); return;
        }
        auto submitted = actor->execute_batch_at_revision(std::move(commands), expected_edit, source_key.value(), project);
        if (!submitted) { controller.documents().report_error(document, submitted.error()); return; }
        auto watched = controller.documents().watch(document, std::move(submitted.value()));
        if (!watched) { controller.documents().report_error(document, watched.error()); return; }
        dialog.EndModal(wxID_OK);
    });
    populate(); dialog.ShowModal();
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
    file.Insert(position++, rotate_backups_id, "Create &Rotated Backup...");
    file.Insert(position++, list_backups_id, "List Rotated Backups");
    file.Insert(position++, prune_backups_id, "Prune Rotated Backups...");
    file.Insert(position++, automatic_backups_id, "Automatic Project Backups...");
    file.Insert(position++, restore_backup_id, "Restore Backup as New Project...");
    file.Insert(position++, restore_recovery_id, "Restore Recovery Artifact as New Project...");
    file.Insert(position++, restore_backup_in_place_id, "Restore Backup In Place...");
    file.Insert(position++, restore_recovery_in_place_id, "Restore Previous Version In Place...");
    file.Insert(position++, archive_source_id, "Archive External Source...");
    file.Insert(position++, rotate_source_archives_id, "Create Rotated Source Archive...");
    file.Insert(position++, list_source_archives_id, "List Rotated Source Archives");
    file.Insert(position++, prune_source_archives_id, "Prune Rotated Source Archives...");
    file.Insert(position++, verify_source_archive_id, "Verify Source Archive...");
    file.Insert(position++, restore_source_archive_id, "Restore Source Archive...");
    file.Insert(position++, cancel_source_archive_id, "Cancel Source Archive Work");
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
    edit.Append(annotation_review_id, "Review Names and Comments...");
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
    if (event.GetId() == automatic_backups_id) {
        event.Enable(true);
        return;
    }
    if (event.GetId() == cancel_source_archive_id) {
        event.Enable(controller_.source_archive_pending());
        return;
    }
    auto id = controller_.documents().active_document();
    auto project = id ? controller_.documents().project(*id) : nullptr;
    if (event.GetId() == annotation_review_id) {
        event.Enable(project && project->state && project->state->user);
        return;
    }
    if (event.GetId() == restore_backup_id || event.GetId() == restore_backup_in_place_id ||
        event.GetId() == restore_recovery_in_place_id || event.GetId() == restore_recovery_id) {
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
    if (event.GetId() == rotate_backups_id || event.GetId() == list_backups_id ||
        event.GetId() == prune_backups_id) {
        bool saved = false;
        if (id)
            for (const auto &document : controller_.documents().documents())
                if (document.id == *id)
                    saved = document.path.has_value();
        event.Enable(id && saved && project && bool(controller_.documents().actor(*id)));
        return;
    }
    if (event.GetId() == archive_source_id || event.GetId() == rotate_source_archives_id ||
        event.GetId() == list_source_archives_id || event.GetId() == prune_source_archives_id ||
        event.GetId() == verify_source_archive_id || event.GetId() == restore_source_archive_id) {
        bool saved = false;
        if (id)
            for (const auto &document : controller_.documents().documents())
                if (document.id == *id) saved = document.path.has_value();
        event.Enable(id && saved && project && project->state && !controller_.source_archive_pending());
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
    if (event.GetId() == cancel_source_archive_id) {
        controller_.cancel_source_archive();
        return;
    }
    if (event.GetId() == automatic_backups_id) {
        wxDialog dialog(&frame_, wxID_ANY, "Automatic Project Backups", wxDefaultPosition, wxDefaultSize,
                        wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);
        const auto options = controller_.automatic_backup_options();
        auto *layout = new wxBoxSizer(wxVERTICAL);
        auto *enabled = new wxCheckBox(&dialog, wxID_ANY, "Back up every saved writable project automatically");
        enabled->SetValue(options.enabled);
        layout->Add(enabled, 0, wxALL, dialog.FromDIP(10));
        auto *fields = new wxFlexGridSizer(2, dialog.FromDIP(8), dialog.FromDIP(10));
        fields->Add(new wxStaticText(&dialog, wxID_ANY, "Interval (minutes, 5-1440):"), 0, wxALIGN_CENTER_VERTICAL);
        auto *interval = new wxSpinCtrl(&dialog, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize,
                                        wxSP_ARROW_KEYS, 5, 1440, options.interval_minutes);
        fields->Add(interval);
        fields->Add(new wxStaticText(&dialog, wxID_ANY, "Generations to retain (1-32):"), 0, wxALIGN_CENTER_VERTICAL);
        auto *retain = new wxSpinCtrl(&dialog, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize,
                                      wxSP_ARROW_KEYS, 1, 32, static_cast<int>(options.retain));
        fields->Add(retain);
        layout->Add(fields, 0, wxLEFT | wxRIGHT | wxBOTTOM, dialog.FromDIP(10));
        auto *help = new wxStaticText(&dialog, wxID_ANY,
            "Backups use the project's sibling -backups base, shared with manual rotated backups. "
            "Older validated generations may be deleted to meet retention. Incomplete retention preserves files "
            "and pauses that project's schedule for review. Settings apply to all open projects and future sessions. "
            "The first attempt follows a full interval; HexLab must remain running. External source files are not copied.");
        help->Wrap(dialog.FromDIP(620));
        layout->Add(help, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, dialog.FromDIP(10));
        auto *status = new wxTextCtrl(&dialog, wxID_ANY, controller_.automatic_backup_status(),
            wxDefaultPosition, dialog.FromDIP(wxSize(620, 230)), wxTE_MULTILINE | wxTE_READONLY);
        status->SetName("Automatic project backup status");
        layout->Add(status, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, dialog.FromDIP(10));
        auto *work_buttons = new wxBoxSizer(wxHORIZONTAL);
        auto *cancel_work = new wxButton(&dialog, wxID_ANY, "Cancel Running Automatic Backups");
        work_buttons->Add(cancel_work, 0, wxRIGHT, dialog.FromDIP(8));
        auto *restart = new wxButton(&dialog, wxID_ANY, "Restart Schedule");
        restart->Enable(options.enabled);
        restart->SetToolTip("After reviewing a retention warning, restart all project countdowns with the current saved settings.");
        work_buttons->Add(restart);
        layout->Add(work_buttons, 0, wxLEFT | wxRIGHT | wxBOTTOM, dialog.FromDIP(10));
        cancel_work->Bind(wxEVT_BUTTON, [&](wxCommandEvent &) {
            controller_.cancel_automatic_backups();
            status->ChangeValue(controller_.automatic_backup_status());
        });
        restart->Bind(wxEVT_BUTTON, [&](wxCommandEvent &) {
            controller_.restart_automatic_backup_schedule();
            status->ChangeValue(controller_.automatic_backup_status());
        });
        layout->Add(dialog.CreateStdDialogButtonSizer(wxOK | wxCANCEL), 0, wxEXPAND | wxALL, dialog.FromDIP(10));
        dialog.SetSizerAndFit(layout);
        dialog.SetMinSize(dialog.GetSize());
        dialog.CentreOnParent();
        wxTimer refresh(&dialog);
        dialog.Bind(wxEVT_TIMER, [&](wxTimerEvent &) {
            status->ChangeValue(controller_.automatic_backup_status());
        }, refresh.GetId());
        refresh.Start(1000);
        const auto answer = dialog.ShowModal();
        refresh.Stop();
        if (answer == wxID_OK) {
            auto saved = controller_.configure_automatic_backups({enabled->GetValue(), interval->GetValue(),
                                                                  static_cast<std::size_t>(retain->GetValue())});
            if (!saved)
                controller_.documents().report_error(saved.error());
        }
        return;
    }
    if (event.GetId() == restore_backup_in_place_id) {
        wxFileDialog source_dialog(&frame_, "Choose project backup", {}, {},
                                   "HexLab project backups (*.hxproj)|*.hxproj|All files (*.*)|*.*",
                                   wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (source_dialog.ShowModal() != wxID_OK)
            return;
        wxFileDialog target_dialog(&frame_, "Choose the existing project to replace", {}, {},
                                   "HexLab projects (*.hxproj)|*.hxproj|All files (*.*)|*.*",
                                   wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (target_dialog.ShowModal() != wxID_OK)
            return;
        const auto source = std::filesystem::path(source_dialog.GetPath().ToStdWstring());
        const auto target = std::filesystem::path(target_dialog.GetPath().ToStdWstring());
        if (wxMessageBox("This replaces the selected project with the backup. The backup and target must belong to the same project. Close all open views of both files first. The current target will be retained as a recovery artifact.",
                         "Confirm In-Place Project Restore", wxYES_NO | wxNO_DEFAULT | wxICON_WARNING,
                         &frame_) != wxYES)
            return;
        auto active = controller_.documents().active_document();
        auto active_project = active ? controller_.documents().project(*active) : nullptr;
        const auto options = active_project ? active_project->analysis_options : AnalysisOptions{};
        auto started = controller_.restore_backup_in_place(source, target, options);
        if (!started) {
            if (active)
                controller_.documents().report_error(*active, started.error());
            else
                controller_.documents().report_error(started.error());
            return;
        }
        if (active && controller_.message)
            controller_.message(*active, "Restoring backup in place...");
        return;
    }
    if (event.GetId() == restore_recovery_in_place_id) {
        wxFileDialog source_dialog(&frame_, "Choose retained previous-version recovery artifact", {}, {},
                                   "HexLab previous-version artifacts (.hexlab-previous-*.tmp)|.hexlab-previous-*.tmp|All files (*.*)|*.*",
                                   wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (source_dialog.ShowModal() != wxID_OK)
            return;
        wxFileDialog target_dialog(&frame_, "Choose the existing project to roll back", {}, {},
                                   "HexLab projects (*.hxproj)|*.hxproj|All files (*.*)|*.*",
                                   wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (target_dialog.ShowModal() != wxID_OK)
            return;
        const auto source = std::filesystem::path(source_dialog.GetPath().ToStdWstring());
        const auto target = std::filesystem::path(target_dialog.GetPath().ToStdWstring());
        if (wxMessageBox("This restores a fully validated retained previous-version artifact over the same project's existing file. Close all open views of the target first. The recovery artifact is retained, and the target must be reopened after restore.",
                         "Confirm Recovery Restore In Place", wxYES_NO | wxNO_DEFAULT | wxICON_WARNING,
                         &frame_) != wxYES)
            return;
        auto active = controller_.documents().active_document();
        auto active_project = active ? controller_.documents().project(*active) : nullptr;
        const auto options = active_project ? active_project->analysis_options : AnalysisOptions{};
        auto started = controller_.restore_recovery_in_place(source, target, options);
        if (!started) {
            if (active)
                controller_.documents().report_error(*active, started.error());
            else
                controller_.documents().report_error(started.error());
            return;
        }
        if (active && controller_.message)
            controller_.message(*active, "Validating retained recovery artifact and restoring project in place...");
        return;
    }
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
    if (event.GetId() == restore_recovery_id) {
        wxFileDialog source_dialog(&frame_, "Choose a recovery artifact", {}, {},
                                   "HexLab recovery artifacts (*.tmp)|*.tmp|All files (*.*)|*.*",
                                   wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (source_dialog.ShowModal() != wxID_OK) return;
        wxFileName source_name(source_dialog.GetPath());
        wxFileDialog destination_dialog(&frame_, "Restore recovery artifact as a new project", source_dialog.GetDirectory(),
                                        source_name.GetName() + "-recovered.hxproj",
                                        "HexLab projects (*.hxproj)|*.hxproj|All files (*.*)|*.*",
                                        wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
        if (destination_dialog.ShowModal() != wxID_OK) return;
        auto active = controller_.documents().active_document();
        auto active_project = active ? controller_.documents().project(*active) : nullptr;
        const auto options = active_project ? active_project->analysis_options : AnalysisOptions{};
        auto destination = std::filesystem::path(destination_dialog.GetPath().ToStdWstring());
        std::error_code error;
        const bool replace = std::filesystem::exists(destination, error);
        if (error) {
            if (active) controller_.documents().report_error(*active, {ErrorCode::io, error.message()});
            else controller_.documents().report_error({ErrorCode::io, error.message()});
            return;
        }
        auto started = controller_.restore_recovery(
            std::filesystem::path(source_dialog.GetPath().ToStdWstring()), std::move(destination), replace, options);
        if (!started) {
            if (active) controller_.documents().report_error(*active, started.error());
            else controller_.documents().report_error(started.error());
            return;
        }
        if (active && controller_.message) controller_.message(*active, "Validating and restoring recovery artifact...");
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
    if (event.GetId() == rotate_backups_id) {
        wxNumberEntryDialog dialog(&frame_, "Create a timestamped backup and keep this many generations.",
                                  "Generations to retain:", "Create Rotated Project Backup", 5, 1, 32);
        if (dialog.ShowModal() != wxID_OK)
            return;
        auto started = controller_.rotate_backups(*id, static_cast<std::size_t>(dialog.GetValue()));
        if (!started)
            controller_.documents().report_error(*id, started.error());
        else if (controller_.message)
            controller_.message(*id, "Creating and rotating project backups...");
        return;
    }
    if (event.GetId() == list_backups_id) {
        auto started = controller_.list_backups(*id);
        if (!started)
            controller_.documents().report_error(*id, started.error());
        else if (controller_.message)
            controller_.message(*id, "Listing rotated project backups...");
        return;
    }
    if (event.GetId() == prune_backups_id) {
        wxNumberEntryDialog dialog(&frame_, "Keep this many newest validated generations.",
                                  "Generations to retain:", "Prune Rotated Project Backups", 5, 1, 32);
        if (dialog.ShowModal() != wxID_OK)
            return;
        const auto retain = static_cast<std::size_t>(dialog.GetValue());
        if (wxMessageBox(wxString::Format("Delete older validated backups and keep at most %zu generations?",
                                          retain),
                         "Confirm Backup Pruning", wxYES_NO | wxICON_WARNING, &frame_) != wxYES)
            return;
        auto started = controller_.prune_backups(*id, retain);
        if (!started)
            controller_.documents().report_error(*id, started.error());
        else if (controller_.message)
            controller_.message(*id, "Pruning rotated project backups...");
        return;
    }
    if (event.GetId() == archive_source_id || event.GetId() == rotate_source_archives_id ||
        event.GetId() == list_source_archives_id || event.GetId() == prune_source_archives_id ||
        event.GetId() == verify_source_archive_id || event.GetId() == restore_source_archive_id) {
        std::optional<std::filesystem::path> project_path;
        for (const auto &document : controller_.documents().documents())
            if (document.id == *id) project_path = document.path;
        if (!project_path) return;
        auto action = event.GetId() == archive_source_id ? SourceArchiveAction::create :
            event.GetId() == rotate_source_archives_id ? SourceArchiveAction::rotate :
            event.GetId() == list_source_archives_id ? SourceArchiveAction::list :
            event.GetId() == prune_source_archives_id ? SourceArchiveAction::prune :
            event.GetId() == verify_source_archive_id ? SourceArchiveAction::verify : SourceArchiveAction::restore;
        std::filesystem::path selected;
        std::filesystem::path output;
        std::size_t retain = 5;
        if (action == SourceArchiveAction::create) {
            const auto filename = project_path->stem().wstring() + L"-source.bin";
            wxFileDialog dialog(&frame_, "Archive matching external source", wxString(project_path->parent_path().wstring()),
                wxString(filename), "All files (*.*)|*.*", wxFD_SAVE);
            if (dialog.ShowModal() != wxID_OK) return;
            selected = std::filesystem::path(dialog.GetPath().ToStdWstring());
            std::error_code error;
            if (std::filesystem::exists(selected, error) || error) {
                controller_.documents().report_error(*id, {ErrorCode::conflict,
                    error ? "Cannot inspect the selected destination" : "Source archives never replace existing files"});
                return;
            }
        } else if (action == SourceArchiveAction::verify) {
            wxFileDialog dialog(&frame_, "Verify external source archive", {}, {}, "All files (*.*)|*.*",
                                wxFD_OPEN | wxFD_FILE_MUST_EXIST);
            if (dialog.ShowModal() != wxID_OK) return;
            selected = std::filesystem::path(dialog.GetPath().ToStdWstring());
        } else if (action == SourceArchiveAction::restore) {
            wxFileDialog archive_dialog(&frame_, "Choose source archive to restore", {}, {},
                                        "All files (*.*)|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
            if (archive_dialog.ShowModal() != wxID_OK) return;
            selected = std::filesystem::path(archive_dialog.GetPath().ToStdWstring());
            const auto filename = project_path->stem().wstring() + L"-source-restored.bin";
            wxFileDialog output_dialog(&frame_, "Restore matching source bytes", {}, wxString(filename),
                                       "All files (*.*)|*.*", wxFD_SAVE);
            if (output_dialog.ShowModal() != wxID_OK) return;
            output = std::filesystem::path(output_dialog.GetPath().ToStdWstring());
            std::error_code error;
            if (std::filesystem::exists(output, error) || error) {
                controller_.documents().report_error(*id, {ErrorCode::conflict,
                    error ? "Cannot inspect the selected destination" : "Source restore never replaces existing files"});
                return;
            }
        } else if (action == SourceArchiveAction::rotate || action == SourceArchiveAction::prune) {
            wxNumberEntryDialog dialog(&frame_, "Source archive generations are validated against the embedded input.",
                "Generations to retain:", action == SourceArchiveAction::rotate ? "Rotate Source Archives" : "Prune Source Archives", 5, 1, 32);
            if (dialog.ShowModal() != wxID_OK) return;
            retain = static_cast<std::size_t>(dialog.GetValue());
            if (action == SourceArchiveAction::prune && wxMessageBox(
                    wxString::Format("Delete older validated source archives and keep at most %zu generations?", retain),
                    "Confirm Source Archive Pruning", wxYES_NO | wxICON_WARNING, &frame_) != wxYES)
                return;
        }
        auto started = controller_.manage_source_archive(*id, action, std::move(selected), retain, std::move(output));
        if (!started) controller_.documents().report_error(*id, started.error());
        else if (controller_.message) {
            const wxString label = action == SourceArchiveAction::create ? "Archiving the matching external source..." :
                action == SourceArchiveAction::rotate ? "Creating and rotating source archives..." :
                action == SourceArchiveAction::list ? "Validating rotated source archives..." :
                action == SourceArchiveAction::prune ? "Pruning validated source archives..." :
                action == SourceArchiveAction::verify ? "Verifying source archive..." : "Restoring source archive...";
            controller_.message(*id, label + " This runs in the background; use File > Cancel Source Archive Work to request cancellation.");
        }
        return;
    }
    if (event.GetId() == patch_manager_id) {
        show_patch_manager(frame_, controller_, *id, std::move(project));
        return;
    }
    if (event.GetId() == annotation_review_id) {
        show_annotation_review(frame_, controller_, *id, std::move(project));
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
        accepted(controller_.all_search_scope() ? controller_.find_next_all(*id) : controller_.find_next(*id));
        return;
    }
    if (event.GetId() == find_previous_id) {
        accepted(controller_.all_search_scope() ? controller_.find_previous_all(*id) : controller_.find_previous(*id));
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
