#include "main_frame.hpp"
#include "support/desktop_test_window.hpp"
#include "project_actions.hpp"
#include "edit_dialogs.hpp"
#include "support/fixture_files.hpp"
#include "hexlab/types/types.hpp"
#include "hexlab/core/sha256.hpp"
#include "hexlab/image/image.hpp"
#include <wx/app.h>
#include <wx/dialog.h>
#include <wx/choicdlg.h>
#include <wx/button.h>
#include <wx/textctrl.h>
#include <wx/stattext.h>
#include <wx/listctrl.h>
#include <wx/menu.h>
#include <wx/choice.h>
#include <wx/checkbox.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/log.h>
#include <wx/dcclient.h>
#include <wx/dcmemory.h>
#include <wx/image.h>
#include <wx/timer.h>
#include <chrono>
#include <cstdio>
using namespace hexlab;
using namespace hexlab::desktop;
using namespace hexlab_test;
namespace {
class EditApp final : public wxApp {
    wxTimer timer_{this};
    MainFrame *frame = nullptr;
    std::unique_ptr<FixtureFile> input;
    std::filesystem::path project, exported;
    int phase = 0, ticks = 0, result = 1;
    std::uint64_t edited_aggregate_id = 0;
    std::shared_future<Result<ProjectReply>> pending_save;
  public:
    bool OnInit() override {
        auto patch_width = parse_patch_text("100");
        if (patch_width) {
            std::fprintf(stderr, "Patch parser accepted an out-of-range hexadecimal octet\n");
            return false;
        }
        auto legal_patch = parse_patch_text("FF 00");
        if (!legal_patch || legal_patch.value() != bytes({0xff, 0x00})) {
            std::fprintf(stderr, "Patch parser rejected valid hexadecimal octets\n");
            return false;
        }
        wxSetAssertHandler([](const wxString &, int, const wxString &, const wxString &, const wxString &message) {
            std::fprintf(stderr, "wx assertion: %s\n", message.utf8_str().data());
            std::_Exit(4);
        });
        wxInitAllImageHandlers();
        input = std::make_unique<FixtureFile>(bytes({0x90, 0xc3, 'H', 'E', 'L', 'L', 'O', 0}));
        project = input->path.wstring() + L".edit.hxproj";
        exported = input->path.wstring() + L".patched.bin";
        frame = new MainFrame;
        show_test_window(frame);
        frame->UpdateWindowUI(wxUPDATE_UI_RECURSE);
        if (frame->GetMenuBar()->FindItem(rename_id)->IsEnabled() ||
            frame->GetMenuBar()->FindItem(wxID_SAVE)->IsEnabled()) {
            fail("Document actions enabled without a project");
            return true;
        }
        OpenRequest request;
        request.path = input->path;
        request.format = Format::raw;
        request.raw = RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x1000}, true, false, true, {}};
        frame->OpenDocument(request);
        Bind(wxEVT_TIMER, [this](wxTimerEvent &) { tick(); });
        timer_.Start(20);
        return true;
    }
    void fail(const char *message) {
        std::fprintf(stderr, "%s (phase %d)\n", message, phase);
        timer_.Stop();
        frame->CloseAllDocuments();
        frame->Close();
    }
    void send(int id) {
        wxCommandEvent event(wxEVT_MENU, id);
        frame->GetEventHandler()->ProcessEvent(event);
    }
    void dialog(int id, const wxString &value) {
        timer_.Stop();
        CallAfter([this, id, value, request_phase = phase] {
            auto *field = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("edit-value"));
            auto *dialog = field ? dynamic_cast<wxDialog *>(field->GetParent()) : nullptr;
            if (!field || !dialog) {
                auto active = frame->projects().active_document();
                auto snapshot = active ? frame->projects().project(*active) : nullptr;
                auto error = frame->documents().last_error();
                std::fprintf(stderr,
                             "Expected edit dialog missing (request phase %d; action %d; derived %d; error %s)\n",
                             request_phase, id, snapshot ? static_cast<int>(snapshot->status) : -1,
                             error ? error->message.c_str() : "none");
                std::_Exit(3);
            }
            field->SetValue(value);
            wxCommandEvent okay(wxEVT_BUTTON, wxID_OK);
            dialog->GetEventHandler()->ProcessEvent(okay);
        });
        send(id);
        timer_.Start(20);
    }
    void aggregate_editor(const wxString &name, const wxString &members, const char *action_name,
                          bool verify_invalid_rejected = false) {
        timer_.Stop();
        CallAfter([this, name, members, verify_invalid_rejected] {
            auto *dialog = dynamic_cast<wxDialog *>(wxWindow::FindWindowByName("type-aggregate-editor", frame));
            auto *name_field = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("type-author-name", dialog));
            auto *members_field = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("type-author-members", dialog));
            auto *error = dynamic_cast<wxStaticText *>(wxWindow::FindWindowByName("type-author-error", dialog));
            if (!dialog || !name_field || !members_field || !error) {
                fail("Aggregate authoring dialog is missing its named fields");
                if (auto *active = dynamic_cast<wxDialog *>(wxGetActiveWindow())) active->EndModal(wxID_CANCEL);
                return;
            }
            name_field->SetValue(name);
            if (verify_invalid_rejected) {
                members_field->SetValue("broken missing_type 0");
                wxCommandEvent invalid(wxEVT_BUTTON, wxID_OK);
                dialog->GetEventHandler()->ProcessEvent(invalid);
                if (error->GetLabel().IsEmpty()) {
                    fail("Invalid aggregate member was not rejected in the editor");
                    wxCommandEvent cancel(wxEVT_BUTTON, wxID_CANCEL);
                    dialog->GetEventHandler()->ProcessEvent(cancel);
                    return;
                }
            }
            members_field->SetValue(members);
            wxCommandEvent okay(wxEVT_BUTTON, wxID_OK);
            dialog->GetEventHandler()->ProcessEvent(okay);
        });
        auto *action = wxWindow::FindWindowByName(action_name, frame);
        if (!action) { fail("Aggregate authoring action is missing"); return; }
        wxCommandEvent click(wxEVT_BUTTON, action->GetId());
        action->GetEventHandler()->ProcessEvent(click);
        timer_.Start(20);
    }
    void assign_selected_type(std::size_t index) {
        timer_.Stop();
        CallAfter([this, index] {
            auto *choice = dynamic_cast<wxSingleChoiceDialog *>(wxGetActiveWindow());
            if (!choice) {
                fail("Type assignment did not open its type chooser");
                if (auto *active = dynamic_cast<wxDialog *>(wxGetActiveWindow())) active->EndModal(wxID_CANCEL);
                return;
            }
            choice->SetSelection(static_cast<int>(index));
            wxCommandEvent okay(wxEVT_BUTTON, wxID_OK);
            choice->GetEventHandler()->ProcessEvent(okay);
        });
        auto *action = wxWindow::FindWindowByName("type-assign", frame);
        if (!action) { fail("Type assignment action is missing"); return; }
        wxCommandEvent click(wxEVT_BUTTON, action->GetId());
        action->GetEventHandler()->ProcessEvent(click);
        timer_.Start(20);
    }
    bool clipboard(const wxString &expected) {
        wxLogNull quiet;
        wxTextDataObject value;
        for (int attempt = 0; attempt < 20; ++attempt) {
            if (wxTheClipboard->Open()) {
                bool readable = wxTheClipboard->GetData(value);
                wxTheClipboard->Close();
                if (readable)
                    return value.GetText() == expected;
            }
            wxMilliSleep(10);
        }
        return false;
    }
    bool capture(const char *name) {
        auto path = std::filesystem::current_path() / "artifacts" / name;
        std::error_code error;
        std::filesystem::create_directories(path.parent_path(), error);
        if (error)
            return false;
        auto size = frame->GetClientSize();
        wxBitmap bitmap(size.x, size.y);
        wxMemoryDC target(bitmap);
        wxClientDC source(frame);
        bool copied = target.Blit(0, 0, size.x, size.y, &source, 0, 0);
        target.SelectObject(wxNullBitmap);
        return copied && bitmap.SaveFile(wxString(path.wstring()), wxBITMAP_TYPE_PNG);
    }
    void tick() {
        if (++ticks > 1000) {
            fail("Edit workflow timed out");
            return;
        }
        if (frame->documents().opening())
            return;
        auto id = frame->projects().active_document();
        if (!id)
            return;
        auto state = frame->projects().project(*id);
        if (!state)
            return;
        auto revision = state->state->revisions.edit;
        // A committed edit can arrive before its replacement instruction facts.
        // Match the real menu contract before requesting another boundary edit.
        const bool boundary_action = (phase >= 10 && phase <= 15) || phase == 18;
        if (boundary_action && state->status != DerivedStatus::fresh && state->status != DerivedStatus::incomplete) {
            frame->UpdateWindowUI(wxUPDATE_UI_RECURSE);
            if (frame->GetMenuBar()->FindItem(code_id)->IsEnabled())
                fail("Code action enabled before current instruction boundaries");
            return;
        }
        if (phase == 0) {
            frame->UpdateWindowUI(wxUPDATE_UI_RECURSE);
            if (frame->GetMenuBar()->FindItem(wxID_UNDO)->IsEnabled() ||
                !frame->GetMenuBar()->FindItem(rename_id)->IsEnabled()) {
                fail("Initial action availability mismatch");
                return;
            }
            auto saved = frame->SaveProjectAs(project);
            if (!saved) {
                fail("Cannot enqueue first save");
                return;
            }
            phase = 1;
        } else if (phase == 1) {
            auto infos = frame->projects().documents();
            if (!infos[0].path)
                return;
            dialog(rename_id, "renamed_entry");
            phase = 2;
        } else if (phase == 2) {
            if (revision != 1)
                return;
            auto *functions = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("functions", frame));
            if (!functions || functions->GetItemText(0, 1) != "renamed_entry") {
                fail("Committed rename did not reach real function view");
                return;
            }
            auto *listing = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("disassembly", frame));
            if (!listing || !listing->GetItemText(0, 2).Contains("renamed_entry")) {
                fail("Committed rename did not reach listing presentation");
                return;
            }
            dialog(comment_id, "first line\nsecond line");
            phase = 3;
        } else if (phase == 3) {
            if (revision != 2)
                return;
            auto *listing = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("disassembly", frame));
            auto *annotations = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("annotations", frame));
            if (!listing || !listing->GetItemText(0, 2).Contains("first line\\nsecond line") || !annotations ||
                annotations->GetItemCount() != 1) {
                fail("Committed comment not displayed in native panes");
                return;
            }
            send(copy_text_id);
            if (!clipboard("renamed_entry: nop ; first line\nsecond line")) {
                fail("Annotated listing clipboard mismatch");
                return;
            }
            dialog(bookmark_id, "entry_mark");
            phase = 4;
        } else if (phase == 4) {
            if (revision != 3)
                return;
            auto *bookmarks = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("bookmarks", frame));
            if (!bookmarks || bookmarks->GetItemCount() != 1 || bookmarks->GetItemText(0, 1) != "entry_mark") {
                fail("Bookmark table mismatch");
                return;
            }
            dialog(patch_id, "CC");
            phase = 5;
        } else if (phase == 5) {
            if (revision != 4)
                return;
            auto *listing = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("disassembly", frame));
            if (!listing || listing->GetItemText(0, 1) != "CC") {
                fail("Committed patch did not reach real listing bytes");
                return;
            }
            auto *bytes = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("bytes", frame));
            if (!listing->GetItemText(0, 3).Contains("patched") || !bytes ||
                !bytes->GetItemText(0, 3).Contains("patched")) {
                fail("Patch state missing in listing or bytes");
                return;
            }
            auto saved = frame->ExportBinary(exported);
            if (!saved) {
                fail("Cannot enqueue binary export");
                return;
            }
            send(wxID_UNDO);
            phase = 6;
        } else if (phase == 6) {
            if (revision != 5 || !std::filesystem::exists(exported))
                return;
            auto output = FileStorage::open(exported);
            if (!output) {
                fail("Export output could not be reopened");
                return;
            }
            const auto expected_export = bytes({0xcc, 0xc3, 'H', 'E', 'L', 'L', 'O', 0});
            auto output_bytes = output.value()->read_at({0}, expected_export.size());
            if (!output_bytes || !std::equal(output_bytes.value().bytes.begin(), output_bytes.value().bytes.end(),
                                             expected_export.begin(), expected_export.end()) ||
                output.value()->size() != expected_export.size()) {
                fail("Export did not preserve the exact committed overlay across the whole fixture");
                return;
            }
            auto *output_log = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("output", frame));
            const auto expected_digest = digest_hex(hash_source(*output.value(), {}).value());
            if (!output_log || !output_log->GetValue().Contains(wxString("SHA256=") + wxString::FromUTF8(expected_digest))) {
                fail("Desktop export did not report its verifiable SHA-256 digest");
                return;
            }
            frame->UpdateWindowUI(wxUPDATE_UI_RECURSE);
            if (!frame->GetMenuBar()->FindItem(wxID_REDO)->IsEnabled()) {
                fail("Redo unavailable after undo");
                return;
            }
            send(wxID_REDO);
            phase = 7;
        } else if (phase == 7) {
            if (revision != 6)
                return;
            dialog(rename_id, wxString::FromUTF8(std::string(513, 'x')));
            phase = 8;
        } else if (phase == 8) {
            if (!frame->documents().last_error())
                return;
            if (revision != 6 || state->state->user->annotations[0].name != "renamed_entry") {
                fail("Failed edit changed committed presentation");
                return;
            }
            frame->CloseAllDocuments();
            frame->OpenProject(project, database::ProjectMode::read_only);
            phase = 9;
        } else if (phase == 9) {
            frame->UpdateWindowUI(wxUPDATE_UI_RECURSE);
            if (state->mode != database::ProjectMode::read_only ||
                frame->GetMenuBar()->FindItem(rename_id)->IsEnabled() ||
                !frame->GetMenuBar()->FindItem(export_id)->IsEnabled() || state->state->revisions.edit != 6 ||
                state->state->user->bookmarks.size() != 1 || state->state->user->patches.size() != 1 ||
                state->effective->read_at({0}, 1).value().bytes[0] != std::byte{0xcc}) {
                fail("Reopened readonly project or menu availability mismatch");
                return;
            }
            frame->CloseAllDocuments();
            frame->OpenProject(project);
            phase = 10;
        } else if (phase == 10) {
            dialog(data_id, "1");
            phase = 11;
        } else if (phase == 11) {
            if (revision != 7)
                return;
            if (state->state->user->decisions.regions.size() != 1) {
                fail("Data decision missing");
                return;
            }
            dialog(code_id, "1");
            phase = 12;
        } else if (phase == 12) {
            if (revision != 8)
                return;
            send(function_id);
            phase = 13;
        } else if (phase == 13) {
            if (revision != 9)
                return;
            dialog(chunks_id, "0x1000+1");
            phase = 14;
        } else if (phase == 14) {
            if (revision != 10)
                return;
            send(suppress_id);
            phase = 15;
        } else if (phase == 15) {
            if (revision != 11)
                return;
            if (!state->state->user->decisions.functions[0].suppressed) {
                fail("Function suppression missing");
                return;
            }
            send(suppress_id);
            phase = 16;
        } else if (phase == 16 || phase == 17) {
            if (revision != (phase == 16 ? 12 : 13))
                return;
            bool remove = phase == 17;
            if (remove && (state->state->user->decisions.references.size() != 1 ||
                           state->state->user->decisions.references[0].kind != UserReferenceKind::read ||
                           state->state->user->decisions.references[0].target != Location{Address{{0}, 0x1001}})) {
                fail("Typed explicit reference mismatch");
                return;
            }
            timer_.Stop();
            CallAfter([remove] {
                auto *target = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("reference-target"));
                auto *dialog = target ? dynamic_cast<wxDialog *>(target->GetParent()) : nullptr;
                auto *kind = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("reference-kind"));
                auto *domain = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("reference-domain"));
                auto *erase = dynamic_cast<wxCheckBox *>(wxWindow::FindWindowByName("reference-remove"));
                if (!target || !dialog || !kind || !domain || !erase) {
                    std::fprintf(stderr, "Typed reference dialog missing\n");
                    std::_Exit(3);
                }
                target->SetValue("0x1001");
                domain->SetSelection(0);
                kind->SetSelection(4);
                erase->SetValue(remove);
                wxCommandEvent okay(wxEVT_BUTTON, wxID_OK);
                dialog->GetEventHandler()->ProcessEvent(okay);
            });
            send(reference_id);
            timer_.Start(20);
            ++phase;
        } else if (phase == 18) {
            if (revision != 14)
                return;
            if (!state->state->user->decisions.references.empty()) {
                fail("Explicit reference removal missing");
                return;
            }
            dialog(chunks_id, "");
            phase = 181;
        } else if (phase == 181) {
            if (revision != 15)
                return;
            if (!state->state->user->decisions.functions[0].chunks.empty()) {
                fail("Empty native chunks dialog did not clear restriction");
                return;
            }
            send(wxID_UNDO);
            phase = 182;
        } else if (phase == 182) {
            if (revision != 16)
                return;
            if (state->state->user->decisions.functions[0].chunks.size() != 1) {
                fail("Undo did not restore native chunk edit");
                return;
            }
            send(wxID_REDO);
            phase = 183;
        } else if (phase == 183) {
            if (revision != 17)
                return;
            if (!state->state->user->decisions.functions[0].chunks.empty()) {
                fail("Redo did not clear native chunk edit");
                return;
            }
            auto integer = types::Type::integer("ui_int32", 4, 4, true);
            if (!integer || !frame->ApplyProjectCommand(DefineType{"ui_int32", integer.value()})) {
                fail("Could not enqueue a persisted desktop type definition");
                return;
            }
            phase = 184;
        } else if (phase == 184) {
            if (revision != 18)
                return;
            auto *definitions = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("type-definitions", frame));
            auto *structure_button = wxWindow::FindWindowByName("type-define-structure", frame);
            auto *header_import_button = wxWindow::FindWindowByName("types-import-header", frame);
            auto *pdb_import_button = wxWindow::FindWindowByName("types-import-pdb", frame);
            if (!definitions || !structure_button || !structure_button->IsEnabled() || !header_import_button ||
                !header_import_button->IsEnabled() || !pdb_import_button || !pdb_import_button->IsEnabled() ||
                definitions->GetItemCount() != 1 || definitions->GetItemText(0, 0) != "ui_int32" ||
                !definitions->GetItemText(0, 1).Contains("int32")) {
                fail("Persisted type definition, structure editor, or type importer is missing from the desktop Type & Symbols browser");
                return;
            }
            phase = 1840;
            aggregate_editor("ui_pair", "value ui_int32 4", "type-define-structure");
        } else if (phase == 1840) {
            if (revision != 19)
                return;
            auto *definitions = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("type-definitions", frame));
            if (!definitions || definitions->GetItemCount() != 2 || definitions->GetItemText(1, 0) != "ui_pair" ||
                !definitions->GetItemText(1, 1).Contains("struct")) {
                fail("Aggregate creation action did not persist the authored structure");
                return;
            }
            phase = 1841;
        } else if (phase == 1841) {
            if (revision != 19)
                return;
            auto *definitions = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("type-definitions", frame));
            if (!definitions || definitions->GetItemCount() != 2 || definitions->GetItemText(1, 0) != "ui_pair" ||
                !definitions->GetItemText(1, 1).Contains("struct")) {
                fail("Persisted structure definition is missing from the desktop Type & Symbols browser");
                return;
            }
            auto *type_layout = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("type-layout-details", frame));
            if (!type_layout) {
                fail("ABI-aware type layout details are missing from the desktop type browser");
                return;
            }
            definitions->SetItemState(1, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
            wxListEvent selected_type(wxEVT_LIST_ITEM_SELECTED, definitions->GetId());
            selected_type.SetIndex(1);
            definitions->GetEventHandler()->ProcessEvent(selected_type);
            if (!type_layout->GetValue().Contains("Size: 4") || !type_layout->GetValue().Contains("value @ 0") ||
                !type_layout->GetValue().Contains("stored offset 4") || !type_layout->GetValue().Contains("Stored size: 8 bytes (differs)")) {
                fail("Selecting a structure did not compare its declared layout with the ABI-computed layout");
                return;
            }
            frame->Navigate(Address{{0}, 0x1000});
            phase = 185;
            assign_selected_type(1);
            edited_aggregate_id = state->state->user->types[1].id;
        } else if (phase == 185) {
            if (revision != 20)
                return;
            auto *assignments = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("type-assignments", frame));
            if (!assignments || assignments->GetItemCount() != 1 ||
                !assignments->GetItemText(0, 0).Contains("0x1000") ||
                assignments->GetItemText(0, 1) != "ui_pair") {
                fail("Persisted type assignment is missing from the desktop Type & Symbols browser");
                return;
            }
            frame->Navigate(Address{{0}, 0x1001});
            assignments->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
            wxListEvent selected_assignment(wxEVT_LIST_ITEM_SELECTED, assignments->GetId());
            selected_assignment.SetIndex(0);
            assignments->GetEventHandler()->ProcessEvent(selected_assignment);
            if (frame->documents().selection() != Location{Address{{0}, 0x1000}}) {
                fail("Activating a type assignment did not navigate to its assigned address");
                return;
            }
            auto *definitions = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("type-definitions", frame));
            if (!definitions) { fail("Type table vanished before the aggregate edit action"); return; }
            definitions->SetItemState(1, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
            wxListEvent selected_type(wxEVT_LIST_ITEM_SELECTED, definitions->GetId());
            selected_type.SetIndex(1);
            definitions->GetEventHandler()->ProcessEvent(selected_type);
            phase = 1851;
            aggregate_editor("ui_pair_edited", "renamed_value ui_int32 0", "type-edit", true);
        } else if (phase == 1851) {
            if (revision != 21)
                return;
            auto *definitions = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("type-definitions", frame));
            auto *assignments = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("type-assignments", frame));
            if (!definitions || definitions->GetItemCount() != 2 || definitions->GetItemText(1, 0) != "ui_pair_edited" ||
                !assignments || assignments->GetItemCount() != 1 || assignments->GetItemText(0, 1) != "ui_pair_edited" ||
                state->state->user->types[1].id != edited_aggregate_id ||
                state->state->user->type_assignments[0].type_id != edited_aggregate_id) {
                fail("Editing an assigned aggregate did not preserve its identity and address assignment");
                return;
            }
            if (!frame->ApplyProjectCommand(AssignType{Address{{0}, 0x1000}, edited_aggregate_id, true})) {
                fail("Could not enqueue removal of a desktop type assignment");
                return;
            }
            phase = 186;
        } else if (phase == 186) {
            if (auto error = frame->documents().last_error()) {
                fail(error->message.c_str());
                return;
            }
            if (revision != 22 || !state->state->user->type_assignments.empty())
                return;
            send(wxID_UNDO);
            phase = 187;
        } else if (phase == 187) {
            if (revision != 23 || state->state->user->type_assignments.size() != 1)
                return;
            if (!pending_save.valid()) {
                auto actor = frame->projects().actor(*id);
                auto submission = actor ? actor->save() : Result<ProjectSubmission>{Error{ErrorCode::invalid_argument, "Project actor is unavailable"}};
                if (!submission) {
                    fail("Could not enqueue project save after restoring the type assignment");
                    return;
                }
                pending_save = submission.value().result;
                auto watched = frame->projects().watch(*id, std::move(submission.value()));
                if (!watched) {
                    fail("Could not track project save");
                    return;
                }
                return;
            }
            if (pending_save.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
                return;
            const auto &saved = pending_save.get();
            if (!saved) {
                fail("Project save did not finish before reopen");
                return;
            }
            pending_save = {};
            frame->CloseAllDocuments();
            frame->OpenProject(project);
            phase = 188;
        } else if (phase == 188) {
            if (frame->projects().documents().empty() || frame->projects().documents()[0].save_state == DocumentSaveState::opening)
                return;
            auto reopened = frame->projects().active_document();
            auto reopened_project = reopened ? frame->projects().project(*reopened) : nullptr;
            auto *assignments = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("type-assignments", frame));
            if (!reopened_project || reopened_project->state->user->type_assignments.size() != 1 ||
                reopened_project->state->user->type_assignments[0].location != Location{Address{{0}, 0x1000}} ||
                !assignments || assignments->GetItemCount() != 1 || assignments->GetItemText(0, 1) != "ui_pair_edited") {
                fail("Saved type assignment did not survive project reopen in the desktop view");
                return;
            }
            frame->SetSize(1200, 800);
            phase = 19;
        } else if (phase == 19) {
            frame->Update();
            if (!capture("project-editing-normal.png")) {
                fail("Normal screenshot failed");
                return;
            }
            frame->SetSize(640, 480);
            phase = 20;
        } else {
            frame->Update();
            auto *listing = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("disassembly", frame));
            if (!listing || listing->GetCountPerPage() < 4) {
                fail("Compact layout leaves fewer than four listing rows visible");
                return;
            }
            if (!capture("project-editing-compact.png")) {
                fail("Compact screenshot failed");
                return;
            }
            result = 0;
            timer_.Stop();
            frame->CloseAllDocuments();
            frame->Close();
        }
    }
    int OnRun() override {
        wxApp::OnRun();
        return result;
    }
    int OnExit() override {
        std::error_code ignored;
        for (auto path : {project, exported}) {
            std::filesystem::remove(path, ignored);
            for (auto suffix : {L"-wal", L"-shm"}) {
                auto side = path;
                side += suffix;
                std::filesystem::remove(side, ignored);
            }
        }
        return wxApp::OnExit();
    }
};
} // namespace
wxIMPLEMENT_APP(EditApp);
