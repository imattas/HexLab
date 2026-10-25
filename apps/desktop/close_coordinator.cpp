#include "close_coordinator.hpp"
#include <wx/dialog.h>
#include <wx/button.h>
#include <wx/stattext.h>
#include <wx/sizer.h>
#include <wx/filedlg.h>
#include <algorithm>
namespace hexlab::desktop {
namespace {
int unsaved_choice(wxWindow *parent, const wxString &name) {
    wxDialog dialog(parent, wxID_ANY, "Unsaved project");
    dialog.SetName("unsaved-choice");
    auto *box = new wxBoxSizer(wxVERTICAL);
    auto *label = new wxStaticText(&dialog, wxID_ANY, "Save changes to " + name.Left(120) + " before closing?");
    label->Wrap(dialog.FromDIP(420));
    box->Add(label, 0, wxALL, 15);
    auto *buttons = new wxStdDialogButtonSizer;
    auto *save = new wxButton(&dialog, wxID_YES, "Save");
    buttons->AddButton(save);
    buttons->AddButton(new wxButton(&dialog, wxID_NO, "Discard"));
    buttons->AddButton(new wxButton(&dialog, wxID_CANCEL, "Cancel"));
    buttons->Realize();
    box->Add(buttons, 0, wxALL | wxALIGN_RIGHT, 10);
    dialog.SetSizerAndFit(box);
    save->SetDefault();
    for (int answer : {wxID_YES, wxID_NO, wxID_CANCEL})
        dialog.Bind(wxEVT_BUTTON, [&](wxCommandEvent &event) { dialog.EndModal(event.GetId()); }, answer);
    return dialog.ShowModal();
}
} // namespace
CloseCoordinator::CloseCoordinator(wxFrame &frame, SessionController &controller)
    : frame_(frame), controller_(controller) {
    frame_.Bind(wxEVT_CLOSE_WINDOW, &CloseCoordinator::window_close, this);
    frame_.Bind(wxEVT_MENU, &CloseCoordinator::document_close, this, wxID_CLOSE);
}
CloseCoordinator::~CloseCoordinator() {
    frame_.Unbind(wxEVT_CLOSE_WINDOW, &CloseCoordinator::window_close, this);
    frame_.Unbind(wxEVT_MENU, &CloseCoordinator::document_close, this, wxID_CLOSE);
}
void CloseCoordinator::cancel_pending() {
    if(disabled_){disabled_=false;frame_.Enable();}
    queue_.clear();
    waiting_.reset();
    frame_requested_ = false;
    approved_ = false;
}
void CloseCoordinator::document_close(wxCommandEvent &) {
    if (frame_requested_ || waiting_)
        return;
    if (auto id = controller_.documents().active_document())
        request_close(*id);
}
void CloseCoordinator::request_close(DocumentId id) {
    if (frame_requested_ || waiting_)
        return;
    queue_ = {id};
    step(false);
}
void CloseCoordinator::request_close_many(std::vector<DocumentId> ids) {
    if (frame_requested_ || approved_ || waiting_)
        return;
    queue_.clear();
    queue_.reserve(ids.size());
    for (auto id : ids)
        if (std::find(queue_.begin(), queue_.end(), id) == queue_.end())
            queue_.push_back(id);
    step(false);
}
void CloseCoordinator::window_close(wxCloseEvent &event) {
    if (approved_ || !event.CanVeto()) {
        event.Skip();
        return;
    }
    if (frame_requested_) {
        event.Veto();
        return;
    }
    frame_requested_ = true;
    queue_.clear();
    if (waiting_)
        queue_.push_back(waiting_->id);
    for (auto &document : controller_.documents().documents())
        if (!waiting_ || waiting_->id != document.id)
            queue_.push_back(document.id);
    step(false);
    if (approved_)
        event.Skip();
    else{
        if(frame_requested_ && !disabled_){disabled_=true;frame_.Disable();}
        event.Veto();
    }
}
void CloseCoordinator::progress() {
    if (waiting_ || frame_requested_ || !queue_.empty())
        step(true);
}
void CloseCoordinator::step(bool schedule_frame) {
    if (stepping_)
        return;
    stepping_ = true;
    struct Reset {
        bool &value;
        ~Reset() { value = false; }
    } reset{stepping_};
    while (!queue_.empty()) {
        auto id = queue_.front();
        auto entries = controller_.documents().documents();
        auto found = std::find_if(entries.begin(), entries.end(), [&](auto &info) { return info.id == id; });
        if (found == entries.end()) {
            if (waiting_ && waiting_->id == id)
                waiting_.reset();
            queue_.erase(queue_.begin());
            continue;
        }
        if (found->save_state == DocumentSaveState::saving) {
            if (!waiting_)
                waiting_ = Waiting{id, false};
            return;
        }
        if (waiting_ && waiting_->id == id) {
            bool failed = found->error.has_value() || (waiting_->require_saved && !found->path);
            waiting_.reset();
            if (failed) {
                cancel_pending();
                return;
            }
        }
        auto project = controller_.documents().project(id);
        if (!found->path && project && project->state->revisions.edit > 0) {
            wxString name = "Untitled";
            if (project->state->provenance && !project->state->provenance->native_path.empty())
                name = wxString(project->state->provenance->native_path.filename().wstring());
            auto answer = unsaved_choice(&frame_, name);
            if (answer == wxID_CANCEL) {
                cancel_pending();
                return;
            }
            if (answer == wxID_YES) {
                wxFileDialog dialog(&frame_, "Save project", {}, "analysis.hxproj",
                                    "HexLab projects (*.hxproj)|*.hxproj", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
                if (dialog.ShowModal() != wxID_OK) {
                    cancel_pending();
                    return;
                }
                std::filesystem::path path = dialog.GetPath().ToStdWstring();
                std::error_code ignored;
                bool replace = std::filesystem::exists(path, ignored);
                auto submitted = controller_.save_as(id, std::move(path), replace);
                if (!submitted) {
                    controller_.documents().report_error(id, submitted.error());
                    cancel_pending();
                    return;
                }
                waiting_ = Waiting{id, true};
                return;
            }
        }
        queue_.erase(queue_.begin());
        controller_.close(id);
    }
    if (frame_requested_) {
        frame_requested_ = false;
        approved_ = true;
        if (schedule_frame)
            frame_.CallAfter([this] {
                if (approved_)
                    frame_.Close();
            });
    }
}
} // namespace hexlab::desktop
