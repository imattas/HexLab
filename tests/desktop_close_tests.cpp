#include "main_frame.hpp"
#include "support/desktop_test_window.hpp"
#include "project_testing.hpp"
#include "support/fixture_files.hpp"
#include <wx/app.h>
#include <wx/dialog.h>
#include <wx/timer.h>
#include <semaphore>
#include <cstdio>
using namespace hexlab;
using namespace hexlab::desktop;
using namespace hexlab_test;
namespace {
struct Gate {
    std::promise<bool> entered;
    std::shared_future<bool> reached = entered.get_future().share();
    std::binary_semaphore released{0};
    std::atomic<bool> opened = false, claimed = false;
    void open() {
        if (!opened.exchange(true))
            released.release();
    }
};
class CloseApp final : public wxApp {
    wxTimer timer_{this};
    MainFrame *frame = nullptr;
    std::unique_ptr<FixtureFile> input;
    std::filesystem::path saved;
    int phase = 0, ticks = 0;
    bool verify = false;
    std::shared_ptr<Gate> gate = std::make_shared<Gate>();
    SessionKey hooked;

  public:
    bool OnInit() override {
        wxSetAssertHandler([](const wxString &, int, const wxString &, const wxString &, const wxString &message) {
            std::fprintf(stderr, "wx assertion: %s\n", message.utf8_str().data());
            std::_Exit(4);
        });
        input = std::make_unique<FixtureFile>(bytes({0x90, 0xc3}));
        saved = input->path.wstring() + L".close.hxproj";
        frame = new MainFrame;
        show_test_window(frame);
        open();
        Bind(wxEVT_TIMER, [this](wxTimerEvent &) { tick(); });
        timer_.Start(20);
        return true;
    }
    void open() {
        OpenRequest request;
        request.path = input->path;
        request.format = Format::raw;
        request.raw = RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x1000}, true, false, true, {}};
        frame->OpenDocument(request);
    }
    void fail(const char *message) {
        std::fprintf(stderr, "%s (phase %d)\n", message, phase);
        gate->open();
        timer_.Stop();
        frame->CloseAllDocuments();
        frame->Close();
    }
    bool choice(int answer) {
        auto seen = std::make_shared<bool>(false);
        CallAfter([seen, answer] {
            auto *dialog = dynamic_cast<wxDialog *>(wxWindow::FindWindowByName("unsaved-choice"));
            if (!dialog)
                return;
            *seen = true;
            wxCommandEvent event(wxEVT_BUTTON, answer);
            dialog->GetEventHandler()->ProcessEvent(event);
        });
        wxCommandEvent close(wxEVT_MENU, wxID_CLOSE);
        frame->GetEventHandler()->ProcessEvent(close);
        return *seen;
    }
    void tick() {
        if (++ticks > 1000) {
            fail("Close workflow timed out");
            return;
        }
        if (frame->documents().opening())
            return;
        auto id = frame->projects().active_document();
        if (!id)
            return;
        auto project = frame->projects().project(*id);
        if (!project)
            return;
        if (phase == 0) {
            if (!frame->ApplyProjectCommand(Comment{FileOffset{0}, "discard me"})) {
                fail("Cannot queue untitled edit");
                return;
            }
            phase = 1;
        } else if (phase == 1) {
            if (project->state->revisions.edit != 1)
                return;
            if (!choice(wxID_CANCEL) || frame->projects().active_document() != id ||
                project->state->user->annotations.size() != 1) {
                fail("Cancel close lost an edited untitled project");
                return;
            }
            if (!choice(wxID_NO) || frame->projects().actor(*id)) {
                fail("Discard did not close the selected untitled project");
                return;
            }
            open();
            phase = 2;
        } else if (phase == 2) {
            if (!frame->ApplyProjectCommand(Comment{FileOffset{0}, "keep me"})) {
                fail("Cannot queue saved edit");
                return;
            }
            phase = 3;
        } else if (phase == 3) {
            if (project->state->revisions.edit != 1)
                return;
            hooked = frame->projects().actor(*id)->view().session;
            auto state = gate;
            workspace_testing::set_actor_hook(hooked, [state](const workspace_testing::ActorCheckpoint &checkpoint) {
                if (checkpoint.phase == workspace_testing::ActorPhase::after_saved && !state->claimed.exchange(true)) {
                    state->entered.set_value(true);
                    state->released.acquire();
                }
            });
            if (!frame->SaveProjectAs(saved)) {
                fail("Cannot queue held Save As");
                return;
            }
            phase = 4;
        } else if (phase == 4) {
            if (gate->reached.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
                return;
            timer_.Stop();
            verify = true;
            bool closed = frame->Close();
            if(!closed && frame->ApplyProjectCommand(Comment{FileOffset{0},"must not edit while closing"})){
                std::fprintf(stderr,"Closing window still accepted a new edit\n");verify=false;
            }
            gate->open();
            if (closed) {
                std::fprintf(stderr, "Window did not defer close while Save As acknowledgement was held\n");
                verify = false;
            }
            phase = 5;
        }
    }
    int OnRun() override {
        wxApp::OnRun();
        workspace_testing::clear_actor_hook(hooked);
        if (!verify)
            return 1;
        auto store = database::ProjectStore::open(saved, database::ProjectMode::read_only, {});
        if (!store) {
            std::fprintf(stderr, "Deferred close did not preserve saved project\n");
            return 1;
        }
        auto state = store.value()->snapshot();
        if (!state || state.value()->revisions.edit != 1 || state.value()->user->annotations.size() != 1 ||
            state.value()->user->annotations[0].comment != "keep me") {
            std::fprintf(stderr, "Deferred close lost committed annotation\n");
            return 1;
        }
        return 0;
    }
    int OnExit() override {
        std::error_code ignored;
        for (auto suffix : {L"", L"-wal", L"-shm"}) {
            auto file = saved;
            file += suffix;
            std::filesystem::remove(file, ignored);
        }
        return wxApp::OnExit();
    }
};
} // namespace
wxIMPLEMENT_APP(CloseApp);
