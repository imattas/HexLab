#include "main_frame.hpp"
#include "support/desktop_test_window.hpp"
#include "project_actions.hpp"
#include "project_testing.hpp"
#include "support/fixture_files.hpp"
#include <wx/app.h>
#include <wx/dialog.h>
#include <wx/textctrl.h>
#include <wx/choice.h>
#include <wx/checkbox.h>
#include <wx/listctrl.h>
#include <wx/button.h>
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
    std::binary_semaphore release{0};
    std::atomic<bool> claimed = false, opened = false;
    void open() {
        if (!opened.exchange(true))
            release.release();
    }
};
class SearchApp final : public wxApp {
    wxTimer timer_{this};
    MainFrame *frame = nullptr;
    std::unique_ptr<FixtureFile> file;
    DocumentId first{0}, second{0};
    SessionKey key;
    std::shared_ptr<Gate> gate = std::make_shared<Gate>();
    int phase = 0, ticks = 0, result = 1;
    std::thread::id gui;

  public:
    bool OnInit() override {
        gui = std::this_thread::get_id();
        wxSetAssertHandler([](const wxString &, int, const wxString &, const wxString &, const wxString &message) {
            std::fprintf(stderr, "wx assertion: %s\n", message.utf8_str().data());
            std::_Exit(4);
        });
        file = std::make_unique<FixtureFile>(
            bytes({0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xb0, 0xff, 0xc3, 'H', 'E',  'L', 'L',  'O',  'H', 'E',
                   'L',  'L',  'O',  0,    0xc3, 0xa9, 0xf0, 0x9f, 0x98, 0x80, 0,   0xe9, 0,   0x3d, 0xd8, 0,   0xde}));
        frame = new MainFrame;
        show_test_window(frame);
        open(0x1000);
        Bind(wxEVT_TIMER, [this](wxTimerEvent &) { tick(); });
        timer_.Start(20);
        return true;
    }
    void open(uint64_t base) {
        OpenRequest request;
        request.path = file->path;
        request.format = Format::raw;
        request.raw = RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, base}, true, false, true, {}};
        frame->OpenDocument(request);
    }
    void fail(const char *message) {
        std::fprintf(stderr, "%s (phase %d)\n", message, phase);
        gate->open();
        timer_.Stop();
        frame->CloseAllDocuments();
        frame->Close();
    }
    void send(int id) {
        wxCommandEvent event(wxEVT_MENU, id);
        frame->GetEventHandler()->ProcessEvent(event);
    }
    bool selected(Location value) { return frame->documents().selection() == value; }
    void find_dialog(int kind, const wxString &value, int limit = 256, bool invalid_first = false, int encoding = 1,
                     bool all_documents = false) {
        timer_.Stop();
        auto failed = std::make_shared<bool>(false);
        CallAfter([kind, value, limit, invalid_first, failed, encoding, all_documents] {
            auto *field = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("search-value"));
            auto *dialog = field ? dynamic_cast<wxDialog *>(field->GetParent()) : nullptr;
            auto *mode = dialog ? dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("search-kind", dialog)) : nullptr;
            auto *count =
                dialog ? dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("search-limit", dialog)) : nullptr;
            if (!field || !dialog || !mode || !count)
                std::_Exit(3);
            mode->SetSelection(kind);
            wxCommandEvent changed(wxEVT_CHOICE, mode->GetId());
            mode->GetEventHandler()->ProcessEvent(changed);
            auto *codec = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("search-encoding", dialog));
            auto *all = dynamic_cast<wxCheckBox *>(wxWindow::FindWindowByName("search-all-documents", dialog));
            if (!codec || !all)
                std::_Exit(3);
            codec->SetSelection(encoding);
            all->SetValue(all_documents);
            count->SetValue(wxString::Format("%d", limit));
            wxCommandEvent okay(wxEVT_BUTTON, wxID_OK);
            if (invalid_first) {
                field->SetValue("GG");
                dialog->GetEventHandler()->ProcessEvent(okay);
                auto *error = wxWindow::FindWindowByName("search-error", dialog);
                if (!dialog->IsShown() || !error || error->GetLabel().empty())
                    std::_Exit(3);
            }
            field->SetValue(value);
            dialog->GetEventHandler()->ProcessEvent(okay);
            if (dialog->IsShown()) {
                auto *error = wxWindow::FindWindowByName("search-error", dialog);
                std::fprintf(stderr, "Valid search rejected: %s\n",
                             error ? error->GetLabel().utf8_str().data() : "missing diagnostic");
                *failed = true;
                dialog->EndModal(wxID_CANCEL);
            }
        });
        send(wxID_FIND);
        if (*failed) {
            fail("Find dialog rejected valid input");
            return;
        }
        timer_.Start(20);
    }
    void tick() {
        if (++ticks > 1000) {
            fail("Search workflow timed out");
            return;
        }
        auto &manager = frame->projects();
        auto active = manager.active_document();
        if (!active)
            return;
        auto history = manager.search_history(*active);
        auto *results = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("search-results", frame));
        if (phase != 6 && frame->documents().opening())
            return;
        if (phase == 0) {
            first = *active;
            key = manager.actor(first)->view().session;
            find_dialog(0, "FF", 1, true);
            phase = 1;
        } else if (phase == 1) {
            if (!results || history->size() != 1)
                return;
            if (!selected(Address{{0}, 0x1003}) || results->GetItemText(0, 1) != "file:0x3") {
                fail("First literal search result did not navigate to actual bytes");
                return;
            }
            send(find_next_id);
            phase = 2;
        } else if (phase == 2) {
            if (history->size() != 2)
                return;
            if (!selected(Address{{0}, 0x1004})) {
                fail("Find Next did not append and navigate next page");
                return;
            }
            send(find_previous_id);
            if (!selected(Address{{0}, 0x1003})) {
                fail("Find Previous lost first location");
                return;
            }
            auto *more = dynamic_cast<wxButton *>(wxWindow::FindWindowByName("search-more", frame));
            if (!more || !more->IsEnabled()) {
                fail("More results unavailable");
                return;
            }
            wxCommandEvent click(wxEVT_BUTTON, more->GetId());
            more->GetEventHandler()->ProcessEvent(click);
            phase = 3;
        } else if (phase == 3) {
            if (history->size() != 3)
                return;
            results->SetItemState(2, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
            if (!selected(Address{{0}, 0x1005})) {
                fail("Nonfirst native search row did not navigate");
                return;
            }
            send(back_id);
            if (!selected(Address{{0}, 0x1003})) {
                fail("Search result selection did not use document navigation history");
                return;
            }
            auto state = gate;
            auto gui_id = gui;
            workspace_testing::set_actor_hook(
                key, [state, gui_id](const workspace_testing::ActorCheckpoint &checkpoint) {
                    if (checkpoint.phase == workspace_testing::ActorPhase::search_started ||
                        checkpoint.phase == workspace_testing::ActorPhase::listing_started)
                        if (std::this_thread::get_id() == gui_id)
                            throw std::runtime_error("Read task ran on GUI thread");
                    if (checkpoint.phase == workspace_testing::ActorPhase::search_computed &&
                        !state->claimed.exchange(true)) {
                        state->entered.set_value(true);
                        state->release.acquire();
                    }
                });
            if (!frame->Find(BytePattern{"FF"})) {
                fail("Cannot queue held search");
                return;
            }
            phase = 4;
        } else if (phase == 4) {
            if (gate->reached.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
                return;
            send(cancel_id);
            send(reanalyze_id);
            if (frame->FindPending()) {
                fail("Cancel left search pending in the GUI");
                return;
            }
            gate->open();
            workspace_testing::clear_actor_hook(key);
            gate = std::make_shared<Gate>();
            auto held = gate;
            workspace_testing::set_actor_hook(key, [held](const workspace_testing::ActorCheckpoint &checkpoint) {
                if (checkpoint.phase == workspace_testing::ActorPhase::search_computed &&
                    !held->claimed.exchange(true)) {
                    held->entered.set_value(true);
                    held->release.acquire();
                }
            });
            if (!frame->Find(BytePattern{"FF"})) {
                fail("Cannot search again after Cancel");
                return;
            }
            phase = 5;
        } else if (phase == 5) {
            if (gate->reached.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
                return;
            if (!frame->ApplyProjectCommand(PatchBytes{FileOffset{3}, bytes({0x7f})})) {
                fail("Cannot patch while search is held");
                return;
            }
            phase = 6;
        } else if (phase == 6) {
            auto project = manager.project(first);
            if (project->state->revisions.bytes != 1)
                return;
            gate->open();
            phase = 7;
        } else if (phase == 7) {
            if (history->size() != 0) {
                fail("Old search completion survived patched source revision");
                return;
            }
            send(find_next_id);
            phase = 70;
        } else if (phase == 70) {
            if (history->size() != 4)
                return;
            if (!selected(Address{{0}, 0x1004})) {
                fail("Find Next did not restart the retained query on the edited source");
                return;
            }
            workspace_testing::clear_actor_hook(key);
            if (!frame->Find(ImmediateQuery{"255", 8, ImmediateInterpretation::unsigned_value})) {
                fail("Cannot queue immediate search");
                return;
            }
            phase = 8;
        } else if (phase == 8) {
            if (history->size() != 1)
                return;
            if (!selected(Address{{0}, 0x1007})) {
                fail("Effective-width immediate search used wrong instruction");
                return;
            }
            find_dialog(1, "HELLO");
            phase = 9;
        } else if (phase == 9) {
            if (history->size() != 2)
                return;
            find_dialog(1, wxString::FromUTF8("\xc3\xa9\xf0\x9f\x98\x80"));
            phase = 90;
        } else if (phase == 90) {
            if (history->size() != 1 || frame->FindPending())
                return;
            if (!selected(Address{{0}, 0x1015}) || results->GetItemText(0, 3) != "6") {
                fail("UTF-8 GUI search mismatch");
                return;
            }
            find_dialog(1, wxString::FromUTF8("\xc3\xa9\xf0\x9f\x98\x80"), 256, false, 2);
            phase = 91;
        } else if (phase == 91) {
            if (history->size() != 1 || frame->FindPending())
                return;
            if (!selected(Address{{0}, 0x101c}) || results->GetItemText(0, 3) != "6") {
                fail("UTF-16 GUI search mismatch");
                return;
            }
            find_dialog(1, "HELLO");
            phase = 92;
        } else if (phase == 92) {
            if (history->size() != 2 || frame->FindPending())
                return;
            open(0x2000);
            phase = 10;
        } else if (phase == 10) {
            if (*active == first)
                return;
            second = *active;
            if (history->size() != 0 || !results || results->GetItemCount() != 0) {
                fail("Another document inherited prior search results");
                return;
            }
            frame->ActivateDocument(first);
            phase = 11;
        } else if (phase == 11) {
            if (*active != first)
                return;
            if (history->size() != 2 || !results || results->GetItemCount() != 2 || !selected(Address{{0}, 0x100a})) {
                fail("Switching tabs did not restore search and navigation");
                return;
            }
            find_dialog(1, "HELLO", 1, false, 1, true);
            phase = 12;
        } else if (phase == 12) {
            if (frame->FindPending() || !results || results->GetItemCount() != 2)
                return;
            auto *more = dynamic_cast<wxButton *>(wxWindow::FindWindowByName("search-more", frame));
            if (!more || !more->IsEnabled()) {
                fail("All-document search did not expose page continuations");
                return;
            }
            wxCommandEvent click(wxEVT_BUTTON, more->GetId());
            more->GetEventHandler()->ProcessEvent(click);
            phase = 13;
        } else if (phase == 13) {
            if (frame->FindPending() || !results || results->GetItemCount() != 4)
                return;
            const auto second_label = wxString::Format("[%llu]", static_cast<unsigned long long>(second.value));
            if (!results->GetItemText(2, 0).Contains(second_label)) {
                fail("All-document search did not group results by their owning document");
                return;
            }
            results->SetItemState(2, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
            if (*manager.active_document() != second || !selected(Address{{0}, 0x200a})) {
                fail("Selecting an all-document result did not activate and navigate its document");
                return;
            }
            result = 0;
            gate->open();
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
        workspace_testing::clear_actor_hook(key);
        return wxApp::OnExit();
    }
};
} // namespace
wxIMPLEMENT_APP(SearchApp);
