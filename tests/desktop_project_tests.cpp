#include "main_frame.hpp"
#include "support/desktop_test_window.hpp"
#include "jump_resolver.hpp"
#include "support/fixture_files.hpp"
#include "support/analysis_fixture.hpp"
#include <wx/app.h>
#include <wx/dialog.h>
#include <wx/notebook.h>
#include <wx/listctrl.h>
#include <wx/button.h>
#include <wx/textctrl.h>
#include <wx/timer.h>
#include <cstdio>
using namespace hexlab;
using namespace hexlab::database;
using namespace hexlab::desktop;
using namespace hexlab_test;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
struct Fixture {
    FixtureFile marker{std::span<const std::byte>{}};
    std::filesystem::path path = marker.path.wstring() + L".desktop.hxproj";
    Fixture(uint64_t base, unsigned first) {
        auto store = take(ProjectStore::create(path, {}));
        MemoryStorage data(bytes({first, 0xc3}));
        take(store->import_input(
            data,
            {Format::raw, RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, base}, true, false, true, {}}},
            {}, {}));
    }
    ~Fixture() {
        std::error_code ignored;
        for (auto suffix : {L"", L"-wal", L"-shm"}) {
            auto file = path;
            file += suffix;
            std::filesystem::remove(file, ignored);
        }
    }
};
class ProjectApp final : public wxApp {
    wxTimer timer_{this};
    MainFrame *frame = nullptr;
    std::unique_ptr<Fixture> a, b, external;
    std::shared_ptr<ProjectStore> owner;
    DocumentId first{0}, second{0};
    int phase = 0, ticks = 0, result = 1;
    bool failed = false;
    std::uint64_t initial_edit_revision = 0;

  public:
    bool OnInit() override {
        wxSetAssertHandler([](const wxString &, int, const wxString &, const wxString &, const wxString &message) {
            std::fprintf(stderr, "wx assertion: %s\n", message.utf8_str().data());
            std::_Exit(4);
        });
        a = std::make_unique<Fixture>(0x1000, 0x90);
        b = std::make_unique<Fixture>(0x2000, 0xcc);
        external = std::make_unique<Fixture>(0x3000, 0x90);
        owner = take(ProjectStore::open(external->path, ProjectMode::read_write, {}));
        frame = new MainFrame;
        show_test_window(frame);
        frame->OpenProject(a->path);
        Bind(wxEVT_TIMER, [this](wxTimerEvent &) { tick(); });
        timer_.Start(20);
        return true;
    }
    void fail(const char *message) {
        failed = true;
        std::fprintf(stderr, "%s (phase %d)\n", message, phase);
        timer_.Stop();
        frame->Close();
    }
    bool selected(Location value) { return frame->documents().selection() == value; }
    void jump(const wxString &value) {
        timer_.Stop();
        CallAfter([this, value] {
            auto *dialog = dynamic_cast<wxDialog *>(wxWindow::FindWindowByLabel("Jump to location"));
            auto *entry = dialog ? dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("location-value", dialog)) : nullptr;
            if (!dialog || !entry) {
                fail("Jump dialog or location entry missing");
                if (dialog)
                    dialog->EndModal(wxID_CANCEL);
                return;
            }
            entry->SetValue(value);
            wxCommandEvent ok(wxEVT_BUTTON, wxID_OK);
            dialog->GetEventHandler()->ProcessEvent(ok);
        });
        wxCommandEvent command(wxEVT_MENU, jump_id);
        frame->GetEventHandler()->ProcessEvent(command);
        if (!failed)
            timer_.Start(20);
    }
    void tick() {
        if (++ticks > 1000) {
            fail("Project desktop workflow timed out");
            return;
        }
        if (frame->documents().opening())
            return;
        auto &manager = frame->projects();
        auto active = manager.active_document();
        if (!active)
            return;
        auto *tabs = dynamic_cast<wxNotebook *>(wxWindow::FindWindowByName("document-tabs", frame));
        auto *listing = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("disassembly", frame));
        auto *bytes_view = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("bytes", frame));
        auto *new_compound_type = dynamic_cast<wxButton *>(wxWindow::FindWindowByName("type-define-compound", frame));
        auto *edit_type = dynamic_cast<wxButton *>(wxWindow::FindWindowByName("type-edit", frame));
        auto *remove_bookmark = dynamic_cast<wxButton *>(wxWindow::FindWindowByName("bookmark-remove", frame));
        auto *rename_bookmark = dynamic_cast<wxButton *>(wxWindow::FindWindowByName("bookmark-rename", frame));
        if (!tabs || !listing || !bytes_view || !new_compound_type || !edit_type) {
            fail("Project tabs or data views missing");
            return;
        }
        if (phase == 0) {
            if (!new_compound_type->IsEnabled() || edit_type->IsEnabled()) {
                fail("Compound type actions do not reflect an open project with no selected type");
                return;
            }
            if (!selected(Address{{0}, 0x1000}) || listing->GetItemText(0, 1) != "90") {
                fail("First project projection mismatch");
                return;
            }
            if (!remove_bookmark || !rename_bookmark) {
                fail("Bookmark management controls missing");
                return;
            }
            first = *active;
            initial_edit_revision = manager.project(first)->state->revisions.edit;
            take(manager.actor(first)->execute(BookmarkCommand{Address{{0}, 0x1000}, "entry", false}));
            phase = 10;
        } else if (phase == 10) {
            if (manager.project(first)->state->user->bookmarks.empty())
                return;
            auto *bookmarks = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("bookmarks", frame));
            if (!bookmarks || bookmarks->GetItemCount() != 1) {
                fail("Bookmark row was not projected into the desktop view");
                return;
            }
            std::vector<std::pair<wxString, Location>> names;
            for (const auto &bookmark : manager.project(first)->state->user->bookmarks)
                names.emplace_back(bookmark.label, bookmark.location);
            const auto match = resolve_named_location(names, "ENTRY");
            if (!match.location || *match.location != Location{Address{{0}, 0x1000}}) {
                fail("Case-insensitive bookmark name did not resolve to its address");
                return;
            }
            names.emplace_back("entry", Address{{0}, 0x1000});
            if (resolve_named_location(names, "Entry").ambiguous) {
                fail("Duplicate names for one address were treated as ambiguous");
                return;
            }
            names.emplace_back("entry", Address{{0}, 0x1001});
            if (!resolve_named_location(names, "Entry").ambiguous) {
                fail("Conflicting locations with the same name were not reported as ambiguous");
                return;
            }
            const auto candidates = named_location_candidates(names, "Entry");
            if (candidates.size() != 2 || candidates[0].location != Location{Address{{0}, 0x1000}} ||
                candidates[1].location != Location{Address{{0}, 0x1001}}) {
                fail("Ambiguous name candidates were not retained in stable unique-location order");
                return;
            }
            frame->Navigate(Address{{0}, 0x1001});
            jump("ENTRY");
            phase = 101;
        } else if (phase == 101) {
            if (!selected(Address{{0}, 0x1000})) {
                fail("Jump by bookmark label did not navigate to its address");
                return;
            }
            take(manager.actor(first)->execute(Comment{Address{{0}, 0x1001}, "second marker"}));
            phase = 102;
        } else if (phase == 102) {
            if (manager.project(first)->state->user->annotations.empty())
                return;
            wxCommandEvent next(wxEVT_MENU, next_marker_id);
            frame->GetEventHandler()->ProcessEvent(next);
            if (!selected(Address{{0}, 0x1001}) || bytes_view->GetItemText(0, 1).Left(2) != "C3") {
                fail("Next marker did not synchronize listing and bytes to the annotation");
                return;
            }
            wxCommandEvent previous(wxEVT_MENU, previous_marker_id);
            frame->GetEventHandler()->ProcessEvent(previous);
            if (!selected(Address{{0}, 0x1000})) {
                fail("Previous marker did not return to the bookmark");
                return;
            }
            wxCommandEvent back(wxEVT_MENU, back_id);
            frame->GetEventHandler()->ProcessEvent(back);
            if (!selected(Address{{0}, 0x1001})) {
                fail("Back history did not include marker navigation");
                return;
            }
            wxCommandEvent forward(wxEVT_MENU, forward_id);
            frame->GetEventHandler()->ProcessEvent(forward);
            if (!selected(Address{{0}, 0x1000}) || bytes_view->GetItemText(0, 1).Left(2) != "90") {
                fail("Forward history did not restore the bookmark across views");
                return;
            }
            auto *bookmarks = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("bookmarks", frame));
            bookmarks->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
            wxCommandEvent click(wxEVT_BUTTON, remove_bookmark->GetId());
            remove_bookmark->GetEventHandler()->ProcessEvent(click);
            phase = 11;
        } else if (phase == 11) {
            if (!manager.project(first)->state->user->bookmarks.empty())
                return;
            frame->Navigate(Address{{0}, 0x1001});
            frame->OpenProject(b->path);
            phase = 1;
        } else if (phase == 1) {
            if (*active == first)
                return;
            second = *active;
            if (tabs->GetPageCount() != 2 || !selected(Address{{0}, 0x2000}) || listing->GetItemText(0, 1) != "CC") {
                fail("Second project is not isolated");
                return;
            }
            tabs->SetSelection(0);
            phase = 2;
        } else if (phase == 2) {
            if (*active != first)
                return;
            if (!selected(Address{{0}, 0x1001}) || bytes_view->GetItemText(0, 1).Left(2) != "C3") {
                fail("Native tab selection lost first navigation");
                return;
            }
            tabs->SetSelection(1);
            take(manager.watch(first, manager.actor(first)->execute(Comment{FileOffset{0}, "inactive edit"})));
            phase = 3;
        } else if (phase == 3) {
            // Bookmark creation, marker annotation, bookmark removal, and the
            // inactive comment each commit one project edit.
            if (manager.project(first)->state->revisions.edit != initial_edit_revision + 4)
                return;
            if (*active != second || !selected(Address{{0}, 0x2000}) ||
                manager.project(second)->state->revisions.edit != 0 || listing->GetItemText(0, 1) != "CC") {
                fail("Inactive completion contaminated active views");
                return;
            }
            frame->OpenProject(a->path);
            phase = 4;
        } else if (phase == 4) {
            if (*active != first)
                return;
            if (manager.documents().size() != 2 || tabs->GetPageCount() != 2 || !selected(Address{{0}, 0x1001})) {
                fail("Duplicate UUID did not activate existing project");
                return;
            }
            wxCommandEvent close(wxEVT_MENU, wxID_CLOSE);
            frame->GetEventHandler()->ProcessEvent(close);
            phase = 5;
        } else if (phase == 5) {
            if (*active != second)
                return;
            if (tabs->GetPageCount() != 1 || !selected(Address{{0}, 0x2000})) {
                fail("Closing first project damaged second tab");
                return;
            }
            frame->OpenProject(external->path);
            phase = 6;
        } else if (phase == 6) {
            if (*active == second)
                return;
            if (manager.project(*active)->mode != ProjectMode::read_only ||
                !tabs->GetPageText(tabs->GetSelection()).Contains("read-only")) {
                fail("External owner read-only state is not visible");
                return;
            }
            frame->CloseAllDocuments();
            if (frame->documents().current() || !manager.documents().empty()) {
                fail("Close all retained a project projection");
                return;
            }
            result = 0;
            timer_.Stop();
            frame->Close();
        }
    }
    int OnRun() override {
        wxApp::OnRun();
        return result;
    }
};
} // namespace
wxIMPLEMENT_APP(ProjectApp);
