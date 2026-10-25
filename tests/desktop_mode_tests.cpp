#include "main_frame.hpp"
#include "support/desktop_test_window.hpp"
#include "open_dialogs.hpp"
#include "graph_canvas.hpp"
#include "project_testing.hpp"
#include "support/fixture_files.hpp"
#include <wx/app.h>
#include <wx/choice.h>
#include <wx/dialog.h>
#include <wx/listctrl.h>
#include <wx/statusbr.h>
#include <wx/textctrl.h>
#include <wx/timer.h>
#include <wx/dcclient.h>
#include <wx/dcmemory.h>
#include <wx/image.h>
#include <wx/msw/wrapwin.h>
#include <semaphore>
#include <cstdio>
#include <algorithm>
using namespace hexlab;
using namespace hexlab::desktop;
using namespace hexlab_test;
namespace {
struct Gate {
    std::atomic<bool> claimed = false, opened = false;
    std::promise<bool> entered;
    std::shared_future<bool> reached = entered.get_future().share();
    std::binary_semaphore released{0};
    void open() {
        if (!opened.exchange(true))
            released.release();
    }
};
class ModeApp final : public wxApp {
    wxTimer timer_{this};
    MainFrame *frame = nullptr;
    std::unique_ptr<FixtureFile> input;
    OpenRequest request;
    DocumentId first{0}, second{0};
    SessionKey hooked;
    std::filesystem::path saved, exported;
    std::shared_ptr<Gate> gate = std::make_shared<Gate>();
    std::shared_ptr<const ProjectSnapshot> long_snapshot;
    std::optional<Location> long_selection;
    int phase = 0, ticks = 0, result = 1, traced = -1;
    void fail(const char *why) {
        std::fprintf(stderr, "%s (phase %d)\n", why, phase);
        gate->open();
        timer_.Stop();
        frame->CloseAllDocuments();
        frame->Close();
    }
    bool require(bool condition, const char *why) {
        if (!condition)
            fail(why);
        return condition;
    }
    void send(int id) {
        wxCommandEvent event(wxEVT_MENU, id);
        frame->GetEventHandler()->ProcessEvent(event);
    }
    wxListCtrl *table(const char *name) { return dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName(name, frame)); }
    bool mode(ExecutionMode expected) {
        auto doc = frame->documents().current();
        return doc && doc->image->layout().mode == expected;
    }
    bool fresh(const ProjectSnapshot &p) {
        return p.functions && (p.status == DerivedStatus::fresh || p.status == DerivedStatus::incomplete);
    }
    bool capture(const char *name) {
        auto path = std::filesystem::current_path() / "artifacts" / name;
        std::error_code error;
        std::filesystem::create_directories(path.parent_path(), error);
        if (error)
            return false;
        auto handle = reinterpret_cast<HWND>(frame->GetHandle());
        ShowWindow(handle, SW_SHOWNOACTIVATE);
        frame->Refresh();
        frame->Update();
        auto size = frame->GetSize();
        wxBitmap bitmap(size.x, size.y, 24);
        wxMemoryDC target(bitmap);
        RedrawWindow(handle, nullptr, nullptr,
                     RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW | RDW_ALLCHILDREN | RDW_FRAME);
        bool copied = PrintWindow(handle, reinterpret_cast<HDC>(target.GetHDC()), 0) != 0;
        target.SelectObject(wxNullBitmap);
        auto pixels = bitmap.ConvertToImage();
        size_t lit = 0, total = 0;
        for (int y = 0; y < pixels.GetHeight(); y += 8)
            for (int x = 0; x < pixels.GetWidth(); x += 8) {
                ++total;
                if (pixels.GetRed(x, y) > 32 || pixels.GetGreen(x, y) > 32 || pixels.GetBlue(x, y) > 32)
                    ++lit;
            }
        return copied && total && lit > total / 10 && bitmap.SaveFile(wxString(path.wstring()), wxBITMAP_TYPE_PNG);
    }

  public:
    bool OnInit() override {
        wxInitAllImageHandlers();
        wxSetAssertHandler([](const wxString &, int, const wxString &, const wxString &, const wxString &message) {
            std::fprintf(stderr, "wx assertion: %s\n", message.utf8_str().data());
            std::_Exit(4);
        });
        input = std::make_unique<FixtureFile>(bytes({0x40, 0x74, 3, 0x90, 0xeb, 1, 0x90, 0xc3}));
        saved = input->path.wstring() + L".mode.hxproj";
        exported = input->path.wstring() + L".export.bin";
        frame = new MainFrame;
        show_test_window(frame);
        OpenRequest arm_request;
        arm_request.path = input->path;
        CallAfter([] {
            auto *base = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("raw-base"));
            auto *dialog = base ? dynamic_cast<wxDialog *>(base->GetParent()) : nullptr;
            auto *choice = dialog ? dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("raw-mode", dialog)) : nullptr;
            auto *entry =
                dialog ? dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("raw-entry", dialog)) : nullptr;
            if (!choice || !entry || choice->GetCount() != 12 || !choice->GetString(3).Contains("AArch64") ||
                !choice->GetString(4).Contains("6502") ||
                !choice->GetString(2).Contains("Segmented") || !choice->GetString(5).Contains("RV32I") ||
                !choice->GetString(6).Contains("RV64I") || !choice->GetString(7).Contains("MIPS64") ||
                !choice->GetString(8).Contains("PPC32") || !choice->GetString(9).Contains("big-endian") ||
                !choice->GetString(10).Contains("PPC64") || !choice->GetString(11).Contains("big-endian")) {
                std::fprintf(stderr, "AArch64 raw choice missing or existing mode indices changed\n");
                if (dialog)
                    dialog->EndModal(wxID_CANCEL);
                else
                    std::_Exit(3);
                return;
            }
            choice->SetSelection(3);
            wxCommandEvent changed(wxEVT_CHOICE, choice->GetId());
            choice->GetEventHandler()->ProcessEvent(changed);
            base->SetValue("0x1000");
            entry->SetValue("0x1001");
            wxCommandEvent okay(wxEVT_BUTTON, wxID_OK);
            dialog->GetEventHandler()->ProcessEvent(okay);
            auto *error = wxWindow::FindWindowByName("raw-error", dialog);
            if (!dialog->IsShown() || !error || !error->GetLabel().Contains("aligned")) {
                std::fprintf(stderr, "AArch64 raw dialog accepted misaligned entry\n");
                std::_Exit(3);
            }
            entry->Clear();
            dialog->GetEventHandler()->ProcessEvent(okay);
        });
        if (!configure_raw_mapping(frame, arm_request) || !arm_request.raw ||
            arm_request.raw->architecture != Architecture::arm64 || arm_request.raw->mode != ExecutionMode::a64 ||
            arm_request.raw->base != Address{{0}, 0x1000} || arm_request.x86_profile_path) {
            fail("Native AArch64 choice did not create the shared raw recipe");
            return true;
        }
        OpenRequest mips64_request;
        mips64_request.path = input->path;
        CallAfter([] {
            auto *base = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("raw-base"));
            auto *dialog = base ? dynamic_cast<wxDialog *>(base->GetParent()) : nullptr;
            auto *choice = dialog ? dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("raw-mode", dialog)) : nullptr;
            if (!choice || choice->GetCount() != 12 || !choice->GetString(7).Contains("MIPS64")) {
                std::fprintf(stderr, "MIPS64 raw choice missing\n");
                if (dialog)
                    dialog->EndModal(wxID_CANCEL);
                else
                    std::_Exit(3);
                return;
            }
            choice->SetSelection(7);
            wxCommandEvent okay(wxEVT_BUTTON, wxID_OK);
            dialog->GetEventHandler()->ProcessEvent(okay);
        });
        if (!configure_raw_mapping(frame, mips64_request) || !mips64_request.raw ||
            mips64_request.raw->architecture != Architecture::mips64 ||
            mips64_request.raw->mode != ExecutionMode::mips64 || mips64_request.raw->base != Address{{0}, 0x1000}) {
            fail("Native MIPS64 choice did not create the shared raw recipe");
            return true;
        }
        request.path = input->path;
        CallAfter([] {
            std::fprintf(stderr, "Raw mode dialog callback\n");
            std::fflush(stderr);
            auto *base = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("raw-base"));
            auto *dialog = base ? dynamic_cast<wxDialog *>(base->GetParent()) : nullptr;
            auto *choice = dialog ? dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("raw-mode", dialog)) : nullptr;
            if (!choice || choice->GetSelection() != 0 || !choice->GetString(0).Contains("x86-64")) {
                std::fprintf(stderr, "Native raw mode selector missing or wrong default\n");
                std::_Exit(3);
            }
            choice->SetSelection(1);
            base->SetValue("0x100000000");
            wxCommandEvent okay(wxEVT_BUTTON, wxID_OK);
            dialog->GetEventHandler()->ProcessEvent(okay);
            auto *error = wxWindow::FindWindowByName("raw-error", dialog);
            if (!dialog->IsShown() || !error || error->GetLabel().empty()) {
                std::fprintf(stderr, "Legacy native base overflow accepted\n");
                std::_Exit(3);
            }
            base->SetValue("0x1000");
            dialog->GetEventHandler()->ProcessEvent(okay);
        });
        std::fprintf(stderr, "Opening raw mode dialog\n");
        std::fflush(stderr);
        if (!configure_raw_mapping(frame, request) || !request.raw || request.raw->mode != ExecutionMode::x86_32) {
            fail("Native raw32 choice did not populate request");
            return true;
        }
        frame->OpenDocument(request);
        Bind(wxEVT_TIMER, [this](wxTimerEvent &) {
            try {
                tick();
            } catch (const std::exception &error) {
                fail(error.what());
            }
        });
        timer_.Start(20);
        return true;
    }
    void tick() {
        if (traced != phase) {
            traced = phase;
            std::fprintf(stderr, "Mixed-mode phase %d\n", phase);
            std::fflush(stderr);
        }
        if (++ticks > 1000) {
            fail("Mixed-mode workflow timed out");
            return;
        }
        auto &manager = frame->projects();
        auto active = manager.active_document();
        if (!active || frame->documents().opening())
            return;
        auto project = manager.project(*active);
        if (!project || !fresh(*project))
            return;
        if (phase == 0) {
            first = *active;
            if (!require(mode(ExecutionMode::x86_32) &&
                             project->functions->instructions[0]->instruction.opcode == Opcode::inc &&
                             frame->GetStatusBar()->GetStatusText().Contains("x86-32"),
                         "Raw32 actual facts or mode label mismatch"))
                return;
            for (auto command : {ProjectCommand{Rename{Address{{0}, 0x1000}, "legacy_start"}},
                                 ProjectCommand{Comment{Address{{0}, 0x1000}, "mode comment"}},
                                 ProjectCommand{SetReference{Address{{0}, 0x1000}, Address{{0}, 0x1006},
                                                             UserReferenceKind::code, false}},
                                 ProjectCommand{SetReference{Address{{0}, 0x1000}, Address{{0}, 0x1007},
                                                             UserReferenceKind::code, false}}})
                if (!require(bool(frame->ApplyProjectCommand(command)), "Cannot queue legacy annotation/reference"))
                    return;
            phase = 1;
        } else if (phase == 1) {
            if (project->state->revisions.edit != 4)
                return;
            if (!require(bool(frame->Find(BytePattern{"90"})), "Cannot search legacy input"))
                return;
            phase = 2;
        } else if (phase == 2) {
            if (frame->FindPending())
                return;
            auto *results = table("search-results");
            if (!results || results->GetItemCount() != 2)
                return;
            results->SetItemState(1, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED,
                                  wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
            if (!require(frame->documents().selection() == Location{Address{{0}, 0x1006}},
                         "Nonfirst legacy search result navigated incorrectly"))
                return;
            frame->Navigate(Address{{0}, 0x1000});
            auto *refs = table("references");
            if (!require(refs && refs->GetItemCount() == 2, "Legacy explicit references missing"))
                return;
            const auto target = refs->GetItemText(1, 1);
            refs->SetItemState(1, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED,
                               wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
            if (!require(frame->documents().selection() ==
                             Location{Address{{0}, target.Contains("1006") ? 0x1006ULL : 0x1007ULL}},
                         "Nonfirst legacy reference navigated incorrectly"))
                return;
            frame->Navigate(Address{{0}, 0x1000});
            phase = 3;
        } else if (phase == 3) {
            auto *canvas = dynamic_cast<GraphCanvas *>(wxWindow::FindWindowByName("graph-canvas", frame));
            auto graph = canvas ? canvas->graph() : nullptr;
            if (!graph || !project_graph_current(*project, *graph))
                return;
            auto node = std::find_if(graph->model->nodes.begin(), graph->model->nodes.end(),
                                     [](auto &n) { return n.selection == Location{Address{{0}, 0x1006}}; });
            if (!require(node != graph->model->nodes.end(), "Legacy graph lost nonfirst block"))
                return;
            auto position = std::find_if(graph->layout->positions.begin(), graph->layout->positions.end(),
                                         [&](auto &p) { return p.node == node->id; });
            if (!require(position != graph->layout->positions.end(), "Legacy graph node has no position"))
                return;
            canvas->fit();
            wxMouseEvent click(wxEVT_LEFT_DOWN);
            click.SetPosition(canvas->to_client({position->bounds.x + 10, position->bounds.y + 10}));
            canvas->GetEventHandler()->ProcessEvent(click);
            if (!require(frame->documents().selection() == Location{Address{{0}, 0x1006}},
                         "Legacy graph click did not navigate"))
                return;
            if (!require(bool(frame->SaveProjectAs(saved)), "Legacy Save As failed"))
                return;
            phase = 4;
        } else if (phase == 4) {
            if (!manager.actor(first)->view().project_path)
                return;
            auto other = request;
            other.raw->architecture = Architecture::x86_64;
            other.raw->mode = ExecutionMode::x86_64;
            frame->OpenDocument(other);
            phase = 5;
        } else if (phase == 5) {
            if (*active == first)
                return;
            second = *active;
            if (!require(mode(ExecutionMode::x86_64) &&
                             project->functions->instructions[0]->instruction.opcode == Opcode::jcc &&
                             project->functions->instructions[0]->instruction.length == 3 &&
                             frame->GetStatusBar()->GetStatusText().Contains("x86-64"),
                         "Second tab did not decode identical bytes in long mode"))
                return;
            long_snapshot = project;
            long_selection = frame->documents().selection();
            hooked = manager.actor(first)->view().session;
            auto held = gate;
            workspace_testing::set_actor_hook(hooked, [held](const workspace_testing::ActorCheckpoint &point) {
                if (point.phase == workspace_testing::ActorPhase::analysis_computed && point.source &&
                    point.source->byte_revision == 1 && !held->claimed.exchange(true)) {
                    held->entered.set_value(true);
                    held->released.acquire();
                }
            });
            frame->ActivateDocument(first);
            if (!require(bool(frame->ApplyProjectCommand(PatchBytes{FileOffset{0}, bytes({0x48})})),
                         "Cannot queue legacy INC-to-DEC patch"))
                return;
            frame->ActivateDocument(second);
            phase = 6;
        } else if (phase == 6) {
            if (gate->reached.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
                return;
            gate->open();
            auto legacy = manager.project(first);
            if (!legacy || !fresh(*legacy) || legacy->state->revisions.bytes != 1)
                return;
            if (!require(*active == second && project->functions == long_snapshot->functions &&
                             frame->documents().selection() == long_selection && mode(ExecutionMode::x86_64),
                         "Late legacy completion changed long-mode tab"))
                return;
            frame->ActivateDocument(first);
            phase = 7;
        } else if (phase == 7) {
            if (project->state->revisions.bytes != 1)
                return;
            if (!require(project->functions->instructions[0]->instruction.opcode == Opcode::dec &&
                             presentation_name(*project, Address{{0}, 0x1000}) == "legacy_start" &&
                             annotation_at(*project, Address{{0}, 0x1000})->comment == "mode comment",
                         "Legacy patched facts or annotations lost"))
                return;
            send(wxID_UNDO);
            phase = 8;
        } else if (phase == 8) {
            if (project->state->revisions.edit != 6)
                return;
            if (!require(project->functions->instructions[0]->instruction.opcode == Opcode::inc,
                         "Legacy undo did not restore INC"))
                return;
            send(wxID_REDO);
            phase = 9;
        } else if (phase == 9) {
            if (project->state->revisions.edit != 7)
                return;
            if (!require(project->functions->instructions[0]->instruction.opcode == Opcode::dec &&
                             bool(frame->ExportBinary(exported)),
                         "Legacy redo/export failed"))
                return;
            phase = 10;
        } else if (phase == 10) {
            if (!std::filesystem::exists(exported))
                return;
            auto source = FileStorage::open(exported).value();
            auto view = source->read_at({0}, 8).value();
            if (!require(std::vector<std::byte>(view.bytes.begin(), view.bytes.end()) ==
                             bytes({0x48, 0x74, 3, 0x90, 0xeb, 1, 0x90, 0xc3}),
                         "Legacy export differs from actual patched bytes"))
                return;
            if (!require(bool(manager.close(first)), "Cannot close legacy writer before readonly reopen"))
                return;
            frame->OpenProject(saved, database::ProjectMode::read_only);
            phase = 11;
        } else if (phase == 11) {
            if (*active == first || *active == second)
                return;
            if (!require(mode(ExecutionMode::x86_32) && project->mode == database::ProjectMode::read_only &&
                             project->state->revisions.edit == 7 &&
                             project->functions->instructions[0]->instruction.opcode == Opcode::dec &&
                             presentation_name(*project, Address{{0}, 0x1000}) == "legacy_start",
                         "Legacy readonly reopen lost mode/history/bytes"))
                return;
            frame->Navigate(Address{{0}, 0x1000});
            if (!require(capture("x86-mode-normal.png"), "Cannot capture normal legacy view"))
                return;
            frame->SetSize(800, 600);
            phase = 12;
        } else {
            auto *listing = table("disassembly");
            const bool captured = capture("x86-mode-compact.png");
            if (!listing || listing->GetCountPerPage() < 4 ||
                !frame->GetStatusBar()->GetStatusText().Contains("x86-32"))
                std::fprintf(stderr, "Compact rows=%d status=%s\n", listing ? listing->GetCountPerPage() : -1,
                             frame->GetStatusBar()->GetStatusText().utf8_str().data());
            if (!require(listing && listing->GetCountPerPage() >= 4 &&
                             frame->GetStatusBar()->GetStatusText().Contains("x86-32") && captured,
                         "Compact legacy view is unreadable or could not be captured"))
                return;
            result = 0;
            timer_.Stop();
            workspace_testing::clear_actor_hook(hooked);
            frame->CloseAllDocuments();
            frame->Close();
        }
    }
    int OnRun() override {
        wxApp::OnRun();
        return result;
    }
    int OnExit() override {
        gate->open();
        workspace_testing::clear_actor_hook(hooked);
        std::error_code ignored;
        for (auto suffix : {L"", L"-wal", L"-shm"}) {
            auto path = saved;
            path += suffix;
            std::filesystem::remove(path, ignored);
        }
        std::filesystem::remove(exported, ignored);
        return wxApp::OnExit();
    }
};
} // namespace
wxIMPLEMENT_APP(ModeApp);
