#include "main_frame.hpp"
#include "support/desktop_test_window.hpp"
#include "data_views.hpp"
#include "support/elf_ui_fixture.hpp"
#include "support/pe_fixture.hpp"
#include "support/fixture_files.hpp"
#include "project_testing.hpp"
#include <wx/app.h>
#include <wx/timer.h>
#include <wx/notebook.h>
#include <wx/textctrl.h>
#include <wx/dialog.h>
#include <wx/dcmemory.h>
#include <wx/image.h>
#include <wx/msw/wrapwin.h>
#include <cstdio>
#include <semaphore>
using namespace hexlab;
using namespace hexlab::desktop;
using namespace hexlab_test;
namespace {
class ElfApp final : public wxApp {
    wxTimer timer_{this};
    MainFrame *frame = nullptr;
    std::unique_ptr<FixtureFile> input;
    int phase = 0, ticks = 0, result = 1;
    DocumentId first{0};
    DocumentId executable{0}, mixed{0};
    std::filesystem::path saved, exported;
    std::unique_ptr<FixtureFile> profile;
    std::shared_ptr<const database::ProjectState> saved_state;
    std::shared_ptr<const ProjectSnapshot> mixed_snapshot;
    std::optional<Location> mixed_selection;
    SessionKey hooked;
    struct Gate {
        std::atomic<bool> claimed = false, opened = false;
        std::promise<bool> entered;
        std::shared_future<bool> reached = entered.get_future().share();
        std::binary_semaphore released{0};
        void release() {
            if (!opened.exchange(true))
                released.release();
        }
    };
    std::shared_ptr<Gate> gate = std::make_shared<Gate>();
    void send(int command) {
        wxCommandEvent event(wxEVT_MENU, command);
        frame->GetEventHandler()->ProcessEvent(event);
    }
    void select(VirtualTable *target, long row) {
        target->SetItemState(row, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED,
                             wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
    }
    void jump(const wxString &value) {
        CallAfter([value] {
            auto *field = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("location-value"));
            auto *dialog = field ? dynamic_cast<wxDialog *>(field->GetParent()) : nullptr;
            if (!field || !dialog)
                throw std::runtime_error("Native jump dialog missing");
            field->SetValue(value);
            wxCommandEvent accepted(wxEVT_BUTTON, wxID_OK);
            dialog->GetEventHandler()->ProcessEvent(accepted);
        });
        send(jump_id);
    }
    bool require(bool ok, const char *why) {
        if (!ok) {
            std::fprintf(stderr, "ELF phase%d: %s\n", phase, why);
            timer_.Stop();
            gate->release();
            workspace_testing::clear_actor_hook(hooked);
            frame->CloseAllDocuments();
            frame->Close();
        }
        return ok;
    }
    VirtualTable *table(const char *name) {
        return dynamic_cast<VirtualTable *>(wxWindow::FindWindowByName(name, frame));
    }
    void open(std::vector<std::byte> data, Format format = Format::automatic) {
        input = std::make_unique<FixtureFile>(data);
        OpenRequest request;
        request.path = input->path;
        request.format = format;
        frame->OpenDocument(request);
    }
    bool capture(const char *name) {
        auto path = std::filesystem::current_path() / "artifacts" / name;
        std::filesystem::create_directories(path.parent_path());
        auto handle = reinterpret_cast<HWND>(frame->GetHandle());
        frame->Refresh();
        frame->Update();
        auto size = frame->GetSize();
        wxBitmap bitmap(size.x, size.y, 24);
        wxMemoryDC target(bitmap);
        RedrawWindow(handle, nullptr, nullptr,
                     RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW | RDW_ALLCHILDREN | RDW_FRAME);
        bool copied = PrintWindow(handle, reinterpret_cast<HDC>(target.GetHDC()), 0) != 0;
        target.SelectObject(wxNullBitmap);
        return copied && bitmap.SaveFile(wxString(path.wstring()), wxBITMAP_TYPE_PNG);
    }
    void tick() {
        if (!require(++ticks < 1200, "workflow timed out"))
            return;
        auto id = frame->projects().active_document();
        if (!id || frame->documents().opening())
            return;
        auto project = frame->projects().project(*id);
        if (!project || !project->loaded)
            return;
        if (phase != 20 && (!project->functions ||
                            (project->status != DerivedStatus::fresh && project->status != DerivedStatus::incomplete)))
            return;
        auto *symbols = table("symbols");
        if (phase == 0) {
            first = *id;
            jump("va:1:0x0");
            if (!require(frame->documents().selection() == Location{Address{{1}, 0}},
                         "qualified ELF domain Jump cannot navigate from initial file view"))
                return;
            jump("va:4294967296:0");
            if (!require(frame->documents().selection() == Location{Address{{1}, 0}},
                         "overflowed explicit Jump domain changed selection"))
                return;
            if (!require(project->state->recipe.format == Format::elf && symbols && symbols->GetItemCount() == 5,
                         "native REL32 symbols missing"))
                return;
            if (!require(symbols->GetItemText(1, 1) == "callee" && symbols->GetItemText(1, 0) == "va:2:0x0",
                         "ELF symbol row identity or section domain lost"))
                return;
            select(symbols, 1);
            if (!require(frame->documents().selection() == Location{Address{{2}, 0}},
                         "nonfirst ELF symbol did not navigate to its section domain"))
                return;
            select(symbols, 2);
            if (!require(frame->documents().selection() == Location{FileOffset{1056}},
                         "undefined ELF symbol did not inspect its exact physical record"))
                return;
            select(symbols, 4);
            if (!require(frame->documents().selection() == Location{Address{{1}, 0}},
                         "same-offset caller domain was confused with callee"))
                return;
            wxCommandEvent follow(wxEVT_MENU, follow_id);
            frame->GetEventHandler()->ProcessEvent(follow);
            if (!require(frame->documents().selection() == Location{Address{{2}, 0}},
                         "native Follow lost original ELF relocation target"))
                return;
            frame->Navigate(Address{{1}, 0});
            if (!require(bool(frame->ApplyProjectCommand(
                             SetReference{Address{{1}, 0}, Address{{1}, 5}, UserReferenceKind::code, false})) &&
                             bool(frame->ApplyProjectCommand(
                                 SetReference{Address{{1}, 0}, Address{{2}, 1}, UserReferenceKind::code, false})),
                         "cannot queue ELF explicit reference rows"))
                return;
            phase = 100;
        } else if (phase == 100) {
            auto *references = table("references");
            if (project->state->revisions.edit != 2 || !references || references->GetItemCount() != 3)
                return;
            const auto target = references->GetItemText(1, 1);
            select(references, 1);
            const auto expected = target == "va:1:0x5"   ? Address{{1}, 5}
                                  : target == "va:2:0x1" ? Address{{2}, 1}
                                                         : Address{{2}, 0};
            if (!require(frame->documents().selection() == Location{expected},
                         "nonfirst ELF reference selection changed its domain"))
                return;
            frame->Navigate(Address{{2}, 0});
            phase = 1;
            open(elf_ui_fixture::object(true), Format::elf);
        } else if (phase == 1) {
            if (*id == first)
                return;
            if (!require(symbols && symbols->GetItemCount() == 5 &&
                             project->loaded->image->decode_context().mode == ExecutionMode::x86_64,
                         "explicit native REL64 not opened"))
                return;
            select(symbols, 2);
            if (!require(frame->documents().selection() == Location{FileOffset{1072}},
                         "ELF64 physical symbol stride lost"))
                return;
            frame->ActivateDocument(first);
            phase = 2;
        } else if (phase == 2) {
            if (*id != first)
                return;
            if (!require(frame->documents().selection() == Location{Address{{2}, 0}},
                         "ELF tab switch lost domain-specific selection"))
                return;
            phase = 3;
            open(elf_ui_fixture::dynamic(false));
        } else if (phase == 3) {
            if (project->loaded->metadata.elf->header.object_type != 3)
                return;
            auto *dynamic = table("elf-dynamic");
            auto *programs = table("elf-programs");
            if (!require(symbols && symbols->GetItemCount() == 3 && dynamic && dynamic->GetItemCount() == 10 &&
                             programs && programs->GetItemCount() >= 3,
                         "sectionless dynamic metadata missing in actual native controls"))
                return;
            if (!require(dynamic->GetItemText(6, 1) == "NEEDED" && dynamic->GetItemText(6, 2) == "libfixture.so",
                         "native dynamic metadata lost declared NEEDED string"))
                return;
            phase = 4;
            open(elf_ui_fixture::dynamic(true, true));
        } else if (phase == 4) {
            if (project->loaded->metadata.elf->header.object_type != 2)
                return;
            select(symbols, 1);
            if (!require(frame->documents().selection() == Location{Address{{0}, UINT64_C(0x100000100)}},
                         "EXEC64 symbol address truncated"))
                return;
            executable = *id;
            saved = input->path.wstring() + L".elf.hxproj";
            exported = input->path.wstring() + L".patched.elf";
            for (auto command : {ProjectCommand{Rename{Address{{0}, UINT64_C(0x100000100)}, "elf_entry"}},
                                 ProjectCommand{Comment{Address{{0}, UINT64_C(0x100000100)}, "native ELF edit"}},
                                 ProjectCommand{PatchBytes{FileOffset{256}, bytes({0xcc})}}})
                if (!require(bool(frame->ApplyProjectCommand(command)), "cannot queue native ELF edit"))
                    return;
            phase = 5;
        } else if (phase == 5) {
            if (project->state->revisions.edit != 3)
                return;
            if (!require(project->effective->read_at({256}, 1).value().bytes[0] == std::byte{0xcc} &&
                             presentation_name(*project, Address{{0}, UINT64_C(0x100000100)}) == "elf_entry",
                         "native ELF edit facts not published"))
                return;
            send(wxID_UNDO);
            phase = 6;
        } else if (phase == 6) {
            if (project->state->revisions.edit != 4)
                return;
            if (!require(project->effective->read_at({256}, 1).value().bytes[0] == std::byte{0x90},
                         "native ELF Undo lost original instruction"))
                return;
            send(wxID_REDO);
            phase = 7;
        } else if (phase == 7) {
            if (project->state->revisions.edit != 5)
                return;
            saved_state = project->state;
            if (!require(project->effective->read_at({256}, 1).value().bytes[0] == std::byte{0xcc} &&
                             bool(frame->SaveProjectAs(saved)),
                         "native ELF Redo or Save As failed"))
                return;
            phase = 8;
        } else if (phase == 8) {
            if (!frame->projects().actor(*id)->view().project_path)
                return;
            if (project->state->uuid == saved_state->uuid)
                return;
            saved_state = project->state;
            if (!require(bool(frame->ExportBinary(exported)), "native ELF export failed"))
                return;
            phase = 9;
        } else if (phase == 9) {
            if (!std::filesystem::exists(exported))
                return;
            auto expected = elf_ui_fixture::dynamic(true, true);
            expected[256] = std::byte{0xcc};
            auto file = FileStorage::open(exported);
            if (!require(bool(file), "native ELF export cannot be reopened"))
                return;
            auto view = file.value()->read_at({0}, expected.size());
            if (!require(view && std::ranges::equal(view.value().bytes, expected),
                         "native ELF export changed bytes beyond exact patch"))
                return;
            if (!require(std::filesystem::remove(input->path), "native ELF source could not be removed"))
                return;
            if (!require(bool(frame->projects().close(*id)), "native ELF saved tab cannot close"))
                return;
            frame->OpenProject(saved, database::ProjectMode::read_only);
            phase = 10;
        } else if (phase == 10) {
            if (project->mode != database::ProjectMode::read_only)
                return;
            if (!require(project->state->uuid == saved_state->uuid &&
                             project->state->revisions == saved_state->revisions &&
                             *project->state->user == *saved_state->user && project->loaded->metadata.elf &&
                             project->effective->read_at({256}, 1).value().bytes[0] == std::byte{0xcc},
                         "source-missing native ELF reopen lost history metadata or patches"))
                return;
            auto *dynamic = table("elf-dynamic");
            auto *notebook = dynamic ? dynamic_cast<wxNotebook *>(dynamic->GetParent()) : nullptr;
            if (!require(notebook != nullptr, "ELF metadata notebook missing"))
                return;
            notebook->SetSelection(notebook->FindPage(dynamic));
            frame->Navigate(Address{{0}, UINT64_C(0x100000100)});
            phase = 11;
        } else if (phase == 11) {
            if (!require(capture("elf-normal.png"), "normal own-window capture failed"))
                return;
            frame->SetSize(900, 620);
            phase = 12;
        } else if (phase == 12) {
            table("elf-dynamic")->EnsureVisible(8);
            if (!require(capture("elf-compact.png"), "compact own-window capture failed"))
                return;
            open(pe_metadata_fixture());
            phase = 13;
        } else if (phase == 13) {
            if (project->loaded->metadata.elf)
                return;
            if (!require(project->state->recipe.format == Format::pe &&
                             symbols->GetItemCount() == static_cast<long>(project->loaded->metadata.exports.size()) &&
                             table("elf-dynamic")->GetItemCount() == 0 && table("elf-programs")->GetItemCount() == 0,
                         "PE tab retained stale ELF symbols or metadata rows"))
                return;
            const std::string text = "hexlab-x86-profile 1\nenvironment real386\na20 enabled\nload 0x10000\nentry 7 "
                                     "0\nstack none\ndomains 1\ndomain 7 0x1000 code \"code\" real\n";
            profile = std::make_unique<FixtureFile>(std::as_bytes(std::span(text)));
            input = std::make_unique<FixtureFile>(bytes({0x90, 0xc3}));
            OpenRequest request;
            request.path = input->path;
            request.format = Format::raw;
            request.x86_profile_path = profile->path;
            frame->OpenDocument(request);
            phase = 14;
        } else if (phase == 14) {
            if (!project->loaded->image->layout().x86_profile)
                return;
            mixed = *id;
            mixed_snapshot = project;
            mixed_selection = frame->documents().selection();
            hooked = frame->projects().actor(first)->view().session;
            auto hold = gate;
            workspace_testing::set_actor_hook(hooked, [hold](const auto &point) {
                if (point.phase == workspace_testing::ActorPhase::analysis_computed && point.source &&
                    point.source->byte_revision == 1 && !hold->claimed.exchange(true)) {
                    hold->entered.set_value(true);
                    hold->released.acquire();
                }
            });
            frame->ActivateDocument(first);
            if (!require(bool(frame->ApplyProjectCommand(PatchBytes{FileOffset{261}, bytes({0xcc})})),
                         "cannot queue background ELF patch"))
                return;
            frame->ActivateDocument(mixed);
            phase = 15;
        } else if (phase == 15) {
            if (gate->reached.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
                return;
            gate->release();
            phase = 16;
        } else if (phase == 16) {
            auto background = frame->projects().project(first);
            if (!background || !background->functions || background->state->revisions.bytes != 1 ||
                (background->status != DerivedStatus::fresh && background->status != DerivedStatus::incomplete))
                return;
            if (!require(*id == mixed && project->functions == mixed_snapshot->functions &&
                             frame->documents().selection() == mixed_selection &&
                             project->loaded->image->layout().x86_profile,
                         "late ELF analysis completion changed segmented tab facts or selection"))
                return;
            frame->ActivateDocument(first);
            phase = 17;
        } else if (phase == 17) {
            if (*id != first)
                return;
            if (!require(project->effective->read_at({261}, 1).value().bytes[0] == std::byte{0xcc} &&
                             project->references->outgoing(Address{{1}, 0}, {}).value().total == 3,
                         "background ELF facts or original-domain references lost"))
                return;
            workspace_testing::clear_actor_hook(hooked);
            open(elf_ui_fixture::dynamic(true));
            phase = 18;
        } else if (phase == 18) {
            if (!project->loaded->metadata.elf || project->loaded->metadata.elf->header.object_type != 3)
                return;
            if (!require(project->loaded->metadata.elf->header.is_64 && symbols->GetItemCount() == 3,
                         "native sectionless DYN64 not opened"))
                return;
            open(elf_ui_fixture::dynamic(false, true));
            phase = 19;
        } else if (phase == 19) {
            if (!project->loaded->metadata.elf || project->loaded->metadata.elf->header.object_type != 2)
                return;
            if (!require(!project->loaded->metadata.elf->header.is_64 && symbols->GetItemCount() == 3,
                         "native EXEC32 not opened"))
                return;
            open(elf_ui_fixture::dynamic(true, false, true), Format::elf);
            phase = 20;
        } else if (phase == 20) {
            if (!project->loaded->metadata.elf || project->loaded->metadata.elf->header.order != ByteOrder::big ||
                frame->projects().actor(*id)->view().analysis_pending)
                return;
            if (!require(!project->functions &&
                             !processor_capabilities(project->loaded->image->decode_context()).can_decode &&
                             symbols->GetItemCount() == 3 && table("elf-programs")->GetItemText(0, 0).Contains("big"),
                         "unsupported native endian context invented decoder facts or hid metadata"))
                return;
            open(elf_dynamic_symbol_fixture::fixture(true, false, 4), Format::elf);
            phase = 21;
        } else if (phase == 21) {
            auto *tables = table("elf-tables");
            if (!require(symbols->GetItemCount() == 0 && tables && tables->GetItemCount() == 1 &&
                             tables->GetItemText(0, 1) == "unavailable",
                         "unbounded native symbol table hides its unknown count or invents symbols"))
                return;
            result = 0;
            timer_.Stop();
            frame->CloseAllDocuments();
            frame->Close();
        }
    }

  public:
    bool OnInit() override {
        wxInitAllImageHandlers();
        wxSetAssertHandler([](const wxString &, int, const wxString &, const wxString &, const wxString &message) {
            std::fprintf(stderr, "wx assertion: %s\n", message.utf8_str().data());
            std::_Exit(4);
        });
        frame = new MainFrame;
        show_test_window(frame);
        open(elf_ui_fixture::object(false));
        Bind(wxEVT_TIMER, [this](wxTimerEvent &) { tick(); });
        timer_.Start(25);
        return true;
    }
    int OnRun() override {
        wxApp::OnRun();
        return result;
    }
    int OnExit() override {
        gate->release();
        workspace_testing::clear_actor_hook(hooked);
        std::error_code ignored;
        for (auto path : {saved, exported})
            if (!path.empty())
                for (auto suffix : {L"", L"-wal", L"-shm"}) {
                    auto file = path;
                    file += suffix;
                    std::filesystem::remove(file, ignored);
                }
        return wxApp::OnExit();
    }
};
} // namespace
wxIMPLEMENT_APP(ElfApp);
