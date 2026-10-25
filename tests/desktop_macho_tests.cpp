#include "main_frame.hpp"
#include "support/desktop_test_window.hpp"
#include "data_views.hpp"
#include "support/macho_relocation_fixture.hpp"
#include "support/macho_chained_fixture.hpp"
#include "hexlab/workspace/macho_presentation.hpp"
#include "project_testing.hpp"
#include <semaphore>
#include "support/fixture_files.hpp"
#include "support/pe_fixture.hpp"
#include <algorithm>
#include <wx/app.h>
#include <wx/timer.h>
#include <wx/button.h>
#include <wx/textctrl.h>
#include <wx/notebook.h>
#include <wx/dcmemory.h>
#include <wx/image.h>
#include <wx/msw/wrapwin.h>
#include <cstdio>
using namespace hexlab;
using namespace hexlab::desktop;
using namespace hexlab_test;
namespace {
class MachOApp final : public wxApp {
    wxTimer timer_{this};
    MainFrame *frame = nullptr;
    std::unique_ptr<FixtureFile> input;
    int ticks = 0, phase = 0, result = 1;
    DocumentId fat{0}, reopened{0}, mixed{0}, background{0};
    SessionKey hooked{};
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
    std::shared_ptr<const ProjectSnapshot> mixed_snapshot;
    std::optional<Location> mixed_selection;
    std::shared_ptr<const ProjectSnapshot> pinned;
    std::shared_ptr<const database::ProjectState> saved_state;
    std::filesystem::path saved, exported;
    std::vector<std::byte> fat_bytes;
    void send(int command) {
        wxCommandEvent event(wxEVT_MENU, command);
        frame->GetEventHandler()->ProcessEvent(event);
    }
    void select(VirtualTable *table, long row) {
        table->SetItemState(row, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED,
                            wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
    }
    void open(std::vector<std::byte> bytes) {
        input = std::make_unique<FixtureFile>(bytes);
        OpenRequest request;
        request.path = input->path;
        frame->OpenDocument(request);
    }
    std::vector<std::byte> universal() {
        auto narrow = macho_fixture::symbols(false);
        auto wide = macho_fixture::symbols(true);
        std::vector<std::byte> bytes(12288);
        const auto put = [&](std::size_t at, std::uint64_t v, std::size_t size) {
            macho_fixture::put(bytes, at, v, size, true);
        };
        put(0, 0xcafebabe, 4);
        put(4, 2, 4);
        for (unsigned n = 0; n < 2; ++n) {
            const auto at = 8 + n * 20;
            put(at, n ? 0x01000007 : 7, 4);
            put(at + 4, 0x80000003, 4);
            put(at + 8, n ? 8192 : 4096, 4);
            put(at + 12, 4096, 4);
            put(at + 16, 12, 4);
        }
        std::copy(narrow.begin(), narrow.end(), bytes.begin() + 4096);
        std::copy(wide.begin(), wide.end(), bytes.begin() + 8192);
        return bytes;
    }
    bool capture(const char *name) {
        auto path = std::filesystem::current_path() / "artifacts" / name;
        std::filesystem::create_directories(path.parent_path());
        const auto hwnd = reinterpret_cast<HWND>(frame->GetHandle());
        // CMake's child startup state can hide the first wx Show(). Render this
        // owned window explicitly without activating it or touching other apps.
        ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW);
        frame->Refresh();
        frame->Update();
        RedrawWindow(hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW | RDW_ALLCHILDREN | RDW_FRAME);
        const auto size = frame->GetSize();
        wxBitmap bitmap(size.x, size.y, 24);
        wxMemoryDC target(bitmap);
        const bool copied = PrintWindow(hwnd, reinterpret_cast<HDC>(target.GetHDC()), 0) != 0;
        target.SelectObject(wxNullBitmap);
        const auto pixels = bitmap.ConvertToImage();
        if (!copied || !pixels.IsOk())
            return false;
        std::size_t lit = 0, samples = 0;
        const auto *rgb = pixels.GetData();
        for (int y = 0; y < pixels.GetHeight(); y += 16)
            for (int x = 0; x < pixels.GetWidth(); x += 16) {
                const auto index = 3 * (static_cast<std::size_t>(y) * pixels.GetWidth() + x);
                ++samples;
                if (rgb[index] > 32 || rgb[index + 1] > 32 || rgb[index + 2] > 32)
                    ++lit;
            }
        if (lit <= samples / 10) {
            std::fprintf(stderr, "Blank own-window capture: lit=%zu/%zu visible=%d iconic=%d\n", lit, samples,
                         IsWindowVisible(hwnd) != 0, IsIconic(hwnd) != 0);
            return false;
        }
        return bitmap.SaveFile(wxString(path.wstring()), wxBITMAP_TYPE_PNG);
    }
    bool require(bool ok, const char *why) {
        if (!ok) {
            std::fprintf(stderr, "Mach-O native phase%d: %s\n", phase, why);
            timer_.Stop();
            gate->release();
            workspace_testing::clear_actor_hook(hooked);
            frame->CloseAllDocuments();
            frame->Close();
        }
        return ok;
    }
    void tick() {
        if (!require(++ticks < 600, "workflow timed out"))
            return;
        const auto id = frame->projects().active_document();
        if (!id || frame->documents().opening())
            return;
        const auto project = frame->projects().project(*id);
        if (!project || !project->loaded || (!project->functions && phase != 17) ||
            project->status == DerivedStatus::pending)
            return;
        auto *symbols = dynamic_cast<VirtualTable *>(wxWindow::FindWindowByName("symbols", frame));
        auto *metadata = dynamic_cast<VirtualTable *>(wxWindow::FindWindowByName("macho-metadata", frame));
        auto *button = dynamic_cast<wxButton *>(wxWindow::FindWindowByName("macho-open-slice", frame));
        if (!require(symbols && metadata && button, "native controls absent"))
            return;
        if (phase == 100) {
            if (project->state->revisions.edit != 2)
                return;
            auto *references = dynamic_cast<VirtualTable *>(wxWindow::FindWindowByName("references", frame));
            if (!references || references->GetItemCount() != 3)
                return;
            const auto target = references->GetItemText(1, 1);
            const auto expected = target == "va:1:0x5"   ? Address{{1}, 5}
                                  : target == "va:2:0x1" ? Address{{2}, 1}
                                                         : Address{{2}, 0};
            select(references, 1);
            if (!require(frame->documents().selection() == Location{expected},
                         "nonfirst native reference lost target domain"))
                return;
            fat_bytes = universal();
            open(fat_bytes);
            phase = 1;
            return;
        }
        if (phase == 1) {
            if (!require(project->loaded->metadata.macho->selected_slice == 1, "default nonfirst slice lost"))
                return;
            fat = *id;
            pinned = project;
            select(metadata, 1);
            if (!require(button->IsEnabled() && frame->documents().selection() == Location{FileOffset{4096}},
                         "slice row did not select original source"))
                return;
            wxCommandEvent press(wxEVT_BUTTON, button->GetId());
            button->GetEventHandler()->ProcessEvent(press);
            phase = 2;
            return;
        }
        if (phase == 2) {
            if (*id == fat)
                return;
            if (!require(project->loaded->metadata.macho->selected_slice == 0 &&
                             project->loaded->image->decode_context().mode == ExecutionMode::x86_32 &&
                             encode_recipe(frame->projects().project(fat)->state->recipe).value() ==
                                 encode_recipe(pinned->state->recipe).value() &&
                             frame->projects().project(fat)->state->uuid == pinned->state->uuid,
                         "opening original slice changed saved selection or project identity"))
                return;
            frame->ActivateDocument(fat);
            phase = 3;
            return;
        }
        if (phase == 3) {
            if (*id != fat)
                return;
            select(symbols, 2);
            if (!require(frame->documents().selection() == Location{FileOffset{9760}},
                         "universal symbol source offset/stride lost"))
                return;
            for (auto command : {ProjectCommand{Rename{Address{{1}, 0}, "native_macho"}},
                                 ProjectCommand{Comment{FileOffset{10241}, "original nlist name"}},
                                 ProjectCommand{PatchBytes{FileOffset{10241}, bytes({0x58})}}})
                if (!require(bool(frame->ApplyProjectCommand(command)), "cannot queue native edit"))
                    return;
            phase = 4;
            return;
        }
        if (phase == 4) {
            if (project->state->revisions.edit != 3)
                return;
            if (!require(presentation_name(*project, Address{{1}, 0}) == "native_macho" &&
                             presentation_name(*project, Address{{2}, 0}) == "Xsame",
                         "native metadata edit/name ownership lost"))
                return;
            send(wxID_UNDO);
            phase = 5;
            return;
        }
        if (phase == 5) {
            if (project->state->revisions.edit != 4)
                return;
            if (!require(presentation_name(*project, Address{{2}, 0}) == "_same", "native undo lost original metadata"))
                return;
            send(wxID_REDO);
            phase = 6;
            return;
        }
        if (phase == 6) {
            if (project->state->revisions.edit != 5)
                return;
            saved = input->path.wstring() + L".macho.hxproj";
            exported = input->path.wstring() + L".patched.macho";
            if (!require(bool(frame->SaveProjectAs(saved)), "native Save As failed"))
                return;
            phase = 7;
            return;
        }
        if (phase == 7) {
            if (!frame->projects().actor(*id)->view().project_path || project->state->uuid == pinned->state->uuid)
                return;
            saved_state = project->state;
            if (!require(bool(frame->ExportBinary(exported)), "native export failed"))
                return;
            phase = 8;
            return;
        }
        if (phase == 8) {
            if (!std::filesystem::exists(exported))
                return;
            auto storage = FileStorage::open(exported);
            if (!require(bool(storage) && storage.value()->size() == fat_bytes.size(), "universal export size changed"))
                return;
            auto exported_bytes = storage.value()->read_at({0}, fat_bytes.size());
            auto expected = fat_bytes;
            expected[10241] = std::byte{0x58};
            if (!require(bool(exported_bytes) &&
                             std::equal(expected.begin(), expected.end(), exported_bytes.value().bytes.begin()),
                         "universal export changed bytes outside patch"))
                return;
            auto original = FileStorage::open(input->path);
            auto original_bytes = original.value()->read_at({0}, fat_bytes.size());
            if (!require(std::equal(fat_bytes.begin(), fat_bytes.end(), original_bytes.value().bytes.begin()),
                         "native edits modified original source"))
                return;
            original.value().reset();
            input.reset();
            frame->CloseAllDocuments();
            frame->OpenProject(saved, database::ProjectMode::read_only);
            phase = 9;
            return;
        }
        if (phase == 9) {
            if (project->mode != database::ProjectMode::read_only)
                return;
            if (!require(project->state->uuid == saved_state->uuid &&
                             project->state->revisions == saved_state->revisions &&
                             *project->state->user == *saved_state->user &&
                             project->loaded->metadata.macho->selected_slice == 1 &&
                             presentation_name(*project, Address{{2}, 0}) == "Xsame",
                         "source-missing native reopen lost saved identity/history/slice"))
                return;
            reopened = *id;
            auto *panel = metadata->GetParent();
            auto *notebook = dynamic_cast<wxNotebook *>(panel->GetParent());
            if (!require(notebook != nullptr, "Mach-O notebook missing"))
                return;
            notebook->SetSelection(notebook->FindPage(panel));
            select(metadata, 0);
            auto *details = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("macho-record-details", frame));
            if (!require(details && details->GetValue().Contains("cpu=0x1000007") &&
                             details->GetValue().Contains("selected=1"),
                         "selected header details lost full CPU word or saved slice"))
                return;
            frame->SetSize(1280, 900);
            phase = 10;
            return;
        }
        if (phase == 10) {
            if (!require(capture("macho-normal.png"), "normal own-window capture failed"))
                return;
            frame->SetSize(900, 620);
            phase = 11;
            return;
        }
        if (phase == 11) {
            if (!require(capture("macho-compact.png"), "compact own-window capture failed"))
                return;
            open(pe_metadata_fixture());
            phase = 12;
            return;
        }
        if (phase == 12) {
            if (project->state->recipe.format != Format::pe)
                return;
            if (!require(metadata->GetItemCount() == 0 && !button->IsEnabled() &&
                             symbols->GetItemCount() == static_cast<long>(project->loaded->metadata.exports.size()),
                         "mixed PE tab retained Mach-O rows/actions"))
                return;
            mixed = *id;
            frame->ActivateDocument(reopened);
            phase = 13;
            return;
        }
        if (phase == 13) {
            if (*id != reopened)
                return;
            if (!require(metadata->GetItemCount() > 9 && symbols->GetItemCount() == 9 &&
                             project->state->uuid == saved_state->uuid,
                         "return to Mach-O tab lost original state"))
                return;
            auto protected_image = macho_fixture::chained();
            macho_fixture::stream(
                protected_image, true, false, 1,
                {0x11, 0x40, '_', 'c', 'l', 'a', 's', 's', 'i', 'c', 0, 0x51, 0x70, 0x90, 6, 0x90, 0});
            const auto crypt = macho_fixture::append_command(protected_image, true, false, 0x2c, 24);
            macho_fixture::put(protected_image, crypt + 8, 1024, 4, false);
            macho_fixture::put(protected_image, crypt + 12, 8, 4, false);
            macho_fixture::put(protected_image, crypt + 16, 1, 4, false);
            const auto dice = macho_fixture::append_command(protected_image, true, false, 0x29, 16);
            macho_fixture::put(protected_image, dice + 8, 3500, 4, false);
            macho_fixture::put(protected_image, dice + 12, 8, 4, false);
            macho_fixture::put(protected_image, 3500, 1040, 4, false);
            macho_fixture::put(protected_image, 3504, 4, 2, false);
            macho_fixture::put(protected_image, 3506, 1, 2, false);
            const auto signature = macho_fixture::append_command(protected_image, true, false, 0x1d, 16);
            macho_fixture::put(protected_image, signature + 8, 3600, 4, false);
            macho_fixture::put(protected_image, signature + 12, 16, 4, false);
            open(protected_image);
            phase = 14;
            return;
        }
        if (phase == 14) {
            if (*id == reopened)
                return;
            bool imported = false, starts = false, pointer = false, dice = false, encrypted = false,
                 signed_bytes = false, classic = false;
            for (std::uint64_t n = 0; n < macho_metadata_row_count(*project); ++n) {
                const auto row = macho_metadata_row_at(*project, n);
                if (row->kind == MachOMetadataKind::chain_import) {
                    select(metadata, static_cast<long>(n));
                    imported = metadata->GetItemText(static_cast<long>(n), 2) == "_ext" &&
                               frame->documents().selection() == Location{row->source};
                }
                if (row->kind == MachOMetadataKind::chain_start)
                    starts = metadata->GetItemText(static_cast<long>(n), 2).Contains("format=0x2");
                if (row->kind == MachOMetadataKind::chain_pointer)
                    pointer = metadata->GetItemText(static_cast<long>(n), 2).Contains("raw=0x");
                if (row->kind == MachOMetadataKind::data_in_code)
                    dice = row->source == FileOffset{3500} &&
                           metadata->GetItemText(static_cast<long>(n), 3).Contains("kind=0x1");
                if (row->kind == MachOMetadataKind::encryption)
                    encrypted = metadata->GetItemText(static_cast<long>(n), 3).Contains("decoding excluded");
                if (row->kind == MachOMetadataKind::signature)
                    signed_bytes =
                        metadata->GetItemText(static_cast<long>(n), 3).Contains("authentication unavailable");
                if (row->kind == MachOMetadataKind::dyld_fixup) {
                    select(metadata, static_cast<long>(n));
                    classic = metadata->GetItemText(static_cast<long>(n), 2).Contains("_classic") &&
                              metadata->GetItemText(static_cast<long>(n), 3).Contains("ordinal=1") &&
                              frame->documents().selection() == Location{row->source};
                }
            }
            if (!require(imported && starts && pointer && dice && encrypted && signed_bytes && classic,
                         "native chained/protection records or original source activation missing"))
                return;
            background = *id;
            hooked = frame->projects().actor(*id)->view().session;
            auto hold = gate;
            workspace_testing::set_actor_hook(hooked, [hold](const auto &point) {
                if (point.phase == workspace_testing::ActorPhase::analysis_computed && point.source &&
                    point.source->byte_revision == 1 && !hold->claimed.exchange(true)) {
                    hold->entered.set_value(true);
                    hold->released.acquire();
                }
            });
            if (!require(bool(frame->ApplyProjectCommand(PatchBytes{FileOffset{2049}, bytes({0x59})})),
                         "cannot queue background metadata edit"))
                return;
            frame->ActivateDocument(mixed);
            mixed_snapshot = frame->projects().project(mixed);
            mixed_selection = frame->documents().selection();
            phase = 15;
            return;
        }
        if (phase == 15) {
            if (gate->reached.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
                return;
            gate->release();
            phase = 16;
            return;
        }
        if (phase == 16) {
            const auto updated = frame->projects().project(background);
            if (!updated || updated->state->revisions.bytes != 1 || !updated->functions ||
                (updated->status != DerivedStatus::fresh && updated->status != DerivedStatus::incomplete))
                return;
            if (!require(*id == mixed && project->loaded == mixed_snapshot->loaded &&
                             project->functions == mixed_snapshot->functions &&
                             frame->documents().selection() == mixed_selection && metadata->GetItemCount() == 0 &&
                             !button->IsEnabled() && updated->loaded->metadata.macho->symbols[0].name == "Ysame",
                         "late Mach-O completion replaced PE metadata, facts, selection or actions"))
                return;
            workspace_testing::clear_actor_hook(hooked);
            open(macho_fixture::symbols(true, true));
            phase = 17;
            return;
        }
        if (phase == 17) {
            if (*id == mixed || frame->projects().actor(*id)->view().analysis_pending)
                return;
            if (!require(!project->functions && project->loaded->metadata.macho &&
                             project->loaded->metadata.macho->container.slices[0].header.order == ByteOrder::big &&
                             metadata->GetItemText(0, 2).Contains("big endian") && symbols->GetItemCount() == 9,
                         "unsupported native endian context hid metadata or invented decoded facts"))
                return;
            result = 0;
            timer_.Stop();
            frame->CloseAllDocuments();
            frame->Close();
            return;
        }
        if (!require(symbols && symbols->GetItemCount() == 9, "original nlist symbols absent"))
            return;
        if (!require(metadata && metadata->GetItemCount() > 9, "indexed metadata absent"))
            return;
        if (!require(wxWindow::FindWindowByName("macho-open-slice", frame) != nullptr,
                     "explicit original-slice opening control absent"))
            return;
        if (!require(symbols->GetItemText(1, 0) == "va:2:0x0", "nonfirst symbol domain lost"))
            return;
        symbols->SetItemState(1, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
        if (!require(frame->documents().selection() == Location{Address{{2}, 0}}, "symbol activation lost domain"))
            return;
        symbols->SetItemState(2, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
        if (!require(frame->documents().selection() == Location{FileOffset{1560}},
                     "undefined symbol source record lost"))
            return;
        frame->Navigate(Address{{1}, 0});
        wxCommandEvent follow(wxEVT_MENU, follow_id);
        frame->GetEventHandler()->ProcessEvent(follow);
        if (!require(frame->documents().selection() == Location{Address{{2}, 0}}, "source-bound Follow lost domain"))
            return;
        frame->Navigate(Address{{1}, 0});
        for (auto command :
             {ProjectCommand{SetReference{Address{{1}, 0}, Address{{1}, 5}, UserReferenceKind::code, false}},
              ProjectCommand{SetReference{Address{{1}, 0}, Address{{2}, 1}, UserReferenceKind::code, false}}})
            if (!require(bool(frame->ApplyProjectCommand(command)), "cannot queue explicit domain references"))
                return;
        phase = 100;
    }

  public:
    bool OnInit() override {
        frame = new MainFrame;
        show_test_window(frame);
        wxInitAllImageHandlers();
        open(macho_fixture::relocated(false));
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
        for (const auto &path : {saved, exported})
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
wxIMPLEMENT_APP(MachOApp);
