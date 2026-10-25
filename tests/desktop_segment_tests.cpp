#include "main_frame.hpp"
#include "support/desktop_test_window.hpp"
#include "open_dialogs.hpp"
#include "graph_canvas.hpp"
#include "data_views.hpp"
#include "project_testing.hpp"
#include "project_actions.hpp"
#include "reference_dialog.hpp"
#include "hexlab/workspace/navigation.hpp"
#include "support/fixture_files.hpp"
#include <wx/app.h>
#include <wx/dialog.h>
#include <wx/choice.h>
#include <wx/textctrl.h>
#include <wx/timer.h>
#include <wx/listctrl.h>
#include <wx/statusbr.h>
#include <wx/notebook.h>
#include <wx/dcmemory.h>
#include <wx/image.h>
#include <wx/msw/wrapwin.h>
#include <fstream>
#include <cstdio>
#include <algorithm>
#include <semaphore>
#include <chrono>
using namespace hexlab;
using namespace hexlab::desktop;
using namespace hexlab_test;
namespace {
struct CompletionGate {
    std::promise<bool> entered;
    std::shared_future<bool> reached = entered.get_future().share();
    std::binary_semaphore released{0};
    std::atomic<bool> claimed = false, opened = false, wrong_thread = false;
    void open() {
        if (!opened.exchange(true))
            released.release();
    }
};
class SegmentApp final : public wxApp {
    wxTimer timer_{this};
    MainFrame *frame = nullptr;
    std::unique_ptr<FixtureFile> input, profile, mixed_input, mixed_profile, flat_input;
    DocumentId mixed_id{0}, flat32_id{0}, flat64_id{0};
    SessionKey hooked;
    std::shared_ptr<CompletionGate> gate = std::make_shared<CompletionGate>();
    std::shared_ptr<const ProjectSnapshot> active64_snapshot;
    std::optional<Location> active64_selection;
    std::vector<std::byte> original_mixed;
    std::filesystem::path saved, exported;
    database::ProjectUuid old_uuid{}, saved_uuid{};
    database::ProjectRevisions saved_revisions;
    std::uint64_t saved_history = 0;
    std::optional<X86RawProfile> saved_profile;
    int result = 1, ticks = 0, phase = 0, compact_ticks = 0;
    bool modal_failed = false, modal_active = false;
    void send(int command) {
        wxCommandEvent event(wxEVT_MENU, command);
        frame->GetEventHandler()->ProcessEvent(event);
    }
    bool jump(int mode, const wxString &value) {
        modal_failed = false;
        CallAfter([this, mode, value] {
            auto *choice = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("location-mode"));
            auto *field = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("location-value"));
            auto *dialog = field ? dynamic_cast<wxDialog *>(field->GetParent()) : nullptr;
            if (!choice || choice->GetCount() <= static_cast<unsigned>(mode) || !dialog) {
                modal_failed = true;
                if (dialog)
                    dialog->EndModal(wxID_CANCEL);
                return;
            }
            choice->SetSelection(mode);
            field->SetValue(value);
            wxCommandEvent accept(wxEVT_BUTTON, wxID_OK);
            dialog->GetEventHandler()->ProcessEvent(accept);
        });
        modal_active = true;
        send(jump_id);
        modal_active = false;
        return !modal_failed;
    }
    bool edit(int command, const wxString &value) {
        modal_failed = false;
        CallAfter([this, value] {
            auto *field = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("edit-value"));
            auto *dialog = field ? dynamic_cast<wxDialog *>(field->GetParent()) : nullptr;
            if (!dialog) {
                modal_failed = true;
                return;
            }
            field->SetValue(value);
            wxCommandEvent accept(wxEVT_BUTTON, wxID_OK);
            dialog->GetEventHandler()->ProcessEvent(accept);
        });
        modal_active = true;
        send(command);
        modal_active = false;
        return !modal_failed;
    }
    static bool file_matches(const std::filesystem::path &path, std::span<const std::byte> expected) {
        auto file = FileStorage::open(path);
        if (!file || file.value()->size() != expected.size())
            return false;
        auto view = file.value()->read_at({0}, expected.size());
        return view && std::ranges::equal(view.value().bytes, expected);
    }
    bool reference_input(const ProjectSnapshot &project) {
        modal_failed = false;
        CallAfter([this] {
            auto *domain = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("reference-domain"));
            auto *field = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("reference-target"));
            auto *dialog = field ? dynamic_cast<wxDialog *>(field->GetParent()) : nullptr;
            if (!domain || domain->GetCount() < 3 || !dialog) {
                modal_failed = true;
                if (dialog)
                    dialog->EndModal(wxID_CANCEL);
                return;
            }
            domain->SetSelection(2);
            field->SetValue("FFFF:0000");
            wxCommandEvent accept(wxEVT_BUTTON, wxID_OK);
            dialog->GetEventHandler()->ProcessEvent(accept);
            auto *error = wxWindow::FindWindowByName("reference-error");
            if (!dialog->IsModal() || !error || error->GetLabel().empty()) {
                modal_failed = true;
                if (dialog->IsModal())
                    dialog->EndModal(wxID_CANCEL);
                return;
            }
            field->SetValue("0008:0005");
            dialog->GetEventHandler()->ProcessEvent(accept);
        });
        modal_active = true;
        auto command = reference_dialog(frame, Address{{2}, 0x10}, {2}, project.loaded->image);
        modal_active = false;
        const auto *reference = command ? std::get_if<SetReference>(&*command) : nullptr;
        return !modal_failed && reference && reference->source == Location{Address{{2}, 0x10}} &&
               reference->target == Location{Address{{7}, 5}} && bool(validate_command(project, *command));
    }
    void open_mixed() {
        auto bytes = hexlab_test::bytes({0x9a, 0, 0, 0x10, 0, 0x9a, 0x10, 0, 0x10, 0, 0x9a, 0, 0, 0x10, 0, 0xc3});
        const auto target = hexlab_test::bytes({0xb8, 0x78, 0x56, 0x34, 0x12, 0x66, 0xcb});
        bytes.insert(bytes.end(), target.begin(), target.end());
        bytes.resize(32, std::byte{0x90});
        bytes.insert(bytes.end(), target.begin(), target.end());
        bytes.resize(48, std::byte{0x90});
        const auto manual = hexlab_test::bytes({0xe9, 0xeb, 0xff, 0xff, 0xff});
        bytes.insert(bytes.end(), manual.begin(), manual.end());
        original_mixed = bytes;
        mixed_input = std::make_unique<FixtureFile>(bytes);
        saved = mixed_input->path.wstring() + L".segmented.hxproj";
        exported = mixed_input->path.wstring() + L".patched.bin";
        const std::string text =
            "hexlab-x86-profile 1\nenvironment protected386\na20 enabled\nload 0x10000\n"
            "entry 7 0\nstack 0x18\ndomains 3\ndomain 7 8 code \"caller\" ffff0000019a0000\n"
            "domain 2 0x10 code \"callee\" ffff1000019a4000\ndomain 3 0x18 data \"stack\" ffff000000920000\n";
        mixed_profile = std::make_unique<FixtureFile>(std::as_bytes(std::span(text)));
        OpenRequest request;
        request.path = mixed_input->path;
        request.format = Format::raw;
        request.x86_profile_path = mixed_profile->path;
        frame->OpenDocument(std::move(request));
    }
    void finish(const char *error = nullptr) {
        if (error)
            std::fprintf(stderr, "%s (phase %d)\n", error, phase);
        else
            result = 0;
        timer_.Stop();
        gate->open();
        workspace_testing::clear_actor_hook(hooked);
        frame->CloseAllDocuments();
        frame->Close();
    }
    bool capture(const char *name) {
        const auto path = std::filesystem::current_path() / "artifacts" / name;
        std::error_code error;
        std::filesystem::create_directories(path.parent_path(), error);
        if (error)
            return false;
        const auto handle = reinterpret_cast<HWND>(frame->GetHandle());
        ShowWindow(handle, SW_SHOWNOACTIVATE);
        frame->Refresh();
        frame->Update();
        const auto size = frame->GetSize();
        wxBitmap bitmap(size.x, size.y, 24);
        wxMemoryDC target(bitmap);
        RedrawWindow(handle, nullptr, nullptr,
                     RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW | RDW_ALLCHILDREN | RDW_FRAME);
        const bool copied = PrintWindow(handle, reinterpret_cast<HDC>(target.GetHDC()), 0) != 0;
        target.SelectObject(wxNullBitmap);
        const auto pixels = bitmap.ConvertToImage();
        std::size_t lit = 0, total = 0;
        for (int y = 0; y < pixels.GetHeight(); y += 8)
            for (int x = 0; x < pixels.GetWidth(); x += 8) {
                ++total;
                if (pixels.GetRed(x, y) > 32 || pixels.GetGreen(x, y) > 32 || pixels.GetBlue(x, y) > 32)
                    ++lit;
            }
        return copied && total && lit > total / 10 && bitmap.SaveFile(wxString(path.wstring()), wxBITMAP_TYPE_PNG);
    }
    void begin() {
        OpenRequest request;
        request.path = input->path;
        CallAfter([this] {
            wxDialog *dialog = nullptr;
            for (auto *window : wxTopLevelWindows)
                if (auto *candidate = dynamic_cast<wxDialog *>(window); candidate && candidate->IsModal())
                    dialog = candidate;
            auto *mode = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("raw-mode"));
            auto *path = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("raw-profile"));
            if (!dialog || !mode || mode->GetCount() < 3 || !path) {
                modal_failed = true;
                std::fprintf(stderr, "Segmented raw profile choice unavailable\n");
                if (dialog)
                    dialog->EndModal(wxID_CANCEL);
                return;
            }
            mode->SetSelection(2);
            wxCommandEvent choice(wxEVT_CHOICE, mode->GetId());
            mode->GetEventHandler()->ProcessEvent(choice);
            auto *base = wxWindow::FindWindowByName("raw-base");
            auto *entry = wxWindow::FindWindowByName("raw-entry");
            if (!path->IsEnabled() || !base || base->IsEnabled() || !entry || entry->IsEnabled()) {
                modal_failed = true;
                dialog->EndModal(wxID_CANCEL);
                return;
            }
            path->SetValue(wxString(profile->path.wstring()));
            wxCommandEvent accept(wxEVT_BUTTON, wxID_OK);
            dialog->GetEventHandler()->ProcessEvent(accept);
        });
        const bool accepted = configure_raw_mapping(frame, request);
        if (modal_failed || !accepted || request.raw || request.x86_profile_path != profile->path) {
            finish("Native raw dialog did not retain a deferred profile request");
            return;
        }
        // Still invalid during the modal handler: only the opening worker reads it.
        {
            std::ofstream file(profile->path, std::ios::binary | std::ios::trunc);
            file << "hexlab-x86-profile 1\nenvironment real386\na20 enabled\nload 0x10000\n"
                    "entry 7 0\nstack none\ndomains 1\ndomain 7 0x1000 code \"code\" real\n";
            if (!file) {
                finish("Cannot write owned native profile fixture");
                return;
            }
        }
        frame->OpenDocument(std::move(request));
        timer_.Start(20);
    }
    void tick() {
        if (modal_active)
            return;
        if (++ticks > 1400) {
            finish("Native segmented import timed out");
            return;
        }
        auto doc = frame->documents().current();
        if (phase >= 17) {
            workflow(doc);
            return;
        }
        if (!doc || !doc->project || doc->project->status == DerivedStatus::pending)
            return;
        const auto &project = *doc->project;
        auto *listing = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("disassembly", frame));
        if (!listing || listing->GetItemCount() == 0 || !project.functions)
            return;
        const auto status = frame->GetStatusBar()->GetStatusText();
        if (phase == 0) {
            if (!project.loaded || project.loaded->image->decode_context().mode != ExecutionMode::x86_16 ||
                project.functions->instructions.size() != 2 || !status.Contains("1000:0000") ||
                !status.Contains("x86-16") || listing->GetItemText(0) != "1000:0000") {
                std::fprintf(stderr, "phase=%d status=%s listing=%s mode=%u instructions=%zu\n", phase,
                             status.utf8_str().data(), listing->GetItemText(0).utf8_str().data(),
                             static_cast<unsigned>(project.loaded->image->decode_context().mode),
                             project.functions->instructions.size());
                finish("Native16 profile location labels or active-mode status are incorrect");
                return;
            }
            phase = 1;
            open_mixed();
            return;
        }
        if (phase == 1) {
            if (project.state->recipe.raw->x86_profile->environment != X86ImageEnvironment::protected386)
                return;
            mixed_id = doc->id;
            frame->Navigate(Address{{7}, 0});
            phase = 2;
            return;
        }
        if (phase == 2) {
            if (listing->GetItemText(0) != "0008:0000")
                return;
            wxUpdateUIEvent enabled(follow_id);
            frame->GetEventHandler()->ProcessEvent(enabled);
            if (!enabled.GetEnabled()) {
                finish("Native far Follow is disabled despite a current declared target");
                return;
            }
            phase = 3;
            send(follow_id);
            return;
        }
        if (phase == 3) {
            if (frame->documents().selection() != Location{Address{{2}, 0}})
                return;
            if (!status.Contains("0010:00000000") || !status.Contains("x86-32")) {
                finish("Far Follow still displays primary16 mode or loses destination selector");
                return;
            }
            phase = 4;
            if (!jump(2, "0008:0000"))
                finish("Selector:offset jump mode is unavailable");
            return;
        }
        if (phase == 4) {
            if (frame->documents().selection() != Location{Address{{7}, 0}})
                return;
            if (listing->GetItemText(0) != "0008:0000")
                return;
            if (!status.Contains("0008:0000") || !status.Contains("x86-16")) {
                finish("Selector jump did not restore caller domain and mode");
                return;
            }
            phase = 5;
            send(follow_id);
            return;
        }
        if (phase == 5) {
            if (frame->documents().selection() != Location{Address{{2}, 0}})
                return;
            phase = 6;
            if (!jump(0, "0x0"))
                finish("Active-domain offset jump failed");
            return;
        }
        if (phase == 6) {
            if (frame->documents().selection() != Location{Address{{2}, 0}}) {
                finish("Plain virtual jump silently reverted to the primary domain");
                return;
            }
            if (!jump(2, "FFFF:0000") || frame->documents().selection() != Location{Address{{2}, 0}}) {
                finish("Rejected selector jump changed the current location");
                return;
            }
            auto *direction = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("reference-direction", frame));
            if (!direction) {
                finish("Native reference direction control missing");
                return;
            }
            direction->SetSelection(1);
            wxCommandEvent incoming(wxEVT_CHOICE, direction->GetId());
            direction->GetEventHandler()->ProcessEvent(incoming);
            phase = 7;
            return;
        }
        if (phase == 7) {
            auto *refs = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("references", frame));
            if (!refs || refs->GetItemCount() != 2)
                return;
            if (refs->GetItemText(1, 0) != "0008:000A" || refs->GetItemText(1, 1) != "0010:00000000") {
                finish("Nonfirst incoming reference labels lost source or target selectors");
                return;
            }
            phase = 8;
            refs->SetItemState(1, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
            return;
        }
        if (phase == 8) {
            if (frame->documents().selection() != Location{Address{{7}, 0xa}})
                return;
            auto *canvas = dynamic_cast<GraphCanvas *>(wxWindow::FindWindowByName("graph-canvas", frame));
            auto graph = canvas ? canvas->graph() : nullptr;
            if (!graph || graph->model->kind != GraphKind::function_cfg)
                return;
            auto node = std::find_if(graph->model->nodes.begin(), graph->model->nodes.end(),
                                     [](const auto &n) { return n.selection == Location{Address{{7}, 5}}; });
            if (node == graph->model->nodes.end())
                return;
            auto placement = std::find_if(graph->layout->positions.begin(), graph->layout->positions.end(),
                                          [&](const auto &p) { return p.node == node->id; });
            if (placement == graph->layout->positions.end()) {
                finish("Far caller graph placement missing");
                return;
            }
            canvas->fit();
            auto point = canvas->to_client({placement->bounds.x + 10, placement->bounds.y + 10});
            auto hit = canvas->hit_test(point);
            if (!hit || !std::holds_alternative<GraphNodeId>(*hit) || std::get<GraphNodeId>(*hit) != node->id) {
                finish("Nonfirst segmented graph node hit mismatch");
                return;
            }
            phase = 9;
            wxMouseEvent click(wxEVT_LEFT_DOWN);
            click.SetPosition(point);
            canvas->GetEventHandler()->ProcessEvent(click);
            return;
        }
        if (phase == 9) {
            if (frame->documents().selection() != Location{Address{{7}, 5}} || listing->GetItemText(0) != "0008:0005")
                return;
            phase = 10;
            send(follow_id);
            return;
        }
        if (phase == 10) {
            if (frame->documents().selection() != Location{Address{{2}, 0x10}})
                return;
            if (!status.Contains("0010:00000010") || !status.Contains("x86-32")) {
                finish("Nonfirst far call target lost active domain context");
                return;
            }
            if (!frame->Find(ImmediateQuery{"0x12345678", 32, ImmediateInterpretation::unsigned_value})) {
                finish("Cannot enqueue segmented immediate search");
                return;
            }
            phase = 11;
            return;
        }
        if (phase == 11) {
            auto *results = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("search-results", frame));
            if (frame->FindPending() || !results || results->GetItemCount() != 2)
                return;
            if (results->GetItemText(1, 2) != "0010:00000010") {
                finish("Native immediate search label lost decoded instruction domain");
                return;
            }
            frame->Navigate(Address{{7}, 0});
            results->SetItemState(1, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
            if (frame->documents().selection() != Location{Address{{2}, 0x10}}) {
                finish("Nonfirst native search result selected a canonical file alias instead of its code domain");
                return;
            }
            phase = 12;
            return;
        }
        if (phase == 12) {
            if (listing->GetItemText(0) != "0010:00000010")
                return;
            auto *kind = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("graph-kind", frame));
            if (!kind) {
                finish("Graph kind selector missing");
                return;
            }
            kind->SetSelection(1);
            wxCommandEvent change(wxEVT_CHOICE, kind->GetId());
            kind->GetEventHandler()->ProcessEvent(change);
            auto *refs = wxWindow::FindWindowByName("references", frame);
            auto *book = refs ? dynamic_cast<wxNotebook *>(refs->GetParent()->GetParent()) : nullptr;
            if (book)
                for (std::size_t n = 0; n < book->GetPageCount(); ++n)
                    if (book->GetPageText(n) == "References")
                        book->SetSelection(n);
            phase = 13;
            return;
        }
        if (phase == 13) {
            auto *canvas = dynamic_cast<GraphCanvas *>(wxWindow::FindWindowByName("graph-canvas", frame));
            auto graph = canvas ? canvas->graph() : nullptr;
            if (!graph || graph->model->kind != GraphKind::image_calls || graph->model->nodes.size() != 3)
                return;
            if (!std::all_of(graph->model->nodes.begin(), graph->model->nodes.end(), [&](const auto &node) {
                    return node.selection &&
                           node.label == format_location(*node.selection, project.loaded->image.get());
                })) {
                finish("Native segmented graph labels lost selector identity");
                return;
            }
            canvas->fit();
            if (!capture("x86-segment-normal.png")) {
                finish("Cannot capture nonblank segmented normal view");
                return;
            }
            auto *pages = dynamic_cast<wxNotebook *>(canvas->GetParent()->GetParent());
            if (!pages) {
                finish("Native center notebook unavailable");
                return;
            }
            for (std::size_t n = 0; n < pages->GetPageCount(); ++n)
                if (pages->GetPageText(n) == "Graph")
                    pages->SetSelection(n);
            canvas->fit();
            if (!canvas->visible_nodes() || !capture("x86-segment-graph.png")) {
                finish("Cannot capture a nonblank segmented call graph");
                return;
            }
            for (std::size_t n = 0; n < pages->GetPageCount(); ++n)
                if (pages->GetPageText(n) == "Disassembly")
                    pages->SetSelection(n);
            frame->SetSize(800, 600);
            phase = 14;
            return;
        }
        if (phase == 14) {
            if (++compact_ticks < 3)
                return;
            auto *refs = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("references", frame));
            auto *results = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("search-results", frame));
            if (!refs || !results || refs->GetColumnWidth(0) + refs->GetColumnWidth(1) > refs->GetClientSize().x ||
                results->GetColumnWidth(0) + results->GetColumnWidth(1) > results->GetClientSize().x) {
                finish("Compact reference or search pane clips the two primary address fields");
                return;
            }
            if (listing->GetCountPerPage() < 4 || !status.Contains("0010:00000010") || !status.Contains("x86-32") ||
                !capture("x86-segment-compact.png")) {
                finish("Compact segmented view lost readable rows or active code context");
                return;
            }
            phase = 15;
            frame->Navigate(Address{{2}, 0x20});
            return;
        }
        if (phase == 15) {
            if (listing->GetItemText(0) != "0010:00000020")
                return;
            if (!listing->GetItemText(0, 3).Contains("manual decode")) {
                finish("Unreached instruction did not use the worker manual decoder");
                return;
            }
            wxUpdateUIEvent enabled(follow_id);
            frame->GetEventHandler()->ProcessEvent(enabled);
            if (!enabled.GetEnabled()) {
                finish("Current manual near branch lost its existing Follow action");
                return;
            }
            phase = 16;
            send(follow_id);
            return;
        }
        if (phase == 16) {
            if (frame->documents().selection() != Location{Address{{2}, 0x10}})
                return;
            hooked = frame->projects().actor(mixed_id)->view().session;
            const auto gui = std::this_thread::get_id();
            auto held = gate;
            workspace_testing::set_actor_hook(hooked, [held, gui](const workspace_testing::ActorCheckpoint &point) {
                if ((point.phase == workspace_testing::ActorPhase::analysis_started ||
                     point.phase == workspace_testing::ActorPhase::graph_started ||
                     point.phase == workspace_testing::ActorPhase::search_started ||
                     point.phase == workspace_testing::ActorPhase::listing_started) &&
                    std::this_thread::get_id() == gui)
                    held->wrong_thread = true;
                if (point.phase == workspace_testing::ActorPhase::analysis_computed && point.source &&
                    point.source->byte_revision == 1 && !held->claimed.exchange(true)) {
                    held->entered.set_value(std::this_thread::get_id() != gui);
                    held->released.acquire();
                }
            });
            if (!frame->ApplyProjectCommand(PatchBytes{Address{{2}, 0x10}, bytes({0xb9})})) {
                finish("Cannot enqueue mixed-domain patch");
                return;
            }
            phase = 17;
        }
    }
    static bool fresh(const std::shared_ptr<const ProjectSnapshot> &project) {
        return project && project->functions &&
               (project->status == DerivedStatus::fresh || project->status == DerivedStatus::incomplete);
    }
    void open_flat(bool long_mode) {
        if (!flat_input)
            flat_input = std::make_unique<FixtureFile>(bytes({0x40, 0x90, 0xc3}));
        OpenRequest request;
        request.path = flat_input->path;
        request.format = Format::raw;
        request.raw = RawOptions{long_mode ? Architecture::x86_64 : Architecture::x86,
                                 long_mode ? ExecutionMode::x86_64 : ExecutionMode::x86_32,
                                 {{0}, long_mode ? 0x2000u : 0x1000u},
                                 true,
                                 false,
                                 true,
                                 {}};
        frame->OpenDocument(std::move(request));
    }
    void workflow(const std::shared_ptr<const DocumentSnapshot> &doc) {
        auto &manager = frame->projects();
        if (gate->wrong_thread) {
            finish("Segmented engine work ran on the GUI thread");
            return;
        }
        if (phase == 17) {
            if (gate->reached.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
                return;
            if (!gate->reached.get()) {
                finish("Delayed analysis did not run off the requesting thread");
                return;
            }
            open_flat(false);
            phase = 18;
            return;
        }
        if (phase == 29) {
            if (!manager.documents().empty())
                return;
            frame->OpenProject(saved, database::ProjectMode::read_only);
            phase = 30;
            return;
        }
        const auto project = doc ? doc->project : nullptr;
        if (!fresh(project))
            return;
        if (phase == 18) {
            if (doc->id == mixed_id)
                return;
            flat32_id = doc->id;
            if (doc->image->decode_context().mode != ExecutionMode::x86_32 ||
                project->functions->instructions.front()->instruction.opcode != Opcode::inc) {
                finish("Flat32 tab decoded identical40/90/C3 bytes in the wrong mode");
                return;
            }
            open_flat(true);
            phase = 19;
            return;
        }
        if (phase == 19) {
            if (doc->id == flat32_id)
                return;
            flat64_id = doc->id;
            if (doc->image->decode_context().mode != ExecutionMode::x86_64 ||
                project->functions->instructions.front()->instruction.opcode != Opcode::nop ||
                project->functions->instructions.front()->instruction.length != 2) {
                finish("Flat64 tab failed the REX prefix versus legacy INC distinction");
                return;
            }
            active64_snapshot = project;
            active64_selection = frame->documents().selection();
            gate->open();
            phase = 20;
            return;
        }
        if (phase == 20) {
            const auto mixed = manager.project(mixed_id);
            if (!fresh(mixed) || mixed->state->revisions.bytes != 1)
                return;
            if (doc->id != flat64_id || project->functions != active64_snapshot->functions ||
                project->loaded->image != active64_snapshot->loaded->image ||
                project->state->uuid != active64_snapshot->state->uuid ||
                project->state->revisions != active64_snapshot->state->revisions ||
                frame->documents().selection() != active64_selection ||
                !frame->GetStatusBar()->GetStatusText().Contains("x86-64")) {
                finish("Late segmented analysis disturbed the active64-bit tab");
                return;
            }
            frame->ActivateDocument(mixed_id);
            phase = 21;
            return;
        }
        if (phase == 21) {
            if (doc->id != mixed_id || project->state->revisions.bytes != 1)
                return;
            auto fact =
                std::find_if(project->functions->instructions.begin(), project->functions->instructions.end(),
                             [](const auto &value) { return value->instruction.address == Address{{2}, 0x10}; });
            auto *listing = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("disassembly", frame));
            if (!listing || !listing->GetItemCount() || listing->GetItemText(0) != "0010:00000010")
                return;
            if (fact == project->functions->instructions.end() || (*fact)->instruction.bytes[0] != std::byte{0xb9} ||
                (*fact)->instruction.context.mode != ExecutionMode::x86_32 ||
                doc->image->decode_context().mode != ExecutionMode::x86_16 ||
                frame->documents().selection() != Location{Address{{2}, 0x10}} ||
                !frame->GetStatusBar()->GetStatusText().Contains("x86-32") ||
                manager.search_history(mixed_id)->size() != 0) {
                finish("Restored mixed tab lost its active domain or retained stale search results");
                return;
            }
            phase = 22;
            if (!reference_input(*project)) {
                finish("Native explicit reference cannot resolve a declared selector");
                return;
            }
            if (!edit(rename_id, "seg_target"))
                finish("Native segmented rename dialog unavailable");
            return;
        }
        if (phase == 22) {
            if (project->state->revisions.edit != 2)
                return;
            if (presentation_name(*project, Address{{2}, 0x10}) != "seg_target" ||
                presentation_name(*project, Address{{7}, 0x20}) == "seg_target") {
                finish("Native rename crossed a logical alias boundary");
                return;
            }
            phase = 23;
            if (!edit(comment_id, "segmented comment"))
                finish("Native segmented comment dialog unavailable");
            return;
        }
        if (phase == 23) {
            if (project->state->revisions.edit != 3)
                return;
            const auto *annotation = annotation_at(*project, Address{{2}, 0x10});
            if (!annotation || annotation->comment != "segmented comment") {
                finish("Native comment lost its segmented location");
                return;
            }
            phase = 24;
            if (!edit(bookmark_id, "segmented mark"))
                finish("Native segmented bookmark dialog unavailable");
            return;
        }
        if (phase == 24) {
            if (project->state->revisions.edit != 4)
                return;
            if (project->state->user->bookmarks.size() != 1 ||
                project->state->user->bookmarks[0].location != Location{Address{{2}, 0x10}}) {
                finish("Native bookmark lost its segmented location");
                return;
            }
            phase = 25;
            for (int n = 0; n < 4; ++n)
                send(wxID_UNDO);
            return;
        }
        if (phase == 25) {
            if (project->state->revisions.edit != 8 || project->state->history_cursor != 0)
                return;
            if (project->state->revisions.bytes != 2 || !project->state->user->annotations.empty() ||
                !project->state->user->bookmarks.empty() ||
                project->loaded->image->read(Address{{2}, 0x10}, 1).value() != bytes({0xb8})) {
                finish("Native undo did not restore original segmented bytes and user records");
                return;
            }
            phase = 26;
            for (int n = 0; n < 4; ++n)
                send(wxID_REDO);
            return;
        }
        if (phase == 26) {
            if (project->state->revisions.edit != 12 || project->state->history_cursor != 4)
                return;
            if (project->state->revisions.bytes != 3 ||
                presentation_name(*project, Address{{2}, 0x10}) != "seg_target" ||
                project->state->user->bookmarks.size() != 1 ||
                project->loaded->image->read(Address{{2}, 0x10}, 1).value() != bytes({0xb9}) ||
                !file_matches(mixed_input->path, original_mixed)) {
                finish("Native redo lost segmented edits or changed the external original");
                return;
            }
            saved_revisions = project->state->revisions;
            saved_history = project->state->history_cursor;
            saved_profile = project->state->recipe.raw->x86_profile;
            old_uuid = project->state->uuid;
            if (!frame->SaveProjectAs(saved)) {
                finish("Cannot enqueue segmented native Save As");
                return;
            }
            phase = 27;
            return;
        }
        if (phase == 27) {
            auto actor = manager.actor(mixed_id);
            if (!actor)
                return;
            const auto view = actor->view();
            if (view.project_path != saved || view.pending_operations || view.snapshot != project)
                return;
            if (project->state->uuid == old_uuid || project->state->revisions != saved_revisions ||
                project->state->history_cursor != saved_history ||
                project->state->recipe.raw->x86_profile != saved_profile) {
                finish("Native Save As lost profile/history or reused the original UUID");
                return;
            }
            saved_uuid = project->state->uuid;
            if (!frame->ExportBinary(exported)) {
                finish("Cannot enqueue segmented native export");
                return;
            }
            phase = 28;
            return;
        }
        if (phase == 28) {
            if (!std::filesystem::exists(exported))
                return;
            auto expected = original_mixed;
            expected[32] = std::byte{0xb9};
            if (!file_matches(exported, expected) || !file_matches(mixed_input->path, original_mixed)) {
                finish("Segmented native export differs from canonical patched file bytes");
                return;
            }
            if (!std::filesystem::remove(mixed_input->path) || !std::filesystem::remove(mixed_profile->path)) {
                finish("Cannot remove owned external segmented source/profile before reopening");
                return;
            }
            gate->open();
            workspace_testing::clear_actor_hook(hooked);
            frame->CloseAllDocuments();
            phase = 29;
            return;
        }
        if (phase == 30) {
            if (project->mode != database::ProjectMode::read_only)
                return;
            if (project->state->uuid != saved_uuid || project->state->revisions != saved_revisions ||
                project->state->history_cursor != saved_history ||
                project->state->recipe.raw->x86_profile != saved_profile ||
                project->derived_cache_status != database::CacheStatus::hit ||
                project->loaded->image->decode_context().mode != ExecutionMode::x86_16) {
                finish("Source-missing native readonly reopen lost segmented profile/history/cache");
                return;
            }
            frame->Navigate(Address{{2}, 0x10});
            phase = 31;
            return;
        }
        if (phase == 31) {
            auto *listing = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("disassembly", frame));
            if (!listing || !listing->GetItemCount() || listing->GetItemText(0) != "0010:00000010")
                return;
            if (!frame->GetStatusBar()->GetStatusText().Contains("x86-32") ||
                presentation_name(*project, Address{{2}, 0x10}) != "seg_target" ||
                project->loaded->image->read(Address{{2}, 0x10}, 1).value() != bytes({0xb9})) {
                finish("Readonly native segmented target lost patched32-bit facts or annotations");
                return;
            }
            wxUpdateUIEvent comment(comment_id), undo(wxID_UNDO);
            frame->GetEventHandler()->ProcessEvent(comment);
            frame->GetEventHandler()->ProcessEvent(undo);
            if (comment.GetEnabled() || undo.GetEnabled()) {
                finish("Readonly segmented mutation actions stayed enabled");
                return;
            }
            if (!frame->ApplyProjectCommand(Comment{Address{{2}, 0x10}, "forbidden"})) {
                finish("Cannot enqueue readonly mutation refusal probe");
                return;
            }
            phase = 32;
            return;
        }
        if (phase == 32) {
            const auto info = manager.documents();
            auto active = manager.active_document();
            auto record = std::find_if(info.begin(), info.end(),
                                       [&](const auto &entry) { return active && entry.id == *active; });
            if (record == info.end() || !record->error || record->error->code != ErrorCode::read_only)
                return;
            const auto *annotation = annotation_at(*project, Address{{2}, 0x10});
            if (project->state->revisions != saved_revisions || project->state->history_cursor != saved_history ||
                !annotation || annotation->comment != "segmented comment") {
                finish("Refused readonly mutation changed segmented user history");
                return;
            }
            finish();
        }
    }

  public:
    bool OnInit() override {
        wxInitAllImageHandlers();
        wxSetAssertHandler([](const wxString &, int, const wxString &, const wxString &, const wxString &message) {
            std::fprintf(stderr, "wx assertion: %s\n", message.utf8_str().data());
            std::_Exit(4);
        });
        input = std::make_unique<FixtureFile>(bytes({0xb0, 0x7f, 0xc3}));
        profile = std::make_unique<FixtureFile>(bytes({0}));
        frame = new MainFrame;
        auto *probe = new VirtualTable(frame, "column-fit-budget", {"File offset", "Virtual address"});
        probe->Hide();
        auto formatted = std::make_shared<std::size_t>(0);
        probe->populate(100000, [formatted](std::size_t, int) {
            ++*formatted;
            return wxString("0010:00000010");
        });
        *formatted = 0;
        probe->fit_columns({0, 1}, 50000);
        if (*formatted > 130) {
            std::fprintf(stderr, "Column fitting scanned an unbounded retained result set\n");
            std::_Exit(3);
        }
        probe->Destroy();
        show_test_window(frame);
        Bind(wxEVT_TIMER, [this](wxTimerEvent &) { tick(); });
        CallAfter([this] { begin(); });
        return true;
    }
    int OnRun() override {
        wxApp::OnRun();
        return result;
    }
    int OnExit() override {
        gate->open();
        workspace_testing::clear_actor_hook(hooked);
        std::error_code ignored;
        if (!saved.empty())
            for (auto suffix : {L"", L"-wal", L"-shm"}) {
                auto path = saved;
                path += suffix;
                std::filesystem::remove(path, ignored);
            }
        if (!exported.empty())
            std::filesystem::remove(exported, ignored);
        return wxApp::OnExit();
    }
};
} // namespace
wxIMPLEMENT_APP(SegmentApp);
