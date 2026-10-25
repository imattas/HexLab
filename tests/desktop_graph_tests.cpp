#include "main_frame.hpp"
#include "support/desktop_test_window.hpp"
#include "graph_canvas.hpp"
#include "project_testing.hpp"
#include "hexlab/workspace/project_graph.hpp"
#include "support/fixture_files.hpp"
#include <wx/app.h>
#include <wx/listctrl.h>
#include <wx/notebook.h>
#include <wx/timer.h>
#include <wx/choice.h>
#include <cstdio>
#include <algorithm>
#include <semaphore>
#include <wx/dcclient.h>
#include <wx/dcmemory.h>
#include <wx/image.h>
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
class GraphApp final : public wxApp {
    wxTimer timer_{this};
    MainFrame *frame = nullptr;
    std::unique_ptr<FixtureFile> file;
    int phase = 0, ticks = 0, result = 1;
    std::shared_ptr<const ProjectGraph> first;
    std::unique_ptr<FixtureFile> calls,unknown,long_block,indirect;
    DocumentId first_id{0};
    SessionKey key;
    std::shared_ptr<Gate> gate = std::make_shared<Gate>();

  public:
    bool OnInit() override {
        wxSetAssertHandler([](const wxString &, int, const wxString &, const wxString &, const wxString &message) {
            std::fprintf(stderr, "wx assertion: %s\n", message.utf8_str().data());
            std::_Exit(4);
        });
        wxInitAllImageHandlers();
        file = std::make_unique<FixtureFile>(bytes({0x74, 3, 0x90, 0xeb, 1, 0x90, 0xc3}));
        frame = new MainFrame;
        show_test_window(frame);
        OpenRequest request;
        request.path = file->path;
        request.format = Format::raw;
        request.raw = RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x1000}, true, false, true, {}};
        frame->OpenDocument(request);
        Bind(wxEVT_TIMER, [this](wxTimerEvent &) { tick(); });
        timer_.Start(20);
        return true;
    }
    void fail(const char *text) {
        std::fprintf(stderr, "%s (phase %d)\n", text, phase);
        gate->open();
        timer_.Stop();
        frame->CloseAllDocuments();
        frame->Close();
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
            fail("Graph workflow timed out");
            return;
        }
        if (frame->documents().opening())
            return;
        auto *canvas = dynamic_cast<GraphCanvas *>(wxWindow::FindWindowByName("graph-canvas", frame));
        auto id = frame->projects().active_document();
        if (!id)
            return;
        auto project = frame->projects().project(*id);
        if (phase == 0) {
            if (!canvas) {
                fail("Actual graph canvas missing");
                return;
            }
            auto *pages = dynamic_cast<wxNotebook *>(canvas->GetParent()->GetParent());
            if (!pages) {
                fail("Graph is not a normal document page");
                return;
            }
            pages->SetSelection(2);
            phase = 1;
        } else if (phase == 1) {
            auto graph = canvas->graph();
            if (!graph)
                return;
            if (graph->model->nodes.size() != 4 || graph->model->edges.size() != 4) {
                fail("Native graph is not literal diamond topology");
                return;
            }
            first = graph;
            first_id = *id;
            // A block is an instruction surface, not just an entry-point link.
            // The second line of the 0x1002 block is the jump at 0x1003.
            canvas->fit();
            auto instruction_node = std::find_if(graph->model->nodes.begin(), graph->model->nodes.end(),
                [](const auto &node) { return node.selection == Location{Address{{0}, 0x1002}}; });
            auto instruction_position = std::find_if(graph->layout->positions.begin(), graph->layout->positions.end(),
                [&](const auto &p) { return p.node == instruction_node->id; });
            const auto top = canvas->to_client({instruction_position->bounds.x, instruction_position->bounds.y});
            const auto next_line = canvas->to_client({instruction_position->bounds.x, instruction_position->bounds.y + 18});
            const auto line = std::max(10, next_line.y - top.y);
            const wxPoint jump_line{top.x + 20, top.y + 6 + 2 * line + line / 2};
            wxMouseEvent instruction_click(wxEVT_LEFT_DOWN);
            instruction_click.SetPosition(jump_line);
            canvas->GetEventHandler()->ProcessEvent(instruction_click);
            auto selected_text = [this](const char *name) {
                auto *table = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName(name, frame));
                const auto row = table ? table->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED) : -1;
                return row >= 0 ? table->GetItemText(row, 0) : wxString{};
            };
            auto *instruction_refs = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("references", frame));
            if (frame->documents().selection() != Location{Address{{0}, 0x1003}} ||
                selected_text("disassembly") != "0x1003" || selected_text("pseudocode-addresses") != "0x1003" ||
                !instruction_refs || instruction_refs->GetItemCount() != 1 ||
                instruction_refs->GetItemText(0, 1) != "0x1006") {
                fail("Graph instruction click did not synchronize listing, pseudocode and outgoing references");
                return;
            }
            auto keypress = [canvas](int key) {
                wxKeyEvent event(wxEVT_CHAR_HOOK);
                event.m_keyCode = key;
                canvas->GetEventHandler()->ProcessEvent(event);
            };
            keypress(WXK_UP);
            if (frame->documents().selection() != Location{Address{{0}, 0x1002}}) {
                fail("Graph Up did not select the previous instruction"); return;
            }
            keypress(WXK_DOWN);
            keypress(WXK_RETURN);
            if (frame->documents().selection() != Location{Address{{0}, 0x1006}}) {
                fail("Graph Enter did not follow the selected instruction target"); return;
            }
            wxCommandEvent instruction_back(wxEVT_MENU, back_id);
            frame->GetEventHandler()->ProcessEvent(instruction_back);
            if (frame->documents().selection() != Location{Address{{0}, 0x1003}}) {
                fail("Graph follow lost shared navigation history"); return;
            }
            wxMouseEvent instruction_double_click(wxEVT_LEFT_DCLICK);
            instruction_double_click.SetPosition(jump_line);
            canvas->GetEventHandler()->ProcessEvent(instruction_double_click);
            if (frame->documents().selection() != Location{Address{{0}, 0x1006}}) {
                fail("Graph instruction double click did not follow its target"); return;
            }
            key = frame->projects().actor(*id)->view().session;
            auto held = gate;
            auto gui = std::this_thread::get_id();
            workspace_testing::set_actor_hook(key, [held, gui](const workspace_testing::ActorCheckpoint &checkpoint) {
                if (checkpoint.phase == workspace_testing::ActorPhase::graph_started &&
                    std::this_thread::get_id() == gui)
                    throw std::runtime_error("Graph ran on GUI thread");
                if (checkpoint.phase == workspace_testing::ActorPhase::graph_computed &&
                    !held->claimed.exchange(true)) {
                    held->entered.set_value(true);
                    held->release.acquire();
                }
            });
            canvas->fit();
            auto node = std::find_if(graph->model->nodes.begin(), graph->model->nodes.end(),
                                     [](auto &n) { return n.selection == Location{Address{{0}, 0x1005}}; });
            auto position = std::find_if(graph->layout->positions.begin(), graph->layout->positions.end(),
                                         [&](auto &p) { return p.node == node->id; });
            auto point = canvas->to_client({position->bounds.x + 10, position->bounds.y + 10});
            auto hit = canvas->hit_test(point);
            if (!hit || !std::holds_alternative<GraphNodeId>(*hit) || std::get<GraphNodeId>(*hit) != node->id) {
                fail("Nonfirst block model-coordinate hit mismatch");
                return;
            }
            wxMouseEvent click(wxEVT_LEFT_DOWN);
            click.SetPosition(point);
            canvas->GetEventHandler()->ProcessEvent(click);
            if (frame->documents().selection() != Location{Address{{0}, 0x1005}}) {
                fail("Graph click did not navigate the active document");
                return;
            }
            auto *listing = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("disassembly", frame));
            auto *bytes = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("bytes", frame));
            if (!listing || !bytes ||
                listing->GetItemText(listing->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED), 0) != "0x1005" ||
                bytes->GetItemText(0, 1).Left(5) != "90 C3") {
                fail("Graph selection did not synchronize listing and bytes");
                return;
            }
            auto *kind = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("graph-kind", frame));
            kind->SetSelection(1);
            wxCommandEvent change(wxEVT_CHOICE, kind->GetId());
            kind->GetEventHandler()->ProcessEvent(change);
            phase = 15;
        } else if (phase == 15) {
            if (gate->reached.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
                return;
            if (!frame->ApplyProjectCommand(Rename{Address{{0}, 0x1005}, "named_branch"})) {
                fail("Cannot enqueue graph rename");
                return;
            }
            phase = 16;
        } else if (phase == 16) {
            if (project->state->revisions.edit != 1)
                return;
            if (canvas->graph()) {
                fail("Old graph remained interactive after presentation changed");
                return;
            }
            gate->open();
            auto *kind = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("graph-kind", frame));
            kind->SetSelection(0);
            wxCommandEvent change(wxEVT_CHOICE, kind->GetId());
            kind->GetEventHandler()->ProcessEvent(change);
            phase = 2;
        } else if (phase == 2) {
            auto graph = canvas->graph();
            if (!graph || graph->model->presentation_revision != 1)
                return;
            bool found = false;
            for (auto &n : graph->model->nodes)
                found = found || n.label == "named_branch";
            if (!found || graph->layout->model_key == first->layout->model_key) {
                fail("Rename did not reflow the actual graph");
                return;
            }
            canvas->pan_by({100000, 100000});
            if (canvas->visible_nodes() != 0) {
                fail("Offscreen graph nodes were not culled");
                return;
            }
            workspace_testing::clear_actor_hook(key);
            canvas->fit();
            if (canvas->visible_nodes() != 4) {
                fail("Fit did not restore visible topology");
                return;
            }
            bool edge_found = false;
            canvas->zoom_by(1.2, {100, 100});
            canvas->pan_by({24, -12});
            for (auto &route : graph->layout->routes) {
                auto edge = std::find_if(graph->model->edges.begin(), graph->model->edges.end(),
                                         [&](auto &e) { return e.id == route.edge; });
                if (edge->selection != Location{Address{{0}, 0x1003}} ||
                    edge->target_location != Location{Address{{0}, 0x1006}})
                    continue;
                for (std::size_t i = 1; i < route.points.size(); ++i) {
                    auto a = route.points[i - 1], b = route.points[i];
                    auto point = canvas->to_client({(a.x + b.x) / 2, (a.y + b.y) / 2});
                    auto hit = canvas->hit_test(point);
                    if (!hit || *hit != GraphHit{edge->id})
                        continue;
                    wxMouseEvent click(wxEVT_LEFT_DOWN);
                    click.SetPosition(point);
                    canvas->GetEventHandler()->ProcessEvent(click);
                    if (frame->documents().selection() != Location{Address{{0}, 0x1003}}) {
                        fail("Edge click lost its source location");
                        return;
                    }
                    wxMouseEvent follow(wxEVT_LEFT_DCLICK);
                    follow.SetPosition(point);
                    canvas->GetEventHandler()->ProcessEvent(follow);
                    if (frame->documents().selection() != Location{Address{{0}, 0x1006}}) {
                        fail("Edge follow lost its typed target");
                        return;
                    }
                    edge_found = true;
                    break;
                }
                if (edge_found)
                    break;
            }
            if (!edge_found) {
                fail("Nonfirst routed edge is not hittable after pan and zoom");
                return;
            }
            frame->Navigate(Address{{0}, 0x1005});
            canvas->fit();
            frame->Update();
            if (!capture("project-graph-normal.png")) {
                fail("Graph screenshot failed");
                return;
            }
            if (!frame->ApplyProjectCommand(
                    SetReference{Address{{0}, 0x1000}, Address{{0}, 0x1002}, UserReferenceKind::read, false})) {
                fail("Cannot add extra reference");
                return;
            }
            phase = 4;
        } else if (phase == 4) {
            if (project->state->revisions.edit != 2 || frame->documents().opening() || !project->references ||
                (project->status!=DerivedStatus::fresh && project->status!=DerivedStatus::incomplete))
                return;
            frame->Navigate(Address{{0}, 0x1000});
            auto *refs = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("references", frame));
            if (!refs || refs->GetItemCount() != 2) {
                fail("Native outgoing reference rows missing");
                return;
            }
            auto target = refs->GetItemText(1, 1);
            Location expected = Address{{0}, target == "0x1002" ? 0x1002ull : 0x1005ull};
            if (target != "0x1002" && target != "0x1005") {
                fail("Nonfirst reference target invented");
                return;
            }
            refs->SetItemState(1, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
            if (frame->documents().selection() != expected) {
                fail("Nonfirst native reference did not navigate");
                return;
            }
            wxCommandEvent back(wxEVT_MENU, back_id);
            frame->GetEventHandler()->ProcessEvent(back);
            if (frame->documents().selection() != Location{Address{{0}, 0x1000}}) {
                fail("Reference selection lost shared navigation history");
                return;
            }
            frame->Navigate(Address{{0}, 0x1006});
            auto *direction = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("reference-direction", frame));
            if (!direction) {
                fail("Incoming reference control missing");
                return;
            }
            direction->SetSelection(1);
            wxCommandEvent change(wxEVT_CHOICE, direction->GetId());
            direction->GetEventHandler()->ProcessEvent(change);
            if (refs->GetItemCount() != 1 || refs->GetItemText(0, 0) != "0x1003") {
                fail("Incoming reference facts mismatch");
                return;
            }
            refs->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
            if (frame->documents().selection() != Location{Address{{0}, 0x1003}}) {
                fail("Incoming row did not navigate source");
                return;
            }
            frame->Navigate(Address{{0}, 0x1005});
            if (!frame->ApplyProjectCommand(PatchBytes{FileOffset{0}, bytes({0xeb})})) {
                fail("Cannot patch graph source");
                return;
            }
            phase = 3;
        } else if (phase == 3) {
            auto graph = canvas->graph();
            if (!graph || graph->model->source_key->byte_revision != 1)
                return;
            if (graph->model->nodes.size() != 2 || graph->model->edges.size() != 1 ||
                !project_graph_current(*project, *graph)) {
                fail("Patched graph retained obsolete topology or labels");
                return;
            }
            calls = std::make_unique<FixtureFile>(bytes({0xe8, 1, 0, 0, 0, 0xc3, 0x90, 0xc3}));
            OpenRequest request;
            request.path = calls->path;
            request.format = Format::raw;
            request.raw = RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x2000}, true, false, true, {}};
            frame->OpenDocument(request);
            phase = 5;
        } else if (phase == 5) {
            if (*id == first_id)
                return;
            auto *kind = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("graph-kind", frame));
            if (!kind || kind->GetSelection() != 0) {
                fail("Second document inherited call graph mode");
                return;
            }
            kind->SetSelection(1);
            wxCommandEvent choice(wxEVT_CHOICE, kind->GetId());
            kind->GetEventHandler()->ProcessEvent(choice);
            phase = 6;
        } else if (phase == 6) {
            auto graph = canvas->graph();
            if (!graph || graph->model->kind != GraphKind::image_calls)
                return;
            if (graph->model->nodes.size() != 2 || graph->model->edges.size() != 1) {
                fail("Actual call graph topology mismatch");
                return;
            }
            canvas->fit();
            bool found = false;
            for (auto &node : graph->model->nodes)
                if (node.selection == Location{Address{{0}, 0x2006}}) {
                    auto pos = std::find_if(graph->layout->positions.begin(), graph->layout->positions.end(),
                                            [&](auto &p) { return p.node == node.id; });
                    wxMouseEvent click(wxEVT_LEFT_DOWN);
                    click.SetPosition(canvas->to_client({pos->bounds.x + 10, pos->bounds.y + 10}));
                    canvas->GetEventHandler()->ProcessEvent(click);
                    found = true;
                    break;
                }
            if (!found || frame->documents().selection() != Location{Address{{0}, 0x2006}}) {
                fail("Nonfirst call graph function did not navigate");
                return;
            }
            unknown=std::make_unique<FixtureFile>(bytes({0xff,0xd0,0xc5}));
            OpenRequest request;request.path=unknown->path;request.format=Format::raw;request.raw=RawOptions{Architecture::x86_64,ExecutionMode::x86_64,{{0},0x3000},true,false,true,{}};frame->OpenDocument(request);phase=8;
        } else if(phase==8){
            if(frame->documents().selection()!=Location{Address{{0},0x3000}})return;
            auto graph=canvas->graph();if(!graph)return;
            auto* status=wxWindow::FindWindowByName("graph-status",frame);
            if(graph->model->complete || !status || !status->GetLabel().Contains("partial")){fail("Unsupported transfer graph hides partial analysis");return;}
            auto* kind=dynamic_cast<wxChoice*>(wxWindow::FindWindowByName("graph-kind",frame));kind->SetSelection(1);wxCommandEvent change(wxEVT_CHOICE,kind->GetId());kind->GetEventHandler()->ProcessEvent(change);phase=9;
        } else if(phase==9){
            auto graph=canvas->graph();if(!graph || graph->model->kind!=GraphKind::image_calls)return;
            bool unresolved=false;for(auto& node:graph->model->nodes)unresolved=unresolved || node.kind==GraphNodeKind::unresolved;
            auto* refs=dynamic_cast<wxListCtrl*>(wxWindow::FindWindowByName("references",frame));
            if(!unresolved || !refs || refs->GetItemCount()!=1 || !refs->GetItemText(0,1).StartsWith("unresolved:")){fail("Indirect call invents a numeric target");return;}
            frame->ActivateDocument(first_id);phase=7;
        } else if (phase == 7) {
            auto graph = canvas->graph();
            if (*id != first_id || !graph)
                return;
            auto *kind = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("graph-kind", frame));
            if (graph->model->kind != GraphKind::function_cfg || graph->model->nodes.size() != 2 ||
                kind->GetSelection() != 0 || frame->documents().selection() != Location{Address{{0}, 0x1005}}) {
                fail("Switching documents mixed graph kind or source");
                return;
            }
            frame->SetSize(640, 480);
            phase = 10;
        } else if (phase == 10) {
            canvas->fit();
            frame->Update();
            if (!capture("project-graph-compact.png")) {
                fail("Compact graph capture failed");
                return;
            }
            std::vector<std::byte> instructions(40, std::byte{0x90});
            instructions.push_back(std::byte{0xc3});
            long_block = std::make_unique<FixtureFile>(std::move(instructions));
            OpenRequest request;
            request.path = long_block->path;
            request.format = Format::raw;
            request.raw = RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x4000}, true, false, true, {}};
            frame->OpenDocument(request);
            phase = 11;
        } else if (phase == 11) {
            if (frame->documents().selection() != Location{Address{{0}, 0x4000}} || !canvas->graph()) return;
            auto graph = canvas->graph();
            if (graph->model->nodes.size() != 1 || !graph->model->nodes.front().block ||
                graph->model->nodes.front().block->instructions.size() != 41) {
                fail("Long-block fixture was not recovered as a single graph block"); return;
            }
            for (int instruction = 1; instruction <= 40; ++instruction) {
                wxKeyEvent down(wxEVT_CHAR_HOOK); down.m_keyCode = WXK_DOWN;
                canvas->GetEventHandler()->ProcessEvent(down);
                if (frame->documents().selection() != Location{Address{{0}, 0x4000u + instruction}}) {
                    fail("Graph keyboard navigation cannot reach instructions beyond the bounded preview"); return;
                }
            }
            // The selected tail remains visible and clickable after the preview scrolls.
            const auto bounds = graph->layout->positions.front().bounds;
            const auto top = canvas->to_client({bounds.x, bounds.y});
            const auto bottom = canvas->to_client({bounds.x + bounds.width, bounds.y + bounds.height});
            const auto next = canvas->to_client({bounds.x, bounds.y + 18});
            const auto line = std::max(10, next.y - top.y);
            const auto count = std::min<int>(16, (bottom.y - 4 - (top.y + 6 + line)) / line);
            if (count <= 0) { fail("Long graph block has no visible instructions"); return; }
            wxMouseEvent tail_click(wxEVT_LEFT_DOWN);
            tail_click.SetPosition({top.x + 20, top.y + 6 + line * count + line / 2});
            canvas->GetEventHandler()->ProcessEvent(tail_click);
            if (frame->documents().selection() != Location{Address{{0}, 0x4028}}) {
                fail("Graph tail preview did not scroll with instruction selection"); return;
            }
            // An unmodified Enter on a return must not follow a previously clicked edge.
            wxKeyEvent enter(wxEVT_CHAR_HOOK); enter.m_keyCode = WXK_RETURN;
            canvas->GetEventHandler()->ProcessEvent(enter);
            if (frame->documents().selection() != Location{Address{{0}, 0x4028}}) {
                fail("Graph Enter reused a stale target on an instruction without a destination"); return;
            }
            // Byte/text searches navigate in the file-offset domain. Graph keys
            // must resume at the mapped instruction, not restart at block entry.
            frame->Navigate(FileOffset{39});
            wxKeyEvent mapped_down(wxEVT_CHAR_HOOK); mapped_down.m_keyCode = WXK_DOWN;
            canvas->GetEventHandler()->ProcessEvent(mapped_down);
            if (frame->documents().selection() != Location{Address{{0}, 0x4028}}) {
                fail("Graph navigation did not resume from a mapped search/bytes location"); return;
            }
            indirect = std::make_unique<FixtureFile>(bytes({0xff, 0xd0, 0xe8, 1, 0, 0, 0, 0xc3, 0x90, 0xc3}));
            OpenRequest request;
            request.path = indirect->path;
            request.format = Format::raw;
            request.raw = RawOptions{Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x5000}, true, false, true, {}};
            frame->OpenDocument(request);
            phase = 12;
        } else if (phase == 12) {
            if (frame->documents().selection() != Location{Address{{0}, 0x5000}} || !canvas->graph()) return;
            auto *kind = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("graph-kind", frame));
            kind->SetSelection(1);
            wxCommandEvent change(wxEVT_CHOICE, kind->GetId());
            kind->GetEventHandler()->ProcessEvent(change);
            phase = 13;
        } else if (phase == 13) {
            const auto graph = canvas->graph();
            if (!graph || graph->model->kind != GraphKind::image_calls) return;
            if (std::none_of(graph->model->nodes.begin(), graph->model->nodes.end(),
                             [](const auto &node) { return node.kind == GraphNodeKind::unresolved; })) {
                fail("Indirect-call fixture did not produce an unresolved graph node"); return;
            }
            wxKeyEvent down(wxEVT_CHAR_HOOK); down.m_keyCode = WXK_DOWN;
            canvas->GetEventHandler()->ProcessEvent(down);
            if (frame->documents().selection() != Location{Address{{0}, 0x5008}}) {
                fail("Unresolved transfer graph node trapped instruction navigation at its source"); return;
            }
            wxKeyEvent end(wxEVT_CHAR_HOOK); end.m_keyCode = WXK_DOWN;
            canvas->GetEventHandler()->ProcessEvent(end);
            if (frame->documents().selection() != Location{Address{{0}, 0x5008}}) {
                fail("Instruction navigation followed a synthetic unresolved node after the final instruction"); return;
            }
            result = 0;
            timer_.Stop();
            frame->CloseAllDocuments();
            frame->Close();
        }
    }
    int OnExit() override {
        gate->open();
        workspace_testing::clear_actor_hook(key);
        return wxApp::OnExit();
    }
    int OnRun() override {
        wxApp::OnRun();
        return result;
    }
};
} // namespace
wxIMPLEMENT_APP(GraphApp);
