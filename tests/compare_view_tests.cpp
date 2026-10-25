#include "compare_view.hpp"
#include "support/desktop_test_window.hpp"
#include "main_frame.hpp"
#include "hexlab/processors/instruction.hpp"
#include <wx/app.h>
#include <wx/menu.h>
#include <wx/listctrl.h>
#include <cstdio>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <stdexcept>
using namespace hexlab::desktop;
namespace {
void check_data_and_sessions() {
    using namespace hexlab;
    Instruction normalized_a;
    normalized_a.opcode = Opcode::mov;
    normalized_a.operands = {RegisterOperand{RegisterBank::gpr, 0, 64, false},
                             ImmediateOperand{42, 8, 64, false, EncodedField{1, 1}}};
    auto normalized_b = normalized_a;
    std::get<RegisterOperand>(normalized_b.operands[0]).index = 3;
    normalized_b.address.offset = 0x1400;
    normalized_b.bytes[0] = std::byte{0x48};
    normalized_b.bytes[1] = std::byte{0xC7};
    const auto fingerprint_a = compare_instruction_fingerprint(normalized_a);
    const auto fingerprint_b = compare_instruction_fingerprint(normalized_b);
    auto changed_constant = normalized_b;
    std::get<ImmediateOperand>(changed_constant.operands[1]).value = 43;
    const auto changed_fingerprint = compare_instruction_fingerprint(changed_constant);
    Instruction call_a;
    call_a.opcode = Opcode::call;
    call_a.flow = FlowKind::call;
    call_a.operands = {RelativeOperand{0x100, 32, 64, EncodedField{1, 4}}};
    auto call_b = call_a;
    std::get<RelativeOperand>(call_b.operands[0]).displacement = -0x4000;
    auto call_wide = call_a;
    std::get<RelativeOperand>(call_wide.operands[0]).encoded_width = 8;
    auto thumb_a = call_a;
    thumb_a.operands = {ThumbRelativeOperand{0x100, 16}};
    auto thumb_b = thumb_a;
    std::get<ThumbRelativeOperand>(thumb_b.operands[0]).encoded_width = 32;
    if (!fingerprint_a || !fingerprint_b || fingerprint_a != fingerprint_b ||
        !changed_fingerprint || changed_fingerprint == fingerprint_a ||
        compare_instruction_fingerprint(call_a) != compare_instruction_fingerprint(call_b) ||
        compare_instruction_fingerprint(call_a) != compare_instruction_fingerprint(call_wide) ||
        compare_instruction_fingerprint(thumb_a) != compare_instruction_fingerprint(thumb_b))
        throw std::runtime_error("normalized instruction fingerprints must ignore register allocation, byte encoding, and branch displacement while preserving constants");

    const hexlab::compare::ChangeRun run{hexlab::compare::ChangeKind::changed, "text", 0x401000, 0x402000, 3};
    if (compare_kind_text(run.kind) != "Changed" ||
        compare_run_text(run) != "Changed text 0x401000 -> 0x402000 (3 bytes)")
        throw std::runtime_error("comparison run display must preserve kind, key, image-relative addresses, and extent");
    const hexlab::compare::FunctionMatch matched{hexlab::compare::FunctionMatchKind::matched, 0x401000, 0x402000, 97};
    const hexlab::compare::FunctionMatch ambiguous{hexlab::compare::FunctionMatchKind::ambiguous, 0x401000, {}, 83};
    const hexlab::compare::FunctionMatch sectioned{hexlab::compare::FunctionMatchKind::matched, 0x100, 0x200, 91, 4, 7};
    if (compare_function_kind_text(matched.kind) != "Matched" ||
        compare_function_text(matched) != "Matched 0x401000 -> 0x402000 (97%)" ||
        compare_function_text(ambiguous) != "Ambiguous 0x401000 -> - (83%)" ||
        compare_function_text(sectioned) != "Matched 4:0x100 -> 7:0x200 (91%)")
        throw std::runtime_error("function result display must preserve confidence, ambiguity, and section domains");
    const std::vector<hexlab::compare::ChangeRun> runs{
        {hexlab::compare::ChangeKind::changed, "text", 0x1000, 0x2000, 2},
        {hexlab::compare::ChangeKind::added, "data", {}, 0x3000, 1},
        {hexlab::compare::ChangeKind::removed, "text", 0x1010, {}, 4},
        {hexlab::compare::ChangeKind::changed, "rdata", 0x1100, 0x2100, 1}};
    CompareRunFilter filter;
    auto visible = filter_compare_runs(runs, filter);
    if (visible != std::vector<std::size_t>{0, 1, 2, 3})
        throw std::runtime_error("comparison run filter defaults to all results in source order");
    filter.show_added = false;
    filter.text = "TEXT";
    visible = filter_compare_runs(runs, filter);
    if (visible != std::vector<std::size_t>{0, 2})
        throw std::runtime_error("comparison run filter combines case-insensitive text and kind selections");
    filter.show_changed = false;
    visible = filter_compare_runs(runs, filter);
    if (visible != std::vector<std::size_t>{2})
        throw std::runtime_error("comparison run filter updates visible rows consistently");
    const auto forward = next_navigable_compare_run(runs, std::vector<std::size_t>{1, 2, 3}, 0, 1);
    const auto backward = next_navigable_compare_run(runs, std::vector<std::size_t>{0, 1, 2, 3}, 1, -1);
    if (!forward || *forward != 2 || !backward || *backward != 0)
        throw std::runtime_error("comparison navigation skips runs without old-side addresses");

    const auto session_path = std::filesystem::temp_directory_path() / "hexlab-desktop-compare-session.hxcmp";
    std::error_code ec;
    std::filesystem::remove(session_path, ec);
    hexlab::compare::Session session{"old.exe", "new.exe",
        {{10, 4, 2, 3, 1, 1, 1, 0}, {run}}, {matched, ambiguous}};
    auto saved = save_compare_session(session_path, session);
    if (!saved) throw std::runtime_error("desktop comparison session save failed: " + saved.error().message);
    auto unnamed = session;
    unnamed.old_name.clear();
    if (save_compare_session(session_path.string() + ".bad", unnamed))
        throw std::runtime_error("desktop comparison session save must reject unnamed inputs");
    if (load_compare_session({}))
        throw std::runtime_error("desktop comparison session open must reject an empty path");
    auto opened = load_compare_session(session_path);
    if (!opened || opened.value().old_name != session.old_name || opened.value().new_name != session.new_name ||
        opened.value().report.runs.size() != 1 || opened.value().functions.size() != 2 ||
        opened.value().functions[1].kind != hexlab::compare::FunctionMatchKind::ambiguous)
        throw std::runtime_error("desktop comparison session open must preserve report and function results");
    const auto invalid_path = session_path.string() + ".invalid";
    {
        std::ofstream invalid(invalid_path, std::ios::binary);
        invalid << "not a comparison session";
    }
    auto rejected = load_compare_session(invalid_path);
    if (rejected) throw std::runtime_error("desktop comparison session open must reject malformed files");
    std::filesystem::remove(session_path, ec);
    std::filesystem::remove(invalid_path, ec);
}
class CompareViewApp final : public wxApp {
    int result_ = 1;
public:
    bool OnInit() override {
        try {
            check_data_and_sessions();
        } catch (const std::exception &error) {
            std::fprintf(stderr, "%s\n", error.what());
            return false;
        }
        auto *parent = new MainFrame;
        show_test_window(parent);
        auto *view = new CompareView(parent, {}, "old", "new", {}, {}, {});
        show_test_window(view);
        CallAfter([this, parent, view] {
            try {
                auto *file = view->GetMenuBar()->GetMenu(0);
                if (!file || file->GetMenuItemCount() != 2 ||
                    file->FindItemByPosition(0)->GetItemLabelText() != "Save Comparison Session As..." ||
                    file->FindItemByPosition(1)->GetItemLabelText() != "Open Comparison Session...")
                    throw std::runtime_error("comparison window must expose session save and open commands");
                auto *main_file = parent->GetMenuBar()->GetMenu(0);
                if (!main_file || !main_file->FindItem(open_compare_session_id))
                    throw std::runtime_error("main File menu must open a comparison session without an existing report");
                if (!wxWindow::FindWindowByName("compare-runs", view) ||
                    !wxWindow::FindWindowByName("compare-functions", view))
                    throw std::runtime_error("session results must reopen in the normal byte and function views");
                result_ = 0;
                std::cout << "desktop comparison view tests passed\n";
            } catch (const std::exception &error) {
                std::fprintf(stderr, "%s\n", error.what());
            }
            parent->Destroy();
            ExitMainLoop();
        });
        return true;
    }
    int OnRun() override { wxApp::OnRun(); return result_; }
};
}
wxIMPLEMENT_APP(CompareViewApp);
