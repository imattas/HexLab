#include "archive_view.hpp"
#include "support/desktop_test_window.hpp"
#include <wx/app.h>
#include <wx/frame.h>
#include <wx/listctrl.h>
#include <cstdio>
#include <stdexcept>

using namespace hexlab;
using namespace hexlab::desktop;
namespace {
class ArchiveApp final : public wxApp {
    int result_ = 1;
public:
    bool OnInit() override {
        auto* frame = new wxFrame(nullptr, wxID_ANY, "Archive test");
        show_test_window(frame);
        ArArchive archive;
        archive.members = {{"__.SYMDEF", {0}, {0}, 4, ArMemberKind::symbol_index},
                           {"module.o", {60}, {120}, 8, ArMemberKind::regular}};
        archive.has_symbol_index = true;
        archive.symbols = {{"exported_symbol", 1}};
        auto* view = new ArchiveView(frame, archive);
        CallAfter([this, frame, view] {
            auto* list = dynamic_cast<wxListCtrl*>(wxWindow::FindWindowByName("ar-member-list", view));
            auto* symbols = dynamic_cast<wxListCtrl*>(wxWindow::FindWindowByName("ar-symbol-list", view));
            try {
                if (!list || list->GetItemCount() != 2) throw std::runtime_error("archive member rows were not displayed");
                if (!symbols || symbols->GetItemCount() != 1 || symbols->GetItemText(0) != "exported_symbol")
                    throw std::runtime_error("indexed archive symbols were not displayed");
                if (symbols->GetItemText(0, 1) != "module.o")
                    throw std::runtime_error("indexed symbol did not resolve to its member name");
                symbols->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                if (view->selected_member() != 1)
                    throw std::runtime_error("indexed symbol selection did not select its archive member");
                symbols->SetItemState(0, 0, wxLIST_STATE_SELECTED);
                list->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                if (view->selected_member()) throw std::runtime_error("symbol index was made openable");
                list->SetItemState(0, 0, wxLIST_STATE_SELECTED);
                list->SetItemState(1, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                if (view->selected_member() != 1) throw std::runtime_error("regular member selection did not preserve stable index");
                result_ = 0;
            } catch (const std::exception& error) { std::fprintf(stderr, "%s\n", error.what()); }
            frame->Destroy();
            ExitMainLoop();
        });
        return true;
    }
    int OnRun() override { wxApp::OnRun(); return result_; }
};
}
wxIMPLEMENT_APP(ArchiveApp);
