#include "main_frame.hpp"
#include <wx/app.h>
#include <wx/cmdline.h>
#include <wx/aui/floatpane.h>
#include <wx/display.h>

namespace hexlab::desktop {
class Application final : public wxApp {
public:
    void OnInitCmdLine(wxCmdLineParser& parser) override {
        wxApp::OnInitCmdLine(parser);
        parser.AddSwitch("", "smoke-test", "Exercise desktop startup and shutdown");
        parser.AddSwitch("", "smoke-test-floating", "Exercise floating pane close and shutdown");
        parser.AddParam("binary",wxCMD_LINE_VAL_STRING,wxCMD_LINE_PARAM_OPTIONAL);
    }
    bool OnCmdLineParsed(wxCmdLineParser& parser) override {
        floating_smoke_ = parser.Found("smoke-test-floating");
        smoke_ = parser.Found("smoke-test") || floating_smoke_;
        if(parser.GetParamCount())path_=parser.GetParam(0);
        return wxApp::OnCmdLineParsed(parser);
    }
    bool OnInit() override {
        if (!wxApp::OnInit()) return false;
        SetAppName("HexLab");
        auto* frame = new MainFrame;
        SetTopWindow(frame);
        if (wxDisplay::GetCount() > 1) {
            wxDisplay display(1);
            const auto area = display.GetClientArea();
            frame->SetPosition({area.x + 16, area.y + 16});
        }
        // Keep launch from pulling focus away from a foreground application.
        frame->ShowWithoutActivating();
        if(!path_.empty()) {
            const std::filesystem::path input=path_.ToStdWstring();
            if(wxString(input.extension().wstring()).CmpNoCase(".hxproj")==0) {
                frame->OpenProject(input);
            } else {
                OpenRequest request;
                request.path=input;
                frame->OpenDocument(std::move(request));
            }
        }
        if (smoke_) {
            result_ = 1;
            CallAfter([this, frame] {
                auto* manager = wxAuiManager::GetManager(frame);
                if (manager) {
                    auto& functions = manager->GetPane("functions");
                    auto& symbols = manager->GetPane("symbols");
                    auto& output = manager->GetPane("output");
                    if (functions.IsOk() && symbols.IsOk() && output.IsOk()) {
                        functions.Float();
                        symbols.Hide();
                        output.Hide();
                        manager->Update();
                        wxCommandEvent reset(wxEVT_MENU, reset_layout_id);
                        frame->GetEventHandler()->ProcessEvent(reset);
                        auto& restored = manager->GetPane("functions");
                        if (restored.IsShown() && restored.IsDocked() &&
                            manager->GetPane("symbols").IsShown() &&
                            manager->GetPane("output").IsShown()) result_ = 0;
                        if (floating_smoke_ && result_ == 0) {
                            result_ = 1;
                            restored.Float();
                            manager->Update();
                            if (restored.frame && restored.frame->Close() && !restored.IsShown()) {
                                CallAfter([this, frame, manager] {
                                    frame->ResetLayout();
                                    auto& pane = manager->GetPane("functions");
                                    pane.Float();
                                    manager->Update();
                                    if (pane.IsShown() && pane.IsFloating() && pane.frame) result_ = 0;
                                    frame->Close();
                                });
                                return;
                            }
                        }
                    }
                }
                frame->Close();
            });
        }
        return true;
    }
    int OnRun() override {
        const int loop_result = wxApp::OnRun();
        return smoke_ ? result_ : loop_result;
    }
private:
    bool smoke_ = false;
    bool floating_smoke_ = false;
    int result_ = 0;
    wxString path_;
};
}
wxIMPLEMENT_APP(hexlab::desktop::Application);
