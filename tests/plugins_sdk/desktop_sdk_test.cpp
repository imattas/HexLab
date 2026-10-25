#include "main_frame.hpp"
#include "../support/desktop_test_window.hpp"
#include "../support/elf_fixture.hpp"

#include <wx/app.h>
#include <wx/button.h>
#include <wx/listctrl.h>
#include <wx/textctrl.h>

#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <thread>

namespace {
bool set_environment(const char *key, const std::string& value) {
#if defined(_WIN32)
    return _putenv_s(key, value.c_str()) == 0;
#else
    return setenv(key, value.c_str(), 1) == 0;
#endif
}
struct EnvironmentGuard {
    std::optional<std::string> input;
    std::optional<std::string> project;
    EnvironmentGuard() {
        if (const auto *value = std::getenv("HEXLAB_SDK_INPUT")) input = value;
        if (const auto *value = std::getenv("HEXLAB_SDK_PROJECT")) project = value;
    }
    ~EnvironmentGuard() {
        set_environment("HEXLAB_SDK_INPUT", input.value_or(""));
        set_environment("HEXLAB_SDK_PROJECT", project.value_or(""));
    }
};
void require(bool value, const char *message) {
    if (!value) throw std::runtime_error(message);
}
template<class Predicate> bool wait_for(Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        wxYield();
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    wxYield();
    return predicate();
}
class SdkPluginUiTest final : public wxApp {
public:
    bool OnInit() override {
        const char *module_path = std::getenv("HEXLAB_TEST_PLUGIN_PATH");
        if (!module_path || !*module_path) return false;
        const auto fixture_dir = std::filesystem::temp_directory_path() /
            ("hexlab_native_sdk_ui_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::error_code ignored;
        std::filesystem::create_directories(fixture_dir);
        const auto input = fixture_dir / "sample.elf";
        const auto project = fixture_dir / "sample.hxproj";
        auto bytes = hexlab_test::elf_fixture::executable(true);
        hexlab_test::elf_fixture::program(bytes, true, 0, 1, 256, 0x400000, 32, 32, 5, 256);
        bytes[256] = std::byte{0xe8}; bytes[257] = std::byte{1}; bytes[258] = std::byte{0};
        bytes[259] = std::byte{0}; bytes[260] = std::byte{0}; bytes[261] = std::byte{0xc3};
        bytes[262] = std::byte{0xc3};
        constexpr char embedded[] = "HexLab SDK string";
        for (std::size_t i = 0; i < sizeof(embedded); ++i) bytes[263 + i] = std::byte(embedded[i]);
        { std::ofstream file(input, std::ios::binary); file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())); }
        auto environment = std::make_shared<EnvironmentGuard>();
        if (!set_environment("HEXLAB_SDK_INPUT", input.string()) ||
            !set_environment("HEXLAB_SDK_PROJECT", project.string())) return false;
        auto *frame = new hexlab::desktop::MainFrame;
        show_test_window(frame);
        const std::string module(module_path);
        CallAfter([this, frame, fixture_dir, environment, module] {
            try {
                auto *view = wxWindow::FindWindowByName("plugin-list", frame);
                auto *list = wxDynamicCast(view, wxListCtrl);
                auto *path = wxDynamicCast(wxWindow::FindWindowByName("plugin-path", frame), wxTextCtrl);
                auto *load = wxWindow::FindWindowByName("plugin-load", frame);
                auto *unload = wxWindow::FindWindowByName("plugin-unload", frame);
                auto *actions = wxDynamicCast(wxWindow::FindWindowByName("plugin-action-list", frame), wxListCtrl);
                auto *invoke = wxWindow::FindWindowByName("plugin-action-invoke", frame);
                auto *status = wxDynamicCast(wxWindow::FindWindowByName("plugin-status", frame), wxTextCtrl);
                require(list && path && load && unload && actions && invoke && status,
                        "Main window plugin manager controls were not created");
                path->SetValue(wxString::FromUTF8(module.c_str()));
                wxCommandEvent load_event(wxEVT_BUTTON, load->GetId());
                load->GetEventHandler()->ProcessEvent(load_event);
                if (!wait_for([&] { return list->GetItemCount() == 1; }))
                    std::fprintf(stderr, "SDK plugin load status: %s\n",
                                 status->GetValue().ToStdString().c_str());
                require(list->GetItemCount() == 1 && list->GetItemText(0) == "org.hexlab.example" &&
                            list->GetItemText(0, 1) == "HexLab C SDK example",
                        "Desktop did not load the compiled C SDK module or show its metadata");
                require(actions->GetItemCount() == 1 && actions->GetItemText(0, 1) == "sample.inspect",
                        "Desktop did not display the SDK module's registered action");
                actions->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                wxCommandEvent invoke_event(wxEVT_BUTTON, invoke->GetId());
                invoke->GetEventHandler()->ProcessEvent(invoke_event);
                require(status->GetValue().Contains("Ran Sample inspect"),
                        "Desktop did not invoke the SDK action");
                list->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                wxCommandEvent unload_event(wxEVT_BUTTON, unload->GetId());
                unload->GetEventHandler()->ProcessEvent(unload_event);
                require(wait_for([&] { return list->GetItemCount() == 0; }) && actions->GetItemCount() == 0,
                        "Desktop did not unload the SDK module and remove its action");
                result_ = 0;
            } catch (const std::exception &error) {
                std::fprintf(stderr, "%s\n", error.what());
            }
            frame->Close();
            std::error_code ignored;
            std::filesystem::remove_all(fixture_dir, ignored);
            (void)environment;
            ExitMainLoop();
        });
        return true;
    }
    int OnRun() override { wxApp::OnRun(); return result_; }
private:
    int result_ = 1;
};
}
wxIMPLEMENT_APP(SdkPluginUiTest);
