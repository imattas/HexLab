#include "plugins_view.hpp"
#include "support/desktop_test_window.hpp"
#include "main_frame.hpp"

#include <wx/aui/aui.h>
#include <wx/app.h>
#include <wx/button.h>
#include <wx/frame.h>
#include <wx/listctrl.h>
#include <wx/log.h>
#include <wx/notebook.h>
#include <wx/textctrl.h>
#include <cstdio>
#include <cstdint>
#include <array>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <filesystem>
#include <fstream>

using namespace hexlab::plugins;

namespace {
int starts = 0, stops = 0;
std::atomic<int> action_calls{0};
std::atomic<bool> block_action{false}, release_action{false}, action_entered{false};
std::atomic<bool> block_start{false}, release_start{false}, start_entered{false};
std::atomic<bool> block_semantic{false}, release_semantic{false}, semantic_entered{false};
std::atomic<bool> semantic_has_blocked{false}, semantic_active{false};
std::atomic<int> semantic_calls{0}, semantic_exits{0}, module_closes{0}, module_closes_while_active{0};
void plugin_action(void *) {
    if (block_action.load()) {
        action_entered = true;
        while (!release_action.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ++action_calls;
}
int32_t plugin_decode(void *, uint64_t, const uint8_t *data, uint32_t size, HexLabDecodedInstruction *out) {
    if (size == 0 || data[0] != 0x90) return 0;
    out->length = 1; out->flow = HEXLAB_INSTRUCTION_FLOW_NORMAL;
    std::strcpy(out->mnemonic, "plugin-nop");
    return 1;
}
int32_t plugin_semantic_decode(void *, uint64_t, const uint8_t *data, uint32_t size,
                               HexLabSemanticInstruction *out) {
    ++semantic_calls;
    if (block_semantic.load() && !semantic_has_blocked.exchange(true)) {
        semantic_active = true;
        semantic_entered = true;
        while (!release_semantic.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        semantic_active = false;
        ++semantic_exits;
    }
    if (size >= 2 && data[0] == 0xfe && data[1] == 0xed) {
        out->length = 2;
        out->flow = HEXLAB_INSTRUCTION_FLOW_NORMAL;
        std::strcpy(out->mnemonic, "plugin-semantic");
        return 1;
    }
    if (size < 5 || data[0] != 0xe8) return 0;
    out->length = 5;
    out->flow = HEXLAB_INSTRUCTION_FLOW_CALL;
    out->operand_count = 1;
    std::strcpy(out->mnemonic, "plugin-call");
    out->operands[0].kind = HEXLAB_SEMANTIC_RELATIVE;
    out->operands[0].width = 32;
    out->operands[0].access = HEXLAB_SEMANTIC_READ;
    out->operands[0].value = 1;
    return 1;
}
int32_t plugin_start(const HexLabHostApi *host, void **instance) {
    if (block_start.load()) {
        start_entered = true;
        while (!release_start.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ++starts; *instance = reinterpret_cast<void *>(std::uintptr_t{1});
    HexLabProcessorExtension processor{}; processor.struct_size = sizeof(processor);
    processor.api_version = HEXLAB_EXTENSION_API_VERSION; processor.extension_id = "ui.test.cpu";
    processor.architecture_id = "x86_64"; processor.mode_id = "x86_64"; processor.decode = plugin_decode;
    HexLabProcessorExtension semantic = processor;
    semantic.extension_id = "ui.test.semantic";
    semantic.decode_semantic = plugin_semantic_decode;
    return host->register_action(host->host_context, "ui.test.run", "Run UI test", nullptr, plugin_action) == 0 &&
        host->register_processor_extension(host->host_context, &processor) == 0 &&
        host->register_processor_extension(host->host_context, &semantic) == 0 ? 0 : -1;
}
void plugin_stop(void *) { ++stops; }
int32_t plugin_query(uint32_t abi, const HexLabHostApi *, HexLabPluginApi *api) {
    api->struct_size = sizeof(*api); api->abi_major = abi; api->abi_minor = 0;
    api->plugin_id = "ui.test"; api->name = "UI Test Plugin"; api->version = "2.0";
    static const char *caps[] = {"analysis.action", "ui.panel"};
    api->capabilities = caps; api->capability_count = 2; api->start = plugin_start; api->stop = plugin_stop;
    static const HexLabCapability declared[] = {{sizeof(HexLabCapability), 2, 1, 0, "analysis.project"}};
    api->declared_capabilities = declared; api->declared_capability_count = 1;
    return 0;
}
class FakeModules final : public ModuleProvider {
public:
    hexlab::Result<ModuleProvider::Module> open(const std::string &) override {
        return ModuleProvider::Module{this, &lookup, &close};
    }
private:
    static void *lookup(void *, const char *name) {
        return std::strcmp(name, HEXLAB_PLUGIN_QUERY_SYMBOL) == 0 ? reinterpret_cast<void *>(&plugin_query) : nullptr;
    }
    static void close(void *) {
        if (semantic_active.load()) ++module_closes_while_active;
        ++module_closes;
    }
};

void require(bool condition, const char *message) {
    if (!condition) { std::fprintf(stderr, "%s\n", message); std::abort(); }
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
class PluginUiApp final : public wxApp {
public:
    bool OnInit() override {
        starts = stops = 0; action_calls = 0;
        block_action = release_action = action_entered = false;
        block_semantic = release_semantic = semantic_entered = semantic_has_blocked = semantic_active = false;
        semantic_calls = semantic_exits = module_closes = module_closes_while_active = 0;
        auto *main = new hexlab::desktop::MainFrame(std::make_shared<FakeModules>());
        show_test_window(main);
        auto *frame = new wxFrame(nullptr, wxID_ANY, "Plugin view test");
        auto *view = new hexlab::desktop::PluginsView(frame, std::make_shared<FakeModules>());
        analysis_cancels = analysis_refreshes = operation_completions = 0;
        mutation_results.clear();
        view->extensions_changing = [this] { ++analysis_cancels; };
        view->extensions_changed = [this] { ++analysis_refreshes; };
        view->extensions_operation_finished = [this](bool changed) {
            ++operation_completions;
            mutation_results.push_back(changed);
        };
        frame->SetClientSize(800, 400); show_test_window(frame); wxYield();
        CallAfter([this, frame, view, main] {
            try {
                auto *manager = wxAuiManager::GetManager(main);
                require(manager && main->GetMenuBar()->FindItem(hexlab::desktop::plugins_panel_id),
                        "Main frame does not expose its Plugins page");
                wxCommandEvent show_plugins(wxEVT_MENU, hexlab::desktop::plugins_panel_id);
                main->GetEventHandler()->ProcessEvent(show_plugins);
                auto *metadata = manager->GetPane("metadata").window;
                auto *pages = dynamic_cast<wxNotebook *>(metadata);
                auto *main_list = wxWindow::FindWindowByName("plugin-list", main);
                require(manager->GetPane("metadata").IsShown() && pages && main_list &&
                            pages->GetCurrentPage() == main_list->GetParent(),
                        "Plugins menu action did not show the docked plugin manager page");
                auto *path = wxDynamicCast(wxWindow::FindWindowByName("plugin-path", view), wxTextCtrl);
                auto *load = wxWindow::FindWindowByName("plugin-load", view);
                auto *unload = wxWindow::FindWindowByName("plugin-unload", view);
                auto *list = wxDynamicCast(wxWindow::FindWindowByName("plugin-list", view), wxListCtrl);
                auto *actions = wxDynamicCast(wxWindow::FindWindowByName("plugin-action-list", view), wxListCtrl);
                auto *invoke = wxWindow::FindWindowByName("plugin-action-invoke", view);
                auto *status = wxDynamicCast(wxWindow::FindWindowByName("plugin-status", view), wxTextCtrl);
                require(path && load && unload && list && actions && invoke && status,
                        "Plugin view lacks lifecycle, metadata, or action controls");
                block_start = true; release_start = false; start_entered = false;
                path->SetValue("fake-plugin.dll");
                wxCommandEvent load_event(wxEVT_BUTTON, load->GetId()); load->GetEventHandler()->ProcessEvent(load_event);
                require(list->GetItemCount() == 0 && status->GetValue().Contains("Loading or unloading"),
                        "Plugin load blocked the UI event handler");
                require(wait_for([&] { return start_entered.load(); }), "Plugin load worker did not start");
                release_start = true;
                block_start = false;
                require(wait_for([&] { return list->GetItemCount() == 1; }) && starts == 1 &&
                            analysis_cancels == 1 && analysis_refreshes == 1 && operation_completions == 1 &&
                            mutation_results == std::vector<bool>{true},
                        "Load button did not load and start the selected plugin");
                path->SetValue("duplicate-plugin.dll");
                wxCommandEvent duplicate_load(wxEVT_BUTTON, load->GetId()); load->GetEventHandler()->ProcessEvent(duplicate_load);
                require(wait_for([&] { return status->GetValue().Contains("Load failed:"); }) &&
                            analysis_cancels == 2 && analysis_refreshes == 1 && operation_completions == 2 &&
                            mutation_results == std::vector<bool>{true, false},
                        "Failed load was reported as a mutation instead of a recovery-only completion");
                auto analysis_options = view->analysis_options();
                require(analysis_options.semantic_decoder && analysis_options.semantic_decoder_identity,
                        "Desktop plugin manager did not expose plugin-backed analysis options");
                const auto identity_before = analysis_options.semantic_decoder_identity();
                const std::array<std::byte, 5> call_bytes{std::byte{0xe8}, std::byte{0}, std::byte{0},
                                                         std::byte{0}, std::byte{0}};
                auto semantic = analysis_options.semantic_decoder(
                    {hexlab::Architecture::x86_64, hexlab::ExecutionMode::x86_64},
                    {{0}, 0x1000}, call_bytes);
                require(semantic && semantic.value() && semantic.value()->flow == hexlab::FlowKind::call &&
                            semantic.value()->direct_target == hexlab::Address{{0}, 0x1006},
                        "Desktop project analysis options did not preserve plugin call semantics");
                hexlab::Instruction nop{}; nop.address = {{0}, 0x1000};
                nop.context = {hexlab::Architecture::x86_64, hexlab::ExecutionMode::x86_64};
                nop.opcode = hexlab::Opcode::nop; nop.flow = hexlab::FlowKind::fallthrough;
                nop.length = 1; nop.bytes[0] = std::byte{0x90};
                const auto decorated = view->apply_display_extension(nop);
                require(decorated && nop.mnemonic_override == "plugin-nop",
                        "Loaded processor extension did not provide the display mnemonic");
                require(list->GetItemText(0) == "ui.test" && list->GetItemText(0, 1) == "UI Test Plugin" &&
                            list->GetItemText(0, 3).Contains("analysis.action") &&
                            list->GetItemText(0, 3).Contains("analysis.project@2.1"),
                        "Plugin list does not expose ID, metadata, and versioned capabilities");
                require(actions->GetItemCount() == 1 && actions->GetItemText(0, 2) == "Run UI test",
                        "Plugin view does not expose registered actions");
                actions->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                block_action = true; release_action = false; action_entered = false;
                wxCommandEvent invoke_event(wxEVT_BUTTON, invoke->GetId()); invoke->GetEventHandler()->ProcessEvent(invoke_event);
                require(status->GetValue().Contains("Running plugin action") && action_calls == 0,
                        "Plugin action blocked the UI instead of being queued");
                require(wait_for([&] { return action_entered.load(); }), "Plugin action worker did not enter callback");
                require(list->GetItemCount() == 1 && actions->GetItemCount() == 1,
                        "Plugin view stopped responding while an action was running");
                release_action = true; block_action = false;
                require(wait_for([&] { return action_calls.load() == 1 && status->GetValue().Contains("Ran Run UI test"); }),
                        "Plugin action completion was not reported after callback exit");
                require(invoke->IsEnabled(), "Plugin action controls were not restored after callback exit");
                list->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                wxCommandEvent unload_event(wxEVT_BUTTON, unload->GetId()); unload->GetEventHandler()->ProcessEvent(unload_event);
                require(wait_for([&] { return list->GetItemCount() == 0; }) && actions->GetItemCount() == 0 &&
                            stops == 1 && analysis_cancels == 3 && analysis_refreshes == 2 && operation_completions == 3 &&
                            mutation_results == std::vector<bool>{true, false, true},
                        "Unload button did not stop the plugin and remove its actions");
                require(analysis_options.semantic_decoder_identity() != identity_before,
                        "Unloading a semantic plugin did not change the analysis cache identity");
                hexlab::Instruction after_unload{}; after_unload.address = {{0}, 0x1000};
                after_unload.context = {hexlab::Architecture::x86_64, hexlab::ExecutionMode::x86_64};
                after_unload.opcode = hexlab::Opcode::nop; after_unload.flow = hexlab::FlowKind::fallthrough;
                after_unload.length = 1; after_unload.bytes[0] = std::byte{0x90};
                const auto no_extension = view->apply_display_extension(after_unload);
                require(no_extension && after_unload.mnemonic_override.empty() && after_unload.opcode == hexlab::Opcode::nop,
                        "Plugin mnemonic remained after unload");

                // Exercise the actual MainFrame plugin manager and project analysis worker.
                // The standalone panel above has no connection to MainFrame's actor pool.
                auto *main_plugins_list = wxDynamicCast(wxWindow::FindWindowByName("plugin-list", main), wxListCtrl);
                auto *main_plugins = main_plugins_list
                    ? dynamic_cast<hexlab::desktop::PluginsView *>(main_plugins_list->GetParent()) : nullptr;
                require(main_plugins != nullptr, "Could not find MainFrame's plugin manager");
                auto *main_path = wxDynamicCast(wxWindow::FindWindowByName("plugin-path", main_plugins), wxTextCtrl);
                auto *main_load = wxWindow::FindWindowByName("plugin-load", main_plugins);
                auto *main_unload = wxWindow::FindWindowByName("plugin-unload", main_plugins);
                auto *main_status = wxDynamicCast(wxWindow::FindWindowByName("plugin-status", main_plugins), wxTextCtrl);
                require(main_path && main_load && main_unload && main_status,
                        "MainFrame plugin manager lacks lifecycle controls");
                const auto closes_before_main_plugin = module_closes.load();
                main_path->SetValue("semantic-project-plugin.dll");
                wxCommandEvent main_load_event(wxEVT_BUTTON, main_load->GetId());
                main_load->GetEventHandler()->ProcessEvent(main_load_event);
                const bool main_plugin_loaded = wait_for([&] { return main_plugins_list->GetItemCount() == 1; });
                if (!main_plugin_loaded)
                    std::fprintf(stderr, "quiescence: main plugin load failed; status=%s\n",
                                 main_status->GetValue().utf8_str().data());
                require(main_plugin_loaded, "Could not load semantic plugin into MainFrame's plugin manager");

                const auto test_path = std::filesystem::temp_directory_path() /
                    ("hexlab-plugin-quiescence-" + std::to_string(
                        std::chrono::steady_clock::now().time_since_epoch().count()) + ".bin");
                {
                    const std::array<unsigned char, 8> bytes{0xfe, 0xed, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3};
                    std::ofstream binary(test_path, std::ios::binary);
                    binary.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
                    require(bool(binary), "Could not create the semantic callback fixture");
                }
                block_semantic = true;
                release_semantic = false;
                semantic_entered = false;
                semantic_has_blocked = false;
                hexlab::OpenRequest request;
                request.path = test_path;
                request.format = hexlab::Format::raw;
                request.raw = hexlab::RawOptions{hexlab::Architecture::x86_64,
                    hexlab::ExecutionMode::x86_64, {{0}, 0x1000}, true, false, true,
                    hexlab::Address{{0}, 0x1000}};
                main->OpenDocument(std::move(request));
                require(wait_for([&] { return semantic_entered.load(); }),
                        "MainFrame project analysis never entered the semantic plugin callback");
                main_plugins_list->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
                wxCommandEvent main_unload_event(wxEVT_BUTTON, main_unload->GetId());
                main_unload->GetEventHandler()->ProcessEvent(main_unload_event);
                require(wait_for([&] { return main_status->GetValue().Contains("Loading or unloading"); }),
                        "MainFrame did not begin asynchronous plugin unload");
                for (int i = 0; i < 25; ++i) {
                    wxYield();
                    std::this_thread::sleep_for(std::chrono::milliseconds(2));
                }
                const bool still_quiescing = main_plugins_list->GetItemCount() == 1 && stops == 1 &&
                    module_closes == closes_before_main_plugin &&
                    module_closes_while_active == 0 && semantic_active;
                if (!still_quiescing)
                    std::fprintf(stderr, "quiescence: pre-release state list=%ld stops=%d closes=%d closes_active=%d active=%d\n",
                                 static_cast<long>(main_plugins_list->GetItemCount()), stops,
                                 module_closes.load(), module_closes_while_active.load(), semantic_active.load());
                release_semantic = true;
                const bool unload_completed = wait_for([&] { return main_plugins_list->GetItemCount() == 0; });
                require(still_quiescing && unload_completed && semantic_exits == 1 && stops == 2 &&
                            module_closes == closes_before_main_plugin + 1 &&
                            module_closes_while_active == 0 && !semantic_active,
                        "Plugin unload did not wait for the active semantic callback to exit (see sampled pre-release state)");
                const auto callbacks_at_unload = semantic_calls.load();
                require(wait_for([&] {
                            const auto docs = main->projects().documents();
                            return !docs.empty() && !docs.front().analysis_pending;
                        }), "Post-unload project analysis did not finish with the new plugin set");
                for (int i = 0; i < 25; ++i) {
                    wxYield();
                    std::this_thread::sleep_for(std::chrono::milliseconds(2));
                }
                require(semantic_calls == callbacks_at_unload && module_closes_while_active == 0,
                        "Post-unload analysis reused the unloaded plugin callback");
                std::error_code remove_error;
                std::filesystem::remove(test_path, remove_error);
                result_ = 0;
            } catch (const std::exception &error) {
                std::fprintf(stderr, "%s\n", error.what());
            }
                frame->Close(); main->Close(); ExitMainLoop();
        });
        return true;
    }
    int OnRun() override { wxApp::OnRun(); return result_; }
private:
    int result_ = 1;
    int analysis_cancels = 0, analysis_refreshes = 0, operation_completions = 0;
    std::vector<bool> mutation_results;
};
}
wxIMPLEMENT_APP(PluginUiApp);
