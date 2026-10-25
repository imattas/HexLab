#include "plugins_view.hpp"
#include "hexlab/plugins/runtime.hpp"

#include <wx/button.h>
#include <wx/dirdlg.h>
#include <wx/filedlg.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/app.h>
#include <algorithm>
#include <string_view>
#include <thread>
#include <mutex>

namespace hexlab::desktop {
namespace {
wxString string(const std::string &value) { return wxString::FromUTF8(value.c_str()); }
std::string bounded_display(std::string_view value, std::size_t maximum_bytes) {
    if (value.size() <= maximum_bytes) return std::string(value);
    constexpr std::string_view suffix = "...";
    std::size_t end = maximum_bytes > suffix.size() ? maximum_bytes - suffix.size() : 0;
    while (end > 0 && (static_cast<unsigned char>(value[end]) & 0xc0u) == 0x80u) --end;
    std::string result(value.substr(0, end));
    result += suffix;
    return result;
}
std::string manifest_capability_summary(const plugins::PluginCandidate &candidate) {
    if (!candidate.manifest) {
        if (!candidate.manifest_error.empty()) return "Invalid sidecar; identity unverified";
        return "No sidecar; identity unverified";
    }
    const auto &manifest = *candidate.manifest;
    std::string result;
    constexpr std::size_t visible_limit = 4;
    if (!manifest.capabilities.empty()) result = "provides ";
    for (std::size_t index = 0; index < manifest.capabilities.size() && index < visible_limit; ++index) {
        if (index != 0) result += ", ";
        const auto &capability = manifest.capabilities[index];
        result += capability.id + "@" + std::to_string(capability.major_version) + "." +
                  std::to_string(capability.minor_version);
    }
    if (manifest.capabilities.size() > visible_limit)
        result += ", ... +" + std::to_string(manifest.capabilities.size() - visible_limit) + " provided";
    if (manifest.required_capabilities.empty()) {
        if (!result.empty()) result += "; ";
        result += "no requirements";
    }
    for (std::size_t index = 0; index < manifest.required_capabilities.size() && index < visible_limit; ++index) {
        if (!result.empty()) result += "; ";
        const auto &capability = manifest.required_capabilities[index];
        result += "requires " + capability.id + "@" + std::to_string(capability.major_version) + "." +
                  std::to_string(capability.minor_version) + ": ";
        const auto resolution = std::find_if(candidate.requirement_preflight.begin(),
            candidate.requirement_preflight.end(), [&](const auto &status) {
                return status.capability.id == capability.id &&
                       status.capability.major_version == capability.major_version &&
                       status.capability.minor_version == capability.minor_version;
            });
        if (resolution == candidate.requirement_preflight.end()) {
            result += "not checked";
            continue;
        }
        switch (resolution->resolution) {
        case plugins::PluginRequirementResolution::host:
            result += "host";
            break;
        case plugins::PluginRequirementResolution::loaded_plugin:
            result += "plugin " + resolution->provider_plugin_id;
            break;
        case plugins::PluginRequirementResolution::candidate_plugin:
            result += "candidate " + resolution->provider_plugin_id + " (not loaded)";
            break;
        case plugins::PluginRequirementResolution::unavailable:
            result += "unavailable";
            break;
        case plugins::PluginRequirementResolution::ambiguous:
            result += "multiple providers";
            break;
        }
    }
    if (manifest.required_capabilities.size() > visible_limit) {
        if (!result.empty()) result += "; ";
        result += "... +" + std::to_string(manifest.required_capabilities.size() - visible_limit) + " requirements";
    }
    if (!result.empty()) result += "; ";
    result += "sidecar advisory; module identity unverified";
    return result;
}
std::string utf8(const wxString &value) {
    const auto encoded = value.utf8_str();
    return {encoded.data(), encoded.length()};
}
}
struct PluginsView::OperationState {
    std::mutex mutex;
    PluginsView *target = nullptr;
    OperationResult result;
    bool lifecycle = true;
};

PluginsView::PluginsView(wxWindow *parent, std::shared_ptr<plugins::ModuleProvider> provider)
    : wxPanel(parent), manager_(std::make_shared<plugins::PluginManager>(std::move(provider))),
      operation_state_(std::make_shared<OperationState>()) {
    operation_state_->target = this;
    auto *root = new wxBoxSizer(wxVERTICAL);
    auto *controls = new wxBoxSizer(wxHORIZONTAL);
    path_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize);
    path_->SetName("plugin-path");
    controls->Add(path_, 1, wxEXPAND | wxRIGHT, FromDIP(4));
    load_button_ = new wxButton(this, wxID_ANY, "Load Plugin");
    load_button_->SetName("plugin-load");
    scan_button_ = new wxButton(this, wxID_ANY, "Scan Directory...");
    scan_button_->SetName("plugin-scan-directory");
    unload_button_ = new wxButton(this, wxID_ANY, "Unload Selected");
    unload_button_->SetName("plugin-unload");
    unload_dependents_button_ = new wxButton(this, wxID_ANY, "Unload With Dependents");
    unload_dependents_button_->SetName("plugin-unload-dependents");
    controls->Add(load_button_, 0, wxRIGHT, FromDIP(4));
    controls->Add(scan_button_, 0, wxRIGHT, FromDIP(4));
    controls->Add(unload_button_, 0, wxRIGHT, FromDIP(4));
    controls->Add(unload_dependents_button_, 0);
    root->Add(controls, 0, wxEXPAND | wxALL, FromDIP(5));

    auto *candidate_controls = new wxBoxSizer(wxHORIZONTAL);
    candidate_controls->Add(new wxStaticText(this, wxID_ANY, "Discovered modules (not loaded)"), 1,
                            wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(6));
    load_candidate_button_ = new wxButton(this, wxID_ANY, "Load Selected Candidate");
    load_candidate_button_->SetName("plugin-candidate-load");
    plan_button_ = new wxButton(this, wxID_ANY, "Preview Dependencies");
    plan_button_->SetName("plugin-candidate-plan");
    load_dependencies_button_ = new wxButton(this, wxID_ANY, "Load With Dependencies");
    load_dependencies_button_->SetName("plugin-candidate-load-dependencies");
    candidate_controls->Add(plan_button_, 0, wxRIGHT, FromDIP(4));
    candidate_controls->Add(load_dependencies_button_, 0, wxRIGHT, FromDIP(4));
    candidate_controls->Add(load_candidate_button_, 0);
    root->Add(candidate_controls, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, FromDIP(5));
    candidates_ = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                                 wxLC_REPORT | wxLC_SINGLE_SEL | wxLC_HRULES | wxLC_VRULES);
    candidates_->SetName("plugin-candidate-list");
    candidates_->InsertColumn(0, "Candidate path");
    candidates_->InsertColumn(1, "Sidecar identity (unverified)");
    candidates_->InsertColumn(2, "Version");
    candidates_->InsertColumn(3, "Capabilities / available providers (advisory)");
    candidates_->SetMinSize(wxSize(-1, FromDIP(86)));
    root->Add(candidates_, 0, wxEXPAND | wxLEFT | wxRIGHT, FromDIP(5));

    list_ = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                           wxLC_REPORT | wxLC_SINGLE_SEL | wxLC_HRULES | wxLC_VRULES);
    list_->SetName("plugin-list");
    for (const auto *column : {"ID", "Name", "Version", "Capabilities"})
        list_->InsertColumn(list_->GetColumnCount(), column);
    root->Add(list_, 1, wxEXPAND | wxLEFT | wxRIGHT, FromDIP(5));
    auto *action_controls = new wxBoxSizer(wxHORIZONTAL);
    action_controls->Add(new wxStaticText(this, wxID_ANY, "Registered actions"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(6));
    invoke_button_ = new wxButton(this, wxID_ANY, "Run Selected Action");
    invoke_button_->SetName("plugin-action-invoke");
    action_controls->Add(invoke_button_, 0);
    root->Add(action_controls, 0, wxLEFT | wxRIGHT | wxTOP, FromDIP(5));
    actions_ = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                              wxLC_REPORT | wxLC_SINGLE_SEL | wxLC_HRULES | wxLC_VRULES);
    actions_->SetName("plugin-action-list");
    actions_->InsertColumn(0, "Plugin");
    actions_->InsertColumn(1, "Action ID");
    actions_->InsertColumn(2, "Label");
    root->Add(actions_, 0, wxEXPAND | wxALL, FromDIP(5));
    auto *provider_controls = new wxBoxSizer(wxHORIZONTAL);
    provider_controls->Add(new wxStaticText(this, wxID_ANY, "Project file"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(5));
    project_path_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize);
    project_path_->SetName("plugin-analysis-project-path");
    provider_controls->Add(project_path_, 1, wxEXPAND | wxRIGHT, FromDIP(5));
    provider_button_ = new wxButton(this, wxID_ANY, "Run Analysis Provider");
    provider_button_->SetName("plugin-analysis-provider-run");
    provider_controls->Add(provider_button_, 0);
    root->Add(provider_controls, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, FromDIP(5));
    providers_ = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                                wxLC_REPORT | wxLC_SINGLE_SEL | wxLC_HRULES | wxLC_VRULES);
    providers_->SetName("plugin-analysis-provider-list");
    providers_->InsertColumn(0, "Plugin"); providers_->InsertColumn(1, "Provider ID"); providers_->InsertColumn(2, "Name");
    root->Add(providers_, 0, wxEXPAND | wxLEFT | wxRIGHT, FromDIP(5));
    status_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize,
                             wxTE_READONLY | wxTE_RICH2 | wxTE_MULTILINE);
    status_->SetName("plugin-status");
    status_->SetMinSize(wxSize(-1, FromDIP(90)));
    root->Add(status_, 0, wxEXPAND | wxALL, FromDIP(5));
    SetSizer(root);
    load_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { load(); });
    scan_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { scan_directory(); });
    load_candidate_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { load_candidate(); });
    plan_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { plan_candidate(); });
    load_dependencies_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { load_candidate_dependencies(); });
    unload_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { unload(); });
    unload_dependents_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { unload_dependents(); });
    invoke_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { invoke_action(); });
    provider_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { run_provider(); });
    refresh();
    const auto manager = manager_;
    const auto state = operation_state_;
    operation_thread_ = std::thread([this, manager, state] {
        for (;;) {
            std::function<OperationResult()> operation;
            bool lifecycle = true;
            {
                std::unique_lock lock(operation_mutex_);
                operation_changed_.wait(lock, [this] { return operation_stopping_ || bool(queued_operation_); });
                if (operation_stopping_ && !queued_operation_) break;
                operation = std::move(queued_operation_);
                queued_operation_ = {};
                lifecycle = queued_operation_lifecycle_;
            }
            OperationResult result;
            try {
                if (lifecycle && extensions_quiesce) extensions_quiesce();
                result = operation();
            } catch (const std::exception &error) {
                result.message = std::string("Plugin operation failed: ") + error.what();
            } catch (...) {
                result.message = "Plugin operation failed with an unknown error.";
            }
            {
                std::lock_guard lock(state->mutex);
                state->result = std::move(result);
                state->lifecycle = lifecycle;
            }
            bool alive = false;
            {
                std::lock_guard lock(state->mutex);
                alive = state->target != nullptr;
            }
            if (alive && wxTheApp)
                wxTheApp->CallAfter([state] {
                    PluginsView *target = nullptr;
                    OperationResult result;
                    bool lifecycle = true;
                    {
                        std::lock_guard lock(state->mutex);
                        target = state->target;
                        result = std::move(state->result);
                        lifecycle = state->lifecycle;
                    }
                    if (target) target->finish_operation(std::move(result), lifecycle);
                });
        }
        // Stop and unload every module on the same serialized thread used for
        // plugin start, preserving thread-affine plugin project handles.
        (void)manager->unload_all();
    });
}

PluginsView::~PluginsView() {
    {
        std::lock_guard lock(operation_state_->mutex);
        operation_state_->target = nullptr;
    }
    {
        std::lock_guard lock(operation_mutex_);
        operation_stopping_ = true;
    }
    operation_changed_.notify_one();
    if (operation_thread_.joinable()) operation_thread_.join();
}

plugins::Status PluginsView::apply_display_extension(Instruction &instruction) const {
    return plugins::apply_display_extension(*manager_, instruction);
}

AnalysisOptions PluginsView::analysis_options(AnalysisOptions options) const {
    return manager_->analysis_options(std::move(options));
}

std::vector<plugins::PluginMenuActionInfo> PluginsView::menu_actions() const {
    return manager_->menu_actions();
}

void PluginsView::invoke_menu_action(const std::string &plugin_id, const std::string &action_id,
                                     const std::string &label) {
    if (operation_pending_) {
        report("Wait for the current plugin operation to finish.");
        return;
    }
    start_operation([manager = manager_, plugin_id, action_id, label] {
        const auto result = manager->invoke_action(plugin_id, action_id);
        if (!result) return OperationResult{std::string("Action failed: ") + result.error().message, false};
        return OperationResult{std::string("Ran ") + label + ".", false};
    }, false, "Running plugin action...");
}

void PluginsView::invoke_action() {
    const auto row = actions_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= action_rows_.size()) {
        report("Select a registered action to run.");
        return;
    }
    const auto &action = action_rows_[static_cast<std::size_t>(row)];
    const auto plugin_id = action.plugin_id;
    const auto action_id = action.id;
    const auto label = action.label;
    start_operation([manager = manager_, plugin_id, action_id, label] {
        const auto result = manager->invoke_action(plugin_id, action_id);
        if (!result) return OperationResult{std::string("Action failed: ") + result.error().message, false};
        return OperationResult{std::string("Ran ") + label + ".", false};
    }, false, "Running plugin action...");
}

void PluginsView::run_provider() {
    if (operation_pending_) return;
    const auto row = providers_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= provider_rows_.size()) {
        report("Select a registered analysis provider."); return;
    }
    const auto provider = provider_rows_[static_cast<std::size_t>(row)];
    const auto project = utf8(project_path_->GetValue());
    if (project.empty()) { report("Enter the path to a saved project file."); return; }
    start_operation([manager = manager_, provider, project] {
        const auto result = manager->run_analysis_provider(provider.plugin_id, provider.provider_id, project);
        if (!result) return OperationResult{std::string("Analysis provider failed: ") + result.error().message, false};
        return OperationResult{result.value().empty() ? std::string("Analysis provider completed with no report.") : result.value(), false};
    }, false, "Running analysis provider...");
}

void PluginsView::load() {
    if (operation_pending_) return;
    auto path = path_->GetValue();
    if (path.empty()) {
#ifdef __WXMSW__
        constexpr const char *wildcard = "Plugin libraries (*.dll)|*.dll|All files (*.*)|*.*";
#elif defined(__APPLE__)
        constexpr const char *wildcard = "Plugin libraries (*.dylib)|*.dylib|All files (*.*)|*";
#else
        constexpr const char *wildcard = "Plugin libraries (*.so, *.so.*)|*.so;*.so.*|All files (*)|*";
#endif
        wxFileDialog dialog(this, "Load Plugin", {}, {}, wildcard, wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (dialog.ShowModal() != wxID_OK) return;
        path = dialog.GetPath();
    }
    const auto module = utf8(path);
    path_->Clear();
    if (extensions_changing) extensions_changing();
    start_operation([manager = manager_, module] {
        const auto loaded = manager->load(module);
        if (!loaded) return OperationResult{std::string("Load failed: ") + loaded.error().message, false};
        return OperationResult{std::string("Loaded ") + loaded.value().name + " (" + loaded.value().id + ").", true};
    });
}

void PluginsView::scan_directory() {
    if (operation_pending_) return;
    wxDirDialog dialog(this, "Choose plugin directory", {}, wxDD_DEFAULT_STYLE | wxDD_DIR_MUST_EXIST);
    if (dialog.ShowModal() != wxID_OK) return;
    const auto directory = utf8(dialog.GetPath());
    start_operation([manager = manager_, directory] {
        const auto scanned = manager->scan_directory(directory);
        if (!scanned) return OperationResult{std::string("Plugin scan failed: ") + scanned.error().message,
                                              false, true, {}};
        OperationResult result;
        result.message = "Found " + std::to_string(scanned.value().size()) +
            " candidate(s). Select one to preview or load its dependencies, or load that module alone. Scanning does not load modules.";
        result.replace_candidates = true;
        result.candidates = std::move(scanned.value());
        return result;
    }, false, "Scanning plugin directory (modules are not loaded)...");
}

void PluginsView::load_candidate() {
    if (operation_pending_) return;
    const auto row = candidates_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= candidate_rows_.size()) {
        report("Select a discovered candidate before loading it.");
        return;
    }
    const auto candidate = candidate_rows_[static_cast<std::size_t>(row)];
    if (extensions_changing) extensions_changing();
    start_operation([manager = manager_, candidate] {
        const auto loaded = manager->load(candidate.path);
        if (!loaded) return OperationResult{std::string("Load failed: ") + loaded.error().message, false};
        std::string message = std::string("Loaded ") + loaded.value().name + " (" + loaded.value().id + ").";
        if (candidate.manifest) {
            if (plugins::manifest_matches(*candidate.manifest, loaded.value())) {
                message += " The sidecar identity and provided and required capabilities match the loaded plugin.";
            } else {
                message += " Warning: the sidecar identity or capability declarations do not match the loaded plugin.";
            }
        } else if (!candidate.manifest_error.empty()) {
            message += " Warning: the sidecar was invalid or unreadable, so loaded metadata is unverified.";
        } else {
            message += " No sidecar manifest was found; loaded metadata is unverified.";
        }
        return OperationResult{std::move(message), true};
    }, true, "Loading selected plugin candidate...");
}

void PluginsView::plan_candidate() {
    if (operation_pending_) return;
    const auto row = candidates_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= candidate_rows_.size()) {
        report("Select a discovered candidate to preview its dependencies.");
        return;
    }
    const auto root_path = candidate_rows_[static_cast<std::size_t>(row)].path;
    start_operation([manager = manager_, candidates = candidate_rows_, root_path] {
        const auto plan = manager->plan_activation(candidates, root_path);
        if (!plan) return OperationResult{"Dependency plan failed: " + plan.error().message, false};
        std::string message = "Activation order (" + std::to_string(plan.value().size()) +
            " new modules; existing providers stay loaded):\n";
        constexpr std::size_t visible_limit = 32;
        for (std::size_t index = 0; index < plan.value().size() && index < visible_limit; ++index) {
            const auto& candidate = plan.value()[index];
            message += std::to_string(index + 1) + ". " + candidate.manifest->id + " " +
                candidate.manifest->version + " -- " + bounded_display(candidate.path, 240) + "\n";
        }
        if (plan.value().size() > visible_limit)
            message += "... " + std::to_string(plan.value().size() - visible_limit) + " additional modules\n";
        message += "Preview uses sidecar declarations only and does not open modules. Load With Dependencies rechecks this plan and verifies each module before start.";
        return OperationResult{std::move(message), false};
    }, false, "Planning plugin dependencies (modules are not loaded)...");
}

void PluginsView::load_candidate_dependencies() {
    if (operation_pending_) return;
    const auto row = candidates_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= candidate_rows_.size()) {
        report("Select a discovered candidate before loading its dependencies.");
        return;
    }
    const auto root_path = candidate_rows_[static_cast<std::size_t>(row)].path;
    if (extensions_changing) extensions_changing();
    start_operation([manager = manager_, candidates = candidate_rows_, root_path] {
        const auto loaded = manager->load_with_dependencies(candidates, root_path);
        if (!loaded) return OperationResult{"Dependency activation failed: " + loaded.error().message, false};
        std::string message = "Activated " + std::to_string(loaded.value().size()) + " plugin(s) in dependency order: ";
        for (const auto& plugin : loaded.value()) {
            if (message.back() != ' ') message += ", ";
            message += plugin.id;
        }
        message += ". All newly loaded modules matched their planned manifests.";
        return OperationResult{std::move(message), true};
    }, true, "Loading selected plugin and its dependencies...");
}

void PluginsView::unload_dependents() {
    if (operation_pending_) return;
    const auto row = list_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= ids_.size()) {
        report("Select a loaded plugin to unload with its dependents.");
        return;
    }
    const auto id = ids_[static_cast<std::size_t>(row)];
    if (extensions_changing) extensions_changing();
    start_operation([manager = manager_, id] {
        const auto removed = manager->unload_with_dependents(id);
        if (!removed) return OperationResult{"Unload failed: " + removed.error().message, false};
        std::string message = "Unloaded in consumer-first order: ";
        for (const auto& plugin_id : removed.value()) {
            if (message.back() != ' ') message += ", ";
            message += plugin_id;
        }
        return OperationResult{message + ".", true};
    }, true, "Unloading selected plugin and its dependents...");
}

void PluginsView::unload() {
    if (operation_pending_) return;
    const auto row = list_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= ids_.size()) {
        report("Select a loaded plugin to unload.");
        return;
    }
    const auto id = ids_[static_cast<std::size_t>(row)];
    if (extensions_changing) extensions_changing();
    start_operation([manager = manager_, id] {
        const auto result = manager->unload(id);
        if (!result) return OperationResult{std::string("Unload failed: ") + result.error().message, false};
        return OperationResult{std::string("Unloaded ") + id + ".", true};
    });
}

void PluginsView::start_operation(std::function<OperationResult()> operation, bool lifecycle,
                                  std::string pending_message) {
    if (operation_pending_) {
        report("Wait for the current plugin operation to finish.");
        return;
    }
    // Reuse the scanned manifests, but refresh provider availability on the
    // worker after every lifecycle attempt, including a rolled-back activation.
    // No filesystem scan or native module query runs on the UI thread.
    auto operation_with_preflight = [manager = manager_, operation = std::move(operation), lifecycle,
        candidates = lifecycle ? candidate_rows_ : std::vector<plugins::PluginCandidate>{}]() mutable {
        auto result = operation();
        if (lifecycle && !result.replace_candidates) {
            try {
                auto refreshed = manager->refresh_requirement_preflight(candidates);
                if (refreshed) {
                    result.candidates = std::move(candidates);
                    result.replace_candidates = true;
                } else {
                    result.message += " Provider availability could not be refreshed: " + refreshed.error().message;
                }
            } catch (...) {
                // A display-only refresh failure must not hide an inventory
                // change or suppress extension/menu invalidation callbacks.
                result.message += " Provider availability could not be refreshed; scan again to update it.";
            }
        }
        return result;
    };
    operation_pending_ = true;
    load_button_->Disable(); unload_button_->Disable(); invoke_button_->Disable(); provider_button_->Disable();
    scan_button_->Disable(); load_candidate_button_->Disable(); candidates_->Disable();
    plan_button_->Disable(); load_dependencies_button_->Disable(); unload_dependents_button_->Disable();
    report(string(pending_message));
    {
        std::lock_guard lock(operation_mutex_);
        queued_operation_ = std::move(operation_with_preflight);
        queued_operation_lifecycle_ = lifecycle;
    }
    operation_changed_.notify_one();
}

void PluginsView::finish_operation(OperationResult result, bool lifecycle) {
    operation_pending_ = false;
    load_button_->Enable(); unload_button_->Enable(); scan_button_->Enable(); candidates_->Enable();
    if (result.replace_candidates) {
        const auto selected_row = candidates_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        const auto selected_path = selected_row >= 0 && static_cast<std::size_t>(selected_row) < candidate_rows_.size()
            ? candidate_rows_[static_cast<std::size_t>(selected_row)].path : std::string{};
        candidate_rows_ = std::move(result.candidates);
        candidates_->DeleteAllItems();
        for (const auto &candidate : candidate_rows_) {
            const auto row = candidates_->InsertItem(candidates_->GetItemCount(), string(bounded_display(candidate.path, 240)));
            if (candidate.manifest) {
                candidates_->SetItem(row, 1, string(bounded_display(
                    candidate.manifest->name + " (" + candidate.manifest->id + ")", 240)));
                candidates_->SetItem(row, 2, string(bounded_display(candidate.manifest->version, 96)));
                candidates_->SetItem(row, 3, string(bounded_display(manifest_capability_summary(candidate), 380)));
            } else {
                candidates_->SetItem(row, 3, string(candidate.manifest_error.empty()
                    ? "No sidecar manifest" : "Invalid or unreadable manifest"));
            }
            if (candidate.path == selected_path)
                candidates_->SetItemState(row, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED,
                                         wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
        }
        const int maximum_widths[]{FromDIP(360), FromDIP(280), FromDIP(120), FromDIP(380)};
        for (int column = 0; column < candidates_->GetColumnCount(); ++column) {
            candidates_->SetColumnWidth(column, wxLIST_AUTOSIZE);
            if (candidates_->GetColumnWidth(column) > maximum_widths[column])
                candidates_->SetColumnWidth(column, maximum_widths[column]);
        }
    }
    report(string(result.message));
    refresh();
    invoke_button_->Enable(!action_rows_.empty());
    provider_button_->Enable(!provider_rows_.empty());
    load_candidate_button_->Enable(!candidate_rows_.empty());
    if (result.changed && extensions_changed) extensions_changed();
    if (lifecycle && extensions_operation_finished) extensions_operation_finished(result.changed);
}

void PluginsView::refresh() {
    list_->DeleteAllItems();
    ids_.clear();
    const auto loaded = manager_->plugins();
    const auto failures = manager_->extension_failures();
    for (const auto &plugin : loaded) {
        const auto row = list_->InsertItem(list_->GetItemCount(), string(plugin.id));
        list_->SetItem(row, 1, string(plugin.name));
        list_->SetItem(row, 2, string(plugin.version));
        wxString capabilities;
        for (const auto &capability : plugin.capabilities) {
            if (!capabilities.empty()) capabilities += ", ";
            capabilities += string(capability);
        }
        for (const auto &capability : plugin.declared_capabilities) {
            if (!capabilities.empty()) capabilities += ", ";
            capabilities += string(capability.id) + wxString::Format("@%u.%u", capability.major_version,
                                                                       capability.minor_version);
        }
        for (const auto &capability : plugin.required_capabilities) {
            if (!capabilities.empty()) capabilities += ", ";
            capabilities += "requires " + string(capability.id) + wxString::Format("@%u.%u",
                capability.major_version, capability.minor_version);
        }
        for (const auto &dependency : plugin.resolved_dependencies) {
            if (!capabilities.empty()) capabilities += ", ";
            capabilities += "provided by " + string(dependency);
        }
        for (const auto &failure : failures) {
            if (failure.plugin_id != plugin.id) continue;
            if (!capabilities.empty()) capabilities += ", ";
            capabilities += "disabled " + string(failure.extension_id) + " (" + string(failure.kind) + ")";
        }
        list_->SetItem(row, 3, capabilities);
        ids_.push_back(plugin.id);
    }
    actions_->DeleteAllItems();
    action_rows_ = manager_->actions();
    for (const auto &action : action_rows_) {
        const auto row = actions_->InsertItem(actions_->GetItemCount(), string(action.plugin_id));
        actions_->SetItem(row, 1, string(action.id));
        actions_->SetItem(row, 2, string(action.label));
    }
    providers_->DeleteAllItems();
    provider_rows_ = manager_->analysis_providers();
    for (const auto &provider : provider_rows_) {
        const auto row = providers_->InsertItem(providers_->GetItemCount(), string(provider.plugin_id));
        providers_->SetItem(row, 1, string(provider.provider_id));
        providers_->SetItem(row, 2, string(provider.display_name));
    }
    list_->SetColumnWidth(0, wxLIST_AUTOSIZE_USEHEADER);
    list_->SetColumnWidth(1, wxLIST_AUTOSIZE_USEHEADER);
    list_->SetColumnWidth(2, wxLIST_AUTOSIZE_USEHEADER);
    list_->SetColumnWidth(3, wxLIST_AUTOSIZE_USEHEADER);
    for (int column = 0; column < actions_->GetColumnCount(); ++column)
        actions_->SetColumnWidth(column, wxLIST_AUTOSIZE_USEHEADER);
    for (int column = 0; column < providers_->GetColumnCount(); ++column)
        providers_->SetColumnWidth(column, wxLIST_AUTOSIZE_USEHEADER);
    invoke_button_->Enable(!action_rows_.empty() && !operation_pending_);
    provider_button_->Enable(!provider_rows_.empty() && !operation_pending_);
    load_candidate_button_->Enable(!candidate_rows_.empty() && !operation_pending_);
    plan_button_->Enable(!candidate_rows_.empty() && !operation_pending_);
    load_dependencies_button_->Enable(!candidate_rows_.empty() && !operation_pending_);
    unload_dependents_button_->Enable(!ids_.empty() && !operation_pending_);
}

void PluginsView::report(const wxString &message) { status_->ChangeValue(message); }
} // namespace hexlab::desktop
