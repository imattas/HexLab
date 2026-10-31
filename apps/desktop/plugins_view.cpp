#include "plugins_view.hpp"
#include "hexlab/plugins/runtime.hpp"
#include "hexlab/core/sha256.hpp"

#include <wx/button.h>
#include <wx/config.h>
#include <wx/dirdlg.h>
#include <wx/filedlg.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/dialog.h>
#include <wx/wrapsizer.h>
#include <wx/app.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/msgdlg.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string_view>
#include <thread>
#include <mutex>
#include <sstream>
#include <span>

namespace hexlab::desktop {
namespace {
constexpr std::size_t max_disabled_candidate_paths = 4096;
constexpr std::size_t max_candidate_report_bytes = 4 * 1024 * 1024;
constexpr std::size_t max_candidate_report_cell_bytes = 128 * 1024;
wxString string(const std::string &value) { return wxString::FromUTF8(value.c_str()); }
bool append_tsv_row(std::string &output, std::span<const std::string_view> cells) {
    auto append = [&](std::string_view value) {
        if (value.size() > max_candidate_report_cell_bytes || output.size() > max_candidate_report_bytes)
            return false;
        const bool quoted = value.find_first_of("\t\r\n\"") != std::string_view::npos;
        const auto extra = value.size() + (quoted ? 2 : 0);
        if (extra > max_candidate_report_bytes - output.size()) return false;
        if (quoted) output.push_back('"');
        for (const char ch : value) {
            if (ch == '"') output.push_back('"');
            output.push_back(ch);
        }
        if (quoted) output.push_back('"');
        return true;
    };
    for (std::size_t index = 0; index < cells.size(); ++index) {
        if (index != 0) {
            if (output.size() == max_candidate_report_bytes) return false;
            output.push_back('\t');
        }
        if (!append(cells[index])) return false;
    }
    if (output.size() > max_candidate_report_bytes - 2) return false;
    output += "\r\n";
    return true;
}
std::string normalize_plugin_path(std::string_view path) {
    if (path.empty() || path.size() > 131072) return {};
    try {
        std::error_code error;
        auto absolute = std::filesystem::absolute(std::filesystem::u8path(std::string(path)), error);
        if (error) return {};
        absolute = absolute.lexically_normal();
        const auto encoded = absolute.u8string();
        return {reinterpret_cast<const char *>(encoded.data()), encoded.size()};
    } catch (...) {
        return {};
    }
}
std::string disabled_candidate_key(std::string_view path) {
    const auto normalized = normalize_plugin_path(path);
    if (normalized.empty()) return {};
    Sha256 hash;
    const auto bytes = std::as_bytes(std::span(normalized.data(), normalized.size()));
    if (!hash.update(bytes)) return {};
    return digest_hex(hash.digest());
}
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
std::string path_utf8(const std::filesystem::path &path) {
    const auto encoded = path.u8string();
    return {reinterpret_cast<const char *>(encoded.data()), encoded.size()};
}
std::string cleanup_id_display(std::string_view id) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result = "\"";
    for (const unsigned char c : id) {
        if (c == '\\' || c == '"') { result += '\\'; result += static_cast<char>(c); }
        else if (c >= 0x20 && c < 0x7f) result += static_cast<char>(c);
        else { result += "\\x"; result += digits[c >> 4]; result += digits[c & 15]; }
    }
    return result + '"';
}
std::string ascii_lower(std::string_view value) {
    std::string result(value);
    for (auto &byte : result)
        if (byte >= 'A' && byte <= 'Z') byte = static_cast<char>(byte + ('a' - 'A'));
    return result;
}
}
struct PluginsView::OperationState {
    std::mutex mutex;
    PluginsView *target = nullptr;
    OperationResult result;
    bool lifecycle = true;
};

PluginsView::PluginsView(wxWindow *parent, std::shared_ptr<plugins::ModuleProvider> provider)
    : wxPanel(parent), manager_(std::make_shared<plugins::PluginManager>(
          std::move(provider), plugins::default_plugin_state_path())),
      operation_state_(std::make_shared<OperationState>()) {
    operation_state_->target = this;
    load_disabled_candidates();
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
    unload_dependents_button_ = new wxButton(this, wxID_ANY, "Review Unload With Dependents...");
    unload_dependents_button_->SetName("plugin-unload-dependents");
    controls->Add(load_button_, 0, wxRIGHT, FromDIP(4));
    controls->Add(scan_button_, 0, wxRIGHT, FromDIP(4));
    controls->Add(unload_button_, 0, wxRIGHT, FromDIP(4));
    root->Add(controls, 0, wxEXPAND | wxALL, FromDIP(5));
    auto *cleanup_controls = new wxWrapSizer(wxHORIZONTAL);
    cleanup_controls->Add(unload_dependents_button_, 0, wxRIGHT, FromDIP(4));
    unload_all_button_ = new wxButton(this, wxID_ANY, "Review Unload All...");
    unload_all_button_->SetName("plugin-unload-all");
    cleanup_controls->Add(unload_all_button_, 0);
    root->Add(cleanup_controls, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(5));

    auto *candidate_controls = new wxBoxSizer(wxHORIZONTAL);
    candidate_controls->Add(new wxStaticText(this, wxID_ANY, "Discovered modules (not loaded)"), 1,
                            wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(6));
    export_candidates_button_ = new wxButton(this, wxID_ANY, "Save Scan Report...");
    export_candidates_button_->SetName("plugin-candidate-export-report");
    candidate_controls->Add(export_candidates_button_, 0, wxRIGHT, FromDIP(4));
    load_candidate_button_ = new wxButton(this, wxID_ANY, "Load Selected Candidate");
    load_candidate_button_->SetName("plugin-candidate-load");
    plan_button_ = new wxButton(this, wxID_ANY, "Preview Dependencies");
    plan_button_->SetName("plugin-candidate-plan");
    load_dependencies_button_ = new wxButton(this, wxID_ANY, "Load With Dependencies");
    load_dependencies_button_->SetName("plugin-candidate-load-dependencies");
    install_candidate_button_ = new wxButton(this, wxID_ANY, "Install / Update Copy...");
    install_candidate_button_->SetName("plugin-candidate-install");
    install_candidate_button_->SetToolTip("Install or update a verified per-user copy without activating it.");
    install_candidate_button_->Enable(false);
    candidate_controls->Add(plan_button_, 0, wxRIGHT, FromDIP(4));
    candidate_controls->Add(load_dependencies_button_, 0, wxRIGHT, FromDIP(4));
    candidate_controls->Add(install_candidate_button_, 0, wxRIGHT, FromDIP(4));
    verify_candidate_signature_button_ = new wxButton(this, wxID_ANY, "Check Authenticode Trust");
    verify_candidate_signature_button_->SetName("plugin-candidate-authenticode");
    verify_candidate_signature_button_->SetToolTip(
        "Check the current Windows Authenticode trust policy without loading the module.");
    verify_candidate_signature_button_->Enable(false);
    candidate_controls->Add(verify_candidate_signature_button_, 0, wxRIGHT, FromDIP(4));
    toggle_candidate_button_ = new wxButton(this, wxID_ANY, "Block Future Activation");
    toggle_candidate_button_->SetName("plugin-candidate-toggle-enabled");
    candidate_controls->Add(toggle_candidate_button_, 0, wxRIGHT, FromDIP(4));
    candidate_controls->Add(load_candidate_button_, 0);
    root->Add(candidate_controls, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, FromDIP(5));
    auto *candidate_filter_controls = new wxBoxSizer(wxHORIZONTAL);
    candidate_filter_controls->Add(new wxStaticText(this, wxID_ANY, "Filter discovered modules:"), 0,
                                   wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(4));
    candidate_filter_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, FromDIP(wxSize(280, -1)));
    candidate_filter_->SetName("plugin-candidate-filter");
    candidate_filter_->SetHint("path, identity, version, capability, or status");
    candidate_filter_->SetMaxLength(2048);
    candidate_filter_controls->Add(candidate_filter_, 1, wxRIGHT, FromDIP(6));
    candidate_count_ = new wxStaticText(this, wxID_ANY, "Discovered modules (0/0)");
    candidate_count_->SetName("plugin-candidate-count");
    candidate_filter_controls->Add(candidate_count_, 0, wxALIGN_CENTER_VERTICAL);
    root->Add(candidate_filter_controls, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, FromDIP(5));
    candidates_ = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                                 wxLC_REPORT | wxLC_SINGLE_SEL | wxLC_HRULES | wxLC_VRULES);
    candidates_->SetName("plugin-candidate-list");
    candidates_->InsertColumn(0, "Candidate path");
    candidates_->InsertColumn(1, "Sidecar identity (unverified)");
    candidates_->InsertColumn(2, "Version");
    candidates_->InsertColumn(3, "Capabilities / available providers (advisory)");
    candidates_->SetMinSize(wxSize(-1, FromDIP(86)));
    root->Add(candidates_, 0, wxEXPAND | wxLEFT | wxRIGHT, FromDIP(5));
    candidate_details_ = new wxTextCtrl(this, wxID_ANY,
        "Select a discovered candidate to review its exact path, sidecar, and integrity status.",
        wxDefaultPosition, wxSize(-1, FromDIP(120)), wxTE_READONLY | wxTE_MULTILINE | wxTE_DONTWRAP);
    candidate_details_->SetName("plugin-candidate-details");
    root->Add(candidate_details_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, FromDIP(5));

    list_ = new wxListCtrl(this, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                           wxLC_REPORT | wxLC_SINGLE_SEL | wxLC_HRULES | wxLC_VRULES);
    list_->SetName("plugin-list");
    for (const auto *column : {"ID", "Name", "Version", "Capabilities"})
        list_->InsertColumn(list_->GetColumnCount(), column);
    root->Add(list_, 1, wxEXPAND | wxLEFT | wxRIGHT, FromDIP(5));
    plugin_details_ = new wxTextCtrl(this, wxID_ANY, "Select a loaded plugin to inspect its full registration details.",
                                     wxDefaultPosition, wxSize(-1, FromDIP(110)),
                                     wxTE_READONLY | wxTE_MULTILINE | wxTE_DONTWRAP);
    plugin_details_->SetName("plugin-details");
    root->Add(plugin_details_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxTOP, FromDIP(5));
    copy_plugin_details_button_ = new wxButton(this, wxID_ANY, "Copy loaded plugin details");
    copy_plugin_details_button_->SetName("plugin-copy-loaded-details");
    copy_plugin_details_button_->SetToolTip("Copy the selected loaded plugin's read-only registration details.");
    copy_plugin_details_button_->Enable(false);
    root->Add(copy_plugin_details_button_, 0, wxALIGN_RIGHT | wxLEFT | wxRIGHT | wxTOP, FromDIP(5));
    auto *action_controls = new wxBoxSizer(wxHORIZONTAL);
    auto *action_count = new wxStaticText(this, wxID_ANY, "Registered actions (0)");
    action_count_ = action_count;
    action_count->SetName("plugin-action-count");
    action_controls->Add(action_count, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(6));
    action_controls->Add(new wxStaticText(this, wxID_ANY, "Filter:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(4));
    action_filter_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, FromDIP(wxSize(220, -1)));
    action_filter_->SetName("plugin-action-filter");
    action_filter_->SetHint("plugin, action ID, or label");
    action_controls->Add(action_filter_, 1, wxRIGHT, FromDIP(6));
    invoke_button_ = new wxButton(this, wxID_ANY, "Run Selected Action");
    invoke_button_->SetName("plugin-action-invoke");
    action_controls->Add(invoke_button_, 0);
    copy_action_button_ = new wxButton(this, wxID_ANY, "Copy Action Details");
    copy_action_button_->SetName("plugin-action-copy-details");
    copy_action_button_->Enable(false);
    action_controls->Add(copy_action_button_, 0, wxLEFT, FromDIP(4));
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
    export_candidates_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { export_candidate_report(); });
    load_candidate_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { load_candidate(); });
    install_candidate_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { install_candidate(); });
    verify_candidate_signature_button_->Bind(wxEVT_BUTTON,
        [this](wxCommandEvent &) { verify_candidate_signature(); });
    toggle_candidate_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { toggle_candidate_enabled(); });
    plan_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { plan_candidate(); });
    load_dependencies_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { load_candidate_dependencies(); });
    unload_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { unload(); });
    unload_dependents_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { unload_dependents(); });
    unload_all_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { review_unload(true); });
    invoke_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { invoke_action(); });
    copy_action_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_action_details(); });
    provider_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { run_provider(); });
    copy_plugin_details_button_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_plugin_details(); });
    action_filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) { refresh_actions(); });
    actions_->Bind(wxEVT_LIST_ITEM_ACTIVATED, [this](wxListEvent &) { invoke_action(); });
    actions_->Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &) {
        copy_action_button_->Enable(!operation_pending_);
    });
    actions_->Bind(wxEVT_LIST_ITEM_DESELECTED, [this](wxListEvent &) {
        copy_action_button_->Enable(actions_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED) >= 0 &&
                                    !operation_pending_);
    });
    providers_->Bind(wxEVT_LIST_ITEM_ACTIVATED, [this](wxListEvent &) { run_provider(); });
    list_->Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &) { show_plugin_details(); });
    list_->Bind(wxEVT_LIST_ITEM_DESELECTED, [this](wxListEvent &) { show_plugin_details(); });
    candidates_->Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &) { show_candidate_details(); });
    candidates_->Bind(wxEVT_LIST_ITEM_DESELECTED, [this](wxListEvent &) { show_candidate_details(); });
    candidate_filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) {
        const auto selected = selected_candidate_index();
        std::optional<std::string> selected_path;
        if (selected) selected_path = candidate_rows_[*selected].path;
        refresh_candidates(selected_path);
    });
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
    if (row < 0 || static_cast<std::size_t>(row) >= visible_action_rows_.size()) {
        report("Select a registered action to run.");
        return;
    }
    const auto &action = action_rows_[visible_action_rows_[static_cast<std::size_t>(row)]];
    const auto plugin_id = action.plugin_id;
    const auto action_id = action.id;
    const auto label = action.label;
    start_operation([manager = manager_, plugin_id, action_id, label] {
        const auto result = manager->invoke_action(plugin_id, action_id);
        if (!result) return OperationResult{std::string("Action failed: ") + result.error().message, false};
        return OperationResult{std::string("Ran ") + label + ".", false};
    }, false, "Running plugin action...");
}

void PluginsView::copy_action_details() {
    const auto row = actions_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= visible_action_rows_.size()) {
        report("Select a registered action before copying its details.");
        return;
    }
    const auto &action = action_rows_[visible_action_rows_[static_cast<std::size_t>(row)]];
    std::string output = "Plugin ID\tAction ID\tLabel\r\n";
    const std::array<std::string_view, 3> cells{action.plugin_id, action.id, action.label};
    if (!append_tsv_row(output, cells) || output.size() > 64 * 1024) {
        report("Action details exceed the clipboard limit; no partial text was copied.");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable; action details were not copied.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(string(output)));
    wxTheClipboard->Close();
    report(copied ? "Copied the selected plugin action as labeled TSV." :
                    "The clipboard rejected the action details.");
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
    if (disabled_candidate_paths_.contains(normalize_plugin_path(module))) {
        report("This module path is blocked for future activation. Select it in Discovered modules and enable it first.");
        return;
    }
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

void PluginsView::export_candidate_report() {
    if (operation_pending_) {
        report("Wait for the current plugin operation to finish before saving its discovery snapshot.");
        return;
    }
    if (candidate_rows_.empty()) {
        report("Scan a plugin directory before saving a discovery report.");
        return;
    }
    if (candidate_rows_.size() > 4096) {
        report("The discovery result exceeds the 4,096-candidate report limit; scan a smaller directory.");
        return;
    }

    std::string output;
    const std::string_view header[]{"path", "manifest_status", "id", "name", "version", "sha256_expected",
        "sha256_observed", "integrity_status", "capabilities_and_preflight", "manifest_error", "activation"};
    if (!append_tsv_row(output, header)) {
        report("Could not serialize the discovery report within its 4 MiB limit.");
        return;
    }
    for (const auto &candidate : candidate_rows_) {
        const bool has_manifest = candidate.manifest.has_value();
        const std::string_view manifest_status = has_manifest ? "present"
            : (candidate.manifest_error.empty() ? "none" : "invalid");
        const std::string_view id = has_manifest ? std::string_view(candidate.manifest->id) : std::string_view{};
        const std::string_view name = has_manifest ? std::string_view(candidate.manifest->name) : std::string_view{};
        const std::string_view version = has_manifest ? std::string_view(candidate.manifest->version) : std::string_view{};
        const std::string_view expected_hash = has_manifest ? std::string_view(candidate.manifest->sha256) : std::string_view{};
        const std::string_view observed_hash = candidate.module_sha256;
        std::string integrity_status = "not-pinned";
        if (has_manifest && !candidate.manifest->sha256.empty())
            integrity_status = candidate.integrity_error.empty() ? "matched-at-scan" :
                "failed: " + candidate.integrity_error;
        const auto capabilities = has_manifest ? manifest_capability_summary(candidate) : std::string{};
        const auto activation = disabled_candidate_paths_.contains(normalize_plugin_path(candidate.path))
            ? std::string_view("blocked") : std::string_view("enabled");
        const std::string_view manifest_error = candidate.manifest_error;
        const std::string_view cells[]{candidate.path, manifest_status, id, name, version, expected_hash,
            observed_hash, integrity_status, capabilities, manifest_error, activation};
        if (!append_tsv_row(output, cells)) {
            report("Discovery report exceeds the 4 MiB file or 128 KiB per-field limit; no file was written.");
            return;
        }
    }

    wxFileDialog dialog(this, "Save Plugin Discovery Report", {}, "plugin-discovery.tsv",
                        "Tab-separated report (*.tsv)|*.tsv|Text files (*.txt)|*.txt",
                        wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    if (dialog.ShowModal() != wxID_OK) return;
    try {
        std::ofstream file(std::filesystem::u8path(utf8(dialog.GetPath())),
                           std::ios::binary | std::ios::trunc);
        if (!file) {
            report("Could not create the discovery report file.");
            return;
        }
        file.write(output.data(), static_cast<std::streamsize>(output.size()));
        file.flush();
        if (!file) {
            report("Could not finish writing the discovery report; the destination may contain a partial file.");
            return;
        }
    } catch (const std::exception &error) {
        report(string(std::string("Could not save discovery report: ") + error.what()));
        return;
    } catch (...) {
        report("Could not save the discovery report because of an unknown file error.");
        return;
    }
    report(string(std::string("Saved ") + std::to_string(candidate_rows_.size()) + " candidate record(s) (" +
           std::to_string(output.size()) + " bytes). The report contains unsigned advisory metadata; it does not load modules."));
}

void PluginsView::load_disabled_candidates() {
    auto *config = wxConfigBase::Get();
    if (!config) return;
    const auto previous_path = config->GetPath();
    config->SetPath("/Plugins/DisabledCandidates");
    long cookie = 0;
    std::size_t entries_seen = 0;
    wxString key;
    for (bool more = config->GetFirstEntry(key, cookie);
         more && entries_seen < max_disabled_candidate_paths * 4 &&
             disabled_candidate_paths_.size() < max_disabled_candidate_paths;
         more = config->GetNextEntry(key, cookie)) {
        ++entries_seen;
        wxString path;
        if (!config->Read(key, &path)) continue;
        auto encoded = normalize_plugin_path(utf8(path));
        if (!encoded.empty() && disabled_candidate_key(encoded) == utf8(key))
            disabled_candidate_paths_.insert(std::move(encoded));
    }
    config->SetPath(previous_path);
}

void PluginsView::toggle_candidate_enabled() {
    if (operation_pending_) return;
    const auto selected = selected_candidate_index();
    if (!selected) {
        report("Select a discovered candidate to block or enable.");
        return;
    }
    const auto &candidate = candidate_rows_[*selected];
    const auto normalized_path = normalize_plugin_path(candidate.path);
    const auto key = disabled_candidate_key(normalized_path);
    if (key.empty()) {
        report("Cannot identify this candidate path for persistent settings.");
        return;
    }
    auto *config = wxConfigBase::Get();
    if (!config) {
        report("Plugin activation settings are unavailable; no preference was changed.");
        return;
    }
    const bool was_disabled = disabled_candidate_paths_.contains(normalized_path);
    if (!was_disabled && disabled_candidate_paths_.size() >= max_disabled_candidate_paths) {
        report("The saved plugin activation blocklist is at its 4096-path limit.");
        return;
    }
    const wxString setting = "/Plugins/DisabledCandidates/" + string(key);
    const bool stored = was_disabled
        ? config->DeleteEntry(setting)
        : config->Write(setting, string(normalized_path));
    if (!stored) {
        report("Cannot save the plugin activation preference; the current setting was retained.");
        return;
    }
    if (!config->Flush()) {
        if (was_disabled) (void)config->Write(setting, string(normalized_path));
        else (void)config->DeleteEntry(setting);
        (void)config->Flush();
        report("Cannot save the plugin activation preference; the previous setting was restored.");
        return;
    }
    if (was_disabled) {
        disabled_candidate_paths_.erase(normalized_path);
        report("Candidate enabled for explicit activation. It was not loaded.");
    } else {
        disabled_candidate_paths_.insert(normalized_path);
        report("Candidate blocked from future activation. A currently loaded module, if any, remains loaded.");
    }
    refresh_candidates(candidate.path);
}

void PluginsView::load_candidate() {
    if (operation_pending_) return;
    const auto selected = selected_candidate_index();
    if (!selected) {
        report("Select a discovered candidate before loading it.");
        return;
    }
    const auto candidate = candidate_rows_[*selected];
    if (disabled_candidate_paths_.contains(normalize_plugin_path(candidate.path))) {
        report("This candidate is blocked. Enable it before loading.");
        return;
    }
    if (extensions_changing) extensions_changing();
    start_operation([manager = manager_, candidate] {
        const auto loaded = manager->load_candidate(candidate);
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

void PluginsView::verify_candidate_signature() {
    if (operation_pending_) return;
    const auto selected = selected_candidate_index();
    if (!selected) {
        report("Select a discovered candidate before checking its Authenticode signature.");
        return;
    }
    const auto path = candidate_rows_[*selected].path;
    start_operation([path] {
        const auto checked = plugins::verify_plugin_authenticode_trust(std::filesystem::u8path(path));
        if (!checked)
            return OperationResult{"Authenticode check failed: " + checked.error().message, false};
        OperationResult result;
        result.signature_path = path;
        result.signature_trust = checked.value();
        switch (checked.value().status) {
        case plugins::PluginAuthenticodeTrustStatus::trusted:
            result.message = "Windows Authenticode policy trusts the selected module. This does not sandbox it.";
            break;
        case plugins::PluginAuthenticodeTrustStatus::not_trusted:
            result.message = "Windows Authenticode policy did not trust the selected module (provider status " +
                std::to_string(checked.value().provider_status) + ").";
            break;
        case plugins::PluginAuthenticodeTrustStatus::unsupported:
            result.message = "No Authenticode trust provider is available on this platform.";
            break;
        }
        return result;
    }, false, "Checking platform Authenticode trust without loading the module...");
}

void PluginsView::install_candidate() {
    if (operation_pending_) return;
    const auto selected = selected_candidate_index();
    if (!selected) {
        report("Select a discovered candidate before installing it.");
        return;
    }
    const auto candidate = candidate_rows_[*selected];
    if (!candidate.manifest || !candidate.manifest_error.empty()) {
        report("Installation requires a valid adjacent plugin sidecar.");
        return;
    }
    if (disabled_candidate_paths_.contains(normalize_plugin_path(candidate.path))) {
        report("This candidate is blocked from activation. Enable it before installing a copy at a new path.");
        return;
    }
    if (candidate.manifest->sha256.empty()) {
        report("Installation requires a sidecar SHA-256 pin so the copied module can be checked against the reviewed scan.");
        return;
    }
    if (!candidate.integrity_error.empty() || candidate.module_sha256 != candidate.manifest->sha256) {
        report("The candidate failed its declared SHA-256 check; it was not installed.");
        return;
    }
    const auto &id = candidate.manifest->id;
    if (id.empty() || id == "." || id == ".." || id.size() > 128 ||
        !std::all_of(id.begin(), id.end(), [](unsigned char ch) {
            return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                   (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-';
        })) {
        report("The sidecar plugin ID cannot be used as a safe install directory name.");
        return;
    }
    const auto state_path = plugins::default_plugin_state_path();
    if (state_path.empty()) {
        report("The per-user plugin install directory is unavailable on this system.");
        return;
    }
    const auto install_root = state_path.parent_path() / "plugins";
    const auto install_directory = install_root / id;
    const auto question = "Copy " + string(candidate.manifest->name) + " (" + string(id) +
        ") and its sidecar into:\n" + string(path_utf8(install_directory)) +
        "\n\nAn existing managed install for this plugin ID will be replaced after the staged copy passes verification. "
        "The module will not be loaded or executed. Its pinned SHA-256 will be checked. Publisher signatures are not verified.";
    if (wxMessageBox(question, "Install Plugin Candidate", wxYES_NO | wxNO_DEFAULT | wxICON_WARNING, this) != wxYES)
        return;

    start_operation([manager = manager_, candidate, install_root, install_directory] {
        for (const auto &loaded : manager->plugins())
            if (loaded.id == candidate.manifest->id)
                return OperationResult{"Unload this plugin before installing another copy with the same ID.", false};
        try {
            const auto source_module = std::filesystem::u8path(candidate.path);
            auto source_sidecar = source_module;
            source_sidecar += ".hexlab-plugin";
            std::error_code ec;
            const auto module_status = std::filesystem::symlink_status(source_module, ec);
            if (ec || std::filesystem::is_symlink(module_status) || !std::filesystem::is_regular_file(module_status))
                return OperationResult{"Candidate module is no longer a regular file; scan it again.", false};
            const auto sidecar_status = std::filesystem::symlink_status(source_sidecar, ec);
            if (ec || std::filesystem::is_symlink(sidecar_status) || !std::filesystem::is_regular_file(sidecar_status))
                return OperationResult{"Candidate sidecar is no longer a regular file; scan it again.", false};
            std::filesystem::create_directories(install_root, ec);
            if (ec) return OperationResult{"Cannot create the per-user plugin directory: " + ec.message(), false};
            const auto root_status = std::filesystem::symlink_status(install_root, ec);
            if (ec || std::filesystem::is_symlink(root_status) || !std::filesystem::is_directory(root_status))
                return OperationResult{"The per-user plugin directory is not a regular directory.", false};
            const auto destination_status = std::filesystem::symlink_status(install_directory, ec);
            const bool replacing = !ec && std::filesystem::exists(destination_status);
            if (replacing) {
                if (std::filesystem::is_symlink(destination_status) ||
                    !std::filesystem::is_directory(destination_status))
                    return OperationResult{"The existing plugin install path is not a regular directory; it was left untouched.", false};
                auto existing = manager->scan_directory(path_utf8(install_directory));
                if (!existing)
                    return OperationResult{"The existing plugin install could not be verified; it was left untouched: " +
                                           existing.error().message, false};
                const auto managed = std::find_if(existing.value().begin(), existing.value().end(),
                    [&](const auto &item) { return item.manifest && item.manifest->id == candidate.manifest->id; });
                if (existing.value().size() != 1 || managed == existing.value().end())
                    return OperationResult{"The existing plugin directory must contain exactly one matching managed candidate; it was left untouched.", false};
            }
            if (ec != std::errc::no_such_file_or_directory && ec)
                return OperationResult{"Cannot inspect the plugin install destination: " + ec.message(), false};

            const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
            const auto staging = install_root / (".installing-" + candidate.manifest->id + "-" + std::to_string(nonce));
            if (!std::filesystem::create_directory(staging, ec) || ec)
                return OperationResult{"Cannot create a temporary plugin install directory: " + ec.message(), false};
            const auto staged_module = staging / source_module.filename();
            const auto staged_sidecar = staging / source_sidecar.filename();
            const auto cleanup = [&] {
                std::error_code ignored;
                std::filesystem::remove(staged_module, ignored);
                ignored.clear();
                std::filesystem::remove(staged_sidecar, ignored);
                ignored.clear();
                std::filesystem::remove(staging, ignored);
            };
            std::filesystem::copy_file(source_module, staged_module, std::filesystem::copy_options::none, ec);
            if (ec) { cleanup(); return OperationResult{"Cannot copy plugin module: " + ec.message(), false}; }
            std::filesystem::copy_file(source_sidecar, staged_sidecar, std::filesystem::copy_options::none, ec);
            if (ec) { cleanup(); return OperationResult{"Cannot copy plugin sidecar: " + ec.message(), false}; }

            auto staged_candidates = manager->scan_directory(path_utf8(staging));
            if (!staged_candidates) {
                cleanup();
                return OperationResult{"Copied candidate did not pass install verification: " + staged_candidates.error().message, false};
            }
            const auto same_capabilities = [](const auto &left, const auto &right) {
                if (left.size() != right.size()) return false;
                for (std::size_t i = 0; i < left.size(); ++i)
                    if (left[i].id != right[i].id || left[i].major_version != right[i].major_version ||
                        left[i].minor_version != right[i].minor_version || left[i].flags != right[i].flags)
                        return false;
                return true;
            };
            const auto verified = std::find_if(staged_candidates.value().begin(), staged_candidates.value().end(),
                [&](const auto &item) {
                    return item.manifest && item.manifest->id == candidate.manifest->id &&
                        item.manifest->name == candidate.manifest->name &&
                        item.manifest->version == candidate.manifest->version &&
                        item.manifest->sha256 == candidate.manifest->sha256 &&
                        same_capabilities(item.manifest->capabilities, candidate.manifest->capabilities) &&
                        same_capabilities(item.manifest->required_capabilities,
                                          candidate.manifest->required_capabilities) &&
                        item.module_sha256 == candidate.module_sha256;
                });
            if (verified == staged_candidates.value().end()) {
                cleanup();
                return OperationResult{"Copied candidate metadata or integrity does not match the reviewed scan; it was not installed.", false};
            }
            const auto backup = install_root / (".previous-" + candidate.manifest->id + "-" + std::to_string(nonce));
            if (replacing) {
                std::filesystem::rename(install_directory, backup, ec);
                if (ec) { cleanup(); return OperationResult{"Cannot move the existing install aside: " + ec.message(), false}; }
            }
            std::filesystem::rename(staging, install_directory, ec);
            if (ec) {
                const auto publish_error = ec.message();
                if (replacing) {
                    std::error_code restore_error;
                    std::filesystem::rename(backup, install_directory, restore_error);
                    cleanup();
                    if (restore_error)
                        return OperationResult{"Cannot publish the update (" + publish_error + "); the previous install remains at " +
                                               path_utf8(backup) + " because restoration failed: " + restore_error.message(), false};
                } else {
                    cleanup();
                }
                return OperationResult{"Cannot publish the plugin install directory: " + publish_error, false};
            }
            std::string cleanup_warning;
            if (replacing) {
                std::filesystem::remove_all(backup, ec);
                if (ec) cleanup_warning = " The previous version remains at " + path_utf8(backup) +
                                          " because cleanup failed: " + ec.message();
            }
            auto installed = manager->scan_directory(path_utf8(install_directory));
            if (!installed)
                return OperationResult{"Plugin files were copied, but the installed directory could not be scanned: " + installed.error().message,
                                       false};
            auto refreshed = manager->refresh_requirement_preflight(installed.value());
            std::string message = std::string(replacing ? "Updated " : "Installed ") + candidate.manifest->name +
                " (" + candidate.manifest->id + ") at " + path_utf8(install_directory) + ". It was not activated." +
                cleanup_warning;
            if (!refreshed) message += " Provider availability could not be refreshed: " + refreshed.error().message;
            return OperationResult{std::move(message), false, true, std::move(installed.value())};
        } catch (const std::exception &error) {
            return OperationResult{std::string("Plugin installation failed: ") + error.what(), false};
        }
    }, false, "Installing plugin files (the module will not be loaded)...");
}

void PluginsView::plan_candidate() {
    if (operation_pending_) return;
    const auto selected = selected_candidate_index();
    if (!selected) {
        report("Select a discovered candidate to preview its dependencies.");
        return;
    }
    const auto root_path = candidate_rows_[*selected].path;
    auto available_candidates = candidate_rows_;
    std::erase_if(available_candidates, [this](const auto &candidate) {
        return disabled_candidate_paths_.contains(normalize_plugin_path(candidate.path));
    });
    start_operation([manager = manager_, candidates = std::move(available_candidates), root_path] {
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
    const auto selected = selected_candidate_index();
    if (!selected) {
        report("Select a discovered candidate before loading its dependencies.");
        return;
    }
    const auto root_path = candidate_rows_[*selected].path;
    if (disabled_candidate_paths_.contains(normalize_plugin_path(root_path))) {
        report("This candidate is blocked. Enable it before loading.");
        return;
    }
    auto available_candidates = candidate_rows_;
    std::erase_if(available_candidates, [this](const auto &candidate) {
        return disabled_candidate_paths_.contains(normalize_plugin_path(candidate.path));
    });
    if (extensions_changing) extensions_changing();
    start_operation([manager = manager_, candidates = std::move(available_candidates), root_path] {
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
    review_unload(false);
}

void PluginsView::review_unload(bool all) {
    if (operation_pending_) return;
    const auto row = list_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (!all && (row < 0 || static_cast<std::size_t>(row) >= ids_.size())) {
        report("Select a loaded plugin to unload with its dependents.");
        return;
    }
    const auto id = all ? std::string{} : ids_[static_cast<std::size_t>(row)];
    start_operation([manager = manager_, id, all] {
        auto plan = manager->plan_unload(id, all);
        if (!plan) return OperationResult{"Cleanup review failed: " + plan.error().message, false};
        OperationResult result{"Cleanup impact is ready for review.", false};
        result.unload_plan = std::move(plan.value());
        return result;
    }, false, "Preparing bounded plugin cleanup review...");
}

void PluginsView::confirm_unload(plugins::PluginUnloadPlan plan) {
    if (operation_pending_) return;
    if (plan.plugin_ids.empty()) { report("No loaded plugins remain to unload."); return; }
    std::ostringstream details;
    details << "Unload " << plan.plugin_ids.size() << " plugin(s) in this consumer-first order:\n";
    for (std::size_t index = 0; index < plan.plugin_ids.size(); ++index)
        details << index + 1 << ". " << cleanup_id_display(plan.plugin_ids[index]) << '\n';
    details << "\nProvider dependencies retained: " << plan.retained_provider_ids.size() << '\n';
    for (const auto &id : plan.retained_provider_ids) details << "  " << cleanup_id_display(id) << '\n';
    details << "\nRegistered actions, loaders, processors and analysis providers belonging to these modules will be removed.\n"
        << "Open-project analysis is canceled/quiesced before unloading and refreshed afterward.\n"
        << "A changed plugin inventory cancels this plan; review again. Native stop callbacks must return cooperatively.\n";
    const auto review = details.str();
    if (review.size() > 128u * 1024u) {
        report("Cleanup review exceeds its 128 KiB display budget; no plugins were unloaded.");
        return;
    }
    wxDialog dialog(this, wxID_ANY, "Review plugin cleanup", wxDefaultPosition, wxDefaultSize,
        wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER);
    dialog.SetName("plugin-cleanup-review");
    auto *layout = new wxBoxSizer(wxVERTICAL);
    auto *text = new wxTextCtrl(&dialog, wxID_ANY, string(review), wxDefaultPosition, FromDIP(wxSize(640, 360)),
        wxTE_READONLY | wxTE_MULTILINE | wxTE_DONTWRAP);
    text->SetName("plugin-cleanup-plan");
    layout->Add(text, 1, wxEXPAND | wxALL, FromDIP(10));
    auto *buttons = new wxBoxSizer(wxHORIZONTAL);
    buttons->AddStretchSpacer();
    auto *cancel = new wxButton(&dialog, wxID_CANCEL, "Cancel");
    cancel->SetDefault();
    buttons->Add(cancel, 0, wxRIGHT, FromDIP(8));
    auto *accept = new wxButton(&dialog, wxID_OK, "Unload reviewed set");
    accept->SetName("plugin-cleanup-confirm");
    buttons->Add(accept);
    layout->Add(buttons, 0, wxEXPAND | wxALL, FromDIP(10));
    dialog.SetSizerAndFit(layout);
    dialog.SetMinSize(FromDIP(wxSize(480, 340)));
    dialog.CentreOnParent();
    if (dialog.ShowModal() != wxID_OK) { report("Cleanup canceled; no plugins were unloaded."); return; }
    if (extensions_changing) extensions_changing();
    start_operation([manager = manager_, plan = std::move(plan)] {
        try {
            const auto removed = manager->unload_reviewed(plan);
            if (!removed) return OperationResult{"Reviewed cleanup rejected: " + removed.error().message, false};
            std::string message = removed.value().failure ? "Cleanup stopped after removing " : "Cleanup completed; removed ";
            message += std::to_string(removed.value().removed.size()) + " of " + std::to_string(plan.plugin_ids.size()) + " reviewed plugin(s).";
            if (removed.value().failure) message += " " + removed.value().failure->message;
            return OperationResult{std::move(message), !removed.value().removed.empty()};
        } catch (const std::exception &error) {
            // An allocation/native exception may occur after an erase. Treat
            // the inventory as changed so clients never retain stale providers.
            return OperationResult{"Cleanup failed; inventory refreshed: " + std::string(error.what()), true};
        } catch (...) {
            return OperationResult{"Cleanup failed unexpectedly; inventory refreshed.", true};
        }
    }, true, "Unloading reviewed plugins in consumer-first order...");
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
    scan_button_->Disable(); export_candidates_button_->Disable(); load_candidate_button_->Disable(); candidates_->Disable();
    install_candidate_button_->Disable();
    verify_candidate_signature_button_->Disable();
    candidate_filter_->Disable();
    plan_button_->Disable(); load_dependencies_button_->Disable(); unload_dependents_button_->Disable();
    unload_all_button_->Disable();
    toggle_candidate_button_->Disable();
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
    if (result.replace_candidates) candidate_signature_results_.clear();
    if (result.signature_trust)
        candidate_signature_results_.insert_or_assign(result.signature_path, *result.signature_trust);
    load_button_->Enable(); unload_button_->Enable(); scan_button_->Enable(); candidates_->Enable(); candidate_filter_->Enable();
    if (result.replace_candidates) {
        const auto selected = selected_candidate_index();
        std::optional<std::string> selected_path;
        if (selected) selected_path = candidate_rows_[*selected].path;
        candidate_rows_ = std::move(result.candidates);
        refresh_candidates(selected_path);
    }
    report(string(result.message));
    refresh();
    invoke_button_->Enable(!visible_action_rows_.empty() && !operation_pending_);
    copy_action_button_->Enable(actions_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED) >= 0);
    provider_button_->Enable(!provider_rows_.empty());
    update_candidate_controls();
    if (result.changed && extensions_changed) extensions_changed();
    if (lifecycle && extensions_operation_finished) extensions_operation_finished(result.changed);
    if (result.unload_plan) confirm_unload(std::move(*result.unload_plan));
}

void PluginsView::refresh() {
    list_->DeleteAllItems();
    ids_.clear();
    plugin_rows_ = manager_->plugins();
    failure_rows_ = manager_->extension_failures();
    loader_rows_ = manager_->loader_extensions();
    processor_rows_ = manager_->processor_extensions();
    for (const auto &plugin : plugin_rows_) {
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
        for (const auto &failure : failure_rows_) {
            if (failure.plugin_id != plugin.id) continue;
            if (!capabilities.empty()) capabilities += ", ";
            capabilities += "disabled " + string(failure.extension_id) + " (" + string(failure.kind) + ")";
        }
        list_->SetItem(row, 3, capabilities);
        ids_.push_back(plugin.id);
    }
    action_rows_ = manager_->actions();
    refresh_actions();
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
    invoke_button_->Enable(!visible_action_rows_.empty() && !operation_pending_);
    provider_button_->Enable(!provider_rows_.empty() && !operation_pending_);
    export_candidates_button_->Enable(!candidate_rows_.empty() && !operation_pending_);
    unload_dependents_button_->Enable(!ids_.empty() && !operation_pending_);
    unload_all_button_->Enable(!ids_.empty() && !operation_pending_);
    show_plugin_details();
    const auto selected_candidate = selected_candidate_index();
    const auto selected_path = selected_candidate
        ? std::optional<std::string>{candidate_rows_[*selected_candidate].path}
        : std::optional<std::string>{};
    refresh_candidates(selected_path);
}

void PluginsView::refresh_actions() {
    if (!actions_ || !action_filter_) return;
    actions_->DeleteAllItems();
    visible_action_rows_.clear();
    copy_action_button_->Enable(false);
    const auto filter = ascii_lower(utf8(action_filter_->GetValue()));
    for (std::size_t index = 0; index < action_rows_.size(); ++index) {
        const auto &action = action_rows_[index];
        if (!filter.empty() && ascii_lower(action.plugin_id).find(filter) == std::string::npos &&
            ascii_lower(action.id).find(filter) == std::string::npos &&
            ascii_lower(action.label).find(filter) == std::string::npos)
            continue;
        const auto row = actions_->InsertItem(actions_->GetItemCount(), string(action.plugin_id));
        actions_->SetItem(row, 1, string(action.id));
        actions_->SetItem(row, 2, string(action.label));
        visible_action_rows_.push_back(index);
    }
    action_count_->SetLabel(string("Registered actions (" + std::to_string(visible_action_rows_.size()) + "/" +
                                   std::to_string(action_rows_.size()) + ")"));
    invoke_button_->Enable(!visible_action_rows_.empty() && !operation_pending_);
}

void PluginsView::update_candidate_controls() {
    if (!candidates_ || !toggle_candidate_button_) return;
    const auto index = selected_candidate_index();
    const bool selected = index.has_value();
    const bool blocked = selected && disabled_candidate_paths_.contains(
        normalize_plugin_path(candidate_rows_[*index].path));
    toggle_candidate_button_->SetLabel(blocked ? "Enable Candidate" : "Block Future Activation");
    toggle_candidate_button_->Enable(selected && !operation_pending_);
    load_candidate_button_->Enable(selected && !blocked && !operation_pending_);
    install_candidate_button_->Enable(selected && !blocked && candidate_rows_[*index].manifest.has_value() &&
                                      !candidate_rows_[*index].manifest->sha256.empty() && !operation_pending_);
    verify_candidate_signature_button_->Enable(selected && !operation_pending_);
    load_dependencies_button_->Enable(selected && !blocked && !operation_pending_);
    plan_button_->Enable(selected && !blocked && !operation_pending_);
}

std::optional<std::size_t> PluginsView::selected_candidate_index() const {
    if (!candidates_) return {};
    const auto row = candidates_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= visible_candidate_rows_.size()) return {};
    const auto index = visible_candidate_rows_[static_cast<std::size_t>(row)];
    return index < candidate_rows_.size() ? std::optional<std::size_t>{index} : std::nullopt;
}

void PluginsView::refresh_candidates(std::optional<std::string> selected_path) {
    if (!candidates_) return;
    visible_candidate_rows_.clear();
    candidates_->DeleteAllItems();
    const auto query = candidate_filter_ ? ascii_lower(utf8(candidate_filter_->GetValue())) : std::string{};
    for (std::size_t index = 0; index < candidate_rows_.size(); ++index) {
        const auto &candidate = candidate_rows_[index];
        const bool blocked = disabled_candidate_paths_.contains(normalize_plugin_path(candidate.path));
        const auto capabilities = candidate.manifest ? manifest_capability_summary(candidate) : std::string{};
        const auto matches = [&](std::string_view field) {
            return query.empty() || ascii_lower(field).find(query) != std::string::npos;
        };
        const bool matches_hash = matches(candidate.module_sha256) ||
            (candidate.manifest && matches(candidate.manifest->sha256));
        if (!matches(candidate.path) &&
            !(candidate.manifest && (matches(candidate.manifest->id) || matches(candidate.manifest->name) ||
                                     matches(candidate.manifest->version))) &&
            !matches(capabilities) && !matches(candidate.manifest_error) &&
            !matches_hash &&
            !matches(blocked ? "blocked" : "enabled"))
            continue;

        const auto display_path = blocked ? "[blocked] " + candidate.path : candidate.path;
        const auto row = candidates_->InsertItem(candidates_->GetItemCount(), string(bounded_display(display_path, 240)));
        if (candidate.manifest) {
            candidates_->SetItem(row, 1, string(bounded_display(
                candidate.manifest->name + " (" + candidate.manifest->id + ")", 240)));
            candidates_->SetItem(row, 2, string(bounded_display(candidate.manifest->version, 96)));
            candidates_->SetItem(row, 3, string(bounded_display(capabilities, 380)));
        } else {
            candidates_->SetItem(row, 3, string(candidate.manifest_error.empty()
                ? "No sidecar manifest" : "Invalid or unreadable manifest"));
        }
        visible_candidate_rows_.push_back(index);
        if (selected_path && candidate.path == *selected_path)
            candidates_->SetItemState(row, wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED,
                                      wxLIST_STATE_SELECTED | wxLIST_STATE_FOCUSED);
    }
    if (candidate_count_)
        candidate_count_->SetLabel(string("Discovered modules (" + std::to_string(visible_candidate_rows_.size()) +
                                           "/" + std::to_string(candidate_rows_.size()) + ")"));
    const int maximum_widths[]{FromDIP(360), FromDIP(280), FromDIP(120), FromDIP(380)};
    for (int column = 0; column < candidates_->GetColumnCount(); ++column) {
        candidates_->SetColumnWidth(column, wxLIST_AUTOSIZE);
        if (candidates_->GetColumnWidth(column) > maximum_widths[column])
            candidates_->SetColumnWidth(column, maximum_widths[column]);
    }
    show_candidate_details();
}

void PluginsView::show_candidate_details() {
    if (!candidate_details_) return;
    const auto selected = selected_candidate_index();
    if (!selected) {
        candidate_details_->ChangeValue("Select a discovered candidate to review its exact path, sidecar, and integrity status.");
        update_candidate_controls();
        return;
    }
    const auto &candidate = candidate_rows_[*selected];
    std::ostringstream details;
    details << "Module path: " << candidate.path << "\n";
    if (const auto checked = candidate_signature_results_.find(candidate.path);
        checked != candidate_signature_results_.end()) {
        const auto &trust = checked->second;
        details << "Platform signature check: ";
        switch (trust.status) {
        case plugins::PluginAuthenticodeTrustStatus::trusted:
            details << "trusted by Windows Authenticode policy"; break;
        case plugins::PluginAuthenticodeTrustStatus::not_trusted:
            details << "not trusted by Windows Authenticode policy (status " << trust.provider_status << ")"; break;
        case plugins::PluginAuthenticodeTrustStatus::unsupported: details << "unsupported"; break;
        }
        details << "\nProvider: " << trust.provider << "\n";
    } else {
        details << "Platform signature check: not checked\n";
    }
    const bool blocked = disabled_candidate_paths_.contains(normalize_plugin_path(candidate.path));
    details << "Future activation: " << (blocked ? "blocked by saved user preference" : "enabled for explicit user activation")
            << "\n";
    if (candidate.manifest) {
        const auto &manifest = *candidate.manifest;
        details << "Sidecar identity (unverified): " << manifest.name << " (" << manifest.id
                << "), version " << manifest.version << "\n";
        if (manifest.sha256.empty()) {
            details << "SHA-256 pin: none\n";
        } else {
            details << "SHA-256 expected: " << manifest.sha256 << "\n";
            details << "SHA-256 observed at scan: "
                    << (candidate.module_sha256.empty() ? "unavailable" : candidate.module_sha256) << "\n";
            details << "Pin status: " << (candidate.integrity_error.empty()
                ? "matched at scan" : "FAILED: " + candidate.integrity_error) << "\n";
        }
        details << "Declared capabilities:\n";
        if (manifest.capabilities.empty()) details << "  (none)\n";
        for (const auto &capability : manifest.capabilities)
            details << "  " << capability.id << "@" << capability.major_version << "."
                    << capability.minor_version << "\n";
        details << "Required capabilities and preflight:\n";
        if (manifest.required_capabilities.empty()) details << "  (none)\n";
        for (const auto &requirement : manifest.required_capabilities) {
            details << "  " << requirement.id << "@" << requirement.major_version << "."
                    << requirement.minor_version << " -> ";
            const auto resolution = std::find_if(candidate.requirement_preflight.begin(),
                candidate.requirement_preflight.end(), [&](const auto &entry) {
                    return entry.capability.id == requirement.id &&
                           entry.capability.major_version == requirement.major_version &&
                           entry.capability.minor_version == requirement.minor_version;
                });
            if (resolution == candidate.requirement_preflight.end()) details << "not checked";
            else switch (resolution->resolution) {
            case plugins::PluginRequirementResolution::host: details << "host"; break;
            case plugins::PluginRequirementResolution::loaded_plugin:
                details << "loaded plugin " << resolution->provider_plugin_id; break;
            case plugins::PluginRequirementResolution::candidate_plugin:
                details << "candidate " << resolution->provider_plugin_id << " (not loaded)"; break;
            case plugins::PluginRequirementResolution::unavailable: details << "unavailable"; break;
            case plugins::PluginRequirementResolution::ambiguous: details << "ambiguous"; break;
            }
            details << '\n';
        }
    } else if (!candidate.manifest_error.empty()) {
        details << "Sidecar: invalid or unreadable: " << candidate.manifest_error << "\n";
    } else {
        details << "Sidecar: none\n";
    }
    details << "A sidecar is unsigned metadata, not publisher verification. The explicit platform check is informational. Native modules run in-process. "
            << "A declared hash pin is rechecked for candidate activation. Blocking a path affects future activation only.\n";
    candidate_details_->ChangeValue(string(details.str()));
    update_candidate_controls();
}

void PluginsView::show_plugin_details() {
    if (!plugin_details_) return;
    const auto row = list_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= ids_.size()) {
        plugin_details_->ChangeValue("Select a loaded plugin to inspect its full registration details.");
        if (copy_plugin_details_button_) copy_plugin_details_button_->Enable(false);
        return;
    }
    const auto id = ids_[static_cast<std::size_t>(row)];
    const auto found = std::find_if(plugin_rows_.begin(), plugin_rows_.end(), [&](const auto &plugin) { return plugin.id == id; });
    if (found == plugin_rows_.end()) {
        plugin_details_->ChangeValue("The selected plugin is no longer loaded. Refresh the selection.");
        if (copy_plugin_details_button_) copy_plugin_details_button_->Enable(false);
        return;
    }
    std::ostringstream details;
    details << found->name << " (" << found->id << ")\nVersion: " << found->version
            << "\nModule path: " << found->module_path
            << "\nPublisher identity: not verified (native plugin metadata is not signed)\nProvides:\n";
    if (found->declared_capabilities.empty() && found->capabilities.empty()) details << "  (none)\n";
    for (const auto &capability : found->capabilities) details << "  " << capability << "\n";
    for (const auto &capability : found->declared_capabilities)
        details << "  " << capability.id << "@" << capability.major_version << "." << capability.minor_version << "\n";
    details << "Requires:\n";
    if (found->required_capabilities.empty()) details << "  (none)\n";
    for (const auto &capability : found->required_capabilities)
        details << "  " << capability.id << "@" << capability.major_version << "." << capability.minor_version << "\n";
    details << "Loaded providers:\n";
    if (found->resolved_dependencies.empty()) details << "  (none)\n";
    for (const auto &dependency : found->resolved_dependencies) details << "  " << dependency << "\n";
    details << "Loader extensions:\n";
    bool any = false;
    for (const auto &extension : loader_rows_) if (extension.plugin_id == id) {
        details << "  " << extension.extension_id << " -> " << extension.format_id << "\n"; any = true;
    }
    if (!any) details << "  (none)\n";
    details << "Processor extensions:\n"; any = false;
    for (const auto &extension : processor_rows_) if (extension.plugin_id == id) {
        details << "  " << extension.extension_id << " -> " << extension.architecture_id << "/" << extension.mode_id << "\n"; any = true;
    }
    if (!any) details << "  (none)\n";
    details << "Actions:\n"; any = false;
    for (const auto &action : action_rows_) if (action.plugin_id == id) {
        details << "  " << action.label << " [" << action.id << "]\n"; any = true;
    }
    if (!any) details << "  (none)\n";
    details << "Analysis providers:\n"; any = false;
    for (const auto &provider : provider_rows_) if (provider.plugin_id == id) {
        details << "  " << provider.display_name << " [" << provider.provider_id << "]\n"; any = true;
    }
    if (!any) details << "  (none)\n";
    details << "Disabled extension registrations:\n"; any = false;
    for (const auto &failure : failure_rows_) if (failure.plugin_id == id) {
        details << "  " << failure.extension_id << " (" << failure.kind << "): " << failure.reason << "\n"; any = true;
    }
    if (!any) details << "  (none)\n";
    plugin_details_->ChangeValue(string(details.str()));
    if (copy_plugin_details_button_) copy_plugin_details_button_->Enable(true);
}

void PluginsView::copy_plugin_details() {
    if (!plugin_details_ || !copy_plugin_details_button_ || !copy_plugin_details_button_->IsEnabled()) {
        report("Select a loaded plugin before copying its details.");
        return;
    }
    constexpr std::size_t byte_limit = 64u * 1024u;
    const auto contents = plugin_details_->GetValue();
    const auto encoded = contents.ToUTF8();
    if (!encoded) {
        report("Could not encode the loaded plugin details as UTF-8.");
        return;
    }
    if (encoded.length() > byte_limit) {
        report("Loaded plugin details exceed the 64 KiB clipboard limit; no partial text was copied.");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable; plugin details were not copied.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(contents));
    wxTheClipboard->Close();
    report(copied ? "Copied the selected loaded plugin details as UTF-8." :
                    "Could not copy the selected loaded plugin details.");
}

void PluginsView::report(const wxString &message) {
    status_->ChangeValue(message.length() <= 16384 ? message :
        string(bounded_display(utf8(message), 16000)) + "\n[Status display truncated at 16,384 characters]");
}
} // namespace hexlab::desktop
