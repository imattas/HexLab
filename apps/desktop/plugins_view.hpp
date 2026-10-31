#pragma once

#include "hexlab/plugins/plugins.hpp"
#include "hexlab/processors/instruction.hpp"
#include <wx/listctrl.h>
#include <wx/panel.h>
#include <wx/textctrl.h>
#include <memory>
#include <functional>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace hexlab::desktop {
class PluginsView final : public wxPanel {
  public:
    explicit PluginsView(wxWindow *, std::shared_ptr<plugins::ModuleProvider> = plugins::make_native_module_provider());
    ~PluginsView() override;
    plugins::Status apply_display_extension(Instruction &) const;
    AnalysisOptions analysis_options(AnalysisOptions = {}) const;
    std::vector<plugins::PluginMenuActionInfo> menu_actions() const;
    void set_active_document_services(plugins::ActiveDocumentServices services) {
        manager_->set_active_document_services(std::move(services));
    }
    void set_active_debugger_services(plugins::ActiveDebuggerServices services) {
        manager_->set_active_debugger_services(std::move(services));
    }
    void set_active_project_breakpoint_services(plugins::ActiveProjectBreakpointServices services) {
        manager_->set_active_project_breakpoint_services(std::move(services));
    }
    void invoke_menu_action(const std::string &plugin_id, const std::string &action_id,
                            const std::string &label);
    std::function<void()> extensions_changing;
    std::function<void()> extensions_quiesce;
    std::function<void()> extensions_changed;
    std::function<void(bool)> extensions_operation_finished;

  private:
    struct OperationResult {
        std::string message;
        bool changed = false;
        bool replace_candidates = false;
        std::vector<plugins::PluginCandidate> candidates;
        std::optional<plugins::PluginUnloadPlan> unload_plan;
        std::string signature_path;
        std::optional<plugins::PluginAuthenticodeTrust> signature_trust;
    };
    struct OperationState;
    std::shared_ptr<plugins::PluginManager> manager_;
    std::shared_ptr<OperationState> operation_state_;
    std::mutex operation_mutex_;
    std::condition_variable operation_changed_;
    std::function<OperationResult()> queued_operation_;
    bool queued_operation_lifecycle_ = true;
    bool operation_stopping_ = false;
    std::thread operation_thread_;
    wxTextCtrl *path_ = nullptr;
    wxListCtrl *list_ = nullptr;
    wxTextCtrl *plugin_details_ = nullptr;
    wxWindow *copy_plugin_details_button_ = nullptr;
    wxWindow *copy_action_button_ = nullptr;
    wxTextCtrl *candidate_details_ = nullptr;
    wxTextCtrl *candidate_filter_ = nullptr;
    wxWindow *candidate_count_ = nullptr;
    wxTextCtrl *action_filter_ = nullptr;
    wxWindow *action_count_ = nullptr;
    wxListCtrl *actions_ = nullptr;
    wxTextCtrl *status_ = nullptr;
    wxTextCtrl *project_path_ = nullptr;
    wxListCtrl *providers_ = nullptr;
    wxListCtrl *candidates_ = nullptr;
    std::vector<std::string> ids_;
    std::vector<plugins::PluginInfo> plugin_rows_;
    std::vector<plugins::LoaderExtensionInfo> loader_rows_;
    std::vector<plugins::ProcessorExtensionInfo> processor_rows_;
    std::vector<plugins::PluginExtensionFailure> failure_rows_;
    std::vector<plugins::PluginActionInfo> action_rows_;
    std::vector<std::size_t> visible_action_rows_;
    std::vector<plugins::AnalysisProviderInfo> provider_rows_;
    std::vector<plugins::PluginCandidate> candidate_rows_;
    std::vector<std::size_t> visible_candidate_rows_;
    std::unordered_set<std::string> disabled_candidate_paths_;
    std::unordered_map<std::string, plugins::PluginAuthenticodeTrust> candidate_signature_results_;
    wxWindow *load_button_ = nullptr, *unload_button_ = nullptr, *invoke_button_ = nullptr;
    wxWindow *provider_button_ = nullptr;
    wxWindow *export_candidates_button_ = nullptr;
    wxWindow *scan_button_ = nullptr, *load_candidate_button_ = nullptr;
    wxWindow *install_candidate_button_ = nullptr;
    wxWindow *verify_candidate_signature_button_ = nullptr;
    wxWindow *plan_button_ = nullptr, *load_dependencies_button_ = nullptr, *unload_dependents_button_ = nullptr;
    wxWindow *unload_all_button_ = nullptr;
    wxWindow *toggle_candidate_button_ = nullptr;
    bool operation_pending_ = false;
    void load_disabled_candidates();
    void load();
    void scan_directory();
    void export_candidate_report();
    void load_candidate();
    void install_candidate();
    void verify_candidate_signature();
    void toggle_candidate_enabled();
    void plan_candidate();
    void load_candidate_dependencies();
    void unload();
    void unload_dependents();
    void review_unload(bool all);
    void confirm_unload(plugins::PluginUnloadPlan);
    void invoke_action();
    void run_provider();
    void start_operation(std::function<OperationResult()>, bool lifecycle = true,
                         std::string pending_message = "Loading or unloading plugin...");
    void finish_operation(OperationResult, bool lifecycle);
    void refresh();
    void refresh_actions();
    void show_plugin_details();
    void copy_plugin_details();
    void copy_action_details();
    void show_candidate_details();
    void refresh_candidates(std::optional<std::string> selected_path = {});
    std::optional<std::size_t> selected_candidate_index() const;
    void update_candidate_controls();
    void report(const wxString &);
};
} // namespace hexlab::desktop
