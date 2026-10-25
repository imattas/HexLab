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
#include <string>
#include <thread>
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
    wxListCtrl *actions_ = nullptr;
    wxTextCtrl *status_ = nullptr;
    wxTextCtrl *project_path_ = nullptr;
    wxListCtrl *providers_ = nullptr;
    wxListCtrl *candidates_ = nullptr;
    std::vector<std::string> ids_;
    std::vector<plugins::PluginActionInfo> action_rows_;
    std::vector<plugins::AnalysisProviderInfo> provider_rows_;
    std::vector<plugins::PluginCandidate> candidate_rows_;
    wxWindow *load_button_ = nullptr, *unload_button_ = nullptr, *invoke_button_ = nullptr;
    wxWindow *provider_button_ = nullptr;
    wxWindow *scan_button_ = nullptr, *load_candidate_button_ = nullptr;
    wxWindow *plan_button_ = nullptr, *load_dependencies_button_ = nullptr, *unload_dependents_button_ = nullptr;
    bool operation_pending_ = false;
    void load();
    void scan_directory();
    void load_candidate();
    void plan_candidate();
    void load_candidate_dependencies();
    void unload();
    void unload_dependents();
    void invoke_action();
    void run_provider();
    void start_operation(std::function<OperationResult()>, bool lifecycle = true,
                         std::string pending_message = "Loading or unloading plugin...");
    void finish_operation(OperationResult, bool lifecycle);
    void refresh();
    void report(const wxString &);
};
} // namespace hexlab::desktop
