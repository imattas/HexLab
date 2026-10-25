#pragma once

#include "hexlab/debugger/debugger.hpp"
#include "debugger_locals.hpp"
#include "hexlab/workspace/document.hpp"
#include "hexlab/workspace/commands.hpp"
#include "hexlab/plugins/plugins.hpp"

#include <wx/panel.h>
#include <wx/timer.h>

#include <memory>
#include <functional>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <stop_token>
#include <vector>

class wxListCtrl;
class wxChoice;
class wxButton;
class wxNotebook;
class wxStaticText;
class wxTextCtrl;
class wxCheckBox;

namespace hexlab { struct DocumentSnapshot; }
namespace hexlab::desktop {
class DebuggerView final : public wxPanel {
  public:
    explicit DebuggerView(wxWindow *parent,
                          std::unique_ptr<debugger::Backend> backend = debugger::make_native_backend(),
                          std::function<std::shared_ptr<const hexlab::DocumentSnapshot>()> document = {},
                          std::function<void(DocumentId, Location)> navigate = {},
                          std::function<std::optional<std::pair<DocumentId, Location>>()> selection = {},
                          std::function<void(ProjectCommand)> submit = {},
                          std::function<bool(std::vector<database::BreakpointHitCount>)> persist_hit_counts = {});
    void document_changed();
    void toggle_selection_breakpoint();
    plugins::ActiveDebuggerServices active_debugger_services(
        std::function<std::int32_t(HexLabActiveDocumentInfo&)> document_query) const;
    ~DebuggerView() override;

  private:
    struct TerminationState;
    struct InspectionState;
    std::shared_ptr<debugger::DebugSession> session_;
    std::shared_ptr<TerminationState> termination_state_;
    std::shared_ptr<InspectionState> inspection_state_;
    bool termination_pending_ = false;
    bool remote_session_active_ = false;
    wxTimer poll_timer_;
    wxTextCtrl *executable_ = nullptr;
    wxTextCtrl *arguments_ = nullptr;
    wxTextCtrl *process_id_ = nullptr;
    wxChoice *processes_choice_ = nullptr;
    wxButton *detach_remote_process_button_ = nullptr;
    wxTextCtrl *remote_host_ = nullptr;
    wxTextCtrl *remote_port_ = nullptr;
    wxTextCtrl *event_ = nullptr;
    wxTextCtrl *state_ = nullptr;
    wxTextCtrl *breakpoint_address_ = nullptr;
    wxTextCtrl *breakpoint_condition_ = nullptr;
    wxTextCtrl *breakpoint_log_message_ = nullptr;
    wxTextCtrl *breakpoint_ignore_count_ = nullptr;
    wxCheckBox *breakpoint_logpoint_ = nullptr;
    wxChoice *breakpoint_kind_ = nullptr;
    wxChoice *breakpoint_size_ = nullptr;
    wxTextCtrl *memory_address_ = nullptr;
    wxTextCtrl *memory_write_bytes_ = nullptr;
    wxTextCtrl *memory_view_ = nullptr;
    wxTextCtrl *memory_search_pattern_ = nullptr;
    wxTextCtrl *memory_search_start_ = nullptr;
    wxTextCtrl *memory_search_length_ = nullptr;
    wxTextCtrl *memory_search_alignment_ = nullptr;
    wxStaticText *memory_search_status_ = nullptr;
    wxChoice *memory_search_permissions_ = nullptr;
    wxButton *memory_search_start_button_ = nullptr;
    wxButton *memory_search_cancel_button_ = nullptr;
    wxNotebook *memory_tabs_ = nullptr;
    wxListCtrl *memory_search_results_ = nullptr;
    wxTextCtrl *watch_expression_ = nullptr;
    wxListCtrl *watch_view_ = nullptr;
    wxTextCtrl *register_value_ = nullptr;
    wxChoice *memory_page_size_ = nullptr;
    wxTextCtrl *log_ = nullptr;
    wxListCtrl *threads_view_ = nullptr;
    wxListCtrl *registers_view_ = nullptr;
    wxListCtrl *locals_view_ = nullptr;
    wxChoice *locals_frame_choice_ = nullptr;
    wxListCtrl *breakpoints_view_ = nullptr;
    wxListCtrl *modules_view_ = nullptr;
    wxListCtrl *memory_regions_view_ = nullptr;
    std::vector<debugger::ThreadInfo> threads_;
    bool thread_run_states_supported_ = false;
    std::vector<debugger::RegisterValue> registers_;
    std::vector<DebuggerStackFrame> locals_stack_frames_;
    std::size_t selected_locals_frame_ = 0;
    std::function<std::shared_ptr<const hexlab::DocumentSnapshot>()> document_;
    std::function<void(DocumentId, Location)> navigate_;
    std::function<std::optional<std::pair<DocumentId, Location>>()> selection_;
    std::function<void(ProjectCommand)> submit_;
    std::function<bool(std::vector<database::BreakpointHitCount>)> persist_hit_counts_;
    std::map<std::uint64_t,std::uint64_t> queued_hit_counts_;
    std::shared_ptr<const DocumentSnapshot> inspection_document_;
    std::optional<std::uint64_t> frames_stop_;
    std::optional<DebuggerImageMapping> frames_mapping_;
    void invalidate_frames();
    void navigate_pc(bool selected_frame);
    bool current_document(const std::shared_ptr<const DocumentSnapshot> &) const;
    std::optional<debugger::ThreadId> selected_register_thread_;
    std::optional<std::size_t> selected_register_index_;
    std::vector<debugger::ProcessInfo> processes_;
    std::vector<debugger::ModuleInfo> modules_;
    std::vector<debugger::MemoryRegion> memory_regions_;
    std::vector<std::string> watch_expressions_;
    std::optional<database::ProjectUuid> watch_project_uuid_;
    std::vector<debugger::Breakpoint> breakpoints_;
    std::optional<std::uint64_t> pending_event_;
    std::optional<debugger::ThreadId> pending_event_thread_;
    std::uint64_t session_generation_ = 0;
    std::uint64_t register_request_ = 0;
    std::uint64_t memory_request_ = 0;
    std::uint64_t module_request_ = 0;
    std::uint64_t region_request_ = 0;
    std::uint64_t locals_request_ = 0;
    std::uint64_t memory_search_request_ = 0;
    std::uint64_t watch_request_ = 0;
    std::stop_source memory_search_stop_;
    std::vector<std::uint64_t> memory_search_matches_;

    void launch();
    void attach();
    void refresh_processes();
    void detach_remote_process();
    void update_process_actions();
    void connect_remote();
    void detach();
    void terminate();
    void finish_terminate(debugger::Status);
    void poll_event();
    void continue_event(debugger::ContinueStatus);
    void continue_selected_thread();
    void thread_context_action(debugger::ThreadResumeKind action);
    void step_event();
    void add_breakpoint();
    void save_breakpoint_rule();
    void remove_breakpoint();
    void apply_project_breakpoints();
    void persist_project_breakpoint_hit_counts();
    void refresh_threads(std::optional<debugger::ThreadId> preferred = {});
    void refresh_registers(std::size_t row);
    void refresh_locals();
    void write_register();
    void refresh_memory();
    void start_memory_search();
    void cancel_memory_search();
    void write_memory();
    void move_memory_page(int direction);
    void refresh_modules();
    void refresh_memory_regions();
    void add_watch_expression();
    void remove_watch_expression();
    void refresh_watches();
    void save_watch_expressions();
    void clear_inspection();
    void enqueue_inspection(int kind, std::function<void()> task);
    void refresh_state();
    void report(const wxString &message);
};
} // namespace hexlab::desktop
