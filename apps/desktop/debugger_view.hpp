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
#include <string>
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
    struct SourceStepOutTarget {
        debugger::BreakpointId breakpoint = 0;
        debugger::ProcessId process = 0;
        debugger::ThreadId thread = 0;
        DocumentId document{0};
        std::uint64_t document_revision = 0;
        std::uint64_t runtime_address = 0;
        std::string source_location;
    };
    std::shared_ptr<debugger::DebugSession> session_;
    std::shared_ptr<TerminationState> termination_state_;
    std::shared_ptr<InspectionState> inspection_state_;
    bool termination_pending_ = false;
    bool remote_session_active_ = false;
    bool remote_connecting_ = false;
    std::uint64_t remote_connect_request_ = 0;
    wxTimer poll_timer_;
    wxTextCtrl *executable_ = nullptr;
    wxTextCtrl *arguments_ = nullptr;
    wxTextCtrl *working_directory_ = nullptr;
    wxTextCtrl *remote_environment_ = nullptr;
    wxStaticText *remote_environment_status_ = nullptr;
    wxTextCtrl *process_id_ = nullptr;
    wxChoice *processes_choice_ = nullptr;
    wxTextCtrl *process_filter_ = nullptr;
    wxChoice *process_sort_ = nullptr;
    wxStaticText *process_filter_status_ = nullptr;
    wxButton *detach_remote_process_button_ = nullptr;
    wxButton *remote_connect_button_ = nullptr;
    wxTextCtrl *remote_host_ = nullptr;
    wxTextCtrl *remote_port_ = nullptr;
    wxTextCtrl *remote_packet_limit_ = nullptr;
    wxCheckBox *remote_no_ack_ = nullptr;
    wxCheckBox *remote_non_stop_ = nullptr;
    wxCheckBox *remote_thread_events_ = nullptr;
    wxTextCtrl *remote_metadata_ = nullptr;
    wxTextCtrl *event_ = nullptr;
    wxTextCtrl *state_ = nullptr;
    wxTextCtrl *target_identity_ = nullptr;
    wxTextCtrl *breakpoint_address_ = nullptr;
    wxTextCtrl *breakpoint_condition_ = nullptr;
    wxTextCtrl *breakpoint_log_message_ = nullptr;
    wxTextCtrl *breakpoint_ignore_count_ = nullptr;
    wxCheckBox *breakpoint_logpoint_ = nullptr;
    wxCheckBox *breakpoint_one_shot_ = nullptr;
    wxChoice *breakpoint_kind_ = nullptr;
    wxChoice *breakpoint_size_ = nullptr;
    wxTextCtrl *memory_address_ = nullptr;
    wxButton *memory_history_back_button_ = nullptr;
    wxButton *memory_history_forward_button_ = nullptr;
    wxChoice *memory_history_choice_ = nullptr;
    bool updating_memory_history_choice_ = false;
    wxTextCtrl *memory_write_bytes_ = nullptr;
    wxCheckBox *memory_write_utf8_ = nullptr;
    wxTextCtrl *memory_view_ = nullptr;
    std::vector<std::byte> memory_page_bytes_;
    std::uint64_t memory_page_address_ = 0;
    wxTextCtrl *memory_tag_type_ = nullptr;
    wxButton *memory_tag_read_button_ = nullptr;
    wxStaticText *memory_tag_status_ = nullptr;
    wxTextCtrl *memory_tag_view_ = nullptr;
    wxTextCtrl *memory_search_pattern_ = nullptr;
    wxTextCtrl *memory_search_start_ = nullptr;
    wxTextCtrl *memory_search_length_ = nullptr;
    wxTextCtrl *memory_search_alignment_ = nullptr;
    wxStaticText *memory_search_status_ = nullptr;
    wxChoice *memory_search_permissions_ = nullptr;
    wxButton *memory_search_start_button_ = nullptr, *memory_search_cancel_button_ = nullptr,
             *memory_search_copy_button_ = nullptr, *memory_search_report_button_ = nullptr;
    wxNotebook *memory_tabs_ = nullptr;
    wxListCtrl *memory_search_results_ = nullptr;
    wxTextCtrl *memory_search_filter_ = nullptr;
    wxStaticText *memory_search_result_count_ = nullptr;
    std::vector<std::size_t> visible_memory_search_rows_;
    std::optional<debugger::MemorySearchReport> memory_search_report_;
    wxTextCtrl *watch_expression_ = nullptr;
    wxListCtrl *watch_view_ = nullptr;
    wxChoice *watch_value_format_ = nullptr;
    wxTextCtrl *register_value_ = nullptr;
    wxChoice *memory_page_size_ = nullptr;
    wxChoice *memory_row_width_ = nullptr;
    wxTextCtrl *log_ = nullptr;
    wxCheckBox *output_follow_ = nullptr;
    wxChoice *output_retention_ = nullptr;
    wxTextCtrl *output_search_ = nullptr;
    wxCheckBox *output_search_case_ = nullptr;
    wxStaticText *output_search_status_ = nullptr;
    std::size_t output_search_cursor_ = 0;
    wxListCtrl *threads_view_ = nullptr;
    wxTextCtrl *thread_filter_ = nullptr;
    wxChoice *thread_state_filter_ = nullptr;
    wxChoice *thread_sort_ = nullptr;
    wxStaticText *thread_filter_status_ = nullptr;
    std::vector<std::size_t> visible_thread_rows_;
    wxButton *copy_thread_button_ = nullptr;
    wxStaticText *thread_selection_summary_ = nullptr;
    wxButton *continue_stopped_peers_button_ = nullptr;
    wxListCtrl *registers_view_ = nullptr;
    wxTextCtrl *register_filter_ = nullptr;
    wxChoice *register_value_format_ = nullptr;
    wxCheckBox *register_changed_only_ = nullptr;
    wxButton *register_baseline_button_ = nullptr;
    wxButton *copy_visible_registers_ = nullptr;
    wxStaticText *register_filter_status_ = nullptr;
    wxNotebook *locals_tabs_ = nullptr;
    wxListCtrl *locals_view_ = nullptr;
    wxListCtrl *frame_registers_view_ = nullptr;
    wxStaticText *frame_register_status_ = nullptr;
    wxChoice *locals_frame_choice_ = nullptr;
    wxListCtrl *breakpoints_view_ = nullptr;
    wxTextCtrl *breakpoint_filter_ = nullptr;
    wxCheckBox *breakpoint_enabled_only_ = nullptr;
    wxStaticText *breakpoint_filter_status_ = nullptr;
    wxChoice *breakpoint_sort_ = nullptr;
    wxListCtrl *modules_view_ = nullptr;
    wxTextCtrl *module_filter_ = nullptr;
    wxChoice *module_sort_ = nullptr;
    wxStaticText *module_filter_status_ = nullptr;
    std::vector<std::size_t> visible_module_rows_;
    wxListCtrl *memory_regions_view_ = nullptr;
    wxTextCtrl *memory_region_filter_ = nullptr;
    wxChoice *memory_region_permission_filter_ = nullptr;
    wxChoice *memory_region_sort_ = nullptr;
    wxStaticText *memory_region_filter_status_ = nullptr;
    wxListCtrl *auxiliary_vector_view_ = nullptr;
    wxTextCtrl *auxiliary_vector_filter_ = nullptr;
    wxStaticText *auxiliary_vector_count_ = nullptr;
    std::vector<std::size_t> visible_auxiliary_vector_rows_;
    wxButton *auxiliary_vector_copy_button_ = nullptr;
    std::string auxiliary_vector_copy_text_;
    wxTextCtrl *os_data_type_ = nullptr;
    wxTextCtrl *os_data_view_ = nullptr;
    wxTextCtrl *os_data_find_ = nullptr;
    wxCheckBox *os_data_find_case_ = nullptr;
    wxStaticText *os_data_find_status_ = nullptr;
    std::size_t os_data_find_cursor_ = 0;
    wxButton *os_data_copy_button_ = nullptr;
    std::string os_data_copy_text_;
    wxButton *signal_info_read_button_ = nullptr;
    wxChoice *signal_info_format_ = nullptr;
    wxStaticText *signal_info_status_ = nullptr;
    wxTextCtrl *signal_info_view_ = nullptr;
    wxTextCtrl *remote_file_path_ = nullptr;
    wxButton *remote_file_read_button_ = nullptr;
    wxStaticText *remote_file_status_ = nullptr;
    wxTextCtrl *remote_file_view_ = nullptr;
    bool remote_file_reading_ = false;
    std::uint64_t remote_file_request_ = 0;
    wxTextCtrl *remote_monitor_command_ = nullptr;
    wxButton *remote_monitor_button_ = nullptr;
    wxStaticText *remote_monitor_status_ = nullptr;
    wxTextCtrl *remote_monitor_output_ = nullptr;
    bool remote_monitor_running_ = false;
    std::uint64_t remote_monitor_request_ = 0;
    std::uint32_t pending_event_code_ = 0;
    std::optional<debugger::DebugEvent> last_event_snapshot_;
    std::map<debugger::ThreadId, std::pair<std::uint64_t, std::string>> thread_last_events_;
    bool signal_info_reading_ = false;
    std::vector<debugger::ThreadInfo> threads_;
    bool thread_run_states_supported_ = false;
    std::vector<debugger::RegisterValue> registers_;
    std::vector<std::string> register_changes_;
    std::vector<std::size_t> visible_register_rows_;
    std::optional<debugger::ThreadId> previous_register_thread_;
    std::vector<debugger::RegisterValue> previous_registers_;
    std::optional<debugger::ThreadId> pinned_register_thread_;
    std::vector<debugger::RegisterValue> pinned_registers_;
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
    void navigate_breakpoint();
    void toggle_breakpoint_enabled();
    void copy_visible_breakpoints();
    bool current_document(const std::shared_ptr<const DocumentSnapshot> &) const;
    std::optional<debugger::ThreadId> selected_register_thread_;
    std::optional<std::size_t> selected_register_index_;
    std::vector<debugger::ProcessInfo> processes_;
    std::vector<debugger::ProcessInfo> visible_processes_;
    std::vector<debugger::ModuleInfo> modules_;
    std::vector<debugger::MemoryRegion> memory_regions_;
    std::vector<std::size_t> visible_memory_region_rows_;
    std::vector<debugger::AuxiliaryVectorEntry> auxiliary_vector_;
    std::vector<std::string> watch_expressions_;
    std::vector<std::string> watch_values_;
    std::vector<std::string> watch_changes_;
    std::vector<std::string> previous_watch_expressions_;
    std::vector<std::string> previous_watch_values_;
    std::optional<debugger::ThreadId> previous_watch_thread_;
    std::optional<database::ProjectUuid> watch_project_uuid_;
    std::optional<database::ProjectUuid> remote_config_project_uuid_;
    std::vector<debugger::Breakpoint> breakpoints_;
    std::vector<std::size_t> visible_breakpoint_rows_;
    std::optional<std::uint64_t> pending_event_;
    std::optional<debugger::ThreadId> pending_event_thread_;
    std::optional<SourceStepOutTarget> source_step_out_target_;
    std::optional<std::uint64_t> thread_schedule_snapshot_event_;
    std::uint64_t session_generation_ = 0;
    std::uint64_t thread_request_ = 0;
    std::uint64_t thread_selection_generation_ = 0;
    std::uint64_t register_request_ = 0;
    std::uint64_t memory_request_ = 0;
    std::uint64_t memory_tag_request_ = 0;
    std::uint64_t module_request_ = 0;
    std::uint64_t region_request_ = 0;
    std::uint64_t auxv_request_ = 0;
    std::uint64_t os_data_request_ = 0;
    std::uint64_t signal_info_request_ = 0;
    std::uint64_t locals_request_ = 0;
    std::uint64_t memory_search_request_ = 0;
    std::uint64_t watch_request_ = 0;
    std::stop_source memory_search_stop_;
    std::vector<std::uint64_t> memory_search_matches_;
    std::vector<std::uint64_t> memory_address_history_;
    std::size_t memory_address_history_position_ = 0;
    bool suppress_memory_history_record_ = false;

    void launch();
    void attach();
    void refresh_processes();
    void render_processes(std::optional<debugger::ProcessId> preferred = {});
    void detach_remote_process();
    void update_process_actions();
    void connect_remote();
    void finish_remote_connect(std::uint64_t request, std::optional<debugger::ProcessInfo> process,
                               std::vector<debugger::ProcessInfo> processes,
                               std::string connect_error, std::string process_error);
    void detach();
    void terminate();
    void finish_terminate(debugger::Status);
    void poll_event();
    void continue_event(debugger::ContinueStatus);
    void continue_selected_thread();
    void continue_stopped_peers();
    void update_thread_schedule_controls();
    void update_thread_selection_summary();
    void thread_context_action(debugger::ThreadResumeKind action);
    void interrupt_selected_thread();
    void step_event();
    void step_out_event();
    bool cancel_source_step_out();
    void add_breakpoint();
    void refresh_breakpoints();
    void render_breakpoints(std::optional<debugger::BreakpointId> preferred = {});
    void save_breakpoint_rule();
    void load_breakpoint_rule();
    void remove_breakpoint();
    void apply_project_breakpoints();
    void persist_project_breakpoint_hit_counts();
    void refresh_threads(std::optional<debugger::ThreadId> preferred = {});
    std::optional<std::size_t> render_threads(std::optional<debugger::ThreadId> preferred = {});
    void refresh_registers(std::size_t row);
    void render_registers();
    void toggle_register_baseline();
    void copy_selected_thread();
    void copy_visible_threads();
    void copy_stack_trace();
    void render_frame_registers();
    void copy_locals();
    void inspect_local_address();
    void inspect_frame_cfa();
    void breakpoint_at_frame();
    void breakpoint_at_memory_address();
    void refresh_locals();
    void write_register();
    void refresh_memory();
    void read_memory_tags();
    void record_memory_address(std::uint64_t address);
    void navigate_memory_history(int direction);
    void navigate_memory_history_to(std::size_t position);
    void update_memory_history_controls();
    void watch_memory_byte();
    void copy_memory_page();
    void save_memory_page_raw();
    void copy_memory_address();
    void copy_inspection_report();
    void copy_registers();
    void copy_visible_registers();
    void copy_selected_register();
    void copy_selected_watch();
    void move_watch_expression(int direction);
    void watch_selected_register();
    void read_selected_register_address();
    void copy_output();
    void copy_matching_output_lines();
    void save_output_to_file();
    void search_output(int direction);
    void start_memory_search();
    void cancel_memory_search();
    void copy_memory_search_matches();
    void copy_memory_search_report();
    void render_memory_search_matches();
    void write_memory();
    void move_memory_page(int direction);
    void refresh_modules();
    void render_modules(std::optional<std::size_t> preferred = {});
    void copy_selected_module();
    void copy_visible_modules();
    void refresh_memory_regions();
    void render_memory_regions(std::optional<std::uint64_t> preferred_start = {});
    void search_selected_memory_region();
    void open_selected_memory_region();
    void copy_selected_memory_region();
    void copy_visible_memory_regions();
    void refresh_auxiliary_vector();
    void render_auxiliary_vector();
    void copy_auxiliary_vector();
    void copy_visible_auxiliary_vector();
    void refresh_os_data();
    void search_os_data(int direction);
    void copy_os_data_table();
    void read_signal_info();
    void read_remote_file();
    void run_remote_monitor_command();
    void add_watch_expression();
    void update_watch_expression();
    void remove_watch_expression();
    void refresh_watches();
    void render_watch_values();
    void save_watch_expressions();
    void save_watch_value_format();
    void reset_watch_baseline();
    void load_remote_configuration();
    void save_remote_configuration(const std::optional<debugger::RemoteTargetMetadata>& = {});
    void clear_inspection();
    void enqueue_inspection(int kind, std::function<void()> task);
    void refresh_state();
    void report(const wxString &message);
};
} // namespace hexlab::desktop
