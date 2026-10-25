#include "debugger_view.hpp"
#include "debugger_locals.hpp"
#include "hexlab/workspace/document.hpp"
#include "hexlab/workspace/project.hpp"

#include <wx/button.h>
#include <wx/choice.h>
#include <wx/checkbox.h>
#include <wx/listctrl.h>
#include <wx/menu.h>
#include <wx/msgdlg.h>
#include <wx/app.h>
#include <wx/config.h>
#include <wx/notebook.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>

#include <charconv>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <exception>
#include <limits>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <string>
#include <string_view>
#include <thread>
#include <atomic>

namespace hexlab::desktop {
namespace {
enum : int { launch_id = wxID_HIGHEST + 220, attach_id, detach_id, terminate_id, wait_id, continue_id, step_id, pass_id,
            add_bp_id, remove_bp_id, apply_project_bp_id, save_breakpoint_rule_id, poll_id, read_memory_id, remote_connect_id, continue_thread_id,
            thread_context_continue_id, thread_context_step_id, thread_context_stop_id,
            previous_memory_id, next_memory_id, refresh_modules_id, refresh_processes_id,
            detach_remote_process_id,
            refresh_memory_regions_id, write_memory_id, write_register_id, navigate_pc_id, navigate_frame_id,
            memory_search_id, cancel_memory_search_id, add_watch_id, remove_watch_id, refresh_watches_id };

std::string narrow(const wxString &value) { return value.ToStdString(); }
std::string hex(std::span<const std::byte> bytes) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string value = "0x";
    for (auto it = bytes.rbegin(); it != bytes.rend(); ++it) {
        const auto b = std::to_integer<unsigned>(*it);
        value.push_back(digits[b >> 4]); value.push_back(digits[b & 15]);
    }
    return value;
}
std::string register_hex(const debugger::RegisterValue &reg) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string value = "0x";
    const bool big_endian = reg.byte_order == ByteOrder::big;
    for (std::size_t i = 0; i < reg.bytes.size(); ++i) {
        const auto index = big_endian ? i : reg.bytes.size() - 1 - i;
        const auto b = std::to_integer<unsigned>(reg.bytes[index]);
        value.push_back(digits[b >> 4]); value.push_back(digits[b & 15]);
    }
    return value;
}
std::string event_name(debugger::EventKind kind) {
    using debugger::EventKind;
    switch (kind) {
    case EventKind::breakpoint: return "breakpoint";
    case EventKind::single_step: return "single step";
    case EventKind::exception: return "exception";
    case EventKind::thread_created: return "thread created";
    case EventKind::thread_exited: return "thread exited";
    case EventKind::module_loaded: return "module loaded";
    case EventKind::module_unloaded: return "module unloaded";
    case EventKind::process_exited: return "process exited";
    case EventKind::output: return "debug output";
    case EventKind::unknown: return "debug event";
    }
    return "debug event";
}
bool parse_unsigned(std::string_view text, std::uint64_t &value) {
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) { text.remove_prefix(2); base = 16; }
    if (text.empty()) return false;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, base);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}
const char *memory_search_completion(debugger::MemorySearchCompletion completion) {
    using debugger::MemorySearchCompletion;
    switch (completion) {
    case MemorySearchCompletion::completed: return "Complete";
    case MemorySearchCompletion::completed_with_read_failures: return "Complete with read failures";
    case MemorySearchCompletion::byte_budget_exhausted: return "Stopped at byte budget";
    case MemorySearchCompletion::comparison_budget_exhausted: return "Stopped at comparison budget";
    case MemorySearchCompletion::result_limit_reached: return "Stopped at result limit";
    case MemorySearchCompletion::canceled: return "Canceled";
    case MemorySearchCompletion::read_failed: return "Stopped after read failure";
    case MemorySearchCompletion::read_failure_limit_reached: return "Stopped at read-failure limit";
    case MemorySearchCompletion::backend_protocol_error: return "Backend protocol error";
    }
    return "Unknown completion";
}
bool parse_hex_bytes(std::string_view text, std::vector<std::byte> &bytes, std::size_t maximum,
                     bool &too_many) {
    bytes.clear();
    too_many = false;
    int high = -1;
    for (const unsigned char ch : text) {
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == ',' || ch == ':') continue;
        int nibble = ch >= '0' && ch <= '9' ? ch - '0' :
                     ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 :
                     ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
        if (nibble < 0) return false;
        if (high < 0) high = nibble;
        else {
            if (bytes.size() == maximum) { too_many = true; return false; }
            bytes.push_back(static_cast<std::byte>((high << 4) | nibble)); high = -1;
        }
    }
    return high < 0 && !bytes.empty();
}
bool split_arguments(std::string_view input, std::vector<std::string> &out) {
    std::string current;
    bool quoted = false, started = false;
    for (char ch : input) {
        if (ch == '"') { quoted = !quoted; started = true; }
        else if (!quoted && (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')) {
            if (started) { out.push_back(std::move(current)); current.clear(); started = false; }
        } else { current.push_back(ch); started = true; }
    }
    if (quoted) return false;
    if (started) out.push_back(std::move(current));
    return true;
}
wxButton *make_button(wxWindow *parent, const wxString &name, const wxString &label, int id) {
    auto *button = new wxButton(parent, id, label); button->SetName(name); return button;
}
wxTextCtrl *make_text(wxWindow *parent, const wxString &name, long style = 0) {
    auto *text = new wxTextCtrl(parent, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize, style);
    text->SetName(name); return text;
}
wxListCtrl *make_list(wxWindow *parent, const wxString &name, std::initializer_list<const char *> columns) {
    auto *list = new wxListCtrl(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                                wxLC_REPORT | wxLC_SINGLE_SEL | wxBORDER_SIMPLE);
    list->SetName(name);
    int i = 0; for (auto *column : columns) list->InsertColumn(i++, column);
    return list;
}
wxString debugger_project_config_path(const database::ProjectUuid &uuid) {
    static constexpr char digits[] = "0123456789abcdef";
    wxString key = "/Debugger/Watches/";
    for (const auto byte : uuid) {
        const auto value = std::to_integer<unsigned>(byte);
        key += digits[value >> 4]; key += digits[value & 15];
    }
    return key;
}
} // namespace

struct DebuggerView::TerminationState {
    std::mutex mutex;
    DebuggerView *target = nullptr;
    std::optional<debugger::Status> result;
};

struct DebuggerView::InspectionState {
    struct Task { int kind; std::function<void()> run; };
    std::mutex mutex;
    std::mutex backend_mutex;
    std::condition_variable ready;
    std::deque<Task> tasks;
    DebuggerView *target = nullptr;
    std::atomic_bool stopping{false};
    std::atomic<std::uint64_t> session_generation{1}, stop_generation{1};
    std::uint64_t session_id = 0;
};

DebuggerView::DebuggerView(wxWindow *parent, std::unique_ptr<debugger::Backend> backend,
                           std::function<std::shared_ptr<const hexlab::DocumentSnapshot>()> document,
                           std::function<void(DocumentId, Location)> navigate,
                           std::function<std::optional<std::pair<DocumentId, Location>>()> selection,
                           std::function<void(ProjectCommand)> submit,
                           std::function<bool(std::vector<database::BreakpointHitCount>)> persist_hit_counts)
    : wxPanel(parent), session_(std::make_shared<debugger::DebugSession>(backend ? std::move(backend) :
          debugger::make_backend_router(debugger::make_native_backend()))),
      termination_state_(std::make_shared<TerminationState>()), poll_timer_(this, poll_id),
      document_(std::move(document)), navigate_(std::move(navigate)), selection_(std::move(selection)), submit_(std::move(submit)),
      persist_hit_counts_(std::move(persist_hit_counts)) {
    termination_state_->target = this;
    inspection_state_ = std::make_shared<InspectionState>();
    static std::atomic<std::uint64_t> next_session_id{1};
    inspection_state_->session_id = next_session_id.fetch_add(1, std::memory_order_relaxed);
    inspection_state_->target = this;
    auto inspection = inspection_state_;
    std::thread([inspection] {
        for (;;) {
            std::function<void()> task;
            {
                std::unique_lock lock(inspection->mutex);
                inspection->ready.wait(lock, [&] { return inspection->stopping || !inspection->tasks.empty(); });
                if (inspection->stopping && inspection->tasks.empty()) return;
                task = std::move(inspection->tasks.front().run);
                inspection->tasks.pop_front();
            }
            try { task(); } catch (...) { }
        }
    }).detach();
    auto *root = new wxBoxSizer(wxVERTICAL);
    auto *target = new wxFlexGridSizer(2, FromDIP(5), FromDIP(5));
    target->AddGrowableCol(1, 1);
    target->Add(new wxStaticText(this, wxID_ANY, "Executable"), 0, wxALIGN_CENTER_VERTICAL);
    executable_ = make_text(this, "debug-executable"); target->Add(executable_, 1, wxEXPAND);
    target->Add(new wxStaticText(this, wxID_ANY, "Arguments"), 0, wxALIGN_CENTER_VERTICAL);
    arguments_ = make_text(this, "debug-arguments"); target->Add(arguments_, 1, wxEXPAND);
    target->Add(new wxStaticText(this, wxID_ANY, "Process"), 0, wxALIGN_CENTER_VERTICAL);
    auto *process_controls = new wxBoxSizer(wxHORIZONTAL);
    processes_choice_ = new wxChoice(this, wxID_ANY); processes_choice_->SetName("debug-processes");
    process_controls->Add(processes_choice_, 1, wxRIGHT, FromDIP(4));
    process_controls->Add(make_button(this, "debug-refresh-processes", "Refresh", refresh_processes_id), 0, wxRIGHT, FromDIP(4));
    detach_remote_process_button_ = make_button(this, "debug-detach-secondary-process", "Detach secondary", detach_remote_process_id);
    detach_remote_process_button_->SetToolTip("Detach the selected listed remote process while keeping the active process attached.");
    detach_remote_process_button_->Disable();
    process_controls->Add(detach_remote_process_button_, 0, wxRIGHT, FromDIP(4));
    process_id_ = make_text(this, "debug-process-id"); process_id_->SetHint("PID (decimal/hex)");
    process_controls->Add(process_id_, 0);
    target->Add(process_controls, 1, wxEXPAND);
    target->Add(new wxStaticText(this, wxID_ANY, "Remote host / port"), 0, wxALIGN_CENTER_VERTICAL);
    auto *remote = new wxBoxSizer(wxHORIZONTAL);
    remote_host_ = make_text(this, "debug-remote-host"); remote_host_->SetValue("127.0.0.1");
    remote_port_ = make_text(this, "debug-remote-port"); remote_port_->SetValue("1234");
    remote->Add(remote_host_, 1, wxRIGHT, FromDIP(4)); remote->Add(remote_port_, 0, wxRIGHT, FromDIP(4));
    remote->Add(make_button(this, "debug-remote-connect", "Connect RSP", remote_connect_id), 0);
    target->Add(remote, 1, wxEXPAND);
    root->Add(target, 0, wxEXPAND | wxALL, FromDIP(6));

    auto *actions = new wxBoxSizer(wxHORIZONTAL);
    actions->Add(make_button(this, "debug-launch", "Launch", launch_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-attach", "Attach", attach_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-detach", "Detach / Disconnect", detach_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-terminate", "Terminate target", terminate_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-wait-event", "Wait Event", wait_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-continue", "Continue", continue_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-continue-thread", "Continue selected thread", continue_thread_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-step", "Step", step_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-pass-event", "Pass Exception", pass_id), 0);
    actions->Add(make_button(this, "debug-show-thread-pc", "Show thread PC", navigate_pc_id), 0, wxLEFT, FromDIP(4));
    actions->Add(make_button(this, "debug-show-frame-pc", "Show frame PC", navigate_frame_id), 0, wxLEFT, FromDIP(4));
    root->Add(actions, 0, wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(6));

    auto *summary = new wxBoxSizer(wxHORIZONTAL);
    summary->Add(new wxStaticText(this, wxID_ANY, "State:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(4));
    state_ = make_text(this, "debug-state", wxTE_READONLY); summary->Add(state_, 1, wxRIGHT, FromDIP(8));
    summary->Add(new wxStaticText(this, wxID_ANY, "Last event:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(4));
    event_ = make_text(this, "debug-event", wxTE_READONLY); summary->Add(event_, 2, wxEXPAND);
    root->Add(summary, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(6));

    auto *details = new wxBoxSizer(wxHORIZONTAL);
    auto *thread_column = new wxBoxSizer(wxVERTICAL);
    thread_column->Add(new wxStaticText(this, wxID_ANY, "Threads"), 0, wxBOTTOM, FromDIP(3));
    threads_view_ = make_list(this, "debug-threads", {"ID", "Name", "State"});
    thread_column->Add(threads_view_, 1, wxEXPAND); details->Add(thread_column, 1, wxEXPAND | wxRIGHT, FromDIP(5));
    auto *register_column = new wxBoxSizer(wxVERTICAL);
    register_column->Add(new wxStaticText(this, wxID_ANY, "Registers"), 0, wxBOTTOM, FromDIP(3));
    registers_view_ = make_list(this, "debug-registers", {"Register", "Value"});
    register_column->Add(registers_view_, 1, wxEXPAND);
    auto *register_controls = new wxBoxSizer(wxHORIZONTAL);
    register_value_ = make_text(this, "debug-register-value");
    register_value_->SetHint("Register value (hex, exact width)");
    register_controls->Add(register_value_, 1, wxRIGHT, FromDIP(3));
    register_controls->Add(make_button(this, "debug-write-register", "Write register", write_register_id), 0);
    register_column->Add(register_controls, 0, wxEXPAND | wxTOP, FromDIP(4));
    details->Add(register_column, 1, wxEXPAND | wxRIGHT, FromDIP(5));
    auto *locals_column = new wxBoxSizer(wxVERTICAL);
    locals_column->Add(new wxStaticText(this, wxID_ANY, "DWARF / PDB locals and parameters"), 0, wxBOTTOM, FromDIP(3));
    locals_frame_choice_ = new wxChoice(this, wxID_ANY);
    locals_frame_choice_->SetName("debug-locals-frame");
    locals_column->Add(locals_frame_choice_, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    locals_view_ = make_list(this, "debug-locals", {"Name", "Kind", "Scope / origin", "Location", "Value"});
    locals_column->Add(locals_view_, 1, wxEXPAND);
    details->Add(locals_column, 2, wxEXPAND | wxRIGHT, FromDIP(5));
    auto *bp_column = new wxBoxSizer(wxVERTICAL);
    bp_column->Add(new wxStaticText(this, wxID_ANY, "Breakpoints"), 0, wxBOTTOM, FromDIP(3));
    breakpoints_view_ = make_list(this, "debug-breakpoints", {"ID", "Address", "Kind"});
    bp_column->Add(breakpoints_view_, 1, wxEXPAND);
    auto *bp_controls = new wxBoxSizer(wxHORIZONTAL);
    breakpoint_address_ = make_text(this, "debug-breakpoint-address"); breakpoint_address_->SetHint("Address (hex/decimal)");
    bp_controls->Add(breakpoint_address_, 1, wxRIGHT, FromDIP(3));
    breakpoint_kind_ = new wxChoice(this, wxID_ANY);
    breakpoint_kind_->SetName("debug-breakpoint-kind");
    breakpoint_kind_->Append("Software");
    breakpoint_kind_->Append("Hardware execute");
    breakpoint_kind_->Append("Hardware read (if supported)");
    breakpoint_kind_->Append("Hardware write");
    breakpoint_kind_->Append("Hardware access");
    breakpoint_kind_->SetSelection(0);
    bp_controls->Add(breakpoint_kind_, 0, wxRIGHT, FromDIP(3));
    breakpoint_size_ = new wxChoice(this, wxID_ANY);
    breakpoint_size_->SetName("debug-breakpoint-size");
    breakpoint_size_->Append("1 byte");
    breakpoint_size_->Append("2 bytes");
    breakpoint_size_->Append("4 bytes");
    breakpoint_size_->Append("8 bytes");
    breakpoint_size_->SetSelection(0);
    breakpoint_size_->Disable();
    bp_controls->Add(breakpoint_size_, 0, wxRIGHT, FromDIP(3));
    bp_controls->Add(make_button(this, "debug-add-breakpoint", "Add", add_bp_id), 0, wxRIGHT, FromDIP(3));
    bp_controls->Add(make_button(this, "debug-remove-breakpoint", "Remove", remove_bp_id), 0);
    bp_controls->Add(make_button(this, "debug-apply-project-breakpoints", "Apply Project", apply_project_bp_id), 0, wxLEFT, FromDIP(3));
    bp_controls->Add(make_button(this, "debug-save-breakpoint-rule", "Save Rule", save_breakpoint_rule_id), 0, wxLEFT, FromDIP(3));
    bp_column->Add(bp_controls, 0, wxEXPAND | wxTOP, FromDIP(4));
    auto *condition_controls = new wxBoxSizer(wxHORIZONTAL);
    breakpoint_condition_ = make_text(this, "debug-breakpoint-condition");
    breakpoint_condition_->SetHint("Condition: registers/constants, mem8/16/32/64(address), arithmetic, comparisons, && || !");
    condition_controls->Add(breakpoint_condition_, 1, wxRIGHT, FromDIP(3));
    breakpoint_logpoint_ = new wxCheckBox(this, wxID_ANY, "Logpoint (auto-continue)");
    breakpoint_logpoint_->SetName("debug-breakpoint-logpoint");
    condition_controls->Add(breakpoint_logpoint_, 0, wxALIGN_CENTER_VERTICAL);
    bp_column->Add(condition_controls, 0, wxEXPAND | wxTOP, FromDIP(4)); details->Add(bp_column, 1, wxEXPAND);
    auto *rule_controls = new wxBoxSizer(wxHORIZONTAL);
    breakpoint_log_message_ = make_text(this, "debug-breakpoint-log-message");
    breakpoint_log_message_->SetHint("Logpoint output text (literal, up to 1024 bytes)");
    rule_controls->Add(breakpoint_log_message_, 1, wxRIGHT, FromDIP(3));
    breakpoint_ignore_count_ = make_text(this, "debug-breakpoint-ignore-count");
    breakpoint_ignore_count_->SetValue("0");
    breakpoint_ignore_count_->SetHint("Ignore first N hits");
    rule_controls->Add(breakpoint_ignore_count_, 0);
    bp_column->Add(rule_controls, 0, wxEXPAND | wxTOP, FromDIP(4));
    root->Add(details, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(6));
    auto *inspect = new wxBoxSizer(wxHORIZONTAL);
    auto *memory_column = new wxBoxSizer(wxVERTICAL);
    memory_tabs_ = new wxNotebook(this, wxID_ANY);
    memory_tabs_->SetName("debug-memory-tabs");
    auto *memory_page = new wxPanel(memory_tabs_);
    auto *memory_page_box = new wxBoxSizer(wxVERTICAL);
    memory_page_box->Add(new wxStaticText(memory_page, wxID_ANY, "Live process memory (bounded pages)"), 0, wxBOTTOM, FromDIP(3));
    auto *memory_controls = new wxBoxSizer(wxHORIZONTAL);
    memory_address_ = make_text(memory_page, "debug-memory-address"); memory_address_->SetHint("Address (hex/decimal)");
    memory_controls->Add(memory_address_, 1, wxRIGHT, FromDIP(3));
    memory_page_size_ = new wxChoice(memory_page, wxID_ANY);
    memory_page_size_->SetName("debug-memory-page-size");
    memory_page_size_->Append("64 bytes"); memory_page_size_->Append("256 bytes"); memory_page_size_->Append("1024 bytes");
    memory_page_size_->SetSelection(1);
    memory_controls->Add(memory_page_size_, 0, wxRIGHT, FromDIP(3));
    memory_controls->Add(make_button(memory_page, "debug-memory-previous", "Previous", previous_memory_id), 0, wxRIGHT, FromDIP(3));
    memory_controls->Add(make_button(memory_page, "debug-read-memory", "Read", read_memory_id), 0, wxRIGHT, FromDIP(3));
    memory_controls->Add(make_button(memory_page, "debug-memory-next", "Next", next_memory_id), 0);
    memory_page_box->Add(memory_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    auto *memory_write_controls = new wxBoxSizer(wxHORIZONTAL);
    memory_write_bytes_ = make_text(memory_page, "debug-memory-write-bytes");
    memory_write_bytes_->SetHint("Bytes to write (hex pairs, e.g. 90 C3)");
    memory_write_controls->Add(memory_write_bytes_, 1, wxRIGHT, FromDIP(3));
    memory_write_controls->Add(make_button(memory_page, "debug-write-memory", "Write bytes", write_memory_id), 0);
    memory_page_box->Add(memory_write_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    memory_view_ = make_text(memory_page, "debug-memory-view", wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    memory_page_box->Add(memory_view_, 1, wxEXPAND);
    memory_page->SetSizer(memory_page_box);
    memory_tabs_->AddPage(memory_page, "Memory", true);

    auto *search_page = new wxPanel(memory_tabs_);
    auto *search_box = new wxBoxSizer(wxVERTICAL);
    search_box->Add(new wxStaticText(search_page, wxID_ANY,
        "Search readable mapped process memory. Double-click a hit to open it in the memory view."),
        0, wxEXPAND | wxBOTTOM, FromDIP(4));
    memory_search_pattern_ = make_text(search_page, "debug-memory-search-pattern");
    memory_search_pattern_->SetHint("Hex bytes and nibble wildcards (e.g. 48 8B ?? A? ?F)");
    search_box->Add(memory_search_pattern_, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    auto *search_scope = new wxFlexGridSizer(2, FromDIP(4), FromDIP(4));
    search_scope->AddGrowableCol(1, 1);
    search_scope->Add(new wxStaticText(search_page, wxID_ANY, "Range start (optional)"), 0, wxALIGN_CENTER_VERTICAL);
    memory_search_start_ = make_text(search_page, "debug-memory-search-start");
    memory_search_start_->SetHint("Hex/decimal; blank scans eligible maps");
    search_scope->Add(memory_search_start_, 1, wxEXPAND);
    search_scope->Add(new wxStaticText(search_page, wxID_ANY, "Range length (optional)"), 0, wxALIGN_CENTER_VERTICAL);
    memory_search_length_ = make_text(search_page, "debug-memory-search-length");
    memory_search_length_->SetHint("Bytes, hex or decimal");
    search_scope->Add(memory_search_length_, 1, wxEXPAND);
    search_scope->Add(new wxStaticText(search_page, wxID_ANY, "Absolute alignment"), 0, wxALIGN_CENTER_VERTICAL);
    memory_search_alignment_ = make_text(search_page, "debug-memory-search-alignment");
    memory_search_alignment_->SetValue("1");
    memory_search_alignment_->SetHint("1 means every byte");
    search_scope->Add(memory_search_alignment_, 1, wxEXPAND);
    search_scope->Add(new wxStaticText(search_page, wxID_ANY, "Region filter"), 0, wxALIGN_CENTER_VERTICAL);
    memory_search_permissions_ = new wxChoice(search_page, wxID_ANY);
    memory_search_permissions_->SetName("debug-memory-search-permissions");
    memory_search_permissions_->Append("All readable regions");
    memory_search_permissions_->Append("Executable");
    memory_search_permissions_->Append("Writable");
    memory_search_permissions_->Append("Non-executable");
    memory_search_permissions_->SetSelection(0);
    search_scope->Add(memory_search_permissions_, 1, wxEXPAND);
    search_box->Add(search_scope, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    auto *search_actions = new wxBoxSizer(wxHORIZONTAL);
    memory_search_start_button_ = make_button(search_page, "debug-memory-search-start", "Search memory", memory_search_id);
    memory_search_cancel_button_ = make_button(search_page, "debug-memory-search-cancel", "Cancel", cancel_memory_search_id);
    memory_search_cancel_button_->Disable();
    search_actions->Add(memory_search_start_button_, 0, wxRIGHT, FromDIP(4));
    search_actions->Add(memory_search_cancel_button_, 0);
    search_box->Add(search_actions, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    memory_search_status_ = new wxStaticText(search_page, wxID_ANY, "No memory search has run.");
    memory_search_status_->SetName("debug-memory-search-status");
    search_box->Add(memory_search_status_, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    memory_search_results_ = make_list(search_page, "debug-memory-search-results", {"Match address"});
    memory_search_results_->SetColumnWidth(0, FromDIP(180));
    search_box->Add(memory_search_results_, 1, wxEXPAND);
    search_page->SetSizer(search_box);
    memory_tabs_->AddPage(search_page, "Search", false);

    auto *watch_page = new wxPanel(memory_tabs_);
    auto *watch_box = new wxBoxSizer(wxVERTICAL);
    watch_box->Add(new wxStaticText(watch_page, wxID_ANY,
        "Evaluate bounded register and memory expressions for the selected stopped thread. Watch expressions persist per project."),
        0, wxEXPAND | wxBOTTOM, FromDIP(4));
    watch_expression_ = make_text(watch_page, "debug-watch-expression", wxTE_PROCESS_ENTER);
    watch_expression_->SetHint("Expression: register, integer, arithmetic, comparisons, mem8/16/32/64(address)");
    watch_box->Add(watch_expression_, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    auto *watch_actions = new wxBoxSizer(wxHORIZONTAL);
    watch_actions->Add(make_button(watch_page, "debug-watch-add", "Add watch", add_watch_id), 0, wxRIGHT, FromDIP(4));
    watch_actions->Add(make_button(watch_page, "debug-watch-remove", "Remove selected", remove_watch_id), 0, wxRIGHT, FromDIP(4));
    watch_actions->Add(make_button(watch_page, "debug-watch-refresh", "Refresh", refresh_watches_id), 0);
    watch_box->Add(watch_actions, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    watch_view_ = make_list(watch_page, "debug-watches", {"Expression", "Value"});
    watch_view_->SetColumnWidth(0, FromDIP(240));
    watch_view_->SetColumnWidth(1, FromDIP(220));
    watch_box->Add(watch_view_, 1, wxEXPAND);
    watch_page->SetSizer(watch_box);
    memory_tabs_->AddPage(watch_page, "Watches", false);
    memory_column->Add(memory_tabs_, 1, wxEXPAND);
    inspect->Add(memory_column, 1, wxEXPAND | wxRIGHT, FromDIP(5));
    auto *module_column = new wxBoxSizer(wxVERTICAL);
    auto *module_heading = new wxBoxSizer(wxHORIZONTAL);
    module_heading->Add(new wxStaticText(this, wxID_ANY, "Loaded modules"), 1, wxALIGN_CENTER_VERTICAL);
    module_heading->Add(make_button(this, "debug-refresh-modules", "Refresh", refresh_modules_id), 0);
    module_column->Add(module_heading, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    modules_view_ = make_list(this, "debug-modules", {"Base", "Size", "Name", "Path"});
    module_column->Add(modules_view_, 1, wxEXPAND); inspect->Add(module_column, 1, wxEXPAND | wxRIGHT, FromDIP(5));
    auto *region_column = new wxBoxSizer(wxVERTICAL);
    auto *region_heading = new wxBoxSizer(wxHORIZONTAL);
    region_heading->Add(new wxStaticText(this, wxID_ANY, "Memory regions"), 1, wxALIGN_CENTER_VERTICAL);
    region_heading->Add(make_button(this, "debug-refresh-memory-regions", "Refresh", refresh_memory_regions_id), 0);
    region_column->Add(region_heading, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    memory_regions_view_ = make_list(this, "debug-memory-regions", {"Start", "Size", "Permissions", "Type"});
    region_column->Add(memory_regions_view_, 1, wxEXPAND); inspect->Add(region_column, 1, wxEXPAND);
    root->Add(inspect, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(6));
    root->Add(new wxStaticText(this, wxID_ANY, "Debugger output"), 0, wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(6));
    log_ = make_text(this, "debug-output", wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    root->Add(log_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(6));
    SetSizer(root);

    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { navigate_pc(false); }, navigate_pc_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { navigate_pc(true); }, navigate_frame_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { launch(); }, launch_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { attach(); }, attach_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { connect_remote(); }, remote_connect_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { detach(); }, detach_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { terminate(); }, terminate_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { poll_event(); }, wait_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { continue_event(debugger::ContinueStatus::handled); }, continue_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { continue_selected_thread(); }, continue_thread_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { step_event(); }, step_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { continue_event(debugger::ContinueStatus::not_handled); }, pass_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { add_breakpoint(); }, add_bp_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { remove_breakpoint(); }, remove_bp_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { apply_project_breakpoints(); }, apply_project_bp_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { save_breakpoint_rule(); }, save_breakpoint_rule_id);
    Bind(wxEVT_CHOICE, [this](wxCommandEvent &event) {
        const auto selection = event.GetSelection();
        const bool hardware_data = selection >= 2 && selection <= 4;
        if (!hardware_data) breakpoint_size_->SetSelection(0);
        breakpoint_size_->Enable(hardware_data);
    }, breakpoint_kind_->GetId());
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { refresh_memory(); }, read_memory_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { write_memory(); }, write_memory_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { write_register(); }, write_register_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { move_memory_page(-1); }, previous_memory_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { move_memory_page(1); }, next_memory_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { start_memory_search(); }, memory_search_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { cancel_memory_search(); }, cancel_memory_search_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { add_watch_expression(); }, add_watch_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { remove_watch_expression(); }, remove_watch_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { refresh_watches(); }, refresh_watches_id);
    watch_expression_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent &) { add_watch_expression(); });
    Bind(wxEVT_LIST_ITEM_ACTIVATED, [this](wxListEvent &event) {
        const auto row = event.GetIndex();
        if (row < 0 || static_cast<std::size_t>(row) >= memory_search_matches_.size()) return;
        memory_tabs_->SetSelection(0);
        memory_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(memory_search_matches_[static_cast<std::size_t>(row)])));
        refresh_memory();
    }, memory_search_results_->GetId());
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { refresh_modules(); }, refresh_modules_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { refresh_memory_regions(); }, refresh_memory_regions_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { refresh_processes(); }, refresh_processes_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { detach_remote_process(); }, detach_remote_process_id);
    Bind(wxEVT_CHOICE, [this](wxCommandEvent &event) {
        const auto selection = event.GetSelection();
        if (selection < 0 || static_cast<std::size_t>(selection) >= processes_.size()) {
            update_process_actions();
            return;
        }
        process_id_->SetValue(wxString::Format("%llu", static_cast<unsigned long long>(processes_[selection].id)));
        update_process_actions();
    }, processes_choice_->GetId());
    Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &event) { refresh_registers(static_cast<std::size_t>(event.GetIndex())); }, threads_view_->GetId());
    threads_view_->Bind(wxEVT_CONTEXT_MENU, [this](wxContextMenuEvent &event) {
        wxPoint point = event.GetPosition();
        if (point == wxDefaultPosition) point = wxPoint(4, 4);
        else point = threads_view_->ScreenToClient(point);
        int hit_flags = 0;
        const auto hit = threads_view_->HitTest(point, hit_flags);
        if (hit >= 0) {
            threads_view_->SetItemState(hit, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
            refresh_registers(static_cast<std::size_t>(hit));
        }
        wxMenu menu;
        menu.Append(thread_context_continue_id, "Continue thread");
        menu.Append(thread_context_step_id, "Step thread");
        menu.Append(thread_context_stop_id, "Stop thread (resume event thread)");
        bool can_continue = false, can_step = false, can_stop = false;
        if (hit >= 0 && static_cast<std::size_t>(hit) < threads_.size() && thread_run_states_supported_ &&
            pending_event_ && pending_event_thread_) {
            const auto &selected_thread = threads_[static_cast<std::size_t>(hit)];
            const auto owner = *pending_event_thread_;
            const auto owner_row = std::find_if(threads_.begin(), threads_.end(), [&](const auto &item) { return item.id == owner; });
            const bool owner_active = owner_row != threads_.end() && owner_row->state != debugger::ThreadState::exited;
            can_continue = owner_active && selected_thread.state == debugger::ThreadState::stopped &&
                selected_thread.state != debugger::ThreadState::exited;
            can_step = can_continue;
            can_stop = owner_active && selected_thread.id != owner && selected_thread.state == debugger::ThreadState::running;
        }
        menu.Enable(thread_context_continue_id, can_continue);
        menu.Enable(thread_context_step_id, can_step);
        menu.Enable(thread_context_stop_id, can_stop);
        menu.AppendSeparator();
        menu.Append(wxID_REFRESH, "Refresh threads");
        const auto selected = threads_view_->GetPopupMenuSelectionFromUser(menu, point);
        if (selected == thread_context_continue_id) thread_context_action(debugger::ThreadResumeKind::continue_execution);
        else if (selected == thread_context_step_id) thread_context_action(debugger::ThreadResumeKind::single_step);
        else if (selected == thread_context_stop_id) thread_context_action(debugger::ThreadResumeKind::stop);
        else if (selected == wxID_REFRESH) refresh_threads(selected_register_thread_);
    });
    locals_frame_choice_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &event) {
        const auto selected = event.GetSelection();
        selected_locals_frame_ = selected == wxNOT_FOUND ? 0 : static_cast<std::size_t>(selected);
        refresh_locals();
    });
    Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &event) {
        const auto row = event.GetIndex();
        if (row < 0 || static_cast<std::size_t>(row) >= registers_.size()) return;
        selected_register_index_ = static_cast<std::size_t>(row);
        register_value_->SetValue(wxString::FromUTF8(register_hex(registers_[*selected_register_index_])));
    }, registers_view_->GetId());
    Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &event) {
        const auto row = event.GetIndex();
        if (row < 0 || static_cast<std::size_t>(row) >= modules_.size()) return;
        const auto &module = modules_[static_cast<std::size_t>(row)];
        memory_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(module.base)));
        refresh_memory();
    }, modules_view_->GetId());
    Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &event) {
        const auto row = event.GetIndex();
        if (row < 0 || static_cast<std::size_t>(row) >= memory_regions_.size()) return;
        const auto address = memory_regions_[static_cast<std::size_t>(row)].start;
        memory_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(address)));
        refresh_memory();
    }, memory_regions_view_->GetId());
    Bind(wxEVT_TIMER, [this](wxTimerEvent &) { poll_event(); }, poll_id);
    document_changed();
    refresh_state();
}

plugins::ActiveDebuggerServices DebuggerView::active_debugger_services(
    std::function<std::int32_t(HexLabActiveDocumentInfo&)> document_query) const {
    plugins::ActiveDebuggerServices services;
    const auto session = session_;
    const auto state = inspection_state_;
    const auto token_valid = [session, state, document_query](const HexLabActiveDebuggerToken& token) {
        if (!session || !state || state->stopping.load(std::memory_order_acquire) ||
            token.session_id != state->session_id ||
            token.session_generation != state->session_generation.load(std::memory_order_acquire) ||
            token.stop_generation != state->stop_generation.load(std::memory_order_acquire)) return false;
        HexLabActiveDebuggerInfo current{}; current.struct_size = sizeof(current);
        current.token.document.struct_size = sizeof(current.token.document);
        if (!document_query) return false;
        HexLabActiveDocumentInfo document{}; document.struct_size = sizeof(document);
        document.token.struct_size = sizeof(document.token);
        if (document_query(document) != HEXLAB_ACTIVE_DOCUMENT_OK) return false;
        const auto& a = token.document; const auto& b = document.token;
        return a.document_id == b.document_id && a.open_generation == b.open_generation &&
            a.edit_revision == b.edit_revision && a.byte_revision == b.byte_revision &&
            a.decision_revision == b.decision_revision;
    };
    services.query = [session, state, document_query](HexLabActiveDebuggerInfo& out) {
        if (!session || !state || !document_query) return HEXLAB_ACTIVE_DEBUGGER_FAILED;
        HexLabActiveDocumentInfo doc{}; doc.struct_size = sizeof(doc); doc.token.struct_size = sizeof(doc.token);
        if (document_query(doc) != HEXLAB_ACTIVE_DOCUMENT_OK) return HEXLAB_ACTIVE_DEBUGGER_FAILED;
        std::lock_guard lock(state->backend_mutex);
        if (state->stopping.load(std::memory_order_acquire)) return HEXLAB_ACTIVE_DEBUGGER_FAILED;
        HexLabActiveDocumentInfo current{}; current.struct_size=sizeof(current); current.token.struct_size=sizeof(current.token);
        if (document_query(current)!=HEXLAB_ACTIVE_DOCUMENT_OK ||
            current.token.document_id!=doc.token.document_id || current.token.open_generation!=doc.token.open_generation ||
            current.token.edit_revision!=doc.token.edit_revision || current.token.byte_revision!=doc.token.byte_revision ||
            current.token.decision_revision!=doc.token.decision_revision) return HEXLAB_ACTIVE_DEBUGGER_STALE;
        out.state = static_cast<std::uint32_t>(session->state());
        out.token.session_id = state->session_id;
        out.token.session_generation = state->session_generation.load(std::memory_order_acquire);
        out.token.stop_generation = state->stop_generation.load(std::memory_order_acquire);
        out.token.document = doc.token;
        if (const auto& process = session->process()) {
            out.has_process = 1; out.process.struct_size = sizeof(out.process);
            out.process.id = process->id; out.process.architecture = static_cast<std::uint32_t>(process->architecture);
            const auto n = std::min(process->name.size(), sizeof(out.process.name) - 1);
            std::memcpy(out.process.name, process->name.data(), n); out.process.name[n] = '\0';
        }
        return HEXLAB_ACTIVE_DEBUGGER_OK;
    };
    services.threads = [session, state, token_valid](const HexLabActiveDebuggerToken& token, std::uint64_t start,
        std::uint32_t capacity, HexLabDebugThread* output, std::uint32_t* written) {
        if (!written || (capacity && !output) || capacity > HEXLAB_ACTIVE_DEBUGGER_MAX_PAGE || !token_valid(token)) return HEXLAB_ACTIVE_DEBUGGER_STALE;
        std::lock_guard lock(state->backend_mutex);
        if (session->state() != debugger::SessionState::stopped) return HEXLAB_ACTIVE_DEBUGGER_NOT_STOPPED;
        if (!token_valid(token)) return HEXLAB_ACTIVE_DEBUGGER_STALE;
        auto rows = session->threads(); if (!rows) return HEXLAB_ACTIVE_DEBUGGER_FAILED;
        const auto begin = std::min<std::size_t>(static_cast<std::size_t>(start), rows.value().size());
        const auto count = std::min<std::size_t>(capacity, rows.value().size() - begin);
        std::vector<HexLabDebugThread> result(count);
        for (std::size_t i=0;i<count;++i) { auto& row=result[i]; if(output[i].struct_size<sizeof(row)) return HEXLAB_ACTIVE_DEBUGGER_INVALID;
            row.struct_size=sizeof(row);
            const auto& src=rows.value()[begin+i]; row.struct_size=sizeof(row); row.id=src.id; row.state=static_cast<std::uint32_t>(src.state);
            const auto n=std::min(src.name.size(),sizeof(row.name)-1); std::memcpy(row.name,src.name.data(),n); row.name[n]='\0'; }
        if (!token_valid(token)) return HEXLAB_ACTIVE_DEBUGGER_STALE;
        std::copy(result.begin(), result.end(), output);
        *written=static_cast<std::uint32_t>(count); return HEXLAB_ACTIVE_DEBUGGER_OK;
    };
    services.read_registers = [session, state, token_valid](const HexLabActiveDebuggerToken& token, std::uint64_t thread,
        std::uint64_t start, std::uint32_t capacity, HexLabDebugRegister* output, std::uint32_t* written) {
        if (!thread || !written || (capacity && !output) || capacity > HEXLAB_ACTIVE_DEBUGGER_MAX_PAGE || !token_valid(token)) return HEXLAB_ACTIVE_DEBUGGER_STALE;
        std::lock_guard lock(state->backend_mutex); if(session->state()!=debugger::SessionState::stopped)return HEXLAB_ACTIVE_DEBUGGER_NOT_STOPPED; if (!token_valid(token)) return HEXLAB_ACTIVE_DEBUGGER_STALE;
        auto rows=session->read_registers(thread); if(!rows) return HEXLAB_ACTIVE_DEBUGGER_FAILED;
        const auto begin=std::min<std::size_t>(static_cast<std::size_t>(start),rows.value().size());
        const auto count=std::min<std::size_t>(capacity,rows.value().size()-begin);
        std::vector<HexLabDebugRegister> result(count);
        for(std::size_t i=0;i<count;++i){auto& row=result[i]; if(output[i].struct_size<sizeof(row))return HEXLAB_ACTIVE_DEBUGGER_INVALID;
            const auto& src=rows.value()[begin+i]; if(src.bytes.size()>sizeof(row.bytes))return HEXLAB_ACTIVE_DEBUGGER_FAILED;
            row={}; row.struct_size=sizeof(row); row.number=src.number; row.byte_count=static_cast<std::uint32_t>(src.bytes.size());
            row.byte_order=!src.byte_order?HEXLAB_DEBUGGER_BYTE_ORDER_UNKNOWN:*src.byte_order==ByteOrder::big?HEXLAB_DEBUGGER_BYTE_ORDER_BIG:HEXLAB_DEBUGGER_BYTE_ORDER_LITTLE;
            std::memcpy(row.bytes,src.bytes.data(),src.bytes.size());
            const auto nn=std::min(src.name.size(),sizeof(row.name)-1), gn=std::min(src.group.size(),sizeof(row.group)-1);
            std::memcpy(row.name,src.name.data(),nn); row.name[nn]='\0'; std::memcpy(row.group,src.group.data(),gn); row.group[gn]='\0'; }
        if (!token_valid(token)) return HEXLAB_ACTIVE_DEBUGGER_STALE;
        std::copy(result.begin(), result.end(), output);
        *written=static_cast<std::uint32_t>(count); return HEXLAB_ACTIVE_DEBUGGER_OK;
    };
    services.read_memory = [session, state, token_valid](const HexLabActiveDebuggerToken& token, std::uint64_t address,
        std::uint32_t size, std::uint8_t* output) {
        if (!output || !size || size>HEXLAB_ACTIVE_DEBUGGER_MAX_READ || !token_valid(token)) return HEXLAB_ACTIVE_DEBUGGER_STALE;
        std::lock_guard lock(state->backend_mutex); if(session->state()!=debugger::SessionState::stopped)return HEXLAB_ACTIVE_DEBUGGER_NOT_STOPPED; if(!token_valid(token))return HEXLAB_ACTIVE_DEBUGGER_STALE;
        auto bytes=session->read_memory(address,size); if(!bytes || bytes.value().size()!=size)return HEXLAB_ACTIVE_DEBUGGER_FAILED;
        if(!token_valid(token))return HEXLAB_ACTIVE_DEBUGGER_STALE;
        for(std::size_t i=0;i<size;++i)output[i]=std::to_integer<std::uint8_t>(bytes.value()[i]);
        return HEXLAB_ACTIVE_DEBUGGER_OK;
    };
    return services;
}

DebuggerView::~DebuggerView() {
    memory_search_stop_.request_stop();
    {
        std::lock_guard lock(termination_state_->mutex);
        termination_state_->target = nullptr;
    }
    {
        std::lock_guard lock(inspection_state_->mutex);
        inspection_state_->target = nullptr;
        inspection_state_->stopping = true;
        inspection_state_->tasks.clear();
    }
    inspection_state_->ready.notify_one();
}

void DebuggerView::enqueue_inspection(int kind, std::function<void()> task) {
    {
        std::lock_guard lock(inspection_state_->mutex);
        if (inspection_state_->stopping) return;
        std::erase_if(inspection_state_->tasks, [kind](const auto &pending) { return pending.kind == kind; });
        inspection_state_->tasks.push_back({kind, std::move(task)});
    }
    inspection_state_->ready.notify_one();
}

void DebuggerView::launch() {
    debugger::Target target;
    target.executable = narrow(executable_->GetValue());
    if (!split_arguments(narrow(arguments_->GetValue()), target.arguments)) {
        report("Arguments contain an unmatched quote."); return;
    }
    if (target.executable.empty()) { report("Choose an executable to launch."); return; }
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->launch(target); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    remote_session_active_ = false;
    event_->Clear(); threads_.clear(); breakpoints_.clear();
    threads_view_->DeleteAllItems(); registers_view_->DeleteAllItems(); breakpoints_view_->DeleteAllItems();
    clear_inspection();
    report(wxString::Format("Launched %s (PID %llu)", result.value().name,
                            static_cast<unsigned long long>(result.value().id)));
    refresh_state(); poll_timer_.Start(100);
}

void DebuggerView::attach() {
    std::uint64_t id = 0;
    const auto selected = processes_choice_->GetSelection();
    const auto entered_id = narrow(process_id_->GetValue());
    const bool selected_process_matches =
        selected >= 0 && static_cast<std::size_t>(selected) < processes_.size() &&
        entered_id == std::to_string(processes_[static_cast<std::size_t>(selected)].id);
    if (selected_process_matches)
        id = processes_[static_cast<std::size_t>(selected)].id;
    else if (!parse_unsigned(entered_id, id)) {
        report("Enter a valid process ID (decimal or 0x-prefixed hexadecimal)."); return;
    }
    if (id == 0) {
        report("Enter a valid process ID (decimal or 0x-prefixed hexadecimal)."); return;
    }
    auto result = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return remote_session_active_ ? session_->attach_remote_process(id) : session_->attach(id);
    }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    if (remote_session_active_) {
        pending_event_.reset(); pending_event_thread_.reset(); threads_.clear(); breakpoints_.clear();
        threads_view_->DeleteAllItems(); registers_view_->DeleteAllItems(); breakpoints_view_->DeleteAllItems();
    }
    event_->Clear(); threads_.clear();
    clear_inspection();
    report(wxString::Format("Attached to %s (PID %llu)", result.value().name,
                            static_cast<unsigned long long>(result.value().id)));
    if (remote_session_active_) refresh_processes();
    refresh_state(); poll_timer_.Start(100);
}

void DebuggerView::refresh_processes() {
    std::optional<debugger::ProcessId> previous_selection;
    const auto previous_row = processes_choice_->GetSelection();
    if (previous_row >= 0 && static_cast<std::size_t>(previous_row) < processes_.size())
        previous_selection = processes_[static_cast<std::size_t>(previous_row)].id;
    processes_choice_->Clear(); processes_.clear();
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->processes(); }();
    if (!result) {
        processes_choice_->Append("Unavailable: " + wxString::FromUTF8(result.error().message));
        update_process_actions();
        report(wxString::FromUTF8(result.error().message)); return;
    }
    processes_ = std::move(result.value());
    for (const auto &process : processes_)
        processes_choice_->Append(wxString::Format("%llu  %s",
            static_cast<unsigned long long>(process.id), wxString::FromUTF8(process.name)));
    if (processes_.empty()) processes_choice_->Append("No processes found");
    const auto active_id = session_->process() ? std::optional<debugger::ProcessId>{session_->process()->id} : std::nullopt;
    std::optional<debugger::ProcessId> desired = active_id;
    if (!desired || std::none_of(processes_.begin(), processes_.end(), [&](const auto &p) { return p.id == *desired; }))
        desired = previous_selection;
    if (desired) {
        const auto row = std::find_if(processes_.begin(), processes_.end(), [&](const auto &p) { return p.id == *desired; });
        if (row != processes_.end()) {
            const auto index = static_cast<int>(std::distance(processes_.begin(), row));
            processes_choice_->SetSelection(index);
            process_id_->SetValue(wxString::Format("%llu", static_cast<unsigned long long>(row->id)));
        }
    }
    update_process_actions();
}

void DebuggerView::update_process_actions() {
    if (!detach_remote_process_button_) return;
    const auto selection = processes_choice_->GetSelection();
    const auto state = session_->state();
    bool enabled = remote_session_active_ && session_->process() &&
        (state == debugger::SessionState::running || state == debugger::SessionState::stopped) &&
        selection >= 0 && static_cast<std::size_t>(selection) < processes_.size();
    if (enabled)
        enabled = processes_[static_cast<std::size_t>(selection)].id != session_->process()->id;
    detach_remote_process_button_->Enable(enabled);
}

void DebuggerView::detach_remote_process() {
    if (!remote_session_active_) {
        report("Secondary-process detach is available only for a connected remote target.");
        return;
    }
    const auto state = session_->state();
    if (state != debugger::SessionState::running && state != debugger::SessionState::stopped) {
        report("There is no active remote session.");
        update_process_actions();
        return;
    }
    const auto selection = processes_choice_->GetSelection();
    if (selection < 0 || static_cast<std::size_t>(selection) >= processes_.size()) {
        report("Select a listed remote process to detach.");
        return;
    }
    const auto process = processes_[static_cast<std::size_t>(selection)];
    const auto active = session_->process();
    if (!active) {
        report("The active remote process identity is unavailable; secondary detach is disabled.");
        update_process_actions();
        return;
    }
    if (process.id == active->id) {
        report("The selected process is active. Use Detach / Disconnect to end this session.");
        update_process_actions();
        return;
    }
    auto result = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return session_->detach_remote_process(process.id);
    }();
    if (!result) {
        report(wxString::FromUTF8(result.error().message));
        refresh_processes();
        return;
    }
    report(wxString::Format("Detached remote process %llu; the active process remains attached.",
                            static_cast<unsigned long long>(process.id)));
    refresh_processes();
    refresh_state();
}

void DebuggerView::connect_remote() {
    const auto host = narrow(remote_host_->GetValue());
    std::uint64_t port = 0;
    if (host.empty() || !parse_unsigned(narrow(remote_port_->GetValue()), port) || port == 0 || port > 65535) {
        report("Enter a host and a TCP port from 1 through 65535."); return;
    }
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->connect_remote(host, static_cast<std::uint16_t>(port)); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); refresh_state(); return; }
    remote_session_active_ = true;
    pending_event_.reset(); pending_event_thread_.reset(); threads_.clear(); breakpoints_.clear();
    threads_view_->DeleteAllItems(); registers_view_->DeleteAllItems(); breakpoints_view_->DeleteAllItems();
    event_->Clear(); clear_inspection();
    report(wxString::Format("Connected to remote target %s (thread %llu)", wxString::FromUTF8(result.value().name),
                            static_cast<unsigned long long>(result.value().id)));
    refresh_processes();
    refresh_state(); poll_timer_.Start(100);
}

void DebuggerView::detach() {
    poll_timer_.Stop();
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->detach(); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    remote_session_active_ = false;
    pending_event_.reset(); pending_event_thread_.reset(); threads_.clear(); breakpoints_.clear();
    threads_view_->DeleteAllItems(); registers_view_->DeleteAllItems(); breakpoints_view_->DeleteAllItems();
    clear_inspection();
    event_->Clear(); report("Detached from debug target."); refresh_state();
}

void DebuggerView::terminate() {
    if (termination_pending_) return;
    const auto current_state = session_->state();
    if (current_state != debugger::SessionState::running && current_state != debugger::SessionState::stopped) {
        report("There is no active target to terminate.");
        return;
    }
    wxString target = "the active target";
    if (session_->process() && !session_->process()->name.empty())
        target = wxString::FromUTF8(session_->process()->name);
    const auto confirmation = wxString::Format(
        "Permanently terminate %s?\n\nDetach leaves the target running.", target);
    wxMessageDialog dialog(this, confirmation, "Confirm target termination",
                           wxYES_NO | wxNO_DEFAULT | wxICON_WARNING);
    if (dialog.ShowModal() != wxID_YES) return;

    termination_pending_ = true;
    Enable(false);
    poll_timer_.Stop();
    report("Terminating debug target...");
    auto state = termination_state_;
    auto session = session_;
    auto inspection = inspection_state_;
    try {
        std::thread([state = std::move(state), session = std::move(session), inspection = std::move(inspection)]() mutable {
            auto result = [&] { std::lock_guard lock(inspection->backend_mutex); return session->terminate(); }();
            bool alive = false;
            {
                std::lock_guard lock(state->mutex);
                state->result.emplace(std::move(result));
                alive = state->target != nullptr;
            }
            if (alive && wxTheApp) wxTheApp->CallAfter([state] {
                DebuggerView *target = nullptr;
                std::optional<debugger::Status> result;
                {
                    std::lock_guard lock(state->mutex);
                    target = state->target;
                    result = std::move(state->result);
                    state->result.reset();
                }
                if (target && result) target->finish_terminate(std::move(*result));
            });
        }).detach();
    } catch (const std::exception &error) {
        termination_pending_ = false;
        Enable(true);
        if (session_->state() == debugger::SessionState::running) poll_timer_.Start(100);
        report(wxString::Format("Could not start target termination: %s", error.what()));
    }
}

void DebuggerView::finish_terminate(debugger::Status result) {
    termination_pending_ = false;
    Enable(true);
    if (!result) {
        if (result.error().code == ErrorCode::unsupported)
            report("Target termination is unsupported by this debugger backend: " +
                   wxString::FromUTF8(result.error().message));
        else
            report(wxString::FromUTF8(result.error().message));
        if (session_->state() == debugger::SessionState::running) poll_timer_.Start(100);
        return;
    }

    poll_timer_.Stop();
    pending_event_.reset(); pending_event_thread_.reset(); breakpoints_.clear();
    breakpoints_view_->DeleteAllItems();
    clear_inspection();
    refresh_threads(selected_register_thread_);
    event_->SetValue("Target terminated.");
    report("Terminated debug target.");
    refresh_state();
}

void DebuggerView::poll_event() {
    document_changed();
    if (session_->state() != debugger::SessionState::running) return;
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->wait_event(std::chrono::milliseconds(0)); }();
    if (!result) {
        if (result.error().code == ErrorCode::busy) { persist_project_breakpoint_hit_counts(); return; }
        poll_timer_.Stop(); report(wxString::FromUTF8(result.error().message)); refresh_state(); return;
    }
    const auto &received = result.value();
    persist_project_breakpoint_hit_counts();
    if (received.kind == debugger::EventKind::output && session_->state() == debugger::SessionState::running) {
        event_->SetValue(wxString::FromUTF8(received.message));
        report(wxString::FromUTF8(received.message));
        refresh_state();
        return;
    }
    inspection_state_->stop_generation.fetch_add(1, std::memory_order_acq_rel);
    invalidate_frames();
    pending_event_ = received.sequence;
    pending_event_thread_ = received.thread ? std::optional{received.thread} : std::nullopt;
    wxString breakpoint_ids;
    for (const auto id : received.breakpoint_ids) {
        if (!breakpoint_ids.empty()) breakpoint_ids += ", ";
        breakpoint_ids += wxString::Format("%llu", static_cast<unsigned long long>(id));
    }
    wxString owned_breakpoints;
    if (!breakpoint_ids.empty()) {
        owned_breakpoints = " (breakpoint IDs: ";
        owned_breakpoints += breakpoint_ids;
        owned_breakpoints += ")";
    }
    event_->SetValue(wxString::Format("%s at 0x%llX, thread %llu, code 0x%X: %s%s",
                                      event_name(received.kind), static_cast<unsigned long long>(received.address),
                                      static_cast<unsigned long long>(received.thread), received.code,
                                      wxString::FromUTF8(received.message), owned_breakpoints));
    report(wxString::Format("Received event %llu: %s", static_cast<unsigned long long>(received.sequence),
                            event_name(received.kind)));
    refresh_state();
    refresh_threads(received.thread ? std::optional{received.thread} : std::nullopt);
    if (received.kind != debugger::EventKind::process_exited) {
        refresh_modules();
        refresh_memory_regions();
        if (received.address != 0) {
            memory_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(received.address)));
            refresh_memory();
        }
    }
    else poll_timer_.Stop();
}

void DebuggerView::continue_event(debugger::ContinueStatus status) {
    if (!pending_event_) { report("There is no pending debug event to continue."); return; }
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->continue_execution(*pending_event_, status); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    report(status == debugger::ContinueStatus::handled ? "Continued event as handled." : "Passed event to the target.");
    pending_event_.reset(); pending_event_thread_.reset(); invalidate_frames(); ++register_request_; refresh_state();
    inspection_state_->stop_generation.fetch_add(1, std::memory_order_acq_rel);
    refresh_threads(selected_register_thread_);
}

void DebuggerView::continue_selected_thread() {
    if (!pending_event_) { report("There is no pending stop event to continue."); return; }
    if (!selected_register_thread_) { report("Select a stopped thread first."); return; }
    if (!pending_event_thread_) { report("The pending event has no identifiable thread; use Continue."); return; }
    if (*selected_register_thread_ != *pending_event_thread_) {
        report(wxString::Format("Thread %llu does not own the pending event; select thread %llu or use Continue.",
            static_cast<unsigned long long>(*selected_register_thread_),
            static_cast<unsigned long long>(*pending_event_thread_)));
        return;
    }
    const auto thread = *selected_register_thread_;
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->continue_thread_execution(*pending_event_, thread); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    pending_event_.reset(); pending_event_thread_.reset(); invalidate_frames(); ++register_request_;
    inspection_state_->stop_generation.fetch_add(1, std::memory_order_acq_rel);
    refresh_state(); refresh_threads(thread);
    report(wxString::Format("Continued thread %llu for the pending event.",
                            static_cast<unsigned long long>(thread)));
}

void DebuggerView::thread_context_action(debugger::ThreadResumeKind action) {
    if (!pending_event_ || !pending_event_thread_) {
        report("A thread action requires a pending event with an identified owner.");
        return;
    }
    if (!selected_register_thread_) {
        report("Select a thread first.");
        return;
    }
    const auto selected = *selected_register_thread_;
    const auto thread = std::find_if(threads_.begin(), threads_.end(), [&](const auto &item) { return item.id == selected; });
    if (thread == threads_.end()) { report("The selected thread is no longer in the refreshed snapshot."); return; }
    if (thread->state == debugger::ThreadState::unknown || thread->state == debugger::ThreadState::exited) {
        report("Run-state is unknown or exited; no thread action was sent.");
        return;
    }
    if (action == debugger::ThreadResumeKind::stop && thread->state != debugger::ThreadState::running) {
        report("Only a known running thread can be stopped from this context menu.");
        return;
    }
    if (action != debugger::ThreadResumeKind::stop && thread->state != debugger::ThreadState::stopped) {
        report("Only a known stopped thread can be continued or stepped from this context menu.");
        return;
    }
    const auto owner = *pending_event_thread_;
    std::vector<debugger::ThreadResumeAction> actions;
    if (selected == owner) {
        actions.push_back({selected, action});
    } else if (action == debugger::ThreadResumeKind::stop) {
        // RSP schedules must consume the pending event. Stopping another
        // running thread therefore resumes the stopped event owner atomically.
        actions.push_back({owner, debugger::ThreadResumeKind::continue_execution});
        actions.push_back({selected, debugger::ThreadResumeKind::stop});
    } else {
        // Keep the event owner stopped while resuming/stepping another thread.
        actions.push_back({owner, debugger::ThreadResumeKind::stop});
        actions.push_back({selected, action});
    }
    auto result = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return session_->resume_threads(*pending_event_, actions);
    }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    const auto event_sequence = *pending_event_;
    pending_event_.reset(); pending_event_thread_.reset();
    inspection_state_->stop_generation.fetch_add(1, std::memory_order_acq_rel);
    invalidate_frames(); ++register_request_; refresh_state(); refresh_threads(selected);
    poll_timer_.Start(100);
    if (action == debugger::ThreadResumeKind::stop) {
        report(wxString::Format("Stopped thread %llu and resumed event-owner thread %llu (event %llu).",
            static_cast<unsigned long long>(selected), static_cast<unsigned long long>(owner),
            static_cast<unsigned long long>(event_sequence)));
    } else {
        report(wxString::Format("%s thread %llu; event-owner thread %llu remains stopped until its next event.",
            action == debugger::ThreadResumeKind::single_step ? "Stepping" : "Continuing",
            static_cast<unsigned long long>(selected), static_cast<unsigned long long>(owner)));
    }
}

void DebuggerView::step_event() {
    if (!pending_event_) { report("There is no pending debug event to single-step."); return; }
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->single_step_execution(*pending_event_); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    pending_event_.reset(); pending_event_thread_.reset(); invalidate_frames(); ++register_request_;
    refresh_state(); refresh_threads(selected_register_thread_);
    poll_timer_.Start(100);
    report("Stepped one instruction; waiting for the next target event.");
}

void DebuggerView::add_breakpoint() {
    std::uint64_t address = 0;
    if (!parse_unsigned(narrow(breakpoint_address_->GetValue()), address)) {
        report("Enter a valid breakpoint address (decimal or 0x-prefixed hexadecimal)."); return;
    }
    const int selected_kind = breakpoint_kind_->GetSelection();
    const int selected_size = breakpoint_size_->GetSelection();
    constexpr std::uint8_t watch_sizes[] = {1, 2, 4, 8};
    const auto size = selected_size >= 0 && selected_size < 4 ? watch_sizes[selected_size] : std::uint8_t{1};
    debugger::BreakpointKind kind = debugger::BreakpointKind::software;
    switch (selected_kind) {
    case 1: kind = debugger::BreakpointKind::execute; break;
    case 2: kind = debugger::BreakpointKind::read; break;
    case 3: kind = debugger::BreakpointKind::write; break;
    case 4: kind = debugger::BreakpointKind::access; break;
    default: break;
    }
    const auto condition = narrow(breakpoint_condition_->GetValue());
    const bool logpoint = breakpoint_logpoint_->GetValue();
    const auto log_message = narrow(breakpoint_log_message_->GetValue());
    std::uint64_t ignore_count = 0;
    if (!parse_unsigned(narrow(breakpoint_ignore_count_->GetValue()), ignore_count)) {
        report("Ignore count must be an unsigned decimal or 0x-prefixed integer."); return;
    }
    if (condition.size() > 256 || log_message.size() > 1024) {
        report("Breakpoint conditions are limited to 256 bytes and log messages to 1024 bytes."); return;
    }
    auto result = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        auto added = session_->add_breakpoint(address, kind, size);
        if (!added) return added;
        if (!condition.empty()) { auto configured=session_->set_breakpoint_condition(added.value().id, condition); if(!configured) { (void)session_->remove_breakpoint(added.value().id); return Result<debugger::Breakpoint>(configured.error()); } }
        if (logpoint) { auto configured=session_->set_breakpoint_logpoint(added.value().id, true, log_message); if(!configured) { (void)session_->remove_breakpoint(added.value().id); return Result<debugger::Breakpoint>(configured.error()); } }
        if (ignore_count) { auto configured=session_->set_breakpoint_ignore_count(added.value().id, ignore_count); if(!configured) { (void)session_->remove_breakpoint(added.value().id); return Result<debugger::Breakpoint>(configured.error()); } }
        const auto configured=session_->breakpoints();
        auto found=std::find_if(configured.begin(),configured.end(),[&](const auto& bp){return bp.id==added.value().id;});
        return found==configured.end()?added:Result<debugger::Breakpoint>(*found);
    }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    const auto breakpoint = result.value(); breakpoints_.push_back(breakpoint);
    if (submit_ && document_) {
        auto current=document_();
        std::string reason;
        if(current && current->project && current->project->loaded && current->project->loaded->image &&
           current->project->state) {
            auto target=[&]{std::lock_guard lock(inspection_state_->backend_mutex);return std::pair{session_->modules(),session_->process()};}();
            auto mapping=target.first?debugger_image_mapping(*current,target.first.value(),target.second?target.second->architecture:Architecture::unknown,reason):std::nullopt;
            auto image_address=mapping?mapping->to_image(*current->project->loaded->image,address):std::nullopt;
            if(image_address) {
                submit_(SetProjectBreakpoint{*image_address,static_cast<database::ProjectBreakpointKind>(kind),size,true,false,condition,logpoint,log_message,ignore_count});
                report(wxString::Format("Breakpoint and rule saved at project address 0x%llX.",static_cast<unsigned long long>(image_address->offset)));
            } else report("Breakpoint added to this session only; the active module mapping does not identify the project image.");
        } else report("Breakpoint added to this session only; no verified project image mapping is available.");
    }
    const auto row = breakpoints_view_->InsertItem(breakpoints_view_->GetItemCount(),
                                                    wxString::Format("%llu", static_cast<unsigned long long>(breakpoint.id)));
    breakpoints_view_->SetItem(row, 1, wxString::Format("0x%llX", static_cast<unsigned long long>(breakpoint.address)));
    const char *kind_name = breakpoint.kind == debugger::BreakpointKind::software ? "software" :
                            breakpoint.kind == debugger::BreakpointKind::execute ? "hardware execute" :
                            breakpoint.kind == debugger::BreakpointKind::read ? "hardware read" :
                            breakpoint.kind == debugger::BreakpointKind::write ? "hardware write" : "hardware access";
    auto description = wxString::FromUTF8(kind_name);
    if (breakpoint.kind != debugger::BreakpointKind::software)
        description += wxString::Format(" (%u byte%s)", static_cast<unsigned>(breakpoint.size), breakpoint.size == 1 ? "" : "s");
    breakpoints_view_->SetItem(row, 2, description);
    if (logpoint) breakpoints_view_->SetItem(row, 2, description + " · logpoint");
    report(description + " breakpoint added.");
}

void DebuggerView::save_breakpoint_rule() {
    const auto selected = breakpoints_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (selected < 0 || static_cast<std::size_t>(selected) >= breakpoints_.size()) {
        report("Select a breakpoint before saving its rule."); return;
    }
    const auto condition = narrow(breakpoint_condition_->GetValue());
    const auto message = narrow(breakpoint_log_message_->GetValue());
    std::uint64_t ignore_count = 0;
    if (condition.size() > 256 || message.size() > 1024 ||
        !parse_unsigned(narrow(breakpoint_ignore_count_->GetValue()), ignore_count)) {
        report("Rule is invalid: condition/message limits are 256/1024 bytes and ignore count must be an unsigned integer."); return;
    }
    auto breakpoint = breakpoints_[static_cast<std::size_t>(selected)];
    auto configured = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        auto status = session_->set_breakpoint_condition(breakpoint.id, condition);
        if (!status) return status;
        status = session_->set_breakpoint_logpoint(breakpoint.id, breakpoint_logpoint_->GetValue(), message);
        if (!status) return status;
        return session_->set_breakpoint_ignore_count(breakpoint.id, ignore_count);
    }();
    if (!configured) { report(wxString::FromUTF8(configured.error().message)); return; }
    if (document_ && submit_) {
        const auto current = document_();
        std::string reason;
        if (current && current->project && current->project->loaded && current->project->loaded->image && current->project->state) {
            auto target = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return std::pair{session_->modules(), session_->process()}; }();
            auto mapping = target.first ? debugger_image_mapping(*current, target.first.value(), target.second ? target.second->architecture : Architecture::unknown, reason) : std::nullopt;
            auto address = mapping ? mapping->to_image(*current->project->loaded->image, breakpoint.address) : std::nullopt;
            if (address) {
                submit_(SetProjectBreakpoint{*address, static_cast<database::ProjectBreakpointKind>(breakpoint.kind), breakpoint.size, breakpoint.enabled, false, condition, breakpoint_logpoint_->GetValue(), message, ignore_count});
                report("Breakpoint rule saved to the project. Hit counts are saved with the project outside undo history.");
                return;
            }
        }
    }
    report("Rule applied to this debug session; no verified project image mapping is available to save it.");
}

void DebuggerView::persist_project_breakpoint_hit_counts() {
    if (!persist_hit_counts_ || !document_) return;
    const auto current = document_();
    if (!current || !current->project || !current->project->loaded || !current->project->loaded->image ||
        !current->project->state || !current->project->state->user ||
        current->project->mode == database::ProjectMode::read_only ||
        current->project->state->user->breakpoints.empty()) return;

    auto target = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return std::pair{session_->modules(), session_->process()};
    }();
    if (!target.first) return;
    std::string reason;
    auto mapping = debugger_image_mapping(*current, target.first.value(),
        target.second ? target.second->architecture : Architecture::unknown, reason);
    if (!mapping) return;
    const auto runtime_breakpoints = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return session_->breakpoints();
    }();

    std::vector<database::BreakpointHitCount> changed;
    for (const auto &saved : current->project->state->user->breakpoints) {
        const auto runtime = mapping->to_runtime(*current->project->loaded->image, saved.address);
        if (!runtime) continue;
        const auto live = std::find_if(runtime_breakpoints.begin(), runtime_breakpoints.end(), [&](const auto &item) {
            return item.address == *runtime && static_cast<unsigned>(item.kind) == static_cast<unsigned>(saved.kind);
        });
        if (live == runtime_breakpoints.end()) continue;
        const auto cached = queued_hit_counts_.find(saved.id);
        const auto previous = cached == queued_hit_counts_.end() ? saved.hit_count : cached->second;
        if (live->hit_count != previous) changed.push_back({saved.id, live->hit_count});
    }
    if (!changed.empty() && persist_hit_counts_(changed))
        for (const auto &counter : changed) queued_hit_counts_[counter.id] = counter.hit_count;
}

void DebuggerView::apply_project_breakpoints() {
    if (!document_) { report("Open a project before applying project breakpoints."); return; }
    const auto current=document_();
    if (!current || !current->project || !current->project->loaded || !current->project->loaded->image ||
        !current->project->state || !current->project->state->user) {
        report("Project breakpoints cannot be applied until the active project image is loaded."); return;
    }
    if (!pending_event_ && session_->state()!=debugger::SessionState::stopped) {
        report("Stop the target before applying project breakpoints."); return;
    }
    std::string reason;
    auto target=[&]{std::lock_guard lock(inspection_state_->backend_mutex);return std::pair{session_->modules(),session_->process()};}();
    auto mapping=target.first?debugger_image_mapping(*current,target.first.value(),target.second?target.second->architecture:Architecture::unknown,reason):std::nullopt;
    if (!mapping) { report(wxString::FromUTF8(reason)); return; }
    std::size_t applied=0, skipped=0;
    for (const auto &saved: current->project->state->user->breakpoints) {
        const auto runtime=mapping->to_runtime(*current->project->loaded->image,saved.address);
        if (!runtime) { ++skipped; continue; }
        const auto duplicate=std::find_if(breakpoints_.begin(),breakpoints_.end(),[&](const auto& item){return item.address==*runtime && item.kind==static_cast<debugger::BreakpointKind>(saved.kind);});
        if (duplicate!=breakpoints_.end()) continue;
        auto added=[&]{std::lock_guard lock(inspection_state_->backend_mutex);return session_->add_breakpoint(*runtime,static_cast<debugger::BreakpointKind>(saved.kind),saved.size);}();
        if (!added) { ++skipped; continue; }
        auto row=added.value();
        auto counter_status = [&] {
            std::lock_guard lock(inspection_state_->backend_mutex);
            return session_->set_breakpoint_hit_count(row.id, saved.hit_count);
        }();
        if (!counter_status) { std::lock_guard lock(inspection_state_->backend_mutex); (void)session_->remove_breakpoint(row.id); ++skipped; continue; }
        auto rule_status = [&] {
            std::lock_guard lock(inspection_state_->backend_mutex);
            auto status = session_->set_breakpoint_condition(row.id, saved.condition);
            if (!status) return status;
            status = session_->set_breakpoint_logpoint(row.id, saved.logpoint, saved.log_message);
            if (!status) return status;
            return session_->set_breakpoint_ignore_count(row.id, saved.ignore_count);
        }();
        if (!rule_status) { std::lock_guard lock(inspection_state_->backend_mutex); (void)session_->remove_breakpoint(row.id); ++skipped; continue; }
        const auto configured_rows = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->breakpoints(); }();
        if (const auto configured = std::find_if(configured_rows.begin(), configured_rows.end(), [&](const auto &bp) { return bp.id == row.id; }); configured != configured_rows.end()) row = *configured;
        if (!saved.enabled) {
            auto disabled=[&]{std::lock_guard lock(inspection_state_->backend_mutex);return session_->set_breakpoint_enabled(row.id,false);}();
            if (!disabled) { std::lock_guard lock(inspection_state_->backend_mutex); const auto removed=session_->remove_breakpoint(row.id); (void)removed; ++skipped; continue; }
            row.enabled=false;
        }
        breakpoints_.push_back(row);
        const auto line=breakpoints_view_->InsertItem(breakpoints_view_->GetItemCount(),wxString::Format("%llu",static_cast<unsigned long long>(row.id)));
        breakpoints_view_->SetItem(line,1,wxString::Format("0x%llX",static_cast<unsigned long long>(row.address)));
        breakpoints_view_->SetItem(line,2,wxString::Format("project %u",static_cast<unsigned>(saved.kind)));
        ++applied;
    }
    report(wxString::Format("Applied %llu project breakpoint(s); %llu were skipped because they were unmapped or unsupported. Saved project addresses were not changed.",static_cast<unsigned long long>(applied),static_cast<unsigned long long>(skipped)));
}

void DebuggerView::remove_breakpoint() {
    const auto row = breakpoints_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= breakpoints_.size()) {
        report("Select a breakpoint to remove."); return;
    }
    const auto breakpoint = breakpoints_[static_cast<std::size_t>(row)];
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->remove_breakpoint(breakpoint.id); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    breakpoints_.erase(breakpoints_.begin() + row); breakpoints_view_->DeleteItem(row);
    if (submit_ && document_) {
        auto current=document_();
        if(current && current->project && current->project->loaded && current->project->loaded->image && current->project->state) {
            auto target=[&]{std::lock_guard lock(inspection_state_->backend_mutex);return std::pair{session_->modules(),session_->process()};}();
            std::string reason;
            auto mapping=target.first?debugger_image_mapping(*current,target.first.value(),target.second?target.second->architecture:Architecture::unknown,reason):std::nullopt;
            auto address=mapping?mapping->to_image(*current->project->loaded->image,breakpoint.address):std::nullopt;
            if(address)submit_(SetProjectBreakpoint{*address,static_cast<database::ProjectBreakpointKind>(breakpoint.kind),breakpoint.size,true,true});
        }
    }
    report("Breakpoint removed.");
}

void DebuggerView::refresh_threads(std::optional<debugger::ThreadId> preferred) {
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->threads(); }();
    auto run_states = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->thread_run_states(); }();
    thread_run_states_supported_ = static_cast<bool>(run_states);
    if (result) threads_ = std::move(result.value());
    else if (!run_states) { report(wxString::FromUTF8(result.error().message)); return; }
    if (run_states) {
        for (const auto &snapshot : run_states.value()) {
            const auto found = std::find_if(threads_.begin(), threads_.end(), [&](const auto &thread) { return thread.id == snapshot.thread; });
            if (found != threads_.end()) found->state = snapshot.state;
            else {
                const auto name = "thread " + std::to_string(snapshot.thread);
                threads_.push_back({snapshot.thread, name, snapshot.state});
            }
        }
    } else if (run_states.error().code != ErrorCode::unsupported) {
        report(wxString::FromUTF8(run_states.error().message));
    }
    threads_view_->DeleteAllItems(); registers_view_->DeleteAllItems();
    for (std::size_t i = 0; i < threads_.size(); ++i) {
        const auto &thread = threads_[i];
        const auto row = threads_view_->InsertItem(static_cast<long>(i),
                                                    wxString::Format("%llu", static_cast<unsigned long long>(thread.id)));
        threads_view_->SetItem(row, 1, wxString::FromUTF8(thread.name));
        const char *state = thread.state == debugger::ThreadState::running ? "running" :
                            thread.state == debugger::ThreadState::stopped ? "stopped" :
                            thread.state == debugger::ThreadState::exited ? "exited" : "unknown";
        threads_view_->SetItem(row, 2, state);
    }
    if (!preferred && selected_register_thread_) preferred = selected_register_thread_;
    auto selected = threads_.end();
    if (preferred) selected = std::find_if(threads_.begin(), threads_.end(), [&](const auto &thread) { return thread.id == *preferred; });
    if (selected == threads_.end()) {
        selected = std::find_if(threads_.begin(), threads_.end(), [](const auto &thread) {
            return thread.state != debugger::ThreadState::exited;
        });
    }
    const auto row = selected == threads_.end() ? std::size_t{0} : static_cast<std::size_t>(selected - threads_.begin());
    if (!threads_.empty()) threads_view_->SetItemState(static_cast<long>(row), wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
    refresh_registers(row);
}

void DebuggerView::refresh_registers(std::size_t row) {
    invalidate_frames();
    registers_view_->DeleteAllItems();
    registers_.clear(); selected_register_thread_.reset(); selected_register_index_.reset();
    register_value_->Clear();
    if (row >= threads_.size()) { refresh_watches(); return; }
    const auto thread = threads_[row].id;
    selected_register_thread_ = thread;
    if (threads_[row].state == debugger::ThreadState::running ||
        threads_[row].state == debugger::ThreadState::exited) { refresh_watches(); return; }
    const auto generation = session_generation_;
    const auto request = ++register_request_;
    auto session = session_;
    auto state = inspection_state_;
    enqueue_inspection(1, [session, state, thread, generation, request] {
        std::lock_guard backend_lock(state->backend_mutex);
        auto result = session->read_registers(thread);
        std::vector<debugger::RegisterValue> values;
        std::string error;
        if (result) values = std::move(result.value()); else error = result.error().message;
        if (auto *app = wxTheApp) app->CallAfter([state, generation, request, thread,
                values = std::move(values), error = std::move(error)]() mutable {
            std::unique_lock lock(state->mutex);
            auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->register_request_ != request ||
                view->selected_register_thread_ != thread) return;
            if (!error.empty()) {
                view->report(wxString::FromUTF8(error));
                lock.unlock();
                view->refresh_watches();
                return;
            }
            view->registers_ = std::move(values);
            for (std::size_t i = 0; i < view->registers_.size(); ++i) {
                const auto &reg = view->registers_[i];
                const auto index = view->registers_view_->InsertItem(static_cast<long>(i), wxString::FromUTF8(reg.name));
                view->registers_view_->SetItem(index, 1, wxString::FromUTF8(register_hex(reg)));
            }
            view->selected_locals_frame_ = 0;
            lock.unlock();
            view->refresh_locals();
            view->refresh_watches();
        });
    });
}

void DebuggerView::refresh_locals() {
    invalidate_frames();
    if (!document_ || !selected_register_thread_ || session_->state() != debugger::SessionState::stopped) return;
    const auto document = document_();
    if (!document || !document->project || !document->project->loaded || !document->project->loaded->image) return;
    const auto selected_thread = std::find_if(threads_.begin(), threads_.end(), [&](const auto &thread) {
        return thread.id == *selected_register_thread_;
    });
    if (selected_thread == threads_.end() || selected_thread->state == debugger::ThreadState::running ||
        selected_thread->state == debugger::ThreadState::exited) return;
    std::optional<std::uint64_t> runtime_pc;
    for (const auto &reg : registers_) {
        const auto name = reg.name;
        if (name == "RIP" || name == "rip" || name == "EIP" || name == "eip" || name == "PC" || name == "pc" ||
            (document->project->loaded->image->layout().architecture == Architecture::arm && (name == "R15" || name == "r15"))) {
            std::uint64_t value = 0;
            const bool big = reg.byte_order == ByteOrder::big;
            if (reg.bytes.empty() || reg.bytes.size() > 8) break;
            for (std::size_t i = 0; i < reg.bytes.size(); ++i) {
                const auto index = big ? i : reg.bytes.size() - 1 - i;
                value = (value << 8) | std::to_integer<std::uint8_t>(reg.bytes[index]);
            }
            runtime_pc = value;
            break;
        }
    }
    if (!runtime_pc) return;
    inspection_document_ = document;
    const auto stop = pending_event_;
    const auto thread = *selected_register_thread_;
    const auto generation = session_generation_;
    const auto request = ++locals_request_;
    const auto register_request = register_request_;
    const auto registers = registers_;
    const auto selected_frame = selected_locals_frame_;
    auto session = session_;
    auto state = inspection_state_;
    enqueue_inspection(5, [session, state, document, stop,
                           registers, runtime_pc = *runtime_pc, selected_frame, thread,
                           generation, request, register_request] {
        std::vector<DebuggerStackFrame> frames;
        std::vector<std::string> labels;
        std::vector<DebuggerLocalRow> rows;
        std::string mapping_reason;
        std::optional<DebuggerImageMapping> inspected_mapping;
        {
            std::lock_guard backend_lock(state->backend_mutex);
            auto modules = session->modules();
            if (modules) {
                const auto process = session->process();
                const auto mapping = debugger_image_mapping(*document, modules.value(),
                    process ? process->architecture : Architecture::unknown, mapping_reason);
                inspected_mapping = mapping;
                if (mapping && mapping->to_image(*document->project->loaded->image, runtime_pc)) {
                    const auto module_base = mapping->runtime_base;
                    const auto module_size = mapping->size;
                    const auto read_memory = [session](std::uint64_t address, std::size_t size) {
                        return session->read_memory(address, size);
                    };
                    const auto architecture = process ? process->architecture : Architecture::unknown;
                    const auto &loaded = *document->project->loaded;
                    const auto *macho = loaded.metadata.macho ? &*loaded.metadata.macho : nullptr;
                    const auto *elf = loaded.metadata.elf ? &*loaded.metadata.elf : nullptr;
                    const auto *pe = loaded.metadata.pe ? &*loaded.metadata.pe : nullptr;
                    frames = debugger_stack_frames_at(*loaded.image, runtime_pc, module_base,
                        module_size, architecture, registers, macho, read_memory, 64,
                        loaded.metadata.preferred_base, elf, pe);
                    for (std::size_t i = 0; i < frames.size(); ++i) {
                        const auto &frame = frames[i];
                        char address[32]{};
                        std::snprintf(address, sizeof(address), "0x%llX", static_cast<unsigned long long>(frame.runtime_pc));
                        std::string label = "Frame " + std::to_string(i) + " - " + address;
                        if (auto symbol = symbolize_debugger_address(*document->project, *loaded.image,
                                frame.runtime_pc, module_base, module_size); symbol) {
                            if (!symbol->name.empty()) {
                                label += " - " + symbol->name;
                                if (symbol->displacement) {
                                    char displacement[24]{};
                                    std::snprintf(displacement, sizeof(displacement), "+0x%llX",
                                        static_cast<unsigned long long>(symbol->displacement));
                                    label += displacement;
                                }
                            }
                            if (symbol->source_location) label += " - " + *symbol->source_location;
                        }
                        labels.push_back(std::move(label));
                    }
                    if (!frames.empty()) {
                        const auto frame_index = std::min(selected_frame, frames.size() - 1);
                        const auto &frame = frames[frame_index];
                        rows = debugger_locals_at(*document->project, *loaded.image, frame.runtime_pc,
                            module_base, architecture, frame.registers, read_memory, frame.call_frame_cfa);
                    }
                } else if (mapping) mapping_reason = "Static mapping unavailable: thread PC is outside mapped executable image coverage.";
            } else mapping_reason = "Static mapping unavailable: " + modules.error().message;
        }
        if (auto *app = wxTheApp) app->CallAfter([state, generation, request, register_request, thread, document, stop, inspected_mapping, mapping_reason = std::move(mapping_reason),
                frames = std::move(frames), labels = std::move(labels), rows = std::move(rows)]() mutable {
            std::lock_guard lock(state->mutex);
            auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->locals_request_ != request ||
                view->register_request_ != register_request || view->selected_register_thread_ != thread || !view->current_document(document) ||
                view->pending_event_ != stop || view->session_->state() != debugger::SessionState::stopped) return;
            if (!mapping_reason.empty()) view->report(wxString::FromUTF8(mapping_reason));
            view->frames_stop_ = stop;
            view->frames_mapping_ = inspected_mapping;
            view->locals_stack_frames_ = std::move(frames);
            if (view->locals_stack_frames_.empty()) return;
            view->selected_locals_frame_ = std::min(view->selected_locals_frame_, view->locals_stack_frames_.size() - 1);
            for (const auto &label : labels) view->locals_frame_choice_->Append(wxString::FromUTF8(label));
            view->locals_frame_choice_->SetSelection(static_cast<int>(view->selected_locals_frame_));
            for (const auto &local : rows) {
                const auto row = view->locals_view_->InsertItem(view->locals_view_->GetItemCount(), wxString::FromUTF8(local.name));
                view->locals_view_->SetItem(row, 1, wxString::FromUTF8(local.kind));
                view->locals_view_->SetItem(row, 2, wxString::FromUTF8(local.scope));
                view->locals_view_->SetItem(row, 3, wxString::FromUTF8(local.location));
                view->locals_view_->SetItem(row, 4, wxString::FromUTF8(local.value));
            }
        });
    });
}

bool DebuggerView::current_document(const std::shared_ptr<const DocumentSnapshot> &expected) const {
    const auto current = document_ ? document_() : nullptr;
    return current && expected && current->id == expected->id && current->revision == expected->revision &&
        current->project == expected->project;
}

void DebuggerView::invalidate_frames() {
    ++locals_request_;
    locals_stack_frames_.clear();
    frames_stop_.reset();
    frames_mapping_.reset();
    locals_frame_choice_->Clear();
    locals_view_->DeleteAllItems();
}

void DebuggerView::document_changed() {
    if (current_document(inspection_document_)) return;
    queued_hit_counts_.clear();
    invalidate_frames();
    if (watch_project_uuid_) save_watch_expressions();
    inspection_document_ = document_ ? document_() : nullptr;
    std::optional<database::ProjectUuid> next_uuid;
    if (inspection_document_ && inspection_document_->project && inspection_document_->project->state)
        next_uuid = inspection_document_->project->state->uuid;
    watch_expressions_.clear();
    watch_project_uuid_ = next_uuid;
    if (watch_project_uuid_) {
        if (auto *config = wxConfigBase::Get(false)) {
            const auto previous_path = config->GetPath();
            config->SetPath(debugger_project_config_path(*watch_project_uuid_));
            long count = 0;
            if (config->Read("Count", &count) && count >= 0 && count <= 64) {
                for (long i = 0; i < count; ++i) {
                    wxString value;
                    if (!config->Read(wxString::Format("Watch%ld", i), &value) || value.empty() || value.length() > 256) continue;
                    auto expression = value.ToStdString();
                    if (expression.size() > 256 || std::find(watch_expressions_.begin(), watch_expressions_.end(), expression) != watch_expressions_.end()) continue;
                    watch_expressions_.push_back(std::move(expression));
                }
            }
            config->SetPath(previous_path);
        }
    }
    refresh_watches();
    selected_locals_frame_ = 0;
    if (inspection_document_ && selected_register_thread_ && !registers_.empty()) refresh_locals();
}

void DebuggerView::save_watch_expressions() {
    if (!watch_project_uuid_) return;
    auto *config = wxConfigBase::Get(false);
    if (!config) return;
    const auto previous_path = config->GetPath();
    config->SetPath(debugger_project_config_path(*watch_project_uuid_));
    std::size_t count = 0;
    for (const auto &expression : watch_expressions_) {
        if (count >= 64 || expression.empty() || expression.size() > 256) continue;
        config->Write(wxString::Format("Watch%lu", static_cast<unsigned long>(count)), wxString::FromUTF8(expression));
        ++count;
    }
    config->Write("Count", static_cast<long>(count));
    config->SetPath(previous_path);
    config->Flush();
}

void DebuggerView::navigate_pc(bool selected_frame) {
    document_changed();
    if (!navigate_ || !pending_event_ || session_->state() != debugger::SessionState::stopped) {
        report("Static navigation requires a stopped target and an open document."); return;
    }
    if (!current_document(inspection_document_) || frames_stop_ != pending_event_ || locals_stack_frames_.empty()) {
        report("Static navigation unavailable: refresh stopped-thread registers and wait for current frame inspection."); return;
    }
    const auto index = selected_frame ? selected_locals_frame_ : std::size_t{0};
    if (index >= locals_stack_frames_.size()) { report("Select an inspected stack frame first."); return; }
    const auto document = inspection_document_;
    std::string reason;
    std::optional<DebuggerImageMapping> mapping;
    {
        std::lock_guard lock(inspection_state_->backend_mutex);
        const auto modules = session_->modules();
        const auto process = session_->process();
        if (modules) mapping = debugger_image_mapping(*document, modules.value(),
            process ? process->architecture : Architecture::unknown, reason);
        else reason = "Static navigation unavailable: " + modules.error().message;
    }
    if (!mapping) { invalidate_frames(); report(wxString::FromUTF8(reason)); return; }
    if (mapping != frames_mapping_) {
        invalidate_frames();
        refresh_locals();
        report("Static navigation unavailable: target module mapping changed; refreshing frames."); return;
    }
    const auto address = mapping->to_image(*document->project->loaded->image, locals_stack_frames_[index].runtime_pc);
    if (!address) { report("Static navigation unavailable: PC is outside mapped executable image coverage."); return; }
    navigate_(document->id, Location{*address});
}

void DebuggerView::toggle_selection_breakpoint() {
    document_changed();
    const auto selected = selection_ ? selection_() : std::nullopt;
    const auto document = document_ ? document_() : nullptr;
    if (!selected || !document || selected->first != document->id ||
        session_->state() != debugger::SessionState::stopped) {
        report("Listing breakpoint requires a stopped target and a selection in the active document."); return;
    }
    std::string reason;
    std::optional<DebuggerImageMapping> mapping;
    {
        std::lock_guard lock(inspection_state_->backend_mutex);
        const auto modules = session_->modules();
        const auto process = session_->process();
        if (modules) mapping = debugger_image_mapping(*document, modules.value(),
            process ? process->architecture : Architecture::unknown, reason);
        else reason = "Listing breakpoint unavailable: " + modules.error().message;
    }
    if (!mapping) { report(wxString::FromUTF8(reason)); return; }
    const auto &image = *document->project->loaded->image;
    std::optional<Address> address;
    if (const auto *value = std::get_if<Address>(&selected->second)) address = *value;
    else if (const auto converted = image.to_address(std::get<FileOffset>(selected->second)); converted)
        address = converted.value();
    const auto runtime = address ? mapping->to_runtime(image, *address) : std::nullopt;
    if (!runtime) { report("Listing breakpoint unavailable: selection is outside mapped executable image coverage."); return; }
    const auto existing = std::find_if(breakpoints_.begin(), breakpoints_.end(), [&](const auto &bp) {
        return bp.kind == debugger::BreakpointKind::software && bp.address == *runtime;
    });
    if (existing != breakpoints_.end()) {
        const auto row = static_cast<long>(existing - breakpoints_.begin());
        breakpoints_view_->SetItemState(-1, 0, wxLIST_STATE_SELECTED);
        breakpoints_view_->SetItemState(row, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
        remove_breakpoint();
    } else {
        breakpoint_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(*runtime)));
        breakpoint_kind_->SetSelection(0);
        add_breakpoint();
    }
}

void DebuggerView::write_register() {
    if (!selected_register_thread_ || !selected_register_index_ || *selected_register_index_ >= registers_.size()) {
        report("Select a register to edit."); return;
    }
    const auto &current = registers_[*selected_register_index_];
    auto input = narrow(register_value_->GetValue());
    constexpr std::size_t max_register_input_chars = 512 * 3;
    if (input.size() > max_register_input_chars) {
        report("Register edit input exceeds the 512-byte register limit."); return;
    }
    std::string_view digits = input;
    if (digits.starts_with("0x") || digits.starts_with("0X")) digits.remove_prefix(2);
    std::vector<std::byte> value;
    bool too_many = false;
    if (!parse_hex_bytes(digits, value, 512, too_many)) {
        report(too_many ? "Register edits are limited to 512 bytes."
                        : "Enter the register value as hexadecimal byte pairs."); return;
    }
    if (value.size() != current.bytes.size()) {
        report(wxString::Format("Register %s requires exactly %llu bytes.", wxString::FromUTF8(current.name),
                                static_cast<unsigned long long>(current.bytes.size()))); return;
    }
    if (current.byte_order != ByteOrder::big) std::reverse(value.begin(), value.end());
    auto update = current;
    update.bytes = std::move(value);
    const auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->write_registers(*selected_register_thread_, std::span<const debugger::RegisterValue>(&update, 1)); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    const auto thread = *selected_register_thread_;
    const auto selected = *selected_register_index_;
    const auto name = current.name;
    auto thread_row = std::find_if(threads_.begin(), threads_.end(), [thread](const auto &candidate) { return candidate.id == thread; });
    if (thread_row != threads_.end()) refresh_registers(static_cast<std::size_t>(thread_row - threads_.begin()));
    if (selected < registers_.size()) {
        registers_view_->SetItemState(static_cast<long>(selected), wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
        selected_register_index_ = selected;
        register_value_->SetValue(wxString::FromUTF8(register_hex(registers_[selected])));
    }
    report(wxString::Format("Wrote register %s.", wxString::FromUTF8(name)));
}

void DebuggerView::refresh_memory() {
    std::uint64_t address = 0;
    if (!parse_unsigned(narrow(memory_address_->GetValue()), address)) {
        memory_view_->SetValue("Memory read failed: invalid address.");
        report("Enter a valid memory address (decimal or 0x-prefixed hexadecimal)."); return;
    }
    const int page = memory_page_size_->GetSelection();
    constexpr std::size_t page_sizes[] = {64, 256, 1024};
    const auto count = page >= 0 && page < 3 ? page_sizes[page] : page_sizes[1];
    const auto generation = session_generation_;
    const auto request = ++memory_request_;
    auto session = session_;
    auto state = inspection_state_;
    memory_view_->SetValue("Reading memory...");
    enqueue_inspection(2, [session, state, address, count, generation, request] {
      std::lock_guard backend_lock(state->backend_mutex);
      auto result = session->read_memory(address, count);
      std::string error, dump;
      if (!result) error = result.error().message;
      else if (result.value().size() > count) error = "backend returned more bytes than requested.";
      else {
        const auto &bytes = result.value();
        for (std::size_t offset = 0; offset < bytes.size(); offset += 16) {
        char line[32]{};
        const auto written = std::snprintf(line, sizeof(line), "%016llX  ",
            static_cast<unsigned long long>(address + offset));
        dump.append(line, static_cast<std::size_t>(written));
        for (std::size_t i = 0; i < 16; ++i) {
            if (offset + i < bytes.size()) {
                const auto value = std::to_integer<unsigned>(bytes[offset + i]);
                static constexpr char digits[] = "0123456789ABCDEF";
                dump.push_back(digits[value >> 4]); dump.push_back(digits[value & 15]);
            } else dump.append("  ");
            dump.push_back(' ');
        }
        dump.append(" | ");
        for (std::size_t i = 0; i < 16 && offset + i < bytes.size(); ++i) {
            const auto value = std::to_integer<unsigned char>(bytes[offset + i]);
            dump.push_back(value >= 32 && value < 127 ? static_cast<char>(value) : '.');
        }
        dump.push_back('\n');
        }
      }
      if (auto *app = wxTheApp) app->CallAfter([state, generation, request, error = std::move(error), dump = std::move(dump)] {
          std::lock_guard lock(state->mutex);
          auto *view = state->target;
          if (!view || view->session_generation_ != generation || view->memory_request_ != request) return;
          if (!error.empty()) {
              view->memory_view_->SetValue("Memory read failed: " + wxString::FromUTF8(error));
              view->report(wxString::FromUTF8(error));
          } else view->memory_view_->SetValue(wxString::FromUTF8(dump));
      });
    });
}

void DebuggerView::start_memory_search() {
    auto parsed = debugger::parse_memory_search_pattern(narrow(memory_search_pattern_->GetValue()));
    if (!parsed) {
        report("Invalid search pattern: " + wxString::FromUTF8(parsed.error().message));
        memory_search_status_->SetLabel("Invalid pattern.");
        return;
    }

    debugger::MemorySearchOptions options;
    const auto start_text = narrow(memory_search_start_->GetValue());
    const auto length_text = narrow(memory_search_length_->GetValue());
    if (start_text.empty() != length_text.empty()) {
        report("Enter both a range start and length, or leave both blank.");
        memory_search_status_->SetLabel("Range needs both a start and length.");
        return;
    }
    if (!start_text.empty()) {
        std::uint64_t start = 0, length = 0;
        if (!parse_unsigned(start_text, start) || !parse_unsigned(length_text, length) || length == 0 ||
            length > std::numeric_limits<std::uint64_t>::max() - start) {
            report("Enter a valid non-empty range that does not wrap the address space.");
            memory_search_status_->SetLabel("Invalid range.");
            return;
        }
        options.ranges.push_back({start, length});
    }
    std::uint64_t alignment = 0;
    if (!parse_unsigned(narrow(memory_search_alignment_->GetValue()), alignment) || alignment == 0) {
        report("Alignment must be a positive decimal or 0x-prefixed integer.");
        memory_search_status_->SetLabel("Invalid alignment.");
        return;
    }
    options.alignment = alignment;
    switch (memory_search_permissions_->GetSelection()) {
    case 1: options.executable = true; break;
    case 2: options.writable = true; break;
    case 3: options.executable = false; break;
    default: break;
    }

    memory_search_stop_.request_stop();
    memory_search_stop_ = std::stop_source{};
    const auto cancellation = memory_search_stop_.get_token();
    const auto generation = session_generation_;
    const auto request = ++memory_search_request_;
    auto pattern = std::move(parsed.value());
    auto session = session_;
    auto state = inspection_state_;
    memory_search_matches_.clear();
    memory_search_results_->DeleteAllItems();
    memory_search_status_->SetLabel("Searching mapped memory...");
    memory_search_start_button_->Disable();
    memory_search_cancel_button_->Enable();
    enqueue_inspection(6, [session, state, generation, request, cancellation,
                           pattern = std::move(pattern), options = std::move(options)]() mutable {
        std::string error;
        std::optional<debugger::MemorySearchReport> report;
        {
            std::lock_guard backend_lock(state->backend_mutex);
            auto result = session->search_memory(pattern, options, cancellation);
            if (result) report = std::move(result.value());
            else error = result.error().message;
        }
        if (auto *app = wxTheApp) app->CallAfter([state, generation, request, error = std::move(error), report = std::move(report)]() mutable {
            std::lock_guard lock(state->mutex);
            auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->memory_search_request_ != request) return;
            view->memory_search_start_button_->Enable();
            view->memory_search_cancel_button_->Disable();
            view->memory_search_matches_.clear();
            view->memory_search_results_->DeleteAllItems();
            if (!error.empty()) {
                view->memory_search_status_->SetLabel("Search failed: " + wxString::FromUTF8(error));
                view->report("Memory search failed: " + wxString::FromUTF8(error));
                return;
            }
            if (!report) return;
            view->memory_search_matches_ = report->matches;
            for (const auto address : view->memory_search_matches_) {
                const auto row = view->memory_search_results_->InsertItem(view->memory_search_results_->GetItemCount(),
                    wxString::Format("0x%llX", static_cast<unsigned long long>(address)));
                (void)row;
            }
            view->memory_search_status_->SetLabel(wxString::Format(
                "%s — %llu hit(s), %llu/%llu bytes read, %llu comparisons, %llu read failure(s).",
                memory_search_completion(report->completion),
                static_cast<unsigned long long>(report->matches.size()),
                static_cast<unsigned long long>(report->bytes_read),
                static_cast<unsigned long long>(report->bytes_requested),
                static_cast<unsigned long long>(report->comparisons),
                static_cast<unsigned long long>(report->failures.size())));
        });
    });
}

void DebuggerView::cancel_memory_search() {
    memory_search_stop_.request_stop();
    memory_search_cancel_button_->Disable();
    memory_search_status_->SetLabel("Canceling memory search...");
}

void DebuggerView::write_memory() {
    std::uint64_t address = 0;
    if (!parse_unsigned(narrow(memory_address_->GetValue()), address)) {
        report("Enter a valid memory address before writing bytes."); return;
    }
    constexpr std::size_t max_write_bytes = 1024;
    constexpr std::size_t max_encoded_chars = max_write_bytes * 3;
    const auto &input = memory_write_bytes_->GetValue();
    if (input.length() > max_encoded_chars) {
        report("Memory write input exceeds the 1024-byte pane limit."); return;
    }
    std::vector<std::byte> bytes;
    bool too_many = false;
    if (!parse_hex_bytes(narrow(input), bytes, max_write_bytes, too_many)) {
        if (too_many) { report("Memory write input exceeds the 1024-byte pane limit."); return; }
        report("Enter non-empty hexadecimal bytes in pairs (for example: 90 C3)."); return;
    }
    const int page = memory_page_size_->GetSelection();
    constexpr std::size_t page_sizes[] = {64, 256, 1024};
    const auto limit = page >= 0 && page < 3 ? page_sizes[page] : page_sizes[1];
    if (bytes.size() > limit) {
        report(wxString::Format("Write is limited to the selected %llu-byte memory page.",
                                static_cast<unsigned long long>(limit))); return;
    }
    if (address > UINT64_MAX - bytes.size()) {
        report("Memory write range would overflow the address space."); return;
    }
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->write_memory(address, bytes); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    memory_write_bytes_->Clear();
    refresh_memory();
    report(wxString::Format("Wrote %llu byte(s) at 0x%llX and refreshed memory.",
                            static_cast<unsigned long long>(bytes.size()),
                            static_cast<unsigned long long>(address)));
}

void DebuggerView::move_memory_page(int direction) {
    std::uint64_t address = 0;
    if (!parse_unsigned(narrow(memory_address_->GetValue()), address)) {
        memory_view_->SetValue("Memory paging failed: invalid address.");
        report("Enter a valid memory address (decimal or 0x-prefixed hexadecimal)."); return;
    }
    const int page = memory_page_size_->GetSelection();
    constexpr std::uint64_t page_sizes[] = {64, 256, 1024};
    const auto count = page >= 0 && page < 3 ? page_sizes[page] : page_sizes[1];
    if (direction < 0) {
        if (address < count) { report("Previous memory page would underflow the address space."); return; }
        address -= count;
    } else {
        if (address > UINT64_MAX - count) { report("Next memory page would overflow the address space."); return; }
        address += count;
    }
    memory_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(address)));
    refresh_memory();
}

void DebuggerView::refresh_modules() {
    invalidate_frames();
    modules_view_->DeleteAllItems();
    modules_.clear();
    const auto generation = session_generation_;
    const auto request = ++module_request_;
    auto session = session_; auto state = inspection_state_;
    enqueue_inspection(3, [session, state, generation, request] {
        std::lock_guard backend_lock(state->backend_mutex);
        auto result = session->modules();
        std::vector<debugger::ModuleInfo> values; std::string error;
        if (result) values = std::move(result.value()); else error = result.error().message;
        if (auto *app = wxTheApp) app->CallAfter([state, generation, request, values = std::move(values), error = std::move(error)]() mutable {
            std::unique_lock lock(state->mutex); auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->module_request_ != request) return;
            view->modules_.clear();
            if (!error.empty()) { view->modules_view_->InsertItem(0, "Unavailable: " + wxString::FromUTF8(error)); view->report(wxString::FromUTF8(error)); return; }
            view->modules_ = std::move(values);
            for (const auto &module : view->modules_) {
                const auto row = view->modules_view_->InsertItem(view->modules_view_->GetItemCount(), wxString::Format("0x%llX", static_cast<unsigned long long>(module.base)));
                view->modules_view_->SetItem(row, 1, wxString::Format("0x%llX", static_cast<unsigned long long>(module.size)));
                view->modules_view_->SetItem(row, 2, wxString::FromUTF8(module.name));
                view->modules_view_->SetItem(row, 3, wxString::FromUTF8(module.path));
            }
            lock.unlock();
            view->refresh_locals();
        });
    });
}

void DebuggerView::refresh_memory_regions() {
    memory_regions_view_->DeleteAllItems();
    memory_regions_.clear();
    const auto generation = session_generation_;
    const auto request = ++region_request_;
    auto session = session_; auto state = inspection_state_;
    enqueue_inspection(4, [session, state, generation, request] {
        std::lock_guard backend_lock(state->backend_mutex);
        auto result = session->memory_regions();
        std::vector<debugger::MemoryRegion> values; std::string error;
        if (result) values = std::move(result.value()); else error = result.error().message;
        if (auto *app = wxTheApp) app->CallAfter([state, generation, request, values = std::move(values), error = std::move(error)]() mutable {
            std::lock_guard lock(state->mutex); auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->region_request_ != request) return;
            view->memory_regions_.clear();
            if (!error.empty()) { view->memory_regions_view_->InsertItem(0, "Unavailable: " + wxString::FromUTF8(error)); view->report(wxString::FromUTF8(error)); return; }
            view->memory_regions_ = std::move(values);
            for (const auto &region : view->memory_regions_) {
                const auto row = view->memory_regions_view_->InsertItem(view->memory_regions_view_->GetItemCount(), wxString::Format("0x%llX", static_cast<unsigned long long>(region.start)));
                view->memory_regions_view_->SetItem(row, 1, wxString::Format("0x%llX", static_cast<unsigned long long>(region.length)));
                std::string permissions;
                permissions.push_back(region.readable ? 'r' : '-'); permissions.push_back(region.writable ? 'w' : '-'); permissions.push_back(region.executable ? 'x' : '-');
                view->memory_regions_view_->SetItem(row, 2, permissions);
                view->memory_regions_view_->SetItem(row, 3, wxString::FromUTF8(region.type));
            }
        });
    });
}

void DebuggerView::add_watch_expression() {
    auto expression = narrow(watch_expression_->GetValue());
    const auto first = std::find_if_not(expression.begin(), expression.end(), [](unsigned char c) { return std::isspace(c); });
    const auto last = std::find_if_not(expression.rbegin(), expression.rend(), [](unsigned char c) { return std::isspace(c); }).base();
    if (first >= last) { report("Enter a watch expression first."); return; }
    expression = std::string(first, last);
    if (expression.size() > 256) { report("Watch expressions are limited to 256 bytes."); return; }
    if (watch_expressions_.size() >= 64) { report("The watch list is limited to 64 expressions."); return; }
    if (std::find(watch_expressions_.begin(), watch_expressions_.end(), expression) != watch_expressions_.end()) {
        report("That watch expression is already in the list."); return;
    }
    watch_expressions_.push_back(std::move(expression));
    save_watch_expressions();
    watch_expression_->Clear();
    refresh_watches();
}

void DebuggerView::remove_watch_expression() {
    const auto row = watch_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= watch_expressions_.size()) {
        report("Select a watch expression to remove."); return;
    }
    watch_expressions_.erase(watch_expressions_.begin() + row);
    save_watch_expressions();
    refresh_watches();
}

void DebuggerView::refresh_watches() {
    watch_view_->DeleteAllItems();
    const auto insert_rows = [&](const wxString &status) {
        for (const auto &expression : watch_expressions_) {
            const auto row = watch_view_->InsertItem(watch_view_->GetItemCount(), wxString::FromUTF8(expression));
            watch_view_->SetItem(row, 1, status);
        }
    };
    if (watch_expressions_.empty()) return;
    if (session_->state() != debugger::SessionState::stopped) {
        insert_rows("target is not stopped");
        return;
    }
    if (!selected_register_thread_) {
        insert_rows("select a stopped thread");
        return;
    }
    const auto selected = std::find_if(threads_.begin(), threads_.end(), [&](const auto &thread) {
        return thread.id == *selected_register_thread_;
    });
    if (selected == threads_.end() || selected->state != debugger::ThreadState::stopped) {
        insert_rows("selected thread is not stopped");
        return;
    }
    insert_rows("evaluating…");
    const auto thread = *selected_register_thread_;
    const auto generation = session_generation_;
    const auto stop = pending_event_;
    const auto request = ++watch_request_;
    const auto expressions = watch_expressions_;
    auto session = session_;
    auto state = inspection_state_;
    enqueue_inspection(6, [session, state, thread, generation, stop, request, expressions] {
        std::vector<std::string> values;
        values.reserve(expressions.size());
        {
            std::lock_guard backend_lock(state->backend_mutex);
            for (const auto &expression : expressions) {
                auto result = session->evaluate_expression(thread, expression);
                if (result) {
                    char value[32]{};
                    std::snprintf(value, sizeof(value), "0x%llX", static_cast<unsigned long long>(result.value()));
                    values.emplace_back(value);
                } else {
                    values.emplace_back("error: " + result.error().message);
                }
            }
        }
        if (auto *app = wxTheApp) app->CallAfter([state, thread, generation, stop, request,
                expressions, values = std::move(values)]() mutable {
            std::lock_guard lock(state->mutex);
            auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->watch_request_ != request ||
                view->selected_register_thread_ != thread || view->pending_event_ != stop ||
                view->session_->state() != debugger::SessionState::stopped || view->watch_expressions_ != expressions)
                return;
            for (std::size_t i = 0; i < values.size(); ++i)
                view->watch_view_->SetItem(static_cast<long>(i), 1, wxString::FromUTF8(values[i]));
        });
    });
}

void DebuggerView::clear_inspection() {
    invalidate_frames();
    inspection_document_.reset();
    ++session_generation_;
    inspection_state_->session_generation.fetch_add(1, std::memory_order_acq_rel);
    inspection_state_->stop_generation.fetch_add(1, std::memory_order_acq_rel);
    ++register_request_; ++memory_request_; ++module_request_; ++region_request_; ++locals_request_;
    ++memory_search_request_;
    ++watch_request_;
    memory_search_stop_.request_stop();
    registers_.clear(); selected_register_thread_.reset(); selected_register_index_.reset();
    registers_view_->DeleteAllItems(); register_value_->Clear();
    modules_.clear(); modules_view_->DeleteAllItems();
    memory_regions_.clear(); memory_regions_view_->DeleteAllItems();
    locals_view_->DeleteAllItems();
    memory_view_->Clear(); memory_address_->Clear();
    memory_search_matches_.clear(); memory_search_results_->DeleteAllItems();
    watch_view_->DeleteAllItems();
    memory_search_status_->SetLabel("No memory search has run.");
    memory_search_start_button_->Enable(); memory_search_cancel_button_->Disable();
}

void DebuggerView::refresh_state() {
    using debugger::SessionState;
    const char *label = "Idle";
    switch (session_->state()) {
    case SessionState::idle: label = "Idle"; break;
    case SessionState::running: label = "Running"; break;
    case SessionState::stopped: label = "Stopped"; break;
    case SessionState::exited: label = "Exited"; break;
    case SessionState::detached: label = "Detached"; break;
    case SessionState::faulted: label = "Faulted"; break;
    }
    state_->SetValue(label);
    update_process_actions();
}

void DebuggerView::report(const wxString &message) {
    log_->AppendText(message + "\n");
    const auto excess = log_->GetLastPosition() - 32768;
    if (excess > 0) log_->Remove(0, excess);
}
} // namespace hexlab::desktop
