#include "debugger_view.hpp"
#include "support/desktop_test_window.hpp"
#include "main_frame.hpp"

#include <wx/app.h>
#include <wx/button.h>
#include <wx/choice.h>
#include <wx/frame.h>
#include <wx/aui/aui.h>
#include <wx/listctrl.h>
#include <wx/textctrl.h>

#include <cstdio>
#include <memory>

using namespace hexlab;
using namespace hexlab::debugger;
using namespace hexlab::desktop;

namespace {
struct FakeState {
    Target launched;
    ProcessId attached = 0;
    std::optional<std::pair<std::uint64_t, ContinueStatus>> continued;
    std::uint64_t breakpoint_address = 0;
    BreakpointKind breakpoint_kind = BreakpointKind::software;
    std::uint8_t breakpoint_size = 1;
    std::uint64_t last_memory_address = 0;
    std::size_t last_memory_size = 0;
    std::uint64_t written_memory_address = 0;
    std::vector<std::byte> written_memory_bytes;
    std::vector<RegisterValue> written_registers;
    ThreadId written_register_thread = 0;
    unsigned register_write_calls = 0;
    std::vector<std::byte> current_register_bytes = std::vector<std::byte>(8, std::byte{0x10});
    bool fail_register_write = false;
    bool fail_memory_read = false;
    bool fail_memory_write = false;
    bool fail_module_list = false;
    bool fail_memory_regions = false;
};

class FakeBackend final : public Backend {
  public:
    explicit FakeBackend(std::shared_ptr<FakeState> state) : state_(std::move(state)) {}
    Result<ProcessInfo> launch(const Target &target) override {
        state_->launched = target;
        event_ready_ = true;
        return ProcessInfo{99, target.executable, Architecture::x86_64};
    }
    Result<ProcessInfo> attach(ProcessId id) override {
        state_->attached = id;
        event_ready_ = true;
        return ProcessInfo{id, "attached-process", Architecture::x86_64};
    }
    Result<std::vector<ProcessInfo>> processes() override {
        return std::vector<ProcessInfo>{{1234, "sample.exe", Architecture::x86_64}};
    }
    Status detach() override { return std::monostate{}; }
    Result<DebugEvent> wait_event(std::chrono::milliseconds) override {
        if (!event_ready_)
            return Error{ErrorCode::busy, "debug event wait timed out"};
        event_ready_ = false;
        return DebugEvent{7, EventKind::breakpoint, 99, 77, 0x401000, "breakpoint", 0, {12, 13}};
    }
    Status continue_event(std::uint64_t sequence, ContinueStatus status) override {
        state_->continued = std::pair{sequence, status};
        return std::monostate{};
    }
    Result<std::vector<std::byte>> read_memory(std::uint64_t address, std::size_t size) override {
        state_->last_memory_address = address;
        state_->last_memory_size = size;
        if (state_->fail_memory_read) return Error{ErrorCode::io, "injected memory read failure"};
        return std::vector<std::byte>(size, std::byte{0x41});
    }
    Status write_memory(std::uint64_t address, std::span<const std::byte> bytes) override {
        if (state_->fail_memory_write) return Error{ErrorCode::io, "injected memory write failure"};
        state_->written_memory_address = address;
        state_->written_memory_bytes.assign(bytes.begin(), bytes.end());
        return std::monostate{};
    }
    Result<std::vector<ThreadInfo>> threads() override {
        return std::vector<ThreadInfo>{{77, "main", ThreadState::stopped}};
    }
    Result<std::vector<ModuleInfo>> modules() override {
        if (state_->fail_module_list) return Error{ErrorCode::io, "injected module enumeration failure"};
        return std::vector<ModuleInfo>{{"sample.exe", "C:/bin/sample.exe", 0x400000, 0x10000}};
    }
    Result<std::vector<MemoryRegion>> memory_regions() override {
        if (state_->fail_memory_regions) return Error{ErrorCode::io, "injected memory-region enumeration failure"};
        return std::vector<MemoryRegion>{{0x400000, 0x1000, true, false, true, "image"},
                                         {0x500000, 0x2000, true, true, false, "private"}};
    }
    Result<std::vector<RegisterValue>> read_registers(ThreadId) override {
        return std::vector<RegisterValue>{{"RIP", state_->current_register_bytes}};
    }
    Status write_registers(ThreadId thread, std::span<const RegisterValue> registers) override {
        ++state_->register_write_calls;
        if (state_->fail_register_write) return Error{ErrorCode::io, "injected register write failure"};
        state_->written_register_thread = thread;
        state_->written_registers.assign(registers.begin(), registers.end());
        if (!registers.empty()) state_->current_register_bytes = registers[0].bytes;
        return std::monostate{};
    }
    Result<Breakpoint> add_breakpoint(std::uint64_t address, BreakpointKind kind) override {
        state_->breakpoint_address = address;
        state_->breakpoint_kind = kind;
        return Breakpoint{12, address, kind, true};
    }
    Result<Breakpoint> add_hardware_breakpoint(std::uint64_t address, BreakpointKind kind, std::uint8_t size) override {
        state_->breakpoint_address = address;
        state_->breakpoint_kind = kind;
        state_->breakpoint_size = size;
        return Breakpoint{13, address, kind, true, size};
    }
    Status remove_breakpoint(BreakpointId) override { return std::monostate{}; }

  private:
    std::shared_ptr<FakeState> state_;
    bool event_ready_ = false;
};

void require(bool condition, const char *message) {
    if (!condition)
        throw std::runtime_error(message);
}

wxButton *button(wxWindow *parent, const wxString &name) {
    return dynamic_cast<wxButton *>(wxWindow::FindWindowByName(name, parent));
}

void click(wxButton *control) {
    require(control != nullptr, "Debugger action button missing");
    wxCommandEvent event(wxEVT_BUTTON, control->GetId());
    control->GetEventHandler()->ProcessEvent(event);
}

class DebuggerApp final : public wxApp {
  public:
    bool OnInit() override {
        wxSetAssertHandler([](const wxString &, int, const wxString &, const wxString &, const wxString &message) {
            std::fprintf(stderr, "wx assertion: %s\n", message.utf8_str().data());
            std::_Exit(4);
        });
        auto *main = new MainFrame;
        show_test_window(main);
        auto *frame = new wxFrame(nullptr, wxID_ANY, "Debugger controls test");
        auto state = std::make_shared<FakeState>();
        auto *view = new DebuggerView(frame, std::make_unique<FakeBackend>(state));
        frame->SetSize(900, 500);
        show_test_window(frame);
        CallAfter([this, frame, view, state, main] {
            try {
                auto *manager = wxAuiManager::GetManager(main);
                require(manager && manager->GetPane("debugger").IsOk() && !manager->GetPane("debugger").IsShown(),
                        "Main frame did not register the debugger pane in its initial hidden state");
                require(main->GetMenuBar()->FindItem(debugger_panel_id) != nullptr,
                        "Debug menu does not expose the debugger panel");
                wxCommandEvent show_debugger(wxEVT_MENU, debugger_panel_id);
                main->GetEventHandler()->ProcessEvent(show_debugger);
                require(manager->GetPane("debugger").IsShown(), "Debug menu did not open the debugger pane");
                auto *executable = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("debug-executable", view));
                auto *arguments = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("debug-arguments", view));
                auto *process_id = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("debug-process-id", view));
                auto *remote_host = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("debug-remote-host", view));
                auto *remote_port = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("debug-remote-port", view));
                auto *processes = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("debug-processes", view));
                auto *debugger_log = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("debug-output", view));
                auto *event = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("debug-event", view));
                auto *threads = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("debug-threads", view));
                auto *registers = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("debug-registers", view));
                auto *locals_frame = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("debug-locals-frame", view));
                auto *breakpoints = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("debug-breakpoints", view));
                auto *modules = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("debug-modules", view));
                auto *memory_regions = dynamic_cast<wxListCtrl *>(wxWindow::FindWindowByName("debug-memory-regions", view));
                auto *memory = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("debug-memory-view", view));
                auto *write_bytes = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("debug-memory-write-bytes", view));
                require(executable && arguments && process_id && processes && remote_host && remote_port && debugger_log && event && threads && registers && locals_frame && breakpoints,
                        "Debugger panel is missing a launch, attach, event, thread, register, frame, or breakpoint control");
                require(remote_host->GetValue() == "127.0.0.1" && remote_port->GetValue() == "1234",
                        "Remote debugger endpoint defaults are missing");
                remote_port->SetValue("0");
                click(button(view, "debug-remote-connect"));
                require(debugger_log->GetValue().Contains("TCP port from 1 through 65535"),
                        "Remote connection rejects invalid ports before contacting a backend");
                executable->SetValue("C:/bin/sample.exe");
                arguments->SetValue("--probe 17");
                click(button(view, "debug-launch"));
                require(state->launched.executable == "C:/bin/sample.exe" && state->launched.arguments.size() == 2 &&
                            state->launched.arguments[0] == "--probe" && state->launched.arguments[1] == "17",
                        "Launch did not pass target path and arguments to the debugger backend");
                click(button(view, "debug-wait-event"));
                require(event->GetValue().Contains("0x401000") && event->GetValue().Contains("breakpoint IDs: 12, 13") &&
                            threads->GetItemCount() == 1 &&
                            registers->GetItemCount() == 1 && registers->GetItemText(0, 0) == "RIP",
                        "Event polling did not show breakpoint, thread, and register state");
                auto *register_value = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("debug-register-value", view));
                require(register_value, "Register editing value control is missing");
                wxListEvent select_register(wxEVT_LIST_ITEM_SELECTED, registers->GetId());
                select_register.SetIndex(0);
                registers->GetEventHandler()->ProcessEvent(select_register);
                register_value->SetValue("8877665544332211");
                click(button(view, "debug-write-register"));
                require(state->written_register_thread == 77 && state->written_registers.size() == 1 &&
                            state->written_registers[0].name == "RIP" &&
                            state->written_registers[0].bytes.size() == 8 &&
                            registers->GetItemText(0, 1) == "0x8877665544332211" &&
                            debugger_log->GetValue().Contains("Wrote register RIP"),
                        "Register editor did not write a selected register with exact width and refresh its displayed value");
                const auto prior_register_calls = state->register_write_calls;
                register_value->SetValue("1234");
                click(button(view, "debug-write-register"));
                require(state->register_write_calls == prior_register_calls &&
                            debugger_log->GetValue().Contains("requires exactly 8 bytes"),
                        "Wrong-width register value reached the backend");
                register_value->SetValue("not-hex");
                click(button(view, "debug-write-register"));
                require(state->register_write_calls == prior_register_calls &&
                            debugger_log->GetValue().Contains("hexadecimal byte pairs"),
                        "Malformed register value reached the backend");
                register_value->SetValue(std::string(1537, 'A'));
                click(button(view, "debug-write-register"));
                require(state->register_write_calls == prior_register_calls &&
                            debugger_log->GetValue().Contains("exceeds the 512-byte register limit"),
                        "Oversized register input was not rejected within the editor bound");
                register_value->SetValue("0x1122334455667788");
                state->fail_register_write = true;
                click(button(view, "debug-write-register"));
                require(state->register_write_calls == prior_register_calls + 1 && state->written_registers.size() == 1 &&
                            debugger_log->GetValue().Contains("injected register write failure") &&
                            register_value->GetValue() == "0x1122334455667788",
                        "Register write failure was hidden or discarded the user's edit");
                state->fail_register_write = false;
                register_value->SetValue("0x8877665544332211");
                require(modules && modules->GetItemCount() == 1 && modules->GetItemText(0, 2) == "sample.exe",
                        "Event polling did not populate loaded modules");
                require(memory_regions && memory_regions->GetItemCount() == 2 &&
                            memory_regions->GetItemText(0, 0) == "0x400000" &&
                            memory_regions->GetItemText(0, 2) == "r-x" &&
                            memory_regions->GetItemText(1, 2) == "rw-",
                        "Event polling did not populate region ranges and page permissions");
                auto *memory_address = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("debug-memory-address", view));
                require(memory_address && memory, "Memory inspection controls are missing");
                require(write_bytes, "Memory write control is missing");
                require(state->last_memory_address == 0x401000 && state->last_memory_size == 256,
                        "A stop event did not refresh a bounded memory page at its address");
                wxListEvent select_module(wxEVT_LIST_ITEM_SELECTED, modules->GetId());
                select_module.SetIndex(0);
                modules->GetEventHandler()->ProcessEvent(select_module);
                require(memory_address->GetValue() == "0x400000" && state->last_memory_address == 0x400000,
                        "Selecting a module did not navigate the live memory view to its base");
                wxListEvent select_region(wxEVT_LIST_ITEM_SELECTED, memory_regions->GetId());
                select_region.SetIndex(1);
                memory_regions->GetEventHandler()->ProcessEvent(select_region);
                require(memory_address->GetValue() == "0x500000" && state->last_memory_address == 0x500000,
                        "Selecting a memory region did not navigate the live memory view to its start");
                state->fail_memory_regions = true;
                click(button(view, "debug-refresh-memory-regions"));
                require(memory_regions->GetItemCount() == 1 && memory_regions->GetItemText(0).Contains("Unavailable") &&
                            debugger_log->GetValue().Contains("injected memory-region enumeration failure"),
                        "Memory-region enumeration failures were shown without retaining stale rows");
                state->fail_memory_regions = false;
                click(button(view, "debug-refresh-memory-regions"));
                require(memory_regions->GetItemCount() == 2,
                        "Memory-region refresh recovered after a visible backend error");
                memory_address->SetValue("0x400000");
                auto *page_size = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("debug-memory-page-size", view));
                require(page_size && page_size->GetCount() == 3,
                        "Memory view is missing its bounded page-size choices");
                page_size->SetSelection(2);
                click(button(view, "debug-memory-next"));
                require(state->last_memory_address == 0x400400 && state->last_memory_size == 1024,
                        "Memory paging did not advance by the selected bounded page size");
                const auto bounded_read_address = state->last_memory_address;
                memory_address->SetValue("0x100");
                click(button(view, "debug-memory-previous"));
                require(state->last_memory_address == bounded_read_address &&
                            debugger_log->GetValue().Contains("underflow"),
                        "Previous page rejected address underflow without issuing another backend read");
                memory_address->SetValue("0xFFFFFFFFFFFFFF00");
                click(button(view, "debug-memory-next"));
                require(state->last_memory_address == bounded_read_address &&
                            debugger_log->GetValue().Contains("overflow"),
                        "Next page rejected address overflow without issuing another backend read");
                memory_address->SetValue("0x400000");
                state->fail_memory_read = true;
                click(button(view, "debug-read-memory"));
                require(memory->GetValue().Contains("Memory read failed"),
                        "Memory read failure did not replace stale bytes");
                require(debugger_log->GetValue().Contains("injected memory read failure"),
                        "Memory read failure was not visible in debugger output");
                state->fail_memory_read = false;
                state->fail_module_list = true;
                click(button(view, "debug-refresh-modules"));
                require(modules->GetItemCount() == 1 && modules->GetItemText(0).Contains("Unavailable") &&
                            debugger_log->GetValue().Contains("injected module enumeration failure"),
                        "Module enumeration failures were not shown in the module list and output");
                state->fail_module_list = false;
                click(button(view, "debug-refresh-modules"));
                require(modules->GetItemCount() == 1 && modules->GetItemText(0, 2) == "sample.exe",
                        "Successful module refresh did not recover from the visible error");
                memory_address->SetValue("0x401000");
                click(button(view, "debug-read-memory"));
                require(memory->GetValue().Contains("0000000000401000") && memory->GetValue().Contains("41"),
                        "Memory inspection did not render addressed bytes");
                write_bytes->SetValue("90 c3, 0F");
                click(button(view, "debug-write-memory"));
                require(state->written_memory_address == 0x401000 && state->written_memory_bytes.size() == 3 &&
                            state->written_memory_bytes[0] == std::byte{0x90} &&
                            state->written_memory_bytes[1] == std::byte{0xC3} &&
                            state->written_memory_bytes[2] == std::byte{0x0F} && write_bytes->IsEmpty() &&
                            debugger_log->GetValue().Contains("Wrote 3 byte(s)"),
                        "Memory write did not parse hex pairs, write at the selected address, and report success");
                const auto previous_write = state->written_memory_bytes;
                write_bytes->SetValue("9");
                click(button(view, "debug-write-memory"));
                require(state->written_memory_bytes == previous_write &&
                            debugger_log->GetValue().Contains("in pairs"),
                        "Malformed odd-nibble memory write reached the backend");
                write_bytes->SetValue("GG");
                click(button(view, "debug-write-memory"));
                require(state->written_memory_bytes == previous_write &&
                            debugger_log->GetValue().Contains("in pairs"),
                        "Non-hex memory write reached the backend");
                page_size->SetSelection(0);
                write_bytes->SetValue(std::string(130, 'A'));
                click(button(view, "debug-write-memory"));
                require(state->written_memory_bytes == previous_write &&
                            debugger_log->GetValue().Contains("limited to the selected 64-byte"),
                        "Oversized memory write exceeded the selected page bound");
                write_bytes->SetValue(std::string(4098, 'A'));
                click(button(view, "debug-write-memory"));
                require(state->written_memory_bytes == previous_write &&
                            debugger_log->GetValue().Contains("exceeds the 1024-byte pane limit"),
                        "Memory write parser did not enforce its global input cap");
                page_size->SetSelection(1);
                write_bytes->SetValue("AA");
                state->fail_memory_write = true;
                click(button(view, "debug-write-memory"));
                require(debugger_log->GetValue().Contains("injected memory write failure") &&
                            state->written_memory_bytes == previous_write && !write_bytes->IsEmpty(),
                        "Backend write failure was hidden or discarded the user's bytes");
                state->fail_memory_write = false;
                write_bytes->Clear();
                click(button(view, "debug-continue"));
                require(state->continued && state->continued->first == 7 &&
                            state->continued->second == ContinueStatus::handled,
                        "Continue did not acknowledge the exact pending debugger event");
                auto *address = dynamic_cast<wxTextCtrl *>(wxWindow::FindWindowByName("debug-breakpoint-address", view));
                require(address != nullptr, "Breakpoint address input missing");
                address->SetValue("0x401020");
                click(button(view, "debug-add-breakpoint"));
                require(state->breakpoint_address == 0x401020 && breakpoints->GetItemCount() == 1,
                        "Breakpoint control did not add and display the requested address");
                auto *breakpoint_kind = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("debug-breakpoint-kind", view));
                auto *breakpoint_size = dynamic_cast<wxChoice *>(wxWindow::FindWindowByName("debug-breakpoint-size", view));
                require(breakpoint_kind && breakpoint_kind->GetCount() == 5 && breakpoint_size && breakpoint_size->GetCount() == 4,
                        "Breakpoint controls do not expose software, hardware access kinds, and watch widths");
                breakpoint_kind->SetSelection(3);
                breakpoint_size->SetSelection(2);
                address->SetValue("0x401040");
                click(button(view, "debug-add-breakpoint"));
                require(state->breakpoint_address == 0x401040 && state->breakpoint_kind == BreakpointKind::write &&
                            state->breakpoint_size == 4 && breakpoints->GetItemCount() == 2 &&
                            breakpoints->GetItemText(1, 2) == "hardware write (4 bytes)",
                        "Selected hardware watchpoint kind and width did not reach the backend and breakpoint list");
                click(button(view, "debug-refresh-processes"));
                require(processes->GetCount() == 1 && processes->GetString(0).Contains("sample.exe"),
                        "Process refresh did not populate backend process selection");
                processes->SetSelection(0);
                wxCommandEvent selected_process(wxEVT_CHOICE, processes->GetId());
                selected_process.SetInt(0);
                processes->GetEventHandler()->ProcessEvent(selected_process);
                require(process_id->GetValue() == "1234",
                        "Selecting a process did not populate its process ID for attach");
                click(button(view, "debug-detach"));
                process_id->SetValue("4321");
                click(button(view, "debug-attach"));
                require(state->attached == 4321,
                        "Manually entered PID did not override a stale process-list selection during attach");
                result_ = 0;
            } catch (const std::exception &error) {
                std::fprintf(stderr, "%s\n", error.what());
            }
            frame->Close();
            main->Close();
            ExitMainLoop();
        });
        return true;
    }
    int OnRun() override {
        wxApp::OnRun();
        return result_;
    }

  private:
    int result_ = 1;
};
} // namespace

wxIMPLEMENT_APP(DebuggerApp);
