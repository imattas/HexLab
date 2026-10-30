#pragma once

#include "hexlab/core/architecture.hpp"
#include "hexlab/core/result.hpp"
#include "hexlab/debugger/debugger_export.hpp"
#include "hexlab/debugger/memory_search.hpp"
#include "hexlab/debugger/remote_environment.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace hexlab::debugger {
namespace rsp { class ByteTransport; }
using ProcessId = std::uint64_t;
using ThreadId = std::uint64_t;
using BreakpointId = std::uint64_t;
using Status = Result<std::monostate>;
inline constexpr std::size_t max_inspection_read = 1024 * 1024;
inline constexpr std::size_t max_inspection_write = 1024 * 1024;
inline constexpr std::size_t max_inspection_modules = 4096;
inline constexpr std::size_t max_inspection_processes = 4096;
inline constexpr std::size_t max_inspection_threads = 4096;
inline constexpr std::size_t max_inspection_memory_regions = 65536;
inline constexpr std::size_t max_inspection_osdata_columns = 64;
inline constexpr std::size_t max_inspection_osdata_rows = 4096;
inline constexpr std::size_t max_inspection_signal_info_bytes = 64 * 1024;
inline constexpr std::size_t max_inspection_remote_file_bytes = 64 * 1024 * 1024;
inline constexpr std::size_t max_debug_event_exception_parameters = 15;

enum class SessionState { idle, running, stopped, exited, detached, faulted };
enum class ThreadState { running, stopped, exited, unknown };
enum class EventKind { breakpoint, single_step, exception, thread_created, thread_exited,
    module_loaded, module_unloaded, process_exited, output, unknown,
    // Debugger-generated stop request, distinct from a target exception.
    interrupted };
enum class ContinueStatus { handled, not_handled };
enum class BreakpointKind { software, hardware, execute, read, write, access };
enum class ThreadResumeKind { continue_execution, single_step, stop };
struct ThreadResumeAction {
    ThreadId thread = 0;
    ThreadResumeKind kind = ThreadResumeKind::continue_execution;
    // On Linux, for a thread with a pending signal-delivery stop, absent
    // preserves/redelivers the signal when it runs; `handled` suppresses it.
    // On Windows, only the pending event owner may set this: `handled` uses
    // DBG_CONTINUE and `not_handled` passes an exception to the debuggee. A
    // Darwin single-thread schedule applies this to its pending ptrace signal;
    // absent defaults to `not_handled` (redelivery). A stop action retains the
    // signal (Linux) or suspends the event owner (Windows).
    std::optional<ContinueStatus> signal_disposition;
};
enum class ThreadResumeOutcomeKind { continue_accepted, single_step_accepted, stop_preserved };
struct ThreadResumeOutcome {
    ThreadId thread = 0;
    ThreadResumeOutcomeKind outcome = ThreadResumeOutcomeKind::continue_accepted;
};

struct Target {
    std::string executable;
    std::vector<std::string> arguments;
    std::string working_directory;
    // Extended-remote launch only. Native launch rejects nonempty changes.
    // At most 256 unique names / 64 KiB total name+value bytes; each name is
    // 1..4096 bytes (no '=' or NUL), each value is <=16 KiB (no NUL).
    std::vector<RemoteEnvironmentChange> remote_environment;
};
struct RemoteConnectOptions {
    std::size_t max_packet_size = 1024 * 1024;
    bool request_no_ack = true;
    bool enable_non_stop = true;
    bool enable_thread_events = true;
};
struct RemoteTargetMetadata {
    std::string architecture_name;
    std::size_t pointer_bits = 0;
    bool big_endian = false;
    bool endian_declared = false;
    std::size_t packet_size = 0;
    std::string target_xml;
};
struct ProcessInfo {
    ProcessId id = 0;
    std::string name;
    Architecture architecture = Architecture::unknown;
};
struct OsDataRow {
    std::vector<std::pair<std::string, std::string>> columns;
};
struct OsDataTable {
    std::string type;
    std::vector<OsDataRow> rows;
};
struct ThreadInfo {
    ThreadId id = 0;
    std::string name;
    ThreadState state = ThreadState::unknown;
    // Optional processor number reported by qXfer:threads:read.
    std::optional<std::uint32_t> core;
    // Optional human-readable host scheduler state (currently Linux /proc).
    // This is observational metadata and does not define debugger stop state.
    std::string native_state;
};
struct ThreadRunState {
    ThreadId thread = 0;
    ThreadState state = ThreadState::unknown;
};
struct ModuleInfo {
    std::string name;
    std::string path;
    std::uint64_t base = 0;
    std::uint64_t size = 0;
};
struct MemoryRegion {
    std::uint64_t start = 0;
    std::uint64_t length = 0;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    std::string type;
    // GDB memory-map flash erase block size, when the remote advertises it.
    std::optional<std::uint64_t> flash_block_size;
};
struct AuxiliaryVectorEntry {
    std::uint64_t type = 0;
    std::uint64_t value = 0;
};
struct RemoteFileInfo {
    std::uint32_t device = 0, inode = 0, mode = 0, link_count = 0;
    std::uint32_t user_id = 0, group_id = 0, device_type = 0;
    std::uint64_t size = 0, block_size = 0, blocks = 0;
    std::int32_t access_time = 0, modification_time = 0, change_time = 0;
};
struct RegisterValue {
    std::string name;
    std::vector<std::byte> bytes;
    std::string group;
    std::uint64_t number = 0;
    std::optional<ByteOrder> byte_order;
    // Optional bounded GDB target-description metadata. Empty for native or
    // undescribed registers; these strings never change wire register identity.
    std::string target_architecture;
    std::string type;
    // False when the target reports this register as unavailable. Bytes are
    // then placeholders and must not be interpreted as a register value.
    bool available = true;
};
struct DebugEvent {
    std::uint64_t sequence = 0;
    EventKind kind = EventKind::unknown;
    ProcessId process = 0;
    ThreadId thread = 0;
    std::uint64_t address = 0;
    std::string message;
    std::uint32_t code = 0;
    std::vector<BreakpointId> breakpoint_ids;
    // Set by native backends when the operating system distinguishes the
    // initial exception notification from a second-chance notification.
    std::optional<bool> first_chance;
    // Raw Windows EXCEPTION_RECORD parameters; meanings depend on exception code.
    std::vector<std::uint64_t> exception_parameters;
    bool exception_parameters_truncated = false;
};
// Linux siginfo_t has a stable three-int header, but the following union is
// target-specific. This helper decodes only that header when the caller has
// explicitly selected the target pointer width and byte order.
struct LinuxSiginfoHeader {
    std::int32_t signal_number = 0;
    std::int32_t error_number = 0;
    std::int32_t code = 0;
    std::vector<std::byte> union_bytes;
};
HEXLAB_DEBUGGER_EXPORT Result<LinuxSiginfoHeader> decode_linux_siginfo_header(
    std::span<const std::byte> bytes, unsigned pointer_bits, ByteOrder byte_order);
struct Breakpoint {
    BreakpointId id = 0;
    std::uint64_t address = 0;
    BreakpointKind kind = BreakpointKind::software;
    bool enabled = true;
    std::uint8_t size = 1;
    // Runtime counters maintained by DebugSession, not by the OS backend.
    std::uint64_t hit_count = 0;
    std::uint64_t ignore_count = 0;
    // Optional pure expression evaluated against the stopped thread's registers.
    std::string condition;
    // Matching hits emit an output event and resume without stopping.
    bool logpoint = false;
    // Literal output text for a logpoint. Empty means use the default address message.
    std::string log_message;
    // Session-only policy: disable this software breakpoint on its first
    // qualifying hit (after ignore count and condition evaluation).
    bool one_shot = false;
};

// The backend owns OS-specific handles and mechanics. Implementations must not
// silently continue events: the session requires an explicit matching sequence.
class HEXLAB_DEBUGGER_EXPORT Backend {
public:
    virtual ~Backend() = default;
    virtual Result<std::vector<ProcessInfo>> processes() {
        return Error{ErrorCode::unsupported, "process enumeration is not supported by this backend"};
    }
    virtual Result<OsDataTable> os_data(std::string_view) {
        return Error{ErrorCode::unsupported, "OS-data inspection is not supported by this backend"};
    }
    virtual Result<ProcessInfo> launch(const Target&) = 0;
    // Starts a new target on an already connected remote session. Native
    // backends leave this unsupported; remote backends may require extended
    // protocol mode and no outstanding event or owned breakpoints.
    virtual Result<ProcessInfo> launch_remote(const Target&) {
        return Error{ErrorCode::unsupported, "launching a target on the connected remote session is not supported"};
    }
    virtual bool remote_launch_available() const noexcept { return false; }
    virtual Result<ProcessInfo> attach(ProcessId) = 0;
    virtual Result<ProcessInfo> connect_remote(std::string_view, std::uint16_t) {
        return Error{ErrorCode::unsupported, "remote debugging is not supported by this backend"};
    }
    virtual Result<ProcessInfo> connect_remote(std::string_view host, std::uint16_t port,
        const RemoteConnectOptions&) { return connect_remote(host, port); }
    virtual std::optional<RemoteTargetMetadata> remote_target_metadata() const { return {}; }
    // Attaches to another inferior on an already connected multiprocess remote session.
    virtual Result<ProcessInfo> attach_remote_process(ProcessId) {
        return Error{ErrorCode::unsupported, "attaching to a process on the connected remote target is not supported"};
    }
    // Detaches a listed secondary process while keeping the selected session process attached.
    virtual Status detach_remote_process(ProcessId) {
        return Error{ErrorCode::unsupported, "detaching a secondary process on the connected remote target is not supported"};
    }
    // Detaches the selected remote inferior while retaining the remote session
    // when that protocol/backend supports independent inferior detach.
    virtual bool supports_remote_current_process_detach() const noexcept { return false; }
    virtual Status detach_remote_current_process(ProcessId) {
        return Error{ErrorCode::unsupported, "detaching the selected remote process independently is not supported"};
    }
    virtual Status detach() = 0;
    // Requests an asynchronous target stop. Completion is reported through wait_event().
    virtual Status request_interrupt() {
        return Error{ErrorCode::unsupported, "target interruption is not supported by this backend"};
    }
    // Requests a stop for one running thread without interrupting its peers.
    // Backends must reject this unless the transport/OS can target that thread.
    virtual Status request_thread_interrupt(ThreadId) {
        return Error{ErrorCode::unsupported, "thread-qualified interruption is not supported by this backend"};
    }
    virtual bool supports_thread_interrupt() const noexcept { return false; }
    virtual Result<DebugEvent> wait_event(std::chrono::milliseconds timeout) = 0;
    // Console output is informational by default. Native debug-output events
    // may hold an OS stop and require the same explicit token acknowledgement
    // as other events; those backends opt in here.
    virtual bool output_events_require_acknowledgement() const noexcept { return false; }
    virtual Status continue_event(std::uint64_t sequence, ContinueStatus) = 0;
    // Some backends synthesize informational events while the target remains
    // stopped and have more queued events to present before resuming it.
    virtual bool acknowledgement_keeps_target_stopped(EventKind) const noexcept { return false; }
    // Resumes exactly one known thread. Backends that cannot preserve that
    // identity must reject the operation rather than fall back to process-wide continue.
    virtual Status continue_thread_event(std::uint64_t, ThreadId, ContinueStatus) {
        return Error{ErrorCode::unsupported, "thread-qualified continue is not supported by this backend"};
    }
    // Validate a complete per-thread schedule before releasing any thread.
    // Omitted threads must not be newly resumed. Unsupported schedules are
    // rejected without consuming the pending event; OS failures may require
    // backend cleanup and cannot undo instructions already executed.
    virtual Status resume_threads_event(std::uint64_t, std::span<const ThreadResumeAction>) {
        return Error{ErrorCode::unsupported, "per-thread resume schedules are not supported by this backend"};
    }
    // Signal disposition on scheduled actions is opt-in because most backends
    // cannot safely preserve or suppress a pending signal per thread.
    virtual bool supports_scheduled_signal_disposition() const noexcept { return false; }
    // Backends without instruction stepping may keep this default behavior.
    virtual Status single_step_event(std::uint64_t, ContinueStatus) {
        return Error{ErrorCode::unsupported, "single-step execution is not supported by this backend"};
    }
    virtual Result<std::vector<std::byte>> read_memory(std::uint64_t address, std::size_t size) = 0;
    virtual bool supports_memory_tag_read() const noexcept { return false; }
    virtual Result<std::vector<std::byte>> read_memory_tags(std::uint64_t, std::size_t, std::int32_t,
        std::size_t = 256 * 1024) {
        return Error{ErrorCode::unsupported, "memory-tag inspection is not supported by this backend"};
    }
    virtual Status write_memory(std::uint64_t address, std::span<const std::byte> bytes) = 0;
    virtual Result<std::vector<ThreadInfo>> threads() = 0;
    // Returns the backend's current per-thread execution-state snapshot.
    // Backends without reliable state tracking keep this unsupported.
    virtual Result<std::vector<ThreadRunState>> thread_run_states() {
        return Error{ErrorCode::unsupported, "per-thread run-state snapshots are not supported by this backend"};
    }
    virtual Result<std::vector<ModuleInfo>> modules() {
        return Error{ErrorCode::unsupported, "module inspection is not supported by this backend"};
    }
    virtual Result<std::vector<MemoryRegion>> memory_regions() {
        return Error{ErrorCode::unsupported, "memory map inspection is not supported by this backend"};
    }
    virtual Result<std::vector<AuxiliaryVectorEntry>> auxiliary_vector() {
        return Error{ErrorCode::unsupported, "auxiliary-vector inspection is not supported by this backend"};
    }
    virtual Result<std::vector<std::byte>> signal_info() {
        return Error{ErrorCode::unsupported, "signal-info inspection is not supported by this backend"};
    }
    virtual Result<std::vector<std::byte>> read_remote_file(std::string_view, std::size_t, std::stop_token = {}) {
        return Error{ErrorCode::unsupported, "remote file inspection is not supported by this backend"};
    }
    virtual Result<std::vector<std::byte>> run_remote_monitor_command(std::string_view, std::stop_token = {}) {
        return Error{ErrorCode::unsupported, "remote monitor commands are not supported by this backend"};
    }
    virtual Result<std::vector<RegisterValue>> read_registers(ThreadId) = 0;
    virtual Status write_registers(ThreadId, std::span<const RegisterValue>) = 0;
    virtual Result<Breakpoint> add_breakpoint(std::uint64_t address, BreakpointKind) = 0;
    virtual Result<Breakpoint> add_hardware_breakpoint(std::uint64_t, BreakpointKind, std::uint8_t) {
        return Error{ErrorCode::unsupported, "hardware breakpoints are not supported by this backend"};
    }
    virtual Status remove_breakpoint(BreakpointId) = 0;
    virtual Status set_breakpoint_enabled(BreakpointId, bool) {
        return Error{ErrorCode::unsupported, "breakpoint enable/disable is not supported by this backend"};
    }
    // Permanently terminates the current target. Backends must report unsupported
    // rather than silently detaching when termination is unavailable.
    virtual Status terminate() {
        return Error{ErrorCode::unsupported, "target termination is not supported by this backend"};
    }
    virtual Result<RemoteFileInfo> stat_remote_file(std::string_view, bool, std::stop_token = {}) {
        return Error{ErrorCode::unsupported, "remote file metadata inspection is not supported by this backend"};
    }
    virtual Result<std::vector<std::byte>> read_remote_symlink(std::string_view, std::size_t, std::stop_token = {}) {
        return Error{ErrorCode::unsupported, "remote symlink inspection is not supported by this backend"};
    }
};

class HEXLAB_DEBUGGER_EXPORT DebugSession {
public:
    explicit DebugSession(std::unique_ptr<Backend> backend);
    ~DebugSession();
    DebugSession(DebugSession&&) noexcept;
    // Replacing an active destination first attempts normal session detach.
    DebugSession& operator=(DebugSession&&) noexcept;
    DebugSession(const DebugSession&) = delete;
    DebugSession& operator=(const DebugSession&) = delete;

    SessionState state() const noexcept;
    const std::optional<ProcessInfo>& process() const noexcept;
    // Reports whether the current backend can preserve or suppress a pending
    // signal as part of a scheduled thread resume.
    bool supports_scheduled_signal_disposition() const noexcept;
    const std::optional<std::string>& last_diagnostic() const noexcept;
    Result<std::vector<ProcessInfo>> processes();
    Result<OsDataTable> os_data(std::string_view type);
    // Launches locally from idle/detached state, or starts a new inferior on
    // an active remote session when that backend supports extended mode.
    Result<ProcessInfo> launch(const Target& target);
    Result<ProcessInfo> attach(ProcessId process);
    Result<ProcessInfo> connect_remote(std::string_view host, std::uint16_t port);
    Result<ProcessInfo> connect_remote(std::string_view host, std::uint16_t port,
        const RemoteConnectOptions& options);
    std::optional<RemoteTargetMetadata> remote_target_metadata() const;
    // Selects a listed process on an active remote session using its attach packet.
    Result<ProcessInfo> attach_remote_process(ProcessId process);
    // Detaches a different listed process on the active multiprocess RSP connection.
    // The process currently selected in this DebugSession is left attached and unchanged.
    Status detach_remote_process(ProcessId process);
    // Terminates the active target and transitions the session to exited.
    // This is distinct from detach(), which leaves the target running.
    Status terminate();
    Status detach();
    // Ask a running target to stop; acknowledge the resulting event through wait_event().
    Status request_interrupt();
    // In a running session, request a stop for one exact thread. This does not
    // predict a stop or change run-state snapshots; the resulting event arrives
    // through wait_event(). Backends without safe thread targeting return unsupported.
    Status request_thread_interrupt(ThreadId thread);
    bool supports_thread_interrupt() const noexcept;
    // Waits at most timeout for an event. Zero polls immediately; negative
    // durations are rejected before entering the backend.
    Result<DebugEvent> wait_event(std::chrono::milliseconds timeout);
    Status continue_execution(std::uint64_t sequence, ContinueStatus status);
    // Resume exactly the selected thread for this stop event.
    Status continue_thread_execution(std::uint64_t sequence, ThreadId thread,
                                     ContinueStatus status = ContinueStatus::handled);
    // Continue, step, or keep stopped named threads as one validated schedule.
    // At least one action must continue or step; omitted threads are not newly
    // resumed. IDs must come from this session's stop event or thread listing,
    // and the backend may reject unsupported schedules. Native all-stop backends
    // require the pending event owner to be represented, including a stop action
    // when a different thread is selected. This is not processor-atomic execution.
    Status resume_threads(std::uint64_t sequence, std::span<const ThreadResumeAction> actions);
    // Apply the same bounded schedule and return one accepted outcome per
    // action. Failures retain the existing resume_threads error/rollback path.
    Result<std::vector<ThreadResumeOutcome>> resume_threads_with_outcomes(
        std::uint64_t sequence, std::span<const ThreadResumeAction> actions);
    // Resume the event thread for one instruction; a subsequent single-step event must be acknowledged normally.
    Status single_step_execution(std::uint64_t sequence, ContinueStatus status = ContinueStatus::handled);
    Result<std::vector<std::byte>> read_memory(std::uint64_t address, std::size_t size);
    bool supports_memory_tag_read() const noexcept;
    // Reads raw target-defined tag bytes while stopped. The result is capped at
    // max_tag_bytes and is not interpreted using a guessed tag granule.
    Result<std::vector<std::byte>> read_memory_tags(std::uint64_t address, std::size_t size,
        std::int32_t type, std::size_t max_tag_bytes = 256 * 1024);
    Result<MemorySearchReport> search_memory(const MemorySearchPattern& pattern,
        const MemorySearchOptions& options = {}, std::stop_token cancellation = {});
    Status write_memory(std::uint64_t address, std::span<const std::byte> bytes);
    Result<std::vector<ThreadInfo>> threads();
    // Thread-state snapshot keyed by session thread IDs. A backend may return
    // unknown when the OS cannot provide a race-free state observation.
    Result<std::vector<ThreadRunState>> thread_run_states();
    Result<std::vector<ModuleInfo>> modules();
    Result<std::vector<MemoryRegion>> memory_regions();
    Result<std::vector<AuxiliaryVectorEntry>> auxiliary_vector();
    // Returns opaque target-ABI signal information for the current stopped event.
    Result<std::vector<std::byte>> signal_info();
    // Reads a bounded file from an RSP remote stub's filesystem, not the
    // debuggee's process-relative filesystem. Native backends return unsupported.
    Result<std::vector<std::byte>> read_remote_file(std::string_view path,
        std::size_t maximum_size = 16 * 1024 * 1024, std::stop_token cancellation = {});
    // Inspects remote path metadata without opening or reading file contents.
    // follow_symlinks selects vFile:stat vs vFile:lstat; native backends return unsupported.
    Result<RemoteFileInfo> stat_remote_file(std::string_view path, bool follow_symlinks = true,
        std::stop_token cancellation = {});
    // Returns the raw target bytes of a remote symbolic link; native backends return unsupported.
    Result<std::vector<std::byte>> read_remote_symlink(std::string_view path,
        std::size_t maximum_size = 16 * 1024, std::stop_token cancellation = {});
    // Sends a bounded RSP qRcmd command while stopped and returns its captured
    // target-console output bytes. Native backends report unsupported.
    Result<std::vector<std::byte>> run_remote_monitor_command(std::string_view command,
        std::stop_token cancellation = {});
    Result<std::vector<RegisterValue>> read_registers(ThreadId thread);
    // Evaluates a bounded register/memory expression against one stopped thread.
    Result<std::uint64_t> evaluate_expression(ThreadId thread, std::string_view expression);
    Status write_registers(ThreadId thread, std::span<const RegisterValue> registers);
    Result<Breakpoint> add_breakpoint(std::uint64_t address, BreakpointKind kind = BreakpointKind::software,
                                      std::uint8_t size = 1);
    Status remove_breakpoint(BreakpointId id);
    // Enable or suspend a session-owned software breakpoint without changing
    // its identifier or original-byte record.
    Status set_breakpoint_enabled(BreakpointId id, bool enabled);
    // Disable a software breakpoint after its first hit that passes its
    // ignore threshold and condition. This policy is not persisted.
    Status set_breakpoint_one_shot(BreakpointId id, bool enabled);
    // Automatically acknowledges the first `count` owned breakpoint hits.
    // A value of zero reports every hit. This is session-only policy.
    Status set_breakpoint_ignore_count(BreakpointId id, std::uint64_t count);
    // Restore a persisted runtime counter when applying a project breakpoint.
    Status set_breakpoint_hit_count(BreakpointId id, std::uint64_t count);
    Status set_breakpoint_condition(BreakpointId id, std::string condition);
    Status set_breakpoint_logpoint(BreakpointId id, bool enabled);
    Status set_breakpoint_logpoint(BreakpointId id, bool enabled, std::string message);
    // Validates and applies all editor-owned rule fields together, so invalid
    // input or an unknown ID cannot leave a partially updated rule.
    Status configure_breakpoint_rule(BreakpointId id, std::string condition,
        bool logpoint, std::string log_message, std::uint64_t ignore_count, bool one_shot);
    // Breakpoints successfully installed through this session, in creation order.
    std::vector<Breakpoint> breakpoints() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Uses DebugActiveProcess/CreateProcess and DebugActiveProcessStop on Windows.
// The factory returns unsupported on other platforms.
HEXLAB_DEBUGGER_EXPORT std::unique_ptr<Backend> make_native_backend();
HEXLAB_DEBUGGER_EXPORT std::unique_ptr<Backend> make_remote_backend();
HEXLAB_DEBUGGER_EXPORT std::unique_ptr<Backend> make_remote_backend(std::unique_ptr<rsp::ByteTransport> transport);
HEXLAB_DEBUGGER_EXPORT std::unique_ptr<Backend> make_backend_router(std::unique_ptr<Backend> native);
} // namespace hexlab::debugger
