#include "hexlab/debugger/debugger.hpp"
#include "darwin_modules.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cstdlib>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <deque>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <tuple>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/thread_info.h>
#include <mach/task_info.h>
#include <mach-o/arch.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/machine.h>
#include <libproc.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(__x86_64__)
#include <mach/i386/thread_status.h>
#elif defined(__arm64__) || defined(__aarch64__)
#include <mach/arm/thread_status.h>
#else
#error "The Darwin debugger backend supports only x86-64 and AArch64 hosts"
#endif

namespace hexlab::debugger {
namespace {
Error sys_error(const char* action) {
    return {ErrorCode::io, std::string(action) + " failed: " + std::strerror(errno)};
}
Error mach_error(const char* action, kern_return_t code) {
    return {ErrorCode::io, std::string(action) + " failed (Mach error " + std::to_string(code) + ")"};
}
Error unsupported(std::string message) { return {ErrorCode::unsupported, std::move(message)}; }

Architecture process_architecture(pid_t pid) {
    char path[PROC_PIDPATHINFO_MAXSIZE]{};
    if (proc_pidpath(pid, path, sizeof(path)) <= 0) return Architecture::unknown;
    std::ifstream image(path, std::ios::binary);
    std::array<unsigned char, 8> header{};
    if (!image.read(reinterpret_cast<char*>(header.data()), header.size())) return Architecture::unknown;
    const auto be32 = [](const unsigned char* bytes) {
        return (static_cast<std::uint32_t>(bytes[0]) << 24) | (static_cast<std::uint32_t>(bytes[1]) << 16) |
               (static_cast<std::uint32_t>(bytes[2]) << 8) | static_cast<std::uint32_t>(bytes[3]);
    };
    const auto le32 = [](const unsigned char* bytes) {
        return static_cast<std::uint32_t>(bytes[0]) | (static_cast<std::uint32_t>(bytes[1]) << 8) |
               (static_cast<std::uint32_t>(bytes[2]) << 16) | (static_cast<std::uint32_t>(bytes[3]) << 24);
    };
    const auto architecture = [](std::uint32_t cpu) {
        if (cpu == 0x01000007u) return Architecture::x86_64; // CPU_TYPE_X86_64
        if (cpu == 0x0100000cu) return Architecture::arm64; // CPU_TYPE_ARM64
        return Architecture::unknown;
    };
    const auto magic_be = be32(header.data());
    const auto magic_le = le32(header.data());
    if (magic_le == MH_MAGIC_64 || magic_le == MH_MAGIC) return architecture(le32(header.data() + 4));
    if (magic_be == MH_MAGIC_64 || magic_be == MH_MAGIC) return architecture(be32(header.data() + 4));
    if (magic_be != FAT_MAGIC && magic_be != FAT_MAGIC_64) return Architecture::unknown;

    // Universal binaries can contain a translated slice as well as the host
    // slice. Prefer the native slice for launch/discovery; attach to a process
    // explicitly launched under translation remains a documented ambiguity.
    const auto count = be32(header.data() + 4);
    if (count == 0 || count > 64) return Architecture::unknown;
    const std::size_t entry_size = magic_be == FAT_MAGIC_64 ? 32 : 20;
    std::vector<unsigned char> table(static_cast<std::size_t>(count) * entry_size);
    if (!image.read(reinterpret_cast<char*>(table.data()), static_cast<std::streamsize>(table.size())))
        return Architecture::unknown;
    bool has_x64 = false, has_arm64 = false;
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto cpu = be32(table.data() + static_cast<std::size_t>(i) * entry_size);
        has_x64 = has_x64 || cpu == 0x01000007u;
        has_arm64 = has_arm64 || cpu == 0x0100000cu;
    }
#if defined(__x86_64__)
    return has_x64 ? Architecture::x86_64 : Architecture::unknown;
#else
    return has_arm64 ? Architecture::arm64 : Architecture::unknown;
#endif
}

template<class T>
void add_register(std::vector<RegisterValue>& out, const char* name, T value, const char* group = "general") {
    RegisterValue reg;
    reg.name = name;
    reg.group = group;
    reg.bytes.resize(sizeof(T));
    std::memcpy(reg.bytes.data(), &value, sizeof(T));
    out.push_back(std::move(reg));
}
bool read_u64(const RegisterValue& reg, const char* name, std::uint64_t& value) {
    if (reg.name != name) return false;
    if (reg.bytes.size() != sizeof(value)) return false;
    std::memcpy(&value, reg.bytes.data(), sizeof(value));
    return true;
}

#if defined(__x86_64__)
struct FloatRegisterField { const char* name; std::size_t offset; std::size_t width; const char* group; };
// Darwin's float-state ABI exposes 32-bit x87 pointer offsets and separate
// selectors, unlike Linux's 64-bit FXSAVE pointer view. Preserve padding and
// reserved fields, including the six unused bytes in each ST/MM slot.
#define FP_FIELD(name, member, width, group) FloatRegisterField{name, offsetof(x86_float_state64_t, __fpu_##member), width, group}
constexpr auto float_register_fields = std::to_array<FloatRegisterField>({
    FP_FIELD("fcw", fcw, 2, "floating-point"), FP_FIELD("fsw", fsw, 2, "floating-point"),
    FP_FIELD("ftw", ftw, 1, "floating-point"), FP_FIELD("fop", fop, 2, "floating-point"),
    FP_FIELD("fip", ip, 4, "floating-point"), FP_FIELD("fcs", cs, 2, "floating-point"),
    FP_FIELD("fdp", dp, 4, "floating-point"), FP_FIELD("fds", ds, 2, "floating-point"),
    FP_FIELD("mxcsr", mxcsr, 4, "floating-point"),
#define ST_FIELD(index) FP_FIELD("st" #index, stmm##index, 10, "floating-point")
    ST_FIELD(0), ST_FIELD(1), ST_FIELD(2), ST_FIELD(3), ST_FIELD(4), ST_FIELD(5), ST_FIELD(6), ST_FIELD(7),
#undef ST_FIELD
#define XMM_FIELD(index) FP_FIELD("xmm" #index, xmm##index, 16, "vector")
    XMM_FIELD(0), XMM_FIELD(1), XMM_FIELD(2), XMM_FIELD(3), XMM_FIELD(4), XMM_FIELD(5), XMM_FIELD(6), XMM_FIELD(7),
    XMM_FIELD(8), XMM_FIELD(9), XMM_FIELD(10), XMM_FIELD(11), XMM_FIELD(12), XMM_FIELD(13), XMM_FIELD(14), XMM_FIELD(15),
#undef XMM_FIELD
});
#undef FP_FIELD
static_assert([] {
    for (const auto& field : float_register_fields)
        if (field.offset + field.width > sizeof(x86_float_state64_t)) return false;
    return true;
}());
const FloatRegisterField* float_register_field(std::string_view name) {
    const auto field = std::find_if(float_register_fields.begin(), float_register_fields.end(),
        [name](const auto& value) { return name == value.name; });
    return field == float_register_fields.end() ? nullptr : &*field;
}
#endif

class DarwinBackend final : public Backend {
    using Clock = std::chrono::steady_clock;
    // A nested rollback/suspension shares its caller's deadline. EINTR and
    // additional TIDs never restart the timeout.
    struct WaitScope {
        DarwinBackend &backend;
        bool owner;
        explicit WaitScope(DarwinBackend &value, std::optional<std::chrono::milliseconds> timeout = {})
            : backend(value), owner(!value.wait_deadline_) {
            if (owner) {
                backend.wait_stop_requested_.store(false);
                const auto duration = timeout ? std::min(backend.wait_timeout_, std::max(*timeout, std::chrono::milliseconds(0))) : backend.wait_timeout_;
                backend.wait_deadline_ = Clock::now() + duration;
                backend.wait_active_.store(true);
            }
        }
        ~WaitScope() { if (owner) { backend.wait_active_.store(false); backend.wait_deadline_.reset(); } }
    };
    struct CleanupScope {
        bool &flag; bool previous;
        CleanupScope(bool &value, bool enabled) : flag(value), previous(value) { if (enabled) flag = true; }
        ~CleanupScope() { flag = previous; }
    };
    struct EventPollScope {
        bool &flag;
        explicit EventPollScope(bool &value) : flag(value) { flag = true; }
        ~EventPollScope() { flag = false; }
    };
public:
    ~DarwinBackend() override {
        if (terminating_) (void)terminate(); else (void)detach();
        // Bounded destruction cannot guarantee a live task accepts resume.
        // Attempt to balance our hold, then release our send right exactly once.
        (void)resume_task();
        release_suspension_port();
    }

    Result<std::vector<ProcessInfo>> processes() override {
        int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
        std::size_t bytes = 0;
        if (sysctl(mib, 4, nullptr, &bytes, nullptr, 0) != 0) return sys_error("sysctl process list size");
        if (bytes > max_inspection_processes * sizeof(kinfo_proc) * 8ULL)
            return Error{ErrorCode::resource_limit, "Darwin process snapshot exceeds its bounded allocation"};
        std::vector<kinfo_proc> entries(bytes / sizeof(kinfo_proc) + 1);
        if (sysctl(mib, 4, entries.data(), &bytes, nullptr, 0) != 0) return sys_error("sysctl process list");
        const auto count = std::min(bytes / sizeof(kinfo_proc), entries.size());
        if (count > max_inspection_processes)
            return Error{ErrorCode::resource_limit, "Darwin process count exceeds the inspection limit"};
        std::vector<ProcessInfo> out;
        out.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            const auto pid = entries[i].kp_proc.p_pid;
            if (pid <= 0) continue;
            out.push_back({static_cast<ProcessId>(pid), entries[i].kp_proc.p_comm,
                           process_architecture(pid)});
        }
        return out;
    }

    Result<ProcessInfo> launch(const Target& target) override {
        WaitScope scope(*this);
        if (startup_cleanup_) { auto cleaned = cleanup_startup(); if (!cleaned) return cleaned.error(); }
        if (pid_ > 0) return Error{ErrorCode::busy, "backend already owns a debug target"};
        if (target.executable.empty()) return Error{ErrorCode::invalid_argument, "executable path is empty"};
        std::vector<char*> argv; argv.reserve(target.arguments.size() + 2);
        argv.push_back(const_cast<char*>(target.executable.c_str()));
        for (const auto &argument : target.arguments) argv.push_back(const_cast<char*>(argument.c_str()));
        argv.push_back(nullptr);
        const auto *executable = target.executable.c_str();
        const auto *directory = target.working_directory.empty() ? nullptr : target.working_directory.c_str();
        auto *arguments = argv.data();
        const pid_t child = fork();
        if (child < 0) return sys_error("fork");
        if (child == 0) {
            if (directory && chdir(directory) != 0) _exit(126);
            if (ptrace(PT_TRACE_ME, 0, nullptr, 0) != 0) _exit(126);
            execv(executable, arguments); _exit(127);
        }
        pid_ = child; startup_cleanup_ = true; startup_kill_ = true;
        auto fail = [&](Error error) -> Result<ProcessInfo> {
            auto cleaned = cleanup_startup();
            if (!cleaned) error.message += "; launch cleanup retained for retry: " + cleaned.error().message;
            return error;
        };
        auto status = wait_status();
        if (!status) { if (status.error().code == ErrorCode::out_of_bounds) exited_ = true; return fail(status.error()); }
        if (WIFEXITED(status.value()) || WIFSIGNALED(status.value())) {
            exited_ = true; return fail(Error{ErrorCode::io, "launched process exited before its Darwin ptrace stop"});
        }
        if (!WIFSTOPPED(status.value())) return fail(Error{ErrorCode::io, "unexpected initial Darwin wait status"});
        stopped_ = true; pending_wait_status_ = status.value(); pending_signal_ = 0;
        const auto arch = process_architecture(child);
        if (!supported_architecture(arch)) return fail(unsupported("Darwin backend does not support this target architecture"));
        auto suspended = suspend_task(); if (!suspended) return fail(suspended.error());
        auto single = require_single_thread(); if (!single) return fail(single.error());
        startup_cleanup_ = false; startup_kill_ = false; pending_wait_status_.reset();
        sequence_ = 0; refresh_module_baseline();
        initial_event_ = DebugEvent{0, EventKind::breakpoint, static_cast<ProcessId>(child), single.value(), 0, "exec stop", SIGTRAP};
        return ProcessInfo{static_cast<ProcessId>(child), target.executable, arch};
    }

    Result<ProcessInfo> attach(ProcessId id) override {
        WaitScope scope(*this);
        if (startup_cleanup_) { auto cleaned = cleanup_startup(); if (!cleaned) return cleaned.error(); }
        if (pid_ > 0) return Error{ErrorCode::busy, "backend already owns a debug target"};
        if (!id || id > static_cast<ProcessId>(std::numeric_limits<pid_t>::max())) return Error{ErrorCode::invalid_argument, "invalid process id"};
        const auto pid = static_cast<pid_t>(id);
        const auto arch = process_architecture(pid);
        if (!supported_architecture(arch)) return unsupported("Darwin backend does not support this target architecture");
        if (ptrace(PT_ATTACHEXC, pid, nullptr, 0) != 0) return sys_error("ptrace PT_ATTACHEXC");
        pid_ = pid; startup_cleanup_ = true; startup_kill_ = false; stop_request_pending_ = true;
        auto fail = [&](Error error) -> Result<ProcessInfo> {
            auto cleaned = cleanup_startup();
            if (!cleaned) error.message += "; attach cleanup retained for retry: " + cleaned.error().message;
            return error;
        };
        auto stopped = ensure_stopped(false); if (!stopped) return fail(stopped.error());
        if (exited_) return fail(Error{ErrorCode::io, "attached Darwin process exited before its initial stop"});
        auto suspended = suspend_task(); if (!suspended) return fail(suspended.error());
        auto single = require_single_thread(); if (!single) return fail(single.error());
        if (!supported_architecture(process_architecture(pid_))) return fail(unsupported("target architecture changed during attach"));
        startup_cleanup_ = false; pending_wait_status_.reset(); sequence_ = 0;
        refresh_module_baseline();
        char name[PROC_PIDPATHINFO_MAXSIZE]{};
        const auto length = proc_pidpath(pid, name, sizeof(name));
        initial_event_ = DebugEvent{0, EventKind::exception, id, single.value(), 0, "attach stop", SIGSTOP};
        return ProcessInfo{id, length > 0 ? name : "process " + std::to_string(id), arch};
    }

    Status detach() override {
        WaitScope scope(*this);
        if (startup_cleanup_) return cleanup_startup();
        if (terminating_) return terminate();
        if (pid_ <= 0) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        if (exited_) { clear(); return std::monostate{}; }
        detaching_ = true;
        auto stopped = ensure_stopped(true); if (!stopped) return stopped;
        if (exited_) { clear(); return std::monostate{}; }
        if (!detach_prepared_) {
            if (!detach_signal_prepared_) {
                auto prepared = prepare_detach(); if (!prepared) return prepared;
                detach_signal_prepared_ = true;
            }
            auto restored = restore_breakpoints(); if (!restored) return restored;
            detach_prepared_ = true;
        }
        auto progress = wait_progress(); if (!progress) return progress;
        auto resumed = resume_task(); if (!resumed) return resumed;
        if (ptrace(PT_DETACH, pid_, reinterpret_cast<caddr_t>(1), detach_signal_) != 0 && errno != ESRCH)
            return sys_error("ptrace PT_DETACH");
        clear(); return std::monostate{};
    }

    Status request_interrupt() override {
        if (wait_active_.load()) { wait_stop_requested_.store(true); return std::monostate{}; }
        return interrupt_target(false);
    }

    Status terminate() override {
        WaitScope scope(*this);
        if (startup_cleanup_) return cleanup_startup();
        if (pid_ <= 0) return Error{ErrorCode::invalid_argument, "no active Darwin debug target"};
        if (exited_) return std::monostate{};
        terminating_ = true;
        auto killed = kill_and_reap(); if (!killed) return killed;
        const auto ended_pid = pid_;
        clear(); pid_ = ended_pid; exited_ = true;
        return std::monostate{};
    }

    Result<DebugEvent> wait_event(std::chrono::milliseconds timeout) override {
        WaitScope scope(*this, timeout); EventPollScope event_scope(event_polling_);
        if (startup_cleanup_ || detaching_ || terminating_) return Error{ErrorCode::busy, "Darwin cleanup must complete before event polling"};
        if (pid_ <= 0) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        if (pending_) return Error{ErrorCode::busy, "previous debug event has not been continued"};
        if (!module_events_.empty()) return take_module_event();
        if (deferred_event_) {
            auto event = std::move(*deferred_event_);
            deferred_event_.reset();
            event.sequence = ++sequence_;
            pending_ = event.sequence;
            pending_module_event_ = false;
            return event;
        }
        if (initial_event_) {
            auto result = *initial_event_;
            initial_event_.reset();
            pending_ = ++sequence_;
            result.sequence = sequence_;
            return result;
        }
        int status = 0;
        if (pending_wait_status_) status = *pending_wait_status_;
        else {
            auto waited = wait_status();
            if (!waited) {
                if (waited.error().code == ErrorCode::out_of_bounds) {
                    exited_ = true; stopped_ = false; release_suspension_port();
                    DebugEvent event{};
                    event.sequence = ++sequence_; event.kind = EventKind::process_exited;
                    event.process = static_cast<ProcessId>(pid_); event.thread = event.process;
                    event.message = "process exited"; pending_ = event.sequence;
                    return event;
                }
                return waited.error();
            }
            status = waited.value(); pending_wait_status_ = status;
        }
        DebugEvent event{};
        event.process = static_cast<ProcessId>(pid_);
        event.thread = event.process;
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            event.kind = EventKind::process_exited;
            event.code = WIFEXITED(status) ? static_cast<std::uint32_t>(WEXITSTATUS(status)) :
                                             static_cast<std::uint32_t>(WTERMSIG(status));
            event.message = "process exited";
            exited_ = true;
            stopped_ = false; release_suspension_port();
            breakpoints_.clear();
        } else if (WIFSTOPPED(status)) {
            if (!stopped_) remember_stop(status);
            auto suspended = suspend_task();
            if (!suspended) return suspended.error();
            event.code = static_cast<std::uint32_t>(WSTOPSIG(status));
            auto thread_list = threads();
            if (!thread_list) return thread_list.error();
            if (thread_list.value().size() != 1)
                return unsupported("Darwin ptrace event ownership is limited to single-thread targets");
            event.thread = thread_list.value().front().id;
            event.kind = step_expected_ && WSTOPSIG(status) == SIGTRAP ? EventKind::single_step :
                         WSTOPSIG(status) == SIGTRAP ? EventKind::breakpoint : EventKind::exception;
            event.message = event.kind == EventKind::single_step ? "single step" :
                            event.kind == EventKind::breakpoint ? "software breakpoint or trace trap" : "signal stop";
            if (step_expected_ && stepping_breakpoint_) {
                const auto bp = breakpoints_.find(stepping_breakpoint_->first);
                if (bp != breakpoints_.end() && bp->second.enabled) {
                    auto rearmed = write_memory_raw(stepping_breakpoint_->first, bp->second.trap);
                    if (!rearmed) return rearmed.error();
                }
                stepping_breakpoint_.reset();
            } else if (stepping_breakpoint_ && WSTOPSIG(status) == SIGTRAP) {
                // A prior attempt may have restored the original instruction
                // before a Mach PC write failed. Reuse that exact ownership.
                const auto bp = breakpoints_.find(stepping_breakpoint_->first);
                if (bp == breakpoints_.end()) return unsupported("Darwin displaced breakpoint ownership is unavailable");
                if (process_architecture(pid_) == Architecture::x86_64) {
                    auto adjusted = write_pc(event.thread, stepping_breakpoint_->first);
                    if (!adjusted) return adjusted.error();
                }
                event.address = stepping_breakpoint_->first;
                event.breakpoint_ids.push_back(bp->second.id);
                event.kind = EventKind::breakpoint; event.message = "software breakpoint";
            } else if (WSTOPSIG(status) == SIGTRAP) {
                auto registers = read_registers_raw_for_id(event.thread);
                if (!registers) return registers.error();
                std::uint64_t pc = 0;
                const auto arch = process_architecture(pid_);
                const char* pc_name = arch == Architecture::arm64 ? "pc" : "rip";
                const auto pc_reg = std::find_if(registers.value().begin(), registers.value().end(),
                    [pc_name](const auto& reg) { return reg.name == pc_name; });
                if (pc_reg != registers.value().end() && pc_reg->bytes.size() == sizeof(pc)) {
                    std::memcpy(&pc, pc_reg->bytes.data(), sizeof(pc));
                    const auto address = arch == Architecture::x86_64 && pc != 0 ? pc - 1 : pc;
                    const auto bp = breakpoints_.find(address);
                    if (bp != breakpoints_.end() && bp->second.enabled) {
                        auto restored = write_memory_raw(address, bp->second.original);
                        if (!restored) return restored.error();
                        stepping_breakpoint_ = std::pair{address, bp->second.trap};
                        if (arch == Architecture::x86_64) {
                            auto adjusted = write_pc(event.thread, address);
                            if (!adjusted) return adjusted.error();
                        }
                        event.address = address;
                        event.breakpoint_ids.push_back(bp->second.id);
                        event.kind = EventKind::breakpoint;
                        event.message = "software breakpoint";
                    }
                }
            }
            observe_module_changes(event.thread);
        } else {
            return Error{ErrorCode::unsupported, "unexpected Darwin wait status"};
        }
        step_expected_ = false;
        pending_wait_status_.reset();
        if (!module_events_.empty()) {
            deferred_event_ = std::move(event);
            return take_module_event();
        }
        event.sequence = ++sequence_;
        pending_ = event.sequence;
        return event;
    }

    Status continue_event(std::uint64_t sequence, ContinueStatus disposition) override {
        WaitScope scope(*this);
        if (startup_cleanup_ || detaching_ || terminating_) return Error{ErrorCode::busy, "Darwin cleanup must complete before resume"};
        if (!pending_ || *pending_ != sequence)
            return Error{ErrorCode::invalid_argument, "event sequence does not match a stopped Darwin event"};
        if (pending_module_event_) {
            pending_.reset();
            pending_module_event_ = false;
            return std::monostate{};
        }
        if (exited_) { pending_.reset(); return std::monostate{}; }
        if (resume_incomplete_) return finish_resume();
        if (!stopped_) return Error{ErrorCode::invalid_argument, "event sequence does not match a stopped Darwin event"};
        auto single = require_single_thread();
        if (!single) return single.error();
        if (stepping_breakpoint_) {
            const int signal = disposition == ContinueStatus::handled ? 0 : pending_signal_;
            if (ptrace(PT_STEP, pid_, reinterpret_cast<caddr_t>(1), signal) != 0) return sys_error("ptrace PT_STEP over breakpoint");
            step_expected_ = true;
            stopped_ = false; resume_incomplete_ = true;
            return finish_resume();
        }
        const int signal = disposition == ContinueStatus::handled ? 0 : pending_signal_;
        if (ptrace(PT_CONTINUE, pid_, reinterpret_cast<caddr_t>(1), signal) != 0) return sys_error("ptrace PT_CONTINUE");
        stopped_ = false; resume_incomplete_ = true;
        return finish_resume();
    }

    bool acknowledgement_keeps_target_stopped(EventKind kind) const noexcept override {
        return kind == EventKind::module_loaded || kind == EventKind::module_unloaded;
    }

    Status continue_thread_event(std::uint64_t sequence, ThreadId thread, ContinueStatus disposition) override {
        WaitScope scope(*this);
        if (startup_cleanup_ || detaching_ || terminating_) return Error{ErrorCode::busy, "Darwin cleanup must complete before resume"};
        if (!pending_ || *pending_ != sequence || (!stopped_ && !resume_incomplete_) || exited_)
            return Error{ErrorCode::invalid_argument, "event sequence does not match a stopped Darwin event"};
        auto single = require_single_thread();
        if (!single) return single.error();
        if (single.value() != thread) return Error{ErrorCode::invalid_argument, "unknown Darwin thread id"};
        // Process-wide ptrace continuation preserves the selected identity only
        // while the suspended task has exactly one thread.
        return continue_event(sequence, disposition);
    }

    Status resume_threads_event(std::uint64_t sequence, std::span<const ThreadResumeAction> actions) override {
        WaitScope scope(*this);
        if (startup_cleanup_ || detaching_ || terminating_) return Error{ErrorCode::busy, "Darwin cleanup must complete before resume"};
        if (!pending_ || *pending_ != sequence || (!stopped_ && !resume_incomplete_) || exited_)
            return Error{ErrorCode::invalid_argument, "event sequence does not match a stopped Darwin event"};
        if (actions.empty() || actions.size() > max_inspection_threads)
            return Error{ErrorCode::invalid_argument, "thread resume schedule must contain 1 to 4096 actions"};
        // Darwin's ptrace path is process-wide. Only the existing proven
        // single-thread target can implement an exact schedule here.
        if (actions.size() != 1)
            return Error{ErrorCode::unsupported, "Darwin native schedules require a single-thread target"};
        auto single = require_single_thread();
        if (!single) return single.error();
        if (actions.front().thread != single.value())
            return Error{ErrorCode::invalid_argument, "unknown Darwin schedule thread id"};
        if (actions.front().kind == ThreadResumeKind::continue_execution)
            return continue_thread_event(sequence, actions.front().thread, ContinueStatus::handled);
        if (actions.front().kind == ThreadResumeKind::single_step)
            return single_step_event(sequence, ContinueStatus::handled);
        return Error{ErrorCode::unsupported, "Darwin native schedules require one continue or step action"};
    }

    Status single_step_event(std::uint64_t sequence, ContinueStatus disposition) override {
        WaitScope scope(*this);
        if (startup_cleanup_ || detaching_ || terminating_) return Error{ErrorCode::busy, "Darwin cleanup must complete before resume"};
        if (!pending_ || *pending_ != sequence || (!stopped_ && !resume_incomplete_))
            return Error{ErrorCode::invalid_argument, "event sequence does not match a stopped Darwin event"};
        if (resume_incomplete_) return finish_resume();
        if (pending_module_event_)
            return Error{ErrorCode::invalid_argument, "module notifications must be acknowledged with continue"};
        auto single = require_single_thread();
        if (!single) return single.error();
        const int signal = disposition == ContinueStatus::handled ? 0 : pending_signal_;
        if (ptrace(PT_STEP, pid_, reinterpret_cast<caddr_t>(1), signal) != 0) return sys_error("ptrace PT_STEP");
        step_expected_ = true;
        stopped_ = false; resume_incomplete_ = true;
        return finish_resume();
    }

    Result<std::vector<std::byte>> read_memory(std::uint64_t address, std::size_t size) override {
        if (size > max_inspection_read || address > UINT64_MAX - size)
            return Error{ErrorCode::invalid_argument, "invalid memory read range"};
        if (size == 0) return std::vector<std::byte>{};
        auto task = task_port(); if (!task) return task.error();
        std::vector<std::byte> bytes(size);
        mach_vm_size_t actual = 0;
        const auto result = mach_vm_read_overwrite(task.value(), static_cast<mach_vm_address_t>(address),
            static_cast<mach_vm_size_t>(size), reinterpret_cast<mach_vm_address_t>(bytes.data()), &actual);
        mach_port_deallocate(mach_task_self(), task.value());
        if (result != KERN_SUCCESS) return mach_error("mach_vm_read_overwrite", result);
        if (actual != size) return Error{ErrorCode::io, "short Mach memory read"};
        return bytes;
    }

    Status write_memory(std::uint64_t address, std::span<const std::byte> bytes) override {
        if (bytes.size() > max_inspection_read || address > UINT64_MAX - bytes.size())
            return Error{ErrorCode::invalid_argument, "invalid memory write range"};
        if (!stopped_) return Error{ErrorCode::busy, "Darwin target must be stopped before memory writes"};
        if (bytes.empty()) return std::monostate{};
        if (stepping_breakpoint_) {
            const auto begin = address;
            const auto end = address + bytes.size();
            const auto step_begin = stepping_breakpoint_->first;
            const auto step_end = step_begin + stepping_breakpoint_->second.size();
            if (begin < step_end && step_begin < end)
                return Error{ErrorCode::busy, "memory writes overlapping a displaced software breakpoint must wait for its single-step"};
        }
        auto previous = read_memory(address, bytes.size()); if (!previous) return previous.error();
        std::vector<std::byte> applied(bytes.begin(), bytes.end());
        auto next_originals = breakpoints_;
        const auto end = address + bytes.size();
        for (auto& [bp_address, bp] : next_originals) {
            const auto bp_end = bp_address + bp.trap.size();
            const auto begin = std::max(address, bp_address);
            const auto overlap_end = std::min(end, bp_end);
            for (auto current = begin; current < overlap_end; ++current) {
                const auto input_offset = static_cast<std::size_t>(current - address);
                const auto bp_offset = static_cast<std::size_t>(current - bp_address);
                bp.original[bp_offset] = bytes[input_offset];
                if (bp.enabled) applied[input_offset] = bp.trap[bp_offset];
            }
        }
        auto written = write_memory_raw(address, applied);
        if (!written) {
            auto rollback = write_memory_raw(address, previous.value());
            if (!rollback) return Error{written.error().code,
                written.error().message + "; memory rollback failed: " + rollback.error().message};
            return written;
        }
        breakpoints_ = std::move(next_originals);
        return std::monostate{};
    }

    Result<std::vector<ThreadInfo>> threads() override {
        auto task = task_port(); if (!task) return task.error();
        thread_act_array_t list = nullptr;
        mach_msg_type_number_t count = 0;
        const auto kr = task_threads(task.value(), &list, &count);
        mach_port_deallocate(mach_task_self(), task.value());
        if (kr != KERN_SUCCESS) return mach_error("task_threads", kr);
        if (count > max_inspection_threads) {
            for (mach_msg_type_number_t i = 0; i < count; ++i) mach_port_deallocate(mach_task_self(), list[i]);
            vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(list), count * sizeof(thread_t));
            return Error{ErrorCode::resource_limit, "Darwin target has more threads than the debugger supports"};
        }
        std::vector<ThreadInfo> out;
        out.reserve(count);
        for (mach_msg_type_number_t i = 0; i < count; ++i) {
            thread_identifier_info_data_t info{};
            mach_msg_type_number_t info_count = THREAD_IDENTIFIER_INFO_COUNT;
            const auto thread = list[i];
            const auto info_result = thread_info(thread, THREAD_IDENTIFIER_INFO,
                reinterpret_cast<thread_info_t>(&info), &info_count);
            if (info_result == KERN_SUCCESS) {
                std::string name = "thread " + std::to_string(info.thread_id);
                // THREAD_EXTENDED_INFO carries the target's optional name.
                // Keep the numeric fallback when the kernel cannot provide it.
                thread_extended_info_data_t extended{};
                mach_msg_type_number_t extended_count = THREAD_EXTENDED_INFO_COUNT;
                const auto name_result = thread_info(thread, THREAD_EXTENDED_INFO,
                    reinterpret_cast<thread_info_t>(&extended), &extended_count);
                if (name_result == KERN_SUCCESS) {
                    const auto *name_end = std::find(extended.pth_name,
                        extended.pth_name + sizeof(extended.pth_name), '\0');
                    if (name_end != extended.pth_name)
                        name.assign(extended.pth_name, name_end);
                }
                out.push_back({info.thread_id, std::move(name),
                               stopped_ && task_suspended_ ? ThreadState::stopped :
                                   (stopped_ ? ThreadState::unknown : ThreadState::running)});
            }
            mach_port_deallocate(mach_task_self(), thread);
        }
        vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(list), count * sizeof(thread_t));
        if (out.size() != static_cast<std::size_t>(count))
            return Error{ErrorCode::io, "Could not identify every Darwin thread in the stopped process snapshot"};
        return out;
    }

    Result<std::vector<ThreadRunState>> thread_run_states() override {
        auto snapshot = threads();
        if (!snapshot) return snapshot.error();
        std::vector<ThreadRunState> out;
        out.reserve(snapshot.value().size());
        for (const auto& thread : snapshot.value())
            out.push_back({thread.id, thread.state});
        return out;
    }

    Result<std::vector<MemoryRegion>> memory_regions() override {
        auto task = task_port(); if (!task) return task.error();
        auto finish = [&](auto result) -> decltype(result) {
            mach_port_deallocate(mach_task_self(), task.value());
            return result;
        };
        std::vector<MemoryRegion> out;
        out.reserve(1024);
        mach_vm_address_t cursor = 0;
        for (;;) {
            mach_vm_address_t region = cursor;
            mach_vm_size_t region_size = 0;
            vm_region_basic_info_data_64_t info{};
            mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t object = MACH_PORT_NULL;
            const auto kr = mach_vm_region(task.value(), &region, &region_size, VM_REGION_BASIC_INFO_64,
                reinterpret_cast<vm_region_info_t>(&info), &info_count, &object);
            if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
            if (kr == KERN_INVALID_ADDRESS) return finish(Result<std::vector<MemoryRegion>>(std::move(out)));
            if (kr != KERN_SUCCESS) return finish(Result<std::vector<MemoryRegion>>(mach_error("mach_vm_region", kr)));
            if (region_size == 0 || region > UINT64_MAX - region_size || region + region_size <= cursor)
                return finish(Result<std::vector<MemoryRegion>>(Error{ErrorCode::malformed,
                    "Darwin memory map contains a zero-sized, non-advancing, or overflowing region"}));
            if (out.size() >= max_inspection_memory_regions)
                return finish(Result<std::vector<MemoryRegion>>(Error{ErrorCode::resource_limit,
                    "Darwin memory map exceeds the inspection region limit"}));
            out.push_back({static_cast<std::uint64_t>(region), static_cast<std::uint64_t>(region_size),
                (info.protection & VM_PROT_READ) != 0, (info.protection & VM_PROT_WRITE) != 0,
                (info.protection & VM_PROT_EXECUTE) != 0, info.shared ? "shared" : "private"});
            cursor = region + region_size;
        }
    }

    Result<std::vector<ModuleInfo>> modules() override {
        if (!stopped_ || !task_suspended_ || exited_)
            return Error{ErrorCode::busy, "Darwin modules require a process-wide stopped snapshot"};
        auto task = task_port();
        if (!task) return task.error();
        task_dyld_info_data_t info{};
        mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
        const auto kr = task_info(task.value(), TASK_DYLD_INFO, reinterpret_cast<task_info_t>(&info), &count);
        mach_port_deallocate(mach_task_self(), task.value());
        if (kr != KERN_SUCCESS) return mach_error("task_info TASK_DYLD_INFO", kr);
        if (count < TASK_DYLD_INFO_COUNT || info.all_image_info_format != TASK_DYLD_ALL_IMAGE_INFO_64)
            return unsupported("Darwin module inspection requires the 64-bit dyld image information ABI");
        if (info.all_image_info_addr == 0 || info.all_image_info_size < 16)
            return Error{ErrorCode::busy, "Darwin dyld image information is not initialized"};
        return darwin::image_modules(info.all_image_info_addr,
            [this](std::uint64_t address, std::size_t size) { return read_memory(address, size); });
    }

    Result<std::vector<RegisterValue>> read_registers(ThreadId thread) override {
        if (!stopped_ || !task_suspended_)
            return Error{ErrorCode::busy, "Darwin thread registers require a process-wide stopped snapshot"};
        auto port = thread_port(thread); if (!port) return port.error();
        auto result = read_registers_raw(port.value());
        mach_port_deallocate(mach_task_self(), port.value());
        return result;
    }

    Status write_registers(ThreadId thread, std::span<const RegisterValue> values) override {
        if (!stopped_ || !task_suspended_)
            return Error{ErrorCode::busy, "Darwin target must be process-wide stopped before register writes"};
        if (values.size() > 128) return Error{ErrorCode::resource_limit, "too many Darwin register writes"};
        for (std::size_t i = 0; i < values.size(); ++i)
            for (std::size_t prior = 0; prior < i; ++prior)
                if (values[i].name == values[prior].name)
                    return Error{ErrorCode::invalid_argument, "duplicate Darwin register write"};
        if (values.empty()) return std::monostate{};
        auto port = thread_port(thread); if (!port) return port.error();
        auto status = write_registers_raw(port.value(), values);
        mach_port_deallocate(mach_task_self(), port.value());
        return status;
    }

    Result<Breakpoint> add_breakpoint(std::uint64_t address, BreakpointKind kind) override {
        if (kind != BreakpointKind::software) return unsupported("Darwin backend currently supports software breakpoints only");
        if (!stopped_) return Error{ErrorCode::busy, "software breakpoints can only be changed while the target is stopped"};
        const auto arch = process_architecture(pid_);
        if (!supported_architecture(arch)) return unsupported("Darwin software breakpoint encoding is unavailable for this target architecture");
        const auto size = arch == Architecture::arm64 ? 4u : 1u;
        if (arch == Architecture::arm64 && (address & 3u) != 0)
            return Error{ErrorCode::invalid_argument, "AArch64 software breakpoint address must be four-byte aligned"};
        if (breakpoints_.contains(address)) return Error{ErrorCode::conflict, "breakpoint already exists at address"};
        auto original = read_memory(address, size); if (!original) return original.error();
        std::vector<std::byte> trap = arch == Architecture::arm64
            ? std::vector<std::byte>{std::byte{0x00}, std::byte{0x00}, std::byte{0x20}, std::byte{0xd4}}
            : std::vector<std::byte>{std::byte{0xcc}};
        auto written = write_memory_raw(address, trap);
        if (!written) {
            auto rollback = write_memory_raw(address, original.value());
            if (!rollback) return Error{written.error().code, written.error().message +
                "; original instruction rollback failed: " + rollback.error().message};
            return written.error();
        }
        const auto id = next_breakpoint_++;
        breakpoints_.emplace(address, BreakpointRecord{id, std::move(original.value()), std::move(trap), true});
        return Breakpoint{id, address, kind, true, static_cast<std::uint8_t>(size)};
    }

    Status remove_breakpoint(BreakpointId id) override {
        if (!stopped_) return Error{ErrorCode::busy, "software breakpoints can only be changed while the target is stopped"};
        const auto found = std::find_if(breakpoints_.begin(), breakpoints_.end(),
            [id](const auto& entry) { return entry.second.id == id; });
        if (found == breakpoints_.end()) return Error{ErrorCode::invalid_argument, "unknown breakpoint id"};
        if (found->second.enabled) {
            auto restored = write_memory_raw(found->first, found->second.original);
            if (!restored) {
                auto rollback = write_memory_raw(found->first, found->second.trap);
                if (!rollback) return Error{restored.error().code, restored.error().message +
                    "; breakpoint trap rollback failed: " + rollback.error().message};
                return restored;
            }
        }
        breakpoints_.erase(found);
        return std::monostate{};
    }

    Status set_breakpoint_enabled(BreakpointId id, bool enabled) override {
        if (!stopped_) return Error{ErrorCode::busy, "software breakpoints can only be changed while the target is stopped"};
        const auto found = std::find_if(breakpoints_.begin(), breakpoints_.end(),
            [id](const auto& entry) { return entry.second.id == id; });
        if (found == breakpoints_.end()) return Error{ErrorCode::invalid_argument, "unknown breakpoint id"};
        if (stepping_breakpoint_ && stepping_breakpoint_->first == found->first && !enabled)
            stepping_breakpoint_.reset();
        else if (stepping_breakpoint_ && stepping_breakpoint_->first == found->first && enabled)
            return Error{ErrorCode::busy, "breakpoint cannot be enabled while its instruction is being displaced"};
        if (found->second.enabled == enabled) return std::monostate{};
        auto changed = write_memory_raw(found->first, enabled ? std::span<const std::byte>(found->second.trap)
                                                              : std::span<const std::byte>(found->second.original));
        if (!changed) {
            auto rollback = write_memory_raw(found->first, enabled ? std::span<const std::byte>(found->second.original)
                                                                   : std::span<const std::byte>(found->second.trap));
            if (!rollback) return Error{changed.error().code, changed.error().message +
                "; breakpoint state rollback failed: " + rollback.error().message};
            return changed;
        }
        found->second.enabled = enabled;
        return std::monostate{};
    }

private:
    static std::chrono::milliseconds configured_wait_timeout() {
        const auto *text = std::getenv("HEXLAB_DARWIN_PTRACE_TIMEOUT_MS");
        if (text) {
            const std::string_view value(text); unsigned milliseconds{};
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), milliseconds);
            if (parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size() && milliseconds >= 1 && milliseconds <= 60000)
                return std::chrono::milliseconds(milliseconds);
        }
        return std::chrono::milliseconds(5000);
    }
    Status interrupt_target(bool allow_stopped) {
        if (pid_ <= 0 || exited_) return Error{ErrorCode::invalid_argument, "no running Darwin debug target"};
        if (stopped_) return allow_stopped ? Status{std::monostate{}} : Status{Error{ErrorCode::busy, "Darwin target is already stopped"}};
        if (!stop_request_pending_) {
            if (kill(pid_, SIGSTOP) != 0) return errno == ESRCH ? Error{ErrorCode::out_of_bounds, "Darwin tracee exited before interrupt"} : sys_error("kill SIGSTOP");
            stop_request_pending_ = true;
        }
        return std::monostate{};
    }
    Status wait_progress(bool cancellable = true) {
        if (cancellable && !cleanup_wait_ && wait_stop_requested_.load()) {
            if (!event_polling_) return Error{ErrorCode::canceled, "Darwin lifecycle wait canceled; ownership retained"};
            wait_stop_requested_.store(false);
            auto interrupted = interrupt_target(true); if (!interrupted && interrupted.error().code != ErrorCode::out_of_bounds) return interrupted;
        }
        if (wait_deadline_ && Clock::now() >= *wait_deadline_)
            return Error{ErrorCode::busy, "Darwin operation deadline expired; ownership retained for retry"};
        return std::monostate{};
    }
    Result<int> wait_status(bool cancellable = true) {
        WaitScope scope(*this);
        for (;;) {
            int status{}; const auto waited = waitpid(pid_, &status, WNOHANG | WUNTRACED);
            if (waited == pid_) return status;
            if (waited < 0 && errno != EINTR) {
                if (errno == ECHILD || errno == ESRCH) return Error{ErrorCode::out_of_bounds, "Darwin tracee is no longer waitable"};
                return sys_error("waitpid Darwin lifecycle");
            }
            auto progress = wait_progress(cancellable); if (!progress) return progress.error();
            usleep(1000);
        }
    }
    void remember_stop(int status) {
        stopped_ = true; pending_wait_status_ = status;
        pending_signal_ = stop_request_pending_ && WSTOPSIG(status) == SIGSTOP ? 0 : WSTOPSIG(status);
        stop_request_pending_ = false;
    }
    Status ensure_stopped(bool need_mach) {
        if (!stopped_) {
            auto interrupted = interrupt_target(true); if (!interrupted && interrupted.error().code != ErrorCode::out_of_bounds) return interrupted;
            // A retained Mach hold must be released so SIGSTOP can reach ptrace.
            auto resumed = resume_task(); if (!resumed) return resumed;
            auto status = wait_status();
            if (!status) {
                if (status.error().code == ErrorCode::out_of_bounds) { exited_ = true; release_suspension_port(); return std::monostate{}; }
                return status.error();
            }
            if (WIFEXITED(status.value()) || WIFSIGNALED(status.value())) {
                exited_ = true; stopped_ = false; release_suspension_port(); pending_wait_status_ = status.value();
                return std::monostate{};
            }
            if (!WIFSTOPPED(status.value())) return unsupported("unexpected Darwin lifecycle stop status");
            remember_stop(status.value());
        }
        return need_mach && !exited_ ? suspend_task() : Status{std::monostate{}};
    }
    Status kill_and_reap() {
        CleanupScope cleanup(cleanup_wait_, true);
        if (exited_) { release_suspension_port(); return std::monostate{}; }
        if (kill(pid_, SIGKILL) != 0 && errno != ESRCH) return sys_error("kill SIGKILL Darwin cleanup");
        auto resumed = resume_task();
        for (;;) {
            auto status = wait_status(false);
            if (!status) {
                if (status.error().code == ErrorCode::out_of_bounds) { exited_ = true; stopped_ = false; release_suspension_port(); return std::monostate{}; }
                if (!resumed) return Error{status.error().code, status.error().message + "; Mach suspension remains owned: " + resumed.error().message};
                return status.error();
            }
            if (WIFEXITED(status.value()) || WIFSIGNALED(status.value())) {
                exited_ = true; stopped_ = false; release_suspension_port(); pending_wait_status_.reset();
                return std::monostate{};
            }
            if (!WIFSTOPPED(status.value())) return unsupported("unexpected Darwin termination status");
            remember_stop(status.value());
            auto progress = wait_progress(false); if (!progress) return progress;
            if (ptrace(PT_KILL, pid_, nullptr, 0) != 0 && errno != ESRCH) return sys_error("ptrace PT_KILL");
            stopped_ = false;
        }
    }
    Status cleanup_startup() {
        WaitScope scope(*this); CleanupScope cleanup(cleanup_wait_, true);
        if (!startup_cleanup_) return std::monostate{};
        if (startup_kill_) { auto killed = kill_and_reap(); if (!killed) return killed; clear(); return std::monostate{}; }
        if (!exited_) {
            auto stopped = ensure_stopped(false); if (!stopped) return stopped;
            if (!exited_) {
                auto resumed = resume_task(); if (!resumed) return resumed;
                auto progress = wait_progress(false); if (!progress) return progress;
                if (ptrace(PT_DETACH, pid_, reinterpret_cast<caddr_t>(1), pending_signal_) != 0 && errno != ESRCH)
                    return sys_error("ptrace PT_DETACH failed attach cleanup");
            }
        }
        clear(); return std::monostate{};
    }
    Status finish_resume() {
        auto resumed = resume_task(); if (!resumed) return resumed;
        resume_incomplete_ = false; pending_.reset(); pending_signal_ = 0;
        return std::monostate{};
    }
    Status prepare_detach() {
        detach_signal_ = pending_signal_;
        if (pending_signal_ != SIGTRAP) return std::monostate{};
        if (step_expected_ || stepping_breakpoint_) { detach_signal_ = 0; return std::monostate{}; }
        if (breakpoints_.empty()) return std::monostate{};
        auto single = require_single_thread(); if (!single) return single.error();
        auto registers = read_registers_raw_for_id(single.value()); if (!registers) return registers.error();
        const auto arch = process_architecture(pid_);
        const auto name = arch == Architecture::x86_64 ? "rip" : "pc";
        const auto reg = std::find_if(registers.value().begin(), registers.value().end(), [&](const auto &value) { return value.name == name; });
        if (reg == registers.value().end() || reg->bytes.size() != 8) return unsupported("Darwin detach cannot identify stopped PC");
        std::uint64_t pc{}; std::memcpy(&pc, reg->bytes.data(), 8);
        const auto address = arch == Architecture::x86_64 && pc ? pc - 1 : pc;
        const auto bp = breakpoints_.find(address);
        if (bp != breakpoints_.end() && bp->second.enabled) {
            if (arch == Architecture::x86_64) { auto rewound = write_pc(single.value(), address); if (!rewound) return rewound; }
            detach_signal_ = 0;
        }
        return std::monostate{};
    }
    void release_suspension_port() {
        if (suspension_task_ != MACH_PORT_NULL) { (void)mach_port_deallocate(mach_task_self(), suspension_task_); suspension_task_ = MACH_PORT_NULL; }
        task_suspended_ = false;
    }
    struct BreakpointRecord { BreakpointId id; std::vector<std::byte> original; std::vector<std::byte> trap; bool enabled; };
    static auto module_key(const ModuleInfo& module) {
        return std::tuple{module.path, module.name, module.base};
    }
    void refresh_module_baseline() {
        auto current = modules();
        if (current) module_snapshot_ = std::move(current.value());
    }
    void observe_module_changes(ThreadId thread) {
        auto current = modules();
        if (!current) return; // dyld may be updating its image list at this stop.
        std::set<decltype(module_key(ModuleInfo{}))> prior_keys;
        std::set<decltype(module_key(ModuleInfo{}))> current_keys;
        for (const auto& module : module_snapshot_) prior_keys.insert(module_key(module));
        for (const auto& module : current.value()) current_keys.insert(module_key(module));
        const auto enqueue = [&](EventKind kind, const ModuleInfo& module) {
            DebugEvent event{};
            event.kind = kind;
            event.process = static_cast<ProcessId>(pid_);
            event.thread = thread;
            event.address = module.base;
            event.message = (kind == EventKind::module_loaded ? "loaded: " : "unloaded: ") +
                            (module.path.empty() ? module.name : module.path);
            module_events_.push_back(std::move(event));
        };
        for (const auto& module : module_snapshot_)
            if (!current_keys.contains(module_key(module))) enqueue(EventKind::module_unloaded, module);
        for (const auto& module : current.value())
            if (!prior_keys.contains(module_key(module))) enqueue(EventKind::module_loaded, module);
        module_snapshot_ = std::move(current.value());
    }
    Result<DebugEvent> take_module_event() {
        auto event = std::move(module_events_.front());
        module_events_.pop_front();
        event.sequence = ++sequence_;
        pending_ = event.sequence;
        pending_module_event_ = true;
        return event;
    }
    static bool supported_architecture(Architecture arch) {
#if defined(__x86_64__)
        return arch == Architecture::x86_64;
#else
        return arch == Architecture::arm64;
#endif
    }
    Result<task_t> task_port() const {
        if (pid_ <= 0) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        task_t task = MACH_PORT_NULL;
        const auto result = task_for_pid(mach_task_self(), pid_, &task);
        if (result != KERN_SUCCESS) return mach_error("task_for_pid", result);
        return task;
    }
    Status suspend_task() {
        if (task_suspended_) return std::monostate{};
        auto task = task_port(); if (!task) return task.error();
        const auto result = task_suspend(task.value());
        if (result != KERN_SUCCESS) {
            mach_port_deallocate(mach_task_self(), task.value());
            return mach_error("task_suspend", result);
        }
        // Retain the exact send right that acquired the hold. A later resume
        // must not depend on another task_for_pid permission check succeeding.
        suspension_task_ = task.value(); task_suspended_ = true;
        return std::monostate{};
    }
    Status resume_task() {
        if (!task_suspended_) return std::monostate{};
        if (suspension_task_ == MACH_PORT_NULL) return Error{ErrorCode::integrity, "Darwin task suspension has no owned port"};
        const auto result = task_resume(suspension_task_);
        if (result != KERN_SUCCESS) return mach_error("task_resume", result);
        release_suspension_port();
        return std::monostate{};
    }
    Result<thread_t> thread_port(ThreadId id) const {
        auto task = task_port(); if (!task) return task.error();
        thread_act_array_t list = nullptr;
        mach_msg_type_number_t count = 0;
        const auto kr = task_threads(task.value(), &list, &count);
        mach_port_deallocate(mach_task_self(), task.value());
        if (kr != KERN_SUCCESS) return mach_error("task_threads", kr);
        if (count > max_inspection_threads) {
            for (mach_msg_type_number_t i = 0; i < count; ++i) mach_port_deallocate(mach_task_self(), list[i]);
            vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(list), count * sizeof(thread_t));
            return Error{ErrorCode::resource_limit, "Darwin target has more threads than the debugger supports"};
        }
        thread_t found = MACH_PORT_NULL;
        for (mach_msg_type_number_t i = 0; i < count; ++i) {
            thread_identifier_info_data_t info{};
            mach_msg_type_number_t info_count = THREAD_IDENTIFIER_INFO_COUNT;
            const bool match = thread_info(list[i], THREAD_IDENTIFIER_INFO, reinterpret_cast<thread_info_t>(&info), &info_count) == KERN_SUCCESS &&
                               info.thread_id == id && found == MACH_PORT_NULL;
            if (match) found = list[i];
            else mach_port_deallocate(mach_task_self(), list[i]);
        }
        vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(list), count * sizeof(thread_t));
        if (found == MACH_PORT_NULL) return Error{ErrorCode::invalid_argument, "unknown Darwin thread id"};
        return found;
    }
    Result<ThreadId> require_single_thread() {
        auto list = threads(); if (!list) return list.error();
        if (list.value().size() != 1)
            return unsupported("Darwin native debugging currently requires a single-thread target");
        return list.value().front().id;
    }
    Result<std::vector<RegisterValue>> read_registers_raw_for_id(ThreadId id) const {
        auto port = thread_port(id); if (!port) return port.error();
        auto result = read_registers_raw(port.value());
        mach_port_deallocate(mach_task_self(), port.value());
        return result;
    }
    Status write_pc(ThreadId id, std::uint64_t pc) const {
        auto port = thread_port(id); if (!port) return port.error();
#if defined(__x86_64__)
        x86_thread_state64_t state{};
        mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
        auto kr = thread_get_state(port.value(), x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&state), &count);
        if (kr == KERN_SUCCESS) {
            state.__rip = pc;
            kr = thread_set_state(port.value(), x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&state), count);
        }
#else
        arm_thread_state64_t state{};
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        auto kr = thread_get_state(port.value(), ARM_THREAD_STATE64, reinterpret_cast<thread_state_t>(&state), &count);
        if (kr == KERN_SUCCESS) {
            state.__pc = pc;
            kr = thread_set_state(port.value(), ARM_THREAD_STATE64, reinterpret_cast<thread_state_t>(&state), count);
        }
#endif
        mach_port_deallocate(mach_task_self(), port.value());
        return kr == KERN_SUCCESS ? Status{std::monostate{}} : Status{mach_error("thread_set_state breakpoint PC", kr)};
    }
    Status write_memory_raw(std::uint64_t address, std::span<const std::byte> bytes) const {
        if (bytes.empty()) return std::monostate{};
        auto task = task_port(); if (!task) return task.error();
        struct Protection { mach_vm_address_t address; mach_vm_size_t size; vm_prot_t original; };
        std::vector<Protection> changed;
        const auto restore = [&]() {
            std::string failures;
            for (auto it = changed.rbegin(); it != changed.rend(); ++it) {
                const auto result = mach_vm_protect(task.value(), it->address, it->size, false, it->original);
                if (result != KERN_SUCCESS) {
                    if (!failures.empty()) failures += "; ";
                    failures += mach_error("mach_vm_protect restore", result).message;
                }
            }
            changed.clear();
            return failures;
        };
        mach_vm_address_t cursor = static_cast<mach_vm_address_t>(address);
        const mach_vm_address_t end = cursor + bytes.size();
        while (cursor < end) {
            mach_vm_address_t region = cursor;
            mach_vm_size_t region_size = 0;
            vm_region_basic_info_data_64_t info{};
            mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t object = MACH_PORT_NULL;
            auto kr = mach_vm_region(task.value(), &region, &region_size, VM_REGION_BASIC_INFO_64,
                reinterpret_cast<vm_region_info_t>(&info), &info_count, &object);
            if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
            if (kr != KERN_SUCCESS || region > cursor || region_size == 0 || region + region_size <= cursor) {
                const auto rollback = restore();
                mach_port_deallocate(mach_task_self(), task.value());
                if (kr != KERN_SUCCESS) return mach_error("mach_vm_region before write", kr);
                return Error{ErrorCode::io, "memory write range is not fully mapped" +
                    (rollback.empty() ? std::string{} : "; " + rollback)};
            }
            const auto chunk_end = std::min(end, region + region_size);
            if ((info.protection & VM_PROT_WRITE) == 0) {
                if ((info.max_protection & VM_PROT_WRITE) == 0) {
                    const auto rollback = restore();
                    mach_port_deallocate(mach_task_self(), task.value());
                    return Error{ErrorCode::unsupported, "target memory region does not permit temporary write access" +
                        (rollback.empty() ? std::string{} : "; " + rollback)};
                }
                const auto chunk_size = chunk_end - cursor;
                const auto writable_protection = (info.protection | VM_PROT_WRITE) & ~VM_PROT_EXECUTE;
                kr = mach_vm_protect(task.value(), cursor, chunk_size, false, writable_protection);
                if (kr != KERN_SUCCESS) {
                    const auto rollback = restore();
                    mach_port_deallocate(mach_task_self(), task.value());
                    return Error{ErrorCode::io, mach_error("mach_vm_protect before write", kr).message +
                        (rollback.empty() ? std::string{} : "; " + rollback)};
                }
                changed.push_back({cursor, chunk_size, info.protection});
            }
            cursor = chunk_end;
        }
        const auto write_result = mach_vm_write(task.value(), static_cast<mach_vm_address_t>(address),
            reinterpret_cast<vm_offset_t>(const_cast<std::byte*>(bytes.data())),
            static_cast<mach_msg_type_number_t>(bytes.size()));
        const auto restore_errors = restore();
        mach_port_deallocate(mach_task_self(), task.value());
        if (write_result != KERN_SUCCESS) return Error{ErrorCode::io,
            mach_error("mach_vm_write", write_result).message +
            (restore_errors.empty() ? std::string{} : "; " + restore_errors)};
        if (!restore_errors.empty()) return Error{ErrorCode::io, "memory was written but page protections could not be fully restored: " + restore_errors};
        return std::monostate{};
    }
    Result<std::vector<RegisterValue>> read_registers_raw(thread_t thread) const {
        if (!supported_architecture(process_architecture(pid_))) return unsupported("Darwin register access does not support this target architecture");
        std::vector<RegisterValue> out;
#if defined(__x86_64__)
        x86_thread_state64_t state{};
        mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
        const auto kr = thread_get_state(thread, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&state), &count);
        if (kr != KERN_SUCCESS) return mach_error("thread_get_state x86-64", kr);
        if (count != x86_THREAD_STATE64_COUNT)
            return Error{ErrorCode::malformed, "incomplete Darwin x86-64 general register state"};
#define ADD_X64(name) add_register(out, #name, state.__##name)
        ADD_X64(rax); ADD_X64(rbx); ADD_X64(rcx); ADD_X64(rdx); ADD_X64(rdi); ADD_X64(rsi);
        ADD_X64(rbp); ADD_X64(rsp); ADD_X64(r8); ADD_X64(r9); ADD_X64(r10); ADD_X64(r11);
        ADD_X64(r12); ADD_X64(r13); ADD_X64(r14); ADD_X64(r15); ADD_X64(rip); ADD_X64(rflags);
        ADD_X64(cs); ADD_X64(fs); ADD_X64(gs);
#undef ADD_X64
        x86_float_state64_t fp{};
        mach_msg_type_number_t fp_count = x86_FLOAT_STATE64_COUNT;
        const auto fp_kr = thread_get_state(thread, x86_FLOAT_STATE64, reinterpret_cast<thread_state_t>(&fp), &fp_count);
        if (fp_kr != KERN_SUCCESS) return mach_error("thread_get_state x86-64 floating-point", fp_kr);
        if (fp_count != x86_FLOAT_STATE64_COUNT)
            return Error{ErrorCode::malformed, "incomplete Darwin x86-64 floating-point register state"};
        const auto* bytes = reinterpret_cast<const std::byte*>(&fp);
        for (const auto& field : float_register_fields) {
            RegisterValue reg;
            reg.name = field.name;
            reg.group = field.group;
            reg.bytes.assign(bytes + field.offset, bytes + field.offset + field.width);
            out.push_back(std::move(reg));
        }
#else
        arm_thread_state64_t state{};
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        const auto kr = thread_get_state(thread, ARM_THREAD_STATE64, reinterpret_cast<thread_state_t>(&state), &count);
        if (kr != KERN_SUCCESS) return mach_error("thread_get_state AArch64", kr);
        if (count != ARM_THREAD_STATE64_COUNT)
            return Error{ErrorCode::malformed, "incomplete Darwin AArch64 general register state"};
        for (unsigned i = 0; i < 29; ++i) add_register(out, ("x" + std::to_string(i)).c_str(), state.__x[i]);
        add_register(out, "x29", state.__fp); add_register(out, "x30", state.__lr);
        add_register(out, "sp", state.__sp); add_register(out, "pc", state.__pc); add_register(out, "cpsr", state.__cpsr);
        arm_neon_state64_t neon{};
        mach_msg_type_number_t neon_count = ARM_NEON_STATE64_COUNT;
        const auto neon_kr = thread_get_state(thread, ARM_NEON_STATE64,
            reinterpret_cast<thread_state_t>(&neon), &neon_count);
        if (neon_kr != KERN_SUCCESS) return mach_error("thread_get_state AArch64 NEON", neon_kr);
        if (neon_count != ARM_NEON_STATE64_COUNT)
            return Error{ErrorCode::malformed, "incomplete Darwin AArch64 NEON register state"};
        for (unsigned i = 0; i < 32; ++i) {
            RegisterValue reg;
            reg.name = "v" + std::to_string(i);
            reg.group = "vector";
            reg.bytes.resize(sizeof(neon.__v[i]));
            std::memcpy(reg.bytes.data(), &neon.__v[i], reg.bytes.size());
            out.push_back(std::move(reg));
        }
        add_register(out, "fpsr", neon.__fpsr, "floating-point");
        add_register(out, "fpcr", neon.__fpcr, "floating-point");
#endif
        return out;
    }
    Status write_registers_raw(thread_t thread, std::span<const RegisterValue> values) const {
        if (!supported_architecture(process_architecture(pid_))) return unsupported("Darwin register access does not support this target architecture");
#if defined(__x86_64__)
        x86_thread_state64_t state{};
        mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
        auto kr = thread_get_state(thread, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&state), &count);
        if (kr != KERN_SUCCESS) return mach_error("thread_get_state before write", kr);
        if (count != x86_THREAD_STATE64_COUNT)
            return Error{ErrorCode::malformed, "incomplete Darwin x86-64 general register state"};
        x86_float_state64_t fp_before{};
        mach_msg_type_number_t fp_count = x86_FLOAT_STATE64_COUNT;
        const bool has_fp = std::any_of(values.begin(), values.end(), [](const auto& reg) {
            return float_register_field(reg.name) != nullptr;
        });
        if (has_fp) {
            kr = thread_get_state(thread, x86_FLOAT_STATE64, reinterpret_cast<thread_state_t>(&fp_before), &fp_count);
            if (kr != KERN_SUCCESS) return mach_error("thread_get_state x86-64 floating-point before write", kr);
            if (fp_count != x86_FLOAT_STATE64_COUNT)
                return Error{ErrorCode::malformed, "incomplete Darwin x86-64 floating-point register state"};
        }
        auto fp_after = fp_before;
        bool has_general = false;
        for (const auto& reg : values) {
#define SET_X64(name) if (read_u64(reg, #name, state.__##name)) { has_general = true; continue; }
            SET_X64(rax); SET_X64(rbx); SET_X64(rcx); SET_X64(rdx); SET_X64(rdi); SET_X64(rsi);
            SET_X64(rbp); SET_X64(rsp); SET_X64(r8); SET_X64(r9); SET_X64(r10); SET_X64(r11);
            SET_X64(r12); SET_X64(r13); SET_X64(r14); SET_X64(r15); SET_X64(rip); SET_X64(rflags);
            SET_X64(cs); SET_X64(fs); SET_X64(gs);
#undef SET_X64
            if (const auto* field = float_register_field(reg.name)) {
                if (reg.bytes.size() != field->width)
                    return Error{ErrorCode::invalid_argument, "Darwin floating-point register width mismatch"};
                if (reg.name == "mxcsr") {
                    std::uint32_t requested{};
                    std::memcpy(&requested, reg.bytes.data(), sizeof(requested));
                    const auto mask = fp_before.__fpu_mxcsrmask == 0 ? 0xffbfu : fp_before.__fpu_mxcsrmask;
                    if ((requested & ~mask) != 0)
                        return Error{ErrorCode::invalid_argument, "Darwin MXCSR write sets unsupported reserved bits"};
                }
                std::memcpy(reinterpret_cast<std::byte*>(&fp_after) + field->offset, reg.bytes.data(), field->width);
                continue;
            }
            return Error{ErrorCode::invalid_argument, "unknown Darwin register or width mismatch"};
        }
        if (has_fp) {
            kr = thread_set_state(thread, x86_FLOAT_STATE64, reinterpret_cast<thread_state_t>(&fp_after), fp_count);
            if (kr != KERN_SUCCESS) return mach_error("thread_set_state x86-64 floating-point", kr);
        }
        if (!has_general) return std::monostate{};
        kr = thread_set_state(thread, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&state), count);
        if (kr != KERN_SUCCESS && has_fp) {
            const auto rollback = thread_set_state(thread, x86_FLOAT_STATE64,
                reinterpret_cast<thread_state_t>(&fp_before), fp_count);
            if (rollback != KERN_SUCCESS)
                return Error{ErrorCode::io, mach_error("thread_set_state x86-64", kr).message +
                    "; floating-point rollback failed: " + mach_error("thread_set_state rollback", rollback).message};
        }
#else
        arm_thread_state64_t state{};
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        auto kr = thread_get_state(thread, ARM_THREAD_STATE64, reinterpret_cast<thread_state_t>(&state), &count);
        if (kr != KERN_SUCCESS) return mach_error("thread_get_state before write", kr);
        if (count != ARM_THREAD_STATE64_COUNT)
            return Error{ErrorCode::malformed, "incomplete Darwin AArch64 general register state before write"};
        arm_neon_state64_t neon_before{};
        mach_msg_type_number_t neon_count = ARM_NEON_STATE64_COUNT;
        bool has_neon_writes = false;
        kr = thread_get_state(thread, ARM_NEON_STATE64,
            reinterpret_cast<thread_state_t>(&neon_before), &neon_count);
        if (kr != KERN_SUCCESS) return mach_error("thread_get_state AArch64 NEON before write", kr);
        if (neon_count != ARM_NEON_STATE64_COUNT)
            return Error{ErrorCode::malformed, "incomplete Darwin AArch64 NEON register state before write"};
        auto neon_after = neon_before;
        for (const auto& reg : values) {
            bool matched = false;
            for (unsigned i = 0; i < 29; ++i) {
                const auto name = "x" + std::to_string(i);
                std::uint64_t value{};
                if (read_u64(reg, name.c_str(), value)) { state.__x[i] = value; matched = true; break; }
            }
            if (!matched && read_u64(reg, "x29", state.__fp)) matched = true;
            if (!matched && read_u64(reg, "x30", state.__lr)) matched = true;
            if (!matched && read_u64(reg, "sp", state.__sp)) matched = true;
            if (!matched && read_u64(reg, "pc", state.__pc)) matched = true;
            if (!matched && reg.name == "cpsr" && reg.bytes.size() == sizeof(state.__cpsr)) {
                std::memcpy(&state.__cpsr, reg.bytes.data(), sizeof(state.__cpsr));
                matched = true;
            }
            if (!matched && reg.name.size() >= 2 && reg.name.front() == 'v' &&
                reg.name.size() <= 3 && reg.bytes.size() == sizeof(neon_after.__v[0])) {
                unsigned index = 0;
                bool digits = true;
                for (std::size_t i = 1; i < reg.name.size(); ++i) {
                    if (reg.name[i] < '0' || reg.name[i] > '9') { digits = false; break; }
                    index = index * 10 + static_cast<unsigned>(reg.name[i] - '0');
                }
                if (digits && index < 32) {
                    std::memcpy(&neon_after.__v[index], reg.bytes.data(), reg.bytes.size());
                    matched = true;
                    has_neon_writes = true;
                }
            }
            if (!matched && reg.name == "fpsr" && reg.bytes.size() == sizeof(neon_after.__fpsr)) {
                std::memcpy(&neon_after.__fpsr, reg.bytes.data(), sizeof(neon_after.__fpsr));
                matched = true;
                has_neon_writes = true;
            }
            if (!matched && reg.name == "fpcr" && reg.bytes.size() == sizeof(neon_after.__fpcr)) {
                std::memcpy(&neon_after.__fpcr, reg.bytes.data(), sizeof(neon_after.__fpcr));
                matched = true;
                has_neon_writes = true;
            }
            if (!matched) return Error{ErrorCode::invalid_argument, "unknown Darwin register or width mismatch"};
        }
        if (has_neon_writes) {
            kr = thread_set_state(thread, ARM_NEON_STATE64,
                reinterpret_cast<thread_state_t>(&neon_after), neon_count);
            if (kr != KERN_SUCCESS) return mach_error("thread_set_state AArch64 NEON", kr);
        }
        kr = thread_set_state(thread, ARM_THREAD_STATE64, reinterpret_cast<thread_state_t>(&state), count);
        if (kr != KERN_SUCCESS && has_neon_writes) {
            const auto rollback = thread_set_state(thread, ARM_NEON_STATE64,
                reinterpret_cast<thread_state_t>(&neon_before), neon_count);
            if (rollback != KERN_SUCCESS)
                return Error{ErrorCode::io, mach_error("thread_set_state", kr).message +
                    "; AArch64 NEON rollback failed: " + mach_error("thread_set_state rollback", rollback).message};
        }
#endif
        return kr == KERN_SUCCESS ? Status{std::monostate{}} : Status{mach_error("thread_set_state", kr)};
    }
    Status restore_breakpoints() {
        for (auto it = breakpoints_.begin(); it != breakpoints_.end();) {
            if (it->second.enabled) {
                auto restored = write_memory_raw(it->first, it->second.original);
                if (!restored) return restored;
            }
            it = breakpoints_.erase(it);
        }
        return std::monostate{};
    }
    void clear() {
        release_suspension_port();
        startup_cleanup_ = false; startup_kill_ = false; detaching_ = false; detach_prepared_ = false; detach_signal_prepared_ = false; terminating_ = false; resume_incomplete_ = false;
        pending_wait_status_.reset(); stop_request_pending_ = false; detach_signal_ = 0;
        pid_ = 0; stopped_ = false; exited_ = false;
        task_suspended_ = false;
        pending_.reset(); initial_event_.reset(); pending_signal_ = 0; step_expected_ = false;
        stepping_breakpoint_.reset(); breakpoints_.clear();
        module_snapshot_.clear(); module_events_.clear(); deferred_event_.reset(); pending_module_event_ = false;
    }
    pid_t pid_ = 0;
    bool stopped_ = false;
    bool task_suspended_ = false;
    bool exited_ = false;
    bool step_expected_ = false;
    std::uint64_t sequence_ = 0;
    BreakpointId next_breakpoint_ = 1;
    int pending_signal_ = 0;
    std::optional<std::uint64_t> pending_;
    std::optional<DebugEvent> initial_event_;
    std::optional<std::pair<std::uint64_t, std::vector<std::byte>>> stepping_breakpoint_;
    std::map<std::uint64_t, BreakpointRecord> breakpoints_;
    std::vector<ModuleInfo> module_snapshot_;
    std::deque<DebugEvent> module_events_;
    std::optional<DebugEvent> deferred_event_;
    bool pending_module_event_ = false;
    task_t suspension_task_ = MACH_PORT_NULL;
    const std::chrono::milliseconds wait_timeout_ = configured_wait_timeout();
    std::optional<Clock::time_point> wait_deadline_;
    std::atomic<bool> wait_active_{false}, wait_stop_requested_{false};
    bool startup_cleanup_ = false, startup_kill_ = false, detaching_ = false, detach_prepared_ = false, detach_signal_prepared_ = false, resume_incomplete_ = false;
    bool terminating_ = false, cleanup_wait_ = false, event_polling_ = false, stop_request_pending_ = false;
    int detach_signal_ = 0;
    std::optional<int> pending_wait_status_;
};
}

std::unique_ptr<Backend> make_native_backend() { return std::make_unique<DarwinBackend>(); }
} // namespace hexlab::debugger
