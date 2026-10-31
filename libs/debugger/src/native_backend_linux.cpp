#include "hexlab/debugger/debugger.hpp"
#include "hardware_breakpoint_state.hpp"
#include "elf_process_architecture.hpp"
#include "linux_x86_fp_registers.hpp"
#include "linux_x86_registers.hpp"
#include "linux_proc_task_state.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdlib>
#include <cerrno>
#include <charconv>
#include <csignal>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <elf.h>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cpuid.h>

#if !defined(__x86_64__)
#error "The Linux ptrace backend currently requires an x86-64 tracer"
#endif

namespace hexlab::debugger {
namespace {
std::optional<detail::X86XstateLayout> host_ymm_xstate_layout() {
    static const auto layout = []() -> std::optional<detail::X86XstateLayout> {
        unsigned int eax{}, ebx{}, ecx{}, edx{};
        if (__get_cpuid_max(0, nullptr) < 0x0d || !__get_cpuid(1, &eax, &ebx, &ecx, &edx) ||
            !(ecx & bit_XSAVE) || !(ecx & bit_OSXSAVE)) return {};
        __asm__ volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0));
        const auto xcr0 = (static_cast<std::uint64_t>(edx) << 32) | eax;
        if (!detail::x86_xcr0_enables_avx(xcr0)) return {};
        __cpuid_count(0x0d, 0, eax, ebx, ecx, edx);
        const auto supported = (static_cast<std::uint64_t>(edx) << 32) | eax;
        if (!(supported & detail::x86_avx_xstate_bit)) return {};
        __cpuid_count(0x0d, 2, eax, ebx, ecx, edx);
        constexpr std::size_t max_xstate_size = 65536;
        if (eax < 256 || ebx < 576 || ebx > max_xstate_size || eax > max_xstate_size - ebx) return {};
        detail::X86XstateLayout result{ebx, eax, supported};
        constexpr std::uint64_t avx512_xcr0_mask = (1ull << 1) | (1ull << 2) | (1ull << 5) | (1ull << 6) | (1ull << 7);
        if ((supported & detail::x86_avx512_xstate_mask) == detail::x86_avx512_xstate_mask &&
            (xcr0 & avx512_xcr0_mask) == avx512_xcr0_mask) {
            const auto component = [&](unsigned int number, std::size_t& offset, std::size_t& size) {
                unsigned int a{}, b{}, c{}, d{};
                __cpuid_count(0x0d, number, a, b, c, d);
                size = a;
                offset = b;
                return size != 0 && offset >= 576 && offset <= max_xstate_size && size <= max_xstate_size - offset;
            };
            std::size_t opmask_offset{}, opmask_size{}, zmm_hi256_offset{}, zmm_hi256_size{},
                        hi16_zmm_offset{}, hi16_zmm_size{};
            if (component(5, opmask_offset, opmask_size) && opmask_size >= 64 &&
                component(6, zmm_hi256_offset, zmm_hi256_size) && zmm_hi256_size >= 512 &&
                component(7, hi16_zmm_offset, hi16_zmm_size) && hi16_zmm_size >= 1024) {
                result.opmask_offset = opmask_offset;
                result.opmask_size = opmask_size;
                result.zmm_hi256_offset = zmm_hi256_offset;
                result.zmm_hi256_size = zmm_hi256_size;
                result.hi16_zmm_offset = hi16_zmm_offset;
                result.hi16_zmm_size = hi16_zmm_size;
            }
        }
        return result;
    }();
    return layout;
}

constexpr std::size_t max_xstate_size = 65536;

Error sys_error(const char* action) {
    return {ErrorCode::io, std::string(action) + " failed: " + std::strerror(errno)};
}
Result<std::optional<std::vector<std::byte>>> read_xstate_image(pid_t tid,
                                                               const detail::X86XstateLayout& layout) {
#ifdef NT_X86_XSTATE
    std::vector<std::byte> image(max_xstate_size);
    iovec state{image.data(), image.size()};
    if (ptrace(PTRACE_GETREGSET, tid,
               reinterpret_cast<void*>(static_cast<std::uintptr_t>(NT_X86_XSTATE)), &state) != 0) {
        if (errno == EINVAL || errno == EIO || errno == ENODEV || errno == ENOSYS)
            return std::optional<std::vector<std::byte>>{};
        return sys_error("PTRACE_GETREGSET x86 XSAVE state");
    }
    if (state.iov_len > image.size() || state.iov_len < 576 ||
        layout.ymm_upper_offset > state.iov_len || layout.component_size > state.iov_len - layout.ymm_upper_offset)
        return Error{ErrorCode::malformed, "Linux x86-64 XSAVE regset has an invalid or truncated layout"};
    image.resize(state.iov_len);
    std::uint64_t xcomp{};
    std::memcpy(&xcomp, image.data() + 520, sizeof(xcomp));
    if (xcomp & (1ull << 63))
        return Error{ErrorCode::unsupported, "compacted Linux x86-64 XSAVE regsets are not supported"};
    if (detail::x86_avx512_state_available(layout) &&
        (layout.opmask_offset > image.size() || layout.opmask_size > image.size() - layout.opmask_offset ||
         layout.zmm_hi256_offset > image.size() || layout.zmm_hi256_size > image.size() - layout.zmm_hi256_offset ||
         layout.hi16_zmm_offset > image.size() || layout.hi16_zmm_size > image.size() - layout.hi16_zmm_offset))
        return Error{ErrorCode::malformed, "Linux x86-64 XSAVE regset truncates an AVX-512 component"};
    return std::optional<std::vector<std::byte>>(std::move(image));
#else
    (void)tid; (void)layout;
    return std::optional<std::vector<std::byte>>{};
#endif
}

Status write_xstate_image(pid_t tid, std::span<const std::byte> image) {
#ifdef NT_X86_XSTATE
    iovec state{const_cast<std::byte*>(image.data()), image.size()};
    if (ptrace(PTRACE_SETREGSET, tid,
               reinterpret_cast<void*>(static_cast<std::uintptr_t>(NT_X86_XSTATE)), &state) != 0)
        return sys_error("PTRACE_SETREGSET x86 XSAVE state");
    return std::monostate{};
#else
    (void)tid; (void)image;
    return Error{ErrorCode::unsupported, "Linux headers do not expose the x86 XSAVE ptrace regset"};
#endif
}

Result<std::vector<std::byte>> read_i386_xstate_image(pid_t tid) {
#ifdef NT_X86_XSTATE
    std::vector<std::byte> image(max_xstate_size);
    iovec state{image.data(), image.size()};
    if (ptrace(PTRACE_GETREGSET, tid,
               reinterpret_cast<void*>(static_cast<std::uintptr_t>(NT_X86_XSTATE)), &state) != 0) {
        if (errno == EINVAL || errno == EIO || errno == ENODEV || errno == ENOSYS)
            return Error{ErrorCode::unsupported, "i386 floating-point/SSE registers require Linux NT_X86_XSTATE support"};
        return sys_error("PTRACE_GETREGSET i386 XSAVE state");
    }
    if (state.iov_len > image.size() || state.iov_len < 576)
        return Error{ErrorCode::malformed, "Linux i386 XSAVE regset has an invalid or truncated layout"};
    image.resize(state.iov_len);
    std::uint64_t xcomp{};
    std::memcpy(&xcomp, image.data() + 520, sizeof(xcomp));
    if (xcomp & (1ull << 63))
        return Error{ErrorCode::unsupported, "compacted Linux i386 XSAVE regsets are not supported"};
    return image;
#else
    (void)tid;
    return Error{ErrorCode::unsupported, "Linux headers do not expose NT_X86_XSTATE for i386 registers"};
#endif
}

bool parse_pid(std::string_view text, pid_t& pid) {
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), pid);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && pid > 0;
}
bool parse_hex(std::string_view text, std::uint64_t& value) {
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}
struct ProcMapping {
    MemoryRegion region;
    std::string path;
};
Result<std::vector<ProcMapping>> read_proc_mappings(pid_t pid) {
    std::ifstream input("/proc/" + std::to_string(pid) + "/maps");
    if (!input) return Error{ErrorCode::io, "failed to read target memory mappings"};
    std::vector<ProcMapping> mappings;
    std::string line;
    while (std::getline(input, line)) {
        std::array<std::string_view, 5> fields{};
        std::string_view remaining(line);
        for (auto& field : fields) {
            const auto first = remaining.find_first_not_of(' ');
            if (first == std::string_view::npos) return Error{ErrorCode::io, "malformed /proc memory mapping"};
            remaining.remove_prefix(first);
            const auto end = remaining.find(' ');
            field = remaining.substr(0, end);
            remaining = end == std::string_view::npos ? std::string_view{} : remaining.substr(end + 1);
        }
        std::uint64_t start{}, end{};
        const auto dash = fields[0].find('-');
        if (dash == std::string_view::npos || !parse_hex(fields[0].substr(0, dash), start) ||
            !parse_hex(fields[0].substr(dash + 1), end) || start >= end || fields[1].size() != 4 ||
            (fields[1][0] != 'r' && fields[1][0] != '-') || (fields[1][1] != 'w' && fields[1][1] != '-') ||
            (fields[1][2] != 'x' && fields[1][2] != '-'))
            return Error{ErrorCode::io, "malformed /proc memory mapping range or permissions"};
        const auto path_start = remaining.find_first_not_of(' ');
        std::string path = path_start == std::string_view::npos ? std::string{} : std::string(remaining.substr(path_start));
        MemoryRegion region{start, end - start, fields[1][0] == 'r', fields[1][1] == 'w', fields[1][2] == 'x',
                            fields[1][3] == 's' ? "shared" : "private"};
        mappings.push_back({std::move(region), std::move(path)});
        if (mappings.size() > 65536)
            return Error{ErrorCode::resource_limit, "target exposes more than 65536 memory mappings"};
    }
    if (input.bad()) return Error{ErrorCode::io, "failed while reading target memory mappings"};
    return mappings;
}
std::string proc_name(pid_t pid) {
    std::ifstream in("/proc/" + std::to_string(pid) + "/comm");
    std::string name;
    std::getline(in, name);
    return name;
}
Architecture proc_architecture(pid_t pid) {
    std::ifstream image("/proc/" + std::to_string(pid) + "/exe", std::ios::binary);
    std::array<std::byte, 20> header{};
    if (!image.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size())))
        return Architecture::unknown;
    return detail::elf_process_architecture(header);
}
template<class T> void add_reg(std::vector<RegisterValue>& out, const char* name, T value) {
    RegisterValue item; item.name = name; item.bytes.resize(sizeof(T));
    std::memcpy(item.bytes.data(), &value, sizeof(T)); out.push_back(std::move(item));
}
bool set_reg(const RegisterValue& source, const char* name, unsigned long long& value) {
    if (source.name != name) return false;
    if (source.bytes.size() != sizeof(value)) return false;
    std::memcpy(&value, source.bytes.data(), sizeof(value)); return true;
}

class LinuxPtraceBackend final : public Backend {
    bool supports_scheduled_signal_disposition() const noexcept override { return true; }
    using Clock = std::chrono::steady_clock;
    // A nested rollback/suspension shares its caller's deadline. EINTR and
    // additional TIDs never restart the timeout.
    struct WaitScope {
        LinuxPtraceBackend &backend;
        bool owner;
        explicit WaitScope(LinuxPtraceBackend &value, std::optional<std::chrono::milliseconds> timeout = {})
            : backend(value), owner(!value.wait_deadline_) {
            if (owner) {
                std::lock_guard gate(backend.wait_gate_mutex_);
                backend.wait_stop_requested_.store(false);
                const auto duration = timeout ? std::min(backend.wait_timeout_, std::max(*timeout, std::chrono::milliseconds(0))) : backend.wait_timeout_;
                backend.wait_deadline_ = Clock::now() + duration;
                backend.wait_active_.store(true);
            }
        }
        ~WaitScope() { if (owner) { std::lock_guard gate(backend.wait_gate_mutex_); backend.wait_active_.store(false); backend.wait_deadline_.reset(); } }
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
    ~LinuxPtraceBackend() override { if (terminating_) (void)terminate(); else (void)detach(); }

    Result<std::vector<ProcessInfo>> processes() override {
        std::vector<ProcessInfo> result;
        std::error_code ec;
        for (std::filesystem::directory_iterator it("/proc", ec), end; !ec && it != end; it.increment(ec)) {
            pid_t pid{};
            const auto leaf = it->path().filename().string();
            if (!parse_pid(leaf, pid)) continue;
            auto name = proc_name(pid);
            if (name.empty()) continue;
            if (result.size() == max_inspection_processes)
                return Error{ErrorCode::resource_limit, "system process count exceeds the inspection limit"};
            result.push_back({static_cast<ProcessId>(pid), std::move(name), proc_architecture(pid)});
        }
        if (ec) return Error{ErrorCode::io, "failed to enumerate /proc: " + ec.message()};
        return result;
    }

    Result<ProcessInfo> launch(const Target& target) override {
        if (!target.remote_environment.empty())
            return Error{ErrorCode::unsupported, "remote environment changes are not supported by native launch"};
        WaitScope scope(*this);
        if (startup_cleanup_) { auto cleanup = cleanup_startup(); if (!cleanup) return cleanup.error(); }
        if (pid_) return Error{ErrorCode::busy, "backend already owns a debug target"};
        if (target.executable.empty()) return Error{ErrorCode::invalid_argument, "executable path is empty"};
        int gate[2]{};
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, gate) != 0) return sys_error("socketpair for ptrace launch");
        std::vector<char*> argv; argv.reserve(target.arguments.size() + 2);
        argv.push_back(const_cast<char*>(target.executable.c_str()));
        for (const auto& arg : target.arguments) argv.push_back(const_cast<char*>(arg.c_str()));
        argv.push_back(nullptr);
        const auto *executable = target.executable.c_str();
        const auto *working_directory = target.working_directory.empty() ? nullptr : target.working_directory.c_str();
        auto *argv_data = argv.data();
        const pid_t child = fork();
        if (child < 0) { const auto error = sys_error("fork"); close(gate[0]); close(gate[1]); return error; }
        if (child == 0) {
            close(gate[1]);
            char release{}; ssize_t count;
            do { count = read(gate[0], &release, 1); } while (count < 0 && errno == EINTR);
            close(gate[0]);
            if (count != 1 || release != 'G') _exit(126);
            if (working_directory && chdir(working_directory) != 0) _exit(126);
            execv(executable, argv_data); _exit(127);
        }
        close(gate[0]);
        pid_ = child; tracked_.insert(child); startup_cleanup_ = true; startup_kill_ = true;
        auto fail_launch = [&](Error error) -> Result<ProcessInfo> {
            if (gate[1] >= 0) { close(gate[1]); gate[1] = -1; }
            auto cleanup = cleanup_startup();
            if (!cleanup) error.message += "; launch cleanup retained for retry: " + cleanup.error().message;
            return error;
        };
        constexpr unsigned long options = PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE;
        if (ptrace(PTRACE_SEIZE, child, nullptr, reinterpret_cast<void*>(options)) != 0)
            return fail_launch(sys_error("PTRACE_SEIZE launched process"));
        seized_.insert(child);
        const char release = 'G'; ssize_t sent;
        do {
            sent = send(gate[1], &release, 1, MSG_NOSIGNAL | MSG_DONTWAIT);
            if (sent < 0 && errno == EINTR) { auto progress = wait_progress(); if (!progress) return fail_launch(progress.error()); }
        } while (sent < 0 && errno == EINTR);
        close(gate[1]); gate[1] = -1;
        if (sent != 1) return fail_launch(sys_error("release ptrace launch gate"));
        auto status = wait_status(child);
        if (!status) {
            if (status.error().code == ErrorCode::out_of_bounds) forget_thread(child);
            return fail_launch(status.error());
        }
        if (WIFSTOPPED(status.value())) stopped_.insert(child);
        else if (WIFEXITED(status.value()) || WIFSIGNALED(status.value())) forget_thread(child);
        if (!WIFSTOPPED(status.value()) || (static_cast<unsigned>(status.value()) >> 16) != PTRACE_EVENT_EXEC)
            return fail_launch(Error{ErrorCode::io, "launched process failed before its ptrace exec stop"});
        const auto arch = proc_architecture(child);
        if (arch != Architecture::x86 && arch != Architecture::x86_64) return fail_launch(Error{ErrorCode::unsupported, "Linux ptrace register support is limited to x86 and x86-64 targets"});
        startup_cleanup_ = false; startup_kill_ = false; launched_ = true; architecture_ = arch; last_signal_ = 0; pending_signal_ = 0;
        pending_.reset(); seq_ = 0;
        initial_event_ = DebugEvent{0, EventKind::breakpoint, static_cast<ProcessId>(child), static_cast<ThreadId>(child), 0, "exec stop", SIGTRAP};
        return ProcessInfo{static_cast<ProcessId>(child), target.executable, arch};
    }

    Result<ProcessInfo> attach(ProcessId id) override {
        WaitScope scope(*this);
        if (startup_cleanup_) { auto cleanup = cleanup_startup(); if (!cleanup) return cleanup.error(); }
        if (pid_) return Error{ErrorCode::busy, "backend already owns a debug target"};
        if (!id || id > static_cast<ProcessId>(std::numeric_limits<pid_t>::max())) return Error{ErrorCode::invalid_argument, "invalid process id"};
        const auto pid = static_cast<pid_t>(id);
        const auto initial_arch = proc_architecture(pid);
        if (initial_arch != Architecture::x86 && initial_arch != Architecture::x86_64) return Error{ErrorCode::unsupported, "Linux ptrace register support is limited to x86 and x86-64 targets"};
        pid_ = pid; startup_cleanup_ = true; startup_kill_ = false;
        auto fail_attach = [&](Error error) -> Result<ProcessInfo> {
            auto cleanup = cleanup_startup();
            if (!cleanup) error.message += "; attach cleanup retained for retry: " + cleanup.error().message;
            return error;
        };
        auto acquire = [&](pid_t tid) -> Status {
            auto progress = wait_progress(); if (!progress) return progress;
            if (tracked_.contains(tid)) return std::monostate{};
            if (tracked_.size() >= max_inspection_threads) return Error{ErrorCode::resource_limit, "target exceeds the thread inspection limit"};
            if (ptrace(PTRACE_SEIZE, tid, nullptr, nullptr) != 0) {
                if (errno == ESRCH) return std::monostate{};
                return sys_error("PTRACE_SEIZE target thread");
            }
            tracked_.insert(tid); seized_.insert(tid);
            if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) == 0) interrupting_.insert(tid);
            else if (errno != ESRCH) return sys_error("PTRACE_INTERRUPT target thread");
            auto status = wait_status(tid);
            if (!status) {
                if (status.error().code == ErrorCode::out_of_bounds) { forget_thread(tid); return std::monostate{}; }
                return status.error();
            }
            interrupting_.erase(tid);
            if (WIFSTOPPED(status.value())) {
                stopped_.insert(tid);
                const auto event = static_cast<unsigned>(status.value()) >> 16;
                if (!(event == PTRACE_EVENT_STOP && WSTOPSIG(status.value()) == SIGTRAP)) defer_stop(tid, status.value());
            } else forget_thread(tid);
            return std::monostate{};
        };
        auto leader = acquire(pid);
        if (!leader) return fail_attach(leader.error());
        if (!tracked_.contains(pid)) return fail_attach(Error{ErrorCode::io, "target exited before it could be stopped"});
        bool stable = false; std::set<pid_t> previous;
        const auto task_dir = "/proc/" + std::to_string(pid) + "/task";
        for (unsigned round = 0; round < 16; ++round) {
            std::set<pid_t> observed; std::error_code ec;
            for (std::filesystem::directory_iterator it(task_dir, ec), end; !ec && it != end; it.increment(ec)) {
                auto progress = wait_progress(); if (!progress) return fail_attach(progress.error());
                pid_t tid{}; if (!parse_pid(it->path().filename().string(), tid)) continue;
                if (observed.size() >= max_inspection_threads) return fail_attach(Error{ErrorCode::resource_limit, "target exceeds the thread inspection limit"});
                observed.insert(tid);
                auto result = acquire(tid); if (!result) return fail_attach(result.error());
            }
            if (ec) return fail_attach(Error{ErrorCode::io, "failed to enumerate target threads during attach: " + ec.message()});
            if (observed == previous && std::all_of(observed.begin(), observed.end(), [&](pid_t tid) { return stopped_.contains(tid); })) { stable = true; break; }
            previous = std::move(observed);
        }
        if (!stable) return fail_attach(Error{ErrorCode::busy, "target thread list did not stabilize during attach"});
        const auto target_architecture = proc_architecture(pid);
        if (target_architecture != Architecture::x86 && target_architecture != Architecture::x86_64)
            return fail_attach(Error{ErrorCode::unsupported, "target architecture changed during attach"});
        for (const auto tid : stopped_) {
            auto progress = wait_progress(); if (!progress) return fail_attach(progress.error());
            if (ptrace(PTRACE_SETOPTIONS, tid, nullptr, reinterpret_cast<void*>(PTRACE_O_TRACECLONE)) != 0)
                return fail_attach(sys_error("PTRACE_SETOPTIONS after attach"));
        }
        startup_cleanup_ = false; launched_ = false; architecture_ = target_architecture; last_signal_ = 0; pending_signal_ = 0;
        pending_.reset(); seq_ = 0;
        initial_event_ = DebugEvent{0, EventKind::exception, id, id, 0, "attach stop", SIGSTOP};
        return ProcessInfo{id, proc_name(pid), target_architecture};
    }

    Status detach() override {
        WaitScope scope(*this);
        if (startup_cleanup_) return cleanup_startup();
        if (terminating_) return terminate();
        if (pid_ <= 0) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        if (exited_) { clear(); return std::monostate{}; }
        if (!detaching_) {
            detach_preparing_ = true; resume_blocked_ = true;
            auto stopped = stop_all_threads(); if (!stopped) { resume_blocked_ = true; return stopped; }
            if (stopped_ != tracked_) return Error{ErrorCode::busy, "detach requires every owned thread stopped"};
            std::set<std::uint64_t> enabled_addresses;
            for (const auto& [id, address] : ids_)
                if (enabled_ids_.contains(id)) enabled_addresses.insert(address);
            // Validate the whole set before rewinding any PCs or restoring any
            // bytes. An earlier detach attempt may already have restored a
            // prefix; those addresses must still hold their saved originals.
            for (const auto& [address, original] : breakpoints_) {
                (void)original;
                auto progress = wait_progress(); if (!progress) return progress;
                auto owned = detach_breakpoint_byte(address, enabled_addresses.contains(address)); if (!owned) return owned.error();
            }
            for (const auto tid : stopped_) {
                if (detach_signals_.contains(tid)) continue;
                auto progress = wait_progress(); if (!progress) return progress;
                int signal = 0;
                const auto deferred = deferred_stops_.find(tid);
                if (deferred != deferred_stops_.end() && WIFSTOPPED(deferred->second) && (static_cast<unsigned>(deferred->second) >> 16) == 0)
                    signal = WSTOPSIG(deferred->second);
                else if (pending_ && pending_->second == tid) signal = pending_signal_;
                if (const auto queued = deferred_signals_.find(tid); queued != deferred_signals_.end()) signal = queued->second;
                if (signal == SIGTRAP) {
                    siginfo_t info{};
                    const bool have_info = ptrace(PTRACE_GETSIGINFO, tid, nullptr, &info) == 0;
                    const auto dr6 = hardware_slots_.empty() ? Result<unsigned long>{0UL} : peek_debug_register(tid, 6);
                    const auto owned_mask = (1UL << hardware_slots_.size()) - 1;
                    const bool owned_hardware = (dr6 && (dr6.value() & owned_mask) != 0) ||
                        (pending_ && pending_->second == tid && pending_debugger_trap_ && !pending_breakpoint_);
                    if ((have_info && info.si_code == TRAP_TRACE) || owned_hardware) signal = 0;
                    if (!owned_hardware && !(have_info && info.si_code == TRAP_TRACE)) {
                        auto ip = instruction_pointer(tid);
                        if (!ip) return ip.error();
                        std::optional<std::uint64_t> address;
                        if (pending_ && pending_->second == tid && pending_breakpoint_ &&
                            (ip.value() == *pending_breakpoint_ || (ip.value() > 0 && ip.value() - 1 == *pending_breakpoint_))) address = *pending_breakpoint_;
                        else if (ip.value() > 0 && std::any_of(ids_.begin(), ids_.end(), [&](const auto &item) {
                            return enabled_ids_.contains(item.first) && item.second == ip.value() - 1;
                        })) address = ip.value() - 1;
                        if (address) {
                            auto rewound = set_instruction_pointer(tid, *address); if (!rewound) return rewound;
                            signal = 0;
                        }
                    }
                }
                detach_signals_[tid] = signal;
            }
            for (const auto& [address, original] : breakpoints_) {
                auto progress = wait_progress(); if (!progress) return progress;
                if (detach_restored_breakpoints_.contains(address)) continue;
                auto owned = detach_breakpoint_byte(address, enabled_addresses.contains(address)); if (!owned) return owned.error();
                // Allocate retry tracking before the target write.
                detach_restored_breakpoints_.insert(address);
                auto restored = replace_software_breakpoint_byte(address, owned.value(), original);
                if (!restored) { detach_restored_breakpoints_.erase(address); return restored; }
            }
            if (!hardware_breakpoints_.empty() && !detach_hardware_cleared_) {
                auto cleared = apply_hardware_breakpoints({}); if (!cleared) return cleared;
                detach_hardware_cleared_ = true;
            }
            detaching_ = true; resume_blocked_ = true;
        }
        const std::vector<pid_t> census(stopped_.begin(), stopped_.end());
        for (const auto tid : census) {
            auto progress = wait_progress(); if (!progress) return progress;
            const int signal = detach_signals_.contains(tid) ? detach_signals_.at(tid) : 0;
            if (ptrace(PTRACE_DETACH, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(signal))) != 0 && errno != ESRCH)
                return sys_error("PTRACE_DETACH");
            forget_thread(tid); detach_signals_.erase(tid);
        }
        if (!tracked_.empty()) return Error{ErrorCode::busy, "detach retained unconfirmed thread ownership"};
        clear(); return std::monostate{};
    }

    Status terminate() override {
        WaitScope scope(*this);
        if (startup_cleanup_) return cleanup_startup();
        if (pid_ <= 0) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        if (exited_) return std::monostate{};
        if (kill(pid_, SIGKILL) != 0 && errno != ESRCH) return sys_error("kill SIGKILL");

        terminating_ = true; resume_blocked_ = true;

        // A ptrace stop prevents a target thread from observing the process-wide
        // SIGKILL. Release every thread already held by a debug event, then
        // continue forwarding SIGKILL through any later ptrace event stops.
        const auto threads = std::vector<pid_t>(stopped_.begin(), stopped_.end());
        for (const auto thread : threads) {
            auto progress = wait_progress(); if (!progress) return progress;
            if (ptrace(PTRACE_CONT, thread, nullptr,
                       reinterpret_cast<void*>(static_cast<std::intptr_t>(SIGKILL))) != 0 && errno != ESRCH)
                return sys_error("PTRACE_CONT while terminating target");
            stopped_.erase(thread); deferred_stops_.erase(thread);
        }
        std::set<pid_t> remaining = tracked_;
        while (!remaining.empty()) {
            bool progressed = false;
            for (auto it = remaining.begin(); it != remaining.end();) {
                auto progress = wait_progress(); if (!progress) return progress;
                const auto thread = *it;
                int status{};
                const auto waited = waitpid(thread, &status, __WALL | WNOHANG);
                if (waited == thread) {
                    progressed = true;
                    if (WIFEXITED(status) || WIFSIGNALED(status)) {
                        it = remaining.erase(it);
                        forget_thread(thread);
                        continue;
                    }
                    if (WIFSTOPPED(status)) {
                        stopped_.insert(thread); defer_stop(thread, status);
                        const auto ptrace_event = static_cast<unsigned>(status) >> 16;
                        if (ptrace_event == PTRACE_EVENT_CLONE) {
                            unsigned long child_tid = 0;
                            if (ptrace(PTRACE_GETEVENTMSG, thread, nullptr, &child_tid) == 0) {
                                if (!child_tid || child_tid > static_cast<unsigned long>(std::numeric_limits<pid_t>::max()))
                                    return Error{ErrorCode::malformed, "termination clone event has an invalid TID"};
                                const auto child = static_cast<pid_t>(child_tid);
                                if (tracked_.insert(child).second) { remaining.insert(child); seized_.insert(child); }
                                if (tracked_.size() > 2 * max_inspection_threads)
                                    return Error{ErrorCode::resource_limit, "termination retains too many automatically owned clone threads"};
                            } else if (errno != ESRCH) {
                                return sys_error("PTRACE_GETEVENTMSG while terminating cloned thread");
                            }
                        }
                        if (ptrace(PTRACE_CONT, thread, nullptr,
                                   reinterpret_cast<void*>(static_cast<std::intptr_t>(SIGKILL))) != 0 && errno != ESRCH)
                            return sys_error("PTRACE_CONT while draining target termination");
                        stopped_.erase(thread); deferred_stops_.erase(thread);
                        ++it;
                        continue;
                    }
                    return Error{ErrorCode::io, "unexpected wait status while terminating target"};
                }
                if (waited < 0) {
                    if (errno == EINTR) { ++it; continue; }
                    if (errno == ECHILD || errno == ESRCH) {
                        progressed = true;
                        it = remaining.erase(it);
                        forget_thread(thread);
                        continue;
                    }
                    return sys_error("waitpid while terminating target");
                }
                ++it;
            }
            if (!remaining.empty()) { auto progress = wait_progress(); if (!progress) return progress; }
            if (!progressed) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        terminating_ = false; exited_ = true;
        pending_.reset();
        initial_event_.reset();
        pending_breakpoint_.reset();
        stopped_.clear();
        step_threads_.clear();
        displaced_step_.reset();
        breakpoint_rollback_.reset();
        breakpoint_rearm_.reset();
        deferred_stops_.clear();
        interrupting_.clear();
        breakpoints_.clear();
        ids_.clear();
        enabled_ids_.clear();
        hardware_breakpoints_.clear();
        hardware_slots_.clear();
        hardware_slot_ids_.clear();
        resume_blocked_ = false;
        return std::monostate{};
    }

    Status request_interrupt() override {
        std::lock_guard gate(wait_gate_mutex_);
        if (pending_ || requested_thread_interrupt_)
            return Error{ErrorCode::busy, "an event or thread-qualified interrupt is already pending"};
        if (wait_active_.load()) { wait_stop_requested_.store(true); return std::monostate{}; }
        return interrupt_running_threads(false);
    }
    Status request_thread_interrupt(ThreadId thread) override {
        std::lock_guard gate(wait_gate_mutex_);
        if (pid_ <= 0 || exited_ || pending_ || startup_cleanup_ || detach_preparing_ || detaching_ || terminating_)
            return Error{ErrorCode::invalid_argument, "thread interrupt requires a running target with no pending event"};
        if (wait_active_.load())
            return Error{ErrorCode::busy, "cannot target a thread while the ptrace event poller is active"};
        if (thread == 0 || thread > static_cast<ThreadId>(std::numeric_limits<pid_t>::max()))
            return Error{ErrorCode::invalid_argument, "thread interrupt requires a valid session thread ID"};
        const auto tid = static_cast<pid_t>(thread);
        if (!tracked_.contains(tid) || !seized_.contains(tid))
            return Error{ErrorCode::invalid_argument, "thread is not a seized thread owned by this session"};
        if (stopped_.contains(tid) || deferred_stops_.contains(tid) || initial_children_.contains(tid))
            return Error{ErrorCode::invalid_argument, "thread interrupt requires a known-running thread"};
        if (!interrupting_.empty() || requested_thread_interrupt_ || wait_stop_requested_.load() ||
            !step_threads_.empty() || displaced_step_ || breakpoint_rollback_ || breakpoint_rearm_ ||
            resume_blocked_ || !hardware_pending_children_.empty())
            return Error{ErrorCode::busy, "another interrupt, step, rollback, or breakpoint configuration is in progress"};
        interrupting_.insert(tid);
        requested_thread_interrupt_ = tid;
        if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) != 0) {
            interrupting_.erase(tid);
            requested_thread_interrupt_.reset();
            if (errno == ESRCH)
                return Error{ErrorCode::invalid_argument, "thread exited before the interrupt was accepted"};
            return sys_error("PTRACE_INTERRUPT selected thread");
        }
        return std::monostate{};
    }
    bool supports_thread_interrupt() const noexcept override { return true; }

    Result<DebugEvent> wait_event(std::chrono::milliseconds timeout) override {
        WaitScope scope(*this, timeout);
        EventPollScope event_scope(event_polling_);
        if (startup_cleanup_ || detach_preparing_ || detaching_ || terminating_) return Error{ErrorCode::busy, "cleanup must complete before event polling"};
        if (pid_ <= 0) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        if (pending_) return Error{ErrorCode::busy, "previous debug event has not been continued"};
        if (initial_event_) {
            auto event = *initial_event_; initial_event_.reset(); event.sequence = ++seq_;
            pending_ = std::pair{event.sequence, static_cast<pid_t>(event.thread)};
            pending_breakpoint_.reset();
            pending_debugger_trap_ = false; pending_signal_ = 0;
            return event;
        }
        auto children = complete_pending_children(); if (!children) return children.error();
        do {
            int status{};
            pid_t tid = 0;
            bool requested_thread_interrupt = false;
            // Collect an active step's completion or exceptional stop before
            // exposing a deferred peer event. Otherwise stopping peers for
            // that event could consume this thread's trace/interrupt stop and
            // leave an outstanding user step to be resumed with PTRACE_CONT.
            // Displaced instructions also retain their code-byte ownership
            // until this thread stops and the trap has been rearmed.
            std::optional<pid_t> active_step_thread;
            if (displaced_step_) active_step_thread = displaced_step_->thread;
            else if (!step_threads_.empty()) active_step_thread = *step_threads_.begin();
            if (!active_step_thread && !deferred_stops_.empty()) {
                const auto first = deferred_stops_.begin();
                tid = first->first; status = first->second;
                deferred_stops_.erase(first);
            }
            for (const auto candidate : tracked_) {
                if (tid) break;
                if (active_step_thread && candidate != *active_step_thread) continue;
                const auto deferred = deferred_stops_.find(candidate);
                if (deferred != deferred_stops_.end()) {
                    tid = candidate; status = deferred->second;
                    deferred_stops_.erase(deferred);
                    break;
                }
                const auto waited = waitpid(candidate, &status, __WALL | WNOHANG);
                if (waited == candidate) { tid = waited; break; }
                if (waited < 0 && errno != ECHILD && errno != EINTR) return sys_error("waitpid");
            }
            if (tid > 0) {
                // waitpid has now consumed the ptrace status that satisfied a
                // previously issued PTRACE_INTERRUPT. Clear the outstanding
                // marker before stop_all_threads() sees this event; otherwise
                // it mistakes the already-stopped task for an interrupt still
                // in flight and waits until the operation deadline expires.
                interrupting_.erase(tid);
                if (WIFSTOPPED(status)) stopped_.insert(tid);
                bool displaced_user_step = false;
                std::string resume_failure;
                bool failed_trace = false;
                const bool requested_user_step = step_threads_.erase(tid) != 0;
                siginfo_t stop_info{};
                const bool trace_complete = WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP &&
                    (static_cast<unsigned>(status) >> 16) == 0 &&
                    ptrace(PTRACE_GETSIGINFO, tid, nullptr, &stop_info) == 0 && stop_info.si_code == TRAP_TRACE;
                // A stepped instruction can also hit a data watchpoint while
                // Linux reports TRAP_TRACE. Inspect DR6 before deciding that
                // an internal step can be swallowed and the process resumed.
                std::optional<unsigned long> stopped_dr6;
                std::optional<Error> hardware_status_error;
                if (!hardware_slots_.empty() && WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP &&
                    (static_cast<unsigned>(status) >> 16) == 0) {
                    auto dr6 = peek_debug_register(tid, 6);
                    if (dr6) stopped_dr6 = dr6.value();
                    else hardware_status_error = dr6.error();
                }
                const bool hardware_trap = stopped_dr6 && ((*stopped_dr6 & 0xfu) != 0);
                const bool internal_step_only = !hardware_trap && !hardware_status_error;
                if (displaced_step_ && displaced_step_->thread == tid) {
                    const auto step = *displaced_step_;
                    const auto owner = std::find_if(ids_.begin(), ids_.end(), [&](const auto& item) {
                        return item.second == step.address && enabled_ids_.contains(item.first);
                    });
                    auto rearmed = owner != ids_.end() && !(tid == pid_ && (WIFEXITED(status) || WIFSIGNALED(status)))
                        ? rearm_software_breakpoint(step.address) : Status{std::monostate{}};
                    if (!rearmed) {
                        // Publish this stop normally and retain the missing
                        // trap as explicit recovery work before any resume.
                        breakpoint_rearm_ = step.address;
                        resume_blocked_ = true;
                        resume_failure = "reinsert INT3 after displaced instruction: " + rearmed.error().message;
                        failed_trace = trace_complete;
                    }
                    displaced_step_.reset();
                    if (trace_complete && resume_failure.empty() && internal_step_only) {
                        if (step.continue_process) {
                            auto resumed = resume_stopped_threads(tid, 0);
                            if (resumed) continue; // internal step completed the original global continue
                            resume_failure = "global continue failed after breakpoint rearm: " + resumed.error().message;
                            failed_trace = true;
                        } else if (step.continue_thread) {
                            if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == 0) {
                                stopped_.erase(tid);
                                continue; // peers remain held after the internal step
                            }
                            resume_failure = sys_error("PTRACE_CONT event thread after breakpoint rearm").message;
                            failed_trace = true;
                        } else if (!step.deferred_resumes.empty()) {
                            std::vector<pid_t> resumed;
                            for (const auto& [resume_tid, signal] : step.deferred_resumes) {
                                if (ptrace(PTRACE_CONT, resume_tid, nullptr,
                                           reinterpret_cast<void*>(static_cast<std::intptr_t>(signal))) == 0) {
                                    stopped_.erase(resume_tid);
                                    deferred_signals_.erase(resume_tid);
                                    resumed.push_back(resume_tid);
                                    continue;
                                }
                                const auto error = sys_error("PTRACE_CONT deferred Linux breakpoint schedule");
                                auto rollback = stop_threads(resumed, true);
                                if (!rollback) {
                                    resume_blocked_ = true;
                                    resume_failure = error.message + "; deferred-schedule rollback failed: " + rollback.error().message;
                                } else {
                                    resume_failure = error.message;
                                }
                                failed_trace = true;
                                break;
                            }
                            if (resume_failure.empty()) continue;
                        } else displaced_user_step = true;
                    } else displaced_user_step = trace_complete && resume_failure.empty() && internal_step_only;
                    if (!trace_complete && WIFSTOPPED(status)) {
                        auto ip = instruction_pointer(tid);
                        if (ip && ip.value() == step.address) pending_breakpoint_ = step.address;
                    }
                }
                DebugEvent event{}; event.sequence = ++seq_; event.process = static_cast<ProcessId>(pid_); event.thread = static_cast<ThreadId>(tid);
                if (WIFEXITED(status) || WIFSIGNALED(status)) {
                    pending_signal_ = 0;
                    pending_debugger_trap_ = false;
                    deferred_signals_.erase(tid);
                    stopped_.erase(tid); tracked_.erase(tid); seized_.erase(tid); interrupting_.erase(tid); deferred_stops_.erase(tid);
                    if (requested_thread_interrupt_ == tid) requested_thread_interrupt_.reset();
                    event.kind = tid == pid_ ? EventKind::process_exited : EventKind::thread_exited;
                    event.code = WIFEXITED(status) ? static_cast<std::uint32_t>(WEXITSTATUS(status)) : static_cast<std::uint32_t>(WTERMSIG(status));
                    event.message = tid == pid_ ? "process exited" : "thread exited";
                    if (tid == pid_) exited_ = true;
                } else if (WIFSTOPPED(status)) {
                    const int signal = WSTOPSIG(status); event.code = static_cast<std::uint32_t>(signal);
                    const auto ptrace_event = static_cast<unsigned>(status) >> 16;
                    const bool was_thread_interrupt = requested_thread_interrupt_ == tid;
                    if (was_thread_interrupt) requested_thread_interrupt_.reset();
                    requested_thread_interrupt = was_thread_interrupt && ptrace_event == PTRACE_EVENT_STOP && signal == SIGTRAP;
                    last_signal_ = ptrace_event == 0 ? static_cast<unsigned>(signal) : 0;
                    if (ptrace_event == PTRACE_EVENT_CLONE) {
                        defer_stop(tid, status);
                        auto child = track_cloned_thread(tid);
                        if (!child) {
                            if (requested_user_step) step_threads_.insert(tid);
                            return child.error();
                        }
                        deferred_stops_.erase(tid);
                        event.kind = EventKind::thread_created; event.message = "thread created";
                    } else {
                    const bool debugger_interrupt = ptrace_event == PTRACE_EVENT_STOP && signal == SIGTRAP;
                    event.kind = debugger_interrupt ? EventKind::interrupted :
                        signal == (SIGTRAP | 0x80) ? EventKind::unknown :
                        (signal == SIGTRAP ? EventKind::breakpoint : EventKind::exception);
                    event.message = debugger_interrupt ? "debugger interrupt" :
                        ptrace_event == PTRACE_EVENT_STOP ? "group stop" : "ptrace stop";
                    if (signal == SIGTRAP && ptrace_event != PTRACE_EVENT_STOP) {
                        bool hardware_breakpoint = false;
                        if (hardware_slots_.size() != 0) {
                            auto dr6 = stopped_dr6 ? Result<unsigned long>{*stopped_dr6} :
                                hardware_status_error ? Result<unsigned long>{*hardware_status_error} : peek_debug_register(tid, 6);
                            if (dr6 && (dr6.value() & 0xf) != 0) {
                                event.breakpoint_ids = detail::hardware_breakpoint_hits(hardware_slot_ids_, dr6.value());
                                const auto owned_mask = static_cast<unsigned long>((1u << hardware_slot_ids_.size()) - 1u);
                                const auto preserved = static_cast<unsigned long>(dr6.value()) & 0xfu & ~owned_mask;
                                auto cleared = poke_debug_register(tid, 6, 0xffff0ff0UL | preserved);
                                if (!cleared) event.message += "; " + cleared.error().message;
                                if (!event.breakpoint_ids.empty()) {
                                    hardware_breakpoint = true;
                                    event.kind = EventKind::breakpoint;
                                    event.message = "hardware breakpoint hit";
                                    if (!cleared) event.message += "; " + cleared.error().message;
                                    const auto hit = std::find_if(hardware_breakpoints_.begin(), hardware_breakpoints_.end(),
                                        [&](const auto& record) { return record.id == event.breakpoint_ids.front(); });
                                    event.address = hit == hardware_breakpoints_.end() ? regs_address(tid) : hit->address;
                                }
                            } else if (!dr6) event.message += "; " + dr6.error().message;
                        }
                        const auto ip = instruction_pointer(tid);
                        if (!hardware_breakpoint && ip && ip.value() > 0) event.address = ip.value() - 1;
                        const auto bp = breakpoints_.find(event.address);
                        const auto owner = std::find_if(ids_.begin(), ids_.end(), [&](const auto& item) {
                            return item.second == event.address && enabled_ids_.contains(item.first);
                        });
                        if (!hardware_breakpoint && internal_step_only &&
                            (displaced_user_step || (requested_user_step && trace_complete))) {
                            event.kind = EventKind::single_step;
                            if (ip) event.address = ip.value();
                        } else if (!hardware_breakpoint && !trace_complete && bp != breakpoints_.end() && owner != ids_.end()) {
                            event.kind = EventKind::breakpoint;
                            pending_breakpoint_ = event.address;
                        }
                        if (trace_complete && !hardware_breakpoint && !internal_step_only) {
                            event.kind = EventKind::exception;
                            if (ip) event.address = ip.value();
                            if (hardware_trap) event.message += "; unowned hardware breakpoint status";
                        }
                    }
                    }
                    pending_debugger_trap_ = event.kind == EventKind::single_step || pending_breakpoint_.has_value() || !event.breakpoint_ids.empty();
                    pending_signal_ = pending_debugger_trap_ ? 0 : signal_from_stop(tid, status);
                    if (const auto queued = deferred_signals_.find(tid); queued != deferred_signals_.end())
                        pending_signal_ = queued->second;
                }
                if (!resume_failure.empty()) {
                    event.message += "; " + resume_failure;
                    if (failed_trace) {
                        pending_breakpoint_.reset(); // the displaced instruction has already executed
                        // A real watchpoint still owns this stop even when
                        // rearming its simultaneous internal step failed.
                        if (event.breakpoint_ids.empty()) {
                            event.kind = EventKind::exception;
                            auto ip = instruction_pointer(tid);
                            if (ip) event.address = ip.value();
                        }
                    }
                }
                if (event.kind != EventKind::process_exited && !requested_thread_interrupt) {
                    auto stopped = stop_all_threads();
                    if (!stopped) {
                        resume_blocked_ = true;
                        event.message += "; peer suspension incomplete: " + stopped.error().message;
                    }
                }
                pending_ = std::pair{event.sequence, tid}; pending_thread_interrupt_ = requested_thread_interrupt; return event;
            }
            auto progress = wait_progress(); if (!progress) return progress.error();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        } while (wait_deadline_ && Clock::now() < *wait_deadline_);
        return Error{ErrorCode::busy, "debug event wait timed out"};
    }

    Status continue_event(std::uint64_t sequence, ContinueStatus disposition) override {
        WaitScope scope(*this);
        if (!pending_ || pending_->first != sequence) return Error{ErrorCode::invalid_argument, "event sequence does not match pending event"};
        const auto tid = pending_->second;
        const int signal = disposition == ContinueStatus::handled ? 0 : pending_signal_;
        if (exited_ && tid == pid_) { clear(); return std::monostate{}; }
        auto recovered = recover_suspension();
        if (!recovered) return recovered;
        if (pending_thread_interrupt_) {
            if (ptrace(PTRACE_CONT, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(signal))) != 0)
                return sys_error("PTRACE_CONT interrupted Linux thread");
            stopped_.erase(tid);
            deferred_signals_.erase(tid);
            pending_breakpoint_.reset(); pending_.reset(); pending_signal_ = 0;
            pending_thread_interrupt_ = false;
            return std::monostate{};
        }
        if (disposition == ContinueStatus::handled) {
            auto displaced = needs_displaced_step(tid);
            if (!displaced) return displaced.error();
            if (displaced.value()) return begin_displaced_step(tid, true);
        }
        auto resumed = resume_stopped_threads(tid, signal);
        if (!resumed) return resumed;
        deferred_signals_.erase(tid);
        pending_breakpoint_.reset(); pending_.reset(); pending_signal_ = 0; pending_thread_interrupt_ = false;
        return std::monostate{};
    }
    Status continue_thread_event(std::uint64_t sequence, ThreadId thread, ContinueStatus disposition) override {
        WaitScope scope(*this);
        if (!pending_ || pending_->first != sequence) return Error{ErrorCode::invalid_argument, "event sequence does not match pending event"};
        const auto tid = pending_->second;
        if (thread != static_cast<ThreadId>(tid) || !tracked_.contains(tid))
            return Error{ErrorCode::invalid_argument, "selected thread does not own the pending stop event"};
        if (exited_ && tid == pid_) return Error{ErrorCode::busy, "the process exit event cannot resume a thread"};
        auto recovered = recover_suspension();
        if (!recovered) return recovered;
        if (!std::all_of(tracked_.begin(), tracked_.end(), [&](pid_t current) { return stopped_.contains(current); }))
            return Error{ErrorCode::busy, "thread-qualified continue requires all peers to remain stopped"};
        const int signal = disposition == ContinueStatus::handled ? 0 : pending_signal_;
        if (disposition == ContinueStatus::handled) {
            auto displaced = needs_displaced_step(tid);
            if (!displaced) return displaced.error();
            if (displaced.value()) return begin_displaced_step(tid, false, true);
        }
        if (ptrace(PTRACE_CONT, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(signal))) != 0)
            return sys_error("PTRACE_CONT selected thread");
        stopped_.erase(tid);
        deferred_signals_.erase(tid);
        pending_breakpoint_.reset(); pending_.reset(); pending_signal_ = 0; pending_thread_interrupt_ = false;
        return std::monostate{};
    }
    Status resume_threads_event(std::uint64_t sequence, std::span<const ThreadResumeAction> actions) override {
        WaitScope scope(*this);
        if (!pending_ || pending_->first != sequence)
            return Error{ErrorCode::invalid_argument, "event sequence does not match pending event"};
        if (pending_->second <= 0 || (pending_->second == pid_ && exited_))
            return Error{ErrorCode::busy, "pending event cannot resume a target thread"};
        if (actions.empty() || actions.size() > max_inspection_threads)
            return Error{ErrorCode::invalid_argument, "thread resume schedule must contain 1 to 4096 actions"};
        auto recovered = recover_suspension();
        if (!recovered) return recovered;
        if (!std::all_of(tracked_.begin(), tracked_.end(), [&](pid_t thread) { return stopped_.contains(thread); }))
            return Error{ErrorCode::busy, "thread resume schedule requires every traced thread to be stopped"};
        const auto owner = pending_->second;
        if (owner <= 0 || !tracked_.contains(owner) || !stopped_.contains(owner))
            return Error{ErrorCode::invalid_argument, "pending event owner is not a stopped thread owned by this session"};
        const auto signal_for = [&](const ThreadResumeAction& action) {
            const auto tid = static_cast<pid_t>(action.thread);
            if (tid == owner && pending_signal_ != 0) return pending_signal_;
            const auto queued = deferred_signals_.find(tid);
            return queued == deferred_signals_.end() ? 0 : queued->second;
        };
        const auto apply_stopped_signal_dispositions = [&] {
            for (const auto& action : actions) {
                const auto tid = static_cast<pid_t>(action.thread);
                if (action.kind != ThreadResumeKind::stop) continue;
                const int signal = signal_for(action);
                if (action.signal_disposition == ContinueStatus::handled) {
                    if (signal != 0 || deferred_signals_.contains(tid)) deferred_signals_[tid] = 0;
                } else if (signal != 0) deferred_signals_[tid] = signal;
            }
        };
        std::set<pid_t> selected;
        std::vector<const ThreadResumeAction*> runnable;
        for (const auto &action : actions) {
            if (!action.thread || action.thread > static_cast<ThreadId>(std::numeric_limits<pid_t>::max()))
                return Error{ErrorCode::invalid_argument, "resume schedule contains an invalid thread ID"};
            if (action.kind != ThreadResumeKind::continue_execution && action.kind != ThreadResumeKind::single_step &&
                action.kind != ThreadResumeKind::stop)
                return Error{ErrorCode::invalid_argument, "resume schedule contains an unknown action"};
            if (action.signal_disposition && *action.signal_disposition != ContinueStatus::handled &&
                *action.signal_disposition != ContinueStatus::not_handled)
                return Error{ErrorCode::invalid_argument, "resume schedule contains an unknown signal disposition"};
            const auto tid = static_cast<pid_t>(action.thread);
            if (!selected.insert(tid).second)
                return Error{ErrorCode::invalid_argument, "resume schedule contains a duplicate thread"};
            if (!tracked_.contains(tid) || !stopped_.contains(tid))
                return Error{ErrorCode::invalid_argument, "resume schedule thread is not a stopped thread owned by this session"};
            if (action.kind != ThreadResumeKind::stop && deferred_stops_.contains(tid))
                return Error{ErrorCode::busy, "resume schedule thread already owns a deferred stop event"};
            if (action.kind != ThreadResumeKind::stop) runnable.push_back(&action);
        }
        if (!selected.contains(owner))
            return Error{ErrorCode::invalid_argument, "resume schedule must include the thread that owns the pending event"};
        if (runnable.empty())
            return Error{ErrorCode::invalid_argument, "resume schedule must continue or step at least one thread"};
        if (!step_threads_.empty() && std::any_of(runnable.begin(), runnable.end(), [](const auto* action) {
                return action->kind == ThreadResumeKind::single_step;
            }))
            return Error{ErrorCode::busy, "cannot issue another Linux single-step while a step result is pending"};

        if (runnable.size() > 1) {
            const auto single_steps = std::count_if(runnable.begin(), runnable.end(), [](const auto *action) {
                return action->kind == ThreadResumeKind::single_step;
            });
            if (single_steps > 1)
                return Error{ErrorCode::unsupported, "Linux ptrace schedules support at most one single-step action"};
            const auto step_action = std::find_if(runnable.begin(), runnable.end(), [](const auto *action) {
                return action->kind == ThreadResumeKind::single_step;
            });
            // Keep a non-owner step last and require the pending event owner
            // to remain stopped. If the step request fails, peer continuations
            // can be interrupted while the original event stays owned.
            if (step_action != runnable.end() &&
                static_cast<pid_t>((*step_action)->thread) != owner) {
                const auto owner_action = std::find_if(actions.begin(), actions.end(), [&](const auto &action) {
                    return static_cast<pid_t>(action.thread) == owner;
                });
                if (owner_action == actions.end() || owner_action->kind != ThreadResumeKind::stop)
                    return Error{ErrorCode::unsupported,
                        "a mixed non-owner step requires the pending event owner to remain stopped"};
            }
            bool pending_breakpoint_needs_step = false;
            if (pending_breakpoint_) {
                auto needs_step = needs_displaced_step(owner);
                if (!needs_step) return needs_step.error();
                pending_breakpoint_needs_step = needs_step.value();
            }
            if (pending_breakpoint_needs_step) {
                const auto owner_action = std::find_if(actions.begin(), actions.end(), [&](const auto& action) {
                    return static_cast<pid_t>(action.thread) == owner;
                });
                if (owner_action != actions.end() && owner_action->kind == ThreadResumeKind::single_step &&
                    std::none_of(runnable.begin(), runnable.end(), [&](const auto *action) {
                        return static_cast<pid_t>(action->thread) != owner &&
                               action->kind != ThreadResumeKind::continue_execution;
                    })) {
                    const int owner_signal = signal_for(*owner_action);
                    if (owner_signal != 0 && owner_action->signal_disposition != ContinueStatus::handled)
                        return Error{ErrorCode::unsupported,
                            "cannot combine a Linux software-breakpoint step-over with delivery of the owner's pending signal"};
                    // Keep peers stopped while the trap byte is displaced. The
                    // owner's user-visible single-step event is delivered first;
                    // the caller can then choose which peers to continue.
                    auto stepped = begin_displaced_step(owner, false);
                    if (!stepped) return stepped;
                    apply_stopped_signal_dispositions();
                    return std::monostate{};
                }
                if (owner_action == actions.end() || owner_action->kind != ThreadResumeKind::continue_execution ||
                    std::any_of(runnable.begin(), runnable.end(), [](const auto* action) {
                        return action->kind != ThreadResumeKind::continue_execution;
                    }))
                    return Error{ErrorCode::unsupported,
                        "a Linux software-breakpoint step-over schedule requires the event owner and selected peers to continue"};
                std::vector<std::pair<pid_t, int>> deferred_resumes;
                deferred_resumes.reserve(runnable.size());
                for (const auto* action : runnable) {
                    const auto tid = static_cast<pid_t>(action->thread);
                    if (tid == owner && action->signal_disposition != ContinueStatus::handled && pending_signal_ != 0)
                        return Error{ErrorCode::unsupported,
                            "cannot combine software-breakpoint step-over with delivery of the owner's pending signal"};
                    const int queued = signal_for(*action);
                    const int delivered = action->signal_disposition == ContinueStatus::handled ? 0 : queued;
                    deferred_resumes.emplace_back(tid, delivered);
                }
                auto stepped = begin_displaced_step(owner, false, false, std::move(deferred_resumes));
                if (!stepped) return stepped;
                apply_stopped_signal_dispositions();
                return std::monostate{};
            }

            // Release non-owner continuations first and the pending-event owner
            // last among continuations. A single step, whether it belongs to
            // the owner or another stopped thread, is always the final request.
            std::vector<pid_t> order;
            order.reserve(runnable.size());
            for (const auto* action : runnable) {
                const auto tid = static_cast<pid_t>(action->thread);
                if (action->kind == ThreadResumeKind::continue_execution && tid != owner)
                    order.push_back(tid);
            }
            const auto owner_continue = std::find_if(runnable.begin(), runnable.end(), [&](const auto *action) {
                return static_cast<pid_t>(action->thread) == owner &&
                       action->kind == ThreadResumeKind::continue_execution;
            });
            if (owner_continue != runnable.end())
                order.push_back(owner);
            if (step_action != runnable.end())
                order.push_back(static_cast<pid_t>((*step_action)->thread));

            std::vector<pid_t> resumed;
            resumed.reserve(order.size() - static_cast<std::size_t>(step_action != runnable.end()));
            for (const auto tid : order) {
                const auto action = std::find_if(runnable.begin(), runnable.end(), [&](const auto* item) {
                    return static_cast<pid_t>(item->thread) == tid;
                });
                const auto* selected_action = *action;
                const int queued_signal = signal_for(*selected_action);
                const int delivered = selected_action->signal_disposition == ContinueStatus::handled ? 0 : queued_signal;
                if (selected_action->kind == ThreadResumeKind::single_step) {
                    if (ptrace(PTRACE_SINGLESTEP, tid, nullptr,
                               reinterpret_cast<void*>(static_cast<std::intptr_t>(delivered))) != 0) {
                        const auto error = sys_error("PTRACE_SINGLESTEP scheduled Linux thread");
                        auto rollback = stop_threads(resumed, true);
                        resume_blocked_ = !rollback;
                        if (!rollback)
                            return Error{error.code, error.message + "; resume rollback failed: " + rollback.error().message};
                        return error;
                    }
                    stopped_.erase(tid);
                    step_threads_.insert(tid);
                    deferred_signals_.erase(tid);
                    if (tid == owner) pending_signal_ = 0;
                    continue;
                }
                if (ptrace(PTRACE_CONT, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(delivered))) != 0) {
                    const auto error = sys_error("PTRACE_CONT scheduled Linux thread");
                    auto rollback = stop_threads(resumed, true);
                    resume_blocked_ = !rollback;
                    if (!rollback)
                        return Error{error.code, error.message + "; resume rollback failed: " + rollback.error().message};
                    return error;
                }
                stopped_.erase(tid);
                deferred_signals_.erase(tid);
                if (tid == owner) pending_signal_ = 0;
                resumed.push_back(tid);
            }
            apply_stopped_signal_dispositions();
            pending_.reset(); pending_breakpoint_.reset(); pending_signal_ = 0; pending_thread_interrupt_ = false; last_signal_ = 0;
            return std::monostate{};
        }

        const auto* selected_action = runnable.front();
        const auto tid = static_cast<pid_t>(selected_action->thread);
        const int queued_signal = signal_for(*selected_action);
        const int delivered = selected_action->signal_disposition == ContinueStatus::handled ? 0 : queued_signal;
        if (pending_breakpoint_ && tid != owner)
            return Error{ErrorCode::unsupported, "cannot preserve a pending software-breakpoint event while scheduling another thread"};
        if (selected_action->kind == ThreadResumeKind::single_step) {
            if (tid == owner && pending_breakpoint_ && delivered == 0) {
                auto displaced = needs_displaced_step(tid);
                if (!displaced) return displaced.error();
                if (displaced.value()) {
                    auto stepped = begin_displaced_step(tid, false);
                    if (stepped) apply_stopped_signal_dispositions();
                    return stepped;
                }
            }
            if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(delivered))) != 0)
                return sys_error("PTRACE_SINGLESTEP scheduled thread");
            stopped_.erase(tid); step_threads_.insert(tid);
            deferred_signals_.erase(tid);
            apply_stopped_signal_dispositions();
            pending_signal_ = 0;
            pending_.reset(); pending_breakpoint_.reset(); pending_thread_interrupt_ = false; last_signal_ = 0;
            return std::monostate{};
        }

        if (tid == owner && pending_breakpoint_ && delivered == 0) {
            auto displaced = needs_displaced_step(tid);
            if (!displaced) return displaced.error();
            if (displaced.value()) {
                auto stepped = begin_displaced_step(tid, false, true);
                if (stepped) apply_stopped_signal_dispositions();
                return stepped;
            }
        } else if (owner != tid && pending_breakpoint_) {
            if (std::find_if(actions.begin(), actions.end(), [&](const auto &action) {
                    return static_cast<pid_t>(action.thread) == owner && action.kind == ThreadResumeKind::stop;
                }) != actions.end())
                return Error{ErrorCode::unsupported, "cannot retain a software-breakpoint owner while scheduling another thread"};
        }
        // A schedule acknowledges the single pending stop, but resumes only the
        // selected thread. Other listed stop actions and omitted threads remain
        // ptrace-stopped until a later event schedule.
        if (ptrace(PTRACE_CONT, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(delivered))) != 0)
            return sys_error("PTRACE_CONT scheduled thread");
        stopped_.erase(tid);
        deferred_signals_.erase(tid);
        apply_stopped_signal_dispositions();
        pending_signal_ = 0;
        pending_.reset(); pending_breakpoint_.reset(); pending_thread_interrupt_ = false; last_signal_ = 0;
        return std::monostate{};
    }
    Status single_step_event(std::uint64_t sequence, ContinueStatus disposition) override {
        WaitScope scope(*this);
        if (!pending_ || pending_->first != sequence) return Error{ErrorCode::invalid_argument, "event sequence does not match pending event"};
        const auto tid = pending_->second;
        auto recovered = recover_suspension();
        if (!recovered) return recovered;
        if (disposition == ContinueStatus::handled) {
            auto displaced = needs_displaced_step(tid);
            if (!displaced) return displaced.error();
            if (displaced.value()) return begin_displaced_step(tid, false);
        }
        const int signal = disposition == ContinueStatus::handled ? 0 : pending_signal_;
        if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(signal))) != 0) return sys_error("PTRACE_SINGLESTEP");
        deferred_signals_.erase(tid);
        pending_.reset(); pending_breakpoint_.reset(); pending_signal_ = 0; pending_thread_interrupt_ = false;
        stopped_.erase(tid); step_threads_.insert(tid); return std::monostate{};
    }

    Result<std::vector<std::byte>> read_memory(std::uint64_t address, std::size_t size) override {
        if (pid_ <= 0 || size > max_inspection_read || address > UINT64_MAX - size)
            return Error{ErrorCode::invalid_argument, "invalid memory read range"};
        std::vector<std::byte> out(size);
        for (std::size_t i = 0; i < size;) {
            errno = 0; const auto word = ptrace(PTRACE_PEEKDATA, pid_, reinterpret_cast<void*>(static_cast<std::uintptr_t>(address + i)), nullptr);
            if (word == -1 && errno) return sys_error("PTRACE_PEEKDATA");
            const auto count = std::min(sizeof(word), size - i); std::memcpy(out.data() + i, &word, count); i += count;
        }
        return out;
    }
    Result<std::vector<std::byte>> signal_info() override {
        if (pid_ <= 0 || !pending_ || pending_->second <= 0 || !tracked_.contains(pending_->second))
            return Error{ErrorCode::unsupported, "there is no pending Linux signal event with a readable siginfo record"};
        siginfo_t info{};
        if (ptrace(PTRACE_GETSIGINFO, pending_->second, nullptr, &info) != 0) {
            if (errno == EINVAL || errno == EIO)
                return Error{ErrorCode::unsupported, "the pending Linux ptrace event has no readable siginfo record"};
            return sys_error("PTRACE_GETSIGINFO");
        }
        std::vector<std::byte> bytes(sizeof(info));
        std::memcpy(bytes.data(), &info, sizeof(info));
        return bytes;
    }
    Status write_memory(std::uint64_t address, std::span<const std::byte> data) override {
        if (detach_preparing_ || detaching_)
            return Error{ErrorCode::busy, "complete detach cleanup before editing target memory"};
        if (pid_ <= 0) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        if (breakpoint_rollback_)
            return Error{ErrorCode::busy, "recover breakpoint-step rollback before editing target memory"};
        if (data.size() > max_inspection_read || address > UINT64_MAX - data.size())
            return Error{ErrorCode::invalid_argument, "invalid memory write range"};
        if (!std::all_of(tracked_.begin(), tracked_.end(), [&](pid_t thread) { return stopped_.contains(thread); }))
            return Error{ErrorCode::busy, "memory writes require every tracked target thread to be stopped"};
        auto original = read_memory_raw(address, data.size());
        if (!original) return original.error();
        std::vector<std::byte> patched(data.begin(), data.end());
        std::vector<std::pair<std::uint64_t, std::byte>> updated_originals;
        if (!data.empty()) {
            const auto end = address + data.size();
            for (auto it = breakpoints_.lower_bound(address); it != breakpoints_.end() && it->first < end; ++it) {
                const auto index = static_cast<std::size_t>(it->first - address);
                updated_originals.emplace_back(it->first, data[index]);
                const auto owner = std::find_if(ids_.begin(), ids_.end(), [&](const auto& item) {
                    return item.second == it->first && enabled_ids_.contains(item.first);
                });
                if (owner != ids_.end()) patched[index] = std::byte{0xcc};
            }
        }
        auto written = write_memory_raw(address, patched);
        if (!written) {
            auto rollback = write_memory_raw(address, original.value());
            if (!rollback)
                return Error{written.error().code, written.error().message + "; memory rollback failed: " + rollback.error().message};
            return written;
        }
        for (const auto& [at, value] : updated_originals) breakpoints_.at(at) = value;
        return std::monostate{};
    }
    Result<std::vector<ThreadInfo>> threads() override {
        if (pid_ <= 0) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        std::vector<ThreadInfo> out;
        if (exited_) {
            out.reserve(tracked_.size());
            for (const auto tid : tracked_)
                out.push_back({static_cast<ThreadId>(tid), {}, ThreadState::exited});
            return out;
        }
        std::error_code ec;
        const auto path = "/proc/" + std::to_string(pid_) + "/task";
        for (std::filesystem::directory_iterator it(path, ec), end; !ec && it != end; it.increment(ec)) {
            pid_t tid{}; if (!parse_pid(it->path().filename().string(), tid)) continue;
            if (out.size() == max_inspection_threads)
                return Error{ErrorCode::resource_limit, "target thread count exceeds the inspection limit"};
            auto name = proc_name(tid);
            ThreadInfo thread{static_cast<ThreadId>(tid), std::move(name),
                stopped_.contains(tid) ? ThreadState::stopped : ThreadState::running};
            thread.native_state = detail::linux_proc_task_state(pid_, tid);
            out.push_back(std::move(thread));
        }
        if (ec) return Error{ErrorCode::io, "failed to enumerate target threads: " + ec.message()};
        return out;
    }
    Result<std::vector<ThreadRunState>> thread_run_states() override {
        if (pid_ <= 0) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        if (tracked_.size() > max_inspection_threads)
            return Error{ErrorCode::resource_limit, "tracked thread count exceeds the inspection limit"};
        std::vector<ThreadRunState> out;
        if (exited_) {
            out.reserve(tracked_.size());
            for (const auto tid : tracked_)
                out.push_back({static_cast<ThreadId>(tid), ThreadState::exited});
            return out;
        }
        auto current = threads();
        if (!current) return current.error();
        out.reserve(current.value().size());
        for (const auto& thread : current.value()) {
            const auto tid = static_cast<pid_t>(thread.id);
            const auto state = !tracked_.contains(tid) ? ThreadState::unknown
                : stopped_.contains(tid) ? ThreadState::stopped : ThreadState::running;
            out.push_back({thread.id, state});
        }
        return out;
    }
    Result<std::vector<MemoryRegion>> memory_regions() override {
        if (pid_ <= 0) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        auto mappings = read_proc_mappings(pid_);
        if (!mappings) return mappings.error();
        if (mappings.value().size() > max_inspection_memory_regions)
            return Error{ErrorCode::resource_limit, "target exposes more than 65536 memory regions"};
        std::vector<MemoryRegion> out;
        out.reserve(mappings.value().size());
        for (auto& mapping : mappings.value()) {
            if (!mapping.path.empty()) mapping.region.type += ":" + mapping.path;
            out.push_back(std::move(mapping.region));
        }
        return out;
    }
    Result<std::vector<ModuleInfo>> modules() override {
        if (pid_ <= 0) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        auto mappings = read_proc_mappings(pid_);
        if (!mappings) return mappings.error();
        struct Range { std::uint64_t base; std::uint64_t end; };
        std::map<std::string, Range> ranges;
        for (const auto& mapping : mappings.value()) {
            if (mapping.path.empty() || mapping.path.front() == '[') continue;
            const auto [it, inserted] = ranges.emplace(mapping.path,
                Range{mapping.region.start, mapping.region.start + mapping.region.length});
            if (!inserted) {
                it->second.base = std::min(it->second.base, mapping.region.start);
                it->second.end = std::max(it->second.end, mapping.region.start + mapping.region.length);
            }
        }
        if (ranges.size() > max_inspection_modules)
            return Error{ErrorCode::resource_limit, "target exposes more than 4096 mapped modules"};
        std::vector<ModuleInfo> out;
        out.reserve(ranges.size());
        for (const auto& [path, range] : ranges) {
            const auto slash = path.find_last_of('/');
            const auto name = slash == std::string::npos ? path : path.substr(slash + 1);
            out.push_back({name, path, range.base, range.end - range.base});
        }
        return out;
    }
    Result<std::vector<RegisterValue>> read_registers(ThreadId thread) override {
        if (architecture_ == Architecture::x86) {
            auto regs = read_i386_registers(static_cast<pid_t>(thread));
            if (!regs) return regs.error();
            auto out = detail::i386_register_values(regs.value());
            auto xstate = read_i386_xstate_image(static_cast<pid_t>(thread));
            if (!xstate && xstate.error().code == ErrorCode::unsupported) return out;
            if (!xstate) return xstate.error();
            auto fp_values = detail::x86_i386_fxsave_register_values(xstate.value());
            if (!fp_values) return fp_values.error();
            out.insert(out.end(), std::make_move_iterator(fp_values.value().begin()),
                       std::make_move_iterator(fp_values.value().end()));
            if (const auto layout = host_ymm_xstate_layout()) {
                auto ymm_values = detail::x86_i386_xstate_ymm_upper_register_values(xstate.value(), *layout);
                if (ymm_values)
                    out.insert(out.end(), std::make_move_iterator(ymm_values.value().begin()),
                               std::make_move_iterator(ymm_values.value().end()));
                else if (ymm_values.error().code != ErrorCode::unsupported) return ymm_values.error();
            }
            return out;
        }
        user_regs_struct r{}; if (ptrace(PTRACE_GETREGS, static_cast<pid_t>(thread), nullptr, &r) != 0) return sys_error("PTRACE_GETREGS");
        std::vector<RegisterValue> out;
#define HEXLAB_REG(name) add_reg(out, #name, r.name)
        HEXLAB_REG(rax); HEXLAB_REG(rbx); HEXLAB_REG(rcx); HEXLAB_REG(rdx); HEXLAB_REG(rsi); HEXLAB_REG(rdi); HEXLAB_REG(rbp); HEXLAB_REG(rsp);
        HEXLAB_REG(r8); HEXLAB_REG(r9); HEXLAB_REG(r10); HEXLAB_REG(r11); HEXLAB_REG(r12); HEXLAB_REG(r13); HEXLAB_REG(r14); HEXLAB_REG(r15);
        HEXLAB_REG(rip); HEXLAB_REG(eflags); HEXLAB_REG(cs); HEXLAB_REG(ss); HEXLAB_REG(ds); HEXLAB_REG(es); HEXLAB_REG(fs); HEXLAB_REG(gs);
#undef HEXLAB_REG
        user_fpregs_struct fp{};
        static_assert(sizeof(fp) >= detail::x86_fxsave_size,
                      "Linux x86-64 user FP state must contain the FXSAVE image");
        if (ptrace(PTRACE_GETFPREGS, static_cast<pid_t>(thread), nullptr, &fp) != 0)
            return sys_error("PTRACE_GETFPREGS");
        const auto fp_image = std::span<const std::byte>(reinterpret_cast<const std::byte*>(&fp), sizeof(fp));
        auto fp_values = detail::x86_fxsave_register_values(fp_image);
        if (!fp_values) return fp_values.error();
        out.insert(out.end(), std::make_move_iterator(fp_values.value().begin()),
                   std::make_move_iterator(fp_values.value().end()));
        if (const auto layout = host_ymm_xstate_layout()) {
            auto xstate = read_xstate_image(static_cast<pid_t>(thread), *layout);
            if (!xstate) return xstate.error();
            if (xstate.value()) {
                auto ymm_values = detail::x86_xstate_ymm_upper_register_values(*xstate.value(), *layout);
                if (!ymm_values) return ymm_values.error();
                out.insert(out.end(), std::make_move_iterator(ymm_values.value().begin()),
                           std::make_move_iterator(ymm_values.value().end()));
                if (detail::x86_avx512_state_available(*layout)) {
                    auto avx512_values = detail::x86_avx512_register_values(*xstate.value(), *layout);
                    if (!avx512_values) return avx512_values.error();
                    out.insert(out.end(), std::make_move_iterator(avx512_values.value().begin()),
                               std::make_move_iterator(avx512_values.value().end()));
                }
            }
        }
        return out;
    }
    Status write_registers(ThreadId thread, std::span<const RegisterValue> registers) override {
        if (detach_preparing_ || detaching_)
            return Error{ErrorCode::busy, "complete detach cleanup before editing target registers"};
        if (breakpoint_rollback_)
            return Error{ErrorCode::busy, "recover breakpoint-step rollback before editing target registers"};
        if (architecture_ == Architecture::x86) {
            const auto tid = static_cast<pid_t>(thread);
            auto original_regs = read_i386_registers(tid);
            if (!original_regs) return original_regs.error();
            auto regs = original_regs.value();
            std::vector<RegisterValue> fp_writes;
            std::vector<RegisterValue> ymm_writes;
            for (const auto& reg : registers) {
                if (detail::x86_i386_fxsave_field(reg.name)) {
                    fp_writes.push_back(reg);
                } else if (detail::x86_i386_ymm_upper_index(reg.name)) {
                    ymm_writes.push_back(reg);
                } else if (!detail::set_i386_register(regs, reg)) {
                    return Error{ErrorCode::invalid_argument, "unknown i386 register or register width mismatch"};
                }
            }
            std::optional<std::vector<std::byte>> original_xstate;
            std::optional<std::vector<std::byte>> updated_xstate;
            if (!fp_writes.empty() || !ymm_writes.empty()) {
                auto xstate = read_i386_xstate_image(tid);
                if (!xstate) return xstate.error();
                original_xstate = std::move(xstate.value());
                updated_xstate = *original_xstate;
                if (!fp_writes.empty()) {
                    auto fp_status = detail::write_x86_i386_fxsave_registers(
                        std::span<std::byte>(updated_xstate->data(), detail::x86_fxsave_size), fp_writes);
                    if (!fp_status) return fp_status.error();
                    detail::x86_set_xstate_bv(*updated_xstate,
                        detail::x86_xstate_bv(*updated_xstate) | 0x3u); // x87 and SSE state are now in use.
                }
                if (!ymm_writes.empty()) {
                    const auto layout = host_ymm_xstate_layout();
                    if (!layout) return Error{ErrorCode::unsupported, "host does not expose AVX state for i386 YMM writes"};
                    auto ymm_status = detail::write_x86_i386_xstate_ymm_upper_registers(
                        *updated_xstate, *layout, ymm_writes);
                    if (!ymm_status) return ymm_status.error();
                }
            }
            const bool write_gpr = std::any_of(registers.begin(), registers.end(), [](const auto& reg) {
                return !detail::x86_i386_fxsave_field(reg.name).has_value() &&
                       !detail::x86_i386_ymm_upper_index(reg.name).has_value();
            });
            return detail::transact_i386_register_sets(!fp_writes.empty() || !ymm_writes.empty(), write_gpr,
                [&] { return write_xstate_image(tid, *updated_xstate); },
                [&] { return write_i386_registers(tid, regs); },
                [&] { return write_xstate_image(tid, *original_xstate); });
        }
        const auto tid = static_cast<pid_t>(thread);
        auto alias_status = detail::validate_x86_avx512_alias_writes(registers);
        if (!alias_status) return alias_status.error();
        const bool write_fp = std::any_of(registers.begin(), registers.end(), [](const auto& reg) {
            return detail::x86_fxsave_field(reg.name).has_value() || reg.name.starts_with("ymm") ||
                   detail::x86_avx512_register_name(reg.name);
        });
        std::vector<RegisterValue> fp_writes;
        user_fpregs_struct fp{}, original_fp{};
        std::optional<std::vector<std::byte>> xstate, original_xstate;
        std::optional<detail::X86XstateLayout> xstate_layout;
        if (write_fp) {
            fp_writes.reserve(registers.size());
            std::vector<RegisterValue> ymm_writes;
            std::vector<RegisterValue> avx512_writes;
            for (const auto& reg : registers) {
                if (detail::x86_fxsave_field(reg.name)) fp_writes.push_back(reg);
                else if (reg.name.starts_with("ymm")) ymm_writes.push_back(reg);
                else if (detail::x86_avx512_register_name(reg.name)) avx512_writes.push_back(reg);
            }
            xstate_layout = host_ymm_xstate_layout();
            if (xstate_layout) {
                auto read = read_xstate_image(tid, *xstate_layout);
                if (!read) return read.error();
                xstate = std::move(read.value());
            }
            if (!xstate) {
                if (!ymm_writes.empty() || !avx512_writes.empty())
                    return Error{ErrorCode::unsupported, "target does not expose usable Linux XSAVE vector components"};
                if (ptrace(PTRACE_GETFPREGS, tid, nullptr, &fp) != 0)
                    return sys_error("PTRACE_GETFPREGS before write");
                original_fp = fp;
                auto fp_status = detail::write_x86_fxsave_registers(
                    std::span<std::byte>(reinterpret_cast<std::byte*>(&fp), sizeof(fp)), fp_writes);
                if (!fp_status) return fp_status.error();
            } else {
                original_xstate = *xstate;
                auto fp_status = detail::write_x86_fxsave_registers(
                    std::span<std::byte>(xstate->data(), detail::x86_fxsave_size), fp_writes);
                if (!fp_status) return fp_status.error();
                // Linux treats an XSAVE component whose XSTATE_BV bit is clear
                // as the architectural init state, even when the corresponding
                // bytes in the buffer are nonzero. Mark x87/SSE present when
                // writing FXSAVE fields (including XMM registers).
                if (!fp_writes.empty())
                    detail::x86_set_xstate_bv(*xstate, detail::x86_xstate_bv(*xstate) | 0x3u);
                auto ymm_status = detail::write_x86_xstate_ymm_upper_registers(*xstate, *xstate_layout, ymm_writes);
                if (!ymm_status) return ymm_status.error();
                if (!avx512_writes.empty()) {
                    if (!detail::x86_avx512_state_available(*xstate_layout))
                        return Error{ErrorCode::unsupported, "target does not expose Linux XSAVE AVX-512 components"};
                    auto avx512_status = detail::write_x86_avx512_registers(*xstate, *xstate_layout, avx512_writes);
                    if (!avx512_status) return avx512_status.error();
                }
            }
        }
        const bool write_gpr = std::any_of(registers.begin(), registers.end(), [](const auto& reg) {
            return !detail::x86_fxsave_field(reg.name).has_value() && !reg.name.starts_with("ymm") &&
                   !detail::x86_avx512_register_name(reg.name);
        });
        user_regs_struct r{};
        if (write_gpr && ptrace(PTRACE_GETREGS, tid, nullptr, &r) != 0)
            return sys_error("PTRACE_GETREGS before write");
        for (const auto& reg : registers) {
            if (detail::x86_fxsave_field(reg.name) || reg.name.starts_with("ymm") ||
                detail::x86_avx512_register_name(reg.name)) continue;
#define HEXLAB_SET(name) if (set_reg(reg, #name, r.name)) continue
            HEXLAB_SET(rax); HEXLAB_SET(rbx); HEXLAB_SET(rcx); HEXLAB_SET(rdx); HEXLAB_SET(rsi); HEXLAB_SET(rdi); HEXLAB_SET(rbp); HEXLAB_SET(rsp);
            HEXLAB_SET(r8); HEXLAB_SET(r9); HEXLAB_SET(r10); HEXLAB_SET(r11); HEXLAB_SET(r12); HEXLAB_SET(r13); HEXLAB_SET(r14); HEXLAB_SET(r15);
            HEXLAB_SET(rip); HEXLAB_SET(eflags); HEXLAB_SET(cs); HEXLAB_SET(ss); HEXLAB_SET(ds); HEXLAB_SET(es); HEXLAB_SET(fs); HEXLAB_SET(gs);
#undef HEXLAB_SET
            return Error{ErrorCode::invalid_argument, "unknown register or register width mismatch"};
        }
        if (write_fp) {
            if (xstate) {
                auto status = write_xstate_image(tid, *xstate);
                if (!status) return status.error();
            } else if (ptrace(PTRACE_SETFPREGS, tid, nullptr, &fp) != 0) {
                return sys_error("PTRACE_SETFPREGS");
            }
        }
        if (write_gpr && ptrace(PTRACE_SETREGS, tid, nullptr, &r) != 0) {
            const auto error = sys_error("PTRACE_SETREGS");
            if (write_fp) {
                const auto rolled_back = original_xstate ? write_xstate_image(tid, *original_xstate)
                    : (ptrace(PTRACE_SETFPREGS, tid, nullptr, &original_fp) == 0
                        ? Status{std::monostate{}} : Status{sys_error("PTRACE_SETFPREGS rollback")});
                if (!rolled_back)
                    return Error{error.code, error.message + "; rollback of FP registers failed: " +
                                 rolled_back.error().message};
            }
            return error;
        }
        return std::monostate{};
    }
    Result<Breakpoint> add_breakpoint(std::uint64_t address, BreakpointKind kind) override {
        if (detach_preparing_ || detaching_)
            return Error{ErrorCode::busy, "complete detach cleanup before editing target breakpoints"};
        if (breakpoint_rollback_)
            return Error{ErrorCode::busy, "recover breakpoint-step rollback before editing target breakpoints"};
        if (kind == BreakpointKind::execute) return add_hardware_breakpoint(address, kind, 1);
        if (kind != BreakpointKind::software) return Error{ErrorCode::unsupported, "Linux ptrace backend supports software and x86 hardware breakpoints"};
        if (breakpoints_.contains(address)) return Error{ErrorCode::conflict, "breakpoint already exists at address"};
        if (breakpoints_.size() >= 4096) return Error{ErrorCode::resource_limit, "Linux software breakpoint limit is 4096"};
        auto current = read_memory(address, 1); if (!current) return current.error();
        if (current.value()[0] == std::byte{0xcc})
            return Error{ErrorCode::conflict, "cannot claim an existing unowned INT3 instruction as a software breakpoint"};
        const std::byte trap{0xcc};
        auto written = write_memory(address, std::span<const std::byte>(&trap, 1));
        if (!written) return written.error();
        breakpoints_[address] = current.value()[0]; const auto id = next_bp_++;
        ids_[id] = address; enabled_ids_.insert(id); return Breakpoint{id, address, kind, true, 1};
    }
    Result<Breakpoint> add_hardware_breakpoint(std::uint64_t address, BreakpointKind kind, std::uint8_t size) override {
        if (detach_preparing_ || detaching_)
            return Error{ErrorCode::busy, "complete detach cleanup before editing target breakpoints"};
        if (kind == BreakpointKind::read)
            return Error{ErrorCode::unsupported, "x86 debug registers cannot distinguish read-only watchpoints; choose access (read/write) or write"};
        if (!pending_ || !stopped_.contains(pending_->second))
            return Error{ErrorCode::busy, "hardware breakpoints can only be changed while a debug event has stopped the target"};
        auto next = hardware_breakpoints_;
        const auto id = next_bp_++;
        next.push_back({id, address, kind, size});
        auto applied = apply_hardware_breakpoints(next);
        if (!applied) return applied.error();
        hardware_breakpoints_ = std::move(next);
        rebuild_hardware_slots();
        return Breakpoint{id, address, kind, true, size};
    }
    Status remove_breakpoint(BreakpointId id) override {
        if (detach_preparing_ || detaching_)
            return Error{ErrorCode::busy, "complete detach cleanup before editing target breakpoints"};
        if (breakpoint_rollback_)
            return Error{ErrorCode::busy, "recover breakpoint-step rollback before editing target breakpoints"};
        const auto hardware = std::find_if(hardware_breakpoints_.begin(), hardware_breakpoints_.end(),
            [id](const auto& breakpoint) { return breakpoint.id == id; });
        if (hardware != hardware_breakpoints_.end()) {
            if (!pending_ || !stopped_.contains(pending_->second))
                return Error{ErrorCode::busy, "hardware breakpoints can only be changed while a debug event has stopped the target"};
            auto next = hardware_breakpoints_;
            std::erase_if(next, [id](const auto& breakpoint) { return breakpoint.id == id; });
            auto applied = apply_hardware_breakpoints(next);
            if (!applied) return applied;
            hardware_breakpoints_ = std::move(next);
            rebuild_hardware_slots();
            return std::monostate{};
        }
        const auto found = ids_.find(id); if (found == ids_.end()) return Error{ErrorCode::invalid_argument, "unknown breakpoint id"};
        const auto address = found->second; const auto original = breakpoints_.at(address);
        if (!std::all_of(tracked_.begin(), tracked_.end(), [&](pid_t thread) { return stopped_.contains(thread); }))
            return Error{ErrorCode::busy, "software breakpoints can only be removed while every traced thread is stopped"};
        const auto expected = enabled_ids_.contains(id) ? std::byte{0xcc} : original;
        auto restored = replace_software_breakpoint_byte(address, expected, original);
        if (!restored) return restored;
        breakpoints_.erase(address); ids_.erase(found); enabled_ids_.erase(id); return std::monostate{};
    }
    Status set_breakpoint_enabled(BreakpointId id, bool enabled) override {
        if (detach_preparing_ || detaching_)
            return Error{ErrorCode::busy, "complete detach cleanup before editing target breakpoints"};
        if (breakpoint_rollback_)
            return Error{ErrorCode::busy, "recover breakpoint-step rollback before editing target breakpoints"};
        const auto hardware = std::find_if(hardware_breakpoints_.begin(), hardware_breakpoints_.end(),
            [id](const auto& item) { return item.id == id; });
        if (hardware != hardware_breakpoints_.end()) {
            if (hardware->enabled == enabled) return std::monostate{};
            auto next = hardware_breakpoints_;
            const auto updated = std::find_if(next.begin(), next.end(), [id](const auto& item) { return item.id == id; });
            updated->enabled = enabled;
            auto applied = apply_hardware_breakpoints(next);
            if (!applied) return applied;
            hardware_breakpoints_ = std::move(next);
            rebuild_hardware_slots();
            return std::monostate{};
        }
        const auto found = ids_.find(id);
        if (found == ids_.end()) return Error{ErrorCode::invalid_argument, "unknown software breakpoint id"};
        const bool was_enabled = enabled_ids_.contains(id);
        if (was_enabled == enabled) return std::monostate{};
        if (!std::all_of(tracked_.begin(), tracked_.end(), [&](pid_t thread) { return stopped_.contains(thread); }))
            return Error{ErrorCode::busy, "software breakpoints can only be changed while every traced thread is stopped"};
        const auto original = breakpoints_.at(found->second);
        auto patched = replace_software_breakpoint_byte(found->second,
            enabled ? original : std::byte{0xcc}, enabled ? std::byte{0xcc} : original);
        if (!patched) return patched;
        if (enabled) enabled_ids_.insert(id); else enabled_ids_.erase(id);
        return std::monostate{};
    }

private:
    static std::chrono::milliseconds configured_wait_timeout() {
        constexpr auto fallback = std::chrono::milliseconds(5000);
        const auto *text = std::getenv("HEXLAB_LINUX_PTRACE_TIMEOUT_MS");
        if (!text) return fallback;
        const std::string_view value(text);
        unsigned milliseconds{};
        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), milliseconds);
        if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || milliseconds < 1 || milliseconds > 60000)
            return fallback;
        return std::chrono::milliseconds(milliseconds);
    }
    Status interrupt_running_threads(bool allow_empty) {
        if (!pid_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        bool requested = false;
        for (const auto tid : tracked_) {
            if (stopped_.contains(tid) || initial_children_.contains(tid)) continue;
            if (interrupting_.contains(tid)) { requested = true; continue; }
            if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) == 0) { interrupting_.insert(tid); requested = true; }
            else if (errno != ESRCH) return sys_error("PTRACE_INTERRUPT");
        }
        if (!requested && !allow_empty) return Error{ErrorCode::busy, "no running traced thread accepted an interrupt"};
        return std::monostate{};
    }
    Status wait_progress(bool cancellable = true) {
        if (cancellable && !cleanup_wait_ && wait_stop_requested_.load()) {
            if (!event_polling_)
                return Error{ErrorCode::canceled, "Linux x86 ptrace wait was interrupted; tracee ownership is retained"};
            wait_stop_requested_.store(false);
            auto interrupted = interrupt_running_threads(true);
            if (!interrupted) return interrupted;
        }
        if (wait_deadline_ && Clock::now() >= *wait_deadline_)
            return Error{ErrorCode::busy, "Linux x86 ptrace operation deadline expired; tracee ownership is retained"};
        return std::monostate{};
    }
    Result<int> wait_status(pid_t tid, bool cancellable = true) {
        WaitScope scope(*this);
        for (;;) {
            int status{};
            const auto waited = waitpid(tid, &status, __WALL | WNOHANG);
            if (waited == tid) return status;
            if (waited < 0 && (errno == ECHILD || errno == ESRCH))
                return Error{ErrorCode::out_of_bounds, "Linux x86 tracee is no longer waitable by this tracer"};
            if (waited < 0 && errno != EINTR) return sys_error("waitpid Linux x86 tracee");
            auto progress = wait_progress(cancellable);
            if (!progress) return progress.error();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    void forget_thread(pid_t tid) {
        tracked_.erase(tid); stopped_.erase(tid); seized_.erase(tid);
        interrupting_.erase(tid); if (requested_thread_interrupt_ == tid) requested_thread_interrupt_.reset();
        deferred_stops_.erase(tid); initial_children_.erase(tid);
        deferred_signals_.erase(tid); hardware_pending_children_.erase(tid); step_threads_.erase(tid);
    }
    int signal_from_stop(pid_t tid, int status) const {
        if (!WIFSTOPPED(status) || (static_cast<unsigned>(status) >> 16) != 0) return 0;
        const int signal = WSTOPSIG(status);
        if (signal == (SIGTRAP | 0x80)) return 0;
        if (signal != SIGTRAP) return signal;
        siginfo_t info{};
        if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &info) != 0) return 0;
        if (info.si_code == TRAP_TRACE) return 0;
        if (info.si_code == TRAP_HWBKPT) {
            auto dr6 = peek_debug_register(tid, 6);
            if (dr6 && !detail::hardware_breakpoint_hits(hardware_slot_ids_, dr6.value()).empty()) return 0;
        }
        if (info.si_code == TRAP_BRKPT || info.si_code == SI_KERNEL) {
            auto ip = instruction_pointer(tid);
            if (ip && ip.value() > 0) {
                const auto address = ip.value() - 1;
                const bool owned = breakpoints_.contains(address) &&
                    std::any_of(ids_.begin(), ids_.end(), [&](const auto& item) {
                        return item.second == address && enabled_ids_.contains(item.first);
                    });
                if (owned) return 0;
            }
        }
        return signal;
    }
    void defer_stop(pid_t tid, int status) {
        deferred_stops_[tid] = status;
        const int signal = signal_from_stop(tid, status);
        if (signal != 0) deferred_signals_[tid] = signal;
    }
    // Failed attach owns only a partial census. Release exactly those TIDs,
    // preserving real signal stops, rather than requiring ownership of peers.
    Status cleanup_startup() {
        WaitScope scope(*this);
        if (!startup_cleanup_) return std::monostate{};
        if (startup_kill_ && !tracked_.empty() && kill(pid_, SIGKILL) != 0 && errno != ESRCH) return sys_error("SIGKILL failed launch");
        const std::vector<pid_t> census(tracked_.begin(), tracked_.end());
        for (const auto tid : census) {
            auto progress = wait_progress(false); if (!progress) return progress;
            if (!startup_kill_ && !stopped_.contains(tid) && !interrupting_.contains(tid)) {
                if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) == 0) interrupting_.insert(tid);
                else if (errno != ESRCH && errno != EIO) return sys_error("PTRACE_INTERRUPT failed attach cleanup");
            }
            while (startup_kill_ || !stopped_.contains(tid)) {
                auto status = wait_status(tid, false); // Cleanup ignores cancellation, but shares the deadline.
                if (!status) {
                    if (status.error().code == ErrorCode::out_of_bounds) { forget_thread(tid); break; }
                    return status.error();
                }
                if (WIFEXITED(status.value()) || WIFSIGNALED(status.value())) { forget_thread(tid); break; }
                if (!WIFSTOPPED(status.value())) return Error{ErrorCode::io, "unexpected failed-startup tracee status"};
                stopped_.insert(tid); interrupting_.erase(tid);
                defer_stop(tid, status.value());
                if (!startup_kill_) break;
                progress = wait_progress(false); if (!progress) return progress;
                if (ptrace(PTRACE_CONT, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(SIGKILL))) != 0 && errno != ESRCH)
                    return sys_error("PTRACE_CONT SIGKILL failed launch");
                stopped_.erase(tid);
            }
            if (!tracked_.contains(tid)) continue;
            const auto status = deferred_stops_.find(tid);
            const int signal = status != deferred_stops_.end() && WIFSTOPPED(status->second) && (static_cast<unsigned>(status->second) >> 16) == 0
                ? WSTOPSIG(status->second) : 0;
            if (ptrace(PTRACE_DETACH, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(signal))) != 0 && errno != ESRCH)
                return sys_error("PTRACE_DETACH failed attach cleanup");
            forget_thread(tid);
        }
        if (!tracked_.empty()) return Error{ErrorCode::busy, "failed-startup cleanup is incomplete"};
        clear(); startup_cleanup_ = false; startup_kill_ = false;
        return std::monostate{};
    }
    Status finish_cloned_thread(pid_t child) {
        auto status = wait_status(child);
        if (!status) {
            if (status.error().code == ErrorCode::out_of_bounds) { forget_thread(child); return std::monostate{}; }
            return status.error();
        }
        if (WIFEXITED(status.value()) || WIFSIGNALED(status.value())) {
            forget_thread(child); deferred_stops_[child] = status.value(); return std::monostate{};
        }
        if (!WIFSTOPPED(status.value())) return Error{ErrorCode::io, "cloned thread did not enter its initial ptrace stop"};
        stopped_.insert(child); interrupting_.erase(child); initial_children_.erase(child);
        if ((static_cast<unsigned>(status.value()) >> 16) != PTRACE_EVENT_STOP) defer_stop(child, status.value());
        if (!hardware_breakpoints_.empty()) {
            hardware_pending_children_.insert(child);
            auto installed = install_hardware_on_thread(child, hardware_breakpoints_, true);
            if (!installed) return installed;
            hardware_pending_children_.erase(child);
        }
        return std::monostate{};
    }
    Status complete_pending_children() {
        const std::vector<pid_t> initial(initial_children_.begin(), initial_children_.end());
        for (const auto child : initial) { auto ready = finish_cloned_thread(child); if (!ready) return ready; }
        const std::vector<pid_t> hardware(hardware_pending_children_.begin(), hardware_pending_children_.end());
        for (const auto child : hardware) {
            auto progress = wait_progress(); if (!progress) return progress;
            auto installed = install_hardware_on_thread(child, hardware_breakpoints_, true);
            if (!installed) return installed;
            hardware_pending_children_.erase(child);
        }
        return std::monostate{};
    }
    Status track_cloned_thread(pid_t parent) {
        unsigned long child_id{};
        if (ptrace(PTRACE_GETEVENTMSG, parent, nullptr, &child_id) != 0) return sys_error("PTRACE_GETEVENTMSG clone");
        if (!child_id || child_id > static_cast<unsigned long>(std::numeric_limits<pid_t>::max()) || child_id == static_cast<unsigned long>(parent))
            return Error{ErrorCode::malformed, "clone event returned an invalid child TID"};
        const auto child = static_cast<pid_t>(child_id);
        if (tracked_.contains(child) && !initial_children_.contains(child)) return std::monostate{};
        tracked_.insert(child); if (seized_.contains(parent)) seized_.insert(child); initial_children_.insert(child);
        if (tracked_.size() > max_inspection_threads)
            return Error{ErrorCode::resource_limit, "cloned-thread limit exceeded; ownership retained for cleanup"};
        return finish_cloned_thread(child);
    }
    struct DisplacedStep {
        pid_t thread;
        std::uint64_t address;
        bool continue_process;
        bool continue_thread = false;
        std::vector<std::pair<pid_t, int>> deferred_resumes;
    };
    struct BreakpointRollback { pid_t thread; std::uint64_t address, instruction_pointer; };
    struct HardwareRecord { BreakpointId id; std::uint64_t address; BreakpointKind kind; std::uint8_t size; bool enabled = true; };

    // Consume only debugger-generated interrupt stops internally. Any signal,
    // clone, or exit racing the interrupt remains an owned, deferred event.
    // Outstanding interrupts survive a timeout so a retry can finish stopping
    // the same threads instead of assuming they are safely stopped.
    Status stop_threads(const std::vector<pid_t>& threads, bool cleanup = false) {
        WaitScope scope(*this);
        CleanupScope rollback_scope(cleanup_wait_, cleanup);
        if (tracked_.size() > 2 * max_inspection_threads)
            return Error{ErrorCode::resource_limit, "too many traced threads for bounded cleanup"};
        auto children = complete_pending_children(); if (!children) return children;
        std::optional<Error> failure;
        for (const auto tid : threads) {
            auto progress = wait_progress(!cleanup); if (!progress) return progress;
            if (!tracked_.contains(tid) || stopped_.contains(tid) || deferred_stops_.contains(tid) || interrupting_.contains(tid)) continue;
            if (!seized_.contains(tid)) return Error{ErrorCode::unsupported, "safe peer suspension requires PTRACE_SEIZE"};
            if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) == 0) interrupting_.insert(tid);
            else {
                const auto code = errno; const auto error = sys_error("PTRACE_INTERRUPT peer thread");
                if (code == ESRCH) {
                    int status{}; const auto waited = waitpid(tid, &status, __WALL | WNOHANG);
                    if (waited == tid) {
                        if (WIFSTOPPED(status)) stopped_.insert(tid);
                        else forget_thread(tid);
                        defer_stop(tid, status);
                        if (WIFSTOPPED(status) && (static_cast<unsigned>(status) >> 16) == PTRACE_EVENT_CLONE) {
                            auto child = track_cloned_thread(tid); if (!child) return child;
                        }
                        continue;
                    }
                }
                if (!failure) failure = error;
            }
        }
        while (!interrupting_.empty()) {
            const std::vector<pid_t> polling(interrupting_.begin(), interrupting_.end());
            for (const auto tid : polling) {
                auto progress = wait_progress(!cleanup); if (!progress) return progress;
                if (!interrupting_.contains(tid)) continue;
                int status{}; const auto waited = waitpid(tid, &status, __WALL | WNOHANG);
                if (waited == tid) {
                    interrupting_.erase(tid);
                    if (WIFSTOPPED(status)) stopped_.insert(tid);
                    else forget_thread(tid);
                    const bool internal = WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP &&
                        (static_cast<unsigned>(status) >> 16) == PTRACE_EVENT_STOP;
                    if (!internal || requested_thread_interrupt_ == tid) defer_stop(tid, status);
                    if (WIFSTOPPED(status) && (static_cast<unsigned>(status) >> 16) == PTRACE_EVENT_CLONE) {
                        auto child = track_cloned_thread(tid); if (!child) return child;
                    }
                } else if (waited < 0 && errno != EINTR && errno != ECHILD && errno != ESRCH) return sys_error("waitpid while stopping peer thread");
            }
            if (interrupting_.empty()) break;
            auto progress = wait_progress(!cleanup); if (!progress) return progress;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return failure ? Status{*failure} : Status{std::monostate{}};
    }
    Status stop_all_threads() {
        return stop_threads(std::vector<pid_t>(tracked_.begin(), tracked_.end()));
    }
    bool has_deferred_stop(pid_t tid) const { return deferred_stops_.contains(tid); }

    // Resume peers first and the acknowledged event thread last. A failure
    // stops every thread released by this attempt and leaves the event owned
    // by the caller. Real events observed during rollback are never discarded.
    Status resume_stopped_threads(pid_t event_thread, int signal) {
        WaitScope scope(*this);
        if (startup_cleanup_ || detach_preparing_ || detaching_ || terminating_) return Error{ErrorCode::busy, "cleanup must complete before resuming"};
        if (tracked_.size() > max_inspection_threads) return Error{ErrorCode::resource_limit, "thread limit exceeded; detach or terminate is required"};
        auto children = complete_pending_children(); if (!children) return children;
        if (resume_blocked_ || !interrupting_.empty())
            return Error{ErrorCode::unsupported, "peer suspension must be recovered before resuming the process"};
        std::vector<pid_t> candidates;
        for (const auto tid : stopped_)
            if (tid != event_thread && !has_deferred_stop(tid)) candidates.push_back(tid);
        if (stopped_.contains(event_thread) && !has_deferred_stop(event_thread)) candidates.push_back(event_thread);
        std::vector<pid_t> resumed;
        for (const auto tid : candidates) {
            const auto queued = deferred_signals_.find(tid);
            const auto delivered = tid == event_thread ? signal : (queued == deferred_signals_.end() ? 0 : queued->second);
            if (ptrace(PTRACE_CONT, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(delivered))) != 0) {
                const auto code = errno;
                const auto error = sys_error("PTRACE_CONT process thread");
                if (code == ESRCH) {
                    int status{};
                    const auto waited = waitpid(tid, &status, __WALL | WNOHANG);
                    if (waited == tid) {
                        defer_stop(tid, status);
                        if (!WIFSTOPPED(status)) stopped_.erase(tid);
                        continue;
                    }
                }
                auto rollback = stop_threads(resumed, true);
                resume_blocked_ = !rollback;
                if (!rollback) return Error{error.code, error.message + "; rollback incomplete: " + rollback.error().message};
                return error;
            }
            stopped_.erase(tid);
            deferred_signals_.erase(tid);
            resumed.push_back(tid);
        }
        return std::monostate{};
    }
    Status recover_suspension() {
        WaitScope scope(*this);
        if (startup_cleanup_ || detach_preparing_ || detaching_ || terminating_) return Error{ErrorCode::busy, "cleanup must complete before resuming"};
        if (tracked_.size() > max_inspection_threads) return Error{ErrorCode::resource_limit, "thread limit exceeded; detach or terminate is required"};
        auto children = complete_pending_children(); if (!children) return children;
        if (!resume_blocked_ && interrupting_.empty() && !breakpoint_rollback_ && !breakpoint_rearm_)
            return std::monostate{};
        auto stopped = stop_all_threads();
        if (!stopped) { resume_blocked_ = true; return stopped; }
        if (breakpoint_rollback_) {
            const auto& rollback = *breakpoint_rollback_;
            auto trap_restored = rearm_software_breakpoint(rollback.address);
            auto ip_restored = set_instruction_pointer(rollback.thread, rollback.instruction_pointer);
            if (!trap_restored || !ip_restored) {
                resume_blocked_ = true;
                return Error{!trap_restored ? trap_restored.error().code : ip_restored.error().code,
                    "breakpoint-step rollback is incomplete; refusing to resume target: " +
                    (!trap_restored ? trap_restored.error().message : ip_restored.error().message)};
            }
            breakpoint_rollback_.reset();
        }
        if (breakpoint_rearm_) {
            const auto owner = std::find_if(ids_.begin(), ids_.end(), [&](const auto& item) {
                return item.second == *breakpoint_rearm_ && enabled_ids_.contains(item.first);
            });
            auto rearmed = owner != ids_.end() ? rearm_software_breakpoint(*breakpoint_rearm_) : Status{std::monostate{}};
            if (!rearmed) {
                resume_blocked_ = true;
                return Error{rearmed.error().code, "breakpoint trap is not rearmed; refusing to resume target: " + rearmed.error().message};
            }
            breakpoint_rearm_.reset();
        }
        resume_blocked_ = false;
        return std::monostate{};
    }
    Result<bool> needs_displaced_step(pid_t tid) const {
        if (!pending_breakpoint_) return false;
        const auto bp = breakpoints_.find(*pending_breakpoint_);
        if (bp == breakpoints_.end()) return false;
        const auto owner = std::find_if(ids_.begin(), ids_.end(), [&](const auto& item) {
            return item.second == bp->first && enabled_ids_.contains(item.first);
        });
        if (owner == ids_.end()) return false;
        auto ip = instruction_pointer(tid);
        if (!ip) return ip.error();
        // A client may explicitly change PC before continuing this stop.
        return ip.value() == bp->first || (bp->first != UINT64_MAX && ip.value() == bp->first + 1);
    }
    Status begin_displaced_step(pid_t tid, bool continue_process, bool continue_thread = false,
                                std::vector<std::pair<pid_t, int>> deferred_resumes = {}) {
        if (displaced_step_) return Error{ErrorCode::busy, "a displaced breakpoint instruction is already running"};
        auto stopped = stop_all_threads();
        if (!stopped) { resume_blocked_ = true; return stopped; }
        const auto address = *pending_breakpoint_;
        auto owned = replace_software_breakpoint_byte(address, std::byte{0xcc}, std::byte{0xcc});
        if (!owned) return owned;
        auto original_ip = instruction_pointer(tid);
        if (!original_ip) return original_ip.error();
        breakpoint_rollback_ = BreakpointRollback{tid, address, original_ip.value()};
        auto restore = [&](Error error) -> Status {
            auto trap_restored = rearm_software_breakpoint(address);
            auto ip_restored = set_instruction_pointer(tid, original_ip.value());
            if (!trap_restored || !ip_restored) {
                resume_blocked_ = true;
                return Error{error.code, error.message + "; breakpoint-step rollback incomplete: " +
                    (!trap_restored ? trap_restored.error().message : ip_restored.error().message)};
            }
            breakpoint_rollback_.reset();
            return error;
        };
        auto moved = set_instruction_pointer(tid, address);
        if (!moved) return restore(moved.error());
        auto displaced = replace_software_breakpoint_byte(address, std::byte{0xcc}, breakpoints_.at(address));
        if (!displaced) return restore(displaced.error());
        if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) != 0)
            return restore(sys_error("PTRACE_SINGLESTEP over software breakpoint"));
        displaced_step_ = DisplacedStep{tid, address, continue_process, continue_thread, std::move(deferred_resumes)};
        breakpoint_rollback_.reset();
        stopped_.erase(tid);
        pending_breakpoint_.reset(); pending_.reset(); pending_signal_ = 0;
        return std::monostate{};
    }
    Result<detail::I386UserRegisters> read_i386_registers(pid_t tid) const {
        detail::I386UserRegisters regs{};
        iovec state{&regs, sizeof(regs)};
        if (ptrace(PTRACE_GETREGSET, tid, reinterpret_cast<void*>(static_cast<std::uintptr_t>(NT_PRSTATUS)), &state) != 0)
            return sys_error("PTRACE_GETREGSET i386 registers");
        if (state.iov_len != sizeof(regs))
            return Error{ErrorCode::unsupported, "kernel returned an unexpected i386 register-set size"};
        return regs;
    }
    Status write_i386_registers(pid_t tid, const detail::I386UserRegisters& regs) const {
        iovec state{const_cast<detail::I386UserRegisters*>(&regs), sizeof(regs)};
        if (ptrace(PTRACE_SETREGSET, tid, reinterpret_cast<void*>(static_cast<std::uintptr_t>(NT_PRSTATUS)), &state) != 0)
            return sys_error("PTRACE_SETREGSET i386 registers");
        return std::monostate{};
    }
    Result<std::uint64_t> instruction_pointer(pid_t tid) const {
        if (architecture_ == Architecture::x86) {
            auto regs = read_i386_registers(tid);
            if (!regs) return regs.error();
            return regs.value().eip;
        }
        user_regs_struct regs{};
        if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) != 0) return sys_error("PTRACE_GETREGS instruction pointer");
        return regs.rip;
    }
    Status set_instruction_pointer(pid_t tid, std::uint64_t address) const {
        if (architecture_ == Architecture::x86) {
            if (address > UINT32_MAX) return Error{ErrorCode::invalid_argument, "i386 instruction pointer exceeds 32 bits"};
            auto regs = read_i386_registers(tid);
            if (!regs) return regs.error();
            regs.value().eip = static_cast<std::uint32_t>(address);
            return write_i386_registers(tid, regs.value());
        }
        user_regs_struct regs{};
        if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) != 0) return sys_error("PTRACE_GETREGS before breakpoint step");
        regs.rip = address;
        if (ptrace(PTRACE_SETREGS, tid, nullptr, &regs) != 0) return sys_error("PTRACE_SETREGS before breakpoint step");
        return std::monostate{};
    }
    Result<std::vector<std::byte>> read_memory_raw(std::uint64_t address, std::size_t size) const {
        if (size > max_inspection_read || address > UINT64_MAX - size)
            return Error{ErrorCode::invalid_argument, "invalid memory read range"};
        std::vector<std::byte> out(size);
        for (std::size_t i = 0; i < size;) {
            errno = 0;
            const auto word = ptrace(PTRACE_PEEKDATA, pid_,
                                    reinterpret_cast<void*>(static_cast<std::uintptr_t>(address + i)), nullptr);
            if (word == -1 && errno) return sys_error("PTRACE_PEEKDATA");
            const auto count = std::min(sizeof(word), size - i);
            std::memcpy(out.data() + i, &word, count);
            i += count;
        }
        return out;
    }
    Status write_memory_raw(std::uint64_t address, std::span<const std::byte> data) const {
        for (std::size_t i = 0; i < data.size();) {
            errno = 0;
            long word = ptrace(PTRACE_PEEKDATA, pid_,
                               reinterpret_cast<void*>(static_cast<std::uintptr_t>(address + i)), nullptr);
            if (word == -1 && errno) return sys_error("PTRACE_PEEKDATA before write");
            const auto count = std::min(sizeof(word), data.size() - i);
            std::memcpy(&word, data.data() + i, count);
            if (ptrace(PTRACE_POKEDATA, pid_, reinterpret_cast<void*>(static_cast<std::uintptr_t>(address + i)),
                       reinterpret_cast<void*>(word)) != 0)
                return sys_error("PTRACE_POKEDATA");
            i += count;
        }
        return std::monostate{};
    }
    Result<unsigned long> peek_debug_register(pid_t tid, unsigned index) const {
        errno = 0;
        const auto offset = offsetof(struct user, u_debugreg) + index * sizeof(unsigned long);
        const auto value = ptrace(PTRACE_PEEKUSER, tid, reinterpret_cast<void*>(offset), nullptr);
        if (value == -1 && errno) return sys_error("PTRACE_PEEKUSER debug register");
        return static_cast<unsigned long>(value);
    }
    Status poke_debug_register(pid_t tid, unsigned index, unsigned long value) const {
        const auto offset = offsetof(struct user, u_debugreg) + index * sizeof(unsigned long);
        if (ptrace(PTRACE_POKEUSER, tid, reinterpret_cast<void*>(offset), reinterpret_cast<void*>(value)) != 0)
            return sys_error("PTRACE_POKEUSER debug register");
        return std::monostate{};
    }
    std::vector<detail::HardwareRequest> hardware_requests(const std::vector<HardwareRecord>& records) const {
        std::vector<detail::HardwareRequest> requests;
        requests.reserve(records.size());
        for (const auto& record : records) if (record.enabled) requests.push_back({record.address, record.kind, record.size});
        return requests;
    }
    void rebuild_hardware_slots() {
        hardware_slots_.clear();
        hardware_slot_ids_.clear();
        for (const auto& record : hardware_breakpoints_) {
            if (!record.enabled) continue;
            hardware_slots_.push_back({record.address, record.kind, record.size});
            hardware_slot_ids_.push_back(record.id);
        }
    }
    std::uint64_t regs_address(pid_t tid) const {
        if (architecture_ == Architecture::x86) {
            auto regs = read_i386_registers(tid);
            return regs ? regs.value().eip : 0;
        }
        user_regs_struct regs{};
        return ptrace(PTRACE_GETREGS, tid, nullptr, &regs) == 0 ? regs.rip : 0;
    }
    Status install_hardware_on_thread(pid_t tid, const std::vector<HardwareRecord>& records,
                                      bool allow_unconfigured_thread = false) {
        detail::DebugRegisters desired;
        const auto requests = hardware_requests(records);
        const auto pointer_size = architecture_ == Architecture::x86 ? std::uint8_t{4} : std::uint8_t{8};
        if (!detail::encode_hardware_breakpoints(requests, pointer_size, desired))
            return Error{ErrorCode::invalid_argument, "invalid x86 hardware breakpoint configuration"};
        std::array<unsigned long, 4> prior{};
        for (unsigned slot = 0; slot < 4; ++slot) {
            auto value = peek_debug_register(tid, slot);
            if (!value) return value.error();
            prior[slot] = value.value();
        }
        auto old_dr7 = peek_debug_register(tid, 7);
        if (!old_dr7) return old_dr7.error();
        if (old_dr7.value() != 0 && !hardware_breakpoints_.empty()) {
            detail::DebugRegisters expected;
            (void)detail::encode_hardware_breakpoints(hardware_requests(hardware_breakpoints_), pointer_size, expected);
            if (old_dr7.value() != expected.dr7 || !std::equal(prior.begin(), prior.end(), expected.address.begin()))
                return Error{ErrorCode::conflict, "thread already uses hardware breakpoint registers outside this debugger"};
        } else if (old_dr7.value() != 0) {
            return Error{ErrorCode::conflict, "thread already uses hardware breakpoint registers outside this debugger"};
        } else {
            if (!hardware_breakpoints_.empty() && !allow_unconfigured_thread)
                return Error{ErrorCode::conflict, "thread hardware breakpoint registers changed outside this debugger"};
            if (std::any_of(prior.begin(), prior.end(), [](unsigned long value) { return value != 0; }))
                return Error{ErrorCode::conflict, "thread has inactive hardware breakpoint addresses owned by another debugger"};
        }
        std::vector<unsigned> changed;
        auto rollback = [&]() -> Status {
            Error first{ErrorCode::io, "hardware breakpoint rollback failed"}; bool failed = false;
            for (auto it = changed.rbegin(); it != changed.rend(); ++it) {
                auto restored = poke_debug_register(tid, *it, *it == 7 ? old_dr7.value() : prior[*it]);
                if (!restored && !failed) { first = restored.error(); failed = true; }
            }
            return failed ? Status{first} : Status{std::monostate{}};
        };
        for (unsigned slot = 0; slot < 4; ++slot) {
            auto result = poke_debug_register(tid, slot, static_cast<unsigned long>(desired.address[slot]));
            if (!result) {
                auto restored = rollback();
                if (!restored) return Error{result.error().code, result.error().message + "; " + restored.error().message};
                return result;
            }
            changed.push_back(slot);
        }
        auto dr7 = poke_debug_register(tid, 7, static_cast<unsigned long>(desired.dr7));
        if (!dr7) {
            auto restored = rollback();
            if (!restored) return Error{dr7.error().code, dr7.error().message + "; " + restored.error().message};
            return dr7;
        }
        changed.push_back(7);
        auto cleared = poke_debug_register(tid, 6, 0xffff0ff0UL);
        if (!cleared) {
            auto restored = rollback();
            if (!restored) return Error{cleared.error().code, cleared.error().message + "; " + restored.error().message};
        }
        return cleared;
    }
    Status apply_hardware_breakpoints(const std::vector<HardwareRecord>& records) {
        for (const auto tid : tracked_) {
            if (!stopped_.contains(tid))
                return Error{ErrorCode::busy, "all target threads must be stopped before changing hardware breakpoints"};
        }
        std::vector<std::pair<pid_t, std::array<unsigned long, 6>>> originals;
        originals.reserve(tracked_.size());
        auto rollback_prior = [&](std::size_t count) {
            std::string errors;
            while (count > 0) {
                const auto& [prior_tid, prior] = originals[--count];
                for (unsigned slot = 0; slot < 4; ++slot) {
                    auto restored = poke_debug_register(prior_tid, slot, prior[slot]);
                    if (!restored) { if (!errors.empty()) errors += "; "; errors += restored.error().message; }
                }
                auto dr7_restored = poke_debug_register(prior_tid, 7, prior[4]);
                auto dr6_restored = poke_debug_register(prior_tid, 6, prior[5]);
                if (!dr7_restored) { if (!errors.empty()) errors += "; "; errors += dr7_restored.error().message; }
                if (!dr6_restored) { if (!errors.empty()) errors += "; "; errors += dr6_restored.error().message; }
            }
            return errors;
        };
        for (const auto tid : tracked_) {
            std::array<unsigned long, 6> old{};
            for (unsigned slot = 0; slot < 4; ++slot) {
                auto value = peek_debug_register(tid, slot);
                if (!value) {
                    const auto rollback_errors = rollback_prior(originals.size());
                    if (!rollback_errors.empty()) return Error{value.error().code,
                        value.error().message + "; rollback was incomplete: " + rollback_errors};
                    return value.error();
                }
                old[slot] = value.value();
            }
            auto dr7 = peek_debug_register(tid, 7);
            if (!dr7) {
                const auto rollback_errors = rollback_prior(originals.size());
                if (!rollback_errors.empty()) return Error{dr7.error().code,
                    dr7.error().message + "; rollback was incomplete: " + rollback_errors};
                return dr7.error();
            }
            old[4] = dr7.value();
            auto dr6 = peek_debug_register(tid, 6);
            if (!dr6) {
                const auto rollback_errors = rollback_prior(originals.size());
                if (!rollback_errors.empty()) return Error{dr6.error().code,
                    dr6.error().message + "; rollback was incomplete: " + rollback_errors};
                return dr6.error();
            }
            old[5] = dr6.value();
            originals.push_back({tid, old});
            auto installed = install_hardware_on_thread(tid, records);
            if (!installed) {
                const auto rollback_errors = rollback_prior(originals.size() - 1);
                if (!rollback_errors.empty()) return Error{installed.error().code,
                    installed.error().message + "; rollback was incomplete: " + rollback_errors};
                return installed;
            }
        }
        return std::monostate{};
    }
    Status replace_software_breakpoint_byte(std::uint64_t address, std::byte expected,
                                            std::byte replacement) {
        auto current = read_memory_raw(address, 1);
        if (!current) return current.error();
        if (current.value().size() != 1 || current.value()[0] != expected)
            return Error{ErrorCode::conflict,
                         "software breakpoint byte changed outside this debugger; refusing to overwrite it"};
        if (expected == replacement) return std::monostate{};
        return write_memory_raw(address, std::span<const std::byte>(&replacement, 1));
    }
    Status rearm_software_breakpoint(std::uint64_t address) {
        const auto original = breakpoints_.find(address);
        if (original == breakpoints_.end())return Error{ErrorCode::conflict, "software breakpoint ownership disappeared during rearm"};
        auto current = read_memory_raw(address, 1); if (!current) return current.error();
        // A retry may observe the already rearmed trap. Only the exact saved
        // original or trap is owned; self-modified bytes are never overwritten.
        if (current.value()[0] == std::byte{0xcc}) return std::monostate{};
        return replace_software_breakpoint_byte(address, original->second, std::byte{0xcc});
    }
    Result<std::byte> detach_breakpoint_byte(std::uint64_t address, bool enabled) {
        const auto original = breakpoints_.at(address);
        const bool restored = detach_restored_breakpoints_.contains(address) || !enabled;
        const bool displaced = (displaced_step_ && displaced_step_->address == address) ||
            (breakpoint_rollback_ && breakpoint_rollback_->address == address) || breakpoint_rearm_ == address;
        auto current = read_memory_raw(address, 1); if (!current) return current.error();
        if (current.value()[0] != (restored ? original : std::byte{0xcc}) &&
            !(!restored && displaced && current.value()[0] == original))
            return Error{ErrorCode::conflict, "software breakpoint byte changed outside this debugger; detach retains stopped target ownership"};
        return current.value()[0];
    }
    void clear() { pending_debugger_trap_ = false; pending_signal_ = 0; pending_thread_interrupt_ = false; requested_thread_interrupt_.reset(); detach_signals_.clear(); detach_restored_breakpoints_.clear(); initial_children_.clear(); hardware_pending_children_.clear(); startup_cleanup_ = false; startup_kill_ = false; detaching_ = false; detach_hardware_cleared_ = false; detach_preparing_ = false; terminating_ = false; pid_ = 0; architecture_ = Architecture::unknown; launched_ = false; exited_ = false; pending_.reset(); initial_event_.reset(); pending_breakpoint_.reset(); stopped_.clear(); tracked_.clear(); seized_.clear(); step_threads_.clear(); displaced_step_.reset(); breakpoint_rollback_.reset(); breakpoint_rearm_.reset(); deferred_stops_.clear(); deferred_signals_.clear(); interrupting_.clear(); resume_blocked_ = false; breakpoints_.clear(); ids_.clear(); enabled_ids_.clear(); hardware_breakpoints_.clear(); hardware_slots_.clear(); hardware_slot_ids_.clear(); }
    pid_t pid_ = 0; bool launched_ = false; bool exited_ = false; std::uint64_t seq_ = 0; BreakpointId next_bp_ = 1;
    Architecture architecture_ = Architecture::unknown;
    unsigned last_signal_ = 0;
    int pending_signal_ = 0;
    std::optional<std::pair<std::uint64_t, pid_t>> pending_;
    std::optional<DebugEvent> initial_event_;
    std::optional<std::uint64_t> pending_breakpoint_;
    std::map<std::uint64_t, std::byte> breakpoints_;
    std::map<BreakpointId, std::uint64_t> ids_;
    std::set<BreakpointId> enabled_ids_;
    std::vector<HardwareRecord> hardware_breakpoints_;
    std::vector<detail::HardwareRequest> hardware_slots_;
    std::vector<BreakpointId> hardware_slot_ids_;
    std::mutex wait_gate_mutex_; std::set<pid_t> stopped_, tracked_, seized_, step_threads_;
    std::optional<pid_t> requested_thread_interrupt_;
    bool pending_thread_interrupt_ = false;
    std::optional<DisplacedStep> displaced_step_;
    std::optional<BreakpointRollback> breakpoint_rollback_;
    std::optional<std::uint64_t> breakpoint_rearm_;
    std::map<pid_t, int> deferred_stops_;
    std::map<pid_t, int> deferred_signals_;
    std::set<pid_t> interrupting_;
    bool resume_blocked_ = false, pending_debugger_trap_ = false;
    const std::chrono::milliseconds wait_timeout_ = configured_wait_timeout();
    std::optional<Clock::time_point> wait_deadline_;
    std::atomic<bool> wait_active_{false}, wait_stop_requested_{false};
    bool startup_cleanup_ = false, startup_kill_ = false, detaching_ = false, detach_hardware_cleared_ = false, event_polling_ = false, terminating_ = false, cleanup_wait_ = false, detach_preparing_ = false;
    std::set<pid_t> initial_children_, hardware_pending_children_;
    std::map<pid_t, int> detach_signals_;
    std::set<std::uint64_t> detach_restored_breakpoints_;
};
}

std::unique_ptr<Backend> make_native_backend() { return std::make_unique<LinuxPtraceBackend>(); }
} // namespace hexlab::debugger
