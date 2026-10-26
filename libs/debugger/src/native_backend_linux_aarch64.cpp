#include "hexlab/debugger/debugger.hpp"
#include "elf_process_architecture.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <signal.h>
#include <string>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

#if !defined(__aarch64__)
#error "The Linux AArch64 ptrace backend must be built for an AArch64 host"
#endif
static_assert(std::endian::native == std::endian::little,
    "The Linux AArch64 debugger supports little-endian hosts and tracees only");
static_assert(sizeof(void*) == 8 && sizeof(long) == 8,
    "The Linux AArch64 debugger requires an LP64 tracer");

namespace hexlab::debugger {
namespace {
constexpr unsigned long nt_prstatus = 1;
constexpr unsigned long nt_fpregset = 2;
// Linux arm64 UAPI notes in <linux/elf.h>. Keep local values so old userspace
// headers still build the backend while the kernel remains the capability
// authority through GETREGSET.
constexpr unsigned long nt_arm_hw_break = 0x402;
constexpr unsigned long nt_arm_hw_watch = 0x403;
constexpr unsigned long nt_arm_sve = 0x405;
constexpr std::size_t aarch64_reg_count = 34; // x0-x30, sp, pc, pstate
constexpr std::size_t aarch64_hwdebug_max_slots = 16;
constexpr std::size_t aarch64_sve_max_vl = 8192; // Linux UAPI __SVE_VL_MAX (512 quadwords).
constexpr std::size_t aarch64_sve_max_regset_size = 512 * 1024;
struct Aarch64HwdebugRegister {
    std::uint64_t address{};
    std::uint32_t control{};
    std::uint32_t pad{};
};
struct Aarch64HwdebugState {
    std::uint32_t info{};
    std::uint32_t pad{};
    std::array<Aarch64HwdebugRegister, aarch64_hwdebug_max_slots> registers{};
};
static_assert(offsetof(Aarch64HwdebugState, registers) == 8);
static_assert(sizeof(Aarch64HwdebugState) == 8 + 16 * 16);
struct Aarch64HardwareBreakpoint {
    BreakpointId id{};
    std::uint64_t address{};
    BreakpointKind kind{};
    std::uint8_t size{};
    std::uint8_t slot{};
    bool enabled{true};
};
struct Aarch64HardwareStepState {
    pid_t thread{};
    Aarch64HwdebugState saved{};
    std::size_t slots{};
};
constexpr std::array<const char*, aarch64_reg_count> names = {
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
    "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20",
    "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
    "sp", "pc", "pstate"};
struct Aarch64Regs { std::uint64_t value[aarch64_reg_count]{}; };
// Linux arm64 UAPI user_fpsimd_state: NT_FPREGSET exposes this fixed legacy
// FPSIMD image even when the task also has a larger SVE vector length.
struct alignas(16) Aarch64FpsimdRegs {
    std::array<std::array<std::byte, 16>, 32> vregs{};
    std::uint32_t fpsr{};
    std::uint32_t fpcr{};
    std::uint32_t reserved[2]{};
};
static_assert(sizeof(Aarch64FpsimdRegs) == 528);

Error sys_error(const char* action) {
    return {ErrorCode::io, std::string(action) + " failed: " + std::strerror(errno)};
}
bool parse_pid(std::string_view text, pid_t& pid) {
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), pid);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && pid > 0;
}
bool parse_hex(std::string_view text, std::uint64_t& value) {
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}
Result<std::vector<MemoryRegion>> read_proc_mappings(pid_t pid) {
    std::ifstream input("/proc/" + std::to_string(pid) + "/maps");
    if (!input) return Error{ErrorCode::io, "failed to read target memory mappings"};
    std::vector<MemoryRegion> out;
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
        std::string type = fields[1][3] == 's' ? "shared" : "private";
        if (path_start != std::string_view::npos) type += ":" + std::string(remaining.substr(path_start));
        out.push_back({start, end - start, fields[1][0] == 'r', fields[1][1] == 'w', fields[1][2] == 'x', std::move(type)});
        if (out.size() > max_inspection_memory_regions)
            return Error{ErrorCode::resource_limit, "target exposes more than 65536 memory regions"};
    }
    if (input.bad()) return Error{ErrorCode::io, "failed while reading target memory mappings"};
    return out;
}
std::string proc_name(pid_t pid) {
    std::ifstream in("/proc/" + std::to_string(pid) + "/comm");
    std::string name; std::getline(in, name); return name;
}
Architecture proc_architecture(pid_t pid) {
    std::ifstream image("/proc/" + std::to_string(pid) + "/exe", std::ios::binary);
    std::array<std::byte, 20> header{};
    if (!image.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size())))
        return Architecture::unknown;
    return detail::elf_process_architecture(header);
}
Result<Aarch64Regs> get_regs(pid_t tid) {
    Aarch64Regs regs{}; iovec io{&regs, sizeof(regs)};
    if (ptrace(PTRACE_GETREGSET, tid, reinterpret_cast<void*>(nt_prstatus), &io) != 0)
        return sys_error("PTRACE_GETREGSET NT_PRSTATUS");
    if (io.iov_len != sizeof(regs)) return Error{ErrorCode::malformed, "AArch64 NT_PRSTATUS regset has an unexpected size"};
    return regs;
}
Status set_regs(pid_t tid, const Aarch64Regs& regs) {
    iovec io{const_cast<Aarch64Regs*>(&regs), sizeof(regs)};
    if (ptrace(PTRACE_SETREGSET, tid, reinterpret_cast<void*>(nt_prstatus), &io) != 0)
        return sys_error("PTRACE_SETREGSET NT_PRSTATUS");
    return std::monostate{};
}
Result<Aarch64FpsimdRegs> get_fpsimd_regs(pid_t tid) {
    Aarch64FpsimdRegs regs{}; iovec io{&regs, sizeof(regs)};
    if (ptrace(PTRACE_GETREGSET, tid, reinterpret_cast<void*>(nt_fpregset), &io) != 0) {
        const int error = errno;
        if (error == EINVAL || error == EIO || error == ENODEV || error == ENOSYS)
            return Error{ErrorCode::unsupported, "Linux AArch64 NT_FPREGSET FPSIMD state is unavailable"};
        errno = error;
        return sys_error("PTRACE_GETREGSET NT_FPREGSET");
    }
    if (io.iov_len != sizeof(regs)) return Error{ErrorCode::malformed, "AArch64 NT_FPREGSET regset has an unexpected size"};
    return regs;
}
Status set_fpsimd_regs(pid_t tid, const Aarch64FpsimdRegs& regs) {
    iovec io{const_cast<Aarch64FpsimdRegs*>(&regs), sizeof(regs)};
    if (ptrace(PTRACE_SETREGSET, tid, reinterpret_cast<void*>(nt_fpregset), &io) != 0) {
        const int error = errno;
        if (error == EINVAL || error == EIO || error == ENODEV || error == ENOSYS)
            return Error{ErrorCode::unsupported, "Linux AArch64 NT_FPREGSET FPSIMD state is unavailable"};
        errno = error;
        return sys_error("PTRACE_SETREGSET NT_FPREGSET");
    }
    return std::monostate{};
}
constexpr std::array<const char*, 32> fpsimd_names = {
    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11",
    "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
    "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"};

struct Aarch64SveHeader {
    std::uint32_t size{};
    std::uint32_t max_size{};
    std::uint16_t vl{};
    std::uint16_t max_vl{};
    std::uint16_t flags{};
    std::uint16_t reserved{};
};
static_assert(sizeof(Aarch64SveHeader) == 16);
constexpr std::uint16_t sve_regs_mask = 1u;
constexpr std::uint16_t sve_regs_fpsimd = 0u;
constexpr std::uint16_t sve_regs_sve = sve_regs_mask;
constexpr std::uint16_t sve_vl_inherit = 2u;
constexpr std::uint16_t sve_vl_onexec = 4u;

struct Aarch64SveState {
    Aarch64SveHeader header{};
    std::vector<std::byte> bytes;
    bool has_sve_registers = false;
};

bool valid_sve_vl(std::uint16_t vl) {
    return vl >= 16 && vl <= aarch64_sve_max_vl && vl % 16 == 0;
}

std::size_t align_sve(std::size_t value) { return (value + 15u) & ~std::size_t{15u}; }

struct Aarch64SveLayout {
    std::size_t z_offset{};
    std::size_t p_offset{};
    std::size_t ffr_offset{};
    std::size_t fpsr_offset{};
    std::size_t fpcr_offset{};
    std::size_t minimum_size{};
};

Result<Aarch64SveLayout> sve_layout(std::uint16_t vl) {
    if (!valid_sve_vl(vl)) return Error{ErrorCode::malformed, "Linux AArch64 SVE header has an invalid vector length"};
    const auto z_bytes = std::size_t{32} * vl;
    const auto predicate_bytes = static_cast<std::size_t>(vl) / 8;
    Aarch64SveLayout layout;
    layout.z_offset = sizeof(Aarch64SveHeader);
    layout.p_offset = layout.z_offset + z_bytes;
    layout.ffr_offset = layout.p_offset + 16 * predicate_bytes;
    layout.fpsr_offset = align_sve(layout.ffr_offset + predicate_bytes);
    layout.fpcr_offset = layout.fpsr_offset + sizeof(std::uint32_t);
    layout.minimum_size = align_sve(layout.fpcr_offset + sizeof(std::uint32_t));
    if (layout.minimum_size > aarch64_sve_max_regset_size)
        return Error{ErrorCode::resource_limit, "Linux AArch64 SVE state exceeds the debugger allocation limit"};
    return layout;
}

Result<Aarch64SveState> get_sve_state(pid_t tid) {
    Aarch64SveHeader header{};
    iovec header_io{&header, sizeof(header)};
    if (ptrace(PTRACE_GETREGSET, tid, reinterpret_cast<void*>(nt_arm_sve), &header_io) != 0) {
        const int error = errno;
        if (error == EINVAL || error == EIO || error == ENODEV || error == ENOSYS)
            return Error{ErrorCode::unsupported, "Linux AArch64 NT_ARM_SVE state is unavailable"};
        errno = error;
        return sys_error("PTRACE_GETREGSET NT_ARM_SVE header");
    }
    if (header_io.iov_len != sizeof(header))
        return Error{ErrorCode::malformed, "Linux AArch64 NT_ARM_SVE header has an unexpected size"};
    constexpr std::uint16_t known_flags = sve_regs_mask | sve_vl_inherit | sve_vl_onexec;
    if (header.reserved != 0 || (header.flags & ~known_flags) != 0 ||
        (header.flags & sve_regs_mask) > sve_regs_sve || !valid_sve_vl(header.max_vl) ||
        !valid_sve_vl(header.vl) || header.vl > header.max_vl ||
        header.size < sizeof(header) || header.max_size < header.size ||
        header.max_size > aarch64_sve_max_regset_size)
        return Error{ErrorCode::malformed, "Linux AArch64 NT_ARM_SVE header exceeds validated bounds"};

    Aarch64SveState state;
    state.header = header;
    state.has_sve_registers = (header.flags & sve_regs_mask) == sve_regs_sve;
    if (header.size == sizeof(header)) {
        // The kernel exposes a header-only NT_ARM_SVE view while another vector
        // mode (notably SME streaming mode) owns the live state. Do not silently
        // substitute the FPSIMD alias and lose that state.
        if (state.has_sve_registers)
            return Error{ErrorCode::malformed, "Linux AArch64 NT_ARM_SVE marks registers active but supplies no payload"};
        return state;
    }
    if (header.size > aarch64_sve_max_regset_size)
        return Error{ErrorCode::resource_limit, "Linux AArch64 NT_ARM_SVE payload exceeds the debugger allocation limit"};
    const auto mode = header.flags & sve_regs_mask;
    std::size_t minimum_size = 0;
    if (mode == sve_regs_sve) {
        auto layout = sve_layout(header.vl); if (!layout) return layout.error();
        minimum_size = layout.value().minimum_size;
    } else if (mode == sve_regs_fpsimd) {
        minimum_size = sizeof(Aarch64SveHeader) + sizeof(Aarch64FpsimdRegs);
    } else {
        return Error{ErrorCode::unsupported, "Linux AArch64 NT_ARM_SVE reports an unknown register format"};
    }
    if (header.size < minimum_size || header.max_size < minimum_size)
        return Error{ErrorCode::malformed, "Linux AArch64 NT_ARM_SVE payload is shorter than its UAPI register layout"};
    state.bytes.resize(header.size);
    iovec io{state.bytes.data(), state.bytes.size()};
    if (ptrace(PTRACE_GETREGSET, tid, reinterpret_cast<void*>(nt_arm_sve), &io) != 0) {
        const int error = errno;
        if (error == EINVAL || error == EIO || error == ENODEV || error == ENOSYS)
            return Error{ErrorCode::unsupported, "Linux AArch64 NT_ARM_SVE state became unavailable"};
        errno = error;
        return sys_error("PTRACE_GETREGSET NT_ARM_SVE payload");
    }
    if (io.iov_len != header.size)
        return Error{ErrorCode::malformed, "Linux AArch64 NT_ARM_SVE payload was truncated"};
    Aarch64SveHeader received{};
    std::memcpy(&received, state.bytes.data(), sizeof(received));
    if (std::memcmp(&received, &header, sizeof(header)) != 0)
        return Error{ErrorCode::busy, "Linux AArch64 NT_ARM_SVE header changed while reading stopped thread state"};
    return state;
}

Status set_sve_state(pid_t tid, const Aarch64SveState& state) {
    if (state.bytes.empty() || state.bytes.size() != state.header.size ||
        state.bytes.size() > aarch64_sve_max_regset_size)
        return Error{ErrorCode::malformed, "refusing to write incomplete Linux AArch64 NT_ARM_SVE state"};
    iovec io{const_cast<std::byte*>(state.bytes.data()), state.bytes.size()};
    if (ptrace(PTRACE_SETREGSET, tid, reinterpret_cast<void*>(nt_arm_sve), &io) != 0) {
        const int error = errno;
        if (error == EINVAL || error == EIO || error == ENODEV || error == ENOSYS)
            return Error{ErrorCode::unsupported, "Linux AArch64 NT_ARM_SVE state cannot be written"};
        errno = error;
        return sys_error("PTRACE_SETREGSET NT_ARM_SVE");
    }
    return std::monostate{};
}
}

class LinuxAarch64Backend final : public Backend {
    using Clock = std::chrono::steady_clock;
    // A nested rollback/suspension shares its caller's deadline. EINTR and
    // additional TIDs never restart the timeout.
    struct WaitScope {
        LinuxAarch64Backend &backend;
        bool owner;
        explicit WaitScope(LinuxAarch64Backend &value, std::optional<std::chrono::milliseconds> timeout = {})
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
    struct EventPollScope {
        bool &flag;
        explicit EventPollScope(bool &value) : flag(value) { flag = true; }
        ~EventPollScope() { flag = false; }
    };
public:
    ~LinuxAarch64Backend() override { (void)detach(); }

    Result<std::vector<ProcessInfo>> processes() override {
        std::vector<ProcessInfo> out; std::error_code ec;
        for (std::filesystem::directory_iterator it("/proc", ec), end; !ec && it != end; it.increment(ec)) {
            pid_t id{}; const auto leaf = it->path().filename().string();
            if (!parse_pid(leaf, id)) continue;
            auto name = proc_name(id); if (name.empty()) continue;
            if (out.size() >= max_inspection_processes) return Error{ErrorCode::resource_limit, "system process count exceeds the inspection limit"};
            out.push_back({static_cast<ProcessId>(id), std::move(name), proc_architecture(id)});
        }
        if (ec) return Error{ErrorCode::io, "failed to enumerate /proc: " + ec.message()};
        return out;
    }

    Result<ProcessInfo> launch(const Target& target) override {
        WaitScope scope(*this);
        if (startup_cleanup_) { auto cleanup = cleanup_startup(); if (!cleanup) return cleanup.error(); }
        if (pid_) return Error{ErrorCode::busy, "backend already owns a debug target"};
        if (target.executable.empty()) return Error{ErrorCode::invalid_argument, "executable path is empty"};
        int gate[2]{};
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, gate) != 0) return sys_error("socketpair for ptrace launch");
        std::vector<char*> argv; argv.reserve(target.arguments.size() + 2);
        argv.push_back(const_cast<char*>(target.executable.c_str()));
        for (const auto& arg : target.arguments) argv.push_back(const_cast<char*>(arg.c_str()));
        argv.push_back(nullptr);
        const pid_t child = fork();
        if (child < 0) { const auto error = sys_error("fork"); close(gate[0]); close(gate[1]); return error; }
        if (child == 0) {
            close(gate[1]);
            char release{}; ssize_t count;
            do { count = read(gate[0], &release, 1); } while (count < 0 && errno == EINTR);
            close(gate[0]);
            if (count != 1 || release != 'G') _exit(126);
            if (!target.working_directory.empty() && chdir(target.working_directory.c_str()) != 0) _exit(126);
            execv(target.executable.c_str(), argv.data()); _exit(127);
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
        if (arch != Architecture::arm64) return fail_launch(Error{ErrorCode::unsupported, "AArch64 ptrace backend only supports AArch64 ELF targets"});
        startup_cleanup_ = false; startup_kill_ = false; last_signal_ = SIGTRAP;
        initial_ = true; seq_ = 0;
        return ProcessInfo{static_cast<ProcessId>(child), target.executable, arch};
    }

    Result<ProcessInfo> attach(ProcessId id) override {
        WaitScope scope(*this);
        if (startup_cleanup_) { auto cleanup = cleanup_startup(); if (!cleanup) return cleanup.error(); }
        if (pid_) return Error{ErrorCode::busy, "backend already owns a debug target"};
        if (!id || id > static_cast<ProcessId>(std::numeric_limits<pid_t>::max())) return Error{ErrorCode::invalid_argument, "invalid process id"};
        const auto pid = static_cast<pid_t>(id);
        if (proc_architecture(pid) != Architecture::arm64) return Error{ErrorCode::unsupported, "AArch64 ptrace backend only supports AArch64 ELF targets"};
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
                if (!(event == PTRACE_EVENT_STOP && WSTOPSIG(status.value()) == SIGTRAP)) deferred_[tid] = status.value();
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
        for (const auto tid : stopped_) {
            auto progress = wait_progress(); if (!progress) return fail_attach(progress.error());
            if (ptrace(PTRACE_SETOPTIONS, tid, nullptr, reinterpret_cast<void*>(PTRACE_O_TRACECLONE)) != 0)
                return fail_attach(sys_error("PTRACE_SETOPTIONS after attach"));
        }
        startup_cleanup_ = false; last_signal_ = SIGSTOP; initial_ = true; seq_ = 0;
        return ProcessInfo{id, proc_name(pid), Architecture::arm64};
    }

    Status detach() override {
        WaitScope scope(*this);
        if (startup_cleanup_) return cleanup_startup();
        if (!pid_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        if (!detaching_) {
            auto stopped = stop_all_threads(); if (!stopped) return stopped;
            auto ownership = require_all_threads_stopped(); if (!ownership) return ownership;
            auto step_restored = restore_hardware_execute_step(); if (!step_restored) return step_restored;
            if (!hardware_breakpoints_.empty() && !detach_hardware_cleared_) {
                auto cleared = apply_hardware_configuration({}, hardware_breakpoints_);
                if (!cleared) return cleared;
                detach_hardware_cleared_ = true;
            }
            for (const auto& [address, original] : breakpoints_) { (void)original; if (enabled_.contains(address) && !write_raw(address, original_instruction(address))) return sys_error("restore software breakpoint"); }
            detaching_ = true;
        }
        const std::vector<pid_t> detach_census(stopped_.begin(), stopped_.end());
        for (const auto tid : detach_census) {
            auto progress = wait_progress(); if (!progress) return progress;
            int signal = 0;
            const auto deferred = deferred_.find(tid);
            if (deferred != deferred_.end() && WIFSTOPPED(deferred->second) &&
                (static_cast<unsigned>(deferred->second) >> 16) == 0)
                signal = WSTOPSIG(deferred->second);
            else if (pending_ && pending_thread_ == tid && pending_signal_ != 0 && !pending_breakpoint_ && !pending_hardware_execute_)
                signal = pending_signal_;
            else if (const auto deferred_signal = deferred_signals_.find(tid); deferred_signal != deferred_signals_.end())
                signal = deferred_signal->second;
            if (signal == SIGTRAP) {
                siginfo_t info{};
                const bool have_info = ptrace(PTRACE_GETSIGINFO, tid, nullptr, &info) == 0;
                if (have_info && info.si_code == TRAP_TRACE) signal = 0;
                auto regs = get_regs(tid);
                if (regs && enabled_.contains(regs.value().value[32])) signal = 0;
                if (have_info && info.si_code == TRAP_HWBKPT && std::any_of(hardware_breakpoints_.begin(), hardware_breakpoints_.end(), [&](const auto &bp) {
                    const auto access = reinterpret_cast<std::uintptr_t>(info.si_addr);
                    return bp.enabled && (hardware_execute_kind(bp.kind) ? regs && regs.value().value[32] == bp.address
                        : access >= bp.address && access - bp.address < bp.size);
                })) signal = 0;
            }
            if (ptrace(PTRACE_DETACH, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(signal))) != 0 && errno != ESRCH) return sys_error("PTRACE_DETACH");
            forget_thread(tid);
        }
        clear(); return std::monostate{};
    }
    Status terminate() override {
        WaitScope scope(*this);
        if (startup_cleanup_) return cleanup_startup();
        if (!pid_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        if (kill(pid_, SIGKILL) != 0 && errno != ESRCH) return sys_error("SIGKILL target");
        const std::vector<pid_t> census(tracked_.begin(), tracked_.end());
        for (const auto tid : census) {
            for (;;) {
                if (stopped_.contains(tid)) {
                    auto progress = wait_progress(); if (!progress) return progress;
                    if (ptrace(PTRACE_CONT, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(SIGKILL))) != 0 && errno != ESRCH)
                        return sys_error("PTRACE_CONT SIGKILL");
                    stopped_.erase(tid); deferred_.erase(tid);
                }
                auto status = wait_status(tid);
                if (!status) {
                    if (status.error().code == ErrorCode::out_of_bounds) { forget_thread(tid); break; }
                    return status.error();
                }
                if (WIFEXITED(status.value()) || WIFSIGNALED(status.value())) { forget_thread(tid); break; }
                if (!WIFSTOPPED(status.value())) return Error{ErrorCode::io, "target thread did not exit after SIGKILL"};
                stopped_.insert(tid); deferred_[tid] = status.value();
                auto progress = wait_progress(); if (!progress) return progress;
                if (ptrace(PTRACE_CONT, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(SIGKILL))) != 0 && errno != ESRCH)
                    return sys_error("PTRACE_CONT SIGKILL");
                stopped_.erase(tid); deferred_.erase(tid);
            }
        }
        clear(); return std::monostate{};
    }
    Status request_interrupt() override {
        // The active poller owns the mutable ptrace state. Cancellation may be
        // requested concurrently without walking its thread sets.
        if (wait_active_.load()) { wait_stop_requested_.store(true); return std::monostate{}; }
        return interrupt_running_threads(false);
    }
    Result<DebugEvent> wait_event(std::chrono::milliseconds timeout) override {
        WaitScope scope(*this, timeout);
        EventPollScope event_scope(event_polling_);
        if (!pid_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        if (pending_) return Error{ErrorCode::busy, "previous debug event has not been continued"};
        if (initial_) { initial_ = false; DebugEvent e{++seq_, EventKind::breakpoint, static_cast<ProcessId>(pid_), static_cast<ThreadId>(pid_), 0, "exec or attach stop", static_cast<std::uint32_t>(last_signal_)}; pending_ = e.sequence; pending_thread_ = pid_; pending_signal_ = 0; return e; }
        const std::vector<pid_t> waiting_children(initial_children_.begin(), initial_children_.end());
        for (const auto child : waiting_children) { auto ready = finish_cloned_thread(child); if (!ready) return ready.error(); }
        do {
            pid_t tid = 0; int status{};
            if (!deferred_.empty()) { const auto it = deferred_.begin(); tid = it->first; status = it->second; deferred_.erase(it); }
            else for (const auto candidate : tracked_) {
                const auto waited = waitpid(candidate, &status, WNOHANG | __WALL);
                if (waited == candidate) { tid = candidate; break; }
                if (waited < 0 && errno != EINTR && errno != ECHILD && errno != ESRCH) return sys_error("waitpid");
            }
            if (tid > 0) {
                DebugEvent e{}; e.sequence = ++seq_; e.process = static_cast<ProcessId>(pid_); e.thread = static_cast<ThreadId>(tid);
                bool hardware_trap = false;
                bool hardware_step_restore_failed = false;
                if (WIFEXITED(status) || WIFSIGNALED(status)) {
                    pending_signal_ = 0;
                    if (hardware_step_state_ && hardware_step_state_->thread == tid) {
                        hardware_step_state_.reset(); step_pending_ = false; step_thread_ = 0;
                    }
                    if (pending_hardware_execute_ && pending_thread_ == tid) pending_hardware_execute_ = false;
                    tracked_.erase(tid); stopped_.erase(tid); seized_.erase(tid); interrupting_.erase(tid);
                    e.kind = tid == pid_ ? EventKind::process_exited : EventKind::thread_exited;
                    e.code = static_cast<std::uint32_t>(WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
                    e.message = tid == pid_ ? "process exited" : "thread exited";
                    if (tid == pid_) exited_ = true;
                } else if (WIFSTOPPED(status)) {
                    stopped_.insert(tid); interrupting_.erase(tid); last_signal_ = WSTOPSIG(status); const auto ptrace_event = static_cast<unsigned>(status) >> 16;
                    pending_signal_ = ptrace_event == 0 ? last_signal_ : 0;
                    if (ptrace_event == PTRACE_EVENT_CLONE) {
                        deferred_[tid] = status;
                        auto child = track_cloned_thread(tid); if (!child) return child.error();
                        deferred_.erase(tid);
                        e.kind = EventKind::thread_created; e.message = "thread created";
                        if (!hardware_configuration_error_.empty()) {
                            e.message += "; " + hardware_configuration_error_;
                            hardware_configuration_error_.clear();
                        }
                    } else {
                        auto regs = get_regs(tid); const auto pc = regs ? regs.value().value[32] : 0;
                        e.address = pc; e.code = static_cast<std::uint32_t>(last_signal_); e.message = "ptrace stop";
                        e.kind = last_signal_ == SIGTRAP && ptrace_event != PTRACE_EVENT_STOP ? EventKind::breakpoint : EventKind::exception;
                        if (ptrace_event == PTRACE_EVENT_STOP) e.message = "interrupt stop";
                        if (last_signal_ == SIGTRAP && ptrace_event == 0) {
                            siginfo_t info{};
                            if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &info) == 0 && info.si_code == TRAP_HWBKPT) {
                                hardware_trap = true;
                                const auto access = reinterpret_cast<std::uintptr_t>(info.si_addr);
                                bool matched_execute = false;
                                std::vector<BreakpointId> watch_candidates;
                                for (const auto& bp : hardware_breakpoints_) {
                                    if (!bp.enabled) continue;
                                    if (hardware_execute_kind(bp.kind) && bp.address == pc) {
                                        e.breakpoint_ids.push_back(bp.id);
                                        matched_execute = true;
                                    } else if (!hardware_execute_kind(bp.kind) &&
                                               access >= bp.address && access - bp.address < bp.size) {
                                        watch_candidates.push_back(bp.id);
                                    }
                                }
                                if (matched_execute) {
                                    e.kind = EventKind::breakpoint; e.message = "AArch64 hardware execute breakpoint hit";
                                    pending_hardware_execute_ = true;
                                    pending_hardware_execute_address_ = pc;
                                }
                                else if (watch_candidates.size() == 1) {
                                    e.breakpoint_ids.push_back(watch_candidates.front());
                                    e.kind = EventKind::breakpoint; e.message = "AArch64 hardware watchpoint hit";
                                } else if (!watch_candidates.empty()) {
                                    e.kind = EventKind::breakpoint;
                                    e.message = "AArch64 hardware watchpoint hit; overlapping read/write slots prevent exact ID attribution";
                                }
                                else { e.kind = EventKind::exception; e.message = "unmatched AArch64 hardware debug exception"; }
                            }
                        }
                        if (hardware_step_state_ && hardware_step_state_->thread == tid) {
                            auto restored = restore_hardware_execute_step();
                            if (!restored) {
                                e.kind = EventKind::exception;
                                e.message += "; failed to restore AArch64 execute-breakpoint state: " + restored.error().message;
                                hardware_step_restore_failed = true;
                            }
                        }
                        if (step_breakpoint_ && step_thread_ == tid) {
                            constexpr std::array<std::byte, 4> brk{std::byte{0x00}, std::byte{0x00}, std::byte{0x20}, std::byte{0xd4}};
                            if (enabled_.contains(*step_breakpoint_) && !write_raw(*step_breakpoint_, brk)) return sys_error("reinsert BRK after displaced instruction");
                            step_breakpoint_.reset(); step_thread_ = 0; step_pending_ = false;
                            if (last_signal_ == SIGTRAP && !hardware_trap) e.kind = EventKind::single_step;
                        } else if (step_pending_ && step_thread_ == tid) {
                            step_pending_ = false; step_thread_ = 0;
                            if (last_signal_ == SIGTRAP && !hardware_trap && !hardware_step_restore_failed)
                                e.kind = EventKind::single_step;
                        }
                        else if (last_signal_ == SIGTRAP && breakpoints_.contains(pc) && enabled_.contains(pc)) pending_breakpoint_ = pc;
                    }
                    if (ptrace_event == PTRACE_EVENT_CLONE && hardware_step_state_ && hardware_step_state_->thread == tid) {
                        auto restored = restore_hardware_execute_step();
                        if (!restored)
                            e.message += "; failed to restore AArch64 execute-breakpoint state: " + restored.error().message;
                        step_pending_ = false; step_thread_ = 0;
                    }
                }
                if (e.kind != EventKind::process_exited) {
                    auto stopped = stop_all_threads();
                    if (!stopped) e.message += "; peer suspension incomplete: " + stopped.error().message;
                }
                if (!hardware_configuration_error_.empty()) {
                    e.message += "; " + hardware_configuration_error_;
                    hardware_configuration_error_.clear();
                }
                pending_ = e.sequence; pending_thread_ = tid; return e;
            }
            auto progress = wait_progress(); if (!progress) return progress.error();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        } while (wait_deadline_ && Clock::now() < *wait_deadline_);
        return Error{ErrorCode::busy, "debug event wait timed out"};
    }
    Status continue_event(std::uint64_t sequence, ContinueStatus disposition) override {
        WaitScope scope(*this);
        if (!pending_ || *pending_ != sequence) return Error{ErrorCode::invalid_argument, "event sequence does not match pending event"};
        auto rollback = recover_resume_rollback(); if (!rollback) return rollback;
        if (exited_) { clear(); return std::monostate{}; }
        auto configured = ensure_hardware_breakpoints_configured(); if (!configured) return configured;
        auto safe = require_all_threads_stopped(); if (!safe) return safe;
        const auto tid = pending_thread_;
        if (pending_breakpoint_ && disposition == ContinueStatus::handled) {
            auto stepped = begin_breakpoint_step(tid, *pending_breakpoint_); if (!stepped) return stepped;
            pending_.reset(); pending_thread_ = 0; pending_signal_ = 0; pending_breakpoint_.reset(); return std::monostate{};
        }
        if (pending_hardware_execute_ && disposition == ContinueStatus::handled) {
            auto stepped = begin_hardware_execute_step(tid, pending_hardware_execute_address_);
            if (!stepped) return stepped;
            pending_.reset(); pending_thread_ = 0; pending_signal_ = 0; pending_hardware_execute_ = false;
            return std::monostate{};
        }
        const int signal = disposition == ContinueStatus::handled ? 0 : pending_signal_;
        auto resumed = resume_stopped_threads(tid, signal); if (!resumed) return resumed;
        pending_.reset(); pending_thread_ = 0; pending_signal_ = 0; pending_breakpoint_.reset(); pending_hardware_execute_ = false; return std::monostate{};
    }
    Status continue_thread_event(std::uint64_t sequence, ThreadId thread, ContinueStatus disposition) override {
        WaitScope scope(*this);
        if (!pending_ || *pending_ != sequence) return Error{ErrorCode::invalid_argument, "event sequence does not match pending event"};
        auto rollback = recover_resume_rollback(); if (!rollback) return rollback;
        if (thread != static_cast<ThreadId>(pending_thread_) || !tracked_.contains(pending_thread_))
            return Error{ErrorCode::invalid_argument, "selected thread does not own the pending stop event"};
        if (exited_) return Error{ErrorCode::busy, "the process exit event cannot resume a thread"};
        auto configured = ensure_hardware_breakpoints_configured(); if (!configured) return configured;
        if (pending_breakpoint_ && disposition == ContinueStatus::handled) {
            auto stepped = begin_breakpoint_step(pending_thread_, *pending_breakpoint_); if (!stepped) return stepped;
        } else if (pending_hardware_execute_ && disposition == ContinueStatus::handled) {
            auto stepped = begin_hardware_execute_step(pending_thread_, pending_hardware_execute_address_);
            if (!stepped) return stepped;
        } else {
            const int signal = disposition == ContinueStatus::handled ? 0 : pending_signal_;
            if (ptrace(PTRACE_CONT, pending_thread_, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(signal))) != 0) return sys_error("PTRACE_CONT selected thread");
            stopped_.erase(pending_thread_);
        }
        pending_.reset(); pending_thread_ = 0; pending_signal_ = 0; pending_breakpoint_.reset(); pending_hardware_execute_ = false; return std::monostate{};
    }
    Status resume_threads_event(std::uint64_t sequence, std::span<const ThreadResumeAction> actions) override {
        WaitScope scope(*this);
        if (!pending_ || *pending_ != sequence)
            return Error{ErrorCode::invalid_argument, "event sequence does not match pending event"};
        if (exited_) return Error{ErrorCode::busy, "the process exit event cannot resume a thread"};
        if (actions.empty() || actions.size() > max_inspection_threads)
            return Error{ErrorCode::invalid_argument, "thread resume schedule must contain 1 to 4096 actions"};
        auto rollback_state = recover_resume_rollback(); if (!rollback_state) return rollback_state;
        auto safe = require_all_threads_stopped(); if (!safe) return safe;
        const auto owner = pending_thread_;
        if (owner <= 0 || !tracked_.contains(owner) || !stopped_.contains(owner))
            return Error{ErrorCode::invalid_argument, "pending event owner is not a stopped thread owned by this session"};
        std::set<pid_t> selected;
        std::vector<const ThreadResumeAction*> runnable;
        const auto signal_for = [&](const ThreadResumeAction& action) {
            const auto tid = static_cast<pid_t>(action.thread);
            if (tid == owner && pending_signal_ != 0) return pending_signal_;
            const auto queued = deferred_signals_.find(tid);
            return queued == deferred_signals_.end() ? 0 : queued->second;
        };
        for (const auto &action : actions) {
            if (!action.thread || action.thread > static_cast<ThreadId>(std::numeric_limits<pid_t>::max()))
                return Error{ErrorCode::invalid_argument, "resume schedule contains an invalid thread ID"};
            if (action.kind != ThreadResumeKind::continue_execution && action.kind != ThreadResumeKind::single_step &&
                action.kind != ThreadResumeKind::stop)
                return Error{ErrorCode::invalid_argument, "resume schedule contains an unknown action"};
            const auto tid = static_cast<pid_t>(action.thread);
            if (!selected.insert(tid).second)
                return Error{ErrorCode::invalid_argument, "resume schedule contains a duplicate thread"};
            if (!tracked_.contains(tid) || !stopped_.contains(tid))
                return Error{ErrorCode::invalid_argument, "resume schedule thread is not stopped by this session"};
            if (action.kind != ThreadResumeKind::stop && deferred_.contains(tid))
                return Error{ErrorCode::busy, "resume schedule thread already owns a deferred stop event"};
            if (action.kind != ThreadResumeKind::stop) runnable.push_back(&action);
            if (action.signal_disposition && *action.signal_disposition != ContinueStatus::handled &&
                *action.signal_disposition != ContinueStatus::not_handled)
                return Error{ErrorCode::invalid_argument, "resume schedule contains an unknown signal disposition"};
        }
        if (!selected.contains(owner))
            return Error{ErrorCode::invalid_argument, "resume schedule must include the thread that owns the pending event"};
        if (runnable.empty())
            return Error{ErrorCode::invalid_argument, "resume schedule must continue or step at least one thread"};

        if (runnable.size() > 1) {
            if (std::any_of(runnable.begin(), runnable.end(), [](const auto* action) {
                    return action->kind != ThreadResumeKind::continue_execution;
                }))
                return Error{ErrorCode::unsupported, "Linux AArch64 multi-thread schedules support continue actions only"};
            if (pending_breakpoint_ || pending_hardware_execute_)
                return Error{ErrorCode::unsupported, "cannot continue multiple AArch64 threads while stepping over a breakpoint"};
            if (step_pending_ && std::any_of(runnable.begin(), runnable.end(), [&](const auto* action) {
                    return static_cast<pid_t>(action->thread) == step_thread_;
                }))
                return Error{ErrorCode::busy, "cannot continue an AArch64 thread while its single-step result is pending"};
            auto configured = ensure_hardware_breakpoints_configured(); if (!configured) return configured;

            // Resume non-owner threads first and the event owner last. If any
            // ptrace request fails, stop every thread already resumed before
            // returning, preserving the pending event for a retry.
            std::vector<pid_t> order;
            order.reserve(runnable.size());
            for (const auto* action : runnable) {
                const auto tid = static_cast<pid_t>(action->thread);
                if (tid != owner) order.push_back(tid);
            }
            if (std::any_of(runnable.begin(), runnable.end(), [&](const auto* action) {
                    return static_cast<pid_t>(action->thread) == owner;
                }))
                order.push_back(owner);

            std::vector<pid_t> resumed;
            resumed.reserve(order.size());
            for (const auto tid : order) {
                const auto action = std::find_if(runnable.begin(), runnable.end(), [&](const auto* item) {
                    return static_cast<pid_t>((*item)->thread) == tid;
                });
                const auto* selected_action = *action;
                const int queued_signal = signal_for(*selected_action);
                const int delivered = selected_action->signal_disposition == ContinueStatus::handled ? 0 : queued_signal;
                if (ptrace(PTRACE_CONT, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(delivered))) != 0) {
                    const auto error = sys_error("PTRACE_CONT scheduled AArch64 thread");
                    rollback_threads_ = resumed;
                    auto rollback = stop_threads_for_rollback(resumed);
                    if (!rollback) {
                        resume_blocked_ = true;
                        return Error{error.code, error.message + "; resume rollback failed: " + rollback.error().message};
                    }
                    rollback_threads_.clear();
                    return error;
                }
                stopped_.erase(tid);
                deferred_signals_.erase(tid);
                resumed.push_back(tid);
            }
            for (const auto& action : actions) {
                const auto tid = static_cast<pid_t>(action.thread);
                if (action.kind != ThreadResumeKind::stop) continue;
                const int signal = signal_for(action);
                if (action.signal_disposition == ContinueStatus::handled) deferred_signals_.erase(tid);
                else if (signal != 0) deferred_signals_[tid] = signal;
            }
            pending_.reset(); pending_thread_ = 0; pending_signal_ = 0;
            pending_breakpoint_.reset(); pending_hardware_execute_ = false;
            return std::monostate{};
        }

        const auto* selected_action = runnable.front();
        const auto tid = static_cast<pid_t>(selected_action->thread);
        const int queued_signal = signal_for(*selected_action);
        const int delivered = selected_action->signal_disposition == ContinueStatus::handled ? 0 : queued_signal;
        if (step_pending_ && tid == step_thread_)
            return Error{ErrorCode::busy, "cannot resume an AArch64 thread while its single-step result is pending"};
        if (pending_breakpoint_ && tid != owner)
            return Error{ErrorCode::unsupported, "cannot preserve a pending software-breakpoint event while scheduling another thread"};
        if (pending_hardware_execute_ && tid != owner)
            return Error{ErrorCode::unsupported, "cannot step over an AArch64 hardware breakpoint on a different thread"};
        auto configured = ensure_hardware_breakpoints_configured(); if (!configured) return configured;
        if (selected_action->kind == ThreadResumeKind::single_step) {
            if (pending_breakpoint_ && delivered == 0) {
                auto stepped = begin_breakpoint_step(tid, *pending_breakpoint_); if (!stepped) return stepped;
            } else if (pending_hardware_execute_ && delivered == 0) {
                auto stepped = begin_hardware_execute_step(tid, pending_hardware_execute_address_);
                if (!stepped) return stepped;
            } else {
                if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(delivered))) != 0) return sys_error("PTRACE_SINGLESTEP scheduled thread");
                stopped_.erase(tid); step_thread_ = tid; step_pending_ = true;
            }
        } else if (pending_breakpoint_ && delivered == 0) {
            auto stepped = begin_breakpoint_step(tid, *pending_breakpoint_); if (!stepped) return stepped;
        } else if (pending_hardware_execute_ && delivered == 0) {
            auto stepped = begin_hardware_execute_step(tid, pending_hardware_execute_address_);
            if (!stepped) return stepped;
        } else {
            if (ptrace(PTRACE_CONT, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(delivered))) != 0) return sys_error("PTRACE_CONT scheduled thread");
            stopped_.erase(tid);
        }
        deferred_signals_.erase(tid);
        for (const auto& action : actions) {
            const auto stopped_tid = static_cast<pid_t>(action.thread);
            if (action.kind != ThreadResumeKind::stop) continue;
            const int signal = signal_for(action);
            if (action.signal_disposition == ContinueStatus::handled) deferred_signals_.erase(stopped_tid);
            else if (signal != 0) deferred_signals_[stopped_tid] = signal;
        }
        pending_.reset(); pending_thread_ = 0; pending_signal_ = 0; pending_breakpoint_.reset(); pending_hardware_execute_ = false;
        return std::monostate{};
    }
    Status single_step_event(std::uint64_t sequence, ContinueStatus disposition) override {
        WaitScope scope(*this);
        if (!pending_ || *pending_ != sequence) return Error{ErrorCode::invalid_argument, "event sequence does not match pending event"};
        auto rollback = recover_resume_rollback(); if (!rollback) return rollback;
        auto configured = ensure_hardware_breakpoints_configured(); if (!configured) return configured;
        const auto tid = pending_thread_;
        const int signal = disposition == ContinueStatus::handled ? 0 : pending_signal_;
        if (pending_breakpoint_ && disposition == ContinueStatus::handled) {
            auto stepped = begin_breakpoint_step(tid, *pending_breakpoint_); if (!stepped) return stepped;
            pending_.reset(); pending_thread_ = 0; pending_signal_ = 0; pending_breakpoint_.reset();
            return std::monostate{};
        }
        if (pending_hardware_execute_ && disposition == ContinueStatus::handled) {
            auto stepped = begin_hardware_execute_step(tid, pending_hardware_execute_address_);
            if (!stepped) return stepped;
            pending_.reset(); pending_thread_ = 0; pending_signal_ = 0; pending_hardware_execute_ = false;
            return std::monostate{};
        }
        if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(signal))) != 0) return sys_error("PTRACE_SINGLESTEP");
        pending_.reset(); pending_thread_ = 0; pending_signal_ = 0; pending_breakpoint_.reset(); pending_hardware_execute_ = false; stopped_.erase(tid); step_thread_ = tid; step_pending_ = true; return std::monostate{};
    }
    Result<std::vector<std::byte>> read_memory(std::uint64_t address, std::size_t size) override {
        if (!pid_ || size > max_inspection_read || address > UINT64_MAX - size) return Error{ErrorCode::invalid_argument, "invalid memory read range"};
        auto safe = require_all_threads_stopped(); if (!safe) return safe.error();
        std::vector<std::byte> out(size);
        constexpr std::size_t word_size = sizeof(long);
        for (std::size_t i = 0; i < size;) {
            const auto at = address + i;
            const auto offset = static_cast<std::size_t>(at % word_size);
            const auto aligned = at - offset;
            errno = 0;
            const auto word = ptrace(PTRACE_PEEKDATA, pid_, reinterpret_cast<void*>(static_cast<std::uintptr_t>(aligned)), nullptr);
            if (word == -1 && errno) return sys_error("PTRACE_PEEKDATA");
            const auto count = std::min(word_size - offset, size - i);
            std::memcpy(out.data() + i, reinterpret_cast<const std::byte*>(&word) + offset, count);
            i += count;
        }
        return out;
    }
    Status write_memory(std::uint64_t address, std::span<const std::byte> bytes) override {
        if (!pid_ || bytes.size() > max_inspection_read || address > UINT64_MAX - bytes.size()) return Error{ErrorCode::invalid_argument, "invalid memory write range"};
        auto safe = require_all_threads_stopped(); if (!safe) return safe;
        auto prior = read_memory(address, bytes.size()); if (!prior) return prior.error();
        auto data = std::vector<std::byte>(bytes.begin(), bytes.end());
        constexpr std::array<std::byte, 4> brk{std::byte{0x00}, std::byte{0x00}, std::byte{0x20}, std::byte{0xd4}};
        std::map<std::uint64_t, std::array<std::byte, 4>> updates;
        for (const auto& [at, original] : breakpoints_) {
            (void)original;
            auto instruction = original_instruction(at);
            bool touched = false;
            for (std::size_t offset = 0; offset < brk.size(); ++offset) {
                const auto byte_address = at + offset;
                if (byte_address < address || byte_address - address >= data.size()) continue;
                const auto index = static_cast<std::size_t>(byte_address - address);
                instruction[offset] = data[index];
                if (enabled_.contains(at)) data[index] = brk[offset];
                touched = true;
            }
            if (touched) updates[at] = {instruction[0], instruction[1], instruction[2], instruction[3]};
        }
        auto written = write_raw(address, data);
        if (!written) {
            auto rollback = write_raw(address, prior.value());
            if (!rollback) return Error{written.error().code, written.error().message + "; memory rollback failed: " + rollback.error().message};
            return written;
        }
        for (const auto& [at, instruction] : updates) {
            originals_[at] = instruction[0]; breakpoints_[at] = instruction[0];
            for (std::size_t n = 1; n < instruction.size(); ++n) extra_originals_[at][n - 1] = instruction[n];
        }
        return std::monostate{};
    }
    Result<std::vector<ThreadInfo>> threads() override {
        if (!pid_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        std::vector<ThreadInfo> out; std::error_code ec; const auto path = "/proc/" + std::to_string(pid_) + "/task";
        for (std::filesystem::directory_iterator it(path, ec), end; !ec && it != end; it.increment(ec)) { pid_t tid{}; if (!parse_pid(it->path().filename().string(), tid)) continue; if (out.size() >= max_inspection_threads) return Error{ErrorCode::resource_limit, "target thread count exceeds the inspection limit"}; const auto state = !tracked_.contains(tid) ? ThreadState::unknown : (stopped_.contains(tid) ? ThreadState::stopped : ThreadState::running); out.push_back({static_cast<ThreadId>(tid), proc_name(tid), state}); }
        if (ec) return Error{ErrorCode::io, "failed to enumerate target threads: " + ec.message()}; return out;
    }
    Result<std::vector<ThreadRunState>> thread_run_states() override {
        auto current = threads(); if (!current) return current.error();
        std::vector<ThreadRunState> out; out.reserve(current.value().size());
        for (const auto &thread : current.value()) out.push_back({thread.id, thread.state});
        return out;
    }
    Result<std::vector<MemoryRegion>> memory_regions() override {
        if (!pid_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        return read_proc_mappings(pid_);
    }
    Result<std::vector<ModuleInfo>> modules() override {
        if (!pid_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        auto mappings = read_proc_mappings(pid_);
        if (!mappings) return mappings.error();
        struct Range { std::uint64_t base; std::uint64_t end; };
        std::map<std::string, Range> ranges;
        for (const auto& mapping : mappings.value()) {
            // read_proc_mappings retains the Linux mapping path after the
            // private:/shared: prefix. Anonymous, bracketed, and empty paths
            // are process regions rather than file-backed modules.
            const auto separator = mapping.type.find(':');
            if (separator == std::string::npos || separator + 1 >= mapping.type.size()) continue;
            const auto path = mapping.type.substr(separator + 1);
            if (path.front() == '[') continue;
            if (mapping.start > std::numeric_limits<std::uint64_t>::max() - mapping.length)
                return Error{ErrorCode::malformed, "target mapping range overflows while enumerating modules"};
            const auto end = mapping.start + mapping.length;
            const auto [it, inserted] = ranges.emplace(path, Range{mapping.start, end});
            if (!inserted) {
                it->second.base = std::min(it->second.base, mapping.start);
                it->second.end = std::max(it->second.end, end);
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
        auto valid = require_stopped_thread(thread); if (!valid) return valid.error();
        auto regs = get_regs(static_cast<pid_t>(thread)); if (!regs) return regs.error(); std::vector<RegisterValue> out; out.reserve(names.size());
        for (std::size_t i = 0; i < names.size(); ++i) {
            RegisterValue r; r.name = names[i]; r.bytes.resize(8); r.byte_order = ByteOrder::little;
            r.group = i == 33 ? "status" : "general";
            std::memcpy(r.bytes.data(), &regs.value().value[i], 8); out.push_back(std::move(r));
        }
        auto append_bytes = [&](std::string name, const std::byte* data, std::size_t size) {
            RegisterValue reg; reg.name = std::move(name); reg.byte_order = ByteOrder::little;
            reg.group = "vector";
            reg.bytes.assign(data, data + size); out.push_back(std::move(reg));
        };
        auto append_u16 = [&](const char* name, std::uint16_t value) {
            RegisterValue reg; reg.name = name; reg.byte_order = ByteOrder::little; reg.bytes.resize(sizeof(value));
            std::memcpy(reg.bytes.data(), &value, sizeof(value)); out.push_back(std::move(reg));
        };
        auto append_fpsimd = [&](const Aarch64FpsimdRegs& fp) {
            for (std::size_t i = 0; i < fpsimd_names.size(); ++i) {
                append_bytes(fpsimd_names[i], fp.vregs[i].data(), fp.vregs[i].size());
                append_bytes("d" + std::to_string(i), fp.vregs[i].data(), 8);
            }
            for (const auto& item : {std::pair{"fpsr", fp.fpsr}, std::pair{"fpcr", fp.fpcr}}) {
                RegisterValue reg; reg.name = item.first; reg.byte_order = ByteOrder::little; reg.bytes.resize(4);
                std::memcpy(reg.bytes.data(), &item.second, 4); out.push_back(std::move(reg));
            }
        };
        auto sve = get_sve_state(static_cast<pid_t>(thread));
        if (sve) {
            // A header-only optional vector view must not hide a valid GPR
            // snapshot. Its vector payload cannot safely be substituted.
            if (sve.value().bytes.empty()) return out;
            append_u16("sve_vl", sve.value().header.vl);
            append_u16("sve_max_vl", sve.value().header.max_vl);
            if (!sve.value().has_sve_registers) {
                Aarch64FpsimdRegs fp{};
                std::memcpy(&fp, sve.value().bytes.data() + sizeof(Aarch64SveHeader), sizeof(fp));
                append_fpsimd(fp);
            } else {
                auto layout = sve_layout(sve.value().header.vl); if (!layout) return layout.error();
                const auto vl = static_cast<std::size_t>(sve.value().header.vl);
                for (std::size_t i = 0; i < 32; ++i) {
                    const auto* z = sve.value().bytes.data() + layout.value().z_offset + i * vl;
                    append_bytes("z" + std::to_string(i), z, vl);
                    append_bytes(fpsimd_names[i], z, 16); // Vn is the low 128 bits of Zn.
                    append_bytes("d" + std::to_string(i), z, 8);
                }
                const auto predicate_size = vl / 8;
                for (std::size_t i = 0; i < 16; ++i)
                    append_bytes("p" + std::to_string(i), sve.value().bytes.data() + layout.value().p_offset + i * predicate_size, predicate_size);
                append_bytes("ffr", sve.value().bytes.data() + layout.value().ffr_offset, predicate_size);
                std::uint32_t fpsr{}, fpcr{};
                std::memcpy(&fpsr, sve.value().bytes.data() + layout.value().fpsr_offset, sizeof(fpsr));
                std::memcpy(&fpcr, sve.value().bytes.data() + layout.value().fpcr_offset, sizeof(fpcr));
                for (const auto& item : {std::pair{"fpsr", fpsr}, std::pair{"fpcr", fpcr}}) {
                    RegisterValue reg; reg.name = item.first; reg.byte_order = ByteOrder::little; reg.bytes.resize(4);
                    std::memcpy(reg.bytes.data(), &item.second, 4); out.push_back(std::move(reg));
                }
            }
        } else if (sve.error().code == ErrorCode::unsupported) {
            auto fp = get_fpsimd_regs(static_cast<pid_t>(thread));
            if (!fp && fp.error().code != ErrorCode::unsupported) return fp.error();
            if (fp) append_fpsimd(fp.value());
        } else return sve.error();
        return out;
    }
    Status write_registers(ThreadId thread, std::span<const RegisterValue> writes) override {
        auto valid = require_stopped_thread(thread); if (!valid) return valid;
        const auto tid = static_cast<pid_t>(thread);
        bool has_gpr = false, has_vector = false, has_sve_specific = false;
        std::array<bool, 32> writes_v{}, writes_z{}, writes_d{};
        std::set<std::string> seen;
        auto parse_indexed = [](std::string_view name, char prefix, std::size_t count, std::size_t& index) {
            if (name.size() < 2 || name.front() != prefix) return false;
            if (name.size() > 2 && name[1] == '0') return false;
            std::size_t value{};
            const auto parsed = std::from_chars(name.data() + 1, name.data() + name.size(), value);
            if (parsed.ec != std::errc{} || parsed.ptr != name.data() + name.size() || value >= count) return false;
            index = value;
            return true;
        };
        for (const auto& reg : writes) {
            if (reg.byte_order && *reg.byte_order != ByteOrder::little)
                return Error{ErrorCode::invalid_argument, "AArch64 register writes require little-endian bytes"};
            if (!seen.insert(reg.name).second)
                return Error{ErrorCode::invalid_argument, "AArch64 register write contains a duplicate register"};
            const auto gpr = std::find(names.begin(), names.end(), reg.name);
            const auto fp = std::find(fpsimd_names.begin(), fpsimd_names.end(), reg.name);
            const bool status = reg.name == "fpsr" || reg.name == "fpcr";
            std::size_t index{};
            const bool zreg = parse_indexed(reg.name, 'z', 32, index);
            if (zreg) writes_z[index] = true;
            const bool dreg = parse_indexed(reg.name, 'd', 32, index);
            if (dreg) writes_d[index] = true;
            const bool preg = parse_indexed(reg.name, 'p', 16, index);
            const bool ffr = reg.name == "ffr";
            if (reg.name == "sve_vl" || reg.name == "sve_max_vl")
                return Error{ErrorCode::unsupported, "SVE vector length metadata is read-only; changing it requires a separate prctl operation"};
            if (gpr != names.end()) {
                if (reg.bytes.size() != 8) return Error{ErrorCode::invalid_argument, "AArch64 GPR width mismatch"};
                has_gpr = true;
            } else if (fp != fpsimd_names.end()) {
                if (reg.bytes.size() != 16) return Error{ErrorCode::invalid_argument, "AArch64 FPSIMD register width mismatch"};
                writes_v[static_cast<std::size_t>(fp - fpsimd_names.begin())] = true;
                has_vector = true;
            } else if (dreg) {
                if (reg.bytes.size() != 8) return Error{ErrorCode::invalid_argument, "AArch64 D register width mismatch"};
                has_vector = true;
            } else if (zreg || preg || ffr) {
                has_vector = true;
                has_sve_specific = true;
            } else if (status) {
                if (reg.bytes.size() != 4) return Error{ErrorCode::invalid_argument, "AArch64 FPSR/FPCR width mismatch"};
                has_vector = true;
            } else return Error{ErrorCode::invalid_argument, "unknown AArch64 register"};
        }
        for (std::size_t i = 0; i < writes_v.size(); ++i)
            if (unsigned(writes_v[i]) + unsigned(writes_z[i]) + unsigned(writes_d[i]) > 1)
                return Error{ErrorCode::invalid_argument, "write one of dN, vN or zN for each aliased vector register"};
        if (writes.empty()) return std::monostate{};
        Result<Aarch64Regs> gpr_before = Error{ErrorCode::unsupported, "GPR state was not requested"};
        if (has_gpr) { gpr_before = get_regs(tid); if (!gpr_before) return gpr_before.error(); }
        std::optional<Aarch64SveState> sve_before, sve_after;
        std::optional<Aarch64FpsimdRegs> fp_before, fp_after;
        if (has_vector) {
            auto sve = get_sve_state(tid);
            if (sve) {
                if (sve.value().bytes.empty())
                    return Error{ErrorCode::unsupported, "Linux AArch64 SVE regset is inactive for this thread; streaming SME state is not exposed"};
                sve_before = std::move(sve.value());
                sve_after = *sve_before;
                if (has_sve_specific && !sve_before->has_sve_registers)
                    return Error{ErrorCode::unsupported, "Z/P/FFR writes require active Linux AArch64 SVE register state"};
            } else if (sve.error().code == ErrorCode::unsupported) {
                auto fp = get_fpsimd_regs(tid); if (!fp) return fp.error();
                fp_before = fp.value(); fp_after = fp.value();
                if (has_sve_specific)
                    return Error{ErrorCode::unsupported, "Z/P/FFR registers require Linux NT_ARM_SVE support"};
            } else return sve.error();
        }
        // All scalable widths are checked before the first payload copy or
        // SETREGSET. VL is a stopped-thread property, not caller input.
        for (const auto& reg : writes) {
            std::size_t index{};
            std::optional<std::size_t> expected;
            const bool zreg = parse_indexed(reg.name, 'z', 32, index);
            const bool predicate = parse_indexed(reg.name, 'p', 16, index) || reg.name == "ffr";
            if (zreg || predicate) {
                if (!sve_before || !sve_before->has_sve_registers)
                    return Error{ErrorCode::unsupported, "scalable writes require a validated active SVE snapshot"};
                expected = zreg ? sve_before->header.vl : sve_before->header.vl / 8;
            }
            if (expected && reg.bytes.size() != *expected)
                return Error{ErrorCode::invalid_argument, "AArch64 scalable register width does not match the stopped thread vector length"};
        }
        auto gpr_after = gpr_before ? gpr_before.value() : Aarch64Regs{};
        for (const auto& reg : writes) {
            const auto gpr = std::find(names.begin(), names.end(), reg.name);
            if (gpr != names.end()) {
                std::memcpy(&gpr_after.value[static_cast<std::size_t>(gpr - names.begin())], reg.bytes.data(), 8);
                continue;
            }
        }
        if (sve_after) {
            if (sve_after->has_sve_registers) {
                auto layout = sve_layout(sve_after->header.vl); if (!layout) return layout.error();
                const auto vl = static_cast<std::size_t>(sve_after->header.vl);
                const auto predicate_size = vl / 8;
                for (const auto& reg : writes) {
                    std::size_t index{};
                    if (parse_indexed(reg.name, 'z', 32, index))
                        std::memcpy(sve_after->bytes.data() + layout.value().z_offset + index * vl, reg.bytes.data(), vl);
                    else if (parse_indexed(reg.name, 'd', 32, index))
                        std::memcpy(sve_after->bytes.data() + layout.value().z_offset + index * vl, reg.bytes.data(), 8);
                    else if (const auto fp = std::find(fpsimd_names.begin(), fpsimd_names.end(), reg.name); fp != fpsimd_names.end())
                        std::memcpy(sve_after->bytes.data() + layout.value().z_offset + static_cast<std::size_t>(fp - fpsimd_names.begin()) * vl,
                                    reg.bytes.data(), 16);
                    else if (parse_indexed(reg.name, 'p', 16, index))
                        std::memcpy(sve_after->bytes.data() + layout.value().p_offset + index * predicate_size, reg.bytes.data(), predicate_size);
                    else if (reg.name == "ffr")
                        std::memcpy(sve_after->bytes.data() + layout.value().ffr_offset, reg.bytes.data(), predicate_size);
                    else if (reg.name == "fpsr")
                        std::memcpy(sve_after->bytes.data() + layout.value().fpsr_offset, reg.bytes.data(), 4);
                    else if (reg.name == "fpcr")
                        std::memcpy(sve_after->bytes.data() + layout.value().fpcr_offset, reg.bytes.data(), 4);
                }
            } else {
                Aarch64FpsimdRegs fp{};
                std::memcpy(&fp, sve_after->bytes.data() + sizeof(Aarch64SveHeader), sizeof(fp));
                for (const auto& reg : writes) {
                    const auto fpreg = std::find(fpsimd_names.begin(), fpsimd_names.end(), reg.name);
                    if (fpreg != fpsimd_names.end()) std::copy(reg.bytes.begin(), reg.bytes.end(), fp.vregs[static_cast<std::size_t>(fpreg - fpsimd_names.begin())].begin());
                    else if (std::size_t index{}; parse_indexed(reg.name, 'd', 32, index))
                        std::copy(reg.bytes.begin(), reg.bytes.end(), fp.vregs[index].begin());
                    else if (reg.name == "fpsr") std::memcpy(&fp.fpsr, reg.bytes.data(), 4);
                    else if (reg.name == "fpcr") std::memcpy(&fp.fpcr, reg.bytes.data(), 4);
                }
                std::memcpy(sve_after->bytes.data() + sizeof(Aarch64SveHeader), &fp, sizeof(fp));
            }
        } else if (fp_after) {
            for (const auto& reg : writes) {
                const auto fp = std::find(fpsimd_names.begin(), fpsimd_names.end(), reg.name);
                if (fp != fpsimd_names.end()) std::copy(reg.bytes.begin(), reg.bytes.end(), fp_after->vregs[static_cast<std::size_t>(fp - fpsimd_names.begin())].begin());
                else if (std::size_t index{}; parse_indexed(reg.name, 'd', 32, index))
                    std::copy(reg.bytes.begin(), reg.bytes.end(), fp_after->vregs[index].begin());
                else if (reg.name == "fpsr") std::memcpy(&fp_after->fpsr, reg.bytes.data(), 4);
                else if (reg.name == "fpcr") std::memcpy(&fp_after->fpcr, reg.bytes.data(), 4);
            }
        }
        auto apply_vector = [&]() -> Status {
            return sve_after ? set_sve_state(tid, *sve_after) : set_fpsimd_regs(tid, *fp_after);
        };
        auto rollback_vector = [&]() -> Status {
            return sve_before ? set_sve_state(tid, *sve_before) : set_fpsimd_regs(tid, *fp_before);
        };
        if (has_gpr && has_vector) {
            // Commit vector state first so a failed GPR set can restore both snapshots.
            auto applied_fp = apply_vector(); if (!applied_fp) {
                auto rollback = rollback_vector();
                if (!rollback) return Error{applied_fp.error().code, applied_fp.error().message + "; vector-state rollback failed: " + rollback.error().message};
                return applied_fp;
            }
            auto applied_gpr = set_regs(tid, gpr_after);
            if (!applied_gpr) {
                auto rollback_gpr = set_regs(tid, gpr_before.value());
                auto rollback_fp = rollback_vector();
                if (!rollback_gpr || !rollback_fp) {
                    auto message = applied_gpr.error().message;
                    if (!rollback_gpr) message += "; GPR rollback failed: " + rollback_gpr.error().message;
                    if (!rollback_fp) message += "; vector-state rollback failed: " + rollback_fp.error().message;
                    return Error{applied_gpr.error().code, std::move(message)};
                }
                return applied_gpr;
            }
            return std::monostate{};
        }
        if (has_vector) {
            auto applied = apply_vector(); if (applied) return applied;
            auto rollback = rollback_vector();
            if (!rollback) return Error{applied.error().code, applied.error().message + "; vector-state rollback failed: " + rollback.error().message};
            return applied;
        }
        auto applied = set_regs(tid, gpr_after); if (applied) return applied;
        auto rollback = set_regs(tid, gpr_before.value());
        if (!rollback) return Error{applied.error().code, applied.error().message + "; GPR rollback failed: " + rollback.error().message};
        return applied;
    }
    Result<Breakpoint> add_breakpoint(std::uint64_t address, BreakpointKind kind) override {
        if (kind == BreakpointKind::hardware)
            return add_hardware_breakpoint(address, BreakpointKind::execute, 1);
        if (kind != BreakpointKind::software) return Error{ErrorCode::unsupported, "AArch64 Linux backend currently supports software breakpoints only"};
        auto safe = require_all_threads_stopped(); if (!safe) return safe.error();
        if (address % 4) return Error{ErrorCode::invalid_argument, "AArch64 instruction breakpoints must be 4-byte aligned"};
        if (std::any_of(hardware_breakpoints_.begin(), hardware_breakpoints_.end(), [&](const auto& bp) {
            return hardware_execute_kind(bp.kind) && bp.address == address;
        })) return Error{ErrorCode::conflict, "software and hardware execute breakpoints cannot share an AArch64 address"};
        if (breakpoints_.contains(address)) return Error{ErrorCode::conflict, "breakpoint already exists at address"};
        auto current = read_memory(address, 4); if (!current) return current.error();
        constexpr std::array<std::byte, 4> brk{std::byte{0x00}, std::byte{0x00}, std::byte{0x20}, std::byte{0xd4}};
        auto installed = write_raw(address, brk); if (!installed) return installed.error();
        originals_[address] = current.value()[0]; for (std::size_t i = 1; i < 4; ++i) extra_originals_[address][i - 1] = current.value()[i];
        breakpoints_[address] = originals_[address]; enabled_.insert(address); const auto id = next_id_++; ids_[id] = address; return Breakpoint{id, address, kind, true, 4};
    }
    Result<Breakpoint> add_hardware_breakpoint(std::uint64_t address, BreakpointKind kind,
                                               std::uint8_t size) override {
        if (!pid_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        auto safe = require_all_threads_stopped(); if (!safe) return safe.error();
        auto step_restored = restore_hardware_execute_step(); if (!step_restored) return step_restored.error();
        auto encoding = hardware_encoding(address, kind, size);
        if (!encoding) return encoding.error();
        if (hardware_execute_kind(kind) && breakpoints_.contains(address))
            return Error{ErrorCode::conflict, "software and hardware execute breakpoints cannot share an AArch64 address"};
        if (std::any_of(hardware_breakpoints_.begin(), hardware_breakpoints_.end(),
            [&](const auto& item) { return item.address == address && item.kind == kind && item.size == size; }))
            return Error{ErrorCode::conflict, "hardware breakpoint already exists at address and kind"};

        const auto note = hardware_note(kind);
        std::map<pid_t, Aarch64HwdebugState> states;
        std::size_t available = aarch64_hwdebug_max_slots;
        for (const auto tid : tracked_) {
            auto state = get_hwdebug_state(tid, note); if (!state) return state.error();
            available = std::min(available, state.value().slots);
            states.emplace(tid, state.value().state);
        }
        if (states.empty()) return Error{ErrorCode::busy, "no stopped target threads are owned"};
        std::optional<std::size_t> slot;
        for (std::size_t candidate = 0; candidate < available; ++candidate) {
            if (std::any_of(hardware_breakpoints_.begin(), hardware_breakpoints_.end(), [&](const auto& bp) {
                return hardware_note(bp.kind) == note && bp.slot == candidate;
            })) continue;
            const bool free = std::all_of(states.begin(), states.end(), [&](const auto& thread) {
                const auto& reg = thread.second.registers[candidate];
                return reg.control == 0 && reg.address == 0;
            });
            if (free) { slot = candidate; break; }
        }
        if (!slot) return Error{ErrorCode::resource_limit, note == nt_arm_hw_break
            ? "target has no common free AArch64 hardware instruction breakpoint slot"
            : "target has no common free AArch64 hardware watchpoint slot"};

        auto next = hardware_breakpoints_;
        const auto id = next_id_;
        next.push_back({id, address, kind, size, static_cast<std::uint8_t>(*slot), true});
        auto applied = apply_hardware_configuration(next, hardware_breakpoints_);
        if (!applied) return applied.error();
        hardware_breakpoints_ = std::move(next);
        ++next_id_;
        Breakpoint result{};
        result.id = id; result.address = address; result.kind = kind; result.enabled = true; result.size = size;
        return result;
    }
    Status remove_breakpoint(BreakpointId id) override {
        const auto hardware = std::find_if(hardware_breakpoints_.begin(), hardware_breakpoints_.end(),
            [id](const auto& item) { return item.id == id; });
        if (hardware != hardware_breakpoints_.end()) {
            auto safe = require_all_threads_stopped(); if (!safe) return safe;
            auto step_restored = restore_hardware_execute_step(); if (!step_restored) return step_restored;
            auto next = hardware_breakpoints_;
            std::erase_if(next, [id](const auto& item) { return item.id == id; });
            auto applied = apply_hardware_configuration(next, hardware_breakpoints_);
            if (!applied) return applied;
            hardware_breakpoints_ = std::move(next);
            return std::monostate{};
        }
        const auto it = ids_.find(id); if (it == ids_.end()) return Error{ErrorCode::invalid_argument, "unknown breakpoint id"}; const auto at = it->second;
        if (enabled_.contains(at)) { auto safe = require_all_threads_stopped(); if (!safe) return safe; auto bytes = original_instruction(at); if (!write_raw(at, bytes)) return sys_error("restore software breakpoint"); }
        ids_.erase(it); enabled_.erase(at); breakpoints_.erase(at); originals_.erase(at); extra_originals_.erase(at); return std::monostate{};
    }
    Status set_breakpoint_enabled(BreakpointId id, bool enabled) override {
        const auto hardware = std::find_if(hardware_breakpoints_.begin(), hardware_breakpoints_.end(),
            [id](const auto& item) { return item.id == id; });
        if (hardware != hardware_breakpoints_.end()) {
            auto safe = require_all_threads_stopped(); if (!safe) return safe;
            auto step_restored = restore_hardware_execute_step(); if (!step_restored) return step_restored;
            auto next = hardware_breakpoints_;
            const auto updated = std::find_if(next.begin(), next.end(),
                [id](const auto& item) { return item.id == id; });
            updated->enabled = enabled;
            auto applied = apply_hardware_configuration(next, hardware_breakpoints_);
            if (!applied) return applied;
            hardware_breakpoints_ = std::move(next);
            return std::monostate{};
        }
        const auto it = ids_.find(id); if (it == ids_.end()) return Error{ErrorCode::invalid_argument, "unknown breakpoint id"}; const auto at = it->second; if (enabled_.contains(at) == enabled) return std::monostate{};
        auto safe = require_all_threads_stopped(); if (!safe) return safe;
        if (enabled) { constexpr std::array<std::byte, 4> brk{std::byte{0x00}, std::byte{0x00}, std::byte{0x20}, std::byte{0xd4}}; auto s = write_raw(at, brk); if (!s) return s; enabled_.insert(at); }
        else { auto s = write_raw(at, original_instruction(at)); if (!s) return s; enabled_.erase(at); }
        return std::monostate{};
    }
private:
    static std::chrono::milliseconds configured_wait_timeout() {
        constexpr auto fallback = std::chrono::milliseconds(5000);
        const auto *text = std::getenv("HEXLAB_AARCH64_PTRACE_TIMEOUT_MS");
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
        if (cancellable && wait_stop_requested_.load()) {
            if (!event_polling_)
                return Error{ErrorCode::canceled, "AArch64 ptrace wait was interrupted; tracee ownership is retained"};
            wait_stop_requested_.store(false);
            auto interrupted = interrupt_running_threads(true);
            if (!interrupted) return interrupted;
        }
        if (wait_deadline_ && Clock::now() >= *wait_deadline_)
            return Error{ErrorCode::busy, "AArch64 ptrace operation deadline expired; tracee ownership is retained"};
        return std::monostate{};
    }
    Result<int> wait_status(pid_t tid, bool cancellable = true) {
        WaitScope scope(*this);
        for (;;) {
            int status{};
            const auto waited = waitpid(tid, &status, __WALL | WNOHANG);
            if (waited == tid) return status;
            if (waited < 0 && (errno == ECHILD || errno == ESRCH))
                return Error{ErrorCode::out_of_bounds, "AArch64 tracee is no longer waitable by this tracer"};
            if (waited < 0 && errno != EINTR) return sys_error("waitpid AArch64 tracee");
            auto progress = wait_progress(cancellable);
            if (!progress) return progress.error();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    void forget_thread(pid_t tid) {
        tracked_.erase(tid); stopped_.erase(tid); seized_.erase(tid);
        interrupting_.erase(tid); deferred_.erase(tid); initial_children_.erase(tid);
        deferred_signals_.erase(tid);
        hardware_unconfigured_threads_.erase(tid);
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
                deferred_[tid] = status.value();
                if (!startup_kill_) break;
                progress = wait_progress(false); if (!progress) return progress;
                if (ptrace(PTRACE_CONT, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(SIGKILL))) != 0 && errno != ESRCH)
                    return sys_error("PTRACE_CONT SIGKILL failed launch");
                stopped_.erase(tid);
            }
            if (!tracked_.contains(tid)) continue;
            const auto status = deferred_.find(tid);
            const int signal = status != deferred_.end() && WIFSTOPPED(status->second) && (static_cast<unsigned>(status->second) >> 16) == 0
                ? WSTOPSIG(status->second) : 0;
            if (ptrace(PTRACE_DETACH, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(signal))) != 0 && errno != ESRCH)
                return sys_error("PTRACE_DETACH failed attach cleanup");
            forget_thread(tid);
        }
        if (!tracked_.empty()) return Error{ErrorCode::busy, "failed-startup cleanup is incomplete"};
        clear(); startup_cleanup_ = false; startup_kill_ = false;
        return std::monostate{};
    }
    struct HwdebugSnapshot { Aarch64HwdebugState state{}; std::size_t slots{}; };
    static bool hardware_execute_kind(BreakpointKind kind) {
        return kind == BreakpointKind::hardware || kind == BreakpointKind::execute;
    }
    static unsigned long hardware_note(BreakpointKind kind) {
        return hardware_execute_kind(kind) ? nt_arm_hw_break : nt_arm_hw_watch;
    }
    static Result<std::pair<std::uint64_t, std::uint32_t>> hardware_encoding(
        std::uint64_t address, BreakpointKind kind, std::uint8_t size) {
        if (address > UINT64_MAX - size)
            return Error{ErrorCode::invalid_argument, "hardware breakpoint range overflows the address space"};
        if (hardware_execute_kind(kind)) {
            if (size != 1 || (address & 3u) != 0)
                return Error{ErrorCode::invalid_argument, "AArch64 execute breakpoints require logical size 1 and four-byte alignment"};
            constexpr std::uint32_t el0 = 2u;
            constexpr std::uint32_t bas = 0x0fu;
            // Linux arm64 encode_ctrl_reg: BAS[12:5], type[4:3], EL0[2:1], E[0].
            return std::pair{address, (bas << 5) | (el0 << 1) | 1u};
        }
        if (kind != BreakpointKind::read && kind != BreakpointKind::write &&
            kind != BreakpointKind::access)
            return Error{ErrorCode::invalid_argument, "unsupported AArch64 hardware breakpoint kind"};
        if (size != 1 && size != 2 && size != 4 && size != 8)
            return Error{ErrorCode::invalid_argument, "AArch64 watchpoint size must be 1, 2, 4, or 8 bytes"};
        const auto offset = static_cast<unsigned>(address & 7u);
        if (offset + size > 8)
            return Error{ErrorCode::invalid_argument, "AArch64 watchpoint range must fit within one aligned eight-byte granule"};
        const auto bas = ((1u << size) - 1u) << offset;
        const std::uint32_t type = kind == BreakpointKind::read ? 1u :
            kind == BreakpointKind::write ? 2u : 3u;
        constexpr std::uint32_t el0 = 2u;
        return std::pair{address & ~std::uint64_t{7}, (bas << 5) | (type << 3) | (el0 << 1) | 1u};
    }
    Result<HwdebugSnapshot> get_hwdebug_state(pid_t tid, unsigned long note) const {
        HwdebugSnapshot snapshot{};
        iovec io{&snapshot.state, sizeof(snapshot.state)};
        if (ptrace(PTRACE_GETREGSET, tid, reinterpret_cast<void*>(note), &io) != 0) {
            const auto error = errno;
            if (error == EINVAL || error == EIO || error == ENODEV || error == ENOTSUP)
                return Error{ErrorCode::unsupported, note == nt_arm_hw_break
                    ? "kernel or target does not expose AArch64 hardware instruction breakpoints"
                    : "kernel or target does not expose AArch64 hardware watchpoints"};
            return sys_error(note == nt_arm_hw_break ? "PTRACE_GETREGSET NT_ARM_HW_BREAK" :
                                                       "PTRACE_GETREGSET NT_ARM_HW_WATCH");
        }
        snapshot.slots = snapshot.state.info & 0xffu;
        if (snapshot.slots == 0)
            return Error{ErrorCode::unsupported, "kernel reports no AArch64 hardware-debug slots for this target"};
        if (snapshot.slots > aarch64_hwdebug_max_slots ||
            io.iov_len < offsetof(Aarch64HwdebugState, registers) + snapshot.slots * sizeof(Aarch64HwdebugRegister) ||
            io.iov_len > sizeof(snapshot.state))
            return Error{ErrorCode::malformed, "kernel returned an invalid AArch64 hardware-debug register set"};
        return snapshot;
    }
    Status set_hwdebug_state(pid_t tid, unsigned long note, const Aarch64HwdebugState& state,
                             std::size_t slots) const {
        if (slots == 0 || slots > aarch64_hwdebug_max_slots)
            return Error{ErrorCode::invalid_argument, "invalid AArch64 hardware-debug slot count"};
        iovec io{const_cast<Aarch64HwdebugState*>(&state),
            offsetof(Aarch64HwdebugState, registers) + slots * sizeof(Aarch64HwdebugRegister)};
        if (ptrace(PTRACE_SETREGSET, tid, reinterpret_cast<void*>(note), &io) != 0) {
            const auto error = errno;
            if (error == EINVAL || error == EIO || error == ENODEV || error == ENOTSUP)
                return Error{ErrorCode::unsupported, "kernel rejected this AArch64 hardware-debug regset update"};
            return sys_error(note == nt_arm_hw_break ? "PTRACE_SETREGSET NT_ARM_HW_BREAK" :
                                                       "PTRACE_SETREGSET NT_ARM_HW_WATCH");
        }
        return std::monostate{};
    }
    Status apply_hardware_configuration(const std::vector<Aarch64HardwareBreakpoint>& next,
                                        const std::vector<Aarch64HardwareBreakpoint>& previous) {
        struct ThreadStateCopy { Aarch64HwdebugState before{}; Aarch64HwdebugState after{}; std::size_t slots{}; };
        using Key = std::pair<pid_t, unsigned long>;
        std::map<Key, ThreadStateCopy> states;
        std::set<unsigned long> notes;
        for (const auto& bp : previous) notes.insert(hardware_note(bp.kind));
        for (const auto& bp : next) notes.insert(hardware_note(bp.kind));
        for (const auto tid : tracked_) for (const auto note : notes) {
            auto snapshot = get_hwdebug_state(tid, note); if (!snapshot) return snapshot.error();
            states.emplace(Key{tid, note}, ThreadStateCopy{snapshot.value().state, snapshot.value().state, snapshot.value().slots});
        }

        for (const auto& old : previous) {
            const auto note = hardware_note(old.kind);
            auto encoding = hardware_encoding(old.address, old.kind, old.size); if (!encoding) return encoding.error();
            for (auto& [key, copy] : states) if (key.second == note) {
                if (hardware_unconfigured_threads_.contains(key.first)) continue;
                if (old.slot >= copy.slots) return Error{ErrorCode::malformed, "owned AArch64 hardware breakpoint slot disappeared"};
                const auto& reg = copy.before.registers[old.slot];
                const auto expected_control = old.enabled ? encoding.value().second : 0u;
                const auto expected_address = old.enabled ? encoding.value().first : 0u;
                if (reg.control != expected_control || reg.address != expected_address)
                    return Error{ErrorCode::conflict, "target AArch64 hardware-debug slot changed outside this session"};
            }
        }
        std::set<std::pair<unsigned long, std::uint8_t>> occupied;
        for (const auto& bp : next) {
            const auto note = hardware_note(bp.kind);
            if (!occupied.emplace(note, bp.slot).second)
                return Error{ErrorCode::conflict, "AArch64 hardware breakpoint slot is assigned more than once"};
            auto encoding = hardware_encoding(bp.address, bp.kind, bp.size); if (!encoding) return encoding.error();
            for (auto& [key, copy] : states) if (key.second == note) {
                if (bp.slot >= copy.slots) return Error{ErrorCode::resource_limit, "AArch64 hardware breakpoint slot is unavailable on a target thread"};
                const bool was_owned = std::any_of(previous.begin(), previous.end(), [&](const auto& old) {
                    return old.id == bp.id && hardware_note(old.kind) == note && old.slot == bp.slot;
                });
                const auto& current = copy.before.registers[bp.slot];
                if (!was_owned && (current.control != 0 || current.address != 0))
                    return Error{ErrorCode::conflict, "selected AArch64 hardware breakpoint slot is already occupied"};
                if (was_owned && hardware_unconfigured_threads_.contains(key.first) &&
                    (current.control != 0 || current.address != 0)) {
                    const auto old = std::find_if(previous.begin(), previous.end(), [&](const auto& item) {
                        return item.id == bp.id && hardware_note(item.kind) == note && item.slot == bp.slot;
                    });
                    auto old_encoding = hardware_encoding(old->address, old->kind, old->size);
                    if (!old_encoding) return old_encoding.error();
                    const auto old_control = old->enabled ? old_encoding.value().second : 0u;
                    const auto old_address = old->enabled ? old_encoding.value().first : 0u;
                    if (current.control != old_control || current.address != old_address)
                        return Error{ErrorCode::conflict, "unconfigured thread has a conflicting AArch64 hardware-debug slot"};
                }
                auto& reg = copy.after.registers[bp.slot];
                reg.address = bp.enabled ? encoding.value().first : 0;
                reg.control = bp.enabled ? encoding.value().second : 0;
            }
        }
        for (const auto& old : previous) {
            const bool retained = std::any_of(next.begin(), next.end(), [&](const auto& bp) { return bp.id == old.id; });
            if (retained) continue;
            const auto note = hardware_note(old.kind);
            for (auto& [key, copy] : states) if (key.second == note) {
                copy.after.registers[old.slot].address = 0;
                copy.after.registers[old.slot].control = 0;
            }
        }

        std::vector<Key> applied;
        for (const auto& [key, copy] : states) {
            if (std::memcmp(&copy.before, &copy.after, sizeof(copy.before)) == 0) continue;
            auto status = set_hwdebug_state(key.first, key.second, copy.after, copy.slots);
            if (!status) {
                auto message = status.error().message;
                for (auto it = applied.rbegin(); it != applied.rend(); ++it) {
                    const auto& prior = states.at(*it);
                    auto rollback = set_hwdebug_state(it->first, it->second, prior.before, prior.slots);
                    if (!rollback) message += "; rollback failed: " + rollback.error().message;
                }
                return Error{status.error().code, std::move(message)};
            }
            applied.push_back(key);
        }
        hardware_unconfigured_threads_.clear();
        return std::monostate{};
    }
    Status configure_hardware_for_new_thread(pid_t tid) {
        std::set<unsigned long> notes;
        for (const auto& bp : hardware_breakpoints_) notes.insert(hardware_note(bp.kind));
        std::map<unsigned long, HwdebugSnapshot> snapshots;
        for (const auto note : notes) {
            auto snapshot = get_hwdebug_state(tid, note); if (!snapshot) return snapshot.error();
            snapshots.emplace(note, snapshot.value());
        }
        std::map<unsigned long, Aarch64HwdebugState> originals;
        for (const auto& [note, snapshot] : snapshots) originals.emplace(note, snapshot.state);
        for (const auto& bp : hardware_breakpoints_) {
            const auto note = hardware_note(bp.kind);
            auto& snapshot = snapshots.at(note);
            if (bp.slot >= snapshot.slots) return Error{ErrorCode::resource_limit, "new thread lacks an owned AArch64 hardware breakpoint slot"};
            auto encoding = hardware_encoding(bp.address, bp.kind, bp.size); if (!encoding) return encoding.error();
            const auto& reg = snapshot.state.registers[bp.slot];
            const auto wanted_control = bp.enabled ? encoding.value().second : 0u;
            const auto wanted_address = bp.enabled ? encoding.value().first : 0u;
            if ((reg.control != 0 || reg.address != 0) &&
                (reg.control != wanted_control || reg.address != wanted_address))
                return Error{ErrorCode::conflict, "new thread inherited a conflicting AArch64 hardware-debug slot"};
            snapshot.state.registers[bp.slot].control = wanted_control;
            snapshot.state.registers[bp.slot].address = wanted_address;
        }
        std::vector<unsigned long> applied;
        for (const auto& [note, snapshot] : snapshots) {
            auto status = set_hwdebug_state(tid, note, snapshot.state, snapshot.slots);
            if (!status) {
                auto message = status.error().message;
                for (auto it = applied.rbegin(); it != applied.rend(); ++it) {
                    const auto& old = snapshots.at(*it);
                    auto rollback = set_hwdebug_state(tid, *it, originals.at(*it), old.slots);
                    if (!rollback) message += "; new-thread rollback failed: " + rollback.error().message;
                }
                return Error{status.error().code, std::move(message)};
            }
            applied.push_back(note);
        }
        return std::monostate{};
    }
    Status restore_hardware_execute_step() {
        if (!hardware_step_state_) return std::monostate{};
        const auto saved = *hardware_step_state_;
        if (!stopped_.contains(saved.thread))
            return Error{ErrorCode::busy, "AArch64 execute-breakpoint step thread must be stopped before restoring debug registers"};
        auto restored = set_hwdebug_state(saved.thread, nt_arm_hw_break, saved.saved, saved.slots);
        if (!restored) return restored;
        hardware_step_state_.reset();
        return std::monostate{};
    }
    Status begin_hardware_execute_step(pid_t tid, std::uint64_t address) {
        auto safe = require_all_threads_stopped(); if (!safe) return safe;
        auto configured = ensure_hardware_breakpoints_configured(); if (!configured) return configured;
        auto snapshot = get_hwdebug_state(tid, nt_arm_hw_break); if (!snapshot) return snapshot.error();
        auto temporarily_disabled = snapshot.value().state;
        bool found = false;
        for (const auto& bp : hardware_breakpoints_) {
            if (!bp.enabled || !hardware_execute_kind(bp.kind) || bp.address != address) continue;
            if (bp.slot >= snapshot.value().slots)
                return Error{ErrorCode::malformed, "owned AArch64 execute-breakpoint slot disappeared before step-over"};
            auto encoding = hardware_encoding(bp.address, bp.kind, bp.size); if (!encoding) return encoding.error();
            const auto& current = snapshot.value().state.registers[bp.slot];
            if (current.control != encoding.value().second || current.address != encoding.value().first)
                return Error{ErrorCode::conflict, "AArch64 execute-breakpoint slot changed before step-over"};
            temporarily_disabled.registers[bp.slot].control = 0;
            found = true;
        }
        if (!found) return Error{ErrorCode::invalid_argument, "no enabled AArch64 execute breakpoint matches the stopped PC"};
        auto disabled = set_hwdebug_state(tid, nt_arm_hw_break, temporarily_disabled, snapshot.value().slots);
        if (!disabled) return disabled;
        hardware_step_state_ = Aarch64HardwareStepState{tid, snapshot.value().state, snapshot.value().slots};
        if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) != 0) {
            const auto error = sys_error("PTRACE_SINGLESTEP over AArch64 hardware breakpoint");
            auto restored = restore_hardware_execute_step();
            if (!restored)
                return Error{error.code, error.message + "; hardware-breakpoint restore failed: " + restored.error().message};
            return error;
        }
        pending_hardware_execute_ = false;
        step_thread_ = tid; step_pending_ = true; stopped_.erase(tid);
        return std::monostate{};
    }
    Status ensure_hardware_breakpoints_configured() {
        WaitScope scope(*this);
        if (detaching_ || startup_cleanup_)
            return Error{ErrorCode::busy, "cleanup is incomplete; retry detach or terminate before resuming"};
        if (tracked_.size() > max_inspection_threads)
            return Error{ErrorCode::resource_limit, "cloned-thread limit exceeded; detach or terminate is required"};
        const std::vector<pid_t> children(initial_children_.begin(), initial_children_.end());
        for (const auto child : children) { auto ready = finish_cloned_thread(child); if (!ready) return ready; }
        if (!interrupting_.empty()) { auto stopped = stop_all_threads(); if (!stopped) return stopped; }
        auto restored = restore_hardware_execute_step(); if (!restored) return restored;
        if (hardware_breakpoints_.empty()) return std::monostate{};
        for (const auto tid : hardware_unconfigured_threads_) {
            if (!stopped_.contains(tid))
                return Error{ErrorCode::busy, "cannot resume while a thread lacks owned AArch64 hardware breakpoints"};
            auto configured = configure_hardware_for_new_thread(tid);
            if (!configured) return configured;
        }
        hardware_unconfigured_threads_.clear();
        hardware_configuration_error_.clear();
        return std::monostate{};
    }
    Status begin_breakpoint_step(pid_t tid, std::uint64_t address) {
        auto safe = require_all_threads_stopped(); if (!safe) return safe;
        auto configured = ensure_hardware_breakpoints_configured(); if (!configured) return configured;
        auto regs = get_regs(tid); if (!regs) return regs.error();
        regs.value().value[32] = address;
        auto moved = set_regs(tid, regs.value()); if (!moved) return moved;
        auto restored = write_raw(address, original_instruction(address)); if (!restored) return restored;
        if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) != 0) {
            const auto error = sys_error("PTRACE_SINGLESTEP over breakpoint");
            constexpr std::array<std::byte, 4> brk{std::byte{0x00}, std::byte{0x00}, std::byte{0x20}, std::byte{0xd4}};
            auto rearmed = write_raw(address, brk);
            if (!rearmed) return Error{error.code, error.message + "; breakpoint rearm failed: " + rearmed.error().message};
            return error;
        }
        step_breakpoint_ = address; step_thread_ = tid; step_pending_ = true; stopped_.erase(tid);
        return std::monostate{};
    }
    Status stop_all_threads() {
        WaitScope scope(*this);
        // Each previously running owned thread can report one automatically
        // attached child before stopping. Cleanup allows that bounded surplus;
        // normal resume still rejects anything above the inspection cap.
        if (tracked_.size() > 2 * max_inspection_threads)
            return Error{ErrorCode::resource_limit, "target thread count exceeds the inspection limit"};
        const std::vector<pid_t> children(initial_children_.begin(), initial_children_.end());
        for (const auto child : children) { auto ready = finish_cloned_thread(child); if (!ready) return ready; }
        const std::vector<pid_t> census(tracked_.begin(), tracked_.end());
        for (const auto tid : census) {
            auto progress = wait_progress(); if (!progress) return progress;
            if (stopped_.contains(tid) || deferred_.contains(tid) || interrupting_.contains(tid)) continue;
            if (!seized_.contains(tid)) return Error{ErrorCode::unsupported, "safe process-wide suspension requires PTRACE_SEIZE ownership"};
            if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) == 0) interrupting_.insert(tid);
            else if (errno == ESRCH) {
                int status{}; const auto waited = waitpid(tid, &status, __WALL | WNOHANG);
                if (waited == tid) {
                    if (WIFSTOPPED(status)) {
                        stopped_.insert(tid);
                        if ((static_cast<unsigned>(status) >> 16) == PTRACE_EVENT_CLONE) {
                            deferred_[tid] = status;
                            auto child = track_cloned_thread(tid); if (!child) return child;
                        }
                        deferred_[tid] = status;
                    } else { tracked_.erase(tid); seized_.erase(tid); stopped_.erase(tid); deferred_[tid] = status; }
                } else if (waited < 0 && errno != ECHILD && errno != EINTR) return sys_error("waitpid after PTRACE_INTERRUPT ESRCH");
            } else return sys_error("PTRACE_INTERRUPT peer thread");
        }
        while (!interrupting_.empty()) {
            // Child initial-stop collection can erase another pending TID.
            // Poll a snapshot rather than retaining iterators across that call.
            const std::vector<pid_t> polling(interrupting_.begin(), interrupting_.end());
            for (const auto tid : polling) {
                auto progress = wait_progress(); if (!progress) return progress;
                if (!interrupting_.contains(tid)) continue;
                int status{}; const auto waited = waitpid(tid, &status, __WALL | WNOHANG);
                if (waited == tid) {
                    interrupting_.erase(tid);
                    if (WIFSTOPPED(status)) {
                        stopped_.insert(tid);
                        const auto event = static_cast<unsigned>(status) >> 16;
                        if (event == PTRACE_EVENT_CLONE) {
                            deferred_[tid] = status;
                            auto child = track_cloned_thread(tid);
                            if (!child) return child;
                        } else if (!(WSTOPSIG(status) == SIGTRAP && event == PTRACE_EVENT_STOP)) deferred_[tid] = status;
                    } else {
                        forget_thread(tid); deferred_[tid] = status;
                    }
                } else if (waited < 0 && errno != EINTR && errno != ECHILD && errno != ESRCH) return sys_error("waitpid while suspending peer thread");
            }
            if (interrupting_.empty()) break;
            auto progress = wait_progress(); if (!progress) return progress;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (stopped_ != tracked_) return Error{ErrorCode::busy, "not every owned target thread reached a ptrace stop"};
        return std::monostate{};
    }
    Status finish_cloned_thread(pid_t child) {
        auto status = wait_status(child);
        if (!status) {
            if (status.error().code == ErrorCode::out_of_bounds) { forget_thread(child); return std::monostate{}; }
            return status.error();
        }
        if (WIFEXITED(status.value()) || WIFSIGNALED(status.value())) {
            forget_thread(child); deferred_[child] = status.value(); return std::monostate{};
        }
        if (!WIFSTOPPED(status.value())) return Error{ErrorCode::io, "cloned thread did not enter a ptrace stop"};
        stopped_.insert(child); interrupting_.erase(child); initial_children_.erase(child);
        const auto event = static_cast<unsigned>(status.value()) >> 16;
        if (event != PTRACE_EVENT_STOP) deferred_[child] = status.value();
        if (!hardware_breakpoints_.empty()) {
            auto configured = configure_hardware_for_new_thread(child);
            if (!configured) {
                hardware_unconfigured_threads_.insert(child);
                hardware_configuration_error_ = configured.error().message;
            }
        }
        return std::monostate{};
    }
    Status track_cloned_thread(pid_t parent) {
        WaitScope scope(*this);
        unsigned long child_id{};
        if (ptrace(PTRACE_GETEVENTMSG, parent, nullptr, &child_id) != 0) return sys_error("PTRACE_GETEVENTMSG clone");
        if (!child_id || child_id > static_cast<unsigned long>(std::numeric_limits<pid_t>::max()))
            return Error{ErrorCode::malformed, "PTRACE_EVENT_CLONE returned an invalid child thread id"};
        const auto child = static_cast<pid_t>(child_id);
        if (child == parent) return Error{ErrorCode::malformed, "PTRACE_EVENT_CLONE returned its parent thread id"};
        if (tracked_.contains(child) && !initial_children_.contains(child)) return std::monostate{};
        // PTRACE_O_TRACECLONE already granted ownership. Record it before any
        // timeout/count check so cleanup cannot forget a kernel-owned child.
        tracked_.insert(child); seized_.insert(child); initial_children_.insert(child);
        if (tracked_.size() > max_inspection_threads)
            return Error{ErrorCode::resource_limit, "target exceeds the thread inspection limit; cloned-thread ownership retained"};
        return finish_cloned_thread(child);
    }
    Status resume_stopped_threads(pid_t event_thread, int signal) {
        WaitScope scope(*this);
        auto configured = ensure_hardware_breakpoints_configured(); if (!configured) return configured;
        std::vector<pid_t> candidates;
        for (const auto tid : stopped_) if (tid != event_thread && !deferred_.contains(tid)) candidates.push_back(tid);
        if (stopped_.contains(event_thread) && !deferred_.contains(event_thread)) candidates.push_back(event_thread);
        std::vector<pid_t> resumed;
        for (const auto tid : candidates) {
            const auto deferred_signal = deferred_signals_.find(tid);
            const int delivered = tid == event_thread ? signal :
                deferred_signal == deferred_signals_.end() ? 0 : deferred_signal->second;
            if (ptrace(PTRACE_CONT, tid, nullptr, reinterpret_cast<void*>(static_cast<std::intptr_t>(delivered))) != 0) {
                const auto error = sys_error("PTRACE_CONT target thread");
                rollback_threads_ = resumed;
                auto rollback = stop_threads_for_rollback(resumed);
                if (!rollback) {
                    resume_blocked_ = true;
                    return Error{error.code, error.message + "; resume rollback failed: " + rollback.error().message};
                }
                rollback_threads_.clear();
                return error;
            }
            deferred_signals_.erase(tid);
            stopped_.erase(tid); resumed.push_back(tid);
        }
        return std::monostate{};
    }
    Status recover_resume_rollback() {
        if (!resume_blocked_) return std::monostate{};
        auto stopped = stop_threads_for_rollback(rollback_threads_);
        if (!stopped) return Error{stopped.error().code,
            "resume rollback is still incomplete: " + stopped.error().message};
        rollback_threads_.clear();
        resume_blocked_ = false;
        return std::monostate{};
    }
    Status stop_threads_for_rollback(const std::vector<pid_t>& threads) {
        WaitScope scope(*this);
        for (const auto tid : threads) {
            if (stopped_.contains(tid) || interrupting_.contains(tid)) continue;
            if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) == 0) interrupting_.insert(tid);
            else if (errno == ESRCH || errno == EIO) interrupting_.insert(tid);
            else return sys_error("PTRACE_INTERRUPT during resume rollback");
        }
        for (const auto tid : threads) {
            if (stopped_.contains(tid)) continue;
            auto status = wait_status(tid, false);
            if (!status) {
                if (status.error().code == ErrorCode::out_of_bounds) { forget_thread(tid); continue; }
                return status.error();
            }
            interrupting_.erase(tid);
            if (WIFEXITED(status.value()) || WIFSIGNALED(status.value())) {
                forget_thread(tid); deferred_[tid] = status.value(); continue;
            }
            if (!WIFSTOPPED(status.value())) return Error{ErrorCode::io, "thread did not stop during resume rollback"};
            stopped_.insert(tid);
            const auto event = static_cast<unsigned>(status.value()) >> 16;
            if (!(WSTOPSIG(status.value()) == SIGTRAP && event == PTRACE_EVENT_STOP)) deferred_[tid] = status.value();
            if (event == PTRACE_EVENT_CLONE) {
                auto child = track_cloned_thread(tid); if (!child) return child;
            }
        }
        return std::monostate{};
    }
    Status require_stopped_thread(ThreadId thread) const {
        if (!pid_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        if (thread > static_cast<ThreadId>(std::numeric_limits<pid_t>::max()) ||
            !tracked_.contains(static_cast<pid_t>(thread)))
            return Error{ErrorCode::invalid_argument, "thread is not owned by this debug session"};
        if (!stopped_.contains(static_cast<pid_t>(thread)))
            return Error{ErrorCode::busy, "register access requires the selected thread to be stopped"};
        return std::monostate{};
    }
    Status require_all_threads_stopped() const {
        if (!pid_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        std::set<pid_t> observed; std::error_code ec;
        const auto path = "/proc/" + std::to_string(pid_) + "/task";
        for (std::filesystem::directory_iterator it(path, ec), end; !ec && it != end; it.increment(ec)) {
            pid_t tid{}; if (!parse_pid(it->path().filename().string(), tid)) continue;
            observed.insert(tid);
            if (observed.size() > (tracked_.size() > max_inspection_threads ? 2 * max_inspection_threads : max_inspection_threads))
                return Error{ErrorCode::resource_limit, "target thread count exceeds the inspection limit"};
        }
        if (ec) return Error{ErrorCode::io, "failed to enumerate target threads before memory modification: " + ec.message()};
        if (observed != tracked_ || stopped_ != tracked_)
            return Error{ErrorCode::busy, "memory and software-breakpoint writes require every process thread to be traced and stopped"};
        return std::monostate{};
    }
    std::vector<std::byte> original_instruction(std::uint64_t at) const { return {originals_.at(at), extra_originals_.at(at)[0], extra_originals_.at(at)[1], extra_originals_.at(at)[2]}; }
    Status write_raw(std::uint64_t address, std::span<const std::byte> bytes) {
        constexpr std::size_t word_size = sizeof(long);
        if (!pid_ || bytes.size() > max_inspection_read || address > UINT64_MAX - bytes.size())
            return Error{ErrorCode::invalid_argument, "invalid raw AArch64 memory write range"};
        for (std::size_t i = 0; i < bytes.size();) {
            const auto at = address + i;
            const auto offset = static_cast<std::size_t>(at % word_size);
            const auto aligned = at - offset;
            const auto count = std::min(word_size - offset, bytes.size() - i);
            long word{};
            if (offset != 0 || count != word_size) {
                errno = 0;
                word = ptrace(PTRACE_PEEKDATA, pid_, reinterpret_cast<void*>(static_cast<std::uintptr_t>(aligned)), nullptr);
                if (word == -1 && errno) return sys_error("PTRACE_PEEKDATA before write");
            }
            std::memcpy(reinterpret_cast<std::byte*>(&word) + offset, bytes.data() + i, count);
            if (ptrace(PTRACE_POKEDATA, pid_, reinterpret_cast<void*>(static_cast<std::uintptr_t>(aligned)), reinterpret_cast<void*>(word)) != 0)
                return sys_error("PTRACE_POKEDATA");
            i += count;
        }
        return std::monostate{};
    }
    void clear() { initial_children_.clear(); startup_cleanup_ = false; startup_kill_ = false; detaching_ = false; detach_hardware_cleared_ = false; pid_ = 0; tracked_.clear(); stopped_.clear(); seized_.clear(); deferred_.clear(); deferred_signals_.clear(); interrupting_.clear(); rollback_threads_.clear(); resume_blocked_ = false; hardware_unconfigured_threads_.clear(); hardware_configuration_error_.clear(); hardware_step_state_.reset(); pending_.reset(); pending_thread_ = 0; pending_signal_ = 0; pending_breakpoint_.reset(); pending_hardware_execute_ = false; pending_hardware_execute_address_ = 0; initial_ = false; exited_ = false; step_breakpoint_.reset(); step_thread_ = 0; step_pending_ = false; breakpoints_.clear(); originals_.clear(); extra_originals_.clear(); ids_.clear(); enabled_.clear(); hardware_breakpoints_.clear(); }
    pid_t pid_ = 0, pending_thread_ = 0, step_thread_ = 0; int pending_signal_ = 0; bool initial_ = false, exited_ = false, step_pending_ = false; std::uint64_t seq_ = 0; BreakpointId next_id_ = 1; int last_signal_ = SIGTRAP;
    std::set<pid_t> tracked_, stopped_, seized_, interrupting_; std::map<pid_t, int> deferred_, deferred_signals_; std::vector<pid_t> rollback_threads_; bool resume_blocked_ = false; std::optional<std::uint64_t> pending_, pending_breakpoint_, step_breakpoint_;
    std::map<std::uint64_t, std::byte> breakpoints_, originals_; std::map<std::uint64_t, std::array<std::byte, 3>> extra_originals_; std::map<BreakpointId, std::uint64_t> ids_; std::set<std::uint64_t> enabled_;
    std::vector<Aarch64HardwareBreakpoint> hardware_breakpoints_;
    std::set<pid_t> hardware_unconfigured_threads_;
    std::string hardware_configuration_error_;
    std::optional<Aarch64HardwareStepState> hardware_step_state_;
    bool pending_hardware_execute_ = false;
    std::uint64_t pending_hardware_execute_address_ = 0;
    const std::chrono::milliseconds wait_timeout_ = configured_wait_timeout();
    std::optional<Clock::time_point> wait_deadline_;
    std::atomic<bool> wait_active_{false}, wait_stop_requested_{false};
    bool startup_cleanup_ = false, startup_kill_ = false, detaching_ = false, detach_hardware_cleared_ = false, event_polling_ = false;
    std::set<pid_t> initial_children_;
};

std::unique_ptr<Backend> make_native_backend() { return std::make_unique<LinuxAarch64Backend>(); }
} // namespace hexlab::debugger

