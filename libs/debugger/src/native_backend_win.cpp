#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include "hexlab/debugger/debugger.hpp"
#include "breakpoint_step_state.hpp"
#include "hardware_breakpoint_state.hpp"
#include "thread_suspend_state.hpp"
#include "x86_fp_registers.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <new>
#if defined(_M_X64)
#include <intrin.h>
#endif

namespace hexlab::debugger {
namespace {
Error win_error(const char* action) {
    return {ErrorCode::io, std::string(action) + " failed (Win32 error " + std::to_string(GetLastError()) + ")"};
}
std::string narrow(const wchar_t* value) {
    if (!value || !*value) return {};
    const auto count = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (count <= 1) return {};
    std::string out(static_cast<std::size_t>(count), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, out.data(), count, nullptr, nullptr);
    out.pop_back();
    return out;
}
std::wstring widen(const std::string& value) {
    if (value.empty()) return {};
    const auto count = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (count <= 0) return {};
    std::wstring out(static_cast<std::size_t>(count), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(), count);
    return out;
}
std::wstring quote(const std::string& argument) {
    const auto input = widen(argument);
    std::wstring out(1, L'"');
    std::size_t slashes = 0;
    for (wchar_t ch : input) {
        if (ch == L'\\') { ++slashes; continue; }
        if (ch == L'"') { out.append(slashes * 2 + 1, L'\\'); out.push_back(ch); slashes = 0; continue; }
        out.append(slashes, L'\\'); slashes = 0; out.push_back(ch);
    }
    out.append(slashes * 2, L'\\');
    out.push_back(L'"');
    return out;
}
template<class T> void append_register(std::vector<RegisterValue>& out, const char* name, T value) {
    RegisterValue reg; reg.name = name; reg.byte_order = ByteOrder::little; reg.bytes.resize(sizeof(value)); std::memcpy(reg.bytes.data(), &value, sizeof(value)); out.push_back(std::move(reg));
}
Status append_x86_fp_registers(std::vector<RegisterValue>& out, std::span<const std::byte> image,
                              bool i386) {
    auto decoded = i386 ? detail::x86_i386_fxsave_register_values(image)
                        : detail::x86_fxsave_register_values(image);
    if (!decoded) return decoded.error();
    for (auto& reg : decoded.value()) {
        reg.group = reg.name.starts_with("xmm") ? "vector" : "floating-point";
        reg.byte_order = ByteOrder::little;
        if (reg.name.starts_with("xmm")) {
            std::uint32_t index = 0;
            const auto parsed = std::from_chars(reg.name.data() + 3,
                reg.name.data() + reg.name.size(), index);
            if (parsed.ec == std::errc{} && parsed.ptr == reg.name.data() + reg.name.size())
                reg.number = index;
        }
        out.push_back(std::move(reg));
    }
    return std::monostate{};
}
template<class T> bool assign_register(const RegisterValue& reg, const char* name, T& value) {
    if (reg.name != name) return false;
    if (reg.bytes.size() != sizeof(value)) return false;
    std::memcpy(&value, reg.bytes.data(), sizeof(value));
    return true;
}

#if defined(_M_X64)
constexpr DWORD64 avx_feature_mask = UINT64_C(1) << 2;
constexpr DWORD64 sse_feature_mask = UINT64_C(1) << 1;
constexpr std::size_t ymm_upper_bytes = 16 * sizeof(M128A);

Error xstate_error(const char* action) {
    const auto code = GetLastError();
    const bool unavailable = code == ERROR_NOT_SUPPORTED || code == ERROR_INVALID_PARAMETER ||
        code == ERROR_INVALID_FUNCTION || code == ERROR_CALL_NOT_IMPLEMENTED;
    return {unavailable ? ErrorCode::unsupported : ErrorCode::io,
        std::string(action) + " failed (Win32 error " + std::to_string(code) + ")"};
}

struct XStateApi {
    DWORD64 (WINAPI *enabled)() = nullptr;
    BOOL (WINAPI *initialize)(PVOID, DWORD, PCONTEXT*, PDWORD) = nullptr;
    BOOL (WINAPI *get_mask)(PCONTEXT, PDWORD64) = nullptr;
    PVOID (WINAPI *locate)(PCONTEXT, DWORD, PDWORD) = nullptr;
    BOOL (WINAPI *set_mask)(PCONTEXT, DWORD64) = nullptr;
};
const XStateApi& xstate_api() {
    static const auto api = [] {
        XStateApi value;
        const auto kernel = GetModuleHandleW(L"kernel32.dll");
        if (!kernel) return value;
        value.enabled = reinterpret_cast<decltype(value.enabled)>(GetProcAddress(kernel, "GetEnabledXStateFeatures"));
        value.initialize = reinterpret_cast<decltype(value.initialize)>(GetProcAddress(kernel, "InitializeContext"));
        value.get_mask = reinterpret_cast<decltype(value.get_mask)>(GetProcAddress(kernel, "GetXStateFeaturesMask"));
        value.locate = reinterpret_cast<decltype(value.locate)>(GetProcAddress(kernel, "LocateXStateFeature"));
        value.set_mask = reinterpret_cast<decltype(value.set_mask)>(GetProcAddress(kernel, "SetXStateFeaturesMask"));
        return value;
    }();
    return api;
}
bool avx_context_enabled(const XStateApi& api) {
    if (!api.enabled || !api.initialize || !api.get_mask || !api.locate || !api.set_mask) return false;
    int cpu[4]{};
    __cpuid(cpu, 0);
    if (cpu[0] < 1) return false;
    __cpuid(cpu, 1);
    constexpr unsigned required_cpu = (1u << 26) | (1u << 27) | (1u << 28); // XSAVE, OSXSAVE, AVX.
    if ((static_cast<unsigned>(cpu[2]) & required_cpu) != required_cpu) return false;
    constexpr auto required_state = sse_feature_mask | avx_feature_mask;
    return (api.enabled() & required_state) == required_state;
}

struct X64AvxContext {
    std::vector<std::byte> storage;
    PCONTEXT context = nullptr;
    std::byte* upper = nullptr;
    X64AvxContext() = default;
    X64AvxContext(const X64AvxContext&) = delete;
    X64AvxContext& operator=(const X64AvxContext&) = delete;
    X64AvxContext(X64AvxContext&&) noexcept = default;
    X64AvxContext& operator=(X64AvxContext&&) noexcept = default;
    bool contains(const void* pointer, std::size_t size) const {
        const auto begin = reinterpret_cast<std::uintptr_t>(storage.data());
        const auto at = reinterpret_cast<std::uintptr_t>(pointer);
        return pointer && at >= begin && at - begin <= storage.size() && size <= storage.size() - (at - begin);
    }
};

Result<X64AvxContext> read_x64_avx_context(HANDLE thread) {
    const auto& api = xstate_api();
    if (!avx_context_enabled(api))
        return Error{ErrorCode::unsupported, "Windows YMM state requires enabled CPU/OS AVX context support"};
    constexpr DWORD requested = CONTEXT_FULL | CONTEXT_FLOATING_POINT | CONTEXT_XSTATE;
    DWORD size = 0;
    if (api.initialize(nullptr, requested, nullptr, &size) || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return Error{ErrorCode::unsupported, "Windows extended context sizing is unavailable"};
    constexpr DWORD maximum_context_bytes = 1024 * 1024;
    if (size < sizeof(CONTEXT) || size > maximum_context_bytes)
        return Error{ErrorCode::unsupported, "Windows extended context size is outside the supported bounds"};
    X64AvxContext result;
    try { result.storage.resize(size); }
    catch (const std::bad_alloc&) { return Error{ErrorCode::resource_limit, "Cannot allocate Windows AVX context"}; }
    DWORD initialized_size = size;
    if (!api.initialize(result.storage.data(), requested, &result.context, &initialized_size) ||
        initialized_size < sizeof(CONTEXT) || initialized_size > size || !result.contains(result.context, sizeof(CONTEXT)) ||
        reinterpret_cast<std::uintptr_t>(result.context) % alignof(CONTEXT) ||
        (result.context->ContextFlags & requested) != requested)
        return Error{ErrorCode::unsupported, "Windows did not initialize a complete x64 AVX context"};
    // Legacy XMM/x87/MXCSR arrive through CONTEXT_FLOATING_POINT. Request only
    // the AVX extension; no other extended feature is read or later submitted.
    DWORD64 selected = 0;
    if (!api.set_mask(result.context, avx_feature_mask) ||
        !api.get_mask(result.context, &selected) || selected != avx_feature_mask)
        return Error{ErrorCode::unsupported, "Windows AVX context feature selection failed"};
    if (!GetThreadContext(thread, result.context)) return xstate_error("GetThreadContext for x64 AVX state");
    if ((result.context->ContextFlags & requested) != requested)
        return Error{ErrorCode::unsupported, "Windows returned an incomplete x64 AVX context"};
    DWORD64 valid = 0;
    if (!api.get_mask(result.context, &valid) || (valid & ~avx_feature_mask))
        return Error{ErrorCode::unsupported, "Windows AVX context validity mask is unavailable"};
    DWORD feature_size = 0;
    result.upper = static_cast<std::byte*>(api.locate(result.context, XSTATE_AVX, &feature_size));
    if (feature_size != ymm_upper_bytes || !result.contains(result.upper, feature_size))
        return Error{ErrorCode::unsupported, "Windows YMM upper-half state has an unavailable or invalid extent"};
    const auto upper_begin = reinterpret_cast<std::uintptr_t>(result.upper);
    const auto context_begin = reinterpret_cast<std::uintptr_t>(result.context);
    if (upper_begin < context_begin + sizeof(CONTEXT) && context_begin < upper_begin + feature_size)
        return Error{ErrorCode::unsupported, "Windows AVX feature overlaps the legacy context"};
    // An absent valid bit means architectural INIT state, not unavailable
    // storage. Its saved bytes are undefined; materialize the zero upper halves.
    if (!(valid & avx_feature_mask)) std::memset(result.upper, 0, feature_size);
    return std::move(result);
}

Status validate_x64_vector_aliases(std::span<const RegisterValue> registers) {
    std::array<const RegisterValue*, 16> xmm{}, ymm{};
    for (const auto& reg : registers) {
        const bool is_ymm = reg.name.starts_with("ymm");
        if (!is_ymm && !reg.name.starts_with("xmm")) continue;
        std::uint32_t index = 0;
        const auto parsed = std::from_chars(reg.name.data() + 3, reg.name.data() + reg.name.size(), index);
        if (parsed.ec != std::errc{} || parsed.ptr != reg.name.data() + reg.name.size() || index >= 16 ||
            reg.name != std::string(is_ymm ? "ymm" : "xmm") + std::to_string(index) ||
            reg.bytes.size() != (is_ymm ? 32u : 16u) ||
            (reg.byte_order && *reg.byte_order != ByteOrder::little))
            return Error{ErrorCode::invalid_argument, "x64 vector edits require xmm0-15/16 bytes or ymm0-15/32 little-endian bytes"};
        auto& previous = is_ymm ? ymm[index] : xmm[index];
        if (previous && previous->bytes != reg.bytes)
            return Error{ErrorCode::conflict, "duplicate x64 vector edits disagree"};
        previous = &reg;
    }
    for (std::size_t index = 0; index < xmm.size(); ++index)
        if (xmm[index] && ymm[index] && !std::equal(xmm[index]->bytes.begin(), xmm[index]->bytes.end(), ymm[index]->bytes.begin()))
            return Error{ErrorCode::conflict, "overlapping XMM and YMM edits disagree on the lower 128 bits"};
    return std::monostate{};
}

void append_ymm_register(std::vector<RegisterValue>& out, std::uint32_t index, const X64AvxContext& state) {
    RegisterValue reg;
    reg.name = "ymm" + std::to_string(index);
    reg.group = "vector";
    reg.number = index;
    reg.byte_order = ByteOrder::little;
    reg.bytes.resize(32);
    std::memcpy(reg.bytes.data(), &state.context->FltSave.XmmRegisters[index], sizeof(M128A));
    std::memcpy(reg.bytes.data() + sizeof(M128A), state.upper + index * sizeof(M128A), sizeof(M128A));
    out.push_back(std::move(reg));
}
#endif

Architecture process_architecture(HANDLE process) {
    using IsWow64Process2Fn = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);
    const auto kernel = GetModuleHandleW(L"kernel32.dll");
    const auto is_wow64_process2 = kernel ? reinterpret_cast<IsWow64Process2Fn>(
        GetProcAddress(kernel, "IsWow64Process2")) : nullptr;
    if (is_wow64_process2) {
        USHORT process_machine = 0, native_machine = 0;
        if (is_wow64_process2(process, &process_machine, &native_machine)) {
            const USHORT machine = process_machine ? process_machine : native_machine;
            switch (machine) {
            case 0x014c: return Architecture::x86;       // IMAGE_FILE_MACHINE_I386
            case 0x8664: return Architecture::x86_64;    // IMAGE_FILE_MACHINE_AMD64
            case 0x01c4: return Architecture::arm;       // IMAGE_FILE_MACHINE_ARMNT
            case 0xaa64: return Architecture::arm64;      // IMAGE_FILE_MACHINE_ARM64
            default: return Architecture::unknown;
            }
        }
    }
    BOOL wow64 = FALSE;
    if (IsWow64Process(process, &wow64) && wow64) return Architecture::x86;
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    switch (info.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: return Architecture::x86_64;
    case PROCESSOR_ARCHITECTURE_INTEL: return Architecture::x86;
#ifdef PROCESSOR_ARCHITECTURE_ARM64
    case PROCESSOR_ARCHITECTURE_ARM64: return Architecture::arm64;
#endif
    case PROCESSOR_ARCHITECTURE_ARM: return Architecture::arm;
    default: return Architecture::unknown;
    }
}

struct Arm64DebugConfiguration {
    std::array<DWORD, 2> breakpoint_control{};
    std::array<DWORD64, 2> breakpoint_value{};
    std::array<DWORD, 2> watch_control{};
    std::array<DWORD64, 2> watch_value{};
    std::size_t breakpoint_count = 0, watch_count = 0;
};

struct Arm32DebugConfiguration {
    std::array<DWORD, 8> breakpoint_control{};
    std::array<DWORD, 8> breakpoint_value{};
    std::size_t breakpoint_count = 0;
};

std::optional<Arm32DebugConfiguration> encode_arm32_debug_configuration(
    const std::vector<detail::HardwareRequest>& requests) {
    // ARMv7 DBGBCR: enable, EL0-only PMC, and BAS for the selected instruction bytes.
    constexpr DWORD enable = 1u;
    constexpr DWORD user_mode = 2u << 1;
    Arm32DebugConfiguration config;
    for (const auto& request : requests) {
        if (request.kind != BreakpointKind::execute || request.size != 1 ||
            config.breakpoint_count == config.breakpoint_control.size() || request.address > UINT32_MAX)
            return {};
        const bool thumb = (request.address & 1u) != 0;
        const auto address = static_cast<DWORD>(request.address & ~std::uint64_t{1});
        DWORD bas = 0xfu;
        DWORD value = address;
        if (thumb) {
            if ((address & 1u) != 0) return {};
            // Thumb hardware breakpoints select a halfword within the aligned word.
            const auto lane = (address & 2u) ? 2u : 0u;
            bas = 0x3u << lane;
            value = address & ~DWORD{3};
        } else if ((address & 3u) != 0) {
            return {};
        }
        const auto slot = config.breakpoint_count++;
        config.breakpoint_control[slot] = enable | user_mode | (bas << 5);
        config.breakpoint_value[slot] = value;
    }
    return config;
}

struct Arm64HardwareStepState {
    DWORD thread = 0;
    std::array<bool, 2> owned{};
    std::array<DWORD, 2> control{};
    std::array<DWORD64, 2> value{};
};

std::optional<Arm64DebugConfiguration> encode_arm64_debug_configuration(
    const std::vector<detail::HardwareRequest>& requests) {
    // ARM64 DBGBCR/DBGWCR fields: E, EL0 privilege control, and BAS/LSC.
    // SSC remains zero for the normal non-secure user state.
    constexpr DWORD enable = 1u << 0;
    constexpr DWORD el0 = 2u << 1;
    Arm64DebugConfiguration config;
    for (const auto& request : requests) {
        if (request.kind == BreakpointKind::execute) {
            if (request.size != 1 || (request.address & 3u) != 0 || config.breakpoint_count == 2) return {};
            constexpr DWORD enabled_user_instruction = enable | el0 | (0xfu << 5);
            config.breakpoint_control[config.breakpoint_count] = enabled_user_instruction;
            config.breakpoint_value[config.breakpoint_count] = request.address;
            ++config.breakpoint_count;
            continue;
        }
        if (request.kind != BreakpointKind::read && request.kind != BreakpointKind::write &&
            request.kind != BreakpointKind::access) return {};
        if ((request.size != 1 && request.size != 2 && request.size != 4 && request.size != 8) ||
            config.watch_count == 2) return {};
        const auto lane = static_cast<unsigned>(request.address & 7u);
        if (lane + request.size > 8 || request.address % request.size != 0) return {};
        const auto bas = ((1u << request.size) - 1u) << lane;
        const DWORD load_store = request.kind == BreakpointKind::read ? 1u :
                                 request.kind == BreakpointKind::write ? 2u : 3u;
        config.watch_control[config.watch_count] = enable | el0 | (load_store << 3) | (bas << 5);
        config.watch_value[config.watch_count] = request.address & ~std::uint64_t{7};
        ++config.watch_count;
    }
    return config;
}

bool arm32_thumb_wide_prefix(std::uint16_t first) {
    return (first & 0xf800u) == 0xe800u || (first & 0xf000u) == 0xf000u;
}

// A temporary successor trap is a step only when the current instruction is
// known to fall through without writing PC or changing instruction state.
std::optional<std::size_t> arm32_linear_instruction_width(std::span<const std::byte> bytes, bool thumb) {
    if (bytes.size() < (thumb ? 2u : 4u)) return {};
    const auto halfword = static_cast<std::uint16_t>(std::to_integer<unsigned>(bytes[0]) |
        (std::to_integer<unsigned>(bytes[1]) << 8));
    if (thumb) {
        if (arm32_thumb_wide_prefix(halfword)) {
            if (bytes.size() < 4) return {};
            // MOVW/MOVT cannot write PC and have no branch or mode-change form.
            const auto second = static_cast<std::uint16_t>(std::to_integer<unsigned>(bytes[2]) |
                (std::to_integer<unsigned>(bytes[3]) << 8));
            return (((halfword & 0xfbf0u) == 0xf240u || (halfword & 0xfbf0u) == 0xf2c0u) &&
                    ((second >> 8) & 15u) != 15u)
                ? std::optional<std::size_t>{4} : std::nullopt;
        }
        if (halfword == 0xbf00u || halfword < 0x4400u ||
            (halfword >= 0x4800u && halfword < 0xb000u) ||
            (halfword >= 0xc000u && halfword < 0xd000u && (halfword & 0xffu) != 0)) return 2;
        return {};
    }
    const std::uint32_t word = static_cast<std::uint32_t>(halfword) |
        (std::to_integer<std::uint32_t>(bytes[2]) << 16) |
        (std::to_integer<std::uint32_t>(bytes[3]) << 24);
    // The A32 data-processing immediate class has no branch, exception, or
    // interworking form. Reject writes to PC and unconditional extensions.
    if ((word >> 28) == 15 || (word & 0x0e000000u) != 0x02000000u ||
        ((word >> 12) & 15u) == 15u) return {};
    return 4;
}

class Win32Backend final : public Backend {
public:
    ~Win32Backend() override { close_handles(); }

    Result<std::vector<ProcessInfo>> processes() override {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return win_error("CreateToolhelp32Snapshot");
        std::vector<ProcessInfo> result;
        result.reserve(max_inspection_processes);
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        BOOL available = Process32FirstW(snapshot, &entry);
        while (available) {
            if (result.size() == max_inspection_processes) {
                CloseHandle(snapshot);
                return Error{ErrorCode::resource_limit, "system process count exceeds the inspection limit"};
            }
            Architecture architecture = Architecture::unknown;
            HANDLE target = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
            if (target) {
                architecture = process_architecture(target);
                CloseHandle(target);
            }
            result.push_back(ProcessInfo{entry.th32ProcessID, narrow(entry.szExeFile), architecture});
            available = Process32NextW(snapshot, &entry);
        }
        CloseHandle(snapshot);
        return result;
    }

    Result<ProcessInfo> launch(const Target& target) override {
        if (process_) return Error{ErrorCode::busy, "backend already owns a debug target"};
        if (target.executable.empty()) return Error{ErrorCode::invalid_argument, "executable path is empty"};
        std::wstring command = quote(target.executable);
        for (const auto& argument : target.arguments) { command.push_back(L' '); command += quote(argument); }
        std::vector<wchar_t> command_buffer(command.begin(), command.end());
        command_buffer.push_back(L'\0');
        const auto executable = widen(target.executable);
        const auto directory = target.working_directory.empty() ? std::wstring{} : widen(target.working_directory);
        STARTUPINFOW startup{}; startup.cb = sizeof(startup);
        PROCESS_INFORMATION info{};
        if (!CreateProcessW(executable.c_str(), command_buffer.data(), nullptr, nullptr, FALSE,
                            DEBUG_ONLY_THIS_PROCESS | CREATE_UNICODE_ENVIRONMENT, nullptr,
                            directory.empty() ? nullptr : directory.c_str(), &startup, &info)) return win_error("CreateProcessW");
        process_ = info.hProcess; process_id_ = info.dwProcessId; launched_ = true; exited_ = false;
        architecture_ = process_architecture(process_);
        CloseHandle(info.hThread);
        return ProcessInfo{info.dwProcessId, target.executable, target_architecture()};
    }

    Result<ProcessInfo> attach(ProcessId id) override {
        if (process_) return Error{ErrorCode::busy, "backend already owns a debug target"};
        if (id == 0 || id > MAXDWORD) return Error{ErrorCode::invalid_argument, "invalid process id"};
        if (!DebugActiveProcess(static_cast<DWORD>(id))) return win_error("DebugActiveProcess");
        process_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_SUSPEND_RESUME,
                               FALSE, static_cast<DWORD>(id));
        if (!process_) { const auto error = win_error("OpenProcess"); DebugActiveProcessStop(static_cast<DWORD>(id)); return error; }
        // Termination is an optional session operation. Keep the debugger's
        // inspection handle usable even when policy denies this extra right.
        terminate_process_ = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, static_cast<DWORD>(id));
        process_id_ = static_cast<DWORD>(id); launched_ = false; exited_ = false;
        architecture_ = process_architecture(process_);
        wchar_t path[32768]{}; DWORD length = static_cast<DWORD>(std::size(path));
        std::string name;
        if (QueryFullProcessImageNameW(process_, 0, path, &length)) name = narrow(path);
        return ProcessInfo{id, std::move(name), target_architecture()};
    }

    Status detach() override {
        auto step_resumed = resume_step_suspensions();
        if (!step_resumed) return step_resumed;
        if (exited_) { exited_ = false; process_id_ = 0; return std::monostate{}; }
        if (!process_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        const bool process_exit_event = pending_ && pending_->dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT;
        if (process_exit_event) {
            if (!ContinueDebugEvent(pending_->dwProcessId, pending_->dwThreadId, DBG_CONTINUE)) return win_error("ContinueDebugEvent");
            close_event_handles(*pending_);
            pending_.reset();
            if (process_) CloseHandle(process_);
            close_terminate_handle();
            process_ = nullptr; process_id_ = 0; launched_ = false;
            breakpoints_.clear(); stepping_breakpoint_.clear(); hardware_breakpoints_.clear(); arm64_step_thread_.reset(); arm64_step_original_cpsr_.reset(); arm64_hardware_step_.reset(); exited_ = true;
            return std::monostate{};
        }
        if (!pending_) {
            DEBUG_EVENT queued{};
            if (WaitForDebugEvent(&queued, 0)) pending_ = queued;
            else if (GetLastError() != ERROR_SEM_TIMEOUT) return win_error("WaitForDebugEvent before detach");
        }
        if (!pending_) {
            // Ask Windows to deliver a breakpoint event, giving the normal
            // debug-event protocol a stable stop point for state cleanup.
            if (!DebugBreakProcess(process_)) return win_error("DebugBreakProcess for detach");
            DEBUG_EVENT event{};
            if (!WaitForDebugEvent(&event, 5000)) {
                if (GetLastError() == ERROR_SEM_TIMEOUT)
                    return Error{ErrorCode::busy, "timed out waiting for the target to stop for detach"};
                return win_error("WaitForDebugEvent for detach");
            }
            pending_ = event;
        }
        if (arm32_step_) {
            auto restored = restore_arm32_step();
            if (!restored) return restored;
        }
        if (!hardware_breakpoints_.empty()) {
            auto cleared = update_hardware_registers({}, hardware_requests());
            if (!cleared) return cleared;
            hardware_breakpoints_.clear();
        }
        for (auto it = breakpoints_.begin(); it != breakpoints_.end();) {
            auto restored = patch_bytes(it->first, it->second.original);
            if (!restored) return restored;
            it = breakpoints_.erase(it);
        }
        // Restore owned state while a pending event still holds the target
        // stopped. In particular, do not resume through an owned INT3 and
        // only then try to put the original byte back.
        if (pending_) {
            if (!ContinueDebugEvent(pending_->dwProcessId, pending_->dwThreadId, DBG_CONTINUE)) return win_error("ContinueDebugEvent");
            close_event_handles(*pending_);
            pending_.reset();
        }
        if (process_id_) {
            DWORD stop_error = ERROR_SUCCESS;
            bool stopped = false;
            for (int attempt = 0; attempt < 50; ++attempt) {
                if (DebugActiveProcessStop(process_id_)) { stopped = true; break; }
                stop_error = GetLastError();
                if (stop_error != ERROR_ACCESS_DENIED) break;
                if (process_ && WaitForSingleObject(process_, 0) == WAIT_OBJECT_0) {
                    CloseHandle(process_); close_terminate_handle(); process_ = nullptr; process_id_ = 0; launched_ = false;
                    breakpoints_.clear(); stepping_breakpoint_.clear(); hardware_breakpoints_.clear(); arm64_step_thread_.reset(); arm64_step_original_cpsr_.reset(); arm64_hardware_step_.reset(); exited_ = true;
                    return std::monostate{};
                }
                Sleep(2);
            }
            if (!stopped) {
                const Error error{ErrorCode::io, "DebugActiveProcessStop failed (Win32 error " + std::to_string(stop_error) + ")"};
                return error;
            }
        }
        close_handles();
        return std::monostate{};
    }

    Status request_interrupt() override {
        if (!process_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        if (exited_) return Error{ErrorCode::invalid_argument, "debug target has exited"};
        if (!DebugBreakProcess(process_)) return win_error("DebugBreakProcess");
        return std::monostate{};
    }

    Status terminate() override {
        if (!process_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        if (pending_ && pending_->dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
            return continue_event(sequence_, ContinueStatus::handled);

        HANDLE termination_handle = launched_ ? process_ : terminate_process_;
        if (!termination_handle)
            return Error{ErrorCode::unsupported, "attached process handle does not grant termination access"};

        const auto process_state = WaitForSingleObject(termination_handle, 0);
        if (process_state == WAIT_FAILED) return win_error("WaitForSingleObject before terminate");
        if (process_state != WAIT_OBJECT_0 && !TerminateProcess(termination_handle, ERROR_CANCELLED)) {
            const auto error = win_error("TerminateProcess");
            if (WaitForSingleObject(termination_handle, 0) != WAIT_OBJECT_0) return error;
        }

        // A pending debug event keeps its reporting thread suspended. After
        // termination was requested, acknowledge it so Windows can deliver the
        // process exit event and the backend can close every event-owned handle.
        if (pending_) {
            if (!ContinueDebugEvent(pending_->dwProcessId, pending_->dwThreadId, DBG_CONTINUE))
                return win_error("ContinueDebugEvent during terminate");
            close_event_handles(*pending_);
            pending_.reset();
        }

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        for (;;) {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now());
            if (remaining <= std::chrono::milliseconds::zero())
                return Error{ErrorCode::busy, "timed out waiting for the terminated process exit event"};
            DEBUG_EVENT event{};
            const auto wait_ms = static_cast<DWORD>(std::clamp<std::int64_t>(remaining.count(), 1, MAXDWORD - 1));
            if (!WaitForDebugEvent(&event, wait_ms)) {
                if (GetLastError() == ERROR_SEM_TIMEOUT)
                    return Error{ErrorCode::busy, "timed out waiting for the terminated process exit event"};
                return win_error("WaitForDebugEvent during terminate");
            }
            if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE)) {
                pending_ = event;
                return win_error("ContinueDebugEvent during terminate");
            }
            close_event_handles(event);
            if (event.dwDebugEventCode != EXIT_PROCESS_DEBUG_EVENT) continue;

            if (process_) CloseHandle(process_);
            close_terminate_handle();
            process_ = nullptr;
            process_id_ = 0;
            launched_ = false;
            exited_ = true;
            pending_.reset();
            breakpoints_.clear();
            stepping_breakpoint_.clear();
            hardware_breakpoints_.clear();
            arm64_step_thread_.reset();
            arm64_step_original_cpsr_.reset();
            for (HANDLE thread : step_suspension_handles_) CloseHandle(thread);
            step_suspension_handles_.clear();
            step_suspended_threads_.clear();
            return std::monostate{};
        }
    }

    Result<DebugEvent> wait_event(std::chrono::milliseconds timeout) override {
        if (!process_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        if (pending_) return Error{ErrorCode::busy, "previous debug event has not been continued"};
        const auto bounded = std::clamp<std::int64_t>(timeout.count(), 0, MAXDWORD - 1);
        DEBUG_EVENT event{};
        if (!WaitForDebugEvent(&event, static_cast<DWORD>(bounded))) {
            if (GetLastError() == ERROR_SEM_TIMEOUT) return Error{ErrorCode::busy, "debug event wait timed out"};
            return win_error("WaitForDebugEvent");
        }
        pending_ = event;
        const bool completed_arm32_step = arm32_step_ && event.dwThreadId == arm32_step_->thread &&
            event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT &&
            reinterpret_cast<std::uintptr_t>(event.u.Exception.ExceptionRecord.ExceptionAddress) == arm32_step_->successor;
        std::string arm32_step_restore_diagnostic;
        if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) arm32_step_.reset();
        else if (arm32_step_) {
            arm32_step_->rewind_successor = completed_arm32_step;
            auto restored = restore_arm32_step();
            if (!restored) arm32_step_restore_diagnostic = restored.error().message;
        }
        Status resumed_threads = std::monostate{};
        if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            for (HANDLE thread : step_suspension_handles_) CloseHandle(thread);
            step_suspension_handles_.clear(); step_suspended_threads_.clear();
        } else {
            resumed_threads = resume_step_suspensions();
        }
        // A software breakpoint is restored after the displaced instruction has
        // trapped, while the debug event still holds the process stopped.
        if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            stepping_breakpoint_.clear();
            arm64_step_thread_.reset();
            arm64_step_original_cpsr_.reset();
        } else if (const auto address = stepping_breakpoint_.complete(event.dwThreadId)) {
            const auto bp = breakpoints_.find(*address);
            const auto trap = bp != breakpoints_.end() ? bp->second.trap : software_breakpoint_instruction();
            auto patched = bp != breakpoints_.end() && bp->second.enabled
                ? patch_bytes(*address, trap) : Status{std::monostate{}};
            if (!patched) {
                stepping_breakpoint_.retain(*address, event.dwThreadId);
                return patched.error();
            }
        }
        const bool completed_arm64_step = arm64_step_thread_ && *arm64_step_thread_ == event.dwThreadId;
        std::string arm64_step_restore_diagnostic;
        if (completed_arm64_step && event.dwDebugEventCode != EXIT_THREAD_DEBUG_EVENT &&
            arm64_step_original_cpsr_) {
            auto restored = restore_arm64_step_cpsr(event.dwThreadId, *arm64_step_original_cpsr_);
            if (restored) {
                arm64_step_thread_.reset();
                arm64_step_original_cpsr_.reset();
            } else arm64_step_restore_diagnostic = restored.error().message;
        } else if (completed_arm64_step) {
            arm64_step_thread_.reset();
            arm64_step_original_cpsr_.reset();
        }
        std::string arm64_hw_step_restore_diagnostic;
        if (arm64_hardware_step_ && arm64_hardware_step_->thread == event.dwThreadId &&
            event.dwDebugEventCode != EXIT_THREAD_DEBUG_EVENT && event.dwDebugEventCode != EXIT_PROCESS_DEBUG_EVENT) {
            auto restored = restore_arm64_hardware_step();
            if (!restored) arm64_hw_step_restore_diagnostic = restored.error().message;
        } else if (arm64_hardware_step_ &&
                   (event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT || event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)) {
            arm64_hardware_step_.reset();
        }
        DebugEvent result{}; result.sequence = ++sequence_; result.process = event.dwProcessId; result.thread = event.dwThreadId;
        switch (event.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:
            result.address = reinterpret_cast<std::uintptr_t>(event.u.Exception.ExceptionRecord.ExceptionAddress);
            result.code = event.u.Exception.ExceptionRecord.ExceptionCode;
            result.first_chance = event.u.Exception.dwFirstChance != FALSE;
            result.kind = result.code == EXCEPTION_BREAKPOINT ? EventKind::breakpoint :
                          result.code == EXCEPTION_SINGLE_STEP ? EventKind::single_step : EventKind::exception;
            result.message = "exception"; break;
        case CREATE_THREAD_DEBUG_EVENT:
            result.kind = EventKind::thread_created; result.message = "thread created";
            if (!hardware_breakpoints_.empty()) {
                const auto expected = target_architecture() == Architecture::arm64
                    ? std::vector<detail::HardwareRequest>{} : hardware_requests();
                auto applied = write_debug_registers(event.u.CreateThread.hThread, hardware_requests(), expected, true);
                if (!applied) return applied.error();
            }
            break;
        case EXIT_THREAD_DEBUG_EVENT: result.kind = EventKind::thread_exited; result.message = "thread exited"; break;
        case LOAD_DLL_DEBUG_EVENT: result.kind = EventKind::module_loaded; result.message = "module loaded"; break;
        case UNLOAD_DLL_DEBUG_EVENT: result.kind = EventKind::module_unloaded; result.message = "module unloaded"; break;
        case EXIT_PROCESS_DEBUG_EVENT: result.kind = EventKind::process_exited; result.code = event.u.ExitProcess.dwExitCode; result.message = "process exited"; break;
        case OUTPUT_DEBUG_STRING_EVENT: result.kind = EventKind::output; result.message = "debug output"; break;
        default: result.kind = EventKind::unknown; result.message = "debug event"; break;
        }
        if (completed_arm32_step) {
            result.kind = EventKind::single_step;
            result.message = "ARM32 sequential instruction step completed";
        }
        arm32_completed_step_pending_ = completed_arm32_step;
        if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP &&
            target_architecture() == Architecture::arm && !hardware_breakpoints_.empty()) {
            for (const auto& breakpoint : hardware_breakpoints_) {
                if (breakpoint.enabled && breakpoint.kind == BreakpointKind::execute &&
                    (breakpoint.address & ~std::uint64_t{1}) == (result.address & ~std::uint64_t{1}))
                    result.breakpoint_ids.push_back(breakpoint.id);
            }
            if (!result.breakpoint_ids.empty()) {
                result.kind = EventKind::breakpoint;
                result.message = "ARM32 hardware execution breakpoint hit";
            }
        } else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP &&
            target_architecture() == Architecture::arm64 && !hardware_breakpoints_.empty()) {
            const auto address = result.address;
            for (const auto& breakpoint : hardware_breakpoints_) {
                if (breakpoint.enabled && breakpoint.kind == BreakpointKind::execute && breakpoint.address == address)
                    result.breakpoint_ids.push_back(breakpoint.id);
            }
            if (!result.breakpoint_ids.empty()) {
                result.kind = EventKind::breakpoint;
                result.message = "ARM64 hardware execution breakpoint hit";
            } else if (!completed_arm64_step && std::any_of(hardware_breakpoints_.begin(), hardware_breakpoints_.end(), [](const auto& bp) {
                           return bp.enabled && bp.kind != BreakpointKind::execute;
                       })) {
                result.kind = EventKind::breakpoint;
                result.message = "ARM64 hardware watchpoint exception; Windows did not expose a hit-slot mask";
            }
        } else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP &&
            !hardware_breakpoints_.empty()) {
            std::string diagnostic;
            const auto dr6 = read_clear_dr6(event.dwThreadId, diagnostic);
            if (dr6) {
                std::vector<BreakpointId> slot_ids;
                slot_ids.reserve(hardware_breakpoints_.size());
                for (const auto& breakpoint : hardware_breakpoints_)
                    if (breakpoint.enabled) slot_ids.push_back(breakpoint.id);
                result.breakpoint_ids = detail::hardware_breakpoint_hits(slot_ids, *dr6);
                if (!result.breakpoint_ids.empty()) {
                    result.kind = EventKind::breakpoint;
                    result.message = "hardware breakpoint hit";
                }
            }
            if (!diagnostic.empty()) result.message += "; " + diagnostic;
        }
        if (!resumed_threads) result.message += "; peer-thread resume failed and will be retried before event acknowledgement";
        if (!arm32_step_restore_diagnostic.empty())
            result.message += "; ARM32 step restoration failed and must complete before resume: " + arm32_step_restore_diagnostic;
        if (!arm64_step_restore_diagnostic.empty())
            result.message += "; ARM64 single-step state restoration failed: " + arm64_step_restore_diagnostic;
        if (!arm64_hw_step_restore_diagnostic.empty())
            result.message += "; ARM64 hardware breakpoint restoration failed: " + arm64_hw_step_restore_diagnostic;
        return result;
    }

    Status continue_event(std::uint64_t sequence, ContinueStatus status) override {
        return continue_event_impl(sequence, status, true);
    }

    Status continue_event_impl(std::uint64_t sequence, ContinueStatus status, bool release_peers) {
        if (!pending_ || sequence != sequence_) return Error{ErrorCode::invalid_argument, "event sequence does not match pending event"};
        if (arm32_completed_step_pending_ && status != ContinueStatus::handled)
            return Error{ErrorCode::invalid_argument, "the debugger-owned ARM32 step trap must be handled"};
        if (arm32_step_) {
            auto restored = restore_arm32_step();
            if (!restored) return restored;
        }
        if (arm64_hardware_step_ && arm64_hardware_step_->thread == pending_->dwThreadId) {
            auto restored = restore_arm64_hardware_step();
            if (!restored) return restored;
        }
        if (status == ContinueStatus::handled && target_architecture() == Architecture::arm64 &&
            pending_->dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            pending_->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
            const auto address = reinterpret_cast<std::uintptr_t>(pending_->u.Exception.ExceptionRecord.ExceptionAddress);
            const bool execute_hit = std::any_of(hardware_breakpoints_.begin(), hardware_breakpoints_.end(),
                [address](const auto& bp) { return bp.enabled && bp.kind == BreakpointKind::execute && bp.address == address; });
            if (execute_hit) return single_step_arm64(sequence, status);
        }
        if (release_peers) {
            auto resumed = resume_step_suspensions();
            if (!resumed) return resumed;
        }
        if (arm64_step_thread_ && *arm64_step_thread_ == pending_->dwThreadId && arm64_step_original_cpsr_) {
            auto restored = restore_arm64_step_cpsr(*arm64_step_thread_, *arm64_step_original_cpsr_);
            if (!restored) return restored;
            arm64_step_thread_.reset();
            arm64_step_original_cpsr_.reset();
        }
        const DWORD disposition = status == ContinueStatus::handled ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
        const bool process_exited = pending_->dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT;
        if (!ContinueDebugEvent(pending_->dwProcessId, pending_->dwThreadId, disposition)) return win_error("ContinueDebugEvent");
        close_event_handles(*pending_);
        pending_.reset();
        arm32_completed_step_pending_ = false;
        if (process_exited) {
            if (process_) CloseHandle(process_);
            close_terminate_handle();
            process_ = nullptr; process_id_ = 0; launched_ = false; breakpoints_.clear();
            stepping_breakpoint_.clear(); hardware_breakpoints_.clear(); arm64_step_thread_.reset(); arm64_step_original_cpsr_.reset(); arm64_hardware_step_.reset(); exited_ = true;
        }
        return std::monostate{};
    }

    Status continue_thread_event(std::uint64_t sequence, ThreadId thread, ContinueStatus status) override {
        if (!pending_ || sequence != sequence_)
            return Error{ErrorCode::invalid_argument, "event sequence does not match pending event"};
        if (pending_->dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT || pending_->dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
            return Error{ErrorCode::busy, "a thread/process exit event cannot resume a thread"};
        if (thread != static_cast<ThreadId>(pending_->dwThreadId))
            return Error{ErrorCode::invalid_argument, "selected thread does not own the pending debug event"};
        const std::array<ThreadId, 1> selected{thread};
        return continue_selected_threads(sequence, selected, status);
    }

    Status resume_threads_event(std::uint64_t sequence, std::span<const ThreadResumeAction> actions) override {
        if (!pending_ || sequence != sequence_)
            return Error{ErrorCode::invalid_argument, "event sequence does not match pending event"};
        if (pending_->dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
            return Error{ErrorCode::busy, "the process exit event cannot resume a thread"};
        if (actions.empty() || actions.size() > max_inspection_threads)
            return Error{ErrorCode::invalid_argument, "thread resume schedule must contain 1 to 4096 actions"};
        const auto owner = static_cast<ThreadId>(pending_->dwThreadId);
        auto live_threads = threads();
        if (!live_threads) return live_threads.error();
        std::vector<ThreadId> seen;
        seen.reserve(actions.size());
        bool includes_owner = false;
        const ThreadResumeAction *owner_action = nullptr;
        std::vector<ThreadId> runnable;
        std::size_t steps = 0;
        for (const auto &action : actions) {
            if (!action.thread || action.thread > MAXDWORD)
                return Error{ErrorCode::invalid_argument, "resume schedule contains an invalid Windows thread ID"};
            if (action.kind != ThreadResumeKind::continue_execution && action.kind != ThreadResumeKind::single_step &&
                action.kind != ThreadResumeKind::stop)
                return Error{ErrorCode::invalid_argument, "resume schedule contains an unknown action"};
            if (std::find(seen.begin(), seen.end(), action.thread) != seen.end())
                return Error{ErrorCode::invalid_argument, "resume schedule contains a duplicate thread ID"};
            seen.push_back(action.thread);
            if (std::none_of(live_threads.value().begin(), live_threads.value().end(), [&](const auto &thread) {
                    return thread.id == action.thread;
                }))
                return Error{ErrorCode::invalid_argument, "resume schedule contains a thread not present in the active target"};
            if (action.thread == owner) {
                includes_owner = true;
                owner_action = &action;
            }
            if (action.kind != ThreadResumeKind::stop) runnable.push_back(action.thread);
            if (action.kind == ThreadResumeKind::single_step) ++steps;
        }
        if (!includes_owner || !owner_action)
            return Error{ErrorCode::invalid_argument, "resume schedule must include the thread that owns the pending event"};
        if (runnable.empty())
            return Error{ErrorCode::invalid_argument, "Windows schedule cannot resume with stop-only actions"};
        if (steps && (steps != 1 || runnable.size() != 1 || owner_action->kind != ThreadResumeKind::single_step))
            return Error{ErrorCode::unsupported, "Windows schedules support one event-thread step or a continue-only thread subset"};
        if (steps)
            return single_step_event(sequence, ContinueStatus::handled);
        if (owner_action->kind != ThreadResumeKind::continue_execution)
            return Error{ErrorCode::unsupported, "Windows continue schedules must resume the pending event owner"};
        return continue_selected_threads(sequence, runnable, ContinueStatus::handled);
    }

    Status continue_selected_threads(std::uint64_t sequence, std::span<const ThreadId> selected, ContinueStatus status) {
        if (!pending_ || sequence != sequence_ || selected.empty() || selected.size() > max_inspection_threads)
            return Error{ErrorCode::invalid_argument, "thread-filtered continue has no matching pending event or selected threads"};
        if (stepping_breakpoint_.active())
            return Error{ErrorCode::busy, "a displaced software-breakpoint step must complete before changing its thread schedule"};
        if (selected.size() > 1 && status == ContinueStatus::handled && target_architecture() == Architecture::arm64 &&
            pending_->dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            pending_->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
            const auto address = reinterpret_cast<std::uintptr_t>(pending_->u.Exception.ExceptionRecord.ExceptionAddress);
            if (std::any_of(hardware_breakpoints_.begin(), hardware_breakpoints_.end(), [address](const auto &breakpoint) {
                    return breakpoint.enabled && breakpoint.kind == BreakpointKind::execute && breakpoint.address == address;
                }))
                return Error{ErrorCode::unsupported, "a Windows ARM64 execute-breakpoint step-over cannot resume a multi-thread subset"};
        }
        // The pending debug event freezes the process while suspend counts are
        // acquired. ContinueDebugEvent then releases only our selected set;
        // every other thread retains exactly one debugger-owned suspend count.
        auto recovered = resume_step_suspensions();
        if (!recovered) return recovered;
        auto suspended = suspend_unselected_threads(selected);
        if (!suspended) return suspended;
        auto result = continue_event_impl(sequence, status, false);
        if (!result) {
            const auto error = result.error();
            auto rollback = resume_step_suspensions();
            if (!rollback)
                return Error{error.code, error.message + "; releasing scheduled peer suspensions also failed: " + rollback.error().message};
        }
        return result;
    }

    Status single_step_event(std::uint64_t sequence, ContinueStatus status) override {
        if (!pending_ || sequence != sequence_)
            return Error{ErrorCode::invalid_argument, "event sequence does not match pending event"};
        if (target_architecture() == Architecture::arm)
            return single_step_arm32(status);
        if (target_architecture() == Architecture::arm64) return single_step_arm64(sequence, status);
        auto resumed = resume_step_suspensions();
        if (!resumed) return resumed;
        if (pending_->dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
            return Error{ErrorCode::invalid_argument, "cannot single-step a process-exit event"};

        const auto thread_id = static_cast<ThreadId>(pending_->dwThreadId);
        std::optional<std::uintptr_t> displaced_breakpoint;
        if (pending_->dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            pending_->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
            const auto address = reinterpret_cast<std::uintptr_t>(pending_->u.Exception.ExceptionRecord.ExceptionAddress);
            const auto found = breakpoints_.find(address);
            if (found != breakpoints_.end()) {
                auto regs = read_registers(thread_id);
                if (!regs) return regs.error();
                auto ip = std::find_if(regs.value().begin(), regs.value().end(), [](const RegisterValue& r) { return r.name == "rip" || r.name == "eip"; });
                if (ip == regs.value().end() || (ip->bytes.size() != sizeof(std::uint32_t) && ip->bytes.size() != sizeof(std::uint64_t)))
                    return Error{ErrorCode::unsupported, "cannot locate instruction pointer for software breakpoint stepping"};
                std::uint64_t current_ip = 0;
                std::memcpy(&current_ip, ip->bytes.data(), ip->bytes.size());
                if (current_ip == address + 1) {
                    auto removed = patch_bytes(address, found->second.original);
                    if (!removed) return removed;
                    const auto rewind_ip = static_cast<std::uint64_t>(address);
                    std::memcpy(ip->bytes.data(), &rewind_ip, ip->bytes.size());
                    auto rewind = write_registers(thread_id, std::span<const RegisterValue>(&*ip, 1));
                    if (!rewind) {
                        auto trap_restored = patch_byte(address, std::byte{0xcc});
                        if (!trap_restored)
                            return Error{ErrorCode::io, rewind.error().message + "; restoring breakpoint trap also failed: " + trap_restored.error().message};
                        return rewind;
                    }
                    displaced_breakpoint = address;
                }
            }
        }
        auto flags = read_eflags(thread_id);
        if (!flags) {
            if (displaced_breakpoint) {
                auto trap_restored = patch_byte(*displaced_breakpoint, std::byte{0xcc});
                if (!trap_restored) return Error{ErrorCode::io, flags.error().message + "; restoring breakpoint trap also failed: " + trap_restored.error().message};
            }
            return flags.error();
        }
        constexpr DWORD trap_flag = 0x100;
        const DWORD original_flags = flags.value();
        auto set = write_eflags(thread_id, original_flags | trap_flag);
        if (!set) {
            if (displaced_breakpoint) {
                auto trap_restored = patch_byte(*displaced_breakpoint, std::byte{0xcc});
                if (!trap_restored) return Error{ErrorCode::io, set.error().message + "; restoring breakpoint trap also failed: " + trap_restored.error().message};
            }
            return set;
        }

        if (displaced_breakpoint && !stepping_breakpoint_.begin(
                *displaced_breakpoint, *displaced_breakpoint + 1, thread_id)) {
            auto flags_restored = write_eflags(thread_id, original_flags);
            auto trap_restored = patch_byte(*displaced_breakpoint, std::byte{0xcc});
            if (!flags_restored || !trap_restored)
                return Error{ErrorCode::io, "restoring state after a concurrent breakpoint step failed" +
                    std::string(!flags_restored ? "; thread flags: " + flags_restored.error().message : "") +
                    std::string(!trap_restored ? "; breakpoint bytes/protection: " + trap_restored.error().message : "")};
            return Error{ErrorCode::busy, "another software breakpoint step is already pending"};
        }

        auto suspended = suspend_peer_threads(thread_id);
        if (!suspended) {
            if (displaced_breakpoint) stepping_breakpoint_.clear();
            auto restored = write_eflags(thread_id, original_flags);
            Status trap_restored = std::monostate{};
            if (displaced_breakpoint) trap_restored = patch_byte(*displaced_breakpoint, std::byte{0xcc});
            if (!restored || !trap_restored)
                return Error{ErrorCode::io, suspended.error().message +
                    std::string(!restored ? "; restoring the thread flags also failed: " + restored.error().message : "") +
                    std::string(!trap_restored ? "; restoring breakpoint bytes/protection also failed: " + trap_restored.error().message : "")};
            return suspended;
        }

        const DWORD disposition = status == ContinueStatus::handled ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
        if (!ContinueDebugEvent(pending_->dwProcessId, pending_->dwThreadId, disposition)) {
            const auto continue_error = win_error("ContinueDebugEvent for single-step");
            if (displaced_breakpoint) stepping_breakpoint_.clear();
            auto restored = write_eflags(thread_id, original_flags);
            Status trap_restored = std::monostate{};
            if (displaced_breakpoint) trap_restored = patch_byte(*displaced_breakpoint, std::byte{0xcc});
            auto released = resume_step_suspensions();
            if (!restored || !trap_restored)
                return Error{ErrorCode::io, continue_error.message +
                    std::string(!restored ? "; restoring the thread flags also failed: " + restored.error().message : "") +
                    std::string(!trap_restored ? "; restoring breakpoint bytes/protection also failed: " + trap_restored.error().message : "")};
            if (!released)
                return Error{ErrorCode::io, continue_error.message + "; releasing peer-thread suspensions also failed: " + released.error().message};
            return continue_error;
        }
        close_event_handles(*pending_);
        pending_.reset();
        return std::monostate{};
    }

    Result<std::vector<std::byte>> read_memory(std::uint64_t address, std::size_t size) override {
        if (!process_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        std::vector<std::byte> bytes(size); SIZE_T read = 0;
        if (size && (!ReadProcessMemory(process_, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address)), bytes.data(), size, &read) || read != size)) return win_error("ReadProcessMemory");
        return bytes;
    }
    Status write_memory(std::uint64_t address, std::span<const std::byte> bytes) override {
        if (!process_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        if (arm32_step_) return Error{ErrorCode::busy, "ARM32 step patch restoration is pending"};
        if (target_architecture() == Architecture::arm && !pending_)
            return Error{ErrorCode::busy, "ARM32 memory writes require a stopped debug event"};
        const auto maximum_address = static_cast<std::uint64_t>((std::numeric_limits<std::uintptr_t>::max)());
        if (bytes.size() > max_inspection_read || address > UINT64_MAX - bytes.size() ||
            address > maximum_address || bytes.size() > maximum_address - address)
            return Error{ErrorCode::invalid_argument, "invalid memory write range"};
        if (bytes.empty()) return std::monostate{};
        const auto start = static_cast<std::uintptr_t>(address);
        const auto end = start + bytes.size();
        if (target_architecture() == Architecture::arm)
            for (const auto& [at, record] : breakpoints_)
                if ((at >= 2 ? at - 2 : 0) < end && start < at + record.extent)
                    return Error{ErrorCode::unsupported, "ARM32 memory write overlaps an instruction with an owned breakpoint"};
        std::vector<std::byte> original(bytes.size());
        SIZE_T read = 0;
        if (!ReadProcessMemory(process_, reinterpret_cast<const void*>(start), original.data(), original.size(), &read) ||
            read != original.size()) return win_error("ReadProcessMemory before write");
        std::vector<std::byte> staged(bytes.begin(), bytes.end());
        std::vector<std::pair<std::uintptr_t, std::vector<std::byte>>> updated_originals;
        for (auto it = breakpoints_.begin(); it != breakpoints_.end(); ++it) {
            const auto bp_end = it->first + it->second.original.size();
            if (bp_end <= start) continue;
            if (it->first >= end) break;
            auto updated = it->second.original;
            const auto& trap = it->second.trap;
            for (std::size_t byte = 0; byte < updated.size(); ++byte) {
                const auto at = it->first + byte;
                if (at < start || at >= end) continue;
                const auto offset = static_cast<std::size_t>(at - start);
                updated[byte] = staged[offset];
                if (it->second.enabled) staged[offset] = trap[byte];
            }
            updated_originals.emplace_back(it->first, std::move(updated));
        }
        SIZE_T written = 0;
        const BOOL write_ok = WriteProcessMemory(process_, reinterpret_cast<void*>(start), staged.data(),
                                                  staged.size(), &written);
        if (!write_ok || written != staged.size()) {
            const DWORD write_error = write_ok ? ERROR_WRITE_FAULT : GetLastError();
            SIZE_T restored = 0;
            const bool rollback_ok = WriteProcessMemory(process_, reinterpret_cast<void*>(start), original.data(),
                                                         original.size(), &restored) != FALSE && restored == original.size();
            if (!rollback_ok) {
                const DWORD rollback_error = GetLastError();
                return Error{ErrorCode::io, "WriteProcessMemory failed (Win32 error " + std::to_string(write_error) +
                    "); restoring original memory also failed (Win32 error " + std::to_string(rollback_error) + ")"};
            }
            SetLastError(write_error);
            return win_error("WriteProcessMemory");
        }
        for (auto& [at, value] : updated_originals) breakpoints_.at(at).original = std::move(value);
        FlushInstructionCache(process_, reinterpret_cast<const void*>(start), staged.size());
        return std::monostate{};
    }
    Result<std::vector<ThreadInfo>> threads() override {
        if (!process_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return win_error("CreateToolhelp32Snapshot");
        std::vector<ThreadInfo> result; THREADENTRY32 entry{}; entry.dwSize = sizeof(entry);
        if (Thread32First(snapshot, &entry)) do {
            if (entry.th32OwnerProcessID == process_id_) {
                if (result.size() == max_inspection_threads) {
                    CloseHandle(snapshot);
                    return Error{ErrorCode::resource_limit, "target thread count exceeds the inspection limit"};
                }
                result.push_back({entry.th32ThreadID, {}, ThreadState::unknown});
            }
            entry.dwSize = sizeof(entry);
        } while (Thread32Next(snapshot, &entry));
        const DWORD enumeration_error = GetLastError();
        CloseHandle(snapshot);
        if (enumeration_error != ERROR_NO_MORE_FILES) {
            SetLastError(enumeration_error);
            return win_error("enumerating target threads");
        }
        return result;
    }
    Result<std::vector<ThreadRunState>> thread_run_states() override {
        if (!process_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        auto current = threads();
        if (!current) return current.error();
        std::vector<ThreadRunState> result;
        result.reserve(current.value().size());
        // WaitForDebugEvent holds the debuggee threads until the event is
        // continued. Outside that interval Windows does not provide a race-free
        // query for arbitrary target-owned SuspendThread counts, so report
        // unknown rather than claiming that an apparently running thread runs.
        const auto state = pending_ && pending_->dwDebugEventCode != EXIT_PROCESS_DEBUG_EVENT
            ? ThreadState::stopped : ThreadState::unknown;
        for (const auto &thread : current.value()) {
            const bool held = std::any_of(step_suspended_threads_.begin(), step_suspended_threads_.end(), [&](HANDLE handle) {
                return static_cast<ThreadId>(GetThreadId(handle)) == thread.id;
            });
            result.push_back({thread.id, held ? ThreadState::stopped : state});
        }
        return result;
    }
    Result<std::vector<ModuleInfo>> modules() override {
        if (!process_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id_);
        if (snapshot == INVALID_HANDLE_VALUE) return win_error("CreateToolhelp32Snapshot modules");
        std::vector<ModuleInfo> result;
        MODULEENTRY32W entry{}; entry.dwSize = sizeof(entry);
        if (Module32FirstW(snapshot, &entry)) do {
            if (result.size() == max_inspection_modules) {
                CloseHandle(snapshot);
                return Error{ErrorCode::invalid_argument, "target exposes more than 4096 modules"};
            }
            result.push_back({narrow(entry.szModule), narrow(entry.szExePath),
                static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(entry.modBaseAddr)),
                static_cast<std::uint64_t>(entry.modBaseSize)});
            entry.dwSize = sizeof(entry);
        } while (Module32NextW(snapshot, &entry));
        CloseHandle(snapshot);
        return result;
    }
    Result<std::vector<MemoryRegion>> memory_regions() override {
        if (!process_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        SYSTEM_INFO system{};
        GetNativeSystemInfo(&system);
        const auto minimum = reinterpret_cast<std::uintptr_t>(system.lpMinimumApplicationAddress);
        const auto maximum = reinterpret_cast<std::uintptr_t>(system.lpMaximumApplicationAddress);
        if (minimum > maximum) return Error{ErrorCode::io, "Windows returned an invalid application address range"};

        std::vector<MemoryRegion> result;
        result.reserve(4096);
        auto cursor = minimum;
        while (cursor <= maximum) {
            MEMORY_BASIC_INFORMATION info{};
            if (!VirtualQueryEx(process_, reinterpret_cast<const void*>(cursor), &info, sizeof(info))) {
                const auto error = GetLastError();
                if (error == ERROR_INVALID_PARAMETER && cursor == maximum) break;
                SetLastError(error);
                return win_error("VirtualQueryEx");
            }
            const auto base = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
            const auto size = static_cast<std::uintptr_t>(info.RegionSize);
            if (!size || base > (std::numeric_limits<std::uintptr_t>::max)() - size)
                return Error{ErrorCode::io, "VirtualQueryEx returned an invalid memory region"};
            const auto end = base + size;
            const auto protection = info.Protect & 0xff;
            const bool guarded = (info.Protect & PAGE_GUARD) != 0 || protection == PAGE_NOACCESS;
            const bool readable = info.State == MEM_COMMIT && !guarded &&
                (protection == PAGE_READONLY || protection == PAGE_READWRITE || protection == PAGE_WRITECOPY ||
                 protection == PAGE_EXECUTE_READ || protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY);
            const bool writable = info.State == MEM_COMMIT && !guarded &&
                (protection == PAGE_READWRITE || protection == PAGE_WRITECOPY ||
                 protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY);
            const bool executable = info.State == MEM_COMMIT && !guarded &&
                (protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ ||
                 protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY);
            const char* kind = info.Type == MEM_IMAGE ? "image" : info.Type == MEM_MAPPED ? "mapped" :
                               info.Type == MEM_PRIVATE ? "private" : "free";
            const char* state = info.State == MEM_COMMIT ? "committed" : info.State == MEM_RESERVE ? "reserved" : "free";
            std::string label = std::string(kind) + "/" + state;
            if (info.State == MEM_COMMIT && (info.Protect & PAGE_GUARD)) label += "/guard";
            result.push_back({static_cast<std::uint64_t>(base), static_cast<std::uint64_t>(size),
                              readable, writable, executable, std::move(label)});
            if (result.size() >= max_inspection_memory_regions && end <= maximum)
                return Error{ErrorCode::resource_limit, "target exposes more than 65536 memory regions"};
            if (end <= cursor) return Error{ErrorCode::io, "VirtualQueryEx did not advance the address cursor"};
            cursor = end;
        }
        return result;
    }
    Result<std::vector<RegisterValue>> read_registers(ThreadId id) override {
        if (target_architecture() == Architecture::arm) {
#if !defined(_M_ARM)
            return Error{ErrorCode::unsupported, "Windows ARM32 context access requires an ARM32 debugger build"};
#else
            if (!pending_) return Error{ErrorCode::busy, "Windows ARM32 contexts are readable only during a debug stop"};
            if (!id || id > MAXDWORD) return Error{ErrorCode::invalid_argument, "invalid ARM32 thread ID"};
            HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, static_cast<DWORD>(id));
            if (!thread) return win_error("OpenThread for ARM32 context");
            if (GetProcessIdOfThread(thread) != process_id_) {
                CloseHandle(thread);
                return Error{ErrorCode::invalid_argument, "ARM32 thread does not belong to the debug target"};
            }
            CONTEXT c{};
            c.ContextFlags = CONTEXT_FULL;
            const bool ok = GetThreadContext(thread, &c) != FALSE;
            const auto error = ok ? Error{} : win_error("GetThreadContext for ARM32");
            CloseHandle(thread);
            if (!ok) return error;
            std::vector<RegisterValue> out;
            out.reserve(13 + 4 + 16 + 1);
            const std::array<DWORD, 13> general{c.R0, c.R1, c.R2, c.R3, c.R4, c.R5, c.R6,
                                                 c.R7, c.R8, c.R9, c.R10, c.R11, c.R12};
            for (unsigned i = 0; i < 13; ++i) {
                RegisterValue reg;
                reg.name = "r" + std::to_string(i);
                reg.byte_order = ByteOrder::little;
                reg.bytes.resize(sizeof(DWORD));
                std::memcpy(reg.bytes.data(), &general[i], sizeof(DWORD));
                out.push_back(std::move(reg));
            }
            append_register(out, "sp", c.Sp);
            append_register(out, "lr", c.Lr);
            append_register(out, "pc", c.Pc);
            append_register(out, "cpsr", c.Cpsr);
            for (unsigned i = 0; i < 16; ++i) {
                RegisterValue reg;
                reg.name = "q" + std::to_string(i);
                reg.group = "vector";
                reg.number = i;
                reg.byte_order = ByteOrder::little;
                reg.bytes.resize(sizeof(c.Q[i]));
                std::memcpy(reg.bytes.data(), &c.Q[i], sizeof(c.Q[i]));
                out.push_back(std::move(reg));
            }
            append_register(out, "fpscr", c.Fpscr);
            return out;
#endif
        }
        if (target_architecture() == Architecture::arm64) {
#if !defined(_M_ARM64)
            return Error{ErrorCode::unsupported, "this debugger build cannot decode Windows ARM64 thread contexts; rebuild for ARM64"};
#else
            if (!pending_) return Error{ErrorCode::busy, "Windows ARM64 contexts are readable only while a debug event has stopped the target"};
            HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, static_cast<DWORD>(id));
            if (!thread) return win_error("OpenThread for ARM64 context");
            CONTEXT c{};
            c.ContextFlags = CONTEXT_ARM64_FULL | CONTEXT_ARM64_X18;
            const bool ok = GetThreadContext(thread, &c) != FALSE;
            const auto error = ok ? Error{} : win_error("GetThreadContext for ARM64");
            CloseHandle(thread);
            if (!ok) return error;
            std::vector<RegisterValue> out;
            out.reserve(31 + 5 + 32);
            for (std::uint32_t i = 0; i <= 30; ++i) {
                RegisterValue reg;
                reg.name = "x" + std::to_string(i);
                reg.byte_order = ByteOrder::little;
                reg.bytes.resize(sizeof(c.X[i]));
                std::memcpy(reg.bytes.data(), &c.X[i], sizeof(c.X[i]));
                out.push_back(std::move(reg));
            }
            append_register(out, "sp", c.Sp);
            append_register(out, "pc", c.Pc);
            append_register(out, "cpsr", c.Cpsr);
            for (std::uint32_t i = 0; i < 32; ++i) {
                RegisterValue reg;
                reg.name = "v" + std::to_string(i);
                reg.byte_order = ByteOrder::little;
                reg.bytes.resize(sizeof(c.V[i]));
                std::memcpy(reg.bytes.data(), &c.V[i], sizeof(c.V[i]));
                out.push_back(std::move(reg));
            }
            append_register(out, "fpcr", c.Fpcr);
            append_register(out, "fpsr", c.Fpsr);
            return out;
#endif
        }
        HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, static_cast<DWORD>(id));
        if (!thread) return win_error("OpenThread");
        std::vector<RegisterValue> out;
#if defined(_WIN64)
        if (target_architecture() == Architecture::x86) {
            WOW64_CONTEXT c{};
            c.ContextFlags = WOW64_CONTEXT_FULL | WOW64_CONTEXT_FLOATING_POINT | WOW64_CONTEXT_EXTENDED_REGISTERS;
            const bool ok = Wow64GetThreadContext(thread, &c) != FALSE; CloseHandle(thread);
            if (!ok) return win_error("Wow64GetThreadContext");
            append_register(out,"eax",c.Eax); append_register(out,"ebx",c.Ebx); append_register(out,"ecx",c.Ecx); append_register(out,"edx",c.Edx);
            append_register(out,"esi",c.Esi); append_register(out,"edi",c.Edi); append_register(out,"ebp",c.Ebp); append_register(out,"esp",c.Esp);
            append_register(out,"eip",c.Eip); append_register(out,"eflags",c.EFlags);
            const auto fp_image = std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(c.ExtendedRegisters), sizeof(c.ExtendedRegisters));
            auto fp = append_x86_fp_registers(out, fp_image, true);
            if (!fp) return fp.error();
        } else
#endif
        {
            CONTEXT legacy{};
#if defined(_M_X64)
            std::optional<X64AvxContext> avx;
            if (target_architecture() == Architecture::x86_64 && pending_) {
                auto captured = read_x64_avx_context(thread);
                if (captured) avx.emplace(std::move(captured.value()));
                else if (captured.error().code != ErrorCode::unsupported) {
                    const auto error = captured.error();
                    CloseHandle(thread);
                    return error;
                }
            }
            CONTEXT& c = avx ? *avx->context : legacy;
            if (!avx) c.ContextFlags = CONTEXT_FULL | CONTEXT_FLOATING_POINT;
            const bool ok = avx.has_value() || GetThreadContext(thread, &c) != FALSE;
#else
            CONTEXT& c = legacy;
#if defined(_M_IX86)
            c.ContextFlags = CONTEXT_FULL | CONTEXT_FLOATING_POINT | CONTEXT_EXTENDED_REGISTERS;
#else
            c.ContextFlags = CONTEXT_FULL;
#endif
            const bool ok = GetThreadContext(thread, &c) != FALSE;
#endif
            const auto error = ok ? Error{} : win_error("GetThreadContext");
            CloseHandle(thread);
            if (!ok) return error;
#if defined(_M_X64)
            append_register(out,"rax",c.Rax); append_register(out,"rbx",c.Rbx); append_register(out,"rcx",c.Rcx); append_register(out,"rdx",c.Rdx);
            append_register(out,"rsi",c.Rsi); append_register(out,"rdi",c.Rdi); append_register(out,"rbp",c.Rbp); append_register(out,"rsp",c.Rsp);
            append_register(out,"rip",c.Rip); append_register(out,"r8",c.R8); append_register(out,"r9",c.R9); append_register(out,"r10",c.R10);
            append_register(out,"r11",c.R11); append_register(out,"r12",c.R12); append_register(out,"r13",c.R13); append_register(out,"r14",c.R14);
            append_register(out,"r15",c.R15); append_register(out,"eflags",c.EFlags);
            static_assert(sizeof(c.FltSave) >= detail::x86_fxsave_size);
            const auto fp_image = std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(&c.FltSave), sizeof(c.FltSave));
            auto fp = append_x86_fp_registers(out, fp_image, false);
            if (!fp) return fp.error();
            if (avx)
                for (std::uint32_t i = 0; i < 16; ++i) append_ymm_register(out, i, *avx);
#elif defined(_M_IX86)
            append_register(out,"eax",c.Eax); append_register(out,"ebx",c.Ebx); append_register(out,"ecx",c.Ecx); append_register(out,"edx",c.Edx);
            append_register(out,"esi",c.Esi); append_register(out,"edi",c.Edi); append_register(out,"ebp",c.Ebp); append_register(out,"esp",c.Esp);
            append_register(out,"eip",c.Eip); append_register(out,"eflags",c.EFlags);
            static_assert(sizeof(c.ExtendedRegisters) >= detail::x86_fxsave_size);
            const auto fp_image = std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(c.ExtendedRegisters), sizeof(c.ExtendedRegisters));
            auto fp = append_x86_fp_registers(out, fp_image, true);
            if (!fp) return fp.error();
#else
            return Error{ErrorCode::unsupported, "this Windows build cannot read the requested target context"};
#endif
        }
        return out;
    }
    Status write_registers(ThreadId id, std::span<const RegisterValue> registers) override {
        if (registers.empty()) return std::monostate{};
        const bool wants_ymm = std::any_of(registers.begin(), registers.end(),
            [](const RegisterValue& reg) { return reg.name.starts_with("ymm"); });
        const bool wants_native_x64_vector = target_architecture() == Architecture::x86_64 &&
            std::any_of(registers.begin(), registers.end(), [](const RegisterValue& reg) {
                return reg.name.starts_with("xmm") || reg.name.starts_with("ymm");
            });
        if (wants_native_x64_vector) {
#if defined(_M_X64)
            auto validated = validate_x64_vector_aliases(registers);
            if (!validated) return validated.error();
#else
            return Error{ErrorCode::unsupported, "native x64 vector edits require an x64 debugger build"};
#endif
        }
        if (wants_ymm) {
#if defined(_M_X64)
            if (target_architecture() != Architecture::x86_64)
                return Error{ErrorCode::unsupported, "YMM editing requires a native x64 target"};
            if (!pending_) return Error{ErrorCode::busy, "YMM registers are writable only while a debug event has stopped the target"};
#else
            return Error{ErrorCode::unsupported, "Windows YMM editing requires an x64 debugger build"};
#endif
        }
        if (target_architecture() == Architecture::arm) {
#if !defined(_M_ARM)
            return Error{ErrorCode::unsupported, "Windows ARM32 context editing requires an ARM32 debugger build"};
#else
            if (arm32_step_) return Error{ErrorCode::busy, "ARM32 step restoration is pending"};
            if (!pending_) return Error{ErrorCode::busy, "Windows ARM32 contexts are writable only during a debug stop"};
            if (!id || id > MAXDWORD) return Error{ErrorCode::invalid_argument, "invalid ARM32 thread ID"};
            HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                       FALSE, static_cast<DWORD>(id));
            if (!thread) return win_error("OpenThread for ARM32 context edit");
            if (GetProcessIdOfThread(thread) != process_id_) {
                CloseHandle(thread);
                return Error{ErrorCode::invalid_argument, "ARM32 thread does not belong to the debug target"};
            }
            CONTEXT c{};
            c.ContextFlags = CONTEXT_FULL;
            if (!GetThreadContext(thread, &c)) {
                const auto error = win_error("GetThreadContext for ARM32 edit");
                CloseHandle(thread);
                return error;
            }
            CONTEXT original = c;
            std::array<DWORD, 13> general{c.R0, c.R1, c.R2, c.R3, c.R4, c.R5, c.R6,
                                          c.R7, c.R8, c.R9, c.R10, c.R11, c.R12};
            std::vector<std::string> seen;
            for (const auto& reg : registers) {
                if ((reg.byte_order && *reg.byte_order != ByteOrder::little) ||
                    std::find(seen.begin(), seen.end(), reg.name) != seen.end()) {
                    CloseHandle(thread);
                    return Error{ErrorCode::invalid_argument, "ARM32 register edits require unique little-endian names"};
                }
                seen.push_back(reg.name);
                bool matched = false;
                if (reg.name.size() >= 2 && reg.name[0] == 'r') {
                    unsigned index = 0;
                    const auto parsed = std::from_chars(reg.name.data() + 1, reg.name.data() + reg.name.size(), index);
                    if (parsed.ec == std::errc{} && parsed.ptr == reg.name.data() + reg.name.size() &&
                        index < 13 && reg.name == "r" + std::to_string(index))
                        matched = assign_register(reg, reg.name.c_str(), general[index]);
                } else if (reg.name == "sp") matched = assign_register(reg, "sp", c.Sp);
                else if (reg.name == "lr") matched = assign_register(reg, "lr", c.Lr);
                else if (reg.name == "pc") matched = assign_register(reg, "pc", c.Pc);
                else if (reg.name == "cpsr") matched = assign_register(reg, "cpsr", c.Cpsr);
                else if (reg.name == "fpscr") matched = assign_register(reg, "fpscr", c.Fpscr);
                else if (reg.name.size() >= 2 && reg.name[0] == 'q') {
                    unsigned index = 0;
                    const auto parsed = std::from_chars(reg.name.data() + 1, reg.name.data() + reg.name.size(), index);
                    if (parsed.ec == std::errc{} && parsed.ptr == reg.name.data() + reg.name.size() &&
                        index < 16 && reg.name == "q" + std::to_string(index) && reg.bytes.size() == sizeof(c.Q[index])) {
                        std::memcpy(&c.Q[index], reg.bytes.data(), sizeof(c.Q[index]));
                        matched = true;
                    }
                }
                if (!matched) {
                    CloseHandle(thread);
                    return Error{ErrorCode::invalid_argument, "unknown or incorrectly sized Windows ARM32 register"};
                }
            }
            c.R0 = general[0]; c.R1 = general[1]; c.R2 = general[2]; c.R3 = general[3];
            c.R4 = general[4]; c.R5 = general[5]; c.R6 = general[6]; c.R7 = general[7];
            c.R8 = general[8]; c.R9 = general[9]; c.R10 = general[10]; c.R11 = general[11]; c.R12 = general[12];
            constexpr DWORD thumb = 1u << 5;
            constexpr DWORD editable_cpsr = 0xf0000000u | thumb; // NZCV and execution state only.
            constexpr DWORD it_state = (3u << 25) | (0x3fu << 10);
            if (((c.Cpsr ^ original.Cpsr) & ~editable_cpsr) ||
                (((c.Cpsr ^ original.Cpsr) & thumb) &&
                 ((c.Cpsr & it_state) || std::find(seen.begin(), seen.end(), "pc") == seen.end())) ||
                (c.Pc & ((c.Cpsr & thumb) ? 1u : 3u)) || (c.Sp & 7u)) {
                CloseHandle(thread);
                return Error{ErrorCode::invalid_argument, "ARM32 CPSR, PC state/alignment, or eight-byte stack alignment is invalid"};
            }
            const auto at_pc = breakpoints_.find(c.Pc);
            if (at_pc != breakpoints_.end() && at_pc->second.enabled &&
                at_pc->second.thumb != ((c.Cpsr & thumb) != 0)) {
                CloseHandle(thread);
                return Error{ErrorCode::conflict, "ARM32 PC state disagrees with an enabled software breakpoint"};
            }
            const bool ok = SetThreadContext(thread, &c) != FALSE;
            const auto error = ok ? Error{} : win_error("SetThreadContext for ARM32 edit");
            const bool rollback_ok = ok || SetThreadContext(thread, &original) != FALSE;
            const auto rollback_error = rollback_ok ? Error{} : win_error("restoring ARM32 context after failed edit");
            CloseHandle(thread);
            if (!rollback_ok) return Error{ErrorCode::io, error.message + "; " + rollback_error.message};
            return ok ? Status{std::monostate{}} : Status{error};
#endif
        }
        if (target_architecture() == Architecture::arm64) {
#if !defined(_M_ARM64)
            return Error{ErrorCode::unsupported, "this debugger build cannot edit Windows ARM64 thread contexts; rebuild for ARM64"};
#else
            if (!pending_) return Error{ErrorCode::busy, "Windows ARM64 contexts are writable only while a debug event has stopped the target"};
            HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                       FALSE, static_cast<DWORD>(id));
            if (!thread) return win_error("OpenThread for ARM64 context edit");
            CONTEXT c{};
            c.ContextFlags = CONTEXT_ARM64_FULL | CONTEXT_ARM64_X18;
            if (!GetThreadContext(thread, &c)) {
                const auto error = win_error("GetThreadContext for ARM64 edit");
                CloseHandle(thread);
                return error;
            }
            for (const auto& reg : registers) {
                bool matched = false;
                for (std::uint32_t i = 0; i <= 30; ++i) {
                    const auto name = "x" + std::to_string(i);
                    if (reg.name != name) continue;
                    if (i == 18) {
                        CloseHandle(thread);
                        return Error{ErrorCode::unsupported, "writing ARM64 x18 is disabled because Windows reserves it as the thread environment pointer"};
                    }
                    matched = assign_register(reg, name.c_str(), c.X[i]);
                    break;
                }
                if (reg.name == "sp") {
                    std::uint64_t value = 0;
                    matched = assign_register(reg, "sp", value);
                    if (matched && (value & 0xfu) != 0) {
                        CloseHandle(thread);
                        return Error{ErrorCode::invalid_argument, "ARM64 stack pointer edits must preserve 16-byte alignment"};
                    }
                    if (matched) c.Sp = value;
                } else if (reg.name == "pc") {
                    std::uint64_t value = 0;
                    matched = assign_register(reg, "pc", value);
                    if (matched && (value & 3u) != 0) {
                        CloseHandle(thread);
                        return Error{ErrorCode::invalid_argument, "ARM64 program counter edits must be four-byte aligned"};
                    }
                    if (matched) c.Pc = value;
                } else if (reg.name == "cpsr") {
                    std::uint32_t value = 0;
                    matched = assign_register(reg, "cpsr", value);
                    constexpr std::uint32_t user_condition_flags = 0xf0000000u;
                    if (matched && ((value ^ c.Cpsr) & ~user_condition_flags) != 0) {
                        CloseHandle(thread);
                        return Error{ErrorCode::invalid_argument, "ARM64 CPSR edits may change only the NZCV condition flags"};
                    }
                    if (matched) c.Cpsr = value;
                } else if (reg.name.size() >= 2 && reg.name[0] == 'v') {
                    std::uint32_t index = 0;
                    const auto parsed = std::from_chars(reg.name.data() + 1, reg.name.data() + reg.name.size(), index);
                    if (parsed.ec == std::errc{} && parsed.ptr == reg.name.data() + reg.name.size() && index < 32) {
                        matched = reg.bytes.size() == sizeof(c.V[index]);
                        if (matched) std::memcpy(&c.V[index], reg.bytes.data(), sizeof(c.V[index]));
                    }
                } else if (reg.name == "fpcr") matched = assign_register(reg, "fpcr", c.Fpcr);
                else if (reg.name == "fpsr") matched = assign_register(reg, "fpsr", c.Fpsr);
                if (!matched) {
                    CloseHandle(thread);
                    return Error{ErrorCode::invalid_argument, "unknown or incorrectly sized Windows ARM64 register"};
                }
            }
            const bool ok = SetThreadContext(thread, &c) != FALSE;
            const auto error = ok ? Error{} : win_error("SetThreadContext for ARM64 edit");
            CloseHandle(thread);
            return ok ? Status{std::monostate{}} : Status{error};
#endif
        }
        HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, static_cast<DWORD>(id));
        if (!thread) return win_error("OpenThread");
#if defined(_WIN64)
        if (target_architecture() == Architecture::x86) {
            WOW64_CONTEXT c{};
            c.ContextFlags = WOW64_CONTEXT_FULL | WOW64_CONTEXT_FLOATING_POINT | WOW64_CONTEXT_EXTENDED_REGISTERS;
            if (!Wow64GetThreadContext(thread, &c)) { CloseHandle(thread); return win_error("Wow64GetThreadContext"); }
            std::vector<RegisterValue> fp_writes;
            for (const auto& reg : registers)
                if (detail::x86_i386_fxsave_field(reg.name)) fp_writes.push_back(reg);
            if (!fp_writes.empty()) {
                auto image = std::span<std::byte>(reinterpret_cast<std::byte*>(c.ExtendedRegisters),
                                                  sizeof(c.ExtendedRegisters));
                auto written = detail::write_x86_i386_fxsave_registers(image, fp_writes);
                if (!written) { CloseHandle(thread); return written; }
            }
            for (const auto& r : registers) {
                if (detail::x86_i386_fxsave_field(r.name)) continue;
                if (assign_register(r,"eax",c.Eax)||assign_register(r,"ebx",c.Ebx)||assign_register(r,"ecx",c.Ecx)||assign_register(r,"edx",c.Edx)||
                    assign_register(r,"esi",c.Esi)||assign_register(r,"edi",c.Edi)||assign_register(r,"ebp",c.Ebp)||assign_register(r,"esp",c.Esp)||
                    assign_register(r,"eip",c.Eip)||assign_register(r,"eflags",c.EFlags)) continue;
                CloseHandle(thread); return Error{ErrorCode::invalid_argument, "unknown or incorrectly sized x86 register"};
            }
            const bool ok = Wow64SetThreadContext(thread, &c) != FALSE; CloseHandle(thread);
            return ok ? Status{std::monostate{}} : Status{win_error("Wow64SetThreadContext")};
        }
#endif
        CONTEXT legacy{};
#if defined(_M_X64)
        std::optional<X64AvxContext> avx;
        if (wants_ymm) {
            auto captured = read_x64_avx_context(thread);
            if (!captured) {
                const auto error = captured.error();
                CloseHandle(thread);
                return error;
            }
            avx.emplace(std::move(captured.value()));
        }
        CONTEXT& c = avx ? *avx->context : legacy;
        if (!avx) c.ContextFlags = CONTEXT_FULL | CONTEXT_FLOATING_POINT;
        DWORD edited_flags = 0;
        const bool captured = avx.has_value() || GetThreadContext(thread, &c) != FALSE;
#else
        CONTEXT& c = legacy;
        c.ContextFlags = CONTEXT_FULL;
        const bool captured = GetThreadContext(thread, &c) != FALSE;
#endif
        if (!captured) {
            const auto error = win_error("GetThreadContext");
            CloseHandle(thread);
            return error;
        }
#if defined(_M_X64)
        std::vector<RegisterValue> fp_writes;
        for (const auto& reg : registers)
            if (detail::x86_fxsave_field(reg.name) && !reg.name.starts_with("xmm"))
                fp_writes.push_back(reg);
        if (!fp_writes.empty()) {
            static_assert(sizeof(c.FltSave) >= detail::x86_fxsave_size);
            std::array<std::byte, detail::x86_fxsave_size> image{};
            std::memcpy(image.data(), &c.FltSave, image.size());
            auto written = detail::write_x86_fxsave_registers(image, fp_writes);
            if (!written) { CloseHandle(thread); return written; }
            std::memcpy(&c.FltSave, image.data(), image.size());
            edited_flags |= CONTEXT_FLOATING_POINT;
        }
#elif defined(_M_IX86)
        std::vector<RegisterValue> fp_writes;
        for (const auto& reg : registers)
            if (detail::x86_i386_fxsave_field(reg.name)) fp_writes.push_back(reg);
        if (!fp_writes.empty()) {
            static_assert(sizeof(c.ExtendedRegisters) >= detail::x86_fxsave_size);
            auto image = std::span<std::byte>(reinterpret_cast<std::byte*>(c.ExtendedRegisters),
                                              sizeof(c.ExtendedRegisters));
            auto written = detail::write_x86_i386_fxsave_registers(image, fp_writes);
            if (!written) { CloseHandle(thread); return written; }
            c.ContextFlags |= CONTEXT_FLOATING_POINT | CONTEXT_EXTENDED_REGISTERS;
        }
#endif
        for (const auto& r : registers) {
#if defined(_M_X64)
            bool vector_matched = false;
            for (std::uint32_t i = 0; i < 16; ++i) {
                const auto name = "xmm" + std::to_string(i);
                if (assign_register(r, name.c_str(), c.FltSave.XmmRegisters[i])) {
                    vector_matched = true;
                    edited_flags |= CONTEXT_FLOATING_POINT;
                    break;
                }
                if (avx && r.name == "ymm" + std::to_string(i)) {
                    std::memcpy(&c.FltSave.XmmRegisters[i], r.bytes.data(), sizeof(M128A));
                    std::memcpy(avx->upper + i * sizeof(M128A), r.bytes.data() + sizeof(M128A), sizeof(M128A));
                    vector_matched = true;
                    edited_flags |= CONTEXT_FLOATING_POINT | CONTEXT_XSTATE;
                    break;
                }
            }
            if (vector_matched) continue;
            if (detail::x86_fxsave_field(r.name) && !r.name.starts_with("xmm")) continue;
            if (assign_register(r,"rax",c.Rax)||assign_register(r,"rbx",c.Rbx)||assign_register(r,"rcx",c.Rcx)||assign_register(r,"rdx",c.Rdx)||
                assign_register(r,"rsi",c.Rsi)||assign_register(r,"rdi",c.Rdi)||assign_register(r,"rbp",c.Rbp)||assign_register(r,"rsp",c.Rsp)||
                assign_register(r,"rip",c.Rip)||assign_register(r,"r8",c.R8)||assign_register(r,"r9",c.R9)||assign_register(r,"r10",c.R10)||
                assign_register(r,"r11",c.R11)||assign_register(r,"r12",c.R12)||assign_register(r,"r13",c.R13)||assign_register(r,"r14",c.R14)||
                assign_register(r,"r15",c.R15)||assign_register(r,"eflags",c.EFlags)) {
                edited_flags |= r.name == "rip" || r.name == "rsp" || r.name == "eflags" ? CONTEXT_CONTROL : CONTEXT_INTEGER;
                continue;
            }
#elif defined(_M_IX86)
            if (detail::x86_i386_fxsave_field(r.name)) continue;
            if (assign_register(r,"eax",c.Eax)||assign_register(r,"ebx",c.Ebx)||assign_register(r,"ecx",c.Ecx)||assign_register(r,"edx",c.Edx)||
                assign_register(r,"esi",c.Esi)||assign_register(r,"edi",c.Edi)||assign_register(r,"ebp",c.Ebp)||assign_register(r,"esp",c.Esp)||
                assign_register(r,"eip",c.Eip)||assign_register(r,"eflags",c.EFlags)) continue;
#else
            CloseHandle(thread); return Error{ErrorCode::unsupported, "this Windows build cannot edit the requested target context"};
#endif
            CloseHandle(thread); return Error{ErrorCode::invalid_argument, "unknown or incorrectly sized register"};
        }
#if defined(_M_X64)
        if (avx) {
            const auto& api = xstate_api();
            DWORD64 selected = 0;
            c.ContextFlags &= edited_flags;
            if (!avx_context_enabled(api) || !api.set_mask(&c, avx_feature_mask) ||
                !api.get_mask(&c, &selected) || selected != avx_feature_mask) {
                CloseHandle(thread);
                return Error{ErrorCode::unsupported, "Windows YMM state is unavailable for this register edit"};
            }
        }
#endif
        const bool ok = SetThreadContext(thread, &c) != FALSE;
#if defined(_M_X64)
        const auto error = ok ? Error{} : avx ? xstate_error("SetThreadContext for x64 AVX state") : win_error("SetThreadContext");
#else
        const auto error = ok ? Error{} : win_error("SetThreadContext");
#endif
        CloseHandle(thread);
        return ok ? Status{std::monostate{}} : Status{error};
    }
    Result<Breakpoint> add_breakpoint(std::uint64_t address, BreakpointKind kind) override {
        if (!process_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        if (arm32_step_) return Error{ErrorCode::busy, "ARM32 step patch restoration is pending"};
        if (kind != BreakpointKind::software) return Error{ErrorCode::invalid_argument, "use hardware breakpoint API for execute/data breakpoints"};
        bool thumb = false;
        if (target_architecture() == Architecture::arm) {
#if !defined(_M_ARM)
            return Error{ErrorCode::unsupported, "Windows ARM32 software breakpoints require an ARM32 debugger build"};
#else
            if (!pending_) return Error{ErrorCode::busy, "ARM32 software breakpoints can only be changed during a debug stop"};
            if (address > UINT32_MAX) return Error{ErrorCode::invalid_argument, "ARM32 breakpoint address exceeds 32 bits"};
            // ARMNT is Thumb code by default. A breakpoint at the stopped PC
            // can use its CPSR to select A32; bit zero explicitly tags Thumb.
            thumb = true;
            if ((address & 1u) == 0 && (address & 3u) == 0) {
                const auto owner = static_cast<ThreadId>(pending_->dwThreadId);
                HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, static_cast<DWORD>(owner));
                if (!thread) return win_error("OpenThread for ARM32 breakpoint mode");
                CONTEXT c{};
                c.ContextFlags = CONTEXT_CONTROL;
                const bool ok = GetThreadContext(thread, &c) != FALSE;
                const auto error = ok ? Error{} : win_error("GetThreadContext for ARM32 breakpoint mode");
                CloseHandle(thread);
                if (!ok) return error;
                if (c.Pc == (address & ~UINT64_C(1))) thumb = (c.Cpsr & (1u << 5)) != 0;
            }
#endif
        }
        const auto key = static_cast<std::uintptr_t>(target_architecture() == Architecture::arm ? address & ~UINT64_C(1) : address);
        if (breakpoints_.contains(key)) return Error{ErrorCode::conflict, "breakpoint already exists at address"};
        const auto trap = target_architecture() == Architecture::arm ? arm32_breakpoint_instruction(thumb) : software_breakpoint_instruction();
        if (target_architecture() == Architecture::arm && (key & (thumb ? 1u : 3u)) != 0)
            return Error{ErrorCode::invalid_argument, "ARM32 breakpoint address is not aligned for its instruction state"};
        if (target_architecture() == Architecture::arm && key > UINT32_MAX - trap.size())
            return Error{ErrorCode::invalid_argument, "ARM32 breakpoint instruction exceeds the address space"};
        if (target_architecture() == Architecture::arm64 && (address & 3u) != 0)
            return Error{ErrorCode::invalid_argument, "ARM64 software breakpoints must be four-byte aligned"};
        if (target_architecture() == Architecture::arm64 && !pending_)
            return Error{ErrorCode::busy, "ARM64 software breakpoints can only be changed while a debug event has stopped the target"};
        const auto end = key + trap.size();
        for (const auto& [at, record] : breakpoints_)
            if (at < end && key < at + record.extent)
                return Error{ErrorCode::conflict, "breakpoint overlaps an existing patched instruction"};
        if (target_architecture() == Architecture::arm && thumb && key >= 2) {
            std::array<std::byte, 2> preceding{};
            SIZE_T preceding_read = 0;
            if (!ReadProcessMemory(process_, reinterpret_cast<const void*>(key - 2), preceding.data(), 2, &preceding_read) ||
                preceding_read != 2)
                return Error{ErrorCode::unsupported, "cannot verify Thumb instruction boundary before breakpoint"};
            if (arm32_thumb_wide_prefix(static_cast<std::uint16_t>(
                    std::to_integer<unsigned>(preceding[0]) | (std::to_integer<unsigned>(preceding[1]) << 8))))
                return Error{ErrorCode::unsupported, "Thumb breakpoint may address the second half of a wide instruction"};
        }
        std::vector<std::byte> original(trap.size()); SIZE_T read = 0;
        if (!ReadProcessMemory(process_, reinterpret_cast<const void*>(key), original.data(), original.size(), &read) || read != original.size()) return win_error("ReadProcessMemory breakpoint instruction");
        const bool wide_thumb = target_architecture() == Architecture::arm && thumb &&
            arm32_thumb_wide_prefix(static_cast<std::uint16_t>(std::to_integer<unsigned>(original[0]) |
                (std::to_integer<unsigned>(original[1]) << 8)));
        const auto extent = wide_thumb ? 4u : trap.size();
        if (target_architecture() == Architecture::arm && key > UINT32_MAX - extent)
            return Error{ErrorCode::invalid_argument, "ARM32 breakpoint instruction exceeds the address space"};
        if (wide_thumb) {
            std::array<std::byte, 2> tail{};
            SIZE_T tail_read = 0;
            if (!ReadProcessMemory(process_, reinterpret_cast<const void*>(key + 2), tail.data(), 2, &tail_read) || tail_read != 2)
                return win_error("ReadProcessMemory wide Thumb breakpoint instruction");
        }
        for (const auto& [at, record] : breakpoints_)
            if (at < key + extent && key < at + record.extent)
                return Error{ErrorCode::conflict, "breakpoint overlaps an existing instruction"};
        auto patched = patch_bytes(key, trap);
        if (!patched) return patched.error();
        const auto id = ++breakpoint_id_; breakpoints_.emplace(key, BreakpointRecord{id, std::move(original), trap, extent, true, thumb});
        return Breakpoint{id, address, kind, true, static_cast<std::uint8_t>(trap.size())};
    }
    Result<Breakpoint> add_hardware_breakpoint(std::uint64_t address, BreakpointKind kind, std::uint8_t size) override {
        if (!process_) return Error{ErrorCode::invalid_argument, "no debug target is attached"};
        const auto architecture = target_architecture();
        if (architecture == Architecture::arm)
            return Error{ErrorCode::unsupported, "Windows ARM32 hardware breakpoint ownership and hit attribution are not implemented"};
        if (architecture != Architecture::x86 && architecture != Architecture::x86_64 &&
            architecture != Architecture::arm64)
            return Error{ErrorCode::unsupported, "hardware breakpoints require a supported x86, x64, or ARM64 target context"};
        if (architecture == Architecture::arm64) {
#if !defined(_M_ARM64)
            return Error{ErrorCode::unsupported, "this debugger build cannot access Windows ARM64 debug registers; rebuild for ARM64"};
#else
            if (!pending_) return Error{ErrorCode::busy, "hardware breakpoints can only be changed while a debug event has stopped the target"};
            auto requests = hardware_requests();
            requests.push_back({address, kind, size});
            if (!encode_arm64_debug_configuration(requests))
                return Error{ErrorCode::invalid_argument, "invalid ARM64 hardware breakpoint kind, size, alignment, or slot capacity"};
            auto applied = update_hardware_registers(requests, hardware_requests());
            if (!applied) return applied.error();
            const auto id = ++breakpoint_id_;
            hardware_breakpoints_.push_back({id, address, kind, size});
            return Breakpoint{id, address, kind, true, size};
#endif
        }
        if (architecture == Architecture::arm) {
#if !defined(_M_ARM)
            return Error{ErrorCode::unsupported, "this debugger build cannot access Windows ARM32 debug registers; rebuild for ARM32"};
#else
            if (!pending_) return Error{ErrorCode::busy, "hardware breakpoints can only be changed while a debug event has stopped the target"};
            auto requests = hardware_requests();
            requests.push_back({address, kind, size});
            if (!encode_arm32_debug_configuration(requests))
                return Error{ErrorCode::invalid_argument, "ARM32 execute breakpoints require aligned ARM/Thumb addresses and one of eight slots"};
            auto applied = update_hardware_registers(requests, hardware_requests());
            if (!applied) return applied.error();
            const auto id = ++breakpoint_id_;
            hardware_breakpoints_.push_back({id, address, kind, size});
            return Breakpoint{id, address, kind, true, size};
#endif
        }
        if (kind == BreakpointKind::read)
            return Error{ErrorCode::unsupported, "x86/x64 debug registers cannot distinguish read-only watchpoints; choose access (read/write) or write"};
        if (!pending_) return Error{ErrorCode::busy, "hardware breakpoints can only be changed while a debug event has stopped the target"};
        auto requests = hardware_requests(); requests.push_back({address, kind, size});
        detail::DebugRegisters encoded;
        const auto pointer_size = static_cast<std::uint8_t>(target_architecture() == Architecture::x86 ? 4 : 8);
        if (!detail::encode_hardware_breakpoints(requests, pointer_size, encoded))
            return Error{ErrorCode::invalid_argument, "invalid hardware breakpoint size/alignment, kind, address, or slot capacity"};
        auto applied = update_hardware_registers(requests, hardware_requests());
        if (!applied) return applied.error();
        const auto id = ++breakpoint_id_;
        hardware_breakpoints_.push_back({id, address, kind, size});
        return Breakpoint{id, address, kind, true, size};
    }
    Status remove_breakpoint(BreakpointId id) override {
        if (arm32_step_) return Error{ErrorCode::busy, "ARM32 step patch restoration is pending"};
        if (!hardware_breakpoints_.empty() && std::any_of(hardware_breakpoints_.begin(), hardware_breakpoints_.end(), [id](const auto& bp) { return bp.id == id; })) {
            if (!pending_) return Error{ErrorCode::busy, "hardware breakpoints can only be changed while a debug event has stopped the target"};
            auto next = hardware_breakpoints_;
            std::erase_if(next, [id](const auto& bp) { return bp.id == id; });
            if (next.size() == hardware_breakpoints_.size()) return Error{ErrorCode::invalid_argument, "unknown breakpoint id"};
            auto requests = requests_from(next);
            auto applied = update_hardware_registers(requests, hardware_requests());
            if (!applied) return applied;
            hardware_breakpoints_ = std::move(next);
            return std::monostate{};
        }
        const auto found = std::find_if(breakpoints_.begin(), breakpoints_.end(), [id](const auto& item) { return item.second.id == id; });
        if (found == breakpoints_.end()) return Error{ErrorCode::invalid_argument, "unknown breakpoint id"};
        if ((target_architecture() == Architecture::arm64 || target_architecture() == Architecture::arm) && !pending_)
            return Error{ErrorCode::busy, "ARM software breakpoints can only be changed while a debug event has stopped the target"};
        auto restored = patch_bytes(found->first, found->second.original);
        if (!restored) return restored;
        breakpoints_.erase(found); return std::monostate{};
    }
    Status set_breakpoint_enabled(BreakpointId id, bool enabled) override {
        if (arm32_step_) return Error{ErrorCode::busy, "ARM32 step patch restoration is pending"};
        const auto hardware = std::find_if(hardware_breakpoints_.begin(), hardware_breakpoints_.end(),
            [id](const auto& item) { return item.id == id; });
        if (hardware != hardware_breakpoints_.end()) {
            if (!pending_) return Error{ErrorCode::busy, "hardware breakpoints can only be changed while a debug event has stopped the target"};
            if (hardware->enabled == enabled) return std::monostate{};
            auto next = hardware_breakpoints_;
            const auto updated = std::find_if(next.begin(), next.end(), [id](const auto& item) { return item.id == id; });
            updated->enabled = enabled;
            auto applied = update_hardware_registers(requests_from(next), hardware_requests());
            if (!applied) return applied;
            hardware_breakpoints_ = std::move(next);
            return std::monostate{};
        }
        const auto found = std::find_if(breakpoints_.begin(), breakpoints_.end(),
            [id](const auto& item) { return item.second.id == id; });
        if (found == breakpoints_.end()) return Error{ErrorCode::invalid_argument, "unknown software breakpoint id"};
        if (found->second.enabled == enabled) return std::monostate{};
        if ((target_architecture() == Architecture::arm64 || target_architecture() == Architecture::arm) && !pending_)
            return Error{ErrorCode::busy, "ARM software breakpoints can only be changed while a debug event has stopped the target"};
        const auto bytes = enabled ? found->second.trap : found->second.original;
        auto patched = patch_bytes(found->first, bytes);
        if (!patched) return patched;
        found->second.enabled = enabled;
        return std::monostate{};
    }

private:
    struct Arm32StepState {
        DWORD thread = 0;
        std::uintptr_t successor = 0;
        std::vector<std::byte> original, trap;
        std::optional<std::uintptr_t> displaced;
        std::optional<DWORD> restore_pc;
        bool thumb = false;
        bool rewind_successor = false;
        bool successor_patched = false;
    };

    Status restore_arm32_step() {
        if (!arm32_step_) return std::monostate{};
        if (arm32_step_->restore_pc || arm32_step_->rewind_successor) {
#if !defined(_M_ARM)
            return Error{ErrorCode::unsupported, "ARM32 step PC restoration requires an ARM32 debugger build"};
#else
            HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                       FALSE, arm32_step_->thread);
            if (!thread) return win_error("OpenThread restoring ARM32 step PC");
            if (GetProcessIdOfThread(thread) != process_id_) {
                CloseHandle(thread);
                return Error{ErrorCode::invalid_argument, "ARM32 step thread no longer belongs to the target"};
            }
            CONTEXT c{};
            c.ContextFlags = CONTEXT_CONTROL;
            if (!GetThreadContext(thread, &c)) {
                const auto error = win_error("GetThreadContext restoring ARM32 step PC");
                CloseHandle(thread);
                return error;
            }
            if (arm32_step_->rewind_successor && ((c.Cpsr & (1u << 5)) != 0) != arm32_step_->thumb) {
                CloseHandle(thread);
                return Error{ErrorCode::unsupported, "ARM32 step stop changed instruction state unexpectedly"};
            }
            DWORD desired = c.Pc;
            if (arm32_step_->restore_pc) desired = *arm32_step_->restore_pc;
            else if (c.Pc == arm32_step_->successor + arm32_step_->trap.size())
                desired = static_cast<DWORD>(arm32_step_->successor);
            else if (c.Pc != arm32_step_->successor) {
                CloseHandle(thread);
                return Error{ErrorCode::unsupported, "ARM32 step stop PC does not match the temporary breakpoint"};
            }
            if (desired != c.Pc) {
                c.Pc = desired;
                if (!SetThreadContext(thread, &c)) {
                    const auto error = win_error("SetThreadContext restoring ARM32 step PC");
                    CloseHandle(thread);
                    return error;
                }
            }
            CloseHandle(thread);
            arm32_step_->restore_pc.reset();
            arm32_step_->rewind_successor = false;
#endif
        }
        if (arm32_step_->successor_patched) {
            auto restored = patch_bytes(arm32_step_->successor, arm32_step_->original);
            if (!restored) return restored;
            arm32_step_->successor_patched = false;
        }
        if (arm32_step_->displaced) {
            const auto found = breakpoints_.find(*arm32_step_->displaced);
            if (found != breakpoints_.end() && found->second.enabled) {
                auto restored = patch_bytes(found->first, found->second.trap);
                if (!restored) return restored;
            }
        }
        arm32_step_.reset();
        return std::monostate{};
    }

    Status single_step_arm32(ContinueStatus status) {
#if !defined(_M_ARM)
        (void)status;
        return Error{ErrorCode::unsupported, "Windows ARM32 stepping requires an ARM32 debugger build"};
#else
        if (status != ContinueStatus::handled)
            return Error{ErrorCode::unsupported, "ARM32 stepping requires a handled pending event"};
        if (pending_->dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT ||
            pending_->dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
            return Error{ErrorCode::invalid_argument, "cannot step an exit event"};
        if (arm32_step_) return Error{ErrorCode::busy, "previous ARM32 step restoration is pending"};
        const DWORD thread_id = pending_->dwThreadId;
        HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, thread_id);
        if (!thread) return win_error("OpenThread for ARM32 step");
        if (GetProcessIdOfThread(thread) != process_id_) {
            CloseHandle(thread);
            return Error{ErrorCode::invalid_argument, "ARM32 step thread does not belong to the target"};
        }
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(thread, &context)) {
            const auto error = win_error("GetThreadContext for ARM32 step");
            CloseHandle(thread);
            return error;
        }
        CONTEXT original_context = context;
        const bool thumb = (context.Cpsr & (1u << 5)) != 0;
        constexpr DWORD it_state = (3u << 25) | (0x3fu << 10);
        if (thumb && (context.Cpsr & it_state) != 0) {
            // The successor trap is only unconditional after the last IT
            // instruction. Earlier instructions may be skipped by their
            // predicate, and the following instruction would still be inside
            // ITSTATE, so a software BKPT there is not a safe step boundary.
            const auto packed_it_state = static_cast<std::uint8_t>(
                ((context.Cpsr >> 8) & 0xfcu) | ((context.Cpsr >> 25) & 3u));
            // ITSTATE advances to zero after this instruction only when it is
            // the final slot; then normal execution reaches the trap outside
            // the conditional block regardless of whether the predicate passes.
            if ((packed_it_state & 7u) != 0) {
                CloseHandle(thread);
                return Error{ErrorCode::unsupported,
                    "ARM32 temporary-trap stepping is available only on the final sequential instruction in a Thumb IT block"};
            }
        }
        std::uintptr_t pc = context.Pc;
        if ((pc & (thumb ? 1u : 3u)) != 0) {
            CloseHandle(thread);
            return Error{ErrorCode::invalid_argument, "ARM32 step PC is misaligned for its CPSR Thumb state"};
        }
        std::optional<std::uintptr_t> displaced;
        if (pending_->dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            pending_->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
            const auto hit = reinterpret_cast<std::uintptr_t>(pending_->u.Exception.ExceptionRecord.ExceptionAddress);
            const auto found = breakpoints_.find(hit);
            if (found != breakpoints_.end() && found->second.enabled) {
                if (found->second.thumb != thumb || (pc != hit && pc != hit + found->second.trap.size())) {
                    CloseHandle(thread);
                    return Error{ErrorCode::unsupported, "ARM32 breakpoint PC/state does not match the owned instruction"};
                }
                pc = hit;
                displaced = hit;
            }
        }
        if (pc > UINT32_MAX - 4u) {
            CloseHandle(thread);
            return Error{ErrorCode::invalid_argument, "ARM32 step exceeds the 32-bit instruction address space"};
        }
        std::array<std::byte, 4> instruction{};
        SIZE_T read = 0;
        if (!ReadProcessMemory(process_, reinterpret_cast<const void*>(pc), instruction.data(), instruction.size(), &read) ||
            read != instruction.size()) {
            const auto error = win_error("ReadProcessMemory for ARM32 step instruction");
            CloseHandle(thread);
            return error;
        }
        if (displaced) {
            const auto& original = breakpoints_.at(*displaced).original;
            std::copy(original.begin(), original.end(), instruction.begin());
        }
        const auto width = arm32_linear_instruction_width(instruction, thumb);
        if (!width) {
            CloseHandle(thread);
            return Error{ErrorCode::unsupported, "ARM32 step supports only verified sequential ARM/Thumb instructions"};
        }
        const auto successor = pc + *width;
        const auto trap = arm32_breakpoint_instruction(thumb);
        if (successor > UINT32_MAX - trap.size()) {
            CloseHandle(thread);
            return Error{ErrorCode::invalid_argument, "ARM32 step successor exceeds the address space"};
        }
        for (const auto& [at, record] : breakpoints_)
            if (at < successor + trap.size() && successor < at + record.extent) {
                CloseHandle(thread);
                return Error{ErrorCode::unsupported, "ARM32 step successor overlaps a user breakpoint"};
            }
        Arm32StepState state;
        state.thread = thread_id;
        state.successor = successor;
        state.trap = trap;
        state.displaced = displaced;
        state.thumb = thumb;
        state.original.resize(trap.size());
        if (!ReadProcessMemory(process_, reinterpret_cast<const void*>(successor), state.original.data(),
                               state.original.size(), &read) || read != state.original.size()) {
            const auto error = win_error("ReadProcessMemory for ARM32 step successor");
            CloseHandle(thread);
            return error;
        }
        auto resumed = resume_step_suspensions();
        if (!resumed) { CloseHandle(thread); return resumed; }
        arm32_step_ = std::move(state);
        if (displaced) {
            auto removed = patch_bytes(*displaced, breakpoints_.at(*displaced).original);
            if (!removed) {
                auto restored = restore_arm32_step();
                CloseHandle(thread);
                if (!restored)
                    return Error{ErrorCode::io, removed.error().message +
                        "; restoring the ARM32 breakpoint also failed: " + restored.error().message};
                return removed;
            }
        }
        auto fail = [&](const Error& cause) -> Status {
            const bool pc_ok = SetThreadContext(thread, &original_context) != FALSE;
            const auto pc_error = pc_ok ? Error{} : win_error("restoring ARM32 step context");
            if (!pc_ok) arm32_step_->restore_pc = original_context.Pc;
            auto restored = restore_arm32_step();
            auto released = resume_step_suspensions();
            CloseHandle(thread);
            if (!pc_ok || !restored || !released)
                return Error{ErrorCode::io, cause.message +
                    (pc_ok ? "" : "; " + pc_error.message) +
                    (restored ? "" : "; restoring ARM32 trap failed: " + restored.error().message) +
                    (released ? "" : "; releasing peer threads failed: " + released.error().message)};
            return cause;
        };
        auto patched = patch_bytes(successor, trap);
        if (!patched) {
            arm32_step_->successor_patched = true; // The patch helper may have failed during rollback.
            return fail(patched.error());
        }
        arm32_step_->successor_patched = true;
        context.Pc = static_cast<DWORD>(pc);
        if (!SetThreadContext(thread, &context)) return fail(win_error("SetThreadContext for ARM32 step"));
        auto suspended = suspend_peer_threads(thread_id);
        if (!suspended) return fail(suspended.error());
        if (!ContinueDebugEvent(pending_->dwProcessId, pending_->dwThreadId, DBG_CONTINUE))
            return fail(win_error("ContinueDebugEvent for ARM32 step"));
        CloseHandle(thread);
        close_event_handles(*pending_);
        pending_.reset();
        arm32_completed_step_pending_ = false;
        return std::monostate{};
#endif
    }

    Status single_step_arm64(std::uint64_t sequence, ContinueStatus status) {
        (void)sequence;
#if !defined(_M_ARM64)
        (void)status;
        return Error{ErrorCode::unsupported, "this debugger build cannot step Windows ARM64 contexts; rebuild for ARM64"};
#else
        auto resumed = resume_step_suspensions();
        if (!resumed) return resumed;
        if (pending_->dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
            return Error{ErrorCode::invalid_argument, "cannot single-step a process-exit event"};
        const auto thread_id = static_cast<ThreadId>(pending_->dwThreadId);
        HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                   FALSE, static_cast<DWORD>(thread_id));
        if (!thread) return win_error("OpenThread for ARM64 single-step");
        CONTEXT context{};
        context.ContextFlags = CONTEXT_ARM64_CONTROL | CONTEXT_ARM64_INTEGER;
        if (!GetThreadContext(thread, &context)) {
            const auto error = win_error("GetThreadContext for ARM64 single-step");
            CloseHandle(thread);
            return error;
        }
        const auto original_pc = context.Pc;
        const auto original_cpsr = context.Cpsr;
        std::optional<Arm64HardwareStepState> hardware_step_state;
        if (pending_->dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            pending_->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
            const auto hit_address = reinterpret_cast<std::uintptr_t>(pending_->u.Exception.ExceptionRecord.ExceptionAddress);
            const auto execute_hit = std::any_of(hardware_breakpoints_.begin(), hardware_breakpoints_.end(),
                [hit_address](const auto& bp) { return bp.enabled && bp.kind == BreakpointKind::execute && bp.address == hit_address; });
            if (execute_hit) {
                if (context.Pc != hit_address) {
                    CloseHandle(thread);
                    return Error{ErrorCode::unsupported, "ARM64 execute-breakpoint context PC does not match the reported hit address"};
                }
                context.ContextFlags |= CONTEXT_ARM64_DEBUG_REGISTERS;
                const auto encoded = encode_arm64_debug_configuration(hardware_requests());
                if (!encoded) { CloseHandle(thread); return Error{ErrorCode::conflict, "cannot encode the active ARM64 execute breakpoints for step-over"}; }
                Arm64HardwareStepState state;
                state.thread = static_cast<DWORD>(thread_id);
                for (std::size_t slot = 0; slot < encoded->breakpoint_count; ++slot) {
                    if (encoded->breakpoint_value[slot] != hit_address) continue;
                    if (context.Bcr[slot] != encoded->breakpoint_control[slot] ||
                        context.Bvr[slot] != encoded->breakpoint_value[slot]) {
                        CloseHandle(thread);
                        return Error{ErrorCode::conflict, "ARM64 execute breakpoint registers changed outside this debugger"};
                    }
                    state.owned[slot] = true;
                    state.control[slot] = context.Bcr[slot];
                    state.value[slot] = context.Bvr[slot];
                    context.Bcr[slot] = 0;
                }
                if (std::none_of(state.owned.begin(), state.owned.end(), [](bool owned) { return owned; })) {
                    CloseHandle(thread);
                    return Error{ErrorCode::conflict, "ARM64 execute breakpoint hit did not match an owned debug slot"};
                }
                hardware_step_state = state;
            }
        }
        std::optional<std::uintptr_t> displaced_breakpoint;
        const auto is_breakpoint_event = pending_->dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            pending_->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT;
        if (is_breakpoint_event) {
            const auto address = reinterpret_cast<std::uintptr_t>(pending_->u.Exception.ExceptionRecord.ExceptionAddress);
            const auto found = breakpoints_.find(address);
            if (found != breakpoints_.end() && found->second.enabled) {
                if (context.Pc != address && context.Pc != static_cast<std::uint64_t>(address) + 4) {
                    CloseHandle(thread);
                    return Error{ErrorCode::unsupported, "ARM64 breakpoint context PC is not at the trap instruction or its following instruction"};
                }
                if (address > UINTPTR_MAX - 4) {
                    CloseHandle(thread);
                    return Error{ErrorCode::invalid_argument, "ARM64 breakpoint address overflows its instruction extent"};
                }
                auto removed = patch_bytes(address, found->second.original);
                if (!removed) {
                    CloseHandle(thread);
                    return removed;
                }
                context.Pc = address;
                displaced_breakpoint = address;
            }
        }
        constexpr DWORD64 arm64_single_step_bit = DWORD64{1} << 21; // PSTATE.SS
        context.Cpsr |= static_cast<DWORD>(arm64_single_step_bit);
        if (!SetThreadContext(thread, &context)) {
            const auto error = win_error("SetThreadContext enabling ARM64 single-step");
            Status trap_restored = std::monostate{};
            if (displaced_breakpoint) trap_restored = patch_bytes(*displaced_breakpoint, software_breakpoint_instruction());
            Status hw_restored = std::monostate{};
            if (hardware_step_state) hw_restored = restore_arm64_hardware_step_state(*hardware_step_state);
            CloseHandle(thread);
            if (!trap_restored || !hw_restored)
                return Error{ErrorCode::io, error.message +
                    std::string(!trap_restored ? "; restoring ARM64 breakpoint bytes/protection also failed: " + trap_restored.error().message : "") +
                    std::string(!hw_restored ? "; restoring ARM64 hardware breakpoints also failed: " + hw_restored.error().message : "")};
            return error;
        }
        CloseHandle(thread);
        if (displaced_breakpoint && !stepping_breakpoint_.begin(
                *displaced_breakpoint, *displaced_breakpoint + 4, thread_id)) {
            HANDLE restore_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                               FALSE, static_cast<DWORD>(thread_id));
            bool restored = false;
            if (restore_thread) {
                CONTEXT restore{};
                restore.ContextFlags = CONTEXT_ARM64_CONTROL | CONTEXT_ARM64_INTEGER;
                if (GetThreadContext(restore_thread, &restore)) {
                    restore.Pc = original_pc;
                    restore.Cpsr = original_cpsr;
                    restored = SetThreadContext(restore_thread, &restore) != FALSE;
                }
                CloseHandle(restore_thread);
            }
            auto trap_restored = patch_bytes(*displaced_breakpoint, software_breakpoint_instruction());
            if (!trap_restored || !restored)
                return Error{ErrorCode::io, "cannot restore ARM64 breakpoint state after a concurrent step" +
                    std::string(!trap_restored ? "; bytes/protection: " + trap_restored.error().message : "")};
            return Error{ErrorCode::busy, "another software breakpoint step is already pending"};
        }
        if (hardware_step_state) arm64_hardware_step_ = *hardware_step_state;
        auto suspended = suspend_peer_threads(thread_id);
        if (!suspended) {
            if (displaced_breakpoint) stepping_breakpoint_.clear();
            auto restored = restore_arm64_step_context(thread_id, original_pc, original_cpsr);
            Status trap_restored = std::monostate{};
            if (displaced_breakpoint) trap_restored = patch_bytes(*displaced_breakpoint, software_breakpoint_instruction());
            Status hw_restored = std::monostate{};
            if (hardware_step_state) { hw_restored = restore_arm64_hardware_step(); }
            if (!restored || !trap_restored || !hw_restored)
                return Error{ErrorCode::io, suspended.error().message +
                    std::string(!restored ? "; restoring ARM64 thread state failed: " + restored.error().message : "") +
                    std::string(!trap_restored ? "; restoring ARM64 breakpoint bytes/protection failed: " + trap_restored.error().message : "") +
                    std::string(!hw_restored ? "; restoring ARM64 hardware breakpoints failed: " + hw_restored.error().message : "")};
            return suspended;
        }
        const DWORD disposition = status == ContinueStatus::handled ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
        if (!ContinueDebugEvent(pending_->dwProcessId, pending_->dwThreadId, disposition)) {
            const auto continue_error = win_error("ContinueDebugEvent for ARM64 single-step");
            if (displaced_breakpoint) stepping_breakpoint_.clear();
            auto restored = restore_arm64_step_context(thread_id, original_pc, original_cpsr);
            Status trap_restored = std::monostate{};
            if (displaced_breakpoint) trap_restored = patch_bytes(*displaced_breakpoint, software_breakpoint_instruction());
            Status hw_restored = std::monostate{};
            if (hardware_step_state) hw_restored = restore_arm64_hardware_step();
            auto released = resume_step_suspensions();
            if (!restored || !trap_restored || !hw_restored)
                return Error{ErrorCode::io, continue_error.message +
                    std::string(!restored ? "; restoring ARM64 thread state failed: " + restored.error().message : "") +
                    std::string(!trap_restored ? "; restoring ARM64 breakpoint bytes/protection failed: " + trap_restored.error().message : "") +
                    std::string(!hw_restored ? "; restoring ARM64 hardware breakpoints failed: " + hw_restored.error().message : "")};
            if (!released)
                return Error{ErrorCode::io, continue_error.message + "; releasing peer-thread suspensions also failed"};
            return continue_error;
        }
        arm64_step_thread_ = static_cast<DWORD>(thread_id);
        arm64_step_original_cpsr_ = original_cpsr;
        if (hardware_step_state) arm64_hardware_step_ = *hardware_step_state;
        close_event_handles(*pending_);
        pending_.reset();
        return std::monostate{};
#endif
    }
    Status restore_arm64_step_context(ThreadId id, std::uint64_t pc, DWORD cpsr) {
#if !defined(_M_ARM64)
        (void)id; (void)pc; (void)cpsr;
        return Error{ErrorCode::unsupported, "Windows ARM64 context restoration requires an ARM64 debugger build"};
#else
        HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                   FALSE, static_cast<DWORD>(id));
        if (!thread) return win_error("OpenThread restoring ARM64 step context");
        CONTEXT context{};
        context.ContextFlags = CONTEXT_ARM64_CONTROL | CONTEXT_ARM64_INTEGER;
        if (!GetThreadContext(thread, &context)) {
            const auto error = win_error("GetThreadContext restoring ARM64 step context");
            CloseHandle(thread);
            return error;
        }
        context.Pc = pc;
        context.Cpsr = cpsr;
        const bool ok = SetThreadContext(thread, &context) != FALSE;
        const auto error = ok ? Error{} : win_error("SetThreadContext restoring ARM64 step context");
        CloseHandle(thread);
        return ok ? Status{std::monostate{}} : Status{error};
#endif
    }
    Status restore_arm64_step_cpsr(DWORD id, DWORD cpsr) {
#if !defined(_M_ARM64)
        (void)id; (void)cpsr;
        return Error{ErrorCode::unsupported, "Windows ARM64 context restoration requires an ARM64 debugger build"};
#else
        HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                   FALSE, id);
        if (!thread) return win_error("OpenThread restoring ARM64 single-step flags");
        CONTEXT context{};
        context.ContextFlags = CONTEXT_ARM64_CONTROL;
        if (!GetThreadContext(thread, &context)) {
            const auto error = win_error("GetThreadContext restoring ARM64 single-step flags");
            CloseHandle(thread);
            return error;
        }
        context.Cpsr = cpsr;
        const bool ok = SetThreadContext(thread, &context) != FALSE;
        const auto error = ok ? Error{} : win_error("SetThreadContext restoring ARM64 single-step flags");
        CloseHandle(thread);
        return ok ? Status{std::monostate{}} : Status{error};
#endif
    }

    Status restore_arm64_hardware_step_state(const Arm64HardwareStepState& state) {
#if !defined(_M_ARM64)
        (void)state;
        return Error{ErrorCode::unsupported, "Windows ARM64 debug-register restoration requires an ARM64 debugger build"};
#else
        HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                   FALSE, state.thread);
        if (!thread) return win_error("OpenThread restoring ARM64 hardware breakpoint step-over");
        CONTEXT context{};
        context.ContextFlags = CONTEXT_ARM64_DEBUG_REGISTERS;
        if (!GetThreadContext(thread, &context)) {
            const auto error = win_error("GetThreadContext restoring ARM64 hardware breakpoint step-over");
            CloseHandle(thread);
            return error;
        }
        for (std::size_t slot = 0; slot < state.owned.size(); ++slot) {
            if (!state.owned[slot]) continue;
            if (context.Bvr[slot] != state.value[slot] ||
                (context.Bcr[slot] != 0 && context.Bcr[slot] != state.control[slot])) {
                CloseHandle(thread);
                return Error{ErrorCode::conflict, "ARM64 execute breakpoint slot changed while stepping over it"};
            }
            if (context.Bcr[slot] == 0) context.Bcr[slot] = state.control[slot];
        }
        const bool ok = SetThreadContext(thread, &context) != FALSE;
        const auto error = ok ? Error{} : win_error("SetThreadContext restoring ARM64 hardware breakpoint step-over");
        CloseHandle(thread);
        return ok ? Status{std::monostate{}} : Status{error};
#endif
    }

    Status restore_arm64_hardware_step() {
        if (!arm64_hardware_step_) return std::monostate{};
        auto restored = restore_arm64_hardware_step_state(*arm64_hardware_step_);
        if (restored) arm64_hardware_step_.reset();
        return restored;
    }

    Status suspend_peer_threads(ThreadId stepping_thread) {
        const std::array<ThreadId, 1> selected{stepping_thread};
        return suspend_unselected_threads(selected);
    }
    Status suspend_unselected_threads(std::span<const ThreadId> selected) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return win_error("CreateToolhelp32Snapshot for thread resume");
        THREADENTRY32 entry{}; entry.dwSize = sizeof(entry);
        std::vector<HANDLE> candidates;
        std::vector<ThreadId> found_selected;
        std::size_t target_threads = 0;
        Error failure{}; bool failed = false;
        if (Thread32First(snapshot, &entry)) do {
            if (entry.th32OwnerProcessID == process_id_) {
                if (++target_threads > max_inspection_threads) {
                    failure = {ErrorCode::resource_limit, "thread resume suspension exceeds the 4096-thread limit"}; failed = true; break;
                }
                if (std::find(selected.begin(), selected.end(), static_cast<ThreadId>(entry.th32ThreadID)) != selected.end())
                    found_selected.push_back(entry.th32ThreadID);
                else {
                    HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
                    if (!thread) { failure = win_error("OpenThread for thread resume"); failed = true; break; }
                    candidates.push_back(thread);
                }
            }
            entry.dwSize = sizeof(entry);
        } while (Thread32Next(snapshot, &entry));
        const DWORD enumeration_error = GetLastError();
        if (!failed && enumeration_error != ERROR_NO_MORE_FILES) {
            SetLastError(enumeration_error);
            failure = win_error("enumerating target threads for thread resume"); failed = true;
        }
        CloseHandle(snapshot);
        if (!failed && std::any_of(selected.begin(), selected.end(), [&](ThreadId thread) {
                return std::find(found_selected.begin(), found_selected.end(), thread) == found_selected.end();
            })) {
            failure = {ErrorCode::invalid_argument, "selected resume thread is absent from the target thread snapshot"}; failed = true;
        }
        if (failed) {
            for (HANDLE thread : candidates) CloseHandle(thread);
            return failure;
        }
        const auto suspended = detail::suspend_other_threads(candidates, static_cast<HANDLE>(nullptr),
            [](HANDLE thread) -> Status {
                if (SuspendThread(thread) == static_cast<DWORD>(-1)) return win_error("SuspendThread for thread resume");
                return std::monostate{};
            },
            [](HANDLE thread) -> Status {
                if (ResumeThread(thread) == static_cast<DWORD>(-1)) return win_error("ResumeThread rollback for thread resume");
                return std::monostate{};
            }, step_suspended_threads_);
        if (!suspended) {
            step_suspension_handles_ = step_suspended_threads_;
            for (HANDLE thread : candidates) {
                if (std::find(step_suspended_threads_.begin(), step_suspended_threads_.end(), thread) == step_suspended_threads_.end())
                    CloseHandle(thread);
            }
            return suspended;
        }
        step_suspension_handles_ = std::move(candidates);
        return std::monostate{};
    }
    Status resume_step_suspensions() {
        auto result = detail::resume_suspended_threads(step_suspended_threads_, [](HANDLE thread) -> Status {
            if (ResumeThread(thread) == static_cast<DWORD>(-1)) return win_error("ResumeThread after thread resume");
            return std::monostate{};
        });
        if (step_suspended_threads_.empty()) {
            for (HANDLE thread : step_suspension_handles_) CloseHandle(thread);
            step_suspension_handles_.clear();
        }
        return result;
    }
    static void close_event_handles(const DEBUG_EVENT& event) {
        switch (event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
            if (event.u.CreateProcessInfo.hThread) CloseHandle(event.u.CreateProcessInfo.hThread);
            if (event.u.CreateProcessInfo.hProcess) CloseHandle(event.u.CreateProcessInfo.hProcess);
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            if (event.u.CreateThread.hThread) CloseHandle(event.u.CreateThread.hThread);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            if (event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
            break;
        default:
            break;
        }
    }
    struct HardwareBreakpointRecord { BreakpointId id; std::uint64_t address; BreakpointKind kind; std::uint8_t size; bool enabled = true; };
    static std::vector<detail::HardwareRequest> requests_from(const std::vector<HardwareBreakpointRecord>& records) {
        std::vector<detail::HardwareRequest> out; out.reserve(records.size());
        for (const auto& bp : records) if (bp.enabled) out.push_back({bp.address, bp.kind, bp.size});
        return out;
    }
    std::vector<detail::HardwareRequest> hardware_requests() const { return requests_from(hardware_breakpoints_); }
    Status update_hardware_registers(const std::vector<detail::HardwareRequest>& requests,
                                     const std::vector<detail::HardwareRequest>& prior_requests) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return win_error("CreateToolhelp32Snapshot for hardware breakpoints");
        THREADENTRY32 entry{}; entry.dwSize = sizeof(entry);
        std::vector<HANDLE> threads;
        Error failure{};
        bool failed = false;
        if (Thread32First(snapshot, &entry)) do {
            if (entry.th32OwnerProcessID == process_id_) {
                HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
                if (!thread) { failure = win_error("OpenThread for hardware breakpoint"); failed = true; break; }
                threads.push_back(thread);
            }
            entry.dwSize = sizeof(entry);
        } while (Thread32Next(snapshot, &entry));
        CloseHandle(snapshot);
        if (failed) {
            for (HANDLE thread : threads) CloseHandle(thread);
            return failure;
        }
        auto status = detail::transact_debug_registers(threads,
            [&](HANDLE thread) { return write_debug_registers(thread, requests, prior_requests); },
            [&](HANDLE thread) { return write_debug_registers(thread, prior_requests, requests); });
        for (HANDLE thread : threads) CloseHandle(thread);
        return status;
    }
    Status write_debug_registers(HANDLE thread, const std::vector<detail::HardwareRequest>& requests,
                                 const std::vector<detail::HardwareRequest>& expected_current,
                                 bool newly_created_thread = false) {
        if (target_architecture() == Architecture::arm) {
#if !defined(_M_ARM)
            return Error{ErrorCode::unsupported, "Windows ARM32 debug-register access requires an ARM32 debugger build"};
#else
            const auto desired = encode_arm32_debug_configuration(requests);
            const auto expected = encode_arm32_debug_configuration(expected_current);
            if (!desired || !expected)
                return Error{ErrorCode::invalid_argument, "invalid ARM32 hardware breakpoint configuration"};
            CONTEXT context{};
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (!GetThreadContext(thread, &context)) return win_error("GetThreadContext for ARM32 hardware breakpoint");
            const auto original = context;
            for (std::size_t i = 0; i < std::max(desired->breakpoint_count, expected->breakpoint_count); ++i) {
                const bool was_owned = i < expected->breakpoint_count;
                const bool will_be_owned = i < desired->breakpoint_count;
                if (was_owned) {
                    if (context.Bcr[i] != expected->breakpoint_control[i] ||
                        context.Bvr[i] != expected->breakpoint_value[i])
                        return Error{ErrorCode::conflict, "ARM32 thread breakpoint register changed outside this debugger"};
                } else if (will_be_owned && (context.Bcr[i] != 0 || context.Bvr[i] != 0)) {
                    return Error{ErrorCode::conflict, "ARM32 thread already uses a requested hardware breakpoint slot"};
                }
                context.Bcr[i] = will_be_owned ? desired->breakpoint_control[i] : 0;
                context.Bvr[i] = will_be_owned ? desired->breakpoint_value[i] : 0;
            }
            if (!SetThreadContext(thread, &context)) return win_error("SetThreadContext for ARM32 hardware breakpoint");
            CONTEXT observed{};
            observed.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (!GetThreadContext(thread, &observed)) {
                const auto read_error = win_error("GetThreadContext verifying ARM32 hardware breakpoint");
                if (!SetThreadContext(thread, &original))
                    return Error{ErrorCode::io, read_error.message + "; failed to restore prior ARM32 debug-register context"};
                return read_error;
            }
            bool verified = true;
            for (std::size_t i = 0; i < std::max(desired->breakpoint_count, expected->breakpoint_count); ++i) {
                const auto expected_control = i < desired->breakpoint_count ? desired->breakpoint_control[i] : 0u;
                const auto expected_value = i < desired->breakpoint_count ? desired->breakpoint_value[i] : 0u;
                verified = verified && observed.Bcr[i] == expected_control && observed.Bvr[i] == expected_value;
            }
            if (!verified) {
                if (!SetThreadContext(thread, &original))
                    return Error{ErrorCode::io, "ARM32 debug comparator is unavailable and prior context restoration failed"};
                return Error{ErrorCode::unsupported, "the ARM32 target does not expose enough hardware execute comparators"};
            }
            return std::monostate{};
#endif
        }
        if (target_architecture() == Architecture::arm64) {
#if !defined(_M_ARM64)
            return Error{ErrorCode::unsupported, "Windows ARM64 debug-register access requires an ARM64 debugger build"};
#else
            const auto desired = encode_arm64_debug_configuration(requests);
            const auto expected = encode_arm64_debug_configuration(expected_current);
            if (!desired || !expected)
                return Error{ErrorCode::invalid_argument, "invalid ARM64 hardware breakpoint configuration"};
            CONTEXT context{};
            context.ContextFlags = CONTEXT_ARM64_DEBUG_REGISTERS;
            if (!GetThreadContext(thread, &context)) return win_error("GetThreadContext for ARM64 hardware breakpoint");
            for (std::size_t i = 0; i < std::max(desired->breakpoint_count, expected->breakpoint_count); ++i) {
                const bool was_owned = i < expected->breakpoint_count;
                const bool will_be_owned = i < desired->breakpoint_count;
                if (was_owned) {
                    if (context.Bcr[i] != expected->breakpoint_control[i] ||
                        context.Bvr[i] != expected->breakpoint_value[i])
                        return Error{ErrorCode::conflict, "ARM64 thread breakpoint register changed outside this debugger"};
                } else if (will_be_owned && (context.Bcr[i] != 0 || context.Bvr[i] != 0)) {
                    return Error{ErrorCode::conflict, "ARM64 thread already uses a requested hardware breakpoint slot"};
                }
                context.Bcr[i] = will_be_owned ? desired->breakpoint_control[i] : 0;
                context.Bvr[i] = will_be_owned ? desired->breakpoint_value[i] : 0;
            }
            for (std::size_t i = 0; i < std::max(desired->watch_count, expected->watch_count); ++i) {
                const bool was_owned = i < expected->watch_count;
                const bool will_be_owned = i < desired->watch_count;
                if (was_owned) {
                    if (context.Wcr[i] != expected->watch_control[i] ||
                        context.Wvr[i] != expected->watch_value[i])
                        return Error{ErrorCode::conflict, "ARM64 thread watchpoint register changed outside this debugger"};
                } else if (will_be_owned && (context.Wcr[i] != 0 || context.Wvr[i] != 0)) {
                    return Error{ErrorCode::conflict, "ARM64 thread already uses a requested watchpoint slot"};
                }
                context.Wcr[i] = will_be_owned ? desired->watch_control[i] : 0;
                context.Wvr[i] = will_be_owned ? desired->watch_value[i] : 0;
            }
            if (!SetThreadContext(thread, &context)) return win_error("SetThreadContext for ARM64 hardware breakpoint");
            return std::monostate{};
#endif
        }
        detail::DebugRegisters dr; const auto ptr = target_architecture() == Architecture::x86 ? 4 : 8;
        if (!detail::encode_hardware_breakpoints(requests, static_cast<std::uint8_t>(ptr), dr))
            return Error{ErrorCode::invalid_argument, "invalid hardware breakpoint configuration"};
#if defined(_WIN64)
        if (target_architecture() == Architecture::x86) {
            WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
            if (!Wow64GetThreadContext(thread, &c)) return win_error("Wow64GetThreadContext for hardware breakpoint");
            detail::DebugRegisters prior; (void)detail::encode_hardware_breakpoints(expected_current, 4, prior);
            constexpr DWORD slot_mask = 0xffff00ffu; // DR0-DR3 enables and RW/LEN fields only.
            const std::array<DWORD, 4> addresses{c.Dr0, c.Dr1, c.Dr2, c.Dr3};
            bool current_matches = (c.Dr7 & slot_mask) == (static_cast<DWORD>(prior.dr7) & slot_mask);
            for (std::size_t i = 0; current_matches && i < expected_current.size(); ++i)
                current_matches = addresses[i] == prior.address[i];
            const bool empty_new_thread = newly_created_thread && (c.Dr7 & slot_mask) == 0 &&
                std::all_of(addresses.begin(), addresses.end(), [](DWORD value) { return value == 0; });
            if (!current_matches && !empty_new_thread)
                return Error{ErrorCode::conflict, "thread hardware breakpoint state changed outside this debugger"};
            for (std::size_t i = expected_current.size(); i < requests.size(); ++i)
                if (!empty_new_thread && addresses[i] != 0)
                    return Error{ErrorCode::conflict, "thread already has an unowned address in a requested hardware slot"};
            std::array<DWORD*, 4> slots{&c.Dr0, &c.Dr1, &c.Dr2, &c.Dr3};
            for (std::size_t i = 0; i < slots.size(); ++i) {
                if (i < requests.size()) *slots[i] = static_cast<DWORD>(dr.address[i]);
                else if (i < expected_current.size()) *slots[i] = 0; // Slots were required to be clear before ownership.
                // Preserve every debug-address register outside our owned slots.
            }
            c.Dr7 = (c.Dr7 & ~slot_mask) | (static_cast<DWORD>(dr.dr7) & slot_mask);
            if (!Wow64SetThreadContext(thread, &c)) return win_error("Wow64SetThreadContext for hardware breakpoint");
            return std::monostate{};
        }
#endif
#if !defined(_M_X64) && !defined(_M_IX86)
        return Error{ErrorCode::unsupported, "this Windows build cannot access x86/x64 debug registers"};
#else
        CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(thread, &c)) return win_error("GetThreadContext for hardware breakpoint");
        detail::DebugRegisters prior; (void)detail::encode_hardware_breakpoints(expected_current, static_cast<std::uint8_t>(ptr), prior);
        using DebugWord = decltype(c.Dr0);
        constexpr DebugWord slot_mask = static_cast<DebugWord>(0xffff00ffu); // DR0-DR3 enables and RW/LEN fields only.
        const std::array<DebugWord, 4> addresses{c.Dr0, c.Dr1, c.Dr2, c.Dr3};
        bool current_matches = (c.Dr7 & slot_mask) == (prior.dr7 & slot_mask);
        for (std::size_t i = 0; current_matches && i < expected_current.size(); ++i)
            current_matches = addresses[i] == prior.address[i];
        const bool empty_new_thread = newly_created_thread && (c.Dr7 & slot_mask) == 0 &&
            std::all_of(addresses.begin(), addresses.end(), [](DebugWord value) { return value == 0; });
        if (!current_matches && !empty_new_thread)
            return Error{ErrorCode::conflict, "thread hardware breakpoint state changed outside this debugger"};
        for (std::size_t i = expected_current.size(); i < requests.size(); ++i)
            if (!empty_new_thread && addresses[i] != 0)
                return Error{ErrorCode::conflict, "thread already has an unowned address in a requested hardware slot"};
        std::array<DebugWord*, 4> slots{&c.Dr0, &c.Dr1, &c.Dr2, &c.Dr3};
        for (std::size_t i = 0; i < slots.size(); ++i) {
            if (i < requests.size()) *slots[i] = dr.address[i];
            else if (i < expected_current.size()) *slots[i] = 0; // Slots were required to be clear before ownership.
            // Preserve every debug-address register outside our owned slots.
        }
        c.Dr7 = static_cast<decltype(c.Dr7)>((c.Dr7 & ~slot_mask) | (dr.dr7 & slot_mask));
        if (!SetThreadContext(thread, &c)) return win_error("SetThreadContext for hardware breakpoint");
        return std::monostate{};
#endif
    }
    std::optional<std::uint64_t> read_clear_dr6(DWORD thread_id, std::string& diagnostic) {
        HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                   FALSE, thread_id);
        if (!thread) { diagnostic = win_error("OpenThread for hardware breakpoint status").message; return std::nullopt; }
#if defined(_WIN64)
        if (target_architecture() == Architecture::x86) {
            WOW64_CONTEXT context{}; context.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
            if (!Wow64GetThreadContext(thread, &context)) {
                diagnostic = win_error("Wow64GetThreadContext for hardware breakpoint status").message;
                CloseHandle(thread); return std::nullopt;
            }
            const auto status = static_cast<std::uint64_t>(context.Dr6);
            if ((context.Dr6 & 0xfu) != 0) {
                context.Dr6 &= ~0xfu;
                if (!Wow64SetThreadContext(thread, &context))
                    diagnostic = win_error("Wow64SetThreadContext clearing hardware breakpoint status").message;
            }
            CloseHandle(thread); return status;
        }
#endif
#if !defined(_M_X64) && !defined(_M_IX86)
        diagnostic = "this Windows build cannot read x86/x64 hardware breakpoint status";
        CloseHandle(thread);
        return std::nullopt;
#else
        CONTEXT context{}; context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(thread, &context)) {
            diagnostic = win_error("GetThreadContext for hardware breakpoint status").message;
            CloseHandle(thread); return std::nullopt;
        }
        const auto status = static_cast<std::uint64_t>(context.Dr6);
        if ((context.Dr6 & 0xfu) != 0) {
            context.Dr6 &= ~0xfu;
            if (!SetThreadContext(thread, &context))
                diagnostic = win_error("SetThreadContext clearing hardware breakpoint status").message;
        }
        CloseHandle(thread); return status;
#endif
    }
    Result<DWORD> read_eflags(ThreadId id) {
        HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, static_cast<DWORD>(id));
        if (!thread) return win_error("OpenThread for single-step");
#if defined(_WIN64)
        if (target_architecture() == Architecture::x86) {
            WOW64_CONTEXT context{}; context.ContextFlags = WOW64_CONTEXT_CONTROL;
            const bool ok = Wow64GetThreadContext(thread, &context) != FALSE;
            const auto error = ok ? Error{} : win_error("Wow64GetThreadContext for single-step");
            CloseHandle(thread);
            if (!ok) return error;
            return context.EFlags;
        }
#endif
#if !defined(_M_X64) && !defined(_M_IX86)
        CloseHandle(thread);
        return Error{ErrorCode::unsupported, "this Windows build cannot read x86/x64 single-step flags"};
#else
        CONTEXT context{}; context.ContextFlags = CONTEXT_CONTROL;
        const bool ok = GetThreadContext(thread, &context) != FALSE;
        const auto error = ok ? Error{} : win_error("GetThreadContext for single-step");
        CloseHandle(thread);
        if (!ok) return error;
        return context.EFlags;
#endif
    }

    Status write_eflags(ThreadId id, DWORD flags) {
        HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                  FALSE, static_cast<DWORD>(id));
        if (!thread) return win_error("OpenThread for single-step");
#if defined(_WIN64)
        if (target_architecture() == Architecture::x86) {
            WOW64_CONTEXT context{}; context.ContextFlags = WOW64_CONTEXT_CONTROL;
            if (!Wow64GetThreadContext(thread, &context)) {
                const auto error = win_error("Wow64GetThreadContext for single-step");
                CloseHandle(thread); return error;
            }
            context.EFlags = flags;
            const bool ok = Wow64SetThreadContext(thread, &context) != FALSE;
            const auto error = ok ? Error{} : win_error("Wow64SetThreadContext for single-step");
            CloseHandle(thread);
            return ok ? Status{std::monostate{}} : Status{error};
        }
#endif
#if !defined(_M_X64) && !defined(_M_IX86)
        CloseHandle(thread);
        return Error{ErrorCode::unsupported, "this Windows build cannot write x86/x64 single-step flags"};
#else
        CONTEXT context{}; context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(thread, &context)) {
            const auto error = win_error("GetThreadContext for single-step");
            CloseHandle(thread); return error;
        }
        context.EFlags = flags;
        const bool ok = SetThreadContext(thread, &context) != FALSE;
        const auto error = ok ? Error{} : win_error("SetThreadContext for single-step");
        CloseHandle(thread);
        return ok ? Status{std::monostate{}} : Status{error};
#endif
    }

    struct BreakpointRecord {
        BreakpointId id;
        std::vector<std::byte> original, trap;
        std::size_t extent;
        bool enabled;
        bool thumb = false;
    };
    static std::vector<std::byte> arm32_breakpoint_instruction(bool thumb) {
        // Thumb BKPT #0 and A32 BKPT #0, in little-endian instruction order.
        return thumb ? std::vector<std::byte>{std::byte{0x00}, std::byte{0xbe}} :
            std::vector<std::byte>{std::byte{0x70}, std::byte{0x00}, std::byte{0x20}, std::byte{0xe1}};
    }
    std::vector<std::byte> software_breakpoint_instruction() const {
        if (target_architecture() == Architecture::arm64) {
            // BRK #0xF000, the ARM64 instruction emitted by MSVC __debugbreak.
            return {std::byte{0x00}, std::byte{0x00}, std::byte{0x3e}, std::byte{0xd4}};
        }
        return {std::byte{0xcc}};
    }
    Status patch_bytes(std::uintptr_t address, std::span<const std::byte> bytes) {
        if (bytes.empty()) return std::monostate{};
        std::vector<std::byte> original(bytes.size());
        SIZE_T read = 0;
        if (!ReadProcessMemory(process_, reinterpret_cast<const void*>(address), original.data(), original.size(), &read) ||
            read != original.size()) return win_error("ReadProcessMemory before code patch");
        DWORD old_protection = 0;
        if (!VirtualProtectEx(process_, reinterpret_cast<void*>(address), bytes.size(), PAGE_EXECUTE_READWRITE, &old_protection))
            return win_error("VirtualProtectEx enabling code patch");

        SIZE_T written = 0;
        const BOOL write_ok = WriteProcessMemory(process_, reinterpret_cast<void*>(address), bytes.data(), bytes.size(), &written);
        const DWORD write_error = write_ok && written == bytes.size() ? ERROR_SUCCESS :
            (write_ok ? ERROR_WRITE_FAULT : GetLastError());
        if (write_error != ERROR_SUCCESS) {
            SIZE_T restored = 0;
            const BOOL rollback_ok = WriteProcessMemory(process_, reinterpret_cast<void*>(address), original.data(),
                                                         original.size(), &restored);
            const DWORD rollback_error = rollback_ok && restored == original.size() ? ERROR_SUCCESS :
                (rollback_ok ? ERROR_WRITE_FAULT : GetLastError());
            FlushInstructionCache(process_, reinterpret_cast<const void*>(address), bytes.size());
            DWORD ignored = 0;
            const BOOL protection_ok = VirtualProtectEx(process_, reinterpret_cast<void*>(address), bytes.size(),
                                                         old_protection, &ignored);
            const DWORD protection_error = protection_ok ? ERROR_SUCCESS : GetLastError();
            std::string message = "code patch write failed (Win32 error " + std::to_string(write_error) + ")";
            if (rollback_error != ERROR_SUCCESS)
                message += "; restoring original bytes failed (Win32 error " + std::to_string(rollback_error) + ")";
            if (protection_error != ERROR_SUCCESS)
                message += "; restoring original page protection failed (Win32 error " + std::to_string(protection_error) + ")";
            return Error{ErrorCode::io, std::move(message)};
        }

        FlushInstructionCache(process_, reinterpret_cast<const void*>(address), bytes.size());
        DWORD ignored = 0;
        if (VirtualProtectEx(process_, reinterpret_cast<void*>(address), bytes.size(), old_protection, &ignored))
            return std::monostate{};

        const DWORD protection_error = GetLastError();
        DWORD writable_protection = 0;
        const BOOL writable_ok = VirtualProtectEx(process_, reinterpret_cast<void*>(address), bytes.size(),
                                                   PAGE_EXECUTE_READWRITE, &writable_protection);
        const DWORD writable_error = writable_ok ? ERROR_SUCCESS : GetLastError();
        DWORD rollback_error = ERROR_SUCCESS;
        if (writable_ok) {
            SIZE_T restored = 0;
            const BOOL rollback_ok = WriteProcessMemory(process_, reinterpret_cast<void*>(address), original.data(),
                                                         original.size(), &restored);
            rollback_error = rollback_ok && restored == original.size() ? ERROR_SUCCESS :
                (rollback_ok ? ERROR_WRITE_FAULT : GetLastError());
            FlushInstructionCache(process_, reinterpret_cast<const void*>(address), bytes.size());
        }
        DWORD final_ignored = 0;
        const BOOL final_protection_ok = VirtualProtectEx(process_, reinterpret_cast<void*>(address), bytes.size(),
                                                           old_protection, &final_ignored);
        const DWORD final_protection_error = final_protection_ok ? ERROR_SUCCESS : GetLastError();
        std::string message = "restoring original page protection after code patch failed (Win32 error " +
            std::to_string(protection_error) + ")";
        if (!writable_ok)
            message += "; could not make the range writable to roll back bytes (Win32 error " + std::to_string(writable_error) + ")";
        else if (rollback_error != ERROR_SUCCESS)
            message += "; restoring original bytes failed (Win32 error " + std::to_string(rollback_error) + ")";
        if (final_protection_error != ERROR_SUCCESS)
            message += "; restoring original page protection after rollback failed (Win32 error " + std::to_string(final_protection_error) + ")";
        return Error{ErrorCode::io, std::move(message)};
    }
    Status patch_byte(std::uintptr_t address, std::byte value) {
        return patch_bytes(address, std::span<const std::byte>(&value, 1));
    }
    Architecture target_architecture() const {
        if (!process_) return Architecture::unknown;
        return architecture_;
    }
    void close_handles() {
        (void)resume_step_suspensions();
        for (HANDLE thread : step_suspension_handles_) CloseHandle(thread);
        step_suspension_handles_.clear(); step_suspended_threads_.clear();
        if (process_) CloseHandle(process_);
        close_terminate_handle();
        process_ = nullptr; process_id_ = 0; launched_ = false; exited_ = false; pending_.reset(); breakpoints_.clear();
        architecture_ = Architecture::unknown;
        stepping_breakpoint_.clear(); hardware_breakpoints_.clear(); arm32_step_.reset(); arm32_completed_step_pending_ = false; arm64_step_thread_.reset(); arm64_step_original_cpsr_.reset(); arm64_hardware_step_.reset();
    }
    void close_terminate_handle() {
        if (terminate_process_) CloseHandle(terminate_process_);
        terminate_process_ = nullptr;
    }
    HANDLE process_ = nullptr;
    HANDLE terminate_process_ = nullptr;
    Architecture architecture_ = Architecture::unknown;
    DWORD process_id_ = 0;
    bool launched_ = false;
    bool exited_ = false;
    std::uint64_t sequence_ = 0;
    BreakpointId breakpoint_id_ = 0;
    std::optional<DEBUG_EVENT> pending_;
    std::optional<DWORD> arm64_step_thread_;
    std::optional<Arm32StepState> arm32_step_;
    bool arm32_completed_step_pending_ = false;
    std::optional<DWORD> arm64_step_original_cpsr_;
    std::optional<Arm64HardwareStepState> arm64_hardware_step_;
    std::vector<HANDLE> step_suspended_threads_;
    std::vector<HANDLE> step_suspension_handles_;
    detail::BreakpointStepState stepping_breakpoint_;
    std::map<std::uintptr_t, BreakpointRecord> breakpoints_;
    std::vector<HardwareBreakpointRecord> hardware_breakpoints_;
};
}
std::unique_ptr<Backend> make_native_backend() { return std::make_unique<Win32Backend>(); }
} // namespace hexlab::debugger
