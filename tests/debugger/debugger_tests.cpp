#include "hexlab/debugger/debugger.hpp"
#include "../../libs/debugger/src/breakpoint_step_state.hpp"
#include "../../libs/debugger/src/hardware_breakpoint_state.hpp"
#include "../../libs/debugger/src/thread_suspend_state.hpp"
#include "../../libs/debugger/src/elf_process_architecture.hpp"
#include "../../libs/debugger/src/linux_x86_registers.hpp"
#include "../../libs/debugger/src/linux_x86_fp_registers.hpp"
#include "support/checks.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <limits>
#include <map>
#include <new>
#include <string>
#include <string_view>
#include <vector>
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#elif defined(__linux__)
#include <poll.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <thread>
#endif

using namespace hexlab;
using namespace hexlab::debugger;

namespace {
#if defined(_WIN32)
constexpr DWORD debugger_fixture_exception = 0xE0424242;
volatile LONG debugger_fixture_exception_handled = 0;
LONG WINAPI debugger_fixture_exception_handler(EXCEPTION_POINTERS* info) {
    if (info && info->ExceptionRecord &&
        info->ExceptionRecord->ExceptionCode == debugger_fixture_exception) {
        InterlockedExchange(&debugger_fixture_exception_handled, 1);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
volatile LONG debugger_software_breakpoint_counter = 0;
extern "C" __declspec(noinline) void debugger_software_breakpoint_target() {
    InterlockedIncrement(&debugger_software_breakpoint_counter);
}
#endif

class FakeBackend final : public Backend {
public:
    Result<std::vector<ProcessInfo>> processes() override { return process_list; }
    Result<ProcessInfo> launch(const Target&) override { return ProcessInfo{42, "fake", Architecture::x86_64}; }
    Result<ProcessInfo> attach(ProcessId id) override { return ProcessInfo{id, "fake", Architecture::x86_64}; }
    Status detach() override { detached = true; return std::monostate{}; }
    Status request_interrupt() override { ++interrupt_calls; return std::monostate{}; }
    Result<DebugEvent> wait_event(std::chrono::milliseconds) override {
        if (!next_event) return Error{ErrorCode::busy, "no event"};
        auto result = *next_event; next_event.reset(); return result;
    }
    Status continue_event(std::uint64_t sequence, ContinueStatus) override {
        continued.push_back(sequence); return std::monostate{};
    }
    Status single_step_event(std::uint64_t sequence, ContinueStatus status) override {
        stepped.push_back({sequence, status}); return std::monostate{};
    }
    Result<std::vector<std::byte>> read_memory(std::uint64_t address, std::size_t size) override {
        ++read_calls;
        std::vector<std::byte> result(size);
        for (std::size_t i = 0; i < size; ++i) result[i] = memory[address + i];
        return result;
    }
    Status write_memory(std::uint64_t address, std::span<const std::byte> bytes) override {
        for (std::size_t i = 0; i < bytes.size(); ++i) memory[address + i] = bytes[i];
        return std::monostate{};
    }
    Result<std::vector<ThreadInfo>> threads() override { return thread_list; }
    Result<std::vector<ModuleInfo>> modules() override { return std::vector<ModuleInfo>{{"fake.dll", "C:/fake.dll", 0x1000, 0x2000}}; }
    Result<std::vector<RegisterValue>> read_registers(ThreadId) override { return std::vector<RegisterValue>{{"ip", {std::byte{0x10}}}}; }
    Status write_registers(ThreadId, std::span<const RegisterValue>) override { return std::monostate{}; }
    Result<Breakpoint> add_breakpoint(std::uint64_t address, BreakpointKind kind) override { return Breakpoint{1, address, kind, true}; }
    Status remove_breakpoint(BreakpointId) override {
        ++remove_breakpoint_calls;
        if (fail_remove_breakpoint) return Error{ErrorCode::io, "injected breakpoint removal failure"};
        return std::monostate{};
    }
    Status set_breakpoint_enabled(BreakpointId id, bool enabled) override {
        ++toggle_breakpoint_calls;
        if (fail_toggle_breakpoint) return Error{ErrorCode::io, "injected breakpoint toggle failure"};
        if (id != 1) return Error{ErrorCode::invalid_argument, "unknown breakpoint id"};
        backend_breakpoint_enabled = enabled;
        return std::monostate{};
    }

    bool detached = false;
    std::vector<ProcessInfo> process_list{{17, "fake-process", Architecture::x86_64}};
    std::vector<ThreadInfo> thread_list{{9, "main", ThreadState::running}};
    std::optional<DebugEvent> next_event;
    std::vector<std::uint64_t> continued;
    std::vector<std::pair<std::uint64_t, ContinueStatus>> stepped;
    std::map<std::uint64_t, std::byte> memory;
    std::size_t read_calls = 0;
    std::size_t interrupt_calls = 0;
    std::size_t remove_breakpoint_calls = 0;
    bool fail_remove_breakpoint = false;
    std::size_t toggle_breakpoint_calls = 0;
    bool fail_toggle_breakpoint = false;
    bool backend_breakpoint_enabled = true;
};

void run_tests() {
    {
        std::array<std::byte, detail::x86_fxsave_size> image{};
        image[detail::x86_xmm_offset(15)] = std::byte{0xa5};
        image[detail::x86_st_offset(7)] = std::byte{0x5a};
        const auto decoded = detail::x86_fxsave_register_values(image);
        hexlab_test::check(decoded && decoded.value().size() == 31,
                           "x86-64 FP state exposes control, x87, and all XMM registers");
        const auto xmm15 = std::find_if(decoded.value().begin(), decoded.value().end(), [](const auto& value) {
            return value.name == "xmm15";
        });
        const auto st7 = std::find_if(decoded.value().begin(), decoded.value().end(), [](const auto& value) {
            return value.name == "st7";
        });
        hexlab_test::check(xmm15 != decoded.value().end() && xmm15->bytes.size() == 16 &&
                               xmm15->bytes.front() == std::byte{0xa5} && st7 != decoded.value().end() &&
                               st7->bytes.size() == 10 && st7->bytes.front() == std::byte{0x5a},
                           "FXSAVE register decoding uses the architectural x87 and XMM slots");
        std::vector<std::byte> new_xmm(16, std::byte{0x31});
        std::vector<std::byte> new_st(10, std::byte{0x72});
        const std::array writes{RegisterValue{"xmm15", new_xmm}, RegisterValue{"st0", new_st}};
        const auto written = detail::write_x86_fxsave_registers(image, writes);
        const auto roundtrip = detail::x86_fxsave_register_values(image);
        hexlab_test::check(written && roundtrip &&
                               std::find_if(roundtrip.value().begin(), roundtrip.value().end(), [](const auto& value) {
                                   return value.name == "xmm15" && value.bytes.front() == std::byte{0x31};
                               }) != roundtrip.value().end() &&
                               std::find_if(roundtrip.value().begin(), roundtrip.value().end(), [](const auto& value) {
                                   return value.name == "st0" && value.bytes.back() == std::byte{0x72};
                               }) != roundtrip.value().end(),
                           "FXSAVE register writes round-trip without changing API register widths");
        const auto before_invalid = image;
        const std::array bad_write{RegisterValue{"xmm0", {std::byte{1}}}};
        hexlab_test::check(!detail::write_x86_fxsave_registers(image, bad_write) && image == before_invalid,
                           "invalid FP register writes fail atomically");
        hexlab_test::check(!detail::x86_fxsave_register_values(std::span<const std::byte>(image).first(511)),
                           "truncated FP state is rejected");
    }
    {
        hexlab_test::check(detail::x86_xcr0_enables_avx((1ull << 1) | (1ull << 2)) &&
                               detail::x86_xcr0_enables_avx((1ull << 0) | (1ull << 1) | (1ull << 2)) &&
                               !detail::x86_xcr0_enables_avx(1ull << 2) &&
                               !detail::x86_xcr0_enables_avx(1ull << 1),
                           "AVX capability requires both SSE and AVX state enabled in XCR0");
        constexpr std::size_t ymm_upper_offset = 576;
        std::vector<std::byte> image(ymm_upper_offset + 16 * 16);
        const detail::X86XstateLayout layout{ymm_upper_offset, 16 * 16, 1ull << 2};
        image[ymm_upper_offset + 15 * 16] = std::byte{0xa5};
        detail::x86_set_xstate_bv(image, detail::x86_avx_xstate_bit);
        auto decoded = detail::x86_xstate_ymm_upper_register_values(image, layout);
        hexlab_test::check(decoded && decoded.value().size() == 16 &&
                               decoded.value()[15].name == "ymm15h" &&
                               decoded.value()[15].bytes.size() == 16 &&
                               decoded.value()[15].bytes.front() == std::byte{0xa5},
                           "XSAVE YMM upper register decoding uses CPUID-provided component offsets");
        const std::array write{RegisterValue{"ymm15h", std::vector<std::byte>(16, std::byte{0x39})}};
        auto written = detail::write_x86_xstate_ymm_upper_registers(image, layout, write);
        decoded = detail::x86_xstate_ymm_upper_register_values(image, layout);
        hexlab_test::check(written && decoded && decoded.value()[15].bytes.front() == std::byte{0x39} &&
                               (detail::x86_xstate_bv(image) & (1ull << 2)) != 0,
                           "XSAVE YMM upper register writes set AVX state and round-trip");
        const auto before_invalid = image;
        const std::array invalid{RegisterValue{"ymm0h", {std::byte{0x1}}}};
        hexlab_test::check(!detail::write_x86_xstate_ymm_upper_registers(image, layout, invalid) && image == before_invalid,
                           "invalid XSAVE YMM writes fail without modifying state");
        auto init_image = image;
        std::fill(init_image.begin() + static_cast<std::ptrdiff_t>(ymm_upper_offset), init_image.end(), std::byte{0x7f});
        detail::x86_set_xstate_bv(init_image, 0);
        decoded = detail::x86_xstate_ymm_upper_register_values(init_image, layout);
        hexlab_test::check(decoded && decoded.value()[15].bytes.front() == std::byte{0},
                           "XSAVE YMM reads report architectural zero when AVX state is in init form");
        hexlab_test::check(!detail::x86_xstate_ymm_upper_register_values(
                               std::span<const std::byte>(image).first(600), layout),
                           "truncated XSAVE YMM component is rejected");
        auto compacted_image = image;
        const std::uint64_t compacted_marker = 1ull << 63;
        std::memcpy(compacted_image.data() + 520, &compacted_marker, sizeof(compacted_marker));
        hexlab_test::check(!detail::x86_xstate_ymm_upper_register_values(compacted_image, layout),
                           "compacted XSAVE images are rejected instead of misreading component offsets");
    }
    {
        detail::I386UserRegisters registers{};
        registers.eax = 0x12345678u;
        registers.eip = 0x87654321u;
        const auto values = detail::i386_register_values(registers);
        const auto eax = std::find_if(values.begin(), values.end(), [](const RegisterValue& value) {
            return value.name == "eax";
        });
        const auto eip = std::find_if(values.begin(), values.end(), [](const RegisterValue& value) {
            return value.name == "eip";
        });
        hexlab_test::check(values.size() == 17 && eax != values.end() &&
                               eax->bytes.size() == sizeof(std::uint32_t) &&
                               eip != values.end() && eip->bytes.size() == sizeof(std::uint32_t),
                           "i386 ptrace register mapping exposes the complete 32-bit register set");
        RegisterValue changed{"eip", {std::byte{0x04}, std::byte{0x03}, std::byte{0x02}, std::byte{0x01}}};
        hexlab_test::check(detail::set_i386_register(registers, changed) && registers.eip == 0x01020304u,
                           "i386 register mapping writes a 32-bit instruction pointer");
        changed.bytes.push_back(std::byte{0});
        hexlab_test::check(!detail::set_i386_register(registers, changed),
                           "i386 register mapping rejects a width-mismatched write");
        std::vector<int> order;
        const auto failed_gpr_transaction = detail::transact_i386_register_sets(
            true, true,
            [&] { order.push_back(1); return Status{std::monostate{}}; },
            [&] { order.push_back(2); return Status{Error{ErrorCode::io, "injected GPR write failure"}}; },
            [&] { order.push_back(3); return Status{std::monostate{}}; });
        hexlab_test::check(!failed_gpr_transaction && order == std::vector<int>{1, 2, 3} &&
                               failed_gpr_transaction.error().message.find("injected GPR write failure") != std::string::npos,
                           "failed i386 GPR writes restore the already-applied FP/SSE regset");
        const auto failed_fp_rollback = detail::transact_i386_register_sets(
            true, true,
            [] { return Status{Error{ErrorCode::io, "injected FP write failure"}}; },
            [] { return Status{std::monostate{}}; },
            [] { return Status{Error{ErrorCode::io, "injected FP rollback failure"}}; });
        hexlab_test::check(!failed_fp_rollback &&
                               failed_fp_rollback.error().message.find("rollback of i386 FP/SSE state failed") != std::string::npos,
                           "i386 FP/SSE rollback failures are returned in the write diagnostic");
    }
    {
        std::array<std::byte, detail::x86_fxsave_size> image{};
        image[8] = std::byte{0x34};
        image[12] = std::byte{0x23};
        image[160 + 7 * 16] = std::byte{0xa7};
        auto values = detail::x86_i386_fxsave_register_values(image);
        const auto find = [&](std::string_view name) {
            return std::find_if(values.value().begin(), values.value().end(), [&](const auto& reg) {
                return reg.name == name;
            });
        };
        const auto fip = find("fip"), fcs = find("fcs"), xmm7 = find("xmm7");
        hexlab_test::check(values && values.value().size() == 25 && fip != values.value().end() &&
                               fip->bytes.size() == 4 && fip->bytes.front() == std::byte{0x34} &&
                               fcs != values.value().end() && fcs->bytes.size() == 2 &&
                               xmm7 != values.value().end() && xmm7->bytes.size() == 16 &&
                               xmm7->bytes.front() == std::byte{0xa7} &&
                               !detail::x86_i386_fxsave_field("xmm8"),
                           "i386 FXSAVE mapping exposes 32-bit FPU pointers and only the eight ABI-visible XMM registers");
        const std::array writes{
            RegisterValue{"fip", std::vector<std::byte>(4, std::byte{0x4f})},
            RegisterValue{"xmm7", std::vector<std::byte>(16, std::byte{0x7f})}};
        const auto write_status = detail::write_x86_i386_fxsave_registers(image, writes);
        values = detail::x86_i386_fxsave_register_values(image);
        const auto updated_fip = std::find_if(values.value().begin(), values.value().end(), [](const auto& reg) {
            return reg.name == "fip";
        });
        const auto updated_xmm7 = std::find_if(values.value().begin(), values.value().end(), [](const auto& reg) {
            return reg.name == "xmm7";
        });
        hexlab_test::check(write_status && updated_fip->bytes.front() == std::byte{0x4f} &&
                               updated_xmm7->bytes.front() == std::byte{0x7f},
                           "i386 FPU/SSE register writes round-trip through the compat FXSAVE layout");
        const auto before_invalid = image;
        const std::array invalid{RegisterValue{"xmm8", std::vector<std::byte>(16)}};
        hexlab_test::check(!detail::write_x86_i386_fxsave_registers(image, invalid) && image == before_invalid,
                           "i386 FPU/SSE writes reject unavailable upper XMM registers without changing state");
        hexlab_test::check(!detail::x86_i386_fxsave_register_values(
                               std::span<const std::byte>(image).first(511)),
                           "truncated i386 FXSAVE state is rejected");
    }
    {
        std::array<std::byte, 20> header{};
        header[0] = std::byte{0x7f}; header[1] = std::byte{'E'};
        header[2] = std::byte{'L'}; header[3] = std::byte{'F'};
        header[4] = std::byte{2}; header[5] = std::byte{1}; header[6] = std::byte{1};
        header[18] = std::byte{62};
        hexlab_test::check(detail::elf_process_architecture(header) == Architecture::x86_64,
                           "Linux process architecture recognizes ELF64 x86-64 images");
        header[4] = std::byte{1}; header[18] = std::byte{3};
        hexlab_test::check(detail::elf_process_architecture(header) == Architecture::x86,
                           "Linux process architecture recognizes ELF32 x86 images");
        header[4] = std::byte{2}; header[18] = std::byte{8};
        hexlab_test::check(detail::elf_process_architecture(header) == Architecture::mips64,
                           "Linux process architecture recognizes ELF64 N64 MIPS little-endian images");
        header[5] = std::byte{2}; header[18] = std::byte{0}; header[19] = std::byte{8};
        hexlab_test::check(detail::elf_process_architecture(header) == Architecture::mips64,
                           "Linux process architecture recognizes ELF64 N64 MIPS big-endian images");
        header[4] = std::byte{1}; header[5] = std::byte{1}; header[19] = std::byte{0};
        header[18] = std::byte{62};
        hexlab_test::check(detail::elf_process_architecture(header) == Architecture::unknown,
                           "Linux process architecture rejects machine/class mismatches");
        header[4] = std::byte{2}; header[5] = std::byte{2}; header[18] = std::byte{0}; header[19] = std::byte{183};
        hexlab_test::check(detail::elf_process_architecture(header) == Architecture::unknown,
                           "Linux process architecture still rejects machine/class mismatches in big-endian ELF");
        hexlab_test::check(detail::elf_process_architecture(std::span<const std::byte>(header).first(19)) ==
                               Architecture::unknown,
                           "Linux process architecture rejects truncated ELF headers");
    }
    {
        auto backend = std::make_unique<FakeBackend>();
        auto* fake = backend.get();
        DebugSession session(std::move(backend));
        hexlab_test::check(!session.request_interrupt(), "interrupt is rejected before a target is running");
        const auto launched = session.launch(Target{"fake", {}, {}});
        hexlab_test::check(static_cast<bool>(launched), "interrupt test target launches");
        hexlab_test::check(static_cast<bool>(session.request_interrupt()) && fake->interrupt_calls == 1 &&
                           session.state() == SessionState::running,
                           "interrupt requests a stop without fabricating a stopped event");
        fake->next_event = DebugEvent{80, EventKind::exception, 42, 9, 0, "interrupted"};
        const auto stopped = session.wait_event(std::chrono::milliseconds(1));
        hexlab_test::check(stopped && session.state() == SessionState::stopped,
                           "interrupt completion arrives through the normal event stream");
        hexlab_test::check(!session.request_interrupt(), "interrupt is rejected while a stop event is pending");
    }
    {
        using namespace hexlab::debugger::detail;
        std::map<int, int> suspend_counts{{10, 0}, {20, 0}, {30, 0}};
        std::vector<int> suspended;
        int attempts = 0;
        const auto result = suspend_other_threads(std::vector<int>{10, 20, 30}, 20,
            [&](int thread) -> Status {
                if (++attempts == 2) return Error{ErrorCode::io, "injected suspend failure"};
                ++suspend_counts[thread];
                return std::monostate{};
            },
            [&](int thread) -> Status { --suspend_counts[thread]; return std::monostate{}; }, suspended);
        hexlab_test::check(!result && suspend_counts == std::map<int, int>{{10, 0}, {20, 0}, {30, 0}} && suspended.empty(),
                           "failed peer-thread suspension rolls back acquired suspension counts");
    }
    {
        using namespace hexlab::debugger::detail;
        std::map<int, int> suspend_counts{{10, 0}, {20, 0}, {30, 0}};
        std::vector<int> still_suspended;
        int attempts = 0;
        const auto result = suspend_other_threads(std::vector<int>{10, 20, 30}, 20,
            [&](int thread) -> Status {
                if (++attempts == 2) return Error{ErrorCode::io, "injected suspend failure"};
                ++suspend_counts[thread];
                return std::monostate{};
            },
            [](int) -> Status { return Error{ErrorCode::io, "injected rollback failure"}; }, still_suspended);
        hexlab_test::check(!result && still_suspended == std::vector<int>{10} &&
                           suspend_counts == std::map<int, int>{{10, 1}, {20, 0}, {30, 0}},
                           "failed suspend rollback retains the thread that still needs a resume");
    }
    {
        using namespace hexlab::debugger::detail;
        std::map<int, int> suspend_counts{{10, 1}, {30, 1}};
        std::vector<int> suspended{10, 30};
        int failures = 1;
        auto release = [&suspend_counts, &failures](int thread) -> Status {
            if (thread == 10 && failures-- > 0) return Error{ErrorCode::io, "injected resume failure"};
            --suspend_counts[thread];
            return std::monostate{};
        };
        const auto first = resume_suspended_threads(suspended, release);
        hexlab_test::check(!first && suspended == std::vector<int>{10} && suspend_counts == std::map<int, int>{{10, 1}, {30, 0}},
                           "failed peer-thread resume retains only the suspension needing retry");
        const auto retry = resume_suspended_threads(suspended, release);
        hexlab_test::check(retry && suspended.empty() && suspend_counts == std::map<int, int>{{10, 0}, {30, 0}},
                           "peer-thread resume retry clears the remaining suspension");
    }
    {
        const std::vector<int> threads{10, 20, 30};
        std::map<int, int> state{{10, 1}, {20, 1}, {30, 1}};
        std::vector<int> rollback_order;
        int attempts = 0;
        const auto updated = detail::transact_debug_registers(threads,
            [&](int thread) -> Status {
                if (++attempts == 2) return Error{ErrorCode::io, "injected context write failure"};
                state[thread] = 2;
                return std::monostate{};
            },
            [&](int thread) -> Status {
                rollback_order.push_back(thread);
                state[thread] = 1;
                return std::monostate{};
            });
        hexlab_test::check(!updated && updated.error().message == "injected context write failure",
                           "hardware register transaction propagates injected update failure");
        hexlab_test::check(state == std::map<int, int>{{10, 1}, {20, 1}, {30, 1}},
                           "hardware register transaction rolls back earlier thread updates");
        hexlab_test::check(rollback_order == std::vector<int>{10},
                           "hardware register rollback visits modified threads in reverse order");
    }
    {
        const std::vector<int> threads{1, 2};
        const auto updated = detail::transact_debug_registers(threads,
            [](int) -> Status { return std::monostate{}; },
            [](int) -> Status { return std::monostate{}; });
        hexlab_test::check(static_cast<bool>(updated), "hardware register transaction succeeds when all thread writes succeed");
    }
    {
        using namespace hexlab::debugger::detail;
        DebugRegisters regs;
        hexlab_test::check(encode_hardware_breakpoints({{0x401000, BreakpointKind::execute, 1}}, 8, regs) &&
                           regs.address[0] == 0x401000 && (regs.dr7 & 1) != 0 && ((regs.dr7 >> 16) & 0xf) == 0,
                           "execute hardware breakpoint uses local enable and execute/one-byte encoding");
        hexlab_test::check(encode_hardware_breakpoints({{0x1000, BreakpointKind::write, 4},
                                                        {0x2000, BreakpointKind::access, 8}}, 8, regs) &&
                           ((regs.dr7 >> 16) & 0xf) == 0xd && ((regs.dr7 >> 20) & 0xf) == 0xb,
                           "data breakpoints encode write and access length fields in independent slots");
        hexlab_test::check(!encode_hardware_breakpoints({{0x1001, BreakpointKind::write, 4}}, 8, regs),
                           "unaligned data breakpoint is rejected");
        hexlab_test::check(!encode_hardware_breakpoints({{0x1000, BreakpointKind::read, 1}}, 4, regs),
                           "x86 rejects read-only hardware breakpoints because DR7 only supports write or access modes");
        hexlab_test::check(!encode_hardware_breakpoints({{0x1000, BreakpointKind::write, 8}}, 4, regs),
                           "x86 rejects unsupported eight-byte hardware breakpoint lengths");
        hexlab_test::check(!encode_hardware_breakpoints({{0x1000, BreakpointKind::execute, 1},
            {0x1001, BreakpointKind::execute, 1}, {0x1002, BreakpointKind::execute, 1},
            {0x1003, BreakpointKind::execute, 1}, {0x1004, BreakpointKind::execute, 1}}, 8, regs),
            "hardware breakpoints reject a fifth slot");
        const auto hits = hardware_breakpoint_hits({101, 102, 103, 104}, 0b1010);
        hexlab_test::check(hits == std::vector<BreakpointId>{102, 104},
            "DR6 B1 and B3 status bits map to the corresponding owned breakpoint identifiers");
        hexlab_test::check(hardware_breakpoint_hits({101}, 0b0010).empty(),
            "DR6 status for an unowned slot is not reported as a debugger breakpoint hit");
    }
    {
        hexlab::debugger::detail::BreakpointStepState protocol;
        hexlab_test::check(!protocol.begin(0x401000, 0x401000, 9),
                           "software breakpoint stepping requires Windows' post-INT3 instruction pointer");
        hexlab_test::check(protocol.begin(0x401000, 0x401001, 9) && protocol.active(),
                           "owned breakpoint is marked displaced for its event thread");
        hexlab_test::check(!protocol.begin(0x402000, 0x402001, 9),
                           "only one displaced software breakpoint can be pending");
        hexlab_test::check(!protocol.complete(10) && protocol.active(),
                           "an unrelated thread event does not rearm or consume the displaced breakpoint");
        const auto rearm = protocol.complete(9);
        hexlab_test::check(rearm && *rearm == 0x401000 && !protocol.active(),
                           "the matching thread's event returns the address to rearm and clears pending state");
        protocol.retain(0x401000, 9);
        hexlab_test::check(protocol.complete(9) == std::optional<std::uintptr_t>{0x401000},
                           "failed byte rearm retains state for a retry on the same thread");
        protocol.begin(0x403000, 0x403001, 11);
        protocol.clear();
        hexlab_test::check(!protocol.active() && !protocol.complete(11),
                           "backend teardown clears displaced-step state");
    }
    auto backend = std::make_unique<FakeBackend>();
    auto* fake = backend.get();
    DebugSession session(std::move(backend));
    auto listed_processes = session.processes();
    hexlab_test::check(listed_processes && listed_processes.value().size() == 1 &&
                       listed_processes.value()[0].id == 17 && listed_processes.value()[0].name == "fake-process",
                       "process discovery delegates to backend while session is idle");
    fake->process_list.resize(max_inspection_processes + 1);
    auto excessive_processes = session.processes();
    hexlab_test::check(!excessive_processes && excessive_processes.error().code == ErrorCode::resource_limit,
                       "session rejects process enumeration results above the inspection cap");
    fake->process_list.resize(1);
    {
        DebugSession routed(make_backend_router(std::make_unique<FakeBackend>()));
        const auto routed_processes = routed.processes();
        hexlab_test::check(routed_processes && routed_processes.value().size() == 1 &&
                               routed_processes.value().front().id == 17,
                           "backend router preserves native process discovery");
    }
    hexlab_test::check(session.state() == SessionState::idle, "new session is idle");
    hexlab_test::check(!session.detach(), "cannot detach an idle session");
    auto attached = session.attach(1234);
    hexlab_test::check(attached && session.state() == SessionState::running, "attach enters running state");
    hexlab_test::check(attached && session.process()->id == 1234, "attached process is exposed");
    fake->thread_list.resize(max_inspection_threads + 1);
    const auto excessive_threads = session.threads();
    hexlab_test::check(!excessive_threads && excessive_threads.error().code == ErrorCode::resource_limit,
                       "session rejects thread snapshots above the inspection cap");
    fake->thread_list.resize(1);
    const auto reads_before_reject = fake->read_calls;
    hexlab_test::check(!session.read_memory(0, max_inspection_read + 1) && fake->read_calls == reads_before_reject,
                       "memory inspection rejects requests above 1 MiB before calling the backend");
    hexlab_test::check(!session.read_memory(UINT64_MAX - 3, 8) && fake->read_calls == reads_before_reject,
                       "memory inspection rejects address wrap before calling the backend");
    auto modules = session.modules();
    hexlab_test::check(modules && modules.value().size() == 1 && modules.value()[0].base == 0x1000,
                       "module inspection delegates bounded module records");

    fake->next_event = DebugEvent{77, EventKind::breakpoint, 1234, 9, 0x401000, "int3"};
    auto event = session.wait_event(std::chrono::milliseconds(1));
    hexlab_test::check(event && session.state() == SessionState::stopped, "breakpoint event stops session");
    hexlab_test::check(!session.continue_execution(76, ContinueStatus::handled), "wrong event sequence is rejected");
    hexlab_test::check(static_cast<bool>(session.continue_execution(77, ContinueStatus::handled)), "matching event resumes session");
    hexlab_test::check(!session.continue_execution(77, ContinueStatus::handled), "event cannot be continued twice");
    hexlab_test::check(session.state() == SessionState::running && fake->continued == std::vector<std::uint64_t>{77}, "continue records one resume");

    fake->next_event = DebugEvent{78, EventKind::breakpoint, 1234, 9, 0x401001, "second breakpoint"};
    event = session.wait_event(std::chrono::milliseconds(1));
    hexlab_test::check(event && session.state() == SessionState::stopped, "second event stops before stepping");
    hexlab_test::check(!session.single_step_execution(77), "single-step rejects a stale event sequence");
    hexlab_test::check(static_cast<bool>(session.single_step_execution(78, ContinueStatus::not_handled)),
                       "single-step accepts the current event sequence");
    hexlab_test::check(session.state() == SessionState::running &&
                           fake->stepped == std::vector<std::pair<std::uint64_t, ContinueStatus>>{{78, ContinueStatus::not_handled}},
                       "single-step resumes once with the requested exception disposition");
    fake->next_event = DebugEvent{79, EventKind::single_step, 1234, 9, 0x401002, "single step"};
    event = session.wait_event(std::chrono::milliseconds(1));
    hexlab_test::check(event && event.value().kind == EventKind::single_step && session.state() == SessionState::stopped,
                       "single-step event returns the session to stopped state");
    hexlab_test::check(static_cast<bool>(session.continue_execution(79, ContinueStatus::handled)),
                       "single-step trap event can be explicitly acknowledged");

    auto bytes = session.read_memory(0x1000, 2);
    hexlab_test::check(bytes && bytes.value().size() == 2, "memory read delegates to backend");
    const std::byte payload[] = {std::byte{0xaa}, std::byte{0xbb}};
    hexlab_test::check(static_cast<bool>(session.write_memory(0x1000, payload)), "memory write delegates to backend");
    bytes = session.read_memory(0x1000, 2);
    hexlab_test::check(bytes && bytes.value()[0] == payload[0] && bytes.value()[1] == payload[1], "written bytes are observable");
    auto threads = session.threads();
    hexlab_test::check(threads && threads.value().size() == 1 && threads.value()[0].id == 9, "thread list delegates to backend");
    auto registers = session.read_registers(9);
    hexlab_test::check(registers && registers.value()[0].name == "ip", "register state delegates to backend");
    auto bp = session.add_breakpoint(0x401000);
    hexlab_test::check(bp && bp.value().address == 0x401000, "breakpoint creation delegates to backend");
    hexlab_test::check(session.breakpoints().size() == 1 && session.breakpoints()[0].id == bp.value().id,
                       "session exposes its active breakpoint inventory");
    fake->fail_toggle_breakpoint = true;
    hexlab_test::check(!session.set_breakpoint_enabled(bp.value().id, false) && session.breakpoints()[0].enabled,
                       "failed breakpoint toggle preserves the session inventory state");
    fake->fail_toggle_breakpoint = false;
    hexlab_test::check(static_cast<bool>(session.set_breakpoint_enabled(bp.value().id, false)) &&
                       !session.breakpoints()[0].enabled && !fake->backend_breakpoint_enabled,
                       "software breakpoint can be disabled without losing its session identity");
    hexlab_test::check(static_cast<bool>(session.set_breakpoint_enabled(bp.value().id, true)) &&
                       session.breakpoints()[0].enabled && fake->backend_breakpoint_enabled,
                       "software breakpoint can be re-enabled with its original identifier");
    const auto toggle_calls = fake->toggle_breakpoint_calls;
    hexlab_test::check(!session.set_breakpoint_enabled(999, false) &&
                       fake->toggle_breakpoint_calls == toggle_calls,
                       "toggling a breakpoint not owned by the session is rejected before backend dispatch");
    hexlab_test::check(!session.remove_breakpoint(999) && fake->remove_breakpoint_calls == 0,
                       "removing a breakpoint not owned by the session is rejected before backend dispatch");
    fake->fail_remove_breakpoint = true;
    hexlab_test::check(!session.remove_breakpoint(bp.value().id) && session.breakpoints().size() == 1,
                       "failed backend removal preserves the active breakpoint inventory");
    fake->fail_remove_breakpoint = false;
    hexlab_test::check(static_cast<bool>(session.remove_breakpoint(bp.value().id)) && session.breakpoints().empty(),
                       "successful breakpoint removal updates the session inventory");
    bp = session.add_breakpoint(0x401004);
    hexlab_test::check(static_cast<bool>(bp), "breakpoint can be installed again after removal");

    fake->next_event = DebugEvent{78, EventKind::process_exited, 1234, 0, 0, "exit"};
    event = session.wait_event(std::chrono::milliseconds(1));
    hexlab_test::check(event && session.state() == SessionState::exited, "process exit transitions session");
    hexlab_test::check(static_cast<bool>(session.continue_execution(78, ContinueStatus::handled)), "exit event is acknowledged");
    hexlab_test::check(session.state() == SessionState::exited, "acknowledging exit preserves terminal state");
    hexlab_test::check(session.breakpoints().empty(), "acknowledging process exit clears stale breakpoint records");
    hexlab_test::check(static_cast<bool>(session.detach()) && fake->detached && session.state() == SessionState::detached, "detach closes session");
}

#if defined(_WIN32)
void run_native_process_discovery_test() {
    DebugSession session(make_native_backend());
    auto processes = session.processes();
    const bool found_self = processes && std::any_of(processes.value().begin(), processes.value().end(),
        [](const ProcessInfo& process) { return process.id == GetCurrentProcessId() && !process.name.empty(); });
    hexlab_test::check(processes && processes.value().size() <= max_inspection_processes,
                       "Win32 process enumeration stays within its documented cap");
    hexlab_test::check(found_self,
                       "Win32 process enumeration includes current process with UTF-8 executable name");
    if (found_self) {
        const auto self = std::find_if(processes.value().begin(), processes.value().end(),
            [](const ProcessInfo& process) { return process.id == GetCurrentProcessId(); });
#if defined(_M_ARM64)
        hexlab_test::check(self->architecture == Architecture::arm64,
                           "Win32 IsWow64Process2 identifies a native ARM64 process");
#elif defined(_M_X64) || defined(_M_AMD64)
        hexlab_test::check(self->architecture == Architecture::x86_64,
                           "Win32 IsWow64Process2 identifies a native x64 process");
#elif defined(_M_IX86) || defined(_M_X86)
        hexlab_test::check(self->architecture == Architecture::x86,
                           "Win32 process discovery identifies an x86 process");
#endif
    }
}

void run_native_launch_lifecycle_test(const std::string &executable) {
    DWORD before = 0;
    hexlab_test::check(GetProcessHandleCount(GetCurrentProcess(), &before) != FALSE,
                       "Win32 can count handles before native lifecycle test");
    DebugSession session(make_native_backend());
    bool completed = true;
    bool observed_registers = false;
    bool observed_memory_regions = false;
    DWORD after_first_cycle = 0;
    for (int attempt = 0; attempt < 8; ++attempt) {
        Target target{executable, {"--debuggee-lifecycle-fixture"}, {}};
        auto launched = session.launch(target);
        if (!launched) { std::fprintf(stderr, "native lifecycle launch failed: %s\n", launched.error().message.c_str()); completed = false; break; }
        bool exited = false;
        for (int event_index = 0; event_index < 100 && !exited; ++event_index) {
            auto event = session.wait_event(std::chrono::milliseconds(100));
            if (!event) {
                if (event.error().code == ErrorCode::busy) continue;
                std::fprintf(stderr, "native lifecycle wait failed: %s\n", event.error().message.c_str());
                completed = false; break;
            }
            if (!observed_registers && event.value().thread != 0) {
                auto registers = session.read_registers(event.value().thread);
                observed_registers = registers && !registers.value().empty();
                if (launched.value().architecture == Architecture::arm64) {
                    const bool has_arm64_context = registers &&
                        std::any_of(registers.value().begin(), registers.value().end(),
                            [](const RegisterValue& reg) { return reg.name == "x0" && reg.bytes.size() == 8; }) &&
                        std::any_of(registers.value().begin(), registers.value().end(),
                            [](const RegisterValue& reg) { return reg.name == "pc" && reg.bytes.size() == 8; }) &&
                        std::any_of(registers.value().begin(), registers.value().end(),
                            [](const RegisterValue& reg) { return reg.name == "sp" && reg.bytes.size() == 8; });
                    hexlab_test::check(has_arm64_context,
                        "Win32 ARM64 thread context exposes x0, pc, and sp as 64-bit registers");
                }
            }
            if (!observed_memory_regions) {
                auto regions = session.memory_regions();
                const bool valid = regions && !regions.value().empty() &&
                    regions.value().size() <= max_inspection_memory_regions &&
                    std::all_of(regions.value().begin(), regions.value().end(), [](const MemoryRegion& region) {
                        return region.length != 0 && region.start <= UINT64_MAX - region.length;
                    });
                hexlab_test::check(valid, "Win32 VirtualQueryEx exposes bounded, valid process memory regions while stopped");
                observed_memory_regions = valid;
            }
            exited = event.value().kind == EventKind::process_exited;
            auto continued = session.continue_execution(event.value().sequence, ContinueStatus::handled);
            if (!continued) { completed = false; break; }
        }
        if (!completed || !exited) { completed = false; break; }
        auto detached = session.detach();
        if (!detached || session.state() != SessionState::detached) { completed = false; break; }
        if (attempt == 0) (void)GetProcessHandleCount(GetCurrentProcess(), &after_first_cycle);
    }
    Sleep(250);
    DWORD after = 0;
    const bool counted = GetProcessHandleCount(GetCurrentProcess(), &after) != FALSE;
    hexlab_test::check(completed, "Win32 launch receives and acknowledges the process event lifecycle through exit");
    hexlab_test::check(observed_registers, "Win32 launched process exposes a stopped thread register context");
    hexlab_test::check(observed_memory_regions, "Win32 native lifecycle exposes process memory regions");
    hexlab_test::check(counted && after_first_cycle != 0 && after <= after_first_cycle + 1,
                       "Win32 launched process event processing closes per-event process, thread, and image handles");
}

void run_native_interrupt_test(const std::string& executable) {
    DebugSession session(make_native_backend());
    const auto launched = session.launch(Target{executable, {"--debuggee-interrupt-fixture"}, {}});
    hexlab_test::check(static_cast<bool>(launched), "Win32 starts an interrupt fixture");
    if (!launched) return;
    const auto initial = session.wait_event(std::chrono::seconds(5));
    const auto continued = initial ? session.continue_execution(initial.value().sequence, ContinueStatus::handled)
        : Status{Error{ErrorCode::busy, "initial event missing"}};
    const auto requested = continued ? session.request_interrupt()
        : Status{Error{ErrorCode::busy, "initial event was not continued"}};
    bool interrupted = false;
    for (int attempt = 0; requested && attempt < 20 && !interrupted; ++attempt) {
        const auto event = session.wait_event(std::chrono::seconds(2));
        if (!event) { if (event.error().code == ErrorCode::busy) continue; break; }
        interrupted = event.value().kind == EventKind::breakpoint;
        if (!interrupted) (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
    }
    hexlab_test::check(requested && interrupted,
        "Win32 DebugBreakProcess produces a normal breakpoint event after an asynchronous request");
    const auto detached = session.detach();
    HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, static_cast<DWORD>(launched.value().id));
    if (process) { (void)TerminateProcess(process, 0); CloseHandle(process); }
    hexlab_test::check(static_cast<bool>(detached), "Win32 releases the interrupted target on detach");
}

void run_native_launch_detach_test(const std::string& executable) {
    DebugSession session(make_native_backend());
    const auto event_name = "Local\\HexLabDebuggerDetach-" + std::to_string(GetCurrentProcessId());
    HANDLE resume_fixture = CreateEventA(nullptr, TRUE, FALSE, event_name.c_str());
    hexlab_test::check(resume_fixture != nullptr, "Win32 creates a release event for the detach fixture");
    if (!resume_fixture) return;
    const auto launched = session.launch(Target{executable, {"--debuggee-detach-fixture", event_name}, {}});
    hexlab_test::check(static_cast<bool>(launched), "Win32 launches a fixture for active detach");
    if (!launched) { CloseHandle(resume_fixture); return; }

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE,
                                FALSE, static_cast<DWORD>(launched.value().id));
    hexlab_test::check(process != nullptr, "Win32 can observe the launched target across detach");
    bool stopped = false;
    for (int event_index = 0; event_index < 100 && !stopped; ++event_index) {
        const auto event = session.wait_event(std::chrono::milliseconds(100));
        if (!event) {
            if (event.error().code == ErrorCode::busy) continue;
            break;
        }
        stopped = event.value().kind == EventKind::breakpoint;
        if (!stopped) (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
    }
    hexlab_test::check(stopped, "Win32 launched target reaches a stopped event before active detach");

    bool installed = false;
    std::byte original{};
    std::uint64_t breakpoint_address = 0;
    if (stopped) {
        const auto modules = session.modules();
        const auto regions = session.memory_regions();
        if (modules && !modules.value().empty() && regions) {
            const auto& module = modules.value().front();
            const auto writable = std::find_if(regions.value().begin(), regions.value().end(), [&](const auto& region) {
                return region.writable && region.length && region.start >= module.base &&
                       region.start < module.base + module.size;
            });
            if (writable != regions.value().end()) breakpoint_address = writable->start;
            const auto byte = session.read_memory(breakpoint_address, 1);
            if (breakpoint_address && byte && byte.value().size() == 1) {
                original = byte.value().front();
                const auto software = session.add_breakpoint(breakpoint_address, BreakpointKind::software);
                const auto hardware = session.add_breakpoint(breakpoint_address, BreakpointKind::execute, 1);
                installed = software && hardware;
            }
        }
    }
    hexlab_test::check(installed, "Win32 launched target owns software and hardware state before detach");

    const std::byte edited = original == std::byte{0x5a} ? std::byte{0x5b} : std::byte{0x5a};
    const auto write_under_breakpoint = stopped && breakpoint_address
        ? session.write_memory(breakpoint_address, std::span<const std::byte>(&edited, 1))
        : Status{Error{ErrorCode::invalid_argument, "breakpoint fixture did not stop"}};
    const auto visible_after_edit = write_under_breakpoint ? session.read_memory(breakpoint_address, 1)
                                                            : Result<std::vector<std::byte>>{write_under_breakpoint.error()};
    const bool trap_preserved = visible_after_edit && visible_after_edit.value().size() == 1 &&
                                visible_after_edit.value().front() == std::byte{0xcc};
    hexlab_test::check(static_cast<bool>(write_under_breakpoint) && trap_preserved,
                       "Win32 memory writes under an owned software breakpoint keep INT3 installed");

    const auto detached = session.detach();
    if (!detached) std::fprintf(stderr, "native launched detach failed: %s\n", detached.error().message.c_str());
    hexlab_test::check(static_cast<bool>(detached) && session.state() == SessionState::detached,
                       "Win32 active detach ends debugging for a launched target");
    hexlab_test::check(session.breakpoints().empty(), "Win32 launched detach clears session breakpoint records");

    bool byte_restored = false;
    if (detached && process) {
        std::byte actual{}; SIZE_T read = 0;
        byte_restored = ReadProcessMemory(process, reinterpret_cast<const void*>(breakpoint_address),
                                         &actual, 1, &read) != FALSE && read == 1 && actual == edited;
    }
    hexlab_test::check(byte_restored, "Win32 launched detach restores debugger-owned software breakpoint bytes");
    const bool survived = process && WaitForSingleObject(process, 100) == WAIT_TIMEOUT;
    hexlab_test::check(survived, "Win32 launched process remains alive after debugger detach");
    SetEvent(resume_fixture);
    const bool exited = process && WaitForSingleObject(process, 5000) == WAIT_OBJECT_0;
    hexlab_test::check(exited, "Win32 detached launched process continues to normal exit");
    if (process) {
        if (!exited) TerminateProcess(process, 1);
        CloseHandle(process);
    }
    CloseHandle(resume_fixture);
}

void run_native_attach_lifecycle_test(const std::string &executable) {
    std::string command = "\"" + executable + "\" --debuggee-attach-fixture";
    STARTUPINFOA startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION created{};
    const bool created_ok = CreateProcessA(nullptr, command.data(), nullptr, nullptr, FALSE,
                                           CREATE_NO_WINDOW, nullptr, nullptr, &startup, &created) != FALSE;
    hexlab_test::check(created_ok, "Win32 creates an unattached fixture for native attach test");
    if (!created_ok) return;
    DebugSession session(make_native_backend());
    const auto attached = session.attach(created.dwProcessId);
    hexlab_test::check(static_cast<bool>(attached), "Win32 backend attaches to an existing process");
    bool got_stopped_thread = false;
    if (attached) {
        bool reached_breakpoint = false;
        for (int event_index = 0; event_index < 100 && !reached_breakpoint; ++event_index) {
            auto event = session.wait_event(std::chrono::milliseconds(100));
            if (!event) {
                if (event.error().code == ErrorCode::busy) continue;
                break;
            }
            if (!got_stopped_thread && event.value().thread != 0) {
                const auto registers = session.read_registers(event.value().thread);
                got_stopped_thread = registers && !registers.value().empty();
            }
            reached_breakpoint = event.value().kind == EventKind::breakpoint;
            if (!reached_breakpoint)
                (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
        }
        hexlab_test::check(got_stopped_thread, "Win32 attached process exposes register context while stopped");
        hexlab_test::check(reached_breakpoint, "Win32 attach receives the initial breakpoint event");
        const auto detached = session.detach();
        if (!detached) std::fprintf(stderr, "native attach detach failed: %s\n", detached.error().message.c_str());
        hexlab_test::check(static_cast<bool>(detached) && session.state() == SessionState::detached,
                           "Win32 backend detaches and resumes an attached process with a pending event");
        if (detached) {
            const auto reattached = session.attach(created.dwProcessId);
            hexlab_test::check(static_cast<bool>(reattached), "Win32 session can reattach to the resumed process");
            bool exit_event = false;
            if (reattached) {
                for (int event_index = 0; event_index < 100 && !exit_event; ++event_index) {
                    auto event = session.wait_event(std::chrono::milliseconds(100));
                    if (!event) {
                        if (event.error().code == ErrorCode::busy) continue;
                        break;
                    }
                    exit_event = event.value().kind == EventKind::process_exited;
                    if (!exit_event)
                        (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
                }
            }
            hexlab_test::check(exit_event, "reattached target produces a process-exit event");
            if (exit_event) {
                const auto exit_detached = session.detach();
                hexlab_test::check(static_cast<bool>(exit_detached) && session.state() == SessionState::detached,
                                   "Win32 detach acknowledges a pending process-exit event without a stale stop call");
            }
        }
    }
    const auto exited = WaitForSingleObject(created.hProcess, 7000) == WAIT_OBJECT_0;
    hexlab_test::check(exited, "Win32 attached fixture continues after detach and exits");
    CloseHandle(created.hThread);
    CloseHandle(created.hProcess);
}

void run_native_single_step_test(const std::string &executable) {
    DebugSession session(make_native_backend());
    Target target{executable, {"--debuggee"}, {}};
    auto launched = session.launch(target);
    hexlab_test::check(static_cast<bool>(launched), "Win32 backend launches native single-step fixture");
    if (!launched) return;
    if (launched.value().architecture == Architecture::arm64) {
        auto event = session.wait_event(std::chrono::seconds(5));
        bool breakpoint_ops = false;
        if (event) {
            const auto registers = session.read_registers(event.value().thread);
            if (registers) {
                const auto pc = std::find_if(registers.value().begin(), registers.value().end(),
                    [](const RegisterValue& reg) { return reg.name == "pc" && reg.bytes.size() == 8; });
                if (pc != registers.value().end()) {
                    std::uint64_t address = 0;
                    std::memcpy(&address, pc->bytes.data(), sizeof(address));
                    const auto original = session.read_memory(address, 4);
                    const auto bp = session.add_breakpoint(address, BreakpointKind::software);
                    const auto disabled = bp ? session.set_breakpoint_enabled(bp.value().id, false)
                                             : Status{bp.error()};
                    const auto restored = session.read_memory(address, 4);
                    const auto enabled = bp ? session.set_breakpoint_enabled(bp.value().id, true)
                                            : Status{bp.error()};
                    const auto removed = bp ? session.remove_breakpoint(bp.value().id)
                                            : Status{bp.error()};
                    breakpoint_ops = original && bp && bp.value().size == 4 && disabled && restored &&
                        restored.value() == original.value() && enabled && removed;
                }
            }
        }
        hexlab_test::check(breakpoint_ops,
                           "Win32 ARM64 software breakpoint installs BRK and restores its four-byte instruction");
        const auto step = event ? session.single_step_execution(event.value().sequence)
                                : Status{Error{ErrorCode::busy, "initial event missing"}};
        hexlab_test::check(!step && step.error().code == ErrorCode::unsupported,
                           "Win32 ARM64 explicitly reports single-step as unsupported");
        if (event) (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
        for (int i = 0; i < 100; ++i) {
            auto next = session.wait_event(std::chrono::milliseconds(100));
            if (!next) continue;
            const bool exited = next.value().kind == EventKind::process_exited;
            (void)session.continue_execution(next.value().sequence, ContinueStatus::handled);
            if (exited) break;
        }
        (void)session.detach();
        return;
    }

    bool requested_step = false;
    bool observed_step = false;
    bool exited = false;
    for (int i = 0; i < 100 && !requested_step; ++i) {
        auto event = session.wait_event(std::chrono::milliseconds(100));
        if (!event) {
            if (event.error().code == ErrorCode::busy) continue;
            hexlab_test::check(false, "Win32 debugger receives events before initial breakpoint");
            break;
        }
        if (event.value().kind == EventKind::breakpoint) {
            auto registers = session.read_registers(event.value().thread);
            const auto ip = registers ? std::find_if(registers.value().begin(), registers.value().end(),
                [](const RegisterValue& reg) { return (reg.name == "rip" || reg.name == "eip") && reg.bytes.size() <= 8; })
                : std::vector<RegisterValue>::iterator{};
            bool software_toggle_ok = false;
            if (registers && ip != registers.value().end()) {
                std::uint64_t address = 0;
                std::memcpy(&address, ip->bytes.data(), ip->bytes.size());
                const auto original = session.read_memory(address, 1);
                const auto software = session.add_breakpoint(address, BreakpointKind::software);
                const std::byte trap{0xcc};
                const auto disabled = software ? session.set_breakpoint_enabled(software.value().id, false)
                                               : Status{software.error()};
                const auto restored = session.read_memory(address, 1);
                const auto enabled = software ? session.set_breakpoint_enabled(software.value().id, true)
                                              : Status{software.error()};
                const auto installed = session.read_memory(address, 1);
                const auto removed = software ? session.remove_breakpoint(software.value().id)
                                              : Status{software.error()};
                software_toggle_ok = original && software && disabled && restored &&
                    restored.value()[0] == original.value()[0] && enabled && installed &&
                    installed.value()[0] == trap && removed;
            }
            hexlab_test::check(software_toggle_ok,
                "Win32 software breakpoints toggle in place and restore their original byte");
            auto step = session.single_step_execution(event.value().sequence);
            requested_step = static_cast<bool>(step);
            hexlab_test::check(requested_step, "Win32 backend sets trap flag and resumes one instruction");
            if (!step) {
                (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
            }
        } else {
            (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
            exited = event.value().kind == EventKind::process_exited;
        }
    }

    for (int i = 0; i < 120 && !exited; ++i) {
        auto event = session.wait_event(std::chrono::milliseconds(100));
        if (!event) {
            if (event.error().code == ErrorCode::busy) continue;
            hexlab_test::check(false, "Win32 single-step fixture continues producing events");
            break;
        }
        if (event.value().kind == EventKind::single_step) observed_step = true;
        exited = event.value().kind == EventKind::process_exited;
        (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
    }
    hexlab_test::check(requested_step && observed_step, "Win32 single-step produces a hardware single-step event");
    hexlab_test::check(exited, "Win32 single-step fixture exits after events are continued");
    if (session.state() == SessionState::exited)
        (void)session.detach();
}

void run_native_owned_breakpoint_step_test(const std::string& executable) {
    DebugSession session(make_native_backend());
    const auto launched = session.launch(Target{executable, {"--debuggee-breakpoint-fixture"}, {}});
    hexlab_test::check(static_cast<bool>(launched), "Win32 launches owned-breakpoint stepping fixture");
    if (!launched || (launched.value().architecture != Architecture::x86 &&
                      launched.value().architecture != Architecture::x86_64)) return;

    std::uint64_t breakpoint_address = 0;
    BreakpointId breakpoint_id = 0;
    bool hit = false;
    bool step_succeeded = false;
    bool trap_rearmed = false;
    bool exited = false;
    for (int i = 0; i < 100 && !exited; ++i) {
        auto event = session.wait_event(std::chrono::milliseconds(100));
        if (!event) { if (event.error().code == ErrorCode::busy) continue; break; }
        if (!breakpoint_id && event.value().kind == EventKind::breakpoint) {
            const auto modules = session.modules();
            const auto image = modules && !modules.value().empty() ? modules.value().front() : ModuleInfo{};
            const auto image_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
            const auto function = reinterpret_cast<std::uintptr_t>(&debugger_software_breakpoint_target);
            const bool valid_image = image_base && function >= image_base && function - image_base < image.size;
            if (valid_image) {
                breakpoint_address = image.base + (function - image_base);
                auto breakpoint = session.add_breakpoint(breakpoint_address, BreakpointKind::software);
                if (breakpoint) breakpoint_id = breakpoint.value().id;
            }
        } else if (breakpoint_id && event.value().kind == EventKind::breakpoint &&
                   event.value().address == breakpoint_address) {
            hit = event.value().first_chance == std::optional<bool>{true};
            const auto stepped = session.single_step_execution(event.value().sequence);
            step_succeeded = static_cast<bool>(stepped);
            if (stepped) {
                auto step_event = session.wait_event(std::chrono::seconds(5));
                if (step_event && step_event.value().kind == EventKind::single_step) {
                    const auto byte = session.read_memory(breakpoint_address, 1);
                    trap_rearmed = byte && byte.value().size() == 1 && byte.value()[0] == std::byte{0xcc};
                    (void)session.remove_breakpoint(breakpoint_id);
                    (void)session.continue_execution(step_event.value().sequence, ContinueStatus::handled);
                }
                continue;
            }
        }
        exited = event.value().kind == EventKind::process_exited;
        (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
    }
    hexlab_test::check(breakpoint_id != 0, "Win32 installs a software breakpoint at a child code address");
    hexlab_test::check(hit, "Win32 reports the owned software breakpoint as a first-chance exception");
    hexlab_test::check(step_succeeded && trap_rearmed,
                       "Win32 single-steps the displaced instruction and rearms its software breakpoint");
    hexlab_test::check(exited, "Win32 owned-breakpoint fixture exits after its step is acknowledged");
}

void run_native_exception_delivery_test(const std::string& executable) {
    DebugSession session(make_native_backend());
    const auto launched = session.launch(Target{executable, {"--debuggee-exception-delivery-fixture"}, {}});
    hexlab_test::check(static_cast<bool>(launched), "Win32 launches exception-delivery fixture");
    if (!launched) return;

    bool forwarded = false;
    bool exited = false;
    bool expected_exit = false;
    for (int i = 0; i < 100 && !exited; ++i) {
        auto event = session.wait_event(std::chrono::milliseconds(100));
        if (!event) { if (event.error().code == ErrorCode::busy) continue; break; }
        if (event.value().kind == EventKind::exception &&
            event.value().code == debugger_fixture_exception) {
            const bool first_chance = event.value().first_chance == std::optional<bool>{true};
            const auto disposition = session.continue_execution(event.value().sequence, ContinueStatus::not_handled);
            forwarded = first_chance && static_cast<bool>(disposition);
            continue;
        }
        exited = event.value().kind == EventKind::process_exited;
        expected_exit = exited && event.value().code == 0x42;
        (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
    }
    hexlab_test::check(forwarded,
                       "Win32 exposes first-chance metadata and forwards an unhandled exception to the child VEH");
    hexlab_test::check(expected_exit,
                       "Win32 child resumes after its vectored exception handler handles the forwarded exception");
}

void run_native_hardware_breakpoint_hit_test(const std::string& executable) {
    DebugSession session(make_native_backend());
    auto launched = session.launch(Target{executable, {"--debuggee"}, {}});
    hexlab_test::check(static_cast<bool>(launched), "Win32 launches hardware-breakpoint fixture");
    if (!launched) return;
    if (launched.value().architecture != Architecture::x86_64) {
        hexlab_test::check(true, "Win32 hardware-breakpoint hit integration applies to x86-64 targets");
        while (session.state() == SessionState::running) {
            auto event = session.wait_event(std::chrono::milliseconds(100));
            if (!event) { if (event.error().code == ErrorCode::busy) continue; break; }
            (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
        }
        if (session.state() == SessionState::exited) (void)session.detach();
        return;
    }

    bool installed = false;
    bool observed_owned_hit = false;
    bool exited = false;
    BreakpointId expected_id = 0;
    for (int i = 0; i < 120 && !exited; ++i) {
        auto event = session.wait_event(std::chrono::milliseconds(100));
        if (!event) { if (event.error().code == ErrorCode::busy) continue; break; }
        if (!installed && event.value().kind == EventKind::breakpoint) {
            auto registers = session.read_registers(event.value().thread);
            auto ip = registers ? std::find_if(registers.value().begin(), registers.value().end(),
                [](const RegisterValue& reg) { return reg.name == "rip"; }) : std::vector<RegisterValue>::iterator{};
            if (registers && ip != registers.value().end() && ip->bytes.size() == sizeof(std::uint64_t)) {
                std::uint64_t address = 0;
                std::memcpy(&address, ip->bytes.data(), sizeof(address));
                auto breakpoint = session.add_breakpoint(address, BreakpointKind::execute, 1);
                installed = static_cast<bool>(breakpoint);
                if (breakpoint) expected_id = breakpoint.value().id;
            }
        } else if (event.value().kind == EventKind::breakpoint &&
                   std::find(event.value().breakpoint_ids.begin(), event.value().breakpoint_ids.end(), expected_id) !=
                       event.value().breakpoint_ids.end()) {
            observed_owned_hit = expected_id != 0;
            if (observed_owned_hit) (void)session.remove_breakpoint(expected_id);
        }
        exited = event.value().kind == EventKind::process_exited;
        (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
    }
    hexlab_test::check(installed, "Win32 installs execute hardware breakpoint at the stopped instruction pointer");
    hexlab_test::check(observed_owned_hit, "Win32 DR6 single-step event identifies the owned hardware breakpoint");
    hexlab_test::check(exited, "Win32 hardware-breakpoint fixture exits after events are acknowledged");
    if (session.state() == SessionState::exited) (void)session.detach();
}
#endif

#if defined(__linux__)
template <class T> void linux_debug_error(const char *operation, const T &result) {
    if (!result) std::fprintf(stderr, "Linux debugger diagnostic: %s: %s\n", operation,
                              result.error().message.c_str());
}

void linux_debug_wait_error(const char *operation, const Result<DebugEvent> &result) {
    if (!result) std::fprintf(stderr, "Linux debugger diagnostic: %s: %s\n", operation,
                              result.error().message.c_str());
}

void run_linux_native_lifecycle_test(const std::string& executable) {
    DebugSession session(make_native_backend());
    auto processes = session.processes();
    const auto self = processes && std::any_of(processes.value().begin(), processes.value().end(),
        [](const ProcessInfo& process) { return process.id == static_cast<ProcessId>(getpid()); });
    hexlab_test::check(self, "Linux native process enumeration includes the current process");
    Target target{executable, {"--linux-debuggee"}, {}};
    auto launched = session.launch(target);
    linux_debug_error("launch lifecycle fixture", launched);
    hexlab_test::check(static_cast<bool>(launched), "Linux ptrace backend launches a traced process");
    if (!launched) return;
    auto event = session.wait_event(std::chrono::seconds(5));
    hexlab_test::check(event && event.value().kind == EventKind::breakpoint,
                       "Linux launched child reports the exec SIGTRAP stop");
    linux_debug_wait_error("wait for lifecycle exec stop", event);
    if (event && event.value().kind != EventKind::breakpoint)
        std::fprintf(stderr, "Linux debugger diagnostic: lifecycle initial event kind=%u message=%s\n",
                     static_cast<unsigned>(event.value().kind), event.value().message.c_str());
    bool registers_ok = false;
    bool extended_registers_ok = false;
    bool ymm_registers_ok = false;
    bool breakpoint_write_ok = false;
    if (event) {
        auto regions = session.memory_regions();
        hexlab_test::check(regions && !regions.value().empty() &&
                           std::any_of(regions.value().begin(), regions.value().end(),
                               [](const MemoryRegion& region) { return region.length != 0 && region.readable; }),
                           "Linux ptrace exposes validated process memory regions while stopped");
        auto modules = session.modules();
        hexlab_test::check(modules && std::any_of(modules.value().begin(), modules.value().end(),
                               [](const ModuleInfo& module) { return module.name == "hexlab_debugger_tests" && module.size != 0; }),
                           "Linux ptrace derives file-backed module ranges from process mappings");
        auto registers = session.read_registers(event.value().thread);
        linux_debug_error("read lifecycle registers", registers);
        registers_ok = registers && std::any_of(registers.value().begin(), registers.value().end(),
            [](const RegisterValue& reg) { return reg.name == "rip" && reg.bytes.size() == sizeof(std::uint64_t); });
        if (registers) {
            const auto xmm = std::find_if(registers.value().begin(), registers.value().end(),
                [](const RegisterValue& reg) { return reg.name == "xmm0" && reg.bytes.size() == 16; });
            const auto st0 = std::find_if(registers.value().begin(), registers.value().end(),
                [](const RegisterValue& reg) { return reg.name == "st0" && reg.bytes.size() == 10; });
            const auto ymm0h = std::find_if(registers.value().begin(), registers.value().end(),
                [](const RegisterValue& reg) { return reg.name == "ymm0h" && reg.bytes.size() == 16; });
            const auto ymm_count = std::count_if(registers.value().begin(), registers.value().end(),
                [](const RegisterValue& reg) { return reg.name.starts_with("ymm") && reg.bytes.size() == 16; });
            ymm_registers_ok = ymm_count == 0;
            if (ymm_count == 16 && ymm0h != registers.value().end()) {
                auto changed_ymm = *ymm0h;
                changed_ymm.bytes[0] ^= std::byte{1};
                const auto changed = session.write_registers(event.value().thread,
                    std::span<const RegisterValue>(&changed_ymm, 1));
                const auto reread = changed ? session.read_registers(event.value().thread)
                    : Result<std::vector<RegisterValue>>{changed.error()};
                const auto changed_value = reread ? std::find_if(reread.value().begin(), reread.value().end(),
                    [](const RegisterValue& reg) { return reg.name == "ymm0h"; })
                    : std::vector<RegisterValue>::const_iterator{};
                const bool visible = reread && changed_value != reread.value().end() &&
                    changed_value->bytes == changed_ymm.bytes;
                const auto restored = session.write_registers(event.value().thread,
                    std::span<const RegisterValue>(&*ymm0h, 1));
                const auto after_restore = restored ? session.read_registers(event.value().thread)
                    : Result<std::vector<RegisterValue>>{restored.error()};
                const auto restored_value = after_restore ? std::find_if(after_restore.value().begin(), after_restore.value().end(),
                    [](const RegisterValue& reg) { return reg.name == "ymm0h"; })
                    : std::vector<RegisterValue>::const_iterator{};
                ymm_registers_ok = visible && restored && after_restore &&
                    restored_value != after_restore.value().end() && restored_value->bytes == ymm0h->bytes;
            } else if (ymm_count == 16) {
                ymm_registers_ok = false;
            }
            auto changed_xmm = xmm == registers.value().end() ? RegisterValue{} : *xmm;
            if (xmm != registers.value().end()) changed_xmm.bytes[0] ^= std::byte{1};
            const auto changed = xmm != registers.value().end()
                ? session.write_registers(event.value().thread, std::span<const RegisterValue>(&changed_xmm, 1))
                : Status{Error{ErrorCode::unsupported, "xmm0 missing"}};
            linux_debug_error("write changed xmm0", changed);
            const auto after_change = changed ? session.read_registers(event.value().thread)
                                              : Result<std::vector<RegisterValue>>{changed.error()};
            linux_debug_error("read back changed xmm0", after_change);
            const auto changed_value = after_change ? std::find_if(after_change.value().begin(), after_change.value().end(),
                [](const RegisterValue& reg) { return reg.name == "xmm0"; }) : std::vector<RegisterValue>::const_iterator{};
            const bool mutation_visible = after_change && changed_value != after_change.value().end() &&
                changed_value->bytes == changed_xmm.bytes;
            const auto restored = xmm != registers.value().end()
                ? session.write_registers(event.value().thread, std::span<const RegisterValue>(&*xmm, 1))
                : Status{Error{ErrorCode::unsupported, "xmm0 missing"}};
            linux_debug_error("restore xmm0", restored);
            const auto after_restore = restored ? session.read_registers(event.value().thread)
                                                : Result<std::vector<RegisterValue>>{restored.error()};
            linux_debug_error("read back restored xmm0", after_restore);
            const auto restored_value = after_restore ? std::find_if(after_restore.value().begin(), after_restore.value().end(),
                [](const RegisterValue& reg) { return reg.name == "xmm0"; }) : std::vector<RegisterValue>::const_iterator{};
            extended_registers_ok = xmm != registers.value().end() && st0 != registers.value().end() && changed &&
                mutation_visible && restored && after_restore && restored_value != after_restore.value().end() &&
                restored_value->bytes == xmm->bytes;
            if (!extended_registers_ok)
                std::fprintf(stderr, "Linux debugger diagnostic: x87/XMM round-trip xmm=%d st0=%d changed=%d visible=%d restored=%d reread=%d value_matches=%d\n",
                    xmm != registers.value().end(), st0 != registers.value().end(), static_cast<bool>(changed),
                    mutation_visible, static_cast<bool>(restored), static_cast<bool>(after_restore),
                    after_restore && xmm != registers.value().end() &&
                        restored_value != after_restore.value().end() && restored_value->bytes == xmm->bytes);
            const auto ip = std::find_if(registers.value().begin(), registers.value().end(),
                [](const RegisterValue& reg) { return reg.name == "rip" && reg.bytes.size() == sizeof(std::uint64_t); });
            if (ip != registers.value().end()) {
                std::uint64_t address = 0;
                std::memcpy(&address, ip->bytes.data(), sizeof(address));
                auto original = session.read_memory(address, 1);
                linux_debug_error("read original breakpoint byte", original);
                const bool original_captured_before_install = static_cast<bool>(original);
                auto breakpoint = session.add_breakpoint(address, BreakpointKind::software);
                linux_debug_error("add software breakpoint", breakpoint);
                const std::byte replacement{0x90}, trap{0xcc};
                auto disabled = breakpoint ? session.set_breakpoint_enabled(breakpoint.value().id, false)
                                           : Status{breakpoint.error()};
                linux_debug_error("disable software breakpoint", disabled);
                auto disabled_byte = session.read_memory(address, 1);
                linux_debug_error("read disabled breakpoint byte", disabled_byte);
                auto enabled = breakpoint ? session.set_breakpoint_enabled(breakpoint.value().id, true)
                                          : Status{breakpoint.error()};
                linux_debug_error("enable software breakpoint", enabled);
                auto enabled_byte = session.read_memory(address, 1);
                linux_debug_error("read enabled breakpoint byte", enabled_byte);
                auto write = breakpoint ? session.write_memory(address, std::span<const std::byte>(&replacement, 1))
                                        : Status{breakpoint.error()};
                linux_debug_error("write through software breakpoint", write);
                auto visible = session.read_memory(address, 1);
                linux_debug_error("read visible breakpoint byte", visible);
                auto removed = breakpoint ? session.remove_breakpoint(breakpoint.value().id)
                                          : Status{breakpoint.error()};
                linux_debug_error("remove software breakpoint", removed);
                auto restored = session.read_memory(address, 1);
                linux_debug_error("read restored breakpoint byte", restored);
                const auto restore_original = removed && original
                    ? session.write_memory(address, original.value())
                    : Status{Error{ErrorCode::busy, "cannot restore the original instruction byte"}};
                linux_debug_error("restore executable instruction byte", restore_original);
                breakpoint_write_ok = breakpoint && original_captured_before_install && original && disabled && disabled_byte &&
                    disabled_byte.value()[0] == original.value()[0] && enabled && enabled_byte &&
                    enabled_byte.value()[0] == trap && write && visible && visible.value()[0] == trap && removed &&
                    restored && restored.value()[0] == replacement && restore_original;
                if (!breakpoint_write_ok)
                    std::fprintf(stderr, "Linux debugger diagnostic: software breakpoint transaction add=%d original=%d disable=%d disabled_byte=%d enable=%d enabled_byte=%d write=%d visible=%d remove=%d restored=%d byte_values=%d/%d/%d/%d/%d\n",
                        static_cast<bool>(breakpoint), static_cast<bool>(original), static_cast<bool>(disabled),
                        static_cast<bool>(disabled_byte), static_cast<bool>(enabled), static_cast<bool>(enabled_byte),
                        static_cast<bool>(write), static_cast<bool>(visible), static_cast<bool>(removed), static_cast<bool>(restored),
                        original && !original.value().empty() ? std::to_integer<int>(original.value()[0]) : -1,
                        disabled_byte && !disabled_byte.value().empty() ? std::to_integer<int>(disabled_byte.value()[0]) : -1,
                        enabled_byte && !enabled_byte.value().empty() ? std::to_integer<int>(enabled_byte.value()[0]) : -1,
                        visible && !visible.value().empty() ? std::to_integer<int>(visible.value()[0]) : -1,
                        restored && !restored.value().empty() ? std::to_integer<int>(restored.value()[0]) : -1);
            }
        }
        (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
    }
    hexlab_test::check(registers_ok, "Linux x86-64 ptrace exposes the instruction pointer register");
    hexlab_test::check(extended_registers_ok,
        "Linux x86-64 ptrace reads x87/XMM state and writes/restores an XMM register");
    hexlab_test::check(ymm_registers_ok,
        "Linux x86-64 ptrace exposes a complete optional YMM upper bank and writes/restores ymm0h");
    hexlab_test::check(breakpoint_write_ok,
        "Linux software breakpoints disable and re-enable in place, while memory edits preserve traps and update the restored byte");
    bool exited = false;
    for (int i = 0; i < 250 && !exited; ++i) {
        event = session.wait_event(std::chrono::milliseconds(50));
        if (!event) { if (event.error().code == ErrorCode::busy) continue; linux_debug_wait_error("wait for child exit", event); break; }
        exited = event.value().kind == EventKind::process_exited;
        (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
    }
    if (!exited) std::fprintf(stderr, "Linux debugger diagnostic: child exit not observed; session state=%u\n",
                              static_cast<unsigned>(session.state()));
    hexlab_test::check(exited, "Linux traced child exit is delivered through the event queue");
    if (session.state() == SessionState::exited) (void)session.detach();
}

void run_linux_launched_interrupt_test(const std::string& executable) {
    DebugSession session(make_native_backend());
    auto failed = session.launch(Target{executable + ".missing", {"--linux-interrupt-debuggee"}, {}});
    if (failed) std::fprintf(stderr, "Linux debugger diagnostic: missing executable unexpectedly launched pid=%llu\n",
                             static_cast<unsigned long long>(failed.value().id));
    hexlab_test::check(!failed, "Linux failed exec is reported instead of publishing a launch");
    int failed_status = 0;
    errno = 0;
    const auto unreaped_child = waitpid(-1, &failed_status, WNOHANG);
    const auto reap_errno = errno;
    if (unreaped_child != -1 || reap_errno != ECHILD)
        std::fprintf(stderr, "Linux debugger diagnostic: failed-exec child reap probe returned pid=%ld errno=%d status=0x%x\n",
                     static_cast<long>(unreaped_child), reap_errno, failed_status);
    if ((unreaped_child != -1 || reap_errno != ECHILD) && !failed)
        std::fprintf(stderr, "Linux debugger diagnostic: failed exec launch error: %s\n", failed.error().message.c_str());
    errno = reap_errno;
    hexlab_test::check(unreaped_child == -1 && errno == ECHILD,
                       "Linux failed exec is reaped before launch returns");

    auto launched = session.launch(Target{executable, {"--linux-interrupt-debuggee", "argument-forwarded"}, {}});
    linux_debug_error("launch interrupt fixture", launched);
    hexlab_test::check(static_cast<bool>(launched), "Linux launches a target that can be asynchronously interrupted");
    if (!launched) return;
    const auto process = launched.value().id;
    auto initial = session.wait_event(std::chrono::seconds(5));
    linux_debug_wait_error("wait for interrupt fixture exec stop", initial);
    const bool initial_stop = initial && initial.value().kind == EventKind::breakpoint;
    if (initial && !initial_stop)
        std::fprintf(stderr, "Linux debugger diagnostic: interrupt fixture initial event kind=%u message=%s\n",
                     static_cast<unsigned>(initial.value().kind), initial.value().message.c_str());
    hexlab_test::check(initial_stop, "Linux seized launch reports the initial exec stop");
    if (!initial) { (void)session.detach(); return; }
    auto resumed = session.continue_execution(initial.value().sequence, ContinueStatus::handled);
    linux_debug_error("resume interrupt fixture", resumed);
    hexlab_test::check(static_cast<bool>(resumed), "Linux resumes the launched target after exec stop");
    auto requested = resumed ? session.request_interrupt() : Status{resumed.error()};
    linux_debug_error("request async interrupt", requested);
    hexlab_test::check(static_cast<bool>(requested), "Linux asynchronous interrupt accepts a launched seized target");
    auto interrupted = requested ? session.wait_event(std::chrono::seconds(5))
                                 : Result<DebugEvent>{Error{ErrorCode::busy, "interrupt was not accepted"}};
    linux_debug_wait_error("wait for async interrupt stop", interrupted);
    if (interrupted && (interrupted.value().kind != EventKind::interrupted || interrupted.value().message != "debugger interrupt"))
        std::fprintf(stderr, "Linux debugger diagnostic: interrupt event kind=%u message=%s\n",
                     static_cast<unsigned>(interrupted.value().kind), interrupted.value().message.c_str());
    const bool stopped = interrupted && interrupted.value().kind == EventKind::interrupted &&
                         interrupted.value().message == "debugger interrupt";
    if (!stopped)
        std::fprintf(stderr, "Linux debugger diagnostic: interrupt outcome requested=%d got_event=%d state=%u\n",
                     static_cast<bool>(requested), static_cast<bool>(interrupted), static_cast<unsigned>(session.state()));
    hexlab_test::check(stopped, "Linux interrupt produces an explicit ptrace stop event");
    if (interrupted && session.state() == SessionState::stopped)
        (void)session.continue_execution(interrupted.value().sequence, ContinueStatus::handled);
    auto detached = session.detach();
    linux_debug_error("detach interrupt fixture", detached);
    hexlab_test::check(static_cast<bool>(detached), "Linux detaches cleanly after interrupting a launched target");
    if (detached) {
        int status = 0;
        const auto waited = waitpid(static_cast<pid_t>(process), &status, WNOHANG);
        const bool survived = waited == 0 && kill(static_cast<pid_t>(process), 0) == 0;
        if (!survived) std::fprintf(stderr, "Linux debugger diagnostic: detached process probe waitpid=%ld errno=%d status=0x%x\n",
                                    static_cast<long>(waited), errno, status);
        hexlab_test::check(survived, "Linux launched target remains alive immediately after debugger detach");
        if (survived) {
            (void)kill(static_cast<pid_t>(process), SIGTERM);
            (void)waitpid(static_cast<pid_t>(process), &status, 0);
        }
    }
}

void run_linux_i386_native_test(const std::string& executable) {
    DebugSession session(make_native_backend());
    auto launched = session.launch(Target{executable, {}, {}});
    hexlab_test::check(launched && launched.value().architecture == Architecture::x86,
                       "Linux ptrace launches and identifies an ELF32 i386 tracee");
    if (!launched) return;

    auto event = session.wait_event(std::chrono::seconds(5));
    auto registers = event ? session.read_registers(event.value().thread)
                           : Result<std::vector<RegisterValue>>{Error{ErrorCode::busy, "exec stop missing"}};
    auto ip = registers ? std::find_if(registers.value().begin(), registers.value().end(),
        [](const RegisterValue& reg) { return reg.name == "eip" && reg.bytes.size() == sizeof(std::uint32_t); })
        : std::vector<RegisterValue>::iterator{};
    const auto xmm0 = registers ? std::find_if(registers.value().begin(), registers.value().end(),
        [](const RegisterValue& reg) { return reg.name == "xmm0" && reg.bytes.size() == 16; })
        : std::vector<RegisterValue>::iterator{};
    const auto st0 = registers ? std::find_if(registers.value().begin(), registers.value().end(),
        [](const RegisterValue& reg) { return reg.name == "st0" && reg.bytes.size() == 10; })
        : std::vector<RegisterValue>::iterator{};
    const bool registers_ok = registers && registers.value().size() >= 42 && ip != registers.value().end();
    std::uint32_t address = 0;
    if (registers_ok) std::memcpy(&address, ip->bytes.data(), sizeof(address));
    const RegisterValue ip_write{"eip", std::vector<std::byte>(sizeof(address))};
    auto writable_ip = ip_write;
    if (registers_ok) std::memcpy(writable_ip.bytes.data(), &address, sizeof(address));
    const auto write_ip = registers_ok ? session.write_registers(event.value().thread,
        std::span<const RegisterValue>(&writable_ip, 1)) : Status{Error{ErrorCode::busy, "i386 registers unavailable"}};
    const bool fp_registers_ok = registers && xmm0 != registers.value().end() && st0 != registers.value().end();
    const auto round_trip_fp = [&](const RegisterValue& original) {
        auto changed = original;
        changed.bytes[0] ^= std::byte{1};
        auto written = session.write_registers(event.value().thread,
            std::span<const RegisterValue>(&changed, 1));
        auto observed = written ? session.read_registers(event.value().thread)
                                : Result<std::vector<RegisterValue>>{written.error()};
        const auto matches = [&](const Result<std::vector<RegisterValue>>& values, const RegisterValue& expected) {
            if (!values) return false;
            const auto found = std::find_if(values.value().begin(), values.value().end(), [&](const auto& value) {
                return value.name == expected.name;
            });
            return found != values.value().end() && found->bytes == expected.bytes;
        };
        const bool changed_visible = matches(observed, changed);
        const auto restored = session.write_registers(event.value().thread,
            std::span<const RegisterValue>(&original, 1));
        const auto after_restore = restored ? session.read_registers(event.value().thread)
                                            : Result<std::vector<RegisterValue>>{restored.error()};
        return changed_visible && restored && matches(after_restore, original);
    };
    const bool fp_write_ok = fp_registers_ok && round_trip_fp(*xmm0) && round_trip_fp(*st0);

    bool software_breakpoint_ok = false;
    bool unsupported_hardware_ok = false;
    std::byte original_instruction{};
    BreakpointId breakpoint_id = 0;
    if (registers_ok && event) {
        auto hardware = session.add_breakpoint(address, BreakpointKind::execute);
        unsupported_hardware_ok = !hardware && hardware.error().code == ErrorCode::unsupported;
        auto original = session.read_memory(address, 1);
        if (original) original_instruction = original.value()[0];
        auto breakpoint = session.add_breakpoint(address, BreakpointKind::software);
        if (breakpoint) {
            breakpoint_id = breakpoint.value().id;
            auto bytes = session.read_memory(address, 1);
            software_breakpoint_ok = original && bytes && bytes.value()[0] == std::byte{0xcc};
        }
    }
    hexlab_test::check(registers_ok && write_ip,
                       "Linux i386 ptrace exposes and writes the 32-bit general register set");
    hexlab_test::check(fp_registers_ok && fp_write_ok,
                       "Linux i386 ptrace exposes x87/SSE context and safely writes/restores st0 and xmm0");
    hexlab_test::check(software_breakpoint_ok,
                       "Linux i386 ptrace installs an INT3 software breakpoint in tracee memory");
    hexlab_test::check(unsupported_hardware_ok,
                       "Linux i386 ptrace rejects unimplemented compat hardware breakpoints explicitly");

    bool observed_hit = false;
    bool removed = false;
    bool original_restored = false;
    bool exited = false;
    if (event) (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
    for (int i = 0; i < 100 && !exited; ++i) {
        event = session.wait_event(std::chrono::milliseconds(100));
        if (!event) { if (event.error().code == ErrorCode::busy) continue; break; }
        if (event.value().kind == EventKind::breakpoint && !observed_hit && breakpoint_id != 0) {
            observed_hit = true;
        } else if (event.value().kind == EventKind::single_step && observed_hit && !removed) {
            removed = static_cast<bool>(session.remove_breakpoint(breakpoint_id));
            auto restored = session.read_memory(address, 1);
            original_restored = removed && restored && restored.value()[0] == original_instruction;
        }
        exited = event.value().kind == EventKind::process_exited;
        (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
    }
    hexlab_test::check(observed_hit && removed && original_restored,
                       "Linux i386 software breakpoint reports a hit and restores its original instruction");
    hexlab_test::check(exited,
                       "Linux i386 traced fixture exits normally after breakpoint stepping");
    if (session.state() == SessionState::exited) (void)session.detach();
}

void run_linux_hardware_breakpoint_test(const std::string& executable) {
    DebugSession session(make_native_backend());
    auto launched = session.launch(Target{executable, {"--linux-debuggee"}, {}});
    hexlab_test::check(static_cast<bool>(launched), "Linux launches a fixture for hardware breakpoint testing");
    if (!launched) return;

    bool installed = false;
    bool observed_owned_hit = false;
    bool exited = false;
    BreakpointId expected_id = 0;
    for (int i = 0; i < 120 && !exited; ++i) {
        auto event = session.wait_event(std::chrono::milliseconds(100));
        if (!event) { if (event.error().code == ErrorCode::busy) continue; break; }
        if (!installed && event.value().kind == EventKind::breakpoint) {
            auto registers = session.read_registers(event.value().thread);
            auto ip = registers ? std::find_if(registers.value().begin(), registers.value().end(),
                [](const RegisterValue& reg) { return reg.name == "rip"; }) : std::vector<RegisterValue>::iterator{};
            if (registers && ip != registers.value().end() && ip->bytes.size() == sizeof(std::uint64_t)) {
                std::uint64_t address = 0;
                std::memcpy(&address, ip->bytes.data(), sizeof(address));
                auto breakpoint = session.add_breakpoint(address, BreakpointKind::execute, 1);
                installed = static_cast<bool>(breakpoint);
                if (breakpoint) expected_id = breakpoint.value().id;
            }
        } else if (event.value().kind == EventKind::breakpoint &&
                   std::find(event.value().breakpoint_ids.begin(), event.value().breakpoint_ids.end(), expected_id) !=
                       event.value().breakpoint_ids.end()) {
            observed_owned_hit = expected_id != 0;
            if (observed_owned_hit) (void)session.remove_breakpoint(expected_id);
        }
        exited = event.value().kind == EventKind::process_exited;
        (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
    }
    hexlab_test::check(installed, "Linux installs an execute hardware breakpoint at the stopped instruction pointer");
    hexlab_test::check(observed_owned_hit, "Linux DR6 reports the owned hardware breakpoint identifier");
    hexlab_test::check(exited, "Linux hardware-breakpoint fixture exits after events are acknowledged");
    if (session.state() == SessionState::exited) (void)session.detach();
}

void run_linux_write_watchpoint_test() {
    struct SharedTarget {
        volatile std::uint64_t watched_value;
        volatile unsigned ready;
        volatile unsigned trigger;
    };
    void* storage = mmap(nullptr, sizeof(SharedTarget), PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    hexlab_test::check(storage != MAP_FAILED, "Linux creates shared state for a write-watchpoint target");
    if (storage == MAP_FAILED) return;
    auto* shared = ::new (storage) SharedTarget{};
    shared->watched_value = 0x1122334455667788ULL;
    const pid_t child = fork();
    hexlab_test::check(child >= 0, "Linux creates a child that will write to the watched address");
    if (child < 0) {
        (void)munmap(storage, sizeof(SharedTarget));
        return;
    }
    if (child == 0) {
        shared->ready = 1;
        while (shared->trigger == 0) std::this_thread::yield();
        shared->watched_value = 0x8877665544332211ULL;
        _exit(0);
    }
    for (int i = 0; i < 500 && shared->ready == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(2));

    DebugSession session(make_native_backend());
    auto attached = shared->ready != 0 ? session.attach(static_cast<ProcessId>(child))
                                       : Result<ProcessInfo>{Error{ErrorCode::busy, "watchpoint child did not start"}};
    linux_debug_error("attach watchpoint child", attached);
    hexlab_test::check(static_cast<bool>(attached), "Linux attaches to the child before its watched write");
    bool installed = false;
    bool observed_owned_hit = false;
    bool observed_write = false;
    bool exited = false;
    std::uint32_t observed_exit_code = std::numeric_limits<std::uint32_t>::max();
    if (attached) {
        auto initial = session.wait_event(std::chrono::milliseconds(50));
        linux_debug_wait_error("wait for watchpoint child initial stop", initial);
        if (initial && initial.value().kind != EventKind::exception)
            std::fprintf(stderr, "Linux debugger diagnostic: watchpoint initial event kind=%u message=%s\n",
                         static_cast<unsigned>(initial.value().kind), initial.value().message.c_str());
        auto breakpoint = initial ? session.add_breakpoint(
            reinterpret_cast<std::uintptr_t>(&shared->watched_value), BreakpointKind::write, sizeof(std::uint64_t))
                                  : Result<Breakpoint>{initial.error()};
        linux_debug_error("install write watchpoint", breakpoint);
        installed = static_cast<bool>(breakpoint);
        hexlab_test::check(installed, "Linux installs an aligned eight-byte write watchpoint on a stopped child");
        if (breakpoint) {
            shared->trigger = 1;
            auto resumed = session.continue_execution(initial.value().sequence, ContinueStatus::handled);
            linux_debug_error("resume watchpoint child", resumed);
            hexlab_test::check(static_cast<bool>(resumed), "Linux resumes the child after installing its watchpoint");
            for (int i = 0; i < 100 && !exited; ++i) {
                auto event = session.wait_event(std::chrono::milliseconds(100));
                if (!event) { if (event.error().code == ErrorCode::busy) continue; linux_debug_wait_error("wait for watchpoint event", event); break; }
                if (event.value().kind == EventKind::breakpoint &&
                    std::find(event.value().breakpoint_ids.begin(), event.value().breakpoint_ids.end(), breakpoint.value().id) !=
                        event.value().breakpoint_ids.end()) {
                    observed_owned_hit = true;
                    observed_write = shared->watched_value == 0x8877665544332211ULL;
                    auto removed = session.remove_breakpoint(breakpoint.value().id);
                    linux_debug_error("remove hit write watchpoint", removed);
                    hexlab_test::check(static_cast<bool>(removed), "Linux removes the hit write watchpoint while stopped");
                }
                exited = event.value().kind == EventKind::process_exited;
                if (exited) observed_exit_code = event.value().code;
                (void)session.continue_execution(event.value().sequence, ContinueStatus::handled);
            }
        } else if (initial) {
            shared->trigger = 1;
            (void)session.continue_execution(initial.value().sequence, ContinueStatus::handled);
        }
    } else {
        shared->trigger = 1;
    }
    if (!observed_owned_hit || !exited)
        std::fprintf(stderr, "Linux debugger diagnostic: write-watchpoint outcome hit=%d committed=%d exited=%d state=%u\n",
                     observed_owned_hit, observed_write, exited, static_cast<unsigned>(session.state()));
    hexlab_test::check(observed_owned_hit, "Linux DR6 maps a data-write stop to its owned breakpoint ID");
    hexlab_test::check(observed_write, "Linux reports the watchpoint after the target store has committed");
    hexlab_test::check(exited, "Linux write-watchpoint target exits after its stop is acknowledged");
    if (session.state() == SessionState::exited) (void)session.detach();
    int status{};
    // A ptrace wait for the process-exit event has already consumed this
    // direct child’s wait status. In that case the original parent correctly
    // gets ECHILD and must not signal a potentially reused PID.
    bool reaped_by_tracer = exited && observed_exit_code == 0;
    bool reaped = reaped_by_tracer;
    pid_t last_waited = -1;
    int last_wait_errno = 0;
    for (int i = 0; i < 100 && !reaped; ++i) {
        errno = 0;
        const auto waited = waitpid(child, &status, WNOHANG);
        last_waited = waited;
        last_wait_errno = errno;
        reaped = waited == child;
        if (!reaped) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!reaped && !exited) { (void)kill(child, SIGKILL); (void)waitpid(child, &status, 0); }
    if (!reaped_by_tracer && reaped && WIFEXITED(status) && WEXITSTATUS(status) == 0)
        reaped = true;
    if (!reaped) {
        std::fprintf(stderr, "Linux debugger diagnostic: watchpoint child was not reaped before forced cleanup; pid=%ld status=0x%x\n",
                     static_cast<long>(child), status);
        std::fprintf(stderr, "Linux debugger diagnostic: last watchpoint waitpid=%ld errno=%d\n",
                     static_cast<long>(last_waited), last_wait_errno);
    }
    hexlab_test::check(reaped && (reaped_by_tracer || (WIFEXITED(status) && WEXITSTATUS(status) == 0)),
                       "Linux watchpoint child is reaped cleanly");
    (void)munmap(storage, sizeof(SharedTarget));
}

void run_linux_multithread_attach_test(const std::string& executable) {
    int ready_pipe[2]{};
    int release_pipe[2]{};
    if (pipe(ready_pipe) != 0) {
        hexlab_test::check(false, "Linux creates a readiness pipe for multithread attach fixture");
        return;
    }
    if (pipe(release_pipe) != 0) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        hexlab_test::check(false, "Linux creates a release pipe for multithread attach fixture");
        return;
    }
    const pid_t child = fork();
    hexlab_test::check(child >= 0, "Linux creates a child for multithread ptrace attach");
    if (child < 0) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        close(release_pipe[0]);
        close(release_pipe[1]);
        return;
    }
    if (child == 0) {
        close(ready_pipe[0]);
        close(release_pipe[1]);
        const auto ready_fd = std::to_string(ready_pipe[1]);
        const auto release_fd = std::to_string(release_pipe[0]);
        execl(executable.c_str(), executable.c_str(), "--linux-attach-debuggee", ready_fd.c_str(),
              release_fd.c_str(), nullptr);
        _exit(127);
    }
    close(ready_pipe[1]);
    close(release_pipe[0]);
    pollfd ready_event{ready_pipe[0], POLLIN, 0};
    const auto ready_poll = poll(&ready_event, 1, 5000);
    char ready_byte{};
    const auto ready_read = ready_poll > 0 && (ready_event.revents & POLLIN)
        ? read(ready_pipe[0], &ready_byte, 1) : -1;
    close(ready_pipe[0]);
    const bool target_threads_ready = ready_read == 1 && ready_byte == 'R';
    hexlab_test::check(target_threads_ready,
                       "Linux attach fixture starts both worker threads before parent attach");
    if (!target_threads_ready) {
        close(release_pipe[1]);
        (void)kill(child, SIGKILL);
        int failed_status{};
        (void)waitpid(child, &failed_status, 0);
        return;
    }
    {
    DebugSession session(make_native_backend());
    auto attached = session.attach(static_cast<ProcessId>(child));
    linux_debug_error("attach multithread child", attached);
    hexlab_test::check(static_cast<bool>(attached), "Linux ptrace attach stops an existing child process");
    if (attached) {
        auto threads = session.threads();
        linux_debug_error("enumerate attached threads", threads);
        const bool all_stopped = threads && threads.value().size() >= 3 &&
            std::all_of(threads.value().begin(), threads.value().end(), [](const ThreadInfo& thread) {
                return thread.state == ThreadState::stopped;
            });
        hexlab_test::check(all_stopped,
            "Linux attach converges on every target thread and reports each stopped before returning");
        if (!all_stopped) {
            if (threads) {
                for (const auto &thread : threads.value())
                    std::fprintf(stderr, "Linux debugger diagnostic: attached thread id=%llu state=%u native=%s\n",
                                 static_cast<unsigned long long>(thread.id), static_cast<unsigned>(thread.state),
                                 thread.native_state.c_str());
            }
        }
        auto event = session.wait_event(std::chrono::milliseconds(50));
        linux_debug_wait_error("wait for multithread attach event", event);
        if (event && event.value().kind != EventKind::exception)
            std::fprintf(stderr, "Linux debugger diagnostic: attach event kind=%u message=%s\n",
                         static_cast<unsigned>(event.value().kind), event.value().message.c_str());
        hexlab_test::check(event && event.value().kind == EventKind::exception,
                           "Linux attach exposes its synthetic initial stop as an explicit event");
        if (event) {
            auto registers = session.read_registers(event.value().thread);
            auto ip = registers ? std::find_if(registers.value().begin(), registers.value().end(),
                [](const RegisterValue& reg) { return reg.name == "rip"; }) : std::vector<RegisterValue>::iterator{};
            if (registers && ip != registers.value().end() && ip->bytes.size() == sizeof(std::uint64_t)) {
                std::uint64_t address = 0;
                std::memcpy(&address, ip->bytes.data(), sizeof(address));
                auto breakpoint = session.add_breakpoint(address, BreakpointKind::execute, 1);
                linux_debug_error("install attach-group execute breakpoint", breakpoint);
                hexlab_test::check(static_cast<bool>(breakpoint),
                    "Linux installs a hardware execute breakpoint across the stopped thread group");
                if (breakpoint) {
                    bool every_thread_configured = true;
                    for (const auto& thread : threads.value()) {
                        errno = 0;
                        const auto dr0 = ptrace(PTRACE_PEEKUSER, static_cast<pid_t>(thread.id),
                            reinterpret_cast<void*>(offsetof(struct user, u_debugreg)), nullptr);
                        const auto dr0_error = errno;
                        errno = 0;
                        const auto dr7 = ptrace(PTRACE_PEEKUSER, static_cast<pid_t>(thread.id),
                            reinterpret_cast<void*>(offsetof(struct user, u_debugreg) + 7 * sizeof(unsigned long)), nullptr);
                        const auto dr7_error = errno;
                        every_thread_configured = every_thread_configured && !(dr0 == -1 && dr0_error) &&
                            !(dr7 == -1 && dr7_error) && static_cast<std::uint64_t>(dr0) == address && (dr7 & 1) != 0;
                    }
                    hexlab_test::check(every_thread_configured,
                        "Linux hardware breakpoint installs DR0/DR7 ownership on every stopped thread");
                    auto removed = session.remove_breakpoint(breakpoint.value().id);
                    hexlab_test::check(static_cast<bool>(removed),
                        "Linux removes an owned hardware breakpoint from every stopped thread");
                }
            } else {
                hexlab_test::check(false, "Linux obtains an instruction pointer for the stopped thread group");
            }
        }
        auto detached = session.detach();
        linux_debug_error("detach multithread child", detached);
        hexlab_test::check(static_cast<bool>(detached), "Linux detach releases every seized target thread");
    }
    }
    const char release_byte = 'Q';
    ssize_t release_sent;
    do { release_sent = write(release_pipe[1], &release_byte, 1); }
    while (release_sent < 0 && errno == EINTR);
    close(release_pipe[1]);
    if (release_sent != 1) {
        std::fprintf(stderr, "Linux debugger diagnostic: could not release attach fixture; errno=%d\n", errno);
        (void)kill(child, SIGKILL);
    }
    int status{};
    bool exited = false;
    for (int i = 0; i < 100 && !exited; ++i) {
        const auto waited = waitpid(child, &status, WNOHANG);
        exited = waited == child;
        if (!exited) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (!exited) { (void)kill(child, SIGKILL); (void)waitpid(child, &status, 0); }
    if (!exited) std::fprintf(stderr, "Linux debugger diagnostic: attached child not reaped after detach; pid=%ld status=0x%x\n",
                              static_cast<long>(child), status);
    hexlab_test::check(exited && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                       "Linux attached child resumes cleanly after detach and exits normally");
}
#endif
}

int main(int argc, char **argv) {
#if defined(_WIN32)
    if (argc == 2 && std::string_view(argv[1]) == "--debuggee") return 0;
    if (argc == 2 && std::string_view(argv[1]) == "--debuggee-lifecycle-fixture") {
        Sleep(1000);
        return 0;
    }
    if (argc == 3 && std::string_view(argv[1]) == "--debuggee-detach-fixture") {
        HANDLE release = OpenEventA(SYNCHRONIZE, FALSE, argv[2]);
        if (!release) return 2;
        const DWORD wait = WaitForSingleObject(release, 10000);
        CloseHandle(release);
        return wait == WAIT_OBJECT_0 ? 0 : 3;
    }
    if (argc == 2 && std::string_view(argv[1]) == "--debuggee-attach-fixture") {
        Sleep(5000);
        return 0;
    }
    if (argc == 2 && std::string_view(argv[1]) == "--debuggee-interrupt-fixture") {
        for (;;) Sleep(1000);
    }
    if (argc == 2 && std::string_view(argv[1]) == "--debuggee-breakpoint-fixture") {
        debugger_software_breakpoint_target();
        return 0;
    }
    if (argc == 2 && std::string_view(argv[1]) == "--debuggee-exception-delivery-fixture") {
        InterlockedExchange(&debugger_fixture_exception_handled, 0);
        const auto handler = AddVectoredExceptionHandler(1, debugger_fixture_exception_handler);
        if (!handler) return 0x44;
        RaiseException(debugger_fixture_exception, 0, 0, nullptr);
        RemoveVectoredExceptionHandler(handler);
        return InterlockedCompareExchange(&debugger_fixture_exception_handled, 0, 0) ? 0x42 : 0x43;
    }
#elif defined(__linux__)
    if (argc == 2 && std::string_view(argv[1]) == "--linux-debuggee") return 0;
    if (argc == 2 && std::string_view(argv[1]) == "--linux-aarch64-debuggee") return 0;
    if (argc >= 2 && std::string_view(argv[1]) == "--linux-interrupt-debuggee") {
        if (argc != 3 || std::string_view(argv[2]) != "argument-forwarded") return 78;
        std::this_thread::sleep_for(std::chrono::seconds(30));
        return 0;
    }
    if (argc == 4 && std::string_view(argv[1]) == "--linux-attach-debuggee") {
        int ready_fd = -1, release_fd = -1;
        const std::string_view ready_arg(argv[2]), release_arg(argv[3]);
        const auto ready_parsed = std::from_chars(ready_arg.data(), ready_arg.data() + ready_arg.size(), ready_fd);
        const auto release_parsed = std::from_chars(release_arg.data(), release_arg.data() + release_arg.size(), release_fd);
        if (ready_parsed.ec != std::errc{} || ready_parsed.ptr != ready_arg.data() + ready_arg.size() || ready_fd < 0 ||
            release_parsed.ec != std::errc{} || release_parsed.ptr != release_arg.data() + release_arg.size() || release_fd < 0)
            return 79;
        std::atomic<unsigned> ready{0};
        std::atomic<bool> stop_workers{false};
        auto worker = [&] {
            ++ready;
            while (!stop_workers.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        };
        std::thread first(worker), second(worker);
        while (ready.load() != 2) std::this_thread::yield();
        const char marker = 'R';
        ssize_t sent;
        do { sent = write(ready_fd, &marker, 1); } while (sent < 0 && errno == EINTR);
        close(ready_fd);
        if (sent != 1) stop_workers.store(true);
        char release{};
        ssize_t received;
        do { received = read(release_fd, &release, 1); } while (received < 0 && errno == EINTR);
        close(release_fd);
        stop_workers.store(true);
        first.join(); second.join();
        return sent == 1 && received == 1 && release == 'Q' ? 0 : 79;
    }
    const std::string executable = argv[0];
    return hexlab_test::run([&] {
        run_tests();
#if defined(__aarch64__)
        DebugSession session(make_native_backend());
        auto launched = session.launch(Target{executable, {"--linux-aarch64-debuggee"}, {}});
        hexlab_test::check(static_cast<bool>(launched), "Linux AArch64 backend launches a native target");
        auto initial = launched ? session.wait_event(std::chrono::seconds(2)) : Result<DebugEvent>{launched.error()};
        hexlab_test::check(initial && initial.value().kind == EventKind::breakpoint, "Linux AArch64 launch reports its exec stop");
        auto registers = initial ? session.read_registers(initial.value().thread) : Result<std::vector<RegisterValue>>{initial.error()};
        std::uint64_t address{}; bool pc_ok = false;
        if (registers) for (const auto& reg : registers.value()) if (reg.name == "pc" && reg.bytes.size() == 8) { std::memcpy(&address, reg.bytes.data(), sizeof(address)); pc_ok = true; break; }
        hexlab_test::check(pc_ok, "Linux AArch64 exposes a 64-bit PC register");
        bool breakpoint_ok = false;
        if (pc_ok) {
            auto original = session.read_memory(address, 4);
            auto bp = session.add_breakpoint(address);
            auto installed = session.read_memory(address, 4);
            breakpoint_ok = original && bp && installed && installed.value() == std::vector<std::byte>{std::byte{0}, std::byte{0}, std::byte{0x20}, std::byte{0xd4}};
            if (bp) {
                auto resumed = session.continue_execution(initial.value().sequence, ContinueStatus::handled);
                auto hit = resumed ? session.wait_event(std::chrono::seconds(2)) : Result<DebugEvent>{resumed.error()};
                breakpoint_ok = breakpoint_ok && hit && hit.value().kind == EventKind::breakpoint && hit.value().address == address;
                auto stepped = hit ? session.continue_execution(hit.value().sequence, ContinueStatus::handled) : Status{Error{ErrorCode::io, "breakpoint was not hit"}};
                auto step_event = stepped ? session.wait_event(std::chrono::seconds(2)) : Result<DebugEvent>{stepped.error()};
                breakpoint_ok = breakpoint_ok && step_event && step_event.value().kind == EventKind::single_step;
                auto removed = session.remove_breakpoint(bp.value().id);
                auto restored = removed ? session.read_memory(address, 4) : Result<std::vector<std::byte>>{removed.error()};
                breakpoint_ok = breakpoint_ok && removed && original && restored && restored.value() == original.value();
                if (step_event) (void)session.continue_execution(step_event.value().sequence, ContinueStatus::handled);
            } else (void)session.continue_execution(initial.value().sequence, ContinueStatus::handled);
        } else if (initial) (void)session.continue_execution(initial.value().sequence, ContinueStatus::handled);
        hexlab_test::check(breakpoint_ok, "Linux AArch64 installs, hits, and removes an aligned BRK software breakpoint");
#else
        run_linux_native_lifecycle_test(executable);
        run_linux_launched_interrupt_test(executable);
        if (argc == 2) run_linux_i386_native_test(argv[1]);
        run_linux_hardware_breakpoint_test(executable);
        run_linux_write_watchpoint_test();
        run_linux_multithread_attach_test(executable);
#endif
    });
#else
    (void)argc;
    (void)argv;
#endif
#if defined(_WIN32)
    const std::string executable = argv[0];
    return hexlab_test::run([&] {
        run_tests();
        run_native_process_discovery_test();
        run_native_attach_lifecycle_test(executable);
        run_native_launch_detach_test(executable);
        run_native_launch_lifecycle_test(executable);
        run_native_interrupt_test(executable);
        run_native_single_step_test(executable);
        run_native_owned_breakpoint_step_test(executable);
        run_native_exception_delivery_test(executable);
        run_native_hardware_breakpoint_hit_test(executable);
    });
#elif defined(__APPLE__) || defined(__linux__)
    return hexlab_test::run([&] { run_tests(); });
#else
    return hexlab_test::run([&] {
        run_tests();
        auto unsupported = make_native_backend()->processes();
        hexlab_test::check(!unsupported && unsupported.error().code == ErrorCode::unsupported,
                           "non-Windows native process enumeration is explicitly unsupported");
    });
#endif
}
