#pragma once

#include <cstdint>
#include <optional>

namespace hexlab::debugger::detail {

// Tracks the one software breakpoint whose INT3 byte is displaced while its
// instruction executes. Kept platform-neutral so the Windows event protocol
// can be tested without launching a debuggee.
class BreakpointStepState {
public:
    bool begin(std::uintptr_t address, std::uint64_t instruction_pointer,
               std::uint64_t thread) noexcept {
        if (active_ || address == UINTPTR_MAX || instruction_pointer != address + 1 || thread == 0)
            return false;
        address_ = address;
        thread_ = thread;
        active_ = true;
        return true;
    }

    std::optional<std::uintptr_t> complete(std::uint64_t thread) noexcept {
        if (!active_ || thread != thread_) return std::nullopt;
        const auto address = address_;
        clear();
        return address;
    }

    void retain(std::uintptr_t address, std::uint64_t thread) noexcept {
        address_ = address;
        thread_ = thread;
        active_ = thread != 0;
    }

    void clear() noexcept {
        active_ = false;
        address_ = 0;
        thread_ = 0;
    }

    bool active() const noexcept { return active_; }

private:
    std::uintptr_t address_ = 0;
    std::uint64_t thread_ = 0;
    bool active_ = false;
};

} // namespace hexlab::debugger::detail
