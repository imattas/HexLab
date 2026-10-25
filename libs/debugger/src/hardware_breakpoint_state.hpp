#pragma once

#include "hexlab/debugger/debugger.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace hexlab::debugger::detail {
struct HardwareRequest { std::uint64_t address; BreakpointKind kind; std::uint8_t size; };
struct DebugRegisters { std::array<std::uint64_t, 4> address{}; std::uint64_t dr7 = 0; };

// Apply one debugger-owned register state to a collection as a transaction.
// A failed apply triggers reverse-order restoration of every earlier item.
// The failing item itself is not restored because callers must treat a failed
// platform setter as not having committed; platforms that cannot guarantee
// that property should include the failing item in their rollback policy.
template<class Item, class Apply, class Rollback>
Status transact_debug_registers(const std::vector<Item>& items, Apply&& apply, Rollback&& rollback) {
    std::size_t applied = 0;
    for (; applied < items.size(); ++applied) {
        auto result = apply(items[applied]);
        if (result) continue;
        std::string message = result.error().message;
        bool rollback_failed = false;
        std::string rollback_errors;
        while (applied > 0) {
            --applied;
            auto restored = rollback(items[applied]);
            if (restored) continue;
            rollback_failed = true;
            if (!rollback_errors.empty()) rollback_errors += "; ";
            rollback_errors += restored.error().message;
        }
        if (rollback_failed)
            message += "; rollback was incomplete: " + rollback_errors;
        return Error{result.error().code, std::move(message)};
    }
    return std::monostate{};
}

inline std::optional<std::uint8_t> length_encoding(std::uint8_t size) {
    switch (size) { case 1: return std::uint8_t{0}; case 2: return std::uint8_t{1}; case 4: return std::uint8_t{3}; case 8: return std::uint8_t{2}; default: return std::nullopt; }
}

inline bool encode_hardware_breakpoints(const std::vector<HardwareRequest>& requests,
                                        std::uint8_t pointer_size,
                                        DebugRegisters& registers) {
    if (requests.size() > 4 || (pointer_size != 4 && pointer_size != 8)) return false;
    registers = {};
    for (std::size_t slot = 0; slot < requests.size(); ++slot) {
        const auto& request = requests[slot];
        if (request.kind != BreakpointKind::execute && request.kind != BreakpointKind::read &&
            request.kind != BreakpointKind::write && request.kind != BreakpointKind::access) return false;
        // x86/x64 debug registers have write-only and read/write data modes,
        // but no read-only data mode. Do not encode a requested read watchpoint
        // as read/write and then report it back as read-only.
        if (request.kind == BreakpointKind::read) return false;
        if (request.kind == BreakpointKind::execute && request.size != 1) return false;
        if (request.size == 8 && pointer_size != 8) return false;
        const auto len = length_encoding(request.size);
        if (!len || (request.address & (request.size - 1)) != 0 ||
            (pointer_size == 4 && request.address > UINT32_MAX)) return false;
        std::uint64_t rw = 0;
        if (request.kind == BreakpointKind::write) rw = 1;
        if (request.kind == BreakpointKind::read || request.kind == BreakpointKind::access) rw = 3;
        registers.address[slot] = request.address;
        registers.dr7 |= std::uint64_t{1} << (slot * 2); // local enable
        registers.dr7 |= (rw | (static_cast<std::uint64_t>(*len) << 2)) << (16 + slot * 4);
    }
    return true;
}

inline std::vector<BreakpointId> hardware_breakpoint_hits(
    const std::vector<BreakpointId>& slot_ids, std::uint64_t dr6) {
    std::vector<BreakpointId> hits;
    const auto slots = std::min<std::size_t>(slot_ids.size(), 4);
    for (std::size_t slot = 0; slot < slots; ++slot)
        if ((dr6 & (std::uint64_t{1} << slot)) != 0) hits.push_back(slot_ids[slot]);
    return hits;
}
} // namespace hexlab::debugger::detail
