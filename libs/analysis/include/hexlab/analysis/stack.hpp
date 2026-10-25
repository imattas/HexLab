#pragma once

#include "hexlab/analysis/analysis_export.hpp"
#include "hexlab/analysis/functions.hpp"

#include <cstdint>
#include <optional>

namespace hexlab {

struct StackSlotAccess {
    Address instruction;
    bool read = false;
    bool written = false;
    bool address_taken = false;
    bool operator==(const StackSlotAccess &) const = default;
};

// A conservative local/argument slot inferred from a direct stack-relative
// memory operand. Offsets are measured from the stack pointer at function
// entry; this makes frame-pointer and stack-pointer references comparable.
struct StackSlot {
    std::int64_t offset_from_entry_sp = 0;
    std::uint16_t width = 0;
    bool read = false;
    bool written = false;
    std::vector<Address> accesses;
    bool address_taken = false;
    // Per-instruction access semantics. `accesses` remains the compact unique
    // location list used by existing consumers; this records which locations
    // read, write, or take the slot's address.
    std::vector<StackSlotAccess> access_details;
    bool operator==(const StackSlot &) const = default;
};

struct StackFrameAnalysis {
    std::vector<StackSlot> slots;
    // Exact high-water stack allocation from entry SP, when every reachable
    // stack-depth path is known. A value of zero is a proven frameless body;
    // nullopt means the recovered flow cannot establish a complete extent.
    std::optional<std::uint64_t> maximum_stack_allocation_bytes;
    // False when the function is incomplete or a stack-relative access could
    // not be assigned a unique offset across its incoming control-flow paths.
    bool complete = true;
};

HEXLAB_ANALYSIS_EXPORT Result<StackFrameAnalysis>
analyze_stack_frame(const FunctionRecord &, const FunctionSnapshot &, std::stop_token);

} // namespace hexlab
