#pragma once

#include "hexlab/processors/instruction.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <variant>

namespace hexlab {

struct A64WideMoveResult {
    std::uint64_t value = 0;
    bool writes_destination = false;
    bool operator==(const A64WideMoveResult &) const = default;
};

// Evaluate decoded W/X MOVN/MOVZ/MOVK. MOVK takes the old destination as an
// input; writes to the architectural zero register are reported as suppressed.
inline std::optional<A64WideMoveResult> evaluate_a64_wide_move_instruction(
    const Instruction &instruction, std::uint64_t prior_destination = 0) noexcept {
    if (instruction.context.architecture != Architecture::arm64 || instruction.context.mode != ExecutionMode::a64 ||
        instruction.flow != FlowKind::fallthrough || instruction.length != 4 || instruction.memory_read ||
        instruction.memory_write || (instruction.opcode != Opcode::a64_movn &&
        instruction.opcode != Opcode::a64_movz && instruction.opcode != Opcode::a64_movk) ||
        (instruction.operands.size() != 2 && instruction.operands.size() != 3) ||
        instruction.access.size() != instruction.operands.size())
        return std::nullopt;
    const bool keep = instruction.opcode == Opcode::a64_movk;
    if (instruction.access[0] != (keep ? OperandAccess::read_write : OperandAccess::write) ||
        instruction.access[1] != OperandAccess::read ||
        (instruction.operands.size() == 3 && instruction.access[2] != OperandAccess::read))
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[1]);
    if (!destination || (destination->bank != RegisterBank::arm64_gpr &&
                         destination->bank != RegisterBank::arm64_zero) ||
        (destination->bank == RegisterBank::arm64_gpr && destination->index >= 31) ||
        (destination->bank == RegisterBank::arm64_zero && destination->index != 31) ||
        (destination->width != 32 && destination->width != 64) || destination->high_byte || !immediate ||
        immediate->encoded_width != 16 || immediate->effective_width != destination->width ||
        immediate->is_signed || immediate->value > UINT16_MAX)
        return std::nullopt;
    unsigned shift = 0;
    if (instruction.operands.size() == 3) {
        const auto *shift_immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
        if (!shift_immediate || shift_immediate->encoded_width != 2 || shift_immediate->effective_width != 8 ||
            shift_immediate->is_signed || shift_immediate->value == 0 ||
            shift_immediate->value > (destination->width == 32 ? 16u : 48u) ||
            (shift_immediate->value & 15u))
            return std::nullopt;
        shift = static_cast<unsigned>(shift_immediate->value);
    }
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (destination->bank == RegisterBank::arm64_gpr &&
        (!has(instruction.register_writes, *destination) || (keep && !has(instruction.register_reads, *destination))))
        return std::nullopt;
    const auto mask = destination->width == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    const auto field_mask = UINT64_C(0xffff) << shift;
    const auto field_value = (immediate->value << shift) & mask;
    std::uint64_t value = field_value;
    if (instruction.opcode == Opcode::a64_movn) value = ~field_value & mask;
    else if (keep) value = ((prior_destination & mask) & ~field_mask) | field_value;
    return A64WideMoveResult{value & mask, destination->bank != RegisterBank::arm64_zero};
}

} // namespace hexlab
