#pragma once

#include "hexlab/processors/instruction.hpp"

#include <cstdint>
#include <optional>

namespace hexlab {

// Evaluate a decoded A64 CSEL/CSINC/CSINV/CSNEG. For conditions 0..13,
// condition_met is resolved by the caller from NZCV; AL/NV always select Rn.
inline std::optional<std::uint64_t> evaluate_a64_conditional_select_instruction(
    const Instruction &instruction, std::uint64_t true_source,
    std::uint64_t false_source, bool condition_met) noexcept {
    const auto opcode = instruction.opcode;
    if ((opcode != Opcode::a64_csel && opcode != Opcode::a64_csinc &&
         opcode != Opcode::a64_csinv && opcode != Opcode::a64_csneg) ||
        instruction.context.architecture != Architecture::arm64 ||
        instruction.context.mode != ExecutionMode::a64 || instruction.operands.size() != 3 ||
        instruction.access.size() != 3 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read || instruction.access[2] != OperandAccess::read ||
        instruction.memory_read || instruction.memory_write || instruction.condition > 15)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *true_reg = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *false_reg = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto valid_register = [](const RegisterOperand *reg) {
        return reg && (reg->bank == RegisterBank::arm64_gpr || reg->bank == RegisterBank::arm64_zero) &&
               (reg->width == 32 || reg->width == 64) && !reg->high_byte;
    };
    if (!valid_register(destination) || !valid_register(true_reg) || !valid_register(false_reg) ||
        destination->width != true_reg->width || destination->width != false_reg->width)
        return std::nullopt;
    const unsigned width = destination->width;
    const auto mask = width == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    const auto lhs = true_reg->bank == RegisterBank::arm64_zero ? 0 : true_source & mask;
    const auto rhs = false_reg->bank == RegisterBank::arm64_zero ? 0 : false_source & mask;
    if (instruction.condition >= 14 || condition_met) return lhs;
    std::uint64_t result = rhs;
    if (opcode == Opcode::a64_csinc) result = (rhs + 1) & mask;
    else if (opcode == Opcode::a64_csinv) result = ~rhs & mask;
    else if (opcode == Opcode::a64_csneg) result = (UINT64_C(0) - rhs) & mask;
    return result & mask;
}

} // namespace hexlab
