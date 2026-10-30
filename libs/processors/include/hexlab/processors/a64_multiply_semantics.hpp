#pragma once

#include "hexlab/processors/instruction.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>

namespace hexlab {

// Evaluate decoded A64 W/X MADD or MSUB. Operand values are in decoder order:
// Rn, Rm, Ra. Arithmetic wraps at the selected width; W results are zero-extended.
inline std::optional<std::uint64_t> evaluate_a64_multiply_accumulate_instruction(
    const Instruction &instruction, std::uint64_t rn_value,
    std::uint64_t rm_value, std::uint64_t ra_value) noexcept {
    const bool subtract = instruction.opcode == Opcode::a64_msub;
    if ((!subtract && instruction.opcode != Opcode::a64_madd) ||
        instruction.context.architecture != Architecture::arm64 ||
        instruction.context.mode != ExecutionMode::a64 || instruction.operands.size() != 4 ||
        instruction.access.size() != 4 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read || instruction.access[2] != OperandAccess::read ||
        instruction.access[3] != OperandAccess::read || instruction.memory_read || instruction.memory_write)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *rn = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *rm = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto *ra = std::get_if<RegisterOperand>(&instruction.operands[3]);
    const auto valid = [](const RegisterOperand *reg) {
        return reg && (reg->bank == RegisterBank::arm64_gpr || reg->bank == RegisterBank::arm64_zero) &&
               (reg->width == 32 || reg->width == 64) && !reg->high_byte;
    };
    if (!valid(destination) || !valid(rn) || !valid(rm) || !valid(ra) ||
        destination->width != rn->width || destination->width != rm->width || destination->width != ra->width)
        return std::nullopt;
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if ((rn->bank != RegisterBank::arm64_zero && !has(instruction.register_reads, *rn)) ||
        (rm->bank != RegisterBank::arm64_zero && !has(instruction.register_reads, *rm)) ||
        (ra->bank != RegisterBank::arm64_zero && !has(instruction.register_reads, *ra)) ||
        (destination->bank != RegisterBank::arm64_zero &&
         !has(instruction.register_writes, *destination)))
        return std::nullopt;
    const auto mask = destination->width == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    const auto rn_bits = rn->bank == RegisterBank::arm64_zero ? 0 : rn_value & mask;
    const auto rm_bits = rm->bank == RegisterBank::arm64_zero ? 0 : rm_value & mask;
    const auto ra_bits = ra->bank == RegisterBank::arm64_zero ? 0 : ra_value & mask;
    const auto product = rn_bits * rm_bits;
    return (subtract ? ra_bits - product : product + ra_bits) & mask;
}

} // namespace hexlab
