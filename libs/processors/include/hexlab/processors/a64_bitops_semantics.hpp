#pragma once

#include "hexlab/processors/instruction.hpp"

#include <algorithm>
#include <bit>
#include <cstdint>
#include <optional>

namespace hexlab {

// Evaluate decoded A64 RBIT, REV16, REV32, REV, CLZ, or CLS in a W/X form.
inline std::optional<std::uint64_t> evaluate_a64_bit_operation_instruction(
    const Instruction &instruction, std::uint64_t source) noexcept {
    const auto opcode = instruction.opcode;
    if ((opcode != Opcode::a64_rbit && opcode != Opcode::a64_rev16 &&
         opcode != Opcode::a64_rev32 && opcode != Opcode::a64_rev &&
         opcode != Opcode::a64_clz && opcode != Opcode::a64_cls) ||
        instruction.context.architecture != Architecture::arm64 ||
        instruction.context.mode != ExecutionMode::a64 || instruction.operands.size() != 2 ||
        instruction.access.size() != 2 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read || instruction.memory_read || instruction.memory_write)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto valid = [](const RegisterOperand *reg) {
        return reg && (reg->bank == RegisterBank::arm64_gpr || reg->bank == RegisterBank::arm64_zero) &&
               (reg->width == 32 || reg->width == 64) && !reg->high_byte;
    };
    if (!valid(destination) || !valid(input) || destination->width != input->width ||
        (opcode == Opcode::a64_rev32 && destination->width != 64))
        return std::nullopt;
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if ((destination->bank != RegisterBank::arm64_zero &&
         !has(instruction.register_writes, *destination)) ||
        (input->bank != RegisterBank::arm64_zero && !has(instruction.register_reads, *input)))
        return std::nullopt;
    const unsigned width = input->width;
    const auto mask = width == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    source = input->bank == RegisterBank::arm64_zero ? 0 : source & mask;
    if (opcode == Opcode::a64_clz || opcode == Opcode::a64_cls) {
        if (width == 32) {
            const auto value = static_cast<std::uint32_t>(source);
            if (opcode == Opcode::a64_clz) return std::countl_zero(value);
            return (value & UINT32_C(0x80000000)) ? std::countl_one(value) - 1u
                                                   : std::countl_zero(value) - 1u;
        }
        if (opcode == Opcode::a64_clz) return std::countl_zero(source);
        return (source & (UINT64_C(1) << 63)) ? std::countl_one(source) - 1u
                                               : std::countl_zero(source) - 1u;
    }
    std::uint64_t result = 0;
    if (opcode == Opcode::a64_rbit) {
        for (unsigned bit = 0; bit < width; ++bit)
            if (source & (UINT64_C(1) << bit)) result |= UINT64_C(1) << (width - bit - 1);
    } else {
        const unsigned group_bytes = opcode == Opcode::a64_rev16 ? 2u :
            opcode == Opcode::a64_rev32 ? 4u : width / 8;
        for (unsigned byte = 0; byte < width / 8; ++byte) {
            const unsigned group_start = (byte / group_bytes) * group_bytes;
            const unsigned source_byte = group_start + group_bytes - byte % group_bytes - 1;
            result |= ((source >> (source_byte * 8)) & 0xffu) << (byte * 8);
        }
    }
    return result & mask;
}

} // namespace hexlab
