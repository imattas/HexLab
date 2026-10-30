#pragma once

#include "hexlab/processors/instruction.hpp"

#include <algorithm>
#include <bit>
#include <cstdint>
#include <optional>

namespace hexlab {

// Evaluate decoded A64 UDIV/SDIV from caller-supplied W/X operands. Divide by
// zero returns zero; signed minimum divided by -1 wraps to the minimum value.
inline std::optional<std::uint64_t> evaluate_a64_divide_instruction(
    const Instruction &instruction, std::uint64_t lhs_bits,
    std::uint64_t rhs_bits) noexcept {
    const bool signed_divide = instruction.opcode == Opcode::a64_sdiv;
    if ((!signed_divide && instruction.opcode != Opcode::a64_udiv) ||
        instruction.context.architecture != Architecture::arm64 ||
        instruction.context.mode != ExecutionMode::a64 || instruction.operands.size() != 3 ||
        instruction.access.size() != 3 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read || instruction.access[2] != OperandAccess::read ||
        instruction.memory_read || instruction.memory_write)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *lhs = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *rhs = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto valid = [](const RegisterOperand *reg) {
        return reg && (reg->bank == RegisterBank::arm64_gpr || reg->bank == RegisterBank::arm64_zero) &&
               (reg->width == 32 || reg->width == 64) && !reg->high_byte;
    };
    if (!valid(destination) || !valid(lhs) || !valid(rhs) || destination->width != lhs->width ||
        destination->width != rhs->width)
        return std::nullopt;
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if ((lhs->bank != RegisterBank::arm64_zero && !has(instruction.register_reads, *lhs)) ||
        (rhs->bank != RegisterBank::arm64_zero && !has(instruction.register_reads, *rhs)) ||
        (destination->bank != RegisterBank::arm64_zero &&
         !has(instruction.register_writes, *destination)))
        return std::nullopt;
    const unsigned width = destination->width;
    const auto mask = width == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    const auto lhs_value = lhs->bank == RegisterBank::arm64_zero ? 0 : lhs_bits & mask;
    const auto rhs_value = rhs->bank == RegisterBank::arm64_zero ? 0 : rhs_bits & mask;
    if (rhs_value == 0) return UINT64_C(0);
    if (!signed_divide) return (lhs_value / rhs_value) & mask;
    if (width == 32) {
        const auto dividend = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(lhs_value));
        const auto divisor = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(rhs_value));
        if (dividend == INT32_MIN && divisor == -1) return lhs_value;
        return static_cast<std::uint32_t>(dividend / divisor);
    }
    const auto dividend = std::bit_cast<std::int64_t>(lhs_value);
    const auto divisor = std::bit_cast<std::int64_t>(rhs_value);
    if (dividend == INT64_MIN && divisor == -1) return lhs_value;
    return std::bit_cast<std::uint64_t>(dividend / divisor);
}

} // namespace hexlab
