#pragma once

#include "hexlab/processors/instruction.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>

namespace hexlab {

using A64SimdBits = std::array<std::uint8_t, 16>;

struct A64SimdIntegerResult {
    A64SimdBits value{};
    std::uint16_t vector_bits = 0;
    bool operator==(const A64SimdIntegerResult &) const = default;
};

// Vector bytes are indexed by increasing bit significance (byte 0 is bits 7:0
// of Vn). Evaluate the decoded three-register wrapping add/sub and logical set.
inline std::optional<A64SimdIntegerResult> evaluate_a64_simd_integer_instruction(
    const Instruction &instruction, const A64SimdBits &lhs,
    const A64SimdBits &rhs) noexcept {
    if (instruction.context.architecture != Architecture::arm64 ||
        instruction.context.mode != ExecutionMode::a64 ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots != 0 ||
        instruction.memory_read || instruction.memory_write ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read)
        return std::nullopt;
    const bool add = instruction.opcode == Opcode::a64_vadd;
    const bool subtract = instruction.opcode == Opcode::a64_vsub;
    const bool logical = instruction.opcode == Opcode::a64_vand ||
                         instruction.opcode == Opcode::a64_vorr ||
                         instruction.opcode == Opcode::a64_veor;
    if (!add && !subtract && !logical) return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *left = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *right = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto vector_bits = instruction.vector_bits;
    const auto element_bits = instruction.vector_element_bits;
    if (!destination || !left || !right || (vector_bits != 64 && vector_bits != 128) ||
        destination->bank != RegisterBank::arm64_simd || left->bank != RegisterBank::arm64_simd ||
        right->bank != RegisterBank::arm64_simd || destination->width != vector_bits ||
        left->width != vector_bits || right->width != vector_bits || destination->index >= 32 ||
        left->index >= 32 || right->index >= 32 || destination->high_byte || left->high_byte ||
        right->high_byte || (logical && element_bits != 8) ||
        ((add || subtract) && (element_bits != 8 && element_bits != 16 &&
                               element_bits != 32 && element_bits != 64)) ||
        element_bits == 0 || vector_bits % element_bits != 0 ||
        (vector_bits == 64 && element_bits == 64))
        return std::nullopt;
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_reads, *left) || !has(instruction.register_reads, *right) ||
        !has(instruction.register_writes, *destination))
        return std::nullopt;
    if (vector_bits == 64 && !has(instruction.register_writes,
                                  RegisterOperand{RegisterBank::arm64_simd, destination->index, 128, false}))
        return std::nullopt;

    A64SimdIntegerResult result{};
    result.vector_bits = vector_bits;
    const unsigned active_bytes = vector_bits / 8;
    if (logical) {
        for (unsigned byte = 0; byte < active_bytes; ++byte) {
            if (instruction.opcode == Opcode::a64_vand) result.value[byte] = lhs[byte] & rhs[byte];
            else if (instruction.opcode == Opcode::a64_vorr) result.value[byte] = lhs[byte] | rhs[byte];
            else result.value[byte] = lhs[byte] ^ rhs[byte];
        }
        return result;
    }

    const unsigned lane_bytes = element_bits / 8;
    const unsigned lane_count = vector_bits / element_bits;
    const std::uint64_t lane_mask = element_bits == 64 ? UINT64_MAX :
        (UINT64_C(1) << element_bits) - 1;
    for (unsigned lane = 0; lane < lane_count; ++lane) {
        const unsigned start = lane * lane_bytes;
        std::uint64_t a = 0, b = 0;
        for (unsigned byte = 0; byte < lane_bytes; ++byte) {
            a |= std::uint64_t(lhs[start + byte]) << (byte * 8);
            b |= std::uint64_t(rhs[start + byte]) << (byte * 8);
        }
        const auto value = (add ? a + b : a - b) & lane_mask;
        for (unsigned byte = 0; byte < lane_bytes; ++byte)
            result.value[start + byte] = static_cast<std::uint8_t>(value >> (byte * 8));
    }
    return result;
}

} // namespace hexlab
