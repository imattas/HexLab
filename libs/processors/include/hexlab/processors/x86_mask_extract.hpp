#pragma once

#include "hexlab/processors/instruction.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace hexlab {

// Evaluates the sign-bit mask produced by legacy/VEX MOVMSKPS, MOVMSKPD, or
// PMOVMSKB. The source span is in architectural byte order (byte zero is least
// significant); memory reads and GPR writes remain caller-owned.
inline std::optional<std::uint32_t> evaluate_x86_mask_extract(
    const Instruction &instruction, std::span<const std::byte> source) noexcept {
    if (instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *vector = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if (!destination || !vector || destination->bank != RegisterBank::gpr ||
        destination->width != 32 || vector->high_byte ||
        (instruction.context.architecture != Architecture::x86 &&
         instruction.context.architecture != Architecture::x86_64) ||
        (instruction.context.mode != ExecutionMode::x86_16 &&
         instruction.context.mode != ExecutionMode::x86_32 &&
         instruction.context.mode != ExecutionMode::x86_64))
        return std::nullopt;

    unsigned lane_bits = 0;
    bool vex = false;
    switch (instruction.opcode) {
    case Opcode::movmskps: lane_bits = 32; break;
    case Opcode::movmskpd: lane_bits = 64; break;
    case Opcode::pmovmskb: lane_bits = 8; break;
    case Opcode::vmovmskps: lane_bits = 32; vex = true; break;
    case Opcode::vmovmskpd: lane_bits = 64; vex = true; break;
    case Opcode::vpmovmskb: lane_bits = 8; vex = true; break;
    default: return std::nullopt;
    }
    const auto vector_width = instruction.vector_bits;
    if ((vector_width != 128 && (vector_width != 256 || !vex)) ||
        (vector_width == 256 && instruction.context.mode != ExecutionMode::x86_64) ||
        instruction.vector_element_bits != lane_bits || vector->width != vector_width ||
        vector->bank != (vector_width == 128 ? RegisterBank::xmm : RegisterBank::ymm) ||
        vector->index >= (instruction.context.mode == ExecutionMode::x86_64 ? 16 : 8) ||
        destination->index >= (instruction.context.mode == ExecutionMode::x86_64 ? 16 : 8) ||
        source.size() != vector_width / 8)
        return std::nullopt;
    if (vex && (instruction.context.mode != ExecutionMode::x86_64 ||
                instruction.context.architecture != Architecture::x86_64))
        return std::nullopt;
    if (std::find(instruction.register_writes.begin(), instruction.register_writes.end(), *destination) ==
            instruction.register_writes.end() ||
        std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *vector) ==
            instruction.register_reads.end())
        return std::nullopt;

    std::uint32_t result = 0;
    const auto lane_count = static_cast<unsigned>(vector_width) / lane_bits;
    for (unsigned lane = 0; lane < lane_count; ++lane) {
        const auto sign_byte = lane * (lane_bits / 8) + lane_bits / 8 - 1;
        if ((std::to_integer<std::uint8_t>(source[sign_byte]) & 0x80u) != 0)
            result |= std::uint32_t{1} << lane;
    }
    return result;
}

} // namespace hexlab
