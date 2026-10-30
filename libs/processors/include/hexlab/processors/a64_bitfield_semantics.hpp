#pragma once

#include "hexlab/processors/instruction.hpp"

#include <cstdint>
#include <optional>

namespace hexlab {
namespace a64_bitfield_detail {
inline std::uint64_t mask(unsigned bits) noexcept {
    return bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
}

inline std::uint64_t rotate_right(std::uint64_t value, unsigned amount, unsigned width) noexcept {
    const auto width_mask = mask(width);
    value &= width_mask;
    amount %= width;
    return amount ? ((value >> amount) | (value << (width - amount))) & width_mask : value;
}
} // namespace a64_bitfield_detail

// Evaluate one decoded A64 UBFM/SBFM/BFM from caller-supplied source and prior
// destination values. Inputs are W- or X-register bit patterns; W results are
// returned zero-extended. XZR/WZR reads are represented by a supplied zero.
inline std::optional<std::uint64_t> evaluate_a64_bitfield_instruction(
    const Instruction &instruction, std::uint64_t source,
    std::uint64_t prior_destination = 0) noexcept {
    using namespace a64_bitfield_detail;
    const auto opcode = instruction.opcode;
    const bool insert = opcode == Opcode::a64_bfm;
    if ((!insert && opcode != Opcode::a64_ubfm && opcode != Opcode::a64_sbfm) ||
        instruction.operands.size() != 4 || instruction.access.size() != 4 ||
        instruction.access[0] != (insert ? OperandAccess::read_write : OperandAccess::write) ||
        instruction.access[1] != OperandAccess::read || instruction.access[2] != OperandAccess::read ||
        instruction.access[3] != OperandAccess::read || instruction.memory_read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *source_reg = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *immr = std::get_if<ImmediateOperand>(&instruction.operands[2]);
    const auto *imms = std::get_if<ImmediateOperand>(&instruction.operands[3]);
    if (!destination || !source_reg || !immr || !imms ||
        (destination->bank != RegisterBank::arm64_gpr && destination->bank != RegisterBank::arm64_zero) ||
        (source_reg->bank != RegisterBank::arm64_gpr && source_reg->bank != RegisterBank::arm64_zero) ||
        destination->width != source_reg->width || (destination->width != 32 && destination->width != 64) ||
        immr->effective_width != destination->width || imms->effective_width != destination->width ||
        immr->value >= destination->width || imms->value >= destination->width)
        return {};

    const unsigned width = destination->width;
    const unsigned rotate = static_cast<unsigned>(immr->value);
    const unsigned top_bit = static_cast<unsigned>(imms->value);
    const unsigned bottom_width = ((top_bit - rotate) & (width - 1)) + 1;
    const auto write_mask = rotate_right(mask(top_bit + 1), rotate, width);
    const auto rotated = rotate_right(source, rotate, width);
    std::uint64_t result = 0;
    if (insert) {
        const auto prior = destination->bank == RegisterBank::arm64_zero ? 0 : prior_destination;
        result = (prior & ~write_mask) | (rotated & write_mask);
    } else {
        const auto bottom_mask = mask(bottom_width);
        const auto bottom = rotated & write_mask & bottom_mask;
        if (opcode == Opcode::a64_sbfm && (bottom & (UINT64_C(1) << (bottom_width - 1))))
            result = (mask(width) & ~bottom_mask) | bottom;
        else
            result = bottom;
    }
    return result & mask(width);
}
} // namespace hexlab
