#pragma once

#include <cstdint>
#include <optional>

#include "hexlab/processors/instruction.hpp"

namespace hexlab {

// Intel CRC32 is reflected CRC-32C (Castagnoli), with a raw caller-owned
// seed and no implicit initial/final complement. Consume low source bytes
// first. The returned CRC is always 32 bits, even for an r64 destination.
inline std::optional<std::uint32_t> evaluate_x86_crc32c(
    std::uint32_t seed, std::uint64_t source, std::uint16_t source_bits) noexcept {
    if (source_bits != 8 && source_bits != 16 && source_bits != 32 && source_bits != 64)
        return {};
    auto crc = seed;
    for (unsigned byte = 0; byte < source_bits / 8; ++byte) {
        crc ^= static_cast<std::uint8_t>(source >> (8 * byte));
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ ((crc & 1) ? UINT32_C(0x82f63b78) : 0);
    }
    return crc;
}

// Validate the scalar decoder's CRC32 operand contract before applying the
// polynomial helper. `source` is the already sampled register or memory value.
inline std::optional<std::uint32_t> evaluate_x86_crc32c_instruction(
    const Instruction &instruction, std::uint32_t seed, std::uint64_t source) noexcept {
    if (instruction.opcode != Opcode::crc32 || instruction.operands.size() != 2 ||
        instruction.access.size() != 2 || instruction.access[0] != OperandAccess::read_write ||
        instruction.access[1] != OperandAccess::read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    if (!destination || destination->bank != RegisterBank::gpr ||
        (destination->width != 32 && destination->width != 64) || destination->high_byte)
        return {};
    std::uint16_t source_width = 0;
    if (const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[1])) {
        if (reg->bank != RegisterBank::gpr || (reg->high_byte && reg->width != 8)) return {};
        source_width = reg->width;
    } else if (const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1])) {
        source_width = memory->data_width;
        if (!instruction.memory_read) return {};
    } else {
        return {};
    }
    if (source_width != 8 && source_width != 16 && source_width != 32 && source_width != 64)
        return {};
    return evaluate_x86_crc32c(seed, source, source_width);
}

} // namespace hexlab
