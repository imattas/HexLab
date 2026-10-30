#pragma once

#include "hexlab/processors/instruction.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace hexlab {

struct X86AlignRightResult {
    std::array<std::byte, 32> bytes{};
    std::uint16_t vector_bits = 0;
    bool zeroed_upper_128 = false;
    bool operator==(const X86AlignRightResult &) const = default;
};

namespace x86_alignr_detail {
inline const ImmediateOperand *shift_operand(const Instruction &instruction,
                                             std::size_t position) noexcept {
    if (instruction.operands.size() <= position)
        return nullptr;
    const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[position]);
    if (!immediate || immediate->encoded_width != 8 || immediate->effective_width != 8 ||
        immediate->is_signed || immediate->value > 0xff)
        return nullptr;
    return immediate;
}

template <std::size_t Width>
inline void align_lane(const std::array<std::byte, Width> &high,
                       const std::array<std::byte, Width> &low,
                       std::array<std::byte, Width> &output,
                       unsigned base, unsigned shift) noexcept {
    for (unsigned byte = 0; byte < 16; ++byte) {
        const auto selected = byte + shift;
        if (selected < 16)
            output[base + byte] = low[base + selected];
        else if (selected < 32)
            output[base + byte] = high[base + selected - 16];
    }
}

inline bool valid_vector(const Operand &operand, RegisterBank bank, unsigned width) noexcept {
    if (const auto *reg = std::get_if<RegisterOperand>(&operand))
        return reg->bank == bank && reg->width == width && !reg->high_byte;
    if (const auto *memory = std::get_if<MemoryOperand>(&operand))
        return memory->data_width == width;
    return false;
}
} // namespace x86_alignr_detail

// The first input is the old destination (the high 128 bits of the 256-bit
// concatenation); the second is the ModRM source (the low 128 bits).
inline std::optional<X86AlignRightResult> evaluate_x86_palignr(
    const Instruction &instruction, const std::array<std::byte, 16> &old_destination,
    const std::array<std::byte, 16> &source) noexcept {
    using namespace x86_alignr_detail;
    const auto *shift = shift_operand(instruction, 2);
    const auto *destination = instruction.operands.empty()
        ? nullptr : std::get_if<RegisterOperand>(&instruction.operands[0]);
    if (instruction.opcode != Opcode::palignr ||
        (instruction.context.architecture != Architecture::x86 &&
         instruction.context.architecture != Architecture::x86_64) ||
        (instruction.context.mode != ExecutionMode::x86_16 &&
         instruction.context.mode != ExecutionMode::x86_32 &&
         instruction.context.mode != ExecutionMode::x86_64) ||
        instruction.operands.size() != 3 || !shift || !destination ||
        destination->bank != RegisterBank::xmm || destination->width != 128 ||
        destination->high_byte || !valid_vector(instruction.operands[1], RegisterBank::xmm, 128) ||
        instruction.vector_bits != 128 || instruction.flow != FlowKind::fallthrough ||
        (instruction.vector_element_bits && instruction.vector_element_bits != 8) ||
        instruction.access.size() != 3 || instruction.access[0] != OperandAccess::read_write ||
        instruction.access[1] != OperandAccess::read || instruction.access[2] != OperandAccess::read ||
        instruction.memory_write || instruction.lock_prefix)
        return std::nullopt;
    X86AlignRightResult result{};
    result.vector_bits = 128;
    std::array<std::byte, 16> output{};
    align_lane(old_destination, source, output, 0, static_cast<unsigned>(shift->value));
    std::copy(output.begin(), output.end(), result.bytes.begin());
    return result;
}

// VEX source1 supplies the high half and source2 the low half. L=1 repeats
// independently in both 128-bit lanes; L=0 clears the upper YMM half.
inline std::optional<X86AlignRightResult> evaluate_x86_vpalignr(
    const Instruction &instruction, const std::array<std::byte, 32> &source1,
    const std::array<std::byte, 32> &source2) noexcept {
    using namespace x86_alignr_detail;
    const auto *shift = shift_operand(instruction, 3);
    const auto *destination = instruction.operands.empty()
        ? nullptr : std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *source1_register = instruction.operands.size() < 2
        ? nullptr : std::get_if<RegisterOperand>(&instruction.operands[1]);
    if (instruction.opcode != Opcode::vpalignr ||
        instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 ||
        instruction.operands.size() != 4 || !shift || !destination ||
        (destination->bank != RegisterBank::xmm && destination->bank != RegisterBank::ymm) ||
        (destination->width != 128 && destination->width != 256) || destination->high_byte ||
        instruction.vector_bits != destination->width ||
        !source1_register || source1_register->bank != destination->bank ||
        source1_register->width != destination->width || source1_register->high_byte ||
        !valid_vector(instruction.operands[2], destination->bank, destination->width) ||
        (instruction.vector_element_bits && instruction.vector_element_bits != 8) ||
        instruction.flow != FlowKind::fallthrough || instruction.x86_evex ||
        instruction.x86_opmask || instruction.x86_opmask_zeroing ||
        instruction.access.size() != 4 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read || instruction.access[2] != OperandAccess::read ||
        instruction.access[3] != OperandAccess::read || instruction.memory_write || instruction.lock_prefix)
        return std::nullopt;
    X86AlignRightResult result{};
    result.vector_bits = destination->width;
    if (destination->width == 128) {
        result.zeroed_upper_128 = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
            [&](RegisterOperand reg) {
                return reg.bank == RegisterBank::ymm && reg.width == 256 && reg.index == destination->index;
            });
        if (!result.zeroed_upper_128)
            return std::nullopt;
    }
    const auto bytes = static_cast<unsigned>(destination->width / 8);
    for (unsigned base = 0; base < bytes; base += 16)
        align_lane(source1, source2, result.bytes, base, static_cast<unsigned>(shift->value));
    return result;
}

} // namespace hexlab
