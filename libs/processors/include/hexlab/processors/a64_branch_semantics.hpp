#pragma once

#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/a64_nzcv_semantics.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>

namespace hexlab {

// Evaluate decoded A64 B.cond using caller-supplied NZCV. AL/NV are not
// conditional-flow instructions in the decoder and are therefore rejected.
inline std::optional<bool> evaluate_a64_conditional_branch_instruction(
    const Instruction &instruction, A64NzcvFlags flags) noexcept {
    if (instruction.opcode != Opcode::a64_b_cond ||
        instruction.context.architecture != Architecture::arm64 || instruction.context.mode != ExecutionMode::a64 ||
        instruction.length != 4 || instruction.flow != FlowKind::conditional_branch ||
        instruction.condition >= 14 || !instruction.direct_target || instruction.operands.size() != 1 ||
        instruction.access.size() != 1 || instruction.access[0] != OperandAccess::read ||
        !std::holds_alternative<RelativeOperand>(instruction.operands[0]) ||
        instruction.memory_read || instruction.memory_write)
        return std::nullopt;
    const RegisterOperand nzcv{RegisterBank::arm_flags, 0, 4, false};
    if (std::find(instruction.register_reads.begin(), instruction.register_reads.end(), nzcv) ==
        instruction.register_reads.end())
        return std::nullopt;
    switch (instruction.condition) {
    case 0: return flags.z;
    case 1: return !flags.z;
    case 2: return flags.c;
    case 3: return !flags.c;
    case 4: return flags.n;
    case 5: return !flags.n;
    case 6: return flags.v;
    case 7: return !flags.v;
    case 8: return flags.c && !flags.z;
    case 9: return !flags.c || flags.z;
    case 10: return flags.n == flags.v;
    case 11: return flags.n != flags.v;
    case 12: return !flags.z && flags.n == flags.v;
    case 13: return flags.z || flags.n != flags.v;
    default: return std::nullopt;
    }
}

// Evaluate decoded A64 CBZ/CBNZ/TBZ/TBNZ predicates from the tested GPR.
inline std::optional<bool> evaluate_a64_test_branch_instruction(
    const Instruction &instruction, std::uint64_t source) noexcept {
    const bool zero_test = instruction.opcode == Opcode::a64_cbz || instruction.opcode == Opcode::a64_cbnz;
    const bool bit_test = instruction.opcode == Opcode::a64_tbz || instruction.opcode == Opcode::a64_tbnz;
    if ((!zero_test && !bit_test) || instruction.context.architecture != Architecture::arm64 ||
        instruction.context.mode != ExecutionMode::a64 || instruction.length != 4 ||
        instruction.flow != FlowKind::conditional_branch || !instruction.direct_target ||
        instruction.memory_read || instruction.memory_write ||
        instruction.operands.size() != (zero_test ? 2u : 3u) ||
        instruction.access.size() != instruction.operands.size())
        return std::nullopt;
    for (const auto access : instruction.access)
        if (access != OperandAccess::read) return std::nullopt;
    const auto *tested = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto valid_register = [](const RegisterOperand *reg) {
        return reg && (reg->bank == RegisterBank::arm64_gpr || reg->bank == RegisterBank::arm64_zero) &&
               (reg->width == 32 || reg->width == 64) && !reg->high_byte;
    };
    if (!valid_register(tested)) return std::nullopt;
    if (bit_test) {
        const auto *bit = std::get_if<ImmediateOperand>(&instruction.operands[1]);
        if (!bit || bit->encoded_width != 6 || bit->effective_width != 6 || bit->is_signed ||
            bit->value >= tested->width)
            return std::nullopt;
    }
    const auto target_index = zero_test ? 1u : 2u;
    if (!std::holds_alternative<RelativeOperand>(instruction.operands[target_index]))
        return std::nullopt;
    if (tested->bank == RegisterBank::arm64_gpr &&
        std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *tested) ==
            instruction.register_reads.end())
        return std::nullopt;
    const auto mask = tested->width == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    if (tested->bank == RegisterBank::arm64_zero) source = 0;
    source &= mask;
    if (zero_test)
        return instruction.opcode == Opcode::a64_cbz ? source == 0 : source != 0;
    const auto bit = std::get<ImmediateOperand>(instruction.operands[1]).value;
    const bool is_set = ((source >> bit) & 1u) != 0;
    return instruction.opcode == Opcode::a64_tbnz ? is_set : !is_set;
}

} // namespace hexlab
