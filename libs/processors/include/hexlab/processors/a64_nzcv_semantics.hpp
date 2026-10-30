#pragma once

#include "hexlab/processors/instruction.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>

namespace hexlab {

struct A64NzcvResult {
    std::uint64_t value = 0;
    bool n = false, z = false, c = false, v = false;
};

struct A64NzcvFlags {
    bool n = false, z = false, c = false, v = false;
    bool operator==(const A64NzcvFlags &) const = default;
};

inline std::optional<A64NzcvResult> evaluate_a64_nzcv_operation(
    Opcode opcode, unsigned width, std::uint64_t lhs, std::uint64_t rhs) noexcept;

struct A64AddSubImmediateResult {
    std::uint64_t value = 0;
    std::optional<A64NzcvFlags> flags;
    bool writes_destination = false;
    bool operator==(const A64AddSubImmediateResult &) const = default;
};

// Evaluate decoded A64 ADD/ADDS/SUB/SUBS immediate forms with GPR/ZR
// operands. SP-based forms are left to a separate address-state evaluator.
inline std::optional<A64AddSubImmediateResult> evaluate_a64_add_sub_immediate_instruction(
    const Instruction &instruction, std::uint64_t source) noexcept {
    const bool subtract = instruction.opcode == Opcode::a64_sub || instruction.opcode == Opcode::a64_subs;
    const bool set_flags = instruction.opcode == Opcode::a64_adds || instruction.opcode == Opcode::a64_subs;
    if ((!subtract && instruction.opcode != Opcode::a64_add && instruction.opcode != Opcode::a64_adds) ||
        instruction.context.architecture != Architecture::arm64 || instruction.context.mode != ExecutionMode::a64 ||
        instruction.length != 4 || instruction.flow != FlowKind::fallthrough || instruction.memory_read ||
        instruction.memory_write || instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
    const auto valid_gpr = [](const RegisterOperand *reg) {
        return reg && (reg->bank == RegisterBank::arm64_gpr || reg->bank == RegisterBank::arm64_zero) &&
               (reg->bank != RegisterBank::arm64_gpr || reg->index < 31) &&
               (reg->bank != RegisterBank::arm64_zero || reg->index == 31) &&
               (reg->width == 32 || reg->width == 64) && !reg->high_byte;
    };
    if (!valid_gpr(destination) || !valid_gpr(input) || destination->width != input->width || !immediate ||
        immediate->encoded_width != 12 || immediate->effective_width != destination->width ||
        immediate->is_signed || immediate->value > 0xffffffu)
        return std::nullopt;
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if ((input->bank != RegisterBank::arm64_zero && !has(instruction.register_reads, *input)) ||
        (destination->bank != RegisterBank::arm64_zero && !has(instruction.register_writes, *destination)))
        return std::nullopt;
    const RegisterOperand nzcv{RegisterBank::arm_flags, 0, 4, false};
    if (set_flags != has(instruction.register_writes, nzcv)) return std::nullopt;
    if (input->bank == RegisterBank::arm64_zero) source = 0;
    const auto operation = evaluate_a64_nzcv_operation(
        subtract ? Opcode::a64_subs : Opcode::a64_adds, destination->width, source, immediate->value);
    if (!operation) return std::nullopt;
    return A64AddSubImmediateResult{operation->value,
        set_flags ? std::optional<A64NzcvFlags>{A64NzcvFlags{operation->n, operation->z, operation->c, operation->v}}
                  : std::nullopt,
        destination->bank != RegisterBank::arm64_zero};
}

struct A64AddSubRegisterResult {
    std::uint64_t value = 0;
    std::optional<A64NzcvFlags> flags;
    bool writes_destination = false;
    bool operator==(const A64AddSubRegisterResult &) const = default;
};

// Evaluate decoded shifted-register ADD/ADDS/SUB/SUBS. The encoded word is
// rechecked so extended-register forms and malformed operand metadata fail
// closed. Register 31 follows the decoder's zero-register interpretation.
inline std::optional<A64AddSubRegisterResult> evaluate_a64_add_sub_register_instruction(
    const Instruction &instruction, std::uint64_t lhs, std::uint64_t rhs) noexcept {
    const bool subtract = instruction.opcode == Opcode::a64_sub || instruction.opcode == Opcode::a64_subs;
    const bool set_flags = instruction.opcode == Opcode::a64_adds || instruction.opcode == Opcode::a64_subs;
    if ((!subtract && instruction.opcode != Opcode::a64_add && instruction.opcode != Opcode::a64_adds) ||
        instruction.context.architecture != Architecture::arm64 || instruction.context.mode != ExecutionMode::a64 ||
        instruction.length != 4 || instruction.flow != FlowKind::fallthrough || instruction.memory_read ||
        instruction.memory_write)
        return std::nullopt;

    const auto bytes = instruction.encoded_bytes();
    if (bytes.size() != 4) return std::nullopt;
    std::uint32_t word = 0;
    for (unsigned i = 0; i < 4; ++i)
        word |= std::uint32_t(std::to_integer<std::uint8_t>(bytes[i])) << (i * 8);
    if ((word & 0x1f200000u) != 0x0b000000u) return std::nullopt; // Shifted-register form only.
    const unsigned width = (word >> 31) ? 64 : 32;
    const unsigned shift = (word >> 22) & 3;
    const unsigned amount = (word >> 10) & 63;
    const unsigned rd_index = word & 31, rn_index = (word >> 5) & 31, rm_index = (word >> 16) & 31;
    if (((word >> 30) & 1) != subtract || (((word >> 29) & 1) != set_flags) ||
        shift == 3 || amount >= width || instruction.operands.size() != (amount || shift ? 4u : 3u) ||
        instruction.access.size() != instruction.operands.size())
        return std::nullopt;

    const auto valid_gpr = [width](const Operand &operand, unsigned index, OperandAccess access) {
        const auto *reg = std::get_if<RegisterOperand>(&operand);
        const auto expected_bank = index == 31 ? RegisterBank::arm64_zero : RegisterBank::arm64_gpr;
        return reg && reg->bank == expected_bank && reg->index == index && reg->width == width &&
               !reg->high_byte && access != OperandAccess::read_write;
    };
    if (!valid_gpr(instruction.operands[0], rd_index, OperandAccess::write) ||
        instruction.access[0] != OperandAccess::write ||
        !valid_gpr(instruction.operands[1], rn_index, OperandAccess::read) ||
        instruction.access[1] != OperandAccess::read ||
        !valid_gpr(instruction.operands[2], rm_index, OperandAccess::read) ||
        instruction.access[2] != OperandAccess::read)
        return std::nullopt;
    if (instruction.operands.size() == 4) {
        const auto *encoded_amount = std::get_if<ImmediateOperand>(&instruction.operands[3]);
        if (!encoded_amount || encoded_amount->value != amount || encoded_amount->encoded_width != 6 ||
            encoded_amount->effective_width != width || encoded_amount->is_signed ||
            instruction.access[3] != OperandAccess::read)
            return std::nullopt;
    }

    const RegisterOperand rn{rn_index == 31 ? RegisterBank::arm64_zero : RegisterBank::arm64_gpr,
                             static_cast<std::uint8_t>(rn_index), static_cast<std::uint16_t>(width), false};
    const RegisterOperand rm{rm_index == 31 ? RegisterBank::arm64_zero : RegisterBank::arm64_gpr,
                             static_cast<std::uint8_t>(rm_index), static_cast<std::uint16_t>(width), false};
    const RegisterOperand rd{rd_index == 31 ? RegisterBank::arm64_zero : RegisterBank::arm64_gpr,
                             static_cast<std::uint8_t>(rd_index), static_cast<std::uint16_t>(width), false};
    const RegisterOperand nzcv{RegisterBank::arm_flags, 0, 4, false};
    const auto expected_reads = (rn_index != 31) + (rm_index != 31);
    if (instruction.register_reads.size() != expected_reads ||
        (rn_index != 31 && instruction.register_reads[0] != rn) ||
        (rm_index != 31 && instruction.register_reads[rn_index != 31 ? 1 : 0] != rm))
        return std::nullopt;
    const auto expected_writes = (rd_index != 31) + set_flags;
    if (instruction.register_writes.size() != expected_writes ||
        (rd_index != 31 && instruction.register_writes[0] != rd) ||
        (set_flags && instruction.register_writes[rd_index != 31 ? 1 : 0] != nzcv))
        return std::nullopt;

    const auto mask = width == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    rhs &= mask;
    if (amount) {
        if (shift == 0) rhs = (rhs << amount) & mask;
        else if (shift == 1) rhs >>= amount;
        else {
            const bool negative = (rhs & (UINT64_C(1) << (width - 1))) != 0;
            rhs >>= amount;
            if (negative) rhs |= (mask << (width - amount)) & mask;
        }
    }
    if (rn_index == 31) lhs = 0;
    if (rm_index == 31) rhs = 0;
    const auto operation = evaluate_a64_nzcv_operation(
        subtract ? Opcode::a64_subs : Opcode::a64_adds, width, lhs, rhs);
    if (!operation) return std::nullopt;
    return A64AddSubRegisterResult{operation->value,
        set_flags ? std::optional<A64NzcvFlags>{A64NzcvFlags{operation->n, operation->z, operation->c, operation->v}}
                  : std::nullopt,
        rd_index != 31};
}

// Evaluate the concrete result/NZCV of A64 ADDS, SUBS, or ANDS for W/X width.
// Operands are raw register bits; W results are returned zero-extended.
inline std::optional<A64NzcvResult> evaluate_a64_nzcv_operation(
    Opcode opcode, unsigned width, std::uint64_t lhs, std::uint64_t rhs) noexcept {
    if (width != 32 && width != 64) return std::nullopt;
    const auto mask = width == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    const auto sign = UINT64_C(1) << (width - 1);
    lhs &= mask;
    rhs &= mask;
    A64NzcvResult result{};
    if (opcode == Opcode::a64_adds) {
        result.value = (lhs + rhs) & mask;
        result.c = width == 32 ? ((lhs + rhs) >> 32) != 0 : result.value < lhs;
        result.v = ((~(lhs ^ rhs) & (lhs ^ result.value) & sign) != 0);
    } else if (opcode == Opcode::a64_subs) {
        result.value = (lhs - rhs) & mask;
        result.c = lhs >= rhs; // A64 C is the no-borrow result.
        result.v = (((lhs ^ rhs) & (lhs ^ result.value) & sign) != 0);
    } else if (opcode == Opcode::a64_ands) {
        result.value = lhs & rhs;
        // Logical flag-setting operations clear C and V.
    } else {
        return std::nullopt;
    }
    result.n = (result.value & sign) != 0;
    result.z = result.value == 0;
    return result;
}

// Evaluate decoded CCMP/CCMN. When the encoded condition is false, the
// fallback immediate supplies NZCV bits [3:0] in N/Z/C/V order.
inline std::optional<A64NzcvFlags> evaluate_a64_conditional_compare_instruction(
    const Instruction &instruction, std::uint64_t lhs, std::uint64_t rhs,
    A64NzcvFlags incoming) noexcept {
    const bool subtract = instruction.opcode == Opcode::a64_ccmp;
    if ((!subtract && instruction.opcode != Opcode::a64_ccmn) ||
        instruction.context.architecture != Architecture::arm64 || instruction.context.mode != ExecutionMode::a64 ||
        instruction.length != 4 || instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::read || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read || instruction.memory_read || instruction.memory_write ||
        instruction.condition > 15 || instruction.flow != FlowKind::fallthrough)
        return std::nullopt;
    const auto *left = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *right_register = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *right_immediate = std::get_if<ImmediateOperand>(&instruction.operands[1]);
    const auto *fallback = std::get_if<ImmediateOperand>(&instruction.operands[2]);
    const auto valid_gpr = [](const RegisterOperand *reg) {
        return reg && (reg->bank == RegisterBank::arm64_gpr || reg->bank == RegisterBank::arm64_zero) &&
               (reg->width == 32 || reg->width == 64) && !reg->high_byte;
    };
    if (!valid_gpr(left) || (!right_register && !right_immediate) || !fallback ||
        (right_register && (!valid_gpr(right_register) || right_register->width != left->width)) ||
        (right_immediate && (right_immediate->encoded_width != 5 || right_immediate->effective_width != left->width ||
                             right_immediate->is_signed || right_immediate->value > 31)) ||
        fallback->encoded_width != 4 || fallback->effective_width != 4 || fallback->is_signed ||
        fallback->value > 15)
        return std::nullopt;
    const auto has_gpr_read = [&](const RegisterOperand &reg) {
        return reg.bank == RegisterBank::arm64_zero ||
               std::find(instruction.register_reads.begin(), instruction.register_reads.end(), reg) !=
                   instruction.register_reads.end();
    };
    if (!has_gpr_read(*left) || (right_register && !has_gpr_read(*right_register)))
        return std::nullopt;
    const RegisterOperand nzcv{RegisterBank::arm_flags, 0, 4, false};
    if (std::find(instruction.register_writes.begin(), instruction.register_writes.end(), nzcv) ==
        instruction.register_writes.end())
        return std::nullopt;
    if (instruction.condition < 14 &&
        std::find(instruction.register_reads.begin(), instruction.register_reads.end(), nzcv) ==
            instruction.register_reads.end())
        return std::nullopt;
    if (left->bank == RegisterBank::arm64_zero) lhs = 0;
    if (right_register && right_register->bank == RegisterBank::arm64_zero) rhs = 0;

    const auto condition = [&]() {
        switch (instruction.condition) {
        case 0: return incoming.z;
        case 1: return !incoming.z;
        case 2: return incoming.c;
        case 3: return !incoming.c;
        case 4: return incoming.n;
        case 5: return !incoming.n;
        case 6: return incoming.v;
        case 7: return !incoming.v;
        case 8: return incoming.c && !incoming.z;
        case 9: return !incoming.c || incoming.z;
        case 10: return incoming.n == incoming.v;
        case 11: return incoming.n != incoming.v;
        case 12: return !incoming.z && incoming.n == incoming.v;
        case 13: return incoming.z || incoming.n != incoming.v;
        default: return true;
        }
    };
    if (!condition()) {
        const auto bits = static_cast<unsigned>(fallback->value);
        return A64NzcvFlags{(bits & 8) != 0, (bits & 4) != 0, (bits & 2) != 0, (bits & 1) != 0};
    }
    const auto operation = evaluate_a64_nzcv_operation(subtract ? Opcode::a64_subs : Opcode::a64_adds,
                                                       left->width, lhs, rhs);
    if (!operation) return std::nullopt;
    return A64NzcvFlags{operation->n, operation->z, operation->c, operation->v};
}

} // namespace hexlab
