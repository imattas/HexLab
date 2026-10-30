#pragma once

#include "hexlab/processors/instruction.hpp"

#include <array>
#include <cstdint>
#include <optional>

namespace hexlab {

struct X86SseScalarCompareResult {
    std::uint64_t eflags_after = 0;
    std::uint32_t mxcsr_after = 0x1f80;
    bool invalid_operation = false;
    bool denormal_operand = false;
    // An unmasked MXCSR exception suppresses EFLAGS retirement.
    bool completed = true;
    bool operator==(const X86SseScalarCompareResult &) const = default;
};

// Evaluate COMISS/UCOMISS from binary32 bit patterns. The caller supplies
// register or memory values and owns memory faults, CPU feature checks, and
// exception delivery. MXCSR sticky IE/DE bits are returned even when an
// unmasked exception prevents EFLAGS retirement.
inline std::optional<X86SseScalarCompareResult> evaluate_x86_sse_scalar_compare(
    const Instruction &instruction, std::uint32_t left, std::uint32_t right,
    std::uint64_t eflags = 0, std::uint32_t mxcsr = 0x1f80) noexcept {
    const bool native_mode =
        (instruction.context.architecture == Architecture::x86 &&
         (instruction.context.mode == ExecutionMode::x86_16 || instruction.context.mode == ExecutionMode::x86_32)) ||
        (instruction.context.architecture == Architecture::x86_64 &&
         instruction.context.mode == ExecutionMode::x86_64);
    if (!native_mode || instruction.operands.size() != 2 ||
        (instruction.opcode != Opcode::comiss && instruction.opcode != Opcode::ucomiss) ||
        (instruction.vector_bits && instruction.vector_bits != 128) ||
        (instruction.vector_element_bits && instruction.vector_element_bits != 32))
        return {};
    const auto valid_xmm = [](const Operand &operand) {
        const auto *reg = std::get_if<RegisterOperand>(&operand);
        return reg && reg->bank == RegisterBank::xmm && reg->width == 128 && !reg->high_byte;
    };
    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
    if (!valid_xmm(instruction.operands[0]) ||
        (!valid_xmm(instruction.operands[1]) && (!memory || memory->data_width != 32)))
        return {};

    constexpr std::uint32_t exponent_mask = 0x7f800000;
    constexpr std::uint32_t fraction_mask = 0x007fffff;
    constexpr std::uint32_t quiet_bit = 0x00400000;
    constexpr std::uint32_t sign_bit = 0x80000000;
    const auto classify = [=](std::uint32_t value) {
        const bool special = (value & exponent_mask) == exponent_mask;
        const bool nan = special && (value & fraction_mask) != 0;
        const bool signaling = nan && (value & quiet_bit) == 0;
        const bool subnormal = (value & exponent_mask) == 0 && (value & fraction_mask) != 0;
        return std::array<bool, 3>{nan, signaling, subnormal};
    };
    const auto a_class = classify(left), b_class = classify(right);
    const bool unordered = a_class[0] || b_class[0];
    const bool invalid = a_class[1] || b_class[1] ||
        (instruction.opcode == Opcode::comiss && unordered);
    const bool daz = (mxcsr & (1u << 6)) != 0;
    const bool denormal = (a_class[2] || b_class[2]) && !daz;
    if (daz) {
        if (a_class[2]) left &= sign_bit;
        if (b_class[2]) right &= sign_bit;
    }

    bool less = false, equal = false;
    if (!unordered) {
        if ((left & ~sign_bit) == 0 && (right & ~sign_bit) == 0) {
            equal = true; // +0 and -0 compare equal.
        } else {
            const auto order_key = [=](std::uint32_t value) {
                return value & sign_bit ? ~value : (value ^ sign_bit);
            };
            less = order_key(left) < order_key(right);
            equal = left == right;
        }
    }

    X86SseScalarCompareResult result;
    result.invalid_operation = invalid;
    result.denormal_operand = denormal;
    result.mxcsr_after = mxcsr | (invalid ? 1u : 0u) | (denormal ? 2u : 0u);
    result.completed = !(invalid && !(mxcsr & (1u << 7))) &&
                       !(denormal && !(mxcsr & (1u << 8)));
    result.eflags_after = eflags;
    if (result.completed) {
        constexpr std::uint64_t changed = (1u << 0) | (1u << 2) | (1u << 4) |
                                          (1u << 6) | (1u << 7) | (1u << 11);
        constexpr std::uint64_t cf = 1u << 0, pf = 1u << 2, zf = 1u << 6;
        const auto condition = unordered ? cf | pf | zf : less ? cf : equal ? zf : 0;
        result.eflags_after = (eflags & ~changed) | condition;
    }
    return result;
}

// Evaluate COMISD/UCOMISD from binary64 bit patterns. As with the single-
// precision forms, MXCSR sticky IE/DE is returned even if EFLAGS cannot retire.
inline std::optional<X86SseScalarCompareResult> evaluate_x86_sse_scalar_compare_double(
    const Instruction &instruction, std::uint64_t left, std::uint64_t right,
    std::uint64_t eflags = 0, std::uint32_t mxcsr = 0x1f80) noexcept {
    const bool native_mode =
        (instruction.context.architecture == Architecture::x86 &&
         (instruction.context.mode == ExecutionMode::x86_16 || instruction.context.mode == ExecutionMode::x86_32)) ||
        (instruction.context.architecture == Architecture::x86_64 &&
         instruction.context.mode == ExecutionMode::x86_64);
    if (!native_mode || instruction.operands.size() != 2 ||
        (instruction.opcode != Opcode::comisd && instruction.opcode != Opcode::ucomisd) ||
        (instruction.vector_bits && instruction.vector_bits != 128) ||
        (instruction.vector_element_bits && instruction.vector_element_bits != 64))
        return {};
    const auto valid_xmm = [](const Operand &operand) {
        const auto *reg = std::get_if<RegisterOperand>(&operand);
        return reg && reg->bank == RegisterBank::xmm && reg->width == 128 && !reg->high_byte;
    };
    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
    if (!valid_xmm(instruction.operands[0]) ||
        (!valid_xmm(instruction.operands[1]) && (!memory || memory->data_width != 64)))
        return {};

    constexpr std::uint64_t exponent_mask = UINT64_C(0x7ff0000000000000);
    constexpr std::uint64_t fraction_mask = UINT64_C(0x000fffffffffffff);
    constexpr std::uint64_t quiet_bit = UINT64_C(0x0008000000000000);
    constexpr std::uint64_t sign_bit = UINT64_C(0x8000000000000000);
    const auto classify = [=](std::uint64_t value) {
        const bool special = (value & exponent_mask) == exponent_mask;
        const bool nan = special && (value & fraction_mask) != 0;
        const bool signaling = nan && (value & quiet_bit) == 0;
        const bool subnormal = (value & exponent_mask) == 0 && (value & fraction_mask) != 0;
        return std::array<bool, 3>{nan, signaling, subnormal};
    };
    const auto a_class = classify(left), b_class = classify(right);
    const bool unordered = a_class[0] || b_class[0];
    const bool invalid = a_class[1] || b_class[1] ||
        (instruction.opcode == Opcode::comisd && unordered);
    const bool daz = (mxcsr & (1u << 6)) != 0;
    const bool denormal = (a_class[2] || b_class[2]) && !daz;
    if (daz) {
        if (a_class[2]) left &= sign_bit;
        if (b_class[2]) right &= sign_bit;
    }

    bool less = false, equal = false;
    if (!unordered) {
        if ((left & ~sign_bit) == 0 && (right & ~sign_bit) == 0) {
            equal = true;
        } else {
            const auto order_key = [=](std::uint64_t value) {
                return value & sign_bit ? ~value : (value ^ sign_bit);
            };
            less = order_key(left) < order_key(right);
            equal = left == right;
        }
    }

    X86SseScalarCompareResult result;
    result.invalid_operation = invalid;
    result.denormal_operand = denormal;
    result.mxcsr_after = mxcsr | (invalid ? 1u : 0u) | (denormal ? 2u : 0u);
    result.completed = !(invalid && !(mxcsr & (1u << 7))) &&
                       !(denormal && !(mxcsr & (1u << 8)));
    result.eflags_after = eflags;
    if (result.completed) {
        constexpr std::uint64_t changed = (1u << 0) | (1u << 2) | (1u << 4) |
                                          (1u << 6) | (1u << 7) | (1u << 11);
        constexpr std::uint64_t cf = 1u << 0, pf = 1u << 2, zf = 1u << 6;
        const auto condition = unordered ? cf | pf | zf : less ? cf : equal ? zf : 0;
        result.eflags_after = (eflags & ~changed) | condition;
    }
    return result;
}

} // namespace hexlab
