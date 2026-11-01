#pragma once

#include "hexlab/processors/instruction.hpp"
#include <bit>

namespace hexlab {
enum class X86DecimalAdjust : std::uint8_t { daa, das, aaa, aas };
struct X86DecimalAdjustResult {
    std::uint16_t ax = 0;
    std::uint64_t flags_value = 0;
    std::uint64_t flags_defined_mask = 0;
    bool operator==(const X86DecimalAdjustResult &) const = default;
};

// Results contain only defined arithmetic flags. Non-arithmetic flags are
// unchanged; arithmetic flags outside flags_defined_mask are undefined.
constexpr std::optional<X86DecimalAdjustResult> evaluate_x86_decimal_adjust(
    X86DecimalAdjust operation, std::uint16_t ax, std::uint64_t incoming_flags) noexcept {
    const auto al = static_cast<std::uint8_t>(ax);
    const bool low = (al & 15u) > 9u || (incoming_flags & 0x10u) != 0;
    X86DecimalAdjustResult result;
    switch (operation) {
    case X86DecimalAdjust::aaa: case X86DecimalAdjust::aas:
        // Full AX arithmetic retains the extra carry/borrow into AH even for
        // inputs outside the usual unpacked-BCD range.
        result.ax = static_cast<std::uint16_t>(low ?
            (operation == X86DecimalAdjust::aaa ? ax + 0x106u : ax - 0x106u) : ax);
        result.ax &= 0xff0fu;
        result.flags_defined_mask = 0x11u;
        if (low) result.flags_value = 0x11u;
        return result;
    case X86DecimalAdjust::daa: case X86DecimalAdjust::das: {
        const bool subtract = operation == X86DecimalAdjust::das;
        const bool high = al > 0x99u || (incoming_flags & 1u) != 0;
        unsigned adjusted = al;
        if (low) adjusted = subtract ? adjusted - 6u : adjusted + 6u;
        if (high) adjusted = subtract ? adjusted - 0x60u : adjusted + 0x60u;
        const auto byte = static_cast<std::uint8_t>(adjusted);
        result.ax = static_cast<std::uint16_t>((ax & 0xff00u) | byte);
        result.flags_defined_mask = 0xd5u;
        // DAS retains a borrow from the low correction when no high
        // correction is selected; DAA's final high decision replaces CF.
        if (high || (subtract && low && al < 6u)) result.flags_value |= 1u;
        if (low) result.flags_value |= 0x10u;
        if ((std::popcount(byte) & 1) == 0) result.flags_value |= 4u;
        if (byte == 0) result.flags_value |= 0x40u;
        if (byte & 0x80u) result.flags_value |= 0x80u;
        return result;
    }
    }
    return std::nullopt;
}

// Shared strict shape check for concrete evaluation and decompiler lowering.
// 66/67 and segment overrides do not change the fixed implicit byte operands.
inline std::optional<X86DecimalAdjust> x86_decimal_adjust_operation(const Instruction &i) noexcept {
    if ((i.context.architecture != Architecture::x86 && i.context.architecture != Architecture::x86_64) ||
        (i.context.mode != ExecutionMode::x86_16 && i.context.mode != ExecutionMode::x86_32) ||
        i.lock_prefix || i.memory_read || i.memory_write || i.flow != FlowKind::fallthrough ||
        !i.operands.empty() || !i.access.empty() || i.x86_repeat != X86RepeatPrefix::none)
        return std::nullopt;
    X86DecimalAdjust operation;
    std::uint8_t opcode;
    switch (i.opcode) {
    case Opcode::daa: operation = X86DecimalAdjust::daa; opcode = 0x27; break;
    case Opcode::das: operation = X86DecimalAdjust::das; opcode = 0x2f; break;
    case Opcode::aaa: operation = X86DecimalAdjust::aaa; opcode = 0x37; break;
    case Opcode::aas: operation = X86DecimalAdjust::aas; opcode = 0x3f; break;
    default: return std::nullopt;
    }
    const auto bytes = i.encoded_bytes();
    if (bytes.empty() || bytes.size() > 15 || bytes.size() != i.length ||
        bytes.back() != std::byte{opcode}) return std::nullopt;
    for (std::size_t n = 0; n + 1 < bytes.size(); ++n) {
        switch (std::to_integer<std::uint8_t>(bytes[n])) {
        case 0x66: case 0x67: case 0x26: case 0x2e: case 0x36: case 0x3e: case 0x64: case 0x65: break;
        default: return std::nullopt;
        }
    }
    const bool unpacked = operation == X86DecimalAdjust::aaa || operation == X86DecimalAdjust::aas;
    const auto width = static_cast<std::uint16_t>(i.context.mode == ExecutionMode::x86_16 ? 16 : 32);
    const RegisterOperand al{RegisterBank::gpr, 0, 8, false}, ah{RegisterBank::gpr, 0, 8, true};
    const RegisterOperand flags{RegisterBank::flags, 0, width, false};
    const std::size_t count = unpacked ? 3 : 2;
    const auto expected = [&](const auto &registers) {
        return registers.size() == count && registers[0] == al && registers.back() == flags &&
            (!unpacked || registers[1] == ah);
    };
    if (!expected(i.register_reads) || !expected(i.register_writes) ||
        (i.x86_flags_read_mask && *i.x86_flags_read_mask != (unpacked ? 0x10u : 0x11u)) ||
        (i.x86_flags_write_mask && *i.x86_flags_write_mask != 0x8d5u)) return std::nullopt;
    return operation;
}

using X86AaaAasResult = X86DecimalAdjustResult;
inline std::optional<X86AaaAasResult> evaluate_x86_aaa_aas_instruction(
    const Instruction &instruction, std::uint16_t ax, std::uint64_t incoming_flags) noexcept {
    const auto operation = x86_decimal_adjust_operation(instruction);
    if (!operation || (*operation != X86DecimalAdjust::aaa && *operation != X86DecimalAdjust::aas))
        return std::nullopt;
    return evaluate_x86_decimal_adjust(*operation, ax, incoming_flags);
}
} // namespace hexlab
