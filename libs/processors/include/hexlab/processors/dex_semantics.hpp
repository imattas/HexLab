#pragma once

#include "hexlab/processors/instruction.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace hexlab {

struct DexIntegerBinaryResult {
    std::uint64_t value = 0;
    std::uint8_t result_width = 32;
    bool operator==(const DexIntegerBinaryResult &) const = default;
};

struct DexIntegerDivideResult {
    std::optional<std::uint64_t> value;
    std::uint8_t result_width = 32;
    bool divide_by_zero = false;
    bool operator==(const DexIntegerDivideResult &) const = default;
};

struct DexIntegerLiteralResult {
    std::optional<std::uint32_t> value;
    bool divide_by_zero = false;
    bool operator==(const DexIntegerLiteralResult &) const = default;
};

struct DexArrayLengthResult {
    std::uint32_t value = 0;
    bool null_pointer_trap = false;
    bool operator==(const DexArrayLengthResult &) const = default;
};

// Evaluate DEX cmpl/cmpg float and double comparisons from raw IEEE bits.
// NaN maps to -1 for cmpl and +1 for cmpg; signed zeros compare equal.
inline std::optional<std::int32_t> evaluate_dex_float_compare_instruction(
    const Instruction &instruction, std::uint64_t lhs_bits,
    std::uint64_t rhs_bits) noexcept {
    if (instruction.context.architecture != Architecture::dex ||
        instruction.context.mode != ExecutionMode::dex || instruction.opcode != Opcode::dex ||
        instruction.length != 4 || instruction.flow != FlowKind::fallthrough ||
        instruction.memory_read || instruction.memory_write || instruction.operands.size() != 3 ||
        instruction.access.size() != 3 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read || instruction.access[2] != OperandAccess::read)
        return std::nullopt;
    const auto opcode = std::to_integer<std::uint8_t>(instruction.bytes[0]);
    const bool single = opcode == 0x2d || opcode == 0x2e;
    const bool greater_nan = opcode == 0x2e || opcode == 0x30;
    if (!single && opcode != 0x2f && opcode != 0x30) return std::nullopt;
    const std::string_view mnemonic = single
        ? (greater_nan ? "cmpg-float" : "cmpl-float")
        : (greater_nan ? "cmpg-double" : "cmpl-double");
    const auto separator = instruction.mnemonic_override.find(' ');
    if (std::string_view(instruction.mnemonic_override).substr(0, separator) != mnemonic)
        return std::nullopt;

    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *left = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *right = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto valid_register = [](const RegisterOperand *reg, unsigned width) {
        return reg && reg->bank == RegisterBank::dex_vreg && reg->width == width && !reg->high_byte;
    };
    const unsigned operand_width = single ? 32u : 64u;
    if (!valid_register(destination, 32) || !valid_register(left, operand_width) ||
        !valid_register(right, operand_width) ||
        (operand_width == 64 && (left->index == UINT16_MAX || right->index == UINT16_MAX)) ||
        (single && ((lhs_bits | rhs_bits) >> 32) != 0))
        return std::nullopt;
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_writes, *destination)) return std::nullopt;
    for (unsigned slot = 0; slot < (single ? 1u : 2u); ++slot) {
        const RegisterOperand lhs_slot{RegisterBank::dex_vreg,
            static_cast<std::uint16_t>(left->index + slot), 32, false};
        const RegisterOperand rhs_slot{RegisterBank::dex_vreg,
            static_cast<std::uint16_t>(right->index + slot), 32, false};
        if (!has(instruction.register_reads, lhs_slot) || !has(instruction.register_reads, rhs_slot))
            return std::nullopt;
    }

    const unsigned fraction_bits = single ? 23u : 52u;
    const unsigned exponent_bits = single ? 8u : 11u;
    const std::uint64_t mask = single ? UINT64_C(0xffffffff) : UINT64_MAX;
    const std::uint64_t sign = UINT64_C(1) << (fraction_bits + exponent_bits);
    const std::uint64_t fraction_mask = (UINT64_C(1) << fraction_bits) - 1;
    const std::uint64_t exponent_mask = (UINT64_C(1) << exponent_bits) - 1;
    lhs_bits &= mask;
    rhs_bits &= mask;
    const auto is_nan = [fraction_bits, exponent_mask, fraction_mask](std::uint64_t bits) {
        return ((bits >> fraction_bits) & exponent_mask) == exponent_mask &&
               (bits & fraction_mask) != 0;
    };
    if (is_nan(lhs_bits) || is_nan(rhs_bits)) return greater_nan ? 1 : -1;
    if ((lhs_bits & ~sign) == 0 && (rhs_bits & ~sign) == 0) return 0;
    const auto order_key = [sign, mask](std::uint64_t bits) {
        return (bits & sign) ? (~bits & mask) : (bits ^ sign);
    };
    const auto lhs_key = order_key(lhs_bits), rhs_key = order_key(rhs_bits);
    return lhs_key < rhs_key ? -1 : lhs_key > rhs_key ? 1 : 0;
}

// Resolve a decoded packed-switch/sparse-switch target. The validated payload
// must already be attached to the instruction; unmatched keys fall through.
inline std::optional<Address> evaluate_dex_switch_instruction(
    const Instruction &instruction, std::int32_t key) noexcept {
    if (instruction.context.architecture != Architecture::dex || instruction.context.mode != ExecutionMode::dex ||
        instruction.opcode != Opcode::dex_switch || instruction.flow != FlowKind::switch_dispatch ||
        !instruction.dex_switch || !instruction.dex_switch->validated || instruction.direct_target ||
        instruction.length != 2 || instruction.memory_read || instruction.memory_write ||
        instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::read || instruction.access[1] != OperandAccess::read)
        return std::nullopt;
    const auto encoded_opcode = std::to_integer<std::uint8_t>(instruction.bytes[0]);
    const bool packed = encoded_opcode == 0x2b;
    if ((!packed && encoded_opcode != 0x2c) || packed != instruction.dex_switch->packed)
        return std::nullopt;
    if (instruction.address.offset > UINT32_MAX || instruction.dex_switch->payload.offset > UINT32_MAX ||
        instruction.dex_switch->payload.space != instruction.address.space)
        return std::nullopt;
    const auto *value_register = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *payload = std::get_if<RelativeOperand>(&instruction.operands[1]);
    if (!value_register || value_register->bank != RegisterBank::dex_vreg ||
        value_register->width != 32 || value_register->high_byte || !payload ||
        payload->encoded_width != 32 || payload->effective_width != 32 ||
        payload->displacement != static_cast<std::int64_t>(instruction.dex_switch->payload.offset) -
                                 static_cast<std::int64_t>(instruction.address.offset))
        return std::nullopt;
    if (std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *value_register) ==
        instruction.register_reads.end())
        return std::nullopt;
    const auto &table = *instruction.dex_switch;
    for (std::size_t index = 0; index < table.cases.size(); ++index) {
        const auto &entry = table.cases[index];
        if (entry.target.space != instruction.address.space || entry.target.offset > UINT32_MAX ||
            (index && (table.packed
                ? static_cast<std::int64_t>(table.cases[index - 1].value) + 1 != entry.value
                : table.cases[index - 1].value >= entry.value)))
            return std::nullopt;
        if (entry.value == key) return entry.target;
    }
    if (instruction.address.offset > UINT32_MAX - instruction.length) return std::nullopt;
    return Address{instruction.address.space, instruction.address.offset + instruction.length};
}

// Evaluate decoded array-length from caller-supplied reference nullness and
// length. A null reference reports the DEX NullPointerException condition.
inline std::optional<DexArrayLengthResult> evaluate_dex_array_length_instruction(
    const Instruction &instruction, bool is_null, std::uint32_t array_length) noexcept {
    if (instruction.context.architecture != Architecture::dex || instruction.context.mode != ExecutionMode::dex ||
        instruction.opcode != Opcode::dex || instruction.length != 2 || instruction.bytes[0] != std::byte{0x21} ||
        instruction.flow != FlowKind::fallthrough || instruction.operands.size() != 2 ||
        instruction.access.size() != 2 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read || !instruction.memory_read || instruction.memory_write)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *array = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto valid_vreg = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::dex_vreg && reg->width == 32 && !reg->high_byte;
    };
    if (!valid_vreg(destination) || !valid_vreg(array)) return std::nullopt;
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_writes, *destination) || !has(instruction.register_reads, *array))
        return std::nullopt;
    if (is_null) return DexArrayLengthResult{0, true};
    if (array_length > static_cast<std::uint32_t>(INT32_MAX)) return std::nullopt;
    return DexArrayLengthResult{array_length, false};
}

// Evaluate DEX int/long shl/shr/ushr forms, including /2addr. Shift amounts
// use the low five bits for int and low six bits for long.
inline std::optional<DexIntegerBinaryResult> evaluate_dex_integer_shift(
    const Instruction &instruction, std::uint64_t value, std::uint32_t amount_value) noexcept {
    if (instruction.context.architecture != Architecture::dex || instruction.context.mode != ExecutionMode::dex ||
        instruction.opcode != Opcode::dex || instruction.memory_read || instruction.memory_write ||
        instruction.flow != FlowKind::fallthrough)
        return std::nullopt;
    const auto &text = instruction.mnemonic_override;
    const auto separator = text.find(' ');
    const std::string_view mnemonic(text.data(), separator == std::string::npos ? text.size() : separator);
    const bool two_address = mnemonic.ends_with("/2addr");
    const auto base = two_address ? mnemonic.substr(0, mnemonic.size() - std::string_view("/2addr").size())
                                  : mnemonic;
    const bool wide = base == "shl-long" || base == "shr-long" || base == "ushr-long";
    const bool integer = base == "shl-int" || base == "shr-int" || base == "ushr-int";
    const bool shift_left = base == "shl-int" || base == "shl-long";
    const bool arithmetic_right = base == "shr-int" || base == "shr-long";
    const bool logical_right = base == "ushr-int" || base == "ushr-long";
    if ((!integer && !wide) ||
        (two_address ? (instruction.operands.size() != 2 || instruction.length != 2)
                     : (instruction.operands.size() != 3 || instruction.length != 4)) ||
        instruction.access.size() != instruction.operands.size() ||
        instruction.access[0] != (two_address ? OperandAccess::read_write : OperandAccess::write) ||
        instruction.access[1] != OperandAccess::read ||
        (!two_address && instruction.access[2] != OperandAccess::read))
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *left = two_address ? destination : std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *amount = std::get_if<RegisterOperand>(&instruction.operands[two_address ? 1 : 2]);
    const auto value_width = static_cast<std::uint16_t>(wide ? 64 : 32);
    if (!destination || !left || !amount || destination->bank != RegisterBank::dex_vreg ||
        left->bank != RegisterBank::dex_vreg || amount->bank != RegisterBank::dex_vreg ||
        destination->width != value_width || left->width != value_width || amount->width != 32 ||
        destination->high_byte || left->high_byte || amount->high_byte ||
        static_cast<unsigned>(destination->index) + value_width / 32 - 1 > UINT16_MAX ||
        static_cast<unsigned>(left->index) + value_width / 32 - 1 > UINT16_MAX)
        return std::nullopt;
    const auto has_slots = [](const auto &effects, const RegisterOperand &reg) {
        for (unsigned slot = 0; slot < reg.width / 32; ++slot) {
            const RegisterOperand component{RegisterBank::dex_vreg,
                static_cast<std::uint16_t>(reg.index + slot), 32, false};
            if (std::find(effects.begin(), effects.end(), component) == effects.end()) return false;
        }
        return true;
    };
    if (!has_slots(instruction.register_reads, *left) || !has_slots(instruction.register_reads, *amount) ||
        !has_slots(instruction.register_writes, *destination))
        return std::nullopt;
    const unsigned width = wide ? 64u : 32u;
    const auto mask = wide ? UINT64_MAX : UINT64_C(0xffffffff);
    value &= mask;
    const unsigned count = amount_value & (width - 1);
    std::uint64_t result = 0;
    if (shift_left) result = (value << count) & mask;
    else if (logical_right) result = value >> count;
    else if (count == 0) result = value;
    else {
        result = value >> count;
        if (value & (UINT64_C(1) << (width - 1)))
            result |= mask & ~((UINT64_C(1) << (width - count)) - 1);
    }
    return DexIntegerBinaryResult{result, static_cast<std::uint8_t>(width)};
}

// Evaluate the three DEX int/lit8 shift opcodes. The encoded signed byte is
// reduced to the low five bits by the Dalvik shift operation.
inline std::optional<DexIntegerBinaryResult> evaluate_dex_integer_literal_shift(
    const Instruction &instruction, std::uint32_t value) noexcept {
    if (instruction.context.architecture != Architecture::dex || instruction.context.mode != ExecutionMode::dex ||
        instruction.opcode != Opcode::dex || instruction.length != 4 || instruction.memory_read ||
        instruction.memory_write || instruction.flow != FlowKind::fallthrough || instruction.operands.size() != 3 ||
        instruction.access.size() != 3 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read || instruction.access[2] != OperandAccess::read)
        return std::nullopt;
    const auto opcode = std::to_integer<std::uint8_t>(instruction.bytes[0]);
    const auto &mnemonic = instruction.mnemonic_override;
    const bool shift_left = opcode == 0xd8 && mnemonic == "shl-int/lit8";
    const bool arithmetic_right = opcode == 0xd9 && mnemonic == "shr-int/lit8";
    const bool logical_right = opcode == 0xda && mnemonic == "ushr-int/lit8";
    if (!shift_left && !arithmetic_right && !logical_right) return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *source = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *literal = std::get_if<ImmediateOperand>(&instruction.operands[2]);
    if (!destination || !source || !literal || destination->bank != RegisterBank::dex_vreg ||
        source->bank != RegisterBank::dex_vreg || destination->width != 32 || source->width != 32 ||
        destination->high_byte || source->high_byte || literal->encoded_width != 8 ||
        literal->effective_width != 32 || !literal->is_signed ||
        std::bit_cast<std::int64_t>(literal->value) < INT8_MIN ||
        std::bit_cast<std::int64_t>(literal->value) > INT8_MAX)
        return std::nullopt;
    const RegisterOperand destination_slot{RegisterBank::dex_vreg, destination->index, 32, false};
    const RegisterOperand source_slot{RegisterBank::dex_vreg, source->index, 32, false};
    if (std::find(instruction.register_writes.begin(), instruction.register_writes.end(), destination_slot) ==
            instruction.register_writes.end() ||
        std::find(instruction.register_reads.begin(), instruction.register_reads.end(), source_slot) ==
            instruction.register_reads.end())
        return std::nullopt;

    const auto count = static_cast<unsigned>(std::bit_cast<std::int64_t>(literal->value)) & 31u;
    const auto bits = static_cast<std::uint64_t>(value);
    std::uint32_t result = 0;
    if (shift_left) result = static_cast<std::uint32_t>(bits << count);
    else if (logical_right) result = static_cast<std::uint32_t>(bits >> count);
    else if (count == 0) result = value;
    else {
        result = static_cast<std::uint32_t>(bits >> count);
        if (value & UINT32_C(0x80000000))
            result |= UINT32_MAX & ~((UINT32_C(1) << (32 - count)) - 1);
    }
    return DexIntegerBinaryResult{result, 32};
}

// Evaluate Dalvik's int lit16/lit8 arithmetic family from the source vreg
// and encoded signed literal. Division and remainder report their arithmetic
// exception separately; all other operations wrap to 32 bits.
inline std::optional<DexIntegerLiteralResult> evaluate_dex_integer_literal(
    const Instruction &instruction, std::uint32_t source) noexcept {
    if (instruction.context.architecture != Architecture::dex || instruction.context.mode != ExecutionMode::dex ||
        instruction.opcode != Opcode::dex || instruction.length != 4 || instruction.memory_read ||
        instruction.memory_write || instruction.flow != FlowKind::fallthrough || instruction.operands.size() != 3 ||
        instruction.access.size() != 3 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read || instruction.access[2] != OperandAccess::read)
        return std::nullopt;
    const auto opcode = std::to_integer<std::uint8_t>(instruction.bytes[0]);
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *literal = std::get_if<ImmediateOperand>(&instruction.operands[2]);
    if (!destination || !input || !literal || destination->bank != RegisterBank::dex_vreg ||
        input->bank != RegisterBank::dex_vreg || destination->width != 32 || input->width != 32 ||
        destination->high_byte || input->high_byte || literal->effective_width != 32 || !literal->is_signed)
        return std::nullopt;
    const bool lit16 = opcode >= 0xd0 && opcode <= 0xd7;
    const bool lit8 = opcode >= 0xd8 && opcode <= 0xe2;
    const auto expected_width = static_cast<std::uint16_t>(lit16 ? 16 : 8);
    const auto expected_mnemonic = [&]() -> std::string_view {
        static constexpr std::string_view names16[]{"add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16",
            "rem-int/lit16", "and-int/lit16", "or-int/lit16", "xor-int/lit16"};
        static constexpr std::string_view names8[]{"add-int/lit8", "rsub-int/lit8", "mul-int/lit8", "div-int/lit8",
            "rem-int/lit8", "and-int/lit8", "or-int/lit8", "xor-int/lit8", "shl-int/lit8", "shr-int/lit8", "ushr-int/lit8"};
        return lit16 ? names16[opcode - 0xd0] : lit8 ? names8[opcode - 0xd8] : std::string_view{};
    };
    const auto separator = instruction.mnemonic_override.find(' ');
    const std::string_view mnemonic(instruction.mnemonic_override.data(),
        separator == std::string::npos ? instruction.mnemonic_override.size() : separator);
    const auto immediate_value = std::bit_cast<std::int64_t>(literal->value);
    if ((!lit16 && !lit8) || mnemonic != expected_mnemonic || literal->encoded_width != expected_width ||
        immediate_value < (lit16 ? INT16_MIN : INT8_MIN) || immediate_value > (lit16 ? INT16_MAX : INT8_MAX))
        return std::nullopt;
    const RegisterOperand dst{RegisterBank::dex_vreg, destination->index, 32, false};
    const RegisterOperand src{RegisterBank::dex_vreg, input->index, 32, false};
    if (std::find(instruction.register_writes.begin(), instruction.register_writes.end(), dst) == instruction.register_writes.end() ||
        std::find(instruction.register_reads.begin(), instruction.register_reads.end(), src) == instruction.register_reads.end())
        return std::nullopt;

    const auto rhs = static_cast<std::uint32_t>(immediate_value);
    const auto signed_source = std::bit_cast<std::int32_t>(source);
    const auto signed_rhs = static_cast<std::int32_t>(immediate_value);
    std::uint32_t result = 0;
    switch (opcode) {
    case 0xd0: case 0xd8: result = source + rhs; break;
    case 0xd1: case 0xd9: result = rhs - source; break;
    case 0xd2: case 0xda: result = source * rhs; break;
    case 0xd3: case 0xdb:
        if (!signed_rhs) return DexIntegerLiteralResult{std::nullopt, true};
        result = signed_source == INT32_MIN && signed_rhs == -1 ? UINT32_C(0x80000000)
            : std::bit_cast<std::uint32_t>(signed_source / signed_rhs);
        break;
    case 0xd4: case 0xdc:
        if (!signed_rhs) return DexIntegerLiteralResult{std::nullopt, true};
        result = signed_source == INT32_MIN && signed_rhs == -1 ? 0
            : std::bit_cast<std::uint32_t>(signed_source % signed_rhs);
        break;
    case 0xd5: case 0xdd: result = source & rhs; break;
    case 0xd6: case 0xde: result = source | rhs; break;
    case 0xd7: case 0xdf: result = source ^ rhs; break;
    case 0xe0: result = source << (rhs & 31); break;
    case 0xe1: {
        const auto shift = rhs & 31;
        result = shift ? source >> shift : source;
        if (shift && (source & UINT32_C(0x80000000))) result |= UINT32_MAX << (32 - shift);
        break;
    }
    case 0xe2: result = source >> (rhs & 31); break;
    default: return std::nullopt;
    }
    return DexIntegerLiteralResult{result, false};
}

// Evaluate selected DEX int/long binary arithmetic and /2addr forms. Inputs
// follow the decoded source-register order; results wrap at 32 or 64 bits.
inline std::optional<DexIntegerBinaryResult> evaluate_dex_integer_binary(
    const Instruction &instruction, std::uint64_t lhs, std::uint64_t rhs) noexcept {
    if (instruction.context.architecture != Architecture::dex || instruction.context.mode != ExecutionMode::dex ||
        instruction.opcode != Opcode::dex || instruction.memory_read || instruction.memory_write ||
        instruction.flow != FlowKind::fallthrough)
        return std::nullopt;
    const auto &text = instruction.mnemonic_override;
    const auto separator = text.find(' ');
    const std::string_view mnemonic(text.data(), separator == std::string::npos ? text.size() : separator);
    const bool two_address = mnemonic.ends_with("/2addr");
    const bool wide = mnemonic.find("-long") != std::string_view::npos;
    const bool integer = wide || mnemonic.find("-int") != std::string_view::npos;
    if (!integer || (two_address ? (instruction.operands.size() != 2 || instruction.length != 2)
                                 : (instruction.operands.size() != 3 || instruction.length != 4)) ||
        instruction.access.size() != instruction.operands.size() ||
        instruction.access[0] != (two_address ? OperandAccess::read_write : OperandAccess::write) ||
        instruction.access[1] != OperandAccess::read ||
        (!two_address && instruction.access[2] != OperandAccess::read))
        return std::nullopt;
    const bool is_add = mnemonic.starts_with("add-");
    const bool is_sub = mnemonic.starts_with("sub-");
    const bool is_mul = mnemonic.starts_with("mul-");
    const bool is_and = mnemonic.starts_with("and-");
    const bool is_or = mnemonic.starts_with("or-");
    const bool is_xor = mnemonic.starts_with("xor-");
    if (!is_add && !is_sub && !is_mul && !is_and && !is_or && !is_xor) return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *left = two_address ? destination : std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *right = std::get_if<RegisterOperand>(&instruction.operands[two_address ? 1 : 2]);
    const auto width = static_cast<std::uint16_t>(wide ? 64 : 32);
    const auto valid = [width](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::dex_vreg && reg->width == width && !reg->high_byte;
    };
    if (!valid(destination) || !valid(left) || !valid(right) ||
        static_cast<unsigned>(destination->index) + width / 32 - 1 > UINT16_MAX ||
        static_cast<unsigned>(left->index) + width / 32 - 1 > UINT16_MAX ||
        static_cast<unsigned>(right->index) + width / 32 - 1 > UINT16_MAX)
        return std::nullopt;
    const auto has_slots = [](const auto &effects, const RegisterOperand &reg) {
        for (unsigned slot = 0; slot < reg.width / 32; ++slot) {
            const RegisterOperand component{RegisterBank::dex_vreg,
                static_cast<std::uint16_t>(reg.index + slot), 32, false};
            if (std::find(effects.begin(), effects.end(), component) == effects.end()) return false;
        }
        return true;
    };
    if (!has_slots(instruction.register_reads, *left) || !has_slots(instruction.register_reads, *right) ||
        !has_slots(instruction.register_writes, *destination))
        return std::nullopt;
    const auto mask = wide ? UINT64_MAX : UINT64_C(0xffffffff);
    lhs &= mask;
    rhs &= mask;
    const auto value = is_add ? lhs + rhs : is_sub ? lhs - rhs : is_mul ? lhs * rhs :
                       is_and ? lhs & rhs : is_or ? lhs | rhs : lhs ^ rhs;
    return DexIntegerBinaryResult{value & mask, static_cast<std::uint8_t>(width)};
}

// Evaluate decoded DEX signed int/long div and rem register forms, including
// /2addr. A zero divisor is an explicit arithmetic-exception result. The
// minimum-value / -1 case wraps to the minimum value and has remainder zero.
inline std::optional<DexIntegerDivideResult> evaluate_dex_integer_divide(
    const Instruction &instruction, std::uint64_t lhs, std::uint64_t rhs) noexcept {
    if (instruction.context.architecture != Architecture::dex || instruction.context.mode != ExecutionMode::dex ||
        instruction.opcode != Opcode::dex || instruction.memory_read || instruction.memory_write ||
        instruction.flow != FlowKind::fallthrough)
        return std::nullopt;
    const auto &text = instruction.mnemonic_override;
    const auto separator = text.find(' ');
    const std::string_view mnemonic(text.data(), separator == std::string::npos ? text.size() : separator);
    const bool two_address = mnemonic.ends_with("/2addr");
    const auto base = two_address ? mnemonic.substr(0, mnemonic.size() - 6) : mnemonic;
    const bool division = base == "div-int" || base == "div-long";
    const bool remainder = base == "rem-int" || base == "rem-long";
    if (!division && !remainder) return std::nullopt;
    const bool wide = base.ends_with("-long");
    const auto width = static_cast<std::uint16_t>(wide ? 64 : 32);
    const auto expected_opcode = wide
        ? static_cast<std::uint8_t>((two_address ? 0xbe : 0x9e) + (remainder ? 1 : 0))
        : static_cast<std::uint8_t>((two_address ? 0xb3 : 0x93) + (remainder ? 1 : 0));
    if (instruction.length != (two_address ? 2u : 4u) ||
        std::to_integer<std::uint8_t>(instruction.bytes[0]) != expected_opcode ||
        instruction.operands.size() != (two_address ? 2u : 3u) ||
        instruction.access.size() != instruction.operands.size() ||
        instruction.access[0] != (two_address ? OperandAccess::read_write : OperandAccess::write) ||
        instruction.access[1] != OperandAccess::read ||
        (!two_address && instruction.access[2] != OperandAccess::read))
        return std::nullopt;

    const auto first_unit = static_cast<std::uint16_t>(
        std::to_integer<std::uint8_t>(instruction.bytes[0]) |
        (std::uint16_t(std::to_integer<std::uint8_t>(instruction.bytes[1])) << 8));
    const auto second_unit = two_address ? std::uint16_t{0} : static_cast<std::uint16_t>(
        std::to_integer<std::uint8_t>(instruction.bytes[2]) |
        (std::uint16_t(std::to_integer<std::uint8_t>(instruction.bytes[3])) << 8));

    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *left = two_address ? destination : std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *right = std::get_if<RegisterOperand>(&instruction.operands[two_address ? 1 : 2]);
    const auto valid = [width](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::dex_vreg && reg->width == width && !reg->high_byte &&
               static_cast<unsigned>(reg->index) + width / 32 - 1 <= UINT16_MAX;
    };
    if (!valid(destination) || !valid(left) || !valid(right)) return std::nullopt;
    if (two_address) {
        if (((first_unit >> 8) & 15) != destination->index || (first_unit >> 12) != right->index)
            return std::nullopt;
    } else if ((first_unit >> 8) != destination->index || (second_unit & 255) != left->index ||
               (second_unit >> 8) != right->index) {
        return std::nullopt;
    }
    const unsigned component_slots = width / 32;
    const unsigned left_first = left->index, right_first = right->index;
    const unsigned overlap_first = std::max(left_first, right_first);
    const unsigned overlap_last = std::min(left_first + component_slots - 1, right_first + component_slots - 1);
    const unsigned overlap_slots = overlap_first <= overlap_last ? overlap_last - overlap_first + 1 : 0;
    const unsigned expected_read_slots = 2 * component_slots - overlap_slots;
    const auto has_slots = [](const auto &effects, const RegisterOperand &reg) {
        for (unsigned slot = 0; slot < reg.width / 32; ++slot) {
            const RegisterOperand component{RegisterBank::dex_vreg,
                static_cast<std::uint16_t>(reg.index + slot), 32, false};
            if (std::find(effects.begin(), effects.end(), component) == effects.end()) return false;
        }
        return true;
    };
    if (instruction.register_reads.size() != expected_read_slots ||
        instruction.register_writes.size() != component_slots ||
        !has_slots(instruction.register_reads, *left) || !has_slots(instruction.register_reads, *right) ||
        !has_slots(instruction.register_writes, *destination))
        return std::nullopt;

    const auto mask = wide ? UINT64_MAX : UINT64_C(0xffffffff);
    lhs &= mask;
    rhs &= mask;
    if (rhs == 0) return DexIntegerDivideResult{std::nullopt, static_cast<std::uint8_t>(width), true};
    if (wide) {
        const auto signed_lhs = std::bit_cast<std::int64_t>(lhs);
        const auto signed_rhs = std::bit_cast<std::int64_t>(rhs);
        if (signed_lhs == INT64_MIN && signed_rhs == -1)
            return DexIntegerDivideResult{division ? lhs : UINT64_C(0), 64, false};
        const auto result = division ? signed_lhs / signed_rhs : signed_lhs % signed_rhs;
        return DexIntegerDivideResult{std::bit_cast<std::uint64_t>(result), 64, false};
    }
    const auto signed_lhs = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(lhs));
    const auto signed_rhs = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(rhs));
    if (signed_lhs == INT32_MIN && signed_rhs == -1)
        return DexIntegerDivideResult{division ? static_cast<std::uint64_t>(static_cast<std::uint32_t>(lhs)) : UINT64_C(0),
                                      32, false};
    const auto result = division ? signed_lhs / signed_rhs : signed_lhs % signed_rhs;
    return DexIntegerDivideResult{static_cast<std::uint32_t>(result), 32, false};
}

struct DexIntegerUnaryResult {
    std::uint64_t value = 0;
    std::uint8_t result_width = 32;
    bool operator==(const DexIntegerUnaryResult &) const = default;
};

// Evaluate decoded neg-int/not-int/neg-long/not-long operations from one raw
// vreg value. Arithmetic wraps at the Dalvik int/long width.
inline std::optional<DexIntegerUnaryResult> evaluate_dex_integer_unary(
    const Instruction &instruction, std::uint64_t source) noexcept {
    if (instruction.context.architecture != Architecture::dex || instruction.context.mode != ExecutionMode::dex ||
        instruction.opcode != Opcode::dex || instruction.operands.size() != 2 ||
        instruction.access.size() != 2 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read || instruction.memory_read || instruction.memory_write)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if (!destination || !input || destination->bank != RegisterBank::dex_vreg ||
        input->bank != RegisterBank::dex_vreg || destination->high_byte || input->high_byte)
        return std::nullopt;
    const auto separator = instruction.mnemonic_override.find(' ');
    const std::string_view name(instruction.mnemonic_override.data(),
        separator == std::string::npos ? instruction.mnemonic_override.size() : separator);
    const bool wide = name == "neg-long" || name == "not-long";
    const bool negate = name == "neg-int" || name == "neg-long";
    if (!wide && !negate && name != "not-int" && name != "not-long") return std::nullopt;
    const auto width = static_cast<std::uint16_t>(wide ? 64 : 32);
    if (destination->width != width || input->width != width ||
        static_cast<unsigned>(destination->index) + width / 32 - 1 > UINT16_MAX ||
        static_cast<unsigned>(input->index) + width / 32 - 1 > UINT16_MAX)
        return std::nullopt;
    const auto slots_present = [](const auto &effects, const RegisterOperand &reg) {
        for (unsigned slot = 0; slot < reg.width / 32; ++slot) {
            const RegisterOperand component{RegisterBank::dex_vreg,
                static_cast<std::uint16_t>(reg.index + slot), 32, false};
            if (std::find(effects.begin(), effects.end(), component) == effects.end()) return false;
        }
        return true;
    };
    if (!slots_present(instruction.register_reads, *input) ||
        !slots_present(instruction.register_writes, *destination))
        return std::nullopt;
    const auto mask = wide ? UINT64_MAX : UINT64_C(0xffffffff);
    source &= mask;
    const auto value = negate ? (UINT64_C(0) - source) & mask : (~source & mask);
    return DexIntegerUnaryResult{value, static_cast<std::uint8_t>(width)};
}

// Evaluate a decoded Dalvik if-* branch using caller-supplied 32-bit vreg
// values. Signed relation forms interpret the values as int32_t; *z forms
// compare their single source against zero.
inline std::optional<bool> evaluate_dex_branch_predicate_instruction(
    const Instruction &instruction, std::uint32_t lhs, std::uint32_t rhs = 0) noexcept {
    if (instruction.context.architecture != Architecture::dex || instruction.context.mode != ExecutionMode::dex ||
        instruction.opcode != Opcode::dex || instruction.flow != FlowKind::conditional_branch ||
        instruction.memory_read || instruction.memory_write || instruction.length != 4)
        return std::nullopt;
    const auto encoded_opcode = std::to_integer<std::uint8_t>(instruction.bytes[0]);
    const bool pair = encoded_opcode >= 0x32 && encoded_opcode <= 0x37;
    if (!(pair || (encoded_opcode >= 0x38 && encoded_opcode <= 0x3d)) ||
        instruction.operands.size() != (pair ? 3u : 2u) || instruction.access.size() != instruction.operands.size())
        return std::nullopt;
    for (const auto access : instruction.access)
        if (access != OperandAccess::read) return std::nullopt;
    const auto *left = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *right = pair ? std::get_if<RegisterOperand>(&instruction.operands[1]) : nullptr;
    const auto *target = std::get_if<RelativeOperand>(&instruction.operands.back());
    const auto valid_register = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::dex_vreg && reg->width == 32 && !reg->high_byte;
    };
    if (!valid_register(left) || (pair && !valid_register(right)) || !target)
        return std::nullopt;
    const auto has_read = [&](const RegisterOperand &reg) {
        const RegisterOperand slot{RegisterBank::dex_vreg, reg.index, 32, false};
        return std::find(instruction.register_reads.begin(), instruction.register_reads.end(), slot) !=
               instruction.register_reads.end();
    };
    if (!has_read(*left) || (pair && !has_read(*right))) return std::nullopt;
    if (!pair) rhs = 0;
    const auto signed_lhs = std::bit_cast<std::int32_t>(lhs);
    const auto signed_rhs = std::bit_cast<std::int32_t>(rhs);
    switch (encoded_opcode) {
    case 0x32: case 0x38: return lhs == rhs;
    case 0x33: case 0x39: return lhs != rhs;
    case 0x34: case 0x3a: return signed_lhs < signed_rhs;
    case 0x35: case 0x3b: return signed_lhs >= signed_rhs;
    case 0x36: case 0x3c: return signed_lhs > signed_rhs;
    case 0x37: case 0x3d: return signed_lhs <= signed_rhs;
    default: return std::nullopt;
    }
}

struct DexIntegerConversionResult {
    std::uint64_t value = 0;
    std::uint8_t result_width = 32;
    bool operator==(const DexIntegerConversionResult &) const = default;
};

// Evaluate decoded DEX int/long and byte/char/short conversions from a source
// register bit pattern. Floating conversions and register-file reads/writes
// remain caller-owned.
inline std::optional<DexIntegerConversionResult> evaluate_dex_integer_conversion(
    const Instruction &instruction, std::uint64_t source) noexcept {
    if (instruction.context.architecture != Architecture::dex || instruction.context.mode != ExecutionMode::dex ||
        instruction.opcode != Opcode::dex || instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if (!destination || !input || destination->bank != RegisterBank::dex_vreg ||
        input->bank != RegisterBank::dex_vreg || destination->high_byte || input->high_byte)
        return std::nullopt;

    unsigned source_width = 32, result_width = 32;
    enum class Operation { int_to_long, long_to_int, int_to_byte, int_to_char, int_to_short } operation;
    const auto separator = instruction.mnemonic_override.find(' ');
    const std::string_view name(instruction.mnemonic_override.data(),
        separator == std::string::npos ? instruction.mnemonic_override.size() : separator);
    if (name == "int-to-long") { operation = Operation::int_to_long; result_width = 64; }
    else if (name == "long-to-int") { operation = Operation::long_to_int; source_width = 64; }
    else if (name == "int-to-byte") operation = Operation::int_to_byte;
    else if (name == "int-to-char") operation = Operation::int_to_char;
    else if (name == "int-to-short") operation = Operation::int_to_short;
    else return std::nullopt;
    if (input->width != source_width || destination->width != result_width)
        return std::nullopt;

    const auto has_slots = [](const auto &effects, const RegisterOperand &operand) {
        for (unsigned slot = 0; slot < operand.width / 32; ++slot) {
            if (static_cast<unsigned>(operand.index) + slot > UINT16_MAX) return false;
            const RegisterOperand component{RegisterBank::dex_vreg,
                static_cast<std::uint16_t>(operand.index + slot), 32, false};
            if (std::find(effects.begin(), effects.end(), component) == effects.end()) return false;
        }
        return true;
    };
    if (!has_slots(instruction.register_reads, *input) ||
        !has_slots(instruction.register_writes, *destination))
        return std::nullopt;

    std::uint64_t value = 0;
    switch (operation) {
    case Operation::int_to_long: {
        const auto low = static_cast<std::uint32_t>(source);
        value = static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int32_t>(low)));
        break;
    }
    case Operation::long_to_int: value = static_cast<std::uint32_t>(source); break;
    case Operation::int_to_byte:
        value = static_cast<std::uint32_t>(static_cast<std::int32_t>(
            std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(source))));
        break;
    case Operation::int_to_char: value = static_cast<std::uint16_t>(source); break;
    case Operation::int_to_short:
        value = static_cast<std::uint32_t>(static_cast<std::int32_t>(
            std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(source))));
        break;
    }
    return DexIntegerConversionResult{value, static_cast<std::uint8_t>(result_width)};
}

struct DexFloatingConversionResult {
    std::uint64_t value = 0;
    std::uint8_t result_width = 32;
    bool operator==(const DexFloatingConversionResult &) const = default;
};

namespace dex_float_detail {
struct Format {
    unsigned width;
    unsigned fraction_bits;
    unsigned exponent_bits;
    int bias;
};
inline constexpr Format f32{32, 23, 8, 127};
inline constexpr Format f64{64, 52, 11, 1023};

constexpr std::uint64_t width_mask(unsigned width) noexcept {
    return width == 64 ? UINT64_MAX : ((UINT64_C(1) << width) - 1);
}
constexpr std::uint64_t fraction_mask(Format format) noexcept {
    return (UINT64_C(1) << format.fraction_bits) - 1;
}
constexpr std::uint64_t exponent_mask(Format format) noexcept {
    return (UINT64_C(1) << format.exponent_bits) - 1;
}

inline std::uint64_t round_right_even(std::uint64_t value, unsigned shift) noexcept {
    if (!shift) return value;
    if (shift > 64) return 0;
    if (shift == 64) {
        const auto halfway = UINT64_C(1) << 63;
        return value > halfway ? 1 : 0;
    }
    const auto quotient = value >> shift;
    const auto remainder = value & ((UINT64_C(1) << shift) - 1);
    const auto halfway = UINT64_C(1) << (shift - 1);
    return quotient + (remainder > halfway || (remainder == halfway && (quotient & 1)) ? 1 : 0);
}

inline std::uint64_t encode_binary(bool negative, std::uint64_t significand, int exponent2,
                                   Format format) noexcept {
    const auto sign = negative ? UINT64_C(1) << (format.width - 1) : 0;
    if (!significand) return sign;
    const int top = 63 - static_cast<int>(std::countl_zero(significand));
    int exponent = top + exponent2;
    const int min_normal = 1 - format.bias;
    const int max_normal = static_cast<int>(exponent_mask(format)) - 1 - format.bias;
    const auto hidden_bit = UINT64_C(1) << format.fraction_bits;
    if (exponent > max_normal)
        return sign | (exponent_mask(format) << format.fraction_bits);

    if (exponent >= min_normal) {
        const int shift = top - static_cast<int>(format.fraction_bits);
        auto rounded = shift > 0 ? round_right_even(significand, static_cast<unsigned>(shift))
                                 : significand << static_cast<unsigned>(-shift);
        if (rounded >= (hidden_bit << 1)) {
            rounded >>= 1;
            ++exponent;
        }
        if (exponent > max_normal)
            return sign | (exponent_mask(format) << format.fraction_bits);
        const auto encoded_exponent = static_cast<std::uint64_t>(exponent + format.bias);
        return sign | (encoded_exponent << format.fraction_bits) | (rounded & fraction_mask(format));
    }

    const int subnormal_shift = (min_normal - static_cast<int>(format.fraction_bits)) - exponent2;
    const auto rounded = subnormal_shift > 0
        ? round_right_even(significand, static_cast<unsigned>(subnormal_shift))
        : significand << static_cast<unsigned>(-subnormal_shift);
    if (rounded >= hidden_bit)
        return sign | (UINT64_C(1) << format.fraction_bits);
    return sign | rounded;
}

inline std::uint64_t integer_to_binary(std::uint64_t source, unsigned source_width,
                                       Format format) noexcept {
    source &= width_mask(source_width);
    const bool negative = ((source >> (source_width - 1)) & 1) != 0;
    const auto magnitude = negative ? (UINT64_C(0) - source) & width_mask(source_width) : source;
    return encode_binary(negative, magnitude, 0, format);
}

inline std::uint64_t convert_binary(std::uint64_t source, Format from, Format to) noexcept {
    source &= width_mask(from.width);
    const bool negative = ((source >> (from.width - 1)) & 1) != 0;
    const auto sign = negative ? UINT64_C(1) << (to.width - 1) : 0;
    const auto source_fraction = source & fraction_mask(from);
    const auto source_exponent = (source >> from.fraction_bits) & exponent_mask(from);
    if (source_exponent == exponent_mask(from)) {
        if (!source_fraction)
            return sign | (exponent_mask(to) << to.fraction_bits);
        auto payload = from.fraction_bits > to.fraction_bits
            ? source_fraction >> (from.fraction_bits - to.fraction_bits)
            : source_fraction << (to.fraction_bits - from.fraction_bits);
        payload &= fraction_mask(to);
        if (!payload) payload = 1;
        return sign | (exponent_mask(to) << to.fraction_bits) | payload;
    }
    std::uint64_t significand = source_fraction;
    int exponent2 = 1 - from.bias - static_cast<int>(from.fraction_bits);
    if (source_exponent) {
        significand |= UINT64_C(1) << from.fraction_bits;
        exponent2 = static_cast<int>(source_exponent) - from.bias - static_cast<int>(from.fraction_bits);
    }
    return encode_binary(negative, significand, exponent2, to);
}

inline std::uint64_t binary_to_signed_integer(std::uint64_t source, Format format,
                                              unsigned result_width) noexcept {
    source &= width_mask(format.width);
    const bool negative = ((source >> (format.width - 1)) & 1) != 0;
    const auto fraction = source & fraction_mask(format);
    const auto exponent_field = (source >> format.fraction_bits) & exponent_mask(format);
    const auto sign_bit = UINT64_C(1) << (result_width - 1);
    const auto result_mask = width_mask(result_width);
    if (exponent_field == exponent_mask(format)) {
        if (fraction) return 0; // Java/Dalvik floating NaN converts to integer zero.
        return negative ? sign_bit : sign_bit - 1;
    }
    if (!exponent_field && !fraction) return 0;
    const int exponent = exponent_field ? static_cast<int>(exponent_field) - format.bias
                                        : 1 - format.bias;
    if (exponent < 0) return 0;
    const auto significand = exponent_field
        ? (UINT64_C(1) << format.fraction_bits) | fraction : fraction;
    if (exponent >= static_cast<int>(result_width - 1)) {
        if (negative && exponent == static_cast<int>(result_width - 1) && !fraction)
            return sign_bit;
        return negative ? sign_bit : sign_bit - 1;
    }
    const int shift = exponent - static_cast<int>(format.fraction_bits);
    const auto magnitude = shift >= 0 ? significand << static_cast<unsigned>(shift)
                                      : significand >> static_cast<unsigned>(-shift);
    return negative ? (UINT64_C(0) - magnitude) & result_mask : magnitude;
}
} // namespace dex_float_detail

// Evaluate decoded neg-float/neg-double and all int/long/float/double
// conversions from raw source bits. IEEE conversion rounding is nearest-even;
// float-to-integer uses Dalvik/Java truncation, NaN-to-zero, and saturation.
inline std::optional<DexFloatingConversionResult> evaluate_dex_floating_conversion(
    const Instruction &instruction, std::uint64_t source) noexcept {
    if (instruction.context.architecture != Architecture::dex || instruction.context.mode != ExecutionMode::dex ||
        instruction.opcode != Opcode::dex || instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.memory_read || instruction.memory_write || instruction.flow != FlowKind::fallthrough)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if (!destination || !input || destination->bank != RegisterBank::dex_vreg ||
        input->bank != RegisterBank::dex_vreg || destination->high_byte || input->high_byte)
        return std::nullopt;

    const auto separator = instruction.mnemonic_override.find(' ');
    const std::string_view name(instruction.mnemonic_override.data(),
        separator == std::string::npos ? instruction.mnemonic_override.size() : separator);
    unsigned source_width = 32;
    unsigned result_width = 32;
    enum class Operation { neg_f32, neg_f64, int_to_f32, int_to_f64, long_to_f32, long_to_f64,
                           f32_to_int, f32_to_long, f32_to_f64, f64_to_int, f64_to_long, f64_to_f32 } operation;
    if (name == "neg-float") operation = Operation::neg_f32;
    else if (name == "neg-double") { operation = Operation::neg_f64; source_width = result_width = 64; }
    else if (name == "int-to-float") operation = Operation::int_to_f32;
    else if (name == "int-to-double") { operation = Operation::int_to_f64; result_width = 64; }
    else if (name == "long-to-float") { operation = Operation::long_to_f32; source_width = 64; }
    else if (name == "long-to-double") { operation = Operation::long_to_f64; source_width = result_width = 64; }
    else if (name == "float-to-int") operation = Operation::f32_to_int;
    else if (name == "float-to-long") { operation = Operation::f32_to_long; result_width = 64; }
    else if (name == "float-to-double") { operation = Operation::f32_to_f64; result_width = 64; }
    else if (name == "double-to-int") { operation = Operation::f64_to_int; source_width = 64; }
    else if (name == "double-to-long") { operation = Operation::f64_to_long; source_width = result_width = 64; }
    else if (name == "double-to-float") { operation = Operation::f64_to_f32; source_width = 64; }
    else return std::nullopt;
    if (input->width != source_width || destination->width != result_width ||
        static_cast<unsigned>(input->index) + source_width / 32 - 1 > UINT16_MAX ||
        static_cast<unsigned>(destination->index) + result_width / 32 - 1 > UINT16_MAX)
        return std::nullopt;

    const auto has_slots = [](const auto &effects, const RegisterOperand &reg) {
        for (unsigned slot = 0; slot < reg.width / 32; ++slot) {
            const RegisterOperand component{RegisterBank::dex_vreg,
                static_cast<std::uint16_t>(reg.index + slot), 32, false};
            if (std::find(effects.begin(), effects.end(), component) == effects.end()) return false;
        }
        return true;
    };
    if (!has_slots(instruction.register_reads, *input) || !has_slots(instruction.register_writes, *destination))
        return std::nullopt;

    using namespace dex_float_detail;
    const auto source_mask = width_mask(source_width);
    source &= source_mask;
    std::uint64_t value = 0;
    switch (operation) {
    case Operation::neg_f32: value = source ^ (UINT64_C(1) << 31); break;
    case Operation::neg_f64: value = source ^ (UINT64_C(1) << 63); break;
    case Operation::int_to_f32: value = integer_to_binary(source, 32, f32); break;
    case Operation::int_to_f64: value = integer_to_binary(source, 32, f64); break;
    case Operation::long_to_f32: value = integer_to_binary(source, 64, f32); break;
    case Operation::long_to_f64: value = integer_to_binary(source, 64, f64); break;
    case Operation::f32_to_int: value = binary_to_signed_integer(source, f32, 32); break;
    case Operation::f32_to_long: value = binary_to_signed_integer(source, f32, 64); break;
    case Operation::f32_to_f64: value = convert_binary(source, f32, f64); break;
    case Operation::f64_to_int: value = binary_to_signed_integer(source, f64, 32); break;
    case Operation::f64_to_long: value = binary_to_signed_integer(source, f64, 64); break;
    case Operation::f64_to_f32: value = convert_binary(source, f64, f32); break;
    }
    return DexFloatingConversionResult{value, static_cast<std::uint8_t>(result_width)};
}

} // namespace hexlab
