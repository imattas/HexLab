#pragma once

#include "hexlab/processors/instruction.hpp"

#include <algorithm>
#include <bit>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <vector>

namespace hexlab {

struct JvmStackManipulationResult {
    std::uint8_t consumed_values = 0;
    // Bottom-to-top permutation of the consumed suffix; each entry indexes
    // the caller's original bottom-to-top category-width span.
    std::vector<std::uint8_t> source_indices;
    bool operator==(const JvmStackManipulationResult &) const = default;
};

// Evaluate decoded JVM stack-manipulation bytecodes from category widths
// (one or two slots) for exactly the consumed suffix, bottom-to-top. The
// returned indices describe the resulting suffix in the same order.
inline std::optional<JvmStackManipulationResult>
evaluate_jvm_stack_manipulation_instruction(const Instruction &instruction,
                                           std::span<const std::uint8_t> category_widths) {
    if (instruction.context.architecture != Architecture::jvm || instruction.context.mode != ExecutionMode::jvm ||
        instruction.opcode != Opcode::jvm || instruction.flow != FlowKind::fallthrough ||
        instruction.length != 1 || !instruction.operands.empty() || !instruction.access.empty() ||
        instruction.memory_read || instruction.memory_write || category_widths.size() > 4)
        return std::nullopt;
    for (const auto width : category_widths)
        if (width != 1 && width != 2) return std::nullopt;

    const auto &name = instruction.mnemonic_override;
    const auto expected_byte = name == "pop" ? 0x57 : name == "pop2" ? 0x58 : name == "dup" ? 0x59 :
        name == "dup_x1" ? 0x5a : name == "dup_x2" ? 0x5b : name == "dup2" ? 0x5c :
        name == "dup2_x1" ? 0x5d : name == "dup2_x2" ? 0x5e : name == "swap" ? 0x5f : 0;
    if (expected_byte == 0 || instruction.bytes[0] != std::byte{static_cast<std::uint8_t>(expected_byte)})
        return std::nullopt;

    JvmStackManipulationResult result;
    result.consumed_values = static_cast<std::uint8_t>(category_widths.size());
    const auto form = [&](std::initializer_list<std::uint8_t> widths,
                          std::initializer_list<std::uint8_t> permutation) {
        if (category_widths.size() != widths.size() ||
            !std::equal(category_widths.begin(), category_widths.end(), widths.begin()))
            return false;
        result.source_indices.assign(permutation.begin(), permutation.end());
        return true;
    };
    if (name == "pop") {
        if (!form({1}, {})) return std::nullopt;
    } else if (name == "pop2") {
        if (!form({2}, {}) && !form({1, 1}, {})) return std::nullopt;
    } else if (name == "dup") {
        if (!form({1}, {0, 0})) return std::nullopt;
    } else if (name == "dup_x1") {
        if (!form({1, 1}, {1, 0, 1})) return std::nullopt;
    } else if (name == "dup_x2") {
        if (!form({2, 1}, {1, 0, 1}) && !form({1, 1, 1}, {2, 0, 1, 2})) return std::nullopt;
    } else if (name == "dup2") {
        if (!form({2}, {0, 0}) && !form({1, 1}, {0, 1, 0, 1})) return std::nullopt;
    } else if (name == "dup2_x1") {
        if (!form({1, 2}, {1, 0, 1}) && !form({1, 1, 1}, {1, 2, 0, 1, 2})) return std::nullopt;
    } else if (name == "dup2_x2") {
        if (!form({2, 2}, {1, 0, 1}) && !form({2, 1, 1}, {1, 2, 0, 1, 2}) &&
            !form({1, 1, 2}, {2, 0, 1, 2}) && !form({1, 1, 1, 1}, {2, 3, 0, 1, 2, 3}))
            return std::nullopt;
    } else if (name == "swap") {
        if (!form({1, 1}, {1, 0})) return std::nullopt;
    } else {
        return std::nullopt;
    }
    return result;
}

struct JvmArrayLengthResult {
    std::uint32_t value = 0;
    bool null_pointer_trap = false;
    bool operator==(const JvmArrayLengthResult &) const = default;
};

// Evaluate decoded iinc/wide iinc from the current local's int bit pattern.
inline std::optional<std::uint32_t> evaluate_jvm_iinc_instruction(
    const Instruction &instruction, std::uint32_t local_value) noexcept {
    if (instruction.context.architecture != Architecture::jvm || instruction.context.mode != ExecutionMode::jvm ||
        instruction.opcode != Opcode::jvm || instruction.flow != FlowKind::fallthrough ||
        instruction.memory_read || instruction.memory_write || instruction.operands.size() != 2 ||
        instruction.access.size() != 2 || instruction.access[0] != OperandAccess::read ||
        instruction.access[1] != OperandAccess::read)
        return std::nullopt;
    const bool wide = instruction.mnemonic_override == "wide iinc";
    if ((!wide && instruction.mnemonic_override != "iinc") || instruction.length != (wide ? 6u : 3u))
        return std::nullopt;
    const auto *index = std::get_if<ImmediateOperand>(&instruction.operands[0]);
    const auto *increment = std::get_if<ImmediateOperand>(&instruction.operands[1]);
    const auto encoded_width = static_cast<std::uint16_t>(wide ? 16 : 8);
    if (!index || !increment || index->encoded_width != encoded_width ||
        index->effective_width != encoded_width || index->is_signed ||
        increment->encoded_width != encoded_width || increment->effective_width != encoded_width ||
        !increment->is_signed || (index->value >> encoded_width) != 0 ||
        (increment->value >> encoded_width) != 0)
        return std::nullopt;
    const auto delta = wide
        ? static_cast<std::int64_t>(std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(increment->value)))
        : static_cast<std::int64_t>(std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(increment->value)));
    return local_value + static_cast<std::uint32_t>(static_cast<std::int32_t>(delta));
}

// Extend a loaded JVM byte/char/short array element to the i32 stack type.
// baload needs the caller to distinguish boolean[] from byte[].
inline std::optional<std::uint32_t> evaluate_jvm_narrow_array_load_instruction(
    const Instruction &instruction, std::uint16_t loaded_bits,
    bool boolean_array = false) noexcept {
    if (instruction.context.architecture != Architecture::jvm || instruction.context.mode != ExecutionMode::jvm ||
        instruction.opcode != Opcode::jvm || instruction.flow != FlowKind::fallthrough ||
        !instruction.operands.empty() || !instruction.access.empty() || instruction.memory_read ||
        instruction.memory_write || instruction.length != 1)
        return std::nullopt;
    if (instruction.mnemonic_override == "baload") {
        if (boolean_array) return static_cast<std::uint8_t>(loaded_bits);
        const auto value = std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(loaded_bits));
        return static_cast<std::uint32_t>(static_cast<std::int32_t>(value));
    }
    if (instruction.mnemonic_override == "caload") return loaded_bits;
    if (instruction.mnemonic_override == "saload") {
        const auto value = std::bit_cast<std::int16_t>(loaded_bits);
        return static_cast<std::uint32_t>(static_cast<std::int32_t>(value));
    }
    return std::nullopt;
}

// Evaluate decoded arraylength with caller-supplied reference nullness and
// length. A null reference reports the JVM NullPointerException edge.
inline std::optional<JvmArrayLengthResult> evaluate_jvm_arraylength_instruction(
    const Instruction &instruction, bool is_null, std::uint32_t array_length) noexcept {
    if (instruction.context.architecture != Architecture::jvm || instruction.context.mode != ExecutionMode::jvm ||
        instruction.opcode != Opcode::jvm || instruction.mnemonic_override != "arraylength" ||
        instruction.flow != FlowKind::fallthrough || !instruction.operands.empty() ||
        !instruction.access.empty() || instruction.memory_read || instruction.memory_write || instruction.length != 1)
        return std::nullopt;
    if (is_null) return JvmArrayLengthResult{0, true};
    if (array_length > static_cast<std::uint32_t>(INT32_MAX)) return std::nullopt;
    return JvmArrayLengthResult{array_length, false};
}

// Evaluate JVM i2b/i2c/i2s from the 32-bit int stack value, returning the
// converted int as its exact 32-bit bit pattern.
inline std::optional<std::uint32_t> evaluate_jvm_narrow_conversion_instruction(
    const Instruction &instruction, std::uint32_t source) noexcept {
    if (instruction.context.architecture != Architecture::jvm || instruction.context.mode != ExecutionMode::jvm ||
        instruction.opcode != Opcode::jvm || instruction.flow != FlowKind::fallthrough ||
        !instruction.operands.empty() || !instruction.access.empty() || instruction.memory_read ||
        instruction.memory_write || instruction.length != 1)
        return std::nullopt;
    if (instruction.mnemonic_override == "i2b") {
        const auto byte = std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(source));
        return static_cast<std::uint32_t>(static_cast<std::int32_t>(byte));
    }
    if (instruction.mnemonic_override == "i2c") return static_cast<std::uint16_t>(source);
    if (instruction.mnemonic_override == "i2s") {
        const auto half = std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(source));
        return static_cast<std::uint32_t>(static_cast<std::int32_t>(half));
    }
    return std::nullopt;
}

// Evaluate JVM i2l/l2i from raw int/long stack bits. The long-to-int result
// is returned zero-extended as an exact 32-bit JVM int bit pattern.
inline std::optional<std::uint64_t> evaluate_jvm_integer_width_conversion_instruction(
    const Instruction &instruction, std::uint64_t source) noexcept {
    if (instruction.context.architecture != Architecture::jvm || instruction.context.mode != ExecutionMode::jvm ||
        instruction.opcode != Opcode::jvm || instruction.flow != FlowKind::fallthrough ||
        !instruction.operands.empty() || !instruction.access.empty() || instruction.memory_read ||
        instruction.memory_write || instruction.length != 1)
        return std::nullopt;
    if (instruction.mnemonic_override == "l2i")
        return static_cast<std::uint32_t>(source);
    if (instruction.mnemonic_override == "i2l") {
        const auto value = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(source));
        return std::bit_cast<std::uint64_t>(static_cast<std::int64_t>(value));
    }
    return std::nullopt;
}

enum class JvmIntegerArithmeticTrap : std::uint8_t { none, divide_by_zero };
struct JvmIntegerArithmeticResult {
    std::uint64_t value = 0;
    std::uint8_t result_width = 32;
    JvmIntegerArithmeticTrap trap = JvmIntegerArithmeticTrap::none;
    bool operator==(const JvmIntegerArithmeticResult &) const = default;
};

// Evaluate JVM wrapping integer arithmetic and bitwise operations from raw
// stack bits. Binary operations consume lhs then rhs; negation uses lhs only.
// Results are returned as exact 32- or 64-bit JVM stack patterns.
inline std::optional<std::uint64_t> evaluate_jvm_integer_arithmetic_instruction(
    const Instruction &instruction, std::uint64_t lhs_bits,
    std::optional<std::uint64_t> rhs_bits = std::nullopt) noexcept {
    if (instruction.context.architecture != Architecture::jvm || instruction.context.mode != ExecutionMode::jvm ||
        instruction.opcode != Opcode::jvm || instruction.flow != FlowKind::fallthrough ||
        !instruction.operands.empty() || !instruction.access.empty() || instruction.memory_read ||
        instruction.memory_write || instruction.length != 1)
        return std::nullopt;
    const auto &name = instruction.mnemonic_override;
    const bool wide = name == "ladd" || name == "lsub" || name == "lmul" || name == "lneg" ||
        name == "land" || name == "lor" || name == "lxor" || name == "lshl" ||
        name == "lshr" || name == "lushr";
    const bool shift = name == "ishl" || name == "ishr" || name == "iushr" ||
        name == "lshl" || name == "lshr" || name == "lushr";
    const bool unary = name == "ineg" || name == "lneg";
    if (name != "iadd" && name != "ladd" && name != "isub" && name != "lsub" &&
        name != "imul" && name != "lmul" && name != "ineg" && name != "lneg" &&
        name != "iand" && name != "land" && name != "ior" && name != "lor" &&
        name != "ixor" && name != "lxor" && name != "ishl" && name != "ishr" &&
        name != "iushr" && name != "lshl" && name != "lshr" && name != "lushr")
        return std::nullopt;
    if (unary == rhs_bits.has_value()) return std::nullopt;
    const auto mask = wide ? UINT64_MAX : UINT64_C(0xffffffff);
    const auto lhs = lhs_bits & mask;
    const auto rhs = rhs_bits.value_or(0) & mask;
    if (shift) {
        const auto count = static_cast<unsigned>(rhs & (wide ? UINT64_C(0x3f) : UINT64_C(0x1f)));
        if (name == "ishl" || name == "lshl") return (lhs << count) & mask;
        if (name == "iushr" || name == "lushr") return lhs >> count;
        if (count == 0) return lhs;
        const auto width = wide ? 64u : 32u;
        auto result = lhs >> count;
        const auto sign_bit = UINT64_C(1) << (width - 1);
        if (lhs & sign_bit)
            result |= mask & ~((UINT64_C(1) << (width - count)) - 1);
        return result & mask;
    }
    if (name == "ineg" || name == "lneg") return (UINT64_C(0) - lhs) & mask;
    if (name == "iadd" || name == "ladd") return (lhs + rhs) & mask;
    if (name == "isub" || name == "lsub") return (lhs - rhs) & mask;
    if (name == "imul" || name == "lmul") return (lhs * rhs) & mask;
    if (name == "iand" || name == "land") return lhs & rhs;
    if (name == "ior" || name == "lor") return lhs | rhs;
    return lhs ^ rhs;
}

// Evaluate decoded JVM idiv/irem/ldiv/lrem from raw stack operand bits.
// Divide-by-zero is reported explicitly; MIN_VALUE/-1 follows JVM wrap rules.
inline std::optional<JvmIntegerArithmeticResult> evaluate_jvm_integer_divide_instruction(
    const Instruction &instruction, std::uint64_t lhs_bits,
    std::uint64_t rhs_bits) noexcept {
    if (instruction.context.architecture != Architecture::jvm || instruction.context.mode != ExecutionMode::jvm ||
        instruction.opcode != Opcode::jvm || instruction.flow != FlowKind::fallthrough ||
        !instruction.operands.empty() || !instruction.access.empty() || instruction.memory_read ||
        instruction.memory_write || instruction.length != 1)
        return std::nullopt;
    const auto &name = instruction.mnemonic_override;
    const bool wide = name == "ldiv" || name == "lrem";
    const bool remainder = name == "irem" || name == "lrem";
    if (name != "idiv" && name != "irem" && name != "ldiv" && name != "lrem")
        return std::nullopt;
    const unsigned width = wide ? 64u : 32u;
    const auto mask = wide ? UINT64_MAX : UINT64_C(0xffffffff);
    lhs_bits &= mask;
    rhs_bits &= mask;
    if (rhs_bits == 0)
        return JvmIntegerArithmeticResult{0, static_cast<std::uint8_t>(width),
                                          JvmIntegerArithmeticTrap::divide_by_zero};
    if (wide) {
        const auto lhs = std::bit_cast<std::int64_t>(lhs_bits);
        const auto rhs = std::bit_cast<std::int64_t>(rhs_bits);
        if (lhs == INT64_MIN && rhs == -1)
            return JvmIntegerArithmeticResult{remainder ? 0 : lhs_bits, 64,
                                              JvmIntegerArithmeticTrap::none};
        const auto value = remainder ? lhs % rhs : lhs / rhs;
        return JvmIntegerArithmeticResult{std::bit_cast<std::uint64_t>(value), 64,
                                          JvmIntegerArithmeticTrap::none};
    }
    const auto lhs = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(lhs_bits));
    const auto rhs = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(rhs_bits));
    if (lhs == INT32_MIN && rhs == -1)
        return JvmIntegerArithmeticResult{remainder ? 0 : static_cast<std::uint32_t>(lhs_bits), 32,
                                          JvmIntegerArithmeticTrap::none};
    const auto value = remainder ? lhs % rhs : lhs / rhs;
    return JvmIntegerArithmeticResult{static_cast<std::uint32_t>(value), 32,
                                      JvmIntegerArithmeticTrap::none};
}

// Evaluate fcmpl/fcmpg/dcmpl/dcmpg from raw IEEE bit patterns. The result is
// the JVM int value -1, 0, or 1; NaN ordering follows the opcode suffix.
inline std::optional<std::int32_t> evaluate_jvm_float_compare_instruction(
    const Instruction &instruction, std::uint64_t lhs, std::uint64_t rhs) noexcept {
    if (instruction.context.architecture != Architecture::jvm || instruction.context.mode != ExecutionMode::jvm ||
        instruction.opcode != Opcode::jvm || instruction.flow != FlowKind::fallthrough ||
        !instruction.operands.empty() || !instruction.access.empty() || instruction.memory_read ||
        instruction.memory_write || instruction.length != 1)
        return std::nullopt;
    const auto &name = instruction.mnemonic_override;
    const bool single = name == "fcmpl" || name == "fcmpg";
    const bool nan_greater = name == "fcmpg" || name == "dcmpg";
    if (!single && name != "dcmpl" && name != "dcmpg") return std::nullopt;
    const unsigned width = single ? 32u : 64u;
    if (single && ((lhs | rhs) >> 32)) return std::nullopt;
    const std::uint64_t exponent_mask = single ? UINT64_C(0x7f800000) : UINT64_C(0x7ff0000000000000);
    const std::uint64_t fraction_mask = single ? UINT64_C(0x007fffff) : UINT64_C(0x000fffffffffffff);
    const std::uint64_t sign_mask = UINT64_C(1) << (width - 1);
    const auto is_nan = [&](std::uint64_t bits) {
        return (bits & exponent_mask) == exponent_mask && (bits & fraction_mask) != 0;
    };
    if (is_nan(lhs) || is_nan(rhs)) return nan_greater ? 1 : -1;
    if ((lhs & ~sign_mask) == 0 && (rhs & ~sign_mask) == 0) return 0; // signed zeros compare equal
    const bool left_negative = (lhs & sign_mask) != 0;
    const bool right_negative = (rhs & sign_mask) != 0;
    if (left_negative != right_negative) return left_negative ? -1 : 1;
    const auto left_magnitude = lhs & ~sign_mask;
    const auto right_magnitude = rhs & ~sign_mask;
    if (left_magnitude == right_magnitude) return 0;
    const bool less = left_negative ? left_magnitude > right_magnitude : left_magnitude < right_magnitude;
    return less ? -1 : 1;
}

// Evaluate JVM lcmp from two raw long stack values. The result is -1, 0, or 1.
inline std::optional<std::int32_t> evaluate_jvm_long_compare_instruction(
    const Instruction &instruction, std::uint64_t lhs_bits, std::uint64_t rhs_bits) noexcept {
    if (instruction.context.architecture != Architecture::jvm || instruction.context.mode != ExecutionMode::jvm ||
        instruction.opcode != Opcode::jvm || instruction.mnemonic_override != "lcmp" ||
        instruction.flow != FlowKind::fallthrough || !instruction.operands.empty() ||
        !instruction.access.empty() || instruction.memory_read || instruction.memory_write || instruction.length != 1)
        return std::nullopt;
    const auto lhs = std::bit_cast<std::int64_t>(lhs_bits);
    const auto rhs = std::bit_cast<std::int64_t>(rhs_bits);
    return lhs < rhs ? -1 : lhs > rhs ? 1 : 0;
}

// Evaluate one decoded JVM int/long shift on raw value and distance bits.
// Results are returned as width-correct 32/64-bit destination patterns.
inline std::optional<std::uint64_t> evaluate_jvm_shift_instruction(
    const Instruction &instruction, std::uint64_t value,
    std::uint64_t shift_distance) noexcept {
    if (instruction.context.architecture != Architecture::jvm || instruction.context.mode != ExecutionMode::jvm ||
        instruction.opcode != Opcode::jvm || instruction.flow != FlowKind::fallthrough ||
        !instruction.operands.empty() || !instruction.access.empty() || instruction.memory_read ||
        instruction.memory_write || instruction.length != 1)
        return std::nullopt;
    const auto &name = instruction.mnemonic_override;
    const bool wide = name == "lshl" || name == "lshr" || name == "lushr";
    const bool left = name == "ishl" || name == "lshl";
    const bool arithmetic = name == "ishr" || name == "lshr";
    const bool logical = name == "iushr" || name == "lushr";
    if (!left && !arithmetic && !logical) return std::nullopt;
    const unsigned width = wide ? 64u : 32u;
    const auto mask = width == 64 ? UINT64_MAX : UINT64_C(0xffffffff);
    const unsigned count = static_cast<unsigned>(shift_distance & (width - 1));
    value &= mask;
    if (left) return (value << count) & mask;
    if (logical) return value >> count;
    if (count == 0) return value;
    auto result = value >> count;
    const auto sign_bit = UINT64_C(1) << (width - 1);
    if (value & sign_bit)
        result |= mask & ~((UINT64_C(1) << (width - count)) - 1);
    return result & mask;
}

// Evaluate JVM ifnull/ifnonnull from caller-supplied reference nullness. The
// decoded relative target is validated but not returned or committed.
inline std::optional<bool> evaluate_jvm_null_branch(
    const Instruction &instruction, bool is_null) noexcept {
    if (instruction.context.architecture != Architecture::jvm || instruction.context.mode != ExecutionMode::jvm ||
        instruction.opcode != Opcode::jvm || instruction.flow != FlowKind::conditional_branch ||
        instruction.operands.size() != 1 || !instruction.direct_target ||
        !std::holds_alternative<RelativeOperand>(instruction.operands[0]))
        return std::nullopt;
    if (instruction.mnemonic_override == "ifnull") return is_null;
    if (instruction.mnemonic_override == "ifnonnull") return !is_null;
    return std::nullopt;
}

// Evaluate if_acmpeq/if_acmpne using caller-supplied reference identity
// tokens. Equal tokens represent the same JVM reference (including null).
inline std::optional<bool> evaluate_jvm_reference_branch(
    const Instruction &instruction, std::uint64_t lhs_identity,
    std::uint64_t rhs_identity) noexcept {
    if (instruction.context.architecture != Architecture::jvm || instruction.context.mode != ExecutionMode::jvm ||
        instruction.opcode != Opcode::jvm || instruction.flow != FlowKind::conditional_branch ||
        instruction.operands.size() != 1 || !instruction.direct_target ||
        !std::holds_alternative<RelativeOperand>(instruction.operands[0]))
        return std::nullopt;
    if (instruction.mnemonic_override == "if_acmpeq") return lhs_identity == rhs_identity;
    if (instruction.mnemonic_override == "if_acmpne") return lhs_identity != rhs_identity;
    return std::nullopt;
}

// Resolve the target selected by decoded tableswitch/lookupswitch for an
// operand-stack int key. The caller performs the dispatch and stack pop.
inline std::optional<Address> evaluate_jvm_switch_instruction(
    const Instruction &instruction, std::int32_t key) noexcept {
    if (instruction.context.architecture != Architecture::jvm || instruction.context.mode != ExecutionMode::jvm ||
        instruction.opcode != Opcode::jvm || instruction.flow != FlowKind::switch_dispatch ||
        !instruction.jvm_switch || !instruction.direct_target ||
        instruction.jvm_switch->default_target != *instruction.direct_target)
        return std::nullopt;
    const auto &table = *instruction.jvm_switch;
    const bool dense = instruction.mnemonic_override == "tableswitch";
    if ((!dense && instruction.mnemonic_override != "lookupswitch") || dense != table.dense)
        return std::nullopt;
    if (dense) {
        if (table.cases.empty()) return std::nullopt;
        const auto first = static_cast<std::int64_t>(table.cases.front().value);
        for (std::size_t index = 0; index < table.cases.size(); ++index)
            if (first + static_cast<std::int64_t>(index) != table.cases[index].value)
                return std::nullopt;
        const auto offset = static_cast<std::int64_t>(key) - first;
        if (offset < 0 || static_cast<std::uint64_t>(offset) >= table.cases.size())
            return table.default_target;
        return table.cases[static_cast<std::size_t>(offset)].target;
    }
    for (std::size_t index = 0; index < table.cases.size(); ++index) {
        if (index && table.cases[index - 1].value >= table.cases[index].value)
            return std::nullopt;
        if (table.cases[index].value == key) return table.cases[index].target;
    }
    return table.default_target;
}

// Evaluate JVM integer conditional branches from operand-stack values. Unary
// ifeq..ifle take one int; if_icmp* take two. The decoded relative target is
// validated but not returned or committed to a program counter.
inline std::optional<bool> evaluate_jvm_integer_branch(
    const Instruction &instruction, std::int32_t lhs,
    std::optional<std::int32_t> rhs = std::nullopt) noexcept {
    if (instruction.context.architecture != Architecture::jvm || instruction.context.mode != ExecutionMode::jvm ||
        instruction.opcode != Opcode::jvm || instruction.flow != FlowKind::conditional_branch ||
        instruction.operands.size() != 1 || !instruction.direct_target ||
        !std::holds_alternative<RelativeOperand>(instruction.operands[0]))
        return std::nullopt;
    bool match = false;
    const auto &name = instruction.mnemonic_override;
    if (!rhs) {
        if (name == "ifeq") match = lhs == 0;
        else if (name == "ifne") match = lhs != 0;
        else if (name == "iflt") match = lhs < 0;
        else if (name == "ifge") match = lhs >= 0;
        else if (name == "ifgt") match = lhs > 0;
        else if (name == "ifle") match = lhs <= 0;
        else return std::nullopt;
    } else {
        if (name == "if_icmpeq") match = lhs == *rhs;
        else if (name == "if_icmpne") match = lhs != *rhs;
        else if (name == "if_icmplt") match = lhs < *rhs;
        else if (name == "if_icmpge") match = lhs >= *rhs;
        else if (name == "if_icmpgt") match = lhs > *rhs;
        else if (name == "if_icmple") match = lhs <= *rhs;
        else return std::nullopt;
    }
    return match;
}

} // namespace hexlab
