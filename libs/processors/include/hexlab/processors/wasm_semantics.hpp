#pragma once

#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/wasm_simd_comparison.hpp"
#include "hexlab/processors/wasm_simd_integer.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <bit>
#include <array>
#include <cmath>
#include <optional>

namespace hexlab {

using WasmV128 = std::array<std::uint8_t, 16>;

// Evaluate deterministic integer lane arithmetic without host signed overflow,
// alignment assumptions, or host-endian reinterpretation. Stack mutation is
// the caller's responsibility; both inputs and the result are raw v128 bits.
inline std::optional<WasmV128> evaluate_wasm_simd_integer_binary_instruction(
    const Instruction &instruction, const WasmV128 &lhs, const WasmV128 &rhs) noexcept {
    if (instruction.context.architecture != Architecture::wasm ||
        instruction.context.mode != ExecutionMode::wasm32 || instruction.opcode != Opcode::wasm ||
        instruction.flow != FlowKind::fallthrough || instruction.length < 2 || instruction.length > 6 ||
        instruction.bytes[0] != std::byte{0xfd} || !instruction.operands.empty() ||
        !instruction.access.empty() || instruction.memory_read || instruction.memory_write)
        return std::nullopt;
    std::uint32_t subopcode = 0;
    bool terminated = false;
    for (unsigned index = 1; index < instruction.length; ++index) {
        const auto byte = std::to_integer<std::uint8_t>(instruction.bytes[index]);
        const auto payload = static_cast<std::uint32_t>(byte & 0x7f);
        if (index == 5 && payload > 15) return std::nullopt;
        subopcode |= payload << ((index - 1) * 7);
        if (!(byte & 0x80)) {
            if (index + 1 != instruction.length) return std::nullopt;
            terminated = true;
            break;
        }
    }
    const auto info = wasm_simd_integer_binary_op(subopcode);
    if (!terminated || !info || instruction.mnemonic_override != info->name) return std::nullopt;
    const auto bits = info->lane_bits;
    const auto bytes = bits / 8;
    const auto mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
    const auto read = [bytes](const WasmV128 &vector, unsigned offset) {
        std::uint64_t value = 0;
        for (unsigned index = 0; index < bytes; ++index)
            value |= static_cast<std::uint64_t>(vector[offset + index]) << (index * 8);
        return value;
    };
    // Signed operations below have lanes at most 32 bits. Conversion uses
    // explicit two's-complement magnitude instead of out-of-range casts.
    const auto signed_lane = [bits, mask](std::uint64_t value) -> std::int64_t {
        return value & (UINT64_C(1) << (bits - 1)) ?
            -static_cast<std::int64_t>((mask - value) + 1) : static_cast<std::int64_t>(value);
    };
    WasmV128 result{};
    for (unsigned offset = 0; offset < 16; offset += bytes) {
        const auto a = read(lhs, offset), b = read(rhs, offset);
        const auto operation = info->operation;
        std::uint64_t value = 0;
        if (operation == "add") value = a + b;
        else if (operation == "sub") value = a - b;
        else if (operation == "mul") value = a * b;
        else if (operation == "min_u") value = std::min(a, b);
        else if (operation == "max_u") value = std::max(a, b);
        else if (operation == "avgr_u") value = (a + b + 1) / 2;
        else if (operation == "add_sat_u") value = std::min(a + b, mask);
        else if (operation == "sub_sat_u") value = a < b ? 0 : a - b;
        else {
            const auto sa = signed_lane(a), sb = signed_lane(b);
            std::int64_t signed_value = 0;
            const auto maximum = static_cast<std::int64_t>((UINT64_C(1) << (bits - 1)) - 1);
            const auto minimum = -maximum - 1;
            if (operation == "min_s") signed_value = std::min(sa, sb);
            else if (operation == "max_s") signed_value = std::max(sa, sb);
            else if (operation == "add_sat_s") signed_value = std::clamp(sa + sb, minimum, maximum);
            else if (operation == "sub_sat_s") signed_value = std::clamp(sa - sb, minimum, maximum);
            else if (operation == "q15mulr_sat_s") {
                const auto product = sa * sb + 16384;
                // Arithmetic right shift by 15, including negative rounding.
                const auto rounded = product >= 0 ? product / 32768 : -((-product + 32767) / 32768);
                signed_value = std::clamp(rounded, minimum, maximum);
            } else return std::nullopt;
            value = static_cast<std::uint64_t>(signed_value);
        }
        value &= mask;
        for (unsigned index = 0; index < bytes; ++index)
            result[offset + index] = static_cast<std::uint8_t>(value >> (index * 8));
    }
    return result;
}

struct WasmSimdLogicalResult {
    WasmV128 vector{};
    std::uint32_t scalar = 0; // Used by v128.any_true; result is 0 or 1.
    bool scalar_result = false;
    bool operator==(const WasmSimdLogicalResult &) const = default;
};

// Evaluate decoded v128 logical operations on the raw 16-byte vectors.
// `rhs` is needed for binary ops and `selector` only for bitselect.
inline std::optional<WasmSimdLogicalResult> evaluate_wasm_simd_logical_instruction(
    const Instruction &instruction, const WasmV128 &lhs,
    const WasmV128 *rhs = nullptr, const WasmV128 *selector = nullptr) noexcept {
    if (instruction.context.architecture != Architecture::wasm ||
        instruction.context.mode != ExecutionMode::wasm32 || instruction.opcode != Opcode::wasm ||
        instruction.flow != FlowKind::fallthrough || instruction.length != 2 ||
        instruction.bytes[0] != std::byte{0xfd} || !instruction.operands.empty() ||
        !instruction.access.empty() || instruction.memory_read || instruction.memory_write)
        return std::nullopt;

    const auto &name = instruction.mnemonic_override;
    const bool binary = name == "v128.and" || name == "v128.andnot" ||
                        name == "v128.or" || name == "v128.xor";
    const bool select = name == "v128.bitselect";
    const bool any = name == "v128.any_true";
    if (name != "v128.not" && !binary && !select && !any)
        return std::nullopt;
    if ((binary && (!rhs || selector)) || (select && (!rhs || !selector)) ||
        ((!binary && !select) && (rhs || selector)))
        return std::nullopt;

    WasmSimdLogicalResult result;
    if (any) {
        result.scalar_result = true;
        result.scalar = std::any_of(lhs.begin(), lhs.end(), [](std::uint8_t byte) { return byte != 0; }) ? 1u : 0u;
        return result;
    }
    for (std::size_t index = 0; index < result.vector.size(); ++index) {
        const auto a = lhs[index];
        const auto b = rhs ? (*rhs)[index] : 0;
        if (name == "v128.not") result.vector[index] = static_cast<std::uint8_t>(~a);
        else if (name == "v128.and") result.vector[index] = static_cast<std::uint8_t>(a & b);
        else if (name == "v128.andnot") result.vector[index] = static_cast<std::uint8_t>(a & static_cast<std::uint8_t>(~b));
        else if (name == "v128.or") result.vector[index] = static_cast<std::uint8_t>(a | b);
        else if (name == "v128.xor") result.vector[index] = static_cast<std::uint8_t>(a ^ b);
        else result.vector[index] = static_cast<std::uint8_t>((a & (*selector)[index]) |
                                                               (b & static_cast<std::uint8_t>(~(*selector)[index])));
    }
    return result;
}

enum class WasmIntegerTrap : std::uint8_t { none, divide_by_zero, signed_overflow };
struct WasmIntegerArithmeticResult {
    std::uint64_t value = 0;
    std::uint8_t result_width = 32;
    WasmIntegerTrap trap = WasmIntegerTrap::none;
    bool operator==(const WasmIntegerArithmeticResult &) const = default;
};

struct WasmMemoryPagesResult {
    std::uint32_t value = 0; // memory.size result, or memory.grow old size / UINT32_MAX on failure.
    std::uint32_t pages_after = 0;
    bool growth_failed = false;
    bool operator==(const WasmMemoryPagesResult &) const = default;
};

// Evaluate decoded MVP memory.size/memory.grow. WebAssembly32 memories are
// limited to 65536 64-KiB pages; growth failure returns -1 without trapping.
inline std::optional<WasmMemoryPagesResult> evaluate_wasm_memory_pages_instruction(
    const Instruction &instruction, std::uint32_t current_pages,
    std::uint32_t delta_pages = 0, std::uint32_t maximum_pages = 65536) noexcept {
    if (instruction.context.architecture != Architecture::wasm ||
        instruction.context.mode != ExecutionMode::wasm32 || instruction.opcode != Opcode::wasm ||
        instruction.flow != FlowKind::fallthrough || instruction.length < 2 || instruction.length > 6 ||
        !instruction.access.empty() || instruction.memory_read || instruction.memory_write ||
        instruction.operands.size() != 1 || current_pages > 65536 || maximum_pages > 65536 ||
        current_pages > maximum_pages)
        return std::nullopt;
    const auto *memory_index = std::get_if<ImmediateOperand>(&instruction.operands[0]);
    if (!memory_index || memory_index->encoded_width != 32 || memory_index->effective_width != 32 ||
        memory_index->is_signed || memory_index->value != 0)
        return std::nullopt;
    if (instruction.mnemonic_override == "memory.size")
        return WasmMemoryPagesResult{current_pages, current_pages, false};
    if (instruction.mnemonic_override != "memory.grow") return std::nullopt;
    if (delta_pages > maximum_pages - current_pages)
        return WasmMemoryPagesResult{UINT32_MAX, current_pages, true};
    return WasmMemoryPagesResult{current_pages, current_pages + delta_pages, false};
}

// Evaluate decoded i32/i64 add/sub/mul/div/rem operations on raw stack bits.
// WebAssembly traps are returned explicitly rather than raised by the host.
inline std::optional<WasmIntegerArithmeticResult> evaluate_wasm_integer_arithmetic(
    const Instruction &instruction, std::uint64_t lhs_bits,
    std::uint64_t rhs_bits) noexcept {
    if (instruction.context.architecture != Architecture::wasm ||
        instruction.context.mode != ExecutionMode::wasm32 || instruction.opcode != Opcode::wasm ||
        instruction.flow != FlowKind::fallthrough || !instruction.operands.empty() ||
        !instruction.access.empty() || instruction.memory_read || instruction.memory_write ||
        instruction.length != 1)
        return std::nullopt;
    const auto &name = instruction.mnemonic_override;
    if (name.size() <= 4 || (!name.starts_with("i32.") && !name.starts_with("i64.")))
        return std::nullopt;
    const bool wide = name.starts_with("i64.");
    const auto operation = name.substr(4);
    const unsigned width = wide ? 64u : 32u;
    const auto mask = wide ? UINT64_MAX : UINT64_C(0xffffffff);
    lhs_bits &= mask;
    rhs_bits &= mask;
    const auto wrap = [mask](std::uint64_t value) { return value & mask; };
    if (operation == "add") return WasmIntegerArithmeticResult{wrap(lhs_bits + rhs_bits), static_cast<std::uint8_t>(width)};
    if (operation == "sub") return WasmIntegerArithmeticResult{wrap(lhs_bits - rhs_bits), static_cast<std::uint8_t>(width)};
    if (operation == "mul") return WasmIntegerArithmeticResult{wrap(lhs_bits * rhs_bits), static_cast<std::uint8_t>(width)};
    const bool signed_divide = operation == "div_s" || operation == "rem_s";
    const bool unsigned_divide = operation == "div_u" || operation == "rem_u";
    if (!signed_divide && !unsigned_divide) return std::nullopt;
    if (rhs_bits == 0)
        return WasmIntegerArithmeticResult{0, static_cast<std::uint8_t>(width), WasmIntegerTrap::divide_by_zero};
    const bool remainder = operation == "rem_s" || operation == "rem_u";
    if (signed_divide && width == 32) {
        const auto lhs = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(lhs_bits));
        const auto rhs = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(rhs_bits));
        if (lhs == INT32_MIN && rhs == -1) {
            if (remainder) return WasmIntegerArithmeticResult{0, 32};
            return WasmIntegerArithmeticResult{0, 32, WasmIntegerTrap::signed_overflow};
        }
        const auto value = remainder ? lhs % rhs : lhs / rhs;
        return WasmIntegerArithmeticResult{static_cast<std::uint32_t>(value), 32};
    }
    if (signed_divide) {
        const auto lhs = std::bit_cast<std::int64_t>(lhs_bits);
        const auto rhs = std::bit_cast<std::int64_t>(rhs_bits);
        if (lhs == INT64_MIN && rhs == -1) {
            if (remainder) return WasmIntegerArithmeticResult{0, 64};
            return WasmIntegerArithmeticResult{0, 64, WasmIntegerTrap::signed_overflow};
        }
        const auto value = remainder ? lhs % rhs : lhs / rhs;
        return WasmIntegerArithmeticResult{std::bit_cast<std::uint64_t>(value), 64};
    }
    return WasmIntegerArithmeticResult{remainder ? lhs_bits % rhs_bits : lhs_bits / rhs_bits,
                                       static_cast<std::uint8_t>(width)};
}

// Evaluate i32/i64 bitwise, shift, and rotate operations on raw stack bits.
inline std::optional<WasmIntegerArithmeticResult> evaluate_wasm_integer_bitwise(
    const Instruction &instruction, std::uint64_t lhs_bits,
    std::uint64_t rhs_bits) noexcept {
    if (instruction.context.architecture != Architecture::wasm ||
        instruction.context.mode != ExecutionMode::wasm32 || instruction.opcode != Opcode::wasm ||
        instruction.flow != FlowKind::fallthrough || !instruction.operands.empty() ||
        !instruction.access.empty() || instruction.memory_read || instruction.memory_write ||
        instruction.length != 1)
        return std::nullopt;
    const auto &name = instruction.mnemonic_override;
    if (name.size() <= 4 || (!name.starts_with("i32.") && !name.starts_with("i64.")))
        return std::nullopt;
    const bool wide = name.starts_with("i64.");
    const auto operation = name.substr(4);
    const unsigned width = wide ? 64u : 32u;
    const auto mask = wide ? UINT64_MAX : UINT64_C(0xffffffff);
    lhs_bits &= mask;
    rhs_bits &= mask;
    if (operation == "and") return WasmIntegerArithmeticResult{lhs_bits & rhs_bits, static_cast<std::uint8_t>(width)};
    if (operation == "or") return WasmIntegerArithmeticResult{lhs_bits | rhs_bits, static_cast<std::uint8_t>(width)};
    if (operation == "xor") return WasmIntegerArithmeticResult{lhs_bits ^ rhs_bits, static_cast<std::uint8_t>(width)};
    const unsigned count = static_cast<unsigned>(rhs_bits) & (width - 1);
    if (operation == "shl")
        return WasmIntegerArithmeticResult{(lhs_bits << count) & mask, static_cast<std::uint8_t>(width)};
    if (operation == "shr_u")
        return WasmIntegerArithmeticResult{lhs_bits >> count, static_cast<std::uint8_t>(width)};
    if (operation == "shr_s") {
        std::uint64_t result = lhs_bits;
        if (count != 0) {
            result >>= count;
            if (lhs_bits & (UINT64_C(1) << (width - 1)))
                result |= mask & ~((UINT64_C(1) << (width - count)) - 1);
        }
        return WasmIntegerArithmeticResult{result & mask, static_cast<std::uint8_t>(width)};
    }
    if (operation == "rotl" || operation == "rotr") {
        if (wide) {
            const auto value = std::rotl(lhs_bits, static_cast<int>(count));
            return WasmIntegerArithmeticResult{operation == "rotl" ? value : std::rotr(lhs_bits, static_cast<int>(count)), 64};
        }
        const auto value = std::rotl(static_cast<std::uint32_t>(lhs_bits), static_cast<int>(count));
        return WasmIntegerArithmeticResult{operation == "rotl" ? value :
            std::rotr(static_cast<std::uint32_t>(lhs_bits), static_cast<int>(count)), 32};
    }
    return std::nullopt;
}

// Evaluate i32/i64 integer comparisons. WebAssembly booleans are i32 0/1.
inline std::optional<std::uint32_t> evaluate_wasm_integer_comparison(
    const Instruction &instruction, std::uint64_t lhs_bits,
    std::uint64_t rhs_bits = 0) noexcept {
    if (instruction.context.architecture != Architecture::wasm ||
        instruction.context.mode != ExecutionMode::wasm32 || instruction.opcode != Opcode::wasm ||
        instruction.flow != FlowKind::fallthrough || !instruction.operands.empty() ||
        !instruction.access.empty() || instruction.memory_read || instruction.memory_write ||
        instruction.length != 1)
        return std::nullopt;
    const auto &name = instruction.mnemonic_override;
    if (name.size() <= 4 || (!name.starts_with("i32.") && !name.starts_with("i64.")))
        return std::nullopt;
    const bool wide = name.starts_with("i64.");
    const auto operation = name.substr(4);
    const auto mask = wide ? UINT64_MAX : UINT64_C(0xffffffff);
    lhs_bits &= mask;
    rhs_bits &= mask;
    bool result = false;
    if (operation == "eqz") result = lhs_bits == 0;
    else if (operation == "eq") result = lhs_bits == rhs_bits;
    else if (operation == "ne") result = lhs_bits != rhs_bits;
    else if (operation == "lt_u") result = lhs_bits < rhs_bits;
    else if (operation == "gt_u") result = lhs_bits > rhs_bits;
    else if (operation == "le_u") result = lhs_bits <= rhs_bits;
    else if (operation == "ge_u") result = lhs_bits >= rhs_bits;
    else if (operation == "lt_s" || operation == "gt_s" || operation == "le_s" || operation == "ge_s") {
        if (wide) {
            const auto lhs = std::bit_cast<std::int64_t>(lhs_bits);
            const auto rhs = std::bit_cast<std::int64_t>(rhs_bits);
            if (operation == "lt_s") result = lhs < rhs;
            else if (operation == "gt_s") result = lhs > rhs;
            else if (operation == "le_s") result = lhs <= rhs;
            else result = lhs >= rhs;
        } else {
            const auto lhs = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(lhs_bits));
            const auto rhs = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(rhs_bits));
            if (operation == "lt_s") result = lhs < rhs;
            else if (operation == "gt_s") result = lhs > rhs;
            else if (operation == "le_s") result = lhs <= rhs;
            else result = lhs >= rhs;
        }
    } else return std::nullopt;
    return result ? 1u : 0u;
}

// Evaluate WebAssembly f32/f64 comparisons from raw IEEE bit patterns. NaN
// comparisons are unordered; the result is an i32 boolean.
inline std::optional<std::uint32_t> evaluate_wasm_float_comparison(
    const Instruction &instruction, std::uint64_t lhs_bits,
    std::uint64_t rhs_bits) noexcept {
    if (instruction.context.architecture != Architecture::wasm ||
        instruction.context.mode != ExecutionMode::wasm32 || instruction.opcode != Opcode::wasm ||
        instruction.flow != FlowKind::fallthrough || !instruction.operands.empty() ||
        !instruction.access.empty() || instruction.memory_read || instruction.memory_write ||
        instruction.length != 1)
        return std::nullopt;
    const auto &name = instruction.mnemonic_override;
    const bool single = name.starts_with("f32.");
    const bool wide = name.starts_with("f64.");
    if (!single && !wide) return std::nullopt;
    const auto operation = name.substr(4);
    const unsigned width = single ? 32u : 64u;
    const auto mask = single ? UINT64_C(0xffffffff) : UINT64_MAX;
    const auto sign = UINT64_C(1) << (width - 1);
    const auto exponent = single ? UINT64_C(0x7f800000) : UINT64_C(0x7ff0000000000000);
    const auto fraction = single ? UINT64_C(0x007fffff) : UINT64_C(0x000fffffffffffff);
    lhs_bits &= mask;
    rhs_bits &= mask;
    const auto is_nan = [&](std::uint64_t value) {
        return (value & exponent) == exponent && (value & fraction) != 0;
    };
    const bool unordered = is_nan(lhs_bits) || is_nan(rhs_bits);
    const auto magnitude = [sign](std::uint64_t value) { return value & ~sign; };
    bool equal = false, less = false, greater = false;
    if (!unordered) {
        const auto lhs_magnitude = magnitude(lhs_bits), rhs_magnitude = magnitude(rhs_bits);
        equal = lhs_magnitude == 0 && rhs_magnitude == 0 ? true : lhs_bits == rhs_bits;
        if (!equal) {
            const bool lhs_negative = (lhs_bits & sign) != 0;
            const bool rhs_negative = (rhs_bits & sign) != 0;
            less = lhs_negative != rhs_negative ? lhs_negative
                : lhs_negative ? lhs_magnitude > rhs_magnitude : lhs_magnitude < rhs_magnitude;
            greater = !less;
        }
    }
    if (operation == "eq") return equal ? 1u : 0u;
    if (operation == "ne") return equal ? 0u : 1u;
    if (operation == "lt") return less ? 1u : 0u;
    if (operation == "gt") return greater ? 1u : 0u;
    if (operation == "le") return (less || equal) ? 1u : 0u;
    if (operation == "ge") return (greater || equal) ? 1u : 0u;
    return std::nullopt;
}

// Evaluate the WebAssembly i32/i64 leading-zero, trailing-zero, and
// population-count operations on a caller-supplied raw integer bit pattern.
inline std::optional<std::uint64_t> evaluate_wasm_integer_bit_count(
    const Instruction &instruction, std::uint64_t value) noexcept {
    if (instruction.context.architecture != Architecture::wasm ||
        instruction.context.mode != ExecutionMode::wasm32 || instruction.opcode != Opcode::wasm ||
        instruction.flow != FlowKind::fallthrough || !instruction.operands.empty() ||
        !instruction.access.empty() || instruction.memory_read || instruction.memory_write ||
        instruction.length != 1)
        return std::nullopt;
    const auto &name = instruction.mnemonic_override;
    const bool wide = name == "i64.clz" || name == "i64.ctz" || name == "i64.popcnt";
    const bool leading = name == "i32.clz" || name == "i64.clz";
    const bool trailing = name == "i32.ctz" || name == "i64.ctz";
    const bool population = name == "i32.popcnt" || name == "i64.popcnt";
    if (!leading && !trailing && !population) return std::nullopt;
    if (!wide) value &= UINT32_MAX;
    if (leading) return wide ? std::countl_zero(value) : std::countl_zero(static_cast<std::uint32_t>(value));
    if (trailing) return wide ? std::countr_zero(value) : std::countr_zero(static_cast<std::uint32_t>(value));
    return wide ? std::popcount(value) : std::popcount(static_cast<std::uint32_t>(value));
}

struct WasmIntegerConversionResult {
    std::uint64_t value = 0;
    std::uint8_t result_width = 32;
    bool operator==(const WasmIntegerConversionResult &) const = default;
};

// Evaluate decoded WebAssembly integer wrap/extend and sign-extension
// conversions from a caller-supplied raw operand bit pattern.
inline std::optional<WasmIntegerConversionResult> evaluate_wasm_integer_conversion(
    const Instruction &instruction, std::uint64_t source) noexcept {
    if (instruction.context.architecture != Architecture::wasm ||
        instruction.context.mode != ExecutionMode::wasm32 || instruction.opcode != Opcode::wasm ||
        instruction.flow != FlowKind::fallthrough || !instruction.operands.empty() ||
        !instruction.access.empty() || instruction.memory_read || instruction.memory_write ||
        instruction.length != 1)
        return std::nullopt;
    const auto &name = instruction.mnemonic_override;
    unsigned input_bits = 0, output_bits = 0;
    bool sign_extend = false;
    if (name == "i32.wrap_i64") { input_bits = 64; output_bits = 32; }
    else if (name == "i64.extend_i32_s") { input_bits = 32; output_bits = 64; sign_extend = true; }
    else if (name == "i64.extend_i32_u") { input_bits = 32; output_bits = 64; }
    else if (name == "i32.extend8_s") { input_bits = 8; output_bits = 32; sign_extend = true; }
    else if (name == "i32.extend16_s") { input_bits = 16; output_bits = 32; sign_extend = true; }
    else if (name == "i64.extend8_s") { input_bits = 8; output_bits = 64; sign_extend = true; }
    else if (name == "i64.extend16_s") { input_bits = 16; output_bits = 64; sign_extend = true; }
    else if (name == "i64.extend32_s") { input_bits = 32; output_bits = 64; sign_extend = true; }
    else return std::nullopt;
    const auto input_mask = input_bits == 64 ? UINT64_MAX : (UINT64_C(1) << input_bits) - 1;
    auto value = source & input_mask;
    if (sign_extend && (value & (UINT64_C(1) << (input_bits - 1)))) value |= ~input_mask;
    if (output_bits == 32) value &= UINT32_MAX;
    return WasmIntegerConversionResult{value, static_cast<std::uint8_t>(output_bits)};
}

// Evaluate untyped or supported numeric typed WebAssembly select. `true_value`
// is selected when the i32 condition is nonzero; values are raw 32/64-bit bits.
inline std::optional<std::uint64_t> evaluate_wasm_select(
    const Instruction &instruction, std::uint64_t true_value, std::uint64_t false_value,
    std::uint32_t condition, unsigned value_width) noexcept {
    if (instruction.context.architecture != Architecture::wasm ||
        instruction.context.mode != ExecutionMode::wasm32 || instruction.opcode != Opcode::wasm ||
        instruction.memory_read || instruction.memory_write || !instruction.access.empty())
        return std::nullopt;
    if (instruction.mnemonic_override == "select") {
        if (!instruction.operands.empty() || (value_width != 32 && value_width != 64))
            return std::nullopt;
    } else if (instruction.mnemonic_override == "select_typed") {
        if (value_width != 32 && value_width != 64) return std::nullopt;
        if (instruction.operands.size() != 1) return std::nullopt;
        const auto *type = std::get_if<ImmediateOperand>(&instruction.operands.front());
        if (!type || type->encoded_width != 8 || type->effective_width != 8 || type->is_signed ||
            (type->value != 0x7f && type->value != 0x7e && type->value != 0x7d && type->value != 0x7c) ||
            value_width != ((type->value == 0x7f || type->value == 0x7d) ? 32u : 64u))
            return std::nullopt;
    } else {
        return std::nullopt;
    }
    const auto mask = value_width == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    return (condition ? true_value : false_value) & mask;
}

// Select a structured label depth from a decoded WebAssembly br_table.
// `selector` is the popped i32 index; out-of-range values choose the default
// label. The helper does not resolve label depth to a code address or mutate
// the WebAssembly operand stack.
inline std::optional<std::uint32_t> evaluate_wasm_br_table(
    const Instruction &instruction, std::uint32_t selector) noexcept {
    if (instruction.context.architecture != Architecture::wasm ||
        instruction.context.mode != ExecutionMode::wasm32 || instruction.opcode != Opcode::wasm ||
        instruction.mnemonic_override != "br_table" || instruction.operands.size() < 2)
        return std::nullopt;
    const auto *count = std::get_if<ImmediateOperand>(&instruction.operands.front());
    if (!count || count->encoded_width != 32 || count->effective_width != 32 || count->is_signed ||
        count->value > 12 || instruction.operands.size() != count->value + 2)
        return std::nullopt;
    const auto label_index = selector < count->value
        ? static_cast<std::size_t>(selector) + 1
        : static_cast<std::size_t>(count->value) + 1;
    for (std::size_t index = 1; index < instruction.operands.size(); ++index) {
        const auto *label = std::get_if<ImmediateOperand>(&instruction.operands[index]);
        if (!label || label->encoded_width != 32 || label->effective_width != 32 ||
            label->is_signed || label->value > UINT32_MAX)
            return std::nullopt;
    }
    const auto *label = std::get_if<ImmediateOperand>(&instruction.operands[label_index]);
    return label ? std::optional<std::uint32_t>{static_cast<std::uint32_t>(label->value)} : std::nullopt;
}

// Evaluate the raw-bit sign operations f32/f64.abs, neg, and copysign. These
// bitwise forms preserve all non-sign payload bits, including NaN payloads.
inline std::optional<std::uint64_t> evaluate_wasm_float_sign_operation(
    const Instruction &instruction, std::uint64_t lhs_bits,
    std::uint64_t rhs_bits = 0) noexcept {
    if (instruction.context.architecture != Architecture::wasm ||
        instruction.context.mode != ExecutionMode::wasm32 || instruction.opcode != Opcode::wasm ||
        instruction.flow != FlowKind::fallthrough || !instruction.operands.empty() ||
        !instruction.access.empty() || instruction.memory_read || instruction.memory_write ||
        instruction.length != 1)
        return std::nullopt;
    const auto &name = instruction.mnemonic_override;
    const bool single = name.starts_with("f32.");
    const bool wide = name.starts_with("f64.");
    if (!single && !wide) return std::nullopt;
    const unsigned width = single ? 32u : 64u;
    const auto mask = single ? UINT64_C(0xffffffff) : UINT64_MAX;
    const auto sign = UINT64_C(1) << (width - 1);
    lhs_bits &= mask;
    rhs_bits &= mask;
    if (name == "f32.abs" || name == "f64.abs") return lhs_bits & ~sign;
    if (name == "f32.neg" || name == "f64.neg") return lhs_bits ^ sign;
    if (name == "f32.copysign" || name == "f64.copysign")
        return (lhs_bits & ~sign) | (rhs_bits & sign);
    return std::nullopt;
}

struct WasmSaturatingConversionResult {
    std::uint64_t value = 0; // Integer result as raw two's-complement bits.
    std::uint8_t result_width = 32;
    bool input_nan = false;
    bool saturated = false;
    bool operator==(const WasmSaturatingConversionResult &) const = default;
};

// Evaluate scalar i32/i64.trunc_sat_f32/f64_{s,u}. Conversion truncates
// toward zero; NaN maps to zero, and out-of-range values clamp to the nearest
// representable integer. The source is supplied as raw IEEE bits.
inline std::optional<WasmSaturatingConversionResult>
evaluate_wasm_saturating_float_to_integer(const Instruction &instruction,
                                           std::uint64_t source_bits) noexcept {
    if (instruction.context.architecture != Architecture::wasm ||
        instruction.context.mode != ExecutionMode::wasm32 || instruction.opcode != Opcode::wasm ||
        instruction.flow != FlowKind::fallthrough || !instruction.operands.empty() ||
        !instruction.access.empty() || instruction.memory_read || instruction.memory_write ||
        instruction.length < 2 || instruction.length > 6 || instruction.bytes[0] != std::byte{0xfc})
        return std::nullopt;

    const auto &name = instruction.mnemonic_override;
    const bool to_i32 = name.starts_with("i32.trunc_sat_");
    const bool to_i64 = name.starts_with("i64.trunc_sat_");
    const bool from_f32 = name.ends_with("_f32_s") || name.ends_with("_f32_u");
    const bool from_f64 = name.ends_with("_f64_s") || name.ends_with("_f64_u");
    if ((!to_i32 && !to_i64) || (!from_f32 && !from_f64)) return std::nullopt;
    const bool signed_result = name.ends_with("_s");
    const unsigned output_width = to_i32 ? 32u : 64u;
    const auto output_mask = output_width == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    const double input = from_f32
        ? static_cast<double>(std::bit_cast<float>(static_cast<std::uint32_t>(source_bits)))
        : std::bit_cast<double>(source_bits);
    if (std::isnan(input))
        return WasmSaturatingConversionResult{0, static_cast<std::uint8_t>(output_width), true, false};

    const double modulus = std::ldexp(1.0, static_cast<int>(output_width));
    if (signed_result) {
        const double sign_limit = modulus / 2.0;
        const double minimum = -sign_limit;
        const double maximum_exclusive = sign_limit;
        if (input >= maximum_exclusive)
            return WasmSaturatingConversionResult{(UINT64_C(1) << (output_width - 1)) - 1,
                                                  static_cast<std::uint8_t>(output_width), false, true};
        const double lower_saturation_limit = output_width == 64 ? minimum : minimum - 1.0;
        if ((output_width == 64 && input < lower_saturation_limit) ||
            (output_width == 32 && input <= lower_saturation_limit))
            return WasmSaturatingConversionResult{UINT64_C(1) << (output_width - 1),
                                                  static_cast<std::uint8_t>(output_width), false, true};
        const auto converted = static_cast<std::int64_t>(input);
        return WasmSaturatingConversionResult{static_cast<std::uint64_t>(converted) & output_mask,
                                              static_cast<std::uint8_t>(output_width), false, false};
    }

    if (input >= modulus)
        return WasmSaturatingConversionResult{output_mask, static_cast<std::uint8_t>(output_width), false, true};
    if (input <= -1.0)
        return WasmSaturatingConversionResult{0, static_cast<std::uint8_t>(output_width), false, true};
    const auto converted = static_cast<std::uint64_t>(input);
    return WasmSaturatingConversionResult{converted & output_mask,
                                          static_cast<std::uint8_t>(output_width), false, false};
}

struct WasmSimdLaneResult {
    WasmV128 vector{};             // Used by replace_lane.
    std::uint64_t scalar = 0;      // Extracted lane payload or extended integer.
    std::uint8_t scalar_width = 0; // 32 for i8/i16/i32/f32 extracts, 64 for i64/f64.
    bool scalar_result = false;
    bool operator==(const WasmSimdLaneResult &) const = default;
};

// Evaluate decoded SIMD scalar lane extract/replace instructions. Vector lanes
// use WebAssembly's little-endian byte order; floating lanes are raw payloads.
// For replacement, `scalar` supplies the low bits of the selected lane.
inline std::optional<WasmSimdLaneResult> evaluate_wasm_simd_lane_instruction(
    const Instruction &instruction, const WasmV128 &vector,
    std::uint64_t scalar = 0) noexcept {
    if (instruction.context.architecture != Architecture::wasm ||
        instruction.context.mode != ExecutionMode::wasm32 || instruction.opcode != Opcode::wasm ||
        instruction.flow != FlowKind::fallthrough || instruction.length < 3 ||
        instruction.length > instruction.bytes.size() ||
        instruction.bytes[0] != std::byte{0xfd} || instruction.operands.size() != 1 ||
        !instruction.access.empty() || instruction.memory_read || instruction.memory_write)
        return std::nullopt;

    const auto &name = instruction.mnemonic_override;
    unsigned lane_count = 0;
    unsigned lane_bytes = 0;
    bool extract = false;
    bool sign_extend = false;
    std::uint8_t subopcode = 0;
    if (name == "i8x16.extract_lane_s") { subopcode = 21; lane_count = 16; lane_bytes = 1; extract = true; sign_extend = true; }
    else if (name == "i8x16.extract_lane_u") { subopcode = 22; lane_count = 16; lane_bytes = 1; extract = true; }
    else if (name == "i8x16.replace_lane") { subopcode = 23; lane_count = 16; lane_bytes = 1; }
    else if (name == "i16x8.extract_lane_s") { subopcode = 24; lane_count = 8; lane_bytes = 2; extract = true; sign_extend = true; }
    else if (name == "i16x8.extract_lane_u") { subopcode = 25; lane_count = 8; lane_bytes = 2; extract = true; }
    else if (name == "i16x8.replace_lane") { subopcode = 26; lane_count = 8; lane_bytes = 2; }
    else if (name == "i32x4.extract_lane") { subopcode = 27; lane_count = 4; lane_bytes = 4; extract = true; }
    else if (name == "i32x4.replace_lane") { subopcode = 28; lane_count = 4; lane_bytes = 4; }
    else if (name == "i64x2.extract_lane") { subopcode = 29; lane_count = 2; lane_bytes = 8; extract = true; }
    else if (name == "i64x2.replace_lane") { subopcode = 30; lane_count = 2; lane_bytes = 8; }
    else if (name == "f32x4.extract_lane") { subopcode = 31; lane_count = 4; lane_bytes = 4; extract = true; }
    else if (name == "f32x4.replace_lane") { subopcode = 32; lane_count = 4; lane_bytes = 4; }
    else if (name == "f64x2.extract_lane") { subopcode = 33; lane_count = 2; lane_bytes = 8; extract = true; }
    else if (name == "f64x2.replace_lane") { subopcode = 34; lane_count = 2; lane_bytes = 8; }
    else return std::nullopt;

    const auto *lane = std::get_if<ImmediateOperand>(&instruction.operands[0]);
    if (!lane || lane->encoded_width != 8 || lane->effective_width != 8 || lane->is_signed ||
        lane->encoding || lane->value >= lane_count ||
        std::to_integer<std::uint8_t>(instruction.bytes[instruction.length - 1]) != lane->value)
        return std::nullopt;

    std::uint64_t encoded_subopcode = 0;
    unsigned shift = 0;
    std::size_t cursor = 1;
    bool terminated = false;
    while (cursor < instruction.length - 1 && cursor <= 5) {
        const auto byte = std::to_integer<std::uint8_t>(instruction.bytes[cursor++]);
        const auto payload = static_cast<std::uint64_t>(byte & 0x7f);
        if (shift >= 32 || (shift == 28 && payload >= 16)) return std::nullopt;
        encoded_subopcode |= payload << shift;
        shift += 7;
        if (!(byte & 0x80)) { terminated = true; break; }
    }
    if (!terminated || cursor != instruction.length - 1 || encoded_subopcode != subopcode)
        return std::nullopt;

    const auto offset = static_cast<std::size_t>(lane->value) * lane_bytes;
    std::uint64_t raw = 0;
    for (unsigned index = 0; index < lane_bytes; ++index)
        raw |= static_cast<std::uint64_t>(vector[offset + index]) << (index * 8);

    WasmSimdLaneResult result{vector, 0, 0, extract};
    if (extract) {
        if (sign_extend) {
            const auto bits = lane_bytes * 8;
            const auto sign = UINT64_C(1) << (bits - 1);
            if (raw & sign)
                raw |= UINT32_MAX & ~((UINT64_C(1) << bits) - 1);
        }
        result.scalar = raw;
        result.scalar_width = static_cast<std::uint8_t>(lane_bytes <= 4 ? 32 : 64);
        return result;
    }

    for (unsigned index = 0; index < lane_bytes; ++index)
        result.vector[offset + index] = static_cast<std::uint8_t>(scalar >> (index * 8));
    return result;
}

} // namespace hexlab
