#pragma once

#include "hexlab/processors/decoder.hpp"
#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace hexlab {

using WasmComparisonV128 = std::array<std::uint8_t, 16>;

namespace wasm_simd_comparison_detail {
struct Operation {
    std::string_view mnemonic;
    std::string_view predicate;
    std::uint8_t lane_bits;
    bool is_signed = false;
    bool is_float = false;
};

inline constexpr std::array<std::string_view, 10> integer_predicates{
    "eq", "ne", "lt_s", "gt_s", "le_s", "ge_s", "lt_u", "gt_u", "le_u", "ge_u"};
inline constexpr std::array<std::string_view, 6> float_predicates{
    "eq", "ne", "lt", "gt", "le", "ge"};
inline constexpr std::array<std::string_view, 6> i64_predicates{
    "eq", "ne", "lt_s", "gt_s", "le_s", "ge_s"};

constexpr std::optional<Operation> operation(std::uint32_t opcode) noexcept {
    if (opcode >= 0x23 && opcode <= 0x40) {
        const auto group = (opcode - 0x23) / 10;
        const auto index = (opcode - 0x23) % 10;
        constexpr std::array<std::string_view, 3> mnemonics{"i8x16", "i16x8", "i32x4"};
        constexpr std::array<std::uint8_t, 3> widths{8, 16, 32};
        const auto bits = widths[group];
        const auto predicate = integer_predicates[index];
        return Operation{mnemonics[group], predicate, bits,
                         predicate.ends_with("_s"), false};
    }
    if (opcode >= 0x41 && opcode <= 0x4c) {
        const auto group = (opcode - 0x41) / 6;
        const auto index = (opcode - 0x41) % 6;
        const auto bits = static_cast<std::uint8_t>(group == 0 ? 32 : 64);
        return Operation{group == 0 ? "f32x4" : "f64x2", float_predicates[index], bits, false, true};
    }
    if (opcode >= 0xd6 && opcode <= 0xdb) {
        const auto index = static_cast<std::size_t>(opcode - 0xd6);
        return Operation{"i64x2", i64_predicates[index], 64, index >= 2, false};
    }
    return std::nullopt;
}

inline bool test(std::string_view predicate, std::uint64_t lhs, std::uint64_t rhs,
                 unsigned bits, bool is_signed) noexcept {
    const auto mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
    lhs &= mask;
    rhs &= mask;
    if (predicate == "eq") return lhs == rhs;
    if (predicate == "ne") return lhs != rhs;
    if (predicate.ends_with("_u")) {
        if (predicate.starts_with("lt")) return lhs < rhs;
        if (predicate.starts_with("gt")) return lhs > rhs;
        if (predicate.starts_with("le")) return lhs <= rhs;
        return lhs >= rhs;
    }
    if (is_signed) {
        const auto signed_value = [bits](std::uint64_t value) noexcept -> std::int64_t {
            if (bits == 64) return std::bit_cast<std::int64_t>(value);
            const auto sign = UINT64_C(1) << (bits - 1);
            return (value & sign) ? static_cast<std::int64_t>(value) -
                static_cast<std::int64_t>(UINT64_C(1) << bits) : static_cast<std::int64_t>(value);
        };
        const auto a = signed_value(lhs), b = signed_value(rhs);
        if (predicate.starts_with("lt")) return a < b;
        if (predicate.starts_with("gt")) return a > b;
        if (predicate.starts_with("le")) return a <= b;
        return a >= b;
    }
    return false;
}

inline bool test_float(std::string_view predicate, std::uint64_t lhs, std::uint64_t rhs,
                       unsigned bits) noexcept {
    const std::uint64_t sign = bits == 32 ? UINT64_C(0x80000000) : UINT64_C(0x8000000000000000);
    const std::uint64_t exponent = bits == 32 ? UINT64_C(0x7f800000) : UINT64_C(0x7ff0000000000000);
    const std::uint64_t fraction = bits == 32 ? UINT64_C(0x007fffff) : UINT64_C(0x000fffffffffffff);
    const std::uint64_t width_mask = bits == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    lhs &= width_mask;
    rhs &= width_mask;
    const auto is_nan = [exponent, fraction](std::uint64_t value) noexcept {
        return (value & exponent) == exponent && (value & fraction) != 0;
    };
    if (is_nan(lhs) || is_nan(rhs)) return predicate == "ne";
    // Normalize both signed zeros before mapping IEEE encodings to monotonic
    // unsigned keys. This implements comparisons without host FP/FTZ behavior.
    if ((lhs & ~sign) == 0) lhs = 0;
    if ((rhs & ~sign) == 0) rhs = 0;
    const auto ordered = [sign, width_mask](std::uint64_t value) noexcept {
        return (value & sign) ? ((~value) & width_mask) : (value ^ sign);
    };
    const auto a = ordered(lhs), b = ordered(rhs);
    if (predicate == "eq") return a == b;
    if (predicate == "ne") return a != b;
    if (predicate == "lt") return a < b;
    if (predicate == "gt") return a > b;
    if (predicate == "le") return a <= b;
    return a >= b;
}
} // namespace wasm_simd_comparison_detail

// Evaluate a decoded WebAssembly SIMD comparison using raw little-endian lanes.
// True lanes become all-one bits; false lanes become zero. IEEE comparisons
// follow WebAssembly's quiet unordered rules (only `ne` is true for NaN).
inline std::optional<WasmComparisonV128> evaluate_wasm_simd_comparison_instruction(
    const Instruction &instruction, const WasmComparisonV128 &lhs,
    const WasmComparisonV128 &rhs) noexcept {
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
    const auto info = wasm_simd_comparison_detail::operation(subopcode);
    const auto &mnemonic = instruction.mnemonic_override;
    if (!terminated || !info || mnemonic.size() != info->mnemonic.size() + info->predicate.size() + 1 ||
        mnemonic.compare(0, info->mnemonic.size(), info->mnemonic) != 0 ||
        mnemonic[info->mnemonic.size()] != '.' ||
        mnemonic.compare(info->mnemonic.size() + 1, info->predicate.size(), info->predicate) != 0)
        return std::nullopt;

    const unsigned lane_bytes = info->lane_bits / 8;
    const auto read = [lane_bytes](const WasmComparisonV128 &vector, unsigned offset) noexcept {
        std::uint64_t value = 0;
        for (unsigned i = 0; i < lane_bytes; ++i)
            value |= static_cast<std::uint64_t>(vector[offset + i]) << (i * 8);
        return value;
    };
    const auto lane_mask = info->lane_bits == 64 ? UINT64_MAX :
        (UINT64_C(1) << info->lane_bits) - 1;
    WasmComparisonV128 result{};
    for (unsigned offset = 0; offset < result.size(); offset += lane_bytes) {
        const auto a = read(lhs, offset), b = read(rhs, offset);
        bool matched = false;
        if (info->is_float) {
            matched = wasm_simd_comparison_detail::test_float(info->predicate, a, b, info->lane_bits);
        } else {
            matched = wasm_simd_comparison_detail::test(info->predicate, a, b, info->lane_bits, info->is_signed);
        }
        const auto lane = matched ? lane_mask : UINT64_C(0);
        for (unsigned i = 0; i < lane_bytes; ++i)
            result[offset + i] = static_cast<std::uint8_t>(lane >> (i * 8));
    }
    return result;
}

} // namespace hexlab
