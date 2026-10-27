#include "hexlab/processors/mips32_semantics.hpp"

#include <bit>
#include <cstdint>

namespace hexlab {

std::optional<Mips32HiLoResult> evaluate_mips32_hilo(Mips32HiLoOperation operation, std::uint32_t lhs,
                                                     std::uint32_t rhs) noexcept {
    switch (operation) {
    case Mips32HiLoOperation::mult: {
        const auto product = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(lhs)) *
                             static_cast<std::int64_t>(std::bit_cast<std::int32_t>(rhs));
        const auto bits = std::bit_cast<std::uint64_t>(product);
        return Mips32HiLoResult{static_cast<std::uint32_t>(bits >> 32), static_cast<std::uint32_t>(bits)};
    }
    case Mips32HiLoOperation::multu: {
        const auto product = static_cast<std::uint64_t>(lhs) * rhs;
        return Mips32HiLoResult{static_cast<std::uint32_t>(product >> 32), static_cast<std::uint32_t>(product)};
    }
    case Mips32HiLoOperation::div: {
        const auto dividend = std::bit_cast<std::int32_t>(lhs);
        const auto divisor = std::bit_cast<std::int32_t>(rhs);
        if (divisor == 0 || (dividend == INT32_MIN && divisor == -1))
            return {};
        const auto quotient = dividend / divisor;
        const auto remainder = dividend % divisor;
        return Mips32HiLoResult{std::bit_cast<std::uint32_t>(remainder), std::bit_cast<std::uint32_t>(quotient)};
    }
    case Mips32HiLoOperation::divu:
        if (!rhs)
            return {};
        return Mips32HiLoResult{lhs % rhs, lhs / rhs};
    }
    return {};
}

namespace {
constexpr std::uint8_t fp_inexact = 1u << 0;
constexpr std::uint8_t fp_underflow = 1u << 1;
constexpr std::uint8_t fp_overflow = 1u << 2;
constexpr std::uint8_t fp_divide_by_zero = 1u << 3;
constexpr std::uint8_t fp_invalid = 1u << 4;
constexpr std::uint32_t fcsr_cause_mask = 0x1fu << 12;
constexpr std::uint32_t fcsr_flag_mask = 0x1fu << 2;
constexpr std::uint32_t fcsr_enable_mask = 0x1fu << 7;
constexpr std::uint32_t fcsr_flush_subnormal = 1u << 24;

struct ExactRatio {
    std::uint64_t numerator = 0;
    std::uint32_t denominator = 1;
    int exponent = 0; // value = (numerator / denominator) * 2^exponent
};

bool should_increment(std::uint32_t rounding, bool negative, std::uint64_t remainder,
                      std::uint32_t denominator, std::uint64_t truncated) noexcept {
    if (!remainder) return false;
    switch (rounding) {
    case 0: { // nearest, ties to even
        const auto twice = remainder * 2;
        return twice > denominator || (twice == denominator && (truncated & 1));
    }
    case 1: return false; // toward zero
    case 2: return !negative; // toward +infinity
    case 3: return negative; // toward -infinity
    default: return false;
    }
}

std::uint32_t overflow_result(bool negative, std::uint32_t rounding) noexcept {
    const bool infinity = rounding == 0 || (rounding == 2 && !negative) ||
                          (rounding == 3 && negative);
    return (negative ? 0x80000000u : 0u) | (infinity ? 0x7f800000u : 0x7f7fffffu);
}

void finalize_fcsr(Mips32DivSResult &result, std::uint32_t fcsr) noexcept {
    const auto cause = static_cast<std::uint32_t>(result.exception_bits) << 12;
    const auto enabled = static_cast<std::uint8_t>((fcsr & fcsr_enable_mask) >> 7);
    result.exception_taken = (result.exception_bits & enabled) != 0;
    result.writes_destination = !result.exception_taken;
    result.fcsr_after = (fcsr & ~fcsr_cause_mask) | cause;
    if (!result.exception_taken)
        result.fcsr_after = (result.fcsr_after & ~fcsr_flag_mask) |
                            ((fcsr & fcsr_flag_mask) | (static_cast<std::uint32_t>(result.exception_bits) << 2));
}

std::optional<ExactRatio> normalized_ratio(std::uint32_t lhs_significand, int lhs_exponent,
                                           std::uint32_t rhs_significand, int rhs_exponent) noexcept {
    if (!lhs_significand || !rhs_significand) return {};
    std::uint64_t numerator = lhs_significand;
    std::uint32_t denominator = rhs_significand;
    int exponent = lhs_exponent - rhs_exponent;
    // Normalize the rational significand to [1, 2) without wide arithmetic.
    while (numerator < denominator) { numerator <<= 1; --exponent; }
    while (numerator >= (std::uint64_t(denominator) << 1)) { denominator <<= 1; ++exponent; }
    return ExactRatio{numerator, denominator, exponent};
}
} // namespace

std::optional<Mips32DivSResult> evaluate_mips32_div_s(std::uint32_t lhs_bits,
                                                       std::uint32_t rhs_bits,
                                                       std::uint32_t fcsr) noexcept {
    if (fcsr & fcsr_flush_subnormal) return {};
    constexpr std::uint32_t sign_mask = 0x80000000u;
    constexpr std::uint32_t exponent_mask = 0x7f800000u;
    constexpr std::uint32_t fraction_mask = 0x007fffffu;
    constexpr std::uint32_t quiet_bit = 0x00400000u;
    const bool negative = ((lhs_bits ^ rhs_bits) & sign_mask) != 0;
    const auto sign = negative ? sign_mask : 0u;
    const auto rounding = fcsr & 3u;
    Mips32DivSResult result{};
    const auto lhs_exp = (lhs_bits & exponent_mask) >> 23;
    const auto rhs_exp = (rhs_bits & exponent_mask) >> 23;
    const auto lhs_frac = lhs_bits & fraction_mask;
    const auto rhs_frac = rhs_bits & fraction_mask;
    const bool lhs_nan = lhs_exp == 0xff && lhs_frac != 0;
    const bool rhs_nan = rhs_exp == 0xff && rhs_frac != 0;

    if (lhs_nan || rhs_nan) {
        // Preserve the first NaN payload and quiet it. A signaling NaN raises
        // Invalid even when the other operand is a quiet NaN.
        const auto first = lhs_nan ? lhs_bits : rhs_bits;
        result.value_bits = first | quiet_bit;
        if ((lhs_nan && !(lhs_frac & quiet_bit)) || (rhs_nan && !(rhs_frac & quiet_bit)))
            result.exception_bits |= fp_invalid;
        finalize_fcsr(result, fcsr);
        return result;
    }

    const bool lhs_inf = lhs_exp == 0xff;
    const bool rhs_inf = rhs_exp == 0xff;
    const bool lhs_zero = lhs_exp == 0 && lhs_frac == 0;
    const bool rhs_zero = rhs_exp == 0 && rhs_frac == 0;
    if ((lhs_inf && rhs_inf) || (lhs_zero && rhs_zero)) {
        result.value_bits = 0x7fc00000u;
        result.exception_bits |= fp_invalid;
        finalize_fcsr(result, fcsr);
        return result;
    }
    if (lhs_inf) {
        result.value_bits = sign | exponent_mask;
        finalize_fcsr(result, fcsr);
        return result;
    }
    if (rhs_inf || lhs_zero) {
        result.value_bits = sign;
        finalize_fcsr(result, fcsr);
        return result;
    }
    if (rhs_zero) {
        result.value_bits = sign | exponent_mask;
        result.exception_bits |= fp_divide_by_zero;
        finalize_fcsr(result, fcsr);
        return result;
    }

    const std::uint32_t lhs_significand = lhs_exp ? (0x00800000u | lhs_frac) : lhs_frac;
    const std::uint32_t rhs_significand = rhs_exp ? (0x00800000u | rhs_frac) : rhs_frac;
    const int lhs_binary_exponent = lhs_exp ? static_cast<int>(lhs_exp) - 127 - 23 : -149;
    const int rhs_binary_exponent = rhs_exp ? static_cast<int>(rhs_exp) - 127 - 23 : -149;
    const auto ratio = normalized_ratio(lhs_significand, lhs_binary_exponent,
                                        rhs_significand, rhs_binary_exponent);
    if (!ratio) return {};
    int exponent = ratio->exponent;

    if (exponent > 127) {
        result.value_bits = overflow_result(negative, rounding);
        result.exception_bits |= fp_overflow | fp_inexact;
        finalize_fcsr(result, fcsr);
        return result;
    }

    if (exponent >= -126) {
        const auto scaled = ratio->numerator << 23;
        auto significand = scaled / ratio->denominator;
        const auto remainder = scaled % ratio->denominator;
        const auto exact_greater_than_max = exponent == 127 && significand == 0x00ffffffu && remainder != 0;
        const bool nearest_overflow = exact_greater_than_max && rounding == 0 &&
            remainder * 2 >= ratio->denominator;
        if (exact_greater_than_max && (rounding != 0 || nearest_overflow)) {
            result.value_bits = overflow_result(negative, rounding);
            result.exception_bits |= fp_overflow | fp_inexact;
            finalize_fcsr(result, fcsr);
            return result;
        }
        if (should_increment(rounding, negative, remainder, ratio->denominator, significand))
            ++significand;
        if (remainder) result.exception_bits |= fp_inexact;
        if (significand == 0x01000000u) {
            significand >>= 1;
            ++exponent;
        }
        if (exponent > 127) {
            result.value_bits = overflow_result(negative, rounding);
            result.exception_bits |= fp_overflow | fp_inexact;
        } else {
            result.value_bits = sign | (static_cast<std::uint32_t>(exponent + 127) << 23) |
                                (static_cast<std::uint32_t>(significand) & fraction_mask);
        }
        finalize_fcsr(result, fcsr);
        return result;
    }

    // Subnormal result: scale in units of 2^-149. If the shift is at most 23,
    // the exact numerator remains below 2^48 and fits in uint64_t.
    const auto shift = -126 - exponent;
    std::uint64_t significand = 0;
    std::uint64_t remainder = 1;
    std::uint32_t denominator = ratio->denominator;
    if (shift <= 23) {
        const auto scaled = ratio->numerator << (23 - shift);
        significand = scaled / denominator;
        remainder = scaled % denominator;
        if (should_increment(rounding, negative, remainder, denominator, significand)) ++significand;
    } else if (shift == 24) {
        // The exact value is in [0.5, 1) subnormal units.
        if (rounding == 0) significand = ratio->numerator > denominator ? 1 : 0;
        else if (rounding == 2) significand = negative ? 0 : 1;
        else if (rounding == 3) significand = negative ? 1 : 0;
    } else {
        significand = rounding == 2 && !negative || rounding == 3 && negative ? 1 : 0;
    }
    // For the shift==24 and larger cases every finite nonzero quotient is
    // inexact, including values rounded to signed zero.
    if (shift >= 24 || (shift <= 23 && remainder != 0)) result.exception_bits |= fp_inexact;
    if ((result.exception_bits & fp_inexact) && significand < 0x00800000u)
        result.exception_bits |= fp_underflow;
    result.value_bits = sign | (significand >= 0x00800000u ? 0x00800000u :
                                static_cast<std::uint32_t>(significand));
    finalize_fcsr(result, fcsr);
    return result;
}

std::uint64_t evaluate_mips32_fp_sign_operation(Mips32FpSignOperation operation, bool double_precision,
                                                std::uint64_t operand_bits) noexcept {
    const std::uint64_t sign_mask = double_precision ? (std::uint64_t{1} << 63) : (std::uint64_t{1} << 31);
    const std::uint64_t format_mask = double_precision ? UINT64_MAX : UINT32_MAX;
    const auto value = operand_bits & format_mask;
    switch (operation) {
    case Mips32FpSignOperation::abs: return value & ~sign_mask;
    case Mips32FpSignOperation::mov: return value;
    case Mips32FpSignOperation::neg: return value ^ sign_mask;
    }
    return value;
}

} // namespace hexlab
