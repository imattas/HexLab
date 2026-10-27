#include "hexlab/processors/x87_semantics.hpp"

#include <bit>
#include <algorithm>

namespace hexlab {
namespace {
constexpr std::uint16_t sign_mask = 0x8000, exponent_mask = 0x7fff;
constexpr std::uint64_t integer_bit = std::uint64_t{1} << 63;
constexpr std::uint64_t quiet_bit = std::uint64_t{1} << 62;
constexpr std::uint16_t fsw_invalid = 1u << 0, fsw_error_summary = 1u << 7;
constexpr std::uint16_t fsw_c0 = 1u << 8, fsw_c1 = 1u << 9, fsw_c2 = 1u << 10;
constexpr std::uint16_t fsw_c3 = 1u << 14, fsw_busy = 1u << 15;
constexpr std::uint16_t fcw_invalid_mask = 1u << 0;
constexpr std::uint16_t fcw_denormal_mask = 1u << 1;
constexpr std::uint16_t fsw_precision = 1u << 5;
constexpr std::uint16_t fsw_overflow = 1u << 3;
constexpr std::uint16_t fsw_denormal = 1u << 1;
constexpr std::uint16_t fsw_underflow = 1u << 4;
constexpr std::uint16_t fcw_underflow_mask = 1u << 4;
constexpr std::uint16_t fcw_precision_mask = 1u << 5;
constexpr std::uint16_t fcw_overflow_mask = 1u << 3;
constexpr std::uint16_t fcw_rounding_mask = 3u << 10;
constexpr std::uint32_t eflags_cf = 1u << 0, eflags_pf = 1u << 2, eflags_af = 1u << 4;
constexpr std::uint32_t eflags_zf = 1u << 6, eflags_sf = 1u << 7, eflags_of = 1u << 11;
constexpr std::uint32_t eflags_compare_mask = eflags_cf | eflags_pf | eflags_af | eflags_zf | eflags_sf | eflags_of;

enum class Class : std::uint8_t { zero, finite, infinity, quiet_nan, signaling_nan, unsupported };
struct Decoded {
    Class kind = Class::unsupported;
    bool negative = false;
    std::uint16_t exponent = 0;
    std::uint64_t significand = 0;
};

Decoded decode(X87Binary80 value) noexcept {
    const auto exponent = static_cast<std::uint16_t>(value.sign_exponent & exponent_mask);
    const bool negative = (value.sign_exponent & sign_mask) != 0;
    const bool integer = (value.significand & integer_bit) != 0;
    if (exponent == exponent_mask) {
        if (!integer) return {Class::unsupported, negative, exponent, value.significand};
        if (value.significand == integer_bit) return {Class::infinity, negative, exponent, value.significand};
        return {(value.significand & quiet_bit) != 0 ? Class::quiet_nan : Class::signaling_nan,
                negative, exponent, value.significand};
    }
    if (exponent == 0) {
        if (value.significand == 0) return {Class::zero, negative, 0, 0};
        // Pseudo-denormals encode the same value as exponent field 1.
        return {Class::finite, negative, static_cast<std::uint16_t>(integer ? 1 : 0), value.significand};
    }
    if (!integer) return {Class::unsupported, negative, exponent, value.significand};
    return {Class::finite, negative, exponent, value.significand};
}

int compare_magnitude(const Decoded &left, const Decoded &right) noexcept {
    if (left.kind == Class::zero) return right.kind == Class::zero ? 0 : -1;
    if (right.kind == Class::zero) return 1;
    const int left_top = static_cast<int>(left.exponent) - 16383 - 63 +
                         (63 - static_cast<int>(std::countl_zero(left.significand)));
    const int right_top = static_cast<int>(right.exponent) - 16383 - 63 +
                          (63 - static_cast<int>(std::countl_zero(right.significand)));
    if (left_top != right_top) return left_top < right_top ? -1 : 1;
    const auto left_normalized = left.significand << std::countl_zero(left.significand);
    const auto right_normalized = right.significand << std::countl_zero(right.significand);
    return left_normalized < right_normalized ? -1 : left_normalized > right_normalized ? 1 : 0;
}

bool is_nan(Class kind) noexcept { return kind == Class::quiet_nan || kind == Class::signaling_nan; }
bool is_invalid_kind(Class kind, X87CompareKind operation) noexcept {
    if (kind == Class::unsupported || kind == Class::signaling_nan) return true;
    const bool unordered = operation == X87CompareKind::fucom || operation == X87CompareKind::fucomi;
    return !unordered && kind == Class::quiet_nan;
}

X87Relation compare_decoded(const Decoded &left, const Decoded &right) noexcept {
    if (left.kind == Class::zero && right.kind == Class::zero) return X87Relation::equal;
    if (left.negative != right.negative)
        return left.negative ? X87Relation::less : X87Relation::greater;
    int magnitude = 0;
    if (left.kind == Class::infinity || right.kind == Class::infinity) {
        magnitude = left.kind == right.kind ? 0 : left.kind == Class::infinity ? 1 : -1;
    } else {
        magnitude = compare_magnitude(left, right);
    }
    if (left.negative) magnitude = -magnitude;
    return magnitude < 0 ? X87Relation::less : magnitude > 0 ? X87Relation::greater : X87Relation::equal;
}

std::uint16_t with_condition_codes(std::uint16_t status, X87Relation relation) noexcept {
    status = static_cast<std::uint16_t>(status & ~(fsw_c0 | fsw_c1 | fsw_c2 | fsw_c3));
    switch (relation) {
    case X87Relation::less: status |= fsw_c0; break;
    case X87Relation::equal: status |= fsw_c3; break;
    case X87Relation::unordered: status |= fsw_c0 | fsw_c2 | fsw_c3; break;
    case X87Relation::greater: break;
    }
    return status;
}

std::uint32_t with_eflags(std::uint32_t flags, X87Relation relation) noexcept {
    flags &= ~eflags_compare_mask;
    switch (relation) {
    case X87Relation::less: flags |= eflags_cf; break;
    case X87Relation::equal: flags |= eflags_zf; break;
    case X87Relation::unordered: flags |= eflags_zf | eflags_pf | eflags_cf; break;
    case X87Relation::greater: break;
    }
    return flags;
}
} // namespace

namespace {
struct RoundedMagnitude {
    std::uint64_t value = 0;
    bool inexact = false;
    bool overflow = false;
    bool incremented = false;
};

RoundedMagnitude round_magnitude(const Decoded &decoded, std::uint8_t rounding,
                                bool truncate) noexcept {
    const int shift = static_cast<int>(decoded.exponent) - 16383 - 63;
    if (decoded.kind == Class::zero) return {};
    if (shift >= 0) {
        if (shift >= 64 || decoded.significand > (UINT64_MAX >> shift))
            return {0, false, true};
        return {decoded.significand << shift, false, false, false};
    }
    const unsigned discarded = static_cast<unsigned>(-shift);
    std::uint64_t integral = 0;
    bool inexact = false, increment = false;
    if (discarded < 64) {
        integral = decoded.significand >> discarded;
        const auto remainder = decoded.significand & ((std::uint64_t{1} << discarded) - 1);
        inexact = remainder != 0;
        if (!truncate && inexact) {
            switch (rounding & 3) {
            case 0: {
                const auto halfway = std::uint64_t{1} << (discarded - 1);
                increment = remainder > halfway || (remainder == halfway && (integral & 1));
                break;
            }
            case 1: increment = decoded.negative; break;
            case 2: increment = !decoded.negative; break;
            default: break;
            }
        }
    } else {
        inexact = decoded.significand != 0;
        if (!truncate && inexact) {
            switch (rounding & 3) {
            case 0: increment = discarded == 64 && decoded.significand > (std::uint64_t{1} << 63); break;
            case 1: increment = decoded.negative; break;
            case 2: increment = !decoded.negative; break;
            default: break;
            }
        }
    }
    if (increment) ++integral;
    return {integral, inexact, false, increment};
}

std::uint16_t signal_exception(std::uint16_t status, std::uint16_t exception) noexcept {
    return static_cast<std::uint16_t>(status | exception | fsw_error_summary | fsw_busy);
}

X87Binary80 x87_indefinite() noexcept {
    return {integer_bit | quiet_bit, static_cast<std::uint16_t>(exponent_mask | sign_mask)};
}

struct BinaryFormat {
    unsigned total_bits, fraction_bits, exponent_bits;
    int bias;
};

constexpr BinaryFormat binary32_format{32, 23, 8, 127};
constexpr BinaryFormat binary64_format{64, 52, 11, 1023};

std::uint64_t width_mask(unsigned width) noexcept {
    return width == 64 ? UINT64_MAX : (std::uint64_t{1} << width) - 1;
}

std::uint64_t sign_field(bool negative, const BinaryFormat &format) noexcept {
    return negative ? std::uint64_t{1} << (format.total_bits - 1) : 0;
}

std::uint64_t infinity_bits(bool negative, const BinaryFormat &format) noexcept {
    const auto exponent = (std::uint64_t{1} << format.exponent_bits) - 1;
    return sign_field(negative, format) | (exponent << format.fraction_bits);
}

std::uint64_t indefinite_bits(const BinaryFormat &format) noexcept {
    const auto quiet = std::uint64_t{1} << (format.fraction_bits - 1);
    return infinity_bits(true, format) | quiet;
}

struct RoundedFormatValue {
    std::uint64_t bits = 0;
    bool inexact = false;
    bool incremented = false;
    bool overflow = false;
    bool underflow = false;
};

bool should_increment(std::uint64_t quotient, std::uint64_t remainder, unsigned shift,
                      bool negative, std::uint8_t rounding) noexcept {
    if (!remainder) return false;
    switch (rounding & 3) {
    case 0:
        if (shift > 64) return false;
        if (shift == 64) {
            const auto halfway = std::uint64_t{1} << 63;
            return remainder > halfway || (remainder == halfway && (quotient & 1));
        }
        if (shift == 0) return false;
        {
            const auto halfway = std::uint64_t{1} << (shift - 1);
            return remainder > halfway || (remainder == halfway && (quotient & 1));
        }
    case 1: return negative; // round toward -infinity
    case 2: return !negative; // round toward +infinity
    default: return false; // chop
    }
}

RoundedFormatValue round_binary80_to_format(const Decoded &decoded, const BinaryFormat &format,
                                             std::uint8_t rounding) noexcept {
    const auto exponent_all_ones = (std::uint64_t{1} << format.exponent_bits) - 1;
    const auto fraction_mask = width_mask(format.fraction_bits);
    const auto exponent_min = 1 - format.bias;
    const auto exponent_max = static_cast<int>(exponent_all_ones - 1) - format.bias;
    const auto precision = format.fraction_bits + 1;
    const auto sign = sign_field(decoded.negative, format);
    if (decoded.kind == Class::zero) return {sign, false, false};
    if (decoded.kind == Class::infinity) return {infinity_bits(decoded.negative, format), false, false};
    if (decoded.kind == Class::quiet_nan || decoded.kind == Class::signaling_nan) {
        const auto payload = (decoded.significand & (integer_bit - 1)) >> (63 - format.fraction_bits);
        const auto quiet = decoded.kind == Class::signaling_nan
            ? std::uint64_t{1} << (format.fraction_bits - 1) : 0;
        return {sign | (exponent_all_ones << format.fraction_bits) | (payload & fraction_mask) | quiet,
                false, false};
    }

    const auto highest = 63u - static_cast<unsigned>(std::countl_zero(decoded.significand));
    const auto normalized = decoded.significand << (63u - highest);
    const auto exponent = (decoded.exponent == 0 ? 1 - 16383 : static_cast<int>(decoded.exponent) - 16383) +
                          static_cast<int>(highest) - 63;
    const auto shift = 63u - precision;
    const auto quotient = normalized >> shift;
    const auto remainder = normalized & ((std::uint64_t{1} << shift) - 1);
    auto rounded = quotient;
    const bool increment = should_increment(quotient, remainder, shift, decoded.negative, rounding);
    if (increment) ++rounded;
    auto rounded_exponent = exponent;
    if (rounded == (std::uint64_t{1} << precision)) {
        rounded >>= 1;
        ++rounded_exponent;
    }
    if (rounded_exponent > exponent_max) {
        bool to_infinity = false;
        switch (rounding & 3) {
        case 0: to_infinity = true; break;
        case 1: to_infinity = decoded.negative; break;
        case 2: to_infinity = !decoded.negative; break;
        default: break;
        }
        const auto bits = to_infinity ? infinity_bits(decoded.negative, format) :
            sign | (static_cast<std::uint64_t>(exponent_all_ones - 1) << format.fraction_bits) | fraction_mask;
        return {bits, true, increment, true, false};
    }
    if (rounded_exponent >= exponent_min) {
        const auto encoded_exponent = static_cast<std::uint64_t>(rounded_exponent + format.bias);
        return {sign | (encoded_exponent << format.fraction_bits) | (rounded & fraction_mask),
                remainder != 0, increment, false, false};
    }

    const auto subnormal_shift = static_cast<unsigned>(63 + exponent_min -
        static_cast<int>(format.fraction_bits) - exponent);
    std::uint64_t subnormal = 0;
    bool inexact = normalized != 0;
    bool subnormal_increment = false;
    if (subnormal_shift < 64) {
        subnormal = normalized >> subnormal_shift;
        const auto sub_remainder = normalized & ((std::uint64_t{1} << subnormal_shift) - 1);
        inexact = sub_remainder != 0;
        subnormal_increment = should_increment(subnormal, sub_remainder, subnormal_shift, decoded.negative, rounding);
        if (subnormal_increment)
            ++subnormal;
    } else {
        subnormal_increment = should_increment(0, normalized, subnormal_shift, decoded.negative, rounding);
        if (subnormal_increment) subnormal = 1;
    }
    if (subnormal >= (std::uint64_t{1} << format.fraction_bits)) {
        // Rounding the largest subnormal upward produces the minimum normal.
        return {sign | (std::uint64_t{1} << format.fraction_bits), inexact, subnormal_increment,
                false, inexact};
    }
    return {sign | subnormal, inexact, subnormal_increment, false, inexact};
}

X87Binary80 quiet_nan(X87Binary80 value) noexcept {
    value.significand |= quiet_bit;
    return value;
}

X87ArithmeticResult invalid_arithmetic(std::uint16_t status, std::uint16_t control,
                                       X87Binary80 masked_value) noexcept {
    X87ArithmeticResult result;
    result.invalid_operation = true;
    result.status_word = static_cast<std::uint16_t>(status & ~fsw_c1);
    if (control & fcw_invalid_mask) {
        result.status_word |= fsw_invalid;
        result.value = masked_value;
    } else {
        result.status_word = signal_exception(result.status_word, fsw_invalid);
        result.completed = false;
    }
    return result;
}

// x87 NaN source selection differs from the usual SIMD first-source rule:
// two same-kind NaNs select the one with the larger significand, while a
// quiet NaN wins over a signaling NaN. Signaling NaNs still raise IE.
bool handle_special_operands(X87Binary80 left, X87Binary80 right,
                             const Decoded &a, const Decoded &b,
                             std::uint16_t control, std::uint16_t status,
                             X87ArithmeticResult &result) noexcept {
    if (a.kind == Class::unsupported || b.kind == Class::unsupported) {
        result = invalid_arithmetic(status, control, x87_indefinite());
        return true;
    }
    const bool a_nan = is_nan(a.kind), b_nan = is_nan(b.kind);
    if (!a_nan && !b_nan) return false;
    const bool signaling = a.kind == Class::signaling_nan || b.kind == Class::signaling_nan;
    X87Binary80 selected = a_nan ? left : right;
    if (a_nan && b_nan) {
        if (a.kind == Class::quiet_nan && b.kind == Class::signaling_nan)
            selected = left;
        else if (b.kind == Class::quiet_nan && a.kind == Class::signaling_nan)
            selected = right;
        else if (right.significand > left.significand)
            selected = right;
    }
    selected = quiet_nan(selected);
    if (signaling)
        result = invalid_arithmetic(status, control, selected);
    else {
        result.status_word = static_cast<std::uint16_t>(status & ~fsw_c1);
        result.value = selected;
    }
    return true;
}

struct Product128 { std::uint64_t hi, lo; };
Product128 shift_right_jam(Product128 value, unsigned amount) noexcept {
    if (!amount) return value;
    if (amount < 64) {
        const auto lost_mask = (std::uint64_t{1} << amount) - 1;
        const bool lost = (value.lo & lost_mask) != 0;
        return {value.hi >> amount,
                (value.lo >> amount) | (value.hi << (64 - amount)) | static_cast<std::uint64_t>(lost)};
    }
    if (amount == 64)
        return {0, value.hi | static_cast<std::uint64_t>(value.lo != 0)};
    if (amount < 128) {
        const auto shift = amount - 64;
        const auto lost_mask = (std::uint64_t{1} << shift) - 1;
        const bool lost = value.lo != 0 || (value.hi & lost_mask) != 0;
        return {0, (value.hi >> shift) | static_cast<std::uint64_t>(lost)};
    }
    return {0, static_cast<std::uint64_t>(value.hi != 0 || value.lo != 0)};
}

Product128 add_wide(Product128 left, Product128 right) noexcept {
    const auto lo = left.lo + right.lo;
    return {left.hi + right.hi + static_cast<std::uint64_t>(lo < left.lo), lo};
}

Product128 subtract_wide(Product128 left, Product128 right) noexcept {
    const auto lo = left.lo - right.lo;
    return {left.hi - right.hi - static_cast<std::uint64_t>(left.lo < right.lo), lo};
}

bool wide_bit(Product128 value, unsigned bit) noexcept {
    return bit < 64 ? ((value.lo >> bit) & 1) != 0
                    : bit < 128 && ((value.hi >> (bit - 64)) & 1) != 0;
}

bool wide_any_below(Product128 value, unsigned bit_count) noexcept {
    if (bit_count >= 128) return value.hi != 0 || value.lo != 0;
    if (bit_count >= 64) {
        const auto high_count = bit_count - 64;
        const auto high_mask = high_count == 0 ? std::uint64_t{0}
            : (std::uint64_t{1} << high_count) - 1;
        return value.lo != 0 || (value.hi & high_mask) != 0;
    }
    const auto low_mask = bit_count == 0 ? std::uint64_t{0}
        : (std::uint64_t{1} << bit_count) - 1;
    return (value.lo & low_mask) != 0;
}

Product128 multiply_u64(std::uint64_t a, std::uint64_t b) noexcept {
    const std::uint64_t a0 = static_cast<std::uint32_t>(a), a1 = a >> 32;
    const std::uint64_t b0 = static_cast<std::uint32_t>(b), b1 = b >> 32;
    const std::uint64_t p00 = a0*b0, p01 = a0*b1, p10 = a1*b0, p11 = a1*b1;
    const std::uint64_t middle = (p00 >> 32) + static_cast<std::uint32_t>(p01) + static_cast<std::uint32_t>(p10);
    return {p11 + (p01 >> 32) + (p10 >> 32) + (middle >> 32),
            (middle << 32) | static_cast<std::uint32_t>(p00)};
}

bool round_up(bool negative, std::uint8_t rc, std::uint64_t retained,
              bool guard, bool sticky) noexcept {
    if (!guard && !sticky) return false;
    switch (rc & 3) {
    case 0: return guard && (sticky || (retained & 1));
    case 1: return negative;
    case 2: return !negative;
    default: return false;
    }
}

struct NormalizedBinary80 {
    std::uint64_t significand = 0;
    int exponent = 0;
};

NormalizedBinary80 normalize_finite(const Decoded &decoded) noexcept {
    auto significand = decoded.significand;
    auto exponent = static_cast<int>(decoded.exponent == 0 ? 1 : decoded.exponent);
    if ((significand & integer_bit) == 0) {
        const auto shift = std::countl_zero(significand);
        significand <<= shift;
        exponent -= static_cast<int>(shift);
    }
    return {significand, exponent};
}

Product128 extended_significand(std::uint64_t significand) noexcept {
    // Three low bits carry guard, round, and sticky information through
    // exponent alignment and cancellation.
    return {significand >> 61, significand << 3};
}

std::uint64_t extended_to_significand(Product128 value) noexcept {
    return (value.hi << 61) | (value.lo >> 3);
}

std::optional<X87ArithmeticResult> round_add_sub_result(
    Product128 extended, int exponent, bool negative,
    const X87AddSubtractRequest &request) noexcept {
    const auto pc = static_cast<std::uint8_t>((request.control_word >> 8) & 3);
    const unsigned precision = pc == 0 ? 24 : pc == 2 ? 53 : 64;
    const unsigned discard = 64 - precision;
    const auto significand = extended_to_significand(extended);
    std::uint64_t retained = significand >> discard;
    bool guard = false;
    bool sticky = false;
    if (discard) {
        guard = ((significand >> (discard - 1)) & 1) != 0;
        const auto discarded_mask = (std::uint64_t{1} << (discard - 1)) - 1;
        sticky = (significand & discarded_mask) != 0 || (extended.lo & 7) != 0;
    } else {
        guard = (extended.lo & 4) != 0;
        sticky = (extended.lo & 3) != 0;
    }
    const bool inexact = guard || sticky;
    const bool increment = round_up(negative,
        static_cast<std::uint8_t>((request.control_word & fcw_rounding_mask) >> 10), retained, guard, sticky);
    const auto precision_max = precision == 64 ? UINT64_MAX : ((std::uint64_t{1} << precision) - 1);
    const bool carry = increment && retained == precision_max;
    if (increment) ++retained;
    if (carry) {
        retained = std::uint64_t{1} << (precision - 1);
        ++exponent;
    }
    const auto rounded_significand = retained << discard;

    X87ArithmeticResult result;
    result.status_word = static_cast<std::uint16_t>(request.status_word & ~fsw_c1);
    if (inexact && (negative != increment)) result.status_word |= fsw_c1;
    const bool overflow = exponent >= 0x7fff;
    if (overflow) {
        result.overflow = true;
        result.precision = true;
        result.status_word |= static_cast<std::uint16_t>((1u << 3) | fsw_precision);
        if ((request.control_word & fcw_overflow_mask) == 0) {
            result.status_word = signal_exception(result.status_word, 1u << 3);
            result.completed = false;
            return result;
        }
        const auto rc = static_cast<std::uint8_t>((request.control_word & fcw_rounding_mask) >> 10);
        const bool infinity = rc == 0 || (rc == 1 && negative) || (rc == 2 && !negative);
        result.value = infinity ? X87Binary80{integer_bit, static_cast<std::uint16_t>(0x7fff | (negative ? sign_mask : 0))}
                                : X87Binary80{UINT64_MAX, static_cast<std::uint16_t>(0x7ffe | (negative ? sign_mask : 0))};
        if ((request.control_word & fcw_precision_mask) == 0) {
            result.status_word = signal_exception(result.status_word, fsw_precision);
            result.completed = false;
        }
        return result;
    }
    if (exponent <= 0) {
        // `extended` carries the normalized significand plus three low GRS
        // bits. Shift it directly to the binary80 subnormal quantum, then
        // account for PC by discarding additional low bits in the same single
        // rounding operation. Earlier operand alignment already jams every
        // bit below the GRS window into bit zero, which remains in `sticky`.
        const int precision_shift = exponent + 63 - static_cast<int>(precision);
        const unsigned subnormal_discard = precision_shift > 0
            ? static_cast<unsigned>(precision_shift) : 0;
        const int signed_shift = 4 - exponent + static_cast<int>(subnormal_discard);
        if (signed_shift <= 0 || signed_shift >= 128) return {};
        const auto shift = static_cast<unsigned>(signed_shift);
        std::uint64_t subnormal_retained = 0;
        if (shift < 64)
            subnormal_retained = (extended.lo >> shift) | (extended.hi << (64 - shift));
        else if (shift == 64)
            subnormal_retained = extended.hi;
        else
            subnormal_retained = extended.hi >> (shift - 64);
        const bool subnormal_guard = wide_bit(extended, shift - 1);
        const bool subnormal_sticky = shift > 1 && wide_any_below(extended, shift - 1);
        const bool subnormal_inexact = subnormal_guard || subnormal_sticky;
        const bool subnormal_increment = round_up(negative,
            static_cast<std::uint8_t>((request.control_word & fcw_rounding_mask) >> 10),
            subnormal_retained, subnormal_guard, subnormal_sticky);
        if (subnormal_increment) ++subnormal_retained;
        const auto fraction = subnormal_retained << subnormal_discard;
        const bool rounded_to_normal = (fraction & integer_bit) != 0;
        const bool tiny = !rounded_to_normal;

        result.status_word &= static_cast<std::uint16_t>(~fsw_c1);
        result.precision = subnormal_inexact;
        result.underflow = tiny && (subnormal_inexact ||
            (request.control_word & fcw_underflow_mask) == 0);
        if (subnormal_inexact) result.status_word |= fsw_precision;
        if (subnormal_inexact && (negative != subnormal_increment)) result.status_word |= fsw_c1;
        if (result.underflow) result.status_word |= fsw_underflow;

        if (result.underflow && (request.control_word & fcw_underflow_mask) == 0) {
            result.status_word = signal_exception(result.status_word, fsw_underflow);
            result.completed = false;
            return result;
        }
        result.value = rounded_to_normal
            ? X87Binary80{integer_bit, static_cast<std::uint16_t>(1 | (negative ? sign_mask : 0))}
            : X87Binary80{fraction, static_cast<std::uint16_t>(negative ? sign_mask : 0)};
        if (subnormal_inexact && (request.control_word & fcw_precision_mask) == 0) {
            result.status_word = signal_exception(result.status_word, fsw_precision);
            result.completed = false;
        }
        return result;
    }
    if (inexact) result.status_word |= fsw_precision;
    result.precision = inexact;
    result.value = X87Binary80{rounded_significand,
        static_cast<std::uint16_t>(exponent | (negative ? sign_mask : 0))};
    if (inexact && (request.control_word & fcw_precision_mask) == 0) {
        result.status_word = signal_exception(result.status_word, fsw_precision);
        result.completed = false;
        return result;
    }
    return result;
}
} // namespace

X87StackState join_x87_stack_states(const X87StackState &left, const X87StackState &right) noexcept {
    X87StackState result;
    if (left.top == right.top) result.top = left.top;
    for (std::size_t i = 0; i < result.tags.size(); ++i)
        if (left.tags[i] == right.tags[i]) result.tags[i] = left.tags[i];
    return result;
}

X87StackState transfer_x87_stack_state(const X87StackState &input, const Instruction &instruction) noexcept {
    auto result = input;
    if (instruction.flow == FlowKind::call) return {};
    if (instruction.opcode == Opcode::opaque || instruction.opcode == Opcode::x86_opaque) return {};
    if (instruction.opcode != Opcode::x87) return result;
    const auto &name = instruction.mnemonic_override;
    if (name == "fldenv" || name == "frstor") {
        result = {};
        return result;
    }
    if (name == "fninit" || name == "finit" || name == "fnsave") {
        result.top = std::uint8_t{0};
        result.tags.fill(X87Tag::empty);
        return result;
    }
    if (name == "fincstp" || name == "fdecstp") {
        if (result.top) {
            const auto delta = name == "fincstp" ? 1 : 7;
            result.top = static_cast<std::uint8_t>((*result.top + delta) & 7);
        }
        return result;
    }
    const bool writes_tag = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
        [](RegisterOperand reg) { return reg.bank == RegisterBank::x87_tag; });
    const bool frees_tag = name == "ffree" || name == "ffreep";
    if (writes_tag && !instruction.x87_stack_delta && !frees_tag) result.tags.fill(std::nullopt);
    // Explicit ST destinations can change a value's tag class. Invalidate
    // those physical tags before applying any implicit push/pop transition.
    if (result.top) {
        const auto count = std::min(instruction.operands.size(), instruction.access.size());
        for (std::size_t i = 0; i < count; ++i) {
            if (instruction.access[i] == OperandAccess::read) continue;
            const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[i]);
            if (!reg || reg->bank != RegisterBank::x87 || reg->index >= 8) continue;
            auto &tag = result.tags[(*result.top + reg->index) & 7];
            if (frees_tag) tag = X87Tag::empty;
            else tag.reset();
        }
    }
    if (instruction.x87_stack_delta > 0) {
        for (int i = 0; result.top && i < instruction.x87_stack_delta; ++i) {
            result.top = static_cast<std::uint8_t>((*result.top + 7) & 7);
            std::optional<X87Tag> pushed_tag;
            const bool destination_empty = result.tags[*result.top] == X87Tag::empty;
            if (destination_empty) {
                if (name == "fldz") pushed_tag = X87Tag::zero;
                else if (name == "fld1" || name == "fldpi" || name == "fldl2e" || name == "fldln2" ||
                         name == "fldlg2" || name == "fldl2t") pushed_tag = X87Tag::valid;
                else if (name == "fld" && input.top && !instruction.operands.empty()) {
                    const auto *source = std::get_if<RegisterOperand>(&instruction.operands.front());
                    if (source && source->bank == RegisterBank::x87 && source->index < 8)
                        if (const auto source_tag = input.tags[(*input.top + source->index) & 7];
                            source_tag && *source_tag != X87Tag::empty)
                            pushed_tag = source_tag;
                }
            }
            // Unknown payloads stay unknown; a masked overflow can also
            // complete with a special indefinite value.
            result.tags[*result.top] = pushed_tag;
        }
    } else if (instruction.x87_stack_delta < 0) {
        for (int i = 0; result.top && i < -instruction.x87_stack_delta; ++i) {
            result.tags[*result.top] = X87Tag::empty;
            result.top = static_cast<std::uint8_t>((*result.top + 1) & 7);
        }
    }
    return result;
}

std::optional<std::uint8_t> x87_physical_register(const X87StackState &state,
                                                   std::uint8_t logical_st) noexcept {
    if (!state.top || logical_st >= 8) return {};
    return static_cast<std::uint8_t>((*state.top + logical_st) & 7);
}

std::optional<X87Relation> compare_x87_binary80(X87Binary80 left, X87Binary80 right) noexcept {
    const auto a = decode(left), b = decode(right);
    if (a.kind == Class::unsupported || b.kind == Class::unsupported || is_nan(a.kind) || is_nan(b.kind))
        return {};
    return compare_decoded(a, b);
}

std::optional<X87CompareResult> evaluate_x87_compare(const X87CompareRequest &request) noexcept {
    const auto left = decode(request.left), right = decode(request.right);
    const bool invalid = is_invalid_kind(left.kind, request.kind) || is_invalid_kind(right.kind, request.kind);
    const auto relation = (left.kind == Class::unsupported || right.kind == Class::unsupported ||
                           is_nan(left.kind) || is_nan(right.kind))
                              ? X87Relation::unordered
                              : compare_decoded(left, right);
    const bool masked = (request.control_word & fcw_invalid_mask) != 0;
    X87CompareResult result;
    result.relation = relation;
    // C1 is defined as zero for all four comparison forms, including an
    // unmasked invalid exception; C0/C2/C3 are retired below by form.
    result.status_word = static_cast<std::uint16_t>(request.status_word & ~fsw_c1);
    result.invalid_operation = invalid;

    if (invalid) result.status_word |= fsw_invalid;
    if (invalid && !masked) {
        result.status_word |= fsw_error_summary | fsw_busy;
        result.completed = false;
        if (request.kind == X87CompareKind::fcomi || request.kind == X87CompareKind::fucomi)
            result.eflags = request.eflags & ~(eflags_af | eflags_sf | eflags_of);
        return result;
    }

    const bool writes_eflags = request.kind == X87CompareKind::fcomi || request.kind == X87CompareKind::fucomi;
    if (writes_eflags)
        result.eflags = with_eflags(request.eflags, relation);
    else
        result.status_word = with_condition_codes(result.status_word, relation);
    return result;
}

std::optional<X87IntegerConvertResult>
evaluate_x87_to_integer(const X87IntegerConvertRequest &request) noexcept {
    if (request.destination_width != 16 && request.destination_width != 32 &&
        request.destination_width != 64)
        return {};

    const auto decoded = decode(request.value);
    const bool special_invalid = decoded.kind == Class::unsupported ||
        decoded.kind == Class::infinity || is_nan(decoded.kind);
    const auto rounded = special_invalid ? RoundedMagnitude{0, false, true, false} :
        round_magnitude(decoded, static_cast<std::uint8_t>((request.control_word & fcw_rounding_mask) >> 10),
                        request.truncate);
    const std::uint64_t positive_limit = request.destination_width == 64
        ? static_cast<std::uint64_t>(INT64_MAX)
        : (std::uint64_t{1} << (request.destination_width - 1)) - 1;
    const std::uint64_t negative_limit = request.destination_width == 64
        ? (std::uint64_t{1} << 63)
        : (std::uint64_t{1} << (request.destination_width - 1));
    const bool out_of_range = rounded.overflow ||
        (decoded.negative ? rounded.value > negative_limit : rounded.value > positive_limit);
    const bool invalid = special_invalid || out_of_range;
    X87IntegerConvertResult result;
    result.status_word = static_cast<std::uint16_t>(request.status_word & ~fsw_c1);
    result.invalid_operation = invalid;
    if (!request.truncate && rounded.inexact && (decoded.negative != rounded.incremented))
        result.status_word |= fsw_c1;

    if (invalid) {
        result.status_word |= fsw_invalid;
        if ((request.control_word & fcw_invalid_mask) == 0) {
            result.status_word = signal_exception(result.status_word, fsw_invalid);
            result.completed = false;
            return result;
        }
        result.destination_bits = std::uint64_t{1} << (request.destination_width - 1);
        return result;
    }

    const bool precision_unmasked = rounded.inexact && (request.control_word & fcw_precision_mask) == 0;
    if (rounded.inexact) result.status_word |= fsw_precision;
    if (precision_unmasked) {
        result.status_word = signal_exception(result.status_word, fsw_precision);
        result.precision = true;
        result.completed = false;
        return result;
    }

    std::uint64_t bits = rounded.value;
    if (decoded.negative) bits = std::uint64_t{0} - bits;
    if (request.destination_width != 64)
        bits &= (std::uint64_t{1} << request.destination_width) - 1;
    result.destination_bits = bits;
    result.precision = rounded.inexact;
    return result;
}

std::optional<X87RoundToIntegralResult>
evaluate_x87_round_to_integral(const X87RoundToIntegralRequest &request) noexcept {
    const auto decoded = decode(request.value);
    if (decoded.kind != Class::zero && decoded.kind != Class::finite && decoded.kind != Class::infinity)
        return {};

    constexpr std::uint16_t fsw_condition_mask = fsw_c0 | fsw_c2 | fsw_c3;
    X87RoundToIntegralResult result;
    result.status_word_defined_mask = static_cast<std::uint16_t>(~fsw_condition_mask);
    result.status_word = static_cast<std::uint16_t>(request.status_word &
        ~(fsw_condition_mask | fsw_c1));

    // At unbiased exponents of 63 or greater, every finite binary80 value is
    // already integral. Keep its original encoding (including pseudo-forms).
    if (decoded.kind == Class::zero || decoded.kind == Class::infinity ||
        decoded.exponent >= 16383 + 63) {
        result.value = request.value;
        return result;
    }

    const auto rounded = round_magnitude(decoded,
        static_cast<std::uint8_t>((request.control_word & fcw_rounding_mask) >> 10), false);
    if (rounded.overflow) return {};
    result.precision = rounded.inexact;
    if (rounded.inexact) {
        result.status_word |= fsw_precision;
        if (decoded.negative != rounded.incremented) result.status_word |= fsw_c1;
    }
    if (rounded.inexact && (request.control_word & fcw_precision_mask) == 0) {
        result.status_word = signal_exception(result.status_word, fsw_precision);
        result.completed = false;
        return result;
    }

    const bool negative = decoded.negative;
    if (rounded.value == 0) {
        result.value = X87Binary80{0, static_cast<std::uint16_t>(negative ? sign_mask : 0)};
        return result;
    }
    const auto highest_bit = 63u - static_cast<unsigned>(std::countl_zero(rounded.value));
    const auto significand = rounded.value << (63u - highest_bit);
    const auto exponent = static_cast<std::uint16_t>(highest_bit + 16383u);
    result.value = X87Binary80{significand,
        static_cast<std::uint16_t>(exponent | (negative ? sign_mask : 0))};
    return result;
}

std::optional<X87ArithmeticResult> evaluate_x87_multiply(const X87MultiplyRequest &request) noexcept {
    if (((request.control_word >> 8) & 3) == 1) return {};
    const auto a = decode(request.left), b = decode(request.right);
    X87ArithmeticResult special;
    if (handle_special_operands(request.left, request.right, a, b,
                                request.control_word, request.status_word, special))
        return special;
    const bool negative = a.negative != b.negative;
    const auto is_denormal = [](const Decoded &value) noexcept {
        return value.kind == Class::finite && value.exponent == 0 &&
               (value.significand & integer_bit) == 0;
    };
    const bool denormal = is_denormal(a) || is_denormal(b);
    if (denormal && (request.control_word & fcw_denormal_mask) == 0) {
        X87ArithmeticResult result;
        result.status_word = signal_exception(
            static_cast<std::uint16_t>(request.status_word & ~fsw_c1), fsw_denormal);
        result.completed = false;
        return result;
    }
    const auto arithmetic_status = static_cast<std::uint16_t>(request.status_word |
        (denormal ? fsw_denormal : 0));
    if (a.kind == Class::infinity || b.kind == Class::infinity) {
        const auto &other = a.kind == Class::infinity ? b : a;
        if (other.kind == Class::zero)
            return invalid_arithmetic(arithmetic_status, request.control_word, x87_indefinite());
        X87ArithmeticResult result;
        result.status_word = static_cast<std::uint16_t>(arithmetic_status & ~fsw_c1);
        result.value = X87Binary80{integer_bit,
            static_cast<std::uint16_t>(exponent_mask | (negative ? sign_mask : 0))};
        return result;
    }
    if (a.kind == Class::zero || b.kind == Class::zero) {
        X87ArithmeticResult result;
        result.status_word = static_cast<std::uint16_t>(arithmetic_status & ~fsw_c1);
        result.value = X87Binary80{0, static_cast<std::uint16_t>(negative ? sign_mask : 0)};
        return result;
    }
    auto a_sig = a.significand, b_sig = b.significand;
    auto a_exp = static_cast<int>(a.exponent == 0 ? 1 : a.exponent);
    auto b_exp = static_cast<int>(b.exponent == 0 ? 1 : b.exponent);
    if ((a_sig & integer_bit) == 0) {
        const auto shift = std::countl_zero(a_sig);
        a_sig <<= shift;
        a_exp -= static_cast<int>(shift);
    }
    if ((b_sig & integer_bit) == 0) {
        const auto shift = std::countl_zero(b_sig);
        b_sig <<= shift;
        b_exp -= static_cast<int>(shift);
    }
    const auto product = multiply_u64(a_sig, b_sig);
    const bool top = (product.hi >> 63) != 0;
    std::uint64_t significand = top ? (product.hi >> 0) : ((product.hi << 1) | (product.lo >> 63));
    const std::uint64_t tail = top ? product.lo : (product.lo << 1);
    const Product128 exact_product{significand, tail};
    int exponent = a_exp + b_exp - 16383 + (top ? 1 : 0);
    const int exact_exponent = exponent;
    const auto pc = static_cast<std::uint8_t>((request.control_word >> 8) & 3);
    const unsigned precision = pc == 0 ? 24 : pc == 2 ? 53 : 64;
    const unsigned discard = 64 - precision;
    std::uint64_t retained = significand >> discard;
    bool guard = false, sticky = tail != 0;
    if (discard) {
        guard = ((significand >> (discard - 1)) & 1) != 0;
        const auto mask = (std::uint64_t{1} << (discard - 1)) - 1;
        sticky = sticky || (significand & mask) != 0;
    } else {
        guard = (tail >> 63) != 0;
        sticky = (tail & (UINT64_MAX >> 1)) != 0;
    }
    const bool inexact = guard || sticky;
    const bool increment = round_up(negative,
        static_cast<std::uint8_t>((request.control_word & fcw_rounding_mask) >> 10), retained, guard, sticky);
    const auto precision_max = precision == 64 ? UINT64_MAX : ((std::uint64_t{1} << precision) - 1);
    const bool carry = increment && retained == precision_max;
    if (increment) ++retained;
    if (carry) {
        retained = std::uint64_t{1} << (precision - 1);
        ++exponent;
    }
    significand = retained << discard;

    X87ArithmeticResult result;
    result.status_word = static_cast<std::uint16_t>(arithmetic_status & ~fsw_c1);
    if (inexact && (negative != increment)) result.status_word |= fsw_c1;
    const bool overflow = exponent >= 0x7fff;
    if (overflow) {
        result.overflow = true;
        result.precision = true;
        result.status_word |= static_cast<std::uint16_t>((1u<<3) | fsw_precision);
        if ((request.control_word & fcw_overflow_mask) == 0) {
            result.status_word = signal_exception(result.status_word, 1u<<3);
            result.completed = false;
            return result;
        }
        const auto rc = static_cast<std::uint8_t>((request.control_word & fcw_rounding_mask) >> 10);
        const bool infinity = rc == 0 || (rc == 1 && negative) || (rc == 2 && !negative);
        result.value = infinity ? X87Binary80{integer_bit, static_cast<std::uint16_t>(0x7fff | (negative ? sign_mask : 0))}
                                : X87Binary80{UINT64_MAX, static_cast<std::uint16_t>(0x7ffe | (negative ? sign_mask : 0))};
        if ((request.control_word & fcw_precision_mask) == 0) {
            result.status_word = signal_exception(result.status_word, fsw_precision);
            result.completed = false;
        }
        return result;
    }
    if (exact_exponent <= 0) {
        // The normalized product is a 128-bit fixed-point value. Shift it
        // into the binary80 subnormal range, then round once at the effective
        // precision. Smaller values have fewer precision bits available, down
        // to the subnormal quantum at fraction bit zero.
        const int precision_shift = exact_exponent + 63 - static_cast<int>(precision);
        const unsigned subnormal_discard = precision_shift > 0
            ? static_cast<unsigned>(precision_shift) : 0;
        const unsigned shift = static_cast<unsigned>(65 - exact_exponent) + subnormal_discard;
        if (shift < 64)
            retained = (exact_product.lo >> shift) | (exact_product.hi << (64 - shift));
        else if (shift == 64)
            retained = exact_product.hi;
        else if (shift < 128)
            retained = exact_product.hi >> (shift - 64);
        else
            retained = 0;
        guard = shift != 0 && wide_bit(exact_product, shift - 1);
        sticky = shift > 1 && wide_any_below(exact_product, shift - 1);
        const bool subnormal_inexact = guard || sticky;
        const bool subnormal_increment = round_up(negative,
            static_cast<std::uint8_t>((request.control_word & fcw_rounding_mask) >> 10),
            retained, guard, sticky);
        if (subnormal_increment) ++retained;
        const auto fraction = retained << subnormal_discard;
        const bool rounded_to_normal = (fraction & integer_bit) != 0;
        const bool tiny = !rounded_to_normal;

        result.status_word &= static_cast<std::uint16_t>(~fsw_c1);
        result.precision = subnormal_inexact;
        result.underflow = tiny && (subnormal_inexact ||
            (request.control_word & fcw_underflow_mask) == 0);
        if (subnormal_inexact) result.status_word |= fsw_precision;
        if (subnormal_inexact && (negative != subnormal_increment)) result.status_word |= fsw_c1;
        if (result.underflow) result.status_word |= fsw_underflow;

        if (result.underflow && (request.control_word & fcw_underflow_mask) == 0) {
            result.status_word = signal_exception(result.status_word, fsw_underflow);
            result.completed = false;
            return result;
        }
        result.value = rounded_to_normal
            ? X87Binary80{integer_bit, static_cast<std::uint16_t>(1 | (negative ? sign_mask : 0))}
            : X87Binary80{fraction, static_cast<std::uint16_t>(negative ? sign_mask : 0)};
        if (subnormal_inexact && (request.control_word & fcw_precision_mask) == 0) {
            result.status_word = signal_exception(result.status_word, fsw_precision);
            result.completed = false;
        }
        return result;
    }
    if (inexact) result.status_word |= fsw_precision;
    result.precision = inexact;
    result.value = X87Binary80{significand, static_cast<std::uint16_t>(exponent | (negative ? sign_mask : 0))};
    if (inexact && (request.control_word & fcw_precision_mask) == 0) {
        result.status_word = signal_exception(result.status_word, fsw_precision);
        result.completed = false;
        return result;
    }
    return result;
}

std::optional<X87ArithmeticResult>
evaluate_x87_add_subtract(const X87AddSubtractRequest &request) noexcept {
    if (((request.control_word >> 8) & 3) == 1 ||
        (request.operation != X87BinaryArithmetic::add &&
         request.operation != X87BinaryArithmetic::subtract))
        return {};
    const auto a = decode(request.left), b = decode(request.right);
    X87ArithmeticResult special;
    if (handle_special_operands(request.left, request.right, a, b,
                                request.control_word, request.status_word, special))
        return special;
    const bool right_negative = b.negative ^ (request.operation == X87BinaryArithmetic::subtract);
    const auto is_subnormal = [](const Decoded &operand) noexcept {
        return operand.kind == Class::finite && operand.exponent == 0 &&
               (operand.significand & integer_bit) == 0;
    };
    const bool denormal = is_subnormal(a) || is_subnormal(b);
    if (denormal && (request.control_word & fcw_denormal_mask) == 0) {
        X87ArithmeticResult result;
        result.status_word = signal_exception(
            static_cast<std::uint16_t>(request.status_word & ~fsw_c1), fsw_denormal);
        result.completed = false;
        return result;
    }
    X87AddSubtractRequest effective_request = request;
    if (denormal) effective_request.status_word |= fsw_denormal;
    if (a.kind == Class::infinity || b.kind == Class::infinity) {
        if (a.kind == Class::infinity && b.kind == Class::infinity &&
            a.negative != right_negative)
            return invalid_arithmetic(effective_request.status_word, request.control_word, x87_indefinite());
        const bool negative = a.kind == Class::infinity ? a.negative : right_negative;
        X87ArithmeticResult result;
        result.status_word = static_cast<std::uint16_t>(effective_request.status_word & ~fsw_c1);
        result.value = X87Binary80{integer_bit,
            static_cast<std::uint16_t>(exponent_mask | (negative ? sign_mask : 0))};
        return result;
    }

    const auto add_denormal_status = [denormal](X87ArithmeticResult result) noexcept {
        if (denormal) result.status_word |= fsw_denormal;
        return result;
    };

    const auto rc = static_cast<std::uint8_t>((request.control_word & fcw_rounding_mask) >> 10);
    if (a.kind == Class::zero && b.kind == Class::zero) {
        const bool negative = a.negative == right_negative ? a.negative : rc == 1;
        X87ArithmeticResult result;
        result.status_word = static_cast<std::uint16_t>(request.status_word & ~fsw_c1);
        result.value = X87Binary80{0, static_cast<std::uint16_t>(negative ? sign_mask : 0)};
        return add_denormal_status(std::move(result));
    }
    if (a.kind == Class::zero || b.kind == Class::zero) {
        const auto &nonzero = a.kind == Class::zero ? b : a;
        const bool negative = a.kind == Class::zero ? right_negative : a.negative;
        const auto normalized = normalize_finite(nonzero);
        auto rounded = round_add_sub_result(
            extended_significand(normalized.significand), normalized.exponent, negative, effective_request);
        if (!rounded) return {};
        return add_denormal_status(std::move(*rounded));
    }

    const auto normalized_a = normalize_finite(a);
    const auto normalized_b = normalize_finite(b);
    const bool b_sign = right_negative;
    const auto compare_magnitude = [](const NormalizedBinary80 &left,
                                      const NormalizedBinary80 &right) noexcept {
        if (left.exponent != right.exponent)
            return left.exponent < right.exponent ? -1 : 1;
        return left.significand < right.significand ? -1 :
               left.significand > right.significand ? 1 : 0;
    };

    const bool same_sign = a.negative == b_sign;
    const NormalizedBinary80 *large = &normalized_a;
    const NormalizedBinary80 *small = &normalized_b;
    bool negative = a.negative;
    const auto magnitude_order = compare_magnitude(normalized_a, normalized_b);
    if (!same_sign && magnitude_order == 0) {
        X87ArithmeticResult result;
        result.status_word = static_cast<std::uint16_t>(request.status_word & ~fsw_c1);
        const bool zero_negative = rc == 1;
        result.value = X87Binary80{0, static_cast<std::uint16_t>(zero_negative ? sign_mask : 0)};
        return add_denormal_status(std::move(result));
    }
    if (magnitude_order < 0) {
        large = &normalized_b;
        small = &normalized_a;
        if (!same_sign) negative = b_sign;
    }

    const auto exponent_difference = static_cast<unsigned>(large->exponent - small->exponent);
    const auto large_extended = extended_significand(large->significand);
    const auto small_extended = shift_right_jam(extended_significand(small->significand),
                                                exponent_difference);
    Product128 combined{};
    int exponent = large->exponent;
    if (same_sign) {
        combined = add_wide(large_extended, small_extended);
        if (wide_bit(combined, 67)) {
            combined = shift_right_jam(combined, 1);
            ++exponent;
        }
    } else {
        combined = subtract_wide(large_extended, small_extended);
        if (!combined.hi && !combined.lo) return {};
        while (!wide_bit(combined, 66)) {
            combined = {static_cast<std::uint64_t>((combined.hi << 1) | (combined.lo >> 63)),
                        combined.lo << 1};
            --exponent;
        }
    }
    auto result = round_add_sub_result(combined, exponent, negative, effective_request);
    if (!result) return {};
    return add_denormal_status(std::move(*result));
}

X87UnaryResult evaluate_x87_unary(X87Binary80 value, std::uint16_t status_word,
                                  X87UnaryArithmetic operation) noexcept {
    if (operation == X87UnaryArithmetic::change_sign)
        value.sign_exponent ^= sign_mask;
    else
        value.sign_exponent &= static_cast<std::uint16_t>(~sign_mask);
    return {value, status_word};
}

std::optional<X87RealLoadResult>
evaluate_x87_load_real(const X87RealLoadRequest &request) noexcept {
    const BinaryFormat *format = request.source_width == 32 ? &binary32_format :
                                 request.source_width == 64 ? &binary64_format : nullptr;
    if (!format || (request.source_width == 32 && (request.source_bits >> 32) != 0)) return {};
    const auto exponent_mask_value = (std::uint64_t{1} << format->exponent_bits) - 1;
    const auto fraction_mask = width_mask(format->fraction_bits);
    const auto bits = request.source_bits & width_mask(format->total_bits);
    const bool negative = ((bits >> (format->total_bits - 1)) & 1) != 0;
    const auto exponent = static_cast<unsigned>((bits >> format->fraction_bits) & exponent_mask_value);
    const auto fraction = bits & fraction_mask;

    X87Binary80 value{};
    value.sign_exponent = static_cast<std::uint16_t>(negative ? sign_mask : 0);
    X87RealLoadResult result;
    result.status_word = static_cast<std::uint16_t>(request.status_word & ~fsw_c1);
    if (exponent == exponent_mask_value) {
        value.sign_exponent |= exponent_mask;
        value.significand = integer_bit | (fraction << (63 - format->fraction_bits));
        if (fraction == 0) {
            value.significand = integer_bit;
        } else {
            const bool signaling = (fraction & (std::uint64_t{1} << (format->fraction_bits - 1))) == 0;
            result.invalid_operation = signaling;
            if (signaling) {
                result.status_word |= fsw_invalid;
                if ((request.control_word & fcw_invalid_mask) == 0) {
                    result.status_word = signal_exception(result.status_word, fsw_invalid);
                    result.completed = false;
                    return result;
                }
                value.significand |= quiet_bit;
            }
        }
        result.value = value;
        return result;
    }

    if (exponent == 0 && fraction == 0) {
        result.value = value;
        return result;
    }
    if (exponent == 0) {
        result.denormal_operand = true;
        result.status_word |= fsw_denormal;
        if ((request.control_word & fcw_denormal_mask) == 0) {
            result.status_word = signal_exception(result.status_word, fsw_denormal);
            result.completed = false;
            return result;
        }
        const auto highest = 63u - static_cast<unsigned>(std::countl_zero(fraction));
        const auto unbiased = static_cast<int>(highest) + 1 - format->bias -
                              static_cast<int>(format->fraction_bits);
        value.significand = fraction << (63u - highest);
        value.sign_exponent |= static_cast<std::uint16_t>(unbiased + 16383);
        result.value = value;
        return result;
    }

    const auto unbiased = static_cast<int>(exponent) - format->bias;
    const auto extended_exponent = unbiased + 16383;
    if (extended_exponent <= 0 || extended_exponent >= exponent_mask) return {};
    value.significand = (std::uint64_t{1} << format->fraction_bits | fraction) <<
                        (63 - format->fraction_bits);
    value.sign_exponent |= static_cast<std::uint16_t>(extended_exponent);
    result.value = value;
    return result;
}

std::optional<X87RealStoreResult>
evaluate_x87_store_real(const X87RealStoreRequest &request) noexcept {
    const BinaryFormat *format = request.destination_width == 32 ? &binary32_format :
                                 request.destination_width == 64 ? &binary64_format : nullptr;
    if (!format) return {};
    const auto decoded = decode(request.value);
    X87RealStoreResult result;
    result.status_word = static_cast<std::uint16_t>(request.status_word & ~fsw_c1);
    const auto signal_invalid = [&]() noexcept {
        result.invalid_operation = true;
        result.status_word |= fsw_invalid;
        if ((request.control_word & fcw_invalid_mask) != 0) {
            result.destination_bits = indefinite_bits(*format);
            return true;
        }
        result.status_word = signal_exception(result.status_word, fsw_invalid);
        result.completed = false;
        return false;
    };

    if (decoded.kind == Class::unsupported) {
        (void)signal_invalid();
        return result;
    }
    if (decoded.kind == Class::signaling_nan) {
        if (!signal_invalid()) return result;
        // A masked signaling NaN is converted to the target's quiet NaN.
        X87Binary80 quieted = request.value;
        quieted.significand |= quiet_bit;
        const auto quiet_decoded = decode(quieted);
        const auto rounded = round_binary80_to_format(quiet_decoded, *format,
            static_cast<std::uint8_t>((request.control_word & fcw_rounding_mask) >> 10));
        result.destination_bits = rounded.bits;
        return result;
    }
    if (decoded.kind == Class::finite && decoded.exponent == 0 &&
        (decoded.significand & integer_bit) == 0) {
        result.denormal_operand = true;
        result.status_word |= fsw_denormal;
        if ((request.control_word & fcw_denormal_mask) == 0) {
            result.status_word = signal_exception(result.status_word, fsw_denormal);
            result.completed = false;
            return result;
        }
    }

    const auto rounded = round_binary80_to_format(decoded, *format,
        static_cast<std::uint8_t>((request.control_word & fcw_rounding_mask) >> 10));
    result.destination_bits = rounded.bits;
    result.overflow = rounded.overflow;
    result.underflow = rounded.underflow;
    result.precision = rounded.inexact;
    if (rounded.inexact && decoded.negative != rounded.incremented)
        result.status_word |= fsw_c1;
    if (rounded.overflow) result.status_word |= fsw_overflow;
    if (rounded.underflow) result.status_word |= fsw_underflow;
    if (rounded.inexact) result.status_word |= fsw_precision;

    if (rounded.overflow && (request.control_word & fcw_overflow_mask) == 0) {
        result.status_word = signal_exception(result.status_word, fsw_overflow);
        result.destination_bits.reset();
        result.completed = false;
    } else if (rounded.underflow && (request.control_word & fcw_underflow_mask) == 0) {
        result.status_word = signal_exception(result.status_word, fsw_underflow);
        result.destination_bits.reset();
        result.completed = false;
    } else if (rounded.inexact && (request.control_word & fcw_precision_mask) == 0) {
        result.status_word = signal_exception(result.status_word, fsw_precision);
        result.destination_bits.reset();
        result.completed = false;
    }
    return result;
}

} // namespace hexlab
