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
constexpr std::uint16_t fcw_zero_divide_mask = 1u << 2;
constexpr std::uint16_t fsw_precision = 1u << 5;
constexpr std::uint16_t fsw_overflow = 1u << 3;
constexpr std::uint16_t fsw_denormal = 1u << 1;
constexpr std::uint16_t fsw_zero_divide = 1u << 2;
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

int compare_wide(Product128 left, Product128 right) noexcept {
    if (left.hi != right.hi) return left.hi < right.hi ? -1 : 1;
    return left.lo < right.lo ? -1 : left.lo > right.lo ? 1 : 0;
}

Product128 shift_left_two(Product128 value) noexcept {
    return {(value.hi << 2) | (value.lo >> 62), value.lo << 2};
}

Product128 square_root_extension(std::uint64_t significand, bool odd_exponent,
                                 bool &inexact_tail) noexcept {
    // Stream pairs from M*2^69 (even exponent) or M*2^70 (odd
    // exponent). This computes 67 root bits without constructing a 133-bit
    // radicand: only the 68-bit partial remainder and root are retained.
    const unsigned appended_zeros = odd_exponent ? 70u : 69u;
    const auto radicand_bit = [&](int position) noexcept {
        if (position < 0 || static_cast<unsigned>(position) < appended_zeros ||
            static_cast<unsigned>(position) >= appended_zeros + 64u) return false;
        return ((significand >> (static_cast<unsigned>(position) - appended_zeros)) & 1u) != 0;
    };
    Product128 root{}, remainder{};
    for (int pair_index = 0; pair_index < 67; ++pair_index) {
        unsigned pair = 0;
        if (!odd_exponent && pair_index == 0) {
            pair = static_cast<unsigned>(radicand_bit(132));
        } else {
            const auto high = 133 - 2 * pair_index;
            pair = (static_cast<unsigned>(radicand_bit(high)) << 1) |
                   static_cast<unsigned>(radicand_bit(high - 1));
        }
        remainder = shift_left_two(remainder);
        remainder.lo |= pair;
        auto trial = shift_left_two(root);
        trial.lo |= 1;
        if (compare_wide(remainder, trial) >= 0) {
            remainder = subtract_wide(remainder, trial);
            root = shift_left_two(root);
            root.lo |= 1;
        } else {
            root = shift_left_two(root);
        }
    }
    inexact_tail = remainder.hi != 0 || remainder.lo != 0;
    // The low output bit is sticky beyond the two retained rounding bits.
    if (inexact_tail) root.lo |= 1;
    return root;
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
        if (signed_shift <= 0) return {};
        const auto shift = static_cast<unsigned>(signed_shift);
        std::uint64_t subnormal_retained = 0;
        if (shift < 64)
            subnormal_retained = (extended.lo >> shift) | (extended.hi << (64 - shift));
        else if (shift == 64)
            subnormal_retained = extended.hi;
        else
            subnormal_retained = extended.hi >> (shift - 64);
        const bool subnormal_guard = wide_bit(extended, shift - 1);
        // For results far below the subnormal range, the retained and guard
        // bits are zero but the jammed sticky bit still distinguishes exact
        // zero from a nonzero value for directed rounding.
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
    const bool tag_transfer = name == "fxch" || name == "fst" || name == "fstp";
    if (writes_tag && !instruction.x87_stack_delta && !frees_tag && !tag_transfer)
        result.tags.fill(std::nullopt);
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
            else if (tag_transfer) continue; // Apply the exact copy/swap below.
            else tag.reset();
        }
        if (name == "fxch") {
            std::uint8_t other = 0xff;
            for (const auto &operand : instruction.operands)
                if (const auto *reg = std::get_if<RegisterOperand>(&operand);
                    reg && reg->bank == RegisterBank::x87 && reg->index < 8) {
                    other = reg->index;
                    break;
                }
            if (other < 8) std::swap(result.tags[*result.top], result.tags[(*result.top + other) & 7]);
        } else if (name == "fst" || name == "fstp") {
            for (const auto &operand : instruction.operands)
                if (const auto *reg = std::get_if<RegisterOperand>(&operand);
                    reg && reg->bank == RegisterBank::x87 && reg->index < 8) {
                    result.tags[(*result.top + reg->index) & 7] = input.tags[*input.top];
                    break;
                }
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

X87PendingExceptionResult evaluate_x87_pending_exception(
    const X87PendingExceptionRequest &request) noexcept {
    constexpr std::uint16_t exception_mask = 0x003f;
    X87PendingExceptionResult result;
    result.status_word = request.status_word;
    result.unmasked_exception_flags = static_cast<std::uint8_t>(
        request.status_word & static_cast<std::uint16_t>(~request.control_word) & exception_mask);
    if (result.unmasked_exception_flags == 0) return result;
    result.status_word = static_cast<std::uint16_t>(result.status_word | fsw_error_summary | fsw_busy);
    result.delivery = request.native_mode ? X87ExceptionDelivery::math_fault
                                          : X87ExceptionDelivery::external_irq13;
    return result;
}

X87StackFaultResult evaluate_x87_stack_fault(const X87StackFaultRequest &request) noexcept {
    constexpr std::uint16_t invalid_operation = 1u << 0;
    constexpr std::uint16_t stack_fault = 1u << 6;
    constexpr std::uint16_t c1 = 1u << 9;
    auto status = static_cast<std::uint16_t>(request.status_word | invalid_operation | stack_fault);
    status = static_cast<std::uint16_t>(status & ~c1);
    if (request.overflow) status = static_cast<std::uint16_t>(status | c1);
    const auto pending = evaluate_x87_pending_exception(
        {request.control_word, status, request.native_mode});
    return {pending.status_word, (request.control_word & invalid_operation) != 0, pending};
}

X87ClearExceptionsResult evaluate_x87_clear_exceptions(std::uint16_t status_word) noexcept {
    // IE/DE/ZE/OE/UE/PE, SF, ES, and B are cleared; TOP and C0-C3 are retained.
    return {static_cast<std::uint16_t>(status_word & ~std::uint16_t{0x80ff})};
}

X87InitializeResult evaluate_x87_initialize() noexcept {
    X87InitializeResult result;
    result.stack.top = std::uint8_t{0};
    result.stack.tags.fill(X87Tag::empty);
    return result;
}

X87StackState retire_x87_stack_state(const X87StackState &input, const Instruction &instruction,
                                     const X87PendingExceptionResult &pending,
                                     bool instruction_completed) noexcept {
    if (!instruction_completed || (instruction.x87_waiting && pending.pending())) return input;
    return transfer_x87_stack_state(input, instruction);
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

std::optional<X87SignOperationResult> evaluate_x87_sign_operation(
    const X87SignOperationRequest &request) noexcept {
    auto value = request.value;
    switch (request.operation) {
    case X87SignOperation::change:
        value.sign_exponent ^= sign_mask;
        break;
    case X87SignOperation::clear:
        value.sign_exponent &= static_cast<std::uint16_t>(~sign_mask);
        break;
    default:
        return {};
    }
    return X87SignOperationResult{value, static_cast<std::uint16_t>(request.status_word & ~(1u << 9))};
}

std::optional<X87CompareResult> evaluate_x87_compare(const X87CompareRequest &request) noexcept {
    const auto left = decode(request.left), right = decode(request.right);
    const bool invalid = is_invalid_kind(left.kind, request.kind) || is_invalid_kind(right.kind, request.kind);
    const auto is_denormal = [](const Decoded &operand) noexcept {
        return operand.kind == Class::finite && operand.exponent == 0 &&
               operand.significand != 0 && (operand.significand & integer_bit) == 0;
    };
    const bool denormal = is_denormal(left) || is_denormal(right);
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
    result.denormal_operand = denormal;

    if (invalid) result.status_word |= fsw_invalid;
    if (invalid && !masked) {
        result.status_word |= fsw_error_summary | fsw_busy;
        result.completed = false;
        if (request.kind == X87CompareKind::fcomi || request.kind == X87CompareKind::fucomi)
            result.eflags = request.eflags & ~(eflags_af | eflags_sf | eflags_of);
        return result;
    }

    if (denormal) {
        result.status_word |= fsw_denormal;
        if ((request.control_word & fcw_denormal_mask) == 0) {
            result.status_word = signal_exception(result.status_word, fsw_denormal);
            result.completed = false;
            if (request.kind == X87CompareKind::fcomi || request.kind == X87CompareKind::fucomi)
                result.eflags = request.eflags & ~(eflags_af | eflags_sf | eflags_of);
            return result;
        }
    }

    const bool writes_eflags = request.kind == X87CompareKind::fcomi || request.kind == X87CompareKind::fucomi;
    if (writes_eflags)
        result.eflags = with_eflags(request.eflags, relation);
    else
        result.status_word = with_condition_codes(result.status_word, relation);
    return result;
}

std::optional<X87CompareResult> evaluate_x87_test(const X87TestRequest &request) noexcept {
    X87CompareRequest comparison;
    comparison.left = request.value;
    comparison.right = {0, 0}; // Canonical positive binary80 zero.
    comparison.control_word = request.control_word;
    comparison.status_word = request.status_word;
    comparison.kind = X87CompareKind::fcom;
    return evaluate_x87_compare(comparison);
}

X87ConditionalMoveResult evaluate_x87_conditional_move(
    const X87ConditionalMoveRequest &request) noexcept {
    const bool cf = (request.eflags & eflags_cf) != 0;
    const bool zf = (request.eflags & eflags_zf) != 0;
    const bool pf = (request.eflags & eflags_pf) != 0;
    bool move = false;
    switch (request.condition) {
    case X87ConditionalMoveCondition::below: move = cf; break;
    case X87ConditionalMoveCondition::equal: move = zf; break;
    case X87ConditionalMoveCondition::below_or_equal: move = cf || zf; break;
    case X87ConditionalMoveCondition::unordered: move = pf; break;
    case X87ConditionalMoveCondition::not_below: move = !cf; break;
    case X87ConditionalMoveCondition::not_equal: move = !zf; break;
    case X87ConditionalMoveCondition::not_below_or_equal: move = !cf && !zf; break;
    case X87ConditionalMoveCondition::ordered: move = !pf; break;
    }
    return {move ? request.source : request.destination, request.eflags, move};
}

X87ExamineResult evaluate_x87_examine(const X87ExamineRequest &request) noexcept {
    constexpr std::uint64_t explicit_integer_bit = std::uint64_t{1} << 63;
    constexpr std::uint16_t condition_mask = fsw_c0 | fsw_c1 | fsw_c2 | fsw_c3;
    const auto exponent = static_cast<std::uint16_t>(request.value.sign_exponent & exponent_mask);
    const bool negative = (request.value.sign_exponent & sign_mask) != 0;
    X87ExamineClass classification = X87ExamineClass::unsupported;
    if (request.empty) {
        classification = X87ExamineClass::empty;
    } else if (exponent == exponent_mask) {
        if (request.value.significand & explicit_integer_bit) {
            classification = request.value.significand == explicit_integer_bit
                ? X87ExamineClass::infinity : X87ExamineClass::nan;
        }
    } else if (exponent == 0) {
        if (request.value.significand == 0)
            classification = X87ExamineClass::zero;
        else
            classification = (request.value.significand & explicit_integer_bit)
                ? X87ExamineClass::normal // pseudo-denormal encodes the minimum normal value
                : X87ExamineClass::denormal;
    } else if (request.value.significand & explicit_integer_bit) {
        classification = X87ExamineClass::normal;
    }

    std::uint16_t condition = 0;
    switch (classification) {
    case X87ExamineClass::unsupported: break; // C3:C2:C0 = 000
    case X87ExamineClass::nan: condition = fsw_c0; break;
    case X87ExamineClass::normal: condition = fsw_c2; break;
    case X87ExamineClass::infinity: condition = fsw_c2 | fsw_c0; break;
    case X87ExamineClass::zero: condition = fsw_c3; break;
    case X87ExamineClass::empty: condition = fsw_c3 | fsw_c0; break;
    case X87ExamineClass::denormal: condition = fsw_c3 | fsw_c2; break;
    }
    auto status = static_cast<std::uint16_t>(request.status_word & ~condition_mask);
    status = static_cast<std::uint16_t>(status | condition | (negative ? fsw_c1 : 0));
    return {classification, status, negative};
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

std::optional<X87ArithmeticResult> evaluate_x87_divide(const X87DivideRequest &request) noexcept {
    if (((request.control_word >> 8) & 3) == 1 ||
        (request.operation != X87DivisionOperation::divide &&
         request.operation != X87DivisionOperation::reverse))
        return {};
    auto left = decode(request.left), right = decode(request.right);
    auto left_value = request.left, right_value = request.right;
    if (request.operation == X87DivisionOperation::reverse) {
        std::swap(left, right);
        std::swap(left_value, right_value);
    }
    const auto initial_status = static_cast<std::uint16_t>(request.status_word & ~fsw_c1);
    X87ArithmeticResult special;
    if (handle_special_operands(left_value, right_value, left, right,
                                request.control_word, initial_status, special))
        return special;
    const bool negative = left.negative != right.negative;
    const auto special_result = [&](X87Binary80 value) {
        X87ArithmeticResult result;
        result.status_word = initial_status;
        result.value = value;
        return result;
    };
    if (left.kind == Class::zero && right.kind == Class::zero)
        return invalid_arithmetic(initial_status, request.control_word, x87_indefinite());
    if (left.kind == Class::infinity && right.kind == Class::infinity)
        return invalid_arithmetic(initial_status, request.control_word, x87_indefinite());
    if (left.kind == Class::infinity)
        return special_result({integer_bit, static_cast<std::uint16_t>(exponent_mask |
            (negative ? sign_mask : 0))});
    if (right.kind == Class::infinity)
        return special_result({0, static_cast<std::uint16_t>(negative ? sign_mask : 0)});
    if (left.kind == Class::zero)
        return special_result({0, static_cast<std::uint16_t>(negative ? sign_mask : 0)});
    if (right.kind == Class::zero) {
        X87ArithmeticResult result;
        result.status_word = static_cast<std::uint16_t>(initial_status | fsw_zero_divide);
        if ((request.control_word & fcw_zero_divide_mask) == 0) {
            result.status_word = signal_exception(result.status_word, fsw_zero_divide);
            result.completed = false;
            return result;
        }
        result.value = X87Binary80{integer_bit,
            static_cast<std::uint16_t>(exponent_mask | (negative ? sign_mask : 0))};
        return result;
    }
    if (left.kind != Class::finite || right.kind != Class::finite) return {};

    const auto denormal_operand = [](const Decoded &operand) noexcept {
        return operand.exponent == 0 && (operand.significand & integer_bit) == 0;
    };
    const bool denormal = denormal_operand(left) || denormal_operand(right);
    if (denormal && (request.control_word & fcw_denormal_mask) == 0) {
        X87ArithmeticResult result;
        result.status_word = signal_exception(
            static_cast<std::uint16_t>(request.status_word & ~fsw_c1), fsw_denormal);
        result.completed = false;
        return result;
    }

    const auto numerator = normalize_finite(left);
    const auto denominator = normalize_finite(right);
    std::uint64_t remainder = 0;
    int exponent = numerator.exponent - denominator.exponent + 16383;
    std::uint64_t significand = integer_bit;
    if (numerator.significand >= denominator.significand) {
        remainder = numerator.significand - denominator.significand;
    } else {
        // Both normalized significands have bit 63 set. The exact value
        // 2*numerator-denominator is nonnegative and below denominator; its
        // low 64 bits are therefore the exact remainder even if 2*numerator
        // has a carry into bit 64.
        remainder = (numerator.significand << 1) - denominator.significand;
        --exponent;
    }

    const auto next_quotient_bit = [&]() noexcept {
        const bool carry = (remainder & integer_bit) != 0;
        const auto doubled = remainder << 1;
        if (carry || doubled >= denominator.significand) {
            remainder = doubled - denominator.significand;
            return true;
        }
        remainder = doubled;
        return false;
    };
    for (int bit = 62; bit >= 0; --bit)
        if (next_quotient_bit()) significand |= std::uint64_t{1} << bit;

    const bool guard = next_quotient_bit();
    const bool round = next_quotient_bit();
    const bool sticky = remainder != 0;
    const Product128 extended{significand >> 61,
        (significand << 3) | (static_cast<std::uint64_t>(guard) << 2) |
        (static_cast<std::uint64_t>(round) << 1) | static_cast<std::uint64_t>(sticky)};

    X87AddSubtractRequest rounding_request;
    rounding_request.control_word = request.control_word;
    rounding_request.status_word = static_cast<std::uint16_t>(request.status_word |
        (denormal ? fsw_denormal : 0));
    auto result = round_add_sub_result(extended, exponent, negative, rounding_request);
    if (!result) return {};
    return result;
}

std::optional<X87ArithmeticResult>
evaluate_x87_square_root(const X87SquareRootRequest &request) noexcept {
    if (((request.control_word >> 8) & 3) == 1) return {};
    const auto decoded = decode(request.value);
    if (decoded.kind == Class::unsupported) return {};
    const auto status = static_cast<std::uint16_t>(request.status_word & ~fsw_c1);
    if (decoded.kind == Class::signaling_nan)
        return invalid_arithmetic(status, request.control_word, quiet_nan(request.value));
    if (decoded.kind == Class::quiet_nan) {
        X87ArithmeticResult result;
        result.status_word = status;
        result.value = request.value;
        return result;
    }
    if (decoded.kind == Class::zero) {
        X87ArithmeticResult result;
        result.status_word = status;
        result.value = request.value; // FSQRT preserves the sign of zero.
        return result;
    }
    if (decoded.kind == Class::infinity) {
        if (decoded.negative)
            return invalid_arithmetic(status, request.control_word, x87_indefinite());
        X87ArithmeticResult result;
        result.status_word = status;
        result.value = request.value;
        return result;
    }
    if (decoded.negative)
        return invalid_arithmetic(status, request.control_word, x87_indefinite());

    const bool denormal = decoded.exponent == 0 &&
                          (decoded.significand & integer_bit) == 0;
    if (denormal && (request.control_word & fcw_denormal_mask) == 0) {
        X87ArithmeticResult result;
        result.status_word = signal_exception(status, fsw_denormal);
        result.completed = false;
        return result;
    }

    const auto normalized = normalize_finite(decoded);
    const int unbiased_exponent = normalized.exponent - 16383;
    const bool odd_exponent = (unbiased_exponent % 2) != 0;
    const int result_unbiased_exponent = unbiased_exponent >= 0
        ? unbiased_exponent / 2 : (unbiased_exponent - 1) / 2;
    bool inexact_tail = false;
    auto extended = square_root_extension(normalized.significand, odd_exponent, inexact_tail);

    X87AddSubtractRequest rounding_request;
    rounding_request.control_word = request.control_word;
    rounding_request.status_word = static_cast<std::uint16_t>(request.status_word |
        (denormal ? fsw_denormal : 0));
    auto result = round_add_sub_result(extended, result_unbiased_exponent + 16383,
                                       false, rounding_request);
    if (!result) return {};
    return result;
}

std::optional<X87ScaleResult> evaluate_x87_scale(const X87ScaleRequest &request) noexcept {
    const auto value = decode(request.value);
    const auto scale = decode(request.scale);
    const auto value_raw_exponent = static_cast<std::uint16_t>(request.value.sign_exponent & exponent_mask);
    const auto scale_raw_exponent = static_cast<std::uint16_t>(request.scale.sign_exponent & exponent_mask);
    if ((value.kind != Class::zero && value.kind != Class::finite) ||
        (scale.kind != Class::zero && scale.kind != Class::finite) ||
        (value.kind == Class::finite && value_raw_exponent == 0) ||
        (scale.kind == Class::finite && scale_raw_exponent == 0))
        return {};

    if (value.kind == Class::zero)
        return X87ScaleResult{request.value, static_cast<std::uint16_t>(request.status_word & ~fsw_c1)};

    std::int64_t integral_scale = 0;
    if (scale.kind == Class::finite) {
        const auto unbiased_scale_exponent = static_cast<int>(scale.exponent) - 16383;
        // Larger magnitudes cannot keep a finite binary80 ST(0) normal.
        if (unbiased_scale_exponent > 14) return {};
        if (unbiased_scale_exponent >= 0) {
            const auto magnitude = scale.significand >> (63 - unbiased_scale_exponent);
            integral_scale = static_cast<std::int64_t>(magnitude);
        }
        if (scale.negative) integral_scale = -integral_scale;
    }

    auto result_value = request.value;
    const auto unbiased_value_exponent = static_cast<int>(value.exponent) - 16383;
    const auto result_exponent = unbiased_value_exponent + integral_scale;
    if (result_exponent < -16382 || result_exponent > 16383) return {};
    result_value.sign_exponent = static_cast<std::uint16_t>(
        (request.value.sign_exponent & sign_mask) | static_cast<std::uint16_t>(result_exponent + 16383));
    return X87ScaleResult{result_value, static_cast<std::uint16_t>(request.status_word & ~fsw_c1)};
}

X87UnaryResult evaluate_x87_unary(X87Binary80 value, std::uint16_t status_word,
                                  X87UnaryArithmetic operation) noexcept {
    if (operation == X87UnaryArithmetic::change_sign)
        value.sign_exponent ^= sign_mask;
    else
        value.sign_exponent &= static_cast<std::uint16_t>(~sign_mask);
    return {value, status_word};
}

std::optional<X87ExtractResult> evaluate_x87_extract(const X87ExtractRequest &request) noexcept {
    const auto decoded = decode(request.value);
    if (decoded.kind == Class::unsupported) return std::nullopt;
    X87ExtractResult result;
    result.status_word = request.status_word;
    if (is_nan(decoded.kind)) {
        result.invalid_operation = decoded.kind == Class::signaling_nan;
        if (result.invalid_operation) {
            if ((request.control_word & fcw_invalid_mask) == 0) {
                result.status_word = signal_exception(result.status_word, fsw_invalid);
                result.completed = false;
                return result;
            }
            result.status_word = static_cast<std::uint16_t>(result.status_word | fsw_invalid);
        }
        // FXTRACT has two floating outputs. Propagate the same sign/payload
        // to both, quieting a masked SNaN without converting through host FP.
        result.significand = quiet_nan(request.value);
        result.exponent = result.significand;
        return result;
    }
    if (decoded.kind == Class::zero) {
        result.zero_divide = true;
        if ((request.control_word & fcw_zero_divide_mask) == 0) {
            result.status_word = signal_exception(result.status_word, fsw_zero_divide);
            result.completed = false;
            return result;
        }
        result.status_word = static_cast<std::uint16_t>(result.status_word | fsw_zero_divide);
        result.significand = request.value;
        result.exponent = {integer_bit, static_cast<std::uint16_t>(exponent_mask | sign_mask)};
        return result;
    }
    if (decoded.kind == Class::infinity) {
        result.significand = {integer_bit, static_cast<std::uint16_t>((decoded.negative ? sign_mask : 0) | 0x3fff)};
        result.exponent = {integer_bit, exponent_mask};
        return result;
    }
    const bool denormal = (request.value.sign_exponent & exponent_mask) == 0 &&
                          request.value.significand != 0 && (request.value.significand & integer_bit) == 0;
    if (denormal) {
        result.denormal_operand = true;
        if ((request.control_word & fcw_denormal_mask) == 0) {
            result.status_word = signal_exception(result.status_word, fsw_denormal);
            result.completed = false;
            return result;
        }
        result.status_word = static_cast<std::uint16_t>(result.status_word | fsw_denormal);
    }
    const auto leading = static_cast<int>(63 - std::countl_zero(decoded.significand));
    const int effective_exponent = decoded.exponent == 0 ? 1 : decoded.exponent;
    const int exponent = effective_exponent - 16383 - 63 + leading;
    const auto normalized = decoded.significand << (63 - leading);
    result.significand = {normalized, static_cast<std::uint16_t>((decoded.negative ? sign_mask : 0) | 0x3fff)};
    if (exponent == 0) {
        result.exponent = {0, 0};
    } else {
        const auto magnitude = static_cast<std::uint64_t>(exponent < 0 ? -exponent : exponent);
        const auto exponent_leading = static_cast<unsigned>(63 - std::countl_zero(magnitude));
        const auto exponent_significand = magnitude << (63 - exponent_leading);
        result.exponent = {exponent_significand,
            static_cast<std::uint16_t>((exponent < 0 ? sign_mask : 0) | (16383 + exponent_leading))};
    }
    return result;
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

std::optional<X87Binary80>
evaluate_x87_load_packed_bcd(const X87PackedBcdLoadRequest &request) noexcept {
    std::uint64_t magnitude = 0;
    std::uint64_t place = 1;
    for (std::size_t byte = 0; byte < 9; ++byte) {
        const auto packed = request.source[byte];
        const auto low = static_cast<std::uint8_t>(packed & 0xf);
        const auto high = static_cast<std::uint8_t>(packed >> 4);
        if (low > 9 || high > 9) return {};
        magnitude += std::uint64_t(low) * place;
        place *= 10;
        magnitude += std::uint64_t(high) * place;
        place *= 10;
    }

    X87Binary80 result{};
    const bool negative = (request.source[9] & 0x80) != 0;
    result.sign_exponent = negative ? sign_mask : 0;
    if (magnitude == 0) return result;
    const auto highest = static_cast<unsigned>(63 - std::countl_zero(magnitude));
    result.significand = magnitude << (63 - highest);
    result.sign_exponent = static_cast<std::uint16_t>(result.sign_exponent | (16383 + highest));
    return result;
}

std::optional<X87PackedBcdStoreResult>
evaluate_x87_store_packed_bcd(const X87PackedBcdStoreRequest &request) noexcept {
    constexpr std::uint64_t largest_bcd_integer = 999999999999999999ULL;
    const auto decoded = decode(request.value);
    std::uint16_t input_status = request.status_word;
    const bool denormal_operand = decoded.kind == Class::finite && decoded.exponent == 0 &&
                                  (decoded.significand & integer_bit) == 0;
    if (denormal_operand) {
        input_status |= fsw_denormal;
        if ((request.control_word & fcw_denormal_mask) == 0) {
            X87PackedBcdStoreResult result;
            result.status_word = signal_exception(input_status, fsw_denormal);
            result.completed = false;
            return result;
        }
    }
    X87IntegerConvertRequest conversion;
    conversion.value = request.value;
    conversion.control_word = static_cast<std::uint16_t>(request.control_word |
        fcw_invalid_mask | fcw_precision_mask);
    conversion.status_word = input_status;
    conversion.destination_width = 64;
    const auto converted = evaluate_x87_to_integer(conversion);
    if (!converted) return {};

    X87PackedBcdStoreResult result;
    result.status_word = converted->status_word;
    result.completed = true;
    result.precision = converted->precision;
    result.invalid_operation = converted->invalid_operation;
    result.rounded_up = (converted->status_word & fsw_c1) != 0;
    const auto indefinite = [] {
        std::array<std::uint8_t, 10> bytes{};
        bytes[8] = 0xc0;
        bytes[9] = 0xff;
        return bytes;
    };
    if (converted->invalid_operation) {
        if ((request.control_word & fcw_invalid_mask) == 0) {
            result.status_word = signal_exception(static_cast<std::uint16_t>(input_status | fsw_invalid), fsw_invalid);
            result.completed = false;
        } else result.destination = indefinite();
        return result;
    }
    if (!converted->destination_bits) return {};

    const auto signed_value = std::bit_cast<std::int64_t>(*converted->destination_bits);
    const bool negative = signed_value < 0 || (signed_value == 0 && decoded.negative);
    const auto magnitude = negative ? std::uint64_t{0} - *converted->destination_bits
                                    : *converted->destination_bits;
    if (magnitude > largest_bcd_integer) {
        result.invalid_operation = true;
        result.precision = false;
        result.rounded_up = false;
        result.status_word = static_cast<std::uint16_t>(input_status & ~fsw_c1) | fsw_invalid;
        if ((request.control_word & fcw_invalid_mask) == 0) {
            result.status_word = signal_exception(result.status_word, fsw_invalid);
            result.completed = false;
            return result;
        }
        result.destination = indefinite();
        return result;
    }

    if (result.precision && (request.control_word & fcw_precision_mask) == 0) {
        result.status_word = signal_exception(result.status_word, fsw_precision);
        result.completed = false;
        return result;
    }

    std::array<std::uint8_t, 10> bytes{};
    auto remaining = magnitude;
    for (std::size_t byte = 0; byte < 9; ++byte) {
        const auto low = static_cast<std::uint8_t>(remaining % 10);
        remaining /= 10;
        const auto high = static_cast<std::uint8_t>(remaining % 10);
        remaining /= 10;
        bytes[byte] = static_cast<std::uint8_t>(low | (high << 4));
    }
    bytes[9] = negative ? 0x80 : 0;
    result.destination = bytes;
    return result;
}

} // namespace hexlab
