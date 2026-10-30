#pragma once

#include <cstdint>
#include <bit>
#include <optional>

namespace hexlab {

// Architectural encoding order for Jcc condition fields (condition & 0x0f).
enum class X86Condition : std::uint8_t {
    overflow, not_overflow, below, above_equal, equal, not_equal,
    below_equal, above, sign, not_sign, parity, not_parity,
    less, greater_equal, less_equal, greater
};

enum class X86LoopCondition : std::uint8_t { counter_nonzero, counter_nonzero_and_zero, counter_nonzero_and_not_zero, counter_zero };
struct X86LoopResult {
    std::uint64_t counter = 0;
    bool taken = false;
    bool decremented = false;
    bool operator==(const X86LoopResult &) const = default;
};

struct X86Flags {
    bool carry = false;
    bool parity = false;
    bool zero = false;
    bool sign = false;
    bool overflow = false;
    bool operator==(const X86Flags &) const = default;
};

enum class X86Arithmetic : std::uint8_t { add, adc, sub, sbb, compare, bit_and, bit_or, bit_xor, test };

struct X86ArithmeticResult {
    std::uint64_t value = 0;
    X86Flags flags{};
    bool operator==(const X86ArithmeticResult &) const = default;
};

struct X86DefinedFlag {
    bool value = false;
    bool defined = false;
    bool operator==(const X86DefinedFlag &) const = default;
};
struct X86MultiplyFlags {
    X86DefinedFlag carry{}, overflow{}, parity{}, zero{}, sign{};
    bool operator==(const X86MultiplyFlags &) const = default;
};
enum class X86MultiplyKind : std::uint8_t { unsigned_multiply, signed_multiply };
struct X86MultiplyResult {
    std::uint64_t low = 0;
    std::uint64_t high = 0;
    X86MultiplyFlags flags{};
    bool operator==(const X86MultiplyResult &) const = default;
};
struct X86DoubleShiftResult {
    std::uint64_t value = 0;
    bool value_defined = true;
    bool flags_unchanged = false;
    X86DefinedFlag carry{}, overflow{}, parity{}, zero{}, sign{}, auxiliary{};
    bool operator==(const X86DoubleShiftResult &) const = default;
};

enum class X86ShiftRotate : std::uint8_t { shl, shr, sar, rol, ror, rcl, rcr };
struct X86ShiftRotateFlags {
    X86DefinedFlag carry{}, parity{}, zero{}, sign{}, overflow{}, auxiliary{};
    bool operator==(const X86ShiftRotateFlags &) const = default;
};
struct X86ShiftRotateResult {
    std::uint64_t value = 0;
    bool value_defined = true;
    bool flags_unchanged = false;
    X86ShiftRotateFlags flags{};
    bool operator==(const X86ShiftRotateResult &) const = default;
};

enum class X86Bmi1 : std::uint8_t { andn, bextr, blsi, blsmsk, blsr };
struct X86Bmi1Result {
    std::uint64_t value = 0;
    X86ShiftRotateFlags flags{};
    bool operator==(const X86Bmi1Result &) const = default;
};

enum class X86Bmi2 : std::uint8_t { pdep, pext };
struct X86Bmi2Result {
    std::uint64_t value = 0;
    bool operator==(const X86Bmi2Result &) const = default;
};

// PDEP scatters source bits into set mask positions; PEXT gathers those
// positions into contiguous low bits. Inputs are architectural bit patterns.
// A 32-bit result is returned zero-extended, including in long mode.
constexpr std::optional<X86Bmi2Result> evaluate_x86_bmi2(
    X86Bmi2 operation, std::uint64_t source, std::uint64_t bit_mask, unsigned width) noexcept {
    if ((operation != X86Bmi2::pdep && operation != X86Bmi2::pext) ||
        (width != 32 && width != 64)) return std::nullopt;
    const std::uint64_t value_mask = width == 64 ? UINT64_MAX : UINT64_C(0xffffffff);
    source &= value_mask;
    bit_mask &= value_mask;
    X86Bmi2Result result{};
    unsigned compact_bit = 0;
    for (unsigned mask_bit = 0; mask_bit < width; ++mask_bit) {
        const auto bit = UINT64_C(1) << mask_bit;
        if (!(bit_mask & bit)) continue;
        if (operation == X86Bmi2::pdep) {
            if (source & (UINT64_C(1) << compact_bit)) result.value |= bit;
        } else if (operation == X86Bmi2::pext) {
            if (source & bit) result.value |= UINT64_C(1) << compact_bit;
        }
        ++compact_bit;
    }
    result.value &= value_mask;
    return result;
}

struct X86BzhiResult {
    std::uint64_t value = 0;
    X86ShiftRotateFlags flags{};
    bool operator==(const X86BzhiResult &) const = default;
};

// Evaluate BMI2 BZHI. The index is the low byte of the second source; an
// index at least as large as the operand width copies the source and sets CF.
constexpr std::optional<X86BzhiResult> evaluate_x86_bzhi(
    std::uint64_t source, std::uint64_t index_value, unsigned width) noexcept {
    if (width != 32 && width != 64) return std::nullopt;
    const auto mask = width == 64 ? UINT64_MAX : UINT64_C(0xffffffff);
    source &= mask;
    const unsigned index = static_cast<std::uint8_t>(index_value);
    const bool oversized = index >= width;
    const auto bit_mask = oversized ? mask : index == 0 ? 0 : (UINT64_C(1) << index) - 1;
    X86BzhiResult result{};
    result.value = source & bit_mask;
    result.flags.carry = {oversized, true};
    result.flags.overflow = {false, true};
    result.flags.sign = {(result.value & (UINT64_C(1) << (width - 1))) != 0, true};
    result.flags.zero = {result.value == 0, true};
    result.flags.parity = {(std::popcount(static_cast<unsigned>(result.value & 0xff)) & 1) == 0, true};
    result.flags.auxiliary = {};
    return result;
}

// Evaluate one supplied hardware sample. This function never produces entropy.
// An unavailable sample writes zero; successful samples truncate to operand size.
struct X86RandomResult {
    std::uint64_t value = 0;
    std::uint64_t flags = 0;
    bool operator==(const X86RandomResult &) const = default;
};
constexpr std::optional<X86RandomResult> evaluate_x86_random(
    std::uint64_t sample, bool available, unsigned width, std::uint64_t incoming_flags) noexcept {
    if (width != 16 && width != 32 && width != 64) return std::nullopt;
    const auto mask = width == 64 ? UINT64_MAX : (UINT64_C(1) << width) - 1;
    // CF/PF/AF/ZF/SF/OF are the only modified FLAGS bits.
    return X86RandomResult{available ? sample & mask : 0,
                           (incoming_flags & ~UINT64_C(0x8d5)) | (available ? 1u : 0u)};
}

enum class X86Adx : std::uint8_t { carry, overflow };
struct X86AdxResult {
    std::uint64_t value = 0;
    X86Flags flags{};
    bool operator==(const X86AdxResult &) const = default;
};

// ADCX and ADOX form independent carry chains. All non-chain status flags are
// preserved. The operand width is restricted to the architectural 32/64-bit
// forms, and overflow is detected without relying on host signed arithmetic.
constexpr std::optional<X86AdxResult> evaluate_x86_adx(
    X86Adx operation, std::uint64_t destination, std::uint64_t source,
    X86Flags incoming, unsigned width) noexcept {
    if (width != 32 && width != 64) return std::nullopt;
    const std::uint64_t mask = width == 64 ? UINT64_MAX : UINT64_C(0xffffffff);
    destination &= mask;
    source &= mask;
    const bool carry_in = operation == X86Adx::carry ? incoming.carry : incoming.overflow;
    std::uint64_t partial = destination + source;
    const bool carry1 = partial < destination;
    const std::uint64_t result_value = partial + static_cast<std::uint64_t>(carry_in);
    const bool carry2 = result_value < partial;
    X86AdxResult result;
    result.value = result_value & mask;
    result.flags = incoming;
    const bool output = width == 64 ? (carry1 || carry2)
                                    : ((destination + source + static_cast<std::uint64_t>(carry_in)) > mask);
    if (operation == X86Adx::carry) result.flags.carry = output;
    else result.flags.overflow = output;
    return result;
}

// Sources follow printed operand order, excluding the destination. Unary
// lowest-set-bit operations ignore source2. AF/PF are always undefined;
// BEXTR also leaves SF undefined. No host-width shifts or signed overflow.
constexpr std::optional<X86Bmi1Result>
evaluate_x86_bmi1(X86Bmi1 operation, std::uint64_t source1,
                  std::uint64_t source2, unsigned width) noexcept {
    if (width != 32 && width != 64) return std::nullopt;
    const auto mask = width == 64 ? UINT64_MAX : UINT64_C(0xffffffff);
    source1 &= mask;
    source2 &= mask;
    X86Bmi1Result result;
    bool carry = false;
    switch (operation) {
    case X86Bmi1::andn: result.value = (~source1 & source2) & mask; break;
    case X86Bmi1::bextr: {
        const unsigned start = static_cast<unsigned>(source2 & 0xff);
        const unsigned length = static_cast<unsigned>((source2 >> 8) & 0xff);
        if (start < width && length != 0) {
            const unsigned available = width - start;
            const unsigned count = length < available ? length : available;
            const auto field_mask = count == 64 ? UINT64_MAX : (UINT64_C(1) << count) - 1;
            result.value = (source1 >> start) & field_mask;
        }
        break;
    }
    case X86Bmi1::blsi:
        result.value = (source1 & (UINT64_C(0) - source1)) & mask;
        carry = source1 != 0;
        break;
    case X86Bmi1::blsmsk:
        result.value = (source1 ^ (source1 - 1)) & mask;
        carry = source1 == 0;
        break;
    case X86Bmi1::blsr:
        result.value = (source1 & (source1 - 1)) & mask;
        carry = source1 == 0;
        break;
    default: return std::nullopt;
    }
    result.flags.carry = {carry, true};
    result.flags.overflow = {false, true};
    result.flags.zero = {result.value == 0, true};
    if (operation != X86Bmi1::bextr)
        result.flags.sign = {(result.value & (UINT64_C(1) << (width - 1))) != 0, true};
    return result;
}

namespace x86_semantics_detail {
struct U128 { std::uint64_t low = 0, high = 0; };
constexpr U128 multiply_u64(std::uint64_t a, std::uint64_t b) noexcept {
    U128 result{};
    U128 addend{a, 0};
    for (unsigned bit = 0; bit < 64; ++bit) {
        if ((b & 1) != 0) {
            const auto old = result.low;
            result.low += addend.low;
            result.high += result.low < old;
            result.high += addend.high;
        }
        b >>= 1;
        addend.high = (addend.high << 1) | (addend.low >> 63);
        addend.low <<= 1;
    }
    return result;
}
constexpr U128 negate(U128 value) noexcept {
    value.low = ~value.low + 1;
    value.high = ~value.high + (value.low == 0);
    return value;
}
constexpr bool supported_width(unsigned width) noexcept {
    return width == 8 || width == 16 || width == 32 || width == 64;
}
constexpr std::uint64_t mask_for(unsigned width) noexcept {
    return width == 64 ? UINT64_MAX : (std::uint64_t{1} << width) - 1;
}
} // namespace x86_semantics_detail

constexpr std::optional<X86MultiplyResult> evaluate_x86_multiply(X86MultiplyKind kind,
                                                                  std::uint64_t lhs,
                                                                  std::uint64_t rhs,
                                                                  unsigned width) noexcept {
    using namespace x86_semantics_detail;
    if (!supported_width(width)) return std::nullopt;
    const auto mask = mask_for(width);
    lhs &= mask; rhs &= mask;
    const bool lhs_negative = kind == X86MultiplyKind::signed_multiply &&
                              (lhs & (std::uint64_t{1} << (width - 1))) != 0;
    const bool rhs_negative = kind == X86MultiplyKind::signed_multiply &&
                              (rhs & (std::uint64_t{1} << (width - 1))) != 0;
    if (lhs_negative) lhs = (~lhs + 1) & mask;
    if (rhs_negative) rhs = (~rhs + 1) & mask;
    U128 product = multiply_u64(lhs, rhs);
    if (lhs_negative != rhs_negative) product = negate(product);
    if (width < 64) {
        const auto unmasked_low = product.low;
        product.high = ((product.high << (64 - width)) | (unmasked_low >> width)) & mask;
        product.low = unmasked_low & mask;
    }
    bool overflow = product.high != 0;
    if (kind == X86MultiplyKind::signed_multiply) {
        const bool low_negative = (product.low & (std::uint64_t{1} << (width - 1))) != 0;
        overflow = product.high != (low_negative ? mask : 0);
    }
    X86MultiplyResult result{product.low, product.high, {}};
    result.flags.carry = {overflow, true};
    result.flags.overflow = {overflow, true};
    return result;
}

enum class X86DivideKind : std::uint8_t { unsigned_divide, signed_divide };
enum class X86DivideStatus : std::uint8_t { success, divide_by_zero, quotient_overflow };
struct X86DivideResult {
    X86DivideStatus status = X86DivideStatus::success;
    std::uint64_t quotient = 0, remainder = 0;
    bool quotient_valid = false, remainder_valid = false;
    bool operator==(const X86DivideResult &) const = default;
};

namespace x86_semantics_detail {
constexpr U128 divide_u128_u64(U128 dividend, std::uint64_t divisor, U128 &quotient) noexcept {
    U128 remainder{};
    for (int bit = 127; bit >= 0; --bit) {
        const bool incoming = bit >= 64 ? ((dividend.high >> (bit - 64)) & 1) != 0
                                       : ((dividend.low >> bit) & 1) != 0;
        const bool carry = (remainder.low >> 63) != 0;
        remainder.high = (remainder.high << 1) | (remainder.low >> 63);
        remainder.low = (remainder.low << 1) | static_cast<std::uint64_t>(incoming);
        if (carry || remainder.low >= divisor) {
            remainder.low -= divisor;
            if (carry) --remainder.high;
            if (bit >= 64) quotient.high |= std::uint64_t{1} << (bit - 64);
            else quotient.low |= std::uint64_t{1} << bit;
        }
    }
    return remainder;
}
constexpr U128 negate_width(U128 v, unsigned width) noexcept {
    v = negate(v);
    if (width < 64) {
        const auto mask = mask_for(width);
        v.low &= mask;
        v.high &= mask;
    }
    return v;
}
} // namespace x86_semantics_detail

constexpr std::optional<X86DivideResult> evaluate_x86_divide(X86DivideKind kind,
                                                              std::uint64_t dividend_low,
                                                              std::uint64_t dividend_high,
                                                              std::uint64_t divisor,
                                                              unsigned width) noexcept {
    using namespace x86_semantics_detail;
    if (!supported_width(width)) return std::nullopt;
    const auto mask = mask_for(width);
    dividend_low &= mask; dividend_high &= mask; divisor &= mask;
    X86DivideResult result{};
    if (divisor == 0) { result.status = X86DivideStatus::divide_by_zero; return result; }
    U128 dividend{dividend_low, dividend_high};
    const bool signed_op = kind == X86DivideKind::signed_divide;
    const auto sign_bit = std::uint64_t{1} << (width - 1);
    const bool dividend_negative = signed_op && (dividend_high & sign_bit) != 0;
    const bool divisor_negative = signed_op && (divisor & sign_bit) != 0;
    if (dividend_negative) dividend = negate_width(dividend, width);
    if (divisor_negative) divisor = (~divisor + 1) & mask;
    U128 quotient{};
    U128 remainder = divide_u128_u64(dividend, divisor, quotient);
    bool overflow = quotient.high != 0 || quotient.low > mask;
    if (signed_op) {
        const auto positive_limit = sign_bit - 1;
        const auto negative_limit = sign_bit;
        overflow = quotient.high != 0 || quotient.low >
                   ((dividend_negative != divisor_negative) ? negative_limit : positive_limit);
    }
    if (overflow) { result.status = X86DivideStatus::quotient_overflow; return result; }
    auto q = quotient.low;
    auto r = remainder.low;
    if (signed_op && dividend_negative != divisor_negative) q = (~q + 1) & mask;
    if (signed_op && dividend_negative) r = (~r + 1) & mask;
    result.quotient = q & mask; result.remainder = r & mask;
    result.quotient_valid = result.remainder_valid = true;
    return result;
}

// Pure integer semantics for the scalar arithmetic operations currently
// decoded by HexLab. `carry_or_borrow` is consumed only by ADC and SBB.
constexpr X86ArithmeticResult evaluate_x86_arithmetic(X86Arithmetic operation,
                                                       std::uint64_t lhs,
                                                       std::uint64_t rhs,
                                                       bool carry_or_borrow,
                                                       unsigned width) noexcept {
    if (width == 0 || width > 64)
        return {};
    const std::uint64_t mask = width == 64 ? UINT64_MAX : (std::uint64_t{1} << width) - 1;
    const std::uint64_t sign = std::uint64_t{1} << (width - 1);
    lhs &= mask;
    rhs &= mask;
    X86ArithmeticResult result{};
    switch (operation) {
    case X86Arithmetic::add:
    case X86Arithmetic::adc: {
        const bool carry_in = operation == X86Arithmetic::adc && carry_or_borrow;
        const bool carry_first = lhs > mask - rhs;
        const std::uint64_t partial = (lhs + rhs) & mask;
        const bool carry_second = carry_in && partial == mask;
        result.value = (partial + static_cast<std::uint64_t>(carry_in)) & mask;
        result.flags.carry = carry_first || carry_second;
        result.flags.overflow = ((~(lhs ^ rhs) & (lhs ^ result.value) & sign) != 0);
        break;
    }
    case X86Arithmetic::sub:
    case X86Arithmetic::sbb:
    case X86Arithmetic::compare: {
        const bool borrow_in = operation == X86Arithmetic::sbb && carry_or_borrow;
        result.value = (lhs - rhs - static_cast<std::uint64_t>(borrow_in)) & mask;
        result.flags.carry = lhs < rhs || (borrow_in && lhs == rhs);
        result.flags.overflow = (((lhs ^ rhs) & (lhs ^ result.value) & sign) != 0);
        break;
    }
    case X86Arithmetic::bit_and:
    case X86Arithmetic::test: result.value = lhs & rhs; break;
    case X86Arithmetic::bit_or: result.value = lhs | rhs; break;
    case X86Arithmetic::bit_xor: result.value = lhs ^ rhs; break;
    }
    result.value &= mask;
    result.flags.parity = (std::popcount(static_cast<unsigned>(result.value & 0xff)) & 1) == 0;
    result.flags.zero = result.value == 0;
    result.flags.sign = (result.value & sign) != 0;
    return result;
}

// SHLD/SHRD use a 5-bit count mask except for 64-bit operands, which use 6
// bits. Counts greater than the operand width have an undefined result and
// flags; a masked count of zero leaves both destination and flags unchanged.
constexpr X86DoubleShiftResult evaluate_x86_double_shift(bool left,
                                                          std::uint64_t destination,
                                                          std::uint64_t source,
                                                          std::uint8_t raw_count,
                                                          unsigned width) noexcept {
    X86DoubleShiftResult result{};
    if (width != 16 && width != 32 && width != 64) {
        result.value_defined = false;
        return result;
    }
    const unsigned count = raw_count & (width == 64 ? 0x3fU : 0x1fU);
    const std::uint64_t mask = x86_semantics_detail::mask_for(width);
    const std::uint64_t sign = std::uint64_t{1} << (width - 1);
    destination &= mask;
    source &= mask;
    result.value = destination;
    if (count == 0) {
        result.flags_unchanged = true;
        return result;
    }
    if (count > width) {
        result.value_defined = false;
        result.carry = {}; result.overflow = {}; result.parity = {};
        result.zero = {}; result.sign = {}; result.auxiliary = {};
        return result;
    }

    if (left) {
        const auto shifted_destination = count == width ? 0 : (destination << count) & mask;
        const auto shifted_source = source >> (width - count);
        result.value = (shifted_destination | shifted_source) & mask;
        result.carry = {((destination >> (width - count)) & 1) != 0, true};
    } else {
        const auto shifted_destination = count == width ? 0 : destination >> count;
        const auto shifted_source = (source << (width - count)) & mask;
        result.value = (shifted_destination | shifted_source) & mask;
        result.carry = {((destination >> (count - 1)) & 1) != 0, true};
    }
    result.sign = {(result.value & sign) != 0, true};
    result.zero = {result.value == 0, true};
    result.parity = {(std::popcount(static_cast<unsigned>(result.value & 0xff)) & 1) == 0, true};
    result.auxiliary = {};
    if (count == 1)
        result.overflow = {((destination & sign) != (result.value & sign)), true};
    return result;
}

// Evaluate scalar x86 shifts and rotates. The caller supplies the effective
// count and the incoming flags; this helper does not read machine state.
constexpr X86ShiftRotateResult evaluate_x86_shift_rotate(X86ShiftRotate operation,
                                                          std::uint64_t value,
                                                          std::uint8_t raw_count,
                                                          unsigned width,
                                                          X86Flags incoming = {},
                                                          X86DefinedFlag incoming_auxiliary = {}) noexcept {
    using namespace x86_semantics_detail;
    X86ShiftRotateResult result{};
    if (!supported_width(width) || static_cast<unsigned>(operation) > static_cast<unsigned>(X86ShiftRotate::rcr)) {
        result.value_defined = false;
        return result;
    }
    const auto mask = mask_for(width);
    const auto sign_bit = std::uint64_t{1} << (width - 1);
    value &= mask;
    result.value = value;
    unsigned count = raw_count & (width == 64 ? 0x3fU : 0x1fU);
    const bool rotate = operation == X86ShiftRotate::rol || operation == X86ShiftRotate::ror;
    const bool through_carry = operation == X86ShiftRotate::rcl || operation == X86ShiftRotate::rcr;
    if (rotate)
        count %= width;
    else if (through_carry && width < 32)
        count %= width + 1;
    if (count == 0) {
        result.flags_unchanged = true;
        result.flags.carry = {incoming.carry, true};
        result.flags.parity = {incoming.parity, true};
        result.flags.zero = {incoming.zero, true};
        result.flags.sign = {incoming.sign, true};
        result.flags.overflow = {incoming.overflow, true};
        result.flags.auxiliary = incoming_auxiliary;
        return result;
    }

    if (!rotate && !through_carry && count > width) {
        result.value_defined = false;
        result.flags.carry = {}; result.flags.parity = {}; result.flags.zero = {};
        result.flags.sign = {}; result.flags.overflow = {}; result.flags.auxiliary = {};
        return result;
    }

    if (operation == X86ShiftRotate::shl || operation == X86ShiftRotate::shr ||
        operation == X86ShiftRotate::sar) {
        const bool left = operation == X86ShiftRotate::shl;
        bool carry = false;
        if (count <= width) {
            carry = left ? ((value >> (width - count)) & 1) != 0
                         : ((value >> (count - 1)) & 1) != 0;
            result.flags.carry = {carry, true};
        }
        if (left)
            result.value = count == width ? 0 : (value << count) & mask;
        else if (operation == X86ShiftRotate::sar) {
            const bool negative = (value & sign_bit) != 0;
            if (count >= width)
                result.value = negative ? mask : 0;
            else {
                result.value = value >> count;
                if (negative)
                    result.value |= mask ^ (mask >> count);
            }
        } else
            result.value = count == width ? 0 : value >> count;
        result.value &= mask;
        result.flags.parity = {(std::popcount(static_cast<unsigned>(result.value & 0xff)) & 1) == 0, true};
        result.flags.zero = {result.value == 0, true};
        result.flags.sign = {(result.value & sign_bit) != 0, true};
        if (count == 1) {
            const bool overflow = left ? (((result.value & sign_bit) != 0) != carry)
                                : operation == X86ShiftRotate::shr ? ((value & sign_bit) != 0) : false;
            result.flags.overflow = {overflow, true};
        }
        return result;
    }

    // Model rotations as bit movement through a width-bit ring, or a
    // width+1-bit ring when the carry flag participates.
    bool carry = incoming.carry;
    if (operation == X86ShiftRotate::rol || operation == X86ShiftRotate::rcl) {
        for (unsigned bit = 0; bit < count; ++bit) {
            const bool next = ((result.value & sign_bit) != 0);
            result.value = (result.value << 1) & mask;
            if (through_carry) {
                if (carry) result.value |= 1;
                carry = next;
            } else {
                if (next) result.value |= 1;
                carry = next;
            }
        }
        result.flags.carry = {carry, true};
        if (count == 1) result.flags.overflow = {((result.value & sign_bit) != 0) != carry, true};
    } else {
        for (unsigned bit = 0; bit < count; ++bit) {
            const bool next = (result.value & 1) != 0;
            result.value >>= 1;
            if (through_carry) {
                if (carry) result.value |= sign_bit;
                carry = next;
            } else {
                if (next) result.value |= sign_bit;
                carry = next;
            }
        }
        result.flags.carry = {carry, true};
        if (count == 1) {
            const bool msb = (result.value & sign_bit) != 0;
            const bool next_msb = (result.value & (sign_bit >> 1)) != 0;
            result.flags.overflow = {msb != next_msb, true};
        }
    }
    result.flags.parity = {incoming.parity, true};
    result.flags.zero = {incoming.zero, true};
    result.flags.sign = {incoming.sign, true};
    result.flags.auxiliary = incoming_auxiliary;
    return result;
}

// Evaluate Jcc predicates from the architectural status flags. Other EFLAGS
// bits do not participate in these sixteen integer condition codes.
constexpr bool evaluate_x86_condition(X86Condition condition, X86Flags flags) noexcept {
    const bool signed_less = flags.sign != flags.overflow;
    switch (condition) {
    case X86Condition::overflow: return flags.overflow;
    case X86Condition::not_overflow: return !flags.overflow;
    case X86Condition::below: return flags.carry;
    case X86Condition::above_equal: return !flags.carry;
    case X86Condition::equal: return flags.zero;
    case X86Condition::not_equal: return !flags.zero;
    case X86Condition::below_equal: return flags.carry || flags.zero;
    case X86Condition::above: return !flags.carry && !flags.zero;
    case X86Condition::sign: return flags.sign;
    case X86Condition::not_sign: return !flags.sign;
    case X86Condition::parity: return flags.parity;
    case X86Condition::not_parity: return !flags.parity;
    case X86Condition::less: return signed_less;
    case X86Condition::greater_equal: return !signed_less;
    case X86Condition::less_equal: return flags.zero || signed_less;
    case X86Condition::greater: return !flags.zero && !signed_less;
    }
    return false;
}

// Evaluate the LOOP-family counter update and branch predicate. Counter width
// is selected by address size (16/32/64); these instructions never alter flags.
constexpr X86LoopResult evaluate_x86_loop(X86LoopCondition condition, std::uint64_t counter,
                                           unsigned counter_width, bool zero_flag = false) noexcept {
    if (counter_width != 16 && counter_width != 32 && counter_width != 64) return {};
    const std::uint64_t mask = counter_width == 64 ? UINT64_MAX : (UINT64_C(1) << counter_width) - 1;
    const bool decremented = condition != X86LoopCondition::counter_zero;
    if (decremented) counter = (counter - 1) & mask;
    bool taken = false;
    switch (condition) {
    case X86LoopCondition::counter_nonzero: taken = counter != 0; break;
    case X86LoopCondition::counter_nonzero_and_zero: taken = counter != 0 && zero_flag; break;
    case X86LoopCondition::counter_nonzero_and_not_zero: taken = counter != 0 && !zero_flag; break;
    case X86LoopCondition::counter_zero: taken = counter == 0; break;
    }
    return {counter, taken, decremented};
}

} // namespace hexlab
