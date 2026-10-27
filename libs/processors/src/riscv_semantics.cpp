#include "hexlab/processors/riscv_semantics.hpp"
#include <algorithm>
#include <bit>

namespace hexlab {
namespace {
std::uint64_t width_mask(unsigned bits) noexcept {
    return bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
}

std::uint64_t multiply_high_unsigned(std::uint64_t a, std::uint64_t b) noexcept {
    const auto a0 = static_cast<std::uint32_t>(a), a1 = static_cast<std::uint32_t>(a >> 32);
    const auto b0 = static_cast<std::uint32_t>(b), b1 = static_cast<std::uint32_t>(b >> 32);
    const std::uint64_t p00 = std::uint64_t{a0} * b0;
    const std::uint64_t p01 = std::uint64_t{a0} * b1;
    const std::uint64_t p10 = std::uint64_t{a1} * b0;
    const std::uint64_t middle = (p00 >> 32) + static_cast<std::uint32_t>(p01) + static_cast<std::uint32_t>(p10);
    return std::uint64_t{a1} * b1 + (p01 >> 32) + (p10 >> 32) + (middle >> 32);
}

bool negative(std::uint64_t value, unsigned bits) noexcept {
    return (value & (UINT64_C(1) << (bits - 1))) != 0;
}

std::uint64_t magnitude(std::uint64_t value, unsigned bits) noexcept {
    const auto mask = width_mask(bits);
    value &= mask;
    return negative(value, bits) ? (UINT64_C(0) - value) & mask : value;
}

std::uint64_t signed_divide(std::uint64_t a, std::uint64_t b, unsigned bits, bool remainder) noexcept {
    const auto mask = width_mask(bits);
    a &= mask;
    b &= mask;
    if (b == 0)
        return remainder ? a : mask;
    const bool a_negative = negative(a, bits), b_negative = negative(b, bits);
    const auto a_magnitude = magnitude(a, bits), b_magnitude = magnitude(b, bits);
    const auto quotient = a_magnitude / b_magnitude;
    const auto rem = a_magnitude % b_magnitude;
    if (remainder)
        return a_negative ? (UINT64_C(0) - rem) & mask : rem;
    const bool result_negative = a_negative != b_negative;
    return result_negative ? (UINT64_C(0) - quotient) & mask : quotient;
}

std::uint64_t unsigned_divide(std::uint64_t a, std::uint64_t b, unsigned bits, bool remainder) noexcept {
    const auto mask = width_mask(bits);
    a &= mask;
    b &= mask;
    if (b == 0)
        return remainder ? a : mask;
    return remainder ? a % b : a / b;
}

std::uint64_t sign_extend_32(std::uint32_t value) noexcept {
    return static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(value)));
}

std::uint64_t multiply_high(std::uint64_t a, std::uint64_t b, unsigned bits, bool signed_a,
                            bool signed_b) noexcept {
    const auto mask = width_mask(bits);
    a &= mask;
    b &= mask;
    std::uint64_t high = 0;
    if (bits <= 32) {
        const auto product = a * b;
        high = product >> bits;
    } else {
        high = multiply_high_unsigned(a, b);
    }
    if (signed_a && negative(a, bits))
        high = (high - b) & mask;
    if (signed_b && negative(b, bits))
        high = (high - a) & mask;
    return high;
}
} // namespace

std::optional<std::uint64_t> evaluate_riscv_m_operation(RiscvOpcode opcode, unsigned xlen, std::uint64_t lhs,
                                                        std::uint64_t rhs) noexcept {
    if (xlen != 32 && xlen != 64)
        return {};
    const auto mask = width_mask(xlen);
    lhs &= mask;
    rhs &= mask;
    switch (opcode) {
    case RiscvOpcode::mul: return (lhs * rhs) & mask;
    case RiscvOpcode::mulh:
        return multiply_high(lhs, rhs, xlen, true, true);
    case RiscvOpcode::mulhsu:
        return multiply_high(lhs, rhs, xlen, true, false);
    case RiscvOpcode::mulhu:
        return multiply_high(lhs, rhs, xlen, false, false);
    case RiscvOpcode::div: return signed_divide(lhs, rhs, xlen, false);
    case RiscvOpcode::divu: return unsigned_divide(lhs, rhs, xlen, false);
    case RiscvOpcode::rem: return signed_divide(lhs, rhs, xlen, true);
    case RiscvOpcode::remu: return unsigned_divide(lhs, rhs, xlen, true);
    case RiscvOpcode::mulw:
        if (xlen != 64) return {};
        return sign_extend_32(static_cast<std::uint32_t>(lhs) * static_cast<std::uint32_t>(rhs));
    case RiscvOpcode::divw:
        if (xlen != 64) return {};
        return sign_extend_32(static_cast<std::uint32_t>(signed_divide(lhs, rhs, 32, false)));
    case RiscvOpcode::divuw:
        if (xlen != 64) return {};
        return sign_extend_32(static_cast<std::uint32_t>(unsigned_divide(lhs, rhs, 32, false)));
    case RiscvOpcode::remw:
        if (xlen != 64) return {};
        return sign_extend_32(static_cast<std::uint32_t>(signed_divide(lhs, rhs, 32, true)));
    case RiscvOpcode::remuw:
        if (xlen != 64) return {};
        return sign_extend_32(static_cast<std::uint32_t>(unsigned_divide(lhs, rhs, 32, true)));
    default: return {};
    }
}

std::optional<std::uint64_t> evaluate_riscv_zbb_count_operation(RiscvOpcode opcode, unsigned xlen,
                                                                std::uint64_t value) noexcept {
    if (xlen != 32 && xlen != 64)
        return {};
    const bool word = opcode == RiscvOpcode::clzw || opcode == RiscvOpcode::ctzw ||
                      opcode == RiscvOpcode::cpopw;
    if (word && xlen != 64)
        return {};
    const unsigned width = word ? 32 : xlen;
    value &= width_mask(width);
    switch (opcode) {
    case RiscvOpcode::clz: case RiscvOpcode::clzw:
        return value ? static_cast<std::uint64_t>(std::countl_zero(value) - (64u - width)) : width;
    case RiscvOpcode::ctz: case RiscvOpcode::ctzw:
        return value ? static_cast<std::uint64_t>(std::countr_zero(value)) : width;
    case RiscvOpcode::cpop: case RiscvOpcode::cpopw:
        return static_cast<std::uint64_t>(std::popcount(value));
    default:
        return {};
    }
}

std::optional<std::uint64_t> evaluate_riscv_zba_operation(RiscvOpcode opcode, unsigned xlen,
                                                           std::uint64_t lhs,
                                                           std::uint64_t rhs) noexcept {
    if (xlen != 32 && xlen != 64) return {};
    const std::uint64_t mask = xlen == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    switch (opcode) {
    case RiscvOpcode::sh1add: return ((lhs << 1) + rhs) & mask;
    case RiscvOpcode::sh2add: return ((lhs << 2) + rhs) & mask;
    case RiscvOpcode::sh3add: return ((lhs << 3) + rhs) & mask;
    case RiscvOpcode::add_uw:
        if (xlen != 64) return {};
        return static_cast<std::uint64_t>(static_cast<std::uint32_t>(lhs)) + rhs;
    case RiscvOpcode::sh1add_uw:
        if (xlen != 64) return {};
        return (static_cast<std::uint64_t>(static_cast<std::uint32_t>(lhs)) << 1) + rhs;
    case RiscvOpcode::sh2add_uw:
        if (xlen != 64) return {};
        return (static_cast<std::uint64_t>(static_cast<std::uint32_t>(lhs)) << 2) + rhs;
    case RiscvOpcode::sh3add_uw:
        if (xlen != 64) return {};
        return (static_cast<std::uint64_t>(static_cast<std::uint32_t>(lhs)) << 3) + rhs;
    case RiscvOpcode::slli_uw:
        if (xlen != 64 || rhs > 63) return {};
        return static_cast<std::uint64_t>(static_cast<std::uint32_t>(lhs)) << rhs;
    default: return {};
    }
}

std::optional<RiscvIntegerConversionResult>
evaluate_riscv_fcvtmod_w_d(std::uint64_t source_bits, unsigned xlen) noexcept {
    if (xlen != 32 && xlen != 64) return {};

    constexpr std::uint64_t fraction_mask = (UINT64_C(1) << 52) - 1;
    const auto exponent = static_cast<unsigned>((source_bits >> 52) & 0x7ffu);
    const auto fraction = source_bits & fraction_mask;
    const bool negative_input = (source_bits >> 63) != 0;
    RiscvIntegerConversionResult result;

    // The Zfa instruction maps infinities and NaNs to zero and raises NV.
    if (exponent == 0x7ffu) {
        result.fflags_set = 0x10;
        return result;
    }

    const bool subnormal = exponent == 0;
    const std::uint64_t significand = subnormal ? fraction : ((UINT64_C(1) << 52) | fraction);
    const int unbiased_exponent = subnormal ? -1022 : static_cast<int>(exponent) - 1023;

    // Compute floor(abs(x)) and fractional status from the binary encoding;
    // this avoids host FP rounding modes and undefined out-of-range casts.
    std::uint64_t truncated_magnitude = 0;
    bool fractional = false;
    if (unbiased_exponent < 0) {
        fractional = significand != 0;
    } else if (unbiased_exponent < 52) {
        const unsigned discarded_bits = static_cast<unsigned>(52 - unbiased_exponent);
        const std::uint64_t discarded_mask = (UINT64_C(1) << discarded_bits) - 1;
        truncated_magnitude = significand >> discarded_bits;
        fractional = (significand & discarded_mask) != 0;
    }

    // FCVTMOD raises the same conversion flags as FCVT.W.D. NV has precedence
    // over NX when the rounded result is outside the signed 32-bit range.
    const std::uint64_t signed_limit = negative_input ? UINT64_C(0x80000000) : UINT64_C(0x7fffffff);
    // Values with exponent > 31 are always outside the signed word range. At
    // exponent 31, truncated_magnitude was computed without a left shift and
    // can be compared exactly, avoiding overflow in the range check.
    const bool invalid = unbiased_exponent > 31 || truncated_magnitude > signed_limit;
    if (invalid) result.fflags_set = 0x10;
    else if (fractional) result.fflags_set = 0x01;

    // The low 32 bits of a left-shifted significand are zero once the shift is
    // 32 or greater, so avoid shifts at or above the C++ integer width.
    std::uint32_t low_bits = 0;
    if (unbiased_exponent >= 0 && unbiased_exponent < 52) {
        low_bits = static_cast<std::uint32_t>(truncated_magnitude);
    } else if (unbiased_exponent >= 52) {
        const auto shift = static_cast<unsigned>(unbiased_exponent - 52);
        if (shift < 32) low_bits = static_cast<std::uint32_t>(significand) << shift;
    }
    if (negative_input) low_bits = std::uint32_t{0} - low_bits;
    result.value = sign_extend_32(low_bits);
    return result;
}

std::optional<RiscvVectorIntegerConfig>
make_riscv_vector_integer_config(std::uint16_t vlen_bits, std::uint8_t xlen_bits,
                                 std::uint64_t vl, std::uint64_t vstart,
                                 std::uint64_t encoded_vtype, bool masked) {
    if ((xlen_bits != 32 && xlen_bits != 64) || (xlen_bits == 32 && encoded_vtype > UINT32_MAX) ||
        vlen_bits < 64 || vlen_bits > 65528 || vlen_bits % 8 != 0)
        return {};
    const auto xmask = width_mask(xlen_bits);
    encoded_vtype &= xmask;
    if ((encoded_vtype & (UINT64_C(1) << (xlen_bits - 1))) != 0 || (encoded_vtype & ~UINT64_C(0xff)) != 0)
        return {}; // vill or reserved high encoding bits
    const unsigned vsew = static_cast<unsigned>((encoded_vtype >> 3) & 7);
    const unsigned vlmul = static_cast<unsigned>(encoded_vtype & 7);
    if (vsew > 3 || vlmul == 4) return {};
    RiscvVectorIntegerConfig config;
    config.vlen_bits = vlen_bits;
    config.sew_bits = static_cast<std::uint8_t>(8u << vsew);
    config.lmul_log2 = static_cast<std::int8_t>(vlmul <= 3 ? static_cast<int>(vlmul) : static_cast<int>(vlmul) - 8);
    config.xlen_bits = xlen_bits;
    config.vl = vl;
    config.vstart = vstart;
    config.masked = masked;
    // Validate VLMAX and the active length through the same common path.
    const auto lanes = static_cast<std::uint64_t>(vlen_bits / config.sew_bits);
    const auto divisor = config.lmul_log2 < 0 ? (UINT64_C(1) << -config.lmul_log2) : 1;
    const auto vlmax = config.lmul_log2 >= 0 ? lanes << config.lmul_log2 : lanes / divisor;
    if ((config.lmul_log2 < 0 && lanes % divisor != 0) || vlmax == 0 || vlmax > 65536 ||
        vl > vlmax || vstart > vl) return {};
    return config;
}

std::optional<RiscvVectorConfigurationState>
evaluate_riscv_vector_configuration(const RiscvInstruction &instruction,
                                   std::uint8_t xlen_bits, std::uint16_t vlen_bits,
                                   std::uint64_t rs1_value, std::uint64_t rs2_value,
                                   std::uint64_t current_vl) {
    if ((xlen_bits != 32 && xlen_bits != 64) || vlen_bits < 64 || vlen_bits > 65528 || vlen_bits % 8)
        return {};
    if (instruction.opcode != RiscvOpcode::vsetvli && instruction.opcode != RiscvOpcode::vsetivli &&
        instruction.opcode != RiscvOpcode::vsetvl)
        return {};
    if (instruction.operands.size() != 3) return {};
    const auto *rd = std::get_if<RiscvRegister>(&instruction.operands[0]);
    if (!rd || rd->floating_point || rd->vector || rd->vector_configuration || rd->index >= 32) return {};

    std::uint64_t avl = 0, encoded_vtype = 0;
    bool rs1_zero = false;
    if (instruction.opcode == RiscvOpcode::vsetivli) {
        const auto *avl_immediate = std::get_if<RiscvImmediate>(&instruction.operands[1]);
        const auto *vtype_immediate = std::get_if<RiscvImmediate>(&instruction.operands[2]);
        if (!avl_immediate || avl_immediate->is_signed || avl_immediate->encoded_width != 5 ||
            avl_immediate->value < 0 || avl_immediate->value > 31 || !vtype_immediate ||
            vtype_immediate->is_signed || vtype_immediate->encoded_width != 10 || vtype_immediate->value < 0)
            return {};
        avl = static_cast<std::uint64_t>(avl_immediate->value);
        encoded_vtype = static_cast<std::uint64_t>(vtype_immediate->value);
    } else {
        const auto *rs1 = std::get_if<RiscvRegister>(&instruction.operands[1]);
        if (!rs1 || rs1->floating_point || rs1->vector || rs1->vector_configuration || rs1->index >= 32)
            return {};
        rs1_zero = rs1->index == 0;
        if (instruction.opcode == RiscvOpcode::vsetvli) {
            const auto *vtype_immediate = std::get_if<RiscvImmediate>(&instruction.operands[2]);
            if (!vtype_immediate || vtype_immediate->is_signed || vtype_immediate->encoded_width != 11 ||
                vtype_immediate->value < 0)
                return {};
            encoded_vtype = static_cast<std::uint64_t>(vtype_immediate->value);
        } else {
            const auto *rs2 = std::get_if<RiscvRegister>(&instruction.operands[2]);
            if (!rs2 || rs2->floating_point || rs2->vector || rs2->vector_configuration || rs2->index >= 32)
                return {};
            encoded_vtype = rs2->index == 0 ? 0 : rs2_value;
        }
    }

    const auto xmask = width_mask(xlen_bits);
    encoded_vtype &= xmask;
    RiscvVectorConfigurationState result;
    result.vstart = 0;
    const auto valid = make_riscv_vector_integer_config(vlen_bits, xlen_bits, 0, 0, encoded_vtype, false);
    if (!valid) {
        result.vill = true;
        result.vtype = UINT64_C(1) << (xlen_bits - 1);
        return result;
    }
    result.vtype = encoded_vtype;
    result.sew_bits = valid->sew_bits;
    result.lmul_log2 = valid->lmul_log2;
    result.tail_agnostic = (encoded_vtype & (UINT64_C(1) << 6)) != 0;
    result.mask_agnostic = (encoded_vtype & (UINT64_C(1) << 7)) != 0;

    if (instruction.opcode != RiscvOpcode::vsetivli) {
        if (rs1_zero)
            avl = rd->index == 0 ? current_vl & xmask : UINT64_MAX;
        else
            avl = rs1_value & xmask;
    }
    const auto base_lanes = static_cast<std::uint64_t>(vlen_bits / valid->sew_bits);
    const auto vlmax = valid->lmul_log2 >= 0
        ? base_lanes << static_cast<unsigned>(valid->lmul_log2)
        : base_lanes / (UINT64_C(1) << static_cast<unsigned>(-valid->lmul_log2));
    result.vl = std::min(avl, vlmax);
    return result;
}

std::optional<RiscvVectorIntegerResult>
evaluate_riscv_vector_integer_operation(RiscvOpcode opcode, const RiscvVectorIntegerConfig &config,
                                       const RiscvVectorIntegerOperands &operands) {
    const unsigned sew = config.sew_bits, xlen = config.xlen_bits;
    if ((sew != 8 && sew != 16 && sew != 32 && sew != 64) || (xlen != 32 && xlen != 64) ||
        config.vlen_bits < 64 || config.vlen_bits > 65528 || config.vlen_bits % 8 != 0 ||
        config.lmul_log2 < -3 || config.lmul_log2 > 3)
        return {};
    const std::uint64_t base_lanes = config.vlen_bits / sew;
    std::uint64_t vlmax = base_lanes;
    if (config.lmul_log2 >= 0) {
        vlmax <<= static_cast<unsigned>(config.lmul_log2);
    } else {
        const auto divisor = UINT64_C(1) << static_cast<unsigned>(-config.lmul_log2);
        if (base_lanes % divisor != 0) return {};
        vlmax = base_lanes / divisor;
    }
    if (vlmax == 0 || vlmax > 65536 || config.vl > vlmax || config.vstart > config.vl ||
        operands.vs2.size() != vlmax ||
        operands.old_destination.size() != vlmax || (config.masked && operands.predicate_mask.size() != vlmax))
        return {};

    const bool gather_vv = opcode == RiscvOpcode::vrgather_vv;
    const bool gather_vx = opcode == RiscvOpcode::vrgather_vx;
    const bool gather_vi = opcode == RiscvOpcode::vrgather_vi;
    const bool slide_up_vx = opcode == RiscvOpcode::vslideup_vx;
    const bool slide_up_vi = opcode == RiscvOpcode::vslideup_vi;
    const bool slide_down_vx = opcode == RiscvOpcode::vslidedown_vx;
    const bool slide_down_vi = opcode == RiscvOpcode::vslidedown_vi;
    if (gather_vv || gather_vx || gather_vi || slide_up_vx || slide_up_vi ||
        slide_down_vx || slide_down_vi) {
        if (gather_vv && operands.vs1.size() != vlmax) return {};
        if ((gather_vi || slide_up_vi || slide_down_vi) &&
            (operands.immediate < 0 || operands.immediate > 31))
            return {};
        const auto xlen_mask = width_mask(xlen);
        const std::uint64_t encoded_index = gather_vx || slide_up_vx || slide_down_vx
            ? operands.scalar & xlen_mask
            : static_cast<std::uint64_t>(operands.immediate);
        const auto element_mask = width_mask(sew);
        RiscvVectorIntegerResult result;
        result.vlmax = vlmax;
        result.element_bits = static_cast<std::uint8_t>(sew);
        result.lanes.assign(operands.old_destination.begin(), operands.old_destination.end());
        for (std::uint64_t lane = config.vstart; lane < config.vl; ++lane) {
            if (config.masked && operands.predicate_mask[static_cast<std::size_t>(lane)] == 0)
                continue;
            std::uint64_t value = 0;
            if (gather_vv || gather_vx || gather_vi) {
                const auto index = gather_vv
                    ? operands.vs1[static_cast<std::size_t>(lane)] & element_mask
                    : encoded_index;
                if (index < vlmax)
                    value = operands.vs2[static_cast<std::size_t>(index)] & element_mask;
            } else if (slide_up_vx || slide_up_vi) {
                if (lane < encoded_index) continue; // Slide-up preserves the low destination elements.
                const auto source_lane = lane - encoded_index;
                if (source_lane < vlmax)
                    value = operands.vs2[static_cast<std::size_t>(source_lane)] & element_mask;
            } else {
                // An out-of-range slide-down source element is architecturally zero.
                if (encoded_index < vlmax - lane)
                    value = operands.vs2[static_cast<std::size_t>(lane + encoded_index)] & element_mask;
            }
            result.lanes[static_cast<std::size_t>(lane)] = value;
        }
        return result;
    }

    // Widening add/sub destinations have EEW=2*SEW and EMUL=2*LMUL.
    // The number of lane indices stays VLEN*LMUL/SEW. The uint64_t result
    // representation therefore supports source SEW through 32 only.
    bool widening_add_sub = false, wide_source = false, subtract = false;
    bool signed_operation = false, vector_source = false;
    switch (opcode) {
#define RV_WIDEN_CASE(op, wide, sub, sign, vec) \
    case RiscvOpcode::op: widening_add_sub = true; wide_source = wide; subtract = sub; \
        signed_operation = sign; vector_source = vec; break
    RV_WIDEN_CASE(vwadd_vv, false, false, true, true);
    RV_WIDEN_CASE(vwadd_vx, false, false, true, false);
    RV_WIDEN_CASE(vwadd_wv, true, false, true, true);
    RV_WIDEN_CASE(vwadd_wx, true, false, true, false);
    RV_WIDEN_CASE(vwaddu_vv, false, false, false, true);
    RV_WIDEN_CASE(vwaddu_vx, false, false, false, false);
    RV_WIDEN_CASE(vwaddu_wv, true, false, false, true);
    RV_WIDEN_CASE(vwaddu_wx, true, false, false, false);
    RV_WIDEN_CASE(vwsub_vv, false, true, true, true);
    RV_WIDEN_CASE(vwsub_vx, false, true, true, false);
    RV_WIDEN_CASE(vwsub_wv, true, true, true, true);
    RV_WIDEN_CASE(vwsub_wx, true, true, true, false);
    RV_WIDEN_CASE(vwsubu_vv, false, true, false, true);
    RV_WIDEN_CASE(vwsubu_vx, false, true, false, false);
    RV_WIDEN_CASE(vwsubu_wv, true, true, false, true);
    RV_WIDEN_CASE(vwsubu_wx, true, true, false, false);
#undef RV_WIDEN_CASE
    default: break;
    }
    if (widening_add_sub) {
        if (sew > 32 || config.lmul_log2 > 2 || (vector_source && operands.vs1.size() != vlmax))
            return {}; // 2*SEW must fit and widened EMUL must remain <= m8.
        const unsigned wide_bits = wide_source ? 2 * sew : sew;
        const auto narrow_mask = width_mask(sew);
        const auto destination_mask = width_mask(2 * sew);
        const auto extend = [](std::uint64_t value, unsigned from, unsigned to, bool sign) {
            const auto from_mask = width_mask(from);
            value &= from_mask;
            if (sign && negative(value, from)) value |= ~from_mask;
            return value & width_mask(to);
        };
        std::uint64_t scalar_narrow = operands.scalar & width_mask(xlen);
        if (sew > xlen && (scalar_narrow & (UINT64_C(1) << (xlen - 1))))
            scalar_narrow |= ~width_mask(xlen);
        scalar_narrow &= narrow_mask;
        RiscvVectorIntegerResult result;
        result.vlmax = vlmax;
        result.element_bits = static_cast<std::uint8_t>(2 * sew);
        result.lanes.assign(operands.old_destination.begin(), operands.old_destination.end());
        for (std::uint64_t lane = config.vstart; lane < config.vl; ++lane) {
            if (config.masked && operands.predicate_mask[static_cast<std::size_t>(lane)] == 0) continue;
            const auto lhs_raw = operands.vs2[static_cast<std::size_t>(lane)];
            const auto rhs_raw = vector_source ? operands.vs1[static_cast<std::size_t>(lane)] : scalar_narrow;
            const auto lhs = extend(lhs_raw, wide_bits, 2 * sew, wide_source && signed_operation);
            const auto rhs = extend(rhs_raw, sew, 2 * sew, signed_operation);
            result.lanes[static_cast<std::size_t>(lane)] =
                (subtract ? lhs - rhs : lhs + rhs) & destination_mask;
        }
        return result;
    }

    bool widening_multiply = false, widening_vector_multiplier = false;
    bool widening_first_signed = false, widening_second_signed = false;
    switch (opcode) {
    case RiscvOpcode::vwmulu_vv: widening_multiply = true; widening_vector_multiplier = true; break;
    case RiscvOpcode::vwmulu_vx: widening_multiply = true; break;
    case RiscvOpcode::vwmulsu_vv: widening_multiply = true; widening_vector_multiplier = true; widening_first_signed = true; break;
    case RiscvOpcode::vwmulsu_vx: widening_multiply = true; widening_first_signed = true; break;
    case RiscvOpcode::vwmul_vv: widening_multiply = true; widening_vector_multiplier = true; widening_first_signed = widening_second_signed = true; break;
    case RiscvOpcode::vwmul_vx: widening_multiply = true; widening_first_signed = widening_second_signed = true; break;
    default: break;
    }
    if (widening_multiply) {
        if (sew > 32 || config.lmul_log2 > 2 ||
            (widening_vector_multiplier && operands.vs1.size() != vlmax))
            return {};
        const auto source_mask = width_mask(sew);
        const auto destination_mask = width_mask(2 * sew);
        const auto extend = [source_mask, sew](std::uint64_t value, bool is_signed) {
            value &= source_mask;
            if (is_signed && negative(value, sew)) value |= ~source_mask;
            return value;
        };
        std::uint64_t scalar = operands.scalar & width_mask(xlen);
        if (sew > xlen && (scalar & (UINT64_C(1) << (xlen - 1))))
            scalar |= ~width_mask(xlen);
        RiscvVectorIntegerResult result;
        result.vlmax = vlmax;
        result.element_bits = static_cast<std::uint8_t>(2 * sew);
        result.lanes.assign(operands.old_destination.begin(), operands.old_destination.end());
        for (std::uint64_t lane = config.vstart; lane < config.vl; ++lane) {
            if (config.masked && operands.predicate_mask[static_cast<std::size_t>(lane)] == 0)
                continue;
            const auto second_raw = widening_vector_multiplier
                ? operands.vs1[static_cast<std::size_t>(lane)] : scalar;
            const auto first_raw = operands.vs2[static_cast<std::size_t>(lane)];
            result.lanes[static_cast<std::size_t>(lane)] =
                (extend(first_raw, widening_first_signed) * extend(second_raw, widening_second_signed)) & destination_mask;
        }
        return result;
    }

    // Widening MAC destinations have EMUL = 2*LMUL and 2*SEW-bit elements.
    // The public lane representation is uint64_t, so SEW=64 (a 128-bit
    // destination) is deliberately left to symbolic lifting.
    bool widening_mac = false, vector_multiplier = false;
    bool first_signed = false, second_signed = false;
    switch (opcode) {
    case RiscvOpcode::vwmaccu_vv: widening_mac = true; vector_multiplier = true; break;
    case RiscvOpcode::vwmaccu_vx: widening_mac = true; break;
    case RiscvOpcode::vwmacc_vv: widening_mac = true; vector_multiplier = true;
        first_signed = second_signed = true; break;
    case RiscvOpcode::vwmacc_vx: widening_mac = true;
        first_signed = second_signed = true; break;
    case RiscvOpcode::vwmaccsu_vv: widening_mac = true; vector_multiplier = true;
        first_signed = true; break;
    case RiscvOpcode::vwmaccsu_vx: widening_mac = true;
        first_signed = true; break;
    case RiscvOpcode::vwmaccus_vx: widening_mac = true;
        second_signed = true; break;
    default: break;
    }
    if (widening_mac) {
        if (sew > 32 || config.lmul_log2 > 2 ||
            (vector_multiplier && operands.vs1.size() != vlmax))
            return {};
        const auto source_mask = width_mask(sew);
        const auto destination_mask = width_mask(2 * sew);
        const auto extend = [source_mask, sew](std::uint64_t value, bool is_signed) {
            value &= source_mask;
            if (is_signed && negative(value, sew)) value |= ~source_mask;
            return value;
        };
        RiscvVectorIntegerResult result;
        result.vlmax = vlmax;
        result.element_bits = static_cast<std::uint8_t>(2 * sew);
        result.lanes.assign(operands.old_destination.begin(), operands.old_destination.end());
        for (std::uint64_t lane = config.vstart; lane < config.vl; ++lane) {
            if (config.masked && operands.predicate_mask[static_cast<std::size_t>(lane)] == 0)
                continue;
            const auto first = vector_multiplier ? operands.vs1[static_cast<std::size_t>(lane)] : operands.scalar;
            const auto second = operands.vs2[static_cast<std::size_t>(lane)];
            const auto product = extend(first, first_signed) * extend(second, second_signed);
            result.lanes[static_cast<std::size_t>(lane)] =
                (operands.old_destination[static_cast<std::size_t>(lane)] + product) & destination_mask;
        }
        return result;
    }

    enum class Operation { add, sub, rsub, bit_and, bit_or, bit_xor, shl, shr, sar,
                           minu, min, maxu, max, mul, mulh, mulhu, mulhsu,
                           divu, div, remu, rem, eq, ne, ltu, lt, leu, le, gtu, gt,
                           vmacc, vnmsac, vmadd, vnmsub };
    Operation operation;
    bool vector_rhs = false, scalar_rhs = false, immediate_rhs = false, mask_result = false;
    switch (opcode) {
#define RV_VECTOR_PAIR(vv, vx, name) case RiscvOpcode::vv: operation = Operation::name; vector_rhs = true; break; case RiscvOpcode::vx: operation = Operation::name; scalar_rhs = true; break
#define RV_VECTOR_TRIPLE(vv, vx, vi, name) RV_VECTOR_PAIR(vv, vx, name); case RiscvOpcode::vi: operation = Operation::name; immediate_rhs = true; break
    RV_VECTOR_TRIPLE(vadd_vv, vadd_vx, vadd_vi, add);
    RV_VECTOR_PAIR(vsub_vv, vsub_vx, sub);
    case RiscvOpcode::vrsub_vx: operation = Operation::rsub; scalar_rhs = true; break;
    case RiscvOpcode::vrsub_vi: operation = Operation::rsub; immediate_rhs = true; break;
    RV_VECTOR_TRIPLE(vand_vv, vand_vx, vand_vi, bit_and);
    RV_VECTOR_TRIPLE(vor_vv, vor_vx, vor_vi, bit_or);
    RV_VECTOR_TRIPLE(vxor_vv, vxor_vx, vxor_vi, bit_xor);
    RV_VECTOR_TRIPLE(vsll_vv, vsll_vx, vsll_vi, shl);
    RV_VECTOR_TRIPLE(vsrl_vv, vsrl_vx, vsrl_vi, shr);
    RV_VECTOR_TRIPLE(vsra_vv, vsra_vx, vsra_vi, sar);
    RV_VECTOR_PAIR(vminu_vv, vminu_vx, minu);
    RV_VECTOR_PAIR(vmin_vv, vmin_vx, min);
    RV_VECTOR_PAIR(vmaxu_vv, vmaxu_vx, maxu);
    RV_VECTOR_PAIR(vmax_vv, vmax_vx, max);
    RV_VECTOR_PAIR(vmul_vv, vmul_vx, mul);
    RV_VECTOR_PAIR(vmulh_vv, vmulh_vx, mulh);
    RV_VECTOR_PAIR(vmulhu_vv, vmulhu_vx, mulhu);
    RV_VECTOR_PAIR(vmulhsu_vv, vmulhsu_vx, mulhsu);
    RV_VECTOR_PAIR(vdivu_vv, vdivu_vx, divu);
    RV_VECTOR_PAIR(vdiv_vv, vdiv_vx, div);
    RV_VECTOR_PAIR(vremu_vv, vremu_vx, remu);
    RV_VECTOR_PAIR(vrem_vv, vrem_vx, rem);
    RV_VECTOR_PAIR(vmacc_vv, vmacc_vx, vmacc);
    RV_VECTOR_PAIR(vnmsac_vv, vnmsac_vx, vnmsac);
    RV_VECTOR_PAIR(vmadd_vv, vmadd_vx, vmadd);
    RV_VECTOR_PAIR(vnmsub_vv, vnmsub_vx, vnmsub);
    case RiscvOpcode::vmseq_vv: operation = Operation::eq; vector_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmseq_vx: operation = Operation::eq; scalar_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmseq_vi: operation = Operation::eq; immediate_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmsne_vv: operation = Operation::ne; vector_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmsne_vx: operation = Operation::ne; scalar_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmsne_vi: operation = Operation::ne; immediate_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmsltu_vv: operation = Operation::ltu; vector_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmsltu_vx: operation = Operation::ltu; scalar_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmslt_vv: operation = Operation::lt; vector_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmslt_vx: operation = Operation::lt; scalar_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmsleu_vv: operation = Operation::leu; vector_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmsleu_vx: operation = Operation::leu; scalar_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmsleu_vi: operation = Operation::leu; immediate_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmsle_vv: operation = Operation::le; vector_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmsle_vx: operation = Operation::le; scalar_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmsle_vi: operation = Operation::le; immediate_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmsgtu_vx: operation = Operation::gtu; scalar_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmsgtu_vi: operation = Operation::gtu; immediate_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmsgt_vx: operation = Operation::gt; scalar_rhs = true; mask_result = true; break;
    case RiscvOpcode::vmsgt_vi: operation = Operation::gt; immediate_rhs = true; mask_result = true; break;
#undef RV_VECTOR_TRIPLE
#undef RV_VECTOR_PAIR
    default: return {};
    }
    if ((vector_rhs && operands.vs1.size() != vlmax) ||
        (!vector_rhs && !scalar_rhs && !immediate_rhs) || (vector_rhs && scalar_rhs) ||
        (scalar_rhs && immediate_rhs)) return {};

    const auto mask = width_mask(sew);
    std::uint64_t scalar = operands.scalar & width_mask(xlen);
    if (scalar_rhs && sew > xlen && (scalar & (UINT64_C(1) << (xlen - 1))))
        scalar |= ~width_mask(xlen);
    scalar &= mask;
    const std::uint64_t imm = static_cast<std::uint64_t>(operands.immediate) & mask;
    const auto signed_less = [sew](std::uint64_t lhs, std::uint64_t rhs) {
        const bool ln = negative(lhs, sew), rn = negative(rhs, sew);
        return ln != rn ? ln : lhs < rhs;
    };
    RiscvVectorIntegerResult result;
    result.vlmax = vlmax;
    result.mask_result = mask_result;
    result.element_bits = mask_result ? 1 : static_cast<std::uint8_t>(sew);
    result.lanes.assign(operands.old_destination.begin(), operands.old_destination.end());
    for (std::uint64_t lane = config.vstart; lane < config.vl; ++lane) {
        if (config.masked && operands.predicate_mask[static_cast<std::size_t>(lane)] == 0) continue;
        const std::uint64_t lhs = operands.vs2.size() == vlmax ? operands.vs2[static_cast<std::size_t>(lane)] & mask : 0;
        if (operands.vs2.size() != vlmax) return {};
        const std::uint64_t rhs = vector_rhs ? operands.vs1[static_cast<std::size_t>(lane)] & mask : scalar_rhs ? scalar : imm;
        std::uint64_t value = 0;
        switch (operation) {
        case Operation::add: value = (lhs + rhs) & mask; break;
        case Operation::sub: value = (lhs - rhs) & mask; break;
        case Operation::rsub: value = (rhs - lhs) & mask; break;
        case Operation::bit_and: value = lhs & rhs; break;
        case Operation::bit_or: value = lhs | rhs; break;
        case Operation::bit_xor: value = lhs ^ rhs; break;
        case Operation::shl: value = (lhs << (rhs & (sew - 1))) & mask; break;
        case Operation::shr: value = lhs >> (rhs & (sew - 1)); break;
        case Operation::sar: {
            const unsigned shift = static_cast<unsigned>(rhs & (sew - 1));
            value = shift == 0 ? lhs : (lhs >> shift) | (negative(lhs, sew) ? (mask ^ (mask >> shift)) : 0);
            break;
        }
        case Operation::minu: value = lhs < rhs ? lhs : rhs; break;
        case Operation::min: value = signed_less(lhs, rhs) ? lhs : rhs; break;
        case Operation::maxu: value = lhs > rhs ? lhs : rhs; break;
        case Operation::max: value = signed_less(lhs, rhs) ? rhs : lhs; break;
        case Operation::mul: value = (lhs * rhs) & mask; break;
        case Operation::mulh: value = multiply_high(lhs, rhs, sew, true, true); break;
        case Operation::mulhu: value = multiply_high(lhs, rhs, sew, false, false); break;
        case Operation::mulhsu: value = multiply_high(lhs, rhs, sew, true, false); break;
        case Operation::divu: value = unsigned_divide(lhs, rhs, sew, false); break;
        case Operation::div: value = signed_divide(lhs, rhs, sew, false); break;
        case Operation::remu: value = unsigned_divide(lhs, rhs, sew, true); break;
        case Operation::rem: value = signed_divide(lhs, rhs, sew, true); break;
        case Operation::vmacc: value = (operands.old_destination[static_cast<std::size_t>(lane)] + lhs * rhs) & mask; break;
        case Operation::vnmsac: value = (operands.old_destination[static_cast<std::size_t>(lane)] - lhs * rhs) & mask; break;
        case Operation::vmadd: value = (lhs + operands.old_destination[static_cast<std::size_t>(lane)] * rhs) & mask; break;
        case Operation::vnmsub: value = (lhs - operands.old_destination[static_cast<std::size_t>(lane)] * rhs) & mask; break;
        case Operation::eq: value = lhs == rhs; break;
        case Operation::ne: value = lhs != rhs; break;
        case Operation::ltu: value = lhs < rhs; break;
        case Operation::lt: value = signed_less(lhs, rhs); break;
        case Operation::leu: value = lhs <= rhs; break;
        case Operation::le: value = !signed_less(rhs, lhs); break;
        case Operation::gtu: value = lhs > rhs; break;
        case Operation::gt: value = signed_less(rhs, lhs); break;
        }
        result.lanes[static_cast<std::size_t>(lane)] = mask_result ? value : value & mask;
    }
    return result;
}

std::optional<RiscvVectorFloatingResult>
evaluate_riscv_vector_floating_operation(RiscvOpcode opcode, const RiscvVectorIntegerConfig &config,
                                         const RiscvVectorFloatingOperands &operands) {
    const unsigned sew = config.sew_bits;
    if ((sew != 32 && sew != 64) || (config.xlen_bits != 32 && config.xlen_bits != 64) ||
        config.vlen_bits < 64 || config.vlen_bits > 65528 || config.vlen_bits % 8 != 0 ||
        config.lmul_log2 < -3 || config.lmul_log2 > 3)
        return {};
    const std::uint64_t base_lanes = config.vlen_bits / sew;
    std::uint64_t vlmax = base_lanes;
    if (config.lmul_log2 >= 0)
        vlmax <<= static_cast<unsigned>(config.lmul_log2);
    else {
        const auto divisor = UINT64_C(1) << static_cast<unsigned>(-config.lmul_log2);
        if (base_lanes % divisor != 0) return {};
        vlmax = base_lanes / divisor;
    }
    if (!vlmax || vlmax > 65536 || config.vl > vlmax || config.vstart > config.vl ||
        operands.vs2.size() != vlmax || operands.old_destination.size() != vlmax ||
        (config.masked && operands.predicate_mask.size() != vlmax))
        return {};

    enum class Operation { classification, sign_copy, sign_invert, sign_xor, min, max, equal, not_equal,
                           less, less_equal, greater, greater_equal };
    Operation operation;
    bool vector_rhs = false, mask_result = false;
    switch (opcode) {
    case RiscvOpcode::vfclass_v: operation = Operation::classification; break;
#define RV_FLOAT_PAIR(vv, vf, name) \
    case RiscvOpcode::vv: operation = Operation::name; vector_rhs = true; break; \
    case RiscvOpcode::vf: operation = Operation::name; break
    RV_FLOAT_PAIR(vfsgnj_vv, vfsgnj_vf, sign_copy);
    RV_FLOAT_PAIR(vfsgnjn_vv, vfsgnjn_vf, sign_invert);
    RV_FLOAT_PAIR(vfsgnjx_vv, vfsgnjx_vf, sign_xor);
    RV_FLOAT_PAIR(vfmin_vv, vfmin_vf, min);
    RV_FLOAT_PAIR(vfmax_vv, vfmax_vf, max);
    RV_FLOAT_PAIR(vmfeq_vv, vmfeq_vf, equal);
    RV_FLOAT_PAIR(vmfne_vv, vmfne_vf, not_equal);
    RV_FLOAT_PAIR(vmflt_vv, vmflt_vf, less);
    RV_FLOAT_PAIR(vmfle_vv, vmfle_vf, less_equal);
#undef RV_FLOAT_PAIR
    case RiscvOpcode::vmfgt_vf: operation = Operation::greater; break;
    case RiscvOpcode::vmfge_vf: operation = Operation::greater_equal; break;
    default: return {};
    }
    if (vector_rhs && operands.vs1.size() != vlmax) return {};
    mask_result = operation == Operation::equal || operation == Operation::not_equal ||
                  operation == Operation::less || operation == Operation::less_equal ||
                  operation == Operation::greater || operation == Operation::greater_equal;

    const auto element_mask = width_mask(sew);
    const auto sign_mask = UINT64_C(1) << (sew - 1);
    const auto exponent_mask = sew == 32 ? UINT64_C(0x7f800000) : UINT64_C(0x7ff0000000000000);
    const auto fraction_mask = sew == 32 ? UINT64_C(0x007fffff) : UINT64_C(0x000fffffffffffff);
    const auto quiet_mask = sew == 32 ? UINT64_C(0x00400000) : UINT64_C(0x0008000000000000);
    const auto canonical_nan = sew == 32 ? UINT64_C(0x7fc00000) : UINT64_C(0x7ff8000000000000);
    const auto is_nan = [&](std::uint64_t value) {
        value &= element_mask;
        return (value & exponent_mask) == exponent_mask && (value & fraction_mask) != 0;
    };
    const auto is_signaling_nan = [&](std::uint64_t value) {
        return is_nan(value) && (value & quiet_mask) == 0;
    };
    const auto is_zero = [&](std::uint64_t value) { return (value & ~sign_mask & element_mask) == 0; };
    const auto ordered_less = [&](std::uint64_t lhs, std::uint64_t rhs) {
        lhs &= element_mask;
        rhs &= element_mask;
        if (is_zero(lhs) && is_zero(rhs)) return false;
        const auto order_key = [&](std::uint64_t value) {
            return (value & sign_mask) ? (~value & element_mask) : (value ^ sign_mask);
        };
        return order_key(lhs) < order_key(rhs);
    };

    RiscvVectorFloatingResult result;
    result.vlmax = vlmax;
    result.mask_result = mask_result;
    result.element_bits = mask_result ? 1 : static_cast<std::uint8_t>(sew);
    result.lanes.assign(operands.old_destination.begin(), operands.old_destination.end());
    for (std::uint64_t lane = config.vstart; lane < config.vl; ++lane) {
        if (config.masked && operands.predicate_mask[static_cast<std::size_t>(lane)] == 0) continue;
        const auto lhs = operands.vs2[static_cast<std::size_t>(lane)] & element_mask;
        const auto rhs = vector_rhs ? operands.vs1[static_cast<std::size_t>(lane)] & element_mask
                                    : operands.scalar & element_mask;
        const bool lhs_nan = is_nan(lhs), rhs_nan = is_nan(rhs);
        const bool any_signaling_nan = is_signaling_nan(lhs) || is_signaling_nan(rhs);
        std::uint64_t value = 0;
        switch (operation) {
        case Operation::classification: {
            const auto magnitude = lhs & ~sign_mask;
            const auto exponent = magnitude & exponent_mask;
            const auto fraction = magnitude & fraction_mask;
            if (exponent == exponent_mask) {
                if (fraction == 0) value = UINT64_C(1) << (lhs & sign_mask ? 0 : 7);
                else {
                    const bool quiet = (fraction & quiet_mask) != 0;
                    value = UINT64_C(1) << (quiet ? 9 : 8);
                }
            } else if (exponent == 0) {
                if (fraction == 0) value = UINT64_C(1) << (lhs & sign_mask ? 3 : 4);
                else value = UINT64_C(1) << (lhs & sign_mask ? 2 : 5);
            } else {
                value = UINT64_C(1) << (lhs & sign_mask ? 1 : 6);
            }
            break;
        }
        case Operation::sign_copy:
            value = (lhs & ~sign_mask) | (rhs & sign_mask);
            break;
        case Operation::sign_invert:
            value = (lhs & ~sign_mask) | ((~rhs) & sign_mask);
            break;
        case Operation::sign_xor:
            value = (lhs & ~sign_mask) | ((lhs ^ rhs) & sign_mask);
            break;
        case Operation::min:
        case Operation::max:
            if (lhs_nan || rhs_nan) {
                if (any_signaling_nan) result.fflags_set |= 0x10;
                value = lhs_nan && rhs_nan ? canonical_nan : lhs_nan ? rhs : lhs;
            } else if (is_zero(lhs) && is_zero(rhs)) {
                // minimumNumber(-0,+0) is -0; maximumNumber(-0,+0) is +0.
                const auto signs = (lhs | rhs) & sign_mask;
                value = operation == Operation::min ? signs : signs ?
                    ((lhs & rhs) & sign_mask) : 0;
            } else {
                const bool take_lhs = ordered_less(lhs, rhs);
                value = operation == Operation::min ? (take_lhs ? lhs : rhs)
                                                    : (take_lhs ? rhs : lhs);
            }
            break;
        case Operation::equal:
        case Operation::not_equal:
        case Operation::less:
        case Operation::less_equal:
        case Operation::greater:
        case Operation::greater_equal: {
            const bool ordered_compare = operation == Operation::less || operation == Operation::less_equal ||
                                        operation == Operation::greater || operation == Operation::greater_equal;
            if (any_signaling_nan || (ordered_compare && (lhs_nan || rhs_nan)))
                result.fflags_set |= 0x10;
            bool predicate = false;
            if (operation == Operation::not_equal && (lhs_nan || rhs_nan)) {
                predicate = true;
            } else if (!lhs_nan && !rhs_nan) {
                const bool less = ordered_less(lhs, rhs);
                const bool equal = lhs == rhs || (is_zero(lhs) && is_zero(rhs));
                switch (operation) {
                case Operation::equal: predicate = equal; break;
                case Operation::not_equal: predicate = !equal; break;
                case Operation::less: predicate = less; break;
                case Operation::less_equal: predicate = less || equal; break;
                case Operation::greater: predicate = !less && !equal; break;
                case Operation::greater_equal: predicate = !less || equal; break;
                default: break;
                }
            }
            value = predicate ? 1u : 0u;
            break;
        }
        }
        result.lanes[static_cast<std::size_t>(lane)] = mask_result ? value : value & element_mask;
    }
    return result;
}

std::optional<RiscvVectorMemoryAccessPlan>
plan_riscv_vector_memory_accesses(RiscvOpcode opcode, const RiscvVectorIntegerConfig &config,
                                  std::uint64_t base, std::uint64_t stride_bits,
                                  std::uint8_t element_bits,
                                  std::span<const std::uint8_t> predicate_mask) {
    const bool load = opcode == RiscvOpcode::vle || opcode == RiscvOpcode::vlse;
    const bool unit_stride = opcode == RiscvOpcode::vle || opcode == RiscvOpcode::vse;
    const bool strided = opcode == RiscvOpcode::vlse || opcode == RiscvOpcode::vsse;
    if ((!unit_stride && !strided) || (element_bits != 8 && element_bits != 16 &&
        element_bits != 32 && element_bits != 64) ||
        (config.xlen_bits != 32 && config.xlen_bits != 64) ||
        (config.sew_bits != 8 && config.sew_bits != 16 &&
         config.sew_bits != 32 && config.sew_bits != 64) ||
        config.vlen_bits < 64 || config.vlen_bits > 65528 || config.vlen_bits % 8 != 0 ||
        config.vlen_bits % config.sew_bits != 0 ||
        config.lmul_log2 < -3 || config.lmul_log2 > 3)
        return {};

    const int sew_log2 = config.sew_bits == 8 ? 3 : config.sew_bits == 16 ? 4 :
                         config.sew_bits == 32 ? 5 : 6;
    const int eew_log2 = element_bits == 8 ? 3 : element_bits == 16 ? 4 :
                         element_bits == 32 ? 5 : 6;
    const int emul_log2 = static_cast<int>(config.lmul_log2) + eew_log2 - sew_log2;
    if (emul_log2 < -3 || emul_log2 > 3)
        return {}; // EMUL outside mf8..m8 is reserved.

    const std::uint64_t base_lanes = config.vlen_bits / config.sew_bits;
    std::uint64_t vlmax = base_lanes;
    if (config.lmul_log2 >= 0)
        vlmax <<= static_cast<unsigned>(config.lmul_log2);
    else {
        const auto divisor = UINT64_C(1) << static_cast<unsigned>(-config.lmul_log2);
        if (base_lanes % divisor != 0) return {};
        vlmax = base_lanes / divisor;
    }
    if (vlmax == 0 || vlmax > 65536 || config.vl > vlmax || config.vstart > config.vl ||
        (config.masked && predicate_mask.size() != vlmax))
        return {};

    const auto xlen_mask = width_mask(config.xlen_bits);
    if (base > xlen_mask || (strided && config.xlen_bits == 32 && stride_bits > UINT32_MAX))
        return {};
    std::int64_t signed_stride = 0;
    if (strided) {
        stride_bits &= xlen_mask;
        if (config.xlen_bits == 32) {
            const auto raw = static_cast<std::uint32_t>(stride_bits);
            signed_stride = raw & UINT32_C(0x80000000)
                ? static_cast<std::int64_t>(raw) - (INT64_C(1) << 32)
                : static_cast<std::int64_t>(raw);
        } else {
            signed_stride = std::bit_cast<std::int64_t>(stride_bits);
        }
    }

    RiscvVectorMemoryAccessPlan plan;
    plan.vlmax = vlmax;
    plan.element_bits = element_bits;
    plan.load = load;
    plan.active_elements.reserve(static_cast<std::size_t>(config.vl - config.vstart));
    const std::uint64_t element_bytes = element_bits / 8;
    for (std::uint64_t lane = config.vstart; lane < config.vl; ++lane) {
        if (config.masked && predicate_mask[static_cast<std::size_t>(lane)] == 0)
            continue;

        const bool negative_stride = strided && signed_stride < 0;
        const std::uint64_t magnitude = !strided ? element_bytes : negative_stride
            ? static_cast<std::uint64_t>(-(signed_stride + 1)) + 1
            : static_cast<std::uint64_t>(signed_stride);
        if (lane != 0 && magnitude > UINT64_MAX / lane)
            return {}; // lane * stride would overflow.
        const auto displacement = lane * magnitude;
        std::uint64_t address = base;
        if (negative_stride) {
            if (displacement > base) return {};
            address -= displacement;
        } else {
            if (displacement > xlen_mask - base) return {};
            address += displacement;
        }
        plan.active_elements.push_back({lane, address});
    }
    return plan;
}

std::optional<RiscvVectorMemoryAccessPlan>
plan_riscv_vector_indexed_memory_accesses(RiscvOpcode opcode, const RiscvVectorIntegerConfig &config,
                                          std::uint64_t base, std::uint8_t index_element_bits,
                                          std::span<const std::uint64_t> index_offsets,
                                          std::span<const std::uint8_t> predicate_mask) {
    const bool load = opcode == RiscvOpcode::vluxei || opcode == RiscvOpcode::vloxei;
    const bool unordered = opcode == RiscvOpcode::vluxei || opcode == RiscvOpcode::vsuxei;
    const bool store = opcode == RiscvOpcode::vsuxei || opcode == RiscvOpcode::vsoxei;
    const auto valid_width = [](unsigned bits) { return bits == 8 || bits == 16 || bits == 32 || bits == 64; };
    if ((!load && !store) || !valid_width(index_element_bits) || !valid_width(config.sew_bits) ||
        (config.xlen_bits != 32 && config.xlen_bits != 64) ||
        config.vlen_bits < 64 || config.vlen_bits > 65528 || config.vlen_bits % 8 != 0 ||
        config.vlen_bits % config.sew_bits != 0 || config.lmul_log2 < -3 || config.lmul_log2 > 3)
        return {};

    const auto log2_width = [](unsigned bits) -> int {
        return bits == 8 ? 3 : bits == 16 ? 4 : bits == 32 ? 5 : 6;
    };
    const int index_emul_log2 = static_cast<int>(config.lmul_log2) +
                                log2_width(index_element_bits) - log2_width(config.sew_bits);
    if (index_emul_log2 < -3 || index_emul_log2 > 3)
        return {}; // Index EEW derives an unrepresentable EMUL.

    const std::uint64_t base_lanes = config.vlen_bits / config.sew_bits;
    std::uint64_t vlmax = base_lanes;
    if (config.lmul_log2 >= 0)
        vlmax <<= static_cast<unsigned>(config.lmul_log2);
    else {
        const auto divisor = UINT64_C(1) << static_cast<unsigned>(-config.lmul_log2);
        if (base_lanes % divisor != 0) return {};
        vlmax = base_lanes / divisor;
    }
    if (!vlmax || vlmax > 65536 || config.vl > vlmax || config.vstart > config.vl ||
        index_offsets.size() != vlmax || (config.masked && predicate_mask.size() != vlmax))
        return {};

    const auto xlen_mask = width_mask(config.xlen_bits);
    const auto index_mask = width_mask(index_element_bits);
    if (base > xlen_mask) return {};
    RiscvVectorMemoryAccessPlan plan;
    plan.vlmax = vlmax;
    plan.element_bits = config.sew_bits;
    plan.index_element_bits = index_element_bits;
    plan.load = load;
    plan.ordered = !unordered;
    plan.active_elements.reserve(static_cast<std::size_t>(config.vl - config.vstart));
    for (std::uint64_t lane = config.vstart; lane < config.vl; ++lane) {
        if (config.masked && predicate_mask[static_cast<std::size_t>(lane)] == 0)
            continue;
        const auto raw_offset = index_offsets[static_cast<std::size_t>(lane)];
        if (raw_offset > index_mask)
            return {}; // Caller supplied bits outside the encoded index EEW.
        const auto offset = raw_offset & xlen_mask; // Wider indices use their low XLEN bits.
        if (offset > xlen_mask - base)
            return {}; // Reject address wrap rather than silently wrapping.
        plan.active_elements.push_back({lane, base + offset});
    }
    return plan;
}
} // namespace hexlab
