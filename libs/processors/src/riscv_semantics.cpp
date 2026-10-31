#include "hexlab/processors/riscv_semantics.hpp"
#include "riscv_estimate_tables.hpp"
#include <algorithm>
#include <bit>
#include <limits>

namespace hexlab {
namespace {
std::uint64_t width_mask(unsigned bits) noexcept {
    return bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
}

struct RiscvVectorFloatAddResult {
    std::uint64_t bits = 0;
    std::uint8_t fflags = 0;
};

RiscvVectorFloatAddResult add_riscv_float_bits(std::uint64_t lhs, std::uint64_t rhs,
                                               unsigned width, unsigned rounding_mode) noexcept {
    const unsigned fraction_bits = width == 32 ? 23 : 52;
    const unsigned exponent_bits = width == 32 ? 8 : 11;
    const int bias = width == 32 ? 127 : 1023;
    const auto element_mask = width_mask(width);
    const auto sign_mask = UINT64_C(1) << (width - 1);
    const auto fraction_mask = (UINT64_C(1) << fraction_bits) - 1;
    const auto exponent_field_mask = (UINT64_C(1) << exponent_bits) - 1;
    const auto exponent_mask = exponent_field_mask << fraction_bits;
    const auto quiet_mask = UINT64_C(1) << (fraction_bits - 1);
    const auto canonical_nan = width == 32 ? UINT64_C(0x7fc00000) : UINT64_C(0x7ff8000000000000);
    lhs &= element_mask;
    rhs &= element_mask;
    const auto exponent = [&](std::uint64_t value) {
        return static_cast<unsigned>((value & exponent_mask) >> fraction_bits);
    };
    const auto fraction = [&](std::uint64_t value) { return value & fraction_mask; };
    const auto is_nan = [&](std::uint64_t value) {
        return exponent(value) == exponent_field_mask && fraction(value) != 0;
    };
    const auto is_signaling_nan = [&](std::uint64_t value) {
        return is_nan(value) && (fraction(value) & quiet_mask) == 0;
    };
    if (is_nan(lhs) || is_nan(rhs))
        return {canonical_nan, static_cast<std::uint8_t>(is_signaling_nan(lhs) || is_signaling_nan(rhs) ? 0x10 : 0)};

    const bool lhs_negative = (lhs & sign_mask) != 0;
    const bool rhs_negative = (rhs & sign_mask) != 0;
    const auto lhs_exponent = exponent(lhs), rhs_exponent = exponent(rhs);
    const bool lhs_infinite = lhs_exponent == exponent_field_mask;
    const bool rhs_infinite = rhs_exponent == exponent_field_mask;
    if (lhs_infinite || rhs_infinite) {
        if (lhs_infinite && rhs_infinite && lhs_negative != rhs_negative)
            return {canonical_nan, 0x10};
        return {lhs_infinite ? lhs : rhs, 0};
    }

    const auto lhs_significand = (lhs_exponent ? (UINT64_C(1) << fraction_bits) : 0) | fraction(lhs);
    const auto rhs_significand = (rhs_exponent ? (UINT64_C(1) << fraction_bits) : 0) | fraction(rhs);
    if (!lhs_significand && !rhs_significand) {
        const auto sign = lhs_negative == rhs_negative ? lhs_negative : rounding_mode == 2;
        return {sign ? sign_mask : 0, 0};
    }
    if (!lhs_significand) return {rhs, 0};
    if (!rhs_significand) return {lhs, 0};

    unsigned large_exponent = std::max(lhs_exponent ? lhs_exponent : 1u,
                                       rhs_exponent ? rhs_exponent : 1u);
    std::uint64_t large = lhs_significand << 3;
    std::uint64_t small = rhs_significand << 3;
    bool result_negative = lhs_negative;
    const unsigned left_exp = lhs_exponent ? lhs_exponent : 1u;
    const unsigned right_exp = rhs_exponent ? rhs_exponent : 1u;
    if (left_exp < right_exp || (left_exp == right_exp && lhs_significand < rhs_significand)) {
        std::swap(large, small);
        result_negative = rhs_negative;
    }
    const unsigned small_exponent = std::min(left_exp, right_exp);
    const auto shift = large_exponent - small_exponent;
    if (shift) {
        const bool discarded = shift >= 64 ? small != 0 : (small & ((UINT64_C(1) << shift) - 1)) != 0;
        small = shift >= 64 ? 0 : small >> shift;
        if (discarded) small |= 1;
    }

    const bool same_sign = lhs_negative == rhs_negative;
    std::uint64_t significand = same_sign ? large + small : large - small;
    if (!significand) {
        const bool sign = rounding_mode == 2;
        return {sign ? sign_mask : 0, 0};
    }
    const auto hidden_extended = UINT64_C(1) << (fraction_bits + 3);
    if (same_sign && significand >= (hidden_extended << 1)) {
        const bool discarded = (significand & 1) != 0;
        significand >>= 1;
        if (discarded) significand |= 1;
        ++large_exponent;
    } else if (!same_sign) {
        while (significand < hidden_extended && large_exponent > 1) {
            significand <<= 1;
            --large_exponent;
        }
    }

    const auto tail = static_cast<unsigned>(significand & 7u);
    const bool inexact = tail != 0;
    const bool guard = (tail & 4u) != 0;
    const bool sticky = (tail & 3u) != 0;
    std::uint64_t rounded = significand >> 3;
    bool increment = false;
    switch (rounding_mode) {
    case 0: increment = guard && (sticky || (rounded & 1u)); break; // RNE
    case 1: break; // RTZ
    case 2: increment = result_negative && inexact; break; // RDN
    case 3: increment = !result_negative && inexact; break; // RUP
    case 4: increment = guard; break; // RMM
    default: break;
    }
    if (increment) ++rounded;

    const auto hidden = UINT64_C(1) << fraction_bits;
    if (rounded >= (hidden << 1)) {
        rounded >>= 1;
        ++large_exponent;
    }
    if (large_exponent >= exponent_field_mask) {
        const bool to_infinity = rounding_mode == 0 || rounding_mode == 4 ||
            (rounding_mode == 2 && result_negative) || (rounding_mode == 3 && !result_negative);
        const auto magnitude = to_infinity ? exponent_mask
            : exponent_mask - (UINT64_C(1) << fraction_bits) | fraction_mask;
        return {(result_negative ? sign_mask : 0) | magnitude, 0x05}; // OF | NX
    }

    const bool subnormal = large_exponent == 1 && rounded < hidden;
    const auto encoded_exponent = subnormal ? 0u : large_exponent;
    const auto encoded_fraction = subnormal ? rounded : (rounded & fraction_mask);
    std::uint8_t flags = inexact ? 0x01 : 0;
    if (subnormal && inexact) flags |= 0x02; // tininess after rounding
    return {(result_negative ? sign_mask : 0) |
            (static_cast<std::uint64_t>(encoded_exponent) << fraction_bits) | encoded_fraction, flags};
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

std::optional<RiscvCsrResult> evaluate_riscv_csr_instruction_impl(
    const RiscvInstruction &instruction, unsigned xlen, std::uint64_t old_csr,
    std::uint64_t source_value) noexcept {
    if ((xlen != 32 && xlen != 64) || instruction.length != 4 ||
        instruction.flow != RiscvFlow::fallthrough || instruction.memory_read || instruction.memory_write ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != RiscvOperandAccess::write ||
        instruction.access[2] != RiscvOperandAccess::read)
        return std::nullopt;
    bool immediate = false;
    switch (instruction.opcode) {
    case RiscvOpcode::csrrw: case RiscvOpcode::csrrs: case RiscvOpcode::csrrc: break;
    case RiscvOpcode::csrrwi: case RiscvOpcode::csrrsi: case RiscvOpcode::csrrci: immediate = true; break;
    default: return std::nullopt;
    }
    const auto *rd = std::get_if<RiscvRegister>(&instruction.operands[0]);
    const auto *csr = std::get_if<RiscvImmediate>(&instruction.operands[1]);
    if (!rd || rd->index > 31 || rd->floating_point || rd->vector || !csr || csr->encoded_width != 12 ||
        csr->is_signed || csr->value < 0 || csr->value > 0xfff)
        return std::nullopt;
    bool source_zero = false;
    if (immediate) {
        const auto *zimm = std::get_if<RiscvImmediate>(&instruction.operands[2]);
        if (!zimm || zimm->encoded_width != 5 || zimm->is_signed || zimm->value < 0 || zimm->value > 31)
            return std::nullopt;
        source_value = static_cast<std::uint64_t>(zimm->value);
        source_zero = source_value == 0;
    } else {
        const auto *rs1 = std::get_if<RiscvRegister>(&instruction.operands[2]);
        if (!rs1 || rs1->index > 31 || rs1->floating_point || rs1->vector)
            return std::nullopt;
        source_zero = rs1->index == 0;
        if (!source_zero && std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *rs1) ==
                                instruction.register_reads.end())
            return std::nullopt;
        if (source_zero) source_value = 0;
    }
    const bool csrrw = instruction.opcode == RiscvOpcode::csrrw || instruction.opcode == RiscvOpcode::csrrwi;
    const bool expected_read = csrrw ? rd->index != 0 : true;
    const bool expected_write = csrrw || !source_zero;
    const auto expected_csr_access = expected_read ? expected_write ? RiscvOperandAccess::read_write
                                                                  : RiscvOperandAccess::read
                                                    : RiscvOperandAccess::write;
    if (instruction.access[1] != expected_csr_access || instruction.csr_read != expected_read ||
        instruction.csr_write != expected_write)
        return std::nullopt;
    if (rd->index != 0 && std::find(instruction.register_writes.begin(), instruction.register_writes.end(), *rd) ==
                              instruction.register_writes.end())
        return std::nullopt;
    const auto mask = width_mask(xlen);
    old_csr &= mask;
    source_value &= mask;
    RiscvCsrResult result{};
    result.writes_rd = rd->index != 0 && expected_read;
    result.rd_value = result.writes_rd ? old_csr : 0;
    result.writes_csr = expected_write;
    result.csr_value = old_csr;
    if (expected_write) {
        switch (instruction.opcode) {
        case RiscvOpcode::csrrw: case RiscvOpcode::csrrwi: result.csr_value = source_value; break;
        case RiscvOpcode::csrrs: case RiscvOpcode::csrrsi: result.csr_value = old_csr | source_value; break;
        case RiscvOpcode::csrrc: case RiscvOpcode::csrrci: result.csr_value = old_csr & ~source_value; break;
        default: return std::nullopt;
        }
        result.csr_value &= mask;
    }
    return result;
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

std::optional<RiscvCsrResult> evaluate_riscv_csr_instruction(
    const RiscvInstruction &instruction, unsigned xlen, std::uint64_t old_csr,
    std::uint64_t source_value) noexcept {
    return evaluate_riscv_csr_instruction_impl(instruction, xlen, old_csr, source_value);
}

std::optional<RiscvCsrPrivilegeCheck> check_riscv_csr_privilege(
    const RiscvInstruction &instruction, unsigned xlen,
    RiscvPrivilegeMode current_privilege) noexcept {
    if (static_cast<unsigned>(current_privilege) >
        static_cast<unsigned>(RiscvPrivilegeMode::machine))
        return {};
    // Reuse the semantic adapter's structural validation without changing
    // state; caller-provided values are irrelevant to access privilege.
    if (!evaluate_riscv_csr_instruction(instruction, xlen, 0, 0))
        return {};
    const auto *csr = std::get_if<RiscvImmediate>(&instruction.operands[1]);
    if (!csr || (instruction.csr_write && ((static_cast<unsigned>(csr->value) >> 10) & 3u) == 3u))
        return {};
    const auto required = static_cast<RiscvPrivilegeMode>(
        (static_cast<unsigned>(csr->value) >> 8) & 3u);
    return RiscvCsrPrivilegeCheck{required,
        static_cast<unsigned>(current_privilege) >= static_cast<unsigned>(required)};
}

std::optional<RiscvFcsrResult> evaluate_riscv_fcsr_instruction(
    const RiscvInstruction &instruction, unsigned xlen, RiscvFcsrState state,
    std::uint64_t source_value) noexcept {
    if (state.fflags > 0x1fu || state.frm > 7u ||
        (xlen != 32 && xlen != 64) || instruction.operands.size() != 3)
        return {};
    const auto *csr = std::get_if<RiscvImmediate>(&instruction.operands[1]);
    if (!csr || csr->value < 1 || csr->value > 3 || csr->is_signed || csr->encoded_width != 12)
        return {};

    std::uint64_t old_value = 0;
    switch (csr->value) {
    case 1: old_value = state.fflags; break;
    case 2: old_value = state.frm; break;
    case 3: old_value = static_cast<std::uint64_t>(state.fflags) |
                         (static_cast<std::uint64_t>(state.frm) << 5); break;
    default: return {};
    }
    const auto operation = evaluate_riscv_csr_instruction(instruction, xlen, old_value, source_value);
    if (!operation) return {};

    RiscvFcsrResult result{};
    result.rd_value = operation->rd_value;
    result.state = state;
    result.writes_rd = operation->writes_rd;
    result.writes_state = operation->writes_csr;
    if (!result.writes_state) return result;
    switch (csr->value) {
    case 1:
        result.state.fflags = static_cast<std::uint8_t>(operation->csr_value & 0x1fu);
        break;
    case 2:
        result.state.frm = static_cast<std::uint8_t>(operation->csr_value & 7u);
        break;
    case 3:
        result.state.fflags = static_cast<std::uint8_t>(operation->csr_value & 0x1fu);
        result.state.frm = static_cast<std::uint8_t>((operation->csr_value >> 5) & 7u);
        break;
    default: return {};
    }
    return result;
}

std::optional<RiscvFcsrState> accrue_riscv_fflags(
    RiscvFcsrState state, std::uint8_t raised_flags) noexcept {
    if (state.fflags > 0x1fu || state.frm > 7u || (raised_flags & ~0x1fu) != 0)
        return {};
    state.fflags = static_cast<std::uint8_t>(state.fflags | raised_flags);
    return state;
}

std::optional<std::uint8_t> resolve_riscv_rounding_mode(
    const RiscvInstruction &instruction, std::uint8_t frm) noexcept {
    if (frm > 7u || !instruction.rounding_mode || *instruction.rounding_mode > 7u)
        return {};
    const auto encoded = *instruction.rounding_mode;
    if (encoded <= 4u)
        return instruction.reads_frm ? std::optional<std::uint8_t>{} : encoded;
    if (encoded != 7u || !instruction.reads_frm || frm > 4u)
        return {};
    return frm;
}

std::optional<std::uint32_t> read_riscv_f32_register_value(
    unsigned flen, std::uint64_t register_bits) noexcept {
    if (flen == 32) {
        if (register_bits >> 32) return {};
        return static_cast<std::uint32_t>(register_bits);
    }
    if (flen != 64) return {};
    if ((register_bits >> 32) != UINT32_MAX)
        return UINT32_C(0x7fc00000); // canonical quiet NaN for an unboxed value
    return static_cast<std::uint32_t>(register_bits);
}

std::optional<std::uint64_t> write_riscv_f32_register_value(
    unsigned flen, std::uint64_t binary32_bits) noexcept {
    if (binary32_bits >> 32) return {};
    if (flen == 32) return binary32_bits;
    if (flen == 64)
        return UINT64_C(0xffffffff00000000) | binary32_bits;
    return {};
}

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

std::optional<RiscvAmoResult> evaluate_riscv_amo_instruction(
    const RiscvInstruction &instruction, unsigned xlen, std::uint64_t old_memory,
    std::uint64_t source_value) noexcept {
    enum class Operation { swap, add, bit_xor, bit_and, bit_or, min_signed, max_signed, min_unsigned, max_unsigned };
    Operation operation{};
    bool word = false;
    switch (instruction.opcode) {
    case RiscvOpcode::amoswap_w: operation = Operation::swap; word = true; break;
    case RiscvOpcode::amoadd_w: operation = Operation::add; word = true; break;
    case RiscvOpcode::amoxor_w: operation = Operation::bit_xor; word = true; break;
    case RiscvOpcode::amoand_w: operation = Operation::bit_and; word = true; break;
    case RiscvOpcode::amoor_w: operation = Operation::bit_or; word = true; break;
    case RiscvOpcode::amomin_w: operation = Operation::min_signed; word = true; break;
    case RiscvOpcode::amomax_w: operation = Operation::max_signed; word = true; break;
    case RiscvOpcode::amominu_w: operation = Operation::min_unsigned; word = true; break;
    case RiscvOpcode::amomaxu_w: operation = Operation::max_unsigned; word = true; break;
    case RiscvOpcode::amoswap_d: operation = Operation::swap; break;
    case RiscvOpcode::amoadd_d: operation = Operation::add; break;
    case RiscvOpcode::amoxor_d: operation = Operation::bit_xor; break;
    case RiscvOpcode::amoand_d: operation = Operation::bit_and; break;
    case RiscvOpcode::amoor_d: operation = Operation::bit_or; break;
    case RiscvOpcode::amomin_d: operation = Operation::min_signed; break;
    case RiscvOpcode::amomax_d: operation = Operation::max_signed; break;
    case RiscvOpcode::amominu_d: operation = Operation::min_unsigned; break;
    case RiscvOpcode::amomaxu_d: operation = Operation::max_unsigned; break;
    default: return {};
    }
    if ((xlen != 32 && xlen != 64) || (!word && xlen != 64) || instruction.length != 4 ||
        (std::to_integer<std::uint8_t>(instruction.bytes[0]) & 0x7fu) != 0x2fu ||
        instruction.flow != RiscvFlow::fallthrough || !instruction.memory_read || !instruction.memory_write ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != RiscvOperandAccess::write ||
        instruction.access[1] != RiscvOperandAccess::read ||
        instruction.access[2] != RiscvOperandAccess::read_write)
        return {};
    const auto *rd = std::get_if<RiscvRegister>(&instruction.operands[0]);
    const auto *rs2 = std::get_if<RiscvRegister>(&instruction.operands[1]);
    const auto *memory = std::get_if<RiscvMemory>(&instruction.operands[2]);
    if (!rd || !rs2 || !memory || rd->index > 31 || rs2->index > 31 ||
        rd->floating_point || rd->vector || rd->vector_configuration ||
        rs2->floating_point || rs2->vector || rs2->vector_configuration ||
        memory->base.index > 31 || memory->base.floating_point || memory->base.vector ||
        memory->base.vector_configuration || memory->displacement != 0 ||
        memory->width != (word ? 32 : 64) || memory->sign_extend != word)
        return {};
    const auto has_register = [](const std::vector<RiscvRegister> &registers, RiscvRegister value) {
        return std::find(registers.begin(), registers.end(), value) != registers.end();
    };
    if ((rd->index != 0 && !has_register(instruction.register_writes, *rd)) ||
        (rs2->index != 0 && !has_register(instruction.register_reads, *rs2)) ||
        (memory->base.index != 0 && !has_register(instruction.register_reads, memory->base)))
        return {};

    const unsigned width = word ? 32u : 64u;
    const auto mask = width_mask(width);
    const auto old_value = old_memory & mask;
    const auto source = source_value & mask;
    std::uint64_t next = 0;
    switch (operation) {
    case Operation::swap: next = source; break;
    case Operation::add: next = (old_value + source) & mask; break;
    case Operation::bit_xor: next = old_value ^ source; break;
    case Operation::bit_and: next = old_value & source; break;
    case Operation::bit_or: next = old_value | source; break;
    case Operation::min_unsigned: next = std::min(old_value, source); break;
    case Operation::max_unsigned: next = std::max(old_value, source); break;
    case Operation::min_signed:
    case Operation::max_signed: {
        const auto sign = UINT64_C(1) << (width - 1);
        const bool old_less = (old_value ^ sign) < (source ^ sign);
        next = (operation == Operation::min_signed ? old_less : !old_less) ? old_value : source;
        break;
    }
    }
    const auto rd_value = word && xlen == 64 ? sign_extend_32(static_cast<std::uint32_t>(old_value)) : old_value;
    return RiscvAmoResult{rd_value, next & mask, static_cast<std::uint8_t>(width), rd->index != 0};
}

std::optional<bool> evaluate_riscv_branch_predicate(RiscvOpcode opcode, unsigned xlen,
                                                     std::uint64_t lhs, std::uint64_t rhs) noexcept {
    if (xlen != 32 && xlen != 64) return {};
    const auto mask = width_mask(xlen);
    lhs &= mask;
    rhs &= mask;
    switch (opcode) {
    case RiscvOpcode::beq: return lhs == rhs;
    case RiscvOpcode::bne: return lhs != rhs;
    case RiscvOpcode::bltu: return lhs < rhs;
    case RiscvOpcode::bgeu: return lhs >= rhs;
    case RiscvOpcode::blt:
    case RiscvOpcode::bge: {
        const auto sign = UINT64_C(1) << (xlen - 1);
        const bool less = (lhs ^ sign) < (rhs ^ sign);
        return opcode == RiscvOpcode::blt ? less : !less;
    }
    default: return {};
    }
}

std::optional<bool> evaluate_riscv_branch_predicate_instruction(const RiscvInstruction &instruction,
                                                                unsigned xlen, std::uint64_t lhs,
                                                                std::uint64_t rhs) noexcept {
    if ((instruction.length != 2 && instruction.length != 4) ||
        instruction.flow != RiscvFlow::conditional_branch || instruction.memory_read || instruction.memory_write ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != RiscvOperandAccess::read || instruction.access[1] != RiscvOperandAccess::read ||
        instruction.access[2] != RiscvOperandAccess::read)
        return {};
    const auto *left = std::get_if<RiscvRegister>(&instruction.operands[0]);
    const auto *right = std::get_if<RiscvRegister>(&instruction.operands[1]);
    if (!left || !right || !std::holds_alternative<RiscvRelative>(instruction.operands[2]) ||
        left->floating_point || left->vector || left->vector_configuration ||
        right->floating_point || right->vector || right->vector_configuration)
        return {};
    const auto is_gpr_read = [&](const RiscvRegister &reg) {
        return reg.index == 0 || std::find(instruction.register_reads.begin(), instruction.register_reads.end(), reg) !=
                                     instruction.register_reads.end();
    };
    if (!is_gpr_read(*left) || !is_gpr_read(*right)) return {};
    if (left->index == 0) lhs = 0;
    if (right->index == 0) rhs = 0;
    return evaluate_riscv_branch_predicate(instruction.opcode, xlen, lhs, rhs);
}

std::optional<RiscvIndirectJumpResult>
evaluate_riscv_jalr_instruction(const RiscvInstruction &instruction, unsigned xlen,
                                std::uint64_t base_value) noexcept {
    if ((xlen != 32 && xlen != 64) || instruction.opcode != RiscvOpcode::jalr ||
        (instruction.length != 2 && instruction.length != 4) ||
        (instruction.flow != RiscvFlow::call && instruction.flow != RiscvFlow::jump &&
         instruction.flow != RiscvFlow::ret) || instruction.operands.size() != 2 ||
        instruction.access.size() != 2 || instruction.access[0] != RiscvOperandAccess::write ||
        instruction.access[1] != RiscvOperandAccess::address || instruction.memory_read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RiscvRegister>(&instruction.operands[0]);
    const auto *address = std::get_if<RiscvMemory>(&instruction.operands[1]);
    if (!destination || !address || destination->floating_point || destination->vector ||
        destination->vector_configuration || destination->index >= 32 || address->base.floating_point ||
        address->base.vector || address->base.vector_configuration || address->base.index >= 32 ||
        address->width != xlen || (instruction.length == 2 && address->displacement != 0) ||
        (instruction.length == 4 && (address->displacement < -2048 || address->displacement > 2047)))
        return {};
    const auto has = [](const auto &registers, RiscvRegister reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if ((address->base.index != 0 && !has(instruction.register_reads, address->base)) ||
        (destination->index != 0 && !has(instruction.register_writes, *destination)))
        return {};
    const auto mask = width_mask(xlen);
    if (address->base.index == 0) base_value = 0;
    const auto target = ((base_value + static_cast<std::uint64_t>(address->displacement)) & mask) & ~UINT64_C(1);
    const auto link = (instruction.address.offset + instruction.length) & mask;
    return RiscvIndirectJumpResult{target, link, destination->index != 0};
}

std::optional<RiscvUpperImmediateResult>
evaluate_riscv_upper_immediate_instruction(const RiscvInstruction &instruction,
                                           unsigned xlen) noexcept {
    if (xlen != 32 && xlen != 64) return {};
    const bool upper = instruction.opcode == RiscvOpcode::lui;
    const bool pc_relative = instruction.opcode == RiscvOpcode::auipc;
    if ((!upper && !pc_relative) || instruction.flow != RiscvFlow::fallthrough ||
        (instruction.length != 2 && instruction.length != 4) || (pc_relative && instruction.length != 4) ||
        instruction.memory_read || instruction.memory_write || instruction.operands.size() != 2 ||
        instruction.access.size() != 2 || instruction.access[0] != RiscvOperandAccess::write ||
        instruction.access[1] != RiscvOperandAccess::read)
        return {};
    const auto *destination = std::get_if<RiscvRegister>(&instruction.operands[0]);
    const auto *immediate = std::get_if<RiscvImmediate>(&instruction.operands[1]);
    const auto expected_immediate_width = static_cast<std::uint8_t>(instruction.length == 2 ? 6 : 20);
    if (!destination || !immediate || destination->floating_point || destination->vector ||
        destination->vector_configuration || destination->index >= 32 ||
        immediate->encoded_width != expected_immediate_width || !immediate->is_signed ||
        (static_cast<std::uint64_t>(immediate->value) & 0xfffu) != 0)
        return {};
    const auto has = [](const auto &registers, RiscvRegister reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (destination->index != 0 && !has(instruction.register_writes, *destination)) return {};
    const auto mask = width_mask(xlen);
    const auto immediate_bits = static_cast<std::uint64_t>(immediate->value) & mask;
    const auto value = (pc_relative ? instruction.address.offset + immediate_bits : immediate_bits) & mask;
    return RiscvUpperImmediateResult{value, static_cast<std::uint8_t>(xlen), destination->index != 0};
}

std::optional<std::uint16_t> evaluate_riscv_fclass(RiscvOpcode opcode, std::uint64_t value) noexcept {
    const bool binary32 = opcode == RiscvOpcode::fclass_s;
    if (!binary32 && opcode != RiscvOpcode::fclass_d) return {};
    const unsigned fraction_bits = binary32 ? 23u : 52u;
    const unsigned exponent_bits = binary32 ? 8u : 11u;
    if (binary32 && (value >> 32)) return {};
    const std::uint64_t fraction_mask = (UINT64_C(1) << fraction_bits) - 1;
    const std::uint64_t exponent_mask = (UINT64_C(1) << exponent_bits) - 1;
    const bool sign = ((value >> (fraction_bits + exponent_bits)) & 1u) != 0;
    const auto exponent = (value >> fraction_bits) & exponent_mask;
    const auto fraction = value & fraction_mask;
    const auto category = [&](unsigned bit) { return std::optional<std::uint16_t>{static_cast<std::uint16_t>(1u << bit)}; };
    if (exponent == exponent_mask) {
        if (!fraction) return category(sign ? 0u : 7u);
        const bool quiet = (fraction & (UINT64_C(1) << (fraction_bits - 1))) != 0;
        return category(quiet ? 9u : 8u);
    }
    if (!exponent) {
        if (!fraction) return category(sign ? 3u : 4u);
        return category(sign ? 2u : 5u);
    }
    return category(sign ? 1u : 6u);
}

std::optional<std::uint16_t>
evaluate_riscv_fclass_instruction(const RiscvInstruction &instruction, std::uint64_t value) noexcept {
    if ((instruction.opcode != RiscvOpcode::fclass_s && instruction.opcode != RiscvOpcode::fclass_d) ||
        instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != RiscvOperandAccess::write || instruction.access[1] != RiscvOperandAccess::read ||
        instruction.writes_fflags || instruction.reads_fflags || instruction.reads_frm)
        return {};
    const auto *destination = std::get_if<RiscvRegister>(&instruction.operands[0]);
    const auto *source = std::get_if<RiscvRegister>(&instruction.operands[1]);
    if (!destination || destination->floating_point || destination->vector || destination->vector_configuration ||
        !source || !source->floating_point || source->vector || source->vector_configuration ||
        std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *source) ==
            instruction.register_reads.end())
        return {};
    const bool writes_destination = std::find(instruction.register_writes.begin(),
        instruction.register_writes.end(), *destination) != instruction.register_writes.end();
    if (writes_destination != (destination->index != 0)) return {};
    return evaluate_riscv_fclass(instruction.opcode, value);
}

std::optional<std::uint64_t> evaluate_riscv_fsgnj_operation(RiscvOpcode opcode, std::uint64_t lhs,
                                                             std::uint64_t rhs) noexcept {
    const bool binary32 = opcode == RiscvOpcode::fsgnj_s || opcode == RiscvOpcode::fsgnjn_s ||
                          opcode == RiscvOpcode::fsgnjx_s;
    const bool binary64 = opcode == RiscvOpcode::fsgnj_d || opcode == RiscvOpcode::fsgnjn_d ||
                          opcode == RiscvOpcode::fsgnjx_d;
    if (!binary32 && !binary64) return {};
    if (binary32 && ((lhs | rhs) >> 32)) return {};
    const unsigned sign_bit = binary32 ? 31u : 63u;
    const std::uint64_t sign_mask = UINT64_C(1) << sign_bit;
    std::uint64_t sign = rhs & sign_mask;
    if (opcode == RiscvOpcode::fsgnjn_s || opcode == RiscvOpcode::fsgnjn_d)
        sign ^= sign_mask;
    else if (opcode == RiscvOpcode::fsgnjx_s || opcode == RiscvOpcode::fsgnjx_d)
        sign = (lhs ^ rhs) & sign_mask;
    return (lhs & ~sign_mask) | sign;
}

std::optional<std::uint64_t> evaluate_riscv_fsgnj_instruction(const RiscvInstruction &instruction,
                                                              std::uint64_t lhs,
                                                              std::uint64_t rhs) noexcept {
    if ((instruction.opcode != RiscvOpcode::fsgnj_s && instruction.opcode != RiscvOpcode::fsgnjn_s &&
         instruction.opcode != RiscvOpcode::fsgnjx_s && instruction.opcode != RiscvOpcode::fsgnj_d &&
         instruction.opcode != RiscvOpcode::fsgnjn_d && instruction.opcode != RiscvOpcode::fsgnjx_d) ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != RiscvOperandAccess::write ||
        instruction.access[1] != RiscvOperandAccess::read ||
        instruction.access[2] != RiscvOperandAccess::read || instruction.memory_read ||
        instruction.memory_write || instruction.writes_fflags || instruction.reads_fflags ||
        instruction.reads_frm)
        return {};
    const auto *destination = std::get_if<RiscvRegister>(&instruction.operands[0]);
    const auto *left = std::get_if<RiscvRegister>(&instruction.operands[1]);
    const auto *right = std::get_if<RiscvRegister>(&instruction.operands[2]);
    const auto is_fpr = [](const RiscvRegister *reg) {
        return reg && reg->floating_point && !reg->vector && !reg->vector_configuration;
    };
    if (!is_fpr(destination) || !is_fpr(left) || !is_fpr(right) ||
        std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *left) ==
            instruction.register_reads.end() ||
        std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *right) ==
            instruction.register_reads.end() ||
        std::find(instruction.register_writes.begin(), instruction.register_writes.end(), *destination) ==
            instruction.register_writes.end())
        return {};
    return evaluate_riscv_fsgnj_operation(instruction.opcode, lhs, rhs);
}

std::optional<RiscvFloatMinMaxResult> evaluate_riscv_float_min_max(
    RiscvOpcode opcode, std::uint64_t lhs, std::uint64_t rhs) noexcept {
    const bool single = opcode == RiscvOpcode::fmin_s || opcode == RiscvOpcode::fmax_s;
    const bool maximum = opcode == RiscvOpcode::fmax_s || opcode == RiscvOpcode::fmax_d;
    if (!single && opcode != RiscvOpcode::fmin_d && opcode != RiscvOpcode::fmax_d) return {};
    if (single && ((lhs | rhs) >> 32)) return {};
    const unsigned fraction_bits = single ? 23u : 52u;
    const unsigned exponent_bits = single ? 8u : 11u;
    const auto mask = single ? UINT64_C(0xffffffff) : UINT64_MAX;
    const auto sign = UINT64_C(1) << (fraction_bits + exponent_bits);
    const auto fraction_mask = (UINT64_C(1) << fraction_bits) - 1;
    const auto exponent_mask = (UINT64_C(1) << exponent_bits) - 1;
    const auto is_nan = [&](std::uint64_t bits) {
        return ((bits >> fraction_bits) & exponent_mask) == exponent_mask && (bits & fraction_mask) != 0;
    };
    const auto is_signaling_nan = [&](std::uint64_t bits) {
        return is_nan(bits) && (bits & (UINT64_C(1) << (fraction_bits - 1))) == 0;
    };
    lhs &= mask;
    rhs &= mask;
    const bool lhs_nan = is_nan(lhs), rhs_nan = is_nan(rhs);
    const std::uint8_t invalid = is_signaling_nan(lhs) || is_signaling_nan(rhs) ? 0x10u : 0u;
    if (lhs_nan && rhs_nan)
        return RiscvFloatMinMaxResult{single ? UINT64_C(0x7fc00000) : UINT64_C(0x7ff8000000000000), invalid};
    if (lhs_nan) return RiscvFloatMinMaxResult{rhs, invalid};
    if (rhs_nan) return RiscvFloatMinMaxResult{lhs, invalid};
    if ((lhs & ~sign) == 0 && (rhs & ~sign) == 0)
        return RiscvFloatMinMaxResult{maximum ? (lhs & rhs & sign) : ((lhs | rhs) & sign), 0};
    const auto order_key = [sign, mask](std::uint64_t bits) {
        return (bits & sign) ? (~bits & mask) : (bits ^ sign);
    };
    const bool lhs_precedes = order_key(lhs) < order_key(rhs);
    return RiscvFloatMinMaxResult{maximum ? (lhs_precedes ? rhs : lhs) : (lhs_precedes ? lhs : rhs), 0};
}

std::optional<RiscvFloatMinMaxResult> evaluate_riscv_float_min_max_instruction(
    const RiscvInstruction &instruction, std::uint64_t lhs,
    std::uint64_t rhs) noexcept {
    if ((instruction.opcode != RiscvOpcode::fmin_s && instruction.opcode != RiscvOpcode::fmax_s &&
         instruction.opcode != RiscvOpcode::fmin_d && instruction.opcode != RiscvOpcode::fmax_d) ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != RiscvOperandAccess::write ||
        instruction.access[1] != RiscvOperandAccess::read ||
        instruction.access[2] != RiscvOperandAccess::read || instruction.memory_read ||
        instruction.memory_write || !instruction.writes_fflags || !instruction.reads_fflags ||
        instruction.reads_frm)
        return {};
    const auto *destination = std::get_if<RiscvRegister>(&instruction.operands[0]);
    const auto *left = std::get_if<RiscvRegister>(&instruction.operands[1]);
    const auto *right = std::get_if<RiscvRegister>(&instruction.operands[2]);
    const auto valid_fpr = [](const RiscvRegister *reg) {
        return reg && reg->floating_point && !reg->vector && !reg->vector_configuration;
    };
    if (!valid_fpr(destination) || !valid_fpr(left) || !valid_fpr(right) ||
        std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *left) ==
            instruction.register_reads.end() ||
        std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *right) ==
            instruction.register_reads.end() ||
        std::find(instruction.register_writes.begin(), instruction.register_writes.end(), *destination) ==
            instruction.register_writes.end())
        return {};
    return evaluate_riscv_float_min_max(instruction.opcode, lhs, rhs);
}

std::optional<RiscvFloatCompareResult> evaluate_riscv_float_compare(
    RiscvOpcode opcode, std::uint64_t lhs, std::uint64_t rhs) noexcept {
    const bool single = opcode == RiscvOpcode::feq_s || opcode == RiscvOpcode::flt_s ||
                        opcode == RiscvOpcode::fle_s;
    const bool equal = opcode == RiscvOpcode::feq_s || opcode == RiscvOpcode::feq_d;
    const bool less = opcode == RiscvOpcode::flt_s || opcode == RiscvOpcode::flt_d;
    const bool less_equal = opcode == RiscvOpcode::fle_s || opcode == RiscvOpcode::fle_d;
    if (!single && !equal && !less && !less_equal) return {};
    if (single && ((lhs | rhs) >> 32) != 0) return {};

    const unsigned fraction_bits = single ? 23u : 52u;
    const unsigned exponent_bits = single ? 8u : 11u;
    const std::uint64_t mask = single ? UINT64_C(0xffffffff) : UINT64_MAX;
    const std::uint64_t sign = UINT64_C(1) << (fraction_bits + exponent_bits);
    const std::uint64_t fraction_mask = (UINT64_C(1) << fraction_bits) - 1;
    const std::uint64_t exponent_mask = (UINT64_C(1) << exponent_bits) - 1;
    lhs &= mask;
    rhs &= mask;
    const auto is_nan = [&](std::uint64_t bits) {
        return ((bits >> fraction_bits) & exponent_mask) == exponent_mask &&
               (bits & fraction_mask) != 0;
    };
    const auto is_signaling_nan = [&](std::uint64_t bits) {
        return is_nan(bits) && (bits & (UINT64_C(1) << (fraction_bits - 1))) == 0;
    };
    const bool lhs_nan = is_nan(lhs), rhs_nan = is_nan(rhs);
    if (lhs_nan || rhs_nan) {
        const bool invalid = equal ? (is_signaling_nan(lhs) || is_signaling_nan(rhs)) : true;
        return RiscvFloatCompareResult{0, static_cast<std::uint8_t>(invalid ? 0x10u : 0u)};
    }
    const bool both_zero = (lhs & ~sign) == 0 && (rhs & ~sign) == 0;
    const auto order_key = [sign, mask](std::uint64_t bits) {
        return (bits & sign) ? (~bits & mask) : (bits ^ sign);
    };
    const bool are_equal = both_zero || lhs == rhs;
    const bool precedes = !both_zero && order_key(lhs) < order_key(rhs);
    const bool result = equal ? are_equal : less ? precedes : (are_equal || precedes);
    return RiscvFloatCompareResult{result ? 1u : 0u, 0};
}

std::optional<RiscvFloatCompareResult> evaluate_riscv_float_compare_instruction(
    const RiscvInstruction &instruction, std::uint64_t lhs,
    std::uint64_t rhs) noexcept {
    const bool comparison = instruction.opcode == RiscvOpcode::feq_s ||
                            instruction.opcode == RiscvOpcode::flt_s ||
                            instruction.opcode == RiscvOpcode::fle_s ||
                            instruction.opcode == RiscvOpcode::feq_d ||
                            instruction.opcode == RiscvOpcode::flt_d ||
                            instruction.opcode == RiscvOpcode::fle_d;
    if (!comparison || instruction.length != 4 || instruction.flow != RiscvFlow::fallthrough ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != RiscvOperandAccess::write ||
        instruction.access[1] != RiscvOperandAccess::read ||
        instruction.access[2] != RiscvOperandAccess::read || instruction.memory_read ||
        instruction.memory_write || !instruction.writes_fflags || !instruction.reads_fflags ||
        instruction.reads_frm || instruction.rounding_mode)
        return {};
    const auto *destination = std::get_if<RiscvRegister>(&instruction.operands[0]);
    const auto *left = std::get_if<RiscvRegister>(&instruction.operands[1]);
    const auto *right = std::get_if<RiscvRegister>(&instruction.operands[2]);
    const auto valid_register = [](const RiscvRegister *reg) {
        return reg && reg->index < 32 && !reg->vector && !reg->vector_configuration;
    };
    if (!valid_register(destination) || !valid_register(left) || !valid_register(right) ||
        destination->floating_point || !left->floating_point || !right->floating_point ||
        std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *left) ==
            instruction.register_reads.end() ||
        std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *right) ==
            instruction.register_reads.end() ||
        std::find(instruction.register_writes.begin(), instruction.register_writes.end(), *destination) ==
            instruction.register_writes.end())
        return {};
    return evaluate_riscv_float_compare(instruction.opcode, lhs, rhs);
}

std::optional<RiscvBitMoveResult>
evaluate_riscv_fmv_instruction(const RiscvInstruction &instruction,
                              unsigned xlen_bits, std::uint64_t source_bits) noexcept {
    if ((xlen_bits != 32 && xlen_bits != 64) || instruction.operands.size() != 2 ||
        instruction.access.size() != 2 || instruction.access[0] != RiscvOperandAccess::write ||
        instruction.access[1] != RiscvOperandAccess::read || instruction.memory_read ||
        instruction.memory_write || instruction.writes_fflags || instruction.reads_fflags ||
        instruction.reads_frm)
        return {};
    const auto *destination = std::get_if<RiscvRegister>(&instruction.operands[0]);
    const auto *source = std::get_if<RiscvRegister>(&instruction.operands[1]);
    if (!destination || !source || destination->index >= 32 || source->index >= 32 ||
        destination->vector || destination->vector_configuration || source->vector || source->vector_configuration)
        return {};
    const bool x_from_w = instruction.opcode == RiscvOpcode::fmv_x_w;
    const bool w_from_x = instruction.opcode == RiscvOpcode::fmv_w_x;
    const bool x_from_d = instruction.opcode == RiscvOpcode::fmv_x_d;
    const bool d_from_x = instruction.opcode == RiscvOpcode::fmv_d_x;
    if (!x_from_w && !w_from_x && !x_from_d && !d_from_x) return {};
    const bool destination_fp = w_from_x || d_from_x;
    const bool source_fp = x_from_w || x_from_d;
    if (destination->floating_point != destination_fp || source->floating_point != source_fp ||
        ((x_from_d || d_from_x) && xlen_bits != 64))
        return {};
    const auto contains = [](const auto &registers, RiscvRegister reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if ((source_fp || source->index != 0) && !contains(instruction.register_reads, *source))
        return {};
    if ((destination_fp || destination->index != 0) &&
        !contains(instruction.register_writes, *destination))
        return {};
    if (source->floating_point == false && source->index == 0) source_bits = 0;
    if (x_from_w) {
        const auto word = static_cast<std::uint32_t>(source_bits);
        if (xlen_bits == 32) return RiscvBitMoveResult{word, 32};
        const auto signed_word = std::bit_cast<std::int32_t>(word);
        return RiscvBitMoveResult{static_cast<std::uint64_t>(static_cast<std::int64_t>(signed_word)), 64};
    }
    if (w_from_x)
        return RiscvBitMoveResult{UINT64_C(0xffffffff00000000) | static_cast<std::uint32_t>(source_bits), 64};
    return RiscvBitMoveResult{source_bits, 64};
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

std::optional<std::uint64_t> evaluate_riscv_zbb_operation(RiscvOpcode opcode, unsigned xlen,
                                                           std::uint64_t lhs,
                                                           std::uint64_t rhs) noexcept {
    if (xlen != 32 && xlen != 64) return {};
    const bool word = opcode == RiscvOpcode::rolw || opcode == RiscvOpcode::rorw ||
                      opcode == RiscvOpcode::roriw;
    if (word && xlen != 64) return {};
    const unsigned width = word ? 32 : xlen;
    const auto mask = width_mask(width);
    lhs &= mask;
    rhs &= mask;
    const auto sign_extend = [width](std::uint64_t value, unsigned source_width) {
        const auto source_mask = width_mask(source_width);
        value &= source_mask;
        return negative(value, source_width) ? (value | ~source_mask) & width_mask(width) : value;
    };
    const auto signed_less = [width](std::uint64_t left, std::uint64_t right) {
        const bool left_negative = negative(left, width), right_negative = negative(right, width);
        return left_negative != right_negative ? left_negative : left < right;
    };
    std::uint64_t result = 0;
    switch (opcode) {
    case RiscvOpcode::andn: result = lhs & ~rhs; break;
    case RiscvOpcode::orn: result = lhs | ~rhs; break;
    case RiscvOpcode::xnor: result = ~(lhs ^ rhs); break;
    case RiscvOpcode::min: result = signed_less(lhs, rhs) ? lhs : rhs; break;
    case RiscvOpcode::max: result = signed_less(lhs, rhs) ? rhs : lhs; break;
    case RiscvOpcode::minu: result = std::min(lhs, rhs); break;
    case RiscvOpcode::maxu: result = std::max(lhs, rhs); break;
    case RiscvOpcode::rol: case RiscvOpcode::rolw:
    case RiscvOpcode::ror: case RiscvOpcode::rorw: case RiscvOpcode::rori: case RiscvOpcode::roriw: {
        const unsigned shift = static_cast<unsigned>(rhs & (width - 1));
        if (!shift) result = lhs;
        else if (opcode == RiscvOpcode::rol || opcode == RiscvOpcode::rolw)
            result = ((lhs << shift) | (lhs >> (width - shift))) & mask;
        else
            result = ((lhs >> shift) | (lhs << (width - shift))) & mask;
        break;
    }
    case RiscvOpcode::sext_b: result = sign_extend(lhs, 8); break;
    case RiscvOpcode::sext_h: result = sign_extend(lhs, 16); break;
    case RiscvOpcode::zext_h: result = lhs & 0xffff; break;
    case RiscvOpcode::orc_b:
        for (unsigned shift = 0; shift < width; shift += 8)
            if (((lhs >> shift) & 0xff) != 0) result |= UINT64_C(0xff) << shift;
        break;
    case RiscvOpcode::rev8:
        for (unsigned byte = 0; byte < width / 8; ++byte)
            result |= ((lhs >> (byte * 8)) & 0xff) << (width - 8 - byte * 8);
        break;
    default: return {};
    }
    result &= mask;
    return word ? sign_extend_32(static_cast<std::uint32_t>(result)) : result;
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

std::optional<std::uint64_t> evaluate_riscv_zbs_operation(RiscvOpcode opcode, unsigned xlen,
                                                           std::uint64_t lhs,
                                                           std::uint64_t bit_index) noexcept {
    if (xlen != 32 && xlen != 64) return {};
    const auto mask = width_mask(xlen);
    lhs &= mask;
    const unsigned index = static_cast<unsigned>(bit_index & (xlen - 1));
    const auto bit = UINT64_C(1) << index;
    switch (opcode) {
    case RiscvOpcode::bclr: case RiscvOpcode::bclri: return lhs & ~bit & mask;
    case RiscvOpcode::bext: case RiscvOpcode::bexti: return (lhs >> index) & 1;
    case RiscvOpcode::binv: case RiscvOpcode::binvi: return (lhs ^ bit) & mask;
    case RiscvOpcode::bset: case RiscvOpcode::bseti: return (lhs | bit) & mask;
    default: return {};
    }
}

std::optional<std::uint64_t>
evaluate_riscv_zbkb_pack_operation(RiscvOpcode opcode, unsigned xlen, std::uint64_t lhs,
                                  std::uint64_t rhs) noexcept {
    if (xlen != 32 && xlen != 64) return {};
    if (opcode == RiscvOpcode::pack) {
        const unsigned half = xlen / 2;
        const auto half_mask = (UINT64_C(1) << half) - 1;
        return ((rhs & half_mask) << half) | (lhs & half_mask);
    }
    if (opcode == RiscvOpcode::packh)
        return ((rhs & 0xff) << 8) | (lhs & 0xff);
    if (opcode == RiscvOpcode::packw && xlen == 64) {
        const auto packed = static_cast<std::uint32_t>(((rhs & 0xffff) << 16) | (lhs & 0xffff));
        return static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(packed)));
    }
    return {};
}

std::optional<std::uint64_t>
evaluate_riscv_zbc_operation(RiscvOpcode opcode, unsigned xlen, std::uint64_t lhs,
                             std::uint64_t rhs) noexcept {
    if (xlen != 32 && xlen != 64) return {};
    const auto mask = width_mask(xlen);
    lhs &= mask;
    rhs &= mask;
    std::uint64_t result = 0;
    if (opcode == RiscvOpcode::clmul) {
        for (unsigned bit = 0; bit < xlen; ++bit)
            if ((rhs >> bit) & 1u) result ^= lhs << bit;
        return result & mask;
    }
    if (opcode == RiscvOpcode::clmulh) {
        // Product bits [2*XLEN-1:XLEN], accumulated without a wider integer.
        for (unsigned bit = 1; bit < xlen; ++bit)
            if ((rhs >> bit) & 1u) result ^= lhs >> (xlen - bit);
        return result & mask;
    }
    if (opcode == RiscvOpcode::clmulr) {
        // Product bits [2*XLEN-2:XLEN-1], the reversed-result window.
        for (unsigned bit = 0; bit < xlen; ++bit)
            if ((rhs >> bit) & 1u) result ^= lhs >> (xlen - bit - 1);
        return result & mask;
    }
    return {};
}

std::optional<std::uint64_t>
evaluate_riscv_zicond_operation(RiscvOpcode opcode, unsigned xlen, std::uint64_t value,
                                std::uint64_t condition) noexcept {
    if (xlen != 32 && xlen != 64) return {};
    const auto mask = width_mask(xlen);
    value &= mask;
    condition &= mask;
    switch (opcode) {
    case RiscvOpcode::czero_eqz: return condition == 0 ? 0 : value;
    case RiscvOpcode::czero_nez: return condition != 0 ? 0 : value;
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

std::optional<RiscvFloatingRoundResult>
evaluate_riscv_fround_operation(RiscvOpcode opcode, std::uint64_t source_bits,
                                std::uint8_t rounding_mode) noexcept {
    const bool single = opcode == RiscvOpcode::fround_s || opcode == RiscvOpcode::froundnx_s;
    const bool exact = opcode == RiscvOpcode::froundnx_s || opcode == RiscvOpcode::froundnx_d;
    if ((!single && opcode != RiscvOpcode::fround_d && opcode != RiscvOpcode::froundnx_d) ||
        rounding_mode > 4)
        return {};

    const unsigned fraction_bits = single ? 23 : 52;
    const unsigned exponent_bits = single ? 8 : 11;
    const int bias = single ? 127 : 1023;
    const std::uint64_t sign_mask = UINT64_C(1) << (fraction_bits + exponent_bits);
    const std::uint64_t fraction_mask = (UINT64_C(1) << fraction_bits) - 1;
    const std::uint64_t exponent_mask = (UINT64_C(1) << exponent_bits) - 1;
    const std::uint64_t quiet_mask = UINT64_C(1) << (fraction_bits - 1);
    const std::uint64_t input = single ? source_bits & UINT32_MAX : source_bits;
    const std::uint64_t sign = input & sign_mask;
    const auto encoded_exponent = static_cast<unsigned>((input >> fraction_bits) & exponent_mask);
    const auto fraction = input & fraction_mask;
    RiscvFloatingRoundResult result{input, 0};

    if (encoded_exponent == exponent_mask) {
        if (fraction != 0 && (fraction & quiet_mask) == 0) {
            result.value = input | quiet_mask;
            result.fflags_set = 0x10; // NV
        }
        return result;
    }

    if (encoded_exponent == 0 && fraction == 0) return result;
    const int exponent = encoded_exponent == 0 ? 1 - bias : static_cast<int>(encoded_exponent) - bias;
    bool fractional = false;
    bool increment = false;
    std::uint64_t magnitude = input & ~sign_mask;
    if (exponent < 0) {
        fractional = true;
        const bool at_least_half = exponent == -1 && fraction != 0;
        const bool exactly_half = exponent == -1 && fraction == 0;
        switch (rounding_mode) {
        case 0: increment = at_least_half && !exactly_half; break; // RNE; zero is even on ties.
        case 1: break; // RTZ
        case 2: increment = sign != 0; break; // RDN
        case 3: increment = sign == 0; break; // RUP
        case 4: increment = at_least_half || exactly_half; break; // RMM
        }
        magnitude = increment ? (static_cast<std::uint64_t>(bias) << fraction_bits) : 0;
    } else if (exponent < static_cast<int>(fraction_bits)) {
        const unsigned discarded = fraction_bits - static_cast<unsigned>(exponent);
        const std::uint64_t discarded_mask = (UINT64_C(1) << discarded) - 1;
        const auto remainder = magnitude & discarded_mask;
        fractional = remainder != 0;
        const auto halfway = UINT64_C(1) << (discarded - 1);
        const auto truncated = magnitude & ~discarded_mask;
        switch (rounding_mode) {
        case 0: increment = remainder > halfway || (remainder == halfway && ((truncated >> discarded) & 1)); break;
        case 1: break;
        case 2: increment = sign != 0 && fractional; break;
        case 3: increment = sign == 0 && fractional; break;
        case 4: increment = remainder >= halfway; break;
        }
        magnitude = truncated + (increment ? (UINT64_C(1) << discarded) : 0);
    }
    result.value = sign | magnitude;
    if (single) result.value &= UINT32_MAX;
    if (exact && fractional) result.fflags_set |= 0x01; // NX
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

    const bool widening_reduction = opcode == RiscvOpcode::vwredsum || opcode == RiscvOpcode::vwredsumu;
    if (widening_reduction && (sew == 64 || config.lmul_log2 > 2))
        return {}; // 128-bit results or an LMUL>8 destination group are unsupported.
    bool reduction = true;
    switch (opcode) {
    case RiscvOpcode::vredsum: case RiscvOpcode::vredand: case RiscvOpcode::vredor:
    case RiscvOpcode::vredxor: case RiscvOpcode::vredminu: case RiscvOpcode::vredmin:
    case RiscvOpcode::vredmaxu: case RiscvOpcode::vredmax:
    case RiscvOpcode::vwredsum: case RiscvOpcode::vwredsumu: break;
    default: reduction = false; break;
    }
    if (reduction) {
        if (config.vstart != 0 || operands.vs1.size() != vlmax ||
            (config.masked && std::any_of(operands.predicate_mask.begin(), operands.predicate_mask.end(),
                                          [](std::uint8_t bit) { return bit > 1; }))) return {};
        const auto element_mask = width_mask(sew);
        const auto result_bits = widening_reduction ? sew * 2 : sew;
        const auto result_mask = width_mask(result_bits);
        auto accumulator = operands.vs1[0] & result_mask;
        const auto signed_less = [sew](std::uint64_t lhs, std::uint64_t rhs) {
            const bool lhs_negative = negative(lhs, sew), rhs_negative = negative(rhs, sew);
            return lhs_negative != rhs_negative ? lhs_negative : lhs < rhs;
        };
        for (std::uint64_t lane = 0; lane < config.vl; ++lane) {
            if (config.masked && operands.predicate_mask[static_cast<std::size_t>(lane)] == 0) continue;
            const auto value = operands.vs2[static_cast<std::size_t>(lane)] & element_mask;
            switch (opcode) {
            case RiscvOpcode::vwredsumu:
                accumulator = (accumulator + value) & result_mask;
                break;
            case RiscvOpcode::vwredsum: {
                const auto extended = negative(value, sew) ? (value | ~element_mask) : value;
                accumulator = (accumulator + extended) & result_mask;
                break;
            }
            case RiscvOpcode::vredsum: accumulator = (accumulator + value) & element_mask; break;
            case RiscvOpcode::vredand: accumulator &= value; break;
            case RiscvOpcode::vredor: accumulator |= value; break;
            case RiscvOpcode::vredxor: accumulator ^= value; break;
            case RiscvOpcode::vredminu: accumulator = std::min(accumulator, value); break;
            case RiscvOpcode::vredmaxu: accumulator = std::max(accumulator, value); break;
            case RiscvOpcode::vredmin: if (signed_less(value, accumulator)) accumulator = value; break;
            case RiscvOpcode::vredmax: if (signed_less(accumulator, value)) accumulator = value; break;
            default: break;
            }
        }
        RiscvVectorIntegerResult result;
        result.vlmax = vlmax;
        result.element_bits = static_cast<std::uint8_t>(result_bits);
        result.lanes.assign(operands.old_destination.begin(), operands.old_destination.end());
        result.lanes[0] = accumulator;
        return result;
    }

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

    enum class Operation { classification, reciprocal_estimate, reciprocal_sqrt_estimate,
                           sign_copy, sign_invert, sign_xor, min, max,
                           reduce_min, reduce_max, reduce_unordered_sum, reduce_ordered_sum,
                           equal, not_equal, less, less_equal, greater, greater_equal };
    Operation operation;
    bool vector_rhs = false, mask_result = false;
    switch (opcode) {
    case RiscvOpcode::vfclass_v: operation = Operation::classification; break;
    case RiscvOpcode::vfrec7_v: operation = Operation::reciprocal_estimate; break;
    case RiscvOpcode::vfrsqrt7_v: operation = Operation::reciprocal_sqrt_estimate; break;
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
    case RiscvOpcode::vfredmin: operation = Operation::reduce_min; break;
    case RiscvOpcode::vfredmax: operation = Operation::reduce_max; break;
    case RiscvOpcode::vfredusum: operation = Operation::reduce_unordered_sum; break;
    case RiscvOpcode::vfredosum: operation = Operation::reduce_ordered_sum; break;
    default: return {};
    }
    const bool reduction = operation == Operation::reduce_min || operation == Operation::reduce_max ||
        operation == Operation::reduce_unordered_sum || operation == Operation::reduce_ordered_sum;
    const bool sum_reduction = operation == Operation::reduce_unordered_sum ||
        operation == Operation::reduce_ordered_sum;
    if (reduction && (config.vstart != 0 || operands.vs1.size() != vlmax ||
        (config.masked && std::any_of(operands.predicate_mask.begin(), operands.predicate_mask.end(),
                                      [](std::uint8_t bit) { return bit > 1; })))) return {};
    if (sum_reduction && (!operands.frm || *operands.frm > 4)) return {};
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

    const bool estimate = operation == Operation::reciprocal_estimate ||
                          operation == Operation::reciprocal_sqrt_estimate;
    if (estimate && (vector_rhs || !operands.vs1.empty())) return {};
    if (operation == Operation::reciprocal_estimate &&
        (!operands.frm || *operands.frm > 4)) return {};
    const unsigned frac_bits = sew == 32 ? 23 : 52;
    const unsigned exp_bits = sew == 32 ? 8 : 11;
    const int bias = (1 << (exp_bits - 1)) - 1;
    const auto estimate_value = [&](std::uint64_t input, std::uint8_t &fflags) {
        const auto sign = input & sign_mask;
        const auto mag = input & ~sign_mask & element_mask;
        const auto exp_field = static_cast<unsigned>((mag & exponent_mask) >> frac_bits);
        const auto frac = mag & fraction_mask;
        const auto max_exp_field = (1u << exp_bits) - 1;
        if (exp_field == max_exp_field) {
            if (frac) {
                if ((frac & quiet_mask) == 0) fflags |= 0x10;
                return canonical_nan;
            }
            if (operation == Operation::reciprocal_estimate) return sign;
            if (sign) fflags |= 0x10;
            return sign ? canonical_nan : UINT64_C(0);
        }
        if (operation == Operation::reciprocal_sqrt_estimate && sign && mag != 0) {
            fflags |= 0x10;
            return canonical_nan;
        }
        if (mag == 0) {
            fflags |= 0x08;
            return sign | exponent_mask;
        }
        const bool normal = exp_field != 0;
        const int e = normal ? static_cast<int>(exp_field)
                             : -static_cast<int>(frac_bits - std::bit_width(frac));
        const std::uint64_t normalized_frac = normal ? frac :
            ((frac << static_cast<unsigned>(1 - e)) & fraction_mask);
        if (operation == Operation::reciprocal_sqrt_estimate) {
            int out_e = 3 * bias - 1 - e;
            out_e = out_e >= 0 ? out_e / 2 : -((-out_e + 1) / 2);
            const auto index = ((e & 1) << 6) | static_cast<unsigned>(normalized_frac >> (frac_bits - 6));
            const auto out_frac = static_cast<std::uint64_t>(processors::detail::vfrsqrt7_table[index]) << (frac_bits - 7);
            const auto out_exp = static_cast<std::uint64_t>(out_e);
            return sign | (out_exp << frac_bits) | out_frac;
        }
        const int out_e = 2 * bias - 1 - e;
        if (out_e > 2 * bias) {
            fflags |= 0x05; // NX | OF
            const auto mode = *operands.frm;
            const bool infinity = sign ? (mode == 2 || mode == 0 || mode == 4)
                                       : (mode == 3 || mode == 0 || mode == 4);
            if (infinity) return sign | exponent_mask;
            return sign | ((static_cast<std::uint64_t>(max_exp_field - 1) << frac_bits) | fraction_mask);
        }
        const unsigned idx = static_cast<unsigned>(normalized_frac >> (frac_bits - 7));
        const auto out_frac = static_cast<std::uint64_t>(processors::detail::vfrec7_table[idx]) << (frac_bits - 7);
        if (out_e == 0 || out_e == -1) {
            const auto sig = (UINT64_C(1) << frac_bits) | out_frac;
            const unsigned shift = static_cast<unsigned>(1 - out_e);
            return sign | (shift >= 64 ? 0 : sig >> shift);
        }
        const auto out_exp = static_cast<std::uint64_t>(out_e);
        return sign | (out_exp << frac_bits) | out_frac;
    };

    const auto minmax = [&](std::uint64_t lhs, std::uint64_t rhs, bool maximum,
                            std::uint8_t &fflags) {
        lhs &= element_mask;
        rhs &= element_mask;
        const bool lhs_nan = is_nan(lhs), rhs_nan = is_nan(rhs);
        if (is_signaling_nan(lhs) || is_signaling_nan(rhs)) fflags |= 0x10;
        if (lhs_nan || rhs_nan) return lhs_nan && rhs_nan ? canonical_nan : lhs_nan ? rhs : lhs;
        if (is_zero(lhs) && is_zero(rhs)) {
            const auto signs = (lhs | rhs) & sign_mask;
            return maximum ? (signs ? ((lhs & rhs) & sign_mask) : UINT64_C(0)) : signs;
        }
        const bool take_lhs = ordered_less(lhs, rhs);
        return maximum ? (take_lhs ? rhs : lhs) : (take_lhs ? lhs : rhs);
    };

    RiscvVectorFloatingResult result;
    result.vlmax = vlmax;
    result.mask_result = mask_result;
    result.element_bits = mask_result ? 1 : static_cast<std::uint8_t>(sew);
    result.lanes.assign(operands.old_destination.begin(), operands.old_destination.end());
    if (reduction) {
        auto accumulator = operands.vs1[0] & element_mask;
        const bool maximum = operation == Operation::reduce_max;
        for (std::uint64_t lane = 0; lane < config.vl; ++lane) {
            if (config.masked && operands.predicate_mask[static_cast<std::size_t>(lane)] == 0) continue;
            if (sum_reduction) {
                const auto added = add_riscv_float_bits(accumulator,
                    operands.vs2[static_cast<std::size_t>(lane)], sew, *operands.frm);
                accumulator = added.bits;
                result.fflags_set |= added.fflags;
            } else {
                accumulator = minmax(accumulator, operands.vs2[static_cast<std::size_t>(lane)], maximum,
                                     result.fflags_set);
            }
        }
        result.lanes[0] = accumulator;
        return result;
    }
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
        case Operation::reciprocal_estimate:
        case Operation::reciprocal_sqrt_estimate:
            value = estimate_value(lhs, result.fflags_set);
            break;
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
        case Operation::reduce_min:
        case Operation::reduce_max:
            // Handled by the scalar reduction path above.
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
    return plan_riscv_vector_memory_accesses(opcode, config, base, stride_bits, element_bits,
                                             predicate_mask, 1);
}

std::optional<RiscvVectorMemoryAccessPlan>
plan_riscv_vector_memory_accesses(RiscvOpcode opcode, const RiscvVectorIntegerConfig &config,
                                  std::uint64_t base, std::uint64_t stride_bits,
                                  std::uint8_t element_bits,
                                  std::span<const std::uint8_t> predicate_mask,
                                  std::uint8_t segment_fields) {
    const bool load = opcode == RiscvOpcode::vle || opcode == RiscvOpcode::vlse;
    const bool unit_stride = opcode == RiscvOpcode::vle || opcode == RiscvOpcode::vse;
    const bool strided = opcode == RiscvOpcode::vlse || opcode == RiscvOpcode::vsse;
    if ((!unit_stride && !strided) || (element_bits != 8 && element_bits != 16 &&
        element_bits != 32 && element_bits != 64) ||
        segment_fields == 0 || segment_fields > 8 ||
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
    if (emul_log2 < -3 || emul_log2 > 3 ||
        (emul_log2 > 0 && segment_fields > (8u >> static_cast<unsigned>(emul_log2))))
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
    const auto active_lanes = config.vl - config.vstart;
    if (active_lanes > std::numeric_limits<std::size_t>::max() / segment_fields)
        return {};
    plan.active_elements.reserve(static_cast<std::size_t>(active_lanes * segment_fields));
    const std::uint64_t element_bytes = element_bits / 8;
    for (std::uint64_t lane = config.vstart; lane < config.vl; ++lane) {
        if (config.masked && predicate_mask[static_cast<std::size_t>(lane)] == 0)
            continue;

        const bool negative_stride = strided && signed_stride < 0;
        const std::uint64_t magnitude = !strided ? element_bytes * segment_fields : negative_stride
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
        for (std::uint8_t field = 0; field < segment_fields; ++field) {
            const auto field_displacement = static_cast<std::uint64_t>(field) * element_bytes;
            if (field_displacement > xlen_mask - address) return {};
            plan.active_elements.push_back({lane, address + field_displacement, field});
        }
    }
    return plan;
}

std::optional<RiscvVectorMemoryAccessPlan>
plan_riscv_vector_indexed_memory_accesses(RiscvOpcode opcode, const RiscvVectorIntegerConfig &config,
                                          std::uint64_t base, std::uint8_t index_element_bits,
                                          std::span<const std::uint64_t> index_offsets,
                                          std::span<const std::uint8_t> predicate_mask) {
    return plan_riscv_vector_indexed_memory_accesses(opcode, config, base, index_element_bits,
                                                    index_offsets, predicate_mask, 1);
}

std::optional<RiscvVectorMemoryAccessPlan>
plan_riscv_vector_indexed_memory_accesses(RiscvOpcode opcode, const RiscvVectorIntegerConfig &config,
                                          std::uint64_t base, std::uint8_t index_element_bits,
                                          std::span<const std::uint64_t> index_offsets,
                                          std::span<const std::uint8_t> predicate_mask,
                                          std::uint8_t segment_fields) {
    const bool load = opcode == RiscvOpcode::vluxei || opcode == RiscvOpcode::vloxei;
    const bool unordered = opcode == RiscvOpcode::vluxei || opcode == RiscvOpcode::vsuxei;
    const bool store = opcode == RiscvOpcode::vsuxei || opcode == RiscvOpcode::vsoxei;
    const auto valid_width = [](unsigned bits) { return bits == 8 || bits == 16 || bits == 32 || bits == 64; };
    if ((!load && !store) || segment_fields == 0 || segment_fields > 8 ||
        !valid_width(index_element_bits) || !valid_width(config.sew_bits) ||
        (config.xlen_bits != 32 && config.xlen_bits != 64) ||
        config.vlen_bits < 64 || config.vlen_bits > 65528 || config.vlen_bits % 8 != 0 ||
        config.vlen_bits % config.sew_bits != 0 || config.lmul_log2 < -3 || config.lmul_log2 > 3)
        return {};

    const auto log2_width = [](unsigned bits) -> int {
        return bits == 8 ? 3 : bits == 16 ? 4 : bits == 32 ? 5 : 6;
    };
    const int index_emul_log2 = static_cast<int>(config.lmul_log2) +
                                log2_width(index_element_bits) - log2_width(config.sew_bits);
    const int data_emul_log2 = config.lmul_log2;
    if (index_emul_log2 < -3 || index_emul_log2 > 3 ||
        (data_emul_log2 > 0 && segment_fields > (8u >> static_cast<unsigned>(data_emul_log2))))
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
    const auto active_lanes = config.vl - config.vstart;
    if (active_lanes > std::numeric_limits<std::size_t>::max() / segment_fields)
        return {};
    plan.active_elements.reserve(static_cast<std::size_t>(active_lanes * segment_fields));
    for (std::uint64_t lane = config.vstart; lane < config.vl; ++lane) {
        if (config.masked && predicate_mask[static_cast<std::size_t>(lane)] == 0)
            continue;
        const auto raw_offset = index_offsets[static_cast<std::size_t>(lane)];
        if (raw_offset > index_mask)
            return {}; // Caller supplied bits outside the encoded index EEW.
        const auto offset = raw_offset & xlen_mask; // Wider indices use their low XLEN bits.
        if (offset > xlen_mask - base)
            return {}; // Reject address wrap rather than silently wrapping.
        const auto address = base + offset;
        const auto element_bytes = static_cast<std::uint64_t>(config.sew_bits / 8);
        for (std::uint8_t field = 0; field < segment_fields; ++field) {
            const auto field_displacement = static_cast<std::uint64_t>(field) * element_bytes;
            if (field_displacement > xlen_mask - address) return {};
            plan.active_elements.push_back({lane, address + field_displacement, field});
        }
    }
    return plan;
}
} // namespace hexlab
