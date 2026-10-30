#include "hexlab/processors/mips32_semantics.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>

namespace hexlab {

std::uint32_t evaluate_mips32_mul_low(std::uint32_t lhs_bits, std::uint32_t rhs_bits) noexcept {
    return static_cast<std::uint32_t>(static_cast<std::uint64_t>(lhs_bits) * rhs_bits);
}

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

std::optional<Mips32HiLoMoveResult>
evaluate_mips32_hilo_move_instruction(const Instruction &instruction,
                                      std::uint32_t hi, std::uint32_t lo,
                                      std::uint32_t gpr_value) noexcept {
    if (instruction.context.architecture != Architecture::mips32 ||
        instruction.context.mode != ExecutionMode::mips32 || instruction.length != 4 ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots != 0 ||
        instruction.memory_read || instruction.memory_write || instruction.operands.size() != 1 ||
        instruction.access.size() != 1)
        return {};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    Mips32HiLoMoveResult result{hi, lo, 0, false, false, false};
    if (instruction.opcode == Opcode::mips_mfhi || instruction.opcode == Opcode::mips_mflo) {
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        if (!destination || destination->bank != RegisterBank::mips_gpr || destination->index > 31 ||
            destination->width != 32 || destination->high_byte || instruction.access[0] != OperandAccess::write)
            return {};
        const bool read_hi = instruction.opcode == Opcode::mips_mfhi;
        const RegisterOperand source{RegisterBank::mips_hilo, static_cast<std::uint8_t>(read_hi ? 0 : 1), 32, false};
        if (!contains(instruction.register_reads, source) ||
            (destination->index != 0 && !contains(instruction.register_writes, *destination)) ||
            (destination->index == 0 && contains(instruction.register_writes, *destination)))
            return {};
        result.gpr_value = read_hi ? hi : lo;
        result.writes_gpr = destination->index != 0;
        return result;
    }
    if (instruction.opcode == Opcode::mips_mthi || instruction.opcode == Opcode::mips_mtlo) {
        const auto *source = std::get_if<RegisterOperand>(&instruction.operands[0]);
        if (!source || source->bank != RegisterBank::mips_gpr || source->index > 31 ||
            source->width != 32 || source->high_byte || instruction.access[0] != OperandAccess::read ||
            !contains(instruction.register_reads, *source))
            return {};
        if (instruction.opcode == Opcode::mips_mthi) {
            const RegisterOperand destination{RegisterBank::mips_hilo, 0, 32, false};
            if (!contains(instruction.register_writes, destination)) return {};
            result.hi = gpr_value;
            result.writes_hi = true;
        } else {
            const RegisterOperand destination{RegisterBank::mips_hilo, 1, 32, false};
            if (!contains(instruction.register_writes, destination)) return {};
            result.lo = gpr_value;
            result.writes_lo = true;
        }
        return result;
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
    const bool flush_subnormal = (fcsr & fcsr_flush_subnormal) != 0;
    constexpr std::uint32_t sign_mask = 0x80000000u;
    constexpr std::uint32_t exponent_mask = 0x7f800000u;
    constexpr std::uint32_t fraction_mask = 0x007fffffu;
    constexpr std::uint32_t quiet_bit = 0x00400000u;
    const auto rounding = fcsr & 3u;
    Mips32DivSResult result{};
    auto lhs_exp = (lhs_bits & exponent_mask) >> 23;
    auto rhs_exp = (rhs_bits & exponent_mask) >> 23;
    auto lhs_frac = lhs_bits & fraction_mask;
    auto rhs_frac = rhs_bits & fraction_mask;
    const bool lhs_nan = lhs_exp == 0xff && lhs_frac != 0;
    const bool rhs_nan = rhs_exp == 0xff && rhs_frac != 0;

    // Release 5 and later replace every subnormal arithmetic input with a
    // same-sign zero when FCSR.FS is set. Flushing an input raises Inexact.
    // Leave the operation's normal exception processing in place so, for
    // example, 0/0 after input flushing still raises Invalid as well.
    if (flush_subnormal) {
        const auto flush_input = [&](std::uint32_t &bits, std::uint32_t &exponent,
                                     std::uint32_t &fraction) {
            if (exponent == 0 && fraction != 0) {
                bits &= sign_mask;
                exponent = 0;
                fraction = 0;
                result.exception_bits |= fp_inexact;
            }
        };
        flush_input(lhs_bits, lhs_exp, lhs_frac);
        flush_input(rhs_bits, rhs_exp, rhs_frac);
    }
    const bool negative = ((lhs_bits ^ rhs_bits) & sign_mask) != 0;
    const auto sign = negative ? sign_mask : 0u;

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

    // In Release 5+ alternate flush mode, tininess is detected before
    // rounding. Every exact nonzero result below the normal range is replaced
    // by signed zero and raises both Underflow and Inexact.
    if (flush_subnormal && exponent < -126) {
        result.value_bits = sign;
        result.exception_bits |= fp_underflow | fp_inexact;
        finalize_fcsr(result, fcsr);
        return result;
    }

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

std::optional<Mips32DivSResult> evaluate_mips32_div_s_instruction(
    const Instruction &instruction, std::uint32_t lhs_bits, std::uint32_t rhs_bits,
    std::uint32_t fcsr_value) noexcept {
    if (instruction.context.architecture != Architecture::mips32 ||
        instruction.context.mode != ExecutionMode::mips32 || instruction.opcode != Opcode::mips_div_s ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read || instruction.memory_read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *left = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *right = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto valid_fpr = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::mips_fpr && reg->width == 32 && !reg->high_byte;
    };
    if (!valid_fpr(destination) || !valid_fpr(left) || !valid_fpr(right)) return {};
    const RegisterOperand fcsr{RegisterBank::mips_fcsr, 0, 32, false};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!contains(instruction.register_reads, *left) || !contains(instruction.register_reads, *right) ||
        !contains(instruction.register_reads, fcsr) || !contains(instruction.register_writes, *destination) ||
        !contains(instruction.register_writes, fcsr))
        return {};
    return evaluate_mips32_div_s(lhs_bits, rhs_bits, fcsr_value);
}

std::optional<bool>
evaluate_mips32_fcc_branch_instruction(const Instruction &instruction,
                                       bool condition_code_value) noexcept {
    if (instruction.context.architecture != Architecture::mips32 ||
        instruction.context.mode != ExecutionMode::mips32 ||
        (instruction.opcode != Opcode::mips_bc1t && instruction.opcode != Opcode::mips_bc1f &&
         instruction.opcode != Opcode::mips_bc1tl && instruction.opcode != Opcode::mips_bc1fl) ||
        instruction.flow != FlowKind::conditional_branch || instruction.delay_slots != 1 ||
        instruction.condition > 7 || instruction.operands.size() != 1 || instruction.access.size() != 1 ||
        instruction.access[0] != OperandAccess::address || !instruction.direct_target ||
        instruction.memory_read || instruction.memory_write ||
        !std::holds_alternative<RelativeOperand>(instruction.operands[0]))
        return {};
    const RegisterOperand selected_fcc{RegisterBank::mips_fcsr,
        static_cast<std::uint8_t>(instruction.condition + 1), 32, false};
    if (std::find(instruction.register_reads.begin(), instruction.register_reads.end(), selected_fcc) ==
        instruction.register_reads.end())
        return {};
    const bool branch_on_true = instruction.opcode == Opcode::mips_bc1t ||
                                instruction.opcode == Opcode::mips_bc1tl;
    return condition_code_value == branch_on_true;
}

std::optional<bool>
evaluate_mips32_integer_branch_instruction(const Instruction &instruction,
                                           std::uint32_t lhs, std::uint32_t rhs) noexcept {
    if (instruction.context.architecture != Architecture::mips32 ||
        instruction.context.mode != ExecutionMode::mips32 ||
        instruction.flow != FlowKind::conditional_branch || instruction.delay_slots != 1 ||
        instruction.length != 4 || !instruction.direct_target || instruction.memory_read || instruction.memory_write)
        return {};
    const auto op = instruction.opcode;
    const bool pair = op == Opcode::mips_beq || op == Opcode::mips_bne ||
        op == Opcode::mips_beql || op == Opcode::mips_bnel;
    const bool unary = op == Opcode::mips_blez || op == Opcode::mips_bgtz ||
        op == Opcode::mips_blezl || op == Opcode::mips_bgtzl || op == Opcode::mips_bltz ||
        op == Opcode::mips_bgez || op == Opcode::mips_bltzl || op == Opcode::mips_bgezl;
    if (!pair && !unary) return {};
    const auto register_count = pair ? 2u : 1u;
    if (instruction.operands.size() != register_count + 1 || instruction.access.size() != register_count + 1 ||
        instruction.access.back() != OperandAccess::address ||
        !std::holds_alternative<RelativeOperand>(instruction.operands.back()))
        return {};
    const auto *left = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *right = pair ? std::get_if<RegisterOperand>(&instruction.operands[1]) : nullptr;
    const auto valid = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::mips_gpr && reg->width == 32 && !reg->high_byte;
    };
    if (!valid(left) || (pair && !valid(right))) return {};
    for (unsigned i = 0; i < register_count; ++i)
        if (instruction.access[i] != OperandAccess::read) return {};
    const auto has_read = [&](const RegisterOperand &reg) {
        return reg.index == 0 || std::find(instruction.register_reads.begin(), instruction.register_reads.end(), reg) !=
                                     instruction.register_reads.end();
    };
    if (!has_read(*left) || (pair && !has_read(*right))) return {};
    if (left->index == 0) lhs = 0;
    if (pair && right->index == 0) rhs = 0;
    const auto signed_lhs = std::bit_cast<std::int32_t>(lhs);
    const auto signed_rhs = std::bit_cast<std::int32_t>(rhs);
    switch (op) {
    case Opcode::mips_beq: case Opcode::mips_beql: return lhs == rhs;
    case Opcode::mips_bne: case Opcode::mips_bnel: return lhs != rhs;
    case Opcode::mips_blez: case Opcode::mips_blezl: return signed_lhs <= 0;
    case Opcode::mips_bgtz: case Opcode::mips_bgtzl: return signed_lhs > 0;
    case Opcode::mips_bltz: case Opcode::mips_bltzl: return signed_lhs < 0;
    case Opcode::mips_bgez: case Opcode::mips_bgezl: return signed_lhs >= 0;
    default: return {};
    }
}

std::optional<Mips32AddImmediateResult>
evaluate_mips32_add_immediate_instruction(const Instruction &instruction,
                                         std::uint32_t source) noexcept {
    const bool trapping = instruction.opcode == Opcode::mips_addi;
    if ((!trapping && instruction.opcode != Opcode::mips_addiu) ||
        instruction.context.architecture != Architecture::mips32 ||
        instruction.context.mode != ExecutionMode::mips32 || instruction.length != 4 ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots != 0 ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read || instruction.memory_read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
    const auto valid_gpr = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::mips_gpr && reg->width == 32 && !reg->high_byte;
    };
    if (!valid_gpr(destination) || !valid_gpr(input) || !immediate ||
        immediate->encoded_width != 16 || immediate->effective_width != 32 || !immediate->is_signed)
        return {};
    const auto delta = std::bit_cast<std::int64_t>(immediate->value);
    if (delta < INT16_MIN || delta > INT16_MAX) return {};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_reads, *input)) return {};
    if (destination->index != 0 && !has(instruction.register_writes, *destination)) return {};
    const auto signed_source = std::bit_cast<std::int32_t>(source);
    const auto wide_result = static_cast<std::int64_t>(signed_source) + delta;
    const bool overflow = trapping && (wide_result < INT32_MIN || wide_result > INT32_MAX);
    const auto result = static_cast<std::uint32_t>(static_cast<std::uint64_t>(wide_result));
    return Mips32AddImmediateResult{result, overflow, destination->index != 0 && !overflow};
}

std::optional<Mips32AddSubResult>
evaluate_mips32_add_sub_instruction(const Instruction &instruction,
                                    std::uint32_t lhs, std::uint32_t rhs) noexcept {
    const bool add = instruction.opcode == Opcode::mips_add || instruction.opcode == Opcode::mips_addu;
    const bool subtract = instruction.opcode == Opcode::mips_sub || instruction.opcode == Opcode::mips_subu;
    const bool trapping = instruction.opcode == Opcode::mips_add || instruction.opcode == Opcode::mips_sub;
    if ((!add && !subtract) || instruction.context.architecture != Architecture::mips32 ||
        instruction.context.mode != ExecutionMode::mips32 || instruction.length != 4 ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots != 0 ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read || instruction.memory_read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *left = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *right = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto valid_gpr = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::mips_gpr && reg->index < 32 &&
               reg->width == 32 && !reg->high_byte;
    };
    if (!valid_gpr(destination) || !valid_gpr(left) || !valid_gpr(right)) return {};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_reads, *left) || !has(instruction.register_reads, *right) ||
        (destination->index != 0 && !has(instruction.register_writes, *destination)))
        return {};
    if (left->index == 0) lhs = 0;
    if (right->index == 0) rhs = 0;
    std::int64_t wide_result = 0;
    if (trapping) {
        const auto signed_lhs = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(lhs));
        const auto signed_rhs = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(rhs));
        wide_result = add ? signed_lhs + signed_rhs : signed_lhs - signed_rhs;
    } else {
        wide_result = static_cast<std::int64_t>(static_cast<std::uint32_t>(add ? lhs + rhs : lhs - rhs));
    }
    const bool overflow = trapping && (wide_result < INT32_MIN || wide_result > INT32_MAX);
    const auto value = static_cast<std::uint32_t>(static_cast<std::uint64_t>(wide_result));
    return Mips32AddSubResult{value, overflow, destination->index != 0 && !overflow};
}

std::optional<std::uint32_t>
evaluate_mips32_set_less_than_immediate_instruction(const Instruction &instruction,
                                                    std::uint32_t source) noexcept {
    const bool signed_compare = instruction.opcode == Opcode::mips_slti;
    if ((!signed_compare && instruction.opcode != Opcode::mips_sltiu) ||
        instruction.context.architecture != Architecture::mips32 ||
        instruction.context.mode != ExecutionMode::mips32 || instruction.length != 4 ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots != 0 ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read || instruction.memory_read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
    const auto valid_gpr = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::mips_gpr && reg->width == 32 && !reg->high_byte;
    };
    if (!valid_gpr(destination) || !valid_gpr(input) || !immediate ||
        immediate->encoded_width != 16 || immediate->effective_width != 32 || !immediate->is_signed)
        return {};
    const auto sign_extended = std::bit_cast<std::int64_t>(immediate->value);
    if (sign_extended < INT16_MIN || sign_extended > INT16_MAX) return {};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_reads, *input) ||
        (destination->index != 0 && !has(instruction.register_writes, *destination)))
        return {};
    if (input->index == 0) source = 0;
    const auto immediate_bits = static_cast<std::uint32_t>(sign_extended);
    if (signed_compare)
        return std::bit_cast<std::int32_t>(source) < std::bit_cast<std::int32_t>(immediate_bits) ? 1u : 0u;
    return source < immediate_bits ? 1u : 0u;
}

std::optional<std::uint32_t>
evaluate_mips32_set_less_than_instruction(const Instruction &instruction,
                                          std::uint32_t lhs, std::uint32_t rhs) noexcept {
    const bool signed_compare = instruction.opcode == Opcode::mips_slt;
    if ((!signed_compare && instruction.opcode != Opcode::mips_sltu) ||
        instruction.context.architecture != Architecture::mips32 ||
        instruction.context.mode != ExecutionMode::mips32 || instruction.length != 4 ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots != 0 ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read || instruction.memory_read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *left = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *right = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto valid_gpr = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::mips_gpr && reg->width == 32 && !reg->high_byte;
    };
    if (!valid_gpr(destination) || !valid_gpr(left) || !valid_gpr(right)) return {};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if ((left->index != 0 && !has(instruction.register_reads, *left)) ||
        (right->index != 0 && !has(instruction.register_reads, *right)) ||
        (destination->index != 0 && !has(instruction.register_writes, *destination)))
        return {};
    if (left->index == 0) lhs = 0;
    if (right->index == 0) rhs = 0;
    if (signed_compare)
        return std::bit_cast<std::int32_t>(lhs) < std::bit_cast<std::int32_t>(rhs) ? 1u : 0u;
    return lhs < rhs ? 1u : 0u;
}

std::optional<std::uint32_t>
evaluate_mips32_logical_instruction(const Instruction &instruction,
                                    std::uint32_t lhs, std::uint32_t rhs) noexcept {
    if ((instruction.opcode != Opcode::mips_and && instruction.opcode != Opcode::mips_or &&
         instruction.opcode != Opcode::mips_xor && instruction.opcode != Opcode::mips_nor) ||
        instruction.context.architecture != Architecture::mips32 ||
        instruction.context.mode != ExecutionMode::mips32 || instruction.length != 4 ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots != 0 ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read || instruction.memory_read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *left = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *right = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto valid_gpr = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::mips_gpr && reg->index < 32 &&
               reg->width == 32 && !reg->high_byte;
    };
    if (!valid_gpr(destination) || !valid_gpr(left) || !valid_gpr(right)) return {};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if ((left->index != 0 && !has(instruction.register_reads, *left)) ||
        (right->index != 0 && !has(instruction.register_reads, *right)) ||
        (destination->index != 0 && !has(instruction.register_writes, *destination)))
        return {};
    if (left->index == 0) lhs = 0;
    if (right->index == 0) rhs = 0;
    switch (instruction.opcode) {
    case Opcode::mips_and: return lhs & rhs;
    case Opcode::mips_or: return lhs | rhs;
    case Opcode::mips_xor: return lhs ^ rhs;
    case Opcode::mips_nor: return ~(lhs | rhs);
    default: return {};
    }
}

std::optional<Mips32LogicalImmediateResult>
evaluate_mips32_logical_immediate_instruction(const Instruction &instruction,
                                              std::uint32_t source) noexcept {
    if ((instruction.opcode != Opcode::mips_andi && instruction.opcode != Opcode::mips_ori &&
         instruction.opcode != Opcode::mips_xori) ||
        instruction.context.architecture != Architecture::mips32 ||
        instruction.context.mode != ExecutionMode::mips32 || instruction.length != 4 ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots != 0 ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read || instruction.memory_read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
    const auto valid_gpr = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::mips_gpr && reg->width == 32 && !reg->high_byte;
    };
    if (!valid_gpr(destination) || !valid_gpr(input) || !immediate ||
        immediate->encoded_width != 16 || immediate->effective_width != 32 || immediate->is_signed ||
        immediate->value > UINT16_MAX)
        return {};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_reads, *input) ||
        (destination->index != 0 && !has(instruction.register_writes, *destination)))
        return {};
    if (input->index == 0) source = 0;
    const auto literal = static_cast<std::uint32_t>(immediate->value);
    const auto value = instruction.opcode == Opcode::mips_andi ? source & literal :
                       instruction.opcode == Opcode::mips_ori ? source | literal : source ^ literal;
    return Mips32LogicalImmediateResult{value, destination->index != 0};
}

std::optional<Mips32MergeLoadResult> evaluate_mips32_merge_load_instruction(
    const Instruction &instruction, std::uint32_t aligned_memory_word,
    std::uint32_t prior_gpr, std::uint8_t address_offset) noexcept {
    if (instruction.context.architecture != Architecture::mips32 ||
        instruction.context.mode != ExecutionMode::mips32 || instruction.length != 4 ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots != 0 ||
        !instruction.memory_read || instruction.memory_write || address_offset > 3 ||
        instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read)
        return {};
    const bool left = instruction.opcode == Opcode::mips_lwl;
    if (!left && instruction.opcode != Opcode::mips_lwr)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
    const auto valid_gpr = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::mips_gpr && reg->index <= 31 &&
               reg->width == 32 && !reg->high_byte;
    };
    if (!valid_gpr(destination) || !memory || memory->data_width != 32 ||
        memory->address_width != 32 || !memory->base || !valid_gpr(&*memory->base) ||
        memory->index || memory->segment || memory->scale != 1 || memory->ip_relative ||
        memory->writeback || memory->post_index)
        return {};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (contains(instruction.register_writes, *destination) != (destination->index != 0))
        return {};

    const bool little = instruction.context.order == ByteOrder::little;
    std::array<std::uint8_t, 4> memory_bytes{};
    for (unsigned address_byte = 0; address_byte < 4; ++address_byte) {
        const unsigned shift = (little ? address_byte : 3u - address_byte) * 8u;
        memory_bytes[address_byte] = static_cast<std::uint8_t>(aligned_memory_word >> shift);
    }
    std::uint32_t merged = prior_gpr;
    const auto merge_byte = [&merged, &memory_bytes](unsigned memory_byte, unsigned register_byte) {
        const unsigned shift = (3u - register_byte) * 8u;
        const auto mask = UINT32_C(0xff) << shift;
        merged = (merged & ~mask) | (static_cast<std::uint32_t>(memory_bytes[memory_byte]) << shift);
    };
    if (little) {
        if (left) {
            for (unsigned memory_byte = 0; memory_byte <= address_offset; ++memory_byte)
                merge_byte(memory_byte, address_offset - memory_byte);
        } else {
            for (unsigned memory_byte = address_offset; memory_byte < 4; ++memory_byte)
                merge_byte(memory_byte, 3u + address_offset - memory_byte);
        }
    } else if (left) {
        for (unsigned memory_byte = address_offset; memory_byte < 4; ++memory_byte)
            merge_byte(memory_byte, memory_byte - address_offset);
    } else {
        for (unsigned memory_byte = 0; memory_byte <= address_offset; ++memory_byte)
            merge_byte(memory_byte, 3u - address_offset + memory_byte);
    }
    if (destination->index == 0)
        return Mips32MergeLoadResult{0, false};
    return Mips32MergeLoadResult{merged, true};
}

std::optional<std::uint32_t>
evaluate_mips32_bitfield_instruction(const Instruction &instruction,
                                     std::uint32_t source,
                                     std::uint32_t prior_destination) noexcept {
    const bool insert = instruction.opcode == Opcode::mips_ins;
    if ((instruction.opcode != Opcode::mips_ext && !insert) ||
        instruction.context.architecture != Architecture::mips32 ||
        instruction.context.mode != ExecutionMode::mips32 || instruction.operands.size() != 4 ||
        instruction.access.size() != 4 ||
        instruction.access[0] != (insert ? OperandAccess::read_write : OperandAccess::write) ||
        instruction.access[1] != OperandAccess::read || instruction.access[2] != OperandAccess::read ||
        instruction.access[3] != OperandAccess::read || instruction.memory_read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *position = std::get_if<ImmediateOperand>(&instruction.operands[2]);
    const auto *size = std::get_if<ImmediateOperand>(&instruction.operands[3]);
    const auto valid_gpr = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::mips_gpr && reg->width == 32 && !reg->high_byte;
    };
    if (!valid_gpr(destination) || !valid_gpr(input) || !position || !size ||
        position->encoded_width != 5 || position->effective_width != 32 ||
        size->encoded_width != 6 || size->effective_width != 32 ||
        position->is_signed || size->is_signed || position->value >= 32 ||
        size->value == 0 || size->value > 32 || position->value + size->value > 32)
        return {};
    const RegisterOperand zero{RegisterBank::mips_gpr, 0, 32, false};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if ((input->index != 0 && !contains(instruction.register_reads, *input)) ||
        (insert && destination->index != 0 && !contains(instruction.register_reads, *destination)) ||
        (destination->index != 0 && !contains(instruction.register_writes, *destination)) ||
        contains(instruction.register_reads, zero) || contains(instruction.register_writes, zero))
        return {};
    const unsigned bit_position = static_cast<unsigned>(position->value);
    const unsigned field_size = static_cast<unsigned>(size->value);
    const auto field_mask = field_size == 32 ? UINT32_MAX : (UINT32_C(1) << field_size) - 1;
    if (input->index == 0) source = 0;
    if (!insert) return (source >> bit_position) & field_mask;
    const auto destination_mask = field_mask << bit_position;
    const auto destination_value = destination->index == 0 ? 0 : prior_destination;
    return (destination_value & ~destination_mask) | ((source << bit_position) & destination_mask);
}

std::optional<std::uint32_t> evaluate_mips32_count_leading(Opcode opcode,
                                                           std::uint32_t source) noexcept {
    if (opcode == Opcode::mips_clz) return static_cast<std::uint32_t>(std::countl_zero(source));
    if (opcode == Opcode::mips_clo) return static_cast<std::uint32_t>(std::countl_one(source));
    return {};
}

std::optional<std::uint32_t>
evaluate_mips32_count_leading_instruction(const Instruction &instruction,
                                          std::uint32_t source) noexcept {
    if (instruction.context.architecture != Architecture::mips32 ||
        instruction.context.mode != ExecutionMode::mips32 ||
        (instruction.opcode != Opcode::mips_clz && instruction.opcode != Opcode::mips_clo) ||
        instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.memory_read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto valid_gpr = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::mips_gpr && reg->width == 32 && !reg->high_byte;
    };
    if (!valid_gpr(destination) || !valid_gpr(input)) return {};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    const RegisterOperand zero{RegisterBank::mips_gpr, 0, 32, false};
    if ((input->index != 0 && !contains(instruction.register_reads, *input)) ||
        (destination->index != 0 && !contains(instruction.register_writes, *destination)) ||
        contains(instruction.register_reads, zero) || contains(instruction.register_writes, zero))
        return {};
    if (input->index == 0) source = 0;
    return evaluate_mips32_count_leading(instruction.opcode, source);
}

std::optional<std::uint32_t>
evaluate_mips32_shift_instruction(const Instruction &instruction,
                                  std::uint32_t source,
                                  std::uint32_t amount_value) noexcept {
    const bool fixed = instruction.opcode == Opcode::mips_sll || instruction.opcode == Opcode::mips_srl ||
                       instruction.opcode == Opcode::mips_sra;
    const bool variable = instruction.opcode == Opcode::mips_sllv || instruction.opcode == Opcode::mips_srlv ||
                          instruction.opcode == Opcode::mips_srav;
    if ((!fixed && !variable) || instruction.context.architecture != Architecture::mips32 ||
        instruction.context.mode != ExecutionMode::mips32 || instruction.operands.size() != 3 ||
        instruction.access.size() != 3 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read || instruction.access[2] != OperandAccess::read ||
        instruction.memory_read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *amount_reg = variable ? std::get_if<RegisterOperand>(&instruction.operands[2]) : nullptr;
    const auto *amount_imm = fixed ? std::get_if<ImmediateOperand>(&instruction.operands[2]) : nullptr;
    const auto valid_gpr = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::mips_gpr && reg->width == 32 && !reg->high_byte;
    };
    if (!valid_gpr(destination) || !valid_gpr(input) ||
        (variable && !valid_gpr(amount_reg)) ||
        (fixed && (!amount_imm || amount_imm->encoded_width != 5 || amount_imm->effective_width != 32 ||
                   amount_imm->is_signed || amount_imm->value > 31)))
        return {};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    const RegisterOperand zero{RegisterBank::mips_gpr, 0, 32, false};
    if ((input->index != 0 && !has(instruction.register_reads, *input)) ||
        (variable && amount_reg->index != 0 && !has(instruction.register_reads, *amount_reg)) ||
        (destination->index != 0 && !has(instruction.register_writes, *destination)) ||
        has(instruction.register_reads, zero) || has(instruction.register_writes, zero))
        return {};
    if (input->index == 0) source = 0;
    unsigned amount = fixed ? static_cast<unsigned>(amount_imm->value) :
                      amount_reg->index == 0 ? 0u : amount_value & 31u;
    switch (instruction.opcode) {
    case Opcode::mips_sll: case Opcode::mips_sllv: return source << amount;
    case Opcode::mips_srl: case Opcode::mips_srlv: return source >> amount;
    case Opcode::mips_sra: case Opcode::mips_srav:
        if (amount == 0) return source;
        return (source >> amount) | ((source & 0x80000000u) ? (UINT32_MAX << (32 - amount)) : 0u);
    default: return {};
    }
}

std::optional<Mips32WordConversionResult> evaluate_mips32_word_conversion(
    bool double_precision, Mips32WordRounding rounding, std::uint64_t source_bits,
    std::uint32_t fcsr) noexcept {
    constexpr std::uint8_t inexact = 1u << 0;
    constexpr std::uint8_t invalid = 1u << 4;
    constexpr std::uint32_t cause_mask = 0x1fu << 12;
    constexpr std::uint32_t flag_mask = 0x1fu << 2;
    constexpr std::uint32_t enable_mask = 0x1fu << 7;
    constexpr std::uint32_t flush_subnormal = 1u << 24;
    const bool flush_inputs = (fcsr & flush_subnormal) != 0;
    if (static_cast<unsigned>(rounding) >
        static_cast<unsigned>(Mips32WordRounding::toward_negative)) return {};

    const unsigned fraction_bits = double_precision ? 52u : 23u;
    const unsigned exponent_bits = double_precision ? 11u : 8u;
    const int bias = double_precision ? 1023 : 127;
    const std::uint64_t fraction_mask = double_precision ? UINT64_C(0x000fffffffffffff)
                                                          : UINT64_C(0x007fffff);
    const std::uint64_t exponent_mask = (UINT64_C(1) << exponent_bits) - 1;
    const std::uint64_t format_mask = double_precision ? UINT64_MAX : UINT32_MAX;
    source_bits &= format_mask;
    const bool negative = (source_bits >> (fraction_bits + exponent_bits)) != 0;
    auto exponent = static_cast<unsigned>((source_bits >> fraction_bits) & exponent_mask);
    auto fraction = source_bits & fraction_mask;
    Mips32WordConversionResult result{};

    // Since Release 5, FS replaces arithmetic subnormal inputs by same-sign
    // zero and raises Inexact, including for floating-to-integer conversion.
    if (flush_inputs && exponent == 0 && fraction != 0) {
        exponent = 0;
        fraction = 0;
        result.exception_bits |= inexact;
    }

    const auto finish = [&]() {
        const auto enabled = static_cast<std::uint8_t>((fcsr & enable_mask) >> 7);
        result.exception_taken = (result.exception_bits & enabled) != 0;
        result.writes_destination = !result.exception_taken;
        result.fcsr_after = (fcsr & ~cause_mask) |
            (static_cast<std::uint32_t>(result.exception_bits) << 12);
        if (!result.exception_taken)
            result.fcsr_after = (result.fcsr_after & ~flag_mask) |
                ((fcsr & flag_mask) | (static_cast<std::uint32_t>(result.exception_bits) << 2));
    };

    if (exponent == exponent_mask) {
        // MIPS specifies the default positive maximum word for every
        // unrepresentable conversion, including infinities and NaNs.
        result.value_bits = UINT32_C(0x7fffffff);
        result.exception_bits |= invalid;
        finish();
        return result;
    }

    std::uint64_t significand = fraction;
    int binary_shift = 1 - bias - static_cast<int>(fraction_bits);
    if (exponent != 0) {
        significand |= UINT64_C(1) << fraction_bits;
        binary_shift = static_cast<int>(exponent) - bias - static_cast<int>(fraction_bits);
    }

    std::uint64_t magnitude = 0;
    bool discarded = false;
    bool too_large = false;
    if (significand != 0 && binary_shift >= 0) {
        if (binary_shift >= 64 || significand > (UINT64_MAX >> binary_shift)) {
            too_large = true;
        } else {
            magnitude = significand << binary_shift;
        }
    } else if (significand != 0) {
        const unsigned discarded_bits = static_cast<unsigned>(-binary_shift);
        std::uint64_t remainder = 0;
        bool increment = false;
        if (discarded_bits >= 64) {
            remainder = significand;
            if (rounding == Mips32WordRounding::toward_positive) increment = !negative;
            else if (rounding == Mips32WordRounding::toward_negative) increment = negative;
        } else {
            const std::uint64_t divisor = UINT64_C(1) << discarded_bits;
            magnitude = significand >> discarded_bits;
            remainder = significand & (divisor - 1);
            switch (rounding) {
            case Mips32WordRounding::nearest_even: {
                const auto half = divisor >> 1;
                increment = remainder > half || (remainder == half && (magnitude & 1));
                break;
            }
            case Mips32WordRounding::toward_zero: break;
            case Mips32WordRounding::toward_positive: increment = !negative && remainder != 0; break;
            case Mips32WordRounding::toward_negative: increment = negative && remainder != 0; break;
            }
        }
        discarded = remainder != 0;
        if (increment) ++magnitude;
    }

    const auto limit = negative ? (UINT64_C(1) << 31) : ((UINT64_C(1) << 31) - 1);
    if (too_large || magnitude > limit) {
        result.value_bits = UINT32_C(0x7fffffff);
        result.exception_bits |= invalid;
    } else {
        const auto word_magnitude = static_cast<std::uint32_t>(magnitude);
        result.value_bits = negative ? (0u - word_magnitude) : word_magnitude;
        if (discarded) result.exception_bits |= inexact;
    }
    finish();
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

std::optional<Mips32FpConditionalMoveResult>
evaluate_mips32_fp_conditional_move_instruction(const Instruction &instruction,
                                                std::uint64_t source_bits,
                                                std::uint64_t prior_destination_bits,
                                                bool fcc_value) noexcept {
    if (instruction.context.architecture != Architecture::mips32 ||
        instruction.context.mode != ExecutionMode::mips32 || instruction.opcode == Opcode::mips_movz_s ||
        instruction.opcode == Opcode::mips_movn_s || instruction.opcode == Opcode::mips_movz_d ||
        instruction.opcode == Opcode::mips_movn_d || instruction.flow != FlowKind::fallthrough ||
        instruction.delay_slots != 0 || instruction.memory_read || instruction.memory_write ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::read_write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read)
        return {};
    const bool single = instruction.opcode == Opcode::mips_movf_s || instruction.opcode == Opcode::mips_movt_s;
    const bool double_precision = instruction.opcode == Opcode::mips_movf_d || instruction.opcode == Opcode::mips_movt_d;
    if (!single && !double_precision) return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *source = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *condition = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto width = static_cast<std::uint16_t>(single ? 32 : 64);
    if (!destination || !source || !condition || destination->bank != RegisterBank::mips_fpr ||
        source->bank != RegisterBank::mips_fpr || destination->index > 31 || source->index > 31 ||
        destination->width != width || source->width != width || destination->high_byte || source->high_byte ||
        condition->bank != RegisterBank::mips_fcsr || condition->index < 1 || condition->index > 8 ||
        condition->width != 32 || condition->high_byte || instruction.condition != condition->index - 1)
        return {};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (instruction.register_reads.size() != 3 || instruction.register_writes.size() != 1 ||
        !has(instruction.register_reads, *destination) || !has(instruction.register_reads, *source) ||
        !has(instruction.register_reads, *condition) || !has(instruction.register_writes, *destination))
        return {};

    const bool move_if_true = instruction.opcode == Opcode::mips_movt_s || instruction.opcode == Opcode::mips_movt_d;
    const bool take_source = fcc_value == move_if_true;
    const auto mask = single ? UINT64_C(0xffffffff) : UINT64_MAX;
    return Mips32FpConditionalMoveResult{
        (take_source ? source_bits : prior_destination_bits) & mask, take_source};
}

} // namespace hexlab
