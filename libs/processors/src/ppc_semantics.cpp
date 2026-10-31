#include "hexlab/processors/ppc_semantics.hpp"

#include <algorithm>
#include <bit>
#include <cstdlib>

namespace hexlab {

std::optional<PpcBranchPredicateResult>
evaluate_ppc_branch_predicate(std::uint8_t bo, std::uint8_t bi, std::uint8_t cr_field,
                              std::uint64_t ctr, unsigned counter_width) noexcept {
    if (bo > 31 || bi > 31 || cr_field > 15 ||
        (counter_width != 32 && counter_width != 64))
        return {};
    const bool ignore_cr = (bo & 0x10u) != 0;
    const bool ignore_ctr = (bo & 0x04u) != 0;
    bool cr_satisfied = true;
    if (!ignore_cr) {
        const bool selected_bit = (cr_field & (1u << (3u - (bi & 3u)))) != 0;
        cr_satisfied = selected_bit == ((bo & 0x08u) != 0);
    }
    PpcBranchPredicateResult result;
    if (!ignore_ctr) {
        const auto mask = counter_width == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
        const auto decremented = ((ctr & mask) - UINT64_C(1)) & mask;
        result.ctr_after = decremented;
        const bool nonzero = decremented != 0;
        result.taken = cr_satisfied && (nonzero != ((bo & 0x02u) != 0));
    } else {
        result.taken = cr_satisfied;
    }
    return result;
}

std::optional<std::uint8_t> evaluate_ppc_compare_instruction(
    const Instruction &instruction, std::uint64_t lhs, std::uint64_t rhs,
    bool xer_so) noexcept {
    const bool ppc32 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc32;
    const bool ppc64 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc64;
    if ((!ppc32 && !ppc64) || instruction.flow != FlowKind::fallthrough || instruction.delay_slots != 0 ||
        instruction.memory_read || instruction.memory_write)
        return {};
    const bool immediate_form = instruction.opcode == Opcode::ppc_cmpi || instruction.opcode == Opcode::ppc_cmpli;
    const bool signed_compare = instruction.opcode == Opcode::ppc_cmp || instruction.opcode == Opcode::ppc_cmpi;
    if (!immediate_form && instruction.opcode != Opcode::ppc_cmp && instruction.opcode != Opcode::ppc_cmpl)
        return {};
    if (instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read)
        return {};
    const auto *field = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *left = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *right = immediate_form ? nullptr : std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto *immediate = immediate_form ? std::get_if<ImmediateOperand>(&instruction.operands[2]) : nullptr;
    if (!field || field->bank != RegisterBank::ppc_cr || field->index > 7 || field->width != 4 ||
        !left || left->bank != RegisterBank::ppc_gpr || left->index > 31 || left->high_byte ||
        (ppc32 && left->width != 32) || (ppc64 && left->width != 32 && left->width != 64) ||
        (right && (right->bank != RegisterBank::ppc_gpr || right->index > 31 || right->high_byte ||
                   right->width != left->width)) ||
        (immediate && (immediate->encoded_width != 16 || immediate->effective_width != left->width ||
                       immediate->is_signed != signed_compare)))
        return {};
    const RegisterOperand xer{RegisterBank::ppc_xer, 0, 32, false};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_writes, *field) || !has(instruction.register_reads, xer) ||
        !has(instruction.register_reads, *left) ||
        (right && !has(instruction.register_reads, *right)))
        return {};
    const unsigned width = left->width;
    const auto mask = width == 64 ? UINT64_MAX : UINT64_C(0xffffffff);
    lhs &= mask;
    if (right) rhs &= mask;
    else if (signed_compare) {
        const auto encoded = std::bit_cast<std::int64_t>(immediate->value);
        if (encoded < INT16_MIN || encoded > INT16_MAX) return {};
        rhs = static_cast<std::uint64_t>(encoded) & mask;
    } else {
        if (immediate->value > UINT16_MAX) return {};
        rhs = immediate->value;
    }
    bool less = false, greater = false;
    if (signed_compare) {
        const auto sign_extend = [width](std::uint64_t value) -> std::int64_t {
            if (width == 32) return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value));
            return std::bit_cast<std::int64_t>(value);
        };
        const auto signed_lhs = sign_extend(lhs), signed_rhs = sign_extend(rhs);
        less = signed_lhs < signed_rhs;
        greater = signed_lhs > signed_rhs;
    } else {
        less = lhs < rhs;
        greater = lhs > rhs;
    }
    return static_cast<std::uint8_t>((less ? 8u : greater ? 4u : 2u) | (xer_so ? 1u : 0u));
}

std::optional<PpcCrTransferResult> evaluate_ppc_cr_transfer_instruction(
    const Instruction &instruction, std::array<std::uint8_t, 8> cr_fields,
    std::uint32_t gpr_source) noexcept {
    const bool ppc32 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc32;
    const bool ppc64 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc64;
    if ((!ppc32 && !ppc64) || instruction.flow != FlowKind::fallthrough ||
        instruction.delay_slots != 0 || instruction.memory_read || instruction.memory_write ||
        instruction.operands.size() != 2 || instruction.access.size() != 2)
        return {};

    const auto mode_width = static_cast<std::uint16_t>(ppc64 ? 64 : 32);
    const auto is_gpr = [mode_width](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::ppc_gpr && reg->index <= 31 &&
               reg->width == mode_width && !reg->high_byte;
    };
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    PpcCrTransferResult result;
    result.cr_fields = cr_fields;

    if (instruction.opcode == Opcode::ppc_mfcr) {
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        const auto *source = std::get_if<RegisterOperand>(&instruction.operands[1]);
        if (!is_gpr(destination) || !source || source->bank != RegisterBank::ppc_cr ||
            source->index != 0 || source->width != 32 || source->high_byte ||
            instruction.access[0] != OperandAccess::write ||
            instruction.access[1] != OperandAccess::read)
            return {};
        for (unsigned field = 0; field < cr_fields.size(); ++field) {
            const RegisterOperand cr{RegisterBank::ppc_cr, static_cast<std::uint8_t>(field), 4, false};
            if (!has(instruction.register_reads, cr) || (cr_fields[field] & 0xf0u) != 0)
                return {};
            result.gpr_value |= static_cast<std::uint32_t>(cr_fields[field]) << ((7u - field) * 4u);
        }
        result.writes_gpr = true;
        if (!has(instruction.register_writes, *destination))
            return {};
        return result;
    }

    if (instruction.opcode == Opcode::ppc_mtcrf) {
        const auto *mask = std::get_if<ImmediateOperand>(&instruction.operands[0]);
        const auto *source = std::get_if<RegisterOperand>(&instruction.operands[1]);
        if (!mask || mask->encoded_width != 8 || mask->effective_width != 8 || mask->is_signed ||
            mask->value > UINT8_MAX || !is_gpr(source) ||
            instruction.access[0] != OperandAccess::read ||
            instruction.access[1] != OperandAccess::read ||
            !has(instruction.register_reads, *source))
            return {};
        const auto field_mask = static_cast<std::uint8_t>(mask->value);
        for (unsigned field = 0; field < cr_fields.size(); ++field) {
            const bool selected = (field_mask & (1u << (7u - field))) != 0;
            const RegisterOperand cr{RegisterBank::ppc_cr, static_cast<std::uint8_t>(field), 4, false};
            if (has(instruction.register_writes, cr) != selected ||
                (cr_fields[field] & 0xf0u) != 0)
                return {};
            if (selected) {
                cr_fields[field] = static_cast<std::uint8_t>((gpr_source >> ((7u - field) * 4u)) & 0xfu);
                result.cr_fields_written |= static_cast<std::uint8_t>(1u << (7u - field));
            }
        }
        result.cr_fields = cr_fields;
        return result;
    }
    return {};
}

std::optional<PpcMcrxrResult> evaluate_ppc_mcrxr_instruction(
    const Instruction &instruction, std::array<std::uint8_t, 8> cr_fields,
    std::uint32_t xer_value) noexcept {
    const bool ppc32 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc32;
    const bool ppc64 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc64;
    if ((!ppc32 && !ppc64) || instruction.opcode != Opcode::ppc_mcrxr ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots != 0 ||
        instruction.memory_read || instruction.memory_write || instruction.operands.size() != 2 ||
        instruction.access.size() != 2 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *source = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if (!destination || destination->bank != RegisterBank::ppc_cr || destination->index >= 8 ||
        destination->width != 4 || destination->high_byte || !source ||
        source->bank != RegisterBank::ppc_xer || source->index != 0 || source->width != 32 ||
        source->high_byte)
        return {};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (instruction.register_reads.size() != 1 || instruction.register_writes.size() != 2 ||
        !has(instruction.register_reads, *source) || !has(instruction.register_writes, *source) ||
        !has(instruction.register_writes, *destination))
        return {};
    for (const auto &reg : instruction.register_writes)
        if (reg.bank == RegisterBank::ppc_cr && reg != *destination)
            return {};
    for (const auto field : cr_fields)
        if ((field & 0xf0u) != 0)
            return {};

    constexpr std::uint32_t ca = UINT32_C(1) << 29;
    constexpr std::uint32_t ov = UINT32_C(1) << 30;
    constexpr std::uint32_t so = UINT32_C(1) << 31;
    const auto field = static_cast<std::uint8_t>(((xer_value & so) ? 8u : 0u) |
                                                 ((xer_value & ov) ? 4u : 0u) |
                                                 ((xer_value & ca) ? 2u : 0u));
    cr_fields[destination->index] = field;
    return PpcMcrxrResult{cr_fields,
                          xer_value & ~(ca | ov | so),
                          static_cast<std::uint8_t>(1u << (7u - destination->index))};
}

std::optional<PpcFpUnaryBitsResult> evaluate_ppc_fp_unary_bits_instruction(
    const Instruction &instruction, std::uint64_t source_bits,
    std::uint32_t fpscr_before) noexcept {
    const bool ppc_mode = instruction.context.architecture == Architecture::powerpc &&
        (instruction.context.mode == ExecutionMode::ppc32 ||
         instruction.context.mode == ExecutionMode::ppc64);
    if (!ppc_mode || (instruction.opcode != Opcode::ppc_fmr &&
                      instruction.opcode != Opcode::ppc_fneg &&
                      instruction.opcode != Opcode::ppc_fabs) ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots != 0 ||
        instruction.memory_read || instruction.memory_write || instruction.operands.size() != 2 ||
        instruction.access.size() != 2 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read)
        return {};

    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *source = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto valid_fpr = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::ppc_fpr && reg->index < 32 &&
               reg->width == 64 && !reg->high_byte;
    };
    if (!valid_fpr(destination) || !valid_fpr(source))
        return {};

    const RegisterOperand fpscr{RegisterBank::ppc_fpscr, 0, 32, false};
    const RegisterOperand cr1{RegisterBank::ppc_cr, 1, 4, false};
    const bool record = std::find(instruction.register_writes.begin(),
                                  instruction.register_writes.end(), cr1) !=
                        instruction.register_writes.end();
    const auto expected_effect_count = record ? 2u : 1u;
    if (instruction.register_reads.size() != expected_effect_count ||
        instruction.register_reads[0] != *source ||
        (record && instruction.register_reads[1] != fpscr) ||
        instruction.register_writes.size() != expected_effect_count ||
        instruction.register_writes[0] != *destination ||
        (record && instruction.register_writes[1] != cr1))
        return {};

    std::uint64_t value = source_bits;
    if (instruction.opcode == Opcode::ppc_fneg)
        value ^= UINT64_C(1) << 63;
    else if (instruction.opcode == Opcode::ppc_fabs)
        value &= ~(UINT64_C(1) << 63);
    std::optional<std::uint8_t> cr1_value;
    if (record)
        cr1_value = static_cast<std::uint8_t>((fpscr_before >> 28) & 0xfu);
    return PpcFpUnaryBitsResult{value, cr1_value};
}

std::optional<PpcFpArithmeticResult> evaluate_ppc_fp_arithmetic_instruction(
    const Instruction &instruction, std::uint64_t lhs_fpr_bits,
    std::uint64_t rhs_fpr_bits, std::uint32_t fpscr_before) noexcept {
    if (instruction.context.architecture != Architecture::powerpc ||
        (instruction.context.mode != ExecutionMode::ppc32 &&
         instruction.context.mode != ExecutionMode::ppc64) ||
        (instruction.opcode != Opcode::ppc_fadds && instruction.opcode != Opcode::ppc_fsubs &&
         instruction.opcode != Opcode::ppc_fmuls) || instruction.flow != FlowKind::fallthrough ||
        instruction.delay_slots != 0 || instruction.memory_read || instruction.memory_write ||
        instruction.operands.size() != 3 ||
        instruction.access != std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read,
                                                         OperandAccess::read} ||
        (fpscr_before & 0x4u) != 0) return {};

    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *left = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *right = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto valid_fpr = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::ppc_fpr && reg->index < 32 &&
            reg->width == 32 && !reg->high_byte;
    };
    if (!valid_fpr(destination) || !valid_fpr(left) || !valid_fpr(right)) return {};

    const RegisterOperand fpscr{RegisterBank::ppc_fpscr, 0, 32, false};
    const RegisterOperand cr1{RegisterBank::ppc_cr, 1, 4, false};
    const auto expected_reads = std::vector<RegisterOperand>{*left, *right, fpscr};
    const bool record = instruction.register_writes.size() == 3 &&
                        instruction.register_writes.back() == cr1;
    const auto expected_writes = record
        ? std::vector<RegisterOperand>{*destination, fpscr, cr1}
        : std::vector<RegisterOperand>{*destination, fpscr};
    if (instruction.register_reads != expected_reads || instruction.register_writes != expected_writes)
        return {};

    const auto as_single = [](std::uint64_t bits) -> std::optional<std::uint32_t> {
        const auto exponent = static_cast<unsigned>((bits >> 52) & 0x7ffu);
        const auto fraction = bits & UINT64_C(0x000fffffffffffff);
        const auto sign = (bits >> 32) & UINT64_C(0x80000000);
        if (exponent == 0x7ffu) return {};
        if (exponent == 0) {
            if (fraction != 0) return {};
            return static_cast<std::uint32_t>(sign);
        }
        const int unbiased = static_cast<int>(exponent) - 1023;
        if (unbiased < -126 || unbiased > 127 || (fraction & ((UINT64_C(1) << 29) - 1)) != 0)
            return {};
        return static_cast<std::uint32_t>(sign) |
            (static_cast<std::uint32_t>(unbiased + 127) << 23) |
            static_cast<std::uint32_t>(fraction >> 29);
    };
    const auto lhs_bits = as_single(lhs_fpr_bits);
    const auto rhs_bits = as_single(rhs_fpr_bits);
    if (!lhs_bits || !rhs_bits) return {};

    const auto top_exponent = [](std::uint32_t bits) {
        const auto exponent = static_cast<int>((bits >> 23) & 0xffu);
        return exponent == 0 ? -10000 : exponent - 127;
    };
    if (instruction.opcode != Opcode::ppc_fmuls && (*lhs_bits & 0x7fffffffu) != 0 &&
        (*rhs_bits & 0x7fffffffu) != 0 &&
        std::abs(top_exponent(*lhs_bits) - top_exponent(*rhs_bits)) > 29) return {};

    const auto lhs_double = std::bit_cast<double>(lhs_fpr_bits);
    const auto rhs_double = std::bit_cast<double>(rhs_fpr_bits);
    double exact = instruction.opcode == Opcode::ppc_fmuls
        ? lhs_double * rhs_double
        : instruction.opcode == Opcode::ppc_fsubs ? lhs_double - rhs_double : lhs_double + rhs_double;
    const bool zero_operands = (*lhs_bits & 0x7fffffffu) == 0 && (*rhs_bits & 0x7fffffffu) == 0;
    std::uint32_t result_bits = 0;
    if (exact == 0.0) {
        const bool lhs_negative = (*lhs_bits >> 31) != 0;
        const bool rhs_negative = ((*rhs_bits >> 31) != 0) ^ (instruction.opcode == Opcode::ppc_fsubs);
        const bool negative = instruction.opcode == Opcode::ppc_fmuls
            ? lhs_negative ^ rhs_negative
            : zero_operands && lhs_negative == rhs_negative ? lhs_negative : (fpscr_before & 3u) == 3u;
        result_bits = negative ? 0x80000000u : 0;
    } else {
        const auto exact_bits = std::bit_cast<std::uint64_t>(exact);
        const auto exponent = static_cast<unsigned>((exact_bits >> 52) & 0x7ffu);
        const auto fraction = exact_bits & UINT64_C(0x000fffffffffffff);
        const int unbiased = static_cast<int>(exponent) - 1023;
        if (exponent == 0 || exponent == 0x7ffu || unbiased < -126 || unbiased > 127 ||
            (fraction & ((UINT64_C(1) << 29) - 1)) != 0) return {};
        result_bits = static_cast<std::uint32_t>((exact_bits >> 32) & 0x80000000u) |
            (static_cast<std::uint32_t>(unbiased + 127) << 23) |
            static_cast<std::uint32_t>(fraction >> 29);
    }

    const auto sign64 = static_cast<std::uint64_t>(result_bits & 0x80000000u) << 32;
    const auto result_exponent = (result_bits >> 23) & 0xffu;
    const auto result_fraction = result_bits & 0x007fffffu;
    const std::uint64_t fpr_bits = result_exponent == 0
        ? sign64
        : sign64 | (static_cast<std::uint64_t>(result_exponent - 127 + 1023) << 52) |
              (static_cast<std::uint64_t>(result_fraction) << 29);
    const bool negative = (result_bits >> 31) != 0;
    const auto fprf = result_exponent == 0 ? (negative ? 0x12u : 0x02u)
                                           : (negative ? 0x08u : 0x04u);
    constexpr std::uint32_t fprf_round_mask = 0x0007f000u;
    const auto fpscr_after = (fpscr_before & ~fprf_round_mask) | (fprf << 12);
    return PpcFpArithmeticResult{fpr_bits, fpscr_after,
                                 record ? std::optional<std::uint8_t>{static_cast<std::uint8_t>(fpscr_after >> 28)}
                                        : std::nullopt};
}

std::optional<PpcVectorBits> evaluate_ppc_vmx_integer_operation(Opcode opcode,
                                                               const PpcVectorBits &va,
                                                               const PpcVectorBits &vb) noexcept {
    switch (opcode) {
    case Opcode::ppc_vand:
    case Opcode::ppc_vandc:
    case Opcode::ppc_vor:
    case Opcode::ppc_vxor:
    case Opcode::ppc_vnor: {
        PpcVectorBits result{};
        for (std::size_t i = 0; i < result.size(); ++i) {
            switch (opcode) {
            case Opcode::ppc_vand: result[i] = va[i] & vb[i]; break;
            case Opcode::ppc_vandc: result[i] = va[i] & static_cast<std::uint8_t>(~vb[i]); break;
            case Opcode::ppc_vor: result[i] = va[i] | vb[i]; break;
            case Opcode::ppc_vxor: result[i] = va[i] ^ vb[i]; break;
            case Opcode::ppc_vnor: result[i] = static_cast<std::uint8_t>(~(va[i] | vb[i])); break;
            default: break;
            }
        }
        return result;
    }
    default: break;
    }

    unsigned lane_bits = 0;
    bool subtract = false;
    switch (opcode) {
    case Opcode::ppc_vaddubm: lane_bits = 8; break;
    case Opcode::ppc_vadduhm: lane_bits = 16; break;
    case Opcode::ppc_vadduwm: lane_bits = 32; break;
    case Opcode::ppc_vsububm: lane_bits = 8; subtract = true; break;
    case Opcode::ppc_vsubuhm: lane_bits = 16; subtract = true; break;
    case Opcode::ppc_vsubuwm: lane_bits = 32; subtract = true; break;
    default: return {};
    }

    PpcVectorBits result{};
    const unsigned lane_bytes = lane_bits / 8;
    const std::uint64_t mask = (UINT64_C(1) << lane_bits) - 1;
    for (unsigned offset = 0; offset < result.size(); offset += lane_bytes) {
        std::uint64_t a = 0, b = 0;
        for (unsigned byte = 0; byte < lane_bytes; ++byte) {
            a = (a << 8) | va[offset + byte];
            b = (b << 8) | vb[offset + byte];
        }
        const auto lane = (subtract ? a - b : a + b) & mask;
        for (unsigned byte = 0; byte < lane_bytes; ++byte)
            result[offset + lane_bytes - 1 - byte] = static_cast<std::uint8_t>(lane >> (byte * 8));
    }
    return result;
}

std::optional<std::uint64_t>
evaluate_ppc_popcntb(Opcode opcode, std::uint64_t value, unsigned register_width) noexcept {
    if (opcode != Opcode::ppc_popcntb || (register_width != 32 && register_width != 64))
        return {};
    const unsigned bytes = register_width / 8;
    std::uint64_t result = 0;
    for (unsigned byte = 0; byte < bytes; ++byte) {
        const auto input = static_cast<std::uint8_t>(value >> (byte * 8));
        result |= static_cast<std::uint64_t>(std::popcount(input)) << (byte * 8);
    }
    if (register_width == 32) result &= UINT32_MAX;
    return result;
}

std::optional<std::uint64_t>
evaluate_ppc_popcnt_word_operation(Opcode opcode, std::uint64_t value,
                                   unsigned register_width) noexcept {
    if ((opcode != Opcode::ppc_popcntw && opcode != Opcode::ppc_popcntd) ||
        (register_width != 32 && register_width != 64) ||
        (opcode == Opcode::ppc_popcntd && register_width != 64))
        return {};
    if (opcode == Opcode::ppc_popcntw)
        return static_cast<std::uint64_t>(std::popcount(static_cast<std::uint32_t>(value)));
    return static_cast<std::uint64_t>(std::popcount(value));
}

std::optional<std::uint64_t>
evaluate_ppc_popcnt_word_instruction(const Instruction &instruction,
                                     std::uint64_t source) noexcept {
    const bool ppc32 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc32;
    const bool ppc64 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc64;
    if ((!ppc32 && !ppc64) ||
        (instruction.opcode != Opcode::ppc_popcntw && instruction.opcode != Opcode::ppc_popcntd) ||
        instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.memory_read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const unsigned register_width = ppc32 ? 32u : 64u;
    const unsigned source_width = instruction.opcode == Opcode::ppc_popcntw ? 32u : 64u;
    if (!destination || !input || destination->bank != RegisterBank::ppc_gpr ||
        input->bank != RegisterBank::ppc_gpr || destination->width != register_width ||
        input->width != source_width || destination->high_byte || input->high_byte)
        return {};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_writes, *destination) || !has(instruction.register_reads, *input))
        return {};
    return evaluate_ppc_popcnt_word_operation(instruction.opcode, source, register_width);
}

std::optional<std::uint64_t>
evaluate_ppc_isel_instruction(const Instruction &instruction,
                              std::uint64_t ra_value, std::uint64_t rb_value,
                              bool condition_bit) noexcept {
    const bool ppc32 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc32;
    const bool ppc64 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc64;
    if ((!ppc32 && !ppc64) || instruction.opcode != Opcode::ppc_isel ||
        instruction.operands.size() != 4 || instruction.access.size() != 4 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read || instruction.access[3] != OperandAccess::read ||
        instruction.memory_read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *ra = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *rb = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto *condition = std::get_if<RegisterOperand>(&instruction.operands[3]);
    const auto width = static_cast<std::uint16_t>(ppc32 ? 32 : 64);
    if (!destination || !ra || !rb || !condition || destination->bank != RegisterBank::ppc_gpr ||
        ra->bank != RegisterBank::ppc_gpr || rb->bank != RegisterBank::ppc_gpr ||
        destination->width != width || ra->width != width || rb->width != width ||
        condition->bank != RegisterBank::ppc_crbit || condition->width != 1 ||
        destination->high_byte || ra->high_byte || rb->high_byte || condition->index >= 32)
        return {};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_writes, *destination) || !has(instruction.register_reads, *ra) ||
        !has(instruction.register_reads, *rb) || !has(instruction.register_reads, *condition))
        return {};
    const auto mask = ppc32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    return (condition_bit ? ra_value : rb_value) & mask;
}

std::optional<bool>
evaluate_ppc_cr_logical_instruction(const Instruction &instruction,
                                    bool ba, bool bb) noexcept {
    if (instruction.context.architecture != Architecture::powerpc ||
        (instruction.context.mode != ExecutionMode::ppc32 && instruction.context.mode != ExecutionMode::ppc64) ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read || instruction.memory_read || instruction.memory_write)
        return {};
    switch (instruction.opcode) {
    case Opcode::ppc_crand: case Opcode::ppc_crandc: case Opcode::ppc_creqv: case Opcode::ppc_crnand:
    case Opcode::ppc_crnor: case Opcode::ppc_cror: case Opcode::ppc_crorc: case Opcode::ppc_crxor:
        break;
    default: return {};
    }
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *left = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *right = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto valid_bit = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::ppc_crbit && reg->width == 1 &&
               reg->index < 32 && !reg->high_byte;
    };
    if (!valid_bit(destination) || !valid_bit(left) || !valid_bit(right)) return {};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_writes, *destination) || !has(instruction.register_reads, *left) ||
        !has(instruction.register_reads, *right))
        return {};
    switch (instruction.opcode) {
    case Opcode::ppc_crand: return ba && bb;
    case Opcode::ppc_crandc: return ba && !bb;
    case Opcode::ppc_creqv: return ba == bb;
    case Opcode::ppc_crnand: return !(ba && bb);
    case Opcode::ppc_crnor: return !(ba || bb);
    case Opcode::ppc_cror: return ba || bb;
    case Opcode::ppc_crorc: return ba || !bb;
    case Opcode::ppc_crxor: return ba != bb;
    default: return {};
    }
}

std::optional<std::uint64_t>
evaluate_ppc_count_leading_zeros(Opcode opcode, std::uint64_t value, unsigned register_width) noexcept {
    const bool word = opcode == Opcode::ppc_cntlzw || opcode == Opcode::ppc_cntlzw_dot;
    const bool doubleword = opcode == Opcode::ppc_cntlzd || opcode == Opcode::ppc_cntlzd_dot;
    if ((!word && !doubleword) || (register_width != 32 && register_width != 64) ||
        (doubleword && register_width != 64))
        return {};
    if (word)
        return static_cast<std::uint64_t>(std::countl_zero(static_cast<std::uint32_t>(value)));
    return static_cast<std::uint64_t>(std::countl_zero(value));
}

std::optional<PpcSignExtendResult>
evaluate_ppc_sign_extend_instruction(const Instruction &instruction,
                                     std::uint64_t source, bool xer_so) noexcept {
    const bool ppc32 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc32;
    const bool ppc64 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc64;
    if (!ppc32 && !ppc64) return {};
    const bool record = instruction.opcode == Opcode::ppc_extsb_dot ||
                        instruction.opcode == Opcode::ppc_extsh_dot ||
                        instruction.opcode == Opcode::ppc_extsw_dot;
    unsigned source_width = 0;
    switch (instruction.opcode) {
    case Opcode::ppc_extsb: case Opcode::ppc_extsb_dot: source_width = 8; break;
    case Opcode::ppc_extsh: case Opcode::ppc_extsh_dot: source_width = 16; break;
    case Opcode::ppc_extsw: case Opcode::ppc_extsw_dot:
        if (!ppc64) return {};
        source_width = 32;
        break;
    default: return {};
    }
    const auto width = static_cast<std::uint16_t>(ppc32 ? 32 : 64);
    if (instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.memory_read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if (!destination || !input || destination->bank != RegisterBank::ppc_gpr ||
        input->bank != RegisterBank::ppc_gpr || destination->width != width || input->width != width ||
        destination->high_byte || input->high_byte)
        return {};
    const RegisterOperand source_effect{RegisterBank::ppc_gpr, input->index,
                                        static_cast<std::uint16_t>(source_width), false};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_reads, source_effect) || !has(instruction.register_writes, *destination))
        return {};
    const RegisterOperand xer{RegisterBank::ppc_xer, 0, 32, false};
    const RegisterOperand cr0{RegisterBank::ppc_cr, 0, 4, false};
    if (record && (!has(instruction.register_reads, xer) || !has(instruction.register_writes, cr0)))
        return {};

    std::int64_t signed_value = 0;
    if (source_width == 8)
        signed_value = std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(source));
    else if (source_width == 16)
        signed_value = std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(source));
    else
        signed_value = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(source));
    const auto mask = ppc32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    const auto value = static_cast<std::uint64_t>(signed_value) & mask;
    std::optional<std::uint8_t> cr_value;
    if (record) {
        const auto relation = signed_value < 0 ? 0x8u : signed_value > 0 ? 0x4u : 0x2u;
        cr_value = static_cast<std::uint8_t>(relation | (xer_so ? 1u : 0u));
    }
    return PpcSignExtendResult{value, cr_value};
}

std::optional<PpcCarryArithmeticResult>
evaluate_ppc_addze_addme_instruction(const Instruction &instruction,
                                    std::uint64_t source, std::uint32_t xer) noexcept {
    const bool ppc32 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc32;
    const bool ppc64 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc64;
    if (!ppc32 && !ppc64) return {};
    const bool add_minus_one = instruction.opcode == Opcode::ppc_addme ||
                               instruction.opcode == Opcode::ppc_addme_dot;
    const bool add_zero = instruction.opcode == Opcode::ppc_addze ||
                          instruction.opcode == Opcode::ppc_addze_dot;
    const bool record = instruction.opcode == Opcode::ppc_addme_dot ||
                        instruction.opcode == Opcode::ppc_addze_dot;
    if ((!add_zero && !add_minus_one) || instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.memory_read || instruction.memory_write)
        return {};
    const auto width = static_cast<std::uint16_t>(ppc32 ? 32 : 64);
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if (!destination || !input || destination->bank != RegisterBank::ppc_gpr ||
        input->bank != RegisterBank::ppc_gpr || destination->width != width || input->width != width ||
        destination->high_byte || input->high_byte)
        return {};
    const RegisterOperand xer_reg{RegisterBank::ppc_xer, 0, 32, false};
    const RegisterOperand cr0_reg{RegisterBank::ppc_cr, 0, 4, false};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_reads, *input) || !has(instruction.register_reads, xer_reg) ||
        !has(instruction.register_writes, *destination) || !has(instruction.register_writes, xer_reg) ||
        (record && !has(instruction.register_writes, cr0_reg)))
        return {};

    constexpr std::uint32_t xer_so = UINT32_C(1) << 31;
    constexpr std::uint32_t xer_ca = UINT32_C(1) << 29;
    const bool carry_in = (xer & xer_ca) != 0;
    const auto mask = ppc32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    source &= mask;
    std::uint64_t value = 0;
    bool carry_out = false;
    if (add_zero) {
        value = (source + static_cast<std::uint64_t>(carry_in)) & mask;
        carry_out = ppc32 ? (static_cast<std::uint64_t>(source) + carry_in > mask)
                          : (carry_in && source == UINT64_MAX);
    } else {
        value = (source + static_cast<std::uint64_t>(carry_in) - 1) & mask;
        carry_out = carry_in || source != 0;
    }
    const auto xer_after = (xer & ~xer_ca) | (carry_out ? xer_ca : 0u);
    std::optional<std::uint8_t> cr0;
    if (record) {
        const auto signed_value = ppc32
            ? static_cast<std::int64_t>(std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value)))
            : std::bit_cast<std::int64_t>(value);
        const auto relation = signed_value < 0 ? 0x8u : signed_value > 0 ? 0x4u : 0x2u;
        cr0 = static_cast<std::uint8_t>(relation | ((xer & xer_so) ? 1u : 0u));
    }
    return PpcCarryArithmeticResult{value, xer_after, cr0};
}

std::optional<PpcCarryArithmeticResult>
evaluate_ppc_carry_binary_instruction(const Instruction &instruction,
                                      std::uint64_t source_a,
                                      std::uint64_t source_b,
                                      std::uint32_t xer) noexcept {
    const bool ppc32 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc32;
    const bool ppc64 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc64;
    if ((!ppc32 && !ppc64) || instruction.flow != FlowKind::fallthrough ||
        instruction.length != 4 || instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read || instruction.memory_read || instruction.memory_write)
        return {};
    bool uses_carry_in = false;
    bool subtract = false;
    switch (instruction.opcode) {
    case Opcode::ppc_addc: break;
    case Opcode::ppc_adde: uses_carry_in = true; break;
    case Opcode::ppc_subfc: subtract = true; break;
    case Opcode::ppc_subfe: uses_carry_in = true; subtract = true; break;
    default: return {};
    }
    const auto width = static_cast<std::uint16_t>(ppc32 ? 32 : 64);
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input_a = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *input_b = std::get_if<RegisterOperand>(&instruction.operands[2]);
    if (!destination || !input_a || !input_b || destination->bank != RegisterBank::ppc_gpr ||
        input_a->bank != RegisterBank::ppc_gpr || input_b->bank != RegisterBank::ppc_gpr ||
        destination->width != width || input_a->width != width || input_b->width != width ||
        destination->index >= 32 || input_a->index >= 32 || input_b->index >= 32 ||
        destination->high_byte || input_a->high_byte || input_b->high_byte)
        return {};
    const RegisterOperand xer_reg{RegisterBank::ppc_xer, 0, 32, false};
    const RegisterOperand cr0_reg{RegisterBank::ppc_cr, 0, 4, false};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    const bool record = has(instruction.register_writes, cr0_reg);
    if (!has(instruction.register_reads, *input_a) || !has(instruction.register_reads, *input_b) ||
        has(instruction.register_reads, xer_reg) != uses_carry_in ||
        !has(instruction.register_writes, *destination) || !has(instruction.register_writes, xer_reg))
        return {};

    constexpr std::uint32_t xer_so = UINT32_C(1) << 31;
    constexpr std::uint32_t xer_ca = UINT32_C(1) << 29;
    const bool carry_in = (xer & xer_ca) != 0;
    const auto mask = ppc32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    source_a &= mask;
    source_b &= mask;
    std::uint64_t value = 0;
    bool carry_out = false;
    if (!subtract) {
        const auto partial = source_a + source_b;
        const bool carry_first = ppc32 ? partial > mask : partial < source_a;
        value = partial + static_cast<std::uint64_t>(carry_in);
        const bool carry_second = carry_in && (ppc32 ? value > mask : value < partial);
        carry_out = carry_first || carry_second;
    } else {
        // SUBFC computes RB - RA and sets CA when the subtraction borrows
        // nowhere. SUBFE subtracts (1-CA) as the incoming borrow.
        const bool borrow = uses_carry_in && !carry_in;
        carry_out = borrow ? source_b > source_a : source_b >= source_a;
        value = source_b - source_a - static_cast<std::uint64_t>(borrow);
    }
    value &= mask;
    const auto xer_after = (xer & ~xer_ca) | (carry_out ? xer_ca : 0u);
    std::optional<std::uint8_t> cr0;
    if (record) {
        const auto signed_value = ppc32
            ? static_cast<std::int64_t>(std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value)))
            : std::bit_cast<std::int64_t>(value);
        const auto relation = signed_value < 0 ? 0x8u : signed_value > 0 ? 0x4u : 0x2u;
        cr0 = static_cast<std::uint8_t>(relation | ((xer & xer_so) ? 1u : 0u));
    }
    return PpcCarryArithmeticResult{value, xer_after, cr0};
}

std::optional<PpcNegateResult>
evaluate_ppc_negate_instruction(const Instruction &instruction,
                                std::uint64_t source, bool xer_so) noexcept {
    const bool ppc32 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc32;
    const bool ppc64 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc64;
    if ((!ppc32 && !ppc64) || instruction.opcode != Opcode::ppc_neg ||
        instruction.flow != FlowKind::fallthrough ||
        instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.memory_read || instruction.memory_write)
        return {};
    const auto width = static_cast<std::uint16_t>(ppc32 ? 32 : 64);
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if (!destination || !input || destination->bank != RegisterBank::ppc_gpr ||
        input->bank != RegisterBank::ppc_gpr || destination->width != width || input->width != width ||
        destination->index > 31 || input->index > 31 || destination->high_byte || input->high_byte)
        return {};
    const RegisterOperand cr0_reg{RegisterBank::ppc_cr, 0, 4, false};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    const bool record = has(instruction.register_writes, cr0_reg);
    if (!has(instruction.register_reads, *input) || !has(instruction.register_writes, *destination))
        return {};
    const auto mask = ppc32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    const auto value = (UINT64_C(0) - (source & mask)) & mask;
    std::optional<std::uint8_t> cr0;
    if (record) {
        const auto signed_value = ppc32
            ? static_cast<std::int64_t>(std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value)))
            : std::bit_cast<std::int64_t>(value);
        const auto relation = signed_value < 0 ? 0x8u : signed_value > 0 ? 0x4u : 0x2u;
        cr0 = static_cast<std::uint8_t>(relation | (xer_so ? 1u : 0u));
    }
    return PpcNegateResult{value, cr0};
}

std::optional<PpcRotateMaskResult>
evaluate_ppc_rotate_mask_instruction(const Instruction &instruction,
                                     std::uint64_t source,
                                     std::optional<std::uint64_t> variable_shift_value,
                                     std::uint64_t prior_destination,
                                     bool xer_so) noexcept {
    const bool ppc32 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc32;
    const bool ppc64 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc64;
    if (!ppc32 && !ppc64) return {};
    const bool insert = instruction.opcode == Opcode::ppc_rlwimi ||
                        instruction.opcode == Opcode::ppc_rlwimi_dot;
    const bool variable = instruction.opcode == Opcode::ppc_rlwnm ||
                          instruction.opcode == Opcode::ppc_rlwnm_dot;
    const bool record = instruction.opcode == Opcode::ppc_rlwimi_dot ||
                        instruction.opcode == Opcode::ppc_rlwinm_dot ||
                        instruction.opcode == Opcode::ppc_rlwnm_dot;
    const bool supported = insert || variable || instruction.opcode == Opcode::ppc_rlwinm ||
                           instruction.opcode == Opcode::ppc_rlwinm_dot;
    if (!supported || (variable != variable_shift_value.has_value()) ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots != 0 ||
        instruction.memory_read || instruction.memory_write || instruction.operands.size() != 5 ||
        instruction.access.size() != 5 ||
        instruction.access[0] != (insert ? OperandAccess::read_write : OperandAccess::write) ||
        instruction.access[1] != OperandAccess::read || instruction.access[2] != OperandAccess::read ||
        instruction.access[3] != OperandAccess::read || instruction.access[4] != OperandAccess::read)
        return {};

    const auto width = static_cast<std::uint16_t>(ppc32 ? 32 : 64);
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto valid_gpr = [width](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::ppc_gpr && reg->index <= 31 &&
               reg->width == width && !reg->high_byte;
    };
    if (!valid_gpr(destination) || !valid_gpr(input)) return {};
    const auto *shift_register = variable ? std::get_if<RegisterOperand>(&instruction.operands[2]) : nullptr;
    const auto *shift_immediate = variable ? nullptr : std::get_if<ImmediateOperand>(&instruction.operands[2]);
    const auto *mb = std::get_if<ImmediateOperand>(&instruction.operands[3]);
    const auto *me = std::get_if<ImmediateOperand>(&instruction.operands[4]);
    if ((variable && !valid_gpr(shift_register)) ||
        (!variable && (!shift_immediate || shift_immediate->encoded_width != 5 ||
                       shift_immediate->effective_width != 5 || shift_immediate->is_signed ||
                       shift_immediate->value > 31)) ||
        !mb || !me || mb->encoded_width != 5 || mb->effective_width != 5 || mb->is_signed ||
        mb->value > 31 || me->encoded_width != 5 || me->effective_width != 5 || me->is_signed ||
        me->value > 31)
        return {};

    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_reads, *input) ||
        !has(instruction.register_writes, *destination) ||
        (insert && !has(instruction.register_reads, *destination)) ||
        (variable && !has(instruction.register_reads, *shift_register)))
        return {};
    const RegisterOperand cr0{RegisterBank::ppc_cr, 0, 4, false};
    if (record != has(instruction.register_writes, cr0)) return {};

    const unsigned shift = variable ? static_cast<unsigned>(*variable_shift_value & 31u)
                                    : static_cast<unsigned>(shift_immediate->value);
    std::uint32_t mask = 0;
    for (unsigned bit = static_cast<unsigned>(mb->value);;) {
        mask |= UINT32_C(1) << (31u - bit);
        if (bit == me->value) break;
        bit = (bit + 1u) & 31u;
    }
    const auto rotated = std::rotl(static_cast<std::uint32_t>(source), static_cast<int>(shift));
    const auto low_result = insert
        ? (static_cast<std::uint32_t>(prior_destination) & ~mask) | (rotated & mask)
        : rotated & mask;
    std::uint64_t value = low_result;
    if (insert && ppc64)
        value |= prior_destination & UINT64_C(0xffffffff00000000);

    std::optional<std::uint8_t> cr_value;
    if (record) {
        const auto signed_value = ppc32
            ? static_cast<std::int64_t>(std::bit_cast<std::int32_t>(low_result))
            : std::bit_cast<std::int64_t>(value);
        const auto relation = signed_value < 0 ? 0x8u : signed_value > 0 ? 0x4u : 0x2u;
        cr_value = static_cast<std::uint8_t>(relation | (xer_so ? 1u : 0u));
    }
    return PpcRotateMaskResult{value, cr_value};
}

std::optional<PpcCarryArithmeticResult>
evaluate_ppc_immediate_carry_instruction(const Instruction &instruction,
                                         std::uint64_t source, std::uint32_t xer) noexcept {
    const bool ppc32 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc32;
    const bool ppc64 = instruction.context.architecture == Architecture::powerpc &&
                       instruction.context.mode == ExecutionMode::ppc64;
    if (!ppc32 && !ppc64) return {};
    const bool add = instruction.opcode == Opcode::ppc_addic || instruction.opcode == Opcode::ppc_addic_dot;
    const bool subtract = instruction.opcode == Opcode::ppc_subfic;
    const bool record = instruction.opcode == Opcode::ppc_addic_dot;
    if ((!add && !subtract) || instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read || instruction.memory_read || instruction.memory_write)
        return {};
    const auto width = static_cast<std::uint16_t>(ppc32 ? 32 : 64);
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
    if (!destination || !input || !immediate || destination->bank != RegisterBank::ppc_gpr ||
        input->bank != RegisterBank::ppc_gpr || destination->width != width || input->width != width ||
        destination->high_byte || input->high_byte || immediate->encoded_width != 16 ||
        immediate->effective_width != width || !immediate->is_signed)
        return {};
    const auto signed_immediate = std::bit_cast<std::int64_t>(immediate->value);
    if (signed_immediate < INT16_MIN || signed_immediate > INT16_MAX) return {};
    const RegisterOperand xer_reg{RegisterBank::ppc_xer, 0, 32, false};
    const RegisterOperand cr0_reg{RegisterBank::ppc_cr, 0, 4, false};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_reads, *input) || !has(instruction.register_reads, xer_reg) ||
        !has(instruction.register_writes, *destination) || !has(instruction.register_writes, xer_reg) ||
        (record && !has(instruction.register_writes, cr0_reg)))
        return {};

    constexpr std::uint32_t xer_so = UINT32_C(1) << 31;
    constexpr std::uint32_t xer_ca = UINT32_C(1) << 29;
    const auto mask = ppc32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    source &= mask;
    const auto immediate_bits = static_cast<std::uint64_t>(signed_immediate) & mask;
    std::uint64_t value = 0;
    bool carry_out = false;
    if (add) {
        value = (source + immediate_bits) & mask;
        carry_out = immediate_bits > mask - source;
    } else {
        value = (immediate_bits - source) & mask;
        carry_out = immediate_bits >= source;
    }
    const auto xer_after = (xer & ~xer_ca) | (carry_out ? xer_ca : 0u);
    std::optional<std::uint8_t> cr0;
    if (record) {
        const auto signed_value = ppc32
            ? static_cast<std::int64_t>(std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value)))
            : std::bit_cast<std::int64_t>(value);
        const auto relation = signed_value < 0 ? 0x8u : signed_value > 0 ? 0x4u : 0x2u;
        cr0 = static_cast<std::uint8_t>(relation | ((xer & xer_so) ? 1u : 0u));
    }
    return PpcCarryArithmeticResult{value, xer_after, cr0};
}

} // namespace hexlab
