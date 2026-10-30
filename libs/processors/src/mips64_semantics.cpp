#include "hexlab/processors/mips64_semantics.hpp"

#include <bit>
#include <algorithm>
#include <cstdint>
#include <limits>

namespace hexlab {
namespace {
bool is_word(Mips64MergeOperation operation) noexcept {
    return operation == Mips64MergeOperation::load_left_word ||
           operation == Mips64MergeOperation::load_right_word ||
           operation == Mips64MergeOperation::store_left_word ||
           operation == Mips64MergeOperation::store_right_word;
}

bool is_load(Mips64MergeOperation operation) noexcept {
    return operation == Mips64MergeOperation::load_left_word ||
           operation == Mips64MergeOperation::load_right_word ||
           operation == Mips64MergeOperation::load_left_doubleword ||
           operation == Mips64MergeOperation::load_right_doubleword;
}

bool is_left(Mips64MergeOperation operation) noexcept {
    return operation == Mips64MergeOperation::load_left_word ||
           operation == Mips64MergeOperation::store_left_word ||
           operation == Mips64MergeOperation::load_left_doubleword ||
           operation == Mips64MergeOperation::store_left_doubleword;
}

unsigned shift_for(unsigned address_lane, unsigned byte_count, ByteOrder order) noexcept {
    return (order == ByteOrder::little ? address_lane : byte_count - 1 - address_lane) * 8;
}

Mips64MultiplyResult multiply_u64(std::uint64_t lhs, std::uint64_t rhs) noexcept {
    const std::uint64_t lhs_low = static_cast<std::uint32_t>(lhs);
    const std::uint64_t lhs_high = lhs >> 32;
    const std::uint64_t rhs_low = static_cast<std::uint32_t>(rhs);
    const std::uint64_t rhs_high = rhs >> 32;
    const auto low_product = lhs_low * rhs_low;
    const auto cross_a = lhs_low * rhs_high;
    const auto cross_b = lhs_high * rhs_low;
    const auto high_product = lhs_high * rhs_high;

    auto low = low_product;
    const auto add_a = cross_a << 32;
    low += add_a;
    const auto carry_a = low < add_a;
    const auto add_b = cross_b << 32;
    const auto before_b = low;
    low += add_b;
    const auto carry_b = low < before_b;
    const auto high = high_product + (cross_a >> 32) + (cross_b >> 32) + carry_a + carry_b;
    return {high, low};
}

bool decoded_mips64_hilo_binary(const Instruction &instruction, bool reads_hilo) noexcept {
    if (instruction.context.architecture != Architecture::mips64 ||
        instruction.context.mode != ExecutionMode::mips64 || instruction.operands.size() != 2 ||
        instruction.access.size() != 2 || instruction.access[0] != OperandAccess::read ||
        instruction.access[1] != OperandAccess::read)
        return false;
    for (const auto &operand : instruction.operands) {
        const auto *reg = std::get_if<RegisterOperand>(&operand);
        if (!reg || reg->bank != RegisterBank::mips_gpr || reg->width != 64 || reg->high_byte)
            return false;
        const bool listed = std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *reg) !=
                            instruction.register_reads.end();
        if (listed != (reg->index != 0)) return false;
    }
    const RegisterOperand hi{RegisterBank::mips_hilo, 0, 64, false};
    const RegisterOperand lo{RegisterBank::mips_hilo, 1, 64, false};
    const auto has = [](const auto &registers, RegisterOperand value) {
        return std::find(registers.begin(), registers.end(), value) != registers.end();
    };
    if (!has(instruction.register_writes, hi) || !has(instruction.register_writes, lo)) return false;
    return reads_hilo ? has(instruction.register_reads, hi) && has(instruction.register_reads, lo)
                      : !has(instruction.register_reads, hi) && !has(instruction.register_reads, lo);
}
}

std::optional<Mips64MergeResult>
evaluate_mips64_merge(Mips64MergeOperation operation, ByteOrder order,
                      std::uint8_t address_offset, std::uint64_t register_value,
                      std::uint64_t memory_word) noexcept {
    if (static_cast<unsigned>(operation) >
        static_cast<unsigned>(Mips64MergeOperation::store_right_doubleword))
        return {};
    const unsigned byte_count = is_word(operation) ? 4 : 8;
    if (address_offset >= byte_count) return {};

    const bool left = is_left(operation);
    unsigned memory_start = 0;
    unsigned register_start = 0;
    unsigned touched = 0;
    if (order == ByteOrder::little) {
        touched = left ? static_cast<unsigned>(address_offset) + 1 : byte_count - address_offset;
        memory_start = left ? 0 : address_offset;
        register_start = left ? byte_count - touched : 0;
    } else {
        touched = left ? byte_count - address_offset : static_cast<unsigned>(address_offset) + 1;
        memory_start = left ? address_offset : 0;
        register_start = left ? 0 : byte_count - touched;
    }

    Mips64MergeResult result;
    result.bytes_touched = static_cast<std::uint8_t>(touched);
    result.writes_register = is_load(operation);
    if (result.writes_register) {
        std::uint32_t merged32 = static_cast<std::uint32_t>(register_value);
        std::uint64_t merged64 = register_value;
        for (unsigned index = 0; index < touched; ++index) {
            const unsigned memory_lane = memory_start + index;
            const unsigned register_lane = register_start + index;
            const unsigned memory_shift = shift_for(memory_lane, byte_count, order);
            const unsigned register_shift = shift_for(register_lane, byte_count, order);
            const auto byte = (memory_word >> memory_shift) & UINT64_C(0xff);
            if (byte_count == 4) {
                const auto lane_mask = UINT32_C(0xff) << register_shift;
                merged32 = (merged32 & ~lane_mask) | static_cast<std::uint32_t>(byte << register_shift);
            } else {
                const auto lane_mask = UINT64_C(0xff) << register_shift;
                merged64 = (merged64 & ~lane_mask) | (byte << register_shift);
            }
            result.register_byte_mask |= UINT64_C(1) << (register_shift / 8);
            result.memory_byte_mask |= UINT64_C(1) << memory_lane;
        }
        if (byte_count == 4) {
            const auto signed_value = std::bit_cast<std::int32_t>(merged32);
            result.value = static_cast<std::uint64_t>(static_cast<std::int64_t>(signed_value));
            result.register_byte_mask |= UINT64_C(0xf0);
        } else {
            result.value = merged64;
        }
        return result;
    }

    std::uint64_t merged_memory = memory_word;
    const std::uint64_t source = byte_count == 4 ? static_cast<std::uint32_t>(register_value)
                                                  : register_value;
    for (unsigned index = 0; index < touched; ++index) {
        const unsigned memory_lane = memory_start + index;
        const unsigned register_lane = register_start + index;
        const unsigned memory_shift = shift_for(memory_lane, byte_count, order);
        const unsigned register_shift = shift_for(register_lane, byte_count, order);
        const auto lane_mask = UINT64_C(0xff) << memory_shift;
        const auto byte = (source >> register_shift) & UINT64_C(0xff);
        merged_memory = (merged_memory & ~lane_mask) | (byte << memory_shift);
        result.memory_byte_mask |= UINT64_C(1) << memory_lane;
    }
    if (byte_count == 4)
        merged_memory = (memory_word & UINT64_C(0xffffffff00000000)) |
                        static_cast<std::uint32_t>(merged_memory);
    result.value = merged_memory;
    return result;
}

std::optional<Mips64MultiplyAccumulateResult>
evaluate_mips64_multiply_accumulate(Mips64MultiplyAccumulateOperation operation,
                                    std::uint64_t lhs, std::uint64_t rhs,
                                    std::uint32_t hi, std::uint32_t lo) noexcept {
    if (static_cast<unsigned>(operation) >
        static_cast<unsigned>(Mips64MultiplyAccumulateOperation::msubu))
        return {};
    const auto lhs_word = static_cast<std::uint32_t>(lhs);
    const auto rhs_word = static_cast<std::uint32_t>(rhs);
    const auto accumulator = (static_cast<std::uint64_t>(hi) << 32) | lo;
    std::uint64_t product = 0;
    switch (operation) {
    case Mips64MultiplyAccumulateOperation::madd:
    case Mips64MultiplyAccumulateOperation::msub: {
        const auto signed_lhs = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(lhs_word));
        const auto signed_rhs = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(rhs_word));
        product = static_cast<std::uint64_t>(signed_lhs * signed_rhs);
        break;
    }
    case Mips64MultiplyAccumulateOperation::maddu:
    case Mips64MultiplyAccumulateOperation::msubu:
        product = static_cast<std::uint64_t>(lhs_word) * static_cast<std::uint64_t>(rhs_word);
        break;
    }
    const auto result = operation == Mips64MultiplyAccumulateOperation::madd ||
                        operation == Mips64MultiplyAccumulateOperation::maddu
        ? accumulator + product : accumulator - product;
    return Mips64MultiplyAccumulateResult{static_cast<std::uint32_t>(result >> 32),
                                          static_cast<std::uint32_t>(result)};
}

std::optional<Mips64MultiplyResult>
evaluate_mips64_multiply(Mips64MultiplyOperation operation,
                         std::uint64_t lhs, std::uint64_t rhs) noexcept {
    if (static_cast<unsigned>(operation) > static_cast<unsigned>(Mips64MultiplyOperation::dmultu))
        return {};
    if (operation == Mips64MultiplyOperation::mult || operation == Mips64MultiplyOperation::multu) {
        const auto lhs_word = static_cast<std::uint32_t>(lhs);
        const auto rhs_word = static_cast<std::uint32_t>(rhs);
        const auto sign_extended = [](std::uint64_t value, std::uint32_t word) {
            return value == static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int32_t>(word)));
        };
        if (!sign_extended(lhs, lhs_word) || !sign_extended(rhs, rhs_word)) return {};

        std::uint64_t product = 0;
        if (operation == Mips64MultiplyOperation::mult) {
            const auto signed_lhs = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(lhs_word));
            const auto signed_rhs = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(rhs_word));
            product = static_cast<std::uint64_t>(signed_lhs * signed_rhs);
        } else {
            product = static_cast<std::uint64_t>(lhs_word) * rhs_word;
        }
        const auto lo_word = static_cast<std::uint32_t>(product);
        const auto hi_word = static_cast<std::uint32_t>(product >> 32);
        return Mips64MultiplyResult{
            static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int32_t>(hi_word))),
            static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int32_t>(lo_word)))};
    }

    auto result = multiply_u64(lhs, rhs);
    if (operation == Mips64MultiplyOperation::dmult) {
        if (lhs >> 63) result.hi -= rhs;
        if (rhs >> 63) result.hi -= lhs;
    }
    return result;
}

std::optional<Mips64DivisionResult>
evaluate_mips64_division(Mips64DivisionOperation operation,
                         std::uint64_t lhs, std::uint64_t rhs) noexcept {
    if (static_cast<unsigned>(operation) > static_cast<unsigned>(Mips64DivisionOperation::ddivu))
        return {};
    const bool word = operation == Mips64DivisionOperation::div ||
                      operation == Mips64DivisionOperation::divu;
    const bool signed_division = operation == Mips64DivisionOperation::div ||
                                 operation == Mips64DivisionOperation::ddiv;
    Mips64DivisionResult result;
    if (word) {
        const auto lhs_word = static_cast<std::uint32_t>(lhs);
        const auto rhs_word = static_cast<std::uint32_t>(rhs);
        const auto sign_extended = [](std::uint64_t value, std::uint32_t low) {
            return value == static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int32_t>(low)));
        };
        if (!sign_extended(lhs, lhs_word) || !sign_extended(rhs, rhs_word)) {
            result.outcome = Mips64DivisionOutcome::unpredictable_word_operand;
            return result;
        }
        if (rhs_word == 0) {
            result.outcome = Mips64DivisionOutcome::unpredictable_divide_by_zero;
            return result;
        }
        std::uint32_t quotient = 0, remainder = 0;
        if (signed_division) {
            const auto signed_lhs = std::bit_cast<std::int32_t>(lhs_word);
            const auto signed_rhs = std::bit_cast<std::int32_t>(rhs_word);
            if (signed_lhs == std::numeric_limits<std::int32_t>::min() && signed_rhs == -1) {
                result.outcome = Mips64DivisionOutcome::unpredictable_signed_overflow;
                return result;
            }
            quotient = static_cast<std::uint32_t>(signed_lhs / signed_rhs);
            remainder = static_cast<std::uint32_t>(signed_lhs % signed_rhs);
        } else {
            quotient = lhs_word / rhs_word;
            remainder = lhs_word % rhs_word;
        }
        result.lo = static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int32_t>(quotient)));
        result.hi = static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int32_t>(remainder)));
        return result;
    }

    if (rhs == 0) {
        result.outcome = Mips64DivisionOutcome::unpredictable_divide_by_zero;
        return result;
    }
    if (signed_division) {
        const auto signed_lhs = std::bit_cast<std::int64_t>(lhs);
        const auto signed_rhs = std::bit_cast<std::int64_t>(rhs);
        if (signed_lhs == std::numeric_limits<std::int64_t>::min() && signed_rhs == -1) {
            result.outcome = Mips64DivisionOutcome::unpredictable_signed_overflow;
            return result;
        }
        result.lo = static_cast<std::uint64_t>(signed_lhs / signed_rhs);
        result.hi = static_cast<std::uint64_t>(signed_lhs % signed_rhs);
    } else {
        result.lo = lhs / rhs;
        result.hi = lhs % rhs;
    }
    return result;
}

std::optional<Mips64MultiplyResult>
evaluate_mips64_multiply_instruction(const Instruction &instruction,
                                     std::uint64_t lhs, std::uint64_t rhs) noexcept {
    if (!decoded_mips64_hilo_binary(instruction, false)) return {};
    Mips64MultiplyOperation operation;
    switch (instruction.opcode) {
    case Opcode::mips64_mult: operation = Mips64MultiplyOperation::mult; break;
    case Opcode::mips64_multu: operation = Mips64MultiplyOperation::multu; break;
    case Opcode::mips64_dmult: operation = Mips64MultiplyOperation::dmult; break;
    case Opcode::mips64_dmultu: operation = Mips64MultiplyOperation::dmultu; break;
    default: return {};
    }
    const auto *left = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *right = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if ((!left->index && lhs) || (!right->index && rhs)) return {};
    return evaluate_mips64_multiply(operation, lhs, rhs);
}

std::optional<Mips64MultiplyAccumulateResult>
evaluate_mips64_multiply_accumulate_instruction(const Instruction &instruction,
                                                std::uint64_t lhs, std::uint64_t rhs,
                                                std::uint32_t hi, std::uint32_t lo) noexcept {
    if (!decoded_mips64_hilo_binary(instruction, true)) return {};
    Mips64MultiplyAccumulateOperation operation;
    switch (instruction.opcode) {
    case Opcode::mips64_madd: operation = Mips64MultiplyAccumulateOperation::madd; break;
    case Opcode::mips64_maddu: operation = Mips64MultiplyAccumulateOperation::maddu; break;
    case Opcode::mips64_msub: operation = Mips64MultiplyAccumulateOperation::msub; break;
    case Opcode::mips64_msubu: operation = Mips64MultiplyAccumulateOperation::msubu; break;
    default: return {};
    }
    const auto *left = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *right = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if ((!left->index && lhs) || (!right->index && rhs)) return {};
    return evaluate_mips64_multiply_accumulate(operation, lhs, rhs, hi, lo);
}

std::optional<Mips64AddSubResult>
evaluate_mips64_add_sub_instruction(const Instruction &instruction,
                                    std::uint64_t lhs, std::uint64_t rhs) noexcept {
    const bool immediate = instruction.opcode == Opcode::mips64_daddi ||
                           instruction.opcode == Opcode::mips64_daddiu;
    const bool add = instruction.opcode == Opcode::mips64_dadd ||
                     instruction.opcode == Opcode::mips64_daddu || immediate;
    const bool subtract = instruction.opcode == Opcode::mips64_dsub ||
                          instruction.opcode == Opcode::mips64_dsubu;
    if ((!add && !subtract) || instruction.context.architecture != Architecture::mips64 ||
        instruction.context.mode != ExecutionMode::mips64 || instruction.length != 4 ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots != 0 ||
        instruction.memory_read || instruction.memory_write || instruction.operands.size() != 3 ||
        instruction.access.size() != 3 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read || instruction.access[2] != OperandAccess::read)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *left = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *right = immediate ? nullptr : std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto *constant = immediate ? std::get_if<ImmediateOperand>(&instruction.operands[2]) : nullptr;
    const auto valid_gpr = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::mips_gpr && reg->index <= 31 &&
               reg->width == 64 && !reg->high_byte;
    };
    if (!valid_gpr(destination) || !valid_gpr(left) ||
        (immediate && (!constant || constant->encoded_width != 16 || constant->effective_width != 64 ||
                       !constant->is_signed)) ||
        (!immediate && !valid_gpr(right)))
        return {};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (has(instruction.register_writes, *destination) != (destination->index != 0) ||
        (left->index != 0 && !has(instruction.register_reads, *left)) ||
        (!immediate && !has(instruction.register_reads, *right)) ||
        (immediate && rhs != 0))
        return {};
    if (left->index == 0 && lhs != 0) return {};
    if (!immediate && right->index == 0 && rhs != 0) return {};

    if (immediate) {
        const auto signed_value = std::bit_cast<std::int64_t>(constant->value);
        if (signed_value < INT16_MIN || signed_value > INT16_MAX) return {};
        rhs = static_cast<std::uint64_t>(signed_value);
    }
    const auto value = add ? lhs + rhs : lhs - rhs;
    const bool trapping = instruction.opcode == Opcode::mips64_dadd ||
                          instruction.opcode == Opcode::mips64_dsub ||
                          instruction.opcode == Opcode::mips64_daddi;
    const bool overflow = trapping && (add
        ? ((~(lhs ^ rhs) & (lhs ^ value)) >> 63) != 0
        : (((lhs ^ rhs) & (lhs ^ value)) >> 63) != 0);
    return Mips64AddSubResult{destination->index == 0 ? 0 : value,
                              overflow, destination->index != 0};
}

std::optional<std::uint64_t>
evaluate_mips64_count_leading(Opcode opcode, std::uint64_t source) noexcept {
    if (opcode == Opcode::mips64_dclz)
        return static_cast<std::uint64_t>(std::countl_zero(source));
    if (opcode == Opcode::mips64_dclo)
        return static_cast<std::uint64_t>(std::countl_one(source));
    return {};
}

std::optional<std::uint64_t>
evaluate_mips64_count_leading_instruction(const Instruction &instruction,
                                         std::uint64_t source) noexcept {
    if (instruction.context.architecture != Architecture::mips64 ||
        instruction.context.mode != ExecutionMode::mips64 || instruction.length != 4 ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots != 0 ||
        (instruction.opcode != Opcode::mips64_dclz && instruction.opcode != Opcode::mips64_dclo) ||
        instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.memory_read || instruction.memory_write)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto valid_gpr = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::mips_gpr && reg->index <= 31 &&
               reg->width == 64 && !reg->high_byte;
    };
    if (!valid_gpr(destination) || !valid_gpr(input)) return {};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    const RegisterOperand zero{RegisterBank::mips_gpr, 0, 64, false};
    if (contains(instruction.register_reads, zero) || contains(instruction.register_writes, zero) ||
        contains(instruction.register_writes, *destination) != (destination->index != 0) ||
        (input->index != 0 && !contains(instruction.register_reads, *input)))
        return {};
    if (input->index == 0) source = 0;
    return evaluate_mips64_count_leading(instruction.opcode, source);
}

std::optional<Mips64DivisionResult>
evaluate_mips64_division_instruction(const Instruction &instruction,
                                     std::uint64_t lhs, std::uint64_t rhs) noexcept {
    if (!decoded_mips64_hilo_binary(instruction, false)) return {};
    Mips64DivisionOperation operation;
    switch (instruction.opcode) {
    case Opcode::mips64_div: operation = Mips64DivisionOperation::div; break;
    case Opcode::mips64_divu: operation = Mips64DivisionOperation::divu; break;
    case Opcode::mips64_ddiv: operation = Mips64DivisionOperation::ddiv; break;
    case Opcode::mips64_ddivu: operation = Mips64DivisionOperation::ddivu; break;
    default: return {};
    }
    const auto *left = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *right = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if ((!left->index && lhs) || (!right->index && rhs)) return {};
    return evaluate_mips64_division(operation, lhs, rhs);
}

std::optional<Mips64FpConditionalMoveResult>
evaluate_mips64_fp_conditional_move_instruction(const Instruction &instruction,
                                                std::uint64_t source_bits,
                                                std::uint64_t prior_destination_bits,
                                                bool fcc_value) noexcept {
    if (instruction.context.architecture != Architecture::mips64 ||
        instruction.context.mode != ExecutionMode::mips64 ||
        (instruction.opcode != Opcode::mips64_movf_s && instruction.opcode != Opcode::mips64_movt_s &&
         instruction.opcode != Opcode::mips64_movf_d && instruction.opcode != Opcode::mips64_movt_d) ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots != 0 ||
        instruction.memory_read || instruction.memory_write || instruction.operands.size() != 3 ||
        instruction.access.size() != 3 || instruction.access[0] != OperandAccess::read_write ||
        instruction.access[1] != OperandAccess::read || instruction.access[2] != OperandAccess::read)
        return {};

    const bool single = instruction.opcode == Opcode::mips64_movf_s ||
                        instruction.opcode == Opcode::mips64_movt_s;
    const bool move_if_true = instruction.opcode == Opcode::mips64_movt_s ||
                              instruction.opcode == Opcode::mips64_movt_d;
    const auto width = static_cast<std::uint16_t>(single ? 32 : 64);
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *source = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *condition = std::get_if<ImmediateOperand>(&instruction.operands[2]);
    if (!destination || !source || destination->bank != RegisterBank::mips_fpr ||
        source->bank != RegisterBank::mips_fpr || destination->index > 31 || source->index > 31 ||
        destination->width != width || source->width != width || destination->high_byte || source->high_byte ||
        !condition || condition->encoded_width != 3 || condition->effective_width != 32 ||
        condition->is_signed || condition->value < 0 || condition->value > 7 ||
        instruction.condition != static_cast<std::uint8_t>(condition->value))
        return {};

    const RegisterOperand fcsr{RegisterBank::mips_fcsr, 0, 32, false};
    if (instruction.register_reads.size() != 3 || instruction.register_writes.size() != 1 ||
        instruction.register_reads[0] != *destination || instruction.register_reads[1] != *source ||
        instruction.register_reads[2] != fcsr || instruction.register_writes[0] != *destination)
        return {};

    const bool take_source = fcc_value == move_if_true;
    const auto mask = single ? UINT64_C(0xffffffff) : UINT64_MAX;
    return Mips64FpConditionalMoveResult{
        (take_source ? source_bits : prior_destination_bits) & mask, take_source};
}

} // namespace hexlab
