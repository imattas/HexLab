#include "hexlab/processors/arm32_semantics.hpp"

#include <algorithm>
#include <bit>
#include <limits>

namespace hexlab {
namespace {
constexpr std::uint8_t n_mask = 8, z_mask = 4, c_mask = 2, v_mask = 1;

bool logical_operation(Arm32AluOperation op) {
    return op == Arm32AluOperation::and_ || op == Arm32AluOperation::eor ||
           op == Arm32AluOperation::tst || op == Arm32AluOperation::teq ||
           op == Arm32AluOperation::orr || op == Arm32AluOperation::mov ||
           op == Arm32AluOperation::bic || op == Arm32AluOperation::mvn;
}

std::optional<Arm32AluOperation> operation_for(Opcode opcode) {
    switch (opcode) {
    case Opcode::a32_and: return Arm32AluOperation::and_;
    case Opcode::a32_eor: return Arm32AluOperation::eor;
    case Opcode::a32_sub: return Arm32AluOperation::sub;
    case Opcode::a32_rsb: return Arm32AluOperation::rsb;
    case Opcode::a32_add: return Arm32AluOperation::add;
    case Opcode::a32_adc: return Arm32AluOperation::adc;
    case Opcode::a32_sbc: return Arm32AluOperation::sbc;
    case Opcode::a32_rsc: return Arm32AluOperation::rsc;
    case Opcode::a32_tst: return Arm32AluOperation::tst;
    case Opcode::a32_teq: return Arm32AluOperation::teq;
    case Opcode::a32_cmp: return Arm32AluOperation::cmp;
    case Opcode::a32_cmn: return Arm32AluOperation::cmn;
    case Opcode::a32_orr: return Arm32AluOperation::orr;
    case Opcode::a32_mov: return Arm32AluOperation::mov;
    case Opcode::a32_bic: return Arm32AluOperation::bic;
    case Opcode::a32_mvn: return Arm32AluOperation::mvn;
    default: return {};
    }
}

bool unary_operation(Arm32AluOperation op) {
    return op == Arm32AluOperation::mov || op == Arm32AluOperation::mvn;
}

bool comparison_operation(Arm32AluOperation op) {
    return op == Arm32AluOperation::tst || op == Arm32AluOperation::teq ||
           op == Arm32AluOperation::cmp || op == Arm32AluOperation::cmn;
}

std::optional<std::uint32_t> read_gpr(const Arm32RegisterReader &reader, const RegisterOperand &operand) {
    if (!reader || operand.bank != RegisterBank::arm32_gpr || operand.width != 32 || operand.high_byte)
        return {};
    return reader(operand);
}

struct ShiftedValue {
    std::uint32_t value = 0;
    std::optional<bool> carry;
};

std::optional<ShiftedValue> shift_operand(const ArmShiftedRegisterOperand &operand,
                                          Arm32Nzcv incoming,
                                          const Arm32RegisterReader &reader) {
    auto source = read_gpr(reader, operand.source);
    if (!source)
        return {};
    std::uint32_t amount = operand.amount;
    if (operand.amount_register) {
        auto runtime = read_gpr(reader, *operand.amount_register);
        if (!runtime)
            return {};
        amount = *runtime & 0xff;
    }
    ShiftedValue result{*source, {}};
    const bool immediate = !operand.amount_register;
    switch (operand.shift) {
    case ArmShift::lsl:
        if (!amount) {
            result.carry = incoming.c;
        } else if (amount < 32) {
            result.value = *source << amount;
            result.carry = ((*source >> (32 - amount)) & 1) != 0;
        } else if (amount == 32) {
            result.value = 0; result.carry = (*source & 1) != 0;
        } else {
            result.value = 0; result.carry = false;
        }
        break;
    case ArmShift::lsr:
        if (!amount) {
            if (immediate) amount = 32;
            else { result.carry = incoming.c; break; }
        }
        if (amount < 32) {
            result.value = *source >> amount;
            result.carry = ((*source >> (amount - 1)) & 1) != 0;
        } else {
            result.value = 0; result.carry = amount == 32 && ((*source >> 31) != 0);
        }
        break;
    case ArmShift::asr:
        if (!amount) {
            if (immediate) amount = 32;
            else { result.carry = incoming.c; break; }
        }
        if (amount < 32) {
            result.value = static_cast<std::uint32_t>(std::bit_cast<std::int32_t>(*source) >> amount);
            result.carry = ((*source >> (amount - 1)) & 1) != 0;
        } else {
            result.value = (*source & 0x80000000u) ? UINT32_MAX : 0;
            result.carry = (*source >> 31) != 0;
        }
        break;
    case ArmShift::ror:
        if (!amount) {
            if (immediate) { // The decoder represents immediate ROR #0 as RRX.
                result.value = (std::uint32_t(incoming.c) << 31) | (*source >> 1);
                result.carry = (*source & 1) != 0;
            } else result.carry = incoming.c;
        } else {
            const auto rotate = amount & 31;
            result.value = rotate ? std::rotr(*source, static_cast<int>(rotate)) : *source;
            result.carry = (result.value >> 31) != 0;
        }
        break;
    case ArmShift::rrx:
        result.value = (std::uint32_t(incoming.c) << 31) | (*source >> 1);
        result.carry = (*source & 1) != 0;
        break;
    }
    return result;
}
} // namespace

std::optional<bool> evaluate_arm32_condition(std::uint8_t condition, Arm32Nzcv flags) noexcept {
    switch (condition) {
    case 0: return flags.z;
    case 1: return !flags.z;
    case 2: return flags.c;
    case 3: return !flags.c;
    case 4: return flags.n;
    case 5: return !flags.n;
    case 6: return flags.v;
    case 7: return !flags.v;
    case 8: return flags.c && !flags.z;
    case 9: return !flags.c || flags.z;
    case 10: return flags.n == flags.v;
    case 11: return flags.n != flags.v;
    case 12: return !flags.z && flags.n == flags.v;
    case 13: return flags.z || flags.n != flags.v;
    case 14: return true;
    default: return {};
    }
}

std::optional<bool> evaluate_arm32_instruction_predicate(const Instruction &instruction,
                                                          Arm32Nzcv flags) noexcept {
    if (instruction.context.architecture != Architecture::arm || !instruction.arm ||
        (instruction.context.mode != ExecutionMode::a32 && instruction.context.mode != ExecutionMode::thumb))
        return {};
    if (instruction.arm->predicate == ArmPredicate::always) return true;
    if (instruction.arm->predicate == ArmPredicate::unknown_it) return {};
    if (instruction.condition >= 14) return {};
    const RegisterOperand apsr{RegisterBank::arm_flags, 0, 4, false};
    if (std::find(instruction.register_reads.begin(), instruction.register_reads.end(), apsr) ==
        instruction.register_reads.end())
        return {};
    return evaluate_arm32_condition(instruction.condition, flags);
}

std::optional<Arm32AluResult> evaluate_arm32_alu(Arm32AluOperation operation,
                                                std::uint32_t lhs,
                                                std::uint32_t operand2,
                                                Arm32Nzcv incoming,
                                                std::optional<bool> shifter_carry) noexcept {
    Arm32AluResult result{};
    result.flags = incoming;
    result.writes_result = !comparison_operation(operation);
    if (logical_operation(operation)) {
        switch (operation) {
        case Arm32AluOperation::and_: case Arm32AluOperation::tst: result.value = lhs & operand2; break;
        case Arm32AluOperation::eor: case Arm32AluOperation::teq: result.value = lhs ^ operand2; break;
        case Arm32AluOperation::orr: result.value = lhs | operand2; break;
        case Arm32AluOperation::mov: result.value = operand2; break;
        case Arm32AluOperation::bic: result.value = lhs & ~operand2; break;
        case Arm32AluOperation::mvn: result.value = ~operand2; break;
        default: return {};
        }
        result.flags.n = (result.value >> 31) != 0;
        result.flags.z = result.value == 0;
        result.flags_written = n_mask | z_mask;
        if (shifter_carry) {
            result.flags.c = *shifter_carry;
            result.flags_written |= c_mask;
        }
        return result;
    }

    const auto signed_lhs = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(lhs));
    const auto signed_rhs = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(operand2));
    std::int64_t signed_result = 0;
    std::uint64_t unsigned_result = 0;
    bool carry = false;
    switch (operation) {
    case Arm32AluOperation::add: case Arm32AluOperation::cmn: {
        unsigned_result = std::uint64_t(lhs) + operand2;
        signed_result = signed_lhs + signed_rhs;
        carry = (unsigned_result >> 32) != 0;
        break;
    }
    case Arm32AluOperation::adc: {
        const auto cin = std::uint64_t(incoming.c);
        unsigned_result = std::uint64_t(lhs) + operand2 + cin;
        signed_result = signed_lhs + signed_rhs + static_cast<std::int64_t>(cin);
        carry = (unsigned_result >> 32) != 0;
        break;
    }
    case Arm32AluOperation::sub: case Arm32AluOperation::cmp: {
        result.value = lhs - operand2;
        signed_result = signed_lhs - signed_rhs;
        carry = lhs >= operand2;
        break;
    }
    case Arm32AluOperation::rsb: {
        result.value = operand2 - lhs;
        signed_result = signed_rhs - signed_lhs;
        carry = operand2 >= lhs;
        break;
    }
    case Arm32AluOperation::sbc: {
        const auto borrow = std::uint64_t(!incoming.c);
        result.value = static_cast<std::uint32_t>(std::uint64_t(lhs) - operand2 - borrow);
        signed_result = signed_lhs - signed_rhs - static_cast<std::int64_t>(borrow);
        carry = std::uint64_t(lhs) >= std::uint64_t(operand2) + borrow;
        break;
    }
    case Arm32AluOperation::rsc: {
        const auto borrow = std::uint64_t(!incoming.c);
        result.value = static_cast<std::uint32_t>(std::uint64_t(operand2) - lhs - borrow);
        signed_result = signed_rhs - signed_lhs - static_cast<std::int64_t>(borrow);
        carry = std::uint64_t(operand2) >= std::uint64_t(lhs) + borrow;
        break;
    }
    default: return {};
    }
    if (operation == Arm32AluOperation::add || operation == Arm32AluOperation::adc ||
        operation == Arm32AluOperation::cmn) {
        result.value = static_cast<std::uint32_t>(unsigned_result);
    }
    result.flags.n = (result.value >> 31) != 0;
    result.flags.z = result.value == 0;
    result.flags.c = carry;
    result.flags.v = signed_result < INT32_MIN || signed_result > INT32_MAX;
    result.flags_written = 15;
    return result;
}

std::optional<Arm32AluResult> evaluate_arm32_nzcv_instruction(const Instruction &instruction,
                                                             Arm32Nzcv incoming,
                                                             const Arm32RegisterReader &read_register) {
    if (instruction.context.architecture != Architecture::arm ||
        (instruction.context.mode != ExecutionMode::a32 && instruction.context.mode != ExecutionMode::thumb) ||
        !instruction.arm || instruction.arm->flags_written == 0 ||
        (instruction.arm->flags_written & 0xf0) || instruction.arm->writes_pc)
        return {};
    const auto operation = operation_for(instruction.opcode);
    if (!operation || instruction.operands.empty())
        return {};
    const bool compare = comparison_operation(*operation), unary = unary_operation(*operation);
    if (instruction.operands.size() != (compare ? 2u : unary ? 2u : 3u))
        return {};
    std::uint8_t decoded_mask = instruction.arm->flags_written;
    const auto *decoded_shift = std::get_if<ArmShiftedRegisterOperand>(
        &instruction.operands.back());
    const bool runtime_shift = decoded_shift && decoded_shift->amount_register.has_value();
    if (!instruction.arm->flags_known && !runtime_shift)
        return {};
    const auto operand2_index = instruction.operands.size() - 1;
    std::uint32_t lhs = 0;
    if (!unary) {
        const auto *source = std::get_if<RegisterOperand>(&instruction.operands[compare ? 0 : 1]);
        const auto value = source ? read_gpr(read_register, *source) : std::nullopt;
        if (!value) return {};
        lhs = *value;
    }
    std::uint32_t rhs = 0;
    std::optional<bool> shifter_carry;
    if (const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[operand2_index])) {
        if (immediate->effective_width != 32 || immediate->value > UINT32_MAX)
            return {};
        rhs = static_cast<std::uint32_t>(immediate->value);
        if (decoded_mask & c_mask)
            shifter_carry = (rhs >> 31) != 0;
    } else if (const auto *shifted = std::get_if<ArmShiftedRegisterOperand>(&instruction.operands[operand2_index])) {
        const auto value = shift_operand(*shifted, incoming, read_register);
        if (!value) return {};
        rhs = value->value;
        shifter_carry = value->carry;
        if (runtime_shift && logical_operation(*operation)) {
            const auto amount = read_gpr(read_register, *shifted->amount_register);
            if (!amount) return {};
            if ((*amount & 0xff) != 0)
                decoded_mask |= c_mask;
        }
    } else if (const auto *source = std::get_if<RegisterOperand>(&instruction.operands[operand2_index])) {
        const auto value = read_gpr(read_register, *source);
        if (!value) return {};
        rhs = *value;
    } else return {};
    if (logical_operation(*operation)) {
        if ((decoded_mask & c_mask) && !shifter_carry)
            return {};
    } else if (decoded_mask != 15) return {};
    auto result = evaluate_arm32_alu(*operation, lhs, rhs, incoming, shifter_carry);
    if (!result) return {};
    // The decoded write mask distinguishes shifter carry preservation from a
    // concrete C result; keep every flag not written by the instruction intact.
    const auto mask = decoded_mask;
    if (!(mask & n_mask)) result->flags.n = incoming.n;
    if (!(mask & z_mask)) result->flags.z = incoming.z;
    if (!(mask & c_mask)) result->flags.c = incoming.c;
    if (!(mask & v_mask)) result->flags.v = incoming.v;
    result->flags_written = mask;
    return result;
}

std::optional<Arm32MultiplyResult>
evaluate_arm32_multiply_instruction(const Instruction &instruction,
                                    std::uint32_t rm, std::uint32_t rs,
                                    std::uint32_t accumulator,
                                    Arm32Nzcv incoming) noexcept {
    if (instruction.context.architecture != Architecture::arm || instruction.context.mode != ExecutionMode::a32 ||
        (instruction.opcode != Opcode::a32_mul && instruction.opcode != Opcode::a32_mla &&
         instruction.opcode != Opcode::a32_mls) || instruction.flow != FlowKind::fallthrough ||
        instruction.memory_read || instruction.memory_write || !instruction.arm)
        return {};
    const bool has_accumulator = instruction.opcode != Opcode::a32_mul;
    const auto operand_count = has_accumulator ? 4u : 3u;
    if (instruction.operands.size() != operand_count || instruction.access.size() != operand_count ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read ||
        (has_accumulator && instruction.access[3] != OperandAccess::read))
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *rm_reg = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *rs_reg = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto *acc_reg = has_accumulator ? std::get_if<RegisterOperand>(&instruction.operands[3]) : nullptr;
    const auto valid = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::arm32_gpr && reg->index < 15 &&
               reg->width == 32 && !reg->high_byte;
    };
    if (!valid(destination) || !valid(rm_reg) || !valid(rs_reg) || (has_accumulator && !valid(acc_reg)))
        return {};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!contains(instruction.register_writes, *destination) ||
        !contains(instruction.register_reads, *rm_reg) || !contains(instruction.register_reads, *rs_reg) ||
        (has_accumulator && !contains(instruction.register_reads, *acc_reg)))
        return {};
    const auto flags = instruction.arm->flags_written;
    if ((flags != 0 && flags != 12) || (flags && !instruction.arm->flags_known)) return {};
    const auto product = static_cast<std::uint64_t>(rm) * rs;
    std::uint32_t value = static_cast<std::uint32_t>(product);
    if (instruction.opcode == Opcode::a32_mla) value = static_cast<std::uint32_t>(value + accumulator);
    else if (instruction.opcode == Opcode::a32_mls) value = static_cast<std::uint32_t>(accumulator - value);
    auto result_flags = incoming;
    if (flags) {
        result_flags.n = (value & 0x80000000u) != 0;
        result_flags.z = value == 0;
    }
    return Arm32MultiplyResult{value, result_flags, flags};
}

std::optional<Arm32LongMultiplyResult>
evaluate_arm32_long_multiply_instruction(const Instruction &instruction,
                                         std::uint32_t rm, std::uint32_t rs,
                                         std::uint64_t accumulator,
                                         Arm32Nzcv incoming) noexcept {
    if (instruction.context.architecture != Architecture::arm ||
        instruction.context.mode != ExecutionMode::a32 || !instruction.arm ||
        instruction.flow != FlowKind::fallthrough || instruction.memory_read ||
        instruction.memory_write)
        return {};
    const bool signed_multiply = instruction.opcode == Opcode::a32_smull ||
                                 instruction.opcode == Opcode::a32_smlal;
    const bool accumulate = instruction.opcode == Opcode::a32_umlal ||
                            instruction.opcode == Opcode::a32_smlal;
    if (!signed_multiply && instruction.opcode != Opcode::a32_umull &&
        instruction.opcode != Opcode::a32_umlal)
        return {};
    if (instruction.operands.size() != 4 || instruction.access.size() != 4 ||
        instruction.access[0] != (accumulate ? OperandAccess::read_write : OperandAccess::write) ||
        instruction.access[1] != (accumulate ? OperandAccess::read_write : OperandAccess::write) ||
        instruction.access[2] != OperandAccess::read || instruction.access[3] != OperandAccess::read)
        return {};
    const auto *lo = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *hi = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *rm_reg = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto *rs_reg = std::get_if<RegisterOperand>(&instruction.operands[3]);
    const auto valid = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::arm32_gpr && reg->index < 15 &&
               reg->width == 32 && !reg->high_byte;
    };
    if (!valid(lo) || !valid(hi) || lo->index == hi->index ||
        !valid(rm_reg) || !valid(rs_reg))
        return {};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!contains(instruction.register_writes, *lo) || !contains(instruction.register_writes, *hi) ||
        !contains(instruction.register_reads, *rm_reg) || !contains(instruction.register_reads, *rs_reg) ||
        (accumulate && (!contains(instruction.register_reads, *lo) ||
                        !contains(instruction.register_reads, *hi))))
        return {};
    const auto flags_written = instruction.arm->flags_written;
    if ((flags_written != 0 && flags_written != 12) ||
        (flags_written != 0 && !instruction.arm->flags_known))
        return {};
    const RegisterOperand flags_reg{RegisterBank::arm_flags, 0, 4, false};
    if (flags_written && (!contains(instruction.register_reads, flags_reg) ||
                          !contains(instruction.register_writes, flags_reg)))
        return {};

    std::uint64_t value;
    if (signed_multiply) {
        const auto signed_product = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(rm)) *
                                    static_cast<std::int64_t>(std::bit_cast<std::int32_t>(rs));
        value = std::bit_cast<std::uint64_t>(signed_product);
    } else {
        value = static_cast<std::uint64_t>(rm) * rs;
    }
    if (accumulate) value += accumulator;
    auto flags = incoming;
    if (flags_written) {
        flags.n = (value >> 63) != 0;
        flags.z = value == 0;
    }
    return Arm32LongMultiplyResult{value, flags, flags_written};
}

std::optional<std::uint32_t> evaluate_arm32_bitfield_instruction(
    const Instruction &instruction, std::uint32_t prior_destination, std::uint32_t source) noexcept {
    if (instruction.context.architecture != Architecture::arm ||
        (instruction.context.mode != ExecutionMode::a32 && instruction.context.mode != ExecutionMode::thumb) ||
        (instruction.opcode != Opcode::arm_sbfx && instruction.opcode != Opcode::arm_ubfx &&
         instruction.opcode != Opcode::arm_bfi && instruction.opcode != Opcode::arm_bfc) ||
        instruction.flow != FlowKind::fallthrough || instruction.memory_read || instruction.memory_write ||
        !instruction.arm || instruction.arm->flags_written != 0 || !instruction.arm->flags_known)
        return {};
    const bool insert = instruction.opcode == Opcode::arm_bfi;
    const bool clear = instruction.opcode == Opcode::arm_bfc;
    const bool preserve = insert || clear;
    const std::size_t expected = (insert ? 4u : clear ? 3u : 4u);
    if (instruction.operands.size() != expected || instruction.access.size() != expected)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto register_limit = instruction.context.mode == ExecutionMode::a32 ? 15u : 13u;
    if (!destination || destination->bank != RegisterBank::arm32_gpr || destination->index >= register_limit ||
        destination->width != 32 || destination->high_byte ||
        instruction.access[0] != (preserve ? OperandAccess::read_write : OperandAccess::write))
        return {};
    std::size_t immediate_index = 2;
    const RegisterOperand *source_reg = nullptr;
    if (insert || (!clear && (instruction.opcode == Opcode::arm_sbfx || instruction.opcode == Opcode::arm_ubfx))) {
        source_reg = std::get_if<RegisterOperand>(&instruction.operands[1]);
        if (!source_reg || source_reg->bank != RegisterBank::arm32_gpr || source_reg->index >= register_limit ||
            source_reg->width != 32 || source_reg->high_byte || instruction.access[1] != OperandAccess::read)
            return {};
    }
    if (insert || clear) {
        if (!std::holds_alternative<ImmediateOperand>(instruction.operands[2])) return {};
        immediate_index = 2;
    } else {
        if (!std::holds_alternative<ImmediateOperand>(instruction.operands[2])) return {};
        immediate_index = 2;
    }
    const auto *lsb_operand = std::get_if<ImmediateOperand>(&instruction.operands[immediate_index]);
    const auto *width_operand = std::get_if<ImmediateOperand>(&instruction.operands[immediate_index + 1]);
    const auto valid_immediate = [](const ImmediateOperand *value) {
        return value && value->encoded_width == 5 && value->effective_width == 32 && !value->is_signed &&
               value->value <= 32;
    };
    if (!valid_immediate(lsb_operand) || !valid_immediate(width_operand) ||
        instruction.access[immediate_index] != OperandAccess::read ||
        instruction.access[immediate_index + 1] != OperandAccess::read) return {};
    const auto lsb = static_cast<unsigned>(lsb_operand->value);
    const auto width = static_cast<unsigned>(width_operand->value);
    if (width == 0 || lsb >= 32 || width > 32 - lsb) return {};
    const auto mask = width == 32 ? UINT32_MAX : ((UINT32_C(1) << width) - 1);
    const auto shifted_mask = mask << lsb;
    if (preserve && instruction.access[1] != OperandAccess::read && !clear) return {};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!contains(instruction.register_writes, *destination) ||
        (preserve && !contains(instruction.register_reads, *destination)) ||
        (source_reg && !contains(instruction.register_reads, *source_reg)))
        return {};
    if (insert) return (prior_destination & ~shifted_mask) | ((source & mask) << lsb);
    if (clear) return prior_destination & ~shifted_mask;
    const auto field = (source >> lsb) & mask;
    if (instruction.opcode == Opcode::arm_ubfx || width == 32 || !(field & (UINT32_C(1) << (width - 1))))
        return field;
    return field | ~mask;
}

std::optional<Arm32SaturatingResult> evaluate_arm32_saturating_instruction(
    const Instruction &instruction, std::uint32_t rm, std::uint32_t rn, bool incoming_q) noexcept {
    if (instruction.context.architecture != Architecture::arm ||
        (instruction.context.mode != ExecutionMode::a32 && instruction.context.mode != ExecutionMode::thumb) ||
        (instruction.opcode != Opcode::arm_qadd && instruction.opcode != Opcode::arm_qsub &&
         instruction.opcode != Opcode::arm_qdadd && instruction.opcode != Opcode::arm_qdsub) ||
        instruction.flow != FlowKind::fallthrough || instruction.memory_read || instruction.memory_write ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 || !instruction.arm ||
        !instruction.arm->q_flag_may_set || instruction.arm->flags_written != 0 || !instruction.arm->flags_known)
        return {};
    const auto register_limit = instruction.context.mode == ExecutionMode::a32 ? 15u : 13u;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *rm_operand = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *rn_operand = std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto valid_register = [register_limit](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::arm32_gpr && reg->index < register_limit &&
               reg->width == 32 && !reg->high_byte;
    };
    if (!valid_register(destination) || !valid_register(rm_operand) || !valid_register(rn_operand) ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read)
        return {};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!contains(instruction.register_writes, *destination) ||
        !contains(instruction.register_reads, *rm_operand) || !contains(instruction.register_reads, *rn_operand))
        return {};

    constexpr std::int64_t minimum = INT32_MIN;
    constexpr std::int64_t maximum = INT32_MAX;
    bool saturated = false;
    const auto clamp = [&](std::int64_t value) {
        if (value < minimum) { saturated = true; return minimum; }
        if (value > maximum) { saturated = true; return maximum; }
        return value;
    };
    const auto first = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(rm));
    const auto second = static_cast<std::int64_t>(std::bit_cast<std::int32_t>(rn));
    std::int64_t value = 0;
    if (instruction.opcode == Opcode::arm_qadd) value = clamp(first + second);
    else if (instruction.opcode == Opcode::arm_qsub) value = clamp(first - second);
    else if (instruction.opcode == Opcode::arm_qdadd || instruction.opcode == Opcode::arm_qdsub) {
        const auto doubled = clamp(second * 2);
        value = instruction.opcode == Opcode::arm_qdadd ? clamp(first + doubled) : clamp(first - doubled);
    } else return {};
    return Arm32SaturatingResult{static_cast<std::uint32_t>(static_cast<std::int32_t>(value)),
                                 incoming_q || saturated};
}

std::optional<ThumbMoveWideResult>
evaluate_thumb_move_wide_instruction(const Instruction &instruction,
                                     std::uint32_t prior_destination) noexcept {
    if (instruction.context.architecture != Architecture::arm ||
        instruction.context.mode != ExecutionMode::thumb || instruction.length != 4 ||
        (instruction.opcode != Opcode::t32_movw && instruction.opcode != Opcode::t32_movt) ||
        instruction.flow != FlowKind::fallthrough || instruction.memory_read || instruction.memory_write ||
        instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != (instruction.opcode == Opcode::t32_movt ? OperandAccess::read_write : OperandAccess::write) ||
        instruction.access[1] != OperandAccess::read)
        return {};
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[1]);
    if (!destination || destination->bank != RegisterBank::arm32_gpr || destination->index >= 13 ||
        destination->width != 32 || destination->high_byte || !immediate ||
        immediate->encoded_width != 16 || immediate->effective_width != 32 || immediate->is_signed ||
        immediate->value > UINT16_MAX)
        return {};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    const bool movt = instruction.opcode == Opcode::t32_movt;
    if (!contains(instruction.register_writes, *destination) ||
        (movt != contains(instruction.register_reads, *destination)))
        return {};
    const auto inserted = static_cast<std::uint32_t>(immediate->value) << 16;
    const auto value = movt ? (prior_destination & 0xffffu) | inserted : static_cast<std::uint32_t>(immediate->value);
    return ThumbMoveWideResult{value};
}

} // namespace hexlab
