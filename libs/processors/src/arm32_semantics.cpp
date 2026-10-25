#include "hexlab/processors/arm32_semantics.hpp"

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

} // namespace hexlab
