#include "hexlab/processors/m6502_semantics.hpp"

#include <algorithm>

namespace hexlab {

std::optional<M6502LoadResult>
evaluate_m6502_load(Opcode opcode, std::uint8_t operand, std::uint8_t status) noexcept {
    if (opcode != Opcode::m6502_lda && opcode != Opcode::m6502_ldx && opcode != Opcode::m6502_ldy)
        return {};
    const auto updated = static_cast<std::uint8_t>((status & 0x7d) |
        (operand == 0 ? 0x02 : 0) | (operand & 0x80));
    return M6502LoadResult{operand, updated};
}

std::optional<M6502BinaryArithmeticResult>
evaluate_m6502_binary_arithmetic(Opcode opcode, std::uint8_t accumulator,
                                 std::uint8_t operand, std::uint8_t status) noexcept {
    if (opcode != Opcode::m6502_adc && opcode != Opcode::m6502_sbc)
        return {};

    const bool subtract = opcode == Opcode::m6502_sbc;
    if (status & 0x08u) {
        const unsigned carry_in = status & 1u;
        std::uint8_t result = 0;
        bool carry = false;
        bool negative = false;
        bool overflow = false;
        if (!subtract) {
            const unsigned low_sum = (accumulator & 0x0f) + (operand & 0x0f) + carry_in;
            const unsigned low_adjusted = low_sum >= 10 ? low_sum + 6 : low_sum;
            const unsigned pre_high_adjust = (accumulator & 0xf0) + (operand & 0xf0) + low_adjusted;
            carry = pre_high_adjust >= 0xa0;
            const auto intermediate = static_cast<std::uint8_t>(pre_high_adjust);
            negative = (intermediate & 0x80) != 0;
            overflow = ((~(accumulator ^ operand) & (accumulator ^ intermediate)) & 0x80) != 0;
            result = static_cast<std::uint8_t>(pre_high_adjust + (carry ? 0x60 : 0));
        } else {
            const unsigned borrow_in = carry_in ? 0u : 1u;
            const unsigned low_a = accumulator & 0x0f;
            const unsigned low_b = operand & 0x0f;
            const bool low_borrow = low_a < low_b + borrow_in;
            const int raw_low = static_cast<int>(low_a) - static_cast<int>(low_b) -
                                static_cast<int>(borrow_in);
            const unsigned corrected_low = static_cast<unsigned>(raw_low + (low_borrow ? -6 : 0));
            const unsigned high_a = accumulator >> 4;
            const unsigned high_b = operand >> 4;
            const bool high_borrow = high_a < high_b + static_cast<unsigned>(low_borrow);
            const int raw_high = static_cast<int>(high_a) - static_cast<int>(high_b) -
                                 static_cast<int>(low_borrow);
            const unsigned corrected_high = static_cast<unsigned>(raw_high + (high_borrow ? -6 : 0));
            const auto intermediate = static_cast<std::uint8_t>(
                (static_cast<unsigned>(static_cast<std::uint8_t>(raw_high)) << 4) | (corrected_low & 0x0f));
            negative = (intermediate & 0x80) != 0;
            overflow = (((accumulator ^ operand) & (accumulator ^ intermediate)) & 0x80) != 0;
            result = static_cast<std::uint8_t>(((corrected_high & 0x0f) << 4) |
                                               (corrected_low & 0x0f));
            carry = !high_borrow;
        }
        // NMOS 6502 decimal Z is taken from the uncorrected binary result;
        // N and V use the intermediate value before high-digit correction.
        const auto binary_right = subtract ? static_cast<std::uint8_t>(~operand) : operand;
        const auto binary_sum = static_cast<std::uint16_t>(accumulator + binary_right + carry_in);
        const auto binary_result = static_cast<std::uint8_t>(binary_sum);
        if (subtract) {
            // SBC's N/V/Z are latched from the binary ALU result; decimal
            // correction only changes A and the no-borrow carry output.
            negative = (binary_result & 0x80) != 0;
            overflow = (((accumulator ^ operand) & (accumulator ^ binary_result)) & 0x80) != 0;
        }
        const auto updated = static_cast<std::uint8_t>((status & 0x3cu) |
            (carry ? 0x01u : 0) | (binary_result == 0 ? 0x02u : 0) |
            (overflow ? 0x40u : 0) | (negative ? 0x80u : 0));
        return M6502BinaryArithmeticResult{result, updated};
    }
    const std::uint16_t right = subtract ? static_cast<std::uint8_t>(~operand) : operand;
    const std::uint16_t sum = static_cast<std::uint16_t>(accumulator + right + (status & 1u));
    const auto result = static_cast<std::uint8_t>(sum);
    const bool overflow = ((accumulator ^ result) &
                           (subtract ? (accumulator ^ operand) : ~(accumulator ^ operand)) & 0x80u) != 0;
    const auto updated = static_cast<std::uint8_t>((status & 0x3cu) |
        ((sum & 0x100u) ? 0x01u : 0) |
        (result == 0 ? 0x02u : 0) |
        (overflow ? 0x40u : 0) |
        (result & 0x80u));
    return M6502BinaryArithmeticResult{result, updated};
}

std::optional<M6502BinaryArithmeticResult>
evaluate_m6502_binary_arithmetic_instruction(const Instruction &instruction,
                                             std::uint8_t accumulator,
                                             std::uint8_t operand,
                                             std::uint8_t status) noexcept {
    if (instruction.context.architecture != Architecture::mos6502 ||
        instruction.context.mode != ExecutionMode::m6502 ||
        (instruction.opcode != Opcode::m6502_adc && instruction.opcode != Opcode::m6502_sbc) ||
        instruction.operands.size() != 1 || instruction.access.size() != 1 ||
        instruction.access[0] != OperandAccess::read || instruction.memory_write)
        return {};
    const RegisterOperand a{RegisterBank::mos6502, 0, 8, false};
    const RegisterOperand p{RegisterBank::mos6502, 3, 8, false};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!contains(instruction.register_reads, a) || !contains(instruction.register_reads, p) ||
        !contains(instruction.register_writes, a) || !contains(instruction.register_writes, p))
        return {};
    if (const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[0])) {
        if (immediate->effective_width != 8 || immediate->value > UINT8_MAX || instruction.memory_read)
            return {};
    } else if (const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[0])) {
        if (memory->data_width != 8 || !instruction.memory_read) return {};
    } else {
        return {};
    }
    return evaluate_m6502_binary_arithmetic(instruction.opcode, accumulator, operand, status);
}

std::optional<M6502CompareResult>
evaluate_m6502_compare(Opcode opcode, std::uint8_t left, std::uint8_t operand,
                       std::uint8_t status) noexcept {
    if (opcode == Opcode::m6502_bit) {
        const auto updated = static_cast<std::uint8_t>((status & 0x3du) |
            ((left & operand) == 0 ? 0x02u : 0u) | (operand & 0xc0u));
        return M6502CompareResult{updated};
    }
    if (opcode != Opcode::m6502_cmp && opcode != Opcode::m6502_cpx && opcode != Opcode::m6502_cpy)
        return {};
    const auto difference = static_cast<std::uint8_t>(left - operand);
    const auto updated = static_cast<std::uint8_t>((status & 0x7cu) |
        (left >= operand ? 0x01u : 0u) | (difference == 0 ? 0x02u : 0u) | (difference & 0x80u));
    return M6502CompareResult{updated};
}

std::optional<M6502AlrResult>
evaluate_m6502_alr_instruction(const Instruction &instruction,
                               std::uint8_t accumulator, std::uint8_t status) noexcept {
    if (instruction.context.architecture != Architecture::mos6502 ||
        instruction.context.mode != ExecutionMode::m6502 || instruction.opcode != Opcode::m6502_alr ||
        instruction.length != 2 || instruction.bytes[0] != std::byte{0x4b} ||
        instruction.operands.size() != 1 || instruction.access.size() != 1 ||
        instruction.access[0] != OperandAccess::read || instruction.memory_read || instruction.memory_write)
        return {};
    const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[0]);
    if (!immediate || immediate->encoded_width != 8 || immediate->effective_width != 8 ||
        immediate->is_signed || immediate->value > UINT8_MAX)
        return {};
    const RegisterOperand a{RegisterBank::mos6502, 0, 8, false};
    const RegisterOperand p{RegisterBank::mos6502, 3, 8, false};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (instruction.register_reads.size() != 2 || instruction.register_writes.size() != 2 ||
        !contains(instruction.register_reads, a) || !contains(instruction.register_reads, p) ||
        !contains(instruction.register_writes, a) || !contains(instruction.register_writes, p))
        return {};
    const auto intermediate = static_cast<std::uint8_t>(accumulator & static_cast<std::uint8_t>(immediate->value));
    const auto result = static_cast<std::uint8_t>(intermediate >> 1);
    const auto updated = static_cast<std::uint8_t>((status & 0x7cu) | (intermediate & 1u) |
        (result == 0 ? 0x02u : 0) | (result & 0x80u));
    return M6502AlrResult{result, updated};
}

std::optional<M6502ShiftResult>
evaluate_m6502_shift(Opcode opcode, std::uint8_t value, std::uint8_t status) noexcept {
    if (opcode != Opcode::m6502_asl && opcode != Opcode::m6502_lsr &&
        opcode != Opcode::m6502_rol && opcode != Opcode::m6502_ror)
        return {};

    const bool carry_in = (status & 0x01u) != 0;
    bool carry_out = false;
    std::uint8_t result = 0;
    switch (opcode) {
    case Opcode::m6502_asl:
        carry_out = (value & 0x80u) != 0;
        result = static_cast<std::uint8_t>(value << 1);
        break;
    case Opcode::m6502_lsr:
        carry_out = (value & 0x01u) != 0;
        result = static_cast<std::uint8_t>(value >> 1);
        break;
    case Opcode::m6502_rol:
        carry_out = (value & 0x80u) != 0;
        result = static_cast<std::uint8_t>((value << 1) | static_cast<unsigned>(carry_in));
        break;
    case Opcode::m6502_ror:
        carry_out = (value & 0x01u) != 0;
        result = static_cast<std::uint8_t>((value >> 1) | (carry_in ? 0x80u : 0u));
        break;
    default:
        return {};
    }
    const auto updated = static_cast<std::uint8_t>((status & 0x7cu) |
        (carry_out ? 0x01u : 0u) | (result == 0 ? 0x02u : 0u) | (result & 0x80u));
    return M6502ShiftResult{result, updated};
}

std::optional<M6502IncrementResult>
evaluate_m6502_increment_decrement(Opcode opcode, std::uint8_t value,
                                   std::uint8_t status) noexcept {
    std::uint8_t result = 0;
    switch (opcode) {
    case Opcode::m6502_inc: case Opcode::m6502_inx: case Opcode::m6502_iny:
        result = static_cast<std::uint8_t>(value + 1u);
        break;
    case Opcode::m6502_dec: case Opcode::m6502_dex: case Opcode::m6502_dey:
        result = static_cast<std::uint8_t>(value - 1u);
        break;
    default: return {};
    }
    const auto updated = static_cast<std::uint8_t>((status & 0x7du) |
        (result == 0 ? 0x02u : 0u) | (result & 0x80u));
    return M6502IncrementResult{result, updated};
}

std::optional<M6502TransferResult>
evaluate_m6502_transfer(Opcode opcode, std::uint8_t source,
                        std::uint8_t status) noexcept {
    switch (opcode) {
    case Opcode::m6502_tax: case Opcode::m6502_tay: case Opcode::m6502_txa:
    case Opcode::m6502_tya: case Opcode::m6502_tsx:
        return M6502TransferResult{source, static_cast<std::uint8_t>((status & 0x7du) |
            (source == 0 ? 0x02u : 0u) | (source & 0x80u)), true};
    case Opcode::m6502_txs:
        return M6502TransferResult{source, status, false};
    default: return {};
    }
}

std::optional<M6502StatusStackResult>
evaluate_m6502_status_stack(Opcode opcode, std::uint8_t status,
                            std::uint8_t pulled_byte) noexcept {
    if (opcode == Opcode::m6502_php)
        return M6502StatusStackResult{static_cast<std::uint8_t>(status | 0x30u), status};
    if (opcode == Opcode::m6502_plp)
        return M6502StatusStackResult{0, static_cast<std::uint8_t>((pulled_byte & 0xcfu) | 0x20u)};
    return {};
}

std::optional<M6502StatusStackResult>
evaluate_m6502_status_stack_instruction(const Instruction &instruction,
                                        std::uint8_t status,
                                        std::uint8_t pulled_byte) noexcept {
    if (instruction.context.architecture != Architecture::mos6502 ||
        instruction.context.mode != ExecutionMode::m6502 ||
        instruction.flow != FlowKind::fallthrough || instruction.length != 1 ||
        !instruction.operands.empty() ||
        !instruction.access.empty())
        return {};
    const RegisterOperand stack{RegisterBank::mos6502, 4, 8, false};
    const RegisterOperand processor_status{RegisterBank::mos6502, 3, 8, false};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (instruction.opcode == Opcode::m6502_php) {
        if (!instruction.memory_write || instruction.memory_read ||
            !contains(instruction.register_reads, stack) ||
            !contains(instruction.register_reads, processor_status) ||
            !contains(instruction.register_writes, stack))
            return {};
    } else if (instruction.opcode == Opcode::m6502_plp) {
        if (!instruction.memory_read || instruction.memory_write ||
            !contains(instruction.register_reads, stack) ||
            !contains(instruction.register_writes, stack) ||
            !contains(instruction.register_writes, processor_status))
            return {};
    } else {
        return {};
    }
    return evaluate_m6502_status_stack(instruction.opcode, status, pulled_byte);
}

std::optional<M6502AccumulatorStackResult>
evaluate_m6502_accumulator_stack(Opcode opcode, std::uint8_t accumulator,
                                 std::uint8_t status, std::uint8_t pulled_byte) noexcept {
    if (opcode == Opcode::m6502_pha)
        return M6502AccumulatorStackResult{accumulator, accumulator, status, false};
    if (opcode == Opcode::m6502_pla) {
        const auto updated = static_cast<std::uint8_t>((status & 0x7du) |
            (pulled_byte == 0 ? 0x02u : 0u) | (pulled_byte & 0x80u));
        return M6502AccumulatorStackResult{0, pulled_byte, updated, true};
    }
    return {};
}

std::optional<M6502AccumulatorStackResult>
evaluate_m6502_accumulator_stack_instruction(const Instruction &instruction,
                                             std::uint8_t accumulator,
                                             std::uint8_t status,
                                             std::uint8_t pulled_byte) noexcept {
    if (instruction.context.architecture != Architecture::mos6502 ||
        instruction.context.mode != ExecutionMode::m6502 ||
        instruction.flow != FlowKind::fallthrough || instruction.length != 1 ||
        !instruction.operands.empty() || !instruction.access.empty())
        return {};
    const RegisterOperand a{RegisterBank::mos6502, 0, 8, false};
    const RegisterOperand p{RegisterBank::mos6502, 3, 8, false};
    const RegisterOperand s{RegisterBank::mos6502, 4, 8, false};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (instruction.opcode == Opcode::m6502_pha) {
        if (!instruction.memory_write || instruction.memory_read ||
            !contains(instruction.register_reads, a) || !contains(instruction.register_reads, s) ||
            !contains(instruction.register_writes, s))
            return {};
    } else if (instruction.opcode == Opcode::m6502_pla) {
        if (!instruction.memory_read || instruction.memory_write ||
            !contains(instruction.register_reads, s) || !contains(instruction.register_writes, a) ||
            !contains(instruction.register_writes, s) || !contains(instruction.register_writes, p))
            return {};
    } else {
        return {};
    }
    return evaluate_m6502_accumulator_stack(instruction.opcode, accumulator, status, pulled_byte);
}

std::optional<M6502ReturnResult>
evaluate_m6502_return(Opcode opcode, std::uint8_t stack_pointer,
                      std::uint8_t first, std::uint8_t second,
                      std::uint8_t third) noexcept {
    if (opcode == Opcode::m6502_rts) {
        const auto stacked = static_cast<std::uint16_t>(first | (static_cast<std::uint16_t>(second) << 8));
        return M6502ReturnResult{static_cast<std::uint16_t>(stacked + 1u),
                                 static_cast<std::uint8_t>(stack_pointer + 2u), 0, false};
    }
    if (opcode == Opcode::m6502_rti) {
        const auto stacked = static_cast<std::uint16_t>(second | (static_cast<std::uint16_t>(third) << 8));
        const auto restored_status = static_cast<std::uint8_t>((first & 0xcfu) | 0x20u);
        return M6502ReturnResult{stacked, static_cast<std::uint8_t>(stack_pointer + 3u), restored_status, true};
    }
    return {};
}

std::optional<M6502ReturnResult>
evaluate_m6502_return_instruction(const Instruction &instruction,
                                  std::uint8_t stack_pointer,
                                  std::uint8_t first, std::uint8_t second,
                                  std::uint8_t third) noexcept {
    if (instruction.context.architecture != Architecture::mos6502 ||
        instruction.context.mode != ExecutionMode::m6502 || instruction.flow != FlowKind::ret ||
        instruction.length != 1 || !instruction.operands.empty() || !instruction.access.empty() ||
        instruction.memory_read || instruction.memory_write)
        return {};
    const RegisterOperand s{RegisterBank::mos6502, 4, 8, false};
    const RegisterOperand p{RegisterBank::mos6502, 3, 8, false};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!contains(instruction.register_reads, s) || !contains(instruction.register_writes, s)) return {};
    if (instruction.opcode == Opcode::m6502_rti) {
        if (!contains(instruction.register_writes, p)) return {};
    } else if (instruction.opcode == Opcode::m6502_rts) {
        if (contains(instruction.register_writes, p)) return {};
    } else {
        return {};
    }
    return evaluate_m6502_return(instruction.opcode, stack_pointer, first, second, third);
}

std::optional<M6502FlagControlResult>
evaluate_m6502_flag_control(Opcode opcode, std::uint8_t status) noexcept {
    std::uint8_t bit = 0;
    bool set = false;
    switch (opcode) {
    case Opcode::m6502_clc: bit = 0x01; break;
    case Opcode::m6502_sec: bit = 0x01; set = true; break;
    case Opcode::m6502_cli: bit = 0x04; break;
    case Opcode::m6502_sei: bit = 0x04; set = true; break;
    case Opcode::m6502_clv: bit = 0x40; break;
    case Opcode::m6502_cld: bit = 0x08; break;
    case Opcode::m6502_sed: bit = 0x08; set = true; break;
    default: return {};
    }
    const auto updated = static_cast<std::uint8_t>(set ? status | bit : status & static_cast<std::uint8_t>(~bit));
    return M6502FlagControlResult{updated};
}

std::optional<M6502FlagControlResult>
evaluate_m6502_flag_control_instruction(const Instruction &instruction,
                                        std::uint8_t status) noexcept {
    if (instruction.context.architecture != Architecture::mos6502 ||
        instruction.context.mode != ExecutionMode::m6502 || instruction.flow != FlowKind::fallthrough ||
        instruction.length != 1 || !instruction.operands.empty() || !instruction.access.empty() ||
        instruction.memory_read || instruction.memory_write)
        return {};
    const RegisterOperand processor_status{RegisterBank::mos6502, 3, 8, false};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!contains(instruction.register_reads, processor_status) ||
        !contains(instruction.register_writes, processor_status))
        return {};
    return evaluate_m6502_flag_control(instruction.opcode, status);
}

std::optional<bool>
evaluate_m6502_branch(Opcode opcode, std::uint8_t status) noexcept {
    constexpr std::uint8_t carry = 0x01;
    constexpr std::uint8_t zero = 0x02;
    constexpr std::uint8_t overflow = 0x40;
    constexpr std::uint8_t negative = 0x80;
    switch (opcode) {
    case Opcode::m6502_bpl: return (status & negative) == 0;
    case Opcode::m6502_bmi: return (status & negative) != 0;
    case Opcode::m6502_bvc: return (status & overflow) == 0;
    case Opcode::m6502_bvs: return (status & overflow) != 0;
    case Opcode::m6502_bcc: return (status & carry) == 0;
    case Opcode::m6502_bcs: return (status & carry) != 0;
    case Opcode::m6502_bne: return (status & zero) == 0;
    case Opcode::m6502_beq: return (status & zero) != 0;
    default: return {};
    }
}

std::optional<bool>
evaluate_m6502_branch_instruction(const Instruction &instruction, std::uint8_t status) noexcept {
    if (instruction.context.architecture != Architecture::mos6502 ||
        instruction.context.mode != ExecutionMode::m6502 ||
        instruction.flow != FlowKind::conditional_branch || instruction.operands.size() != 1 ||
        instruction.access.size() != 1 || instruction.access[0] != OperandAccess::address ||
        !std::holds_alternative<RelativeOperand>(instruction.operands[0]) || !instruction.direct_target)
        return {};
    const RegisterOperand processor_status{RegisterBank::mos6502, 3, 8, false};
    if (std::find(instruction.register_reads.begin(), instruction.register_reads.end(), processor_status) ==
        instruction.register_reads.end())
        return {};
    return evaluate_m6502_branch(instruction.opcode, status);
}

} // namespace hexlab
