#include "hexlab/processors/m6502_semantics.hpp"

#include <algorithm>
#include <cstddef>

namespace hexlab {

std::optional<M6502LoadResult>
evaluate_m6502_load(Opcode opcode, std::uint8_t operand, std::uint8_t status) noexcept {
    if (opcode != Opcode::m6502_lda && opcode != Opcode::m6502_ldx && opcode != Opcode::m6502_ldy)
        return {};
    const auto updated = static_cast<std::uint8_t>((status & 0x7d) |
        (operand == 0 ? 0x02 : 0) | (operand & 0x80));
    return M6502LoadResult{operand, updated};
}

std::optional<M6502LogicalResult>
evaluate_m6502_logical(Opcode opcode, std::uint8_t accumulator,
                       std::uint8_t operand, std::uint8_t status) noexcept {
    std::uint8_t result = 0;
    switch (opcode) {
    case Opcode::m6502_and: result = accumulator & operand; break;
    case Opcode::m6502_ora: result = accumulator | operand; break;
    case Opcode::m6502_eor: result = accumulator ^ operand; break;
    default: return {};
    }
    const auto updated = static_cast<std::uint8_t>((status & 0x7du) |
        (result == 0 ? 0x02u : 0u) | (result & 0x80u));
    return M6502LogicalResult{result, updated};
}

std::optional<M6502LogicalResult>
evaluate_m6502_logical_instruction(const Instruction &instruction,
                                   std::uint8_t accumulator,
                                   std::uint8_t operand, std::uint8_t status) noexcept {
    if (instruction.context.architecture != Architecture::mos6502 ||
        instruction.context.mode != ExecutionMode::m6502 ||
        instruction.flow != FlowKind::fallthrough || instruction.direct_target ||
        instruction.operands.size() != 1 || instruction.access.size() != 1 ||
        instruction.access[0] != OperandAccess::read || instruction.memory_write)
        return {};
    const auto encoded = std::to_integer<std::uint8_t>(instruction.bytes[0]);
    // Group-one operations 0/1/2 are ORA/AND/EOR; all eight modes are legal.
    if ((encoded & 3u) != 1u || (encoded >> 5) > 2u) return {};
    constexpr Opcode operations[]{Opcode::m6502_ora, Opcode::m6502_and, Opcode::m6502_eor};
    if (instruction.opcode != operations[encoded >> 5]) return {};
    const unsigned mode = (encoded >> 2) & 7u;
    const unsigned length = mode == 3 || mode == 6 || mode == 7 ? 3u : 2u;
    if (instruction.length != length) return {};

    const RegisterOperand a{RegisterBank::mos6502, 0, 8, false};
    const RegisterOperand x{RegisterBank::mos6502, 1, 8, false};
    const RegisterOperand y{RegisterBank::mos6502, 2, 8, false};
    const RegisterOperand p{RegisterBank::mos6502, 3, 8, false};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    const bool indexed = mode == 0 || mode == 4 || mode == 5 || mode == 6 || mode == 7;
    const auto index = mode == 4 || mode == 6 ? y : x;
    if (instruction.register_reads.size() != (indexed ? 3u : 2u) ||
        instruction.register_writes.size() != 2 ||
        !contains(instruction.register_reads, a) || !contains(instruction.register_reads, p) ||
        !contains(instruction.register_writes, a) || !contains(instruction.register_writes, p) ||
        (indexed && !contains(instruction.register_reads, index)))
        return {};

    const auto low = std::to_integer<std::uint8_t>(instruction.bytes[1]);
    if (mode == 2) {
        const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[0]);
        if (!immediate || immediate->encoded_width != 8 || immediate->effective_width != 8 ||
            immediate->is_signed || immediate->value != low || operand != low ||
            immediate->encoding != EncodedField{1, 1} || instruction.memory_read)
            return {};
    } else {
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[0]);
        const unsigned address = length == 3
            ? low | (unsigned(std::to_integer<std::uint8_t>(instruction.bytes[2])) << 8) : low;
        if (!memory || !instruction.memory_read || memory->data_width != 8 ||
            memory->address_width != 16 || memory->segment || memory->base ||
            memory->scale != 1 || memory->displacement != address || memory->ip_relative ||
            memory->writeback || memory->post_index || memory->writeback_displacement != 0 ||
            !memory->index_extend.empty() || memory->index_shift_amount != 0 ||
            memory->displacement_encoding != EncodedField{1, static_cast<std::uint8_t>(length - 1)} ||
            (indexed ? memory->index != index : memory->index.has_value()))
            return {};
        if (memory->resolved_address && (indexed ||
            memory->resolved_address != Address{instruction.address.space, address}))
            return {};
    }
    return evaluate_m6502_logical(instruction.opcode, accumulator, operand, status);
}

static std::optional<M6502BinaryArithmeticResult>
evaluate_binary_arithmetic(Opcode opcode, std::uint8_t accumulator,
                           std::uint8_t operand, std::uint8_t status, bool cmos) noexcept {
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
        if (cmos) {
            // W65C02 updates N/Z from the corrected decimal result. V follows
            // the binary ALU result, independent of decimal adjustment.
            negative = (result & 0x80u) != 0;
            overflow = ((accumulator ^ binary_result) &
                (subtract ? (accumulator ^ operand) : static_cast<std::uint8_t>(~(accumulator ^ operand))) &
                0x80u) != 0;
        }
        const auto zero = cmos ? result == 0 : binary_result == 0;
        const auto updated = static_cast<std::uint8_t>((status & 0x3cu) |
            (carry ? 0x01u : 0) | (zero ? 0x02u : 0) |
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
evaluate_m6502_binary_arithmetic(Opcode opcode, std::uint8_t accumulator,
                                 std::uint8_t operand, std::uint8_t status) noexcept {
    return evaluate_binary_arithmetic(opcode, accumulator, operand, status, false);
}

std::optional<M6502BinaryArithmeticResult>
evaluate_m65c02_binary_arithmetic(Opcode opcode, std::uint8_t accumulator,
                                  std::uint8_t operand, std::uint8_t status) noexcept {
    return evaluate_binary_arithmetic(opcode, accumulator, operand, status, true);
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

std::optional<M6502BinaryArithmeticResult>
evaluate_m65c02_binary_arithmetic_instruction(const Instruction &instruction,
                                              std::uint8_t accumulator,
                                              std::uint8_t operand,
                                              std::uint8_t status) noexcept {
    if (instruction.context.architecture != Architecture::mos6502 ||
        instruction.context.mode != ExecutionMode::m65c02 ||
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
    return evaluate_m65c02_binary_arithmetic(instruction.opcode, accumulator, operand, status);
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

std::optional<M6502CompareResult>
evaluate_m65c02_compare(Opcode opcode, std::uint8_t left, std::uint8_t operand,
                        std::uint8_t status, bool immediate_bit) noexcept {
    if (opcode == Opcode::m6502_bit) {
        const auto updated = immediate_bit
            ? static_cast<std::uint8_t>((status & 0xfdu) | ((left & operand) == 0 ? 0x02u : 0u))
            : static_cast<std::uint8_t>((status & 0x3du) | ((left & operand) == 0 ? 0x02u : 0u) |
                                        (operand & 0xc0u));
        return M6502CompareResult{updated};
    }
    if (immediate_bit || (opcode != Opcode::m6502_cmp && opcode != Opcode::m6502_cpx &&
                          opcode != Opcode::m6502_cpy))
        return {};
    const auto difference = static_cast<std::uint8_t>(left - operand);
    const auto updated = static_cast<std::uint8_t>((status & 0x7cu) |
        (left >= operand ? 0x01u : 0u) | (difference == 0 ? 0x02u : 0u) | (difference & 0x80u));
    return M6502CompareResult{updated};
}

std::optional<M6502CompareResult>
evaluate_m65c02_compare_instruction(const Instruction &instruction,
                                    std::uint8_t left, std::uint8_t operand,
                                    std::uint8_t status) noexcept {
    if (instruction.context.architecture != Architecture::mos6502 ||
        instruction.context.mode != ExecutionMode::m65c02 || instruction.operands.size() != 1 ||
        instruction.access.size() != 1 || instruction.access[0] != OperandAccess::read ||
        instruction.memory_write)
        return {};
    RegisterOperand selected{RegisterBank::mos6502,
        static_cast<std::uint16_t>(instruction.opcode == Opcode::m6502_cpx ? 1 :
                                   instruction.opcode == Opcode::m6502_cpy ? 2 : 0), 8, false};
    if (instruction.opcode != Opcode::m6502_cmp && instruction.opcode != Opcode::m6502_cpx &&
        instruction.opcode != Opcode::m6502_cpy && instruction.opcode != Opcode::m6502_bit)
        return {};
    if (std::find(instruction.register_reads.begin(), instruction.register_reads.end(), selected) ==
        instruction.register_reads.end())
        return {};
    const RegisterOperand processor_status{RegisterBank::mos6502, 3, 8, false};
    if (std::find(instruction.register_reads.begin(), instruction.register_reads.end(), processor_status) ==
            instruction.register_reads.end() ||
        std::find(instruction.register_writes.begin(), instruction.register_writes.end(), processor_status) ==
            instruction.register_writes.end())
        return {};
    bool immediate_bit = false;
    if (const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[0])) {
        if (instruction.opcode != Opcode::m6502_bit || immediate->effective_width != 8 ||
            immediate->value > UINT8_MAX || instruction.memory_read)
            return {};
        immediate_bit = true;
    } else if (const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[0])) {
        if (memory->data_width != 8 || !instruction.memory_read || instruction.memory_write)
            return {};
    } else {
        return {};
    }
    return evaluate_m65c02_compare(instruction.opcode, left, operand, status, immediate_bit);
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

std::optional<M6502ShiftResult>
evaluate_m6502_shift_instruction(const Instruction &instruction,
                                 std::uint8_t value, std::uint8_t status) noexcept {
    if (instruction.context.architecture != Architecture::mos6502 ||
        instruction.context.mode != ExecutionMode::m6502 ||
        instruction.flow != FlowKind::fallthrough || instruction.direct_target ||
        instruction.address.offset > UINT16_MAX ||
        instruction.length < 1 || instruction.length > 3 || instruction.length > instruction.bytes.size() ||
        instruction.operands.size() != 1 || instruction.access.size() != 1 ||
        instruction.access[0] != OperandAccess::read_write)
        return {};

    const auto encoded = std::to_integer<std::uint8_t>(instruction.bytes[0]);
    Opcode expected_opcode{};
    switch (encoded & 0x60u) {
    case 0x00: expected_opcode = Opcode::m6502_asl; break;
    case 0x20: expected_opcode = Opcode::m6502_rol; break;
    case 0x40: expected_opcode = Opcode::m6502_lsr; break;
    case 0x60: expected_opcode = Opcode::m6502_ror; break;
    }
    if (instruction.opcode != expected_opcode) return {};

    enum class Form { accumulator, zero_page, absolute, zero_page_x, absolute_x };
    Form form;
    std::uint8_t expected_length = 0;
    switch (encoded & 0x1fu) {
    case 0x0a: form = Form::accumulator; expected_length = 1; break;
    case 0x06: form = Form::zero_page; expected_length = 2; break;
    case 0x0e: form = Form::absolute; expected_length = 3; break;
    case 0x16: form = Form::zero_page_x; expected_length = 2; break;
    case 0x1e: form = Form::absolute_x; expected_length = 3; break;
    default: return {};
    }
    if (instruction.length != expected_length) return {};

    const RegisterOperand a{RegisterBank::mos6502, 0, 8, false};
    const RegisterOperand x{RegisterBank::mos6502, 1, 8, false};
    const RegisterOperand p{RegisterBank::mos6502, 3, 8, false};
    const auto contains = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!contains(instruction.register_reads, p) || !contains(instruction.register_writes, p)) return {};

    if (form == Form::accumulator) {
        const auto *operand = std::get_if<RegisterOperand>(&instruction.operands[0]);
        if (!operand || *operand != a || instruction.memory_read || instruction.memory_write ||
            instruction.register_reads.size() != 2 || instruction.register_writes.size() != 2 ||
            !contains(instruction.register_reads, a) || !contains(instruction.register_writes, a))
            return {};
    } else {
        const auto *operand = std::get_if<MemoryOperand>(&instruction.operands[0]);
        if (!operand || !instruction.memory_read || !instruction.memory_write ||
            instruction.register_writes.size() != 1 || operand->data_width != 8 || operand->address_width != 16 ||
            operand->segment || operand->base || operand->scale != 1 || operand->ip_relative ||
            operand->writeback || operand->post_index || operand->writeback_displacement != 0 ||
            !operand->index_extend.empty() || operand->index_shift_amount != 0)
            return {};

        const bool indexed = form == Form::zero_page_x || form == Form::absolute_x;
        if (instruction.register_reads.size() != (indexed ? 2u : 1u) ||
            (indexed ? (operand->index != x || !contains(instruction.register_reads, x)) : operand->index.has_value()))
            return {};
        const auto address = expected_length == 2
            ? std::uint16_t(std::to_integer<std::uint8_t>(instruction.bytes[1]))
            : std::uint16_t(std::to_integer<std::uint8_t>(instruction.bytes[1]) |
                (std::uint16_t(std::to_integer<std::uint8_t>(instruction.bytes[2])) << 8));
        if (operand->displacement != address ||
            operand->displacement_encoding != EncodedField{1, static_cast<std::uint8_t>(expected_length - 1)} ||
            (indexed ? operand->resolved_address.has_value()
                     : operand->resolved_address != Address{instruction.address.space, address}))
            return {};
    }
    return evaluate_m6502_shift(instruction.opcode, value, status);
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

std::optional<M6502InterruptEntryResult>
evaluate_m6502_hardware_interrupt(M6502HardwareInterrupt interrupt,
                                  std::uint16_t program_counter,
                                  std::uint8_t stack_pointer,
                                  std::uint8_t status,
                                  std::uint8_t vector_low,
                                  std::uint8_t vector_high) noexcept {
    std::uint16_t vector_address = 0;
    switch (interrupt) {
    case M6502HardwareInterrupt::irq: vector_address = 0xfffe; break;
    case M6502HardwareInterrupt::nmi: vector_address = 0xfffa; break;
    default: return {};
    }

    const auto pushed_status = static_cast<std::uint8_t>((status & 0xefu) | 0x20u);
    const auto next_status = static_cast<std::uint8_t>((status & 0xcfu) | 0x24u);
    const auto next_stack = static_cast<std::uint8_t>(stack_pointer - 3u);
    const auto target = static_cast<std::uint16_t>(vector_low |
        (static_cast<std::uint16_t>(vector_high) << 8));
    return M6502InterruptEntryResult{target, next_stack, next_status,
                                     static_cast<std::uint8_t>(program_counter >> 8),
                                     static_cast<std::uint8_t>(program_counter),
                                     pushed_status, vector_address};
}

std::optional<M65C02ControlResult>
evaluate_m65c02_wait_stop(Opcode opcode, std::uint16_t next_program_counter,
                          std::uint8_t stack_pointer, std::uint8_t status) noexcept {
    M65C02RunState state{};
    if (opcode == Opcode::m65c02_wai) state = M65C02RunState::waiting;
    else if (opcode == Opcode::m65c02_stp) state = M65C02RunState::stopped;
    else return {};
    return M65C02ControlResult{state, next_program_counter, stack_pointer, status};
}

std::optional<M65C02ControlResult>
evaluate_m65c02_wait_stop_instruction(const Instruction &instruction,
                                      std::uint16_t next_program_counter,
                                      std::uint8_t stack_pointer,
                                      std::uint8_t status) noexcept {
    if (instruction.context.architecture != Architecture::mos6502 ||
        instruction.context.mode != ExecutionMode::m65c02 || instruction.length != 1 ||
        !instruction.operands.empty() || !instruction.access.empty() ||
        instruction.memory_read || instruction.memory_write)
        return {};
    const auto opcode = instruction.opcode;
    if ((opcode == Opcode::m65c02_wai && instruction.flow != FlowKind::fallthrough) ||
        (opcode == Opcode::m65c02_stp && instruction.flow != FlowKind::trap))
        return {};
    return evaluate_m65c02_wait_stop(opcode, next_program_counter, stack_pointer, status);
}

std::optional<M65C02ControlResult>
evaluate_m65c02_wait_interrupt(M65C02RunState state,
                               M6502HardwareInterrupt interrupt,
                               std::uint16_t program_counter,
                               std::uint8_t stack_pointer, std::uint8_t status,
                               std::uint8_t vector_low,
                               std::uint8_t vector_high) noexcept {
    if (state != M65C02RunState::waiting) return {};
    if (interrupt != M6502HardwareInterrupt::irq && interrupt != M6502HardwareInterrupt::nmi)
        return {};
    // IRQ is level-sensitive. Even with I set it releases WAI, but cannot
    // start the interrupt frame; execution resumes at the post-WAI PC.
    if (interrupt == M6502HardwareInterrupt::irq && (status & 0x04u) != 0)
        return M65C02ControlResult{M65C02RunState::running, program_counter,
                                   stack_pointer, status};

    const auto entry = evaluate_m6502_hardware_interrupt(interrupt, program_counter,
        stack_pointer, status, vector_low, vector_high);
    if (!entry) return {};
    const auto cmos_status = static_cast<std::uint8_t>(entry->status & ~0x08u);
    return M65C02ControlResult{M65C02RunState::running, entry->program_counter,
        entry->stack_pointer, cmos_status, true,
        entry->pushed_program_counter_high, entry->pushed_program_counter_low,
        entry->pushed_status, entry->vector_address};
}

std::optional<M65C02ControlResult>
evaluate_m65c02_reset(M65C02RunState state, std::uint8_t stack_pointer,
                      std::uint8_t status, std::uint8_t vector_low,
                      std::uint8_t vector_high) noexcept {
    if (state != M65C02RunState::running && state != M65C02RunState::waiting &&
        state != M65C02RunState::stopped)
        return {};
    const auto target = static_cast<std::uint16_t>(vector_low |
        (static_cast<std::uint16_t>(vector_high) << 8));
    // D is cleared, I and the modeled always-one bit are asserted. Other
    // flags are software-initialized/unspecified by reset and left as supplied.
    const auto reset_status = static_cast<std::uint8_t>((status & ~0x18u) | 0x24u);
    return M65C02ControlResult{M65C02RunState::running, target, stack_pointer,
                               reset_status};
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

std::optional<M6502BranchBusTrace>
trace_m6502_branch_bus(const Instruction &instruction, std::uint8_t status) noexcept {
    if (instruction.context.architecture != Architecture::mos6502 ||
        instruction.context.mode != ExecutionMode::m6502 ||
        instruction.address.offset > UINT16_MAX || instruction.length != 2 || instruction.bytes.size() < 2 ||
        instruction.flow != FlowKind::conditional_branch || instruction.operands.size() != 1 ||
        instruction.access.size() != 1 || instruction.access[0] != OperandAccess::address ||
        instruction.memory_read || instruction.memory_write || !instruction.direct_target ||
        instruction.direct_target->space != instruction.address.space ||
        instruction.direct_target->offset > UINT16_MAX || !instruction.m6502_timing)
        return {};

    std::uint8_t expected_opcode = 0;
    switch (instruction.opcode) {
    case Opcode::m6502_bpl: expected_opcode = 0x10; break;
    case Opcode::m6502_bmi: expected_opcode = 0x30; break;
    case Opcode::m6502_bvc: expected_opcode = 0x50; break;
    case Opcode::m6502_bvs: expected_opcode = 0x70; break;
    case Opcode::m6502_bcc: expected_opcode = 0x90; break;
    case Opcode::m6502_bcs: expected_opcode = 0xb0; break;
    case Opcode::m6502_bne: expected_opcode = 0xd0; break;
    case Opcode::m6502_beq: expected_opcode = 0xf0; break;
    default: return {};
    }
    const auto *relative = std::get_if<RelativeOperand>(&instruction.operands[0]);
    const auto &timing = *instruction.m6502_timing;
    const auto pc = static_cast<std::uint16_t>(instruction.address.offset);
    const auto sequential = static_cast<std::uint16_t>(pc + 2u);
    const auto displacement = static_cast<std::int8_t>(std::to_integer<std::uint8_t>(instruction.bytes[1]));
    const auto expected_target = static_cast<std::uint16_t>(sequential + displacement);
    if (std::to_integer<std::uint8_t>(instruction.bytes[0]) != expected_opcode || !relative ||
        relative->encoded_width != 8 || relative->effective_width != 16 ||
        relative->displacement != displacement || relative->encoding != EncodedField{1, 1} ||
        *instruction.direct_target != Address{instruction.address.space, expected_target} ||
        timing.base_cycles != 2 || timing.page_cross_penalty || !timing.branch_taken_penalty ||
        !timing.branch_page_cross_penalty || timing.decimal_mode_penalty)
        return {};

    const RegisterOperand processor_status{RegisterBank::mos6502, 3, 8, false};
    if (instruction.register_reads.size() != 1 || instruction.register_reads[0] != processor_status ||
        !instruction.register_writes.empty())
        return {};
    const auto taken = evaluate_m6502_branch(instruction.opcode, status);
    if (!taken) return {};

    M6502BranchBusTrace trace;
    const auto append = [&](std::uint16_t address, M6502BusAccessKind kind) {
        const auto cycle = static_cast<std::uint8_t>(trace.access_count + 1u);
        trace.accesses[trace.access_count++] = M6502BusAccess{address, kind, cycle};
    };
    append(pc, M6502BusAccessKind::opcode_fetch);
    append(static_cast<std::uint16_t>(pc + 1u), M6502BusAccessKind::operand_fetch);
    trace.branch_taken = *taken;
    trace.next_program_counter = *taken ? expected_target : sequential;
    if (*taken) {
        append(sequential, M6502BusAccessKind::dummy_read);
        trace.page_crossed = (sequential & 0xff00u) != (expected_target & 0xff00u);
        if (trace.page_crossed) {
            const auto intermediate = static_cast<std::uint16_t>(
                (sequential & 0xff00u) | (expected_target & 0x00ffu));
            append(intermediate, M6502BusAccessKind::dummy_read);
        }
    }
    return trace;
}

std::optional<bool>
evaluate_m65c02_bit_branch(Opcode opcode, std::uint8_t bit, std::uint8_t value) noexcept {
    if (bit > 7 || (opcode != Opcode::m65c02_bbr && opcode != Opcode::m65c02_bbs))
        return {};
    const bool set = (value & static_cast<std::uint8_t>(1u << bit)) != 0;
    return opcode == Opcode::m65c02_bbs ? set : !set;
}

std::optional<bool>
evaluate_m65c02_bit_branch_instruction(const Instruction &instruction,
                                       std::uint8_t zero_page_value) noexcept {
    if (instruction.context.architecture != Architecture::mos6502 ||
        instruction.context.mode != ExecutionMode::m65c02 ||
        (instruction.opcode != Opcode::m65c02_bbr && instruction.opcode != Opcode::m65c02_bbs) ||
        instruction.condition > 7 || instruction.flow != FlowKind::conditional_branch ||
        instruction.length != 3 || instruction.operands.size() != 2 ||
        instruction.access.size() != 2 || instruction.access[0] != OperandAccess::read ||
        instruction.access[1] != OperandAccess::address || !instruction.memory_read ||
        instruction.memory_write || !instruction.direct_target || instruction.address.offset > UINT16_MAX)
        return {};
    const auto opcode_byte = std::to_integer<std::uint8_t>(instruction.bytes[0]);
    const bool set_branch = instruction.opcode == Opcode::m65c02_bbs;
    if ((opcode_byte & 0x0fu) != 0x0fu || ((opcode_byte >> 4) & 7u) != instruction.condition ||
        ((opcode_byte & 0x80u) != 0) != set_branch)
        return {};
    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[0]);
    const auto *relative = std::get_if<RelativeOperand>(&instruction.operands[1]);
    if (!memory || memory->data_width != 8 || memory->address_width != 16 || memory->segment ||
        memory->base || memory->index || memory->ip_relative || memory->scale != 1 || memory->writeback ||
        !memory->resolved_address || memory->resolved_address->space != instruction.address.space ||
        memory->resolved_address->offset > 0xff || memory->displacement < 0 ||
        static_cast<std::uint64_t>(memory->displacement) != memory->resolved_address->offset ||
        !relative || relative->encoded_width != 8 || relative->effective_width != 16 ||
        relative->displacement != static_cast<std::int8_t>(std::to_integer<std::uint8_t>(instruction.bytes[2])))
        return {};
    const auto expected_target = static_cast<std::uint16_t>(instruction.address.offset + 3 + relative->displacement);
    if (*instruction.direct_target != Address{instruction.address.space, expected_target} ||
        memory->resolved_address->offset != std::to_integer<std::uint8_t>(instruction.bytes[1]))
        return {};
    return evaluate_m65c02_bit_branch(instruction.opcode, instruction.condition, zero_page_value);
}

} // namespace hexlab
