#include "hexlab/processors/m6502_semantics.hpp"

namespace hexlab {

std::optional<M6502BinaryArithmeticResult>
evaluate_m6502_binary_arithmetic(Opcode opcode, std::uint8_t accumulator,
                                 std::uint8_t operand, std::uint8_t status) noexcept {
    if (opcode != Opcode::m6502_adc && opcode != Opcode::m6502_sbc)
        return {};

    const bool subtract = opcode == Opcode::m6502_sbc;
    if (status & 0x08u) {
        const auto valid_bcd = [](std::uint8_t value) noexcept {
            return (value & 0x0fu) <= 9 && (value >> 4) <= 9;
        };
        if (!valid_bcd(accumulator) || !valid_bcd(operand)) return {};
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

} // namespace hexlab
