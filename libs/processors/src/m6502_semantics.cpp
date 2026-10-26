#include "hexlab/processors/m6502_semantics.hpp"

namespace hexlab {

std::optional<M6502BinaryArithmeticResult>
evaluate_m6502_binary_arithmetic(Opcode opcode, std::uint8_t accumulator,
                                 std::uint8_t operand, std::uint8_t status) noexcept {
    if ((opcode != Opcode::m6502_adc && opcode != Opcode::m6502_sbc) || (status & 0x08u))
        return {};

    const bool subtract = opcode == Opcode::m6502_sbc;
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
