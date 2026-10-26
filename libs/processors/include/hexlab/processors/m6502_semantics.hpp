#pragma once

#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/processors_export.hpp"
#include <cstdint>
#include <optional>

namespace hexlab {

struct M6502BinaryArithmeticResult {
    std::uint8_t accumulator = 0;
    std::uint8_t status = 0;
    bool operator==(const M6502BinaryArithmeticResult &) const = default;
};

// Evaluate an NMOS 6502 ADC or SBC after the caller has fetched its operand.
// P.D must be clear: decimal-mode arithmetic has distinct result/flag rules.
// C is the carry input for ADC and the no-borrow input for SBC. The returned
// P updates C/Z/V/N and preserves I/D/B/U and all other unchanged status bits.
// Other opcodes and a set decimal flag return no result.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502BinaryArithmeticResult>
evaluate_m6502_binary_arithmetic(Opcode opcode, std::uint8_t accumulator,
                                 std::uint8_t operand, std::uint8_t status) noexcept;

} // namespace hexlab
