#pragma once

#include "hexlab/processors/instruction.hpp"

#include <cstdint>
#include <functional>
#include <optional>

namespace hexlab {

struct Arm32Nzcv {
    bool n = false, z = false, c = false, v = false;
    bool operator==(const Arm32Nzcv &) const = default;
};

enum class Arm32AluOperation : std::uint8_t {
    and_, eor, sub, rsb, add, adc, sbc, rsc, tst, teq, cmp, cmn, orr, mov, bic, mvn
};

struct Arm32AluResult {
    std::uint32_t value = 0;
    Arm32Nzcv flags{};
    // Mask uses architectural NZCV positions: N=8, Z=4, C=2, V=1.
    std::uint8_t flags_written = 0;
    bool writes_result = true;
    bool operator==(const Arm32AluResult &) const = default;
};

// Evaluate an ALU operation after the caller has resolved and shifted operand2.
// `shifter_carry` is required only when a logical operation writes C. `incoming.c`
// supplies the carry-in for ADC/SBC/RSC. Arithmetic is modulo 2^32.
std::optional<Arm32AluResult> evaluate_arm32_alu(Arm32AluOperation operation,
                                                std::uint32_t lhs,
                                                std::uint32_t operand2,
                                                Arm32Nzcv incoming,
                                                std::optional<bool> shifter_carry = {}) noexcept;

using Arm32RegisterReader = std::function<std::optional<std::uint32_t>(const RegisterOperand &)>;

// Evaluate a decoded, flag-setting A32/Thumb data-processing instruction.
// The callback supplies runtime GPR values; immediate and register-shifted
// operand2 forms, including RRX and register-specified shifts, are evaluated here.
// PC-writing, multiply, memory, unknown-flag, and unsupported operand forms fail closed.
std::optional<Arm32AluResult> evaluate_arm32_nzcv_instruction(const Instruction &instruction,
                                                             Arm32Nzcv incoming,
                                                             const Arm32RegisterReader &read_register);

} // namespace hexlab
