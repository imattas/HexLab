#pragma once

#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/processors_export.hpp"

#include <cstdint>
#include <functional>
#include <optional>

namespace hexlab {

struct Arm32Nzcv {
    bool n = false, z = false, c = false, v = false;
    bool operator==(const Arm32Nzcv &) const = default;
};

// Evaluate the architectural A32 condition field (EQ through LE; AL is 14).
// Reserved/unconditional-extension condition 15 is deliberately not treated
// as a predicate.
HEXLAB_PROCESSORS_EXPORT std::optional<bool> evaluate_arm32_condition(std::uint8_t condition,
                                                                       Arm32Nzcv flags) noexcept;
// Apply the predicate metadata retained by a decoded A32 or Thumb instruction.
// Unknown Thumb IT context and unsupported encoding-space conditions fail closed.
HEXLAB_PROCESSORS_EXPORT std::optional<bool> evaluate_arm32_instruction_predicate(
    const Instruction &instruction, Arm32Nzcv flags) noexcept;

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
HEXLAB_PROCESSORS_EXPORT std::optional<Arm32AluResult> evaluate_arm32_alu(Arm32AluOperation operation,
                                                std::uint32_t lhs,
                                                std::uint32_t operand2,
                                                Arm32Nzcv incoming,
                                                std::optional<bool> shifter_carry = {}) noexcept;

using Arm32RegisterReader = std::function<std::optional<std::uint32_t>(const RegisterOperand &)>;

// Evaluate a decoded, flag-setting A32/Thumb data-processing instruction.
// The callback supplies runtime GPR values; immediate and register-shifted
// operand2 forms, including RRX and register-specified shifts, are evaluated here.
// PC-writing, multiply, memory, unknown-flag, and unsupported operand forms fail closed.
HEXLAB_PROCESSORS_EXPORT std::optional<Arm32AluResult> evaluate_arm32_nzcv_instruction(const Instruction &instruction,
                                                             Arm32Nzcv incoming,
                                                             const Arm32RegisterReader &read_register);

struct Arm32MultiplyResult {
    std::uint32_t value = 0;
    Arm32Nzcv flags{};
    std::uint8_t flags_written = 0;
    bool operator==(const Arm32MultiplyResult &) const = default;
};

// Evaluate decoded A32 MUL/MLA/MLS. Caller supplies operand bit patterns and
// incoming flags; only record forms update N/Z and preserve C/V.
HEXLAB_PROCESSORS_EXPORT std::optional<Arm32MultiplyResult>
evaluate_arm32_multiply_instruction(const Instruction &instruction,
                                    std::uint32_t rm, std::uint32_t rs,
                                    std::uint32_t accumulator = 0,
                                    Arm32Nzcv incoming = {}) noexcept;

struct Arm32LongMultiplyResult {
    std::uint64_t value = 0;
    Arm32Nzcv flags{};
    std::uint8_t flags_written = 0;
    bool operator==(const Arm32LongMultiplyResult &) const = default;
};

// Evaluate decoded A32 UMULL/UMLAL/SMULL/SMLAL. Accumulator is the prior
// concatenated hi:lo destination value for accumulate forms.
HEXLAB_PROCESSORS_EXPORT std::optional<Arm32LongMultiplyResult>
evaluate_arm32_long_multiply_instruction(const Instruction &instruction,
                                         std::uint32_t rm, std::uint32_t rs,
                                         std::uint64_t accumulator = 0,
                                         Arm32Nzcv incoming = {}) noexcept;

// Evaluate decoded A32/T32 SBFX, UBFX, BFI, or BFC. `prior_destination` is
// read by insert/clear operations; `source` supplies the second register for
// extract/insert operations. Invalid ranges and inconsistent decoder facts
// fail closed.
HEXLAB_PROCESSORS_EXPORT std::optional<std::uint32_t> evaluate_arm32_bitfield_instruction(
    const Instruction &instruction, std::uint32_t prior_destination, std::uint32_t source) noexcept;

struct Arm32SaturatingResult {
    std::uint32_t value = 0;
    bool q_flag = false;
    bool operator==(const Arm32SaturatingResult &) const = default;
};

// Evaluate A32/T32 QADD, QSUB, QDADD, or QDSUB from Rm and Rn bit patterns.
// `incoming_q` models the sticky APSR.Q bit and is never cleared by these ops.
HEXLAB_PROCESSORS_EXPORT std::optional<Arm32SaturatingResult> evaluate_arm32_saturating_instruction(
    const Instruction &instruction, std::uint32_t rm, std::uint32_t rn, bool incoming_q = false) noexcept;

struct ThumbMoveWideResult {
    std::uint32_t value = 0;
    bool operator==(const ThumbMoveWideResult &) const = default;
};

// Evaluate decoded Thumb-2 MOVW/MOVT. MOVT inserts the immediate into the
// upper half of a caller-supplied prior destination value.
HEXLAB_PROCESSORS_EXPORT std::optional<ThumbMoveWideResult>
evaluate_thumb_move_wide_instruction(const Instruction &instruction,
                                     std::uint32_t prior_destination = 0) noexcept;

} // namespace hexlab
