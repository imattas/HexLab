#pragma once

#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/processors_export.hpp"
#include <cstdint>
#include <optional>

namespace hexlab {

struct M6502LoadResult {
    std::uint8_t value = 0;
    std::uint8_t status = 0;
    bool operator==(const M6502LoadResult &) const = default;
};
// Evaluate LDA/LDX/LDY after the caller fetches the operand byte. Only N/Z
// change; C/I/D/V and the modeled B/U status bits are preserved. The opcode
// selects A, X or Y at the caller; memory accesses remain caller-owned.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502LoadResult>
evaluate_m6502_load(Opcode opcode, std::uint8_t operand, std::uint8_t status) noexcept;

struct M6502BinaryArithmeticResult {
    std::uint8_t accumulator = 0;
    std::uint8_t status = 0;
    bool operator==(const M6502BinaryArithmeticResult &) const = default;
};

// Evaluate an NMOS 6502 ADC or SBC after the caller has fetched its operand.
// C is the carry input for ADC and the no-borrow input for SBC. The returned
// P updates C/Z/V/N and preserves I/D/B/U and all other unchanged status bits.
// Decimal mode applies NMOS nibble correction to every byte input, including
// out-of-range BCD digits. Other opcodes return no result.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502BinaryArithmeticResult>
evaluate_m6502_binary_arithmetic(Opcode opcode, std::uint8_t accumulator,
                                 std::uint8_t operand, std::uint8_t status) noexcept;
// Bind ADC/SBC evaluation to the decoded accumulator, P, and byte-operand
// facts. The caller supplies the fetched operand and current A/P values.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502BinaryArithmeticResult>
evaluate_m6502_binary_arithmetic_instruction(const Instruction &instruction,
                                             std::uint8_t accumulator,
                                             std::uint8_t operand,
                                             std::uint8_t status) noexcept;

struct M6502CompareResult {
    std::uint8_t status = 0;
    bool operator==(const M6502CompareResult &) const = default;
};

// Evaluate CMP/CPX/CPY or BIT after the caller fetches the operand. For BIT,
// left is A; for compare instructions it is the selected register. Updates
// only the flags defined by the instruction and preserves the remaining P bits.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502CompareResult>
evaluate_m6502_compare(Opcode opcode, std::uint8_t left, std::uint8_t operand,
                       std::uint8_t status) noexcept;

struct M6502AlrResult {
    std::uint8_t accumulator = 0;
    std::uint8_t status = 0;
    bool operator==(const M6502AlrResult &) const = default;
};

// Evaluate NMOS undocumented ALR ($4B): AND A with the immediate byte, then
// shift the intermediate right. C comes from the intermediate bit 0; N/Z come
// from the final accumulator and other modeled P bits are preserved.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502AlrResult>
evaluate_m6502_alr_instruction(const Instruction &instruction,
                               std::uint8_t accumulator, std::uint8_t status) noexcept;

struct M6502ShiftResult {
    std::uint8_t value = 0;
    std::uint8_t status = 0;
    bool operator==(const M6502ShiftResult &) const = default;
};
// Evaluate the NMOS 6502 ASL/LSR/ROL/ROR byte operation after the caller has
// fetched its operand. Rotates consume P.C; all four operations update C/Z/N
// and preserve the remaining modeled status bits. Memory access and register
// selection remain caller-owned.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502ShiftResult>
evaluate_m6502_shift(Opcode opcode, std::uint8_t value, std::uint8_t status) noexcept;

struct M6502IncrementResult {
    std::uint8_t value = 0;
    std::uint8_t status = 0;
    bool operator==(const M6502IncrementResult &) const = default;
};

// Evaluate byte INC/DEC or register INX/DEX/INY/DEY. The caller selects the
// operand and performs any memory access; C and other unaffected P bits stay.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502IncrementResult>
evaluate_m6502_increment_decrement(Opcode opcode, std::uint8_t value,
                                   std::uint8_t status) noexcept;

struct M6502TransferResult {
    std::uint8_t value = 0;
    std::uint8_t status = 0;
    bool updates_status = false;
    bool operator==(const M6502TransferResult &) const = default;
};

// Evaluate TAX/TAY/TXA/TYA/TSX/TXS for one byte source. TXS preserves P;
// the other transfers update N/Z and preserve all other modeled P bits.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502TransferResult>
evaluate_m6502_transfer(Opcode opcode, std::uint8_t source,
                        std::uint8_t status) noexcept;

struct M6502StatusStackResult {
    std::uint8_t stack_byte = 0;
    std::uint8_t status = 0;
    bool operator==(const M6502StatusStackResult &) const = default;
};

// Evaluate PHP/PLP status-byte handling. PHP sets the pushed B/U bits; PLP
// ignores the pulled B bit and forces the unused status bit high.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502StatusStackResult>
evaluate_m6502_status_stack(Opcode opcode, std::uint8_t status,
                            std::uint8_t pulled_byte = 0) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<M6502StatusStackResult>
evaluate_m6502_status_stack_instruction(const Instruction &instruction,
                                        std::uint8_t status,
                                        std::uint8_t pulled_byte = 0) noexcept;

struct M6502AccumulatorStackResult {
    std::uint8_t stack_byte = 0;
    std::uint8_t accumulator = 0;
    std::uint8_t status = 0;
    bool pulls_accumulator = false;
    bool operator==(const M6502AccumulatorStackResult &) const = default;
};

// Evaluate PHA/PLA data and flag behavior; stack addressing remains external.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502AccumulatorStackResult>
evaluate_m6502_accumulator_stack(Opcode opcode, std::uint8_t accumulator,
                                 std::uint8_t status, std::uint8_t pulled_byte = 0) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<M6502AccumulatorStackResult>
evaluate_m6502_accumulator_stack_instruction(const Instruction &instruction,
                                             std::uint8_t accumulator,
                                             std::uint8_t status,
                                             std::uint8_t pulled_byte = 0) noexcept;

struct M6502ReturnResult {
    std::uint16_t program_counter = 0;
    std::uint8_t stack_pointer = 0;
    std::uint8_t status = 0;
    bool updates_status = false;
    bool operator==(const M6502ReturnResult &) const = default;
};

// Evaluate RTS/RTI using caller-fetched stack bytes in pop order.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502ReturnResult>
evaluate_m6502_return(Opcode opcode, std::uint8_t stack_pointer,
                      std::uint8_t first, std::uint8_t second,
                      std::uint8_t third = 0) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<M6502ReturnResult>
evaluate_m6502_return_instruction(const Instruction &instruction,
                                  std::uint8_t stack_pointer,
                                  std::uint8_t first, std::uint8_t second,
                                  std::uint8_t third = 0) noexcept;

struct M6502FlagControlResult {
    std::uint8_t status = 0;
    bool operator==(const M6502FlagControlResult &) const = default;
};

// Evaluate CLC/SEC/CLI/SEI/CLV/CLD/SED by updating only the selected P bit.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502FlagControlResult>
evaluate_m6502_flag_control(Opcode opcode, std::uint8_t status) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<M6502FlagControlResult>
evaluate_m6502_flag_control_instruction(const Instruction &instruction,
                                        std::uint8_t status) noexcept;

// Evaluate a documented NMOS relative branch from the incoming processor
// status byte. The decoded adapter rejects non-branch or malformed forms.
HEXLAB_PROCESSORS_EXPORT std::optional<bool>
evaluate_m6502_branch(Opcode opcode, std::uint8_t status) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<bool>
evaluate_m6502_branch_instruction(const Instruction &instruction, std::uint8_t status) noexcept;

} // namespace hexlab
