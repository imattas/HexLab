#pragma once

#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/processors_export.hpp"
#include <array>
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

struct M6502LogicalResult {
    std::uint8_t accumulator = 0;
    std::uint8_t status = 0;
    bool operator==(const M6502LogicalResult &) const = default;
};

// Evaluate official AND/ORA/EOR after the caller fetches the operand byte.
// Only A and P.N/Z change; decimal mode does not affect the byte operation.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502LogicalResult>
evaluate_m6502_logical(Opcode opcode, std::uint8_t accumulator,
                       std::uint8_t operand, std::uint8_t status) noexcept;
// Accept only the 24 official NMOS encodings with matching byte-operand,
// register-effect and fallthrough facts. Immediate operand values must match
// the supplied operand. Memory access and committing A/P remain caller-owned.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502LogicalResult>
evaluate_m6502_logical_instruction(const Instruction &instruction,
                                   std::uint8_t accumulator,
                                   std::uint8_t operand, std::uint8_t status) noexcept;

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
// Evaluate W65C02 ADC/SBC after the caller fetches its operand. Decimal mode
// applies CMOS correction, takes N/Z from the corrected result, and computes
// V from the binary ALU result. Other opcodes return no result.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502BinaryArithmeticResult>
evaluate_m65c02_binary_arithmetic(Opcode opcode, std::uint8_t accumulator,
                                 std::uint8_t operand, std::uint8_t status) noexcept;
// Bind ADC/SBC evaluation to the decoded accumulator, P, and byte-operand
// facts. The caller supplies the fetched operand and current A/P values.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502BinaryArithmeticResult>
evaluate_m6502_binary_arithmetic_instruction(const Instruction &instruction,
                                             std::uint8_t accumulator,
                                             std::uint8_t operand,
                                             std::uint8_t status) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<M6502BinaryArithmeticResult>
evaluate_m65c02_binary_arithmetic_instruction(const Instruction &instruction,
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
// Evaluate W65C02 CMP/CPX/CPY or BIT. For BIT, pass true only for the
// immediate form, which updates Z while preserving N/V.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502CompareResult>
evaluate_m65c02_compare(Opcode opcode, std::uint8_t left, std::uint8_t operand,
                        std::uint8_t status, bool immediate_bit = false) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<M6502CompareResult>
evaluate_m65c02_compare_instruction(const Instruction &instruction,
                                    std::uint8_t left, std::uint8_t operand,
                                    std::uint8_t status) noexcept;

struct M65C02TsbTrbResult {
    std::uint8_t memory_value = 0;
    std::uint8_t status = 0;
    bool operator==(const M65C02TsbTrbResult &) const = default;
};
// Evaluate W65C02 TSB/TRB. Z reflects A & the original memory byte; memory
// receives memory | A for TSB or memory & ~A for TRB. Other P bits are kept.
HEXLAB_PROCESSORS_EXPORT std::optional<M65C02TsbTrbResult>
evaluate_m65c02_tsb_trb(Opcode opcode, std::uint8_t accumulator,
                        std::uint8_t memory_value, std::uint8_t status) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<M65C02TsbTrbResult>
evaluate_m65c02_tsb_trb_instruction(const Instruction &instruction,
                                    std::uint8_t accumulator,
                                    std::uint8_t memory_value,
                                    std::uint8_t status) noexcept;

struct M65C02RmbSmbResult {
    std::uint8_t memory_value = 0;
    bool operator==(const M65C02RmbSmbResult &) const = default;
};
// Evaluate W65C02 RMB/SMB for bit 0..7. These operations do not change P.
HEXLAB_PROCESSORS_EXPORT std::optional<M65C02RmbSmbResult>
evaluate_m65c02_rmb_smb(Opcode opcode, std::uint8_t bit,
                        std::uint8_t memory_value) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<M65C02RmbSmbResult>
evaluate_m65c02_rmb_smb_instruction(const Instruction &instruction,
                                    std::uint8_t memory_value) noexcept;

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
// Evaluate the shared NMOS 6502/W65C02 ASL/LSR/ROL/ROR byte operation after
// the caller has fetched its operand. Rotates consume P.C; all four operations
// update C/Z/N and preserve the remaining modeled status bits. Memory access
// and register selection remain caller-owned.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502ShiftResult>
evaluate_m6502_shift(Opcode opcode, std::uint8_t value, std::uint8_t status) noexcept;
// Bind an already-fetched value to one of the documented NMOS/W65C02
// ASL/LSR/ROL/ROR encodings. The adapter validates the instruction mode,
// bytes, operand form, register effects, and memory effects before returning
// the byte/flag result. The caller still performs the fetch and (for memory
// forms) the write.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502ShiftResult>
evaluate_m6502_shift_instruction(const Instruction &instruction,
                                 std::uint8_t value, std::uint8_t status) noexcept;

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

enum class M6502HardwareInterrupt : std::uint8_t { irq, nmi };

struct M6502InterruptEntryResult {
    std::uint16_t program_counter = 0;
    std::uint8_t stack_pointer = 0;
    std::uint8_t status = 0;
    std::uint8_t pushed_program_counter_high = 0;
    std::uint8_t pushed_program_counter_low = 0;
    std::uint8_t pushed_status = 0;
    std::uint16_t vector_address = 0;
    bool operator==(const M6502InterruptEntryResult &) const = default;
};

// Evaluate an already accepted NMOS IRQ/NMI entry. The caller supplies the
// interrupted PC/P/S and bytes read from the selected vector. This models the
// architectural frame and post-entry registers, not interrupt recognition,
// bus cycles, or memory writes.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502InterruptEntryResult>
evaluate_m6502_hardware_interrupt(M6502HardwareInterrupt interrupt,
                                  std::uint16_t program_counter,
                                  std::uint8_t stack_pointer,
                                  std::uint8_t status,
                                  std::uint8_t vector_low,
                                  std::uint8_t vector_high) noexcept;
// W65C02 IRQ/NMI entry has the same pushed frame but clears D after saving P.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502InterruptEntryResult>
evaluate_m65c02_hardware_interrupt(M6502HardwareInterrupt interrupt,
                                   std::uint16_t program_counter,
                                   std::uint8_t stack_pointer,
                                   std::uint8_t status,
                                   std::uint8_t vector_low,
                                   std::uint8_t vector_high) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<M6502InterruptEntryResult>
evaluate_m6502_brk(std::uint16_t program_counter, std::uint8_t stack_pointer,
                   std::uint8_t status, std::uint8_t vector_low,
                   std::uint8_t vector_high) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<M6502InterruptEntryResult>
evaluate_m65c02_brk(std::uint16_t program_counter, std::uint8_t stack_pointer,
                    std::uint8_t status, std::uint8_t vector_low,
                    std::uint8_t vector_high) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<M6502InterruptEntryResult>
evaluate_m6502_brk_instruction(const Instruction &instruction,
                               std::uint16_t program_counter, std::uint8_t stack_pointer,
                               std::uint8_t status, std::uint8_t vector_low,
                               std::uint8_t vector_high) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<M6502InterruptEntryResult>
evaluate_m65c02_brk_instruction(const Instruction &instruction,
                                std::uint16_t program_counter, std::uint8_t stack_pointer,
                                std::uint8_t status, std::uint8_t vector_low,
                                std::uint8_t vector_high) noexcept;

// Coarse W65C02 execution-control state for event evaluators. This is not a
// cycle-accurate CPU state machine; the caller owns pin sampling and memory.
enum class M65C02RunState : std::uint8_t { running, waiting, stopped };

struct M65C02ControlResult {
    M65C02RunState state = M65C02RunState::running;
    std::uint16_t program_counter = 0;
    std::uint8_t stack_pointer = 0;
    std::uint8_t status = 0;
    bool interrupt_entry = false;
    std::uint8_t pushed_program_counter_high = 0;
    std::uint8_t pushed_program_counter_low = 0;
    std::uint8_t pushed_status = 0;
    std::uint16_t vector_address = 0;
    bool operator==(const M65C02ControlResult &) const = default;
};

// Apply decoded WAI/STP control effects with PC already advanced past the
// one-byte instruction. Other opcodes and non-running input states reject.
HEXLAB_PROCESSORS_EXPORT std::optional<M65C02ControlResult>
evaluate_m65c02_wait_stop(Opcode opcode, std::uint16_t next_program_counter,
                          std::uint8_t stack_pointer, std::uint8_t status) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<M65C02ControlResult>
evaluate_m65c02_wait_stop_instruction(const Instruction &instruction,
                                      std::uint16_t next_program_counter,
                                      std::uint8_t stack_pointer,
                                      std::uint8_t status) noexcept;

// Deliver a pending IRQ/NMI while WAI is active. A masked IRQ wakes WAI and
// resumes at the saved post-WAI PC without vectoring; NMI always vectors. The
// caller supplies vector bytes and has already sampled/latched the event.
HEXLAB_PROCESSORS_EXPORT std::optional<M65C02ControlResult>
evaluate_m65c02_wait_interrupt(M65C02RunState state,
                               M6502HardwareInterrupt interrupt,
                               std::uint16_t program_counter,
                               std::uint8_t stack_pointer, std::uint8_t status,
                               std::uint8_t vector_low,
                               std::uint8_t vector_high) noexcept;

// Apply architectural reset register effects from any control state. Caller
// supplies bytes fetched from $FFFC/$FFFD. S and software flags are preserved
// because reset-time S bus activity and unspecified flags are not modeled.
HEXLAB_PROCESSORS_EXPORT std::optional<M65C02ControlResult>
evaluate_m65c02_reset(M65C02RunState state, std::uint8_t stack_pointer,
                      std::uint8_t status, std::uint8_t vector_low,
                      std::uint8_t vector_high) noexcept;

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

enum class M6502BusAccessKind : std::uint8_t {
    opcode_fetch, operand_fetch, dummy_read, stack_read, stack_write, vector_read,
    data_read, data_write, dummy_write
};
struct M6502BusAccess {
    std::uint16_t address = 0;
    M6502BusAccessKind kind = M6502BusAccessKind::opcode_fetch;
    std::uint8_t cycle = 0;
    std::optional<std::uint8_t> value;
    bool operator==(const M6502BusAccess &) const = default;
};

// Caller-supplied state for ordinary byte-memory instruction traces. Pointer
// bytes are used by indexed-indirect/indirect-indexed and CMOS (zp) forms.
struct M6502MemoryBusInputs {
    std::uint8_t accumulator = 0, x = 0, y = 0, status = 0;
    std::uint8_t memory_value = 0;
    std::optional<std::uint8_t> pointer_low, pointer_high;
};
struct M6502MemoryBusTrace {
    std::array<M6502BusAccess, 8> accesses{};
    std::uint8_t access_count = 0;
    std::uint16_t effective_address = 0, next_program_counter = 0;
    std::optional<std::uint8_t> result_value;
    bool page_crossed = false;
    bool operator==(const M6502MemoryBusTrace &) const = default;
};
// Trace validated documented NMOS/65C02 byte loads, stores, ALU/compare, and
// memory INC/DEC/ASL/LSR/ROL/ROR plus W65C02 TSB/TRB/RMB/SMB. NMOS
// read/modify/write forms report the original-value dummy write; W65C02 forms
// report the second effective-address read before the final write. The caller
// supplies A/P and the value read from the final effective address (and pointer
// bytes where needed); no memory or pin model is implied.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502MemoryBusTrace>
trace_m6502_memory_bus(const Instruction &instruction,
                       const M6502MemoryBusInputs &inputs) noexcept;
struct M6502IndirectJumpBusTrace {
    std::array<M6502BusAccess, 5> accesses{};
    std::uint8_t access_count = 0;
    std::uint16_t pointer_address = 0, high_byte_address = 0, next_program_counter = 0;
    bool operator==(const M6502IndirectJumpBusTrace &) const = default;
};
// Trace the five documented NMOS JMP (absolute) bus cycles. The caller
// supplies the two pointer bytes; the high-byte address applies the NMOS
// same-page wrap at xxFF. CMOS indexed-indirect variants are not accepted.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502IndirectJumpBusTrace>
trace_m6502_indirect_jump_bus(const Instruction &instruction,
                              std::uint8_t pointer_low,
                              std::uint8_t pointer_high) noexcept;
struct M6502InterruptBusTrace {
    std::array<M6502BusAccess, 7> accesses{};
    std::uint8_t access_count = 0;
    std::uint16_t next_program_counter = 0;
    std::uint8_t next_stack_pointer = 0;
    std::uint8_t next_status = 0;
    bool operator==(const M6502InterruptBusTrace &) const = default;
};
// Trace an already accepted NMOS IRQ/NMI entry. The caller supplies PC/P/S and
// the two bytes fetched from the selected vector; pin sampling remains external.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502InterruptBusTrace>
trace_m6502_hardware_interrupt_bus(M6502HardwareInterrupt interrupt,
                                   std::uint16_t program_counter,
                                   std::uint8_t stack_pointer, std::uint8_t status,
                                   std::uint8_t vector_low, std::uint8_t vector_high) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<M6502InterruptBusTrace>
trace_m65c02_hardware_interrupt_bus(M6502HardwareInterrupt interrupt,
                                    std::uint16_t program_counter,
                                    std::uint8_t stack_pointer, std::uint8_t status,
                                    std::uint8_t vector_low, std::uint8_t vector_high) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<M6502InterruptBusTrace>
trace_m6502_brk_bus(const Instruction &instruction, std::uint16_t program_counter,
                    std::uint8_t stack_pointer, std::uint8_t status,
                    std::uint8_t vector_low, std::uint8_t vector_high) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<M6502InterruptBusTrace>
trace_m65c02_brk_bus(const Instruction &instruction, std::uint16_t program_counter,
                     std::uint8_t stack_pointer, std::uint8_t status,
                     std::uint8_t vector_low, std::uint8_t vector_high) noexcept;
struct M6502BranchBusTrace {
    std::array<M6502BusAccess, 4> accesses{};
    std::uint8_t access_count = 0;
    std::uint16_t next_program_counter = 0;
    bool branch_taken = false;
    bool page_crossed = false;
    bool operator==(const M6502BranchBusTrace &) const = default;
};
// Describe the NMOS branch's opcode/offset fetches and conditional dummy reads.
// A taken branch reads PC+2; a page-crossing branch also reads the intermediate
// address with the old high byte and target low byte. This is an address trace,
// not a memory model or pin-level trace. Only a validated NMOS BPL/BMI/BVC/BVS/
// BCC/BCS/BNE/BEQ instruction and known incoming status are accepted.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502BranchBusTrace>
trace_m6502_branch_bus(const Instruction &instruction, std::uint8_t status) noexcept;

struct M65C02BitBranchBusTrace {
    std::array<M6502BusAccess, 7> accesses{};
    std::uint8_t access_count = 0;
    std::uint16_t zero_page_address = 0;
    std::uint16_t next_program_counter = 0;
    bool branch_taken = false;
    bool page_crossed = false;
    bool operator==(const M65C02BitBranchBusTrace &) const = default;
};
// Trace a validated W65C02 BBR/BBS bus sequence. The caller supplies the
// fetched zero-page byte; pin sampling and memory data outside that read remain
// external to this bounded address trace.
HEXLAB_PROCESSORS_EXPORT std::optional<M65C02BitBranchBusTrace>
trace_m65c02_bit_branch_bus(const Instruction &instruction,
                            std::uint8_t zero_page_value) noexcept;

struct M6502StackBusTrace {
    std::array<M6502BusAccess, 4> accesses{};
    std::uint8_t access_count = 0;
    std::uint16_t next_program_counter = 0;
    std::uint8_t next_stack_pointer = 0;
    bool operator==(const M6502StackBusTrace &) const = default;
};
// Trace the documented NMOS PHA/PHP/PLA/PLP cycles. Stack addresses are in
// page one; instruction and internal dummy reads are retained as address facts.
// Bus values and pins are outside this bounded trace.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502StackBusTrace>
trace_m6502_stack_bus(const Instruction &instruction, std::uint8_t stack_pointer) noexcept;

struct M6502ControlStackBusTrace {
    std::array<M6502BusAccess, 6> accesses{};
    std::uint8_t access_count = 0;
    std::uint16_t next_program_counter = 0;
    std::uint8_t next_stack_pointer = 0;
    bool operator==(const M6502ControlStackBusTrace &) const = default;
};
// Trace NMOS JSR/RTS/RTI stack cycles. Return instructions consume stack data
// in bus-read order (RTS: low/high; RTI: P/low/high) to resolve the next PC.
HEXLAB_PROCESSORS_EXPORT std::optional<M6502ControlStackBusTrace>
trace_m6502_control_stack_bus(const Instruction &instruction, std::uint8_t stack_pointer,
                              std::array<std::uint8_t, 3> pulled_bytes = {}) noexcept;

// Evaluate a W65C02 BBR/BBS branch from its zero-page byte. `bit` is the
// decoded bit number (0-7); the result is only the branch decision.
HEXLAB_PROCESSORS_EXPORT std::optional<bool>
evaluate_m65c02_bit_branch(Opcode opcode, std::uint8_t bit, std::uint8_t value) noexcept;
HEXLAB_PROCESSORS_EXPORT std::optional<bool>
evaluate_m65c02_bit_branch_instruction(const Instruction &instruction,
                                       std::uint8_t zero_page_value) noexcept;

struct M65C02BitBranchResult {
    std::uint16_t next_program_counter = 0;
    std::uint8_t cycles = 0;
    bool branch_taken = false;
    bool page_crossed = false;
    bool operator==(const M65C02BitBranchResult &) const = default;
};
// Resolve a decoded W65C02 BBR/BBS using its fetched zero-page byte. Cycles
// include the base operation, taken-branch penalty, and taken page-cross cost.
HEXLAB_PROCESSORS_EXPORT std::optional<M65C02BitBranchResult>
evaluate_m65c02_bit_branch_execution(const Instruction &instruction,
                                     std::uint8_t zero_page_value) noexcept;

} // namespace hexlab
