#pragma once

#include "hexlab/processors/x64_instruction_semantics.hpp"
#include <functional>

namespace hexlab {

enum class X86StringAccessKind { source_read, destination_read, destination_write };

struct X86StringAccessFault {
    X86StringAccessKind access = X86StringAccessKind::source_read;
    std::uint64_t offset = 0;
    std::optional<RegisterOperand> segment;
};

enum class X86StringExecutionStatus { completed, memory_fault, iteration_limit };

struct X86StringMemoryCallbacks {
    // Width is the decoded element width in bits; offsets have not had segment
    // bases applied. `nullopt`/false reports a memory access fault.
    std::function<std::optional<std::uint64_t>(std::optional<RegisterOperand>,
                                               std::uint64_t, std::uint8_t)> read;
    std::function<bool(std::optional<RegisterOperand>, std::uint64_t,
                       std::uint64_t, std::uint8_t)> write;
};

struct X86StringExecution {
    X86StringState state{};
    std::uint64_t iterations = 0;
    X86StringExecutionStatus status = X86StringExecutionStatus::completed;
    std::optional<X86StringAccessFault> fault;
};

// Execute a decoded string instruction through caller-owned memory callbacks.
// Each iteration commits architectural state only after its accesses succeed,
// so a fault reports progress up to (but not including) the faulting element.
inline std::optional<X86StringExecution>
execute_x86_string_instruction(const Instruction &instruction, X86StringState state,
                               const X86StringMemoryCallbacks &memory,
                               std::uint64_t max_iterations) {
    X86StringExecution result{state};
    const auto opcode = instruction.opcode;
    const bool reads_source = opcode == Opcode::x86_movs || opcode == Opcode::x86_cmps ||
                              opcode == Opcode::x86_lods;
    const bool reads_destination = opcode == Opcode::x86_cmps || opcode == Opcode::x86_scas;
    if (!reads_source && !reads_destination && opcode != Opcode::x86_stos)
        return std::nullopt;
    unsigned element_width = 0;
    for (const auto &operand : instruction.operands)
        if (const auto *memory_operand = std::get_if<MemoryOperand>(&operand)) {
            element_width = memory_operand->data_width;
            break;
        }
    if (!element_width) return std::nullopt;

    while (true) {
        // Probe operand shape and addresses before invoking callbacks. Dummy
        // values are replaced by the actual samples below.
        auto probe = evaluate_x86_string_iteration(instruction, result.state,
                                                   reads_source ? std::optional<std::uint64_t>{0} : std::nullopt,
                                                   reads_destination ? std::optional<std::uint64_t>{0} : std::nullopt);
        if (!probe) return std::nullopt;
        if (!probe->executed) return result;
        if (result.iterations >= max_iterations) {
            result.status = X86StringExecutionStatus::iteration_limit;
            return result;
        }

        std::optional<std::uint64_t> source_value;
        std::optional<std::uint64_t> destination_value;
        auto fail = [&](X86StringAccessKind access, std::uint64_t offset,
                        std::optional<RegisterOperand> segment) {
            result.status = X86StringExecutionStatus::memory_fault;
            result.fault = X86StringAccessFault{access, offset, segment};
        };
        if (reads_source) {
            if (!memory.read || !probe->source_offset) {
                fail(X86StringAccessKind::source_read, probe->source_offset.value_or(0), probe->source_segment);
                return result;
            }
            source_value = memory.read(probe->source_segment, *probe->source_offset,
                                       static_cast<std::uint8_t>(element_width));
            if (!source_value) {
                fail(X86StringAccessKind::source_read, *probe->source_offset, probe->source_segment);
                return result;
            }
        }
        if (reads_destination) {
            if (!memory.read || !probe->destination_offset) {
                fail(X86StringAccessKind::destination_read, probe->destination_offset.value_or(0), probe->destination_segment);
                return result;
            }
            const auto *operand = std::get_if<MemoryOperand>(&instruction.operands.back());
            if (!operand || operand->data_width != element_width) return std::nullopt;
            destination_value = memory.read(probe->destination_segment, *probe->destination_offset,
                                            static_cast<std::uint8_t>(element_width));
            if (!destination_value) {
                fail(X86StringAccessKind::destination_read, *probe->destination_offset, probe->destination_segment);
                return result;
            }
        }

        auto iteration = evaluate_x86_string_iteration(instruction, result.state,
                                                       source_value, destination_value);
        if (!iteration || !iteration->executed) return std::nullopt;
        if (iteration->memory_write_value) {
            const auto *operand = std::get_if<MemoryOperand>(&instruction.operands.front());
            if (!operand) return std::nullopt;
            if (!memory.write || !iteration->memory_write_offset ||
                !memory.write(iteration->memory_write_segment, *iteration->memory_write_offset,
                              *iteration->memory_write_value, static_cast<std::uint8_t>(element_width))) {
                fail(X86StringAccessKind::destination_write,
                     iteration->memory_write_offset.value_or(0), iteration->memory_write_segment);
                return result;
            }
        }
        result.state = iteration->state;
        ++result.iterations;
        if (!iteration->repeat) return result;
    }
}

} // namespace hexlab
