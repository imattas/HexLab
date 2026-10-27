#pragma once

#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/x64_semantics.hpp"
#include <algorithm>
#include <optional>
#include <bit>
#include <type_traits>
#include <variant>

namespace hexlab {

namespace x64_instruction_semantics_detail {
inline unsigned operand_width(const Operand &operand) noexcept {
    return std::visit([](const auto &value) -> unsigned {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, RegisterOperand>)
            return value.bank == RegisterBank::gpr ? value.width : 0;
        else if constexpr (std::is_same_v<T, MemoryOperand>)
            return value.data_width;
        else
            return 0;
    }, operand);
}
inline bool x86_context(const Instruction &instruction) noexcept {
    return instruction.context.architecture == Architecture::x86 ||
           instruction.context.architecture == Architecture::x86_64;
}
} // namespace x64_instruction_semantics_detail

// LAHF copies the defined arithmetic-status subset into AH, forces bit 1,
// and clears bits 3 and 5. Other FLAGS bits are not represented in AH.
inline std::uint8_t evaluate_x86_lahf(std::uint64_t flags) noexcept {
    return static_cast<std::uint8_t>(0x02u | (flags & 0xd5u));
}

inline std::optional<std::uint8_t> evaluate_x86_lahf_instruction(const Instruction &instruction,
                                                                 std::uint64_t flags) noexcept {
    if (!x64_instruction_semantics_detail::x86_context(instruction) || instruction.opcode != Opcode::lahf)
        return std::nullopt;
    const bool reads_flags = std::any_of(instruction.register_reads.begin(), instruction.register_reads.end(),
        [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
    const bool writes_ah = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
        [](RegisterOperand reg) { return reg.bank == RegisterBank::gpr && reg.index == 0 &&
                                         reg.width == 8 && reg.high_byte; });
    if (!reads_flags || !writes_ah) return std::nullopt;
    return evaluate_x86_lahf(flags);
}

// Evaluate LOOP/LOOPE/LOOPNE/JCXZ-family control flow using a decoded
// instruction. `counter` is the pre-instruction CX/ECX/RCX value.
inline std::optional<X86LoopResult> evaluate_x86_loop_instruction(const Instruction &instruction,
                                                                  std::uint64_t counter,
                                                                  bool zero_flag = false) noexcept {
    if (!x64_instruction_semantics_detail::x86_context(instruction) ||
        instruction.opcode != Opcode::x86_loop || !instruction.x86_loop_condition ||
        instruction.flow != FlowKind::conditional_branch ||
        (instruction.x86_loop_counter_width != 16 && instruction.x86_loop_counter_width != 32 &&
         instruction.x86_loop_counter_width != 64))
        return std::nullopt;
    return evaluate_x86_loop(*instruction.x86_loop_condition, counter,
                             instruction.x86_loop_counter_width, zero_flag);
}

// Architectural state touched by one x86 string-instruction iteration.
// Memory accesses are supplied by the caller; this result describes the
// effective offsets, segment registers, and any store while keeping the helper
// independent of image, process, or emulator memory ownership. Segment-base
// resolution and memory access belong to the caller.
struct X86StringState {
    std::uint64_t source_index = 0;
    std::uint64_t destination_index = 0;
    std::uint64_t count = 0;
    std::uint64_t accumulator = 0;
    bool direction_flag = false;
    X86Flags flags{};
    bool operator==(const X86StringState &) const = default;
};

struct X86BitOperationFlags {
    X86DefinedFlag carry{}, parity{}, auxiliary{}, zero{}, sign{}, overflow{};
    bool operator==(const X86BitOperationFlags &) const = default;
};

struct X86BitOperationResult {
    std::uint64_t value = 0;
    std::uint64_t bit_index = 0;
    std::int64_t memory_element_adjustment = 0;
    bool writes_destination = false;
    bool destination_defined = true;
    X86BitOperationFlags flags{};
    bool operator==(const X86BitOperationResult &) const = default;
};

// Evaluate a decoded BT/BTS/BTR/BTC or BSF/BSR/TZCNT/LZCNT. `source_value`
// is the bit base for BT-family operations and the searched operand for scans.
// Register bit indices are supplied as `index_value`; immediate indices are
// consumed from the decoded instruction. For memory bit strings the returned
// element adjustment is in bytes and the bit index is normalized to the
// selected element. The caller remains responsible for the actual memory read
// or write and for applying flags with undefined architected bits preserved as
// undefined.
inline std::optional<X86BitOperationResult>
evaluate_x86_bit_operation_instruction(const Instruction &instruction,
                                      std::uint64_t source_value,
                                      std::optional<std::uint64_t> index_value = std::nullopt) noexcept {
    using namespace x64_instruction_semantics_detail;
    if (!x86_context(instruction) || instruction.operands.size() != 2)
        return std::nullopt;
    const auto opcode = instruction.opcode;
    const bool bt_family = opcode == Opcode::bt || opcode == Opcode::bts ||
                           opcode == Opcode::btr || opcode == Opcode::btc;
    const bool scan = opcode == Opcode::bsf || opcode == Opcode::bsr ||
                      opcode == Opcode::tzcnt || opcode == Opcode::lzcnt;
    if (!bt_family && !scan)
        return std::nullopt;
    const unsigned width = operand_width(instruction.operands[0]);
    if (width != 16 && width != 32 && width != 64)
        return std::nullopt;
    const std::uint64_t mask = width == 64 ? UINT64_MAX : (std::uint64_t{1} << width) - 1;
    source_value &= mask;
    X86BitOperationResult result{};

    if (scan) {
        if (!std::holds_alternative<RegisterOperand>(instruction.operands[0]) ||
            (!std::holds_alternative<RegisterOperand>(instruction.operands[1]) &&
             !std::holds_alternative<MemoryOperand>(instruction.operands[1])) ||
            operand_width(instruction.operands[1]) != width)
            return std::nullopt;
        const bool count_op = opcode == Opcode::tzcnt || opcode == Opcode::lzcnt;
        result.writes_destination = true;
        result.destination_defined = source_value != 0 || count_op;
        if (opcode == Opcode::bsf || opcode == Opcode::tzcnt)
            result.value = source_value == 0 ? (count_op ? width : 0)
                                              : std::countr_zero(source_value);
        else if (opcode == Opcode::bsr)
            result.value = source_value == 0 ? (count_op ? width : 0)
                                              : width - 1 - (std::countl_zero(source_value) - (64 - width));
        else
            result.value = source_value == 0 ? width : std::countl_zero(source_value) - (64 - width);
        result.value &= mask;
        if (count_op) {
            result.flags.carry = {source_value == 0, true};
            result.flags.zero = {result.value == 0, true};
        } else {
            result.flags.zero = {source_value == 0, true};
        }
        return result;
    }

    const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[1]);
    const auto *index_register = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if ((!immediate && !index_register) || (index_register &&
        (index_register->bank != RegisterBank::gpr || !index_value)) ||
        (immediate && immediate->effective_width != 8))
        return std::nullopt;
    std::uint64_t raw_index = immediate ? immediate->value : *index_value;
    bool memory_base = std::holds_alternative<MemoryOperand>(instruction.operands[0]);
    if (!memory_base && !std::holds_alternative<RegisterOperand>(instruction.operands[0]))
        return std::nullopt;
    if (memory_base && index_register) {
        const unsigned index_width = index_register->width;
        if (index_width != width)
            return std::nullopt;
        raw_index &= mask;
        std::int64_t signed_index = 0;
        if (width == 64) {
            signed_index = std::bit_cast<std::int64_t>(raw_index);
        } else {
            const auto sign = std::uint64_t{1} << (width - 1);
            signed_index = (raw_index & sign) ? static_cast<std::int64_t>(raw_index) -
                                                  static_cast<std::int64_t>(std::uint64_t{1} << width)
                                              : static_cast<std::int64_t>(raw_index);
        }
        const auto signed_width = static_cast<std::int64_t>(width);
        auto quotient = signed_index / signed_width;
        auto remainder = signed_index % signed_width;
        if (remainder < 0) { --quotient; remainder += signed_width; }
        result.memory_element_adjustment = quotient * static_cast<std::int64_t>(width / 8);
        result.bit_index = static_cast<std::uint64_t>(remainder);
    } else {
        // Register destinations select within the register. Memory immediate
        // indices are unsigned and may advance across consecutive elements.
        if (memory_base) {
            result.memory_element_adjustment = static_cast<std::int64_t>(raw_index / width) *
                                               static_cast<std::int64_t>(width / 8);
            result.bit_index = raw_index % width;
        } else {
            result.bit_index = raw_index & (width - 1);
        }
    }

    const auto bit_mask = std::uint64_t{1} << result.bit_index;
    const bool old_bit = (source_value & bit_mask) != 0;
    result.flags.carry = {old_bit, true};
    result.value = source_value;
    switch (opcode) {
    case Opcode::bt: break;
    case Opcode::bts: result.value |= bit_mask; result.writes_destination = true; break;
    case Opcode::btr: result.value &= ~bit_mask; result.writes_destination = true; break;
    case Opcode::btc: result.value ^= bit_mask; result.writes_destination = true; break;
    default: return std::nullopt;
    }
    result.value &= mask;
    return result;
}

struct X86StringIteration {
    X86StringState state{};
    bool executed = false;
    bool repeat = false;
    std::optional<std::uint64_t> source_offset;
    std::optional<std::uint64_t> destination_offset;
    std::optional<std::uint64_t> memory_write_offset;
    std::optional<std::uint64_t> memory_write_value;
    std::optional<RegisterOperand> source_segment;
    std::optional<RegisterOperand> destination_segment;
    std::optional<RegisterOperand> memory_write_segment;
};

// Evaluate one iteration of a decoded MOVS/CMPS/STOS/LODS/SCAS instruction.
// For operations that read memory, provide the value sampled at the source
// and/or destination address. A REP-prefixed instruction with count zero does
// not execute an iteration and therefore does not require memory values.
inline std::optional<X86StringIteration>
evaluate_x86_string_iteration(const Instruction &instruction, X86StringState state,
                              std::optional<std::uint64_t> source_value,
                              std::optional<std::uint64_t> destination_value) noexcept {
    using namespace x64_instruction_semantics_detail;
    if (!x86_context(instruction) ||
        (instruction.context.mode != ExecutionMode::x86_16 &&
         instruction.context.mode != ExecutionMode::x86_32 &&
         instruction.context.mode != ExecutionMode::x86_64))
        return std::nullopt;

    const bool move_string = instruction.opcode == Opcode::x86_movs;
    const bool compare_string = instruction.opcode == Opcode::x86_cmps;
    const bool store_string = instruction.opcode == Opcode::x86_stos;
    const bool load_string = instruction.opcode == Opcode::x86_lods;
    const bool scan_string = instruction.opcode == Opcode::x86_scas;
    if (!move_string && !compare_string && !store_string && !load_string && !scan_string)
        return std::nullopt;

    const MemoryOperand *memory[2]{};
    std::size_t memory_count = 0;
    for (const auto &operand : instruction.operands)
        if (const auto *value = std::get_if<MemoryOperand>(&operand)) {
            if (memory_count >= 2) return std::nullopt;
            memory[memory_count++] = value;
        }
    const unsigned width = memory_count ? memory[0]->data_width : 0;
    const unsigned address_width = memory_count ? memory[0]->address_width : 0;
    if ((width != 8 && width != 16 && width != 32 && width != 64) ||
        (address_width != 16 && address_width != 32 && address_width != 64))
        return std::nullopt;
    if ((width == 64 && instruction.context.mode != ExecutionMode::x86_64) ||
        (instruction.context.mode == ExecutionMode::x86_16 && address_width == 64) ||
        (instruction.context.mode == ExecutionMode::x86_32 && address_width == 64) ||
        (instruction.context.mode == ExecutionMode::x86_64 && address_width == 16))
        return std::nullopt;
    if ((move_string || compare_string) ? memory_count != 2 : memory_count != 1)
        return std::nullopt;
    const auto is_gpr = [&](std::size_t operand_index, unsigned register_index) {
        if (operand_index >= instruction.operands.size()) return false;
        const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[operand_index]);
        return reg && reg->bank == RegisterBank::gpr && reg->index == register_index &&
               reg->width == width && !reg->high_byte;
    };
    const auto is_memory = [&](std::size_t operand_index, const MemoryOperand *expected) {
        return operand_index < instruction.operands.size() &&
               std::get_if<MemoryOperand>(&instruction.operands[operand_index]) == expected;
    };
    const auto has_string_index = [&](const MemoryOperand *operand, unsigned register_index) {
        return operand->base && operand->base->bank == RegisterBank::gpr &&
               operand->base->index == register_index && operand->base->width == address_width &&
               !operand->base->high_byte;
    };
    if (move_string && (instruction.operands.size() != 2 || !is_memory(0, memory[0]) ||
                        !is_memory(1, memory[1]) || !has_string_index(memory[0], 7) ||
                        !has_string_index(memory[1], 6)))
        return std::nullopt;
    if (compare_string && (instruction.operands.size() != 2 || !is_memory(0, memory[0]) ||
                           !is_memory(1, memory[1]) || !has_string_index(memory[0], 6) ||
                           !has_string_index(memory[1], 7)))
        return std::nullopt;
    if (store_string && (instruction.operands.size() != 2 || !is_memory(0, memory[0]) ||
                         !is_gpr(1, 0) || !has_string_index(memory[0], 7)))
        return std::nullopt;
    if (load_string && (instruction.operands.size() != 2 || !is_gpr(0, 0) ||
                        !is_memory(1, memory[0]) || !has_string_index(memory[0], 6)))
        return std::nullopt;
    if (scan_string && (instruction.operands.size() != 2 || !is_gpr(0, 0) ||
                        !is_memory(1, memory[0]) || !has_string_index(memory[0], 7)))
        return std::nullopt;
    for (std::size_t index = 0; index < memory_count; ++index) {
        const auto *operand = memory[index];
        if (operand->data_width != width || operand->address_width != address_width ||
            operand->ip_relative || operand->index || operand->scale != 1 || operand->displacement != 0 ||
            (operand->segment && (operand->segment->bank != RegisterBank::segment || operand->segment->width != 16)))
            return std::nullopt;
    }

    const auto value_mask = width == 64 ? UINT64_MAX : (UINT64_C(1) << width) - 1;
    const auto address_mask = address_width == 64 ? UINT64_MAX : (UINT64_C(1) << address_width) - 1;
    const auto source_index = state.source_index & address_mask;
    const auto destination_index = state.destination_index & address_mask;
    const bool repeated = instruction.x86_repeat != X86RepeatPrefix::none;
    const auto count = state.count & address_mask;

    X86StringIteration result;
    result.state = state;
    if (repeated && !count) return result;
    if (move_string || compare_string || load_string) {
        result.source_offset = source_index;
        result.source_segment = memory[move_string ? 1 : compare_string ? 0 : 0]->segment;
        if (!source_value) return std::nullopt;
    }
    if (move_string || compare_string || store_string || scan_string) {
        result.destination_offset = destination_index;
        result.destination_segment = memory[move_string ? 0 : compare_string ? 1 : 0]->segment;
    }
    if (compare_string && !destination_value) return std::nullopt;
    if (scan_string && !destination_value) return std::nullopt;

    const std::uint64_t bytes = width / 8;
    const auto advance = [&](std::uint64_t old) {
        const auto low = (old & address_mask);
        const auto updated = state.direction_flag ? (low - bytes) & address_mask
                                                  : (low + bytes) & address_mask;
        // A 16-bit address-size write preserves the upper part of the legacy
        // 32-bit index/count register when used as an override in 32-bit code.
        return address_width == 16 && instruction.context.mode != ExecutionMode::x86_16
                   ? (old & ~address_mask) | updated
                   : updated;
    };

    if (move_string) {
        result.memory_write_offset = destination_index;
        result.memory_write_value = *source_value & value_mask;
        result.memory_write_segment = result.destination_segment;
    } else if (store_string) {
        result.memory_write_offset = destination_index;
        result.memory_write_value = state.accumulator & value_mask;
        result.memory_write_segment = result.destination_segment;
    } else if (load_string) {
        const auto loaded = *source_value & value_mask;
        if (width == 32)
            result.state.accumulator = loaded; // 32-bit GPR writes zero-extend in 64-bit mode.
        else
            result.state.accumulator = (state.accumulator & ~value_mask) | loaded;
    } else {
        const auto lhs = scan_string ? state.accumulator : *source_value;
        const auto rhs = *destination_value;
        const auto comparison = evaluate_x86_arithmetic(X86Arithmetic::compare, lhs, rhs, false, width);
        result.state.flags = comparison.flags;
    }

    if (move_string || compare_string || load_string)
        result.state.source_index = advance(state.source_index);
    if (move_string || compare_string || store_string || scan_string)
        result.state.destination_index = advance(state.destination_index);
    if (repeated) {
        const auto decremented = (count - 1) & address_mask;
        result.state.count = address_width == 16 && instruction.context.mode != ExecutionMode::x86_16
                                 ? (state.count & ~address_mask) | decremented
                                 : decremented;
    }
    result.executed = true;
    const bool comparison_satisfied = !compare_string && !scan_string ||
        (instruction.x86_repeat == X86RepeatPrefix::rep ? result.state.flags.zero
                                                         : !result.state.flags.zero);
    result.repeat = repeated && ((result.state.count & address_mask) != 0) && comparison_satisfied;
    return result;
}

// Evaluate the two width-sized sources of a decoded MUL/IMUL. For one-operand
// forms lhs is the implicit accumulator input; the returned halves are split
// at the decoded operand width. For two/three-operand IMUL, low is the
// destination-width result and high is its adjacent upper half.
inline std::optional<X86MultiplyResult>
evaluate_x86_multiply_instruction(const Instruction &instruction,
                                 std::uint64_t lhs, std::uint64_t rhs) noexcept {
    if (!x64_instruction_semantics_detail::x86_context(instruction) ||
        (instruction.opcode != Opcode::mul && instruction.opcode != Opcode::imul) ||
        instruction.operands.empty() ||
        (instruction.opcode == Opcode::mul && instruction.operands.size() != 1) ||
        (instruction.opcode == Opcode::imul && instruction.operands.size() > 3))
        return std::nullopt;
    const unsigned width = x64_instruction_semantics_detail::operand_width(instruction.operands[0]);
    if (width != 8 && width != 16 && width != 32 && width != 64)
        return std::nullopt;
    const auto kind = instruction.opcode == Opcode::mul ? X86MultiplyKind::unsigned_multiply
                                                        : X86MultiplyKind::signed_multiply;
    return evaluate_x86_multiply(kind, lhs, rhs, width);
}

inline std::optional<X86DivideResult>
evaluate_x86_divide_instruction(const Instruction &instruction,
                                std::uint64_t dividend_low,
                                std::uint64_t dividend_high,
                                std::uint64_t divisor) noexcept {
    if (!x64_instruction_semantics_detail::x86_context(instruction) ||
        (instruction.opcode != Opcode::div && instruction.opcode != Opcode::idiv) ||
        instruction.operands.size() != 1)
        return std::nullopt;
    const unsigned width = x64_instruction_semantics_detail::operand_width(instruction.operands[0]);
    if (width != 8 && width != 16 && width != 32 && width != 64)
        return std::nullopt;
    return evaluate_x86_divide(instruction.opcode == Opcode::div ? X86DivideKind::unsigned_divide
                                                                 : X86DivideKind::signed_divide,
                               dividend_low, dividend_high, divisor, width);
}

// Evaluate a decoded scalar arithmetic instruction using the values supplied
// for its destination and source. Returns nullopt for unrelated instructions,
// malformed operand shapes, or operands without an x86 scalar width.
inline std::optional<X86ArithmeticResult>
evaluate_x86_arithmetic_instruction(const Instruction &instruction,
                                    std::uint64_t lhs,
                                    std::uint64_t rhs,
                                    bool carry_or_borrow) noexcept {
    if (instruction.context.architecture != Architecture::x86 &&
        instruction.context.architecture != Architecture::x86_64)
        return std::nullopt;
    X86Arithmetic operation{};
    switch (instruction.opcode) {
    case Opcode::add: operation = X86Arithmetic::add; break;
    case Opcode::adc: operation = X86Arithmetic::adc; break;
    case Opcode::sub: operation = X86Arithmetic::sub; break;
    case Opcode::sbb: operation = X86Arithmetic::sbb; break;
    case Opcode::cmp: operation = X86Arithmetic::compare; break;
    case Opcode::bit_and: operation = X86Arithmetic::bit_and; break;
    case Opcode::bit_or: operation = X86Arithmetic::bit_or; break;
    case Opcode::bit_xor: operation = X86Arithmetic::bit_xor; break;
    case Opcode::test: operation = X86Arithmetic::test; break;
    default: return std::nullopt;
    }
    if (instruction.operands.size() < 2)
        return std::nullopt;
    const auto width = std::visit([](const auto &operand) -> unsigned {
        using T = std::decay_t<decltype(operand)>;
        if constexpr (std::is_same_v<T, RegisterOperand>)
            return operand.bank == RegisterBank::gpr ? operand.width : 0;
        else if constexpr (std::is_same_v<T, MemoryOperand>)
            return operand.data_width;
        else
            return 0;
    }, instruction.operands.front());
    if (width != 8 && width != 16 && width != 32 && width != 64)
        return std::nullopt;
    return evaluate_x86_arithmetic(operation, lhs, rhs, carry_or_borrow, width);
}

// Evaluate a decoded scalar shift/rotate. The caller supplies the destination
// value and, for CL/register-count forms, its runtime count. Memory is never
// read here; its decoded width only supplies the operation width.
inline std::optional<X86ShiftRotateResult>
evaluate_x86_shift_rotate_instruction(const Instruction &instruction,
                                      std::uint64_t destination,
                                      std::optional<std::uint8_t> runtime_count = std::nullopt,
                                      X86Flags incoming = {},
                                      X86DefinedFlag incoming_auxiliary = {}) noexcept {
    if (!x64_instruction_semantics_detail::x86_context(instruction) || instruction.operands.size() != 2)
        return std::nullopt;
    X86ShiftRotate operation{};
    switch (instruction.opcode) {
    case Opcode::shl: operation = X86ShiftRotate::shl; break;
    case Opcode::shr: operation = X86ShiftRotate::shr; break;
    case Opcode::sar: operation = X86ShiftRotate::sar; break;
    case Opcode::rol: operation = X86ShiftRotate::rol; break;
    case Opcode::ror: operation = X86ShiftRotate::ror; break;
    case Opcode::rcl: operation = X86ShiftRotate::rcl; break;
    case Opcode::rcr: operation = X86ShiftRotate::rcr; break;
    default: return std::nullopt;
    }
    const auto width = x64_instruction_semantics_detail::operand_width(instruction.operands[0]);
    if (!x86_semantics_detail::supported_width(width))
        return std::nullopt;
    std::uint8_t count = 0;
    if (const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[1])) {
        if (immediate->effective_width != 8)
            return std::nullopt;
        count = static_cast<std::uint8_t>(immediate->value);
    } else if (const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[1])) {
        if (reg->bank != RegisterBank::gpr || reg->index != 1 || reg->width != 8 || reg->high_byte ||
            !runtime_count)
            return std::nullopt;
        count = *runtime_count;
    } else {
        return std::nullopt;
    }
    return evaluate_x86_shift_rotate(operation, destination, count, width, incoming, incoming_auxiliary);
}

// Evaluate a decoded SHLD/SHRD. The caller supplies the values read from the
// destination and ModRM register source; immediate counts come from the
// instruction and CL counts must be supplied at runtime. This helper does not
// perform memory access or modify architectural state.
inline std::optional<X86DoubleShiftResult>
evaluate_x86_double_shift_instruction(const Instruction &instruction,
                                      std::uint64_t destination,
                                      std::uint64_t source,
                                      std::optional<std::uint8_t> runtime_count = std::nullopt) noexcept {
    using namespace x64_instruction_semantics_detail;
    if (!x86_context(instruction) || instruction.operands.size() != 3 ||
        (instruction.opcode != Opcode::shld && instruction.opcode != Opcode::shrd))
        return std::nullopt;

    const unsigned width = operand_width(instruction.operands[0]);
    if ((width != 16 && width != 32 && width != 64) ||
        (width == 64 && instruction.context.mode != ExecutionMode::x86_64) ||
        operand_width(instruction.operands[1]) != width ||
        !std::holds_alternative<RegisterOperand>(instruction.operands[1]))
        return std::nullopt;
    const auto *destination_register = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *destination_memory = std::get_if<MemoryOperand>(&instruction.operands[0]);
    const auto *source_register = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if ((!destination_register && !destination_memory) ||
        (destination_register && destination_register->bank != RegisterBank::gpr) ||
        !source_register || source_register->bank != RegisterBank::gpr)
        return std::nullopt;

    std::uint8_t count = 0;
    if (const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2])) {
        if (immediate->effective_width != 8)
            return std::nullopt;
        count = static_cast<std::uint8_t>(immediate->value);
    } else if (const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[2])) {
        if (reg->bank != RegisterBank::gpr || reg->index != 1 || reg->width != 8 ||
            reg->high_byte || !runtime_count)
            return std::nullopt;
        count = *runtime_count;
    } else {
        return std::nullopt;
    }
    return evaluate_x86_double_shift(instruction.opcode == Opcode::shld, destination, source, count, width);
}

// Evaluate the value written by a decoded MOV-family instruction. The caller
// supplies a runtime value for register or memory sources; immediate values
// are taken directly from the decoded instruction.
inline std::optional<std::uint64_t>
evaluate_x86_data_move_instruction(const Instruction &instruction,
                                   std::optional<std::uint64_t> runtime_source = std::nullopt) noexcept {
    if (instruction.context.architecture != Architecture::x86 &&
        instruction.context.architecture != Architecture::x86_64)
        return std::nullopt;
    const bool zero_extend = instruction.opcode == Opcode::movzx;
    const bool sign_extend = instruction.opcode == Opcode::movsx || instruction.opcode == Opcode::movsxd;
    if (instruction.opcode != Opcode::mov && !zero_extend && !sign_extend)
        return std::nullopt;
    if (instruction.operands.size() != 2)
        return std::nullopt;
    if ((zero_extend || sign_extend) &&
        (!std::holds_alternative<RegisterOperand>(instruction.operands[0]) ||
         !std::holds_alternative<RegisterOperand>(instruction.operands[1]) &&
             !std::holds_alternative<MemoryOperand>(instruction.operands[1])))
        return std::nullopt;
    if (instruction.opcode == Opcode::movsxd && instruction.context.mode != ExecutionMode::x86_64)
        return std::nullopt;

    const auto scalar_width = [](const Operand &operand) -> unsigned {
        return std::visit([](const auto &value) -> unsigned {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, RegisterOperand>)
                return value.bank == RegisterBank::gpr ? value.width : 0;
            else if constexpr (std::is_same_v<T, MemoryOperand>)
                return value.data_width;
            else if constexpr (std::is_same_v<T, ImmediateOperand>)
                return value.effective_width;
            else
                return 0;
        }, operand);
    };
    const unsigned destination_width = scalar_width(instruction.operands[0]);
    const unsigned source_width = scalar_width(instruction.operands[1]);
    if ((destination_width != 8 && destination_width != 16 && destination_width != 32 && destination_width != 64) ||
        (source_width != 8 && source_width != 16 && source_width != 32 && source_width != 64))
        return std::nullopt;

    std::uint64_t source = 0;
    if (const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[1]))
        source = immediate->value;
    else if (runtime_source)
        source = *runtime_source;
    else
        return std::nullopt;

    const std::uint64_t source_mask = source_width == 64 ? UINT64_MAX : (std::uint64_t{1} << source_width) - 1;
    const std::uint64_t destination_mask =
        destination_width == 64 ? UINT64_MAX : (std::uint64_t{1} << destination_width) - 1;
    source &= source_mask;

    if (instruction.opcode == Opcode::mov) {
        // MOV transfers equal-sized scalar operands; immediate operands carry
        // their effective width, including C7's imm32-to-r64 sign extension.
        if (source_width != destination_width)
            return std::nullopt;
        return source & destination_mask;
    }
    if (std::holds_alternative<ImmediateOperand>(instruction.operands[1]))
        return std::nullopt;
    if (source_width >= destination_width || (instruction.opcode == Opcode::movsxd &&
                                               (source_width != 32 || destination_width != 64)))
        return std::nullopt;
    if (zero_extend)
        return source & destination_mask;

    const std::uint64_t source_sign = std::uint64_t{1} << (source_width - 1);
    if (source & source_sign)
        source |= ~source_mask;
    return source & destination_mask;
}

} // namespace hexlab
