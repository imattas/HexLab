#pragma once

#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/x64_semantics.hpp"
#include <algorithm>
#include <functional>
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

// Validate the typed hardware-random instruction before evaluating a caller-
// supplied sample/availability pair. The value is the printed destination slice;
// callers merge 16-bit partial writes and zero-extend 32-bit long-mode writes.
inline std::optional<X86RandomResult> evaluate_x86_random_instruction(
    const Instruction &instruction, std::uint64_t sample, bool available,
    std::uint64_t incoming_flags) noexcept {
    const bool long_mode = instruction.context.architecture == Architecture::x86_64 &&
        instruction.context.mode == ExecutionMode::x86_64;
    const bool legacy = instruction.context.architecture == Architecture::x86 &&
        (instruction.context.mode == ExecutionMode::x86_16 || instruction.context.mode == ExecutionMode::x86_32);
    if ((!long_mode && !legacy) || (instruction.opcode != Opcode::rdrand && instruction.opcode != Opcode::rdseed) ||
        instruction.flow != FlowKind::fallthrough || instruction.lock_prefix || instruction.memory_read ||
        instruction.memory_write || instruction.operands.size() != 1 || instruction.access.size() != 1 ||
        instruction.access[0] != OperandAccess::write || instruction.x86_repeat != X86RepeatPrefix::none)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    if (!destination || destination->bank != RegisterBank::gpr || destination->high_byte ||
        destination->index >= (long_mode ? 16 : 8) ||
        (destination->width != 16 && destination->width != 32 && !(long_mode && destination->width == 64)))
        return std::nullopt;
    const auto full_width = static_cast<std::uint16_t>(long_mode ? 64 :
        instruction.context.mode == ExecutionMode::x86_16 ? 16 : 32);
    const RegisterOperand flags{RegisterBank::flags, 0, full_width, false};
    const RegisterOperand full{RegisterBank::gpr, destination->index, full_width, false};
    std::vector<RegisterOperand> reads, writes;
    if (destination->width < full_width) {
        if (destination->width == 16) reads.push_back(full);
        writes.push_back(full);
    }
    reads.push_back(flags);
    writes.push_back(*destination);
    writes.push_back(flags);
    if (instruction.register_reads != reads || instruction.register_writes != writes) return std::nullopt;
    auto result = evaluate_x86_random(sample, available, destination->width, incoming_flags);
    if (result && full_width != 64) result->flags &= (UINT64_C(1) << full_width) - 1;
    return result;
}

struct X86ExchangeResult {
    std::uint64_t first_value = 0;
    std::uint64_t second_value = 0;
    std::uint8_t width = 0;
    bool operator==(const X86ExchangeResult &) const = default;
};

// Evaluate register-register XCHG. Memory forms are rejected because their
// atomic memory effects are outside this pure register evaluator.
inline std::optional<X86ExchangeResult> evaluate_x86_exchange_instruction(
    const Instruction &instruction, std::uint64_t first_value,
    std::uint64_t second_value) noexcept {
    using namespace x64_instruction_semantics_detail;
    if (!x86_context(instruction) || instruction.opcode != Opcode::xchg ||
        instruction.flow != FlowKind::fallthrough || instruction.memory_read || instruction.memory_write ||
        instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::read_write || instruction.access[1] != OperandAccess::read_write)
        return std::nullopt;
    const auto *first = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *second = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if (!first || !second || first->bank != RegisterBank::gpr || second->bank != RegisterBank::gpr ||
        first->width != second->width || (first->width != 8 && first->width != 16 &&
        first->width != 32 && first->width != 64) || (first->width == 64 &&
        instruction.context.architecture != Architecture::x86_64))
        return std::nullopt;
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_reads, *first) || !has(instruction.register_reads, *second) ||
        !has(instruction.register_writes, *first) || !has(instruction.register_writes, *second))
        return std::nullopt;
    const auto mask = x86_semantics_detail::mask_for(first->width);
    if (*first == *second && ((first_value ^ second_value) & mask) != 0)
        return std::nullopt;
    return X86ExchangeResult{second_value & mask, first_value & mask,
                             static_cast<std::uint8_t>(first->width)};
}

struct X86XaddResult {
    std::uint64_t destination_value = 0;
    std::uint64_t source_value = 0;
    X86Flags flags{};
    std::uint8_t width = 0;
    bool writes_source = true;
    bool operator==(const X86XaddResult &) const = default;
};

// Evaluate register-register XADD. Memory-destination and locked atomic forms
// are caller-owned and rejected; a source/destination alias writes only the sum.
inline std::optional<X86XaddResult> evaluate_x86_xadd_instruction(
    const Instruction &instruction, std::uint64_t old_destination,
    std::uint64_t old_source) noexcept {
    using namespace x64_instruction_semantics_detail;
    if (!x86_context(instruction) || instruction.opcode != Opcode::xadd ||
        instruction.flow != FlowKind::fallthrough || instruction.memory_read || instruction.memory_write ||
        instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::read_write || instruction.access[1] != OperandAccess::read_write)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *source = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if (!destination || !source || destination->bank != RegisterBank::gpr || source->bank != RegisterBank::gpr ||
        destination->width != source->width || (destination->width != 8 && destination->width != 16 &&
        destination->width != 32 && destination->width != 64) ||
        (destination->width == 64 && instruction.context.architecture != Architecture::x86_64))
        return std::nullopt;
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    const bool writes_flags = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
        [](const RegisterOperand &reg) { return reg.bank == RegisterBank::flags && reg.index == 0; });
    if (!has(instruction.register_reads, *destination) || !has(instruction.register_reads, *source) ||
        !has(instruction.register_writes, *destination) || !has(instruction.register_writes, *source) ||
        !writes_flags)
        return std::nullopt;
    const auto mask = x86_semantics_detail::mask_for(destination->width);
    old_destination &= mask;
    old_source &= mask;
    const auto arithmetic = evaluate_x86_arithmetic(X86Arithmetic::add, old_destination, old_source,
                                                    false, destination->width);
    return X86XaddResult{arithmetic.value, old_destination, arithmetic.flags,
                         static_cast<std::uint8_t>(destination->width), *destination != *source};
}

struct X86CmpxchgResult {
    std::uint64_t destination_value = 0;
    std::uint64_t accumulator_value = 0;
    X86Flags flags{};
    std::uint8_t width = 0;
    bool matched = false;
    bool writes_destination = false;
    bool writes_accumulator = false;
    bool operator==(const X86CmpxchgResult &) const = default;
};

// Evaluate register-destination CMPXCHG. Memory/LOCK forms and aliases where
// the destination is the implicit accumulator are rejected.
inline std::optional<X86CmpxchgResult> evaluate_x86_cmpxchg_instruction(
    const Instruction &instruction, std::uint64_t old_accumulator,
    std::uint64_t old_destination, std::uint64_t source_value) noexcept {
    using namespace x64_instruction_semantics_detail;
    if (!x86_context(instruction) || instruction.opcode != Opcode::cmpxchg ||
        instruction.flow != FlowKind::fallthrough || instruction.memory_read || instruction.memory_write ||
        instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::read_write ||
        instruction.access[1] != OperandAccess::read)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *source = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if (!destination || !source || destination->bank != RegisterBank::gpr ||
        source->bank != RegisterBank::gpr || destination->width != source->width ||
        (destination->width != 8 && destination->width != 16 &&
         destination->width != 32 && destination->width != 64) ||
        (destination->width == 64 && instruction.context.architecture != Architecture::x86_64))
        return std::nullopt;
    const RegisterOperand accumulator{RegisterBank::gpr, 0, destination->width, false};
    if (*destination == accumulator) return std::nullopt;
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    const bool writes_flags = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
        [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
    if (!has(instruction.register_reads, *destination) ||
        !has(instruction.register_reads, *source) ||
        !has(instruction.register_reads, accumulator) ||
        !has(instruction.register_writes, *destination) ||
        !has(instruction.register_writes, accumulator) || !writes_flags)
        return std::nullopt;

    const auto mask = x86_semantics_detail::mask_for(destination->width);
    old_accumulator &= mask;
    old_destination &= mask;
    source_value &= mask;
    const auto comparison = evaluate_x86_arithmetic(X86Arithmetic::compare, old_accumulator,
                                                   old_destination, false, destination->width);
    const bool matched = old_accumulator == old_destination;
    return X86CmpxchgResult{matched ? source_value : old_destination,
                            matched ? old_accumulator : old_destination,
                            comparison.flags, static_cast<std::uint8_t>(destination->width),
                            matched, matched, !matched};
}

// Evaluate decoded CMPXCHG8B/16B using caller-supplied memory and implicit
// register-pair values. Memory access, faults, and LOCK atomicity remain the
// caller's responsibility.
inline std::optional<X86CmpxchgWideResult> evaluate_x86_cmpxchg_wide_instruction(
    const Instruction &instruction, std::uint64_t memory_low, std::uint64_t memory_high,
    std::uint64_t accumulator_low, std::uint64_t accumulator_high,
    std::uint64_t source_low, std::uint64_t source_high, X86Flags incoming) noexcept {
    using namespace x64_instruction_semantics_detail;
    const bool legacy = instruction.context.architecture == Architecture::x86 &&
        (instruction.context.mode == ExecutionMode::x86_16 || instruction.context.mode == ExecutionMode::x86_32);
    const bool long_mode = instruction.context.architecture == Architecture::x86_64 &&
        instruction.context.mode == ExecutionMode::x86_64;
    const bool wide = instruction.opcode == Opcode::cmpxchg16b;
    if ((!legacy && !long_mode) ||
        (instruction.opcode != Opcode::cmpxchg8b && !wide) || (wide && !long_mode) ||
        instruction.flow != FlowKind::fallthrough || instruction.operands.size() != 1 ||
        instruction.access.size() != 1 || instruction.access[0] != OperandAccess::read_write ||
        !instruction.memory_read || !instruction.memory_write)
        return std::nullopt;
    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[0]);
    const unsigned pair_width = wide ? 64 : 32;
    if (!memory || memory->data_width != pair_width * 2) return std::nullopt;
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    const RegisterOperand accumulator_low_reg{RegisterBank::gpr, 0, static_cast<std::uint16_t>(pair_width), false};
    const RegisterOperand accumulator_high_reg{RegisterBank::gpr, 2, static_cast<std::uint16_t>(pair_width), false};
    const RegisterOperand source_low_reg{RegisterBank::gpr, 3, static_cast<std::uint16_t>(pair_width), false};
    const RegisterOperand source_high_reg{RegisterBank::gpr, 1, static_cast<std::uint16_t>(pair_width), false};
    const auto flags_width = static_cast<std::uint16_t>(long_mode ? 64 :
        instruction.context.mode == ExecutionMode::x86_16 ? 16 : 32);
    const RegisterOperand flags{RegisterBank::flags, 0, flags_width, false};
    for (const auto reg : {accumulator_low_reg, accumulator_high_reg, source_low_reg, source_high_reg})
        if (!has(instruction.register_reads, reg)) return std::nullopt;
    if (!has(instruction.register_reads, flags) ||
        instruction.register_writes != std::vector<RegisterOperand>{
            accumulator_low_reg, accumulator_high_reg, flags}) return std::nullopt;
    return evaluate_x86_cmpxchg_wide(pair_width, memory_low, memory_high,
        accumulator_low, accumulator_high, source_low, source_high, incoming);
}

// Caller supplies the runtime destination/source values (memory reads are
// intentionally outside this pure evaluator). Validate the decoded operand
// effects before applying either independent ADX carry chain.
inline std::optional<X86AdxResult> evaluate_x86_adx_instruction(
    const Instruction &instruction, std::uint64_t destination, std::uint64_t source,
    X86Flags incoming) noexcept {
    using namespace x64_instruction_semantics_detail;
    if (!x86_context(instruction) ||
        (instruction.opcode != Opcode::adcx && instruction.opcode != Opcode::adox) ||
        instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::read_write ||
        instruction.access[1] != OperandAccess::read)
        return std::nullopt;
    const auto *destination_operand = std::get_if<RegisterOperand>(&instruction.operands[0]);
    if (!destination_operand || destination_operand->bank != RegisterBank::gpr ||
        destination_operand->high_byte ||
        (destination_operand->width != 32 && destination_operand->width != 64) ||
        (destination_operand->width == 64 && instruction.context.mode != ExecutionMode::x86_64) ||
        operand_width(instruction.operands[1]) != destination_operand->width)
        return std::nullopt;
    if (const auto *source_register = std::get_if<RegisterOperand>(&instruction.operands[1])) {
        if (source_register->bank != RegisterBank::gpr || source_register->high_byte)
            return std::nullopt;
    } else if (!std::holds_alternative<MemoryOperand>(instruction.operands[1])) {
        return std::nullopt;
    }
    const bool reads_flags = std::any_of(instruction.register_reads.begin(), instruction.register_reads.end(),
        [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
    const bool writes_flags = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
        [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
    if (!reads_flags || !writes_flags) return std::nullopt;
    return evaluate_x86_adx(instruction.opcode == Opcode::adcx ? X86Adx::carry : X86Adx::overflow,
                            destination, source, incoming, destination_operand->width);
}

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

// SAHF replaces only CF/PF/AF/ZF/SF from AH and preserves every other FLAGS
// bit. The decoder represents SAHF in the x87 opcode family so its existing
// bounded FNSTSW/SAHF comparison-chain recognition can consume the instruction.
inline std::uint64_t evaluate_x86_sahf(std::uint64_t flags, std::uint8_t ah) noexcept {
    constexpr std::uint64_t status_mask = 0xd5u;
    return (flags & ~status_mask) | (static_cast<std::uint64_t>(ah) & status_mask);
}

inline std::optional<std::uint64_t> evaluate_x86_sahf_instruction(const Instruction &instruction,
                                                                  std::uint64_t flags,
                                                                  std::uint8_t ah) noexcept {
    if (!x64_instruction_semantics_detail::x86_context(instruction) || instruction.opcode != Opcode::x87 ||
        instruction.mnemonic_override != "sahf")
        return std::nullopt;
    const bool reads_ah = std::any_of(instruction.register_reads.begin(), instruction.register_reads.end(),
        [](RegisterOperand reg) { return reg.bank == RegisterBank::gpr && reg.index == 0 &&
                                         reg.width == 8 && reg.high_byte; });
    const auto written_flags = std::find_if(instruction.register_writes.begin(), instruction.register_writes.end(),
        [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
    if (!reads_ah || written_flags == instruction.register_writes.end() ||
        (written_flags->width != 16 && written_flags->width != 32 && written_flags->width != 64))
        return std::nullopt;
    return evaluate_x86_sahf(flags, ah) & x86_semantics_detail::mask_for(written_flags->width);
}

// Evaluate CLC/STC/CMC, CLI/STI, and CLD/STD against the prior whole FLAGS value.
// The decoder retains the specific mnemonic as an override on the shared
// x86 semantic opcode so the operation remains visible to formatters.
inline std::optional<std::uint64_t> evaluate_x86_flag_control_instruction(
    const Instruction &instruction, std::uint64_t flags) noexcept {
    if (!x64_instruction_semantics_detail::x86_context(instruction) ||
        instruction.opcode != Opcode::x86_flag_control)
        return std::nullopt;
    const bool reads_flags = std::any_of(instruction.register_reads.begin(), instruction.register_reads.end(),
        [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
    const auto written_flags = std::find_if(instruction.register_writes.begin(), instruction.register_writes.end(),
        [](RegisterOperand reg) { return reg.bank == RegisterBank::flags; });
    if (!reads_flags || written_flags == instruction.register_writes.end() ||
        (written_flags->width != 16 && written_flags->width != 32 && written_flags->width != 64))
        return std::nullopt;

    constexpr std::uint64_t carry = 1u;
    constexpr std::uint64_t interrupt_enable = 1u << 9;
    constexpr std::uint64_t direction = 1u << 10;
    if (instruction.mnemonic_override == "clc") flags &= ~carry;
    else if (instruction.mnemonic_override == "stc") flags |= carry;
    else if (instruction.mnemonic_override == "cmc") flags ^= carry;
    else if (instruction.mnemonic_override == "cli") flags &= ~interrupt_enable;
    else if (instruction.mnemonic_override == "sti") flags |= interrupt_enable;
    else if (instruction.mnemonic_override == "cld") flags &= ~direction;
    else if (instruction.mnemonic_override == "std") flags |= direction;
    else return std::nullopt;
    return flags & x86_semantics_detail::mask_for(written_flags->width);
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

// Evaluate the register value produced by BSWAP. The decoder already resolves
// the architectural width (including REX.W in long mode); 32-bit results are
// zero-extended as required by x86-64 GPR writes.
inline std::optional<std::uint64_t> evaluate_x86_bswap_instruction(
    const Instruction &instruction, std::uint64_t source) noexcept {
    using namespace x64_instruction_semantics_detail;
    if (!x86_context(instruction) || instruction.opcode != Opcode::bswap ||
        instruction.operands.size() != 1 || instruction.access.size() != 1 ||
        instruction.access[0] != OperandAccess::read_write)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    if (!destination || destination->bank != RegisterBank::gpr || destination->high_byte ||
        (destination->width != 32 && destination->width != 64) ||
        (destination->width == 64 && instruction.context.mode != ExecutionMode::x86_64))
        return std::nullopt;
    const unsigned bytes = destination->width / 8;
    std::uint64_t result = 0;
    for (unsigned index = 0; index < bytes; ++index)
        result |= ((source >> (index * 8)) & 0xffu) << ((bytes - index - 1) * 8);
    return result;
}

struct X86SignExtendAccumulatorResult {
    std::uint64_t accumulator_value = 0;
    std::uint64_t high_value = 0;
    std::uint8_t width = 0;
    bool writes_accumulator = false;
    bool writes_high = false;
    bool operator==(const X86SignExtendAccumulatorResult &) const = default;
};

// Evaluate implicit accumulator sign-extension forms used to prepare a
// signed dividend. The caller commits whichever implicit registers are written.
inline std::optional<X86SignExtendAccumulatorResult>
evaluate_x86_sign_extend_accumulator_instruction(const Instruction &instruction,
                                                  std::uint64_t accumulator) noexcept {
    using namespace x64_instruction_semantics_detail;
    if (!x86_context(instruction) || instruction.flow != FlowKind::fallthrough ||
        !instruction.operands.empty() || !instruction.access.empty() ||
        instruction.memory_read || instruction.memory_write)
        return std::nullopt;
    unsigned input_width = 0, output_width = 0;
    bool writes_accumulator = false;
    bool writes_high = false;
    switch (instruction.opcode) {
    case Opcode::cbw: input_width = 8; output_width = 16; writes_accumulator = true; break;
    case Opcode::cwde: input_width = 16; output_width = 32; writes_accumulator = true; break;
    case Opcode::cdqe: input_width = 32; output_width = 64; writes_accumulator = true; break;
    case Opcode::cwd: input_width = output_width = 16; writes_high = true; break;
    case Opcode::cdq: input_width = output_width = 32; writes_high = true; break;
    case Opcode::cqo: input_width = output_width = 64; writes_high = true; break;
    default: return std::nullopt;
    }
    if (output_width == 64 && instruction.context.mode != ExecutionMode::x86_64)
        return std::nullopt;
    const RegisterOperand input{RegisterBank::gpr, 0, static_cast<std::uint16_t>(input_width), false};
    const RegisterOperand destination{RegisterBank::gpr, 0, static_cast<std::uint16_t>(output_width), false};
    const RegisterOperand high{RegisterBank::gpr, 2, static_cast<std::uint16_t>(output_width), false};
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_reads, input) ||
        (writes_accumulator && !has(instruction.register_writes, destination)) ||
        (writes_high && !has(instruction.register_writes, high)))
        return std::nullopt;
    const auto input_mask = input_width == 64 ? UINT64_MAX : (UINT64_C(1) << input_width) - 1;
    const auto output_mask = output_width == 64 ? UINT64_MAX : (UINT64_C(1) << output_width) - 1;
    const auto source = accumulator & input_mask;
    const bool negative = (source & (UINT64_C(1) << (input_width - 1))) != 0;
    std::uint64_t accumulator_value = source;
    std::uint64_t high_value = 0;
    if (writes_accumulator && negative) accumulator_value |= ~input_mask;
    if (writes_accumulator) accumulator_value &= output_mask;
    if (writes_high && negative) high_value = output_mask;
    return X86SignExtendAccumulatorResult{accumulator_value, high_value,
        static_cast<std::uint8_t>(output_width), writes_accumulator, writes_high};
}

// Evaluate the byte written by SETcc from caller-supplied flags. Memory writes
// are validated as decoded facts but remain caller-owned.
inline std::optional<std::uint8_t> evaluate_x86_setcc_instruction(
    const Instruction &instruction, X86Flags flags) noexcept {
    using namespace x64_instruction_semantics_detail;
    if (!x86_context(instruction) || instruction.opcode != Opcode::setcc ||
        !instruction.x86_condition || instruction.flow != FlowKind::fallthrough ||
        instruction.operands.size() != 1 || instruction.access.size() != 1 ||
        instruction.access[0] != OperandAccess::write || instruction.memory_read)
        return std::nullopt;
    if (const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[0])) {
        if (reg->bank != RegisterBank::gpr || reg->width != 8 || instruction.memory_write ||
            std::find(instruction.register_writes.begin(), instruction.register_writes.end(), *reg) ==
                instruction.register_writes.end()) return std::nullopt;
    } else if (const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[0])) {
        if (memory->data_width != 8 || !instruction.memory_write || !instruction.register_writes.empty())
            return std::nullopt;
    } else {
        return std::nullopt;
    }
    return static_cast<std::uint8_t>(evaluate_x86_condition(*instruction.x86_condition, flags));
}

// Evaluate decoded CMOVcc. The source value is supplied even when the
// condition is false because memory sources are architecturally read either way.
inline std::optional<std::uint64_t> evaluate_x86_cmovcc_instruction(
    const Instruction &instruction, std::uint64_t old_destination,
    std::uint64_t source, X86Flags flags) noexcept {
    using namespace x64_instruction_semantics_detail;
    if (!x86_context(instruction) || instruction.opcode != Opcode::cmovcc ||
        !instruction.x86_condition || instruction.flow != FlowKind::fallthrough ||
        instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::read_write ||
        instruction.access[1] != OperandAccess::read || instruction.memory_write)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    if (!destination || destination->bank != RegisterBank::gpr || destination->high_byte ||
        (destination->width != 16 && destination->width != 32 && destination->width != 64) ||
        (destination->width == 64 && instruction.context.mode != ExecutionMode::x86_64) ||
        std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *destination) ==
            instruction.register_reads.end() ||
        std::find(instruction.register_writes.begin(), instruction.register_writes.end(), *destination) ==
            instruction.register_writes.end())
        return std::nullopt;
    unsigned source_width = 0;
    if (const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[1])) {
        if (reg->bank != RegisterBank::gpr || reg->width != destination->width || reg->high_byte ||
            instruction.memory_read ||
            std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *reg) ==
                instruction.register_reads.end())
            return std::nullopt;
        source_width = reg->width;
    } else if (const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1])) {
        if (memory->data_width != destination->width || !instruction.memory_read) return std::nullopt;
        source_width = memory->data_width;
    } else {
        return std::nullopt;
    }
    const unsigned architectural_width = instruction.context.mode == ExecutionMode::x86_64 ? 64u : 32u;
    const auto architectural_mask = architectural_width == 64 ? UINT64_MAX : UINT64_C(0xffffffff);
    old_destination &= architectural_mask;
    if (!evaluate_x86_condition(*instruction.x86_condition, flags)) return old_destination;
    const auto source_mask = source_width == 64 ? UINT64_MAX : (UINT64_C(1) << source_width) - 1;
    if (source_width == 64) return source & source_mask;
    if (source_width == 32 && instruction.context.mode == ExecutionMode::x86_64)
        return source & source_mask; // A taken W-style GPR write clears the upper half.
    const auto destination_mask = source_mask;
    return (old_destination & ~destination_mask) | (source & destination_mask);
}

// Compute LEA's effective offset for base/index forms with 32/64-bit address
// sizes. This does not read the addressed memory or apply segment bases.
inline std::optional<std::uint64_t> evaluate_x86_lea_instruction(
    const Instruction &instruction,
    const std::function<std::optional<std::uint64_t>(const RegisterOperand &)> &read_register) {
    using namespace x64_instruction_semantics_detail;
    if (!x86_context(instruction) || instruction.opcode != Opcode::lea ||
        instruction.flow != FlowKind::fallthrough || instruction.operands.size() != 2 ||
        instruction.access.size() != 2 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::address || instruction.memory_read ||
        instruction.memory_write || !read_register)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
    if (!destination || !memory || destination->bank != RegisterBank::gpr || destination->high_byte ||
        (destination->width != 16 && destination->width != 32 && destination->width != 64) ||
        memory->data_width != destination->width ||
        (destination->width == 64 && instruction.context.mode != ExecutionMode::x86_64) ||
        (memory->address_width != 32 && memory->address_width != 64) || memory->ip_relative ||
        (memory->scale != 1 && memory->scale != 2 && memory->scale != 4 && memory->scale != 8))
        return std::nullopt;
    const auto valid_address_register = [memory](const std::optional<RegisterOperand> &reg) {
        return !reg || (reg->bank == RegisterBank::gpr && reg->width == memory->address_width &&
                        !reg->high_byte);
    };
    if (!valid_address_register(memory->base) || !valid_address_register(memory->index))
        return std::nullopt;
    const auto address_mask = memory->address_width == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    std::uint64_t effective = static_cast<std::uint64_t>(memory->displacement);
    if (memory->base) {
        const auto value = read_register(*memory->base);
        if (!value) return std::nullopt;
        effective += *value & address_mask;
    }
    if (memory->index) {
        const auto value = read_register(*memory->index);
        if (!value) return std::nullopt;
        effective += (*value & address_mask) * memory->scale;
    }
    effective &= address_mask;
    const auto destination_mask = destination->width == 64 ? UINT64_MAX :
        (UINT64_C(1) << destination->width) - 1;
    return effective & destination_mask;
}

struct X86AamAadResult {
    std::uint8_t al = 0;
    std::uint8_t ah = 0;
    std::uint64_t flags_value = 0;
    std::uint64_t flags_defined_mask = 0; // PF/ZF/SF; AF/CF/OF are undefined.
    bool divide_error = false; // AAM with radix zero does not retire.
    bool operator==(const X86AamAadResult &) const = default;
};

// Evaluate the byte results and defined SF/ZF/PF bits of decoded legacy AAM
// or AAD. AAM's zero radix reports a divide error with no committed byte or
// flag results. Radix and byte inputs are caller-supplied decoded/runtime data.
inline std::optional<X86AamAadResult> evaluate_x86_aam_aad_instruction(
    const Instruction &instruction, std::uint8_t al, std::uint8_t ah) noexcept {
    if ((instruction.context.architecture != Architecture::x86 &&
         instruction.context.architecture != Architecture::x86_64) ||
        (instruction.context.mode != ExecutionMode::x86_16 &&
         instruction.context.mode != ExecutionMode::x86_32) ||
        (instruction.opcode != Opcode::aam && instruction.opcode != Opcode::aad) ||
        instruction.operands.size() != 1 || instruction.access.size() != 1 ||
        instruction.access[0] != OperandAccess::read)
        return std::nullopt;
    const auto *radix = std::get_if<ImmediateOperand>(&instruction.operands[0]);
    if (!radix || radix->encoded_width != 8 || radix->effective_width != 8 ||
        radix->is_signed || radix->value > 0xff)
        return std::nullopt;
    const RegisterOperand al_register{RegisterBank::gpr, 0, 8, false};
    const RegisterOperand ah_register{RegisterBank::gpr, 0, 8, true};
    const auto contains = [](const auto &registers, RegisterOperand value) {
        return std::find(registers.begin(), registers.end(), value) != registers.end();
    };
    const auto flags_width = instruction.context.mode == ExecutionMode::x86_16 ? 16u : 32u;
    const bool writes_flags = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
        [&](RegisterOperand reg) { return reg.bank == RegisterBank::flags && reg.width == flags_width; });
    if (!contains(instruction.register_reads, al_register) ||
        !contains(instruction.register_writes, al_register) ||
        !contains(instruction.register_writes, ah_register) ||
        !writes_flags ||
        (instruction.opcode == Opcode::aad && !contains(instruction.register_reads, ah_register)) ||
        (instruction.opcode == Opcode::aam && contains(instruction.register_reads, ah_register)))
        return std::nullopt;

    const auto base = static_cast<std::uint8_t>(radix->value);
    X86AamAadResult result;
    if (instruction.opcode == Opcode::aam) {
        if (!base) {
            result.divide_error = true;
            return result;
        }
        result.al = static_cast<std::uint8_t>(al % base);
        result.ah = static_cast<std::uint8_t>(al / base);
    } else {
        result.al = static_cast<std::uint8_t>(static_cast<unsigned>(al) +
                                               static_cast<unsigned>(ah) * base);
        result.ah = 0;
    }
    constexpr std::uint64_t pf = UINT64_C(1) << 2;
    constexpr std::uint64_t zf = UINT64_C(1) << 6;
    constexpr std::uint64_t sf = UINT64_C(1) << 7;
    result.flags_defined_mask = pf | zf | sf;
    if ((std::popcount(result.al) & 1) == 0) result.flags_value |= pf;
    if (!result.al) result.flags_value |= zf;
    if (result.al & 0x80u) result.flags_value |= sf;
    return result;
}

struct X86DaaDasResult {
    std::uint8_t al = 0;
    std::uint64_t flags_value = 0;
    std::uint64_t flags_defined_mask = 0; // CF/AF/PF/ZF/SF; OF is undefined.
    bool operator==(const X86DaaDasResult &) const = default;
};

// Evaluate decoded legacy DAA/DAS using AL and the incoming AF/CF bits. The
// returned flags contain only defined outputs; callers must keep OF unknown.
inline std::optional<X86DaaDasResult> evaluate_x86_daa_das_instruction(
    const Instruction &instruction, std::uint8_t al, std::uint64_t incoming_flags) noexcept {
    if ((instruction.context.architecture != Architecture::x86 &&
         instruction.context.architecture != Architecture::x86_64) ||
        (instruction.context.mode != ExecutionMode::x86_16 &&
         instruction.context.mode != ExecutionMode::x86_32) ||
        (instruction.opcode != Opcode::daa && instruction.opcode != Opcode::das) ||
        instruction.length != 1 || instruction.bytes[0] !=
            std::byte{static_cast<std::uint8_t>(instruction.opcode == Opcode::daa ? 0x27 : 0x2f)} ||
        !instruction.operands.empty() || !instruction.access.empty())
        return std::nullopt;
    const RegisterOperand al_register{RegisterBank::gpr, 0, 8, false};
    const auto contains = [](const auto &registers, RegisterOperand value) {
        return std::find(registers.begin(), registers.end(), value) != registers.end();
    };
    const auto flags_width = instruction.context.mode == ExecutionMode::x86_16 ? 16u : 32u;
    const RegisterOperand flags_register{RegisterBank::flags, 0, static_cast<std::uint16_t>(flags_width), false};
    if (!contains(instruction.register_reads, al_register) ||
        !contains(instruction.register_writes, al_register) ||
        !contains(instruction.register_reads, flags_register) ||
        !contains(instruction.register_writes, flags_register))
        return std::nullopt;

    constexpr std::uint64_t cf = UINT64_C(1) << 0;
    constexpr std::uint64_t pf = UINT64_C(1) << 2;
    constexpr std::uint64_t af = UINT64_C(1) << 4;
    constexpr std::uint64_t zf = UINT64_C(1) << 6;
    constexpr std::uint64_t sf = UINT64_C(1) << 7;
    const bool subtract = instruction.opcode == Opcode::das;
    const bool adjust_low = (al & 0x0f) > 9 || (incoming_flags & af) != 0;
    const bool adjust_high = al > 0x99 || (incoming_flags & cf) != 0;
    unsigned adjusted = al;
    if (adjust_low) adjusted = subtract ? adjusted - 6u : adjusted + 6u;
    if (adjust_high) adjusted = subtract ? adjusted - 0x60u : adjusted + 0x60u;
    X86DaaDasResult result;
    result.al = static_cast<std::uint8_t>(adjusted);
    result.flags_defined_mask = cf | af | pf | zf | sf;
    if (adjust_high) result.flags_value |= cf;
    if (adjust_low) result.flags_value |= af;
    if ((std::popcount(result.al) & 1) == 0) result.flags_value |= pf;
    if (result.al == 0) result.flags_value |= zf;
    if (result.al & 0x80u) result.flags_value |= sf;
    return result;
}

struct X86PopcntResult {
    std::uint64_t value = 0;
    std::uint64_t flags = 0;
    bool operator==(const X86PopcntResult &) const = default;
};

// Evaluate a decoded POPCNT after its register or memory source has been read.
// POPCNT defines CF/PF/AF/ZF/SF/OF and preserves every other FLAGS bit.
inline std::optional<X86PopcntResult> evaluate_x86_popcnt_instruction(
    const Instruction &instruction, std::uint64_t source, std::uint64_t incoming_flags) noexcept {
    using namespace x64_instruction_semantics_detail;
    if (!x86_context(instruction) || instruction.opcode != Opcode::popcnt ||
        instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const unsigned width = destination && destination->bank == RegisterBank::gpr ? destination->width : 0;
    if (!destination || destination->high_byte || (width != 16 && width != 32 && width != 64) ||
        (instruction.context.mode != ExecutionMode::x86_16 &&
         instruction.context.mode != ExecutionMode::x86_32 && instruction.context.mode != ExecutionMode::x86_64) ||
        (width == 64 && instruction.context.mode != ExecutionMode::x86_64) ||
        operand_width(instruction.operands[1]) != width)
        return std::nullopt;
    const auto destination_write = std::find(instruction.register_writes.begin(), instruction.register_writes.end(),
                                             *destination);
    if (destination_write == instruction.register_writes.end()) return std::nullopt;
    if (const auto *source_register = std::get_if<RegisterOperand>(&instruction.operands[1])) {
        if (source_register->bank != RegisterBank::gpr || source_register->high_byte ||
            std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *source_register) ==
                instruction.register_reads.end()) return std::nullopt;
    } else if (!std::holds_alternative<MemoryOperand>(instruction.operands[1])) {
        return std::nullopt;
    } else if (!instruction.memory_read) {
        return std::nullopt;
    }
    const auto flag_register = [](RegisterOperand reg) {
        return reg.bank == RegisterBank::flags &&
            (reg.width == 16 || reg.width == 32 || reg.width == 64);
    };
    const auto incoming = std::find_if(instruction.register_reads.begin(), instruction.register_reads.end(), flag_register);
    const auto outgoing = std::find_if(instruction.register_writes.begin(), instruction.register_writes.end(), flag_register);
    const auto expected_flags_width = instruction.context.mode == ExecutionMode::x86_16 ? 16u :
        instruction.context.mode == ExecutionMode::x86_64 ? 64u : 32u;
    if (incoming == instruction.register_reads.end() || outgoing == instruction.register_writes.end() ||
        incoming->width != outgoing->width || outgoing->width != expected_flags_width)
        return std::nullopt;

    const std::uint64_t operand_mask = width == 64 ? UINT64_MAX : (UINT64_C(1) << width) - 1;
    constexpr std::uint64_t affected = (UINT64_C(1) << 0) | (UINT64_C(1) << 2) |
        (UINT64_C(1) << 4) | (UINT64_C(1) << 6) | (UINT64_C(1) << 7) | (UINT64_C(1) << 11);
    const std::uint64_t flags_mask = outgoing->width == 64 ? UINT64_MAX :
        (UINT64_C(1) << outgoing->width) - 1;
    const auto masked_source = source & operand_mask;
    X86PopcntResult result;
    result.value = static_cast<std::uint64_t>(std::popcount(masked_source));
    result.flags = (incoming_flags & ~affected) |
        (masked_source == 0 ? (UINT64_C(1) << 6) : 0);
    result.flags &= flags_mask;
    return result;
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

// BMI1 sources are caller-owned values in printed operand order (excluding
// the destination). Memory is neither read nor written by this evaluator.
inline std::optional<X86Bmi1Result>
evaluate_x86_bmi1_instruction(const Instruction &instruction, std::uint64_t source1,
                              std::optional<std::uint64_t> source2 = std::nullopt) noexcept {
    using namespace x64_instruction_semantics_detail;
    if (!x86_context(instruction) || instruction.context.mode != ExecutionMode::x86_64)
        return std::nullopt;
    X86Bmi1 operation;
    bool unary = false;
    switch (instruction.opcode) {
    case Opcode::andn: operation = X86Bmi1::andn; break;
    case Opcode::bextr: operation = X86Bmi1::bextr; break;
    case Opcode::blsi: operation = X86Bmi1::blsi; unary = true; break;
    case Opcode::blsmsk: operation = X86Bmi1::blsmsk; unary = true; break;
    case Opcode::blsr: operation = X86Bmi1::blsr; unary = true; break;
    default: return std::nullopt;
    }
    const unsigned count = unary ? 2 : 3;
    if ((!unary && !source2) || instruction.operands.size() != count || instruction.access.size() != count ||
        instruction.access[0] != OperandAccess::write)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    if (!destination || destination->bank != RegisterBank::gpr || destination->index > 15 ||
        destination->high_byte || (destination->width != 32 && destination->width != 64))
        return std::nullopt;
    const unsigned width = destination->width;
    for (unsigned index = 1; index < count; ++index) {
        if (instruction.access[index] != OperandAccess::read ||
            operand_width(instruction.operands[index]) != width)
            return std::nullopt;
        if (const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[index])) {
            if (reg->bank != RegisterBank::gpr || reg->index > 15 || reg->high_byte)
                return std::nullopt;
        } else if (!std::holds_alternative<MemoryOperand>(instruction.operands[index])) {
            return std::nullopt;
        }
        // Only ModRM.r/m may address memory: ANDN source2, all other source1.
        const bool register_only = !unary && index == (operation == X86Bmi1::andn ? 1u : 2u);
        if (register_only && !std::holds_alternative<RegisterOperand>(instruction.operands[index]))
            return std::nullopt;
    }
    return evaluate_x86_bmi1(operation, source1, source2.value_or(0), width);
}

// The caller supplies runtime values for the printed source and mask operands;
// memory reads and architectural dispatch/CPUID checks remain outside this pure adapter.
inline std::optional<X86Bmi2Result> evaluate_x86_bmi2_instruction(
    const Instruction &instruction, std::uint64_t source, std::uint64_t bit_mask) noexcept {
    using namespace x64_instruction_semantics_detail;
    if (!x86_context(instruction) ||
        (instruction.context.mode != ExecutionMode::x86_32 && instruction.context.mode != ExecutionMode::x86_64) ||
        (instruction.context.architecture == Architecture::x86 &&
         instruction.context.mode != ExecutionMode::x86_32) ||
        (instruction.context.architecture == Architecture::x86_64 &&
         instruction.context.mode != ExecutionMode::x86_64) ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read || instruction.access[2] != OperandAccess::read)
        return std::nullopt;
    X86Bmi2 operation;
    if (instruction.opcode == Opcode::pdep) operation = X86Bmi2::pdep;
    else if (instruction.opcode == Opcode::pext) operation = X86Bmi2::pext;
    else return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *source_reg = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if (!destination || !source_reg || destination->bank != RegisterBank::gpr ||
        source_reg->bank != RegisterBank::gpr || destination->high_byte || source_reg->high_byte ||
        destination->index > 15 || source_reg->index > 15 ||
        (instruction.context.architecture == Architecture::x86 &&
         (destination->index > 7 || source_reg->index > 7)) ||
        (destination->width != 32 && destination->width != 64) ||
        destination->width != source_reg->width || operand_width(instruction.operands[2]) != destination->width ||
        (destination->width == 64 && instruction.context.mode != ExecutionMode::x86_64))
        return std::nullopt;
    if (const auto *mask_reg = std::get_if<RegisterOperand>(&instruction.operands[2])) {
        if (mask_reg->bank != RegisterBank::gpr || mask_reg->high_byte || mask_reg->index > 15 ||
            (instruction.context.architecture == Architecture::x86 && mask_reg->index > 7))
            return std::nullopt;
    } else if (!std::holds_alternative<MemoryOperand>(instruction.operands[2])) {
        return std::nullopt;
    }
    return evaluate_x86_bmi2(operation, source, bit_mask, destination->width);
}

// Evaluate BMI2 SHLX/SHRX/SARX/RORX. The caller supplies the source value and,
// except for RORX, the count-register value; memory reads remain caller-owned.
inline std::optional<std::uint64_t> evaluate_x86_bmi2_shift_instruction(
    const Instruction &instruction, std::uint64_t source,
    std::uint64_t runtime_count = 0) noexcept {
    using namespace x64_instruction_semantics_detail;
    if (instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 ||
        instruction.flow != FlowKind::fallthrough || instruction.memory_write ||
        (instruction.opcode != Opcode::shlx && instruction.opcode != Opcode::shrx &&
         instruction.opcode != Opcode::sarx && instruction.opcode != Opcode::rorx) ||
        instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read)
        return std::nullopt;
    const bool immediate_count = instruction.opcode == Opcode::rorx;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const unsigned width = destination ? destination->width : 0;
    if (!destination || destination->bank != RegisterBank::gpr || destination->index > 15 || destination->high_byte ||
        (width != 32 && width != 64) || operand_width(instruction.operands[1]) != width ||
        (std::holds_alternative<MemoryOperand>(instruction.operands[1]) && !instruction.memory_read) ||
        (std::holds_alternative<RegisterOperand>(instruction.operands[1]) && instruction.memory_read))
        return std::nullopt;
    const auto *source_register = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if (source_register && (source_register->bank != RegisterBank::gpr || source_register->index > 15 ||
                            source_register->high_byte))
        return std::nullopt;
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    if (!has(instruction.register_writes, *destination) ||
        (source_register && !has(instruction.register_reads, *source_register)))
        return std::nullopt;
    std::uint64_t count = runtime_count;
    if (immediate_count) {
        const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
        if (!immediate || immediate->encoded_width != 8 || immediate->effective_width != 8 || immediate->is_signed)
            return std::nullopt;
        count = immediate->value;
    } else {
        const auto *count_register = std::get_if<RegisterOperand>(&instruction.operands[2]);
        if (!count_register || count_register->bank != RegisterBank::gpr || count_register->index > 15 ||
            count_register->width != width ||
            count_register->high_byte || !has(instruction.register_reads, *count_register))
            return std::nullopt;
    }
    const auto mask = x86_semantics_detail::mask_for(width);
    source &= mask;
    const unsigned shift = static_cast<unsigned>(count) & (width - 1);
    if (instruction.opcode == Opcode::shlx) return (source << shift) & mask;
    if (instruction.opcode == Opcode::shrx) return source >> shift;
    if (instruction.opcode == Opcode::rorx) {
        if (width == 32) return std::rotr(static_cast<std::uint32_t>(source), static_cast<int>(shift));
        return std::rotr(source, static_cast<int>(shift));
    }
    if (shift == 0) return source;
    auto result = source >> shift;
    if (source & (UINT64_C(1) << (width - 1)))
        result |= mask & ~((UINT64_C(1) << (width - shift)) - 1);
    return result & mask;
}

// Evaluate the scalar result and defined status flags for a decoded BZHI.
// Register and memory source values are supplied by the caller.
inline std::optional<X86BzhiResult> evaluate_x86_bzhi_instruction(
    const Instruction &instruction, std::uint64_t source, std::uint64_t index) noexcept {
    using namespace x64_instruction_semantics_detail;
    if (instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 ||
        instruction.flow != FlowKind::fallthrough || instruction.opcode != Opcode::bzhi ||
        instruction.memory_write || instruction.operands.size() != 3 || instruction.access.size() != 3 ||
        instruction.access[0] != OperandAccess::write || instruction.access[1] != OperandAccess::read ||
        instruction.access[2] != OperandAccess::read)
        return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *index_register = std::get_if<RegisterOperand>(&instruction.operands[2]);
    if (!destination || !index_register || destination->bank != RegisterBank::gpr ||
        destination->index > 15 || destination->high_byte ||
        (destination->width != 32 && destination->width != 64) ||
        index_register->bank != RegisterBank::gpr || index_register->index > 15 ||
        index_register->width != destination->width || index_register->high_byte ||
        operand_width(instruction.operands[1]) != destination->width)
        return std::nullopt;
    const auto has = [](const auto &registers, RegisterOperand reg) {
        return std::find(registers.begin(), registers.end(), reg) != registers.end();
    };
    const auto *source_register = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if (source_register && (source_register->bank != RegisterBank::gpr || source_register->index > 15 ||
                            source_register->high_byte))
        return std::nullopt;
    if ((std::holds_alternative<MemoryOperand>(instruction.operands[1]) && !instruction.memory_read) ||
        (source_register && instruction.memory_read) || !has(instruction.register_writes, *destination) ||
        !has(instruction.register_reads, *index_register) ||
        (source_register && !has(instruction.register_reads, *source_register)) ||
        !has(instruction.register_writes, {RegisterBank::flags, 0, 64, false}))
        return std::nullopt;
    return evaluate_x86_bzhi(source, index, destination->width);
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
