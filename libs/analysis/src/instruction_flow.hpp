#pragma once
#include "hexlab/processors/decoder.hpp"
#include "hexlab/image/image.hpp"
namespace hexlab::analysis_detail {
inline bool is_arm_literal_pc_load(const Instruction &instruction) {
    if (instruction.context.architecture != Architecture::arm ||
        instruction.context.mode != ExecutionMode::a32 || instruction.opcode != Opcode::a32_ldr ||
        (instruction.flow != FlowKind::jump && instruction.flow != FlowKind::conditional_branch) ||
        !instruction.arm || !instruction.arm->writes_pc ||
        instruction.operands.size() != 2)
        return false;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *memory = std::get_if<ArmMemoryOperand>(&instruction.operands[1]);
    const auto *offset = memory ? std::get_if<std::uint32_t>(&memory->offset) : nullptr;
    return destination && destination->bank == RegisterBank::arm32_gpr && destination->index == 15 &&
           memory && memory->base.bank == RegisterBank::arm32_gpr && memory->base.index == 15 && offset &&
           memory->pre_index && !memory->writeback && memory->data_width == 32 && !memory->sign_extend &&
           memory->resolved_address.has_value() && instruction.arm->exchange == ArmExchange::address_bit0;
}
inline bool is_mips_branch_likely(const Instruction &instruction) {
    switch (instruction.opcode) {
    case Opcode::mips_beql: case Opcode::mips_bnel: case Opcode::mips_blezl:
    case Opcode::mips_bgtzl: case Opcode::mips_bltzl: case Opcode::mips_bgezl:
    case Opcode::mips_bc1tl: case Opcode::mips_bc1fl:
    case Opcode::mips64_bc1tl: case Opcode::mips64_bc1fl:
        return true;
    default:
        return false;
    }
}
inline bool supports_automatic_flow(DecodeContext context) {
    if (context.architecture == Architecture::arm)
        return context.mode == ExecutionMode::a32 || context.mode == ExecutionMode::thumb ||
               context.mode == ExecutionMode::unknown;
    return processor_capabilities(context).can_decode;
}
inline bool supports_automatic_flow(const Image &image) {
    if (image.layout().execution_profile)
        return std::any_of(image.layout().execution_profile->ranges.begin(), image.layout().execution_profile->ranges.end(),
                           [](const auto &range) { return supports_automatic_flow(range.context); });
    return supports_automatic_flow(image.decode_context());
}
inline bool has_delay_slot(const Instruction &instruction) {
    return (instruction.context.architecture == Architecture::mips32 ||
            instruction.context.architecture == Architecture::mips64) && instruction.delay_slots == 1 &&
           instruction.flow != FlowKind::fallthrough;
}
inline Result<Address> delay_slot_address(const Instruction &instruction) {
    if (!has_delay_slot(instruction))
        return Error{ErrorCode::unsupported, "Instruction has no modeled delay slot"};
    if (instruction.context.architecture == Architecture::mips32 &&
        instruction.address.offset > UINT32_MAX - instruction.byte_length())
        return Error{ErrorCode::out_of_bounds, "MIPS32 delay slot exceeds its 32-bit address domain"};
    if (instruction.context.architecture == Architecture::mips64 &&
        instruction.address.offset > UINT64_MAX - instruction.byte_length())
        return Error{ErrorCode::out_of_bounds, "MIPS64 delay slot exceeds its 64-bit address domain"};
    return Address{instruction.address.space, instruction.address.offset + instruction.byte_length()};
}
inline Result<Address> continuation_address(const Instruction &instruction) {
    const auto &context = instruction.context;
    if (!supports_automatic_flow(context))
        return Error{ErrorCode::unsupported, "Instruction continuation requires a supported processor context"};
    if (context.architecture == Architecture::x86 &&
        (context.mode == ExecutionMode::x86_16 || context.mode == ExecutionMode::x86_32)) {
        if (instruction.address.offset > UINT32_MAX)
            return Error{ErrorCode::out_of_bounds, "Instruction exceeds its 32-bit address domain"};
        auto next = static_cast<uint32_t>(instruction.address.offset + instruction.byte_length());
        // CALL continuation models the pushed return IP. A 16-bit near CALL
        // returns to low IP16; an untaken 16-bit conditional branch keeps EIP32.
        if (instruction.flow == FlowKind::call && instruction.stack_value_width == 16)
            next &= 0xffff;
        return Address{instruction.address.space, next};
    }
    if (context.architecture == Architecture::x86_64 && context.mode == ExecutionMode::x86_64)
        return advance(instruction.address, instruction.byte_length());
    if (context.architecture == Architecture::arm64 && context.mode == ExecutionMode::a64)
        return advance(instruction.address, instruction.byte_length());
    if (context.architecture == Architecture::arm &&
        (context.mode == ExecutionMode::a32 || context.mode == ExecutionMode::thumb))
        return advance(instruction.address, instruction.byte_length());
    if ((context.architecture == Architecture::riscv64 &&
         (context.mode == ExecutionMode::rv64 || context.mode == ExecutionMode::rv64c)) ||
        (context.architecture == Architecture::riscv32 && context.mode == ExecutionMode::rv32))
        return advance(instruction.address, instruction.byte_length());
    if (context.architecture == Architecture::powerpc && context.mode == ExecutionMode::ppc32)
        return Address{instruction.address.space,
                       static_cast<std::uint32_t>(instruction.address.offset + instruction.byte_length())};
    if (context.architecture == Architecture::powerpc && context.mode == ExecutionMode::ppc64)
        return advance(instruction.address, instruction.byte_length());
    if (context.architecture == Architecture::mips32 && context.mode == ExecutionMode::mips32) {
        const auto extra = has_delay_slot(instruction) ? 4u : 0u;
        if (instruction.address.offset > UINT32_MAX - instruction.byte_length() - extra)
            return Error{ErrorCode::out_of_bounds, "MIPS continuation exceeds its 32-bit address domain"};
        return Address{instruction.address.space, instruction.address.offset + instruction.byte_length() + extra};
    }
    if (context.architecture == Architecture::mips64 && context.mode == ExecutionMode::mips64) {
        const auto extra = has_delay_slot(instruction) ? 4u : 0u;
        if (instruction.address.offset > UINT64_MAX - instruction.byte_length() - extra)
            return Error{ErrorCode::out_of_bounds, "MIPS64 continuation exceeds its address domain"};
        return Address{instruction.address.space, instruction.address.offset + instruction.byte_length() + extra};
    }
    if (context.architecture == Architecture::mos6502 && context.mode == ExecutionMode::m6502)
        return Address{instruction.address.space,
                       static_cast<std::uint16_t>(instruction.address.offset + instruction.byte_length())};
    if (context.architecture == Architecture::dex && context.mode == ExecutionMode::dex) {
        if (instruction.address.offset > UINT32_MAX - instruction.byte_length())
            return Error{ErrorCode::out_of_bounds, "DEX continuation exceeds its method address space"};
        return Address{instruction.address.space, instruction.address.offset + instruction.byte_length()};
    }
    return Error{ErrorCode::unsupported, "Instruction continuation requires a supported processor context"};
}
} // namespace hexlab::analysis_detail
