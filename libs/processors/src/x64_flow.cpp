#include "x64_internal.hpp"

namespace hexlab::x64_detail {
namespace {
void stack(State &s, bool read, bool write, std::uint16_t value_width = 0) {
    s.i.stack_value_width = value_width ? value_width : s.stack_width();
    s.i.stack_slot_count = 1;
    s.i.register_reads.push_back(gpr(4, s.rules.stack_address_width()));
    s.i.register_writes.push_back(gpr(4, s.rules.stack_address_width()));
    if (!s.rules.long_mode() && (s.rules.segmented_memory() || s.rules.context.stack_address_width))
        s.i.register_reads.push_back({RegisterBank::segment, 2, 16, false});
    s.i.memory_read |= read;
    s.i.memory_write |= write;
}
void branch(State &s, Opcode opcode, unsigned bytes, FlowKind flow) {
    s.i.opcode = opcode;
    s.i.flow = flow;
    std::optional<EncodedField> field;
    const auto displacement = sign_value(s.encoded(bytes, field), bytes * 8);
    s.operand(RelativeOperand{displacement, static_cast<std::uint16_t>(bytes * 8),
                              s.rules.near_width(s.operand_override), field},
              OperandAccess::read);
    if (flow == FlowKind::call)
        stack(s, false, true, s.rules.near_width(s.operand_override));
}
} // namespace
bool stack_flow(State &s, std::uint8_t opcode, bool extended) {
    if (extended) {
        if (opcode >= 0x40 && opcode <= 0x4f) {
            auto m = modrm(s, s.width());
            s.i.opcode = Opcode::cmovcc;
            s.i.condition = opcode & 15;
            s.i.x86_condition = static_cast<X86Condition>(s.i.condition);
            s.operand(m.reg, OperandAccess::read_write);
            s.operand(m.rm, OperandAccess::read);
            s.flags_read = true;
        } else if (opcode >= 0x90 && opcode <= 0x9f) {
            auto m = modrm(s, 8);
            s.i.opcode = Opcode::setcc;
            s.i.condition = opcode & 15;
            s.i.x86_condition = static_cast<X86Condition>(s.i.condition);
            s.operand(m.rm, OperandAccess::write);
            s.flags_read = true;
        } else if (opcode >= 0x80 && opcode <= 0x8f) {
            branch(s, Opcode::jcc, s.rules.near_displacement_bytes(s.operand_override), FlowKind::conditional_branch);
            s.i.condition = opcode & 15;
            s.i.x86_condition = static_cast<X86Condition>(s.i.condition);
            s.flags_read = true;
        } else if (opcode == 0xa2) {
            s.i.opcode = Opcode::cpuid;
            s.i.register_reads.push_back(gpr(0, 32)); // EAX leaf selector.
            s.i.register_reads.push_back(gpr(1, 32)); // ECX subleaf selector.
            for (const auto index : {0u, 3u, 1u, 2u}) {
                const auto result = gpr(index, 32);
                // A 32-bit GPR write clears its upper half in long mode.
                if (s.rules.long_mode()) s.i.register_writes.push_back(gpr(index, 64));
                s.i.register_writes.push_back(result);
            }
        } else if (opcode == 0x1f) {
            auto m = modrm(s, s.width());
            if (m.group != 0)
                unsupported("Multi-byte NOP extension is not covered");
            s.i.opcode = Opcode::nop;
            s.operand(m.rm, OperandAccess::address);
        } else if (opcode == 0x1e && s.group1 == 0xf3) {
            auto variant = s.take(1);
            if (variant == 0xfa)
                s.i.opcode = Opcode::endbr64;
            else if (variant == 0xfb && !s.rules.long_mode())
                s.i.opcode = Opcode::endbr32;
            else
                unsupported("ENDBR variant is not covered in this mode");
        } else
            return false;
        return true;
    }
    if (opcode == 0xf5 || opcode == 0xf8 || opcode == 0xf9 || opcode == 0xfc || opcode == 0xfd) {
        // These instructions replace one bit of the FLAGS value. Keep the
        // unaffected bits as an explicit input to the whole-register model.
        s.i.opcode = Opcode::x86_flag_control;
        switch (opcode) {
        case 0xf5: s.i.mnemonic_override = "cmc"; break;
        case 0xf8: s.i.mnemonic_override = "clc"; break;
        case 0xf9: s.i.mnemonic_override = "stc"; break;
        case 0xfc: s.i.mnemonic_override = "cld"; break;
        case 0xfd: s.i.mnemonic_override = "std"; break;
        }
        s.flags_read = true;
        s.flags_write = true;
    } else if (opcode == 0x60 || opcode == 0x61) {
        if (s.rules.long_mode())
            invalid("PUSHA/POPA are invalid in 64-bit mode");
        const auto width = s.stack_width();
        const bool push_all = opcode == 0x60;
        s.i.opcode = push_all ? Opcode::pusha : Opcode::popa;
        stack(s, !push_all, push_all, width);
        s.i.stack_slot_count = 8;
        if (push_all) {
            // PUSHA records the pre-decrement stack pointer in the fifth slot.
            for (std::uint8_t index = 0; index < 8; ++index)
                s.i.register_reads.push_back(gpr(index, width));
        } else {
            // POPA consumes the saved SP slot but discards its value.
            for (const std::uint8_t index : {std::uint8_t{7}, std::uint8_t{6}, std::uint8_t{5},
                                             std::uint8_t{3}, std::uint8_t{2}, std::uint8_t{1}, std::uint8_t{0}})
                s.i.register_writes.push_back(gpr(index, width));
        }
    } else if (opcode == 0x9c || opcode == 0x9d) {
        const bool pop_flags = opcode == 0x9d;
        const auto width = s.stack_width();
        s.i.opcode = pop_flags ? Opcode::popf : Opcode::pushf;
        stack(s, pop_flags, !pop_flags, width);
        auto &registers = pop_flags ? s.i.register_writes : s.i.register_reads;
        registers.push_back({RegisterBank::flags, 0, width, false});
    } else if (opcode == 0x9e) {
        // SAHF consumes AH and defines the arithmetic condition flags. Keep it
        // in the x87 semantic family so FSW -> FNSTSW AX -> SAHF can be
        // recognized as one bounded comparison-result chain by the lifter.
        s.i.opcode = Opcode::x87;
        s.i.mnemonic_override = "sahf";
        s.i.register_reads.push_back({RegisterBank::gpr, 0, 8, true});
        s.i.register_reads.push_back({RegisterBank::flags, 0, s.rules.pointer_width(), false});
        s.i.register_writes.push_back({RegisterBank::flags, 0, s.rules.pointer_width(), false});
    } else if (opcode == 0x9f) {
        // LAHF copies SF/ZF/AF/PF/CF to AH and leaves FLAGS unchanged.
        s.i.opcode = Opcode::lahf;
        s.i.register_reads.push_back({RegisterBank::flags, 0, s.rules.pointer_width(), false});
        s.i.register_writes.push_back({RegisterBank::gpr, 0, 8, true});
    } else if (opcode == 0xc8) {
        const auto width = s.stack_width();
        std::optional<EncodedField> allocation_field, level_field;
        const auto allocation = s.encoded(2, allocation_field);
        const auto encoded_level = static_cast<std::uint8_t>(s.encoded(1, level_field));
        const auto level = static_cast<std::uint8_t>(encoded_level & 0x1f);
        s.i.opcode = Opcode::enter;
        s.operand(ImmediateOperand{allocation, 16, 16, false, allocation_field}, OperandAccess::read);
        s.operand(ImmediateOperand{encoded_level, 8, 8, false, level_field}, OperandAccess::read);
        stack(s, level > 1, true, width);
        s.i.stack_slot_count = static_cast<std::uint8_t>(level ? level + 1 : 1);
        s.i.register_reads.push_back(gpr(5, width));
        s.i.register_writes.push_back(gpr(5, width));
    } else if (opcode >= 0x50 && opcode <= 0x5f) {
        const bool pop = opcode >= 0x58;
        s.i.opcode = pop ? Opcode::pop : Opcode::push;
        s.operand(s.reg(opcode & 7, s.stack_width(), (s.rex & 1) != 0),
                  pop ? OperandAccess::write : OperandAccess::read);
        stack(s, pop, !pop);
    } else if (opcode == 0x68 || opcode == 0x6a) {
        s.i.opcode = Opcode::push;
        s.operand(s.immediate(opcode == 0x6a          ? 8
                              : s.stack_width() == 16 ? 16
                                                      : 32,
                              s.stack_width(), true),
                  OperandAccess::read);
        stack(s, false, true);
    } else if (opcode == 0x8f) {
        if ((s.peek() & 31) >= 8)
            unsupported("XOP map is not covered");
        auto m = modrm(s, s.stack_width());
        if (m.group != 0)
            unsupported("POP extension is not covered");
        s.i.opcode = Opcode::pop;
        s.operand(m.rm, OperandAccess::write);
        stack(s, true, false);
    } else if (opcode == 0xff) {
        const auto group = (s.peek() >> 3) & 7;
        if (group == 3 || group == 5) {
            if (s.rules.long_mode())
                unsupported("Long-mode far indirect transfers are not covered");
            if ((s.peek() >> 6) == 3)
                invalid("Far indirect transfer requires a memory pointer");
            const auto offset_width = s.rules.near_width(s.operand_override);
            auto m = modrm(s, static_cast<std::uint16_t>(offset_width + 16), offset_width);
            s.i.opcode = group == 3 ? Opcode::call : Opcode::jmp;
            s.i.flow = group == 3 ? FlowKind::call : FlowKind::jump;
            s.operand(FarMemoryOperand{std::get<MemoryOperand>(m.rm), offset_width}, OperandAccess::read);
            s.i.register_writes.push_back({RegisterBank::segment, 1, 16, false});
            if (group == 3) {
                stack(s, false, true, offset_width);
                s.i.stack_slot_count = 2;
                s.i.register_reads.push_back({RegisterBank::segment, 1, 16, false});
            }
            return true;
        }
        if (group != 2 && group != 4 && group != 6)
            return false;
        auto m = modrm(s, group == 6 ? s.stack_width() : s.rules.near_width(s.operand_override));
        s.i.opcode = group == 2 ? Opcode::call : group == 4 ? Opcode::jmp : Opcode::push;
        s.i.flow = group == 2 ? FlowKind::call : group == 4 ? FlowKind::jump : FlowKind::fallthrough;
        s.operand(m.rm, OperandAccess::read);
        if (group != 4)
            stack(s, false, true, group == 2 ? s.rules.near_width(s.operand_override) : s.stack_width());
    } else if (opcode == 0xc9) {
        s.i.opcode = Opcode::leave;
        s.i.stack_value_width = s.stack_width();
        s.i.stack_slot_count = 1;
        s.i.register_reads.push_back(gpr(5, s.rules.stack_address_width()));
        s.i.register_writes.push_back(gpr(4, s.rules.stack_address_width()));
        s.i.register_writes.push_back(gpr(5, s.stack_width()));
        s.i.memory_read = true;
        if (!s.rules.long_mode() && (s.rules.segmented_memory() || s.rules.context.stack_address_width))
            s.i.register_reads.push_back({RegisterBank::segment, 2, 16, false});
    } else if (opcode == 0x9a || opcode == 0xea) {
        if (s.rules.long_mode())
            invalid("Immediate far transfers are invalid in64-bit mode");
        const auto offset_width = s.rules.near_width(s.operand_override);
        std::optional<EncodedField> offset_field, selector_field;
        const auto offset = static_cast<std::uint32_t>(s.encoded(offset_width / 8, offset_field));
        const auto selector = static_cast<std::uint16_t>(s.encoded(2, selector_field));
        s.i.opcode = opcode == 0x9a ? Opcode::call : Opcode::jmp;
        s.i.flow = opcode == 0x9a ? FlowKind::call : FlowKind::jump;
        s.operand(FarPointerOperand{selector, offset, offset_width, offset_field, selector_field}, OperandAccess::read);
        s.i.register_writes.push_back({RegisterBank::segment, 1, 16, false});
        if (opcode == 0x9a) {
            stack(s, false, true, offset_width);
            s.i.stack_slot_count = 2;
            s.i.register_reads.push_back({RegisterBank::segment, 1, 16, false});
        }
    } else if (opcode == 0xe8 || opcode == 0xe9 || opcode == 0xeb)
        branch(s, opcode == 0xe8 ? Opcode::call : Opcode::jmp,
               opcode == 0xeb ? 1 : s.rules.near_displacement_bytes(s.operand_override),
               opcode == 0xe8 ? FlowKind::call : FlowKind::jump);
    else if (opcode >= 0x70 && opcode <= 0x7f) {
        branch(s, Opcode::jcc, 1, FlowKind::conditional_branch);
        s.i.condition = opcode & 15;
        s.i.x86_condition = static_cast<X86Condition>(s.i.condition);
        s.flags_read = true;
    } else if (opcode >= 0xe0 && opcode <= 0xe3) {
        // LOOP/LOOPE/LOOPNE and JCXZ/JECXZ/JRCXZ use address size for the
        // counter register. The branch displacement remains rel8.
        const auto width = s.rules.address_width(s.address_override);
        s.i.opcode = Opcode::x86_loop;
        s.i.flow = FlowKind::conditional_branch;
        s.i.x86_loop_condition = opcode == 0xe0 ? X86LoopCondition::counter_nonzero_and_not_zero
                                  : opcode == 0xe1 ? X86LoopCondition::counter_nonzero_and_zero
                                  : opcode == 0xe2 ? X86LoopCondition::counter_nonzero
                                                   : X86LoopCondition::counter_zero;
        s.i.x86_loop_counter_width = width;
        const RegisterOperand counter{RegisterBank::gpr, 1, width, false};
        s.i.register_reads.push_back(counter);
        if (opcode != 0xe3) {
            s.i.register_writes.push_back(counter);
            const auto full_width = s.rules.pointer_width();
            if (width < full_width) {
                const RegisterOperand full_counter{RegisterBank::gpr, 1, full_width, false};
                // A 16-bit counter update preserves the wider register's high
                // bits; a 32-bit long-mode update clears the high half.
                if (width == 16) s.i.register_reads.push_back(full_counter);
                s.i.register_writes.push_back(full_counter);
            }
        }
        if (opcode == 0xe0 || opcode == 0xe1)
            s.flags_read = true;
        std::optional<EncodedField> field;
        const auto displacement = sign_value(s.encoded(1, field), 8);
        s.operand(RelativeOperand{displacement, 8, s.rules.near_width(s.operand_override), field}, OperandAccess::read);
    } else if (opcode == 0xc2 || opcode == 0xc3) {
        s.i.opcode = Opcode::ret;
        s.i.flow = FlowKind::ret;
        stack(s, true, false, s.rules.near_width(s.operand_override));
        if (opcode == 0xc2)
            s.operand(s.immediate(16, 16, false), OperandAccess::read);
    } else if (opcode == 0xca || opcode == 0xcb) {
        if (s.rules.long_mode())
            unsupported("Long-mode far returns are not covered");
        s.i.opcode = Opcode::retf;
        s.i.flow = FlowKind::ret;
        stack(s, true, false, s.rules.near_width(s.operand_override));
        s.i.stack_slot_count = 2;
        s.i.register_writes.push_back({RegisterBank::segment, 1, 16, false});
        if (opcode == 0xca)
            s.operand(s.immediate(16, 16, false), OperandAccess::read);
    } else if (opcode == 0xcc) {
        s.i.opcode = Opcode::int3;
        s.i.flow = FlowKind::trap;
    } else if (opcode >= 0x90 && opcode <= 0x97) {
        const auto register_index = static_cast<std::uint8_t>(opcode & 7);
        const bool extended_register = (s.rex & 1) != 0;
        if (opcode == 0x90 && !extended_register) {
            s.i.opcode = s.group1 == 0xf3 ? Opcode::pause : Opcode::nop;
        } else {
            if (opcode == 0x90 && s.group1 == 0xf3)
                unsupported("REP-prefixed extended accumulator XCHG is not covered");
            s.i.opcode = Opcode::xchg;
            s.operand(gpr(0, s.width()), OperandAccess::read_write);
            s.operand(s.reg(register_index, s.width(), extended_register), OperandAccess::read_write);
        }
    } else
        return false;
    return true;
}
} // namespace hexlab::x64_detail
