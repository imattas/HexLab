#include "a64_internal.hpp"
namespace hexlab::a64_detail {
namespace {
void relative(Instruction &i, std::uint32_t bits, unsigned width) {
    const auto displacement = signed_value(bits, width) * 4;
    operand(i, RelativeOperand{displacement, static_cast<std::uint16_t>(width), 64, {}}, OperandAccess::read);
    i.direct_target = target(i.address, displacement);
}
} // namespace
bool flow(Instruction &i, std::uint32_t word) {
    if ((word & 0x7c000000u) == 0x14000000u) {
        const bool link = (word >> 31) != 0;
        i.opcode = link ? Opcode::a64_bl : Opcode::a64_b;
        i.flow = link ? FlowKind::call : FlowKind::jump;
        relative(i, word & 0x3ffffffu, 26);
        if (link)
            i.register_writes.push_back(reg(30));
    } else if ((word & 0xff000010u) == 0x54000000u) {
        i.opcode = Opcode::a64_b_cond;
        i.flow = FlowKind::conditional_branch;
        i.condition = static_cast<std::uint8_t>(word & 15);
        if (i.condition >= 14)
            i.flow = FlowKind::jump;
        // AL/NV do not depend on NZCV.
        if (i.condition < 14)
            i.register_reads.push_back(nzcv);
        relative(i, (word >> 5) & 0x7ffffu, 19);
    } else if ((word & 0x7e000000u) == 0x34000000u) {
        i.opcode = (word & 0x01000000u) ? Opcode::a64_cbnz : Opcode::a64_cbz;
        i.flow = FlowKind::conditional_branch;
        operand(i, reg(word & 31, (word >> 31) ? 64 : 32), OperandAccess::read);
        relative(i, (word >> 5) & 0x7ffffu, 19);
    } else if ((word & 0x7e000000u) == 0x36000000u) {
        const auto bit = ((word >> 26) & 32) | ((word >> 19) & 31);
        i.opcode = (word & 0x01000000u) ? Opcode::a64_tbnz : Opcode::a64_tbz;
        i.flow = FlowKind::conditional_branch;
        operand(i, reg(word & 31, bit >= 32 ? 64 : 32), OperandAccess::read);
        immediate(i, bit, 6, 6);
        relative(i, (word >> 5) & 0x3fffu, 14);
    } else if ((word & 0xfffffc1fu) == 0xd61f0000u || (word & 0xfffffc1fu) == 0xd63f0000u ||
               (word & 0xfffffc1fu) == 0xd65f0000u) {
        const auto kind = word & 0xfffffc1fu;
        i.opcode = kind == 0xd61f0000u ? Opcode::a64_br : kind == 0xd63f0000u ? Opcode::a64_blr : Opcode::a64_ret;
        i.flow = kind == 0xd61f0000u ? FlowKind::jump : kind == 0xd63f0000u ? FlowKind::call : FlowKind::ret;
        operand(i, reg((word >> 5) & 31), OperandAccess::read);
        if (i.flow == FlowKind::call)
            i.register_writes.push_back(reg(30));
    } else if ((word & 0xffe0001fu) == 0xd4200000u) {
        i.opcode = Opcode::a64_brk;
        i.flow = FlowKind::trap;
        immediate(i, (word >> 5) & 0xffff, 16, 16);
    } else if (word == 0xd503201fu) {
        i.opcode = Opcode::a64_nop;
    } else {
        return false;
    }
    return true;
}
} // namespace hexlab::a64_detail
