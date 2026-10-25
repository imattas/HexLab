#include "arm32_internal.hpp"
#include <algorithm>
namespace hexlab::arm32_detail {
namespace {
RegisterOperand gpr(unsigned n) { return {RegisterBank::arm32_gpr, static_cast<std::uint8_t>(n), 32, false}; }
void read(Instruction &i, RegisterOperand r) {
    if (std::find(i.register_reads.begin(), i.register_reads.end(), r) == i.register_reads.end())
        i.register_reads.push_back(r);
}
bool multiple(Instruction &i, std::uint32_t w) {
    const auto rn = (w >> 16) & 15;
    const auto mask = static_cast<std::uint16_t>(w);
    const bool load = w & 0x100000, wb = w & 0x200000, up = w & 0x800000, pre = w & 0x1000000;
    if ((w & 0x400000) || rn == 15 || !mask || (wb && (mask & (1u << rn))))
        return false; // Privileged/user-bank, empty list and base overlap not enabled.
    i.opcode = load ? Opcode::a32_ldm : Opcode::a32_stm;
    i.arm->multiple_mode =
        up ? (pre ? ArmMultipleMode::ib : ArmMultipleMode::ia) : (pre ? ArmMultipleMode::db : ArmMultipleMode::da);
    i.arm->writeback = wb;
    i.operands.emplace_back(gpr(rn));
    i.operands.emplace_back(ArmRegisterListOperand{mask});
    i.access = {wb ? OperandAccess::read_write : OperandAccess::read,
                load ? OperandAccess::write : OperandAccess::read};
    read(i, gpr(rn));
    for (unsigned n = 0; n < 16; ++n)
        if (mask & (1u << n)) {
            if (load)
                i.register_writes.push_back(gpr(n));
            else
                read(i, gpr(n));
        }
    if (wb)
        i.register_writes.push_back(gpr(rn));
    i.memory_read = load;
    i.memory_write = !load;
    if (load && (mask & 0x8000)) {
        i.arm->writes_pc = true;
        i.arm->exchange = ArmExchange::address_bit0;
        i.flow = rn == 13 && up && !pre && wb ? FlowKind::ret
                 : i.condition < 14                 ? FlowKind::conditional_branch
                                                    : FlowKind::jump;
    }
    return true;
}
} // namespace
bool memory(Instruction &i, std::uint32_t w) {
    if ((w & 0x0e000000) == 0x08000000)
        return multiple(i, w);
    const bool ordinary = (w & 0x0c000000) == 0x04000000;
    const bool extra = (w & 0x0e000090) == 0x00000090 && (w & 0x60);
    if (!ordinary && !extra)
        return false;
    const bool load = w & 0x100000, pre = w & 0x1000000, up = w & 0x800000;
    const bool explicit_wb = w & 0x200000, wb = !pre || explicit_wb;
    const auto rn = (w >> 16) & 15, rt = (w >> 12) & 15;
    const bool immediate = ordinary ? !(w & 0x2000000) : (w & 0x400000) != 0;
    const auto extra_kind = (w >> 5) & 3;
    const auto width = ordinary ? (w & 0x400000 ? 8u : 32u) : extra_kind == 2 ? 8u : 16u;
    const bool sign = extra && extra_kind >= 2;
    if ((!pre && explicit_wb) || (wb && (rn == 15 || rn == rt)) || (rt == 15 && width != 32) ||
        (rn == 15 && (!immediate || !load)) || (sign && !load))
        return false;
    ArmMemoryOperand memory{gpr(rn)};
    memory.add = up;
    memory.pre_index = pre;
    memory.writeback = wb;
    memory.data_width = static_cast<std::uint16_t>(width);
    memory.sign_extend = sign;
    if (immediate) {
        const auto offset = ordinary ? w & 0xfff : ((w >> 4) & 0xf0) | (w & 15);
        memory.offset = offset;
        if (rn == 15) {
            const auto target = static_cast<std::int64_t>(i.address.offset) + 8 +
                                (up ? static_cast<std::int64_t>(offset) : -static_cast<std::int64_t>(offset));
            if (target >= 0 && target <= UINT32_MAX)
                memory.resolved_address = Address{i.address.space, static_cast<std::uint64_t>(target)};
        }
    } else {
        const auto rm = w & 15;
        if (rm == 15 || (ordinary ? (w & 0x10) != 0 : (w & 0xf00) != 0))
            return false;
        auto shift = ordinary ? static_cast<ArmShift>((w >> 5) & 3) : ArmShift::lsl;
        auto amount = static_cast<std::uint8_t>(ordinary ? (w >> 7) & 31 : 0);
        if (!amount && ordinary) {
            if (shift == ArmShift::lsr || shift == ArmShift::asr)
                amount = 32;
            else if (shift == ArmShift::ror) {
                shift = ArmShift::rrx;
                amount = 1;
            }
        }
        memory.offset = ArmShiftedRegisterOperand{gpr(rm), shift, amount, {}};
    }
    i.opcode = ordinary ? (width == 8 ? (load ? Opcode::a32_ldrb : Opcode::a32_strb)
                                      : (load ? Opcode::a32_ldr : Opcode::a32_str))
               : sign   ? (width == 8 ? Opcode::a32_ldrsb : Opcode::a32_ldrsh)
               : load   ? Opcode::a32_ldrh
                        : Opcode::a32_strh;
    i.operands.emplace_back(gpr(rt));
    i.operands.emplace_back(memory);
    i.access = {load ? OperandAccess::write : OperandAccess::read, load ? OperandAccess::read : OperandAccess::write};
    if (load)
        i.register_writes.push_back(gpr(rt));
    else
        read(i, gpr(rt));
    read(i, gpr(rn));
    if (const auto shifted = std::get_if<ArmShiftedRegisterOperand>(&memory.offset)) {
        read(i, shifted->source);
        if (shifted->shift == ArmShift::rrx)
            read(i, {RegisterBank::arm_flags, 0, 4, false});
    }
    if (wb)
        i.register_writes.push_back(gpr(rn));
    i.arm->writeback = wb;
    i.memory_read = load;
    i.memory_write = !load;
    if (load && rt == 15) {
        i.arm->writes_pc = true;
        i.arm->exchange = ArmExchange::address_bit0;
        i.flow = i.condition < 14 ? FlowKind::conditional_branch : FlowKind::jump;
    }
    return true;
}
} // namespace hexlab::arm32_detail
