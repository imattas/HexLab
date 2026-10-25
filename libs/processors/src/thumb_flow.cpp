#include "thumb_internal.hpp"
#include <bit>
namespace hexlab::thumb_detail {
namespace {
void link(Instruction &i) {
    i.register_writes.push_back(reg(14));
    i.arm->return_mode = ExecutionMode::thumb;
    i.arm->link_address = target(i.address, i.length);
}
void branch(Instruction &i, std::int64_t displacement, unsigned width, bool call, bool exchange = false,
            bool explicit_condition = false) {
    i.opcode = exchange ? Opcode::t32_blx : call ? Opcode::t32_bl : Opcode::t32_b;
    i.flow = call                                                                ? FlowKind::call
             : explicit_condition || i.arm->predicate == ArmPredicate::condition ? FlowKind::conditional_branch
                                                                                 : FlowKind::jump;
    i.operands.emplace_back(ThumbRelativeOperand{displacement, static_cast<std::uint16_t>(width)});
    i.access.push_back(OperandAccess::read);
    const auto base = exchange ? Address{i.address.space, (i.address.offset + 4) & ~UINT64_C(3)} : i.address;
    i.direct_target = exchange ? target(base, displacement) : target(base, 4 + displacement);
    i.arm->writes_pc = true;
    i.arm->target_mode = exchange ? ExecutionMode::a32 : ExecutionMode::thumb;
    i.arm->exchange = exchange ? ArmExchange::forced_a32 : ArmExchange::none;
    if (call)
        link(i);
}
} // namespace
bool flow(Instruction &i, std::uint16_t h, std::optional<std::uint16_t> second) {
    if (second) {
        if ((h & 0xfff0) == 0xe8d0 && (*second & 0xffe0) == 0xf000) {
            const auto rn = h & 15, rm = *second & 15;
            if (rn == 13 || rm == 13 || rm == 15 || !i.arm->it_before.known)
                return false;
            const bool halfword = (*second & 0x10) != 0;
            const auto base = reg(rn), index = reg(rm);
            MemoryOperand table{static_cast<std::uint16_t>(halfword ? 16 : 8), 32, {}, base, index,
                                static_cast<std::uint8_t>(halfword ? 2 : 1), 0};
            i.opcode = halfword ? Opcode::arm_tbh : Opcode::arm_tbb;
            i.operands = {table};
            i.access = {OperandAccess::address};
            read(i, base);
            read(i, index);
            i.memory_read = true;
            i.flow = FlowKind::jump;
            i.arm->writes_pc = true;
            i.arm->target_mode = ExecutionMode::thumb;
            return true;
        }
        if ((h & 0xf800) != 0xf000)
            return false;
        const auto low = *second;
        const auto s = (h >> 10) & 1, j1 = (low >> 13) & 1, j2 = (low >> 11) & 1;
        const auto kind = low & 0xd000;
        if (kind == 0x8000) {
            const auto condition = (h >> 6) & 15;
            if (condition >= 14 || !i.arm->it_before.known || active(i))
                return false;
            i.condition = static_cast<std::uint8_t>(condition);
            i.arm->predicate = ArmPredicate::condition;
            read(i, flags);
            const auto bits = (s << 20) | (j2 << 19) | (j1 << 18) | ((h & 63) << 12) | ((low & 0x7ff) << 1);
            branch(i, signed_bits(bits, 21), 20, false, false, true);
            return true;
        }
        if (kind != 0x9000 && kind != 0xd000 && kind != 0xc000)
            return false;
        const bool exchange = kind == 0xc000, call = kind != 0x9000;
        if (exchange && (low & 1))
            return false;
        const auto bits = (s << 24) | ((1 ^ (j1 ^ s)) << 23) | ((1 ^ (j2 ^ s)) << 22) | ((h & 0x3ff) << 12) |
                          ((low & (exchange ? 0x7fe : 0x7ff)) << 1);
        branch(i, signed_bits(bits, 25), exchange ? 23 : 24, call, exchange);
        return true;
    }
    if ((h & 0xff00) == 0xbf00) {
        const unsigned mask = h & 15, condition = (h >> 4) & 15;
        if (!mask) {
            if (h != 0xbf00)
                return false;
            i.opcode = Opcode::t32_nop;
            return true;
        }
        if (!i.arm->it_before.known || active(i) || condition == 15 || (condition == 14 && std::popcount(mask) != 1))
            return false;
        i.opcode = Opcode::t32_it;
        i.condition = 14;
        i.arm->predicate = ArmPredicate::always;
        i.arm->it_after = {true, static_cast<std::uint8_t>(h)};
        i.operands = {ImmediateOperand{condition, 4, 4, false, {}}, ImmediateOperand{mask, 4, 4, false, {}}};
        i.access = {OperandAccess::read, OperandAccess::read};
        return true;
    }
    if ((h & 0xf800) == 0xe000) {
        branch(i, signed_bits((h & 0x7ff) << 1, 12), 11, false);
        return true;
    }
    if ((h & 0xf000) == 0xd000) {
        const auto condition = (h >> 8) & 15;
        if (condition == 15) {
            i.opcode = Opcode::t32_svc;
            i.flow = FlowKind::trap;
            i.operands = {ImmediateOperand{h & 255u, 8, 32, false, {}}};
            i.access = {OperandAccess::read};
            return true;
        }
        if (condition == 14 || !i.arm->it_before.known || active(i))
            return false;
        i.condition = static_cast<std::uint8_t>(condition);
        i.arm->predicate = ArmPredicate::condition;
        read(i, flags);
        branch(i, signed_bits((h & 255) << 1, 9), 8, false, false, true);
        return true;
    }
    if ((h & 0xf500) == 0xb100) {
        if (!i.arm->it_before.known || active(i))
            return false;
        const auto offset = ((h >> 3) & 31) * 2 + ((h >> 9) & 1) * 64;
        i.opcode = (h & 0x800) ? Opcode::t32_cbnz : Opcode::t32_cbz;
        i.flow = FlowKind::conditional_branch;
        i.operands = {reg(h & 7), ThumbRelativeOperand{static_cast<std::int64_t>(offset), 6}};
        i.access = {OperandAccess::read, OperandAccess::read};
        read(i, reg(h & 7));
        i.direct_target = target(i.address, 4 + offset);
        i.arm->writes_pc = true;
        i.arm->target_mode = ExecutionMode::thumb;
        return true;
    }
    if ((h & 0xff00) == 0x4700) {
        const auto rm = (h >> 3) & 15;
        if ((h & 7) || rm == 15)
            return false;
        const bool call = h & 0x80;
        i.opcode = call ? Opcode::t32_blx : Opcode::t32_bx;
        i.flow = call ? FlowKind::call : rm == 14 ? FlowKind::ret : FlowKind::jump;
        i.operands = {reg(rm)};
        i.access = {OperandAccess::read};
        read(i, reg(rm));
        i.arm->writes_pc = true;
        i.arm->exchange = ArmExchange::address_bit0;
        if (call)
            link(i);
        return true;
    }
    if ((h & 0xff00) == 0xbe00) {
        i.opcode = Opcode::t32_bkpt;
        i.flow = FlowKind::trap;
        i.condition = 14;
        i.arm->predicate = ArmPredicate::always;
        i.register_reads.clear();
        i.operands = {ImmediateOperand{h & 255u, 8, 32, false, {}}};
        i.access = {OperandAccess::read};
        return true;
    }
    return false;
}
} // namespace hexlab::thumb_detail
