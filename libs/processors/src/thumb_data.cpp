#include "thumb_internal.hpp"
namespace hexlab::thumb_detail {
namespace {
bool alu(Instruction &i, unsigned op, unsigned rd, unsigned rn, std::uint32_t operand, bool immediate, bool implicit,
         bool always_flags = false, std::uint16_t immediate_width = 8) {
    const auto state = i.arm->it_before;
    const bool setflags = always_flags || (implicit && state.known && !state.bits);
    const auto word = 0xe0000000u | (op << 21) | (setflags ? 0x100000 : 0) | (immediate ? 0x2000000 : 0) | (rn << 16) |
                      (rd << 12) | operand;
    if (!arm32_detail::data(i, word))
        return false;
    if (immediate)
        for (auto &destination_operand : i.operands)
            if (auto value = std::get_if<ImmediateOperand>(&destination_operand))
                value->encoded_width = immediate_width;
    if (implicit && !state.known) {
        i.arm->flags_written = 0;
        i.arm->flags_known = false;
    }
    if (i.arm->writes_pc) {
        i.arm->exchange = ArmExchange::none;
        i.arm->target_mode = ExecutionMode::thumb;
    }
    return true;
}
} // namespace
bool data(Instruction &i, std::uint16_t h) {
    const auto rd = h & 7, rm = (h >> 3) & 7;
    if ((h & 0xe000) == 0 && (h & 0x1800) != 0x1800) {
        const auto shift = (h >> 11) & 3, amount = (h >> 6) & 31;
        return alu(i, 13, rd, 0, rm | (shift << 5) | (amount << 7), false, true);
    }
    if ((h & 0xf800) == 0x1800) {
        const bool immediate = h & 0x400, sub = h & 0x200;
        return alu(i, sub ? 2 : 4, rd, rm, (h >> 6) & 7, immediate, true, false, 3);
    }
    if ((h & 0xe000) == 0x2000) {
        const auto op = (h >> 11) & 3, r = (h >> 8) & 7;
        if (op == 0)
            return alu(i, 13, r, 0, h & 255, true, true);
        if (op == 1)
            return alu(i, 10, 0, r, h & 255, true, false, true);
        return alu(i, op == 2 ? 4 : 2, r, r, h & 255, true, true);
    }
    if ((h & 0xfc00) == 0x4000) {
        const auto op = (h >> 6) & 15;
        if (op == 2 || op == 3 || op == 4 || op == 7) {
            const auto shift = op == 2 ? 0 : op == 3 ? 1 : op == 4 ? 2 : 3;
            return alu(i, 13, rd, 0, rd | (shift << 5) | 0x10 | (rm << 8), false, true);
        }
        if (op == 9)
            return alu(i, 3, rd, rm, 0, true, true, false, 0);
        if (op == 13) {
            i.opcode = Opcode::t32_mul;
            i.operands = {reg(rd), reg(rm)};
            i.access = {OperandAccess::read_write, OperandAccess::read};
            read(i, reg(rd));
            read(i, reg(rm));
            i.register_writes.push_back(reg(rd));
            if (!i.arm->it_before.known)
                i.arm->flags_known = false;
            else if (!active(i)) {
                i.arm->flags_written = 12;
                i.register_writes.push_back(flags);
            }
            return true;
        }
        static constexpr unsigned codes[]{0, 1, 0, 0, 0, 5, 6, 0, 8, 0, 10, 11, 12, 0, 14, 15};
        const bool compare = op == 8 || op == 10 || op == 11, unary = op == 15;
        return alu(i, codes[op], compare ? 0 : rd, unary ? 0 : rd, rm, false, !compare, compare);
    }
    if ((h & 0xfc00) == 0x4400) {
        const auto op = (h >> 8) & 3, d = (h & 7) | ((h >> 4) & 8), m = (h >> 3) & 15;
        if (op == 3)
            return false; // Register exchanges are handled by flow.
        if (op == 1) {
            if (d == 15 || m == 15 || (d < 8 && m < 8))
                return false;
            return alu(i, 10, 0, d, m, false, false, true);
        }
        if (d == 15 && m == 15)
            return false;
        return alu(i, op == 0 ? 4 : 13, d, op == 0 ? d : 0, m, false, false);
    }
    if ((h & 0xf800) == 0xa000) {
        const auto d = (h >> 8) & 7, offset = (h & 255) * 4;
        i.opcode = Opcode::t32_adr;
        ArmMemoryOperand address{reg(15)};
        address.offset = static_cast<std::uint32_t>(offset);
        address.resolved_address = target({i.address.space, (i.address.offset + 4) & ~UINT64_C(3)}, offset);
        i.operands = {reg(d), address};
        i.access = {OperandAccess::write, OperandAccess::address};
        read(i, reg(15));
        i.register_writes.push_back(reg(d));
        return true;
    }
    if ((h & 0xf800) == 0xa800)
        return alu(i, 4, (h >> 8) & 7, 13, 0xf00 | (h & 255), true, false);
    if ((h & 0xff00) == 0xb000)
        return alu(i, (h & 0x80) ? 2 : 4, 13, 13, 0xf00 | (h & 127), true, false, false, 7);
    return false;
}
} // namespace hexlab::thumb_detail
