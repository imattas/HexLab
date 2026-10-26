#include "x64_internal.hpp"

namespace hexlab::x64_detail {
bool bit_operations(State &s, std::uint8_t opcode, bool extended) {
    if (!extended)
        return false;

    if (opcode >= 0xc8 && opcode <= 0xcf) {
        // BSWAP uses a fixed 32-bit operand outside long mode; in long mode
        // REX.W selects the 64-bit form and 66 is ignored by the encoding.
        const std::uint16_t width = s.rules.long_mode() ? ((s.rex & 8) ? 64 : 32) : s.width();
        if (width != 32 && width != 64)
            invalid("BSWAP does not support a 16-bit operand");
        s.i.opcode = Opcode::bswap;
        s.operand(s.reg(opcode & 7, width, (s.rex & 1) != 0), OperandAccess::read_write);
        return true;
    }

    if (opcode == 0xb8) {
        if (s.group1 != 0xf3)
            invalid("POPCNT requires the F3 mandatory prefix");
        s.i.opcode = Opcode::popcnt;
        const auto m = modrm(s, s.width());
        s.operand(m.reg, OperandAccess::write);
        s.operand(m.rm, OperandAccess::read);
        // POPCNT clears CF/PF/AF/SF/OF and sets ZF when its source is zero.
        s.flags_write = true;
        return true;
    }

    if (opcode == 0xa4 || opcode == 0xa5 || opcode == 0xac || opcode == 0xad) {
        const auto width = s.width();
        const auto m = modrm(s, width, width);
        const bool immediate = opcode == 0xa4 || opcode == 0xac;
        s.i.opcode = opcode == 0xa4 || opcode == 0xa5 ? Opcode::shld : Opcode::shrd;
        s.operand(m.rm, OperandAccess::read_write);
        s.operand(m.reg, OperandAccess::read);
        if (immediate)
            s.operand(s.immediate(8, 8, false), OperandAccess::read);
        else
            s.operand(gpr(1, 8), OperandAccess::read);
        s.flags_write = true;
        return true;
    }

    Opcode operation{};
    bool immediate = false;
    bool scan = false;
    switch (opcode) {
    case 0xa3: operation = Opcode::bt; break;
    case 0xab: operation = Opcode::bts; break;
    case 0xb3: operation = Opcode::btr; break;
    case 0xbb: operation = Opcode::btc; break;
    case 0xbc:
        operation = s.group1 == 0xf3 ? Opcode::tzcnt : Opcode::bsf;
        scan = true;
        break;
    case 0xbd:
        operation = s.group1 == 0xf3 ? Opcode::lzcnt : Opcode::bsr;
        scan = true;
        break;
    case 0xba:
        immediate = true;
        break;
    default: return false;
    }

    const auto width = s.width();
    const auto m = modrm(s, width);
    if (immediate) {
        switch (m.group) {
        case 4: operation = Opcode::bt; break;
        case 5: operation = Opcode::bts; break;
        case 6: operation = Opcode::btr; break;
        case 7: operation = Opcode::btc; break;
        default: invalid("0F BA bit-operation extension is reserved");
        }
    }

    s.i.opcode = operation;
    const bool read_modify_write = operation == Opcode::bts || operation == Opcode::btr || operation == Opcode::btc;
    if (!scan && read_modify_write)
        s.lock_allowed = std::holds_alternative<MemoryOperand>(m.rm);
    if (scan) {
        s.operand(m.reg, OperandAccess::write);
        s.operand(m.rm, OperandAccess::read);
    } else {
        s.operand(m.rm, read_modify_write ? OperandAccess::read_write : OperandAccess::read);
        if (immediate)
            s.operand(s.immediate(8, 8, false), OperandAccess::read);
        else
            s.operand(m.reg, OperandAccess::read);
    }
    s.flags_write = true;
    return true;
}
} // namespace hexlab::x64_detail
