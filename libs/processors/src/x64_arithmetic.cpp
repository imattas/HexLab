#include "x64_internal.hpp"

namespace hexlab::x64_detail {
namespace {
constexpr Opcode binary_ops[]{Opcode::add,     Opcode::bit_or, Opcode::adc,     Opcode::sbb,
                              Opcode::bit_and, Opcode::sub,    Opcode::bit_xor, Opcode::cmp};
void binary(State &s, Opcode opcode, Operand destination, Operand source) {
    s.i.opcode = opcode;
    const bool compare = opcode == Opcode::cmp || opcode == Opcode::test;
    s.lock_allowed = !compare && std::holds_alternative<MemoryOperand>(destination);
    s.operand(std::move(destination), compare ? OperandAccess::read : OperandAccess::read_write);
    s.operand(std::move(source), OperandAccess::read);
    s.flags_write = true;
    s.flags_read = opcode == Opcode::adc || opcode == Opcode::sbb;
}
} // namespace
bool arithmetic(State &s, std::uint8_t opcode, bool extended) {
    const auto wide = s.width();
    if (extended) {
        if (opcode == 0xc7) {
            const auto group = (s.peek() >> 3) & 7;
            if (group == 6 || group == 7) {
                const auto m = modrm(s, wide);
                // Memory /6 and /7 select VMX system instructions, not
                // malformed RDRAND/RDSEED operands.
                if (m.mod != 3)
                    unsupported("0F C7 memory system forms are outside the scalar random subset");
                s.i.opcode = group == 6 ? Opcode::rdrand : Opcode::rdseed;
                s.operand(m.rm, OperandAccess::write);
                const auto destination = std::get<RegisterOperand>(m.rm);
                const auto full_width = s.rules.pointer_width();
                if (wide < full_width) {
                    const auto full = gpr(static_cast<std::uint8_t>(destination.index), full_width);
                    if (wide == 16) s.i.register_reads.push_back(full);
                    s.i.register_writes.push_back(full);
                }
                // CF reports availability; OF/SF/ZF/AF/PF clear. Preserve
                // all remaining bits through the incoming whole-FLAGS value.
                s.flags_read = true;
                s.flags_write = true;
                return true;
            }
            auto m = modrm(s, s.rules.long_mode() && (s.rex & 8) ? 128 : 64);
            if (m.group != 1)
                return false;
            if (m.mod == 3)
                invalid("CMPXCHG8B/16B requires a memory operand");
            const bool wide_exchange = s.rules.long_mode() && (s.rex & 8);
            const std::uint16_t pair_width = wide_exchange ? 64 : 32;
            s.i.opcode = wide_exchange ? Opcode::cmpxchg16b : Opcode::cmpxchg8b;
            s.lock_allowed = true;
            s.operand(std::move(m.rm), OperandAccess::read_write);
            for (const std::uint8_t index : {std::uint8_t{0}, std::uint8_t{2}, std::uint8_t{3}, std::uint8_t{1}})
                s.i.register_reads.push_back(gpr(index, pair_width));
            s.i.register_writes.push_back(gpr(0, pair_width));
            s.i.register_writes.push_back(gpr(2, pair_width));
            s.flags_write = true;
            return true;
        }
        if (opcode == 0xb0 || opcode == 0xb1 || opcode == 0xc0 || opcode == 0xc1) {
            const auto width = static_cast<std::uint16_t>((opcode == 0xb0 || opcode == 0xc0) ? 8 : wide);
            auto m = modrm(s, width);
            const bool exchange_add = opcode == 0xc0 || opcode == 0xc1;
            s.i.opcode = exchange_add ? Opcode::xadd : Opcode::cmpxchg;
            s.lock_allowed = std::holds_alternative<MemoryOperand>(m.rm);
            if (exchange_add) {
                s.operand(m.rm, OperandAccess::read_write);
                s.operand(m.reg, OperandAccess::read_write);
            } else {
                s.operand(m.rm, OperandAccess::read_write);
                s.operand(m.reg, OperandAccess::read);
                const auto accumulator = gpr(0, width);
                s.i.register_reads.push_back(accumulator);
                s.i.register_writes.push_back(accumulator);
            }
            s.flags_write = true;
            return true;
        }
        if (opcode != 0xaf)
            return false;
        s.i.opcode = Opcode::imul;
        auto m = modrm(s, wide);
        s.operand(m.reg, OperandAccess::read_write);
        s.operand(m.rm, OperandAccess::read);
        s.flags_write = true;
        return true;
    }
    if (!s.rules.long_mode() && opcode >= 0x40 && opcode <= 0x4f) {
        s.i.opcode = opcode < 0x48 ? Opcode::inc : Opcode::dec;
        s.operand(s.reg(opcode & 7, wide, false), OperandAccess::read_write);
        s.flags_read = true;
        s.flags_write = true;
        return true;
    }
    if (opcode < 0x40 && (opcode & 7) <= 5) {
        const auto operation = binary_ops[opcode >> 3];
        const auto form = opcode & 7;
        const auto width = static_cast<std::uint16_t>((form & 1) ? wide : 8);
        if (form < 4) {
            auto m = modrm(s, width);
            if (form & 2)
                binary(s, operation, m.reg, m.rm);
            else
                binary(s, operation, m.rm, m.reg);
        } else {
            auto imm = s.immediate(width == 64 ? 32 : width, width, width == 64);
            binary(s, operation, gpr(0, width), imm);
        }
    } else if (opcode == 0x80 || opcode == 0x81 || opcode == 0x83) {
        const auto width = static_cast<std::uint16_t>(opcode == 0x80 ? 8 : wide);
        auto m = modrm(s, width);
        auto imm = s.immediate(opcode == 0x83 ? 8 : width == 64 ? 32 : width, width, opcode == 0x83 || width == 64);
        binary(s, binary_ops[m.group], m.rm, imm);
    } else if (opcode == 0x84 || opcode == 0x85) {
        auto m = modrm(s, (opcode & 1) ? wide : 8);
        binary(s, Opcode::test, m.rm, m.reg);
    } else if (opcode == 0xa8 || opcode == 0xa9) {
        const auto width = static_cast<std::uint16_t>((opcode & 1) ? wide : 8);
        auto imm = s.immediate(width == 64 ? 32 : width, width, width == 64);
        binary(s, Opcode::test, gpr(0, width), imm);
    } else if (opcode == 0xf6 || opcode == 0xf7) {
        const auto width = static_cast<std::uint16_t>((opcode & 1) ? wide : 8);
        auto m = modrm(s, width);
        if (m.group == 0)
            binary(s, Opcode::test, m.rm, s.immediate(width == 64 ? 32 : width, width, width == 64));
        else if (m.group == 2 || m.group == 3) {
            s.i.opcode = m.group == 2 ? Opcode::bit_not : Opcode::neg;
            s.lock_allowed = std::holds_alternative<MemoryOperand>(m.rm);
            s.operand(m.rm, OperandAccess::read_write);
            s.flags_write = m.group == 3;
        } else if (m.group >= 4) {
            // F6/F7 /4-/7 use the accumulator and (for non-byte forms) the
            // high half of the accumulator pair implicitly.
            const auto group = m.group;
            const bool divide = group >= 6;
            const auto low_read_width = static_cast<std::uint16_t>(width == 8 && divide ? 16 : width);
            const auto low = gpr(0, low_read_width);
            const auto high = width == 8 ? s.reg(4, 8, false) : gpr(2, width);
            s.i.opcode = group == 4 ? Opcode::mul : group == 5 ? Opcode::imul : group == 6 ? Opcode::div : Opcode::idiv;
            s.operand(m.rm, OperandAccess::read);
            s.i.register_reads.push_back(low);
            if (divide && width != 8)
                s.i.register_reads.push_back(high);
            if (width == 8) {
                if (divide) {
                    s.i.register_writes.push_back(gpr(0, 8));
                    s.i.register_writes.push_back(s.reg(4, 8, false));
                } else
                    s.i.register_writes.push_back(gpr(0, 16));
            } else {
                s.i.register_writes.push_back(gpr(0, width));
                s.i.register_writes.push_back(high);
            }
            s.flags_write = !divide;
        } else
            unsupported("F6/F7 arithmetic extension is not yet covered");
    } else if (opcode == 0xfe || opcode == 0xff) {
        if (((s.peek() >> 3) & 7) > 1)
            return false;
        auto m = modrm(s, opcode == 0xfe ? 8 : wide);
        s.i.opcode = m.group == 0 ? Opcode::inc : Opcode::dec;
        s.lock_allowed = std::holds_alternative<MemoryOperand>(m.rm);
        s.operand(m.rm, OperandAccess::read_write);
        s.flags_read = true;
        s.flags_write = true;
    } else if (opcode == 0x69 || opcode == 0x6b) {
        auto m = modrm(s, wide);
        s.i.opcode = Opcode::imul;
        s.operand(m.reg, OperandAccess::write);
        s.operand(m.rm, OperandAccess::read);
        s.operand(s.immediate(opcode == 0x6b ? 8 : wide == 64 ? 32 : wide, wide, true), OperandAccess::read);
        s.flags_write = true;
    } else if (opcode == 0xc0 || opcode == 0xc1 || (opcode >= 0xd0 && opcode <= 0xd3)) {
        static constexpr Opcode shifts[]{Opcode::rol, Opcode::ror, Opcode::rcl, Opcode::rcr,
                                         Opcode::shl, Opcode::shr, Opcode::shl, Opcode::sar};
        auto m = modrm(s, (opcode & 1) ? wide : 8);
        if (m.group == 6)
            unsupported("Undocumented shift extension is not covered");
        s.i.opcode = shifts[m.group];
        s.operand(m.rm, OperandAccess::read_write);
        if (opcode == 0xc0 || opcode == 0xc1)
            s.operand(s.immediate(8, 8, false), OperandAccess::read);
        else if (opcode == 0xd0 || opcode == 0xd1)
            s.operand(ImmediateOperand{1, 0, 8, false}, OperandAccess::read);
        else
            s.operand(gpr(1, 8), OperandAccess::read);
        s.flags_write = true;
        s.flags_read = m.group == 2 || m.group == 3;
    } else
        return false;
    return true;
}
bool accumulator_sign_extension(State &s, std::uint8_t opcode, bool extended) {
    if (extended || (opcode != 0x98 && opcode != 0x99))
        return false;
    const auto width = s.width();
    if (opcode == 0x98) {
        s.i.opcode = width == 16 ? Opcode::cbw : width == 32 ? Opcode::cwde : Opcode::cdqe;
        s.i.register_reads.push_back(gpr(0, static_cast<std::uint16_t>(width / 2)));
        s.i.register_writes.push_back(gpr(0, width));
    } else {
        s.i.opcode = width == 16 ? Opcode::cwd : width == 32 ? Opcode::cdq : Opcode::cqo;
        s.i.register_reads.push_back(gpr(0, width));
        s.i.register_writes.push_back(gpr(2, width));
    }
    return true;
}
} // namespace hexlab::x64_detail
