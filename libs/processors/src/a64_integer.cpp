#include "a64_internal.hpp"
#include <bit>
namespace hexlab::a64_detail {
namespace {
bool logical_immediate(Instruction &i, std::uint32_t word, unsigned width) {
    if ((word & 0x1f800000u) != 0x12000000u)
        return false;
    const unsigned n = (word >> 22) & 1;
    const unsigned imms = (word >> 10) & 0x3f;
    const unsigned immr = (word >> 16) & 0x3f;
    if (width == 32 && n != 0)
        return false;
    const unsigned selector = (n << 6) | ((~imms) & 0x3f);
    if (!selector)
        return false;
    const unsigned len = 31u - static_cast<unsigned>(std::countl_zero(selector));
    if (len < 1 || len > 6 || (width == 32 && len > 5))
        return false;
    const unsigned element_width = 1u << len;
    const unsigned levels = element_width - 1;
    const unsigned s = imms & levels;
    const unsigned r = immr & levels;
    if (s == levels)
        return false;
    const std::uint64_t element_mask = element_width == 64 ? UINT64_MAX : (UINT64_C(1) << element_width) - 1;
    std::uint64_t element = (UINT64_C(1) << (s + 1)) - 1;
    if (r)
        element = ((element >> r) | (element << (element_width - r))) & element_mask;
    std::uint64_t mask = 0;
    for (unsigned bit = 0; bit < width; bit += element_width)
        mask |= element << bit;

    switch ((word >> 29) & 3) {
    case 0: i.opcode = Opcode::a64_and; break;
    case 1: i.opcode = Opcode::a64_orr; break;
    case 2: i.opcode = Opcode::a64_eor; break;
    default: i.opcode = Opcode::a64_ands; break;
    }
    operand(i, reg(word & 31, width), OperandAccess::write);
    operand(i, reg((word >> 5) & 31, width), OperandAccess::read);
    immediate(i, mask, 13, width);
    if (i.opcode == Opcode::a64_ands)
        i.register_writes.push_back(nzcv);
    return true;
}
} // namespace
bool integer(Instruction &i, std::uint32_t word) {
    const unsigned width = (word >> 31) ? 64 : 32;
    // EXTR extracts a width-sized window from Rn concatenated with Rm.
    // sf/N must agree, and the 32-bit form reserves imm6[5].
    if ((word & 0x7fa00000u) == 0x13800000u) {
        const unsigned n = (word >> 22) & 1;
        const unsigned lsb = (word >> 10) & 63;
        if (n != (width == 64 ? 1u : 0u) || lsb >= width)
            return false;
        i.opcode = Opcode::a64_extr;
        operand(i, reg(word & 31, width), OperandAccess::write);
        operand(i, reg((word >> 5) & 31, width), OperandAccess::read);
        operand(i, reg((word >> 16) & 31, width), OperandAccess::read);
        immediate(i, lsb, 6, width);
        const unsigned destination = word & 31;
        if (width == 32 && destination != 31)
            i.register_writes.push_back(reg(destination, 64));
        return true;
    }
    // Conditional compare (register/immediate). The mask intentionally omits
    // bit 11 so both forms match: zero selects Rm, one selects imm5. It checks
    // the fixed high pattern and reserved-zero bits 10 and 4. Bit 30 selects
    // subtraction (CCMP) rather than addition (CCMN).
    if ((word & 0x3fe00410u) == 0x3a400000u) {
        i.opcode = (word & 0x40000000u) ? Opcode::a64_ccmp : Opcode::a64_ccmn;
        i.condition = static_cast<std::uint8_t>((word >> 12) & 15);
        operand(i, reg((word >> 5) & 31, width), OperandAccess::read);
        if (word & 0x00000800u)
            immediate(i, (word >> 16) & 31, 5, width);
        else
            operand(i, reg((word >> 16) & 31, width), OperandAccess::read);
        immediate(i, word & 15, 4, 4);
        if (i.condition < 14)
            i.register_reads.push_back(nzcv);
        i.register_writes.push_back(nzcv);
        return true;
    }
    // Conditional select: choose Rn or transformed Rm according to NZCV.
    // op (bit 30) and o2 (bit 10) select CSEL/CSINC/CSINV/CSNEG.
    if ((word & 0x1fe00000u) == 0x1a800000u && !(word & 0x20000000u) &&
        !(word & 0x00000800u)) {
        const bool invert = (word & 0x40000000u) != 0;
        const bool increment = (word & 0x00000400u) != 0;
        i.opcode = invert ? (increment ? Opcode::a64_csneg : Opcode::a64_csinv)
                          : (increment ? Opcode::a64_csinc : Opcode::a64_csel);
        i.condition = static_cast<std::uint8_t>((word >> 12) & 15);
        operand(i, reg(word & 31, width), OperandAccess::write);
        operand(i, reg((word >> 5) & 31, width), OperandAccess::read);
        operand(i, reg((word >> 16) & 31, width), OperandAccess::read);
        if (i.condition < 14)
            i.register_reads.push_back(nzcv);
        const unsigned destination = word & 31;
        if (width == 32 && destination != 31)
            i.register_writes.push_back(reg(destination, 64));
        return true;
    }
    // AArch64 two-source integer division. The architecture defines division
    // by zero as zero; the decompiler keeps the operation explicit.
    const auto division_encoding = word & 0x7fe0fc00u;
    if (division_encoding == 0x1ac00800u || division_encoding == 0x1ac00c00u) {
        i.opcode = division_encoding == 0x1ac00800u ? Opcode::a64_udiv : Opcode::a64_sdiv;
        operand(i, reg(word & 31, width), OperandAccess::write);
        operand(i, reg((word >> 5) & 31, width), OperandAccess::read);
        operand(i, reg((word >> 16) & 31, width), OperandAccess::read);
        const unsigned destination = word & 31;
        if (width == 32 && destination != 31)
            i.register_writes.push_back(reg(destination, 64));
        return true;
    }
    // Integer data-processing (three source): Rd = Ra +/- (Rn * Rm).
    // Bit 15 selects subtraction; all other fixed/reserved bits are checked by
    // this mask while sf (bit 31) remains available for the W/X width.
    if ((word & 0x7fe00000u) == 0x1b000000u) {
        const bool subtract = (word & 0x00008000u) != 0;
        i.opcode = subtract ? Opcode::a64_msub : Opcode::a64_madd;
        operand(i, reg(word & 31, width), OperandAccess::write);
        operand(i, reg((word >> 5) & 31, width), OperandAccess::read);
        operand(i, reg((word >> 16) & 31, width), OperandAccess::read);
        operand(i, reg((word >> 10) & 31, width), OperandAccess::read);
        const auto destination = (word & 31u);
        if (width == 32 && destination != 31)
            i.register_writes.push_back(reg(destination, 64));
        return true;
    }
    if (logical_immediate(i, word, width))
        return true;
    if ((word & 0x1f800000u) == 0x13000000u) {
        const unsigned opc = (word >> 29) & 3;
        const unsigned immr = (word >> 16) & 0x3f;
        const unsigned imms = (word >> 10) & 0x3f;
        if (opc == 3 || (word & 0x00200000u) || immr >= width || imms >= width ||
            ((word >> 22) & 1) != (width == 64 ? 1u : 0u))
            return false; // Reserved opc, fixed-bit and width encodings have no native semantics.
        i.opcode = opc == 0 ? Opcode::a64_sbfm : opc == 1 ? Opcode::a64_bfm : Opcode::a64_ubfm;
        operand(i, reg(word & 31, width), opc == 1 ? OperandAccess::read_write : OperandAccess::write);
        operand(i, reg((word >> 5) & 31, width), OperandAccess::read);
        immediate(i, immr, 6, width);
        immediate(i, imms, 6, width);
        if (opc == 1 && width == 32 && (word & 31) != 31)
            i.register_writes.push_back(reg(word & 31, 64));
        return true;
    }
    const auto shift = (word >> 22) & 3;
    const auto amount = (word >> 10) & 63;
    const bool add_sub = (word & 0x1f200000u) == 0x0b000000u;
    const bool logical = (word & 0x1f000000u) == 0x0a000000u;
    if (!add_sub && !logical)
        return false;
    if (amount >= width)
        return false;
    if (add_sub && shift == 3)
        return false;
    if (logical && ((word >> 21) & 1))
        return false; // BIC/ORN/EON/BICS have separate opcode contracts.

    const bool set_flags = add_sub && ((word >> 29) & 1);
    if (add_sub) {
        const bool subtract = (word >> 30) & 1;
        i.opcode = subtract ? (set_flags ? Opcode::a64_subs : Opcode::a64_sub)
                            : (set_flags ? Opcode::a64_adds : Opcode::a64_add);
    } else {
        switch ((word >> 29) & 3) {
        case 0: i.opcode = Opcode::a64_and; break;
        case 1: i.opcode = Opcode::a64_orr; break;
        case 2: i.opcode = Opcode::a64_eor; break;
        default: i.opcode = Opcode::a64_ands; break;
        }
    }
    operand(i, reg(word & 31, width), OperandAccess::write);
    operand(i, reg((word >> 5) & 31, width), OperandAccess::read);
    operand(i, reg((word >> 16) & 31, width), OperandAccess::read);
    if (amount || shift)
        operand(i, ImmediateOperand{amount, 6, static_cast<std::uint16_t>(width), false, {}}, OperandAccess::read);
    if (set_flags || i.opcode == Opcode::a64_ands)
        i.register_writes.push_back(nzcv);
    return true;
}
} // namespace hexlab::a64_detail
