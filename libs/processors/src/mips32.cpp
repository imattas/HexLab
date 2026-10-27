#include "hexlab/processors/decoder.hpp"
#include <algorithm>
#include <bit>

namespace hexlab {
namespace {
using R = RegisterOperand;
constexpr RegisterBank bank = RegisterBank::mips_gpr;
R reg(unsigned index) { return {bank, static_cast<std::uint8_t>(index), 32, false}; }
R fpr(unsigned index, unsigned width = 32) { return {RegisterBank::mips_fpr, static_cast<std::uint8_t>(index), static_cast<std::uint16_t>(width), false}; }
R hilo(unsigned index) { return {RegisterBank::mips_hilo, static_cast<std::uint8_t>(index), 32, false}; }
R cp0(unsigned index) { return {RegisterBank::mips_cp0, static_cast<std::uint8_t>(index), 32, false}; }
R fcsr() { return {RegisterBank::mips_fcsr, 0, 32, false}; }
R fcc(unsigned index) { return {RegisterBank::mips_fcsr, static_cast<std::uint8_t>(index + 1), 32, false}; }
std::int64_t signed16(std::uint32_t value) {
    const auto imm = value & 0xffff;
    return (imm & 0x8000) ? static_cast<std::int64_t>(imm) - 0x10000 : imm;
}
DecodeResult invalid(const char *why) { return {DecodeStatus::invalid, {}, why}; }
void add_target(Instruction &i, std::int64_t displacement, ByteOrder order) {
    const auto pc = static_cast<std::uint32_t>(i.address.offset);
    const auto target = static_cast<std::uint32_t>(static_cast<std::uint64_t>(pc + 4u) +
                                                   static_cast<std::uint64_t>(displacement * 4));
    i.direct_target = Address{i.address.space, target};
    i.operands.push_back(RelativeOperand{displacement * 4, 16, 32, EncodedField{static_cast<std::uint8_t>(order == ByteOrder::little ? 0 : 2), 2}});
}
void branch(Instruction &i, Opcode opcode, unsigned rs, unsigned rt, std::int64_t displacement, bool conditional, ByteOrder order) {
    i.opcode = opcode;
    i.operands = {reg(rs), reg(rt)};
    i.access = {OperandAccess::read, OperandAccess::read};
    i.register_reads = {reg(rs), reg(rt)};
    i.flow = conditional ? FlowKind::conditional_branch : FlowKind::jump;
    add_target(i, displacement, order);
    i.access.push_back(OperandAccess::address);
    i.delay_slots = 1;
}
} // namespace

DecodeResult decode_mips32(std::span<const std::byte> bytes, Address at) {
    return decode_mips32(ByteOrder::little, bytes, at);
}
DecodeResult decode_mips32(ByteOrder order, std::span<const std::byte> bytes, Address at) {
    if (bytes.size() < 4)
        return {DecodeStatus::truncated, {}, "MIPS32 instruction needs four bytes"};
    if ((at.offset & 3) != 0)
        return invalid("MIPS32 instruction address is not word-aligned");
    if (at.offset > UINT32_MAX)
        return invalid("MIPS32 instruction address exceeds its 32-bit domain");
    const std::uint32_t w = order == ByteOrder::little ? std::to_integer<std::uint32_t>(bytes[0]) |
                            (std::to_integer<std::uint32_t>(bytes[1]) << 8) |
                            (std::to_integer<std::uint32_t>(bytes[2]) << 16) |
                            (std::to_integer<std::uint32_t>(bytes[3]) << 24)
                            : (std::to_integer<std::uint32_t>(bytes[0]) << 24) |
                            (std::to_integer<std::uint32_t>(bytes[1]) << 16) |
                            (std::to_integer<std::uint32_t>(bytes[2]) << 8) |
                            std::to_integer<std::uint32_t>(bytes[3]);
    const auto op = w >> 26, rs = (w >> 21) & 31, rt = (w >> 16) & 31, rd = (w >> 11) & 31;
    const auto shamt = (w >> 6) & 31, funct = w & 63;
    Instruction i;
    i.context = {Architecture::mips32, ExecutionMode::mips32, order};
    i.address = at;
    std::copy_n(bytes.begin(), 4, i.bytes.begin());
    i.length = 4;
    auto binary = [&](Opcode opcode) {
        i.opcode = opcode;
        i.operands = {reg(rd), reg(rs), reg(rt)};
        i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
        i.register_reads = {reg(rs), reg(rt)};
        if (rd) i.register_writes = {reg(rd)};
    };
    auto immediate = [&](Opcode opcode, bool sign) {
        i.opcode = opcode;
        i.operands = {reg(rt), reg(rs), ImmediateOperand{static_cast<std::uint64_t>(sign ? signed16(w) : (w & 0xffff)), 16, 32, sign, EncodedField{static_cast<std::uint8_t>(order == ByteOrder::little ? 0 : 2), 2}}};
        i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
        i.register_reads = {reg(rs)};
        if (rt) i.register_writes = {reg(rt)};
    };
    if (op == 0) {
        switch (funct) {
        case 0x00: case 0x02: case 0x03: // fixed shifts
            if (rs != 0) return invalid("Reserved fixed-shift encoding");
            i.opcode = funct == 0 ? Opcode::mips_sll : funct == 2 ? Opcode::mips_srl : Opcode::mips_sra;
            i.operands = {reg(rd), reg(rt), ImmediateOperand{shamt, 5, 32, false, EncodedField{3, 1}}};
            i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
            i.register_reads = {reg(rt)}; if (rd) i.register_writes = {reg(rd)}; break;
        case 0x04: case 0x06: case 0x07:
            if (shamt != 0) return invalid("Reserved variable-shift encoding");
            i.opcode = funct == 4 ? Opcode::mips_sllv : funct == 6 ? Opcode::mips_srlv : Opcode::mips_srav;
            i.operands = {reg(rd), reg(rt), reg(rs)};
            i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
            i.register_reads = {reg(rt), reg(rs)}; if (rd) i.register_writes = {reg(rd)}; break;
        case 0x08: case 0x09: // jr / jalr
            if (rt != 0 || shamt != 0 || (funct == 8 && rd != 0)) return invalid("Reserved register-jump encoding");
            i.opcode = funct == 8 ? Opcode::mips_jr : Opcode::mips_jalr;
            i.operands = {reg(rs)}; i.access = {OperandAccess::read}; i.register_reads = {reg(rs)};
            if (funct == 8 && rs == 31) i.flow = FlowKind::ret;
            else if (funct == 9) { i.flow = FlowKind::call; if (rd) i.register_writes = {reg(rd)}; }
            else i.flow = FlowKind::jump;
            i.delay_slots = 1; break;
        case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25:
            if (shamt != 0) return invalid("Reserved arithmetic encoding");
            binary(funct == 0x20 ? Opcode::mips_add : funct == 0x21 ? Opcode::mips_addu :
                   funct == 0x22 ? Opcode::mips_sub : funct == 0x23 ? Opcode::mips_subu :
                   funct == 0x24 ? Opcode::mips_and : funct == 0x25 ? Opcode::mips_or : Opcode::mips_xor); break;
        case 0x26:
            if (shamt != 0) return invalid("Reserved arithmetic encoding"); binary(Opcode::mips_xor); break;
        case 0x27:
            if (shamt != 0) return invalid("Reserved arithmetic encoding"); binary(Opcode::mips_nor); break;
        case 0x2a: case 0x2b:
            if (shamt != 0) return invalid("Reserved arithmetic encoding"); binary(funct == 0x2a ? Opcode::mips_slt : Opcode::mips_sltu); break;
        case 0x10: case 0x12: // MFHI / MFLO
            if (rs != 0 || rt != 0 || shamt != 0) return invalid("Reserved MFHI/MFLO encoding");
            i.opcode = funct == 0x10 ? Opcode::mips_mfhi : Opcode::mips_mflo;
            i.operands = {reg(rd)};
            i.access = {OperandAccess::write};
            i.register_reads = {hilo(funct == 0x10 ? 0 : 1)};
            if (rd) i.register_writes = {reg(rd)};
            break;
        case 0x11: case 0x13: // MTHI / MTLO
            if (rt != 0 || rd != 0 || shamt != 0) return invalid("Reserved MTHI/MTLO encoding");
            i.opcode = funct == 0x11 ? Opcode::mips_mthi : Opcode::mips_mtlo;
            i.operands = {reg(rs)};
            i.access = {OperandAccess::read};
            i.register_reads = {reg(rs)};
            i.register_writes = {hilo(funct == 0x11 ? 0 : 1)};
            break;
        case 0x18: case 0x19: case 0x1a: case 0x1b: // MULT/U, DIV/U
            if (rd != 0 || shamt != 0) return invalid("Reserved MULT/DIV encoding");
            i.opcode = funct == 0x18 ? Opcode::mips_mult : funct == 0x19 ? Opcode::mips_multu :
                       funct == 0x1a ? Opcode::mips_div : Opcode::mips_divu;
            i.operands = {reg(rs), reg(rt)};
            i.access = {OperandAccess::read, OperandAccess::read};
            i.register_reads = {reg(rs), reg(rt)};
            i.register_writes = {hilo(0), hilo(1)};
            break;
        case 0x0c: case 0x0d: { // SYSCALL / BREAK encode a 20-bit exception code.
            const auto code = (w >> 6) & 0xfffffu;
            i.opcode = funct == 0x0c ? Opcode::mips_syscall : Opcode::mips_break;
            if (code) i.operands = {ImmediateOperand{code, 20, 32, false, {}}};
            i.flow = FlowKind::trap;
            break;
        }
        case 0x0f: // SYNC stype
            if (rs != 0 || rt != 0 || rd != 0) return invalid("Reserved SYNC encoding");
            i.opcode = Opcode::mips_sync;
            if (shamt) i.operands = {ImmediateOperand{shamt, 5, 32, false, EncodedField{0, 2}}};
            break;
        default: return invalid("Reserved MIPS32 SPECIAL function");
        }
    } else if (op == 0x1f) {
        // MIPS32 Release 2 SPECIAL3 EXT/INS. EXT stores size-1 in rd;
        // INS stores the inclusive most-significant bit in rd.
        const unsigned position = shamt;
        const unsigned field = rd;
        const bool insert = funct == 0x04;
        unsigned size = 0;
        if (funct == 0x00) {
            size = field + 1;
            if (position + size > 32) return invalid("Reserved MIPS32 EXT range");
            i.opcode = Opcode::mips_ext;
        } else if (insert) {
            if (field < position) return invalid("Reserved MIPS32 INS range");
            size = field - position + 1;
            i.opcode = Opcode::mips_ins;
        } else {
            return {DecodeStatus::unsupported, {}, "MIPS32 SPECIAL3 operation is outside the EXT/INS subset"};
        }
        i.operands = {reg(rt), reg(rs),
            ImmediateOperand{position, 5, 32, false, EncodedField{3, 1}},
            ImmediateOperand{size, 6, 32, false, EncodedField{2, 1}}};
        i.access = {insert ? OperandAccess::read_write : OperandAccess::write,
                    OperandAccess::read, OperandAccess::read, OperandAccess::read};
        if (insert && rt) i.register_reads = {reg(rt)};
        if (rs) i.register_reads.push_back(reg(rs));
        if (rt) i.register_writes = {reg(rt)};
    } else if (op == 2 || op == 3) {
        i.opcode = op == 2 ? Opcode::mips_j : Opcode::mips_jal;
        const auto pc4 = static_cast<std::uint32_t>(static_cast<std::uint32_t>(at.offset) + 4u);
        i.direct_target = Address{at.space, (pc4 & 0xf0000000u) | ((w & 0x03ffffffu) << 2)};
        i.operands = {RelativeOperand{static_cast<std::int64_t>(w & 0x03ffffffu) << 2, 26, 32, EncodedField{0, 4}}};
        i.access = {OperandAccess::read};
        i.flow = op == 2 ? FlowKind::jump : FlowKind::call;
        if (op == 3) i.register_writes = {reg(31)};
        i.delay_slots = 1;
    } else if (op == 4 || op == 5 || op == 0x14 || op == 0x15) {
        branch(i, op == 4 ? Opcode::mips_beq : op == 5 ? Opcode::mips_bne :
                  op == 0x14 ? Opcode::mips_beql : Opcode::mips_bnel,
               rs, rt, signed16(w), true, order);
    } else if (op == 6 || op == 7 || op == 0x16 || op == 0x17) {
        if (rt != 0) return invalid("Reserved BLEZ/BGTZ encoding");
        i.opcode = op == 6 ? Opcode::mips_blez : op == 7 ? Opcode::mips_bgtz : op == 0x16 ? Opcode::mips_blezl : Opcode::mips_bgtzl;
        i.operands = {reg(rs)}; i.access = {OperandAccess::read}; i.register_reads = {reg(rs)};
        i.flow = FlowKind::conditional_branch; add_target(i, signed16(w), order); i.access.push_back(OperandAccess::address); i.delay_slots = 1;
    } else if (op == 1) {
        if (rt != 0 && rt != 1 && rt != 2 && rt != 3)
            return {DecodeStatus::unsupported, {}, "MIPS32 REGIMM branch-likely/link form is not implemented"};
        i.opcode = rt == 0 ? Opcode::mips_bltz : rt == 1 ? Opcode::mips_bgez : rt == 2 ? Opcode::mips_bltzl : Opcode::mips_bgezl;
        i.operands = {reg(rs)}; i.access = {OperandAccess::read}; i.register_reads = {reg(rs)};
        i.flow = FlowKind::conditional_branch; add_target(i, signed16(w), order); i.access.push_back(OperandAccess::address); i.delay_slots = 1;
    } else if (op == 8 || op == 9 || op == 10 || op == 11 || (op >= 12 && op <= 14)) {
        immediate(op == 8 ? Opcode::mips_addi : op == 9 ? Opcode::mips_addiu : op == 10 ? Opcode::mips_slti :
                  op == 11 ? Opcode::mips_sltiu : op == 12 ? Opcode::mips_andi : op == 13 ? Opcode::mips_ori : Opcode::mips_xori,
                  op < 12);
    } else if (op == 15) {
        if (rs != 0) return invalid("Reserved LUI encoding");
        i.opcode = Opcode::mips_lui;
        i.operands = {reg(rt), ImmediateOperand{w & 0xffff, 16, 32, false, EncodedField{static_cast<std::uint8_t>(order == ByteOrder::little ? 0 : 2), 2}}};
        i.access = {OperandAccess::write, OperandAccess::read}; if (rt) i.register_writes = {reg(rt)};
    } else {
        bool coprocessor_instruction = false;
        Opcode opcode = Opcode::opaque; unsigned width = 0; bool load = false;
        switch (op) {
        case 0x20: opcode=Opcode::mips_lb;width=8;load=true;break; case 0x21: opcode=Opcode::mips_lh;width=16;load=true;break;
        case 0x22: opcode=Opcode::mips_lwl;width=32;load=true;break; case 0x23: opcode=Opcode::mips_lw;width=32;load=true;break;
        case 0x24: opcode=Opcode::mips_lbu;width=8;load=true;break; case 0x25: opcode=Opcode::mips_lhu;width=16;load=true;break;
        case 0x26: opcode=Opcode::mips_lwr;width=32;load=true;break; case 0x28: opcode=Opcode::mips_sb;width=8;load=false;break;
        case 0x29: opcode=Opcode::mips_sh;width=16;load=false;break; case 0x2a: opcode=Opcode::mips_swl;width=32;load=false;break;
        case 0x2b: opcode=Opcode::mips_sw;width=32;load=false;break; case 0x2e: opcode=Opcode::mips_swr;width=32;load=false;break;
        default:
            if (op == 0x31 || op == 0x39 || op == 0x35 || op == 0x3d) { // LWC1/SWC1/LDC1/SDC1.
                const bool fp_load = op == 0x31 || op == 0x35;
                const bool double_width = op == 0x35 || op == 0x3d;
                const std::uint16_t fp_width = double_width ? 64 : 32;
                i.opcode = op == 0x31 ? Opcode::mips_lwc1 : op == 0x39 ? Opcode::mips_swc1 :
                           op == 0x35 ? Opcode::mips_ldc1 : Opcode::mips_sdc1;
                const auto fp = fpr(rt, fp_width);
                const auto memory = MemoryOperand{fp_width, 32, {}, reg(rs), {}, 1, signed16(w), false, {},
                    EncodedField{static_cast<std::uint8_t>(order == ByteOrder::little ? 0 : 2), 2}};
                i.operands = {fp, memory};
                i.access = fp_load ? std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read}
                                   : std::vector<OperandAccess>{OperandAccess::read, OperandAccess::write};
                i.memory_read = fp_load; i.memory_write = !fp_load;
                if (fp_load) i.register_writes = {fp}; else i.register_reads = {fp};
                return {DecodeStatus::decoded, std::move(i), {}};
            }
            if (op == 0x11) { // COP1 scalar arithmetic and CC0 branches.
                if (rs == 8) { // BC1F/BC1T and likely FCC0-FCC7 forms.
                    const auto condition_code = (rt >> 2) & 7;
                    i.opcode = (rt & 2) ? ((rt & 1) ? Opcode::mips_bc1tl : Opcode::mips_bc1fl)
                                         : ((rt & 1) ? Opcode::mips_bc1t : Opcode::mips_bc1f);
                    i.condition = static_cast<std::uint8_t>(condition_code);
                    i.flow = FlowKind::conditional_branch; i.delay_slots = 1;
                    i.register_reads = {fcc(condition_code)};
                    i.access = {OperandAccess::address};
                    add_target(i, signed16(w), order);
                    return {DecodeStatus::decoded, std::move(i), {}};
                }
                if (rs == 0 || rs == 2 || rs == 4 || rs == 6) { // MFC1/CFC1/MTC1/CTC1.
                    if ((w & 0x7ffu) != 0) return invalid("Reserved MIPS32 COP1 transfer encoding");
                    const bool from_cop = rs == 0 || rs == 2;
                    const bool control = rs == 2 || rs == 6;
                    if (control && rd != 25 && rd != 26 && rd != 28 && rd != 31)
                        return {DecodeStatus::unsupported, {}, "MIPS32 COP1 control transfers support FCCR25, FEXR26, FENR28, and FCSR31"};
                    const auto general = reg(rt);
                    const auto cop = control ? R{RegisterBank::mips_fcsr,
                        static_cast<std::uint8_t>(rd == 31 ? 0 : rd), 32, false} : fpr(rd);
                    i.opcode = rs == 0 ? Opcode::mips_mfc1 : rs == 2 ? Opcode::mips_cfc1 :
                               rs == 4 ? Opcode::mips_mtc1 : Opcode::mips_ctc1;
                    i.operands = {general, cop};
                    i.access = from_cop ? std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read}
                                        : std::vector<OperandAccess>{OperandAccess::read, OperandAccess::write};
                    if (from_cop) {
                        i.register_reads = {cop};
                        if (control && rd != 31) i.register_reads.push_back(fcsr());
                        if (rt) i.register_writes = {general};
                    } else {
                        if (rt) i.register_reads = {general};
                        i.register_writes = {cop};
                        if (control && rd != 31) {
                            i.register_reads.push_back(fcsr());
                            i.register_writes.push_back(fcsr());
                        }
                        if (control && (rd == 25 || rd == 31))
                            for (unsigned condition_code = 0; condition_code < 8; ++condition_code)
                                i.register_writes.push_back(fcc(condition_code));
                    }
                    return {DecodeStatus::decoded, std::move(i), {}};
                }
                if (rs != 16 && rs != 17 && rs != 20)
                    return {DecodeStatus::unsupported, {}, "MIPS32 COP1 format is outside the implemented S/D/W subset"};
                const unsigned ft = rt, fs = rd, fd = shamt;
                const unsigned fp_function = funct;
                bool unary = false, compare = false, explicit_operands = false;
                const bool double_format = rs == 17;
                const auto source_width = double_format ? 64u : 32u;
                const auto left = fpr(fs, source_width), right = fpr(ft, source_width);
                unsigned destination_width = source_width;
                const auto set_unary_conversion = [&](Opcode opcode, unsigned dst_width) {
                    i.opcode = opcode; unary = true;
                    destination_width = dst_width;
                    explicit_operands = true;
                };
                if ((rs == 16 || rs == 17) && fp_function <= 7) {
                    if (rs == 16) {
                        switch (fp_function) {
                        case 0: i.opcode=Opcode::mips_add_s; break; case 1: i.opcode=Opcode::mips_sub_s; break;
                        case 2: i.opcode=Opcode::mips_mul_s; break; case 3: i.opcode=Opcode::mips_div_s; break;
                        case 4: i.opcode=Opcode::mips_sqrt_s; unary=true; break; case 5: i.opcode=Opcode::mips_abs_s; unary=true; break;
                        case 6: i.opcode=Opcode::mips_mov_s; unary=true; break; case 7: i.opcode=Opcode::mips_neg_s; unary=true; break;
                        }
                    } else {
                        switch (fp_function) {
                        case 0: i.opcode=Opcode::mips_add_d; break; case 1: i.opcode=Opcode::mips_sub_d; break;
                        case 2: i.opcode=Opcode::mips_mul_d; break; case 3: i.opcode=Opcode::mips_div_d; break;
                        case 4: i.opcode=Opcode::mips_sqrt_d; unary=true; break; case 5: i.opcode=Opcode::mips_abs_d; unary=true; break;
                        case 6: i.opcode=Opcode::mips_mov_d; unary=true; break; case 7: i.opcode=Opcode::mips_neg_d; unary=true; break;
                        }
                    }
                } else if ((rs == 16 || rs == 17) && fp_function >= 0x30 && fp_function <= 0x3f) {
                    if ((shamt & 3u) != 0) return invalid("Reserved COP1 compare condition-code bits are nonzero");
                    const auto condition_code = static_cast<std::uint8_t>((shamt >> 2) & 7);
                    i.opcode = double_format ? Opcode::mips64_c_cond_d : Opcode::mips64_c_cond_s;
                    i.condition = static_cast<std::uint8_t>((condition_code << 4) | (fp_function & 0x0f));
                    compare = true;
                } else if ((rs == 17 && fp_function == 0x20) || (rs == 16 && fp_function == 0x21)) {
                    set_unary_conversion(rs == 17 ? Opcode::mips_cvt_s_d : Opcode::mips_cvt_d_s, rs == 17 ? 32 : 64);
                } else if ((rs == 16 || rs == 17) && fp_function >= 0x0c && fp_function <= 0x0f) {
                    const auto base = rs == 16 ? Opcode::mips_round_w_s : Opcode::mips_round_w_d;
                    set_unary_conversion(static_cast<Opcode>(static_cast<unsigned>(base) + (fp_function - 0x0c)), 32);
                } else if ((rs == 16 || rs == 17) && fp_function == 0x24) {
                    set_unary_conversion(rs == 16 ? Opcode::mips_cvt_w_s : Opcode::mips_cvt_w_d, 32);
                } else if (rs == 20 && (fp_function == 0x20 || fp_function == 0x21)) {
                    destination_width = fp_function == 0x21 ? 64 : 32;
                    const auto destination = fpr(fd, destination_width);
                    const auto source = fpr(fs, 32);
                    i.opcode = fp_function == 0x20 ? Opcode::mips_cvt_s_w : Opcode::mips_cvt_d_w;
                    i.operands = {destination, source};
                    i.access = {OperandAccess::write, OperandAccess::read};
                    i.register_reads = {source, fcsr()};
                    i.register_writes = {destination, fcsr()};
                    unary = true;
                    explicit_operands = true;
                } else if (!explicit_operands) {
                    return {DecodeStatus::unsupported, {}, "MIPS32 COP1 S/D/W operation is not implemented"};
                }
                if (unary && ft != 0) return invalid("Reserved COP1 unary operand field");
                if (compare) {
                    i.operands = {left, right}; i.access = {OperandAccess::read, OperandAccess::read};
                    const auto condition_code = static_cast<unsigned>((i.condition >> 4) & 7);
                    i.register_reads = {left, right}; i.register_writes = {fcc(condition_code)};
                } else {
                    const auto destination = fpr(fd, destination_width);
                    i.operands = unary ? std::vector<Operand>{destination, left}
                                       : std::vector<Operand>{destination, left, right};
                    i.access = unary ? std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read}
                                     : std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read, OperandAccess::read};
                    const bool fcsr_effect = i.opcode != Opcode::mips_abs_s && i.opcode != Opcode::mips_mov_s &&
                        i.opcode != Opcode::mips_neg_s && i.opcode != Opcode::mips_abs_d &&
                        i.opcode != Opcode::mips_mov_d && i.opcode != Opcode::mips_neg_d;
                    i.register_reads = unary ? std::vector<RegisterOperand>{left}
                                             : std::vector<RegisterOperand>{left, right};
                    if (fcsr_effect) i.register_reads.push_back(fcsr());
                    i.register_writes = {destination};
                    if (fcsr_effect) i.register_writes.push_back(fcsr());
                }
                return {DecodeStatus::decoded, std::move(i), {}};
            }
            if (op == 0x10) {
                if (rs == 0 || rs == 4) { // MFC0 / MTC0, select zero only.
                    if ((w & 0x7f8u) != 0 || (w & 7u) != 0)
                        return {DecodeStatus::unsupported, {}, "MIPS32 CP0 register selects are not implemented"};
                    const auto coprocessor = cp0(rd);
                    const auto general = reg(rt);
                    i.opcode = rs == 0 ? Opcode::mips_mfc0 : Opcode::mips_mtc0;
                    i.operands = {general, coprocessor};
                    i.access = rs == 0 ? std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read}
                                       : std::vector<OperandAccess>{OperandAccess::read, OperandAccess::write};
                    if (rs == 0) {
                        i.register_reads = {coprocessor};
                        if (rt) i.register_writes = {general};
                    } else {
                        i.register_reads = {general};
                        i.register_writes = {coprocessor};
                    }
                    coprocessor_instruction = true;
                    break;
                }
                if (rs == 16 && rt == 0 && rd == 0 && shamt == 0 && funct == 0x18) {
                    i.opcode = Opcode::mips_eret;
                    i.flow = FlowKind::ret;
                    coprocessor_instruction = true;
                    break;
                }
            }
            return op >= 0x10 && op <= 0x13 ? DecodeResult{DecodeStatus::unsupported, {}, "MIPS32 coprocessor instruction is not implemented"} : invalid("Reserved or unsupported MIPS32 opcode");
        }
        if (coprocessor_instruction) return {DecodeStatus::decoded, std::move(i), {}};
        i.opcode = opcode;
        MemoryOperand mem{static_cast<std::uint16_t>(width),32,{},reg(rs),{},1,signed16(w),false,{},EncodedField{static_cast<std::uint8_t>(order == ByteOrder::little ? 0 : 2),2}};
        i.operands = {reg(rt), mem}; i.access = {load ? OperandAccess::write : OperandAccess::read,
                                                   load ? OperandAccess::read : OperandAccess::write};
        if (load) { i.memory_read = true; if (rt) i.register_writes = {reg(rt)}; }
        else { i.memory_write = true; i.register_reads = {reg(rt)}; }
    }
    return {DecodeStatus::decoded, std::move(i), {}};
}
} // namespace hexlab
