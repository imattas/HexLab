#include "hexlab/processors/decoder.hpp"

#include <algorithm>

namespace hexlab {
namespace {
using R = RegisterOperand;
R reg(unsigned index) { return {RegisterBank::mips_gpr, static_cast<std::uint8_t>(index), 64, false}; }
std::int64_t signed16(std::uint32_t word) {
    const auto value = word & 0xffffu;
    return (value & 0x8000u) ? static_cast<std::int64_t>(value) - 0x10000 : value;
}
DecodeResult invalid(const char *reason) { return {DecodeStatus::invalid, {}, reason}; }
void target(Instruction &i, std::int64_t displacement) {
    i.direct_target = Address{i.address.space, i.address.offset + 4 + static_cast<std::uint64_t>(displacement * 4)};
    i.operands.push_back(RelativeOperand{displacement * 4, 16, 64, EncodedField{0, 2}});
}
void branch(Instruction &i, Opcode opcode, unsigned rs, unsigned rt, std::int64_t offset) {
    i.opcode = opcode;
    i.operands = {reg(rs), reg(rt)};
    i.access = {OperandAccess::read, OperandAccess::read};
    i.register_reads = {reg(rs), reg(rt)};
    i.flow = FlowKind::conditional_branch;
    target(i, offset);
    i.access.push_back(OperandAccess::address);
    i.delay_slots = 1;
}
} // namespace

DecodeResult decode_mips64(std::span<const std::byte> bytes, Address at, ByteOrder order) {
    if (bytes.size() < 4)
        return {DecodeStatus::truncated, {}, "MIPS64 instruction needs four bytes"};
    if (at.offset & 3)
        return invalid("MIPS64 instruction address is not word-aligned");
    const std::uint32_t b0 = std::to_integer<std::uint32_t>(bytes[0]);
    const std::uint32_t b1 = std::to_integer<std::uint32_t>(bytes[1]);
    const std::uint32_t b2 = std::to_integer<std::uint32_t>(bytes[2]);
    const std::uint32_t b3 = std::to_integer<std::uint32_t>(bytes[3]);
    const std::uint32_t word = order == ByteOrder::big ? (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
                                                        : b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    const auto op = word >> 26, rs = (word >> 21) & 31, rt = (word >> 16) & 31,
               rd = (word >> 11) & 31, shamt = (word >> 6) & 31, funct = word & 63;
    Instruction i;
    i.context = {Architecture::mips64, ExecutionMode::mips64, order};
    i.address = at;
    std::copy_n(bytes.begin(), 4, i.bytes.begin());
    i.length = 4;
    const auto binary = [&](Opcode opcode) {
        i.opcode = opcode;
        i.operands = {reg(rd), reg(rs), reg(rt)};
        i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
        i.register_reads = {reg(rs), reg(rt)};
        if (rd) i.register_writes = {reg(rd)};
    };
    const RegisterOperand hi{RegisterBank::mips_hilo, 0, 64, false};
    const RegisterOperand lo{RegisterBank::mips_hilo, 1, 64, false};
    if (op == 0x11) {
        const RegisterOperand fcsr{RegisterBank::mips_fcsr, 0, 32, false};
        if (rs == 8) { // BC1F/BC1T, FCC0-FCC7, non-likely forms.
            i.opcode = (rt & 2) ? ((rt & 1) ? Opcode::mips64_bc1tl : Opcode::mips64_bc1fl)
                                 : ((rt & 1) ? Opcode::mips_bc1t : Opcode::mips_bc1f);
            i.condition = static_cast<std::uint8_t>((rt >> 2) & 7);
            i.flow = FlowKind::conditional_branch; i.delay_slots = 1;
            i.register_reads = {fcsr}; i.access = {OperandAccess::address};
            target(i, signed16(word));
            return {DecodeStatus::decoded, std::move(i), {}};
        }
        if (rs == 0 || rs == 1 || rs == 2 || rs == 4 || rs == 5 || rs == 6) {
            if ((word & 0x7ffu) != 0) return invalid("Reserved MIPS64 COP1 transfer encoding");
            const bool from_cop = rs == 0 || rs == 1 || rs == 2;
            const bool control = rs == 2 || rs == 6;
            const bool doubleword = rs == 1 || rs == 5;
            if (control && rd != 31 && rd != 25 && rd != 26 && rd != 28)
                return {DecodeStatus::unsupported, {}, "MIPS64 COP1 control transfers support FCCR25, FEXR26, FENR28, and FCSR31"};
            const auto general = reg(rt);
            const RegisterOperand cop = control ? RegisterOperand{RegisterBank::mips_fcsr,
                static_cast<std::uint8_t>(rd == 31 ? 0 : rd), 32, false} : RegisterOperand{RegisterBank::mips_fpr,
                static_cast<std::uint8_t>(rd), static_cast<std::uint16_t>(doubleword ? 64 : 32), false};
            i.opcode = rs == 0 ? Opcode::mips64_mfc1 : rs == 1 ? Opcode::mips64_dmfc1 :
                       rs == 2 ? Opcode::mips64_cfc1 : rs == 4 ? Opcode::mips64_mtc1 :
                       rs == 5 ? Opcode::mips64_dmtc1 : Opcode::mips64_ctc1;
            i.operands = {general, cop};
            i.access = from_cop ? std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read}
                                : std::vector<OperandAccess>{OperandAccess::read, OperandAccess::write};
            if (from_cop) {
                i.register_reads = {cop};
                if (control && rd != 31) i.register_reads.push_back(fcsr);
                if (rt) i.register_writes = {general};
            } else {
                if (rt) i.register_reads = {general};
                i.register_writes = {cop};
                if (control && rd != 31) {
                    i.register_reads.push_back(fcsr);
                    i.register_writes.push_back(fcsr);
                }
            }
            return {DecodeStatus::decoded, std::move(i), {}};
        }
        if (rs != 16 && rs != 17 && rs != 20 && rs != 21)
            return {DecodeStatus::unsupported, {}, "MIPS64 COP1 format is outside the S/D/W/L subset"};
        if ((rs == 16 || rs == 17) && (funct == 0x11 || funct == 0x12 || funct == 0x13)) {
            const bool is_double = rs == 17;
            const auto width = static_cast<std::uint16_t>(is_double ? 64 : 32);
            const bool fcc_move = funct == 0x11;
            if (fcc_move && (rt & 2))
                return invalid("Reserved MIPS64 MOVF/MOVT condition field");
            i.opcode = is_double
                ? (funct == 0x11 ? ((rt & 1) ? Opcode::mips64_movt_d : Opcode::mips64_movf_d) :
                   funct == 0x12 ? Opcode::mips64_movz_d : Opcode::mips64_movn_d)
                : (funct == 0x11 ? ((rt & 1) ? Opcode::mips64_movt_s : Opcode::mips64_movf_s) :
                   funct == 0x12 ? Opcode::mips64_movz_s : Opcode::mips64_movn_s);
            const RegisterOperand destination{RegisterBank::mips_fpr, static_cast<std::uint8_t>(shamt), width, false};
            const RegisterOperand source{RegisterBank::mips_fpr, static_cast<std::uint8_t>(rd), width, false};
            i.operands = {destination, source};
            i.access = {OperandAccess::read_write, OperandAccess::read};
            i.register_reads = {destination, source};
            i.register_writes = {destination};
            if (fcc_move) {
                const auto cc = static_cast<std::uint8_t>((rt >> 2) & 7);
                i.operands.emplace_back(ImmediateOperand{cc, 3, 32, false, {}});
                i.access.push_back(OperandAccess::read);
                i.register_reads.push_back(fcsr);
                i.condition = cc;
            } else {
                const auto condition = reg(rt);
                i.operands.emplace_back(condition);
                i.access.push_back(OperandAccess::read);
                if (rt) i.register_reads.push_back(condition);
            }
            return {DecodeStatus::decoded, std::move(i), {}};
        }
        const bool double_format = rs == 17;
        const auto ft = static_cast<unsigned>(rt), fs = static_cast<unsigned>(rd), fd = static_cast<unsigned>(shamt);
        const std::uint16_t source_width = rs == 17 || rs == 21 ? 64 : 32;
        const RegisterOperand left{RegisterBank::mips_fpr, static_cast<std::uint8_t>(fs), source_width, false};
        const RegisterOperand right{RegisterBank::mips_fpr, static_cast<std::uint8_t>(ft), source_width, false};
        bool unary = false, compare = false;
        std::uint16_t destination_width = source_width;
        const auto conversion = [&](Opcode opcode, std::uint16_t result_width) {
            i.opcode = opcode; unary = true; destination_width = result_width;
        };
        if ((rs == 16 || rs == 17) && funct <= 7) {
            if (double_format) {
                static constexpr Opcode operations[]{Opcode::mips_add_d, Opcode::mips_sub_d, Opcode::mips_mul_d,
                    Opcode::mips_div_d, Opcode::mips_sqrt_d, Opcode::mips_abs_d, Opcode::mips_mov_d, Opcode::mips_neg_d};
                i.opcode = operations[funct];
            } else {
                static constexpr Opcode operations[]{Opcode::mips_add_s, Opcode::mips_sub_s, Opcode::mips_mul_s,
                    Opcode::mips_div_s, Opcode::mips_sqrt_s, Opcode::mips_abs_s, Opcode::mips_mov_s, Opcode::mips_neg_s};
                i.opcode = operations[funct];
            }
            unary = funct >= 4;
            if (unary && ft != 0) return invalid("Reserved MIPS64 COP1 unary operand field");
        } else if ((rs == 16 || rs == 17) && funct >= 0x30 && funct <= 0x3f) {
            if (shamt & 3) return invalid("Reserved MIPS64 COP1 compare condition fields");
            const auto condition_code = static_cast<std::uint8_t>((shamt >> 2) & 7);
            if (funct == 0x32 || funct == 0x3c || funct == 0x3e)
                i.condition = condition_code;
            else
                i.condition = static_cast<std::uint8_t>((condition_code << 4) | (funct & 0x0f));
            if (funct == 0x32)
                i.opcode = double_format ? Opcode::mips_c_eq_d : Opcode::mips_c_eq_s;
            else if (funct == 0x3c)
                i.opcode = double_format ? Opcode::mips_c_lt_d : Opcode::mips_c_lt_s;
            else if (funct == 0x3e)
                i.opcode = double_format ? Opcode::mips_c_le_d : Opcode::mips_c_le_s;
            else
                i.opcode = double_format ? Opcode::mips64_c_cond_d : Opcode::mips64_c_cond_s;
            compare = true;
        } else if ((rs == 16 || rs == 17) && funct >= 0x08 && funct <= 0x0b) {
            static constexpr Opcode single[]{Opcode::mips64_round_l_s, Opcode::mips64_trunc_l_s,
                Opcode::mips64_ceil_l_s, Opcode::mips64_floor_l_s};
            static constexpr Opcode dbl[]{Opcode::mips64_round_l_d, Opcode::mips64_trunc_l_d,
                Opcode::mips64_ceil_l_d, Opcode::mips64_floor_l_d};
            conversion(double_format ? dbl[funct - 0x08] : single[funct - 0x08], 64);
        } else if ((rs == 16 || rs == 17) && funct >= 0x0c && funct <= 0x0f) {
            static constexpr Opcode single[]{Opcode::mips_round_w_s, Opcode::mips_trunc_w_s,
                Opcode::mips_ceil_w_s, Opcode::mips_floor_w_s};
            static constexpr Opcode dbl[]{Opcode::mips_round_w_d, Opcode::mips_trunc_w_d,
                Opcode::mips_ceil_w_d, Opcode::mips_floor_w_d};
            conversion(double_format ? dbl[funct - 0x0c] : single[funct - 0x0c], 32);
        } else if ((rs == 16 || rs == 17) && funct == 0x20 && double_format) {
            conversion(Opcode::mips_cvt_s_d, 32);
        } else if (rs == 16 && funct == 0x21) {
            conversion(Opcode::mips_cvt_d_s, 64);
        } else if ((rs == 16 || rs == 17) && funct == 0x24) {
            conversion(double_format ? Opcode::mips_cvt_w_d : Opcode::mips_cvt_w_s, 32);
        } else if ((rs == 16 || rs == 17) && funct == 0x25) {
            conversion(double_format ? Opcode::mips64_cvt_l_d : Opcode::mips64_cvt_l_s, 64);
        } else if (rs == 20 && funct == 0x20) {
            conversion(Opcode::mips_cvt_s_w, 32);
        } else if (rs == 20 && funct == 0x21) {
            conversion(Opcode::mips_cvt_d_w, 64);
        } else if (rs == 21 && funct == 0x20) {
            conversion(Opcode::mips64_cvt_s_l, 32);
        } else if (rs == 21 && funct == 0x21) {
            conversion(Opcode::mips64_cvt_d_l, 64);
        } else {
            return {DecodeStatus::unsupported, {}, "MIPS64 COP1 S/D/W/L operation is not implemented"};
        }
        if (unary) {
            if (ft != 0) return invalid("Reserved MIPS64 COP1 unary operand field");
            const RegisterOperand destination{RegisterBank::mips_fpr, static_cast<std::uint8_t>(fd), destination_width, false};
            i.operands = {destination, left};
            i.access = {OperandAccess::write, OperandAccess::read};
            i.register_reads = {left, fcsr}; i.register_writes = {destination, fcsr};
        } else if (compare) {
            i.operands = {left, right}; i.access = {OperandAccess::read, OperandAccess::read};
            i.register_reads = {left, right, fcsr}; i.register_writes = {fcsr};
        } else {
            const RegisterOperand destination{RegisterBank::mips_fpr, static_cast<std::uint8_t>(fd), source_width, false};
            i.operands = {destination, left, right};
            i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
            i.register_reads = {left, right, fcsr}; i.register_writes = {destination, fcsr};
        }
    } else if (op == 0x31 || op == 0x35 || op == 0x39 || op == 0x3d) { // LWC1/LDC1/SWC1/SDC1.
        const bool load = op == 0x31 || op == 0x35;
        const bool double_width = op == 0x35 || op == 0x3d;
        const std::uint16_t width = double_width ? 64 : 32;
        const RegisterOperand fp{RegisterBank::mips_fpr, static_cast<std::uint8_t>(rt), width, false};
        MemoryOperand memory{width, 64, {}, reg(rs), {}, 1, signed16(word), false, {}, EncodedField{0, 2}};
        i.opcode = op == 0x31 ? Opcode::mips_lwc1 : op == 0x39 ? Opcode::mips_swc1 :
                   op == 0x35 ? Opcode::mips_ldc1 : Opcode::mips_sdc1;
        i.operands = {fp, memory};
        i.access = load ? std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read}
                        : std::vector<OperandAccess>{OperandAccess::read, OperandAccess::write};
        i.memory_read = load; i.memory_write = !load;
        if (load) i.register_writes = {fp}; else i.register_reads = {fp};
    } else if (op == 0) {
        switch (funct) {
        case 0x08: case 0x09:
            if (rt || shamt || (funct == 0x08 && rd)) return invalid("Reserved MIPS64 register jump encoding");
            i.opcode = funct == 8 ? Opcode::mips_jr : Opcode::mips_jalr;
            i.operands = {reg(rs)};
            i.access = {OperandAccess::read};
            i.register_reads = {reg(rs)};
            if (funct == 8 && rs == 31) i.flow = FlowKind::ret;
            else if (funct == 9) { i.flow = FlowKind::call; if (rd) i.register_writes = {reg(rd)}; }
            else i.flow = FlowKind::jump;
            i.delay_slots = 1;
            break;
        case 0x10: case 0x12: // MFHI/MFLO
            if (rs || rt || shamt) return invalid("Reserved MIPS64 HI/LO read encoding");
            i.opcode = funct == 0x10 ? Opcode::mips64_mfhi : Opcode::mips64_mflo;
            i.operands = {reg(rd)}; i.access = {OperandAccess::write};
            i.register_reads = {funct == 0x10 ? hi : lo};
            if (rd) i.register_writes = {reg(rd)};
            break;
        case 0x11: case 0x13: // MTHI/MTLO
            if (rt || rd || shamt) return invalid("Reserved MIPS64 HI/LO write encoding");
            i.opcode = funct == 0x11 ? Opcode::mips64_mthi : Opcode::mips64_mtlo;
            i.operands = {reg(rs)}; i.access = {OperandAccess::read};
            if (rs) i.register_reads = {reg(rs)};
            i.register_writes = {funct == 0x11 ? hi : lo};
            break;
        case 0x1c: case 0x1d: case 0x1e: case 0x1f: // DMULT/U, DDIV/U
            if (rd || shamt) return invalid("Reserved MIPS64 doubleword HI/LO arithmetic encoding");
            i.opcode = funct == 0x1c ? Opcode::mips64_dmult : funct == 0x1d ? Opcode::mips64_dmultu :
                       funct == 0x1e ? Opcode::mips64_ddiv : Opcode::mips64_ddivu;
            i.operands = {reg(rs), reg(rt)}; i.access = {OperandAccess::read, OperandAccess::read};
            i.register_reads = {reg(rs), reg(rt)}; i.register_writes = {hi, lo};
            break;
        case 0x18: case 0x19: case 0x1a: case 0x1b: // MULT/U, DIV/U
            if (rd || shamt) return invalid("Reserved MIPS64 word HI/LO arithmetic encoding");
            i.opcode = funct == 0x18 ? Opcode::mips64_mult : funct == 0x19 ? Opcode::mips64_multu :
                       funct == 0x1a ? Opcode::mips64_div : Opcode::mips64_divu;
            i.operands = {reg(rs), reg(rt)}; i.access = {OperandAccess::read, OperandAccess::read};
            i.register_reads = {reg(rs), reg(rt)}; i.register_writes = {hi, lo};
            break;
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x36: {
            // Trap comparisons use the otherwise-unused rd/shamt bits as a
            // 10-bit software trap code; they are not reserved zeros.
            static constexpr Opcode operations[]{Opcode::mips64_tge, Opcode::mips64_tgeu,
                Opcode::mips64_tlt, Opcode::mips64_tltu, Opcode::mips64_teq, Opcode::mips64_tne};
            const unsigned index = funct == 0x30 ? 0 : funct == 0x31 ? 1 : funct == 0x32 ? 2 :
                                   funct == 0x33 ? 3 : funct == 0x34 ? 4 : 5;
            i.opcode = operations[index];
            i.operands = {reg(rs), reg(rt), ImmediateOperand{(word >> 6) & 0x3ffu, 10, 32, false,
                                                              EncodedField{0, 2}}};
            i.access = {OperandAccess::read, OperandAccess::read, OperandAccess::read};
            if (rs) i.register_reads.push_back(reg(rs));
            if (rt) i.register_reads.push_back(reg(rt));
            break;
        }
        case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25: case 0x26: case 0x27:
        case 0x2a: case 0x2b:
            if (shamt) return invalid("Reserved MIPS64 arithmetic encoding");
            binary(funct == 0x20 ? Opcode::mips64_add : funct == 0x21 ? Opcode::mips64_addu :
                   funct == 0x22 ? Opcode::mips64_sub : funct == 0x23 ? Opcode::mips64_subu :
                   funct == 0x24 ? Opcode::mips_and : funct == 0x25 ? Opcode::mips_or :
                   funct == 0x26 ? Opcode::mips_xor : funct == 0x27 ? Opcode::mips_nor :
                   funct == 0x2a ? Opcode::mips64_slt : Opcode::mips64_sltu);
            break;
        case 0x2c: case 0x2d: case 0x2e: case 0x2f:
            if (shamt) return invalid("Reserved MIPS64 doubleword arithmetic encoding");
            binary(funct == 0x2c ? Opcode::mips64_dadd : funct == 0x2d ? Opcode::mips64_daddu :
                   funct == 0x2e ? Opcode::mips64_dsub : Opcode::mips64_dsubu);
            break;
        case 0x00: case 0x02: case 0x03: case 0x38: case 0x3a: case 0x3b:
        case 0x3c: case 0x3e: case 0x3f: {
            const bool rotate = (funct == 0x3a || funct == 0x3e) && rs == 1;
            if (rs && !rotate) return invalid("Reserved MIPS64 fixed-shift encoding");
            unsigned amount = shamt;
            Opcode opcode;
            if (rotate) {
                opcode = funct == 0x3a ? Opcode::mips64_drotr : Opcode::mips64_drotr32;
                if (funct == 0x3e) amount += 32;
            } else if (funct == 0x00) opcode = Opcode::mips64_sll;
            else if (funct == 0x02) opcode = Opcode::mips64_srl;
            else if (funct == 0x03) opcode = Opcode::mips64_sra;
            else if (funct == 0x38) opcode = Opcode::mips64_dsll;
            else if (funct == 0x3a) opcode = Opcode::mips64_dsrl;
            else if (funct == 0x3b) opcode = Opcode::mips64_dsra;
            else if (funct == 0x3c) { opcode = Opcode::mips64_dsll32; amount += 32; }
            else if (funct == 0x3e) { opcode = Opcode::mips64_dsrl32; amount += 32; }
            else { opcode = Opcode::mips64_dsra32; amount += 32; }
            if ((funct <= 3 && amount > 31) || (funct >= 0x38 && amount > 63))
                return invalid("MIPS64 shift amount exceeds its operand width");
            i.opcode = opcode;
            i.operands = {reg(rd), reg(rt), ImmediateOperand{amount, 6, 64, false, EncodedField{3, 1}}};
            i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
            i.register_reads = {reg(rt)};
            if (rd) i.register_writes = {reg(rd)};
            break;
        }
        case 0x14: case 0x16: case 0x17:
            if (funct == 0x16 && shamt == 1) i.opcode = Opcode::mips64_drotrv;
            else {
                if (shamt) return invalid("Reserved MIPS64 variable-shift encoding");
                i.opcode = funct == 0x14 ? Opcode::mips64_dsllv : funct == 0x16 ? Opcode::mips64_dsrlv : Opcode::mips64_dsrav;
            }
            i.operands = {reg(rd), reg(rt), reg(rs)};
            i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
            i.register_reads = {reg(rt), reg(rs)};
            if (rd) i.register_writes = {reg(rd)};
            break;
        case 0x04: case 0x06: case 0x07:
            if (shamt) return invalid("Reserved MIPS64 variable-shift encoding");
            i.opcode = funct == 4 ? Opcode::mips64_sllv : funct == 6 ? Opcode::mips64_srlv : Opcode::mips64_srav;
            i.operands = {reg(rd), reg(rt), reg(rs)};
            i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
            i.register_reads = {reg(rt), reg(rs)};
            if (rd) i.register_writes = {reg(rd)};
            break;
        case 0x0a: case 0x0b:
            if (shamt) return invalid("Reserved MIPS64 conditional-move encoding");
            i.opcode = funct == 0x0a ? Opcode::mips64_movz : Opcode::mips64_movn;
            i.operands = {reg(rd), reg(rs), reg(rt)};
            i.access = {OperandAccess::read_write, OperandAccess::read, OperandAccess::read};
            i.register_reads = {reg(rd), reg(rs), reg(rt)};
            if (rd) i.register_writes = {reg(rd)};
            break;
        case 0x0f:
            if (rs || rt || rd) return invalid("Reserved MIPS64 SYNC encoding");
            i.opcode = Opcode::mips_sync;
            if (shamt) i.operands = {ImmediateOperand{shamt, 5, 32, false, EncodedField{0, 2}}};
            break;
        default: return invalid("Reserved or unsupported MIPS64 SPECIAL function");
        }
    } else if (op == 0x1c && funct == 0x02) {
        // MUL produces the low 32 bits of a signed word product, sign-extended
        // to the 64-bit GPR. HI/LO are architecturally unpredictable.
        if (shamt) return invalid("Reserved MIPS64 MUL encoding");
        i.opcode = Opcode::mips64_mul;
        i.operands = {reg(rd), reg(rs), reg(rt)};
        i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
        if (rs) i.register_reads.push_back(reg(rs));
        if (rt) i.register_reads.push_back(reg(rt));
        if (rd) i.register_writes.push_back(reg(rd));
        i.register_writes.push_back(hi);
        i.register_writes.push_back(lo);
    } else if (op == 0x1c) {
        // Pre-Release 6 SPECIAL2 count-leading forms. In these encodings the
        // architecture requires rt == rd for compliant software.
        if (funct == 0x00 || funct == 0x01 || funct == 0x04 || funct == 0x05) {
            if (rd || shamt) return invalid("Reserved MIPS64 SPECIAL2 multiply-accumulate encoding");
            i.opcode = funct == 0x00 ? Opcode::mips64_madd : funct == 0x01 ? Opcode::mips64_maddu :
                       funct == 0x04 ? Opcode::mips64_msub : Opcode::mips64_msubu;
            i.operands = {reg(rs), reg(rt)};
            i.access = {OperandAccess::read, OperandAccess::read};
            i.register_reads = {reg(rs), reg(rt), hi, lo};
            i.register_writes = {hi, lo};
        } else {
        Opcode opcode;
        switch (funct) {
        case 0x20: opcode = Opcode::mips_clz; break;
        case 0x21: opcode = Opcode::mips_clo; break;
        case 0x24: opcode = Opcode::mips64_dclz; break;
        case 0x25: opcode = Opcode::mips64_dclo; break;
        default: return {DecodeStatus::unsupported, {}, "MIPS64 SPECIAL2 operation is not implemented"};
        }
        if (rt != rd || shamt != 0)
            return invalid("Reserved MIPS64 count-leading encoding");
        i.opcode = opcode;
        i.operands = {reg(rd), reg(rs)};
        i.access = {OperandAccess::write, OperandAccess::read};
        if (rs) i.register_reads = {reg(rs)};
        if (rd) i.register_writes = {reg(rd)};
        }
    } else if (op == 0x1f) {
        // MIPS64 Release 2 SPECIAL3 doubleword extract/insert fields. The
        // three encodings divide the architectural field range into the
        // lower, crossing, and upper-word cases.
        const auto position_field = static_cast<unsigned>(shamt);
        const auto size_field = static_cast<unsigned>(rd);
        const auto function = static_cast<unsigned>(funct);
        bool insert = false;
        unsigned position = 0;
        unsigned size = 0;
        Opcode opcode = Opcode::opaque;
        switch (function) {
        case 0x03: // DEXT; position 0..31, size 1..32.
            position = position_field; size = size_field + 1;
            if (position + size > 64) return invalid("Reserved MIPS64 DEXT range");
            opcode = Opcode::mips64_dext; break;
        case 0x01: // DEXTM; destination field extends above bit 31.
            position = position_field; size = size_field + 33;
            if (position + size > 64) return invalid("Reserved MIPS64 DEXTM range");
            opcode = Opcode::mips64_dextm; break;
        case 0x02: // DEXTU; source begins in the upper word.
            position = position_field + 32; size = size_field + 1;
            if (position + size > 64) return invalid("Reserved MIPS64 DEXTU range");
            opcode = Opcode::mips64_dextu; break;
        case 0x07: // DINS; MSB is encoded directly in rd.
            if (size_field < position_field) return invalid("Reserved MIPS64 DINS range");
            position = position_field; size = size_field - position_field + 1;
            insert = true; opcode = Opcode::mips64_dins; break;
        case 0x05: // DINSM; destination MSB is in the upper word.
            position = position_field; size = size_field + 33;
            if (position + size > 64) return invalid("Reserved MIPS64 DINSM range");
            insert = true; opcode = Opcode::mips64_dinsm; break;
        case 0x06: // DINSU; source and destination begin in the upper word.
            position = position_field + 32; size = size_field + 1;
            if (position + size > 64) return invalid("Reserved MIPS64 DINSU range");
            insert = true; opcode = Opcode::mips64_dinsu; break;
        default:
            return {DecodeStatus::unsupported, {}, "MIPS64 SPECIAL3 operation is outside the bitfield subset"};
        }
        i.opcode = opcode;
        i.operands = {reg(rt), reg(rs),
            ImmediateOperand{position, 6, 64, false, EncodedField{3, 1}},
            ImmediateOperand{size, 7, 64, false, EncodedField{2, 1}}};
        i.access = {insert ? OperandAccess::read_write : OperandAccess::write,
                    OperandAccess::read, OperandAccess::read, OperandAccess::read};
        if (insert && rt) i.register_reads.push_back(reg(rt));
        if (rs) i.register_reads.push_back(reg(rs));
        if (rt) i.register_writes.push_back(reg(rt));
    } else if (op == 2 || op == 3) {
        i.opcode = op == 2 ? Opcode::mips_j : Opcode::mips_jal;
        const auto pc4 = at.offset + 4;
        const auto target_value = (pc4 & ~UINT64_C(0x0fffffff)) | (std::uint64_t{word & 0x03ffffffu} << 2);
        i.direct_target = Address{i.address.space, target_value};
        i.operands = {RelativeOperand{static_cast<std::int64_t>(word & 0x03ffffffu) << 2, 26, 64, EncodedField{0, 4}}};
        i.access = {OperandAccess::address};
        i.flow = op == 2 ? FlowKind::jump : FlowKind::call;
        if (op == 3) i.register_writes = {reg(31)};
        i.delay_slots = 1;
    } else if (op == 4 || op == 5 || op == 0x14 || op == 0x15) {
        branch(i, op == 4 ? Opcode::mips_beq : op == 5 ? Opcode::mips_bne :
                  op == 0x14 ? Opcode::mips_beql : Opcode::mips_bnel, rs, rt, signed16(word));
    } else if (op == 6 || op == 7 || op == 0x16 || op == 0x17) {
        if (rt) return invalid("Reserved MIPS64 BLEZ/BGTZ encoding");
        i.opcode = op == 6 ? Opcode::mips_blez : op == 7 ? Opcode::mips_bgtz : op == 0x16 ? Opcode::mips_blezl : Opcode::mips_bgtzl;
        i.operands = {reg(rs)}; i.access = {OperandAccess::read}; i.register_reads = {reg(rs)};
        i.flow = FlowKind::conditional_branch; target(i, signed16(word)); i.access.push_back(OperandAccess::address); i.delay_slots = 1;
    } else if (op == 1) {
        if (rt == 8 || rt == 9 || rt == 10 || rt == 11 || rt == 12 || rt == 14) {
            static constexpr Opcode trap_operations[]{Opcode::mips64_tgei, Opcode::mips64_tgeiu,
                Opcode::mips64_tlti, Opcode::mips64_tltiu, Opcode::mips64_teqi, Opcode::mips64_tnei};
            const unsigned index = rt == 8 ? 0 : rt == 9 ? 1 : rt == 10 ? 2 :
                                   rt == 11 ? 3 : rt == 12 ? 4 : 5;
            i.opcode = trap_operations[index];
            i.operands = {reg(rs), ImmediateOperand{static_cast<std::uint64_t>(signed16(word)), 16, 64,
                                                     true, EncodedField{2, 2}}};
            i.access = {OperandAccess::read, OperandAccess::read};
            if (rs) i.register_reads = {reg(rs)};
        } else {
        if (rt > 3 && (rt < 16 || rt > 19)) return {DecodeStatus::unsupported, {}, "MIPS64 REGIMM suboperation is unsupported"};
        const bool link = rt >= 16;
        const bool ge_zero = (rt & 1) != 0;
        const bool likely = (rt & 2) != 0;
        i.opcode = link ? (ge_zero ? (likely ? Opcode::mips64_bgezall : Opcode::mips64_bgezal)
                                    : (likely ? Opcode::mips64_bltzall : Opcode::mips64_bltzal)) :
                   ge_zero ? (likely ? Opcode::mips_bgezl : Opcode::mips_bgez)
                           : (likely ? Opcode::mips_bltzl : Opcode::mips_bltz);
        i.operands = {reg(rs)}; i.access = {OperandAccess::read}; i.register_reads = {reg(rs)};
        if (link) i.register_writes = {reg(31)};
        i.flow = FlowKind::conditional_branch; target(i, signed16(word)); i.access.push_back(OperandAccess::address); i.delay_slots = 1;
        }
    } else if (op == 0x08 || op == 0x09 || op == 0x0a || op == 0x0b || (op >= 0x0c && op <= 0x0e) || op == 0x18 || op == 0x19) {
        i.opcode = op == 0x08 ? Opcode::mips64_addi : op == 0x09 ? Opcode::mips64_addiu : op == 0x0a ? Opcode::mips64_slti :
                   op == 0x0b ? Opcode::mips64_sltiu : op == 0x0c ? Opcode::mips_andi : op == 0x0d ? Opcode::mips_ori :
                   op == 0x0e ? Opcode::mips_xori : op == 0x18 ? Opcode::mips64_daddi : Opcode::mips64_daddiu;
        const bool sign = op == 0x08 || op == 0x09 || op == 0x0a || op == 0x0b || op == 0x18 || op == 0x19;
        const auto raw = sign ? static_cast<std::uint64_t>(signed16(word)) : std::uint64_t{word & 0xffffu};
        i.operands = {reg(rt), reg(rs), ImmediateOperand{raw, 16, 64, sign, EncodedField{2, 2}}};
        i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
        if (rs) i.register_reads = {reg(rs)};
        if (rt) i.register_writes = {reg(rt)};
    } else if (op == 0x0f) {
        if (rs) return invalid("Reserved MIPS64 LUI encoding");
        i.opcode = Opcode::mips_lui;
        i.operands = {reg(rt), ImmediateOperand{word & 0xffffu, 16, 16, false, EncodedField{2, 2}}};
        i.access = {OperandAccess::write, OperandAccess::read};
        if (rt) i.register_writes = {reg(rt)};
    } else {
        Opcode opcode = Opcode::opaque; unsigned width = 0; bool load = false;
        bool unaligned_merge = false;
        switch (op) {
        case 0x20: opcode=Opcode::mips_lb;width=8;load=true;break; case 0x21: opcode=Opcode::mips_lh;width=16;load=true;break;
        case 0x23: opcode=Opcode::mips_lw;width=32;load=true;break; case 0x24: opcode=Opcode::mips_lbu;width=8;load=true;break;
        case 0x25: opcode=Opcode::mips_lhu;width=16;load=true;break; case 0x27: opcode=Opcode::mips64_lwu;width=32;load=true;break;
        case 0x28: opcode=Opcode::mips_sb;width=8;break; case 0x29: opcode=Opcode::mips_sh;width=16;break;
        case 0x2b: opcode=Opcode::mips_sw;width=32;break;
        case 0x22: opcode=Opcode::mips64_lwl;width=32;load=true;unaligned_merge=true;break;
        case 0x26: opcode=Opcode::mips64_lwr;width=32;load=true;unaligned_merge=true;break;
        case 0x2a: opcode=Opcode::mips64_swl;width=32;unaligned_merge=true;break;
        case 0x2e: opcode=Opcode::mips64_swr;width=32;unaligned_merge=true;break;
        case 0x1a: opcode=Opcode::mips64_ldl;width=64;load=true;unaligned_merge=true;break;
        case 0x1b: opcode=Opcode::mips64_ldr;width=64;load=true;unaligned_merge=true;break;
        case 0x2c: opcode=Opcode::mips64_sdl;width=64;unaligned_merge=true;break;
        case 0x2d: opcode=Opcode::mips64_sdr;width=64;unaligned_merge=true;break;
        case 0x30: opcode=Opcode::mips64_ll;width=32;load=true;break;
        case 0x38: opcode=Opcode::mips64_sc;width=32;break;
        case 0x34: opcode=Opcode::mips64_lld;width=64;load=true;break; case 0x37: opcode=Opcode::mips64_ld;width=64;load=true;break;
        case 0x3c: opcode=Opcode::mips64_scd;width=64;break;
        case 0x3f: opcode=Opcode::mips64_sd;width=64;break;
        default: return op >= 0x10 && op <= 0x13 ? DecodeResult{DecodeStatus::unsupported, {}, "MIPS64 coprocessor instruction is unsupported"}
                                                           : invalid("Reserved or unsupported MIPS64 opcode");
        }
        i.opcode = opcode;
        MemoryOperand memory{static_cast<std::uint16_t>(width), 64, {}, reg(rs), {}, 1, signed16(word), false, {}, EncodedField{0, 2}};
        i.operands = {reg(rt), memory};
        const bool conditional_store = opcode == Opcode::mips64_scd || opcode == Opcode::mips64_sc;
        i.access = {load ? (unaligned_merge ? OperandAccess::read_write : OperandAccess::write) :
                    (conditional_store ? OperandAccess::read_write : OperandAccess::read),
                    load ? OperandAccess::read : (unaligned_merge ? OperandAccess::read_write : OperandAccess::write)};
        i.memory_read = load || (unaligned_merge && !load); i.memory_write = !load;
        if (unaligned_merge && rs) i.register_reads.push_back(reg(rs));
        if (load) {
            if (unaligned_merge && rt) i.register_reads.push_back(reg(rt));
            if (rt) i.register_writes = {reg(rt)};
        }
        else {
            if (rt) i.register_reads = {reg(rt)};
            if (conditional_store && rt) i.register_writes = {reg(rt)};
        }
    }
    return {DecodeStatus::decoded, std::move(i), {}};
}
} // namespace hexlab
