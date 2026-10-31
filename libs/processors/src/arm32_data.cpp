#include "arm32_internal.hpp"
#include <algorithm>
#include <bit>
#include <limits>
namespace hexlab::arm32_detail {
namespace {
RegisterOperand gpr(unsigned n) { return {RegisterBank::arm32_gpr, static_cast<std::uint8_t>(n), 32, false}; }
constexpr RegisterOperand flags{RegisterBank::arm_flags, 0, 4, false};
void read(Instruction &i, RegisterOperand r) {
    if (std::find(i.register_reads.begin(), i.register_reads.end(), r) == i.register_reads.end())
        i.register_reads.push_back(r);
}
} // namespace
bool data(Instruction &i, std::uint32_t word) {
    // ARMv6 byte-reversal and bit-reversal operations. The fixed fields
    // distinguish all four encodings; PC operands are rejected as UNPREDICTABLE.
    const auto reverse_key = word & 0x0fff0ff0u;
    Opcode reverse_opcode{};
    bool reverse = true;
    switch (reverse_key) {
    case 0x06bf0f30u: reverse_opcode = Opcode::a32_rev; break;
    case 0x06bf0fb0u: reverse_opcode = Opcode::a32_rev16; break;
    case 0x06ff0fb0u: reverse_opcode = Opcode::a32_revsh; break;
    case 0x06ff0f30u: reverse_opcode = Opcode::a32_rbit; break;
    default: reverse = false; break;
    }
    if (reverse) {
        const auto rd = (word >> 12) & 15, rm = word & 15;
        if (rd == 15 || rm == 15)
            return false;
        const auto destination = gpr(rd), source = gpr(rm);
        i.opcode = reverse_opcode;
        i.operands = {destination, source};
        i.access = {OperandAccess::write, OperandAccess::read};
        read(i, source);
        i.register_writes.push_back(destination);
        return true;
    }
    // A32 multiply encodings occupy the otherwise-unallocated register-shift
    // space. Decode them before the ordinary data-processing class.
    const auto mul_rn = (word >> 16) & 15, mul_rd = (word >> 12) & 15;
    const auto mul_rs = (word >> 8) & 15, mul_rm = word & 15;
    // Saturating scalar add/subtract. Bits 22:21 select whether Rn is
    // doubled and whether that doubled value is added or subtracted.
    if ((word & 0x0f900ff0u) == 0x01000050u) {
        const auto rd = (word >> 12) & 15;
        const auto rn = (word >> 16) & 15;
        const auto rm = word & 15;
        if (rd == 15 || rn == 15 || rm == 15)
            return false;
        const auto operation = (word >> 21) & 3;
        static constexpr Opcode opcodes[]{Opcode::arm_qadd, Opcode::arm_qsub,
                                           Opcode::arm_qdadd, Opcode::arm_qdsub};
        const auto destination = gpr(rd), first = gpr(rm), second = gpr(rn);
        i.opcode = opcodes[operation];
        i.operands = {destination, first, second};
        i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
        read(i, first); read(i, second);
        i.register_writes.push_back(destination);
        i.arm->q_flag_may_set = true;
        return true;
    }
    const auto bitfield_key = word & 0x0fe00070u;
    const auto bitfield_rd = (word >> 12) & 15;
    const auto bitfield_rn = word & 15;
    const auto bitfield_lsb = (word >> 7) & 31;
    const auto bitfield_msb_or_width = (word >> 16) & 31;
    const auto append_field = [&](unsigned value) {
        i.operands.emplace_back(ImmediateOperand{value, 5, 32, false, {}});
        i.access.push_back(OperandAccess::read);
    };
    if (bitfield_key == 0x07c00010u) { // BFI/BFC: msb is encoded, not width-1.
        if (bitfield_rd == 15 || bitfield_msb_or_width < bitfield_lsb)
            return false;
        const auto width = bitfield_msb_or_width - bitfield_lsb + 1;
        const auto destination = gpr(bitfield_rd);
        if (bitfield_rn == 15) {
            i.opcode = Opcode::arm_bfc;
            i.operands = {destination};
            i.access = {OperandAccess::read_write};
            read(i, destination);
        } else {
            i.opcode = Opcode::arm_bfi;
            i.operands = {destination, gpr(bitfield_rn)};
            i.access = {OperandAccess::read_write, OperandAccess::read};
            read(i, destination);
            read(i, gpr(bitfield_rn));
        }
        append_field(bitfield_lsb);
        append_field(width);
        i.register_writes.push_back(destination);
        return true;
    }
    if (bitfield_key == 0x07a00050u || bitfield_key == 0x07e00050u) { // SBFX/UBFX
        const auto width = bitfield_msb_or_width + 1;
        if (bitfield_rd == 15 || bitfield_rn == 15 || bitfield_lsb + width > 32)
            return false;
        const bool signed_extract = bitfield_key == 0x07a00050u;
        const auto destination = gpr(bitfield_rd), source = gpr(bitfield_rn);
        i.opcode = signed_extract ? Opcode::arm_sbfx : Opcode::arm_ubfx;
        i.operands = {destination, source};
        i.access = {OperandAccess::write, OperandAccess::read};
        append_field(bitfield_lsb);
        append_field(width);
        read(i, source);
        i.register_writes.push_back(destination);
        return true;
    }
    if ((word & 0x0ff000f0) == 0x00600090) { // MLS Rd, Rm, Rs, Rn
        if (mul_rd == 15 || mul_rn == 15 || mul_rm == 15 || mul_rs == 15)
            return false;
        i.opcode = Opcode::a32_mls;
        i.operands = {gpr(mul_rd), gpr(mul_rm), gpr(mul_rs), gpr(mul_rn)};
        i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read, OperandAccess::read};
        read(i, gpr(mul_rm)); read(i, gpr(mul_rs)); read(i, gpr(mul_rn));
        i.register_writes.push_back(gpr(mul_rd));
        return true;
    }
    const bool long_mul = (word & 0x0f8000f0) == 0x00800090;
    const bool short_mul = (word & 0x0fc000f0) == 0x00000090;
    if (long_mul || short_mul) {
        if (long_mul) {
            const bool signed_mul = (word & 0x00400000) != 0;
            const bool accumulate = (word & 0x00200000) != 0;
            const auto lo = mul_rd, hi = mul_rn;
            if (lo == 15 || hi == 15 || lo == hi || mul_rm == 15 || mul_rs == 15)
                return false;
            i.opcode = signed_mul ? (accumulate ? Opcode::a32_smlal : Opcode::a32_smull)
                                  : (accumulate ? Opcode::a32_umlal : Opcode::a32_umull);
            i.operands = {gpr(lo), gpr(hi), gpr(mul_rm), gpr(mul_rs)};
            i.access = {accumulate ? OperandAccess::read_write : OperandAccess::write,
                        accumulate ? OperandAccess::read_write : OperandAccess::write,
                        OperandAccess::read, OperandAccess::read};
            read(i, gpr(mul_rm)); read(i, gpr(mul_rs));
            if (accumulate) { read(i, gpr(lo)); read(i, gpr(hi)); }
            i.register_writes = {gpr(lo), gpr(hi)};
            if (word & 0x00100000) {
                i.arm->flags_written = 12; // N and Z are defined; C and V are preserved.
                i.arm->flags_known = true;
                read(i, flags);
                i.register_writes.push_back(flags);
            }
            return true;
        }
        const bool accumulate = (word & 0x00200000) != 0;
        const bool setflags = (word & 0x00100000) != 0;
        const auto destination = mul_rd, accumulator = mul_rn;
        if (destination == 15 || mul_rm == 15 || mul_rs == 15 ||
            (accumulate ? accumulator == 15 : accumulator != 0))
            return false;
        i.opcode = accumulate ? Opcode::a32_mla : Opcode::a32_mul;
        i.operands = accumulate ? std::vector<Operand>{gpr(destination), gpr(mul_rm), gpr(mul_rs), gpr(accumulator)}
                                : std::vector<Operand>{gpr(destination), gpr(mul_rm), gpr(mul_rs)};
        i.access = accumulate ? std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read,
                     OperandAccess::read, OperandAccess::read} : std::vector<OperandAccess>{OperandAccess::write,
                     OperandAccess::read, OperandAccess::read};
        read(i, gpr(mul_rm)); read(i, gpr(mul_rs));
        if (accumulate) read(i, gpr(accumulator));
        i.register_writes.push_back(gpr(destination));
        if (setflags) {
            i.arm->flags_written = 12; i.arm->flags_known = true;
            read(i, flags); i.register_writes.push_back(flags);
        }
        return true;
    }
    // ARMv6 signed/unsigned byte and halfword extend operations. Rn=pc
    // selects the non-accumulating form; all other Rn values are the base
    // operand of the extend-add form. Rotate is restricted to multiples of 8.
    const auto extend_encoding = word & 0x0ff003f0;
    const bool sxtb16 = extend_encoding == 0x06800070;
    const bool uxtb16 = extend_encoding == 0x06c00070;
    if (sxtb16 || uxtb16) {
        const auto rn = (word >> 16) & 15;
        const auto rd = (word >> 12) & 15;
        const auto rm = word & 15;
        if (rd == 15 || rm == 15)
            return false;
        const bool add = rn != 15;
        i.opcode = sxtb16 ? (add ? Opcode::a32_sxtab16 : Opcode::a32_sxtb16)
                          : (add ? Opcode::a32_uxtab16 : Opcode::a32_uxtb16);
        const auto rotated = ArmShiftedRegisterOperand{
            gpr(rm), ArmShift::ror, static_cast<std::uint8_t>(((word >> 10) & 3) * 8), std::nullopt};
        if (add) {
            i.operands = {gpr(rd), gpr(rn), rotated};
            i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
            read(i, gpr(rn));
        } else {
            i.operands = {gpr(rd), rotated};
            i.access = {OperandAccess::write, OperandAccess::read};
        }
        read(i, gpr(rm));
        i.register_writes.push_back(gpr(rd));
        return true;
    }
    const bool sxtb = extend_encoding == 0x06a00070;
    const bool sxth = extend_encoding == 0x06b00070;
    const bool uxtb = extend_encoding == 0x06e00070;
    const bool uxth = extend_encoding == 0x06f00070;
    if (sxtb || sxth || uxtb || uxth) {
        const auto rn = (word >> 16) & 15;
        const auto rd = (word >> 12) & 15;
        const auto rm = word & 15;
        if (rd == 15 || rm == 15)
            return false;
        const bool add = rn != 15;
        i.opcode = sxtb ? (add ? Opcode::a32_sxtab : Opcode::a32_sxtb) :
                   sxth ? (add ? Opcode::a32_sxtah : Opcode::a32_sxth) :
                   uxtb ? (add ? Opcode::a32_uxtab : Opcode::a32_uxtb) :
                          (add ? Opcode::a32_uxtah : Opcode::a32_uxth);
        if (add) {
            i.operands = {gpr(rd), gpr(rn), ArmShiftedRegisterOperand{
                gpr(rm), ArmShift::ror, static_cast<std::uint8_t>(((word >> 10) & 3) * 8), std::nullopt}};
            i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
            read(i, gpr(rn));
        } else {
            i.operands = {gpr(rd), ArmShiftedRegisterOperand{
                gpr(rm), ArmShift::ror, static_cast<std::uint8_t>(((word >> 10) & 3) * 8), std::nullopt}};
            i.access = {OperandAccess::write, OperandAccess::read};
        }
        read(i, gpr(rm));
        i.register_writes.push_back(gpr(rd));
        return true;
    }
    if ((word & 0x0c000000) != 0)
        return false;
    const auto op = (word >> 21) & 15;
    const bool s = (word & 0x100000) != 0, immediate = (word & 0x2000000) != 0;
    const auto rn = (word >> 16) & 15, rd = (word >> 12) & 15;
    const bool compare = op >= 8 && op <= 11, unary = op == 13 || op == 15;
    if ((compare && (!s || rd)) || (unary && rn) || (rd == 15 && s))
        return false; // Status-register/movwide/exception-return encoding spaces.
    const bool register_shift = !immediate && (word & 0x10);
    const auto rm = word & 15, rs = (word >> 8) & 15;
    if (register_shift && ((word & 0x80) || rm == 15 || rs == 15 || rd == 15 || (!unary && rn == 15)))
        return false; // Multiply/extra-load-store encodings and forbidden PC forms.
    i.opcode = static_cast<Opcode>(static_cast<unsigned>(Opcode::a32_and) + op);
    if (!compare) {
        i.operands.emplace_back(gpr(rd));
        i.access.push_back(OperandAccess::write);
        i.register_writes.push_back(gpr(rd));
    }
    if (!unary) {
        i.operands.emplace_back(gpr(rn));
        i.access.push_back(OperandAccess::read);
        read(i, gpr(rn));
    }
    bool carry_written = false, carry_unknown = false;
    if (immediate) {
        const auto rotation = ((word >> 8) & 15) * 2;
        const auto value = std::rotr(static_cast<std::uint32_t>(word & 255), static_cast<int>(rotation));
        i.operands.emplace_back(ImmediateOperand{value, 12, 32, false, {}});
        carry_written = rotation != 0;
    } else {
        auto shift = static_cast<ArmShift>((word >> 5) & 3);
        auto amount = static_cast<std::uint8_t>((word >> 7) & 31);
        if (!register_shift && !amount) {
            if (shift == ArmShift::lsr || shift == ArmShift::asr)
                amount = 32;
            else if (shift == ArmShift::ror) {
                shift = ArmShift::rrx;
                amount = 1;
            }
        }
        i.operands.emplace_back(ArmShiftedRegisterOperand{gpr(rm), shift,
                                                          static_cast<std::uint8_t>(register_shift ? 0 : amount),
                                                          register_shift ? std::optional{gpr(rs)} : std::nullopt});
        read(i, gpr(rm));
        if (register_shift)
            read(i, gpr(rs));
        if (shift == ArmShift::rrx)
            read(i, flags);
        carry_written = !register_shift && amount != 0;
        carry_unknown = register_shift;
    }
    i.access.push_back(OperandAccess::read);
    const bool arithmetic = (op >= 2 && op <= 7) || op == 10 || op == 11;
    if (op >= 5 && op <= 7)
        read(i, flags);
    if (s) {
        i.arm->flags_written = static_cast<std::uint8_t>(arithmetic ? 15 : carry_written ? 14 : 12);
        i.arm->flags_known = arithmetic || !carry_unknown;
        if (i.arm->flags_written != 15)
            read(i, flags); // Partial APSR updates retain the flag bits outside the write mask.
        i.register_writes.push_back(flags);
    }
    if (!compare && rd == 15) {
        i.arm->writes_pc = true;
        i.arm->exchange = ArmExchange::address_bit0; // Armv7 A32 ALUWritePC.
        i.flow = unary && op == 13 && !immediate && !register_shift && rm == 14 && (word & 0xff0) == 0 ? FlowKind::ret
                                                                                                       : FlowKind::jump;
        // Resolve only writes whose complete value is encoded in this instruction.
        // Register-derived values stay indirect; no register propagation is implied.
        if (immediate) {
            const auto operand2 = std::get<ImmediateOperand>(i.operands.back()).value;
            const auto pc = static_cast<std::uint64_t>(i.address.offset) + 8;
            std::optional<std::uint64_t> value;
            if (unary && op == 13) // MOV pc, #imm
                value = operand2;
            else if (unary && op == 15) // MVN pc, #imm
                value = static_cast<std::uint32_t>(~operand2);
            else if (!unary && rn == 15 && i.address.offset <= UINT32_MAX - 8) {
                if (op == 2 && pc >= operand2) // SUB pc, pc, #imm
                    value = pc - operand2;
                else if (op == 3 && operand2 >= pc) // RSB pc, pc, #imm
                    value = operand2 - pc;
                else if (op == 4 && pc <= UINT32_MAX - operand2) // ADD pc, pc, #imm
                    value = pc + operand2;
            }
            if (value && *value <= UINT32_MAX) {
                const bool thumb = (*value & 1) != 0;
                const auto physical = thumb ? (*value & ~UINT64_C(1)) : (*value & ~UINT64_C(3));
                i.direct_target = Address{i.address.space, physical};
                i.arm->target_mode = thumb ? ExecutionMode::thumb : ExecutionMode::a32;
            }
        }
    }
    return true;
}
} // namespace hexlab::arm32_detail
