#include "thumb_internal.hpp"
#include <bit>
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
namespace {
std::optional<std::uint32_t> expand_modified_immediate(std::uint16_t first, std::uint16_t second) {
    const auto imm12 = static_cast<std::uint16_t>(((first >> 10) & 1) << 11 |
                                                  ((second >> 12) & 7) << 8 |
                                                  (second & 0xff));
    if ((imm12 >> 10) == 0) {
        const auto pattern = (imm12 >> 8) & 3;
        const auto byte = static_cast<std::uint32_t>(imm12 & 0xff);
        if (pattern == 0) return byte;
        if (byte == 0) return {};
        switch (pattern) {
        case 1: return (byte << 16) | byte;
        case 2: return (byte << 24) | (byte << 8);
        case 3: return (byte << 24) | (byte << 16) | (byte << 8) | byte;
        }
    }
    const auto unrotated = UINT32_C(0x80) | (imm12 & 0x7f);
    return std::rotr(unrotated, static_cast<int>((imm12 >> 7) & 31));
}
} // namespace
bool data_wide(Instruction &i, std::uint16_t first, std::uint16_t second) {
    // Thumb-2 long multiply family, T1. Its fields match the A32 long
    // multiply operands but have a different register-pair ordering. In the
    // second halfword bit 15 is fixed zero and RdLo occupies bits 14:12;
    // bits 7:4 are also fixed zero. Adapt only validated forms to the shared
    // A32 decoder so both encodings retain identical effects.
    if ((first & 0xff80u) == 0xfb80u && (second & 0x80f0u) == 0) {
        const auto operation = (first >> 4) & 7u;
        if (operation == 0 || operation == 2 || operation == 4 || operation == 6) {
            const auto rn = first & 15u;
            const auto rd_lo = (second >> 12) & 15u;
            const auto rd_hi = (second >> 8) & 15u;
            const auto rm = second & 15u;
            if (rn != 15 && rm != 15 && rd_lo != 15 && rd_hi != 15 && rd_lo != rd_hi) {
                const bool signed_multiply = (operation & 2u) == 0;
                const bool accumulate = (operation & 4u) != 0;
                const auto normalized = UINT32_C(0xe0800090) |
                    (signed_multiply ? UINT32_C(0x00400000) : 0) |
                    (accumulate ? UINT32_C(0x00200000) : 0) |
                    (rd_hi << 16) | (rd_lo << 12) | (rn << 8) | rm;
                // A32 uses RdLo in bits 15:12, RdHi in 19:16, Rm in 3:0,
                // and Rs in 11:8. Preserve the Thumb IT predicate already
                // attached to the instruction; the synthetic condition is AL.
                return arm32_detail::data(i, normalized);
            }
        }
        return false;
    }
    if ((first & 0xfff0u) == 0xfa80u && (second & 0xf0f0u) == 0xf080u) {
        const auto rn = first & 15u;
        const auto rd = (second >> 8) & 15u;
        const auto rm = second & 15u;
        if (rd >= 13 || rn >= 13 || rm >= 13)
            return false;
        const auto operation = (second >> 4) & 3u;
        static constexpr Opcode opcodes[]{Opcode::arm_qadd, Opcode::arm_qdadd,
                                           Opcode::arm_qsub, Opcode::arm_qdsub};
        const auto destination = reg(rd), first_source = reg(rm), second_source = reg(rn);
        i.opcode = opcodes[operation];
        i.operands = {destination, first_source, second_source};
        i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
        read(i, first_source); read(i, second_source);
        i.register_writes.push_back(destination);
        i.arm->q_flag_may_set = true;
        return true;
    }
    const auto bitfield_key = first & 0xfff0u;
    const bool signed_extract = bitfield_key == 0xf340u;
    const bool unsigned_extract = bitfield_key == 0xf3c0u;
    const bool insert_or_clear = bitfield_key == 0xf360u;
    if ((signed_extract || unsigned_extract || insert_or_clear) && !(second & 0x20u)) {
        const auto rn = first & 15u;
        const auto rd = (second >> 8) & 15u;
        const auto lsb = (((second >> 12) & 7u) << 2) | ((second >> 6) & 3u);
        const auto encoded_width = second & 31u;
        const auto destination = reg(rd);
        const auto append_field = [&](unsigned value) {
            i.operands.emplace_back(ImmediateOperand{value, 5, 32, false, {}});
            i.access.push_back(OperandAccess::read);
        };
        if (rd >= 13 || lsb > 31)
            return false;
        if (insert_or_clear) {
            const auto msb = encoded_width;
            if (msb < lsb)
                return false;
            const auto width = msb - lsb + 1;
            if (rn == 15) {
                i.opcode = Opcode::arm_bfc;
                i.operands = {destination};
                i.access = {OperandAccess::read_write};
                read(i, destination);
            } else {
                if (rn >= 13)
                    return false;
                i.opcode = Opcode::arm_bfi;
                i.operands = {destination, reg(rn)};
                i.access = {OperandAccess::read_write, OperandAccess::read};
                read(i, destination);
                read(i, reg(rn));
            }
            append_field(lsb);
            append_field(width);
        } else {
            const auto width = encoded_width + 1;
            if (rn >= 13 || lsb + width > 32)
                return false;
            const auto source = reg(rn);
            i.opcode = signed_extract ? Opcode::arm_sbfx : Opcode::arm_ubfx;
            i.operands = {destination, source};
            i.access = {OperandAccess::write, OperandAccess::read};
            append_field(lsb);
            append_field(width);
            read(i, source);
        }
        i.register_writes.push_back(destination);
        return true;
    }
    // Thumb-2 ROR (register), T2. Reuse the established scalar MOV-with-
    // register-controlled-shift representation so its operand formatter,
    // register effects, and lifting remain consistent with A32.
    if ((first & 0xffe0) == 0xfa60 && (second & 0xf0f0) == 0xf000) {
        const auto rn = first & 15;
        const auto setflags = (first & 0x10) != 0;
        const auto rd = (second >> 8) & 15;
        const auto rm = second & 15;
        if (rn == 13 || rn == 15 || rd == 13 || rd == 15 || rm == 13 || rm == 15)
            return false;
        const auto a32_encoding = UINT32_C(0xe0000000) | (13u << 21) |
            (setflags ? UINT32_C(0x00100000) : 0) | (rd << 12) | (rm << 8) |
            (3u << 5) | 0x10u | rn;
        if (!arm32_detail::data(i, a32_encoding))
            return false;
        if (setflags) {
            // A variable rotate can replace C for a nonzero low-byte amount;
            // the A32 generic shift path conservatively marks only N/Z.
            i.arm->flags_written = 14;
            i.arm->flags_known = false;
        }
        return true;
    }
    // Thumb-2 MOVW/MOVT (T3): split imm16 across both halfwords. MOVT
    // preserves the low half of Rd, so its old value is an explicit input.
    const auto move_key = first & 0xfbf0;
    const bool movw = move_key == 0xf240;
    const bool movt = move_key == 0xf2c0;
    if ((movw || movt) && !(second & 0x8000)) {
        const auto rd = (second >> 8) & 15;
        if (rd == 13 || rd == 15)
            return false;
        const auto immediate = static_cast<std::uint32_t>(((first & 15) << 12) |
            (((first >> 10) & 1) << 11) | (((second >> 12) & 7) << 8) | (second & 0xff));
        const auto destination = reg(rd);
        i.opcode = movw ? Opcode::t32_movw : Opcode::t32_movt;
        i.operands = {destination, ImmediateOperand{immediate, 16, 32, false, {}}};
        i.access = {movt ? OperandAccess::read_write : OperandAccess::write, OperandAccess::read};
        if (movt)
            read(i, destination);
        i.register_writes.push_back(destination);
        return true;
    }
    // Thumb-2 modified-immediate ADD/SUB (T3) and unflagged ADDW/SUBW (T4).
    // Keep Rn/Rd in r0-r12 so PC aliases and architecture-profile SP rules
    // cannot be mistaken for plain arithmetic in this profile-free decoder.
    const auto arithmetic_key = first & 0xfbe0;
    const bool add_modified = arithmetic_key == 0xf100;
    const bool adc_modified = arithmetic_key == 0xf140;
    const bool sbc_modified = arithmetic_key == 0xf160;
    const bool sub_modified = arithmetic_key == 0xf1a0;
    const bool rsb_modified = arithmetic_key == 0xf1c0;
    const bool add_wide = arithmetic_key == 0xf200;
    const bool sub_wide = arithmetic_key == 0xf2a0;
    if ((add_wide || sub_wide) && (first & 0x10))
        return false; // ADDW/SUBW reserve the S bit as zero.
    if ((add_modified || adc_modified || sbc_modified || sub_modified || rsb_modified || add_wide || sub_wide) &&
        !(second & 0x8000)) {
        const auto rn = first & 15;
        const auto rd = (second >> 8) & 15;
        const bool modified = add_modified || adc_modified || sbc_modified || sub_modified || rsb_modified;
        const bool setflags = modified && (first & 0x10);
        if (rn == 13 || rn == 15 || rd == 13 || rd == 15)
            return false;
        const auto immediate = modified ? expand_modified_immediate(first, second)
            : std::optional<std::uint32_t>{static_cast<std::uint32_t>(((first >> 10) & 1) << 11 |
                ((second >> 12) & 7) << 8 | (second & 0xff))};
        if (!immediate) return false;
        const bool subtract = sub_modified || sub_wide;
        if (modified && (adc_modified || sbc_modified || rsb_modified)) {
            const unsigned operation = adc_modified ? 5u : sbc_modified ? 6u : 3u;
            const auto normalized = UINT32_C(0xe0000000) | (operation << 21) |
                ((first & 0x10) ? UINT32_C(0x00100000) : 0) | UINT32_C(0x02000000) |
                (rn << 16) | (rd << 12);
            if (!arm32_detail::data(i, normalized))
                return false;
            // Reuse A32's complete arithmetic/read/write and carry-input
            // effects, but retain the ThumbExpandImm value decoded above.
            auto *decoded_immediate = i.operands.empty() ? nullptr :
                std::get_if<ImmediateOperand>(&i.operands.back());
            if (!decoded_immediate)
                return false;
            decoded_immediate->value = *immediate;
            decoded_immediate->encoded_width = 12;
            return true;
        }
        i.opcode = !modified ? (subtract ? Opcode::t32_subw : Opcode::t32_addw)
                             : (subtract ? Opcode::a32_sub : Opcode::a32_add);
        const auto destination = reg(rd), source = reg(rn);
        i.operands = {destination, source, ImmediateOperand{*immediate, 12, 32, false, {}}};
        i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
        read(i, source);
        i.register_writes.push_back(destination);
        if (setflags) {
            i.arm->flags_written = 15;
            i.arm->flags_known = true;
            i.register_writes.push_back(flags);
        }
        return true;
    }
    // Thumb-2 scalar extend/extend-add: FA0n/FA1n/FA4n/FA5n Fd8m,
    // with rotate in second-halfword bits 5:4. Rn=15 selects the unary alias.
    // Keep packed-byte DSP operations and other FAxx classes outside this slice.
    if ((second & 0xf0c0) != 0xf080)
        return false;
    // Packed-byte extension family. FA2x/FA3x are unary SXTB16/UXTB16;
    // FA6x/FA7x add the rotated byte lanes to Rn. Rotation is ROR #0/#8/#16/#24.
    const auto rn = first & 15, rd = (second >> 8) & 15, rm = second & 15;
    std::optional<Opcode> packed;
    switch (first & 0xfff0) {
    case 0xfa20: packed = rn == 15 ? Opcode::t32_sxtb16 : Opcode::t32_sxtab16; break;
    case 0xfa30: packed = rn == 15 ? Opcode::t32_uxtb16 : Opcode::t32_uxtab16; break;
    default: break;
    }
    if (packed) {
        if (rd == 13 || rd == 15 || rm == 13 || rm == 15 || (*packed == Opcode::t32_sxtab16 && rn == 13) ||
            (*packed == Opcode::t32_uxtab16 && rn == 13))
            return false;
        i.opcode = *packed;
        const auto rotated = ArmShiftedRegisterOperand{reg(rm), ArmShift::ror,
            static_cast<std::uint8_t>(((second >> 4) & 3) * 8), std::nullopt};
        const bool add = *packed == Opcode::t32_sxtab16 || *packed == Opcode::t32_uxtab16;
        i.operands = add ? std::vector<Operand>{reg(rd), reg(rn), rotated}
                         : std::vector<Operand>{reg(rd), rotated};
        i.access = add ? std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read, OperandAccess::read}
                       : std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read};
        if (add) read(i, reg(rn));
        read(i, reg(rm));
        i.register_writes.push_back(reg(rd));
        return true;
    }
    std::uint32_t a32_encoding = 0;
    switch (first & 0xfff0) {
    case 0xfa00: a32_encoding = 0x06b00070; break; // SXTAH / SXTH
    case 0xfa10: a32_encoding = 0x06f00070; break; // UXTAH / UXTH
    case 0xfa40: a32_encoding = 0x06a00070; break; // SXTAB / SXTB
    case 0xfa50: a32_encoding = 0x06e00070; break; // UXTAB / UXTB
    default: return false;
    }
    // Use the ARMv7 Thumb restrictions; ARMv8 SP relaxations require a profile.
    if (rd == 13 || rd == 15 || rm == 13 || rm == 15 || rn == 13)
        return false;
    // Reuse the established A32 shape and data effects. The Thumb instruction's
    // bytes, length, condition and incoming/outgoing IT state stay authoritative.
    const auto rotation = ((second >> 4) & 3) << 10;
    return arm32_detail::data(i, 0xe0000000u | a32_encoding | (rn << 16) |
                                (rd << 12) | rotation | rm);
}

bool data(Instruction &i, std::uint16_t h) {
    const auto rd = h & 7, rm = (h >> 3) & 7;
    // Thumb-1 extend-register family (SXTH/SXTB/UXTH/UXTB).
    // These are pure 32-bit register transforms and do not update APSR.
    if ((h & 0xff00) == 0xb200) {
        static constexpr Opcode extend_opcodes[]{Opcode::a32_sxth, Opcode::a32_sxtb,
                                                  Opcode::a32_uxth, Opcode::a32_uxtb};
        i.opcode = extend_opcodes[(h >> 6) & 3];
        i.operands = {reg(rd), reg(rm)};
        i.access = {OperandAccess::write, OperandAccess::read};
        read(i, reg(rm));
        i.register_writes.push_back(reg(rd));
        return true;
    }
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
