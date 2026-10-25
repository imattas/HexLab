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
    // A32 multiply encodings occupy the otherwise-unallocated register-shift
    // space. Decode them before the ordinary data-processing class.
    const auto mul_rn = (word >> 16) & 15, mul_rd = (word >> 12) & 15;
    const auto mul_rs = (word >> 8) & 15, mul_rm = word & 15;
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
