#include "hexlab/processors/decoder.hpp"
#include <algorithm>
#include <bit>
#include <cstdint>

namespace hexlab {
namespace {
using R = RegisterOperand;
constexpr RegisterBank gpr_bank = RegisterBank::ppc_gpr;
R gpr(unsigned index, unsigned width) { return {gpr_bank, static_cast<std::uint8_t>(index), static_cast<std::uint16_t>(width), false}; }
R cr(unsigned field) { return {RegisterBank::ppc_cr, static_cast<std::uint8_t>(field), 4, false}; }
R lr(unsigned width) { return {RegisterBank::ppc_lr, 0, static_cast<std::uint16_t>(width), false}; }
R ctr(unsigned width) { return {RegisterBank::ppc_ctr, 0, static_cast<std::uint16_t>(width), false}; }
R xer() { return {RegisterBank::ppc_xer, 0, 32, false}; }
R fpr(unsigned index, unsigned bits) { return {RegisterBank::ppc_fpr, static_cast<std::uint8_t>(index), static_cast<std::uint16_t>(bits), false}; }
R fpscr() { return {RegisterBank::ppc_fpscr, 0, 32, false}; }
R cr1() { return {RegisterBank::ppc_cr, 1, 4, false}; }
R vr(unsigned index) { return {RegisterBank::ppc_vr, static_cast<std::uint8_t>(index), 128, false}; }
DecodeResult fail(DecodeStatus status, const char *why) { return {status, {}, why}; }
std::uint32_t word(std::span<const std::byte> bytes, ByteOrder order) {
    std::uint32_t result = 0;
    if (order == ByteOrder::big) {
        for (auto byte : bytes.first(4))
            result = (result << 8) | std::to_integer<std::uint32_t>(byte);
    } else {
        for (unsigned n = 0; n < 4; ++n)
            result |= std::to_integer<std::uint32_t>(bytes[n]) << (n * 8);
    }
    return result;
}
std::int64_t sext(std::uint32_t value, unsigned width) {
    const auto sign = std::uint32_t{1} << (width - 1);
    return (value & sign) ? static_cast<std::int64_t>(value) - (std::int64_t{1} << width)
                          : static_cast<std::int64_t>(value);
}
void set_target(Instruction &i, std::int64_t displacement, bool absolute, unsigned encoded_width) {
    std::uint64_t target = absolute ? static_cast<std::uint64_t>(displacement)
                                    : i.address.offset + static_cast<std::uint64_t>(displacement);
    if (i.context.mode == ExecutionMode::ppc32)
        target &= UINT32_MAX;
    i.direct_target = Address{i.address.space, target};
    i.operands.push_back(RelativeOperand{displacement, static_cast<std::uint16_t>(encoded_width),
                                         static_cast<std::uint16_t>(i.context.mode == ExecutionMode::ppc32 ? 32 : 64),
                                         EncodedField{0, 4}});
    i.access.push_back(OperandAccess::address);
}
void mark_destination(Instruction &i, R destination) {
    i.operands.emplace_back(destination);
    i.access.push_back(OperandAccess::write);
    i.register_writes.push_back(destination);
}
void branch_link(Instruction &i, bool link) {
    if (link) {
        i.register_writes.push_back(lr(i.context.mode == ExecutionMode::ppc32 ? 32 : 64));
        i.access.push_back(OperandAccess::write);
    }
}
} // namespace

DecodeResult decode_powerpc(DecodeContext context, std::span<const std::byte> bytes, Address at) {
    const bool ppc32 = context.architecture == Architecture::powerpc && context.mode == ExecutionMode::ppc32;
    const bool ppc64 = context.architecture == Architecture::powerpc && context.mode == ExecutionMode::ppc64;
    if (!ppc32 && !ppc64)
        return fail(DecodeStatus::unsupported, "PowerPC architecture and mode do not match");
    if (context.segmented_memory || context.stack_address_width)
        return fail(DecodeStatus::unsupported, "PowerPC has no x86 segmented or stack-address override mode");
    if (bytes.size() < 4)
        return fail(DecodeStatus::truncated, "PowerPC instruction requires four bytes");
    if (at.offset & 3)
        return fail(DecodeStatus::invalid, "PowerPC instruction address is not four-byte aligned");
    if (ppc32 && at.offset > UINT32_MAX)
        return fail(DecodeStatus::invalid, "PPC32 instruction address exceeds its 32-bit domain");
    const unsigned width = ppc32 ? 32u : 64u;
    const auto w = word(bytes, context.order);
    const unsigned op = w >> 26;
    const unsigned rt = (w >> 21) & 31, ra = (w >> 16) & 31, rb = (w >> 11) & 31;
    const unsigned rc = w & 1;
    Instruction i;
    i.context = context;
    i.address = at;
    std::copy_n(bytes.begin(), 4, i.bytes.begin());
    i.length = 4;
    const auto add_imm = [&](Opcode opcode, bool shifted) {
        const auto value = sext(w & 0xffff, 16) * (shifted ? 65536 : 1);
        i.opcode = opcode;
        mark_destination(i, gpr(rt, width));
        if (ra) { i.operands.emplace_back(gpr(ra, width)); i.access.push_back(OperandAccess::read); i.register_reads.push_back(gpr(ra, width)); }
        else { i.operands.emplace_back(ImmediateOperand{0, 0, static_cast<std::uint16_t>(width), true, {}}); i.access.push_back(OperandAccess::read); }
        i.operands.emplace_back(ImmediateOperand{static_cast<std::uint64_t>(value), 16, static_cast<std::uint16_t>(width), true, EncodedField{2, 2}});
        i.access.push_back(OperandAccess::read);
    };
    const auto logical_imm = [&](Opcode opcode, bool shifted, bool record) {
        i.opcode = opcode;
        mark_destination(i, gpr(ra, width));
        i.operands.emplace_back(gpr(rt, width));
        i.access.push_back(OperandAccess::read);
        i.register_reads.push_back(gpr(rt, width));
        const auto immediate = (w & 0xffff) << (shifted ? 16 : 0);
        i.operands.emplace_back(ImmediateOperand{immediate, 16, static_cast<std::uint16_t>(width), false, EncodedField{2, 2}});
        i.access.push_back(OperandAccess::read);
        if (record) i.register_writes.push_back(cr(0));
    };
    const auto load_store = [&](Opcode opcode, unsigned data_width, bool load, bool update, bool sign_extend) {
        if (update && (ra == 0 || (load && ra == rt)))
            return false;
        i.opcode = opcode;
        const auto data = gpr(rt, width);
        i.operands.emplace_back(data);
        i.access.push_back(load ? OperandAccess::write : OperandAccess::read);
        if (load) i.register_writes.push_back(data);
        else i.register_reads.push_back(data);
        const auto displacement = sext(w & 0xffff, 16);
        MemoryOperand memory{static_cast<std::uint16_t>(data_width), static_cast<std::uint16_t>(width), {},
                            ra ? std::optional<R>(gpr(ra, width)) : std::nullopt, {}, 1, displacement, false, {}, EncodedField{2, 2}};
        i.operands.emplace_back(memory);
        i.access.push_back(OperandAccess::address);
        if (ra) i.register_reads.push_back(gpr(ra, width));
        if (update) i.register_writes.push_back(gpr(ra, width));
        i.memory_read = load;
        i.memory_write = !load;
        (void)sign_extend;
        return true;
    };
    const auto indexed_load_store = [&](Opcode opcode, unsigned data_width, bool load, bool update) {
        if (update && (ra == 0 || (load && ra == rt))) return false;
        i.opcode = opcode;
        const auto data = gpr(rt, width);
        i.operands.emplace_back(data);
        i.access.push_back(load ? OperandAccess::write : OperandAccess::read);
        if (load) i.register_writes.push_back(data); else i.register_reads.push_back(data);
        const std::optional<R> base = ra ? std::optional<R>{gpr(ra, width)} : std::nullopt;
        MemoryOperand memory{static_cast<std::uint16_t>(data_width), static_cast<std::uint16_t>(width), {},
                             base, gpr(rb, width), 1, 0, false, {}, {}};
        i.operands.emplace_back(memory);
        i.access.push_back(OperandAccess::address);
        if (ra) i.register_reads.push_back(gpr(ra, width));
        i.register_reads.push_back(gpr(rb, width));
        if (update) i.register_writes.push_back(gpr(ra, width));
        i.memory_read = load;
        i.memory_write = !load;
        return true;
    };
    if (op == 12 || op == 13) {
        i.opcode = op == 12 ? Opcode::ppc_addic : Opcode::ppc_addic_dot;
        mark_destination(i, gpr(rt, width));
        i.operands.emplace_back(gpr(ra, width));
        i.access.push_back(OperandAccess::read);
        i.register_reads.push_back(gpr(ra, width));
        i.operands.emplace_back(ImmediateOperand{static_cast<std::uint64_t>(sext(w & 0xffff, 16)), 16,
                                                  static_cast<std::uint16_t>(width), true, EncodedField{2, 2}});
        i.access.push_back(OperandAccess::read);
        // XER.CA is an architectural side effect even when the carry value is
        // not statically known. The dot form additionally writes CR0.
        i.register_writes.push_back(xer());
        if (op == 13) i.register_writes.push_back(cr(0));
    } else if (op == 7 || op == 8) {
        const auto immediate = sext(w & 0xffff, 16);
        i.opcode = op == 7 ? Opcode::ppc_mulli : Opcode::ppc_subfic;
        mark_destination(i, gpr(rt, width));
        i.operands.emplace_back(gpr(ra, width));
        i.access.push_back(OperandAccess::read);
        i.register_reads.push_back(gpr(ra, width));
        i.operands.emplace_back(ImmediateOperand{static_cast<std::uint64_t>(immediate), 16,
                                                  static_cast<std::uint16_t>(width), true, EncodedField{2, 2}});
        i.access.push_back(OperandAccess::read);
        if (op == 8) i.register_writes.push_back(xer());
    } else if (op == 10 || op == 11) {
        const bool wide = (w & (1u << 21)) != 0;
        const unsigned bf = (w >> 23) & 7;
        if ((w & (1u << 22)) || (ppc32 && wide))
            return fail(DecodeStatus::invalid, "PowerPC immediate compare has a reserved field or width");
        const auto compare_width = ppc64 && wide ? 64u : 32u;
        const auto immediate = op == 11 ? sext(w & 0xffff, 16) : static_cast<std::int64_t>(w & 0xffff);
        i.opcode = op == 11 ? Opcode::ppc_cmpi : Opcode::ppc_cmpli;
        i.operands.emplace_back(cr(bf));
        i.operands.emplace_back(gpr(ra, compare_width));
        i.operands.emplace_back(ImmediateOperand{static_cast<std::uint64_t>(immediate), 16,
                                                  static_cast<std::uint16_t>(compare_width), op == 11,
                                                  EncodedField{2, 2}});
        i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
        i.register_reads.push_back(gpr(ra, compare_width));
        i.register_writes.push_back(cr(bf));
    } else if (op == 20 || op == 21 || op == 23) {
        const bool insert = op == 20, variable = op == 23, record = rc != 0;
        const unsigned shift = variable ? rb : ((w >> 11) & 31);
        const unsigned mb = (w >> 6) & 31, me = (w >> 1) & 31;
        i.opcode = op == 20 ? (record ? Opcode::ppc_rlwimi_dot : Opcode::ppc_rlwimi) :
                   op == 21 ? (record ? Opcode::ppc_rlwinm_dot : Opcode::ppc_rlwinm) :
                              (record ? Opcode::ppc_rlwnm_dot : Opcode::ppc_rlwnm);
        mark_destination(i, gpr(ra, width));
        i.operands.emplace_back(gpr(rt, width));
        i.access.push_back(OperandAccess::read);
        i.register_reads.push_back(gpr(rt, width));
        if (insert) {
            i.access.front() = OperandAccess::read_write;
            i.register_reads.push_back(gpr(ra, width));
        }
        if (variable) {
            i.operands.emplace_back(gpr(rb, width));
            i.access.push_back(OperandAccess::read);
            i.register_reads.push_back(gpr(rb, width));
        } else {
            i.operands.emplace_back(ImmediateOperand{shift, 5, 5, false, EncodedField{1, 1}});
            i.access.push_back(OperandAccess::read);
        }
        i.operands.emplace_back(ImmediateOperand{mb, 5, 5, false, EncodedField{2, 1}});
        i.operands.emplace_back(ImmediateOperand{me, 5, 5, false, EncodedField{2, 1}});
        i.access.insert(i.access.end(), {OperandAccess::read, OperandAccess::read});
        if (record) i.register_writes.push_back(cr(0));
    } else if (op == 14 || op == 15) {
        add_imm(op == 14 ? Opcode::ppc_addi : Opcode::ppc_addis, op == 15);
    } else if (op >= 24 && op <= 29) {
        const bool shifted = op == 25 || op == 27 || op == 29;
        const bool record = op == 28 || op == 29;
        const Opcode opcode = op == 24 ? Opcode::ppc_ori : op == 25 ? Opcode::ppc_oris :
                              op == 26 ? Opcode::ppc_xori : op == 27 ? Opcode::ppc_xoris :
                              op == 28 ? Opcode::ppc_andi_dot : Opcode::ppc_andis_dot;
        logical_imm(opcode, shifted, record);
        if (op == 24 && rt == 0 && ra == 0 && (w & 0xffff) == 0) {
            i.opcode = Opcode::ppc_nop;
            i.operands.clear(); i.access.clear(); i.register_reads.clear(); i.register_writes.clear();
        }
    } else if (op == 48 || op == 50 || op == 52 || op == 54) {
        const bool load = op == 48 || op == 50;
        const unsigned bits = op == 48 || op == 52 ? 32u : 64u;
        const auto data = fpr(rt, bits);
        MemoryOperand memory{static_cast<std::uint16_t>(bits), static_cast<std::uint16_t>(width), {},
            ra ? std::optional<R>(gpr(ra, width)) : std::nullopt, {}, 1, sext(w & 0xffff, 16), false, {}, EncodedField{2, 2}};
        i.opcode = op == 48 ? Opcode::ppc_lfs : op == 50 ? Opcode::ppc_lfd : op == 52 ? Opcode::ppc_stfs : Opcode::ppc_stfd;
        i.operands = {data, memory};
        i.access = {load ? OperandAccess::write : OperandAccess::read, OperandAccess::address};
        if (load) i.register_writes.push_back(data); else i.register_reads.push_back(data);
        if (ra) i.register_reads.push_back(gpr(ra, width));
        i.memory_read = load;
        i.memory_write = !load;
    } else if (op == 32 || op == 33 || op == 34 || op == 35 || op == 36 || op == 37 ||
               op == 38 || op == 39 || op == 40 || op == 41 || op == 42 || op == 43 || op == 44 || op == 45) {
        Opcode opcode = Opcode::ppc_lwz;
        unsigned size = 32;
        bool load = true, update = (op & 1) != 0, sign = false;
        switch (op) {
        case 32: case 33: opcode = op == 32 ? Opcode::ppc_lwz : Opcode::ppc_lwzu; break;
        case 34: case 35: opcode = op == 34 ? Opcode::ppc_lbz : Opcode::ppc_lbzu; size = 8; break;
        case 36: case 37: opcode = op == 36 ? Opcode::ppc_stw : Opcode::ppc_stwu; load = false; break;
        case 38: case 39: opcode = op == 38 ? Opcode::ppc_stb : Opcode::ppc_stbu; load = false; size = 8; break;
        case 40: case 41: opcode = op == 40 ? Opcode::ppc_lhz : Opcode::ppc_lhzu; size = 16; break;
        case 42: case 43: opcode = op == 42 ? Opcode::ppc_lha : Opcode::ppc_lhau; size = 16; sign = true; break;
        case 44: case 45: opcode = op == 44 ? Opcode::ppc_sth : Opcode::ppc_sthu; load = false; size = 16; break;
        }
        if (!load_store(opcode, size, load, update, sign))
            return fail(DecodeStatus::invalid, "PowerPC update-form load/store has an invalid base or destination");
    } else if ((op == 58 || op == 62) && ppc64) {
        const auto form = w & 3;
        const bool load = op == 58;
        if (form == 2 && load)
            return fail(DecodeStatus::unsupported, "Valid PowerPC LWA DS-form is outside the enabled subset");
        if (form > 1)
            return fail(DecodeStatus::invalid, "Reserved PowerPC DS-form selector");
        const bool update = form == 1;
        const Opcode opcode = load ? (update ? Opcode::ppc_ldu : Opcode::ppc_ld)
                                   : (update ? Opcode::ppc_stdu : Opcode::ppc_std);
        const auto saved = w;
        (void)saved;
        if (update && (ra == 0 || (load && ra == rt)))
            return fail(DecodeStatus::invalid, "PowerPC update-form load/store has an invalid base or destination");
        const auto displacement = sext(w & 0xfffc, 16);
        i.opcode = opcode;
        auto data = gpr(rt, width);
        i.operands.emplace_back(data); i.access.push_back(load ? OperandAccess::write : OperandAccess::read);
        if (load) i.register_writes.push_back(data); else i.register_reads.push_back(data);
        MemoryOperand memory{64, 64, {}, ra ? std::optional<R>(gpr(ra, 64)) : std::nullopt, {},
                             1, displacement, false, {}, EncodedField{2, 2}};
        i.operands.emplace_back(memory); i.access.push_back(OperandAccess::address);
        if (ra) i.register_reads.push_back(gpr(ra, 64));
        if (update) i.register_writes.push_back(gpr(ra, 64));
        i.memory_read = load; i.memory_write = !load;
    } else if (op == 17) {
        // SC-form: reserved bits 6:19 and 27:30 must be zero; bit 31 is the
        // fixed one in the architectural numbering, yielding low suffix 10b.
        if ((w & 0x03fff000u) != 0 || (w & 0x1fu) != 0x2u)
            return fail(DecodeStatus::invalid, "PowerPC SC has nonzero reserved bits or an invalid fixed suffix");
        i.opcode = Opcode::ppc_sc;
        const auto level = (w >> 5) & 0x7f;
        i.operands.emplace_back(ImmediateOperand{level, 7, 7, false, EncodedField{2, 2}});
        i.access.push_back(OperandAccess::read);
        i.flow = FlowKind::trap;
    } else if (op == 18) {
        const auto displacement = sext(w & 0x03fffffc, 26);
        const bool absolute = (w & 2) != 0, link = (w & 1) != 0;
        i.opcode = Opcode::ppc_b;
        i.flow = link ? FlowKind::call : FlowKind::jump;
        set_target(i, displacement, absolute, 24);
        branch_link(i, link);
    } else if (op == 16) {
        const unsigned bo = (w >> 21) & 31, bi = (w >> 16) & 31;
        const bool ignore_cr = (bo & 0x10) != 0, ignore_ctr = (bo & 0x04) != 0;
        const bool absolute = (w & 2) != 0, link = (w & 1) != 0;
        i.opcode = Opcode::ppc_bc;
        i.operands.emplace_back(ImmediateOperand{bo, 5, 5, false, EncodedField{0, 3}});
        i.operands.emplace_back(ImmediateOperand{bi, 5, 5, false, EncodedField{1, 2}});
        i.access = {OperandAccess::read, OperandAccess::read};
        if (!ignore_cr) { i.register_reads.push_back(cr(bi / 4)); i.operands.emplace_back(cr(bi / 4)); i.access.push_back(OperandAccess::read); }
        if (!ignore_ctr) { i.register_reads.push_back(ctr(width)); i.register_writes.push_back(ctr(width)); }
        i.flow = (!ignore_cr || !ignore_ctr) ? FlowKind::conditional_branch : (link ? FlowKind::call : FlowKind::jump);
        set_target(i, sext(w & 0xfffc, 16), absolute, 14);
        branch_link(i, link);
    } else if (op == 19) {
        const unsigned xo = (w >> 1) & 0x3ff;
        const unsigned bo = (w >> 21) & 31, bi = (w >> 16) & 31;
        const bool link = (w & 1) != 0;
        if (xo != 16 && xo != 528)
            return fail(DecodeStatus::unsupported, "PowerPC opcode-19 instruction is outside the enabled branch subset");
        const bool is_lr = xo == 16;
        i.opcode = is_lr ? Opcode::ppc_bclr : Opcode::ppc_bcctr;
        i.operands.emplace_back(ImmediateOperand{bo, 5, 5, false, {}});
        i.operands.emplace_back(ImmediateOperand{bi, 5, 5, false, {}});
        i.access = {OperandAccess::read, OperandAccess::read};
        const bool ignore_cr = (bo & 0x10) != 0, ignore_ctr = (bo & 0x04) != 0;
        if (!ignore_cr) { i.register_reads.push_back(cr(bi / 4)); i.operands.emplace_back(cr(bi / 4)); i.access.push_back(OperandAccess::read); }
        if (is_lr) i.register_reads.push_back(lr(width));
        else i.register_reads.push_back(ctr(width));
        if (!ignore_ctr && is_lr) i.register_writes.push_back(ctr(width));
        else if (!ignore_ctr && !is_lr)
            return fail(DecodeStatus::invalid, "PowerPC BCCTR cannot decrement and test CTR");
        i.flow = (!ignore_cr || !ignore_ctr) ? FlowKind::conditional_branch : (link ? FlowKind::call : FlowKind::jump);
        if (is_lr && !link && ignore_cr && ignore_ctr && bi == 0)
            i.flow = FlowKind::ret;
        branch_link(i, link);
    } else if (op == 30) {
        if (!ppc64)
            return fail(DecodeStatus::unsupported, "PowerPC doubleword rotate requires PPC64 mode");
        const unsigned md_xo = (w >> 2) & 7;
        const unsigned mds_xo = (w >> 1) & 15;
        const bool record = rc != 0;
        const unsigned sh = ((w >> 11) & 31) | (((w >> 1) & 1) << 5);
        const unsigned bound = (w >> 5) & 63;
        bool insert = false, variable = false;
        unsigned mask_begin = 0, mask_end = 63;
        if (md_xo <= 3) {
            switch (md_xo) {
            case 0: i.opcode = record ? Opcode::ppc_rldicl_dot : Opcode::ppc_rldicl; mask_begin = bound; break;
            case 1: i.opcode = record ? Opcode::ppc_rldicr_dot : Opcode::ppc_rldicr; mask_end = bound; break;
            case 2:
                i.opcode = record ? Opcode::ppc_rldic_dot : Opcode::ppc_rldic;
                mask_begin = bound; mask_end = 63 - sh; break;
            case 3:
                i.opcode = record ? Opcode::ppc_rldimi_dot : Opcode::ppc_rldimi;
                insert = true; mask_begin = bound; mask_end = 63 - sh; break;
            }
        } else if (mds_xo == 8 || mds_xo == 9) {
            variable = true;
            mask_begin = mds_xo == 8 ? bound : 0;
            mask_end = mds_xo == 8 ? 63 : bound;
            i.opcode = mds_xo == 8 ? (record ? Opcode::ppc_rldcl_dot : Opcode::ppc_rldcl)
                                   : (record ? Opcode::ppc_rldcr_dot : Opcode::ppc_rldcr);
        } else {
            return fail(DecodeStatus::unsupported, "PowerPC opcode-30 form is outside the enabled doubleword rotate subset");
        }
        mark_destination(i, gpr(ra, 64));
        i.operands.emplace_back(gpr(rt, 64));
        i.access.push_back(OperandAccess::read);
        i.register_reads.push_back(gpr(rt, 64));
        if (insert) {
            i.access.front() = OperandAccess::read_write;
            i.register_reads.push_back(gpr(ra, 64));
        }
        if (variable) {
            i.operands.emplace_back(gpr(rb, 64));
            i.access.push_back(OperandAccess::read);
            i.register_reads.push_back(gpr(rb, 64));
        } else {
            i.operands.emplace_back(ImmediateOperand{sh, 6, 6, false, EncodedField{2, 2}});
            i.access.push_back(OperandAccess::read);
        }
        i.operands.emplace_back(ImmediateOperand{mask_begin, 6, 6, false, EncodedField{2, 2}});
        i.operands.emplace_back(ImmediateOperand{mask_end, 6, 6, false, EncodedField{2, 2}});
        i.access.insert(i.access.end(), {OperandAccess::read, OperandAccess::read});
        if (record) i.register_writes.push_back(cr(0));
    } else if (op == 31) {
        const unsigned xo = (w >> 1) & 0x3ff;
        const auto xform_binary = [&](Opcode opcode, bool carry_in, bool carry_out) {
            i.opcode = opcode;
            mark_destination(i, gpr(rt, width));
            i.operands.emplace_back(gpr(ra, width));
            i.operands.emplace_back(gpr(rb, width));
            i.access.insert(i.access.end(), {OperandAccess::read, OperandAccess::read});
            i.register_reads = {gpr(ra, width), gpr(rb, width)};
            if (carry_in) {
                i.access.push_back(OperandAccess::read);
                i.register_reads.push_back(xer());
            }
            if (carry_out) i.register_writes.push_back(xer());
            if (rc) i.register_writes.push_back(cr(0));
        };
        if ((xo == 266 || xo == 40 || xo == 444 || xo == 316 || xo == 28 ||
             xo == 60 || xo == 124 || xo == 284 || xo == 412 || xo == 476) && !(w & 0x400)) {
            const bool logical = xo == 444 || xo == 316 || xo == 28 || xo == 60 || xo == 124 ||
                                 xo == 284 || xo == 412 || xo == 476;
            const bool record = rc != 0;
            i.opcode = xo == 266 ? (record ? Opcode::ppc_add_dot : Opcode::ppc_add) :
                       xo == 40 ? (record ? Opcode::ppc_subf_dot : Opcode::ppc_subf) :
                       xo == 444 ? (record ? Opcode::ppc_or_dot : Opcode::ppc_or) :
                       xo == 316 ? (record ? Opcode::ppc_xor_dot : Opcode::ppc_xor) :
                       xo == 28 ? (record ? Opcode::ppc_and_dot : Opcode::ppc_and) :
                       xo == 60 ? (record ? Opcode::ppc_andc_dot : Opcode::ppc_andc) :
                       xo == 124 ? (record ? Opcode::ppc_nor_dot : Opcode::ppc_nor) :
                       xo == 284 ? (record ? Opcode::ppc_eqv_dot : Opcode::ppc_eqv) :
                       xo == 412 ? (record ? Opcode::ppc_orc_dot : Opcode::ppc_orc) :
                                   (record ? Opcode::ppc_nand_dot : Opcode::ppc_nand);
            mark_destination(i, gpr(logical ? ra : rt, width));
            i.operands.emplace_back(gpr(logical ? rt : ra, width)); i.operands.emplace_back(gpr(rb, width));
            i.access.insert(i.access.end(), {OperandAccess::read, OperandAccess::read});
            i.register_reads = {gpr(logical ? rt : ra, width), gpr(rb, width)};
            if (record) i.register_writes.push_back(cr(0));
        } else if ((xo & 0x1ff) == 0 || (xo & 0x1ff) == 32) {
            if (rc)
                return fail(DecodeStatus::invalid, "PowerPC register compare has a reserved record bit");
            const bool wide = (xo & 0x200) != 0;
            if (wide && !ppc64)
                return fail(DecodeStatus::invalid, "PowerPC 64-bit compare is invalid in PPC32 mode");
            const bool logical = (xo & 0x1ff) == 32;
            const unsigned bf = rt >> 2;
            const unsigned compare_width = wide ? 64u : 32u;
            i.opcode = logical ? Opcode::ppc_cmpl : Opcode::ppc_cmp;
            i.operands = {cr(bf), gpr(ra, compare_width), gpr(rb, compare_width)};
            i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
            i.register_reads = {gpr(ra, compare_width), gpr(rb, compare_width)};
            i.register_writes.push_back(cr(bf));
        } else if (xo == 26 || xo == 58 || xo == 954 || xo == 922 || xo == 986) {
            if (rb != 0)
                return fail(DecodeStatus::invalid, "PowerPC count/extend instruction has a reserved source field");
            if ((xo == 58 || xo == 986) && !ppc64)
                return fail(DecodeStatus::unsupported, "PowerPC doubleword count/extend requires PPC64 mode");
            const bool record = rc != 0;
            i.opcode = xo == 26 ? (record ? Opcode::ppc_cntlzw_dot : Opcode::ppc_cntlzw) :
                       xo == 58 ? (record ? Opcode::ppc_cntlzd_dot : Opcode::ppc_cntlzd) :
                       xo == 954 ? (record ? Opcode::ppc_extsb_dot : Opcode::ppc_extsb) :
                       xo == 922 ? (record ? Opcode::ppc_extsh_dot : Opcode::ppc_extsh) :
                                   (record ? Opcode::ppc_extsw_dot : Opcode::ppc_extsw);
            const auto source_width = xo == 26 || xo == 58 ? (xo == 26 ? 32u : 64u) :
                                      xo == 954 ? 8u : xo == 922 ? 16u : 32u;
            i.operands = {gpr(ra, width), gpr(rt, width)};
            i.access = {OperandAccess::write, OperandAccess::read};
            i.register_writes = {gpr(ra, width)};
            i.register_reads = {gpr(rt, source_width)};
            if (record) i.register_writes.push_back(cr(0));
        } else if (xo == 10 || xo == 138 || xo == 8 || xo == 136) {
            const bool carry_in = xo == 138 || xo == 136;
            xform_binary(xo == 10 ? Opcode::ppc_addc : xo == 138 ? Opcode::ppc_adde :
                         xo == 8 ? Opcode::ppc_subfc : Opcode::ppc_subfe,
                         carry_in, true);
        } else if (xo == 104) {
            if (rb != 0 || (w & 0x400))
                return fail(DecodeStatus::invalid, "PowerPC NEG has a reserved source field or overflow-enable bit");
            i.opcode = Opcode::ppc_neg;
            mark_destination(i, gpr(rt, width));
            i.operands.emplace_back(gpr(ra, width));
            i.access.push_back(OperandAccess::read);
            i.register_reads.push_back(gpr(ra, width));
            if (rc) i.register_writes.push_back(cr(0));
        } else if (xo == 235 || xo == 233 || xo == 491 || xo == 459 || xo == 489 || xo == 457) {
            if ((xo == 233 || xo == 489 || xo == 457) && !ppc64)
                return fail(DecodeStatus::unsupported, "PowerPC doubleword arithmetic requires PPC64 mode");
            if (w & 0x400)
                return fail(DecodeStatus::unsupported, "PowerPC multiply/divide overflow-enable form is not modeled");
            i.opcode = xo == 235 ? Opcode::ppc_mullw : xo == 233 ? Opcode::ppc_mulld :
                       xo == 491 ? Opcode::ppc_divw : xo == 459 ? Opcode::ppc_divwu :
                       xo == 489 ? Opcode::ppc_divd : Opcode::ppc_divdu;
            mark_destination(i, gpr(rt, width));
            i.operands.emplace_back(gpr(ra, width));
            i.operands.emplace_back(gpr(rb, width));
            i.access.insert(i.access.end(), {OperandAccess::read, OperandAccess::read});
            i.register_reads = {gpr(ra, width), gpr(rb, width)};
            if (rc) i.register_writes.push_back(cr(0));
        } else if (xo == 24 || xo == 536 || xo == 792 || xo == 824 ||
                   xo == 27 || xo == 539 || xo == 794 || (xo & 0x1fe) == 412) {
            const bool sradi = (xo & 0x1fe) == 412;
            const bool doubleword = xo == 27 || xo == 539 || xo == 794 || sradi;
            if (doubleword && !ppc64)
                return fail(DecodeStatus::unsupported, "PowerPC doubleword shift requires PPC64 mode");
            if ((w & 0x400) || (xo == 824 && rb > 31))
                return fail(DecodeStatus::invalid, "PowerPC shift has a reserved field or overflow-enable bit");
            i.opcode = xo == 24 ? Opcode::ppc_slw : xo == 536 ? Opcode::ppc_srw :
                       xo == 792 ? Opcode::ppc_sraw : xo == 824 ? Opcode::ppc_srawi :
                       xo == 27 ? Opcode::ppc_sld : xo == 539 ? Opcode::ppc_srd :
                       sradi ? Opcode::ppc_sradi : Opcode::ppc_srad;
            mark_destination(i, gpr(ra, width));
            i.operands.emplace_back(gpr(rt, width));
            i.access.push_back(OperandAccess::read);
            i.register_reads.push_back(gpr(rt, width));
            if (xo == 824 || sradi) {
                const auto amount = sradi ? (((xo & 1) << 5) | rb) : rb;
                std::optional<EncodedField> shift_encoding;
                if (!sradi) shift_encoding = EncodedField{2, 1};
                i.operands.emplace_back(ImmediateOperand{amount, static_cast<std::uint16_t>(sradi ? 6 : 5),
                                                          static_cast<std::uint16_t>(sradi ? 6 : 5), false,
                                                          shift_encoding});
                i.access.push_back(OperandAccess::read);
            } else {
                i.operands.emplace_back(gpr(rb, width));
                i.access.push_back(OperandAccess::read);
                i.register_reads.push_back(gpr(rb, width));
            }
            if (xo == 792 || xo == 824 || xo == 794 || sradi)
                i.register_writes.push_back(xer());
            if (rc) i.register_writes.push_back(cr(0));
        } else if (xo == 23 || xo == 55 || xo == 87 || xo == 119 || xo == 151 || xo == 183 ||
                   xo == 215 || xo == 247 || xo == 279 || xo == 311 || xo == 343 || xo == 375 ||
                   xo == 407 || xo == 439 || xo == 21 || xo == 53 || xo == 149 || xo == 181 ||
                   xo == 534 || xo == 790 || xo == 662 || xo == 918 || xo == 532 || xo == 660) {
            if (rc) return fail(DecodeStatus::invalid, "PowerPC indexed load/store has a reserved record bit");
            const bool update = xo == 55 || xo == 119 || xo == 183 || xo == 247 || xo == 311 || xo == 375 ||
                                xo == 439 || xo == 53 || xo == 181;
            const bool load = xo == 23 || xo == 55 || xo == 87 || xo == 119 || xo == 279 || xo == 311 ||
                              xo == 343 || xo == 375 || xo == 21 || xo == 53 || xo == 534 || xo == 790 || xo == 532;
            const bool doubleword = xo == 21 || xo == 53 || xo == 149 || xo == 181 || xo == 532 || xo == 660;
            if (doubleword && !ppc64)
                return fail(DecodeStatus::unsupported, "PowerPC indexed doubleword memory operation requires PPC64 mode");
            const unsigned size = doubleword ? 64u :
                (xo == 87 || xo == 119 || xo == 215 || xo == 247) ? 8u :
                (xo == 279 || xo == 311 || xo == 343 || xo == 375 || xo == 407 || xo == 439 || xo == 790 || xo == 918) ? 16u : 32u;
            Opcode opcode = Opcode::ppc_lwzx;
            if (xo == 23) opcode = Opcode::ppc_lwzx; else if (xo == 55) opcode = Opcode::ppc_lwzux;
            else if (xo == 87) opcode = Opcode::ppc_lbzx; else if (xo == 119) opcode = Opcode::ppc_lbzux;
            else if (xo == 279) opcode = Opcode::ppc_lhzx; else if (xo == 311) opcode = Opcode::ppc_lhzux;
            else if (xo == 343) opcode = Opcode::ppc_lhax; else if (xo == 375) opcode = Opcode::ppc_lhaux;
            else if (xo == 151) opcode = Opcode::ppc_stwx; else if (xo == 183) opcode = Opcode::ppc_stwux;
            else if (xo == 215) opcode = Opcode::ppc_stbx; else if (xo == 247) opcode = Opcode::ppc_stbux;
            else if (xo == 407) opcode = Opcode::ppc_sthx; else if (xo == 439) opcode = Opcode::ppc_sthux;
            else if (xo == 21) opcode = Opcode::ppc_ldx; else if (xo == 53) opcode = Opcode::ppc_ldux;
            else if (xo == 149) opcode = Opcode::ppc_stdx; else if (xo == 181) opcode = Opcode::ppc_stdux;
            else if (xo == 534) opcode = Opcode::ppc_lwbrx; else if (xo == 790) opcode = Opcode::ppc_lhbrx;
            else if (xo == 662) opcode = Opcode::ppc_stwbrx; else if (xo == 918) opcode = Opcode::ppc_sthbrx;
            else if (xo == 532) opcode = Opcode::ppc_ldbrx; else if (xo == 660) opcode = Opcode::ppc_stdbrx;
            if (!indexed_load_store(opcode, size, load, update))
                return fail(DecodeStatus::invalid, "PowerPC indexed update-form load/store has an invalid base or destination");
        } else if (xo == 19 && !rc) {
            if (ra != 0 || rb != 0)
                return fail(DecodeStatus::invalid, "PowerPC MFCR has reserved source fields");
            i.opcode = Opcode::ppc_mfcr;
            i.operands = {gpr(rt, width), R{RegisterBank::ppc_cr, 0, 32, false}};
            i.access = {OperandAccess::write, OperandAccess::read};
            i.register_writes.push_back(gpr(rt, width));
            for (unsigned field = 0; field < 8; ++field) i.register_reads.push_back(cr(field));
        } else if (xo == 144 && !rc) {
            if (w & (1u << 20))
                return fail(DecodeStatus::invalid, "PowerPC MTCRF has a reserved field set");
            const unsigned mask = (w >> 12) & 0xff;
            i.opcode = Opcode::ppc_mtcrf;
            i.operands = {ImmediateOperand{mask, 8, 8, false, EncodedField{1, 2}}, gpr(rt, width)};
            i.access = {OperandAccess::read, OperandAccess::read};
            i.register_reads.push_back(gpr(rt, width));
            for (unsigned field = 0; field < 8; ++field)
                if (mask & (1u << (7 - field))) i.register_writes.push_back(cr(field));
        } else if (xo == 339 || xo == 467) {
            const unsigned spr = ((w >> 16) & 31) | (((w >> 11) & 31) << 5);
            const bool from_special = xo == 339;
            const RegisterBank bank = spr == 1 ? RegisterBank::ppc_xer : spr == 8 ? RegisterBank::ppc_lr :
                                      spr == 9 ? RegisterBank::ppc_ctr : RegisterBank::ppc_lr;
            if (spr != 1 && spr != 8 && spr != 9)
                return fail(DecodeStatus::unsupported, "PowerPC SPR is outside the enabled XER/LR/CTR subset");
            const R special{bank, 0, static_cast<std::uint16_t>(spr == 1 ? 32 : width), false};
            i.opcode = spr == 1 ? (from_special ? Opcode::ppc_mfxer : Opcode::ppc_mtxer) :
                       from_special ? (spr == 8 ? Opcode::ppc_mflr : Opcode::ppc_mfctr)
                                    : (spr == 8 ? Opcode::ppc_mtlr : Opcode::ppc_mtctr);
            if (from_special) {
                i.operands = {gpr(rt, width), special}; i.access = {OperandAccess::write, OperandAccess::read};
                i.register_writes.push_back(gpr(rt, width));
                i.register_reads.push_back(special);
            } else {
                i.operands = {special, gpr(rt, width)}; i.access = {OperandAccess::write, OperandAccess::read};
                i.register_writes.push_back(special); i.register_reads.push_back(gpr(rt, width));
            }
        } else {
            return fail(DecodeStatus::unsupported, "PowerPC opcode-31 X-form is outside the enabled integer subset");
        }
    } else if (op == 63 && ((w >> 1) & 0x3ff) == 0) {
        // Floating compare unordered. BF occupies the high three bits of the
        // nominal FRT field; the remaining two bits are reserved.
        if (rc || (rt & 3) != 0)
            return fail(DecodeStatus::invalid, "PowerPC FCMPU has reserved fields set");
        const auto field = cr((w >> 23) & 7);
        const auto left = fpr(ra, 64), right = fpr(rb, 64);
        i.opcode = Opcode::ppc_fcmpu;
        i.operands = {field, left, right};
        i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
        i.register_reads = {left, right, fpscr()};
        i.register_writes = {field, fpscr()};
    } else if (op == 63 && ((w >> 1) & 0x3ff) == 32) {
        // Floating compare ordered has the same operands/results as FCMPU,
        // but its signaling-NaN/quiet-NaN exception behavior differs.
        if (rc || (rt & 3) != 0)
            return fail(DecodeStatus::invalid, "PowerPC FCMPO has reserved fields set");
        const auto field = cr((w >> 23) & 7);
        const auto left = fpr(ra, 64), right = fpr(rb, 64);
        i.opcode = Opcode::ppc_fcmpo;
        i.operands = {field, left, right};
        i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
        i.register_reads = {left, right, fpscr()};
        i.register_writes = {field, fpscr()};
    } else if ((op == 63 && (((w >> 1) & 0x3ff) == 14 || ((w >> 1) & 0x3ff) == 15 ||
                             ((w >> 1) & 0x3ff) == 142 || ((w >> 1) & 0x3ff) == 143 ||
                             ((w >> 1) & 0x3ff) == 814 || ((w >> 1) & 0x3ff) == 815 ||
                             ((w >> 1) & 0x3ff) == 846 || ((w >> 1) & 0x3ff) == 942 ||
                             ((w >> 1) & 0x3ff) == 943 || ((w >> 1) & 0x3ff) == 974)) ||
               (op == 59 && ((w >> 1) & 0x3ff) == 846)) {
        // Power ISA Book I 4.6.7.2: exact ten-bit X-form XO, not the
        // five-bit A-form arithmetic selector. Integer payloads remain in FPRs.
        const auto xo = (w >> 1) & 0x3ff;
        const bool to_integer = op == 63 && xo != 846 && xo != 974;
        const bool word = xo == 14 || xo == 15 || xo == 142 || xo == 143;
        const bool single_result = op == 59;
        if (ra != 0)
            return fail(DecodeStatus::invalid, "PowerPC FP conversion has nonzero reserved fields");
        if (!word && !ppc64)
            return fail(DecodeStatus::unsupported, "PowerPC doubleword FP conversion requires PPC64 mode");
        i.opcode = xo == 14 ? Opcode::ppc_fctiw : xo == 15 ? Opcode::ppc_fctiwz :
                   xo == 142 ? Opcode::ppc_fctiwu : xo == 143 ? Opcode::ppc_fctiwuz :
                   xo == 814 ? Opcode::ppc_fctid : xo == 815 ? Opcode::ppc_fctidz :
                   xo == 942 ? Opcode::ppc_fctidu : xo == 943 ? Opcode::ppc_fctiduz :
                   xo == 974 ? Opcode::ppc_fcfidu : single_result ? Opcode::ppc_fcfids : Opcode::ppc_fcfid;
        const auto destination = fpr(rt, 64), source = fpr(rb, 64);
        const bool from_integer = !to_integer;
        i.operands = {destination, source};
        // An enabled invalid conversion suppresses the FRT update. FCFID* has
        // no invalid-operation case and always produces a rounded FP result.
        i.access = {from_integer ? OperandAccess::write : OperandAccess::read_write, OperandAccess::read};
        i.register_reads = {source, fpscr()};
        if (!from_integer) i.register_reads.push_back(destination);
        i.register_writes = {destination, fpscr()};
        if (rc) i.register_writes.push_back(cr1());
    } else if (op == 63 && (((w >> 1) & 0x3ff) == 12 || ((w >> 1) & 0x3ff) == 40 ||
                            ((w >> 1) & 0x3ff) == 72 || ((w >> 1) & 0x3ff) == 264)) {
        const auto xo10 = (w >> 1) & 0x3ff;
        if (ra != 0)
            return fail(DecodeStatus::invalid, "PowerPC unary floating instruction has nonzero reserved fields");
        const auto opcode = xo10 == 12 ? Opcode::ppc_frsp : xo10 == 40 ? Opcode::ppc_fneg :
                            xo10 == 72 ? Opcode::ppc_fmr : Opcode::ppc_fabs;
        const auto destination = fpr(rt, 64);
        const auto source = fpr(rb, 64);
        i.opcode = opcode;
        i.operands = {destination, source};
        i.access = {OperandAccess::write, OperandAccess::read};
        i.register_writes = {destination};
        i.register_reads = {source};
        if (opcode == Opcode::ppc_frsp) {
            i.register_reads.push_back(fpscr());
            i.register_writes.push_back(fpscr());
        }
        if (rc) {
            if (std::find(i.register_reads.begin(), i.register_reads.end(), fpscr()) == i.register_reads.end())
                i.register_reads.push_back(fpscr());
            i.register_writes.push_back(cr1());
        }
    } else if (op == 59 || op == 63) {
        const unsigned xo = (w >> 1) & 31;
        const bool single = op == 59;
        const unsigned bits = single ? 32u : 64u;
        const unsigned frc = (w >> 6) & 31;
        // A-form fused multiply-add/subtract uses all three source FPRs:
        // FRA, FRC, and FRB. The fused operation rounds once.
        if (xo == 28 || xo == 29 || xo == 30 || xo == 31) {
            const auto destination = fpr(rt, bits);
            const auto left = fpr(ra, bits), multiplier = fpr(frc, bits), addend = fpr(rb, bits);
            i.opcode = xo == 29 ? (single ? Opcode::ppc_fmadds : Opcode::ppc_fmadd) :
                       xo == 28 ? (single ? Opcode::ppc_fmsubs : Opcode::ppc_fmsub) :
                       xo == 31 ? (single ? Opcode::ppc_fnmadds : Opcode::ppc_fnmadd) :
                                  (single ? Opcode::ppc_fnmsubs : Opcode::ppc_fnmsub);
            i.operands = {destination, left, multiplier, addend};
            i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read, OperandAccess::read};
            i.register_writes = {destination, fpscr()};
            i.register_reads = {left, multiplier, addend, fpscr()};
            if (rc) i.register_writes.push_back(cr1());
            return {DecodeStatus::decoded, std::move(i), {}};
        }
        Opcode opcode;
        const char *unsupported = "PowerPC floating-point XO is outside the enabled scalar arithmetic subset";
        if (xo == 18) opcode = single ? Opcode::ppc_fdivs : Opcode::ppc_fdiv;
        else if (xo == 20) opcode = single ? Opcode::ppc_fsubs : Opcode::ppc_fsub;
        else if (xo == 21) opcode = single ? Opcode::ppc_fadds : Opcode::ppc_fadd;
        else if (xo == 25) opcode = single ? Opcode::ppc_fmuls : Opcode::ppc_fmul;
        else return fail(DecodeStatus::unsupported, unsupported);
        const bool multiply = xo == 25;
        if ((multiply && rb != 0) || (!multiply && frc != 0))
            return fail(DecodeStatus::invalid, "PowerPC floating arithmetic has a nonzero reserved operand field");
        const auto destination = fpr(rt, bits);
        const auto left = fpr(ra, bits);
        const auto right = fpr(multiply ? frc : rb, bits);
        i.opcode = opcode;
        i.operands = {destination, left, right};
        i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
        i.register_writes.push_back(destination);
        i.register_reads = {left, right};
        i.register_reads.push_back(fpscr());
        i.register_writes.push_back(fpscr());
        if (rc)
            i.register_writes.push_back(cr1());
    } else if (op == 4) {
        // VMX VX form: six-bit primary opcode, three five-bit vector registers,
        // and an exact eleven-bit extended opcode. None of the selected forms
        // uses a record bit or an additional modifier field.
        const unsigned vx_xo = w & 0x7ff;
        unsigned element_bits = 0;
        switch (vx_xo) {
        case 0:    i.opcode = Opcode::ppc_vaddubm; element_bits = 8; break;
        case 64:   i.opcode = Opcode::ppc_vadduhm; element_bits = 16; break;
        case 128:  i.opcode = Opcode::ppc_vadduwm; element_bits = 32; break;
        case 1024: i.opcode = Opcode::ppc_vsububm; element_bits = 8; break;
        case 1088: i.opcode = Opcode::ppc_vsubuhm; element_bits = 16; break;
        case 1152: i.opcode = Opcode::ppc_vsubuwm; element_bits = 32; break;
        case 1028: i.opcode = Opcode::ppc_vand; break;
        case 1092: i.opcode = Opcode::ppc_vandc; break;
        case 1156: i.opcode = Opcode::ppc_vor; break;
        case 1220: i.opcode = Opcode::ppc_vxor; break;
        case 1284: i.opcode = Opcode::ppc_vnor; break;
        default: return fail(DecodeStatus::unsupported, "PowerPC opcode-4 form is outside the enabled VMX integer subset");
        }
        const auto destination = vr(rt), left = vr(ra), right = vr(rb);
        i.operands = {destination, left, right};
        i.access = {OperandAccess::write, OperandAccess::read, OperandAccess::read};
        i.register_reads = {left, right};
        i.register_writes = {destination};
        i.vector_bits = 128;
        i.vector_element_bits = static_cast<std::uint16_t>(element_bits);
    } else {
        return fail(DecodeStatus::invalid, "Reserved or unsupported PowerPC primary opcode");
    }
    return {DecodeStatus::decoded, std::move(i), {}};
}
} // namespace hexlab
