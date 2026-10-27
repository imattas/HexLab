#include "hexlab/processors/riscv.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <string>

namespace hexlab {
namespace {
std::uint16_t halfword(std::span<const std::byte> bytes) {
    return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[0]) |
                                      (std::to_integer<std::uint8_t>(bytes[1]) << 8));
}

std::uint32_t word(std::span<const std::byte> bytes) {
    std::uint32_t value = 0;
    for (unsigned n = 0; n < 4; ++n)
        value |= std::to_integer<std::uint32_t>(bytes[n]) << (8 * n);
    return value;
}

std::int64_t sign_extend(std::uint64_t value, unsigned width) {
    const auto sign = UINT64_C(1) << (width - 1);
    if (value & sign)
        return static_cast<std::int64_t>(value) - static_cast<std::int64_t>(UINT64_C(1) << width);
    return static_cast<std::int64_t>(value);
}

std::optional<Address> add_target(Address at, std::int64_t delta) {
    if (delta >= 0) {
        const auto amount = static_cast<std::uint64_t>(delta);
        if (amount <= UINT64_MAX - at.offset)
            return Address{at.space, at.offset + amount};
    } else {
        const auto amount = static_cast<std::uint64_t>(-(delta + 1)) + 1;
        if (amount <= at.offset)
            return Address{at.space, at.offset - amount};
    }
    return {};
}

RiscvDecodeResult failure(DecodeStatus status, const char *reason) {
    return {status, {}, reason};
}

void operand(RiscvInstruction &instruction, RiscvOperand value, RiscvOperandAccess access);
void read_register(RiscvInstruction &instruction, unsigned index);
void read_vector_configuration(RiscvInstruction &instruction);
void read_vector_destination(RiscvInstruction &instruction, unsigned index) {
    // The old value supplies prestart, masked-off, slide-up, and undisturbed
    // tail elements. Keeping it as a dependency makes lifting policy-aware.
    instruction.register_reads.push_back(RiscvRegister{static_cast<std::uint8_t>(index), false, true});
}

bool decode_vector_configuration(std::uint32_t w, RiscvInstruction &i) {
    const unsigned rd = (w >> 7) & 31, rs1 = (w >> 15) & 31, rs2 = (w >> 20) & 31;
    const unsigned top = w >> 30;
    i.opcode = RiscvOpcode::vsetvli;
    if (top == 3) {
        i.opcode = RiscvOpcode::vsetivli;
        operand(i, RiscvRegister{static_cast<std::uint8_t>(rd)}, RiscvOperandAccess::write);
        operand(i, RiscvImmediate{static_cast<std::int64_t>(rs1), 5, false}, RiscvOperandAccess::read);
        operand(i, RiscvImmediate{static_cast<std::int64_t>((w >> 20) & 0x3ff), 10, false}, RiscvOperandAccess::read);
    } else if (((w >> 25) & 0x7f) == 0x40) {
        i.opcode = RiscvOpcode::vsetvl;
        operand(i, RiscvRegister{static_cast<std::uint8_t>(rd)}, RiscvOperandAccess::write);
        operand(i, RiscvRegister{static_cast<std::uint8_t>(rs1)}, RiscvOperandAccess::read);
        operand(i, RiscvRegister{static_cast<std::uint8_t>(rs2)}, RiscvOperandAccess::read);
    } else if ((w >> 31) == 0) {
        operand(i, RiscvRegister{static_cast<std::uint8_t>(rd)}, RiscvOperandAccess::write);
        operand(i, RiscvRegister{static_cast<std::uint8_t>(rs1)}, RiscvOperandAccess::read);
        operand(i, RiscvImmediate{static_cast<std::int64_t>((w >> 20) & 0x7ff), 11, false}, RiscvOperandAccess::read);
    } else {
        return false;
    }
    // vl and vtype are architectural implicit destinations of all vset* forms.
    i.register_writes.push_back(RiscvRegister{0, false, false, true});
    i.register_writes.push_back(RiscvRegister{1, false, false, true});
    i.register_writes.push_back(RiscvRegister{2, false, false, true}); // vstart is reset to zero.
    if (i.opcode != RiscvOpcode::vsetivli && rd == 0 && rs1 == 0)
        i.register_reads.push_back(RiscvRegister{0, false, false, true}); // AVL is the current vl.
    return true;
}

bool decode_vector_integer(std::uint32_t w, RiscvInstruction &i) {
    const unsigned funct6 = w >> 26, vm = (w >> 25) & 1;
    const unsigned vs2 = (w >> 20) & 31, vs1 = (w >> 15) & 31;
    const unsigned funct3 = (w >> 12) & 7, vd = (w >> 7) & 31;
    // This subset deliberately accepts only the standard integer VV/VX/VI
    // forms. Other widths, reductions, mask destinations and operand classes
    // remain outside the decoder's advertised coverage.
    unsigned form = funct3 == 0 ? 0 : funct3 == 4 ? 1 : funct3 == 3 ? 2 : 3;
    if (form == 3 || (funct6 == 2 && form == 2)) return false; // VSUB.VI is reserved.
    RiscvOpcode op;
    switch (funct6) {
    case 3:
        // VRSUB has VX and VI forms only; VV is reserved.
        if (form == 1) op = RiscvOpcode::vrsub_vx;
        else if (form == 2) op = RiscvOpcode::vrsub_vi;
        else return false;
        break;
    case 0: op = form == 0 ? RiscvOpcode::vadd_vv : form == 1 ? RiscvOpcode::vadd_vx : RiscvOpcode::vadd_vi; break;
    case 2: if (form > 1) return false; op = form == 0 ? RiscvOpcode::vsub_vv : RiscvOpcode::vsub_vx; break;
    case 9: op = form == 0 ? RiscvOpcode::vand_vv : form == 1 ? RiscvOpcode::vand_vx : RiscvOpcode::vand_vi; break;
    case 10: op = form == 0 ? RiscvOpcode::vor_vv : form == 1 ? RiscvOpcode::vor_vx : RiscvOpcode::vor_vi; break;
    case 11: op = form == 0 ? RiscvOpcode::vxor_vv : form == 1 ? RiscvOpcode::vxor_vx : RiscvOpcode::vxor_vi; break;
    default: return false;
    }
    i.opcode = op;
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vd), false, true}, RiscvOperandAccess::write);
    read_vector_destination(i, vd);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs2), false, true}, RiscvOperandAccess::read);
    if (form == 0)
        operand(i, RiscvRegister{static_cast<std::uint8_t>(vs1), false, true}, RiscvOperandAccess::read);
    else if (form == 1)
        operand(i, RiscvRegister{static_cast<std::uint8_t>(vs1)}, RiscvOperandAccess::read);
    else
        operand(i, RiscvImmediate{sign_extend(vs1, 5), 5, true}, RiscvOperandAccess::read);
    if (!vm) {
        RiscvRegister mask{0, false, true};
        i.register_reads.push_back(mask);
    }
    i.vector_masked = !vm;
    return true;
}

bool decode_vector_reduction(std::uint32_t w, RiscvInstruction &i) {
    const unsigned funct6 = w >> 26, vm = (w >> 25) & 1;
    const unsigned vs2 = (w >> 20) & 31, vs1 = (w >> 15) & 31;
    const unsigned funct3 = (w >> 12) & 7, vd = (w >> 7) & 31;
    // Integer reductions are OPMVV-only and require vm=1. vs1 is the
    // vector-register seed (its element zero), while vd is a vector result.
    if (funct3 != 2 || vm != 1 || funct6 > 7) return false;
    static constexpr RiscvOpcode ops[]{RiscvOpcode::vredsum, RiscvOpcode::vredand,
        RiscvOpcode::vredor, RiscvOpcode::vredxor, RiscvOpcode::vredminu,
        RiscvOpcode::vredmin, RiscvOpcode::vredmaxu, RiscvOpcode::vredmax};
    i.opcode = ops[funct6];
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vd), false, true}, RiscvOperandAccess::write);
    read_vector_destination(i, vd);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs2), false, true}, RiscvOperandAccess::read);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs1), false, true}, RiscvOperandAccess::read);
    return true;
}

bool decode_vector_compare(std::uint32_t w, RiscvInstruction &i) {
    const unsigned funct6 = w >> 26, vm = (w >> 25) & 1;
    const unsigned vs2 = (w >> 20) & 31, vs1 = (w >> 15) & 31;
    const unsigned funct3 = (w >> 12) & 7, vd = (w >> 7) & 31;
    if (funct6 < 0x18 || funct6 > 0x1f) return false;

    const unsigned form = funct3 == 0 ? 0 : funct3 == 4 ? 1 : funct3 == 3 ? 2 : 3;
    static constexpr std::array<RiscvOpcode, 20> compare_ops{
        RiscvOpcode::vmseq_vv, RiscvOpcode::vmseq_vx, RiscvOpcode::vmseq_vi,
        RiscvOpcode::vmsne_vv, RiscvOpcode::vmsne_vx, RiscvOpcode::vmsne_vi,
        RiscvOpcode::vmsltu_vv, RiscvOpcode::vmsltu_vx,
        RiscvOpcode::vmslt_vv, RiscvOpcode::vmslt_vx,
        RiscvOpcode::vmsleu_vv, RiscvOpcode::vmsleu_vx, RiscvOpcode::vmsleu_vi,
        RiscvOpcode::vmsle_vv, RiscvOpcode::vmsle_vx, RiscvOpcode::vmsle_vi,
        RiscvOpcode::vmsgtu_vx, RiscvOpcode::vmsgtu_vi,
        RiscvOpcode::vmsgt_vx, RiscvOpcode::vmsgt_vi};
    const std::size_t operation = (funct6 - 0x18) * 3;
    std::size_t selected = operation;
    switch (funct6) {
    case 0x18: case 0x19: case 0x1c: case 0x1d:
        if (form > 2) return false;
        selected += form;
        break;
    case 0x1a: case 0x1b:
        if (form > 1) return false; // The VI encoding is reserved.
        selected = (funct6 == 0x1a ? 6u : 8u) + form;
        break;
    case 0x1e: case 0x1f:
        if (form == 0 || form == 3) return false; // VMSGT has VX and VI forms only.
        selected = (funct6 == 0x1e ? 16u : 18u) + (form - 1);
        break;
    default: return false;
    }
    if (selected >= compare_ops.size()) return false;

    i.opcode = compare_ops[selected];
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vd), false, true}, RiscvOperandAccess::write);
    read_vector_destination(i, vd);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs2), false, true}, RiscvOperandAccess::read);
    if (form == 0)
        operand(i, RiscvRegister{static_cast<std::uint8_t>(vs1), false, true}, RiscvOperandAccess::read);
    else if (form == 1)
        operand(i, RiscvRegister{static_cast<std::uint8_t>(vs1)}, RiscvOperandAccess::read);
    else
        operand(i, RiscvImmediate{sign_extend(vs1, 5), 5, true}, RiscvOperandAccess::read);
    if (!vm)
        i.register_reads.push_back(RiscvRegister{0, false, true});
    i.vector_masked = !vm;
    return true;
}

bool decode_vector_shift_minmax(std::uint32_t w, RiscvInstruction &i) {
    const unsigned funct6 = w >> 26, vm = (w >> 25) & 1;
    const unsigned vs2 = (w >> 20) & 31, vs1 = (w >> 15) & 31;
    const unsigned funct3 = (w >> 12) & 7, vd = (w >> 7) & 31;
    const unsigned form = funct3 == 0 ? 0 : funct3 == 4 ? 1 : funct3 == 3 ? 2 : 3;
    RiscvOpcode op;
    bool shift = false;
    switch (funct6) {
    case 0x25: shift = true; op = form == 0 ? RiscvOpcode::vsll_vv : form == 1 ? RiscvOpcode::vsll_vx : RiscvOpcode::vsll_vi; break;
    case 0x28: shift = true; op = form == 0 ? RiscvOpcode::vsrl_vv : form == 1 ? RiscvOpcode::vsrl_vx : RiscvOpcode::vsrl_vi; break;
    case 0x29: shift = true; op = form == 0 ? RiscvOpcode::vsra_vv : form == 1 ? RiscvOpcode::vsra_vx : RiscvOpcode::vsra_vi; break;
    case 0x04: if (form > 1) return false; op = form == 0 ? RiscvOpcode::vminu_vv : RiscvOpcode::vminu_vx; break;
    case 0x05: if (form > 1) return false; op = form == 0 ? RiscvOpcode::vmin_vv : RiscvOpcode::vmin_vx; break;
    case 0x06: if (form > 1) return false; op = form == 0 ? RiscvOpcode::vmaxu_vv : RiscvOpcode::vmaxu_vx; break;
    case 0x07: if (form > 1) return false; op = form == 0 ? RiscvOpcode::vmax_vv : RiscvOpcode::vmax_vx; break;
    default: return false;
    }
    if (form > 2) return false;
    i.opcode = op;
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vd), false, true}, RiscvOperandAccess::write);
    read_vector_destination(i, vd);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs2), false, true}, RiscvOperandAccess::read);
    if (form == 0)
        operand(i, RiscvRegister{static_cast<std::uint8_t>(vs1), false, true}, RiscvOperandAccess::read);
    else if (form == 1)
        operand(i, RiscvRegister{static_cast<std::uint8_t>(vs1)}, RiscvOperandAccess::read);
    else
        operand(i, RiscvImmediate{shift ? static_cast<std::int64_t>(vs1) : sign_extend(vs1, 5), 5, !shift}, RiscvOperandAccess::read);
    if (!vm) i.register_reads.push_back(RiscvRegister{0, false, true});
    i.vector_masked = !vm;
    return true;
}

bool decode_vector_floating(std::uint32_t w, RiscvInstruction &i) {
    const unsigned funct6 = w >> 26, vm = (w >> 25) & 1;
    const unsigned vs2 = (w >> 20) & 31, vs1 = (w >> 15) & 31;
    const unsigned funct3 = (w >> 12) & 7, vd = (w >> 7) & 31;
    // VFUNARY1 uses OPFVV and encodes its sub-op in vs1.
    if (funct3 == 1 && funct6 == 0x13 &&
        (vs1 == 0 || vs1 == 4 || vs1 == 5 || vs1 == 16)) {
        switch (vs1) {
        case 0: i.opcode = RiscvOpcode::vfsqrt_v; break;
        case 4: i.opcode = RiscvOpcode::vfrsqrt7_v; break;
        case 5: i.opcode = RiscvOpcode::vfrec7_v; break;
        case 16: i.opcode = RiscvOpcode::vfclass_v; break;
        }
        // vfrec7's overflow result depends on frm; reciprocal-square-root
        // estimates are independent of frm. All three arithmetic operations
        // can accrue IEEE exceptions, unlike classification.
        i.reads_frm = vs1 == 0 || vs1 == 5;
        i.reads_fflags = vs1 != 16;
        i.writes_fflags = vs1 != 16;
        operand(i, RiscvRegister{static_cast<std::uint8_t>(vd), false, true}, RiscvOperandAccess::write);
        read_vector_destination(i, vd);
        operand(i, RiscvRegister{static_cast<std::uint8_t>(vs2), false, true}, RiscvOperandAccess::read);
        if (!vm) i.register_reads.push_back(RiscvRegister{0, false, true});
        i.vector_masked = !vm;
        return true;
    }
    if (funct3 != 1 && funct3 != 5) return false; // OPFVV and OPFVF only.
    const bool scalar = funct3 == 5;
    RiscvOpcode op;
    bool uses_rounding = false, flags = false;
    switch (funct6) {
    case 0x00: op = scalar ? RiscvOpcode::vfadd_vf : RiscvOpcode::vfadd_vv; uses_rounding = flags = true; break;
    case 0x02: op = scalar ? RiscvOpcode::vfsub_vf : RiscvOpcode::vfsub_vv; uses_rounding = flags = true; break;
    case 0x20: op = scalar ? RiscvOpcode::vfdiv_vf : RiscvOpcode::vfdiv_vv; uses_rounding = flags = true; break;
    case 0x24: op = scalar ? RiscvOpcode::vfmul_vf : RiscvOpcode::vfmul_vv; uses_rounding = flags = true; break;
    case 0x29: op = scalar ? RiscvOpcode::vfmacc_vf : RiscvOpcode::vfmacc_vv; uses_rounding = flags = true; break;
    case 0x2b: op = scalar ? RiscvOpcode::vfnmacc_vf : RiscvOpcode::vfnmacc_vv; uses_rounding = flags = true; break;
    case 0x2d: op = scalar ? RiscvOpcode::vfmsac_vf : RiscvOpcode::vfmsac_vv; uses_rounding = flags = true; break;
    case 0x2f: op = scalar ? RiscvOpcode::vfnmsac_vf : RiscvOpcode::vfnmsac_vv; uses_rounding = flags = true; break;
    case 0x28: op = scalar ? RiscvOpcode::vfmadd_vf : RiscvOpcode::vfmadd_vv; uses_rounding = flags = true; break;
    case 0x2a: op = scalar ? RiscvOpcode::vfnmadd_vf : RiscvOpcode::vfnmadd_vv; uses_rounding = flags = true; break;
    case 0x2c: op = scalar ? RiscvOpcode::vfmsub_vf : RiscvOpcode::vfmsub_vv; uses_rounding = flags = true; break;
    case 0x2e: op = scalar ? RiscvOpcode::vfnmsub_vf : RiscvOpcode::vfnmsub_vv; uses_rounding = flags = true; break;
    case 0x08: op = scalar ? RiscvOpcode::vfsgnj_vf : RiscvOpcode::vfsgnj_vv; break;
    case 0x09: op = scalar ? RiscvOpcode::vfsgnjn_vf : RiscvOpcode::vfsgnjn_vv; break;
    case 0x0a: op = scalar ? RiscvOpcode::vfsgnjx_vf : RiscvOpcode::vfsgnjx_vv; break;
    case 0x04: op = scalar ? RiscvOpcode::vfmin_vf : RiscvOpcode::vfmin_vv; flags = true; break;
    case 0x06: op = scalar ? RiscvOpcode::vfmax_vf : RiscvOpcode::vfmax_vv; flags = true; break;
    case 0x18: op = scalar ? RiscvOpcode::vmfeq_vf : RiscvOpcode::vmfeq_vv; flags = true; break;
    case 0x1c: op = scalar ? RiscvOpcode::vmfne_vf : RiscvOpcode::vmfne_vv; flags = true; break;
    case 0x1b: op = scalar ? RiscvOpcode::vmflt_vf : RiscvOpcode::vmflt_vv; flags = true; break;
    case 0x19: op = scalar ? RiscvOpcode::vmfle_vf : RiscvOpcode::vmfle_vv; flags = true; break;
    case 0x1d: if (!scalar) return false; op = RiscvOpcode::vmfgt_vf; flags = true; break;
    case 0x1f: if (!scalar) return false; op = RiscvOpcode::vmfge_vf; flags = true; break;
    default: return false;
    }
    i.opcode = op;
    i.writes_fflags = flags;
    i.reads_frm = uses_rounding;
    i.reads_fflags = flags;
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vd), false, true}, RiscvOperandAccess::write);
    read_vector_destination(i, vd);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs2), false, true}, RiscvOperandAccess::read);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs1), scalar, !scalar}, RiscvOperandAccess::read);
    if (!vm) i.register_reads.push_back(RiscvRegister{0, false, true});
    i.vector_masked = !vm;
    return true;
}

bool decode_vector_multiply(std::uint32_t w, RiscvInstruction &i) {
    const unsigned funct6 = w >> 26, vm = (w >> 25) & 1;
    const unsigned vs2 = (w >> 20) & 31, vs1 = (w >> 15) & 31;
    const unsigned funct3 = (w >> 12) & 7, vd = (w >> 7) & 31;
    if (funct3 != 2 && funct3 != 6)
        return false; // The single-width multiply family has VV and VX forms only.
    const bool scalar = funct3 == 6;
    RiscvOpcode op;
    switch (funct6) {
    case 0x25: op = scalar ? RiscvOpcode::vmul_vx : RiscvOpcode::vmul_vv; break;
    case 0x27: op = scalar ? RiscvOpcode::vmulh_vx : RiscvOpcode::vmulh_vv; break;
    case 0x24: op = scalar ? RiscvOpcode::vmulhu_vx : RiscvOpcode::vmulhu_vv; break;
    case 0x26: op = scalar ? RiscvOpcode::vmulhsu_vx : RiscvOpcode::vmulhsu_vv; break;
    default: return false;
    }
    i.opcode = op;
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vd), false, true}, RiscvOperandAccess::write);
    read_vector_destination(i, vd);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs2), false, true}, RiscvOperandAccess::read);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs1), false, !scalar}, RiscvOperandAccess::read);
    if (!vm)
        i.register_reads.push_back(RiscvRegister{0, false, true});
    i.vector_masked = !vm;
    return true;
}

bool decode_vector_multiply_add(std::uint32_t w, RiscvInstruction &i) {
    const unsigned funct6 = w >> 26, vm = (w >> 25) & 1;
    const unsigned vs2 = (w >> 20) & 31, vs1 = (w >> 15) & 31;
    const unsigned funct3 = (w >> 12) & 7, vd = (w >> 7) & 31;
    if (funct3 != 2 && funct3 != 6)
        return false; // RVV 1.0 provides only OPMVV and OPMVX multiply-add forms.
    const bool scalar = funct3 == 6;
    RiscvOpcode op;
    switch (funct6) {
    case 0x2d: op = scalar ? RiscvOpcode::vmacc_vx : RiscvOpcode::vmacc_vv; break;
    case 0x2f: op = scalar ? RiscvOpcode::vnmsac_vx : RiscvOpcode::vnmsac_vv; break;
    case 0x29: op = scalar ? RiscvOpcode::vmadd_vx : RiscvOpcode::vmadd_vv; break;
    case 0x2b: op = scalar ? RiscvOpcode::vnmsub_vx : RiscvOpcode::vnmsub_vv; break;
    case 0x3c: op = scalar ? RiscvOpcode::vwmaccu_vx : RiscvOpcode::vwmaccu_vv; break;
    case 0x3d: op = scalar ? RiscvOpcode::vwmacc_vx : RiscvOpcode::vwmacc_vv; break;
    case 0x3e: if (!scalar) return false; op = RiscvOpcode::vwmaccus_vx; break;
    case 0x3f: op = scalar ? RiscvOpcode::vwmaccsu_vx : RiscvOpcode::vwmaccsu_vv; break;
    default: return false;
    }
    // Widening destinations use EMUL = 2*LMUL. This stateless decoder does
    // not know vtype, so it cannot validate EMUL <= 8 or destination group
    // alignment and overlap with source groups. The lane evaluator checks
    // EMUL; physical register-group validation remains outside this API.
    i.opcode = op;
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vd), false, true}, RiscvOperandAccess::write);
    read_vector_destination(i, vd);
    // Unlike the other binary integer operations, the architectural assembly
    // syntax orders rs1/vs1 before vs2 for this three-source family.
    if (scalar)
        operand(i, RiscvRegister{static_cast<std::uint8_t>(vs1)}, RiscvOperandAccess::read);
    else
        operand(i, RiscvRegister{static_cast<std::uint8_t>(vs1), false, true}, RiscvOperandAccess::read);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs2), false, true}, RiscvOperandAccess::read);
    if (!vm)
        i.register_reads.push_back(RiscvRegister{0, false, true});
    i.vector_masked = !vm;
    return true;
}

bool decode_vector_widening_multiply(std::uint32_t w, RiscvInstruction &i) {
    const unsigned funct6 = w >> 26, vm = (w >> 25) & 1;
    const unsigned vs2 = (w >> 20) & 31, vs1 = (w >> 15) & 31;
    const unsigned funct3 = (w >> 12) & 7, vd = (w >> 7) & 31;
    if ((funct6 < 0x38 || funct6 > 0x3b) || (funct3 != 2 && funct3 != 6))
        return false;
    const bool scalar = funct3 == 6;
    static constexpr RiscvOpcode vv_ops[]{RiscvOpcode::vwmulu_vv, RiscvOpcode::vwmulsu_vv,
                                          RiscvOpcode::vwmul_vv, RiscvOpcode::vwmul_vv};
    static constexpr RiscvOpcode vx_ops[]{RiscvOpcode::vwmulu_vx, RiscvOpcode::vwmulsu_vx,
                                          RiscvOpcode::vwmul_vx, RiscvOpcode::vwmul_vx};
    i.opcode = scalar ? vx_ops[funct6 - 0x38] : vv_ops[funct6 - 0x38];
    // The final funct6 value is vwmul (0x3b); 0x39 is reserved.
    if (funct6 == 0x39) return false;
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vd), false, true}, RiscvOperandAccess::write);
    read_vector_destination(i, vd);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs2), false, true}, RiscvOperandAccess::read);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs1), false, !scalar}, RiscvOperandAccess::read);
    if (!vm) i.register_reads.push_back(RiscvRegister{0, false, true});
    i.vector_masked = !vm;
    return true;
}

bool decode_vector_widening_add_sub(std::uint32_t w, RiscvInstruction &i) {
    const unsigned funct6 = w >> 26, vm = (w >> 25) & 1;
    const unsigned vs2 = (w >> 20) & 31, vs1 = (w >> 15) & 31;
    const unsigned funct3 = (w >> 12) & 7, vd = (w >> 7) & 31;
    if (funct3 != 2 && funct3 != 6) return false;
    const bool scalar = funct3 == 6;
    static constexpr RiscvOpcode vv_ops[]{RiscvOpcode::vwaddu_vv, RiscvOpcode::vwadd_vv,
        RiscvOpcode::vwsubu_vv, RiscvOpcode::vwsub_vv, RiscvOpcode::vwaddu_wv,
        RiscvOpcode::vwadd_wv, RiscvOpcode::vwsubu_wv, RiscvOpcode::vwsub_wv};
    static constexpr RiscvOpcode vx_ops[]{RiscvOpcode::vwaddu_vx, RiscvOpcode::vwadd_vx,
        RiscvOpcode::vwsubu_vx, RiscvOpcode::vwsub_vx, RiscvOpcode::vwaddu_wx,
        RiscvOpcode::vwadd_wx, RiscvOpcode::vwsubu_wx, RiscvOpcode::vwsub_wx};
    if (funct6 < 0x30 || funct6 > 0x37) return false;
    i.opcode = scalar ? vx_ops[funct6 - 0x30] : vv_ops[funct6 - 0x30];
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vd), false, true}, RiscvOperandAccess::write);
    read_vector_destination(i, vd);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs2), false, true}, RiscvOperandAccess::read);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs1), false, !scalar}, RiscvOperandAccess::read);
    if (!vm) i.register_reads.push_back(RiscvRegister{0, false, true});
    i.vector_masked = !vm;
    return true;
}

bool decode_vector_divide(std::uint32_t w, RiscvInstruction &i) {
    const unsigned funct6 = w >> 26, vm = (w >> 25) & 1;
    const unsigned vs2 = (w >> 20) & 31, vs1 = (w >> 15) & 31;
    const unsigned funct3 = (w >> 12) & 7, vd = (w >> 7) & 31;
    if (funct6 < 0x20 || funct6 > 0x23 || (funct3 != 2 && funct3 != 6)) return false;
    const bool scalar = funct3 == 6;
    static constexpr RiscvOpcode vector_ops[]{
        RiscvOpcode::vdivu_vv, RiscvOpcode::vdiv_vv, RiscvOpcode::vremu_vv, RiscvOpcode::vrem_vv};
    static constexpr RiscvOpcode scalar_ops[]{
        RiscvOpcode::vdivu_vx, RiscvOpcode::vdiv_vx, RiscvOpcode::vremu_vx, RiscvOpcode::vrem_vx};
    i.opcode = scalar ? scalar_ops[funct6 - 0x20] : vector_ops[funct6 - 0x20];
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vd), false, true}, RiscvOperandAccess::write);
    read_vector_destination(i, vd);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs2), false, true}, RiscvOperandAccess::read);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs1), false, !scalar}, RiscvOperandAccess::read);
    if (!vm) i.register_reads.push_back(RiscvRegister{0, false, true});
    i.vector_masked = !vm;
    return true;
}

bool decode_vector_permutation(std::uint32_t w, RiscvInstruction &i) {
    const unsigned funct6 = w >> 26, vm = (w >> 25) & 1;
    const unsigned vs2 = (w >> 20) & 31, vs1 = (w >> 15) & 31;
    const unsigned funct3 = (w >> 12) & 7, vd = (w >> 7) & 31;
    const unsigned form = funct3 == 0 ? 0 : funct3 == 4 ? 1 : funct3 == 3 ? 2 : 3;
    if (form > 2) return false;

    RiscvOpcode op;
    if (funct6 == 0x0c) {
        op = form == 0 ? RiscvOpcode::vrgather_vv
             : form == 1 ? RiscvOpcode::vrgather_vx
                         : RiscvOpcode::vrgather_vi;
    } else if (funct6 == 0x0e || funct6 == 0x0f) {
        if (form == 0) return false; // Slide offsets are scalar or immediate.
        if (funct6 == 0x0e)
            op = form == 1 ? RiscvOpcode::vslideup_vx : RiscvOpcode::vslideup_vi;
        else
            op = form == 1 ? RiscvOpcode::vslidedown_vx : RiscvOpcode::vslidedown_vi;
    } else {
        return false;
    }

    i.opcode = op;
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vd), false, true}, RiscvOperandAccess::write);
    read_vector_destination(i, vd);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(vs2), false, true}, RiscvOperandAccess::read);
    if (form == 0)
        operand(i, RiscvRegister{static_cast<std::uint8_t>(vs1), false, true}, RiscvOperandAccess::read);
    else if (form == 1)
        operand(i, RiscvRegister{static_cast<std::uint8_t>(vs1)}, RiscvOperandAccess::read);
    else
        // Gather/slide offsets are unsigned and zero-extended, unlike the
        // sign-extended immediates used by ordinary OPIVI arithmetic.
        operand(i, RiscvImmediate{static_cast<std::int64_t>(vs1), 5, false}, RiscvOperandAccess::read);
    if (!vm) i.register_reads.push_back(RiscvRegister{0, false, true});
    i.vector_masked = !vm;
    return true;
}

bool decode_vector_memory(std::uint32_t w, RiscvInstruction &i, bool store) {
    const unsigned width_code = (w >> 12) & 7;
    const unsigned width = width_code == 0 ? 8 : width_code == 5 ? 16 :
                           width_code == 6 ? 32 : width_code == 7 ? 64 : 0;
    const unsigned mop = (w >> 26) & 3;
    // Single-field integer unit-stride, strided, and indexed accesses only.
    // Keep segmented, fault-only-first, whole-register, and mask forms opaque.
    if (!width || (w >> 29) != 0 || ((w >> 28) & 1) != 0 ||
        (mop == 0 && ((w >> 20) & 0x1f) != 0))
        return false;
    const unsigned vd_vs3 = (w >> 7) & 31, base = (w >> 15) & 31;
    const unsigned stride = (w >> 20) & 31;
    const bool unmasked = ((w >> 25) & 1) != 0;
    i.vector_masked = !unmasked;
    if (mop == 0)
        i.opcode = store ? RiscvOpcode::vse : RiscvOpcode::vle;
    else if (mop == 1)
        i.opcode = store ? RiscvOpcode::vsuxei : RiscvOpcode::vluxei;
    else if (mop == 2)
        i.opcode = store ? RiscvOpcode::vsse : RiscvOpcode::vlse;
    else
        i.opcode = store ? RiscvOpcode::vsoxei : RiscvOpcode::vloxei;
    if (store)
        operand(i, RiscvRegister{static_cast<std::uint8_t>(vd_vs3), false, true}, RiscvOperandAccess::read);
    else {
        operand(i, RiscvRegister{static_cast<std::uint8_t>(vd_vs3), false, true}, RiscvOperandAccess::write);
        read_vector_destination(i, vd_vs3);
    }
    operand(i, RiscvMemory{RiscvRegister{static_cast<std::uint8_t>(base)}, 0,
                           static_cast<std::uint8_t>(width), false},
            store ? RiscvOperandAccess::write : RiscvOperandAccess::read);
    read_register(i, base);
    if (mop == 1 || mop == 3)
        operand(i, RiscvRegister{static_cast<std::uint8_t>(stride), false, true}, RiscvOperandAccess::read);
    else if (mop == 2)
        operand(i, RiscvRegister{static_cast<std::uint8_t>(stride)}, RiscvOperandAccess::read);
    if (!unmasked)
        i.register_reads.push_back(RiscvRegister{0, false, true});
    i.memory_read = !store;
    i.memory_write = store;
    return true;
}

void operand(RiscvInstruction &instruction, RiscvOperand value, RiscvOperandAccess access) {
    if (const auto *reg = std::get_if<RiscvRegister>(&value)) {
        if ((access == RiscvOperandAccess::read || access == RiscvOperandAccess::read_write) &&
            (reg->floating_point || reg->vector || reg->index != 0))
            instruction.register_reads.push_back(*reg);
        if ((access == RiscvOperandAccess::write || access == RiscvOperandAccess::read_write) &&
            (reg->floating_point || reg->vector || reg->index != 0))
            instruction.register_writes.push_back(*reg);
    }
    instruction.operands.push_back(std::move(value));
    instruction.access.push_back(access);
}

void read_register(RiscvInstruction &instruction, unsigned index) {
    if (index != 0)
        instruction.register_reads.push_back({static_cast<std::uint8_t>(index)});
}

void read_vector_configuration(RiscvInstruction &instruction) {
    instruction.register_reads.push_back({0, false, false, true}); // vl
    instruction.register_reads.push_back({1, false, false, true}); // vtype
    instruction.register_reads.push_back({2, false, false, true}); // vstart
    instruction.register_writes.push_back({2, false, false, true}); // successful completion resets vstart.
}

void relative_operand(RiscvInstruction &instruction, std::int64_t displacement, unsigned width) {
    const auto target = add_target(instruction.address, displacement);
    operand(instruction, RiscvRelative{displacement, static_cast<std::uint8_t>(width), target},
            RiscvOperandAccess::read);
    instruction.direct_target = target;
}

void set_rr(RiscvInstruction &i, RiscvOpcode op, unsigned rd, unsigned rs1, unsigned rs2) {
    i.opcode = op;
    operand(i, RiscvRegister{static_cast<std::uint8_t>(rd)}, RiscvOperandAccess::write);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(rs1)}, RiscvOperandAccess::read);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(rs2)}, RiscvOperandAccess::read);
}

void set_ri(RiscvInstruction &i, RiscvOpcode op, unsigned rd, unsigned rs1, std::int64_t immediate,
            unsigned encoded_width, bool is_signed = true) {
    i.opcode = op;
    operand(i, RiscvRegister{static_cast<std::uint8_t>(rd)}, RiscvOperandAccess::write);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(rs1)}, RiscvOperandAccess::read);
    operand(i, RiscvImmediate{immediate, static_cast<std::uint8_t>(encoded_width), is_signed},
            RiscvOperandAccess::read);
}

bool decode_op(std::uint32_t w, RiscvInstruction &i, bool word_form, unsigned xlen) {
    const unsigned rd = (w >> 7) & 31, f3 = (w >> 12) & 7, rs1 = (w >> 15) & 31, rs2 = (w >> 20) & 31;
    const unsigned f7 = w >> 25;
    const bool m_extension = f7 == 1;
    const bool word = word_form;
    if (!word && f7 == 0x10 && (f3 == 2 || f3 == 4 || f3 == 6)) {
        const auto op = f3 == 2 ? RiscvOpcode::sh1add : f3 == 4 ? RiscvOpcode::sh2add : RiscvOpcode::sh3add;
        set_rr(i, op, rd, rs1, rs2);
        return true;
    }
    if (xlen == 64) {
        if (word && f7 == 0x04 && f3 == 0) {
            set_rr(i, RiscvOpcode::add_uw, rd, rs1, rs2);
            return true;
        }
        if (word && f7 == 0x10 && (f3 == 2 || f3 == 4 || f3 == 6)) {
            const auto op = f3 == 2 ? RiscvOpcode::sh1add_uw : f3 == 4 ? RiscvOpcode::sh2add_uw : RiscvOpcode::sh3add_uw;
            set_rr(i, op, rd, rs1, rs2);
            return true;
        }
    }
    // Zbb count operations use the unary OP encoding with rs2=0. Reject
    // nonzero rs2 here instead of interpreting reserved encodings as aliases.
    if (f7 == 0x30 && rs2 == 0 && f3 >= 1 && f3 <= 3) {
        if (word && xlen != 64)
            return false;
        const auto base = word ? 3u : 0u;
        i.opcode = static_cast<RiscvOpcode>(static_cast<unsigned>(RiscvOpcode::clz) + base + f3 - 1);
        operand(i, RiscvRegister{static_cast<std::uint8_t>(rd)}, RiscvOperandAccess::write);
        operand(i, RiscvRegister{static_cast<std::uint8_t>(rs1)}, RiscvOperandAccess::read);
        return true;
    }
    if (m_extension) {
        if (word && xlen != 64)
            return false;
        if (!word) {
            static constexpr std::array<RiscvOpcode, 8> ops{
                RiscvOpcode::mul, RiscvOpcode::mulh, RiscvOpcode::mulhsu, RiscvOpcode::mulhu,
                RiscvOpcode::div, RiscvOpcode::divu, RiscvOpcode::rem, RiscvOpcode::remu};
            set_rr(i, ops[f3], rd, rs1, rs2);
            return true;
        }
        if (f3 == 0 || f3 >= 4) {
            const auto op = f3 == 0 ? RiscvOpcode::mulw : f3 == 4 ? RiscvOpcode::divw
                             : f3 == 5 ? RiscvOpcode::divuw : f3 == 6 ? RiscvOpcode::remw : RiscvOpcode::remuw;
            set_rr(i, op, rd, rs1, rs2);
            return true;
        }
        return false;
    }

    if (!word) {
        if (f7 == 0) {
            static constexpr std::array<RiscvOpcode, 8> ops{
                RiscvOpcode::add, RiscvOpcode::sll, RiscvOpcode::slt, RiscvOpcode::sltu,
                RiscvOpcode::bit_xor, RiscvOpcode::srl, RiscvOpcode::bit_or, RiscvOpcode::bit_and};
            set_rr(i, ops[f3], rd, rs1, rs2);
            return true;
        }
        if (f7 == 0x20 && (f3 == 0 || f3 == 5)) {
            set_rr(i, f3 == 0 ? RiscvOpcode::sub : RiscvOpcode::sra, rd, rs1, rs2);
            return true;
        }
        return false;
    }

    if (f3 == 0 && (f7 == 0 || f7 == 0x20)) {
        set_rr(i, f7 == 0 ? RiscvOpcode::addw : RiscvOpcode::subw, rd, rs1, rs2);
        return true;
    }
    if (f7 == 0 && f3 == 1) {
        set_rr(i, RiscvOpcode::sllw, rd, rs1, rs2);
        return true;
    }
    if ((f7 == 0 || f7 == 0x20) && f3 == 5) {
        set_rr(i, f7 == 0 ? RiscvOpcode::srlw : RiscvOpcode::sraw, rd, rs1, rs2);
        return true;
    }
    return false;
}

bool decode_op_imm(std::uint32_t w, RiscvInstruction &i, bool word_form, unsigned xlen) {
    const unsigned rd = (w >> 7) & 31, f3 = (w >> 12) & 7, rs1 = (w >> 15) & 31;
    const unsigned low = (w >> 20) & (word_form || xlen == 32 ? 31 : 63);
    const unsigned upper = w >> (word_form || xlen == 32 ? 25 : 26);
    const auto imm = sign_extend(w >> 20, 12);
    if (word_form && xlen != 64)
        return false;
    if (word_form && xlen == 64 && f3 == 1 && (w & 0xfc00707fu) == 0x0800101bu) {
        const unsigned shift = (w >> 20) & 63;
        set_ri(i, RiscvOpcode::slli_uw, rd, rs1, shift, 6, false);
        return true;
    }
    if (word_form) {
        if (f3 == 0) {
            set_ri(i, RiscvOpcode::addiw, rd, rs1, imm, 12);
            return true;
        }
        if (f3 == 1 && (w >> 25) == 0) {
            set_ri(i, RiscvOpcode::slliw, rd, rs1, low, 5, false);
            return true;
        }
        if (f3 == 5 && ((w >> 25) == 0 || (w >> 25) == 0x20)) {
            set_ri(i, (w >> 25) == 0 ? RiscvOpcode::srliw : RiscvOpcode::sraiw, rd, rs1, low, 5, false);
            return true;
        }
        return false;
    }
    switch (f3) {
    case 0: set_ri(i, RiscvOpcode::addi, rd, rs1, imm, 12); return true;
    case 2: set_ri(i, RiscvOpcode::slti, rd, rs1, imm, 12); return true;
    case 3: set_ri(i, RiscvOpcode::sltiu, rd, rs1, imm, 12); return true;
    case 4: set_ri(i, RiscvOpcode::bit_xor, rd, rs1, imm, 12); return true;
    case 6: set_ri(i, RiscvOpcode::bit_or, rd, rs1, imm, 12); return true;
    case 7: set_ri(i, RiscvOpcode::bit_and, rd, rs1, imm, 12); return true;
    case 1:
        if (upper != 0)
            return false;
        set_ri(i, RiscvOpcode::slli, rd, rs1, low, 6, false);
        return true;
    case 5:
        if (upper != 0 && upper != (xlen == 32 ? 0x20u : 0x10u))
            return false;
        set_ri(i, upper == 0 ? RiscvOpcode::srli : RiscvOpcode::srai, rd, rs1, low,
               xlen == 32 ? 5 : 6, false);
        return true;
    }
    return false;
}

bool decode_load(std::uint32_t w, RiscvInstruction &i, unsigned xlen) {
    const unsigned f3 = (w >> 12) & 7;
    static constexpr std::array<RiscvOpcode, 7> ops{RiscvOpcode::lb, RiscvOpcode::lh, RiscvOpcode::lw, RiscvOpcode::ld,
                                                    RiscvOpcode::lbu, RiscvOpcode::lhu, RiscvOpcode::lwu};
    static constexpr std::array<std::uint8_t, 7> widths{8, 16, 32, 64, 8, 16, 32};
    if (f3 >= ops.size() || (xlen == 32 && (f3 == 3 || f3 == 6)))
        return false;
    const unsigned rd = (w >> 7) & 31, rs1 = (w >> 15) & 31;
    const auto displacement = sign_extend(w >> 20, 12);
    i.opcode = ops[f3];
    operand(i, RiscvRegister{static_cast<std::uint8_t>(rd)}, RiscvOperandAccess::write);
    operand(i, RiscvMemory{RiscvRegister{static_cast<std::uint8_t>(rs1)}, displacement, widths[f3], f3 <= 2},
            RiscvOperandAccess::read);
    read_register(i, rs1);
    i.memory_read = true;
    return true;
}

bool decode_store(std::uint32_t w, RiscvInstruction &i, unsigned xlen) {
    const unsigned f3 = (w >> 12) & 7;
    if (f3 > (xlen == 32 ? 2u : 3u))
        return false;
    static constexpr std::array<RiscvOpcode, 4> ops{RiscvOpcode::sb, RiscvOpcode::sh, RiscvOpcode::sw, RiscvOpcode::sd};
    static constexpr std::array<std::uint8_t, 4> widths{8, 16, 32, 64};
    const unsigned rs1 = (w >> 15) & 31, rs2 = (w >> 20) & 31;
    const auto bits = ((w >> 25) << 5) | ((w >> 7) & 31);
    i.opcode = ops[f3];
    operand(i, RiscvRegister{static_cast<std::uint8_t>(rs2)}, RiscvOperandAccess::read);
    operand(i, RiscvMemory{RiscvRegister{static_cast<std::uint8_t>(rs1)}, sign_extend(bits, 12), widths[f3], false},
            RiscvOperandAccess::write);
    read_register(i, rs1);
    i.memory_write = true;
    return true;
}

bool decode_fp_load(std::uint32_t w, RiscvInstruction &i) {
    const unsigned f3 = (w >> 12) & 7, rd = (w >> 7) & 31, rs1 = (w >> 15) & 31;
    const unsigned width = f3 == 2 ? 32 : f3 == 3 ? 64 : 0;
    if (!width)
        return false;
    i.opcode = width == 32 ? RiscvOpcode::flw : RiscvOpcode::fld;
    operand(i, RiscvRegister{static_cast<std::uint8_t>(rd), true}, RiscvOperandAccess::write);
    operand(i, RiscvMemory{RiscvRegister{static_cast<std::uint8_t>(rs1)}, sign_extend(w >> 20, 12),
                           static_cast<std::uint8_t>(width), false}, RiscvOperandAccess::read);
    read_register(i, rs1);
    i.memory_read = true;
    return true;
}

bool decode_fp_store(std::uint32_t w, RiscvInstruction &i) {
    const unsigned f3 = (w >> 12) & 7, rs1 = (w >> 15) & 31, rs2 = (w >> 20) & 31;
    const unsigned width = f3 == 2 ? 32 : f3 == 3 ? 64 : 0;
    if (!width)
        return false;
    const auto immediate = ((w >> 25) << 5) | ((w >> 7) & 31);
    i.opcode = width == 32 ? RiscvOpcode::fsw : RiscvOpcode::fsd;
    operand(i, RiscvRegister{static_cast<std::uint8_t>(rs2), true}, RiscvOperandAccess::read);
    operand(i, RiscvMemory{RiscvRegister{static_cast<std::uint8_t>(rs1)}, sign_extend(immediate, 12),
                           static_cast<std::uint8_t>(width), false}, RiscvOperandAccess::write);
    read_register(i, rs1);
    i.memory_write = true;
    return true;
}

bool decode_fp_op(std::uint32_t w, RiscvInstruction &i, unsigned xlen) {
    const unsigned major = w & 0x7f, rd = (w >> 7) & 31, f3 = (w >> 12) & 7;
    const unsigned rs1 = (w >> 15) & 31, rs2 = (w >> 20) & 31, rs3 = (w >> 27) & 31;
    const unsigned fmt = (w >> 25) & 3, f7 = (w >> 25) & 0x7f;
    if (major != 0x53 && major != 0x43 && major != 0x47 && major != 0x4b && major != 0x4f) return false;
    if (fmt == 2) return false; // Q is recognized but outside this F/D slice.
    if (fmt == 3) return false;
    const bool d = fmt == 1;
    auto set = [&](RiscvOpcode op, bool flags, bool rm, bool uses_rounding = true) {
        if (rm && (f3 == 5 || f3 == 6)) return false;
        i.opcode = op;
        i.writes_fflags = flags;
        // Exception flags accrue by OR into FCSR, rather than replacing the
        // previous flags. Only dynamic rounding observes the frm field.
        i.reads_fflags = flags;
        i.reads_frm = rm && uses_rounding && f3 == 7;
        if (rm) i.rounding_mode = static_cast<std::uint8_t>(f3);
        return true;
    };
    auto fp_rd = [&] { operand(i, RiscvRegister{static_cast<std::uint8_t>(rd), true}, RiscvOperandAccess::write); };
    auto fp_rs1 = [&] { operand(i, RiscvRegister{static_cast<std::uint8_t>(rs1), true}, RiscvOperandAccess::read); };
    auto fp_rs2 = [&] { operand(i, RiscvRegister{static_cast<std::uint8_t>(rs2), true}, RiscvOperandAccess::read); };
    auto gpr_rd = [&] { operand(i, RiscvRegister{static_cast<std::uint8_t>(rd)}, RiscvOperandAccess::write); };
    auto gpr_rs1 = [&] { operand(i, RiscvRegister{static_cast<std::uint8_t>(rs1)}, RiscvOperandAccess::read); };
    if (major != 0x53) {
        if (fmt > 1) return false;
        static constexpr RiscvOpcode s_ops[]{RiscvOpcode::fmadd_s,RiscvOpcode::fmsub_s,RiscvOpcode::fnmsub_s,RiscvOpcode::fnmadd_s};
        static constexpr RiscvOpcode d_ops[]{RiscvOpcode::fmadd_d,RiscvOpcode::fmsub_d,RiscvOpcode::fnmsub_d,RiscvOpcode::fnmadd_d};
        if (!set(d ? d_ops[(major >> 2) & 3] : s_ops[(major >> 2) & 3], true, true)) return false;
        fp_rd(); fp_rs1(); fp_rs2(); operand(i,RiscvRegister{static_cast<std::uint8_t>(rs3),true},RiscvOperandAccess::read); return true;
    }
    const unsigned operation = f7 & ~1u;
    const auto s = [&](RiscvOpcode op) { return set(op, true, true); };
    const auto plain = [&](RiscvOpcode op, bool flags=false) { return set(op, flags, false); };
    bool ok = false, dst_fp = true, src1_fp = true, src2_fp = true, unary = false;
    if (operation == 0x00) { ok=s(d?RiscvOpcode::fadd_d:RiscvOpcode::fadd_s); }
    else if (operation == 0x04) { ok=s(d?RiscvOpcode::fsub_d:RiscvOpcode::fsub_s); }
    else if (operation == 0x08) { ok=s(d?RiscvOpcode::fmul_d:RiscvOpcode::fmul_s); }
    else if (operation == 0x0c) { ok=s(d?RiscvOpcode::fdiv_d:RiscvOpcode::fdiv_s); }
    else if (operation == 0x2c && rs2==0) { ok=s(d?RiscvOpcode::fsqrt_d:RiscvOpcode::fsqrt_s); unary=true; }
    else if (operation == 0x10) { static constexpr RiscvOpcode ops[2][3]{{RiscvOpcode::fsgnj_s,RiscvOpcode::fsgnjn_s,RiscvOpcode::fsgnjx_s},{RiscvOpcode::fsgnj_d,RiscvOpcode::fsgnjn_d,RiscvOpcode::fsgnjx_d}}; if(f3<3) ok=plain(ops[d][f3]); }
    else if (operation == 0x14) {
        if(f3<2) ok=plain(d?(f3?RiscvOpcode::fmax_d:RiscvOpcode::fmin_d):(f3?RiscvOpcode::fmax_s:RiscvOpcode::fmin_s),true);
        else if(f3<4) ok=plain(d?(f3==3?RiscvOpcode::fmaxm_d:RiscvOpcode::fminm_d):(f3==3?RiscvOpcode::fmaxm_s:RiscvOpcode::fminm_s),true);
    }
    else if (operation == 0x50) {
        if (f3 >= 1 && f3 <= 2) {
            ok=plain(d?(f3==2?RiscvOpcode::feq_d:RiscvOpcode::flt_d):(f3==2?RiscvOpcode::feq_s:RiscvOpcode::flt_s),true);
            dst_fp=false; src1_fp=src2_fp=true;
        } else if (f3 == 0) { ok=plain(d?RiscvOpcode::fle_d:RiscvOpcode::fle_s,true); dst_fp=false; }
        else if (f3 == 4 || f3 == 5) {
            // Zfa FLEQ/FLTQ are bit-14 variants of FLE/FLT. Quiet NaNs do
            // not raise NV, but signaling NaNs still can.
            ok=plain(d?(f3==4?RiscvOpcode::fleq_d:RiscvOpcode::fltq_d)
                       :(f3==4?RiscvOpcode::fleq_s:RiscvOpcode::fltq_s),true);
            dst_fp=false;
        }
    }
    else if (operation == 0x60 && d && rs2 == 8 && f3 == 1) {
        ok = set(RiscvOpcode::fcvtmod_w_d, true, true, false);
        dst_fp = false; unary = true;
    }
    else if (operation == 0x70 && rs2==0 && (f3==0 || f3==1) && (!d || f3==1 || xlen==64)) { ok=plain(d?(f3?RiscvOpcode::fclass_d:RiscvOpcode::fmv_x_d):(f3?RiscvOpcode::fclass_s:RiscvOpcode::fmv_x_w)); dst_fp=false; unary=true; }
    else if (operation == 0x78 && rs2 == 1 && f3 == 0) {
        // Zfa FLI uses the FMV.W.X encoding with rs2=1; rs1 is a five-bit
        // constant selector, not an integer-register source.
        i.opcode = d ? RiscvOpcode::fli_d : RiscvOpcode::fli_s;
        operand(i, RiscvRegister{static_cast<std::uint8_t>(rd), true}, RiscvOperandAccess::write);
        operand(i, RiscvImmediate{static_cast<std::int64_t>(rs1), 5, false}, RiscvOperandAccess::read);
        return true;
    }
    else if (operation == 0x78 && rs2==0 && f3==0 && (!d || xlen==64)) { ok=plain(d?RiscvOpcode::fmv_d_x:RiscvOpcode::fmv_w_x); src1_fp=false; unary=true; }
    else if ((operation==0x60 || operation==0x68) && rs2<=3 && (rs2<2 || xlen==64)) {
        const bool to_int=operation==0x60; static constexpr RiscvOpcode tos[2][4]{{RiscvOpcode::fcvt_w_s,RiscvOpcode::fcvt_wu_s,RiscvOpcode::fcvt_l_s,RiscvOpcode::fcvt_lu_s},{RiscvOpcode::fcvt_w_d,RiscvOpcode::fcvt_wu_d,RiscvOpcode::fcvt_l_d,RiscvOpcode::fcvt_lu_d}};
        static constexpr RiscvOpcode froms[2][4]{{RiscvOpcode::fcvt_s_w,RiscvOpcode::fcvt_s_wu,RiscvOpcode::fcvt_s_l,RiscvOpcode::fcvt_s_lu},{RiscvOpcode::fcvt_d_w,RiscvOpcode::fcvt_d_wu,RiscvOpcode::fcvt_d_l,RiscvOpcode::fcvt_d_lu}};
        // Every 32-bit integer is represented exactly by binary64. These two
        // forms cannot raise exceptions, although rm is decoded as usual.
        const bool exact = !to_int && d && rs2 < 2;
        ok=set(to_int?tos[d][rs2]:froms[d][rs2],!exact,true,!exact); dst_fp=!to_int; src1_fp=to_int; unary=true;
    }
    else if (operation==0x20 && rs2==((f7 & 1) ? 0u : 1u)) {
        const bool to_double = (f7 & 1) != 0;
        ok=set(to_double ? RiscvOpcode::fcvt_d_s : RiscvOpcode::fcvt_s_d, true, true, !to_double);
    }
    else if (operation == 0x20 && (rs2 == 4 || rs2 == 5)) {
        const bool exact = rs2 == 5;
        ok = set(d ? (exact ? RiscvOpcode::froundnx_d : RiscvOpcode::fround_d)
                   : (exact ? RiscvOpcode::froundnx_s : RiscvOpcode::fround_s), true, true);
        unary = true;
    }
    if (!ok) return false;
    if (dst_fp) fp_rd(); else gpr_rd();
    if (src1_fp) fp_rs1(); else gpr_rs1();
    if (!unary && operation!=0x20) { if(src2_fp) fp_rs2(); else operand(i,RiscvRegister{static_cast<std::uint8_t>(rs2)},RiscvOperandAccess::read); }
    return true;
}

bool decode_branch(std::uint32_t w, RiscvInstruction &i) {
    const unsigned f3 = (w >> 12) & 7;
    static constexpr std::array<RiscvOpcode, 8> ops{RiscvOpcode::beq, RiscvOpcode::bne, RiscvOpcode::beq,
                                                    RiscvOpcode::beq, RiscvOpcode::blt, RiscvOpcode::bge,
                                                    RiscvOpcode::bltu, RiscvOpcode::bgeu};
    if (f3 == 2 || f3 == 3)
        return false;
    const auto bits = (((w >> 31) & 1) << 12) | (((w >> 7) & 1) << 11) | (((w >> 25) & 0x3f) << 5) |
                      (((w >> 8) & 0xf) << 1);
    const unsigned rs1 = (w >> 15) & 31, rs2 = (w >> 20) & 31;
    i.opcode = ops[f3];
    i.flow = RiscvFlow::conditional_branch;
    operand(i, RiscvRegister{static_cast<std::uint8_t>(rs1)}, RiscvOperandAccess::read);
    operand(i, RiscvRegister{static_cast<std::uint8_t>(rs2)}, RiscvOperandAccess::read);
    relative_operand(i, sign_extend(bits, 13), 13);
    return true;
}

bool decode_system(std::uint32_t w, RiscvInstruction &i, std::string &reason) {
    const unsigned f3 = (w >> 12) & 7, rd = (w >> 7) & 31, rs1 = (w >> 15) & 31, imm = w >> 20;
    if (f3 != 0) {
        if (f3 == 4) // Reserved by the unprivileged ISA, even when Zicsr is enabled.
            return false;

        const bool immediate = f3 >= 5;
        const unsigned source = rs1;
        const unsigned csr = imm;
        bool csr_read = false, csr_write = false;
        switch (f3) {
        case 1: i.opcode = RiscvOpcode::csrrw; csr_read = rd != 0; csr_write = true; break;
        case 2: i.opcode = RiscvOpcode::csrrs; csr_read = true; csr_write = source != 0; break;
        case 3: i.opcode = RiscvOpcode::csrrc; csr_read = true; csr_write = source != 0; break;
        case 5: i.opcode = RiscvOpcode::csrrwi; csr_read = rd != 0; csr_write = true; break;
        case 6: i.opcode = RiscvOpcode::csrrsi; csr_read = true; csr_write = source != 0; break;
        case 7: i.opcode = RiscvOpcode::csrrci; csr_read = true; csr_write = source != 0; break;
        default: return false;
        }
        i.csr_read = csr_read;
        i.csr_write = csr_write;
        operand(i, RiscvRegister{static_cast<std::uint8_t>(rd)}, RiscvOperandAccess::write);
        operand(i, RiscvImmediate{static_cast<std::int64_t>(csr), 12, false},
                csr_read ? csr_write ? RiscvOperandAccess::read_write : RiscvOperandAccess::read
                         : RiscvOperandAccess::write);
        if (immediate)
            operand(i, RiscvImmediate{static_cast<std::int64_t>(source), 5, false}, RiscvOperandAccess::read);
        else
            operand(i, RiscvRegister{static_cast<std::uint8_t>(source)}, RiscvOperandAccess::read);
        return true;
    }
    if (rd || rs1)
        return false;
    if (imm == 0) {
        i.opcode = RiscvOpcode::ecall;
        i.flow = RiscvFlow::trap;
        return true;
    }
    if (imm == 1) {
        i.opcode = RiscvOpcode::ebreak;
        i.flow = RiscvFlow::trap;
        return true;
    }
    reason = "privileged SYSTEM instruction is outside the enabled unprivileged subset";
    return false;
}

bool decode_atomic(std::uint32_t w, RiscvInstruction &i, unsigned xlen) {
    const unsigned funct5 = (w >> 27) & 31, aq = (w >> 26) & 1, rl = (w >> 25) & 1;
    const unsigned rs2 = (w >> 20) & 31, rs1 = (w >> 15) & 31;
    const unsigned funct3 = (w >> 12) & 7, rd = (w >> 7) & 31;
    if ((funct3 != 2 && funct3 != 3) || (funct3 == 3 && xlen != 64) ||
        (funct5 == 0x02 && rs2 != 0))
        return false;

    const bool word_form = funct3 == 2;
    RiscvOpcode opcode;
    switch (funct5) {
    case 0x02: opcode = word_form ? RiscvOpcode::lr_w : RiscvOpcode::lr_d; break;
    case 0x03: opcode = word_form ? RiscvOpcode::sc_w : RiscvOpcode::sc_d; break;
    case 0x01: opcode = word_form ? RiscvOpcode::amoswap_w : RiscvOpcode::amoswap_d; break;
    case 0x00: opcode = word_form ? RiscvOpcode::amoadd_w : RiscvOpcode::amoadd_d; break;
    case 0x04: opcode = word_form ? RiscvOpcode::amoxor_w : RiscvOpcode::amoxor_d; break;
    case 0x0c: opcode = word_form ? RiscvOpcode::amoand_w : RiscvOpcode::amoand_d; break;
    case 0x08: opcode = word_form ? RiscvOpcode::amoor_w : RiscvOpcode::amoor_d; break;
    case 0x10: opcode = word_form ? RiscvOpcode::amomin_w : RiscvOpcode::amomin_d; break;
    case 0x14: opcode = word_form ? RiscvOpcode::amomax_w : RiscvOpcode::amomax_d; break;
    case 0x18: opcode = word_form ? RiscvOpcode::amominu_w : RiscvOpcode::amominu_d; break;
    case 0x1c: opcode = word_form ? RiscvOpcode::amomaxu_w : RiscvOpcode::amomaxu_d; break;
    default: return false;
    }

    i.opcode = opcode;
    i.atomic_aq = aq != 0;
    i.atomic_rl = rl != 0;
    operand(i, RiscvRegister{static_cast<std::uint8_t>(rd)}, RiscvOperandAccess::write);
    const bool load_reserved = funct5 == 0x02;
    const bool store_conditional = funct5 == 0x03;
    if (!load_reserved)
        operand(i, RiscvRegister{static_cast<std::uint8_t>(rs2)}, RiscvOperandAccess::read);
    const auto width = static_cast<std::uint8_t>(word_form ? 32 : 64);
    const RiscvMemory memory{RiscvRegister{static_cast<std::uint8_t>(rs1)}, 0, width,
                             word_form && !store_conditional};
    operand(i, memory, load_reserved ? RiscvOperandAccess::read
                                     : store_conditional ? RiscvOperandAccess::write
                                                         : RiscvOperandAccess::read_write);
    read_register(i, rs1);
    i.memory_read = load_reserved || (!store_conditional);
    i.memory_write = store_conditional || (!load_reserved);
    return true;
}

bool decode_word(std::uint32_t w, RiscvInstruction &i, std::string &unsupported, unsigned xlen) {
    const unsigned opcode = w & 0x7f, rd = (w >> 7) & 31, rs1 = (w >> 15) & 31;
    switch (opcode) {
    case 0x37: { // LUI: sign-extended 32-bit U-immediate.
        i.opcode = RiscvOpcode::lui;
        operand(i, RiscvRegister{static_cast<std::uint8_t>(rd)}, RiscvOperandAccess::write);
        const auto value = sign_extend(w & 0xfffff000u, 32);
        operand(i, RiscvImmediate{value, 20, true}, RiscvOperandAccess::read);
        return true;
    }
    case 0x17: { // AUIPC.
        i.opcode = RiscvOpcode::auipc;
        operand(i, RiscvRegister{static_cast<std::uint8_t>(rd)}, RiscvOperandAccess::write);
        const auto value = sign_extend(w & 0xfffff000u, 32);
        operand(i, RiscvImmediate{value, 20, true}, RiscvOperandAccess::read);
        return true;
    }
    case 0x6f: { // JAL.
        const auto bits = (((w >> 31) & 1) << 20) | (((w >> 12) & 0xff) << 12) | (((w >> 20) & 1) << 11) |
                          (((w >> 21) & 0x3ff) << 1);
        const auto displacement = sign_extend(bits, 21);
        i.opcode = RiscvOpcode::jal;
        const bool link = rd == 1 || rd == 5;
        i.flow = link ? RiscvFlow::call : RiscvFlow::jump;
        operand(i, RiscvRegister{static_cast<std::uint8_t>(rd)}, RiscvOperandAccess::write);
        relative_operand(i, displacement, 21);
        return true;
    }
    case 0x67: { // JALR; funct3 is reserved except zero.
        if (((w >> 12) & 7) != 0)
            return false;
        const auto displacement = sign_extend(w >> 20, 12);
        i.opcode = RiscvOpcode::jalr;
        i.flow = rd == 0 && (rs1 == 1 || rs1 == 5) && displacement == 0 ? RiscvFlow::ret
                 : rd == 1 || rd == 5                         ? RiscvFlow::call
                                                            : RiscvFlow::jump;
        operand(i, RiscvRegister{static_cast<std::uint8_t>(rd)}, RiscvOperandAccess::write);
        operand(i, RiscvMemory{RiscvRegister{static_cast<std::uint8_t>(rs1)}, displacement,
                               static_cast<std::uint8_t>(xlen), false},
                RiscvOperandAccess::address);
        read_register(i, rs1);
        return true;
    }
    case 0x63: return decode_branch(w, i);
    case 0x03: return decode_load(w, i, xlen);
    case 0x23: return decode_store(w, i, xlen);
    case 0x13: return decode_op_imm(w, i, false, xlen);
    case 0x1b: return xlen == 64 && decode_op_imm(w, i, true, xlen);
    case 0x33: return decode_op(w, i, false, xlen);
    case 0x3b: return xlen == 64 && decode_op(w, i, true, xlen);
    case 0x0f: {
        const unsigned f3 = (w >> 12) & 7;
        if (f3 == 1) {
            if (rd != 0 || rs1 != 0 || (w >> 20) != 0)
                return false;
            i.opcode = RiscvOpcode::fence_i;
            return true;
        }
        if (f3 != 0 || rd != 0 || rs1 != 0)
            return false;
        if ((w >> 28) != 0) {
            unsupported = "non-base FENCE ordering encoding is unsupported";
            return false;
        }
        i.opcode = RiscvOpcode::fence;
        operand(i, RiscvImmediate{static_cast<std::int64_t>((w >> 24) & 15), 4, false}, RiscvOperandAccess::read);
        operand(i, RiscvImmediate{static_cast<std::int64_t>((w >> 20) & 15), 4, false}, RiscvOperandAccess::read);
        return true;
    }
    case 0x73: return decode_system(w, i, unsupported);
    case 0x2f: return decode_atomic(w, i, xlen);
    case 0x07:
        if (decode_fp_load(w, i)) return true;
        if (decode_vector_memory(w, i, false)) { read_vector_configuration(i); return true; }
        return false;
    case 0x27:
        if (decode_fp_store(w, i)) return true;
        if (decode_vector_memory(w, i, true)) { read_vector_configuration(i); return true; }
        return false;
    case 0x43: case 0x47: case 0x4b: case 0x4f: case 0x53:
        if (((w >> 25) & 3) == 2) {
            unsupported = "quad-precision floating-point format is outside the enabled F/D subset";
            return false;
        }
        return decode_fp_op(w, i, xlen);
    case 0x57:
        if (((w >> 12) & 7) == 7 && decode_vector_configuration(w, i))
            return true;
        if (((w >> 12) & 7) == 7) {
            unsupported = "reserved or unimplemented vector-configuration encoding";
            return false;
        }
        if (decode_vector_reduction(w, i) || decode_vector_integer(w, i) || decode_vector_compare(w, i) || decode_vector_floating(w, i) || decode_vector_widening_add_sub(w, i) || decode_vector_widening_multiply(w, i) || decode_vector_multiply_add(w, i) ||
            decode_vector_shift_minmax(w, i) ||
            decode_vector_multiply(w, i) || decode_vector_divide(w, i) || decode_vector_permutation(w, i)) {
            read_vector_configuration(i);
            return true;
        }
        {
            const unsigned funct6 = w >> 26, funct3 = (w >> 12) & 7;
            const bool implemented = funct6 == 0 || funct6 == 2 || funct6 == 3 || funct6 == 4 || funct6 == 5 || funct6 == 6 ||
                                     funct6 == 7 || funct6 == 9 || funct6 == 10 || funct6 == 11 ||
                                     funct6 == 0x25 || funct6 == 0x28 || funct6 == 0x29 || funct6 == 0x2b ||
                                     funct6 == 0x2d || funct6 == 0x2f ||
                                     (funct6 >= 0x3c && funct6 <= 0x3f) ||
                                     funct6 == 0x0c || funct6 == 0x0e || funct6 == 0x0f ||
                                     (funct6 >= 0x18 && funct6 <= 0x1f) || (funct6 >= 0x20 && funct6 <= 0x23);
            const bool floating_implemented = funct6 == 0 || funct6 == 2 || funct6 == 4 || funct6 == 6 ||
                funct6 == 8 || funct6 == 9 || funct6 == 10 || funct6 == 0x18 || funct6 == 0x19 ||
                funct6 == 0x1b || funct6 == 0x1c || funct6 == 0x1d || funct6 == 0x1f ||
                funct6 == 0x20 || funct6 == 0x24 || funct6 == 0x13;
            if ((implemented && (funct3 == 0 || funct3 == 3 || funct3 == 4)) || floating_implemented)
                return false; // Reserved operand class of an explicitly implemented integer/FP operation.
            unsupported = "RVV operand class or operation is outside the enabled vector subset";
            return false;
        }
    case 0x0b: case 0x2b: case 0x5b: case 0x7b:
        unsupported = "custom or non-base opcode is outside the enabled RV64I/M subset";
        return false;
    default:
        return false;
    }
}

bool decode_compressed(std::uint16_t h, RiscvInstruction &i, std::string &unsupported) {
    const unsigned q = h & 3, f3 = h >> 13, rd = (h >> 7) & 31, rs2 = (h >> 2) & 31;
    const unsigned rp = 8 + ((h >> 2) & 7), rq = 8 + ((h >> 7) & 7);
    auto imm6 = [&] { return sign_extend(((h >> 12) & 1) << 5 | ((h >> 2) & 31), 6); };
    auto load = [&](unsigned r, unsigned base, std::int64_t off, unsigned width) {
        i.opcode = width == 64 ? RiscvOpcode::ld : RiscvOpcode::lw;
        operand(i, RiscvRegister{static_cast<std::uint8_t>(r)}, RiscvOperandAccess::write);
        operand(i, RiscvMemory{RiscvRegister{static_cast<std::uint8_t>(base)}, off,
                               static_cast<std::uint8_t>(width), width == 32}, RiscvOperandAccess::read);
        read_register(i, base); i.memory_read = true;
    };
    auto store = [&](unsigned r, unsigned base, std::int64_t off, unsigned width) {
        i.opcode = width == 64 ? RiscvOpcode::sd : RiscvOpcode::sw;
        operand(i, RiscvRegister{static_cast<std::uint8_t>(r)}, RiscvOperandAccess::read);
        operand(i, RiscvMemory{RiscvRegister{static_cast<std::uint8_t>(base)}, off,
                               static_cast<std::uint8_t>(width), false}, RiscvOperandAccess::write);
        read_register(i, base); i.memory_write = true;
    };
    if (q == 0) {
        const auto u = ((h >> 11) & 3) << 4 | ((h >> 7) & 15) << 6 | ((h >> 6) & 1) << 2 | ((h >> 5) & 1) << 3;
        const auto lw = ((h >> 10) & 7) << 3 | ((h >> 6) & 1) << 2 | ((h >> 5) & 1) << 6;
        const auto ld = ((h >> 10) & 7) << 3 | ((h >> 5) & 3) << 6;
        switch (f3) {
        case 0: if (!u) return false; set_ri(i,RiscvOpcode::addi,rp,2,u,10,false); return true;
        case 1: case 5: unsupported = "compressed floating-point instruction requires a disabled extension"; return false;
        case 2: load(rp,rq,lw,32); return true;
        case 3: load(rp,rq,ld,64); return true;
        case 6: store(rp,rq,lw,32); return true;
        case 7: store(rp,rq,ld,64); return true;
        default: return false;
        }
    }
    if (q == 1) {
        switch (f3) {
        case 0: set_ri(i,RiscvOpcode::addi,rd,rd,imm6(),6); return true;
        case 1: if (!rd) return false; set_ri(i,RiscvOpcode::addiw,rd,rd,imm6(),6); return true;
        case 2: set_ri(i,RiscvOpcode::addi,rd,0,imm6(),6); return true;
        case 3:
            if (rd == 2) {
                const auto v=sign_extend(((h>>12)&1)<<9|((h>>6)&1)<<4|((h>>5)&1)<<6|((h>>3)&3)<<7|((h>>2)&1)<<5,10);
                if (!v) return false; set_ri(i,RiscvOpcode::addi,2,2,v,10); return true;
            }
            if (!rd || !((h>>2)&31)) return false;
            i.opcode=RiscvOpcode::lui;
            operand(i,RiscvRegister{static_cast<std::uint8_t>(rd)},RiscvOperandAccess::write);
            operand(i,RiscvImmediate{sign_extend(((h>>12)&1)<<5|((h>>2)&31),6)*4096,6,true},RiscvOperandAccess::read);
            return true;
        case 4: {
            const unsigned sub=(h>>10)&3; const auto sh=((h>>12)&1)<<5|((h>>2)&31);
            if (sub==0 || sub==1) { if ((h>>12)&1) return false; set_ri(i,sub?RiscvOpcode::srai:RiscvOpcode::srli,rq,rq,sh,6,false); return true; }
            if (sub==2) { set_ri(i,RiscvOpcode::bit_and,rq,rq,imm6(),6); return true; }
            const unsigned sel=(h>>5)&3; const bool wide=(h>>12)&1;
            if (!wide) { if(sel>3)return false; static constexpr RiscvOpcode ops[]{RiscvOpcode::sub,RiscvOpcode::bit_xor,RiscvOpcode::bit_or,RiscvOpcode::bit_and}; set_rr(i,ops[sel],rq,rq,rs2); return true; }
            if(sel>1)return false; set_rr(i,sel?RiscvOpcode::addw:RiscvOpcode::subw,rq,rq,rs2); return true;
        }
        case 5: { const auto b=((h>>12)&1)<<11|((h>>11)&1)<<4|((h>>9)&3)<<8|((h>>8)&1)<<10|((h>>7)&1)<<6|((h>>6)&1)<<7|((h>>3)&7)<<1|((h>>2)&1)<<5; i.opcode=RiscvOpcode::jal;i.flow=RiscvFlow::jump;operand(i,RiscvRegister{0},RiscvOperandAccess::write);relative_operand(i,sign_extend(b,12),12);return true; }
        case 6: case 7: { const auto b=((h>>12)&1)<<8|((h>>10)&3)<<3|((h>>5)&3)<<6|((h>>3)&3)<<1|((h>>2)&1)<<5; i.opcode=f3==6?RiscvOpcode::beq:RiscvOpcode::bne;i.flow=RiscvFlow::conditional_branch;operand(i,RiscvRegister{static_cast<std::uint8_t>(rq)},RiscvOperandAccess::read);operand(i,RiscvRegister{0},RiscvOperandAccess::read);relative_operand(i,sign_extend(b,9),9);return true; }
        }
    }
    if (q == 2) {
        switch(f3) {
        case 0: set_ri(i,RiscvOpcode::slli,rd,rd,((h>>12)&1)<<5|((h>>2)&31),6,false);return true;
        case 1: case 5: unsupported="compressed floating-point instruction requires a disabled extension";return false;
        case 2: if(!rd)return false; load(rd,2,((h>>12)&1)<<5|((h>>4)&7)<<2|((h>>2)&3)<<6,32);return true;
        case 3: if(!rd)return false; load(rd,2,((h>>12)&1)<<5|((h>>5)&3)<<3|((h>>2)&7)<<6,64);return true;
        case 4: {
            const bool high=(h>>12)&1;
            if(!high && !rs2) { if(!rd)return false;i.opcode=RiscvOpcode::jalr;i.flow=(rd==1||rd==5)?RiscvFlow::ret:RiscvFlow::jump;operand(i,RiscvRegister{0},RiscvOperandAccess::write);operand(i,RiscvMemory{RiscvRegister{static_cast<std::uint8_t>(rd)},0,64,false},RiscvOperandAccess::address);read_register(i,rd);return true; }
            if(!high) { set_rr(i,RiscvOpcode::add,rd,0,rs2);return true; }
            if(!rs2 && !rd) {i.opcode=RiscvOpcode::ebreak;i.flow=RiscvFlow::trap;return true;}
            if(!rs2) {i.opcode=RiscvOpcode::jalr;i.flow=RiscvFlow::call;operand(i,RiscvRegister{1},RiscvOperandAccess::write);operand(i,RiscvMemory{RiscvRegister{static_cast<std::uint8_t>(rd)},0,64,false},RiscvOperandAccess::address);read_register(i,rd);return true;}
            set_rr(i,RiscvOpcode::add,rd,rd,rs2);return true;
        }
        case 6: store(rs2,2,((h>>9)&15)<<2|((h>>7)&3)<<6,32);return true;
        case 7: store(rs2,2,((h>>10)&7)<<3|((h>>7)&7)<<6,64);return true;
        }
    }
    return false;
}
} // namespace

namespace {
RiscvDecodeResult decode_riscv(std::span<const std::byte> bytes, Address at, unsigned xlen, bool compressed) {
    if (at.offset & (compressed ? 1u : 3u))
        return failure(DecodeStatus::invalid, compressed ? "RV64IC instruction address is not two-byte aligned"
                      : xlen == 32 ? "RV32I instruction address is not four-byte aligned"
                                   : "RV64I instruction address is not four-byte aligned");
    if (bytes.size() < 2)
        return failure(DecodeStatus::truncated, "RISC-V instruction length prefix is truncated");

    const auto first = halfword(bytes);
    const auto low5 = first & 0x1f;
    if ((first & 3) != 3) {
        if (!compressed)
            return failure(DecodeStatus::unsupported, "compressed instruction detected; C extension is disabled");
        RiscvInstruction instruction; instruction.address = at; instruction.length = 2;
        std::copy_n(bytes.begin(), 2, instruction.bytes.begin());
        std::string unsupported;
        if (!decode_compressed(first, instruction, unsupported))
            return failure(unsupported.empty() ? DecodeStatus::invalid : DecodeStatus::unsupported,
                           unsupported.empty() ? "reserved or unimplemented RV64C encoding" : unsupported.c_str());
        return {DecodeStatus::decoded, std::move(instruction), {}};
    }
    if (low5 == 0x1f) {
        std::size_t required = 6;
        if ((first & 0x3f) == 0x3f) {
            if ((first & 0x7f) != 0x7f)
                required = 8;
            else {
                if (bytes.size() < 2)
                    return failure(DecodeStatus::truncated, "long RISC-V instruction length prefix is truncated");
                const auto n = (first >> 12) & 7;
                required = 10 + 2 * n; // 80 + 16*n bits.
            }
        }
        if (bytes.size() < required)
            return failure(DecodeStatus::truncated, "variable-length RISC-V instruction bytes are truncated");
        return failure(DecodeStatus::unsupported, "variable-length RISC-V instruction is outside the enabled subset");
    }
    if (bytes.size() < 4)
        return failure(DecodeStatus::truncated, "32-bit RISC-V instruction bytes are truncated");

    RiscvInstruction instruction;
    instruction.address = at;
    instruction.length = 4;
    std::copy_n(bytes.begin(), instruction.length, instruction.bytes.begin());
    std::string unsupported;
    if (!decode_word(word(bytes.first(4)), instruction, unsupported, xlen)) {
        if (!unsupported.empty())
            return failure(DecodeStatus::unsupported, unsupported.c_str());
        return failure(DecodeStatus::invalid, xlen == 32 ? "reserved or unimplemented RV32I/M encoding"
                                                        : "reserved or unimplemented RV64I/M encoding");
    }
    return {DecodeStatus::decoded, std::move(instruction), {}};
}
} // namespace

RiscvDecodeResult decode_riscv64(std::span<const std::byte> bytes, Address at) {
    return decode_riscv(bytes, at, 64, false);
}
RiscvDecodeResult decode_riscv64c(std::span<const std::byte> bytes, Address at) {
    return decode_riscv(bytes, at, 64, true);
}
RiscvDecodeResult decode_riscv32(std::span<const std::byte> bytes, Address at) {
    return decode_riscv(bytes, at, 32, false);
}
} // namespace hexlab
