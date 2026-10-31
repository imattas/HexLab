#pragma once

#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/processors_export.hpp"
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace hexlab {

enum class RiscvOpcode {
    lui, auipc, jal, jalr,
    beq, bne, blt, bge, bltu, bgeu,
    lb, lh, lw, ld, lbu, lhu, lwu,
    sb, sh, sw, sd,
    addi, slti, sltiu, xori, ori, andi, slli, srli, srai,
    add, sub, sll, slt, sltu, bit_xor, srl, sra, bit_or, bit_and,
    fence, ecall, ebreak,
    addiw, slliw, srliw, sraiw,
    addw, subw, sllw, srlw, sraw,
    mul, mulh, mulhsu, mulhu, div, divu, rem, remu,
    mulw, divw, divuw, remw, remuw,
    lr_w, sc_w, amoswap_w, amoadd_w, amoxor_w, amoand_w, amoor_w, amomin_w, amomax_w, amominu_w, amomaxu_w,
    lr_d, sc_d, amoswap_d, amoadd_d, amoxor_d, amoand_d, amoor_d, amomin_d, amomax_d, amominu_d, amomaxu_d,
    csrrw, csrrs, csrrc, csrrwi, csrrsi, csrrci,
    flw, fld, fsw, fsd,
    fadd_s, fsub_s, fmul_s, fdiv_s, fsqrt_s, fsgnj_s, fsgnjn_s, fsgnjx_s, fmin_s, fmax_s,
    fmadd_s, fmsub_s, fnmsub_s, fnmadd_s, feq_s, flt_s, fle_s, fclass_s,
    fcvt_w_s, fcvt_wu_s, fcvt_l_s, fcvt_lu_s, fcvt_s_w, fcvt_s_wu, fcvt_s_l, fcvt_s_lu,
    fmv_x_w, fmv_w_x,
    fadd_d, fsub_d, fmul_d, fdiv_d, fsqrt_d, fsgnj_d, fsgnjn_d, fsgnjx_d, fmin_d, fmax_d,
    fmadd_d, fmsub_d, fnmsub_d, fnmadd_d, feq_d, flt_d, fle_d, fclass_d,
    fcvt_w_d, fcvt_wu_d, fcvt_l_d, fcvt_lu_d, fcvt_d_w, fcvt_d_wu, fcvt_d_l, fcvt_d_lu,
    fcvt_s_d, fcvt_d_s, fmv_x_d, fmv_d_x,
    // Appended RVV 1.0 configuration forms.
    vsetvli, vsetivli, vsetvl,
    // RVV 1.0 integer elementwise arithmetic (unmasked and v0-masked).
    vadd_vv, vadd_vx, vadd_vi, vsub_vv, vsub_vx,
    vand_vv, vand_vx, vand_vi, vor_vv, vor_vx, vor_vi, vxor_vv, vxor_vx, vxor_vi,
    vle, vse,
    // RVV integer comparison instructions write mask values to a vector register.
    vmseq_vv, vmseq_vx, vmseq_vi, vmsne_vv, vmsne_vx, vmsne_vi,
    vmsltu_vv, vmsltu_vx, vmslt_vv, vmslt_vx,
    vmsleu_vv, vmsleu_vx, vmsleu_vi, vmsle_vv, vmsle_vx, vmsle_vi,
    vmsgtu_vx, vmsgtu_vi, vmsgt_vx, vmsgt_vi,
    // RVV base integer shifts and min/max, appended for stable decoder IDs.
    vsll_vv, vsll_vx, vsll_vi, vsrl_vv, vsrl_vx, vsrl_vi, vsra_vv, vsra_vx, vsra_vi,
    vminu_vv, vminu_vx, vmin_vv, vmin_vx, vmaxu_vv, vmaxu_vx, vmax_vv, vmax_vx,
    // Appended RVV reverse-subtract scalar/immediate forms for serialized ID stability.
    vrsub_vx, vrsub_vi,
    // RVV single-width integer multiply forms; preserve persisted decoder IDs.
    vmul_vv, vmul_vx, vmulh_vv, vmulh_vx, vmulhu_vv, vmulhu_vx, vmulhsu_vv, vmulhsu_vx,
    // Single-width integer divide/remainder forms, appended for ID stability.
    vdivu_vv, vdivu_vx, vdiv_vv, vdiv_vx, vremu_vv, vremu_vx, vrem_vv, vrem_vx,
    // RVV strided unit-element memory forms; appended for stable opcode IDs.
    vlse, vsse,
    // RVV gather and slide permutation operations.
    vrgather_vv, vrgather_vx, vrgather_vi,
    vslideup_vx, vslideup_vi, vslidedown_vx, vslidedown_vi,
    // Indexed single-field integer vector memory forms; appended for ID stability.
    vluxei, vloxei, vsuxei, vsoxei,
    // Zbb scalar count operations, appended for decoder ID stability.
    clz, ctz, cpop, clzw, ctzw, cpopw,
    // Non-widening integer multiply-accumulate/subtract; destructive vd forms.
    vmacc_vv, vmacc_vx, vnmsac_vv, vnmsac_vx, vmadd_vv, vmadd_vx, vnmsub_vv, vnmsub_vx,
    // RVV widening integer multiply-accumulate; append for persisted decoder IDs.
    vwmaccu_vv, vwmaccu_vx, vwmacc_vv, vwmacc_vx,
    vwmaccsu_vv, vwmaccsu_vx, vwmaccus_vx,
    // RVV widening add/sub forms (append for serialized ID stability).
    vwadd_vv, vwadd_vx, vwadd_wv, vwadd_wx,
    vwaddu_vv, vwaddu_vx, vwaddu_wv, vwaddu_wx,
    vwsub_vv, vwsub_vx, vwsub_wv, vwsub_wx,
    vwsubu_vv, vwsubu_vx, vwsubu_wv, vwsubu_wx,
    // Zba address-generation operations; appended for stable decoded IDs.
    sh1add, sh2add, sh3add, add_uw, sh1add_uw, sh2add_uw, sh3add_uw, slli_uw,
    // Zbs single-bit operations; appended for stable decoded IDs.
    bclr, bext, binv, bset, bclri, bexti, binvi, bseti,
    // RVV non-accumulating widening integer multiply; appended for ID stability.
    vwmulu_vv, vwmulu_vx, vwmulsu_vv, vwmulsu_vx, vwmul_vv, vwmul_vx,
    // RVV base floating-point VV/VF arithmetic, sign, min/max, and compare forms.
    vfadd_vv, vfadd_vf, vfsub_vv, vfsub_vf, vfmul_vv, vfmul_vf, vfdiv_vv, vfdiv_vf,
    vfsgnj_vv, vfsgnj_vf, vfsgnjn_vv, vfsgnjn_vf, vfsgnjx_vv, vfsgnjx_vf,
    vfmin_vv, vfmin_vf, vfmax_vv, vfmax_vf,
    vmfeq_vv, vmfeq_vf, vmfne_vv, vmfne_vf, vmflt_vv, vmflt_vf, vmfle_vv, vmfle_vf,
    vmfgt_vf, vmfge_vf,
    vfmacc_vv, vfmacc_vf, vfnmacc_vv, vfnmacc_vf, vfmsac_vv, vfmsac_vf, vfnmsac_vv, vfnmsac_vf,
    vfmadd_vv, vfmadd_vf, vfnmadd_vv, vfnmadd_vf, vfmsub_vv, vfmsub_vf, vfnmsub_vv, vfnmsub_vf,
    vfsqrt_v, vfclass_v,
    // RVV reciprocal estimate operations; append for stable serialized IDs.
    vfrsqrt7_v, vfrec7_v,
    vredsum, vredand, vredor, vredxor, vredminu, vredmin, vredmaxu, vredmax,
    // Scalar Zfa conversion appended to preserve existing opcode IDs.
    fcvtmod_w_d,
    // Scalar Zfa immediate floating constants; appended for numeric ID stability.
    fli_s, fli_d,
    // Zfa round-to-integral forms, appended for stable decoder IDs.
    fround_s, froundnx_s, fround_d, froundnx_d,
    // Zfa minimum/maximum-number variants.
    fminm_s, fmaxm_s, fminm_d, fmaxm_d,
    // Quiet scalar comparisons; appended to preserve decoder IDs.
    fleq_s, fltq_s, fleq_d, fltq_d,
    // Zifencei instruction-cache synchronization, appended for stable IDs.
    fence_i,
    // Remaining scalar Zbb integer bit-manipulation forms (appended for ID stability).
    andn, orn, xnor, min, minu, max, maxu, rol, ror, rori,
    sext_b, sext_h, zext_h, orc_b, rev8, rolw, rorw, roriw,
    // RVV single-width floating-point reductions; appended for decoder ID stability.
    vfredusum, vfredosum, vfredmin, vfredmax,
    // RVV mask-register logical operations, appended for opcode stability.
    vmand_mm, vmnand_mm, vmandn_mm, vmxor_mm, vmor_mm, vmnor_mm, vmorn_mm, vmxnor_mm,
    // Zbc scalar carry-less multiply forms; append to preserve decoder IDs.
    clmul, clmulh, clmulr,
    // Zicond conditional-zero forms; appended to preserve serialized decoder IDs.
    czero_eqz, czero_nez,
    // Ztso FENCE.TSO encoding; appended to preserve serialized decoder IDs.
    fence_tso,
    // Zbkb scalar packing operations; append for stable decoded IDs.
    pack, packh, packw,
    // RVV mask prefix, index, and reduction-to-GPR forms; preserve IDs above.
    vcpop_m, vfirst_m, vmsbf_m, vmsof_m, vmsif_m, viota_m, vid_v,
    // RVV widening floating-point reductions; appended to preserve decoder IDs.
    vfwredusum, vfwredosum,
    // RVV widening integer reductions, appended to preserve decoder IDs.
    vwredsum, vwredsumu
};

struct RiscvRegister {
    std::uint8_t index = 0;
    bool floating_point = false;
    bool vector = false;
    bool vector_configuration = false;
    bool operator==(const RiscvRegister &) const = default;
};

struct RiscvImmediate {
    std::int64_t value = 0;
    std::uint8_t encoded_width = 0;
    bool is_signed = false;
    bool operator==(const RiscvImmediate &) const = default;
};

struct RiscvMemory {
    RiscvRegister base;
    std::int64_t displacement = 0;
    std::uint8_t width = 0;
    bool sign_extend = false;
    bool operator==(const RiscvMemory &) const = default;
};

struct RiscvRelative {
    std::int64_t displacement = 0;
    std::uint8_t encoded_width = 0;
    std::optional<Address> target;
    bool operator==(const RiscvRelative &) const = default;
};

using RiscvOperand = std::variant<RiscvRegister, RiscvImmediate, RiscvMemory, RiscvRelative>;
enum class RiscvOperandAccess { read, write, read_write, address };
enum class RiscvFlow { fallthrough, call, conditional_branch, jump, ret, trap };

struct RiscvInstruction {
    Address address{{0}, 0};
    std::array<std::byte, 4> bytes{};
    std::uint8_t length = 0;
    RiscvOpcode opcode = RiscvOpcode::addi;
    std::vector<RiscvOperand> operands;
    std::vector<RiscvOperandAccess> access;
    std::vector<RiscvRegister> register_reads, register_writes;
    RiscvFlow flow = RiscvFlow::fallthrough;
    std::optional<Address> direct_target;
    bool memory_read = false, memory_write = false;
    bool atomic_aq = false, atomic_rl = false;
    bool csr_read = false, csr_write = false;
    std::optional<std::uint8_t> rounding_mode;
    bool writes_fflags = false;
    bool vector_masked = false;
    // Number of interleaved vector fields for segmented RVV memory operations.
    // One is the ordinary single-field form.
    std::uint8_t vector_segment_fields = 1;
    bool reads_frm = false;
    bool reads_fflags = false;
};

struct RiscvDecodeResult {
    DecodeStatus status = DecodeStatus::unsupported;
    std::optional<RiscvInstruction> instruction;
    std::string reason;
};

// Bounded static decoder for RV64I/M/A/Zicsr plus RVV vector-configuration forms. C and other extensions are disabled;
// RV64I uses IALIGN=32 here.
HEXLAB_PROCESSORS_EXPORT RiscvDecodeResult decode_riscv64(std::span<const std::byte>, Address);
// RV32I/M/A integer, multiply/divide, and word-atomic subsets. Other extensions and C are not enabled.
HEXLAB_PROCESSORS_EXPORT RiscvDecodeResult decode_riscv32(std::span<const std::byte>, Address);
// RV64I/M/A plus integer RV64C (not floating-point C forms); IALIGN=16.
HEXLAB_PROCESSORS_EXPORT RiscvDecodeResult decode_riscv64c(std::span<const std::byte>, Address);

} // namespace hexlab
