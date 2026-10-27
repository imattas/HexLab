#pragma once
#include "hexlab/core/address.hpp"
#include "hexlab/core/architecture.hpp"
#include "hexlab/processors/x64_semantics.hpp"
#include <array>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace hexlab {
enum class DecodeStatus { decoded, unsupported, invalid, truncated };
enum class FlowKind { fallthrough, call, conditional_branch, jump, ret, trap, switch_dispatch, data };
enum class RegisterBank { gpr, ip, flags, segment, arm32_gpr, arm64_gpr, arm64_sp, arm64_zero, arm_flags, riscv_gpr, mips_gpr, mos6502, mips_hilo, mips_cp0, x87, ppc_gpr, ppc_cr, ppc_lr, ppc_ctr, xmm, riscv_fpr, riscv_fstatus, mips_fpr, mips_fcsr, cil_stack, ymm, riscv_vpr, riscv_vcsr, cil_continuation, ppc_xer, x87_status, x87_control, x87_tag, arm64_simd, dex_vreg, jvm_local, wasm_stack, mxcsr, zmm, opmask, ppc_fpr, jvm_stack, ppc_fpscr, ppc_vr, wasm_local };
enum class Opcode {
    mov,
    movzx,
    movsx,
    movsxd,
    lea,
    push,
    pop,
    leave,
    add,
    bit_or,
    adc,
    sbb,
    bit_and,
    sub,
    bit_xor,
    cmp,
    test,
    inc,
    dec,
    bit_not,
    neg,
    imul,
    rol,
    ror,
    rcl,
    rcr,
    shl,
    shr,
    sar,
    call,
    jmp,
    jcc,
    ret,
    int3,
    nop,
    endbr64,
    pause,
    endbr32,
    retf,
    a64_b,
    a64_bl,
    a64_b_cond,
    a64_cbz,
    a64_cbnz,
    a64_tbz,
    a64_tbnz,
    a64_br,
    a64_blr,
    a64_ret,
    a64_brk,
    a64_nop,
    a64_movn,
    a64_movz,
    a64_movk,
    a64_add,
    a64_adds,
    a64_sub,
    a64_subs,
    a64_and,
    a64_orr,
    a64_eor,
    a64_ands,
    a64_adr,
    a64_adrp,
    a64_ldr,
    a64_str,
    a64_ldrb,
    a64_strb,
    a64_ldrh,
    a64_strh,
    a32_b,
    a32_bl,
    a32_bx,
    a32_blx,
    a32_nop,
    a32_bkpt,
    a32_svc,
    a32_and,
    a32_eor,
    a32_sub,
    a32_rsb,
    a32_add,
    a32_adc,
    a32_sbc,
    a32_rsc,
    a32_tst,
    a32_teq,
    a32_cmp,
    a32_cmn,
    a32_orr,
    a32_mov,
    a32_bic,
    a32_mvn,
    a32_ldr,
    a32_str,
    a32_ldrb,
    a32_strb,
    a32_ldrh,
    a32_strh,
    a32_ldrsb,
    a32_ldrsh,
    a32_ldm,
    a32_stm,
    t32_b,
    t32_bl,
    t32_bx,
    t32_blx,
    t32_cbz,
    t32_cbnz,
    t32_it,
    t32_nop,
    t32_bkpt,
    t32_svc,
    t32_adr,
    t32_mul,
    // Appended so existing serialized/ABI enum values stay unchanged.
    mul,
    div,
    idiv,
    // Appended to preserve values stored by older project/cache formats.
    rv_lui, rv_auipc, rv_jal, rv_jalr,
    rv_beq, rv_bne, rv_blt, rv_bge, rv_bltu, rv_bgeu,
    rv_lb, rv_lh, rv_lw, rv_ld, rv_lbu, rv_lhu, rv_lwu,
    rv_sb, rv_sh, rv_sw, rv_sd,
    rv_addi, rv_slti, rv_sltiu, rv_xori, rv_ori, rv_andi, rv_slli, rv_srli, rv_srai,
    rv_add, rv_sub, rv_sll, rv_slt, rv_sltu, rv_xor, rv_srl, rv_sra, rv_or, rv_and,
    rv_fence, rv_ecall, rv_ebreak,
    rv_addiw, rv_slliw, rv_srliw, rv_sraiw,
    rv_addw, rv_subw, rv_sllw, rv_srlw, rv_sraw,
    rv_mul, rv_mulh, rv_mulhsu, rv_mulhu, rv_div, rv_divu, rv_rem, rv_remu,
    rv_mulw, rv_divw, rv_divuw, rv_remw, rv_remuw,
    mips_sll, mips_srl, mips_sra, mips_sllv, mips_srlv, mips_srav,
    mips_jr, mips_jalr, mips_add, mips_addu, mips_sub, mips_subu,
    mips_and, mips_or, mips_xor, mips_nor, mips_slt, mips_sltu,
    mips_j, mips_jal, mips_beq, mips_bne, mips_blez, mips_bgtz,
    mips_addi, mips_addiu, mips_slti, mips_sltiu, mips_andi, mips_ori, mips_xori, mips_lui,
    mips_bltz, mips_bgez, mips_lb, mips_lh, mips_lwl, mips_lw, mips_lbu, mips_lhu, mips_lwr,
    mips_sb, mips_sh, mips_swl, mips_sw, mips_swr,
    // Appended to preserve values stored by older project/cache formats.
    cmovcc, setcc,
    m6502_lda, m6502_ldx, m6502_ldy, m6502_sta, m6502_stx, m6502_sty,
    m6502_adc, m6502_sbc, m6502_and, m6502_ora, m6502_eor, m6502_cmp, m6502_cpx, m6502_cpy,
    m6502_bit, m6502_inc, m6502_dec, m6502_inx, m6502_dex, m6502_iny, m6502_dey,
    m6502_tax, m6502_tay, m6502_txa, m6502_tya, m6502_tsx, m6502_txs,
    m6502_pha, m6502_php, m6502_pla, m6502_plp,
    m6502_jmp, m6502_jsr, m6502_rts, m6502_rti, m6502_brk,
    m6502_bpl, m6502_bmi, m6502_bvc, m6502_bvs, m6502_bcc, m6502_bcs, m6502_bne, m6502_beq,
    m6502_clc, m6502_sec, m6502_cli, m6502_sei, m6502_clv, m6502_cld, m6502_sed,
    m6502_asl, m6502_lsr, m6502_rol, m6502_ror,
    // Generic x86 decode with display text but no inferred operand semantics.
    x86_opaque,
    // Generic third-party decode display only; no typed operands or flow facts.
    opaque,
    // Appended so existing serialized/cache opcode values stay unchanged.
    bsf,
    bsr,
    bt,
    bts,
    btr,
    btc,
    tzcnt,
    lzcnt,
    xadd,
    cmpxchg,
    // A32 integer multiply family; appended to keep persisted opcode values stable.
    a32_mul, a32_mla, a32_mls, a32_umull, a32_umlal, a32_smull, a32_smlal,
    mips_mult, mips_multu, mips_div, mips_divu, mips_mfhi, mips_mflo, mips_mthi, mips_mtlo,
    mips_syscall, mips_break, mips_sync, mips_mfc0, mips_mtc0, mips_eret,
    x86_movs, x86_cmps, x86_stos, x86_lods, x86_scas,
    // Appended to preserve persisted opcode values above.
    rv_lr_w, rv_sc_w, rv_amoswap_w, rv_amoadd_w, rv_amoxor_w, rv_amoand_w, rv_amoor_w,
    rv_amomin_w, rv_amomax_w, rv_amominu_w, rv_amomaxu_w,
    rv_lr_d, rv_sc_d, rv_amoswap_d, rv_amoadd_d, rv_amoxor_d, rv_amoand_d, rv_amoor_d,
    rv_amomin_d, rv_amomax_d, rv_amominu_d, rv_amomaxu_d,
    xchg,
    cbw,
    cwde,
    cdqe,
    cwd,
    cdq,
    cqo,
    // Appended so persisted/cache Opcode ordinals after the A64 block stay unchanged.
    a64_sbfm,
    a64_ubfm,
    // Appended so existing persisted opcode values remain unchanged.
    x87,
    // Appended N64 forms: instruction words stay 32-bit, GPR/address effects are 64-bit.
    mips64_dadd, mips64_daddu, mips64_dsub, mips64_dsubu, mips64_daddiu,
    mips64_dsll, mips64_dsrl, mips64_dsra, mips64_dsllv, mips64_dsrlv, mips64_dsrav,
    mips64_dsll32, mips64_dsrl32, mips64_dsra32,
    mips64_ld, mips64_sd, mips64_lwu, mips64_lld, mips64_scd,
    // Appended PowerPC/POWER integer subset.
    ppc_addi, ppc_addis, ppc_ori, ppc_oris, ppc_xori, ppc_xoris, ppc_andi_dot, ppc_andis_dot,
    ppc_add, ppc_add_dot, ppc_subf, ppc_subf_dot, ppc_or, ppc_or_dot, ppc_xor, ppc_xor_dot,
    ppc_and, ppc_and_dot, ppc_cmp, ppc_cmpl,
    ppc_lwz, ppc_lwzu, ppc_lbz, ppc_lbzu, ppc_lhz, ppc_lhzu, ppc_lha, ppc_lhau,
    ppc_stw, ppc_stwu, ppc_stb, ppc_stbu, ppc_sth, ppc_sthu, ppc_ld, ppc_ldu, ppc_std, ppc_stdu,
    ppc_b, ppc_bc, ppc_bclr, ppc_bcctr, ppc_mflr, ppc_mtlr, ppc_mfctr, ppc_mtctr, ppc_nop,
    // Appended to preserve persisted opcode values: initial SSE2 and scalar FP subset.
    movdqa, movdqu, paddd, paddq, psubd, psubq, pand, por, pxor,
    movss, movsd, addss, addsd, subss, subsd, mulss, mulsd, divss, divsd,
    // Appended RISC-V Zicsr forms preserve every existing serialized opcode value.
    rv_csrrw, rv_csrrs, rv_csrrc, rv_csrrwi, rv_csrrsi, rv_csrrci,
    // Appended RISC-V F/D scalar forms.
    rv_flw, rv_fld, rv_fsw, rv_fsd,
    rv_fadd_s, rv_fsub_s, rv_fmul_s, rv_fdiv_s, rv_fsqrt_s, rv_fsgnj_s, rv_fsgnjn_s, rv_fsgnjx_s, rv_fmin_s, rv_fmax_s,
    rv_fmadd_s, rv_fmsub_s, rv_fnmsub_s, rv_fnmadd_s, rv_feq_s, rv_flt_s, rv_fle_s, rv_fclass_s,
    rv_fcvt_w_s, rv_fcvt_wu_s, rv_fcvt_l_s, rv_fcvt_lu_s, rv_fcvt_s_w, rv_fcvt_s_wu, rv_fcvt_s_l, rv_fcvt_s_lu,
    rv_fmv_x_w, rv_fmv_w_x,
    rv_fadd_d, rv_fsub_d, rv_fmul_d, rv_fdiv_d, rv_fsqrt_d, rv_fsgnj_d, rv_fsgnjn_d, rv_fsgnjx_d, rv_fmin_d, rv_fmax_d,
    rv_fmadd_d, rv_fmsub_d, rv_fnmsub_d, rv_fnmadd_d, rv_feq_d, rv_flt_d, rv_fle_d, rv_fclass_d,
    rv_fcvt_w_d, rv_fcvt_wu_d, rv_fcvt_l_d, rv_fcvt_lu_d, rv_fcvt_d_w, rv_fcvt_d_wu, rv_fcvt_d_l, rv_fcvt_d_lu,
    rv_fcvt_s_d, rv_fcvt_d_s, rv_fmv_x_d, rv_fmv_d_x
    , mips_lwc1, mips_swc1,
    mips_add_s, mips_sub_s, mips_mul_s, mips_div_s, mips_sqrt_s, mips_abs_s, mips_mov_s, mips_neg_s,
    mips_c_eq_s, mips_c_lt_s, mips_c_le_s, mips_bc1t, mips_bc1f,
    pcmpeqb, pcmpeqw, pcmpeqd, pcmpgtb, pcmpgtw, pcmpgtd,
    // Appended AVX VEX.128/.256 decoder subset.
    vaddps, vaddpd, vsubps, vsubpd, vmulps, vmulpd, vxorps, vxorpd, vandps, vandpd, vmovups,
    // MIPS64 HILO and doubleword multiply/divide operations, appended for cache stability.
    mips64_dmult, mips64_dmultu, mips64_ddiv, mips64_ddivu,
    mips64_mfhi, mips64_mflo, mips64_mthi, mips64_mtlo,
    // RVV configuration forms.
    rv_vsetvli, rv_vsetivli, rv_vsetvl,
    mips64_daddi,
    // Additional PowerPC scalar integer forms; appended to preserve cache IDs.
    ppc_mulli, ppc_subfic, ppc_cmpi, ppc_cmpli,
    ppc_rlwimi, ppc_rlwimi_dot, ppc_rlwinm, ppc_rlwinm_dot, ppc_rlwnm, ppc_rlwnm_dot
    , mips_ldc1, mips_sdc1,
    mips_add_d, mips_sub_d, mips_mul_d, mips_div_d, mips_sqrt_d, mips_abs_d, mips_mov_d, mips_neg_d,
    mips_c_eq_d, mips_c_lt_d, mips_c_le_d,
    mips_cvt_s_d, mips_cvt_d_s, mips_cvt_w_s, mips_cvt_w_d, mips_cvt_s_w, mips_cvt_d_w,
    mips_round_w_s, mips_trunc_w_s, mips_ceil_w_s, mips_floor_w_s,
    mips_round_w_d, mips_trunc_w_d, mips_ceil_w_d, mips_floor_w_d,
    // x86 stack-frame and flags-stack instructions; appended for cache stability.
    pushf, popf, pusha, popa, enter,
    // MIPS64 COP1 data/control transfers and long-format conversions.
    mips64_mfc1, mips64_dmfc1, mips64_cfc1, mips64_mtc1, mips64_dmtc1, mips64_ctc1,
    mips64_cvt_l_s, mips64_cvt_l_d, mips64_cvt_s_l, mips64_cvt_d_l,
    mips64_round_l_s, mips64_trunc_l_s, mips64_ceil_l_s, mips64_floor_l_s,
    mips64_round_l_d, mips64_trunc_l_d, mips64_ceil_l_d, mips64_floor_l_d,
    // RVV integer arithmetic; appended to preserve existing serialized opcode IDs.
    rv_vadd_vv, rv_vadd_vx, rv_vadd_vi, rv_vsub_vv, rv_vsub_vx,
    rv_vand_vv, rv_vand_vx, rv_vand_vi, rv_vor_vv, rv_vor_vx, rv_vor_vi,
    rv_vxor_vv, rv_vxor_vx, rv_vxor_vi,
    // MIPS64 word HI/LO arithmetic; appended to preserve serialized opcode IDs.
    mips64_mult, mips64_multu, mips64_div, mips64_divu,
    // RVV unit-stride integer memory operations; appended for serialized ID stability.
    rv_vle, rv_vse,
    // Appended for persisted opcode stability: scalar x86 double shifts.
    shld, shrd,
    // MIPS branch-likely encodings, appended to preserve cache IDs.
    mips_beql, mips_bnel, mips_blezl, mips_bgtzl, mips_bltzl, mips_bgezl,
    // Expanded PowerPC integer/indexed-memory forms; appended for cache ID stability.
    ppc_addic, ppc_addic_dot, ppc_addc, ppc_adde, ppc_subfc, ppc_subfe, ppc_neg,
    ppc_mullw, ppc_mulld, ppc_divw, ppc_divwu, ppc_divd, ppc_divdu,
    ppc_slw, ppc_srw, ppc_sraw, ppc_srawi, ppc_sld, ppc_srd, ppc_srad, ppc_sradi,
    ppc_lwzx, ppc_lwzux, ppc_lbzx, ppc_lbzux, ppc_lhzx, ppc_lhzux, ppc_lhax, ppc_lhaux,
    ppc_stwx, ppc_stwux, ppc_stbx, ppc_stbux, ppc_sthx, ppc_sthux,
    ppc_ldx, ppc_ldux, ppc_stdx, ppc_stdux,
    ppc_lwbrx, ppc_lhbrx, ppc_stwbrx, ppc_sthbrx, ppc_mfcr, ppc_mtcrf, ppc_sc, ppc_mfxer, ppc_mtxer,
    // Additional SSE2 packed integer arithmetic; appended for cache stability.
    paddb, paddw, psubb, psubw, paddsb, paddsw, paddusb, paddusw,
    psubsb, psubsw, psubusb, psubusw,
    // SSE2 packed logical and shift operations; appended for cache stability.
    pandn, psllw, pslld, psllq, psrlw, psrld, psrlq, psraw, psrad,
    // AArch64 integer pair memory operations; append to preserve persisted IDs.
    a64_ldp, a64_stp,
    // MIPS unaligned merge loads/stores; append to preserve persisted IDs.
    mips64_lwl, mips64_lwr, mips64_swl, mips64_swr,
    mips64_ldl, mips64_ldr, mips64_sdl, mips64_sdr,
    arm_tbb, arm_tbh,
    // RVV mask-producing integer comparisons; appended to preserve cache IDs.
    rv_vmseq_vv, rv_vmseq_vx, rv_vmseq_vi, rv_vmsne_vv, rv_vmsne_vx, rv_vmsne_vi,
    rv_vmsltu_vv, rv_vmsltu_vx, rv_vmslt_vv, rv_vmslt_vx,
    rv_vmsleu_vv, rv_vmsleu_vx, rv_vmsleu_vi, rv_vmsle_vv, rv_vmsle_vx, rv_vmsle_vi,
    rv_vmsgtu_vx, rv_vmsgtu_vi, rv_vmsgt_vx, rv_vmsgt_vi,
    // Full MIPS64 scalar COP1 condition-code compare family.
    mips64_c_cond_s, mips64_c_cond_d,
    // PPC X-form logic, count-leading-zero and sign-extension operations.
    ppc_andc, ppc_andc_dot, ppc_nand, ppc_nand_dot, ppc_nor, ppc_nor_dot,
    ppc_orc, ppc_orc_dot, ppc_eqv, ppc_eqv_dot,
    ppc_cntlzw, ppc_cntlzw_dot, ppc_cntlzd, ppc_cntlzd_dot,
    ppc_extsb, ppc_extsb_dot, ppc_extsh, ppc_extsh_dot, ppc_extsw, ppc_extsw_dot,
    // Additional common SSE2 packed multiply/min/max/shuffle forms.
    pmullw, pmulhw, pmulhuw, pmuludq, pmaddwd, pminub, pmaxub, pminsw, pmaxsw, pshufd,
    // RVV shifts and min/max, appended to preserve serialized opcode IDs.
    rv_vsll_vv, rv_vsll_vx, rv_vsll_vi, rv_vsrl_vv, rv_vsrl_vx, rv_vsrl_vi,
    rv_vsra_vv, rv_vsra_vx, rv_vsra_vi, rv_vminu_vv, rv_vminu_vx, rv_vmin_vv, rv_vmin_vx,
    rv_vmaxu_vv, rv_vmaxu_vx, rv_vmax_vv, rv_vmax_vx,
    // RVV reverse-subtract scalar/immediate forms; appended for cache stability.
    rv_vrsub_vx, rv_vrsub_vi,
    // AArch64 AdvSIMD integer arithmetic and logic, appended for cache stability.
    a64_vadd, a64_vsub, a64_vand, a64_vorr, a64_veor,
    // AVX/AVX2 packed integer arithmetic and logic; appended for cache stability.
    vpaddb, vpaddw, vpaddd, vpaddq, vpand, vpor, vpxor,
    // AVX2 packed byte/word/dword/qword subtraction; appended for cache stability.
    vpsubb, vpsubw, vpsubd, vpsubq,
    // AArch64 scalar multiply-accumulate operations; appended for cache stability.
    a64_madd, a64_msub,
    vpcmpeqb, vpcmpeqw, vpcmpeqd, vpcmpeqq,
    vpcmpgtb, vpcmpgtw, vpcmpgtd, vpcmpgtq,
    // MIPS count-leading-zero/one word and doubleword forms.
    mips_clz, mips_clo, mips64_dclz, mips64_dclo,
    rv_vmul_vv, rv_vmul_vx, rv_vmulh_vv, rv_vmulh_vx,
    rv_vmulhu_vv, rv_vmulhu_vx, rv_vmulhsu_vv, rv_vmulhsu_vx,
    // RVV single-width integer divide/remainder forms, appended for cache stability.
    rv_vdivu_vv, rv_vdivu_vx, rv_vdiv_vv, rv_vdiv_vx,
    rv_vremu_vv, rv_vremu_vx, rv_vrem_vv, rv_vrem_vx,
    // AVX2 packed word multiply forms; append for persisted opcode stability.
    vpmullw, vpmulhw, vpmulhuw,
    // PPC64 indexed doubleword byte-reversed load/store; append for cache IDs.
    ppc_ldbrx, ppc_stdbrx,
    // AArch64 AdvSIMD floating point three-register arithmetic; appended for cache IDs.
    a64_fadd, a64_fsub, a64_fmul, a64_fdiv, a64_fmax, a64_fmin,
    // PPC64 doubleword rotate-and-mask instruction family; appended for cache stability.
    ppc_rldicl, ppc_rldicl_dot, ppc_rldicr, ppc_rldicr_dot, ppc_rldic, ppc_rldic_dot,
    ppc_rldimi, ppc_rldimi_dot, ppc_rldcl, ppc_rldcl_dot, ppc_rldcr, ppc_rldcr_dot,
    // RVV strided element loads/stores; append to preserve persisted IDs.
    rv_vlse, rv_vsse,
    // MIPS64 Release 2 SPECIAL3 doubleword bitfield operations.
    mips64_dextm, mips64_dextu, mips64_dext, mips64_dinsm, mips64_dinsu, mips64_dins,
    // RVV gather/slide operations; append to preserve serialized opcode IDs.
    rv_vrgather_vv, rv_vrgather_vx, rv_vrgather_vi,
    rv_vslideup_vx, rv_vslideup_vi, rv_vslidedown_vx, rv_vslidedown_vi,
    // Appended WebAssembly scalar operator display opcode; preserves all prior IDs.
    wasm,
    dex,
    // AVX2 packed saturating add/subtract and signed/unsigned min/max; appended for cache stability.
    vpaddsb, vpaddsw, vpaddusb, vpaddusw,
    vpsubsb, vpsubsw, vpsubusb, vpsubusw,
    vpminub, vpminsw, vpmaxub, vpmaxsw,
    // Appended JVM bytecode display opcode; preserves all persisted IDs.
    jvm,
    // Appended RVV indexed-memory opcodes; do not renumber persisted IDs.
    rv_vluxei, rv_vloxei, rv_vsuxei, rv_vsoxei,
    // DEX packed/sparse switch dispatch, appended for cache ID stability.
    dex_switch,
    // Scalar PowerPC floating-point arithmetic and memory forms; appended for cache stability.
    ppc_lfs, ppc_lfd, ppc_stfs, ppc_stfd,
    ppc_fadds, ppc_fsubs, ppc_fmuls, ppc_fdivs,
    ppc_fadd, ppc_fsub, ppc_fmul, ppc_fdiv,
    // MIPS64 COP1 branch-likely forms, appended for persisted opcode stability.
    mips64_bc1tl, mips64_bc1fl,
    // AArch64 conditional selects and scalar division; appended for cache stability.
    a64_csel, a64_csinc, a64_csinv, a64_csneg, a64_udiv, a64_sdiv,
    // x86 LOOP-family addition preserves all serialized opcode values.
    x86_loop,
    // RISC-V Zbb scalar count operations; appended for cache ID stability.
    rv_clz, rv_ctz, rv_cpop, rv_clzw, rv_ctzw, rv_cpopw,
    // AVX2 packed integer dataflow; append only to preserve persisted opcode IDs.
    vpandn, vpavgb, vpavgw,
    vpminsb, vpminsd, vpminuw, vpminud, vpmaxsb, vpmaxsd, vpmaxuw, vpmaxud,
    vpmulld, vpmuldq, vpmuludq, vpmaddwd, vpmaddubsw,
    vphaddw, vphaddd, vphaddsw, vphsubw, vphsubd, vphsubsw,
    vpsignb, vpsignw, vpsignd,
    vpunpcklbw, vpunpcklwd, vpunpckldq, vpunpcklqdq,
    vpunpckhbw, vpunpckhwd, vpunpckhdq, vpunpckhqdq,
    vpacksswb, vpackssdw, vpackuswb, vpackusdw, vpshufb, vpsadbw,
    // Appended scalar PowerPC floating-point compare and unary operations.
    ppc_fcmpu, ppc_fcmpo, ppc_fmr, ppc_fneg, ppc_fabs, ppc_frsp,
    // EVEX dword/qword bitwise forms; append to preserve persisted opcode IDs.
    vpandd, vpandq, vpord, vporq, vpxord, vpxorq,
    // VMX VX-form integer operations; append to preserve persisted opcode IDs.
    ppc_vaddubm, ppc_vadduhm, ppc_vadduwm,
    ppc_vsububm, ppc_vsubuhm, ppc_vsubuwm,
    ppc_vand, ppc_vandc, ppc_vor, ppc_vxor, ppc_vnor,
    // RVV non-widening integer multiply-accumulate forms; preserve prior IDs.
    rv_vmacc_vv, rv_vmacc_vx, rv_vnmsac_vv, rv_vnmsac_vx,
    rv_vmadd_vv, rv_vmadd_vx, rv_vnmsub_vv, rv_vnmsub_vx,
    // RVV widening integer MAC forms; append to retain serialized opcode IDs.
    rv_vwmaccu_vv, rv_vwmaccu_vx, rv_vwmacc_vv, rv_vwmacc_vx,
    rv_vwmaccsu_vv, rv_vwmaccsu_vx, rv_vwmaccus_vx,
    // AArch64 conditional compares; append to preserve serialized opcode IDs.
    a64_ccmp, a64_ccmn,
    // EVEX packed integer compare to opmask; append to retain serialized IDs.
    vpcmpb, vpcmpw, vpcmpd, vpcmpq,
    vpcmpub, vpcmpuw, vpcmpud, vpcmpuq,
    // MIPS64 integer extension coverage; append to preserve serialized IDs.
    mips64_movz, mips64_movn, mips64_bltzal, mips64_bgezal,
    mips64_bltzall, mips64_bgezall, mips64_ll, mips64_sc,
    mips64_add, mips64_addu, mips64_sub, mips64_subu, mips64_slt, mips64_sltu,
    mips64_sll, mips64_srl, mips64_sra, mips64_sllv, mips64_srlv, mips64_srav,
    mips64_addi, mips64_addiu, mips64_slti, mips64_sltiu,
    // x86 scalar count/byte-order operations; append to preserve serialized IDs.
    bswap, popcnt,
    // MIPS32 COP1 data/control transfers; appended to preserve serialized IDs.
    mips_mfc1, mips_cfc1, mips_mtc1, mips_ctc1,
    // AArch64 signed word load; append to preserve persisted opcode IDs.
    a64_ldrsw,
    // RVV widening add/sub forms, appended after all prior persisted IDs.
    rv_vwadd_vv, rv_vwadd_vx, rv_vwadd_wv, rv_vwadd_wx,
    rv_vwaddu_vv, rv_vwaddu_vx, rv_vwaddu_wv, rv_vwaddu_wx,
    rv_vwsub_vv, rv_vwsub_vx, rv_vwsub_wv, rv_vwsub_wx,
    rv_vwsubu_vv, rv_vwsubu_vx, rv_vwsubu_wv, rv_vwsubu_wx,
    // Appended RISC-V Zba scalar address-generation forms.
    rv_sh1add, rv_sh2add, rv_sh3add, rv_add_uw, rv_sh1add_uw, rv_sh2add_uw, rv_sh3add_uw, rv_slli_uw,
    // RVV non-accumulating widening integer multiply; appended for ID stability.
    rv_vwmulu_vv, rv_vwmulu_vx, rv_vwmulsu_vv, rv_vwmulsu_vx, rv_vwmul_vv, rv_vwmul_vx,
    // EVEX variable packed shifts; append to preserve persisted opcode IDs.
    vpsllvw, vpsllvd, vpsllvq, vpsrlvw, vpsrlvd, vpsrlvq, vpsravw, vpsravd, vpsravq,
    // RVV floating arithmetic, sign, min/max and compare forms; appended for cache stability.
    rv_vfadd_vv, rv_vfadd_vf, rv_vfsub_vv, rv_vfsub_vf, rv_vfmul_vv, rv_vfmul_vf,
    rv_vfdiv_vv, rv_vfdiv_vf, rv_vfsgnj_vv, rv_vfsgnj_vf, rv_vfsgnjn_vv, rv_vfsgnjn_vf,
    rv_vfsgnjx_vv, rv_vfsgnjx_vf, rv_vfmin_vv, rv_vfmin_vf, rv_vfmax_vv, rv_vfmax_vf,
    rv_vmfeq_vv, rv_vmfeq_vf, rv_vmfne_vv, rv_vmfne_vf, rv_vmflt_vv, rv_vmflt_vf,
    rv_vmfle_vv, rv_vmfle_vf, rv_vmfgt_vf, rv_vmfge_vf,
    // RVV single-width fused floating multiply-add/subtract; append for ID stability.
    rv_vfmacc_vv, rv_vfmacc_vf, rv_vfnmacc_vv, rv_vfnmacc_vf, rv_vfmsac_vv, rv_vfmsac_vf,
    rv_vfnmsac_vv, rv_vfnmsac_vf, rv_vfmadd_vv, rv_vfmadd_vf, rv_vfnmadd_vv, rv_vfnmadd_vf,
    rv_vfmsub_vv, rv_vfmsub_vf, rv_vfnmsub_vv, rv_vfnmsub_vf,
    // Appended AVX packed floating division forms; preserve stored opcode IDs.
    vdivps, vdivpd,
    // AArch64 preserving bitfield move; append to preserve persisted IDs.
    a64_bfm,
    // AVX2 immediate-count packed shifts; append to preserve cache IDs.
    vpsllw, vpslld, vpsllq, vpsrlw, vpsrld, vpsrlq, vpsraw, vpsrad, vpslldq, vpsrldq,
    // Scalar PowerPC FP/integer conversions; preserve persisted IDs.
    ppc_fctiw, ppc_fctiwz, ppc_fctid, ppc_fctidz, ppc_fcfid,
    ppc_fctiwu, ppc_fctiwuz, ppc_fctidu, ppc_fctiduz, ppc_fcfidu, ppc_fcfids,
    // AVX packed signed integer absolute value; preserve persisted opcode IDs.
    vpabsb, vpabsw, vpabsd,
    // MIPS64 conditional trap comparisons; append to preserve persisted IDs.
    mips64_tge, mips64_tgeu, mips64_tlt, mips64_tltu, mips64_teq, mips64_tne,
    // RVV unary square-root and IEEE class mask; appended for ID stability.
    rv_vfsqrt_v, rv_vfclass_v,
    // EVEX packed floating compare-to-opmask forms; append to preserve IDs.
    vcmpps, vcmppd,
    // RVV reciprocal estimate intrinsics; append to preserve cached IDs.
    rv_vfrsqrt7_v, rv_vfrec7_v,
    // x86 wide memory compare-exchange; appended to retain persisted IDs.
    cmpxchg8b, cmpxchg16b,
    // BMI2 scalar integer operations; append to preserve serialized opcode IDs.
    bzhi, mulx, pdep, pext, rorx, sarx, shlx, shrx,
    // MIPS64 REGIMM immediate traps; appended to preserve serialized opcode IDs.
    mips64_tgei, mips64_tgeiu, mips64_tlti, mips64_tltiu, mips64_teqi, mips64_tnei,
    // RVV integer reductions, appended to preserve serialized IDs.
    rv_vredsum, rv_vredand, rv_vredor, rv_vredxor, rv_vredminu, rv_vredmin, rv_vredmaxu, rv_vredmax,
    // Zfa FCVTMOD.W.D, appended to preserve serialized opcode IDs.
    rv_fcvtmod_w_d,
    ppc_fmadd, ppc_fmsub, ppc_fnmadd, ppc_fnmsub,
    ppc_fmadds, ppc_fmsubs, ppc_fnmadds, ppc_fnmsubs,
    // Scalar Zfa load-immediate floating constants; append for cache stability.
    rv_fli_s, rv_fli_d,
    // Zfa round-to-integral forms; appended for cache stability.
    rv_fround_s, rv_froundnx_s, rv_fround_d, rv_froundnx_d,
    // Zfa minimum/maximum-number variants; appended for cache stability.
    rv_fminm_s, rv_fmaxm_s, rv_fminm_d, rv_fmaxm_d,
    // MIPS64 COP1 conditional floating-register moves; append for cache stability.
    mips64_movf_s, mips64_movt_s, mips64_movz_s, mips64_movn_s,
    mips64_movf_d, mips64_movt_d, mips64_movz_d, mips64_movn_d,
    // MIPS64 Release 2 doubleword rotate-right forms; append for stable IDs.
    mips64_drotr, mips64_drotr32, mips64_drotrv,
    // NMOS 6502 undocumented decrement-and-compare family; appended for ID stability.
    m6502_dcp,
    // MIPS32 Release 2 SPECIAL3 variable bitfield operations.
    mips_ext, mips_ins,
    // Stable undocumented NMOS 6502 shift/logical RMW families.
    m6502_slo, m6502_rla, m6502_sre,
    // Stable undocumented NMOS 6502 rotate-then-add family.
    m6502_rra,
    // Stable undocumented NMOS 6502 increment-then-subtract family.
    m6502_isc,
    // NMOS 6502 undocumented load-and-stack-mask form.
    m6502_las,
    // Legacy SSSE3 horizontal integer operations; append for persisted IDs.
    phaddw, phaddd, phaddsw, phsubw, phsubd, phsubsw,
    // SSSE3 byte shuffle; appended to preserve persisted opcode IDs.
    pshufb,
    // MIPS64 pre-Release 6 SPECIAL2 word multiply-accumulate operations.
    mips64_madd, mips64_maddu, mips64_msub, mips64_msubu,
    // Scalar Zfa quiet comparisons; appended to preserve serialized IDs.
    rv_fleq_s, rv_fltq_s, rv_fleq_d, rv_fltq_d,
    // MIPS64 SPECIAL2 word multiply-to-GPR form; append for stable IDs.
    mips64_mul,
    // NMOS 6502 undocumented AND-immediate aliases; appended for stable IDs.
    m6502_anc
};
enum class OperandAccess { read, write, read_write, address };
// The encoded x86 group-one repeat prefix is retained separately from the
// operation: F2/F3 have different stopping rules for CMPS/SCAS than MOVS/LODS/STOS.
enum class X86RepeatPrefix { none, repne, rep };
// Byte coordinates within the original instruction, independent of the value's
// effective width. Implicit operands have no encoded field.
struct EncodedField {
    std::uint8_t offset = 0, size = 0;
    bool operator==(const EncodedField &) const = default;
};
struct RegisterOperand {
    RegisterBank bank;
    std::uint8_t index;
    std::uint16_t width;
    bool high_byte;
    bool operator==(const RegisterOperand &) const = default;
};
struct MemoryOperand {
    std::uint16_t data_width = 0, address_width = 64;
    std::optional<RegisterOperand> segment, base, index;
    std::uint8_t scale = 1;
    std::int64_t displacement = 0;
    bool ip_relative = false;
    std::optional<Address> resolved_address;
    std::optional<EncodedField> displacement_encoding;
    // A64 register-offset memory forms keep the extension and optional
    // scaled shift explicit instead of flattening them into a byte scale.
    std::string index_extend;
    std::uint8_t index_shift_amount = 0;
    bool writeback = false;
    bool post_index = false;
    std::int64_t writeback_displacement = 0;
};
struct ImmediateOperand {
    std::uint64_t value;
    std::uint16_t encoded_width, effective_width;
    bool is_signed;
    std::optional<EncodedField> encoding;
};
struct RelativeOperand {
    std::int64_t displacement;
    std::uint16_t encoded_width;
    std::uint16_t effective_width = 0;
    std::optional<EncodedField> encoding;
};
struct FarPointerOperand {
    std::uint16_t selector;
    std::uint32_t offset;
    std::uint16_t offset_width;
    std::optional<EncodedField> offset_encoding, selector_encoding;
    bool operator==(const FarPointerOperand &) const = default;
};
struct FarMemoryOperand {
    MemoryOperand address;
    std::uint16_t offset_width;
};
enum class ArmShift { lsl, lsr, asr, ror, rrx };
struct ArmShiftedRegisterOperand {
    RegisterOperand source;
    ArmShift shift = ArmShift::lsl;
    std::uint8_t amount = 0;
    std::optional<RegisterOperand> amount_register;
    bool operator==(const ArmShiftedRegisterOperand &) const = default;
};
struct ArmMemoryOperand {
    RegisterOperand base;
    std::variant<std::uint32_t, ArmShiftedRegisterOperand> offset = std::uint32_t{0};
    bool add = true, pre_index = true, writeback = false;
    std::uint16_t data_width = 32;
    bool sign_extend = false;
    std::optional<Address> resolved_address;
    bool operator==(const ArmMemoryOperand &) const = default;
};
struct ArmRegisterListOperand {
    std::uint16_t mask = 0;
    bool operator==(const ArmRegisterListOperand &) const = default;
};
// Packed Thumb branch fields have different scaling/ranges from A32 fields.
struct ThumbRelativeOperand {
    std::int64_t displacement = 0;
    std::uint16_t encoded_width = 0;
    bool operator==(const ThumbRelativeOperand &) const = default;
};
// Preserve existing variant indexes for canonical data; append new forms.
using Operand =
    std::variant<RegisterOperand, MemoryOperand, ImmediateOperand, RelativeOperand, FarPointerOperand, FarMemoryOperand,
                 ArmShiftedRegisterOperand, ArmMemoryOperand, ArmRegisterListOperand, ThumbRelativeOperand>;
enum class ArmPredicate { always, condition, unknown_it };
enum class ArmExchange { none, address_bit0, forced_a32, forced_thumb };
enum class ArmMultipleMode { ia, ib, da, db };
// Known zero means outside an IT block; unknown must not invent a predicate.
struct ThumbITState {
    bool known = false;
    std::uint8_t bits = 0;
    bool operator==(const ThumbITState &) const = default;
};
struct ArmInstructionInfo {
    ArmPredicate predicate = ArmPredicate::always;
    ArmExchange exchange = ArmExchange::none;
    // NZCV bits, in architectural order (N=8, Z=4, C=2, V=1).
    std::uint8_t flags_written = 0;
    bool flags_known = true;
    bool writes_pc = false, writeback = false;
    ArmMultipleMode multiple_mode = ArmMultipleMode::ia;
    ThumbITState it_before, it_after;
    std::optional<ExecutionMode> target_mode, return_mode;
    // Physical address, preserving its domain; Thumb state lives in return_mode.
    std::optional<Address> link_address;
    bool operator==(const ArmInstructionInfo &) const = default;
};
struct DexSwitchCase {
    std::int32_t value = 0;
    Address target{{0}, 0};
    // Source bytes in the DEX file. Packed keys all derive from first_key;
    // sparse keys each have their own source word.
    FileOffset key_source{0}, target_source{0};
    bool operator==(const DexSwitchCase &) const = default;
};
struct DexSwitchTable {
    bool packed = false;
    Address payload{{0}, 0};
    // True only after the payload has been read and validated against source bytes.
    bool validated = false;
    std::vector<DexSwitchCase> cases;
    FileOffset payload_source{0};
    std::uint32_t payload_bytes = 0;
    bool operator==(const DexSwitchTable &) const = default;
};
struct JvmSwitchCase {
    std::int32_t value = 0;
    Address target{{0}, 0};
    bool operator==(const JvmSwitchCase &) const = default;
};
struct JvmSwitchTable {
    bool dense = false; // tableswitch when true, lookupswitch when false.
    Address default_target{{0}, 0};
    std::vector<JvmSwitchCase> cases;
    bool operator==(const JvmSwitchTable &) const = default;
};
struct Instruction {
    DecodeContext context;
    Address address{{0}, 0};
    std::array<std::byte, 15> bytes{};
    // Full encoded byte count. Most native instructions fit the legacy
    // 15-byte buffer; extended bytecode instructions retain their full bytes
    // in extended_bytes without truncating this extent.
    std::uint32_t length = 0;
    Opcode opcode = Opcode::nop;
    std::string mnemonic_override;
    std::vector<Operand> operands;
    std::vector<OperandAccess> access;
    std::vector<RegisterOperand> register_reads, register_writes;
    FlowKind flow = FlowKind::fallthrough;
    std::optional<Address> direct_target;
    std::optional<DexSwitchTable> dex_switch;
    std::optional<JvmSwitchTable> jvm_switch;
    std::uint8_t condition = 0;
    // Set for x86 Jcc instructions; condition remains for compatibility with
    // existing architecture-neutral clients.
    std::optional<X86Condition> x86_condition;
    std::optional<X86LoopCondition> x86_loop_condition;
    std::uint16_t x86_loop_counter_width = 0;
    X86RepeatPrefix x86_repeat = X86RepeatPrefix::none;
    // EVEX writemask decorator. K0 means unmasked and is represented by an
    // empty optional; a present index is 1..7. Zeroing applies only to the
    // destination's inactive vector elements.
    bool x86_evex = false;
    // EVEX.b memory tuple broadcast for the supported packed FP arithmetic
    // subset. The memory operand width is one lane, replicated by the op.
    bool x86_evex_broadcast = false;
    // EVEX.b embedded suppress-all-exceptions decoration on packed compares.
    bool x86_evex_sae = false;
    std::optional<std::uint8_t> x86_opmask;
    bool x86_opmask_zeroing = false;
    bool memory_read = false, memory_write = false;
    std::uint16_t stack_value_width = 0;
    std::uint8_t stack_slot_count = 0;
    // x87 stack depth change: +1 pushes a value, -1 pops one value.
    std::int8_t x87_stack_delta = 0;
    bool lock_prefix = false;
    std::optional<ArmInstructionInfo> arm;
    // Number of architecturally executed instructions after a control transfer
    // before its target takes effect. Zero for architectures without delay slots.
    std::uint8_t delay_slots = 0;
    bool atomic_aq = false, atomic_rl = false;
    // RISC-V CSR state is separate from the integer register and memory banks.
    bool csr_read = false, csr_write = false;
    std::optional<std::uint8_t> rounding_mode;
    bool writes_fflags = false;
    bool riscv_vector_masked = false;
    // Vector operation shape. vector_bits is the architectural register width;
    // vector_element_bits is zero when the operation has no lane interpretation.
    std::uint16_t vector_bits = 0, vector_element_bits = 0;
    // Some bytecode formats have variable-width instructions larger than the
    // native instruction-byte buffer. Retain the full encoding only then.
    std::vector<std::byte> extended_bytes;
    // RVV floating arithmetic reads the dynamic RISC-V frm control field.
    bool reads_frm = false;
    // Accrued exception flags are sticky, so vector FP operations read old fflags.
    bool reads_fflags = false;
    std::size_t byte_length() const noexcept { return length; }
    std::span<const std::byte> encoded_bytes() const noexcept {
        if (!extended_bytes.empty()) return extended_bytes;
        if (length > bytes.size()) return {};
        return std::span<const std::byte>(bytes).first(length);
    }
};
struct DecodeResult {
    DecodeStatus status;
    std::optional<Instruction> instruction;
    std::string reason;
};
} // namespace hexlab

