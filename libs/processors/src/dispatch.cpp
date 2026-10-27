#include "x64_internal.hpp"
#include "capstone_fallback.hpp"
#include "hexlab/processors/riscv.hpp"
#include <algorithm>
#include <array>
namespace hexlab {
namespace {
DecodeResult decode_riscv_context(DecodeContext context, std::span<const std::byte> bytes, Address at) {
    const bool rv32 = context.mode == ExecutionMode::rv32;
    auto result = rv32 ? decode_riscv32(bytes, at)
                       : context.mode == ExecutionMode::rv64c ? decode_riscv64c(bytes, at) : decode_riscv64(bytes, at);
    if (!result.instruction)
        return {result.status, {}, std::move(result.reason)};
    const auto &source = *result.instruction;
    const std::uint8_t register_width = rv32 ? 32 : 64;
    static constexpr std::array<Opcode, 60> opcodes{
        Opcode::rv_lui, Opcode::rv_auipc, Opcode::rv_jal, Opcode::rv_jalr,
        Opcode::rv_beq, Opcode::rv_bne, Opcode::rv_blt, Opcode::rv_bge, Opcode::rv_bltu, Opcode::rv_bgeu,
        Opcode::rv_lb, Opcode::rv_lh, Opcode::rv_lw, Opcode::rv_ld, Opcode::rv_lbu, Opcode::rv_lhu, Opcode::rv_lwu,
        Opcode::rv_sb, Opcode::rv_sh, Opcode::rv_sw, Opcode::rv_sd,
        Opcode::rv_addi, Opcode::rv_slti, Opcode::rv_sltiu, Opcode::rv_xori, Opcode::rv_ori, Opcode::rv_andi,
        Opcode::rv_slli, Opcode::rv_srli, Opcode::rv_srai,
        Opcode::rv_add, Opcode::rv_sub, Opcode::rv_sll, Opcode::rv_slt, Opcode::rv_sltu, Opcode::rv_xor,
        Opcode::rv_srl, Opcode::rv_sra, Opcode::rv_or, Opcode::rv_and,
        Opcode::rv_fence, Opcode::rv_ecall, Opcode::rv_ebreak,
        Opcode::rv_addiw, Opcode::rv_slliw, Opcode::rv_srliw, Opcode::rv_sraiw,
        Opcode::rv_addw, Opcode::rv_subw, Opcode::rv_sllw, Opcode::rv_srlw, Opcode::rv_sraw,
        Opcode::rv_mul, Opcode::rv_mulh, Opcode::rv_mulhsu, Opcode::rv_mulhu, Opcode::rv_div, Opcode::rv_divu,
        Opcode::rv_rem, Opcode::rv_remu};
    // RV64 word and M-extension word forms follow the base table.
    static constexpr std::array<Opcode, 5> word_m{Opcode::rv_mulw, Opcode::rv_divw, Opcode::rv_divuw,
                                                   Opcode::rv_remw, Opcode::rv_remuw};
    static constexpr std::array<Opcode, 22> atomics{
        Opcode::rv_lr_w, Opcode::rv_sc_w, Opcode::rv_amoswap_w, Opcode::rv_amoadd_w, Opcode::rv_amoxor_w,
        Opcode::rv_amoand_w, Opcode::rv_amoor_w, Opcode::rv_amomin_w, Opcode::rv_amomax_w,
        Opcode::rv_amominu_w, Opcode::rv_amomaxu_w, Opcode::rv_lr_d, Opcode::rv_sc_d, Opcode::rv_amoswap_d,
        Opcode::rv_amoadd_d, Opcode::rv_amoxor_d, Opcode::rv_amoand_d, Opcode::rv_amoor_d,
        Opcode::rv_amomin_d, Opcode::rv_amomax_d, Opcode::rv_amominu_d, Opcode::rv_amomaxu_d};
    static constexpr std::array<Opcode, 6> csrs{Opcode::rv_csrrw, Opcode::rv_csrrs, Opcode::rv_csrrc,
                                                 Opcode::rv_csrrwi, Opcode::rv_csrrsi, Opcode::rv_csrrci};
    static constexpr std::array<Opcode, 62> fp_ops{
        Opcode::rv_flw,Opcode::rv_fld,Opcode::rv_fsw,Opcode::rv_fsd,
        Opcode::rv_fadd_s,Opcode::rv_fsub_s,Opcode::rv_fmul_s,Opcode::rv_fdiv_s,Opcode::rv_fsqrt_s,Opcode::rv_fsgnj_s,Opcode::rv_fsgnjn_s,Opcode::rv_fsgnjx_s,Opcode::rv_fmin_s,Opcode::rv_fmax_s,Opcode::rv_fmadd_s,Opcode::rv_fmsub_s,Opcode::rv_fnmsub_s,Opcode::rv_fnmadd_s,Opcode::rv_feq_s,Opcode::rv_flt_s,Opcode::rv_fle_s,Opcode::rv_fclass_s,Opcode::rv_fcvt_w_s,Opcode::rv_fcvt_wu_s,Opcode::rv_fcvt_l_s,Opcode::rv_fcvt_lu_s,Opcode::rv_fcvt_s_w,Opcode::rv_fcvt_s_wu,Opcode::rv_fcvt_s_l,Opcode::rv_fcvt_s_lu,Opcode::rv_fmv_x_w,Opcode::rv_fmv_w_x,
        Opcode::rv_fadd_d,Opcode::rv_fsub_d,Opcode::rv_fmul_d,Opcode::rv_fdiv_d,Opcode::rv_fsqrt_d,Opcode::rv_fsgnj_d,Opcode::rv_fsgnjn_d,Opcode::rv_fsgnjx_d,Opcode::rv_fmin_d,Opcode::rv_fmax_d,Opcode::rv_fmadd_d,Opcode::rv_fmsub_d,Opcode::rv_fnmsub_d,Opcode::rv_fnmadd_d,Opcode::rv_feq_d,Opcode::rv_flt_d,Opcode::rv_fle_d,Opcode::rv_fclass_d,Opcode::rv_fcvt_w_d,Opcode::rv_fcvt_wu_d,Opcode::rv_fcvt_l_d,Opcode::rv_fcvt_lu_d,Opcode::rv_fcvt_d_w,Opcode::rv_fcvt_d_wu,Opcode::rv_fcvt_d_l,Opcode::rv_fcvt_d_lu,Opcode::rv_fcvt_s_d,Opcode::rv_fcvt_d_s,Opcode::rv_fmv_x_d,Opcode::rv_fmv_d_x};
    const auto opcode_index = static_cast<std::size_t>(source.opcode);
    Opcode opcode;
    if (opcode_index < opcodes.size())
        opcode = opcodes[opcode_index];
    else if (opcode_index >= 60 && opcode_index < 65)
        opcode = word_m[opcode_index - 60];
    else if (opcode_index >= 65 && opcode_index < 87)
        opcode = atomics[opcode_index - 65];
    else if (opcode_index >= 87 && opcode_index < 93)
        opcode = csrs[opcode_index - 87];
    else if (opcode_index >= 93 && opcode_index < 155)
        opcode = fp_ops[opcode_index - 93];
    else if (opcode_index >= 155 && opcode_index <= 157)
        opcode = std::array{Opcode::rv_vsetvli, Opcode::rv_vsetivli, Opcode::rv_vsetvl}[opcode_index - 155];
    else if (opcode_index >= 158 && opcode_index <= 171)
        opcode = std::array{Opcode::rv_vadd_vv, Opcode::rv_vadd_vx, Opcode::rv_vadd_vi,
                            Opcode::rv_vsub_vv, Opcode::rv_vsub_vx, Opcode::rv_vand_vv,
                            Opcode::rv_vand_vx, Opcode::rv_vand_vi, Opcode::rv_vor_vv,
                            Opcode::rv_vor_vx, Opcode::rv_vor_vi, Opcode::rv_vxor_vv,
                            Opcode::rv_vxor_vx, Opcode::rv_vxor_vi}[opcode_index - 158];
    else if (opcode_index == 172)
        opcode = Opcode::rv_vle;
    else if (opcode_index == 173)
        opcode = Opcode::rv_vse;
    else if (opcode_index >= 174 && opcode_index <= 193)
        opcode = std::array{
            Opcode::rv_vmseq_vv, Opcode::rv_vmseq_vx, Opcode::rv_vmseq_vi,
            Opcode::rv_vmsne_vv, Opcode::rv_vmsne_vx, Opcode::rv_vmsne_vi,
            Opcode::rv_vmsltu_vv, Opcode::rv_vmsltu_vx, Opcode::rv_vmslt_vv, Opcode::rv_vmslt_vx,
            Opcode::rv_vmsleu_vv, Opcode::rv_vmsleu_vx, Opcode::rv_vmsleu_vi,
            Opcode::rv_vmsle_vv, Opcode::rv_vmsle_vx, Opcode::rv_vmsle_vi,
            Opcode::rv_vmsgtu_vx, Opcode::rv_vmsgtu_vi, Opcode::rv_vmsgt_vx, Opcode::rv_vmsgt_vi
        }[opcode_index - 174];
    else if (opcode_index >= 194 && opcode_index <= 210)
        opcode = std::array{Opcode::rv_vsll_vv, Opcode::rv_vsll_vx, Opcode::rv_vsll_vi,
            Opcode::rv_vsrl_vv, Opcode::rv_vsrl_vx, Opcode::rv_vsrl_vi,
            Opcode::rv_vsra_vv, Opcode::rv_vsra_vx, Opcode::rv_vsra_vi,
            Opcode::rv_vminu_vv, Opcode::rv_vminu_vx, Opcode::rv_vmin_vv, Opcode::rv_vmin_vx,
            Opcode::rv_vmaxu_vv, Opcode::rv_vmaxu_vx, Opcode::rv_vmax_vv, Opcode::rv_vmax_vx}[opcode_index - 194];
    else if (opcode_index == 211 || opcode_index == 212)
        opcode = std::array{Opcode::rv_vrsub_vx, Opcode::rv_vrsub_vi}[opcode_index - 211];
    else if (opcode_index >= 213 && opcode_index <= 220)
        opcode = std::array{Opcode::rv_vmul_vv, Opcode::rv_vmul_vx, Opcode::rv_vmulh_vv, Opcode::rv_vmulh_vx,
                            Opcode::rv_vmulhu_vv, Opcode::rv_vmulhu_vx,
                            Opcode::rv_vmulhsu_vv, Opcode::rv_vmulhsu_vx}[opcode_index - 213];
    else if (opcode_index >= 221 && opcode_index <= 228)
        opcode = std::array{Opcode::rv_vdivu_vv, Opcode::rv_vdivu_vx, Opcode::rv_vdiv_vv, Opcode::rv_vdiv_vx,
                            Opcode::rv_vremu_vv, Opcode::rv_vremu_vx, Opcode::rv_vrem_vv, Opcode::rv_vrem_vx}[opcode_index - 221];
    else if (opcode_index == 229)
        opcode = Opcode::rv_vlse;
    else if (opcode_index == 230)
        opcode = Opcode::rv_vsse;
    else if (opcode_index >= 231 && opcode_index <= 237)
        opcode = std::array{Opcode::rv_vrgather_vv, Opcode::rv_vrgather_vx, Opcode::rv_vrgather_vi,
                            Opcode::rv_vslideup_vx, Opcode::rv_vslideup_vi,
                            Opcode::rv_vslidedown_vx, Opcode::rv_vslidedown_vi}[opcode_index - 231];
    else if (opcode_index >= 238 && opcode_index <= 241)
        opcode = std::array{Opcode::rv_vluxei, Opcode::rv_vloxei, Opcode::rv_vsuxei, Opcode::rv_vsoxei}
            [opcode_index - 238];
    else if (opcode_index >= 242 && opcode_index <= 247)
        opcode = std::array{Opcode::rv_clz, Opcode::rv_ctz, Opcode::rv_cpop,
                            Opcode::rv_clzw, Opcode::rv_ctzw, Opcode::rv_cpopw}[opcode_index - 242];
    else if (opcode_index >= 248 && opcode_index <= 255)
        opcode = std::array{Opcode::rv_vmacc_vv, Opcode::rv_vmacc_vx, Opcode::rv_vnmsac_vv,
                            Opcode::rv_vnmsac_vx, Opcode::rv_vmadd_vv, Opcode::rv_vmadd_vx,
                            Opcode::rv_vnmsub_vv, Opcode::rv_vnmsub_vx}[opcode_index - 248];
    else if (opcode_index >= 256 && opcode_index <= 262)
        opcode = std::array{Opcode::rv_vwmaccu_vv, Opcode::rv_vwmaccu_vx,
                            Opcode::rv_vwmacc_vv, Opcode::rv_vwmacc_vx,
                            Opcode::rv_vwmaccsu_vv, Opcode::rv_vwmaccsu_vx,
                            Opcode::rv_vwmaccus_vx}[opcode_index - 256];
    else if (opcode_index >= 263 && opcode_index <= 278)
        opcode = std::array{Opcode::rv_vwadd_vv, Opcode::rv_vwadd_vx, Opcode::rv_vwadd_wv, Opcode::rv_vwadd_wx,
            Opcode::rv_vwaddu_vv, Opcode::rv_vwaddu_vx, Opcode::rv_vwaddu_wv, Opcode::rv_vwaddu_wx,
            Opcode::rv_vwsub_vv, Opcode::rv_vwsub_vx, Opcode::rv_vwsub_wv, Opcode::rv_vwsub_wx,
            Opcode::rv_vwsubu_vv, Opcode::rv_vwsubu_vx, Opcode::rv_vwsubu_wv, Opcode::rv_vwsubu_wx}[opcode_index - 263];
    else if (opcode_index >= 279 && opcode_index <= 286)
        opcode = std::array{Opcode::rv_sh1add, Opcode::rv_sh2add, Opcode::rv_sh3add, Opcode::rv_add_uw,
            Opcode::rv_sh1add_uw, Opcode::rv_sh2add_uw, Opcode::rv_sh3add_uw, Opcode::rv_slli_uw}
            [opcode_index - 279];
    else if (opcode_index >= 287 && opcode_index <= 292)
        opcode = std::array{Opcode::rv_vwmulu_vv, Opcode::rv_vwmulu_vx, Opcode::rv_vwmulsu_vv,
            Opcode::rv_vwmulsu_vx, Opcode::rv_vwmul_vv, Opcode::rv_vwmul_vx}[opcode_index - 287];
    else if (opcode_index >= 293 && opcode_index <= 320)
        opcode = std::array{Opcode::rv_vfadd_vv, Opcode::rv_vfadd_vf, Opcode::rv_vfsub_vv, Opcode::rv_vfsub_vf,
            Opcode::rv_vfmul_vv, Opcode::rv_vfmul_vf, Opcode::rv_vfdiv_vv, Opcode::rv_vfdiv_vf,
            Opcode::rv_vfsgnj_vv, Opcode::rv_vfsgnj_vf, Opcode::rv_vfsgnjn_vv, Opcode::rv_vfsgnjn_vf,
            Opcode::rv_vfsgnjx_vv, Opcode::rv_vfsgnjx_vf, Opcode::rv_vfmin_vv, Opcode::rv_vfmin_vf,
            Opcode::rv_vfmax_vv, Opcode::rv_vfmax_vf, Opcode::rv_vmfeq_vv, Opcode::rv_vmfeq_vf,
            Opcode::rv_vmfne_vv, Opcode::rv_vmfne_vf, Opcode::rv_vmflt_vv, Opcode::rv_vmflt_vf,
            Opcode::rv_vmfle_vv, Opcode::rv_vmfle_vf, Opcode::rv_vmfgt_vf, Opcode::rv_vmfge_vf}[opcode_index - 293];
    else if (opcode_index >= 321 && opcode_index <= 336)
        opcode = std::array{Opcode::rv_vfmacc_vv, Opcode::rv_vfmacc_vf, Opcode::rv_vfnmacc_vv, Opcode::rv_vfnmacc_vf,
            Opcode::rv_vfmsac_vv, Opcode::rv_vfmsac_vf, Opcode::rv_vfnmsac_vv, Opcode::rv_vfnmsac_vf,
            Opcode::rv_vfmadd_vv, Opcode::rv_vfmadd_vf, Opcode::rv_vfnmadd_vv, Opcode::rv_vfnmadd_vf,
            Opcode::rv_vfmsub_vv, Opcode::rv_vfmsub_vf, Opcode::rv_vfnmsub_vv, Opcode::rv_vfnmsub_vf}[opcode_index - 321];
    else if (opcode_index == 337 || opcode_index == 338)
        opcode = std::array{Opcode::rv_vfsqrt_v, Opcode::rv_vfclass_v}[opcode_index - 337];
    else if (opcode_index == 339 || opcode_index == 340)
        opcode = std::array{Opcode::rv_vfrsqrt7_v, Opcode::rv_vfrec7_v}[opcode_index - 339];
    else if (opcode_index >= 341 && opcode_index <= 348)
        opcode = std::array{Opcode::rv_vredsum, Opcode::rv_vredand, Opcode::rv_vredor, Opcode::rv_vredxor,
            Opcode::rv_vredminu, Opcode::rv_vredmin, Opcode::rv_vredmaxu, Opcode::rv_vredmax}[opcode_index - 341];
    else if (opcode_index == 349)
        opcode = Opcode::rv_fcvtmod_w_d;
    else if (opcode_index == 350 || opcode_index == 351)
        opcode = opcode_index == 350 ? Opcode::rv_fli_s : Opcode::rv_fli_d;
    else if (opcode_index >= 352 && opcode_index <= 355)
        opcode = std::array{Opcode::rv_fround_s, Opcode::rv_froundnx_s,
                            Opcode::rv_fround_d, Opcode::rv_froundnx_d}[opcode_index - 352];
    else if (opcode_index >= 356 && opcode_index <= 359)
        opcode = std::array{Opcode::rv_fminm_s, Opcode::rv_fmaxm_s,
                            Opcode::rv_fminm_d, Opcode::rv_fmaxm_d}[opcode_index - 356];
    else if (opcode_index >= 360 && opcode_index <= 363)
        opcode = std::array{Opcode::rv_fleq_s, Opcode::rv_fltq_s,
                            Opcode::rv_fleq_d, Opcode::rv_fltq_d}[opcode_index - 360];
    else if (source.opcode == RiscvOpcode::fence_i)
        opcode = Opcode::rv_fence_i;
    else
        return {DecodeStatus::invalid, {}, "RV64 opcode has no generic representation"};

    Instruction instruction;
    instruction.context = context;
    instruction.address = source.address;
    instruction.bytes = {};
    std::copy_n(source.bytes.begin(), source.length, instruction.bytes.begin());
    instruction.length = source.length;
    instruction.opcode = opcode;
    instruction.flow = static_cast<FlowKind>(source.flow);
    instruction.direct_target = source.direct_target;
    instruction.memory_read = source.memory_read;
    instruction.memory_write = source.memory_write;
    instruction.atomic_aq = source.atomic_aq;
    instruction.atomic_rl = source.atomic_rl;
    instruction.csr_read = source.csr_read;
    instruction.csr_write = source.csr_write;
    instruction.rounding_mode = source.rounding_mode;
    instruction.writes_fflags = source.writes_fflags;
    instruction.riscv_vector_masked = source.vector_masked;
    instruction.reads_frm = source.reads_frm;
    instruction.reads_fflags = source.reads_fflags;
    for (const auto &operand : source.operands) {
        instruction.operands.push_back(std::visit([register_width](const auto &part) -> Operand {
            using T = std::decay_t<decltype(part)>;
            if constexpr (std::is_same_v<T, RiscvRegister>)
                return RegisterOperand{part.vector_configuration ? RegisterBank::riscv_vcsr : part.vector ? RegisterBank::riscv_vpr : part.floating_point ? RegisterBank::riscv_fpr : RegisterBank::riscv_gpr, part.index, static_cast<std::uint8_t>(part.vector ? 0 : part.floating_point ? 64 : register_width), false};
            else if constexpr (std::is_same_v<T, RiscvImmediate>)
                return ImmediateOperand{static_cast<std::uint64_t>(part.value), part.encoded_width, register_width, part.is_signed, {}};
            else if constexpr (std::is_same_v<T, RiscvMemory>)
                return MemoryOperand{part.width, register_width, {},
                                     RegisterOperand{RegisterBank::riscv_gpr, part.base.index, register_width, false}, {}, 1,
                                     part.displacement, false, {}, {}};
            else
                return RelativeOperand{part.displacement, part.encoded_width, register_width, {}};
        }, operand));
    }
    for (auto access : source.access)
        instruction.access.push_back(static_cast<OperandAccess>(access));
    for (auto reg : source.register_reads)
        instruction.register_reads.push_back({reg.vector_configuration ? RegisterBank::riscv_vcsr : reg.vector ? RegisterBank::riscv_vpr : reg.floating_point ? RegisterBank::riscv_fpr : RegisterBank::riscv_gpr, reg.index, static_cast<std::uint8_t>(reg.vector ? 0 : reg.floating_point ? 64 : register_width), false});
    // riscv_fstatus index 1 is the three-bit frm alias in architectural FCSR;
    // index 0 remains the five-bit fflags field written by FP operations.
    if (source.reads_frm)
        instruction.register_reads.push_back({RegisterBank::riscv_fstatus, 1, 3, false});
    if (source.reads_fflags)
        instruction.register_reads.push_back({RegisterBank::riscv_fstatus, 0, 5, false});
    for (auto reg : source.register_writes)
        instruction.register_writes.push_back({reg.vector_configuration ? RegisterBank::riscv_vcsr : reg.vector ? RegisterBank::riscv_vpr : reg.floating_point ? RegisterBank::riscv_fpr : RegisterBank::riscv_gpr, reg.index, static_cast<std::uint8_t>(reg.vector ? 0 : reg.floating_point ? 64 : register_width), false});
    if (source.writes_fflags)
        instruction.register_writes.push_back({RegisterBank::riscv_fstatus, 0, 5, false});
    return {DecodeStatus::decoded, std::move(instruction), {}};
}
} // namespace
std::uint32_t control_operand_index(const Instruction &instruction) noexcept {
    if ((instruction.context.architecture == Architecture::riscv64 || instruction.context.architecture == Architecture::riscv32) &&
        (instruction.flow == FlowKind::conditional_branch || instruction.flow == FlowKind::call ||
         instruction.flow == FlowKind::jump))
        for (std::uint32_t i = 0; i < instruction.operands.size(); ++i)
            if (std::holds_alternative<RelativeOperand>(instruction.operands[i]))
                return i;
    if (instruction.context.architecture == Architecture::arm ||
        (instruction.context.architecture == Architecture::arm64 && instruction.context.mode == ExecutionMode::a64))
        for (std::uint32_t i = 0; i < instruction.operands.size(); ++i)
            if (std::holds_alternative<RelativeOperand>(instruction.operands[i]) ||
                std::holds_alternative<ThumbRelativeOperand>(instruction.operands[i]))
                return i;
    return 0;
}
ProcessorCapabilities processor_capabilities(DecodeContext context) noexcept {
    if (context.order != ByteOrder::little && context.architecture != Architecture::powerpc &&
        context.architecture != Architecture::mips32 && context.architecture != Architecture::mips64)
        return {false, 0, {}, "This processor byte order has no enabled decoder"};
    if (context.architecture == Architecture::arm && context.mode == ExecutionMode::thumb) {
        if (context.segmented_memory || context.stack_address_width)
            return {false, 0, {}, "Thumb does not use x86 segmentation or stack-address overrides"};
        return {true, 4, "Thumb scalar subset", {}};
    }
    if (context.architecture == Architecture::arm && context.mode == ExecutionMode::a32) {
        if (context.segmented_memory || context.stack_address_width)
            return {false, 0, {}, "A32 does not use x86 segmentation or stack-address overrides"};
        return {true, 4, "A32 scalar subset", {}};
    }
    if (context.architecture == Architecture::arm64 && context.mode == ExecutionMode::a64) {
        if (context.segmented_memory || context.stack_address_width)
            return {false, 0, {}, "A64 does not use x86 segmentation or stack-address overrides"};
        return {true, 4, "AArch64 scalar subset", {}};
    }
    if (context.architecture == Architecture::riscv64 &&
        (context.mode == ExecutionMode::rv64 || context.mode == ExecutionMode::rv64c)) {
        if (context.segmented_memory || context.stack_address_width)
            return {false, 0, {}, "RV64 does not use x86 segmentation or stack-address overrides"};
        return {true, 4, context.mode == ExecutionMode::rv64c ? "RV64IC scalar subset plus RVV configuration" : "RV64I/M scalar subset plus RVV configuration", {}};
    }
    if (context.architecture == Architecture::riscv32 && context.mode == ExecutionMode::rv32) {
        if (context.segmented_memory || context.stack_address_width)
            return {false, 0, {}, "RV32 does not use x86 segmentation or stack-address overrides"};
        return {true, 4, "RV32I/M scalar subset plus RVV configuration", {}};
    }
    if (context.architecture == Architecture::mips32 && context.mode == ExecutionMode::mips32) {
        if (context.segmented_memory || context.stack_address_width)
            return {false, 0, {}, "MIPS32 does not use x86 segmentation or stack-address overrides"};
        return {true, 4, context.order == ByteOrder::little ? "MIPS32 little-endian scalar and system-register subset"
                                                              : "MIPS32 big-endian scalar and system-register subset", {}};
    }
    if (context.architecture == Architecture::mips64 && context.mode == ExecutionMode::mips64) {
        if (context.segmented_memory || context.stack_address_width)
            return {false, 0, {}, "MIPS64 does not use x86 segmentation or stack-address overrides"};
        return {true, 4, context.order == ByteOrder::little ? "MIPS64 little-endian integer and scalar COP1 subset"
                                                             : "MIPS64 big-endian integer and scalar COP1 subset", {}};
    }
    if (context.architecture == Architecture::powerpc &&
        (context.mode == ExecutionMode::ppc32 || context.mode == ExecutionMode::ppc64)) {
        if (context.segmented_memory || context.stack_address_width)
            return {false, 0, {}, "PowerPC does not use x86 segmentation or stack-address overrides"};
        return {true, 4, context.mode == ExecutionMode::ppc32 ? "PowerPC 32-bit integer subset" : "PowerPC 64-bit integer subset", {}};
    }
    if (context.architecture == Architecture::wasm && context.mode == ExecutionMode::wasm32) {
        if (context.segmented_memory || context.stack_address_width)
            return {false, 0, {}, "WebAssembly does not use x86 segmentation or stack-address overrides"};
        return {true, 15, "WebAssembly 1.0 scalar operators", {}};
    }
    if (context.architecture == Architecture::dex && context.mode == ExecutionMode::dex) {
        if (context.order != ByteOrder::little || context.segmented_memory || context.stack_address_width)
            return {false, 0, {}, "Dalvik DEX uses little-endian 16-bit code units without x86 address overrides"};
        return {true, 10, "Dalvik DEX core instruction formats", {}};
    }
    if (context.architecture == Architecture::jvm && context.mode == ExecutionMode::jvm) {
        if (context.order != ByteOrder::big || context.segmented_memory || context.stack_address_width)
            return {false, 0, {}, "JVM classfile bytecode uses big-endian operands without x86 address overrides"};
        return {true, 255, "JVM classfile bytecodes with bounded switch decoding", {}};
    }
    if (context.architecture == Architecture::mos6502 && context.mode == ExecutionMode::m6502) {
        if (context.segmented_memory || context.stack_address_width)
            return {false, 0, {}, "6502 does not use x86 segmentation or stack-address overrides"};
        return {true, 3, "MOS 6502 scalar subset", {}};
    }
    if (context.architecture == Architecture::x86_64 && context.mode == ExecutionMode::x86_64) {
        if (context.segmented_memory)
            return {false, 0, {}, "This segmented address model requires legacy x86 mode"};
        if (context.stack_address_width != 0 && context.stack_address_width != 64)
            return {false, 0, {}, "Long mode requires64-bit stack addressing"};
        return {true, 15, "x86-64 scalar subset", {}};
    }
    if (context.architecture == Architecture::x86 &&
        (context.mode == ExecutionMode::x86_16 || context.mode == ExecutionMode::x86_32) &&
        context.stack_address_width != 0 && context.stack_address_width != 16 && context.stack_address_width != 32)
        return {false, 0, {}, "Legacy stack address size must be16 or32"};
    if (context.architecture == Architecture::x86 && context.mode == ExecutionMode::x86_32)
        return {true, 15, "x86-32 scalar subset", {}};
    if (context.architecture == Architecture::x86 && context.mode == ExecutionMode::x86_16)
        return {true, 15, "x86-16 scalar subset", {}};
    return {false, 0, {}, "This architecture and execution mode have no enabled decoder"};
}
std::span<const ProcessorVariantInfo> processor_variant_inventory() noexcept {
    static constexpr std::array variants{
        ProcessorVariantInfo{"x86-16", {Architecture::x86, ExecutionMode::x86_16, ByteOrder::little}, {}},
        ProcessorVariantInfo{"x86-32", {Architecture::x86, ExecutionMode::x86_32, ByteOrder::little}, {}},
        ProcessorVariantInfo{"x86-64", {Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little}, {}},
        ProcessorVariantInfo{"a32", {Architecture::arm, ExecutionMode::a32, ByteOrder::little}, {}},
        ProcessorVariantInfo{"thumb", {Architecture::arm, ExecutionMode::thumb, ByteOrder::little}, {}},
        ProcessorVariantInfo{"a64", {Architecture::arm64, ExecutionMode::a64, ByteOrder::little}, {}},
        ProcessorVariantInfo{"rv32", {Architecture::riscv32, ExecutionMode::rv32, ByteOrder::little}, {}},
        ProcessorVariantInfo{"rv64", {Architecture::riscv64, ExecutionMode::rv64, ByteOrder::little}, {}},
        ProcessorVariantInfo{"rv64c", {Architecture::riscv64, ExecutionMode::rv64c, ByteOrder::little}, {}},
        ProcessorVariantInfo{"mips32le", {Architecture::mips32, ExecutionMode::mips32, ByteOrder::little}, {}},
        ProcessorVariantInfo{"mips32be", {Architecture::mips32, ExecutionMode::mips32, ByteOrder::big}, {}},
        ProcessorVariantInfo{"mips64le", {Architecture::mips64, ExecutionMode::mips64, ByteOrder::little}, {}},
        ProcessorVariantInfo{"mips64be", {Architecture::mips64, ExecutionMode::mips64, ByteOrder::big}, {}},
        ProcessorVariantInfo{"ppc32le", {Architecture::powerpc, ExecutionMode::ppc32, ByteOrder::little}, {}},
        ProcessorVariantInfo{"ppc32be", {Architecture::powerpc, ExecutionMode::ppc32, ByteOrder::big}, {}},
        ProcessorVariantInfo{"ppc64le", {Architecture::powerpc, ExecutionMode::ppc64, ByteOrder::little}, {}},
        ProcessorVariantInfo{"ppc64be", {Architecture::powerpc, ExecutionMode::ppc64, ByteOrder::big}, {}},
        ProcessorVariantInfo{"6502", {Architecture::mos6502, ExecutionMode::m6502, ByteOrder::little}, {}},
        ProcessorVariantInfo{"wasm32", {Architecture::wasm, ExecutionMode::wasm32, ByteOrder::little}, {}, false},
        ProcessorVariantInfo{"dex", {Architecture::dex, ExecutionMode::dex, ByteOrder::little}, {}},
        ProcessorVariantInfo{"jvm", {Architecture::jvm, ExecutionMode::jvm, ByteOrder::big}, {}}
    };
    static const auto inventory = [] {
        auto result = variants;
        for (auto &variant : result)
            variant.capabilities = processor_capabilities(variant.context);
        return result;
    }();
    return inventory;
}
DecodeResult decode_instruction(DecodeContext context, std::span<const std::byte> bytes, Address at) {
    auto capability = processor_capabilities(context);
    if (!capability.can_decode)
        return {DecodeStatus::unsupported, {}, std::string(capability.reason)};
    DecodeResult result;
    if (context.architecture == Architecture::wasm && context.mode == ExecutionMode::wasm32)
        result = decode_wasm(bytes, at);
    else if (context.architecture == Architecture::dex && context.mode == ExecutionMode::dex)
        result = decode_dex(bytes, at);
    else if (context.architecture == Architecture::jvm && context.mode == ExecutionMode::jvm)
        result = decode_jvm(bytes, at);
    else if (context.mode == ExecutionMode::a64)
        result = decode_a64(bytes, at);
    else if (context.mode == ExecutionMode::a32)
        result = decode_a32(bytes, at);
    else if (context.mode == ExecutionMode::thumb)
        result = decode_thumb(bytes, at);
    else if (context.architecture == Architecture::riscv64 &&
        (context.mode == ExecutionMode::rv64 || context.mode == ExecutionMode::rv64c))
        result = decode_riscv_context(context, bytes, at);
    else if (context.architecture == Architecture::riscv32 && context.mode == ExecutionMode::rv32)
        result = decode_riscv_context(context, bytes, at);
    else if (context.architecture == Architecture::mips32 && context.mode == ExecutionMode::mips32)
        result = decode_mips32(context.order, bytes, at);
    else if (context.architecture == Architecture::mips64 && context.mode == ExecutionMode::mips64)
        result = decode_mips64(bytes, at, context.order);
    else if (context.architecture == Architecture::powerpc &&
             (context.mode == ExecutionMode::ppc32 || context.mode == ExecutionMode::ppc64))
        result = decode_powerpc(context, bytes, at);
    else if (context.architecture == Architecture::mos6502 && context.mode == ExecutionMode::m6502)
        result = decode_m6502(bytes, at);
    else {
        result = x64_detail::decode_scalar(bytes, at, context);
        if (result.status == DecodeStatus::unsupported)
            result = x64_detail::decode_zydis_fallback(bytes, at, context);
    }
    const auto riscv_opcode = bytes.size() >= 4
        ? (std::to_integer<std::uint8_t>(bytes[0]) & 0x7f) : 0;
    const auto riscv_funct3 = bytes.size() >= 4
        ? ((std::to_integer<std::uint8_t>(bytes[1]) >> 4) & 7) : 0;
    const bool riscv_vector_memory_encoding = (riscv_opcode == 0x07 || riscv_opcode == 0x27) &&
        (riscv_funct3 == 0 || riscv_funct3 == 5 || riscv_funct3 == 6 || riscv_funct3 == 7);
    const bool riscv_vector_encoding =
        (context.architecture == Architecture::riscv64 || context.architecture == Architecture::riscv32) &&
        bytes.size() >= 4 && (riscv_opcode == 0x57 || riscv_vector_memory_encoding);
    if (result.status == DecodeStatus::unsupported && !riscv_vector_encoding &&
        context.architecture != Architecture::wasm && context.architecture != Architecture::dex &&
        context.architecture != Architecture::jvm) {
        auto fallback = processor_detail::decode_capstone_fallback(context, bytes, at);
        if (fallback.status == DecodeStatus::decoded || fallback.status == DecodeStatus::truncated)
            return fallback;
    }
    return result;
}
} // namespace hexlab
