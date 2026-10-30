#include "capstone_fallback.hpp"
#include <capstone/capstone.h>
#include <algorithm>
#include <cctype>
#include <string_view>
#include <limits>

namespace hexlab::processor_detail {
namespace {
std::optional<RegisterOperand> x86_register(csh handle, unsigned reg, unsigned width) {
    const char *raw = cs_reg_name(handle, reg);
    if (!raw) return {};
    const std::string_view n(raw);
    if (n.size()>2 && n[0]=='r' && std::isdigit(static_cast<unsigned char>(n[1]))) {
        if(n.ends_with("b"))width=8;else if(n.ends_with("w"))width=16;else if(n.ends_with("d"))width=32;else width=64;
    }
    else if (n.starts_with("e") && (n.ends_with("ax")||n.ends_with("bx")||n.ends_with("cx")||n.ends_with("dx")||n.ends_with("si")||n.ends_with("di")||n.ends_with("bp")||n.ends_with("sp")||n=="eip"||n=="eflags")) width=32;
    else if (n=="ax"||n=="bx"||n=="cx"||n=="dx"||n=="si"||n=="di"||n=="bp"||n=="sp"||n=="ip"||n=="flags") width=16;
    else if (n=="al"||n=="bl"||n=="cl"||n=="dl"||n=="ah"||n=="bh"||n=="ch"||n=="dh"||n=="sil"||n=="dil"||n=="spl"||n=="bpl") width=8;
    auto indexed = [&](std::string_view prefix, RegisterBank bank, unsigned bits,
                       unsigned max) -> std::optional<RegisterOperand> {
        if (!n.starts_with(prefix)) return {};
        unsigned value = 0;
        for (auto c : n.substr(prefix.size())) {
            if (!std::isdigit(static_cast<unsigned char>(c))) return {};
            value = value * 10 + static_cast<unsigned>(c - '0');
        }
        if (value >= max) return {};
        return RegisterOperand{bank, static_cast<std::uint8_t>(value), static_cast<std::uint16_t>(bits), false};
    };
    if (n == "al" || n == "ax" || n == "eax" || n == "rax") return RegisterOperand{RegisterBank::gpr,0,static_cast<std::uint16_t>(width),false};
    if (n == "cl" || n == "cx" || n == "ecx" || n == "rcx") return RegisterOperand{RegisterBank::gpr,1,static_cast<std::uint16_t>(width),false};
    if (n == "dl" || n == "dx" || n == "edx" || n == "rdx") return RegisterOperand{RegisterBank::gpr,2,static_cast<std::uint16_t>(width),false};
    if (n == "bl" || n == "bx" || n == "ebx" || n == "rbx") return RegisterOperand{RegisterBank::gpr,3,static_cast<std::uint16_t>(width),false};
    if (n == "ah" || n == "ch" || n == "dh" || n == "bh") return RegisterOperand{RegisterBank::gpr, static_cast<std::uint8_t>(n[0]=='a'?0:n[0]=='c'?1:n[0]=='d'?2:3), 8, true};
    if (n == "spl" || n == "sp" || n == "esp" || n == "rsp") return RegisterOperand{RegisterBank::gpr,4,static_cast<std::uint16_t>(width),false};
    if (n == "bpl" || n == "bp" || n == "ebp" || n == "rbp") return RegisterOperand{RegisterBank::gpr,5,static_cast<std::uint16_t>(width),false};
    if (n == "sil" || n == "si" || n == "esi" || n == "rsi") return RegisterOperand{RegisterBank::gpr,6,static_cast<std::uint16_t>(width),false};
    if (n == "dil" || n == "di" || n == "edi" || n == "rdi") return RegisterOperand{RegisterBank::gpr,7,static_cast<std::uint16_t>(width),false};
    if (n.size() >= 2 && n[0]=='r' && std::isdigit(static_cast<unsigned char>(n[1]))) {
        unsigned i=0, p=1; while(p<n.size() && std::isdigit(static_cast<unsigned char>(n[p]))) i=i*10+unsigned(n[p++]-'0');
        if (i>=8 && i<=15) return RegisterOperand{RegisterBank::gpr,static_cast<std::uint8_t>(i),static_cast<std::uint16_t>(width),false};
    }
    if (n == "rip" || n == "eip" || n == "ip") return RegisterOperand{RegisterBank::ip,0,static_cast<std::uint16_t>(width),false};
    if (n == "rflags" || n == "eflags" || n == "flags") return RegisterOperand{RegisterBank::flags,0,static_cast<std::uint16_t>(width),false};
    constexpr std::string_view segs[] = {"es","cs","ss","ds","fs","gs"};
    for(unsigned i=0;i<6;i++) if(n==segs[i]) return RegisterOperand{RegisterBank::segment,static_cast<std::uint8_t>(i),16,false};
    if (auto x=indexed("xmm",RegisterBank::xmm,128,32)) return x;
    if (auto x=indexed("ymm",RegisterBank::ymm,256,32)) return x;
    if (auto x=indexed("zmm",RegisterBank::zmm,512,32)) return x;
    if (auto x=indexed("k",RegisterBank::opmask,64,8)) return x;
    return {};
}
std::optional<RegisterOperand> named_register(csh handle, unsigned reg, unsigned width, Architecture arch) {
    if (arch==Architecture::x86 || arch==Architecture::x86_64) return x86_register(handle,reg,width);
    if (arch==Architecture::mos6502) {
        switch (reg) {
        case MOS65XX_REG_ACC: return RegisterOperand{RegisterBank::mos6502,0,8,false};
        case MOS65XX_REG_X: return RegisterOperand{RegisterBank::mos6502,1,8,false};
        case MOS65XX_REG_Y: return RegisterOperand{RegisterBank::mos6502,2,8,false};
        case MOS65XX_REG_P: return RegisterOperand{RegisterBank::mos6502,3,8,false};
        case MOS65XX_REG_SP: return RegisterOperand{RegisterBank::mos6502,4,8,false};
        default: return {};
        }
    }
    const char *raw=cs_reg_name(handle,reg); if(!raw) return {};
    const std::string_view n(raw);
    auto number=[&](std::string_view prefix,unsigned limit)->std::optional<unsigned>{
        if(!n.starts_with(prefix)) return {}; unsigned v=0; auto s=n.substr(prefix.size()); if(s.empty()) return {};
        for(char c:s){if(!std::isdigit(static_cast<unsigned char>(c)))return {};v=v*10+unsigned(c-'0');} if(v>=limit)return {}; return v;
    };
    if(arch==Architecture::arm64){
        if(n.size()>1 && n[0]=='w') width=32;
        else if(n.size()>1 && n[0]=='x') width=64;
        else if(n=="wsp"||n=="wzr") width=32;
        if(n=="sp"||n=="wsp") return RegisterOperand{RegisterBank::arm64_sp,0,static_cast<std::uint16_t>(width),false};
        if(n=="xzr"||n=="wzr") return RegisterOperand{RegisterBank::arm64_zero,0,static_cast<std::uint16_t>(width),false};
        if(auto i=number("x",31)) return RegisterOperand{RegisterBank::arm64_gpr,static_cast<std::uint8_t>(*i),static_cast<std::uint16_t>(width),false};
        if(auto i=number("w",31)) return RegisterOperand{RegisterBank::arm64_gpr,static_cast<std::uint8_t>(*i),static_cast<std::uint16_t>(width),false};
        for(auto p:{"v","q","d","s","h","b"}) if(auto i=number(p,32)) return RegisterOperand{RegisterBank::arm64_simd,static_cast<std::uint8_t>(*i),static_cast<std::uint16_t>(width),false};
        if(n=="nzcv") return RegisterOperand{RegisterBank::arm_flags,0,4,false};
    }
    if(arch==Architecture::arm){
        if(n=="sp") return RegisterOperand{RegisterBank::arm32_gpr,13,static_cast<std::uint16_t>(width),false};
        if(n=="lr") return RegisterOperand{RegisterBank::arm32_gpr,14,static_cast<std::uint16_t>(width),false};
        if(n=="pc") return RegisterOperand{RegisterBank::arm32_gpr,15,static_cast<std::uint16_t>(width),false};
        if(auto i=number("r",16)) return RegisterOperand{RegisterBank::arm32_gpr,static_cast<std::uint8_t>(*i),static_cast<std::uint16_t>(width),false};
        if(n=="cpsr"||n=="apsr") return RegisterOperand{RegisterBank::arm_flags,0,32,false};
    }
    if(arch==Architecture::riscv32||arch==Architecture::riscv64){
        constexpr std::string_view abi[]={"zero","ra","sp","gp","tp","t0","t1","t2","s0","s1","a0","a1","a2","a3","a4","a5","a6","a7","s2","s3","s4","s5","s6","s7","s8","s9","s10","s11","t3","t4","t5","t6"};
        for(unsigned i=0;i<32;i++) if(n==abi[i] || (number("x",32)&&*number("x",32)==i))
            return RegisterOperand{RegisterBank::riscv_gpr,static_cast<std::uint8_t>(i),static_cast<std::uint16_t>(width),false};
        if(auto i=number("f",32)) return RegisterOperand{RegisterBank::riscv_fpr,static_cast<std::uint8_t>(*i),static_cast<std::uint16_t>(width),false};
    }
    if(arch==Architecture::mips32||arch==Architecture::mips64){
        if(n=="zero") return RegisterOperand{RegisterBank::mips_gpr,0,static_cast<std::uint16_t>(width),false};
        constexpr std::string_view names[]={"zero","at","v0","v1","a0","a1","a2","a3","t0","t1","t2","t3","t4","t5","t6","t7","s0","s1","s2","s3","s4","s5","s6","s7","t8","t9","k0","k1","gp","sp","fp","ra"};
        for(unsigned i=0;i<32;i++) if(n==names[i]) return RegisterOperand{RegisterBank::mips_gpr,static_cast<std::uint8_t>(i),static_cast<std::uint16_t>(width),false};
        if(n=="hi"||n=="lo") return RegisterOperand{RegisterBank::mips_hilo,static_cast<std::uint8_t>(n=="lo"),static_cast<std::uint16_t>(width),false};
        if(n=="fcsr") return RegisterOperand{RegisterBank::mips_fcsr,0,32,false};
    }
    if(arch==Architecture::powerpc){
        if(auto i=number("r",32)) return RegisterOperand{RegisterBank::ppc_gpr,static_cast<std::uint8_t>(*i),static_cast<std::uint16_t>(width),false};
        if(auto i=number("cr",8)) return RegisterOperand{RegisterBank::ppc_cr,static_cast<std::uint8_t>(*i),4,false};
        if(n=="lr"||n=="lr8") return RegisterOperand{RegisterBank::ppc_lr,0,static_cast<std::uint16_t>(width),false};
        if(n=="ctr"||n=="ctr8") return RegisterOperand{RegisterBank::ppc_ctr,0,static_cast<std::uint16_t>(width),false};
        if(n=="xer") return RegisterOperand{RegisterBank::ppc_xer,0,32,false};
    }
    return {};
}
void add_unique(std::vector<RegisterOperand>& v, RegisterOperand r) {
    if (std::find(v.begin(),v.end(),r)==v.end()) v.push_back(r);
}
bool control_transfer(FlowKind flow) {
    return flow==FlowKind::call || flow==FlowKind::jump || flow==FlowKind::conditional_branch;
}
std::optional<Address> absolute_target(const Instruction &instruction, std::int64_t value,
                                       unsigned width, unsigned alignment) {
    const auto offset=width==32?static_cast<std::uint64_t>(static_cast<std::uint32_t>(value))
                                :static_cast<std::uint64_t>(value);
    if(offset%alignment) return {};
    return Address{instruction.address.space,offset};
}
std::optional<Address> relative_target(const Instruction &instruction, std::int64_t displacement,
                                       unsigned width, unsigned alignment) {
    const auto base=instruction.address.offset;
    const auto magnitude=displacement<0?static_cast<std::uint64_t>(-(displacement+1))+1
                                       :static_cast<std::uint64_t>(displacement);
    if(width==32 && base>UINT32_MAX) return {};
    if(displacement<0 ? magnitude>base : magnitude>(width==32?UINT32_MAX:UINT64_MAX)-base)
        return {};
    const auto offset=displacement<0?base-magnitude:base+magnitude;
    if(offset%alignment) return {};
    return Address{instruction.address.space,offset};
}
bool mips_classic_direct(unsigned id) {
    switch(id) {
    case MIPS_INS_J: case MIPS_INS_JAL: case MIPS_INS_BAL:
    case MIPS_INS_BEQ: case MIPS_INS_BNE: case MIPS_INS_BGEZ: case MIPS_INS_BLTZ:
    case MIPS_INS_BGTZ: case MIPS_INS_BLEZ:
    // Branch-and-link conditionals still use the classic delayed control
    // transfer format. Their flow remains `call` when Capstone marks it so,
    // but the decoded target and one delay slot are equally important facts.
    case MIPS_INS_BGEZAL: case MIPS_INS_BLTZAL:
    case MIPS_INS_BC1T: case MIPS_INS_BC1F:
        return true;
    default:return false;
    }
}
bool ppc_direct_branch(unsigned id) {
    switch(id) {
    case PPC_INS_B: case PPC_INS_BA: case PPC_INS_BL: case PPC_INS_BLA:
    case PPC_INS_BC: case PPC_INS_BCA: case PPC_INS_BCL: case PPC_INS_BCLA:
        return true;
    default:return false;
    }
}
bool riscv_relative_branch(unsigned id) {
    switch(id) {
    case RISCV_INS_BEQ:case RISCV_INS_BNE:case RISCV_INS_BLT:case RISCV_INS_BGE:
    case RISCV_INS_BLTU:case RISCV_INS_BGEU:case RISCV_INS_C_BEQZ:case RISCV_INS_C_BNEZ:
    case RISCV_INS_JAL:case RISCV_INS_C_J:case RISCV_INS_C_JAL:
        return true;
    default:return false;
    }
}
bool mips_conditional_branch(unsigned id) {
    switch (id) {
    case MIPS_INS_BEQ: case MIPS_INS_BNE: case MIPS_INS_BGEZ: case MIPS_INS_BLTZ:
    case MIPS_INS_BGEZAL: case MIPS_INS_BLTZAL:
    case MIPS_INS_BGTZ: case MIPS_INS_BLEZ: case MIPS_INS_BC0F: case MIPS_INS_BC0T:
    case MIPS_INS_BC0FL: case MIPS_INS_BC0TL: case MIPS_INS_BC1F: case MIPS_INS_BC1FL:
    case MIPS_INS_BC1T: case MIPS_INS_BC1TL: case MIPS_INS_BC2F: case MIPS_INS_BC2FL:
    case MIPS_INS_BC2T: case MIPS_INS_BC2TL: case MIPS_INS_BC3F: case MIPS_INS_BC3FL:
    case MIPS_INS_BC3T: case MIPS_INS_BC3TL: case MIPS_INS_BC1EQZ: case MIPS_INS_BC1NEZ:
    case MIPS_INS_BC2EQZ: case MIPS_INS_BC2NEZ: case MIPS_INS_BEQL: case MIPS_INS_BNEL:
    case MIPS_INS_BGEZL: case MIPS_INS_BGTZL: case MIPS_INS_BLEZL: case MIPS_INS_BLTZL:
    case MIPS_INS_BEQZ: case MIPS_INS_BNEZ: case MIPS_INS_BEQZ16: case MIPS_INS_BNEZ16:
    case MIPS_INS_BTEQZ: case MIPS_INS_BTNEZ: case MIPS_INS_BEQC: case MIPS_INS_BNEC:
    case MIPS_INS_BGEC: case MIPS_INS_BGEUC: case MIPS_INS_BLTC: case MIPS_INS_BLTUC:
    case MIPS_INS_BGEZC: case MIPS_INS_BGTZC: case MIPS_INS_BLEZC: case MIPS_INS_BLTZC:
    case MIPS_INS_BEQZC: case MIPS_INS_BNEZC: case MIPS_INS_BOVC: case MIPS_INS_BNVC:
        return true;
    default:
        return false;
    }
}
struct MemoryRole {
    OperandAccess access;
    std::uint16_t data_width;
};
std::optional<MemoryRole> capstone_memory_role(Architecture architecture, unsigned id) {
    const auto read = [](unsigned width) { return MemoryRole{OperandAccess::read, static_cast<std::uint16_t>(width)}; };
    const auto write = [](unsigned width) { return MemoryRole{OperandAccess::write, static_cast<std::uint16_t>(width)}; };
    const auto read_write = [](unsigned width) { return MemoryRole{OperandAccess::read_write, static_cast<std::uint16_t>(width)}; };
    if (architecture == Architecture::arm64) {
        switch (id) {
        case ARM64_INS_LDRB: case ARM64_INS_LDTRB: case ARM64_INS_LDURB:
        case ARM64_INS_LDRSB: case ARM64_INS_LDTRSB: case ARM64_INS_LDURSB:
            return read(8);
        case ARM64_INS_LDRH: case ARM64_INS_LDTRH: case ARM64_INS_LDURH:
        case ARM64_INS_LDRSH: case ARM64_INS_LDTRSH: case ARM64_INS_LDURSH:
            return read(16);
        case ARM64_INS_LDRSW: case ARM64_INS_LDTRSW: case ARM64_INS_LDURSW:
            return read(32);
        case ARM64_INS_STRB: case ARM64_INS_STTRB: case ARM64_INS_STURB:
            return write(8);
        case ARM64_INS_STRH: case ARM64_INS_STTRH: case ARM64_INS_STURH:
            return write(16);
        case ARM64_INS_LDP: case ARM64_INS_LDPSW: case ARM64_INS_STP:
            // Pair widths are resolved from the destination/source GPRs below.
            return read(0);
        case ARM64_INS_LDR: case ARM64_INS_LDTR: case ARM64_INS_LDUR:
        case ARM64_INS_STR: case ARM64_INS_STTR: case ARM64_INS_STUR:
            // The base-width forms are resolved from the GPR name below.
            return read(0);
        default: return {};
        }
    }
    if (architecture == Architecture::riscv32 || architecture == Architecture::riscv64) {
        if (id >= RISCV_INS_AMOADD_D && id <= RISCV_INS_AMOXOR_W_RL) {
            // The bundled Capstone header lays out all nine W/D AMO families
            // as four D ordering variants followed by four W variants.
            const auto family_offset = id - RISCV_INS_AMOADD_D;
            return read_write(family_offset % 8 < 4 ? 64 : 32);
        }
        switch (id) {
        case RISCV_INS_LB: case RISCV_INS_LBU: return read(8);
        case RISCV_INS_LH: case RISCV_INS_LHU: return read(16);
        case RISCV_INS_LW: case RISCV_INS_LWU: case RISCV_INS_FLW:
        case RISCV_INS_C_LW: case RISCV_INS_C_LWSP: case RISCV_INS_C_FLW: case RISCV_INS_C_FLWSP: return read(32);
        case RISCV_INS_LD: case RISCV_INS_FLD: case RISCV_INS_C_LD: case RISCV_INS_C_LDSP:
        case RISCV_INS_C_FLD: case RISCV_INS_C_FLDSP: return read(64);
        case RISCV_INS_LR_W: case RISCV_INS_LR_W_AQ: case RISCV_INS_LR_W_AQ_RL: case RISCV_INS_LR_W_RL: return read(32);
        case RISCV_INS_LR_D: case RISCV_INS_LR_D_AQ: case RISCV_INS_LR_D_AQ_RL: case RISCV_INS_LR_D_RL: return read(64);
        case RISCV_INS_SB: return write(8);
        case RISCV_INS_SH: return write(16);
        case RISCV_INS_SW: case RISCV_INS_FSW: case RISCV_INS_C_SW: case RISCV_INS_C_SWSP:
        case RISCV_INS_C_FSW: case RISCV_INS_C_FSWSP: return write(32);
        case RISCV_INS_SD: case RISCV_INS_FSD: case RISCV_INS_C_SD: case RISCV_INS_C_SDSP:
        case RISCV_INS_C_FSD: case RISCV_INS_C_FSDSP: return write(64);
        case RISCV_INS_SC_W: case RISCV_INS_SC_W_AQ: case RISCV_INS_SC_W_AQ_RL: case RISCV_INS_SC_W_RL: return write(32);
        case RISCV_INS_SC_D: case RISCV_INS_SC_D_AQ: case RISCV_INS_SC_D_AQ_RL: case RISCV_INS_SC_D_RL: return write(64);
        default: return {};
        }
    }
    if (architecture == Architecture::mips32 || architecture == Architecture::mips64) {
        switch (id) {
        case MIPS_INS_LB: case MIPS_INS_LBU: case MIPS_INS_LBU16: case MIPS_INS_LBUX: return read(8);
        case MIPS_INS_LH: case MIPS_INS_LHU: case MIPS_INS_LHU16: case MIPS_INS_LHX: return read(16);
        case MIPS_INS_LW: case MIPS_INS_LW16: case MIPS_INS_LWL: case MIPS_INS_LWR:
        case MIPS_INS_LWC1: case MIPS_INS_LWC2: case MIPS_INS_LWC3: case MIPS_INS_LWXC1:
        case MIPS_INS_LWXS: case MIPS_INS_LWX: case MIPS_INS_LWU: case MIPS_INS_LL: return read(32);
        case MIPS_INS_LD: case MIPS_INS_LDL: case MIPS_INS_LDR: case MIPS_INS_LDC1:
        case MIPS_INS_LDC2: case MIPS_INS_LDC3: case MIPS_INS_LDXC1: case MIPS_INS_LLD: return read(64);
        case MIPS_INS_SB: case MIPS_INS_SB16: return write(8);
        case MIPS_INS_SH: case MIPS_INS_SH16: return write(16);
        case MIPS_INS_SW: case MIPS_INS_SW16: case MIPS_INS_SWL: case MIPS_INS_SWR:
        case MIPS_INS_SWC1: case MIPS_INS_SWC2: case MIPS_INS_SWC3: case MIPS_INS_SWXC1:
        case MIPS_INS_SC: return write(32);
        case MIPS_INS_SD: case MIPS_INS_SDL: case MIPS_INS_SDR: case MIPS_INS_SDC1:
        case MIPS_INS_SDC2: case MIPS_INS_SDC3: case MIPS_INS_SDXC1: case MIPS_INS_SCD: return write(64);
        default: return {};
        }
    }
    if (architecture == Architecture::powerpc) {
        switch (id) {
        case PPC_INS_LBZ: case PPC_INS_LBZU: case PPC_INS_LBZUX: case PPC_INS_LBZX:
        case PPC_INS_LBZCIX: return read(8);
        case PPC_INS_LHZ: case PPC_INS_LHZU: case PPC_INS_LHZUX: case PPC_INS_LHZX:
        case PPC_INS_LHZCIX: case PPC_INS_LHBRX: return read(16);
        case PPC_INS_LWZ: case PPC_INS_LWZU: case PPC_INS_LWZUX: case PPC_INS_LWZX:
        case PPC_INS_LWZCIX: case PPC_INS_LWBRX: case PPC_INS_LFS: case PPC_INS_LFSU:
        case PPC_INS_LFSUX: case PPC_INS_LFSX: case PPC_INS_LWARX:
        case PPC_INS_LWA: case PPC_INS_LWAUX: case PPC_INS_LWAX: return read(32);
        case PPC_INS_LD: case PPC_INS_LDU: case PPC_INS_LDUX: case PPC_INS_LDX:
        case PPC_INS_LFD: case PPC_INS_LFDU: case PPC_INS_LFDUX: case PPC_INS_LFDX:
        case PPC_INS_LDARX: return read(64);
        // Full-width Altivec/VSX vector transfers. Element/splat operations
        // are intentionally left unclassified because their memory width is
        // instruction-specific and differs from the destination vector width.
        case PPC_INS_LVX: case PPC_INS_LVXL: case PPC_INS_LXV: case PPC_INS_LXVX:
            return read(128);
        case PPC_INS_STB: case PPC_INS_STBU: case PPC_INS_STBUX: case PPC_INS_STBX:
        case PPC_INS_STBCIX: return write(8);
        case PPC_INS_STH: case PPC_INS_STHU: case PPC_INS_STHUX: case PPC_INS_STHX:
        case PPC_INS_STHCIX: case PPC_INS_STHBRX: return write(16);
        case PPC_INS_STW: case PPC_INS_STWU: case PPC_INS_STWUX: case PPC_INS_STWX:
        case PPC_INS_STWCIX: case PPC_INS_STWBRX: case PPC_INS_STFS: case PPC_INS_STFSU:
        case PPC_INS_STFSUX: case PPC_INS_STFSX: case PPC_INS_STWCX: return write(32);
        case PPC_INS_STD: case PPC_INS_STDU: case PPC_INS_STDUX: case PPC_INS_STDX:
        case PPC_INS_STFD: case PPC_INS_STFDU: case PPC_INS_STFDUX: case PPC_INS_STFDX:
        case PPC_INS_STDCX: return write(64);
        case PPC_INS_STVX: case PPC_INS_STVXL: case PPC_INS_STXV: case PPC_INS_STXVX:
            return write(128);
        default: return {};
        }
    }
    return {};
}
void apply_capstone_detail(csh handle, const cs_insn& insn, Instruction& out, Architecture architecture) {
    const auto *d=insn.detail;
    if (!d) return;
    bool call=false,ret=false,trap=false,jump=false;
    for(unsigned i=0;i<d->groups_count;i++) {
        switch(d->groups[i]) {
        case CS_GRP_CALL:call=true;break;
        case CS_GRP_RET:case CS_GRP_IRET:ret=true;break;
        case CS_GRP_INT:trap=true;break;
        case CS_GRP_JUMP:jump=true;break;
        }
    }
    // Some backends attach both JUMP and CALL/RET groups. A later group must
    // not overwrite the more specific control-transfer class.
    out.flow=trap?FlowKind::trap:ret?FlowKind::ret:call?FlowKind::call:jump?FlowKind::jump:FlowKind::fallthrough;
    const bool may_be_conditional_branch = out.flow != FlowKind::call && out.flow != FlowKind::ret &&
                                            out.flow != FlowKind::trap;
    if(architecture==Architecture::arm64 && may_be_conditional_branch) {
        const auto cc=d->arm64.cc;
        if((insn.id==ARM64_INS_B || insn.id==ARM64_INS_BC) && cc>ARM64_CC_INVALID && cc<ARM64_CC_AL)
            out.flow=FlowKind::conditional_branch;
        if(insn.id==ARM64_INS_CBZ || insn.id==ARM64_INS_CBNZ ||
           insn.id==ARM64_INS_TBZ || insn.id==ARM64_INS_TBNZ)
            out.flow=FlowKind::conditional_branch;
    } else if(architecture==Architecture::arm && may_be_conditional_branch) {
        const auto cc=d->arm.cc;
        if((insn.id==ARM_INS_B && cc>ARM_CC_INVALID && cc<ARM_CC_AL) ||
           insn.id==ARM_INS_CBZ || insn.id==ARM_INS_CBNZ)
            out.flow=FlowKind::conditional_branch;
    } else if((architecture==Architecture::riscv32 || architecture==Architecture::riscv64) &&
              may_be_conditional_branch) {
        switch(insn.id) {
        case RISCV_INS_BEQ: case RISCV_INS_BNE: case RISCV_INS_BLT: case RISCV_INS_BGE:
        case RISCV_INS_BLTU: case RISCV_INS_BGEU: case RISCV_INS_C_BEQZ: case RISCV_INS_C_BNEZ:
            out.flow=FlowKind::conditional_branch;break;
        default:break;
        }
    } else if((architecture==Architecture::mips32 || architecture==Architecture::mips64) &&
              may_be_conditional_branch) {
        if (mips_conditional_branch(insn.id)) out.flow=FlowKind::conditional_branch;
    } else if(architecture==Architecture::powerpc && may_be_conditional_branch) {
        // The CTR-only branch aliases do not always carry a decoded BO/BI
        // condition in Capstone detail. Preserve their conditional identity
        // explicitly, including prediction, absolute, and link variants.
        const bool ctr_branch = [&] {
            switch (insn.id) {
            case PPC_INS_BDNZ: case PPC_INS_BDNZA: case PPC_INS_BDNZF:
            case PPC_INS_BDNZFA: case PPC_INS_BDNZFL: case PPC_INS_BDNZFLA:
            case PPC_INS_BDNZFLR: case PPC_INS_BDNZFLRL: case PPC_INS_BDNZL:
            case PPC_INS_BDNZLA: case PPC_INS_BDNZLR: case PPC_INS_BDNZLRL:
            case PPC_INS_BDNZT: case PPC_INS_BDNZTA: case PPC_INS_BDNZTL:
            case PPC_INS_BDNZTLA: case PPC_INS_BDNZTLR: case PPC_INS_BDNZTLRL:
            case PPC_INS_BDZ: case PPC_INS_BDZA: case PPC_INS_BDZF:
            case PPC_INS_BDZFA: case PPC_INS_BDZFL: case PPC_INS_BDZFLA:
            case PPC_INS_BDZFLR: case PPC_INS_BDZFLRL: case PPC_INS_BDZL:
            case PPC_INS_BDZLA: case PPC_INS_BDZLR: case PPC_INS_BDZLRL:
            case PPC_INS_BDZT: case PPC_INS_BDZTA: case PPC_INS_BDZTL:
            case PPC_INS_BDZTLA: case PPC_INS_BDZTLR: case PPC_INS_BDZTLRL:
                return true;
            default: return false;
            }
        }();
        if(d->ppc.bc!=PPC_BC_INVALID || ctr_branch)
            out.flow=FlowKind::conditional_branch;
    }
    const bool x86=architecture==Architecture::x86 || architecture==Architecture::x86_64;
    if (architecture==Architecture::arm64) {
        const auto& a=d->arm64; if(a.op_count>8)return;
        const auto memory_role=capstone_memory_role(architecture,insn.id);
        for(unsigned i=0;i<a.op_count;i++) { const auto& op=a.operands[i];
            if(op.access==0 && (op.type==ARM64_OP_REG||op.type==ARM64_OP_MEM)) continue;
            const auto ac=(op.access&CS_AC_WRITE)?((op.access&CS_AC_READ)?OperandAccess::read_write:OperandAccess::write):OperandAccess::read;
            if(op.type==ARM64_OP_REG){auto r=named_register(handle,op.reg,64,architecture); if(r){out.operands.emplace_back(*r);out.access.push_back(ac);}}
            else if(op.type==ARM64_OP_IMM){out.operands.emplace_back(ImmediateOperand{static_cast<std::uint64_t>(op.imm),64,64,true,{}});out.access.push_back(OperandAccess::read);}
            else if(op.type==ARM64_OP_MEM){MemoryOperand m;m.address_width=64;m.displacement=op.mem.disp;m.base=named_register(handle,op.mem.base,64,architecture);if(op.mem.index)m.index=named_register(handle,op.mem.index,64,architecture);
                if(memory_role) {
                    m.data_width=memory_role->data_width;
                    if(m.data_width==0) {
                        unsigned element_width=0, register_count=1;
                        if(insn.id==ARM64_INS_LDP||insn.id==ARM64_INS_STP) register_count=2;
                        if(insn.id==ARM64_INS_LDPSW) { element_width=32; register_count=2; }
                        else for(unsigned j=0;j<i;j++) if(a.operands[j].type==ARM64_OP_REG) {
                            const char* reg_name=cs_reg_name(handle,a.operands[j].reg);
                            if(!reg_name) continue;
                            const std::string_view name(reg_name);
                            if(name.size()>1 && name[0]=='w' && std::isdigit(static_cast<unsigned char>(name[1]))) element_width=32;
                            else if(name.size()>1 && name[0]=='x' && std::isdigit(static_cast<unsigned char>(name[1]))) element_width=64;
                            if(element_width) break;
                        }
                        if(element_width) m.data_width=static_cast<std::uint16_t>(element_width*register_count);
                    }
                }
                out.operands.emplace_back(m);out.access.push_back(ac);out.memory_read|=ac==OperandAccess::read||ac==OperandAccess::read_write;out.memory_write|=ac==OperandAccess::write||ac==OperandAccess::read_write;}
        }
    } else if (architecture==Architecture::arm) {
        const auto& a=d->arm;if(a.op_count>36)return;
        for(unsigned i=0;i<a.op_count;i++){const auto& op=a.operands[i];if(op.access==0&&(op.type==ARM_OP_REG||op.type==ARM_OP_MEM))continue;const auto ac=(op.access&CS_AC_WRITE)?((op.access&CS_AC_READ)?OperandAccess::read_write:OperandAccess::write):OperandAccess::read;
            if(op.type==ARM_OP_REG){auto r=named_register(handle,op.reg,32,architecture);if(r){out.operands.emplace_back(*r);out.access.push_back(ac);}}
            else if(op.type==ARM_OP_IMM){out.operands.emplace_back(ImmediateOperand{static_cast<std::uint32_t>(op.imm),32,32,true,{}});out.access.push_back(OperandAccess::read);}
            else if(op.type==ARM_OP_MEM){MemoryOperand m;m.address_width=32;m.displacement=op.mem.disp;m.scale=op.mem.scale>0?static_cast<std::uint8_t>(op.mem.scale):1;m.base=named_register(handle,op.mem.base,32,architecture);if(op.mem.index)m.index=named_register(handle,op.mem.index,32,architecture);out.operands.emplace_back(m);out.access.push_back(ac);out.memory_read|=ac!=OperandAccess::write;out.memory_write|=ac==OperandAccess::write||ac==OperandAccess::read_write;}
        }
    } else if (architecture==Architecture::riscv32 || architecture==Architecture::riscv64) {
        const auto& rv=d->riscv; if(rv.op_count>8)return;
        const auto memory_role=capstone_memory_role(architecture,insn.id);
        // Capstone's RISC-V operands have no per-operand access field. Map
        // register operands only when cs_regs_access can establish the role.
        std::array<uint16_t,64> reads{},writes{}; uint8_t nr=0,nw=0;
        const bool access_known=cs_regs_access(handle,&insn,reads.data(),&nr,writes.data(),&nw)==CS_ERR_OK;
        for(unsigned i=0;i<rv.op_count;i++) { const auto& op=rv.operands[i];
            if(op.type==RISCV_OP_REG) {
                auto r=named_register(handle,op.reg,architecture==Architecture::riscv64?64:32,architecture); if(!r||!access_known) continue;
                bool rd=false,wr=false; for(unsigned j=0;j<nr;j++) rd|=reads[j]==op.reg; for(unsigned j=0;j<nw;j++) wr|=writes[j]==op.reg;
                if(!rd&&!wr) continue;
                out.operands.emplace_back(*r); out.access.push_back(rd&&wr?OperandAccess::read_write:wr?OperandAccess::write:OperandAccess::read);
            } else if(op.type==RISCV_OP_IMM) {
                out.operands.emplace_back(ImmediateOperand{static_cast<std::uint64_t>(op.imm),64,64,true,{}}); out.access.push_back(OperandAccess::read);
            } else if(op.type==RISCV_OP_MEM) {
                MemoryOperand m;m.address_width=architecture==Architecture::riscv64?64:32;m.displacement=op.mem.disp;
                if(memory_role)m.data_width=memory_role->data_width;
                m.base=named_register(handle,op.mem.base,m.address_width,architecture);
                const auto access=memory_role?memory_role->access:OperandAccess::address;
                out.operands.emplace_back(m);out.access.push_back(access);
                out.memory_read|=access==OperandAccess::read||access==OperandAccess::read_write;
                out.memory_write|=access==OperandAccess::write||access==OperandAccess::read_write;
            }
        }
    } else if (architecture==Architecture::mips32 || architecture==Architecture::mips64) {
        const auto& m=d->mips;if(m.op_count>10)return;
        const auto memory_role=capstone_memory_role(architecture,insn.id);
        std::array<uint16_t,64> reads{},writes{};uint8_t nr=0,nw=0;
        const bool known=cs_regs_access(handle,&insn,reads.data(),&nr,writes.data(),&nw)==CS_ERR_OK;
        for(unsigned i=0;i<m.op_count;i++){const auto& op=m.operands[i];
            if(op.type==MIPS_OP_IMM){out.operands.emplace_back(ImmediateOperand{static_cast<std::uint64_t>(op.imm),64,64,true,{}});out.access.push_back(OperandAccess::read);}
            else if(op.type==MIPS_OP_REG&&known){auto r=named_register(handle,op.reg,architecture==Architecture::mips64?64:32,architecture);if(!r)continue;bool rd=false,wr=false;for(unsigned j=0;j<nr;j++)rd|=reads[j]==op.reg;for(unsigned j=0;j<nw;j++)wr|=writes[j]==op.reg;if(rd||wr){out.operands.emplace_back(*r);out.access.push_back(rd&&wr?OperandAccess::read_write:wr?OperandAccess::write:OperandAccess::read);}}
            else if(op.type==MIPS_OP_MEM){MemoryOperand mem;mem.address_width=architecture==Architecture::mips64?64:32;mem.displacement=op.mem.disp;if(memory_role)mem.data_width=memory_role->data_width;mem.base=named_register(handle,op.mem.base,mem.address_width,architecture);const auto access=memory_role?memory_role->access:OperandAccess::address;out.operands.emplace_back(mem);out.access.push_back(access);out.memory_read|=access==OperandAccess::read||access==OperandAccess::read_write;out.memory_write|=access==OperandAccess::write||access==OperandAccess::read_write;}
        }
    } else if (architecture==Architecture::powerpc) {
        const auto& p=d->ppc;if(p.op_count>8)return;
        const auto memory_role=capstone_memory_role(architecture,insn.id);
        std::array<uint16_t,64> reads{},writes{};uint8_t nr=0,nw=0;
        const bool known=cs_regs_access(handle,&insn,reads.data(),&nr,writes.data(),&nw)==CS_ERR_OK;
        for(unsigned i=0;i<p.op_count;i++){const auto& op=p.operands[i];
            if(op.type==PPC_OP_IMM){out.operands.emplace_back(ImmediateOperand{static_cast<std::uint64_t>(op.imm),64,64,true,{}});out.access.push_back(OperandAccess::read);}
            else if(op.type==PPC_OP_REG&&known){auto r=named_register(handle,op.reg,out.context.mode==ExecutionMode::ppc64?64:32,architecture);if(!r)continue;bool rd=false,wr=false;for(unsigned j=0;j<nr;j++)rd|=reads[j]==op.reg;for(unsigned j=0;j<nw;j++)wr|=writes[j]==op.reg;if(rd||wr){out.operands.emplace_back(*r);out.access.push_back(rd&&wr?OperandAccess::read_write:wr?OperandAccess::write:OperandAccess::read);}}
            else if(op.type==PPC_OP_MEM){MemoryOperand mem;mem.address_width=out.context.mode==ExecutionMode::ppc64?64:32;mem.displacement=op.mem.disp;if(memory_role)mem.data_width=memory_role->data_width;mem.base=named_register(handle,op.mem.base,mem.address_width,architecture);const auto access=memory_role?memory_role->access:OperandAccess::address;out.operands.emplace_back(mem);out.access.push_back(access);out.memory_read|=access==OperandAccess::read||access==OperandAccess::read_write;out.memory_write|=access==OperandAccess::write||access==OperandAccess::read_write;}
        }
    } else if (architecture==Architecture::mos6502) {
        const auto &m=d->mos65xx;
        if(m.op_count>3)return;
        OperandAccess memory_access = OperandAccess::address;
        switch (insn.id) {
        case MOS65XX_INS_ADC: case MOS65XX_INS_AND: case MOS65XX_INS_BIT:
        case MOS65XX_INS_CMP: case MOS65XX_INS_CPX: case MOS65XX_INS_CPY:
        case MOS65XX_INS_EOR: case MOS65XX_INS_LDA: case MOS65XX_INS_LDX:
        case MOS65XX_INS_LDY: case MOS65XX_INS_ORA: case MOS65XX_INS_SBC:
            memory_access = OperandAccess::read; break;
        case MOS65XX_INS_STA: case MOS65XX_INS_STX: case MOS65XX_INS_STY:
        case MOS65XX_INS_STZ:
            memory_access = OperandAccess::write; break;
        case MOS65XX_INS_ASL: case MOS65XX_INS_DEC: case MOS65XX_INS_INC:
        case MOS65XX_INS_LSR: case MOS65XX_INS_ROL: case MOS65XX_INS_ROR:
        case MOS65XX_INS_RMB: case MOS65XX_INS_SMB:
        case MOS65XX_INS_TRB: case MOS65XX_INS_TSB:
            memory_access = OperandAccess::read_write; break;
        case MOS65XX_INS_BBR: case MOS65XX_INS_BBS:
            memory_access = OperandAccess::read; break;
        case MOS65XX_INS_JMP:
            if (m.am==MOS65XX_AM_ABS_IND || m.am==MOS65XX_AM_ABS_X_IND)
                memory_access = OperandAccess::read;
            break;
        default: break;
        }
        std::array<uint16_t,64> reads{},writes{};uint8_t nr=0,nw=0;
        const bool known=cs_regs_access(handle,&insn,reads.data(),&nr,writes.data(),&nw)==CS_ERR_OK;
        const auto has_register=[&](const auto &set,uint8_t count,unsigned reg){
            return std::find(set.begin(),set.begin()+count,reg)!=set.begin()+count;
        };
        for(unsigned i=0;i<m.op_count;i++){
            const auto &op=m.operands[i];
            if(op.type==MOS65XX_OP_REG&&known){
                auto r=named_register(handle,op.reg,8,architecture);if(!r)continue;
                const bool rd=has_register(reads,nr,op.reg),wr=has_register(writes,nw,op.reg);
                if(rd||wr){out.operands.emplace_back(*r);out.access.push_back(rd&&wr?OperandAccess::read_write:wr?OperandAccess::write:OperandAccess::read);}
            }else if(op.type==MOS65XX_OP_IMM){
                out.operands.emplace_back(ImmediateOperand{op.imm,8,8,false,{}});
                out.access.push_back(OperandAccess::read);
            }else if(op.type==MOS65XX_OP_MEM){
                MemoryOperand mem;mem.address_width=16;mem.data_width=8;
                mem.displacement=static_cast<std::int64_t>(op.mem);
                switch(m.am){
                case MOS65XX_AM_ZP_X:case MOS65XX_AM_ABS_X:case MOS65XX_AM_ZP_X_IND:case MOS65XX_AM_ABS_X_IND:
                    mem.index=RegisterOperand{RegisterBank::mos6502,1,8,false};break;
                case MOS65XX_AM_ZP_Y:case MOS65XX_AM_ABS_Y:case MOS65XX_AM_ZP_IND_Y:case MOS65XX_AM_ZP_IND_LONG_Y:
                    mem.index=RegisterOperand{RegisterBank::mos6502,2,8,false};break;
                default:break;
                }
                if((m.am==MOS65XX_AM_ZP||m.am==MOS65XX_AM_ABS||m.am==MOS65XX_AM_ZP_REL||
                    m.am==MOS65XX_AM_REL||m.am==MOS65XX_AM_ZP_IND||m.am==MOS65XX_AM_ZP_IND_Y||
                    m.am==MOS65XX_AM_ZP_IND_LONG||m.am==MOS65XX_AM_ABS_IND||
                    m.am==MOS65XX_AM_ABS_IND_LONG)&&op.mem<=UINT16_MAX)
                    mem.resolved_address=Address{out.address.space,op.mem};
                const bool relative_target = (m.am==MOS65XX_AM_REL && i==0) ||
                    (m.am==MOS65XX_AM_ZP_REL && i==1);
                const auto access = relative_target ? OperandAccess::address : memory_access;
                out.operands.emplace_back(mem);out.access.push_back(access);
                out.memory_read |= access==OperandAccess::read || access==OperandAccess::read_write;
                out.memory_write |= access==OperandAccess::write || access==OperandAccess::read_write;
                if((insn.id==MOS65XX_INS_JMP||insn.id==MOS65XX_INS_JSR)&&m.am==MOS65XX_AM_ABS&&op.mem<=UINT16_MAX)
                    out.direct_target=Address{out.address.space,op.mem};
            }
        }
        // An indirect memory operand reads its pointer bytes even for a store
        // whose final data access is write-only. The generic operand model has
        // no separate pointer operand, so preserve this conservative summary.
        switch (m.am) {
        case MOS65XX_AM_ZP_IND: case MOS65XX_AM_ZP_X_IND: case MOS65XX_AM_ZP_IND_Y:
        case MOS65XX_AM_ZP_IND_LONG: case MOS65XX_AM_ZP_IND_LONG_Y:
        case MOS65XX_AM_ABS_IND: case MOS65XX_AM_ABS_X_IND: case MOS65XX_AM_ABS_IND_LONG:
        case MOS65XX_AM_SR_IND_Y:
            out.memory_read = true;
            break;
        default:
            break;
        }
        switch(insn.id){
        case MOS65XX_INS_BCC:case MOS65XX_INS_BCS:case MOS65XX_INS_BEQ:case MOS65XX_INS_BMI:
        case MOS65XX_INS_BNE:case MOS65XX_INS_BPL:case MOS65XX_INS_BVC:case MOS65XX_INS_BVS:
        case MOS65XX_INS_BBR:case MOS65XX_INS_BBS:
            out.flow=FlowKind::conditional_branch;break;
        case MOS65XX_INS_BRA:case MOS65XX_INS_BRL:
            out.flow=FlowKind::jump;break;
        default:break;
        }
        if(m.am==MOS65XX_AM_REL&&m.op_count==1&&m.operands[0].type==MOS65XX_OP_MEM&&
           (out.flow==FlowKind::conditional_branch||out.flow==FlowKind::jump))
            out.direct_target=Address{out.address.space,m.operands[0].mem};
        else if(m.am==MOS65XX_AM_ZP_REL&&m.op_count==2&&m.operands[1].type==MOS65XX_OP_MEM&&
                out.flow==FlowKind::conditional_branch)
            out.direct_target=Address{out.address.space,m.operands[1].mem};
    }
    if(architecture==Architecture::arm64 && control_transfer(out.flow)) {
        const auto &a=d->arm64;
        const bool relative=insn.id==ARM64_INS_B || insn.id==ARM64_INS_BC || insn.id==ARM64_INS_BL ||
                            insn.id==ARM64_INS_CBZ || insn.id==ARM64_INS_CBNZ ||
                            insn.id==ARM64_INS_TBZ || insn.id==ARM64_INS_TBNZ;
        if(relative && a.op_count && a.operands[a.op_count-1].type==ARM64_OP_IMM)
            out.direct_target=absolute_target(out,a.operands[a.op_count-1].imm,64,4);
    } else if(architecture==Architecture::arm && control_transfer(out.flow)) {
        const auto &a=d->arm;
        const bool relative=insn.id==ARM_INS_B || insn.id==ARM_INS_BL || insn.id==ARM_INS_BLX ||
                            insn.id==ARM_INS_CBZ || insn.id==ARM_INS_CBNZ;
        if(relative && a.op_count && a.operands[a.op_count-1].type==ARM_OP_IMM) {
            // The bundled Capstone printer applies the ARM/Thumb PC bias
            // (and Thumb BLX alignment) before storing the detail operand.
            const auto target=static_cast<std::uint32_t>(a.operands[a.op_count-1].imm);
            const unsigned alignment=insn.id==ARM_INS_BLX && out.context.mode==ExecutionMode::thumb?4:
                                     out.context.mode==ExecutionMode::thumb || insn.id==ARM_INS_BLX?2:4;
            if(target%alignment==0)
                out.direct_target=Address{out.address.space,target};
        }
    } else if((architecture==Architecture::riscv32 || architecture==Architecture::riscv64) &&
              control_transfer(out.flow)) {
        const auto &rv=d->riscv;
        if(insn.id==RISCV_INS_JAL && rv.op_count>1 && rv.operands[0].type==RISCV_OP_REG) {
            if(const auto rd=named_register(handle,rv.operands[0].reg,
                                           architecture==Architecture::riscv64?64:32,architecture);
               rd && rd->bank==RegisterBank::riscv_gpr && rd->index==0)
                out.flow=FlowKind::jump;
        }
        if(riscv_relative_branch(insn.id) && rv.op_count && rv.operands[rv.op_count-1].type==RISCV_OP_IMM)
            out.direct_target=relative_target(out,rv.operands[rv.op_count-1].imm,
                architecture==Architecture::riscv64?64:32,out.context.mode==ExecutionMode::rv64c?2:4);
    } else if((architecture==Architecture::mips32 || architecture==Architecture::mips64) &&
              control_transfer(out.flow) && mips_classic_direct(insn.id)) {
        const auto &m=d->mips;
        // These classic MIPS forms use a delay slot and Capstone places the
        // decoded absolute branch address in their final immediate operand.
        out.delay_slots=1;
        if(m.op_count && m.operands[m.op_count-1].type==MIPS_OP_IMM)
            out.direct_target=absolute_target(out,m.operands[m.op_count-1].imm,
                architecture==Architecture::mips64?64:32,4);
    } else if(architecture==Architecture::powerpc && control_transfer(out.flow) &&
              ppc_direct_branch(insn.id)) {
        const auto &p=d->ppc;
        // The bundled Capstone printer has already added the PC for relative
        // PPC branches and retained the absolute result in detail.
        if(p.op_count && p.operands[p.op_count-1].type==PPC_OP_IMM)
            out.direct_target=absolute_target(out,p.operands[p.op_count-1].imm,
                out.context.mode==ExecutionMode::ppc64?64:32,4);
    }
    if (x86) {
      const std::string_view mnemonic(insn.mnemonic);
      if (may_be_conditional_branch && ((mnemonic.size()>1 && mnemonic[0]=='j' && mnemonic!="jmp" && mnemonic!="ljmp") || mnemonic.starts_with("loop")))
          out.flow=FlowKind::conditional_branch;
    }
    if (x86 && d->x86.op_count <= 8) {
        const auto& x=d->x86;
        for(unsigned i=0;i<x.op_count;i++) {
            const auto& op=x.operands[i];
            OperandAccess access = (op.access & CS_AC_READ) && (op.access & CS_AC_WRITE) ? OperandAccess::read_write
                                 : (op.access & CS_AC_WRITE) ? OperandAccess::write
                                 : (op.access & CS_AC_READ) ? OperandAccess::read : OperandAccess::read;
            if(op.type==X86_OP_REG) {
                if (op.access == 0) continue;
                auto r=x86_register(handle,op.reg,op.size*8);
                if(!r) continue;
                out.operands.emplace_back(*r); out.access.push_back(access);
                if(access==OperandAccess::read || access==OperandAccess::read_write) add_unique(out.register_reads,*r);
                if(access==OperandAccess::write || access==OperandAccess::read_write) add_unique(out.register_writes,*r);
            } else if(op.type==X86_OP_IMM) {
                out.operands.emplace_back(ImmediateOperand{static_cast<std::uint64_t>(op.imm),static_cast<std::uint16_t>(op.size*8),static_cast<std::uint16_t>(op.size*8),true,{}});
                out.access.push_back(OperandAccess::read);
                if (out.flow==FlowKind::jump || out.flow==FlowKind::conditional_branch || out.flow==FlowKind::call) {
                    out.direct_target=Address{out.address.space,static_cast<std::uint64_t>(op.imm)};
                }
            } else if(op.type==X86_OP_MEM) {
                if (op.access == 0) continue;
                MemoryOperand m; m.data_width=static_cast<std::uint16_t>(op.size*8);
                m.address_width=out.context.mode==ExecutionMode::x86_16?16:out.context.mode==ExecutionMode::x86_32?32:64;
                m.scale=op.mem.scale>0?static_cast<std::uint8_t>(op.mem.scale):1; m.displacement=op.mem.disp;
                if(op.mem.base) m.base=x86_register(handle,op.mem.base,m.address_width);
                if(op.mem.index) m.index=x86_register(handle,op.mem.index,m.address_width);
                if(op.mem.segment) m.segment=x86_register(handle,op.mem.segment,16);
                m.ip_relative=m.base && m.base->bank==RegisterBank::ip;
                out.operands.emplace_back(m); out.access.push_back(access);
                out.memory_read |= access==OperandAccess::read || access==OperandAccess::read_write;
                out.memory_write |= access==OperandAccess::write || access==OperandAccess::read_write;
                if(m.base) add_unique(out.register_reads,*m.base);
                if(m.index) add_unique(out.register_reads,*m.index);
            }
        }
    }
    std::array<uint16_t,64> read{}, write{}; uint8_t read_count=0,write_count=0;
    if(cs_regs_access(handle,&insn,read.data(),&read_count,write.data(),&write_count)==CS_ERR_OK) {
        std::vector<RegisterOperand> rr,rw; bool complete=true;
        const unsigned width=architecture==Architecture::arm64||architecture==Architecture::mips64||architecture==Architecture::riscv64?64:architecture==Architecture::arm||architecture==Architecture::mips32||architecture==Architecture::riscv32?32:architecture==Architecture::powerpc?(out.context.mode==ExecutionMode::ppc64?64:32):architecture==Architecture::x86_64?64:architecture==Architecture::x86?out.context.mode==ExecutionMode::x86_64?64:out.context.mode==ExecutionMode::x86_32?32:16:8;
        for(unsigned i=0;i<read_count;i++) { auto r=named_register(handle,read[i],width,architecture); if(!r){complete=false;break;} add_unique(rr,*r); }
        for(unsigned i=0;i<write_count && complete;i++) { auto r=named_register(handle,write[i],width,architecture); if(!r){complete=false;break;} add_unique(rw,*r); }
        if(complete) { out.register_reads=std::move(rr); out.register_writes=std::move(rw); }
    }
    if (architecture == Architecture::mos6502) {
        bool stack_read = false, stack_write = false;
        switch (insn.id) {
        case MOS65XX_INS_PHA: case MOS65XX_INS_PHP:
        case MOS65XX_INS_JSR: case MOS65XX_INS_BRK:
            stack_write = true; break;
        case MOS65XX_INS_PLA: case MOS65XX_INS_PLP:
        case MOS65XX_INS_RTS: case MOS65XX_INS_RTI:
            stack_read = true; break;
        default: break;
        }
        if (stack_read || stack_write) {
            const RegisterOperand stack{RegisterBank::mos6502, 4, 8, false};
            add_unique(out.register_reads, stack);
            add_unique(out.register_writes, stack);
            out.memory_read |= stack_read;
            out.memory_write |= stack_write;
        }
    }
}
bool capstone_context(DecodeContext context, cs_arch &arch, cs_mode &mode) {
    const bool mips_mode =
        (context.architecture == Architecture::mips32 && context.mode == ExecutionMode::mips32) ||
        (context.architecture == Architecture::mips64 && context.mode == ExecutionMode::mips64);
    const bool powerpc_mode = context.architecture == Architecture::powerpc &&
        (context.mode == ExecutionMode::ppc32 || context.mode == ExecutionMode::ppc64);
    if (context.order != ByteOrder::little &&
        !(context.order == ByteOrder::big && (mips_mode || powerpc_mode)))
        return false;
    const auto endian = context.order == ByteOrder::big ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
    switch (context.mode) {
    case ExecutionMode::a64:
        if (context.architecture != Architecture::arm64) return false;
        arch = CS_ARCH_ARM64; mode = CS_MODE_LITTLE_ENDIAN; return true;
    case ExecutionMode::a32:
        if (context.architecture != Architecture::arm) return false;
        arch = CS_ARCH_ARM; mode = static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN); return true;
    case ExecutionMode::thumb:
        if (context.architecture != Architecture::arm) return false;
        arch = CS_ARCH_ARM; mode = static_cast<cs_mode>(CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); return true;
    case ExecutionMode::mips32:
        if (context.architecture != Architecture::mips32) return false;
        arch = CS_ARCH_MIPS; mode = static_cast<cs_mode>(CS_MODE_MIPS32 | endian); return true;
    case ExecutionMode::mips64:
        if (context.architecture != Architecture::mips64) return false;
        arch = CS_ARCH_MIPS; mode = static_cast<cs_mode>(CS_MODE_MIPS64 | endian); return true;
    case ExecutionMode::rv32:
        if (context.architecture != Architecture::riscv32) return false;
        arch = CS_ARCH_RISCV; mode = static_cast<cs_mode>(CS_MODE_RISCV32 | CS_MODE_LITTLE_ENDIAN); return true;
    case ExecutionMode::rv64:
    case ExecutionMode::rv64c:
        if (context.architecture != Architecture::riscv64) return false;
        arch = CS_ARCH_RISCV;
        mode = static_cast<cs_mode>(CS_MODE_RISCV64 | CS_MODE_LITTLE_ENDIAN |
                                    (context.mode == ExecutionMode::rv64c ? CS_MODE_RISCVC : 0));
        return true;
    case ExecutionMode::m6502:
        if (context.architecture != Architecture::mos6502) return false;
        arch = CS_ARCH_MOS65XX; mode = static_cast<cs_mode>(CS_MODE_MOS65XX_6502 | CS_MODE_LITTLE_ENDIAN); return true;
    case ExecutionMode::x86_16:
    case ExecutionMode::x86_32:
    case ExecutionMode::x86_64:
        if (context.architecture != Architecture::x86 && context.architecture != Architecture::x86_64) return false;
        arch = CS_ARCH_X86;
        mode = context.mode == ExecutionMode::x86_16 ? CS_MODE_16
             : context.mode == ExecutionMode::x86_32 ? CS_MODE_32 : CS_MODE_64;
        return true;
    case ExecutionMode::ppc32:
    case ExecutionMode::ppc64:
        if (context.architecture != Architecture::powerpc) return false;
        arch = CS_ARCH_PPC;
        mode = static_cast<cs_mode>((context.mode == ExecutionMode::ppc32 ? CS_MODE_32 : CS_MODE_64) | endian);
        return true;
    default: return false;
    }
}
}

DecodeResult decode_capstone_fallback(DecodeContext context, std::span<const std::byte> bytes, Address address) {
    cs_arch arch{};
    cs_mode mode{};
    if (!capstone_context(context, arch, mode))
        return {DecodeStatus::unsupported, {}, "Capstone fallback has no matching architecture mode"};
    if (bytes.empty())
        return {DecodeStatus::truncated, {}, "No bytes available for fallback decode"};
    csh handle{};
    if (cs_open(arch, mode, &handle) != CS_ERR_OK)
        return {DecodeStatus::unsupported, {}, "Capstone could not initialize the requested mode"};
    if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) { cs_close(&handle); return {DecodeStatus::unsupported, {}, "Capstone detail unavailable"}; }
    cs_insn *decoded = nullptr;
    const auto count = cs_disasm(handle, reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size(),
                                 address.offset, 1, &decoded);
    if (count == 0 || decoded == nullptr) {
        cs_close(&handle);
        return {DecodeStatus::unsupported, {}, "Capstone found no instruction in the available bytes"};
    }
    if (decoded[0].size == 0 || decoded[0].size > bytes.size() || decoded[0].size > Instruction{}.bytes.size()) {
        cs_free(decoded, count);
        cs_close(&handle);
        return {DecodeStatus::unsupported, {}, "Capstone returned an invalid instruction length"};
    }
    Instruction instruction;
    instruction.context = context;
    instruction.address = address;
    instruction.length = static_cast<std::uint8_t>(decoded[0].size);
    instruction.opcode = Opcode::opaque;
    instruction.mnemonic_override = decoded[0].mnemonic;
    if (decoded[0].op_str[0]) {
        instruction.mnemonic_override += " ";
        instruction.mnemonic_override += decoded[0].op_str;
    }
    std::copy_n(bytes.begin(), instruction.length, instruction.bytes.begin());
    apply_capstone_detail(handle, decoded[0], instruction, context.architecture);
    cs_free(decoded, count);
    cs_close(&handle);
    return {DecodeStatus::decoded, std::move(instruction), {}};
}
}
