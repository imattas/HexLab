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
    }
    if(arch==Architecture::powerpc){ if(auto i=number("r",32)) return RegisterOperand{RegisterBank::ppc_gpr,static_cast<std::uint8_t>(*i),static_cast<std::uint16_t>(width),false}; }
    return {};
}
void add_unique(std::vector<RegisterOperand>& v, RegisterOperand r) {
    if (std::find(v.begin(),v.end(),r)==v.end()) v.push_back(r);
}
void apply_capstone_detail(csh handle, const cs_insn& insn, Instruction& out, Architecture architecture) {
    const auto *d=insn.detail;
    if (!d) return;
    for(unsigned i=0;i<d->groups_count;i++) {
        switch(d->groups[i]) {
        case CS_GRP_CALL: out.flow=FlowKind::call; break;
        case CS_GRP_RET: case CS_GRP_IRET: out.flow=FlowKind::ret; break;
        case CS_GRP_INT: out.flow=FlowKind::trap; break;
        case CS_GRP_JUMP:
            // Capstone does not identify conditionality portably. On x86, a
            // relative branch group or a conditional mnemonic is explicit.
            if (insn.id == X86_INS_JMP || insn.id == X86_INS_LJMP) out.flow=FlowKind::jump;
            else if (insn.id >= X86_INS_JAE && insn.id <= X86_INS_JS) out.flow=FlowKind::conditional_branch;
            else out.flow=FlowKind::jump;
            break;
        }
    }
    const bool x86=architecture==Architecture::x86 || architecture==Architecture::x86_64;
    if (architecture==Architecture::arm64) {
        const auto& a=d->arm64; if(a.op_count>8)return;
        for(unsigned i=0;i<a.op_count;i++) { const auto& op=a.operands[i];
            if(op.access==0 && (op.type==ARM64_OP_REG||op.type==ARM64_OP_MEM)) continue;
            const auto ac=(op.access&CS_AC_WRITE)?((op.access&CS_AC_READ)?OperandAccess::read_write:OperandAccess::write):OperandAccess::read;
            if(op.type==ARM64_OP_REG){auto r=named_register(handle,op.reg,64,architecture); if(r){out.operands.emplace_back(*r);out.access.push_back(ac);}}
            else if(op.type==ARM64_OP_IMM){out.operands.emplace_back(ImmediateOperand{static_cast<std::uint64_t>(op.imm),64,64,true,{}});out.access.push_back(OperandAccess::read);if(out.flow==FlowKind::call||out.flow==FlowKind::jump||out.flow==FlowKind::conditional_branch)out.direct_target=Address{out.address.space,static_cast<std::uint64_t>(op.imm)};}
            else if(op.type==ARM64_OP_MEM){MemoryOperand m;m.address_width=64;m.displacement=op.mem.disp;m.base=named_register(handle,op.mem.base,64,architecture);if(op.mem.index)m.index=named_register(handle,op.mem.index,64,architecture);out.operands.emplace_back(m);out.access.push_back(ac);out.memory_read|=ac!=OperandAccess::write;out.memory_write|=ac==OperandAccess::write||ac==OperandAccess::read_write;}
        }
    } else if (architecture==Architecture::arm) {
        const auto& a=d->arm;if(a.op_count>36)return;
        for(unsigned i=0;i<a.op_count;i++){const auto& op=a.operands[i];if(op.access==0&&(op.type==ARM_OP_REG||op.type==ARM_OP_MEM))continue;const auto ac=(op.access&CS_AC_WRITE)?((op.access&CS_AC_READ)?OperandAccess::read_write:OperandAccess::write):OperandAccess::read;
            if(op.type==ARM_OP_REG){auto r=named_register(handle,op.reg,32,architecture);if(r){out.operands.emplace_back(*r);out.access.push_back(ac);}}
            else if(op.type==ARM_OP_IMM){out.operands.emplace_back(ImmediateOperand{static_cast<std::uint32_t>(op.imm),32,32,true,{}});out.access.push_back(OperandAccess::read);if(out.flow==FlowKind::call||out.flow==FlowKind::jump||out.flow==FlowKind::conditional_branch)out.direct_target=Address{out.address.space,static_cast<std::uint32_t>(op.imm)};}
            else if(op.type==ARM_OP_MEM){MemoryOperand m;m.address_width=32;m.displacement=op.mem.disp;m.scale=op.mem.scale>0?static_cast<std::uint8_t>(op.mem.scale):1;m.base=named_register(handle,op.mem.base,32,architecture);if(op.mem.index)m.index=named_register(handle,op.mem.index,32,architecture);out.operands.emplace_back(m);out.access.push_back(ac);out.memory_read|=ac!=OperandAccess::write;out.memory_write|=ac==OperandAccess::write||ac==OperandAccess::read_write;}
        }
    } else if (architecture==Architecture::riscv32 || architecture==Architecture::riscv64) {
        const auto& rv=d->riscv; if(rv.op_count>8)return;
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
                m.base=named_register(handle,op.mem.base,m.address_width,architecture);
                out.operands.emplace_back(m);out.access.push_back(OperandAccess::address);
            }
        }
    } else if (architecture==Architecture::mips32 || architecture==Architecture::mips64) {
        const auto& m=d->mips;if(m.op_count>10)return;
        std::array<uint16_t,64> reads{},writes{};uint8_t nr=0,nw=0;
        const bool known=cs_regs_access(handle,&insn,reads.data(),&nr,writes.data(),&nw)==CS_ERR_OK;
        for(unsigned i=0;i<m.op_count;i++){const auto& op=m.operands[i];
            if(op.type==MIPS_OP_IMM){out.operands.emplace_back(ImmediateOperand{static_cast<std::uint64_t>(op.imm),64,64,true,{}});out.access.push_back(OperandAccess::read);}
            else if(op.type==MIPS_OP_REG&&known){auto r=named_register(handle,op.reg,architecture==Architecture::mips64?64:32,architecture);if(!r)continue;bool rd=false,wr=false;for(unsigned j=0;j<nr;j++)rd|=reads[j]==op.reg;for(unsigned j=0;j<nw;j++)wr|=writes[j]==op.reg;if(rd||wr){out.operands.emplace_back(*r);out.access.push_back(rd&&wr?OperandAccess::read_write:wr?OperandAccess::write:OperandAccess::read);}}
            else if(op.type==MIPS_OP_MEM){MemoryOperand mem;mem.address_width=architecture==Architecture::mips64?64:32;mem.displacement=op.mem.disp;mem.base=named_register(handle,op.mem.base,mem.address_width,architecture);out.operands.emplace_back(mem);out.access.push_back(OperandAccess::address);}
        }
    } else if (architecture==Architecture::powerpc) {
        const auto& p=d->ppc;if(p.op_count>8)return;
        std::array<uint16_t,64> reads{},writes{};uint8_t nr=0,nw=0;
        const bool known=cs_regs_access(handle,&insn,reads.data(),&nr,writes.data(),&nw)==CS_ERR_OK;
        for(unsigned i=0;i<p.op_count;i++){const auto& op=p.operands[i];
            if(op.type==PPC_OP_IMM){out.operands.emplace_back(ImmediateOperand{static_cast<std::uint64_t>(op.imm),64,64,true,{}});out.access.push_back(OperandAccess::read);}
            else if(op.type==PPC_OP_REG&&known){auto r=named_register(handle,op.reg,out.context.mode==ExecutionMode::ppc64?64:32,architecture);if(!r)continue;bool rd=false,wr=false;for(unsigned j=0;j<nr;j++)rd|=reads[j]==op.reg;for(unsigned j=0;j<nw;j++)wr|=writes[j]==op.reg;if(rd||wr){out.operands.emplace_back(*r);out.access.push_back(rd&&wr?OperandAccess::read_write:wr?OperandAccess::write:OperandAccess::read);}}
            else if(op.type==PPC_OP_MEM){MemoryOperand mem;mem.address_width=out.context.mode==ExecutionMode::ppc64?64:32;mem.displacement=op.mem.disp;mem.base=named_register(handle,op.mem.base,mem.address_width,architecture);out.operands.emplace_back(mem);out.access.push_back(OperandAccess::address);}
        }
    } else if (architecture==Architecture::mos6502) {
        const auto &m=d->mos65xx;
        if(m.op_count>3)return;
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
                    m.am==MOS65XX_AM_REL)&&op.mem<=UINT16_MAX)
                    mem.resolved_address=Address{out.address.space,op.mem};
                out.operands.emplace_back(mem);out.access.push_back(OperandAccess::address);
                if((insn.id==MOS65XX_INS_JMP||insn.id==MOS65XX_INS_JSR)&&m.am==MOS65XX_AM_ABS&&op.mem<=UINT16_MAX)
                    out.direct_target=Address{out.address.space,op.mem};
            }
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
    if (x86) {
      const std::string_view mnemonic(insn.mnemonic);
      if (out.flow==FlowKind::jump && ((mnemonic.size()>1 && mnemonic[0]=='j' && mnemonic!="jmp" && mnemonic!="ljmp") || mnemonic.starts_with("loop")))
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
