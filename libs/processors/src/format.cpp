#include "hexlab/processors/format.hpp"
#include "x64_internal.hpp"
#include "a64_internal.hpp"
#include "arm32_internal.hpp"
#include <algorithm>
#include <sstream>

namespace hexlab {
namespace {
std::string hex(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}
std::string signed_hex(std::int64_t value) {
    return value < 0 ? "-" + hex(static_cast<std::uint64_t>(-(value + 1)) + 1) : hex(static_cast<std::uint64_t>(value));
}
const char *riscv_status_trap_csr_name(std::uint64_t number) noexcept {
    switch (number) {
    case 0x100: return "sstatus";
    case 0x104: return "sie";
    case 0x105: return "stvec";
    case 0x106: return "scounteren";
    case 0x140: return "sscratch";
    case 0x141: return "sepc";
    case 0x142: return "scause";
    case 0x143: return "stval";
    case 0x144: return "sip";
    case 0x180: return "satp";
    case 0x300: return "mstatus";
    case 0x301: return "misa";
    case 0x302: return "medeleg";
    case 0x303: return "mideleg";
    case 0x304: return "mie";
    case 0x305: return "mtvec";
    case 0x306: return "mcounteren";
    case 0x340: return "mscratch";
    case 0x341: return "mepc";
    case 0x342: return "mcause";
    case 0x343: return "mtval";
    case 0x344: return "mip";
    default: return nullptr;
    }
}
std::string memory_text(const MemoryOperand &m, bool address_only) {
    std::string out;
    if (!address_only)
        out += m.data_width == 8    ? "byte ptr "
               : m.data_width == 16 ? "word ptr "
               : m.data_width == 32 ? "dword ptr "
               : m.data_width == 48 ? "fword ptr "
               : m.data_width == 80 ? "tbyte ptr "
               : m.data_width == 128 ? "xmmword ptr "
               : m.data_width == 256 ? "ymmword ptr "
               : m.data_width == 512 ? "zmmword ptr "
               : m.data_width == 112 ? "14-byte ptr "
               : m.data_width == 224 ? "28-byte ptr "
               : m.data_width == 752 ? "94-byte ptr "
               : m.data_width == 864 ? "108-byte ptr "
                                    : "qword ptr ";
    if (m.segment)
        out += register_name(*m.segment) + ":";
    out += "[";
    bool term = false;
    if (m.base) {
        out += register_name(*m.base);
        term = true;
    }
    if (m.index) {
        if (term)
            out += " + ";
        out += register_name(*m.index);
        if (m.scale != 1)
            out += "*" + std::to_string(m.scale);
        term = true;
    }
    if (!term)
        out += m.resolved_address ? hex(m.resolved_address->offset) : signed_hex(m.displacement);
    else if (m.displacement)
        out += (m.displacement < 0 ? " - " : " + ") + hex(m.displacement < 0
                                                              ? static_cast<std::uint64_t>(-(m.displacement + 1)) + 1
                                                              : static_cast<std::uint64_t>(m.displacement));
    out += "]";
    if (m.writeback) {
        if (m.post_index)
            out += ", " + signed_hex(m.writeback_displacement);
        else
            out += "!";
    }
    return out;
}
} // namespace
std::string register_name(const RegisterOperand &r) {
    if (r.bank == RegisterBank::x87)
        return r.width == 80 && r.index < 8 ? (r.index == 0 ? "st" : "st(" + std::to_string(r.index) + ")")
                                            : "?x87-register";
    if (r.bank == RegisterBank::x87_status) return r.index == 0 && r.width == 16 ? "fsw" : "?x87-status";
    if (r.bank == RegisterBank::x87_control) return r.index == 0 && r.width == 16 ? "fcw" : "?x87-control";
    if (r.bank == RegisterBank::x87_tag) return r.index == 0 && r.width == 16 ? "ftw" : "?x87-tag";
    if (r.bank == RegisterBank::xmm)
        return r.width == 128 && r.index < 32 ? "xmm" + std::to_string(r.index) : "?xmm-register";
    if (r.bank == RegisterBank::ymm)
        return r.width == 256 && r.index < 32 ? "ymm" + std::to_string(r.index) : "?ymm-register";
    if (r.bank == RegisterBank::zmm)
        return r.width == 512 && r.index < 32 ? "zmm" + std::to_string(r.index) : "?zmm-register";
    if (r.bank == RegisterBank::opmask)
        return r.width == 64 && r.index < 8 ? "k" + std::to_string(r.index) : "?opmask-register";
    if (r.bank == RegisterBank::arm64_simd)
        return r.index < 32 && (r.width == 64 || r.width == 128)
            ? "v" + std::to_string(r.index) : "?arm64-simd-register";
    if (r.bank == RegisterBank::dex_vreg)
        return r.index <= 65535 && r.width == 32 ? "v" + std::to_string(r.index) : "?dex-register";
    if (r.bank == RegisterBank::mos6502) {
        static constexpr const char *names[]{"a", "x", "y", "p", "s"};
        return r.index < std::size(names) && r.width == 8 ? names[r.index] : "?6502-register";
    }
    if (r.bank == RegisterBank::mips_gpr) {
        static constexpr const char *names[]{"zero","at","v0","v1","a0","a1","a2","a3","t0","t1","t2","t3","t4","t5","t6","t7","s0","s1","s2","s3","s4","s5","s6","s7","t8","t9","k0","k1","gp","sp","fp","ra"};
        return r.index < 32 && (r.width == 32 || r.width == 64) ? names[r.index] : "?mips-register";
    }
    if (r.bank == RegisterBank::mips_fpr)
        return r.index < 32 && (r.width == 32 || r.width == 64) ? "f" + std::to_string(r.index) : "?mips-fpr";
    if (r.bank == RegisterBank::mips_fcsr) {
        if (r.width != 32) return "?mips-fcsr";
        if (r.index >= 1 && r.index <= 8) return "fcc" + std::to_string(r.index - 1);
        switch (r.index) {
        case 0: return "fcsr";
        case 25: return "fccr";
        case 26: return "fexr";
        case 28: return "fenr";
        default: return "?mips-fcsr";
        }
    }
    if (r.bank == RegisterBank::ppc_gpr)
        return r.index < 32 && (r.width == 32 || r.width == 64) ? "r" + std::to_string(r.index) : "?ppc-register";
    if (r.bank == RegisterBank::ppc_fpr)
        return r.index < 32 && (r.width == 32 || r.width == 64) ? "f" + std::to_string(r.index) : "?ppc-fpr";
    if (r.bank == RegisterBank::ppc_vr)
        return r.index < 32 && r.width == 128 ? "v" + std::to_string(r.index) : "?ppc-vr";
    if (r.bank == RegisterBank::ppc_cr)
        return r.width == 32 && r.index == 0 ? "cr" : r.index < 8 && r.width == 4 ? "cr" + std::to_string(r.index) : "?ppc-cr";
    if (r.bank == RegisterBank::ppc_crbit) {
        static constexpr const char *bit_names[]{"lt", "gt", "eq", "so"};
        return r.width == 1 && r.index < 32 ? "cr" + std::to_string(r.index / 4) + "." + bit_names[r.index % 4]
                                            : "?ppc-crbit";
    }
    if (r.bank == RegisterBank::ppc_lr)
        return r.index == 0 && (r.width == 32 || r.width == 64) ? "lr" : "?ppc-lr";
    if (r.bank == RegisterBank::ppc_ctr)
        return r.index == 0 && (r.width == 32 || r.width == 64) ? "ctr" : "?ppc-ctr";
    if (r.bank == RegisterBank::ppc_xer)
        return r.index == 0 && r.width == 32 ? "xer" : "?ppc-xer";
    if (r.bank == RegisterBank::ppc_fpscr)
        return r.index == 0 && r.width == 32 ? "fpscr" : "?ppc-fpscr";
    if (r.bank == RegisterBank::mips_hilo)
        return r.index == 0 && (r.width == 32 || r.width == 64) ? "hi" : r.index == 1 && (r.width == 32 || r.width == 64) ? "lo" : "?mips-hilo";
    if (r.bank == RegisterBank::mips_cp0) {
        static constexpr const char *names[]{"index", "random", "entrylo0", "entrylo1", "context", "pagemask",
                                              "wired", "hwrena", "badvaddr", "count", "entryhi", "compare",
                                              "status", "cause", "epc", "prid", "config", "lladdr", "watchlo",
                                              "watchhi", "xcontext", "?c0r21", "?c0r22", "debug", "depc",
                                              "?c0r25", "?c0r26", "?c0r27", "taglo", "taghi", "errorepc", "desave"};
        if (r.index >= 32 || (r.width != 32 && r.width != 64)) return "?mips-cp0-register";
        const auto name = names[r.index];
        return name[0] == '?' ? "c0r" + std::to_string(r.index) : name;
    }
    if (r.bank == RegisterBank::riscv_gpr)
        return r.index < 32 && (r.width == 32 || r.width == 64) ? "x" + std::to_string(r.index) : "?riscv-register";
    if (r.bank == RegisterBank::riscv_fpr)
        return r.index < 32 && r.width == 64 ? "f" + std::to_string(r.index) : "?riscv-fpr";
    if (r.bank == RegisterBank::riscv_fstatus) return r.index == 1 ? "frm" : "fflags";
    if (r.bank == RegisterBank::riscv_vpr)
        return r.index < 32 ? "v" + std::to_string(r.index) : "?riscv-vector-register";
    if (r.bank == RegisterBank::riscv_vcsr)
        return r.index == 0 ? "vl" : r.index == 1 ? "vtype" : r.index == 2 ? "vstart" : "?riscv-vector-state";
    if (r.bank == RegisterBank::arm64_gpr)
        return r.index < 31 && (r.width == 32 || r.width == 64)
                   ? std::string(r.width == 64 ? "x" : "w") + std::to_string(r.index)
                   : "?arm64-register";
    if (r.bank == RegisterBank::arm64_sp)
        return r.index == 31 && r.width == 64 ? "sp" : r.index == 31 && r.width == 32 ? "wsp" : "?arm64-sp";
    if (r.bank == RegisterBank::arm64_zero)
        return r.index == 31 && r.width == 64 ? "xzr" : r.index == 31 && r.width == 32 ? "wzr" : "?arm64-zero";
    if (r.bank == RegisterBank::arm_flags)
        return r.index == 0 && r.width == 4 ? "nzcv" : "?arm-flags";
    if (r.bank == RegisterBank::arm32_gpr)
        return r.index < 16 && r.width == 32 ? "r" + std::to_string(r.index) : "?arm32-register";
    if (r.bank == RegisterBank::arm32_vfp)
        return arm32_vfp_register_valid(r)
            ? std::string(r.width == 64 ? "d" : "s") + std::to_string(r.index) : "?arm32-vfp-register";
    static constexpr const char *names8[]{"al",  "cl",  "dl",   "bl",   "spl",  "bpl",  "sil",  "dil",
                                          "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};
    static constexpr const char *names16[]{"ax",  "cx",  "dx",   "bx",   "sp",   "bp",   "si",   "di",
                                           "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
    static constexpr const char *names32[]{"eax", "ecx", "edx",  "ebx",  "esp",  "ebp",  "esi",  "edi",
                                           "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
    static constexpr const char *names64[]{"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                           "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
    static constexpr const char *high[]{"ah", "ch", "dh", "bh"};
    static constexpr const char *segments[]{"es", "cs", "ss", "ds", "fs", "gs"};
    if (r.bank == RegisterBank::ip)
        return r.width == 16 ? "ip" : r.width == 32 ? "eip" : "rip";
    if (r.bank == RegisterBank::flags)
        return r.width == 16 ? "flags" : r.width == 32 ? "eflags" : "rflags";
    if (r.bank == RegisterBank::segment)
        return r.index < 6 ? segments[r.index] : "?segment";
    if (r.high_byte)
        return r.index < 4 ? high[r.index] : "?high";
    if (r.index >= 16)
        return "?register";
    return r.width == 8    ? names8[r.index]
           : r.width == 16 ? names16[r.index]
           : r.width == 32 ? names32[r.index]
                           : names64[r.index];
}
std::string opcode_name(Opcode op, std::uint8_t condition) {
    if (op == Opcode::x87)
        return "x87";
    if (op >= Opcode::mips_sll && op <= Opcode::mips_swr) {
        static constexpr const char *names[]{"sll","srl","sra","sllv","srlv","srav","jr","jalr","add","addu","sub","subu","and","or","xor","nor","slt","sltu","j","jal","beq","bne","blez","bgtz","addi","addiu","slti","sltiu","andi","ori","xori","lui","bltz","bgez","lb","lh","lwl","lw","lbu","lhu","lwr","sb","sh","swl","sw","swr"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::mips_sll)];
    }
    if (op >= Opcode::mips_mult && op <= Opcode::mips_mtlo) {
        static constexpr const char *names[]{"mult", "multu", "div", "divu", "mfhi", "mflo", "mthi", "mtlo"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::mips_mult)];
    }
    if (op >= Opcode::mips_syscall && op <= Opcode::mips_eret) {
        static constexpr const char *names[]{"syscall", "break", "sync", "mfc0", "mtc0", "eret"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::mips_syscall)];
    }
    if (op >= Opcode::mips_lwc1 && op <= Opcode::mips_bc1f) {
        static constexpr const char *names[]{"lwc1","swc1","add.s","sub.s","mul.s","div.s","sqrt.s","abs.s","mov.s","neg.s","c.eq.s","c.lt.s","c.le.s","bc1t","bc1f"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::mips_lwc1)];
    }
    switch (op) {
    case Opcode::mips64_jr_hb: return "jr.hb";
    case Opcode::mips64_jalr_hb: return "jalr.hb";
    case Opcode::mips64_c_cond_s: return "c.cond.s";
    case Opcode::mips64_c_cond_d: return "c.cond.d";
    case Opcode::mips64_bc1tl: return "bc1tl";
    case Opcode::mips64_bc1fl: return "bc1fl";
    case Opcode::mips_bc1tl: return "bc1tl";
    case Opcode::mips_bc1fl: return "bc1fl";
    case Opcode::mips_clz: return "clz";
    case Opcode::mips_clo: return "clo";
    case Opcode::mips_mul: return "mul";
    case Opcode::mips64_dclz: return "dclz";
    case Opcode::mips64_dclo: return "dclo";
    case Opcode::mips64_mul: return "mul";
    case Opcode::mips64_madd: return "madd";
    case Opcode::mips64_maddu: return "maddu";
    case Opcode::mips64_msub: return "msub";
    case Opcode::mips64_msubu: return "msubu";
    case Opcode::mips64_drotr: return "drotr";
    case Opcode::mips64_drotr32: return "drotr32";
    case Opcode::mips64_drotrv: return "drotrv";
    case Opcode::mips64_rotr: return "rotr";
    case Opcode::mips64_rotrv: return "rotrv";
    case Opcode::mips64_dextm: return "dextm";
    case Opcode::mips64_dextu: return "dextu";
    case Opcode::mips64_dext: return "dext";
    case Opcode::mips64_dinsm: return "dinsm";
    case Opcode::mips64_dinsu: return "dinsu";
    case Opcode::mips64_dins: return "dins";
    case Opcode::mips64_dsbh: return "dsbh";
    case Opcode::mips64_dshd: return "dshd";
    case Opcode::mips64_wsbh: return "wsbh";
    case Opcode::mips64_seb: return "seb";
    case Opcode::mips64_seh: return "seh";
    case Opcode::mips_ext: return "ext";
    case Opcode::mips_ins: return "ins";
    case Opcode::rdrand: return "rdrand";
    case Opcode::rdseed: return "rdseed";
    case Opcode::crc32: return "crc32";
    case Opcode::comiss: return "comiss";
    case Opcode::ucomiss: return "ucomiss";
    case Opcode::comisd: return "comisd";
    case Opcode::ucomisd: return "ucomisd";
    case Opcode::movbe: return "movbe";
    case Opcode::mips64_movf: return "movf";
    case Opcode::mips64_movt: return "movt";
    case Opcode::mips64_movz: return "movz";
    case Opcode::mips64_movn: return "movn";
    case Opcode::mips_movf_s: return "movf.s";
    case Opcode::mips_movt_s: return "movt.s";
    case Opcode::mips_movz_s: return "movz.s";
    case Opcode::mips_movn_s: return "movn.s";
    case Opcode::mips_movf_d: return "movf.d";
    case Opcode::mips_movt_d: return "movt.d";
    case Opcode::mips_movz_d: return "movz.d";
    case Opcode::mips_movn_d: return "movn.d";
    case Opcode::mips32_movz: return "movz";
    case Opcode::mips32_movn: return "movn";
    case Opcode::mips64_movf_s: return "movf.s";
    case Opcode::mips64_movt_s: return "movt.s";
    case Opcode::mips64_movz_s: return "movz.s";
    case Opcode::mips64_movn_s: return "movn.s";
    case Opcode::mips64_movf_d: return "movf.d";
    case Opcode::mips64_movt_d: return "movt.d";
    case Opcode::mips64_movz_d: return "movz.d";
    case Opcode::mips64_movn_d: return "movn.d";
    case Opcode::mips64_bltzal: return "bltzal";
    case Opcode::mips64_bgezal: return "bgezal";
    case Opcode::mips64_bltzall: return "bltzall";
    case Opcode::mips64_bgezall: return "bgezall";
    case Opcode::mips64_tge: return "tge";
    case Opcode::mips64_tgeu: return "tgeu";
    case Opcode::mips64_tlt: return "tlt";
    case Opcode::mips64_tltu: return "tltu";
    case Opcode::mips64_teq: return "teq";
    case Opcode::mips64_tne: return "tne";
    case Opcode::mips64_tgei: return "tgei";
    case Opcode::mips64_tgeiu: return "tgeiu";
    case Opcode::mips64_tlti: return "tlti";
    case Opcode::mips64_tltiu: return "tltiu";
    case Opcode::mips64_teqi: return "teqi";
    case Opcode::mips64_tnei: return "tnei";
    case Opcode::mips64_ll: return "ll";
    case Opcode::mips64_sc: return "sc";
    case Opcode::mips64_add: return "add";
    case Opcode::mips64_addu: return "addu";
    case Opcode::mips64_sub: return "sub";
    case Opcode::mips64_subu: return "subu";
    case Opcode::mips64_slt: return "slt";
    case Opcode::mips64_sltu: return "sltu";
    case Opcode::mips64_sll: return "sll";
    case Opcode::mips64_srl: return "srl";
    case Opcode::mips64_sra: return "sra";
    case Opcode::mips64_sllv: return "sllv";
    case Opcode::mips64_srlv: return "srlv";
    case Opcode::mips64_srav: return "srav";
    case Opcode::mips64_addi: return "addi";
    case Opcode::mips64_addiu: return "addiu";
    case Opcode::mips64_slti: return "slti";
    case Opcode::mips64_sltiu: return "sltiu";
    case Opcode::mips64_mult: return "mult";
    case Opcode::mips_beql: return "beql";
    case Opcode::mips_bnel: return "bnel";
    case Opcode::mips_blezl: return "blezl";
    case Opcode::mips_bgtzl: return "bgtzl";
    case Opcode::mips_bltzl: return "bltzl";
    case Opcode::mips_bgezl: return "bgezl";
    case Opcode::mips_bltzal: return "bltzal";
    case Opcode::mips_bgezal: return "bgezal";
    case Opcode::mips_bltzall: return "bltzall";
    case Opcode::mips_bgezall: return "bgezall";
    case Opcode::mips64_multu: return "multu";
    case Opcode::mips64_div: return "div";
    case Opcode::mips64_divu: return "divu";
    case Opcode::mips_ldc1: return "ldc1"; case Opcode::mips_sdc1: return "sdc1";
    case Opcode::mips_add_d: return "add.d"; case Opcode::mips_sub_d: return "sub.d";
    case Opcode::mips_mul_d: return "mul.d"; case Opcode::mips_div_d: return "div.d";
    case Opcode::mips_sqrt_d: return "sqrt.d"; case Opcode::mips_abs_d: return "abs.d";
    case Opcode::mips_mov_d: return "mov.d"; case Opcode::mips_neg_d: return "neg.d";
    case Opcode::mips_c_eq_d: return "c.eq.d"; case Opcode::mips_c_lt_d: return "c.lt.d"; case Opcode::mips_c_le_d: return "c.le.d";
    case Opcode::mips_cvt_s_d: return "cvt.s.d"; case Opcode::mips_cvt_d_s: return "cvt.d.s";
    case Opcode::mips_cvt_w_s: return "cvt.w.s"; case Opcode::mips_cvt_w_d: return "cvt.w.d";
    case Opcode::mips_cvt_s_w: return "cvt.s.w"; case Opcode::mips_cvt_d_w: return "cvt.d.w";
    case Opcode::mips_round_w_s: return "round.w.s"; case Opcode::mips_trunc_w_s: return "trunc.w.s";
    case Opcode::mips_ceil_w_s: return "ceil.w.s"; case Opcode::mips_floor_w_s: return "floor.w.s";
    case Opcode::mips_round_w_d: return "round.w.d"; case Opcode::mips_trunc_w_d: return "trunc.w.d";
    case Opcode::mips_ceil_w_d: return "ceil.w.d"; case Opcode::mips_floor_w_d: return "floor.w.d";
    default: break;
    }
    if (op >= Opcode::mips64_dadd && op <= Opcode::mips64_scd) {
        static constexpr const char *names[]{"dadd", "daddu", "dsub", "dsubu", "daddiu", "dsll", "dsrl", "dsra",
            "dsllv", "dsrlv", "dsrav", "dsll32", "dsrl32", "dsra32", "ld", "sd", "lwu", "lld", "scd"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::mips64_dadd)];
    }
    switch (op) {
    case Opcode::mips64_dmult: return "dmult";
    case Opcode::mips64_dmultu: return "dmultu";
    case Opcode::mips64_ddiv: return "ddiv";
    case Opcode::mips64_ddivu: return "ddivu";
    case Opcode::mips64_mfhi: return "mfhi";
    case Opcode::mips64_mflo: return "mflo";
    case Opcode::mips64_mthi: return "mthi";
    case Opcode::mips64_mtlo: return "mtlo";
    case Opcode::mips64_daddi: return "daddi";
    case Opcode::mips64_dmfc0: return "dmfc0";
    case Opcode::mips64_dmtc0: return "dmtc0";
    case Opcode::mips64_mfc1: return "mfc1";
    case Opcode::mips64_dmfc1: return "dmfc1";
    case Opcode::mips64_cfc1: return "cfc1";
    case Opcode::mips64_mtc1: return "mtc1";
    case Opcode::mips64_dmtc1: return "dmtc1";
    case Opcode::mips64_ctc1: return "ctc1";
    case Opcode::mips_mfc1: return "mfc1";
    case Opcode::mips_cfc1: return "cfc1";
    case Opcode::mips_mtc1: return "mtc1";
    case Opcode::mips_ctc1: return "ctc1";
    case Opcode::mips64_cvt_l_s: return "cvt.l.s";
    case Opcode::mips64_cvt_l_d: return "cvt.l.d";
    case Opcode::mips64_cvt_s_l: return "cvt.s.l";
    case Opcode::mips64_cvt_d_l: return "cvt.d.l";
    case Opcode::mips64_round_l_s: return "round.l.s";
    case Opcode::mips64_trunc_l_s: return "trunc.l.s";
    case Opcode::mips64_ceil_l_s: return "ceil.l.s";
    case Opcode::mips64_floor_l_s: return "floor.l.s";
    case Opcode::mips64_round_l_d: return "round.l.d";
    case Opcode::mips64_trunc_l_d: return "trunc.l.d";
    case Opcode::mips64_ceil_l_d: return "ceil.l.d";
    case Opcode::mips64_floor_l_d: return "floor.l.d";
    case Opcode::mips64_lwl: return "lwl";
    case Opcode::mips64_lwr: return "lwr";
    case Opcode::mips64_swl: return "swl";
    case Opcode::mips64_swr: return "swr";
    case Opcode::mips64_ldl: return "ldl";
    case Opcode::mips64_ldr: return "ldr";
    case Opcode::mips64_sdl: return "sdl";
    case Opcode::mips64_sdr: return "sdr";
    case Opcode::mips64_pref: return "pref";
    default: break;
    }
    if (op >= Opcode::ppc_addi && op <= Opcode::ppc_nop) {
        static constexpr const char *names[]{"addi", "addis", "ori", "oris", "xori", "xoris", "andi.", "andis.",
            "add", "add.", "subf", "subf.", "or", "or.", "xor", "xor.", "and", "and.", "cmp", "cmpl",
            "lwz", "lwzu", "lbz", "lbzu", "lhz", "lhzu", "lha", "lhau", "stw", "stwu", "stb", "stbu",
            "sth", "sthu", "ld", "ldu", "std", "stdu", "b", "bc", "bclr", "bcctr", "mflr", "mtlr",
            "mfctr", "mtctr", "nop"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::ppc_addi)];
    }
    if (op >= Opcode::ppc_mulli && op <= Opcode::ppc_rlwnm_dot) {
        static constexpr const char *names[]{"mulli", "subfic", "cmpi", "cmpli", "rlwimi", "rlwimi.",
            "rlwinm", "rlwinm.", "rlwnm", "rlwnm."};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::ppc_mulli)];
    }
    if (op >= Opcode::ppc_addic && op <= Opcode::ppc_mtxer) {
        static constexpr const char *names[]{"addic", "addic.", "addc", "adde", "subfc", "subfe", "neg",
            "mullw", "mulld", "divw", "divwu", "divd", "divdu", "slw", "srw", "sraw", "srawi",
            "sld", "srd", "srad", "sradi", "lwzx", "lwzux", "lbzx", "lbzux", "lhzx", "lhzux",
            "lhax", "lhaux", "stwx", "stwux", "stbx", "stbux", "sthx", "sthux", "ldx", "ldux",
            "stdx", "stdux", "lwbrx", "lhbrx", "stwbrx", "sthbrx", "mfcr", "mtcrf", "sc", "mfxer", "mtxer"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::ppc_addic)];
    }
    if (op == Opcode::ppc_addze) return "addze";
    if (op == Opcode::ppc_addze_dot) return "addze";
    if (op == Opcode::ppc_addme) return "addme";
    if (op == Opcode::ppc_addme_dot) return "addme";
    if (op == Opcode::ppc_mulhw) return "mulhw";
    if (op == Opcode::ppc_mulhwu) return "mulhwu";
    if (op >= Opcode::ppc_andc && op <= Opcode::ppc_extsw_dot) {
        static constexpr const char *names[]{"andc", "andc.", "nand", "nand.", "nor", "nor.",
            "orc", "orc.", "eqv", "eqv.", "cntlzw", "cntlzw.", "cntlzd", "cntlzd.",
            "extsb", "extsb.", "extsh", "extsh.", "extsw", "extsw."};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::ppc_andc)];
    }
    if (op == Opcode::movmskps) return "movmskps";
    if (op == Opcode::movmskpd) return "movmskpd";
    if (op == Opcode::pmovmskb) return "pmovmskb";
    if (op == Opcode::vmovmskps) return "vmovmskps";
    if (op == Opcode::vmovmskpd) return "vmovmskpd";
    if (op == Opcode::vpmovmskb) return "vpmovmskb";
    if (op >= Opcode::kandb && op <= Opcode::knotq) {
        static constexpr const char *names[]{"kandb", "kandw", "kandd", "kandq",
            "kandnb", "kandnw", "kandnd", "kandnq", "korb", "korw", "kord", "korq",
            "kxorb", "kxorw", "kxord", "kxorq", "kxnorb", "kxnorw", "kxnord", "kxnorq",
            "knotb", "knotw", "knotd", "knotq"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::kandb)];
    }
    if (op >= Opcode::kmovb && op <= Opcode::kmovq) {
        static constexpr const char *names[]{"kmovb", "kmovw", "kmovd", "kmovq"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::kmovb)];
    }
    if (op >= Opcode::movdqa && op <= Opcode::divsd) {
        static constexpr const char *names[]{"movdqa", "movdqu", "paddd", "paddq", "psubd", "psubq", "pand", "por",
            "pxor", "movss", "movsd", "addss", "addsd", "subss", "subsd", "mulss", "mulsd", "divss", "divsd"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::movdqa)];
    }
    if (op >= Opcode::vaddps && op <= Opcode::vmovups) {
        static constexpr const char *names[]{"vaddps", "vaddpd", "vsubps", "vsubpd", "vmulps", "vmulpd",
            "vxorps", "vxorpd", "vandps", "vandpd", "vmovups"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::vaddps)];
    }
    switch (op) {
    case Opcode::ppc_lwa: return "lwa";
    case Opcode::ppc_lwax: return "lwax";
    case Opcode::ppc_lwaux: return "lwaux";
    case Opcode::ppc_popcntw: return "popcntw";
    case Opcode::ppc_popcntd: return "popcntd";
    case Opcode::ppc_popcntb: return "popcntb";
    case Opcode::ppc_isel: return "isel";
    case Opcode::ppc_addo: return "addo";
    case Opcode::ppc_addo_dot: return "addo.";
    case Opcode::ppc_subfo: return "subfo";
    case Opcode::ppc_subfo_dot: return "subfo.";
    case Opcode::ppc_mcrf: return "mcrf";
    case Opcode::ppc_mcrxr: return "mcrxr";
    case Opcode::ppc_crand: return "crand";
    case Opcode::ppc_crandc: return "crandc";
    case Opcode::ppc_creqv: return "creqv";
    case Opcode::ppc_crnand: return "crnand";
    case Opcode::ppc_crnor: return "crnor";
    case Opcode::ppc_cror: return "cror";
    case Opcode::ppc_crorc: return "crorc";
    case Opcode::ppc_crxor: return "crxor";
    case Opcode::ppc_ldbrx: return "ldbrx";
    case Opcode::ppc_stdbrx: return "stdbrx";
    case Opcode::ppc_rldicl: return "rldicl";
    case Opcode::ppc_rldicl_dot: return "rldicl.";
    case Opcode::ppc_rldicr: return "rldicr";
    case Opcode::ppc_rldicr_dot: return "rldicr.";
    case Opcode::ppc_rldic: return "rldic";
    case Opcode::ppc_rldic_dot: return "rldic.";
    case Opcode::ppc_rldimi: return "rldimi";
    case Opcode::ppc_rldimi_dot: return "rldimi.";
    case Opcode::ppc_rldcl: return "rldcl";
    case Opcode::ppc_rldcl_dot: return "rldcl.";
    case Opcode::ppc_rldcr: return "rldcr";
    case Opcode::ppc_rldcr_dot: return "rldcr.";
    case Opcode::ppc_lfs: return "lfs";
    case Opcode::ppc_lfd: return "lfd";
    case Opcode::ppc_stfs: return "stfs";
    case Opcode::ppc_stfd: return "stfd";
    case Opcode::ppc_fadds: return "fadds";
    case Opcode::ppc_fsubs: return "fsubs";
    case Opcode::ppc_fmuls: return "fmuls";
    case Opcode::ppc_fdivs: return "fdivs";
    case Opcode::ppc_fadd: return "fadd";
    case Opcode::ppc_fsub: return "fsub";
    case Opcode::ppc_fmul: return "fmul";
    case Opcode::ppc_fdiv: return "fdiv";
    case Opcode::ppc_fmadd: return "fmadd";
    case Opcode::ppc_fmsub: return "fmsub";
    case Opcode::ppc_fnmadd: return "fnmadd";
    case Opcode::ppc_fnmsub: return "fnmsub";
    case Opcode::ppc_fmadds: return "fmadds";
    case Opcode::ppc_fmsubs: return "fmsubs";
    case Opcode::ppc_fnmadds: return "fnmadds";
    case Opcode::ppc_fnmsubs: return "fnmsubs";
    case Opcode::ppc_fcmpu: return "fcmpu";
    case Opcode::ppc_fcmpo: return "fcmpo";
    case Opcode::ppc_tw: return "tw";
    case Opcode::ppc_td: return "td";
    case Opcode::ppc_fmr: return "fmr";
    case Opcode::ppc_fneg: return "fneg";
    case Opcode::ppc_fabs: return "fabs";
    case Opcode::ppc_frsp: return "frsp";
    case Opcode::ppc_fctiw: return "fctiw";
    case Opcode::ppc_fctiwz: return "fctiwz";
    case Opcode::ppc_fctid: return "fctid";
    case Opcode::ppc_fctidz: return "fctidz";
    case Opcode::ppc_fcfid: return "fcfid";
    case Opcode::ppc_fctiwu: return "fctiwu";
    case Opcode::ppc_fctiwuz: return "fctiwuz";
    case Opcode::ppc_fctidu: return "fctidu";
    case Opcode::ppc_fctiduz: return "fctiduz";
    case Opcode::ppc_fcfidu: return "fcfidu";
    case Opcode::ppc_fcfids: return "fcfids";
    case Opcode::ppc_mffs: return "mffs";
    case Opcode::ppc_mtfsb0: return "mtfsb0";
    case Opcode::ppc_mtfsb1: return "mtfsb1";
    case Opcode::ppc_mtfsfi: return "mtfsfi";
    case Opcode::ppc_mtfsf: return "mtfsf";
    case Opcode::ppc_mcrfs: return "mcrfs";
    case Opcode::ppc_vaddubm: return "vaddubm";
    case Opcode::ppc_vadduhm: return "vadduhm";
    case Opcode::ppc_vadduwm: return "vadduwm";
    case Opcode::ppc_vsububm: return "vsububm";
    case Opcode::ppc_vsubuhm: return "vsubuhm";
    case Opcode::ppc_vsubuwm: return "vsubuwm";
    case Opcode::ppc_vand: return "vand";
    case Opcode::ppc_vandc: return "vandc";
    case Opcode::ppc_vor: return "vor";
    case Opcode::ppc_vxor: return "vxor";
    case Opcode::ppc_vnor: return "vnor";
    case Opcode::vpaddb: return "vpaddb";
    case Opcode::vpsllvw: return "vpsllvw";
    case Opcode::vpsllvd: return "vpsllvd";
    case Opcode::vpsllvq: return "vpsllvq";
    case Opcode::vpsrlvw: return "vpsrlvw";
    case Opcode::vpsrlvd: return "vpsrlvd";
    case Opcode::vpsrlvq: return "vpsrlvq";
    case Opcode::vpsravw: return "vpsravw";
    case Opcode::vpsravd: return "vpsravd";
    case Opcode::vpsravq: return "vpsravq";
    case Opcode::vpsllw: return "vpsllw";
    case Opcode::vpslld: return "vpslld";
    case Opcode::vpsllq: return "vpsllq";
    case Opcode::vpsrlw: return "vpsrlw";
    case Opcode::vpsrld: return "vpsrld";
    case Opcode::vpsrlq: return "vpsrlq";
    case Opcode::vpsraw: return "vpsraw";
    case Opcode::vpsrad: return "vpsrad";
    case Opcode::vpslldq: return "vpslldq";
    case Opcode::vpsrldq: return "vpsrldq";
    case Opcode::vpaddw: return "vpaddw";
    case Opcode::vpaddsb: return "vpaddsb";
    case Opcode::vpaddsw: return "vpaddsw";
    case Opcode::vpaddusb: return "vpaddusb";
    case Opcode::vpaddusw: return "vpaddusw";
    case Opcode::vpaddd: return "vpaddd";
    case Opcode::vpaddq: return "vpaddq";
    case Opcode::vpand: return "vpand";
    case Opcode::vpor: return "vpor";
    case Opcode::vpxor: return "vpxor";
    case Opcode::vpandd: return "vpandd";
    case Opcode::vpandnd: return "vpandnd";
    case Opcode::vpandq: return "vpandq";
    case Opcode::vpandnq: return "vpandnq";
    case Opcode::vpord: return "vpord";
    case Opcode::vporq: return "vporq";
    case Opcode::vpxord: return "vpxord";
    case Opcode::vpxorq: return "vpxorq";
    case Opcode::vpsubb: return "vpsubb";
    case Opcode::vpsubw: return "vpsubw";
    case Opcode::vpsubsb: return "vpsubsb";
    case Opcode::vpsubsw: return "vpsubsw";
    case Opcode::vpsubusb: return "vpsubusb";
    case Opcode::vpsubusw: return "vpsubusw";
    case Opcode::vpsubd: return "vpsubd";
    case Opcode::vpsubq: return "vpsubq";
    case Opcode::vpmullw: return "vpmullw";
    case Opcode::vpmulhw: return "vpmulhw";
    case Opcode::vpmulhuw: return "vpmulhuw";
    case Opcode::vpminub: return "vpminub";
    case Opcode::vpminsw: return "vpminsw";
    case Opcode::vpmaxub: return "vpmaxub";
    case Opcode::vpmaxsw: return "vpmaxsw";
    case Opcode::vpandn: return "vpandn";
    case Opcode::vpavgb: return "vpavgb";
    case Opcode::vpavgw: return "vpavgw";
    case Opcode::vpminsb: return "vpminsb";
    case Opcode::vpminsd: return "vpminsd";
    case Opcode::vpminuw: return "vpminuw";
    case Opcode::vpminud: return "vpminud";
    case Opcode::vpmaxsb: return "vpmaxsb";
    case Opcode::vpmaxsd: return "vpmaxsd";
    case Opcode::vpmaxuw: return "vpmaxuw";
    case Opcode::vpmaxud: return "vpmaxud";
    case Opcode::vpmulld: return "vpmulld";
    case Opcode::vpmuldq: return "vpmuldq";
    case Opcode::vpmuludq: return "vpmuludq";
    case Opcode::vpmaddwd: return "vpmaddwd";
    case Opcode::vpmaddubsw: return "vpmaddubsw";
    case Opcode::vphaddw: return "vphaddw";
    case Opcode::vphaddd: return "vphaddd";
    case Opcode::vphaddsw: return "vphaddsw";
    case Opcode::vphsubw: return "vphsubw";
    case Opcode::vphsubd: return "vphsubd";
    case Opcode::vphsubsw: return "vphsubsw";
    case Opcode::vpsignb: return "vpsignb";
    case Opcode::vpsignw: return "vpsignw";
    case Opcode::vpsignd: return "vpsignd";
    case Opcode::vpabsb: return "vpabsb";
    case Opcode::vpabsw: return "vpabsw";
    case Opcode::vpabsd: return "vpabsd";
    case Opcode::vcmpps: return "vcmpps";
    case Opcode::vcmppd: return "vcmppd";
    case Opcode::cmpps: return "cmpps";
    case Opcode::cmppd: return "cmppd";
    case Opcode::cmpss: return "cmpss";
    case Opcode::cmpsd: return "cmpsd";
    case Opcode::vpunpcklbw: return "vpunpcklbw";
    case Opcode::vpunpcklwd: return "vpunpcklwd";
    case Opcode::vpunpckldq: return "vpunpckldq";
    case Opcode::vpunpcklqdq: return "vpunpcklqdq";
    case Opcode::vpunpckhbw: return "vpunpckhbw";
    case Opcode::vpunpckhwd: return "vpunpckhwd";
    case Opcode::vpunpckhdq: return "vpunpckhdq";
    case Opcode::vpunpckhqdq: return "vpunpckhqdq";
    case Opcode::vpacksswb: return "vpacksswb";
    case Opcode::vpackssdw: return "vpackssdw";
    case Opcode::vpackuswb: return "vpackuswb";
    case Opcode::vpackusdw: return "vpackusdw";
    case Opcode::vpshufb: return "vpshufb";
    case Opcode::vshufps: return "vshufps";
    case Opcode::vshufpd: return "vshufpd";
    case Opcode::vpshufd: return "vpshufd";
    case Opcode::vpsadbw: return "vpsadbw";
    case Opcode::vpermd: return "vpermd";
    case Opcode::vpermb: return "vpermb";
    case Opcode::vpternlogd: return "vpternlogd";
    case Opcode::vpternlogq: return "vpternlogq";
    case Opcode::vpmullq: return "vpmullq";
    case Opcode::vpminsq: return "vpminsq";
    case Opcode::vpminuq: return "vpminuq";
    case Opcode::vpmaxsq: return "vpmaxsq";
    case Opcode::vpmaxuq: return "vpmaxuq";
    case Opcode::vpmovm2b: return "vpmovm2b";
    case Opcode::vpmovm2w: return "vpmovm2w";
    case Opcode::vpmovm2d: return "vpmovm2d";
    case Opcode::vpmovm2q: return "vpmovm2q";
    case Opcode::vpmovb2m: return "vpmovb2m";
    case Opcode::vpmovw2m: return "vpmovw2m";
    case Opcode::vpmovd2m: return "vpmovd2m";
    case Opcode::vpmovq2m: return "vpmovq2m";
    case Opcode::vpopcntb: return "vpopcntb";
    case Opcode::vpopcntw: return "vpopcntw";
    case Opcode::vpopcntd: return "vpopcntd";
    case Opcode::vpopcntq: return "vpopcntq";
    case Opcode::vpcmpeqb: return "vpcmpeqb";
    case Opcode::vpcmpeqw: return "vpcmpeqw";
    case Opcode::vpcmpeqd: return "vpcmpeqd";
    case Opcode::vpcmpeqq: return "vpcmpeqq";
    case Opcode::vpcmpgtb: return "vpcmpgtb";
    case Opcode::vpcmpgtw: return "vpcmpgtw";
    case Opcode::vpcmpgtd: return "vpcmpgtd";
    case Opcode::vpcmpgtq: return "vpcmpgtq";
    case Opcode::vpcmpb: return "vpcmpb";
    case Opcode::vpcmpw: return "vpcmpw";
    case Opcode::vpcmpd: return "vpcmpd";
    case Opcode::vpcmpq: return "vpcmpq";
    case Opcode::vpcmpub: return "vpcmpub";
    case Opcode::vpcmpuw: return "vpcmpuw";
    case Opcode::vpcmpud: return "vpcmpud";
    case Opcode::vpcmpuq: return "vpcmpuq";
    case Opcode::vdivps: return "vdivps";
    case Opcode::vdivpd: return "vdivpd";
    default: break;
    }
    if (op >= Opcode::pcmpeqb && op <= Opcode::pcmpgtd) {
        static constexpr const char *names[]{"pcmpeqb", "pcmpeqw", "pcmpeqd", "pcmpgtb", "pcmpgtw", "pcmpgtd"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::pcmpeqb)];
    }
    if (op == Opcode::pcmpgtq) return "pcmpgtq";
    switch (op) {
    case Opcode::paddb: return "paddb"; case Opcode::paddw: return "paddw";
    case Opcode::psubb: return "psubb"; case Opcode::psubw: return "psubw";
    case Opcode::paddsb: return "paddsb"; case Opcode::paddsw: return "paddsw";
    case Opcode::paddusb: return "paddusb"; case Opcode::paddusw: return "paddusw";
    case Opcode::psubsb: return "psubsb"; case Opcode::psubsw: return "psubsw";
    case Opcode::psubusb: return "psubusb"; case Opcode::psubusw: return "psubusw";
    case Opcode::pandn: return "pandn";
    case Opcode::psllw: return "psllw"; case Opcode::pslld: return "pslld"; case Opcode::psllq: return "psllq";
    case Opcode::psrlw: return "psrlw"; case Opcode::psrld: return "psrld"; case Opcode::psrlq: return "psrlq";
    case Opcode::pslldq: return "pslldq"; case Opcode::psrldq: return "psrldq";
    case Opcode::psraw: return "psraw"; case Opcode::psrad: return "psrad";
    case Opcode::pmullw: return "pmullw"; case Opcode::pmulhw: return "pmulhw";
    case Opcode::pmulhuw: return "pmulhuw"; case Opcode::pmuludq: return "pmuludq";
    case Opcode::pmaddwd: return "pmaddwd"; case Opcode::psadbw: return "psadbw";
    case Opcode::pminub: return "pminub"; case Opcode::pmaxub: return "pmaxub";
    case Opcode::pminsw: return "pminsw"; case Opcode::pmaxsw: return "pmaxsw";
    case Opcode::pavgb: return "pavgb"; case Opcode::pavgw: return "pavgw";
    case Opcode::phaddw: return "phaddw"; case Opcode::phaddd: return "phaddd";
    case Opcode::phaddsw: return "phaddsw"; case Opcode::phsubw: return "phsubw";
    case Opcode::phsubd: return "phsubd"; case Opcode::phsubsw: return "phsubsw";
    case Opcode::pshufd: return "pshufd";
    case Opcode::pshufb: return "pshufb";
    case Opcode::pmaddubsw: return "pmaddubsw"; case Opcode::pmulhrsw: return "pmulhrsw";
    case Opcode::psignb: return "psignb"; case Opcode::psignw: return "psignw";
    case Opcode::psignd: return "psignd";
    case Opcode::pabsb: return "pabsb"; case Opcode::pabsw: return "pabsw";
    case Opcode::pabsd: return "pabsd";
    case Opcode::ptest: return "ptest";
    case Opcode::vptest: return "vptest";
    default: break;
    }
    if (op >= Opcode::rv_lui && op <= Opcode::rv_remuw) {
        static constexpr const char *riscv_names[]{
            "lui", "auipc", "jal", "jalr", "beq", "bne", "blt", "bge", "bltu", "bgeu",
            "lb", "lh", "lw", "ld", "lbu", "lhu", "lwu", "sb", "sh", "sw", "sd",
            "addi", "slti", "sltiu", "xori", "ori", "andi", "slli", "srli", "srai",
            "add", "sub", "sll", "slt", "sltu", "xor", "srl", "sra", "or", "and",
            "fence", "ecall", "ebreak", "addiw", "slliw", "srliw", "sraiw", "addw", "subw",
            "sllw", "srlw", "sraw", "mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem",
            "remu", "mulw", "divw", "divuw", "remw", "remuw"};
        return riscv_names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_lui)];
    }
    if (op >= Opcode::rv_lr_w && op <= Opcode::rv_amomaxu_d) {
        static constexpr const char *atomic_names[]{
            "lr.w", "sc.w", "amoswap.w", "amoadd.w", "amoxor.w", "amoand.w", "amoor.w", "amomin.w",
            "amomax.w", "amominu.w", "amomaxu.w", "lr.d", "sc.d", "amoswap.d", "amoadd.d", "amoxor.d",
            "amoand.d", "amoor.d", "amomin.d", "amomax.d", "amominu.d", "amomaxu.d"};
        return atomic_names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_lr_w)];
    }
    if (op >= Opcode::rv_csrrw && op <= Opcode::rv_csrrci) {
        static constexpr const char *csr_names[]{"csrrw", "csrrs", "csrrc", "csrrwi", "csrrsi", "csrrci"};
        return csr_names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_csrrw)];
    }
    if (op == Opcode::rv_fcvtmod_w_d) return "fcvtmod.w.d";
    if (op == Opcode::rv_andn) return "andn";
    if (op == Opcode::rv_orn) return "orn";
    if (op == Opcode::rv_xnor) return "xnor";
    if (op == Opcode::rv_min) return "min";
    if (op == Opcode::rv_minu) return "minu";
    if (op == Opcode::rv_max) return "max";
    if (op == Opcode::rv_maxu) return "maxu";
    if (op == Opcode::rv_rol) return "rol";
    if (op == Opcode::rv_ror) return "ror";
    if (op == Opcode::rv_rori) return "rori";
    if (op == Opcode::rv_sext_b) return "sext.b";
    if (op == Opcode::rv_sext_h) return "sext.h";
    if (op == Opcode::rv_zext_h) return "zext.h";
    if (op == Opcode::rv_orc_b) return "orc.b";
    if (op == Opcode::rv_rev8) return "rev8";
    if (op == Opcode::rv_rolw) return "rolw";
    if (op == Opcode::rv_rorw) return "rorw";
    if (op == Opcode::rv_roriw) return "roriw";
    if (op == Opcode::rv_fence_i) return "fence.i";
    if (op == Opcode::rv_fence_tso) return "fence.tso";
    if (op == Opcode::rv_fli_s) return "fli.s";
    if (op == Opcode::rv_fli_d) return "fli.d";
    if (op == Opcode::rv_fround_s) return "fround.s";
    if (op == Opcode::rv_froundnx_s) return "froundnx.s";
    if (op == Opcode::rv_fround_d) return "fround.d";
    if (op == Opcode::rv_froundnx_d) return "froundnx.d";
    if (op == Opcode::rv_fminm_s) return "fminm.s";
    if (op == Opcode::rv_fmaxm_s) return "fmaxm.s";
    if (op == Opcode::rv_fminm_d) return "fminm.d";
    if (op == Opcode::rv_fmaxm_d) return "fmaxm.d";
    if (op == Opcode::rv_fleq_s) return "fleq.s";
    if (op == Opcode::rv_fltq_s) return "fltq.s";
    if (op == Opcode::rv_fleq_d) return "fleq.d";
    if (op == Opcode::rv_fltq_d) return "fltq.d";
    if (op >= Opcode::rv_flw && op <= Opcode::rv_fmv_d_x) {
        static constexpr const char *fp_names[]{
            "flw","fld","fsw","fsd","fadd.s","fsub.s","fmul.s","fdiv.s","fsqrt.s","fsgnj.s","fsgnjn.s","fsgnjx.s","fmin.s","fmax.s","fmadd.s","fmsub.s","fnmsub.s","fnmadd.s","feq.s","flt.s","fle.s","fclass.s","fcvt.w.s","fcvt.wu.s","fcvt.l.s","fcvt.lu.s","fcvt.s.w","fcvt.s.wu","fcvt.s.l","fcvt.s.lu","fmv.x.w","fmv.w.x",
            "fadd.d","fsub.d","fmul.d","fdiv.d","fsqrt.d","fsgnj.d","fsgnjn.d","fsgnjx.d","fmin.d","fmax.d","fmadd.d","fmsub.d","fnmsub.d","fnmadd.d","feq.d","flt.d","fle.d","fclass.d","fcvt.w.d","fcvt.wu.d","fcvt.l.d","fcvt.lu.d","fcvt.d.w","fcvt.d.wu","fcvt.d.l","fcvt.d.lu","fcvt.s.d","fcvt.d.s","fmv.x.d","fmv.d.x"};
        return fp_names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_flw)];
    }
    if (op >= Opcode::rv_vsetvli && op <= Opcode::rv_vsetvl) {
        static constexpr const char *names[]{"vsetvli", "vsetivli", "vsetvl"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_vsetvli)];
    }
    if (op >= Opcode::rv_vredsum && op <= Opcode::rv_vredmax) {
        static constexpr const char *names[]{"vredsum.vs", "vredand.vs", "vredor.vs", "vredxor.vs",
            "vredminu.vs", "vredmin.vs", "vredmaxu.vs", "vredmax.vs"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_vredsum)];
    }
    if (op >= Opcode::rv_vcpop_m && op <= Opcode::rv_vid_v) {
        static constexpr const char *names[]{"vcpop.m", "vfirst.m", "vmsbf.m", "vmsof.m",
            "vmsif.m", "viota.m", "vid.v"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_vcpop_m)];
    }
    if (op >= Opcode::rv_vmand_mm && op <= Opcode::rv_vmxnor_mm) {
        static constexpr const char *names[]{"vmand.mm", "vmnand.mm", "vmandn.mm", "vmxor.mm",
            "vmor.mm", "vmnor.mm", "vmorn.mm", "vmxnor.mm"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_vmand_mm)];
    }
    if (op == Opcode::rv_vfredusum) return "vfredusum.vs";
    if (op == Opcode::rv_vfredosum) return "vfredosum.vs";
    if (op == Opcode::rv_vfredmin) return "vfredmin.vs";
    if (op == Opcode::rv_vfredmax) return "vfredmax.vs";
    if (op == Opcode::rv_vfwredusum) return "vfwredusum.vs";
    if (op == Opcode::rv_vfwredosum) return "vfwredosum.vs";
    if (op >= Opcode::rv_vadd_vv && op <= Opcode::rv_vxor_vi) {
        static constexpr const char *names[]{"vadd.vv","vadd.vx","vadd.vi","vsub.vv","vsub.vx",
            "vand.vv","vand.vx","vand.vi","vor.vv","vor.vx","vor.vi","vxor.vv","vxor.vx","vxor.vi"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_vadd_vv)];
    }
    if (op >= Opcode::rv_vmseq_vv && op <= Opcode::rv_vmsgt_vi) {
        static constexpr const char *names[]{
            "vmseq.vv", "vmseq.vx", "vmseq.vi", "vmsne.vv", "vmsne.vx", "vmsne.vi",
            "vmsltu.vv", "vmsltu.vx", "vmslt.vv", "vmslt.vx",
            "vmsleu.vv", "vmsleu.vx", "vmsleu.vi", "vmsle.vv", "vmsle.vx", "vmsle.vi",
            "vmsgtu.vx", "vmsgtu.vi", "vmsgt.vx", "vmsgt.vi"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_vmseq_vv)];
    }
    if (op >= Opcode::rv_vsll_vv && op <= Opcode::rv_vmax_vx) {
        static constexpr const char *names[]{"vsll.vv","vsll.vx","vsll.vi","vsrl.vv","vsrl.vx","vsrl.vi",
            "vsra.vv","vsra.vx","vsra.vi","vminu.vv","vminu.vx","vmin.vv","vmin.vx",
            "vmaxu.vv","vmaxu.vx","vmax.vv","vmax.vx"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_vsll_vv)];
    }
    if (op == Opcode::rv_vrsub_vx) return "vrsub.vx";
    if (op == Opcode::rv_vrsub_vi) return "vrsub.vi";
    if (op >= Opcode::rv_vmul_vv && op <= Opcode::rv_vmulhsu_vx) {
        static constexpr const char *names[]{"vmul.vv", "vmul.vx", "vmulh.vv", "vmulh.vx",
                                             "vmulhu.vv", "vmulhu.vx", "vmulhsu.vv", "vmulhsu.vx"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_vmul_vv)];
    }
    if (op >= Opcode::rv_vmacc_vv && op <= Opcode::rv_vnmsub_vx) {
        static constexpr const char *names[]{"vmacc.vv", "vmacc.vx", "vnmsac.vv", "vnmsac.vx",
                                             "vmadd.vv", "vmadd.vx", "vnmsub.vv", "vnmsub.vx"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_vmacc_vv)];
    }
    if (op >= Opcode::rv_vwmaccu_vv && op <= Opcode::rv_vwmaccus_vx) {
        static constexpr const char *names[]{"vwmaccu.vv", "vwmaccu.vx", "vwmacc.vv", "vwmacc.vx",
                                             "vwmaccsu.vv", "vwmaccsu.vx", "vwmaccus.vx"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_vwmaccu_vv)];
    }
    if (op >= Opcode::rv_vwadd_vv && op <= Opcode::rv_vwsubu_wx) {
        static constexpr const char *names[]{"vwadd.vv","vwadd.vx","vwadd.wv","vwadd.wx",
            "vwaddu.vv","vwaddu.vx","vwaddu.wv","vwaddu.wx","vwsub.vv","vwsub.vx","vwsub.wv","vwsub.wx",
            "vwsubu.vv","vwsubu.vx","vwsubu.wv","vwsubu.wx"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_vwadd_vv)];
    }
    if (op >= Opcode::rv_vwmulu_vv && op <= Opcode::rv_vwmul_vx) {
        static constexpr const char *names[]{"vwmulu.vv", "vwmulu.vx", "vwmulsu.vv", "vwmulsu.vx",
                                             "vwmul.vv", "vwmul.vx"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_vwmulu_vv)];
    }
    if (op >= Opcode::rv_vfadd_vv && op <= Opcode::rv_vfnmsub_vf) {
        static constexpr const char *names[]{"vfadd.vv","vfadd.vf","vfsub.vv","vfsub.vf","vfmul.vv","vfmul.vf",
            "vfdiv.vv","vfdiv.vf","vfsgnj.vv","vfsgnj.vf","vfsgnjn.vv","vfsgnjn.vf",
            "vfsgnjx.vv","vfsgnjx.vf","vfmin.vv","vfmin.vf","vfmax.vv","vfmax.vf",
            "vmfeq.vv","vmfeq.vf","vmfne.vv","vmfne.vf","vmflt.vv","vmflt.vf",
            "vmfle.vv","vmfle.vf","vmfgt.vf","vmfge.vf",
            "vfmacc.vv","vfmacc.vf","vfnmacc.vv","vfnmacc.vf","vfmsac.vv","vfmsac.vf",
            "vfnmsac.vv","vfnmsac.vf","vfmadd.vv","vfmadd.vf","vfnmadd.vv","vfnmadd.vf",
            "vfmsub.vv","vfmsub.vf","vfnmsub.vv","vfnmsub.vf"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_vfadd_vv)];
    }
    if (op == Opcode::rv_vfsqrt_v) return "vfsqrt.v";
    if (op == Opcode::rv_vfclass_v) return "vfclass.v";
    if (op == Opcode::rv_vfrsqrt7_v) return "vfrsqrt7.v";
    if (op == Opcode::rv_vfrec7_v) return "vfrec7.v";
    if (op >= Opcode::rv_sh1add && op <= Opcode::rv_slli_uw) {
        static constexpr const char *names[]{"sh1add", "sh2add", "sh3add", "add.uw",
            "sh1add.uw", "sh2add.uw", "sh3add.uw", "slli.uw"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_sh1add)];
    }
    if (op >= Opcode::rv_bclr && op <= Opcode::rv_bseti) {
        static constexpr const char *names[]{"bclr", "bext", "binv", "bset",
            "bclri", "bexti", "binvi", "bseti"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_bclr)];
    }
    if (op >= Opcode::rv_clmul && op <= Opcode::rv_clmulr) {
        static constexpr const char *names[]{"clmul", "clmulh", "clmulr"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_clmul)];
    }
    if (op == Opcode::rv_czero_eqz) return "czero.eqz";
    if (op == Opcode::rv_czero_nez) return "czero.nez";
    if (op >= Opcode::rv_pack && op <= Opcode::rv_packw) {
        static constexpr const char *names[]{"pack", "packh", "packw"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_pack)];
    }
    if (op >= Opcode::rv_vdivu_vv && op <= Opcode::rv_vrem_vx) {
        static constexpr const char *names[]{"vdivu.vv", "vdivu.vx", "vdiv.vv", "vdiv.vx",
                                             "vremu.vv", "vremu.vx", "vrem.vv", "vrem.vx"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_vdivu_vv)];
    }
    if (op == Opcode::rv_vle) return "vle";
    if (op == Opcode::rv_vse) return "vse";
    if (op == Opcode::rv_vlse) return "vlse";
    if (op == Opcode::rv_vsse) return "vsse";
    if (op == Opcode::rv_vluxei) return "vluxei";
    if (op == Opcode::rv_vloxei) return "vloxei";
    if (op == Opcode::rv_vsuxei) return "vsuxei";
    if (op == Opcode::rv_vsoxei) return "vsoxei";
    if (op >= Opcode::rv_clz && op <= Opcode::rv_cpopw) {
        static constexpr const char *names[]{"clz", "ctz", "cpop", "clzw", "ctzw", "cpopw"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_clz)];
    }
    if (op >= Opcode::rv_vrgather_vv && op <= Opcode::rv_vslidedown_vi) {
        static constexpr const char *names[]{"vrgather.vv", "vrgather.vx", "vrgather.vi",
            "vslideup.vx", "vslideup.vi", "vslidedown.vx", "vslidedown.vi"};
        return names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::rv_vrgather_vv)];
    }
    if (op == Opcode::mul)
        return "mul";
    if (op == Opcode::div)
        return "div";
    if (op == Opcode::idiv)
        return "idiv";
    if (op == Opcode::lahf)
        return "lahf";
    if (op == Opcode::adcx) return "adcx";
    if (op == Opcode::adox) return "adox";
    if (op == Opcode::bsf) return "bsf";
    if (op == Opcode::bsr) return "bsr";
    if (op == Opcode::bt) return "bt";
    if (op == Opcode::bts) return "bts";
    if (op == Opcode::btr) return "btr";
    if (op == Opcode::btc) return "btc";
    if (op == Opcode::tzcnt) return "tzcnt";
    if (op == Opcode::lzcnt) return "lzcnt";
    if (op == Opcode::shld) return "shld";
    if (op == Opcode::shrd) return "shrd";
    if (op == Opcode::xadd) return "xadd";
    if (op == Opcode::cmpxchg) return "cmpxchg";
    if (op == Opcode::xchg) return "xchg";
    if (op == Opcode::bswap) return "bswap";
    if (op == Opcode::popcnt) return "popcnt";
    if (op == Opcode::bzhi) return "bzhi";
    if (op == Opcode::andn) return "andn";
    if (op == Opcode::bextr) return "bextr";
    if (op == Opcode::blsi) return "blsi";
    if (op == Opcode::blsmsk) return "blsmsk";
    if (op == Opcode::blsr) return "blsr";
    if (op == Opcode::mulx) return "mulx";
    if (op == Opcode::pdep) return "pdep";
    if (op == Opcode::pext) return "pext";
    if (op == Opcode::rorx) return "rorx";
    if (op == Opcode::sarx) return "sarx";
    if (op == Opcode::shlx) return "shlx";
    if (op == Opcode::shrx) return "shrx";
    if (op == Opcode::cmpxchg8b) return "cmpxchg8b";
    if (op == Opcode::cmpxchg16b) return "cmpxchg16b";
    if (op == Opcode::cbw) return "cbw";
    if (op == Opcode::aam) return "aam";
    if (op == Opcode::aad) return "aad";
    if (op == Opcode::daa) return "daa";
    if (op == Opcode::das) return "das";
    if (op == Opcode::cwde) return "cwde";
    if (op == Opcode::cdqe) return "cdqe";
    if (op == Opcode::cwd) return "cwd";
    if (op == Opcode::cdq) return "cdq";
    if (op == Opcode::cqo) return "cqo";
    if (op == Opcode::x86_movs) return "movs";
    if (op == Opcode::x86_cmps) return "cmps";
    if (op == Opcode::x86_stos) return "stos";
    if (op == Opcode::x86_lods) return "lods";
    if (op == Opcode::x86_scas) return "scas";
    if (op == Opcode::x86_ins) return "ins";
    if (op == Opcode::x86_outs) return "outs";
    if (op == Opcode::pushf) return "pushf";
    if (op == Opcode::popf) return "popf";
    if (op == Opcode::pusha) return "pusha";
    if (op == Opcode::popa) return "popa";
    if (op == Opcode::enter) return "enter";
    if ((op >= Opcode::a32_b && op <= Opcode::t32_mul) ||
        (op >= Opcode::a32_sxtb && op <= Opcode::a32_uxtah) ||
        (op >= Opcode::t32_sxtb16 && op <= Opcode::t32_uxtab16) ||
        (op >= Opcode::a32_sxtb16 && op <= Opcode::a32_uxtab16) ||
        op == Opcode::t32_addw || op == Opcode::t32_subw ||
        op == Opcode::arm_tbb || op == Opcode::arm_tbh)
        return arm32_detail::mnemonic(op, condition);
    if ((op >= Opcode::a64_b && op <= Opcode::a64_strh) || op == Opcode::a64_sbfm || op == Opcode::a64_ubfm || op == Opcode::a64_bfm ||
        op == Opcode::a64_ccmp || op == Opcode::a64_ccmn)
        return a64_detail::mnemonic(op, condition);
    static constexpr const char *names[]{"mov",  "movzx", "movsx", "movsxd", "arpl", "bound", "les", "lds", "lea",   "push",    "pop", "leave",
                                         "add",  "or",    "adc",   "sbb",     "and",   "sub",     "xor", "cmp",
                                         "test", "inc",   "dec",   "not",     "neg",   "imul",    "rol", "ror",
                                         "rcl",  "rcr",   "shl",   "shr",     "sar",   "call",    "jmp", "jcc",
                                         "ret",  "int3",  "nop",   "endbr64", "pause", "endbr32", "retf"};
    static constexpr const char *conditions[]{"jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                                              "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"};
    static constexpr const char *condition_suffixes[]{"o", "no", "b", "ae", "e", "ne", "be", "a",
                                                       "s", "ns", "p", "np", "l", "ge", "le", "g"};
    if (op == Opcode::jcc)
        return conditions[condition & 15];
    if (op == Opcode::x86_loop) return "loop";
    if (op == Opcode::cmovcc)
        return std::string("cmov") + condition_suffixes[condition & 15];
    if (op == Opcode::setcc)
        return std::string("set") + condition_suffixes[condition & 15];
    static constexpr const char *m6502_names[]{"lda", "ldx", "ldy", "sta", "stx", "sty", "adc", "sbc",
        "and", "ora", "eor", "cmp", "cpx", "cpy", "bit", "inc", "dec", "inx", "dex", "iny", "dey",
        "tax", "tay", "txa", "tya", "tsx", "txs", "pha", "php", "pla", "plp", "jmp", "jsr", "rts",
        "rti", "brk", "bpl", "bmi", "bvc", "bvs", "bcc", "bcs", "bne", "beq", "clc", "sec", "cli",
        "sei", "clv", "cld", "sed", "asl", "lsr", "rol", "ror"};
    if (op >= Opcode::m6502_lda && op <= Opcode::m6502_ror)
        return m6502_names[static_cast<std::size_t>(op) - static_cast<std::size_t>(Opcode::m6502_lda)];
    if (op == Opcode::m6502_dcp) return "dcp";
    if (op == Opcode::m6502_slo) return "slo";
    if (op == Opcode::m6502_rla) return "rla";
    if (op == Opcode::m6502_sre) return "sre";
    if (op == Opcode::m6502_rra) return "rra";
    if (op == Opcode::m6502_isc) return "isc";
    if (op == Opcode::m6502_las) return "las";
    if (op == Opcode::m6502_anc) return "anc";
    if (op == Opcode::m6502_alr) return "alr";
    if (op == Opcode::m6502_lax) return "lax";
    if (op == Opcode::m6502_sax) return "sax";
    if (op == Opcode::m6502_kil) return "kil";
    if (op == Opcode::m65c02_bra) return "bra";
    if (op == Opcode::m65c02_stz) return "stz";
    if (op == Opcode::m65c02_phx) return "phx";
    if (op == Opcode::m65c02_plx) return "plx";
    if (op == Opcode::m65c02_phy) return "phy";
    if (op == Opcode::m65c02_ply) return "ply";
    if (op == Opcode::m65c02_tsb) return "tsb";
    if (op == Opcode::m65c02_trb) return "trb";
    if (op == Opcode::m65c02_rmb) return std::string("rmb") + std::to_string(condition & 7);
    if (op == Opcode::m65c02_smb) return std::string("smb") + std::to_string(condition & 7);
    if (op == Opcode::m65c02_bbr) return std::string("bbr") + std::to_string(condition & 7);
    if (op == Opcode::m65c02_bbs) return std::string("bbs") + std::to_string(condition & 7);
    if (op == Opcode::m65c02_wai) return "wai";
    if (op == Opcode::m65c02_stp) return "stp";
    if (op == Opcode::palignr) return "palignr";
    if (op == Opcode::vpalignr) return "vpalignr";
    const auto index = static_cast<std::size_t>(op);
    return index < std::size(names) ? names[index] : "?opcode";
}
std::string format_instruction(const Instruction &i) {
    if (i.opcode == Opcode::wasm) {
        std::string out = i.mnemonic_override;
        if (i.bytes[0] == std::byte{0xfd} && i.mnemonic_override == "v128.const") {
            const auto encoded = i.encoded_bytes();
            if (encoded.size() < 18) return out + " <missing immediate bytes>";
            static constexpr char hex_digits[] = "0123456789abcdef";
            out += " 0x";
            for (std::size_t index = 2; index < 18; ++index) {
                const auto byte = std::to_integer<std::uint8_t>(encoded[index]);
                out.push_back(hex_digits[byte >> 4]);
                out.push_back(hex_digits[byte & 0x0f]);
            }
            return out;
        }
        if (i.bytes[0] == std::byte{0xfd} &&
            (out.find("extract_lane") != std::string::npos || out.find("replace_lane") != std::string::npos)) {
            for (const auto &operand : i.operands) {
                if (const auto *immediate = std::get_if<ImmediateOperand>(&operand)) {
                    out += " " + std::to_string(immediate->value);
                    break;
                }
            }
        }
        return out;
    }
    if (i.opcode == Opcode::dex || i.opcode == Opcode::x86_opaque || i.opcode == Opcode::opaque)
        return i.mnemonic_override;
    if (i.context.architecture == Architecture::mos6502) {
        std::string out = opcode_name(i.opcode, i.condition);
        if (i.operands.empty()) return out;
        out += " ";
        if ((i.opcode == Opcode::m65c02_bbr || i.opcode == Opcode::m65c02_bbs) && i.operands.size() == 2) {
            if (const auto *mem = std::get_if<MemoryOperand>(&i.operands[0]))
                out += hex(static_cast<std::uint64_t>(mem->displacement));
            if (const auto *rel = std::get_if<RelativeOperand>(&i.operands[1]))
                out += ", " + (i.direct_target ? hex(i.direct_target->offset) : signed_hex(rel->displacement));
            return out;
        }
        if (const auto *imm = std::get_if<ImmediateOperand>(&i.operands[0]))
            out += "#" + hex(imm->value);
        else if (const auto *rel = std::get_if<RelativeOperand>(&i.operands[0]))
            out += i.direct_target ? hex(i.direct_target->offset) : signed_hex(rel->displacement);
        else if (const auto *mem = std::get_if<MemoryOperand>(&i.operands[0])) {
            const auto encoded = i.bytes[0];
            const auto address = hex(static_cast<std::uint64_t>(mem->displacement));
            if (encoded == std::byte{0x6c}) out += "(" + address + ")";
            else if (i.context.mode == ExecutionMode::m65c02 && encoded == std::byte{0x7c}) out += "(" + address + ", x)";
            else if (i.context.mode == ExecutionMode::m65c02 && (std::to_integer<unsigned>(encoded) & 0x1f) == 0x12) out += "(" + address + ")";
            else if ((std::to_integer<unsigned>(encoded) & 0x1f) == 0x01) out += "(" + address + ", x)";
            else if ((std::to_integer<unsigned>(encoded) & 0x1f) == 0x11) out += "(" + address + "), y";
            else {
                out += address;
                if (mem->index) out += ", " + register_name(*mem->index);
            }
        } else if (const auto *reg = std::get_if<RegisterOperand>(&i.operands[0]))
            out += register_name(*reg);
        return out;
    }
    if (i.context.architecture == Architecture::mips32 || i.context.architecture == Architecture::mips64) {
        if (i.opcode == Opcode::mips64_c_cond_s || i.opcode == Opcode::mips64_c_cond_d) {
            static constexpr const char *conditions[]{"f", "un", "eq", "ueq", "olt", "ult", "ole", "ule",
                "sf", "ngle", "seq", "ngl", "lt", "nge", "le", "ngt"};
            const auto predicate = static_cast<std::size_t>(i.condition & 0x0f);
            const auto condition_code = static_cast<std::uint8_t>((i.condition >> 4) & 7);
            std::string out = std::string("c.") + conditions[predicate] +
                              (i.opcode == Opcode::mips64_c_cond_s ? ".s" : ".d");
            if (i.context.architecture == Architecture::mips32 || condition_code)
                out += " fcc" + std::to_string(condition_code);
            for (const auto &item : i.operands)
                if (const auto *r = std::get_if<RegisterOperand>(&item))
                    out += (out.find(' ') == std::string::npos ? " " : ", ") + register_name(*r);
            return out;
        }
        std::string out = opcode_name(i.opcode, i.condition);
        const bool fcc_operand = (i.context.architecture == Architecture::mips32 || i.condition != 0) &&
            ((i.opcode >= Opcode::mips_c_eq_s && i.opcode <= Opcode::mips_c_le_s) ||
             (i.opcode >= Opcode::mips_c_eq_d && i.opcode <= Opcode::mips_c_le_d) ||
             i.opcode == Opcode::mips_bc1f || i.opcode == Opcode::mips_bc1t ||
             i.opcode == Opcode::mips_bc1tl || i.opcode == Opcode::mips_bc1fl ||
             i.opcode == Opcode::mips64_bc1tl || i.opcode == Opcode::mips64_bc1fl);
        if (fcc_operand) out += " fcc" + std::to_string(i.condition & 7);
        for (std::size_t n = 0; n < i.operands.size(); ++n) {
            out += (n || fcc_operand) ? ", " : " ";
            if (const auto *r = std::get_if<RegisterOperand>(&i.operands[n])) out += register_name(*r);
            else if (const auto *imm = std::get_if<ImmediateOperand>(&i.operands[n])) {
                if (imm->is_signed && static_cast<std::int64_t>(imm->value) < 0)
                    out += "-0x" + [&] { std::ostringstream s; s << std::hex << (std::uint64_t(0) - imm->value); return s.str(); }();
                else out += hex(imm->value);
            } else if (const auto *m = std::get_if<MemoryOperand>(&i.operands[n])) {
                const auto displacement = m->displacement < 0 ? "-0x" + hex(static_cast<std::uint64_t>(-(m->displacement + 1)) + 1).substr(2) : hex(m->displacement);
                out += displacement + "(" + (m->base ? register_name(*m->base) : "?") + ")";
            } else if (const auto *rel = std::get_if<RelativeOperand>(&i.operands[n]))
                out += i.direct_target ? hex(i.direct_target->offset) : hex(rel->displacement);
        }
        return out;
    }
    if (i.context.architecture == Architecture::powerpc) {
        std::string out = opcode_name(i.opcode, i.condition);
        if ((i.opcode == Opcode::ppc_fctiw || i.opcode == Opcode::ppc_fctiwz ||
             i.opcode == Opcode::ppc_fctid || i.opcode == Opcode::ppc_fctidz ||
             i.opcode == Opcode::ppc_fcfid || i.opcode == Opcode::ppc_fctiwu ||
             i.opcode == Opcode::ppc_fctiwuz || i.opcode == Opcode::ppc_fctidu ||
             i.opcode == Opcode::ppc_fctiduz || i.opcode == Opcode::ppc_fcfidu ||
             i.opcode == Opcode::ppc_fcfids ||
             i.opcode == Opcode::ppc_fmadd || i.opcode == Opcode::ppc_fmsub ||
             i.opcode == Opcode::ppc_fnmadd || i.opcode == Opcode::ppc_fnmsub ||
             i.opcode == Opcode::ppc_fmadds || i.opcode == Opcode::ppc_fmsubs ||
             i.opcode == Opcode::ppc_fnmadds || i.opcode == Opcode::ppc_fnmsubs ||
             i.opcode == Opcode::ppc_mffs || i.opcode == Opcode::ppc_mtfsb0 ||
             i.opcode == Opcode::ppc_mtfsb1 || i.opcode == Opcode::ppc_mtfsfi ||
             i.opcode == Opcode::ppc_mtfsf) &&
            std::find(i.register_writes.begin(), i.register_writes.end(),
                      RegisterOperand{RegisterBank::ppc_cr, 1, 4, false}) != i.register_writes.end())
            out += ".";
        for (std::size_t n = 0; n < i.operands.size(); ++n) {
            out += n ? ", " : " ";
            const auto &operand = i.operands[n];
            if (const auto *reg = std::get_if<RegisterOperand>(&operand)) out += register_name(*reg);
            else if (const auto *imm = std::get_if<ImmediateOperand>(&operand))
                out += imm->is_signed ? signed_hex(x64_detail::sign_value(imm->value, imm->effective_width)) : hex(imm->value);
            else if (const auto *mem = std::get_if<MemoryOperand>(&operand)) {
                if ((i.opcode == Opcode::ppc_lwax || i.opcode == Opcode::ppc_lwaux) && mem->index)
                    out += (mem->base ? register_name(*mem->base) : "0") + ", " + register_name(*mem->index);
                else
                    out += signed_hex(mem->displacement) + "(" + (mem->base ? register_name(*mem->base) : "0") + ")";
            } else if (const auto *rel = std::get_if<RelativeOperand>(&operand))
                out += i.direct_target ? hex(i.direct_target->offset) : signed_hex(rel->displacement);
        }
        return out;
    }
    if ((i.context.architecture == Architecture::riscv64 &&
         (i.context.mode == ExecutionMode::rv64 || i.context.mode == ExecutionMode::rv64c)) ||
        (i.context.architecture == Architecture::riscv32 && i.context.mode == ExecutionMode::rv32)) {
        std::string out = opcode_name(i.opcode, i.condition);
        if (i.opcode >= Opcode::rv_lr_w && i.opcode <= Opcode::rv_amomaxu_d) {
            if (i.atomic_aq && i.atomic_rl) out += ".aqrl";
            else if (i.atomic_aq) out += ".aq";
            else if (i.atomic_rl) out += ".rl";
        }
        for (std::size_t n = 0; n < i.operands.size(); ++n) {
            out += n ? ", " : " ";
            const auto &operand = i.operands[n];
            if (const auto *reg = std::get_if<RegisterOperand>(&operand))
                out += register_name(*reg);
            else if (const auto *immediate = std::get_if<ImmediateOperand>(&operand)) {
                const bool csr_operation = i.opcode >= Opcode::rv_csrrw && i.opcode <= Opcode::rv_csrrci;
                const auto *csr_name = csr_operation && n == 1 && immediate->encoded_width == 12 &&
                        !immediate->is_signed
                    ? riscv_status_trap_csr_name(immediate->value)
                    : nullptr;
                if (csr_name) {
                    out += csr_name;
                } else if ((i.opcode == Opcode::rv_vsetvli || i.opcode == Opcode::rv_vsetivli) &&
                    n == 2 && immediate->effective_width >= 10) {
                    const auto value = immediate->value;
                    const auto vsew = static_cast<unsigned>((value >> 3) & 7);
                    const auto vlmul = static_cast<unsigned>(value & 7);
                    if (value <= 0xff && vsew <= 3 && vlmul != 4) {
                        static constexpr const char *lmul[]{"m1", "m2", "m4", "m8", "?", "mf8", "mf4", "mf2"};
                        out += "e" + std::to_string(8u << vsew) + ", " + lmul[vlmul] +
                               ((value & 0x40) ? ", ta" : ", tu") +
                               ((value & 0x80) ? ", ma" : ", mu");
                    } else {
                        out += hex(value);
                    }
                } else {
                    out += immediate->is_signed
                               ? signed_hex(x64_detail::sign_value(immediate->value, immediate->effective_width))
                               : hex(immediate->value);
                }
            }
            else if (const auto *rel = std::get_if<RelativeOperand>(&operand))
                out += i.direct_target ? hex(i.direct_target->offset) : signed_hex(rel->displacement);
            else if (const auto *memory = std::get_if<MemoryOperand>(&operand))
                out += signed_hex(memory->displacement) + "(" +
                       (memory->base ? register_name(*memory->base) : "?") + ")";
        }
        if (i.rounding_mode) {
            static constexpr const char *rounding[]{"rne","rtz","rdn","rup","rmm","reserved5","reserved6","dyn"};
            if (!i.operands.empty()) out += ", ";
            out += rounding[*i.rounding_mode & 7];
        }
        return out;
    }
    if (i.context.architecture == Architecture::arm &&
        (i.context.mode == ExecutionMode::a32 || i.context.mode == ExecutionMode::thumb))
        return arm32_detail::format(i);
    if (i.context.architecture == Architecture::arm64 && i.context.mode == ExecutionMode::a64)
        return a64_detail::format(i);
    std::string mnemonic = i.opcode == Opcode::x87 || i.opcode == Opcode::x86_flag_control
        ? i.mnemonic_override : opcode_name(i.opcode, i.condition);
    if (i.opcode == Opcode::x86_loop && i.x86_loop_condition) {
        switch (*i.x86_loop_condition) {
        case X86LoopCondition::counter_nonzero: mnemonic = "loop"; break;
        case X86LoopCondition::counter_nonzero_and_zero: mnemonic = "loope"; break;
        case X86LoopCondition::counter_nonzero_and_not_zero: mnemonic = "loopne"; break;
        case X86LoopCondition::counter_zero:
            mnemonic = i.x86_loop_counter_width == 16 ? "jcxz" : i.x86_loop_counter_width == 32 ? "jecxz" : "jrcxz";
            break;
        }
    }
    if (i.context.architecture == Architecture::powerpc &&
        (i.opcode == Opcode::ppc_addc || i.opcode == Opcode::ppc_adde ||
         i.opcode == Opcode::ppc_addze || i.opcode == Opcode::ppc_addze_dot ||
         i.opcode == Opcode::ppc_addme || i.opcode == Opcode::ppc_addme_dot ||
         i.opcode == Opcode::ppc_subfc || i.opcode == Opcode::ppc_subfe || i.opcode == Opcode::ppc_neg ||
         i.opcode == Opcode::ppc_mullw || i.opcode == Opcode::ppc_mulld ||
         i.opcode == Opcode::ppc_mulhw || i.opcode == Opcode::ppc_mulhwu ||
         i.opcode == Opcode::ppc_divw || i.opcode == Opcode::ppc_divwu ||
         i.opcode == Opcode::ppc_divd || i.opcode == Opcode::ppc_divdu ||
         i.opcode == Opcode::ppc_slw || i.opcode == Opcode::ppc_srw ||
         i.opcode == Opcode::ppc_sraw || i.opcode == Opcode::ppc_srawi ||
         i.opcode == Opcode::ppc_sld || i.opcode == Opcode::ppc_srd ||
         i.opcode == Opcode::ppc_srad || i.opcode == Opcode::ppc_sradi) &&
        std::find_if(i.register_writes.begin(), i.register_writes.end(), [](const RegisterOperand &reg) {
            return reg.bank == RegisterBank::ppc_cr && reg.index == 0;
        }) != i.register_writes.end())
        mnemonic += ".";
    if (i.opcode == Opcode::rv_vle || i.opcode == Opcode::rv_vse ||
        i.opcode == Opcode::rv_vlse || i.opcode == Opcode::rv_vsse ||
        i.opcode == Opcode::rv_vluxei || i.opcode == Opcode::rv_vloxei ||
        i.opcode == Opcode::rv_vsuxei || i.opcode == Opcode::rv_vsoxei) {
        const auto memory = std::find_if(i.operands.begin(), i.operands.end(), [](const Operand &operand) {
            return std::holds_alternative<MemoryOperand>(operand);
        });
        if (memory != i.operands.end()) {
            const auto width = std::get<MemoryOperand>(*memory).data_width;
            const bool indexed = i.opcode == Opcode::rv_vluxei || i.opcode == Opcode::rv_vloxei ||
                                 i.opcode == Opcode::rv_vsuxei || i.opcode == Opcode::rv_vsoxei;
            const bool load = i.opcode == Opcode::rv_vle || i.opcode == Opcode::rv_vlse ||
                              i.opcode == Opcode::rv_vluxei || i.opcode == Opcode::rv_vloxei;
            const bool strided = i.opcode == Opcode::rv_vlse || i.opcode == Opcode::rv_vsse;
            const char *prefix = indexed ? (i.opcode == Opcode::rv_vluxei ? "vluxei" :
                                            i.opcode == Opcode::rv_vloxei ? "vloxei" :
                                            i.opcode == Opcode::rv_vsuxei ? "vsuxei" : "vsoxei")
                               : load ? (strided ? "vlse" : "vle") : (strided ? "vsse" : "vse");
            const auto fields = std::max<std::uint8_t>(1, i.riscv_vector_segment_fields);
            if (fields == 1) {
                mnemonic = std::string(prefix) + std::to_string(width) + ".v";
            } else if (indexed) {
                const char *segmented_prefix = i.opcode == Opcode::rv_vluxei ? "vluxseg" :
                    i.opcode == Opcode::rv_vloxei ? "vloxseg" :
                    i.opcode == Opcode::rv_vsuxei ? "vsuxseg" : "vsoxseg";
                mnemonic = std::string(segmented_prefix) + std::to_string(fields) + "ei" +
                           std::to_string(width) + ".v";
            } else {
                const char *segmented_prefix = load ? (strided ? "vlsseg" : "vlseg")
                                                    : (strided ? "vssseg" : "vsseg");
                mnemonic = std::string(segmented_prefix) + std::to_string(fields) + "e" +
                           std::to_string(width) + ".v";
            }
        }
    }
    if (i.opcode == Opcode::pushf && i.stack_value_width == 16 && i.context.mode == ExecutionMode::x86_64)
        mnemonic = "pushfw";
    else if (i.opcode == Opcode::pushf && i.stack_value_width == 32)
        mnemonic = "pushfd";
    else if (i.opcode == Opcode::pushf && i.stack_value_width == 64)
        mnemonic = "pushfq";
    else if (i.opcode == Opcode::popf && i.stack_value_width == 16 && i.context.mode == ExecutionMode::x86_64)
        mnemonic = "popfw";
    else if (i.opcode == Opcode::popf && i.stack_value_width == 32)
        mnemonic = "popfd";
    else if (i.opcode == Opcode::popf && i.stack_value_width == 64)
        mnemonic = "popfq";
    else if (i.opcode == Opcode::pusha && i.stack_value_width == 32)
        mnemonic = "pushad";
    else if (i.opcode == Opcode::popa && i.stack_value_width == 32)
        mnemonic = "popad";
    if (i.opcode == Opcode::x86_movs || i.opcode == Opcode::x86_cmps || i.opcode == Opcode::x86_stos ||
        i.opcode == Opcode::x86_lods || i.opcode == Opcode::x86_scas ||
        i.opcode == Opcode::x86_ins || i.opcode == Opcode::x86_outs) {
        std::uint16_t width = 0;
        for (const auto &operand : i.operands)
            if (const auto *memory = std::get_if<MemoryOperand>(&operand)) {
                width = memory->data_width;
                break;
            }
        mnemonic += width == 8 ? "b" : width == 16 ? "w" : width == 32 ? "d" : width == 64 ? "q" : "?";
    }
    const auto repeat = i.x86_repeat == X86RepeatPrefix::rep ? "rep "
                        : i.x86_repeat == X86RepeatPrefix::repne ? "repne "
                                                                 : "";
    std::string out = (i.lock_prefix ? "lock " : "") + std::string(repeat) + mnemonic;
    const bool implicit_string = i.opcode == Opcode::x86_movs || i.opcode == Opcode::x86_cmps ||
                                 i.opcode == Opcode::x86_stos || i.opcode == Opcode::x86_lods ||
                                 i.opcode == Opcode::x86_scas || i.opcode == Opcode::x86_ins ||
                                 i.opcode == Opcode::x86_outs;
    const bool string_segment_override = implicit_string && std::any_of(
        i.operands.begin(), i.operands.end(), [](const Operand &operand) {
            const auto *memory = std::get_if<MemoryOperand>(&operand);
            return memory && memory->segment.has_value();
        });
    for (std::size_t n = 0; (!implicit_string || string_segment_override) && n < i.operands.size(); ++n) {
        out += n ? ", " : " ";
        const auto &operand = i.operands[n];
        if (const auto *reg = std::get_if<RegisterOperand>(&operand))
            out += register_name(*reg);
        else if (const auto *immediate = std::get_if<ImmediateOperand>(&operand))
            out += immediate->is_signed
                       ? signed_hex(x64_detail::sign_value(immediate->value, immediate->effective_width))
                       : hex(immediate->value);
        else if (const auto *rel = std::get_if<RelativeOperand>(&operand))
            out += i.direct_target ? hex(i.direct_target->offset) : "rel " + signed_hex(rel->displacement);
        else if (const auto *m = std::get_if<MemoryOperand>(&operand)) {
            out += memory_text(*m, i.opcode == Opcode::lea);
            if (i.x86_evex_broadcast && i.vector_element_bits != 0)
                out += "{1to" + std::to_string(i.vector_bits / i.vector_element_bits) + "}";
        }
        else if (const auto *far_pointer = std::get_if<FarPointerOperand>(&operand))
            out += hex(far_pointer->selector) + ":" + hex(far_pointer->offset);
        else if (const auto *far_memory = std::get_if<FarMemoryOperand>(&operand))
            out += "far " + memory_text(far_memory->address, false);
        if (n == 0 && i.x86_opmask) {
            out += "{k" + std::to_string(*i.x86_opmask) + "}";
            if (i.x86_opmask_zeroing)
                out += "{z}";
        }
    }
    if (i.riscv_vector_masked)
        out += ", v0.t";
    if (i.x86_evex_sae)
        out += " {sae}";
    return out;
}
} // namespace hexlab
