#include "hexlab/processors/riscv.hpp"
#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <array>
#include <span>
#include <variant>

using namespace hexlab;
using namespace hexlab_test;

namespace {
RiscvDecodeResult decode(std::uint32_t word, Address at = {{0}, 0x1000}) {
    const std::array bytes{static_cast<std::byte>(word & 0xff), static_cast<std::byte>((word >> 8) & 0xff),
                           static_cast<std::byte>((word >> 16) & 0xff), static_cast<std::byte>(word >> 24)};
    return decode_riscv64(bytes, at);
}

std::uint32_t atomic_word(unsigned funct5, unsigned aq, unsigned rl, unsigned rs2, unsigned rs1,
                          unsigned funct3, unsigned rd) {
    return (funct5 << 27) | (aq << 26) | (rl << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) |
           (rd << 7) | 0x2f;
}

void check_decoded(std::uint32_t word, RiscvOpcode opcode, std::size_t operands, Address at = {{0}, 0x1000}) {
    const auto result = decode(word, at);
    check(result.status == DecodeStatus::decoded && result.instruction.has_value(), "known RV64 encoding decodes");
    if (!result.instruction)
        throw std::runtime_error("RV64 instruction fixture failed: " + result.reason);
    check(result.instruction->opcode == opcode, "RV64 opcode matches literal encoding");
    check(result.instruction->length == 4 && result.instruction->operands.size() == operands,
          "RV64 instruction has expected length and operand count");
}

RiscvDecodeResult decode_c(std::uint16_t half, Address at = {{0}, 0x1000}) {
    const std::array bytes{static_cast<std::byte>(half & 0xff), static_cast<std::byte>(half >> 8)};
    return decode_riscv64c(bytes, at);
}

void compressed_tests() {
    auto result = decode_c(0x0001); // c.nop
    check(result.status == DecodeStatus::decoded && result.instruction && result.instruction->length == 2 &&
              result.instruction->opcode == RiscvOpcode::addi && result.instruction->register_writes.empty(),
          "C.NOP is a two-byte semantic no-op");
    result = decode_c(0x0800); // c.addi4spn x8, sp, 16
    check(result.instruction && result.instruction->opcode == RiscvOpcode::addi && result.instruction->length == 2 &&
              std::get<RiscvRegister>(result.instruction->operands[0]) == RiscvRegister{8} &&
              std::get<RiscvRegister>(result.instruction->operands[1]) == RiscvRegister{2} &&
              std::get<RiscvImmediate>(result.instruction->operands[2]).value == 16,
          "C.ADDI4SPN expands its scattered unsigned offset and compact register");
    result = decode_c(0xe504); // c.sd x9, 8(x10)
    check(result.instruction && result.instruction->opcode == RiscvOpcode::sd && result.instruction->memory_write &&
              std::get<RiscvMemory>(result.instruction->operands[1]) == RiscvMemory{RiscvRegister{10}, 8, 64, false},
          "RV64C compact doubleword store expands its scaled offset");
    result = decode_c(0xa009, {{0}, 0x1000}); // c.j +2
    check(result.instruction && result.instruction->flow == RiscvFlow::jump && result.instruction->length == 2 &&
              result.instruction->direct_target == Address{{0}, 0x1002},
          "C.J reconstructs its signed halfword-scaled target");
    result = decode_c(0xc089); // c.beqz x8, +2
    check(result.instruction && result.instruction->flow == RiscvFlow::conditional_branch &&
              result.instruction->direct_target == Address{{0}, 0x1002} &&
              std::get<RiscvRegister>(result.instruction->operands[1]) == RiscvRegister{0},
          "C.BEQZ integrates compact-register branch flow");
    result = decode_c(0x8282); // c.jr x5
    check(result.instruction && result.instruction->opcode == RiscvOpcode::jalr &&
              result.instruction->flow == RiscvFlow::ret && result.instruction->register_reads == std::vector<RiscvRegister>{{5}},
          "C.JR follows the existing indirect-return classification");
    result = decode_c(0x9002); // c.ebreak
    check(result.instruction && result.instruction->opcode == RiscvOpcode::ebreak &&
              result.instruction->flow == RiscvFlow::trap,
          "C.EBREAK is represented as a trap");
    check(decode_c(0x0000).status == DecodeStatus::invalid, "zero C.ADDI4SPN immediate is reserved");
    check(decode_c(0x0002).status == DecodeStatus::decoded, "C.SLLI with rd=x0 is a valid hint encoding");
    check(decode_c(0x8006).status == DecodeStatus::decoded, "C.MV with rd=x0 is a valid hint encoding");
    check(decode_c(0x2000).status == DecodeStatus::unsupported, "compressed floating load remains unsupported");
    check(decode_c(0x0001, {{0}, 0x1002}).status == DecodeStatus::decoded,
          "RV64C permits instructions on two-byte boundaries");
    const std::array<std::byte, 1> partial{std::byte{0x01}};
    check(decode_riscv64c(partial, {{0}, 0x1000}).status == DecodeStatus::truncated,
          "one-byte compressed instruction prefix is truncated");
}

void format_tests() {
    auto result = decode(0x003100b3); // add x1, x2, x3 (R)
    check_decoded(0x003100b3, RiscvOpcode::add, 3);
    auto &i = *result.instruction;
    check(std::get<RiscvRegister>(i.operands[0]) == RiscvRegister{1} &&
              std::get<RiscvRegister>(i.operands[1]) == RiscvRegister{2} &&
              std::get<RiscvRegister>(i.operands[2]) == RiscvRegister{3},
          "R-format register fields retain rd, rs1, rs2 order");
    check(i.register_reads == std::vector<RiscvRegister>{{2}, {3}} &&
              i.register_writes == std::vector<RiscvRegister>{{1}},
          "R-format records operand register effects");

    result = decode(0xfff10093); // addi x1, x2, -1 (I)
    check_decoded(0xfff10093, RiscvOpcode::addi, 3);
    check(std::get<RiscvImmediate>(result.instruction->operands[2]) == RiscvImmediate{-1, 12, true},
          "I-format immediate is sign extended from twelve encoded bits");

    result = decode(0x02111093); // slli x1, x2, 33 (I shift-immediate)
    check_decoded(0x02111093, RiscvOpcode::slli, 3);
    check(std::get<RiscvImmediate>(result.instruction->operands[2]) == RiscvImmediate{33, 6, false},
          "RV64 shift-immediate retains its six-bit unsigned shamt");

    result = decode(0xfe21bc23); // sd x2, -8(x3) (S)
    check_decoded(0xfe21bc23, RiscvOpcode::sd, 2);
    check(std::get<RiscvMemory>(result.instruction->operands[1]) == RiscvMemory{RiscvRegister{3}, -8, 64, false},
          "S-format displacement combines split fields and retains access width");
    check(result.instruction->memory_write && !result.instruction->memory_read,
          "store format records a write only");

    result = decode(0x00208463); // beq x1, x2, +8 (B)
    check_decoded(0x00208463, RiscvOpcode::beq, 3);
    check(result.instruction->flow == RiscvFlow::conditional_branch &&
              std::get<RiscvRelative>(result.instruction->operands[2]) == RiscvRelative{8, 13, Address{{0}, 0x1008}} &&
              result.instruction->direct_target == Address{{0}, 0x1008},
          "B-format immediate reconstructs scaled signed target");

    result = decode(0x123450b7); // lui x1, 0x12345 (U)
    check_decoded(0x123450b7, RiscvOpcode::lui, 2);
    check(std::get<RiscvImmediate>(result.instruction->operands[1]) == RiscvImmediate{0x12345000, 20, true},
          "U-format immediate is shifted to its architectural value");
    result = decode(0x12345097); // auipc x1, 0x12345 (U)
    check_decoded(0x12345097, RiscvOpcode::auipc, 2);
    check(!result.instruction->direct_target, "AUIPC arithmetic is not mislabeled as a control-flow target");

    result = decode(0x100000ef); // jal x1, +0x100 (J)
    check_decoded(0x100000ef, RiscvOpcode::jal, 2);
    check(result.instruction->flow == RiscvFlow::call && result.instruction->direct_target == Address{{0}, 0x1100} &&
              std::get<RiscvRelative>(result.instruction->operands[1]).displacement == 0x100,
          "J-format reconstructs target and recognizes link-register call");

    result = decode(0x000280e7); // jalr x1, 0(x5)
    check_decoded(0x000280e7, RiscvOpcode::jalr, 2);
    check(result.instruction->flow == RiscvFlow::call &&
              std::get<RiscvMemory>(result.instruction->operands[1]) == RiscvMemory{RiscvRegister{5}, 0, 64, false},
          "JALR represents its indirect base and link effect");
    result = decode(0x00008067); // jalr x0, 0(x1) == ret
    check(result.instruction && result.instruction->flow == RiscvFlow::ret,
          "canonical JALR return is classified as return");
    result = decode(0x00028067); // jalr x0, 0(x5) == alternate-link return
    check(result.instruction && result.instruction->flow == RiscvFlow::ret,
          "alternate-link JALR return is classified as return");
    result = decode(0xffdff06f); // jal x0, -4
    check(result.instruction && result.instruction->flow == RiscvFlow::jump &&
              result.instruction->direct_target == Address{{0}, 0xffc},
          "negative J-format displacement sign extends to the correct target");
    result = decode(0xffdff06f, {{0}, 0});
    check(result.instruction && !result.instruction->direct_target,
          "out-of-domain negative direct target is left unresolved");

    result = decode(0x00003003); // ld x0, 0(x0) (I load)
    check_decoded(0x00003003, RiscvOpcode::ld, 2);
    check(result.instruction->memory_read && result.instruction->register_writes.empty(),
          "load from x0 records memory read and suppresses hardwired-zero write");
    result = decode(0x00002083); // lw x1, 0(x0)
    check_decoded(0x00002083, RiscvOpcode::lw, 2);
    check(std::get<RiscvMemory>(result.instruction->operands[1]).width == 32 &&
              std::get<RiscvMemory>(result.instruction->operands[1]).sign_extend,
          "narrow signed load preserves data width and sign-extension behavior");

    result = decode(0x00f0000f); // fence (misc-mem)
    check_decoded(0x00f0000f, RiscvOpcode::fence, 2);
    check(std::get<RiscvImmediate>(result.instruction->operands[0]).value == 0 &&
              std::get<RiscvImmediate>(result.instruction->operands[1]).value == 0xf,
          "FENCE exposes predecessor and successor masks");

    result = decode(0x00000073); // ecall (system)
    check_decoded(0x00000073, RiscvOpcode::ecall, 0);
    check(result.instruction->flow == RiscvFlow::trap, "ECALL is a trap-style control transfer");

    result = decode(0x027302b3); // mul x5, x6, x7 (M extension R)
    check_decoded(0x027302b3, RiscvOpcode::mul, 3);
    result = decode(0x02b302bb); // mulw x5, x6, x11 (M extension RV64 word form)
    check_decoded(0x02b302bb, RiscvOpcode::mulw, 3);
    result = decode(0x007302bb); // addw x5, x6, x7 (OP-32)
    check_decoded(0x007302bb, RiscvOpcode::addw, 3);
    result = decode(0xfff1009b); // addiw x1, x2, -1 (OP-IMM-32)
    check_decoded(0xfff1009b, RiscvOpcode::addiw, 3);
}

void vector_configuration_tests() {
    const auto vsetvli_word = (0x416u << 20) | (6u << 15) | (7u << 12) | (5u << 7) | 0x57u;
    auto result = decode(vsetvli_word);
    check(result.instruction && result.instruction->opcode == RiscvOpcode::vsetvli &&
              result.instruction->operands.size() == 3 && result.instruction->register_reads.size() == 1 &&
              result.instruction->register_writes.size() == 4,
          "VSETVLI preserves AVL, vtype immediate, destination, and implicit VL/VTYPE writes");
    check(result.instruction && std::get<RiscvImmediate>(result.instruction->operands[2]).value == 0x416 &&
              !result.instruction->memory_read && !result.instruction->memory_write,
          "VSETVLI exposes the full 11-bit vtype immediate without inventing memory effects");

    const auto vsetivli_word = (3u << 30) | (0x15u << 20) | (7u << 15) | (7u << 12) | (5u << 7) | 0x57u;
    result = decode(vsetivli_word);
    check(result.instruction && result.instruction->opcode == RiscvOpcode::vsetivli &&
              std::get<RiscvImmediate>(result.instruction->operands[1]).value == 7 &&
              std::get<RiscvImmediate>(result.instruction->operands[2]).value == 0x15,
          "VSETIVLI separates its immediate AVL from its 10-bit vtype immediate");

    const auto vsetvl_word = (0x40u << 25) | (7u << 20) | (6u << 15) | (7u << 12) | (5u << 7) | 0x57u;
    result = decode(vsetvl_word);
    check(result.instruction && result.instruction->opcode == RiscvOpcode::vsetvl &&
              result.instruction->register_reads.size() == 2 && result.instruction->register_writes.size() == 4,
          "VSETVL reads both scalar inputs and records implicit VL/VTYPE writes");

    const std::array bytes{static_cast<std::byte>(vsetvli_word & 0xff), static_cast<std::byte>((vsetvli_word >> 8) & 0xff),
                           static_cast<std::byte>((vsetvli_word >> 16) & 0xff), static_cast<std::byte>(vsetvli_word >> 24)};
    const auto generic = decode_instruction({Architecture::riscv64, ExecutionMode::rv64}, bytes, {{0}, 0x1000});
    check(generic.instruction && generic.instruction->opcode == Opcode::rv_vsetvli &&
              generic.instruction->register_writes.size() == 4 &&
              register_name(generic.instruction->register_writes[1]) == "vl" &&
              register_name(generic.instruction->register_writes[2]) == "vtype" &&
              format_instruction(*generic.instruction).find("vsetvli") != std::string::npos,
          "generic RV64 decoding retains vector configuration state effects and assembly spelling");
    const auto generic32 = decode_instruction({Architecture::riscv32, ExecutionMode::rv32}, bytes, {{0}, 0x1000});
    check(generic32.instruction && generic32.instruction->opcode == Opcode::rv_vsetvli &&
              generic32.instruction->register_writes[1].width == 32,
          "RV32 also accepts the shared vector-configuration encoding at XLEN width");
    const auto vadd_vv = (4u << 20) | (5u << 15) | (3u << 7) | 0x57u;
    result = decode(vadd_vv);
    check(result.instruction && result.instruction->opcode == RiscvOpcode::vadd_vv &&
              result.instruction->operands.size() == 3 && result.instruction->register_reads.size() == 7 &&
              result.instruction->register_writes.size() == 2,
          "VADD.VV exposes vector source and destination register effects");
    const auto vadd_vx = (1u << 25) | (4u << 20) | (6u << 15) | (4u << 12) | (3u << 7) | 0x57u;
    result = decode(vadd_vx);
    check(result.instruction && result.instruction->opcode == RiscvOpcode::vadd_vx &&
              std::get<RiscvRegister>(result.instruction->operands[2]).index == 6 &&
              !std::get<RiscvRegister>(result.instruction->operands[2]).vector,
          "VADD.VX distinguishes the scalar GPR operand from vector sources");
    const auto vand_vi = (9u << 26) | (1u << 25) | (31u << 15) | (3u << 12) | (8u << 7) | 0x57u;
    result = decode(vand_vi);
    check(result.instruction && result.instruction->opcode == RiscvOpcode::vand_vi &&
              std::get<RiscvImmediate>(result.instruction->operands[2]).value == -1,
          "VAND.VI sign-extends its five-bit immediate");
    const auto masked = (4u << 20) | (5u << 15) | (3u << 7) | 0x57u;
    result = decode(masked);
    check(result.instruction && result.instruction->register_reads.size() == 7 &&
              result.instruction->register_reads[3].vector && result.instruction->register_reads[3].index == 0,
          "masked vector arithmetic records the implicit v0 predicate read");
    check(decode(0x00002057).instruction && decode(0x00002057).instruction->opcode == RiscvOpcode::vredsum,
          "VREDSUM uses the vector reduction opcode and seed operands");
    const auto sub_vi_reserved = (2u << 26) | (1u << 15) | (3u << 12) | (2u << 7) | 0x57u;
    check(decode(sub_vi_reserved).status == DecodeStatus::invalid,
          "reserved VSUB.VI form is rejected");
    const std::array arithmetic_bytes{static_cast<std::byte>(vadd_vv & 0xff), static_cast<std::byte>((vadd_vv >> 8) & 0xff),
        static_cast<std::byte>((vadd_vv >> 16) & 0xff), static_cast<std::byte>(vadd_vv >> 24)};
    const auto generic_vector = decode_instruction({Architecture::riscv64, ExecutionMode::rv64}, arithmetic_bytes, {{0}, 0x1000});
    check(generic_vector.instruction && generic_vector.instruction->opcode == Opcode::rv_vadd_vv &&
              format_instruction(*generic_vector.instruction).find("vadd.vv") != std::string::npos &&
              register_name(generic_vector.instruction->register_writes[0]) == "v3",
          "generic dispatch preserves typed RVV registers and assembly spelling");
}

void invalid_and_truncation_tests() {
    const std::array<std::byte, 4> addi{std::byte{0x93}, std::byte{0x00}, std::byte{0x10}, std::byte{0x00}};
    for (std::size_t n = 0; n < addi.size(); ++n)
        check(decode_riscv64(std::span<const std::byte>(addi).first(n), {{0}, 0x1000}).status == DecodeStatus::truncated,
              "partial base instruction is reported as truncated");
    check(decode_riscv64({}, {{0}, 0x1000}).status == DecodeStatus::truncated, "empty stream is truncated");
    check(decode_riscv64(addi, {{0}, 0x1002}).status == DecodeStatus::invalid,
          "base-only RV64I rejects a misaligned instruction address");

    check(decode(0x00002063).status == DecodeStatus::invalid, "reserved branch funct3 is invalid");
    check(decode(0x04011093).status == DecodeStatus::invalid, "reserved SLLI upper immediate bits are invalid");
    check(decode(0x00000000).status == DecodeStatus::unsupported, "compressed encoding is detected, not misdecoded as 32-bit");
    check(decode(0x0000100f).instruction && decode(0x0000100f).instruction->opcode == RiscvOpcode::fence_i,
          "FENCE.I decodes as the instruction-cache synchronization operation");
    const auto csrrw_zero_rd = decode(0x00001073);
    check(csrrw_zero_rd.instruction && !csrrw_zero_rd.instruction->csr_read &&
              csrrw_zero_rd.instruction->csr_write,
          "CSRRW with rd=x0 decodes as a CSR write without reading its old value");
    check(decode(atomic_word(0x05, 0, 0, 0, 0, 2, 0)).status == DecodeStatus::invalid,
          "reserved atomic funct5 encoding is rejected");

    const std::array<std::byte, 6> long_instruction{std::byte{0x1f}, std::byte{0x00}, std::byte{0}, std::byte{0},
                                                    std::byte{0}, std::byte{0}};
    check(decode_riscv64(std::span<const std::byte>(long_instruction).first(4), {{0}, 0x1000}).status ==
              DecodeStatus::truncated,
          "detected 48-bit instruction cannot be accepted from only four bytes");
    check(decode_riscv64(long_instruction, {{0}, 0x1000}).status == DecodeStatus::unsupported,
          "complete 48-bit instruction is explicitly unsupported");
}

void atomic_tests() {
    constexpr std::array<unsigned, 11> atomic_funct5{0x02, 0x03, 0x01, 0x00, 0x04, 0x0c, 0x08, 0x10, 0x14, 0x18, 0x1c};
    constexpr std::array<RiscvOpcode, 11> word_opcodes{
        RiscvOpcode::lr_w, RiscvOpcode::sc_w, RiscvOpcode::amoswap_w, RiscvOpcode::amoadd_w,
        RiscvOpcode::amoxor_w, RiscvOpcode::amoand_w, RiscvOpcode::amoor_w, RiscvOpcode::amomin_w,
        RiscvOpcode::amomax_w, RiscvOpcode::amominu_w, RiscvOpcode::amomaxu_w};
    constexpr std::array<RiscvOpcode, 11> double_opcodes{
        RiscvOpcode::lr_d, RiscvOpcode::sc_d, RiscvOpcode::amoswap_d, RiscvOpcode::amoadd_d,
        RiscvOpcode::amoxor_d, RiscvOpcode::amoand_d, RiscvOpcode::amoor_d, RiscvOpcode::amomin_d,
        RiscvOpcode::amomax_d, RiscvOpcode::amominu_d, RiscvOpcode::amomaxu_d};
    for (std::size_t index = 0; index < atomic_funct5.size(); ++index) {
        const auto rs2 = atomic_funct5[index] == 0x02 ? 0u : 7u;
        const auto word = decode(atomic_word(atomic_funct5[index], 0, 0, rs2, 4, 2, 5));
        check(word.instruction && word.instruction->opcode == word_opcodes[index],
              "all eleven RV32/RV64 word atomic operations decode to typed opcodes");
        const auto dword = decode(atomic_word(atomic_funct5[index], 0, 0, rs2, 4, 3, 5));
        check(dword.instruction && dword.instruction->opcode == double_opcodes[index],
              "all eleven RV64 doubleword atomic operations decode to typed opcodes");
    }

    auto result = decode(atomic_word(0b00010, 1, 0, 0, 4, 2, 5)); // lr.w.aq x5, (x4)
    check(result.instruction && result.instruction->opcode == RiscvOpcode::lr_w &&
              result.instruction->memory_read && !result.instruction->memory_write &&
              result.instruction->register_reads == std::vector<RiscvRegister>{{4}} &&
              result.instruction->register_writes == std::vector<RiscvRegister>{{5}} &&
              result.instruction->atomic_aq && !result.instruction->atomic_rl,
          "LR.W records its signed result, read effect, register effects, and acquire bit");
    check(result.instruction && std::get<RiscvMemory>(result.instruction->operands[1]) ==
                                    RiscvMemory{RiscvRegister{4}, 0, 32, true},
          "LR.W sign-extends the reserved word value to XLEN");

    result = decode(atomic_word(0b00011, 1, 1, 7, 6, 3, 5)); // sc.d.aqrl x5, x7, (x6)
    check(result.instruction && result.instruction->opcode == RiscvOpcode::sc_d &&
              !result.instruction->memory_read && result.instruction->memory_write &&
              result.instruction->register_reads == (std::vector<RiscvRegister>{{7}, {6}}) &&
              result.instruction->register_writes == std::vector<RiscvRegister>{{5}} &&
              result.instruction->atomic_aq && result.instruction->atomic_rl,
          "SC.D records address and source reads, status write, store effect, and aq/rl ordering");

    result = decode(atomic_word(0b00000, 0, 1, 7, 6, 2, 5)); // amoadd.w.rl x5, x7, (x6)
    check(result.instruction && result.instruction->opcode == RiscvOpcode::amoadd_w &&
              result.instruction->memory_read && result.instruction->memory_write &&
              result.instruction->access.size() == 3 &&
              result.instruction->access[2] == RiscvOperandAccess::read_write &&
              result.instruction->atomic_rl && !result.instruction->atomic_aq,
          "AMOADD.W models atomic read-modify-write and release ordering");

    const auto rv32 = atomic_word(0b00000, 0, 0, 7, 6, 2, 5);
    const std::array rv32_bytes{static_cast<std::byte>(rv32 & 0xff), static_cast<std::byte>((rv32 >> 8) & 0xff),
                                static_cast<std::byte>((rv32 >> 16) & 0xff), static_cast<std::byte>(rv32 >> 24)};
    result = decode_riscv32(rv32_bytes, {{0}, 0x1000});
    check(result.instruction && result.instruction->opcode == RiscvOpcode::amoadd_w &&
              std::get<RiscvMemory>(result.instruction->operands[2]).width == 32,
          "RV32A supports word atomic operations at XLEN 32");

    check(decode(atomic_word(0b00010, 0, 0, 1, 4, 2, 5)).status == DecodeStatus::invalid,
          "LR requires its reserved rs2 field to be zero");
    check(decode(atomic_word(0b00010, 0, 0, 0, 4, 1, 5)).status == DecodeStatus::invalid,
          "reserved atomic widths are rejected");
}

void fp_memory_tests() {
    auto result = decode(0x0042a187); // flw f3, 4(x5)
    check(result.status == DecodeStatus::decoded && result.instruction.has_value(),
          "FLW known-answer encoding is decoded");
    if (result.instruction) {
        check(result.instruction->memory_read && !result.instruction->memory_write &&
                  result.instruction->operands.size() == 2,
              "FLW records a memory read and destination operand");
        check(std::get<RiscvMemory>(result.instruction->operands[1]) ==
                  RiscvMemory{RiscvRegister{5}, 4, 32, false},
              "FLW retains 32-bit memory width and XLEN-independent address base");
    }

    result = decode(0xff82b187); // fld f3, -8(x5)
    check(result.status == DecodeStatus::decoded && result.instruction && result.instruction->memory_read &&
              std::get<RiscvMemory>(result.instruction->operands[1]) ==
                  RiscvMemory{RiscvRegister{5}, -8, 64, false},
          "FLD sign extends its offset and retains 64-bit memory width");
    result = decode(0x0032a227); // fsw f3, 4(x5)
    check(result.status == DecodeStatus::decoded && result.instruction && !result.instruction->memory_read &&
              result.instruction->memory_write && result.instruction->operands.size() == 2,
          "FSW records a single memory write");
    result = decode(0xfe32bc27); // fsd f3, -8(x5)
    check(result.status == DecodeStatus::decoded && result.instruction && result.instruction->memory_write &&
              std::get<RiscvMemory>(result.instruction->operands[1]).width == 64 &&
              std::get<RiscvMemory>(result.instruction->operands[1]).displacement == -8,
          "FSD combines split signed displacement and doubleword access width");

    const std::uint32_t invalid_flw = 0x00001087; // FLW funct3=1 is reserved.
    check(decode(invalid_flw).status == DecodeStatus::invalid,
          "reserved floating-point load widths are invalid");
    const std::uint32_t rv32_fld = 0x00003007;
    const std::array rv32_fld_bytes{static_cast<std::byte>(rv32_fld), static_cast<std::byte>(rv32_fld >> 8),
                                    static_cast<std::byte>(rv32_fld >> 16), static_cast<std::byte>(rv32_fld >> 24)};
    const auto rv32_double = decode_riscv32(rv32_fld_bytes, {{0}, 0x1000});
    check(rv32_double.status == DecodeStatus::decoded && rv32_double.instruction &&
              std::get<RiscvMemory>(rv32_double.instruction->operands[1]).width == 64,
          "RV32D retains double-width memory while addressing through XLEN 32");
}

void fp_operation_tests() {
    constexpr std::array<std::uint32_t, 18> valid_forms{
        0x002081d3, // fadd.s f3, f1, f2
        0x082081d3, // fsub.s f3, f1, f2
        0x102081d3, // fmul.s f3, f1, f2
        0x182081d3, // fdiv.s f3, f1, f2
        0x580081d3, // fsqrt.s f3, f1
        0x022081d3, // fadd.d f3, f1, f2
        0x1a2081d3, // fdiv.d f3, f1, f2
        0x18208243, // fmadd.s f4, f1, f2, f3
        0x18208247, // fmsub.s f4, f1, f2, f3
        0x1820824b, // fnmsub.s f4, f1, f2, f3
        0x1820824f, // fnmadd.s f4, f1, f2, f3
        0x1a208247, // fmsub.d f4, f1, f2, f3
        0xa020a2d3, // feq.s x5, f1, f2
        0xe00092d3, // fclass.s x5, f1
        0xc00082d3, // fcvt.w.s x5, f1
        0xd00281d3, // fcvt.s.w f3, x5
        0x401081d3, // fcvt.s.d f3, f1
        0x420081d3  // fcvt.d.s f3, f1
    };
    for (const auto word : valid_forms)
        check(decode(word).status == DecodeStatus::decoded,
              "supported scalar floating-point instruction known-answer encoding is decoded");

    auto result = decode(0x0020a1d3); // fadd.s f3, f1, f2, rdn
    check(result.status == DecodeStatus::decoded && result.instruction,
          "static rounding mode is accepted on S arithmetic");
    result = decode(0x0020f1d3); // fadd.s f3, f1, f2, dyn
    check(result.status == DecodeStatus::decoded && result.instruction,
          "dynamic rounding mode is accepted");

    check(decode(0x0020d1d3).status == DecodeStatus::invalid,
          "reserved static rounding value five is invalid");
    check(decode(0x0020e1d3).status == DecodeStatus::invalid,
          "reserved static rounding value six is invalid");
    check(decode(0x1820d243).status == DecodeStatus::invalid,
          "reserved fused-operation rounding mode is invalid");
    check(decode(0x042081d3).status == DecodeStatus::unsupported,
          "valid quad-precision format stays explicitly unsupported");
}

void fp_dispatch_tests() {
    const std::uint32_t word = 0x0020a1d3; // fadd.s f3, f1, f2, rdn
    const std::array bytes{static_cast<std::byte>(word), static_cast<std::byte>(word >> 8),
                           static_cast<std::byte>(word >> 16), static_cast<std::byte>(word >> 24)};
    DecodeContext context{Architecture::riscv64, ExecutionMode::rv64, ByteOrder::little};
    const auto decoded = decode_instruction(context, bytes, {{0}, 0x1000});
    check(decoded.status == DecodeStatus::decoded && decoded.instruction,
          "generic processor dispatch accepts RISC-V F/D instructions");
    if (decoded.instruction) {
        const auto &i = *decoded.instruction;
        check(i.opcode == Opcode::rv_fadd_s && i.rounding_mode == 2 && i.writes_fflags,
              "generic F/D instruction retains opcode, rounding mode, and floating status effect");
        check(i.operands.size() == 3 && std::get<RegisterOperand>(i.operands[0]).bank == RegisterBank::riscv_fpr &&
                  std::get<RegisterOperand>(i.operands[0]).width == 64 &&
                  i.register_writes.size() == 2 && i.register_writes[1].bank == RegisterBank::riscv_fstatus,
              "FPR operands use the physical bank and fflags is tracked separately");
        check(format_instruction(i) == "fadd.s f3, f1, f2, rdn",
              "generic formatter renders FPR names and static rounding mode");
    }
}

void zicsr_tests() {
    auto result = decode(0x300312f3); // csrrw x5, mstatus, x6
    check(result.status == DecodeStatus::decoded && result.instruction.has_value(),
          "Zicsr CSRRW known-answer encoding is decoded");
    if (result.instruction) {
        check(result.instruction->opcode == RiscvOpcode::csrrw && result.instruction->operands.size() == 3 &&
                  std::get<RiscvImmediate>(result.instruction->operands[1]) == RiscvImmediate{0x300, 12, false} &&
                  result.instruction->register_reads == std::vector<RiscvRegister>{{6}} &&
                  result.instruction->register_writes == std::vector<RiscvRegister>{{5}},
              "CSRRW exposes its CSR address and integer-register effects");
        check(result.instruction->csr_read && result.instruction->csr_write &&
                  result.instruction->access == std::vector<RiscvOperandAccess>{RiscvOperandAccess::write,
                      RiscvOperandAccess::read_write, RiscvOperandAccess::read},
              "CSRRW reports both CSR effects and an explicit read-write CSR operand");
    }

    result = decode(0xc0002073); // csrrs x0, cycle, x0
    check(result.status == DecodeStatus::decoded && result.instruction &&
              result.instruction->opcode == RiscvOpcode::csrrs && result.instruction->operands.size() == 3 &&
              result.instruction->csr_read && !result.instruction->csr_write &&
              result.instruction->register_reads.empty() && result.instruction->register_writes.empty(),
          "CSRRS known-answer encoding retains three explicit operands");

    result = decode(0x300332f3); // csrrc x5, mstatus, x6
    check(result.status == DecodeStatus::decoded && result.instruction &&
              result.instruction->opcode == RiscvOpcode::csrrc && result.instruction->csr_read &&
              result.instruction->csr_write && result.instruction->register_reads == std::vector<RiscvRegister>{{6}},
          "CSRRC reads the old CSR and conditionally writes a cleared value");

    result = decode(0x300352f3); // csrrwi x5, mstatus, 6
    check(result.status == DecodeStatus::decoded && result.instruction &&
              result.instruction->opcode == RiscvOpcode::csrrwi && result.instruction->operands.size() == 3 &&
              std::get<RiscvImmediate>(result.instruction->operands[2]) == RiscvImmediate{6, 5, false},
          "CSRRWI preserves its unsigned five-bit zimm field");
    check(result.instruction->csr_write && result.instruction->csr_read &&
              result.instruction->register_reads.empty(),
          "CSRRWI reads old CSR state when rd is nonzero");

    result = decode(0xc00062f3); // csrrsi x5, cycle, 0
    check(result.status == DecodeStatus::decoded && result.instruction &&
              result.instruction->opcode == RiscvOpcode::csrrsi && result.instruction->csr_read &&
              !result.instruction->csr_write,
          "CSRRSI zero mask does not write the CSR");
    result = decode(0x300372f3); // csrrci x5, mstatus, 6
    check(result.status == DecodeStatus::decoded && result.instruction &&
              result.instruction->opcode == RiscvOpcode::csrrci && result.instruction->csr_read &&
              result.instruction->csr_write &&
              std::get<RiscvImmediate>(result.instruction->operands[2]) == RiscvImmediate{6, 5, false},
          "CSRRCI nonzero mask reads and writes the selected CSR");

    const std::array<std::byte, 4> reserved{std::byte{0x73}, std::byte{0x40}, std::byte{0x00}, std::byte{0x30}};
    check(decode_riscv64(reserved, {{0}, 0x1000}).status == DecodeStatus::invalid,
          "reserved SYSTEM funct3 remains invalid with Zicsr enabled");
    const std::array<std::byte, 3> partial{std::byte{0xf3}, std::byte{0x12}, std::byte{0x03}};
    check(decode_riscv64(partial, {{0}, 0x1000}).status == DecodeStatus::truncated,
          "truncated Zicsr instruction remains truncated");
}
} // namespace

int main() {
    return run([] {
        format_tests();
        invalid_and_truncation_tests();
        compressed_tests();
        vector_configuration_tests();
        atomic_tests();
        fp_memory_tests();
        fp_operation_tests();
        fp_dispatch_tests();
        zicsr_tests();
    });
}
