#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
#include "support/checks.hpp"

#include <array>
#include <utility>

using namespace hexlab;
using namespace hexlab_test;

namespace {
DecodeResult decode(std::uint32_t word, std::uint64_t address = 0x1'0000'1000ULL) {
    const std::array bytes{std::byte{static_cast<unsigned char>(word & 0xff)},
                           std::byte{static_cast<unsigned char>((word >> 8) & 0xff)},
                           std::byte{static_cast<unsigned char>((word >> 16) & 0xff)},
                           std::byte{static_cast<unsigned char>((word >> 24) & 0xff)}};
    return decode_instruction({Architecture::mips64, ExecutionMode::mips64, ByteOrder::little},
                              bytes, Address{{0}, address});
}

void n64_scalar_decode() {
    // DADDIU t0,a0,-8. The signed immediate must remain -8 and GPR operands
    // must retain the 64-bit N64 register width.
    const auto daddiu = decode((0x19u << 26) | (4u << 21) | (8u << 16) | 0xfff8u);
    check(daddiu.status == DecodeStatus::decoded && daddiu.instruction &&
              daddiu.instruction->opcode == Opcode::mips64_daddiu &&
              daddiu.instruction->operands.size() == 3,
          "N64 DADDIU decodes as a distinct 64-bit operation");
    if (daddiu.instruction) {
        const auto *destination = std::get_if<RegisterOperand>(&daddiu.instruction->operands[0]);
        const auto *source = std::get_if<RegisterOperand>(&daddiu.instruction->operands[1]);
        const auto *immediate = std::get_if<ImmediateOperand>(&daddiu.instruction->operands[2]);
        check(destination && destination->index == 8 && destination->width == 64 && source &&
                  source->index == 4 && source->width == 64 && immediate && immediate->is_signed &&
                  static_cast<std::int64_t>(immediate->value) == -8,
              "DADDIU preserves 64-bit registers and sign-extended immediate");
        check(format_instruction(*daddiu.instruction) == "daddiu t0, a0, -0x8",
              "MIPS64 formatting uses MIPS GPR aliases and signed immediates");
    }

    const auto daddi = decode((0x18u << 26) | (4u << 21) | (8u << 16) | 0xfff8u);
    check(daddi.status == DecodeStatus::decoded && daddi.instruction &&
              format_instruction(*daddi.instruction) == "daddi t0, a0, -0x8" &&
              daddi.instruction->register_reads == std::vector<RegisterOperand>{{RegisterBank::mips_gpr, 4, 64, false}} &&
              daddi.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_gpr, 8, 64, false}},
          "N64 trapping DADDI preserves signed 16-bit immediate and 64-bit effects");

    // LD s0,-32(sp); MIPS64 memory addresses and register values are 64-bit.
    const auto ld = decode((0x37u << 26) | (29u << 21) | (16u << 16) | 0xffe0u);
    check(ld.status == DecodeStatus::decoded && ld.instruction && ld.instruction->opcode == Opcode::mips64_ld &&
              ld.instruction->memory_read,
          "N64 LD decodes with a memory read");
    if (ld.instruction) {
        const auto *destination = std::get_if<RegisterOperand>(&ld.instruction->operands[0]);
        const auto *memory = std::get_if<MemoryOperand>(&ld.instruction->operands[1]);
        check(destination && destination->index == 16 && destination->width == 64 && memory &&
                  memory->data_width == 64 && memory->address_width == 64 && memory->base &&
                  memory->base->index == 29 && memory->displacement == -32,
              "LD preserves 64-bit destination, base, and signed displacement");
    }

    // SCD reads its source and writes the same GPR with the success flag.
    const auto scd = decode((0x3cu << 26) | (29u << 21) | (8u << 16) | 8u);
    check(scd.status == DecodeStatus::decoded && scd.instruction &&
              scd.instruction->opcode == Opcode::mips64_scd &&
              scd.instruction->memory_write &&
              scd.instruction->register_reads == std::vector<RegisterOperand>{{RegisterBank::mips_gpr, 8, 64, false}} &&
              scd.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_gpr, 8, 64, false}} &&
              scd.instruction->access[0] == OperandAccess::read_write,
          "SCD decodes source and success-result register effects");

    // PREF is an architecturally nonbinding prefetch hint. It consumes an
    // effective address but does not itself read or write program memory.
    const auto pref = decode((0x33u << 26) | (8u << 21) | (5u << 16) | 0xfff0u);
    const auto *pref_memory = pref.instruction && pref.instruction->operands.size() > 1
                                  ? std::get_if<MemoryOperand>(&pref.instruction->operands[1]) : nullptr;
    check(pref.status == DecodeStatus::decoded && pref.instruction &&
              pref.instruction->opcode == Opcode::mips64_pref &&
              pref.instruction->operands.size() == 2 && pref_memory && pref_memory->base &&
              pref_memory->base->index == 8 && pref_memory->displacement == -16 &&
              pref.instruction->register_reads == std::vector<RegisterOperand>{{RegisterBank::mips_gpr, 8, 64, false}} &&
              !pref.instruction->memory_read && !pref.instruction->memory_write &&
              format_instruction(*pref.instruction) == "pref 0x5, -0x10(t0)",
          "PREF retains hint/address while avoiding a false architectural memory access");

    const auto dmult = decode((8u << 21) | (9u << 16) | 0x1cu);
    const auto mfhi = decode((8u << 11) | 0x10u);
    const auto ddivu = decode((10u << 21) | (11u << 16) | 0x1fu);
    const auto mtlo = decode((12u << 21) | 0x13u);
    check(dmult.status == DecodeStatus::decoded && mfhi.status == DecodeStatus::decoded &&
              ddivu.status == DecodeStatus::decoded && mtlo.status == DecodeStatus::decoded,
          "N64 doubleword multiply/divide and HI/LO moves decode as typed instructions");
    if (dmult.instruction && mfhi.instruction && ddivu.instruction && mtlo.instruction) {
        check(format_instruction(*dmult.instruction).starts_with("dmult ") &&
                  dmult.instruction->register_reads.size() == 2 &&
                  dmult.instruction->register_reads[0].width == 64 &&
                  dmult.instruction->register_writes.size() == 2 &&
                  dmult.instruction->register_writes[0].bank == RegisterBank::mips_hilo &&
                  dmult.instruction->register_writes[0].width == 64,
              "DMULT writes the full-width HI/LO pair");
        check(format_instruction(*mfhi.instruction) == "mfhi t0" &&
                  mfhi.instruction->register_reads.size() == 1 &&
                  mfhi.instruction->register_reads[0].bank == RegisterBank::mips_hilo &&
                  mfhi.instruction->register_reads[0].width == 64,
              "MFHI reads the 64-bit HI register");
        check(format_instruction(*ddivu.instruction) == "ddivu t2, t3" &&
                  ddivu.instruction->register_reads.size() == 2 &&
                  ddivu.instruction->register_writes.size() == 2 &&
                  ddivu.instruction->register_writes[1] == RegisterOperand{RegisterBank::mips_hilo, 1, 64, false},
              "DDIVU reads 64-bit operands and updates HI/LO");
        check(format_instruction(*mtlo.instruction) == "mtlo t4" &&
                  mtlo.instruction->register_reads.size() == 1 &&
                  mtlo.instruction->register_reads[0].width == 64 &&
                  mtlo.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_hilo, 1, 64, false}},
              "MTLO writes the 64-bit LO register");
    }

    // BEQ has a 64-bit target and still owns one delay-slot instruction.
    const auto branch = decode((4u << 26) | (8u << 21) | (9u << 16) | 1u);
    check(branch.status == DecodeStatus::decoded && branch.instruction &&
              branch.instruction->direct_target == Address{{0}, 0x1'0000'1008ULL} &&
              branch.instruction->delay_slots == 1 && branch.instruction->register_reads.size() == 2 &&
              branch.instruction->register_reads[0].width == 64,
          "N64 branch retains 64-bit address and delay-slot semantics");

    const auto lui = decode((0x0fu << 26) | (8u << 16) | 0x8000u);
    const auto *lui_immediate = lui.instruction && lui.instruction->operands.size() > 1
                                    ? std::get_if<ImmediateOperand>(&lui.instruction->operands[1])
                                    : nullptr;
    check(lui.status == DecodeStatus::decoded && lui.instruction &&
              lui_immediate && lui_immediate->value == 0x8000 &&
              format_instruction(*lui.instruction) == "lui t0, 0x8000",
          "MIPS64 LUI formatting preserves the unsigned 16-bit instruction field");

    const std::array<std::byte, 3> short_word{};
    const auto truncated = decode_instruction(
        {Architecture::mips64, ExecutionMode::mips64, ByteOrder::little}, short_word, Address{{0}, 0x1000});
    check(truncated.status == DecodeStatus::truncated, "MIPS64 fixed-width truncation is explicit");
    check(decode(0x0000003du).status == DecodeStatus::invalid, "reserved MIPS64 SPECIAL function remains invalid");
    const auto big_capability = processor_capabilities({Architecture::mips64, ExecutionMode::mips64, ByteOrder::big});
    check(big_capability.can_decode && big_capability.display_name.find("scalar COP1") != std::string_view::npos,
          "big-endian MIPS64 advertises the integer and scalar COP1 subset");
}

void big_endian_mips64_decode() {
    const auto decode_big = [](std::uint32_t word, std::uint64_t address) {
        const std::array bytes{std::byte{static_cast<unsigned char>((word >> 24) & 0xff)},
                               std::byte{static_cast<unsigned char>((word >> 16) & 0xff)},
                               std::byte{static_cast<unsigned char>((word >> 8) & 0xff)},
                               std::byte{static_cast<unsigned char>(word & 0xff)}};
        return decode_instruction({Architecture::mips64, ExecutionMode::mips64, ByteOrder::big},
                                  bytes, Address{{0}, address});
    };
    const auto daddiu = decode_big((0x19u << 26) | (4u << 21) | (8u << 16) | 0xfff8u, 0x1000);
    const auto *big_immediate = daddiu.instruction && daddiu.instruction->operands.size() > 2
                                    ? std::get_if<ImmediateOperand>(&daddiu.instruction->operands[2]) : nullptr;
    check(daddiu.status == DecodeStatus::decoded && daddiu.instruction &&
              daddiu.instruction->opcode == Opcode::mips64_daddiu &&
              big_immediate && big_immediate->is_signed &&
              static_cast<std::int64_t>(big_immediate->value) == -8 &&
              daddiu.instruction->context.order == ByteOrder::big,
          "big-endian MIPS64 decodes DADDIU with signed immediate and byte order");
    const auto ld = decode_big((0x37u << 26) | (29u << 21) | (16u << 16) | 0xffe0u, 0x1004);
    const auto *memory = ld.instruction && ld.instruction->operands.size() > 1
                             ? std::get_if<MemoryOperand>(&ld.instruction->operands[1]) : nullptr;
    check(ld.status == DecodeStatus::decoded && ld.instruction && ld.instruction->opcode == Opcode::mips64_ld &&
              memory && memory->displacement == -32 && memory->address_width == 64,
          "big-endian MIPS64 decodes LD fields in architectural order");
    const auto branch = decode_big((4u << 26) | (8u << 21) | (9u << 16) | 0xfffeu, 0x1008);
    check(branch.status == DecodeStatus::decoded && branch.instruction &&
              branch.instruction->opcode == Opcode::mips_beq &&
              branch.instruction->direct_target == Address{{0}, 0x1004},
          "big-endian MIPS64 sign extends branch displacement");
}

void n64_cop1_decode() {
    const auto cop1 = [](unsigned fmt, unsigned ft, unsigned fs, unsigned fd, unsigned function) {
        return decode((0x11u << 26) | (fmt << 21) | (ft << 16) | (fs << 11) | (fd << 6) | function);
    };
    const auto add_d = cop1(17, 3, 4, 5, 0);
    check(add_d.status == DecodeStatus::decoded && add_d.instruction &&
              add_d.instruction->opcode == Opcode::mips_add_d &&
              format_instruction(*add_d.instruction) == "add.d f5, f4, f3" &&
              add_d.instruction->register_reads.size() == 3 &&
              add_d.instruction->register_reads[0] == RegisterOperand{RegisterBank::mips_fpr, 4, 64, false} &&
              add_d.instruction->register_reads[2] == RegisterOperand{RegisterBank::mips_fcsr, 0, 32, false} &&
              add_d.instruction->register_writes.size() == 2 &&
              add_d.instruction->register_writes[0] == RegisterOperand{RegisterBank::mips_fpr, 5, 64, false},
          "N64 ADD.D decodes with 64-bit FPR and FCSR effects");

    const auto compare = cop1(16, 6, 7, 0, 0x3c);
    check(compare.status == DecodeStatus::decoded && compare.instruction &&
              compare.instruction->opcode == Opcode::mips_c_lt_s &&
              compare.instruction->register_reads.size() == 3 &&
              compare.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_fcsr, 0, 32, false}},
          "N64 C.LT.S writes the FCSR condition state");

    const auto load = decode((0x35u << 26) | (29u << 21) | (8u << 16) | 0xfff0u);
    check(load.status == DecodeStatus::decoded && load.instruction && load.instruction->opcode == Opcode::mips_ldc1 &&
              load.instruction->memory_read && load.instruction->register_writes ==
                  std::vector<RegisterOperand>{{RegisterBank::mips_fpr, 8, 64, false}},
          "N64 LDC1 retains 64-bit address and FPR effects");
    const auto single_store = decode((0x39u << 26) | (29u << 21) | (9u << 16) | 12u);
    check(single_store.status == DecodeStatus::decoded && single_store.instruction &&
              single_store.instruction->opcode == Opcode::mips_swc1 && single_store.instruction->memory_write &&
              single_store.instruction->register_reads == std::vector<RegisterOperand>{{RegisterBank::mips_fpr, 9, 32, false}},
          "N64 SWC1 reads the 32-bit scalar lane and writes memory");

    const auto branch = decode((0x11u << 26) | (8u << 21) | (1u << 16) | 2u);
    check(branch.status == DecodeStatus::decoded && branch.instruction && branch.instruction->opcode == Opcode::mips_bc1t &&
              branch.instruction->flow == FlowKind::conditional_branch && branch.instruction->delay_slots == 1 &&
              branch.instruction->direct_target == Address{{0}, 0x1'0000'100cULL} &&
              branch.instruction->register_reads == std::vector<RegisterOperand>{{RegisterBank::mips_fcsr, 0, 32, false}},
          "N64 BC1T tests FCC0 and preserves its classic delay slot");
    const auto likely_branch = decode((0x11u << 26) | (8u << 21) | (3u << 16) | 1u);
    check(likely_branch.status == DecodeStatus::decoded && likely_branch.instruction &&
              likely_branch.instruction->opcode == Opcode::mips64_bc1tl &&
              likely_branch.instruction->flow == FlowKind::conditional_branch &&
              likely_branch.instruction->delay_slots == 1 &&
              likely_branch.instruction->direct_target == Address{{0}, 0x1'0000'1008ULL} &&
              likely_branch.instruction->register_reads ==
                  std::vector<RegisterOperand>{{RegisterBank::mips_fcsr, 0, 32, false}},
          "COP1 likely branches decode with FCC state and retain their annulled delay slot");
    const auto unsupported_format = cop1(20, 0, 1, 2, 0);
    check(unsupported_format.status == DecodeStatus::unsupported,
          "N64 COP1 word arithmetic remains unsupported");

    const auto transfer = decode((0x11u << 26) | (0u << 21) | (8u << 16) | (9u << 11)); // MFC1 t0,f9
    check(transfer.status == DecodeStatus::decoded && transfer.instruction &&
              transfer.instruction->opcode == Opcode::mips64_mfc1 &&
              transfer.instruction->register_reads == std::vector<RegisterOperand>{{RegisterBank::mips_fpr, 9, 32, false}} &&
              transfer.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::mips_gpr, 8, 64, false}} &&
              format_instruction(*transfer.instruction) == "mfc1 t0, f9",
          "MFC1 models a 32-bit FPR read and 64-bit GPR destination");
    const auto control = decode((0x11u << 26) | (2u << 21) | (8u << 16) | (31u << 11));
    check(control.status == DecodeStatus::decoded && control.instruction &&
              control.instruction->opcode == Opcode::mips64_cfc1 &&
              control.instruction->register_reads == std::vector<RegisterOperand>{{RegisterBank::mips_fcsr, 0, 32, false}},
          "CFC1 FCSR31 transfer retains typed control-register effects");
    for (const auto &[fmt, expected] : std::array{
             std::pair{1u, Opcode::mips64_dmfc1}, std::pair{4u, Opcode::mips64_mtc1},
             std::pair{5u, Opcode::mips64_dmtc1}, std::pair{6u, Opcode::mips64_ctc1}}) {
        const auto moved = decode((0x11u << 26) | (fmt << 21) | (8u << 16) |
                                  ((fmt == 6 ? 31u : 9u) << 11));
        check(moved.status == DecodeStatus::decoded && moved.instruction && moved.instruction->opcode == expected,
              "MIPS64 COP1 transfer encoding decodes with its operation identity");
    }
    const auto round_long = cop1(16, 0, 4, 5, 0x08);
    check(round_long.status == DecodeStatus::decoded && round_long.instruction &&
              round_long.instruction->opcode == Opcode::mips64_round_l_s &&
              round_long.instruction->register_reads.size() == 2 &&
              round_long.instruction->register_writes[0] == RegisterOperand{RegisterBank::mips_fpr, 5, 64, false},
          "ROUND.L.S decodes as a 64-bit FPR result with FCSR effects");
    const auto cvt_s_l = cop1(21, 0, 4, 5, 0x20);
    const auto cvt_l_d = cop1(17, 0, 4, 5, 0x25);
    const auto cvt_s_w = cop1(20, 0, 4, 5, 0x20);
    check(cvt_s_l.status == DecodeStatus::decoded && cvt_s_l.instruction && cvt_s_l.instruction->opcode == Opcode::mips64_cvt_s_l &&
              cvt_s_l.instruction->register_reads[0].width == 64 && cvt_s_l.instruction->register_writes[0].width == 32 &&
              cvt_l_d.status == DecodeStatus::decoded && cvt_l_d.instruction && cvt_l_d.instruction->opcode == Opcode::mips64_cvt_l_d &&
              cvt_s_w.status == DecodeStatus::decoded && cvt_s_w.instruction && cvt_s_w.instruction->opcode == Opcode::mips_cvt_s_w,
          "COP1 S/D/W/L conversion encodings retain source and destination widths");
}
} // namespace

int main() { return run([] { n64_scalar_decode(); big_endian_mips64_decode(); n64_cop1_decode(); }); }
