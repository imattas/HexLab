#include "hexlab/core/architecture.hpp"
#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
#include "hexlab/processors/riscv.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <type_traits>
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
namespace {
void context_tests() {
    static_assert(static_cast<int>(Architecture::x86) == 1 && static_cast<int>(Architecture::x86_64) == 2);
    static_assert(static_cast<int>(ExecutionMode::x86_32) == 2 && static_cast<int>(ExecutionMode::x86_64) == 3);
    static_assert(static_cast<int>(Architecture::arm64) == 4 && static_cast<int>(Architecture::riscv64) == 5);
    static_assert(static_cast<int>(ExecutionMode::a64) == 6 && static_cast<int>(ExecutionMode::rv64) == 7);
    static_assert(static_cast<int>(ExecutionMode::rv64c) == 8);
    static_assert(static_cast<int>(RegisterBank::riscv_gpr) == static_cast<int>(RegisterBank::arm_flags) + 1);
    static_assert(static_cast<int>(Opcode::rv_lui) == static_cast<int>(Opcode::idiv) + 1);
    static_assert(std::is_trivially_copyable_v<DecodeContext> && std::is_trivially_copyable_v<ProcessorCapabilities>);
    static_assert(noexcept(processor_capabilities(DecodeContext{})));
    check(DecodeContext{}.architecture == Architecture::unknown && DecodeContext{}.mode == ExecutionMode::unknown,
          "hand-constructed instructions have no guessed processor context");
    const DecodeContext x64{Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little};
    auto capability = processor_capabilities(x64);
    check(capability.can_decode && capability.max_instruction_bytes == 15 && !capability.display_name.empty() &&
              capability.reason.empty(),
          "existing x64 context reports immutable decoder capability");
    const auto input = bytes({0x48, 0x89, 0xd8});
    const Address at{{7}, 0x1000};
    auto decoded = decode_instruction(x64, input, at);
    auto legacy = decode_x64(input, at);
    check(decoded.status == DecodeStatus::decoded && decoded.instruction && decoded.instruction->context == x64,
          "dispatch publishes explicit decoder context");
    if (!decoded.instruction || !legacy.instruction)
        return;
    auto &instruction = *decoded.instruction;
    check(instruction.address == at && instruction.length == 3 && instruction.opcode == Opcode::mov &&
              std::get<RegisterOperand>(instruction.operands[0]) == RegisterOperand{RegisterBank::gpr, 0, 64, false} &&
              std::get<RegisterOperand>(instruction.operands[1]) == RegisterOperand{RegisterBank::gpr, 3, 64, false},
          "dispatch matches literal x64 opcode/registers independently of formatter");
    check(instruction.context == legacy.instruction->context &&
              instruction.register_reads == legacy.instruction->register_reads &&
              instruction.register_writes == legacy.instruction->register_writes &&
              format_instruction(instruction) == "mov rax, rbx",
          "source-compatible wrapper keeps existing observable records");
    for (auto context : {DecodeContext{}, DecodeContext{Architecture::x86, ExecutionMode::x86_64, ByteOrder::little},
                         DecodeContext{Architecture::x86_64, ExecutionMode::x86_32, ByteOrder::little},
                         DecodeContext{Architecture::x86, ExecutionMode::unknown, ByteOrder::little},

                         DecodeContext{Architecture::arm, ExecutionMode::x86_64, ByteOrder::little},
                         DecodeContext{Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::big},
                         DecodeContext{static_cast<Architecture>(999), ExecutionMode::x86_64, ByteOrder::little}}) {
        auto unsupported = processor_capabilities(context);
        auto result = decode_instruction(context, input, at);
        check(!unsupported.can_decode && unsupported.max_instruction_bytes == 0 && !unsupported.reason.empty(),
              "unsupported context has a concrete capability reason");
        check(result.status == DecodeStatus::unsupported && !result.instruction && !result.reason.empty(),
              "unsupported context never falls through to x64 byte interpretation");
    }
    auto short_input = decode_instruction(x64, std::span<const std::byte>(input).first(2), at);
    check(short_input.status == DecodeStatus::truncated && !short_input.instruction,
          "dispatch preserves decoder truncation status");
}
void capstone_opaque_tests() {
    const DecodeContext a64{Architecture::arm64, ExecutionMode::a64, ByteOrder::little};
    auto fp = decode_instruction(a64, bytes({0x20, 0x28, 0x22, 0x1e}), {{0}, 0x2000});
    check(fp.status == DecodeStatus::decoded && fp.instruction && fp.instruction->opcode == Opcode::a64_fadd &&
              fp.instruction->length == 4 && fp.instruction->operands.size() == 3 &&
              std::any_of(fp.instruction->register_writes.begin(), fp.instruction->register_writes.end(),
                  [](RegisterOperand reg) { return reg.bank == RegisterBank::arm64_simd && reg.width == 32; }) &&
              std::any_of(fp.instruction->register_writes.begin(), fp.instruction->register_writes.end(),
                  [](RegisterOperand reg) { return reg.bank == RegisterBank::arm64_simd && reg.width == 128; }) &&
              fp.instruction->flow == FlowKind::fallthrough && format_instruction(*fp.instruction).starts_with("fadd"),
          "A64 scalar FADD uses typed SIMD operands and a 32-bit destination");
    const DecodeContext rv64{Architecture::riscv64, ExecutionMode::rv64, ByteOrder::little};
    auto rv_fp = decode_instruction(rv64, bytes({0xd3, 0x00, 0x31, 0x00}), {{0}, 0x3000});
    check(rv_fp.status == DecodeStatus::decoded && rv_fp.instruction && rv_fp.instruction->opcode == Opcode::rv_fadd_s &&
              rv_fp.instruction->length == 4 && rv_fp.instruction->operands.size() == 3 &&
              rv_fp.instruction->flow == FlowKind::fallthrough && format_instruction(*rv_fp.instruction).starts_with("fadd.s"),
          "RISC-V scalar FP dispatch uses native typed semantics instead of the opaque fallback");
    const DecodeContext mips{Architecture::mips32, ExecutionMode::mips32, ByteOrder::little};
    // MFC1 is a typed COP1 transfer with an integer destination and FPR source.
    auto mips_fp = decode_instruction(mips, bytes({0x00, 0x08, 0x02, 0x44}), {{0}, 0x4000});
    check(mips_fp.status == DecodeStatus::decoded && mips_fp.instruction && mips_fp.instruction->opcode == Opcode::mips_mfc1 &&
              mips_fp.instruction->length == 4 && mips_fp.instruction->operands.size() == 2 &&
              mips_fp.instruction->register_writes == std::vector{RegisterOperand{RegisterBank::mips_gpr, 2, 32, false}} &&
              format_instruction(*mips_fp.instruction).starts_with("mfc1"),
          "MIPS32 MFC1 preserves its integer destination and FPR source effects");
}

void m6502_tests() {
    const DecodeContext mode{Architecture::mos6502, ExecutionMode::m6502, ByteOrder::little};
    const auto cap = processor_capabilities(mode);
    check(cap.can_decode && cap.max_instruction_bytes == 3 && cap.display_name == "MOS 6502 scalar subset",
          "6502 decoder advertises its classic NMOS mode and maximum instruction size");
    const auto lda = bytes({0xa9, 0x42});
    auto decoded = decode_instruction(mode, lda, {{3}, 0x8000});
    check(decoded.instruction && decoded.instruction->opcode == Opcode::m6502_lda &&
              decoded.instruction->length == 2 && decoded.instruction->register_writes ==
                  std::vector<RegisterOperand>{{RegisterBank::mos6502, 0, 8, false},
                                                {RegisterBank::mos6502, 3, 8, false}} &&
              format_instruction(*decoded.instruction) == "lda #0x42",
          "6502 immediate load decodes with A write effect and stable syntax");
    const auto ldx = bytes({0xb6, 0xf0});
    decoded = decode_instruction(mode, ldx, {{3}, 0x8002});
    check(decoded.instruction && decoded.instruction->length == 2 && decoded.instruction->memory_read &&
              decoded.instruction->register_writes == std::vector<RegisterOperand>{{RegisterBank::mos6502, 1, 8, false},
                                                                                   {RegisterBank::mos6502, 3, 8, false}} &&
              format_instruction(*decoded.instruction) == "ldx 0xf0, y",
          "6502 zero-page indexed load models its implicit index register");
    const auto branch_bytes = bytes({0xd0, 0xfc});
    decoded = decode_instruction(mode, branch_bytes, {{3}, 0x8004});
    check(decoded.instruction && decoded.instruction->flow == FlowKind::conditional_branch &&
              decoded.instruction->direct_target == Address{{3}, 0x8002} &&
              format_instruction(*decoded.instruction) == "bne 0x8002",
          "6502 signed relative branch resolves from the following instruction");
    const auto unofficial_nop = decode_instruction(mode, bytes({0x80, 0x00}), {{3}, 0});
    check(unofficial_nop.instruction && unofficial_nop.instruction->opcode == Opcode::nop &&
              unofficial_nop.instruction->length == 2,
          "NMOS immediate unofficial NOP is distinguished from the 65C02 BRA encoding");
    check(decode_instruction(mode, bytes({0xa9}), {{3}, 0}).status == DecodeStatus::truncated,
          "6502 immediate truncation is distinguished from invalid opcodes");
    const auto jmp = decode_instruction(mode, bytes({0x4c, 0x34, 0x12}), {{3}, 0xfffc});
    check(jmp.instruction && jmp.instruction->flow == FlowKind::jump &&
              jmp.instruction->direct_target == Address{{3}, 0x1234} &&
              format_instruction(*jmp.instruction) == "jmp 0x1234",
          "6502 absolute jump carries direct control-flow target");
    std::array<std::uint8_t, 256> length{};
    for (const auto op : {0x00,0x08,0x0a,0x18,0x28,0x2a,0x38,0x40,0x48,0x4a,0x58,0x60,0x68,0x6a,
                          0x78,0x88,0x8a,0x98,0x9a,0xa8,0xaa,0xb8,0xba,0xc8,0xca,0xd8,0xe8,0xea,0xf8})
        length[op] = 1;
    for (const auto op : {0x01,0x05,0x06,0x09,0x10,0x11,0x15,0x16,0x21,0x24,0x25,0x26,0x29,0x30,
                          0x31,0x35,0x36,0x41,0x45,0x46,0x49,0x50,0x51,0x55,0x56,0x61,0x65,0x66,
                          0x69,0x70,0x71,0x75,0x76,0x81,0x84,0x85,0x86,0x90,0x91,0x94,0x95,0x96,
                          0xa0,0xa1,0xa2,0xa4,0xa5,0xa6,0xa9,0xb0,0xb1,0xb4,0xb5,0xb6,0xc0,0xc1,
                          0xc4,0xc5,0xc6,0xc9,0xd0,0xd1,0xd5,0xd6,0xe0,0xe1,0xe4,0xe5,0xe6,0xe9,
                          0xf0,0xf1,0xf5,0xf6})
        length[op] = 2;
    for (const auto op : {0x0d,0x0e,0x19,0x1d,0x1e,0x20,0x2c,0x2d,0x2e,0x39,0x3d,0x3e,0x4c,0x4d,
                          0x4e,0x59,0x5d,0x5e,0x6c,0x6d,0x6e,0x79,0x7d,0x7e,0x8c,0x8d,0x8e,0x99,
                          0x9d,0xac,0xad,0xae,0xb9,0xbc,0xbd,0xbe,0xcc,0xcd,0xce,0xd9,0xdd,0xde,
                          0xec,0xed,0xee,0xf9,0xfd,0xfe})
        length[op] = 3;
    check(std::count_if(length.begin(), length.end(), [](auto n) { return n != 0; }) == 151,
          "literal 6502 opcode matrix contains all 151 official NMOS instructions");
    for (unsigned op = 0; op != 256; ++op) {
        if (!length[op]) continue;
        const auto encoded = bytes({op, 0x34, 0x12});
        auto result = decode_instruction(mode, encoded, {{3}, 0x8000});
        check(result.instruction && result.instruction->length == length[op],
              "every official NMOS opcode decodes with its documented instruction length");
        if (length[op] > 1)
            check(decode_instruction(mode, std::span<const std::byte>(encoded).first(length[op] - 1),
                                     {{3}, 0x8000}).status == DecodeStatus::truncated,
                  "every multibyte official opcode reports truncation at its final missing byte");
    }
    decoded = decode_instruction(mode, bytes({0x61, 0x44}), {{3}, 0x1000});
    check(decoded.instruction && decoded.instruction->opcode == Opcode::m6502_adc &&
              decoded.instruction->memory_read && decoded.instruction->register_reads ==
                  std::vector<RegisterOperand>{{RegisterBank::mos6502, 1, 8, false},
                                               {RegisterBank::mos6502, 0, 8, false},
                                               {RegisterBank::mos6502, 3, 8, false}} &&
              decoded.instruction->register_writes ==
                  std::vector<RegisterOperand>{{RegisterBank::mos6502, 0, 8, false},
                                               {RegisterBank::mos6502, 3, 8, false}} &&
              format_instruction(*decoded.instruction) == "adc (0x44, x)",
          "ADC indexed-indirect models pointer, accumulator, carry and result flags");
    decoded = decode_instruction(mode, bytes({0x91, 0x44}), {{3}, 0x1000});
    check(decoded.instruction && decoded.instruction->memory_read && decoded.instruction->memory_write &&
              decoded.instruction->register_reads ==
                  std::vector<RegisterOperand>{{RegisterBank::mos6502, 2, 8, false},
                                               {RegisterBank::mos6502, 0, 8, false}} &&
              format_instruction(*decoded.instruction) == "sta (0x44), y",
          "STA indirect-indexed preserves pointer read, indexed register dependency and memory write");
    decoded = decode_instruction(mode, bytes({0x0a}), {{3}, 0x1000});
    check(decoded.instruction && decoded.instruction->register_reads ==
              std::vector<RegisterOperand>{{RegisterBank::mos6502, 0, 8, false},
                                           {RegisterBank::mos6502, 3, 8, false}} &&
              decoded.instruction->register_writes ==
              std::vector<RegisterOperand>{{RegisterBank::mos6502, 0, 8, false},
                                           {RegisterBank::mos6502, 3, 8, false}} &&
              format_instruction(*decoded.instruction) == "asl a",
          "accumulator shift records A and preserves unaffected processor-status bits");
    decoded = decode_instruction(mode, bytes({0x6c, 0x34, 0x12}), {{3}, 0x1000});
    check(decoded.instruction && decoded.instruction->flow == FlowKind::jump &&
              !decoded.instruction->direct_target && decoded.instruction->memory_read &&
              format_instruction(*decoded.instruction) == "jmp (0x1234)",
          "indirect JMP retains an unresolved pointer and the NMOS page-wrap case is not fabricated");
    const auto unofficial = decode_instruction(mode, bytes({0x03, 0x44}), {{3}, 0x1000});
    check(unofficial.instruction && unofficial.instruction->opcode == Opcode::m6502_slo &&
              format_instruction(*unofficial.instruction).starts_with("slo"),
          "implemented NMOS SLO retains its combined unofficial-opcode identity");
    const std::array<std::pair<unsigned, const char *>, 8> addressing_forms{{
        {0x01, "ora (0x34, x)"}, {0x05, "ora 0x34"}, {0x09, "ora #0x34"}, {0x0d, "ora 0x1234"},
        {0x11, "ora (0x34), y"}, {0x15, "ora 0x34, x"}, {0x19, "ora 0x1234, y"}, {0x1d, "ora 0x1234, x"}}};
    for (const auto &[opcode, expected] : addressing_forms) {
        decoded = decode_instruction(mode, bytes({opcode, 0x34, 0x12}), {{3}, 0x1000});
        check(decoded.instruction && format_instruction(*decoded.instruction) == expected,
              "regular NMOS ALU group formats each of its eight addressing modes");
    }
}
void riscv_dispatch_tests() {
    const DecodeContext rv64{Architecture::riscv64, ExecutionMode::rv64, ByteOrder::little};
    const auto capability = processor_capabilities(rv64);
    check(capability.can_decode && capability.max_instruction_bytes == 4,
          "RV64 context advertises the bounded fixed-width decoder");
    const auto addi = bytes({0x93, 0x00, 0x50, 0x00}); // addi x1, x0, 5
    const auto decoded = decode_instruction(rv64, addi, {{0}, 0x1000});
    check(decoded.status == DecodeStatus::decoded && decoded.instruction &&
              decoded.instruction->context == rv64 && decoded.instruction->opcode == Opcode::rv_addi &&
              decoded.instruction->register_writes == std::vector{RegisterOperand{RegisterBank::riscv_gpr, 1, 64, false}} &&
              format_instruction(*decoded.instruction) == "addi x1, x0, 0x5",
          "generic decode dispatch adapts RV64I facts and canonical assembly formatting");
    const auto csrrw = decode_instruction(rv64, bytes({0xf3, 0x12, 0x03, 0x30}), {{0}, 0x1000});
    check(csrrw.instruction && csrrw.instruction->opcode == Opcode::rv_csrrw && csrrw.instruction->csr_read &&
              csrrw.instruction->csr_write &&
              format_instruction(*csrrw.instruction) == "csrrw x5, mstatus, x6",
          "generic RV64 dispatch preserves Zicsr identity, effects, and canonical CSR operand formatting");
    const auto csrrsi = decode_instruction(rv64, bytes({0xf3, 0x62, 0x00, 0xc0}), {{0}, 0x1004});
    check(csrrsi.instruction && csrrsi.instruction->opcode == Opcode::rv_csrrsi &&
              csrrsi.instruction->csr_read && !csrrsi.instruction->csr_write,
          "generic dispatch preserves CSRRSI zero-mask read-only semantics");
    check(csrrsi.instruction && format_instruction(*csrrsi.instruction) == "csrrsi x5, 0xc00, 0x0",
          "RISC-V formatter preserves CSR address and unsigned zimm syntax");
    const auto branch = bytes({0x63, 0x84, 0x20, 0x00}); // beq x1, x2, +8
    const auto branch_result = decode_instruction(rv64, branch, {{0}, 0x1000});
    check(branch_result.instruction && branch_result.instruction->flow == FlowKind::conditional_branch &&
              branch_result.instruction->direct_target == Address{{0}, 0x1008} &&
              format_instruction(*branch_result.instruction) == "beq x1, x2, 0x1008",
          "generic RV64 conditional branch preserves flow and target facts");
    const auto mulw = bytes({0xbb, 0x00, 0x31, 0x02}); // mulw x1, x2, x3
    const auto mulw_result = decode_instruction(rv64, mulw, {{0}, 0x1004});
    check(mulw_result.instruction && mulw_result.instruction->opcode == Opcode::rv_mulw &&
              format_instruction(*mulw_result.instruction) == "mulw x1, x2, x3",
          "generic RV64 mapping covers the M extension word-opcode tail");
    const auto lr_w = decode_instruction(rv64, bytes({0xaf, 0x22, 0x02, 0x14}), {{0}, 0x1008});
    check(lr_w.instruction && lr_w.instruction->opcode == Opcode::rv_lr_w && lr_w.instruction->atomic_aq &&
              !lr_w.instruction->atomic_rl && lr_w.instruction->memory_read && !lr_w.instruction->memory_write,
          "generic dispatch preserves LR.W acquire and memory-read effects");
    check(lr_w.instruction && format_instruction(*lr_w.instruction) == "lr.w.aq x5, 0x0(x4)",
          "RISC-V formatter emits standard LR.W acquire syntax without x86 memory qualifiers");
    const auto sc_d = decode_instruction(rv64, bytes({0xaf, 0x32, 0x73, 0x1e}), {{0}, 0x100c});
    check(sc_d.instruction && sc_d.instruction->opcode == Opcode::rv_sc_d && sc_d.instruction->atomic_aq &&
              sc_d.instruction->atomic_rl && !sc_d.instruction->memory_read && sc_d.instruction->memory_write,
          "generic dispatch preserves SC.D aq/rl ordering and store-conditional effects");
    check(sc_d.instruction && format_instruction(*sc_d.instruction) == "sc.d.aqrl x5, x7, 0x0(x6)",
          "RISC-V formatter preserves sequentially consistent SC.D ordering and operand order");
    check(decode_instruction(rv64, std::span<const std::byte>(addi).first(3), {{0}, 0}).status == DecodeStatus::truncated,
          "generic RV64 dispatch preserves truncated instruction status");
    const DecodeContext rv32{Architecture::riscv32, ExecutionMode::rv32, ByteOrder::little};
    const auto rv32_addi = decode_instruction(rv32, addi, {{0}, 0x1000});
    check(processor_capabilities(rv32).can_decode && rv32_addi.instruction &&
              rv32_addi.instruction->register_writes ==
                  std::vector{RegisterOperand{RegisterBank::riscv_gpr, 1, 32, false}} &&
              format_instruction(*rv32_addi.instruction) == "addi x1, x0, 0x5",
          "RV32I dispatch preserves 32-bit register width while sharing canonical x-register names");
    const auto rv32_branch = decode_instruction(rv32, branch, {{0}, 0x1000});
    check(rv32_branch.instruction && rv32_branch.instruction->direct_target == Address{{0}, 0x1008},
          "RV32I branch target enters the common control-flow pipeline");
    const auto rv32_mul = decode_instruction(rv32, bytes({0xb3, 0x00, 0x31, 0x02}), {{0}, 0x1000});
    check(rv32_mul.instruction && rv32_mul.instruction->opcode == Opcode::rv_mul &&
              decode_instruction(rv32, bytes({0x03, 0x30, 0x00, 0x00}), {{0}, 0x1000}).status == DecodeStatus::invalid,
          "RV32IM exposes generic multiply semantics while rejecting RV64-only LD");
    const auto rv32_csrrw = decode_instruction(rv32, bytes({0xf3, 0x12, 0x03, 0x30}), {{0}, 0x1000});
    check(rv32_csrrw.instruction && rv32_csrrw.instruction->opcode == Opcode::rv_csrrw &&
              rv32_csrrw.instruction->register_writes ==
                  std::vector{RegisterOperand{RegisterBank::riscv_gpr, 5, 32, false}} &&
              rv32_csrrw.instruction->csr_read && rv32_csrrw.instruction->csr_write,
          "RV32 dispatch preserves CSR operations with XLEN-sized integer effects");
    const auto rv32_load = decode_instruction(rv32, bytes({0x83, 0x20, 0x00, 0x00}), {{0}, 0x1000});
    const auto *rv32_memory = rv32_load.instruction && rv32_load.instruction->operands.size() > 1
                                  ? std::get_if<MemoryOperand>(&rv32_load.instruction->operands[1])
                                  : nullptr;
    check(rv32_memory && rv32_memory->address_width == 32 && rv32_memory->base &&
              rv32_memory->base->width == 32,
          "RV32I memory operands retain a 32-bit address width and base register");
    check(decode_instruction(rv32, bytes({0x93, 0x10, 0xf0, 0x01}), {{0}, 0x1000}).instruction.has_value() &&
              decode_instruction(rv32, bytes({0x93, 0x10, 0xf0, 0x21}), {{0}, 0x1000}).status == DecodeStatus::invalid,
          "RV32I shift-immediate accepts five-bit shamt and rejects reserved upper encoding bits");
    const DecodeContext rv64c{Architecture::riscv64, ExecutionMode::rv64c, ByteOrder::little};
    const auto compressed = bytes({0x01, 0x00});
    const auto c_nop = decode_instruction(rv64c, compressed, {{0}, 0x1002});
    const auto rv64c_csrrw = decode_instruction(rv64c, bytes({0xf3, 0x12, 0x03, 0x30}), {{0}, 0x1004});
    check(rv64c_csrrw.instruction && rv64c_csrrw.instruction->opcode == Opcode::rv_csrrw &&
              rv64c_csrrw.instruction->length == 4,
          "Zicsr remains available alongside compressed RV64C dispatch");
    check(c_nop.instruction && c_nop.instruction->length == 2 && c_nop.instruction->opcode == Opcode::rv_addi &&
              c_nop.instruction->context == rv64c && format_instruction(*c_nop.instruction) == "addi x0, x0, 0x0",
          "RV64IC dispatch decodes and formats two-byte instructions at halfword alignment");
}
void x64_canaries() {
    const DecodeContext mode{Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little};
    auto decode = [&](std::initializer_list<unsigned> values, Address at = Address{{0}, 0x1000}) {
        auto input = bytes(values);
        auto result = decode_instruction(mode, input, at);
        check(result.status == DecodeStatus::decoded && result.instruction &&
                  result.instruction->length == input.size(),
              "mode-refactor canary has exact original x64 length");
        if (!result.instruction)
            throw std::runtime_error(result.reason);
        check(result.instruction->context == mode, "every original scalar path retains the explicit x64 context");
        return *result.instruction;
    };
    auto before = decode({0x40, 0x66, 0x88, 0xe0});
    auto after = decode({0x66, 0x40, 0x88, 0xe0});
    check(std::get<RegisterOperand>(before.operands[1]) == RegisterOperand{RegisterBank::gpr, 0, 8, true} &&
              std::get<RegisterOperand>(after.operands[1]) == RegisterOperand{RegisterBank::gpr, 4, 8, false},
          "legacy prefix after REX restores AH while final REX selects SPL");
    auto address_override = decode({0x67, 0x48, 0x8b, 0x05, 0x10, 0, 0, 0});
    auto memory = std::get<MemoryOperand>(address_override.operands[1]);
    check(memory.data_width == 64 && memory.address_width == 32 && memory.ip_relative &&
              memory.base == RegisterOperand{RegisterBank::ip, 0, 32, false} &&
              memory.resolved_address == Address{{0}, 0x1018},
          "x64 address override keeps final-end EIP-relative resolution");
    auto no_base = decode({0x48, 0x8b, 0x04, 0x25, 0xff, 0xff, 0xff, 0xff});
    memory = std::get<MemoryOperand>(no_base.operands[1]);
    check(!memory.base && !memory.index && !memory.ip_relative && memory.displacement == -1 &&
              memory.resolved_address == Address{{0}, UINT64_MAX},
          "x64 no-base SIB sign extends displacement without inventing IP");
    auto immediate = decode({0x48, 0x83, 0xc0, 0xff});
    auto value = std::get<ImmediateOperand>(immediate.operands[1]);
    check(value.encoded_width == 8 && value.effective_width == 64 && value.value == UINT64_MAX && value.is_signed,
          "x64 signed immediate retains encoded and effective widths");
    auto push = decode({0x66, 0x50});
    check(std::get<RegisterOperand>(push.operands[0]).width == 16 && push.memory_write &&
              std::find(push.register_reads.begin(), push.register_reads.end(),
                        RegisterOperand{RegisterBank::gpr, 4, 64, false}) != push.register_reads.end(),
          "x64 16-bit push operand does not shrink its stack pointer");
    auto call = decode({0x66, 0xe8, 0xfb, 0xff, 0xff, 0xff});
    check(call.flow == FlowKind::call && call.direct_target == Address{{0}, 0x1001} &&
              std::get<RelativeOperand>(call.operands[0]).encoded_width == 32,
          "x64 near call keeps rel32 with operand-size override");
    auto locked = decode({0xf0, 0x48, 0x01, 0x08});
    check(locked.lock_prefix && locked.memory_read && locked.memory_write && locked.opcode == Opcode::add,
          "x64 lock remains typed memory read/write metadata");
    auto end = decode({0xe9, 0, 0, 0, 0}, Address{{0}, UINT64_MAX - 3});
    check(!end.direct_target, "x64 overflowing instruction end never fabricates a target");
    auto moffs = decode({0x48, 0xa1, 0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
    memory = std::get<MemoryOperand>(moffs.operands[1]);
    check(memory.data_width == 64 && memory.address_width == 64 && !memory.ip_relative &&
              memory.resolved_address == Address{{0}, UINT64_C(0xfffffffffffffff0)},
          "moffs64 retains the entire unsigned absolute offset");
    moffs = decode({0x67, 0xa3, 0, 0, 0, 0x80});
    memory = std::get<MemoryOperand>(moffs.operands[0]);
    check(moffs.memory_write && memory.data_width == 32 && memory.address_width == 32 &&
              memory.resolved_address == Address{{0}, 0x80000000},
          "moffs32 address override is unsigned and never IP-relative");
    auto explicit_stack = mode;
    explicit_stack.stack_address_width = 64;
    auto explicit_push = decode_instruction(explicit_stack, bytes({0x50}), {{0}, 0x1000});
    auto default_push = decode({0x50});
    check(explicit_push.instruction && explicit_push.instruction->context == explicit_stack &&
              explicit_push.instruction->register_reads == default_push.register_reads &&
              explicit_push.instruction->register_writes == default_push.register_writes,
          "explicit legal long stack width preserves default effects");
}
void segmented32_tests() {
    DecodeContext flat{Architecture::x86, ExecutionMode::x86_32, ByteOrder::little};
    auto segmented = flat;
    segmented.segmented_memory = true;
    auto raw = bytes({0x8b, 0x05, 0, 0x20, 0, 0});
    auto a = decode_instruction(flat, raw, {{7}, 0x1000});
    auto b = decode_instruction(segmented, raw, {{7}, 0x1000});
    check(a.instruction && b.instruction, "flat and segmented32 share opcode decoding");
    if (!a.instruction || !b.instruction)
        return;
    const auto &ma = std::get<MemoryOperand>(a.instruction->operands[1]);
    const auto &mb = std::get<MemoryOperand>(b.instruction->operands[1]);
    check(ma.resolved_address == Address{{7}, 0x2000} && !ma.segment,
          "existing flat32 absolute address remains compatible");
    check(!mb.resolved_address && mb.segment == RegisterOperand{RegisterBank::segment, 3, 16, false},
          "segmented32 absolute offset needs an unproved DS value");
    auto bp = decode_instruction(segmented, bytes({0x8b, 0x45, 0}), {{7}, 0x1000});
    check(bp.instruction && std::get<MemoryOperand>(bp.instruction->operands[1]).segment ==
                                RegisterOperand{RegisterBank::segment, 2, 16, false},
          "segmented32 EBP base uses SS");
    auto short_stack = flat;
    short_stack.stack_address_width = 16;
    auto plain = decode_instruction(short_stack, raw, {{7}, 0x1000});
    check(plain.instruction &&
              std::get<MemoryOperand>(plain.instruction->operands[1]).resolved_address == ma.resolved_address,
          "SS.B alone does not change the data addressing model");
    auto invalid = DecodeContext{Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little};
    invalid.segmented_memory = true;
    check(!processor_capabilities(invalid).can_decode, "legacy segmentation is not a long-mode address model");
}
} // namespace
int main() {
    return run([] {
        context_tests();
        capstone_opaque_tests();
        m6502_tests();
        riscv_dispatch_tests();
        x64_canaries();
        segmented32_tests();
    });
}
