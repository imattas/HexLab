#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
#include "support/checks.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <iostream>
using namespace hexlab;
using namespace hexlab_test;
namespace {
constexpr DecodeContext context{Architecture::arm64, ExecutionMode::a64, ByteOrder::little};
constexpr RegisterBank gpr = RegisterBank::arm64_gpr, sp = RegisterBank::arm64_sp, zero = RegisterBank::arm64_zero,
                       flags = RegisterBank::arm_flags;
RegisterOperand reg(unsigned index, unsigned width = 64, RegisterBank bank = gpr) {
    return {bank, static_cast<std::uint8_t>(index), static_cast<std::uint16_t>(width), false};
}
std::array<std::byte, 4> bytes(std::uint32_t word) {
    return {std::byte(word), std::byte(word >> 8), std::byte(word >> 16), std::byte(word >> 24)};
}
template <class F> void decoded(std::uint32_t word, F assertions, Address at = {{7}, 0x1000}) {
    const auto source = bytes(word);
    const auto result = decode_instruction(context, source, at);
    check(result.status == DecodeStatus::decoded && result.instruction.has_value(), "literal A64 word decodes");
    if (!result.instruction)
        return;
    const auto &i = *result.instruction;
    check(i.length == 4 && i.address == at && i.context == context &&
              std::equal(source.begin(), source.end(), i.bytes.begin()),
          "exact A64 source/context retained");
    for (unsigned n = 0; n < 4; ++n)
        check(decode_instruction(context, std::span(source).first(n), at).status == DecodeStatus::truncated,
              "every incomplete fixed-width instruction is truncated");
    assertions(i);
}
bool has(const std::vector<RegisterOperand> &values, RegisterOperand value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}
void flow() {
    for (auto word : {0x5400004eu, 0x5400004fu})
        decoded(word, [](const auto &i) {
            check(i.flow == FlowKind::jump && i.register_reads.empty(),
                  "ARM AL/NV branch conditions are always true and do not create a false fallthrough");
            check(opcode_name(i.opcode, i.condition) == (i.condition == 14 ? "b.al" : "b.nv"),
                  "public opcode name uses architecture-specific condition spelling");
        });
    decoded(0x14000002, [](const auto &i) {
        check(i.flow == FlowKind::jump && i.direct_target == Address{{7}, 0x1008} &&
                  format_instruction(i) == "b 0x1008",
              "B uses instruction PC, domain and scaled immediate");
        const auto &operand = std::get<RelativeOperand>(i.operands[0]);
        check(operand.displacement == 8 && operand.encoded_width == 26 && !operand.encoding,
              "packed branch bits do not invent a contiguous byte field");
    });
    decoded(0x97ffffff, [](const auto &i) {
        check(i.flow == FlowKind::call && i.direct_target == Address{{7}, 0xffc} && has(i.register_writes, reg(30)) &&
                  !i.stack_value_width && !i.memory_write && format_instruction(i) == "bl 0xffc",
              "BL negative target writes LR without x86 stack effects");
    });
    decoded(0x54ffffe1, [](const auto &i) {
        check(i.flow == FlowKind::conditional_branch && i.condition == 1 && i.direct_target == Address{{7}, 0xffc} &&
                  has(i.register_reads, reg(0, 4, flags)) && format_instruction(i) == "b.ne 0xffc",
              "B.cond uses ARM predicate and NZCV");
    });
    decoded(0xb4000040, [](const auto &i) {
        check(i.flow == FlowKind::conditional_branch && i.direct_target == Address{{7}, 0x1008} &&
                  i.register_reads == std::vector{reg(0)} && format_instruction(i) == "cbz x0, 0x1008",
              "CBZ reads tested register rather than flags");
    });
    decoded(0x37280041, [](const auto &i) {
        check(i.direct_target == Address{{7}, 0x1008} && format_instruction(i) == "tbnz w1, #0x5, 0x1008",
              "test-bit branch preserves bit and target");
    });
    decoded(0xd61f0060, [](const auto &i) {
        check(i.flow == FlowKind::jump && !i.direct_target && i.register_reads == std::vector{reg(3)} &&
                  format_instruction(i) == "br x3",
              "BR remains indirect");
    });
    decoded(0xd63f0080, [](const auto &i) {
        check(i.flow == FlowKind::call && !i.direct_target && has(i.register_writes, reg(30)) &&
                  has(i.register_reads, reg(4)),
              "BLR records source and link register separately");
    });
    decoded(0xd65f03c0, [](const auto &i) {
        check(i.flow == FlowKind::ret && !i.direct_target && i.register_reads == std::vector{reg(30)} &&
                  format_instruction(i) == "ret x30",
              "RET retains its explicit register without stack reads");
    });
    decoded(0xd4202460, [](const auto &i) {
        check(i.flow == FlowKind::trap && format_instruction(i) == "brk #0x123", "BRK retains immediate");
    });
    decoded(0xd503201f, [](const auto &i) { check(format_instruction(i) == "nop", "exact architectural NOP"); });
    decoded(0x14000001, [](const auto &i) { check(!i.direct_target, "overflowing branch does not wrap"); },
            {{7}, UINT64_MAX - 3});
    for (auto word : {0x14000000u, 0x15ffffffu, 0x16000000u, 0x17ffffffu})
        decoded(word, [](const auto &i) { check(i.flow == FlowKind::jump, "branch signed immediate boundaries"); });
}
void data() {
    decoded(0xd3483c20, [](const auto &i) {
        check(i.opcode == Opcode::a64_ubfm && format_instruction(i) == "ubfx x0, x1, #0x8, #0x8" &&
                  i.operands.size() == 4 && i.register_reads == std::vector{reg(1)} &&
                  i.register_writes == std::vector{reg(0)},
              "UBFM contiguous extraction is decoded with width and effects");
    });
    decoded(0xd348fc20, [](const auto &i) {
        check(i.opcode == Opcode::a64_ubfm && format_instruction(i) == "lsr x0, x1, #0x8",
              "UBFM LSR alias preserves the encoded shift");
    });
    decoded(0xd378dc20, [](const auto &i) {
        check(i.opcode == Opcode::a64_ubfm && format_instruction(i) == "lsl x0, x1, #0x8",
              "UBFM LSL alias recognizes wrapped bitfield bounds");
    });
    decoded(0x93442c62, [](const auto &i) {
        check(i.opcode == Opcode::a64_sbfm && format_instruction(i) == "sbfx x2, x3, #0x4, #0x8",
              "SBFM contiguous extraction is decoded with signed alias");
    });
    for (auto word : {0x5300fc20u, 0xd320fc20u, 0xb3403c20u}) {
        const auto source = bytes(word);
        const auto result = decode_instruction(context, source, {{7}, 0x1000});
        check(!result.instruction || (result.instruction->opcode != Opcode::a64_sbfm &&
                                      result.instruction->opcode != Opcode::a64_ubfm),
              "invalid width bounds and unimplemented BFM do not acquire bitfield semantics");
    }
    decoded(0xd2824680, [](const auto &i) {
        check(format_instruction(i) == "movz x0, #0x1234" && i.register_writes == std::vector{reg(0)} &&
                  i.register_reads.empty(),
              "MOVZ register and immediate effects");
    });
    decoded(0xf2b579a1, [](const auto &i) {
        check(format_instruction(i) == "movk x1, #0xabcd, lsl #0x10" && i.access[0] == OperandAccess::read_write &&
                  i.register_reads == std::vector{reg(1)} && i.register_writes == std::vector{reg(1)},
              "MOVK preserves destination bits");
    });
    decoded(0x12800002, [](const auto &i) {
        check(format_instruction(i) == "movn w2, #0x0" && i.register_writes == std::vector{reg(2, 32)},
              "MOVN W destination identity");
    });
    decoded(0x910043e0, [](const auto &i) {
        check(format_instruction(i) == "add x0, sp, #0x10" && i.register_reads == std::vector{reg(31, 64, sp)} &&
                  i.register_writes == std::vector{reg(0)},
              "ADD source31 is SP");
    });
    decoded(0xf100041f, [](const auto &i) {
        check(format_instruction(i) == "subs xzr, x0, #0x1" && i.register_writes == std::vector{reg(0, 4, flags)},
              "SUBS destination31 is zero; NZCV is state");
    });
    decoded(0x9140041f, [](const auto &i) {
        check(format_instruction(i) == "add sp, x0, #0x1000" && i.register_writes == std::vector{reg(31, 64, sp)},
              "ADD shift12 and destination SP");
    });
    decoded(0x10000040, [](const auto &i) {
        const auto *m = std::get_if<MemoryOperand>(&i.operands[1]);
        check(m && m->resolved_address == Address{{7}, 0x1008} && m->displacement == 8 && m->ip_relative &&
                  i.access[1] == OperandAccess::address && !i.memory_read && !i.direct_target &&
                  format_instruction(i) == "adr x0, #0x1008",
              "ADR computes current-PC address");
    });
    decoded(0xf0ffffe1,
            [](const auto &i) {
                const auto *m = std::get_if<MemoryOperand>(&i.operands[1]);
                check(m && m->resolved_address == Address{{7}, 0} && m->displacement == -4096 &&
                          format_instruction(i) == "adrp x1, #0x0",
                      "ADRP negative offset uses page-aligned PC");
            },
            {{7}, 0x1ffc});
    decoded(0x10ffffe0,
            [](const auto &i) {
                const auto *m = std::get_if<MemoryOperand>(&i.operands[1]);
                check(m && !m->resolved_address && m->displacement == -4 && i.access[1] == OperandAccess::address &&
                          !i.direct_target && !i.memory_read,
                      "ADR underflow retains source-relative calculation without inventing target");
            },
            {{7}, 0});
    decoded(0xb0000000,
            [](const auto &i) {
                const auto *m = std::get_if<MemoryOperand>(&i.operands[1]);
                check(m && !m->resolved_address && m->displacement == 4096 && !i.direct_target,
                      "ADRP overflow remains decoded with unavailable computed address");
            },
            {{7}, UINT64_MAX - 3});
    decoded(0xf9400fe0, [](const auto &i) {
        const auto &m = std::get<MemoryOperand>(i.operands[1]);
        check(m.base == reg(31, 64, sp) && m.data_width == 64 && m.displacement == 24 && !m.displacement_encoding &&
                  i.memory_read && !i.memory_write && format_instruction(i) == "ldr x0, [sp, #0x18]",
              "LDR scaled offset and SP address");
    });
    decoded(0x3900043f, [](const auto &i) {
        const auto &m = std::get<MemoryOperand>(i.operands[1]);
        check(m.base == reg(1) && m.data_width == 8 && m.displacement == 1 && i.memory_write &&
                  !has(i.register_reads, reg(31, 32, zero)) && format_instruction(i) == "strb wzr, [x1, #0x1]",
              "STRB zero register is constant, not SP or writable state");
    });
    for (unsigned width : {32, 64})
        for (unsigned rd = 0; rd < 32; ++rd)
            for (unsigned immediate : {0, 1, 4095})
                decoded((width == 64 ? 0x91000000u : 0x11000000u) | (immediate << 10) | (rd << 5) | rd,
                        [=](const auto &i) {
                            check(std::get<RegisterOperand>(i.operands[0]) == reg(rd, width, rd == 31 ? sp : gpr) &&
                                      std::get<ImmediateOperand>(i.operands[2]).value == immediate,
                                  "ADD register31/width/immediate boundary matrix");
                        });
}
void shifted_register() {
    decoded(0x8b020020, [](const auto &i) {
        check(i.opcode == Opcode::a64_add && format_instruction(i) == "add x0, x1, x2" &&
                  i.register_reads == std::vector{reg(1), reg(2)} && i.register_writes == std::vector{reg(0)},
              "ADD shifted register default LSL and effects");
    });
    decoded(0x0b021c20, [](const auto &i) {
        check(i.opcode == Opcode::a64_add && format_instruction(i) == "add w0, w1, w2, lsl #0x7" &&
                  i.register_reads == std::vector{reg(1, 32), reg(2, 32)}, "ADD W shifted register");
    });
    decoded(0xab020020, [](const auto &i) {
        check(i.opcode == Opcode::a64_adds && format_instruction(i) == "adds x0, x1, x2" &&
                  i.register_writes == std::vector{reg(0), reg(0, 4, flags)} &&
                  i.register_reads == std::vector{reg(1), reg(2)},
              "ADDS writes destination and NZCV without reading prior flags");
    });
    decoded(0x8b1f03e0, [](const auto &i) {
        check(format_instruction(i) == "add x0, xzr, xzr" && i.register_reads.empty(),
              "shifted arithmetic register 31 is the zero register");
    });
    decoded(0xeb02003f, [](const auto &i) {
        check(i.opcode == Opcode::a64_subs && format_instruction(i) == "subs xzr, x1, x2" &&
                  i.register_reads == std::vector{reg(1), reg(2)} && i.register_writes == std::vector{reg(0, 4, flags)},
              "SUBS zero destination still writes NZCV");
    });
    decoded(0x8b82fc20, [](const auto &i) {
        check(format_instruction(i) == "add x0, x1, x2, asr #0x3f", "ADD ASR boundary");
    });
    decoded(0x8a021c20, [](const auto &i) {
        check(i.opcode == Opcode::a64_and && format_instruction(i) == "and x0, x1, x2, lsl #0x7" &&
                  i.register_writes == std::vector{reg(0)}, "AND shifted-register semantics");
    });
    decoded(0xaa020020, [](const auto &i) {
        check(i.opcode == Opcode::a64_orr && format_instruction(i) == "orr x0, x1, x2", "ORR shifted register");
    });
    decoded(0xca021c20, [](const auto &i) {
        check(i.opcode == Opcode::a64_eor && format_instruction(i) == "eor x0, x1, x2, lsl #0x7", "EOR shifted register");
    });
    decoded(0xea02003f, [](const auto &i) {
        check(i.opcode == Opcode::a64_ands && format_instruction(i) == "ands xzr, x1, x2" &&
                  i.register_writes == std::vector{reg(0, 4, flags)}, "ANDS zero destination flags");
    });
    decoded(0x8a020020 | (1u << 22), [](const auto &i) {
        check(format_instruction(i) == "and x0, x1, x2, lsr #0x0", "non-default zero shift remains explicit");
    });
    decoded(0x8a021c20 | (3u << 22), [](const auto &i) {
        check(format_instruction(i) == "and x0, x1, x2, ror #0x7", "logical shifted register supports ROR");
    });
    decoded(0x0be20020, [](const auto &i) {
        check(i.opcode == Opcode::a64_add && std::get<RegisterOperand>(i.operands[0]).width == 32 &&
                  std::get<RegisterOperand>(i.operands[2]).width == 32,
              "extended-register ADD preserves its 32-bit W-register operands");
    });
    decoded(0x8b228020, [](const auto &i) {
        check(i.opcode == Opcode::a64_add && std::get<RegisterOperand>(i.operands[0]).width == 64 &&
                  std::get<RegisterOperand>(i.operands[2]).width == 32,
              "extended-register ADD preserves the W-source width in an X-register operation");
    });
    decoded(0x8a220020, [](const auto &i) {
        check(format_instruction(i) == "bic x0, x1, x2" && i.operands.size() == 3,
              "BIC shifted-register form decodes as a valid logical operation");
    });
    for (auto word : {0x0b000020u | (3u << 22), 0x0b000020u | (32u << 10),
                      0x0a000020u | (32u << 10)}) {
        const auto result = decode_instruction(context, bytes(word), {{7}, 0x1000});
        check((result.status != DecodeStatus::decoded && !result.instruction) ||
                  (result.instruction && result.instruction->opcode == Opcode::opaque && result.instruction->operands.empty()),
              "reserved shift types and oversized shift amounts have no fabricated semantic facts");
    }
}
void logical_immediate() {
    decoded(0x92401c20, [](const auto &i) {
        check(i.opcode == Opcode::a64_and && format_instruction(i) == "and x0, x1, #0xff" &&
                  i.operands.size() == 3 && std::get<ImmediateOperand>(i.operands[2]).value == 0xff &&
                  i.register_reads == std::vector{reg(1)} && i.register_writes == std::vector{reg(0)},
              "logical immediate expands the encoded repeated bitmask into a typed constant");
    });
    decoded(0xb2089fe0, [](const auto &i) {
        check(i.opcode == Opcode::a64_orr &&
                  std::get<ImmediateOperand>(i.operands[2]).value == 0xff00ff00ff00ff00ULL,
              "logical immediate rotates within its element before replication across the register");
    });
    decoded(0xd2401c20, [](const auto &i) {
        check(i.opcode == Opcode::a64_eor && std::get<ImmediateOperand>(i.operands[2]).value == 0xff,
              "EOR logical-immediate opcode preserves the decoded mask");
    });
    decoded(0x12001c20, [](const auto &i) {
        check(i.opcode == Opcode::a64_and && std::get<RegisterOperand>(i.operands[0]) == reg(0, 32) &&
                  std::get<ImmediateOperand>(i.operands[2]).value == 0xff &&
                  std::get<ImmediateOperand>(i.operands[2]).effective_width == 32,
              "32-bit logical immediate uses the W-register mask width");
    });
    decoded(0xb2401fe0, [](const auto &i) {
        check(i.opcode == Opcode::a64_orr && format_instruction(i) == "orr x0, xzr, #0xff" &&
                  i.register_reads.empty(),
              "logical immediate ORR recognizes the architectural zero register");
    });
    decoded(0xf2401c20, [](const auto &i) {
        check(i.opcode == Opcode::a64_ands && i.register_writes == std::vector{reg(0), reg(0, 4, flags)},
              "ANDS logical immediate records its NZCV write");
    });
    for (auto word : {0x92000000u | (31u << 10), 0x92400000u | (63u << 10), 0x12000000u | (1u << 22)}) {
        const auto result = decode_instruction(context, bytes(word), {{7}, 0x1000});
        check(result.status != DecodeStatus::decoded || !result.instruction ||
                  result.instruction->opcode == Opcode::opaque,
              "reserved empty/all-ones masks and N:sf mismatches do not invent logical constants");
    }
}
void boundaries() {
    check(processor_capabilities(context).can_decode && processor_capabilities(context).max_instruction_bytes == 4,
          "A64 capability has exact fixed instruction bound");
    const auto source = bytes(0xd503201f);
    check(decode_instruction(context, source, {{0}, 1}).status == DecodeStatus::invalid,
          "A64 misaligned instruction address invalid");
    for (unsigned kind = 0; kind < 4; ++kind) {
        auto bad = context;
        if (kind == 0)
            bad.order = ByteOrder::big;
        if (kind == 1)
            bad.architecture = Architecture::arm;
        if (kind == 2)
            bad.segmented_memory = true;
        if (kind == 3)
            bad.stack_address_width = 64;
        check(decode_instruction(bad, source, {{0}, 0}).status == DecodeStatus::unsupported,
              "incompatible context cannot enter A64 decoder");
    }
    decoded(0x4e284800, [](const auto &i) {
        check(format_instruction(i) == "aese v0.16b, v0.16b" && i.operands.size() == 2,
              "AES extension instruction retains its vector operands");
    });
    for (auto word : {0xffffffffu, 0xd503233fu, 0x52c00000u}) {
        const auto result = decode_instruction(context, bytes(word), {{0}, 0});
        check((result.status != DecodeStatus::decoded && !result.instruction) ||
                  (result.instruction && result.instruction->opcode == Opcode::opaque && result.instruction->operands.empty()),
              "unsupported extensions/reserved move-wide width never become scalar facts");
    }
}
} // namespace
int main() {
    return run([] {
        shifted_register();
        logical_immediate();
        boundaries();
        flow();
        data();
    });
}


