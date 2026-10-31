#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
#include "support/checks.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
namespace {
constexpr DecodeContext context{Architecture::arm, ExecutionMode::a32, ByteOrder::little};
RegisterOperand reg(unsigned n) { return {RegisterBank::arm32_gpr, static_cast<std::uint8_t>(n), 32, false}; }
constexpr RegisterOperand flags{RegisterBank::arm_flags, 0, 4, false};
std::array<std::byte, 4> bytes(std::uint32_t word) {
    return {std::byte(word), std::byte(word >> 8), std::byte(word >> 16), std::byte(word >> 24)};
}
template <class F> void decoded(std::uint32_t word, F assertions, Address at = {{7}, 0x1000}) {
    const auto input = bytes(word);
    const auto result = decode_instruction(context, input, at);
    check(result.status == DecodeStatus::decoded && result.instruction.has_value(), "A32 literal control word decodes");
    if (!result.instruction)
        return;
    const auto &i = *result.instruction;
    check(i.context == context && i.address == at && i.length == 4 &&
              std::equal(input.begin(), input.end(), i.bytes.begin()),
          "A32 source/context are exact");
    for (unsigned n = 0; n < 4; ++n)
        check(decode_instruction(context, std::span(input).first(n), at).status == DecodeStatus::truncated,
              "A32 complete-word boundary is exact");
    assertions(i);
}
template <class I>
void info(const I &i, unsigned predicate, unsigned exchange, std::optional<ExecutionMode> target,
          std::optional<Address> link) {
    if constexpr (requires { i.arm; }) {
        check(i.arm && static_cast<unsigned>(i.arm->predicate) == predicate &&
                  static_cast<unsigned>(i.arm->exchange) == exchange && i.arm->target_mode == target &&
                  i.arm->link_address == link,
              "A32 predicate/state/link metadata is explicit");
        check(i.arm && i.arm->flags_known && i.arm->flags_written == 0 && i.arm->writes_pc && !i.arm->writeback &&
                  !i.arm->it_before.known && !i.arm->it_before.bits && !i.arm->it_after.known && !i.arm->it_after.bits,
              "A32 controls preserve flags and carry no invented Thumb IT state or writeback");
        check(i.arm &&
                  i.arm->return_mode == (i.flow == FlowKind::call ? std::optional{ExecutionMode::a32} : std::nullopt),
              "A32 return state is explicit only for link-producing controls");
    } else
        check(false, "A32 control metadata exists");
}
void branches() {
    decoded(0xea000000, [](const auto &i) {
        check(i.flow == FlowKind::jump && i.direct_target == Address{{7}, 0x1008} &&
                  format_instruction(i) == "b 0x1008",
              "B uses PC+8 rather than next instruction");
        check(std::get<RelativeOperand>(i.operands[0]).encoded_width == 24 &&
                  !std::get<RelativeOperand>(i.operands[0]).encoding,
              "A32 packed branch has no fake byte field");
        info(i, 0, 0, ExecutionMode::a32, {});
    });
    decoded(0xeb000001, [](const auto &i) {
        check(i.flow == FlowKind::call && i.direct_target == Address{{7}, 0x100c} &&
                  i.register_writes == std::vector{reg(14)} && !i.memory_write && !i.stack_value_width &&
                  format_instruction(i) == "bl 0x100c",
              "BL writes LR without x86 stack effects");
        info(i, 0, 0, ExecutionMode::a32, Address{{7}, 0x1004});
    });
    for (unsigned condition = 0; condition < 14; ++condition)
        decoded((condition << 28) | 0x0afffffe, [=](const auto &i) {
            check(i.flow == FlowKind::conditional_branch && i.condition == condition &&
                      i.direct_target == Address{{7}, 0x1000} && i.register_reads == std::vector{flags},
                  "every ordinary A32 predicate retains NZCV dependency");
            info(i, 1, 0, ExecutionMode::a32, {});
        });
    for (unsigned h = 0; h < 2; ++h)
        decoded(0xfa000000 | (h << 24), [=](const auto &i) {
            check(i.flow == FlowKind::call && i.condition == 14 && i.direct_target == Address{{7}, 0x1008 + h * 2} &&
                      i.register_reads.empty() && i.register_writes == std::vector{reg(14)},
                  "BLX immediate H bit selects halfword Thumb destination unconditionally");
            info(i, 0, 3, ExecutionMode::thumb, Address{{7}, 0x1004});
        });
    decoded(0xe12fff1e, [](const auto &i) {
        check(i.flow == FlowKind::ret && !i.direct_target && i.register_reads == std::vector{reg(14)} &&
                  format_instruction(i) == "bx lr",
              "BX LR is an indirect return with unavailable state");
        info(i, 0, 1, {}, {});
    });
    decoded(0x112fff1e, [](const auto &i) {
        check(i.condition == 1 &&
                  std::find(i.register_reads.begin(), i.register_reads.end(), flags) != i.register_reads.end() &&
                  format_instruction(i) == "bxne lr",
              "conditional return keeps predicate rather than pretending unconditional execution");
        info(i, 1, 1, {}, {});
    });
    decoded(0xe12fff33, [](const auto &i) {
        check(i.flow == FlowKind::call && i.register_reads == std::vector{reg(3)} &&
                  i.register_writes == std::vector{reg(14)} && format_instruction(i) == "blx r3",
              "BLX register records read source and write link");
        info(i, 0, 1, {}, Address{{7}, 0x1004});
    });
    decoded(0xea000000, [](const auto &i) { check(!i.direct_target, "A32 checked target cannot wrap its domain"); },
            {{7}, UINT32_MAX - 3});
    for (auto word : {0xea7fffffu, 0xea800000u, 0xeaffffffu})
        decoded(word, [](const auto &i) {
            check(i.flow == FlowKind::jump, "A32 signed displacement limits retain instruction");
        });
}
void computed_pc_targets() {
    decoded(0xe28ff001, [](const auto &i) {
        check(i.flow == FlowKind::jump && i.arm->writes_pc && i.direct_target == Address{{7}, 0x1008} &&
                  i.arm->target_mode == ExecutionMode::thumb,
              "ADD pc, pc, #imm resolves an odd interworking target from architectural PC+8");
    });
    decoded(0xe24ff008, [](const auto &i) {
        check(i.flow == FlowKind::jump && i.direct_target == Address{{7}, 0x1000} &&
                  i.arm->target_mode == ExecutionMode::a32,
              "SUB pc, pc, #imm resolves an aligned A32 target");
    });
    decoded(0xe3a0f001, [](const auto &i) {
        check(i.direct_target == Address{{7}, 0} && i.arm->target_mode == ExecutionMode::thumb,
              "MOV pc, #imm resolves only the physical address and state separately");
    });
    decoded(0xe1a0f001, [](const auto &i) {
        check(!i.direct_target && !i.arm->target_mode && i.arm->exchange == ArmExchange::address_bit0,
              "register-dependent PC writes retain an explicit unresolved state");
    });
    decoded(0x028ff001, [](const auto &i) {
        check(i.flow == FlowKind::conditional_branch && i.condition == 0 &&
                  std::find(i.register_reads.begin(), i.register_reads.end(), flags) != i.register_reads.end() &&
                  i.direct_target == Address{{7}, 0x1008} &&
                  i.arm->target_mode == ExecutionMode::thumb,
              "predicated computed PC writes retain both NZCV guard and resolved destination state");
    });
    decoded(0xe26ff000, [](const auto &i) {
        check(i.flow == FlowKind::jump && !i.direct_target && !i.arm->target_mode,
              "computed PC underflow remains unresolved instead of wrapping into the 32-bit domain");
    });
    decoded(0xe28ff001, [](const auto &i) { check(!i.direct_target, "computed PC target overflow remains unresolved"); },
            {{7}, UINT32_MAX - 3});
}
void system_and_bounds() {
    decoded(0xe320f000, [](const auto &i) {
        check(i.flow == FlowKind::fallthrough && format_instruction(i) == "nop", "architectural A32 NOP");
    });
    decoded(0xe1212374, [](const auto &i) {
        check(i.flow == FlowKind::trap && format_instruction(i) == "bkpt #0x1234",
              "BKPT split immediate is retained without execution");
    });
    decoded(0xef345678, [](const auto &i) {
        check(i.flow == FlowKind::trap && format_instruction(i) == "svc #0x345678",
              "SVC is a typed trap, never host execution");
    });
    check(processor_capabilities(context).can_decode && processor_capabilities(context).max_instruction_bytes == 4,
          "A32 capability is a bounded control subset");
    for (auto at : {UINT64_C(1), UINT64_C(2), UINT64_C(0x100000000)})
        check(decode_instruction(context, bytes(0xea000000), {{0}, at}).status == DecodeStatus::invalid,
              "A32 alignment and address width are checked");
    for (unsigned n = 0; n < 4; ++n) {
        auto bad = context;
        if (n == 0)
            bad.order = ByteOrder::big;
        if (n == 1)
            bad.segmented_memory = true;
        if (n == 2)
            bad.stack_address_width = 32;
        if (n == 3)
            bad.architecture = Architecture::arm64;
        check(decode_instruction(bad, bytes(0xea000000), {{0}, 0}).status == DecodeStatus::unsupported,
              "A32 rejects incompatible contexts");
    }
    for (auto word : {0xffffffffu, 0x11212374u, 0xe12fff1fu}) {
        const auto result = decode_instruction(context, bytes(word), {{0}, 0});
        check(result.status != DecodeStatus::decoded ||
                  (result.instruction && result.instruction->opcode == Opcode::opaque && result.instruction->operands.empty()),
              "unimplemented or constrained forms do not fabricate semantic facts");
    }
}
} // namespace
int main() {
    return run([] {
        branches();
        computed_pc_targets();
        system_and_bounds();
    });
}
