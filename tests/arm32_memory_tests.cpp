#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
#include "support/checks.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
namespace {
RegisterOperand reg(unsigned n) { return {RegisterBank::arm32_gpr, static_cast<std::uint8_t>(n), 32, false}; }
std::array<std::byte, 4> bytes(std::uint32_t w) {
    return {std::byte(w), std::byte(w >> 8), std::byte(w >> 16), std::byte(w >> 24)};
}
template <class F> void decoded(std::uint32_t w, F test) {
    const auto r = decode_a32(bytes(w), {{9}, 0x1000});
    check(r.status == DecodeStatus::decoded && r.instruction.has_value(), "A32 memory/list word decodes");
    if (r.instruction)
        test(*r.instruction);
}
template <class I>
void memory(const I &i, bool add, bool pre, bool wb, unsigned width, bool sign, std::optional<Address> resolved = {}) {
    bool found = false;
    for (const auto &op : i.operands)
        std::visit(
            [&](const auto &p) {
                if constexpr (requires {
                                  p.pre_index;
                                  p.offset;
                                  p.add;
                                  p.writeback;
                                  p.sign_extend;
                              })
                    found = p.add == add && p.pre_index == pre && p.writeback == wb && p.data_width == width &&
                            p.sign_extend == sign && p.resolved_address == resolved;
            },
            op);
    check(found, "ARM memory retains indexing/sign/writeback/literal semantics independently of x86 addressing");
}
template <class I> void list(const I &i, unsigned mask, unsigned mode) {
    bool found = false;
    for (const auto &op : i.operands)
        std::visit(
            [&](const auto &p) {
                if constexpr (requires { p.mask; })
                    found = p.mask == mask;
            },
            op);
    check(found && i.arm && static_cast<unsigned>(i.arm->multiple_mode) == mode,
          "ARM register mask and transfer direction are explicit");
}
void singles() {
    decoded(0xe5910004, [](const auto &i) {
        memory(i, true, true, false, 32, false);
        check(i.memory_read && !i.memory_write && i.register_writes == std::vector{reg(0)} &&
                  format_instruction(i) == "ldr r0, [r1, #0x4]",
              "offset LDR writes destination and reads memory");
    });
    decoded(0xe5b10004, [](const auto &i) {
        memory(i, true, true, true, 32, false);
        check(i.arm->writeback && i.register_writes == std::vector{reg(0), reg(1)} &&
                  format_instruction(i) == "ldr r0, [r1, #0x4]!",
              "pre-index LDR writes updated base");
    });
    decoded(0xe4910004, [](const auto &i) {
        memory(i, true, false, true, 32, false);
        check(format_instruction(i) == "ldr r0, [r1], #0x4", "post-index accesses original base before update");
    });
    decoded(0xe5110004, [](const auto &i) {
        memory(i, false, true, false, 32, false);
        check(format_instruction(i) == "ldr r0, [r1, #-0x4]", "subtract offset is not discarded");
    });
    decoded(0xe7810102, [](const auto &i) {
        memory(i, true, true, false, 32, false);
        check(i.memory_write && !i.memory_read && i.register_writes.empty() &&
                  format_instruction(i) == "str r0, [r1, r2, lsl #2]",
              "register-offset STR uses typed shift");
    });
    decoded(0xe59f0004, [](const auto &i) { memory(i, true, true, false, 32, false, Address{{9}, 0x100c}); });
    decoded(0xe51f0004, [](const auto &i) { memory(i, false, true, false, 32, false, Address{{9}, 0x1004}); });
    decoded(0xe5d10001, [](const auto &i) { memory(i, true, true, false, 8, false); });
    decoded(0xe1d100b2, [](const auto &i) { memory(i, true, true, false, 16, false); });
    decoded(0xe1d100d2, [](const auto &i) { memory(i, true, true, false, 8, true); });
    decoded(0xe1d100f2, [](const auto &i) { memory(i, true, true, false, 16, true); });
    decoded(0xe1c100b2, [](const auto &i) {
        memory(i, true, true, false, 16, false);
        check(i.memory_write, "halfword store remains distinct");
    });
    decoded(0xe591f004, [](const auto &i) {
        check(i.flow == FlowKind::jump && i.arm->writes_pc && static_cast<unsigned>(i.arm->exchange) == 1 &&
                  !i.direct_target,
              "load PC retains unknown memory value and exchange");
    });
}
void multiples() {
    decoded(0xe92d4010, [](const auto &i) {
        list(i, 0x4010, 3);
        check(i.memory_write && i.arm->writeback && i.register_writes == std::vector{reg(13)} &&
                  format_instruction(i) == "stmdb sp!, {r4, lr}",
              "stack multiple transfer remains architectural register/memory effects");
    });
    decoded(0xe8bd8010, [](const auto &i) {
        list(i, 0x8010, 0);
        check(i.memory_read && i.flow == FlowKind::ret && i.arm->writes_pc && i.arm->writeback &&
                  format_instruction(i) == "ldmia sp!, {r4, pc}",
              "POP-style LDM returns with unavailable loaded state");
    });
    for (unsigned mode = 0; mode < 4; ++mode) {
        const auto word =
            0xe8010005u | ((mode == 0 || mode == 1) ? 0x800000 : 0) | ((mode == 1 || mode == 3) ? 0x1000000 : 0);
        decoded(word, [=](const auto &i) { list(i, 5, mode); });
    }
}
void negatives() {
    for (auto w : {0xe5b11004u, 0xe7910012u, 0xe5bf0004u, 0xe4b10004u, 0xe5d1f004u, 0xe8910000u, 0xe8b10002u,
                   0xe8fd8001u, 0xe1c100d2u})
        check(decode_a32(bytes(w), {{0}, 0}).status != DecodeStatus::decoded,
              "unprivileged/overlap/status/malformed/doubleword forms cannot fabricate scalar memory effects");
}
} // namespace
int main() {
    return run([] {
        singles();
        multiples();
        negatives();
    });
}
