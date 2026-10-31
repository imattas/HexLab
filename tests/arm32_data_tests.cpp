#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
#include "support/checks.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
namespace {
RegisterOperand reg(unsigned n) { return {RegisterBank::arm32_gpr, static_cast<std::uint8_t>(n), 32, false}; }
constexpr RegisterOperand flags{RegisterBank::arm_flags, 0, 4, false};
std::array<std::byte, 4> bytes(std::uint32_t w) {
    return {std::byte(w), std::byte(w >> 8), std::byte(w >> 16), std::byte(w >> 24)};
}
template <class F> void decoded(std::uint32_t w, F check_fact) {
    const auto result = decode_a32(bytes(w), {{9}, 0x1000});
    check(result.status == DecodeStatus::decoded && result.instruction.has_value(), "A32 data source word decodes");
    if (result.instruction)
        check_fact(*result.instruction);
}
bool reads(const Instruction &i, RegisterOperand r) {
    return std::find(i.register_reads.begin(), i.register_reads.end(), r) != i.register_reads.end();
}
template <class I> void shifted(const I &i, unsigned kind, unsigned amount, std::optional<unsigned> amount_reg = {}) {
    bool found = false;
    for (const auto &op : i.operands)
        std::visit(
            [&](const auto &part) {
                if constexpr (requires {
                                  part.shift;
                                  part.amount;
                                  part.amount_register;
                                  part.source;
                              }) {
                    found = part.source == reg(1) && static_cast<unsigned>(part.shift) == kind &&
                            part.amount == amount &&
                            part.amount_register == (amount_reg ? std::optional{reg(*amount_reg)} : std::nullopt);
                }
            },
            op);
    check(found, "barrel shifter is a typed operand, preserving immediate versus register and RRX");
}
void immediate() {
    const char *names[]{"and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc",
                        "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn"};
    for (unsigned op = 0; op < 16; ++op) {
        const bool compare = op >= 8 && op <= 11, unary = op == 13 || op == 15;
        const auto rn = unary ? 0 : 2, rd = compare ? 0 : 3;
        decoded(0xe2000001 | (op << 21) | (rn << 16) | (rd << 12) | (compare ? 0x100000 : 0), [=](const auto &i) {
            check(i.operands.size() == (compare || unary ? 2u : 3u) && i.arm && i.arm->flags_known &&
                      i.arm->flags_written == (compare ? (op >= 10 ? 15u : 12u) : 0u),
                  "A32 immediate data operands and NZCV write mask");
            check(opcode_name(i.opcode, i.condition) == names[op], "A32 data opcode names remain distinct");
            check(i.register_writes == (compare ? std::vector{flags} : std::vector{reg(3)}),
                  "compare never writes encoded Rd; ordinary data writes its destination");
            check(!i.memory_read && !i.memory_write && i.flow == FlowKind::fallthrough,
                  "data ALU has no invented memory or control effects");
        });
    }
    decoded(0xe3a004ff, [](const auto &i) {
        check(std::get<ImmediateOperand>(i.operands.back()).value == 0xff000000 &&
                  format_instruction(i) == "mov r0, #0xff000000",
              "rotated immediate expands 8-bit payload without inventing a contiguous encoded field");
    });
    decoded(0xe3b004ff, [](const auto &i) {
        check(i.arm->flags_written == 14 && i.arm->flags_known, "rotated MOVS overwrites NZC while preserving V");
        check(reads(i, flags), "rotated MOVS reads preserved V from the incoming flags value");
    });
    decoded(0xe1b00001, [](const auto &i) {
        check(i.arm->flags_written == 12 && reads(i, flags),
              "MOVS without a shifter carry result reads preserved C and V");
    });
    decoded(0xe1b00081, [](const auto &i) {
        check(i.arm->flags_written == 14 && reads(i, flags),
              "MOVS with an immediate shifter carry result still reads preserved V");
    });
    decoded(0xe2923001, [](const auto &i) {
        check(i.arm->flags_written == 15 && format_instruction(i) == "adds r3, r2, #0x1",
              "arithmetic S updates all NZCV flags");
    });
    decoded(0x12923001, [](const auto &i) {
        check(reads(i, flags) && format_instruction(i) == "addsne r3, r2, #0x1",
              "predicated flags writes remain explicit and guarded");
    });
    decoded(0xe2a23001, [](const auto &i) { check(reads(i, flags), "ADC uses old carry even without S"); });
}
void shifts() {
    decoded(0xe1a00001, [](const auto &i) {
        shifted(i, 0, 0);
        check(format_instruction(i) == "mov r0, r1", "unshifted register has canonical MOV spelling");
    });
    decoded(0xe1a00021, [](const auto &i) {
        shifted(i, 1, 32);
        check(format_instruction(i) == "mov r0, r1, lsr #32", "zero LSR field means32");
    });
    decoded(0xe1a00041, [](const auto &i) { shifted(i, 2, 32); });
    decoded(0xe1a00061, [](const auto &i) {
        shifted(i, 4, 1);
        check(reads(i, flags), "RRX consumes carry even without S");
    });
    decoded(0xe1b00211, [](const auto &i) {
        shifted(i, 0, 0, 2);
        check(reads(i, reg(2)) && reads(i, flags) && !i.arm->flags_known && i.arm->flags_written == 12,
              "register shift keeps unknown conditional C update rather than claiming unconditional overwrite");
    });
    decoded(0xe1a0f00e, [](const auto &i) {
        check(i.flow == FlowKind::ret && i.arm->writes_pc && static_cast<unsigned>(i.arm->exchange) == 1 &&
                  !i.direct_target,
              "MOV PC LR is an indirect interworking return");
    });
    decoded(0xe28f0004, [](const auto &i) {
        check(reads(i, reg(15)) && format_instruction(i) == "add r0, pc, #0x4",
              "PC source remains explicit for architectural PC+8 semantics");
    });
    for (auto w : {0xe1b0f00eu, 0xe1810291u, 0xe1a00f11u, 0xe10f0000u, 0xe3000000u}) {
        const auto result = decode_a32(bytes(w), {{0}, 0});
        check(w == 0xe10f0000u ? result.status == DecodeStatus::decoded && result.instruction &&
                                   result.instruction->opcode == Opcode::a32_mrs
                             : result.status != DecodeStatus::decoded,
              "MRS uses its status opcode while the remaining excluded encoding forms stay unsupported");
    }
}
} // namespace
int main() {
    return run([] {
        immediate();
        shifts();
    });
}
