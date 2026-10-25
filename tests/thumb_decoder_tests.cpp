#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
#include "support/checks.hpp"
#include <algorithm>
#include <bit>
using namespace hexlab;
using namespace hexlab_test;
namespace {
constexpr DecodeContext context{Architecture::arm, ExecutionMode::thumb, ByteOrder::little};
constexpr ThumbITState outside{true, 0};
RegisterOperand reg(unsigned n) { return {RegisterBank::arm32_gpr, static_cast<std::uint8_t>(n), 32, false}; }
constexpr RegisterOperand flags{RegisterBank::arm_flags, 0, 4, false};
std::vector<std::byte> bytes(unsigned h, std::optional<unsigned> second = {}) {
    std::vector<std::byte> b{std::byte(h), std::byte(h >> 8)};
    if (second) {
        b.push_back(std::byte(*second));
        b.push_back(std::byte(*second >> 8));
    }
    return b;
}
template <class S> DecodeResult decode(std::span<const std::byte> b, Address at, S state) {
    if constexpr (requires { decode_thumb(b, at, state); })
        return decode_thumb(b, at, state);
    else
        return decode_instruction(context, b, at);
}
template <class F>
void decoded(unsigned h, F test, ThumbITState state = outside, Address at = {{9}, 0x1000},
             std::optional<unsigned> second = {}) {
    const auto b = bytes(h, second);
    const auto r = decode(b, at, state);
    check(r.status == DecodeStatus::decoded && r.instruction.has_value(), "Thumb source encoding decodes");
    if (!r.instruction)
        return;
    const auto &i = *r.instruction;
    check(i.context == context && i.address == at && i.length == b.size() &&
              std::equal(b.begin(), b.end(), i.bytes.begin()),
          "Thumb source bytes/halfword order/context preserved");
    test(i);
}
bool reads(const Instruction &i, RegisterOperand r) {
    return std::find(i.register_reads.begin(), i.register_reads.end(), r) != i.register_reads.end();
}
void controls() {
    decoded(0xe000, [](const auto &i) {
        check(i.direct_target == Address{{9}, 0x1004} && i.flow == FlowKind::jump &&
                  i.arm->target_mode == ExecutionMode::thumb && format_instruction(i) == "b 0x1004",
              "Thumb B uses PC+4 and physical Thumb target");
        check(!std::holds_alternative<RelativeOperand>(i.operands[0]),
              "Thumb packed relatives remain distinct from A32 fields with different coordinate rules");
    });
    decoded(0xe7fe, [](const auto &i) { check(i.direct_target == i.address, "Thumb signed branch displacement"); });
    for (unsigned c = 0; c < 14; ++c)
        decoded(0xd000 | (c << 8), [=](const auto &i) {
            check(i.condition == c && i.flow == FlowKind::conditional_branch && reads(i, flags),
                  "Thumb encoded branch condition is explicit");
        });
    decoded(0xb100, [](const auto &i) {
        check(i.direct_target == Address{{9}, 0x1004} && i.flow == FlowKind::conditional_branch && !reads(i, flags) &&
                  i.operands.size() == 2,
              "CBZ compares register without inventing NZCV dependency");
    });
    decoded(0xbbf8, [](const auto &i) {
        check(i.direct_target == Address{{9}, 0x1082}, "CBNZ unsigned six-bit split displacement");
    });
    decoded(0x4770, [](const auto &i) {
        check(i.flow == FlowKind::ret && i.arm->exchange == ArmExchange::address_bit0 && !i.arm->target_mode &&
                  format_instruction(i) == "bx lr",
              "BX LR retains unknown exchange state");
    });
    decoded(0x4798, [](const auto &i) {
        check(i.flow == FlowKind::call && i.arm->link_address == Address{{9}, 0x1002} &&
                  i.arm->return_mode == ExecutionMode::thumb && i.register_writes == std::vector{reg(14)},
              "BLX register keeps physical link and return mode separately");
    });
    decoded(
        0xf000,
        [](const auto &i) {
            check(i.length == 4 && i.direct_target == Address{{9}, 0x1004} &&
                      i.arm->link_address == Address{{9}, 0x1004} && i.arm->return_mode == ExecutionMode::thumb,
                  "BL wide decodes S/J split bits and four-byte link");
        },
        outside, {{9}, 0x1000}, 0xf800);
    decoded(
        0xf000,
        [](const auto &i) {
            check(i.direct_target == Address{{9}, 0x1004} && i.arm->exchange == ArmExchange::forced_a32 &&
                      i.arm->target_mode == ExecutionMode::a32,
                  "BLX wide aligns PC base and forces A32");
        },
        outside, {{9}, 0x1002}, 0xe800);
    decoded(
        0xf000,
        [](const auto &i) {
            check(i.flow == FlowKind::jump && i.direct_target == Address{{9}, 0x1004}, "B wide reconstruction");
        },
        outside, {{9}, 0x1000}, 0xb800);
    decoded(
        0xf040,
        [](const auto &i) {
            check(i.flow == FlowKind::conditional_branch && i.condition == 1 && i.direct_target == Address{{9}, 0x1004},
                  "conditional B wide uses original J bits rather than BL inversion");
        },
        outside, {{9}, 0x1000}, 0x8000);
    decoded(0xdf34, [](const auto &i) {
        check(i.flow == FlowKind::trap && format_instruction(i) == "svc #0x34",
              "Thumb SVC is an instruction fact only");
    });
}
void it() {
    decoded(0xbf0c, [](const auto &i) {
        check(i.arm->it_before == outside && i.arm->it_after == ThumbITState{true, 0x0c} &&
                  format_instruction(i) == "ite eq",
              "IT mask creates explicit then/else state");
    });
    decoded(0x2001,
            [](const auto &i) {
                check(i.arm->predicate == ArmPredicate::condition && i.condition == 0 && i.arm->flags_written == 0 &&
                          i.arm->flags_known && i.arm->it_after == ThumbITState{true, 0x18} &&
                          format_instruction(i) == "moveq r0, #0x1",
                      "IT suppresses implicit S and advances into else predicate");
            },
            {true, 0x0c});
    decoded(0x2002,
            [](const auto &i) {
                check(i.condition == 1 && i.arm->it_after == outside && format_instruction(i) == "movne r0, #0x2",
                      "last IT member clears state");
            },
            {true, 0x18});
    decoded(0x2001,
            [](const auto &i) {
                check(i.arm->predicate == ArmPredicate::unknown_it && i.condition == 255 && !i.arm->flags_known &&
                          i.arm->flags_written == 0 && i.arm->it_after == ThumbITState{} &&
                          format_instruction(i).find("IT state unknown") != std::string::npos,
                      "isolated Thumb instruction never invents predicate/implicit flags or IT boundary");
            },
            {});
    decoded(0x2001, [](const auto &i) {
        check(i.arm->flags_known && i.arm->flags_written == 12 && i.register_writes == std::vector{reg(0), flags} &&
                  reads(i, flags) && format_instruction(i) == "movs r0, #0x1",
              "known no-IT enables implicit narrow flag effects and preserves incoming C/V");
    });
    decoded(
        0x2801,
        [](const auto &i) { check(i.arm->flags_written == 15 && reads(i, flags), "CMP still sets flags inside IT"); },
        {true, 8});
    decoded(0xbe12,
            [](const auto &i) {
                check(i.arm->predicate == ArmPredicate::always && i.condition == 14 &&
                          i.arm->it_after == ThumbITState{true, 0x18},
                      "BKPT remains unconditional even inside IT");
            },
            {true, 0x0c});
    decoded(0xe000,
            [](const auto &i) {
                check(i.arm->predicate == ArmPredicate::condition && i.condition == 0 && i.arm->it_after == outside,
                      "branch accepted in last IT slot with guard retained");
            },
            {true, 8});
    for (auto h : {0xbf08u, 0xe000u, 0x4770u, 0xbd01u, 0xd000u, 0xb100u})
        check(decode(bytes(h), {{0}, 0x1000}, ThumbITState{true, 0x0c}).status != DecodeStatus::decoded,
              "nested IT, early PC transfer and forbidden conditional forms reject");
    for (auto h : {0xbff8u, 0xbfefu})
        check(decode(bytes(h), {{0}, 0x1000}, outside).status != DecodeStatus::decoded,
              "invalid IT condition/mask combinations reject");
    check(decode(bytes(0xbf08), {{0}, 0x1000}, ThumbITState{}).status != DecodeStatus::decoded,
          "IT cannot manufacture a trusted root from unknown incoming state");
    for (auto state : {ThumbITState{false, 8}, ThumbITState{true, 0x10}, ThumbITState{true, 0xf8}})
        check(decode(bytes(0xbf00), {{0}, 0x1000}, state).status == DecodeStatus::invalid,
              "noncanonical explicit IT state rejects");
}
void scalar() {
    decoded(0x2001, [](const auto &i) {
        check(std::get<ImmediateOperand>(i.operands.back()).encoded_width == 8,
              "Thumb imm8 retains original bit width rather than translated ARM rotate width");
    });
    decoded(0x1c88, [](const auto &i) {
        check(std::get<ImmediateOperand>(i.operands.back()).encoded_width == 3, "Thumb small ADD retains imm3 field");
    });
    decoded(0xb001, [](const auto &i) {
        check(std::get<ImmediateOperand>(i.operands.back()).encoded_width == 7,
              "Thumb SP adjustment retains imm7 field");
    });
    decoded(0x4248, [](const auto &i) {
        check(std::get<ImmediateOperand>(i.operands.back()).encoded_width == 0,
              "Thumb negate has implicit zero rather than an invented immediate field");
    });
    for (auto h : {0x0048u, 0x0848u, 0x1048u, 0x1888u, 0x1c88u, 0x2001u, 0x2801u, 0x3001u, 0x3801u, 0x4008u, 0x4048u,
                   0x4088u, 0x40c8u, 0x4108u, 0x4148u, 0x4188u, 0x41c8u, 0x4208u, 0x4248u, 0x4288u, 0x42c8u, 0x4308u,
                   0x4348u, 0x4388u, 0x43c8u, 0x4408u, 0x4580u, 0x4608u, 0x5008u, 0x5208u, 0x5408u, 0x5608u, 0x5808u,
                   0x5a08u, 0x5c08u, 0x5e08u, 0x6008u, 0x6808u, 0x7008u, 0x7808u, 0x8008u, 0x8808u, 0x9001u, 0x9801u,
                   0xa801u, 0xb001u, 0xb081u, 0xb510u, 0xbd10u, 0xc203u, 0xc903u})
        decoded(h, [](const auto &i) { check(i.arm.has_value(), "Thumb scalar families preserve typed ARM effects"); });
    decoded(0x4801,
            [](const auto &i) {
                check(std::get<ArmMemoryOperand>(i.operands[1]).resolved_address == Address{{9}, 0x1008} &&
                          i.memory_read,
                      "Thumb literal memory uses aligned PC+4");
            },
            outside, {{9}, 0x1002});
    decoded(0xa001,
            [](const auto &i) {
                check(!i.memory_read &&
                          std::get<ArmMemoryOperand>(i.operands[1]).resolved_address == Address{{9}, 0x1008},
                      "Thumb ADR is address-only with aligned PC+4");
            },
            outside, {{9}, 0x1002});
    decoded(0x46f7, [](const auto &i) {
        check(i.flow == FlowKind::ret && i.arm->target_mode == ExecutionMode::thumb &&
                  i.arm->exchange == ArmExchange::none,
              "Thumb MOV PC LR stays Thumb, unlike A32 ALUWritePC");
    });
    decoded(0xbd10, [](const auto &i) {
        check(i.flow == FlowKind::ret && i.arm->exchange == ArmExchange::address_bit0 && i.memory_read,
              "Thumb POP PC can interwork through loaded value");
    });
}
void bounds() {
    const auto wide = bytes(0xf000, 0xf800);
    for (unsigned n = 0; n < 4; ++n)
        check(decode(std::span(wide).first(n), {{0}, 0x1000}, outside).status == DecodeStatus::truncated,
              "wide Thumb cannot fall back to a narrow prefix");
    for (auto at : {UINT64_C(1), UINT64_C(0x100000000)})
        check(decode(bytes(0xbf00), {{0}, at}, outside).status == DecodeStatus::invalid,
              "Thumb halfword alignment and address domain validated");
    check(decode(wide, {{0}, 0xfffffffe}, outside).status == DecodeStatus::invalid,
          "wide Thumb cannot straddle 32-bit domain end");
    for (auto h : {0xde00u, 0xb400u, 0xbc00u, 0xc100u})
        check(decode(bytes(h), {{0}, 0x1000}, outside).status != DecodeStatus::decoded,
              "reserved/trap and empty-list forms do not fabricate facts");
    decoded(0xe000, [](const auto &i) { check(!i.direct_target, "Thumb direct target cannot wrap address domain"); },
            outside, {{0}, 0xfffffffe});
    check(processor_capabilities(context).can_decode && processor_capabilities(context).max_instruction_bytes == 4,
          "Thumb capability includes narrow/wide framing");
}
void state_matrix() {
    for (unsigned c = 0; c < 15; ++c)
        for (unsigned mask = 1; mask < 16; ++mask) {
            const auto result = decode(bytes(0xbf00 | (c << 4) | mask), {{9}, 0x1000}, outside);
            const bool valid = c != 14 || std::popcount(mask) == 1;
            check((result.status == DecodeStatus::decoded) == valid,
                  "every IT condition/mask combination follows architectural legality");
            if (!valid || !result.instruction)
                continue;
            auto state = result.instruction->arm->it_after;
            unsigned slots = 0;
            while (state.bits && slots < 5) {
                const auto member = decode(bytes(0xbf00), {{9}, 0x1002 + 2 * slots}, state);
                check(member.instruction && member.instruction->condition == (state.bits >> 4),
                      "all IT masks preserve then/else predicate sequence");
                if (!member.instruction)
                    break;
                state = member.instruction->arm->it_after;
                ++slots;
            }
            check(state == outside && slots == static_cast<unsigned>(4 - std::countr_zero(mask)),
                  "IT mask length and exact clear boundary are canonical");
        }
    struct Wide {
        unsigned first, second;
        std::int64_t offset;
    };
    for (auto w : {Wide{0xf3ff, 0x97ff, 16777214}, Wide{0xf400, 0x9000, -16777216}, Wide{0xf7ff, 0xbfff, -2},
                   Wide{0xf3ff, 0xd7ff, 16777214}, Wide{0xf400, 0xd000, -16777216}, Wide{0xf3ff, 0xc7fe, 16777212},
                   Wide{0xf07f, 0xafff, 1048574}, Wide{0xf440, 0x8000, -1048576}})
        decoded(
            w.first,
            [=](const auto &i) {
                check(std::get<ThumbRelativeOperand>(i.operands[0]).displacement == w.offset,
                      "wide Thumb S/J sign and scaling limits remain exact");
            },
            outside, {{9}, 0x1000}, w.second);
    check(decode(bytes(0xf000, 0xe801), {{9}, 0x1000}, outside).status != DecodeStatus::decoded,
          "BLX wide reserved H bit rejects");
    for (unsigned n = 0; n < 4; ++n) {
        auto bad = context;
        if (n == 0)
            bad.order = ByteOrder::big;
        if (n == 1)
            bad.stack_address_width = 32;
        if (n == 2)
            bad.segmented_memory = true;
        if (n == 3)
            bad.architecture = Architecture::arm64;
        check(decode_instruction(bad, bytes(0xbf00), {{0}, 0}).status == DecodeStatus::unsupported,
              "Thumb dispatcher rejects incompatible static contexts");
    }
}
} // namespace
int main() {
    return run([] {
        controls();
        it();
        scalar();
        bounds();
        state_matrix();
    });
}
