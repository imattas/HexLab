#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/processors/decoder.hpp"

#include <array>
#include <cstdlib>
#include <iostream>

using namespace hexlab;
using namespace hexlab::decompiler;

namespace {
void require(bool condition, const char *message) {
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

DecodeResult a32(std::uint32_t word, std::uint64_t address = 0x1000) {
    std::array<std::byte, 4> bytes{};
    for (unsigned i = 0; i < 4; ++i) bytes[i] = std::byte((word >> (8 * i)) & 0xff);
    return decode_a32(bytes, Address{{0}, address});
}

DecodeResult thumb(std::uint16_t halfword, std::uint64_t address = 0x1000, ThumbITState state = {true, 0}) {
    std::array<std::byte, 2> bytes{std::byte(halfword & 0xff), std::byte(halfword >> 8)};
    return decode_thumb(bytes, Address{{0}, address}, state);
}

LiftedFunction lift(Instruction instruction) {
    auto source = std::make_shared<BasicBlock>();
    source->id = BlockId{1};
    source->begin = instruction.address;
    source->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{1, std::move(instruction), {}}));
    FunctionRecord record{FunctionId{1}, source->begin, {}, {source->id}, {}, {}, true};
    FunctionSnapshot snapshot;
    snapshot.blocks = {source};
    auto result = lift_function(record, snapshot);
    require(bool(result), "decoded ARM instruction should lift in a one-block function");
    return std::move(result).value();
}

Instruction arm_instruction(Opcode opcode, std::vector<Operand> operands) {
    Instruction instruction;
    instruction.context = {Architecture::arm, ExecutionMode::a32, ByteOrder::little};
    instruction.address = Address{{0}, 0x1200};
    instruction.opcode = opcode;
    instruction.operands = std::move(operands);
    instruction.arm.emplace();
    return instruction;
}
}

int main() {
    auto rsb = a32(0xe2610007);
    require(rsb.status == DecodeStatus::decoded, "A32 RSB fixture decodes");
    require(format_pseudocode(lift(*rsb.instruction)).find("r0 = (0x7 - r1);") != std::string::npos,
            "A32 RSB preserves reverse operand order in typed output");

    const RegisterOperand r0{RegisterBank::arm32_gpr, 0, 32, false};
    const RegisterOperand r1{RegisterBank::arm32_gpr, 1, 32, false};
    const RegisterOperand r2{RegisterBank::arm32_gpr, 2, 32, false};
    const auto text_for = [&](Opcode opcode, std::vector<Operand> operands) {
        return format_pseudocode(lift(arm_instruction(opcode, std::move(operands))));
    };
    require(text_for(Opcode::a32_sub, {r0, r1, r2}).find("r0 = (r1 - r2);") != std::string::npos &&
                text_for(Opcode::a32_add, {r0, r1, r2}).find("r0 = (r1 + r2);") != std::string::npos,
            "A32 SUB and ADD retain their encoded source order");
    require(text_for(Opcode::a32_and, {r0, r1, r2}).find("r0 = (r1 & r2);") != std::string::npos &&
                text_for(Opcode::a32_eor, {r0, r1, r2}).find("r0 = (r1 ^ r2);") != std::string::npos &&
                text_for(Opcode::a32_orr, {r0, r1, r2}).find("r0 = (r1 | r2);") != std::string::npos,
            "A32 logical arithmetic families lift to typed bitwise expressions");
    require(text_for(Opcode::a32_bic, {r0, r1, r2}).find("r0 = (r1 & ~(r2));") != std::string::npos &&
                text_for(Opcode::a32_mvn, {r0, r2}).find("r0 = ~(r2);") != std::string::npos &&
                text_for(Opcode::a32_mov, {r0, r2}).find("r0 = r2;") != std::string::npos,
            "A32 BIC, MVN, and MOV retain complement and transfer semantics");
    require(text_for(Opcode::a32_adc, {r0, r1, r2}).find("carry_add((r1 + r2), carry_flag(flags))") != std::string::npos &&
                text_for(Opcode::a32_sbc, {r0, r1, r2}).find("carry_sub((r1 - r2), carry_flag(flags))") != std::string::npos &&
                text_for(Opcode::a32_rsc, {r0, r1, r2}).find("carry_sub((r2 - r1), carry_flag(flags))") != std::string::npos,
            "A32 ADC, SBC, and RSC retain carry input and reverse subtraction order");

    auto conditional_add = a32(0x10810002);
    require(conditional_add.status == DecodeStatus::decoded, "conditional A32 ADD fixture decodes");
    auto conditional_text = format_pseudocode(lift(*conditional_add.instruction));
    require(conditional_text.find("arm_guard(!(arm_flag_z(flags))") != std::string::npos &&
                conditional_text.find("arm_select((r1 + r2), r0)") != std::string::npos,
            "conditional A32 ADD retains its false-path register value");

    const std::array<std::string, 14> arm_conditions{
        "arm_flag_z(flags)", "!(arm_flag_z(flags))", "arm_flag_c(flags)", "!(arm_flag_c(flags))",
        "arm_flag_n(flags)", "!(arm_flag_n(flags))", "arm_flag_v(flags)", "!(arm_flag_v(flags))",
        "(arm_flag_c(flags) && !(arm_flag_z(flags)))", "(!(arm_flag_c(flags)) || arm_flag_z(flags))",
        "(arm_flag_n(flags) == arm_flag_v(flags))", "(arm_flag_n(flags) != arm_flag_v(flags))",
        "(!(arm_flag_z(flags)) && arm_flag_n(flags) == arm_flag_v(flags))",
        "(arm_flag_z(flags) || arm_flag_n(flags) != arm_flag_v(flags))"};
    for (std::uint32_t condition = 0; condition < arm_conditions.size(); ++condition) {
        auto branch = a32((condition << 28) | 0x0a000000);
        require(branch.status == DecodeStatus::decoded, "A32 condition truth-table branch decodes");
        require(format_pseudocode(lift(*branch.instruction)).find(arm_conditions[condition]) != std::string::npos,
                "A32 conditional predicates reconstruct the architectural NZCV truth table");
    }

    auto compare = a32(0xe3510000);
    require(compare.status == DecodeStatus::decoded, "A32 CMP fixture decodes");
    auto compare_lifted = lift(*compare.instruction);
    require(std::holds_alternative<Intrinsic>(compare_lifted.blocks[0].instructions[0].statement) &&
                std::get<Intrinsic>(compare_lifted.blocks[0].instructions[0].statement).name == "arm_compare_sub",
            "A32 CMP has an explicit NZCV-producing effect");
    auto adds = a32(0xe0910002);
    require(adds.status == DecodeStatus::decoded, "A32 ADDS fixture decodes");
    auto adds_lifted = lift(*adds.instruction);
    auto adds_effect = std::get_if<Intrinsic>(&adds_lifted.blocks[0].instructions[0].statement);
    require(adds_effect && adds_effect->name == "arm_data_add" && adds_effect->register_writes.size() == 2,
            "A32 ADDS retains both arithmetic destination and NZCV writes");

    auto movs_logical = a32(0xe1b00001);
    require(movs_logical.status == DecodeStatus::decoded, "A32 MOVS logical-flags fixture decodes");
    const auto movs_logical_text = format_pseudocode(lift(*movs_logical.instruction));
    require(movs_logical_text.find("signbit(") != std::string::npos &&
                movs_logical_text.find("== 0x0") != std::string::npos &&
                movs_logical_text.find("arm_flag_c(flags)") != std::string::npos &&
                movs_logical_text.find("arm_flag_v(flags)") != std::string::npos,
            "logical MOVS reconstructs NZ and explicitly preserves incoming C and V");

    auto rotated_movs = a32(0xe3b004ff);
    require(rotated_movs.status == DecodeStatus::decoded, "A32 rotated-immediate MOVS fixture decodes");
    const auto rotated_flags_text = format_pseudocode(lift(*rotated_movs.instruction));
    require(rotated_flags_text.find("arm_shift_carry_out(") != std::string::npos,
            "rotated-immediate logical flags replace C with the shifter carry result");

    auto tst_logical = a32(0xe1110002);
    require(tst_logical.status == DecodeStatus::decoded, "A32 TST logical-flags fixture decodes");
    const auto tst_flags_text = format_pseudocode(lift(*tst_logical.instruction));
    require(tst_flags_text.find("signbit(") != std::string::npos &&
                tst_flags_text.find("arm_flag_v(flags)") != std::string::npos,
            "TST reconstructs logical NZ while preserving V");

    auto movs_shifted = a32(0xe1b00211);
    require(movs_shifted.status == DecodeStatus::decoded, "A32 register-shifted MOVS fixture decodes");
    const auto shifted_flags_text = format_pseudocode(lift(*movs_shifted.instruction));
    require(shifted_flags_text.find("arm_shift_carry_out(") != std::string::npos &&
                shifted_flags_text.find("arm_flag_c(flags)") != std::string::npos,
            "register-controlled logical shift reconstructs conditional shifter carry while retaining old C");

    auto conditional_movs = a32(0x11b00001);
    require(conditional_movs.status == DecodeStatus::decoded, "predicated A32 MOVS fixture decodes");
    const auto conditional_movs_text = format_pseudocode(lift(*conditional_movs.instruction));
    require(conditional_movs_text.find("!(arm_flag_z(flags))") != std::string::npos &&
                conditional_movs_text.find("arm_guard(") != std::string::npos &&
                conditional_movs_text.find("arm_flag_n(") != std::string::npos &&
                conditional_movs_text.find("arm_flag_z(") != std::string::npos,
            "predicated logical flags preserve the old NZCV state when the condition is false");

    auto it = thumb(0xbf18);
    require(it.status == DecodeStatus::decoded && it.instruction->arm->it_after == ThumbITState{true, 0x18},
            "Thumb IT records the state for exactly the next governed instruction");
    auto it_move = thumb(0x2001, 0x1002, it.instruction->arm->it_after);
    require(it_move.status == DecodeStatus::decoded && it_move.instruction->arm->predicate == ArmPredicate::condition,
            "Thumb IT applies the expected predicate to its governed instruction");
    require(it_move.instruction->arm->it_after == ThumbITState{true, 0},
            "Thumb IT state advances exactly once after its final governed instruction");
    auto it_text = format_pseudocode(lift(*it_move.instruction));
    require(it_text.find("arm_guard(!(arm_flag_z(flags))") != std::string::npos,
            "Thumb IT predication preserves the destination on the false path");

    auto unknown_it = thumb(0x2001, 0x1000, {});
    require(unknown_it.status == DecodeStatus::decoded, "unknown-context Thumb instruction fixture decodes");
    auto unknown_lifted = lift(*unknown_it.instruction);
    require(std::holds_alternative<Intrinsic>(unknown_lifted.blocks[0].instructions[0].statement) &&
                std::get<Intrinsic>(unknown_lifted.blocks[0].instructions[0].statement).name.find("thumb_unknown_it_") == 0,
            "unknown Thumb IT context remains an explicit conservative intrinsic");

    auto literal = thumb(0x4801);
    require(literal.status == DecodeStatus::decoded &&
                format_pseudocode(lift(*literal.instruction)).find("r0 = *[(0x1008)];") != std::string::npos,
            "Thumb PC-relative literal load uses its decoded, aligned target");

    auto writeback_load = a32(0xe5b10004);
    require(writeback_load.status == DecodeStatus::decoded, "A32 pre-indexed writeback load fixture decodes");
    auto writeback = lift(*writeback_load.instruction);
    require(std::holds_alternative<Intrinsic>(writeback.blocks[0].instructions[0].statement) &&
                std::get<Intrinsic>(writeback.blocks[0].instructions[0].statement).name == "arm_load_writeback" &&
                std::get<Intrinsic>(writeback.blocks[0].instructions[0].statement).register_writes.size() == 2,
            "A32 load writeback keeps both loaded destination and updated base effects");

    auto conditional_store = a32(0x15810004);
    require(conditional_store.status == DecodeStatus::decoded, "conditional A32 STR fixture decodes");
    auto store_effect = lift(*conditional_store.instruction);
    require(std::holds_alternative<Intrinsic>(store_effect.blocks[0].instructions[0].statement) &&
                std::get<Intrinsic>(store_effect.blocks[0].instructions[0].statement).name == "arm_conditional_store",
            "conditional A32 STR retains a guarded memory write");

    auto call = a32(0xeb000000);
    require(call.status == DecodeStatus::decoded && call.instruction->arm->target_mode == ExecutionMode::a32,
            "A32 BL records its direct target execution mode");
    auto call_lifted = lift(*call.instruction);
    require(std::holds_alternative<Intrinsic>(call_lifted.blocks[0].instructions[0].statement) &&
                std::get<Intrinsic>(call_lifted.blocks[0].instructions[0].statement).name == "arm_call_a32" &&
                std::get<Intrinsic>(call_lifted.blocks[0].instructions[0].statement).register_writes.size() == 1,
            "A32 BL retains target mode and link-register effect in the lifted call");

    auto blx = a32(0xfa000000);
    require(blx.status == DecodeStatus::decoded && blx.instruction->arm->target_mode == ExecutionMode::thumb,
            "A32 BLX immediate records the A32-to-Thumb mode transition");
    require(std::get<Intrinsic>(lift(*blx.instruction).blocks[0].instructions[0].statement).name == "arm_call_thumb",
            "lifted BLX preserves its Thumb target mode");

    auto bx = thumb(0x4700);
    require(bx.status == DecodeStatus::decoded && bx.instruction->arm->exchange == ArmExchange::address_bit0,
            "Thumb BX records architectural interworking semantics");
    require(std::get<Intrinsic>(lift(*bx.instruction).blocks[0].instructions[0].statement).name ==
                "arm_indirect_branch_exchange",
            "lifted indirect BX remains an explicit mode-exchanging branch");

    auto bx_lr = a32(0xe12fff1e);
    require(bx_lr.status == DecodeStatus::decoded && bx_lr.instruction->flow == FlowKind::ret,
            "A32 BX LR is recognized as a return transfer");
    require(std::get<Intrinsic>(lift(*bx_lr.instruction).blocks[0].instructions[0].statement).name ==
                "arm_return_exchange",
            "lifted BX LR retains the return interworking operation");

    auto pop_pc = thumb(0xbd00);
    require(pop_pc.status == DecodeStatus::decoded && pop_pc.instruction->flow == FlowKind::ret,
            "Thumb POP PC fixture decodes as a return");
    require(std::get<Intrinsic>(lift(*pop_pc.instruction).blocks[0].instructions[0].statement).name ==
                "arm_return_load_multiple_exchange",
            "lifted POP PC retains register-list memory, writeback, and mode-exchange effects");
}
