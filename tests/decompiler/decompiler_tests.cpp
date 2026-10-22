#include "hexlab/decompiler/decompiler.hpp"

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

std::shared_ptr<const BasicBlock> sample_block() {
    const Address entry{{0}, 0x1000};
    RegisterOperand rax{RegisterBank::gpr, 0, 64, false};
    Instruction add;
    add.address = entry;
    add.opcode = Opcode::add;
    add.operands = {rax, ImmediateOperand{2, 8, 64, false, {}}};
    Instruction ret;
    ret.address = Address{{0}, 0x1004};
    ret.opcode = Opcode::ret;
    ret.flow = FlowKind::ret;
    auto block = std::make_shared<BasicBlock>();
    block->id = BlockId{7};
    block->begin = entry;
    block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{11, add, {}}));
    block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{12, ret, {}}));
    return block;
}
} // namespace

int main() {
    FunctionRecord record;
    record.id = FunctionId{3};
    record.entry = Address{{0}, 0x1000};
    record.blocks = {BlockId{7}};
    FunctionSnapshot snapshot;
    snapshot.blocks.push_back(sample_block());

    auto lifted = lift_function(record, snapshot);
    require(lifted.has_value(), "valid analysis function should lift");
    require(lifted.value().blocks.size() == 1, "lift preserves a single basic block");
    require(lifted.value().blocks[0].instructions.size() == 2, "lift preserves instruction origins");
    const auto &assignment = std::get<Assign>(lifted.value().blocks[0].instructions[0].statement);
    require(assignment.value->type == ValueType{TypeKind::integer, 64, false}, "register width propagates to IR type");
    const auto rendered = format_pseudocode(lifted.value());
    require(rendered == format_pseudocode(lifted.value()), "pseudocode output is deterministic");
    if (rendered.find("r0 = (r0 + 0x2);") == std::string::npos)
        std::cerr << rendered;
    require(rendered.find("r0 = (r0 + 0x2);") != std::string::npos, "integer add is rendered as an assignment");
    require(rendered.find("return;") != std::string::npos, "return instruction is represented");

    FunctionSnapshot missing;
    auto rejected = lift_function(record, missing);
    require(!rejected && rejected.error().code == ErrorCode::invalid_argument,
            "a function cannot silently lift without its blocks");

    const RegisterOperand r0{RegisterBank::gpr, 0, 64, false};
    const RegisterOperand r1{RegisterBank::gpr, 1, 64, false};
    const Address entry{{0}, 0x2000}, left{{0}, 0x2010}, right{{0}, 0x2020}, join{{0}, 0x2030};
    auto reg = std::make_shared<Expression>(Expression{{TypeKind::integer, 64, false}, RegisterValue{r0}});
    auto value = [](std::uint64_t n) -> ExpressionPtr {
        return std::make_shared<Expression>(Expression{{TypeKind::integer, 64, false},
                                                       ConstantValue{n, {TypeKind::integer, 64, false}}});
    };
    LiftedFunction diamond{FunctionId{9}, entry,
        {{BlockId{10}, entry, {{ {entry, 20}, Branch{"test", left, right} }},
          {{entry, left, BlockId{11}, BlockEdgeKind::conditional_true},
           {entry, right, BlockId{12}, BlockEdgeKind::conditional_false}}, {}},
         {BlockId{11}, left, {{{left, 21}, Assign{r0, value(1)}}},
          {{left, join, BlockId{13}, BlockEdgeKind::jump}}, {}},
         {BlockId{12}, right, {{{right, 22}, Assign{r0, value(2)}}},
          {{right, join, BlockId{13}, BlockEdgeKind::jump}}, {}},
         {BlockId{13}, join, {{{join, 23}, Assign{r1, reg}}}, {}, {}}}, {}};
    auto ssa = to_ssa(diamond);
    require(ssa.has_value(), "valid control-flow graph converts to SSA");
    const auto &merge = ssa.value().blocks[3];
    require(merge.phis.size() == 1 && merge.phis[0].inputs.size() == 2,
            "a register defined on both incoming paths receives one phi node");
    const auto &merge_assign = std::get<Assign>(merge.instructions[0].statement);
    const auto &merge_use = std::get<RegisterValue>(merge_assign.value->value);
    require(merge_use.version == merge.phis[0].version,
            "uses after a control-flow join read the merged SSA version");
    require(merge.phis[0].inputs[0].version != merge.phis[0].inputs[1].version,
            "phi inputs preserve distinct reaching definitions");
    const auto ssa_text = format_pseudocode(ssa.value());
    require(ssa_text.find(" = phi(loc_2010: r0_1, loc_2020: r0_2);") != std::string::npos,
            "pseudocode renders stable, address-attributed phi inputs");
    require(ssa_text.find("r1_1 = r0_3;") != std::string::npos,
            "pseudocode renders versioned assignments and uses");

    LiftedFunction constants{FunctionId{13}, entry,
        {{BlockId{40}, entry,
          {{{entry, 60}, Assign{r0, value(5)}},
           {{Address{{0}, 0x2004}, 61}, Assign{r1, std::make_shared<Expression>(Expression{
               {TypeKind::integer, 64, false}, BinaryValue{"add", reg, value(3)}})}}}, {}, {}}}, {}};
    auto constants_ssa = to_ssa(constants);
    require(bool(constants_ssa), "constant propagation fixture converts to SSA");
    auto folded = constants_ssa ? simplify_constants(constants_ssa.value())
                                : Result<LiftedFunction>(Error{ErrorCode::invalid_argument, "SSA fixture failed"});
    require(bool(folded), "constant simplification accepts valid SSA");
    if (folded) {
        const auto &folded_assign = std::get<Assign>(folded.value().blocks[0].instructions[1].statement);
        require(std::holds_alternative<ConstantValue>(folded_assign.value->value) &&
                    std::get<ConstantValue>(folded_assign.value->value).value == 8,
                "constant register values propagate through SSA arithmetic");
    }
    const RegisterOperand byte_reg{RegisterBank::gpr, 2, 8, false};
    const RegisterOperand byte_result{RegisterBank::gpr, 3, 8, false};
    const auto byte_value = [](std::uint64_t n) -> ExpressionPtr {
        const ValueType type{TypeKind::integer, 8, false};
        return std::make_shared<Expression>(Expression{type, ConstantValue{n, type}});
    };
    LiftedFunction wrapping{FunctionId{14}, entry,
        {{BlockId{41}, entry,
          {{{entry, 62}, Assign{byte_reg, byte_value(0xff)}},
           {{Address{{0}, 0x2008}, 63}, Assign{byte_result, std::make_shared<Expression>(Expression{
               {TypeKind::integer, 8, false}, BinaryValue{"add", std::make_shared<Expression>(Expression{
                   {TypeKind::integer, 8, false}, RegisterValue{byte_reg}}), byte_value(1)}})}}}, {}, {}}}, {}};
    auto wrapping_ssa = to_ssa(wrapping);
    auto wrapped = wrapping_ssa ? simplify_constants(wrapping_ssa.value())
                               : Result<LiftedFunction>(Error{ErrorCode::invalid_argument, "wrap fixture failed"});
    require(wrapped && std::get<ConstantValue>(std::get<Assign>(
                wrapped.value().blocks[0].instructions[1].statement).value->value).value == 0,
            "constant arithmetic wraps at the destination bit width");
    const RegisterOperand word_reg{RegisterBank::gpr, 4, 32, false};
    LiftedFunction extension_folding{FunctionId{15}, entry,
        {{BlockId{42}, entry,
          {{{entry, 64}, Assign{word_reg, std::make_shared<Expression>(Expression{
               {TypeKind::integer, 32, false}, UnaryValue{"sext", byte_value(0xff)}}), 1}},
           {{Address{{0}, 0x200c}, 65}, Assign{byte_result, std::make_shared<Expression>(Expression{
               {TypeKind::integer, 8, false}, BinaryValue{"sar", byte_value(0x80), byte_value(1)}}), 1}}}, {}, {}}}, {}};
    auto extension_folded = simplify_constants(extension_folding);
    require(extension_folded && std::get<ConstantValue>(std::get<Assign>(
                extension_folded.value().blocks[0].instructions[0].statement).value->value).value == 0xffffffff,
            "constant sign extension preserves the source sign bit");
    require(extension_folded && std::get<ConstantValue>(std::get<Assign>(
                extension_folded.value().blocks[0].instructions[1].statement).value->value).value == 0xc0,
            "arithmetic right shift fills the declared bit width");
    LiftedFunction call_barrier{FunctionId{16}, entry,
        {{BlockId{43}, entry,
          {{{entry, 66}, Assign{r0, value(5)}},
           {{Address{{0}, 0x2010}, 67}, Call{Address{{0}, 0x5000}, {}}},
           {{Address{{0}, 0x2014}, 68}, Assign{r1, reg}}}, {}, {}}}, {}};
    auto call_barrier_ssa = to_ssa(call_barrier);
    auto call_barrier_result = call_barrier_ssa ? simplify_constants(call_barrier_ssa.value())
        : Result<LiftedFunction>(Error{ErrorCode::invalid_argument, "call barrier fixture failed"});
    require(call_barrier_result && std::holds_alternative<RegisterValue>(std::get<Assign>(
                call_barrier_result.value().blocks[0].instructions[2].statement).value->value),
            "unknown call clobbers prevent register-constant propagation");
    auto duplicate_definition = extension_folding;
    duplicate_definition.blocks[0].instructions.push_back(duplicate_definition.blocks[0].instructions[0]);
    require(!simplify_constants(duplicate_definition),
            "invalid SSA with duplicate versions is rejected before propagation");

    const auto structured = format_structured_pseudocode(diamond);
    require(structured.text.find("if (test)") != std::string::npos &&
                structured.text.find("goto") == std::string::npos,
            "a canonical two-arm diamond is emitted as structured if/else C-like output");
    require(!structured.used_fallback, "supported diamond reports structured output");

    const auto structured_ssa = format_structured_pseudocode(ssa.value());
    require(!structured_ssa.used_fallback,
            "SSA diamonds with edge-lowerable join phis are structured");
    require(structured_ssa.text.find("if (test)") != std::string::npos &&
                structured_ssa.text.find("goto") == std::string::npos &&
                structured_ssa.text.find("r0_3 = r0_1;") != std::string::npos &&
                structured_ssa.text.find("r0_3 = r0_2;") != std::string::npos,
            "join phi values are copied on their corresponding structured edges");

    const Address true_middle{{0}, 0x2040}, true_tail{{0}, 0x2050};
    LiftedFunction chained_diamond{FunctionId{17}, entry,
        {{BlockId{30}, join, {{{join, 70}, Return{reg}}}, {}, {}},
         {BlockId{31}, right, {{{right, 71}, Assign{r1, value(2)}}},
          {{right, join, BlockId{30}, BlockEdgeKind::jump}}, {}},
         {BlockId{32}, entry, {{{entry, 72}, Branch{"ready", left, right}}},
          {{entry, left, BlockId{34}, BlockEdgeKind::conditional_true},
           {entry, right, BlockId{31}, BlockEdgeKind::conditional_false}}, {}},
         {BlockId{33}, true_tail, {{{true_tail, 73}, Assign{r1, value(4)}}},
          {{true_tail, join, BlockId{30}, BlockEdgeKind::jump}}, {}},
         {BlockId{34}, left, {{{left, 74}, Assign{r1, value(3)}}},
          {{left, true_middle, BlockId{35}, BlockEdgeKind::jump}}, {}},
         {BlockId{35}, true_middle, {{{true_middle, 75}, Assign{r0, value(5)}}},
          {{true_middle, true_tail, BlockId{33}, BlockEdgeKind::jump}}, {}}}, {}};
    auto chained_ssa = to_ssa(chained_diamond);
    require(chained_ssa.has_value(), "straight-line arm chains can be converted to SSA");
    const auto chained_structured = chained_ssa ? format_structured_pseudocode(chained_ssa.value())
        : StructuredPseudocode{};
    require(!chained_structured.used_fallback && chained_structured.text.find("goto") == std::string::npos &&
                chained_structured.text.find("0x3;") != std::string::npos &&
                chained_structured.text.find("0x4;") != std::string::npos,
            "a reducible diamond with a multi-block arm is emitted without labels or gotos");

    const Address return_block{{0}, 0x2060}, continue_block{{0}, 0x2070};
    LiftedFunction early_return{FunctionId{18}, entry,
        {{BlockId{40}, entry, {{{entry, 76}, Branch{"is_zero", return_block, continue_block}}},
          {{entry, return_block, BlockId{41}, BlockEdgeKind::conditional_true},
           {entry, continue_block, BlockId{42}, BlockEdgeKind::conditional_false}}, {}},
         {BlockId{41}, return_block, {{{return_block, 77}, Return{}}}, {}, {}},
         {BlockId{42}, continue_block,
          {{{continue_block, 78}, Assign{r0, value(9)}}}, {}, {}}}, {}};
    const auto early_return_structured = format_structured_pseudocode(early_return);
    require(!early_return_structured.used_fallback &&
                early_return_structured.text.find("if (is_zero) {\n        return;") != std::string::npos &&
                early_return_structured.text.find("goto") == std::string::npos,
            "a conditional early return is emitted as a one-arm structured if");
    auto false_arm_return = early_return;
    auto &inverted_branch = std::get<Branch>(false_arm_return.blocks[0].instructions[0].statement);
    std::swap(inverted_branch.true_target, inverted_branch.false_target);
    std::swap(false_arm_return.blocks[0].successors[0].target, false_arm_return.blocks[0].successors[1].target);
    const auto inverted_return_structured = format_structured_pseudocode(false_arm_return);
    if (inverted_return_structured.used_fallback ||
        inverted_return_structured.text.find("if (!(is_zero)) {\n        return;") == std::string::npos)
        std::cerr << inverted_return_structured.text;
    require(!inverted_return_structured.used_fallback &&
                inverted_return_structured.text.find("if (!(is_zero)) {\n        return;") != std::string::npos,
            "a return on the false branch preserves the inverted condition");
    auto two_return_arms = early_return;
    two_return_arms.blocks[2].instructions.push_back({{Address{{0}, 0x2074}, 80}, Return{reg}});
    const auto two_return_structured = format_structured_pseudocode(two_return_arms);
    require(two_return_structured.used_fallback && !two_return_structured.fallback_reason.empty(),
            "a conditional with two distinct terminal returns is not misreported as a one-arm early return");
    auto malformed_phi = ssa.value();
    malformed_phi.blocks[3].phis[0].inputs.pop_back();
    const auto malformed_structured = format_structured_pseudocode(malformed_phi);
    require(malformed_structured.used_fallback && !malformed_structured.fallback_reason.empty(),
            "incomplete SSA edge copies retain explicit conservative fallback");

    const Address loop_entry{{0}, 0x3000}, header{{0}, 0x3010}, body{{0}, 0x3020}, exit{{0}, 0x3030};
    auto loop_reg = std::make_shared<Expression>(Expression{{TypeKind::integer, 64, false}, RegisterValue{r0}});
    LiftedFunction loop{FunctionId{10}, loop_entry,
        {{BlockId{20}, loop_entry, {{{loop_entry, 30}, Assign{r0, value(0)}},
                                    {{Address{{0}, 0x3004}, 38}, Branch{"true", header, {}}}},
          {{loop_entry, header, BlockId{21}, BlockEdgeKind::jump}}, {}},
         {BlockId{21}, header, {{{header, 31}, Branch{"nonzero", body, exit}}},
          {{header, body, BlockId{22}, BlockEdgeKind::conditional_true},
           {header, exit, BlockId{23}, BlockEdgeKind::conditional_false}}, {}},
         {BlockId{22}, body, {{{body, 32}, Assign{r0, std::make_shared<Expression>(Expression{
             {TypeKind::integer, 64, false}, BinaryValue{"add", loop_reg, value(1)}})}}},
          {{body, header, BlockId{21}, BlockEdgeKind::jump}}, {}},
         {BlockId{23}, exit, {{{exit, 33}, Return{loop_reg}}}, {}, {}}}, {}};
    auto loop_ssa = to_ssa(loop);
    require(loop_ssa && loop_ssa.value().blocks[1].phis.size() == 1 &&
                loop_ssa.value().blocks[1].phis[0].inputs.size() == 2,
            "loop header receives a phi with entry and back-edge definitions");
    const auto &loop_increment = std::get<Assign>(loop_ssa.value().blocks[2].instructions[0].statement);
    const auto &loop_increment_input = std::get<RegisterValue>(
        std::get<BinaryValue>(loop_increment.value->value).left->value);
    require(loop_increment_input.version == loop_ssa.value().blocks[1].phis[0].version,
            "loop body reads the merged header version");
    const auto structured_loop = format_structured_pseudocode(loop);
    require(!structured_loop.used_fallback && structured_loop.text.find("while (nonzero)") != std::string::npos &&
                structured_loop.text.find("goto") == std::string::npos && structured_loop.text.find("return r0;") != std::string::npos,
            "a canonical pre-tested reducible loop is emitted as while with its exit continuation");
    const auto structured_loop_ssa = format_structured_pseudocode(loop_ssa.value());
    require(!structured_loop_ssa.used_fallback && structured_loop_ssa.text.find("while (nonzero)") != std::string::npos &&
                structured_loop_ssa.text.find("r0_2 = r0_1;") != std::string::npos &&
                structured_loop_ssa.text.find("r0_2 = r0_3;") != std::string::npos &&
                structured_loop_ssa.text.find("goto") == std::string::npos,
            "a loop-header SSA phi lowers to initialization and back-edge copies around while");

    const Address chain_body{{0}, 0x3070}, chain_middle{{0}, 0x3080}, chain_exit{{0}, 0x3090};
    LiftedFunction chained_loop{FunctionId{21}, loop_entry, {}, {}};
    chained_loop.blocks = {
        {BlockId{61}, chain_middle, {{{chain_middle, 90}, Assign{r1, value(7)}}},
         {{chain_middle, header, BlockId{64}, BlockEdgeKind::jump}}, {}},
        {BlockId{62}, chain_body,
         {{{chain_body, 91}, Assign{r0, std::make_shared<Expression>(Expression{
               {TypeKind::integer, 64, false}, BinaryValue{"add", loop_reg, value(1)}})}},
          {{Address{{0}, 0x3074}, 92}, Branch{"true", chain_middle, {}}}},
         {{chain_body, chain_middle, BlockId{61}, BlockEdgeKind::jump}}, {}},
        {BlockId{63}, loop_entry,
         {{{loop_entry, 93}, Assign{r0, value(0)}},
          {{Address{{0}, 0x3004}, 94}, Branch{"true", header, {}}}},
         {{loop_entry, header, BlockId{64}, BlockEdgeKind::jump}}, {}},
        {BlockId{64}, header, {{{header, 95}, Branch{"keep_going", chain_body, chain_exit}}},
         {{header, chain_body, BlockId{62}, BlockEdgeKind::conditional_true},
          {header, chain_exit, BlockId{65}, BlockEdgeKind::conditional_false}}, {}},
        {BlockId{65}, chain_exit, {{{chain_exit, 96}, Return{loop_reg}}}, {}, {}}
    };
    const auto chained_loop_plain = format_structured_pseudocode(chained_loop);
    require(!chained_loop_plain.used_fallback && chained_loop_plain.text.find("while (keep_going)") != std::string::npos &&
                chained_loop_plain.text.find("0x7;") != std::string::npos &&
                chained_loop_plain.text.find("goto") == std::string::npos,
            "a pre-tested loop with a multi-block straight-line body is structured");
    auto chained_loop_ssa = to_ssa(chained_loop);
    const auto chained_loop_versioned = chained_loop_ssa ? format_structured_pseudocode(chained_loop_ssa.value())
        : StructuredPseudocode{};
    require(chained_loop_ssa && !chained_loop_versioned.used_fallback &&
                chained_loop_versioned.text.find("r0_2 = r0_1;") != std::string::npos &&
                chained_loop_versioned.text.find("r0_2 = r0_3;") != std::string::npos &&
                chained_loop_versioned.text.find("goto") == std::string::npos,
            "multi-block loop SSA phi copies use the actual final latch predecessor");
    auto side_exit_chained_loop = chained_loop;
    std::get<Branch>(side_exit_chained_loop.blocks[1].instructions.back().statement) =
        Branch{"error", chain_middle, chain_exit};
    side_exit_chained_loop.blocks[1].successors.push_back(
        {chain_body, chain_exit, BlockId{65}, BlockEdgeKind::conditional_false});
    const auto rejected_side_exit_loop = format_structured_pseudocode(side_exit_chained_loop);
    require(rejected_side_exit_loop.used_fallback && rejected_side_exit_loop.text.find("goto") != std::string::npos,
            "a multi-block while body with a conditional side exit keeps explicit CFG transfers");
    const Address do_body{{0}, 0x3040}, do_latch{{0}, 0x3050}, do_exit{{0}, 0x3060};
    LiftedFunction do_loop{FunctionId{19}, do_body,
        {{BlockId{50}, do_body, {{{do_body, 34}, Assign{r0, value(1)}},
                                  {{Address{{0}, 0x3044}, 35}, Branch{"true", do_latch, {}}}},
          {{do_body, do_latch, BlockId{51}, BlockEdgeKind::jump}}, {}},
         {BlockId{51}, do_latch, {{{do_latch, 36}, Branch{"ready", do_body, do_exit}}},
          {{do_latch, do_body, BlockId{50}, BlockEdgeKind::conditional_true},
           {do_latch, do_exit, BlockId{52}, BlockEdgeKind::conditional_false}}, {}},
         {BlockId{52}, do_exit, {{{do_exit, 37}, Return{reg}}}, {}, {}}}, {}};
    const auto structured_do_loop = format_structured_pseudocode(do_loop);
    require(!structured_do_loop.used_fallback &&
                structured_do_loop.text.find("do {\n        r0 = 0x1;") != std::string::npos &&
                structured_do_loop.text.find("} while (ready);") != std::string::npos &&
                structured_do_loop.text.find("goto") == std::string::npos,
            "a canonical post-tested reducible loop is emitted as do-while without gotos");
    auto inverted_do_loop = do_loop;
    auto &do_branch = std::get<Branch>(inverted_do_loop.blocks[1].instructions[0].statement);
    std::swap(do_branch.true_target, do_branch.false_target);
    std::swap(inverted_do_loop.blocks[1].successors[0].target, inverted_do_loop.blocks[1].successors[1].target);
    const auto structured_inverted_do = format_structured_pseudocode(inverted_do_loop);
    require(!structured_inverted_do.used_fallback &&
                structured_inverted_do.text.find("} while (!(ready));") != std::string::npos,
            "a post-tested loop with the back edge on the false arm preserves condition polarity");

    auto unsupported_loop = do_loop;
    unsupported_loop.blocks[0].successors.push_back({do_body, do_exit, BlockId{52}, BlockEdgeKind::jump});
    const auto unsupported_structured_loop = format_structured_pseudocode(unsupported_loop);
    require(unsupported_structured_loop.used_fallback && !unsupported_structured_loop.fallback_reason.empty() &&
                unsupported_structured_loop.text.find("goto") != std::string::npos,
            "a loop with a side exit retains explicit goto fallback");

    Instruction load;
    load.address = entry;
    load.opcode = Opcode::a32_ldr;
    load.operands = {RegisterOperand{RegisterBank::arm32_gpr, 1, 32, false},
                     ArmMemoryOperand{RegisterOperand{RegisterBank::arm32_gpr, 0, 32, false},
                                      std::uint32_t{4}, true, true, false, 32, false, {}}};
    auto arm_block = std::make_shared<BasicBlock>();
    arm_block->id = BlockId{30};
    arm_block->begin = entry;
    arm_block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{40, load, {}}));
    FunctionRecord arm_record{FunctionId{11}, entry, {}, {BlockId{30}}, {}, {}, true};
    FunctionSnapshot arm_snapshot;
    arm_snapshot.blocks.push_back(arm_block);
    auto arm_lifted = lift_function(arm_record, arm_snapshot);
    require(arm_lifted && std::holds_alternative<Assign>(arm_lifted.value().blocks[0].instructions[0].statement),
            "A32 load lifts as a register assignment rather than an opaque intrinsic");
    if (arm_lifted && std::holds_alternative<Assign>(arm_lifted.value().blocks[0].instructions[0].statement)) {
        const auto &loaded = std::get<Assign>(arm_lifted.value().blocks[0].instructions[0].statement);
        require(std::holds_alternative<MemoryValue>(loaded.value->value) && loaded.value->type.bits == 32,
                "A32 load retains typed memory semantics");
        require(format_pseudocode(arm_lifted.value()).find("r1 = *[(r0 + 0x4)];") != std::string::npos,
                "A32 immediate offset is represented in rendered memory address");
    }
    auto shifted_load = load;
    shifted_load.operands[1] = ArmMemoryOperand{
        RegisterOperand{RegisterBank::arm32_gpr, 0, 32, false},
        ArmShiftedRegisterOperand{RegisterOperand{RegisterBank::arm32_gpr, 2, 32, false}, ArmShift::lsl, 2, {}},
        true, true, false, 32, false, {}};
    auto shifted_block = std::make_shared<BasicBlock>();
    shifted_block->id = BlockId{31};
    shifted_block->begin = entry;
    shifted_block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{41, shifted_load, {}}));
    FunctionRecord shifted_record{FunctionId{12}, entry, {}, {BlockId{31}}, {}, {}, true};
    FunctionSnapshot shifted_snapshot;
    shifted_snapshot.blocks.push_back(shifted_block);
    auto shifted_lifted = lift_function(shifted_record, shifted_snapshot);
    require(shifted_lifted && format_pseudocode(shifted_lifted.value()).find(
                "r1 = *[(r0 + (r2 << 2))];") != std::string::npos,
            "A32 register-offset shift remains explicit in the computed address");

    const Address extension_entry{{0}, 0x4000};
    const RegisterOperand eax{RegisterBank::gpr, 0, 32, false};
    const RegisterOperand bl{RegisterBank::gpr, 3, 8, false};
    auto extension_lift = [&](Opcode opcode, std::uint64_t id, RegisterOperand destination,
                              RegisterOperand source) {
        Instruction extension;
        extension.address = extension_entry;
        extension.opcode = opcode;
        extension.operands = {destination, source};
        auto block = std::make_shared<BasicBlock>();
        block->id = BlockId{id};
        block->begin = extension_entry;
        block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{id, extension, {}}));
        FunctionRecord extension_record{FunctionId{id}, extension_entry, {}, {BlockId{id}}, {}, {}, true};
        FunctionSnapshot extension_snapshot;
        extension_snapshot.blocks.push_back(block);
        return lift_function(extension_record, extension_snapshot);
    };
    auto zero_extended = extension_lift(Opcode::movzx, 50, eax, bl);
    require(zero_extended && std::holds_alternative<Assign>(
                zero_extended.value().blocks[0].instructions[0].statement),
            "MOVZX lifts as a register assignment");
    const auto &zero_extension_assign = std::get<Assign>(zero_extended.value().blocks[0].instructions[0].statement);
    require(zero_extension_assign.value->type.bits == 32 &&
                std::holds_alternative<UnaryValue>(zero_extension_assign.value->value) &&
                std::get<UnaryValue>(zero_extension_assign.value->value).operation == "zext",
            "MOVZX explicitly zero-extends its narrow source to the destination width");
    auto sign_extended = extension_lift(Opcode::movsx, 51, eax, bl);
    require(sign_extended && std::holds_alternative<Assign>(
                sign_extended.value().blocks[0].instructions[0].statement),
            "MOVSX lifts as a register assignment");
    const auto &sign_extension_assign = std::get<Assign>(sign_extended.value().blocks[0].instructions[0].statement);
    require(sign_extension_assign.value->type.bits == 32 &&
                std::holds_alternative<UnaryValue>(sign_extension_assign.value->value) &&
                std::get<UnaryValue>(sign_extension_assign.value->value).operation == "sext",
            "MOVSX explicitly sign-extends its narrow source to the destination width");
    const RegisterOperand rax{RegisterBank::gpr, 0, 64, false};
    const RegisterOperand ecx{RegisterBank::gpr, 1, 32, false};
    auto sign_extended_dword = extension_lift(Opcode::movsxd, 52, rax, ecx);
    require(sign_extended_dword && std::holds_alternative<Assign>(
                sign_extended_dword.value().blocks[0].instructions[0].statement),
            "MOVSXD lifts as a register assignment");
    const auto &sign_extension_dword_assign = std::get<Assign>(
        sign_extended_dword.value().blocks[0].instructions[0].statement);
    require(sign_extension_dword_assign.value->type.bits == 64 &&
                std::holds_alternative<UnaryValue>(sign_extension_dword_assign.value->value) &&
                std::get<UnaryValue>(sign_extension_dword_assign.value->value).operation == "sext",
            "MOVSXD explicitly sign-extends its 32-bit source to 64 bits");
}
