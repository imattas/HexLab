#include "hexlab/decompiler/decompiler.hpp"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

using namespace hexlab;
using namespace hexlab::decompiler;

static ExpressionPtr reg(RegisterOperand reg, std::uint32_t version) {
    return std::make_shared<Expression>(Expression{{TypeKind::integer, reg.width, false}, RegisterValue{reg, version}});
}
static ExpressionPtr constant(std::uint64_t value, std::uint16_t bits = 64) {
    ValueType type{TypeKind::integer, bits, false};
    return std::make_shared<Expression>(Expression{type, ConstantValue{value, type}});
}
static ExpressionPtr predicate(bool value) {
    ValueType type{TypeKind::boolean, 1, false};
    return std::make_shared<Expression>(Expression{type, ConstantValue{value ? 1u : 0u, type}});
}
static void check(bool condition, const char *message) {
    if (condition) return;
    std::cerr << "FAIL: " << message << '\n';
    std::exit(1);
}

static std::pair<std::uint64_t, std::size_t> execute_constant_cfg(const LiftedFunction &function) {
    using RegisterVersion = std::tuple<unsigned, unsigned, std::uint32_t>;
    std::map<BlockId, const LiftedBlock *> blocks;
    for (const auto &block : function.blocks) blocks.emplace(block.id, &block);
    const auto entry = std::find_if(function.blocks.begin(), function.blocks.end(), [&](const auto &block) {
        return block.begin == function.entry;
    });
    check(entry != function.blocks.end(), "semantic fixture has an entry block");
    const LiftedBlock *current = &*entry;
    std::map<RegisterVersion, std::uint64_t> values;
    std::optional<BlockId> predecessor;
    std::size_t stores = 0;
    for (std::size_t steps = 0; steps < 64; ++steps) {
        for (const auto &phi : current->phis) {
            const auto incoming = std::find_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &input) {
                return predecessor && input.predecessor == *predecessor;
            });
            if (incoming == phi.inputs.end()) continue;
            const auto source = values.find({static_cast<unsigned>(phi.destination.bank), phi.destination.index,
                                             incoming->version});
            check(source != values.end(), "semantic fixture defines every selected phi input");
            values[{static_cast<unsigned>(phi.destination.bank), phi.destination.index, phi.version}] = source->second;
        }
        bool transferred = false;
        for (const auto &instruction : current->instructions) {
            if (const auto *assignment = std::get_if<Assign>(&instruction.statement)) {
                if (!assignment->destination_version) continue;
                std::uint64_t value = 0;
                if (const auto *constant_value = std::get_if<ConstantValue>(&assignment->value->value))
                    value = constant_value->value;
                else if (const auto *reg_value = std::get_if<RegisterValue>(&assignment->value->value);
                         reg_value && reg_value->version) {
                    const auto found = values.find({static_cast<unsigned>(reg_value->reg.bank), reg_value->reg.index,
                                                    *reg_value->version});
                    check(found != values.end(), "semantic fixture reads a defined register version");
                    value = found->second;
                } else check(false, "semantic fixture uses only constants and SSA registers");
                values[{static_cast<unsigned>(assignment->destination.bank), assignment->destination.index,
                        *assignment->destination_version}] = value;
            } else if (std::holds_alternative<Store>(instruction.statement)) {
                ++stores;
            } else if (const auto *branch = std::get_if<Branch>(&instruction.statement)) {
                bool take_true = true;
                if (branch->predicate) {
                    if (const auto *constant_value = std::get_if<ConstantValue>(&branch->predicate->value))
                        take_true = constant_value->value != 0;
                    else if (const auto *reg_value = std::get_if<RegisterValue>(&branch->predicate->value);
                             reg_value && reg_value->version) {
                        const auto found = values.find({static_cast<unsigned>(reg_value->reg.bank), reg_value->reg.index,
                                                        *reg_value->version});
                        check(found != values.end(), "semantic fixture branch reads a defined register version");
                        take_true = found->second != 0;
                    } else check(false, "semantic fixture branch predicate is supported");
                }
                const auto target = take_true ? branch->true_target : branch->false_target;
                check(target.has_value(), "semantic fixture branch has a selected target");
                const auto edge = std::find_if(current->successors.begin(), current->successors.end(), [&](const auto &item) {
                    return item.target == *target && item.block;
                });
                check(edge != current->successors.end(), "semantic fixture branch target has a CFG edge");
                predecessor = current->id;
                current = blocks.at(*edge->block);
                transferred = true;
                break;
            } else if (const auto *ret = std::get_if<Return>(&instruction.statement)) {
                if (const auto *constant_value = std::get_if<ConstantValue>(&ret->value->value))
                    return {constant_value->value, stores};
                check(false, "semantic fixture returns a constant");
            }
        }
        if (!transferred) check(false, "semantic fixture terminates with a return");
    }
    check(false, "semantic fixture stays within the execution step limit");
    return {};
}

int main() {
    const Address entry{{0}, 0x1000};
    const RegisterOperand r0{RegisterBank::gpr, 0, 64, false};
    const RegisterOperand r1{RegisterBank::gpr, 1, 64, false};
    const RegisterOperand r2{RegisterBank::gpr, 2, 64, false};
    const RegisterOperand r3{RegisterBank::gpr, 3, 64, false};
    LiftedFunction fn{FunctionId{1}, entry, {
        {BlockId{1}, entry,
         {{{entry, 1}, Assign{r0, constant(1), 1}},
          {{{0}, 0x1001}, Assign{r1, reg(r0, 1), 1}},
          {{{0}, 0x1002}, Assign{r2, reg(r1, 1), 1}},
          {{{0}, 0x1003}, Return{reg(r2, 1)}}}, {}, {}}}, {}};
    const auto optimized = eliminate_dead_code(fn);
    assert(optimized);
    assert(optimized.value().blocks[0].instructions.size() == 4);

    auto dead_chain = fn;
    std::get<Return>(dead_chain.blocks[0].instructions.back().statement).value = constant(0);
    const auto cleaned = eliminate_dead_code(dead_chain);
    assert(cleaned && cleaned.value().blocks[0].instructions.size() == 1);
    assert(std::holds_alternative<Return>(cleaned.value().blocks[0].instructions.front().statement));

    auto effects = dead_chain;
    MemoryValue memory;
    memory.type = {TypeKind::integer, 32, false};
    memory.absolute = Address{{0}, 0x2000};
    auto load = std::make_shared<Expression>(Expression{memory.type, memory});
    effects.blocks[0].instructions.insert(effects.blocks[0].instructions.begin(),
        {{{0}, 0x0ff0}, Assign{r3, load, 1}});
    effects.blocks[0].instructions.push_back({{{0}, 0x1004}, Call{Address{{0}, 0x3000}, {}}});
    effects.blocks[0].instructions.push_back({{{0}, 0x1005},
        Store{constant(0x2000), constant(9, 32)}});
    effects.blocks[0].instructions.push_back({{{0}, 0x1006}, Intrinsic{"opaque", {constant(1)}}});
    const auto preserved = eliminate_dead_code(effects);
    assert(preserved && preserved.value().blocks[0].instructions.size() == 5);
    assert(std::holds_alternative<Assign>(preserved.value().blocks[0].instructions[0].statement));
    assert(std::holds_alternative<Call>(preserved.value().blocks[0].instructions[2].statement));
    assert(std::holds_alternative<Store>(preserved.value().blocks[0].instructions[3].statement));
    assert(std::holds_alternative<Intrinsic>(preserved.value().blocks[0].instructions[4].statement));

    auto phi_function = dead_chain;
    phi_function.blocks[0].phis.push_back({r0, 4, {{BlockId{2}, 2}, {BlockId{3}, 3}}});
    const auto phi_cleaned = eliminate_dead_code(phi_function);
    assert(phi_cleaned && phi_cleaned.value().blocks[0].phis.empty());

    auto invalid = fn;
    invalid.blocks[0].instructions.push_back(invalid.blocks[0].instructions[0]);
    assert(!eliminate_dead_code(invalid));

    // Constant predicates must select one CFG arm and remove the dead path.
    const Address branch_entry{{0}, 0x4000}, true_address{{0}, 0x4010}, false_address{{0}, 0x4020};
    LiftedBlock branch_block;
    branch_block.id = BlockId{10}; branch_block.begin = branch_entry;
    branch_block.instructions.push_back({{branch_entry, 10},
        Branch{"predicate", true_address, false_address, predicate(true)}});
    branch_block.successors = {{branch_entry, true_address, BlockId{11}, BlockEdgeKind::conditional_true},
                               {branch_entry, false_address, BlockId{12}, BlockEdgeKind::conditional_false}};
    LiftedBlock true_block;
    true_block.id = BlockId{11}; true_block.begin = true_address;
    true_block.instructions.push_back({{true_address, 11}, Return{constant(7)}});
    LiftedBlock false_block;
    false_block.id = BlockId{12}; false_block.begin = false_address;
    false_block.instructions.push_back({{false_address, 12}, Return{constant(9)}});
    LiftedFunction constant_branch{FunctionId{10}, branch_entry,
                                   {branch_block, true_block, false_block}, {}};
    const auto folded_branch = simplify_constants(constant_branch);
    check(folded_branch && folded_branch.value().blocks.size() == 2,
          "constant true branch keeps only reachable blocks");
    check(folded_branch.value().blocks.front().id == BlockId{10}, "constant branch preserves entry block");
    check(folded_branch.value().blocks.front().successors.size() == 1,
          "constant branch replaces two edges with one");
    check(folded_branch.value().blocks.front().successors.front().block == BlockId{11},
          "constant true selects true successor");
    check(folded_branch.value().blocks.front().successors.front().kind == BlockEdgeKind::jump,
          "constant branch successor becomes unconditional");
    const auto &chosen_branch = std::get<Branch>(folded_branch.value().blocks.front().instructions.back().statement);
    check(chosen_branch.condition == "true" && chosen_branch.true_target == true_address &&
              !chosen_branch.false_target && !chosen_branch.predicate,
          "folded branch has normalized unconditional IR");
    check(std::none_of(folded_branch.value().blocks.begin(), folded_branch.value().blocks.end(),
                       [](const auto &block) { return block.id == BlockId{12}; }),
          "constant true removes false block");

    std::get<Branch>(constant_branch.blocks.front().instructions.back().statement).predicate = predicate(false);
    const auto folded_false = simplify_constants(constant_branch);
    check(folded_false && folded_false.value().blocks.size() == 2,
          "constant false branch keeps only reachable blocks");
    check(folded_false.value().blocks.front().successors.front().block == BlockId{12},
          "constant false selects false successor");

    LiftedBlock true_to_join;
    true_to_join.id = BlockId{21}; true_to_join.begin = true_address;
    true_to_join.instructions.push_back({{true_address, 21}, Branch{"true", Address{{0}, 0x4030}, {}, {}}});
    true_to_join.successors.push_back({true_address, Address{{0}, 0x4030}, BlockId{23}, BlockEdgeKind::jump});
    LiftedBlock false_to_join;
    false_to_join.id = BlockId{22}; false_to_join.begin = false_address;
    false_to_join.instructions.push_back({{false_address, 22}, Branch{"true", Address{{0}, 0x4030}, {}, {}}});
    false_to_join.successors.push_back({false_address, Address{{0}, 0x4030}, BlockId{23}, BlockEdgeKind::jump});
    LiftedBlock join;
    join.id = BlockId{23}; join.begin = Address{{0}, 0x4030};
    join.phis.push_back({r0, 3, {{BlockId{21}, 1}, {BlockId{22}, 2}}});
    join.instructions.push_back({{join.begin, 23}, Return{reg(r0, 3)}});
    branch_block.successors = {{branch_entry, true_address, BlockId{21}, BlockEdgeKind::conditional_true},
                               {branch_entry, false_address, BlockId{22}, BlockEdgeKind::conditional_false}};
    auto branch_to_join = constant_branch;
    branch_to_join.blocks = {branch_block, true_to_join, false_to_join, join};
    const auto pruned_phi = simplify_constants(branch_to_join);
    check(pruned_phi && pruned_phi.value().blocks.size() == 3,
          "constant branch preserves selected path and join");
    const auto surviving_join = std::find_if(pruned_phi.value().blocks.begin(), pruned_phi.value().blocks.end(),
        [](const auto &block) { return block.id == BlockId{23}; });
    check(surviving_join != pruned_phi.value().blocks.end(), "join block remains reachable");
    check(surviving_join->phis.size() == 1 && surviving_join->phis.front().inputs.size() == 1,
          "phi input from removed path is deleted");
    check(surviving_join->phis.front().inputs.front().predecessor == BlockId{21},
          "phi keeps the surviving predecessor");

    // The untaken predecessor can remain reachable while its edge to the join is removed.
    auto edge_pruned = constant_branch;
    std::get<Branch>(branch_block.instructions.back().statement).false_target = Address{{0}, 0x4030};
    branch_block.successors = {{branch_entry, true_address, BlockId{21}, BlockEdgeKind::conditional_true},
                               {branch_entry, Address{{0}, 0x4030}, BlockId{23}, BlockEdgeKind::conditional_false}};
    LiftedBlock route_to_join = true_to_join;
    LiftedBlock direct_join = join;
    direct_join.phis.front().inputs = {{BlockId{10}, 1}, {BlockId{21}, 2}};
    edge_pruned.blocks = {branch_block, route_to_join, direct_join};
    const auto edge_phi = simplify_constants(edge_pruned);
    check(edge_phi && edge_phi.value().blocks.size() == 3, "join remains reachable by selected route");
    const auto edge_join = std::find_if(edge_phi.value().blocks.begin(), edge_phi.value().blocks.end(),
        [](const auto &block) { return block.id == BlockId{23}; });
    check(edge_join != edge_phi.value().blocks.end() && edge_join->phis.size() == 1 &&
              edge_join->phis.front().inputs.size() == 1 &&
              edge_join->phis.front().inputs.front().predecessor == BlockId{21},
          "phi removes input for reachable predecessor whose edge was pruned");

    // Removing an untaken predecessor exposes constants at a join. The pass
    // must revisit the SSA facts and fold branches downstream of that join.
    const Address cascade_entry{{0}, 0x5000}, live_address{{0}, 0x5010}, dead_address{{0}, 0x5020};
    const Address join_address{{0}, 0x5030}, result_yes{{0}, 0x5040}, result_no{{0}, 0x5050};
    LiftedBlock cascade_head;
    cascade_head.id = BlockId{30}; cascade_head.begin = cascade_entry;
    cascade_head.instructions = {
        {{cascade_entry, 300}, Assign{r0, predicate(true), 1}},
        {{{0}, 0x5001}, Branch{"predicate", live_address, dead_address, reg(r0, 1)}}};
    cascade_head.successors = {{cascade_entry, live_address, BlockId{31}, BlockEdgeKind::conditional_true},
                               {cascade_entry, dead_address, BlockId{32}, BlockEdgeKind::conditional_false}};
    LiftedBlock live_arm;
    live_arm.id = BlockId{31}; live_arm.begin = live_address;
    live_arm.instructions = {{{live_address, 310}, Assign{r1, predicate(true), 1}},
                             {{{0}, 0x5011}, Branch{"true", join_address, {}, {}}}};
    live_arm.successors = {{live_address, join_address, BlockId{33}, BlockEdgeKind::jump}};
    LiftedBlock dead_arm;
    dead_arm.id = BlockId{32}; dead_arm.begin = dead_address;
    dead_arm.instructions = {{{dead_address, 320}, Store{constant(0x9000), constant(1, 8)}},
                             {{{0}, 0x5021}, Branch{"true", join_address, {}, {}}}};
    dead_arm.successors = {{dead_address, join_address, BlockId{33}, BlockEdgeKind::jump}};
    LiftedBlock cascade_join;
    cascade_join.id = BlockId{33}; cascade_join.begin = join_address;
    cascade_join.phis = {{r1, 3, {{BlockId{31}, 1}, {BlockId{32}, 2}}}};
    cascade_join.instructions = {{{join_address, 330}, Branch{"predicate", result_yes, result_no, reg(r1, 3)}}};
    cascade_join.successors = {{join_address, result_yes, BlockId{34}, BlockEdgeKind::conditional_true},
                               {join_address, result_no, BlockId{35}, BlockEdgeKind::conditional_false}};
    LiftedBlock yes_block;
    yes_block.id = BlockId{34}; yes_block.begin = result_yes;
    yes_block.instructions = {{{result_yes, 340}, Return{constant(11)}}};
    LiftedBlock no_block;
    no_block.id = BlockId{35}; no_block.begin = result_no;
    no_block.instructions = {{{result_no, 350}, Return{constant(12)}}};
    LiftedFunction cascade{FunctionId{30}, cascade_entry,
        {cascade_head, live_arm, dead_arm, cascade_join, yes_block, no_block}, {}};
    const auto original_semantics = execute_constant_cfg(cascade);
    const auto cascaded = simplify_constants(cascade);
    check(cascaded && cascaded.value().blocks.size() == 4,
          "successive constant branch pruning removes both unreachable arms");
    check(std::none_of(cascaded.value().blocks.begin(), cascaded.value().blocks.end(), [](const auto &block) {
              return block.id == BlockId{32} || block.id == BlockId{35};
          }), "dead side-effecting and downstream blocks are unreachable");
    const auto cascade_join_out = std::find_if(cascaded.value().blocks.begin(), cascaded.value().blocks.end(),
        [](const auto &block) { return block.id == BlockId{33}; });
    check(cascade_join_out != cascaded.value().blocks.end() && cascade_join_out->phis.front().inputs.size() == 1,
          "iterated pruning resolves the join phi from its surviving predecessor");
    const auto cascade_branch_out = std::get<Branch>(cascade_join_out->instructions.back().statement);
    check(cascade_branch_out.condition == "true" && cascade_branch_out.true_target == result_yes,
          "resolved join constant selects the downstream branch");
    check(cascaded.value().blocks.front().instructions.front().origin.instruction_id == 300 &&
              cascaded.value().blocks.front().instructions.front().origin.address == cascade_entry,
          "CFG simplification preserves original instruction identity and address mapping");
    check(execute_constant_cfg(cascaded.value()) == original_semantics && original_semantics.first == 11 &&
              original_semantics.second == 0,
          "CFG simplification preserves return value and removes only the untaken store effect");
}
