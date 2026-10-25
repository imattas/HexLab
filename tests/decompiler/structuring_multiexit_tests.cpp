#include "hexlab/decompiler/decompiler.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <map>
#include <sstream>

using namespace hexlab;
using namespace hexlab::decompiler;

namespace {
void require(bool condition, const char *message) {
    if (!condition) { std::cerr << message << '\n'; std::exit(1); }
}
Address address(std::uint64_t offset) { return Address{{0}, offset}; }
const RegisterOperand result_register{RegisterBank::gpr, 0, 32, false};
ExpressionPtr constant(std::uint64_t value) {
    return std::make_shared<Expression>(Expression{
        {TypeKind::integer, 32, false}, ConstantValue{value, {TypeKind::integer, 32, false}}});
}
ExpressionPtr result_value() {
    return std::make_shared<Expression>(Expression{
        {TypeKind::integer, 32, false}, RegisterValue{result_register, {}}});
}
LiftedBlock block(std::uint64_t index, std::vector<Statement> statements,
                  std::vector<std::pair<std::uint64_t, BlockEdgeKind>> targets = {}) {
    LiftedBlock value{BlockId{index}, address(0x7000 + index * 0x10)};
    for (std::size_t n = 0; n < statements.size(); ++n)
        value.instructions.push_back({{address(value.begin.offset + n), index * 10 + n}, statements[n]});
    for (const auto &[target, kind] : targets)
        value.successors.push_back({value.begin, address(0x7000 + target * 0x10), BlockId{target}, kind});
    return value;
}
Branch branch(const char *name, std::uint64_t left, std::uint64_t right) {
    return Branch{name, address(0x7000 + left * 0x10), address(0x7000 + right * 0x10)};
}
// Both branch paths define r0, join at 3, and only then choose a return.
LiftedFunction diamond_before_returns() {
    return {FunctionId{700}, address(0x7000), {
        block(0, {branch("choose_value", 1, 2)},
            {{1, BlockEdgeKind::conditional_true}, {2, BlockEdgeKind::conditional_false}}),
        block(1, {Assign{result_register, constant(11)}}, {{3, BlockEdgeKind::jump}}),
        block(2, {Assign{result_register, constant(22)}}, {{3, BlockEdgeKind::jump}}),
        block(3, {Intrinsic{"shared_effect", {}, IntrinsicMemoryEffect::none}, branch("accept", 4, 5)},
            {{4, BlockEdgeKind::conditional_true}, {5, BlockEdgeKind::conditional_false}}),
        block(4, {Return{result_value()}}),
        block(5, {Return{constant(99)}})
    }, {}};
}
// Early return bypasses a whole SSA diamond. The join is local to the else arm.
LiftedFunction early_return_before_diamond() {
    auto function = diamond_before_returns();
    function.blocks.erase(function.blocks.begin() + 5);
    function.blocks[3].instructions.pop_back();
    function.blocks[3].successors = {{address(0x7030), address(0x7040), BlockId{4}, BlockEdgeKind::jump}};
    function.blocks.push_back(block(6, {branch("reject", 7, 0)},
        {{7, BlockEdgeKind::conditional_true}, {0, BlockEdgeKind::conditional_false}}));
    function.blocks.push_back(block(7, {Return{constant(77)}}));
    function.entry = address(0x7060);
    std::reverse(function.blocks.begin(), function.blocks.end());
    return function;
}
// The join is shared across a nested early-return region and its outer sibling.
// Flattening either branch independently duplicates `shared_effect` or loses
// the incoming value selection at the SSA phi.
LiftedFunction nested_early_return_with_shared_join() {
    return {FunctionId{702}, address(0x7000), {
        block(0, {branch("outer", 1, 2)},
            {{1, BlockEdgeKind::conditional_true}, {2, BlockEdgeKind::conditional_false}}),
        block(1, {Intrinsic{"nested_effect", {}, IntrinsicMemoryEffect::none},
                  Assign{result_register, constant(11)}, branch("inner", 3, 4)},
            {{3, BlockEdgeKind::conditional_true}, {4, BlockEdgeKind::conditional_false}}),
        block(2, {Assign{result_register, constant(22)}}, {{3, BlockEdgeKind::jump}}),
        block(3, {Intrinsic{"shared_effect", {}, IntrinsicMemoryEffect::none}, Return{result_value()}}),
        block(4, {Return{constant(99)}})
    }, {}};
}
LiftedFunction ssa_pipeline(const LiftedFunction &function) {
    const auto ssa = to_ssa(function);
    require(ssa.has_value(), "multi-exit fixture converts to SSA");
    const auto folded = simplify_constants(ssa.value());
    require(folded.has_value(), "multi-exit SSA fixture simplifies");
    const auto identities = simplify_identities(folded.value());
    require(identities.has_value(), "multi-exit expressions simplify");
    const auto live = eliminate_dead_code(identities.value());
    require(live.has_value(), "multi-exit fixture retains live definitions");
    return live.value();
}
std::size_t occurrences(const std::string &text, const std::string &needle) {
    std::size_t count = 0, position = 0;
    while ((position = text.find(needle, position)) != std::string::npos) { ++count; position += needle.size(); }
    return count;
}
// Execute the emitted subset, independently of CFG/post-dominator analysis.
// This detects misplaced shared effects, reversed arms and wrong phi copies.
struct Execution { std::optional<std::uint64_t> returned; unsigned effects = 0; unsigned nested_effects = 0; };
Execution execute(const std::string &text, const std::map<std::string, bool> &conditions) {
    std::istringstream lines(text);
    std::string line;
    std::vector<bool> scopes{true};
    std::vector<bool> decisions;
    std::map<std::string, std::uint64_t> values;
    Execution result;
    const auto value_of = [&](const std::string &value) {
        if (value.starts_with("0x")) return static_cast<std::uint64_t>(std::stoull(value, nullptr, 16));
        require(values.contains(value), "structured execution only reads defined SSA values");
        return values.at(value);
    };
    while (std::getline(lines, line)) {
        const auto first = line.find_first_not_of(' ');
        if (first == std::string::npos) continue;
        line.erase(0, first);
        if (line.starts_with("function ")) continue;
        if (line.starts_with("if (")) {
            const auto condition_end = line.rfind(") {");
            require(condition_end != std::string::npos, "structured condition has a closing delimiter");
            auto condition = line.substr(4, condition_end - 4);
            const bool inverted = condition.starts_with("!(") && condition.ends_with(')');
            if (inverted) condition = condition.substr(2, condition.size() - 3);
            require(conditions.contains(condition), "structured condition is an original fixture predicate");
            const auto decision = conditions.at(condition) != inverted;
            decisions.push_back(decision);
            scopes.push_back(scopes.back() && decision);
        } else if (line.starts_with("} else {")) {
            require(scopes.size() > 1 && !decisions.empty(), "else has a matching conditional");
            scopes.back() = scopes[scopes.size() - 2] && !decisions.back();
        } else if (line.starts_with('}')) {
            if (scopes.size() > 1) { scopes.pop_back(); decisions.pop_back(); }
        } else if (scopes.back()) {
            const auto semicolon = line.find(';');
            require(semicolon != std::string::npos, "structured execution sees a complete statement");
            line.resize(semicolon);
            if (line.starts_with("return ")) { result.returned = value_of(line.substr(7)); break; }
            if (line == "shared_effect()") { ++result.effects; continue; }
            if (line == "nested_effect()") { ++result.nested_effects; continue; }
            const auto equal = line.find(" = ");
            require(equal != std::string::npos, "structured execution sees a supported SSA assignment");
            values[line.substr(0, equal)] = value_of(line.substr(equal + 3));
        }
    }
    require(result.returned.has_value(), "every generated execution reaches a real return");
    return result;
}
void check_phi_copies(const LiftedFunction &function, const StructuredPseudocode &output) {
    const auto join = std::find_if(function.blocks.begin(), function.blocks.end(), [](const auto &item) {
        return item.id == BlockId{3};
    });
    require(join != function.blocks.end() && join->phis.size() == 1, "fixture retains the live result phi");
    const auto &phi = join->phis.front();
    for (const auto &input : phi.inputs) {
        const auto copy = "r0_" + std::to_string(phi.version) + " = r0_" + std::to_string(input.version) + ";";
        require(occurrences(output.text, copy) == 1 &&
                output.text.find(copy) < output.text.find("shared_effect()"),
                "each incoming result is copied once before the shared effect");
    }
}
}

int main() {
    const auto function = ssa_pipeline(diamond_before_returns());
    const auto output = format_structured_pseudocode(function);
    if (output.used_fallback) std::cerr << output.fallback_reason << '\n' << output.text;
    require(!output.used_fallback, "an SSA diamond followed by two returns structures without gotos");
    require(occurrences(output.text, "if (choose_value)") == 1 &&
            occurrences(output.text, "if (accept)") == 1 && occurrences(output.text, "return ") == 2 &&
            occurrences(output.text, "shared_effect()") == 1 && output.text.find("goto") == std::string::npos,
            "shared code executes once before the final return choice");
    check_phi_copies(function, output);
    for (const bool choose : {false, true}) for (const bool accept : {false, true}) {
        const auto executed = execute(output.text, {{"choose_value", choose}, {"accept", accept}});
        require(executed.returned == (accept ? (choose ? 11u : 22u) : 99u) && executed.effects == 1,
                "all diamond/return paths preserve the selected value and one shared side effect");
    }

    const auto early = ssa_pipeline(early_return_before_diamond());
    const auto early_output = format_structured_pseudocode(early);
    require(!early_output.used_fallback && early_output.text.find("if (reject)") != std::string::npos &&
            early_output.text.find("return 0x4d;") < early_output.text.find("if (choose_value)") &&
            occurrences(early_output.text, "shared_effect()") == 1 &&
            occurrences(early_output.text, "return ") == 2,
            "an early return preserves the nested diamond's local join with shuffled storage");
    check_phi_copies(early, early_output);
    for (const bool reject : {false, true}) for (const bool choose : {false, true}) {
        const auto executed = execute(early_output.text, {{"reject", reject}, {"choose_value", choose}});
        require(executed.returned == (reject ? 77u : (choose ? 11u : 22u)) &&
                executed.effects == (reject ? 0u : 1u),
                "an early return bypasses assignments and effects in the continuation");
    }

    const auto nested_shared = ssa_pipeline(nested_early_return_with_shared_join());
    const auto nested_shared_output = format_structured_pseudocode(nested_shared);
    require(!nested_shared_output.used_fallback &&
                nested_shared_output.text.find("if (outer)") != std::string::npos &&
                nested_shared_output.text.find("if (inner)") != std::string::npos &&
                occurrences(nested_shared_output.text, "shared_effect()") == 1 &&
                occurrences(nested_shared_output.text, "nested_effect()") == 1 &&
                occurrences(nested_shared_output.text, "goto") == 0,
            "a nested early return and outer sibling share one structured continuation");
    check_phi_copies(nested_shared, nested_shared_output);
    for (const bool outer : {false, true}) for (const bool inner : {false, true}) {
        const auto executed = execute(nested_shared_output.text, {{"outer", outer}, {"inner", inner}});
        require(executed.returned == (outer ? (inner ? 11u : 99u) : 22u) &&
                    executed.effects == (outer && !inner ? 0u : 1u) &&
                    executed.nested_effects == (outer ? 1u : 0u),
                "shared-join phi values and side-effect counts match every nested return path");
    }

    auto prefixed = diamond_before_returns();
    prefixed.blocks.push_back(block(8, {Intrinsic{"prefix_effect", {}, IntrinsicMemoryEffect::none}},
        {{0, BlockEdgeKind::jump}}));
    prefixed.entry = address(0x7080);
    const auto prefix_output = format_structured_pseudocode(ssa_pipeline(prefixed));
    require(!prefix_output.used_fallback && occurrences(prefix_output.text, "prefix_effect()") == 1 &&
            prefix_output.text.find("prefix_effect()") < prefix_output.text.find("if (choose_value)"),
            "straight-line function setup precedes a multi-exit structured region");

    auto exit_phi = function;
    auto result_exit = std::find_if(exit_phi.blocks.begin(), exit_phi.blocks.end(), [](const auto &item) {
        return item.id == BlockId{4};
    });
    const auto source_version = std::get<RegisterValue>(std::get<Return>(result_exit->instructions.back().statement).value->value).version;
    require(source_version.has_value(), "the accepted return reads an SSA result");
    result_exit->phis.push_back({result_register, 100, {{BlockId{3}, *source_version}}});
    std::get<Return>(result_exit->instructions.back().statement).value = std::make_shared<Expression>(Expression{
        {TypeKind::integer, 32, false}, RegisterValue{result_register, 100}});
    const auto exit_phi_output = format_structured_pseudocode(exit_phi);
    require(!exit_phi_output.used_fallback && occurrences(exit_phi_output.text, "r0_100 = r0_") == 1,
            "a terminal arm lowers its single-predecessor phi before its return");
    for (const bool choose : {false, true}) {
        const auto executed = execute(exit_phi_output.text, {{"choose_value", choose}, {"accept", true}});
        require(executed.returned == (choose ? 11u : 22u) && executed.effects == 1,
                "terminal phi copies select the accepted result on both incoming value paths");
    }

    auto malformed = function;
    auto join = std::find_if(malformed.blocks.begin(), malformed.blocks.end(), [](const auto &item) {
        return item.id == BlockId{3};
    });
    join->phis.front().inputs.pop_back();
    const auto bad_phi = format_structured_pseudocode(malformed);
    require(bad_phi.used_fallback && bad_phi.text == format_pseudocode(malformed),
            "incomplete multi-exit phi metadata retains the lossless CFG");

    auto unterminated = function;
    unterminated.blocks.back().instructions.clear();
    require(format_structured_pseudocode(unterminated).used_fallback,
            "a missing return cannot be promoted into a terminating virtual-exit arm");

    auto cyclic = function;
    cyclic.blocks.back().instructions = {{{address(0x7050), 750}, Branch{"true", address(0x7000), {}}}};
    cyclic.blocks.back().successors = {{address(0x7050), address(0x7000), BlockId{0}, BlockEdgeKind::jump}};
    require(format_structured_pseudocode(cyclic).used_fallback, "virtual exits do not hide a cyclic region");

    LiftedFunction shared_early_join{FunctionId{701}, address(0x7000), {
        block(0, {branch("outer", 1, 2)},
            {{1, BlockEdgeKind::conditional_true}, {2, BlockEdgeKind::conditional_false}}),
        block(1, {branch("inner", 3, 4)},
            {{3, BlockEdgeKind::conditional_true}, {4, BlockEdgeKind::conditional_false}}),
        block(2, {Intrinsic{"shared_effect", {}, IntrinsicMemoryEffect::none}}, {{4, BlockEdgeKind::jump}}),
        block(3, {Return{constant(11)}}), block(4, {Return{constant(22)}})
    }, {}};
    const auto shared_early_join_output = format_structured_pseudocode(shared_early_join);
    require(!shared_early_join_output.used_fallback &&
                occurrences(shared_early_join_output.text, "shared_effect()") == 1 &&
                occurrences(shared_early_join_output.text, "return ") == 2 &&
                shared_early_join_output.text.find("goto") == std::string::npos,
            "a shared terminal continuation is emitted once after the nested return choice");
    for (const bool outer : {false, true}) for (const bool inner : {false, true}) {
        const auto executed = execute(shared_early_join_output.text, {{"outer", outer}, {"inner", inner}});
        require(executed.returned == (outer && inner ? 11u : 22u) &&
                    executed.effects == (outer ? 0u : 1u),
                "a shared return remains on the paths that reach it and its effect runs once");
    }

    LiftedFunction crossing{FunctionId{703}, address(0x7000), {
        block(0, {branch("outer", 1, 2)},
            {{1, BlockEdgeKind::conditional_true}, {2, BlockEdgeKind::conditional_false}}),
        block(1, {branch("inner", 3, 4)},
            {{3, BlockEdgeKind::conditional_true}, {4, BlockEdgeKind::conditional_false}}),
        block(2, {}, {{3, BlockEdgeKind::jump}}),
        block(3, {Intrinsic{"shared_effect", {}, IntrinsicMemoryEffect::none}, branch("finish", 5, 6)},
            {{5, BlockEdgeKind::conditional_true}, {6, BlockEdgeKind::conditional_false}}),
        block(4, {Return{constant(11)}}),
        block(5, {Return{constant(22)}}),
        block(6, {Return{constant(33)}})
    }, {}};
    std::reverse(crossing.blocks.begin(), crossing.blocks.end());
    const auto crossing_output = format_structured_pseudocode(crossing);
    require(!crossing_output.used_fallback && occurrences(crossing_output.text, "if (finish)") == 1 &&
                occurrences(crossing_output.text, "shared_effect()") == 1 &&
                occurrences(crossing_output.text, "goto") == 0,
            "a shared nonterminal conditional is emitted once after a nested early return");
    for (const bool outer : {false, true}) for (const bool inner : {false, true})
        for (const bool finish : {false, true}) {
            const auto executed = execute(crossing_output.text,
                {{"outer", outer}, {"inner", inner}, {"finish", finish}});
            require(executed.returned == (outer && !inner ? 11u : (finish ? 22u : 33u)) &&
                        executed.effects == (outer && !inner ? 0u : 1u),
                    "the shared nonterminal continuation preserves return values and effect counts");
        }
}
