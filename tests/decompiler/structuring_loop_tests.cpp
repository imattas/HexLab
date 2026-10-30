#include "hexlab/decompiler/decompiler.hpp"

#include <cstdlib>
#include <iostream>

using namespace hexlab;
using namespace hexlab::decompiler;

namespace {
void require(bool condition, const char *message) {
    if (!condition) { std::cerr << message << '\n'; std::exit(1); }
}

Address address(std::uint64_t value) { return Address{{0}, value}; }

LiftedFunction loop_with_conditional_break() {
    const auto entry = address(0x5000);
    const auto header = address(0x5010);
    const auto body = address(0x5020);
    const auto latch = address(0x5030);
    const auto exit = address(0x5040);
    const RegisterOperand counter{RegisterBank::gpr, 0, 64, false};
    auto literal = std::make_shared<Expression>(Expression{
        {TypeKind::integer, 64, false}, ConstantValue{0, {TypeKind::integer, 64, false}}});

    LiftedFunction function{FunctionId{500}, entry, {}, {}};
    function.blocks = {
        {BlockId{500}, entry,
         {{{entry, 500}, Assign{counter, literal}},
          {{address(0x5004), 501}, Branch{"true", header, {}}}},
         {{entry, header, BlockId{501}, BlockEdgeKind::jump}}, {}},
        {BlockId{501}, header, {{{header, 502}, Branch{"keep_going", body, exit}}},
         {{header, body, BlockId{502}, BlockEdgeKind::conditional_true},
          {header, exit, BlockId{504}, BlockEdgeKind::conditional_false}}, {}},
        {BlockId{502}, body,
         {{{body, 503}, Assign{counter, literal}},
          {{address(0x5024), 504}, Branch{"stop_now", exit, latch}}},
         {{body, exit, BlockId{504}, BlockEdgeKind::conditional_true},
          {body, latch, BlockId{503}, BlockEdgeKind::conditional_false}}, {}},
        {BlockId{503}, latch, {{{latch, 505}, Branch{"true", header, {}}}},
         {{latch, header, BlockId{501}, BlockEdgeKind::jump}}, {}},
        {BlockId{504}, exit, {{{exit, 506}, Return{}}}, {}, {}}
    };
    return function;
}

LiftedFunction loop_with_conditional_continue() {
    auto function = loop_with_conditional_break();
    const auto header = address(0x5010);
    const auto latch = address(0x5030);
    const RegisterOperand counter{RegisterBank::gpr, 0, 64, false};
    function.blocks[1].phis.push_back({counter, 1,
        {{BlockId{500}, 0}, {BlockId{502}, 2}, {BlockId{503}, 3}}});
    auto &body = function.blocks[2];
    std::get<Branch>(body.instructions.back().statement) = Branch{"skip_rest", header, latch};
    body.successors[0].target = header;
    body.successors[0].block = BlockId{501};
    return function;
}

LiftedFunction nested_while_loops() {
    const auto entry = address(0x6000);
    const auto outer_header = address(0x6010);
    const auto outer_body = address(0x6020);
    const auto inner_header = address(0x6030);
    const auto inner_body = address(0x6040);
    const auto inner_latch = address(0x6050);
    const auto inner_exit = address(0x6060);
    const auto outer_latch = address(0x6070);
    const auto outer_exit = address(0x6080);
    LiftedFunction function{FunctionId{600}, entry, {}, {}};
    function.blocks = {
        {BlockId{604}, inner_body, {{{inner_body, 604}, Intrinsic{"inner_step", {}, {}}}},
         {{inner_body, inner_latch, BlockId{605}, BlockEdgeKind::jump}}, {}},
        {BlockId{600}, entry, {{{entry, 600}, Branch{"true", outer_header, {}}}},
         {{entry, outer_header, BlockId{601}, BlockEdgeKind::jump}}, {}},
        {BlockId{608}, outer_exit, {{{outer_exit, 608}, Return{}}}, {}, {}},
        {BlockId{603}, inner_header, {{{inner_header, 603}, Branch{"inner_more", inner_body, inner_exit}}},
         {{inner_header, inner_body, BlockId{604}, BlockEdgeKind::conditional_true},
          {inner_header, inner_exit, BlockId{606}, BlockEdgeKind::conditional_false}}, {}},
        {BlockId{601}, outer_header, {{{outer_header, 601}, Branch{"outer_more", outer_body, outer_exit}}},
         {{outer_header, outer_body, BlockId{602}, BlockEdgeKind::conditional_true},
          {outer_header, outer_exit, BlockId{608}, BlockEdgeKind::conditional_false}}, {}},
        {BlockId{607}, outer_latch, {{{outer_latch, 607}, Branch{"true", outer_header, {}}}},
         {{outer_latch, outer_header, BlockId{601}, BlockEdgeKind::jump}}, {}},
        {BlockId{606}, inner_exit, {{{inner_exit, 606}, Intrinsic{"after_inner", {}, {}}}},
         {{inner_exit, outer_latch, BlockId{607}, BlockEdgeKind::jump}}, {}},
        {BlockId{605}, inner_latch, {{{inner_latch, 605}, Branch{"true", inner_header, {}}}},
         {{inner_latch, inner_header, BlockId{603}, BlockEdgeKind::jump}}, {}},
        {BlockId{602}, outer_body, {{{outer_body, 602}, Intrinsic{"before_inner", {}, {}}}},
         {{outer_body, inner_header, BlockId{603}, BlockEdgeKind::jump}}, {}}
    };
    return function;
}

LiftedFunction loop_with_conditional_diamond() {
    const auto entry = address(0x7000), header = address(0x7010), split = address(0x7020);
    const auto yes = address(0x7030), no = address(0x7040), join = address(0x7050), exit = address(0x7060);
    LiftedFunction function{FunctionId{700}, entry, {}, {}};
    function.blocks = {
        {BlockId{700}, entry, {{{entry, 700}, Branch{"true", header, {}}}},
         {{entry, header, BlockId{701}, BlockEdgeKind::jump}}, {}},
        {BlockId{701}, header, {{{header, 701}, Branch{"keep_going", split, exit}}},
         {{header, split, BlockId{702}, BlockEdgeKind::conditional_true},
          {header, exit, BlockId{706}, BlockEdgeKind::conditional_false}}, {}},
        {BlockId{702}, split, {{{split, 702}, Intrinsic{"before_choice", {}, {}}},
         {{address(0x7024), 703}, Branch{"choose_yes", yes, no}}},
         {{split, yes, BlockId{703}, BlockEdgeKind::conditional_true},
          {split, no, BlockId{704}, BlockEdgeKind::conditional_false}}, {}},
        {BlockId{703}, yes, {{{yes, 704}, Intrinsic{"yes_step", {}, {}}},
          {{address(0x7034), 705}, Branch{"true", join, {}}}},
         {{yes, join, BlockId{705}, BlockEdgeKind::jump}}, {}},
        {BlockId{704}, no, {{{no, 706}, Intrinsic{"no_step", {}, {}}},
          {{address(0x7044), 707}, Branch{"true", join, {}}}},
         {{no, join, BlockId{705}, BlockEdgeKind::jump}}, {}},
        {BlockId{705}, join, {{{join, 708}, Intrinsic{"after_choice", {}, {}}},
          {{address(0x7054), 709}, Branch{"true", header, {}}}},
         {{join, header, BlockId{701}, BlockEdgeKind::jump}}, {}},
        {BlockId{706}, exit, {{{exit, 710}, Return{}}}, {}, {}}
    };
    return function;
}

LiftedFunction loop_with_switch_dispatch() {
    const auto entry = address(0x8000), header = address(0x8010), dispatch_at = address(0x8020);
    const auto case_zero = address(0x8030), case_one = address(0x8040);
    const auto default_case = address(0x8050), join = address(0x8060), exit = address(0x8070);
    const RegisterOperand selector{RegisterBank::gpr, 0, 64, false};
    const auto selector_value = std::make_shared<Expression>(Expression{
        {TypeKind::integer, 64, false}, RegisterValue{selector, std::nullopt}});
    LiftedFunction function{FunctionId{800}, entry, {}, {}};
    function.blocks = {
        {BlockId{800}, entry, {{{entry, 800}, Branch{"true", header, {}}}},
         {{entry, header, BlockId{801}, BlockEdgeKind::jump}}, {}},
        {BlockId{801}, header, {{{header, 801}, Branch{"keep_going", dispatch_at, exit}}},
         {{header, dispatch_at, BlockId{802}, BlockEdgeKind::conditional_true},
          {header, exit, BlockId{807}, BlockEdgeKind::conditional_false}}, {}},
        {BlockId{802}, dispatch_at, {{{dispatch_at, 802}, Branch{"true", {}, {}}}},
         {{dispatch_at, case_zero, BlockId{803}, BlockEdgeKind::jump},
          {dispatch_at, case_one, BlockId{804}, BlockEdgeKind::jump},
          {dispatch_at, default_case, BlockId{805}, BlockEdgeKind::jump}}, {}},
        {BlockId{803}, case_zero,
         {{{case_zero, 803}, Intrinsic{"case_zero_work", {}, {}}},
          {{address(0x8034), 8034}, Branch{"true", join, {}}}},
         {{case_zero, join, BlockId{806}, BlockEdgeKind::jump}}, {}},
        {BlockId{804}, case_one,
         {{{case_one, 804}, Intrinsic{"case_one_work", {}, {}}},
          {{address(0x8044), 8044}, Branch{"true", join, {}}}},
         {{case_one, join, BlockId{806}, BlockEdgeKind::jump}}, {}},
        {BlockId{805}, default_case,
         {{{default_case, 805}, Intrinsic{"default_work", {}, {}}},
          {{address(0x8054), 8054}, Branch{"true", join, {}}}},
         {{default_case, join, BlockId{806}, BlockEdgeKind::jump}}, {}},
        {BlockId{806}, join,
         {{{join, 806}, Intrinsic{"after_switch", {}, {}}},
          {{address(0x8064), 8064}, Branch{"true", header, {}}}},
         {{join, header, BlockId{801}, BlockEdgeKind::jump}}, {}},
        {BlockId{807}, exit, {{{exit, 807}, Return{}}}, {}, {}}
    };
    function.blocks[2].switch_dispatch = LiftedBlock::SwitchDispatch{
        selector_value, {{0, case_zero}, {1, case_one}}, default_case, true};
    return function;
}

LiftedFunction posttested_loop_with_switch_dispatch() {
    const auto entry = address(0x9000), dispatch_at = address(0x9010);
    const auto case_zero = address(0x9020), case_one = address(0x9030);
    const auto default_case = address(0x9040), latch = address(0x9050), exit = address(0x9060);
    const RegisterOperand selector{RegisterBank::gpr, 0, 64, false};
    const auto selector_value = std::make_shared<Expression>(Expression{
        {TypeKind::integer, 64, false}, RegisterValue{selector, std::nullopt}});
    LiftedFunction function{FunctionId{900}, entry, {}, {}};
    function.blocks = {
        {BlockId{900}, entry, {{{entry, 900}, Branch{"true", dispatch_at, {}}}},
         {{entry, dispatch_at, BlockId{901}, BlockEdgeKind::jump}}, {}},
        {BlockId{901}, dispatch_at, {{{dispatch_at, 901}, Branch{"true", {}, {}}}},
         {{dispatch_at, case_zero, BlockId{902}, BlockEdgeKind::jump},
          {dispatch_at, case_one, BlockId{903}, BlockEdgeKind::jump},
          {dispatch_at, default_case, BlockId{904}, BlockEdgeKind::jump}}, {}},
        {BlockId{902}, case_zero,
         {{{case_zero, 902}, Intrinsic{"case_zero_work", {}, {}}},
          {{address(0x9024), 9024}, Branch{"true", latch, {}}}},
         {{case_zero, latch, BlockId{905}, BlockEdgeKind::jump}}, {}},
        {BlockId{903}, case_one,
         {{{case_one, 903}, Intrinsic{"case_one_work", {}, {}}},
          {{address(0x9034), 9034}, Branch{"true", latch, {}}}},
         {{case_one, latch, BlockId{905}, BlockEdgeKind::jump}}, {}},
        {BlockId{904}, default_case,
         {{{default_case, 904}, Intrinsic{"default_work", {}, {}}},
          {{address(0x9044), 9044}, Branch{"true", latch, {}}}},
         {{default_case, latch, BlockId{905}, BlockEdgeKind::jump}}, {}},
        {BlockId{905}, latch, {{{latch, 905}, Branch{"repeat", entry, exit}}},
         {{latch, entry, BlockId{900}, BlockEdgeKind::conditional_true},
          {latch, exit, BlockId{906}, BlockEdgeKind::conditional_false}}, {}},
        {BlockId{906}, exit, {{{exit, 906}, Return{}}}, {}, {}}
    };
    function.blocks[1].switch_dispatch = LiftedBlock::SwitchDispatch{
        selector_value, {{0, case_zero}, {1, case_one}}, default_case, true};
    function.blocks[1].instructions.back().statement = Branch{"true", {}, {}};
    return function;
}
}

int main() {
    const auto function = loop_with_conditional_break();
    const auto output = format_structured_pseudocode(function);
    require(!output.used_fallback && output.text.find("while (keep_going)") != std::string::npos &&
                output.text.find("if (stop_now)") != std::string::npos &&
                output.text.find("break;") != std::string::npos &&
                output.text.find("goto") == std::string::npos,
            "a natural while loop with a conditional early exit emits a scoped break");

    const auto continue_function = loop_with_conditional_continue();
    const auto continue_output = format_structured_pseudocode(continue_function);
    require(!continue_output.used_fallback && continue_output.text.find("if (skip_rest)") != std::string::npos &&
                continue_output.text.find("continue;") != std::string::npos &&
                continue_output.text.find("r0_1 = r0_0;") != std::string::npos &&
                continue_output.text.find("r0_1 = r0_2;") != std::string::npos &&
                continue_output.text.find("r0_1 = r0_3;") != std::string::npos &&
                continue_output.text.find("goto") == std::string::npos,
            "conditional continue preserves initialization and every header-phi edge assignment");

    const auto diamond_output = format_structured_pseudocode(loop_with_conditional_diamond());
    require(!diamond_output.used_fallback && diamond_output.text.find("while (keep_going)") != std::string::npos &&
                diamond_output.text.find("if (choose_yes)") != std::string::npos &&
                diamond_output.text.find("yes_step()") < diamond_output.text.find("no_step()") &&
                diamond_output.text.find("after_choice()") > diamond_output.text.find("no_step()") &&
                diamond_output.text.find("goto") == std::string::npos,
            "a reconverging conditional diamond inside a natural loop emits one nested if/else region");

    const auto switch_function = loop_with_switch_dispatch();
    const auto switch_output = format_structured_pseudocode(switch_function);
    require(!switch_output.used_fallback && switch_output.text.find("while (keep_going)") != std::string::npos &&
                switch_output.text.find("switch (r0)") != std::string::npos &&
                switch_output.text.find("case 0x0:") != std::string::npos &&
                switch_output.text.find("case 0x1:") != std::string::npos &&
                switch_output.text.find("default:") != std::string::npos &&
                switch_output.text.find("case_zero_work()") < switch_output.text.find("case_one_work()") &&
                switch_output.text.find("default_work()") < switch_output.text.find("after_switch()") &&
                switch_output.text.find("after_switch()") == switch_output.text.rfind("after_switch()") &&
                switch_output.text.find("goto") == std::string::npos,
            "complete switch arms inside a natural loop converge on one emitted continuation");
    auto switch_with_phi = posttested_loop_with_switch_dispatch();
    const RegisterOperand switch_result{RegisterBank::gpr, 1, 64, false};
    switch_with_phi.blocks[5].phis.push_back({switch_result, 1,
        {{BlockId{902}, 2}, {BlockId{903}, 3}, {BlockId{904}, 4}}});
    const auto switch_phi_output = format_structured_pseudocode(switch_with_phi);
    require(!switch_phi_output.used_fallback &&
                switch_phi_output.text.find("do {") != std::string::npos &&
                switch_phi_output.text.find("switch (r0)") != std::string::npos &&
                switch_phi_output.text.find("r1_1 = r1_2;") != std::string::npos &&
                switch_phi_output.text.find("r1_1 = r1_3;") != std::string::npos &&
                switch_phi_output.text.find("r1_1 = r1_4;") != std::string::npos &&
                switch_phi_output.text.find("case_zero_work()") < switch_phi_output.text.find("r1_1 = r1_2;") &&
                switch_phi_output.text.find("r1_1 = r1_2;") < switch_phi_output.text.find("break;") &&
                switch_phi_output.text.find("} while (repeat);") != std::string::npos &&
                switch_phi_output.text.find("goto") == std::string::npos,
            "switch case tails lower exact register-phi inputs before one shared loop continuation");
    auto malformed_switch_phi = switch_with_phi;
    malformed_switch_phi.blocks[5].phis[0].inputs.pop_back();
    const auto malformed_switch_phi_output = format_structured_pseudocode(malformed_switch_phi);
    require(malformed_switch_phi_output.used_fallback && !malformed_switch_phi_output.fallback_reason.empty(),
            "loop-switch continuation rejects missing case-tail phi inputs");
    const auto nested_output = format_structured_pseudocode(nested_while_loops());
    require(!nested_output.used_fallback && nested_output.text.find("while (outer_more)") != std::string::npos &&
                nested_output.text.find("while (inner_more)") != std::string::npos &&
                nested_output.text.find("before_inner()") < nested_output.text.find("while (inner_more)") &&
                nested_output.text.find("after_inner()") > nested_output.text.find("while (inner_more)") &&
                nested_output.text.find("goto") == std::string::npos,
            "a nested natural loop emits the inner region before resuming the outer body");
    auto incomplete_switch = switch_function;
    incomplete_switch.blocks[2].switch_dispatch->complete = false;
    const auto incomplete_switch_output = format_structured_pseudocode(incomplete_switch);
    require(incomplete_switch_output.used_fallback && !incomplete_switch_output.fallback_reason.empty(),
            "incomplete loop switch metadata retains explicit goto output");
    auto mismatched_switch = switch_function;
    mismatched_switch.blocks[2].switch_dispatch->cases[1].target = address(0x8080);
    const auto mismatched_switch_output = format_structured_pseudocode(mismatched_switch);
    require(mismatched_switch_output.used_fallback && !mismatched_switch_output.fallback_reason.empty(),
            "loop switch metadata that disagrees with CFG successors retains explicit goto output");
    return 0;
}
