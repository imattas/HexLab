#include "hexlab/analysis/abi.hpp"
#include "support/checks.hpp"

using namespace hexlab;
using namespace hexlab_test;

namespace {
types::TypePtr integer(std::uint64_t bytes) {
    return types::Type::integer("i", bytes, bytes, true).value();
}
types::TypePtr floating(std::uint64_t bytes) {
    return types::Type::floating("f", bytes, bytes).value();
}
types::TypePtr pointer() {
    return types::Type::pointer(types::Type::void_type(), 8, 8).value();
}
types::TypePtr function(types::TypePtr result, std::vector<types::TypePtr> args) {
    std::vector<types::Parameter> parameters;
    for (std::size_t i = 0; i < args.size(); ++i)
        parameters.push_back({"arg" + std::to_string(i), std::move(args[i])});
    return types::Type::function(std::move(result), std::move(parameters), false).value();
}
const AbiLocation &location(const AbiValueLocation &value, std::size_t index = 0) {
    return value.locations.at(index);
}
}

int main() {
    return run([] {
        const auto a64_scalar_fn = function(integer(8), {integer(4), pointer(), floating(4), floating(8)});
        const auto a64_scalars = classify_abi_signature(CallingConvention::aapcs64, *a64_scalar_fn);
        check(a64_scalars.complete && a64_scalars.pointer_size == 8 && a64_scalars.stack_alignment == 16 &&
              location(a64_scalars.arguments[0]).register_name == "X0" &&
              location(a64_scalars.arguments[1]).register_name == "X1" &&
              location(a64_scalars.arguments[2]).register_name == "S0" &&
              location(a64_scalars.arguments[3]).register_name == "D1" &&
              location(a64_scalars.result).register_name == "X0",
              "AAPCS64 uses independent X/W and V scalar argument banks");

        const auto f32a = floating(4);
        const auto f64a = floating(8);
        const auto inner_hfa = types::Type::structure("InnerHFA", {{"a", f32a, 0}, {"b", f32a, 4}}, 8, 4).value();
        const auto nested_hfa = types::Type::structure("NestedHFA",
            {{"inner", inner_hfa, 0}, {"tail", f32a, 8}}, 12, 4).value();
        const auto a64_hfas = classify_abi_signature(CallingConvention::aapcs64,
            *function(nested_hfa, {nested_hfa}));
        check(a64_hfas.result.supported && a64_hfas.result.locations.size() == 3 &&
              location(a64_hfas.result).register_name == "S0" &&
              location(a64_hfas.result, 1).register_name == "S1" &&
              location(a64_hfas.result, 2).register_name == "S2" &&
              location(a64_hfas.result, 2).value_offset == 8,
              "AAPCS64 recursively flattens and returns nested HFAs in V registers");
        check(a64_hfas.arguments[0].locations.size() == 3 &&
              location(a64_hfas.arguments[0]).register_name == "S0" &&
              location(a64_hfas.arguments[0], 2).value_offset == 8,
              "AAPCS64 passes nested HFA members through one SIMD register each");

        const auto float_overlay = types::Type::union_type("FloatOverlay",
            {{"single", f32a, 0}, {"alternate", f32a, 0}}, 4, 4).value();
        const auto union_hfa = classify_abi_signature(CallingConvention::aapcs64,
            *function(types::Type::void_type(), {float_overlay, f32a}));
        check(union_hfa.arguments[0].locations.size() == 1 &&
              location(union_hfa.arguments[0]).register_name == "S0" &&
              location(union_hfa.arguments[1]).register_name == "S1",
              "AAPCS64 counts uniquely addressable union members once when classifying an HFA");

        const auto pair64 = types::Type::structure("Pair64",
            {{"a", integer(8), 0}, {"b", integer(8), 8}}, 16, 8).value();
        const auto big = types::Type::structure("Big",
            {{"a", integer(8), 0}, {"b", integer(8), 8}, {"c", integer(8), 16}}, 24, 8).value();
        const auto a64_aggregates = classify_abi_signature(CallingConvention::aapcs64,
            *function(big, {pair64, integer(8), integer(8), integer(8), integer(8), integer(8), integer(8), pair64}));
        check(a64_aggregates.result.indirect && location(a64_aggregates.result).register_name == "X8" &&
              location(a64_aggregates.arguments[0]).register_name == "X0" &&
              location(a64_aggregates.arguments[0], 1).register_name == "X1" &&
              location(a64_aggregates.arguments[1]).register_name == "X2" &&
              location(a64_aggregates.arguments[7]).kind == AbiLocationKind::stack &&
              location(a64_aggregates.arguments[7]).stack_offset == 0,
              "AAPCS64 classifies direct composites, hidden X8 return, and whole-argument GPR exhaustion");

        const auto a64_stack = classify_abi_signature(CallingConvention::aapcs64,
            *function(types::Type::void_type(), {integer(8), integer(8), integer(8), integer(8),
                integer(8), integer(8), integer(8), integer(8), integer(8), f64a, f64a, f64a,
                f64a, f64a, f64a, f64a, f64a, f64a}));
        check(location(a64_stack.arguments[8]).kind == AbiLocationKind::stack &&
              location(a64_stack.arguments[8]).stack_offset == 0 &&
              location(a64_stack.arguments[17]).kind == AbiLocationKind::stack &&
              location(a64_stack.arguments[17]).stack_offset == 8 &&
              a64_stack.stack_argument_bytes == 16,
              "AAPCS64 spills exhausted GPR and SIMD banks into aligned entry-SP slots");

        const auto a64_vector = types::Type::array(f64a, 2).value();
        const auto hfa2 = types::Type::structure("HFA2", {{"a", f64a, 0}, {"b", f64a, 8}}, 16, 8).value();
        const auto a64_hfa_spill = classify_abi_signature(CallingConvention::aapcs64,
            *function(types::Type::void_type(), {f64a, f64a, f64a, f64a, f64a, f64a, f64a, hfa2, f64a}));
        check(location(a64_hfa_spill.arguments[7]).kind == AbiLocationKind::stack &&
              location(a64_hfa_spill.arguments[7]).stack_offset == 0 &&
              location(a64_hfa_spill.arguments[8]).kind == AbiLocationKind::stack &&
              location(a64_hfa_spill.arguments[8]).stack_offset == 16,
              "AAPCS64 spills an HFA whole and exhausts the SIMD bank when registers are insufficient");

        const auto hfa5 = types::Type::array(f32a, 5).value();
        const auto a64_hfa_limit = classify_abi_signature(CallingConvention::aapcs64,
            *function(types::Type::void_type(), {hfa5}));
        check(a64_hfa_limit.arguments[0].indirect &&
              location(a64_hfa_limit.arguments[0]).register_name == "X0",
              "AAPCS64 aggregates beyond four FP elements use ordinary large-composite rules");

        const auto u128 = integer(16);
        const auto a64_u128 = classify_abi_signature(CallingConvention::aapcs64,
            *function(u128, {u128}));
        check(a64_u128.result.locations.size() == 2 &&
              location(a64_u128.result, 1).register_name == "X1" &&
              a64_u128.arguments[0].locations.size() == 2 &&
              location(a64_u128.arguments[0], 1).register_name == "X1",
              "AAPCS64 128-bit integer scalars split across consecutive general registers");
        const auto a64_unsupported = classify_abi_signature(CallingConvention::aapcs64,
            *types::Type::function(types::Type::void_type(), {{"v", a64_vector}}, true).value());
        check(!a64_unsupported.complete && !a64_unsupported.arguments[0].supported &&
              a64_unsupported.arguments[0].reason.find("variadic") != std::string::npos,
              "AAPCS64 rejects variadic forms explicitly");
        const auto sysv_fn = function(floating(8),
            {integer(8), floating(8), integer(4), floating(4), integer(8), floating(8),
             integer(8), floating(8), integer(8), floating(8), integer(8), floating(8),
             integer(8), floating(8), integer(8), floating(8), integer(8), floating(8)});
        const auto sysv = classify_abi_signature(CallingConvention::sysv_x86_64, *sysv_fn);
        check(sysv.arguments.size() == 18, "SysV classifies each declared argument");
        check(location(sysv.arguments[0]).register_name == "RDI" &&
              location(sysv.arguments[2]).register_name == "ESI", "SysV integer args use independent GPR bank");
        check(location(sysv.arguments[11]).register_name == "XMM5", "SysV floating args use independent XMM bank");
        check(location(sysv.arguments[12]).kind == AbiLocationKind::stack &&
              location(sysv.arguments[12]).stack_offset == 8, "SysV first spilled integer is after return address");
        check(location(sysv.arguments[14]).kind == AbiLocationKind::stack &&
              location(sysv.arguments[14]).stack_offset == 16 &&
              location(sysv.arguments[17]).kind == AbiLocationKind::stack &&
              location(sysv.arguments[17]).stack_offset == 32,
              "SysV spilled scalars use ordered eight-byte slots across register banks");
        check(location(sysv.result).register_name == "XMM0" && sysv.stack_alignment == 16,
              "SysV floating return and call alignment are described");

        const auto win_fn = function(integer(4),
            {integer(8), floating(8), pointer(), floating(4), integer(4), floating(8)});
        const auto win = classify_abi_signature(CallingConvention::windows_x64, *win_fn);
        check(location(win.arguments[0]).register_name == "RCX" &&
              location(win.arguments[1]).register_name == "XMM1" &&
              location(win.arguments[2]).register_name == "R8" &&
              location(win.arguments[3]).register_name == "XMM3", "Windows x64 uses positional argument registers");
        check(win.shadow_space == 32 && location(win.arguments[4]).kind == AbiLocationKind::stack &&
              location(win.arguments[4]).stack_offset == 40, "Windows x64 reports shadow and first stack argument");
        check(location(win.result).register_name == "EAX", "Windows integer return uses width-appropriate RAX alias");

        const auto legacy_fn = function(integer(8), {integer(4), floating(8), integer(8)});
        const auto legacy = classify_abi_signature(CallingConvention::x86_32_cdecl, *legacy_fn);
        check(location(legacy.arguments[0]).stack_offset == 4 &&
              location(legacy.arguments[1]).stack_offset == 8 &&
              location(legacy.arguments[2]).stack_offset == 16,
              "cdecl arguments use entry-SP offsets and four-byte slots");
        check(legacy.stack_argument_bytes == 20, "cdecl stack byte count includes rounded argument slots");
        check(location(legacy.result).register_name == "EAX" &&
              location(legacy.result).value_offset == 0 &&
              location(legacy.result, 1).register_name == "EDX" &&
              location(legacy.result, 1).value_offset == 4,
              "cdecl 64-bit integer return maps low and high halves to EAX:EDX");
        check(legacy.stack_alignment == 4 && legacy.shadow_space == 0, "cdecl reports 32-bit stack model");

        auto aggregate = types::Type::structure("Triple", {{"a", integer(8), 0}, {"b", integer(8), 8}, {"c", integer(8), 16}}, 24, 8).value();
        const auto unsupported = classify_abi_signature(CallingConvention::sysv_x86_64,
            *function(types::Type::void_type(), {aggregate, types::Type::array(integer(4), 4).value()}));
        check(unsupported.arguments[0].supported && location(unsupported.arguments[0]).kind == AbiLocationKind::stack,
              "oversized SysV aggregate is passed in memory");
        check(unsupported.arguments[1].supported,
              "arrays are recursively classified as aggregates");
        const auto unsupported_return = classify_abi_signature(CallingConvention::windows_x64,
            *function(aggregate, {integer(4)}));
        check(unsupported_return.result.supported && unsupported_return.result.indirect &&
              location(unsupported_return.result).register_name == "RCX" &&
              location(unsupported_return.arguments[0]).register_name == "EDX",
              "Windows large aggregate return uses hidden RCX and shifts positional arguments");
        const auto sysv_hidden = classify_abi_signature(CallingConvention::sysv_x86_64,
            *function(aggregate, {integer(8)}));
        check(sysv_hidden.result.indirect && location(sysv_hidden.result).register_name == "RDI" &&
              location(sysv_hidden.arguments[0]).register_name == "RSI",
              "SysV memory return uses hidden RDI and consumes the first integer argument register");
        const auto cdecl_hidden = classify_abi_signature(CallingConvention::x86_32_cdecl,
            *function(aggregate, {integer(4)}));
        check(cdecl_hidden.result.indirect && location(cdecl_hidden.result).stack_offset == 4 &&
              location(cdecl_hidden.arguments[0]).stack_offset == 8,
              "cdecl aggregate return places the hidden result pointer before explicit stack arguments");
        const auto small_win = types::Type::structure("Small", {{"a", integer(4), 0}, {"b", integer(4), 4}}, 8, 4).value();
        const auto win_small = classify_abi_signature(CallingConvention::windows_x64,
            *function(types::Type::void_type(), {small_win}));
        check(win_small.arguments[0].supported && !win_small.arguments[0].indirect &&
              location(win_small.arguments[0]).register_name == "RCX",
              "Windows x64 passes eligible eight-byte aggregates in a positional integer register");

        const auto pair32 = types::Type::structure("Pair32",
            {{"lo", integer(4), 0}, {"hi", integer(4), 4}}, 8, 4).value();
        const auto triple64 = types::Type::structure("Triple64",
            {{"a", integer(8), 0}, {"b", integer(8), 8}, {"c", integer(8), 16}}, 24, 8).value();

        struct AggregateAbiCase {
            const char *name;
            CallingConvention convention;
            types::TypePtr aggregate;
            std::uint64_t argument_stack_offset;
            std::string argument_first;
            std::string argument_second;
            AbiLocationKind argument_kind;
            bool argument_indirect;
            std::string result_first;
            std::string result_second;
            AbiLocationKind result_kind;
            bool result_indirect;
            std::uint64_t result_stack_offset;
        };
        const std::vector<AggregateAbiCase> aggregate_matrix{
            {"SysV AMD64 8-byte", CallingConvention::sysv_x86_64, pair32, 0, "RDI", "", AbiLocationKind::register_, false,
             "RAX", "", AbiLocationKind::register_, false, 0},
            {"Microsoft x64 8-byte", CallingConvention::windows_x64, pair32, 0, "RCX", "", AbiLocationKind::register_, false,
             "RAX", "", AbiLocationKind::register_, false, 0},
            {"x86 cdecl 8-byte", CallingConvention::x86_32_cdecl, pair32, 8, "", "", AbiLocationKind::stack, false,
             "", "", AbiLocationKind::stack, true, 4},
            {"AAPCS64 8-byte", CallingConvention::aapcs64, pair32, 0, "X0", "", AbiLocationKind::register_, false,
             "X0", "", AbiLocationKind::register_, false, 0},
            {"SysV AMD64 16-byte", CallingConvention::sysv_x86_64, pair64, 0, "RDI", "RSI", AbiLocationKind::register_, false,
             "RAX", "RDX", AbiLocationKind::register_, false, 0},
            {"Microsoft x64 16-byte", CallingConvention::windows_x64, pair64, 0, "RDX", "", AbiLocationKind::register_, true,
             "RCX", "", AbiLocationKind::register_, true, 0},
            {"x86 cdecl 16-byte", CallingConvention::x86_32_cdecl, pair64, 8, "", "", AbiLocationKind::stack, false,
             "", "", AbiLocationKind::stack, true, 4},
            {"AAPCS64 16-byte", CallingConvention::aapcs64, pair64, 0, "X0", "X1", AbiLocationKind::register_, false,
             "X0", "X1", AbiLocationKind::register_, false, 0},
            {"SysV AMD64 24-byte", CallingConvention::sysv_x86_64, triple64, 8, "", "", AbiLocationKind::stack, false,
             "RDI", "", AbiLocationKind::register_, true, 0},
            {"Microsoft x64 24-byte", CallingConvention::windows_x64, triple64, 0, "RDX", "", AbiLocationKind::register_, true,
             "RCX", "", AbiLocationKind::register_, true, 0},
            {"x86 cdecl 24-byte", CallingConvention::x86_32_cdecl, triple64, 8, "", "", AbiLocationKind::stack, false,
             "", "", AbiLocationKind::stack, true, 4},
            {"AAPCS64 24-byte", CallingConvention::aapcs64, triple64, 0, "X0", "", AbiLocationKind::register_, true,
             "X8", "", AbiLocationKind::register_, true, 0},
        };
        for (const auto &expected : aggregate_matrix) {
            const auto classified = classify_abi_signature(expected.convention,
                *function(expected.aggregate, {expected.aggregate}));
            const auto &argument = classified.arguments[0];
            const auto &result = classified.result;
            check(classified.complete && argument.supported && result.supported &&
                  argument.indirect == expected.argument_indirect &&
                  result.indirect == expected.result_indirect &&
                  !argument.locations.empty() && !result.locations.empty() &&
                  argument.locations[0].kind == expected.argument_kind &&
                  (expected.argument_kind != AbiLocationKind::stack ||
                   argument.locations[0].stack_offset == expected.argument_stack_offset) &&
                  result.locations[0].kind == expected.result_kind &&
                  (expected.result_kind != AbiLocationKind::stack ||
                   result.locations[0].stack_offset == expected.result_stack_offset) &&
                  (expected.argument_first.empty() || location(argument).register_name == expected.argument_first) &&
                  (expected.argument_second.empty() ||
                   (argument.locations.size() > 1 && location(argument, 1).register_name == expected.argument_second)) &&
                  (expected.result_first.empty() || location(result).register_name == expected.result_first) &&
                  (expected.result_second.empty() ||
                   (result.locations.size() > 1 && location(result, 1).register_name == expected.result_second)),
                  expected.name);
        }

        const auto pointer32 = types::Type::pointer(types::Type::void_type(), 4, 4).value();
        const auto pointer_record32 = types::Type::structure("PointerRecord32",
            {{"pointer", pointer32, 0}}, 4, 4).value();
        const auto pointer_record_windows = classify_abi_signature(CallingConvention::windows_x64,
            *function(pointer_record32, {pointer_record32}));
        check(pointer_record_windows.result.locations.size() == 1 &&
              pointer_record_windows.result.locations[0].register_name == "RAX" &&
              pointer_record_windows.result.locations[0].size == 8 &&
              pointer_record_windows.arguments[0].locations[0].register_name == "RCX" &&
              pointer_record_windows.arguments[0].locations[0].size == 8,
              "Windows x64 aggregate result uses computed ABI layout consistently with its argument");

        const auto f32 = floating(4);
        const auto i32 = integer(4);
        const auto pair = types::Type::structure("Pair", {{"x", integer(8), 0}, {"y", integer(8), 8}}, 16, 8).value();
        const auto mixed = types::Type::structure("Mixed", {{"x", floating(8), 0}, {"y", integer(8), 8}}, 16, 8).value();
        const auto nested = types::Type::structure("Nested", {{"values", types::Type::array(f32, 2).value(), 0}}, 8, 4).value();
        const auto sysv_aggregates = classify_abi_signature(CallingConvention::sysv_x86_64,
            *function(pair, {mixed, nested}));
        check(sysv_aggregates.result.supported && sysv_aggregates.result.locations.size() == 2 &&
              location(sysv_aggregates.result).register_name == "RAX" &&
              location(sysv_aggregates.result, 1).register_name == "RDX",
              "SysV two INTEGER eightbytes return in RAX and RDX");
        check(sysv_aggregates.arguments[0].supported && sysv_aggregates.arguments[0].locations.size() == 2 &&
              location(sysv_aggregates.arguments[0]).register_name == "XMM0" &&
              location(sysv_aggregates.arguments[0], 1).register_name == "RDI",
              "SysV mixed aggregate recursively classifies SSE and INTEGER eightbytes");
        check(sysv_aggregates.arguments[1].locations.size() == 1 &&
              location(sysv_aggregates.arguments[1]).register_name == "XMM1",
              "SysV recursively classifies floating arrays");
        const auto choice = types::Type::union_type("Choice", {{"i", integer(8), 0}, {"f", floating(8), 0}}, 8, 8).value();
        const auto sysv_union = classify_abi_signature(CallingConvention::sysv_x86_64,
            *function(types::Type::void_type(), {choice}));
        check(sysv_union.arguments[0].supported && location(sysv_union.arguments[0]).register_name == "RDI",
              "SysV union members merge their register classes with INTEGER precedence");
    });
}
