#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/loaders/cil.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>

using namespace hexlab;
using namespace hexlab::decompiler;

namespace {
void require(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
ManagedMethodAnalysis method(std::vector<std::byte> il) {
    ManagedMethodAnalysis result;
    result.method.token = 0x06000001;
    result.method.name = "Compute";
    result.method.declaring_type = "Demo.Program";
    result.status = ManagedMethodStatus::decoded;
    CilMethodBody body;
    body.max_stack = 8;
    body.il = std::move(il);
    result.body = std::move(body);
    auto decoded = decode_cil_instructions(result.body->il);
    if (!decoded) throw std::runtime_error(decoded.error().message);
    result.instructions = std::move(decoded.value());
    return result;
}
void core_stack_cfg_and_pseudocode() {
    // local_0 = arg_0 + 1; if (local_0) local_0 = 1; else local_0 = 0; return local_0.
    auto input = method({std::byte{0x02}, std::byte{0x17}, std::byte{0x58}, std::byte{0x0a},
                         std::byte{0x06}, std::byte{0x2d}, std::byte{0x04}, std::byte{0x16},
                         std::byte{0x0a}, std::byte{0x2b}, std::byte{0x02}, std::byte{0x17},
                         std::byte{0x0a}, std::byte{0x06}, std::byte{0x2a}});
    auto result = decompile_managed_method(input);
    if (!result) throw std::runtime_error(result.error().message);
    require(bool(result), "CIL stack and control-flow lifting succeeds");
    require(result.value().lifted.blocks.size() == 4, "CIL branch leaders form distinct IR blocks");
    require(result.value().pseudocode.text.find("arg_0") != std::string::npos &&
            result.value().pseudocode.text.find("local_0") != std::string::npos &&
            result.value().pseudocode.text.find("+ 0x1") != std::string::npos,
            "pseudocode preserves argument, local and arithmetic expressions");
    require(result.value().pseudocode.text.find("if (") != std::string::npos &&
            result.value().pseudocode.text.find("return local_0") != std::string::npos,
            "pseudocode retains conditional control flow and return value");
}
void exception_regions_are_preserved_and_use_opaque_fallback() {
    auto input = method({std::byte{0x00}, std::byte{0x2a}});
    input.body->has_more_sections = true;
    input.body->exception_clauses.push_back({CilExceptionKind::finally_clause, 0, 1, 1, 1, 0, 0});
    auto result = decompile_managed_method(input);
    require(!result && result.error().code == ErrorCode::unsupported,
            "CIL EH clause is retained without inventing dispatch or finally edges");
}
void tokenized_calls_and_returns() {
    auto input = method({std::byte{0x02}, std::byte{0x28}, std::byte{0x02}, std::byte{0x00},
                         std::byte{0x00}, std::byte{0x06}, std::byte{0x2a}});
    input.resolved_call_signatures.emplace(0x06000002, ManagedMethodSignature{1,false,true});
    auto result = decompile_managed_method(input);
    require(bool(result), "signature-resolved CIL call lifts");
    require(result.value().referenced_tokens == std::vector<std::uint32_t>{0x06000002},
            "called MethodDef token is retained");
    require(result.value().pseudocode.text.find("call_0x06000002(arg_0)") != std::string::npos,
            "pseudocode preserves call token and argument expression");
    require(result.value().pseudocode.text.find("return call_0x06000002") != std::string::npos,
            "call result reaches method return");
}
void evaluation_stack_merges() {
    // Both conditional arms leave one Int32 value for the shared ret.
    auto input = method({std::byte{0x02}, std::byte{0x2d}, std::byte{0x03},
                         std::byte{0x17}, std::byte{0x2b}, std::byte{0x03},
                         std::byte{0x18}, std::byte{0x2b}, std::byte{0x00},
                         std::byte{0x2a}});
    auto result = decompile_managed_method(input);
    if (!result) throw std::runtime_error("compatible merge: " + result.error().message);
    require(bool(result), "compatible non-empty CIL branch stacks merge");
    const auto join = std::find_if(result.value().lifted.blocks.begin(), result.value().lifted.blocks.end(),
                                   [](const auto &block) { return block.begin.offset == 9; });
    require(join != result.value().lifted.blocks.end() && join->phis.size() == 1 && join->phis[0].inputs.size() == 2,
            "CIL stack merge creates an SSA phi with both predecessor values");
    require(result.value().pseudocode.text.find("return stack_0_") != std::string::npos,
            "CIL stack phi feeds the merged return value");

    auto depth_mismatch = method({std::byte{0x02}, std::byte{0x2d}, std::byte{0x03},
                                  std::byte{0x17}, std::byte{0x2b}, std::byte{0x00},
                                  std::byte{0x2a}});
    auto depth_result = decompile_managed_method(depth_mismatch);
    require(!depth_result && depth_result.error().code == ErrorCode::malformed,
            "CIL merge with unequal evaluation-stack depths is malformed");

    auto type_mismatch = method({std::byte{0x02}, std::byte{0x2d}, std::byte{0x03},
                                 std::byte{0x17}, std::byte{0x2b}, std::byte{0x0b},
                                 std::byte{0x21}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                                 std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                                 std::byte{0x2b}, std::byte{0x00}, std::byte{0x2a}});
    auto type_result = decompile_managed_method(type_mismatch);
    require(!type_result && type_result.error().code == ErrorCode::malformed,
            "CIL merge with incompatible stack types is malformed");
}
void call_values_survive_stack_merges() {
    auto input = method({std::byte{0x02}, std::byte{0x2d}, std::byte{0x07},
                         std::byte{0x28}, std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x06},
                         std::byte{0x2b}, std::byte{0x07},
                         std::byte{0x28}, std::byte{0x03}, std::byte{0x00}, std::byte{0x00}, std::byte{0x06},
                         std::byte{0x2b}, std::byte{0x00}, std::byte{0x2a}});
    input.resolved_call_signatures.emplace(0x06000002, ManagedMethodSignature{0, false, true});
    input.resolved_call_signatures.emplace(0x06000003, ManagedMethodSignature{0, false, true});
    auto result = decompile_managed_method(input);
    require(bool(result), "signature-resolved call results cross conditional edges");
    require(result.value().referenced_tokens == std::vector<std::uint32_t>{0x06000002, 0x06000003},
            "call tokens remain attached to both branches and the join");
    const auto join = std::find_if(result.value().lifted.blocks.begin(), result.value().lifted.blocks.end(),
                                   [](const auto &block) { return block.begin.offset == 17; });
    require(join != result.value().lifted.blocks.end() && join->phis.size() == 1 && join->phis[0].inputs.size() == 2,
            "opaque call results merge without inventing a concrete type");
    std::size_t unknown_effect_calls = 0;
    for (const auto &block : result.value().lifted.blocks)
        for (const auto &instruction : block.instructions)
            if (const auto *intrinsic = std::get_if<Intrinsic>(&instruction.statement);
                intrinsic && intrinsic->name.starts_with("call_0x")) {
                require(intrinsic->memory_effect == IntrinsicMemoryEffect::unknown,
                        "stack materialization preserves unknown call memory effects");
                ++unknown_effect_calls;
            }
    require(unknown_effect_calls == 2, "both call effects remain represented after stack merging");
}
void explicit_failure_cases() {
    auto exception_sections = method({std::byte{0x2a}});
    exception_sections.body->has_more_sections = true;
    require(decompile_managed_method(exception_sections).error().code == ErrorCode::unsupported,
            "CIL methods with unmodeled extra sections are rejected");
    auto underflow = method({std::byte{0x58}, std::byte{0x2a}});
    require(decompile_managed_method(underflow).error().code == ErrorCode::malformed,
            "CIL evaluation-stack underflow is rejected as malformed");
    auto overflow = method({std::byte{0x17}, std::byte{0x17}, std::byte{0x58}, std::byte{0x2a}});
    overflow.body->max_stack = 1;
    require(decompile_managed_method(overflow).error().code == ErrorCode::malformed,
            "CIL declared max_stack is enforced");
    auto unknown = method({std::byte{0xff}, std::byte{0x2a}});
    auto partial = decompile_managed_method(unknown);
    require(bool(partial) && !partial.value().complete && !partial.value().lifted.diagnostics.empty(),
            "unknown opcode remains explicit and marks decompilation incomplete");
    auto known_unsupported = method({std::byte{0x7e}, std::byte{0x01}, std::byte{0x00},
                                    std::byte{0x00}, std::byte{0x04}, std::byte{0x2a}});
    auto unsupported = decompile_managed_method(known_unsupported);
    require(bool(unsupported) && !unsupported.value().complete && !unsupported.value().lifted.diagnostics.empty(),
            "known unsupported opcode remains explicit and marks decompilation incomplete");
    auto unresolved_call = method({std::byte{0x28}, std::byte{0x02}, std::byte{0x00},
                                   std::byte{0x00}, std::byte{0x06}, std::byte{0x2a}});
    require(decompile_managed_method(unresolved_call).error().code == ErrorCode::unsupported,
            "calls without signature metadata are explicitly unsupported");
}
}

int main() {
    try {
        core_stack_cfg_and_pseudocode();
        exception_regions_are_preserved_and_use_opaque_fallback();
        tokenized_calls_and_returns();
        evaluation_stack_merges();
        call_values_survive_stack_merges();
        explicit_failure_cases();
        std::cout << "managed CIL decompiler tests passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
