#include "hexlab/decompiler/wasm_lifting.hpp"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <vector>

using namespace hexlab;
using namespace hexlab::decompiler;

namespace {
void require(bool condition, const char *message) {
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

bool has_zero_wasm_stack_result(const LiftedFunction &lifted) {
    for (const auto &block : lifted.blocks)
        for (const auto &item : block.instructions)
            if (const auto *assignment = std::get_if<Assign>(&item.statement);
                assignment && assignment->destination.bank == RegisterBank::wasm_stack) {
                const auto *value = std::get_if<ConstantValue>(&assignment->value->value);
                if (value && value->type.bits == 32 && value->value == 0) return true;
            }
    return false;
}

Instruction instruction(std::uint64_t offset, std::uint8_t opcode,
                        std::initializer_list<std::uint64_t> immediates = {}) {
    Instruction result;
    result.context.architecture = Architecture::wasm;
    result.context.mode = ExecutionMode::wasm32;
    result.address = {{0}, offset};
    result.bytes[0] = static_cast<std::byte>(opcode);
    result.length = 1;
    for (const auto immediate : immediates) {
        result.operands.emplace_back(ImmediateOperand{immediate, 1, 32, false, {}});
        if (result.length < result.bytes.size())
            result.bytes[result.length++] = static_cast<std::byte>(immediate & 0xffU);
    }
    return result;
}
}

int main() {
    // select chooses a non-null function reference, stores it in a local, and
    // then tests that local. The decompiler should carry the proven fact across
    // the local assignment instead of emitting a runtime nullness predicate.
    auto block = std::make_shared<BasicBlock>();
    block->id = BlockId{1};
    block->begin = {{0}, 0};
    const std::vector<Instruction> body{
        instruction(0, 0xd0, {0x70}),    // ref.null funcref
        instruction(2, 0xd2, {0}),       // ref.func 0
        instruction(4, 0x41, {1}),       // i32.const 1
        instruction(6, 0x1b),            // select
        instruction(7, 0x21, {1}),       // local.set 1
        instruction(9, 0x20, {1}),       // local.get 1
        instruction(11, 0xd1),           // ref.is_null
        instruction(12, 0x0b),           // end
    };
    std::uint64_t next_id = 1;
    for (const auto &decoded : body)
        block->instructions.push_back(std::make_shared<InstructionFact>(
            InstructionFact{next_id++, decoded, {}}));

    FunctionRecord function;
    function.id = FunctionId{1};
    function.entry = {{0}, 0};
    function.blocks = {BlockId{1}};
    FunctionSnapshot snapshot;
    snapshot.blocks.push_back(block);

    WasmMetadata metadata;
    metadata.function_type_indices = {0};
    metadata.function_types = {WasmFunctionType{1, 1, {0x70}, {0x7f}}};
    metadata.function_locals = {WasmFunctionLocals{0, {0x70}}};

    auto lifted = lift_wasm_function(function, snapshot, &metadata);
    require(lifted.has_value(), "typed Wasm function lifts");
    require(has_zero_wasm_stack_result(lifted.value()),
            "select-derived non-null fact survives a local assignment and reaches the stack exit as zero");

    // A dynamic condition still proves non-nullness when both alternatives
    // are references to functions.
    block->instructions.clear();
    const std::vector<Instruction> same_nullness_body{
        instruction(0, 0xd2, {0}),       // ref.func 0
        instruction(2, 0xd2, {1}),       // ref.func 1
        instruction(4, 0x20, {0}),       // local.get 0 (dynamic selector)
        instruction(6, 0x1b),            // select
        instruction(7, 0x21, {1}),       // local.set 1
        instruction(9, 0x20, {1}),       // local.get 1
        instruction(11, 0xd1),           // ref.is_null
        instruction(12, 0x0b),           // end
    };
    next_id = 1;
    for (const auto &decoded : same_nullness_body)
        block->instructions.push_back(std::make_shared<InstructionFact>(
            InstructionFact{next_id++, decoded, {}}));
    metadata.function_type_indices = {0, 0};
    metadata.function_types[0].parameter_types[0] = 0x7f;

    lifted = lift_wasm_function(function, snapshot, &metadata);
    require(lifted.has_value(), "dynamic Wasm select function lifts");
    require(has_zero_wasm_stack_result(lifted.value()),
            "select alternatives with matching non-null facts survive a local assignment");
}
