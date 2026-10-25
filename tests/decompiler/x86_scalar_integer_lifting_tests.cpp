#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/processors/decoder.hpp"

#include <cstdlib>
#include <iostream>

using namespace hexlab;
using namespace hexlab::decompiler;
namespace {
void check(bool value, const char *message) { if (!value) { std::cerr << message << '\n'; std::exit(1); } }
Instruction decode(std::initializer_list<unsigned char> raw, Address at) {
    std::vector<std::byte> bytes;
    for (const auto value : raw) bytes.push_back(std::byte{value});
    auto result = decode_instruction({Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little}, bytes, at);
    check(result.status == DecodeStatus::decoded && result.instruction, "scalar test fixture decodes");
    return *result.instruction;
}
Intrinsic lift(Instruction instruction) {
    auto block = std::make_shared<BasicBlock>();
    block->id = BlockId{1}; block->begin = instruction.address;
    block->instructions = {std::make_shared<InstructionFact>(InstructionFact{1, std::move(instruction), {}})};
    FunctionRecord record; record.id = FunctionId{1}; record.entry = block->begin; record.blocks = {block->id};
    FunctionSnapshot snapshot; snapshot.blocks = {block};
    auto result = lift_function(record, snapshot);
    check(result && std::holds_alternative<Intrinsic>(result.value().blocks[0].instructions[0].statement),
          "scalar arithmetic lifts to explicit intrinsic");
    return std::get<Intrinsic>(result.value().blocks[0].instructions[0].statement);
}
}
int main() {
    const Address at{{0}, 0x4000};
    auto add = lift(decode({0x48, 0x01, 0xd8}, at)); // add rax,rbx
    check(add.name == "x86_add_i64" && add.operands.size() == 2 && add.result_type &&
          add.result_type->kind == TypeKind::integer && add.result_type->bits == 64 &&
          add.operands[0]->type.bits == 64 && add.operands[1]->type.bits == 64,
          "ADD keeps decoded operand width through typed IR");
    check(add.register_writes.size() == 2 && add.register_writes[0].bank == RegisterBank::gpr &&
          add.register_writes[1].bank == RegisterBank::flags,
          "ADD carries both destination and FLAGS definitions");

    auto sub = lift(decode({0x83, 0xe8, 0xff}, at)); // sub eax,-1 (sign-extended imm8)
    const auto *negative_immediate = std::get_if<ConstantValue>(&sub.operands[1]->value);
    check(sub.name == "x86_sub_i32" && sub.result_type && sub.result_type->bits == 32 &&
          sub.operands[1]->type.bits == 32 && negative_immediate && negative_immediate->value == 0xffffffffu,
          "negative sign-extended imm8 is lifted as the destination-width bit pattern");

    auto cmp = lift(decode({0x48, 0x39, 0xd8}, at)); // cmp rax,rbx
    check(cmp.name == "x86_cmp_i64" && !cmp.result_type && cmp.register_writes.size() == 1 &&
          cmp.register_writes[0].bank == RegisterBank::flags,
          "CMP defines FLAGS without inventing a destination result");

    auto test = lift(decode({0x85, 0xc0}, at)); // test eax,eax
    check(test.name == "x86_test_i32" && !test.result_type && test.operands[0]->type.bits == 32 &&
          test.register_writes.size() == 1 && test.register_writes[0].bank == RegisterBank::flags,
          "TEST preserves width and flag-only output");

    auto logic = lift(decode({0x48, 0x21, 0xd8}, at)); // and rax,rbx
    check(logic.name == "x86_and_i64" && logic.result_type && logic.register_writes.size() == 2,
          "logical arithmetic retains typed result and flag writes");

    auto memory_add = lift(decode({0x48, 0x01, 0x18}, at)); // add qword ptr [rax],rbx
    check(memory_add.name == "x86_add_i64" && !memory_add.result_type &&
          memory_add.memory_effect == IntrinsicMemoryEffect::unknown &&
          memory_add.register_writes.size() == 1 && memory_add.register_writes[0].bank == RegisterBank::flags &&
          std::holds_alternative<MemoryValue>(memory_add.operands[0]->value),
          "memory-destination arithmetic keeps read-modify-write memory and FLAGS effects");

    auto memory_cmp = lift(decode({0x48, 0x3b, 0x18}, at)); // cmp rbx,qword ptr [rax]
    check(memory_cmp.name == "x86_cmp_i64" && memory_cmp.memory_effect == IntrinsicMemoryEffect::read &&
          memory_cmp.register_writes.size() == 1 && memory_cmp.register_writes[0].bank == RegisterBank::flags,
          "memory comparison reads its source without inventing a write");
}
