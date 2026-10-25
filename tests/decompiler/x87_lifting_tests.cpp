#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/processors/decoder.hpp"
#include <cstdlib>
#include <array>
#include <iostream>

using namespace hexlab;
using namespace hexlab::decompiler;

namespace {
void require(bool condition, const char *message) {
    if (!condition) { std::cerr << message << '\n'; std::exit(1); }
}
Instruction decode(std::initializer_list<unsigned> raw, std::uint64_t address) {
    std::array<std::byte, 15> bytes{};
    std::size_t length = 0;
    for (const auto value : raw) bytes[length++] = static_cast<std::byte>(value);
    auto decoded = decode_x64(std::span(bytes.data(), length), Address{{0}, address});
    require(decoded.status == DecodeStatus::decoded && decoded.instruction, "x87 literal decodes");
    return std::move(*decoded.instruction);
}
LiftedFunction lift(std::vector<Instruction> instructions) {
    auto block = std::make_shared<BasicBlock>();
    block->id = BlockId{1}; block->begin = Address{{0}, 0x1000};
    for (std::size_t n = 0; n < instructions.size(); ++n) {
        block->instructions.push_back(std::make_shared<InstructionFact>(
            InstructionFact{n + 1, std::move(instructions[n]), {}}));
    }
    FunctionRecord record; record.id = FunctionId{1}; record.entry = block->begin; record.blocks = {block->id};
    FunctionSnapshot snapshot; snapshot.blocks = {block};
    auto result = lift_function(record, snapshot);
    require(bool(result), "x87 function lifts");
    return std::move(result).value();
}
}

int main() {
    const auto code = lift({decode({0xd9, 0x00}, 0x1000),   // fld dword ptr [rax]
                           decode({0xd8, 0xc1}, 0x1002),   // fadd st, st(1)
                           decode({0xdd, 0x18}, 0x1004)}); // fstp qword ptr [rax]
    require(code.blocks[0].instructions.size() == 3, "x87 sequence remains three instructions");
    const auto &load = std::get<Intrinsic>(code.blocks[0].instructions[0].statement);
    require(load.name == "x87_fld" && load.memory_effect == IntrinsicMemoryEffect::read &&
                load.register_writes == std::vector<RegisterOperand>{{RegisterBank::x87, 0, 80, false}},
            "FLD is a typed x87 stack push with a read memory effect");
    const auto *loaded_value = load.operands.empty() ? nullptr : &load.operands.front()->type;
    require(loaded_value && loaded_value->kind == TypeKind::floating && loaded_value->bits == 32,
            "FLD preserves its source floating width");
    const auto &add = std::get<Intrinsic>(code.blocks[0].instructions[1].statement);
    require(add.name == "x87_fadd" && add.result_type == ValueType{TypeKind::floating, 80, false} &&
                add.register_writes == std::vector<RegisterOperand>{{RegisterBank::x87, 0, 80, false}},
            "FADD carries an 80-bit result and ST0 write");
    const auto &store = std::get<Intrinsic>(code.blocks[0].instructions[2].statement);
    require(store.name == "x87_fstp" && store.memory_effect == IntrinsicMemoryEffect::write &&
                store.register_writes == std::vector<RegisterOperand>{{RegisterBank::x87, 0, 80, false}},
            "FSTP combines memory write and x87 stack pop effects");
    require(format_pseudocode(code).find("x87_fadd") != std::string::npos,
            "x87 operation remains visible in pseudocode");

    const auto integer_code = lift({decode({0xdb, 0x00}, 0x1010), // fild dword ptr [rax]
                                    decode({0xda, 0x00}, 0x1012), // fiadd dword ptr [rax]
                                    decode({0xdb, 0x18}, 0x1014)}); // fistp dword ptr [rax]
    const auto &integer_load = std::get<Intrinsic>(integer_code.blocks[0].instructions[0].statement);
    const auto &integer_add = std::get<Intrinsic>(integer_code.blocks[0].instructions[1].statement);
    const auto &integer_store = std::get<Intrinsic>(integer_code.blocks[0].instructions[2].statement);
    require(integer_load.operands[0]->type == ValueType{TypeKind::integer, 32, false} &&
                integer_load.result_type == ValueType{TypeKind::floating, 80, false},
            "FILD converts an integer memory source to the x87 stack type");
    require(integer_add.operands.size() == 2 &&
                integer_add.operands[0]->type == ValueType{TypeKind::integer, 32, false} &&
                integer_add.operands[1]->type == ValueType{TypeKind::floating, 80, false} &&
                integer_add.register_writes == std::vector<RegisterOperand>{{RegisterBank::x87, 0, 80, false}},
            "FIADD keeps the integer memory operand separate from implicit ST0");
    require(integer_store.memory_effect == IntrinsicMemoryEffect::write &&
                integer_store.operands[0]->type == ValueType{TypeKind::integer, 32, false} &&
                !integer_store.result_type,
            "FISTP retains integer store width without inventing a floating result");
}
