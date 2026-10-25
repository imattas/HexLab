#include "hexlab/decompiler/decompiler.hpp"

#include <array>
#include <cstdlib>
#include <iostream>

using namespace hexlab;
using namespace hexlab::decompiler;

namespace {
void require(bool ok, const char *message) {
    if (!ok) { std::cerr << message << '\n'; std::exit(1); }
}
Instruction decode(std::uint32_t word, ExecutionMode mode, ByteOrder order, std::uint64_t address = 0x1000) {
    std::array<std::byte, 4> bytes{};
    for (unsigned n = 0; n < 4; ++n) {
        const auto shift = order == ByteOrder::big ? (3 - n) * 8 : n * 8;
        bytes[n] = std::byte((word >> shift) & 0xff);
    }
    auto result = decode_instruction({Architecture::powerpc, mode, order}, bytes, {{0}, address});
    require(result.status == DecodeStatus::decoded && result.instruction, "literal PPC fixture decodes");
    return std::move(*result.instruction);
}
LiftedFunction lift(std::vector<Instruction> instructions) {
    auto block = std::make_shared<BasicBlock>(); block->id = BlockId{1}; block->begin = instructions.front().address;
    for (std::size_t n = 0; n < instructions.size(); ++n)
        block->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{n + 1, std::move(instructions[n]), {}}));
    FunctionRecord record; record.id = FunctionId{1}; record.entry = block->begin; record.blocks = {block->id};
    FunctionSnapshot snapshot; snapshot.blocks = {block};
    auto result = lift_function(record, snapshot);
    require(bool(result), "PPC function lifts");
    return std::move(result).value();
}
}

int main() {
    // Known PPC32 and PPC64 encodings, deliberately stored in opposite byte orders.
    auto addi32 = decode((14u << 26) | (3u << 21) | (4u << 16) | 7u, ExecutionMode::ppc32, ByteOrder::big);
    auto addi64 = decode((14u << 26) | (5u << 21) | (6u << 16) | 0xfffcu, ExecutionMode::ppc64, ByteOrder::little, 0x1004);
    require(addi32.register_writes.front().width == 32 && addi64.register_writes.front().width == 64,
            "PPC32/64 fixtures retain architecture width through lifting input");
    auto arithmetic = lift({addi32, addi64});
    const auto *a32 = std::get_if<Assign>(&arithmetic.blocks[0].instructions[0].statement);
    const auto *a64 = std::get_if<Assign>(&arithmetic.blocks[0].instructions[1].statement);
    const auto *sum = a32 ? std::get_if<BinaryValue>(&a32->value->value) : nullptr;
    const auto *imm = sum ? std::get_if<ConstantValue>(&sum->right->value) : nullptr;
    require(a32 && a32->value->type.bits == 32 && sum && sum->operation == "add" && imm && imm->value == 7,
            "ADDI lowers to a typed PPC32 add expression");
    require(a64 && a64->value->type.bits == 64 && format_pseudocode(arithmetic).find("0xfffffffffffffffc") != std::string::npos,
            "ADDI sign-extends a PPC64 immediate");

    const auto add = decode((31u << 26) | (4u << 21) | (5u << 16) | (6u << 11) | (266u << 1), ExecutionMode::ppc32, ByteOrder::big);
    const auto lwz = decode((32u << 26) | (3u << 21) | (4u << 16) | 0xfff0u, ExecutionMode::ppc64, ByteOrder::big, 0x1004);
    const auto stw = decode((36u << 26) | (3u << 21) | (4u << 16) | 8u, ExecutionMode::ppc32, ByteOrder::big, 0x1008);
    auto memory = lift({add, lwz, stw});
    require(std::get_if<Assign>(&memory.blocks[0].instructions[0].statement) &&
                std::get_if<Assign>(&memory.blocks[0].instructions[1].statement) &&
                std::get_if<Store>(&memory.blocks[0].instructions[2].statement),
            "X-form arithmetic and D-form word loads/stores become typed assignments and stores");
    const auto *load = std::get_if<Assign>(&memory.blocks[0].instructions[1].statement);
    const auto *zero_extend = load ? std::get_if<UnaryValue>(&load->value->value) : nullptr;
    require(zero_extend && zero_extend->operation == "zext" && zero_extend->operand->type.bits == 32,
            "LWZ zero-extends its 32-bit memory result");

    const auto bc = decode((16u << 26) | (12u << 21) | (2u << 16) | 0x10u, ExecutionMode::ppc64, ByteOrder::big);
    const auto ret = decode((19u << 26) | (20u << 21) | (16u << 1), ExecutionMode::ppc64, ByteOrder::big, 0x1004);
    auto control = lift({bc, ret});
    require(std::get_if<Branch>(&control.blocks[0].instructions[0].statement) &&
                std::get_if<Return>(&control.blocks[0].instructions[1].statement) &&
                format_pseudocode(control).find("loc_1010") != std::string::npos &&
                format_pseudocode(control).find("return;") != std::string::npos,
            "conditional direct branch retains target and canonical BCLR becomes a void return");
    std::cout << "PowerPC typed lifting coverage passed\n";
}
