#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/processors/decoder.hpp"

#include <array>
#include <cstdlib>
#include <iostream>

using namespace hexlab;
using namespace hexlab::decompiler;

namespace {
void require(bool condition, const char *message) {
    if (!condition) { std::cerr << message << '\n'; std::exit(1); }
}

LiftedFunction lift_program(std::span<const std::byte> code) {
    auto block = std::make_shared<BasicBlock>();
    block->id = BlockId{1};
    block->begin = Address{{0}, 0x1000};
    std::size_t offset = 0;
    std::uint64_t id = 1;
    while (offset < code.size()) {
        const auto decoded = decode_m6502(code.subspan(offset), Address{{0}, 0x1000 + offset});
        require(decoded.status == DecodeStatus::decoded && decoded.instruction,
                "fixture is a sequence of documented 6502 instructions");
        offset += decoded.instruction->length;
        block->instructions.push_back(std::make_shared<const InstructionFact>(
            InstructionFact{id++, *decoded.instruction, {}}));
    }
    FunctionRecord function;
    function.id = FunctionId{1};
    function.entry = block->begin;
    function.blocks = {block->id};
    FunctionSnapshot snapshot;
    snapshot.blocks = {block};
    const auto result = lift_function(function, snapshot);
    require(bool(result), "decoded MOS 6502 function lifts");
    return result.value();
}
}

int main() {
    constexpr std::array program{
        std::byte{0xa9}, std::byte{0x2a},             // LDA #$2a
        std::byte{0x8d}, std::byte{0x00}, std::byte{0x20}, // STA $2000
        std::byte{0xaa},                              // TAX
        std::byte{0xe8},                              // INX
        std::byte{0xc9}, std::byte{0x2a},             // CMP #$2a
        std::byte{0xf0}, std::byte{0x00},             // BEQ $100b
        std::byte{0x60}                               // RTS
    };
    const auto lifted = lift_program(program);
    const auto text = format_pseudocode(lifted);
    require(text.find("m6502_load(0x2a, P) /* writes A, P */;") != std::string::npos,
            "LDA immediate defines accumulator and status outputs");
    require(text.find("*[(0x2000)] = A;") != std::string::npos,
            "STA absolute becomes a memory store");
    require(text.find("m6502_transfer(A, P) /* writes X, P */;") != std::string::npos &&
                text.find("m6502_increment(X, ((X + 0x1) & 0xff), P) /* writes X, P */;") != std::string::npos,
            "register transfer and increment retain their register and status effects");
    require(text.find("if (((P & 0x2) == 0x2)) goto loc_100b;") != std::string::npos,
            "BEQ tests the zero bit in the status register");
    require(text.find("return unknown(RTS pulls") != std::string::npos,
            "RTS becomes a function return");
    const auto ssa = to_ssa(lifted);
    require(bool(ssa), "6502 lifted operations convert to SSA");
    const auto ssa_text = format_pseudocode(ssa.value());
    require(ssa_text.find("P_4 = ") != std::string::npos &&
                ssa_text.find("A_1 UGE 0x2a") != std::string::npos &&
                ssa_text.find("A_1 == 0x2a") != std::string::npos &&
                ssa_text.find("signbit((A_1 - 0x2a))") != std::string::npos,
            "CMP explicitly defines carry, zero, and negative bits in the SSA status version");
    require(ssa_text.find("if (((P_4 & 0x2) == 0x2))") != std::string::npos,
            "a following BEQ reads the status version produced by CMP");
}
