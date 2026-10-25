#include "hexlab/processors/x86_sse2_integer_semantics.hpp"

#include <array>
#include <cstdlib>
#include <iostream>

using namespace hexlab;
namespace {
void check(bool value, const char *message) {
    if (!value) { std::cerr << message << '\n'; std::exit(1); }
}
std::array<std::byte, 16> bytes(std::initializer_list<unsigned> values) {
    std::array<std::byte, 16> out{};
    std::size_t i = 0;
    for (auto value : values) { if (i < out.size()) out[i++] = static_cast<std::byte>(value); }
    return out;
}
Instruction instruction(Opcode opcode) {
    Instruction i;
    i.context = {Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little};
    i.opcode = opcode;
    i.operands = {RegisterOperand{RegisterBank::xmm, 0, 128, false},
                  RegisterOperand{RegisterBank::xmm, 1, 128, false}};
    return i;
}
void arithmetic_and_logic() {
    const auto a = bytes({0xff,0xff,0xff,0x7f, 1,0,0,0, 0,0,0,0, 0xfe,0xff,0xff,0xff});
    const auto b = bytes({1,0,0,0, 2,0,0,0, 0,0,0,0, 3,0,0,0});
    auto add = evaluate_x86_sse2_packed_integer(instruction(Opcode::paddd), a, b);
    check(add && add->lane_bits == 32 && add->bytes[0] == std::byte{0} &&
          add->bytes[1] == std::byte{0} && add->bytes[2] == std::byte{0} &&
          add->bytes[3] == std::byte{0x80}, "PADDD wraps independently at signed boundary");
    check(add->bytes[4] == std::byte{3}, "PADDD keeps lanes independent");
    auto sub = evaluate_x86_sse2_packed_integer(instruction(Opcode::psubq), a, b);
    check(sub && sub->lane_bits == 64 && sub->bytes[0] == std::byte{0xfe}, "PSUBQ wraps modulo 64 bits");
    auto logic = evaluate_x86_sse2_packed_integer(instruction(Opcode::pxor), a, b);
    check(logic && logic->lane_bits == 0 && logic->bytes[0] == std::byte{0xfe}, "PXOR evaluates full vector bitwise");
}
void compares() {
    const auto signed_lanes = bytes({0xff,0x7f, 0x00,0x80, 1,0, 0xff,0xff,
                                     0x80,0xff,0,0, 0,0,0,0});
    const auto zero = bytes({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0});
    auto gt = evaluate_x86_sse2_packed_integer(instruction(Opcode::pcmpgtw), signed_lanes, zero);
    check(gt && gt->lane_bits == 16 && gt->bytes[0] == std::byte{0xff} &&
          gt->bytes[1] == std::byte{0xff} && gt->bytes[2] == std::byte{0} &&
          gt->bytes[3] == std::byte{0}, "PCMPGTW uses signed comparisons and all-ones masks");
    auto eq = evaluate_x86_sse2_packed_integer(instruction(Opcode::pcmpeqd), zero, zero);
    check(eq && eq->bytes[0] == std::byte{0xff} && eq->bytes[3] == std::byte{0xff} &&
          eq->bytes[4] == std::byte{0xff}, "PCMPEQD equal lanes become all-one masks");
}
void validation() {
    auto wrong = instruction(Opcode::paddd);
    wrong.context.architecture = Architecture::arm64;
    std::array<std::byte,16> zero{};
    check(!evaluate_x86_sse2_packed_integer(wrong, zero, zero), "non-x86 instruction rejected");
    check(!evaluate_x86_sse2_packed_integer(instruction(Opcode::add), zero, zero), "unsupported opcode rejected");
}
void opcode_coverage() {
    constexpr Opcode supported[]{Opcode::paddd, Opcode::paddq, Opcode::psubd, Opcode::psubq,
        Opcode::pand, Opcode::por, Opcode::pxor, Opcode::pcmpeqb, Opcode::pcmpeqw,
        Opcode::pcmpeqd, Opcode::pcmpgtb, Opcode::pcmpgtw, Opcode::pcmpgtd};
    std::array<std::byte,16> zero{};
    for (auto opcode : supported)
        check(evaluate_x86_sse2_packed_integer(instruction(opcode), zero, zero).has_value(),
              "every decoded SSE2 packed integer arithmetic, logic, and compare opcode evaluates");
    auto with_memory = instruction(Opcode::paddd);
    MemoryOperand source{};
    source.address_width = 64;
    source.data_width = 128;
    with_memory.operands[1] = source;
    check(evaluate_x86_sse2_packed_integer(with_memory, zero, zero).has_value(),
          "SSE2 packed operation accepts a full-width memory source");
    source.data_width = 64;
    with_memory.operands[1] = source;
    check(!evaluate_x86_sse2_packed_integer(with_memory, zero, zero),
          "SSE2 packed operation rejects a short memory source");
}
}
int main() { arithmetic_and_logic(); compares(); validation(); opcode_coverage(); }
