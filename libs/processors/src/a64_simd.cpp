#include "a64_internal.hpp"

namespace hexlab::a64_detail {
namespace {
RegisterOperand vreg(unsigned index, unsigned width) {
    return {RegisterBank::arm64_simd, static_cast<std::uint8_t>(index),
            static_cast<std::uint16_t>(width), false};
}

void three_registers(Instruction &instruction, Opcode opcode, std::uint32_t word,
                     unsigned vector_bits, unsigned element_bits) {
    const auto destination = vreg(word & 31, vector_bits);
    const auto left = vreg((word >> 5) & 31, vector_bits);
    const auto right = vreg((word >> 16) & 31, vector_bits);
    instruction.opcode = opcode;
    instruction.vector_bits = static_cast<std::uint16_t>(vector_bits);
    instruction.vector_element_bits = static_cast<std::uint16_t>(element_bits);
    operand(instruction, destination, OperandAccess::write);
    operand(instruction, left, OperandAccess::read);
    operand(instruction, right, OperandAccess::read);

    // D-form AdvSIMD writes clear the upper half of the architectural V
    // register. Keep the encoded low-half destination for formatting and
    // also publish the full-register write for data-flow clients.
    if (vector_bits == 64)
        instruction.register_writes.push_back(vreg(word & 31, 128));
}
} // namespace

bool simd(Instruction &instruction, std::uint32_t word) {
    const unsigned vector_bits = (word & (1u << 30)) ? 128 : 64;
    const unsigned size = (word >> 22) & 3;

    // Floating-point three-same vector arithmetic. Accept only single and
    // double arrangements; half precision requires explicit feature gating.
    const auto fp_class = word & 0x9f20fc00u;
    std::optional<Opcode> fp_opcode;
    if (fp_class == 0x0e20d400u) fp_opcode = Opcode::a64_fadd;
    else if (fp_class == 0x0ea0d400u) fp_opcode = Opcode::a64_fsub;
    else if (fp_class == 0x0e20dc00u) fp_opcode = Opcode::a64_fmul;
    else if (fp_class == 0x0e20fc00u) fp_opcode = Opcode::a64_fdiv;
    else if (fp_class == 0x0e20f400u) fp_opcode = Opcode::a64_fmax;
    else if (fp_class == 0x0ea0f400u) fp_opcode = Opcode::a64_fmin;
    if (fp_opcode) {
        if (size > 1 || (size == 1 && vector_bits != 128)) return false;
        three_registers(instruction, *fp_opcode, word, vector_bits, size == 0 ? 32 : 64);
        return true;
    }

    // ADD/SUB (vector), integer three-same. The size field is the lane
    // element width; 64-bit lanes require the 128-bit Q arrangement.
    if ((word & 0x9f20fc00u) == 0x0e208400u) {
        if (vector_bits == 64 && size == 3) return false;
        const unsigned element_bits = 8u << size;
        three_registers(instruction, (word & (1u << 29)) ? Opcode::a64_vsub : Opcode::a64_vadd,
                        word, vector_bits, element_bits);
        return true;
    }

    // AND/ORR/EOR (vector). Their arrangement is byte-oriented; bits 23:21
    // distinguish the operation and are reserved as part of the fixed mask.
    const auto logical_class = word & 0xbfe0fc00u;
    Opcode logical_opcode;
    if (logical_class == 0x0e201c00u) logical_opcode = Opcode::a64_vand;
    else if (logical_class == 0x0ea01c00u) logical_opcode = Opcode::a64_vorr;
    else if (logical_class == 0x2e201c00u) logical_opcode = Opcode::a64_veor;
    else return false;

    three_registers(instruction, logical_opcode, word, vector_bits, 8);
    return true;
}
} // namespace hexlab::a64_detail
