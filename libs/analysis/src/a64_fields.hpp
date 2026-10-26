#pragma once
#include "hexlab/processors/decoder.hpp"
namespace hexlab::analysis_detail {
// This is the original instruction-word footprint, not a byte-aligned operand
// field. The instruction keeps its packed EncodedField absent.
inline bool a64_packed_operand(const Instruction &i, std::uint32_t index) {
    if (i.context != DecodeContext{Architecture::arm64, ExecutionMode::a64, ByteOrder::little} || i.length != 4 ||
        index >= i.operands.size())
        return false;
    const auto canonical = decode_a64(std::span(i.bytes).first(4), i.address);
    if (!canonical.instruction || canonical.instruction->opcode != i.opcode)
        return false;
    switch (i.opcode) {
    case Opcode::a64_b:
    case Opcode::a64_bl:
    case Opcode::a64_b_cond:
        return index == 0;
    case Opcode::a64_cbz:
    case Opcode::a64_cbnz:
    case Opcode::a64_adr:
    case Opcode::a64_adrp:
    case Opcode::a64_movn:
    case Opcode::a64_movz:
    case Opcode::a64_movk:
    case Opcode::a64_ldr:
    case Opcode::a64_ldrsw:
    case Opcode::a64_str:
    case Opcode::a64_ldrb:
    case Opcode::a64_strb:
    case Opcode::a64_ldrh:
    case Opcode::a64_strh:
        return index == 1;
    case Opcode::a64_tbz:
    case Opcode::a64_tbnz:
    case Opcode::a64_add:
    case Opcode::a64_adds:
    case Opcode::a64_sub:
    case Opcode::a64_subs:
        return index == 2;
    default:
        return false;
    }
}
} // namespace hexlab::analysis_detail
