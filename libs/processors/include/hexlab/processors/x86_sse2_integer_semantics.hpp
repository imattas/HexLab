#pragma once

#include "hexlab/processors/instruction.hpp"

#include <array>
#include <cstdint>
#include <optional>

namespace hexlab {

// Result of evaluating one 128-bit SSE2 packed-integer operation. `lane_bits`
// is zero for full-vector logical operations and otherwise identifies the
// independent arithmetic/compare lane width.
struct X86Sse2PackedIntegerResult {
    std::array<std::byte, 16> bytes{};
    std::uint8_t lane_bits = 0;
    bool operator==(const X86Sse2PackedIntegerResult &) const = default;
};

namespace x86_sse2_integer_detail {
inline std::uint64_t load_lane(const std::array<std::byte, 16> &value,
                               unsigned offset, unsigned width) noexcept {
    std::uint64_t lane = 0;
    for (unsigned i = 0; i < width / 8; ++i)
        lane |= static_cast<std::uint64_t>(std::to_integer<unsigned>(value[offset + i])) << (i * 8);
    return lane;
}
inline void store_lane(std::array<std::byte, 16> &value, unsigned offset,
                       unsigned width, std::uint64_t lane) noexcept {
    for (unsigned i = 0; i < width / 8; ++i)
        value[offset + i] = static_cast<std::byte>(lane >> (i * 8));
}
inline bool supported(Opcode opcode) noexcept {
    switch (opcode) {
    case Opcode::paddb: case Opcode::paddw: case Opcode::paddd: case Opcode::paddq:
    case Opcode::psubb: case Opcode::psubw: case Opcode::psubd: case Opcode::psubq:
    case Opcode::paddsb: case Opcode::paddsw: case Opcode::paddusb: case Opcode::paddusw:
    case Opcode::psubsb: case Opcode::psubsw: case Opcode::psubusb: case Opcode::psubusw:
    case Opcode::pand: case Opcode::por: case Opcode::pxor:
    case Opcode::pandn:
    case Opcode::psllw: case Opcode::pslld: case Opcode::psllq:
    case Opcode::psrlw: case Opcode::psrld: case Opcode::psrlq: case Opcode::psraw: case Opcode::psrad:
    case Opcode::pcmpeqb: case Opcode::pcmpeqw: case Opcode::pcmpeqd:
    case Opcode::pcmpgtb: case Opcode::pcmpgtw: case Opcode::pcmpgtd:
        return true;
    default: return false;
    }
}
inline bool valid_operand(const Operand &operand, bool destination) noexcept {
    if (const auto *reg = std::get_if<RegisterOperand>(&operand))
        return reg->bank == RegisterBank::xmm && reg->width == 128;
    if (!destination) {
        if (const auto *memory = std::get_if<MemoryOperand>(&operand))
            return memory->data_width == 128;
    }
    return false;
}
} // namespace x86_sse2_integer_detail

// Evaluates supported legacy SSE2 integer packed operations using the actual
// decoded instruction identity. Inputs and result are in architectural byte
// order (byte 0 is the least-significant byte). Memory fetching is caller-owned.
inline std::optional<X86Sse2PackedIntegerResult> evaluate_x86_sse2_packed_integer(
    const Instruction &instruction, const std::array<std::byte, 16> &left,
    const std::array<std::byte, 16> &right) noexcept {
    using namespace x86_sse2_integer_detail;
    if ((instruction.context.architecture != Architecture::x86 &&
         instruction.context.architecture != Architecture::x86_64) ||
        instruction.operands.size() != 2 || !supported(instruction.opcode) ||
        !valid_operand(instruction.operands[0], true))
        return std::nullopt;

    const auto op = instruction.opcode;
    const bool immediate_shift = op == Opcode::psllw || op == Opcode::pslld || op == Opcode::psllq ||
        op == Opcode::psrlw || op == Opcode::psrld || op == Opcode::psrlq || op == Opcode::psraw || op == Opcode::psrad;
    const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[1]);
    if (immediate_shift && immediate) {
        if (immediate->encoded_width != 8 || immediate->effective_width != 8 || immediate->is_signed)
            return std::nullopt;
    } else if (!valid_operand(instruction.operands[1], false)) {
        return std::nullopt;
    }

    X86Sse2PackedIntegerResult result{};
    unsigned lane_bits = 0;
    switch (op) {
    case Opcode::paddd: case Opcode::psubd: case Opcode::pcmpeqd: case Opcode::pcmpgtd:
    case Opcode::pslld: case Opcode::psrld: case Opcode::psrad:
        lane_bits = 32; break;
    case Opcode::paddq: case Opcode::psubq: case Opcode::psllq: case Opcode::psrlq:
        lane_bits = 64; break;
    case Opcode::paddw: case Opcode::psubw: case Opcode::paddsw: case Opcode::paddusw:
    case Opcode::psubsw: case Opcode::psubusw: case Opcode::pcmpeqw: case Opcode::pcmpgtw:
    case Opcode::psllw: case Opcode::psrlw: case Opcode::psraw:
        lane_bits = 16; break;
    case Opcode::paddb: case Opcode::psubb: case Opcode::paddsb: case Opcode::paddusb:
    case Opcode::psubsb: case Opcode::psubusb: case Opcode::pcmpeqb: case Opcode::pcmpgtb:
        lane_bits = 8; break;
    default: break;
    }
    result.lane_bits = static_cast<std::uint8_t>(lane_bits);
    if (lane_bits == 0) {
        for (unsigned offset = 0; offset < 16; ++offset) {
            const auto a = std::to_integer<unsigned>(left[offset]);
            const auto b = std::to_integer<unsigned>(right[offset]);
            const auto value = op == Opcode::pand ? (a & b) : op == Opcode::pandn ? ((~a) & b) :
                               op == Opcode::por ? (a | b) : (a ^ b);
            result.bytes[offset] = static_cast<std::byte>(value);
        }
        return result;
    }

    const auto lane_mask = lane_bits == 64 ? UINT64_MAX : (UINT64_C(1) << lane_bits) - 1;
    for (unsigned offset = 0; offset < 16; offset += lane_bits / 8) {
        const auto a = load_lane(left, offset, lane_bits);
        const auto b = load_lane(right, offset, lane_bits);
        std::uint64_t value = 0;
        if (op == Opcode::psllw || op == Opcode::pslld || op == Opcode::psllq ||
            op == Opcode::psrlw || op == Opcode::psrld || op == Opcode::psrlq ||
            op == Opcode::psraw || op == Opcode::psrad) {
            const auto count = immediate ? immediate->value : load_lane(right, 0, 64);
            const bool left_shift = op == Opcode::psllw || op == Opcode::pslld || op == Opcode::psllq;
            const bool arithmetic = op == Opcode::psraw || op == Opcode::psrad;
            const auto sign = UINT64_C(1) << (lane_bits - 1);
            if (count >= lane_bits) {
                value = arithmetic && (a & sign) ? lane_mask : 0;
            } else if (left_shift) {
                value = (a << static_cast<unsigned>(count)) & lane_mask;
            } else if (arithmetic) {
                value = a >> static_cast<unsigned>(count);
                if (count != 0 && (a & sign))
                    value |= lane_mask ^ (lane_mask >> static_cast<unsigned>(count));
            } else {
                value = a >> static_cast<unsigned>(count);
            }
        } else if (op == Opcode::paddd || op == Opcode::paddq || op == Opcode::paddb || op == Opcode::paddw)
            value = (a + b) & lane_mask;
        else if (op == Opcode::psubd || op == Opcode::psubq || op == Opcode::psubb || op == Opcode::psubw)
            value = (a - b) & lane_mask;
        else if (op == Opcode::paddusb || op == Opcode::paddusw)
            value = a + b > lane_mask ? lane_mask : a + b;
        else if (op == Opcode::psubusb || op == Opcode::psubusw)
            value = a < b ? 0 : a - b;
        else if (op == Opcode::paddsb || op == Opcode::paddsw || op == Opcode::psubsb || op == Opcode::psubsw) {
            const auto sign = UINT64_C(1) << (lane_bits - 1);
            const auto signed_a = (a & sign) ? static_cast<std::int64_t>(a) - static_cast<std::int64_t>(sign * 2)
                                             : static_cast<std::int64_t>(a);
            const auto signed_b = (b & sign) ? static_cast<std::int64_t>(b) - static_cast<std::int64_t>(sign * 2)
                                             : static_cast<std::int64_t>(b);
            auto signed_value = (op == Opcode::paddsb || op == Opcode::paddsw)
                ? signed_a + signed_b : signed_a - signed_b;
            const auto minimum = -static_cast<std::int64_t>(sign);
            const auto maximum = static_cast<std::int64_t>(sign - 1);
            if (signed_value < minimum) signed_value = minimum;
            if (signed_value > maximum) signed_value = maximum;
            value = static_cast<std::uint64_t>(signed_value) & lane_mask;
        }
        else if (op == Opcode::pandn)
            value = (~a) & b;
        else if (op == Opcode::pcmpeqb || op == Opcode::pcmpeqw || op == Opcode::pcmpeqd)
            value = a == b ? lane_mask : 0;
        else {
            const auto sign = UINT64_C(1) << (lane_bits - 1);
            value = ((a ^ sign) > (b ^ sign)) ? lane_mask : 0;
        }
        store_lane(result.bytes, offset, lane_bits, value);
    }
    return result;
}

} // namespace hexlab
