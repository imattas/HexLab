#pragma once

#include "hexlab/processors/instruction.hpp"

#include <algorithm>
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
inline std::int64_t signed_lane(std::uint64_t value, unsigned width) noexcept {
    const auto sign = UINT64_C(1) << (width - 1);
    return (value & sign) ? static_cast<std::int64_t>(value) - static_cast<std::int64_t>(UINT64_C(1) << width)
                          : static_cast<std::int64_t>(value);
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
    case Opcode::phaddw: case Opcode::phaddd: case Opcode::phaddsw:
    case Opcode::phsubw: case Opcode::phsubd: case Opcode::phsubsw:
    case Opcode::pshufb:
    case Opcode::pminub: case Opcode::pmaxub: case Opcode::pminsw: case Opcode::pmaxsw:
    case Opcode::pmullw: case Opcode::pmulhw: case Opcode::pmulhuw:
    case Opcode::pmuludq: case Opcode::pmaddwd: case Opcode::pavgb: case Opcode::pavgw:
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
    if (op == Opcode::pshufb) {
        for (unsigned i = 0; i < 16; ++i) {
            const auto control = std::to_integer<unsigned>(right[i]);
            result.bytes[i] = (control & 0x80) ? std::byte{0} : left[control & 0x0f];
        }
        result.lane_bits = 8;
        return result;
    }
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
    case Opcode::pminsw: case Opcode::pmaxsw: case Opcode::pmullw: case Opcode::pmulhw:
    case Opcode::pmulhuw: case Opcode::pavgw:
    case Opcode::phaddw: case Opcode::phaddsw: case Opcode::phsubw: case Opcode::phsubsw:
        lane_bits = 16; break;
    case Opcode::phaddd: case Opcode::phsubd:
        lane_bits = 32; break;
    case Opcode::pmuludq: lane_bits = 64; break;
    case Opcode::pmaddwd: lane_bits = 32; break;
    case Opcode::paddb: case Opcode::psubb: case Opcode::paddsb: case Opcode::paddusb:
    case Opcode::psubsb: case Opcode::psubusb: case Opcode::pcmpeqb: case Opcode::pcmpgtb:
    case Opcode::pminub: case Opcode::pmaxub: case Opcode::pavgb:
        lane_bits = 8; break;
    default: break;
    }
    result.lane_bits = static_cast<std::uint8_t>(lane_bits);
    const bool horizontal = op == Opcode::phaddw || op == Opcode::phaddd || op == Opcode::phaddsw ||
        op == Opcode::phsubw || op == Opcode::phsubd || op == Opcode::phsubsw;
    if (horizontal) {
        const bool subtract = op == Opcode::phsubw || op == Opcode::phsubd || op == Opcode::phsubsw;
        const bool saturating = op == Opcode::phaddsw || op == Opcode::phsubsw;
        const unsigned lane_bytes = lane_bits / 8;
        for (unsigned half = 0; half < 2; ++half) {
            const auto &input = half == 0 ? left : right;
            for (unsigned pair = 0; pair < 8 / lane_bytes; ++pair) {
                const unsigned src = pair * 2 * lane_bytes;
                const auto a = load_lane(input, src, lane_bits);
                const auto b = load_lane(input, src + lane_bytes, lane_bits);
                std::uint64_t value = subtract ? a - b : a + b;
                if (saturating) {
                    const auto sign = UINT64_C(1) << (lane_bits - 1);
                    const auto signed_a = (a & sign) ? static_cast<std::int64_t>(a) - static_cast<std::int64_t>(sign * 2) : static_cast<std::int64_t>(a);
                    const auto signed_b = (b & sign) ? static_cast<std::int64_t>(b) - static_cast<std::int64_t>(sign * 2) : static_cast<std::int64_t>(b);
                    auto signed_value = subtract ? signed_a - signed_b : signed_a + signed_b;
                    const auto minimum = -static_cast<std::int64_t>(sign);
                    const auto maximum = static_cast<std::int64_t>(sign - 1);
                    if (signed_value < minimum) signed_value = minimum;
                    if (signed_value > maximum) signed_value = maximum;
                    value = static_cast<std::uint64_t>(signed_value);
                }
                store_lane(result.bytes, half * 8 + pair * lane_bytes, lane_bits, value);
            }
        }
        return result;
    }
    // These instructions widen or select lanes and therefore cannot use the
    // ordinary one-result-per-input-lane loop below.
    if (op == Opcode::pmuludq) {
        for (unsigned lane = 0; lane < 2; ++lane) {
            const auto offset = lane * 8;
            const auto product = load_lane(left, offset, 32) * load_lane(right, offset, 32);
            store_lane(result.bytes, offset, 64, product);
        }
        return result;
    }
    if (op == Opcode::pmaddwd) {
        for (unsigned lane = 0; lane < 4; ++lane) {
            const auto offset = lane * 4;
            const auto a0 = signed_lane(load_lane(left, offset, 16), 16);
            const auto a1 = signed_lane(load_lane(left, offset + 2, 16), 16);
            const auto b0 = signed_lane(load_lane(right, offset, 16), 16);
            const auto b1 = signed_lane(load_lane(right, offset + 2, 16), 16);
            const auto sum = static_cast<std::int64_t>(a0) * b0 + static_cast<std::int64_t>(a1) * b1;
            store_lane(result.bytes, lane * 4, 32, static_cast<std::uint64_t>(sum));
        }
        return result;
    }
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
        else if (op == Opcode::pminub) value = std::min(a, b);
        else if (op == Opcode::pmaxub) value = std::max(a, b);
        else if (op == Opcode::pavgb || op == Opcode::pavgw) value = (a + b + 1) >> 1;
        else if (op == Opcode::pminsw || op == Opcode::pmaxsw) {
            const auto signed_a = signed_lane(a, 16);
            const auto signed_b = signed_lane(b, 16);
            value = static_cast<std::uint16_t>(op == Opcode::pminsw
                ? std::min(signed_a, signed_b) : std::max(signed_a, signed_b));
        }
        else if (op == Opcode::pmullw) value = (a * b) & lane_mask;
        else if (op == Opcode::pmulhuw) value = ((a * b) >> 16) & lane_mask;
        else if (op == Opcode::pmulhw) {
            const auto product = static_cast<std::int32_t>(signed_lane(a, 16)) *
                                 static_cast<std::int32_t>(signed_lane(b, 16));
            value = static_cast<std::uint32_t>(product) >> 16;
        }
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
