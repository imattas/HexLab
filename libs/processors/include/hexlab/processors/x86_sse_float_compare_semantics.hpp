#pragma once

#include "hexlab/processors/instruction.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace hexlab {

struct X86SseFloatCompareResult {
    std::array<std::byte, 16> bytes{};
    std::uint8_t lane_bits = 0;
    bool invalid_operation = false;
    bool denormal_operand = false;
    bool completed = true;
    // MXCSR after sticky IE/DE status bits are accumulated. Control and all
    // unsupported status bits retain the caller-provided value.
    std::uint32_t mxcsr_after = 0x1f80;
    bool operator==(const X86SseFloatCompareResult &) const = default;
};

namespace x86_sse_float_compare_detail {
inline bool supported(Opcode opcode) noexcept {
    return opcode == Opcode::cmpps || opcode == Opcode::cmppd ||
           opcode == Opcode::cmpss || opcode == Opcode::cmpsd;
}
inline unsigned lane_bits(Opcode opcode) noexcept {
    return opcode == Opcode::cmppd || opcode == Opcode::cmpsd ? 64u : 32u;
}
inline bool scalar(Opcode opcode) noexcept {
    return opcode == Opcode::cmpss || opcode == Opcode::cmpsd;
}
inline bool vector_register(const Operand &operand) noexcept {
    const auto *reg = std::get_if<RegisterOperand>(&operand);
    return reg && reg->bank == RegisterBank::xmm && reg->width == 128 && !reg->high_byte;
}
inline std::uint64_t load(const std::array<std::byte, 16> &value, unsigned offset,
                          unsigned bits) noexcept {
    std::uint64_t result = 0;
    for (unsigned byte = 0; byte < bits / 8; ++byte)
        result |= static_cast<std::uint64_t>(std::to_integer<unsigned>(value[offset + byte])) << (byte * 8);
    return result;
}
inline void store(std::array<std::byte, 16> &value, unsigned offset, unsigned bits,
                  std::uint64_t lane) noexcept {
    for (unsigned byte = 0; byte < bits / 8; ++byte)
        value[offset + byte] = static_cast<std::byte>(lane >> (byte * 8));
}
} // namespace x86_sse_float_compare_detail

// Evaluate CMPPS/CMPPD/CMPSS/CMPSD from their exact binary32/binary64 bit
// encodings. Memory access remains caller-owned; mxcsr_after contains sticky
// invalid/denormal status updates, including when an unmasked fault suppresses
// destination retirement.
// If `completed` is false, an unmasked FP exception prevents committing bytes.
inline std::optional<X86SseFloatCompareResult> evaluate_x86_sse_float_compare(
    const Instruction &instruction, const std::array<std::byte, 16> &left,
    const std::array<std::byte, 16> &right, std::uint32_t mxcsr = 0x1f80) noexcept {
    using namespace x86_sse_float_compare_detail;
    if ((instruction.context.architecture != Architecture::x86 &&
         instruction.context.architecture != Architecture::x86_64) ||
        instruction.operands.size() != 3 || !supported(instruction.opcode) ||
        !vector_register(instruction.operands[0]))
        return std::nullopt;
    const auto bits = lane_bits(instruction.opcode);
    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
    const auto *predicate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
    if ((!memory && !vector_register(instruction.operands[1])) ||
        (memory && memory->data_width != (scalar(instruction.opcode) ? bits : 128)) ||
        !predicate || predicate->encoded_width != 8 || predicate->effective_width != 8 ||
        predicate->is_signed || predicate->value > 7 ||
        (instruction.vector_bits && instruction.vector_bits != 128) ||
        (instruction.vector_element_bits && instruction.vector_element_bits != bits))
        return std::nullopt;

    X86SseFloatCompareResult result{};
    result.bytes = left;
    result.lane_bits = static_cast<std::uint8_t>(bits);
    const auto exponent_mask = bits == 32 ? UINT64_C(0x7f800000) : UINT64_C(0x7ff0000000000000);
    const auto fraction_mask = bits == 32 ? UINT64_C(0x007fffff) : UINT64_C(0x000fffffffffffff);
    const auto quiet_mask = bits == 32 ? UINT64_C(0x00400000) : UINT64_C(0x0008000000000000);
    const auto sign_mask = bits == 32 ? UINT64_C(0x80000000) : UINT64_C(0x8000000000000000);
    const auto encoding_mask = bits == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    const bool daz = (mxcsr & (UINT32_C(1) << 6)) != 0;
    const bool signaling_predicate = predicate->value == 1 || predicate->value == 2 ||
        predicate->value == 5 || predicate->value == 6;
    const unsigned lane_count = scalar(instruction.opcode) ? 1u : 128u / bits;
    for (unsigned lane = 0; lane < lane_count; ++lane) {
        const unsigned offset = lane * (bits / 8);
        auto a = load(left, offset, bits);
        auto b = load(right, offset, bits);
        const auto classify = [&](std::uint64_t value) {
            const bool special = (value & exponent_mask) == exponent_mask;
            const auto fraction = value & fraction_mask;
            const bool nan = special && fraction != 0;
            const bool signaling = nan && !(fraction & quiet_mask);
            const bool subnormal = (value & exponent_mask) == 0 && (value & fraction_mask) != 0;
            return std::array<bool, 3>{nan, signaling, subnormal};
        };
        const auto class_a = classify(a);
        const auto class_b = classify(b);
        const bool unordered = class_a[0] || class_b[0];
        result.invalid_operation |= class_a[1] || class_b[1] ||
            (signaling_predicate && unordered && !(class_a[1] || class_b[1]));
        const bool denormal = class_a[2] || class_b[2];
        result.denormal_operand |= denormal && !daz;
        if (daz) {
            if (class_a[2]) a &= sign_mask;
            if (class_b[2]) b &= sign_mask;
        }
        bool less = false;
        bool equal = false;
        if (!unordered) {
            const auto magnitude_mask = ~sign_mask;
            if ((a & magnitude_mask) == 0 && (b & magnitude_mask) == 0) {
                equal = true;
            } else {
                const auto order_key = [&](std::uint64_t value) {
                    return value & sign_mask ? ((~value) & encoding_mask) : (value ^ sign_mask);
                };
                less = order_key(a) < order_key(b);
                equal = a == b;
            }
        }
        bool match = false;
        switch (predicate->value) {
        case 0: match = !unordered && equal; break;
        case 1: match = !unordered && less; break;
        case 2: match = !unordered && (less || equal); break;
        case 3: match = unordered; break;
        case 4: match = unordered || !equal; break;
        case 5: match = unordered || !less; break;
        case 6: match = unordered || (!less && !equal); break;
        case 7: match = !unordered; break;
        default: return std::nullopt;
        }
        store(result.bytes, offset, bits, match ? (bits == 32 ? UINT32_MAX : UINT64_MAX) : 0);
    }
    result.completed = !(result.invalid_operation && !(mxcsr & (UINT32_C(1) << 7))) &&
        !(result.denormal_operand && !(mxcsr & (UINT32_C(1) << 8)));
    result.mxcsr_after = mxcsr | (result.invalid_operation ? UINT32_C(1) : 0) |
        (result.denormal_operand ? UINT32_C(1) << 1 : 0);
    return result;
}

} // namespace hexlab
