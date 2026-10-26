#pragma once

#include "hexlab/processors/instruction.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace hexlab {

// Exact result for the currently decoded VEX integer/bitwise subset. Inputs
// and outputs are in architectural byte order (byte zero is least significant).
// The high half is present for consistent YMM-state results; it is zero for a
// VEX.128 register destination and unused for stores.
struct X86AvxPackedResult {
    std::array<std::byte, 32> bytes{};
    std::uint16_t vector_bits = 0;
    bool zeroed_upper_128 = false;
    bool operator==(const X86AvxPackedResult &) const = default;
};

struct X86EvexIntegerResult {
    std::array<std::byte, 64> bytes{};
    std::uint16_t vector_bits = 0;
    bool operator==(const X86EvexIntegerResult &) const = default;
};

struct X86EvexMaskCompareResult {
    std::uint64_t mask = 0;
    std::uint16_t vector_bits = 0;
    std::uint8_t active_bits = 0;
    bool operator==(const X86EvexMaskCompareResult &) const = default;
};

namespace x86_avx_detail {
// Input and result lane shapes are separate for narrowing, widening and
// mixed-signedness operations. Every shape here uses full-width vector inputs;
// horizontal operations, packing and unpacking stay within each 128-bit half.
struct IntegerDataflowShape {
    std::uint16_t first_bits, second_bits, result_bits;
    bool first_signed, second_signed, result_signed;
};

inline std::optional<IntegerDataflowShape> integer_dataflow_shape(Opcode opcode) noexcept {
    switch (opcode) {
    case Opcode::vpandn: case Opcode::vpavgb: case Opcode::vpshufb:
    case Opcode::vpunpcklbw: case Opcode::vpunpckhbw:
        return IntegerDataflowShape{8, 8, 8, false, false, false};
    case Opcode::vpavgw: case Opcode::vpunpcklwd: case Opcode::vpunpckhwd:
    case Opcode::vpminuw: case Opcode::vpmaxuw:
        return IntegerDataflowShape{16, 16, 16, false, false, false};
    case Opcode::vpunpckldq: case Opcode::vpunpckhdq: case Opcode::vpminud: case Opcode::vpmaxud:
        return IntegerDataflowShape{32, 32, 32, false, false, false};
    case Opcode::vpunpcklqdq: case Opcode::vpunpckhqdq:
        return IntegerDataflowShape{64, 64, 64, false, false, false};
    case Opcode::vpminsb: case Opcode::vpmaxsb: case Opcode::vpsignb:
        return IntegerDataflowShape{8, 8, 8, true, true, true};
    case Opcode::vpminsd: case Opcode::vpmaxsd: case Opcode::vpsignd: case Opcode::vpmulld:
    case Opcode::vphaddd: case Opcode::vphsubd:
        return IntegerDataflowShape{32, 32, 32, true, true, true};
    case Opcode::vpsignw: case Opcode::vphaddw: case Opcode::vphaddsw:
    case Opcode::vphsubw: case Opcode::vphsubsw:
        return IntegerDataflowShape{16, 16, 16, true, true, true};
    case Opcode::vpmuldq: return IntegerDataflowShape{32, 32, 64, true, true, true};
    case Opcode::vpmuludq: return IntegerDataflowShape{32, 32, 64, false, false, false};
    case Opcode::vpmaddwd: return IntegerDataflowShape{16, 16, 32, true, true, true};
    case Opcode::vpmaddubsw: return IntegerDataflowShape{8, 8, 16, false, true, true};
    case Opcode::vpacksswb: return IntegerDataflowShape{16, 16, 8, true, true, true};
    case Opcode::vpackssdw: return IntegerDataflowShape{32, 32, 16, true, true, true};
    case Opcode::vpackuswb: return IntegerDataflowShape{16, 16, 8, true, true, false};
    case Opcode::vpackusdw: return IntegerDataflowShape{32, 32, 16, true, true, false};
    case Opcode::vpsadbw: return IntegerDataflowShape{8, 8, 64, false, false, false};
    default: return std::nullopt;
    }
}

// Deliberately separate from the VEX whitelist: EVEX comparisons write K
// registers, and several VEX dataflow opcodes have no equivalent EVEX form.
inline std::optional<IntegerDataflowShape> evex_integer_shape(Opcode opcode) noexcept {
    switch (opcode) {
    case Opcode::vpsllvw: case Opcode::vpsrlvw: return IntegerDataflowShape{16,16,16,false,false,false};
    case Opcode::vpsllvd: case Opcode::vpsrlvd: return IntegerDataflowShape{32,32,32,false,false,false};
    case Opcode::vpsllvq: case Opcode::vpsrlvq: return IntegerDataflowShape{64,64,64,false,false,false};
    case Opcode::vpsravw: return IntegerDataflowShape{16,16,16,true,false,true};
    case Opcode::vpsravd: return IntegerDataflowShape{32,32,32,true,false,true};
    case Opcode::vpsravq: return IntegerDataflowShape{64,64,64,true,false,true};
    case Opcode::vpaddb: case Opcode::vpsubb: case Opcode::vpaddusb: case Opcode::vpsubusb:
    case Opcode::vpminub: case Opcode::vpmaxub:
        return IntegerDataflowShape{8,8,8,false,false,false};
    case Opcode::vpaddsb: case Opcode::vpsubsb:
        return IntegerDataflowShape{8,8,8,true,true,true};
    case Opcode::vpaddw: case Opcode::vpsubw: case Opcode::vpaddusw: case Opcode::vpsubusw:
    case Opcode::vpmulhuw:
        return IntegerDataflowShape{16,16,16,false,false,false};
    case Opcode::vpaddsw: case Opcode::vpsubsw: case Opcode::vpminsw: case Opcode::vpmaxsw:
    case Opcode::vpmullw: case Opcode::vpmulhw:
        return IntegerDataflowShape{16,16,16,true,true,true};
    case Opcode::vpaddd: case Opcode::vpsubd:
        return IntegerDataflowShape{32,32,32,false,false,false};
    case Opcode::vpaddq: case Opcode::vpsubq:
        return IntegerDataflowShape{64,64,64,false,false,false};
    case Opcode::vpandd: case Opcode::vpord: case Opcode::vpxord:
        return IntegerDataflowShape{32,32,32,false,false,false};
    case Opcode::vpandq: case Opcode::vporq: case Opcode::vpxorq:
        return IntegerDataflowShape{64,64,64,false,false,false};
    case Opcode::vpavgb: case Opcode::vpavgw:
    case Opcode::vpminsb: case Opcode::vpminsd: case Opcode::vpminuw: case Opcode::vpminud:
    case Opcode::vpmaxsb: case Opcode::vpmaxsd: case Opcode::vpmaxuw: case Opcode::vpmaxud:
    case Opcode::vpmulld: case Opcode::vpmuldq: case Opcode::vpmuludq:
    case Opcode::vpmaddwd: case Opcode::vpmaddubsw:
        return integer_dataflow_shape(opcode);
    default: return std::nullopt;
    }
}
struct EvexCompareShape {
    std::uint16_t lane_bits;
    bool is_signed;
};
inline std::optional<EvexCompareShape> evex_compare_shape(Opcode opcode) noexcept {
    switch (opcode) {
    case Opcode::vpcmpb: return EvexCompareShape{8, true};
    case Opcode::vpcmpw: return EvexCompareShape{16, true};
    case Opcode::vpcmpd: return EvexCompareShape{32, true};
    case Opcode::vpcmpq: return EvexCompareShape{64, true};
    case Opcode::vpcmpub: return EvexCompareShape{8, false};
    case Opcode::vpcmpuw: return EvexCompareShape{16, false};
    case Opcode::vpcmpud: return EvexCompareShape{32, false};
    case Opcode::vpcmpuq: return EvexCompareShape{64, false};
    default: return std::nullopt;
    }
}
inline bool is_evex_vector(const Operand &operand, unsigned bits) noexcept {
    const auto *reg=std::get_if<RegisterOperand>(&operand);
    const auto bank = bits == 128 ? RegisterBank::xmm : bits == 256 ? RegisterBank::ymm : RegisterBank::zmm;
    return reg && reg->bank == bank && reg->width == bits && reg->index < 32 &&
           !reg->high_byte;
}

inline bool is_avx_integer_bitwise_or_compare(Opcode opcode) noexcept {
    if (integer_dataflow_shape(opcode)) return true;
    switch (opcode) {
    case Opcode::vpaddb: case Opcode::vpaddw: case Opcode::vpaddd: case Opcode::vpaddq:
    case Opcode::vpaddsb: case Opcode::vpaddsw: case Opcode::vpaddusb: case Opcode::vpaddusw:
    case Opcode::vpsubb: case Opcode::vpsubw: case Opcode::vpsubd: case Opcode::vpsubq:
    case Opcode::vpsubsb: case Opcode::vpsubsw: case Opcode::vpsubusb: case Opcode::vpsubusw:
    case Opcode::vpminub: case Opcode::vpminsw: case Opcode::vpmaxub: case Opcode::vpmaxsw:
    case Opcode::vpmullw: case Opcode::vpmulhw: case Opcode::vpmulhuw:
    case Opcode::vpcmpeqb: case Opcode::vpcmpeqw: case Opcode::vpcmpeqd: case Opcode::vpcmpeqq:
    case Opcode::vpcmpgtb: case Opcode::vpcmpgtw: case Opcode::vpcmpgtd: case Opcode::vpcmpgtq:
    case Opcode::vpand: case Opcode::vpor: case Opcode::vpxor:
    case Opcode::vandps: case Opcode::vandpd: case Opcode::vxorps: case Opcode::vxorpd:
        return true;
    default:
        return false;
    }
}

inline unsigned lane_width(Opcode opcode) noexcept {
    switch (opcode) {
    case Opcode::vpaddb: case Opcode::vpsubb: case Opcode::vpaddsb: case Opcode::vpaddusb:
    case Opcode::vpsubsb: case Opcode::vpsubusb: case Opcode::vpminub: case Opcode::vpmaxub: return 8;
    case Opcode::vpaddw: case Opcode::vpsubw: case Opcode::vpaddsw: case Opcode::vpaddusw:
    case Opcode::vpsubsw: case Opcode::vpsubusw: case Opcode::vpminsw: case Opcode::vpmaxsw: return 16;
    case Opcode::vpmullw: case Opcode::vpmulhw: case Opcode::vpmulhuw: return 16;
    case Opcode::vpaddd: case Opcode::vpsubd: return 32;
    case Opcode::vpaddq: case Opcode::vpsubq: return 64;
    case Opcode::vpcmpeqb: case Opcode::vpcmpgtb: return 8;
    case Opcode::vpcmpeqw: case Opcode::vpcmpgtw: return 16;
    case Opcode::vpcmpeqd: case Opcode::vpcmpgtd: return 32;
    case Opcode::vpcmpeqq: case Opcode::vpcmpgtq: return 64;
    default: return 0;
    }
}

inline bool is_xmm_or_ymm(const Operand &operand, unsigned bits) noexcept {
    const auto *reg = std::get_if<RegisterOperand>(&operand);
    return reg && reg->width == bits && reg->index < 16 && !reg->high_byte &&
        reg->bank == (bits == 128 ? RegisterBank::xmm : RegisterBank::ymm);
}

template <std::size_t Size>
inline std::uint64_t load_lane(const std::array<std::byte, Size> &value,
                               unsigned offset, unsigned width) noexcept {
    std::uint64_t lane = 0;
    for (unsigned i = 0; i < width / 8; ++i)
        lane |= static_cast<std::uint64_t>(std::to_integer<unsigned>(value[offset + i])) << (8 * i);
    return lane;
}

template <std::size_t Size>
inline void store_lane(std::array<std::byte, Size> &value, unsigned offset,
                       unsigned width, std::uint64_t lane) noexcept {
    for (unsigned i = 0; i < width / 8; ++i)
        value[offset + i] = static_cast<std::byte>(lane >> (8 * i));
}
inline std::int64_t signed_lane(std::uint64_t value, unsigned width) noexcept {
    if (width == 64) return std::bit_cast<std::int64_t>(value);
    const auto sign = UINT64_C(1) << (width - 1);
    if (!(value & sign)) return static_cast<std::int64_t>(value);
    return static_cast<std::int64_t>(value) - static_cast<std::int64_t>(UINT64_C(1) << width);
}
inline bool is_equal_compare(Opcode opcode) noexcept {
    return opcode == Opcode::vpcmpeqb || opcode == Opcode::vpcmpeqw ||
           opcode == Opcode::vpcmpeqd || opcode == Opcode::vpcmpeqq;
}
inline bool is_greater_compare(Opcode opcode) noexcept {
    return opcode == Opcode::vpcmpgtb || opcode == Opcode::vpcmpgtw ||
           opcode == Opcode::vpcmpgtd || opcode == Opcode::vpcmpgtq;
}

template <std::size_t Size>
inline void evaluate_integer_dataflow(Opcode opcode, IntegerDataflowShape shape,
    const std::array<std::byte, Size> &first, const std::array<std::byte, Size> &second,
    std::array<std::byte, Size> &output, unsigned bytes) noexcept {
    const auto lane_bytes = static_cast<unsigned>(shape.first_bits / 8);
    const auto mask = shape.result_bits == 64 ? UINT64_MAX : (UINT64_C(1) << shape.result_bits) - 1;
    const auto saturate = [](std::int64_t value, unsigned bits, bool is_signed) {
        const auto minimum = is_signed ? -(INT64_C(1) << (bits - 1)) : INT64_C(0);
        const auto maximum = is_signed ? (INT64_C(1) << (bits - 1)) - 1 : (INT64_C(1) << bits) - 1;
        return static_cast<std::uint64_t>(std::clamp(value, minimum, maximum));
    };
    const bool pack = opcode == Opcode::vpacksswb || opcode == Opcode::vpackssdw ||
                      opcode == Opcode::vpackuswb || opcode == Opcode::vpackusdw;
    const bool unpack_low = opcode == Opcode::vpunpcklbw || opcode == Opcode::vpunpcklwd ||
                            opcode == Opcode::vpunpckldq || opcode == Opcode::vpunpcklqdq;
    const bool unpack_high = opcode == Opcode::vpunpckhbw || opcode == Opcode::vpunpckhwd ||
                             opcode == Opcode::vpunpckhdq || opcode == Opcode::vpunpckhqdq;
    const bool horizontal_add = opcode == Opcode::vphaddw || opcode == Opcode::vphaddd || opcode == Opcode::vphaddsw;
    const bool horizontal_sub = opcode == Opcode::vphsubw || opcode == Opcode::vphsubd || opcode == Opcode::vphsubsw;
    const bool horizontal_saturate = opcode == Opcode::vphaddsw || opcode == Opcode::vphsubsw;
    // Lane-local forms repeat independently across each 128-bit group.
    for (unsigned base = 0; base < bytes; base += 16) {
        if (opcode == Opcode::vpshufb) {
            for (unsigned i = 0; i < 16; ++i) {
                const auto selector = std::to_integer<unsigned>(second[base + i]);
                output[base + i] = selector & 0x80 ? std::byte{} : first[base + (selector & 15)];
            }
        } else if (pack) {
            for (unsigned source = 0; source < 2; ++source)
                for (unsigned i = 0; i < 16 / lane_bytes; ++i) {
                    const auto value = signed_lane(load_lane(source ? second : first,
                        base + i * lane_bytes, shape.first_bits), shape.first_bits);
                    store_lane(output, base + source * 8 + i * (shape.result_bits / 8), shape.result_bits,
                        saturate(value, shape.result_bits, shape.result_signed));
                }
        } else if (unpack_low || unpack_high) {
            for (unsigned i = 0; i < 8 / lane_bytes; ++i) {
                const auto input_offset = base + (unpack_high ? 8 : 0) + i * lane_bytes;
                store_lane(output, base + 2 * i * lane_bytes, shape.result_bits,
                    load_lane(first, input_offset, shape.first_bits));
                store_lane(output, base + (2 * i + 1) * lane_bytes, shape.result_bits,
                    load_lane(second, input_offset, shape.first_bits));
            }
        } else if (horizontal_add || horizontal_sub) {
            for (unsigned source = 0; source < 2; ++source)
                for (unsigned i = 0; i < 8 / lane_bytes; ++i) {
                    const auto &input = source ? second : first;
                    const auto offset = base + 2 * i * lane_bytes;
                    const auto left = signed_lane(load_lane(input, offset, shape.first_bits), shape.first_bits);
                    const auto right = signed_lane(load_lane(input, offset + lane_bytes, shape.first_bits), shape.first_bits);
                    const auto value = horizontal_sub ? left - right : left + right;
                    store_lane(output, base + source * 8 + i * lane_bytes, shape.result_bits,
                        horizontal_saturate ? saturate(value, 16, true) : static_cast<std::uint64_t>(value) & mask);
                }
        } else if (opcode == Opcode::vpmaddwd || opcode == Opcode::vpmaddubsw) {
            for (unsigned i = 0; i < 16 / (2 * lane_bytes); ++i) {
                std::int64_t sum = 0;
                for (unsigned j = 0; j < 2; ++j) {
                    const auto offset = base + (2 * i + j) * lane_bytes;
                    const auto left = load_lane(first, offset, shape.first_bits);
                    const auto right = signed_lane(load_lane(second, offset, shape.second_bits), shape.second_bits);
                    sum += (shape.first_signed ? signed_lane(left, shape.first_bits) : static_cast<std::int64_t>(left)) * right;
                }
                // PMADDWD's exceptional 0x80000000 result wraps; only MADDUBSW saturates.
                store_lane(output, base + i * (shape.result_bits / 8), shape.result_bits,
                    opcode == Opcode::vpmaddubsw ? saturate(sum, 16, true) : static_cast<std::uint64_t>(sum) & mask);
            }
        } else if (opcode == Opcode::vpsadbw) {
            for (unsigned group = 0; group < 2; ++group) {
                std::uint64_t sum = 0;
                for (unsigned i = 0; i < 8; ++i) {
                    const auto offset = base + group * 8 + i;
                    const auto left = std::to_integer<unsigned>(first[offset]);
                    const auto right = std::to_integer<unsigned>(second[offset]);
                    sum += left > right ? left - right : right - left;
                }
                store_lane(output, base + group * 8, 64, sum);
            }
        } else {
            const bool widening_multiply = opcode == Opcode::vpmuldq || opcode == Opcode::vpmuludq;
            const auto stride = widening_multiply ? 8u : lane_bytes;
            for (unsigned i = 0; i < 16; i += stride) {
                const auto left = load_lane(first, base + i, shape.first_bits);
                const auto right = load_lane(second, base + i, shape.second_bits);
                const auto lhs = signed_lane(left, shape.first_bits);
                const auto rhs = signed_lane(right, shape.second_bits);
                std::uint64_t value = 0;
                switch (opcode) {
                case Opcode::vpcmpeqb: case Opcode::vpcmpeqw: case Opcode::vpcmpeqd:
                    value = left == right ? mask : 0; break;
                case Opcode::vpcmpgtb: case Opcode::vpcmpgtw: case Opcode::vpcmpgtd:
                    value = signed_lane(left, shape.first_bits) > signed_lane(right, shape.second_bits) ? mask : 0; break;
                case Opcode::vpandn: value = ~left & right; break;
                case Opcode::vpavgb: case Opcode::vpavgw: value = (left + right + 1) / 2; break;
                case Opcode::vpminsb: case Opcode::vpminsd: value = static_cast<std::uint64_t>(std::min(lhs, rhs)); break;
                case Opcode::vpmaxsb: case Opcode::vpmaxsd: value = static_cast<std::uint64_t>(std::max(lhs, rhs)); break;
                case Opcode::vpminuw: case Opcode::vpminud: value = std::min(left, right); break;
                case Opcode::vpmaxuw: case Opcode::vpmaxud: value = std::max(left, right); break;
                case Opcode::vpmulld: case Opcode::vpmuludq: value = left * right; break;
                case Opcode::vpmuldq: value = static_cast<std::uint64_t>(lhs * rhs); break;
                case Opcode::vpsignb: case Opcode::vpsignw: case Opcode::vpsignd:
                    value = rhs == 0 ? 0 : rhs < 0 ? UINT64_C(0) - left : left; break;
                default: break; // Only shapes in the closed switch above reach this helper.
                }
                store_lane(output, base + i, shape.result_bits, value & mask);
            }
        }
    }
}
template <std::size_t Size>
inline bool evaluate_integer_lanes(Opcode opcode, unsigned lane_bits,
    const std::array<std::byte, Size> &first, const std::array<std::byte, Size> &second,
    std::array<std::byte, Size> &output, unsigned bytes) noexcept {
    if(lane_bits!=8&&lane_bits!=16&&lane_bits!=32&&lane_bits!=64)return false;
    const auto mask = lane_bits == 64 ? UINT64_MAX : (UINT64_C(1) << lane_bits) - 1;
    for (unsigned offset = 0; offset < bytes; offset += lane_bits / 8) {
        const auto left = load_lane(first, offset, lane_bits);
        const auto right = load_lane(second, offset, lane_bits);
        std::uint64_t value = 0;
        if (is_equal_compare(opcode)) {
            value = left == right ? mask : 0;
        } else if (is_greater_compare(opcode)) {
            value = signed_lane(left, lane_bits) > signed_lane(right, lane_bits) ? mask : 0;
        } else if (opcode == Opcode::vpmullw) {
            value = (left * right) & mask;
        } else if (opcode == Opcode::vpmulhw) {
            value = (static_cast<std::uint64_t>(signed_lane(left, 16) * signed_lane(right, 16)) >> 16) & mask;
        } else if (opcode == Opcode::vpmulhuw) {
            value = (left * right >> 16) & mask;
        } else if (opcode == Opcode::vpminub) {
            value = std::min(left, right);
        } else if (opcode == Opcode::vpmaxub) {
            value = std::max(left, right);
        } else if (opcode == Opcode::vpminsw || opcode == Opcode::vpmaxsw) {
            const auto lhs = signed_lane(left, 16);
            const auto rhs = signed_lane(right, 16);
            value = static_cast<std::uint64_t>(opcode == Opcode::vpminsw
                ? std::min(lhs, rhs) : std::max(lhs, rhs)) & mask;
        } else if (opcode == Opcode::vpaddsb || opcode == Opcode::vpaddsw ||
                   opcode == Opcode::vpsubsb || opcode == Opcode::vpsubsw) {
            const auto lhs = signed_lane(left, lane_bits);
            const auto rhs = signed_lane(right, lane_bits);
            const auto raw = lhs + ((opcode == Opcode::vpsubsb || opcode == Opcode::vpsubsw) ? -rhs : rhs);
            const auto minimum = -(INT64_C(1) << (lane_bits - 1));
            const auto maximum = (INT64_C(1) << (lane_bits - 1)) - 1;
            value = static_cast<std::uint64_t>(std::clamp(raw, minimum, maximum)) & mask;
        } else if (opcode == Opcode::vpaddusb || opcode == Opcode::vpaddusw ||
                   opcode == Opcode::vpsubusb || opcode == Opcode::vpsubusw) {
            if (opcode == Opcode::vpsubusb || opcode == Opcode::vpsubusw)
                value = left > right ? left - right : 0;
            else
                value = std::min(mask, left + right);
        } else if (opcode == Opcode::vpaddb || opcode == Opcode::vpaddw ||
                           opcode == Opcode::vpaddd || opcode == Opcode::vpaddq
            ) {
            value = (left + right) & mask;
        } else if (opcode == Opcode::vpsubb || opcode == Opcode::vpsubw ||
                   opcode == Opcode::vpsubd || opcode == Opcode::vpsubq) {
            value = (left - right) & mask;
        } else return false;
        store_lane(output, offset, lane_bits, value);
    }
    return true;
}
} // namespace x86_avx_detail

// Evaluates the subset with fully specified integer/bitwise lane semantics.
// For arithmetic, source1 is operand 1 (VEX.vvvv) and source2 is operand 2
// (ModRM.r/m); for VMOVUPS, source1 contains the loaded/stored vector. Memory
// reads and writes are caller-owned. Floating-point add/subtract/multiply are
// deliberately not evaluated because MXCSR rounding, denormals, and exception
// state are not inputs to this helper.
inline std::optional<X86AvxPackedResult> evaluate_x86_avx_packed(
    const Instruction &instruction, const std::array<std::byte, 32> &source1,
    const std::array<std::byte, 32> &source2) noexcept {
    using namespace x86_avx_detail;
    if (instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 || instruction.operands.size() < 2 ||
        instruction.x86_opmask || instruction.x86_opmask_zeroing)
        return std::nullopt;

    const bool move = instruction.opcode == Opcode::vmovups;
    if (!move && !is_avx_integer_bitwise_or_compare(instruction.opcode)) return std::nullopt;
    if (!move && instruction.operands.size() != 3) return std::nullopt;
    if (move && instruction.operands.size() != 2) return std::nullopt;

    const bool store = move && std::holds_alternative<MemoryOperand>(instruction.operands[0]);
    std::uint16_t bits = 0;
    std::optional<std::uint8_t> register_destination;
    if (move) {
        const auto *vector_register = store
            ? std::get_if<RegisterOperand>(&instruction.operands[1])
            : std::get_if<RegisterOperand>(&instruction.operands[0]);
        if (!vector_register || (vector_register->bank != RegisterBank::xmm && vector_register->bank != RegisterBank::ymm))
            return std::nullopt;
        bits = vector_register->width;
        if (bits != 128 && bits != 256) return std::nullopt;
        if (!store) register_destination = vector_register->index;
        const auto &other = store ? instruction.operands[0] : instruction.operands[1];
        if (!is_xmm_or_ymm(store ? instruction.operands[1] : instruction.operands[0], bits)) return std::nullopt;
        if (const auto *memory = std::get_if<MemoryOperand>(&other)) {
            if (memory->data_width != bits) return std::nullopt;
        } else if (!is_xmm_or_ymm(other, bits)) {
            return std::nullopt;
        }
    } else {
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        if (!destination || (destination->bank != RegisterBank::xmm && destination->bank != RegisterBank::ymm))
            return std::nullopt;
        bits = destination->width;
        if ((bits != 128 && bits != 256) || !is_xmm_or_ymm(instruction.operands[0], bits) ||
            !is_xmm_or_ymm(instruction.operands[1], bits))
            return std::nullopt;
        register_destination = destination->index;
        const auto &source = instruction.operands[2];
        if (const auto *memory = std::get_if<MemoryOperand>(&source)) {
            if (memory->data_width != bits) return std::nullopt;
        } else if (!is_xmm_or_ymm(source, bits)) {
            return std::nullopt;
        }
    }

    if (instruction.vector_bits && instruction.vector_bits != bits) return std::nullopt;

    X86AvxPackedResult result{};
    result.vector_bits = bits;
    if (bits == 128 && register_destination) {
        result.zeroed_upper_128 = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
            [&](RegisterOperand reg) {
                return reg.bank == RegisterBank::ymm && reg.width == 256 && reg.index == *register_destination;
            });
        if (!result.zeroed_upper_128) return std::nullopt;
    }

    const auto bytes = static_cast<unsigned>(bits / 8);
    if (move) {
        for (unsigned i = 0; i < bytes; ++i) result.bytes[i] = source1[i];
        return result;
    }

    if (const auto shape = integer_dataflow_shape(instruction.opcode)) {
        evaluate_integer_dataflow(instruction.opcode, *shape, source1, source2, result.bytes, bytes);
        return result;
    }

    const auto lane_bits = lane_width(instruction.opcode);
    if (lane_bits) {
        if(!evaluate_integer_lanes(instruction.opcode,lane_bits,source1,source2,result.bytes,bytes))return std::nullopt;
        return result;
    }

    for (unsigned i = 0; i < bytes; ++i) {
        const auto left = std::to_integer<unsigned>(source1[i]);
        const auto right = std::to_integer<unsigned>(source2[i]);
        unsigned value = 0;
        switch (instruction.opcode) {
        case Opcode::vpand: case Opcode::vandps: case Opcode::vandpd: value = left & right; break;
        case Opcode::vpor: value = left | right; break;
        case Opcode::vpxor: case Opcode::vxorps: case Opcode::vxorpd: value = left ^ right; break;
        default: return std::nullopt;
        }
        result.bytes[i] = static_cast<std::byte>(value);
    }
    return result;
}

// Exact bounded EVEX.128/.256/.512 integer dataflow with result-lane
// writemasking. VL forms return zeroed bytes above their active vector width.
// Sources and memory bytes are caller-owned. Merge masking requires the old
// destination even when a supplied runtime mask happens to enable every lane.
// This helper does not execute CPU feature checks, memory faults or FP state.
inline std::optional<X86EvexIntegerResult> evaluate_x86_evex_integer(
    const Instruction &instruction, const std::array<std::byte, 64> &source1,
    const std::array<std::byte, 64> &source2,
    const std::array<std::byte, 64> *old_destination = nullptr,
    std::uint64_t opmask_value = UINT64_MAX) noexcept {
    using namespace x86_avx_detail;
    if (instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 || instruction.operands.size() != 3 ||
        !instruction.x86_evex ||
        (instruction.vector_bits != 128 && instruction.vector_bits != 256 && instruction.vector_bits != 512) ||
        (instruction.x86_opmask_zeroing && !instruction.x86_opmask))
        return std::nullopt;
    const auto shape=evex_integer_shape(instruction.opcode);
    if(!shape||(instruction.vector_element_bits&&instruction.vector_element_bits!=shape->result_bits))return std::nullopt;
    const auto *memory=std::get_if<MemoryOperand>(&instruction.operands[2]);
    const auto vector_bits = static_cast<unsigned>(instruction.vector_bits);
    if(!is_evex_vector(instruction.operands[0],vector_bits)||!is_evex_vector(instruction.operands[1],vector_bits)||
       (!is_evex_vector(instruction.operands[2],vector_bits)&&(!memory||memory->data_width!=vector_bits)))return std::nullopt;
    if(instruction.x86_opmask&&(*instruction.x86_opmask==0||*instruction.x86_opmask>7))return std::nullopt;
    if(instruction.x86_opmask&&!instruction.x86_opmask_zeroing&&!old_destination)return std::nullopt;
    X86EvexIntegerResult result{};result.vector_bits=static_cast<std::uint16_t>(vector_bits);
    const auto active_bytes = vector_bits / 8;
    if(const auto dataflow=integer_dataflow_shape(instruction.opcode))
        evaluate_integer_dataflow(instruction.opcode,*dataflow,source1,source2,result.bytes,active_bytes);
    else if (instruction.opcode == Opcode::vpandd || instruction.opcode == Opcode::vpandq ||
             instruction.opcode == Opcode::vpord || instruction.opcode == Opcode::vporq ||
             instruction.opcode == Opcode::vpxord || instruction.opcode == Opcode::vpxorq) {
        for (unsigned byte = 0; byte < active_bytes; ++byte) {
            const auto left = std::to_integer<unsigned>(source1[byte]);
            const auto right = std::to_integer<unsigned>(source2[byte]);
            const auto value = (instruction.opcode == Opcode::vpandd || instruction.opcode == Opcode::vpandq) ? left & right :
                (instruction.opcode == Opcode::vpord || instruction.opcode == Opcode::vporq) ? left | right : left ^ right;
            result.bytes[byte] = static_cast<std::byte>(value);
        }
    }
    else if(!evaluate_integer_lanes(instruction.opcode,shape->result_bits,source1,source2,result.bytes,active_bytes))return std::nullopt;
    // Writemask bits index destination elements, not source elements. This
    // distinction matters for even-dword products and adjacent multiply-adds.
    if(instruction.x86_opmask)for(unsigned lane=0;lane<vector_bits/shape->result_bits;++lane){
        if((opmask_value>>lane)&1)continue;
        const auto lane_bytes=static_cast<unsigned>(shape->result_bits/8);
        const auto begin=lane*lane_bytes;
        for(unsigned byte=0;byte<lane_bytes;++byte)
            result.bytes[begin+byte]=instruction.x86_opmask_zeroing?std::byte{}:(*old_destination)[begin+byte];
    }
    return result;
}

// VPCMP writes a K register. Masked-off comparisons and bits above the active
// element count become zero; there is no old-destination merge operand.
inline std::optional<X86EvexMaskCompareResult> evaluate_x86_evex_mask_compare(
    const Instruction &instruction, const std::array<std::byte, 64> &source1,
    const std::array<std::byte, 64> &source2, std::uint64_t opmask_value = UINT64_MAX) noexcept {
    using namespace x86_avx_detail;
    const auto shape = evex_compare_shape(instruction.opcode);
    if (instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 || !instruction.x86_evex ||
        !shape || instruction.operands.size() != 4 || instruction.x86_opmask_zeroing ||
        (instruction.vector_bits != 128 && instruction.vector_bits != 256 && instruction.vector_bits != 512) ||
        (instruction.vector_element_bits && instruction.vector_element_bits != shape->lane_bits))
        return std::nullopt;
    const auto width = static_cast<unsigned>(instruction.vector_bits);
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[2]);
    const auto *predicate = std::get_if<ImmediateOperand>(&instruction.operands[3]);
    if (!destination || destination->bank != RegisterBank::opmask || destination->index >= 8 ||
        destination->width != 64 || destination->high_byte ||
        !is_evex_vector(instruction.operands[1], width) ||
        (!is_evex_vector(instruction.operands[2], width) && (!memory || memory->data_width != width)) ||
        !predicate || predicate->encoded_width != 8 || predicate->effective_width != 8 || predicate->is_signed ||
        predicate->value > 7 ||
        (instruction.x86_opmask && (*instruction.x86_opmask == 0 || *instruction.x86_opmask >= 8)))
        return std::nullopt;
    X86EvexMaskCompareResult result{};
    result.vector_bits = static_cast<std::uint16_t>(width);
    result.active_bits = static_cast<std::uint8_t>(width / shape->lane_bits);
    for (unsigned lane = 0; lane < result.active_bits; ++lane) {
        if (instruction.x86_opmask && !(opmask_value & (UINT64_C(1) << lane))) continue;
        const unsigned offset = lane * shape->lane_bits / 8;
        const auto first = load_lane(source1, offset, shape->lane_bits);
        const auto second = load_lane(source2, offset, shape->lane_bits);
        const bool equal = first == second;
        const bool less = shape->is_signed ? signed_lane(first, shape->lane_bits) < signed_lane(second, shape->lane_bits)
                                           : first < second;
        bool match = false;
        switch (predicate->value) {
        case 0: match = equal; break;
        case 1: match = less; break;
        case 2: match = less || equal; break;
        case 3: match = false; break;
        case 4: match = !equal; break;
        case 5: match = !less; break;
        case 6: match = !less && !equal; break;
        case 7: match = true; break;
        }
        if (match) result.mask |= UINT64_C(1) << lane;
    }
    return result;
}

} // namespace hexlab
