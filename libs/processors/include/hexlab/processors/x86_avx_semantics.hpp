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

// VEX floating comparison results are vector lanes, unlike EVEX's K result.
// bytes includes the cleared high YMM half for a completed VEX.128 result.
struct X86AvxFloatCompareResult {
    std::array<std::byte, 32> bytes{};
    std::uint16_t vector_bits = 0;
    std::uint8_t lane_bits = 0;
    bool zeroed_upper_128 = false;
    bool invalid_operation = false;
    bool denormal_operand = false;
    bool completed = true;
    std::uint32_t mxcsr_after = 0x1f80;
    bool operator==(const X86AvxFloatCompareResult &) const = default;
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

struct X86EvexFpClassResult {
    std::uint64_t mask = 0;
    std::uint16_t vector_bits = 0;
    std::uint8_t active_bits = 0;
    bool operator==(const X86EvexFpClassResult &) const = default;
};

struct X86EvexFloatCompareResult {
    std::uint64_t mask = 0;
    std::uint16_t vector_bits = 0;
    std::uint8_t active_bits = 0;
    bool invalid_operation = false;
    bool denormal_operand = false;
    // An unmasked #I or #D suppresses retirement unless embedded SAE is set.
    bool completed = true;
    std::uint32_t mxcsr_after = 0x1f80;
    bool operator==(const X86EvexFloatCompareResult &) const = default;
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
    case Opcode::vpandn: case Opcode::vpavgb: case Opcode::vpshufb: case Opcode::vpermb:
    case Opcode::vpunpcklbw: case Opcode::vpunpckhbw:
        return IntegerDataflowShape{8, 8, 8, false, false, false};
    case Opcode::vpavgw: case Opcode::vpunpcklwd: case Opcode::vpunpckhwd:
    case Opcode::vpminuw: case Opcode::vpmaxuw:
        return IntegerDataflowShape{16, 16, 16, false, false, false};
    case Opcode::vpunpckldq: case Opcode::vpunpckhdq: case Opcode::vpminud: case Opcode::vpmaxud:
        return IntegerDataflowShape{32, 32, 32, false, false, false};
    case Opcode::vpunpcklqdq: case Opcode::vpunpckhqdq:
        return IntegerDataflowShape{64, 64, 64, false, false, false};
    case Opcode::vpcmpgtq:
        // Signed qword inputs produce a full-width unsigned lane mask.
        return IntegerDataflowShape{64, 64, 64, true, true, false};
    case Opcode::vpminsb: case Opcode::vpmaxsb: case Opcode::vpsignb:
        return IntegerDataflowShape{8, 8, 8, true, true, true};
    // VEX packed variable shifts use SRC1 as the data vector and SRC2 as the
    // per-lane count vector. Arithmetic-right data lanes are signed; counts
    // are always interpreted as unsigned values.
    case Opcode::vpsllvd: case Opcode::vpsrlvd:
        return IntegerDataflowShape{32, 32, 32, false, false, false};
    case Opcode::vpsllvq: case Opcode::vpsrlvq:
        return IntegerDataflowShape{64, 64, 64, false, false, false};
    case Opcode::vpsravd:
        return IntegerDataflowShape{32, 32, 32, true, false, true};
    case Opcode::vpminsd: case Opcode::vpmaxsd: case Opcode::vpsignd: case Opcode::vpmulld:
    case Opcode::vphaddd: case Opcode::vphsubd:
        return IntegerDataflowShape{32, 32, 32, true, true, true};
    case Opcode::vpmullq:
        return IntegerDataflowShape{64, 64, 64, false, false, false};
    case Opcode::vpminsq: case Opcode::vpmaxsq:
        return IntegerDataflowShape{64, 64, 64, true, true, true};
    case Opcode::vpminuq: case Opcode::vpmaxuq:
        return IntegerDataflowShape{64, 64, 64, false, false, false};
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
    case Opcode::vpermd: return IntegerDataflowShape{32, 32, 32, false, false, false};
    default: return std::nullopt;
    }
}

inline std::optional<IntegerDataflowShape> immediate_shift_shape(Opcode opcode) noexcept {
    switch (opcode) {
    case Opcode::vpsllw: case Opcode::vpsrlw: return IntegerDataflowShape{16, 8, 16, false, false, false};
    case Opcode::vpsraw: return IntegerDataflowShape{16, 8, 16, true, false, true};
    case Opcode::vpslld: case Opcode::vpsrld: return IntegerDataflowShape{32, 8, 32, false, false, false};
    case Opcode::vpsrad: return IntegerDataflowShape{32, 8, 32, true, false, true};
    case Opcode::vpsllq: case Opcode::vpsrlq: return IntegerDataflowShape{64, 8, 64, false, false, false};
    // These shift the 128-bit groups as a byte string, independently within
    // each 16-byte AVX lane.
    case Opcode::vpslldq: case Opcode::vpsrldq: return IntegerDataflowShape{128, 8, 128, false, false, false};
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
    case Opcode::vpandd: case Opcode::vpandnd: case Opcode::vpord: case Opcode::vpxord:
        return IntegerDataflowShape{32,32,32,false,false,false};
    case Opcode::vpandq: case Opcode::vpandnq: case Opcode::vporq: case Opcode::vpxorq:
        return IntegerDataflowShape{64,64,64,false,false,false};
    case Opcode::vpavgb: case Opcode::vpavgw: case Opcode::vpsadbw: case Opcode::vpermb:
    case Opcode::vpunpcklbw: case Opcode::vpunpcklwd: case Opcode::vpunpckldq: case Opcode::vpunpcklqdq:
    case Opcode::vpunpckhbw: case Opcode::vpunpckhwd: case Opcode::vpunpckhdq: case Opcode::vpunpckhqdq:
    case Opcode::vpminsb: case Opcode::vpminsd: case Opcode::vpminsq: case Opcode::vpminuw: case Opcode::vpminud: case Opcode::vpminuq:
    case Opcode::vpmaxsb: case Opcode::vpmaxsd: case Opcode::vpmaxsq: case Opcode::vpmaxuw: case Opcode::vpmaxud: case Opcode::vpmaxuq:
    case Opcode::vpmulld: case Opcode::vpmullq: case Opcode::vpmuldq: case Opcode::vpmuludq:
    case Opcode::vpmaddwd: case Opcode::vpmaddubsw:
    case Opcode::vpermd:
    // Packing narrows signed inputs, independently within 128-bit groups;
    // writemask elements follow the narrowed result rather than input lanes.
    case Opcode::vpacksswb: case Opcode::vpackssdw: case Opcode::vpackuswb: case Opcode::vpackusdw:
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

inline std::optional<unsigned> absolute_lane_width(Opcode opcode) noexcept {
    switch (opcode) {
    case Opcode::vpabsb: return 8;
    case Opcode::vpabsw: return 16;
    case Opcode::vpabsd: return 32;
    default: return std::nullopt;
    }
}

inline bool is_xmm_or_ymm(const Operand &operand, unsigned bits) noexcept {
    const auto *reg = std::get_if<RegisterOperand>(&operand);
    return reg && reg->width == bits && reg->index < 16 && !reg->high_byte &&
        reg->bank == (bits == 128 ? RegisterBank::xmm : RegisterBank::ymm);
}

inline bool is_vex_context(const Instruction &instruction) noexcept {
    return (instruction.context.architecture == Architecture::x86 &&
            instruction.context.mode == ExecutionMode::x86_32) ||
           (instruction.context.architecture == Architecture::x86_64 &&
            instruction.context.mode == ExecutionMode::x86_64);
}

inline bool vex_registers_valid(const Instruction &instruction) noexcept {
    if (instruction.context.mode != ExecutionMode::x86_32)
        return true;
    const auto valid = [](RegisterOperand reg) {
        return (reg.bank != RegisterBank::xmm && reg.bank != RegisterBank::ymm) || reg.index < 8;
    };
    for (const auto &operand : instruction.operands)
        if (const auto *reg = std::get_if<RegisterOperand>(&operand); reg && !valid(*reg))
            return false;
    return std::all_of(instruction.register_reads.begin(), instruction.register_reads.end(), valid) &&
           std::all_of(instruction.register_writes.begin(), instruction.register_writes.end(), valid);
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
template <std::size_t Size>
inline void evaluate_absolute_lanes(unsigned lane_bits,
    const std::array<std::byte, Size> &source, std::array<std::byte, Size> &output,
    unsigned bytes) noexcept {
    const auto mask = (UINT64_C(1) << lane_bits) - 1;
    for (unsigned offset = 0; offset < bytes; offset += lane_bits / 8) {
        const auto raw = load_lane(source, offset, lane_bits);
        const auto signed_value = signed_lane(raw, lane_bits);
        const auto absolute = signed_value < 0 ? (UINT64_C(0) - raw) & mask : raw;
        store_lane(output, offset, lane_bits, absolute);
    }
}
inline bool is_equal_compare(Opcode opcode) noexcept {
    return opcode == Opcode::vpcmpeqb || opcode == Opcode::vpcmpeqw ||
           opcode == Opcode::vpcmpeqd || opcode == Opcode::vpcmpeqq;
}
inline bool is_greater_compare(Opcode opcode) noexcept {
    return opcode == Opcode::vpcmpgtb || opcode == Opcode::vpcmpgtw ||
           opcode == Opcode::vpcmpgtd || opcode == Opcode::vpcmpgtq;
}
inline bool is_variable_shift(Opcode opcode) noexcept {
    switch (opcode) {
    case Opcode::vpsllvw: case Opcode::vpsllvd: case Opcode::vpsllvq:
    case Opcode::vpsrlvw: case Opcode::vpsrlvd: case Opcode::vpsrlvq:
    case Opcode::vpsravw: case Opcode::vpsravd: case Opcode::vpsravq:
        return true;
    default:
        return false;
    }
}

inline bool is_left_immediate_shift(Opcode opcode) noexcept {
    return opcode == Opcode::vpsllw || opcode == Opcode::vpslld || opcode == Opcode::vpsllq ||
           opcode == Opcode::vpslldq;
}

inline bool is_arithmetic_immediate_shift(Opcode opcode) noexcept {
    return opcode == Opcode::vpsraw || opcode == Opcode::vpsrad;
}

template <std::size_t Size>
inline std::uint64_t load_lane(const std::array<std::byte, Size> &value,
                               unsigned offset, unsigned width) noexcept;
template <std::size_t Size>
inline void store_lane(std::array<std::byte, Size> &value, unsigned offset,
                       unsigned width, std::uint64_t lane) noexcept;

template <std::size_t Size>
inline void evaluate_immediate_shift(Opcode opcode, const std::array<std::byte, Size> &source,
                                    std::uint8_t count, std::array<std::byte, Size> &output,
                                    unsigned bytes) noexcept {
    const auto shape = immediate_shift_shape(opcode);
    if (!shape) return;
    if (shape->result_bits == 128) {
        for (unsigned base = 0; base < bytes; base += 16) {
            for (unsigned i = 0; i < 16; ++i) {
                std::byte value{};
                if (count < 16) {
                    if (is_left_immediate_shift(opcode)) {
                        if (i >= count) value = source[base + i - count];
                    } else if (i + count < 16) {
                        value = source[base + i + count];
                    }
                }
                output[base + i] = value;
            }
        }
        return;
    }
    const auto lane_bytes = static_cast<unsigned>(shape->result_bits / 8);
    const auto mask = shape->result_bits == 64 ? UINT64_MAX : (UINT64_C(1) << shape->result_bits) - 1;
    for (unsigned offset = 0; offset < bytes; offset += lane_bytes) {
        const auto value = load_lane(source, offset, shape->result_bits);
        std::uint64_t shifted = 0;
        if (is_arithmetic_immediate_shift(opcode)) {
            const bool negative = (value & (UINT64_C(1) << (shape->result_bits - 1))) != 0;
            if (count >= shape->result_bits) shifted = negative ? mask : 0;
            else if (!count) shifted = value;
            else {
                shifted = value >> count;
                if (negative) shifted |= (~UINT64_C(0)) << (shape->result_bits - count);
            }
        } else if (count < shape->result_bits) {
            shifted = is_left_immediate_shift(opcode) ? value << count : value >> count;
        }
        store_lane(output, offset, shape->result_bits, shifted & mask);
    }
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
    if (opcode == Opcode::vpermd) {
        const auto lane_bits = static_cast<unsigned>(shape.result_bits);
        const auto permutation_lane_bytes = lane_bits / 8;
        const auto lanes = bytes / permutation_lane_bytes;
        for (unsigned lane = 0; lane < lanes; ++lane) {
            const auto selector = load_lane(first, lane * permutation_lane_bytes, lane_bits);
            const auto source_lane = static_cast<unsigned>(selector & (lanes - 1));
            store_lane(output, lane * permutation_lane_bytes, lane_bits,
                       load_lane(second, source_lane * permutation_lane_bytes, lane_bits));
        }
        return;
    }
    if (opcode == Opcode::vpermb) {
        for (unsigned lane = 0; lane < bytes; ++lane) {
            const auto selector = std::to_integer<unsigned>(second[lane]);
            output[lane] = first[selector & (bytes - 1)];
        }
        return;
    }
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
                case Opcode::vpsllvw: case Opcode::vpsllvd: case Opcode::vpsllvq:
                    value = right >= shape.result_bits ? 0 : left << right;
                    break;
                case Opcode::vpsrlvw: case Opcode::vpsrlvd: case Opcode::vpsrlvq:
                    value = right >= shape.result_bits ? 0 : left >> right;
                    break;
                case Opcode::vpsravw: case Opcode::vpsravd: case Opcode::vpsravq: {
                    const auto width = static_cast<unsigned>(shape.result_bits);
                    const bool negative = (left & (UINT64_C(1) << (width - 1))) != 0;
                    if (right >= width) value = negative ? mask : 0;
                    else if (right == 0) value = left;
                    else {
                        value = left >> right;
                        if (negative) value |= (~UINT64_C(0)) << (width - right);
                    }
                    break;
                }
                case Opcode::vpcmpeqb: case Opcode::vpcmpeqw: case Opcode::vpcmpeqd:
                    value = left == right ? mask : 0; break;
                case Opcode::vpcmpgtb: case Opcode::vpcmpgtw: case Opcode::vpcmpgtd: case Opcode::vpcmpgtq:
                    value = signed_lane(left, shape.first_bits) > signed_lane(right, shape.second_bits) ? mask : 0; break;
                case Opcode::vpandn: case Opcode::vpandnd: case Opcode::vpandnq:
                    value = ~left & right; break;
                case Opcode::vpavgb: case Opcode::vpavgw: value = (left + right + 1) / 2; break;
                case Opcode::vpminsb: case Opcode::vpminsd: case Opcode::vpminsq: value = static_cast<std::uint64_t>(std::min(lhs, rhs)); break;
                case Opcode::vpmaxsb: case Opcode::vpmaxsd: case Opcode::vpmaxsq: value = static_cast<std::uint64_t>(std::max(lhs, rhs)); break;
                case Opcode::vpminuw: case Opcode::vpminud: case Opcode::vpminuq: value = std::min(left, right); break;
                case Opcode::vpmaxuw: case Opcode::vpmaxud: case Opcode::vpmaxuq: value = std::max(left, right); break;
                case Opcode::vpmulld: case Opcode::vpmullq: case Opcode::vpmuludq: value = left * right; break;
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
// For binary arithmetic, source1 is operand 1 (VEX.vvvv) and source2 is
// operand 2 (ModRM.r/m); for unary VPABS, source1 contains its sole ModRM.r/m
// vector source. For VMOVUPS, source1 contains the loaded/stored vector. Memory
// reads and writes are caller-owned. Floating-point add/subtract/multiply are
// deliberately not evaluated because MXCSR rounding, denormals, and exception
// state are not inputs to this helper.
inline std::optional<X86AvxPackedResult> evaluate_x86_avx_packed(
    const Instruction &instruction, const std::array<std::byte, 32> &source1,
    const std::array<std::byte, 32> &source2) noexcept {
    using namespace x86_avx_detail;
    if (!is_vex_context(instruction) || !vex_registers_valid(instruction) || instruction.operands.size() < 2 ||
        instruction.x86_evex ||
        instruction.x86_opmask || instruction.x86_opmask_zeroing)
        return std::nullopt;

    const bool move = instruction.opcode == Opcode::vmovups;
    const bool shuffle = instruction.opcode == Opcode::vshufps || instruction.opcode == Opcode::vshufpd;
    const bool immediate_shuffle = instruction.opcode == Opcode::vpshufd;
    const bool immediate_blend = instruction.opcode == Opcode::vpblendd;
    const auto immediate_shift = immediate_shift_shape(instruction.opcode);
    const auto absolute = absolute_lane_width(instruction.opcode);
    if (!move && !shuffle && !immediate_shuffle && !immediate_blend && !immediate_shift && !absolute &&
        !is_avx_integer_bitwise_or_compare(instruction.opcode))
        return std::nullopt;
    if (shuffle && instruction.operands.size() != 4) return std::nullopt;
    if ((!move && !shuffle && !immediate_shuffle && !immediate_blend && !absolute && instruction.operands.size() != 3) ||
        (immediate_shuffle && instruction.operands.size() != 3)) return std::nullopt;
    if (immediate_blend && instruction.operands.size() != 4) return std::nullopt;
    if (move && instruction.operands.size() != 2) return std::nullopt;

    const bool store = move && std::holds_alternative<MemoryOperand>(instruction.operands[0]);
    std::uint16_t bits = 0;
    std::optional<std::uint16_t> register_destination;
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
    } else if (absolute) {
        if (instruction.operands.size() != 2) return std::nullopt;
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        const auto &source = instruction.operands[1];
        if (!destination || (destination->bank != RegisterBank::xmm && destination->bank != RegisterBank::ymm))
            return std::nullopt;
        bits = destination->width;
        if ((bits != 128 && bits != 256) || !is_xmm_or_ymm(instruction.operands[0], bits) ||
            (instruction.vector_bits && instruction.vector_bits != bits) ||
            (instruction.vector_element_bits && instruction.vector_element_bits != *absolute))
            return std::nullopt;
        if (const auto *memory = std::get_if<MemoryOperand>(&source)) {
            if (memory->data_width != bits) return std::nullopt;
        } else if (!is_xmm_or_ymm(source, bits)) {
            return std::nullopt;
        }
        register_destination = destination->index;
    } else if (immediate_shuffle) {
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        if (!destination || (destination->bank != RegisterBank::xmm && destination->bank != RegisterBank::ymm))
            return std::nullopt;
        bits = destination->width;
        if ((bits != 128 && bits != 256) || !is_xmm_or_ymm(instruction.operands[0], bits) ||
            (instruction.vector_bits && instruction.vector_bits != bits) ||
            (instruction.vector_element_bits && instruction.vector_element_bits != 32))
            return std::nullopt;
        register_destination = destination->index;
        const auto &source = instruction.operands[1];
        if (const auto *memory = std::get_if<MemoryOperand>(&source)) {
            if (memory->data_width != bits) return std::nullopt;
        } else if (!is_xmm_or_ymm(source, bits)) {
            return std::nullopt;
        }
        const auto *selector = std::get_if<ImmediateOperand>(&instruction.operands[2]);
        if (!selector || selector->encoded_width != 8 || selector->effective_width != 8 ||
            selector->is_signed || selector->value > 0xff)
            return std::nullopt;
    } else if (immediate_blend) {
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        if (!destination || (destination->bank != RegisterBank::xmm && destination->bank != RegisterBank::ymm))
            return std::nullopt;
        bits = destination->width;
        if ((bits != 128 && bits != 256) || !is_xmm_or_ymm(instruction.operands[0], bits) ||
            (instruction.vector_bits && instruction.vector_bits != bits) ||
            (instruction.vector_element_bits && instruction.vector_element_bits != 32) ||
            !is_xmm_or_ymm(instruction.operands[1], bits))
            return std::nullopt;
        register_destination = destination->index;
        const auto &source = instruction.operands[2];
        if (const auto *memory = std::get_if<MemoryOperand>(&source)) {
            if (memory->data_width != bits) return std::nullopt;
        } else if (!is_xmm_or_ymm(source, bits)) {
            return std::nullopt;
        }
        const auto *selector = std::get_if<ImmediateOperand>(&instruction.operands[3]);
        if (!selector || selector->encoded_width != 8 || selector->effective_width != 8 ||
            selector->is_signed || selector->value > 0xff)
            return std::nullopt;
    } else if (immediate_shift) {
        const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
        if (!destination || (destination->bank != RegisterBank::xmm && destination->bank != RegisterBank::ymm))
            return std::nullopt;
        bits = destination->width;
        if ((bits != 128 && bits != 256) || !is_xmm_or_ymm(instruction.operands[0], bits))
            return std::nullopt;
        register_destination = destination->index;
        const auto &source = instruction.operands[1];
        if (const auto *memory = std::get_if<MemoryOperand>(&source)) {
            if (memory->data_width != bits) return std::nullopt;
        } else if (!is_xmm_or_ymm(source, bits)) {
            return std::nullopt;
        }
        const auto *count = std::get_if<ImmediateOperand>(&instruction.operands[2]);
        if (!count || count->encoded_width != 8 || count->effective_width != 8 ||
            count->is_signed || count->value > 0xff ||
            (instruction.vector_element_bits && instruction.vector_element_bits != immediate_shift->result_bits))
            return std::nullopt;
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
    if (instruction.opcode == Opcode::vpcmpgtq && instruction.vector_element_bits &&
        instruction.vector_element_bits != 64) return std::nullopt;
    if (instruction.opcode == Opcode::vpermd && bits != 256) return std::nullopt;
    if (shuffle) {
        const auto *selector = std::get_if<ImmediateOperand>(&instruction.operands[3]);
        const auto lane_bits = instruction.opcode == Opcode::vshufps ? 32u : 64u;
        if (!selector || selector->encoded_width != 8 || selector->effective_width != 8 || selector->is_signed ||
            (instruction.vector_element_bits && instruction.vector_element_bits != lane_bits) ||
            !is_xmm_or_ymm(instruction.operands[1], bits))
            return std::nullopt;
        if (const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[2])) {
            if (memory->data_width != bits) return std::nullopt;
        } else if (!is_xmm_or_ymm(instruction.operands[2], bits)) {
            return std::nullopt;
        }
    }

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

    if (immediate_shuffle) {
        const auto selector = static_cast<unsigned>(std::get<ImmediateOperand>(instruction.operands[2]).value);
        for (unsigned lane_base = 0; lane_base < bytes; lane_base += 16) {
            for (unsigned output_lane = 0; output_lane < 4; ++output_lane) {
                const unsigned source_lane = (selector >> (output_lane * 2)) & 3u;
                for (unsigned byte = 0; byte < 4; ++byte)
                    result.bytes[lane_base + output_lane * 4 + byte] =
                        source1[lane_base + source_lane * 4 + byte];
            }
        }
        return result;
    }

    if (immediate_blend) {
        const auto selector = static_cast<unsigned>(std::get<ImmediateOperand>(instruction.operands[3]).value);
        for (unsigned lane = 0; lane < bytes / 4; ++lane) {
            const auto &source = (selector >> lane) & 1u ? source2 : source1;
            for (unsigned byte = 0; byte < 4; ++byte)
                result.bytes[lane * 4 + byte] = source[lane * 4 + byte];
        }
        return result;
    }

    if (shuffle) {
        const auto selector = static_cast<unsigned>(std::get<ImmediateOperand>(instruction.operands[3]).value);
        const unsigned lane_bytes = instruction.opcode == Opcode::vshufps ? 4 : 8;
        const unsigned lanes_per_128 = 16 / lane_bytes;
        for (unsigned lane_base = 0; lane_base < bytes; lane_base += 16) {
            for (unsigned output_lane = 0; output_lane < lanes_per_128; ++output_lane) {
                const unsigned selector_bit = instruction.opcode == Opcode::vshufps
                    ? output_lane * 2 : (lane_base / 16) * 2 + (output_lane == 0 ? 0 : 1);
                const unsigned source_lane = (selector >> selector_bit) & (instruction.opcode == Opcode::vshufps ? 3u : 1u);
                const bool from_second = instruction.opcode == Opcode::vshufps
                    ? output_lane >= 2 : output_lane == 1;
                const auto &input = from_second ? source2 : source1;
                const unsigned copy_from = lane_base + source_lane * lane_bytes;
                const unsigned copy_to = lane_base + output_lane * lane_bytes;
                for (unsigned byte = 0; byte < lane_bytes; ++byte)
                    result.bytes[copy_to + byte] = input[copy_from + byte];
            }
        }
        return result;
    }

    if (immediate_shift) {
        const auto *count = std::get_if<ImmediateOperand>(&instruction.operands[2]);
        if (!count) return std::nullopt;
        evaluate_immediate_shift(instruction.opcode, source1, static_cast<std::uint8_t>(count->value),
                                 result.bytes, bytes);
        return result;
    }

    if (absolute) {
        evaluate_absolute_lanes(*absolute, source1, result.bytes, bytes);
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
    const auto immediate_shape = immediate_shift_shape(instruction.opcode);
    if (immediate_shape && immediate_shape->second_bits == 8 &&
        immediate_shape->result_bits != 128) {
        const auto width = static_cast<unsigned>(instruction.vector_bits);
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
        const auto *count_operand = std::get_if<ImmediateOperand>(&instruction.operands[2]);
        if (!is_evex_vector(instruction.operands[0], width) ||
            (!is_evex_vector(instruction.operands[1], width) && (!memory || memory->data_width != width)) ||
            !count_operand || count_operand->encoded_width != 8 || count_operand->effective_width != 8 ||
            count_operand->is_signed || count_operand->value > 0xff ||
            (instruction.vector_element_bits && instruction.vector_element_bits != immediate_shape->result_bits) ||
            instruction.x86_evex_broadcast || instruction.x86_evex_sae ||
            (instruction.x86_opmask && (*instruction.x86_opmask == 0 || *instruction.x86_opmask > 7)) ||
            (instruction.x86_opmask && !instruction.x86_opmask_zeroing && !old_destination))
            return std::nullopt;
        X86EvexIntegerResult result{};
        result.vector_bits = static_cast<std::uint16_t>(width);
        const auto lane_bits = static_cast<unsigned>(immediate_shape->result_bits);
        const auto lane_bytes = lane_bits / 8;
        const auto lane_mask = lane_bits == 64 ? UINT64_MAX : (UINT64_C(1) << lane_bits) - 1;
        const bool left_shift = instruction.opcode == Opcode::vpsllw || instruction.opcode == Opcode::vpslld ||
                                instruction.opcode == Opcode::vpsllq;
        const bool arithmetic = instruction.opcode == Opcode::vpsraw || instruction.opcode == Opcode::vpsrad;
        for (unsigned offset = 0; offset < width / 8; offset += lane_bytes) {
            const auto lane = offset / lane_bytes;
            const auto input = load_lane(source1, offset, lane_bits);
            const auto sign = UINT64_C(1) << (lane_bits - 1);
            std::uint64_t value = 0;
            if (count_operand->value >= lane_bits) {
                value = arithmetic && (input & sign) ? lane_mask : 0;
            } else if (left_shift) {
                value = (input << static_cast<unsigned>(count_operand->value)) & lane_mask;
            } else {
                value = input >> static_cast<unsigned>(count_operand->value);
                if (arithmetic && count_operand->value != 0 && (input & sign))
                    value |= lane_mask ^ (lane_mask >> static_cast<unsigned>(count_operand->value));
            }
            if (instruction.x86_opmask && !((opmask_value >> lane) & 1))
                value = instruction.x86_opmask_zeroing ? 0 : load_lane(*old_destination, offset, lane_bits);
            store_lane(result.bytes, offset, lane_bits, value & lane_mask);
        }
        return result;
    }
    if (instruction.opcode == Opcode::vpshufd) {
        const auto width = static_cast<unsigned>(instruction.vector_bits);
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
        const auto *selector = std::get_if<ImmediateOperand>(&instruction.operands[2]);
        if (!is_evex_vector(instruction.operands[0], width) ||
            (!is_evex_vector(instruction.operands[1], width) && (!memory || memory->data_width != width)) ||
            !selector || selector->encoded_width != 8 || selector->effective_width != 8 || selector->is_signed ||
            (instruction.vector_element_bits && instruction.vector_element_bits != 32) ||
            (instruction.x86_opmask && (*instruction.x86_opmask == 0 || *instruction.x86_opmask > 7)) ||
            (instruction.x86_opmask && !instruction.x86_opmask_zeroing && !old_destination))
            return std::nullopt;
        X86EvexIntegerResult result{};
        result.vector_bits = static_cast<std::uint16_t>(width);
        const auto active_bytes = width / 8;
        for (unsigned base = 0; base < active_bytes; base += 16)
            for (unsigned lane = 0; lane < 4; ++lane) {
                const auto source_lane = (selector->value >> (2 * lane)) & 3;
                const auto destination_lane = base / 4 + lane;
                const auto source_offset = base + static_cast<unsigned>(source_lane) * 4;
                const auto destination_offset = base + lane * 4;
                const bool active = !instruction.x86_opmask || ((opmask_value >> destination_lane) & 1);
                for (unsigned byte = 0; byte < 4; ++byte) {
                    result.bytes[destination_offset + byte] = active
                        ? source1[source_offset + byte]
                        : instruction.x86_opmask_zeroing ? std::byte{} : (*old_destination)[destination_offset + byte];
                }
            }
        return result;
    }
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
    else if (is_variable_shift(instruction.opcode))
        evaluate_integer_dataflow(instruction.opcode,*shape,source1,source2,result.bytes,active_bytes);
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

// Exact EVEX VPTERNLOGD/Q evaluation. source_a is the pre-instruction
// destination, source_b is EVEX.vvvv, and source_c is ModRM.r/m. It also
// supplies the merge value for masked-off destination lanes.
inline std::optional<X86EvexIntegerResult> evaluate_x86_evex_ternary_logic(
    const Instruction &instruction, const std::array<std::byte, 64> &source_a,
    const std::array<std::byte, 64> &source_b, const std::array<std::byte, 64> &source_c,
    std::uint64_t opmask_value = UINT64_MAX) noexcept {
    using namespace x86_avx_detail;
    const bool qword = instruction.opcode == Opcode::vpternlogq;
    if (instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 || !instruction.x86_evex ||
        (instruction.opcode != Opcode::vpternlogd && !qword) || instruction.operands.size() != 4 ||
        (instruction.vector_bits != 128 && instruction.vector_bits != 256 && instruction.vector_bits != 512) ||
        instruction.x86_evex_broadcast || instruction.x86_evex_sae ||
        (instruction.vector_element_bits && instruction.vector_element_bits != (qword ? 64 : 32)) ||
        (instruction.x86_opmask_zeroing && !instruction.x86_opmask))
        return std::nullopt;
    const auto width = static_cast<unsigned>(instruction.vector_bits);
    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[2]);
    const auto *truth_table = std::get_if<ImmediateOperand>(&instruction.operands[3]);
    if (!is_evex_vector(instruction.operands[0], width) || !is_evex_vector(instruction.operands[1], width) ||
        (!is_evex_vector(instruction.operands[2], width) && (!memory || memory->data_width != width)) ||
        !truth_table || truth_table->encoded_width != 8 || truth_table->effective_width != 8 || truth_table->is_signed ||
        (instruction.x86_opmask && (*instruction.x86_opmask == 0 || *instruction.x86_opmask > 7)))
        return std::nullopt;
    X86EvexIntegerResult result{};
    result.vector_bits = static_cast<std::uint16_t>(width);
    const auto lane_bits = qword ? 64u : 32u;
    const auto lane_bytes = lane_bits / 8;
    for (unsigned offset = 0; offset < width / 8; offset += lane_bytes) {
        const auto lane = offset / lane_bytes;
        const auto lane_mask = lane_bits == 64 ? UINT64_MAX : (UINT64_C(1) << lane_bits) - 1;
        const bool active = !instruction.x86_opmask || ((opmask_value >> lane) & 1);
        auto value = active ? UINT64_C(0) : instruction.x86_opmask_zeroing ? UINT64_C(0)
            : load_lane(source_a, offset, lane_bits);
        if (active) {
            const auto a = load_lane(source_a, offset, lane_bits);
            const auto b = load_lane(source_b, offset, lane_bits);
            const auto c = load_lane(source_c, offset, lane_bits);
            value = 0;
            for (unsigned bit = 0; bit < lane_bits; ++bit) {
                const auto index = static_cast<unsigned>(((a >> bit) & 1) << 2 |
                    ((b >> bit) & 1) << 1 | ((c >> bit) & 1));
                if ((truth_table->value >> index) & 1)
                    value |= UINT64_C(1) << bit;
            }
        }
        store_lane(result.bytes, offset, lane_bits, value & lane_mask);
    }
    return result;
}

inline std::optional<X86EvexIntegerResult> evaluate_x86_evex_mask_to_vector(
    const Instruction &instruction, std::uint64_t mask_value) noexcept {
    using namespace x86_avx_detail;
    unsigned element_bits = 0;
    switch (instruction.opcode) {
    case Opcode::vpmovm2b: element_bits = 8; break;
    case Opcode::vpmovm2w: element_bits = 16; break;
    case Opcode::vpmovm2d: element_bits = 32; break;
    case Opcode::vpmovm2q: element_bits = 64; break;
    default: return std::nullopt;
    }
    if (instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 || !instruction.x86_evex ||
        instruction.operands.size() != 2 ||
        (instruction.vector_bits != 128 && instruction.vector_bits != 256 && instruction.vector_bits != 512) ||
        (instruction.vector_element_bits && instruction.vector_element_bits != element_bits) ||
        instruction.x86_opmask || instruction.x86_opmask_zeroing)
        return std::nullopt;
    const auto width = static_cast<unsigned>(instruction.vector_bits);
    const auto *source_mask = std::get_if<RegisterOperand>(&instruction.operands[1]);
    if (!is_evex_vector(instruction.operands[0], width) || !source_mask ||
        source_mask->bank != RegisterBank::opmask || source_mask->index >= 8 || source_mask->width != 64 ||
        source_mask->high_byte)
        return std::nullopt;
    X86EvexIntegerResult result{};
    result.vector_bits = static_cast<std::uint16_t>(width);
    const auto lanes = width / element_bits;
    const auto lane_mask = element_bits == 64 ? UINT64_MAX : (UINT64_C(1) << element_bits) - 1;
    for (unsigned lane = 0; lane < lanes; ++lane)
        store_lane(result.bytes, lane * (element_bits / 8), element_bits,
            (mask_value & (UINT64_C(1) << lane)) ? lane_mask : 0);
    return result;
}

inline std::optional<X86EvexMaskCompareResult> evaluate_x86_evex_vector_to_mask(
    const Instruction &instruction, const std::array<std::byte, 64> &source) noexcept {
    using namespace x86_avx_detail;
    unsigned element_bits = 0;
    switch (instruction.opcode) {
    case Opcode::vpmovb2m: element_bits = 8; break;
    case Opcode::vpmovw2m: element_bits = 16; break;
    case Opcode::vpmovd2m: element_bits = 32; break;
    case Opcode::vpmovq2m: element_bits = 64; break;
    default: return std::nullopt;
    }
    if (instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 || !instruction.x86_evex ||
        instruction.operands.size() != 2 ||
        (instruction.vector_bits != 128 && instruction.vector_bits != 256 && instruction.vector_bits != 512) ||
        (instruction.vector_element_bits && instruction.vector_element_bits != element_bits) ||
        instruction.x86_opmask || instruction.x86_opmask_zeroing)
        return std::nullopt;
    const auto width = static_cast<unsigned>(instruction.vector_bits);
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    if (!destination || destination->bank != RegisterBank::opmask || destination->index >= 8 ||
        destination->width != 64 || destination->high_byte || !is_evex_vector(instruction.operands[1], width))
        return std::nullopt;
    X86EvexMaskCompareResult result{};
    result.vector_bits = static_cast<std::uint16_t>(width);
    result.active_bits = static_cast<std::uint8_t>(width / element_bits);
    const auto sign = UINT64_C(1) << (element_bits - 1);
    for (unsigned lane = 0; lane < result.active_bits; ++lane)
        if (load_lane(source, lane * (element_bits / 8), element_bits) & sign)
            result.mask |= UINT64_C(1) << lane;
    return result;
}

// Caller-driven value semantics for the decoded VEX K-register Boolean family.
// The source values are the low 8/16/32/64-bit contents of the decoded K
// operands. K-register destinations are zero-extended from the opcode width.
struct X86OpmaskBooleanResult {
    std::uint64_t value = 0;
    std::uint8_t width = 0;
    bool operator==(const X86OpmaskBooleanResult &) const = default;
};

// Defined RFLAGS bit-vector update for KTEST/KORTEST. Bits outside
// written_mask are preserved by callers; architectural RFLAGS positions are used.
struct X86OpmaskTestResult {
    std::uint64_t flags_value = 0;
    std::uint64_t written_mask = 0;
    std::uint8_t width = 0;
    bool operator==(const X86OpmaskTestResult &) const = default;
};

inline std::optional<X86OpmaskTestResult> evaluate_x86_opmask_test(
    const Instruction &instruction, std::uint64_t destination, std::uint64_t source) noexcept {
    unsigned width = 0; bool use_or = false;
    switch (instruction.opcode) {
#define HEXLAB_KTEST_CASE(op, bits, is_or) case Opcode::op: width = bits; use_or = is_or; break
    HEXLAB_KTEST_CASE(ktestb,8,false); HEXLAB_KTEST_CASE(ktestw,16,false);
    HEXLAB_KTEST_CASE(ktestd,32,false); HEXLAB_KTEST_CASE(ktestq,64,false);
    HEXLAB_KTEST_CASE(kortestb,8,true); HEXLAB_KTEST_CASE(kortestw,16,true);
    HEXLAB_KTEST_CASE(kortestd,32,true); HEXLAB_KTEST_CASE(kortestq,64,true);
#undef HEXLAB_KTEST_CASE
    default: return std::nullopt;
    }
    if (instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 || instruction.flow != FlowKind::fallthrough ||
        instruction.x86_evex || instruction.operands.size() != 2 || instruction.access.size() != 2 ||
        instruction.access[0] != OperandAccess::read || instruction.access[1] != OperandAccess::read ||
        instruction.memory_read || instruction.memory_write || instruction.register_reads.size() != 3 ||
        instruction.register_writes.size() != 1) return std::nullopt;
    for (const auto &operand : instruction.operands) {
        const auto *reg = std::get_if<RegisterOperand>(&operand);
        if (!reg || reg->bank != RegisterBank::opmask || reg->index >= 8 || reg->width != 64 || reg->high_byte)
            return std::nullopt;
    }
    const auto mask = width == 64 ? UINT64_MAX : (UINT64_C(1) << width) - 1;
    destination &= mask; source &= mask;
    const bool cf = use_or ? ((destination | source) == mask) : ((destination & ~source & mask) == 0);
    const bool zf = use_or ? ((destination | source) == 0) : ((destination & source) == 0);
    const auto *flags_read = &instruction.register_reads[2];
    const auto &flags_write = instruction.register_writes[0];
    if (instruction.register_reads[0].bank != RegisterBank::opmask || instruction.register_reads[0].index !=
            std::get<RegisterOperand>(instruction.operands[0]).index || instruction.register_reads[0].width != 64 ||
        instruction.register_reads[1].bank != RegisterBank::opmask || instruction.register_reads[1].index !=
            std::get<RegisterOperand>(instruction.operands[1]).index || instruction.register_reads[1].width != 64 ||
        flags_read->bank != RegisterBank::flags || flags_read->width !=
            (instruction.context.mode == ExecutionMode::x86_64 ? 64 : 32) ||
        flags_write.bank != RegisterBank::flags || flags_write.index != 0 || flags_write.width != flags_read->width ||
        flags_write.high_byte)
        return std::nullopt;
    constexpr std::uint64_t CF = 1, PF = 1u << 2, AF = 1u << 4, ZF = 1u << 6, SF = 1u << 7, OF = 1u << 11;
    constexpr std::uint64_t written = CF | PF | AF | ZF | SF | OF;
    return X86OpmaskTestResult{(cf ? CF : 0) | (zf ? ZF : 0), written, static_cast<std::uint8_t>(width)};
}

inline std::optional<X86OpmaskBooleanResult> evaluate_x86_opmask_boolean(
    const Instruction &instruction, std::uint64_t source1,
    std::optional<std::uint64_t> source2 = std::nullopt) noexcept {
    unsigned width = 0;
    enum class Operation : std::uint8_t { and_, and_not, or_, xor_, xnor, not_ } operation{};
    switch (instruction.opcode) {
    case Opcode::kandb: width = 8; operation = Operation::and_; break;
    case Opcode::kandw: width = 16; operation = Operation::and_; break;
    case Opcode::kandd: width = 32; operation = Operation::and_; break;
    case Opcode::kandq: width = 64; operation = Operation::and_; break;
    case Opcode::kandnb: width = 8; operation = Operation::and_not; break;
    case Opcode::kandnw: width = 16; operation = Operation::and_not; break;
    case Opcode::kandnd: width = 32; operation = Operation::and_not; break;
    case Opcode::kandnq: width = 64; operation = Operation::and_not; break;
    case Opcode::korb: width = 8; operation = Operation::or_; break;
    case Opcode::korw: width = 16; operation = Operation::or_; break;
    case Opcode::kord: width = 32; operation = Operation::or_; break;
    case Opcode::korq: width = 64; operation = Operation::or_; break;
    case Opcode::kxorb: width = 8; operation = Operation::xor_; break;
    case Opcode::kxorw: width = 16; operation = Operation::xor_; break;
    case Opcode::kxord: width = 32; operation = Operation::xor_; break;
    case Opcode::kxorq: width = 64; operation = Operation::xor_; break;
    case Opcode::kxnorb: width = 8; operation = Operation::xnor; break;
    case Opcode::kxnorw: width = 16; operation = Operation::xnor; break;
    case Opcode::kxnord: width = 32; operation = Operation::xnor; break;
    case Opcode::kxnorq: width = 64; operation = Operation::xnor; break;
    case Opcode::knotb: width = 8; operation = Operation::not_; break;
    case Opcode::knotw: width = 16; operation = Operation::not_; break;
    case Opcode::knotd: width = 32; operation = Operation::not_; break;
    case Opcode::knotq: width = 64; operation = Operation::not_; break;
    default: return std::nullopt;
    }

    const bool unary = operation == Operation::not_;
    const auto expected_operands = unary ? 2u : 3u;
    if (instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 ||
        instruction.flow != FlowKind::fallthrough || instruction.x86_evex ||
        instruction.x86_opmask || instruction.x86_opmask_zeroing ||
        instruction.x86_evex_broadcast || instruction.x86_evex_sae ||
        instruction.memory_read || instruction.memory_write ||
        instruction.operands.size() != expected_operands ||
        instruction.access.size() != expected_operands ||
        instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read ||
        (!unary && instruction.access[2] != OperandAccess::read) ||
        (unary && source2.has_value()) || (!unary && !source2))
        return std::nullopt;

    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *first = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *second = unary ? nullptr : std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto valid_register = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::opmask && reg->index < 8 &&
            reg->width == 64 && !reg->high_byte;
    };
    if (!valid_register(destination) || !valid_register(first) || (!unary && !valid_register(second)) ||
        instruction.register_reads.size() != expected_operands - 1 ||
        instruction.register_writes.size() != 1 ||
        instruction.register_writes[0].bank != RegisterBank::opmask ||
        instruction.register_writes[0].index != destination->index ||
        instruction.register_writes[0].width != 64 || instruction.register_writes[0].high_byte)
        return std::nullopt;
    if (instruction.register_reads[0].bank != RegisterBank::opmask ||
        instruction.register_reads[0].index != first->index ||
        instruction.register_reads[0].width != 64 || instruction.register_reads[0].high_byte)
        return std::nullopt;
    if (!unary && (instruction.register_reads[1].bank != RegisterBank::opmask ||
        instruction.register_reads[1].index != second->index ||
        instruction.register_reads[1].width != 64 || instruction.register_reads[1].high_byte))
        return std::nullopt;

    const auto mask = width == 64 ? UINT64_MAX : (UINT64_C(1) << width) - 1;
    std::uint64_t value = 0;
    switch (operation) {
    case Operation::and_: value = source1 & *source2; break;
    case Operation::and_not: value = ~source1 & *source2; break;
    case Operation::or_: value = source1 | *source2; break;
    case Operation::xor_: value = source1 ^ *source2; break;
    case Operation::xnor: value = ~(source1 ^ *source2); break;
    case Operation::not_: value = ~source1; break;
    }
    return X86OpmaskBooleanResult{value & mask, static_cast<std::uint8_t>(width)};
}

// Value semantics for KADD, KSHIFT, and KUNPCK. Inputs are the decoded K
// register values; KSHIFT's immediate is passed separately.
inline std::optional<X86OpmaskBooleanResult> evaluate_x86_opmask_arithmetic(
    const Instruction &instruction, std::uint64_t source1,
    std::optional<std::uint64_t> source2 = std::nullopt,
    std::optional<std::uint8_t> shift = std::nullopt) noexcept {
    unsigned width = 0;
    enum class Operation : std::uint8_t { add, left, right, unpack } operation{};
    switch (instruction.opcode) {
#define HEXLAB_KARITH_WIDTHS(prefix, op) \
    case Opcode::prefix##b: width = 8; operation = Operation::op; break; \
    case Opcode::prefix##w: width = 16; operation = Operation::op; break; \
    case Opcode::prefix##d: width = 32; operation = Operation::op; break; \
    case Opcode::prefix##q: width = 64; operation = Operation::op; break
    HEXLAB_KARITH_WIDTHS(kadd, add);
    case Opcode::kshiftlb: width = 8; operation = Operation::left; break;
    case Opcode::kshiftlw: width = 16; operation = Operation::left; break;
    case Opcode::kshiftld: width = 32; operation = Operation::left; break;
    case Opcode::kshiftlq: width = 64; operation = Operation::left; break;
    case Opcode::kshiftrb: width = 8; operation = Operation::right; break;
    case Opcode::kshiftrw: width = 16; operation = Operation::right; break;
    case Opcode::kshiftrd: width = 32; operation = Operation::right; break;
    case Opcode::kshiftrq: width = 64; operation = Operation::right; break;
#undef HEXLAB_KARITH_WIDTHS
    case Opcode::kunpckbw: width = 16; operation = Operation::unpack; break;
    case Opcode::kunpckwd: width = 32; operation = Operation::unpack; break;
    case Opcode::kunpckdq: width = 64; operation = Operation::unpack; break;
    default: return std::nullopt;
    }
    const bool unary = operation == Operation::left || operation == Operation::right;
    if (instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 || instruction.flow != FlowKind::fallthrough ||
        instruction.x86_evex || instruction.x86_opmask || instruction.x86_opmask_zeroing ||
        instruction.memory_read || instruction.memory_write || instruction.operands.size() != 3 ||
        instruction.access.size() != 3 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read || instruction.access[2] != OperandAccess::read ||
        (!unary && !source2) || (unary != shift.has_value())) return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *first = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto *second = unary ? nullptr : std::get_if<RegisterOperand>(&instruction.operands[2]);
    const auto *immediate = unary ? std::get_if<ImmediateOperand>(&instruction.operands[2]) : nullptr;
    const auto valid_register = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::opmask && reg->index < 8 && reg->width == 64 && !reg->high_byte;
    };
    if (!valid_register(destination) || !valid_register(first) ||
        (unary && (!immediate || immediate->value != *shift || immediate->encoded_width != 8)) ||
        (!unary && !valid_register(second)) ||
        instruction.register_writes.size() != 1 || instruction.register_writes[0].bank != RegisterBank::opmask ||
        instruction.register_writes[0].index != destination->index || instruction.register_writes[0].width != 64 ||
        instruction.register_reads.size() != (unary ? 1u : 2u) || instruction.register_reads[0] != *first ||
        (!unary && instruction.register_reads[1] != *second)) return std::nullopt;
    const auto mask = width == 64 ? UINT64_MAX : (UINT64_C(1) << width) - 1;
    std::uint64_t value = 0;
    if (operation == Operation::add) value = (source1 + *source2) & mask;
    else if (operation == Operation::left) value = *shift >= width ? 0 : (source1 & mask) << *shift;
    else if (operation == Operation::right) value = *shift >= width ? 0 : (source1 & mask) >> *shift;
    else {
        const unsigned half_bytes = width / 16;
        for (unsigned i = 0; i < half_bytes; ++i) {
            value |= ((source1 >> (8 * i)) & 0xff) << (16 * i);
            value |= ((*source2 >> (8 * i)) & 0xff) << (16 * i + 8);
        }
    }
    return X86OpmaskBooleanResult{value & mask, static_cast<std::uint8_t>(width)};
}

inline std::optional<X86EvexIntegerResult> evaluate_x86_evex_popcount(
    const Instruction &instruction, const std::array<std::byte, 64> &source,
    const std::array<std::byte, 64> *old_destination = nullptr,
    std::uint64_t opmask_value = UINT64_MAX) noexcept {
    using namespace x86_avx_detail;
    unsigned element_bits = 0;
    switch (instruction.opcode) {
    case Opcode::vpopcntb: element_bits = 8; break;
    case Opcode::vpopcntw: element_bits = 16; break;
    case Opcode::vpopcntd: element_bits = 32; break;
    case Opcode::vpopcntq: element_bits = 64; break;
    default: return std::nullopt;
    }
    if (instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 || !instruction.x86_evex ||
        instruction.operands.size() != 2 ||
        (instruction.vector_bits != 128 && instruction.vector_bits != 256 && instruction.vector_bits != 512) ||
        (instruction.vector_element_bits && instruction.vector_element_bits != element_bits) ||
        instruction.x86_evex_broadcast || instruction.x86_evex_sae ||
        (instruction.x86_opmask_zeroing && !instruction.x86_opmask))
        return std::nullopt;
    const auto width = static_cast<unsigned>(instruction.vector_bits);
    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
    if (!is_evex_vector(instruction.operands[0], width) ||
        (!is_evex_vector(instruction.operands[1], width) && (!memory || memory->data_width != width)) ||
        (instruction.x86_opmask && (*instruction.x86_opmask == 0 || *instruction.x86_opmask > 7)) ||
        (instruction.x86_opmask && !instruction.x86_opmask_zeroing && !old_destination))
        return std::nullopt;
    X86EvexIntegerResult result{};
    result.vector_bits = static_cast<std::uint16_t>(width);
    const auto lanes = width / element_bits;
    const auto lane_bytes = element_bits / 8;
    for (unsigned lane = 0; lane < lanes; ++lane) {
        const auto offset = lane * lane_bytes;
        const bool active = !instruction.x86_opmask || ((opmask_value >> lane) & 1);
        const auto count = active ? static_cast<std::uint64_t>(std::popcount(
            load_lane(source, offset, element_bits))) : UINT64_C(0);
        const auto value = !active && !instruction.x86_opmask_zeroing
            ? load_lane(*old_destination, offset, element_bits) : count;
        store_lane(result.bytes, offset, element_bits, value);
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

// VFPCLASS has no floating-point exceptions. MXCSR.DAZ controls whether
// subnormal inputs are classified as signed zero; memory access and faults
// remain the caller's responsibility. Masked-off lanes and high K bits clear.
inline std::optional<X86EvexFpClassResult> evaluate_x86_evex_fpclass(
    const Instruction &instruction, const std::array<std::byte, 64> &source,
    std::uint64_t opmask_value = UINT64_MAX, std::uint32_t mxcsr = 0x1f80) noexcept {
    using namespace x86_avx_detail;
    if (instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 || !instruction.x86_evex ||
        (instruction.opcode != Opcode::vfpclassps && instruction.opcode != Opcode::vfpclasspd) ||
        (instruction.vector_bits != 128 && instruction.vector_bits != 256 && instruction.vector_bits != 512) ||
        instruction.operands.size() != 3 || instruction.x86_opmask_zeroing || instruction.x86_evex_sae ||
        (instruction.x86_opmask && (*instruction.x86_opmask == 0 || *instruction.x86_opmask >= 8)))
        return std::nullopt;
    const unsigned width = instruction.vector_bits;
    const unsigned lane_bits = instruction.opcode == Opcode::vfpclassps ? 32 : 64;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
    const auto *classes = std::get_if<ImmediateOperand>(&instruction.operands[2]);
    const bool source_vector = is_evex_vector(instruction.operands[1], width);
    const bool source_memory = memory && memory->data_width ==
        (instruction.x86_evex_broadcast ? lane_bits : width);
    if (!destination || destination->bank != RegisterBank::opmask || destination->index >= 8 ||
        destination->width != 64 || destination->high_byte ||
        (!source_vector && !source_memory) || (instruction.x86_evex_broadcast && !memory) ||
        !classes || classes->encoded_width != 8 || classes->effective_width != 8 || classes->is_signed ||
        (instruction.vector_element_bits && instruction.vector_element_bits != lane_bits))
        return std::nullopt;

    const unsigned lanes = width / lane_bits;
    const auto exponent_mask = lane_bits == 32 ? UINT64_C(0x7f800000) : UINT64_C(0x7ff0000000000000);
    const auto fraction_mask = lane_bits == 32 ? UINT64_C(0x007fffff) : UINT64_C(0x000fffffffffffff);
    const auto quiet_mask = lane_bits == 32 ? UINT64_C(0x00400000) : UINT64_C(0x0008000000000000);
    const auto sign_mask = lane_bits == 32 ? UINT64_C(0x80000000) : UINT64_C(0x8000000000000000);
    const bool daz = (mxcsr & (UINT32_C(1) << 6)) != 0;
    X86EvexFpClassResult result{};
    result.vector_bits = static_cast<std::uint16_t>(width);
    result.active_bits = static_cast<std::uint8_t>(lanes);
    for (unsigned lane = 0; lane < lanes; ++lane) {
        if (instruction.x86_opmask && !(opmask_value & (UINT64_C(1) << lane))) continue;
        const unsigned offset = instruction.x86_evex_broadcast ? 0 : lane * (lane_bits / 8);
        auto bits = load_lane(source, offset, lane_bits);
        const bool denormal = (bits & exponent_mask) == 0 && (bits & fraction_mask) != 0;
        if (daz && denormal) bits &= sign_mask;
        const bool negative = (bits & sign_mask) != 0;
        const auto exponent = bits & exponent_mask;
        const auto fraction = bits & fraction_mask;
        const bool special = exponent == exponent_mask;
        const bool nan = special && fraction != 0;
        const bool signaling = nan && !(fraction & quiet_mask);
        const bool zero = exponent == 0 && fraction == 0;
        const bool infinity = special && fraction == 0;
        const bool finite_nonzero = !special && !zero;
        const bool matches =
            (((classes->value >> 0) & 1) && nan && !signaling) ||
            (((classes->value >> 1) & 1) && zero && !negative) ||
            (((classes->value >> 2) & 1) && zero && negative) ||
            (((classes->value >> 3) & 1) && infinity && !negative) ||
            (((classes->value >> 4) & 1) && infinity && negative) ||
            (((classes->value >> 5) & 1) && denormal && !daz) ||
            (((classes->value >> 6) & 1) && finite_nonzero && negative) ||
            (((classes->value >> 7) & 1) && signaling);
        if (matches) result.mask |= UINT64_C(1) << lane;
    }
    return result;
}

namespace x86_avx_detail {
// Shared IEEE bit-pattern engine. Public entry points validate operand shapes
// and predicates before calling; inactive EVEX lanes never raise exceptions.
template <std::size_t Size>
inline X86EvexFloatCompareResult evaluate_float_compare_lanes(
    unsigned width, unsigned lane_bits, std::uint8_t predicate,
    const std::array<std::byte, Size> &source1,
    const std::array<std::byte, Size> &source2, std::uint64_t opmask_value,
    bool broadcast, bool sae, std::uint32_t mxcsr) noexcept {
    X86EvexFloatCompareResult result{};
    result.vector_bits = static_cast<std::uint16_t>(width);
    result.active_bits = static_cast<std::uint8_t>(width / lane_bits);
    const auto exponent_mask = lane_bits == 32 ? UINT64_C(0x7f800000) : UINT64_C(0x7ff0000000000000);
    const auto fraction_mask = lane_bits == 32 ? UINT64_C(0x007fffff) : UINT64_C(0x000fffffffffffff);
    const auto quiet_mask = lane_bits == 32 ? UINT64_C(0x00400000) : UINT64_C(0x0008000000000000);
    const auto sign_mask = lane_bits == 32 ? UINT64_C(0x80000000) : UINT64_C(0x8000000000000000);
    const auto encoding_mask = lane_bits == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    const bool daz = (mxcsr & (UINT32_C(1) << 6)) != 0;
    bool signaling_predicate = false;
    switch (predicate) {
    case 1: case 2: case 5: case 6: case 9: case 10: case 13: case 14:
    case 16: case 19: case 20: case 23: case 24: case 27: case 28: case 31:
        signaling_predicate = true;
        break;
    default:
        break;
    }
    for (unsigned lane = 0; lane < result.active_bits; ++lane) {
        if (!(opmask_value & (UINT64_C(1) << lane))) continue;
        const auto offset = broadcast ? 0 : lane * (lane_bits / 8);
        auto left = x86_avx_detail::load_lane(source1, lane * (lane_bits / 8), lane_bits);
        auto right = x86_avx_detail::load_lane(source2, offset, lane_bits);
        const auto classify = [&](std::uint64_t bits) {
            const bool special = (bits & exponent_mask) == exponent_mask;
            const auto fraction = bits & fraction_mask;
            const bool nan = special && fraction != 0;
            const bool signaling = nan && !(fraction & quiet_mask);
            const bool subnormal = (bits & exponent_mask) == 0 && (bits & fraction_mask) != 0;
            return std::array<bool, 3>{nan, signaling, subnormal};
        };
        const auto left_class = classify(left);
        const auto right_class = classify(right);
        const bool nan = left_class[0] || right_class[0];
        result.invalid_operation |= left_class[1] || right_class[1] ||
            (signaling_predicate && nan && !(left_class[1] || right_class[1]));
        const bool denormal = left_class[2] || right_class[2];
        result.denormal_operand |= denormal && !daz;
        if (daz) {
            if (left_class[2]) left &= sign_mask;
            if (right_class[2]) right &= sign_mask;
        }

        bool less = false, equal = false;
        if (!nan) {
            const auto magnitude_mask = ~sign_mask;
            const bool left_zero = (left & magnitude_mask) == 0;
            const bool right_zero = (right & magnitude_mask) == 0;
            if (left_zero && right_zero) {
                equal = true;
            } else {
                const auto order_key = [&](std::uint64_t bits) {
                    return bits & sign_mask ? ((~bits) & encoding_mask) : (bits ^ sign_mask);
                };
                const auto left_key = order_key(left), right_key = order_key(right);
                less = left_key < right_key;
                equal = left == right;
            }
        }
        const bool unordered = nan;
        const bool greater = !unordered && !less && !equal;
        bool match = false;
        switch (predicate) {
        case 0: case 8: case 16: case 24: match = equal || (unordered && (predicate == 8 || predicate == 24)); break;
        case 1: case 17: match = !unordered && less; break;
        case 2: case 18: match = !unordered && (less || equal); break;
        case 3: case 19: match = unordered; break;
        case 4: case 20: match = unordered || !equal; break;
        case 5: case 21: match = unordered || !less; break;
        case 6: case 22: match = unordered || (!less && !equal); break;
        case 7: case 23: match = !unordered; break;
        case 9: case 25: match = unordered || less; break;
        case 10: case 26: match = unordered || less || equal; break;
        case 11: case 27: match = false; break;
        case 12: case 28: match = !unordered && !equal; break;
        case 13: case 29: match = !unordered && (greater || equal); break;
        case 14: case 30: match = !unordered && greater; break;
        case 15: case 31: match = true; break;
        default: break; // Callers validate the five-bit predicate.
        }
        if (match) result.mask |= UINT64_C(1) << lane;
    }
    result.completed = sae ||
        (!(result.invalid_operation && !(mxcsr & (UINT32_C(1) << 7))) &&
         !(result.denormal_operand && !(mxcsr & (UINT32_C(1) << 8))));
    result.mxcsr_after = mxcsr;
    if (!sae) {
        if (result.invalid_operation) result.mxcsr_after |= UINT32_C(1);
        if (result.denormal_operand) result.mxcsr_after |= UINT32_C(1) << 1;
    }
    return result;
}
} // namespace x86_avx_detail

// Evaluate the decoded VEX.128/.256 VCMPPS/VCMPPD forms. source1 is
// VEX.vvvv and source2 is the register value or caller-loaded full memory
// vector. The 32 predicates use exact IEEE encodings, with no host FP work.
// MXCSR supplies DAZ and exception masks; mxcsr_after carries sticky IE/DE
// status changes while memory faults remain caller-owned. If completed is false, neither bytes nor upper clearing
// may be committed, including when an exception occurred in a later lane.
inline std::optional<X86AvxFloatCompareResult> evaluate_x86_avx_float_compare(
    const Instruction &instruction, const std::array<std::byte, 32> &source1,
    const std::array<std::byte, 32> &source2, std::uint32_t mxcsr = 0x1f80) noexcept {
    using namespace x86_avx_detail;
    if (!is_vex_context(instruction) || !vex_registers_valid(instruction) || instruction.x86_evex ||
        instruction.x86_opmask || instruction.x86_opmask_zeroing ||
        instruction.x86_evex_broadcast || instruction.x86_evex_sae ||
        (instruction.opcode != Opcode::vcmpps && instruction.opcode != Opcode::vcmppd) ||
        (instruction.vector_bits != 128 && instruction.vector_bits != 256) ||
        instruction.operands.size() != 4)
        return std::nullopt;
    const auto width = static_cast<unsigned>(instruction.vector_bits);
    const unsigned lane_bits = instruction.opcode == Opcode::vcmpps ? 32 : 64;
    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[2]);
    const auto *predicate = std::get_if<ImmediateOperand>(&instruction.operands[3]);
    if ((instruction.vector_element_bits && instruction.vector_element_bits != lane_bits) ||
        !is_xmm_or_ymm(instruction.operands[0], width) ||
        !is_xmm_or_ymm(instruction.operands[1], width) ||
        (!is_xmm_or_ymm(instruction.operands[2], width) && (!memory || memory->data_width != width)) ||
        !predicate || predicate->encoded_width != 8 || predicate->effective_width != 8 ||
        predicate->is_signed || predicate->value >= 32)
        return std::nullopt;
    const auto comparison = evaluate_float_compare_lanes(width, lane_bits,
        static_cast<std::uint8_t>(predicate->value), source1, source2, UINT64_MAX,
        false, false, mxcsr);
    X86AvxFloatCompareResult result{};
    result.vector_bits = static_cast<std::uint16_t>(width);
    result.lane_bits = static_cast<std::uint8_t>(lane_bits);
    result.zeroed_upper_128 = width == 128;
    result.invalid_operation = comparison.invalid_operation;
    result.denormal_operand = comparison.denormal_operand;
    result.completed = comparison.completed;
    result.mxcsr_after = comparison.mxcsr_after;
    for (unsigned lane = 0; lane < width / lane_bits; ++lane)
        store_lane(result.bytes, lane * (lane_bits / 8), lane_bits,
            comparison.mask & (UINT64_C(1) << lane) ? UINT64_MAX : 0);
    return result;
}

// Evaluate EVEX VCMPPS/VCMPPD predicates directly from IEEE bit patterns.
// source2 supplies a full vector for register/non-broadcast operands and the
// scalar value in its low bytes for an EVEX.b memory broadcast. MXCSR supplies
// DAZ and exception-mask controls; mxcsr_after contains sticky IE/DE changes,
// except for embedded SAE. If completed is false, the partial mask must not be
// committed because an unmasked floating-point exception was raised.
inline std::optional<X86EvexFloatCompareResult> evaluate_x86_evex_float_compare(
    const Instruction &instruction, const std::array<std::byte, 64> &source1,
    const std::array<std::byte, 64> &source2, std::uint64_t opmask_value = UINT64_MAX,
    std::uint32_t mxcsr = 0x1f80) noexcept {
    if (instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 || !instruction.x86_evex ||
        (instruction.opcode != Opcode::vcmpps && instruction.opcode != Opcode::vcmppd) ||
        (instruction.vector_bits != 128 && instruction.vector_bits != 256 && instruction.vector_bits != 512) ||
        instruction.operands.size() != 4 || instruction.x86_opmask_zeroing ||
        (instruction.x86_opmask && (*instruction.x86_opmask == 0 || *instruction.x86_opmask >= 8)))
        return std::nullopt;
    const auto width = static_cast<unsigned>(instruction.vector_bits);
    const unsigned lane_bits = instruction.opcode == Opcode::vcmpps ? 32 : 64;
    if (instruction.vector_element_bits && instruction.vector_element_bits != lane_bits) return std::nullopt;
    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[2]);
    const auto *predicate = std::get_if<ImmediateOperand>(&instruction.operands[3]);
    const bool source2_vector = x86_avx_detail::is_evex_vector(instruction.operands[2], width);
    const bool source2_memory = memory && memory->data_width ==
        (instruction.x86_evex_broadcast ? lane_bits : width);
    if (!destination || destination->bank != RegisterBank::opmask || destination->index >= 8 ||
        destination->width != 64 || destination->high_byte ||
        !x86_avx_detail::is_evex_vector(instruction.operands[1], width) ||
        (!source2_vector && !source2_memory) ||
        (instruction.x86_evex_broadcast && !memory) || !predicate ||
        predicate->encoded_width != 8 || predicate->effective_width != 8 || predicate->is_signed ||
        predicate->value >= 32)
        return std::nullopt;

    return x86_avx_detail::evaluate_float_compare_lanes(width, lane_bits,
        static_cast<std::uint8_t>(predicate->value), source1, source2,
        instruction.x86_opmask ? opmask_value : UINT64_MAX,
        instruction.x86_evex_broadcast, instruction.x86_evex_sae, mxcsr);
}

struct X86SimdMovemaskResult {
    std::uint32_t mask = 0;
    std::uint16_t vector_bits = 0;
    std::uint8_t lane_bits = 0;
    std::uint8_t destination_width = 32;
    bool operator==(const X86SimdMovemaskResult &) const = default;
};

// Evaluate register-source PMOVMSKB/VPMOVMSKB and VMOVMSKPS/VMOVMSKPD.
// `source` is in architectural byte order, with byte zero least significant.
inline std::optional<X86SimdMovemaskResult> evaluate_x86_simd_movemask(
    const Instruction &instruction, const std::array<std::byte, 32> &source) noexcept {
    if (instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 || instruction.flow != FlowKind::fallthrough ||
        instruction.x86_evex || instruction.x86_opmask || instruction.x86_opmask_zeroing ||
        instruction.memory_read || instruction.memory_write || instruction.operands.size() != 2 ||
        instruction.access.size() != 2 || instruction.access[0] != OperandAccess::write ||
        instruction.access[1] != OperandAccess::read)
        return std::nullopt;

    unsigned lane_bits = 0;
    switch (instruction.opcode) {
    case Opcode::pmovmskb:
    case Opcode::vpmovmskb: lane_bits = 8; break;
    case Opcode::vmovmskps: lane_bits = 32; break;
    case Opcode::vmovmskpd: lane_bits = 64; break;
    default: return std::nullopt;
    }
    const auto vector_bits = instruction.vector_bits;
    if ((vector_bits != 128 && vector_bits != 256) ||
        instruction.vector_element_bits != lane_bits ||
        (instruction.opcode == Opcode::pmovmskb && vector_bits != 128) ||
        (instruction.opcode != Opcode::pmovmskb && vector_bits != 128 && vector_bits != 256))
        return std::nullopt;

    const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
    const auto *input = std::get_if<RegisterOperand>(&instruction.operands[1]);
    const auto expected_vector_bank = vector_bits == 128 ? RegisterBank::xmm : RegisterBank::ymm;
    if (!destination || destination->bank != RegisterBank::gpr || destination->width != 32 ||
        destination->high_byte || !input || input->bank != expected_vector_bank ||
        input->width != vector_bits || input->high_byte)
        return std::nullopt;

    const auto lane_bytes = lane_bits / 8;
    const auto lane_count = vector_bits / lane_bits;
    X86SimdMovemaskResult result{0, vector_bits, static_cast<std::uint8_t>(lane_bits), 32};
    for (unsigned lane = 0; lane < lane_count; ++lane) {
        const auto msb_byte = lane * lane_bytes + lane_bytes - 1;
        const auto sign = (std::to_integer<std::uint8_t>(source[msb_byte]) >> 7) & 1u;
        result.mask |= static_cast<std::uint32_t>(sign) << lane;
    }
    return result;
}

} // namespace hexlab
