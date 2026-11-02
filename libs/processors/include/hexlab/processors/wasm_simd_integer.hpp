#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace hexlab {

// No-immediate, two-v128-input / one-v128-result integer lane arithmetic.
// Shared by binary decoding, module stack validation, and typed lifting.
struct WasmSimdIntegerBinaryOp {
    std::uint32_t subopcode;
    std::string_view name;
    unsigned lane_bits;
    std::string_view operation;
};

inline std::optional<WasmSimdIntegerBinaryOp> wasm_simd_integer_binary_op(
    std::uint32_t subopcode) noexcept {
    static constexpr WasmSimdIntegerBinaryOp operations[]{
        {0x6e, "i8x16.add", 8, "add"}, {0x71, "i8x16.sub", 8, "sub"},
        {0x8e, "i16x8.add", 16, "add"}, {0x91, "i16x8.sub", 16, "sub"},
        {0xae, "i32x4.add", 32, "add"}, {0xb1, "i32x4.sub", 32, "sub"},
        {0xce, "i64x2.add", 64, "add"}, {0xd1, "i64x2.sub", 64, "sub"},
        {0x6f, "i8x16.add_sat_s", 8, "add_sat_s"}, {0x70, "i8x16.add_sat_u", 8, "add_sat_u"},
        {0x72, "i8x16.sub_sat_s", 8, "sub_sat_s"}, {0x73, "i8x16.sub_sat_u", 8, "sub_sat_u"},
        {0x8f, "i16x8.add_sat_s", 16, "add_sat_s"}, {0x90, "i16x8.add_sat_u", 16, "add_sat_u"},
        {0x92, "i16x8.sub_sat_s", 16, "sub_sat_s"}, {0x93, "i16x8.sub_sat_u", 16, "sub_sat_u"},
        {0x95, "i16x8.mul", 16, "mul"}, {0xb5, "i32x4.mul", 32, "mul"},
        {0xd5, "i64x2.mul", 64, "mul"},
        {0x76, "i8x16.min_s", 8, "min_s"}, {0x77, "i8x16.min_u", 8, "min_u"},
        {0x78, "i8x16.max_s", 8, "max_s"}, {0x79, "i8x16.max_u", 8, "max_u"},
        {0x96, "i16x8.min_s", 16, "min_s"}, {0x97, "i16x8.min_u", 16, "min_u"},
        {0x98, "i16x8.max_s", 16, "max_s"}, {0x99, "i16x8.max_u", 16, "max_u"},
        {0xb6, "i32x4.min_s", 32, "min_s"}, {0xb7, "i32x4.min_u", 32, "min_u"},
        {0xb8, "i32x4.max_s", 32, "max_s"}, {0xb9, "i32x4.max_u", 32, "max_u"},
        {0x7b, "i8x16.avgr_u", 8, "avgr_u"}, {0x9b, "i16x8.avgr_u", 16, "avgr_u"},
        {0x82, "i16x8.q15mulr_sat_s", 16, "q15mulr_sat_s"},
        {0xba, "i32x4.dot_i16x8_s", 16, "dot_i16x8_s"}};
    for (const auto &operation : operations)
        if (operation.subopcode == subopcode) return operation;
    return std::nullopt;
}

enum class WasmSimdIntegerExtendedKind : std::uint8_t {
    narrow,
    extend,
    pairwise_add,
    extended_multiply
};

// Explicit metadata for core integer SIMD transforms. `source_lane_bits` and
// `result_lane_bits` describe the widened/narrowed lane widths. Narrowing reads
// signed source lanes for both result kinds; `signed_result` selects whether
// the narrowed result saturates to signed or unsigned bounds. For the other
// operations `signed_input` controls sign extension/multiplication.
struct WasmSimdIntegerExtendedOp {
    std::uint32_t subopcode;
    std::string_view name;
    WasmSimdIntegerExtendedKind kind;
    unsigned source_lane_bits;
    unsigned result_lane_bits;
    bool signed_input;
    bool signed_result;
    bool high_half;
};

inline std::optional<WasmSimdIntegerExtendedOp> wasm_simd_integer_extended_op(
    std::uint32_t subopcode) noexcept {
    using Kind = WasmSimdIntegerExtendedKind;
    static constexpr WasmSimdIntegerExtendedOp operations[]{
        {0x65, "i8x16.narrow_i16x8_s", Kind::narrow, 16, 8, true, true, false},
        {0x66, "i8x16.narrow_i16x8_u", Kind::narrow, 16, 8, true, false, false},
        {0x85, "i16x8.narrow_i32x4_s", Kind::narrow, 32, 16, true, true, false},
        {0x86, "i16x8.narrow_i32x4_u", Kind::narrow, 32, 16, true, false, false},
        {0x7c, "i16x8.extadd_pairwise_i8x16_s", Kind::pairwise_add, 8, 16, true, true, false},
        {0x7d, "i16x8.extadd_pairwise_i8x16_u", Kind::pairwise_add, 8, 16, false, false, false},
        {0x7e, "i32x4.extadd_pairwise_i16x8_s", Kind::pairwise_add, 16, 32, true, true, false},
        {0x7f, "i32x4.extadd_pairwise_i16x8_u", Kind::pairwise_add, 16, 32, false, false, false},
        {0x87, "i16x8.extend_low_i8x16_s", Kind::extend, 8, 16, true, true, false},
        {0x88, "i16x8.extend_high_i8x16_s", Kind::extend, 8, 16, true, true, true},
        {0x89, "i16x8.extend_low_i8x16_u", Kind::extend, 8, 16, false, false, false},
        {0x8a, "i16x8.extend_high_i8x16_u", Kind::extend, 8, 16, false, false, true},
        {0xa7, "i32x4.extend_low_i16x8_s", Kind::extend, 16, 32, true, true, false},
        {0xa8, "i32x4.extend_high_i16x8_s", Kind::extend, 16, 32, true, true, true},
        {0xa9, "i32x4.extend_low_i16x8_u", Kind::extend, 16, 32, false, false, false},
        {0xaa, "i32x4.extend_high_i16x8_u", Kind::extend, 16, 32, false, false, true},
        {0xc7, "i64x2.extend_low_i32x4_s", Kind::extend, 32, 64, true, true, false},
        {0xc8, "i64x2.extend_high_i32x4_s", Kind::extend, 32, 64, true, true, true},
        {0xc9, "i64x2.extend_low_i32x4_u", Kind::extend, 32, 64, false, false, false},
        {0xca, "i64x2.extend_high_i32x4_u", Kind::extend, 32, 64, false, false, true},
        {0x9c, "i16x8.extmul_low_i8x16_s", Kind::extended_multiply, 8, 16, true, true, false},
        {0x9d, "i16x8.extmul_high_i8x16_s", Kind::extended_multiply, 8, 16, true, true, true},
        {0x9e, "i16x8.extmul_low_i8x16_u", Kind::extended_multiply, 8, 16, false, false, false},
        {0x9f, "i16x8.extmul_high_i8x16_u", Kind::extended_multiply, 8, 16, false, false, true},
        {0xbc, "i32x4.extmul_low_i16x8_s", Kind::extended_multiply, 16, 32, true, true, false},
        {0xbd, "i32x4.extmul_high_i16x8_s", Kind::extended_multiply, 16, 32, true, true, true},
        {0xbe, "i32x4.extmul_low_i16x8_u", Kind::extended_multiply, 16, 32, false, false, false},
        {0xbf, "i32x4.extmul_high_i16x8_u", Kind::extended_multiply, 16, 32, false, false, true},
        {0xdc, "i64x2.extmul_low_i32x4_s", Kind::extended_multiply, 32, 64, true, true, false},
        {0xdd, "i64x2.extmul_high_i32x4_s", Kind::extended_multiply, 32, 64, true, true, true},
        {0xde, "i64x2.extmul_low_i32x4_u", Kind::extended_multiply, 32, 64, false, false, false},
        {0xdf, "i64x2.extmul_high_i32x4_u", Kind::extended_multiply, 32, 64, false, false, true}};
    for (const auto &operation : operations)
        if (operation.subopcode == subopcode) return operation;
    return std::nullopt;
}

} // namespace hexlab
