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
        {0x82, "i16x8.q15mulr_sat_s", 16, "q15mulr_sat_s"}};
    for (const auto &operation : operations)
        if (operation.subopcode == subopcode) return operation;
    return std::nullopt;
}

} // namespace hexlab
