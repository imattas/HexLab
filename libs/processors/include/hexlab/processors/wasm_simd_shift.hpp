#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace hexlab {

struct WasmSimdIntegerShiftOp {
    std::uint32_t subopcode;
    std::string_view name;
    std::string_view intrinsic_name;
    unsigned lane_bits;
    std::string_view operation;
};

// Integer lane shifts use an i32 shift-count operand and produce a v128.
inline constexpr WasmSimdIntegerShiftOp wasm_simd_integer_shift_ops[]{
    {0x6b, "i8x16.shl", "wasm_i8x16_shl", 8, "shl"}, {0x6c, "i8x16.shr_s", "wasm_i8x16_shr_s", 8, "shr_s"},
    {0x6d, "i8x16.shr_u", "wasm_i8x16_shr_u", 8, "shr_u"},
    {0x8b, "i16x8.shl", "wasm_i16x8_shl", 16, "shl"}, {0x8c, "i16x8.shr_s", "wasm_i16x8_shr_s", 16, "shr_s"},
    {0x8d, "i16x8.shr_u", "wasm_i16x8_shr_u", 16, "shr_u"},
    {0xab, "i32x4.shl", "wasm_i32x4_shl", 32, "shl"}, {0xac, "i32x4.shr_s", "wasm_i32x4_shr_s", 32, "shr_s"},
    {0xad, "i32x4.shr_u", "wasm_i32x4_shr_u", 32, "shr_u"},
    {0xcb, "i64x2.shl", "wasm_i64x2_shl", 64, "shl"}, {0xcc, "i64x2.shr_s", "wasm_i64x2_shr_s", 64, "shr_s"},
    {0xcd, "i64x2.shr_u", "wasm_i64x2_shr_u", 64, "shr_u"}};

inline constexpr std::optional<WasmSimdIntegerShiftOp> wasm_simd_integer_shift_op(
    std::uint32_t subopcode) noexcept {
    for (const auto &operation : wasm_simd_integer_shift_ops)
        if (operation.subopcode == subopcode) return operation;
    return std::nullopt;
}

} // namespace hexlab
