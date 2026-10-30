#pragma once
#include "x64_internal.hpp"

namespace hexlab::x64_detail {
// Handles the selected 0F SIMD opcode families after prefixes and the second
// opcode byte have been consumed. Returns false for unrelated opcodes.
bool simd(State &, std::uint8_t opcode, bool extended);
// Handles the selected legacy 0F 38 SSSE3 opcode family.
bool simd_0f38(State &, std::uint8_t opcode);
// Handles the selected legacy 0F 3A immediate SIMD family.
bool simd_0f3a(State &, std::uint8_t opcode);
bool vex_simd(State &, std::uint8_t opcode, unsigned map, unsigned pp, unsigned vvvv, bool l, bool w);
bool evex_simd(State &, std::uint8_t opcode, unsigned map, unsigned pp, unsigned vvvv, bool w,
               unsigned vector_bits, unsigned mask, bool zeroing, bool reg_high, bool rm_high, bool broadcast);
} // namespace hexlab::x64_detail
