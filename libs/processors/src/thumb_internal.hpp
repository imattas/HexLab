#pragma once
#include "arm32_internal.hpp"
#include <algorithm>
namespace hexlab::thumb_detail {
inline RegisterOperand reg(unsigned n) { return {RegisterBank::arm32_gpr, static_cast<std::uint8_t>(n), 32, false}; }
inline constexpr RegisterOperand flags{RegisterBank::arm_flags, 0, 4, false};
inline void read(Instruction &i, RegisterOperand r) {
    if (std::find(i.register_reads.begin(), i.register_reads.end(), r) == i.register_reads.end())
        i.register_reads.push_back(r);
}
inline std::optional<Address> target(Address at, std::int64_t displacement) {
    const auto value = static_cast<std::int64_t>(at.offset) + displacement;
    if (value < 0 || value > UINT32_MAX)
        return {};
    return Address{at.space, static_cast<std::uint64_t>(value)};
}
inline std::int64_t signed_bits(std::uint32_t value, unsigned bits) {
    return (value & (1u << (bits - 1))) ? static_cast<std::int64_t>(value) - (INT64_C(1) << bits) : value;
}
inline bool active(const Instruction &i) { return i.arm->it_before.known && i.arm->it_before.bits; }
bool flow(Instruction &, std::uint16_t, std::optional<std::uint16_t>);
bool data(Instruction &, std::uint16_t);
bool memory(Instruction &, std::uint16_t);
} // namespace hexlab::thumb_detail
