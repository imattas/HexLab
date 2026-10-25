#pragma once
#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
namespace hexlab::a64_detail {
inline RegisterOperand reg(unsigned index, unsigned width = 64, bool stack = false) {
    return {index == 31 ? (stack ? RegisterBank::arm64_sp : RegisterBank::arm64_zero) : RegisterBank::arm64_gpr,
            static_cast<std::uint8_t>(index), static_cast<std::uint16_t>(width), false};
}
inline constexpr RegisterOperand nzcv{RegisterBank::arm_flags, 0, 4, false};
inline void operand(Instruction &i, Operand value, OperandAccess access) {
    if (const auto *r = std::get_if<RegisterOperand>(&value); r && r->bank != RegisterBank::arm64_zero) {
        if (access == OperandAccess::read || access == OperandAccess::read_write)
            i.register_reads.push_back(*r);
        if (access == OperandAccess::write || access == OperandAccess::read_write)
            i.register_writes.push_back(*r);
    }
    i.operands.push_back(std::move(value));
    i.access.push_back(access);
}
inline std::int64_t signed_value(std::uint64_t bits, unsigned width) {
    const auto sign = UINT64_C(1) << (width - 1);
    return (bits & sign) ? -static_cast<std::int64_t>((UINT64_C(1) << width) - bits) : static_cast<std::int64_t>(bits);
}
inline std::optional<Address> target(Address at, std::int64_t displacement) {
    if (displacement >= 0) {
        if (static_cast<std::uint64_t>(displacement) <= UINT64_MAX - at.offset)
            return Address{at.space, at.offset + static_cast<std::uint64_t>(displacement)};
    } else {
        const auto magnitude = static_cast<std::uint64_t>(-(displacement + 1)) + 1;
        if (magnitude <= at.offset)
            return Address{at.space, at.offset - magnitude};
    }
    return {};
}
inline void immediate(Instruction &i, std::uint64_t value, unsigned encoded, unsigned effective) {
    operand(
        i,
        ImmediateOperand{value, static_cast<std::uint16_t>(encoded), static_cast<std::uint16_t>(effective), false, {}},
        OperandAccess::read);
}
bool flow(Instruction &, std::uint32_t);
bool data(Instruction &, std::uint32_t);
bool simd(Instruction &, std::uint32_t);
bool integer(Instruction &, std::uint32_t);
std::string format(const Instruction &);
std::string mnemonic(Opcode, std::uint8_t);
} // namespace hexlab::a64_detail

