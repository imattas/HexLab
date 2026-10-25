#pragma once
#include "hexlab/processors/decoder.hpp"
#include <algorithm>
#include <bit>

namespace hexlab::x64_detail {
struct Failure {
    DecodeStatus status;
    std::string reason;
};
[[noreturn]] inline void unsupported(const char *reason) { throw Failure{DecodeStatus::unsupported, reason}; }
[[noreturn]] inline void invalid(const char *reason) { throw Failure{DecodeStatus::invalid, reason}; }
inline std::int64_t sign_value(std::uint64_t value, unsigned bits) {
    if (bits == 64)
        return std::bit_cast<std::int64_t>(value);
    const auto mask = (std::uint64_t{1} << bits) - 1;
    value &= mask;
    return value & (std::uint64_t{1} << (bits - 1)) ? -static_cast<std::int64_t>(((~value) & mask) + 1)
                                                    : static_cast<std::int64_t>(value);
}
inline RegisterOperand gpr(std::uint8_t index, std::uint16_t width) { return {RegisterBank::gpr, index, width, false}; }
// Shared x86 parsing rules. Public dispatch controls which contexts are enabled.
struct ModeRules {
    DecodeContext context;
    explicit ModeRules(DecodeContext value) : context(value) {
        if (!processor_capabilities(value).can_decode)
            unsupported("This context has no x86 scalar mode rules");
    }
    bool long_mode() const { return context.mode == ExecutionMode::x86_64; }
    bool default16() const { return context.mode == ExecutionMode::x86_16; }
    bool segmented_memory() const { return default16() || context.segmented_memory; }
    std::uint16_t pointer_width() const { return long_mode() ? 64 : default16() ? 16 : 32; }
    std::uint16_t stack_address_width() const {
        return context.stack_address_width ? context.stack_address_width : pointer_width();
    }
    std::uint16_t operand_width(bool override_size, std::uint8_t rex) const {
        return long_mode() && (rex & 8) ? 64 : default16() ? (override_size ? 32 : 16) : override_size ? 16 : 32;
    }
    std::uint16_t address_width(bool override_size) const {
        return long_mode()   ? (override_size ? 32 : 64)
               : default16() ? (override_size ? 32 : 16)
                             : (override_size ? 16 : 32);
    }
    std::uint16_t stack_width(bool override_size) const {
        return long_mode() ? (override_size ? 16 : 64) : operand_width(override_size, 0);
    }
    std::uint16_t near_width(bool override_size) const { return long_mode() ? 64 : operand_width(override_size, 0); }
    unsigned near_displacement_bytes(bool override_size) const {
        return long_mode() ? 4 : near_width(override_size) / 8;
    }
};
struct State {
    std::span<const std::byte> input;
    ModeRules rules;
    std::size_t position = 0;
    std::uint8_t rex = 0, group1 = 0;
    bool operand_override = false, address_override = false, flags_read = false, flags_write = false,
         lock_allowed = false;
    std::optional<RegisterOperand> segment;
    Instruction i;
    explicit State(std::span<const std::byte> bytes, Address address, DecodeContext context)
        : input(bytes), rules(context) {
        i.address = address;
        i.context = context;
    }
    std::uint64_t take(std::size_t amount);
    std::uint64_t encoded(std::size_t amount, std::optional<EncodedField> &field) {
        const auto start = position;
        const auto value = take(amount);
        field = EncodedField{static_cast<std::uint8_t>(start), static_cast<std::uint8_t>(amount)};
        return value;
    }
    std::uint8_t peek() const;
    std::uint16_t width() const { return rules.operand_width(operand_override, rex); }
    std::uint16_t stack_width() const { return rules.stack_width(operand_override); }
    RegisterOperand reg(unsigned raw, std::uint16_t width, bool extended) const;
    ImmediateOperand immediate(unsigned encoded, unsigned effective, bool is_signed);
    void operand(Operand value, OperandAccess access) {
        i.operands.push_back(std::move(value));
        i.access.push_back(access);
    }
};
struct ModRM {
    std::uint8_t group, mod;
    RegisterOperand reg;
    Operand rm;
};
void prefixes(State &);
ModRM modrm(State &, std::uint16_t rm_width, std::uint16_t reg_width = 0);
void finish(State &, std::string &reason);
bool move(State &, std::uint8_t, bool extended);
bool arithmetic(State &, std::uint8_t, bool extended);
bool bit_operations(State &, std::uint8_t, bool extended);
bool accumulator_sign_extension(State &, std::uint8_t, bool extended);
bool stack_flow(State &, std::uint8_t, bool extended);
bool x87(State &, std::uint8_t);
DecodeResult decode_scalar(std::span<const std::byte>, Address, DecodeContext);
DecodeResult decode_zydis_fallback(std::span<const std::byte>, Address, DecodeContext);
} // namespace hexlab::x64_detail
