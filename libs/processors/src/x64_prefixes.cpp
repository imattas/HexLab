#include "x64_internal.hpp"

namespace hexlab::x64_detail {
std::uint64_t State::take(std::size_t amount) {
    if (amount > 15 - position)
        invalid("Instruction exceeds architectural length limit");
    if (position > input.size() || amount > input.size() - position)
        throw Failure{DecodeStatus::truncated, "Instruction bytes are truncated"};
    std::uint64_t value = 0;
    for (std::size_t n = 0; n < amount; ++n)
        value |= std::to_integer<std::uint64_t>(input[position++]) << (8 * n);
    return value;
}
std::uint8_t State::peek() const {
    if (position >= 15)
        invalid("Instruction exceeds architectural length limit");
    if (position >= input.size())
        throw Failure{DecodeStatus::truncated, "Instruction prefix or opcode is truncated"};
    return std::to_integer<std::uint8_t>(input[position]);
}
void prefixes(State &s) {
    for (;;) {
        const auto byte = s.peek();
        if (s.rules.long_mode() && byte >= 0x40 && byte <= 0x4f) {
            s.rex = static_cast<std::uint8_t>(s.take(1));
            continue;
        }
        if (byte == 0xf0 || byte == 0xf2 || byte == 0xf3) {
            if (s.group1 != 0 && s.group1 != byte)
                unsupported("Conflicting group-one prefixes are not covered");
            s.group1 = byte;
        } else if (byte == 0x66)
            s.operand_override = true;
        else if (byte == 0x67)
            s.address_override = true;
        else if (byte == 0x64 || byte == 0x65)
            s.segment =
                RegisterOperand{RegisterBank::segment, static_cast<std::uint8_t>(byte == 0x64 ? 4 : 5), 16, false};
        else if (byte == 0x26 || byte == 0x2e || byte == 0x36 || byte == 0x3e) {
            if (s.rules.long_mode())
                s.segment.reset();
            else
                s.segment = RegisterOperand{RegisterBank::segment,
                                            static_cast<std::uint8_t>(byte == 0x26   ? 0
                                                                      : byte == 0x2e ? 1
                                                                      : byte == 0x36 ? 2
                                                                                     : 3),
                                            16, false};
        } else
            break;
        (void)s.take(1);
        s.rex = 0; // A REX prefix is effective only after the legacy prefixes.
    }
}
RegisterOperand State::reg(unsigned raw, std::uint16_t bits, bool extended) const {
    const auto index = static_cast<std::uint8_t>(raw + (extended ? 8 : 0));
    if (bits == 8 && !rex && index >= 4 && index < 8)
        return {RegisterBank::gpr, static_cast<std::uint8_t>(index - 4), 8, true};
    return gpr(index, bits);
}
ImmediateOperand State::immediate(unsigned encoded, unsigned effective, bool is_signed) {
    std::optional<EncodedField> field;
    auto value = this->encoded(encoded / 8, field);
    if (is_signed)
        value = static_cast<std::uint64_t>(sign_value(value, encoded));
    if (effective < 64)
        value &= (std::uint64_t{1} << effective) - 1;
    return {value, static_cast<std::uint16_t>(encoded), static_cast<std::uint16_t>(effective), is_signed, field};
}
} // namespace hexlab::x64_detail
