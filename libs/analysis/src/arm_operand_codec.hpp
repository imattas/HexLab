#pragma once
#include "hexlab/processors/instruction.hpp"
namespace hexlab::arm_operand_detail {
inline bool valid_thumb_relative(const ThumbRelativeOperand &r) {
    if (r.encoded_width == 6)
        return r.displacement >= 0 && r.displacement < 128 && r.displacement % 2 == 0;
    unsigned bits = 0;
    switch (r.encoded_width) {
    case 8:
        bits = 9;
        break;
    case 11:
        bits = 12;
        break;
    case 20:
        bits = 21;
        break;
    case 23:
    case 24:
        bits = 25;
        break;
    default:
        return false;
    }
    return r.displacement % (r.encoded_width == 23 ? 4 : 2) == 0 && r.displacement >= -(INT64_C(1) << (bits - 1)) &&
           r.displacement < (INT64_C(1) << (bits - 1));
}
inline bool valid_reg(const RegisterOperand &r) {
    return r.bank == RegisterBank::arm32_gpr && r.index < 16 && r.width == 32 && !r.high_byte;
}
inline bool valid_shift(const ArmShiftedRegisterOperand &s) {
    if (!valid_reg(s.source))
        return false;
    if (s.amount_register)
        return valid_reg(*s.amount_register) && s.amount_register->index != 15 && s.source.index != 15 &&
               s.amount == 0 && static_cast<unsigned>(s.shift) <= static_cast<unsigned>(ArmShift::ror);
    switch (s.shift) {
    case ArmShift::lsl:
        return s.amount <= 31;
    case ArmShift::lsr:
    case ArmShift::asr:
        return s.amount >= 1 && s.amount <= 32;
    case ArmShift::ror:
        return s.amount >= 1 && s.amount <= 31;
    case ArmShift::rrx:
        return s.amount == 1;
    }
    return false;
}
inline bool valid_memory(const ArmMemoryOperand &m) {
    if (!valid_reg(m.base) || (m.data_width != 8 && m.data_width != 16 && m.data_width != 32) ||
        (m.sign_extend && m.data_width == 32) || (!m.pre_index && !m.writeback) || (m.writeback && m.base.index == 15))
        return false;
    if (const auto imm = std::get_if<std::uint32_t>(&m.offset)) {
        if (*imm > 4095)
            return false;
    } else {
        const auto &s = std::get<ArmShiftedRegisterOperand>(m.offset);
        if (!valid_shift(s) || s.amount_register || s.source.index == 15 || m.base.index == 15)
            return false;
    }
    return !m.resolved_address ||
           (m.base.index == 15 && m.pre_index && !m.writeback && std::holds_alternative<std::uint32_t>(m.offset) &&
            m.resolved_address->offset <= UINT32_MAX);
}
template <class W> void write_reg(W &out, const RegisterOperand &r) {
    out.number(static_cast<unsigned>(r.bank), 1);
    out.number(r.index, 1);
    out.number(r.width, 2);
    out.number(r.high_byte, 1);
}
template <class R> RegisterOperand read_reg(R &in) {
    const auto bank = static_cast<RegisterBank>(in.number(1));
    const auto index = static_cast<std::uint8_t>(in.number(1));
    const auto width = static_cast<std::uint16_t>(in.number(2));
    return {bank, index, width, in.flag()};
}
template <class W> void write_shift(W &out, const ArmShiftedRegisterOperand &s) {
    write_reg(out, s.source);
    out.number(static_cast<unsigned>(s.shift), 1);
    out.number(s.amount, 1);
    out.number(s.amount_register.has_value(), 1);
    if (s.amount_register)
        write_reg(out, *s.amount_register);
}
template <class R> ArmShiftedRegisterOperand read_shift(R &in) {
    ArmShiftedRegisterOperand s{read_reg(in)};
    s.shift = static_cast<ArmShift>(in.number(1));
    s.amount = static_cast<std::uint8_t>(in.number(1));
    if (in.flag())
        s.amount_register = read_reg(in);
    return s;
}
template <class W> void write_memory(W &out, const ArmMemoryOperand &m) {
    write_reg(out, m.base);
    out.number(m.offset.index(), 1);
    if (const auto imm = std::get_if<std::uint32_t>(&m.offset))
        out.number(*imm, 4);
    else
        write_shift(out, std::get<ArmShiftedRegisterOperand>(m.offset));
    out.number(m.add, 1);
    out.number(m.pre_index, 1);
    out.number(m.writeback, 1);
    out.number(m.data_width, 2);
    out.number(m.sign_extend, 1);
    out.number(m.resolved_address.has_value(), 1);
    if (m.resolved_address)
        out.address(*m.resolved_address);
}
template <class R, class Require> ArmMemoryOperand read_memory(R &in, Require require) {
    ArmMemoryOperand m{read_reg(in)};
    const auto tag = in.number(1);
    require(tag <= 1, "Invalid ARM offset kind");
    if (!tag)
        m.offset = static_cast<std::uint32_t>(in.number(4));
    else
        m.offset = read_shift(in);
    m.add = in.flag();
    m.pre_index = in.flag();
    m.writeback = in.flag();
    m.data_width = static_cast<std::uint16_t>(in.number(2));
    m.sign_extend = in.flag();
    if (in.flag())
        m.resolved_address = in.address();
    require(valid_memory(m), "Invalid ARM memory expression");
    return m;
}
} // namespace hexlab::arm_operand_detail
