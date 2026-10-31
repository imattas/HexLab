#include "x64_internal.hpp"
#include "x64_simd_internal.hpp"

namespace hexlab::x64_detail {
namespace {
bool string_operation(State &s, std::uint8_t opcode) {
    if (opcode >= 0x6c && opcode <= 0x6f) {
        const bool input = opcode == 0x6c || opcode == 0x6d;
        const bool byte = opcode == 0x6c || opcode == 0x6e;
        const auto scalar_width = static_cast<std::uint16_t>(s.rules.long_mode()
            ? (s.operand_override ? 16 : 32) : s.width());
        const auto data_width = static_cast<std::uint16_t>(byte ? 8 : scalar_width);
        const auto address_width = s.rules.address_width(s.address_override);
        const RegisterOperand index{RegisterBank::gpr, static_cast<std::uint8_t>(input ? 7 : 6), address_width, false};
        const RegisterOperand port{RegisterBank::gpr, 2, 16, false};
        MemoryOperand memory;
        memory.data_width = data_width;
        memory.address_width = address_width;
        memory.base = index;
        memory.segment = input ? std::optional<RegisterOperand>{{RegisterBank::segment, 0, 16, false}} : s.segment;
        if (!input && !memory.segment && s.rules.segmented_memory())
            memory.segment = RegisterOperand{RegisterBank::segment, 3, 16, false};
        s.i.opcode = input ? Opcode::x86_ins : Opcode::x86_outs;
        s.i.x86_repeat = s.group1 == 0xf3 ? X86RepeatPrefix::rep
                         : s.group1 == 0xf2 ? X86RepeatPrefix::repne : X86RepeatPrefix::none;
        if (input) s.i.register_reads.push_back(port);
        s.flags_read = true; // DF selects forward or backward index movement.
        s.i.register_reads.push_back(index);
        s.i.register_writes.push_back(index);
        if (s.i.x86_repeat != X86RepeatPrefix::none) {
            const RegisterOperand count{RegisterBank::gpr, 1, address_width, false};
            s.i.register_reads.push_back(count);
            s.i.register_writes.push_back(count);
        }
        if (input) {
            s.operand(memory, OperandAccess::write);
            s.i.memory_write = true;
        } else {
            s.operand(port, OperandAccess::read);
            s.operand(memory, OperandAccess::read);
            s.i.memory_read = true;
        }
        return true;
    }
    if (opcode < 0xa4 || opcode > 0xaf || (opcode > 0xa7 && opcode < 0xaa))
        return false;

    const bool byte = opcode == 0xa4 || opcode == 0xa6 || opcode == 0xaa || opcode == 0xac || opcode == 0xae;
    const auto data_width = static_cast<std::uint16_t>(byte ? 8 : s.width());
    const auto address_width = s.rules.address_width(s.address_override);
    const RegisterOperand source_index{RegisterBank::gpr, 6, address_width, false};
    const RegisterOperand destination_index{RegisterBank::gpr, 7, address_width, false};
    const RegisterOperand accumulator{RegisterBank::gpr, 0, data_width, false};
    const auto memory = [&](RegisterOperand base, std::optional<RegisterOperand> segment) {
        MemoryOperand result;
        result.data_width = data_width;
        result.address_width = address_width;
        result.base = base;
        result.segment = segment;
        return result;
    };
    const auto source_segment = s.segment ? s.segment
                                          : s.rules.segmented_memory()
                                                ? std::optional<RegisterOperand>{{RegisterBank::segment, 3, 16, false}}
                                                : std::nullopt;
    const auto destination_segment = s.rules.segmented_memory()
                                        ? std::optional<RegisterOperand>{{RegisterBank::segment, 0, 16, false}}
                                        : std::nullopt;
    s.i.x86_repeat = s.group1 == 0xf3 ? X86RepeatPrefix::rep
                     : s.group1 == 0xf2 ? X86RepeatPrefix::repne
                                        : X86RepeatPrefix::none;

    switch (opcode) {
    case 0xa4: case 0xa5:
        s.i.opcode = Opcode::x86_movs;
        s.operand(memory(destination_index, destination_segment), OperandAccess::write);
        s.operand(memory(source_index, source_segment), OperandAccess::read);
        break;
    case 0xa6: case 0xa7:
        s.i.opcode = Opcode::x86_cmps;
        s.operand(memory(source_index, source_segment), OperandAccess::read);
        s.operand(memory(destination_index, destination_segment), OperandAccess::read);
        s.flags_write = true;
        break;
    case 0xaa: case 0xab:
        s.i.opcode = Opcode::x86_stos;
        s.operand(memory(destination_index, destination_segment), OperandAccess::write);
        s.operand(accumulator, OperandAccess::read);
        break;
    case 0xac: case 0xad:
        s.i.opcode = Opcode::x86_lods;
        s.operand(accumulator, OperandAccess::write);
        s.operand(memory(source_index, source_segment), OperandAccess::read);
        break;
    case 0xae: case 0xaf:
        s.i.opcode = Opcode::x86_scas;
        s.operand(accumulator, OperandAccess::read);
        s.operand(memory(destination_index, destination_segment), OperandAccess::read);
        s.flags_write = true;
        break;
    default: return false;
    }
    // Every string operation advances one or both index registers according to DF.
    if (opcode == 0xa4 || opcode == 0xa5 || opcode == 0xa6 || opcode == 0xa7 || opcode == 0xac || opcode == 0xad)
        s.i.register_writes.push_back(source_index);
    if (opcode != 0xac && opcode != 0xad)
        s.i.register_writes.push_back(destination_index);
    s.flags_read = true; // Direction flag controls index movement.
    if (s.i.x86_repeat != X86RepeatPrefix::none) {
        const RegisterOperand count{RegisterBank::gpr, 1, address_width, false};
        s.i.register_reads.push_back(count);
        s.i.register_writes.push_back(count);
        if (s.i.opcode == Opcode::x86_cmps || s.i.opcode == Opcode::x86_scas)
            s.flags_read = true; // REPE/REPNE additionally stop on ZF.
    }
    return true;
}
} // namespace
bool move(State &s, std::uint8_t opcode, bool extended) {
    const auto wide = s.width();
    if (!extended && (opcode == 0x27 || opcode == 0x2f)) {
        if (s.rules.long_mode())
            invalid("DAA/DAS are not valid in long mode");
        s.i.opcode = opcode == 0x27 ? Opcode::daa : Opcode::das;
        const RegisterOperand al{RegisterBank::gpr, 0, 8, false};
        s.i.register_reads.push_back(al);
        s.i.register_writes.push_back(al);
        s.flags_read = true;
        s.flags_write = true;
        return true;
    }
    if (!extended && (opcode == 0xd4 || opcode == 0xd5)) {
        if (s.rules.long_mode())
            invalid("AAM/AAD are not valid in long mode");
        s.i.opcode = opcode == 0xd4 ? Opcode::aam : Opcode::aad;
        const auto base = s.immediate(8, 8, false);
        s.operand(base, OperandAccess::read);
        const RegisterOperand al{RegisterBank::gpr, 0, 8, false};
        const RegisterOperand ah{RegisterBank::gpr, 0, 8, true};
        s.i.register_reads.push_back(al);
        if (opcode == 0xd4)
            s.i.register_writes.insert(s.i.register_writes.end(), {al, ah});
        else {
            s.i.register_reads.push_back(ah);
            s.i.register_writes.push_back(al);
            s.i.register_writes.push_back(ah);
        }
        s.flags_write = true;
        return true;
    }
    if (!extended && opcode == 0x62) {
        if (s.rules.long_mode())
            invalid("BOUND is not valid in long mode; opcode 62 is the EVEX prefix");
        const auto width = s.width();
        auto m = modrm(s, width, width);
        if (m.mod == 3 || !std::holds_alternative<MemoryOperand>(m.rm))
            invalid("BOUND requires a memory bounds-pair operand");
        auto &bounds = std::get<MemoryOperand>(m.rm);
        // One typed memory operand spans the lower and upper bound values.
        bounds.data_width = static_cast<std::uint16_t>(width * 2);
        s.i.opcode = Opcode::bound;
        s.i.flow = FlowKind::trap;
        s.operand(m.reg, OperandAccess::read);
        s.operand(bounds, OperandAccess::read);
        return true;
    }
    if (!extended && (opcode == 0xc4 || opcode == 0xc5)) {
        if (s.rules.long_mode())
            invalid("LES/LDS are not valid in long mode; C4/C5 are VEX prefixes");
        if (!s.rules.default16() && s.position < s.input.size() && (s.peek() & 0xc0u) == 0xc0u)
            unsupported("VEX prefix in legacy mode is outside the typed x86 subset");
        const auto width = s.width();
        auto m = modrm(s, width, width);
        if (m.mod == 3 || !std::holds_alternative<MemoryOperand>(m.rm))
            invalid("LES/LDS require a memory far-pointer operand");
        auto &pointer = std::get<MemoryOperand>(m.rm);
        pointer.data_width = static_cast<std::uint16_t>(width + 16);
        s.i.opcode = opcode == 0xc4 ? Opcode::les : Opcode::lds;
        s.operand(m.reg, OperandAccess::write);
        s.operand(pointer, OperandAccess::read);
        s.i.register_writes.push_back({RegisterBank::segment, static_cast<std::uint8_t>(opcode == 0xc4 ? 0 : 3), 16, false});
        return true;
    }
    if (!extended && (opcode == 0x86 || opcode == 0x87)) {
        const auto width = static_cast<std::uint16_t>(opcode == 0x86 ? 8 : wide);
        auto m = modrm(s, width);
        s.i.opcode = Opcode::xchg;
        s.lock_allowed = std::holds_alternative<MemoryOperand>(m.rm);
        s.operand(m.rm, OperandAccess::read_write);
        s.operand(m.reg, OperandAccess::read_write);
        return true;
    }
    if (extended) {
        if (opcode != 0xb6 && opcode != 0xb7 && opcode != 0xbe && opcode != 0xbf)
            return false;
        s.i.opcode = (opcode == 0xb6 || opcode == 0xb7) ? Opcode::movzx : Opcode::movsx;
        auto m = modrm(s, (opcode == 0xb6 || opcode == 0xbe) ? 8 : 16, wide);
        s.operand(m.reg, OperandAccess::write);
        s.operand(m.rm, OperandAccess::read);
        return true;
    }
    if (opcode >= 0x88 && opcode <= 0x8b) {
        s.i.opcode = Opcode::mov;
        auto m = modrm(s, (opcode & 1) ? wide : 8);
        if (opcode & 2) {
            s.operand(m.reg, OperandAccess::write);
            s.operand(m.rm, OperandAccess::read);
        } else {
            s.operand(m.rm, OperandAccess::write);
            s.operand(m.reg, OperandAccess::read);
        }
    } else if (opcode >= 0xa0 && opcode <= 0xa3) {
        s.i.opcode = Opcode::mov;
        MemoryOperand memory;
        memory.data_width = static_cast<std::uint16_t>((opcode & 1) ? wide : 8);
        memory.address_width = s.rules.address_width(s.address_override);
        memory.segment = s.segment;
        if (!memory.segment && s.rules.segmented_memory())
            memory.segment = RegisterOperand{RegisterBank::segment, 3, 16, false};
        memory.displacement =
            std::bit_cast<std::int64_t>(s.encoded(memory.address_width / 8, memory.displacement_encoding));
        const auto accumulator = gpr(0, memory.data_width);
        if (opcode & 2) {
            s.operand(memory, OperandAccess::write);
            s.operand(accumulator, OperandAccess::read);
        } else {
            s.operand(accumulator, OperandAccess::write);
            s.operand(memory, OperandAccess::read);
        }
    } else if (opcode >= 0xb0 && opcode <= 0xbf) {
        s.i.opcode = Opcode::mov;
        const auto bits = static_cast<std::uint16_t>(opcode < 0xb8 ? 8 : wide);
        s.operand(s.reg(opcode & 7, bits, (s.rex & 1) != 0), OperandAccess::write);
        s.operand(s.immediate(bits, bits, false), OperandAccess::read);
    } else if (opcode == 0xc6 || opcode == 0xc7) {
        s.i.opcode = Opcode::mov;
        const auto bits = static_cast<std::uint16_t>(opcode == 0xc6 ? 8 : wide);
        auto m = modrm(s, bits);
        if (m.group != 0)
            unsupported("C6/C7 extension is not covered");
        s.operand(m.rm, OperandAccess::write);
        s.operand(s.immediate(bits == 64 ? 32 : bits, bits, bits == 64), OperandAccess::read);
    } else if (opcode == 0x8d) {
        s.i.opcode = Opcode::lea;
        auto m = modrm(s, wide);
        if (m.mod == 3)
            invalid("LEA requires a memory address operand");
        // LEA computes the effective offset; FS/GS bases do not participate.
        // Keep the original prefix in bytes, without adding a segment read.
        std::get<MemoryOperand>(m.rm).segment.reset();
        s.operand(m.reg, OperandAccess::write);
        s.operand(m.rm, OperandAccess::address);
    } else if (opcode == 0x63) {
        if (!s.rules.long_mode()) {
            // ARPL is fixed-width: operand-size override does not select a
            // 32-bit form. ModRM r/m is the destination, unlike MOVSXD.
            s.i.opcode = Opcode::arpl;
            auto m = modrm(s, 16);
            s.operand(m.rm, OperandAccess::read_write);
            s.operand(m.reg, OperandAccess::read);
            s.flags_write = true;
        } else {
            s.i.opcode = Opcode::movsxd;
            // Long-mode opcode 63 has both the sign-extending r64 form
            // (REX.W) and the valid same-width r32 form (without REX.W).
            const auto destination_width = static_cast<std::uint16_t>((s.rex & 8) ? 64 : 32);
            auto m = modrm(s, 32, destination_width);
            s.operand(m.reg, OperandAccess::write);
            s.operand(m.rm, OperandAccess::read);
        }
    } else
        return false;
    return true;
}
DecodeResult decode_scalar(std::span<const std::byte> input, Address address, DecodeContext context) {
    using namespace x64_detail;
    try {
        if ((context.mode == ExecutionMode::x86_16 || context.mode == ExecutionMode::x86_32) &&
            address.offset > UINT32_MAX)
            invalid("Instruction address exceeds legacy32-bit EIP domain");
        State state(input, address, context);
        prefixes(state);
        // Address-size and segment overrides may precede VEX. Legacy mandatory
        // prefixes and REX may not; keep them from being silently reinterpreted.
        const auto next = state.peek();
        if (state.rules.long_mode() && next == 0x62) {
            if (state.group1 || state.operand_override || state.rex)
                invalid("Legacy mandatory or REX prefix preceding EVEX is invalid");
            (void)state.take(1);
            const auto p0 = static_cast<unsigned>(state.take(1));
            const auto p1 = static_cast<unsigned>(state.take(1));
            const auto p2 = static_cast<unsigned>(state.take(1));
            if (p0 & 0x0c)
                invalid("EVEX reserved P0 bits are set");
            const unsigned map = p0 & 3;
            if (map == 0)
                invalid("EVEX opcode map zero is reserved");
            if (!(p1 & 4))
                invalid("EVEX fixed P1 bit is not set");
            const unsigned pp = p1 & 3;
            const bool w = (p1 & 0x80) != 0;
            const unsigned vvvv = ((~p1 >> 3) & 15) | (((~p2 >> 3) & 1) << 4);
            const auto vector_length = (p2 >> 5) & 3;
            const unsigned vector_bits = vector_length == 0 ? 128 : vector_length == 1 ? 256 :
                                         vector_length == 2 ? 512 : 0;
            const unsigned mask = p2 & 7;
            const bool zeroing = (p2 & 0x80) != 0;
            const bool broadcast = (p2 & 0x10) != 0;
            // P0.R extends ModRM.reg by 8; P0.R' extends it by 16.
            const bool reg_high = ((~p0 >> 4) & 1) != 0;
            const bool rm_high = ((~p0 >> 6) & 1) != 0;
            state.rex = static_cast<std::uint8_t>(0x40 | (((~p0 >> 7) & 1) << 2) |
                                                  (((~p0 >> 6) & 1) << 1) | ((~p0 >> 5) & 1));
            const auto opcode = static_cast<std::uint8_t>(state.take(1));
            if (!evex_simd(state, opcode, map, pp, vvvv, w, vector_bits, mask, zeroing,
                           reg_high, rm_high, broadcast))
                unsupported("EVEX opcode form is not covered");
            std::string reason;
            finish(state, reason);
            return {DecodeStatus::decoded, std::move(state.i), std::move(reason)};
        }
        // In legacy modes C4/C5 are LES/LDS opcodes. Their second byte can
        // distinguish a VEX prefix only when the top two bits are both set.
        // Keep 16-bit mode on the legacy path until its full VEX constraints
        // are modeled; 32-bit mode shares the existing VEX instruction forms.
        const bool vex_legacy32 = state.i.context.mode == ExecutionMode::x86_32 &&
                                  (next == 0xc4 || next == 0xc5) && state.position + 1 < state.input.size() &&
                                  (std::to_integer<unsigned>(state.input[state.position + 1]) & 0xc0) == 0xc0;
        if ((state.rules.long_mode() || vex_legacy32) && (next == 0xc4 || next == 0xc5)) {
            if (state.group1 || state.operand_override || state.rex)
                invalid("Legacy mandatory or REX prefix preceding VEX is invalid");
            const auto lead = static_cast<std::uint8_t>(state.take(1));
            unsigned map = 1, pp = 0, vvvv = 0;
            bool l = false, w = false;
            if (lead == 0xc5) {
                const auto b = static_cast<unsigned>(state.take(1));
                state.rex = static_cast<std::uint8_t>(0x40 | ((~b >> 7 & 1) << 2));
                vvvv = (~b >> 3) & 15;
                l = (b & 4) != 0;
                pp = b & 3;
            } else {
                const auto b2 = static_cast<unsigned>(state.take(1));
                const auto b3 = static_cast<unsigned>(state.take(1));
                map = b2 & 31;
                if (map == 0)
                    invalid("VEX opcode map zero is reserved");
                state.rex = static_cast<std::uint8_t>(0x40 | ((~b2 >> 7 & 1) << 2) |
                                                      ((~b2 >> 6 & 1) << 1) | (~b2 >> 5 & 1));
                w = (b3 & 0x80) != 0;
                vvvv = (~b3 >> 3) & 15;
                l = (b3 & 4) != 0;
                pp = b3 & 3;
            }
            if (!state.rules.long_mode()) {
                // AVX in 32-bit mode has only XMM/YMM0-7 and GPR0-7.
                // VEX.R/X/B and the upper vvvv register numbers cannot name
                // registers there.
                if ((state.rex & 7) || vvvv > 7)
                    invalid("VEX register extension is unavailable in 32-bit mode");
                state.rex = 0;
            }
            const auto opcode = static_cast<std::uint8_t>(state.take(1));
            if (!vex_simd(state, opcode, map, pp, vvvv, l, w))
                unsupported("VEX opcode form is not covered");
            std::string reason;
            finish(state, reason);
            return {DecodeStatus::decoded, std::move(state.i), std::move(reason)};
        }
        auto opcode = static_cast<std::uint8_t>(state.take(1));
        bool extended = opcode == 0x0f;
        if (extended) {
            opcode = static_cast<std::uint8_t>(state.take(1));
            if (opcode == 0x3a) {
                const auto map_opcode = static_cast<std::uint8_t>(state.take(1));
                if (!simd_0f3a(state, map_opcode))
                    unsupported("Legacy 0F 3A opcode is outside the enabled immediate SIMD subset");
                std::string reason;
                finish(state, reason);
                return {DecodeStatus::decoded, std::move(state.i), std::move(reason)};
            }
            if (opcode == 0x38) {
                const auto map_opcode = static_cast<std::uint8_t>(state.take(1));
                if (map_opcode == 0xf6 &&
                    ((state.group1 == 0 && state.operand_override) ||
                     (state.group1 == 0xf3 && !state.operand_override))) {
                    const std::uint16_t width = state.rules.long_mode() && (state.rex & 8) ? 64 : 32;
                    const auto decoded = modrm(state, width, width);
                    state.i.opcode = state.group1 == 0xf3 ? Opcode::adox : Opcode::adcx;
                    state.operand(decoded.reg, OperandAccess::read_write);
                    state.operand(decoded.rm, OperandAccess::read);
                    state.flags_read = true;
                    state.flags_write = true;
                } else if ((map_opcode == 0xf0 || map_opcode == 0xf1) && state.group1 == 0xf2) {
                    const std::uint16_t destination_width = state.rules.long_mode() && (state.rex & 8) ? 64 : 32;
                    const std::uint16_t source_width = map_opcode == 0xf0 ? 8 : state.width();
                    const auto decoded = modrm(state, source_width, destination_width);
                    state.i.opcode = Opcode::crc32;
                    state.operand(decoded.reg, OperandAccess::read_write);
                    state.operand(decoded.rm, OperandAccess::read);
                    if (state.rules.long_mode() && destination_width == 32)
                        state.i.register_writes.push_back(gpr(decoded.reg.index, 64));
                } else if (map_opcode == 0xf0 || map_opcode == 0xf1) {
                    if (state.group1 == 0xf3)
                        invalid("REP is not valid for MOVBE");
                    const auto width = state.width();
                    const auto decoded = modrm(state, width, width);
                    if (!std::holds_alternative<MemoryOperand>(decoded.rm))
                        invalid("MOVBE requires a memory ModRM r/m operand");
                    const bool load = map_opcode == 0xf0;
                    state.i.opcode = Opcode::movbe;
                    state.operand(load ? Operand{decoded.reg} : decoded.rm, OperandAccess::write);
                    state.operand(load ? decoded.rm : Operand{decoded.reg}, OperandAccess::read);
                    if (load) {
                        const auto full_width = state.rules.pointer_width();
                        if (width < full_width) {
                            const auto full = gpr(decoded.reg.index, full_width);
                            // A 16-bit write preserves the wider view; a
                            // 32-bit long-mode write clears its high half.
                            if (width == 16) state.i.register_reads.push_back(full);
                            state.i.register_writes.push_back(full);
                        }
                    }
                } else if (!simd_0f38(state, map_opcode))
                    unsupported("Legacy 0F 38 opcode is outside the enabled scalar/SSSE3 subset");
                std::string reason;
                finish(state, reason);
                return {DecodeStatus::decoded, std::move(state.i), std::move(reason)};
            }
        }
        const bool f3_bit_count = extended && (opcode == 0xbc || opcode == 0xbd || opcode == 0xb8);
        // CMOVcc and SETcc share the architectural condition encoding used by
        // Jcc. Preserve condition and FLAGS dependency in the typed decode.
        bool conditional_data = false;
        if (extended && opcode >= 0x40 && opcode <= 0x4f) {
            const auto width = state.width();
            const auto decoded = modrm(state, width);
            state.i.opcode = Opcode::cmovcc;
            state.i.condition = opcode & 0x0f;
            state.i.x86_condition = static_cast<X86Condition>(state.i.condition);
            state.operand(decoded.reg, OperandAccess::read_write);
            state.operand(decoded.rm, OperandAccess::read);
            state.flags_read = true;
            conditional_data = true;
        } else if (extended && opcode >= 0x90 && opcode <= 0x9f) {
            const auto decoded = modrm(state, 8);
            state.i.opcode = Opcode::setcc;
            state.i.condition = opcode & 0x0f;
            state.i.x86_condition = static_cast<X86Condition>(state.i.condition);
            state.operand(decoded.rm, OperandAccess::write);
            state.flags_read = true;
            conditional_data = true;
        }
        const bool string_form = !extended && ((opcode >= 0x6c && opcode <= 0x6f) ||
            (opcode >= 0xa4 && opcode <= 0xaf && !(opcode >= 0xa8 && opcode <= 0xa9)));
        const bool simd_form = simd(state, opcode, extended);
        if (!simd_form && ((state.group1 == 0xf2 && !string_form) ||
            (state.group1 == 0xf3 && !f3_bit_count && !string_form &&
             !((!extended && (opcode == 0x90 || opcode == 0xc3)) || (extended && opcode == 0x1e)))))
            unsupported("Repeat/mandatory prefix form is not yet covered");
        if (!conditional_data && !simd_form && !(string_form && string_operation(state, opcode)) && !(!extended && x87(state, opcode)) &&
            !move(state, opcode, extended) &&
            !accumulator_sign_extension(state, opcode, extended) && !bit_operations(state, opcode, extended) &&
            !arithmetic(state, opcode, extended) &&
            !stack_flow(state, opcode, extended))
            unsupported("Opcode form is not yet covered");
        std::string reason;
        finish(state, reason);
        return {DecodeStatus::decoded, std::move(state.i), std::move(reason)};
    } catch (const Failure &failure) {
        return {failure.status, {}, failure.reason};
    }
}
} // namespace hexlab::x64_detail
namespace hexlab {
DecodeResult decode_x64(std::span<const std::byte> input, Address address) {
    return x64_detail::decode_scalar(input, address, {Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little});
}
DecodeResult decode_x86_32(std::span<const std::byte> input, Address address) {
    return x64_detail::decode_scalar(input, address, {Architecture::x86, ExecutionMode::x86_32, ByteOrder::little});
}
DecodeResult decode_x86_16(std::span<const std::byte> input, Address address) {
    return x64_detail::decode_scalar(input, address, {Architecture::x86, ExecutionMode::x86_16, ByteOrder::little});
}
} // namespace hexlab
