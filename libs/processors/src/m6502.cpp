#include "hexlab/processors/decoder.hpp"
#include <algorithm>
#include <array>
#include <cstdint>

namespace hexlab {
namespace {
using R = RegisterOperand;
constexpr RegisterBank bank = RegisterBank::mos6502;
enum class Mode : std::uint8_t { immediate, zero_page, zero_page_x, zero_page_y, absolute, absolute_x,
                                absolute_y, indexed_indirect, indirect_indexed, indirect, accumulator, implied, relative };
R reg(unsigned n) { return {bank, static_cast<std::uint8_t>(n), 8, false}; }
constexpr R a{bank, 0, 8, false}, x{bank, 1, 8, false}, y{bank, 2, 8, false}, p{bank, 3, 8, false}, s{bank, 4, 8, false};
DecodeResult bad(DecodeStatus status, const char *reason) { return {status, {}, reason}; }
}

DecodeResult decode_m6502(std::span<const std::byte> bytes, Address at) {
    if (at.offset > UINT16_MAX)
        return bad(DecodeStatus::invalid, "6502 address exceeds its 16-bit address space");
    if (bytes.empty())
        return bad(DecodeStatus::truncated, "6502 instruction needs an opcode byte");
    const auto op = std::to_integer<unsigned>(bytes[0]);
    Instruction i;
    i.context = {Architecture::mos6502, ExecutionMode::m6502, ByteOrder::little};
    i.address = at;
    auto finish = [&](unsigned length) -> DecodeResult {
        i.length = static_cast<std::uint8_t>(length);
        std::copy_n(bytes.begin(), length, i.bytes.begin());
        return {DecodeStatus::decoded, std::move(i), {}};
    };
    auto need = [&](unsigned n) { return bytes.size() >= n; };
    auto byte = [&](unsigned n) { return std::to_integer<std::uint8_t>(bytes[n]); };
    auto absolute = [&] { return static_cast<std::uint16_t>(byte(1) | (unsigned(byte(2)) << 8)); };
    auto sized_mode = [](Mode mode) {
        switch (mode) {
        case Mode::immediate: case Mode::zero_page: case Mode::zero_page_x: case Mode::zero_page_y:
        case Mode::indexed_indirect: case Mode::indirect_indexed: case Mode::relative: return 2u;
        case Mode::absolute: case Mode::absolute_x: case Mode::absolute_y: case Mode::indirect: return 3u;
        case Mode::accumulator: case Mode::implied: return 1u;
        }
        return 1u;
    };
    auto begin = [&](Opcode opcode, unsigned length) -> bool {
        if (!need(length)) return false;
        i.opcode = opcode;
        return true;
    };
    auto memory = [&](Mode mode) {
        const auto length = sized_mode(mode);
        const std::uint16_t address = length == 2 ? std::uint16_t(byte(1)) : absolute();
        MemoryOperand m{8, 16, {}, {}, {}, 1, address, false, {},
                        EncodedField{1, static_cast<std::uint8_t>(length - 1)}};
        if (mode == Mode::zero_page_x || mode == Mode::absolute_x || mode == Mode::indexed_indirect)
            m.index = x;
        else if (mode == Mode::zero_page_y || mode == Mode::absolute_y || mode == Mode::indirect_indexed)
            m.index = y;
        if (!m.index && mode != Mode::indirect)
            m.resolved_address = Address{at.space, address};
        return m;
    };
    auto data_op = [&](Opcode opcode, Mode mode, R value, bool store, bool rmw = false,
                       bool writes_flags = true, bool reads_carry = false) -> DecodeResult {
        const auto length = sized_mode(mode);
        if (!begin(opcode, length)) return bad(DecodeStatus::truncated, "6502 operand bytes are truncated");
        if (mode == Mode::accumulator) {
            i.operands.emplace_back(a);
            i.access = {OperandAccess::read_write};
            i.register_reads.push_back(a);
            i.register_writes.push_back(a);
        } else if (mode == Mode::immediate) {
            i.operands.emplace_back(ImmediateOperand{byte(1), 8, 8, false, EncodedField{1, 1}});
            i.access = {OperandAccess::read};
        } else {
            const auto m = memory(mode);
            i.operands.emplace_back(m);
            i.access = {rmw ? OperandAccess::read_write : store ? OperandAccess::write : OperandAccess::read};
            if (m.index) i.register_reads.push_back(*m.index);
            if (mode == Mode::indexed_indirect || mode == Mode::indirect_indexed) i.memory_read = true; // pointer fetch
            if (store) {
                i.memory_write = true;
                i.register_reads.push_back(value);
            } else {
                i.memory_read = true;
                if (rmw) i.memory_write = true;
            }
        }
        const bool uses_value = opcode == Opcode::m6502_dcp || opcode == Opcode::m6502_slo ||
            opcode == Opcode::m6502_rla || opcode == Opcode::m6502_sre ||
            opcode == Opcode::m6502_adc || opcode == Opcode::m6502_sbc ||
            opcode == Opcode::m6502_and || opcode == Opcode::m6502_ora || opcode == Opcode::m6502_eor ||
            opcode == Opcode::m6502_cmp || opcode == Opcode::m6502_cpx || opcode == Opcode::m6502_cpy ||
            opcode == Opcode::m6502_bit;
        if (uses_value) i.register_reads.push_back(value);
        const bool writes_value = opcode == Opcode::m6502_slo || opcode == Opcode::m6502_rla ||
            opcode == Opcode::m6502_sre || opcode == Opcode::m6502_adc || opcode == Opcode::m6502_sbc ||
            opcode == Opcode::m6502_and || opcode == Opcode::m6502_ora || opcode == Opcode::m6502_eor ||
            opcode == Opcode::m6502_lda || opcode == Opcode::m6502_ldx || opcode == Opcode::m6502_ldy;
        if (writes_value) i.register_writes.push_back(value);
        if (writes_flags) i.register_writes.push_back(p);
        if (reads_carry) i.register_reads.push_back(p);
        return finish(length);
    };
    auto implied = [&](Opcode opcode, unsigned length = 1) -> bool {
        if (!begin(opcode, length)) return false;
        return true;
    };
    auto transfer = [&](Opcode opcode, R from, R to, bool flags) -> DecodeResult {
        implied(opcode);
        i.register_reads.push_back(from);
        i.register_writes.push_back(to);
        if (flags) i.register_writes.push_back(p);
        return finish(1);
    };

    auto dcp = [&](Mode mode) {
        return data_op(Opcode::m6502_dcp, mode, a, false, true);
    };
    auto undocumented_rmw = [&](Opcode opcode, Mode mode) {
        return data_op(opcode, mode, a, false, true, true, opcode == Opcode::m6502_rla);
    };

    // Regular ALU family: xx01 encodes the operation in bits 7..5 and the
    // addressing form in bits 4..2. This covers 55 legal NMOS opcodes.
    if ((op & 3) == 1) {
        static constexpr Opcode operations[]{Opcode::m6502_ora, Opcode::m6502_and, Opcode::m6502_eor,
            Opcode::m6502_adc, Opcode::m6502_sta, Opcode::m6502_lda, Opcode::m6502_cmp, Opcode::m6502_sbc};
        static constexpr Mode modes[]{Mode::indexed_indirect, Mode::zero_page, Mode::immediate, Mode::absolute,
            Mode::indirect_indexed, Mode::zero_page_x, Mode::absolute_y, Mode::absolute_x};
        const auto operation = (op >> 5) & 7;
        const auto address_mode = (op >> 2) & 7;
        if (!(operation == 4 && address_mode == 2)) {
            const auto mode = modes[address_mode];
            const bool writes = operation == 4;
            return data_op(operations[operation], mode, a, writes, false, !writes,
                           operation == 3 || operation == 7);
        }
    }

    switch (op) {
    // Undocumented NMOS decrement-then-compare family. These byte forms are
    // stable on the NMOS 6502; the decoder records their combined effects.
    case 0xc7: return dcp(Mode::zero_page);
    case 0xd7: return dcp(Mode::zero_page_x);
    case 0xcf: return dcp(Mode::absolute);
    case 0xdf: return dcp(Mode::absolute_x);
    case 0xdb: return dcp(Mode::absolute_y);
    case 0xc3: return dcp(Mode::indexed_indirect);
    case 0xd3: return dcp(Mode::indirect_indexed);
    // Stable undocumented NMOS shift/logic combinations, seven forms each.
    case 0x03: return undocumented_rmw(Opcode::m6502_slo, Mode::indexed_indirect);
    case 0x07: return undocumented_rmw(Opcode::m6502_slo, Mode::zero_page);
    case 0x0f: return undocumented_rmw(Opcode::m6502_slo, Mode::absolute);
    case 0x13: return undocumented_rmw(Opcode::m6502_slo, Mode::indirect_indexed);
    case 0x17: return undocumented_rmw(Opcode::m6502_slo, Mode::zero_page_x);
    case 0x1b: return undocumented_rmw(Opcode::m6502_slo, Mode::absolute_y);
    case 0x1f: return undocumented_rmw(Opcode::m6502_slo, Mode::absolute_x);
    case 0x23: return undocumented_rmw(Opcode::m6502_rla, Mode::indexed_indirect);
    case 0x27: return undocumented_rmw(Opcode::m6502_rla, Mode::zero_page);
    case 0x2f: return undocumented_rmw(Opcode::m6502_rla, Mode::absolute);
    case 0x33: return undocumented_rmw(Opcode::m6502_rla, Mode::indirect_indexed);
    case 0x37: return undocumented_rmw(Opcode::m6502_rla, Mode::zero_page_x);
    case 0x3b: return undocumented_rmw(Opcode::m6502_rla, Mode::absolute_y);
    case 0x3f: return undocumented_rmw(Opcode::m6502_rla, Mode::absolute_x);
    case 0x43: return undocumented_rmw(Opcode::m6502_sre, Mode::indexed_indirect);
    case 0x47: return undocumented_rmw(Opcode::m6502_sre, Mode::zero_page);
    case 0x4f: return undocumented_rmw(Opcode::m6502_sre, Mode::absolute);
    case 0x53: return undocumented_rmw(Opcode::m6502_sre, Mode::indirect_indexed);
    case 0x57: return undocumented_rmw(Opcode::m6502_sre, Mode::zero_page_x);
    case 0x5b: return undocumented_rmw(Opcode::m6502_sre, Mode::absolute_y);
    case 0x5f: return undocumented_rmw(Opcode::m6502_sre, Mode::absolute_x);
    // Logical shifts and rotates (memory and accumulator forms).
    case 0x06: return data_op(Opcode::m6502_asl, Mode::zero_page, {}, false, true);
    case 0x0a: return data_op(Opcode::m6502_asl, Mode::accumulator, a, false, true);
    case 0x0e: return data_op(Opcode::m6502_asl, Mode::absolute, {}, false, true);
    case 0x16: return data_op(Opcode::m6502_asl, Mode::zero_page_x, {}, false, true);
    case 0x1e: return data_op(Opcode::m6502_asl, Mode::absolute_x, {}, false, true);
    case 0x26: return data_op(Opcode::m6502_rol, Mode::zero_page, {}, false, true, true, true);
    case 0x2a: return data_op(Opcode::m6502_rol, Mode::accumulator, a, false, true, true, true);
    case 0x2e: return data_op(Opcode::m6502_rol, Mode::absolute, {}, false, true, true, true);
    case 0x36: return data_op(Opcode::m6502_rol, Mode::zero_page_x, {}, false, true, true, true);
    case 0x3e: return data_op(Opcode::m6502_rol, Mode::absolute_x, {}, false, true, true, true);
    case 0x46: return data_op(Opcode::m6502_lsr, Mode::zero_page, {}, false, true);
    case 0x4a: return data_op(Opcode::m6502_lsr, Mode::accumulator, a, false, true);
    case 0x4e: return data_op(Opcode::m6502_lsr, Mode::absolute, {}, false, true);
    case 0x56: return data_op(Opcode::m6502_lsr, Mode::zero_page_x, {}, false, true);
    case 0x5e: return data_op(Opcode::m6502_lsr, Mode::absolute_x, {}, false, true);
    case 0x66: return data_op(Opcode::m6502_ror, Mode::zero_page, {}, false, true, true, true);
    case 0x6a: return data_op(Opcode::m6502_ror, Mode::accumulator, a, false, true, true, true);
    case 0x6e: return data_op(Opcode::m6502_ror, Mode::absolute, {}, false, true, true, true);
    case 0x76: return data_op(Opcode::m6502_ror, Mode::zero_page_x, {}, false, true, true, true);
    case 0x7e: return data_op(Opcode::m6502_ror, Mode::absolute_x, {}, false, true, true, true);

    // Remaining loads and stores.
    case 0xa2: return data_op(Opcode::m6502_ldx, Mode::immediate, x, false);
    case 0xa6: return data_op(Opcode::m6502_ldx, Mode::zero_page, x, false);
    case 0xb6: return data_op(Opcode::m6502_ldx, Mode::zero_page_y, x, false);
    case 0xae: return data_op(Opcode::m6502_ldx, Mode::absolute, x, false);
    case 0xbe: return data_op(Opcode::m6502_ldx, Mode::absolute_y, x, false);
    case 0xa0: return data_op(Opcode::m6502_ldy, Mode::immediate, y, false);
    case 0xa4: return data_op(Opcode::m6502_ldy, Mode::zero_page, y, false);
    case 0xb4: return data_op(Opcode::m6502_ldy, Mode::zero_page_x, y, false);
    case 0xac: return data_op(Opcode::m6502_ldy, Mode::absolute, y, false);
    case 0xbc: return data_op(Opcode::m6502_ldy, Mode::absolute_x, y, false);
    case 0x86: return data_op(Opcode::m6502_stx, Mode::zero_page, x, true, false, false);
    case 0x96: return data_op(Opcode::m6502_stx, Mode::zero_page_y, x, true, false, false);
    case 0x8e: return data_op(Opcode::m6502_stx, Mode::absolute, x, true, false, false);
    case 0x84: return data_op(Opcode::m6502_sty, Mode::zero_page, y, true, false, false);
    case 0x94: return data_op(Opcode::m6502_sty, Mode::zero_page_x, y, true, false, false);
    case 0x8c: return data_op(Opcode::m6502_sty, Mode::absolute, y, true, false, false);

    // Compare and BIT instructions.
    case 0xc0: return data_op(Opcode::m6502_cpy, Mode::immediate, y, false);
    case 0xc4: return data_op(Opcode::m6502_cpy, Mode::zero_page, y, false);
    case 0xcc: return data_op(Opcode::m6502_cpy, Mode::absolute, y, false);
    case 0xe0: return data_op(Opcode::m6502_cpx, Mode::immediate, x, false);
    case 0xe4: return data_op(Opcode::m6502_cpx, Mode::zero_page, x, false);
    case 0xec: return data_op(Opcode::m6502_cpx, Mode::absolute, x, false);
    case 0x24: return data_op(Opcode::m6502_bit, Mode::zero_page, a, false);
    case 0x2c: return data_op(Opcode::m6502_bit, Mode::absolute, a, false);

    // Increment/decrement memory and index registers.
    case 0xc6: return data_op(Opcode::m6502_dec, Mode::zero_page, {}, false, true);
    case 0xd6: return data_op(Opcode::m6502_dec, Mode::zero_page_x, {}, false, true);
    case 0xce: return data_op(Opcode::m6502_dec, Mode::absolute, {}, false, true);
    case 0xde: return data_op(Opcode::m6502_dec, Mode::absolute_x, {}, false, true);
    case 0xe6: return data_op(Opcode::m6502_inc, Mode::zero_page, {}, false, true);
    case 0xf6: return data_op(Opcode::m6502_inc, Mode::zero_page_x, {}, false, true);
    case 0xee: return data_op(Opcode::m6502_inc, Mode::absolute, {}, false, true);
    case 0xfe: return data_op(Opcode::m6502_inc, Mode::absolute_x, {}, false, true);
    case 0xe8: return transfer(Opcode::m6502_inx, x, x, true);
    case 0xca: return transfer(Opcode::m6502_dex, x, x, true);
    case 0xc8: return transfer(Opcode::m6502_iny, y, y, true);
    case 0x88: return transfer(Opcode::m6502_dey, y, y, true);

    // Transfers.
    case 0xaa: return transfer(Opcode::m6502_tax, a, x, true);
    case 0xa8: return transfer(Opcode::m6502_tay, a, y, true);
    case 0x8a: return transfer(Opcode::m6502_txa, x, a, true);
    case 0x98: return transfer(Opcode::m6502_tya, y, a, true);
    case 0xba: return transfer(Opcode::m6502_tsx, s, x, true);
    case 0x9a: return transfer(Opcode::m6502_txs, x, s, false);

    // Stack operations and processor flags.
    case 0x48: implied(Opcode::m6502_pha); i.register_reads = {a, s}; i.register_writes = {s}; i.memory_write = true; return finish(1);
    case 0x08: implied(Opcode::m6502_php); i.register_reads = {p, s}; i.register_writes = {s}; i.memory_write = true; return finish(1);
    case 0x68: implied(Opcode::m6502_pla); i.register_reads = {s}; i.register_writes = {a, s, p}; i.memory_read = true; return finish(1);
    case 0x28: implied(Opcode::m6502_plp); i.register_reads = {s}; i.register_writes = {s, p}; i.memory_read = true; return finish(1);
    case 0x18: implied(Opcode::m6502_clc); i.register_reads = {p}; i.register_writes = {p}; return finish(1);
    case 0x38: implied(Opcode::m6502_sec); i.register_reads = {p}; i.register_writes = {p}; return finish(1);
    case 0x58: implied(Opcode::m6502_cli); i.register_reads = {p}; i.register_writes = {p}; return finish(1);
    case 0x78: implied(Opcode::m6502_sei); i.register_reads = {p}; i.register_writes = {p}; return finish(1);
    case 0xb8: implied(Opcode::m6502_clv); i.register_reads = {p}; i.register_writes = {p}; return finish(1);
    case 0xd8: implied(Opcode::m6502_cld); i.register_reads = {p}; i.register_writes = {p}; return finish(1);
    case 0xf8: implied(Opcode::m6502_sed); i.register_reads = {p}; i.register_writes = {p}; return finish(1);

    // Direct and indirect control flow.
    case 0x4c: case 0x20: {
        if (!begin(op == 0x4c ? Opcode::m6502_jmp : Opcode::m6502_jsr, 3))
            return bad(DecodeStatus::truncated, "6502 absolute control target is truncated");
        const auto target = absolute();
        i.operands.emplace_back(RelativeOperand{target, 16, 16, EncodedField{1, 2}});
        i.access = {OperandAccess::address};
        i.direct_target = Address{at.space, target};
        i.flow = op == 0x4c ? FlowKind::jump : FlowKind::call;
        if (op == 0x20) { i.register_reads = {s}; i.register_writes = {s}; }
        return finish(3);
    }
    case 0x6c: {
        if (!begin(Opcode::m6502_jmp, 3)) return bad(DecodeStatus::truncated, "6502 indirect JMP pointer is truncated");
        auto pointer = memory(Mode::indirect);
        pointer.data_width = 16;
        i.operands.emplace_back(pointer);
        i.access = {OperandAccess::address};
        i.memory_read = true;
        i.flow = FlowKind::jump;
        return finish(3);
    }
    case 0x60: case 0x40: {
        implied(op == 0x60 ? Opcode::m6502_rts : Opcode::m6502_rti);
        i.flow = FlowKind::ret;
        i.register_reads = {s}; i.register_writes = {s};
        if (op == 0x40) i.register_writes.push_back(p);
        return finish(1);
    }
    case 0x00:
        implied(Opcode::m6502_brk); i.flow = FlowKind::trap;
        i.register_reads = {s, p}; i.register_writes = {s, p}; return finish(1);
    case 0xea: implied(Opcode::nop); return finish(1);

    // Relative branches. The processor status is the condition source; the
    // condition code remains encoded by the selected opcode.
    case 0x10: case 0x30: case 0x50: case 0x70: case 0x90: case 0xb0: case 0xd0: case 0xf0: {
        if (!begin(Opcode::m6502_bpl, 2)) return bad(DecodeStatus::truncated, "6502 branch displacement is truncated");
        static constexpr Opcode branches[]{Opcode::m6502_bpl, Opcode::m6502_bmi, Opcode::m6502_bvc,
            Opcode::m6502_bvs, Opcode::m6502_bcc, Opcode::m6502_bcs, Opcode::m6502_bne, Opcode::m6502_beq};
        i.opcode = branches[((op >> 4) - 1) / 2];
        const auto displacement = static_cast<std::int8_t>(byte(1));
        i.operands.emplace_back(RelativeOperand{displacement, 8, 16, EncodedField{1, 1}});
        i.access = {OperandAccess::address};
        i.register_reads = {p};
        i.flow = FlowKind::conditional_branch;
        i.direct_target = Address{at.space, static_cast<std::uint16_t>(at.offset + 2 + displacement)};
        return finish(2);
    }
    default: break;
    }

    // LDA/LDX/LDY and STX/STY have asymmetric legal addressing modes.
    switch (op) {
    case 0xa9: return data_op(Opcode::m6502_lda, Mode::immediate, a, false);
    case 0xa5: return data_op(Opcode::m6502_lda, Mode::zero_page, a, false);
    case 0xb5: return data_op(Opcode::m6502_lda, Mode::zero_page_x, a, false);
    case 0xad: return data_op(Opcode::m6502_lda, Mode::absolute, a, false);
    case 0xbd: return data_op(Opcode::m6502_lda, Mode::absolute_x, a, false);
    case 0xb9: return data_op(Opcode::m6502_lda, Mode::absolute_y, a, false);
    default: break;
    }

    // Group-2 load/store, compare, BIT, and memory RMW opcode map.
    switch (op) {
    case 0xa2: return data_op(Opcode::m6502_ldx, Mode::immediate, x, false);
    case 0xa6: return data_op(Opcode::m6502_ldx, Mode::zero_page, x, false);
    case 0xb6: return data_op(Opcode::m6502_ldx, Mode::zero_page_y, x, false);
    case 0xae: return data_op(Opcode::m6502_ldx, Mode::absolute, x, false);
    case 0xbe: return data_op(Opcode::m6502_ldx, Mode::absolute_y, x, false);
    case 0xa0: return data_op(Opcode::m6502_ldy, Mode::immediate, y, false);
    case 0xa4: return data_op(Opcode::m6502_ldy, Mode::zero_page, y, false);
    case 0xb4: return data_op(Opcode::m6502_ldy, Mode::zero_page_x, y, false);
    case 0xac: return data_op(Opcode::m6502_ldy, Mode::absolute, y, false);
    case 0xbc: return data_op(Opcode::m6502_ldy, Mode::absolute_x, y, false);
    case 0x86: return data_op(Opcode::m6502_stx, Mode::zero_page, x, true, false, false);
    case 0x96: return data_op(Opcode::m6502_stx, Mode::zero_page_y, x, true, false, false);
    case 0x8e: return data_op(Opcode::m6502_stx, Mode::absolute, x, true, false, false);
    case 0x84: return data_op(Opcode::m6502_sty, Mode::zero_page, y, true, false, false);
    case 0x94: return data_op(Opcode::m6502_sty, Mode::zero_page_x, y, true, false, false);
    case 0x8c: return data_op(Opcode::m6502_sty, Mode::absolute, y, true, false, false);
    case 0xc0: return data_op(Opcode::m6502_cpy, Mode::immediate, y, false);
    case 0xc4: return data_op(Opcode::m6502_cpy, Mode::zero_page, y, false);
    case 0xcc: return data_op(Opcode::m6502_cpy, Mode::absolute, y, false);
    case 0xe0: return data_op(Opcode::m6502_cpx, Mode::immediate, x, false);
    case 0xe4: return data_op(Opcode::m6502_cpx, Mode::zero_page, x, false);
    case 0xec: return data_op(Opcode::m6502_cpx, Mode::absolute, x, false);
    case 0x24: return data_op(Opcode::m6502_bit, Mode::zero_page, a, false);
    case 0x2c: return data_op(Opcode::m6502_bit, Mode::absolute, a, false);
    case 0xc6: return data_op(Opcode::m6502_dec, Mode::zero_page, {}, false, true);
    case 0xd6: return data_op(Opcode::m6502_dec, Mode::zero_page_x, {}, false, true);
    case 0xce: return data_op(Opcode::m6502_dec, Mode::absolute, {}, false, true);
    case 0xde: return data_op(Opcode::m6502_dec, Mode::absolute_x, {}, false, true);
    case 0xe6: return data_op(Opcode::m6502_inc, Mode::zero_page, {}, false, true);
    case 0xf6: return data_op(Opcode::m6502_inc, Mode::zero_page_x, {}, false, true);
    case 0xee: return data_op(Opcode::m6502_inc, Mode::absolute, {}, false, true);
    case 0xfe: return data_op(Opcode::m6502_inc, Mode::absolute_x, {}, false, true);
    default: break;
    }

    // 65C02-defined encodings are called out separately; other unassigned
    // encodings are undocumented NMOS instructions (including stable illegal
    // operations) and are deliberately not assigned fabricated semantics.
    if (op == 0x80 || op == 0x64 || op == 0x74 || op == 0x89 || op == 0x9c || op == 0x9e ||
        op == 0x12 || op == 0x32 || op == 0x52 || op == 0x72 || op == 0x92 || op == 0xb2 || op == 0xd2 || op == 0xf2 ||
        op == 0x04 || op == 0x0c || op == 0x14 || op == 0x1a || op == 0x34 || op == 0x3a || op == 0x3c ||
        op == 0x5a || op == 0x7a || op == 0x7c || op == 0x89 || op == 0x9c || op == 0xcb || op == 0xdb)
        return bad(DecodeStatus::unsupported, "65C02-only opcode is not enabled in the NMOS 6502 mode");
    return bad(DecodeStatus::unsupported, "Undocumented NMOS 6502 opcode has no defined decoder semantics");
}
} // namespace hexlab
