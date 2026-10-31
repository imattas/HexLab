#include "hexlab/processors/decoder.hpp"
#include <algorithm>
#include <array>
#include <cstdint>

namespace hexlab {
namespace {
using R = RegisterOperand;
constexpr RegisterBank bank = RegisterBank::mos6502;
enum class Mode : std::uint8_t { immediate, zero_page, zero_page_x, zero_page_y, zero_page_indirect, absolute, absolute_x,
                                absolute_y, indexed_indirect, indirect_indexed, indirect, accumulator, implied, relative };
R reg(unsigned n) { return {bank, static_cast<std::uint8_t>(n), 8, false}; }
constexpr R a{bank, 0, 8, false}, x{bank, 1, 8, false}, y{bank, 2, 8, false}, p{bank, 3, 8, false}, s{bank, 4, 8, false};
DecodeResult bad(DecodeStatus status, const char *reason) { return {status, {}, reason}; }
constexpr std::array<std::uint8_t, 256> documented_cycles{
    // 00-0f
    7,6,0,0,0,3,5,0,3,2,2,0,0,4,6,0,
    // 10-1f
    2,5,0,0,0,4,6,0,2,4,2,0,0,4,7,0,
    // 20-2f
    6,6,0,0,3,3,5,0,4,2,2,0,4,4,6,0,
    // 30-3f
    2,5,0,0,0,4,6,0,2,4,2,0,0,4,7,0,
    // 40-4f
    6,6,0,0,0,3,5,0,3,2,2,0,3,4,6,0,
    // 50-5f
    2,5,0,0,0,4,6,0,2,4,2,0,0,4,7,0,
    // 60-6f
    6,6,0,0,0,3,5,0,4,2,2,0,5,4,6,0,
    // 70-7f
    2,5,0,0,0,4,6,0,2,4,2,0,0,4,7,0,
    // 80-8f
    0,6,0,0,3,3,3,0,2,0,2,0,4,4,4,0,
    // 90-9f
    2,6,0,0,4,4,4,0,2,5,2,0,0,5,0,5,
    // a0-af
    2,6,2,0,3,3,3,0,2,2,2,0,4,4,4,0,
    // b0-bf
    2,5,0,0,4,4,4,0,2,4,2,0,4,4,4,0,
    // c0-cf
    2,6,0,0,3,3,5,0,2,2,2,0,4,4,6,0,
    // d0-df
    2,5,0,0,0,4,6,0,2,4,0,0,0,4,7,0,
    // e0-ef
    2,6,0,0,3,3,5,0,2,2,2,0,4,4,6,0,
    // f0-ff
    2,5,0,0,0,4,6,0,2,4,2,0,0,4,7,0};
}

static DecodeResult decode_m6502_impl(std::span<const std::byte> bytes, Address at, bool cmos) {
    if (at.offset > UINT16_MAX)
        return bad(DecodeStatus::invalid, "6502 address exceeds its 16-bit address space");
    if (bytes.empty())
        return bad(DecodeStatus::truncated, "6502 instruction needs an opcode byte");
    const auto op = std::to_integer<unsigned>(bytes[0]);
    Instruction i;
    i.context = {Architecture::mos6502, cmos ? ExecutionMode::m65c02 : ExecutionMode::m6502, ByteOrder::little};
    i.address = at;
    auto finish = [&](unsigned length) -> DecodeResult {
        i.length = static_cast<std::uint8_t>(length);
        std::copy_n(bytes.begin(), length, i.bytes.begin());
        const auto base_cycles = documented_cycles[op];
        if (base_cycles || cmos) {
            M6502Timing timing;
            timing.base_cycles = base_cycles;
            if (cmos) {
                // W65C02S differs from the NMOS base table for indirect JMP,
                // absolute-X read/modify/write, and its extension opcodes.
                if (op == 0x6c) timing.base_cycles = 6;
                if (op == 0x1e || op == 0x3e || op == 0x5e || op == 0x7e || op == 0xde || op == 0xfe)
                    timing.base_cycles = 6;
                if (op == 0x12 || op == 0x32 || op == 0x52 || op == 0x72 ||
                    op == 0x92 || op == 0xb2 || op == 0xd2 || op == 0xf2)
                    timing.base_cycles = 5; // (zp) ALU/load/store forms.
                else if (op == 0x80) timing.base_cycles = 3; // BRA includes its taken cycle.
                else if (op == 0x64) timing.base_cycles = 3;
                else if (op == 0x74) timing.base_cycles = 4;
                else if (op == 0x9c) timing.base_cycles = 4;
                else if (op == 0x9e) timing.base_cycles = 5;
                else if (op == 0x04 || op == 0x14) timing.base_cycles = 5; // TSB/TRB zp.
                else if (op == 0x0c || op == 0x1c) timing.base_cycles = 6; // TSB/TRB abs.
                else if (op == 0x89) timing.base_cycles = 2;
                else if (op == 0x34 || op == 0x3c) timing.base_cycles = 4;
                else if (op == 0x1a || op == 0x3a) timing.base_cycles = 2;
                else if (op == 0x5a || op == 0xda) timing.base_cycles = 3; // PHX/PHY.
                else if (op == 0x7a || op == 0xfa) timing.base_cycles = 4; // PLX/PLY.
                else if ((op & 0x0f) == 0x07) timing.base_cycles = 5; // RMB/SMB.
                else if ((op & 0x0f) == 0x0f) timing.base_cycles = 5; // BBR/BBS.
                else if (op == 0xcb || op == 0xdb) timing.base_cycles = 3; // WAI/STP.
                else if (op == 0x7c) timing.base_cycles = 6; // JMP (abs,X).
            }
            if (i.flow == FlowKind::conditional_branch) {
                timing.branch_taken_penalty = true;
                timing.branch_page_cross_penalty = true;
            } else if (cmos && (op == 0x80 || (op & 0x0f) == 0x0f)) {
                // BRA is always taken (already included in its base); BBR/BBS
                // take one additional cycle and may take another across pages.
                timing.branch_page_cross_penalty = true;
                if ((op & 0x0f) == 0x0f) timing.branch_taken_penalty = true;
            } else if (i.memory_read && !i.memory_write) {
                const auto *operand = i.operands.empty() ? nullptr : std::get_if<MemoryOperand>(&i.operands.front());
                // The absolute indexed forms have a three-byte encoding. The
                // (zp),Y family has its own low-nibble encoding and a two-byte
                // instruction; both gain one read cycle only across a page.
                timing.page_cross_penalty = (operand && operand->index && length == 3 && op != 0x7c) ||
                                            ((op & 0x1f) == 0x11);
            }
            timing.decimal_mode_penalty = cmos &&
                (i.opcode == Opcode::m6502_adc || i.opcode == Opcode::m6502_sbc);
            i.m6502_timing = timing;
        }
        return {DecodeStatus::decoded, std::move(i), {}};
    };
    auto need = [&](unsigned n) { return bytes.size() >= n; };
    auto byte = [&](unsigned n) { return std::to_integer<std::uint8_t>(bytes[n]); };
    auto absolute = [&] { return static_cast<std::uint16_t>(byte(1) | (unsigned(byte(2)) << 8)); };
    auto sized_mode = [](Mode mode) {
        switch (mode) {
        case Mode::immediate: case Mode::zero_page: case Mode::zero_page_x: case Mode::zero_page_y: case Mode::zero_page_indirect:
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
        if (!m.index && mode != Mode::indirect && mode != Mode::zero_page_indirect)
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
            if (mode == Mode::indexed_indirect || mode == Mode::indirect_indexed || mode == Mode::zero_page_indirect) i.memory_read = true; // pointer fetch
            if (store) {
                i.memory_write = true;
                i.register_reads.push_back(value);
            } else {
                i.memory_read = true;
                if (rmw) i.memory_write = true;
            }
        }
        const bool uses_value = opcode == Opcode::m6502_dcp || opcode == Opcode::m6502_isc || opcode == Opcode::m6502_slo ||
            opcode == Opcode::m6502_rla || opcode == Opcode::m6502_sre || opcode == Opcode::m6502_rra ||
            opcode == Opcode::m6502_adc || opcode == Opcode::m6502_sbc ||
            opcode == Opcode::m6502_and || opcode == Opcode::m6502_anc || opcode == Opcode::m6502_ora || opcode == Opcode::m6502_eor ||
            opcode == Opcode::m6502_cmp || opcode == Opcode::m6502_cpx || opcode == Opcode::m6502_cpy ||
            opcode == Opcode::m6502_bit;
        if (uses_value) i.register_reads.push_back(value);
        const bool writes_value = opcode == Opcode::m6502_slo || opcode == Opcode::m6502_rla ||
            opcode == Opcode::m6502_sre || opcode == Opcode::m6502_rra || opcode == Opcode::m6502_adc || opcode == Opcode::m6502_sbc ||
            opcode == Opcode::m6502_and || opcode == Opcode::m6502_anc || opcode == Opcode::m6502_ora || opcode == Opcode::m6502_eor ||
            opcode == Opcode::m6502_lda || opcode == Opcode::m6502_ldx || opcode == Opcode::m6502_ldy;
        if (writes_value) i.register_writes.push_back(value);
        if (writes_flags) i.register_writes.push_back(p);
        // A partial N/Z update preserves the incoming modeled P bits.
        if (reads_carry || opcode == Opcode::m6502_lda || opcode == Opcode::m6502_ldx || opcode == Opcode::m6502_ldy)
            i.register_reads.push_back(p);
        return finish(length);
    };
    // CMOS-only zero-page-indirect forms are distinct from NMOS KIL aliases.
    if (cmos && (op == 0x12 || op == 0x32 || op == 0x52 || op == 0x72 ||
                 op == 0x92 || op == 0xb2 || op == 0xd2 || op == 0xf2)) {
        static constexpr Opcode operations[]{Opcode::m6502_ora, Opcode::m6502_and, Opcode::m6502_eor,
            Opcode::m6502_adc, Opcode::m6502_sta, Opcode::m6502_lda, Opcode::m6502_cmp, Opcode::m6502_sbc};
        const unsigned operation = op >> 5;
        return data_op(operations[operation], Mode::zero_page_indirect, a, operation == 4, false, operation != 4,
                       operation == 3 || operation == 7);
    }
    if (cmos && (op == 0x80 || op == 0x64 || op == 0x74 || op == 0x9c || op == 0x9e)) {
        if (op == 0x80) {
            if (!begin(Opcode::m65c02_bra, 2)) return bad(DecodeStatus::truncated, "65C02 BRA displacement is truncated");
            const auto displacement = static_cast<std::int8_t>(byte(1));
            i.operands.emplace_back(RelativeOperand{displacement, 8, 16, EncodedField{1, 1}});
            i.access = {OperandAccess::address}; i.flow = FlowKind::jump;
            i.direct_target = Address{at.space, static_cast<std::uint16_t>(at.offset + 2 + displacement)};
            return finish(2);
        }
        const Mode mode = op == 0x64 ? Mode::zero_page : op == 0x74 ? Mode::zero_page_x : op == 0x9c ? Mode::absolute : Mode::absolute_x;
        const auto length = sized_mode(mode);
        if (!begin(Opcode::m65c02_stz, length)) return bad(DecodeStatus::truncated, "65C02 STZ operand is truncated");
        auto operand = memory(mode); i.operands.emplace_back(operand); i.access = {OperandAccess::write};
        if (operand.index) i.register_reads.push_back(*operand.index);
        i.memory_write = true;
        return finish(length);
    }
    if (cmos && (op == 0x04 || op == 0x0c || op == 0x14 || op == 0x1c)) {
        const auto mode = (op == 0x04 || op == 0x14) ? Mode::zero_page : Mode::absolute;
        if (!begin((op == 0x04 || op == 0x0c) ? Opcode::m65c02_tsb : Opcode::m65c02_trb,
                   sized_mode(mode)))
            return bad(DecodeStatus::truncated, "65C02 TSB/TRB operand is truncated");
        i.operands.emplace_back(memory(mode));
        i.access = {OperandAccess::read_write};
        i.register_reads = {a, p};
        i.register_writes = {p};
        i.memory_read = i.memory_write = true;
        return finish(sized_mode(mode));
    }
    if (cmos && (op == 0x89 || op == 0x34 || op == 0x3c)) {
        const auto mode = op == 0x89 ? Mode::immediate : op == 0x34 ? Mode::zero_page_x : Mode::absolute_x;
        auto result = data_op(Opcode::m6502_bit, mode, a, false);
        if (result.status == DecodeStatus::decoded) {
            // CMOS BIT immediate changes only Z. All BIT forms preserve
            // unaffected status bits, so the incoming P value is an input.
            result.instruction->register_reads.push_back(p);
        }
        return result;
    }
    if (cmos && (op == 0x1a || op == 0x3a)) {
        if (!begin(op == 0x1a ? Opcode::m6502_inc : Opcode::m6502_dec, 1))
            return bad(DecodeStatus::truncated, "65C02 accumulator increment/decrement is truncated");
        i.operands.emplace_back(a);
        i.access = {OperandAccess::read_write};
        i.register_reads = {a, p};
        i.register_writes = {a, p};
        return finish(1);
    }
    if (cmos && (op == 0x5a || op == 0x7a || op == 0xda || op == 0xfa)) {
        const bool push = op == 0x5a || op == 0xda;
        const auto value = (op == 0x5a || op == 0x7a) ? y : x;
        const Opcode opcode = op == 0x5a ? Opcode::m65c02_phy : op == 0x7a ? Opcode::m65c02_ply :
                              op == 0xda ? Opcode::m65c02_phx : Opcode::m65c02_plx;
        if (!begin(opcode, 1)) return bad(DecodeStatus::truncated, "65C02 stack operation is truncated");
        if (push) {
            i.register_reads = {value, s};
            i.register_writes = {s};
            i.memory_write = true;
        } else {
            i.register_reads = {s, p};
            i.register_writes = {value, s, p};
            i.memory_read = true;
        }
        return finish(1);
    }
    if (cmos && (op & 0x0f) == 0x07) {
        const auto bit = static_cast<std::uint8_t>((op >> 4) & 7);
        if (!begin((op & 0x80) ? Opcode::m65c02_smb : Opcode::m65c02_rmb, 2))
            return bad(DecodeStatus::truncated, "65C02 RMB/SMB zero-page operand is truncated");
        i.condition = bit;
        i.operands.emplace_back(memory(Mode::zero_page));
        i.access = {OperandAccess::read_write};
        i.memory_read = i.memory_write = true;
        return finish(2);
    }
    if (cmos && (op & 0x0f) == 0x0f) {
        if (!begin((op & 0x80) ? Opcode::m65c02_bbs : Opcode::m65c02_bbr, 3))
            return bad(DecodeStatus::truncated, "65C02 BBR/BBS operands are truncated");
        i.condition = static_cast<std::uint8_t>((op >> 4) & 7);
        i.operands.emplace_back(memory(Mode::zero_page));
        const auto displacement = static_cast<std::int8_t>(byte(2));
        i.operands.emplace_back(RelativeOperand{displacement, 8, 16, EncodedField{2, 1}});
        i.access = {OperandAccess::read, OperandAccess::address};
        i.memory_read = true;
        i.flow = FlowKind::conditional_branch;
        i.direct_target = Address{at.space, static_cast<std::uint16_t>(at.offset + 3 + displacement)};
        return finish(3);
    }
    if (cmos && (op == 0xcb || op == 0xdb)) {
        if (!begin(op == 0xcb ? Opcode::m65c02_wai : Opcode::m65c02_stp, 1))
            return bad(DecodeStatus::truncated, "65C02 wait/stop opcode is truncated");
        if (op == 0xdb) i.flow = FlowKind::trap;
        return finish(1);
    }
    if (cmos && op == 0x7c) {
        if (!begin(Opcode::m6502_jmp, 3)) return bad(DecodeStatus::truncated, "65C02 indexed JMP pointer is truncated");
        auto pointer = memory(Mode::absolute_x);
        pointer.data_width = 16;
        i.operands.emplace_back(pointer);
        i.access = {OperandAccess::address};
        i.register_reads = {x};
        i.memory_read = true;
        i.flow = FlowKind::jump;
        return finish(3);
    }
    // Do not let the NMOS unofficial-opcode table reinterpret bytes in the
    // CMOS profile. The supported CMOS additions above have explicit cases;
    // remaining CMOS-only assignments and reserved bytes stay unsupported.
    if (cmos && documented_cycles[op] == 0)
        return bad(DecodeStatus::unsupported, "65C02 opcode is outside the implemented CMOS subset");
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
        return data_op(opcode, mode, a, false, true, true,
                       opcode == Opcode::m6502_rla || opcode == Opcode::m6502_rra || opcode == Opcode::m6502_isc);
    };
    auto las = [&]() -> DecodeResult {
        const auto length = sized_mode(Mode::absolute_y);
        if (!begin(Opcode::m6502_las, length))
            return bad(DecodeStatus::truncated, "6502 operand bytes are truncated");
        i.operands.emplace_back(memory(Mode::absolute_y));
        i.access = {OperandAccess::read};
        i.register_reads = {y, s, p};
        i.register_writes = {a, x, s, p};
        i.memory_read = true;
        return finish(length);
    };
    auto axs = [&]() -> DecodeResult {
        if (!begin(Opcode::m6502_axs, 2))
            return bad(DecodeStatus::truncated, "6502 operand bytes are truncated");
        i.operands.emplace_back(ImmediateOperand{byte(1), 8, 8, false, EncodedField{1, 1}});
        i.access = {OperandAccess::read};
        i.register_reads = {a, x};
        i.register_writes = {x, p};
        return finish(2);
    };
    auto alr = [&]() -> DecodeResult {
        if (!begin(Opcode::m6502_alr, 2))
            return bad(DecodeStatus::truncated, "6502 operand bytes are truncated");
        i.operands.emplace_back(ImmediateOperand{byte(1), 8, 8, false, EncodedField{1, 1}});
        i.access = {OperandAccess::read};
        i.register_reads = {a, p};
        i.register_writes = {a, p};
        return finish(2);
    };
    auto lax = [&](Mode mode) -> DecodeResult {
        const auto length = sized_mode(mode);
        if (!begin(Opcode::m6502_lax, length))
            return bad(DecodeStatus::truncated, "6502 LAX operand bytes are truncated");
        const auto operand = memory(mode);
        i.operands.emplace_back(operand);
        i.access = {OperandAccess::read};
        if (operand.index) i.register_reads.push_back(*operand.index);
        i.register_reads.push_back(p);
        i.register_writes = {a, x, p};
        i.memory_read = true;
        return finish(length);
    };
    auto sax = [&](Mode mode) -> DecodeResult {
        const auto length = sized_mode(mode);
        if (!begin(Opcode::m6502_sax, length))
            return bad(DecodeStatus::truncated, "6502 SAX operand bytes are truncated");
        const auto operand = memory(mode);
        i.operands.emplace_back(operand);
        i.access = {OperandAccess::write};
        if (operand.index) i.register_reads.push_back(*operand.index);
        i.register_reads.push_back(a);
        i.register_reads.push_back(x);
        i.memory_write = true;
        return finish(length);
    };
    auto undocumented_nop = [&](Mode mode) -> DecodeResult {
        const auto length = sized_mode(mode);
        if (!begin(Opcode::nop, length))
            return bad(DecodeStatus::truncated, "6502 unofficial NOP operand bytes are truncated");
        if (mode == Mode::implied) {
            i.access = {};
        } else if (mode == Mode::immediate) {
            i.operands.emplace_back(ImmediateOperand{byte(1), 8, 8, false, EncodedField{1, 1}});
            i.access = {OperandAccess::read};
        } else {
            const auto operand = memory(mode);
            i.operands.emplace_back(operand);
            i.access = {OperandAccess::read};
            if (operand.index) i.register_reads.push_back(*operand.index);
            i.memory_read = true;
        }
        return finish(length);
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
    // NMOS KIL/JAM locks instruction execution until reset. Represent it as a
    // terminal trap; reset-line and bus-lock behavior are outside this IR.
    case 0x02: case 0x12: case 0x22: case 0x32: case 0x42: case 0x52:
    case 0x62: case 0x72: case 0x92: case 0xb2: case 0xd2: case 0xf2:
        if (!begin(Opcode::m6502_kil, 1))
            return bad(DecodeStatus::truncated, "6502 KIL opcode is truncated");
        i.flow = FlowKind::trap;
        return finish(1);
    case 0x4b: return alr();
    // AXS (also called SBX) is the stable NMOS $CB immediate form.
    case 0xcb: return axs();
    case 0x0b: case 0x2b: return data_op(Opcode::m6502_anc, Mode::immediate, a, false);
    case 0xa3: return lax(Mode::indexed_indirect);
    case 0xa7: return lax(Mode::zero_page);
    case 0xaf: return lax(Mode::absolute);
    case 0xb3: return lax(Mode::indirect_indexed);
    case 0xb7: return lax(Mode::zero_page_y);
    case 0xbf: return lax(Mode::absolute_y);
    case 0x83: return sax(Mode::indexed_indirect);
    case 0x87: return sax(Mode::zero_page);
    case 0x8f: return sax(Mode::absolute);
    case 0x97: return sax(Mode::zero_page_y);
    // Undocumented NMOS decrement-then-compare family. These byte forms are
    // stable on the NMOS 6502; the decoder records their combined effects.
    case 0xc7: return dcp(Mode::zero_page);
    case 0xd7: return dcp(Mode::zero_page_x);
    case 0xcf: return dcp(Mode::absolute);
    case 0xdf: return dcp(Mode::absolute_x);
    case 0xdb: return dcp(Mode::absolute_y);
    case 0xc3: return dcp(Mode::indexed_indirect);
    case 0xd3: return dcp(Mode::indirect_indexed);
    // Stable undocumented NMOS increment-then-subtract family.
    case 0xe3: return undocumented_rmw(Opcode::m6502_isc, Mode::indexed_indirect);
    case 0xe7: return undocumented_rmw(Opcode::m6502_isc, Mode::zero_page);
    case 0xef: return undocumented_rmw(Opcode::m6502_isc, Mode::absolute);
    case 0xf3: return undocumented_rmw(Opcode::m6502_isc, Mode::indirect_indexed);
    case 0xf7: return undocumented_rmw(Opcode::m6502_isc, Mode::zero_page_x);
    case 0xfb: return undocumented_rmw(Opcode::m6502_isc, Mode::absolute_y);
    case 0xff: return undocumented_rmw(Opcode::m6502_isc, Mode::absolute_x);
    // Unofficial load-and-stack-mask opcode has one NMOS absolute,Y form.
    case 0xbb: return las();
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
    // Stable undocumented NMOS ROR-then-ADC read/modify/write family.
    case 0x63: return undocumented_rmw(Opcode::m6502_rra, Mode::indexed_indirect);
    case 0x67: return undocumented_rmw(Opcode::m6502_rra, Mode::zero_page);
    case 0x6f: return undocumented_rmw(Opcode::m6502_rra, Mode::absolute);
    case 0x73: return undocumented_rmw(Opcode::m6502_rra, Mode::indirect_indexed);
    case 0x77: return undocumented_rmw(Opcode::m6502_rra, Mode::zero_page_x);
    case 0x7b: return undocumented_rmw(Opcode::m6502_rra, Mode::absolute_y);
    case 0x7f: return undocumented_rmw(Opcode::m6502_rra, Mode::absolute_x);
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

    // Stable NMOS multi-byte and implied unofficial NOP encodings. The DOP
    // and TOP forms perform the effective-address read but do not alter flags.
    case 0x1a: case 0x3a: case 0x5a: case 0x7a: case 0xda: case 0xfa:
        return undocumented_nop(Mode::implied);
    case 0x80: case 0x82: case 0x89: case 0xc2: case 0xe2:
        return undocumented_nop(Mode::immediate);
    case 0x04: case 0x44: case 0x64:
        return undocumented_nop(Mode::zero_page);
    case 0x14: case 0x34: case 0x54: case 0x74: case 0xd4: case 0xf4:
        return undocumented_nop(Mode::zero_page_x);
    case 0x0c:
        return undocumented_nop(Mode::absolute);
    case 0x1c: case 0x3c: case 0x5c: case 0xdc: case 0xfc:
        return undocumented_nop(Mode::absolute_x);

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
    if (!cmos && (op == 0x9c || op == 0x9e))
        return bad(DecodeStatus::unsupported, "65C02-only opcode is not enabled in the NMOS 6502 mode");
    return bad(DecodeStatus::unsupported, "Undocumented NMOS 6502 opcode has no defined decoder semantics");
}
DecodeResult decode_m6502(std::span<const std::byte> bytes, Address at) {
    return decode_m6502_impl(bytes, at, false);
}
DecodeResult decode_m65c02(std::span<const std::byte> bytes, Address at) {
    return decode_m6502_impl(bytes, at, true);
}
} // namespace hexlab
