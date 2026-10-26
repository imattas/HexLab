#include "hexlab/processors/decoder.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <string>

namespace hexlab {
namespace {
DecodeResult fail(DecodeStatus s, std::string why) { return {s, {}, std::move(why)}; }
bool code_unit(std::span<const std::byte> b, unsigned index, std::uint16_t &v) {
    const auto p = std::size_t(index) * 2;
    if (p > b.size() || b.size() - p < 2) return false;
    v = std::to_integer<std::uint8_t>(b[p]) |
        (std::uint16_t(std::to_integer<std::uint8_t>(b[p + 1])) << 8);
    return true;
}
std::string vr(unsigned n) { return "v" + std::to_string(n); }
std::uint32_t le32(std::uint16_t a, std::uint16_t b) { return std::uint32_t(a) | (std::uint32_t(b) << 16); }
}

DecodeResult decode_dex(std::span<const std::byte> bytes, Address at) {
    if (at.offset & 1)
        return fail(DecodeStatus::invalid, "DEX instruction address is not code-unit aligned");
    std::uint16_t first = 0;
    if (!code_unit(bytes, 0, first)) return fail(DecodeStatus::truncated, "truncated DEX code unit");
    const auto op = std::uint8_t(first & 0xff), hi = std::uint8_t(first >> 8);
    unsigned words = 1;
    std::string text;
    FlowKind flow = FlowKind::fallthrough;
    std::optional<Address> target;
    std::optional<DexSwitchTable> dex_switch;
    std::optional<std::uint16_t> dex_type_index;
    const auto ensure = [&](unsigned count) {
        std::uint16_t ignored = 0;
        return code_unit(bytes, count - 1, ignored);
    };
    const auto word = [&](unsigned index) { std::uint16_t value = 0; (void)code_unit(bytes, index, value); return value; };
    const auto branch = [&](std::int64_t units, FlowKind kind) {
        flow = kind;
        const auto delta = units * 2;
        if (delta >= 0) {
            const auto amount = static_cast<std::uint64_t>(delta);
            if (at.offset <= UINT32_MAX && amount <= UINT32_MAX - at.offset)
                target = Address{at.space, at.offset + amount};
        } else {
            const auto amount = static_cast<std::uint64_t>(-(delta + 1)) + 1;
            if (amount <= at.offset) target = Address{at.space, at.offset - amount};
        }
    };
    if (op == 0x00) {
        if (hi) return fail(DecodeStatus::unsupported, "DEX payload pseudo-instruction is not decoded");
        text = "nop";
    } else if (op >= 0x01 && op <= 0x09) {
        static constexpr std::array<std::string_view, 9> names{
            "move", "move/from16", "move/16", "move-wide", "move-wide/from16", "move-wide/16",
            "move-object", "move-object/from16", "move-object/16"};
        const auto form = (op - 1) % 3;
        if (form == 0) text = std::string(names[op - 1]) + " " + vr(hi & 15) + ", " + vr(hi >> 4);
        else if (form == 1) { words = 2; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX 22x move"); text = std::string(names[op - 1]) + " " + vr(hi) + ", " + vr(word(1)); }
        else { words = 3; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX 32x move"); text = std::string(names[op - 1]) + " " + vr(word(1)) + ", " + vr(word(2)); }
    } else if (op >= 0x0a && op <= 0x0d) {
        static constexpr std::array<std::string_view, 4> names{"move-result", "move-result-wide", "move-result-object", "move-exception"};
        text = std::string(names[op - 0x0a]) + " " + vr(hi);
    } else if (op == 0x0e) { text = "return-void"; flow = FlowKind::ret;
    } else if (op >= 0x0f && op <= 0x11) {
        static constexpr std::array<std::string_view, 3> names{"return", "return-wide", "return-object"};
        text = std::string(names[op - 0x0f]) + " " + vr(hi); flow = FlowKind::ret;
    } else if (op == 0x12) {
        const auto value = static_cast<std::int8_t>(hi);
        text = "const/4 " + vr(hi & 15) + ", " + std::to_string(value >> 4);
    } else if (op == 0x13 || op == 0x15 || op == 0x16 || op == 0x19) {
        words = 2; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX 21s constant");
        const std::int64_t value = op == 0x15
            ? std::bit_cast<std::int32_t>(std::uint32_t(word(1)) << 16)
            : op == 0x19 ? std::bit_cast<std::int64_t>(std::uint64_t(word(1)) << 48)
            : static_cast<std::int64_t>(std::bit_cast<std::int16_t>(word(1)));
        text = std::string(op == 0x13 ? "const/16 " : op == 0x15 ? "const/high16 " : op == 0x16 ? "const-wide/16 " : "const-wide/high16 ") + vr(hi) + ", " + std::to_string(value);
    } else if (op == 0x14 || op == 0x17) {
        words = 3; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX 31i constant");
        text = std::string(op == 0x14 ? "const " : "const-wide/32 ") + vr(hi) + ", " + std::to_string(static_cast<std::int32_t>(le32(word(1), word(2))));
    } else if (op == 0x18) {
        words = 5; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX 51l constant");
        const auto value = std::uint64_t(word(1)) | (std::uint64_t(word(2)) << 16) |
            (std::uint64_t(word(3)) << 32) | (std::uint64_t(word(4)) << 48);
        text = "const-wide " + vr(hi) + ", " + std::to_string(static_cast<std::int64_t>(value));
    } else if (op == 0x1a || op == 0x1c || op == 0x1f || op == 0x20 || op == 0x22 || op == 0x60 || op == 0x61 || op == 0x62 || op == 0x67 ||
               (op >= 0x52 && op <= 0x6d)) {
        words = 2; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX type-index instruction");
        if (op <= 0x22) {
            if (op == 0x20) {
                text = "instance-of " + vr(hi & 15) + ", " + vr(hi >> 4) + ", type@" + std::to_string(word(1));
            } else {
                const char *name = op == 0x1a ? "const-string" : op == 0x1c ? "const-class" :
                                   op == 0x1f ? "check-cast" : "new-instance";
                const char *kind = op == 0x1a ? "string" : "type";
                text = std::string(name) + " " + vr(hi) + ", " + kind + "@" + std::to_string(word(1));
            }
        } else {
            static constexpr std::array<std::string_view, 28> names{
                "iget", "iget-wide", "iget-object", "iget-boolean", "iget-byte", "iget-char", "iget-short",
                "iput", "iput-wide", "iput-object", "iput-boolean", "iput-byte", "iput-char", "iput-short",
                "sget", "sget-wide", "sget-object", "sget-boolean", "sget-byte", "sget-char", "sget-short",
                "sput", "sput-wide", "sput-object", "sput-boolean", "sput-byte", "sput-char", "sput-short"};
            const auto reg_a = static_cast<unsigned>(hi & 15);
            const auto reg_b = static_cast<unsigned>(hi >> 4);
            const bool instance = op < 0x60;
            if (instance)
                text = std::string(names[op - 0x52]) + " " + vr(reg_a) + ", " + vr(reg_b) + ", field@" + std::to_string(word(1));
            else
                text = std::string(names[op - 0x52]) + " " + vr(hi) + ", field@" + std::to_string(word(1));
        }
    } else if (op == 0x21) {
        text = "array-length " + vr(hi & 15) + ", " + vr(hi >> 4);
    } else if (op == 0x23) {
        words = 2; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX new-array");
        text = "new-array " + vr(hi & 15) + ", " + vr(hi >> 4) + ", type@" + std::to_string(word(1));
    } else if (op == 0x24) {
        words = 3;
        if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX filled-new-array");
        const unsigned count = (first >> 12) & 15;
        const unsigned last = (first >> 8) & 15;
        const auto list = word(2);
        if (count > 5) return fail(DecodeStatus::invalid, "DEX filled-new-array register count exceeds five");
        const std::array<unsigned, 5> regs{static_cast<unsigned>(list & 15), static_cast<unsigned>((list >> 4) & 15),
            static_cast<unsigned>((list >> 8) & 15), static_cast<unsigned>((list >> 12) & 15), last};
        text = "filled-new-array {";
        for (unsigned i = 0; i < count; ++i) {
            if (i) text += ", ";
            text += vr(regs[i]);
        }
        dex_type_index = word(1);
        text += "}, type@" + std::to_string(*dex_type_index);
    } else if (op == 0x25) {
        words = 3;
        if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX filled-new-array/range");
        const auto count = static_cast<unsigned>(hi);
        const auto start = static_cast<unsigned>(word(2));
        if (count && start > UINT16_MAX - (count - 1))
            return fail(DecodeStatus::invalid, "DEX filled-new-array register range overflows 16-bit register indexes");
        if (count && start + count - 1 > UINT8_MAX)
            return fail(DecodeStatus::unsupported, "DEX register indexes above 255 exceed the typed operand model");
        text = "filled-new-array/range {";
        if (count) text += vr(start) + " .. " + vr(start + count - 1);
        dex_type_index = word(1);
        text += "}, type@" + std::to_string(*dex_type_index);
    } else if (op >= 0x44 && op <= 0x51) {
        words = 2; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX array access");
        static constexpr std::array<std::string_view, 14> names{
            "aget", "aget-wide", "aget-object", "aget-boolean", "aget-byte", "aget-char", "aget-short",
            "aput", "aput-wide", "aput-object", "aput-boolean", "aput-byte", "aput-char", "aput-short"};
        const auto operands = word(1);
        text = std::string(names[op - 0x44]) + " " + vr(hi) + ", " + vr(operands & 255) + ", " + vr(operands >> 8);
    } else if (op == 0x1b) {
        words = 3; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX jumbo string reference");
        text = "const-string/jumbo " + vr(hi) + ", string@" + std::to_string(le32(word(1), word(2)));
    } else if (op == 0x1d || op == 0x1e || op == 0x27) {
        text = std::string(op == 0x1d ? "monitor-enter " : op == 0x1e ? "monitor-exit " : "throw ") + vr(hi);
        if (op == 0x27) flow = FlowKind::trap;
    } else if (op == 0x2b || op == 0x2c) {
        words = 3;
        if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX switch");
        const auto units = std::bit_cast<std::int32_t>(le32(word(1), word(2)));
        const auto delta = static_cast<std::int64_t>(units) * 2;
        std::uint64_t payload_offset = 0;
        if (delta >= 0) {
            const auto amount = static_cast<std::uint64_t>(delta);
            if (at.offset > UINT32_MAX || amount > UINT32_MAX - at.offset)
                return fail(DecodeStatus::invalid, "DEX switch payload target exceeds the method address space");
            payload_offset = at.offset + amount;
        } else {
            const auto amount = static_cast<std::uint64_t>(-delta);
            if (amount > at.offset)
                return fail(DecodeStatus::invalid, "DEX switch payload target precedes the method address space");
            payload_offset = at.offset - amount;
        }
        if (payload_offset & 3)
            return fail(DecodeStatus::invalid, "DEX switch payload is not four-byte aligned");
        dex_switch = DexSwitchTable{op == 0x2b, Address{at.space, payload_offset}, false, {}};
        text = std::string(op == 0x2b ? "packed-switch " : "sparse-switch ") + vr(hi) + ", payload " +
               std::to_string(payload_offset);
        flow = FlowKind::switch_dispatch;
    } else if (op >= 0x2d && op <= 0x31) {
        words = 2; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX compare");
        static constexpr std::array<std::string_view, 5> names{
            "cmpl-float", "cmpg-float", "cmpl-double", "cmpg-double", "cmp-long"};
        const auto operands = word(1);
        text = std::string(names[op - 0x2d]) + " " + vr(hi) + ", " +
               vr(operands & 255) + ", " + vr(operands >> 8);
    } else if (op >= 0x28 && op <= 0x2a) {
        std::int64_t offset = 0;
        if (op == 0x28) { text = "goto"; offset = static_cast<std::int8_t>(hi); }
        else if (op == 0x29) { words = 2; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX goto/16"); text = "goto/16"; offset = static_cast<std::int16_t>(word(1)); }
        else { words = 3; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX goto/32"); text = "goto/32"; offset = static_cast<std::int32_t>(le32(word(1), word(2))); }
        branch(offset, FlowKind::jump); if (target) text += " " + std::to_string(target->offset);
    } else if (op >= 0xd0 && op <= 0xe2) {
        words = 2; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX literal arithmetic");
        if (op <= 0xd7) {
            static constexpr std::array<std::string_view, 8> names{
                "add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16",
                "rem-int/lit16", "and-int/lit16", "or-int/lit16", "xor-int/lit16"};
            const auto literal = std::bit_cast<std::int16_t>(word(1));
            text = std::string(names[op - 0xd0]) + " " + vr(hi & 15) + ", " +
                   vr(hi >> 4) + ", " + std::to_string(literal);
        } else {
            static constexpr std::array<std::string_view, 11> names{
                "add-int/lit8", "rsub-int/lit8", "mul-int/lit8", "div-int/lit8",
                "rem-int/lit8", "and-int/lit8", "or-int/lit8", "xor-int/lit8",
                "shl-int/lit8", "shr-int/lit8", "ushr-int/lit8"};
            const auto operands = word(1);
            const auto literal = std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(operands >> 8));
            text = std::string(names[op - 0xd8]) + " " + vr(hi) + ", " +
                   vr(operands & 255) + ", " + std::to_string(literal);
        }
    } else if ((op >= 0x32 && op <= 0x37) || (op >= 0x38 && op <= 0x3d)) {
        words = 2; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX conditional branch");
        const auto offset = static_cast<std::int16_t>(word(1));
        if (op <= 0x37) {
            static constexpr std::array<std::string_view, 6> names{"if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le"};
            text = std::string(names[op - 0x32]) + " " + vr(hi & 15) + ", " + vr(hi >> 4);
        } else {
            static constexpr std::array<std::string_view, 6> names{"if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"};
            text = std::string(names[op - 0x38]) + " " + vr(hi);
        }
        branch(offset, FlowKind::conditional_branch); if (target) text += ", " + std::to_string(target->offset);
    } else if (op >= 0x6e && op <= 0x72) {
        words = 3; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX invoke");
        static constexpr std::array<std::string_view, 5> names{"invoke-virtual", "invoke-super", "invoke-direct", "invoke-static", "invoke-interface"};
        const unsigned count = (first >> 12) & 15;
        const unsigned last = (first >> 8) & 15;
        const auto list = word(2);
        if (count > 5) return fail(DecodeStatus::invalid, "DEX invoke register count exceeds five");
        const std::array<unsigned, 5> regs{static_cast<unsigned>(list & 15), static_cast<unsigned>((list >> 4) & 15),
            static_cast<unsigned>((list >> 8) & 15), static_cast<unsigned>((list >> 12) & 15), last};
        text = std::string(names[op - 0x6e]) + " {";
        for (unsigned i = 0; i < count; ++i) { if (i) text += ", "; text += vr(regs[i]); }
        text += "}, method@" + std::to_string(word(1)); flow = FlowKind::call;
    } else if (op >= 0x74 && op <= 0x78) {
        words = 3; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX invoke/range");
        static constexpr std::array<std::string_view, 5> names{"invoke-virtual/range", "invoke-super/range", "invoke-direct/range", "invoke-static/range", "invoke-interface/range"};
        const unsigned count = hi;
        const auto start = word(2);
        text = std::string(names[op - 0x74]) + " {";
        if (count) text += vr(start) + " .. " + vr(std::uint32_t(start) + count - 1);
        text += "}, method@" + std::to_string(word(1)); flow = FlowKind::call;
    } else if (op >= 0x7b && op <= 0x8f) {
        static constexpr std::array<std::string_view, 21> names{
            "neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double",
            "int-to-long", "int-to-float", "int-to-double", "long-to-int", "long-to-float",
            "long-to-double", "float-to-int", "float-to-long", "float-to-double",
            "double-to-int", "double-to-long", "double-to-float", "int-to-byte", "int-to-char", "int-to-short"};
        text = std::string(names[op - 0x7b]) + " " + vr(hi & 15) + ", " + vr(hi >> 4);
    } else if (op >= 0x90 && op <= 0xaf) {
        words = 2; if (!ensure(words)) return fail(DecodeStatus::truncated, "truncated DEX arithmetic");
        static constexpr std::array<std::string_view, 32> names{
            "add-int","sub-int","mul-int","div-int","rem-int","and-int","or-int","xor-int","shl-int","shr-int","ushr-int",
            "add-long","sub-long","mul-long","div-long","rem-long","and-long","or-long","xor-long","shl-long","shr-long","ushr-long",
            "add-float","sub-float","mul-float","div-float","rem-float","add-double","sub-double","mul-double","div-double","rem-double"};
        const auto rhs = word(1); text = std::string(names[op - 0x90]) + " " + vr(hi) + ", " + vr(rhs & 255) + ", " + vr(rhs >> 8);
    } else if (op >= 0xb0 && op <= 0xcf) {
        static constexpr std::array<std::string_view, 32> names{
            "add-int/2addr","sub-int/2addr","mul-int/2addr","div-int/2addr","rem-int/2addr","and-int/2addr","or-int/2addr","xor-int/2addr","shl-int/2addr","shr-int/2addr","ushr-int/2addr",
            "add-long/2addr","sub-long/2addr","mul-long/2addr","div-long/2addr","rem-long/2addr","and-long/2addr","or-long/2addr","xor-long/2addr","shl-long/2addr","shr-long/2addr","ushr-long/2addr",
            "add-float/2addr","sub-float/2addr","mul-float/2addr","div-float/2addr","rem-float/2addr","add-double/2addr","sub-double/2addr","mul-double/2addr","div-double/2addr","rem-double/2addr"};
        text = std::string(names[op - 0xb0]) + " " + vr(hi & 15) + ", " + vr(hi >> 4);
    } else return fail(DecodeStatus::unsupported, "DEX opcode is outside the enabled scalar subset");
    const auto length = words * 2;
    if (length > 10) return fail(DecodeStatus::invalid, "DEX instruction exceeds the supported instruction width");
    if (bytes.size() < length) return fail(DecodeStatus::truncated, "truncated DEX instruction");
    Instruction instruction; instruction.context = {Architecture::dex, ExecutionMode::dex, ByteOrder::little};
    instruction.address = at; instruction.length = static_cast<std::uint8_t>(length);
    std::copy_n(bytes.begin(), length, instruction.bytes.begin());
    instruction.opcode = dex_switch ? Opcode::dex_switch : Opcode::dex;
    instruction.memory_read = op == 0x21 || op == 0x2b || op == 0x2c || (op >= 0x44 && op <= 0x4a) ||
                              (op >= 0x52 && op <= 0x58) || (op >= 0x60 && op <= 0x66);
    instruction.memory_write = (op >= 0x4b && op <= 0x51) || (op >= 0x59 && op <= 0x5f) ||
                               (op >= 0x67 && op <= 0x6d);
    if (op == 0x22 || op == 0x23 || op == 0x24 || op == 0x25 || (op >= 0x6e && op <= 0x78))
        instruction.memory_read = instruction.memory_write = true;
    instruction.mnemonic_override = std::move(text); instruction.flow = flow; instruction.direct_target = target;
    instruction.dex_switch = std::move(dex_switch);
    // Keep operand order identical to the Dalvik syntax. Wide operands are
    // 64-bit values, but effects name both constituent 32-bit slots so accesses
    // through the high half alias ordinary single-slot operations.
    bool unrepresentable_register = false;
    const auto reg = [&](unsigned index, OperandAccess access, unsigned width = 32) {
        if (index > UINT8_MAX || (width == 64 && index == UINT8_MAX)) {
            unrepresentable_register = true;
            return;
        }
        instruction.operands.emplace_back(RegisterOperand{RegisterBank::dex_vreg,
            static_cast<std::uint8_t>(index), static_cast<std::uint16_t>(width), false});
        instruction.access.push_back(access);
        for (unsigned slot = 0; slot < width / 32; ++slot) {
            const RegisterOperand effect{RegisterBank::dex_vreg,
                static_cast<std::uint8_t>(index + slot), 32, false};
            const auto add = [&](auto &effects) {
                if (std::find(effects.begin(), effects.end(), effect) == effects.end()) effects.push_back(effect);
            };
            if (access == OperandAccess::read || access == OperandAccess::read_write) add(instruction.register_reads);
            if (access == OperandAccess::write || access == OperandAccess::read_write) add(instruction.register_writes);
        }
    };
    const auto imm = [&](std::uint64_t value, unsigned encoded, unsigned effective, bool sign = false) {
        instruction.operands.emplace_back(ImmediateOperand{value, static_cast<std::uint16_t>(encoded),
            static_cast<std::uint16_t>(effective), sign, {}});
        instruction.access.push_back(OperandAccess::read);
    };
    constexpr auto read = OperandAccess::read, write = OperandAccess::write, rw = OperandAccess::read_write;
    const unsigned a = hi & 15, b = hi >> 4;
    if (op >= 0x01 && op <= 0x09) {
        const unsigned form = (op - 1) % 3, width = op >= 0x04 && op <= 0x06 ? 64 : 32;
        reg(form == 0 ? a : form == 1 ? hi : word(1), write, width);
        reg(form == 0 ? b : form == 1 ? word(1) : word(2), read, width);
    } else if (op >= 0x0a && op <= 0x0d) reg(hi, write, op == 0x0b ? 64 : 32);
    else if (op >= 0x0f && op <= 0x11) reg(hi, read, op == 0x10 ? 64 : 32);
    else if (op >= 0x12 && op <= 0x19) {
        const unsigned width = op >= 0x16 ? 64 : 32;
        reg(op == 0x12 ? a : hi, write, width);
        if (op == 0x12) imm(static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int8_t>(hi) >> 4)), 4, 32, true);
        else if (op == 0x15) imm(std::uint32_t(word(1)) << 16, 16, 32);
        else if (op == 0x19) imm(std::uint64_t(word(1)) << 48, 16, 64);
        else if (op == 0x13 || op == 0x16)
            imm(static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int16_t>(word(1)))), 16, width, true);
        else if (op == 0x14) imm(le32(word(1), word(2)), 32, 32);
        else if (op == 0x17)
            imm(static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int32_t>(le32(word(1), word(2))))), 32, width, true);
        else imm(std::uint64_t(word(1)) | (std::uint64_t(word(2)) << 16) |
                 (std::uint64_t(word(3)) << 32) | (std::uint64_t(word(4)) << 48), 64, 64);
    } else if (op == 0x1a || op == 0x1b || op == 0x1c || op == 0x1f || op == 0x22) {
        // check-cast refines a reference's verifier type without defining a vreg.
        reg(hi, op == 0x1f ? read : write);
        imm(op == 0x1b ? le32(word(1), word(2)) : word(1), op == 0x1b ? 32 : 16, op == 0x1b ? 32 : 16);
    } else if (op == 0x1d || op == 0x1e || op == 0x27 || op == 0x2b || op == 0x2c) reg(hi, read);
    else if (op == 0x20 || op == 0x21 || op == 0x23) {
        reg(a, write); reg(b, read);
        if (op != 0x21) imm(word(1), 16, 16);
    } else if (op == 0x24 || op == 0x25 || (op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
        const bool range = op == 0x25 || op >= 0x74;
        const unsigned count = range ? hi : b;
        if (count > 15)
            return fail(DecodeStatus::unsupported, "DEX register list exceeds the typed instruction operand budget");
        if (range) {
            const unsigned start = word(2);
            if (count && start > UINT16_MAX - (count - 1))
                return fail(DecodeStatus::invalid, "DEX register range overflows 16-bit register indexes");
            for (unsigned i = 0; i < count; ++i) reg(start + i, read);
        } else {
            const auto list = word(2);
            const std::array<unsigned, 5> regs{unsigned(list & 15), unsigned((list >> 4) & 15),
                unsigned((list >> 8) & 15), unsigned((list >> 12) & 15), a};
            for (unsigned i = 0; i < count; ++i) reg(regs[i], read);
        }
        // Invoke lists encode argument words, including both words of wide
        // arguments. Prototype/type resolution belongs to method analysis.
        imm(word(1), 16, 16);
    } else if (op >= 0x2d && op <= 0x31) {
        reg(hi, write);
        reg(word(1) & 255, read, op >= 0x2f ? 64 : 32);
        reg(word(1) >> 8, read, op >= 0x2f ? 64 : 32);
    } else if (op >= 0x32 && op <= 0x37) { reg(a, read); reg(b, read); }
    else if (op >= 0x38 && op <= 0x3d) reg(hi, read);
    else if (op >= 0x44 && op <= 0x51) {
        reg(hi, op <= 0x4a ? write : read, op == 0x45 || op == 0x4c ? 64 : 32);
        reg(word(1) & 255, read); reg(word(1) >> 8, read);
    } else if (op >= 0x52 && op <= 0x6d) {
        const bool instance = op < 0x60;
        const bool get = op <= 0x58 || (op >= 0x60 && op <= 0x66);
        const bool wide = op == 0x53 || op == 0x5a || op == 0x61 || op == 0x68;
        reg(instance ? a : hi, get ? write : read, wide ? 64 : 32);
        if (instance) reg(b, read);
        imm(word(1), 16, 16);
    } else if (op >= 0x7b && op <= 0x8f) {
        const bool wide_dest = op == 0x7d || op == 0x7e || op == 0x80 || op == 0x81 ||
            op == 0x83 || op == 0x86 || op == 0x88 || op == 0x89 || op == 0x8b;
        const bool wide_source = op == 0x7d || op == 0x7e || op == 0x80 ||
            (op >= 0x84 && op <= 0x86) || (op >= 0x8a && op <= 0x8c);
        reg(a, write, wide_dest ? 64 : 32); reg(b, read, wide_source ? 64 : 32);
    } else if (op >= 0x90 && op <= 0xcf) {
        const bool two_address = op >= 0xb0;
        const unsigned operation = two_address ? op - 0x20 : op;
        const bool wide = (operation >= 0x9b && operation <= 0xa5) || operation >= 0xab;
        const bool shift = operation >= 0xa3 && operation <= 0xa5;
        reg(two_address ? a : hi, two_address ? rw : write, wide ? 64 : 32);
        if (!two_address) reg(word(1) & 255, read, wide ? 64 : 32);
        reg(two_address ? b : word(1) >> 8, read, wide && !shift ? 64 : 32);
    } else if (op >= 0xd0 && op <= 0xe2) {
        reg(op <= 0xd7 ? a : hi, write); reg(op <= 0xd7 ? b : word(1) & 255, read);
        const std::int64_t value = op <= 0xd7 ? std::bit_cast<std::int16_t>(word(1)) :
            std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(word(1) >> 8));
        imm(static_cast<std::uint64_t>(value), op <= 0xd7 ? 16 : 8, 32, true);
    }
    if (unrepresentable_register)
        return fail(DecodeStatus::unsupported, "DEX register indexes above 255 exceed the typed operand model (including wide pairs)");
    if (instruction.dex_switch) {
        instruction.operands.emplace_back(RelativeOperand{static_cast<std::int64_t>(instruction.dex_switch->payload.offset) -
            static_cast<std::int64_t>(at.offset), 32, 32, {}});
        instruction.access.push_back(OperandAccess::read);
    }
    if ((op >= 0x28 && op <= 0x2a) || (op >= 0x32 && op <= 0x3d)) {
        const std::int64_t units = op == 0x28 ? std::bit_cast<std::int8_t>(hi) :
            op == 0x2a ? std::bit_cast<std::int32_t>(le32(word(1), word(2))) :
            std::bit_cast<std::int16_t>(word(1));
        instruction.operands.emplace_back(RelativeOperand{units * 2,
            static_cast<std::uint16_t>(op == 0x28 ? 8 : op == 0x2a ? 32 : 16), 32, {}});
        instruction.access.push_back(OperandAccess::read);
    }
    return {DecodeStatus::decoded, std::move(instruction), {}};
}
} // namespace hexlab
