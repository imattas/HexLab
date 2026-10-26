#include "hexlab/processors/decoder.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace hexlab {
namespace {
enum class LebResult { ok, truncated, invalid, too_long };
LebResult uleb(std::span<const std::byte> bytes, std::size_t &position, unsigned bits,
               std::uint64_t &value) noexcept {
    value = 0;
    const unsigned limit = (bits + 6) / 7;
    for (unsigned n = 0; n < limit; ++n) {
        if (position >= bytes.size()) return LebResult::truncated;
        const auto byte = std::to_integer<std::uint8_t>(bytes[position++]);
        const auto payload = static_cast<std::uint64_t>(byte & 0x7f);
        const auto remaining = bits - n * 7;
        if (remaining < 7 && payload >= (std::uint64_t{1} << remaining)) return LebResult::invalid;
        value |= payload << (n * 7);
        if (!(byte & 0x80)) return LebResult::ok;
    }
    return LebResult::invalid;
}
LebResult sleb(std::span<const std::byte> bytes, std::size_t &position, unsigned bits,
               std::int64_t &value) noexcept {
    std::uint64_t raw = 0;
    const unsigned limit = (bits + 6) / 7;
    unsigned shift = 0;
    std::uint8_t byte = 0;
    for (unsigned n = 0; n < limit; ++n) {
        if (position >= bytes.size()) return LebResult::truncated;
        byte = std::to_integer<std::uint8_t>(bytes[position++]);
        const auto payload = static_cast<std::uint64_t>(byte & 0x7f);
        const auto remaining = bits - n * 7;
        if (remaining < 7) {
            const auto sign = (payload & (std::uint64_t{1} << (remaining - 1))) != 0;
            const auto unused = payload >> remaining;
            const auto expected_unused = sign ? ((std::uint64_t{1} << (7 - remaining)) - 1) : 0;
            if (unused != expected_unused)
                return LebResult::invalid;
        }
        if (shift < 64) raw |= payload << shift;
        shift += 7;
        if (!(byte & 0x80)) {
            if (shift < 64 && (byte & 0x40)) raw |= (~std::uint64_t{0}) << shift;
            if (bits < 64) {
                const auto sign = std::uint64_t{1} << (bits - 1);
                const auto mask = (std::uint64_t{1} << bits) - 1;
                raw &= mask;
                if (raw & sign) raw |= ~mask;
            }
            value = static_cast<std::int64_t>(raw);
            return LebResult::ok;
        }
    }
    return LebResult::invalid;
}
constexpr std::array<std::string_view, 128> numeric_names{
    "i32.eqz", "i32.eq", "i32.ne", "i32.lt_s", "i32.lt_u", "i32.gt_s", "i32.gt_u", "i32.le_s", "i32.le_u", "i32.ge_s", "i32.ge_u",
    "i64.eqz", "i64.eq", "i64.ne", "i64.lt_s", "i64.lt_u", "i64.gt_s", "i64.gt_u", "i64.le_s", "i64.le_u", "i64.ge_s", "i64.ge_u",
    "f32.eq", "f32.ne", "f32.lt", "f32.gt", "f32.le", "f32.ge", "f64.eq", "f64.ne", "f64.lt", "f64.gt", "f64.le", "f64.ge",
    "i32.clz", "i32.ctz", "i32.popcnt", "i32.add", "i32.sub", "i32.mul", "i32.div_s", "i32.div_u", "i32.rem_s", "i32.rem_u", "i32.and", "i32.or", "i32.xor", "i32.shl", "i32.shr_s", "i32.shr_u", "i32.rotl", "i32.rotr",
    "i64.clz", "i64.ctz", "i64.popcnt", "i64.add", "i64.sub", "i64.mul", "i64.div_s", "i64.div_u", "i64.rem_s", "i64.rem_u", "i64.and", "i64.or", "i64.xor", "i64.shl", "i64.shr_s", "i64.shr_u", "i64.rotl", "i64.rotr",
    "f32.abs", "f32.neg", "f32.ceil", "f32.floor", "f32.trunc", "f32.nearest", "f32.sqrt", "f32.add", "f32.sub", "f32.mul", "f32.div", "f32.min", "f32.max", "f32.copysign",
    "f64.abs", "f64.neg", "f64.ceil", "f64.floor", "f64.trunc", "f64.nearest", "f64.sqrt", "f64.add", "f64.sub", "f64.mul", "f64.div", "f64.min", "f64.max", "f64.copysign",
    "i32.wrap_i64", "i32.trunc_f32_s", "i32.trunc_f32_u", "i32.trunc_f64_s", "i32.trunc_f64_u", "i64.extend_i32_s", "i64.extend_i32_u", "i64.trunc_f32_s", "i64.trunc_f32_u", "i64.trunc_f64_s", "i64.trunc_f64_u",
    "f32.convert_i32_s", "f32.convert_i32_u", "f32.convert_i64_s", "f32.convert_i64_u", "f32.demote_f64", "f64.convert_i32_s", "f64.convert_i32_u", "f64.convert_i64_s", "f64.convert_i64_u", "f64.promote_f32",
    "i32.reinterpret_f32", "i64.reinterpret_f64", "f32.reinterpret_i32", "f64.reinterpret_i64", "i32.extend8_s", "i32.extend16_s", "i64.extend8_s", "i64.extend16_s", "i64.extend32_s"};
constexpr std::array<std::string_view, 23> memory_names{
    "i32.load", "i64.load", "f32.load", "f64.load", "i32.load8_s", "i32.load8_u", "i32.load16_s", "i32.load16_u",
    "i64.load8_s", "i64.load8_u", "i64.load16_s", "i64.load16_u", "i64.load32_s", "i64.load32_u", "i32.store", "i64.store",
    "f32.store", "f64.store", "i32.store8", "i32.store16", "i64.store8", "i64.store16", "i64.store32"};
DecodeResult fail(DecodeStatus status, std::string reason) { return {status, {}, std::move(reason)}; }
}

DecodeResult decode_wasm(std::span<const std::byte> bytes, Address at) {
    if (bytes.empty()) return fail(DecodeStatus::truncated, "truncated WebAssembly opcode");
    const auto op = std::to_integer<std::uint8_t>(bytes[0]);
    std::size_t position = 1;
    std::string mnemonic;
    std::vector<Operand> operands;
    const auto add_u = [&](unsigned width) -> LebResult {
        std::uint64_t value = 0;
        const auto result = uleb(bytes, position, width, value);
        if (result == LebResult::ok)
            operands.push_back(ImmediateOperand{value, static_cast<std::uint8_t>(std::min(64u, width)), 32, false, {}});
        return result;
    };
    const auto add_s = [&](unsigned width, unsigned effective) -> LebResult {
        std::int64_t value = 0;
        const auto result = sleb(bytes, position, width, value);
        if (result == LebResult::ok)
            operands.push_back(ImmediateOperand{static_cast<std::uint64_t>(value), static_cast<std::uint8_t>(width), static_cast<std::uint8_t>(effective), true, {}});
        return result;
    };
    const auto decode_leb_result = [](LebResult result) -> DecodeResult {
        if (result == LebResult::truncated) return fail(DecodeStatus::truncated, "truncated WebAssembly immediate");
        if (result == LebResult::too_long) return fail(DecodeStatus::unsupported, "WebAssembly instruction exceeds the fixed instruction byte capacity");
        return fail(DecodeStatus::invalid, "invalid WebAssembly LEB128 immediate");
    };
    LebResult last_leb_result = LebResult::ok;
    const auto require_u = [&](unsigned width) -> bool {
        last_leb_result = add_u(width);
        return last_leb_result == LebResult::ok;
    };
    if (op <= 0x05) {
        constexpr std::array<std::string_view, 6> names{"unreachable", "nop", "block", "loop", "if", "else"};
        mnemonic = names[op];
        if (op >= 0x02 && op <= 0x04) {
            // Block type is a signed 33-bit type index or a one-byte value type.
            std::int64_t ignored = 0;
            const auto result = sleb(bytes, position, 33, ignored);
            if (result != LebResult::ok) return decode_leb_result(result);
            operands.push_back(ImmediateOperand{static_cast<std::uint64_t>(ignored), 33, 32, true, {}});
        }
    } else if (op == 0x0b || op == 0x0f || op == 0x1a || op == 0x1b) {
        mnemonic = op == 0x0b ? "end" : op == 0x0f ? "return" : op == 0x1a ? "drop" : "select";
    } else if (op == 0x0c || op == 0x0d || op == 0x10 || (op >= 0x20 && op <= 0x24)) {
        mnemonic = op == 0x0c ? "br" : op == 0x0d ? "br_if" : op == 0x10 ? "call" :
                   op == 0x20 ? "local.get" : op == 0x21 ? "local.set" : op == 0x22 ? "local.tee" : op == 0x23 ? "global.get" : "global.set";
        if (!require_u(32)) return decode_leb_result(last_leb_result);
    } else if (op == 0x0e) {
        mnemonic = "br_table";
        std::uint64_t count = 0;
        auto result = uleb(bytes, position, 32, count);
        if (result != LebResult::ok) return decode_leb_result(result);
        if (count > 12) return fail(DecodeStatus::unsupported, "br_table exceeds the maximum case count that can fit in a 15-byte instruction");
        operands.push_back(ImmediateOperand{count, 32, 32, false, {}});
        for (std::uint64_t n = 0; n <= count; ++n) {
            std::uint64_t label = 0;
            result = uleb(bytes, position, 32, label);
            if (result != LebResult::ok) return decode_leb_result(result);
            operands.push_back(ImmediateOperand{label, 32, 32, false, {}});
            if (position > 15) return fail(DecodeStatus::unsupported, "br_table instruction exceeds 15 encoded bytes");
        }
    } else if (op == 0x11) {
        mnemonic = "call_indirect";
        if (!require_u(32) || !require_u(32)) return decode_leb_result(last_leb_result);
    } else if (op >= 0x28 && op <= 0x3e) {
        mnemonic = memory_names[op - 0x28];
        const auto align = add_u(32);
        if (align != LebResult::ok) return decode_leb_result(align);
        const auto offset = add_u(32);
        if (offset != LebResult::ok) return decode_leb_result(offset);
    } else if (op == 0x3f || op == 0x40) {
        mnemonic = op == 0x3f ? "memory.size" : "memory.grow";
        if (!require_u(32)) return decode_leb_result(last_leb_result);
    } else if (op == 0x41 || op == 0x42) {
        mnemonic = op == 0x41 ? "i32.const" : "i64.const";
        const auto result = add_s(op == 0x41 ? 32 : 64, op == 0x41 ? 32 : 64);
        if (result != LebResult::ok) return decode_leb_result(result);
    } else if (op == 0x43 || op == 0x44) {
        const std::size_t size = op == 0x43 ? 4 : 8;
        if (bytes.size() - position < size) return fail(DecodeStatus::truncated, "truncated WebAssembly floating-point immediate");
        mnemonic = op == 0x43 ? "f32.const" : "f64.const";
        std::uint64_t bits = 0;
        for (std::size_t n = 0; n < size; ++n) bits |= std::uint64_t(std::to_integer<std::uint8_t>(bytes[position++])) << (n * 8);
        operands.push_back(ImmediateOperand{bits, static_cast<std::uint8_t>(size * 8), static_cast<std::uint8_t>(size * 8), false, {}});
    } else if (op >= 0x45 && op <= 0xc4) {
        mnemonic = numeric_names[op - 0x45];
    } else {
        return fail(DecodeStatus::unsupported, "WebAssembly opcode is outside the enabled core scalar subset");
    }
    if (position > 15) return fail(DecodeStatus::unsupported, "WebAssembly instruction exceeds the fixed instruction byte capacity");
    Instruction instruction;
    instruction.context = {Architecture::wasm, ExecutionMode::wasm32, ByteOrder::little};
    instruction.address = at;
    instruction.length = static_cast<std::uint8_t>(position);
    std::copy_n(bytes.begin(), position, instruction.bytes.begin());
    instruction.opcode = Opcode::wasm;
    instruction.mnemonic_override = std::move(mnemonic);
    instruction.operands = std::move(operands);
    return {DecodeStatus::decoded, std::move(instruction), {}};
}
} // namespace hexlab
