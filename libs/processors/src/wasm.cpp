#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/wasm_semantics.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <string>
#include <string_view>

namespace hexlab {
namespace {
constexpr std::size_t wasm_instruction_capacity = 32;
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
constexpr std::array<std::uint8_t, 23> memory_alignment_log2{
    2, 3, 2, 3, 0, 0, 1, 1, 0, 0, 1, 1, 2, 2, 2, 3, 2, 3, 0, 1, 0, 1, 2};
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
            if (ignored < 0 && ignored != -64 && ignored != -1 && ignored != -2 &&
                ignored != -3 && ignored != -4 && ignored != -16)
                return fail(DecodeStatus::invalid, "invalid WebAssembly block value type");
            operands.push_back(ImmediateOperand{static_cast<std::uint64_t>(ignored), 33, 32, true, {}});
        }
    } else if (op == 0x1c) {
        mnemonic = "select_typed";
        std::uint64_t count = 0;
        const auto result = uleb(bytes, position, 32, count);
        if (result != LebResult::ok) return decode_leb_result(result);
        if (count != 1) return fail(DecodeStatus::invalid, "typed select requires exactly one result type");
        if (position >= bytes.size()) return fail(DecodeStatus::truncated, "truncated typed select value type");
        const auto type = std::to_integer<std::uint8_t>(bytes[position++]);
        if (type != 0x7f && type != 0x7e && type != 0x7d && type != 0x7c &&
            type != 0x70 && type != 0x6f)
            return fail(DecodeStatus::unsupported, "typed select value type is outside the numeric and reference subset");
        operands.push_back(ImmediateOperand{type, 8, 8, false, {}});
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
        const auto *table_index = std::get_if<ImmediateOperand>(&operands.back());
        if (!table_index || table_index->value != 0)
            return fail(DecodeStatus::invalid, "WebAssembly 1.0 call_indirect reserved table index must be zero");
    } else if (op >= 0x28 && op <= 0x3e) {
        mnemonic = memory_names[op - 0x28];
        const auto align = add_u(32);
        if (align != LebResult::ok) return decode_leb_result(align);
        const auto *alignment = std::get_if<ImmediateOperand>(&operands.back());
        if (!alignment || alignment->value > memory_alignment_log2[op - 0x28])
            return fail(DecodeStatus::invalid, "WebAssembly scalar memarg alignment exceeds the access width");
        const auto offset = add_u(32);
        if (offset != LebResult::ok) return decode_leb_result(offset);
    } else if (op == 0x3f || op == 0x40) {
        mnemonic = op == 0x3f ? "memory.size" : "memory.grow";
        if (!require_u(32)) return decode_leb_result(last_leb_result);
        const auto *memory_index = std::get_if<ImmediateOperand>(&operands.back());
        if (!memory_index || memory_index->value != 0)
            return fail(DecodeStatus::invalid, "WebAssembly 1.0 memory index must be zero");
    } else if (op == 0xfd) {
        std::uint64_t subopcode = 0;
        const auto result = uleb(bytes, position, 32, subopcode);
        if (result != LebResult::ok) return decode_leb_result(result);

        std::string_view name;
        unsigned access_log2 = 0;
        bool lane_indexed = false;
        bool lane_immediate = false;
        bool shuffle_immediate = false;
        unsigned lane_count = 0;
        bool memory_access = true;
        bool vector_constant = false;
        static constexpr std::array<std::string_view, 42> comparison_names{
            "i8x16.eq", "i8x16.ne", "i8x16.lt_s", "i8x16.lt_u", "i8x16.gt_s", "i8x16.gt_u", "i8x16.le_s", "i8x16.le_u", "i8x16.ge_s", "i8x16.ge_u",
            "i16x8.eq", "i16x8.ne", "i16x8.lt_s", "i16x8.lt_u", "i16x8.gt_s", "i16x8.gt_u", "i16x8.le_s", "i16x8.le_u", "i16x8.ge_s", "i16x8.ge_u",
            "i32x4.eq", "i32x4.ne", "i32x4.lt_s", "i32x4.lt_u", "i32x4.gt_s", "i32x4.gt_u", "i32x4.le_s", "i32x4.le_u", "i32x4.ge_s", "i32x4.ge_u",
            "f32x4.eq", "f32x4.ne", "f32x4.lt", "f32x4.gt", "f32x4.le", "f32x4.ge",
            "f64x2.eq", "f64x2.ne", "f64x2.lt", "f64x2.gt", "f64x2.le", "f64x2.ge"};
        struct SimdOpcodeName { std::uint64_t opcode; std::string_view name; };
        // Finalized Relaxed SIMD encodings occupy a separate range after the
        // core SIMD opcodes. Keep the table explicit so reserved values stay
        // rejected rather than being accepted by a broad range check.
        static constexpr SimdOpcodeName relaxed_simd_names[]{
            {0x100, "i8x16.relaxed_swizzle"},
            {0x101, "i32x4.relaxed_trunc_f32x4_s"}, {0x102, "i32x4.relaxed_trunc_f32x4_u"},
            {0x103, "i32x4.relaxed_trunc_f64x2_s_zero"}, {0x104, "i32x4.relaxed_trunc_f64x2_u_zero"},
            {0x105, "f32x4.relaxed_madd"}, {0x106, "f32x4.relaxed_nmadd"},
            {0x107, "f64x2.relaxed_madd"}, {0x108, "f64x2.relaxed_nmadd"},
            {0x109, "i8x16.relaxed_laneselect"}, {0x10a, "i16x8.relaxed_laneselect"},
            {0x10b, "i32x4.relaxed_laneselect"}, {0x10c, "i64x2.relaxed_laneselect"},
            {0x10d, "f32x4.relaxed_min"}, {0x10e, "f32x4.relaxed_max"},
            {0x10f, "f64x2.relaxed_min"}, {0x110, "f64x2.relaxed_max"},
            {0x111, "i16x8.relaxed_q15mulr_s"},
            {0x112, "i16x8.relaxed_dot_i8x16_i7x16_s"},
            {0x113, "i32x4.relaxed_dot_i8x16_i7x16_add_s"}};
        // Integer SIMD forms outside the shared binary arithmetic family. Keep
        // an explicit opcode table so reserved SIMD gaps are never accepted
        // by broad numeric ranges.
        static constexpr SimdOpcodeName extended_integer_names[]{
            {0x65, "i8x16.narrow_i16x8_s"}, {0x66, "i8x16.narrow_i16x8_u"},
            {0x6b, "i8x16.shl"}, {0x6c, "i8x16.shr_s"}, {0x6d, "i8x16.shr_u"},
            {0x7c, "i16x8.extadd_pairwise_i8x16_s"}, {0x7d, "i16x8.extadd_pairwise_i8x16_u"},
            {0x7e, "i32x4.extadd_pairwise_i16x8_s"}, {0x7f, "i32x4.extadd_pairwise_i16x8_u"},
            {0x85, "i16x8.narrow_i32x4_s"}, {0x86, "i16x8.narrow_i32x4_u"},
            {0x87, "i16x8.extend_low_i8x16_s"}, {0x88, "i16x8.extend_high_i8x16_s"},
            {0x89, "i16x8.extend_low_i8x16_u"}, {0x8a, "i16x8.extend_high_i8x16_u"},
            {0x8b, "i16x8.shl"}, {0x8c, "i16x8.shr_s"}, {0x8d, "i16x8.shr_u"},
            {0x9c, "i16x8.extmul_low_i8x16_s"}, {0x9d, "i16x8.extmul_high_i8x16_s"},
            {0x9e, "i16x8.extmul_low_i8x16_u"}, {0x9f, "i16x8.extmul_high_i8x16_u"},
            {0xa7, "i32x4.extend_low_i16x8_s"}, {0xa8, "i32x4.extend_high_i16x8_s"},
            {0xa9, "i32x4.extend_low_i16x8_u"}, {0xaa, "i32x4.extend_high_i16x8_u"},
            {0xab, "i32x4.shl"}, {0xac, "i32x4.shr_s"}, {0xad, "i32x4.shr_u"},
            {0xba, "i32x4.dot_i16x8_s"},
            {0xbc, "i32x4.extmul_low_i16x8_s"}, {0xbd, "i32x4.extmul_high_i16x8_s"},
            {0xbe, "i32x4.extmul_low_i16x8_u"}, {0xbf, "i32x4.extmul_high_i16x8_u"},
            {0xc7, "i64x2.extend_low_i32x4_s"}, {0xc8, "i64x2.extend_high_i32x4_s"},
            {0xc9, "i64x2.extend_low_i32x4_u"}, {0xca, "i64x2.extend_high_i32x4_u"},
            {0xcb, "i64x2.shl"}, {0xcc, "i64x2.shr_s"}, {0xcd, "i64x2.shr_u"},
            {0xd6, "i64x2.eq"}, {0xd7, "i64x2.ne"}, {0xd8, "i64x2.lt_s"},
            {0xd9, "i64x2.gt_s"}, {0xda, "i64x2.le_s"}, {0xdb, "i64x2.ge_s"},
            {0xdc, "i64x2.extmul_low_i32x4_s"}, {0xdd, "i64x2.extmul_high_i32x4_s"},
            {0xde, "i64x2.extmul_low_i32x4_u"}, {0xdf, "i64x2.extmul_high_i32x4_u"}};
        const auto integer_arithmetic = wasm_simd_integer_binary_op(static_cast<std::uint32_t>(subopcode));
        const auto relaxed_simd = std::find_if(std::begin(relaxed_simd_names), std::end(relaxed_simd_names),
            [subopcode](const SimdOpcodeName &candidate) { return candidate.opcode == subopcode; });
        const auto extended_integer = std::find_if(std::begin(extended_integer_names), std::end(extended_integer_names),
            [subopcode](const SimdOpcodeName &candidate) { return candidate.opcode == subopcode; });
        static constexpr std::array<SimdOpcodeName, 16> floating_arithmetic_names{{
            {0xe4, "f32x4.add"}, {0xe5, "f32x4.sub"}, {0xe6, "f32x4.mul"}, {0xe7, "f32x4.div"},
            {0xe8, "f32x4.min"}, {0xe9, "f32x4.max"}, {0xea, "f32x4.pmin"}, {0xeb, "f32x4.pmax"},
            {0xf0, "f64x2.add"}, {0xf1, "f64x2.sub"}, {0xf2, "f64x2.mul"}, {0xf3, "f64x2.div"},
            {0xf4, "f64x2.min"}, {0xf5, "f64x2.max"}, {0xf6, "f64x2.pmin"}, {0xf7, "f64x2.pmax"}}};
        static constexpr SimdOpcodeName floating_unary_names[]{
            {0x67, "f32x4.ceil"}, {0x68, "f32x4.floor"}, {0x69, "f32x4.trunc"},
            {0x6a, "f32x4.nearest"}, {0x74, "f64x2.ceil"}, {0x75, "f64x2.floor"},
            {0x7a, "f64x2.trunc"}, {0x94, "f64x2.nearest"},
            {0xe0, "f32x4.abs"}, {0xe1, "f32x4.neg"}, {0xe3, "f32x4.sqrt"},
            {0xec, "f64x2.abs"}, {0xed, "f64x2.neg"}, {0xef, "f64x2.sqrt"}};
        static constexpr SimdOpcodeName floating_conversion_names[]{
            {0x5e, "f32x4.demote_f64x2_zero"}, {0x5f, "f64x2.promote_low_f32x4"},
            {0xf8, "i32x4.trunc_sat_f32x4_s"}, {0xf9, "i32x4.trunc_sat_f32x4_u"},
            {0xfa, "f32x4.convert_i32x4_s"}, {0xfb, "f32x4.convert_i32x4_u"},
            {0xfc, "i32x4.trunc_sat_f64x2_s_zero"}, {0xfd, "i32x4.trunc_sat_f64x2_u_zero"},
            {0xfe, "f64x2.convert_low_i32x4_s"}, {0xff, "f64x2.convert_low_i32x4_u"}};
        static constexpr std::array<SimdOpcodeName, 5> i8_unary_names{{
            {0x60, "i8x16.abs"}, {0x61, "i8x16.neg"}, {0x62, "i8x16.popcnt"},
            {0x63, "i8x16.all_true"}, {0x64, "i8x16.bitmask"}}};
        static constexpr std::array<SimdOpcodeName, 12> wider_integer_unary_names{{
            {0x80, "i16x8.abs"}, {0x81, "i16x8.neg"}, {0x83, "i16x8.all_true"}, {0x84, "i16x8.bitmask"},
            {0xa0, "i32x4.abs"}, {0xa1, "i32x4.neg"}, {0xa3, "i32x4.all_true"}, {0xa4, "i32x4.bitmask"},
            {0xc0, "i64x2.abs"}, {0xc1, "i64x2.neg"}, {0xc3, "i64x2.all_true"}, {0xc4, "i64x2.bitmask"}}};
        const auto floating_arithmetic = std::find_if(floating_arithmetic_names.begin(), floating_arithmetic_names.end(),
            [subopcode](const SimdOpcodeName &candidate) { return candidate.opcode == subopcode; });
        const auto floating_unary = std::find_if(std::begin(floating_unary_names), std::end(floating_unary_names),
            [subopcode](const SimdOpcodeName &candidate) { return candidate.opcode == subopcode; });
        const auto floating_conversion = std::find_if(std::begin(floating_conversion_names), std::end(floating_conversion_names),
            [subopcode](const SimdOpcodeName &candidate) { return candidate.opcode == subopcode; });
        const auto i8_unary = std::find_if(i8_unary_names.begin(), i8_unary_names.end(),
            [subopcode](const SimdOpcodeName &candidate) { return candidate.opcode == subopcode; });
        const auto wider_integer_unary = std::find_if(wider_integer_unary_names.begin(), wider_integer_unary_names.end(),
            [subopcode](const SimdOpcodeName &candidate) { return candidate.opcode == subopcode; });
        if (relaxed_simd != std::end(relaxed_simd_names)) {
            name = relaxed_simd->name;
            memory_access = false;
        } else if (integer_arithmetic) {
            name = integer_arithmetic->name;
            memory_access = false;
        } else if (extended_integer != std::end(extended_integer_names)) {
            name = extended_integer->name;
            memory_access = false;
        } else if (floating_arithmetic != floating_arithmetic_names.end()) {
            name = floating_arithmetic->name;
            memory_access = false;
        } else if (floating_unary != std::end(floating_unary_names)) {
            name = floating_unary->name;
            memory_access = false;
        } else if (floating_conversion != std::end(floating_conversion_names)) {
            name = floating_conversion->name;
            memory_access = false;
        } else if (i8_unary != i8_unary_names.end()) {
            name = i8_unary->name;
            memory_access = false;
        } else if (wider_integer_unary != wider_integer_unary_names.end()) {
            name = wider_integer_unary->name;
            memory_access = false;
        } else if (subopcode >= 0x23 && subopcode <= 0x4c) {
            name = comparison_names[static_cast<std::size_t>(subopcode - 0x23)];
            memory_access = false;
        } else switch (subopcode) {
        case 12: name = "v128.const"; vector_constant = true; memory_access = false; break;
        case 13: name = "i8x16.shuffle"; shuffle_immediate = true; memory_access = false; break;
        case 14: name = "i8x16.swizzle"; memory_access = false; break;
        case 15: name = "i8x16.splat"; memory_access = false; break;
        case 16: name = "i16x8.splat"; memory_access = false; break;
        case 17: name = "i32x4.splat"; memory_access = false; break;
        case 18: name = "i64x2.splat"; memory_access = false; break;
        case 19: name = "f32x4.splat"; memory_access = false; break;
        case 20: name = "f64x2.splat"; memory_access = false; break;
        case 21: name = "i8x16.extract_lane_s"; lane_count = 16; lane_immediate = true; memory_access = false; break;
        case 22: name = "i8x16.extract_lane_u"; lane_count = 16; lane_immediate = true; memory_access = false; break;
        case 23: name = "i8x16.replace_lane"; lane_count = 16; lane_immediate = true; memory_access = false; break;
        case 24: name = "i16x8.extract_lane_s"; lane_count = 8; lane_immediate = true; memory_access = false; break;
        case 25: name = "i16x8.extract_lane_u"; lane_count = 8; lane_immediate = true; memory_access = false; break;
        case 26: name = "i16x8.replace_lane"; lane_count = 8; lane_immediate = true; memory_access = false; break;
        case 27: name = "i32x4.extract_lane"; lane_count = 4; lane_immediate = true; memory_access = false; break;
        case 28: name = "i32x4.replace_lane"; lane_count = 4; lane_immediate = true; memory_access = false; break;
        case 29: name = "i64x2.extract_lane"; lane_count = 2; lane_immediate = true; memory_access = false; break;
        case 30: name = "i64x2.replace_lane"; lane_count = 2; lane_immediate = true; memory_access = false; break;
        case 31: name = "f32x4.extract_lane"; lane_count = 4; lane_immediate = true; memory_access = false; break;
        case 32: name = "f32x4.replace_lane"; lane_count = 4; lane_immediate = true; memory_access = false; break;
        case 33: name = "f64x2.extract_lane"; lane_count = 2; lane_immediate = true; memory_access = false; break;
        case 34: name = "f64x2.replace_lane"; lane_count = 2; lane_immediate = true; memory_access = false; break;
        case 77: name = "v128.not"; memory_access = false; break;
        case 78: name = "v128.and"; memory_access = false; break;
        case 79: name = "v128.andnot"; memory_access = false; break;
        case 80: name = "v128.or"; memory_access = false; break;
        case 81: name = "v128.xor"; memory_access = false; break;
        case 82: name = "v128.bitselect"; memory_access = false; break;
        case 83: name = "v128.any_true"; memory_access = false; break;
        case 0: name = "v128.load"; access_log2 = 4; break;
        case 1: name = "v128.load8x8_s"; access_log2 = 3; break;
        case 2: name = "v128.load8x8_u"; access_log2 = 3; break;
        case 3: name = "v128.load16x4_s"; access_log2 = 3; break;
        case 4: name = "v128.load16x4_u"; access_log2 = 3; break;
        case 5: name = "v128.load32x2_s"; access_log2 = 3; break;
        case 6: name = "v128.load32x2_u"; access_log2 = 3; break;
        case 7: name = "v128.load8_splat"; access_log2 = 0; break;
        case 8: name = "v128.load16_splat"; access_log2 = 1; break;
        case 9: name = "v128.load32_splat"; access_log2 = 2; break;
        case 10: name = "v128.load64_splat"; access_log2 = 3; break;
        case 11: name = "v128.store"; access_log2 = 4; break;
        case 84: name = "v128.load8_lane"; access_log2 = 0; lane_indexed = true; break;
        case 85: name = "v128.load16_lane"; access_log2 = 1; lane_indexed = true; break;
        case 86: name = "v128.load32_lane"; access_log2 = 2; lane_indexed = true; break;
        case 87: name = "v128.load64_lane"; access_log2 = 3; lane_indexed = true; break;
        case 88: name = "v128.store8_lane"; access_log2 = 0; lane_indexed = true; break;
        case 89: name = "v128.store16_lane"; access_log2 = 1; lane_indexed = true; break;
        case 90: name = "v128.store32_lane"; access_log2 = 2; lane_indexed = true; break;
        case 91: name = "v128.store64_lane"; access_log2 = 3; lane_indexed = true; break;
        case 92: name = "v128.load32_zero"; access_log2 = 2; break;
        case 93: name = "v128.load64_zero"; access_log2 = 3; break;
        default:
            return fail(DecodeStatus::unsupported, "WebAssembly SIMD opcode is outside the enabled vector-memory subset");
        }

        mnemonic = name;
        if (vector_constant) {
            if (bytes.size() - position < 16)
                return fail(DecodeStatus::truncated, "truncated WebAssembly SIMD v128.const immediate");
            for (unsigned word_index = 0; word_index < 2; ++word_index) {
                std::uint64_t word = 0;
                for (unsigned byte_index = 0; byte_index < 8; ++byte_index)
                    word |= std::uint64_t(std::to_integer<std::uint8_t>(bytes[position++])) << (byte_index * 8);
                operands.push_back(ImmediateOperand{word, 64, 64, false, {}});
            }
        } else if (shuffle_immediate) {
            if (bytes.size() - position < 16)
                return fail(DecodeStatus::truncated, "truncated WebAssembly SIMD shuffle lane vector");
            for (unsigned lane = 0; lane < 16; ++lane) {
                const auto selected = std::to_integer<std::uint8_t>(bytes[position++]);
                if (selected >= 32)
                    return fail(DecodeStatus::invalid, "WebAssembly SIMD shuffle lane exceeds the two input vectors");
                operands.push_back(ImmediateOperand{selected, 8, 8, false, {}});
            }
        } else if (memory_access) {
            const auto alignment = add_u(32);
            if (alignment != LebResult::ok) return decode_leb_result(alignment);
            const auto offset = add_u(32);
            if (offset != LebResult::ok) return decode_leb_result(offset);
            const auto align_operand = std::get_if<ImmediateOperand>(&operands[operands.size() - 2]);
            if (!align_operand || align_operand->value > access_log2)
                return fail(DecodeStatus::invalid, "WebAssembly SIMD memarg alignment exceeds the access width");
        }
        if (lane_indexed) {
            if (position >= bytes.size()) return fail(DecodeStatus::truncated, "truncated WebAssembly SIMD lane index");
            const auto lane = std::to_integer<std::uint8_t>(bytes[position++]);
            const auto lane_cardinality = 16u >> access_log2;
            if (lane >= lane_cardinality) return fail(DecodeStatus::invalid, "WebAssembly SIMD lane index exceeds the vector lane count");
            operands.push_back(ImmediateOperand{lane, 8, 8, false, {}});
        } else if (lane_immediate) {
            if (position >= bytes.size()) return fail(DecodeStatus::truncated, "truncated WebAssembly SIMD lane index");
            const auto lane = std::to_integer<std::uint8_t>(bytes[position++]);
            if (lane >= lane_count) return fail(DecodeStatus::invalid, "WebAssembly SIMD lane index exceeds the vector lane count");
            operands.push_back(ImmediateOperand{lane, 8, 8, false, {}});
        }
    } else if (op == 0xfc) {
        std::uint64_t subopcode = 0;
        const auto result = uleb(bytes, position, 32, subopcode);
        if (result != LebResult::ok) return decode_leb_result(result);
        if (subopcode > 17)
            return fail(DecodeStatus::unsupported, "WebAssembly 0xfc subopcode is outside the enabled scalar-conversion, bulk-memory, and table-operation subset");
        static constexpr std::array<std::string_view, 18> names{
            "i32.trunc_sat_f32_s", "i32.trunc_sat_f32_u", "i32.trunc_sat_f64_s", "i32.trunc_sat_f64_u",
            "i64.trunc_sat_f32_s", "i64.trunc_sat_f32_u", "i64.trunc_sat_f64_s", "i64.trunc_sat_f64_u",
            "memory.init", "data.drop", "memory.copy", "memory.fill",
            "table.init", "elem.drop", "table.copy", "table.grow", "table.size", "table.fill"};
        mnemonic = names[static_cast<std::size_t>(subopcode)];
        if (subopcode >= 8) {
            const unsigned immediate_count = subopcode == 8 || subopcode == 10 ||
                                             subopcode == 12 || subopcode == 14 ? 2 : 1;
            for (unsigned n = 0; n < immediate_count; ++n)
                if (!require_u(32)) return decode_leb_result(last_leb_result);
        }
    } else if (op == 0xd0) {
        mnemonic = "ref.null";
        std::int64_t heap_type = 0;
        const auto result = sleb(bytes, position, 33, heap_type);
        if (result != LebResult::ok) return decode_leb_result(result);
        if (heap_type != -16 && heap_type != -17)
            return fail(DecodeStatus::unsupported, "only ref.null funcref and externref are supported");
        mnemonic = heap_type == -16 ? "ref.null funcref" : "ref.null externref";
        operands.push_back(ImmediateOperand{static_cast<std::uint64_t>(heap_type), 33, 32, true, {}});
    } else if (op == 0xd1) {
        mnemonic = "ref.is_null";
    } else if (op == 0xd2) {
        mnemonic = "ref.func";
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
    if (position > wasm_instruction_capacity)
        return fail(DecodeStatus::unsupported, "WebAssembly instruction exceeds the 32-byte instruction capacity");
    Instruction instruction;
    instruction.context = {Architecture::wasm, ExecutionMode::wasm32, ByteOrder::little};
    instruction.address = at;
    instruction.length = static_cast<std::uint32_t>(position);
    std::copy_n(bytes.begin(), std::min(position, instruction.bytes.size()), instruction.bytes.begin());
    if (position > instruction.bytes.size())
        instruction.extended_bytes.assign(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(position));
    instruction.opcode = Opcode::wasm;
    instruction.mnemonic_override = std::move(mnemonic);
    instruction.operands = std::move(operands);
    // Calls have an ordinary sequential continuation, but must remain calls
    // in the shared analysis graph so callers can retain call sites and
    // follow proven direct targets. Indirect calls intentionally carry no
    // direct target.
    if (instruction.mnemonic_override == "call" || instruction.mnemonic_override == "call_indirect")
        instruction.flow = FlowKind::call;
    return {DecodeStatus::decoded, std::move(instruction), {}};
}
} // namespace hexlab
