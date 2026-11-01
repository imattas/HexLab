#include "hexlab/processors/mips64_semantics.hpp"

#include <algorithm>
#include <array>
#include <bit>

namespace hexlab {
namespace {
constexpr Mips64FpNumericInfo operations[]{
    {Opcode::mips_add_s, "mips64.add.s", 32, 32, false, false, true},
    {Opcode::mips_sub_s, "mips64.sub.s", 32, 32, false, false, true},
    {Opcode::mips_mul_s, "mips64.mul.s", 32, 32, false, false, true},
    {Opcode::mips_div_s, "mips64.div.s", 32, 32, false, false, true},
    {Opcode::mips_sqrt_s, "mips64.sqrt.s", 32, 32},
    {Opcode::mips_add_d, "mips64.add.d", 64, 64, false, false, true},
    {Opcode::mips_sub_d, "mips64.sub.d", 64, 64, false, false, true},
    {Opcode::mips_mul_d, "mips64.mul.d", 64, 64, false, false, true},
    {Opcode::mips_div_d, "mips64.div.d", 64, 64, false, false, true},
    {Opcode::mips_sqrt_d, "mips64.sqrt.d", 64, 64},
    {Opcode::mips_cvt_s_d, "mips64.cvt.s.d", 64, 32},
    {Opcode::mips_cvt_d_s, "mips64.cvt.d.s", 32, 64},
    {Opcode::mips_cvt_s_w, "mips64.cvt.s.w", 32, 32, true},
    {Opcode::mips_cvt_d_w, "mips64.cvt.d.w", 32, 64, true},
    {Opcode::mips64_cvt_s_l, "mips64.cvt.s.l", 64, 32, true},
    {Opcode::mips64_cvt_d_l, "mips64.cvt.d.l", 64, 64, true},
    {Opcode::mips_cvt_w_s, "mips64.cvt.w.s", 32, 32, false, true},
    {Opcode::mips_cvt_w_d, "mips64.cvt.w.d", 64, 32, false, true},
    {Opcode::mips64_cvt_l_s, "mips64.cvt.l.s", 32, 64, false, true},
    {Opcode::mips64_cvt_l_d, "mips64.cvt.l.d", 64, 64, false, true},
    {Opcode::mips_round_w_s, "mips64.round.w.s", 32, 32, false, true},
    {Opcode::mips_trunc_w_s, "mips64.trunc.w.s", 32, 32, false, true},
    {Opcode::mips_ceil_w_s, "mips64.ceil.w.s", 32, 32, false, true},
    {Opcode::mips_floor_w_s, "mips64.floor.w.s", 32, 32, false, true},
    {Opcode::mips_round_w_d, "mips64.round.w.d", 64, 32, false, true},
    {Opcode::mips_trunc_w_d, "mips64.trunc.w.d", 64, 32, false, true},
    {Opcode::mips_ceil_w_d, "mips64.ceil.w.d", 64, 32, false, true},
    {Opcode::mips_floor_w_d, "mips64.floor.w.d", 64, 32, false, true},
    {Opcode::mips64_round_l_s, "mips64.round.l.s", 32, 64, false, true},
    {Opcode::mips64_trunc_l_s, "mips64.trunc.l.s", 32, 64, false, true},
    {Opcode::mips64_ceil_l_s, "mips64.ceil.l.s", 32, 64, false, true},
    {Opcode::mips64_floor_l_s, "mips64.floor.l.s", 32, 64, false, true},
    {Opcode::mips64_round_l_d, "mips64.round.l.d", 64, 64, false, true},
    {Opcode::mips64_trunc_l_d, "mips64.trunc.l.d", 64, 64, false, true},
    {Opcode::mips64_ceil_l_d, "mips64.ceil.l.d", 64, 64, false, true},
    {Opcode::mips64_floor_l_d, "mips64.floor.l.d", 64, 64, false, true},
};
const Mips64FpNumericInfo *info(Opcode opcode) noexcept {
    const auto found = std::find_if(std::begin(operations), std::end(operations),
        [=](const auto &item) { return item.opcode == opcode; });
    return found == std::end(operations) ? nullptr : found;
}
// 2,176 bits cover exact alignment of any two normal binary64 operands.
// Products and the scaled division/square-root intermediates need <= 112 bits.
struct Magnitude {
    std::array<std::uint32_t, 68> words{};
    bool bit(int index) const noexcept {
        return index >= 0 && index < 2176 && ((words[index / 32] >> (index % 32)) & 1u);
    }
    int top() const noexcept {
        for (int n = 67; n >= 0; --n)
            if (words[n]) return n * 32 + static_cast<int>(std::bit_width(words[n])) - 1;
        return -1;
    }
};
Magnitude magnitude(std::uint64_t value, int shift = 0) noexcept {
    Magnitude out;
    for (int bit = 0; bit < 64; ++bit)
        if ((value >> bit) & 1u) out.words[(bit + shift) / 32] |= 1u << ((bit + shift) % 32);
    return out;
}
int compare(const Magnitude &a, const Magnitude &b) noexcept {
    for (int n = 67; n >= 0; --n)
        if (a.words[n] != b.words[n]) return a.words[n] > b.words[n] ? 1 : -1;
    return 0;
}
Magnitude combine(const Magnitude &a, const Magnitude &b, bool subtract) noexcept {
    Magnitude out;
    std::uint64_t carry = 0;
    for (int n = 0; n < 68; ++n) {
        const auto value = subtract ? std::uint64_t{a.words[n]} - b.words[n] - carry :
                                     std::uint64_t{a.words[n]} + b.words[n] + carry;
        out.words[n] = static_cast<std::uint32_t>(value);
        carry = subtract ? value >> 63 : value >> 32;
    }
    return out;
}
Magnitude product(std::uint64_t a, std::uint64_t b) noexcept {
    Magnitude out;
    for (unsigned n = 0; n < 2; ++n) {
        std::uint64_t carry = 0;
        for (unsigned m = 0; m < 2; ++m) {
            const auto value = std::uint64_t{static_cast<std::uint32_t>(a >> (32 * n))} *
                static_cast<std::uint32_t>(b >> (32 * m)) + out.words[n + m] + carry;
            out.words[n + m] = static_cast<std::uint32_t>(value);
            carry = value >> 32;
        }
        out.words[n + 2] = static_cast<std::uint32_t>(carry);
    }
    return out;
}
struct Number { std::uint64_t significand; int scale; bool negative; };
std::optional<Number> decode(std::uint64_t bits, const Mips64FpNumericInfo &item) noexcept {
    const auto width = item.source_width;
    if (width == 32 && bits > UINT32_MAX) return {};
    const bool negative = (bits >> (width - 1)) != 0;
    if (item.integer_source) {
        const auto value = negative ? (std::uint64_t{0} - bits) : bits;
        return Number{width == 32 ? value & UINT32_MAX : value, 0, negative};
    }
    const int fraction_bits = width == 32 ? 23 : 52;
    const int bias = width == 32 ? 127 : 1023;
    const auto exponent_mask = width == 32 ? 255u : 2047u;
    const auto exponent = static_cast<unsigned>((bits >> fraction_bits) & exponent_mask);
    const auto fraction = bits & ((UINT64_C(1) << fraction_bits) - 1);
    if (exponent == exponent_mask || (exponent == 0 && fraction != 0)) return {};
    return Number{exponent ? fraction | (UINT64_C(1) << fraction_bits) : 0,
        exponent ? static_cast<int>(exponent) - bias - fraction_bits : 0, negative};
}
struct Rounded { std::uint64_t value; bool inexact; };
std::optional<Rounded> round(const Magnitude &value, int shift, bool negative,
                              unsigned mode, bool sticky) noexcept {
    if (value.top() - shift >= 64 || (shift <= 0 && sticky)) return {};
    std::uint64_t result = 0;
    for (int n = 0; n < 64; ++n) if (value.bit(n + shift)) result |= UINT64_C(1) << n;
    bool lower = sticky;
    for (int n = 0; n < std::min(shift - 1, 2176); ++n) lower |= value.bit(n);
    const bool guard = value.bit(shift - 1);
    const bool inexact = guard || lower;
    const bool increment = mode == 0 ? guard && (lower || (result & 1)) :
        mode == 2 ? inexact && !negative : mode == 3 ? inexact && negative : false;
    if (increment && result == UINT64_MAX) return {};
    return Rounded{result + increment, inexact};
}
std::optional<Mips64FpNumericResult> finish(std::uint64_t bits, bool inexact,
                                           std::uint32_t fcsr) noexcept {
    // Only Inexact can arise within the supported normal finite domain.
    if (inexact && (fcsr & (1u << 7))) return {};
    return Mips64FpNumericResult{bits, (fcsr & ~0x0003f000u) |
        (inexact ? 0x00001004u : 0), inexact};
}
std::optional<Mips64FpNumericResult> pack(const Magnitude &value, int scale, bool negative,
    const Mips64FpNumericInfo &item, unsigned mode, bool sticky, std::uint32_t fcsr) noexcept {
    if (item.integer_result) {
        const auto rounded = round(value, -scale, negative, mode, sticky);
        if (!rounded) return {};
        const auto limit = UINT64_C(1) << (item.result_width - 1);
        if (rounded->value > limit || (!negative && rounded->value == limit)) return {};
        const auto bits = negative ? std::uint64_t{0} - rounded->value : rounded->value;
        return finish(item.result_width == 32 ? bits & UINT32_MAX : bits, rounded->inexact, fcsr);
    }
    const int fraction_bits = item.result_width == 32 ? 23 : 52;
    const int bias = item.result_width == 32 ? 127 : 1023;
    const auto sign = negative ? UINT64_C(1) << (item.result_width - 1) : 0;
    const auto top = value.top();
    if (top < 0) return sticky ? std::optional<Mips64FpNumericResult>{} : finish(sign, false, fcsr);
    int exponent = top + scale;
    if (exponent < 1 - bias || exponent > bias) return {};
    auto rounded = round(value, top - fraction_bits, negative, mode, sticky);
    if (!rounded) return {};
    if (rounded->value == (UINT64_C(1) << (fraction_bits + 1))) {
        rounded->value >>= 1;
        if (++exponent > bias) return {};
    }
    const auto bits = sign | (std::uint64_t{static_cast<unsigned>(exponent + bias)} << fraction_bits) |
        (rounded->value & ((UINT64_C(1) << fraction_bits) - 1));
    return finish(bits, rounded->inexact, fcsr);
}
} // namespace

std::span<const Mips64FpNumericInfo> mips64_fp_numeric_inventory() noexcept { return operations; }

std::optional<Mips64FpNumericResult> evaluate_mips64_fp_numeric(
    Opcode opcode, std::uint64_t left_bits, std::uint64_t right_bits, std::uint32_t fcsr) noexcept {
    const auto *item = info(opcode);
    if (!item || (fcsr & (1u << 24))) return {};
    const auto left = decode(left_bits, *item);
    const auto right = item->binary ? decode(right_bits, *item) : std::optional<Number>{Number{0, 0, false}};
    if (!left || !right) return {};
    unsigned mode = fcsr & 3u;
    if (item->intrinsic_name.starts_with("mips64.round.")) mode = 0;
    if (item->intrinsic_name.starts_with("mips64.trunc.")) mode = 1;
    if (item->intrinsic_name.starts_with("mips64.ceil.")) mode = 2;
    if (item->intrinsic_name.starts_with("mips64.floor.")) mode = 3;
    const bool add = opcode == Opcode::mips_add_s || opcode == Opcode::mips_add_d;
    const bool subtract = opcode == Opcode::mips_sub_s || opcode == Opcode::mips_sub_d;
    if (add || subtract) {
        const auto scale = std::min(left->scale, right->scale);
        const auto a = magnitude(left->significand, left->scale - scale);
        const auto b = magnitude(right->significand, right->scale - scale);
        const bool right_negative = right->negative != subtract;
        if (left->negative == right_negative)
            return pack(combine(a, b, false), scale, left->negative, *item, mode, false, fcsr);
        const auto order = compare(a, b);
        return pack(order >= 0 ? combine(a, b, true) : combine(b, a, true), scale,
            order == 0 ? mode == 3 : order > 0 ? left->negative : right_negative, *item, mode, false, fcsr);
    }
    if (opcode == Opcode::mips_mul_s || opcode == Opcode::mips_mul_d)
        return pack(product(left->significand, right->significand), left->scale + right->scale,
            left->negative != right->negative, *item, mode, false, fcsr);
    if (opcode == Opcode::mips_div_s || opcode == Opcode::mips_div_d) {
        if (right->significand == 0) return {};
        const int precision = item->result_width == 32 ? 24 : 53;
        const int shift = precision + 2 + (left->significand < right->significand ? 1 : 0);
        const auto numerator = magnitude(left->significand, shift);
        std::uint64_t quotient = 0, remainder = 0;
        for (int n = numerator.top(); n >= 0; --n) {
            remainder = (remainder << 1) | static_cast<std::uint64_t>(numerator.bit(n));
            quotient <<= 1;
            if (remainder >= right->significand) { remainder -= right->significand; ++quotient; }
        }
        return pack(magnitude(quotient), left->scale - right->scale - shift,
            left->negative != right->negative, *item, mode, remainder != 0, fcsr);
    }
    if (opcode == Opcode::mips_sqrt_s || opcode == Opcode::mips_sqrt_d) {
        if (left->negative && left->significand) return {};
        if (!left->significand) return finish(left_bits, false, fcsr);
        auto significand = left->significand;
        int scale = left->scale;
        if (scale % 2) { significand <<= 1; --scale; }
        const int precision = item->result_width == 32 ? 24 : 53;
        const int shift = 2 * (precision + 2 - (static_cast<int>(std::bit_width(significand)) - 1) / 2);
        const auto radicand = magnitude(significand, shift);
        std::uint64_t root = 0, remainder = 0;
        for (int pair = radicand.top() / 2; pair >= 0; --pair) {
            remainder = (remainder << 2) | (radicand.bit(pair * 2 + 1) ? 2u : 0u) |
                static_cast<std::uint64_t>(radicand.bit(pair * 2));
            root <<= 1;
            const auto trial = (root << 1) | 1u;
            if (remainder >= trial) { remainder -= trial; ++root; }
        }
        return pack(magnitude(root), scale / 2 - shift / 2, false, *item, mode, remainder != 0, fcsr);
    }
    return pack(magnitude(left->significand), left->scale, left->negative, *item, mode, false, fcsr);
}

std::optional<Mips64FpNumericInfo> mips64_fp_numeric_instruction_info(const Instruction &instruction) noexcept {
    const auto *item = info(instruction.opcode);
    if (!item || instruction.context.architecture != Architecture::mips64 ||
        instruction.context.mode != ExecutionMode::mips64 || instruction.length != 4 ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots ||
        instruction.memory_read || instruction.memory_write || instruction.operands.size() != (item->binary ? 3u : 2u)) return {};
    std::vector<RegisterOperand> reads, writes;
    std::vector<OperandAccess> access;
    for (std::size_t n = 0; n < instruction.operands.size(); ++n) {
        const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[n]);
        if (!reg || reg->bank != RegisterBank::mips_fpr || reg->index > 31 || reg->high_byte ||
            reg->width != (n == 0 ? item->result_width : item->source_width)) return {};
        if (n) reads.push_back(*reg); else writes.push_back(*reg);
        access.push_back(n ? OperandAccess::read : OperandAccess::write);
    }
    const RegisterOperand control{RegisterBank::mips_fcsr, 0, 32, false};
    reads.push_back(control); writes.push_back(control);
    if (instruction.access != access || instruction.register_reads != reads || instruction.register_writes != writes) return {};
    return *item;
}
std::optional<Mips64FpNumericResult> evaluate_mips64_fp_numeric_instruction(
    const Instruction &instruction, std::uint64_t left, std::uint64_t right, std::uint32_t fcsr) noexcept {
    if (!mips64_fp_numeric_instruction_info(instruction)) return {};
    return evaluate_mips64_fp_numeric(instruction.opcode, left, right, fcsr);
}
} // namespace hexlab
