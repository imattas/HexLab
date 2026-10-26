#include "hexlab/processors/x87_semantics.hpp"

#include <bit>
#include <algorithm>

namespace hexlab {
namespace {
constexpr std::uint16_t sign_mask = 0x8000, exponent_mask = 0x7fff;
constexpr std::uint64_t integer_bit = std::uint64_t{1} << 63;
constexpr std::uint64_t quiet_bit = std::uint64_t{1} << 62;
constexpr std::uint16_t fsw_invalid = 1u << 0, fsw_error_summary = 1u << 7;
constexpr std::uint16_t fsw_c0 = 1u << 8, fsw_c1 = 1u << 9, fsw_c2 = 1u << 10;
constexpr std::uint16_t fsw_c3 = 1u << 14, fsw_busy = 1u << 15;
constexpr std::uint16_t fcw_invalid_mask = 1u << 0;
constexpr std::uint32_t eflags_cf = 1u << 0, eflags_pf = 1u << 2, eflags_af = 1u << 4;
constexpr std::uint32_t eflags_zf = 1u << 6, eflags_sf = 1u << 7, eflags_of = 1u << 11;
constexpr std::uint32_t eflags_compare_mask = eflags_cf | eflags_pf | eflags_af | eflags_zf | eflags_sf | eflags_of;

enum class Class : std::uint8_t { zero, finite, infinity, quiet_nan, signaling_nan, unsupported };
struct Decoded {
    Class kind = Class::unsupported;
    bool negative = false;
    std::uint16_t exponent = 0;
    std::uint64_t significand = 0;
};

Decoded decode(X87Binary80 value) noexcept {
    const auto exponent = static_cast<std::uint16_t>(value.sign_exponent & exponent_mask);
    const bool negative = (value.sign_exponent & sign_mask) != 0;
    const bool integer = (value.significand & integer_bit) != 0;
    if (exponent == exponent_mask) {
        if (!integer) return {Class::unsupported, negative, exponent, value.significand};
        if (value.significand == integer_bit) return {Class::infinity, negative, exponent, value.significand};
        return {(value.significand & quiet_bit) != 0 ? Class::quiet_nan : Class::signaling_nan,
                negative, exponent, value.significand};
    }
    if (exponent == 0) {
        if (value.significand == 0) return {Class::zero, negative, 0, 0};
        // Pseudo-denormals encode the same value as exponent field 1.
        return {Class::finite, negative, static_cast<std::uint16_t>(integer ? 1 : 0), value.significand};
    }
    if (!integer) return {Class::unsupported, negative, exponent, value.significand};
    return {Class::finite, negative, exponent, value.significand};
}

int compare_magnitude(const Decoded &left, const Decoded &right) noexcept {
    if (left.kind == Class::zero) return right.kind == Class::zero ? 0 : -1;
    if (right.kind == Class::zero) return 1;
    const int left_top = static_cast<int>(left.exponent) - 16383 - 63 +
                         (63 - static_cast<int>(std::countl_zero(left.significand)));
    const int right_top = static_cast<int>(right.exponent) - 16383 - 63 +
                          (63 - static_cast<int>(std::countl_zero(right.significand)));
    if (left_top != right_top) return left_top < right_top ? -1 : 1;
    const auto left_normalized = left.significand << std::countl_zero(left.significand);
    const auto right_normalized = right.significand << std::countl_zero(right.significand);
    return left_normalized < right_normalized ? -1 : left_normalized > right_normalized ? 1 : 0;
}

bool is_nan(Class kind) noexcept { return kind == Class::quiet_nan || kind == Class::signaling_nan; }
bool is_invalid_kind(Class kind, X87CompareKind operation) noexcept {
    if (kind == Class::unsupported || kind == Class::signaling_nan) return true;
    const bool unordered = operation == X87CompareKind::fucom || operation == X87CompareKind::fucomi;
    return !unordered && kind == Class::quiet_nan;
}

X87Relation compare_decoded(const Decoded &left, const Decoded &right) noexcept {
    if (left.kind == Class::zero && right.kind == Class::zero) return X87Relation::equal;
    if (left.negative != right.negative)
        return left.negative ? X87Relation::less : X87Relation::greater;
    int magnitude = 0;
    if (left.kind == Class::infinity || right.kind == Class::infinity) {
        magnitude = left.kind == right.kind ? 0 : left.kind == Class::infinity ? 1 : -1;
    } else {
        magnitude = compare_magnitude(left, right);
    }
    if (left.negative) magnitude = -magnitude;
    return magnitude < 0 ? X87Relation::less : magnitude > 0 ? X87Relation::greater : X87Relation::equal;
}

std::uint16_t with_condition_codes(std::uint16_t status, X87Relation relation) noexcept {
    status = static_cast<std::uint16_t>(status & ~(fsw_c0 | fsw_c1 | fsw_c2 | fsw_c3));
    switch (relation) {
    case X87Relation::less: status |= fsw_c0; break;
    case X87Relation::equal: status |= fsw_c3; break;
    case X87Relation::unordered: status |= fsw_c0 | fsw_c2 | fsw_c3; break;
    case X87Relation::greater: break;
    }
    return status;
}

std::uint32_t with_eflags(std::uint32_t flags, X87Relation relation) noexcept {
    flags &= ~eflags_compare_mask;
    switch (relation) {
    case X87Relation::less: flags |= eflags_cf; break;
    case X87Relation::equal: flags |= eflags_zf; break;
    case X87Relation::unordered: flags |= eflags_zf | eflags_pf | eflags_cf; break;
    case X87Relation::greater: break;
    }
    return flags;
}
} // namespace

X87StackState join_x87_stack_states(const X87StackState &left, const X87StackState &right) noexcept {
    X87StackState result;
    if (left.top == right.top) result.top = left.top;
    for (std::size_t i = 0; i < result.tags.size(); ++i)
        if (left.tags[i] == right.tags[i]) result.tags[i] = left.tags[i];
    return result;
}

X87StackState transfer_x87_stack_state(const X87StackState &input, const Instruction &instruction) noexcept {
    auto result = input;
    if (instruction.flow == FlowKind::call) return {};
    if (instruction.opcode == Opcode::opaque || instruction.opcode == Opcode::x86_opaque) return {};
    if (instruction.opcode != Opcode::x87) return result;
    const auto &name = instruction.mnemonic_override;
    if (name == "fldenv" || name == "frstor") {
        result = {};
        return result;
    }
    if (name == "fninit" || name == "finit" || name == "fnsave") {
        result.top = std::uint8_t{0};
        result.tags.fill(X87Tag::empty);
        return result;
    }
    if (name == "fincstp" || name == "fdecstp") {
        if (result.top) {
            const auto delta = name == "fincstp" ? 1 : 7;
            result.top = static_cast<std::uint8_t>((*result.top + delta) & 7);
        }
        return result;
    }
    const bool writes_tag = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
        [](RegisterOperand reg) { return reg.bank == RegisterBank::x87_tag; });
    if (writes_tag && !instruction.x87_stack_delta) result.tags.fill(std::nullopt);
    // Explicit ST destinations can change a value's tag class. Invalidate
    // those physical tags before applying any implicit push/pop transition.
    if (result.top) {
        const auto count = std::min(instruction.operands.size(), instruction.access.size());
        for (std::size_t i = 0; i < count; ++i) {
            if (instruction.access[i] == OperandAccess::read) continue;
            const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[i]);
            if (!reg || reg->bank != RegisterBank::x87 || reg->index >= 8) continue;
            result.tags[(*result.top + reg->index) & 7].reset();
        }
    }
    if (instruction.x87_stack_delta > 0) {
        for (int i = 0; result.top && i < instruction.x87_stack_delta; ++i) {
            result.top = static_cast<std::uint8_t>((*result.top + 7) & 7);
            std::optional<X87Tag> pushed_tag;
            const bool destination_empty = result.tags[*result.top] == X87Tag::empty;
            if (destination_empty) {
                if (name == "fldz") pushed_tag = X87Tag::zero;
                else if (name == "fld1" || name == "fldpi" || name == "fldl2e" || name == "fldln2" ||
                         name == "fldlg2" || name == "fldl2t") pushed_tag = X87Tag::valid;
                else if (name == "fld" && input.top && !instruction.operands.empty()) {
                    const auto *source = std::get_if<RegisterOperand>(&instruction.operands.front());
                    if (source && source->bank == RegisterBank::x87 && source->index < 8)
                        if (const auto source_tag = input.tags[(*input.top + source->index) & 7];
                            source_tag && *source_tag != X87Tag::empty)
                            pushed_tag = source_tag;
                }
            }
            // Unknown payloads stay unknown; a masked overflow can also
            // complete with a special indefinite value.
            result.tags[*result.top] = pushed_tag;
        }
    } else if (instruction.x87_stack_delta < 0) {
        for (int i = 0; result.top && i < -instruction.x87_stack_delta; ++i) {
            result.tags[*result.top] = X87Tag::empty;
            result.top = static_cast<std::uint8_t>((*result.top + 1) & 7);
        }
    }
    return result;
}

std::optional<std::uint8_t> x87_physical_register(const X87StackState &state,
                                                   std::uint8_t logical_st) noexcept {
    if (!state.top || logical_st >= 8) return {};
    return static_cast<std::uint8_t>((*state.top + logical_st) & 7);
}

std::optional<X87Relation> compare_x87_binary80(X87Binary80 left, X87Binary80 right) noexcept {
    const auto a = decode(left), b = decode(right);
    if (a.kind == Class::unsupported || b.kind == Class::unsupported || is_nan(a.kind) || is_nan(b.kind))
        return {};
    return compare_decoded(a, b);
}

std::optional<X87CompareResult> evaluate_x87_compare(const X87CompareRequest &request) noexcept {
    const auto left = decode(request.left), right = decode(request.right);
    const bool invalid = is_invalid_kind(left.kind, request.kind) || is_invalid_kind(right.kind, request.kind);
    const auto relation = (left.kind == Class::unsupported || right.kind == Class::unsupported ||
                           is_nan(left.kind) || is_nan(right.kind))
                              ? X87Relation::unordered
                              : compare_decoded(left, right);
    const bool masked = (request.control_word & fcw_invalid_mask) != 0;
    X87CompareResult result;
    result.relation = relation;
    // C1 is defined as zero for all four comparison forms, including an
    // unmasked invalid exception; C0/C2/C3 are retired below by form.
    result.status_word = static_cast<std::uint16_t>(request.status_word & ~fsw_c1);
    result.invalid_operation = invalid;

    if (invalid) result.status_word |= fsw_invalid;
    if (invalid && !masked) {
        result.status_word |= fsw_error_summary | fsw_busy;
        result.completed = false;
        if (request.kind == X87CompareKind::fcomi || request.kind == X87CompareKind::fucomi)
            result.eflags = request.eflags & ~(eflags_af | eflags_sf | eflags_of);
        return result;
    }

    const bool writes_eflags = request.kind == X87CompareKind::fcomi || request.kind == X87CompareKind::fucomi;
    if (writes_eflags)
        result.eflags = with_eflags(request.eflags, relation);
    else
        result.status_word = with_condition_codes(result.status_word, relation);
    return result;
}

} // namespace hexlab
