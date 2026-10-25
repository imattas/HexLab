#include "hexlab/decompiler/optimizer.hpp"
#include "hexlab/processors/riscv_semantics.hpp"

#include <algorithm>
#include <bit>
#include <charconv>
#include <iterator>
#include <map>
#include <new>
#include <set>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <stdexcept>

namespace hexlab::decompiler {
namespace {
using Key = std::tuple<unsigned, unsigned, unsigned, bool, std::uint32_t>;

Key key(RegisterOperand reg, std::uint32_t version) {
    return {static_cast<unsigned>(reg.bank), reg.index, reg.width, reg.high_byte, version};
}

std::uint64_t width_mask(std::uint16_t bits) {
    return bits >= 64 ? UINT64_MAX : ((std::uint64_t{1} << bits) - 1);
}

ExpressionPtr constant_expression(const ConstantValue &constant) {
    return std::make_shared<Expression>(Expression{constant.type, constant});
}

std::optional<ConstantValue> fold_unary(const UnaryValue &unary, ValueType result_type) {
    const auto *operand = unary.operand ? std::get_if<ConstantValue>(&unary.operand->value) : nullptr;
    if (!operand || !operand->type.bits || operand->type.bits > 64 ||
        !result_type.bits || result_type.bits > 64)
        return {};
    const auto source_mask = width_mask(operand->type.bits);
    const auto result_mask = width_mask(result_type.bits);
    if (unary.operation == "bitnot" && operand->type.kind == TypeKind::integer &&
        result_type == operand->type)
        return ConstantValue{~operand->value & result_mask, result_type};
    if (unary.operation == "not" && operand->type.kind == TypeKind::boolean && operand->type.bits == 1 &&
        result_type.kind == TypeKind::boolean && result_type.bits == 1 && operand->value <= 1)
        return ConstantValue{(operand->value & 1) == 0 ? 1u : 0u, result_type};
    if (unary.operation == "signbit" && operand->type.kind == TypeKind::integer &&
        result_type.kind == TypeKind::boolean && result_type.bits == 1)
        return ConstantValue{(operand->value & (std::uint64_t{1} << (operand->type.bits - 1))) != 0 ? 1u : 0u,
                             result_type};
    if (unary.operation == "parity8" && operand->type.kind == TypeKind::integer && operand->type.bits >= 8 &&
        result_type.kind == TypeKind::boolean && result_type.bits == 1)
        return ConstantValue{(std::popcount(static_cast<unsigned int>(operand->value & 0xff)) & 1) == 0 ? 1u : 0u,
                             result_type};

    const auto fixed_amount = [&](std::string_view prefix) -> std::optional<unsigned> {
        const std::string_view operation = unary.operation;
        if (!operation.starts_with(prefix) || operation.size() == prefix.size() || operation.size() > prefix.size() + 3)
            return {};
        unsigned amount = 0;
        const auto suffix = operation.substr(prefix.size());
        const auto parsed = std::from_chars(suffix.data(), suffix.data() + suffix.size(), amount);
        if (parsed.ec != std::errc{} || parsed.ptr != suffix.data() + suffix.size() || amount > 64)
            return {};
        return amount;
    };
    if (operand->type.kind == TypeKind::integer && result_type == operand->type) {
        for (const auto [prefix, operation] : {
                 std::pair<std::string_view, std::string_view>{"ror_", "ror"},
                 {"shl_", "shl"}, {"shr_", "shr"}, {"sar_", "sar"},
                 {"lsl_", "shl"}, {"lsr_", "shr"}, {"asr_", "sar"}}) {
            const auto amount = fixed_amount(prefix);
            if (!amount) continue;
            if (operation == "ror") {
                const auto shift = *amount % operand->type.bits;
                const auto value = operand->value & source_mask;
                const auto rotated = shift == 0 ? value :
                    ((value >> shift) | (value << (operand->type.bits - shift))) & source_mask;
                return ConstantValue{rotated, result_type};
            }
            if (*amount >= operand->type.bits) return {};
            const auto shift = *amount;
            const auto value = operand->value & source_mask;
            if (operation == "shl") return ConstantValue{(value << shift) & result_mask, result_type};
            if (operation == "shr") return ConstantValue{value >> shift, result_type};
            const bool negative = (value & (std::uint64_t{1} << (operand->type.bits - 1))) != 0;
            auto shifted = value >> shift;
            if (negative && shift) shifted |= source_mask ^ (source_mask >> shift);
            return ConstantValue{shifted & result_mask, result_type};
        }
    }
    if (unary.operation == "trunc32") return ConstantValue{operand->value & UINT32_MAX, result_type};
    if (unary.operation == "zext")
        return ConstantValue{operand->value & source_mask & result_mask, result_type};
    if (unary.operation == "sext") {
        auto value = operand->value & source_mask;
        const auto sign = std::uint64_t{1} << (operand->type.bits - 1);
        if (value & sign) value |= ~source_mask;
        return ConstantValue{value & result_mask, result_type};
    }
    return {};
}

std::optional<RiscvOpcode> riscv_m_opcode(const std::string &name) {
    if (name == "rvm_mul") return RiscvOpcode::mul;
    if (name == "rvm_mulh") return RiscvOpcode::mulh;
    if (name == "rvm_mulhsu") return RiscvOpcode::mulhsu;
    if (name == "rvm_mulhu") return RiscvOpcode::mulhu;
    if (name == "rvm_div") return RiscvOpcode::div;
    if (name == "rvm_divu") return RiscvOpcode::divu;
    if (name == "rvm_rem") return RiscvOpcode::rem;
    if (name == "rvm_remu") return RiscvOpcode::remu;
    if (name == "rvm_mulw") return RiscvOpcode::mulw;
    if (name == "rvm_divw") return RiscvOpcode::divw;
    if (name == "rvm_divuw") return RiscvOpcode::divuw;
    if (name == "rvm_remw") return RiscvOpcode::remw;
    if (name == "rvm_remuw") return RiscvOpcode::remuw;
    return {};
}
std::optional<ConstantValue> fold_binary(const BinaryValue &binary, ValueType result_type) {
    const auto *left = binary.left ? std::get_if<ConstantValue>(&binary.left->value) : nullptr;
    const auto *right = binary.right ? std::get_if<ConstantValue>(&binary.right->value) : nullptr;
    if (!left || !right || !left->type.bits || left->type.bits > 64 ||
        !right->type.bits || right->type.bits > 64 ||
        !result_type.bits || result_type.bits > 64)
        return {};
    const auto bits = left->type.bits;
    const auto a = left->value & width_mask(bits), b = right->value & width_mask(bits);
    const bool comparison = binary.operation == "eq" || binary.operation == "ne" || binary.operation == "ult" ||
        binary.operation == "uge" || binary.operation == "ule" || binary.operation == "ugt" || binary.operation == "slt" ||
        binary.operation == "sge" || binary.operation == "sle" || binary.operation == "sgt";
    if (comparison) {
        if (left->type.bits != right->type.bits) return {};
        const bool sign_a = ((a >> (bits - 1)) & 1) != 0, sign_b = ((b >> (bits - 1)) & 1) != 0;
        const bool signed_less = sign_a != sign_b ? sign_a : a < b;
        bool value = false;
        if (binary.operation == "eq") value = a == b;
        else if (binary.operation == "ne") value = a != b;
        else if (binary.operation == "ult") value = a < b;
        else if (binary.operation == "uge") value = a >= b;
        else if (binary.operation == "ule") value = a <= b;
        else if (binary.operation == "ugt") value = a > b;
        else if (binary.operation == "slt") value = signed_less;
        else if (binary.operation == "sge") value = !signed_less;
        else if (binary.operation == "sle") value = signed_less || a == b;
        else value = !signed_less && a != b;
        return ConstantValue{value ? 1u : 0u, result_type};
    }
    const auto result_bits = result_type.bits;
    const bool is_shift = binary.operation == "shl" || binary.operation == "shr" || binary.operation == "sar";
    if ((!is_shift && (left->type.bits != result_bits || right->type.bits != result_bits)) ||
        (is_shift && left->type.bits != result_bits)) return {};
    const auto mask = width_mask(result_bits);
    if (const auto m_opcode = riscv_m_opcode(binary.operation)) {
        const auto folded = evaluate_riscv_m_operation(*m_opcode, bits, left->value, right->value);
        if (folded) return ConstantValue{*folded & width_mask(bits), result_type};
        return {};
    }
    std::uint64_t value = 0;
    if (binary.operation == "add") value = left->value + right->value;
    else if (binary.operation == "sub") value = left->value - right->value;
    else if (binary.operation == "mul") value = left->value * right->value;
    else if (binary.operation == "and") value = left->value & right->value;
    else if (binary.operation == "or") value = left->value | right->value;
    else if (binary.operation == "xor") value = left->value ^ right->value;
    else if (binary.operation == "shl" || binary.operation == "shr" || binary.operation == "sar") {
        if (right->value >= bits) return {};
        const auto shift = static_cast<unsigned>(right->value);
        if (binary.operation == "shl") value = left->value << shift;
        else if (binary.operation == "shr") value = left->value >> shift;
        else {
            value = left->value & mask;
            const bool negative = (value & (std::uint64_t{1} << (bits - 1))) != 0;
            value >>= shift;
            if (negative && shift) value |= mask ^ (mask >> shift);
        }
    } else return {};
    return ConstantValue{value & mask, result_type};
}

using PureDefinitions = std::map<Key, ExpressionPtr>;
using SymbolicInputs = std::map<Key, std::pair<RegisterOperand, ValueType>>;

struct KnownBits {
    std::uint16_t width = 0;
    std::uint64_t zero = 0;
    std::uint64_t one = 0;
};

std::optional<KnownBits> evaluate_known_bits(const ExpressionPtr &expression,
                                             std::size_t &work, std::size_t depth = 0) {
    constexpr std::size_t max_proof_work = 65'536;
    if (!expression || depth > 32 || ++work > max_proof_work ||
        !expression->type.bits || expression->type.bits > 64)
        return {};
    const auto width = expression->type.bits;
    const auto mask = width_mask(width);
    if (const auto *constant = std::get_if<ConstantValue>(&expression->value)) {
        if (constant->type != expression->type) return {};
        const auto value = constant->value & mask;
        return KnownBits{width, (~value) & mask, value};
    }
    if (const auto *reg = std::get_if<RegisterValue>(&expression->value)) {
        if (!reg->version || reg->reg.width != width) return {};
        return KnownBits{width, 0, 0};
    }
    if (const auto *unary = std::get_if<UnaryValue>(&expression->value)) {
        const auto operand = evaluate_known_bits(unary->operand, work, depth + 1);
        if (!operand || !operand->width) return {};
        const auto source_mask = width_mask(operand->width);
        const auto result_mask = mask;
        if (unary->operation == "bitnot" && operand->width == width &&
            expression->type.kind == TypeKind::integer && unary->operand->type.kind == TypeKind::integer)
            return KnownBits{width, operand->one & result_mask, operand->zero & result_mask};
        if (unary->operation == "not" && operand->width == 1 && width == 1 &&
            expression->type.kind == TypeKind::boolean && unary->operand->type.kind == TypeKind::boolean)
            return KnownBits{1, operand->one & 1, operand->zero & 1};
        if (unary->operation == "signbit" && unary->operand->type.kind == TypeKind::integer &&
            expression->type.kind == TypeKind::boolean && width == 1) {
            const auto sign = std::uint64_t{1} << (operand->width - 1);
            if (operand->one & sign) return KnownBits{1, 0, 1};
            if (operand->zero & sign) return KnownBits{1, 1, 0};
            return KnownBits{1, 0, 0};
        }
        if (unary->operation == "parity8" && unary->operand->type.kind == TypeKind::integer &&
            operand->width >= 8 &&
            expression->type.kind == TypeKind::boolean && width == 1) {
            if (((operand->zero | operand->one) & 0xff) == 0xff) {
                const auto value = operand->one & 0xff;
                const bool even = (std::popcount(static_cast<unsigned>(value)) & 1) == 0;
                return KnownBits{1, even ? 0u : 1u, even ? 1u : 0u};
            }
            return KnownBits{1, 0, 0};
        }
        if ((unary->operation == "zext" || unary->operation == "sext" || unary->operation == "trunc32") &&
            expression->type.kind == TypeKind::integer && unary->operand->type.kind == TypeKind::integer) {
            if (unary->operation == "zext" && width >= operand->width) {
                const auto high = result_mask & ~source_mask;
                return KnownBits{width, (operand->zero & source_mask) | high, operand->one & source_mask};
            }
            if (unary->operation == "sext" && width >= operand->width) {
                const auto sign = std::uint64_t{1} << (operand->width - 1);
                const auto high = result_mask & ~source_mask;
                auto zero = operand->zero & source_mask;
                auto one = operand->one & source_mask;
                if (operand->zero & sign) zero |= high;
                if (operand->one & sign) one |= high;
                return KnownBits{width, zero, one};
            }
            if (unary->operation == "trunc32" && width == 32 && operand->width >= width)
                return KnownBits{width, operand->zero & result_mask, operand->one & result_mask};
        }
        // The constant folder spells fixed-count unary shifts as an operation
        // suffix. Preserve only facts that are independent of unknown bits.
        const auto fixed_amount = [&](std::string_view prefix) -> std::optional<unsigned> {
            if (!std::string_view(unary->operation).starts_with(prefix) || unary->operation.size() <= prefix.size() ||
                unary->operation.size() > prefix.size() + 3) return {};
            unsigned amount = 0;
            const auto suffix = std::string_view(unary->operation).substr(prefix.size());
            const auto parsed = std::from_chars(suffix.data(), suffix.data() + suffix.size(), amount);
            if (parsed.ec != std::errc{} || parsed.ptr != suffix.data() + suffix.size()) return {};
            return amount;
        };
        if (operand->width == width && expression->type.kind == TypeKind::integer &&
            unary->operand->type.kind == TypeKind::integer) {
            for (const auto [prefix, kind] : {
                     std::pair<std::string_view, std::string_view>{"shl_", "shl"},
                     {"shr_", "shr"}, {"sar_", "sar"}, {"lsl_", "shl"},
                     {"lsr_", "shr"}, {"asr_", "sar"}}) {
                const auto amount = fixed_amount(prefix);
                if (!amount || *amount >= width) continue;
                const auto shift = *amount;
                if (kind == "shl") {
                    const auto inserted = shift ? ((std::uint64_t{1} << shift) - 1) : 0;
                    return KnownBits{width, ((operand->zero << shift) | inserted) & mask,
                                     (operand->one << shift) & mask};
                }
                const auto inserted = mask ^ (mask >> shift);
                auto zero = operand->zero >> shift;
                auto one = operand->one >> shift;
                if (kind == "shr") zero |= inserted;
                else {
                    const auto sign = std::uint64_t{1} << (width - 1);
                    if (operand->zero & sign) zero |= inserted;
                    if (operand->one & sign) one |= inserted;
                }
                return KnownBits{width, zero & mask, one & mask};
            }
        }
        return {};
    }
    if (const auto *binary = std::get_if<BinaryValue>(&expression->value)) {
        const auto left = evaluate_known_bits(binary->left, work, depth + 1);
        const auto right = evaluate_known_bits(binary->right, work, depth + 1);
        if (!left || !right) return {};
        const auto left_type = binary->left->type;
        const auto right_type = binary->right->type;
        const bool integers = left_type.kind == TypeKind::integer && right_type.kind == TypeKind::integer;
        const auto boolean = [](bool value) {
            return KnownBits{1, value ? 0u : 1u, value ? 1u : 0u};
        };
        const bool comparison = binary->operation == "eq" || binary->operation == "ne" ||
            binary->operation == "ult" || binary->operation == "uge" || binary->operation == "ule" ||
            binary->operation == "ugt" || binary->operation == "slt" || binary->operation == "sge" ||
            binary->operation == "sle" || binary->operation == "sgt";
        if (comparison && expression->type.kind == TypeKind::boolean && expression->type.bits == 1 &&
            left->width == right->width && (integers || (left_type.kind == TypeKind::boolean &&
                                                          right_type.kind == TypeKind::boolean))) {
            const auto common_mask = width_mask(left->width);
            const auto conflict = (left->one & right->zero) | (left->zero & right->one);
            std::optional<bool> proven;
            if (binary->operation == "eq" || binary->operation == "ne") {
                if (conflict) proven = binary->operation == "ne";
                else if (((left->zero | left->one) & common_mask) == common_mask &&
                         ((right->zero | right->one) & common_mask) == common_mask) {
                    const bool equal = left->one == right->one;
                    proven = binary->operation == "eq" ? equal : !equal;
                }
            } else if (integers) {
                auto l = *left, r = *right;
                const bool signed_compare = binary->operation[0] == 's';
                if (signed_compare) {
                    const auto sign = std::uint64_t{1} << (left->width - 1);
                    const auto flip_sign = [sign](KnownBits facts) {
                        const auto was_zero = facts.zero & sign;
                        const auto was_one = facts.one & sign;
                        facts.zero = (facts.zero & ~sign) | was_one;
                        facts.one = (facts.one & ~sign) | was_zero;
                        return facts;
                    };
                    l = flip_sign(l); r = flip_sign(r);
                }
                const auto l_min = l.one, l_max = common_mask & ~l.zero;
                const auto r_min = r.one, r_max = common_mask & ~r.zero;
                if (binary->operation == "ult" || binary->operation == "slt") {
                    if (l_max < r_min) proven = true;
                    else if (l_min >= r_max) proven = false;
                } else if (binary->operation == "uge" || binary->operation == "sge") {
                    if (l_min >= r_max) proven = true;
                    else if (l_max < r_min) proven = false;
                } else if (binary->operation == "ule" || binary->operation == "sle") {
                    if (l_max <= r_min) proven = true;
                    else if (l_min > r_max) proven = false;
                } else if (binary->operation == "ugt" || binary->operation == "sgt") {
                    if (l_min > r_max) proven = true;
                    else if (l_max <= r_min) proven = false;
                }
            }
            return proven ? std::optional<KnownBits>(boolean(*proven))
                          : std::optional<KnownBits>(KnownBits{1, 0, 0});
        }
        if (!integers || left->width != right->width || left->width != width ||
            expression->type.kind != TypeKind::integer) return {};
        if (binary->operation == "and")
            return KnownBits{width, (left->zero | right->zero) & mask, (left->one & right->one) & mask};
        if (binary->operation == "or")
            return KnownBits{width, (left->zero & right->zero) & mask, (left->one | right->one) & mask};
        if (binary->operation == "xor") {
            return KnownBits{width,
                ((left->zero & right->zero) | (left->one & right->one)) & mask,
                ((left->one & right->zero) | (left->zero & right->one)) & mask};
        }
        if ((binary->operation == "add" || binary->operation == "sub") &&
            binary->left->type == expression->type && binary->right->type == expression->type) {
            // Propagate bit facts through modular arithmetic. Each bit's
            // operand and carry possibilities are over-approximated, so a
            // fact is emitted only when every combination agrees. In
            // particular, no overflow or signed-range assumptions are made.
            auto add_right = *right;
            std::uint8_t carries = 1; // bit 0 means carry 0 is possible.
            if (binary->operation == "sub") {
                add_right.zero = right->one;
                add_right.one = right->zero;
                carries = 2; // two's-complement subtraction starts with +1.
            }
            std::uint64_t known_zero = 0, known_one = 0;
            for (std::uint16_t bit = 0; bit < width; ++bit) {
                const auto bit_mask = std::uint64_t{1} << bit;
                const bool a_zero = (left->zero & bit_mask) != 0 ||
                    ((left->zero | left->one) & bit_mask) == 0;
                const bool a_one = (left->one & bit_mask) != 0 ||
                    ((left->zero | left->one) & bit_mask) == 0;
                const bool b_zero = (add_right.zero & bit_mask) != 0 ||
                    ((add_right.zero | add_right.one) & bit_mask) == 0;
                const bool b_one = (add_right.one & bit_mask) != 0 ||
                    ((add_right.zero | add_right.one) & bit_mask) == 0;
                bool output_zero = false, output_one = false;
                std::uint8_t next_carries = 0;
                for (unsigned a = 0; a <= 1; ++a) {
                    if (a ? !a_one : !a_zero) continue;
                    for (unsigned b = 0; b <= 1; ++b) {
                        if (b ? !b_one : !b_zero) continue;
                        for (unsigned carry = 0; carry <= 1; ++carry) {
                            if ((carries & (std::uint8_t{1} << carry)) == 0) continue;
                            const auto sum = a + b + carry;
                            (sum & 1u) ? output_one = true : output_zero = true;
                            next_carries |= std::uint8_t{1} << (sum >> 1);
                        }
                    }
                }
                if (output_zero && !output_one) known_zero |= bit_mask;
                if (output_one && !output_zero) known_one |= bit_mask;
                carries = next_carries;
            }
            return KnownBits{width, known_zero & mask, known_one & mask};
        }
        const bool shift = binary->operation == "shl" || binary->operation == "shr" || binary->operation == "sar";
        const auto shift_mask = width_mask(right->width);
        if (shift && (((right->zero | right->one) & shift_mask) == shift_mask)) {
            const auto amount = right->one;
            if (amount >= width) return {};
            if (binary->operation == "shl") {
                const auto inserted = amount ? ((std::uint64_t{1} << amount) - 1) : 0;
                return KnownBits{width, ((left->zero << amount) | inserted) & mask,
                                 (left->one << amount) & mask};
            }
            const auto inserted = mask ^ (mask >> amount);
            auto zero = left->zero >> amount, one = left->one >> amount;
            if (binary->operation == "shr") zero |= inserted;
            else {
                const auto sign = std::uint64_t{1} << (width - 1);
                if (left->zero & sign) zero |= inserted;
                if (left->one & sign) one |= inserted;
            }
            return KnownBits{width, zero & mask, one & mask};
        }
        return {};
    }
    return {};
}

bool pure_expression_tree(const ExpressionPtr &expression, std::size_t &nodes, std::size_t depth) {
    if (!expression) return true;
    if (++nodes > 512 || depth > 32) return false;
    if (std::holds_alternative<RegisterValue>(expression->value) ||
        std::holds_alternative<ConstantValue>(expression->value)) return true;
    if (const auto *unary = std::get_if<UnaryValue>(&expression->value))
        return pure_expression_tree(unary->operand, nodes, depth + 1);
    if (const auto *binary = std::get_if<BinaryValue>(&expression->value))
        return pure_expression_tree(binary->left, nodes, depth + 1) &&
               pure_expression_tree(binary->right, nodes, depth + 1);
    return false;
}

ExpressionPtr expand_pure_ssa(const ExpressionPtr &expression, const PureDefinitions &definitions,
                              std::set<Key> &active, SymbolicInputs &inputs,
                              std::size_t &nodes, std::size_t depth) {
    constexpr std::size_t max_nodes = 512;
    constexpr std::size_t max_depth = 32;
    if (!expression || ++nodes > max_nodes || depth > max_depth) return {};
    if (const auto *reg = std::get_if<RegisterValue>(&expression->value)) {
        if (!reg->version || !reg->reg.width || reg->reg.width != expression->type.bits) return {};
        const auto id = key(reg->reg, *reg->version);
        const auto definition = definitions.find(id);
        if (definition == definitions.end()) {
            const auto [found, inserted] = inputs.emplace(id, std::pair{reg->reg, expression->type});
            if (!inserted && found->second.second != expression->type) return {};
            return expression;
        }
        if (!active.insert(id).second) return {};
        auto expanded = expand_pure_ssa(definition->second, definitions, active, inputs, nodes, depth + 1);
        active.erase(id);
        return expanded;
    }
    if (const auto *constant = std::get_if<ConstantValue>(&expression->value))
        return constant->type == expression->type ? expression : ExpressionPtr{};
    if (const auto *unary = std::get_if<UnaryValue>(&expression->value)) {
        auto operand = expand_pure_ssa(unary->operand, definitions, active, inputs, nodes, depth + 1);
        if (!operand) return {};
        return std::make_shared<Expression>(Expression{expression->type, UnaryValue{unary->operation, operand}});
    }
    if (const auto *binary = std::get_if<BinaryValue>(&expression->value)) {
        auto left = expand_pure_ssa(binary->left, definitions, active, inputs, nodes, depth + 1);
        auto right = expand_pure_ssa(binary->right, definitions, active, inputs, nodes, depth + 1);
        if (!left || !right) return {};
        return std::make_shared<Expression>(Expression{expression->type,
                                                        BinaryValue{binary->operation, left, right}});
    }
    // Memory, unknown and named-variable leaves are outside the proof domain.
    return {};
}

std::optional<ConstantValue> evaluate_symbolic(const ExpressionPtr &expression,
                                                const std::map<Key, ConstantValue> &inputs) {
    if (!expression) return {};
    if (const auto *constant = std::get_if<ConstantValue>(&expression->value))
        return constant->type == expression->type ? std::optional<ConstantValue>(*constant) : std::nullopt;
    if (const auto *reg = std::get_if<RegisterValue>(&expression->value)) {
        if (!reg->version) return {};
        const auto found = inputs.find(key(reg->reg, *reg->version));
        return found != inputs.end() ? std::optional<ConstantValue>(found->second) : std::nullopt;
    }
    if (const auto *unary = std::get_if<UnaryValue>(&expression->value)) {
        auto operand = evaluate_symbolic(unary->operand, inputs);
        if (!operand) return {};
        auto value = constant_expression(*operand);
        return fold_unary(UnaryValue{unary->operation, value}, expression->type);
    }
    if (const auto *binary = std::get_if<BinaryValue>(&expression->value)) {
        auto left = evaluate_symbolic(binary->left, inputs);
        auto right = evaluate_symbolic(binary->right, inputs);
        if (!left || !right) return {};
        return fold_binary(BinaryValue{binary->operation, constant_expression(*left), constant_expression(*right)},
                           expression->type);
    }
    return {};
}

std::optional<bool> prove_small_boolean(const ExpressionPtr &predicate,
                                       const PureDefinitions &definitions,
                                       std::size_t &work) {
    if (!predicate || predicate->type.kind != TypeKind::boolean || predicate->type.bits != 1) return {};
    SymbolicInputs symbols;
    std::set<Key> active;
    std::size_t nodes = 0;
    const auto expanded = expand_pure_ssa(predicate, definitions, active, symbols, nodes, 0);
    if (!expanded) return {};
    const auto known = evaluate_known_bits(expanded, work);
    if (known && known->width == 1 &&
        (known->one & 1) != 0)
        return true;
    if (known && known->width == 1 &&
        (known->zero & 1) != 0)
        return false;
    unsigned input_bits = 0;
    for (const auto &[id, symbol] : symbols) {
        (void)id;
        const auto &reg = symbol.first;
        if (reg.width > 12 || input_bits + reg.width > 12) return {};
        input_bits += reg.width;
    }
    const std::size_t valuations = std::size_t{1} << input_bits;
    if (work + valuations > 65'536) return {};
    work += valuations;
    std::optional<bool> common;
    for (std::size_t assignment = 0; assignment < valuations; ++assignment) {
        std::map<Key, ConstantValue> values;
        unsigned offset = 0;
        for (const auto &[id, symbol] : symbols) {
            const auto &[reg, type] = symbol;
            const auto mask = width_mask(reg.width);
            values.emplace(id, ConstantValue{(assignment >> offset) & mask,
                                             type});
            offset += reg.width;
        }
        const auto result = evaluate_symbolic(expanded, values);
        if (!result || result->type.kind != TypeKind::boolean || result->type.bits != 1 || result->value > 1)
            return {};
        const bool current = result->value != 0;
        if (common && *common != current) return {};
        common = current;
    }
    return common;
}

ExpressionPtr simplify_expression(const ExpressionPtr &expression,
                                  const std::map<Key, ConstantValue> &constants,
                                  bool allow_register_propagation, bool require_matching_type = false) {
    if (!expression) return {};
    auto copy = std::make_shared<Expression>(*expression);
    if (const auto *reg = std::get_if<RegisterValue>(&copy->value)) {
        if (allow_register_propagation && reg->version) {
            const auto found = constants.find(key(reg->reg, *reg->version));
            if (found != constants.end() && (!require_matching_type || found->second.type == copy->type))
                return constant_expression(found->second);
        }
        return copy;
    }
    if (auto *unary = std::get_if<UnaryValue>(&copy->value)) {
        unary->operand = simplify_expression(unary->operand, constants, allow_register_propagation, require_matching_type);
        if (auto folded = fold_unary(*unary, copy->type)) return constant_expression(*folded);
        return copy;
    }
    if (auto *binary = std::get_if<BinaryValue>(&copy->value)) {
        binary->left = simplify_expression(binary->left, constants, allow_register_propagation, require_matching_type);
        binary->right = simplify_expression(binary->right, constants, allow_register_propagation, require_matching_type);
        if (auto folded = fold_binary(*binary, copy->type)) return constant_expression(*folded);
        return copy;
    }
    return copy;
}

void simplify_statement(Statement &statement, const std::map<Key, ConstantValue> &constants,
                        bool allow_register_propagation, bool require_matching_type = false) {
    std::visit([&](auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, Assign>)
            value.value = simplify_expression(value.value, constants, allow_register_propagation, require_matching_type);
        else if constexpr (std::is_same_v<T, Store>) {
            value.address = simplify_expression(value.address, constants, allow_register_propagation, require_matching_type);
            value.value = simplify_expression(value.value, constants, allow_register_propagation, require_matching_type);
        } else if constexpr (std::is_same_v<T, Call>)
            value.indirect_target = simplify_expression(value.indirect_target, constants, allow_register_propagation, require_matching_type);
        else if constexpr (std::is_same_v<T, Branch>) {
            value.predicate = simplify_expression(value.predicate, constants, allow_register_propagation, require_matching_type);
            value.indirect_target = simplify_expression(value.indirect_target, constants, allow_register_propagation, require_matching_type);
        }
        else if constexpr (std::is_same_v<T, Return>)
            value.value = simplify_expression(value.value, constants, allow_register_propagation, require_matching_type);
        else if constexpr (std::is_same_v<T, Intrinsic>) {
            for (auto &operand : value.operands)
                operand = simplify_expression(operand, constants, allow_register_propagation, require_matching_type);
            for (auto &output : value.register_output_values)
                output = simplify_expression(output, constants, allow_register_propagation, require_matching_type);
        }
    }, statement);
}

struct SsaDefinitionRef {
    const LiftedBlock::Phi *phi = nullptr;
    const Assign *assignment = nullptr;
    bool phi_inputs_complete = false;
};

struct LoopConstantValue {
    enum class Kind { unknown, cycle, constant } kind = Kind::unknown;
    ConstantValue value;
    bool contains_cycle = false;
};

// Resolve only constants and exact register copies. A cycle is kept distinct
// from an unknown input so a loop phi can ignore its own back-edge after all
// concrete entry values prove the same constant. Arbitrary expressions,
// memory reads, and unsupported definitions remain unknown.
class LoopConstantResolver {
  public:
    explicit LoopConstantResolver(const std::map<Key, SsaDefinitionRef> &definitions)
        : definitions_(definitions) {}

    LoopConstantValue resolve(const Key &version) {
        if (++work_ > max_work_ || visiting_.size() >= max_depth_) {
            exhausted_ = true;
            return {};
        }
        if (const auto cached = memo_.find(version); cached != memo_.end()) return cached->second;
        if (visiting_.contains(version)) return {LoopConstantValue::Kind::cycle, {}, true};
        const auto definition = definitions_.find(version);
        if (definition == definitions_.end()) return {};

        visiting_.insert(version);
        LoopConstantValue result;
        if (definition->second.assignment) {
            const auto &expression = definition->second.assignment->value;
            if (expression) {
                if (const auto *constant = std::get_if<ConstantValue>(&expression->value);
                    constant && constant->type == expression->type &&
                    expression->type.bits == definition->second.assignment->destination.width)
                    result = {LoopConstantValue::Kind::constant, *constant};
                else if (const auto *copy = std::get_if<RegisterValue>(&expression->value);
                         copy && copy->version && copy->reg.width == expression->type.bits &&
                         expression->type.bits == definition->second.assignment->destination.width) {
                    result = resolve(key(copy->reg, *copy->version));
                    if (result.kind == LoopConstantValue::Kind::constant && result.value.type != expression->type)
                        result = {};
                }
            }
        } else if (definition->second.phi && definition->second.phi_inputs_complete) {
            std::optional<ConstantValue> common;
            bool unknown_input = false;
            bool concrete_input = false;
            bool saw_cycle = false;
            for (const auto &phi_input : definition->second.phi->inputs) {
                const auto value = resolve(key(definition->second.phi->destination, phi_input.version));
                if (value.kind == LoopConstantValue::Kind::cycle) {
                    saw_cycle = true;
                    continue;
                }
                if (value.kind != LoopConstantValue::Kind::constant) {
                    unknown_input = true;
                    saw_cycle = saw_cycle || value.contains_cycle;
                    break;
                }
                concrete_input = true;
                saw_cycle = saw_cycle || value.contains_cycle;
                if (!common) common = value.value;
                else if (*common != value.value) {
                    unknown_input = true;
                    break;
                }
            }
            if (!unknown_input && concrete_input && common &&
                common->type.bits == definition->second.phi->destination.width)
                result = {LoopConstantValue::Kind::constant, *common, saw_cycle};
            else if (!unknown_input && !concrete_input && saw_cycle)
                result = {LoopConstantValue::Kind::cycle, {}, true};
            else result.contains_cycle = saw_cycle;
        }
        visiting_.erase(version);
        // Do not memoize a context-dependent cycle. A later root resolution
        // may have a concrete entry value available for that same version.
        if (result.kind != LoopConstantValue::Kind::cycle && !result.contains_cycle)
            memo_.emplace(version, result);
        return result;
    }

    bool exhausted() const noexcept { return exhausted_; }

  private:
    static constexpr std::size_t max_work_ = 1'000'000;
    static constexpr std::size_t max_depth_ = 128;
    const std::map<Key, SsaDefinitionRef> &definitions_;
    std::map<Key, LoopConstantValue> memo_;
    std::set<Key> visiting_;
    std::size_t work_ = 0;
    bool exhausted_ = false;
};

// Sparse conditional constant propagation keeps only values proved from
// executable CFG edges. Unknown definitions are distinct from values proven
// to be non-constant so cycles can settle before a branch is conservatively
// opened in both directions.
struct SccpValue {
    enum class Kind { unknown, constant, overdefined } kind = Kind::unknown;
    ConstantValue constant;
};

using SccpEdge = std::pair<BlockId, std::size_t>;

struct SccpBudgetExceeded {};

struct SccpBudget {
    std::size_t work = 0;
    void tick(std::size_t amount = 1) {
        constexpr std::size_t limit = 8'000'000;
        if (amount > limit - work)
            throw SccpBudgetExceeded{};
        work += amount;
    }
};

SccpValue sccp_overdefined() { return {SccpValue::Kind::overdefined, {}}; }

SccpValue sccp_join(SccpValue left, const SccpValue &right) {
    if (right.kind == SccpValue::Kind::unknown) return left;
    if (left.kind == SccpValue::Kind::unknown) return right;
    if (left.kind == SccpValue::Kind::overdefined || right.kind == SccpValue::Kind::overdefined)
        return sccp_overdefined();
    return left.constant == right.constant ? left : sccp_overdefined();
}

bool sccp_merge(std::map<Key, SccpValue> &values, const Key &version, const SccpValue &incoming) {
    if (incoming.kind == SccpValue::Kind::unknown) return false;
    auto &current = values[version];
    auto joined = sccp_join(current, incoming);
    if (joined.kind == current.kind &&
        (joined.kind != SccpValue::Kind::constant || joined.constant == current.constant))
        return false;
    current = std::move(joined);
    return true;
}

SccpValue sccp_constant(const Expression &expression, const ConstantValue &constant) {
    if (constant.type != expression.type || !constant.type.bits || constant.type.bits > 64 ||
        (constant.value & ~width_mask(constant.type.bits)) != 0 ||
        (constant.type.kind == TypeKind::boolean && (constant.type.bits != 1 || constant.value > 1)))
        return sccp_overdefined();
    return {SccpValue::Kind::constant, constant};
}

SccpValue sccp_evaluate(const ExpressionPtr &expression, const std::map<Key, SccpValue> &values,
                        const std::set<Key> &definitions, SccpBudget &budget, std::size_t depth = 0) {
    budget.tick();
    if (!expression || depth > 128) return sccp_overdefined();
    if (const auto *constant = std::get_if<ConstantValue>(&expression->value))
        return sccp_constant(*expression, *constant);
    if (const auto *reg = std::get_if<RegisterValue>(&expression->value)) {
        if (!reg->version || !reg->reg.width || reg->reg.width != expression->type.bits)
            return sccp_overdefined();
        const auto id = key(reg->reg, *reg->version);
        if (!definitions.contains(id)) return sccp_overdefined();
        const auto found = values.find(id);
        return found == values.end() ? SccpValue{} : found->second;
    }
    if (const auto *unary = std::get_if<UnaryValue>(&expression->value)) {
        const auto operand = sccp_evaluate(unary->operand, values, definitions, budget, depth + 1);
        if (operand.kind == SccpValue::Kind::overdefined) return operand;
        if (operand.kind == SccpValue::Kind::unknown) return {};
        const auto folded = fold_unary(UnaryValue{unary->operation, constant_expression(operand.constant)},
                                       expression->type);
        return folded ? sccp_constant(*expression, *folded) : sccp_overdefined();
    }
    if (const auto *binary = std::get_if<BinaryValue>(&expression->value)) {
        const auto left = sccp_evaluate(binary->left, values, definitions, budget, depth + 1);
        const auto right = sccp_evaluate(binary->right, values, definitions, budget, depth + 1);
        if (left.kind == SccpValue::Kind::overdefined || right.kind == SccpValue::Kind::overdefined)
            return sccp_overdefined();
        if (left.kind == SccpValue::Kind::unknown || right.kind == SccpValue::Kind::unknown)
            return {};
        const auto folded = fold_binary(
            BinaryValue{binary->operation, constant_expression(left.constant), constant_expression(right.constant)},
            expression->type);
        return folded ? sccp_constant(*expression, *folded) : sccp_overdefined();
    }
    // Loads, unknown values, and named variables are not constant facts.
    return sccp_overdefined();
}

struct SccpBranchEdges {
    std::size_t on_true = 0;
    std::size_t on_false = 0;
};

std::optional<SccpBranchEdges> sccp_branch_edges(const LiftedBlock &block, const Branch &branch) {
    if (block.instructions.empty() || !branch.true_target || !branch.false_target ||
        *branch.true_target == *branch.false_target ||
        branch.indirect_target || branch.delay_slot_snapshot_block || branch.delay_slot_snapshot_instruction ||
        branch.annuls_delay_slot_on_false || block.successors.size() != 2)
        return {};
    std::optional<std::size_t> on_true, on_false;
    for (std::size_t index = 0; index < block.successors.size(); ++index) {
        const auto &edge = block.successors[index];
        if (edge.kind == BlockEdgeKind::conditional_true && edge.target == branch.true_target) {
            if (on_true) return {};
            on_true = index;
        } else if ((edge.kind == BlockEdgeKind::conditional_false || edge.kind == BlockEdgeKind::fallthrough) &&
                   edge.target == branch.false_target) {
            if (on_false) return {};
            on_false = index;
        }
    }
    if (!on_true || !on_false || *on_true == *on_false) return {};
    return SccpBranchEdges{*on_true, *on_false};
}

Result<LiftedFunction> sparse_conditional_constants(const LiftedFunction &input) {
    try {
        std::map<BlockId, std::size_t> block_index;
        std::vector<std::size_t> entries;
        std::set<Key> definitions;
        std::set<Key> nonconstant_outputs;
        if (input.blocks.size() > 1'000'000) return input;
        std::size_t total_items = input.blocks.size();
        for (std::size_t index = 0; index < input.blocks.size(); ++index) {
            const auto &block = input.blocks[index];
            if (!block_index.emplace(block.id, index).second)
                return Error{ErrorCode::invalid_argument, "Sparse constant propagation found duplicate block IDs"};
            if (block.begin == input.entry) entries.push_back(index);
            if (block.phis.size() > 1'000'000 - total_items)
                return input;
            total_items += block.phis.size();
            for (const auto &phi : block.phis)
                if (!definitions.insert(key(phi.destination, phi.version)).second)
                    return Error{ErrorCode::invalid_argument, "SSA function contains duplicate definitions"};
            if (block.instructions.size() > 1'000'000 - total_items)
                return input;
            total_items += block.instructions.size();
            for (const auto &instruction : block.instructions) {
                if (const auto *assignment = std::get_if<Assign>(&instruction.statement);
                    assignment && assignment->destination_version &&
                    !definitions.insert(key(assignment->destination, *assignment->destination_version)).second)
                    return Error{ErrorCode::invalid_argument, "SSA function contains duplicate definitions"};
                if (const auto *call = std::get_if<Call>(&instruction.statement)) {
                    for (std::size_t i = 0; i < std::min(call->register_writes.size(), call->register_output_versions.size()); ++i)
                        nonconstant_outputs.insert(key(call->register_writes[i], call->register_output_versions[i]));
                    if (call->return_register && call->return_version)
                        nonconstant_outputs.insert(key(*call->return_register, *call->return_version));
                } else if (const auto *intrinsic = std::get_if<Intrinsic>(&instruction.statement)) {
                    for (std::size_t i = 0; i < std::min(intrinsic->register_writes.size(), intrinsic->register_output_versions.size()); ++i)
                        nonconstant_outputs.insert(key(intrinsic->register_writes[i], intrinsic->register_output_versions[i]));
                }
            }
        }
        for (const auto &version : nonconstant_outputs)
            if (definitions.contains(version))
                return Error{ErrorCode::invalid_argument, "SSA output version has more than one definition"};
        if (entries.size() != 1 || input.blocks.empty()) return input;

        SccpBudget budget;
        std::set<BlockId> structural_reachable;
        std::vector<BlockId> structural_pending{input.blocks[entries.front()].id};
        while (!structural_pending.empty()) {
            budget.tick();
            const auto id = structural_pending.back();
            structural_pending.pop_back();
            if (!structural_reachable.insert(id).second) continue;
            const auto found = block_index.find(id);
            if (found == block_index.end()) continue;
            for (const auto &edge : input.blocks[found->second].successors) {
                budget.tick();
                if (edge.block && block_index.contains(*edge.block)) structural_pending.push_back(*edge.block);
            }
        }
        std::map<Key, SccpValue> values;
        for (const auto &version : nonconstant_outputs) values.emplace(version, sccp_overdefined());
        std::set<BlockId> reachable{input.blocks[entries.front()].id};
        std::set<SccpEdge> feasible_edges;
        std::map<BlockId, std::set<BlockId>> feasible_predecessors;
        std::set<BlockId> forced_unknown_branches;
        auto mark_edge = [&](const LiftedBlock &block, std::size_t edge_index, bool &changed) {
            if (!feasible_edges.insert({block.id, edge_index}).second) return;
            changed = true;
            const auto &edge = block.successors[edge_index];
            if (edge.block && block_index.contains(*edge.block)) {
                feasible_predecessors[*edge.block].insert(block.id);
                if (reachable.insert(*edge.block).second) changed = true;
            }
        };
        auto run_to_fixed_point = [&]() {
            bool changed = true;
            while (changed) {
                changed = false;
                for (const auto &block : input.blocks) {
                    budget.tick();
                    if (!reachable.contains(block.id)) continue;
                    const auto predecessors = feasible_predecessors.find(block.id);
                    for (const auto &phi : block.phis) {
                        budget.tick(phi.inputs.size() + 1);
                        SccpValue merged;
                        bool malformed = predecessors == feasible_predecessors.end() || predecessors->second.empty();
                        if (predecessors != feasible_predecessors.end()) {
                            for (const auto predecessor : predecessors->second) {
                                const LiftedBlock::PhiInput *found = nullptr;
                                for (const auto &input_value : phi.inputs) {
                                    if (input_value.predecessor != predecessor) continue;
                                    if (found) { malformed = true; break; }
                                    found = &input_value;
                                }
                                if (!found) { malformed = true; continue; }
                                const auto incoming = values.find(key(phi.destination, found->version));
                                const SccpValue value = incoming == values.end() ? SccpValue{} : incoming->second;
                                merged = sccp_join(merged, value);
                            }
                        }
                        if (malformed) merged = sccp_overdefined();
                        if (merged.kind == SccpValue::Kind::constant &&
                            merged.constant.type.bits != phi.destination.width)
                            merged = sccp_overdefined();
                        changed = sccp_merge(values, key(phi.destination, phi.version), merged) || changed;
                    }

                    for (const auto &instruction : block.instructions) {
                        budget.tick();
                        if (const auto *assignment = std::get_if<Assign>(&instruction.statement);
                            assignment && assignment->destination_version) {
                            auto value = sccp_evaluate(assignment->value, values, definitions, budget);
                            if (value.kind == SccpValue::Kind::constant &&
                                value.constant.type.bits != assignment->destination.width)
                                value = sccp_overdefined();
                            changed = sccp_merge(values, key(assignment->destination, *assignment->destination_version), value) || changed;
                        }
                    }

                    const Branch *branch = block.instructions.empty() ? nullptr
                        : std::get_if<Branch>(&block.instructions.back().statement);
                    std::optional<SccpBranchEdges> branch_edges;
                    SccpValue predicate;
                    if (branch && branch->condition != "true") {
                        branch_edges = sccp_branch_edges(block, *branch);
                        predicate = sccp_evaluate(branch->predicate, values, definitions, budget);
                    }
                    for (std::size_t edge_index = 0; edge_index < block.successors.size(); ++edge_index) {
                        bool feasible = true;
                        if (branch && branch_edges && !forced_unknown_branches.contains(block.id)) {
                            if (predicate.kind == SccpValue::Kind::constant &&
                                predicate.constant.type.kind == TypeKind::boolean && predicate.constant.type.bits == 1 &&
                                predicate.constant.value <= 1) {
                                feasible = predicate.constant.value ? edge_index == branch_edges->on_true
                                                                    : edge_index == branch_edges->on_false;
                            } else if (predicate.kind == SccpValue::Kind::unknown) {
                                feasible = false;
                            }
                        }
                        if (feasible) mark_edge(block, edge_index, changed);
                    }
                }
            }
        };
        run_to_fixed_point();

        // A bottom predicate at convergence is not a proof of a dead edge.
        // Open both edges and propagate the newly reachable values instead.
        bool opened_unknown = false;
        for (const auto &block : input.blocks) {
            if (!reachable.contains(block.id) || block.instructions.empty()) continue;
            const auto *branch = std::get_if<Branch>(&block.instructions.back().statement);
            if (!branch || branch->condition == "true" || !sccp_branch_edges(block, *branch)) continue;
            const auto predicate = sccp_evaluate(branch->predicate, values, definitions, budget);
            if (predicate.kind == SccpValue::Kind::unknown && forced_unknown_branches.insert(block.id).second)
                opened_unknown = true;
        }
        if (opened_unknown) run_to_fixed_point();

        LiftedFunction result = input;
        std::map<Key, ConstantValue> constants;
        for (const auto &[version, value] : values)
            if (value.kind == SccpValue::Kind::constant) constants.emplace(version, value.constant);
        std::vector<LiftedBlock> kept;
        kept.reserve(result.blocks.size());
        for (auto &block : result.blocks) {
            if (structural_reachable.contains(block.id) && !reachable.contains(block.id)) continue;
            if (!reachable.contains(block.id)) {
                kept.push_back(std::move(block));
                continue;
            }
            for (auto &instruction : block.instructions)
                simplify_statement(instruction.statement, constants, true, true);
            if (!block.instructions.empty()) {
                auto *branch = std::get_if<Branch>(&block.instructions.back().statement);
                if (branch && branch->condition != "true" && !forced_unknown_branches.contains(block.id)) {
                    const auto edges = sccp_branch_edges(block, *branch);
                    const auto predicate = sccp_evaluate(branch->predicate, values, definitions, budget);
                    if (edges && predicate.kind == SccpValue::Kind::constant &&
                        predicate.constant.type.kind == TypeKind::boolean && predicate.constant.type.bits == 1 &&
                        predicate.constant.value <= 1) {
                        const auto selected = predicate.constant.value ? edges->on_true : edges->on_false;
                        const auto original = block_index.find(block.id);
                        if (original != block_index.end()) {
                            const auto &edge = input.blocks[original->second].successors[selected];
                            branch->condition = "true";
                            branch->true_target = edge.target;
                            branch->false_target.reset();
                            branch->predicate.reset();
                        }
                    }
                }
            }
            std::vector<BlockSuccessor> successors;
            for (std::size_t edge_index = 0; edge_index < block.successors.size(); ++edge_index)
                if (feasible_edges.contains({block.id, edge_index})) successors.push_back(block.successors[edge_index]);
            block.successors = std::move(successors);
            auto predecessor_is_feasible = [&](BlockId predecessor) {
                const auto source_found = block_index.find(predecessor);
                if (source_found == block_index.end()) return false;
                const auto &source = input.blocks[source_found->second];
                for (std::size_t edge_index = 0; edge_index < source.successors.size(); ++edge_index)
                    if (source.successors[edge_index].block == block.id && feasible_edges.contains({predecessor, edge_index}))
                        return true;
                return false;
            };
            auto predecessor_edge_exists = [&](BlockId predecessor) {
                const auto source_found = block_index.find(predecessor);
                if (source_found == block_index.end()) return false;
                const auto &source = input.blocks[source_found->second];
                return std::any_of(source.successors.begin(), source.successors.end(), [&](const auto &edge) {
                    return edge.block == block.id;
                });
            };
            for (auto &phi : block.phis)
                phi.inputs.erase(std::remove_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &item) {
                    return structural_reachable.contains(item.predecessor) &&
                           predecessor_edge_exists(item.predecessor) &&
                           !predecessor_is_feasible(item.predecessor);
                }), phi.inputs.end());
            if (block.memory_phi)
                block.memory_phi->inputs.erase(std::remove_if(block.memory_phi->inputs.begin(), block.memory_phi->inputs.end(),
                    [&](const auto &item) { return structural_reachable.contains(item.predecessor) &&
                                                   predecessor_edge_exists(item.predecessor) &&
                                                   !predecessor_is_feasible(item.predecessor); }),
                    block.memory_phi->inputs.end());
            for (auto &phi : block.memory_partition_phis)
                phi.inputs.erase(std::remove_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &item) {
                    return structural_reachable.contains(item.predecessor) &&
                           predecessor_edge_exists(item.predecessor) &&
                           !predecessor_is_feasible(item.predecessor);
                }), phi.inputs.end());
            kept.push_back(std::move(block));
        }
        result.blocks = std::move(kept);
        return result;
    } catch (const SccpBudgetExceeded &) {
        return input;
    } catch (const Error &error) {
        return error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Sparse constant propagation allocation failed"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Sparse constant propagation exceeds container limits"};
    }
}
} // namespace

static Result<LiftedFunction> simplify_constants_once(const LiftedFunction &input) {
    LiftedFunction result = input;
    const bool has_call = std::any_of(result.blocks.begin(), result.blocks.end(), [](const auto &block) {
        return std::any_of(block.instructions.begin(), block.instructions.end(), [](const auto &instruction) {
            return std::holds_alternative<Call>(instruction.statement);
        });
    });
    const bool allow_register_propagation = !has_call;
    std::set<Key> definitions;
    for (const auto &block : result.blocks) {
        for (const auto &phi : block.phis)
            if (!definitions.insert(key(phi.destination, phi.version)).second)
                return Error{ErrorCode::invalid_argument, "SSA function contains duplicate definitions"};
        for (const auto &instruction : block.instructions) {
            if (const auto *assignment = std::get_if<Assign>(&instruction.statement);
                assignment && assignment->destination_version &&
                !definitions.insert(key(assignment->destination, *assignment->destination_version)).second)
                return Error{ErrorCode::invalid_argument, "SSA function contains duplicate definitions"};
        }
    }
    std::map<Key, ConstantValue> constants;
    if (has_call) {
        // Calls have unknown register clobbers in this IR. Keep propagation
        // local to each basic block and discard the environment at every call:
        // this preserves facts before a call without carrying stale register
        // values through the call or into another block.
        for (auto &block : result.blocks) {
            std::map<Key, ConstantValue> local_constants;
            for (auto &instruction : block.instructions) {
                simplify_statement(instruction.statement, local_constants, true);
                if (std::holds_alternative<Call>(instruction.statement)) {
                    local_constants.clear();
                    continue;
                }
                const auto *assignment = std::get_if<Assign>(&instruction.statement);
                if (!assignment || !assignment->destination_version) continue;
                const auto *constant = assignment->value
                    ? std::get_if<ConstantValue>(&assignment->value->value) : nullptr;
                if (constant)
                    local_constants.emplace(key(assignment->destination, *assignment->destination_version), *constant);
            }
        }
    } else {
        std::map<Key, SsaDefinitionRef> definitions_by_version;
        constexpr std::size_t max_loop_constant_definitions = 250'000;
        std::size_t indexed_definitions = 0;
        bool index_complete = true;
        std::set<BlockId> block_ids;
        for (const auto &block : result.blocks) block_ids.insert(block.id);
        if (block_ids.size() != result.blocks.size()) index_complete = false;
        std::map<BlockId, std::set<BlockId>> cfg_predecessors;
        for (const auto &block : result.blocks)
            for (const auto &edge : block.successors)
                if (edge.block && block_ids.contains(*edge.block))
                    cfg_predecessors[*edge.block].insert(block.id);
        for (const auto &block : result.blocks) {
            for (const auto &phi : block.phis) {
                if (++indexed_definitions > max_loop_constant_definitions) {
                    index_complete = false;
                    break;
                }
                std::set<BlockId> phi_predecessors;
                for (const auto &phi_input : phi.inputs)
                    phi_predecessors.insert(phi_input.predecessor);
                const auto expected = cfg_predecessors.find(block.id);
                const bool phi_inputs_complete = phi_predecessors.size() == phi.inputs.size() &&
                    ((expected == cfg_predecessors.end() && phi_predecessors.empty()) ||
                     (expected != cfg_predecessors.end() && phi_predecessors == expected->second));
                definitions_by_version.emplace(key(phi.destination, phi.version),
                                                SsaDefinitionRef{&phi, nullptr, phi_inputs_complete});
            }
            if (!index_complete) break;
            for (const auto &instruction : block.instructions) {
                if (const auto *assignment = std::get_if<Assign>(&instruction.statement);
                    assignment && assignment->destination_version) {
                    if (++indexed_definitions > max_loop_constant_definitions) {
                        index_complete = false;
                        break;
                    }
                    definitions_by_version.emplace(key(assignment->destination, *assignment->destination_version),
                                                   SsaDefinitionRef{nullptr, assignment, false});
                }
            }
            if (!index_complete) break;
        }
        if (index_complete) {
            LoopConstantResolver loop_constants(definitions_by_version);
            for (const auto &[version, definition] : definitions_by_version) {
                (void)definition;
                const auto inferred = loop_constants.resolve(version);
                if (inferred.kind == LoopConstantValue::Kind::constant)
                    constants.emplace(version, inferred.value);
                if (loop_constants.exhausted()) break;
            }
        }

        bool changed = true;
        while (changed) {
            changed = false;
            for (auto &block : result.blocks) {
                for (const auto &phi : block.phis) {
                    if (phi.inputs.empty()) continue;
                    std::optional<ConstantValue> merged;
                    bool known = true;
                    for (const auto &incoming : phi.inputs) {
                        const auto found = constants.find(key(phi.destination, incoming.version));
                        if (found == constants.end()) { known = false; break; }
                        if (!merged) merged = found->second;
                        else if (merged->value != found->second.value || merged->type != found->second.type) {
                            known = false;
                            break;
                        }
                    }
                    if (known && merged) {
                        const auto inserted = constants.emplace(key(phi.destination, phi.version), *merged);
                        if (inserted.second) changed = true;
                    }
                }
                for (auto &instruction : block.instructions) {
                    auto *assignment = std::get_if<Assign>(&instruction.statement);
                    if (!assignment || !assignment->destination_version) continue;
                    assignment->value = simplify_expression(assignment->value, constants, allow_register_propagation);
                    const auto *constant = assignment->value
                        ? std::get_if<ConstantValue>(&assignment->value->value) : nullptr;
                    if (!constant) continue;
                    const auto inserted = constants.emplace(
                        key(assignment->destination, *assignment->destination_version), *constant);
                    if (inserted.second) changed = true;
                }
            }
        }
    }

    // Opaque-predicate proof is deliberately limited to side-effect-free
    // functions. Calls, memory writes and intrinsics can hide state changes or
    // unknown register effects, so they disable this additional reasoning.
    const bool pure_function = std::all_of(result.blocks.begin(), result.blocks.end(), [](const auto &block) {
        for (const auto &instruction : block.instructions) {
            std::size_t nodes = 0;
            const bool safe = std::visit([&](const auto &statement) {
                using T = std::decay_t<decltype(statement)>;
                if constexpr (std::is_same_v<T, Assign>)
                    return pure_expression_tree(statement.value, nodes, 0);
                else if constexpr (std::is_same_v<T, Branch>)
                    return pure_expression_tree(statement.predicate, nodes, 0) &&
                           pure_expression_tree(statement.indirect_target, nodes, 0);
                else if constexpr (std::is_same_v<T, Return>)
                    return pure_expression_tree(statement.value, nodes, 0);
                else return false;
            }, instruction.statement);
            if (!safe) return false;
        }
        return true;
    });
    std::size_t predicate_work = 0;
    std::set<BlockId> folded_branches;
    // A definition in a block with a unique predecessor chain is available
    // on every path to the branch. Use that small, conservative slice to prove
    // predicates whose setup crosses straight-line CFG block boundaries.
    // Blocks with joins stop the walk; phi values remain independent inputs.
    std::map<BlockId, std::size_t> unique_predecessor;
    std::map<BlockId, std::size_t> block_positions;
    for (std::size_t i = 0; i < result.blocks.size(); ++i)
        block_positions.emplace(result.blocks[i].id, i);
    std::set<BlockId> entry_reachable;
    if (const auto entry = std::find_if(result.blocks.begin(), result.blocks.end(), [&](const auto &candidate) {
            return candidate.begin == result.entry;
        }); entry != result.blocks.end()) {
        std::vector<BlockId> pending{entry->id};
        while (!pending.empty()) {
            const auto id = pending.back();
            pending.pop_back();
            if (!entry_reachable.insert(id).second) continue;
            const auto found = block_positions.find(id);
            if (found == block_positions.end()) continue;
            for (const auto &edge : result.blocks[found->second].successors)
                if (edge.block && block_positions.contains(*edge.block)) pending.push_back(*edge.block);
        }
    }
    std::map<BlockId, std::set<std::size_t>> predecessor_sets;
    for (std::size_t i = 0; i < result.blocks.size(); ++i)
        for (const auto &edge : result.blocks[i].successors)
            if (edge.block && block_positions.contains(*edge.block))
                predecessor_sets[*edge.block].insert(i);
    for (const auto &[target, sources] : predecessor_sets) {
        if (sources.size() == 1) unique_predecessor[target] = *sources.begin();
    }
    for (auto &block : result.blocks) {
        for (auto &instruction : block.instructions)
            simplify_statement(instruction.statement, constants, allow_register_propagation);
        if (pure_function && !block.instructions.empty()) {
            if (auto *branch = std::get_if<Branch>(&block.instructions.back().statement);
                branch && branch->predicate) {
                PureDefinitions block_definitions;
                auto add_assignments = [&](const LiftedBlock &source, bool exclude_terminator) {
                    auto end = source.instructions.end();
                    if (exclude_terminator && end != source.instructions.begin()) --end;
                    for (auto instruction = source.instructions.begin(); instruction != end; ++instruction)
                        if (const auto *assignment = std::get_if<Assign>(&instruction->statement);
                            assignment && assignment->destination_version && assignment->value)
                            block_definitions.emplace(key(assignment->destination, *assignment->destination_version),
                                                      assignment->value);
                };
                add_assignments(block, true);
                std::set<BlockId> visited_chain{block.id};
                auto current = block.id;
                bool chain_bounded = true;
                for (std::size_t steps = 0; steps < 256; ++steps) {
                    if (!entry_reachable.contains(current)) break;
                    const auto current_position = block_positions.find(current);
                    if (current_position == block_positions.end() ||
                        result.blocks[current_position->second].begin == result.entry) break;
                    const auto predecessor = unique_predecessor.find(current);
                    if (predecessor == unique_predecessor.end()) break;
                    const auto &source = result.blocks[predecessor->second];
                    if (!visited_chain.insert(source.id).second) break;
                    add_assignments(source, true);
                    current = source.id;
                    if (steps == 255) chain_bounded = false;
                }
                if (chain_bounded)
                    if (const auto proven = prove_small_boolean(branch->predicate, block_definitions, predicate_work))
                        branch->predicate = constant_expression(ConstantValue{
                            *proven ? 1u : 0u, ValueType{TypeKind::boolean, 1, false}});
            }
        }
        if (block.instructions.empty() || block.successors.size() != 2)
            continue;
        auto *branch = std::get_if<Branch>(&block.instructions.back().statement);
        if (!branch || branch->condition == "true" || !branch->predicate || !branch->true_target ||
            !branch->false_target || branch->true_target == branch->false_target)
            continue;
        const auto *predicate = std::get_if<ConstantValue>(&branch->predicate->value);
        if (!predicate || predicate->type.kind != TypeKind::boolean || predicate->type.bits != 1 ||
            predicate->value > 1)
            continue;
        const bool take_true = predicate->value != 0;
        const auto selected = take_true ? *branch->true_target : *branch->false_target;
        const auto true_edge = std::find_if(block.successors.begin(), block.successors.end(), [&](const auto &edge) {
            return edge.kind == BlockEdgeKind::conditional_true && edge.target == branch->true_target && edge.block;
        });
        const auto false_edge = std::find_if(block.successors.begin(), block.successors.end(), [&](const auto &edge) {
            return (edge.kind == BlockEdgeKind::conditional_false || edge.kind == BlockEdgeKind::fallthrough) &&
                   edge.target == branch->false_target && edge.block;
        });
        if (true_edge == block.successors.end() || false_edge == block.successors.end() || true_edge == false_edge)
            continue;
        const auto selected_block = take_true ? true_edge->block : false_edge->block;
        const auto source = (take_true ? true_edge : false_edge)->source;
        branch->condition = "true";
        branch->true_target = selected;
        branch->false_target.reset();
        branch->predicate.reset();
        block.successors = {{source, selected, selected_block, BlockEdgeKind::jump}};
        folded_branches.insert(block.id);
    }

    if (!folded_branches.empty()) {
        std::map<BlockId, std::size_t> block_by_id;
        for (std::size_t i = 0; i < result.blocks.size(); ++i)
            block_by_id.emplace(result.blocks[i].id, i);
        const auto entry = std::find_if(result.blocks.begin(), result.blocks.end(), [&](const auto &block) {
            return block.begin == result.entry;
        });
        if (entry != result.blocks.end()) {
            std::set<BlockId> reachable;
            std::vector<BlockId> pending{entry->id};
            while (!pending.empty()) {
                const auto id = pending.back();
                pending.pop_back();
                if (!reachable.insert(id).second)
                    continue;
                const auto found = block_by_id.find(id);
                if (found == block_by_id.end())
                    continue;
                for (const auto &successor : result.blocks[found->second].successors)
                    if (successor.block && block_by_id.contains(*successor.block))
                        pending.push_back(*successor.block);
            }
            result.blocks.erase(std::remove_if(result.blocks.begin(), result.blocks.end(), [&](const auto &block) {
                return !reachable.contains(block.id);
            }), result.blocks.end());
            for (auto &block : result.blocks) {
                std::set<BlockId> predecessors;
                for (const auto &candidate : result.blocks)
                    for (const auto &edge : candidate.successors)
                        if (edge.block && *edge.block == block.id)
                            predecessors.insert(candidate.id);
                for (auto &phi : block.phis)
                    phi.inputs.erase(std::remove_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &input) {
                        return !reachable.contains(input.predecessor) || !predecessors.contains(input.predecessor);
                    }), phi.inputs.end());
                if (block.memory_phi)
                    block.memory_phi->inputs.erase(std::remove_if(block.memory_phi->inputs.begin(),
                        block.memory_phi->inputs.end(), [&](const auto &input) {
                            return !reachable.contains(input.predecessor) || !predecessors.contains(input.predecessor);
                        }), block.memory_phi->inputs.end());
                for (auto &phi : block.memory_partition_phis)
                    phi.inputs.erase(std::remove_if(phi.inputs.begin(), phi.inputs.end(), [&](const auto &input) {
                        return !reachable.contains(input.predecessor) || !predecessors.contains(input.predecessor);
                    }), phi.inputs.end());
            }
        }
    }
    return result;
}

Result<LiftedFunction> simplify_constants(const LiftedFunction &input) {
    auto sparse = sparse_conditional_constants(input);
    if (!sparse) return sparse.error();
    auto simplified = simplify_constants_once(sparse.value());
    if (!simplified) return simplified.error();
    auto count_conditional_branches = [](const LiftedFunction &function) {
        std::size_t count = 0;
        for (const auto &block : function.blocks)
            for (const auto &instruction : block.instructions)
                if (const auto *branch = std::get_if<Branch>(&instruction.statement);
                    branch && (branch->false_target || branch->condition != "true"))
                    ++count;
        return count;
    };

    auto current = std::move(simplified.value());
    auto prior_branch_count = count_conditional_branches(input);
    for (;;) {
        const auto branch_count = count_conditional_branches(current);
        if (branch_count >= prior_branch_count) return current;
        prior_branch_count = branch_count;
        simplified = simplify_constants_once(current);
        if (!simplified) return simplified.error();
        current = std::move(simplified.value());
    }
}

namespace {
using EntryKey = std::pair<std::uint32_t, std::uint64_t>;
EntryKey entry_key(Address address) { return {address.space.value, address.offset}; }

// A single shared budget covers validation, graph traversal and rewriting.
// In particular, large phi/input lists and repeated alias invalidations do not
// escape the instruction budget by hiding inside one instruction.
struct SummaryBudget {
    const CallSummaryOptions &options;
    std::stop_token stop;
    std::size_t work = 0, blocks = 0, instructions = 0, expressions = 0;

    void take(std::size_t &used, std::size_t amount, std::size_t limit) {
        if (stop.stop_requested()) throw Error{ErrorCode::canceled, "Call-summary optimization canceled"};
        if (amount > limit - used)
            throw Error{ErrorCode::resource_limit, "Call-summary optimization exceeded its budget"};
        used += amount;
    }
    void tick(std::size_t amount = 1) { take(work, amount, options.max_work); }
};

void inspect_expression(const ExpressionPtr &expression, SummaryBudget &budget, std::size_t depth = 1) {
    if (!expression) return;
    budget.tick();
    if (depth > budget.options.max_expression_depth)
        throw Error{ErrorCode::resource_limit, "Call-summary expression nesting exceeds its budget"};
    budget.take(budget.expressions, 1, budget.options.max_expression_nodes);
    if (const auto *unary = std::get_if<UnaryValue>(&expression->value))
        inspect_expression(unary->operand, budget, depth + 1);
    else if (const auto *binary = std::get_if<BinaryValue>(&expression->value)) {
        inspect_expression(binary->left, budget, depth + 1);
        inspect_expression(binary->right, budget, depth + 1);
    }
}

template<class Visitor> void statement_expressions(const Statement &statement, Visitor &&visit) {
    std::visit([&](const auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, Assign>) visit(value.value);
        else if constexpr (std::is_same_v<T, Store>) { visit(value.address); visit(value.value); }
        else if constexpr (std::is_same_v<T, Call>) visit(value.indirect_target);
        else if constexpr (std::is_same_v<T, Branch>) { visit(value.predicate); visit(value.indirect_target); }
        else if constexpr (std::is_same_v<T, Return>) visit(value.value);
        else if constexpr (std::is_same_v<T, Intrinsic>) {
            for (const auto &operand : value.operands) visit(operand);
            for (const auto &output : value.register_output_values) visit(output);
        }
    }, statement);
}

bool register_aliases(RegisterOperand a, RegisterOperand b) {
    // Width/high-byte variants share storage. AVX and SSE names also overlap.
    const bool vector_alias = (a.bank == RegisterBank::xmm || a.bank == RegisterBank::ymm) &&
                              (b.bank == RegisterBank::xmm || b.bank == RegisterBank::ymm);
    return a.index == b.index && (a.bank == b.bank || vector_alias);
}

void add_write(std::vector<RegisterOperand> &writes, RegisterOperand reg, SummaryBudget &budget) {
    for (auto &existing : writes) {
        budget.tick();
        if (register_aliases(existing, reg)) return;
    }
    writes.push_back(reg);
}

void invalidate_registers(std::map<Key, ConstantValue> &constants,
                          const std::vector<RegisterOperand> &writes, SummaryBudget &budget) {
    for (auto it = constants.begin(); it != constants.end();) {
        budget.tick();
        bool clobbered = false;
        const auto &[bank, index, width, high_byte, version] = it->first;
        const RegisterOperand reg{static_cast<RegisterBank>(bank), static_cast<std::uint8_t>(index),
                                  static_cast<std::uint16_t>(width), high_byte};
        for (const auto write : writes) {
            budget.tick();
            if (register_aliases(reg, write)) { clobbered = true; break; }
        }
        if (clobbered) it = constants.erase(it);
        else ++it;
    }
}

bool usable_constant(const ConstantValue &value) {
    return value.type.bits && value.type.bits <= 64 &&
        (value.type.kind == TypeKind::integer || value.type.kind == TypeKind::boolean ||
         value.type.kind == TypeKind::pointer) &&
        (value.value & ~width_mask(value.type.bits)) == 0;
}

struct SummaryWorker {
    std::span<const CallSummaryInput> inputs;
    SummaryBudget &budget;
    std::map<EntryKey, std::size_t> entries;
    std::set<EntryKey> conflicts;
    std::vector<FunctionCallSummary> summaries;
    // 0 unvisited, 1 active, 2 complete; an active target is never summarized.
    std::vector<unsigned char> state;

    const FunctionCallSummary *lookup(const Call &call) const {
        if (!call.direct_target || call.indirect_target || call.delay_slot_snapshot_block ||
            call.delay_slot_snapshot_instruction) return nullptr;
        const auto target = entry_key(*call.direct_target);
        if (conflicts.contains(target)) return nullptr;
        const auto found = entries.find(target);
        if (found == entries.end() || state[found->second] != 2 || !summaries[found->second].proven)
            return nullptr;
        return &summaries[found->second];
    }

    void call_constants(const Call &call, std::map<Key, ConstantValue> &constants) {
        const auto *summary = lookup(call);
        if (!summary || !summary->register_effects_known) constants.clear();
        else invalidate_registers(constants, summary->register_writes, budget);
        // The ABI result itself is a new definition even if the callee body
        // contains no explicit write to the caller's modeled return register.
        invalidate_registers(constants, call.register_writes, budget);
        if (call.return_register)
            invalidate_registers(constants, {*call.return_register}, budget);
        if (summary && summary->return_constant && call.return_register && call.return_version &&
            call.return_register->width == summary->return_constant->type.bits)
            constants.emplace(key(*call.return_register, *call.return_version), *summary->return_constant);
    }

    void advance_constants(Statement &statement, std::map<Key, ConstantValue> &constants) {
        budget.tick();
        statement_expressions(statement, [&](const auto &expression) { inspect_expression(expression, budget); });
        // Delayed transfers read a snapshot predating their delay slot. The
        // local environment here describes the current instruction instead.
        const bool delayed = std::visit([](const auto &value) {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, Call> || std::is_same_v<T, Branch> || std::is_same_v<T, Return>)
                return value.delay_slot_snapshot_block.has_value() || value.delay_slot_snapshot_instruction.has_value();
            else return false;
        }, statement);
        if (delayed) {
            if (std::holds_alternative<Call>(statement)) constants.clear();
            return;
        }
        simplify_statement(statement, constants, true, true);
        if (const auto *call = std::get_if<Call>(&statement)) call_constants(*call, constants);
        else if (const auto *intrinsic = std::get_if<Intrinsic>(&statement)) {
            // Opaque instruction effects cannot preserve register facts.
            if (intrinsic->name != "nop" || !intrinsic->register_writes.empty() ||
                intrinsic->memory_effect != IntrinsicMemoryEffect::none) constants.clear();
        } else if (const auto *assignment = std::get_if<Assign>(&statement);
                   assignment && assignment->destination_version && assignment->value) {
            const auto *constant = std::get_if<ConstantValue>(&assignment->value->value);
            if (constant && usable_constant(*constant) && assignment->destination.width == constant->type.bits)
                constants.emplace(key(assignment->destination, *assignment->destination_version), *constant);
        }
    }

    void summarize(std::size_t index, std::size_t depth) {
        budget.tick();
        if (state[index] == 2) return;
        if (state[index] == 1) return;
        auto &summary = summaries[index];
        const auto &input = inputs[index];
        const auto &function = *input.function;
        const auto reject = [&](const char *reason) {
            summary = FunctionCallSummary{};
            summary.entry = function.entry;
            summary.reason = reason;
            state[index] = 2;
        };
        if (depth > budget.options.max_call_depth) { reject("Call depth exceeds summary limit"); return; }
        if (!input.body_is_complete || input.externally_bound || !function.diagnostics.empty() ||
            conflicts.contains(entry_key(function.entry))) {
            reject("Body is incomplete, externally bound, diagnostic-bearing or conflicting"); return;
        }
        state[index] = 1;
        // All CFG exits must be explicit normal returns and every edge must
        // identify a block at the same exact address in this body. Unresolved
        // jumps/tail calls cannot be mistaken for an effect-free exit.
        std::map<BlockId, const LiftedBlock *> blocks;
        std::size_t entries_at_address = 0, returns = 0;
        for (const auto &block : function.blocks) {
            budget.tick();
            if (!blocks.emplace(block.id, &block).second) { reject("Duplicate block identity"); return; }
            entries_at_address += block.begin == function.entry;
        }
        if (entries_at_address != 1) { reject("Body has no unique entry block"); return; }
        summary.register_effects_known = input.boundary_register_effects_known;
        summary.may_read_memory = input.boundary_memory_effect != IntrinsicMemoryEffect::none;
        summary.may_write_memory = input.boundary_memory_effect == IntrinsicMemoryEffect::write ||
                                   input.boundary_memory_effect == IntrinsicMemoryEffect::unknown;
        for (const auto reg : input.boundary_register_writes) add_write(summary.register_writes, reg, budget);
        bool unanimous_return = true;
        for (const auto &block : function.blocks) {
            budget.tick();
            if (block.instructions.empty()) { reject("Body contains an empty block"); return; }
            for (const auto &edge : block.successors) {
                budget.tick();
                const auto found = edge.block ? blocks.find(*edge.block) : blocks.end();
                if (found == blocks.end() || !edge.target || *edge.target != found->second->begin ||
                    edge.kind == BlockEdgeKind::unresolved) { reject("Body has an unresolved exit"); return; }
            }
            const auto *terminal_return = std::get_if<Return>(&block.instructions.back().statement);
            if ((block.successors.empty() && !terminal_return) || (terminal_return && !block.successors.empty())) {
                reject("Body has an unmodeled exit"); return;
            }
            bool unknown_expression = false;
            const auto memory_reads = [&](const auto &self, const ExpressionPtr &expression) -> void {
                if (!expression) return;
                budget.tick();
                if (std::holds_alternative<MemoryValue>(expression->value)) summary.may_read_memory = true;
                else if (std::holds_alternative<UnknownValue>(expression->value) ||
                         std::holds_alternative<VariableValue>(expression->value)) unknown_expression = true;
                else if (const auto *unary = std::get_if<UnaryValue>(&expression->value)) self(self, unary->operand);
                else if (const auto *binary = std::get_if<BinaryValue>(&expression->value)) {
                    self(self, binary->left); self(self, binary->right);
                }
            };
            // Dispatch metadata also contributes executable selector effects;
            // validation's size/depth inspection does not establish purity.
            if (block.switch_dispatch) memory_reads(memory_reads, block.switch_dispatch->selector);
            if (unknown_expression) { reject("Body contains an opaque switch selector"); return; }
            std::map<Key, ConstantValue> constants;
            for (std::size_t n = 0; n < block.instructions.size(); ++n) {
                budget.tick();
                auto statement = block.instructions[n].statement;
                statement_expressions(statement, [&](const auto &expression) { memory_reads(memory_reads, expression); });
                if (unknown_expression) { reject("Body contains an opaque value"); return; }
                if (const auto *call = std::get_if<Call>(&statement)) {
                    if (!call->direct_target || call->indirect_target || call->delay_slot_snapshot_block ||
                        call->delay_slot_snapshot_instruction) { reject("Body contains an indirect or delayed call"); return; }
                    const auto target = entries.find(entry_key(*call->direct_target));
                    if (target == entries.end() || conflicts.contains(entry_key(*call->direct_target)) ||
                        state[target->second] == 1) { reject("Body calls an unknown, conflicting or recursive callee"); return; }
                    summarize(target->second, depth + 1);
                    const auto *callee = lookup(*call);
                    if (!callee) { reject("Body calls an unsummarized callee"); return; }
                    summary.register_effects_known &= callee->register_effects_known;
                    summary.may_read_memory |= callee->may_read_memory;
                    summary.may_write_memory |= callee->may_write_memory;
                    for (const auto reg : callee->register_writes) add_write(summary.register_writes, reg, budget);
                    for (const auto reg : call->register_writes) add_write(summary.register_writes, reg, budget);
                    if (call->return_register) add_write(summary.register_writes, *call->return_register, budget);
                } else if (const auto *assignment = std::get_if<Assign>(&statement)) {
                    if (!assignment->value) { reject("Body contains an opaque assignment"); return; }
                    add_write(summary.register_writes, assignment->destination, budget);
                }
                else if (std::holds_alternative<Store>(statement)) {
                    summary.may_write_memory = true;
                } else if (const auto *intrinsic = std::get_if<Intrinsic>(&statement)) {
                    // Even a memory-free opaque intrinsic may have unmodeled
                    // register/flag effects. Only the canonical nop is safe.
                    if (intrinsic->name != "nop" || !intrinsic->operands.empty() ||
                        !intrinsic->register_writes.empty() || intrinsic->memory_effect != IntrinsicMemoryEffect::none) {
                        reject("Body contains an opaque intrinsic"); return;
                    }
                } else if (const auto *branch = std::get_if<Branch>(&statement)) {
                    if (n + 1 != block.instructions.size() || branch->indirect_target ||
                        branch->delay_slot_snapshot_block || branch->delay_slot_snapshot_instruction) {
                        reject("Body contains an unsupported branch"); return;
                    }
                    const auto has_target = [&](const std::optional<Address> &address) {
                        if (!address) return false;
                        return std::any_of(block.successors.begin(), block.successors.end(), [&](const auto &edge) {
                            budget.tick(); return edge.target == address;
                        });
                    };
                    if (!has_target(branch->true_target) ||
                        (branch->false_target && !has_target(branch->false_target))) {
                        reject("Branch target is outside the body"); return;
                    }
                } else if (const auto *ret = std::get_if<Return>(&statement)) {
                    if (n + 1 != block.instructions.size() || ret->delay_slot_snapshot_block ||
                        ret->delay_slot_snapshot_instruction) { reject("Body contains an unsupported return"); return; }
                }
                advance_constants(statement, constants);
                if (const auto *ret = std::get_if<Return>(&statement)) {
                    ++returns;
                    const auto *constant = ret->value ? std::get_if<ConstantValue>(&ret->value->value) : nullptr;
                    if (!constant || !usable_constant(*constant)) unanimous_return = false;
                    else if (!summary.return_constant) summary.return_constant = *constant;
                    else if (*summary.return_constant != *constant) unanimous_return = false;
                }
            }
        }
        if (!returns) { reject("Body has no modeled return"); return; }
        if (!unanimous_return) summary.return_constant.reset();
        summary.proven = true;
        state[index] = 2;
    }
};

using MemoryAliases = std::map<std::uint32_t, std::uint32_t>;
std::uint32_t resolve_memory(std::uint32_t version, const MemoryAliases &aliases, SummaryBudget &budget) {
    for (std::size_t remaining = aliases.size();;) {
        budget.tick();
        const auto found = aliases.find(version);
        if (found == aliases.end()) return version;
        if (!remaining--) throw Error{ErrorCode::invalid_argument, "Call-summary memory aliases form a cycle"};
        version = found->second;
    }
}

ExpressionPtr rewrite_memory(const ExpressionPtr &expression, const MemoryAliases &aliases, SummaryBudget &budget) {
    if (!expression) return {};
    budget.tick();
    auto result = std::make_shared<Expression>(*expression);
    if (auto *memory = std::get_if<MemoryValue>(&result->value)) {
        if (memory->memory_version) memory->memory_version = resolve_memory(*memory->memory_version, aliases, budget);
    } else if (auto *unary = std::get_if<UnaryValue>(&result->value))
        unary->operand = rewrite_memory(unary->operand, aliases, budget);
    else if (auto *binary = std::get_if<BinaryValue>(&result->value)) {
        binary->left = rewrite_memory(binary->left, aliases, budget);
        binary->right = rewrite_memory(binary->right, aliases, budget);
    }
    return result;
}

void rewrite_memory(LiftedFunction &function, const MemoryAliases &aliases, SummaryBudget &budget) {
    if (aliases.empty()) return;
    const auto version = [&](std::optional<std::uint32_t> &value) {
        if (value) value = resolve_memory(*value, aliases, budget);
    };
    for (auto &block : function.blocks) {
        budget.tick();
        if (block.memory_phi) for (auto &input : block.memory_phi->inputs) {
            budget.tick(); input.version = resolve_memory(input.version, aliases, budget);
        }
        if (block.switch_dispatch)
            block.switch_dispatch->selector = rewrite_memory(block.switch_dispatch->selector, aliases, budget);
        for (auto &instruction : block.instructions) std::visit([&](auto &value) {
            budget.tick();
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, Assign>) value.value = rewrite_memory(value.value, aliases, budget);
            else if constexpr (std::is_same_v<T, Store>) {
                value.address = rewrite_memory(value.address, aliases, budget);
                value.value = rewrite_memory(value.value, aliases, budget);
                version(value.memory_input_version);
            } else if constexpr (std::is_same_v<T, Call>) {
                value.indirect_target = rewrite_memory(value.indirect_target, aliases, budget);
                version(value.memory_input_version); version(value.memory_output_version);
                if (value.x86_stack_effect)
                    version(value.x86_stack_effect->memory_input_version);
            } else if constexpr (std::is_same_v<T, Branch>) {
                value.predicate = rewrite_memory(value.predicate, aliases, budget);
                value.indirect_target = rewrite_memory(value.indirect_target, aliases, budget);
            } else if constexpr (std::is_same_v<T, Return>) {
                value.value = rewrite_memory(value.value, aliases, budget);
                if (value.x86_stack_effect)
                    version(value.x86_stack_effect->memory_input_version);
            }
            else if constexpr (std::is_same_v<T, Intrinsic>) {
                for (auto &operand : value.operands) operand = rewrite_memory(operand, aliases, budget);
                for (auto &output : value.register_output_values) output = rewrite_memory(output, aliases, budget);
                version(value.memory_input_version);
            }
        }, instruction.statement);
    }
}

void validate_summary_input(const CallSummaryInput &input, SummaryBudget &budget) {
    if (!input.function) throw Error{ErrorCode::invalid_argument, "Call-summary input has a null body"};
    if (input.boundary_memory_effect != IntrinsicMemoryEffect::none &&
        input.boundary_memory_effect != IntrinsicMemoryEffect::read &&
        input.boundary_memory_effect != IntrinsicMemoryEffect::write &&
        input.boundary_memory_effect != IntrinsicMemoryEffect::unknown)
        throw Error{ErrorCode::invalid_argument, "Call-summary boundary has an invalid memory effect"};
    budget.tick(input.boundary_register_writes.size());
    const auto &function = *input.function;
    budget.take(budget.blocks, function.blocks.size(), budget.options.max_blocks);
    std::set<Key> definitions;
    std::set<std::uint32_t> memory_definitions;
    const auto define_register = [&](RegisterOperand reg, std::optional<std::uint32_t> v) {
        budget.tick();
        if (v && (!*v || !definitions.insert(key(reg, *v)).second))
            throw Error{ErrorCode::invalid_argument, "Call-summary input has invalid SSA register definitions"};
    };
    const auto define_memory = [&](std::optional<std::uint32_t> v) {
        budget.tick();
        if (v && (!*v || !memory_definitions.insert(*v).second))
            throw Error{ErrorCode::invalid_argument, "Call-summary input has invalid SSA memory definitions"};
    };
    for (const auto &block : function.blocks) {
        budget.tick();
        budget.take(budget.instructions, block.instructions.size(), budget.options.max_instructions);
        budget.tick(block.successors.size());
        for (const auto &phi : block.phis) {
            define_register(phi.destination, phi.version); budget.tick(phi.inputs.size());
        }
        if (block.memory_phi) {
            define_memory(block.memory_phi->version); budget.tick(block.memory_phi->inputs.size());
        }
        if (block.switch_dispatch) {
            budget.tick(block.switch_dispatch->cases.size());
            inspect_expression(block.switch_dispatch->selector, budget);
        }
        for (const auto &instruction : block.instructions) {
            budget.tick();
            statement_expressions(instruction.statement, [&](const auto &expression) { inspect_expression(expression, budget); });
            std::visit([&](const auto &value) {
                using T = std::decay_t<decltype(value)>;
                if constexpr (std::is_same_v<T, Assign>) define_register(value.destination, value.destination_version);
                else if constexpr (std::is_same_v<T, Store>) define_memory(value.memory_output_version);
                else if constexpr (std::is_same_v<T, Call>) {
                    budget.tick(value.register_inputs.size());
                    budget.tick(value.register_writes.size());
                    if (!value.register_output_versions.empty() && value.register_output_versions.size() != value.register_writes.size())
                        throw Error{ErrorCode::invalid_argument, "Call-summary call SSA definitions are incomplete"};
                    bool return_defined = false;
                    for (std::size_t i = 0; i < value.register_output_versions.size(); ++i) {
                        define_register(value.register_writes[i], value.register_output_versions[i]);
                        if (value.return_register == value.register_writes[i]) {
                            if (value.return_version != value.register_output_versions[i])
                                throw Error{ErrorCode::invalid_argument, "Call-summary call return version disagrees with its output"};
                            return_defined = true;
                        }
                    }
                    if (value.return_register && !return_defined) define_register(*value.return_register, value.return_version);
                    else if (!value.return_register && value.return_version)
                        throw Error{ErrorCode::invalid_argument, "Call-summary return version has no register"};
                    if (value.memory_output_version != value.memory_input_version) define_memory(value.memory_output_version);
                } else if constexpr (std::is_same_v<T, Intrinsic>) {
                    budget.tick(value.operands.size());
                    budget.tick(value.register_output_values.size());
                    budget.tick(value.register_writes.size());
                    if (!value.register_output_versions.empty() && value.register_output_versions.size() != value.register_writes.size())
                        throw Error{ErrorCode::invalid_argument, "Call-summary intrinsic SSA definitions are incomplete"};
                    for (std::size_t i = 0; i < value.register_output_versions.size(); ++i)
                        define_register(value.register_writes[i], value.register_output_versions[i]);
                    define_memory(value.memory_output_version);
                }
            }, instruction.statement);
        }
    }
}
} // namespace

Result<CallSummaryOptimization> optimize_with_call_summaries(
    std::span<const CallSummaryInput> inputs, const CallSummaryOptions &options, std::stop_token stop) {
    try {
        if (!options.max_functions || !options.max_blocks || !options.max_instructions ||
            !options.max_expression_nodes || !options.max_expression_depth || options.max_expression_depth > 256 ||
            !options.max_call_depth || options.max_call_depth > 128 || !options.max_work)
            return Error{ErrorCode::invalid_argument, "Call-summary limits must be nonzero and nesting must be bounded"};
        if (inputs.size() > options.max_functions)
            return Error{ErrorCode::resource_limit, "Call-summary function count exceeds its budget"};
        SummaryBudget budget{options, stop};
        budget.tick();
        SummaryWorker worker{inputs, budget, {}, {}, std::vector<FunctionCallSummary>(inputs.size()),
                             std::vector<unsigned char>(inputs.size())};
        for (std::size_t i = 0; i < inputs.size(); ++i) {
            validate_summary_input(inputs[i], budget);
            const auto entry = inputs[i].function->entry;
            worker.summaries[i].entry = entry;
            if (!worker.entries.emplace(entry_key(entry), i).second) worker.conflicts.insert(entry_key(entry));
        }
        for (std::size_t i = 0; i < inputs.size(); ++i) worker.summarize(i, 1);
        CallSummaryOptimization result;
        result.functions.reserve(inputs.size());
        for (const auto &input : inputs) {
            budget.tick();
            LiftedFunction function = *input.function;
            MemoryAliases aliases;
            for (auto &block : function.blocks) {
                std::map<Key, ConstantValue> constants;
                for (auto &instruction : block.instructions) {
                    worker.advance_constants(instruction.statement, constants);
                    const auto *call = std::get_if<Call>(&instruction.statement);
                    const auto *summary = call ? worker.lookup(*call) : nullptr;
                    if (summary && !summary->may_write_memory && call->memory_input_version &&
                        call->memory_output_version && call->memory_input_version != call->memory_output_version)
                        aliases.emplace(*call->memory_output_version, *call->memory_input_version);
                }
            }
            rewrite_memory(function, aliases, budget);
            result.functions.push_back(std::move(function));
        }
        result.summaries = std::move(worker.summaries);
        budget.tick();
        return result;
    } catch (const Error &error) {
        return error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Call-summary optimization allocation failed"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Call-summary optimization allocation exceeds container limits"};
    }
}
} // namespace hexlab::decompiler
