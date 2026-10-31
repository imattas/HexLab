#include "hexlab/decompiler/decompiler.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <functional>
#include <map>
#include <optional>
#include <queue>
#include <set>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace hexlab::decompiler {
namespace {
std::uint64_t mask(std::uint16_t bits) {
    return bits == 64 ? UINT64_MAX : ((std::uint64_t{1} << bits) - 1);
}

bool valid_bitvector(const Expression &e) {
    return (e.type.kind == TypeKind::integer || e.type.kind == TypeKind::boolean) &&
           e.type.bits > 0 && e.type.bits <= 64;
}

bool pure(const ExpressionPtr &expression) {
    if (!expression) return false;
    if (std::holds_alternative<RegisterValue>(expression->value) ||
        std::holds_alternative<ConstantValue>(expression->value) ||
        std::holds_alternative<X87Binary80Value>(expression->value)) return true;
    if (const auto *unary = std::get_if<UnaryValue>(&expression->value)) return pure(unary->operand);
    if (const auto *binary = std::get_if<BinaryValue>(&expression->value))
        return pure(binary->left) && pure(binary->right);
    return false;
}

bool pure_bitvector(const ExpressionPtr &expression, unsigned depth = 0) {
    if (!expression || depth > 64 || !valid_bitvector(*expression)) return false;
    if (const auto *reg = std::get_if<RegisterValue>(&expression->value))
        return reg->version.has_value();
    if (std::holds_alternative<ConstantValue>(expression->value)) return true;
    if (const auto *unary = std::get_if<UnaryValue>(&expression->value))
        return unary->operand && unary->operand->type.kind != TypeKind::floating &&
               pure_bitvector(unary->operand, depth + 1);
    if (const auto *binary = std::get_if<BinaryValue>(&expression->value))
        return binary->left && binary->right &&
               pure_bitvector(binary->left, depth + 1) && pure_bitvector(binary->right, depth + 1);
    return false;
}

// A small total-expression whitelist for select rewrites. In particular,
// division/remainder, memory, intrinsics, and unknown values are excluded so
// dropping an unchosen arm cannot hide a fault or observable effect.
bool total_select_value(const ExpressionPtr &expression, unsigned depth = 0) {
    if (!expression || depth > 64 || !valid_bitvector(*expression)) return false;
    if (const auto *reg = std::get_if<RegisterValue>(&expression->value))
        return reg->version.has_value();
    if (std::holds_alternative<ConstantValue>(expression->value)) return true;
    if (const auto *unary = std::get_if<UnaryValue>(&expression->value))
        return (unary->operation == "neg" || unary->operation == "bitnot" ||
                unary->operation == "not" || unary->operation == "sext") && unary->operand &&
               total_select_value(unary->operand, depth + 1);
    const auto *binary = std::get_if<BinaryValue>(&expression->value);
    if (!binary || !binary->left || !binary->right) return false;
    if (binary->operation == "pair")
        return binary->left->type == expression->type && binary->right->type == expression->type &&
               total_select_value(binary->left, depth + 1) &&
               total_select_value(binary->right, depth + 1);
    if (binary->operation == "select_if") {
        const auto *alternatives = std::get_if<BinaryValue>(&binary->right->value);
        return (binary->left->type.kind == TypeKind::integer ||
                binary->left->type.kind == TypeKind::boolean) &&
               alternatives && alternatives->operation == "pair" &&
               binary->right->type == expression->type &&
               alternatives->left && alternatives->right &&
               alternatives->left->type == expression->type &&
               alternatives->right->type == expression->type &&
               total_select_value(binary->left, depth + 1) &&
               total_select_value(binary->right, depth + 1);
    }
    static constexpr std::array<std::string_view, 21> total_binary_operations{
        "add", "sub", "mul", "and", "or", "xor", "shl", "shr", "sar",
        "rotl", "rotr", "eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"};
    if (std::find(total_binary_operations.begin(), total_binary_operations.end(), binary->operation) ==
        total_binary_operations.end()) return false;
    if (!total_select_value(binary->left, depth + 1) ||
        !total_select_value(binary->right, depth + 1)) return false;
    const bool comparison = binary->operation == "eq" || binary->operation == "ne" ||
        binary->operation == "ult" || binary->operation == "ule" || binary->operation == "ugt" ||
        binary->operation == "uge" || binary->operation == "slt" || binary->operation == "sle" ||
        binary->operation == "sgt" || binary->operation == "sge";
    if (comparison)
        return expression->type.kind == TypeKind::boolean && expression->type.bits == 1 &&
               binary->left->type == binary->right->type;
    return binary->left->type == expression->type && binary->right->type == expression->type;
}

std::size_t mix_hash(std::size_t seed, std::size_t value) {
    return seed ^ (value + std::size_t{0x9e3779b9} + (seed << 6) + (seed >> 2));
}

std::size_t type_hash(const ValueType &type) {
    auto hash = static_cast<std::size_t>(type.kind);
    hash = mix_hash(hash, type.bits);
    hash = mix_hash(hash, type.is_signed);
    hash = mix_hash(hash, static_cast<std::size_t>(type.element_kind));
    hash = mix_hash(hash, type.element_bits);
    return mix_hash(hash, type.lanes);
}

std::size_t expression_hash(const ExpressionPtr &expression) {
    auto hash = mix_hash(static_cast<std::size_t>(0xcbf29ce484222325ULL), type_hash(expression->type));
    hash = mix_hash(hash, expression->value.index());
    if (const auto *reg = std::get_if<RegisterValue>(&expression->value)) {
        hash = mix_hash(hash, static_cast<std::size_t>(reg->reg.bank));
        hash = mix_hash(hash, reg->reg.index);
        hash = mix_hash(hash, reg->reg.width);
        hash = mix_hash(hash, reg->reg.high_byte);
        hash = mix_hash(hash, reg->version.value_or(UINT32_MAX));
    } else if (const auto *value = std::get_if<X87Binary80Value>(&expression->value)) {
        hash = mix_hash(hash, static_cast<std::size_t>(value->value.significand));
        hash = mix_hash(hash, static_cast<std::size_t>(value->value.significand >> 32));
        hash = mix_hash(hash, value->value.sign_exponent);
    } else if (const auto *value = std::get_if<ConstantValue>(&expression->value)) {
        hash = mix_hash(hash, static_cast<std::size_t>(value->value));
        hash = mix_hash(hash, static_cast<std::size_t>(value->value >> 32));
        hash = mix_hash(hash, type_hash(value->type));
    } else if (const auto *unary = std::get_if<UnaryValue>(&expression->value)) {
        hash = mix_hash(hash, std::hash<std::string>{}(unary->operation));
        hash = mix_hash(hash, expression_hash(unary->operand));
    } else if (const auto *binary = std::get_if<BinaryValue>(&expression->value)) {
        hash = mix_hash(hash, std::hash<std::string>{}(binary->operation));
        hash = mix_hash(hash, expression_hash(binary->left));
        hash = mix_hash(hash, expression_hash(binary->right));
    }
    return hash;
}

using VersionKey = std::tuple<unsigned, unsigned, unsigned, bool, std::uint32_t>;
using Definitions = std::map<VersionKey, ExpressionPtr>;

VersionKey version_key(const RegisterValue &value) {
    return {static_cast<unsigned>(value.reg.bank), value.reg.index, value.reg.width,
            value.reg.high_byte, *value.version};
}

ExpressionPtr substitute(const ExpressionPtr &input, const Definitions &definitions,
                         std::size_t &budget, unsigned depth = 0) {
    if (!input || !budget || depth > 64) return input;
    --budget;
    if (const auto *reg = std::get_if<RegisterValue>(&input->value); reg && reg->version) {
        const auto found = definitions.find(version_key(*reg));
        if (found != definitions.end()) return found->second;
        return input;
    }
    auto result = std::make_shared<Expression>(*input);
    if (auto *unary = std::get_if<UnaryValue>(&result->value))
        unary->operand = substitute(unary->operand, definitions, budget, depth + 1);
    else if (auto *binary = std::get_if<BinaryValue>(&result->value)) {
        binary->left = substitute(binary->left, definitions, budget, depth + 1);
        binary->right = substitute(binary->right, definitions, budget, depth + 1);
    }
    return result;
}

std::size_t expression_nodes(const ExpressionPtr &expression, std::size_t limit = 256) {
    if (!expression) return 0;
    if (!limit) return 1;
    std::size_t count = 1;
    if (const auto *unary = std::get_if<UnaryValue>(&expression->value)) {
        const auto operand = expression_nodes(unary->operand, limit - count);
        if (operand > limit - count) return limit + 1;
        count += operand;
    }
    else if (const auto *binary = std::get_if<BinaryValue>(&expression->value)) {
        const auto left = expression_nodes(binary->left, limit - count);
        if (left > limit - count) return limit + 1;
        count += left;
        const auto right = expression_nodes(binary->right, limit - count);
        if (right > limit - count) return limit + 1;
        count += right;
    }
    return count;
}

bool structurally_equal(const ExpressionPtr &a, const ExpressionPtr &b) {
    if (a == b) return true;
    if (!a || !b || a->type != b->type || a->value.index() != b->value.index()) return false;
    if (const auto *x = std::get_if<RegisterValue>(&a->value))
        return *x == std::get<RegisterValue>(b->value);
    if (const auto *x = std::get_if<ConstantValue>(&a->value))
        return *x == std::get<ConstantValue>(b->value);
    if (const auto *x = std::get_if<X87Binary80Value>(&a->value))
        return *x == std::get<X87Binary80Value>(b->value);
    if (const auto *x = std::get_if<UnaryValue>(&a->value)) {
        const auto &y = std::get<UnaryValue>(b->value);
        return x->operation == y.operation && structurally_equal(x->operand, y.operand);
    }
    if (const auto *x = std::get_if<BinaryValue>(&a->value)) {
        const auto &y = std::get<BinaryValue>(b->value);
        return x->operation == y.operation && structurally_equal(x->left, y.left) &&
               structurally_equal(x->right, y.right);
    }
    return false;
}

bool bitwise_complements(const ExpressionPtr &a, const ExpressionPtr &b) {
    if (!a || !b || a->type != b->type || a->type.kind != TypeKind::integer ||
        !a->type.bits || a->type.bits > 64)
        return false;
    const auto is_complement = [](const ExpressionPtr &candidate, const ExpressionPtr &value) {
        const auto *unary = candidate ? std::get_if<UnaryValue>(&candidate->value) : nullptr;
        return unary && unary->operation == "bitnot" && unary->operand &&
               unary->operand->type == value->type && structurally_equal(unary->operand, value);
    };
    return is_complement(a, b) || is_complement(b, a);
}

struct AvailableExpression {
    ExpressionPtr expression;
    RegisterOperand destination;
    std::uint32_t version = 0;
    std::size_t generation = 0;
};

// Reuse pure, SSA-qualified expressions from dominating blocks. The dominator
// tree is important here: an expression computed on only one side of a branch
// is never visible on the other side or at their join.
void eliminate_dominating_common_expressions(LiftedFunction &function,
                                              const std::map<BlockId, std::size_t> &indexes) {
    const auto count = function.blocks.size();
    if (count < 2 || count > 100'000) return;
    // The current call IR does not model every implicit register clobber. An
    // opaque intrinsic may have the same issue, so retain block-local CSE for
    // those functions rather than carrying values across an unmodeled effect.
    for (const auto &block : function.blocks)
        for (const auto &instruction : block.instructions)
            if (std::holds_alternative<Call>(instruction.statement) ||
                std::holds_alternative<Intrinsic>(instruction.statement))
                return;
    const auto missing = count;
    std::vector<std::vector<std::size_t>> successors(count), predecessors(count);
    std::size_t edge_count = 0;
    for (std::size_t source = 0; source < count; ++source) {
        for (const auto &edge : function.blocks[source].successors) {
            if (!edge.block) continue;
            const auto found = indexes.find(*edge.block);
            if (found != indexes.end()) successors[source].push_back(found->second);
        }
        auto &next = successors[source];
        std::sort(next.begin(), next.end());
        next.erase(std::unique(next.begin(), next.end()), next.end());
        if (next.size() > 500'000 - edge_count) return;
        edge_count += next.size();
        for (const auto target : next) predecessors[target].push_back(source);
    }

    const auto entry = std::find_if(function.blocks.begin(), function.blocks.end(), [&](const auto &block) {
        return block.begin == function.entry;
    });
    if (entry == function.blocks.end()) return;
    const auto root = static_cast<std::size_t>(entry - function.blocks.begin());

    // Iterative DFS avoids stack growth on generated functions with very deep
    // control-flow chains.
    std::vector<std::size_t> postorder;
    std::vector<bool> visited(count, false);
    std::vector<std::pair<std::size_t, std::size_t>> dfs{{root, 0}};
    visited[root] = true;
    while (!dfs.empty()) {
        auto &[block, next] = dfs.back();
        if (next < successors[block].size()) {
            const auto target = successors[block][next++];
            if (!visited[target]) {
                visited[target] = true;
                dfs.emplace_back(target, 0);
            }
        } else {
            postorder.push_back(block);
            dfs.pop_back();
        }
    }
    std::vector<std::size_t> reverse_postorder(postorder.rbegin(), postorder.rend());
    std::vector<std::size_t> order(count, missing);
    for (std::size_t i = 0; i < reverse_postorder.size(); ++i) order[reverse_postorder[i]] = i;

    // Cooper-Harvey-Kennedy immediate-dominator iteration over reverse
    // postorder gives near-linear behavior for the common reducible CFG case.
    std::vector<std::size_t> idom(count, missing);
    idom[root] = root;
    auto intersect = [&](std::size_t left, std::size_t right) {
        while (left != right) {
            while (order[left] > order[right]) left = idom[left];
            while (order[right] > order[left]) right = idom[right];
        }
        return left;
    };
    bool changed = true;
    std::size_t rounds = 0;
    while (changed && rounds++ <= reverse_postorder.size()) {
        changed = false;
        for (std::size_t position = 1; position < reverse_postorder.size(); ++position) {
            const auto block = reverse_postorder[position];
            auto first = missing;
            for (const auto predecessor : predecessors[block])
                if (idom[predecessor] != missing) {
                    first = predecessor;
                    break;
                }
            if (first == missing) continue;
            auto candidate = first;
            for (const auto predecessor : predecessors[block])
                if (predecessor != first && idom[predecessor] != missing)
                    candidate = intersect(predecessor, candidate);
            if (idom[block] != candidate) {
                idom[block] = candidate;
                changed = true;
            }
        }
    }
    if (changed) return;

    std::vector<std::vector<std::size_t>> dominator_children(count);
    for (const auto block : reverse_postorder)
        if (block != root && idom[block] != missing)
            dominator_children[idom[block]].push_back(block);

    std::map<std::size_t, std::vector<AvailableExpression>> available;
    std::vector<std::size_t> insertion_log;
    std::size_t generation = 1;
    std::size_t next_generation = 2;
    struct Frame {
        std::size_t block;
        std::size_t child = 0;
        std::size_t insertion_mark = 0;
        std::size_t prior_generation = 1;
        bool processed = false;
    };
    std::vector<Frame> walk{{root}};
    while (!walk.empty()) {
        auto &frame = walk.back();
        if (!frame.processed) {
            frame.processed = true;
            frame.insertion_mark = insertion_log.size();
            frame.prior_generation = generation;
            auto &block = function.blocks[frame.block];
            for (auto &instruction : block.instructions) {
                auto *assignment = std::get_if<Assign>(&instruction.statement);
                if (assignment && assignment->destination_version && pure(assignment->value) &&
                    pure_bitvector(assignment->value) && expression_nodes(assignment->value) <= 256) {
                    const auto hash = expression_hash(assignment->value);
                    const auto found = available.find(hash);
                    const AvailableExpression *match = nullptr;
                    if (found != available.end())
                        for (const auto &candidate : found->second)
                            if (candidate.generation == generation &&
                                structurally_equal(candidate.expression, assignment->value)) {
                                match = &candidate;
                                break;
                            }
                    if (match) {
                        assignment->value = std::make_shared<Expression>(Expression{
                            assignment->value->type,
                            RegisterValue{match->destination, match->version}});
                    } else {
                        available[hash].push_back({assignment->value, assignment->destination,
                                                   *assignment->destination_version, generation});
                        insertion_log.push_back(hash);
                    }
                }
                if (std::holds_alternative<Call>(instruction.statement) ||
                    std::holds_alternative<Intrinsic>(instruction.statement) ||
                    std::holds_alternative<Store>(instruction.statement)) {
                    // Calls have unmodeled register clobbers; intrinsic and
                    // store effects are also treated as barriers to match the
                    // established local-CSE contract.
                    generation = next_generation++;
                }
            }
        }
        if (frame.child < dominator_children[frame.block].size()) {
            const auto child = dominator_children[frame.block][frame.child++];
            walk.push_back(Frame{child, 0, insertion_log.size(), generation, false});
            continue;
        }
        while (insertion_log.size() > frame.insertion_mark) {
            const auto hash = insertion_log.back();
            insertion_log.pop_back();
            auto found = available.find(hash);
            if (found == available.end()) continue;
            found->second.pop_back();
            if (found->second.empty()) available.erase(found);
        }
        generation = frame.prior_generation;
        walk.pop_back();
    }
}

ExpressionPtr constant(std::uint64_t value, ValueType type) {
    value &= mask(type.bits);
    return std::make_shared<Expression>(Expression{type, ConstantValue{value, type}});
}

ExpressionPtr simplify_associative_bitwise(const ExpressionPtr &expression) {
    if (!expression || !valid_bitvector(*expression) || !pure_bitvector(expression) ||
        expression_nodes(expression) > 256)
        return {};
    const auto *root = std::get_if<BinaryValue>(&expression->value);
    if (!root || (root->operation != "and" && root->operation != "or" && root->operation != "xor"))
        return {};

    const auto operation = root->operation;
    const auto type = expression->type;
    const auto all = mask(type.bits);
    struct Term { ExpressionPtr value; bool retained = true; };
    std::vector<Term> terms;
    std::map<std::size_t, std::vector<std::size_t>> buckets;
    std::vector<ExpressionPtr> pending{expression};
    std::uint64_t constant_value = operation == "and" ? all : 0;
    std::size_t constants_seen = 0;
    bool duplicate_removed = false;

    while (!pending.empty()) {
        auto current = std::move(pending.back());
        pending.pop_back();
        if (!current || current->type != type || !pure_bitvector(current)) return {};
        if (const auto *binary = std::get_if<BinaryValue>(&current->value);
            binary && binary->operation == operation && binary->left && binary->right &&
            binary->left->type == type && binary->right->type == type) {
            pending.push_back(binary->right);
            pending.push_back(binary->left);
            continue;
        }
        if (const auto *value = std::get_if<ConstantValue>(&current->value)) {
            if (value->type != type) return {};
            ++constants_seen;
            if (operation == "and") constant_value &= value->value & all;
            else if (operation == "or") constant_value |= value->value & all;
            else constant_value ^= value->value & all;
            if ((operation == "and" && !constant_value) ||
                (operation == "or" && constant_value == all))
                return constant(constant_value, type);
            continue;
        }

        if (type.kind == TypeKind::integer) {
            const auto complement = std::find_if(terms.begin(), terms.end(), [&](const auto &term) {
                return term.retained && bitwise_complements(term.value, current);
            });
            if (complement != terms.end()) {
                if (operation != "xor") return constant(operation == "and" ? 0 : all, type);
                complement->retained = false;
                constant_value ^= all;
                ++constants_seen;
                duplicate_removed = true;
                continue;
            }
        }

        const auto hash = expression_hash(current);
        auto &bucket = buckets[hash];
        const auto duplicate = std::find_if(bucket.begin(), bucket.end(), [&](std::size_t index) {
            return structurally_equal(terms[index].value, current);
        });
        if (duplicate == bucket.end()) {
            bucket.push_back(terms.size());
            terms.push_back({std::move(current), true});
        } else if (operation == "xor") {
            terms[*duplicate].retained = !terms[*duplicate].retained;
            duplicate_removed = true;
        } else {
            duplicate_removed = true;
        }
    }

    std::vector<ExpressionPtr> operands;
    operands.reserve(terms.size() + 1);
    for (auto &term : terms)
        if (term.retained) operands.push_back(std::move(term.value));
    const auto identity = operation == "and" ? all : 0;
    if (constants_seen && (!operands.empty() ? constant_value != identity : true)) {
        operands.push_back(constant(constant_value, type));
    }
    if (operands.empty()) return constant(constant_value, type);
    if (operands.size() == 1) {
        if (constants_seen || duplicate_removed) return operands.front();
        return {};
    }
    if (!constants_seen && !duplicate_removed) return {};

    // All leaves are pure and have one exact bit-vector type, so associative
    // rebuilding preserves their fixed-width value and cannot move effects.
    while (operands.size() > 1) {
        std::vector<ExpressionPtr> next;
        next.reserve((operands.size() + 1) / 2);
        for (std::size_t i = 0; i < operands.size(); i += 2) {
            if (i + 1 == operands.size()) next.push_back(std::move(operands[i]));
            else next.push_back(std::make_shared<Expression>(Expression{
                type, BinaryValue{operation, std::move(operands[i]), std::move(operands[i + 1])}}));
        }
        operands = std::move(next);
    }
    return operands.front();
}

// Recombine complementary masked copies without distributing arbitrary
// expressions. Exact SSA equality and constant masks make both identities
// direct bit-vector equalities, and purity prevents erasing effects.
ExpressionPtr simplify_mask_partition(const ExpressionPtr &expression) {
    const auto *root = expression ? std::get_if<BinaryValue>(&expression->value) : nullptr;
    if (!root || (root->operation != "or" && root->operation != "and") ||
        !valid_bitvector(*expression) || expression->type.kind != TypeKind::integer ||
        !root->left || !root->right || !pure_bitvector(root->left) || !pure_bitvector(root->right))
        return {};
    const auto inner_operation = root->operation == "or" ? "and" : "or";
    const auto *left = std::get_if<BinaryValue>(&root->left->value);
    const auto *right = std::get_if<BinaryValue>(&root->right->value);
    if (!left || !right || left->operation != inner_operation || right->operation != inner_operation ||
        root->left->type != expression->type || root->right->type != expression->type ||
        !left->left || !left->right || !right->left || !right->right)
        return {};
    if (left->left->type != expression->type || left->right->type != expression->type ||
        right->left->type != expression->type || right->right->type != expression->type)
        return {};
    const auto split = [&](const BinaryValue &term, ExpressionPtr &value, const ConstantValue *&bits) {
        const auto *a = std::get_if<ConstantValue>(&term.left->value);
        const auto *b = std::get_if<ConstantValue>(&term.right->value);
        if (a && b) return false;
        if (a) { value = term.right; bits = a; }
        else if (b) { value = term.left; bits = b; }
        else return false;
        return value->type == expression->type && bits->type == expression->type;
    };
    ExpressionPtr left_value, right_value;
    const ConstantValue *left_bits = nullptr, *right_bits = nullptr;
    if (!split(*left, left_value, left_bits) || !split(*right, right_value, right_bits) ||
        !pure_bitvector(left_value) || !pure_bitvector(right_value) ||
        !structurally_equal(left_value, right_value)) return {};
    const auto combined = root->operation == "or"
        ? (left_bits->value | right_bits->value) : (left_bits->value & right_bits->value);
    return std::make_shared<Expression>(Expression{expression->type,
        BinaryValue{inner_operation, left_value, constant(combined, expression->type)}});
}

// Clearing from x the bits also present in x & y is subtraction without
// borrow: every subtracted one is already a set bit in x. XOR has the same
// result because x & y is a subset of x. Keep the proof structural and
// fixed-width; no arithmetic is moved across unrelated expressions.
ExpressionPtr simplify_masked_clear(const ExpressionPtr &expression) {
    const auto *root = expression ? std::get_if<BinaryValue>(&expression->value) : nullptr;
    if (!root || (root->operation != "sub" && root->operation != "xor") ||
        expression->type.kind != TypeKind::integer || !valid_bitvector(*expression) ||
        !root->left || !root->right || root->left->type != expression->type ||
        root->right->type != expression->type || !pure_bitvector(expression) ||
        expression_nodes(expression) > 256)
        return {};

    const auto match = [&](const ExpressionPtr &value, const ExpressionPtr &masked) -> ExpressionPtr {
        const auto *and_value = masked ? std::get_if<BinaryValue>(&masked->value) : nullptr;
        if (!and_value || and_value->operation != "and" || !and_value->left || !and_value->right ||
            masked->type != expression->type || and_value->left->type != expression->type ||
            and_value->right->type != expression->type)
            return {};
        ExpressionPtr other;
        if (structurally_equal(value, and_value->left)) other = and_value->right;
        else if (structurally_equal(value, and_value->right)) other = and_value->left;
        else return {};
        if (!pure_bitvector(value) || !pure_bitvector(other)) return {};
        auto inverted = std::make_shared<Expression>(Expression{expression->type,
            UnaryValue{"bitnot", other}});
        return std::make_shared<Expression>(Expression{expression->type,
            BinaryValue{"and", value, std::move(inverted)}});
    };

    if (root->operation == "sub") return match(root->left, root->right);
    if (auto simplified = match(root->left, root->right)) return simplified;
    return match(root->right, root->left);
}

// Boolean consensus: (x | y) & (x | ~y) == x, and its dual
// (x & y) | (x & ~y) == x. Keep this deliberately structural: both copies
// of x and y must be the same pure, versioned SSA expressions, and all
// operations must have the same fixed-width integer type.
ExpressionPtr simplify_consensus(const ExpressionPtr &expression) {
    const auto *root = expression ? std::get_if<BinaryValue>(&expression->value) : nullptr;
    if (!root || !valid_bitvector(*expression) || expression->type.kind != TypeKind::integer ||
        !root->left || !root->right || !pure_bitvector(root->left) || !pure_bitvector(root->right) ||
        expression_nodes(expression) > 256)
        return {};
    const auto inner_operation = root->operation == "and" ? "or" :
                                 root->operation == "or" ? "and" : "";
    if (!*inner_operation) return {};
    const auto *left = std::get_if<BinaryValue>(&root->left->value);
    const auto *right = std::get_if<BinaryValue>(&root->right->value);
    if (!left || !right || left->operation != inner_operation || right->operation != inner_operation ||
        root->left->type != expression->type || root->right->type != expression->type ||
        !left->left || !left->right || !right->left || !right->right ||
        left->left->type != expression->type || left->right->type != expression->type ||
        right->left->type != expression->type || right->right->type != expression->type)
        return {};
    const std::array<ExpressionPtr, 2> a{left->left, left->right};
    const std::array<ExpressionPtr, 2> b{right->left, right->right};
    for (std::size_t ai = 0; ai < a.size(); ++ai)
        for (std::size_t bi = 0; bi < b.size(); ++bi)
            if (structurally_equal(a[ai], b[bi]) &&
                bitwise_complements(a[1 - ai], b[1 - bi]) && pure_bitvector(a[ai]))
                return a[ai];
    return {};
}

// x | (~x & y) == x | y, with the dual x & (~x | y) == x & y.
// Restrict this to total expressions so the rewrite cannot hide a trapping or
// poison-producing operation in either operand.
ExpressionPtr simplify_complemented_absorption(const ExpressionPtr &expression) {
    const auto *root = expression ? std::get_if<BinaryValue>(&expression->value) : nullptr;
    if (!root || (root->operation != "and" && root->operation != "or") ||
        expression->type.kind != TypeKind::integer || !valid_bitvector(*expression) ||
        !root->left || !root->right || expression_nodes(expression) > 256 ||
        !total_select_value(root->left) || !total_select_value(root->right))
        return {};

    const auto inner_operation = root->operation == "or" ? "and" : "or";
    const auto match = [&](const ExpressionPtr &candidate,
                           const ExpressionPtr &nested_expression) -> ExpressionPtr {
        const auto *nested = nested_expression
            ? std::get_if<BinaryValue>(&nested_expression->value) : nullptr;
        if (!nested || nested->operation != inner_operation || !nested->left || !nested->right ||
            candidate->type != expression->type || nested_expression->type != expression->type ||
            nested->left->type != expression->type || nested->right->type != expression->type)
            return {};
        for (const auto &value : {nested->left, nested->right}) {
            const auto &other = value == nested->left ? nested->right : nested->left;
            if (bitwise_complements(candidate, value) && total_select_value(other))
                return std::make_shared<Expression>(Expression{expression->type,
                    BinaryValue{root->operation, candidate, other}});
        }
        return {};
    };
    if (auto simplified = match(root->left, root->right)) return simplified;
    return match(root->right, root->left);
}

// A sign-extended one-bit predicate is exactly an all-zero/all-one mask.
// Therefore (yes & sext(c)) | (no & ~sext(c)) is c ? yes : no. Require the
// exact same SSA predicate in both masks and total pure arms; do not infer the
// same property for arbitrary integer masks or zext(bool).
ExpressionPtr simplify_boolean_mask_select(const ExpressionPtr &expression) {
    const auto *root = expression ? std::get_if<BinaryValue>(&expression->value) : nullptr;
    if (!root || root->operation != "or" || expression->type.kind != TypeKind::integer ||
        !valid_bitvector(*expression) || !root->left || !root->right ||
        expression_nodes(expression) > 256 || !pure_bitvector(expression))
        return {};
    const auto *left = std::get_if<BinaryValue>(&root->left->value);
    const auto *right = std::get_if<BinaryValue>(&root->right->value);
    if (!left || !right || left->operation != "and" || right->operation != "and" ||
        root->left->type != expression->type || root->right->type != expression->type ||
        !left->left || !left->right || !right->left || !right->right)
        return {};

    struct MaskedValue {
        ExpressionPtr value;
        ExpressionPtr predicate;
        bool inverted = false;
    };
    const auto split = [&](const BinaryValue &term) -> std::optional<MaskedValue> {
        const auto parse_mask = [&](const ExpressionPtr &candidate,
                                    ExpressionPtr &predicate, bool &inverted) {
            const auto *unary = candidate ? std::get_if<UnaryValue>(&candidate->value) : nullptr;
            if (!unary) return false;
            const ExpressionPtr *extension = nullptr;
            if (unary->operation == "sext") extension = &candidate;
            else if (unary->operation == "bitnot" && unary->operand) {
                const auto *inner = std::get_if<UnaryValue>(&unary->operand->value);
                if (inner && inner->operation == "sext") {
                    extension = &unary->operand;
                    inverted = true;
                }
            }
            if (!extension) return false;
            const auto *sign_extend = std::get_if<UnaryValue>(&(*extension)->value);
            if (!sign_extend || !sign_extend->operand || (*extension)->type != expression->type ||
                sign_extend->operand->type.kind != TypeKind::boolean || sign_extend->operand->type.bits != 1 ||
                !pure_bitvector(sign_extend->operand))
                return false;
            predicate = sign_extend->operand;
            return true;
        };
        ExpressionPtr predicate;
        bool inverted = false;
        ExpressionPtr value;
        if (parse_mask(term.left, predicate, inverted)) value = term.right;
        else {
            predicate.reset();
            inverted = false;
            if (!parse_mask(term.right, predicate, inverted)) return {};
            value = term.left;
        }
        if (!value || value->type != expression->type || !total_select_value(value)) return {};
        return MaskedValue{std::move(value), std::move(predicate), inverted};
    };

    const auto yes_term = split(*left);
    const auto no_term = split(*right);
    if (!yes_term || !no_term || yes_term->inverted == no_term->inverted ||
        !structurally_equal(yes_term->predicate, no_term->predicate))
        return {};
    const auto yes = yes_term->inverted ? no_term->value : yes_term->value;
    const auto no = yes_term->inverted ? yes_term->value : no_term->value;
    if (yes->type != expression->type || no->type != expression->type) return {};
    auto alternatives = std::make_shared<Expression>(Expression{expression->type,
        BinaryValue{"pair", yes, no}});
    return std::make_shared<Expression>(Expression{expression->type,
        BinaryValue{"select_if", yes_term->predicate, std::move(alternatives)}});
}

// base ^ ((base ^ other) & sext(predicate)) is predicate ? other : base.
// A complemented sign-extension swaps the selected arms. As with the OR-mask
// form above, require versioned bitvectors and total values so the rewrite
// cannot hide effects or target traps.
ExpressionPtr simplify_xor_mask_select(const ExpressionPtr &expression) {
    const auto *root = expression ? std::get_if<BinaryValue>(&expression->value) : nullptr;
    if (!root || root->operation != "xor" || expression->type.kind != TypeKind::integer ||
        !valid_bitvector(*expression) || !root->left || !root->right ||
        expression_nodes(expression) > 256 || !pure_bitvector(expression))
        return {};

    const auto try_order = [&](const ExpressionPtr &masked_expression,
                               const ExpressionPtr &base) -> ExpressionPtr {
        const auto *masked = masked_expression
            ? std::get_if<BinaryValue>(&masked_expression->value) : nullptr;
        if (!masked || masked->operation != "and" || masked_expression->type != expression->type ||
            !masked->left || !masked->right || masked->left->type != expression->type ||
            masked->right->type != expression->type || base->type != expression->type)
            return {};

        const auto try_delta = [&](const ExpressionPtr &delta_expression,
                                   const ExpressionPtr &mask_expression) -> ExpressionPtr {
            const auto *delta = delta_expression
                ? std::get_if<BinaryValue>(&delta_expression->value) : nullptr;
            if (!delta || delta->operation != "xor" || delta_expression->type != expression->type ||
                !delta->left || !delta->right || delta->left->type != expression->type ||
                delta->right->type != expression->type)
                return {};

            ExpressionPtr predicate_mask = mask_expression;
            bool inverted = false;
            const auto *extension = predicate_mask
                ? std::get_if<UnaryValue>(&predicate_mask->value) : nullptr;
            if (extension && extension->operation == "bitnot" && extension->operand) {
                inverted = true;
                predicate_mask = extension->operand;
                extension = std::get_if<UnaryValue>(&predicate_mask->value);
            }
            if (!extension || extension->operation != "sext" || !extension->operand ||
                predicate_mask->type != expression->type ||
                extension->operand->type.kind != TypeKind::boolean ||
                extension->operand->type.bits != 1 || !pure_bitvector(extension->operand))
                return {};

            ExpressionPtr other;
            if (structurally_equal(base, delta->left)) other = delta->right;
            else if (structurally_equal(base, delta->right)) other = delta->left;
            else return {};
            if (!total_select_value(base) || !other || other->type != expression->type ||
                !total_select_value(other))
                return {};

            auto yes = inverted ? base : other;
            auto no = inverted ? other : base;
            auto alternatives = std::make_shared<Expression>(Expression{expression->type,
                BinaryValue{"pair", std::move(yes), std::move(no)}});
            return std::make_shared<Expression>(Expression{expression->type,
                BinaryValue{"select_if", extension->operand, std::move(alternatives)}});
        };
        if (auto direct = try_delta(masked->left, masked->right)) return direct;
        return try_delta(masked->right, masked->left);
    };
    if (auto direct = try_order(root->left, root->right)) return direct;
    return try_order(root->right, root->left);
}

// Flatten a nested select controlled by the same exact SSA predicate:
// c ? (c ? a : b) : d == c ? a : d, and its false-arm dual. Total pure
// bitvectors and exact predicate identity avoid path, alias, and effect guesses.
ExpressionPtr simplify_nested_select(const ExpressionPtr &expression) {
    if (!expression || expression_nodes(expression) > 256 ||
        !total_select_value(expression)) return {};
    const auto *root = std::get_if<BinaryValue>(&expression->value);
    const auto *outer = root && root->operation == "select_if" && root->right
        ? std::get_if<BinaryValue>(&root->right->value) : nullptr;
    if (!root || root->operation != "select_if" || !root->left || !outer ||
        outer->operation != "pair" || !outer->left || !outer->right) return {};
    const auto flatten = [&](const ExpressionPtr &nested_expression, bool true_arm) -> ExpressionPtr {
        const auto *nested = nested_expression
            ? std::get_if<BinaryValue>(&nested_expression->value) : nullptr;
        const auto *choices = nested && nested->operation == "select_if" && nested->right
            ? std::get_if<BinaryValue>(&nested->right->value) : nullptr;
        if (!nested || nested->operation != "select_if" ||
            !structurally_equal(root->left, nested->left) || !choices ||
            choices->operation != "pair" || !choices->left || !choices->right ||
            nested_expression->type != expression->type ||
            nested->right->type != expression->type ||
            choices->left->type != expression->type || choices->right->type != expression->type)
            return {};
        auto yes = true_arm ? choices->left : outer->left;
        auto no = true_arm ? outer->right : choices->right;
        auto alternatives = std::make_shared<Expression>(Expression{expression->type,
            BinaryValue{"pair", std::move(yes), std::move(no)}});
        return std::make_shared<Expression>(Expression{expression->type,
            BinaryValue{"select_if", root->left, std::move(alternatives)}});
    };
    if (auto flattened = flatten(outer->left, true)) return flattened;
    return flatten(outer->right, false);
}

// x - (x & (x - 1)) isolates the least significant set bit. In a fixed-width
// bitvector this is exactly x & (0 - x), including x == 0 and wraparound.
ExpressionPtr simplify_lowest_set_bit(const ExpressionPtr &expression) {
    const auto *root = expression ? std::get_if<BinaryValue>(&expression->value) : nullptr;
    if (!root || root->operation != "sub" || expression->type.kind != TypeKind::integer ||
        !valid_bitvector(*expression) || !root->left || !root->right ||
        !pure_bitvector(expression) || expression_nodes(expression) > 256)
        return {};
    const auto *masked = std::get_if<BinaryValue>(&root->right->value);
    if (!masked || masked->operation != "and" || root->right->type != expression->type ||
        !root->left || root->left->type != expression->type || !masked->left || !masked->right ||
        masked->left->type != expression->type || masked->right->type != expression->type)
        return {};
    const auto matches_decrement = [&](const ExpressionPtr &candidate) {
        const auto *decrement = candidate ? std::get_if<BinaryValue>(&candidate->value) : nullptr;
        if (!decrement || decrement->operation != "sub" || !decrement->left || !decrement->right ||
            decrement->left->type != expression->type || decrement->right->type != expression->type)
            return false;
        const auto *one = std::get_if<ConstantValue>(&decrement->right->value);
        return structurally_equal(root->left, decrement->left) && one && one->type == expression->type &&
               (one->value & mask(expression->type.bits)) == 1;
    };
    if (!structurally_equal(root->left, masked->left) || !matches_decrement(masked->right))
        if (!structurally_equal(root->left, masked->right) || !matches_decrement(masked->left))
            return {};
    auto negated = std::make_shared<Expression>(Expression{expression->type,
        BinaryValue{"sub", constant(0, expression->type), root->left}});
    return std::make_shared<Expression>(Expression{expression->type,
        BinaryValue{"and", root->left, std::move(negated)}});
}

// For fixed-width integers, x + y = (x ^ y) + 2 * (x & y), modulo the
// destination width. Rewriting the difference isolates the carry contribution
// without expanding arbitrary arithmetic expressions.
ExpressionPtr simplify_add_xor_difference(const ExpressionPtr &expression) {
    const auto *root = expression ? std::get_if<BinaryValue>(&expression->value) : nullptr;
    if (!root || root->operation != "sub" || expression->type.kind != TypeKind::integer ||
        !valid_bitvector(*expression) || !root->left || !root->right ||
        root->left->type != expression->type || root->right->type != expression->type ||
        !pure_bitvector(expression) || expression_nodes(expression) > 256)
        return {};
    const auto *sum = std::get_if<BinaryValue>(&root->left->value);
    const auto *difference = std::get_if<BinaryValue>(&root->right->value);
    if (!sum || sum->operation != "add" || !difference || difference->operation != "xor" ||
        !sum->left || !sum->right || !difference->left || !difference->right ||
        sum->left->type != expression->type || sum->right->type != expression->type ||
        difference->left->type != expression->type || difference->right->type != expression->type ||
        !pure_bitvector(root->left) || !pure_bitvector(root->right))
        return {};
    const bool same_order = structurally_equal(sum->left, difference->left) &&
                            structurally_equal(sum->right, difference->right);
    const bool reverse_order = structurally_equal(sum->left, difference->right) &&
                               structurally_equal(sum->right, difference->left);
    if (!same_order && !reverse_order)
        return {};
    auto shared_and = std::make_shared<Expression>(Expression{expression->type,
        BinaryValue{"and", sum->left, sum->right}});
    return std::make_shared<Expression>(Expression{expression->type,
        BinaryValue{"shl", std::move(shared_and), constant(1, expression->type)}});
}

// Reverse x + y = (x ^ y) + ((x & y) << 1). Recognize the direct
// two-term carry decomposition, preserving fixed-width modular behavior.
ExpressionPtr simplify_carry_recombination(const ExpressionPtr &expression) {
    const auto *root = expression ? std::get_if<BinaryValue>(&expression->value) : nullptr;
    if (!root || root->operation != "add" || expression->type.kind != TypeKind::integer ||
        !valid_bitvector(*expression) || !root->left || !root->right ||
        root->left->type != expression->type || root->right->type != expression->type ||
        !pure_bitvector(expression) || expression_nodes(expression) > 256)
        return {};

    const auto match = [&](const ExpressionPtr &xor_value, const ExpressionPtr &carry_value)
        -> ExpressionPtr {
        const auto *xor_bits = xor_value ? std::get_if<BinaryValue>(&xor_value->value) : nullptr;
        const auto *shift = carry_value ? std::get_if<BinaryValue>(&carry_value->value) : nullptr;
        if (!xor_bits || xor_bits->operation != "xor" || !xor_bits->left || !xor_bits->right ||
            !shift || shift->operation != "shl" || !shift->left || !shift->right ||
            xor_value->type != expression->type || carry_value->type != expression->type ||
            xor_bits->left->type != expression->type || xor_bits->right->type != expression->type ||
            shift->left->type != expression->type || shift->right->type != expression->type)
            return {};
        const auto *one = std::get_if<ConstantValue>(&shift->right->value);
        const auto *and_bits = std::get_if<BinaryValue>(&shift->left->value);
        if (!one || one->type != expression->type || (one->value & mask(expression->type.bits)) != 1 ||
            !and_bits || and_bits->operation != "and" || !and_bits->left || !and_bits->right ||
            and_bits->left->type != expression->type || and_bits->right->type != expression->type)
            return {};
        const bool same = structurally_equal(xor_bits->left, and_bits->left) &&
                          structurally_equal(xor_bits->right, and_bits->right);
        const bool reversed = structurally_equal(xor_bits->left, and_bits->right) &&
                              structurally_equal(xor_bits->right, and_bits->left);
        if (!same && !reversed) return {};
        return std::make_shared<Expression>(Expression{expression->type,
            BinaryValue{"add", xor_bits->left, xor_bits->right}});
    };
    if (auto value = match(root->left, root->right)) return value;
    return match(root->right, root->left);
}

// Cancel a repeated, exact SSA term in fixed-width additive expressions.
// Because these are integer bit-vectors, all equalities hold modulo 2^width.
// Structural version matching prevents cancellation across changed values.
ExpressionPtr simplify_additive_cancellation(const ExpressionPtr &expression) {
    const auto *root = expression ? std::get_if<BinaryValue>(&expression->value) : nullptr;
    if (!root || (root->operation != "add" && root->operation != "sub") ||
        expression->type.kind != TypeKind::integer || !valid_bitvector(*expression) ||
        !root->left || !root->right || root->left->type != expression->type ||
        root->right->type != expression->type || !pure_bitvector(expression) ||
        expression_nodes(expression) > 256)
        return {};

    const auto cancel = [&](const ExpressionPtr &candidate, const ExpressionPtr &other,
                            std::string_view nested_operation, bool cancel_left) -> ExpressionPtr {
        const auto *nested = candidate ? std::get_if<BinaryValue>(&candidate->value) : nullptr;
        if (!nested || nested->operation != nested_operation || !nested->left || !nested->right ||
            candidate->type != expression->type || nested->left->type != expression->type ||
            nested->right->type != expression->type || !pure_bitvector(candidate) ||
            !pure_bitvector(other))
            return {};
        const auto &canceled = cancel_left ? nested->left : nested->right;
        const auto &survivor = cancel_left ? nested->right : nested->left;
        return structurally_equal(canceled, other) ? survivor : ExpressionPtr{};
    };

    if (root->operation == "sub") {
        // (x + y) - x == y; (x + y) - y == x.
        if (auto value = cancel(root->left, root->right, "add", true)) return value;
        if (auto value = cancel(root->left, root->right, "add", false)) return value;
        // x - (x - y) == y.
        if (auto value = cancel(root->right, root->left, "sub", true)) return value;
    } else {
        // (x - y) + y == x; (y - x) + x == y, with add operands
        // accepted in either order.
        if (auto value = cancel(root->left, root->right, "sub", false)) return value;
        if (auto value = cancel(root->right, root->left, "sub", false)) return value;
    }
    return {};
}

ExpressionPtr simplify_rotate_cancellation(const ExpressionPtr &expression) {
    // Compose adjacent rotations modulo the exact bit width. This handles
    // cancellation and reduces any pair to at most one pure SSA rotation.
    const auto *root = expression ? std::get_if<BinaryValue>(&expression->value) : nullptr;
    if (!root || (root->operation != "rotl" && root->operation != "rotr") ||
        !valid_bitvector(*expression) || !root->left || !root->right ||
        root->left->type != expression->type || root->right->type != expression->type ||
        !pure_bitvector(expression) || expression_nodes(expression) > 256)
        return {};
    const auto *outer_count = std::get_if<ConstantValue>(&root->right->value);
    if (!outer_count || outer_count->type != expression->type) return {};
    const auto width = static_cast<std::int64_t>(expression->type.bits);
    const auto outer = static_cast<std::int64_t>(outer_count->value % expression->type.bits);
    const auto *inner = std::get_if<BinaryValue>(&root->left->value);
    if (!inner || (inner->operation != "rotl" && inner->operation != "rotr") ||
        !inner->left || !inner->right || inner->left->type != expression->type ||
        inner->right->type != expression->type)
        return outer == 0 ? root->left : ExpressionPtr{};
    const auto *inner_count = std::get_if<ConstantValue>(&inner->right->value);
    if (!inner_count || inner_count->type != expression->type || !pure_bitvector(inner->left)) return {};
    const auto inner_amount = static_cast<std::int64_t>(inner_count->value % expression->type.bits);
    const auto net = (root->operation == "rotl" ? outer : -outer) +
                     (inner->operation == "rotl" ? inner_amount : -inner_amount);
    const auto normalized = (net % width + width) % width;
    if (!normalized) return inner->left;
    const bool use_left = normalized <= width / 2;
    const auto amount = static_cast<std::uint64_t>(use_left ? normalized : width - normalized);
    return std::make_shared<Expression>(Expression{expression->type,
        BinaryValue{use_left ? "rotl" : "rotr", inner->left,
                    constant(amount, expression->type)}});
}

// Compose fixed-count integer shifts only when both encoded counts are
// canonical, in range, and the source is a pure SSA bitvector. Besides
// reducing same-direction chains, equal opposite shifts expose the exact
// retained bit range without relying on signed arithmetic assumptions.
ExpressionPtr simplify_shift_composition(const ExpressionPtr &expression) {
    const auto *outer = expression ? std::get_if<BinaryValue>(&expression->value) : nullptr;
    if (!outer || !outer->left || !outer->right || expression->type.kind != TypeKind::integer ||
        expression->type.bits < 2 || expression->type.bits > 64 ||
        (outer->operation != "shl" && outer->operation != "shr" && outer->operation != "sar") ||
        outer->left->type != expression->type || outer->right->type != expression->type ||
        !pure_bitvector(expression) || expression_nodes(expression) > 256 ||
        (outer->operation == "sar" && !expression->type.is_signed))
        return {};
    const auto *outer_count = std::get_if<ConstantValue>(&outer->right->value);
    const auto *inner = std::get_if<BinaryValue>(&outer->left->value);
    if (!outer_count || outer_count->type != expression->type ||
        outer_count->value != (outer_count->value & mask(expression->type.bits)) ||
        !inner || !inner->left || !inner->right || inner->left->type != expression->type ||
        inner->right->type != expression->type)
        return {};
    const auto *inner_count = std::get_if<ConstantValue>(&inner->right->value);
    if (!inner_count || inner_count->type != expression->type ||
        inner_count->value != (inner_count->value & mask(expression->type.bits)))
        return {};
    const auto width = static_cast<std::uint64_t>(expression->type.bits);
    const auto outer_amount = outer_count->value;
    const auto inner_amount = inner_count->value;
    if (outer_amount >= width || inner_amount >= width || !inner_amount || !outer_amount)
        return {};
    if ((outer->operation == "shl" && inner->operation == "shl") ||
        (outer->operation == "shr" && inner->operation == "shr") ||
        (outer->operation == "sar" && inner->operation == "sar")) {
        const auto combined = inner_amount + outer_amount;
        if (outer->operation != "sar" && combined >= width && total_select_value(inner->left))
            return constant(0, expression->type);
        if (outer->operation != "sar" && combined >= width) return {};
        const auto count = outer->operation == "sar" ? std::min(combined, width - 1) : combined;
        return std::make_shared<Expression>(Expression{expression->type,
            BinaryValue{outer->operation, inner->left, constant(count, expression->type)}});
    }
    if (inner_amount != outer_amount ||
        !((outer->operation == "shr" && inner->operation == "shl") ||
          (outer->operation == "shl" && inner->operation == "shr")))
        return {};
    const auto kept = outer->operation == "shr"
        ? mask(static_cast<std::uint16_t>(width - outer_amount))
        : mask(expression->type.bits) ^ mask(static_cast<std::uint16_t>(outer_amount));
    return std::make_shared<Expression>(Expression{expression->type,
        BinaryValue{"and", inner->left, constant(kept, expression->type)}});
}

ExpressionPtr simplify(const ExpressionPtr &input) {
    if (!input) return {};
    auto result = std::make_shared<Expression>(*input);
    if (auto *unary = std::get_if<UnaryValue>(&result->value)) {
        unary->operand = simplify(unary->operand);
        if (unary->operation == "bitnot" && unary->operand && result->type.kind == TypeKind::integer &&
            valid_bitvector(*result) && unary->operand->type == result->type &&
            pure_bitvector(unary->operand)) {
            if (const auto *inner = std::get_if<UnaryValue>(&unary->operand->value);
                inner && inner->operation == "bitnot" && inner->operand &&
                inner->operand->type == result->type && pure_bitvector(inner->operand))
                return inner->operand;
        }
        if (unary->operation == "neg" && unary->operand && result->type.kind == TypeKind::integer &&
            valid_bitvector(*result) && unary->operand->type == result->type &&
            pure_bitvector(unary->operand)) {
            if (const auto *inner = std::get_if<UnaryValue>(&unary->operand->value);
                inner && inner->operation == "neg" && inner->operand &&
                inner->operand->type == result->type && pure_bitvector(inner->operand))
                return inner->operand;
        }
        return result;
    }
    auto *binary = std::get_if<BinaryValue>(&result->value);
    if (!binary) return result;
    binary->left = simplify(binary->left);
    binary->right = simplify(binary->right);
    const auto &left = binary->left;
    const auto &right = binary->right;
    if (!valid_bitvector(*result) || !left || !right || !valid_bitvector(*left) ||
        !valid_bitvector(*right))
        return result;
    if (auto shifted = simplify_shift_composition(result)) return shifted;
    if (auto select = simplify_nested_select(result)) return select;
    const bool comparison = binary->operation == "eq" || binary->operation == "ne" ||
        binary->operation == "ult" || binary->operation == "uge" || binary->operation == "ule" ||
        binary->operation == "ugt" || binary->operation == "slt" || binary->operation == "sge" ||
        binary->operation == "sle" || binary->operation == "sgt";
    if (comparison && left->type == right->type && left->type.bits > 0 && left->type.bits <= 64 &&
        (left->type.kind == TypeKind::integer || left->type.kind == TypeKind::boolean) &&
        result->type.kind == TypeKind::boolean && result->type.bits == 1 &&
        structurally_equal(left, right) &&
        (std::holds_alternative<ConstantValue>(left->value) ||
         (std::get_if<RegisterValue>(&left->value) &&
          std::get<RegisterValue>(left->value).version.has_value()))) {
        const bool always_true = binary->operation == "eq" || binary->operation == "uge" ||
            binary->operation == "ule" || binary->operation == "sge" || binary->operation == "sle";
        return constant(always_true ? 1 : 0, result->type);
    }
    if (binary->operation == "udiv" && result->type.kind == TypeKind::integer &&
        !result->type.is_signed && result->type.bits >= 2 &&
        left->type == result->type && right->type == result->type &&
        pure_bitvector(left) && pure_bitvector(right) && expression_nodes(left) <= 254) {
        const auto *divisor = std::get_if<ConstantValue>(&right->value);
        const bool canonical_divisor = divisor && divisor->type == result->type &&
            divisor->value == (divisor->value & mask(result->type.bits));
        if (canonical_divisor && divisor->value == 1) return left;
        if (canonical_divisor && std::has_single_bit(divisor->value))
            return std::make_shared<Expression>(Expression{result->type,
                BinaryValue{"shr", left, constant(std::countr_zero(divisor->value), result->type)}});
    }
    if (binary->operation == "urem" && result->type.kind == TypeKind::integer &&
        !result->type.is_signed && result->type.bits >= 2 &&
        left->type == result->type && right->type == result->type &&
        pure_bitvector(left) && pure_bitvector(right) && expression_nodes(left) <= 254) {
        const auto *divisor = std::get_if<ConstantValue>(&right->value);
        const bool canonical_divisor = divisor && divisor->type == result->type &&
            divisor->value == (divisor->value & mask(result->type.bits));
        if (canonical_divisor && divisor->value == 1) return constant(0, result->type);
        if (canonical_divisor && std::has_single_bit(divisor->value))
            return std::make_shared<Expression>(Expression{result->type,
                BinaryValue{"and", left, constant(divisor->value - 1, result->type)}});
    }
    if (binary->operation == "srem" && result->type.kind == TypeKind::integer &&
        result->type.is_signed && result->type.bits >= 2 && result->type.bits <= 64 &&
        left->type == result->type && right->type == result->type &&
        pure_bitvector(left) && total_select_value(left) && expression_nodes(left) <= 48) {
        const auto *divisor = std::get_if<ConstantValue>(&right->value);
        const auto sign_bit = std::uint64_t{1} << (result->type.bits - 1);
        const bool canonical_divisor = divisor && divisor->type == result->type &&
            divisor->value == (divisor->value & mask(result->type.bits));
        if (canonical_divisor && divisor->value != 0 && divisor->value < sign_bit &&
            std::has_single_bit(divisor->value)) {
            if (divisor->value == 1) return constant(0, result->type);
            const auto remainder_mask = divisor->value - 1;
            auto sign = std::make_shared<Expression>(Expression{result->type,
                BinaryValue{"sar", left, constant(result->type.bits - 1, result->type)}});
            auto bias = std::make_shared<Expression>(Expression{result->type,
                BinaryValue{"and", std::move(sign), constant(remainder_mask, result->type)}});
            auto adjusted = std::make_shared<Expression>(Expression{result->type,
                BinaryValue{"add", left, bias}});
            auto low_bits = std::make_shared<Expression>(Expression{result->type,
                BinaryValue{"and", std::move(adjusted), constant(remainder_mask, result->type)}});
            return std::make_shared<Expression>(Expression{result->type,
                BinaryValue{"sub", std::move(low_bits), std::move(bias)}});
        }
    }
    if (left->type != result->type || right->type != result->type)
        return result;
    if (auto canonical = simplify_associative_bitwise(result)) return canonical;
    if (auto partition = simplify_mask_partition(result)) return partition;
    if (auto cleared = simplify_masked_clear(result)) return cleared;
    if (auto select = simplify_boolean_mask_select(result)) return select;
    if (auto select = simplify_xor_mask_select(result)) return select;
    if (auto consensus = simplify_consensus(result)) return consensus;
    if (auto absorbed = simplify_complemented_absorption(result)) return absorbed;
    if (auto carry = simplify_add_xor_difference(result)) return carry;
    if (auto carry = simplify_carry_recombination(result)) return carry;
    if (auto low_bit = simplify_lowest_set_bit(result)) return low_bit;
    if (auto additive = simplify_additive_cancellation(result)) return additive;
    if (auto rotation = simplify_rotate_cancellation(result)) return rotation;
    const auto *lc = std::get_if<ConstantValue>(&left->value);
    const auto *rc = std::get_if<ConstantValue>(&right->value);
    const auto all = mask(result->type.bits);
    if (binary->operation == "and") {
        if (structurally_equal(left, right) && pure(left)) return left;
        const auto absorbs = [&](const ExpressionPtr &candidate, const ExpressionPtr &other,
                                 std::string_view nested_operation) {
            const auto *nested = other ? std::get_if<BinaryValue>(&other->value) : nullptr;
            return nested && pure_bitvector(other) && nested->operation == nested_operation &&
                   nested->left && nested->right &&
                   nested->left->type == other->type && nested->right->type == other->type &&
                   ((structurally_equal(candidate, nested->left) && pure_bitvector(candidate)) ||
                    (structurally_equal(candidate, nested->right) && pure_bitvector(candidate)));
        };
        if (absorbs(left, right, "or")) return left;
        if (absorbs(right, left, "or")) return right;
        if ((lc && !(lc->value & all) && pure(right)) || (rc && !(rc->value & all) && pure(left)))
            return constant(0, result->type);
        if (lc && (lc->value & all) == all) return right;
        if (rc && (rc->value & all) == all) return left;
    } else if (binary->operation == "or") {
        if (structurally_equal(left, right) && pure(left)) return left;
        const auto absorbs = [&](const ExpressionPtr &candidate, const ExpressionPtr &other,
                                 std::string_view nested_operation) {
            const auto *nested = other ? std::get_if<BinaryValue>(&other->value) : nullptr;
            return nested && pure_bitvector(other) && nested->operation == nested_operation &&
                   nested->left && nested->right &&
                   nested->left->type == other->type && nested->right->type == other->type &&
                   ((structurally_equal(candidate, nested->left) && pure_bitvector(candidate)) ||
                    (structurally_equal(candidate, nested->right) && pure_bitvector(candidate)));
        };
        if (absorbs(left, right, "and")) return left;
        if (absorbs(right, left, "and")) return right;
        if ((lc && (lc->value & all) == all && pure(right)) ||
            (rc && (rc->value & all) == all && pure(left))) return constant(all, result->type);
        if (lc && !(lc->value & all)) return right;
        if (rc && !(rc->value & all)) return left;
    } else if (binary->operation == "xor") {
        if (lc && !(lc->value & all)) return right;
        if (rc && !(rc->value & all)) return left;
        if (structurally_equal(left, right) && pure(left)) return constant(0, result->type);
    } else if (binary->operation == "add" || binary->operation == "sub" ||
               binary->operation == "shl" || binary->operation == "shr" || binary->operation == "sar") {
        if (binary->operation == "add" && result->type.kind == TypeKind::integer &&
            bitwise_complements(left, right) && pure_bitvector(left) && pure_bitvector(right))
            return constant(all, result->type);
        if (rc && !(rc->value & all)) return left;
        if (binary->operation == "add" && lc && !(lc->value & all)) return right;
        if (binary->operation == "shr" && rc) {
            const auto *shift = std::get_if<BinaryValue>(&left->value);
            const auto *shift_amount = shift && shift->operation == "shl" && shift->right
                ? std::get_if<ConstantValue>(&shift->right->value) : nullptr;
            const auto amount = rc->value & all;
            if (shift_amount && (shift_amount->value & all) == amount && amount > 0 &&
                amount < result->type.bits && shift->left && shift->left->type == result->type &&
                pure(shift->left)) {
                const auto kept = all >> static_cast<unsigned>(amount);
                return std::make_shared<Expression>(Expression{result->type,
                    BinaryValue{"and", shift->left, constant(kept, result->type)}});
            }
        }
        if (binary->operation == "shl" && rc && result->type.kind == TypeKind::integer) {
            const auto *shift = std::get_if<BinaryValue>(&left->value);
            const auto *shift_amount = shift && shift->operation == "shr" && shift->right
                ? std::get_if<ConstantValue>(&shift->right->value) : nullptr;
            const auto amount = rc->value & all;
            if (shift_amount && shift_amount->type == result->type &&
                (shift_amount->value & all) == amount && amount > 0 &&
                amount < result->type.bits && shift->left && shift->left->type == result->type &&
                pure_bitvector(shift->left)) {
                const auto cleared_low = (std::uint64_t{1} << static_cast<unsigned>(amount)) - 1;
                const auto kept = all ^ cleared_low;
                return std::make_shared<Expression>(Expression{result->type,
                    BinaryValue{"and", shift->left, constant(kept, result->type)}});
            }
        }
        if (binary->operation == "sub" && rc) {
            const auto *inner = std::get_if<BinaryValue>(&left->value);
            if (inner && inner->operation == "add" && inner->left && inner->right &&
                inner->left->type == result->type && inner->right->type == result->type) {
                const auto *inner_left_constant = std::get_if<ConstantValue>(&inner->left->value);
                const auto *inner_right_constant = std::get_if<ConstantValue>(&inner->right->value);
                if (inner_left_constant && (inner_left_constant->value & all) == (rc->value & all) &&
                    pure(inner->right)) return inner->right;
                if (inner_right_constant && (inner_right_constant->value & all) == (rc->value & all) &&
                    pure(inner->left)) return inner->left;
            }
        }
    } else if (binary->operation == "mul") {
        if ((lc && !(lc->value & all) && pure(right)) || (rc && !(rc->value & all) && pure(left)))
            return constant(0, result->type);
        if (lc && (lc->value & all) == 1) return right;
        if (rc && (rc->value & all) == 1) return left;
        if (result->type.kind == TypeKind::integer) {
            const auto is_all_ones = [&](const ConstantValue *value) {
                return value && value->type == result->type && value->value == all;
            };
            if (is_all_ones(lc) && pure_bitvector(right))
                return std::make_shared<Expression>(Expression{result->type,
                    UnaryValue{"neg", right}});
            if (is_all_ones(rc) && pure_bitvector(left))
                return std::make_shared<Expression>(Expression{result->type,
                    UnaryValue{"neg", left}});
            const auto shift_for = [&](const ConstantValue *value) -> std::optional<unsigned> {
                if (!value || value->type != result->type) return {};
                const auto factor = value->value & all;
                if (!factor || (factor & (factor - 1)) != 0) return {};
                const auto amount = static_cast<unsigned>(std::countr_zero(factor));
                return amount > 0 && amount < result->type.bits
                    ? std::optional<unsigned>{amount} : std::nullopt;
            };
            if (const auto amount = shift_for(rc); amount && pure_bitvector(left))
                return std::make_shared<Expression>(Expression{result->type,
                    BinaryValue{"shl", left, constant(*amount, result->type)}});
            if (const auto amount = shift_for(lc); amount && pure_bitvector(right))
                return std::make_shared<Expression>(Expression{result->type,
                    BinaryValue{"shl", right, constant(*amount, result->type)}});
            const auto shift_plus_one_for = [&](const ConstantValue *value) -> std::optional<unsigned> {
                if (!value || value->type != result->type ||
                    value->value != (value->value & all)) return {};
                const auto remainder = value->value - 1;
                if (!remainder || (remainder & (remainder - 1)) != 0) return {};
                const auto amount = static_cast<unsigned>(std::countr_zero(remainder));
                return amount > 0 && amount < result->type.bits
                    ? std::optional<unsigned>{amount} : std::nullopt;
            };
            const auto rewrite_shift_plus_one = [&](const ExpressionPtr &operand, unsigned amount) {
                auto shifted = std::make_shared<Expression>(Expression{result->type,
                    BinaryValue{"shl", operand, constant(amount, result->type)}});
                return std::make_shared<Expression>(Expression{result->type,
                    BinaryValue{"add", std::move(shifted), operand}});
            };
            if (const auto amount = shift_plus_one_for(rc); amount && left->type == result->type &&
                pure_bitvector(left) &&
                expression_nodes(left) <= 256)
                return rewrite_shift_plus_one(left, *amount);
            if (const auto amount = shift_plus_one_for(lc); amount && right->type == result->type &&
                pure_bitvector(right) &&
                expression_nodes(right) <= 256)
                return rewrite_shift_plus_one(right, *amount);
        }
    }
    if ((binary->operation == "sub" || binary->operation == "xor") &&
        structurally_equal(left, right) && pure(left)) return constant(0, result->type);
    return result;
}

void simplify_statement(Statement &statement, const Definitions &definitions) {
    auto rewrite = [&](ExpressionPtr &expression) {
        std::size_t budget = 512;
        expression = simplify(substitute(expression, definitions, budget));
    };
    std::visit([&](auto &s) {
        using T = std::decay_t<decltype(s)>;
        if constexpr (std::is_same_v<T, Assign>) rewrite(s.value);
        else if constexpr (std::is_same_v<T, Store>) { rewrite(s.address); rewrite(s.value); }
        else if constexpr (std::is_same_v<T, Call>) rewrite(s.indirect_target);
        else if constexpr (std::is_same_v<T, Branch>) { rewrite(s.predicate); rewrite(s.indirect_target); }
        else if constexpr (std::is_same_v<T, Return>) rewrite(s.value);
        else if constexpr (std::is_same_v<T, Intrinsic>) for (auto &operand : s.operands) rewrite(operand);
    }, statement);
}
}

Result<LiftedFunction> simplify_identities(const LiftedFunction &input) {
    LiftedFunction output = input;
    auto simplify_block = [](LiftedBlock &block, Definitions definitions) {
        struct AvailableExpression {
            ExpressionPtr expression;
            RegisterOperand destination;
            std::uint32_t version;
        };
        std::map<std::size_t, std::vector<AvailableExpression>> available;
        for (auto &instruction : block.instructions) {
            simplify_statement(instruction.statement, definitions);
            if (auto *assignment = std::get_if<Assign>(&instruction.statement);
                assignment && assignment->destination_version && pure(assignment->value) &&
                pure_bitvector(assignment->value) && expression_nodes(assignment->value) <= 256) {
                const auto hash = expression_hash(assignment->value);
                const auto found = available.find(hash);
                const AvailableExpression *match = nullptr;
                if (found != available.end())
                    for (const auto &candidate : found->second)
                        if (structurally_equal(candidate.expression, assignment->value)) {
                            match = &candidate;
                            break;
                        }
                if (match) {
                    assignment->value = std::make_shared<Expression>(Expression{
                        assignment->value->type,
                        RegisterValue{match->destination, match->version}});
                } else {
                    available[hash].push_back({assignment->value, assignment->destination,
                                               *assignment->destination_version});
                }
            }
            if (const auto *assignment = std::get_if<Assign>(&instruction.statement);
                assignment && assignment->destination_version && pure(assignment->value) &&
                expression_nodes(assignment->value) <= 256) {
                RegisterValue destination{assignment->destination, assignment->destination_version};
                if (definitions.size() >= 4096) definitions.clear();
                definitions[version_key(destination)] = assignment->value;
            }
            if (std::holds_alternative<Call>(instruction.statement) ||
                std::holds_alternative<Intrinsic>(instruction.statement) ||
                std::holds_alternative<Store>(instruction.statement))
                available.clear();
            if (std::holds_alternative<Call>(instruction.statement) ||
                std::holds_alternative<Intrinsic>(instruction.statement))
                definitions.clear();
        }
        return definitions;
    };

    const auto count = output.blocks.size();
    std::map<BlockId, std::size_t> indexes;
    bool unique_ids = true;
    for (std::size_t i = 0; i < count; ++i)
        unique_ids &= indexes.emplace(output.blocks[i].id, i).second;
    if (!unique_ids) {
        for (auto &block : output.blocks) simplify_block(block, {});
        return output;
    }

    // Use the CFG, not storage order, to carry definitions through acyclic
    // blocks. Joins, cycles, and delay-slot edges do not inherit facts.
    std::vector<std::map<std::size_t, bool>> predecessors(count);
    std::vector<std::set<std::size_t>> successors(count);
    for (std::size_t i = 0; i < count; ++i) {
        for (const auto &edge : output.blocks[i].successors) {
            if (!edge.block) continue;
            const auto found = indexes.find(*edge.block);
            if (found == indexes.end()) continue;
            const auto target = found->second;
            successors[i].insert(target);
            const bool can_propagate = edge.kind != BlockEdgeKind::delay_slot;
            auto [prior, inserted] = predecessors[target].emplace(i, can_propagate);
            if (!inserted) prior->second = prior->second && can_propagate;
        }
    }

    std::vector<std::size_t> incoming(count);
    std::queue<std::size_t> ready;
    for (std::size_t i = 0; i < count; ++i) {
        incoming[i] = predecessors[i].size();
        if (!incoming[i]) ready.push(i);
    }
    std::vector<bool> processed(count, false);
    std::vector<Definitions> outputs(count);
    while (!ready.empty()) {
        const auto i = ready.front();
        ready.pop();
        Definitions definitions;
        if (predecessors[i].size() == 1 && predecessors[i].begin()->second) {
            const auto predecessor = predecessors[i].begin()->first;
            if (processed[predecessor]) definitions = outputs[predecessor];
        }
        outputs[i] = simplify_block(output.blocks[i], std::move(definitions));
        processed[i] = true;
        for (const auto successor : successors[i])
            if (--incoming[successor] == 0) ready.push(successor);
    }

    // Cyclic components keep local simplification but receive no predecessor
    // substitutions; this avoids guessing values around loop-carried state.
    for (std::size_t i = 0; i < count; ++i)
        if (!processed[i]) simplify_block(output.blocks[i], {});
    eliminate_dominating_common_expressions(output, indexes);
    return output;
}
} // namespace hexlab::decompiler
