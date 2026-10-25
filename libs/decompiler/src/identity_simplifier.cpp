#include "hexlab/decompiler/decompiler.hpp"

#include <algorithm>
#include <functional>
#include <map>
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
        std::holds_alternative<ConstantValue>(expression->value)) return true;
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

ExpressionPtr simplify(const ExpressionPtr &input) {
    if (!input) return {};
    auto result = std::make_shared<Expression>(*input);
    if (auto *unary = std::get_if<UnaryValue>(&result->value)) {
        unary->operand = simplify(unary->operand);
        return result;
    }
    auto *binary = std::get_if<BinaryValue>(&result->value);
    if (!binary) return result;
    binary->left = simplify(binary->left);
    binary->right = simplify(binary->right);
    const auto &left = binary->left;
    const auto &right = binary->right;
    if (!valid_bitvector(*result) || !left || !right || !valid_bitvector(*left) ||
        !valid_bitvector(*right) || left->type != result->type || right->type != result->type)
        return result;
    if (auto canonical = simplify_associative_bitwise(result)) return canonical;
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
