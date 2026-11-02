#include "hexlab/decompiler/decompiler.hpp"

#include <algorithm>
#include <map>
#include <new>
#include <tuple>
#include <type_traits>

namespace hexlab::decompiler {
namespace {
// Namespaces must stay distinct: a partition version is not a whole-memory
// version, and equal numeric register versions need not denote equal values.
enum class Space { reg, memory, partition };
using Key = std::tuple<Space, unsigned, unsigned, unsigned, bool, std::string, std::uint32_t>;

Key register_key(RegisterOperand reg, std::uint32_t version) {
    return {Space::reg, static_cast<unsigned>(reg.bank), reg.index, reg.width,
            reg.high_byte, {}, version};
}
Key memory_key(std::uint32_t version) { return {Space::memory, 0, 0, 0, false, {}, version}; }
Key partition_key(const std::string &partition, std::uint32_t version) {
    return {Space::partition, 0, 0, 0, false, partition, version};
}

bool supported_register(RegisterOperand reg) {
    // JVM stack transport has a different definition model. A64 SIMD SSA
    // normalizes overlapping views; do not infer identities between them here.
    return reg.width && reg.bank != RegisterBank::jvm_stack && reg.bank != RegisterBank::arm64_simd;
}

struct BudgetExceeded {};
struct Budget {
    std::size_t expressions = 0;
    void expression(unsigned depth) {
        if (depth > 128 || ++expressions > 1'000'000) throw BudgetExceeded{};
    }
};

template<class StatementType, class Visit>
void visit_statement_expressions(StatementType &statement, Visit visit) {
    std::visit([&](auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, Assign> || std::is_same_v<T, Return>) visit(value.value);
        else if constexpr (std::is_same_v<T, Store>) { visit(value.address); visit(value.value); }
        else if constexpr (std::is_same_v<T, Call>) visit(value.indirect_target);
        else if constexpr (std::is_same_v<T, Branch>) { visit(value.predicate); visit(value.indirect_target); }
        else if constexpr (std::is_same_v<T, Intrinsic>) {
            for (auto &operand : value.operands) visit(operand);
            for (auto &output : value.register_output_values) visit(output);
        }
    }, statement);
}

// The same walk serves preflight and rewriting, so new expression-bearing
// fields cannot accidentally be budgeted but then omitted by the transform.
struct Rewriter {
    const std::map<Key, Key> &aliases;
    Budget budget;
    bool unsupported_timing = false;

    std::uint32_t version(const Key &key) const {
        const auto found = aliases.find(key);
        return std::get<6>(found == aliases.end() ? key : found->second);
    }
    void reg(RegisterOperand reg, std::optional<std::uint32_t> &value) const {
        if (value) value = version(register_key(reg, *value));
    }
    void memory(std::optional<std::uint32_t> &value) const {
        if (value) value = version(memory_key(*value));
    }
    ExpressionPtr expression(const ExpressionPtr &input, unsigned depth = 0) {
        if (!input) return {};
        budget.expression(depth);
        if (aliases.empty()) {
            if (const auto *value = std::get_if<MemoryValue>(&input->value))
                expression(value->effective_address, depth + 1);
            else if (const auto *value = std::get_if<UnaryValue>(&input->value))
                expression(value->operand, depth + 1);
            else if (const auto *value = std::get_if<BinaryValue>(&input->value)) {
                expression(value->left, depth + 1);
                expression(value->right, depth + 1);
            }
            return input;
        }
        auto output = *input;
        if (auto *value = std::get_if<RegisterValue>(&output.value)) {
            reg(value->reg, value->version);
        } else if (auto *value = std::get_if<MemoryValue>(&output.value)) {
            if (value->base) reg(*value->base, value->base_version);
            if (value->index) reg(*value->index, value->index_version);
            if (value->stack_frame_register) reg(*value->stack_frame_register, value->stack_frame_version);
            memory(value->memory_version);
            if (value->memory_partition && value->memory_partition_version)
                value->memory_partition_version = version(
                    partition_key(*value->memory_partition, *value->memory_partition_version));
            value->effective_address = expression(value->effective_address, depth + 1);
        } else if (auto *value = std::get_if<UnaryValue>(&output.value)) {
            value->operand = expression(value->operand, depth + 1);
        } else if (auto *value = std::get_if<BinaryValue>(&output.value)) {
            value->left = expression(value->left, depth + 1);
            value->right = expression(value->right, depth + 1);
        }
        return std::make_shared<Expression>(std::move(output));
    }
    void statement(Statement &statement) {
        visit_statement_expressions(statement, [&](ExpressionPtr &value) { value = expression(value); });
        std::visit([&](auto &value) {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, Store>) {
                memory(value.memory_input_version);
            } else if constexpr (std::is_same_v<T, Call>) {
                for (auto &input : value.register_inputs) reg(input.reg, input.version);
                // A summarized read-only call can preserve its input state;
                // that output is a use, not a new SSA memory definition.
                const bool preserves_memory = value.memory_input_version == value.memory_output_version;
                memory(value.memory_input_version);
                if (preserves_memory) value.memory_output_version = value.memory_input_version;
                if (value.x86_stack_effect) memory(value.x86_stack_effect->memory_input_version);
            } else if constexpr (std::is_same_v<T, Return>) {
                if (value.x86_stack_effect) memory(value.x86_stack_effect->memory_input_version);
            } else if constexpr (std::is_same_v<T, Intrinsic>) {
                memory(value.memory_input_version);
            }
            if constexpr (std::is_same_v<T, Store> || std::is_same_v<T, Call> || std::is_same_v<T, Intrinsic>) {
                for (auto &effect : value.memory_partition_effects)
                    effect.input_version = version(partition_key(effect.partition, effect.input_version));
            }
        }, statement);
    }
    void preflight(const LiftedFunction &function) {
        std::size_t instructions = 0, edges = 0, inputs = 0, merges = 0, facts = 0;
        for (const auto &block : function.blocks) {
            instructions += block.instructions.size();
            edges += block.successors.size();
            merges += block.phis.size() + block.memory_partition_phis.size() + (block.memory_phi ? 1 : 0);
            facts += block.trap_edges.size() + block.exception_handlers.size() + block.exception_memory_edges.size();
            unsupported_timing |= !block.exception_handlers.empty() || !block.exception_memory_edges.empty();
            for (const auto &edge : block.successors)
                unsupported_timing |= edge.kind == BlockEdgeKind::delay_slot || edge.kind == BlockEdgeKind::exception;
            if (instructions > 200'000 || edges > 4096 || merges > 16384) throw BudgetExceeded{};
            for (const auto &phi : block.phis) inputs += phi.inputs.size();
            if (block.memory_phi) inputs += block.memory_phi->inputs.size();
            for (const auto &phi : block.memory_partition_phis) inputs += phi.inputs.size();
            if (inputs > 65536) throw BudgetExceeded{};
            for (const auto &instruction : block.instructions) {
                std::visit([&](const auto &value) {
                    using T = std::decay_t<decltype(value)>;
                    if constexpr (std::is_same_v<T, Store> || std::is_same_v<T, Call> || std::is_same_v<T, Intrinsic>)
                        facts += value.memory_partition_effects.size();
                    if constexpr (std::is_same_v<T, Call> || std::is_same_v<T, Intrinsic>)
                        facts += value.register_writes.size() + value.register_output_versions.size();
                    if constexpr (std::is_same_v<T, Call>)
                        facts += value.register_inputs.size() + value.abi_upper_half_writes.size();
                    if constexpr (std::is_same_v<T, Intrinsic>)
                        facts += value.operands.size() + value.register_output_values.size();
                    if constexpr (std::is_same_v<T, Call> || std::is_same_v<T, Branch> || std::is_same_v<T, Return>)
                        unsupported_timing |= value.delay_slot_snapshot_block.has_value() ||
                                              value.delay_slot_snapshot_instruction.has_value();
                }, instruction.statement);
                if (facts > 1'000'000) throw BudgetExceeded{};
                visit_statement_expressions(instruction.statement,
                    [&](const ExpressionPtr &value) { expression(value); });
            }
            if (block.switch_dispatch) {
                facts += block.switch_dispatch->cases.size();
                expression(block.switch_dispatch->selector);
            }
            if (facts > 1'000'000) throw BudgetExceeded{};
            for (const auto &edge : block.trap_edges) expression(edge.condition);
        }
    }
    void function(LiftedFunction &function) {
        std::size_t instructions = 0, edges = 0, inputs = 0, merges = 0;
        for (auto &block : function.blocks) {
            instructions += block.instructions.size();
            edges += block.successors.size();
            merges += block.phis.size() + block.memory_partition_phis.size() + (block.memory_phi ? 1 : 0);
            if (instructions > 200'000 || edges > 4096) throw BudgetExceeded{};
            if (merges > 16384) throw BudgetExceeded{};
            for (auto &phi : block.phis) {
                inputs += phi.inputs.size();
                for (auto &input : phi.inputs)
                    input.version = version(register_key(phi.destination, input.version));
            }
            if (block.memory_phi) {
                inputs += block.memory_phi->inputs.size();
                for (auto &input : block.memory_phi->inputs) input.version = version(memory_key(input.version));
            }
            for (auto &phi : block.memory_partition_phis) {
                inputs += phi.inputs.size();
                for (auto &input : phi.inputs) input.version = version(partition_key(phi.partition, input.version));
            }
            if (inputs > 65536) throw BudgetExceeded{};
            for (auto &instruction : block.instructions) statement(instruction.statement);
            if (block.switch_dispatch) block.switch_dispatch->selector = expression(block.switch_dispatch->selector);
            for (auto &edge : block.trap_edges) edge.condition = expression(edge.condition);
        }
    }
};

struct Merge {
    Key destination;
    std::vector<Key> inputs;
};

// Solve the copy/phi dependency graph in SCC order. A cyclic web with one
// outside value is an identity; a rootless cycle is not a known value. Iterative
// DFS avoids making the number of phis a host stack-depth limit.
std::map<Key, Key> find_aliases(const std::vector<Merge> &merges) {
    const auto count = merges.size();
    std::map<Key, std::size_t> index;
    for (std::size_t i = 0; i < count; ++i) index.emplace(merges[i].destination, i);
    std::vector<std::vector<std::size_t>> edges(count), reverse(count);
    std::size_t edge_count = 0;
    for (std::size_t i = 0; i < count; ++i) {
        edge_count += merges[i].inputs.size();
        if (edge_count > 65536) throw BudgetExceeded{};
        for (const auto &input : merges[i].inputs) {
            const auto found = index.find(input);
            if (found == index.end()) continue;
            edges[i].push_back(found->second);
            reverse[found->second].push_back(i);
        }
    }
    std::vector<bool> visited(count, false);
    std::vector<std::size_t> order;
    for (std::size_t start = 0; start < count; ++start) {
        if (visited[start]) continue;
        std::vector<std::pair<std::size_t, std::size_t>> pending{{start, 0}};
        visited[start] = true;
        while (!pending.empty()) {
            auto &[node, next] = pending.back();
            if (next < edges[node].size()) {
                const auto target = edges[node][next++];
                if (!visited[target]) {
                    visited[target] = true;
                    pending.emplace_back(target, 0);
                }
            } else {
                order.push_back(node);
                pending.pop_back();
            }
        }
    }
    const auto unset = count;
    std::vector<std::size_t> component(count, unset);
    std::vector<std::vector<std::size_t>> components;
    for (auto item = order.rbegin(); item != order.rend(); ++item) {
        if (component[*item] != unset) continue;
        const auto id = components.size();
        components.emplace_back();
        std::vector<std::size_t> pending{*item};
        component[*item] = id;
        while (!pending.empty()) {
            const auto node = pending.back();
            pending.pop_back();
            components.back().push_back(node);
            for (const auto target : reverse[node]) if (component[target] == unset) {
                component[target] = id;
                pending.push_back(target);
            }
        }
    }
    std::map<Key, Key> aliases;
    // Edges point from definitions to inputs, so dependency SCCs have larger
    // component numbers and must be resolved first.
    for (std::size_t id = components.size(); id-- > 0;) {
        std::optional<Key> root;
        bool conflict = false;
        for (const auto node : components[id]) for (const auto &input : merges[node].inputs) {
            const auto internal = index.find(input);
            if (internal != index.end() && component[internal->second] == id) continue;
            const auto resolved = aliases.find(input);
            const auto &value = resolved == aliases.end() ? input : resolved->second;
            if (root && *root != value) conflict = true;
            else root = value;
        }
        if (!root || conflict) continue;
        for (const auto node : components[id]) aliases.emplace(merges[node].destination, *root);
    }
    return aliases;
}
} // namespace

Result<LiftedFunction> simplify_redundant_phis(const LiftedFunction &input) {
    try {
        if (input.blocks.size() > 1024) throw BudgetExceeded{};
        // Bound expression walks before invoking the general SSA validator.
        const std::map<Key, Key> no_aliases;
        Rewriter preflight{no_aliases, {}};
        preflight.preflight(input);
        auto valid = validate_register_ssa(input);
        if (!valid) return valid.error();
        // Unreachable definitions are outside the validator's contract. Keep
        // them intact rather than conflating their version numbers with live IR.
        if (valid.value().reachable_blocks != input.blocks.size() || preflight.unsupported_timing) return input;

        std::vector<Merge> merges;
        const auto add = [&](Merge merge) {
            if (merges.size() >= 16384) throw BudgetExceeded{};
            merges.push_back(std::move(merge));
        };
        for (const auto &block : input.blocks) {
            for (const auto &phi : block.phis) {
                if (!supported_register(phi.destination) || phi.inputs.empty()) continue;
                Merge merge{register_key(phi.destination, phi.version), {}};
                for (const auto &incoming : phi.inputs)
                    merge.inputs.push_back(register_key(phi.destination, incoming.version));
                add(std::move(merge));
            }
            for (const auto &instruction : block.instructions) {
                const auto *assign = std::get_if<Assign>(&instruction.statement);
                if (!assign || !assign->destination_version || !assign->value ||
                    !supported_register(assign->destination)) continue;
                const auto *source = std::get_if<RegisterValue>(&assign->value->value);
                if (!source || !source->version || source->reg != assign->destination ||
                    assign->value->type.bits != source->reg.width ||
                    (assign->value->type.kind != TypeKind::integer &&
                     assign->value->type.kind != TypeKind::pointer &&
                     assign->value->type.kind != TypeKind::boolean)) continue;
                add({register_key(assign->destination, *assign->destination_version),
                     {register_key(source->reg, *source->version)}});
            }
            if (block.memory_phi && !block.memory_phi->inputs.empty()) {
                Merge merge{memory_key(block.memory_phi->version), {}};
                for (const auto &incoming : block.memory_phi->inputs)
                    merge.inputs.push_back(memory_key(incoming.version));
                add(std::move(merge));
            }
            for (const auto &phi : block.memory_partition_phis) {
                if (phi.inputs.empty()) continue;
                Merge merge{partition_key(phi.partition, phi.version), {}};
                for (const auto &incoming : phi.inputs)
                    merge.inputs.push_back(partition_key(phi.partition, incoming.version));
                add(std::move(merge));
            }
        }
        const auto aliases = find_aliases(merges);
        if (aliases.empty()) return input;
        LiftedFunction output = input;
        for (auto &block : output.blocks) {
            std::erase_if(block.phis, [&](const auto &phi) {
                return aliases.contains(register_key(phi.destination, phi.version));
            });
            if (block.memory_phi && aliases.contains(memory_key(block.memory_phi->version))) block.memory_phi.reset();
            std::erase_if(block.memory_partition_phis, [&](const auto &phi) {
                return aliases.contains(partition_key(phi.partition, phi.version));
            });
            std::erase_if(block.instructions, [&](const auto &instruction) {
                const auto *assign = std::get_if<Assign>(&instruction.statement);
                return assign && assign->destination_version &&
                    aliases.contains(register_key(assign->destination, *assign->destination_version));
            });
        }
        Rewriter rewrite{aliases, {}};
        rewrite.function(output);
        auto checked = validate_register_ssa(output);
        if (!checked) return checked.error();
        return output;
    } catch (const BudgetExceeded &) {
        return Error{ErrorCode::resource_limit, "SSA merge cleanup exceeds its analysis budget"};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "SSA merge cleanup allocation failed"};
    }
}
} // namespace hexlab::decompiler
