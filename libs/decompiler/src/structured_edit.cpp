#include "hexlab/decompiler/decompiler.hpp"

#include <new>
#include <type_traits>

namespace hexlab::decompiler {
namespace {
struct EditState {
    RegisterValue target;
    ExpressionPtr replacement;
    bool found = false;
    bool mismatch = false;
    bool invalid_address_replacement = false;
    bool invalid_call_input_replacement = false;
    bool invalid_phi_replacement = false;
};

ExpressionPtr rewrite(const ExpressionPtr &expression, EditState &state) {
    if (!expression) return {};
    if (const auto *reg = std::get_if<RegisterValue>(&expression->value);
        reg && *reg == state.target) {
        state.found = true;
        if (expression->type != state.replacement->type) state.mismatch = true;
        return state.replacement;
    }

    auto copy = *expression;
    if (auto *unary = std::get_if<UnaryValue>(&copy.value)) {
        unary->operand = rewrite(unary->operand, state);
    } else if (auto *binary = std::get_if<BinaryValue>(&copy.value)) {
        binary->left = rewrite(binary->left, state);
        binary->right = rewrite(binary->right, state);
    } else if (auto *memory = std::get_if<MemoryValue>(&copy.value)) {
        const auto replace_address_register = [&](std::optional<RegisterOperand> &reg,
                                                  std::optional<std::uint32_t> &version) {
            if (!reg || !version || *reg != state.target.reg || *version != *state.target.version)
                return;
            state.found = true;
            const auto *replacement = std::get_if<RegisterValue>(&state.replacement->value);
            if (!replacement || replacement->reg.width != reg->width) {
                state.mismatch = true;
                state.invalid_address_replacement = true;
                return;
            }
            reg = replacement->reg;
            version = replacement->version;
        };
        replace_address_register(memory->base, memory->base_version);
        replace_address_register(memory->index, memory->index_version);
    }
    return std::make_shared<Expression>(std::move(copy));
}

void rewrite_statement(Statement &statement, EditState &state) {
    std::visit([&](auto &item) {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, Assign>) {
            item.value = rewrite(item.value, state);
        } else if constexpr (std::is_same_v<T, Store>) {
            item.address = rewrite(item.address, state);
            item.value = rewrite(item.value, state);
        } else if constexpr (std::is_same_v<T, Call>) {
            item.indirect_target = rewrite(item.indirect_target, state);
            for (auto &input : item.register_inputs) {
                if (input != state.target) continue;
                state.found = true;
                const auto *replacement = std::get_if<RegisterValue>(&state.replacement->value);
                if (!replacement || !replacement->version ||
                    replacement->reg.width != input.reg.width) {
                    state.mismatch = true;
                    state.invalid_call_input_replacement = true;
                    continue;
                }
                input = *replacement;
            }
        } else if constexpr (std::is_same_v<T, Branch>) {
            item.predicate = rewrite(item.predicate, state);
            item.indirect_target = rewrite(item.indirect_target, state);
        } else if constexpr (std::is_same_v<T, Return>) {
            item.value = rewrite(item.value, state);
        } else if constexpr (std::is_same_v<T, Intrinsic>) {
            for (auto &operand : item.operands) operand = rewrite(operand, state);
            for (auto &value : item.register_output_values) value = rewrite(value, state);
        }
    }, statement);
}
} // namespace

Result<LiftedFunction> replace_register_uses(
    const LiftedFunction &input, RegisterValue target, ExpressionPtr replacement) {
    if (!target.version || !replacement)
        return Error{ErrorCode::invalid_argument, "SSA use replacement requires a versioned target and a replacement expression"};
    try {
        LiftedFunction output = input;
        EditState state{target, std::move(replacement)};
        for (auto &block : output.blocks) {
            for (auto &phi : block.phis) {
                if (phi.destination != state.target.reg) continue;
                for (auto &input : phi.inputs) {
                    if (input.version != *state.target.version) continue;
                    state.found = true;
                    const auto *replacement = std::get_if<RegisterValue>(&state.replacement->value);
                    if (!replacement || !replacement->version || replacement->reg != phi.destination) {
                        state.mismatch = true;
                        state.invalid_phi_replacement = true;
                        continue;
                    }
                    input.version = *replacement->version;
                }
            }
            for (auto &instruction : block.instructions)
                rewrite_statement(instruction.statement, state);
            if (block.switch_dispatch)
                block.switch_dispatch->selector = rewrite(block.switch_dispatch->selector, state);
            for (auto &edge : block.trap_edges)
                edge.condition = rewrite(edge.condition, state);
        }
        if (state.invalid_address_replacement)
            return Error{ErrorCode::invalid_argument, "Memory address register uses require an equal-width register replacement"};
        if (state.invalid_call_input_replacement)
            return Error{ErrorCode::invalid_argument, "Call register-input snapshots require an equal-width versioned register replacement"};
        if (state.invalid_phi_replacement)
            return Error{ErrorCode::invalid_argument, "Phi inputs require a versioned replacement of the same register"};
        if (state.mismatch)
            return Error{ErrorCode::invalid_argument, "SSA use replacement type must exactly match every target use"};
        if (!state.found)
            return Error{ErrorCode::invalid_argument, "SSA use replacement target does not occur in the function"};
        return output;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "SSA use replacement allocation failed"};
    }
}
} // namespace hexlab::decompiler
