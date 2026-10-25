#include "hexlab/decompiler/decompiler.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <tuple>
#include <type_traits>

namespace hexlab::decompiler {
namespace {
using Key = std::tuple<unsigned, unsigned, unsigned, bool, std::uint32_t>;

Key key(RegisterOperand reg, std::uint32_t version) {
    return {static_cast<unsigned>(reg.bank), reg.index, reg.width, reg.high_byte, version};
}

bool pure(const ExpressionPtr &expression) {
    if (!expression) return true;
    return std::visit([](const auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, RegisterValue> || std::is_same_v<T, ConstantValue>) return true;
        else if constexpr (std::is_same_v<T, UnaryValue>) return pure(value.operand);
        else if constexpr (std::is_same_v<T, BinaryValue>) return pure(value.left) && pure(value.right);
        else return false;
    }, expression->value);
}

void collect_uses(const ExpressionPtr &expression, std::set<Key> &uses) {
    if (!expression) return;
    std::visit([&](const auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, RegisterValue>) {
            if (value.version) uses.insert(key(value.reg, *value.version));
        } else if constexpr (std::is_same_v<T, MemoryValue>) {
            if (value.base && value.base_version) uses.insert(key(*value.base, *value.base_version));
            if (value.index && value.index_version) uses.insert(key(*value.index, *value.index_version));
        } else if constexpr (std::is_same_v<T, UnaryValue>) collect_uses(value.operand, uses);
        else if constexpr (std::is_same_v<T, BinaryValue>) {
            collect_uses(value.left, uses);
            collect_uses(value.right, uses);
        }
    }, expression->value);
}

void collect_statement_uses(const Statement &statement, std::set<Key> &uses) {
    std::visit([&](const auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, Assign>) collect_uses(value.value, uses);
        else if constexpr (std::is_same_v<T, Store>) {
            collect_uses(value.address, uses);
            collect_uses(value.value, uses);
        } else if constexpr (std::is_same_v<T, Call>) {
            collect_uses(value.indirect_target, uses);
            for (const auto &input : value.register_inputs)
                if (input.version) uses.insert(key(input.reg, *input.version));
        }
        else if constexpr (std::is_same_v<T, Branch>) {
            collect_uses(value.predicate, uses);
            collect_uses(value.indirect_target, uses);
        }
        else if constexpr (std::is_same_v<T, Return>) collect_uses(value.value, uses);
        else if constexpr (std::is_same_v<T, Intrinsic>) {
            for (const auto &operand : value.operands) collect_uses(operand, uses);
            for (const auto &output : value.register_output_values) collect_uses(output, uses);
        }
    }, statement);
}
} // namespace

Result<LiftedFunction> eliminate_dead_code(const LiftedFunction &input) {
    LiftedFunction result = input;
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

    bool changed = true;
    while (changed) {
        changed = false;
        std::set<Key> uses;
        for (const auto &block : result.blocks) {
            for (const auto &phi : block.phis)
                for (const auto &incoming : phi.inputs) uses.insert(key(phi.destination, incoming.version));
            for (const auto &instruction : block.instructions)
                collect_statement_uses(instruction.statement, uses);
        }
        for (auto &block : result.blocks) {
            const auto old_phi_count = block.phis.size();
            block.phis.erase(std::remove_if(block.phis.begin(), block.phis.end(), [&](const auto &phi) {
                return !uses.contains(key(phi.destination, phi.version));
            }), block.phis.end());
            changed |= block.phis.size() != old_phi_count;

            const auto old_instruction_count = block.instructions.size();
            block.instructions.erase(std::remove_if(block.instructions.begin(), block.instructions.end(), [&](const auto &instruction) {
                const auto *assignment = std::get_if<Assign>(&instruction.statement);
                return assignment && assignment->destination_version && pure(assignment->value) &&
                       !uses.contains(key(assignment->destination, *assignment->destination_version));
            }), block.instructions.end());
            changed |= block.instructions.size() != old_instruction_count;
        }
    }
    return result;
}
} // namespace hexlab::decompiler
