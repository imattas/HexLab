#include "hexlab/decompiler/type_recovery.hpp"

#include <algorithm>
#include <map>
#include <tuple>
#include <type_traits>

namespace hexlab::decompiler {
namespace {
using Key = std::tuple<unsigned, unsigned, unsigned, bool>;
Key key(RegisterOperand reg) {
    return {static_cast<unsigned>(reg.bank), reg.index, reg.width, reg.high_byte};
}
bool overlaps(RegisterOperand a, RegisterOperand b) {
    const auto simd = [](RegisterBank bank) {
        return bank == RegisterBank::xmm || bank == RegisterBank::ymm;
    };
    if (a.index != b.index || (a.bank != b.bank && !(simd(a.bank) && simd(b.bank)))) return false;
    const unsigned a_begin = a.high_byte ? 8 : 0, b_begin = b.high_byte ? 8 : 0;
    return a_begin < b_begin + b.width && b_begin < a_begin + a.width;
}
void collect(const ExpressionPtr &expression, std::map<Key, RegisterOperand> &registers) {
    if (!expression) return;
    std::visit([&](const auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, RegisterValue>) registers[key(value.reg)] = value.reg;
        else if constexpr (std::is_same_v<T, MemoryValue>) {
            if (value.base) registers[key(*value.base)] = *value.base;
            if (value.index) registers[key(*value.index)] = *value.index;
            if (value.stack_frame_register) registers[key(*value.stack_frame_register)] = *value.stack_frame_register;
        } else if constexpr (std::is_same_v<T, UnaryValue>) collect(value.operand, registers);
        else if constexpr (std::is_same_v<T, BinaryValue>) {
            collect(value.left, registers); collect(value.right, registers);
        }
    }, expression->value);
}
} // namespace

Result<LiftedFunction> prepare_call_effects(const LiftedFunction &input, const AbiDescription &abi) {
    if (abi.caller_saved_registers.empty()) return input;
    if (abi.caller_saved_registers.size() > 256)
        return Error{ErrorCode::resource_limit, "ABI call outputs exceed their 256-register budget"};
    std::map<Key, RegisterOperand> represented;
    for (const auto reg : abi.caller_saved_registers) {
        if (!reg.width) return Error{ErrorCode::invalid_argument, "ABI call outputs contain a zero-width register"};
        represented[key(reg)] = reg;
    }
    for (const auto &block : input.blocks) {
        for (const auto &phi : block.phis) represented[key(phi.destination)] = phi.destination;
        if (block.switch_dispatch) collect(block.switch_dispatch->selector, represented);
        for (const auto &instruction : block.instructions) std::visit([&](const auto &statement) {
            using T = std::decay_t<decltype(statement)>;
            if constexpr (std::is_same_v<T, Assign>) {
                represented[key(statement.destination)] = statement.destination;
                collect(statement.value, represented);
            } else if constexpr (std::is_same_v<T, Store>) {
                collect(statement.address, represented); collect(statement.value, represented);
            } else if constexpr (std::is_same_v<T, Call>) {
                collect(statement.indirect_target, represented);
                for (const auto &value : statement.register_inputs) represented[key(value.reg)] = value.reg;
                for (const auto reg : statement.register_writes) represented[key(reg)] = reg;
                if (statement.return_register) represented[key(*statement.return_register)] = *statement.return_register;
            } else if constexpr (std::is_same_v<T, Branch>) {
                collect(statement.predicate, represented); collect(statement.indirect_target, represented);
            } else if constexpr (std::is_same_v<T, Return>) collect(statement.value, represented);
            else if constexpr (std::is_same_v<T, Intrinsic>) {
                for (const auto &operand : statement.operands) collect(operand, represented);
                for (const auto &output : statement.register_output_values) collect(output, represented);
                for (const auto reg : statement.register_writes) represented[key(reg)] = reg;
            }
        }, instruction.statement);
    }
    LiftedFunction result = input;
    for (auto &block : result.blocks) for (auto &instruction : block.instructions) {
        auto *call = std::get_if<Call>(&instruction.statement);
        if (!call) continue;
        std::map<Key, RegisterOperand> outputs;
        auto writes = abi.caller_saved_registers;
        for (const auto reg : call->register_writes)
            if (std::find(call->abi_upper_half_writes.begin(), call->abi_upper_half_writes.end(), reg) ==
                call->abi_upper_half_writes.end())
                writes.push_back(reg);
        if (call->return_register) writes.push_back(*call->return_register);
        for (const auto reg : writes) {
            if (!reg.width) return Error{ErrorCode::invalid_argument, "Call outputs contain a zero-width register"};
            outputs[key(reg)] = reg;
        }
        call->abi_upper_half_writes.clear();
        for (const auto &[alias_key, alias] : represented) {
            // Windows preserves the low halves of XMM6-15, but not their YMM
            // upper halves. A represented whole YMM value is therefore unknown.
            const bool volatile_upper = abi.name == "x86-64 Windows" &&
                alias.bank == RegisterBank::ymm && alias.index < 16;
            if (volatile_upper) {
                outputs[alias_key] = alias;
                const bool whole_write = std::any_of(writes.begin(), writes.end(), [&](const auto reg) {
                    return overlaps(alias, reg) && reg.width >= alias.width;
                });
                if (!whole_write) call->abi_upper_half_writes.push_back(alias);
            }
            for (const auto reg : writes) {
                if (overlaps(alias, reg)) { outputs[alias_key] = alias; break; }
            }
        }
        if (outputs.size() > 256)
            return Error{ErrorCode::resource_limit, "ABI call outputs exceed their 256-register budget"};
        call->register_writes.clear();
        for (const auto &[output_key, reg] : outputs) { (void)output_key; call->register_writes.push_back(reg); }
        call->register_output_versions.clear();
        call->return_version.reset();
    }
    return result;
}
} // namespace hexlab::decompiler
