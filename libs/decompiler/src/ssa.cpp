#include "hexlab/decompiler/decompiler.hpp"

#include <algorithm>
#include <bit>
#include <functional>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <tuple>

namespace hexlab::decompiler {
namespace {
using Key = std::tuple<unsigned, unsigned, unsigned, bool>;
Key key(RegisterOperand reg) { return {static_cast<unsigned>(reg.bank), reg.index, reg.width, reg.high_byte}; }
using AbsoluteMemoryRange = std::tuple<std::uint32_t, std::uint64_t, std::uint64_t>;
using AbsoluteMemoryPartitions = std::map<AbsoluteMemoryRange, std::string>;
using PointerRoot = std::pair<Key, std::uint32_t>;
struct PointerOrigin { PointerRoot root; std::int64_t offset = 0; bool operator==(const PointerOrigin &) const = default; };
using PointerValueKey = std::pair<Key, std::uint32_t>;
using PointerOrigins = std::map<PointerValueKey, PointerOrigin>;
using IntegerConstants = std::map<PointerValueKey, std::uint64_t>;
using FlatAddressRootKey = std::pair<unsigned, unsigned>;
using FlatAddressRoots = std::map<FlatAddressRootKey, PointerRoot>;
using DynamicMemoryRange = std::tuple<PointerRoot, std::int64_t, std::int64_t>;
using DynamicMemoryPartitions = std::map<DynamicMemoryRange, std::string>;

std::optional<std::int64_t> add_signed(std::int64_t left, std::int64_t right) {
    if ((right > 0 && left > std::numeric_limits<std::int64_t>::max() - right) ||
        (right < 0 && left < std::numeric_limits<std::int64_t>::min() - right)) return {};
    return left + right;
}

std::optional<std::uint64_t> integer_constant(const ExpressionPtr &expression,
                                              const IntegerConstants &constants);

std::optional<PointerOrigin> pointer_origin(const ExpressionPtr &expression, const PointerOrigins &origins,
                                            const IntegerConstants &constants) {
    if (!expression) return {};
    if (const auto *reg = std::get_if<RegisterValue>(&expression->value)) {
        if (!reg->version || !expression->type.bits || expression->type.bits != reg->reg.width) return {};
        const auto found = origins.find({key(reg->reg), *reg->version});
        return found == origins.end() ? std::optional<PointerOrigin>{} : found->second;
    }
    const auto *binary = std::get_if<BinaryValue>(&expression->value);
    if (!binary || (binary->operation != "add" && binary->operation != "sub")) return {};
    if (!expression->type.bits || !binary->left || !binary->right ||
        binary->left->type.bits != expression->type.bits || binary->right->type.bits != expression->type.bits)
        return {};
    auto left = pointer_origin(binary->left, origins, constants);
    auto offset_constant = integer_constant(binary->right, constants);
    if (!left && binary->operation == "add") {
        left = pointer_origin(binary->right, origins, constants);
        offset_constant = integer_constant(binary->left, constants);
    }
    if (!left || !offset_constant || std::get<2>(left->root.first) != expression->type.bits ||
        *offset_constant > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) return {};
    auto delta = static_cast<std::int64_t>(*offset_constant);
    if (binary->operation == "sub") delta = -delta;
    const auto offset = add_signed(left->offset, delta);
    if (!offset) return {};
    left->offset = *offset;
    return left;
}

std::optional<std::uint64_t> integer_constant(const ExpressionPtr &expression,
                                              const IntegerConstants &constants) {
    const auto evaluate = [&](const auto &self, const ExpressionPtr &node, unsigned depth)
        -> std::optional<std::uint64_t> {
        constexpr unsigned max_constant_expression_depth = 32;
        if (depth > max_constant_expression_depth || !node ||
            node->type.kind != TypeKind::integer || !node->type.bits || node->type.bits > 64) return {};
        const auto width = node->type.bits;
        const auto mask = width == 64 ? std::numeric_limits<std::uint64_t>::max()
                                      : (std::uint64_t{1} << width) - 1;
        if (const auto *constant = std::get_if<ConstantValue>(&node->value)) {
            if (constant->type.kind != TypeKind::integer || constant->type.bits != width ||
                constant->value > mask) return {};
            return constant->value;
        }
        if (const auto *reg = std::get_if<RegisterValue>(&node->value)) {
            if (!reg->version || reg->reg.width != width) return {};
            const auto found = constants.find({key(reg->reg), *reg->version});
            if (found != constants.end() && found->second <= mask) return found->second;
            return {};
        }
        const auto *binary = std::get_if<BinaryValue>(&node->value);
        if (!binary || !binary->left || !binary->right ||
            binary->left->type.kind != TypeKind::integer || binary->right->type.kind != TypeKind::integer ||
            binary->left->type.bits != width || binary->right->type.bits != width ||
            (binary->operation != "add" && binary->operation != "sub" && binary->operation != "mul")) return {};
        const auto left = self(self, binary->left, depth + 1);
        const auto right = self(self, binary->right, depth + 1);
        if (!left || !right) return {};
        if (binary->operation == "add") {
            if (*right > mask - *left) return {};
            return *left + *right;
        }
        if (binary->operation == "sub") {
            if (*left < *right) return {};
            return *left - *right;
        }
        if (*right && *left > mask / *right) return {};
        return *left * *right;
    };
    return evaluate(evaluate, expression, 0);
}

std::optional<std::int64_t> flat_address_constant(PointerValueKey value,
                                                  const IntegerConstants &constants) {
    const auto bank = std::get<0>(value.first);
    const auto width = std::get<2>(value.first);
    // These register banks have flat, unsegmented address calculations in the
    // supported profiles. The generic x86 GPR bank is intentionally excluded:
    // a segment override can make equal offsets refer to different addresses.
    if (bank != static_cast<unsigned>(RegisterBank::arm32_gpr) &&
        bank != static_cast<unsigned>(RegisterBank::arm64_gpr) &&
        bank != static_cast<unsigned>(RegisterBank::riscv_gpr) &&
        bank != static_cast<unsigned>(RegisterBank::mips_gpr) &&
        bank != static_cast<unsigned>(RegisterBank::ppc_gpr)) return {};
    if (width != 32 && width != 64) return {};
    const auto found = constants.find(value);
    if (found == constants.end() || found->second > static_cast<std::uint64_t>(
            std::numeric_limits<std::int64_t>::max())) return {};
    return static_cast<std::int64_t>(found->second);
}

std::optional<DynamicMemoryRange> dynamic_memory_range(const MemoryValue &memory, const PointerOrigins &origins,
                                                       const IntegerConstants &constants) {
    if (!memory.base || memory.absolute || !memory.type.bits || memory.type.bits % 8 ||
        !memory.base_version) return {};
    const auto found = origins.find({key(*memory.base), *memory.base_version});
    if (found == origins.end()) return {};
    if (std::get<2>(found->second.root.first) != memory.base->width) return {};
    auto displacement = memory.displacement;
    if (memory.index) {
        if (!memory.index_version ||
            (memory.index_shift != "" && memory.index_shift != "lsl")) return {};
        const auto index = constants.find({key(*memory.index), *memory.index_version});
        if (index == constants.end()) return {};
        std::optional<std::int64_t> index_value;
        if (memory.index_extend.empty()) {
            if (memory.index->width != memory.base->width ||
                index->second > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) return {};
            index_value = static_cast<std::int64_t>(index->second);
        } else if (memory.index_extend == "uxtw") {
            if (memory.index->width != 32 || index->second > std::numeric_limits<std::uint32_t>::max()) return {};
            index_value = static_cast<std::int64_t>(index->second);
        } else if (memory.index_extend == "sxtw") {
            if (memory.index->width != 32 || index->second > std::numeric_limits<std::uint32_t>::max()) return {};
            index_value = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(index->second));
        } else if (memory.index_extend == "sxtx") {
            if (memory.index->width != 64 || memory.base->width != 64) return {};
            index_value = std::bit_cast<std::int64_t>(index->second);
        } else if (memory.index_extend == "uxtx") {
            // UXTX (also rendered by A64 assemblers as LSL when the shift is
            // present) preserves the full 64-bit unsigned index. Dynamic
            // partition offsets are signed, so values outside that domain
            // cannot be represented without wrapping and must stay on the
            // whole-memory chain.
            if (memory.index->width != 64 || memory.base->width != 64 ||
                index->second > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) return {};
            index_value = static_cast<std::int64_t>(index->second);
        } else {
            return {};
        }
        const auto shift = static_cast<unsigned>(memory.index_shift_amount);
        if (shift >= 63 || memory.scale == 0 ||
            static_cast<std::uint64_t>(memory.scale) >
                (static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) >> shift)) return {};
        const auto factor = static_cast<std::int64_t>(static_cast<std::uint64_t>(memory.scale) << shift);
        if (*index_value > std::numeric_limits<std::int64_t>::max() / factor ||
            *index_value < std::numeric_limits<std::int64_t>::min() / factor) return {};
        auto delta = *index_value * factor;
        if (!memory.index_add) {
            if (delta == std::numeric_limits<std::int64_t>::min()) return {};
            delta = -delta;
        }
        const auto adjusted = add_signed(displacement, delta);
        if (!adjusted) return {};
        displacement = *adjusted;
    }
    const auto begin = add_signed(found->second.offset, displacement);
    const auto bytes = static_cast<std::int64_t>(memory.type.bits / 8);
    if (!begin || bytes <= 0 || *begin > std::numeric_limits<std::int64_t>::max() - bytes) return {};
    const auto address_width = std::get<2>(found->second.root.first);
    if (address_width < 2) return {};
    const auto offset_limit_bits = std::min(address_width - 2, 60u);
    const auto conservative_offset_limit = std::int64_t{1} << offset_limit_bits;
    if (*begin < -conservative_offset_limit || *begin + bytes > conservative_offset_limit) return {};
    return DynamicMemoryRange{found->second.root, *begin, *begin + bytes};
}
bool is_absolute_memory_partition(const std::string &partition) {
    return partition.starts_with("\x1fglobal:");
}

std::optional<AbsoluteMemoryRange> absolute_memory_range(const MemoryValue &memory) {
    if (!memory.absolute || memory.base || memory.index || !memory.type.bits || memory.type.bits % 8)
        return {};
    const auto bytes = static_cast<std::uint64_t>(memory.type.bits / 8);
    if (!bytes || bytes > 256 || memory.absolute->offset > std::numeric_limits<std::uint64_t>::max() - bytes)
        return {};
    return AbsoluteMemoryRange{memory.absolute->space.value, memory.absolute->offset,
                               memory.absolute->offset + bytes};
}

void collect_expression(const ExpressionPtr &expression, std::set<Key> &variables) {
    if (!expression) return;
    std::visit([&](const auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, RegisterValue>) variables.insert(key(value.reg));
        else if constexpr (std::is_same_v<T, MemoryValue>) {
            if (value.base) variables.insert(key(*value.base));
            if (value.index) variables.insert(key(*value.index));
        } else if constexpr (std::is_same_v<T, UnaryValue>) collect_expression(value.operand, variables);
        else if constexpr (std::is_same_v<T, BinaryValue>) {
            collect_expression(value.left, variables);
            collect_expression(value.right, variables);
        }
    }, expression->value);
}

void rename_expression(ExpressionPtr &expression, const std::map<Key, std::vector<std::uint32_t>> &stacks) {
    if (!expression) return;
    auto copy = std::make_shared<Expression>(*expression);
    std::visit([&](auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, RegisterValue>) {
            // JVM stack values and phis are already SSA, including old values
            // referenced after parallel edge transport and stack permutations.
            if (value.reg.bank != RegisterBank::jvm_stack)
                value.version = stacks.at(key(value.reg)).back();
        }
        else if constexpr (std::is_same_v<T, MemoryValue>) {
            if (value.base) value.base_version = stacks.at(key(*value.base)).back();
            if (value.index) value.index_version = stacks.at(key(*value.index)).back();
        } else if constexpr (std::is_same_v<T, UnaryValue>) rename_expression(value.operand, stacks);
        else if constexpr (std::is_same_v<T, BinaryValue>) {
            rename_expression(value.left, stacks);
            rename_expression(value.right, stacks);
        }
    }, copy->value);
    expression = std::move(copy);
}

void rename_memory(ExpressionPtr &expression, std::uint32_t version) {
    if (!expression) return;
    auto copy = std::make_shared<Expression>(*expression);
    std::visit([&](auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, MemoryValue>) value.memory_version = version;
        else if constexpr (std::is_same_v<T, UnaryValue>) rename_memory(value.operand, version);
        else if constexpr (std::is_same_v<T, BinaryValue>) {
            rename_memory(value.left, version); rename_memory(value.right, version);
        }
    }, copy->value);
    expression = std::move(copy);
}

void clear_partition_memory(ExpressionPtr &expression) {
    if (!expression) return;
    auto copy = std::make_shared<Expression>(*expression);
    std::visit([&](auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, MemoryValue>) {
            value.memory_partition.reset();
            value.memory_partition_version.reset();
        } else if constexpr (std::is_same_v<T, UnaryValue>) clear_partition_memory(value.operand);
        else if constexpr (std::is_same_v<T, BinaryValue>) {
            clear_partition_memory(value.left); clear_partition_memory(value.right);
        }
    }, copy->value);
    expression = std::move(copy);
}

void rename_partition_memory(ExpressionPtr &expression,
                             const std::map<std::string, std::uint32_t> &versions,
                             const AbsoluteMemoryPartitions &absolute_partitions,
                             const DynamicMemoryPartitions &dynamic_partitions,
                             const PointerOrigins &pointer_origins,
                             const IntegerConstants &integer_constants) {
    if (!expression) return;
    auto copy = std::make_shared<Expression>(*expression);
    std::visit([&](auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, MemoryValue>) {
            std::optional<std::string> partition;
            if (value.stack_variable) {
                partition = *value.stack_variable;
            } else if (const auto range = absolute_memory_range(value)) {
                const auto found = absolute_partitions.find(*range);
                if (found != absolute_partitions.end()) partition = found->second;
            } else if (const auto range = dynamic_memory_range(value, pointer_origins, integer_constants)) {
                const auto found = dynamic_partitions.find(*range);
                if (found != dynamic_partitions.end()) partition = found->second;
            }
            if (partition) {
                const auto found = versions.find(*partition);
                if (found != versions.end()) {
                    value.memory_partition = found->first;
                    value.memory_partition_version = found->second;
                }
            }
        } else if constexpr (std::is_same_v<T, UnaryValue>)
            rename_partition_memory(value.operand, versions, absolute_partitions, dynamic_partitions, pointer_origins,
                                    integer_constants);
        else if constexpr (std::is_same_v<T, BinaryValue>) {
            rename_partition_memory(value.left, versions, absolute_partitions, dynamic_partitions, pointer_origins,
                                    integer_constants);
            rename_partition_memory(value.right, versions, absolute_partitions, dynamic_partitions, pointer_origins,
                                    integer_constants);
        }
    }, copy->value);
    expression = std::move(copy);
}

void collect_stack_partitions(const ExpressionPtr &expression, std::set<std::string> &partitions) {
    if (!expression) return;
    std::visit([&](const auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, MemoryValue>) {
            if (value.stack_variable) partitions.insert(*value.stack_variable);
        } else if constexpr (std::is_same_v<T, UnaryValue>) collect_stack_partitions(value.operand, partitions);
        else if constexpr (std::is_same_v<T, BinaryValue>) {
            collect_stack_partitions(value.left, partitions);
            collect_stack_partitions(value.right, partitions);
        }
    }, expression->value);
}

void collect_absolute_memory_ranges(const ExpressionPtr &expression,
                                    std::set<AbsoluteMemoryRange> &ranges,
                                    std::size_t maximum, bool &overflow) {
    if (!expression) return;
    std::visit([&](const auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, MemoryValue>) {
            if (const auto range = absolute_memory_range(value); range && !ranges.contains(*range)) {
                if (ranges.size() >= maximum) overflow = true;
                else ranges.insert(*range);
            }
        } else if constexpr (std::is_same_v<T, UnaryValue>) {
            collect_absolute_memory_ranges(value.operand, ranges, maximum, overflow);
        } else if constexpr (std::is_same_v<T, BinaryValue>) {
            collect_absolute_memory_ranges(value.left, ranges, maximum, overflow);
            collect_absolute_memory_ranges(value.right, ranges, maximum, overflow);
        }
    }, expression->value);
}

void clear_memory_versions(ExpressionPtr &expression) {
    if (!expression) return;
    auto copy = std::make_shared<Expression>(*expression);
    std::visit([&](auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, MemoryValue>) value.memory_version.reset();
        else if constexpr (std::is_same_v<T, UnaryValue>) clear_memory_versions(value.operand);
        else if constexpr (std::is_same_v<T, BinaryValue>) {
            clear_memory_versions(value.left); clear_memory_versions(value.right);
        }
    }, copy->value);
    expression = std::move(copy);
}

void rename_memory_expression(ExpressionPtr &expression, std::uint32_t version) {
    if (!expression) return;
    auto copy = std::make_shared<Expression>(*expression);
    std::visit([&](auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, MemoryValue>) value.memory_version = version;
        else if constexpr (std::is_same_v<T, UnaryValue>) rename_memory_expression(value.operand, version);
        else if constexpr (std::is_same_v<T, BinaryValue>) {
            rename_memory_expression(value.left, version);
            rename_memory_expression(value.right, version);
        }
    }, copy->value);
    expression = std::move(copy);
}

bool contains_memory_read(const ExpressionPtr &expression) {
    if (!expression) return false;
    return std::visit([&](const auto &value) -> bool {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, MemoryValue>) return true;
        else if constexpr (std::is_same_v<T, UnaryValue>) return contains_memory_read(value.operand);
        else if constexpr (std::is_same_v<T, BinaryValue>)
            return contains_memory_read(value.left) || contains_memory_read(value.right);
        return false;
    }, expression->value);
}

void collect_statement(const Statement &statement, std::set<Key> &variables, std::set<Key> &definitions) {
    std::visit([&](const auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, Assign>) {
            variables.insert(key(value.destination));
            definitions.insert(key(value.destination));
            collect_expression(value.value, variables);
        } else if constexpr (std::is_same_v<T, Store>) {
            collect_expression(value.address, variables); collect_expression(value.value, variables);
        } else if constexpr (std::is_same_v<T, Call>) {
            collect_expression(value.indirect_target, variables);
            for (const auto reg : value.register_writes) {
                variables.insert(key(reg));
                definitions.insert(key(reg));
            }
            if (value.return_register) {
                variables.insert(key(*value.return_register));
                definitions.insert(key(*value.return_register));
            }
        }
        else if constexpr (std::is_same_v<T, Return>) collect_expression(value.value, variables);
        else if constexpr (std::is_same_v<T, Branch>) {
            collect_expression(value.predicate, variables);
            collect_expression(value.indirect_target, variables);
        }
        else if constexpr (std::is_same_v<T, Intrinsic>) {
            for (const auto &operand : value.operands) collect_expression(operand, variables);
            for (const auto &output : value.register_output_values) collect_expression(output, variables);
            for (const auto reg : value.register_writes) {
                variables.insert(key(reg));
                definitions.insert(key(reg));
            }
        }
    }, statement);
}
} // namespace

Result<LiftedFunction> to_ssa(const LiftedFunction &input,
                              std::span<const RegisterOperand> call_argument_registers) {
    if (input.blocks.empty()) return Error{ErrorCode::invalid_argument, "SSA conversion requires at least one block"};
    if (call_argument_registers.size() > 256)
        return Error{ErrorCode::resource_limit, "SSA call snapshot exceeds its 256-register budget"};
    std::vector<RegisterOperand> tracked_call_registers;
    std::set<Key> tracked_call_keys;
    tracked_call_registers.reserve(call_argument_registers.size());
    for (const auto reg : call_argument_registers) {
        if (!reg.width) return Error{ErrorCode::invalid_argument, "SSA call snapshot contains a zero-width register"};
        if (tracked_call_keys.insert(key(reg)).second) tracked_call_registers.push_back(reg);
    }
    for (const auto &block : input.blocks) for (const auto &instruction : block.instructions)
        if (const auto *call = std::get_if<Call>(&instruction.statement)) {
            if (call->register_writes.size() > 256)
                return Error{ErrorCode::resource_limit, "SSA call outputs exceed their 256-register budget"};
            std::set<Key> outputs;
            for (const auto reg : call->register_writes)
                if (!reg.width || !outputs.insert(key(reg)).second)
                    return Error{ErrorCode::invalid_argument, "SSA call outputs contain a zero-width or duplicate register"};
        }
    for (const auto &block : input.blocks) for (const auto &instruction : block.instructions)
        if (const auto *intrinsic = std::get_if<Intrinsic>(&instruction.statement))
            if (intrinsic->register_writes.size() > 256)
                return Error{ErrorCode::resource_limit, "SSA intrinsic outputs exceed their 256-register budget"};
            else {
                std::set<Key> outputs;
                for (const auto reg : intrinsic->register_writes)
                    if (!reg.width || !outputs.insert(key(reg)).second)
                        return Error{ErrorCode::invalid_argument,
                                     "SSA intrinsic outputs contain a zero-width or duplicate register"};
            }
    for (const auto &block : input.blocks) for (const auto &instruction : block.instructions)
        if (const auto *intrinsic = std::get_if<Intrinsic>(&instruction.statement))
            if (!intrinsic->register_output_values.empty() &&
                intrinsic->register_output_values.size() != intrinsic->register_writes.size())
                return Error{ErrorCode::invalid_argument, "intrinsic output formulas must match register outputs"};
            else if (std::any_of(intrinsic->register_output_values.begin(), intrinsic->register_output_values.end(),
                                 [](const auto &value) { return !value; }))
                return Error{ErrorCode::invalid_argument, "intrinsic output formula is null"};
    LiftedFunction result = input;
    const std::size_t count = result.blocks.size();
    std::vector<std::vector<LiftedBlock::Phi>> jvm_stack_phis(count);
    std::map<std::uint64_t, std::size_t> ids;
    std::map<std::pair<std::uint32_t, std::uint64_t>, std::size_t> addresses;
    for (std::size_t i = 0; i < count; ++i) {
        if (!ids.emplace(result.blocks[i].id.value, i).second)
            return Error{ErrorCode::invalid_argument, "SSA function contains duplicate block IDs"};
        if (!addresses.emplace(std::pair{result.blocks[i].begin.space.value, result.blocks[i].begin.offset}, i).second)
            return Error{ErrorCode::invalid_argument, "SSA function contains duplicate block addresses"};
        for (const auto &phi : result.blocks[i].phis)
            if (phi.destination.bank == RegisterBank::jvm_stack) jvm_stack_phis[i].push_back(phi);
        result.blocks[i].phis.clear();
        result.blocks[i].memory_phi.reset();
        result.blocks[i].memory_partition_phis.clear();
        for (auto &instruction : result.blocks[i].instructions) std::visit([&](auto &statement) {
            using T = std::decay_t<decltype(statement)>;
            if constexpr (std::is_same_v<T, Assign>) {
                clear_memory_versions(statement.value);
                clear_partition_memory(statement.value);
            }
            else if constexpr (std::is_same_v<T, Store>) {
                statement.memory_input_version.reset(); statement.memory_output_version.reset();
                statement.memory_partition.reset();
                statement.memory_partition_effects.clear();
                clear_memory_versions(statement.address); clear_memory_versions(statement.value);
                clear_partition_memory(statement.address); clear_partition_memory(statement.value);
            } else if constexpr (std::is_same_v<T, Call>) {
                statement.memory_input_version.reset(); statement.memory_output_version.reset();
                statement.memory_partition_effects.clear();
                if (statement.x86_stack_effect)
                    statement.x86_stack_effect->memory_input_version.reset();
                statement.register_inputs.clear();
                statement.return_version.reset();
                statement.register_output_versions.clear();
                clear_memory_versions(statement.indirect_target);
                clear_partition_memory(statement.indirect_target);
            }
            else if constexpr (std::is_same_v<T, Return>) {
                if (statement.x86_stack_effect)
                    statement.x86_stack_effect->memory_input_version.reset();
                clear_memory_versions(statement.value);
                clear_partition_memory(statement.value);
            }
            else if constexpr (std::is_same_v<T, Branch>) {
                clear_memory_versions(statement.predicate);
                clear_memory_versions(statement.indirect_target);
                clear_partition_memory(statement.predicate);
                clear_partition_memory(statement.indirect_target);
            }
            else if constexpr (std::is_same_v<T, Intrinsic>) {
                statement.memory_input_version.reset(); statement.memory_output_version.reset();
                statement.memory_partition_effects.clear();
                statement.register_output_versions.clear();
                for (auto &operand : statement.operands) {
                    clear_memory_versions(operand);
                    clear_partition_memory(operand);
                }
            }
        }, instruction.statement);
        if (result.blocks[i].switch_dispatch)
            clear_memory_versions(result.blocks[i].switch_dispatch->selector);
        if (result.blocks[i].switch_dispatch)
            clear_partition_memory(result.blocks[i].switch_dispatch->selector);
    }
    const auto entry_address = addresses.find({result.entry.space.value, result.entry.offset});
    if (entry_address == addresses.end())
        return Error{ErrorCode::invalid_argument, "SSA function entry has no recovered block"};
    const std::size_t entry = entry_address->second;

    std::vector<std::set<std::size_t>> predecessors(count), successors(count);
    for (std::size_t i = 0; i < count; ++i) for (const auto &edge : result.blocks[i].successors) {
        std::optional<std::size_t> target;
        if (edge.block) {
            const auto found = ids.find(edge.block->value);
            if (found != ids.end()) target = found->second;
        } else if (edge.target) {
            const auto found = addresses.find({edge.target->space.value, edge.target->offset});
            if (found != addresses.end()) target = found->second;
        }
        if (target) { successors[i].insert(*target); predecessors[*target].insert(i); }
    }
    using ExceptionMemoryEdge = LiftedBlock::ExceptionMemoryEdge;
    std::map<std::pair<std::size_t, std::size_t>, ExceptionMemoryEdge> exception_memory_edges;
    for (std::size_t source = 0; source < count; ++source)
        for (const auto &edge : result.blocks[source].exception_memory_edges) {
            const auto target = addresses.find({edge.target.space.value, edge.target.offset});
            if (target == addresses.end() || !successors[source].contains(target->second) ||
                std::none_of(result.blocks[source].successors.begin(), result.blocks[source].successors.end(),
                    [&](const auto &successor) {
                        return successor.kind == BlockEdgeKind::exception && successor.source == edge.source &&
                               successor.target == edge.target;
                    }))
                return Error{ErrorCode::invalid_argument, "SSA exception memory edge disagrees with CFG"};
            if (std::any_of(result.blocks[source].successors.begin(), result.blocks[source].successors.end(),
                    [&](const auto &successor) {
                        return successor.kind != BlockEdgeKind::exception &&
                               ((successor.target && *successor.target == edge.target) ||
                                (successor.block && successor.block->value == result.blocks[target->second].id.value));
                    }))
                return Error{ErrorCode::invalid_argument,
                    "SSA cannot merge ordinary and exceptional memory on parallel edges"};
            if (!exception_memory_edges.emplace(std::pair{source, target->second}, edge).second)
                return Error{ErrorCode::invalid_argument, "SSA has multiple memory states for one exception edge"};
            if (edge.timing == LiftedBlock::ExceptionMemoryTiming::opaque_effect &&
                std::none_of(result.blocks[source].instructions.begin(), result.blocks[source].instructions.end(),
                    [&](const auto &instruction) {
                        const auto *intrinsic = std::get_if<Intrinsic>(&instruction.statement);
                        return instruction.origin.address == edge.source && intrinsic &&
                               intrinsic->memory_effect == IntrinsicMemoryEffect::unknown;
                    }))
                return Error{ErrorCode::invalid_argument, "opaque exception edge has no unknown memory effect"};
        }

    std::set<std::size_t> reachable{entry};
    std::vector<std::size_t> pending{entry};
    while (!pending.empty()) {
        const auto current = pending.back(); pending.pop_back();
        for (auto next : successors[current]) if (reachable.insert(next).second) pending.push_back(next);
    }

    std::vector<std::set<std::size_t>> dominators(count);
    for (auto block : reachable) dominators[block] = block == entry ? std::set<std::size_t>{entry} : reachable;
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto block : reachable) {
            if (block == entry) continue;
            std::set<std::size_t> next;
            bool first = true;
            for (auto pred : predecessors[block]) if (reachable.contains(pred)) {
                if (first) { next = dominators[pred]; first = false; }
                else {
                    std::set<std::size_t> intersection;
                    std::set_intersection(next.begin(), next.end(), dominators[pred].begin(), dominators[pred].end(),
                                          std::inserter(intersection, intersection.end()));
                    next = std::move(intersection);
                }
            }
            next.insert(block);
            if (next != dominators[block]) { dominators[block] = std::move(next); changed = true; }
        }
    }

    std::vector<std::optional<std::size_t>> idom(count);
    std::vector<std::vector<std::size_t>> dom_children(count);
    for (auto block : reachable) if (block != entry) {
        for (auto candidate : dominators[block]) if (candidate != block &&
             (!idom[block] || dominators[candidate].size() > dominators[*idom[block]].size())) idom[block] = candidate;
        if (idom[block]) dom_children[*idom[block]].push_back(block);
    }
    std::vector<std::set<std::size_t>> frontier(count);
    for (auto block : reachable) {
        std::size_t pred_count = 0;
        for (auto pred : predecessors[block]) pred_count += reachable.contains(pred);
        if (pred_count < 2 || !idom[block]) continue;
        for (auto pred : predecessors[block]) if (reachable.contains(pred)) {
            auto runner = pred;
            while (runner != *idom[block]) {
                frontier[runner].insert(block);
                if (!idom[runner]) break;
                runner = *idom[runner];
            }
        }
    }

    std::set<Key> variables;
    std::map<Key, std::set<std::size_t>> definition_blocks;
    std::map<Key, RegisterOperand> registers;
    std::set<std::size_t> memory_definitions;
    for (auto block : reachable) for (const auto &instruction : result.blocks[block].instructions) {
        std::set<Key> definitions;
        collect_statement(instruction.statement, variables, definitions);
        for (const auto &key_value : definitions)
            if (std::get<0>(key_value) != static_cast<unsigned>(RegisterBank::jvm_stack))
                definition_blocks[key_value].insert(block);
        const bool defines_memory = std::visit([](const auto &statement) {
            using T = std::decay_t<decltype(statement)>;
            if constexpr (std::is_same_v<T, Store> || std::is_same_v<T, Call>) return true;
            else if constexpr (std::is_same_v<T, Intrinsic>)
                return statement.memory_effect == IntrinsicMemoryEffect::write ||
                       statement.memory_effect == IntrinsicMemoryEffect::unknown;
            else return false;
        }, instruction.statement);
        if (defines_memory) memory_definitions.insert(block);
        std::visit([&](const auto &statement) {
            using T = std::decay_t<decltype(statement)>;
            if constexpr (std::is_same_v<T, Assign>) registers[key(statement.destination)] = statement.destination;
            else if constexpr (std::is_same_v<T, Call>) {
                if (statement.return_register) registers[key(*statement.return_register)] = *statement.return_register;
                for (const auto reg : statement.register_writes) registers[key(reg)] = reg;
            }
            else if constexpr (std::is_same_v<T, Intrinsic>)
                for (const auto reg : statement.register_writes) registers[key(reg)] = reg;
        }, instruction.statement);
        std::function<void(const ExpressionPtr &)> save_regs = [&](const ExpressionPtr &expression) {
            if (!expression) return;
            std::visit([&](const auto &value) {
                using T = std::decay_t<decltype(value)>;
                if constexpr (std::is_same_v<T, RegisterValue>) registers[key(value.reg)] = value.reg;
                else if constexpr (std::is_same_v<T, MemoryValue>) {
                    if (value.base) registers[key(*value.base)] = *value.base;
                    if (value.index) registers[key(*value.index)] = *value.index;
                } else if constexpr (std::is_same_v<T, UnaryValue>) save_regs(value.operand);
                else if constexpr (std::is_same_v<T, BinaryValue>) { save_regs(value.left); save_regs(value.right); }
            }, expression->value);
        };
        std::visit([&](const auto &statement) {
            using T = std::decay_t<decltype(statement)>;
            if constexpr (std::is_same_v<T, Assign>) save_regs(statement.value);
            else if constexpr (std::is_same_v<T, Store>) { save_regs(statement.address); save_regs(statement.value); }
            else if constexpr (std::is_same_v<T, Call>) save_regs(statement.indirect_target);
            else if constexpr (std::is_same_v<T, Return>) save_regs(statement.value);
            else if constexpr (std::is_same_v<T, Branch>) {
                save_regs(statement.predicate);
                save_regs(statement.indirect_target);
            }
            else if constexpr (std::is_same_v<T, Intrinsic>) {
                for (const auto &operand : statement.operands) save_regs(operand);
                for (const auto &output : statement.register_output_values) save_regs(output);
            }
        }, instruction.statement);
    }
    for (const auto reg : tracked_call_registers) {
        const auto variable = key(reg);
        variables.insert(variable);
        registers[variable] = reg;
    }
    for (auto block : reachable) if (result.blocks[block].switch_dispatch &&
        result.blocks[block].switch_dispatch->selector) {
        collect_expression(result.blocks[block].switch_dispatch->selector, variables);
        std::function<void(const ExpressionPtr &)> save_switch_regs = [&](const ExpressionPtr &expression) {
            if (!expression) return;
            std::visit([&](const auto &value) {
                using T = std::decay_t<decltype(value)>;
                if constexpr (std::is_same_v<T, RegisterValue>) registers[key(value.reg)] = value.reg;
                else if constexpr (std::is_same_v<T, UnaryValue>) save_switch_regs(value.operand);
                else if constexpr (std::is_same_v<T, BinaryValue>) {
                    save_switch_regs(value.left); save_switch_regs(value.right);
                }
            }, expression->value);
        };
        save_switch_regs(result.blocks[block].switch_dispatch->selector);
    }

    // This bank is owned by the JVM lifter's stack-shape/phi pass. Rebuilding
    // it from sequential register writes would lose explicit older versions.
    std::erase_if(variables, [](const auto &variable) {
        return std::get<0>(variable) == static_cast<unsigned>(RegisterBank::jvm_stack);
    });
    if (!memory_definitions.empty()) {
        std::vector<std::size_t> work(memory_definitions.begin(), memory_definitions.end());
        std::set<std::size_t> placed;
        while (!work.empty()) {
            const auto block = work.back(); work.pop_back();
            for (auto join : frontier[block]) if (placed.insert(join).second) {
                result.blocks[join].memory_phi = LiftedBlock::MemoryPhi{};
                if (!memory_definitions.contains(join)) work.push_back(join);
            }
        }
    }
    // A single exceptional predecessor still needs its own input: the normal
    // dominator stack contains the throwing instruction's success state.
    for (const auto &[edge, timing] : exception_memory_edges) {
        (void)timing;
        if (reachable.contains(edge.first) && reachable.contains(edge.second))
            result.blocks[edge.second].memory_phi = LiftedBlock::MemoryPhi{};
    }

    std::vector<std::map<Key, std::size_t>> phi_positions(count);
    for (const auto &variable : variables) {
        std::vector<std::size_t> work(definition_blocks[variable].begin(), definition_blocks[variable].end());
        std::set<std::size_t> visited;
        while (!work.empty()) {
            const auto block = work.back(); work.pop_back();
            for (auto join : frontier[block]) if (visited.insert(join).second) {
                auto &phis = result.blocks[join].phis;
                const auto position = phis.size();
                phis.push_back({registers.at(variable), 0, {}});
                phi_positions[join].emplace(variable, position);
                if (!definition_blocks[variable].contains(join)) work.push_back(join);
            }
        }
    }
    for (auto &block : result.blocks) std::sort(block.phis.begin(), block.phis.end(),
        [](const auto &a, const auto &b) { return key(a.destination) < key(b.destination); });
    // Sorting changes phi slots, so rebuild their register-to-position index.
    for (auto &positions : phi_positions) positions.clear();
    for (auto block : reachable) for (std::size_t p = 0; p < result.blocks[block].phis.size(); ++p)
        phi_positions[block].emplace(key(result.blocks[block].phis[p].destination), p);

    std::map<Key, std::vector<std::uint32_t>> stacks;
    std::map<Key, std::uint32_t> counters;
    std::vector<std::uint32_t> memory_stack{0};
    std::uint32_t memory_counter = 0;
    for (const auto &variable : variables) stacks[variable].push_back(0);
    using VersionSnapshot = std::map<Key, std::uint32_t>;
    using SnapshotPoint = std::pair<std::uint64_t, std::uint64_t>;
    std::map<SnapshotPoint, VersionSnapshot> instruction_input_versions;
    std::map<std::uint64_t, VersionSnapshot> block_exit_versions;
    std::map<SnapshotPoint, std::uint32_t> instruction_input_memory_versions;
    std::map<SnapshotPoint, std::uint32_t> instruction_unknown_memory_versions;
    std::map<std::uint64_t, std::uint32_t> block_exit_memory_versions;
    bool unresolved_exception_memory = false;
    const auto capture_versions = [&]() {
        VersionSnapshot snapshot;
        for (const auto &[variable, versions] : stacks)
            if (!versions.empty()) snapshot.emplace(variable, versions.back());
        return snapshot;
    };
    const auto versions_at = [&](std::optional<BlockId> source_block,
                                 std::optional<std::uint64_t> source_instruction)
        -> std::map<Key, std::vector<std::uint32_t>> {
        auto snapshot = stacks;
        if (!source_block) return snapshot;
        const VersionSnapshot *saved = nullptr;
        if (source_instruction) {
            const auto found = instruction_input_versions.find({source_block->value, *source_instruction});
            if (found != instruction_input_versions.end()) saved = &found->second;
        }
        if (!saved) {
            const auto found = block_exit_versions.find(source_block->value);
            if (found != block_exit_versions.end()) saved = &found->second;
        }
        if (saved) for (const auto &[variable, version] : *saved)
            snapshot[variable] = {version};
        return snapshot;
    };
    const auto memory_version_at = [&](std::optional<BlockId> source_block,
                                       std::optional<std::uint64_t> source_instruction) {
        if (source_block) {
            if (source_instruction) {
                const auto found = instruction_input_memory_versions.find({source_block->value, *source_instruction});
                if (found != instruction_input_memory_versions.end()) return found->second;
            }
            const auto found = block_exit_memory_versions.find(source_block->value);
            if (found != block_exit_memory_versions.end()) return found->second;
        }
        return memory_stack.back();
    };
    std::function<void(std::size_t)> rename = [&](std::size_t block_index) {
        auto &block = result.blocks[block_index];
        std::map<Key, std::size_t> pushed;
        const auto define = [&](const Key &variable) {
            const auto version = ++counters[variable];
            stacks[variable].push_back(version); ++pushed[variable];
            return version;
        };
        for (auto &phi : block.phis) phi.version = define(key(phi.destination));
        const bool has_memory_phi = block.memory_phi.has_value();
        if (block.memory_phi) {
            block.memory_phi->version = ++memory_counter;
            memory_stack.push_back(block.memory_phi->version);
        }
        std::size_t memory_definitions_in_block = 0;
        for (auto &instruction : block.instructions) {
            instruction_input_versions.try_emplace({block.id.value, instruction.origin.instruction_id}, capture_versions());
            instruction_input_memory_versions.try_emplace({block.id.value, instruction.origin.instruction_id}, memory_stack.back());
            std::visit([&](auto &statement) {
            using T = std::decay_t<decltype(statement)>;
            if constexpr (std::is_same_v<T, Assign>) {
                rename_expression(statement.value, stacks);
                rename_memory(statement.value, memory_stack.back());
                if (statement.destination.bank != RegisterBank::jvm_stack)
                    statement.destination_version = define(key(statement.destination));
            } else if constexpr (std::is_same_v<T, Store>) {
                rename_expression(statement.address, stacks); rename_expression(statement.value, stacks);
                rename_memory(statement.address, memory_stack.back());
                rename_memory(statement.value, memory_stack.back());
                statement.memory_input_version = memory_stack.back();
                statement.memory_output_version = ++memory_counter;
                memory_stack.push_back(*statement.memory_output_version);
                ++memory_definitions_in_block;
            } else if constexpr (std::is_same_v<T, Call>) {
                const auto state = versions_at(statement.delay_slot_snapshot_block, statement.delay_slot_snapshot_instruction);
                rename_expression(statement.indirect_target, state);
                rename_memory(statement.indirect_target, memory_version_at(statement.delay_slot_snapshot_block,
                                                                            statement.delay_slot_snapshot_instruction));
                statement.register_inputs.clear();
                statement.register_inputs.reserve(tracked_call_registers.size());
                for (const auto reg : tracked_call_registers) {
                    const auto found = stacks.find(key(reg));
                    if (found == stacks.end() || found->second.empty()) continue;
                    // Arguments are read at call execution, after any delay
                    // slot. Only the indirect target uses the earlier target
                    // snapshot captured above.
                    statement.register_inputs.push_back({reg, found->second.back()});
                }
                statement.register_output_versions.clear();
                std::map<Key, std::uint32_t> outputs;
                for (const auto reg : statement.register_writes) {
                    const auto variable = key(reg);
                    const auto version = define(variable);
                    outputs.emplace(variable, version);
                    statement.register_output_versions.push_back(version);
                }
                if (statement.return_register) {
                    const auto found = outputs.find(key(*statement.return_register));
                    statement.return_version = found == outputs.end()
                        ? define(key(*statement.return_register)) : found->second;
                }
                statement.memory_input_version = memory_stack.back();
                if (statement.x86_stack_effect)
                    statement.x86_stack_effect->memory_input_version = statement.memory_input_version;
                statement.memory_output_version = ++memory_counter;
                memory_stack.push_back(*statement.memory_output_version);
                ++memory_definitions_in_block;
            } else if constexpr (std::is_same_v<T, Return>) {
                const auto state = versions_at(statement.delay_slot_snapshot_block, statement.delay_slot_snapshot_instruction);
                rename_expression(statement.value, state);
                rename_memory(statement.value, memory_version_at(statement.delay_slot_snapshot_block,
                                                                  statement.delay_slot_snapshot_instruction));
                if (statement.x86_stack_effect)
                    statement.x86_stack_effect->memory_input_version =
                        memory_version_at(statement.delay_slot_snapshot_block, statement.delay_slot_snapshot_instruction);
            } else if constexpr (std::is_same_v<T, Branch>) {
                const auto state = versions_at(statement.delay_slot_snapshot_block, statement.delay_slot_snapshot_instruction);
                const auto memory_version = memory_version_at(statement.delay_slot_snapshot_block,
                                                              statement.delay_slot_snapshot_instruction);
                rename_expression(statement.predicate, state);
                rename_memory(statement.predicate, memory_version);
                rename_expression(statement.indirect_target, state);
                rename_memory(statement.indirect_target, memory_version);
            }
            else if constexpr (std::is_same_v<T, Intrinsic>) {
                for (auto &operand : statement.operands) {
                    rename_expression(operand, stacks); rename_memory(operand, memory_stack.back());
                }
                for (auto &output : statement.register_output_values) {
                    rename_expression(output, stacks); rename_memory(output, memory_stack.back());
                }
                statement.register_output_versions.clear();
                for (const auto reg : statement.register_writes)
                    statement.register_output_versions.push_back(define(key(reg)));
                if (statement.memory_effect != IntrinsicMemoryEffect::none)
                    statement.memory_input_version = memory_stack.back();
                if (statement.memory_effect == IntrinsicMemoryEffect::write ||
                    statement.memory_effect == IntrinsicMemoryEffect::unknown) {
                    statement.memory_output_version = ++memory_counter;
                    memory_stack.push_back(*statement.memory_output_version);
                    ++memory_definitions_in_block;
                }
            }
            }, instruction.statement);
            if (const auto *intrinsic = std::get_if<Intrinsic>(&instruction.statement);
                intrinsic && intrinsic->memory_effect == IntrinsicMemoryEffect::unknown &&
                intrinsic->memory_output_version)
                instruction_unknown_memory_versions.try_emplace(
                    SnapshotPoint{block.id.value, instruction.origin.instruction_id},
                    *intrinsic->memory_output_version);
        }
        block_exit_versions[block.id.value] = capture_versions();
        block_exit_memory_versions[block.id.value] = memory_stack.back();
        if (block.switch_dispatch)
            rename_expression(block.switch_dispatch->selector, stacks);
        if (block.switch_dispatch) rename_memory(block.switch_dispatch->selector, memory_stack.back());
        for (auto successor : successors[block_index]) if (reachable.contains(successor)) {
            auto &target = result.blocks[successor];
            for (auto &[variable, position] : phi_positions[successor])
                target.phis[position].inputs.push_back({block.id, stacks.at(variable).back()});
            if (target.memory_phi) {
                auto version = memory_stack.back();
                if (const auto edge = exception_memory_edges.find({block_index, successor});
                    edge != exception_memory_edges.end()) {
                    const auto site = std::find_if(block.instructions.begin(), block.instructions.end(),
                        [&](const auto &instruction) { return instruction.origin.address == edge->second.source; });
                    if (site != block.instructions.end()) {
                        const SnapshotPoint point{block.id.value, site->origin.instruction_id};
                        const auto &versions = edge->second.timing ==
                            LiftedBlock::ExceptionMemoryTiming::before_instruction
                            ? instruction_input_memory_versions : instruction_unknown_memory_versions;
                        const auto found = versions.find(point);
                        if (found == versions.end()) unresolved_exception_memory = true;
                        else version = found->second;
                    } else if (edge->second.timing != LiftedBlock::ExceptionMemoryTiming::before_instruction)
                        unresolved_exception_memory = true;
                }
                target.memory_phi->inputs.push_back({block.id, version});
            }
        }
        for (auto child : dom_children[block_index]) rename(child);
        for (const auto &[variable, amount] : pushed)
            for (std::size_t i = 0; i < amount; ++i) stacks[variable].pop_back();
        for (std::size_t i = 0; i < memory_definitions_in_block; ++i) memory_stack.pop_back();
        if (has_memory_phi) memory_stack.pop_back();
    };
    rename(entry);
    if (unresolved_exception_memory)
        return Error{ErrorCode::invalid_argument, "SSA could not resolve throwing instruction memory state"};
    for (auto block : reachable) for (auto &phi : result.blocks[block].phis) {
        std::sort(phi.inputs.begin(), phi.inputs.end(), [&](const auto &a, const auto &b) {
            return ids.at(a.predecessor.value) < ids.at(b.predecessor.value);
        });
        std::size_t expected = 0;
        for (auto pred : predecessors[block]) expected += reachable.contains(pred);
        if (phi.inputs.size() != expected)
            return Error{ErrorCode::invalid_argument, "SSA conversion could not resolve every phi input"};
    }
    for (auto block : reachable) if (auto &phi = result.blocks[block].memory_phi) {
        std::sort(phi->inputs.begin(), phi->inputs.end(), [&](const auto &a, const auto &b) {
            return ids.at(a.predecessor.value) < ids.at(b.predecessor.value);
        });
        std::size_t expected = 0;
        for (auto pred : predecessors[block]) expected += reachable.contains(pred);
        if (phi->inputs.size() != expected)
            return Error{ErrorCode::invalid_argument, "SSA conversion could not resolve every memory phi input"};
    }

    // Add independent version chains for stack slots already proven by the
    // existing recovery pass. The original whole-memory chain is retained for
    // every access and every unclassified effect.
    // The partition renamer currently has only block-exit edge snapshots.
    // Keep the correct whole-memory chain until partitions gain the same
    // instruction-specific exceptional input selection.
    std::optional<Result<LiftedFunction>> recovered_slots;
    if (exception_memory_edges.empty()) recovered_slots.emplace(recover_stack_variables(result));
    if (recovered_slots && *recovered_slots) {
        auto partitioned = std::move(recovered_slots->value());
        // Exact integer constants are needed only for finite indexed accesses.
        // Propagate literals and same-width SSA copies, plus unanimous phis.
        // These exact facts also permit pointer arithmetic by a proven constant
        // register offset; arithmetic and unresolved loop-carried values remain unknown.
        IntegerConstants integer_constants;
        std::set<PointerValueKey> nonconstant_values;
        bool constants_changed = true;
        for (std::size_t iteration = 0; constants_changed && iteration < 64; ++iteration) {
            constants_changed = false;
            const auto propagate_constant = [&](PointerValueKey value, std::uint64_t constant) {
                if (nonconstant_values.contains(value)) return;
                auto [found, inserted] = integer_constants.emplace(value, constant);
                if (inserted) constants_changed = true;
                else if (found->second != constant) {
                    integer_constants.erase(found);
                    nonconstant_values.insert(value);
                }
            };
            for (auto block_index : reachable) {
                for (const auto &phi : partitioned.blocks[block_index].phis) {
                    if (phi.inputs.empty()) continue;
                    std::optional<std::uint64_t> unanimous;
                    bool complete = true;
                    for (const auto &input : phi.inputs) {
                        const auto found = integer_constants.find({key(phi.destination), input.version});
                        if (found == integer_constants.end()) { complete = false; break; }
                        if (!unanimous) unanimous = found->second;
                        else if (*unanimous != found->second) { complete = false; break; }
                    }
                    if (complete && unanimous) {
                        propagate_constant(PointerValueKey{key(phi.destination), phi.version}, *unanimous);
                    }
                }
                for (const auto &instruction : partitioned.blocks[block_index].instructions)
                    if (const auto *assign = std::get_if<Assign>(&instruction.statement);
                        assign && assign->destination_version) {
                        if (!assign->value || assign->destination.width != assign->value->type.bits) continue;
                        const auto candidate = integer_constant(assign->value, integer_constants);
                        if (!candidate) continue;
                        propagate_constant(PointerValueKey{key(assign->destination), *assign->destination_version},
                                           *candidate);
                    }
            }
        }

        // Track pointer identity through SSA copies, constant add/sub (including
        // offsets in constant-proven SSA registers), and unanimous phis. Flat
        // architecture registers with proven numeric addresses share one root
        // per bank and width. Every other value gets an opaque root; distinct
        // roots remain may-alias, so this never licenses cross-root disjointness.
        PointerOrigins pointer_origins;
        FlatAddressRoots flat_address_roots;
        for (const auto &[value, constant] : integer_constants) {
            (void)constant;
            if (!flat_address_constant(value, integer_constants)) continue;
            flat_address_roots.try_emplace(
                FlatAddressRootKey{std::get<0>(value.first), std::get<2>(value.first)},
                PointerRoot{value.first, value.second});
        }
        const auto initial_pointer_origin = [&](PointerValueKey value) {
            const auto constant = flat_address_constant(value, integer_constants);
            if (constant) {
                const auto root = flat_address_roots.find(
                    FlatAddressRootKey{std::get<0>(value.first), std::get<2>(value.first)});
                if (root != flat_address_roots.end()) return PointerOrigin{root->second, *constant};
            }
            return PointerOrigin{PointerRoot{value.first, value.second}, 0};
        };
        for (const auto &variable : variables)
            pointer_origins.emplace(PointerValueKey{variable, 0}, initial_pointer_origin({variable, 0}));
        for (auto block_index : reachable) for (const auto &phi : partitioned.blocks[block_index].phis)
            pointer_origins.emplace(PointerValueKey{key(phi.destination), phi.version},
                                    initial_pointer_origin({key(phi.destination), phi.version}));
        for (auto block_index : reachable) for (const auto &instruction : partitioned.blocks[block_index].instructions)
            if (const auto *assign = std::get_if<Assign>(&instruction.statement); assign && assign->destination_version)
                pointer_origins.emplace(PointerValueKey{key(assign->destination), *assign->destination_version},
                    initial_pointer_origin({key(assign->destination), *assign->destination_version}));
        // Call results and ABI-clobbered registers have opaque values, but they
        // are still stable roots when copied or adjusted later. Giving each
        // definition its own root enables bounded accesses through that value;
        // stores through other roots continue to invalidate it because roots
        // from calls are not assumed disjoint.
        for (auto block_index : reachable) for (const auto &instruction : partitioned.blocks[block_index].instructions)
            if (const auto *call = std::get_if<Call>(&instruction.statement)) {
                if (call->return_register && call->return_version)
                    pointer_origins.emplace(PointerValueKey{key(*call->return_register), *call->return_version},
                        initial_pointer_origin({key(*call->return_register), *call->return_version}));
                const auto count = std::min(call->register_writes.size(), call->register_output_versions.size());
                for (std::size_t i = 0; i < count; ++i) {
                    const auto reg = call->register_writes[i];
                    const auto version = call->register_output_versions[i];
                    pointer_origins.emplace(PointerValueKey{key(reg), version},
                        initial_pointer_origin({key(reg), version}));
                }
            }
        bool provenance_changed = true;
        for (std::size_t iteration = 0; provenance_changed && iteration < 64; ++iteration) {
            provenance_changed = false;
            for (auto block_index : reachable) {
                for (const auto &phi : partitioned.blocks[block_index].phis) {
                    if (phi.inputs.empty()) continue;
                    std::optional<PointerOrigin> unanimous;
                    bool complete = true;
                    for (const auto &input : phi.inputs) {
                        const auto found = pointer_origins.find({key(phi.destination), input.version});
                        if (found == pointer_origins.end()) { complete = false; break; }
                        if (!unanimous) unanimous = found->second;
                        else if (*unanimous != found->second) { complete = false; break; }
                    }
                    if (complete && unanimous) {
                        auto &origin = pointer_origins[{key(phi.destination), phi.version}];
                        if (origin != *unanimous) { origin = *unanimous; provenance_changed = true; }
                    }
                }
                for (const auto &instruction : partitioned.blocks[block_index].instructions)
                    if (const auto *assign = std::get_if<Assign>(&instruction.statement); assign && assign->destination_version) {
                        if (!assign->value || assign->destination.width != assign->value->type.bits) continue;
                        const auto candidate = pointer_origin(assign->value, pointer_origins, integer_constants);
                        if (!candidate) continue;
                        auto &origin = pointer_origins[{key(assign->destination), *assign->destination_version}];
                        if (origin != *candidate) { origin = *candidate; provenance_changed = true; }
                    }
            }
        }
        std::set<std::string> partitions;
        constexpr std::size_t max_absolute_ranges = 4'096;
        std::set<AbsoluteMemoryRange> absolute_ranges;
        std::set<DynamicMemoryRange> dynamic_ranges;
        bool absolute_range_overflow = false;
        const auto inspect_expression = [&](const ExpressionPtr &expression) {
            collect_stack_partitions(expression, partitions);
            collect_absolute_memory_ranges(expression, absolute_ranges, max_absolute_ranges, absolute_range_overflow);
            std::function<void(const ExpressionPtr &)> collect_dynamic = [&](const ExpressionPtr &node) {
                if (!node) return;
                std::visit([&](const auto &value) {
                    using T = std::decay_t<decltype(value)>;
                    if constexpr (std::is_same_v<T, MemoryValue>) {
                        if (const auto range = dynamic_memory_range(value, pointer_origins, integer_constants))
                            dynamic_ranges.insert(*range);
                    } else if constexpr (std::is_same_v<T, UnaryValue>) collect_dynamic(value.operand);
                    else if constexpr (std::is_same_v<T, BinaryValue>) { collect_dynamic(value.left); collect_dynamic(value.right); }
                }, node->value);
            };
            collect_dynamic(expression);
        };
        std::size_t global_writes = 0;
        std::size_t local_writes = 0;
        std::map<std::pair<std::size_t, std::size_t>, std::string> store_partitions;
        std::map<std::pair<std::size_t, std::size_t>, AbsoluteMemoryRange> global_store_ranges;
        std::map<std::pair<std::size_t, std::size_t>, DynamicMemoryRange> dynamic_store_ranges;
        for (std::size_t block_index = 0; block_index < count; ++block_index) {
            for (std::size_t instruction_index = 0;
                 instruction_index < partitioned.blocks[block_index].instructions.size(); ++instruction_index) {
                const auto &instruction = partitioned.blocks[block_index].instructions[instruction_index];
                std::visit([&](const auto &statement) {
                    using T = std::decay_t<decltype(statement)>;
                    if constexpr (std::is_same_v<T, Assign>) inspect_expression(statement.value);
                    else if constexpr (std::is_same_v<T, Store>) {
                        inspect_expression(statement.address); inspect_expression(statement.value);
                        const auto *address = statement.address
                            ? std::get_if<MemoryValue>(&statement.address->value) : nullptr;
                        if (address && address->stack_variable) {
                            partitions.insert(*address->stack_variable);
                            store_partitions.emplace(std::pair{block_index, instruction_index},
                                                     *address->stack_variable);
                            ++local_writes;
                        } else if (address) {
                            if (const auto range = absolute_memory_range(*address)) {
                                global_store_ranges.emplace(std::pair{block_index, instruction_index}, *range);
                                ++local_writes;
                            } else if (const auto range = dynamic_memory_range(*address, pointer_origins,
                                                                                integer_constants)) {
                                dynamic_store_ranges.emplace(std::pair{block_index, instruction_index}, *range);
                                ++local_writes;
                            } else ++global_writes;
                        } else ++global_writes;
                    } else if constexpr (std::is_same_v<T, Call>) {
                        inspect_expression(statement.indirect_target);
                        ++global_writes;
                    } else if constexpr (std::is_same_v<T, Branch>) {
                        inspect_expression(statement.predicate); inspect_expression(statement.indirect_target);
                    } else if constexpr (std::is_same_v<T, Return>) inspect_expression(statement.value);
                    else if constexpr (std::is_same_v<T, Intrinsic>) {
                        for (const auto &operand : statement.operands) inspect_expression(operand);
                        for (const auto &output : statement.register_output_values) inspect_expression(output);
                        if (statement.memory_effect == IntrinsicMemoryEffect::write ||
                            statement.memory_effect == IntrinsicMemoryEffect::unknown) ++global_writes;
                    }
                }, instruction.statement);
            }
            if (partitioned.blocks[block_index].switch_dispatch)
                inspect_expression(partitioned.blocks[block_index].switch_dispatch->selector);
        }

        AbsoluteMemoryPartitions absolute_partitions;
        std::map<std::string, AbsoluteMemoryRange> absolute_partition_ranges;
        if (!absolute_range_overflow && !absolute_ranges.empty()) {
            auto range = absolute_ranges.begin();
            while (range != absolute_ranges.end()) {
                const auto space = std::get<0>(*range);
                const auto component_begin = std::get<1>(*range);
                auto component_end = std::get<2>(*range);
                auto next = std::next(range);
                while (next != absolute_ranges.end() && std::get<0>(*next) == space &&
                       std::get<1>(*next) < component_end) {
                    component_end = std::max(component_end, std::get<2>(*next));
                    ++next;
                }
                const auto partition = std::string("\x1fglobal:") + std::to_string(space) + ":" +
                                       std::to_string(component_begin) + ":" + std::to_string(component_end);
                partitions.insert(partition);
                absolute_partition_ranges.emplace(
                    partition, AbsoluteMemoryRange{space, component_begin, component_end});
                for (auto member = range; member != next; ++member)
                    absolute_partitions.emplace(*member, partition);
                range = next;
            }
        }
        for (const auto &[where, range] : global_store_ranges) {
            const auto partition = absolute_partitions.find(range);
            if (partition == absolute_partitions.end()) {
                ++global_writes;
                --local_writes;
            } else {
                store_partitions.emplace(where, partition->second);
            }
        }

        DynamicMemoryPartitions dynamic_partitions;
        std::map<std::string, DynamicMemoryRange> dynamic_partition_ranges;
        if (dynamic_ranges.size() <= max_absolute_ranges) {
            auto range = dynamic_ranges.begin();
            while (range != dynamic_ranges.end()) {
                const auto root = std::get<0>(*range);
                const auto component_begin = std::get<1>(*range);
                auto component_end = std::get<2>(*range);
                auto next = std::next(range);
                while (next != dynamic_ranges.end() && std::get<0>(*next) == root &&
                       std::get<1>(*next) < component_end) {
                    component_end = std::max(component_end, std::get<2>(*next));
                    ++next;
                }
                const auto &root_reg = root.first;
                const auto partition = std::string("\x1f" "dynamic:") + std::to_string(std::get<0>(root_reg)) + ":" +
                    std::to_string(std::get<1>(root_reg)) + ":" + std::to_string(std::get<2>(root_reg)) + ":" +
                    std::to_string(std::get<3>(root_reg)) + ":" + std::to_string(root.second) + ":" +
                    std::to_string(component_begin) + ":" + std::to_string(component_end);
                partitions.insert(partition);
                const DynamicMemoryRange component{root, component_begin, component_end};
                dynamic_partition_ranges.emplace(partition, component);
                for (auto member = range; member != next; ++member) dynamic_partitions.emplace(*member, partition);
                range = next;
            }
        } else {
            // If dynamic-location tracking exceeds its cap, those writes fall
            // back to the existing broad memory clobber path.
            for (const auto &[where, range] : dynamic_store_ranges) { (void)range; ++global_writes; --local_writes; }
            dynamic_store_ranges.clear();
        }
        for (const auto &[where, range] : dynamic_store_ranges) {
            const auto partition = dynamic_partitions.find(range);
            if (partition == dynamic_partitions.end()) { ++global_writes; --local_writes; }
            else store_partitions.emplace(where, partition->second);
        }

        constexpr std::size_t max_partitions = 128;
        constexpr std::size_t max_partition_events = 2'000'000;
        constexpr std::size_t max_partition_phi_inputs = 65'536;
        const bool event_overflow = partitions.size() &&
            global_writes > (max_partition_events - std::min(local_writes, max_partition_events)) /
                                partitions.size();
        if (!partitions.empty() && partitions.size() <= max_partitions &&
            local_writes <= max_partition_events && !event_overflow) {
            std::set<std::string> written_partitions;
            for (const auto &[where, partition] : store_partitions) {
                (void)where;
                written_partitions.insert(partition);
            }
            if (global_writes || !dynamic_store_ranges.empty())
                written_partitions.insert(partitions.begin(), partitions.end());
            std::size_t phi_inputs = 0;
            bool within_phi_budget = true;
            for (auto block_index : reachable) {
                std::size_t incoming = 0;
                for (auto predecessor : predecessors[block_index]) incoming += reachable.contains(predecessor);
                if (incoming < 2) continue;
                if (written_partitions.size() && incoming >
                    (max_partition_phi_inputs - std::min(phi_inputs, max_partition_phi_inputs)) /
                        written_partitions.size()) {
                    within_phi_budget = false;
                    break;
                }
                phi_inputs += incoming * written_partitions.size();
                for (const auto &partition : written_partitions)
                    partitioned.blocks[block_index].memory_partition_phis.push_back({partition, 0, {}});
            }
            if (within_phi_budget) {
                std::map<std::string, std::vector<std::uint32_t>> partition_stacks;
                for (const auto &partition : partitions) partition_stacks[partition].push_back(0);
                std::uint64_t partition_counter = 0;
                using PartitionSnapshot = std::map<std::string, std::uint32_t>;
                using PartitionSnapshotPoint = std::pair<std::uint64_t, std::uint64_t>;
                std::map<PartitionSnapshotPoint, PartitionSnapshot> instruction_partition_versions;
                std::map<std::uint64_t, PartitionSnapshot> block_exit_partition_versions;
                const auto capture_partitions = [&]() {
                    PartitionSnapshot state;
                    for (const auto &[partition, stack] : partition_stacks)
                        if (!stack.empty()) state.emplace(partition, stack.back());
                    return state;
                };
                const auto partitions_at = [&](std::optional<BlockId> source_block,
                                               std::optional<std::uint64_t> source_instruction) {
                    auto state = capture_partitions();
                    if (source_block) {
                        const PartitionSnapshot *saved = nullptr;
                        if (source_instruction) {
                            const auto found = instruction_partition_versions.find(
                                {source_block->value, *source_instruction});
                            if (found != instruction_partition_versions.end()) saved = &found->second;
                        }
                        if (!saved) {
                            const auto found = block_exit_partition_versions.find(source_block->value);
                            if (found != block_exit_partition_versions.end()) saved = &found->second;
                        }
                        if (saved) state = *saved;
                    }
                    return state;
                };
                std::function<void(std::size_t)> rename_partitions = [&](std::size_t block_index) {
                    auto &block = partitioned.blocks[block_index];
                    std::map<std::string, std::size_t> pushed;
                    const auto advance = [&](const std::string &partition) {
                        if (partition_counter >= std::numeric_limits<std::uint32_t>::max()) return false;
                        const auto version = static_cast<std::uint32_t>(++partition_counter);
                        partition_stacks[partition].push_back(version);
                        ++pushed[partition];
                        return true;
                    };
                    const auto invalidate_all = [&](std::vector<MemoryPartitionEffect> &effects) {
                        effects.clear();
                        for (const auto &partition : partitions) {
                            const auto input_version = partition_stacks[partition].back();
                            if (!advance(partition)) continue;
                            effects.push_back({partition, input_version, partition_stacks[partition].back()});
                        }
                    };
                    const auto invalidate_for_dynamic_store = [&](const DynamicMemoryRange &written,
                                                                   std::vector<MemoryPartitionEffect> &effects) {
                        effects.clear();
                        const auto written_root = std::get<0>(written);
                        const auto written_begin = std::get<1>(written);
                        const auto written_end = std::get<2>(written);
                        for (const auto &partition : partitions) {
                            bool proven_disjoint = false;
                            if (const auto known = dynamic_partition_ranges.find(partition);
                                known != dynamic_partition_ranges.end() && std::get<0>(known->second) == written_root) {
                                proven_disjoint = written_end <= std::get<1>(known->second) ||
                                                  std::get<2>(known->second) <= written_begin;
                            }
                            if (proven_disjoint) continue;
                            const auto input_version = partition_stacks[partition].back();
                            if (!advance(partition)) continue;
                            effects.push_back({partition, input_version, partition_stacks[partition].back()});
                        }
                    };
                    const auto invalidate_for_absolute_store = [&](const AbsoluteMemoryRange &written,
                                                                     std::vector<MemoryPartitionEffect> &effects) {
                        effects.clear();
                        const auto written_space = std::get<0>(written);
                        const auto written_begin = std::get<1>(written);
                        const auto written_end = std::get<2>(written);
                        for (const auto &partition : partitions) {
                            bool proven_disjoint = false;
                            if (const auto known = absolute_partition_ranges.find(partition);
                                known != absolute_partition_ranges.end()) {
                                const auto &range = known->second;
                                proven_disjoint = std::get<0>(range) != written_space ||
                                    std::get<2>(range) <= written_begin || written_end <= std::get<1>(range);
                            }
                            if (proven_disjoint) continue;
                            const auto input_version = partition_stacks[partition].back();
                            if (!advance(partition)) continue;
                            effects.push_back({partition, input_version, partition_stacks[partition].back()});
                        }
                    };
                    for (auto &phi : block.memory_partition_phis) {
                        if (!advance(phi.partition)) return;
                        phi.version = partition_stacks[phi.partition].back();
                    }
                    for (std::size_t instruction_index = 0;
                         instruction_index < block.instructions.size(); ++instruction_index) {
                        auto &instruction = block.instructions[instruction_index];
                        instruction_partition_versions.try_emplace(
                            {block.id.value, instruction.origin.instruction_id}, capture_partitions());
                        const auto rename_reads = [&](ExpressionPtr &expression, const PartitionSnapshot &state) {
                            rename_partition_memory(expression, state, absolute_partitions, dynamic_partitions,
                                                    pointer_origins, integer_constants);
                        };
                        std::visit([&](auto &statement) {
                            using T = std::decay_t<decltype(statement)>;
                            if constexpr (std::is_same_v<T, Assign>)
                                rename_reads(statement.value, capture_partitions());
                            else if constexpr (std::is_same_v<T, Store>) {
                                rename_reads(statement.address, capture_partitions());
                                rename_reads(statement.value, capture_partitions());
                                const auto target = store_partitions.find({block_index, instruction_index});
                                if (target != store_partitions.end()) {
                                    statement.memory_partition = target->second;
                                    const auto dynamic_target = dynamic_store_ranges.find({block_index, instruction_index});
                                    if (dynamic_target != dynamic_store_ranges.end())
                                        invalidate_for_dynamic_store(dynamic_target->second, statement.memory_partition_effects);
                                    else if (const auto absolute_target = global_store_ranges.find(
                                                 {block_index, instruction_index});
                                             absolute_target != global_store_ranges.end())
                                        invalidate_for_absolute_store(absolute_target->second,
                                                                      statement.memory_partition_effects);
                                    else {
                                        statement.memory_partition_effects.clear();
                                        const auto input_version = partition_stacks[target->second].back();
                                        if (advance(target->second))
                                            statement.memory_partition_effects.push_back(
                                                {target->second, input_version, partition_stacks[target->second].back()});
                                    }
                                } else {
                                    invalidate_all(statement.memory_partition_effects);
                                }
                            } else if constexpr (std::is_same_v<T, Call>) {
                                const auto state = partitions_at(statement.delay_slot_snapshot_block,
                                                                 statement.delay_slot_snapshot_instruction);
                                rename_reads(statement.indirect_target, state);
                                // Stack recovery only exposes slots proven nonescaping and
                                // nonoverlapping. Such a slot cannot be reached by a callee,
                                // while absolute ranges remain visible to unknown callees.
                                statement.memory_partition_effects.clear();
                                for (const auto &partition : partitions) {
                                    if (!is_absolute_memory_partition(partition) &&
                                        !dynamic_partition_ranges.contains(partition)) continue;
                                    const auto input_version = partition_stacks[partition].back();
                                    if (advance(partition))
                                        statement.memory_partition_effects.push_back(
                                            {partition, input_version, partition_stacks[partition].back()});
                                }
                            } else if constexpr (std::is_same_v<T, Branch>) {
                                const auto state = partitions_at(statement.delay_slot_snapshot_block,
                                                                 statement.delay_slot_snapshot_instruction);
                                rename_reads(statement.predicate, state);
                                rename_reads(statement.indirect_target, state);
                            } else if constexpr (std::is_same_v<T, Return>) {
                                const auto state = partitions_at(statement.delay_slot_snapshot_block,
                                                                 statement.delay_slot_snapshot_instruction);
                                rename_reads(statement.value, state);
                            } else if constexpr (std::is_same_v<T, Intrinsic>) {
                                for (auto &operand : statement.operands)
                                    rename_reads(operand, capture_partitions());
                                for (auto &output : statement.register_output_values)
                                    rename_reads(output, capture_partitions());
                                if (statement.memory_effect == IntrinsicMemoryEffect::write ||
                                    statement.memory_effect == IntrinsicMemoryEffect::unknown)
                                    invalidate_all(statement.memory_partition_effects);
                            }
                        }, instruction.statement);
                    }
                    block_exit_partition_versions[block.id.value] = capture_partitions();
                    if (block.switch_dispatch)
                        rename_partition_memory(block.switch_dispatch->selector, capture_partitions(),
                                                absolute_partitions, dynamic_partitions, pointer_origins,
                                                integer_constants);
                    for (auto successor : successors[block_index]) if (reachable.contains(successor)) {
                        auto &target = partitioned.blocks[successor];
                        for (auto &phi : target.memory_partition_phis)
                            phi.inputs.push_back({block.id, partition_stacks[phi.partition].back()});
                    }
                    for (auto child : dom_children[block_index]) rename_partitions(child);
                    for (const auto &[partition, amount] : pushed)
                        for (std::size_t i = 0; i < amount; ++i) partition_stacks[partition].pop_back();
                };
                rename_partitions(entry);
                bool valid_partition_phis = true;
                for (auto block_index : reachable) for (auto &phi : partitioned.blocks[block_index].memory_partition_phis) {
                    std::sort(phi.inputs.begin(), phi.inputs.end(), [&](const auto &a, const auto &b) {
                        return ids.at(a.predecessor.value) < ids.at(b.predecessor.value);
                    });
                    std::size_t expected = 0;
                    for (auto predecessor : predecessors[block_index]) expected += reachable.contains(predecessor);
                    if (phi.inputs.size() != expected) valid_partition_phis = false;
                }
                if (valid_partition_phis) result = std::move(partitioned);
            }
        }
    }
    for (std::size_t i = 0; i < count; ++i)
        result.blocks[i].phis.insert(result.blocks[i].phis.end(), jvm_stack_phis[i].begin(), jvm_stack_phis[i].end());
    return result;
}

Result<LiftedFunction> to_ssa(const LiftedFunction &input) {
    return to_ssa(input, {});
}
} // namespace hexlab::decompiler
