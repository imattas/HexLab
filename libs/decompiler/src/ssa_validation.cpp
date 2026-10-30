#include "hexlab/decompiler/decompiler.hpp"

#include <algorithm>
#include <functional>
#include <iterator>
#include <map>
#include <set>
#include <tuple>

namespace hexlab::decompiler {
namespace {
using RegisterKey = std::tuple<unsigned, unsigned, unsigned, bool>;
using ValueKey = std::pair<RegisterKey, std::uint32_t>;
using PartitionValueKey = std::pair<std::string, std::uint32_t>;

RegisterKey key(RegisterOperand reg) {
    if (reg.bank == RegisterBank::arm64_simd) reg.width = 128;
    return {static_cast<unsigned>(reg.bank), reg.index, reg.width, reg.high_byte};
}

bool is_jvm_stack(RegisterOperand reg) { return reg.bank == RegisterBank::jvm_stack; }

struct Definition {
    std::size_t block = 0;
    std::optional<std::size_t> instruction;
};

Error invalid(std::string message) { return {ErrorCode::invalid_argument, std::move(message)}; }
}

Result<SsaRegisterValidation> validate_register_ssa(const LiftedFunction &function) {
    if (function.blocks.empty()) return invalid("SSA validation requires at least one block");

    const auto count = function.blocks.size();
    std::map<std::uint64_t, std::size_t> block_by_id;
    std::map<std::pair<std::uint32_t, std::uint64_t>, std::size_t> block_by_address;
    for (std::size_t i = 0; i < count; ++i) {
        if (!block_by_id.emplace(function.blocks[i].id.value, i).second)
            return invalid("SSA validation found duplicate block IDs");
        if (!block_by_address.emplace(
                std::pair{function.blocks[i].begin.space.value, function.blocks[i].begin.offset}, i).second)
            return invalid("SSA validation found duplicate block addresses");
    }
    const auto entry_it = block_by_address.find({function.entry.space.value, function.entry.offset});
    if (entry_it == block_by_address.end()) return invalid("SSA validation entry has no block");
    const auto entry = entry_it->second;

    std::vector<std::set<std::size_t>> predecessors(count), successors(count);
    for (std::size_t i = 0; i < count; ++i) for (const auto &edge : function.blocks[i].successors) {
        std::optional<std::size_t> target_by_id;
        std::optional<std::size_t> target_by_address;
        if (edge.block) {
            const auto found = block_by_id.find(edge.block->value);
            if (found != block_by_id.end()) target_by_id = found->second;
        }
        if (edge.target) {
            const auto found = block_by_address.find({edge.target->space.value, edge.target->offset});
            if (found != block_by_address.end()) target_by_address = found->second;
        }
        if (edge.block && edge.target &&
            (!target_by_id || !target_by_address || *target_by_id != *target_by_address)) {
            return invalid("SSA CFG edge block ID and address disagree");
        }
        const auto target = target_by_id ? target_by_id : target_by_address;
        if (target) {
            successors[i].insert(*target);
            predecessors[*target].insert(i);
        }
    }

    std::set<std::size_t> reachable{entry};
    std::vector<std::size_t> pending{entry};
    while (!pending.empty()) {
        const auto block = pending.back();
        pending.pop_back();
        for (const auto next : successors[block]) if (reachable.insert(next).second) pending.push_back(next);
    }

    std::vector<std::set<std::size_t>> dominators(count);
    for (const auto block : reachable)
        dominators[block] = block == entry ? std::set<std::size_t>{entry} : reachable;
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto block : reachable) {
            if (block == entry) continue;
            std::set<std::size_t> next;
            bool first = true;
            for (const auto predecessor : predecessors[block]) if (reachable.contains(predecessor)) {
                if (first) {
                    next = dominators[predecessor];
                    first = false;
                } else {
                    std::set<std::size_t> intersection;
                    std::set_intersection(next.begin(), next.end(), dominators[predecessor].begin(),
                        dominators[predecessor].end(), std::inserter(intersection, intersection.end()));
                    next = std::move(intersection);
                }
            }
            next.insert(block);
            if (next != dominators[block]) {
                dominators[block] = std::move(next);
                changed = true;
            }
        }
    }

    std::map<ValueKey, Definition> definitions;
    std::map<std::uint32_t, Definition> memory_definitions;
    std::map<PartitionValueKey, Definition> partition_definitions;
    SsaRegisterValidation summary;
    summary.reachable_blocks = reachable.size();
    const auto define = [&](RegisterOperand reg, std::uint32_t version, std::size_t block,
                            std::optional<std::size_t> instruction) -> Result<bool> {
        if (is_jvm_stack(reg)) return true;
        if (!reg.width || !version) return invalid("SSA register definition has a zero width or version");
        const ValueKey value{key(reg), version};
        const auto [it, inserted] = definitions.emplace(value, Definition{block, instruction});
        if (!inserted) {
            if (it->second.block != block || it->second.instruction != instruction)
                return invalid("SSA register version has multiple definitions");
            return false;
        }
        ++summary.definitions;
        return true;
    };
    const auto define_partition = [&](const std::string &partition, std::uint32_t version,
                                      std::size_t block, std::optional<std::size_t> instruction) -> Result<bool> {
        if (partition.empty() || !version)
            return invalid("SSA memory-partition definition has an empty partition or zero version");
        const auto [it, inserted] = partition_definitions.emplace(
            PartitionValueKey{partition, version}, Definition{block, instruction});
        if (!inserted)
            return invalid("SSA memory-partition version has multiple definitions");
        (void)it;
        return true;
    };
    const auto define_memory = [&](std::uint32_t version, std::size_t block,
                                   std::optional<std::size_t> instruction) -> Result<bool> {
        if (!version) return invalid("SSA whole-memory definition has version zero");
        if (!memory_definitions.emplace(version, Definition{block, instruction}).second)
            return invalid("SSA whole-memory version has multiple definitions");
        return true;
    };

    for (const auto block_index : reachable) {
        const auto &block = function.blocks[block_index];
        std::set<ValueKey> block_phi_definitions;
        for (const auto &phi : block.phis) {
            if (!is_jvm_stack(phi.destination) &&
                !block_phi_definitions.insert({key(phi.destination), phi.version}).second)
                return invalid("SSA block contains a duplicate phi definition");
            const auto added = define(phi.destination, phi.version, block_index, {});
            if (!added) return added.error();
            if (added.value()) ++summary.phi_nodes;
        }
        std::set<std::string> partition_phi_names;
        for (const auto &phi : block.memory_partition_phis) {
            if (phi.partition.empty() || !partition_phi_names.insert(phi.partition).second)
                return invalid("SSA block contains an empty or duplicate memory-partition phi");
            const auto defined = define_partition(phi.partition, phi.version, block_index, {});
            if (!defined) return defined.error();
        }
        if (block.memory_phi) {
            const auto defined = define_memory(block.memory_phi->version, block_index, {});
            if (!defined) return defined.error();
        }
        if (block.instructions.size() > 1'000'000)
            return Error{ErrorCode::resource_limit, "SSA validation block exceeds its instruction budget"};
        for (std::size_t i = 0; i < block.instructions.size(); ++i) {
            const auto &statement = block.instructions[i].statement;
            Result<bool> added{true};
            if (const auto *assign = std::get_if<Assign>(&statement)) {
                if (!is_jvm_stack(assign->destination) && !assign->destination_version)
                    return invalid("SSA assignment has no destination version");
                if (assign->destination_version)
                    added = define(assign->destination, *assign->destination_version, block_index, i);
            } else if (const auto *store = std::get_if<Store>(&statement)) {
                if (!store->memory_input_version || !store->memory_output_version)
                    return invalid("SSA store has no complete whole-memory version pair");
                if (store->memory_output_version) {
                    added = define_memory(*store->memory_output_version, block_index, i);
                }
            } else if (const auto *call = std::get_if<Call>(&statement)) {
                if (!call->memory_input_version || !call->memory_output_version)
                    return invalid("SSA call has no complete whole-memory version pair");
                if (call->memory_output_version && call->memory_input_version != call->memory_output_version) {
                    added = define_memory(*call->memory_output_version, block_index, i);
                    if (!added) return added.error();
                }
                if (call->register_output_versions.size() != call->register_writes.size())
                    return invalid("SSA call output versions do not match its register writes");
                std::set<RegisterKey> outputs;
                for (std::size_t n = 0; n < call->register_writes.size(); ++n) {
                    if (!outputs.insert(key(call->register_writes[n])).second)
                        return invalid("SSA call writes one register view more than once");
                    added = define(call->register_writes[n], call->register_output_versions[n], block_index, i);
                    if (!added) return added.error();
                }
                if (call->return_register.has_value() != call->return_version.has_value())
                    return invalid("SSA call return register and version are incomplete");
                if (call->return_register) {
                    added = define(*call->return_register, *call->return_version, block_index, i);
                }
            } else if (const auto *intrinsic = std::get_if<Intrinsic>(&statement)) {
                const bool reads_memory = intrinsic->memory_effect != IntrinsicMemoryEffect::none;
                const bool writes_memory = intrinsic->memory_effect == IntrinsicMemoryEffect::write ||
                    intrinsic->memory_effect == IntrinsicMemoryEffect::read_write ||
                    intrinsic->memory_effect == IntrinsicMemoryEffect::unknown;
                if (intrinsic->memory_input_version.has_value() != reads_memory ||
                    intrinsic->memory_output_version.has_value() != writes_memory)
                    return invalid("SSA intrinsic whole-memory versions disagree with its declared effect");
                if (intrinsic->memory_output) {
                    const auto location = intrinsic->memory_output->location_operand;
                    const auto value = intrinsic->memory_output->value_operand;
                    if (intrinsic->memory_effect != IntrinsicMemoryEffect::read_write ||
                        location >= intrinsic->operands.size() || value >= intrinsic->operands.size() ||
                        location == value || !intrinsic->operands[location] || !intrinsic->operands[value] ||
                        intrinsic->operands[location]->type != intrinsic->operands[value]->type ||
                        intrinsic->operands[location]->type.kind != TypeKind::integer ||
                        intrinsic->operands[location]->type.bits != 8 ||
                        !std::holds_alternative<MemoryValue>(intrinsic->operands[location]->value) ||
                        !intrinsic->memory_input_version || !intrinsic->memory_output_version)
                        return invalid("SSA intrinsic concrete memory output is malformed");
                }
                if (intrinsic->memory_output_version) {
                    added = define_memory(*intrinsic->memory_output_version, block_index, i);
                    if (!added) return added.error();
                }
                if (intrinsic->register_output_versions.size() != intrinsic->register_writes.size())
                    return invalid("SSA intrinsic output versions do not match its register writes");
                std::set<RegisterKey> outputs;
                for (std::size_t n = 0; n < intrinsic->register_writes.size(); ++n) {
                    if (!outputs.insert(key(intrinsic->register_writes[n])).second)
                        return invalid("SSA intrinsic writes one register view more than once");
                    added = define(intrinsic->register_writes[n], intrinsic->register_output_versions[n], block_index, i);
                    if (!added) return added.error();
                }
            }
            if (!added) return added.error();
            const std::vector<MemoryPartitionEffect> *partition_effects = nullptr;
            if (const auto *store = std::get_if<Store>(&statement)) partition_effects = &store->memory_partition_effects;
            else if (const auto *call = std::get_if<Call>(&statement)) partition_effects = &call->memory_partition_effects;
            else if (const auto *intrinsic = std::get_if<Intrinsic>(&statement))
                partition_effects = &intrinsic->memory_partition_effects;
            if (partition_effects) {
                std::set<std::string> written_partitions;
                for (const auto &effect : *partition_effects) {
                    if (!written_partitions.insert(effect.partition).second)
                        return invalid("SSA instruction contains duplicate memory-partition effects");
                    const auto defined = define_partition(effect.partition, effect.output_version, block_index, i);
                    if (!defined) return defined.error();
                }
            }
        }
    }

    const auto check_use = [&](RegisterOperand reg, std::optional<std::uint32_t> version,
                               std::size_t use_block, std::size_t use_instruction) -> Result<bool> {
        if (is_jvm_stack(reg)) return true;
        if (!reg.width || !version) return invalid("SSA register use has no width or version");
        ++summary.uses;
        if (*version == 0) return true; // Implicit incoming value at function entry.
        const auto found = definitions.find({key(reg), *version});
        if (found == definitions.end()) return invalid("SSA register use refers to an undefined version");
        const auto &definition = found->second;
        if (definition.block == use_block) {
            if (definition.instruction && *definition.instruction >= use_instruction)
                return invalid("SSA register use precedes its definition in a block");
        } else if (!dominators[use_block].contains(definition.block)) {
            return invalid("SSA register definition does not dominate its use");
        }
        return true;
    };
    const auto check_partition_use = [&](const std::string &partition, std::uint32_t version,
                                         std::size_t use_block, std::size_t use_instruction) -> Result<bool> {
        if (partition.empty()) return invalid("SSA memory-partition use has an empty partition name");
        if (!version) return true; // Incoming partition state at function entry.
        const auto found = partition_definitions.find({partition, version});
        if (found == partition_definitions.end())
            return invalid("SSA memory-partition use refers to an undefined version");
        const auto &definition = found->second;
        if (definition.block == use_block) {
            if (definition.instruction && *definition.instruction >= use_instruction)
                return invalid("SSA memory-partition use precedes its definition in a block");
        } else if (!dominators[use_block].contains(definition.block)) {
            return invalid("SSA memory-partition definition does not dominate its use");
        }
        return true;
    };
    const auto check_memory_use = [&](std::uint32_t version, std::size_t use_block,
                                      std::size_t use_instruction) -> Result<bool> {
        if (!version) return true; // Incoming whole-memory state at function entry.
        const auto found = memory_definitions.find(version);
        if (found == memory_definitions.end()) return invalid("SSA memory use refers to an undefined version");
        const auto &definition = found->second;
        if (definition.block == use_block) {
            if (definition.instruction && *definition.instruction >= use_instruction)
                return invalid("SSA memory use precedes its definition in a block");
        } else if (!dominators[use_block].contains(definition.block)) {
            return invalid("SSA memory definition does not dominate its use");
        }
        return true;
    };

    std::function<Result<bool>(const ExpressionPtr &, std::size_t, std::size_t, unsigned)> check_expression;
    check_expression = [&](const ExpressionPtr &expression, std::size_t block, std::size_t instruction,
                          unsigned depth) -> Result<bool> {
        if (!expression) return true;
        if (depth > 256) return Error{ErrorCode::resource_limit, "SSA expression exceeds validation depth"};
        return std::visit([&](const auto &value) -> Result<bool> {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, RegisterValue>) {
                return check_use(value.reg, value.version, block, instruction);
            } else if constexpr (std::is_same_v<T, MemoryValue>) {
                if (!value.memory_version)
                    return invalid("SSA memory load has no whole-memory version");
                auto memory_checked = check_memory_use(*value.memory_version, block, instruction);
                if (!memory_checked) return memory_checked.error();
                if (value.memory_partition.has_value() != value.memory_partition_version.has_value())
                    return invalid("SSA memory-partition name and version are incomplete");
                if (value.memory_partition) {
                    auto checked = check_partition_use(*value.memory_partition, *value.memory_partition_version,
                                                       block, instruction);
                    if (!checked) return checked.error();
                }
                if (value.base) {
                    auto checked = check_use(*value.base, value.base_version, block, instruction);
                    if (!checked) return checked.error();
                }
                if (value.index) {
                    auto checked = check_use(*value.index, value.index_version, block, instruction);
                    if (!checked) return checked.error();
                }
                if (value.stack_frame_register.has_value() != value.stack_frame_version.has_value())
                    return invalid("SSA stack-frame register and version are incomplete");
                if (value.stack_frame_register) {
                    auto checked = check_use(*value.stack_frame_register, value.stack_frame_version,
                                             block, instruction);
                    if (!checked) return checked.error();
                }
                return true;
            } else if constexpr (std::is_same_v<T, UnaryValue>) {
                return check_expression(value.operand, block, instruction, depth + 1);
            } else if constexpr (std::is_same_v<T, BinaryValue>) {
                auto left = check_expression(value.left, block, instruction, depth + 1);
                if (!left) return left.error();
                return check_expression(value.right, block, instruction, depth + 1);
            }
            return true;
        }, expression->value);
    };

    const auto check_phi_inputs = [&](std::size_t block_index, const LiftedBlock::Phi &phi) -> Result<bool> {
        std::set<std::size_t> seen;
        for (const auto &input : phi.inputs) {
            const auto predecessor = block_by_id.find(input.predecessor.value);
            if (predecessor == block_by_id.end() || !reachable.contains(predecessor->second) ||
                !predecessors[block_index].contains(predecessor->second) ||
                !seen.insert(predecessor->second).second)
                return invalid("SSA phi has a duplicate or non-predecessor input");
            auto checked = check_use(phi.destination, input.version, predecessor->second,
                                     function.blocks[predecessor->second].instructions.size());
            if (!checked) return checked.error();
        }
        std::size_t expected = 0;
        for (const auto predecessor : predecessors[block_index]) expected += reachable.contains(predecessor);
        if (seen.size() != expected) return invalid("SSA phi does not cover every reachable predecessor");
        return true;
    };
    const auto check_partition_phi_inputs = [&](std::size_t block_index,
                                                const LiftedBlock::MemoryPartitionPhi &phi) -> Result<bool> {
        std::set<std::size_t> seen;
        for (const auto &input : phi.inputs) {
            const auto predecessor = block_by_id.find(input.predecessor.value);
            if (predecessor == block_by_id.end() || !reachable.contains(predecessor->second) ||
                !predecessors[block_index].contains(predecessor->second) ||
                !seen.insert(predecessor->second).second)
                return invalid("SSA memory-partition phi has a duplicate or non-predecessor input");
            auto checked = check_partition_use(phi.partition, input.version, predecessor->second,
                                               function.blocks[predecessor->second].instructions.size());
            if (!checked) return checked.error();
        }
        std::size_t expected = 0;
        for (const auto predecessor : predecessors[block_index]) expected += reachable.contains(predecessor);
        if (seen.size() != expected)
            return invalid("SSA memory-partition phi does not cover every reachable predecessor");
        return true;
    };
    const auto check_memory_phi_inputs = [&](std::size_t block_index,
                                             const LiftedBlock::MemoryPhi &phi) -> Result<bool> {
        std::set<std::size_t> seen;
        for (const auto &input : phi.inputs) {
            const auto predecessor = block_by_id.find(input.predecessor.value);
            if (predecessor == block_by_id.end() || !reachable.contains(predecessor->second) ||
                !predecessors[block_index].contains(predecessor->second) ||
                !seen.insert(predecessor->second).second)
                return invalid("SSA memory phi has a duplicate or non-predecessor input");
            auto checked = check_memory_use(input.version, predecessor->second,
                function.blocks[predecessor->second].instructions.size());
            if (!checked) return checked.error();
        }
        std::size_t expected = 0;
        for (const auto predecessor : predecessors[block_index]) expected += reachable.contains(predecessor);
        if (seen.size() != expected)
            return invalid("SSA memory phi does not cover every reachable predecessor");
        return true;
    };

    for (const auto block_index : reachable) {
        const auto &block = function.blocks[block_index];
        for (const auto &phi : block.phis) {
            auto checked = check_phi_inputs(block_index, phi);
            if (!checked) return checked.error();
        }
        for (const auto &phi : block.memory_partition_phis) {
            auto checked = check_partition_phi_inputs(block_index, phi);
            if (!checked) return checked.error();
        }
        if (block.memory_phi) {
            auto checked = check_memory_phi_inputs(block_index, *block.memory_phi);
            if (!checked) return checked.error();
        }
        for (std::size_t i = 0; i < block.instructions.size(); ++i) {
            const auto &statement = block.instructions[i].statement;
            Result<bool> checked{true};
            if (const auto *assign = std::get_if<Assign>(&statement)) {
                checked = check_expression(assign->value, block_index, i, 0);
            } else if (const auto *store = std::get_if<Store>(&statement)) {
                checked = check_expression(store->address, block_index, i, 0);
                if (checked) checked = check_expression(store->value, block_index, i, 0);
                if (checked) checked = check_memory_use(*store->memory_input_version, block_index, i);
            } else if (const auto *call = std::get_if<Call>(&statement)) {
                checked = check_expression(call->indirect_target, block_index, i, 0);
                if (checked) for (const auto &input : call->register_inputs) {
                    checked = check_use(input.reg, input.version, block_index, i);
                    if (!checked) break;
                }
                if (checked) checked = check_memory_use(*call->memory_input_version, block_index, i);
                if (checked && call->x86_stack_effect &&
                    call->x86_stack_effect->memory_input_version != call->memory_input_version)
                    checked = invalid("SSA call stack effect disagrees with its whole-memory input");
            } else if (const auto *branch = std::get_if<Branch>(&statement)) {
                checked = check_expression(branch->predicate, block_index, i, 0);
                if (checked) checked = check_expression(branch->indirect_target, block_index, i, 0);
            } else if (const auto *ret = std::get_if<Return>(&statement)) {
                checked = check_expression(ret->value, block_index, i, 0);
                if (checked && ret->x86_stack_effect) {
                    if (!ret->x86_stack_effect->memory_input_version)
                        checked = invalid("SSA return stack effect has no whole-memory input");
                    else checked = check_memory_use(*ret->x86_stack_effect->memory_input_version,
                                                    block_index, i);
                }
            } else if (const auto *intrinsic = std::get_if<Intrinsic>(&statement)) {
                for (const auto &operand : intrinsic->operands) {
                    checked = check_expression(operand, block_index, i, 0);
                    if (!checked) break;
                }
                if (checked) for (const auto &output : intrinsic->register_output_values) {
                    checked = check_expression(output, block_index, i, 0);
                    if (!checked) break;
                }
                if (checked && intrinsic->memory_input_version)
                    checked = check_memory_use(*intrinsic->memory_input_version, block_index, i);
            }
            if (!checked) return checked.error();
            const std::vector<MemoryPartitionEffect> *partition_effects = nullptr;
            if (const auto *store = std::get_if<Store>(&statement)) {
                partition_effects = &store->memory_partition_effects;
                if (store->memory_partition) {
                    if (store->memory_partition->empty() ||
                        std::none_of(partition_effects->begin(), partition_effects->end(), [&](const auto &effect) {
                            return effect.partition == *store->memory_partition;
                        }))
                        return invalid("SSA store partition has no matching partition effect");
                }
            } else if (const auto *call = std::get_if<Call>(&statement)) {
                partition_effects = &call->memory_partition_effects;
            } else if (const auto *intrinsic = std::get_if<Intrinsic>(&statement)) {
                partition_effects = &intrinsic->memory_partition_effects;
            }
            if (partition_effects) for (const auto &effect : *partition_effects) {
                auto partition_use = check_partition_use(effect.partition, effect.input_version,
                                                         block_index, i);
                if (!partition_use) return partition_use.error();
            }
        }
        if (block.switch_dispatch) {
            auto checked = check_expression(block.switch_dispatch->selector, block_index,
                                            block.instructions.size(), 0);
            if (!checked) return checked.error();
        }
    }

    return summary;
}
} // namespace hexlab::decompiler
