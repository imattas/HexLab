#include "hexlab/analysis/switches.hpp"
#include "hexlab/analysis/relocations.hpp"
#include "instruction_flow.hpp"

#include "hexlab/image/image.hpp"
#include "hexlab/processors/decoder.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <deque>
#include <limits>
#include <map>

namespace hexlab {
namespace {
constexpr std::size_t max_blocks = 1000000;
constexpr std::size_t max_instructions = 16000000;
constexpr std::size_t max_relative_base_scan = 4096;
// Keep hostile or malformed tables bounded while supporting real compiler
// output with several hundred switch arms.
constexpr std::size_t max_entries = 4096;

bool x86_mode(DecodeContext context) {
    return context.architecture == Architecture::x86 || context.architecture == Architecture::x86_64;
}

bool executable_file_byte(const Image &image, Address at) {
    const auto *segment = image.segment_at(at);
    if (!segment || !segment->executable || at.offset < segment->begin.offset)
        return false;
    return at.offset - segment->begin.offset < segment->file_size && image.code_window(at, 1) == 1;
}

bool file_backed_range(const Image &image, Address at, std::size_t size, bool executable) {
    std::uint64_t cursor = at.offset;
    std::size_t remaining = size;
    while (remaining) {
        const auto *segment = image.segment_at({at.space, cursor});
        if (!segment || (executable && !segment->executable) || (!executable && !segment->readable) ||
            cursor < segment->begin.offset)
            return false;
        const auto relative = cursor - segment->begin.offset;
        if (relative >= segment->file_size)
            return false;
        const auto available = segment->file_size - relative;
        const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(available, remaining));
        if (count == 0)
            return false;
        remaining -= count;
        if (remaining) {
            if (count > UINT64_MAX - cursor)
                return false;
            cursor += count;
        }
    }
    return true;
}

std::optional<Address> add_offset(Address base, std::uint64_t delta, const Image &image) {
    const auto *space = image.space(base.space);
    if (!space || delta > UINT64_MAX - base.offset)
        return {};
    const auto value = base.offset + delta;
    if (space->width_bits < 64 && value >= (UINT64_C(1) << space->width_bits))
        return {};
    return Address{base.space, value};
}

std::optional<Address> add_signed_offset(Address base, std::int64_t delta, const Image &image) {
    if (delta < 0) {
        const auto magnitude = static_cast<std::uint64_t>(-(delta + 1)) + 1;
        if (magnitude > base.offset)
            return {};
        return Address{base.space, base.offset - magnitude};
    }
    return add_offset(base, static_cast<std::uint64_t>(delta), image);
}

struct A64RelocatedTableAddress {
    bool relocation_present = false;
    std::optional<Address> address;
    std::vector<std::uint64_t> rows;
};

A64RelocatedTableAddress a64_adrp_add_relocated_address(const Image &image, const ImageMetadata *metadata,
                                                        const RelocationResolver *relocations,
                                                        const Instruction &page, const Instruction &add,
                                                        std::stop_token stop) {
    if (!metadata || !metadata->elf || !relocations || metadata->elf->header.machine != 183 ||
        !metadata->elf->header.is_64 || metadata->elf->header.order != ByteOrder::little ||
        metadata->elf->header.object_type != 1)
        return {};
    auto page_resolution = relocations->operand(page, 1, stop);
    auto add_resolution = relocations->operand(add, 2, stop);
    if (!page_resolution || !add_resolution)
        return {};
    const auto &page_rows = page_resolution.value().relocations;
    const auto &add_rows = add_resolution.value().relocations;
    if (page_rows.empty() && add_rows.empty())
        return {};
    A64RelocatedTableAddress result;
    result.relocation_present = true;
    if (page_rows.size() != 1 || add_rows.size() != 1 || page_rows.front() == add_rows.front() ||
        page_rows.front() >= metadata->elf->relocations.size() || add_rows.front() >= metadata->elf->relocations.size())
        return result;

    const auto &page_relocation = metadata->elf->relocations[static_cast<std::size_t>(page_rows.front())];
    const auto &add_relocation = metadata->elf->relocations[static_cast<std::size_t>(add_rows.front())];
    const auto target_section_matches = [](const ElfRelocation &relocation, Address place) {
        return relocation.target_section && *relocation.target_section == place.space.value;
    };
    // ADR_PREL_PG_HI21 and its NC form compute the same symbol page;
    // NC omits the linker's overflow diagnostic, not the address equation.
    if ((page_relocation.type != 275 && page_relocation.type != 276) || add_relocation.type != 277 ||
        page_relocation.kind != ElfRelocationKind::unknown || add_relocation.kind != ElfRelocationKind::unknown ||
        !page_relocation.explicit_addend || !add_relocation.explicit_addend ||
        !page_relocation.addend || !add_relocation.addend || page_relocation.addend != add_relocation.addend ||
        !page_relocation.symbol_index_validated || !add_relocation.symbol_index_validated ||
        !page_relocation.symbol_table || page_relocation.symbol_table != add_relocation.symbol_table ||
        page_relocation.symbol_index != add_relocation.symbol_index || page_relocation.place != page.address ||
        add_relocation.place != add.address || page_relocation.field_size != 4 || add_relocation.field_size != 4 ||
        !target_section_matches(page_relocation, page.address) || !target_section_matches(add_relocation, add.address) ||
        page.address.space != add.address.space)
        return result;

    const auto symbol_table = std::find_if(metadata->elf->symbol_tables.begin(), metadata->elf->symbol_tables.end(),
        [&](const ElfSymbolTable &candidate) { return candidate.source == *page_relocation.symbol_table; });
    if (symbol_table == metadata->elf->symbol_tables.end() || !symbol_table->count || !symbol_table->symbol_begin ||
        page_relocation.symbol_index >= *symbol_table->count ||
        *symbol_table->symbol_begin > metadata->elf->symbols.size() ||
        page_relocation.symbol_index > metadata->elf->symbols.size() - *symbol_table->symbol_begin)
        return result;
    const auto symbol_index = *symbol_table->symbol_begin + page_relocation.symbol_index;
    if (symbol_index >= metadata->elf->symbols.size())
        return result;
    const auto &symbol = metadata->elf->symbols[static_cast<std::size_t>(symbol_index)];
    if (symbol.state != ElfSymbolState::defined || !symbol.address ||
        (symbol.type != 0 && symbol.type != 1 && symbol.type != 3) || symbol.binding != 0 ||
        symbol.visibility > 3 || symbol.address->space.value != symbol.section_index)
        return result;

    const auto table = add_signed_offset(*symbol.address, *page_relocation.addend, image);
    if (!table)
        return result;
    result.address = table;
    result.rows = {page_rows.front(), add_rows.front()};
    return result;
}

std::optional<Address> relocated_operand_address(const Instruction &instruction, std::uint32_t index,
                                                 std::optional<Address> decoded,
                                                 const RelocationResolver *relocations,
                                                 std::stop_token stop) {
    if (relocations) {
        auto resolution = relocations->operand(instruction, index, stop);
        if (!resolution)
            return {};
        if (resolution.value().relocated())
            return resolution.value().address;
    }
    return decoded;
}

std::optional<Address> absolute_table_base(const Instruction &instruction, const MemoryOperand &memory,
                                           std::uint32_t operand_index,
                                           const RelocationResolver *relocations,
                                           std::stop_token stop) {
    if (memory.segment)
        return {};
    if (const auto resolved = relocated_operand_address(instruction, operand_index, memory.resolved_address,
                                                        relocations, stop))
        return resolved;
    if (relocations) {
        const auto resolution = relocations->operand(instruction, operand_index, stop);
        if (!resolution || resolution.value().relocated())
            return {};
    }
    // x64 RIP-relative operands are resolved by the decoder from instruction
    // end + signed displacement. Preserve that exact address for table reads.
    if (memory.base || memory.ip_relative ||
        (memory.address_width != 16 && memory.address_width != 32 && memory.address_width != 64))
        return {};
    std::uint64_t offset = static_cast<std::uint64_t>(memory.displacement);
    if (memory.address_width < 64)
        offset &= (UINT64_C(1) << memory.address_width) - 1;
    return Address{instruction.address.space, offset};
}

struct TableTarget {
    Address address;
    SwitchCase::TargetSource source = SwitchCase::TargetSource::encoded_bytes;
    std::vector<std::uint64_t> relocation_rows;
    std::vector<std::uint64_t> dyld_classic_rows;
    std::vector<std::uint64_t> dyld_chained_rows;
};

std::optional<TableTarget> table_target(const Image &image, Address table, std::size_t index,
                                        std::size_t width, bool relative_to_table = false,
                                        const RelocationResolver *relocations = nullptr, std::stop_token stop = {},
                                        std::optional<Address> relative_base = {}) {
    if (index > (UINT64_MAX / width))
        return {};
    const auto entry = add_offset(table, static_cast<std::uint64_t>(index * width), image);
    if (!entry)
        return {};
    if (!file_backed_range(image, *entry, width, false))
        return {};
    if (relocations) {
        auto fixed = relocations->data_at(image, *entry, static_cast<std::uint8_t>(width), stop);
        if (!fixed)
            return {};
        if (fixed.value().relocated()) {
            if (!fixed.value().address)
                return {};
            const auto source = fixed.value().dyld
                                    ? SwitchCase::TargetSource::macho_dyld_rebase
                                    : relocations->format() == RelocationFormat::macho
                                          ? SwitchCase::TargetSource::macho_relocation
                                          : SwitchCase::TargetSource::elf_relocation;
            TableTarget target{*fixed.value().address, source};
            target.relocation_rows = fixed.value().relocations;
            if (fixed.value().dyld)
                for (const auto origin : fixed.value().dyld->resolution.origins)
                    (origin.source == MachODyldSource::classic ? target.dyld_classic_rows
                                                               : target.dyld_chained_rows)
                        .push_back(origin.row);
            return target;
        }
    }
    const auto bytes = image.read(*entry, width);
    if (!bytes || bytes.value().size() != width)
        return {};
    const auto *space = image.space(table.space);
    if (!space)
        return {};
    std::uint64_t value = 0;
    if (space->order == ByteOrder::little) {
        for (std::size_t i = 0; i < width; ++i)
            value |= std::uint64_t(std::to_integer<unsigned char>(bytes.value()[i])) << (i * 8);
    } else {
        for (const auto byte : bytes.value())
            value = (value << 8) | std::to_integer<unsigned char>(byte);
    }
    if (relative_to_table) {
        if (width != 4)
            return {};
        const auto base = relative_base.value_or(table);
        if (base.space != table.space)
            return {};
        const auto displacement = static_cast<std::int32_t>(static_cast<std::uint32_t>(value));
        if (displacement < 0) {
            const auto magnitude = static_cast<std::uint64_t>(-static_cast<std::int64_t>(displacement));
            if (magnitude > base.offset)
                return {};
            return TableTarget{Address{base.space, base.offset - magnitude}};
        }
        const auto target = add_offset(base, static_cast<std::uint32_t>(displacement), image);
        return target ? std::optional<TableTarget>(TableTarget{*target}) : std::nullopt;
    }
    return TableTarget{Address{table.space, value}};
}

std::optional<std::uint64_t> unsigned_table_entry(const Image &image, Address table, std::size_t index,
                                                  std::size_t width) {
    if ((width != 1 && width != 2) || index > UINT64_MAX / width)
        return {};
    const auto entry = add_offset(table, static_cast<std::uint64_t>(index * width), image);
    if (!entry || !file_backed_range(image, *entry, width, false))
        return {};
    const auto bytes = image.read(*entry, width);
    if (!bytes || bytes.value().size() != width)
        return {};
    const auto *space = image.space(table.space);
    if (!space)
        return {};
    std::uint64_t value = 0;
    if (space->order == ByteOrder::little) {
        for (std::size_t n = 0; n < width; ++n)
            value |= std::uint64_t(std::to_integer<unsigned char>(bytes.value()[n])) << (n * 8);
    } else {
        for (const auto byte : bytes.value())
            value = (value << 8) | std::to_integer<unsigned char>(byte);
    }
    return value;
}

bool decodes_at(const Image &image, DecodeContext context, Address target, std::stop_token stop) {
    if (stop.stop_requested() || !executable_file_byte(image, target))
        return false;
    const auto target_context = image.context_at(target);
    if (!target_context || target_context.value().architecture != context.architecture ||
        target_context.value().mode != context.mode)
        return false;
    const auto count = static_cast<std::size_t>(image.code_window(target, 15));
    if (count == 0)
        return false;
    const auto bytes = image.read(target, count);
    if (!bytes)
        return false;
    const auto decoded = decode_instruction(context, bytes.value(), target);
    return decoded.status == DecodeStatus::decoded && decoded.instruction.has_value() &&
           file_backed_range(image, target, decoded.instruction->length, true);
}

const RegisterOperand *register_operand(const Instruction &instruction, std::size_t index) {
    return index < instruction.operands.size()
               ? std::get_if<RegisterOperand>(&instruction.operands[index])
               : nullptr;
}

bool same_register(const RegisterOperand *a, const RegisterOperand *b) {
    return a && b && a->bank == b->bank && a->index == b->index;
}

bool writes_register(const Instruction &instruction, RegisterOperand reg) {
    if (std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                    [&](const RegisterOperand &written) { return same_register(&written, &reg); }))
        return true;
    for (std::size_t i = 0; i < instruction.operands.size() && i < instruction.access.size(); ++i) {
        const auto *operand = std::get_if<RegisterOperand>(&instruction.operands[i]);
        if (operand && same_register(operand, &reg) &&
            (instruction.access[i] == OperandAccess::write || instruction.access[i] == OperandAccess::read_write))
            return true;
    }
    return false;
}

using GuardAddress = std::pair<std::uint32_t, std::uint64_t>;
GuardAddress guard_address(Address value) { return {value.space.value, value.offset}; }

struct SwitchGuardGraph {
    struct Node {
        const InstructionFact *fact = nullptr;
        std::vector<std::size_t> predecessors;
        bool alternate_entry = false;
        bool ambiguous = false;
    };
    std::vector<Node> nodes;
    std::map<GuardAddress, std::size_t> addresses;
    // A proof is optional evidence. Exhaustion retains the unbounded table
    // scan rather than spending unbounded work on many candidate guards.
    std::size_t remaining_work = 2000000;

    bool proves(Address sequence, Address dispatch, Address compare, Address guard, Address fallthrough, RegisterOperand selector,
                DecodeContext context, std::stop_token stop) {
        const auto end = addresses.find(guard_address(sequence));
        const auto boundary = addresses.find(guard_address(guard));
        const auto comparison = addresses.find(guard_address(compare));
        if (end == addresses.end() || boundary == addresses.end() || comparison == addresses.end()) return false;
        const auto endpoint = end->second;
        const auto guard_index = boundary->second;
        const auto &guard_node = nodes[guard_index];
        if (guard_node.alternate_entry || guard_node.ambiguous || guard_node.predecessors.size() != 1 ||
            guard_node.predecessors.front() != comparison->second || nodes[comparison->second].ambiguous)
            return false;
        // Account for the per-node scratch arrays and ready-queue scan before
        // allocating them, so many failed guards cannot multiply graph work.
        if (nodes.size() > remaining_work / 4) return false;
        remaining_work -= nodes.size() * 4;
        // A transfer into the middle of the recognized setup sequence bypasses
        // both the guard and the selector-preserving path to its beginning.
        auto cursor = end;
        std::optional<std::size_t> previous;
        Address expected = sequence;
        bool reached_dispatch = false;
        for (; cursor != addresses.end(); ++cursor) {
            if (stop.stop_requested() || remaining_work == 0) return false;
            --remaining_work;
            const auto &node = nodes[cursor->second];
            const auto &instruction = node.fact->instruction;
            if (instruction.address != expected || instruction.context != context || node.ambiguous ||
                node.alternate_entry) return false;
            if (previous && (node.predecessors.size() != 1 || node.predecessors.front() != *previous))
                return false;
            if (instruction.address == dispatch) { reached_dispatch = true; break; }
            if (instruction.flow != FlowKind::fallthrough) return false;
            const auto next = analysis_detail::continuation_address(instruction);
            if (!next) return false;
            previous = cursor->second;
            expected = next.value();
        }
        if (!reached_dispatch) return false;
        std::vector<bool> seen(nodes.size(), false);
        std::vector<std::size_t> dependencies(nodes.size(), 0);
        std::vector<std::vector<std::size_t>> dependents(nodes.size());
        std::vector<std::size_t> pending{endpoint};
        seen[endpoint] = true;
        std::size_t visited = 0;
        bool reached_guard = false;
        while (!pending.empty()) {
            if (stop.stop_requested() || remaining_work == 0) return false;
            --remaining_work;
            const auto current = pending.back();
            pending.pop_back();
            ++visited;
            const auto &node = nodes[current];
            const auto &instruction = node.fact->instruction;
            if (node.alternate_entry || node.ambiguous || node.predecessors.empty()) return false;
            if (current != endpoint &&
                (instruction.context != context || instruction.opcode == Opcode::opaque ||
                 instruction.opcode == Opcode::x86_opaque || writes_register(instruction, selector) ||
                 instruction.flow == FlowKind::call || instruction.flow == FlowKind::ret ||
                 instruction.flow == FlowKind::trap ||
                 ((instruction.flow == FlowKind::jump || instruction.flow == FlowKind::conditional_branch) &&
                  !instruction.direct_target)))
                return false;
            for (const auto predecessor : node.predecessors) {
                if (stop.stop_requested() || remaining_work == 0) return false;
                --remaining_work;
                if (predecessor == guard_index) {
                    // Only the selector-in-range edge establishes this fact.
                    // Reaching the default arm and then rejoining is a bypass.
                    if (instruction.address != fallthrough) return false;
                    reached_guard = true;
                    continue;
                }
                ++dependencies[current];
                dependents[predecessor].push_back(current);
                if (!seen[predecessor]) {
                    seen[predecessor] = true;
                    pending.push_back(predecessor);
                }
            }
        }
        if (!reached_guard) return false;
        // Reject cyclic backward cones. This deliberately does not guess a
        // loop invariant for a selector, even when no visible write occurs.
        std::deque<std::size_t> ready;
        for (std::size_t i = 0; i < nodes.size(); ++i)
            if (seen[i] && dependencies[i] == 0) ready.push_back(i);
        std::size_t resolved = 0;
        while (!ready.empty()) {
            if (stop.stop_requested() || remaining_work == 0) return false;
            --remaining_work;
            const auto current = ready.front();
            ready.pop_front();
            ++resolved;
            for (const auto next : dependents[current])
                if (--dependencies[next] == 0) ready.push_back(next);
        }
        return resolved == visited;
    }
};

using GuardBlocks = std::map<std::uint64_t, std::shared_ptr<const BasicBlock>>;
struct SwitchGuardContext {
    const GuardBlocks &blocks;
    std::optional<SwitchGuardGraph> graph;
    bool graph_attempted = false;
    std::size_t remaining_scan_work = 4000000;
    bool scan(std::stop_token stop) {
        if (stop.stop_requested() || remaining_scan_work == 0) return false;
        --remaining_scan_work;
        return true;
    }
};

std::optional<SwitchGuardGraph> switch_guard_graph(
    const FunctionRecord &function, const FunctionSnapshot &snapshot,
    SwitchGuardContext &guards, std::stop_token stop) {
    constexpr std::size_t max_guard_nodes = 100000;
    constexpr std::size_t max_guard_edges = 1000000;
    if (function.blocks.size() > max_guard_nodes) return {};
    SwitchGuardGraph graph;
    for (const auto id : function.blocks) {
        if (!guards.scan(stop)) return {};
        const auto block = guards.blocks.find(id.value);
        if (block == guards.blocks.end()) return {};
        for (const auto &fact : block->second->instructions) {
            if (!guards.scan(stop)) return {};
            if (!fact) continue;
            const auto key = guard_address(fact->instruction.address);
            const auto found = graph.addresses.find(key);
            if (found != graph.addresses.end()) {
                if (graph.nodes[found->second].fact != fact.get())
                    graph.nodes[found->second].ambiguous = true;
                continue;
            }
            if (graph.nodes.size() == max_guard_nodes) return {};
            graph.addresses.emplace(key, graph.nodes.size());
            graph.nodes.push_back({fact.get(), {}, false, false});
        }
    }
    const auto mark_entry = [&](Address address) {
        const auto found = graph.addresses.find(guard_address(address));
        if (found != graph.addresses.end()) graph.nodes[found->second].alternate_entry = true;
    };
    mark_entry(function.entry);
    for (const auto &other : snapshot.functions)
        if (!guards.scan(stop)) return {};
        else if (other) mark_entry(other->entry);
    std::size_t edges = 0;
    const auto connect = [&](const InstructionFact *source, Address target, bool trusted) {
        const auto destination = graph.addresses.find(guard_address(target));
        if (destination == graph.addresses.end()) return true;
        if (++edges > max_guard_edges) return false;
        auto &node = graph.nodes[destination->second];
        const auto origin = source ? graph.addresses.find(guard_address(source->instruction.address))
                                   : graph.addresses.end();
        if (!trusted || origin == graph.addresses.end() ||
            graph.nodes[origin->second].fact != source) {
            node.alternate_entry = true;
        } else node.predecessors.push_back(origin->second);
        return true;
    };
    // Include all known incoming transfers, including callers and blocks not
    // owned by this function. Such entries cannot inherit the guard's value.
    for (const auto &block : snapshot.blocks) {
        if (!guards.scan(stop)) return {};
        if (!block) continue;
        std::map<GuardAddress, const InstructionFact *> member_sources;
        for (const auto &fact : block->instructions) {
            if (!guards.scan(stop)) return {};
            if (!fact) continue;
            const auto &instruction = fact->instruction;
            const auto member = graph.addresses.find(guard_address(instruction.address));
            if (member != graph.addresses.end() && graph.nodes[member->second].fact == fact.get())
                member_sources.emplace(member->first, fact.get());
            if (instruction.direct_target && !connect(fact.get(), *instruction.direct_target, true)) return {};
            if (instruction.flow == FlowKind::fallthrough || instruction.flow == FlowKind::conditional_branch ||
                instruction.flow == FlowKind::call) {
                const auto next = analysis_detail::continuation_address(instruction);
                if (next && !connect(fact.get(), next.value(), true)) return {};
            }
        }
        for (const auto &edge : block->successors) {
            if (!guards.scan(stop)) return {};
            if (!edge.target) continue;
            const auto source = member_sources.find(guard_address(edge.source));
            const InstructionFact *fact = source == member_sources.end() ? nullptr : source->second;
            bool trusted = false;
            if (fact && edge.kind != BlockEdgeKind::unresolved && edge.kind != BlockEdgeKind::delay_slot) {
                const auto &instruction = fact->instruction;
                const auto next = analysis_detail::continuation_address(instruction);
                trusted = instruction.direct_target == edge.target ||
                    ((instruction.flow == FlowKind::fallthrough || instruction.flow == FlowKind::conditional_branch ||
                      instruction.flow == FlowKind::call) && next && next.value() == *edge.target);
            }
            if (!connect(fact, *edge.target, trusted)) return {};
        }
    }
    for (auto &node : graph.nodes) {
        if (!guards.scan(stop)) return {};
        std::sort(node.predecessors.begin(), node.predecessors.end());
        node.predecessors.erase(std::unique(node.predecessors.begin(), node.predecessors.end()),
                                node.predecessors.end());
    }
    return graph;
}

struct SwitchBound {
    std::uint32_t case_count = 0;
    Address default_target{{0}, 0};
    bool operator==(const SwitchBound &) const = default;
};

std::optional<SwitchBound> guarded_case_bound(const Image &image, const FunctionRecord &function,
                                               const FunctionSnapshot &snapshot,
                                               const RegisterOperand &selector, Address sequence_begin, Address dispatch,
                                               DecodeContext context, SwitchGuardContext &guards, std::stop_token stop) {
    // A guard only bounds the table when its known predecessor proof is
    // exhaustive. An incomplete function/snapshot can omit a block that enters
    // setup without passing this guard, so retain prefix scanning but publish
    // no case count or default-target evidence.
    if (!function.complete || !snapshot.complete || stop.stop_requested())
        return {};
    const auto &blocks = guards.blocks;

    std::optional<SwitchBound> result;
    for (const auto id : function.blocks) {
        if (!guards.scan(stop))
            return {};
        const auto found = blocks.find(id.value);
        if (found == blocks.end())
            continue;
        const auto &instructions = found->second->instructions;
        for (std::size_t branch_index = 1; branch_index < instructions.size(); ++branch_index) {
            if (!guards.scan(stop))
                return {};
            const auto &compare_fact = instructions[branch_index - 1];
            const auto &branch_fact = instructions[branch_index];
            if (!compare_fact || !branch_fact)
                continue;
            const auto &compare = compare_fact->instruction;
            const auto &branch = branch_fact->instruction;
            if (compare.flow != FlowKind::fallthrough || compare.context != branch.context ||
                branch.flow != FlowKind::conditional_branch || branch.context != context ||
                !branch.direct_target)
                continue;
            bool exclusive_upper_bound = false;
            bool signed_upper_bound = false;
            bool mips_strict_upper_bound = false;
            const RegisterOperand *compared_register = nullptr;
            const ImmediateOperand *immediate = nullptr;
            if (x86_mode(context) && compare.opcode == Opcode::cmp && compare.operands.size() == 2 &&
                branch.opcode == Opcode::jcc && branch.x86_condition &&
                (*branch.x86_condition == X86Condition::above ||
                 *branch.x86_condition == X86Condition::above_equal ||
                 *branch.x86_condition == X86Condition::greater)) {
                compared_register = register_operand(compare, 0);
                immediate = std::get_if<ImmediateOperand>(&compare.operands[1]);
                exclusive_upper_bound = *branch.x86_condition == X86Condition::above;
                signed_upper_bound = *branch.x86_condition == X86Condition::greater;
            } else if (context.architecture == Architecture::arm64 && context.mode == ExecutionMode::a64 &&
                       compare.opcode == Opcode::a64_subs && compare.operands.size() == 3 &&
                       branch.opcode == Opcode::a64_b_cond &&
                       (branch.condition == 2 || branch.condition == 8 || branch.condition == 12)) {
                // CMP is SUBS to WZR/XZR. B.HS (CS) proves selector < imm;
                // B.HI proves selector <= imm; B.GT is the signed upper guard
                // paired with B.LT below. Immediate representation and width
                // are checked below.
                const auto *destination = register_operand(compare, 0);
                compared_register = register_operand(compare, 1);
                immediate = std::get_if<ImmediateOperand>(&compare.operands[2]);
                if (!destination || destination->bank != RegisterBank::arm64_gpr || destination->index != 31 ||
                    !immediate || immediate->encoded_width != 12 || immediate->is_signed)
                    continue;
                exclusive_upper_bound = branch.condition == 8;
                signed_upper_bound = branch.condition == 12;
            } else if (context.architecture == Architecture::arm && context.mode == ExecutionMode::thumb &&
                       compare.opcode == Opcode::a32_cmp && compare.operands.size() == 2 &&
                       branch.opcode == Opcode::t32_b && (branch.condition == 2 || branch.condition == 8)) {
                compared_register = register_operand(compare, 0);
                immediate = std::get_if<ImmediateOperand>(&compare.operands[1]);
                exclusive_upper_bound = branch.condition == 8;
            } else if (context.architecture == Architecture::riscv64 && context.mode == ExecutionMode::rv64 &&
                       compare.opcode == Opcode::rv_sltiu && compare.operands.size() == 3 &&
                       branch.opcode == Opcode::rv_beq && branch.operands.size() == 3) {
                // SLTIU Xguard, Xselector, positive_bound; BEQ Xguard, X0,
                // default proves that the fallthrough selector is below the
                // bound. A negative immediate is sign-extended before the
                // unsigned comparison and is not a useful table bound here.
                const auto *guard = register_operand(compare, 0);
                compared_register = register_operand(compare, 1);
                immediate = std::get_if<ImmediateOperand>(&compare.operands[2]);
                const auto *left = register_operand(branch, 0);
                const auto *right = register_operand(branch, 1);
                if (!guard || !compared_register || !immediate || guard->bank != RegisterBank::riscv_gpr ||
                    guard->width != 64 || guard->index == 0 || *guard == *compared_register ||
                    !((same_register(left, guard) && right && right->bank == RegisterBank::riscv_gpr &&
                       right->width == 64 && right->index == 0) ||
                      (same_register(right, guard) && left && left->bank == RegisterBank::riscv_gpr &&
                       left->width == 64 && left->index == 0)) ||
                    immediate->encoded_width != 12 || immediate->effective_width != 64 ||
                    !immediate->is_signed || immediate->value == 0 || immediate->value > 2047)
                    continue;
            } else if ((context.architecture == Architecture::mips32 && context.mode == ExecutionMode::mips32) ||
                       (context.architecture == Architecture::mips64 && context.mode == ExecutionMode::mips64)) {
                const auto expected_compare = context.mode == ExecutionMode::mips64
                    ? Opcode::mips64_sltiu : Opcode::mips_sltiu;
                if (compare.opcode != expected_compare || compare.operands.size() != 3 ||
                    branch.opcode != Opcode::mips_beq || branch.operands.size() != 3 ||
                    branch.delay_slots != 1)
                    continue;
                const auto *guard = register_operand(compare, 0);
                compared_register = register_operand(compare, 1);
                immediate = std::get_if<ImmediateOperand>(&compare.operands[2]);
                const auto *left = register_operand(branch, 0);
                const auto *right = register_operand(branch, 1);
                const auto width = context.mode == ExecutionMode::mips64 ? 64u : 32u;
                const bool tests_guard_against_zero =
                    (same_register(left, guard) && right && right->bank == RegisterBank::mips_gpr &&
                     right->width == width && right->index == 0) ||
                    (same_register(right, guard) && left && left->bank == RegisterBank::mips_gpr &&
                     left->width == width && left->index == 0);
                if (!guard || !compared_register || !immediate || !tests_guard_against_zero ||
                    guard->bank != RegisterBank::mips_gpr || guard->width != width || guard->index == 0 ||
                    *guard == *compared_register || compared_register->bank != RegisterBank::mips_gpr ||
                    compared_register->width != width || immediate->encoded_width != 16 ||
                    immediate->effective_width != width || !immediate->is_signed ||
                    immediate->value == 0 || immediate->value > max_entries)
                    continue;
                // SLTIU produces one when selector < bound. BEQ to the default
                // arm therefore rejects selector >= bound, leaving exactly
                // [0, bound) for the table. The classic delay slot executes
                // on both paths and must be a known, side-effect-free op.
                mips_strict_upper_bound = true;
            } else {
                continue;
            }
            const auto compare_end = analysis_detail::continuation_address(compare);
            const auto branch_end = analysis_detail::continuation_address(branch);
            if (!compare_end || compare_end.value() != branch.address || !branch_end)
                continue;

            if (mips_strict_upper_bound) {
                if (branch_index + 1 >= instructions.size() || !instructions[branch_index + 1] ||
                    branch_end.value() != sequence_begin)
                    continue;
                const auto &delay_slot = instructions[branch_index + 1]->instruction;
                const auto slot_address = add_offset(branch.address, branch.byte_length(), image);
                if (!slot_address || delay_slot.address != *slot_address || delay_slot.context != context ||
                    delay_slot.flow != FlowKind::fallthrough || delay_slot.delay_slots != 0 ||
                    !delay_slot.register_writes.empty() || delay_slot.memory_read || delay_slot.memory_write)
                    continue;
            }

            if (*branch.direct_target == sequence_begin || *branch.direct_target == branch_end.value())
                continue;
            if (!signed_upper_bound && branch_end.value() != sequence_begin) {
                if (!guards.graph_attempted) {
                    guards.graph = switch_guard_graph(function, snapshot, guards, stop);
                    guards.graph_attempted = true;
                }
                if (!guards.graph || !guards.graph->proves(sequence_begin, dispatch, compare.address,
                                                            branch.address, branch_end.value(), selector, context, stop))
                    continue;
            } else if (!signed_upper_bound) {
                // Keep the existing local proof available even when the optional
                // cross-block graph exceeds its stricter memory/work budget.
                bool bypass = false;
                const auto enters_guarded_region = [&](Address target) {
                    return target.space == sequence_begin.space && target.offset >= branch.address.offset &&
                           target.offset <= dispatch.offset;
                };
                for (const auto &[other_id, other] : blocks) {
                    if (!guards.scan(stop))
                        return {};
                    for (const auto &edge : other->successors)
                        if (!guards.scan(stop))
                            return {};
                        else if (edge.target && enters_guarded_region(*edge.target) &&
                            !(other_id == id.value && edge.kind == BlockEdgeKind::conditional_false &&
                              edge.source == branch.address && edge.target == sequence_begin))
                            bypass = true;
                    for (const auto &fact : other->instructions)
                        if (!guards.scan(stop))
                            return {};
                        else if (fact && fact->instruction.direct_target &&
                            enters_guarded_region(*fact->instruction.direct_target))
                            bypass = true;
                }
                if (bypass)
                    continue;
            }

            const bool x86_zero_extend_index = signed_upper_bound && x86_mode(context) &&
                context.mode == ExecutionMode::x86_64 && compared_register &&
                compared_register->bank == RegisterBank::gpr && compared_register->width == 32 &&
                !compared_register->high_byte && selector.bank == RegisterBank::gpr &&
                selector.width == 64 && !selector.high_byte && compared_register->index == selector.index;
            const bool exact_selector = compared_register && *compared_register == selector;
            if (!compared_register || (!exact_selector && !x86_zero_extend_index) ||
                (x86_mode(context) && (selector.bank != RegisterBank::gpr || selector.high_byte ||
                 (selector.width != 16 && selector.width != 32 && selector.width != 64))) ||
                (context.architecture == Architecture::arm64 &&
                 (selector.bank != RegisterBank::arm64_gpr || (selector.width != 32 && selector.width != 64) ||
                  !compared_register || compared_register->width != selector.width)) ||
                (context.architecture == Architecture::arm &&
                 (selector.bank != RegisterBank::arm32_gpr || selector.width != 32 || selector.high_byte ||
                  !compared_register || compared_register->bank != RegisterBank::arm32_gpr ||
                  compared_register->width != selector.width)) ||
                (context.architecture == Architecture::riscv64 &&
                 (selector.bank != RegisterBank::riscv_gpr || selector.width != 64 || selector.index == 0 ||
                  !compared_register || compared_register->width != 64)) ||
                !immediate || immediate->effective_width != (x86_zero_extend_index ? compared_register->width : selector.width) ||
                immediate->effective_width > 64 || immediate->encoded_width == 0 ||
                immediate->encoded_width > immediate->effective_width ||
                (immediate->encoded_width < 64 && immediate->value >= (UINT64_C(1) << immediate->encoded_width)))
                continue;
            std::optional<std::uint64_t> signed_range_min;
            std::optional<std::uint64_t> signed_range_max;
            std::optional<Address> normalized_sequence;
            if (signed_upper_bound) {
                if (branch_index < 3 || !compared_register || !immediate ||
                    (compared_register->width != 16 && compared_register->width != 32 && compared_register->width != 64))
                    continue;
                const auto &lower_compare_fact = instructions[branch_index - 3];
                const auto &lower_branch_fact = instructions[branch_index - 2];
                if (!lower_compare_fact || !lower_branch_fact)
                    continue;
                const auto &lower_compare = lower_compare_fact->instruction;
                const auto &lower_branch = lower_branch_fact->instruction;
                const bool a64_signed_pair = context.architecture == Architecture::arm64 &&
                    context.mode == ExecutionMode::a64 && lower_compare.opcode == Opcode::a64_subs &&
                    lower_compare.operands.size() == 3 && lower_branch.opcode == Opcode::a64_b_cond &&
                    lower_branch.condition == 11;
                const bool x86_signed_pair = x86_mode(context) && lower_compare.opcode == Opcode::cmp &&
                    lower_compare.operands.size() == 2 && lower_branch.opcode == Opcode::jcc &&
                    lower_branch.x86_condition && *lower_branch.x86_condition == X86Condition::less;
                const auto *lower_register = x86_signed_pair
                    ? register_operand(lower_compare, 0)
                    : a64_signed_pair && register_operand(lower_compare, 0) &&
                          register_operand(lower_compare, 0)->index == 31
                        ? register_operand(lower_compare, 1) : nullptr;
                const auto *lower_immediate = x86_signed_pair
                    ? (lower_compare.operands.size() > 1
                        ? std::get_if<ImmediateOperand>(&lower_compare.operands[1]) : nullptr)
                    : a64_signed_pair && lower_compare.operands.size() > 2
                        ? std::get_if<ImmediateOperand>(&lower_compare.operands[2]) : nullptr;
                const auto *lower_destination = a64_signed_pair
                    ? register_operand(lower_compare, 0) : nullptr;
                const auto lower_compare_end = analysis_detail::continuation_address(lower_compare);
                const auto lower_branch_end = analysis_detail::continuation_address(lower_branch);
                if (lower_compare.context != context || lower_branch.context != context ||
                    lower_compare.flow != FlowKind::fallthrough || lower_branch.flow != FlowKind::conditional_branch ||
                    !(x86_signed_pair || a64_signed_pair) || !lower_branch.direct_target ||
                    *lower_branch.direct_target != *branch.direct_target || !lower_register ||
                    (a64_signed_pair && (!lower_destination || lower_destination->bank != RegisterBank::arm64_gpr ||
                                         lower_destination->index != 31 || !lower_immediate || lower_immediate->is_signed)) ||
                    *lower_register != *compared_register ||
                    !lower_immediate || lower_immediate->effective_width != compared_register->width ||
                    lower_immediate->encoded_width == 0 ||
                    lower_immediate->encoded_width > lower_immediate->effective_width || !lower_compare_end ||
                    (lower_immediate->encoded_width < 64 &&
                     lower_immediate->value >= (UINT64_C(1) << lower_immediate->encoded_width)) ||
                    lower_compare_end.value() != lower_branch.address || !lower_branch_end ||
                    lower_branch_end.value() != compare.address || immediate->effective_width != compared_register->width ||
                    immediate->encoded_width == 0 || immediate->encoded_width > immediate->effective_width)
                    continue;
                const auto sign_bit = UINT64_C(1) << (compared_register->width - 1);
                if ((lower_immediate->value & sign_bit) || (immediate->value & sign_bit) ||
                    lower_immediate->value > immediate->value)
                    continue;
                signed_range_min = lower_immediate->value;
                signed_range_max = immediate->value;
                if (*signed_range_min == 0 && !exact_selector)
                    continue;
                if (*signed_range_min != 0) {
                    // Dense signed ranges with a nonzero lower bound commonly
                    // subtract that bound before indexing. Accept only the
                    // exact in-place SUB at the upper guard's fallthrough;
                    // broad register-value propagation is deliberately out of
                    // scope.
                    if (branch_index + 1 >= instructions.size() || !instructions[branch_index + 1])
                        continue;
                    const auto &normalization = instructions[branch_index + 1]->instruction;
                    const auto normalization_end = analysis_detail::continuation_address(normalization);
                    const bool a64_normalization = context.architecture == Architecture::arm64 &&
                        context.mode == ExecutionMode::a64 && normalization.opcode == Opcode::a64_sub &&
                        normalization.operands.size() == 3;
                    const auto *normalized_register = normalization.opcode == Opcode::sub &&
                        normalization.operands.size() == 2 ? register_operand(normalization, 0) : nullptr;
                    const auto *normalization_immediate = normalization.opcode == Opcode::sub &&
                        normalization.operands.size() == 2
                            ? std::get_if<ImmediateOperand>(&normalization.operands[1])
                            : a64_normalization ? std::get_if<ImmediateOperand>(&normalization.operands[2]) : nullptr;
                    const auto *normalization_source = a64_normalization
                        ? register_operand(normalization, 1) : normalized_register;
                    const auto *a64_destination = a64_normalization
                        ? register_operand(normalization, 0) : nullptr;
                    const bool destination_is_same = a64_normalization
                        ? a64_destination && normalization_source && *a64_destination == *normalization_source &&
                              *normalization_source == *compared_register
                        : normalized_register && (selector.bank == normalized_register->bank &&
                              selector.index == normalized_register->index && !selector.high_byte &&
                              !normalized_register->high_byte &&
                              (selector.width == normalized_register->width ||
                               (context.architecture == Architecture::x86_64 &&
                                context.mode == ExecutionMode::x86_64 && selector.width == 64 &&
                                normalized_register->width == 32)));
                    if (normalization.address != branch_end.value() || normalization.flow != FlowKind::fallthrough ||
                        normalization.context != context || !destination_is_same || !normalization_immediate ||
                        (a64_normalization && (normalization_immediate->encoded_width != 12 ||
                                               normalization_immediate->is_signed)) ||
                        normalization_immediate->effective_width != normalization_source->width ||
                        normalization_immediate->value != *signed_range_min || !normalization_end)
                        continue;
                    normalized_sequence = normalization.address;
                }
            }
            const auto encoded_width = immediate->encoded_width;
            if (immediate->is_signed &&
                ((encoded_width < 64 && (immediate->value & (UINT64_C(1) << (encoded_width - 1)))) ||
                 (encoded_width == 64 && immediate->value > static_cast<std::uint64_t>(INT64_MAX))))
                continue;
            // For signed normalized ranges the encoded upper endpoint may be
            // numerically larger than the entry cap while the interval itself
            // remains small (for example 10000..10003). Bound the derived
            // span below; retain this cheap early check for ordinary bounds.
            if (!signed_range_max && immediate->value > max_entries)
                continue;
            if (signed_range_max) {
                if (!guards.graph_attempted) {
                    guards.graph = switch_guard_graph(function, snapshot, guards, stop);
                    guards.graph_attempted = true;
                }
                if (!guards.graph)
                    continue;
                const auto upper_compare_node = guards.graph->addresses.find(guard_address(compare.address));
                const auto lower_branch_node = guards.graph->addresses.find(guard_address(
                    instructions[branch_index - 2]->instruction.address));
                const auto lower_compare_node = guards.graph->addresses.find(guard_address(
                    instructions[branch_index - 3]->instruction.address));
                if (upper_compare_node == guards.graph->addresses.end() ||
                    lower_branch_node == guards.graph->addresses.end() ||
                    lower_compare_node == guards.graph->addresses.end())
                    continue;
                const auto &upper_node = guards.graph->nodes[upper_compare_node->second];
                const auto &lower_node = guards.graph->nodes[lower_branch_node->second];
                if (upper_node.alternate_entry || upper_node.ambiguous || upper_node.predecessors.size() != 1 ||
                    upper_node.predecessors.front() != lower_branch_node->second ||
                    lower_node.alternate_entry || lower_node.ambiguous || lower_node.predecessors.size() != 1 ||
                    lower_node.predecessors.front() != lower_compare_node->second ||
                    !guards.graph->proves(normalized_sequence.value_or(sequence_begin), dispatch, compare.address,
                                          branch.address, normalized_sequence.value_or(branch_end.value()),
                                          selector, context, stop))
                    continue;
            }
            std::uint64_t count = immediate->value;
            if (signed_range_max && signed_range_min) {
                if (*signed_range_max < *signed_range_min)
                    continue;
                count = *signed_range_max - *signed_range_min + 1;
            } else if (exclusive_upper_bound) {
                if (count == UINT64_MAX)
                    continue;
                ++count;
            }
            if (count == 0 || count > max_entries || count > UINT32_MAX ||
                !decodes_at(image, context, *branch.direct_target, stop))
                continue;
            const SwitchBound candidate{static_cast<std::uint32_t>(count), *branch.direct_target};
            if (result && *result != candidate)
                return {};
            result = candidate;
        }
    }
    return result;
}

std::optional<SwitchSite> relative_offset_switch(const Image &image,
                                                 const FunctionRecord &function,
                                                 const FunctionSnapshot &snapshot,
                                                 const std::vector<std::shared_ptr<const InstructionFact>> &facts,
                                                 std::size_t dispatch_index, SwitchGuardContext &guards,
                                                 const RelocationResolver *relocations, std::stop_token stop) {
    if (dispatch_index < 3 || !facts[dispatch_index] || stop.stop_requested())
        return {};
    const auto &dispatch = facts[dispatch_index]->instruction;
    if (dispatch.opcode != Opcode::jmp || dispatch.flow != FlowKind::jump ||
        dispatch.context.mode != ExecutionMode::x86_64)
        return {};
    const auto *target_reg = register_operand(dispatch, 0);
    if (!target_reg)
        return {};

    for (std::size_t load_index = dispatch_index - 2; load_index > 0; --load_index) {
        const auto add_index = load_index + 1;
        const auto lea_index = load_index - 1;
        if (!facts[lea_index] || !facts[load_index] || !facts[add_index])
            continue;
        const auto &lea = facts[lea_index]->instruction;
        const auto &load = facts[load_index]->instruction;
        const auto &add = facts[add_index]->instruction;
        const auto lea_end = analysis_detail::continuation_address(lea);
        const auto load_end = analysis_detail::continuation_address(load);
        const auto add_end = analysis_detail::continuation_address(add);
        if (lea.flow != FlowKind::fallthrough || load.flow != FlowKind::fallthrough ||
            add.flow != FlowKind::fallthrough || !lea_end || !load_end || !add_end ||
            lea_end.value() != load.address || load_end.value() != add.address || add_end.value() != dispatch.address)
            continue;
        if (lea.opcode != Opcode::lea || load.opcode != Opcode::movsxd || add.opcode != Opcode::add)
            continue;
        const auto *table_reg = register_operand(lea, 0);
        const auto *loaded_reg = register_operand(load, 0);
        const auto *add_dest = register_operand(add, 0);
        const auto *add_src = register_operand(add, 1);
        const auto *table_address = lea.operands.size() > 1
                                        ? std::get_if<MemoryOperand>(&lea.operands[1])
                                        : nullptr;
        const auto resolved_table = table_address
                                        ? relocated_operand_address(lea, 1, table_address->resolved_address,
                                                                    relocations, stop)
                                        : std::optional<Address>{};
        const auto *entries = load.operands.size() > 1
                                  ? std::get_if<MemoryOperand>(&load.operands[1])
                                  : nullptr;
        if (!table_reg || !loaded_reg || !add_dest || !add_src || !table_address || !entries ||
            !same_register(loaded_reg, target_reg) || !same_register(add_dest, loaded_reg) ||
            !same_register(add_src, table_reg) || !same_register(entries->base ? &*entries->base : nullptr, table_reg) ||
            !entries->index || entries->scale != 4 || entries->data_width != 32 || table_address->segment ||
            entries->segment || entries->displacement != 0 ||
            same_register(table_reg, &*entries->index) || same_register(table_reg, loaded_reg) ||
            !table_address->ip_relative || !resolved_table ||
            (table_address->base && table_address->base->bank != RegisterBank::ip) || table_address->index)
            continue;

        SwitchSite site;
        site.dispatch = dispatch.address;
        site.table = *resolved_table;
        site.selector = *entries->index;
        site.scale = 4;
        site.entry_encoding = SwitchEntryEncoding::signed_offset_from_table;
        if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector, lea.address,
                                                  dispatch.address, dispatch.context, guards, stop)) {
            site.case_count = bound->case_count;
            site.default_target = bound->default_target;
        }
        const auto scan_limit = site.case_count ? *site.case_count : max_entries;
        for (std::size_t index = 0; index < scan_limit; ++index) {
            if (stop.stop_requested())
                return {};
            const auto target = table_target(image, site.table, index, 4, true, relocations, stop);
            if (!target || !decodes_at(image, dispatch.context, target->address, stop)) {
                site.complete = false;
                break;
            }
            site.cases.push_back({static_cast<std::uint32_t>(index), target->address, target->source,
                                  target->relocation_rows, target->dyld_classic_rows, target->dyld_chained_rows});
        }
        if (!site.case_count && site.cases.size() == max_entries)
            site.complete = false;
        if (site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1))
            return site;
    }
    return {};
}

std::optional<SwitchSite> relative_offset_register_base_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    std::stop_token stop) {
    // Recognize the common PIC variant where the signed offset is loaded and
    // dispatched contiguously, but LEA established the table base earlier in
    // this same block:
    //   LEA Rbase, [RIP+table]; ...; MOVSXD Roff, [Rbase+Rindex*4];
    //   ADD Roff, Rbase; JMP Roff.
    if (dispatch_index < 2 || !facts[dispatch_index] || !facts[dispatch_index - 1] ||
        !facts[dispatch_index - 2] || stop.stop_requested())
        return {};
    const auto &dispatch = facts[dispatch_index]->instruction;
    const auto &add = facts[dispatch_index - 1]->instruction;
    const auto &load = facts[dispatch_index - 2]->instruction;
    if (dispatch.opcode != Opcode::jmp || dispatch.flow != FlowKind::jump ||
        dispatch.context.architecture != Architecture::x86_64 || dispatch.context.mode != ExecutionMode::x86_64 ||
        add.context != dispatch.context || load.context != dispatch.context ||
        add.opcode != Opcode::add || add.flow != FlowKind::fallthrough ||
        load.opcode != Opcode::movsxd || load.flow != FlowKind::fallthrough ||
        dispatch.operands.size() != 1 || add.operands.size() != 2 || load.operands.size() != 2)
        return {};
    const auto load_end = analysis_detail::continuation_address(load);
    const auto add_end = analysis_detail::continuation_address(add);
    if (!load_end || load_end.value() != add.address || !add_end || add_end.value() != dispatch.address)
        return {};

    const auto *target_reg = register_operand(dispatch, 0);
    const auto *loaded_reg = register_operand(load, 0);
    const auto *add_dest = register_operand(add, 0);
    const auto *add_src = register_operand(add, 1);
    const auto *entries = std::get_if<MemoryOperand>(&load.operands[1]);
    if (!target_reg || !loaded_reg || !add_dest || !add_src || !entries ||
        target_reg->bank != RegisterBank::gpr || target_reg->width != 64 || target_reg->high_byte ||
        !same_register(target_reg, loaded_reg) || !same_register(loaded_reg, add_dest) ||
        !entries->base || !same_register(entries->base ? &*entries->base : nullptr, add_src) ||
        !same_register(add_src, &*entries->base) || !entries->index || entries->scale != 4 ||
        entries->data_width != 32 || entries->address_width != 64 || entries->segment ||
        entries->displacement != 0 || same_register(add_src, loaded_reg) ||
        same_register(add_src, &*entries->index) || entries->index->bank != RegisterBank::gpr ||
        entries->index->width != 64 || entries->index->high_byte)
        return {};
    const RegisterOperand table_reg = *entries->base;
    if (table_reg.bank != RegisterBank::gpr || table_reg.width != 64 || table_reg.high_byte)
        return {};

    // The nearest write to the base register must be a resolved RIP-relative
    // LEA. Unknown instruction facts, calls, and control-flow changes prevent
    // proving that the table base still has that value at the indexed load.
    std::optional<Address> table;
    std::optional<Address> base_definition;
    std::optional<std::size_t> base_definition_index;
    std::size_t examined = 0;
    for (std::size_t cursor = dispatch_index - 2; cursor > 0 && examined < max_relative_base_scan;) {
        ++examined;
        --cursor;
        if (stop.stop_requested() || !facts[cursor])
            return {};
        const auto &candidate = facts[cursor]->instruction;
        if (candidate.context != dispatch.context || candidate.flow != FlowKind::fallthrough)
            return {};
        if (!writes_register(candidate, table_reg))
            continue;
        if (candidate.opcode != Opcode::lea || candidate.operands.size() != 2)
            return {};
        const auto *destination = register_operand(candidate, 0);
        const auto *address = std::get_if<MemoryOperand>(&candidate.operands[1]);
        const auto resolved_table = address
                                        ? relocated_operand_address(candidate, 1, address->resolved_address,
                                                                    relocations, stop)
                                        : std::optional<Address>{};
        if (!destination || destination->width != 64 || destination->high_byte ||
            !same_register(destination, &table_reg) || !address || address->segment ||
            !address->ip_relative || address->address_width != 64 || !resolved_table ||
            (address->base && address->base->bank != RegisterBank::ip) || address->index)
            return {};
        const auto candidate_end = analysis_detail::continuation_address(candidate);
        if (!candidate_end || candidate_end.value().space != load.address.space ||
            candidate_end.value().offset > load.address.offset)
            return {};
        table = resolved_table;
        base_definition = candidate.address;
        base_definition_index = cursor;
        break;
    }
    if (!table || !base_definition || !base_definition_index)
        return {};

    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *table;
    site.selector = *entries->index;
    site.scale = 4;
    site.entry_encoding = SwitchEntryEncoding::signed_offset_from_table;
    bool selector_unchanged = true;
    for (std::size_t i = *base_definition_index + 1; i < dispatch_index - 2; ++i) {
        if (stop.stop_requested() || !facts[i] ||
            facts[i]->instruction.context != dispatch.context ||
            facts[i]->instruction.flow != FlowKind::fallthrough ||
            writes_register(facts[i]->instruction, site.selector)) {
            selector_unchanged = false;
            break;
        }
    }
    if (selector_unchanged) {
        if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector,
                                                  *base_definition, dispatch.address, dispatch.context, guards, stop)) {
            site.case_count = bound->case_count;
            site.default_target = bound->default_target;
        }
    }
    const auto scan_limit = site.case_count ? *site.case_count : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested())
            return {};
        const auto target = table_target(image, site.table, index, 4, true, relocations, stop);
        if (!target || !decodes_at(image, dispatch.context, target->address, stop)) {
            site.complete = false;
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), target->address, target->source,
                              target->relocation_rows, target->dyld_classic_rows, target->dyld_chained_rows});
    }
    if (!site.case_count && site.cases.size() == max_entries)
        site.complete = false;
    return site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1)
        ? std::optional<SwitchSite>(std::move(site)) : std::nullopt;
}

std::optional<SwitchSite> register_based_absolute_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    std::stop_token stop) {
    if (dispatch_index == 0 || !facts[dispatch_index] || !facts[dispatch_index - 1] || stop.stop_requested())
        return {};
    const auto &dispatch = facts[dispatch_index]->instruction;
    const auto &lea = facts[dispatch_index - 1]->instruction;
    if (dispatch.context.mode != ExecutionMode::x86_64 || lea.context != dispatch.context ||
        dispatch.opcode != Opcode::jmp || dispatch.flow != FlowKind::jump ||
        lea.opcode != Opcode::lea || lea.flow != FlowKind::fallthrough)
        return {};
    const auto lea_end = analysis_detail::continuation_address(lea);
    if (!lea_end || lea_end.value() != dispatch.address)
        return {};

    const RegisterOperand *base = nullptr;
    const MemoryOperand *table_address = nullptr;
    for (const auto &operand : lea.operands) {
        if (const auto *reg = std::get_if<RegisterOperand>(&operand)) {
            if (base) return {};
            base = reg;
        } else if (const auto *memory = std::get_if<MemoryOperand>(&operand)) {
            if (table_address) return {};
            table_address = memory;
        }
    }
    const MemoryOperand *entries = nullptr;
    for (const auto &operand : dispatch.operands) {
        if (const auto *memory = std::get_if<MemoryOperand>(&operand)) {
            if (entries) return {};
            entries = memory;
        }
    }
    if (!base || !table_address || !entries || base->bank != RegisterBank::gpr || base->width != 64 ||
        base->high_byte || !table_address->ip_relative ||
        table_address->segment || table_address->index ||
        (table_address->base && table_address->base->bank != RegisterBank::ip) ||
        entries->segment || !same_register(entries->base ? &*entries->base : nullptr, base) ||
        !entries->index || entries->index->bank != RegisterBank::gpr || entries->index->width != 64 ||
        entries->index->high_byte || same_register(&*entries->index, base) ||
        entries->scale != 8 || entries->data_width != 64 || entries->address_width != 64 ||
        entries->displacement != 0)
        return {};
    const auto resolved_table = relocated_operand_address(lea, 1, table_address->resolved_address,
                                                          relocations, stop);
    if (!resolved_table)
        return {};

    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *resolved_table;
    site.selector = *entries->index;
    site.scale = 8;
    if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector, lea.address,
                                               dispatch.address, dispatch.context, guards, stop)) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    const auto scan_limit = site.case_count ? *site.case_count : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested()) return {};
        const auto target = table_target(image, site.table, index, 8, false, relocations, stop);
        if (!target || !decodes_at(image, dispatch.context, target->address, stop)) {
            site.complete = false;
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), target->address, target->source,
                              target->relocation_rows, target->dyld_classic_rows, target->dyld_chained_rows});
    }
    if (!site.case_count && site.cases.size() == max_entries) site.complete = false;
    if (site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1))
        return site;
    return {};
}

std::optional<SwitchSite> a64_indexed_absolute_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    const ImageMetadata *metadata, std::stop_token stop) {
    if (dispatch_index < 3 || stop.stop_requested() || !facts[dispatch_index] ||
        !facts[dispatch_index - 1] || !facts[dispatch_index - 2] || !facts[dispatch_index - 3])
        return {};
    const auto &dispatch = facts[dispatch_index]->instruction;
    const auto &load = facts[dispatch_index - 1]->instruction;
    const auto &add = facts[dispatch_index - 2]->instruction;
    const auto &page = facts[dispatch_index - 3]->instruction;
    if (dispatch.context.architecture != Architecture::arm64 || dispatch.context.mode != ExecutionMode::a64 ||
        dispatch.opcode != Opcode::a64_br || dispatch.flow != FlowKind::jump ||
        load.context != dispatch.context || add.context != dispatch.context || page.context != dispatch.context ||
        load.opcode != Opcode::a64_ldr || load.flow != FlowKind::fallthrough ||
        add.opcode != Opcode::a64_add || add.flow != FlowKind::fallthrough ||
        page.opcode != Opcode::a64_adrp || page.flow != FlowKind::fallthrough)
        return {};
    const auto page_end = analysis_detail::continuation_address(page);
    const auto add_end = analysis_detail::continuation_address(add);
    const auto load_end = analysis_detail::continuation_address(load);
    if (!page_end || page_end.value() != add.address || !add_end || add_end.value() != load.address ||
        !load_end || load_end.value() != dispatch.address || page.operands.size() != 2 ||
        add.operands.size() != 3 || load.operands.size() != 2 || dispatch.operands.size() != 1)
        return {};

    const auto *page_reg = register_operand(page, 0);
    const auto *page_address = std::get_if<MemoryOperand>(&page.operands[1]);
    const auto pair = a64_adrp_add_relocated_address(image, metadata, relocations, page, add, stop);
    if (pair.relocation_present && !pair.address)
        return {}; // An unproven pair must never fall back to placeholder bytes.
    const auto resolved_page = page_address && !pair.address
                                   ? relocated_operand_address(page, 1, page_address->resolved_address,
                                                               relocations, stop)
                                   : std::optional<Address>{};
    const auto *add_dest = register_operand(add, 0);
    const auto *add_src = register_operand(add, 1);
    const auto *low = std::get_if<ImmediateOperand>(&add.operands[2]);
    const auto *loaded_reg = register_operand(load, 0);
    const auto *entries = std::get_if<MemoryOperand>(&load.operands[1]);
    const auto *branch_reg = register_operand(dispatch, 0);
    if (!page_reg || page_reg->bank != RegisterBank::arm64_gpr || page_reg->width != 64 ||
        page_reg->index == 31 || !page_address || (!resolved_page && !pair.address) ||
        !page_address->ip_relative || page_address->address_width != 64 || page_address->base ||
        page_address->index || page_address->segment || !add_dest || !add_src || !same_register(page_reg, add_dest) ||
        !same_register(page_reg, add_src) || add_dest->width != 64 || add_src->width != 64 ||
        !low || low->value > 4095 || low->encoded_width != 12 || low->effective_width != 64 || low->is_signed ||
        !loaded_reg || !entries || !branch_reg ||
        loaded_reg->bank != RegisterBank::arm64_gpr || loaded_reg->width != 64 ||
        loaded_reg->index == 31 || branch_reg->width != 64 ||
        !same_register(loaded_reg, branch_reg) || !same_register(entries->base ? &*entries->base : nullptr, page_reg) ||
        !entries->base || entries->base->width != 64 ||
        !entries->index || entries->index->bank != RegisterBank::arm64_gpr || entries->index->width != 64 ||
        entries->index->index == 31 ||
        entries->data_width != 64 || entries->address_width != 64 || entries->displacement != 0 ||
        entries->segment || entries->index_extend != "" || entries->index_shift_amount != 3 ||
        same_register(page_reg, loaded_reg) || same_register(page_reg, &*entries->index) ||
        same_register(loaded_reg, &*entries->index))
        return {};
    if (page.length != 4 || add.length != 4 || load.length != 4 || dispatch.length != 4 ||
        (std::to_integer<unsigned>(add.bytes[dispatch.context.order == ByteOrder::little ? 2 : 1]) & 0x40u))
        return {}; // ADD must use the unshifted low-12 immediate.
    const auto relocated_table = pair.address ? std::optional<Address>{}
        : relocated_operand_address(add, 2, {}, relocations, stop);
    if (relocations && !pair.address) {
        const auto low_resolution = relocations->operand(add, 2, stop);
        if (!low_resolution || (low_resolution.value().relocated() && !low_resolution.value().address))
            return {};
    }
    const auto table = pair.address ? pair.address
        : relocated_table ? relocated_table : add_offset(*resolved_page, low->value, image);
    if (!table)
        return {};

    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *table;
    site.selector = *entries->index;
    site.scale = 8;
    if (pair.address) {
        site.table_base_source = SwitchSite::TableBaseSource::elf_relocation_pair;
        site.table_base_relocation_rows = pair.rows;
    }
    const auto *space = image.space(table->space);
    if (!space || space->width_bits != 64)
        return {};
    if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector, page.address,
                                               dispatch.address, dispatch.context, guards, stop)) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    const auto scan_limit = site.case_count ? *site.case_count : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested())
            return {};
        const auto target = table_target(image, *table, index, 8, false, relocations, stop);
        if (!target || !decodes_at(image, dispatch.context, target->address, stop)) {
            site.complete = false;
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), target->address, target->source,
                              target->relocation_rows, target->dyld_classic_rows, target->dyld_chained_rows});
    }
    if (!site.case_count && site.cases.size() == max_entries)
        site.complete = false;
    // A complete guard can prove a one-entry dispatch just as reliably as a
    // larger table. Keep unguarded one-entry prefixes ambiguous, since they
    // may simply be the first readable word of a larger table.
    return site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1)
        ? std::optional<SwitchSite>(std::move(site)) : std::nullopt;
}

std::optional<SwitchSite> a64_adr_indexed_absolute_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    std::stop_token stop) {
    // Small AArch64 PIC tables can materialize the complete table address in
    // one ADR instead of ADRP/ADD:
    //   ADR Xbase, table; LDR Xtarget, [Xbase, Xindex, LSL #3]; BR Xtarget.
    if (dispatch_index < 2 || stop.stop_requested() || !facts[dispatch_index] ||
        !facts[dispatch_index - 1] || !facts[dispatch_index - 2])
        return {};
    const auto &dispatch = facts[dispatch_index]->instruction;
    const auto &load = facts[dispatch_index - 1]->instruction;
    const auto &address = facts[dispatch_index - 2]->instruction;
    if (dispatch.context.architecture != Architecture::arm64 || dispatch.context.mode != ExecutionMode::a64 ||
        dispatch.opcode != Opcode::a64_br || dispatch.flow != FlowKind::jump ||
        load.context != dispatch.context || address.context != dispatch.context ||
        load.opcode != Opcode::a64_ldr || load.flow != FlowKind::fallthrough ||
        address.opcode != Opcode::a64_adr || address.flow != FlowKind::fallthrough ||
        dispatch.operands.size() != 1 || load.operands.size() != 2 || address.operands.size() != 2)
        return {};
    const auto address_end = analysis_detail::continuation_address(address);
    const auto load_end = analysis_detail::continuation_address(load);
    if (!address_end || address_end.value() != load.address || !load_end || load_end.value() != dispatch.address)
        return {};

    const auto *base = register_operand(address, 0);
    const auto *table_operand = std::get_if<MemoryOperand>(&address.operands[1]);
    const auto table = table_operand
        ? relocated_operand_address(address, 1, table_operand->resolved_address, relocations, stop)
        : std::optional<Address>{};
    const auto *target = register_operand(load, 0);
    const auto *entries = std::get_if<MemoryOperand>(&load.operands[1]);
    const auto *branch_register = register_operand(dispatch, 0);
    if (!base || base->bank != RegisterBank::arm64_gpr || base->width != 64 || base->index == 31 ||
        !table_operand || !table_operand->ip_relative || table_operand->base || table_operand->index ||
        table_operand->segment || !table || !target || target->bank != RegisterBank::arm64_gpr ||
        target->width != 64 || target->index == 31 || !branch_register || !same_register(target, branch_register) ||
        !entries || !same_register(entries->base ? &*entries->base : nullptr, base) || !entries->index ||
        entries->index->bank != RegisterBank::arm64_gpr || entries->index->width != 64 ||
        entries->index->index == 31 || entries->data_width != 64 || entries->address_width != 64 ||
        entries->displacement != 0 || entries->segment || !entries->index_extend.empty() ||
        entries->index_shift_amount != 3 || same_register(base, target) ||
        same_register(base, &*entries->index) || same_register(target, &*entries->index))
        return {};

    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *table;
    site.selector = *entries->index;
    site.scale = 8;
    if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector, address.address,
                                               dispatch.address, dispatch.context, guards, stop)) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    const auto scan_limit = site.case_count ? *site.case_count : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested())
            return {};
        const auto candidate = table_target(image, site.table, index, 8, false, relocations, stop);
        if (!candidate || !decodes_at(image, dispatch.context, candidate->address, stop)) {
            site.complete = false;
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), candidate->address, candidate->source,
                              candidate->relocation_rows, candidate->dyld_classic_rows,
                              candidate->dyld_chained_rows});
    }
    if (!site.case_count && site.cases.size() == max_entries)
        site.complete = false;
    return site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1)
        ? std::optional<SwitchSite>(std::move(site)) : std::nullopt;
}

std::optional<SwitchSite> a64_signed_offset_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    const ImageMetadata *metadata, std::stop_token stop) {
    // Recognize either exact signed-offset sequence:
    //   ADRP Xbase; ADD Xbase, Xbase, #lo12; LDR Woff, [Xbase, Wsel, UXTW #2];
    //   SXTW Xoff, Woff (encoded as SBFM Xoff, Xoff, #0, #31);
    //   ADD Xoff, Xbase, Xoff; BR Xoff.
    //   ADRP Xbase; ADD Xbase, Xbase, #lo12; LDRSW Xoff, [Xbase, Wsel, UXTW #2];
    //   ADD Xtarget, Xbase, Xoff; BR Xtarget.
    // Signedness comes only from the explicit SBFM alias or native LDRSW opcode.
    const bool native_signed_load = dispatch_index >= 2 && facts[dispatch_index - 2] &&
        facts[dispatch_index - 2]->instruction.opcode == Opcode::a64_ldrsw;
    const std::size_t setup_size = native_signed_load ? 4 : 5;
    if (dispatch_index < setup_size || stop.stop_requested())
        return {};
    const auto first = dispatch_index - setup_size;
    for (std::size_t i = first; i <= dispatch_index; ++i)
        if (!facts[i])
            return {};

    const auto &page = facts[first]->instruction;
    const auto &base_add = facts[first + 1]->instruction;
    const auto &load = facts[first + 2]->instruction;
    const auto &sign_extend = facts[first + 3]->instruction;
    const auto &target_add = facts[dispatch_index - 1]->instruction;
    const auto &dispatch = facts[dispatch_index]->instruction;
    if (dispatch.context.architecture != Architecture::arm64 || dispatch.context.mode != ExecutionMode::a64 ||
        dispatch.opcode != Opcode::a64_br || dispatch.flow != FlowKind::jump ||
        page.context != dispatch.context || base_add.context != dispatch.context || load.context != dispatch.context ||
        sign_extend.context != dispatch.context || target_add.context != dispatch.context ||
        page.opcode != Opcode::a64_adrp || page.flow != FlowKind::fallthrough ||
        base_add.opcode != Opcode::a64_add || base_add.flow != FlowKind::fallthrough ||
        load.opcode != (native_signed_load ? Opcode::a64_ldrsw : Opcode::a64_ldr) ||
        load.flow != FlowKind::fallthrough ||
        (!native_signed_load && (sign_extend.opcode != Opcode::a64_sbfm || sign_extend.flow != FlowKind::fallthrough)) ||
        target_add.opcode != Opcode::a64_add || target_add.flow != FlowKind::fallthrough)
        return {};
    const auto page_end = analysis_detail::continuation_address(page);
    const auto base_add_end = analysis_detail::continuation_address(base_add);
    const auto load_end = analysis_detail::continuation_address(load);
    const auto sign_extend_end = analysis_detail::continuation_address(sign_extend);
    const auto target_add_end = analysis_detail::continuation_address(target_add);
    if (!page_end || page_end.value() != base_add.address || !base_add_end || base_add_end.value() != load.address ||
        !load_end || load_end.value() != sign_extend.address ||
        (!native_signed_load && (!sign_extend_end || sign_extend_end.value() != target_add.address)) ||
        (native_signed_load && sign_extend.address != target_add.address) ||
        !target_add_end || target_add_end.value() != dispatch.address ||
        page.operands.size() != 2 || base_add.operands.size() != 3 || load.operands.size() != 2 ||
        (!native_signed_load && sign_extend.operands.size() != 4) ||
        (native_signed_load && sign_extend.operands.size() != 3) || target_add.operands.size() != 3 || dispatch.operands.size() != 1)
        return {};

    const auto *page_reg = register_operand(page, 0);
    const auto *page_address = std::get_if<MemoryOperand>(&page.operands[1]);
    const auto relocated_pair = a64_adrp_add_relocated_address(image, metadata, relocations, page, base_add, stop);
    if (relocated_pair.relocation_present && !relocated_pair.address)
        return {};
    if (base_add.bytes.size() < 4)
        return {};
    const auto add_word = std::to_integer<std::uint32_t>(base_add.bytes[0]) |
                          (std::to_integer<std::uint32_t>(base_add.bytes[1]) << 8) |
                          (std::to_integer<std::uint32_t>(base_add.bytes[2]) << 16) |
                          (std::to_integer<std::uint32_t>(base_add.bytes[3]) << 24);
    // The switch idiom forms a low-12-bit table address; shifted ADD forms are
    // a different address construction even when they happen to resolve.
    if (add_word & (1u << 22))
        return {};
    const auto decoded_page = page_address
                                  ? relocated_operand_address(page, 1, page_address->resolved_address,
                                                              relocations, stop)
                                  : std::optional<Address>{};
    const auto resolved_page = relocated_pair.address
        ? std::optional<Address>{Address{relocated_pair.address->space,
                                         relocated_pair.address->offset & ~UINT64_C(4095)}}
        : decoded_page;
    const auto *base_dest = register_operand(base_add, 0);
    const auto *base_source = register_operand(base_add, 1);
    const auto *low = std::get_if<ImmediateOperand>(&base_add.operands[2]);
    const auto *loaded_reg = register_operand(load, 0);
    const auto *entries = std::get_if<MemoryOperand>(&load.operands[1]);
    const auto *extended_dest = native_signed_load ? loaded_reg : register_operand(sign_extend, 0);
    const auto *extended_source = native_signed_load ? loaded_reg : register_operand(sign_extend, 1);
    const auto *immr = native_signed_load ? nullptr : std::get_if<ImmediateOperand>(&sign_extend.operands[2]);
    const auto *imms = native_signed_load ? nullptr : std::get_if<ImmediateOperand>(&sign_extend.operands[3]);
    const auto *target_dest = register_operand(target_add, 0);
    const auto *target_left = register_operand(target_add, 1);
    const auto *target_right = register_operand(target_add, 2);
    const auto *branch_reg = register_operand(dispatch, 0);
    if (!page_reg || page_reg->bank != RegisterBank::arm64_gpr || page_reg->width != 64 ||
        !page_address || !resolved_page || page_address->base || page_address->index ||
        page_address->segment || !page_address->ip_relative || page_address->address_width != 64 ||
        !base_dest || !base_source || !same_register(page_reg, base_dest) ||
        !same_register(page_reg, base_source) || !low || low->encoded_width != 12 ||
        low->effective_width != 64 || low->is_signed ||
        !loaded_reg ||
        loaded_reg->bank != RegisterBank::arm64_gpr ||
        loaded_reg->width != (native_signed_load ? 64 : 32) || !entries ||
        !same_register(entries->base ? &*entries->base : nullptr, page_reg) || !entries->base ||
        entries->base->width != 64 || !entries->index ||
        entries->index->bank != RegisterBank::arm64_gpr || entries->index->width != 32 ||
        entries->data_width != 32 || entries->address_width != 64 || entries->displacement != 0 ||
        entries->segment || entries->index_extend != "uxtw" || entries->index_shift_amount != 2 ||
        same_register(page_reg, &*entries->index) || same_register(page_reg, loaded_reg) ||
        !extended_dest || extended_dest->bank != RegisterBank::arm64_gpr || extended_dest->width != 64 ||
        !same_register(extended_dest, loaded_reg) || !extended_source || extended_source->width != 64 ||
        !same_register(extended_source, loaded_reg) ||
        (!native_signed_load && (!immr || immr->encoded_width != 6 || immr->effective_width != 64 ||
         immr->is_signed || immr->value != 0 || !imms || imms->encoded_width != 6 ||
         imms->effective_width != 64 || imms->is_signed || imms->value != 31)) ||
        !target_dest || target_dest->bank != RegisterBank::arm64_gpr || target_dest->width != 64 ||
        !same_register(target_dest, branch_reg) ||
        (!native_signed_load && !same_register(target_dest, extended_dest)) ||
        !branch_reg || branch_reg->bank != RegisterBank::arm64_gpr || branch_reg->width != 64 ||
        !target_left || !target_right || target_left->width != 64 || target_right->width != 64 ||
        !((same_register(target_left, page_reg) && same_register(target_right, extended_dest)) ||
          (same_register(target_right, page_reg) && same_register(target_left, extended_dest))) ||
        same_register(page_reg, extended_dest))
        return {};

    const auto relocated_table = relocated_operand_address(base_add, 2, {}, relocations, stop);
    const auto table = relocated_pair.address ? relocated_pair.address
        : relocated_table ? relocated_table : add_offset(*resolved_page, low->value, image);
    if (!table)
        return {};
    const auto *space = image.space(table->space);
    if (!space || space->width_bits != 64)
        return {};

    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *table;
    site.selector = *entries->index;
    site.scale = 4;
    site.entry_encoding = SwitchEntryEncoding::signed_offset_from_table;
    if (relocated_pair.address) {
        site.table_base_source = SwitchSite::TableBaseSource::elf_relocation_pair;
        site.table_base_relocation_rows = relocated_pair.rows;
    }
    if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector, page.address,
                                               dispatch.address, dispatch.context, guards, stop)) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    const auto scan_limit = site.case_count ? *site.case_count : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested())
            return {};
        const auto target = table_target(image, *table, index, 4, true, relocations, stop);
        if (!target || !decodes_at(image, dispatch.context, target->address, stop)) {
            site.complete = false;
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), target->address, target->source,
                              target->relocation_rows, target->dyld_classic_rows, target->dyld_chained_rows});
    }
    if (!site.case_count && site.cases.size() == max_entries)
        site.complete = false;
    // As for absolute-pointer tables, only a proved guard makes a single
    // signed-offset entry sufficient evidence for a switch site.
    return site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1)
        ? std::optional<SwitchSite>(std::move(site)) : std::nullopt;
}

std::optional<SwitchSite> a64_separate_base_signed_offset_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    const ImageMetadata *metadata, std::stop_token stop) {
    // AArch64 position-independent code commonly keeps the entry table and
    // the code-relative base distinct:
    //   ADR[P]/[ADD] Xtable, table; LDRSW Xoffset, [Xtable, Wsel, UXTW #2];
    //   ADR Xcode, code_base; ADD Xtarget, Xcode, Xoffset; BR Xtarget.
    if (dispatch_index < 4 || stop.stop_requested() || !facts[dispatch_index] ||
        !facts[dispatch_index - 1] || !facts[dispatch_index - 2] ||
        !facts[dispatch_index - 3] || !facts[dispatch_index - 4])
        return {};
    const bool page_form = facts[dispatch_index - 4]->instruction.opcode == Opcode::a64_add;
    if (page_form && (dispatch_index < 5 || !facts[dispatch_index - 5]))
        return {};
    const auto first = dispatch_index - (page_form ? 5 : 4);
    const auto &table_address = facts[first]->instruction;
    const auto &table_add = page_form ? facts[first + 1]->instruction : table_address;
    const auto &load = facts[dispatch_index - 3]->instruction;
    const auto &code_address = facts[dispatch_index - 2]->instruction;
    const auto &target_add = facts[dispatch_index - 1]->instruction;
    const auto &dispatch = facts[dispatch_index]->instruction;
    if (dispatch.context.architecture != Architecture::arm64 || dispatch.context.mode != ExecutionMode::a64 ||
        dispatch.opcode != Opcode::a64_br || dispatch.flow != FlowKind::jump ||
        table_address.opcode != (page_form ? Opcode::a64_adrp : Opcode::a64_adr) ||
        (page_form && table_add.opcode != Opcode::a64_add) ||
        load.opcode != Opcode::a64_ldrsw || code_address.opcode != Opcode::a64_adr ||
        target_add.opcode != Opcode::a64_add ||
        table_address.operands.size() != 2 || (page_form && table_add.operands.size() != 3) ||
        load.operands.size() != 2 || code_address.operands.size() != 2 ||
        target_add.operands.size() != 3 || dispatch.operands.size() != 1)
        return {};
    for (std::size_t index = first; index < dispatch_index; ++index) {
        if (!facts[index] || facts[index]->instruction.context != dispatch.context ||
            facts[index]->instruction.flow != FlowKind::fallthrough)
            return {};
        const auto next = analysis_detail::continuation_address(facts[index]->instruction);
        if (!next || next.value() != facts[index + 1]->instruction.address)
            return {};
    }

    const auto *table_reg = register_operand(page_form ? table_add : table_address, 0);
    const auto *table_operand = std::get_if<MemoryOperand>(&table_address.operands[1]);
    if (!table_reg || table_reg->bank != RegisterBank::arm64_gpr || table_reg->width != 64 ||
        table_reg->index == 31 || !table_operand || !table_operand->ip_relative ||
        table_operand->address_width != 64 || table_operand->base || table_operand->index ||
        table_operand->segment)
        return {};
    std::optional<Address> table;
    std::vector<std::uint64_t> table_relocation_rows;
    if (page_form) {
        const auto *page_reg = register_operand(table_address, 0);
        const auto *add_source = register_operand(table_add, 1);
        const auto *low = std::get_if<ImmediateOperand>(&table_add.operands[2]);
        if (!page_reg || page_reg->bank != RegisterBank::arm64_gpr || page_reg->width != 64 ||
            !same_register(page_reg, table_reg) || !same_register(add_source, table_reg) ||
            !low || low->encoded_width != 12 || low->effective_width != 64 || low->is_signed ||
            table_add.bytes.size() != 4)
            return {};
        const auto add_word = std::to_integer<std::uint32_t>(table_add.bytes[0]) |
                              (std::to_integer<std::uint32_t>(table_add.bytes[1]) << 8) |
                              (std::to_integer<std::uint32_t>(table_add.bytes[2]) << 16) |
                              (std::to_integer<std::uint32_t>(table_add.bytes[3]) << 24);
        if (add_word & (1u << 22))
            return {}; // This pattern uses an unshifted low-12 ADD.
        const auto pair = a64_adrp_add_relocated_address(image, metadata, relocations,
                                                           table_address, table_add, stop);
        table_relocation_rows = pair.rows;
        if (pair.relocation_present && !pair.address)
            return {};
        const auto decoded_page = relocated_operand_address(table_address, 1,
            table_operand->resolved_address, relocations, stop);
        if (!decoded_page && !pair.address)
            return {};
        const auto page = pair.address
            ? std::optional<Address>{Address{pair.address->space, pair.address->offset & ~UINT64_C(4095)}}
            : decoded_page;
        const auto relocated_low = relocated_operand_address(table_add, 2, {}, relocations, stop);
        table = pair.address ? pair.address
            : relocated_low ? relocated_low : add_offset(*page, low->value, image);
    } else {
        table = relocated_operand_address(table_address, 1, table_operand->resolved_address,
                                          relocations, stop);
    }
    if (!table || table->space != dispatch.address.space || !file_backed_range(image, *table, 4, false))
        return {};

    const auto *loaded = register_operand(load, 0);
    const auto *entries = std::get_if<MemoryOperand>(&load.operands[1]);
    const auto *code_reg = register_operand(code_address, 0);
    const auto *code_operand = std::get_if<MemoryOperand>(&code_address.operands[1]);
    const auto code_base = code_operand
        ? relocated_operand_address(code_address, 1, code_operand->resolved_address, relocations, stop)
        : std::optional<Address>{};
    const auto *target = register_operand(target_add, 0);
    const auto *left = register_operand(target_add, 1);
    const auto *right = register_operand(target_add, 2);
    const auto *branch = register_operand(dispatch, 0);
    if (!loaded || loaded->bank != RegisterBank::arm64_gpr || loaded->width != 64 || loaded->index == 31 ||
        !entries || !entries->base || !same_register(&*entries->base, table_reg) ||
        entries->base->width != 64 || !entries->index ||
        entries->index->bank != RegisterBank::arm64_gpr || entries->index->width != 32 ||
        entries->index->index == 31 || entries->data_width != 32 || entries->address_width != 64 ||
        entries->displacement != 0 || entries->scale != 1 || entries->segment ||
        entries->index_extend != "uxtw" || entries->index_shift_amount != 2 ||
        same_register(loaded, table_reg) || same_register(loaded, &*entries->index) ||
        !code_reg || code_reg->bank != RegisterBank::arm64_gpr || code_reg->width != 64 ||
        code_reg->index == 31 || !code_operand || !code_operand->ip_relative ||
        code_operand->address_width != 64 || code_operand->base || code_operand->index ||
        code_operand->segment || !code_base || code_base->space != dispatch.address.space ||
        same_register(code_reg, loaded) || same_register(code_reg, &*entries->index) ||
        !target || target->bank != RegisterBank::arm64_gpr || target->width != 64 ||
        target->index == 31 || !left || !right || left->bank != RegisterBank::arm64_gpr ||
        right->bank != RegisterBank::arm64_gpr || left->width != 64 || right->width != 64 ||
        !((same_register(left, code_reg) && same_register(right, loaded)) ||
          (same_register(right, code_reg) && same_register(left, loaded))) ||
        same_register(target, &*entries->index) || !branch || !same_register(target, branch) ||
        branch->bank != RegisterBank::arm64_gpr || branch->width != 64 || target_add.bytes.size() != 4)
        return {};
    const auto add_word = std::to_integer<std::uint32_t>(target_add.bytes[0]) |
                          (std::to_integer<std::uint32_t>(target_add.bytes[1]) << 8) |
                          (std::to_integer<std::uint32_t>(target_add.bytes[2]) << 16) |
                          (std::to_integer<std::uint32_t>(target_add.bytes[3]) << 24);
    if (((add_word >> 22) & 3u) != 0 || ((add_word >> 10) & 63u) != 0)
        return {}; // Offset is added without a hidden shift or extension.

    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *table;
    site.selector = *entries->index;
    site.scale = 4;
    site.entry_encoding = SwitchEntryEncoding::signed_offset_from_target_base;
    site.target_base = *code_base;
    if (!table_relocation_rows.empty()) {
        site.table_base_source = SwitchSite::TableBaseSource::elf_relocation_pair;
        site.table_base_relocation_rows = std::move(table_relocation_rows);
    }
    if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector,
                                               table_address.address, dispatch.address, dispatch.context,
                                               guards, stop)) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    const auto scan_limit = site.case_count ? *site.case_count : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested())
            return {};
        const auto candidate = table_target(image, site.table, index, 4, true,
                                            relocations, stop, site.target_base);
        if (!candidate) {
            site.complete = false;
            site.incomplete_reason = "table entry unreadable or unresolved relocation/fixup";
            break;
        }
        if (!decodes_at(image, dispatch.context, candidate->address, stop)) {
            site.complete = false;
            site.incomplete_reason = "table target is not file-backed executable AArch64 code";
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), candidate->address, candidate->source,
                              candidate->relocation_rows, candidate->dyld_classic_rows,
                              candidate->dyld_chained_rows});
    }
    if (!site.case_count && site.cases.size() == max_entries) {
        site.complete = false;
        site.incomplete_reason = "table scan reached the 4096-entry limit";
    }
    return site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1)
        ? std::optional<SwitchSite>(std::move(site)) : std::nullopt;
}

std::optional<std::int64_t> riscv_switch_immediate(const Instruction &instruction, std::size_t index,
                                                    std::uint8_t encoded_width) {
    if (index >= instruction.operands.size())
        return {};
    const auto *value = std::get_if<ImmediateOperand>(&instruction.operands[index]);
    if (!value || value->encoded_width != encoded_width || !value->is_signed)
        return {};
    return std::bit_cast<std::int64_t>(value->value);
}

std::optional<Address> riscv_table_base(const Image &image,
                                        const std::vector<std::shared_ptr<const InstructionFact>> &facts,
                                        std::size_t before, const RegisterOperand &base,
                                        const RelocationResolver *relocations, std::stop_token stop) {
    // Resolve only a nearby, unambiguous AUIPC[/ADDI] definition of the base.
    // This intentionally avoids general register-value propagation.
    constexpr std::size_t max_setup_scan = 64;
    const auto begin = before > max_setup_scan ? before - max_setup_scan : 0;
    std::optional<std::size_t> definition;
    for (std::size_t index = before; index > begin; --index) {
        if (stop.stop_requested())
            return {};
        const auto &fact = facts[index - 1];
        if (fact && writes_register(fact->instruction, base)) {
            definition = index - 1;
            break;
        }
    }
    if (!definition || !facts[*definition])
        return {};
    const auto &last = facts[*definition]->instruction;
    if (last.context.architecture != Architecture::riscv64 || last.context.mode != ExecutionMode::rv64)
        return {};
    const auto *destination = register_operand(last, 0);
    if (!destination || !same_register(destination, &base) || destination->width != 64)
        return {};

    if (last.opcode == Opcode::rv_auipc && last.operands.size() == 2) {
        const auto high = riscv_switch_immediate(last, 1, 20);
        if (!high)
            return {};
        const auto relocated = relocated_operand_address(last, 1, {}, relocations, stop);
        if (relocations) {
            const auto resolved = relocations->operand(last, 1, stop);
            if (!resolved || (resolved.value().relocated() && !resolved.value().address))
                return {};
        }
        return relocated ? relocated : add_signed_offset(last.address, *high, image);
    }
    if (last.opcode != Opcode::rv_addi || last.operands.size() != 3 || *definition == 0)
        return {};
    const auto *source = register_operand(last, 1);
    const auto low = riscv_switch_immediate(last, 2, 12);
    if (!source || !same_register(source, &base) || source->width != 64 || !low || !facts[*definition - 1])
        return {};
    const auto &high_instruction = facts[*definition - 1]->instruction;
    const auto high_end = analysis_detail::continuation_address(high_instruction);
    const auto *high_destination = register_operand(high_instruction, 0);
    const auto high = high_instruction.opcode == Opcode::rv_auipc && high_instruction.operands.size() == 2
                          ? riscv_switch_immediate(high_instruction, 1, 20)
                          : std::optional<std::int64_t>{};
    if (high_instruction.context != last.context || high_instruction.flow != FlowKind::fallthrough ||
        !high_end || high_end.value() != last.address || !high_destination ||
        !same_register(high_destination, &base) || high_destination->width != 64 || !high)
        return {};
    const auto relocated = relocated_operand_address(last, 2, {}, relocations, stop);
    if (relocations) {
        const auto resolved = relocations->operand(last, 2, stop);
        if (!resolved || (resolved.value().relocated() && !resolved.value().address))
            return {};
    }
    if (relocated)
        return relocated;
    const auto page = add_signed_offset(high_instruction.address, *high, image);
    return page ? add_signed_offset(*page, *low, image) : std::nullopt;
}

std::optional<SwitchSite> riscv_indexed_absolute_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    std::stop_token stop) {
    // RV64 absolute-pointer table form:
    //   SLLI Xindex, Xselector, 3; ADD Xaddress, Xbase, Xindex;
    //   LD Xtarget, 0(Xaddress); JALR X0, 0(Xtarget).
    // The table base may have been materialized near the dispatch by a nearby
    // AUIPC/ADDI pair. A short straight-line scan locates the scaled selector.
    if (dispatch_index < 3 || stop.stop_requested())
        return {};
    const auto &dispatch_fact = facts[dispatch_index];
    const auto &load_fact = facts[dispatch_index - 1];
    const auto &address_add_fact = facts[dispatch_index - 2];
    if (!dispatch_fact || !load_fact || !address_add_fact)
        return {};
    const auto &dispatch = dispatch_fact->instruction;
    const auto &load = load_fact->instruction;
    const auto &address_add = address_add_fact->instruction;
    if (dispatch.context.architecture != Architecture::riscv64 || dispatch.context.mode != ExecutionMode::rv64 ||
        dispatch.opcode != Opcode::rv_jalr || dispatch.flow != FlowKind::jump ||
        load.context != dispatch.context || address_add.context != dispatch.context ||
        load.opcode != Opcode::rv_ld || load.flow != FlowKind::fallthrough ||
        address_add.opcode != Opcode::rv_add || address_add.flow != FlowKind::fallthrough ||
        dispatch.operands.size() != 2 || load.operands.size() != 2 || address_add.operands.size() != 3)
        return {};
    const auto add_end = analysis_detail::continuation_address(address_add);
    const auto load_end = analysis_detail::continuation_address(load);
    if (!add_end || add_end.value() != load.address || !load_end || load_end.value() != dispatch.address)
        return {};

    const auto *add_destination = register_operand(address_add, 0);
    const auto *add_left = register_operand(address_add, 1);
    const auto *add_right = register_operand(address_add, 2);
    const auto *loaded_reg = register_operand(load, 0);
    const auto *load_memory = std::get_if<MemoryOperand>(&load.operands[1]);
    const auto *branch_destination = register_operand(dispatch, 0);
    const auto *branch_memory = std::get_if<MemoryOperand>(&dispatch.operands[1]);
    if (!add_destination || !add_left || !add_right || !loaded_reg ||
        !load_memory || !branch_destination || !branch_memory ||
        add_destination->bank != RegisterBank::riscv_gpr || add_destination->width != 64 ||
        add_destination->index == 0 || loaded_reg->bank != RegisterBank::riscv_gpr ||
        loaded_reg->width != 64 || loaded_reg->index == 0 || branch_destination->bank != RegisterBank::riscv_gpr ||
        branch_destination->width != 64 || branch_destination->index != 0 ||
        !same_register(branch_memory->base ? &*branch_memory->base : nullptr, loaded_reg) ||
        branch_memory->displacement != 0 || branch_memory->index || branch_memory->address_width != 64 ||
        !same_register(load_memory->base ? &*load_memory->base : nullptr, add_destination) ||
        load_memory->displacement != 0 || load_memory->index || load_memory->address_width != 64 ||
        load_memory->data_width != 64 ||
        same_register(add_destination, loaded_reg))
        return {};

    const auto scale_search_end = dispatch_index - 2;
    const auto scale_search_begin = scale_search_end > 64 ? scale_search_end - 64 : 0;
    std::optional<std::size_t> scale_index;
    const RegisterOperand *index_reg = nullptr;
    const RegisterOperand *selector = nullptr;
    const RegisterOperand *base = nullptr;
    for (std::size_t candidate = scale_search_end; candidate > scale_search_begin; --candidate) {
        if (stop.stop_requested())
            return {};
        const auto &fact = facts[candidate - 1];
        if (!fact)
            continue;
        const auto &instruction = fact->instruction;
        if (instruction.opcode != Opcode::rv_slli || instruction.flow != FlowKind::fallthrough ||
            instruction.context != dispatch.context || instruction.operands.size() != 3 ||
            (!same_register(register_operand(instruction, 0), add_left) &&
             !same_register(register_operand(instruction, 0), add_right)))
            continue;
        const auto *scaled = register_operand(instruction, 0);
        const auto *source = register_operand(instruction, 1);
        const auto *amount = std::get_if<ImmediateOperand>(&instruction.operands[2]);
        if (!scaled || scaled->bank != RegisterBank::riscv_gpr || scaled->width != 64 || scaled->index == 0 ||
            !source || source->bank != RegisterBank::riscv_gpr || source->width != 64 || source->index == 0 ||
            !amount || amount->encoded_width != 6 || amount->effective_width != 64 || amount->is_signed ||
            amount->value != 3)
            continue;
        const auto *candidate_base = same_register(add_left, scaled) ? add_right : add_left;
        if (!candidate_base || candidate_base->bank != RegisterBank::riscv_gpr ||
            candidate_base->width != 64 || candidate_base->index == 0 ||
            same_register(candidate_base, scaled) || same_register(candidate_base, source) ||
            same_register(candidate_base, loaded_reg))
            continue;
        bool killed = false;
        auto expected = analysis_detail::continuation_address(instruction);
        if (!expected)
            continue;
        for (std::size_t between = candidate; between < scale_search_end; ++between) {
            if (!facts[between] || facts[between]->instruction.address != expected.value() ||
                facts[between]->instruction.context != dispatch.context ||
                facts[between]->instruction.flow != FlowKind::fallthrough ||
                writes_register(facts[between]->instruction, *scaled) ||
                writes_register(facts[between]->instruction, *source)) {
                killed = true;
                break;
            }
            expected = analysis_detail::continuation_address(facts[between]->instruction);
            if (!expected) {
                killed = true;
                break;
            }
        }
        if (!killed && expected.value() == address_add.address) {
            scale_index = candidate - 1;
            index_reg = scaled;
            selector = source;
            base = candidate_base;
            break;
        }
    }
    if (!scale_index || !index_reg || !selector || !base || index_reg->index == 0 || selector->index == 0 ||
        same_register(index_reg, selector) || same_register(index_reg, loaded_reg) ||
        same_register(selector, add_destination) || same_register(selector, loaded_reg))
        return {};
    if (!base || base->bank != RegisterBank::riscv_gpr || base->width != 64 || base->index == 0 ||
        same_register(base, index_reg) || same_register(base, selector) || same_register(base, loaded_reg))
        return {};
    const auto table = riscv_table_base(image, facts, dispatch_index - 2, *base, relocations, stop);
    if (!table)
        return {};

    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *table;
    site.selector = *selector;
    site.scale = 8;
    const auto &scale = facts[*scale_index]->instruction;
    if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector, scale.address,
                                               dispatch.address, dispatch.context, guards, stop)) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    const auto scan_limit = site.case_count ? *site.case_count : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested())
            return {};
        const auto target = table_target(image, site.table, index, 8, false, relocations, stop);
        if (!target || !decodes_at(image, dispatch.context, target->address, stop)) {
            site.complete = false;
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), target->address, target->source,
                              target->relocation_rows, target->dyld_classic_rows, target->dyld_chained_rows});
    }
    if (!site.case_count && site.cases.size() == max_entries)
        site.complete = false;
    return site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1)
        ? std::optional<SwitchSite>(std::move(site)) : std::nullopt;
}

std::optional<SwitchSite> mips64_register_absolute_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    std::stop_token stop) {
    // MIPS64 N64 absolute table form, bounded to one straight-line block:
    //   LUI/ORI tableBase; DSLL index, selector, 3; DADDU address, tableBase, index;
    //   LD target, 0(address); JR target.
    // The same register facts also accept DADDIU adjustments around the base.
    if (dispatch_index < 4 || dispatch_index >= facts.size() || stop.stop_requested() ||
        !facts[dispatch_index])
        return {};
    const auto &dispatch = facts[dispatch_index]->instruction;
    if (dispatch.context.architecture != Architecture::mips64 ||
        dispatch.context.mode != ExecutionMode::mips64 || dispatch.opcode != Opcode::mips_jr ||
        dispatch.flow != FlowKind::jump || dispatch.operands.size() != 1)
        return {};
    const auto *target_register = register_operand(dispatch, 0);
    if (!target_register || target_register->bank != RegisterBank::mips_gpr || target_register->width != 64 ||
        target_register->index == 0 || !facts[dispatch_index - 1])
        return {};
    const auto &terminal_load = facts[dispatch_index - 1]->instruction;
    const auto load_end = analysis_detail::continuation_address(terminal_load);
    const auto *loaded_register = terminal_load.operands.empty() ? nullptr : register_operand(terminal_load, 0);
    if (!load_end || load_end.value() != dispatch.address || terminal_load.context != dispatch.context ||
        terminal_load.opcode != Opcode::mips64_ld || terminal_load.flow != FlowKind::fallthrough ||
        !loaded_register || !same_register(loaded_register, target_register))
        return {};

    struct Value {
        std::optional<Address> constant;
        std::optional<Address> table_base;
        std::optional<RegisterOperand> selector;
        std::uint64_t scale = 1;
        Address scale_instruction{};
        bool has_scale_instruction = false;
    };
    std::map<std::uint32_t, Value> registers;
    const auto remember = [&](std::uint32_t index, Value value) { registers[index] = std::move(value); };
    for (std::size_t index = 0; index < dispatch_index; ++index) {
        if (stop.stop_requested() || !facts[index])
            return {};
        const auto &instruction = facts[index]->instruction;
        if (instruction.context != dispatch.context || instruction.flow != FlowKind::fallthrough ||
            instruction.delay_slots)
            return {};

        const auto *destination = instruction.operands.empty() ? nullptr : register_operand(instruction, 0);
        const auto erase_written = [&] {
            for (const auto &written : instruction.register_writes)
                if (written.bank == RegisterBank::mips_gpr && written.index != 0)
                    registers.erase(written.index);
        };
        if (instruction.opcode == Opcode::mips_lui && instruction.operands.size() == 2 && destination &&
            destination->bank == RegisterBank::mips_gpr && destination->width == 64 && destination->index != 0) {
            const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[1]);
            if (!immediate || immediate->effective_width != 16 || immediate->value > 0xffff) {
                erase_written();
                continue;
            }
            const auto word = static_cast<std::uint32_t>(immediate->value << 16);
            const auto signed_word = std::bit_cast<std::int32_t>(word);
            const auto value = static_cast<std::uint64_t>(static_cast<std::int64_t>(signed_word));
            erase_written();
            remember(destination->index, Value{Address{dispatch.address.space, value}});
            continue;
        }
        if (instruction.opcode == Opcode::mips_ori && instruction.operands.size() == 3 && destination) {
            const auto *source = register_operand(instruction, 1);
            const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
            std::optional<Value> value;
            if (destination->bank == RegisterBank::mips_gpr && destination->width == 64 && destination->index != 0 &&
                source && source->bank == RegisterBank::mips_gpr && source->width == 64 && immediate &&
                immediate->encoded_width == 16 && immediate->effective_width == 64 && !immediate->is_signed &&
                immediate->value <= 0xffff) {
                std::optional<Value> base;
                if (source->index == 0) base = Value{Address{dispatch.address.space, 0}};
                else if (const auto found = registers.find(source->index); found != registers.end())
                    base = found->second;
                if (base && base->constant && base->constant->space == dispatch.address.space)
                    value = Value{Address{dispatch.address.space, base->constant->offset | immediate->value}};
            }
            erase_written();
            if (value) remember(destination->index, std::move(*value));
            continue;
        }
        if (instruction.opcode == Opcode::mips64_daddiu && instruction.operands.size() == 3 && destination) {
            const auto *source = register_operand(instruction, 1);
            const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
            std::optional<Value> value;
            if (destination->bank == RegisterBank::mips_gpr && destination->width == 64 && destination->index != 0 &&
                source && source->bank == RegisterBank::mips_gpr && source->width == 64 && immediate &&
                immediate->effective_width == 64 && immediate->is_signed) {
                std::optional<Value> base;
                if (source->index == 0) base = Value{Address{dispatch.address.space, 0}};
                else if (const auto found = registers.find(source->index); found != registers.end())
                    base = found->second;
                if (base && base->constant && base->constant->space == dispatch.address.space) {
                    const auto signed_immediate = std::bit_cast<std::int64_t>(immediate->value);
                    if (const auto adjusted = add_signed_offset(*base->constant, signed_immediate, image))
                        value = Value{*adjusted};
                } else if (base && base->table_base && base->selector && base->table_base->space == dispatch.address.space) {
                    const auto signed_immediate = std::bit_cast<std::int64_t>(immediate->value);
                    if (const auto adjusted = add_signed_offset(*base->table_base, signed_immediate, image)) {
                        auto combined = *base;
                        combined.table_base = *adjusted;
                        value = std::move(combined);
                    }
                }
            }
            erase_written();
            if (value) remember(destination->index, std::move(*value));
            continue;
        }
        if (instruction.opcode == Opcode::mips64_dsll && instruction.operands.size() == 3 && destination) {
            const auto *source = register_operand(instruction, 1);
            const auto *amount = std::get_if<ImmediateOperand>(&instruction.operands[2]);
            std::optional<Value> value;
            if (destination->bank == RegisterBank::mips_gpr && destination->width == 64 && destination->index != 0 &&
                source && source->bank == RegisterBank::mips_gpr && source->width == 64 && source->index != 0 &&
                amount && amount->effective_width == 64 && amount->value < 64) {
                const auto factor = UINT64_C(1) << amount->value;
                value = Value{{}, {}, *source, factor, instruction.address, true};
            }
            erase_written();
            if (value) remember(destination->index, std::move(*value));
            continue;
        }
        if (instruction.opcode == Opcode::mips64_daddu && instruction.operands.size() == 3 && destination) {
            const auto *left = register_operand(instruction, 1);
            const auto *right = register_operand(instruction, 2);
            std::optional<Value> value;
            if (destination->bank == RegisterBank::mips_gpr && destination->width == 64 && destination->index != 0 &&
                left && right && left->bank == RegisterBank::mips_gpr && right->bank == RegisterBank::mips_gpr &&
                left->width == 64 && right->width == 64) {
                const auto value_of = [&](const RegisterOperand &reg) -> std::optional<Value> {
                    if (reg.index == 0) return Value{Address{dispatch.address.space, 0}};
                    const auto found = registers.find(reg.index);
                    return found == registers.end() ? std::nullopt : std::optional<Value>{found->second};
                };
                const auto lhs = value_of(*left), rhs = value_of(*right);
                if (lhs && rhs && lhs->constant && rhs->constant && lhs->constant->space == dispatch.address.space &&
                    rhs->constant->space == dispatch.address.space) {
                    if (const auto sum = add_offset(*lhs->constant, rhs->constant->offset, image)) value = Value{*sum};
                } else {
                    const Value *scaled = lhs && lhs->selector && !lhs->constant ? &*lhs :
                                          rhs && rhs->selector && !rhs->constant ? &*rhs : nullptr;
                    const Value *base = lhs && lhs->constant ? &*lhs : rhs && rhs->constant ? &*rhs : nullptr;
                    if (scaled && base && base->constant && base->constant->space == dispatch.address.space &&
                        scaled->selector->index != 0 && scaled->scale &&
                        !same_register(&*scaled->selector, &*left) && !same_register(&*scaled->selector, &*right)) {
                        auto combined = *scaled;
                        combined.table_base = *base->constant;
                        combined.constant.reset();
                        value = std::move(combined);
                    } else if (lhs && lhs->table_base && lhs->selector && rhs && rhs->constant) {
                        if (const auto adjusted = add_offset(*lhs->table_base, rhs->constant->offset, image)) {
                            auto combined = *lhs;
                            combined.table_base = *adjusted;
                            value = std::move(combined);
                        }
                    } else if (rhs && rhs->table_base && rhs->selector && lhs && lhs->constant) {
                        if (const auto adjusted = add_offset(*rhs->table_base, lhs->constant->offset, image)) {
                            auto combined = *rhs;
                            combined.table_base = *adjusted;
                            value = std::move(combined);
                        }
                    }
                }
            }
            erase_written();
            if (value) remember(destination->index, std::move(*value));
            continue;
        }
        if (instruction.opcode == Opcode::mips64_ld && instruction.operands.size() == 2 && destination) {
            const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
            std::optional<Value> value;
            if (destination->bank == RegisterBank::mips_gpr && destination->width == 64 && destination->index != 0 &&
                memory && memory->data_width == 64 && memory->address_width == 64 && memory->base &&
                memory->base->bank == RegisterBank::mips_gpr && memory->base->width == 64 &&
                memory->base->index != 0) {
                const auto address = registers.find(memory->base->index);
                if (address != registers.end() && address->second.table_base && address->second.selector) {
                    if (const auto table = add_signed_offset(*address->second.table_base, memory->displacement, image)) {
                        auto loaded = address->second;
                        loaded.table_base = *table;
                        value = std::move(loaded);
                    }
                }
            }
            erase_written();
            if (value) remember(destination->index, std::move(*value));
            continue;
        }
        erase_written();
    }

    const auto found = registers.find(target_register->index);
    if (found == registers.end() || !found->second.table_base || !found->second.selector ||
        found->second.scale != 8 || !found->second.has_scale_instruction ||
        !file_backed_range(image, *found->second.table_base, 8, false))
        return {};
    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *found->second.table_base;
    site.selector = *found->second.selector;
    site.scale = 8;
    if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector,
                                               found->second.scale_instruction, dispatch.address,
                                               dispatch.context, guards, stop)) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    const auto scan_limit = site.case_count ? *site.case_count : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested()) return {};
        const auto target = table_target(image, site.table, index, 8, false, relocations, stop);
        if (!target || !decodes_at(image, dispatch.context, target->address, stop)) {
            site.complete = false;
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), target->address, target->source,
                              target->relocation_rows, target->dyld_classic_rows, target->dyld_chained_rows});
    }
    if (!site.case_count && site.cases.size() == max_entries) site.complete = false;
    return site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1)
        ? std::optional<SwitchSite>(std::move(site)) : std::nullopt;
}

std::optional<SwitchSite> mips32_register_absolute_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    std::stop_token stop) {
    // MIPS32 O32 absolute table form, bounded to one straight-line block:
    //   LUI/ORI tableBase; SLL index, selector, 3; ADDU address, tableBase, index;
    //   LW target, 0(address); JR target.
    // The same register facts also accept ADDIU adjustments around the base.
    if (dispatch_index < 4 || dispatch_index >= facts.size() || stop.stop_requested() ||
        !facts[dispatch_index])
        return {};
    const auto &dispatch = facts[dispatch_index]->instruction;
    if (dispatch.context.architecture != Architecture::mips32 ||
        dispatch.context.mode != ExecutionMode::mips32 || dispatch.opcode != Opcode::mips_jr ||
        dispatch.flow != FlowKind::jump || dispatch.operands.size() != 1)
        return {};
    const auto *target_register = register_operand(dispatch, 0);
    if (!target_register || target_register->bank != RegisterBank::mips_gpr || target_register->width != 32 ||
        target_register->index == 0 || !facts[dispatch_index - 1])
        return {};
    const auto &terminal_load = facts[dispatch_index - 1]->instruction;
    const auto load_end = analysis_detail::continuation_address(terminal_load);
    const auto *loaded_register = terminal_load.operands.empty() ? nullptr : register_operand(terminal_load, 0);
    if (!load_end || load_end.value() != dispatch.address || terminal_load.context != dispatch.context ||
        terminal_load.opcode != Opcode::mips_lw || terminal_load.flow != FlowKind::fallthrough ||
        !loaded_register || !same_register(loaded_register, target_register))
        return {};

    struct Value {
        std::optional<Address> constant;
        std::optional<Address> table_base;
        std::optional<RegisterOperand> selector;
        std::uint64_t scale = 1;
        Address scale_instruction{};
        bool has_scale_instruction = false;
    };
    std::map<std::uint32_t, Value> registers;
    const auto remember = [&](std::uint32_t index, Value value) { registers[index] = std::move(value); };
    for (std::size_t index = 0; index < dispatch_index; ++index) {
        if (stop.stop_requested() || !facts[index])
            return {};
        const auto &instruction = facts[index]->instruction;
        if (instruction.context != dispatch.context || instruction.flow != FlowKind::fallthrough ||
            instruction.delay_slots)
            return {};

        const auto *destination = instruction.operands.empty() ? nullptr : register_operand(instruction, 0);
        const auto erase_written = [&] {
            for (const auto &written : instruction.register_writes)
                if (written.bank == RegisterBank::mips_gpr && written.index != 0)
                    registers.erase(written.index);
        };
        if (instruction.opcode == Opcode::mips_lui && instruction.operands.size() == 2 && destination &&
            destination->bank == RegisterBank::mips_gpr && destination->width == 32 && destination->index != 0) {
            const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[1]);
            if (!immediate || immediate->effective_width != 16 || immediate->value > 0xffff) {
                erase_written();
                continue;
            }
            const auto word = static_cast<std::uint32_t>(immediate->value << 16);
            const auto value = static_cast<std::uint64_t>(word);
            erase_written();
            remember(destination->index, Value{Address{dispatch.address.space, value}});
            continue;
        }
        if (instruction.opcode == Opcode::mips_ori && instruction.operands.size() == 3 && destination) {
            const auto *source = register_operand(instruction, 1);
            const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
            std::optional<Value> value;
            if (destination->bank == RegisterBank::mips_gpr && destination->width == 32 && destination->index != 0 &&
                source && source->bank == RegisterBank::mips_gpr && source->width == 32 && immediate &&
                immediate->encoded_width == 16 && immediate->effective_width == 32 && !immediate->is_signed &&
                immediate->value <= 0xffff) {
                std::optional<Value> base;
                if (source->index == 0) base = Value{Address{dispatch.address.space, 0}};
                else if (const auto found = registers.find(source->index); found != registers.end())
                    base = found->second;
                if (base && base->constant && base->constant->space == dispatch.address.space)
                    value = Value{Address{dispatch.address.space, base->constant->offset | immediate->value}};
            }
            erase_written();
            if (value) remember(destination->index, std::move(*value));
            continue;
        }
        if (instruction.opcode == Opcode::mips_addiu && instruction.operands.size() == 3 && destination) {
            const auto *source = register_operand(instruction, 1);
            const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
            std::optional<Value> value;
            if (destination->bank == RegisterBank::mips_gpr && destination->width == 32 && destination->index != 0 &&
                source && source->bank == RegisterBank::mips_gpr && source->width == 32 && immediate &&
                immediate->effective_width == 32 && immediate->is_signed) {
                std::optional<Value> base;
                if (source->index == 0) base = Value{Address{dispatch.address.space, 0}};
                else if (const auto found = registers.find(source->index); found != registers.end())
                    base = found->second;
                if (base && base->constant && base->constant->space == dispatch.address.space) {
                    const auto signed_immediate = std::bit_cast<std::int64_t>(immediate->value);
                    if (const auto adjusted = add_signed_offset(*base->constant, signed_immediate, image))
                        value = Value{*adjusted};
                } else if (base && base->table_base && base->selector && base->table_base->space == dispatch.address.space) {
                    const auto signed_immediate = std::bit_cast<std::int64_t>(immediate->value);
                    if (const auto adjusted = add_signed_offset(*base->table_base, signed_immediate, image)) {
                        auto combined = *base;
                        combined.table_base = *adjusted;
                        value = std::move(combined);
                    }
                }
            }
            erase_written();
            if (value) remember(destination->index, std::move(*value));
            continue;
        }
        if (instruction.opcode == Opcode::mips_sll && instruction.operands.size() == 3 && destination) {
            const auto *source = register_operand(instruction, 1);
            const auto *amount = std::get_if<ImmediateOperand>(&instruction.operands[2]);
            std::optional<Value> value;
            if (destination->bank == RegisterBank::mips_gpr && destination->width == 32 && destination->index != 0 &&
                source && source->bank == RegisterBank::mips_gpr && source->width == 32 && source->index != 0 &&
                amount && amount->effective_width == 32 && amount->value < 32) {
                const auto factor = UINT32_C(1) << amount->value;
                value = Value{{}, {}, *source, factor, instruction.address, true};
            }
            erase_written();
            if (value) remember(destination->index, std::move(*value));
            continue;
        }
        if (instruction.opcode == Opcode::mips_addu && instruction.operands.size() == 3 && destination) {
            const auto *left = register_operand(instruction, 1);
            const auto *right = register_operand(instruction, 2);
            std::optional<Value> value;
            if (destination->bank == RegisterBank::mips_gpr && destination->width == 32 && destination->index != 0 &&
                left && right && left->bank == RegisterBank::mips_gpr && right->bank == RegisterBank::mips_gpr &&
                left->width == 32 && right->width == 32) {
                const auto value_of = [&](const RegisterOperand &reg) -> std::optional<Value> {
                    if (reg.index == 0) return Value{Address{dispatch.address.space, 0}};
                    const auto found = registers.find(reg.index);
                    return found == registers.end() ? std::nullopt : std::optional<Value>{found->second};
                };
                const auto lhs = value_of(*left), rhs = value_of(*right);
                if (lhs && rhs && lhs->constant && rhs->constant && lhs->constant->space == dispatch.address.space &&
                    rhs->constant->space == dispatch.address.space) {
                    if (const auto sum = add_offset(*lhs->constant, rhs->constant->offset, image)) value = Value{*sum};
                } else {
                    const Value *scaled = lhs && lhs->selector && !lhs->constant ? &*lhs :
                                          rhs && rhs->selector && !rhs->constant ? &*rhs : nullptr;
                    const Value *base = lhs && lhs->constant ? &*lhs : rhs && rhs->constant ? &*rhs : nullptr;
                    if (scaled && base && base->constant && base->constant->space == dispatch.address.space &&
                        scaled->selector->index != 0 && scaled->scale &&
                        !same_register(&*scaled->selector, &*left) && !same_register(&*scaled->selector, &*right)) {
                        auto combined = *scaled;
                        combined.table_base = *base->constant;
                        combined.constant.reset();
                        value = std::move(combined);
                    } else if (lhs && lhs->table_base && lhs->selector && rhs && rhs->constant) {
                        if (const auto adjusted = add_offset(*lhs->table_base, rhs->constant->offset, image)) {
                            auto combined = *lhs;
                            combined.table_base = *adjusted;
                            value = std::move(combined);
                        }
                    } else if (rhs && rhs->table_base && rhs->selector && lhs && lhs->constant) {
                        if (const auto adjusted = add_offset(*rhs->table_base, lhs->constant->offset, image)) {
                            auto combined = *rhs;
                            combined.table_base = *adjusted;
                            value = std::move(combined);
                        }
                    }
                }
            }
            erase_written();
            if (value) remember(destination->index, std::move(*value));
            continue;
        }
        if (instruction.opcode == Opcode::mips_lw && instruction.operands.size() == 2 && destination) {
            const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
            std::optional<Value> value;
            if (destination->bank == RegisterBank::mips_gpr && destination->width == 32 && destination->index != 0 &&
                memory && memory->data_width == 32 && memory->address_width == 32 && memory->base &&
                memory->base->bank == RegisterBank::mips_gpr && memory->base->width == 32 &&
                memory->base->index != 0) {
                const auto address = registers.find(memory->base->index);
                if (address != registers.end() && address->second.table_base && address->second.selector) {
                    if (const auto table = add_signed_offset(*address->second.table_base, memory->displacement, image)) {
                        auto loaded = address->second;
                        loaded.table_base = *table;
                        value = std::move(loaded);
                    }
                }
            }
            erase_written();
            if (value) remember(destination->index, std::move(*value));
            continue;
        }
        erase_written();
    }

    const auto found = registers.find(target_register->index);
    if (found == registers.end() || !found->second.table_base || !found->second.selector ||
        same_register(&*found->second.selector, target_register) || found->second.scale != 4 ||
        !found->second.has_scale_instruction || !file_backed_range(image, *found->second.table_base, 4, false))
        return {};
    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *found->second.table_base;
    site.selector = *found->second.selector;
    site.scale = 4;
    if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector,
                                               found->second.scale_instruction, dispatch.address,
                                               dispatch.context, guards, stop)) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    const auto scan_limit = site.case_count ? *site.case_count : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested()) return {};
        const auto target = table_target(image, site.table, index, 4, false, relocations, stop);
        if (!target || !decodes_at(image, dispatch.context, target->address, stop)) {
            site.complete = false;
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), target->address, target->source,
                              target->relocation_rows, target->dyld_classic_rows, target->dyld_chained_rows});
    }
    if (!site.case_count && site.cases.size() == max_entries) site.complete = false;
    return site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1)
        ? std::optional<SwitchSite>(std::move(site)) : std::nullopt;
}

std::optional<SwitchSite> riscv_indexed_relative_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    std::stop_token stop) {
    // AUIPC Xbase[, ADDI Xbase, Xbase, lo]; SLLI Xindex, Xselector, 2;
    // ADD Xaddress, Xbase, Xindex; LW Xoffset, 0(Xaddress);
    // ADD Xtarget, Xbase, Xoffset; JALR X0, 0(Xtarget).
    // LW sign-extends the table's 32-bit entries before the target ADD.
    if (dispatch_index < 5 || stop.stop_requested())
        return {};
    const auto &dispatch = facts[dispatch_index];
    const auto &target_add = facts[dispatch_index - 1];
    const auto &load = facts[dispatch_index - 2];
    const auto &address_add = facts[dispatch_index - 3];
    const auto &scale = facts[dispatch_index - 4];
    const auto &last_setup = facts[dispatch_index - 5];
    if (!dispatch || !target_add || !load || !address_add || !scale || !last_setup)
        return {};
    const auto &branch_instruction = dispatch->instruction;
    const auto &target_instruction = target_add->instruction;
    const auto &load_instruction = load->instruction;
    const auto &address_instruction = address_add->instruction;
    const auto &scale_instruction = scale->instruction;
    const auto &setup_instruction = last_setup->instruction;
    if (branch_instruction.context.architecture != Architecture::riscv64 ||
        branch_instruction.context.mode != ExecutionMode::rv64 ||
        branch_instruction.opcode != Opcode::rv_jalr || branch_instruction.flow != FlowKind::jump ||
        target_instruction.opcode != Opcode::rv_add || load_instruction.opcode != Opcode::rv_lw ||
        address_instruction.opcode != Opcode::rv_add || scale_instruction.opcode != Opcode::rv_slli ||
        (setup_instruction.opcode != Opcode::rv_auipc && setup_instruction.opcode != Opcode::rv_addi) ||
        branch_instruction.operands.size() != 2 || target_instruction.operands.size() != 3 ||
        load_instruction.operands.size() != 2 || address_instruction.operands.size() != 3 ||
        scale_instruction.operands.size() != 3)
        return {};

    std::size_t first = dispatch_index - 5;
    if (setup_instruction.opcode == Opcode::rv_addi) {
        if (first == 0 || !facts[first - 1] ||
            facts[first - 1]->instruction.opcode != Opcode::rv_auipc)
            return {};
        --first;
    }
    // All definitions and uses are adjacent in one recovered block. This
    // avoids guessing across unknown writes, calls, or other control paths.
    for (std::size_t index = first; index < dispatch_index; ++index) {
        if (!facts[index] || !facts[index + 1])
            return {};
        const auto &current = facts[index]->instruction;
        const auto next = analysis_detail::continuation_address(current);
        if (current.context != branch_instruction.context || current.flow != FlowKind::fallthrough ||
            !next || next.value() != facts[index + 1]->instruction.address)
            return {};
    }

    const auto *branch_destination = register_operand(branch_instruction, 0);
    const auto *branch_memory = std::get_if<MemoryOperand>(&branch_instruction.operands[1]);
    const auto *target_destination = register_operand(target_instruction, 0);
    const auto *target_left = register_operand(target_instruction, 1);
    const auto *target_right = register_operand(target_instruction, 2);
    const auto *loaded_offset = register_operand(load_instruction, 0);
    const auto *load_memory = std::get_if<MemoryOperand>(&load_instruction.operands[1]);
    const auto *address_destination = register_operand(address_instruction, 0);
    const auto *address_left = register_operand(address_instruction, 1);
    const auto *address_right = register_operand(address_instruction, 2);
    const auto *scaled_index = register_operand(scale_instruction, 0);
    const auto *selector = register_operand(scale_instruction, 1);
    const auto *amount = std::get_if<ImmediateOperand>(&scale_instruction.operands[2]);
    const auto gpr64 = [](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::riscv_gpr && reg->width == 64 && reg->index != 0;
    };
    if (!branch_destination || branch_destination->bank != RegisterBank::riscv_gpr ||
        branch_destination->width != 64 || branch_destination->index != 0 ||
        !branch_memory || !target_destination || !target_left || !target_right ||
        !gpr64(target_destination) || !gpr64(loaded_offset) || !load_memory ||
        !gpr64(address_destination) || !address_left || !address_right ||
        !gpr64(scaled_index) || !gpr64(selector) ||
        !amount || amount->encoded_width != 6 || amount->effective_width != 64 ||
        amount->is_signed || amount->value != 2 ||
        !same_register(branch_memory->base ? &*branch_memory->base : nullptr, target_destination) ||
        branch_memory->segment || branch_memory->index || branch_memory->ip_relative ||
        branch_memory->displacement != 0 || branch_memory->address_width != 64 ||
        !same_register(load_memory->base ? &*load_memory->base : nullptr, address_destination) ||
        load_memory->segment || load_memory->index || load_memory->ip_relative ||
        load_memory->displacement != 0 || load_memory->address_width != 64 ||
        load_memory->data_width != 32)
        return {};

    const auto *base = same_register(target_left, loaded_offset) ? target_right
        : same_register(target_right, loaded_offset) ? target_left : nullptr;
    if (!gpr64(base) || same_register(base, selector) || same_register(base, scaled_index) ||
        same_register(base, address_destination) || same_register(base, loaded_offset) ||
        !((same_register(address_left, base) && same_register(address_right, scaled_index)) ||
          (same_register(address_right, base) && same_register(address_left, scaled_index))))
        return {};
    const auto *setup_destination = register_operand(setup_instruction, 0);
    if (!same_register(setup_destination, base))
        return {};
    if (first != dispatch_index - 5) {
        const auto *high_destination = register_operand(facts[first]->instruction, 0);
        if (!same_register(high_destination, base))
            return {};
    }
    const auto table = riscv_table_base(image, facts, dispatch_index - 4, *base, relocations, stop);
    if (!table)
        return {};

    SwitchSite site;
    site.dispatch = branch_instruction.address;
    site.table = *table;
    site.selector = *selector;
    site.scale = 4;
    site.entry_encoding = SwitchEntryEncoding::signed_offset_from_table;
    if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector,
                                               facts[first]->instruction.address, site.dispatch,
                                               branch_instruction.context, guards, stop)) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    const auto scan_limit = site.case_count ? *site.case_count : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested())
            return {};
        const auto target = table_target(image, site.table, index, 4, true, relocations, stop);
        if (!target || !decodes_at(image, branch_instruction.context, target->address, stop)) {
            site.complete = false;
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), target->address, target->source,
                              target->relocation_rows, target->dyld_classic_rows, target->dyld_chained_rows});
    }
    if (!site.case_count && site.cases.size() == max_entries)
        site.complete = false;
    return site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1)
        ? std::optional<SwitchSite>(std::move(site)) : std::nullopt;
}

std::optional<SwitchSite> thumb_table_branch_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, std::stop_token stop) {
    if (dispatch_index >= facts.size() || !facts[dispatch_index] || stop.stop_requested())
        return {};
    const auto &dispatch = facts[dispatch_index]->instruction;
    if (dispatch.context.architecture != Architecture::arm || dispatch.context.mode != ExecutionMode::thumb ||
        (dispatch.opcode != Opcode::arm_tbb && dispatch.opcode != Opcode::arm_tbh) ||
        dispatch.flow != FlowKind::jump || dispatch.operands.size() != 1)
        return {};
    const auto *memory = std::get_if<MemoryOperand>(&dispatch.operands.front());
    if (!memory || !memory->base || !memory->index || memory->base->bank != RegisterBank::arm32_gpr ||
        memory->base->index != 15 || memory->base->width != 32 ||
        memory->index->bank != RegisterBank::arm32_gpr || memory->index->index == 15 ||
        memory->index->width != 32 || memory->index->high_byte || memory->displacement != 0 ||
        memory->address_width != 32 || memory->segment || memory->resolved_address)
        return {};
    const std::size_t entry_width = dispatch.opcode == Opcode::arm_tbb ? 1 : 2;
    if (memory->data_width != entry_width * 8 || memory->scale != entry_width)
        return {};
    const auto table = add_offset(dispatch.address, 4, image);
    if (!table || !file_backed_range(image, *table, entry_width, false))
        return {};

    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *table;
    site.selector = *memory->index;
    site.scale = static_cast<std::uint8_t>(entry_width);
    site.entry_encoding = SwitchEntryEncoding::thumb_scaled_pc_relative;
    if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector,
                                               dispatch.address, dispatch.address, dispatch.context, guards, stop)) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    const auto scan_limit = site.case_count ? *site.case_count : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested())
            return {};
        const auto displacement = unsigned_table_entry(image, site.table, index, entry_width);
        if (!displacement || *displacement > UINT64_MAX / 2) {
            site.complete = false;
            break;
        }
        const auto target = add_offset(site.table, *displacement * 2, image);
        if (!target || !decodes_at(image, dispatch.context, *target, stop)) {
            site.complete = false;
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), *target});
    }
    if (!site.case_count && site.cases.size() == max_entries)
        site.complete = false;
    if (site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1))
        return site;
    return {};
}
} // namespace

static Result<SwitchAnalysis> analyze_switch_tables_impl(const Image &image, const FunctionRecord &function,
                                                          const FunctionSnapshot &snapshot,
                                                          const RelocationResolver *relocations,
                                                          const ImageMetadata *metadata,
                                                          std::stop_token stop) {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Switch analysis canceled"};
    if (function.blocks.empty())
        return Error{ErrorCode::invalid_argument, "Function has no recovered blocks"};
    if (function.blocks.size() > max_blocks || snapshot.blocks.size() > max_blocks)
        return Error{ErrorCode::resource_limit, "Switch analysis block budget exceeded"};
    std::size_t instruction_count = 0;
    for (const auto &block : snapshot.blocks) {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "Switch analysis canceled"};
        if (!block)
            continue;
        if (block->instructions.size() > max_instructions - instruction_count)
            return Error{ErrorCode::resource_limit, "Switch analysis instruction budget exceeded"};
        instruction_count += block->instructions.size();
    }

    SwitchAnalysis result;
    result.complete = function.complete && snapshot.complete;
    std::map<std::uint64_t, std::shared_ptr<const BasicBlock>> blocks;
    for (const auto &block : snapshot.blocks)
        if (block)
            blocks.emplace(block->id.value, block);

    SwitchGuardContext guards{blocks};

    for (const auto id : function.blocks) {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "Switch analysis canceled"};
        const auto found = blocks.find(id.value);
        if (found == blocks.end()) {
            result.complete = false;
            continue;
        }
        for (std::size_t fact_index = 0; fact_index < found->second->instructions.size(); ++fact_index) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "Switch analysis canceled"};
            const auto &fact = found->second->instructions[fact_index];
            if (!fact)
                continue;
            const auto &instruction = fact->instruction;
            if ((instruction.context.architecture == Architecture::mips64 && instruction.context.mode == ExecutionMode::mips64 ||
                 instruction.context.architecture == Architecture::mips32 && instruction.context.mode == ExecutionMode::mips32) &&
                instruction.opcode == Opcode::mips_jr && instruction.flow == FlowKind::jump) {
                auto mips_switch = instruction.context.mode == ExecutionMode::mips64
                    ? mips64_register_absolute_switch(image, function, snapshot, found->second->instructions, fact_index,
                                                      guards, relocations, stop)
                    : mips32_register_absolute_switch(image, function, snapshot, found->second->instructions, fact_index,
                                                      guards, relocations, stop);
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Switch analysis canceled"};
                if (mips_switch) {
                    result.complete = result.complete && mips_switch->complete;
                    result.sites.push_back(std::move(*mips_switch));
                }
                continue;
            }
            if (instruction.context.architecture == Architecture::riscv64 &&
                instruction.context.mode == ExecutionMode::rv64 && instruction.opcode == Opcode::rv_jalr &&
                instruction.flow == FlowKind::jump) {
                auto riscv_switch = riscv_indexed_absolute_switch(image, function, snapshot,
                                                                   found->second->instructions, fact_index,
                                                                   guards, relocations, stop);
                if (!riscv_switch && !stop.stop_requested())
                    riscv_switch = riscv_indexed_relative_switch(image, function, snapshot,
                                                                  found->second->instructions, fact_index,
                                                                  guards, relocations, stop);
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Switch analysis canceled"};
                if (riscv_switch) {
                    result.complete = result.complete && riscv_switch->complete;
                    result.sites.push_back(std::move(*riscv_switch));
                }
                continue;
            }
            if (instruction.context.architecture == Architecture::arm &&
                instruction.context.mode == ExecutionMode::thumb &&
                (instruction.opcode == Opcode::arm_tbb || instruction.opcode == Opcode::arm_tbh) &&
                instruction.flow == FlowKind::jump) {
                auto thumb_switch = thumb_table_branch_switch(image, function, snapshot,
                                                               found->second->instructions, fact_index, guards, stop);
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Switch analysis canceled"};
                if (thumb_switch) {
                    result.complete = result.complete && thumb_switch->complete;
                    result.sites.push_back(std::move(*thumb_switch));
                }
                continue;
            }
            if (instruction.context.architecture == Architecture::arm64 &&
                instruction.opcode == Opcode::a64_br && instruction.flow == FlowKind::jump) {
                auto a64_switch = a64_indexed_absolute_switch(image, function, snapshot,
                                                               found->second->instructions, fact_index, guards,
                                                               relocations, metadata, stop);
                if (!a64_switch && !stop.stop_requested())
                    a64_switch = a64_adr_indexed_absolute_switch(image, function, snapshot,
                                                                  found->second->instructions, fact_index, guards,
                                                                  relocations, stop);
                if (!a64_switch && !stop.stop_requested())
                    a64_switch = a64_signed_offset_switch(image, function, snapshot,
                                                           found->second->instructions, fact_index, guards,
                                                            relocations, metadata, stop);
                if (!a64_switch && !stop.stop_requested())
                    a64_switch = a64_separate_base_signed_offset_switch(image, function, snapshot,
                                                                          found->second->instructions, fact_index,
                                                                          guards, relocations, metadata, stop);
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Switch analysis canceled"};
                if (a64_switch) {
                    result.complete = result.complete && a64_switch->complete;
                    result.sites.push_back(std::move(*a64_switch));
                }
                continue;
            }
            if (!x86_mode(instruction.context) || instruction.context.segmented_memory ||
                instruction.opcode != Opcode::jmp || instruction.flow != FlowKind::jump)
                continue;

            const MemoryOperand *table_memory = nullptr;
            std::optional<Address> table_base;
            for (std::size_t operand_index = 0; operand_index < instruction.operands.size(); ++operand_index) {
                const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[operand_index]);
                const auto candidate = memory && memory->index && !memory->base
                                           ? absolute_table_base(instruction, *memory,
                                                                 static_cast<std::uint32_t>(operand_index),
                                                                 relocations, stop)
                                           : std::optional<Address>{};
                if (memory && candidate) {
                    if (table_memory) {
                        table_memory = nullptr;
                        table_base.reset();
                        break;
                    }
                    table_memory = memory;
                    table_base = candidate;
                }
            }
            if (!table_memory) {
                auto register_based = register_based_absolute_switch(image, function, snapshot,
                                                                       found->second->instructions,
                                                                       fact_index, guards, relocations, stop);
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Switch analysis canceled"};
                if (register_based) {
                    result.complete = result.complete && register_based->complete;
                    result.sites.push_back(std::move(*register_based));
                    continue;
                }
                auto register_relative = relative_offset_register_base_switch(
                    image, function, snapshot, found->second->instructions, fact_index, guards, relocations, stop);
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Switch analysis canceled"};
                if (register_relative) {
                    result.complete = result.complete && register_relative->complete;
                    result.sites.push_back(std::move(*register_relative));
                    continue;
                }
                auto relative = relative_offset_switch(image, function, snapshot, found->second->instructions,
                                                       fact_index, guards, relocations, stop);
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Switch analysis canceled"};
                if (relative) {
                    result.complete = result.complete && relative->complete;
                    result.sites.push_back(std::move(*relative));
                }
                continue;
            }

            const auto pointer_width = instruction.context.mode == ExecutionMode::x86_16 ? 16u
                                       : instruction.context.mode == ExecutionMode::x86_32 ? 32u
                                       : instruction.context.mode == ExecutionMode::x86_64 ? 64u : 0u;
            const std::size_t pointer_bytes = pointer_width / 8;
            const bool relative_offsets = instruction.context.mode == ExecutionMode::x86_64 &&
                                          table_memory->ip_relative && table_memory->scale == 4;
            const std::size_t entry_bytes = relative_offsets ? 4 : pointer_bytes;
            if (!entry_bytes || table_memory->data_width != pointer_width ||
                table_memory->scale != entry_bytes)
                continue;

            SwitchSite site;
            site.dispatch = instruction.address;
            if (!table_base)
                continue;
            site.table = *table_base;
            site.selector = *table_memory->index;
            site.scale = table_memory->scale;
            if (relative_offsets)
                site.entry_encoding = SwitchEntryEncoding::signed_offset_from_table;
            if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector,
                                                      instruction.address, instruction.address, instruction.context, guards, stop)) {
                site.case_count = bound->case_count;
                site.default_target = bound->default_target;
            }
            const auto scan_limit = site.case_count ? *site.case_count : max_entries;
            for (std::size_t index = 0; index < scan_limit; ++index) {
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Switch analysis canceled"};
                const auto target = table_target(image, site.table, index, entry_bytes, relative_offsets,
                                                 relocations, stop);
                if (!target || !decodes_at(image, instruction.context, target->address, stop)) {
                    site.complete = false;
                    break;
                }
                if (index > std::numeric_limits<std::uint32_t>::max()) {
                    site.complete = false;
                    break;
                }
                site.cases.push_back({static_cast<std::uint32_t>(index), target->address, target->source,
                                      target->relocation_rows, target->dyld_classic_rows,
                                      target->dyld_chained_rows});
            }
            if (!site.case_count && site.cases.size() == max_entries)
                site.complete = false;
            if (site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1)) {
                result.complete = result.complete && site.complete;
                result.sites.push_back(std::move(site));
            }
        }
    }
    return result;
}
Result<SwitchAnalysis> analyze_switch_tables(const Image &image, const FunctionRecord &function,
                                             const FunctionSnapshot &snapshot, std::stop_token stop) {
    return analyze_switch_tables_impl(image, function, snapshot, nullptr, nullptr, stop);
}
Result<SwitchAnalysis> analyze_switch_tables(const Image &image, const RelocationResolver &relocations,
                                             const FunctionRecord &function, const FunctionSnapshot &snapshot,
                                             std::stop_token stop) {
    return analyze_switch_tables_impl(image, function, snapshot, &relocations, relocations.source_metadata(), stop);
}
Result<SwitchAnalysis> analyze_switch_tables(const Image &image, const ImageMetadata &metadata,
                                             const FunctionRecord &function, const FunctionSnapshot &snapshot,
                                             std::stop_token stop) {
    auto resolver = RelocationResolver::create(image, metadata, stop);
    if (!resolver)
        return resolver.error();
    return analyze_switch_tables_impl(image, function, snapshot, &resolver.value(), &metadata, stop);
}
} // namespace hexlab
