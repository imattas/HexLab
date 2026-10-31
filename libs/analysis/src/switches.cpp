#include "hexlab/analysis/switches.hpp"
#include "hexlab/analysis/relocations.hpp"
#include "dex_switch_internal.hpp"
#include "instruction_flow.hpp"

#include "hexlab/image/image.hpp"
#include "hexlab/processors/decoder.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <deque>
#include <functional>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <tuple>

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
                                        std::optional<Address> relative_base = {}, unsigned relative_xlen = 64,
                                        bool unsigned_relative = false) {
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
            // A resolved relocation address does not prove that the stored
            // field is an unsigned displacement from this separately held
            // register base. Never reinterpret such fields as raw RVA bytes.
            if (unsigned_relative)
                return {};
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
        if ((width != 2 && width != 4) &&
            !(width == 1 && (relative_xlen == 32 || (relative_xlen == 64 && relative_base))))
            return {};
        const auto base = relative_base.value_or(table);
        if (base.space != table.space)
            return {};
        if (unsigned_relative) {
            if (width != 4 || relative_xlen != 64)
                return {};
            const auto target = add_offset(base, static_cast<std::uint32_t>(value), image);
            return target ? std::optional<TableTarget>(TableTarget{*target}) : std::nullopt;
        }
        const auto displacement = width == 1
            ? static_cast<std::int64_t>(static_cast<std::int8_t>(static_cast<std::uint8_t>(value)))
            : width == 2
                ? static_cast<std::int64_t>(static_cast<std::int16_t>(static_cast<std::uint16_t>(value)))
                : static_cast<std::int64_t>(static_cast<std::int32_t>(static_cast<std::uint32_t>(value)));
        if (relative_xlen == 32) {
            if (width != 1 && width != 2 && width != 4)
                return {};
            if (base.offset > std::numeric_limits<std::uint32_t>::max())
                return {};
            const auto target = static_cast<std::uint32_t>(base.offset) + static_cast<std::uint32_t>(displacement);
            return TableTarget{Address{base.space, target}};
        }
        if (relative_xlen != 64)
            return {};
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

struct ElfRelocationTableScan {
    bool applicable = false;
    bool reject_unbounded = false;
    bool complete = false;
    std::vector<SwitchCase> cases;
};

bool decodes_at(const Image &image, DecodeContext context, Address target, std::stop_token stop);

ElfRelocationTableScan scan_static_elf_absolute_table(const Image &image, Address table,
                                                      std::uint32_t case_count, DecodeContext context,
                                                      const RelocationResolver *relocations,
                                                      const ImageMetadata *metadata, std::stop_token stop) {
    ElfRelocationTableScan result;
    if (case_count > max_entries || !relocations || !metadata || !metadata->elf || metadata->macho ||
        relocations->format() != RelocationFormat::elf || !metadata->elf->header.is_64 ||
        metadata->elf->header.order != ByteOrder::little)
        return result;
    const auto machine = metadata->elf->header.machine;
    const bool x64 = machine == 62 && context.architecture == Architecture::x86_64 &&
                     context.mode == ExecutionMode::x86_64;
    const bool a64 = machine == 183 && context.architecture == Architecture::arm64 &&
                     context.mode == ExecutionMode::a64;
    if (!x64 && !a64)
        return result;

    if (!case_count) {
        // A relocation-bearing table without a proven count has no safe extent.
        // Detect it only to suppress the legacy prefix scan; do not publish any
        // entries from this unbounded probe.
        for (std::size_t index = 0; index < max_entries; ++index) {
            if (stop.stop_requested())
                return result;
            const auto entry = add_offset(table, static_cast<std::uint64_t>(index) * 8, image);
            if (!entry || !file_backed_range(image, *entry, 8, false))
                break;
            auto evidence = relocations->data_at(image, *entry, 8, stop);
            if (evidence && evidence.value().relocated()) {
                result.reject_unbounded = true;
                break;
            }
        }
        return result;
    }

    // Activate the relocation-only path only when this bounded slot range has
    // at least one relocation. Ordinary encoded tables keep their normal path.
    for (std::uint32_t index = 0; index < case_count; ++index) {
        if (stop.stop_requested())
            return result;
        const auto entry = add_offset(table, static_cast<std::uint64_t>(index) * 8, image);
        if (!entry)
            break;
        auto evidence = relocations->data_at(image, *entry, 8, stop);
        if (evidence && evidence.value().relocated()) {
            result.applicable = true;
            break;
        }
    }
    if (!result.applicable)
        return result;

    const auto extent = static_cast<std::uint64_t>(case_count) * 8;
    if (!file_backed_range(image, table, static_cast<std::size_t>(extent), false)) {
        result.complete = false;
        return result;
    }
    result.complete = true;
    result.cases.reserve(case_count);
    for (std::uint32_t index = 0; index < case_count; ++index) {
        if (stop.stop_requested()) {
            result.complete = false;
            break;
        }
        const auto entry = add_offset(table, static_cast<std::uint64_t>(index) * 8, image);
        if (!entry || !file_backed_range(image, *entry, 8, false)) {
            result.complete = false;
            break;
        }
        auto fixed = relocations->data_at(image, *entry, 8, stop);
        if (!fixed || !fixed.value().address || fixed.value().relocations.size() != 1 || fixed.value().dyld) {
            result.complete = false;
            break;
        }
        const auto row_index = fixed.value().relocations.front();
        if (row_index >= metadata->elf->relocations.size()) {
            result.complete = false;
            break;
        }
        const auto &row = metadata->elf->relocations[static_cast<std::size_t>(row_index)];
        const auto expected_type = x64 ? 1u : 257u; // R_X86_64_64 / R_AARCH64_ABS64
        const auto target_section = entry->space.value;
        bool exact_rela = metadata->elf->header.object_type == 1 && row.type == expected_type &&
                          row.kind == ElfRelocationKind::absolute &&
                          row.field_size == 8 && row.explicit_addend && row.addend && row.symbol_index_validated &&
                          row.place == entry && row.target_section == target_section && row.source.section &&
                          *row.source.section < metadata->elf->sections.size() && row.symbol_table &&
                          row.symbol_table->section;
        if (exact_rela) {
            const auto &relocation_section = metadata->elf->sections[*row.source.section];
            exact_rela = relocation_section.type == 4 && relocation_section.info == target_section &&
                         relocation_section.link == *row.symbol_table->section;
        }
        if (!exact_rela || !decodes_at(image, context, *fixed.value().address, stop)) {
            result.complete = false;
            break;
        }
        result.cases.push_back({index, *fixed.value().address, SwitchCase::TargetSource::elf_relocation,
                                fixed.value().relocations});
    }
    result.complete = result.complete && result.cases.size() == case_count;
    return result;
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

std::optional<Address> decoded_instruction_end(const Image &image, DecodeContext context, Address target,
                                               std::stop_token stop) {
    if (stop.stop_requested() || !executable_file_byte(image, target))
        return {};
    const auto target_context = image.context_at(target);
    if (!target_context || target_context.value().architecture != context.architecture ||
        target_context.value().mode != context.mode)
        return {};
    const auto count = static_cast<std::size_t>(image.code_window(target, 15));
    if (!count)
        return {};
    const auto bytes = image.read(target, count);
    if (!bytes)
        return {};
    const auto decoded = decode_instruction(context, bytes.value(), target);
    if (decoded.status != DecodeStatus::decoded || !decoded.instruction ||
        !decoded.instruction->length ||
        !file_backed_range(image, target, decoded.instruction->length, true) ||
        decoded.instruction->length > UINT64_MAX - target.offset)
        return {};
    return Address{target.space, target.offset + decoded.instruction->length};
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

struct ReachingTableBase {
    Address table;
    Address definition;
    std::vector<std::uint64_t> relocation_rows;
};

std::optional<ReachingTableBase> x86_path_complete_table_base(
    const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const SwitchGuardGraph &graph, const Instruction &load, const RegisterOperand &base,
    const RelocationResolver *relocations, Address dispatch, std::stop_token stop) {
    constexpr std::size_t max_blocks = 128;
    constexpr std::size_t max_snapshot_blocks = 1024;
    constexpr std::size_t max_nodes = 4096;
    constexpr std::size_t max_edges = 8192;
    const auto width = load.context.mode == ExecutionMode::x86_64 ? 64u
        : load.context.mode == ExecutionMode::x86_32 ? 32u : 0u;
    if (!function.complete || !snapshot.complete || function.blocks.size() > max_blocks ||
        snapshot.blocks.size() > max_snapshot_blocks ||
        graph.nodes.size() > max_nodes || !width || base.width != width || base.bank != RegisterBank::gpr)
        return {};
    if (relocations) {
        const auto load_resolution = relocations->operand(load, 1, stop);
        if (!load_resolution || load_resolution.value().relocated())
            return {};
    }

    // The graph contains only known targets. An unresolved indirect transfer
    // elsewhere in the snapshot could enter this function without appearing
    // as a predecessor, so decline the proof when any such transfer is known.
    for (const auto &block : snapshot.blocks) {
        if (stop.stop_requested() || !block)
            return {};
        for (const auto &fact : block->instructions) {
            if (stop.stop_requested() || !fact)
                return {};
            const auto &instruction = fact->instruction;
            if (instruction.address != dispatch &&
                (instruction.flow == FlowKind::switch_dispatch ||
                 ((instruction.flow == FlowKind::jump || instruction.flow == FlowKind::call) &&
                  !instruction.direct_target)))
                return {};
        }
        for (const auto &edge : block->successors)
            if (edge.source != dispatch && !edge.target && edge.kind == BlockEdgeKind::unresolved)
                return {};
    }
    if (snapshot.candidates.size() > 8192)
        return {};
    std::map<GuardAddress, bool> candidate_entries;
    for (const auto &candidate : snapshot.candidates)
        candidate_entries.emplace(guard_address(candidate.entry), true);

    const auto load_node = graph.addresses.find(guard_address(load.address));
    if (load_node == graph.addresses.end())
        return {};
    const auto load_index = load_node->second;
    if (graph.nodes[load_index].alternate_entry || graph.nodes[load_index].ambiguous ||
        graph.nodes[load_index].predecessors.empty())
        return {};

    std::vector<bool> seen(graph.nodes.size(), false);
    std::vector<bool> definitions(graph.nodes.size(), false);
    std::vector<std::size_t> dependencies(graph.nodes.size(), 0);
    std::vector<std::vector<std::size_t>> dependents(graph.nodes.size());
    std::vector<std::size_t> pending = graph.nodes[load_index].predecessors;
    std::size_t edge_count = pending.size();
    if (edge_count > max_edges)
        return {};
    std::size_t visited = 0;
    std::optional<ReachingTableBase> result;
    while (!pending.empty()) {
        if (stop.stop_requested() || visited >= max_nodes)
            return {};
        const auto current = pending.back();
        pending.pop_back();
        if (seen[current])
            continue;
        seen[current] = true;
        ++visited;
        const auto &node = graph.nodes[current];
        if (!node.fact || node.alternate_entry || node.ambiguous)
            return {};
        const auto &instruction = node.fact->instruction;
        if (instruction.context != load.context)
            return {};
        if (candidate_entries.contains(guard_address(instruction.address)))
            return {};

        const bool lea_candidate = instruction.opcode == Opcode::lea &&
            instruction.operands.size() == 2 && instruction.flow == FlowKind::fallthrough &&
            same_register(register_operand(instruction, 0), &base);
        if (lea_candidate) {
            const auto *destination = register_operand(instruction, 0);
            const auto *address = std::get_if<MemoryOperand>(&instruction.operands[1]);
            if (!destination || destination->width != width || !address || address->segment ||
                address->address_width != width || address->index)
                return {};
            const bool valid_base_form = width == 64
                ? address->ip_relative && (!address->base || address->base->bank == RegisterBank::ip)
                : !address->ip_relative && !address->base;
            if (!valid_base_form)
                return {};
            const auto table = width == 64
                ? relocated_operand_address(instruction, 1, address->resolved_address, relocations, stop)
                : absolute_table_base(instruction, *address, 1, relocations, stop);
            if (!table)
                return {};
            if (width == 32 && table->offset > UINT32_MAX)
                return {};
            ReachingTableBase candidate{*table, instruction.address, {}};
            if (relocations) {
                const auto resolution = relocations->operand(instruction, 1, stop);
                if (!resolution || resolution.value().dyld)
                    return {};
                candidate.relocation_rows = resolution.value().relocations;
            }
            if (result && (result->table != candidate.table || result->definition != candidate.definition ||
                           result->relocation_rows != candidate.relocation_rows))
                return {};
            result = std::move(candidate);
            definitions[current] = true;
            continue;
        }

        const auto *destination = register_operand(instruction, 0);
        const bool recognized_register_write = destination && destination->bank == RegisterBank::gpr &&
            !same_register(destination, &base) &&
            (instruction.opcode == Opcode::mov || instruction.opcode == Opcode::movzx ||
             instruction.opcode == Opcode::movsx || instruction.opcode == Opcode::movsxd ||
             instruction.opcode == Opcode::lea || instruction.opcode == Opcode::add ||
             instruction.opcode == Opcode::sub || instruction.opcode == Opcode::bit_and ||
             instruction.opcode == Opcode::bit_or || instruction.opcode == Opcode::bit_xor ||
             instruction.opcode == Opcode::shl || instruction.opcode == Opcode::shr ||
             instruction.opcode == Opcode::sar ||
             instruction.opcode == Opcode::inc || instruction.opcode == Opcode::dec);
        const bool recognized_no_register_write = instruction.opcode == Opcode::nop ||
            instruction.opcode == Opcode::cmp || instruction.opcode == Opcode::test;
        const bool recognized_control =
            (instruction.flow == FlowKind::jump && instruction.opcode == Opcode::jmp &&
             instruction.direct_target) ||
            (instruction.flow == FlowKind::conditional_branch && instruction.opcode == Opcode::jcc &&
             instruction.direct_target);
        const bool safe_instruction = recognized_control ||
            (instruction.flow == FlowKind::fallthrough &&
             (recognized_register_write || recognized_no_register_write));
        if (writes_register(instruction, base) || instruction.opcode == Opcode::opaque ||
            instruction.opcode == Opcode::x86_opaque || instruction.flow == FlowKind::call ||
            instruction.flow == FlowKind::ret || instruction.flow == FlowKind::trap ||
            !safe_instruction || node.predecessors.empty())
            return {};
        dependencies[current] = node.predecessors.size();
        for (const auto predecessor : node.predecessors) {
            if (++edge_count > max_edges)
                return {};
            dependents[predecessor].push_back(current);
            pending.push_back(predecessor);
        }
    }
    if (!result)
        return {};

    std::deque<std::size_t> ready;
    for (std::size_t i = 0; i < graph.nodes.size(); ++i)
        if (seen[i] && definitions[i])
            ready.push_back(i);
    std::size_t resolved = 0;
    while (!ready.empty()) {
        if (stop.stop_requested())
            return {};
        const auto current = ready.front();
        ready.pop_front();
        ++resolved;
        for (const auto next : dependents[current])
            if (--dependencies[next] == 0)
                ready.push_back(next);
    }
    if (resolved != visited)
        return {};
    return result;
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
            bool ppc_strict_upper_bound = false;
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
            } else if (context.architecture == Architecture::arm && context.mode == ExecutionMode::a32 &&
                       compare.opcode == Opcode::a32_cmp && compare.operands.size() == 2 &&
                       branch.opcode == Opcode::a32_b && (branch.condition == 2 || branch.condition == 8)) {
                compared_register = register_operand(compare, 0);
                immediate = std::get_if<ImmediateOperand>(&compare.operands[1]);
                exclusive_upper_bound = branch.condition == 8;
            } else if (((context.architecture == Architecture::riscv64 && context.mode == ExecutionMode::rv64) ||
                        (context.architecture == Architecture::riscv32 && context.mode == ExecutionMode::rv32)) &&
                       compare.opcode == Opcode::rv_sltiu && compare.operands.size() == 3 &&
                       branch.opcode == Opcode::rv_beq && branch.operands.size() == 3) {
                // SLTIU guard, selector, positive_bound; BEQ guard, X0,
                // default proves that the fallthrough selector is below the
                // bound for both XLENs. A negative immediate is sign-extended
                // before the unsigned comparison and is not a useful table bound.
                const auto *guard = register_operand(compare, 0);
                compared_register = register_operand(compare, 1);
                immediate = std::get_if<ImmediateOperand>(&compare.operands[2]);
                const auto *left = register_operand(branch, 0);
                const auto *right = register_operand(branch, 1);
                const auto width = context.mode == ExecutionMode::rv32 ? 32u : 64u;
                if (!guard || !compared_register || !immediate || guard->bank != RegisterBank::riscv_gpr ||
                    guard->width != width || guard->index == 0 || *guard == *compared_register ||
                    !((same_register(left, guard) && right && right->bank == RegisterBank::riscv_gpr &&
                       right->width == width && right->index == 0) ||
                      (same_register(right, guard) && left && left->bank == RegisterBank::riscv_gpr &&
                       left->width == width && left->index == 0)) ||
                    immediate->encoded_width != 12 || immediate->effective_width != width ||
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
            } else if (context.architecture == Architecture::powerpc && context.mode == ExecutionMode::ppc32 &&
                       compare.opcode == Opcode::ppc_cmpli && compare.operands.size() == 3 &&
                       branch.opcode == Opcode::ppc_bc && branch.operands.size() == 4) {
                // CMPLWI CRf, rSelector, bound; BGE CRf, default. BO=4
                // branches when the selected CR bit is clear; BI=4*f selects
                // the LT bit set by CMPLI in CR field f, so fallthrough proves
                // the unsigned interval [0, bound).
                const auto *field = register_operand(compare, 0);
                compared_register = register_operand(compare, 1);
                immediate = std::get_if<ImmediateOperand>(&compare.operands[2]);
                const auto *bo = std::get_if<ImmediateOperand>(&branch.operands[0]);
                const auto *bi = std::get_if<ImmediateOperand>(&branch.operands[1]);
                const auto *branch_field = register_operand(branch, 2);
                if (!field || field->bank != RegisterBank::ppc_cr || field->width != 4 ||
                    !compared_register || compared_register->bank != RegisterBank::ppc_gpr ||
                    compared_register->width != 32 || !immediate || immediate->encoded_width != 16 ||
                    immediate->effective_width != 32 || immediate->is_signed || immediate->value == 0 ||
                    immediate->value > max_entries || !bo || bo->value != 4 || !bi ||
                    bi->value != static_cast<std::uint64_t>(field->index) * 4 ||
                    !branch_field || branch_field->bank != RegisterBank::ppc_cr ||
                    branch_field->index != field->index || branch_field->width != field->width)
                    continue;
                ppc_strict_upper_bound = true;
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
            if (!signed_upper_bound &&
                (branch_end.value() != sequence_begin || ppc_strict_upper_bound)) {
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
                ((context.architecture == Architecture::riscv64 || context.architecture == Architecture::riscv32) &&
                 (selector.bank != RegisterBank::riscv_gpr ||
                  selector.width != (context.mode == ExecutionMode::rv32 ? 32 : 64) || selector.index == 0 ||
                  !compared_register || compared_register->width != selector.width)) ||
                (context.architecture == Architecture::powerpc &&
                 (selector.bank != RegisterBank::ppc_gpr || selector.width != 32 || selector.index == 0 ||
                  !compared_register || compared_register->bank != RegisterBank::ppc_gpr ||
                  compared_register->width != 32)) ||
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
    //   LEA Rbase, [RIP+table]; ...; MOVSX[D] Roff, [Rbase+Rindex*1/2/4];
    //   ADD Roff, Rbase; JMP Roff.
    // MOV Roff32, [Rbase+Rindex*4+disp] instead zero-extends a dword.
    // Those entries are unsigned offsets from Rbase (often an image base),
    // while Rbase+disp locates a distinct table.
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
        (load.opcode != Opcode::movsxd && load.opcode != Opcode::mov && load.opcode != Opcode::movsx) ||
        load.flow != FlowKind::fallthrough ||
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
    const bool unsigned_offsets = load.opcode == Opcode::mov;
    const bool signed_byte_offsets = load.opcode == Opcode::movsx && entries && entries->data_width == 8;
    const bool signed_word_offsets = load.opcode == Opcode::movsx && entries && entries->data_width == 16;
    const auto entry_width = signed_byte_offsets ? std::size_t{1}
        : signed_word_offsets ? std::size_t{2} : std::size_t{4};
    if (!target_reg || !loaded_reg || !add_dest || !add_src || !entries ||
        target_reg->bank != RegisterBank::gpr || target_reg->width != 64 || target_reg->high_byte ||
        loaded_reg->bank != RegisterBank::gpr || loaded_reg->width != (unsigned_offsets ? 32 : 64) ||
        loaded_reg->high_byte || add_dest->width != 64 || add_dest->high_byte ||
        add_src->bank != RegisterBank::gpr || add_src->width != 64 || add_src->high_byte ||
        !same_register(target_reg, loaded_reg) || !same_register(loaded_reg, add_dest) ||
        !entries->base || !same_register(entries->base ? &*entries->base : nullptr, add_src) ||
        !same_register(add_src, &*entries->base) || !entries->index || entries->scale != entry_width ||
        entries->data_width != entry_width * 8 || entries->address_width != 64 || entries->segment || entries->ip_relative ||
        (!unsigned_offsets && !signed_word_offsets && entries->displacement != 0) || same_register(add_src, loaded_reg) ||
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
    std::vector<std::uint64_t> base_relocation_rows;
    bool cross_block_base = false;
    std::size_t examined = 0;
    for (std::size_t cursor = dispatch_index - 2; cursor > 0 && examined < max_relative_base_scan;) {
        ++examined;
        --cursor;
        if (stop.stop_requested() || !facts[cursor])
            return {};
        const auto &candidate = facts[cursor]->instruction;
        if (candidate.context != dispatch.context || candidate.flow != FlowKind::fallthrough ||
            candidate.opcode == Opcode::opaque || candidate.opcode == Opcode::x86_opaque)
            return {};
        const auto candidate_end = analysis_detail::continuation_address(candidate);
        if (!candidate_end || !facts[cursor + 1] ||
            candidate_end.value() != facts[cursor + 1]->instruction.address)
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
        // An indexed-load displacement carrying its own relocation is not a
        // proven constant displacement from this base register, regardless
        // of whether the table entries are signed or unsigned.
        if (relocations) {
            const auto load_resolution = relocations->operand(load, 1, stop);
            if (!load_resolution || load_resolution.value().relocated())
                return {};
        }
        if (relocations) {
            const auto resolution = relocations->operand(candidate, 1, stop);
            if (!resolution)
                return {};
            base_relocation_rows = resolution.value().relocations;
            // Dyld ownership is not represented by base relocation rows.
            // Keep unsigned base construction explicit and inspectable.
            if (unsigned_offsets && resolution.value().dyld)
                return {};
        }
        table = resolved_table;
        base_definition = candidate.address;
        base_definition_index = cursor;
        break;
    }
    if (!table || !base_definition || !base_definition_index) {
        if (function.blocks.size() > 128 || snapshot.blocks.size() > 1024)
            return {};
        std::size_t snapshot_facts = 0;
        std::size_t snapshot_edges = 0;
        for (const auto &block : snapshot.blocks) {
            if (stop.stop_requested() || !block || block->instructions.size() > 16384 - snapshot_facts ||
                block->successors.size() > 32768 - snapshot_edges)
                return {};
            snapshot_facts += block->instructions.size();
            snapshot_edges += block->successors.size();
        }
        std::size_t function_facts = 0;
        for (const auto id : function.blocks) {
            const auto block = guards.blocks.find(id.value);
            if (block == guards.blocks.end() || !block->second ||
                block->second->instructions.size() > 4096 - function_facts)
                return {};
            function_facts += block->second->instructions.size();
        }
        if (!guards.graph_attempted) {
            guards.graph_attempted = true;
            guards.graph = switch_guard_graph(function, snapshot, guards, stop);
        }
        if (!guards.graph || stop.stop_requested())
            return {};
        const auto reaching = x86_path_complete_table_base(function, snapshot, *guards.graph,
                                                            load, table_reg, relocations,
                                                            dispatch.address, stop);
        if (!reaching)
            return {};
        table = reaching->table;
        base_definition = reaching->definition;
        base_relocation_rows = reaching->relocation_rows;
        cross_block_base = true;
    }
    if (!table || !base_definition || (!base_definition_index && !cross_block_base))
        return {};

    SwitchSite site;
    site.dispatch = dispatch.address;
    const auto entry_table = (unsigned_offsets || signed_word_offsets)
        ? add_signed_offset(*table, entries->displacement, image) : table;
    if (!entry_table)
        return {};
    site.table = *entry_table;
    site.selector = *entries->index;
    site.scale = static_cast<std::uint8_t>(entry_width);
    site.entry_encoding = unsigned_offsets ? SwitchEntryEncoding::unsigned_dword_offset_from_target_base
        : (signed_byte_offsets || signed_word_offsets) ? SwitchEntryEncoding::signed_offset_from_target_base
                              : SwitchEntryEncoding::signed_offset_from_table;
    if (unsigned_offsets || signed_byte_offsets || signed_word_offsets)
        site.target_base = *table;
    site.base_definition = base_definition;
    site.selector_use = load.address;
    if (!base_relocation_rows.empty()) {
        site.table_base_source = SwitchSite::TableBaseSource::operand_relocation;
        site.table_base_relocation_rows = std::move(base_relocation_rows);
    }
    bool selector_unchanged = true;
    if (!cross_block_base) {
        for (std::size_t i = *base_definition_index + 1; i < dispatch_index - 2; ++i) {
            if (stop.stop_requested() || !facts[i] ||
                facts[i]->instruction.context != dispatch.context ||
                facts[i]->instruction.flow != FlowKind::fallthrough ||
                writes_register(facts[i]->instruction, site.selector)) {
                selector_unchanged = false;
                break;
            }
        }
    }
    if (selector_unchanged && cross_block_base) {
        if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector,
                                                  load.address, dispatch.address, dispatch.context, guards, stop)) {
            site.case_count = bound->case_count;
            site.default_target = bound->default_target;
        }
    } else if (selector_unchanged) {
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
        const auto target = table_target(image, site.table, index, entry_width, true, relocations, stop,
                                         site.target_base, 64, unsigned_offsets);
        if (!target) {
            site.complete = false;
            site.incomplete_reason = "table entry unreadable, address overflow, or unsupported relocation/fixup";
            break;
        }
        if (!decodes_at(image, dispatch.context, target->address, stop)) {
            site.complete = false;
            site.incomplete_reason = "table target is not file-backed executable x86-64 code";
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), target->address, target->source,
                              target->relocation_rows, target->dyld_classic_rows, target->dyld_chained_rows});
    }
    if (!site.case_count && site.cases.size() == max_entries) {
        site.complete = false;
        site.incomplete_reason = "table scan reached the 4096-entry limit";
    }
    return site.cases.size() >= 2 || (site.case_count && (site.cases.size() == 1 || !site.complete))
        ? std::optional<SwitchSite>(std::move(site)) : std::nullopt;
}

std::optional<SwitchSite> x86_32_signed_word_register_base_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    std::stop_token stop) {
    // Exact compact relative-offset forms:
    //   LEA Ebase, [table]; MOVSX Eoff, [Ebase+Eindex*1/2+disp];
    //   LEA Ebase, [table]; MOV Eoff, [Ebase+Eindex*4+disp];
    //   ADD Eoff, Ebase; JMP Eoff.
    if (dispatch_index < 3 || stop.stop_requested() || !facts[dispatch_index] ||
        !facts[dispatch_index - 1] || !facts[dispatch_index - 2] || !facts[dispatch_index - 3])
        return {};
    const auto &dispatch = facts[dispatch_index]->instruction;
    const auto &add = facts[dispatch_index - 1]->instruction;
    const auto &load = facts[dispatch_index - 2]->instruction;
    const auto &lea = facts[dispatch_index - 3]->instruction;
    if (dispatch.context.mode != ExecutionMode::x86_32 || add.context != dispatch.context ||
        load.context != dispatch.context || lea.context != dispatch.context ||
        dispatch.opcode != Opcode::jmp || dispatch.flow != FlowKind::jump ||
        add.opcode != Opcode::add || add.flow != FlowKind::fallthrough ||
        (load.opcode != Opcode::movsx && load.opcode != Opcode::mov) ||
        load.flow != FlowKind::fallthrough ||
        lea.opcode != Opcode::lea || lea.flow != FlowKind::fallthrough ||
        dispatch.operands.size() != 1 || add.operands.size() != 2 || load.operands.size() != 2 ||
        lea.operands.size() != 2)
        return {};
    const auto lea_end = analysis_detail::continuation_address(lea);
    const auto load_end = analysis_detail::continuation_address(load);
    const auto add_end = analysis_detail::continuation_address(add);
    if (!lea_end || lea_end.value() != load.address || !load_end || load_end.value() != add.address ||
        !add_end || add_end.value() != dispatch.address)
        return {};

    const auto *base = register_operand(lea, 0);
    const auto *offset = register_operand(load, 0);
    const auto *load_base = register_operand(add, 1);
    const auto *add_dest = register_operand(add, 0);
    const auto *target = register_operand(dispatch, 0);
    const auto *table_address = std::get_if<MemoryOperand>(&lea.operands[1]);
    const auto *entries = std::get_if<MemoryOperand>(&load.operands[1]);
    const auto entry_bytes = entries ? static_cast<std::size_t>(entries->data_width / 8) : 0;
    const bool exact_load_width = entries &&
        ((load.opcode == Opcode::movsx && (entries->data_width == 8 || entries->data_width == 16)) ||
         (load.opcode == Opcode::mov && entries->data_width == 32));
    if (!base || !offset || !load_base || !add_dest || !target || !table_address || !entries ||
        base->bank != RegisterBank::gpr || base->width != 32 || offset->bank != RegisterBank::gpr ||
        offset->width != 32 || load_base->width != 32 || !same_register(load_base, base) ||
        add_dest->width != 32 || !same_register(add_dest, offset) || target->width != 32 ||
        !same_register(target, offset) || same_register(base, offset) ||
        table_address->ip_relative || table_address->address_width != 32 || table_address->segment ||
        table_address->base || table_address->index || entries->address_width != 32 || !exact_load_width ||
        (entries->scale != 1 && entries->scale != 2 && entries->scale != 4) ||
        entries->scale != entry_bytes ||
        entries->ip_relative || entries->segment ||
        !entries->base || !same_register(&*entries->base, base) || !entries->index ||
        entries->index->bank != RegisterBank::gpr || entries->index->width != 32 ||
        same_register(&*entries->index, base) || same_register(&*entries->index, offset))
        return {};
    const auto table_base = relocated_operand_address(lea, 1, table_address->resolved_address,
                                                       relocations, stop);
    if (!table_base || table_base->offset > UINT32_MAX)
        return {};
    if (relocations) {
        const auto load_resolution = relocations->operand(load, 1, stop);
        if (!load_resolution || load_resolution.value().relocated())
            return {};
    }
    const auto table = add_signed_offset(*table_base, entries->displacement, image);
    if (!table || table->offset > UINT32_MAX)
        return {};

    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *table;
    site.target_base = *table_base;
    site.selector = *entries->index;
    site.scale = static_cast<std::uint8_t>(entry_bytes);
    site.entry_encoding = SwitchEntryEncoding::signed_offset_from_target_base;
    site.base_definition = lea.address;
    site.selector_use = load.address;
    if (relocations) {
        const auto base_resolution = relocations->operand(lea, 1, stop);
        if (!base_resolution)
            return {};
        if (base_resolution.value().relocated()) {
            site.table_base_source = SwitchSite::TableBaseSource::operand_relocation;
            site.table_base_relocation_rows = base_resolution.value().relocations;
        }
    }
    if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector,
                                               lea.address, dispatch.address, dispatch.context, guards, stop)) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    const auto scan_limit = site.case_count ? *site.case_count : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested())
            return {};
        const auto entry = table_target(image, site.table, index, entry_bytes, true, relocations, stop,
                                        site.target_base, 32);
        if (!entry || !decodes_at(image, dispatch.context, entry->address, stop)) {
            site.complete = false;
            site.incomplete_reason = "x86-32 signed relative entry is unreadable, unresolved, or not executable code";
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), entry->address, entry->source,
                              entry->relocation_rows, entry->dyld_classic_rows, entry->dyld_chained_rows});
    }
    if (!site.case_count && site.cases.size() == max_entries) {
        site.complete = false;
        site.incomplete_reason = "x86-32 signed relative table scan reached the 4096-entry limit";
    }
    return site.cases.size() >= 2 || (site.case_count && (site.cases.size() == 1 || !site.complete))
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
    const auto mode_width = dispatch.context.mode == ExecutionMode::x86_64 ? 64u
        : dispatch.context.mode == ExecutionMode::x86_32 ? 32u : 0u;
    const auto entry_bytes = mode_width / 8;
    if (!mode_width || lea.context != dispatch.context ||
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
    const bool table_address_shape = mode_width == 64
        ? table_address && table_address->ip_relative && table_address->address_width == 64 &&
              (!table_address->base || table_address->base->bank == RegisterBank::ip)
        : table_address && !table_address->ip_relative && table_address->address_width == 32 &&
              !table_address->base;
    if (!base || !table_address || !entries || base->bank != RegisterBank::gpr || base->width != mode_width ||
        base->high_byte || !table_address_shape ||
        table_address->segment || table_address->index ||
        entries->segment || !same_register(entries->base ? &*entries->base : nullptr, base) ||
        !entries->index || entries->index->bank != RegisterBank::gpr || entries->index->width != mode_width ||
        entries->index->high_byte || same_register(&*entries->index, base) ||
        entries->scale != entry_bytes || entries->data_width != mode_width || entries->address_width != mode_width ||
        entries->displacement != 0)
        return {};
    const auto resolved_table = relocated_operand_address(lea, 1, table_address->resolved_address,
                                                          relocations, stop);
    if (!resolved_table || (mode_width == 32 && resolved_table->offset > UINT32_MAX))
        return {};

    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *resolved_table;
    site.selector = *entries->index;
    site.scale = static_cast<std::uint8_t>(entry_bytes);
    if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector, lea.address,
                                               dispatch.address, dispatch.context, guards, stop)) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    const auto *metadata = relocations ? relocations->source_metadata() : nullptr;
    const auto strict_scan = mode_width == 64
        ? scan_static_elf_absolute_table(image, site.table, site.case_count.value_or(0),
                                         dispatch.context, relocations, metadata, stop)
        : ElfRelocationTableScan{};
    if (strict_scan.reject_unbounded)
        return {};
    if (strict_scan.applicable) {
        site.cases = strict_scan.cases;
        site.complete = strict_scan.complete;
        if (!site.complete)
            site.incomplete_reason = "ELF absolute-pointer table has an incomplete or unsupported relocation prefix";
    } else {
        const auto scan_limit = site.case_count ? *site.case_count : max_entries;
        for (std::size_t index = 0; index < scan_limit; ++index) {
            if (stop.stop_requested()) return {};
            const auto target = table_target(image, site.table, index, entry_bytes, false, relocations, stop);
            if (!target || !decodes_at(image, dispatch.context, target->address, stop)) {
                site.complete = false;
                break;
            }
            site.cases.push_back({static_cast<std::uint32_t>(index), target->address, target->source,
                                  target->relocation_rows, target->dyld_classic_rows, target->dyld_chained_rows});
        }
        if (!site.case_count && site.cases.size() == max_entries) site.complete = false;
    }
    if (site.cases.size() >= 2 || (site.case_count && (site.cases.size() == 1 || !site.complete)))
        return site;
    return {};
}

std::optional<SwitchSite> register_loaded_absolute_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    std::stop_token stop) {
    // Bounded x86-32 forms:
    //   LEA Rbase, [absolute_table]; MOV Rtarget, [Rbase+Rindex*entry_bytes]; JMP Rtarget.
    //   MOV Rtarget, [absolute_table+Rindex*entry_bytes]; JMP Rtarget.
    if (dispatch_index == 0 || stop.stop_requested() || !facts[dispatch_index] ||
        !facts[dispatch_index - 1])
        return {};
    const auto &dispatch = facts[dispatch_index]->instruction;
    const auto &load = facts[dispatch_index - 1]->instruction;
    const auto address_width = dispatch.context.mode == ExecutionMode::x86_32 ? 32u : 0u;
    const auto entry_bytes = address_width / 8;
    if (!address_width || load.context != dispatch.context ||
        dispatch.opcode != Opcode::jmp || dispatch.flow != FlowKind::jump ||
        load.opcode != Opcode::mov || load.flow != FlowKind::fallthrough ||
        load.operands.size() != 2 || dispatch.operands.size() != 1)
        return {};
    const auto load_end = analysis_detail::continuation_address(load);
    if (!load_end || load_end.value() != dispatch.address)
        return {};

    const auto *loaded = register_operand(load, 0);
    const auto *target = register_operand(dispatch, 0);
    const auto *entries = std::get_if<MemoryOperand>(&load.operands[1]);
    if (!loaded || !target || !entries || loaded->bank != RegisterBank::gpr || loaded->width != address_width ||
        target->bank != RegisterBank::gpr || target->width != address_width ||
        !same_register(loaded, target) || entries->address_width != address_width ||
        entries->data_width != address_width || entries->scale != entry_bytes ||
        entries->ip_relative || entries->segment ||
        !entries->index || entries->index->bank != RegisterBank::gpr || entries->index->width != address_width ||
        same_register(&*entries->index, loaded))
        return {};
    std::optional<Address> table;
    std::optional<Address> base_definition;
    std::vector<std::uint64_t> base_relocation_rows;
    bool cross_block_base = false;
    if (entries->base) {
        bool adjacent_definition = false;
        if (dispatch_index >= 2 && facts[dispatch_index - 2]) {
            const auto &lea = facts[dispatch_index - 2]->instruction;
            const auto lea_end = analysis_detail::continuation_address(lea);
            const auto *base = register_operand(lea, 0);
            const auto *table_address = lea.operands.size() == 2
                ? std::get_if<MemoryOperand>(&lea.operands[1]) : nullptr;
            if (lea.context == dispatch.context && lea.opcode == Opcode::lea &&
                lea.flow == FlowKind::fallthrough && lea_end && lea_end.value() == load.address &&
                base && base->bank == RegisterBank::gpr && base->width == address_width &&
                !same_register(base, loaded) && !same_register(base, &*entries->index) &&
                table_address && !table_address->ip_relative &&
                table_address->address_width == address_width && !table_address->segment &&
                !table_address->base && !table_address->index && entries->displacement == 0 &&
                same_register(&*entries->base, base)) {
                table = absolute_table_base(lea, *table_address, 1, relocations, stop);
                if (!table)
                    return {};
                base_definition = lea.address;
                adjacent_definition = true;
                if (relocations) {
                    const auto load_resolution = relocations->operand(load, 1, stop);
                    if (!load_resolution || load_resolution.value().relocated())
                        return {};
                }
                if (relocations) {
                    const auto resolution = relocations->operand(lea, 1, stop);
                    if (!resolution || resolution.value().dyld)
                        return {};
                    base_relocation_rows = resolution.value().relocations;
                }
            }
        }
        if (!adjacent_definition) {
            if (entries->displacement != 0 || function.blocks.size() > 128 || snapshot.blocks.size() > 1024)
                return {};
            std::size_t snapshot_facts = 0;
            std::size_t snapshot_edges = 0;
            for (const auto &block : snapshot.blocks) {
                if (stop.stop_requested() || !block || block->instructions.size() > 16384 - snapshot_facts ||
                    block->successors.size() > 32768 - snapshot_edges)
                    return {};
                snapshot_facts += block->instructions.size();
                snapshot_edges += block->successors.size();
            }
            std::size_t function_facts = 0;
            for (const auto id : function.blocks) {
                const auto block = guards.blocks.find(id.value);
                if (block == guards.blocks.end() || !block->second ||
                    block->second->instructions.size() > 4096 - function_facts)
                    return {};
                function_facts += block->second->instructions.size();
            }
            if (!guards.graph_attempted) {
                guards.graph_attempted = true;
                guards.graph = switch_guard_graph(function, snapshot, guards, stop);
            }
            if (!guards.graph || stop.stop_requested())
                return {};
            const auto reaching = x86_path_complete_table_base(function, snapshot, *guards.graph,
                                                                load, *entries->base, relocations,
                                                                dispatch.address, stop);
            if (!reaching)
                return {};
            table = reaching->table;
            base_definition = reaching->definition;
            base_relocation_rows = reaching->relocation_rows;
            cross_block_base = true;
        }
    } else {
        table = absolute_table_base(load, *entries, 1, relocations, stop);
    }
    if (!table || table->offset > UINT32_MAX)
        return {};

    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *table;
    site.selector = *entries->index;
    site.scale = static_cast<std::uint8_t>(entry_bytes);
    site.selector_use = load.address;
    site.base_definition = base_definition;
    if (relocations && !base_definition) {
        const auto resolution = relocations->operand(load, 1, stop);
        if (!resolution)
            return {};
        if (resolution.value().relocated()) {
            site.table_base_source = SwitchSite::TableBaseSource::operand_relocation;
            site.table_base_relocation_rows = resolution.value().relocations;
        }
    }
    if (!base_relocation_rows.empty()) {
        site.table_base_source = SwitchSite::TableBaseSource::operand_relocation;
        site.table_base_relocation_rows = std::move(base_relocation_rows);
    }
    if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector,
                                               cross_block_base ? load.address : base_definition.value_or(load.address),
                                               dispatch.address,
                                               dispatch.context, guards, stop)) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    const auto scan_limit = site.case_count ? *site.case_count : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested())
            return {};
        const auto entry = table_target(image, site.table, index, entry_bytes, false, relocations, stop);
        if (!entry || !decodes_at(image, dispatch.context, entry->address, stop)) {
            site.complete = false;
            site.incomplete_reason = "x86-32 table entry is unreadable, unresolved, or not executable code";
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), entry->address, entry->source,
                              entry->relocation_rows, entry->dyld_classic_rows, entry->dyld_chained_rows});
    }
    if (!site.case_count && site.cases.size() == max_entries) {
        site.complete = false;
        site.incomplete_reason = "x86-32 table scan reached the 4096-entry limit";
    }
    return site.cases.size() >= 2 || (site.case_count && (site.cases.size() == 1 || !site.complete))
        ? std::optional<SwitchSite>(std::move(site)) : std::nullopt;
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
    const auto strict_scan = scan_static_elf_absolute_table(image, *table, site.case_count.value_or(0),
                                                             dispatch.context, relocations, metadata, stop);
    if (strict_scan.reject_unbounded)
        return {};
    if (strict_scan.applicable) {
        site.cases = strict_scan.cases;
        site.complete = strict_scan.complete;
        if (!site.complete)
            site.incomplete_reason = "ELF absolute-pointer table has an incomplete or unsupported relocation prefix";
    } else {
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
    }
    // A complete guard can prove a one-entry dispatch just as reliably as a
    // larger table. Keep unguarded one-entry prefixes ambiguous, since they
    // may simply be the first readable word of a larger table.
    return site.cases.size() >= 2 || (site.case_count && (site.cases.size() == 1 || !site.complete))
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
    const auto *metadata = relocations ? relocations->source_metadata() : nullptr;
    const auto strict_scan = scan_static_elf_absolute_table(image, site.table, site.case_count.value_or(0),
                                                             dispatch.context, relocations, metadata, stop);
    if (strict_scan.reject_unbounded)
        return {};
    if (strict_scan.applicable) {
        site.cases = strict_scan.cases;
        site.complete = strict_scan.complete;
        if (!site.complete)
            site.incomplete_reason = "ELF absolute-pointer table has an incomplete or unsupported relocation prefix";
    } else {
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
    }
    return site.cases.size() >= 2 || (site.case_count && (site.cases.size() == 1 || !site.complete))
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
    //   ADRP Xbase; ADD Xbase, Xbase, #lo12; LDRH Woff, [Xbase, Wsel, UXTW #1];
    //   SXTH Xoff, Woff (encoded as SBFM Xoff, Xoff, #0, #15);
    //   ADD Xoff, Xbase, Xoff; BR Xoff.
    //   ADRP Xbase; ADD Xbase, Xbase, #lo12; LDRSW Xoff, [Xbase, Wsel, UXTW #2];
    //   ADD Xtarget, Xbase, Xoff; BR Xtarget.
    // Signedness comes only from the explicit SBFM alias or native LDRSW opcode.
    const bool native_signed_load = dispatch_index >= 2 && facts[dispatch_index - 2] &&
        facts[dispatch_index - 2]->instruction.opcode == Opcode::a64_ldrsw;
    const bool signed_halfword_load = dispatch_index >= 3 && facts[dispatch_index - 3] &&
        facts[dispatch_index - 3]->instruction.opcode == Opcode::a64_ldrh;
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
        load.opcode != (native_signed_load ? Opcode::a64_ldrsw :
                        signed_halfword_load ? Opcode::a64_ldrh : Opcode::a64_ldr) ||
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
    const std::uint8_t entry_width = signed_halfword_load ? 16 : 32;
    const std::uint8_t entry_shift = signed_halfword_load ? 1 : 2;
    const std::uint64_t sign_extend_last_bit = signed_halfword_load ? 15 : 31;
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
        entries->data_width != entry_width || entries->address_width != 64 || entries->displacement != 0 ||
        entries->segment || entries->index_extend != "uxtw" || entries->index_shift_amount != entry_shift ||
        same_register(page_reg, &*entries->index) || same_register(page_reg, loaded_reg) ||
        !extended_dest || extended_dest->bank != RegisterBank::arm64_gpr || extended_dest->width != 64 ||
        !same_register(extended_dest, loaded_reg) || !extended_source || extended_source->width != 64 ||
        !same_register(extended_source, loaded_reg) ||
        (!native_signed_load && (!immr || immr->encoded_width != 6 || immr->effective_width != 64 ||
         immr->is_signed || immr->value != 0 || !imms || imms->encoded_width != 6 ||
         imms->effective_width != 64 || imms->is_signed || imms->value != sign_extend_last_bit)) ||
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
    site.scale = signed_halfword_load ? 2 : 4;
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
        const auto target = table_target(image, *table, index, signed_halfword_load ? 2 : 4,
                                         true, relocations, stop);
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
    return (site.cases.size() >= 2 || site.case_count.has_value()) && !site.cases.empty()
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
        (load.opcode != Opcode::a64_ldrsw && load.opcode != Opcode::a64_ldrb) || code_address.opcode != Opcode::a64_adr ||
        target_add.opcode != Opcode::a64_add ||
        table_address.operands.size() != 2 || (page_form && table_add.operands.size() != 3) ||
        load.operands.size() != 2 || code_address.operands.size() != 2 ||
        (target_add.operands.size() != 3 && target_add.operands.size() != 4) || dispatch.operands.size() != 1)
        return {};
    const bool byte_offset_form = load.opcode == Opcode::a64_ldrb;
    if (byte_offset_form != (target_add.operands.size() == 4))
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
    if (!table || table->space != dispatch.address.space || !file_backed_range(image, *table, byte_offset_form ? 1 : 4, false))
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
    if (!loaded || loaded->bank != RegisterBank::arm64_gpr || loaded->width != (byte_offset_form ? 32 : 64) || loaded->index == 31 ||
        !entries || !entries->base || !same_register(&*entries->base, table_reg) ||
        entries->base->width != 64 || !entries->index ||
        entries->index->bank != RegisterBank::arm64_gpr || entries->index->width != 32 ||
        entries->index->index == 31 || entries->data_width != (byte_offset_form ? 8 : 32) || entries->address_width != 64 ||
        entries->displacement != 0 || entries->scale != 1 || entries->segment ||
        entries->index_extend != "uxtw" || entries->index_shift_amount != (byte_offset_form ? 0 : 2) ||
        same_register(loaded, table_reg) || same_register(loaded, &*entries->index) ||
        !code_reg || code_reg->bank != RegisterBank::arm64_gpr || code_reg->width != 64 ||
        code_reg->index == 31 || !code_operand || !code_operand->ip_relative ||
        code_operand->address_width != 64 || code_operand->base || code_operand->index ||
        code_operand->segment || !code_base || code_base->space != dispatch.address.space ||
        same_register(code_reg, loaded) || same_register(code_reg, &*entries->index) ||
        !target || target->bank != RegisterBank::arm64_gpr || target->width != 64 ||
        target->index == 31 || !left || !right || left->bank != RegisterBank::arm64_gpr ||
        right->bank != RegisterBank::arm64_gpr || left->width != 64 || right->width != 64 ||
        (byte_offset_form ?
          !(same_register(left, code_reg) && same_register(right, loaded)) :
          !((same_register(left, code_reg) && same_register(right, loaded)) ||
            (same_register(right, code_reg) && same_register(left, loaded)))) ||
        same_register(target, &*entries->index) || !branch || !same_register(target, branch) ||
        branch->bank != RegisterBank::arm64_gpr || branch->width != 64 || target_add.bytes.size() != 4)
        return {};
    if (byte_offset_form) {
        const auto *shift = std::get_if<ImmediateOperand>(&target_add.operands[3]);
        if (!shift || shift->value != 2 || shift->encoded_width != 6 || shift->effective_width != 64 || shift->is_signed)
            return {};
    }
    const auto add_word = std::to_integer<std::uint32_t>(target_add.bytes[0]) |
                          (std::to_integer<std::uint32_t>(target_add.bytes[1]) << 8) |
                          (std::to_integer<std::uint32_t>(target_add.bytes[2]) << 16) |
                          (std::to_integer<std::uint32_t>(target_add.bytes[3]) << 24);
    if (((add_word >> 22) & 3u) != 0 || (!byte_offset_form && ((add_word >> 10) & 63u) != 0) ||
        (byte_offset_form && ((add_word >> 10) & 63u) != 2))
        return {}; // Offset is added without a hidden shift or extension.

    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *table;
    site.selector = *entries->index;
    site.scale = byte_offset_form ? 1 : 4;
    site.entry_encoding = byte_offset_form ? SwitchEntryEncoding::unsigned_byte_offset_scaled_from_target_base
                                           : SwitchEntryEncoding::signed_offset_from_target_base;
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
        std::optional<TableTarget> candidate;
        if (byte_offset_form) {
            const auto entry = add_offset(site.table, index, image);
            if (entry && file_backed_range(image, *entry, 1, false)) {
                const auto byte = image.read(*entry, 1);
                if (byte && byte.value().size() == 1) {
                    const auto delta = static_cast<std::uint64_t>(std::to_integer<unsigned char>(byte.value()[0])) * 4;
                    const auto address = add_offset(site.target_base.value(), delta, image);
                    if (address) candidate = TableTarget{*address};
                }
            }
        } else {
            candidate = table_target(image, site.table, index, 4, true,
                                     relocations, stop, site.target_base);
        }
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
    const auto xlen = last.context.mode == ExecutionMode::rv64 ? 64u
        : last.context.mode == ExecutionMode::rv32 ? 32u : 0u;
    const bool matching_architecture = xlen == 64
        ? last.context.architecture == Architecture::riscv64
        : xlen == 32 && last.context.architecture == Architecture::riscv32;
    if (!matching_architecture)
        return {};
    const auto add_xlen_signed = [&](Address address, std::int64_t delta) -> std::optional<Address> {
        if (xlen == 32) {
            if (address.offset > std::numeric_limits<std::uint32_t>::max())
                return {};
            const auto offset = static_cast<std::uint32_t>(address.offset) + static_cast<std::uint32_t>(delta);
            return Address{address.space, offset};
        }
        return add_signed_offset(address, delta, image);
    };
    const auto lui_address = [&](std::int64_t value) {
        const auto offset = xlen == 32 ? static_cast<std::uint64_t>(static_cast<std::uint32_t>(value))
                                       : static_cast<std::uint64_t>(value);
        return Address{last.address.space, offset};
    };
    const auto *destination = register_operand(last, 0);
    if (!destination || !same_register(destination, &base) || destination->width != xlen || base.width != xlen)
        return {};

    if ((last.opcode == Opcode::rv_auipc || last.opcode == Opcode::rv_lui) && last.operands.size() == 2) {
        const auto high = riscv_switch_immediate(last, 1, 20);
        if (!high)
            return {};
        const auto relocated = relocated_operand_address(last, 1, {}, relocations, stop);
        if (relocations) {
            const auto resolved = relocations->operand(last, 1, stop);
            if (!resolved || (resolved.value().relocated() && !resolved.value().address))
                return {};
        }
        if (relocated) {
            if (xlen == 32 && relocated->offset > std::numeric_limits<std::uint32_t>::max())
                return {};
            return relocated;
        }
        if (last.opcode == Opcode::rv_auipc)
            return add_xlen_signed(last.address, *high);
        // The decoded U-immediate is already shifted into bits 31:12 and
        // sign-extended to XLEN by LUI.
        return lui_address(*high);
    }
    if (last.opcode != Opcode::rv_addi || last.operands.size() != 3 || *definition == 0)
        return {};
    const auto *source = register_operand(last, 1);
    const auto low = riscv_switch_immediate(last, 2, 12);
    if (!source || !same_register(source, &base) || source->width != xlen || !low || !facts[*definition - 1])
        return {};
    const auto &high_instruction = facts[*definition - 1]->instruction;
    const auto high_end = analysis_detail::continuation_address(high_instruction);
    const auto *high_destination = register_operand(high_instruction, 0);
    const auto high = (high_instruction.opcode == Opcode::rv_auipc || high_instruction.opcode == Opcode::rv_lui) &&
                              high_instruction.operands.size() == 2
                          ? riscv_switch_immediate(high_instruction, 1, 20)
                          : std::optional<std::int64_t>{};
    if (high_instruction.context != last.context || high_instruction.flow != FlowKind::fallthrough ||
        !high_end || high_end.value() != last.address || !high_destination ||
        !same_register(high_destination, &base) || high_destination->width != xlen || !high)
        return {};
    const auto relocated = relocated_operand_address(last, 2, {}, relocations, stop);
    if (relocations) {
        const auto resolved = relocations->operand(last, 2, stop);
        if (!resolved || (resolved.value().relocated() && !resolved.value().address))
            return {};
    }
    if (relocated) {
        if (xlen == 32 && relocated->offset > std::numeric_limits<std::uint32_t>::max())
            return {};
        return relocated;
    }
    const auto high_address = high_instruction.opcode == Opcode::rv_auipc
        ? add_xlen_signed(high_instruction.address, *high)
        : std::optional<Address>(lui_address(*high));
    return high_address ? add_xlen_signed(*high_address, *low) : std::nullopt;
}

std::optional<SwitchSite> riscv_indexed_absolute_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    std::stop_token stop) {
    // RV32/RV64 absolute-pointer table forms use XLEN-sized entries:
    //   SLLI Xindex, Xselector, log2(XLEN/8); ADD Xaddress, Xbase, Xindex;
    //   LW/LD Xtarget, 0(Xaddress); JALR X0, 0(Xtarget).
    // The table base may have been materialized near the dispatch by an
    // AUIPC/ADDI or LUI/ADDI pair. A short straight-line scan locates selector scaling.
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
    const auto xlen = dispatch.context.mode == ExecutionMode::rv64 ? 64u
        : dispatch.context.mode == ExecutionMode::rv32 ? 32u : 0u;
    const auto entry_bytes = xlen / 8;
    const auto scale_shift = xlen == 64 ? 3u : 2u;
    const bool matching_architecture = xlen == 64
        ? dispatch.context.architecture == Architecture::riscv64
        : xlen == 32 && dispatch.context.architecture == Architecture::riscv32;
    if (!matching_architecture || dispatch.opcode != Opcode::rv_jalr || dispatch.flow != FlowKind::jump ||
        load.context != dispatch.context || address_add.context != dispatch.context ||
        load.opcode != (xlen == 64 ? Opcode::rv_ld : Opcode::rv_lw) || load.flow != FlowKind::fallthrough ||
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
        add_destination->bank != RegisterBank::riscv_gpr || add_destination->width != xlen ||
        add_destination->index == 0 || loaded_reg->bank != RegisterBank::riscv_gpr ||
        loaded_reg->width != xlen || loaded_reg->index == 0 || branch_destination->bank != RegisterBank::riscv_gpr ||
        branch_destination->width != xlen || branch_destination->index != 0 ||
        !same_register(branch_memory->base ? &*branch_memory->base : nullptr, loaded_reg) ||
        branch_memory->displacement != 0 || branch_memory->index || branch_memory->address_width != xlen ||
        !same_register(load_memory->base ? &*load_memory->base : nullptr, add_destination) ||
        load_memory->displacement != 0 || load_memory->index || load_memory->address_width != xlen ||
        load_memory->data_width != xlen ||
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
        if (!scaled || scaled->bank != RegisterBank::riscv_gpr || scaled->width != xlen || scaled->index == 0 ||
            !source || source->bank != RegisterBank::riscv_gpr || source->width != xlen || source->index == 0 ||
            !amount || amount->encoded_width != (xlen == 64 ? 6 : 5) || amount->effective_width != xlen ||
            amount->is_signed || amount->value != scale_shift)
            continue;
        const auto *candidate_base = same_register(add_left, scaled) ? add_right : add_left;
        if (!candidate_base || candidate_base->bank != RegisterBank::riscv_gpr ||
            candidate_base->width != xlen || candidate_base->index == 0 ||
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
    if (!base || base->bank != RegisterBank::riscv_gpr || base->width != xlen || base->index == 0 ||
        same_register(base, index_reg) || same_register(base, selector) || same_register(base, loaded_reg))
        return {};
    const auto table = riscv_table_base(image, facts, dispatch_index - 2, *base, relocations, stop);
    if (!table)
        return {};

    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *table;
    site.selector = *selector;
    site.scale = static_cast<std::uint8_t>(entry_bytes);
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
        const auto target = table_target(image, site.table, index, entry_bytes, false, relocations, stop);
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

std::optional<std::uint64_t> mips64_path_complete_constant(
    const FunctionRecord &function, const FunctionSnapshot &snapshot, const SwitchGuardGraph &graph,
    Address before, RegisterOperand wanted, const RelocationResolver *relocations,
    bool control_flow_closed, std::stop_token stop) {
    constexpr std::size_t path_max_blocks = 128;
    constexpr std::size_t path_max_snapshot_blocks = 1024;
    constexpr std::size_t path_max_nodes = 4096;
    constexpr std::size_t path_max_edges = 8192;
    constexpr std::size_t path_max_work = 32768;
    if (!function.complete || !snapshot.complete || function.blocks.size() > path_max_blocks ||
        snapshot.blocks.size() > path_max_snapshot_blocks || graph.nodes.size() > path_max_nodes ||
        snapshot.candidates.size() > 8192 || wanted.bank != RegisterBank::mips_gpr ||
        wanted.width != 64 || wanted.index == 0 || !control_flow_closed || stop.stop_requested())
        return {};

    const auto node = graph.addresses.find(guard_address(before));
    if (node == graph.addresses.end() || !graph.nodes[node->second].fact ||
        graph.nodes[node->second].fact->instruction.address != before)
        return {};

    using Key = std::tuple<std::size_t, std::uint16_t, bool>;
    std::map<Key, std::optional<std::uint64_t>> memo;
    std::set<Key> active;
    std::size_t remaining_work = path_max_work;
    std::function<std::optional<std::uint64_t>(std::size_t, std::uint16_t)> incoming;
    std::function<std::optional<std::uint64_t>(std::size_t, std::uint16_t)> after;
    const auto relocation_free = [&](const Instruction &instruction, std::uint32_t operand) {
        if (!relocations) return true;
        const auto resolution = relocations->operand(instruction, operand, stop);
        return resolution && !resolution.value().relocated();
    };
    incoming = [&](std::size_t current, std::uint16_t reg) -> std::optional<std::uint64_t> {
        if (reg == 0) return 0;
        const Key key{current, reg, false};
        if (const auto found = memo.find(key); found != memo.end()) return found->second;
        if (stop.stop_requested() || remaining_work == 0 || !active.insert(key).second) return {};
        --remaining_work;
        const auto &node_value = graph.nodes[current];
        if (!node_value.fact || node_value.alternate_entry || node_value.ambiguous ||
            node_value.predecessors.empty()) {
            active.erase(key);
            memo.emplace(key, std::nullopt);
            return {};
        }
        std::optional<std::uint64_t> unanimous;
        std::size_t visited_edges = 0;
        for (const auto predecessor : node_value.predecessors) {
            if (stop.stop_requested() || remaining_work == 0 || ++visited_edges > path_max_edges) {
                active.erase(key);
                return {};
            }
            --remaining_work;
            const auto value = after(predecessor, reg);
            if (!value || (unanimous && *unanimous != *value)) {
                active.erase(key);
                memo.emplace(key, std::nullopt);
                return {};
            }
            unanimous = value;
        }
        active.erase(key);
        memo.emplace(key, unanimous);
        return unanimous;
    };
    after = [&](std::size_t current, std::uint16_t reg) -> std::optional<std::uint64_t> {
        if (reg == 0) return 0;
        const Key key{current, reg, true};
        if (const auto found = memo.find(key); found != memo.end()) return found->second;
        if (stop.stop_requested() || remaining_work == 0 || !active.insert(key).second) return {};
        --remaining_work;
        const auto &node_value = graph.nodes[current];
        if (!node_value.fact || node_value.ambiguous) {
            active.erase(key);
            memo.emplace(key, std::nullopt);
            return {};
        }
        const auto &instruction = node_value.fact->instruction;
        if (instruction.context.architecture != Architecture::mips64 ||
            instruction.context.mode != ExecutionMode::mips64 || instruction.delay_slots ||
            instruction.flow == FlowKind::call || instruction.flow == FlowKind::ret ||
            instruction.flow == FlowKind::trap || instruction.flow == FlowKind::switch_dispatch ||
            instruction.opcode == Opcode::opaque || instruction.opcode == Opcode::x86_opaque ||
            (instruction.flow != FlowKind::fallthrough && instruction.flow != FlowKind::conditional_branch &&
             instruction.flow != FlowKind::jump)) {
            active.erase(key);
            memo.emplace(key, std::nullopt);
            return {};
        }
        if (!writes_register(instruction, RegisterOperand{RegisterBank::mips_gpr, reg, 64, false})) {
            const auto value = incoming(current, reg);
            active.erase(key);
            memo.emplace(key, value);
            return value;
        }

        const auto *destination = instruction.operands.empty() ? nullptr : register_operand(instruction, 0);
        const auto *source = instruction.operands.size() > 1 ? register_operand(instruction, 1) : nullptr;
        const auto immediate = [&](std::size_t index, bool signed_value, std::uint16_t effective_width)
            -> std::optional<std::uint64_t> {
            if (index >= instruction.operands.size() || !relocation_free(instruction,
                    static_cast<std::uint32_t>(index))) return {};
            const auto *value = std::get_if<ImmediateOperand>(&instruction.operands[index]);
            if (!value || value->encoded_width != 16 || value->effective_width != effective_width ||
                value->is_signed != signed_value || (!signed_value && value->value > 0xffff)) return {};
            return value->value;
        };
        std::optional<std::uint64_t> result;
        if (!destination || destination->bank != RegisterBank::mips_gpr || destination->width != 64 ||
            destination->index != reg || destination->index == 0 || instruction.flow != FlowKind::fallthrough) {
            result.reset();
        } else if (instruction.opcode == Opcode::mips_lui && instruction.operands.size() == 2) {
            if (const auto value = immediate(1, false, 16)) {
                const auto word = static_cast<std::uint32_t>(*value << 16);
                result = static_cast<std::uint64_t>(static_cast<std::int64_t>(std::bit_cast<std::int32_t>(word)));
            }
        } else if ((instruction.opcode == Opcode::mips_ori || instruction.opcode == Opcode::mips64_daddiu) &&
                   instruction.operands.size() == 3 && source && source->bank == RegisterBank::mips_gpr &&
                   source->width == 64) {
            const auto literal = instruction.opcode == Opcode::mips_ori
                ? immediate(2, false, 64) : immediate(2, true, 64);
            const auto base = literal ? incoming(current, source->index) : std::nullopt;
            if (base && literal) {
                if (instruction.opcode == Opcode::mips_ori) result = *base | *literal;
                else {
                    const auto displacement = std::bit_cast<std::int64_t>(*literal);
                    if (displacement < 0) {
                        const auto magnitude = std::uint64_t{0} - *literal;
                        if (*base >= magnitude) result = *base - magnitude;
                    } else {
                        const auto magnitude = static_cast<std::uint64_t>(displacement);
                        if (*base <= UINT64_MAX - magnitude) result = *base + magnitude;
                    }
                }
            }
        } else if (instruction.opcode == Opcode::mips64_daddu && instruction.operands.size() == 3) {
            const auto *left = register_operand(instruction, 1);
            const auto *right = register_operand(instruction, 2);
            if (left && right && left->bank == RegisterBank::mips_gpr && right->bank == RegisterBank::mips_gpr &&
                left->width == 64 && right->width == 64) {
                const auto lhs = incoming(current, left->index);
                const auto rhs = incoming(current, right->index);
                if (lhs && rhs && *lhs <= UINT64_MAX - *rhs) result = *lhs + *rhs;
            }
        }
        active.erase(key);
        memo.emplace(key, result);
        return result;
    };
    return incoming(node->second, wanted.index);
}

std::optional<SwitchSite> mips64_register_absolute_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    std::stop_token stop) {
    // MIPS64 N64 absolute and signed-relative table forms, bounded to one
    // straight-line block:
    //   LUI/ORI tableBase; DSLL index, selector, 3; DADDU address, tableBase, index;
    //   LD target, 0(address); JR target.
    // Relative tables use sign-extending LW or LH followed by
    // DADDU target, codeBase, target; JR target.
    // The same register facts also accept DADDIU adjustments around the base.
    if (dispatch_index < 4 || dispatch_index >= facts.size() || stop.stop_requested() ||
        !facts[dispatch_index])
        return {};
    const auto &dispatch = facts[dispatch_index]->instruction;
    if (dispatch.context.architecture != Architecture::mips64 ||
        dispatch.context.mode != ExecutionMode::mips64 ||
        (dispatch.opcode != Opcode::mips_jr && dispatch.opcode != Opcode::mips64_jr_hb) ||
        dispatch.flow != FlowKind::jump || dispatch.operands.size() != 1)
        return {};
    const auto *target_register = register_operand(dispatch, 0);
    if (!target_register || target_register->bank != RegisterBank::mips_gpr || target_register->width != 64 ||
        target_register->index == 0 || !facts[dispatch_index - 1])
        return {};
    bool relative_table = false;
    std::optional<RegisterOperand> relative_base_register;
    std::size_t terminal_load_index = dispatch_index - 1;
    if (dispatch_index >= 2 && facts[dispatch_index - 1]) {
        const auto &add = facts[dispatch_index - 1]->instruction;
        if (add.context == dispatch.context && add.opcode == Opcode::mips64_daddu &&
            add.flow == FlowKind::fallthrough && add.operands.size() == 3 &&
            same_register(register_operand(add, 0), target_register)) {
            const auto *left = register_operand(add, 1);
            const auto *right = register_operand(add, 2);
            if (same_register(left, target_register) && right && !same_register(right, target_register))
                relative_base_register = *right;
            else if (same_register(right, target_register) && left && !same_register(left, target_register))
                relative_base_register = *left;
            if (relative_base_register) {
                relative_table = true;
                terminal_load_index = dispatch_index - 2;
            }
        }
    }
    if (terminal_load_index >= facts.size() || !facts[terminal_load_index])
        return {};
    const auto &terminal_load = facts[terminal_load_index]->instruction;
    const bool relative_halfword_table = relative_table && terminal_load.opcode == Opcode::mips_lh;
    const std::size_t relative_entry_bytes = relative_halfword_table ? 2 : 4;
    const auto load_end = analysis_detail::continuation_address(terminal_load);
    const auto *loaded_register = terminal_load.operands.empty() ? nullptr : register_operand(terminal_load, 0);
    const auto expected_load_end = relative_table
        ? std::optional<Address>{facts[dispatch_index - 1]->instruction.address}
        : std::optional<Address>{dispatch.address};
    if (!load_end || !expected_load_end || load_end.value() != expected_load_end.value() ||
        terminal_load.context != dispatch.context ||
        terminal_load.opcode != (relative_table
            ? (relative_halfword_table ? Opcode::mips_lh : Opcode::mips_lw) : Opcode::mips64_ld) ||
        terminal_load.flow != FlowKind::fallthrough ||
        !loaded_register || !same_register(loaded_register, target_register))
        return {};
    if (relative_table) {
        const auto add_end = analysis_detail::continuation_address(facts[dispatch_index - 1]->instruction);
        if (!add_end || add_end.value() != dispatch.address || !relative_base_register ||
            relative_base_register->bank != RegisterBank::mips_gpr || relative_base_register->width != 64)
            return {};
    }

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
    // Carry only unanimously established 64-bit constants into this block.
    // The dynamic selector and table facts remain local to the straight-line
    // transfer below.
    if (!facts.empty() && facts.front()) {
        bool bounded_graph_candidate = function.complete && snapshot.complete &&
            function.blocks.size() <= 128 && snapshot.blocks.size() <= 1024;
        std::size_t function_instruction_count = 0;
        if (bounded_graph_candidate) {
            for (const auto id : function.blocks) {
                const auto block = guards.blocks.find(id.value);
                if (block == guards.blocks.end() || !block->second ||
                    block->second->instructions.size() > 4096 - function_instruction_count) {
                    bounded_graph_candidate = false;
                    break;
                }
                function_instruction_count += block->second->instructions.size();
            }
        }
        if (!guards.graph_attempted && bounded_graph_candidate) {
            guards.graph_attempted = true;
            guards.graph = switch_guard_graph(function, snapshot, guards, stop);
        }
        if (guards.graph) {
            bool control_flow_closed = snapshot.complete && snapshot.blocks.size() <= 1024;
            for (const auto &block : snapshot.blocks) {
                if (!control_flow_closed) break;
                if (stop.stop_requested() || !guards.scan(stop) || !block) {
                    control_flow_closed = false;
                    break;
                }
                for (const auto &fact : block->instructions) {
                    if (stop.stop_requested() || !guards.scan(stop) || !fact) {
                        control_flow_closed = false;
                        break;
                    }
                    const auto &instruction = fact->instruction;
                    if (instruction.address != dispatch.address &&
                        (instruction.flow == FlowKind::switch_dispatch ||
                         ((instruction.flow == FlowKind::jump || instruction.flow == FlowKind::call) &&
                          !instruction.direct_target)))
                        control_flow_closed = false;
                }
                if (!control_flow_closed) break;
                for (const auto &edge : block->successors) {
                    if (stop.stop_requested() || !guards.scan(stop)) {
                        control_flow_closed = false;
                        break;
                    }
                    if (edge.source != dispatch.address && !edge.target && edge.kind == BlockEdgeKind::unresolved)
                        control_flow_closed = false;
                }
            }
            std::set<std::uint16_t> entry_reads;
            for (const auto &fact : facts) {
                if (stop.stop_requested() || !fact) return {};
                for (const auto &read : fact->instruction.register_reads)
                    if (read.bank == RegisterBank::mips_gpr && read.width == 64 && read.index != 0)
                        entry_reads.insert(read.index);
            }
            const auto block_entry = facts.front()->instruction.address;
            for (const auto reg : entry_reads) {
                if (stop.stop_requested()) return {};
                const RegisterOperand operand{RegisterBank::mips_gpr, reg, 64, false};
                if (const auto value = mips64_path_complete_constant(function, snapshot, *guards.graph,
                        block_entry, operand, relocations, control_flow_closed, stop))
                    remember(reg, Value{Address{dispatch.address.space, *value}});
            }
        }
    }
    // The final DADDU in a relative table transforms the loaded offset into a
    // code address; keep it out of setup-value propagation so it cannot be
    // mistaken for a table-base adjustment.
    const auto setup_end = relative_table ? dispatch_index - 1 : dispatch_index;
    for (std::size_t index = 0; index < setup_end; ++index) {
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
        if ((instruction.opcode == Opcode::mips64_ld ||
             (relative_table && (instruction.opcode == Opcode::mips_lw ||
                                 instruction.opcode == Opcode::mips_lh))) &&
            instruction.operands.size() == 2 && destination) {
            const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
            std::optional<Value> value;
            const auto entry_width = instruction.opcode == Opcode::mips64_ld ? 64u
                : instruction.opcode == Opcode::mips_lh ? 16u : 32u;
            if (destination->bank == RegisterBank::mips_gpr && destination->width == 64 && destination->index != 0 &&
                memory && memory->data_width == entry_width && memory->address_width == 64 && memory->base &&
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
        found->second.scale != (relative_table ? relative_entry_bytes : 8u) || !found->second.has_scale_instruction ||
        !file_backed_range(image, *found->second.table_base,
                           relative_table ? relative_entry_bytes : 8u, false))
        return {};
    std::optional<Address> relative_base;
    if (relative_table) {
        if (!relative_base_register || relative_base_register->index == target_register->index)
            return {};
        if (relative_base_register->index == 0)
            relative_base = Address{dispatch.address.space, 0};
        else if (const auto base = registers.find(relative_base_register->index);
                 base != registers.end() && base->second.constant)
            relative_base = base->second.constant;
        if (!relative_base || relative_base->space != found->second.table_base->space)
            return {};
    }
    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *found->second.table_base;
    site.selector = *found->second.selector;
    site.scale = static_cast<std::uint8_t>(relative_table ? relative_entry_bytes : 8);
    if (relative_table) {
        site.entry_encoding = relative_halfword_table
            ? SwitchEntryEncoding::signed_halfword_offset_from_target_base
            : SwitchEntryEncoding::signed_offset_from_target_base;
        site.target_base = relative_base;
    }
    if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector,
                                               found->second.scale_instruction, dispatch.address,
                                               dispatch.context, guards, stop)) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    const auto scan_limit = site.case_count ? *site.case_count : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested()) return {};
        std::optional<TableTarget> target;
        if (relative_table) {
            const auto slot = add_offset(site.table, static_cast<std::uint64_t>(index) * relative_entry_bytes, image);
            if (slot && file_backed_range(image, *slot, relative_entry_bytes, false)) {
                bool raw_slot = true;
                if (relocations) {
                    const auto evidence = relocations->data_at(image, *slot,
                        static_cast<std::uint8_t>(relative_entry_bytes), stop);
                    raw_slot = evidence && !evidence.value().relocated();
                }
                if (raw_slot)
                    target = table_target(image, site.table, index, relative_entry_bytes, true, nullptr, stop,
                                          relative_base, 64, false);
            }
        } else {
            target = table_target(image, site.table, index, 8, false, relocations, stop);
        }
        if (!target || !decodes_at(image, dispatch.context, target->address, stop)) {
            site.complete = false;
            if (relative_table)
                site.incomplete_reason = relative_halfword_table
                    ? "MIPS64 signed halfword-relative entry could not be resolved to executable code"
                    : "MIPS64 signed-relative entry could not be resolved to executable code";
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), target->address, target->source,
                              target->relocation_rows, target->dyld_classic_rows, target->dyld_chained_rows});
    }
    if (!site.case_count && site.cases.size() == max_entries) site.complete = false;
    return site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1)
        ? std::optional<SwitchSite>(std::move(site)) : std::nullopt;
}

std::optional<std::uint32_t> mips32_path_complete_constant(
    const FunctionRecord &function, const FunctionSnapshot &snapshot, const SwitchGuardGraph &graph,
    Address before, RegisterOperand wanted, const RelocationResolver *relocations,
    Address dispatch, bool control_flow_closed, std::stop_token stop) {
    constexpr std::size_t max_blocks = 128;
    constexpr std::size_t max_snapshot_blocks = 1024;
    constexpr std::size_t max_nodes = 4096;
    constexpr std::size_t max_edges = 8192;
    constexpr std::size_t max_work = 32768;
    if (!function.complete || !snapshot.complete || function.blocks.size() > max_blocks ||
        snapshot.blocks.size() > max_snapshot_blocks || graph.nodes.size() > max_nodes ||
        snapshot.candidates.size() > 8192 || wanted.bank != RegisterBank::mips_gpr ||
        wanted.width != 32 || wanted.index == 0 || !control_flow_closed || stop.stop_requested())
        return {};

    const auto node = graph.addresses.find(guard_address(before));
    if (node == graph.addresses.end() || !graph.nodes[node->second].fact ||
        graph.nodes[node->second].fact->instruction.address != before)
        return {};

    using Key = std::tuple<std::size_t, std::uint8_t, bool>;
    std::map<Key, std::optional<std::uint32_t>> memo;
    std::set<Key> active;
    std::size_t remaining_work = max_work;
    std::function<std::optional<std::uint32_t>(std::size_t, std::uint8_t)> incoming;
    std::function<std::optional<std::uint32_t>(std::size_t, std::uint8_t)> after;
    const auto relocation_free = [&](const Instruction &instruction, std::uint32_t operand) {
        if (!relocations) return true;
        auto resolution = relocations->operand(instruction, operand, stop);
        return resolution && !resolution.value().relocated();
    };
    incoming = [&](std::size_t current, std::uint8_t reg) -> std::optional<std::uint32_t> {
        if (reg == 0) return 0;
        const Key key{current, reg, false};
        if (const auto found = memo.find(key); found != memo.end()) return found->second;
        if (stop.stop_requested() || remaining_work == 0 || !active.insert(key).second) return {};
        --remaining_work;
        const auto &node_value = graph.nodes[current];
        if (!node_value.fact || node_value.alternate_entry || node_value.ambiguous ||
            node_value.predecessors.empty()) {
            active.erase(key);
            memo.emplace(key, std::nullopt);
            return {};
        }
        std::optional<std::uint32_t> unanimous;
        std::size_t visited_edges = 0;
        for (const auto predecessor : node_value.predecessors) {
            if (stop.stop_requested() || remaining_work == 0 || ++visited_edges > max_edges) {
                active.erase(key);
                return {};
            }
            --remaining_work;
            const auto value = after(predecessor, reg);
            if (!value || (unanimous && *unanimous != *value)) {
                active.erase(key);
                memo.emplace(key, std::nullopt);
                return {};
            }
            unanimous = value;
        }
        active.erase(key);
        memo.emplace(key, unanimous);
        return unanimous;
    };
    after = [&](std::size_t current, std::uint8_t reg) -> std::optional<std::uint32_t> {
        if (reg == 0) return 0;
        const Key key{current, reg, true};
        if (const auto found = memo.find(key); found != memo.end()) return found->second;
        if (stop.stop_requested() || remaining_work == 0 || !active.insert(key).second) return {};
        --remaining_work;
        const auto &node_value = graph.nodes[current];
        if (!node_value.fact || node_value.ambiguous) {
            active.erase(key);
            memo.emplace(key, std::nullopt);
            return {};
        }
        const auto &instruction = node_value.fact->instruction;
        if (instruction.context.architecture != Architecture::mips32 ||
            instruction.context.mode != ExecutionMode::mips32 || instruction.delay_slots ||
            instruction.flow == FlowKind::call || instruction.flow == FlowKind::ret ||
            instruction.flow == FlowKind::trap || instruction.flow == FlowKind::switch_dispatch ||
            instruction.opcode == Opcode::opaque || instruction.opcode == Opcode::x86_opaque ||
            (instruction.flow != FlowKind::fallthrough && instruction.flow != FlowKind::conditional_branch &&
             instruction.flow != FlowKind::jump)) {
            active.erase(key);
            memo.emplace(key, std::nullopt);
            return {};
        }
        if (!writes_register(instruction, RegisterOperand{RegisterBank::mips_gpr, reg, 32, false})) {
            const auto value = incoming(current, reg);
            active.erase(key);
            memo.emplace(key, value);
            return value;
        }

        const auto *destination = instruction.operands.empty() ? nullptr : register_operand(instruction, 0);
        const auto *source = instruction.operands.size() > 1 ? register_operand(instruction, 1) : nullptr;
        const auto immediate = [&](std::size_t index, bool signed_value) -> std::optional<std::uint32_t> {
            if (index >= instruction.operands.size() || !relocation_free(instruction,
                    static_cast<std::uint32_t>(index))) return {};
            const auto *value = std::get_if<ImmediateOperand>(&instruction.operands[index]);
            if (!value || value->encoded_width != 16 || value->effective_width != 32 ||
                value->is_signed != signed_value || (!signed_value && value->value > 0xffff)) return {};
            return static_cast<std::uint32_t>(value->value);
        };
        std::optional<std::uint32_t> result;
        if (!destination || destination->bank != RegisterBank::mips_gpr || destination->width != 32 ||
            destination->index != reg || destination->index == 0 || instruction.flow != FlowKind::fallthrough) {
            result.reset();
        } else if (instruction.opcode == Opcode::mips_lui && instruction.operands.size() == 2) {
            if (const auto value = immediate(1, false)) result = *value << 16;
        } else if ((instruction.opcode == Opcode::mips_ori || instruction.opcode == Opcode::mips_addiu) &&
                   instruction.operands.size() == 3 && source && source->bank == RegisterBank::mips_gpr &&
                   source->width == 32) {
            const auto literal = immediate(2, instruction.opcode == Opcode::mips_addiu);
            const auto base = literal ? incoming(current, source->index) : std::nullopt;
            if (base && literal) {
                if (instruction.opcode == Opcode::mips_ori) result = *base | *literal;
                else {
                    const auto displacement = std::bit_cast<std::int32_t>(*literal);
                    const auto sum = static_cast<std::int64_t>(*base) + displacement;
                    if (sum >= 0 && sum <= UINT32_MAX) result = static_cast<std::uint32_t>(sum);
                }
            }
        } else if (instruction.opcode == Opcode::mips_addu && instruction.operands.size() == 3) {
            const auto *left = register_operand(instruction, 1);
            const auto *right = register_operand(instruction, 2);
            if (left && right && left->bank == RegisterBank::mips_gpr && right->bank == RegisterBank::mips_gpr &&
                left->width == 32 && right->width == 32) {
                const auto lhs = incoming(current, left->index);
                const auto rhs = incoming(current, right->index);
                if (lhs && rhs && *lhs <= UINT32_MAX - *rhs) result = *lhs + *rhs;
            }
        }
        active.erase(key);
        memo.emplace(key, result);
        return result;
    };
    return incoming(node->second, wanted.index);
}

std::optional<SwitchSite> mips32_register_absolute_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    std::stop_token stop) {
    // MIPS32 O32 absolute or signed-relative table forms, bounded to one
    // straight-line block. Relative entries add a separately proven code base
    // to the signed word loaded from the table.
    //   LUI/ORI tableBase; SLL index, selector, 2; ADDU address, tableBase, index;
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
    bool relative_table = false;
    bool relative_halfword_sign_extension = false;
    bool relative_byte_sign_extension = false;
    std::optional<RegisterOperand> relative_base_register;
    std::size_t terminal_load_index = dispatch_index - 1;
    if (dispatch_index >= 2 && facts[dispatch_index - 1]) {
        const auto &add = facts[dispatch_index - 1]->instruction;
        if (add.context == dispatch.context && add.opcode == Opcode::mips_addu &&
            add.flow == FlowKind::fallthrough && add.operands.size() == 3 &&
            same_register(register_operand(add, 0), target_register)) {
            const auto *left = register_operand(add, 1);
            const auto *right = register_operand(add, 2);
            if (same_register(left, target_register) && right && !same_register(right, target_register))
                relative_base_register = *right;
            else if (same_register(right, target_register) && left && !same_register(left, target_register))
                relative_base_register = *left;
            if (relative_base_register) {
                relative_table = true;
                terminal_load_index = dispatch_index - 2;
                // Some O32 compilers load unsigned narrow entries and explicitly
                // sign-extend them before adding the code base.
                if (dispatch_index >= 4 && facts[dispatch_index - 2] && facts[dispatch_index - 3]) {
                    const auto &arithmetic_shift = facts[dispatch_index - 2]->instruction;
                    const auto &left_shift = facts[dispatch_index - 3]->instruction;
                    const auto exact_shift = [&](const Instruction &instruction, Opcode opcode,
                                                 const Instruction &next, std::uint64_t expected_amount) {
                        const auto *destination = instruction.operands.size() == 3
                            ? register_operand(instruction, 0) : nullptr;
                        const auto *source = instruction.operands.size() == 3
                            ? register_operand(instruction, 1) : nullptr;
                        const auto *amount = instruction.operands.size() == 3
                            ? std::get_if<ImmediateOperand>(&instruction.operands[2]) : nullptr;
                        const auto end = analysis_detail::continuation_address(instruction);
                        return instruction.context == dispatch.context && instruction.opcode == opcode &&
                            instruction.flow == FlowKind::fallthrough && instruction.delay_slots == 0 &&
                            end && end.value() == next.address && same_register(destination, target_register) &&
                            same_register(source, target_register) && amount && amount->encoded_width == 5 &&
                            amount->effective_width == 32 && !amount->is_signed &&
                            amount->value == expected_amount;
                    };
                    const auto sign_extends = [&](std::uint64_t amount) {
                        return exact_shift(arithmetic_shift, Opcode::mips_sra,
                                           facts[dispatch_index - 1]->instruction, amount) &&
                               exact_shift(left_shift, Opcode::mips_sll, arithmetic_shift, amount);
                    };
                    if (sign_extends(16)) {
                        relative_halfword_sign_extension = true;
                        terminal_load_index = dispatch_index - 4;
                    } else if (sign_extends(24)) {
                        relative_byte_sign_extension = true;
                        terminal_load_index = dispatch_index - 4;
                    }
                }
            }
        }
    }
    if (terminal_load_index >= facts.size() || !facts[terminal_load_index]) return {};
    const auto &terminal_load = facts[terminal_load_index]->instruction;
    const auto load_end = analysis_detail::continuation_address(terminal_load);
    const auto *loaded_register = terminal_load.operands.empty() ? nullptr : register_operand(terminal_load, 0);
    const auto expected_load_end = relative_table
        ? std::optional<Address>{(relative_halfword_sign_extension || relative_byte_sign_extension)
            ? facts[dispatch_index - 3]->instruction.address
            : facts[dispatch_index - 1]->instruction.address}
        : std::optional<Address>{dispatch.address};
    if (!load_end || !expected_load_end || load_end.value() != expected_load_end.value() ||
        terminal_load.context != dispatch.context ||
        (terminal_load.opcode != Opcode::mips_lw &&
         !(relative_table && terminal_load.opcode == Opcode::mips_lh) &&
         !(relative_halfword_sign_extension && terminal_load.opcode == Opcode::mips_lhu) &&
         !(relative_table && terminal_load.opcode == Opcode::mips_lb) &&
         !(relative_byte_sign_extension && terminal_load.opcode == Opcode::mips_lbu)) ||
        terminal_load.flow != FlowKind::fallthrough ||
        !loaded_register || !same_register(loaded_register, target_register))
        return {};
    if (relative_table) {
        const auto add_end = analysis_detail::continuation_address(facts[dispatch_index - 1]->instruction);
        if (!add_end || add_end.value() != dispatch.address || !relative_base_register ||
            relative_base_register->bank != RegisterBank::mips_gpr || relative_base_register->width != 32 ||
            relative_base_register->index == target_register->index)
            return {};
    }

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
    // Seed constants that reach the beginning of this basic block only when
    // every CFG predecessor path agrees. Dynamic selector values remain
    // unknown; the existing same-block transfer then proves the table scale
    // and address calculation from the seeded bases.
    if (!facts.empty() && facts.front()) {
        bool bounded_graph_candidate = function.complete && snapshot.complete &&
            function.blocks.size() <= 128 && snapshot.blocks.size() <= 1024;
        std::size_t function_instruction_count = 0;
        if (bounded_graph_candidate) {
            for (const auto id : function.blocks) {
                const auto block = guards.blocks.find(id.value);
                if (block == guards.blocks.end() || !block->second ||
                    block->second->instructions.size() > 4096 - function_instruction_count) {
                    bounded_graph_candidate = false;
                    break;
                }
                function_instruction_count += block->second->instructions.size();
            }
        }
        if (!guards.graph_attempted && bounded_graph_candidate) {
            guards.graph_attempted = true;
            guards.graph = switch_guard_graph(function, snapshot, guards, stop);
        }
        if (guards.graph) {
            bool control_flow_closed = snapshot.complete && snapshot.blocks.size() <= 1024;
            for (const auto &block : snapshot.blocks) {
                if (!control_flow_closed) break;
                if (stop.stop_requested()) return {};
                if (!guards.scan(stop) || !block) { control_flow_closed = false; break; }
                for (const auto &fact : block->instructions) {
                    if (stop.stop_requested()) return {};
                    if (!guards.scan(stop) || !fact) { control_flow_closed = false; break; }
                    const auto &instruction = fact->instruction;
                    if (instruction.address != dispatch.address &&
                        (instruction.flow == FlowKind::switch_dispatch ||
                         ((instruction.flow == FlowKind::jump || instruction.flow == FlowKind::call) &&
                          !instruction.direct_target)))
                        control_flow_closed = false;
                }
                if (!control_flow_closed) break;
                for (const auto &edge : block->successors) {
                    if (stop.stop_requested()) return {};
                    if (!guards.scan(stop)) { control_flow_closed = false; break; }
                    if (edge.source != dispatch.address && !edge.target && edge.kind == BlockEdgeKind::unresolved)
                        control_flow_closed = false;
                }
                if (!control_flow_closed) break;
            }
            std::set<std::uint8_t> entry_reads;
            for (const auto &fact : facts) {
                if (stop.stop_requested() || !fact) return {};
                for (const auto &read : fact->instruction.register_reads)
                    if (read.bank == RegisterBank::mips_gpr && read.width == 32 && read.index != 0)
                        entry_reads.insert(read.index);
            }
            const auto block_entry = facts.front()->instruction.address;
            for (const auto reg : entry_reads) {
                if (stop.stop_requested()) return {};
                const RegisterOperand operand{RegisterBank::mips_gpr, reg, 32, false};
                if (const auto value = mips32_path_complete_constant(function, snapshot, *guards.graph,
                        block_entry, operand, relocations, dispatch.address, control_flow_closed, stop))
                    remember(reg, Value{Address{dispatch.address.space, *value}});
            }
        }
    }
    const auto setup_end = relative_table
        ? dispatch_index - ((relative_halfword_sign_extension || relative_byte_sign_extension) ? 3 : 1)
        : dispatch_index;
    for (std::size_t index = 0; index < setup_end; ++index) {
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
                    // Byte-relative tables need no shift before adding the
                    // selector to the byte table base. Accept that direct
                    // form only when the selector is an untouched block-entry
                    // value; an unsupported transform is never a selector.
                    if (!value && relative_table) {
                        const auto unscaled = [&](const RegisterOperand &selector,
                                                  const std::optional<Value> &selector_value,
                                                  const std::optional<Value> &base_value) -> std::optional<Value> {
                            if (selector_value || !base_value || !base_value->constant ||
                                base_value->constant->space != dispatch.address.space || selector.index == 0)
                                return {};
                            for (std::size_t prior = 0; prior < index; ++prior) {
                                if (!facts[prior] || facts[prior]->instruction.opcode == Opcode::opaque ||
                                    writes_register(facts[prior]->instruction, selector))
                                    return {};
                            }
                            Value result;
                            result.table_base = base_value->constant;
                            result.selector = selector;
                            result.scale = 1;
                            result.scale_instruction = instruction.address;
                            result.has_scale_instruction = true;
                            return result;
                        };
                        value = unscaled(*right, rhs, lhs);
                        if (!value) value = unscaled(*left, lhs, rhs);
                    }
                }
            }
            erase_written();
            if (value) remember(destination->index, std::move(*value));
            continue;
        }
        const bool table_entry_load = instruction.opcode == Opcode::mips_lw ||
            (relative_table && (instruction.opcode == Opcode::mips_lh ||
                                (relative_halfword_sign_extension && instruction.opcode == Opcode::mips_lhu) ||
                                instruction.opcode == Opcode::mips_lb ||
                                (relative_byte_sign_extension && instruction.opcode == Opcode::mips_lbu)));
        if (table_entry_load && instruction.operands.size() == 2 && destination) {
            const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
            std::optional<Value> value;
            const auto entry_width = instruction.opcode == Opcode::mips_lh || instruction.opcode == Opcode::mips_lhu
                ? 16u : instruction.opcode == Opcode::mips_lb || instruction.opcode == Opcode::mips_lbu
                    ? 8u : 32u;
            if (destination->bank == RegisterBank::mips_gpr && destination->width == 32 && destination->index != 0 &&
                memory && memory->data_width == entry_width && memory->address_width == 32 && memory->base &&
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
    const auto entry_width = !relative_table ? 4u
        : terminal_load.opcode == Opcode::mips_lb || terminal_load.opcode == Opcode::mips_lbu ||
          relative_byte_sign_extension ? 1u
        : terminal_load.opcode == Opcode::mips_lh || relative_halfword_sign_extension ? 2u : 4u;
    if (found == registers.end() || !found->second.table_base || !found->second.selector ||
        same_register(&*found->second.selector, target_register) ||
        found->second.scale != entry_width ||
        !found->second.has_scale_instruction ||
        !file_backed_range(image, *found->second.table_base, entry_width, false))
        return {};
    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *found->second.table_base;
    site.selector = *found->second.selector;
    site.scale = static_cast<std::uint8_t>(found->second.scale);
    if (relative_table) {
        if (same_register(&*found->second.selector, &*relative_base_register)) return {};
        std::optional<Address> relative_base;
        if (relative_base_register->index == 0)
            relative_base = Address{dispatch.address.space, 0};
        else if (const auto base = registers.find(relative_base_register->index);
                 base != registers.end() && base->second.constant)
            relative_base = base->second.constant;
        if (!relative_base || relative_base->space != dispatch.address.space ||
            relative_base->offset > UINT32_MAX)
            return {};
        site.entry_encoding = entry_width == 2
            ? SwitchEntryEncoding::signed_halfword_offset_from_target_base
            : SwitchEntryEncoding::signed_offset_from_target_base;
        site.target_base = relative_base;
    }
    if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector,
                                               found->second.scale_instruction, dispatch.address,
                                               dispatch.context, guards, stop)) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    const auto scan_limit = site.case_count ? *site.case_count : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested()) return {};
        std::optional<TableTarget> target;
        if (relative_table) {
            const auto slot = add_offset(site.table, static_cast<std::uint64_t>(index) * entry_width, image);
            bool raw_slot = slot && file_backed_range(image, *slot, entry_width, false);
            if (raw_slot && relocations) {
                const auto evidence = relocations->data_at(image, *slot, entry_width, stop);
                raw_slot = evidence && !evidence.value().relocated();
            }
            if (raw_slot)
                target = table_target(image, site.table, index, entry_width, true, nullptr, stop,
                                      site.target_base, 32, false);
        } else {
            target = table_target(image, site.table, index, 4, false, relocations, stop);
        }
        if (!target || !decodes_at(image, dispatch.context, target->address, stop)) {
            site.complete = false;
            if (relative_table)
                site.incomplete_reason = "MIPS32 signed-relative entry could not be resolved to executable code";
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), target->address, target->source,
                              target->relocation_rows, target->dyld_classic_rows, target->dyld_chained_rows});
    }
    if (!site.case_count && site.cases.size() == max_entries) site.complete = false;
    return site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1)
        ? std::optional<SwitchSite>(std::move(site)) : std::nullopt;
}

std::optional<SwitchSite> ppc32_register_absolute_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    std::stop_token stop) {
    // PPC32 indexed table forms:
    //   ADDIS/ORI tableBase; MULLI index, selector, 4 (or SLWI by 2);
    //   LWZX target, tableBase, index; [ADD target, tableBase, target];
    //   or for relative halfwords, LHAX target, tableBase, index; ADD target, codeBase, target;
    //   MTCTR target; BCTR.
    // This deliberately handles linked images with literal instruction
    // immediates. Relocation-paired HA/LO table bases need a separate proof.
    if (dispatch_index < 4 || dispatch_index >= facts.size() || stop.stop_requested() ||
        !facts[dispatch_index])
        return {};
    const auto &dispatch = facts[dispatch_index]->instruction;
    if (dispatch.context.architecture != Architecture::powerpc ||
        dispatch.context.mode != ExecutionMode::ppc32 || dispatch.opcode != Opcode::ppc_bcctr ||
        dispatch.flow != FlowKind::jump || dispatch.operands.size() < 2)
        return {};
    const auto ctr_read = std::any_of(dispatch.register_reads.begin(), dispatch.register_reads.end(),
        [](const RegisterOperand &reg) { return reg.bank == RegisterBank::ppc_ctr && reg.width == 32; });
    if (!ctr_read || !facts[dispatch_index - 1] || !facts[dispatch_index - 2])
        return {};
    const auto &move_to_ctr = facts[dispatch_index - 1]->instruction;
    const auto mtctr_end = analysis_detail::continuation_address(move_to_ctr);
    const auto dispatch_target = move_to_ctr.operands.size() == 2
        ? register_operand(move_to_ctr, 1) : nullptr;
    if (move_to_ctr.context != dispatch.context || move_to_ctr.opcode != Opcode::ppc_mtctr ||
        move_to_ctr.flow != FlowKind::fallthrough || !mtctr_end || mtctr_end.value() != dispatch.address ||
        !dispatch_target || dispatch_target->bank != RegisterBank::ppc_gpr || dispatch_target->width != 32 ||
        dispatch_target->index == 0 || !facts[dispatch_index - 2])
        return {};
    const Instruction *relative_target_add = nullptr;
    std::size_t load_index = dispatch_index - 2;
    if (dispatch_index >= 4 && facts[dispatch_index - 2] &&
        facts[dispatch_index - 2]->instruction.opcode == Opcode::ppc_add) {
        relative_target_add = &facts[dispatch_index - 2]->instruction;
        load_index = dispatch_index - 3;
    }
    if (!facts[load_index]) return {};
    const auto &terminal_load = facts[load_index]->instruction;
    const auto load_end = analysis_detail::continuation_address(terminal_load);
    const auto *loaded_register = terminal_load.operands.empty() ? nullptr : register_operand(terminal_load, 0);
    const bool halfword_relative = relative_target_add && terminal_load.opcode == Opcode::ppc_lhax;
    if (terminal_load.context != dispatch.context ||
        (terminal_load.opcode != Opcode::ppc_lwzx && !halfword_relative) ||
        terminal_load.flow != FlowKind::fallthrough || !load_end ||
        load_end.value() != (relative_target_add ? relative_target_add->address : move_to_ctr.address) ||
        !loaded_register || !same_register(loaded_register, dispatch_target) || terminal_load.operands.size() != 2)
        return {};
    if (relative_target_add) {
        const auto add_end = analysis_detail::continuation_address(*relative_target_add);
        if (relative_target_add->context != dispatch.context || relative_target_add->flow != FlowKind::fallthrough ||
            !add_end || add_end.value() != move_to_ctr.address || relative_target_add->operands.size() != 3 ||
            !same_register(register_operand(*relative_target_add, 0), dispatch_target))
            return {};
        const auto *left = register_operand(*relative_target_add, 1);
        const auto *right = register_operand(*relative_target_add, 2);
        if (!same_register(left, dispatch_target) && !same_register(right, dispatch_target))
            return {};
    }

    struct Value {
        std::optional<Address> constant;
        std::optional<Address> table_base;
        std::optional<RegisterOperand> selector;
        std::uint64_t scale = 1;
        Address scale_instruction{};
        bool has_scale_instruction = false;
    };
    std::map<std::uint32_t, Value> registers;
    const auto erase_written = [&](const Instruction &instruction) {
        for (const auto &written : instruction.register_writes)
            if (written.bank == RegisterBank::ppc_gpr && written.width == 32)
                registers.erase(written.index);
    };
    const auto decoded_immediate_is_unrelocated = [&](const Instruction &instruction, std::uint32_t operand) {
        if (!relocations)
            return true;
        auto resolution = relocations->operand(instruction, operand, stop);
        return resolution && !resolution.value().relocated();
    };
    const auto add32 = [&](Address base, std::int64_t delta) {
        return Address{base.space, static_cast<std::uint32_t>(base.offset + static_cast<std::uint64_t>(delta))};
    };

    const auto setup_end = relative_target_add ? dispatch_index - 2 : dispatch_index - 1;
    for (std::size_t index = 0; index < setup_end; ++index) {
        if (stop.stop_requested() || !facts[index])
            return {};
        const auto &instruction = facts[index]->instruction;
        if (instruction.context != dispatch.context || instruction.flow != FlowKind::fallthrough ||
            instruction.delay_slots)
            return {};
        if (index) {
            if (!facts[index - 1])
                return {};
            const auto previous_end = analysis_detail::continuation_address(facts[index - 1]->instruction);
            if (!previous_end || previous_end.value() != instruction.address)
                return {};
        }
        const auto *destination = instruction.operands.empty() ? nullptr : register_operand(instruction, 0);
        const auto valid_destination = [&](const RegisterOperand *reg) {
            return reg && reg->bank == RegisterBank::ppc_gpr && reg->width == 32 && reg->index != 0;
        };

        if (instruction.opcode == Opcode::ppc_addis && instruction.operands.size() == 3 &&
            valid_destination(destination)) {
            const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
            const auto *source = register_operand(instruction, 1);
            const bool zero_base = std::get_if<ImmediateOperand>(&instruction.operands[1]) != nullptr &&
                std::get<ImmediateOperand>(instruction.operands[1]).value == 0;
            std::optional<Address> base;
            if (zero_base)
                base = Address{dispatch.address.space, 0};
            else if (source && source->bank == RegisterBank::ppc_gpr && source->width == 32 && source->index) {
                if (const auto found = registers.find(source->index); found != registers.end())
                    base = found->second.constant;
            }
            if (immediate && immediate->effective_width == 32 && immediate->is_signed && base &&
                base->space == dispatch.address.space && decoded_immediate_is_unrelocated(instruction, 2)) {
                const auto signed_value = std::bit_cast<std::int64_t>(immediate->value);
                erase_written(instruction);
                registers[destination->index] = Value{add32(*base, signed_value)};
            } else {
                erase_written(instruction);
            }
            continue;
        }
        if (instruction.opcode == Opcode::ppc_addi && instruction.operands.size() == 3 &&
            valid_destination(destination)) {
            const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
            const auto *source = register_operand(instruction, 1);
            const bool zero_base = std::get_if<ImmediateOperand>(&instruction.operands[1]) != nullptr &&
                std::get<ImmediateOperand>(instruction.operands[1]).value == 0;
            std::optional<Address> base;
            if (zero_base)
                base = Address{dispatch.address.space, 0};
            else if (source && source->bank == RegisterBank::ppc_gpr && source->width == 32 && source->index) {
                if (const auto found = registers.find(source->index); found != registers.end())
                    base = found->second.constant;
            }
            if (immediate && immediate->effective_width == 32 && immediate->is_signed && base &&
                base->space == dispatch.address.space && decoded_immediate_is_unrelocated(instruction, 2)) {
                const auto signed_value = std::bit_cast<std::int64_t>(immediate->value);
                erase_written(instruction);
                registers[destination->index] = Value{add32(*base, signed_value)};
            } else {
                erase_written(instruction);
            }
            continue;
        }
        if (instruction.opcode == Opcode::ppc_ori && instruction.operands.size() == 3 &&
            valid_destination(destination)) {
            const auto *source = register_operand(instruction, 1);
            const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
            std::optional<Address> base;
            if (source && source->bank == RegisterBank::ppc_gpr && source->width == 32) {
                if (!source->index)
                    base = Address{dispatch.address.space, 0};
                else if (const auto found = registers.find(source->index); found != registers.end())
                    base = found->second.constant;
            }
            if (immediate && immediate->encoded_width == 16 && immediate->effective_width == 32 &&
                !immediate->is_signed && immediate->value <= 0xffff && base &&
                base->space == dispatch.address.space && decoded_immediate_is_unrelocated(instruction, 2)) {
                const auto target = Address{base->space, base->offset | immediate->value};
                erase_written(instruction);
                registers[destination->index] = Value{target};
            } else {
                erase_written(instruction);
            }
            continue;
        }
        const auto entry_scale = halfword_relative ? 2u : 4u;
        const bool multiply_scale = instruction.opcode == Opcode::ppc_mulli &&
                                    instruction.operands.size() == 3;
        const bool shift_scale = instruction.opcode == Opcode::ppc_rlwinm &&
                                 instruction.operands.size() == 5;
        if ((multiply_scale || shift_scale) && valid_destination(destination)) {
            const auto *source = register_operand(instruction, 1);
            std::optional<Value> value;
            bool exact_scale = false;
            if (multiply_scale) {
                const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
                exact_scale = immediate && immediate->effective_width == 32 && immediate->is_signed &&
                    std::bit_cast<std::int64_t>(immediate->value) == entry_scale &&
                    decoded_immediate_is_unrelocated(instruction, 2);
            } else {
                const auto *shift = std::get_if<ImmediateOperand>(&instruction.operands[2]);
                const auto *mask_begin = std::get_if<ImmediateOperand>(&instruction.operands[3]);
                const auto *mask_end = std::get_if<ImmediateOperand>(&instruction.operands[4]);
                exact_scale = shift && mask_begin && mask_end && shift->value == (halfword_relative ? 1u : 2u) &&
                    mask_begin->value == 0 && mask_end->value == (halfword_relative ? 30u : 29u);
            }
            if (exact_scale && source && source->bank == RegisterBank::ppc_gpr &&
                source->width == 32 && source->index) {
                Value scaled;
                scaled.selector = *source;
                scaled.scale = entry_scale;
                scaled.scale_instruction = instruction.address;
                scaled.has_scale_instruction = true;
                value = std::move(scaled);
            }
            erase_written(instruction);
            if (value)
                registers[destination->index] = std::move(*value);
            continue;
        }
        if ((instruction.opcode == Opcode::ppc_lwzx ||
             (halfword_relative && instruction.opcode == Opcode::ppc_lhax)) && instruction.operands.size() == 2 &&
            valid_destination(destination)) {
            const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
            std::optional<Value> loaded;
            if (memory && memory->data_width == (halfword_relative ? 16u : 32u) &&
                memory->address_width == 32 && memory->base &&
                memory->index && memory->scale == 1) {
                const auto base = registers.find(memory->base->index);
                const auto index_value = registers.find(memory->index->index);
                if (memory->base->bank == RegisterBank::ppc_gpr && memory->base->width == 32 &&
                    memory->index->bank == RegisterBank::ppc_gpr && memory->index->width == 32 &&
                    base != registers.end() && base->second.constant &&
                    base->second.constant->space == dispatch.address.space && index_value != registers.end() &&
                    index_value->second.selector && index_value->second.has_scale_instruction &&
                    index_value->second.scale == entry_scale) {
                    Value table_value;
                    table_value.constant = *base->second.constant;
                    table_value.table_base = add32(*base->second.constant, memory->displacement);
                    table_value.selector = index_value->second.selector;
                    table_value.scale = index_value->second.scale;
                    table_value.scale_instruction = index_value->second.scale_instruction;
                    table_value.has_scale_instruction = true;
                    loaded = std::move(table_value);
                }
            }
            erase_written(instruction);
            if (loaded)
                registers[destination->index] = std::move(*loaded);
            continue;
        }
        erase_written(instruction);
    }

    const auto loaded = registers.find(dispatch_target->index);
    if (loaded == registers.end() || !loaded->second.table_base || !loaded->second.selector ||
        !loaded->second.has_scale_instruction || loaded->second.scale != (halfword_relative ? 2u : 4u) ||
        same_register(&*loaded->second.selector, dispatch_target) ||
        !file_backed_range(image, *loaded->second.table_base, halfword_relative ? 2u : 4u, false))
        return {};
    if (relative_target_add) {
        const auto *left = register_operand(*relative_target_add, 1);
        const auto *right = register_operand(*relative_target_add, 2);
        const auto *base_register = same_register(left, dispatch_target) ? right : left;
        const auto base = base_register && base_register->bank == RegisterBank::ppc_gpr && base_register->index
            ? registers.find(base_register->index) : registers.end();
        if (base == registers.end() || !base->second.constant || !loaded->second.constant ||
            *base->second.constant != *loaded->second.constant)
            return {};
    }
    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *loaded->second.table_base;
    site.selector = *loaded->second.selector;
    site.scale = static_cast<std::uint8_t>(loaded->second.scale);
    if (relative_target_add) {
        site.entry_encoding = halfword_relative ? SwitchEntryEncoding::signed_halfword_offset_from_target_base
                                                : SwitchEntryEncoding::signed_offset_from_target_base;
        site.target_base = loaded->second.constant;
    }
    const auto bound = guarded_case_bound(image, function, snapshot, site.selector,
                                           loaded->second.scale_instruction, dispatch.address,
                                           dispatch.context, guards, stop);
    if (bound && (bound->case_count == 0 || bound->case_count > max_entries))
        return {};
    if (bound) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    // Without an exact selector guard, retain only the contiguous prefix whose
    // entries independently resolve to executable PPC32 instructions. The
    // result stays partial because table extent and default remain unknown.
    const auto scan_limit = bound ? static_cast<std::size_t>(bound->case_count) : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested())
            return {};
        const auto entry_bytes = halfword_relative ? 2u : 4u;
        const auto target = table_target(image, site.table, index, entry_bytes, relative_target_add != nullptr,
                                         relocations, stop,
                                         relative_target_add ? site.target_base : std::nullopt,
                                         32);
        if (!target || !decodes_at(image, dispatch.context, target->address, stop)) {
            site.complete = false;
            site.incomplete_reason = bound
                ? "table entry is unreadable, unresolved, or not executable PPC32 code"
                : "unguarded table prefix ended at an unreadable, unresolved, or non-executable PPC32 entry";
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), target->address, target->source,
                              target->relocation_rows, target->dyld_classic_rows, target->dyld_chained_rows});
    }
    if (!bound && site.cases.size() == max_entries) {
        site.complete = false;
        site.incomplete_reason = "unguarded PPC32 table prefix reached the 4096-entry scan cap";
    }
    return site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1)
        ? std::optional<SwitchSite>(std::move(site)) : std::nullopt;
}

std::optional<SwitchSite> riscv_indexed_relative_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, const RelocationResolver *relocations,
    std::stop_token stop) {
    // AUIPC Xbase[, ADDI Xbase, Xbase, lo]; SLLI Xindex, Xselector, 1|2;
    // ADD Xaddress, Xbase, Xindex; LH|LW Xoffset, 0(Xaddress);
    // ADD Xtarget, Xbase, Xoffset; JALR X0, 0(Xtarget).
    // LH/LW sign-extend 16/32-bit byte displacements before the target ADD.
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
    const bool halfword_offsets = load_instruction.opcode == Opcode::rv_lh;
    const std::uint64_t entry_bytes = halfword_offsets ? 2 : 4;
    const std::uint64_t scale_shift = halfword_offsets ? 1 : 2;
    const bool rv32 = branch_instruction.context.architecture == Architecture::riscv32 &&
                      branch_instruction.context.mode == ExecutionMode::rv32;
    const bool rv64 = branch_instruction.context.architecture == Architecture::riscv64 &&
                      branch_instruction.context.mode == ExecutionMode::rv64;
    const unsigned xlen = rv32 ? 32u : rv64 ? 64u : 0u;
    if (xlen == 0 || branch_instruction.opcode != Opcode::rv_jalr || branch_instruction.flow != FlowKind::jump ||
        target_instruction.opcode != Opcode::rv_add ||
        (load_instruction.opcode != Opcode::rv_lw && !halfword_offsets) ||
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
    const auto gpr = [xlen](const RegisterOperand *reg) {
        return reg && reg->bank == RegisterBank::riscv_gpr && reg->width == xlen && reg->index != 0;
    };
    if (!branch_destination || branch_destination->bank != RegisterBank::riscv_gpr ||
        branch_destination->width != xlen || branch_destination->index != 0 ||
        !branch_memory || !target_destination || !target_left || !target_right ||
        !gpr(target_destination) || !gpr(loaded_offset) || !load_memory ||
        !gpr(address_destination) || !address_left || !address_right ||
        !gpr(scaled_index) || !gpr(selector) ||
        !amount || amount->encoded_width != (xlen == 32 ? 5 : 6) || amount->effective_width != xlen ||
        amount->is_signed || amount->value != scale_shift ||
        !same_register(branch_memory->base ? &*branch_memory->base : nullptr, target_destination) ||
        branch_memory->segment || branch_memory->index || branch_memory->ip_relative ||
        branch_memory->displacement != 0 || branch_memory->address_width != xlen ||
        !same_register(load_memory->base ? &*load_memory->base : nullptr, address_destination) ||
        load_memory->segment || load_memory->index || load_memory->ip_relative ||
        load_memory->displacement != 0 || load_memory->address_width != xlen ||
        load_memory->data_width != entry_bytes * 8)
        return {};

    const auto *base = same_register(target_left, loaded_offset) ? target_right
        : same_register(target_right, loaded_offset) ? target_left : nullptr;
    if (!gpr(base) || same_register(base, selector) || same_register(base, scaled_index) ||
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
    site.scale = static_cast<std::uint8_t>(entry_bytes);
    site.entry_encoding = halfword_offsets ? SwitchEntryEncoding::signed_halfword_offset_from_table
                                          : SwitchEntryEncoding::signed_offset_from_table;
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
        const auto target = table_target(image, site.table, index, entry_bytes, true, relocations, stop, {}, xlen);
        if (!target || target->address.space != branch_instruction.address.space ||
            (xlen == 32 && target->address.offset > std::numeric_limits<std::uint32_t>::max()) ||
            !decodes_at(image, branch_instruction.context, target->address, stop)) {
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
    // The table bytes begin after the 32-bit instruction. The architectural
    // PC value used as the branch target base is word-aligned independently;
    // for a dispatch at address 2 mod 4 it is two bytes before the table.
    const auto table = add_offset(dispatch.address, 4, image);
    const auto pc_value = add_offset(dispatch.address, 4, image);
    const auto target_base = pc_value
        ? std::optional<Address>(Address{pc_value->space, pc_value->offset & ~UINT64_C(3)})
        : std::optional<Address>{};
    if (!table || !target_base || !file_backed_range(image, *table, entry_width, false))
        return {};

    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *table;
    site.target_base = *target_base;
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
        const auto target = add_offset(*site.target_base, *displacement * 2, image);
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

std::optional<SwitchSite> a32_pc_indexed_ldr_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, std::stop_token stop) {
    if (dispatch_index >= facts.size() || !facts[dispatch_index] || stop.stop_requested())
        return {};
    const auto &dispatch = facts[dispatch_index]->instruction;
    if (dispatch.context.architecture != Architecture::arm || dispatch.context.mode != ExecutionMode::a32 ||
        dispatch.opcode != Opcode::a32_ldr || dispatch.flow != FlowKind::jump || dispatch.condition != 14 ||
        dispatch.operands.size() != 2 || !dispatch.arm || !dispatch.arm->writes_pc)
        return {};
    const auto *destination = register_operand(dispatch, 0);
    const auto *memory = std::get_if<ArmMemoryOperand>(&dispatch.operands[1]);
    const auto *offset = memory ? std::get_if<ArmShiftedRegisterOperand>(&memory->offset) : nullptr;
    if (!destination || destination->bank != RegisterBank::arm32_gpr || destination->index != 15 ||
        destination->width != 32 || !memory || memory->base.bank != RegisterBank::arm32_gpr ||
        memory->base.index != 15 || memory->base.width != 32 || !offset ||
        offset->source.bank != RegisterBank::arm32_gpr || offset->source.index == 15 ||
        offset->source.width != 32 || offset->shift != ArmShift::lsl || offset->amount != 2 ||
        offset->amount_register || !memory->add || !memory->pre_index || memory->writeback ||
        memory->data_width != 32 || memory->sign_extend || memory->resolved_address)
        return {};

    // In A32, the architectural PC operand is the current instruction address
    // plus eight. This exact unshifted-register variant reads a contiguous
    // array of 32-bit absolute ARM destinations. Bit-zero interworking entries
    // are intentionally rejected; proving mixed-mode target contexts needs a
    // separate mode-aware CFG treatment.
    const auto table = add_offset(dispatch.address, 8, image);
    if (!table || !file_backed_range(image, *table, 4, false))
        return {};
    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *table;
    site.selector = offset->source;
    site.scale = 4;
    site.entry_encoding = SwitchEntryEncoding::absolute_pointer;
    if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector,
                                               dispatch.address, dispatch.address, dispatch.context, guards, stop)) {
        site.case_count = bound->case_count;
        site.default_target = bound->default_target;
    }
    const auto scan_limit = site.case_count ? *site.case_count : max_entries;
    for (std::size_t index = 0; index < scan_limit; ++index) {
        if (stop.stop_requested())
            return {};
        const auto raw = unsigned_table_entry(image, site.table, index, 4);
        if (!raw || (*raw & 3) != 0) {
            site.complete = false;
            break;
        }
        const Address target{dispatch.address.space, *raw};
        if (!decodes_at(image, dispatch.context, target, stop)) {
            site.complete = false;
            break;
        }
        site.cases.push_back({static_cast<std::uint32_t>(index), target});
    }
    if (!site.case_count && site.cases.size() == max_entries)
        site.complete = false;
    return site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1)
        ? std::optional<SwitchSite>(std::move(site)) : std::nullopt;
}

std::optional<SwitchSite> a32_pc_add_branch_table_switch(
    const Image &image, const FunctionRecord &function, const FunctionSnapshot &snapshot,
    const std::vector<std::shared_ptr<const InstructionFact>> &facts,
    std::size_t dispatch_index, SwitchGuardContext &guards, std::stop_token stop) {
    if (dispatch_index >= facts.size() || !facts[dispatch_index] || stop.stop_requested())
        return {};
    const auto &dispatch = facts[dispatch_index]->instruction;
    if (dispatch.context.architecture != Architecture::arm || dispatch.context.mode != ExecutionMode::a32 ||
        dispatch.opcode != Opcode::a32_add || dispatch.flow != FlowKind::jump || dispatch.condition != 14 ||
        dispatch.operands.size() != 3 || !dispatch.arm || !dispatch.arm->writes_pc ||
        dispatch.arm->flags_written != 0)
        return {};
    const auto *destination = register_operand(dispatch, 0);
    const auto *base = register_operand(dispatch, 1);
    const auto *indexed = std::get_if<ArmShiftedRegisterOperand>(&dispatch.operands[2]);
    if (!destination || destination->bank != RegisterBank::arm32_gpr || destination->index != 15 ||
        destination->width != 32 || !base || base->bank != RegisterBank::arm32_gpr || base->index != 15 ||
        base->width != 32 || !indexed || indexed->source.bank != RegisterBank::arm32_gpr ||
        indexed->source.index == 15 || indexed->source.width != 32 || indexed->source.high_byte ||
        indexed->shift != ArmShift::lsl || indexed->amount != 2 || indexed->amount_register)
        return {};

    // ADD pc, pc, Rm, LSL #2 indexes an inline array of A32 B instructions.
    // Scan only when the CFG guard proves the exact number of branch entries.
    const auto table = add_offset(dispatch.address, 8, image);
    if (!table || !file_backed_range(image, *table, 4, true))
        return {};
    SwitchSite site;
    site.dispatch = dispatch.address;
    site.table = *table;
    site.selector = indexed->source;
    site.scale = 4;
    site.entry_encoding = SwitchEntryEncoding::a32_branch_instruction;
    const auto bound = guarded_case_bound(image, function, snapshot, site.selector,
                                           dispatch.address, dispatch.address, dispatch.context, guards, stop);
    if (stop.stop_requested())
        return {};
    if (!bound || bound->case_count == 0 || bound->case_count > max_entries)
        return {};
    site.case_count = bound->case_count;
    site.default_target = bound->default_target;
    for (std::uint32_t index = 0; index < bound->case_count; ++index) {
        if (stop.stop_requested())
            return {};
        const auto entry = add_offset(*table, static_cast<std::uint64_t>(index) * 4, image);
        if (!entry || !file_backed_range(image, *entry, 4, true)) {
            site.complete = false;
            break;
        }
        const auto bytes = image.read(*entry, 4);
        if (!bytes || bytes.value().size() != 4) {
            site.complete = false;
            break;
        }
        const auto decoded = decode_instruction(dispatch.context, bytes.value(), *entry);
        if (decoded.status != DecodeStatus::decoded || !decoded.instruction ||
            decoded.instruction->length != 4 || decoded.instruction->opcode != Opcode::a32_b ||
            decoded.instruction->condition != 14 || decoded.instruction->flow != FlowKind::jump ||
            !decoded.instruction->direct_target || !decodes_at(image, dispatch.context,
                                                                 *decoded.instruction->direct_target, stop)) {
            site.complete = false;
            break;
        }
        site.cases.push_back({index, *decoded.instruction->direct_target});
    }
    if (site.cases.size() != bound->case_count)
        site.complete = false;
    return site.cases.size() >= 2 || (site.case_count && site.cases.size() == 1)
        ? std::optional<SwitchSite>(std::move(site)) : std::nullopt;
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
            if (instruction.context.architecture == Architecture::dex && instruction.opcode == Opcode::dex_switch &&
                instruction.dex_switch) {
                auto decoded = instruction;
                auto populated = function_detail::populate_dex_switch_table(image, decoded, nullptr, stop);
                if (!populated)
                    return populated.error();
                if (!populated.value() || !decoded.dex_switch || !decoded.dex_switch->validated)
                    continue;
                const auto selector = std::find_if(decoded.operands.begin(), decoded.operands.end(), [](const auto &operand) {
                    const auto *reg = std::get_if<RegisterOperand>(&operand);
                    return reg && reg->bank == RegisterBank::dex_vreg;
                });
                if (selector == decoded.operands.end())
                    continue;
                const auto *selector_reg = std::get_if<RegisterOperand>(&*selector);
                SwitchSite site;
                site.dispatch = instruction.address;
                site.table = decoded.dex_switch->payload;
                site.selector = *selector_reg;
                site.selector_use = instruction.address;
                site.entry_encoding = SwitchEntryEncoding::decoded_metadata;
                site.table_base_source = SwitchSite::TableBaseSource::encoded_bytes;
                site.case_count = static_cast<std::uint32_t>(decoded.dex_switch->cases.size());
                const auto fallthrough = analysis_detail::continuation_address(instruction);
                if (fallthrough)
                    site.default_target = fallthrough.value();
                for (const auto &item : decoded.dex_switch->cases)
                    site.cases.push_back({static_cast<std::uint32_t>(item.value), item.target});
                result.sites.push_back(std::move(site));
                continue;
            }
            if (instruction.context.architecture == Architecture::powerpc &&
                instruction.context.mode == ExecutionMode::ppc32 && instruction.opcode == Opcode::ppc_bcctr &&
                instruction.flow == FlowKind::jump) {
                auto ppc_switch = ppc32_register_absolute_switch(image, function, snapshot,
                    found->second->instructions, fact_index, guards, relocations, stop);
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Switch analysis canceled"};
                if (ppc_switch) {
                    result.complete = result.complete && ppc_switch->complete;
                    result.sites.push_back(std::move(*ppc_switch));
                }
                continue;
            }
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
            const bool riscv32_jalr = instruction.context.architecture == Architecture::riscv32 &&
                instruction.context.mode == ExecutionMode::rv32;
            const bool riscv64_jalr = instruction.context.architecture == Architecture::riscv64 &&
                instruction.context.mode == ExecutionMode::rv64;
            if ((riscv32_jalr || riscv64_jalr) && instruction.opcode == Opcode::rv_jalr &&
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
            if (instruction.context.architecture == Architecture::arm &&
                instruction.context.mode == ExecutionMode::a32 && instruction.opcode == Opcode::a32_add &&
                instruction.flow == FlowKind::jump) {
                auto arm_switch = a32_pc_add_branch_table_switch(image, function, snapshot,
                    found->second->instructions, fact_index, guards, stop);
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Switch analysis canceled"};
                if (arm_switch) {
                    result.complete = result.complete && arm_switch->complete;
                    result.sites.push_back(std::move(*arm_switch));
                }
                continue;
            }
            if (instruction.context.architecture == Architecture::arm &&
                instruction.context.mode == ExecutionMode::a32 && instruction.opcode == Opcode::a32_ldr &&
                instruction.flow == FlowKind::jump) {
                auto arm_switch = a32_pc_indexed_ldr_switch(image, function, snapshot,
                    found->second->instructions, fact_index, guards, stop);
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Switch analysis canceled"};
                if (arm_switch) {
                    result.complete = result.complete && arm_switch->complete;
                    result.sites.push_back(std::move(*arm_switch));
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
                auto register_loaded = register_loaded_absolute_switch(
                    image, function, snapshot, found->second->instructions, fact_index, guards, relocations, stop);
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Switch analysis canceled"};
                if (register_loaded) {
                    result.complete = result.complete && register_loaded->complete;
                    result.sites.push_back(std::move(*register_loaded));
                    continue;
                }
                auto x86_32_relative = x86_32_signed_word_register_base_switch(
                    image, function, snapshot, found->second->instructions, fact_index, guards, relocations, stop);
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Switch analysis canceled"};
                if (x86_32_relative) {
                    result.complete = result.complete && x86_32_relative->complete;
                    result.sites.push_back(std::move(*x86_32_relative));
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
            const Instruction *x86_16_scale = nullptr;
            if (instruction.context.mode == ExecutionMode::x86_16 && pointer_width == 16 &&
                table_memory->data_width == 16 && table_memory->address_width == 16 &&
                table_memory->scale == 1 && table_memory->index && !table_memory->base &&
                !table_memory->segment && !table_memory->ip_relative && fact_index > 0 &&
                found->second->instructions[fact_index - 1]) {
                const auto &scale = found->second->instructions[fact_index - 1]->instruction;
                const auto *destination = register_operand(scale, 0);
                const auto *amount = scale.operands.size() == 2
                    ? std::get_if<ImmediateOperand>(&scale.operands[1]) : nullptr;
                const auto scale_end = analysis_detail::continuation_address(scale);
                if (scale.context == instruction.context && scale.opcode == Opcode::shl &&
                    scale.flow == FlowKind::fallthrough && scale.operands.size() == 2 &&
                    scale_end && scale_end.value() == instruction.address && destination &&
                    same_register(destination, &*table_memory->index) &&
                    destination->bank == RegisterBank::gpr && destination->width == 16 &&
                    !destination->high_byte && amount && amount->value == 1)
                    x86_16_scale = &scale;
            }
            const bool relative_offsets = instruction.context.mode == ExecutionMode::x86_64 &&
                                          table_memory->ip_relative && table_memory->scale == 4;
            const std::size_t entry_bytes = x86_16_scale ? 2 : relative_offsets ? 4 : pointer_bytes;
            if (!entry_bytes || table_memory->data_width != pointer_width ||
                (table_memory->scale != entry_bytes && !x86_16_scale))
                continue;

            SwitchSite site;
            site.dispatch = instruction.address;
            if (!table_base)
                continue;
            site.table = *table_base;
            site.selector = *table_memory->index;
            site.selector_use = x86_16_scale ? std::optional<Address>{x86_16_scale->address}
                                             : std::optional<Address>{};
            site.scale = static_cast<std::uint8_t>(entry_bytes);
            if (relative_offsets)
                site.entry_encoding = SwitchEntryEncoding::signed_offset_from_table;
            if (const auto bound = guarded_case_bound(image, function, snapshot, site.selector,
                    x86_16_scale ? x86_16_scale->address : instruction.address,
                    instruction.address, instruction.context, guards, stop)) {
                site.case_count = bound->case_count;
                site.default_target = bound->default_target;
            }
            const auto strict_scan = !relative_offsets && entry_bytes == 8
                ? scan_static_elf_absolute_table(image, site.table, site.case_count.value_or(0),
                                                  instruction.context, relocations, metadata, stop)
                : ElfRelocationTableScan{};
            if (strict_scan.reject_unbounded)
                continue;
            if (strict_scan.applicable) {
                site.cases = strict_scan.cases;
                site.complete = strict_scan.complete;
                if (!site.complete)
                    site.incomplete_reason = "ELF absolute-pointer table has an incomplete or unsupported relocation prefix";
            } else {
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
            }
            if (site.cases.size() >= 2 || (site.case_count && (site.cases.size() == 1 || !site.complete))) {
                result.complete = result.complete && site.complete;
                result.sites.push_back(std::move(site));
            }
        }
    }
    // Each target is checked for decodability when its table entry is read,
    // but individually decodable starts can still overlap one another or the
    // encoded table bytes. Keep only the verified table prefix before the
    // first conflicting instruction extent.
    constexpr std::size_t target_overlap_work_budget = 1'000'000;
    std::size_t target_overlap_work = target_overlap_work_budget;
    for (auto &site : result.sites) {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "Switch target-overlap validation canceled"};
        if (site.entry_encoding == SwitchEntryEncoding::decoded_metadata || !site.scale)
            continue;
        const auto context = image.context_at(site.dispatch);
        if (!context) {
            site.complete = false;
            if (!site.incomplete_reason)
                site.incomplete_reason = "switch dispatch context is unavailable for target-overlap validation";
            result.complete = false;
            continue;
        }
        const auto table_entries = site.case_count.value_or(static_cast<std::uint32_t>(site.cases.size()));
        bool table_range_valid = table_entries <= max_entries &&
            table_entries <= UINT64_MAX / site.scale;
        const auto table_bytes = table_range_valid ? std::uint64_t{table_entries} * site.scale : 0;
        table_range_valid = table_range_valid && table_bytes <= UINT64_MAX - site.table.offset;
        const auto table_end = table_range_valid ? site.table.offset + table_bytes : 0;
        if (!table_range_valid) {
            site.complete = false;
            if (!site.incomplete_reason)
                site.incomplete_reason = "switch table extent overflows or exceeds its case bound";
        }

        std::map<GuardAddress, std::uint64_t> decoded_ranges;
        std::size_t case_index = 0;
        while (case_index < site.cases.size()) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "Switch target-overlap validation canceled"};
            if (!target_overlap_work) {
                site.complete = false;
                if (!site.incomplete_reason)
                    site.incomplete_reason = "switch target-overlap validation reached its work limit";
                break;
            }
            --target_overlap_work;
            const auto &item = site.cases[case_index];
            const auto end = decoded_instruction_end(image, context.value(), item.target, stop);
            if (!end || end->space != item.target.space) {
                site.complete = false;
                if (!site.incomplete_reason)
                    site.incomplete_reason = "switch case target instruction extent is not file-backed executable code";
                site.cases.resize(case_index);
                break;
            }
            bool overlap = table_range_valid && item.target.space == site.table.space &&
                item.target.offset < table_end && end->offset > site.table.offset;
            const auto key = guard_address(item.target);
            const auto next = decoded_ranges.lower_bound(key);
            if (next != decoded_ranges.end() && next->first == key) {
                // Multiple case values may intentionally share one block.
                overlap = overlap || next->second != end->offset;
            } else {
                if (next != decoded_ranges.end() && next->first.first == key.first &&
                    next->first.second < end->offset)
                    overlap = true;
                if (next != decoded_ranges.begin()) {
                    const auto previous = std::prev(next);
                    if (previous->first.first == key.first && previous->second > item.target.offset)
                        overlap = true;
                }
            }
            if (overlap) {
                site.complete = false;
                if (!site.incomplete_reason)
                    site.incomplete_reason = "switch case instruction overlaps another target or its table bytes";
                site.cases.resize(case_index);
                break;
            }
            decoded_ranges.emplace(key, end->offset);
            ++case_index;
        }
        result.complete = result.complete && site.complete;
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
