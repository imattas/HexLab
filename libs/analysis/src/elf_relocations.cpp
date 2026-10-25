#include "hexlab/analysis/elf_relocations.hpp"
#include "hexlab/analysis/relocations.hpp"
#include "control_target.hpp"
#include "a64_fields.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <map>
#include <tuple>
namespace hexlab {
namespace {
struct Failure {
    Error error;
};
void require(bool condition, const char *message, ErrorCode code = ErrorCode::malformed) {
    if (!condition)
        throw Failure{{code, message}};
}
void canceled(std::stop_token stop) {
    require(!stop.stop_requested(), "ELF relocation resolution canceled", ErrorCode::canceled);
}
template <class F> auto guarded(F operation) -> decltype(operation()) {
    try {
        return operation();
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate ELF relocation index"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "ELF relocation index exceeds allocation limits"};
    }
}
using SourceKey = std::tuple<std::optional<std::uint32_t>, std::uint64_t, bool, std::uint32_t, std::uint64_t>;
SourceKey key(const ElfTableSource &source) {
    return {source.section, source.file_offset, bool(source.address), source.address ? source.address->space.value : 0,
            source.address ? source.address->offset : 0};
}
enum class Use { absolute, pc_relative, register_based, far_pointer, symbolic_data };
struct Field {
    EncodedField bytes;
    Use use;
    unsigned target_width = 64;
};
std::optional<std::uint64_t> sum(std::uint64_t base, std::int64_t addend, std::uint64_t bias, unsigned width) {
    if (width < 64) {
        const auto mask = (UINT64_C(1) << width) - 1;
        return (base + static_cast<std::uint64_t>(addend) + bias) & mask;
    }
    if (addend < 0) {
        const auto magnitude = static_cast<std::uint64_t>(-(addend + 1)) + 1;
        if (magnitude > bias) {
            const auto subtract = magnitude - bias;
            if (subtract > base)
                return {};
            return base - subtract;
        }
        bias -= magnitude;
    } else {
        const auto positive = static_cast<std::uint64_t>(addend);
        if (bias > UINT64_MAX - positive)
            return {};
        bias += positive;
    }
    if (bias > UINT64_MAX - base)
        return {};
    return base + bias;
}
} // namespace
struct ElfRelocationResolver::State {
    struct Entry {
        std::uint64_t begin, end, subtree_end, index;
    };
    const ElfMetadata *metadata = nullptr;
    std::map<std::uint32_t, std::vector<Entry>> domains;
    std::vector<Entry> files;
    std::map<SourceKey, const ElfSymbolTable *> symbols;
    std::vector<bool> retained;
    mutable std::atomic<std::uint64_t> work_left{64 * 1024 * 1024};
    std::uint32_t max_matches = 4096;
    void charge() const {
        auto remaining = work_left.load(std::memory_order_relaxed);
        for (;;) {
            require(remaining != 0, "ELF relocation lookup work budget exhausted", ErrorCode::resource_limit);
            if (work_left.compare_exchange_weak(remaining, remaining - 1, std::memory_order_relaxed))
                return;
        }
    }
    void query_entries(const std::vector<Entry> &entries, std::uint64_t begin, std::uint64_t size,
                       std::vector<std::uint64_t> &rows, std::stop_token stop) const {
        require(size <= UINT64_MAX - begin, "ELF operand field address overflow", ErrorCode::overflow);
        const auto end = begin + size;
        const auto visit = [&](auto &&self, std::size_t first, std::size_t last) -> void {
            if (first == last)
                return;
            canceled(stop);
            charge();
            const auto middle = first + (last - first) / 2;
            const auto &entry = entries[middle];
            if (entry.subtree_end <= begin || entries[first].begin >= end)
                return;
            self(self, first, middle);
            if (entry.begin < end && entry.end > begin) {
                require(rows.size() < max_matches, "ELF relocation match budget exhausted", ErrorCode::resource_limit);
                rows.push_back(entry.index);
            }
            if (entry.begin < end)
                self(self, middle + 1, last);
        };
        visit(visit, 0, entries.size());
    }
    void query(Address begin, std::uint64_t size, std::vector<std::uint64_t> &rows, std::stop_token stop) const {
        const auto found = domains.find(begin.space.value);
        if (found != domains.end())
            query_entries(found->second, begin.offset, size, rows, stop);
    }
    static void build(std::vector<Entry> &entries, std::stop_token stop) {
        std::sort(entries.begin(), entries.end(), [stop](const auto &a, const auto &b) {
            canceled(stop);
            return std::tie(a.begin, a.index) < std::tie(b.begin, b.index);
        });
        const auto subtree = [&](auto &&self, std::size_t first, std::size_t last) -> std::uint64_t {
            if (first == last)
                return 0;
            canceled(stop);
            const auto middle = first + (last - first) / 2;
            const auto left = self(self, first, middle), right = self(self, middle + 1, last);
            return entries[middle].subtree_end = std::max({entries[middle].end, left, right});
        };
        (void)subtree(subtree, 0, entries.size());
    }
    const ElfSymbol *symbol(std::uint64_t index) const noexcept {
        if (!metadata || index >= metadata->relocations.size())
            return nullptr;
        const auto &row = metadata->relocations[static_cast<std::size_t>(index)];
        if (!row.symbol_index_validated || !row.symbol_table)
            return nullptr;
        const auto found = symbols.find(key(*row.symbol_table));
        if (found == symbols.end() || !found->second->count || !found->second->symbol_begin ||
            row.symbol_index >= *found->second->count)
            return nullptr;
        return &metadata->symbols[static_cast<std::size_t>(*found->second->symbol_begin + row.symbol_index)];
    }
    ElfOperandResolution solve(ElfOperandResolution output, Use use, std::uint64_t bias, unsigned width) const {
        const auto unresolved = [&](ElfResolutionReason reason) {
            output.reason = reason;
            return std::move(output);
        };
        if (output.relocations.empty())
            return output;
        if (output.relocations.size() != 1)
            return unresolved(ElfResolutionReason::ambiguous);
        const auto index = output.relocations[0];
        const auto &row = metadata->relocations[static_cast<std::size_t>(index)];
        if (retained[static_cast<std::size_t>(index)])
            return unresolved(ElfResolutionReason::unsupported);
        const bool absolute = row.kind == ElfRelocationKind::absolute, pc = row.kind == ElfRelocationKind::pc_relative;
        if (!row.field_size || !*row.field_size || (!absolute && !pc) ||
            (use != Use::symbolic_data && ((absolute && use != Use::absolute) || (pc && use != Use::pc_relative))))
            return unresolved(ElfResolutionReason::unsupported);
        const auto *definition = symbol(index);
        if (!definition)
            return unresolved(ElfResolutionReason::unavailable_symbol);
        if (definition->state == ElfSymbolState::undefined)
            return unresolved(ElfResolutionReason::undefined_symbol);
        if (definition->type > 3 || definition->binding > 2 || definition->visibility > 3)
            return unresolved(ElfResolutionReason::unsupported);
        if (metadata->header.object_type == 3 && definition->binding != 0 && definition->visibility == 0)
            return unresolved(ElfResolutionReason::preemptible_symbol);
        auto target = definition->address;
        if (!target && definition->state == ElfSymbolState::absolute && metadata->header.object_type != 1)
            target = Address{{0}, definition->value};
        if (!target)
            return unresolved(ElfResolutionReason::symbol_not_address);
        if (!row.addend)
            return unresolved(ElfResolutionReason::unavailable_addend);
        require(width == 16 || width == 32 || width == 64, "Invalid ELF reference address width",
                ErrorCode::invalid_argument);
        // Absolute expressions are pointer-width bit patterns. In particular,
        // a valid32S result may be a negative64-bit constant. PC relationships
        // retain checked address-domain arithmetic rather than inventing a wrap.
        const auto mask = width == 64 ? UINT64_MAX : (UINT64_C(1) << width) - 1;
        const auto result =
            absolute ? std::optional<std::uint64_t>{(target->offset + static_cast<std::uint64_t>(*row.addend)) & mask}
                     : sum(target->offset, *row.addend, bias, width);
        if (!result)
            return unresolved(ElfResolutionReason::overflow);
        if (metadata->header.machine == 62 && absolute && (row.type == 10 || row.type == 11)) {
            const auto bits = static_cast<unsigned>(*row.field_size * 8);
            const auto mask = (UINT64_C(1) << bits) - 1;
            const auto low = *result & mask;
            const auto extended = row.type == 11 && (low & (UINT64_C(1) << (bits - 1))) ? (low | ~mask) : low;
            if (extended != *result)
                return unresolved(ElfResolutionReason::overflow);
        }
        target->offset = *result;
        output.reason = ElfResolutionReason::resolved;
        output.address = target;
        return output;
    }
};
Result<ElfRelocationResolver> ElfRelocationResolver::create(const ImageMetadata &metadata, std::stop_token stop) {
    return create(metadata, ElfResolutionLimits{}, stop);
}
Result<ElfRelocationResolver> ElfRelocationResolver::create(const ImageMetadata &metadata, ElfResolutionLimits limits,
                                                            std::stop_token stop) {
    return guarded([&]() -> Result<ElfRelocationResolver> {
        canceled(stop);
        require(limits.lookup_work && limits.lookup_work <= 64 * 1024 * 1024 && limits.max_matches &&
                    limits.max_matches <= 4096,
                "ELF resolution limits exceed supported bounds", ErrorCode::invalid_argument);
        auto state = std::make_shared<State>();
        state->work_left.store(limits.lookup_work);
        state->max_matches = limits.max_matches;
        if (!metadata.elf)
            return ElfRelocationResolver{std::move(state)};
        const auto &elf = *metadata.elf;
        state->metadata = &elf;
        require(elf.relocations.size() <= 1000000 && elf.symbol_tables.size() <= 1000000,
                "ELF relocation analysis record limit exceeded", ErrorCode::resource_limit);
        for (const auto &table : elf.symbol_tables) {
            canceled(stop);
            require(table.count.has_value() == table.symbol_begin.has_value(),
                    "ELF symbol bound/row availability differs");
            if (table.count)
                require(*table.symbol_begin <= elf.symbols.size() &&
                            *table.count <= elf.symbols.size() - *table.symbol_begin,
                        "ELF symbol index exceeds canonical rows");
            require(state->symbols.emplace(key(table.source), &table).second, "Duplicate ELF symbol namespace");
        }
        state->retained.resize(elf.relocations.size());
        for (std::uint64_t index = 0; index < elf.relocations.size(); ++index) {
            canceled(stop);
            const auto &row = elf.relocations[static_cast<std::size_t>(index)];
            const bool retained = elf.header.object_type != 1 && row.target_section && row.source.section &&
                                  *row.source.section < elf.sections.size() &&
                                  !(elf.sections[*row.source.section].flags & 2) && row.symbol_table &&
                                  row.symbol_table->section && *row.symbol_table->section < elf.sections.size() &&
                                  elf.sections[*row.symbol_table->section].type == 2;
            state->retained[static_cast<std::size_t>(index)] = retained;
            // Preserve raw provenance, but let the decoder describe linked
            // operands. A retained record must never override their bytes.
            if (retained)
                continue;
            if (row.kind == ElfRelocationKind::none || row.field_size == 0)
                continue;
            const auto size = row.field_size.value_or(1);
            if (row.place) {
                require(size <= UINT64_MAX - row.place->offset, "ELF relocation interval overflow",
                        ErrorCode::overflow);
                state->domains[row.place->space.value].push_back(
                    {row.place->offset, row.place->offset + size, 0, index});
            }
            if (row.file_place) {
                require(size <= UINT64_MAX - row.file_place->value, "ELF file relocation interval overflow",
                        ErrorCode::overflow);
                state->files.push_back({row.file_place->value, row.file_place->value + size, 0, index});
            }
        }
        for (auto &[domain, entries] : state->domains)
            State::build(entries, stop);
        State::build(state->files, stop);
        return ElfRelocationResolver{std::move(state)};
    });
}
Result<ElfOperandResolution> ElfRelocationResolver::operand(const Instruction &instruction, std::uint32_t index,
                                                            std::stop_token stop) const {
    return guarded([&]() -> Result<ElfOperandResolution> {
        canceled(stop);
        ElfOperandResolution output;
        if (state_->domains.empty())
            return output;
        require(index < instruction.operands.size(), "ELF operand index exceeds decoded instruction",
                ErrorCode::invalid_argument);
        require(instruction.length && instruction.length <= 15, "Invalid decoded instruction extent",
                ErrorCode::invalid_argument);
        if (instruction.context.mode == ExecutionMode::a64) {
            if (!analysis_detail::a64_packed_operand(instruction, index))
                return output;
            state_->query(instruction.address, 4, output.relocations, stop);
            if (output.relocations.empty())
                return output;
            output.reason =
                output.relocations.size() == 1 ? ElfResolutionReason::unsupported : ElfResolutionReason::ambiguous;
            if (output.relocations.size() != 1)
                return output;
            const auto &row = state_->metadata->relocations[output.relocations.front()];
            const bool branch = (instruction.opcode == Opcode::a64_bl && row.type == 283) ||
                                (instruction.opcode == Opcode::a64_b && row.type == 282);
            if (!branch || state_->metadata->header.machine != 183 || !state_->metadata->header.is_64 ||
                state_->metadata->header.order != ByteOrder::little || !row.explicit_addend ||
                row.place != instruction.address || row.field_size != 4)
                return output;
            auto solved = state_->solve(std::move(output), Use::pc_relative, 0, 64);
            if (solved.address && (solved.address->offset & 3)) {
                solved.address.reset();
                solved.reason = ElfResolutionReason::field_mismatch;
            }
            return solved;
        }
        std::array<Field, 2> fields{};
        std::size_t count = 0;
        const auto append = [&](const std::optional<EncodedField> &bytes, Use use, unsigned width) {
            if (!bytes)
                return;
            require(bytes->size && bytes->offset < instruction.length &&
                        bytes->size <= instruction.length - bytes->offset,
                    "Operand encoding exceeds original instruction", ErrorCode::invalid_argument);
            fields[count++] = {*bytes, use, width};
        };
        const auto memory = [&](const MemoryOperand &value) {
            const auto use = value.segment                 ? Use::register_based
                             : value.ip_relative           ? Use::pc_relative
                             : (value.base || value.index) ? Use::register_based
                                                           : Use::absolute;
            append(value.displacement_encoding, use, value.address_width);
        };
        const auto width = state_->metadata->header.is_64 ? 64u : 32u;
        std::visit(
            [&](const auto &value) {
                using T = std::decay_t<decltype(value)>;
                if constexpr (std::is_same_v<T, RelativeOperand>) {
                    require(bool(value.encoding), "Relative operand lacks decoded field coordinates",
                            ErrorCode::invalid_argument);
                    append(value.encoding, Use::pc_relative, value.effective_width ? value.effective_width : width);
                } else if constexpr (std::is_same_v<T, ImmediateOperand>)
                    append(value.encoding, Use::absolute, width);
                else if constexpr (std::is_same_v<T, MemoryOperand>)
                    memory(value);
                else if constexpr (std::is_same_v<T, FarMemoryOperand>)
                    memory(value.address);
                else if constexpr (std::is_same_v<T, FarPointerOperand>) {
                    append(value.offset_encoding, Use::far_pointer, width);
                    append(value.selector_encoding, Use::far_pointer, width);
                }
            },
            instruction.operands[index]);
        for (std::size_t i = 0; i < count; ++i) {
            const auto at = advance(instruction.address, fields[i].bytes.offset);
            if (!at)
                return at.error();
            state_->query(at.value(), fields[i].bytes.size, output.relocations, stop);
        }
        std::sort(output.relocations.begin(), output.relocations.end());
        output.relocations.erase(std::unique(output.relocations.begin(), output.relocations.end()),
                                 output.relocations.end());
        if (output.relocations.empty())
            return output;
        const auto unresolved = [&](ElfResolutionReason reason) -> Result<ElfOperandResolution> {
            output.reason = reason;
            return std::move(output);
        };
        if (output.relocations.size() != 1)
            return unresolved(ElfResolutionReason::ambiguous);
        const auto &row = state_->metadata->relocations[static_cast<std::size_t>(output.relocations[0])];
        const Field *field = nullptr;
        for (std::size_t i = 0; i < count; ++i)
            if (row.place == advance(instruction.address, fields[i].bytes.offset).value() &&
                row.field_size == fields[i].bytes.size)
                field = &fields[i];
        if (!row.field_size)
            return unresolved(ElfResolutionReason::unsupported);
        if (!field)
            return unresolved(ElfResolutionReason::field_mismatch);
        const auto bias = field->use == Use::pc_relative ? instruction.length - field->bytes.offset : 0;
        return state_->solve(std::move(output), field->use, bias, field->target_width);
    });
}
Result<ElfOperandResolution> ElfRelocationResolver::data(std::uint64_t index, std::stop_token stop) const {
    return guarded([&]() -> Result<ElfOperandResolution> {
        canceled(stop);
        require(state_->metadata && index < state_->metadata->relocations.size(), "Invalid raw ELF relocation index",
                ErrorCode::invalid_argument);
        const auto &row = state_->metadata->relocations[static_cast<std::size_t>(index)];
        ElfOperandResolution output;
        if (row.kind == ElfRelocationKind::none)
            return output;
        const auto size = row.field_size.value_or(1);
        if (size && row.place)
            state_->query(*row.place, size, output.relocations, stop);
        else if (size && row.file_place)
            state_->query_entries(state_->files, row.file_place->value, size, output.relocations, stop);
        if (output.relocations.empty())
            output.relocations.push_back(index);
        std::sort(output.relocations.begin(), output.relocations.end());
        return state_->solve(std::move(output), Use::symbolic_data, 0, state_->metadata->header.is_64 ? 64 : 32);
    });
}
Result<ElfOperandResolution> ElfRelocationResolver::data_at(Address place, std::optional<FileOffset> file_place,
                                                              std::uint8_t width, std::stop_token stop) const {
    return guarded([&]() -> Result<ElfOperandResolution> {
        canceled(stop);
        require(width && width <= 8, "Invalid ELF data slot width", ErrorCode::invalid_argument);
        ElfOperandResolution output;
        if (!state_->metadata)
            return output;
        state_->query(place, width, output.relocations, stop);
        if (file_place)
            state_->query_entries(state_->files, file_place->value, width, output.relocations, stop);
        std::sort(output.relocations.begin(), output.relocations.end());
        output.relocations.erase(std::unique(output.relocations.begin(), output.relocations.end()), output.relocations.end());
        if (output.relocations.empty())
            return output;
        for (const auto index : output.relocations) {
            const auto &row = state_->metadata->relocations[static_cast<std::size_t>(index)];
            const auto exact_virtual = row.place && *row.place == place;
            const auto exact_file = file_place && row.file_place && *row.file_place == *file_place;
            if ((!exact_virtual && !exact_file) || row.field_size.value_or(1) != width) {
                output.reason = ElfResolutionReason::unsupported;
                return output;
            }
        }
        return state_->solve(std::move(output), Use::symbolic_data, 0,
                             state_->metadata->header.is_64 ? 64 : 32);
    });
}
const ElfSymbol *ElfRelocationResolver::symbol(std::uint64_t index) const noexcept { return state_->symbol(index); }
Result<std::optional<Address>> ElfRelocationResolver::control_target(const Image &image, const Instruction &instruction,
                                                                     std::stop_token stop) const {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Control target resolution canceled"};
    if (!instruction.operands.empty()) {
        const auto relocated = operand(instruction, analysis_detail::control_operand_index(instruction), stop);
        if (!relocated)
            return relocated.error();
        if (relocated.value().relocated()) {
            if (std::holds_alternative<RelativeOperand>(
                    instruction.operands[analysis_detail::control_operand_index(instruction)]))
                return relocated.value().address;
            return std::optional<Address>{}; // A relocated pointer slot is not its stored control target.
        }
    }
    return analysis_detail::control_target(image, instruction);
}
Result<std::optional<Address>> resolve_control_target(const Image &image, const ImageMetadata &metadata,
                                                      const Instruction &instruction, std::stop_token stop) {
    auto resolver = RelocationResolver::create(image, metadata, stop);
    if (!resolver)
        return resolver.error();
    return resolver.value().control_target(image, instruction, stop);
}
} // namespace hexlab
