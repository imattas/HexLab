#include "hexlab/analysis/macho_relocations.hpp"
#include "control_target.hpp"
#include "a64_fields.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <map>
#include <tuple>
namespace hexlab {
namespace {
struct Failure {
    Error error;
};
void require(bool ok, const char *message, ErrorCode code = ErrorCode::malformed) {
    if (!ok)
        throw Failure{{code, message}};
}
void canceled(std::stop_token stop) {
    require(!stop.stop_requested(), "Mach-O relocation resolution canceled", ErrorCode::canceled);
}
template <class F> auto guarded(F operation) -> decltype(operation()) {
    try {
        return operation();
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate Mach-O relocation index"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Mach-O relocation allocation limit"};
    }
}
enum class Use { absolute, relative, memory_pc, register_based, symbolic_data, far_pointer };
struct Field {
    EncodedField bytes;
    Use use;
};
std::int64_t signed_bits(std::uint64_t bits, unsigned size) {
    const auto width = size * 8;
    if (width < 64) {
        const auto mask = (UINT64_C(1) << width) - 1;
        bits &= mask;
        if (bits & (UINT64_C(1) << (width - 1)))
            bits |= ~mask;
    }
    return std::bit_cast<std::int64_t>(bits);
}
std::optional<std::uint64_t> sum(std::uint64_t base, std::int64_t delta, std::uint64_t bias = 0) {
    if (delta < 0) {
        const auto magnitude = std::uint64_t(-(delta + 1)) + 1;
        if (magnitude > bias) {
            const auto subtract = magnitude - bias;
            return subtract <= base ? std::optional{base - subtract} : std::nullopt;
        }
        bias -= magnitude;
    } else {
        if (std::uint64_t(delta) > UINT64_MAX - bias)
            return {};
        bias += std::uint64_t(delta);
    }
    return bias <= UINT64_MAX - base ? std::optional{base + bias} : std::nullopt;
}
} // namespace
struct MachORelocationResolver::State {
    struct Interval {
        std::uint64_t begin, end, maximum, row;
    };
    const MachOMetadata *metadata = nullptr;
    std::map<std::uint32_t, std::vector<Interval>> domains;
    std::vector<Interval> files;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> encrypted_files;
    std::map<std::uint32_t, const MachOSymbolTable *> symbols;
    mutable std::atomic<std::uint64_t> work_left{0};
    std::uint32_t max_matches = 4096;
    void charge() const {
        auto left = work_left.load(std::memory_order_relaxed);
        for (;;) {
            require(left != 0, "Mach-O relocation lookup budget exhausted", ErrorCode::resource_limit);
            if (work_left.compare_exchange_weak(left, left - 1, std::memory_order_relaxed))
                return;
        }
    }
    static void build(std::vector<Interval> &items, std::stop_token stop) {
        std::sort(items.begin(), items.end(), [stop](const auto &a, const auto &b) {
            canceled(stop);
            return std::tie(a.begin, a.row) < std::tie(b.begin, b.row);
        });
        const auto mark = [&](auto &&self, std::size_t first, std::size_t last) -> std::uint64_t {
            if (first == last)
                return 0;
            canceled(stop);
            const auto middle = first + (last - first) / 2;
            return items[middle].maximum =
                       std::max({items[middle].end, self(self, first, middle), self(self, middle + 1, last)});
        };
        (void)mark(mark, 0, items.size());
    }
    void query(const std::vector<Interval> &items, std::uint64_t begin, std::uint64_t size,
               std::vector<std::uint64_t> &rows, std::stop_token stop) const {
        require(size <= UINT64_MAX - begin, "Mach-O field extent overflow", ErrorCode::overflow);
        const auto end = begin + size;
        const auto visit = [&](auto &&self, std::size_t first, std::size_t last) -> void {
            if (first == last)
                return;
            canceled(stop);
            charge();
            const auto middle = first + (last - first) / 2;
            const auto &item = items[middle];
            if (item.maximum <= begin || items[first].begin >= end)
                return;
            self(self, first, middle);
            if (item.begin < end && item.end > begin) {
                require(rows.size() < max_matches, "Mach-O relocation match limit", ErrorCode::resource_limit);
                rows.push_back(item.row);
            }
            if (item.begin < end)
                self(self, middle + 1, last);
        };
        visit(visit, 0, items.size());
    }
    void query(Address begin, std::uint64_t size, std::vector<std::uint64_t> &rows, std::stop_token stop) const {
        const auto found = domains.find(begin.space.value);
        if (found != domains.end())
            query(found->second, begin.offset, size, rows, stop);
    }
    const MachOSymbol *symbol(std::uint64_t index) const noexcept {
        if (!metadata || index >= metadata->relocations.size())
            return nullptr;
        const auto &row = metadata->relocations[static_cast<std::size_t>(index)];
        if (!row.symbol_index_validated || !row.symbol_table)
            return nullptr;
        const auto found = symbols.find(*row.symbol_table);
        if (found == symbols.end() || row.symbol_number >= found->second->count)
            return nullptr;
        return &metadata->symbols[static_cast<std::size_t>(found->second->first_symbol + row.symbol_number)];
    }
    void compound(MachOOperandResolution &value) const {
        if (value.relocations.size() != 1)
            return;
        const auto &row = metadata->relocations[static_cast<std::size_t>(value.relocations[0])];
        if (row.pair)
            value.relocations.push_back(*row.pair);
        std::sort(value.relocations.begin(), value.relocations.end());
    }
    MachOOperandResolution solve(MachOOperandResolution out, Use use, std::optional<std::uint64_t> original_end,
                                 std::uint64_t tail) const {
        using R = MachOResolutionReason;
        const auto fail = [&](R why) {
            out.reason = why;
            return std::move(out);
        };
        if (out.relocations.empty())
            return out;
        const auto index = out.relocations[0];
        const auto &row = metadata->relocations[static_cast<std::size_t>(index)];
        if (out.relocations.size() != 1 && !(out.relocations.size() == 2 && row.pair == out.relocations[1]))
            return fail(R::ambiguous);
        for (const auto id : out.relocations) {
            const auto &field = metadata->relocations[static_cast<std::size_t>(id)];
            if (field.auxiliary || encrypted_files.empty())
                continue;
            if (!field.file_place)
                return fail(R::unsupported);
            const auto begin = field.file_place->value;
            require(field.field_size <= UINT64_MAX - begin, "Mach-O encrypted field extent overflow",
                    ErrorCode::overflow);
            const auto end = begin + field.field_size;
            const auto after = std::lower_bound(encrypted_files.begin(), encrypted_files.end(), end,
                                                [&](const auto &range, auto value) {
                                                    charge();
                                                    return range.first < value;
                                                });
            if (after != encrypted_files.begin() && std::prev(after)->second > begin)
                return fail(R::unsupported);
        }
        const auto &header = metadata->container.slices[metadata->selected_slice].header;
        if (row.retained)
            return fail(R::retained);
        if (metadata->relocation_tables[row.table].kind != MachORelocationSource::section || header.file_type != 1)
            return fail(R::runtime_binding);
        const auto cpu = header.cpu_type;
        if (header.order != ByteOrder::little || (cpu != 7 && cpu != 0x01000007) || header.is_64 != (cpu == 0x01000007))
            return fail(R::unsupported);
        if (!row.encoded_value)
            return fail(R::unavailable_field);
        using K = MachORelocationKind;
        if (row.kind == K::subtractor) {
            if (!row.pair || row.scattered || row.pc_relative || (row.field_size != 4 && row.field_size != 8))
                return fail(R::unsupported);
            const auto *subtrahend = symbol(index), *minuend = symbol(*row.pair);
            if (!subtrahend || !minuend)
                return fail(R::unavailable_symbol);
            if ((subtrahend->descriptor | minuend->descriptor) & 0xc0)
                return fail(R::weak_symbol);
            if (!subtrahend->address || !minuend->address)
                return fail(R::symbol_not_address);
            if (subtrahend->address->space != minuend->address->space)
                return fail(R::different_domains);
            const auto mask = row.field_size == 8 ? UINT64_MAX : UINT64_C(0xffffffff);
            out.constant = (minuend->address->offset - subtrahend->address->offset + *row.encoded_value) & mask;
            out.reason = R::resolved;
            return out;
        }
        const bool pc = row.kind == K::pc_relative || row.kind == K::branch;
        const bool absolute = row.kind == K::absolute;
        if (row.scattered || (!pc && !absolute) || row.pc_relative != pc ||
            (pc && (row.field_size != 4 || !original_end)) || (cpu == 7 && row.field_size > 4) ||
            (cpu == 0x01000007 && absolute && row.field_size == 2) ||
            (use != Use::symbolic_data &&
             ((absolute && use != Use::absolute) || (pc && use != Use::relative && use != Use::memory_pc))) ||
            (row.kind == K::branch && use != Use::relative))
            return fail(R::unsupported);
        const auto bits = *row.encoded_value;
        std::optional<Address> target;
        if (row.external) {
            const auto *definition = symbol(index);
            if (!definition)
                return fail(R::unavailable_symbol);
            if (definition->state == MachOSymbolState::undefined ||
                definition->state == MachOSymbolState::prebound_undefined)
                return fail(R::undefined_symbol);
            if (definition->descriptor & 0xc0)
                return fail(R::weak_symbol);
            target = definition->address;
            if (!target)
                return fail(R::symbol_not_address);
            // x64 external PC addends are literal. i386 already encodes the
            // negative original PC. Local records below encode original VAs.
            const auto bias = pc ? (cpu == 7 ? *original_end : tail) : 0;
            const auto result = sum(target->offset, signed_bits(bits, row.field_size), bias);
            if (!result)
                return fail(R::overflow);
            target->offset = *result;
        } else if (!row.symbol_number) {
            out.constant = bits;
            out.reason = R::resolved;
            return out;
        } else {
            if (row.symbol_number > metadata->sections.size())
                return fail(R::unsupported);
            const auto &section = metadata->sections[row.symbol_number - 1];
            const auto original = pc ? sum(*original_end, signed_bits(bits, row.field_size)) : std::optional{bits};
            if (!original || *original < section.address)
                return fail(R::overflow);
            target = Address{{section.ordinal}, *original - section.address};
        }
        if (cpu == 7 && target->offset > UINT32_MAX)
            return fail(R::overflow);
        if (absolute && row.field_size < 8 && target->offset >= (UINT64_C(1) << (row.field_size * 8)))
            return fail(R::overflow);
        out.reason = R::resolved;
        out.address = target;
        return out;
    }
};
Result<MachORelocationResolver> MachORelocationResolver::create(const ImageMetadata &metadata, std::stop_token stop) {
    return create(metadata, MachOResolutionLimits{}, stop);
}
Result<MachORelocationResolver> MachORelocationResolver::create(const ImageMetadata &metadata,
                                                                MachOResolutionLimits limits, std::stop_token stop) {
    return guarded([&]() -> Result<MachORelocationResolver> {
        canceled(stop);
        require(limits.lookup_work <= 64 * 1024 * 1024 && limits.max_matches && limits.max_matches <= 4096,
                "Invalid Mach-O resolution limits", ErrorCode::invalid_argument);
        auto state = std::make_shared<State>();
        state->work_left.store(limits.lookup_work);
        state->max_matches = limits.max_matches;
        if (!metadata.macho)
            return MachORelocationResolver{std::move(state)};
        const auto &m = *metadata.macho;
        state->metadata = &m;
        require(m.selected_slice < m.container.slices.size(), "Missing selected Mach-O slice");
        require(m.relocations.size() <= 1000000 && m.symbol_tables.size() <= 65536, "Mach-O resolver record limit",
                ErrorCode::resource_limit);
        for (const auto &table : m.symbol_tables) {
            canceled(stop);
            require(table.first_symbol <= m.symbols.size() && table.count <= m.symbols.size() - table.first_symbol,
                    "Mach-O symbol namespace exceeds rows");
            require(state->symbols.emplace(table.command_index, &table).second, "Duplicate Mach-O symbol namespace");
        }
        std::uint64_t budget = 0;
        const auto charge = [&](std::uint64_t size) {
            require(size <= 64 * 1024 * 1024 - budget, "Mach-O resolver index budget", ErrorCode::resource_limit);
            budget += size;
        };
        const auto &slice = m.container.slices[m.selected_slice];
        for (const auto &range : m.encryption) {
            canceled(stop);
            if (!range.cryptid || !range.size)
                continue;
            require(range.offset.value >= slice.offset && range.offset.value - slice.offset == range.raw_offset &&
                        range.raw_offset <= slice.size && range.size <= slice.size - range.raw_offset &&
                        range.size <= UINT64_MAX - range.offset.value,
                    "Mach-O encrypted declaration crosses selected slice");
            charge(sizeof(std::pair<std::uint64_t, std::uint64_t>) * 2);
            state->encrypted_files.emplace_back(range.offset.value, range.offset.value + range.size);
        }
        std::sort(state->encrypted_files.begin(), state->encrypted_files.end(), [stop](const auto &a, const auto &b) {
            canceled(stop);
            return a < b;
        });
        std::size_t used = 0;
        for (const auto range : state->encrypted_files) {
            canceled(stop);
            if (used && range.first <= state->encrypted_files[used - 1].second)
                state->encrypted_files[used - 1].second =
                    std::max(state->encrypted_files[used - 1].second, range.second);
            else
                state->encrypted_files[used++] = range;
        }
        state->encrypted_files.resize(used);
        for (std::uint64_t i = 0; i < m.relocations.size(); ++i) {
            canceled(stop);
            const auto &row = m.relocations[static_cast<std::size_t>(i)];
            require(row.table < m.relocation_tables.size(), "Missing Mach-O relocation table");
            require(row.field_size == 1 || row.field_size == 2 || row.field_size == 4 || row.field_size == 8,
                    "Invalid Mach-O relocation width");
            if (row.pair)
                require(*row.pair < m.relocations.size() && *row.pair != i &&
                            m.relocations[static_cast<std::size_t>(*row.pair)].pair == i,
                        "Invalid Mach-O relocation companion");
            if (row.retained || row.auxiliary)
                continue;
            if (row.place) {
                require(row.field_size <= UINT64_MAX - row.place->offset, "Mach-O VM interval overflow",
                        ErrorCode::overflow);
                if (!state->domains.contains(row.place->space.value))
                    charge(128);
                charge(sizeof(State::Interval) * 2);
                state->domains[row.place->space.value].push_back(
                    {row.place->offset, row.place->offset + row.field_size, 0, i});
            }
            if (row.file_place) {
                require(row.field_size <= UINT64_MAX - row.file_place->value, "Mach-O file interval overflow",
                        ErrorCode::overflow);
                charge(sizeof(State::Interval) * 2);
                state->files.push_back({row.file_place->value, row.file_place->value + row.field_size, 0, i});
            }
        }
        for (auto &[space, intervals] : state->domains)
            State::build(intervals, stop);
        State::build(state->files, stop);
        return MachORelocationResolver{std::move(state)};
    });
}
Result<MachOOperandResolution> MachORelocationResolver::operand(const Instruction &instruction, std::uint32_t index,
                                                                std::stop_token stop) const {
    return guarded([&]() -> Result<MachOOperandResolution> {
        canceled(stop);
        MachOOperandResolution out;
        require(index < instruction.operands.size(), "Mach-O operand index out of bounds", ErrorCode::invalid_argument);
        if (!state_->metadata || state_->domains.empty())
            return out;
        require(instruction.length && instruction.length <= 15, "Invalid instruction length",
                ErrorCode::invalid_argument);
        if (instruction.context.mode == ExecutionMode::a64) {
            if (!analysis_detail::a64_packed_operand(instruction, index))
                return out;
            state_->query(instruction.address, 4, out.relocations, stop);
            if (out.relocations.empty())
                return out;
            using R = MachOResolutionReason;
            out.reason = out.relocations.size() == 1 ? R::unsupported : R::ambiguous;
            if (out.relocations.size() != 1)
                return out;
            const auto id = out.relocations.front();
            const auto &row = state_->metadata->relocations[id];
            const auto &header = state_->metadata->container.slices[state_->metadata->selected_slice].header;
            if (!state_->encrypted_files.empty()) {
                if (!row.file_place || row.file_place->value > UINT64_MAX - 4)
                    return out;
                const auto begin = row.file_place->value, end = begin + 4;
                const auto after = std::lower_bound(state_->encrypted_files.begin(), state_->encrypted_files.end(), end,
                                                    [&](const auto &range, auto value) {
                                                        state_->charge();
                                                        return range.first < value;
                                                    });
                if (after != state_->encrypted_files.begin() && std::prev(after)->second > begin)
                    return out;
            }
            if (header.cpu_type != 0x0100000c || !header.is_64 || header.order != ByteOrder::little ||
                header.file_type != 1 || row.retained || row.type != 2 || !row.pc_relative || !row.external ||
                row.scattered || row.auxiliary || row.pair || row.field_size != 4 || row.place != instruction.address ||
                row.kind != MachORelocationKind::branch || !row.encoded_value ||
                (instruction.opcode != Opcode::a64_bl && instruction.opcode != Opcode::a64_b))
                return out;
            std::uint32_t word = 0;
            for (unsigned n = 0; n < 4; ++n)
                word |= std::to_integer<std::uint32_t>(instruction.bytes[n]) << (8 * n);
            if (*row.encoded_value != word)
                return out;
            const auto *symbol = state_->symbol(id);
            if (!symbol) {
                out.reason = R::unavailable_symbol;
                return out;
            }
            if (symbol->state == MachOSymbolState::undefined) {
                out.reason = R::undefined_symbol;
                return out;
            }
            if (symbol->descriptor & 0xc0) {
                out.reason = R::weak_symbol;
                return out;
            }
            if (!symbol->address) {
                out.reason = R::symbol_not_address;
                return out;
            }
            const auto bits = static_cast<std::uint64_t>(word & 0x3ffffffu);
            // Mach-O instruction addends have an explicit ADDEND companion;
            // the placeholder instruction immediate is not a scalar addend.
            if (bits != 0)
                return out;
            const auto address = *symbol->address;
            if (address.offset & 3) {
                out.reason = R::field_mismatch;
                return out;
            }
            out.address = address;
            out.reason = R::resolved;
            return out;
        }
        std::array<Field, 2> fields{};
        std::size_t count = 0;
        const auto append = [&](std::optional<EncodedField> bytes, Use use) {
            if (!bytes)
                return;
            require(bytes->size && bytes->offset < instruction.length &&
                        bytes->size <= instruction.length - bytes->offset,
                    "Mach-O operand encoding exceeds instruction", ErrorCode::invalid_argument);
            fields[count++] = {*bytes, use};
        };
        const auto memory = [&](const MemoryOperand &value) {
            append(value.displacement_encoding, value.segment                 ? Use::register_based
                                                : value.ip_relative           ? Use::memory_pc
                                                : (value.base || value.index) ? Use::register_based
                                                                              : Use::absolute);
        };
        std::visit(
            [&](const auto &value) {
                using T = std::decay_t<decltype(value)>;
                if constexpr (std::is_same_v<T, RelativeOperand>)
                    append(value.encoding, Use::relative);
                else if constexpr (std::is_same_v<T, ImmediateOperand>)
                    append(value.encoding, Use::absolute);
                else if constexpr (std::is_same_v<T, MemoryOperand>)
                    memory(value);
                else if constexpr (std::is_same_v<T, FarMemoryOperand>)
                    memory(value.address);
                else if constexpr (std::is_same_v<T, FarPointerOperand>) {
                    append(value.offset_encoding, Use::far_pointer);
                    append(value.selector_encoding, Use::far_pointer);
                }
            },
            instruction.operands[index]);
        for (std::size_t i = 0; i < count; ++i) {
            const auto at = advance(instruction.address, fields[i].bytes.offset);
            if (!at)
                return at.error();
            state_->query(at.value(), fields[i].bytes.size, out.relocations, stop);
        }
        std::sort(out.relocations.begin(), out.relocations.end());
        out.relocations.erase(std::unique(out.relocations.begin(), out.relocations.end()), out.relocations.end());
        if (out.relocations.empty())
            return out;
        state_->compound(out);
        const auto &row = state_->metadata->relocations[static_cast<std::size_t>(out.relocations[0])];
        const Field *field = nullptr;
        for (std::size_t i = 0; i < count; ++i)
            if (row.place == advance(instruction.address, fields[i].bytes.offset).value() &&
                row.field_size == fields[i].bytes.size)
                field = &fields[i];
        if (!field) {
            out.reason = MachOResolutionReason::field_mismatch;
            return out;
        }
        std::optional<std::uint64_t> original_end;
        if (instruction.address.space.value && instruction.address.space.value <= state_->metadata->sections.size()) {
            const auto &section = state_->metadata->sections[instruction.address.space.value - 1];
            original_end = sum(section.address, instruction.length, instruction.address.offset);
        }
        const auto tail = instruction.length - field->bytes.offset - field->bytes.size;
        return state_->solve(std::move(out), field->use, original_end, tail);
    });
}
Result<MachOOperandResolution> MachORelocationResolver::data(std::uint64_t index, std::stop_token stop) const {
    return guarded([&]() -> Result<MachOOperandResolution> {
        canceled(stop);
        require(state_->metadata && index < state_->metadata->relocations.size(), "Mach-O data row out of bounds",
                ErrorCode::invalid_argument);
        const auto &rows = state_->metadata->relocations;
        if (rows[static_cast<std::size_t>(index)].auxiliary && rows[static_cast<std::size_t>(index)].pair)
            index = *rows[static_cast<std::size_t>(index)].pair;
        const auto &row = rows[static_cast<std::size_t>(index)];
        MachOOperandResolution out;
        if (row.retained) {
            out.relocations.push_back(index);
            state_->compound(out);
            return state_->solve(std::move(out), Use::symbolic_data, {}, 0);
        }
        if (row.place)
            state_->query(*row.place, row.field_size, out.relocations, stop);
        else if (row.file_place)
            state_->query(state_->files, row.file_place->value, row.field_size, out.relocations, stop);
        if (out.relocations.empty())
            out.relocations.push_back(index);
        std::sort(out.relocations.begin(), out.relocations.end());
        state_->compound(out);
        return state_->solve(std::move(out), Use::symbolic_data, {}, 0);
    });
}
Result<MachOOperandResolution> MachORelocationResolver::data_at(Address place,
                                                                  std::optional<FileOffset> file_place,
                                                                  std::uint8_t width, std::stop_token stop) const {
    return guarded([&]() -> Result<MachOOperandResolution> {
        canceled(stop);
        require(width && width <= 8, "Invalid Mach-O data slot width", ErrorCode::invalid_argument);
        MachOOperandResolution output;
        if (!state_->metadata)
            return output;
        state_->query(place, width, output.relocations, stop);
        if (file_place)
            state_->query(state_->files, file_place->value, width, output.relocations, stop);
        for (auto &index : output.relocations) {
            const auto &row = state_->metadata->relocations[static_cast<std::size_t>(index)];
            if (row.auxiliary && row.pair)
                index = *row.pair;
        }
        std::sort(output.relocations.begin(), output.relocations.end());
        output.relocations.erase(std::unique(output.relocations.begin(), output.relocations.end()), output.relocations.end());
        if (output.relocations.empty())
            return output;
        for (const auto index : output.relocations) {
            const auto &row = state_->metadata->relocations[static_cast<std::size_t>(index)];
            const auto exact_virtual = row.place && *row.place == place;
            const auto exact_file = file_place && row.file_place && *row.file_place == *file_place;
            if ((!exact_virtual && !exact_file) || row.field_size != width) {
                output.reason = MachOResolutionReason::unsupported;
                return output;
            }
        }
        state_->compound(output);
        return state_->solve(std::move(output), Use::symbolic_data, {}, 0);
    });
}
const MachOSymbol *MachORelocationResolver::symbol(std::uint64_t row) const noexcept { return state_->symbol(row); }
Result<std::optional<Address>> MachORelocationResolver::control_target(const Image &image,
                                                                       const Instruction &instruction,
                                                                       std::stop_token stop) const {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Mach-O control resolution canceled"};
    if (!instruction.operands.empty()) {
        auto result = operand(instruction, analysis_detail::control_operand_index(instruction), stop);
        if (!result)
            return result.error();
        if (result.value().relocated()) {
            if (std::holds_alternative<RelativeOperand>(
                    instruction.operands[analysis_detail::control_operand_index(instruction)]))
                return result.value().address;
            return std::optional<Address>{};
        }
    }
    return analysis_detail::control_target(image, instruction);
}
} // namespace hexlab
