#include "elf_internal.hpp"
#include <algorithm>
#include <bit>
#include <map>
#include <set>

namespace hexlab::elf_detail {
namespace {
constexpr std::size_t max_types = 100'000;
constexpr std::size_t max_bases_per_type = 4096;
constexpr std::size_t max_name = 1024;
constexpr std::size_t max_slots_per_vtable = 65'536;
constexpr std::size_t max_total_vtable_slots = 1'000'000;

bool same_source(const ElfTableSource &a, const ElfTableSource &b) {
    return a.section == b.section && a.file_offset == b.file_offset && a.address == b.address;
}

struct Parser {
    const ByteStorage &storage;
    const Image &image;
    ElfMetadata &metadata;
    Budget &budget;
    std::stop_token stop;
    Reader reader;
    std::map<std::pair<std::uint32_t, std::uint64_t>, std::vector<const ElfRelocation *>> relocations_by_place;
    std::map<std::pair<std::size_t, std::uint32_t>, const ElfSymbol *> symbols_by_index;

    Parser(const ByteStorage &s, const Image &i, ElfMetadata &m, Budget &b, std::stop_token t)
        : storage(s), image(i), metadata(m), budget(b), stop(t), reader(s, m.header.order, t) {
        for (const auto &rel : metadata.relocations)
            if (rel.place) relocations_by_place[{rel.place->space.value, rel.place->offset}].push_back(&rel);
        for (const auto &sym : metadata.symbols)
            if (sym.table) symbols_by_index[{*sym.table, sym.index}] = &sym;
    }

    std::vector<Address> pointer_candidates(Address slot) {
        auto raw = read_virtual(reader, image, slot, 8, budget, stop);
        const auto value = reader.value(raw.bytes, 0, 8);
        std::vector<Address> candidates;
        if (value && image.segment_at({slot.space, value}) && image.to_file_offset({slot.space, value}))
            candidates.push_back({slot.space, value});
        const auto found_relocations = relocations_by_place.find({slot.space.value, slot.offset});
        if (found_relocations != relocations_by_place.end()) for (const auto *rel_ptr : found_relocations->second) {
            const auto &rel = *rel_ptr;
            canceled(stop);
            if (!rel.symbol_index_validated)
                continue;
            if (rel.kind == ElfRelocationKind::base_relative && rel.addend && *rel.addend >= 0) {
                const Address at{slot.space, static_cast<std::uint64_t>(*rel.addend)};
                if (image.segment_at(at) && image.to_file_offset(at)) candidates.push_back(at);
                continue;
            }
            if (!rel.symbol_table || (rel.kind != ElfRelocationKind::absolute && rel.kind != ElfRelocationKind::global_data))
                continue;
            for (std::size_t table_index = 0; table_index < metadata.symbol_tables.size(); ++table_index) {
                if (!same_source(metadata.symbol_tables[table_index].source, *rel.symbol_table)) continue;
                const auto symbol = symbols_by_index.find({table_index, rel.symbol_index});
                if (symbol != symbols_by_index.end()) {
                    const auto &sym = *symbol->second;
                    if (!sym.address) continue;
                    std::uint64_t target = sym.address->offset;
                    if (rel.addend) {
                        if (*rel.addend < 0) {
                            const auto magnitude = static_cast<std::uint64_t>(-(*rel.addend + 1)) + 1;
                            if (target < magnitude) continue;
                            target -= magnitude;
                        } else if (static_cast<std::uint64_t>(*rel.addend) <= UINT64_MAX - target)
                            target += static_cast<std::uint64_t>(*rel.addend);
                        else continue;
                    }
                    const Address at{sym.address->space, target};
                    if (image.segment_at(at) && image.to_file_offset(at)) candidates.push_back(at);
                }
            }
        }
        std::sort(candidates.begin(), candidates.end(), [](Address a, Address b) {
            return std::tie(a.space.value, a.offset) < std::tie(b.space.value, b.offset);
        });
        candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());
        return candidates;
    }

    std::optional<Address> pointer(Address slot) {
        auto candidates = pointer_candidates(slot);
        return candidates.size() == 1 ? std::optional<Address>(candidates.front()) : std::nullopt;
    }

    std::optional<std::string> c_string(Address at) {
        std::string result;
        result.reserve(64);
        for (std::size_t n = 0; n < max_name; ++n) {
            canceled(stop);
            auto byte = read_virtual(reader, image, at, 1, budget, stop);
            const auto c = static_cast<char>(std::to_integer<unsigned char>(byte.bytes[0]));
            if (!c) return result;
            result.push_back(c);
            if (at.offset == UINT64_MAX) return std::nullopt;
            ++at.offset;
        }
        return std::nullopt;
    }

    std::optional<std::string> type_name(Address type) {
        if (!image.segment_at(type) || !image.to_file_offset(type)) return std::nullopt;
        auto name_pointer = pointer({type.space, add(type.offset, 8)});
        return name_pointer ? c_string(*name_pointer) : std::nullopt;
    }

    std::optional<ElfRttiDescriptorKind> descriptor_kind(Address type) {
        auto vptr = pointer(type);
        if (!vptr) return std::nullopt;
        for (const auto &sym : metadata.symbols) {
            if (sym.name != "_ZTVN10__cxxabiv117__class_type_infoE" &&
                sym.name != "_ZTVN10__cxxabiv120__si_class_type_infoE" &&
                sym.name != "_ZTVN10__cxxabiv121__vmi_class_type_infoE") continue;
            if (!sym.address || sym.address->space != vptr->space || sym.address->offset > UINT64_MAX - 16 ||
                sym.address->offset + 16 != vptr->offset) continue;
            if (sym.name == "_ZTVN10__cxxabiv117__class_type_infoE") return ElfRttiDescriptorKind::class_type;
            if (sym.name == "_ZTVN10__cxxabiv120__si_class_type_infoE") return ElfRttiDescriptorKind::single_inheritance;
            return ElfRttiDescriptorKind::multiple_inheritance;
        }
        return std::nullopt;
    }

    void run() {
        if (!metadata.header.is_64 || metadata.header.object_type == 4) return;
        std::map<std::uint64_t, std::size_t> classes;
        std::vector<const ElfSymbol *> type_symbols;
        std::set<std::pair<std::uint64_t, std::uint64_t>> type_info_addresses;
        for (const auto &symbol : metadata.symbols)
            if (symbol.name.starts_with("_ZTI") && symbol.state == ElfSymbolState::defined && symbol.address) {
                type_symbols.push_back(&symbol);
                type_info_addresses.emplace(symbol.address->space.value, symbol.address->offset);
            }
        require(type_symbols.size() <= max_types, "ELF RTTI type count exceeds limit", ErrorCode::resource_limit);
        for (const auto *symbol : type_symbols) {
            canceled(stop);
            const auto type = *symbol->address;
            if (!image.segment_at(type) || !image.to_file_offset(type)) continue;
            auto kind = descriptor_kind(type);
            if (!kind) continue; // Runtime ABI descriptor or ambiguous vptr, retained as opaque.
            ElfRttiClass row;
            row.type_info = type;
            row.descriptor_kind = *kind;
            row.mangled_name = type_name(type);
            if (!row.mangled_name) row.diagnostic = "type_info name pointer is unresolved or invalid";
            if (auto vptr = pointer(type)) row.descriptor_vtable = *vptr;
            else row.diagnostic = "type_info descriptor vtable pointer is unresolved or ambiguous";
            budget.include(sizeof(ElfRttiClass) + (row.mangled_name ? row.mangled_name->size() : 0));
            classes.emplace(type.offset, metadata.rtti_classes.size());
            metadata.rtti_classes.push_back(std::move(row));
        }
        for (auto &row : metadata.rtti_classes) {
            canceled(stop);
            const auto kind = row.descriptor_kind;
            if (kind == ElfRttiDescriptorKind::class_type) continue;
            const auto base_count = kind == ElfRttiDescriptorKind::single_inheritance ? 1u : 0u;
            std::uint32_t count = base_count;
            std::uint64_t base_at = add(row.type_info.offset, 16);
            if (kind == ElfRttiDescriptorKind::multiple_inheritance) {
                auto header = read_virtual(reader, image, {row.type_info.space, base_at}, 8, budget, stop);
                count = static_cast<std::uint32_t>(reader.value(header.bytes, 4, 4));
                base_at = add(base_at, 8);
            }
            if (count > max_bases_per_type) {
                row.diagnostic = "RTTI base count exceeds limit";
                metadata.rtti_complete = false;
                continue;
            }
            bool graph_valid = true;
            std::vector<ElfRttiBase> bases;
            for (std::uint32_t index = 0; index < count; ++index) {
                const auto item = add(base_at, std::uint64_t(index) * 16);
                auto base = pointer({row.type_info.space, item});
                if (!base) { graph_valid = false; break; }
                auto raw = read_virtual(reader, image, {row.type_info.space, add(item, 8)}, 8, budget, stop);
                const auto bits = reader.value(raw.bytes, 0, 8);
                const auto signed_bits = std::bit_cast<std::int64_t>(bits);
                const auto low = static_cast<std::uint64_t>(signed_bits) & 0xff;
                const auto base_offset = signed_bits >> 8;
                ElfRttiBase edge{*base, type_name(*base), signed_bits, base_offset, bool(low & 1), bool(low & 2)};
                bases.push_back(std::move(edge));
            }
            if (!graph_valid) {
                row.diagnostic = "one or more base RTTI pointers are unresolved or ambiguous";
                metadata.rtti_complete = false;
            } else {
                row.direct_bases = std::move(bases);
                for (const auto &base : row.direct_bases)
                    if (!classes.contains(base.type_info.offset)) metadata.rtti_complete = false;
            }
        }
        std::set<std::pair<std::uint64_t, std::uint64_t>> rtti_addresses;
        for (const auto &rtti : metadata.rtti_classes)
            rtti_addresses.emplace(rtti.type_info.space.value, rtti.type_info.offset);
        std::size_t total_slots = 0;
        for (const auto &symbol : metadata.symbols) {
            canceled(stop);
            if (!symbol.name.starts_with("_ZTV") || symbol.state != ElfSymbolState::defined || !symbol.address ||
                symbol.size < 16 || !image.segment_at(*symbol.address)) continue;
            const auto begin = *symbol.address;
            if (symbol.size > UINT64_MAX - begin.offset) {
                metadata.rtti_complete = false;
                continue;
            }
            auto header = read_virtual(reader, image, begin, 16, budget, stop);
            const auto top = std::bit_cast<std::int64_t>(reader.value(header.bytes, 0, 8));
            auto type = pointer({begin.space, add(begin.offset, 8)});
            ElfVTableHeader vtable{begin, {begin.space, add(begin.offset, 16)}, top, type, {}, symbol.index};
            if (type) {
                for (const auto &rtti : metadata.rtti_classes)
                    if (rtti.type_info == *type) { vtable.type_name = rtti.mangled_name; break; }
                if (!vtable.type_name) vtable.type_name = type_name(*type);
            }

            // Only decode the primary table (offset-to-top == 0) when its
            // type_info names a defined ABI RTTI record. This intentionally
            // excludes opaque and construction-like layouts.
            const bool validated_primary = top == 0 && type &&
                rtti_addresses.contains({type->space.value, type->offset});
            if (validated_primary && symbol.size >= 16) {
                vtable.slots_scanned = true;
                vtable.slots_complete = true;
                const auto available = (symbol.size - 16) / 8;
                const auto bounded = std::min<std::uint64_t>(available, max_slots_per_vtable);
                if (available > max_slots_per_vtable || total_slots > max_total_vtable_slots - bounded) {
                    vtable.slots_complete = false;
                    metadata.rtti_complete = false;
                }
                const auto slot_count = static_cast<std::size_t>(
                    std::min<std::uint64_t>(bounded, max_total_vtable_slots - std::min(total_slots, max_total_vtable_slots)));
                for (std::size_t index = 0; index < slot_count; ++index) {
                    canceled(stop);
                    const Address slot_address{begin.space, add(vtable.address_point.offset,
                                                                static_cast<std::uint64_t>(index) * 8)};
                    // A secondary vtable address point begins with its own
                    // offset-to-top and a pointer to a known type_info object.
                    if (index + 1 < available) {
                        const Address next_slot{begin.space, add(slot_address.offset, 8)};
                        auto next_targets = pointer_candidates(next_slot);
                        if (next_targets.size() == 1 &&
                            type_info_addresses.contains({next_targets.front().space.value, next_targets.front().offset})) {
                            vtable.slots_complete = false;
                            break;
                        }
                    }
                    auto targets = pointer_candidates(slot_address);
                    ElfVTableSlot row;
                    row.index = static_cast<std::uint32_t>(index);
                    row.slot = slot_address;
                    if (targets.empty()) {
                        auto raw_slot = read_virtual(reader, image, slot_address, 8, budget, stop);
                        const auto has_relocation = relocations_by_place.contains(
                            {slot_address.space.value, slot_address.offset});
                        row.state = reader.value(raw_slot.bytes, 0, 8) == 0 && !has_relocation
                                        ? ElfVTableSlotState::null_pointer
                                        : ElfVTableSlotState::unresolved;
                    } else if (targets.size() > 1) {
                        row.state = ElfVTableSlotState::ambiguous;
                    } else {
                        const auto *target_segment = image.segment_at(targets.front());
                        if (target_segment && target_segment->executable) {
                            row.target = targets.front();
                            row.state = ElfVTableSlotState::resolved_executable;
                        } else {
                            row.state = ElfVTableSlotState::non_executable_target;
                        }
                    }
                    budget.include(sizeof(ElfVTableSlot));
                    vtable.slots.push_back(std::move(row));
                }
                total_slots += vtable.slots.size();
            }
            budget.include(sizeof(ElfVTableHeader) + (vtable.type_name ? vtable.type_name->size() : 0));
            metadata.vtable_headers.push_back(std::move(vtable));
        }
    }
};
} // namespace

Result<bool> read_rtti(const ByteStorage &storage, const Image &image, ElfMetadata &metadata, Budget &budget,
                       std::stop_token stop) {
    try {
        if (!metadata.header.is_64 || metadata.header.object_type == 4) return true;
        Parser(storage, image, metadata, budget, stop).run();
        return metadata.rtti_complete;
    } catch (const Failure &failure) {
        return failure.error;
    }
}
} // namespace hexlab::elf_detail

