#include "macho_internal.hpp"
#include <algorithm>
#include <map>
namespace hexlab::macho_detail {
namespace {
MachORelocationKind kind(std::uint32_t cpu, std::uint8_t type, bool pc) {
    using K = MachORelocationKind;
    if (cpu == 7) {
        switch (type) {
        case 0:
            return pc ? K::pc_relative : K::absolute;
        case 1:
            return K::pair;
        case 2:
        case 4:
            return K::section_difference;
        case 3:
            return K::prebound;
        case 5:
            return K::tlv;
        }
    } else if (cpu == 0x01000007) {
        switch (type) {
        case 0:
            return K::absolute;
        case 1:
        case 6:
        case 7:
        case 8:
            return K::pc_relative;
        case 2:
            return K::branch;
        case 3:
        case 4:
            return K::got;
        case 5:
            return K::subtractor;
        case 9:
            return K::tlv;
        }
    } else if (cpu == 0x0100000c) {
        if (type == 0) return K::absolute;
        if (type == 1) return K::subtractor;
        if (type == 2) return K::branch;
        if (type == 10) return K::addend;
    } else if ((cpu == 12 || cpu == 18) && type == 1) {
        return K::pair; // Known payload layout; foreign ISA formulas remain unsupported.
    }
    return K::unknown;
}
bool x86(std::uint32_t cpu) { return cpu == 7 || cpu == 0x01000007; }
void pair_rows(MachOMetadata &metadata, const MachORelocationTable &table, std::uint32_t cpu, std::stop_token stop) {
    using K = MachORelocationKind;
    for (std::uint32_t index = 0; index < table.count; ++index) {
        canceled(stop);
        const auto id = table.first_row + index;
        auto &row = metadata.relocations[static_cast<std::size_t>(id)];
        if (row.kind == K::subtractor || row.kind == K::section_difference || row.kind == K::addend) {
            require(index + 1 < table.count, "Mach-O relocation requires following pair record");
            auto &next = metadata.relocations[static_cast<std::size_t>(id + 1)];
            if (row.kind == K::subtractor) {
                require(next.kind == K::absolute && next.offset == row.offset && next.length == row.length &&
                            !row.pc_relative && !next.pc_relative && row.external && !row.scattered && !next.scattered,
                        "Invalid Mach-O subtractor/unsigned pair");
                next.auxiliary = true;
            } else if (row.kind == K::section_difference) {
                require(next.kind == K::pair && next.length == row.length && (!row.scattered || next.scattered),
                        "Invalid Mach-O section-difference pair");
                next.auxiliary = true;
            } else {
                require(!next.auxiliary && row.offset == next.offset, "Invalid Mach-O ARM64 addend companion");
                metadata.relocations_complete = false;
            }
            row.pair = id + 1;
            next.pair = id;
            ++index;
        } else if (row.kind == K::pair && cpu == 7 && !row.pair) {
            require(false, "Orphan Mach-O generic relocation pair");
        }
    }
}
void map_field(MachORelocation &row, const MachORelocationTable &table, const MachOMetadata &metadata,
               const Image &image, const Reader &reader, std::optional<std::uint64_t> dynamic_base) {
    if (row.kind == MachORelocationKind::pair || row.kind == MachORelocationKind::addend)
        return;
    const auto &header = metadata.container.slices[metadata.selected_slice].header;
    if (table.kind == MachORelocationSource::section) {
        const auto &section = metadata.sections[table.owner - 1];
        require(row.offset <= section.size && row.field_size <= section.size - row.offset,
                "Mach-O relocation field exceeds target section");
        if (section.file_offset)
            row.file_place = FileOffset{add(section.file_offset->value, row.offset)};
        // Linked debug declarations are file-only, even when their raw address
        // happens to overlap a mapped section. The containing segment must also
        // participate in the image before its section can identify a VM field.
        if (header.file_type != 1 &&
            ((section.flags & 0x02000000) || !(metadata.segments[section.segment_index].initial_protection & 7)))
            return;
        const Address at{header.file_type == 1 ? AddressSpaceId{section.ordinal} : AddressSpaceId{0},
                         header.file_type == 1 ? row.offset : add(section.address, row.offset)};
        if (image.segment_at(at))
            row.place = at;
        if (header.file_type == 1 || !row.place)
            return;
    } else {
        if (!dynamic_base)
            return;
        // Normal r_address is int32_t. In x64 a negative runtime offset can
        // refer back from the first writable segment into an earlier segment.
        // Scattered records instead carry an explicitly unsigned24-bit offset.
        if (!row.scattered && (row.raw_address & 0x80000000)) {
            const auto magnitude = UINT64_C(0x100000000) - row.raw_address;
            require(magnitude <= *dynamic_base, "Mach-O runtime relocation offset underflows image base");
            row.place = Address{{0}, *dynamic_base - magnitude};
        } else
            row.place = Address{{0}, add(*dynamic_base, row.offset)};
    }
    // Canonical linked/runtime mapping governs initialized backing, including
    // normalized splits and zero-fill. A discontiguous field has no one file offset.
    const auto at = *row.place;
    std::optional<FileOffset> first;
    bool contiguous = true;
    for (std::uint64_t i = 0; i < row.field_size; ++i) {
        const Address byte{at.space, add(at.offset, i)};
        require(image.segment_at(byte) != nullptr, "Mach-O runtime relocation crosses unmapped memory");
        const auto file = image.to_file_offset(byte);
        if (!file) {
            contiguous = false;
            continue;
        }
        if (i == 0)
            first = file.value();
        else if (!first || file.value().value != add(first->value, i))
            contiguous = false;
        (void)reader.file(file.value().value - metadata.container.slices[metadata.selected_slice].offset, 1);
    }
    row.file_place = contiguous ? first : std::nullopt;
}
} // namespace
void read_relocations(const ByteStorage &storage, const Image &image, MachOMetadata &metadata, Budget &budget,
                      std::stop_token stop) {
    const auto &slice = metadata.container.slices[metadata.selected_slice];
    const auto cpu = slice.header.cpu_type;
    Reader reader(storage, slice, stop);
    std::map<std::uint32_t, const MachOSymbolTable *> symbols;
    for (const auto &table : metadata.symbol_tables)
        symbols.emplace(table.command_index, &table);
    std::optional<std::uint64_t> dynamic_base;
    if (cpu == 0x01000007 || (slice.header.flags & 0x20)) {
        for (const auto &segment : metadata.segments)
            if (segment.initial_protection & 2) {
                dynamic_base = segment.address;
                break;
            }
    } else if (!metadata.segments.empty()) {
        dynamic_base = metadata.segments[0].address;
    }
    const auto append = [&](MachORelocationSource source, std::uint32_t owner, std::uint32_t relative,
                            std::uint32_t count, std::optional<std::uint32_t> symbol_table) {
        canceled(stop);
        if (!count)
            return;
        require(count <= 1000000 - metadata.relocations.size(), "Mach-O relocation count exceeds budget",
                ErrorCode::resource_limit);
        const auto extent = std::uint64_t(count) * 8;
        const auto offset = reader.file(relative, extent);
        budget.include(sizeof(MachORelocationTable) + extent + std::uint64_t(count) * sizeof(MachORelocation));
        const auto table_id = static_cast<std::uint32_t>(metadata.relocation_tables.size());
        MachORelocationTable table{source, owner, count, offset, metadata.relocations.size(), symbol_table};
        for (std::uint32_t index = 0; index < count; ++index) {
            const auto bytes = reader.bytes(std::uint64_t(relative) + std::uint64_t(index) * 8, 8);
            MachORelocation row;
            row.table = table_id;
            row.index = index;
            row.record_file_offset = add(offset.value, std::uint64_t(index) * 8);
            row.raw_address = static_cast<std::uint32_t>(reader.value(bytes.bytes, 0, 4));
            row.raw_info = static_cast<std::uint32_t>(reader.value(bytes.bytes, 4, 4));
            row.scattered = cpu != 0x01000007 && bool(row.raw_address & 0x80000000);
            if (row.scattered) {
                row.offset = row.raw_address & 0xffffff;
                row.type = static_cast<std::uint8_t>((row.raw_address >> 24) & 15);
                row.length = static_cast<std::uint8_t>((row.raw_address >> 28) & 3);
                row.pc_relative = bool(row.raw_address & 0x40000000);
                row.value = row.raw_info;
            } else {
                row.offset = row.raw_address;
                const bool little = slice.header.order == ByteOrder::little;
                row.symbol_number = little ? row.raw_info & 0xffffff : row.raw_info >> 8;
                row.type = static_cast<std::uint8_t>(little ? row.raw_info >> 28 : row.raw_info & 15);
                row.length = static_cast<std::uint8_t>((row.raw_info >> (little ? 25 : 5)) & 3);
                row.pc_relative = bool((row.raw_info >> (little ? 24 : 7)) & 1);
                row.external = bool((row.raw_info >> (little ? 27 : 4)) & 1);
            }
            row.field_size = static_cast<std::uint8_t>(1u << row.length);
            row.kind = kind(cpu, row.type, row.pc_relative);
            row.auxiliary = row.kind == MachORelocationKind::pair || row.kind == MachORelocationKind::addend;
            row.retained = slice.header.file_type != 1 && source == MachORelocationSource::section;
            if (!x86(cpu) || row.kind == MachORelocationKind::unknown)
                metadata.relocations_complete = false;
            if (!row.scattered && !row.auxiliary) {
                if (row.external) {
                    row.symbol_table = symbol_table;
                    const auto found = symbol_table ? symbols.find(*symbol_table) : symbols.end();
                    if (found != symbols.end()) {
                        require(row.symbol_number < found->second->count,
                                "Mach-O relocation symbol index exceeds nlist table");
                        row.symbol_index_validated = true;
                    } else
                        metadata.relocations_complete = false;
                } else {
                    require(row.symbol_number <= metadata.sections.size(),
                            "Mach-O relocation section ordinal exceeds table");
                }
            }
            metadata.relocations.push_back(std::move(row));
        }
        pair_rows(metadata, table, cpu, stop);
        for (std::uint64_t i = table.first_row; i < table.first_row + table.count; ++i)
            map_field(metadata.relocations[static_cast<std::size_t>(i)], table, metadata, image, reader, dynamic_base);
        metadata.relocation_tables.push_back(std::move(table));
    };
    const auto common_symbols =
        metadata.symbol_tables.size() == 1 ? std::optional{metadata.symbol_tables[0].command_index} : std::nullopt;
    for (const auto &section : metadata.sections)
        append(MachORelocationSource::section, section.ordinal, section.relocation_offset, section.relocation_count,
               common_symbols);
    for (const auto &table : metadata.dynamic_symbol_tables) {
        append(MachORelocationSource::external, table.command_index, table.tables[4].raw_offset, table.tables[4].count,
               table.symbol_table);
        append(MachORelocationSource::local, table.command_index, table.tables[5].raw_offset, table.tables[5].count,
               table.symbol_table);
    }
    // Mach-O tables commonly order fields in descending addresses. Read sampled
    // field bits in file order to keep source-dependency range insertion bounded
    // for ordinary large objects instead of repeatedly prepending their ranges.
    std::vector<std::size_t> sample;
    budget.include(metadata.relocations.size() * sizeof(std::size_t));
    if (x86(cpu) || cpu == 0x0100000c)
        for (std::size_t index = 0; index < metadata.relocations.size(); ++index) {
            const auto &row = metadata.relocations[index];
            if ((x86(cpu) || row.kind == MachORelocationKind::branch) &&
                !row.retained && !row.auxiliary && row.kind != MachORelocationKind::unknown &&
                (row.place || row.file_place))
                sample.push_back(index);
        }
    std::sort(sample.begin(), sample.end(), [&](auto a, auto b) {
        return metadata.relocations[a].file_place.value_or(FileOffset{UINT64_MAX}).value <
               metadata.relocations[b].file_place.value_or(FileOffset{UINT64_MAX}).value;
    });
    for (const auto index : sample) {
        canceled(stop);
        auto &row = metadata.relocations[index];
        std::uint64_t value = 0;
        for (std::uint64_t byte = 0; byte < row.field_size; ++byte) {
            std::optional<FileOffset> file;
            if (row.place) {
                auto at = image.to_file_offset({row.place->space, add(row.place->offset, byte)});
                if (at)
                    file = at.value();
            } else
                file = FileOffset{add(row.file_place->value, byte)};
            if (file) {
                const auto raw = reader.bytes(file->value - slice.offset, 1);
                const auto shift = slice.header.order == ByteOrder::little ? byte : row.field_size - byte - 1;
                value |= std::to_integer<std::uint64_t>(raw.bytes[0]) << (8 * shift);
            }
        }
        row.encoded_value = value;
    }
}
} // namespace hexlab::macho_detail
