#include "elf_internal.hpp"
#include <algorithm>
#include <map>
namespace hexlab::elf_detail {
void resolve_symbol(ElfSymbol &symbol, const Image &image, const ElfMetadata &metadata) {
    // AAPCS32 uses bit zero of an STT_FUNC value to report Thumb state. Keep
    // that tagged value in ElfSymbol::value for provenance, but use its even
    // physical address for all section bounds and image lookups. Other symbol
    // kinds retain their complete value; bit zero is not a general address tag.
    const bool thumb_function =
        metadata.header.machine == 40 && !metadata.header.is_64 && symbol.type == 2 && (symbol.value & 1u) != 0;
    const std::uint64_t physical_value = thumb_function ? symbol.value & ~UINT64_C(1) : symbol.value;
    const bool extended = symbol.raw_section == 0xffff;
    if (!extended && symbol.raw_section == 0)
        return;
    if (!extended && symbol.raw_section == 0xfff1) {
        symbol.state = ElfSymbolState::absolute;
        return;
    }
    if (!extended && symbol.raw_section == 0xfff2) {
        require(metadata.header.object_type == 1, "SHN_COMMON requires relocatable ELF");
        symbol.state = ElfSymbolState::common;
        return;
    }
    if (!extended && symbol.raw_section >= 0xff00) {
        symbol.state = ElfSymbolState::reserved;
        return;
    }
    if (metadata.sections.empty() && metadata.header.object_type != 1) {
        require(symbol.section_index != 0, "Extended ELF section index cannot be zero");
        symbol.state = symbol.type == 6 ? ElfSymbolState::tls : ElfSymbolState::defined;
        if (symbol.type == 6)
            return;
        const Address at{{0}, physical_value};
        if (!image.segment_at(at))
            return;
        const auto end = add(at.offset, symbol.size);
        for (auto cursor = at.offset; cursor < end;) {
            const auto *segment = image.segment_at({{0}, cursor});
            require(segment != nullptr, "Dynamic ELF symbol crosses unmapped memory");
            cursor = add(cursor, std::min(end - cursor, segment->size - (cursor - segment->begin.offset)));
        }
        symbol.address = at;
        return;
    }
    require(symbol.section_index && symbol.section_index < metadata.sections.size(),
            "ELF symbol section index is outside table");
    const auto &section = metadata.sections[symbol.section_index];
    symbol.state = symbol.type == 6 ? ElfSymbolState::tls : ElfSymbolState::defined;
    // Executable TLS values are offsets in the TLS block, not section VAs.
    // Do not invent a TLS base or memory address from them.
    if (symbol.type == 6 && metadata.header.object_type != 1) {
        require(symbol.size <= section.size, "ELF TLS symbol exceeds section size");
        return;
    }
    std::uint64_t offset = physical_value;
    if (metadata.header.object_type != 1) {
        require(physical_value >= section.address, "ELF symbol precedes its declared section");
        offset = physical_value - section.address;
    }
    require(offset <= section.size && symbol.size <= section.size - offset, "ELF symbol extent exceeds its section");
    if (symbol.type == 6 || !(section.flags & 2) || offset == section.size)
        return;
    const Address address{metadata.header.object_type == 1 ? AddressSpaceId{symbol.section_index} : AddressSpaceId{0},
                          physical_value};
    if (image.segment_at(address))
        symbol.address = address;
}
ElfSymbol decode_symbol(const Reader &reader, std::span<const std::byte> bytes, bool wide, ElfTableSource source,
                        std::uint32_t index, ByteView names, Budget &budget) {
    const auto get = [&](std::size_t at, std::size_t n) { return reader.value(bytes, at, n); };
    ElfSymbol symbol;
    symbol.table = source.section;
    symbol.table_offset = source.file_offset;
    symbol.table_address = source.address;
    symbol.index = index;
    symbol.name_index = static_cast<std::uint32_t>(get(0, 4));
    const auto info = get(wide ? 4 : 12, 1);
    symbol.binding = static_cast<std::uint8_t>(info >> 4);
    symbol.type = static_cast<std::uint8_t>(info & 15);
    symbol.other = static_cast<std::uint8_t>(get(wide ? 5 : 13, 1));
    symbol.visibility = symbol.other & 7;
    symbol.raw_section = static_cast<std::uint16_t>(get(wide ? 6 : 14, 2));
    symbol.section_index = symbol.raw_section;
    symbol.value = get(wide ? 8 : 4, wide ? 8 : 4);
    symbol.size = get(wide ? 16 : 8, wide ? 8 : 4);
    if (index == 0)
        require(symbol.name_index == 0 && info == 0 && symbol.other == 0 && symbol.raw_section == 0 &&
                    symbol.value == 0 && symbol.size == 0,
                "ELF first symbol must be the zero undefined entry");
    if (symbol.name_index) {
        require(symbol.name_index < names.bytes.size(), "ELF symbol name is outside string table");
        const auto tail = names.bytes.subspan(symbol.name_index);
        const auto end = std::find(tail.begin(), tail.end(), std::byte{0});
        require(end != tail.end(), "Unterminated ELF symbol name");
        const auto length = static_cast<std::size_t>(end - tail.begin());
        budget.include(length);
        symbol.name.assign(reinterpret_cast<const char *>(tail.data()), length);
    }
    return symbol;
}
void read_symbols(const ByteStorage &storage, const Image &image, ElfMetadata &metadata, Budget &budget,
                  std::stop_token stop) {
    const auto is_symbols = [](const ElfSection &section) { return section.type == 2 || section.type == 11; };
    if (std::none_of(metadata.sections.begin(), metadata.sections.end(),
                     [&](const auto &section) {
                         return is_symbols(section) || section.type == 18 || section.type == 17;
                     }))
        return;
    const bool wide = metadata.header.is_64;
    const auto minimum = wide ? 24u : 16u;
    Reader reader(storage, metadata.header.order, stop);
    budget.include(metadata.sections.size() * sizeof(std::uint32_t));
    std::vector<std::uint32_t> companions(metadata.sections.size(), UINT32_MAX);
    std::size_t total = 0;
    for (const auto &section : metadata.sections) {
        canceled(stop);
        if (section.type == 18 && !(section.flags & 0x800)) {
            require(section.link < metadata.sections.size() && is_symbols(metadata.sections[section.link]),
                    "ELF SHNDX link must name a symbol table");
            require(companions[section.link] == UINT32_MAX, "Duplicate ELF SHNDX companion");
            require(section.entry_size == 4 && section.size % 4 == 0, "Invalid ELF SHNDX record stride/extent");
            companions[section.link] = section.index;
        }
        if (!is_symbols(section) || (section.flags & 0x800))
            continue;
        require(section.entry_size >= minimum && section.size % section.entry_size == 0,
                "Invalid ELF symbol record stride/extent");
        const auto count = section.size / section.entry_size;
        require(count && count <= 1000000 - total, "ELF symbol record budget exceeded", ErrorCode::resource_limit);
        require(section.info >= 1 && section.info <= count, "ELF symbol local partition is outside table");
        require(section.link < metadata.sections.size() && metadata.sections[section.link].type == 3,
                "ELF symbol link must name STRTAB");
        total += static_cast<std::size_t>(count);
    }
    budget.include(total * sizeof(ElfSymbol));
    metadata.symbols.reserve(total);
    std::map<std::uint32_t, ByteView> strings;
    const auto string_table = [&](std::uint32_t index) -> const ByteView & {
        if (const auto found = strings.find(index); found != strings.end())
            return found->second;
        const auto &table = metadata.sections[index];
        budget.include(sizeof(ByteView) + sizeof(std::uint32_t) + 3 * sizeof(void *));
        ByteView view;
        if (table.flags & 0x800) {
            auto expanded = std::make_shared<const std::vector<std::uint8_t>>(
                read_debug_section_bytes(storage, metadata, table, budget, stop));
            require(!expanded->empty(), "ELF symbol string table requires boundary terminators");
            view.owner = expanded;
            view.bytes = {reinterpret_cast<const std::byte *>(expanded->data()), expanded->size()};
        } else if (table.size) {
            require(table.size <= metadata_limit && table.size <= std::numeric_limits<std::size_t>::max(),
                    "ELF symbol string table exceeds metadata budget", ErrorCode::resource_limit);
            budget.include(table.size);
            view = reader.bytes(table.offset, static_cast<std::size_t>(table.size));
        }
        if (!view.bytes.empty())
            require(view.bytes.front() == std::byte{0} && view.bytes.back() == std::byte{0},
                    "ELF symbol string table requires boundary terminators");
        return strings.emplace(index, std::move(view)).first->second;
    };
    for (const auto &table : metadata.sections) {
        canceled(stop);
        if (!is_symbols(table) || (table.flags & 0x800))
            continue;
        const auto count = table.size / table.entry_size;
        const ElfSection *companion = nullptr;
        if (companions[table.index] != UINT32_MAX) {
            companion = &metadata.sections[companions[table.index]];
            require(companion->size / 4 == count, "ELF SHNDX companion count differs from symbols");
        }
        const auto &names = string_table(table.link);
        budget.include(sizeof(ElfSymbolTable));
        metadata.symbol_tables.push_back(
            {{table.index, table.offset}, table.entry_size, count, metadata.symbols.size()});
        for (std::uint32_t index = 0; index < count; ++index) {
            const auto view = reader.bytes(table.offset + table.entry_size * index, minimum);
            auto symbol =
                decode_symbol(reader, view.bytes, wide, {table.index, table.offset, {}}, index, names, budget);
            require(index < table.info ? symbol.binding == 0 : symbol.binding != 0,
                    "ELF symbol binding disagrees with local partition");
            std::uint64_t extended_index = 0;
            if (companion) {
                const auto word = reader.bytes(companion->offset + std::uint64_t{index} * 4, 4);
                extended_index = reader.value(word.bytes, 0, 4);
                require(symbol.raw_section == 0xffff || extended_index == 0, "Unused ELF SHNDX entry must be zero");
            }
            if (symbol.raw_section == 0xffff) {
                require(companion != nullptr, "ELF symbol XINDEX requires SHNDX companion");
                symbol.section_index = static_cast<std::uint32_t>(extended_index);
            }
            resolve_symbol(symbol, image, metadata);
            metadata.symbols.push_back(std::move(symbol));
        }
    }
    // SHT_GROUP is meaningful only for ET_REL. Preserve the signature and
    // exact member list so callers can inspect COMDAT/grouped sections without
    // pretending that the loader has selected or discarded duplicate groups.
    budget.include(metadata.sections.size() * sizeof(std::uint8_t));
    std::vector<std::uint8_t> grouped(metadata.sections.size());
    for (const auto &section : metadata.sections) {
        canceled(stop);
        if (section.type != 17) // SHT_GROUP
            continue;
        require(metadata.header.object_type == 1, "SHT_GROUP requires relocatable ELF");
        require(section.size >= 8 && section.size % 4 == 0 && section.entry_size == 4,
                "Invalid ELF section-group record extent/stride");
        require(section.link < metadata.sections.size() && is_symbols(metadata.sections[section.link]),
                "ELF section-group link must name a symbol table");
        const auto table = std::find_if(metadata.symbol_tables.begin(), metadata.symbol_tables.end(),
            [&](const ElfSymbolTable &candidate) { return candidate.source.section == section.link; });
        require(table != metadata.symbol_tables.end() && table->symbol_begin && table->count,
                "ELF section-group signature table is unavailable");
        require(section.info < *table->count, "ELF section-group signature index is outside symbol table");
        const auto signature_at = static_cast<std::size_t>(*table->symbol_begin + section.info);
        require(signature_at < metadata.symbols.size(), "ELF section-group signature symbol is unavailable");
        const auto flags_view = reader.bytes(section.offset, 4);
        const auto flags = static_cast<std::uint32_t>(reader.value(flags_view.bytes, 0, 4));
        budget.include(sizeof(ElfSectionGroup) + (section.size / 4 - 1) * sizeof(std::uint32_t));
        ElfSectionGroup group;
        group.section = section.index;
        group.flags = flags;
        group.signature_symbol = section.info;
        group.signature_symbol_table = section.link;
        group.signature_name = metadata.symbols[signature_at].name;
        group.members.reserve(static_cast<std::size_t>(section.size / 4 - 1));
        for (std::uint64_t at = 4; at < section.size; at += 4) {
            canceled(stop);
            const auto member_view = reader.bytes(section.offset + at, 4);
            const auto member = static_cast<std::uint32_t>(reader.value(member_view.bytes, 0, 4));
            require(member != 0 && member < metadata.sections.size() && member != section.index,
                    "ELF section-group member index is invalid");
            require(metadata.sections[member].flags & 0x200,
                    "ELF section-group member lacks SHF_GROUP");
            require(!grouped[member], "ELF section belongs to multiple groups");
            grouped[member] = 1;
            group.members.push_back(member);
        }
        metadata.section_groups.push_back(std::move(group));
    }
    for (const auto &section : metadata.sections)
        if (section.flags & 0x200)
            require(grouped[section.index], "SHF_GROUP section has no SHT_GROUP membership");
}
} // namespace hexlab::elf_detail
