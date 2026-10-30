#include "macho_internal.hpp"
#include <algorithm>
namespace hexlab::macho_detail {
namespace {
std::string string_at(std::span<const std::byte> strings, std::uint64_t index, Budget &budget, std::stop_token stop) {
    canceled(stop);
    if (!index)
        return {};
    require(index < strings.size(), "Mach-O symbol string index exceeds string table");
    const auto tail = strings.subspan(static_cast<std::size_t>(index));
    const auto extent = std::min<std::size_t>(tail.size(), 65537);
    const auto begin = tail.begin(), end = std::find(begin, begin + extent, std::byte{0});
    require(end != begin + extent, "Unterminated or oversized Mach-O symbol name");
    const auto size = static_cast<std::size_t>(end - begin);
    budget.include(size);
    return {reinterpret_cast<const char *>(tail.data()), size};
}
void resolve(MachOSymbol &symbol, const Image &image, MachOMetadata &metadata) {
    const auto &header = metadata.container.slices[metadata.selected_slice].header;
    if (symbol.type & 0xe0) {
        symbol.state = MachOSymbolState::debug;
        return;
    }
    switch (symbol.type & 0x0e) {
    case 0:
        require(symbol.section == 0, "Mach-O undefined/common symbol has a section ordinal");
        symbol.state = symbol.value ? MachOSymbolState::common : MachOSymbolState::undefined;
        break;
    case 2:
        require(symbol.section == 0, "Mach-O absolute symbol has a section ordinal");
        symbol.state = MachOSymbolState::absolute;
        return;
    case 0xa:
        require(symbol.section == 0, "Mach-O indirect symbol has a section ordinal");
        symbol.state = MachOSymbolState::indirect;
        return;
    case 0xc:
        symbol.state = MachOSymbolState::prebound_undefined;
        break;
    case 0xe: {
        symbol.state = MachOSymbolState::defined;
        require(symbol.section && symbol.section <= metadata.sections.size(),
                "Mach-O symbol section ordinal exceeds table");
        const auto &section = metadata.sections[symbol.section - 1];
        const auto type = section.flags & 255;
        if (type >= 0x11 && type <= 0x15)
            return; // TLV templates/descriptors have no known per-thread address.
        const bool inside = symbol.value >= section.address && symbol.value - section.address < section.size;
        if (header.file_type == 1) {
            if (!inside) {
                if (symbol.value != add(section.address, section.size))
                    metadata.symbols_complete = false;
                return;
            }
            symbol.address = Address{{section.ordinal}, symbol.value - section.address};
        } else {
            // Linked header aliases can precede their named section. Keep their
            // mapped address, but never treat them as section instruction seeds.
            const Address address{{0}, symbol.value};
            if (image.segment_at(address))
                symbol.address = address;
        }
        if (symbol.address && inside && !(section.flags & 0x02000000) && (section.flags & 0x80000400)) {
            const auto *mapped = image.segment_at(*symbol.address);
            symbol.code =
                mapped && mapped->executable && symbol.address->offset - mapped->begin.offset < mapped->file_size;
        }
        return;
    }
    default:
        symbol.state = MachOSymbolState::unknown;
        metadata.symbols_complete = false;
        return;
    }
    if (header.file_type != 1 && (header.flags & 0x80) &&
        (symbol.state == MachOSymbolState::undefined || symbol.state == MachOSymbolState::prebound_undefined))
        symbol.library_ordinal = static_cast<std::uint8_t>(symbol.descriptor >> 8);
}
} // namespace
void read_symbols(const ByteStorage &storage, const Image &image, MachOMetadata &metadata, Budget &budget,
                  std::stop_token stop) {
    const auto &slice = metadata.container.slices[metadata.selected_slice];
    Reader reader(storage, slice, stop);
    for (const auto &command : slice.header.commands) {
        canceled(stop);
        if (command.command != 2)
            continue;
        require(command.size >= 24, "Truncated Mach-O symbol-table command");
        const auto bytes = reader.bytes(command.file_offset - slice.offset, 24);
        const auto field = [&](std::size_t at) { return static_cast<std::uint32_t>(reader.value(bytes.bytes, at, 4)); };
        MachOSymbolTable table;
        table.command_index = command.index;
        table.raw_symbol_offset = field(8);
        table.count = field(12);
        table.raw_string_offset = field(16);
        table.string_size = field(20);
        table.stride = slice.header.is_64 ? 16 : 12;
        table.first_symbol = metadata.symbols.size();
        require(table.count <= 1000000 - metadata.symbols.size(), "Mach-O symbol count exceeds budget",
                ErrorCode::resource_limit);
        const auto extent = std::uint64_t(table.count) * table.stride;
        table.symbol_offset = reader.file(table.raw_symbol_offset, extent);
        table.string_offset = reader.file(table.raw_string_offset, table.string_size);
        budget.include(sizeof(MachOSymbolTable) + extent + table.string_size +
                       std::uint64_t(table.count) * sizeof(MachOSymbol));
        const auto strings = reader.bytes(table.raw_string_offset, table.string_size);
        for (std::uint32_t index = 0; index < table.count; ++index) {
            canceled(stop);
            const auto relative = std::uint64_t(table.raw_symbol_offset) + std::uint64_t(index) * table.stride;
            const auto record = reader.bytes(relative, table.stride);
            MachOSymbol symbol;
            symbol.table_command = table.command_index;
            symbol.index = index;
            symbol.record_file_offset = reader.file(relative, table.stride).value;
            symbol.string_index = static_cast<std::uint32_t>(reader.value(record.bytes, 0, 4));
            symbol.type = static_cast<std::uint8_t>(reader.value(record.bytes, 4, 1));
            symbol.section = static_cast<std::uint8_t>(reader.value(record.bytes, 5, 1));
            symbol.descriptor = static_cast<std::uint16_t>(reader.value(record.bytes, 6, 2));
            symbol.value = reader.value(record.bytes, 8, slice.header.is_64 ? 8 : 4);
            symbol.name = string_at(strings.bytes, symbol.string_index, budget, stop);
            resolve(symbol, image, metadata);
            if (symbol.state == MachOSymbolState::indirect)
                symbol.indirect_name = string_at(strings.bytes, symbol.value, budget, stop);
            metadata.symbols.push_back(std::move(symbol));
        }
        metadata.symbol_tables.push_back(std::move(table));
    }
}
void read_indirect_symbol_bindings(MachOMetadata &metadata, Budget &budget, std::stop_token stop) {
    constexpr std::uint32_t section_non_lazy_symbol_pointers = 0x6;
    constexpr std::uint32_t section_lazy_symbol_pointers = 0x7;
    constexpr std::uint32_t section_symbol_stubs = 0x8;
    constexpr std::uint32_t section_thread_local_variable_pointers = 0x13;
    constexpr std::uint32_t indirect_symbol_local = 0x80000000;
    constexpr std::uint32_t indirect_symbol_absolute = 0x40000000;
    constexpr std::size_t max_bindings = 1'000'000;
    const auto &header = metadata.container.slices[metadata.selected_slice].header;
    const std::uint64_t pointer_size = header.is_64 ? 8 : 4;
    const bool has_supported_sections = std::any_of(metadata.sections.begin(), metadata.sections.end(),
        [&](const auto &section) {
            const auto type = section.flags & 0xff;
            return type == section_symbol_stubs || type == section_lazy_symbol_pointers ||
                   type == section_non_lazy_symbol_pointers || type == section_thread_local_variable_pointers;
        });
    if (!has_supported_sections)
        return;
    if (metadata.dynamic_symbol_tables.size() != 1) {
        metadata.indirect_symbol_bindings_complete = false;
        return;
    }
    bool capacity_exhausted = false;
    for (const auto &dynamic : metadata.dynamic_symbol_tables) {
        canceled(stop);
        const MachOSymbolTable *symbols = nullptr;
        if (dynamic.symbol_table) {
            for (const auto &table : metadata.symbol_tables) {
                if (table.command_index != *dynamic.symbol_table)
                    continue;
                if (symbols) {
                    symbols = nullptr;
                    metadata.indirect_symbol_bindings_complete = false;
                    break;
                }
                symbols = &table;
            }
            if (!symbols)
                metadata.indirect_symbol_bindings_complete = false;
        }
        for (const auto &section : metadata.sections) {
            canceled(stop);
            const auto section_type = section.flags & 0xff;
            std::uint64_t stride = 0;
            if (section_type == section_symbol_stubs)
                stride = section.reserved2;
            else if (section_type == section_lazy_symbol_pointers ||
                     section_type == section_non_lazy_symbol_pointers ||
                     section_type == section_thread_local_variable_pointers)
                stride = pointer_size;
            else
                continue;
            if (!stride || section.size % stride) {
                metadata.indirect_symbol_bindings_complete = false;
                continue;
            }
            const auto slot_count = section.size / stride;
            if (section.reserved1 > dynamic.indirect_symbols.size() ||
                slot_count > dynamic.indirect_symbols.size() - section.reserved1) {
                metadata.indirect_symbol_bindings_complete = false;
                continue;
            }
            if (metadata.indirect_symbol_bindings.size() > max_bindings ||
                slot_count > max_bindings - metadata.indirect_symbol_bindings.size()) {
                metadata.indirect_symbol_bindings_complete = false;
                capacity_exhausted = true;
                break;
            }
            for (std::uint64_t slot = 0; slot < slot_count; ++slot) {
                canceled(stop);
                const auto table_index = static_cast<std::uint32_t>(section.reserved1 + slot);
                const auto raw_index = dynamic.indirect_symbols[table_index];
                MachOIndirectSymbolBinding binding;
                binding.dynamic_symbol_table_command = dynamic.command_index;
                binding.symbol_table_command = dynamic.symbol_table;
                binding.section_ordinal = section.ordinal;
                binding.section_type = static_cast<std::uint8_t>(section_type);
                binding.slot_index = slot;
                binding.section_offset = slot * stride;
                binding.indirect_table_index = table_index;
                binding.raw_symbol_index = raw_index;
                if (section.file_offset)
                    binding.slot_file_offset = FileOffset{add(section.file_offset->value, binding.section_offset)};
                if (raw_index == indirect_symbol_local)
                    binding.kind = MachOIndirectBindingKind::local;
                else if (raw_index == indirect_symbol_absolute)
                    binding.kind = MachOIndirectBindingKind::absolute;
                else if (raw_index & (indirect_symbol_local | indirect_symbol_absolute)) {
                    binding.kind = MachOIndirectBindingKind::reserved_flags;
                    metadata.indirect_symbol_bindings_complete = false;
                } else {
                    binding.kind = MachOIndirectBindingKind::symbol;
                    if (symbols && raw_index < symbols->count)
                        binding.symbol_index = raw_index;
                    else
                        metadata.indirect_symbol_bindings_complete = false;
                }
                budget.include(sizeof(MachOIndirectSymbolBinding));
                metadata.indirect_symbol_bindings.push_back(std::move(binding));
            }
        }
        if (capacity_exhausted)
            break;
    }
}
} // namespace hexlab::macho_detail
