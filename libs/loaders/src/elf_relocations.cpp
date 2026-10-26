#include "elf_internal.hpp"
#include <algorithm>
#include <bit>
namespace hexlab::elf_detail {
namespace {
struct Field {
    ElfRelocationKind kind;
    std::optional<std::uint64_t> size;
};
Field field(const ElfHeader &header, std::uint32_t type) {
    using K = ElfRelocationKind;
    const auto word = header.is_64 ? 8u : 4u;
    if (type == 0)
        return {K::none, 0};
    if (header.machine == 3) {
        switch (type) {
        case 1:
            return {K::absolute, 4};
        case 2:
            return {K::pc_relative, 4};
        case 4:
            return {K::plt_relative, 4};
        case 3:
        case 9:
        case 10:
        case 43:
            return {K::got, 4};
        case 11:
            return {K::plt_absolute, 4};
        case 5:
            return {K::copy, {}};
        case 6:
            return {K::global_data, 4};
        case 7:
            return {K::jump_slot, 4};
        case 8:
            return {K::base_relative, 4};
        case 20:
            return {K::absolute, 2};
        case 21:
            return {K::pc_relative, 2};
        case 22:
            return {K::absolute, 1};
        case 23:
            return {K::pc_relative, 1};
        case 38:
            return {K::symbol_size, 4};
        case 42:
            return {K::ifunc, 4};
        case 12:
        case 13:
        case 14:
        case 15:
        case 16:
        case 17:
        case 18:
        case 19:
        case 24:
        case 28:
        case 32:
        case 33:
        case 34:
        case 35:
        case 36:
        case 37:
            return {K::tls, 4};
        case 25:
        case 26:
        case 27:
        case 29:
        case 30:
        case 31:
        case 39:
        case 40:
        case 41:
            return {K::tls, {}};
        default:
            break;
        }
    } else if (header.machine == 62) {
        switch (type) {
        case 1:
            return {K::absolute, 8};
        case 2:
            return {K::pc_relative, 4};
        case 4:
            return {K::plt_relative, 4};
        case 3:
        case 9:
        case 26:
        case 41:
        case 42:
        case 43:
        case 46:
        case 49:
            return {K::got, 4};
        case 25:
        case 27:
        case 28:
        case 29:
        case 30:
        case 31:
            return {K::got, 8};
        case 5:
            return {K::copy, {}};
        case 6:
            return {K::global_data, word};
        case 7:
            return {K::jump_slot, word};
        case 8:
            return {K::base_relative, word};
        case 10:
        case 11:
            return {K::absolute, 4};
        case 12:
            return {K::absolute, 2};
        case 13:
            return {K::pc_relative, 2};
        case 14:
            return {K::absolute, 1};
        case 15:
            return {K::pc_relative, 1};
        case 24:
            return {K::pc_relative, 8};
        case 32:
            return {K::symbol_size, 4};
        case 33:
            return {K::symbol_size, 8};
        case 16:
        case 17:
        case 18:
            return {K::tls, 8};
        case 19:
        case 20:
        case 21:
        case 22:
        case 23:
        case 34:
        case 44:
        case 45:
        case 47:
        case 48:
        case 50:
        case 51:
            return {K::tls, 4};
        case 35:
            return {K::tls, 0};
        case 36:
            return {K::tls, 2 * word};
        case 37:
            return {K::ifunc, word};
        case 38:
            return {K::base_relative, 8};
        default:
            break;
        }
    }
    if (header.machine == 183 && header.is_64) {
        switch (type) {
        case 257: return {K::absolute, 8}; // ABS64
        case 258: return {K::absolute, 4}; // ABS32
        case 259: return {K::absolute, 2}; // ABS16
        case 260: return {K::pc_relative, 8}; // PREL64
        case 261: return {K::pc_relative, 4}; // PREL32
        case 262: return {K::pc_relative, 2}; // PREL16
        case 1024: return {K::copy, {}};
        case 1025: return {K::global_data, 8};
        case 1026: return {K::jump_slot, 8};
        case 1027: return {K::base_relative, 8};
        case 1028: case 1029: case 1032: return {K::tls, 8};
        case 1030: case 1033: return {K::tls, 4};
        case 1031: case 1034: return {K::tls, 2};
        case 1035: return {K::tls, 16}; // TLSDESC pair
        case 1036: return {K::ifunc, 8}; // IRELATIVE
        case 282: case 283: return {K::pc_relative, 4}; // CALL26/JUMP26
        default: break;
        }
    }
    if (header.machine == 40 && !header.is_64) {
        switch (type) {
        case 2: return {K::absolute, 4}; // R_ARM_ABS32
        case 3: return {K::pc_relative, 4}; // R_ARM_REL32
        case 5: return {K::absolute, 2}; // R_ARM_ABS16
        case 8: return {K::absolute, 1}; // R_ARM_ABS8
        case 20: return {K::copy, {}}; // R_ARM_COPY
        case 21: return {K::global_data, 4}; // R_ARM_GLOB_DAT
        case 22: return {K::jump_slot, 4}; // R_ARM_JUMP_SLOT
        case 23: return {K::base_relative, 4}; // R_ARM_RELATIVE
        default: break;
        }
    }
    if (header.machine == 21 && header.is_64) {
        switch (type) {
        case 20: return {K::global_data, 8}; // R_PPC64_GLOB_DAT
        case 22: return {K::base_relative, 8}; // R_PPC64_RELATIVE
        case 38: return {K::absolute, 8}; // R_PPC64_ADDR64
        default: break;
        }
    }
    if (header.machine == 243) {
        switch (type) {
        case 1: return {K::absolute, 4}; // R_RISCV_32
        case 2:
            if (header.is_64) return {K::absolute, 8}; // R_RISCV_64
            break;
        case 3: return {K::base_relative, word}; // R_RISCV_RELATIVE
        case 4: return {K::copy, {}}; // R_RISCV_COPY
        case 5: return {K::jump_slot, word}; // R_RISCV_JUMP_SLOT
        case 6: case 8: case 10: return {K::tls, 4};
        case 7: case 9: case 11: return {K::tls, 8};
        case 12: return {K::tls, 2 * word}; // R_RISCV_TLSDESC
        case 58: return {K::ifunc, word}; // R_RISCV_IRELATIVE
        default: break;
        }
    }
    return {K::unknown, {}};
}
std::uint32_t relative_type(const ElfHeader &header) {
    // RELR carries locations rather than r_info, so use the architecture's
    // ordinary RELATIVE number only when it is known. The semantic kind is
    // supplied by the RELR encoding itself.
    switch (header.machine) {
    case 3: return 8;       // EM_386: R_386_RELATIVE
    case 8: return 3;       // EM_MIPS: R_MIPS_REL32
    case 20: return 22;     // EM_PPC: R_PPC_RELATIVE
    case 21: return 22;     // EM_PPC64: R_PPC64_RELATIVE
    case 40: return 23;     // EM_ARM: R_ARM_RELATIVE
    case 62: return 8;      // EM_X86_64: R_X86_64_RELATIVE
    case 183: return 1027;  // EM_AARCH64: R_AARCH64_RELATIVE
    case 243: return 3;     // EM_RISCV: R_RISCV_RELATIVE
    default: return 0;
    }
}
std::int64_t signed_value(std::uint64_t value, std::size_t n) {
    if (n < 8 && (value & (std::uint64_t{1} << (n * 8 - 1))))
        value |= UINT64_MAX << (n * 8);
    return std::bit_cast<std::int64_t>(value);
}
bool uses_addend(ElfRelocationKind kind) {
    using K = ElfRelocationKind;
    return kind == K::absolute || kind == K::pc_relative || kind == K::plt_relative || kind == K::plt_absolute ||
           kind == K::base_relative || kind == K::got || kind == K::symbol_size || kind == K::ifunc;
}
void map_place(ElfRelocation &row, const ElfSection *target, const Image &image, const Reader &reader, bool implicit,
               bool implicit_global_addend = false) {
    if (row.kind == ElfRelocationKind::none)
        return;
    const auto extent = row.field_size.value_or(1);
    const auto sample_addend = implicit && (uses_addend(row.kind) ||
        (implicit_global_addend && row.kind == ElfRelocationKind::global_data)) &&
        row.field_size && extent && extent <= 8;
    if (target) {
        require(row.offset <= target->size && extent <= target->size - row.offset,
                "ELF relocation field exceeds target section");
        const Address address{{target->index}, row.offset};
        if (image.segment_at(address))
            row.place = address;
        if (target->type != 8 && extent)
            row.file_place = FileOffset{add(target->offset, row.offset)};
        if (sample_addend) {
            if (target->type == 8)
                row.addend = 0;
            else {
                const auto bytes = reader.bytes(row.file_place->value, static_cast<std::size_t>(extent));
                row.addend = signed_value(reader.value(bytes.bytes, 0, static_cast<std::size_t>(extent)),
                                          static_cast<std::size_t>(extent));
            }
        }
        return;
    }
    const Address at{{0}, row.offset};
    auto remaining = extent, cursor = row.offset;
    std::uint64_t raw = 0;
    std::size_t done = 0;
    std::optional<std::uint64_t> file;
    bool contiguous = true;
    while (remaining) {
        const auto *segment = image.segment_at({{0}, cursor});
        require(segment != nullptr, "ELF relocation points outside mapped memory");
        const auto relative = cursor - segment->begin.offset;
        const auto count = std::min(remaining, segment->size - relative);
        auto initialized = relative < segment->file_size ? std::min(count, segment->file_size - relative) : 0;
        if (initialized) {
            const auto position = add(segment->file_begin.value, relative);
            if (!file) {
                if (done)
                    contiguous = false;
                else
                    file = position;
            } else if (position != add(*file, done))
                contiguous = false;
            if (sample_addend) {
                const auto bytes = reader.bytes(position, static_cast<std::size_t>(initialized));
                // Place addends are assembled in virtual order, independent of
                // how normalized mappings split their canonical file ranges.
                for (std::size_t i = 0; i < initialized; ++i) {
                    const auto shift =
                        image.layout().space.order == ByteOrder::little ? done + i : extent - done - i - 1;
                    raw |= std::to_integer<std::uint64_t>(bytes.bytes[i]) << (8 * shift);
                }
            }
        }
        if (initialized < count)
            contiguous = false;
        cursor = add(cursor, count);
        done += static_cast<std::size_t>(count);
        remaining -= count;
    }
    if (image.segment_at(at))
        row.place = at;
    if (contiguous && file)
        row.file_place = FileOffset{*file};
    if (sample_addend)
        row.addend = signed_value(raw, static_cast<std::size_t>(extent));
}
} // namespace
std::uint64_t read_relocation_table(const Reader &reader, const Image &image, ElfMetadata &metadata,
                                    const RelocationInput &input, Budget &budget, RelocationRegistry &registry,
                                    std::stop_token stop) {
    const auto word = metadata.header.is_64 ? 8u : 4u;
    const auto minimum = (input.rela ? 3u : 2u) * word;
    require(input.stride >= minimum && input.size % input.stride == 0, "Invalid ELF relocation stride/extent");
    require(input.size <= metadata_limit, "ELF relocation array extent exceeds budget", ErrorCode::resource_limit);
    const auto count = input.size / input.stride;
    const std::optional<ElfTableSource> symbols = input.symbols ? std::optional{input.symbols->source} : std::nullopt;
    const RelocationRegistry::TableKey table_key{source_key(input.source), input.size,  input.stride, input.rela,
                                                 source_key(symbols),      input.target};
    if (const auto found = registry.tables.find(table_key); found != registry.tables.end())
        return found->second;
    require(count <= 1000000 - registry.processed, "ELF relocation record budget exceeded", ErrorCode::resource_limit);
    budget.include(sizeof(ElfRelocationTable) + count * sizeof(std::uint64_t) + sizeof(table_key) +
                   sizeof(std::uint64_t) + 3 * sizeof(void *));
    ElfRelocationTable table{input.source, input.size, input.stride, input.rela, symbols, input.target, {}};
    table.rows.reserve(static_cast<std::size_t>(count));
    const ElfSection *target = nullptr;
    if (metadata.header.object_type == 1) {
        require(input.target && *input.target < metadata.sections.size() && metadata.sections[*input.target].type != 0,
                "Relocatable ELF relocation requires target section");
        target = &metadata.sections[*input.target];
    }
    // Linked files can retain static relocations for post-link tools. Those
    // records name SYMTAB, and their REL fields already contain linked results.
    const bool retained = metadata.header.object_type != 1 && input.target && input.source.section &&
                          !(metadata.sections[*input.source.section].flags & 2) && input.symbols &&
                          input.symbols->source.section && metadata.sections[*input.symbols->source.section].type == 2;
    if (metadata.header.object_type != 1 && input.target && !(metadata.sections[*input.target].flags & 2))
        target = &metadata.sections[*input.target];
    for (std::uint32_t index = 0; index < count; ++index) {
        canceled(stop);
        ++registry.processed;
        const auto offset = input.stride * index;
        ByteView bytes;
        std::uint64_t record_file;
        if (input.source.address) {
            const auto at = take(advance(*input.source.address, offset));
            record_file = take(image.to_file_offset(at)).value;
            bytes = read_virtual(reader, image, at, minimum, budget, stop);
        } else {
            record_file = add(input.source.file_offset, offset);
            bytes = reader.bytes(record_file, minimum);
        }
        ElfRelocation row;
        row.source = input.source;
        row.index = index;
        row.explicit_addend = input.rela;
        row.target_section = input.target;
        row.record_file_offset = record_file;
        row.record_stride = input.stride;
        row.offset = reader.value(bytes.bytes, 0, word);
        const auto info = reader.value(bytes.bytes, word, word);
        row.type = static_cast<std::uint32_t>(metadata.header.is_64 ? info & UINT32_MAX : info & 255);
        row.symbol_index = static_cast<std::uint32_t>(info >> (metadata.header.is_64 ? 32 : 8));
        if (input.rela)
            row.addend = signed_value(reader.value(bytes.bytes, 2 * word, word), word);
        const auto description = field(metadata.header, row.type);
        row.kind = description.kind;
        row.field_size = description.size;
        const bool unused = row.symbol_index == 0 &&
                            (row.kind == ElfRelocationKind::none || row.kind == ElfRelocationKind::base_relative ||
                             row.kind == ElfRelocationKind::ifunc);
        const ElfSymbol *symbol = nullptr;
        if (input.symbols) {
            row.symbol_table = input.symbols->source;
            if (input.symbols->count && input.symbols->symbol_begin) {
                require(row.symbol_index < *input.symbols->count, "ELF relocation symbol index is outside table");
                row.symbol_index_validated = true;
                symbol = &metadata.symbols[static_cast<std::size_t>(*input.symbols->symbol_begin + row.symbol_index)];
            } else {
                row.symbol_index_validated = unused;
                metadata.relocations_complete = false;
            }
        } else {
            require(row.symbol_index == 0, "ELF symbolic relocation requires a symbol table");
            row.symbol_index_validated = true;
        }
        if (row.kind == ElfRelocationKind::base_relative || row.kind == ElfRelocationKind::ifunc)
            require(row.symbol_index == 0, "ELF base/IFUNC relative relocation requires symbol0");
        if (row.kind == ElfRelocationKind::copy && symbol)
            row.field_size = symbol->size;
        if (row.kind == ElfRelocationKind::unknown || !row.field_size)
            metadata.relocations_complete = false;
        const bool packed_rel = metadata.header.machine == 183 && (row.type == 282 || row.type == 283) && !input.rela;
        if (packed_rel)
            metadata.relocations_complete = false;
        map_place(row, target, image, reader, !input.rela && !retained && !packed_rel,
                  metadata.header.machine == 40);
        const RelocationRegistry::RowKey key{record_file, minimum, source_key(unused ? std::nullopt : row.symbol_table),
                                             metadata.header.object_type == 1 ? input.target : std::nullopt};
        if (const auto found = registry.rows.find(key); found != registry.rows.end()) {
            const auto &old = metadata.relocations[static_cast<std::size_t>(found->second)];
            require(old.offset == row.offset && old.type == row.type && old.symbol_index == row.symbol_index &&
                        old.kind == row.kind && old.field_size == row.field_size && old.addend == row.addend &&
                        old.explicit_addend == row.explicit_addend && old.place == row.place &&
                        old.file_place == row.file_place,
                    "Conflicting ELF relocation aliases");
            table.rows.push_back(found->second);
        } else {
            budget.include(sizeof(ElfRelocation) + sizeof(key) + sizeof(std::uint64_t) + 3 * sizeof(void *));
            const auto id = static_cast<std::uint64_t>(metadata.relocations.size());
            registry.rows.emplace(key, id);
            metadata.relocations.push_back(std::move(row));
            table.rows.push_back(id);
        }
    }
    const auto id = static_cast<std::uint64_t>(metadata.relocation_tables.size());
    registry.tables.emplace(table_key, id);
    metadata.relocation_tables.push_back(std::move(table));
    return id;
}
std::uint64_t read_relr_table(const Reader &reader, const Image &image, ElfMetadata &metadata,
                              const ElfTableSource &source, std::uint64_t size, std::uint64_t stride,
                              std::optional<std::uint32_t> target_section, Budget &budget,
                              RelocationRegistry &registry, std::stop_token stop) {
    require(metadata.header.object_type == 2 || metadata.header.object_type == 3,
            "ELF RELR is valid only for ET_EXEC or ET_DYN", ErrorCode::unsupported);
    const std::uint64_t word = metadata.header.is_64 ? 8 : 4;
    require(stride == word && size % word == 0, "Invalid ELF RELR entry width or table extent");
    require(size <= metadata_limit, "ELF RELR table exceeds metadata budget", ErrorCode::resource_limit);
    const auto entry_count = size / word;
    require(entry_count <= 1000000, "ELF RELR entry count exceeds budget", ErrorCode::resource_limit);
    const RelocationRegistry::TableKey table_key{source_key(source), size, stride, false, {}, target_section};
    if (const auto found = registry.tables.find(table_key); found != registry.tables.end())
        return found->second;

    require(registry.processed <= 1000000, "ELF relocation record budget exceeded", ErrorCode::resource_limit);
    budget.include(sizeof(ElfRelocationTable) + entry_count * sizeof(std::uint64_t) + sizeof(table_key) +
                   sizeof(std::uint64_t) + 3 * sizeof(void *));
    ElfRelocationTable table{source, size, stride, false, {}, target_section, {}};
    const auto max_rows = 1000000 - registry.processed;
    table.rows.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(entry_count, max_rows)));
    const auto bits = static_cast<unsigned>(word * 8);
    std::optional<std::uint64_t> next;
    std::optional<std::uint64_t> last_location;
    const auto mapped_source = [&](std::uint64_t byte_offset, std::uint64_t &record_file) {
        ByteView bytes;
        if (source.address) {
            const auto at = take(advance(*source.address, byte_offset));
            record_file = take(image.to_file_offset(at)).value;
            bytes = read_virtual(reader, image, at, static_cast<std::size_t>(word), budget, stop);
        } else {
            record_file = add(source.file_offset, byte_offset);
            bytes = reader.bytes(record_file, static_cast<std::size_t>(word));
        }
        return bytes;
    };
    auto append_location = [&](std::uint64_t location, std::uint32_t index, std::uint64_t record_file) {
        canceled(stop);
        require(location % word == 0, "ELF RELR target is not word-aligned");
        require(location <= UINT64_MAX - word, "ELF RELR target extent overflows", ErrorCode::overflow);
        require(!last_location || location > *last_location, "ELF RELR targets are duplicated or out of order");
        last_location = location;
        require(registry.processed < 1000000, "ELF relocation record budget exceeded", ErrorCode::resource_limit);
        ++registry.processed;
        ElfRelocation row;
        row.source = source;
        row.index = index;
        row.type = relative_type(metadata.header);
        row.symbol_index = 0;
        row.symbol_index_validated = true;
        row.target_section = target_section;
        row.offset = location;
        row.explicit_addend = false;
        row.field_size = word;
        row.kind = ElfRelocationKind::base_relative;
        row.record_file_offset = record_file;
        row.record_stride = word;
        const ElfSection *target = nullptr;
        if (target_section) {
            require(*target_section < metadata.sections.size(), "ELF RELR target section is invalid");
            target = &metadata.sections[*target_section];
        }
        map_place(row, target, image, reader, true);
        // A bitmap may encode many target locations in one source word. Key
        // identity by target while preserving the source word in row provenance.
        const RelocationRegistry::RowKey row_key{location, word, {}, target_section};
        if (const auto found = registry.rows.find(row_key); found != registry.rows.end()) {
            const auto &old = metadata.relocations[static_cast<std::size_t>(found->second)];
            require(old.offset == row.offset && old.kind == row.kind && old.field_size == row.field_size &&
                        old.addend == row.addend && old.explicit_addend == row.explicit_addend &&
                        old.place == row.place && old.file_place == row.file_place,
                    "Conflicting ELF RELR aliases");
            table.rows.push_back(found->second);
        } else {
            budget.include(sizeof(ElfRelocation) + sizeof(row_key) + sizeof(std::uint64_t) + 3 * sizeof(void *));
            const auto id = static_cast<std::uint64_t>(metadata.relocations.size());
            registry.rows.emplace(row_key, id);
            metadata.relocations.push_back(std::move(row));
            table.rows.push_back(id);
        }
    };
    std::uint32_t expanded_index = 0;
    for (std::uint64_t i = 0; i < entry_count; ++i) {
        canceled(stop);
        std::uint64_t record_file = 0;
        const auto bytes = mapped_source(i * word, record_file);
        const auto entry = reader.value(bytes.bytes, 0, static_cast<std::size_t>(word));
        if ((entry & 1) == 0) {
            require(entry % word == 0, "ELF RELR direct address is not word-aligned");
            append_location(entry, expanded_index++, record_file);
            require(entry <= UINT64_MAX - word, "ELF RELR direct address overflows", ErrorCode::overflow);
            next = entry + word;
            continue;
        }
        require(next.has_value(), "ELF RELR bitmap appears before a direct address");
        const auto bitmap = entry >> 1;
        for (unsigned bit = 0; bit < bits - 1; ++bit) {
            if ((bitmap & (std::uint64_t{1} << bit)) == 0)
                continue;
            require(bit <= (UINT64_MAX - *next) / word, "ELF RELR bitmap target overflows", ErrorCode::overflow);
            append_location(*next + static_cast<std::uint64_t>(bit) * word, expanded_index++, record_file);
        }
        const auto advance_words = static_cast<std::uint64_t>(bits - 1) * word;
        require(*next <= UINT64_MAX - advance_words, "ELF RELR bitmap cursor overflows", ErrorCode::overflow);
        next = *next + advance_words;
    }
    const auto id = static_cast<std::uint64_t>(metadata.relocation_tables.size());
    registry.tables.emplace(table_key, id);
    metadata.relocation_tables.push_back(std::move(table));
    return id;
}
std::uint64_t read_android_packed_relocation_table(const Reader &reader, const Image &image,
                                                   ElfMetadata &metadata, const ElfTableSource &source,
                                                   std::uint64_t size, bool rela,
                                                   const ElfSymbolTable *symbols, Budget &budget,
                                                   RelocationRegistry &registry, std::stop_token stop) {
    require(metadata.header.object_type == 2 || metadata.header.object_type == 3,
            "Android packed ELF relocations require ET_EXEC or ET_DYN", ErrorCode::unsupported);
    require(size >= 5 && size <= metadata_limit, "Android packed ELF relocation extent is invalid",
            ErrorCode::resource_limit);
    const auto symbol_source = symbols ? std::optional{symbols->source} : std::nullopt;
    const RelocationRegistry::TableKey key{source_key(source), size, 0, rela, source_key(symbol_source), {}};
    if (const auto found = registry.tables.find(key); found != registry.tables.end())
        return found->second;

    ByteView packed;
    if (source.address)
        packed = read_virtual(reader, image, *source.address, static_cast<std::size_t>(size), budget, stop);
    else {
        budget.include(size);
        packed = reader.bytes(source.file_offset, static_cast<std::size_t>(size));
    }
    require(packed.bytes[0] == std::byte{'A'} && packed.bytes[1] == std::byte{'P'} &&
                packed.bytes[2] == std::byte{'S'} && packed.bytes[3] == std::byte{'2'},
            "Android packed ELF relocation magic is not APS2");
    std::size_t cursor = 4;
    const auto sleb = [&]() -> std::int64_t {
        std::uint64_t bits = 0;
        unsigned shift = 0;
        for (unsigned index = 0; index < 10; ++index) {
            require(cursor < packed.bytes.size(), "Truncated Android packed ELF relocation integer");
            const auto byte = std::to_integer<std::uint8_t>(packed.bytes[cursor++]);
            const auto payload = static_cast<std::uint8_t>(byte & 0x7f);
            if (shift == 63) {
                require(payload == 0 || payload == 0x7f,
                        "Android packed ELF relocation integer overflows 64 bits");
                if (payload == 0x7f) bits |= (std::uint64_t{1} << 63);
            } else {
                bits |= static_cast<std::uint64_t>(payload) << shift;
            }
            if ((byte & 0x80) == 0) {
                if (shift < 63 && (byte & 0x40)) bits |= UINT64_MAX << (shift + 7);
                return std::bit_cast<std::int64_t>(bits);
            }
            shift += 7;
        }
        require(false, "Android packed ELF relocation integer is too long", ErrorCode::malformed);
        return 0;
    };
    const auto nonnegative = [&](const char *what) -> std::uint64_t {
        const auto value = sleb();
        require(value >= 0, what);
        return static_cast<std::uint64_t>(value);
    };
    const auto count = nonnegative("Android packed ELF relocation count is negative");
    require(registry.processed <= 1000000 && count <= 1000000 && count <= 1000000 - registry.processed,
            "Android packed ELF relocation count exceeds budget", ErrorCode::resource_limit);
    auto relocation_offset = nonnegative("Android packed ELF relocation base offset is negative");
    budget.include(sizeof(ElfRelocationTable) + count * sizeof(std::uint64_t) + sizeof(key) +
                   sizeof(std::uint64_t) + 3 * sizeof(void *));
    ElfRelocationTable table{source, size, 0, rela, symbol_source, {}, {}};
    table.rows.reserve(static_cast<std::size_t>(count));
    std::int64_t addend = 0;
    std::uint64_t emitted = 0;
    const auto checked_addend = [](std::int64_t left, std::int64_t right) {
        require((right <= 0 || left <= INT64_MAX - right) &&
                    (right >= 0 || left >= INT64_MIN - right),
                "Android packed ELF relocation addend overflows", ErrorCode::overflow);
        return static_cast<std::int64_t>(left + right);
    };
    while (emitted < count) {
        canceled(stop);
        const auto group_source_offset = cursor;
        const auto group_size = nonnegative("Android packed ELF relocation group size is negative");
        const auto flags = nonnegative("Android packed ELF relocation group flags are negative");
        require(group_size && group_size <= count - emitted && (flags & ~UINT64_C(15)) == 0,
                "Invalid Android packed ELF relocation group", ErrorCode::malformed);
        constexpr std::uint64_t by_info = 1, by_offset = 2, by_addend = 4, has_addend = 8;
        require(!(flags & by_addend) || (flags & has_addend),
                "Android packed ELF relocation group has invalid addend flags");
        require(rela || !(flags & (by_addend | has_addend)),
                "Android REL packed group unexpectedly carries addends");
        const auto group_offset_delta = (flags & by_offset)
            ? nonnegative("Android packed ELF relocation offset delta is negative") : 0;
        std::uint64_t group_info = 0;
        if (flags & by_info) group_info = static_cast<std::uint64_t>(sleb());
        std::int64_t group_addend_delta = 0;
        if ((flags & (by_addend | has_addend)) == (by_addend | has_addend))
            group_addend_delta = sleb();
        if (rela && !(flags & has_addend)) addend = 0;
        const auto first_group_row = table.rows.size();
        for (std::uint64_t in_group = 0; in_group < group_size; ++in_group) {
            canceled(stop);
            const auto delta = (flags & by_offset)
                ? group_offset_delta : nonnegative("Android packed ELF relocation offset delta is negative");
            require(delta <= UINT64_MAX - relocation_offset,
                    "Android packed ELF relocation offset overflows", ErrorCode::overflow);
            relocation_offset += delta;
            const auto info = (flags & by_info) ? group_info : static_cast<std::uint64_t>(sleb());
            const auto type = static_cast<std::uint32_t>(metadata.header.is_64 ? info & UINT32_MAX : info & 255);
            const auto symbol_index = static_cast<std::uint32_t>(info >> (metadata.header.is_64 ? 32 : 8));
            if (rela && (flags & has_addend))
                addend = checked_addend(addend, (flags & by_addend) ? group_addend_delta : sleb());
            require(registry.processed < 1000000, "ELF relocation record budget exceeded", ErrorCode::resource_limit);
            ++registry.processed;
            ElfRelocation row;
            row.source = source;
            row.index = static_cast<std::uint32_t>(emitted);
            row.type = type;
            row.symbol_index = symbol_index;
            row.explicit_addend = rela;
            row.target_section.reset();
            row.offset = relocation_offset;
            if (rela) row.addend = addend;
            const auto description = field(metadata.header, row.type);
            row.kind = description.kind;
            row.field_size = description.size;
            const bool unused = row.symbol_index == 0 &&
                (row.kind == ElfRelocationKind::none || row.kind == ElfRelocationKind::base_relative ||
                 row.kind == ElfRelocationKind::ifunc);
            const ElfSymbol *symbol = nullptr;
            if (symbols) {
                row.symbol_table = symbols->source;
                if (symbols->count && symbols->symbol_begin) {
                    require(row.symbol_index < *symbols->count,
                            "Android packed ELF relocation symbol index is outside table");
                    row.symbol_index_validated = true;
                    symbol = &metadata.symbols[static_cast<std::size_t>(*symbols->symbol_begin + row.symbol_index)];
                } else {
                    row.symbol_index_validated = unused;
                    metadata.relocations_complete = false;
                }
            } else {
                require(row.symbol_index == 0,
                        "Android packed ELF symbolic relocation requires a symbol table");
                row.symbol_index_validated = true;
            }
            if (row.kind == ElfRelocationKind::base_relative || row.kind == ElfRelocationKind::ifunc)
                require(row.symbol_index == 0, "ELF base/IFUNC relative relocation requires symbol0");
            if (row.kind == ElfRelocationKind::copy && symbol) row.field_size = symbol->size;
            if (row.kind == ElfRelocationKind::unknown || !row.field_size) metadata.relocations_complete = false;
            row.record_file_offset = source.address
                ? take(image.to_file_offset(take(advance(*source.address, group_source_offset)))).value
                : add(source.file_offset, group_source_offset);
            row.record_stride = 0;
            map_place(row, nullptr, image, reader, !rela);
            budget.include(sizeof(ElfRelocation) + 3 * sizeof(void *));
            const auto id = static_cast<std::uint64_t>(metadata.relocations.size());
            metadata.relocations.push_back(std::move(row));
            table.rows.push_back(id);
            ++emitted;
        }
        require(cursor > group_source_offset, "Android packed ELF relocation group consumed no input");
        const auto group_extent = cursor - group_source_offset;
        for (auto row = first_group_row; row < table.rows.size(); ++row)
            metadata.relocations[static_cast<std::size_t>(table.rows[static_cast<std::size_t>(row)])].record_stride =
                group_extent;
    }
    require(cursor == packed.bytes.size(), "Trailing bytes follow Android packed ELF relocations");
    const auto id = static_cast<std::uint64_t>(metadata.relocation_tables.size());
    registry.tables.emplace(key, id);
    metadata.relocation_tables.push_back(std::move(table));
    return id;
}
void read_relocations(const ByteStorage &storage, const Image &image, ElfMetadata &metadata, Budget &budget,
                      RelocationRegistry &registry, std::stop_token stop) {
    if (std::none_of(metadata.sections.begin(), metadata.sections.end(),
                     [](const auto &s) { return s.type == 4 || s.type == 9 || s.type == 19; }))
        return;
    budget.include(metadata.sections.size() * sizeof(const ElfSymbolTable *));
    std::vector<const ElfSymbolTable *> symbols(metadata.sections.size());
    for (const auto &table : metadata.symbol_tables)
        if (table.source.section)
            symbols[*table.source.section] = &table;
    Reader reader(storage, metadata.header.order, stop);
    for (const auto &section : metadata.sections) {
        canceled(stop);
        if (section.type == 19) {
            require(!(section.flags & 0x800), "Compressed ELF RELR sections are unsupported", ErrorCode::unsupported);
            require(section.link == 0 && section.info == 0, "ELF RELR section must not link a symbol or target section");
            const auto word = metadata.header.is_64 ? 8u : 4u;
            require(section.entry_size == word, "ELF RELR sh_entsize must equal the ELF word size");
            (void)read_relr_table(reader, image, metadata, {section.index, section.offset, {}}, section.size,
                                  section.entry_size, {}, budget, registry, stop);
            continue;
        }
        if ((section.type != 4 && section.type != 9) || (section.flags & 0x800))
            continue;
        const ElfSymbolTable *symbol_table = nullptr;
        if (section.link) {
            require(section.link < metadata.sections.size() &&
                        (metadata.sections[section.link].type == 2 || metadata.sections[section.link].type == 11),
                    "ELF relocation link must name symbol table");
            symbol_table = symbols[section.link];
            require(symbol_table != nullptr, "ELF relocation symbol table is unavailable", ErrorCode::unsupported);
        }
        if (section.info)
            require(section.info < metadata.sections.size() && metadata.sections[section.info].type != 0,
                    "ELF relocation target section is invalid");
        const auto target = section.info ? std::optional{section.info} : std::nullopt;
        (void)read_relocation_table(reader, image, metadata,
                                    {{section.index, section.offset, {}},
                                     section.size,
                                     section.entry_size,
                                     section.type == 4,
                                     target,
                                     symbol_table},
                                    budget, registry, stop);
    }
}
} // namespace hexlab::elf_detail
