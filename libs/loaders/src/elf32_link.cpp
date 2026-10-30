#include "hexlab/loaders/elf_link.hpp"
#include "hexlab/loaders/elf.hpp"
#include "hexlab/image/elf_metadata.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <optional>
#include <tuple>

namespace hexlab {
namespace {
struct Failure { Error error; };
void require(bool condition, std::string message, ErrorCode code = ErrorCode::malformed) {
    if (!condition) throw Failure{{code, std::move(message)}};
}
void canceled(std::stop_token stop) {
    require(!stop.stop_requested(), "ELF32 link canceled", ErrorCode::canceled);
}
std::uint64_t align_up(std::uint64_t value, std::uint64_t alignment) {
    require(alignment && (alignment & (alignment - 1)) == 0,
            "ELF32 section alignment is not a power of two");
    require(value <= UINT64_MAX - (alignment - 1), "ELF32 layout alignment overflows", ErrorCode::resource_limit);
    return (value + alignment - 1) & ~(alignment - 1);
}
void put(std::vector<std::byte> &bytes, std::size_t offset, std::uint64_t value, std::size_t width) {
    require(offset <= bytes.size() && width <= bytes.size() - offset,
            "ELF32 output field exceeds output extent", ErrorCode::resource_limit);
    for (std::size_t i = 0; i < width; ++i)
        bytes[offset + i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
}
std::uint32_t read32(std::span<const std::byte> bytes) {
    require(bytes.size() == 4, "ELF32 relocation addend has an invalid width");
    return std::to_integer<std::uint32_t>(bytes[0]) |
           (std::to_integer<std::uint32_t>(bytes[1]) << 8) |
           (std::to_integer<std::uint32_t>(bytes[2]) << 16) |
           (std::to_integer<std::uint32_t>(bytes[3]) << 24);
}
std::uint16_t read16(std::span<const std::byte> bytes) {
    require(bytes.size() == 2, "ELF32 relocation addend has an invalid width");
    return std::to_integer<std::uint16_t>(bytes[0]) |
           (std::to_integer<std::uint16_t>(bytes[1]) << 8);
}
struct Placement {
    std::uint16_t output_section = 0;
    std::uint64_t offset = 0, local_offset = 0, size = 0;
};
struct Object {
    ElfMetadata elf;
    std::map<std::uint32_t, Placement> sections;
    std::array<std::vector<std::byte>, 4> bytes;
    std::array<std::uint64_t, 4> local_ends{};
};
struct Definition {
    std::size_t object = 0;
    std::uint32_t symbol_index = 0;
    bool strong = false, common = false;
    std::uint64_t common_size = 0, common_alignment = 1, common_offset = 0;
};
struct OutputSymbol {
    std::string name;
    std::uint8_t info = 0, other = 0;
    std::uint16_t section = 0;
    std::uint32_t value = 0, size = 0;
};
std::vector<std::byte> make_output(const std::array<std::vector<std::byte>, 4> &sections,
                                  std::uint64_t bss_size, const std::array<std::uint64_t, 4> &alignments,
                                  const std::vector<OutputSymbol> &symbols, std::uint64_t max_output) {
    std::vector<std::byte> strings{std::byte{0}};
    std::vector<std::uint32_t> symbol_names;
    symbol_names.reserve(symbols.size());
    for (const auto &symbol : symbols) {
        require(symbol.name.size() < max_output && strings.size() <= max_output - symbol.name.size() - 1 &&
                    symbol.name.size() < UINT32_MAX && strings.size() <= UINT32_MAX - symbol.name.size() - 1,
                "ELF32 symbol string table exceeds 32-bit offsets", ErrorCode::resource_limit);
        symbol_names.push_back(static_cast<std::uint32_t>(strings.size()));
        for (const char ch : symbol.name) strings.push_back(static_cast<std::byte>(ch));
        strings.push_back(std::byte{0});
    }
    std::vector<std::byte> symtab(16, std::byte{0});
    std::uint32_t local_count = 1;
    for (std::size_t i = 0; i < symbols.size(); ++i) {
        const auto &symbol = symbols[i];
        const auto at = symtab.size();
        require(at <= max_output && 16 <= max_output - at && at <= UINT32_MAX - 16,
                "ELF32 symbol table exceeds configured limit", ErrorCode::resource_limit);
        symtab.resize(at + 16);
        put(symtab, at, symbol_names[i], 4);
        put(symtab, at + 4, symbol.value, 4);
        put(symtab, at + 8, symbol.size, 4);
        put(symtab, at + 12, symbol.info, 1);
        put(symtab, at + 13, symbol.other, 1);
        put(symtab, at + 14, symbol.section, 2);
        if ((symbol.info >> 4) == 0) ++local_count;
    }

    std::vector<std::byte> shstrings{std::byte{0}};
    const auto name = [&](std::string_view text) {
        const auto offset = static_cast<std::uint32_t>(shstrings.size());
        for (char ch : text) shstrings.push_back(static_cast<std::byte>(ch));
        shstrings.push_back(std::byte{0});
        return offset;
    };
    const auto text_name = name(".text");
    const auto rodata_name = name(".rodata");
    const auto data_name = name(".data");
    const auto bss_name = name(".bss");
    const auto str_name = name(".strtab");
    const auto sym_name = name(".symtab");
    const auto shstr_name = name(".shstrtab");

    std::vector<std::byte> out(52, std::byte{0});
    std::array<std::uint32_t, 4> offsets{};
    for (std::size_t i = 0; i < sections.size(); ++i) {
        require(sections[i].size() <= UINT32_MAX, "ELF32 section size exceeds 32-bit format", ErrorCode::resource_limit);
        const auto alignment = std::max<std::uint64_t>(1, alignments[i]);
        const auto at = align_up(out.size(), alignment);
        require(at <= UINT32_MAX && at <= max_output && sections[i].size() <= max_output - at,
                "ELF32 linked section data exceeds output limit", ErrorCode::resource_limit);
        out.resize(static_cast<std::size_t>(at));
        offsets[i] = static_cast<std::uint32_t>(at);
        out.insert(out.end(), sections[i].begin(), sections[i].end());
    }
    const auto bss_offset = align_up(out.size(), std::max<std::uint64_t>(1, alignments[3]));
    require(bss_offset <= UINT32_MAX && bss_offset <= max_output && bss_size <= UINT32_MAX,
            "ELF32 .bss exceeds output limits", ErrorCode::resource_limit);
    require(strings.size() <= UINT32_MAX, "ELF32 string table exceeds 32-bit size", ErrorCode::resource_limit);
    require(out.size() <= UINT32_MAX && out.size() <= max_output && strings.size() <= max_output - out.size(),
            "ELF32 string table exceeds output limit", ErrorCode::resource_limit);
    const auto str_offset = out.size(); out.insert(out.end(), strings.begin(), strings.end());
    const auto sym_offset = align_up(out.size(), 4);
    require(sym_offset <= UINT32_MAX && sym_offset <= max_output && symtab.size() <= UINT32_MAX,
            "ELF32 symbol table exceeds 32-bit format", ErrorCode::resource_limit);
    out.resize(static_cast<std::size_t>(sym_offset));
    require(sym_offset <= max_output && symtab.size() <= max_output - sym_offset,
            "ELF32 symbol table exceeds output limit", ErrorCode::resource_limit);
    out.insert(out.end(), symtab.begin(), symtab.end());
    require(out.size() <= UINT32_MAX && shstrings.size() <= UINT32_MAX,
            "ELF32 section-name table exceeds 32-bit format", ErrorCode::resource_limit);
    require(out.size() <= max_output && shstrings.size() <= max_output - out.size(),
            "ELF32 section-name table exceeds output limit", ErrorCode::resource_limit);
    const auto shstr_offset = out.size(); out.insert(out.end(), shstrings.begin(), shstrings.end());
    const auto shoff = align_up(out.size(), 4);
    require(shoff <= UINT32_MAX && 8 * 40 <= UINT32_MAX - shoff && shoff <= max_output && 8 * 40 <= max_output - shoff,
            "ELF32 section table exceeds output limit", ErrorCode::resource_limit);
    out.resize(static_cast<std::size_t>(shoff + 8 * 40));
    const auto section = [&](std::size_t index, std::uint32_t section_name, std::uint32_t type,
                             std::uint32_t flags, std::uint32_t offset, std::uint32_t size,
                             std::uint32_t link, std::uint32_t info, std::uint32_t alignment,
                             std::uint32_t entry_size) {
        const auto at = static_cast<std::size_t>(shoff) + index * 40;
        put(out, at, section_name, 4); put(out, at + 4, type, 4); put(out, at + 8, flags, 4);
        put(out, at + 12, 0, 4); put(out, at + 16, offset, 4); put(out, at + 20, size, 4);
        put(out, at + 24, link, 4); put(out, at + 28, info, 4); put(out, at + 32, alignment, 4);
        put(out, at + 36, entry_size, 4);
    };
    section(1, text_name, 1, 6, offsets[0], static_cast<std::uint32_t>(sections[0].size()), 0, 0,
            static_cast<std::uint32_t>(alignments[0]), 0);
    section(2, rodata_name, 1, 2, offsets[1], static_cast<std::uint32_t>(sections[1].size()), 0, 0,
            static_cast<std::uint32_t>(alignments[1]), 0);
    section(3, data_name, 1, 3, offsets[2], static_cast<std::uint32_t>(sections[2].size()), 0, 0,
            static_cast<std::uint32_t>(alignments[2]), 0);
    section(4, bss_name, 8, 3, static_cast<std::uint32_t>(bss_offset), static_cast<std::uint32_t>(bss_size), 0, 0,
            static_cast<std::uint32_t>(alignments[3]), 0);
    section(5, str_name, 3, 0, static_cast<std::uint32_t>(str_offset), static_cast<std::uint32_t>(strings.size()), 0, 0, 1, 0);
    section(6, sym_name, 2, 0, static_cast<std::uint32_t>(sym_offset), static_cast<std::uint32_t>(symtab.size()), 5,
            local_count, 4, 16);
    section(7, shstr_name, 3, 0, static_cast<std::uint32_t>(shstr_offset), static_cast<std::uint32_t>(shstrings.size()), 0, 0, 1, 0);
    out[0] = std::byte{0x7f}; out[1] = std::byte{'E'}; out[2] = std::byte{'L'}; out[3] = std::byte{'F'};
    out[4] = std::byte{1}; out[5] = std::byte{1}; out[6] = std::byte{1};
    put(out, 16, 1, 2); put(out, 18, 3, 2); put(out, 20, 1, 4);
    put(out, 32, shoff, 4); put(out, 40, 52, 2); put(out, 42, 0, 2);
    put(out, 44, 0, 2); put(out, 46, 40, 2); put(out, 48, 8, 2); put(out, 50, 7, 2);
    require(out.size() <= max_output, "ELF32 linked output exceeds configured limit", ErrorCode::resource_limit);
    return out;
}
} // namespace

Result<std::vector<std::byte>> link_elf32_i386_text(
    std::span<const std::shared_ptr<const ByteStorage>> inputs, std::stop_token stop, ElfLinkLimits limits) {
    try {
        require(!inputs.empty() && inputs.size() <= limits.max_objects,
                "ELF32 link object count is outside configured limits", ErrorCode::resource_limit);
        require(limits.max_symbols && limits.max_relocations && limits.max_output_bytes,
                "ELF32 link limits must be positive", ErrorCode::invalid_argument);
        std::vector<Object> objects;
        objects.reserve(inputs.size());
        std::array<std::uint64_t, 4> ends{}, alignments{1, 1, 1, 1};
        std::size_t symbol_count = 0, relocation_count = 0;
        const auto section_index = [](std::string_view section_name) -> std::optional<std::uint16_t> {
            if (section_name == ".text" || section_name.starts_with(".text.")) return std::uint16_t{1};
            if (section_name == ".rodata" || section_name.starts_with(".rodata.")) return std::uint16_t{2};
            if (section_name == ".data" || section_name.starts_with(".data.")) return std::uint16_t{3};
            if (section_name == ".bss" || section_name.starts_with(".bss.")) return std::uint16_t{4};
            return {};
        };
        for (const auto &input : inputs) {
            canceled(stop);
            require(input != nullptr, "ELF32 link input storage is null", ErrorCode::invalid_argument);
            auto loaded = load_elf(input, stop);
            if (!loaded) throw Failure{loaded.error()};
            require(loaded.value().metadata.elf.has_value(), "ELF32 link input has no ELF metadata", ErrorCode::unsupported);
            auto &elf = *loaded.value().metadata.elf;
            require(elf.header.object_type == 1 && !elf.header.is_64 && elf.header.order == ByteOrder::little &&
                        elf.header.machine == 3,
                    "ELF32 link subset requires little-endian i386 ET_REL objects", ErrorCode::unsupported);
            require(elf.relocations_complete, "ELF32 input relocation metadata is incomplete", ErrorCode::unsupported);
            require(elf.symbols.size() <= limits.max_symbols - symbol_count,
                    "ELF32 link symbol limit exceeded", ErrorCode::resource_limit);
            symbol_count += elf.symbols.size();
            Object object;
            object.elf = std::move(elf);
            for (const auto &section : object.elf.sections) {
                canceled(stop);
                if (!(section.flags & 2)) continue;
                const auto output_section = section_index(section.name);
                require(output_section.has_value() &&
                            ((*output_section == 4 && section.type == 8) ||
                             (*output_section != 4 && section.type == 1)),
                        "ELF32 link subset supports allocated .text/.rodata/.data/.bss only; found " + section.name,
                        ErrorCode::unsupported);
                if (*output_section == 1)
                    require((section.flags & 5) == 4, "ELF32 .text must be executable and non-writable", ErrorCode::unsupported);
                if (*output_section == 2)
                    require((section.flags & (1 | 4)) == 0, "ELF32 .rodata must be read-only", ErrorCode::unsupported);
                if (*output_section == 3 || *output_section == 4)
                    require((section.flags & 3) == 1, "ELF32 data sections must be writable and non-executable", ErrorCode::unsupported);
                require(!object.sections.contains(section.index), "Duplicate ELF32 section index", ErrorCode::malformed);
                const auto output_index = static_cast<std::size_t>(*output_section - 1);
                const auto alignment = std::max<std::uint64_t>(1, section.alignment);
                alignments[output_index] = std::max(alignments[output_index], alignment);
                const auto output_offset = align_up(ends[output_index], alignment);
                const auto local_offset = align_up(object.local_ends[output_index], alignment);
                require(output_offset <= limits.max_output_bytes && section.size <= limits.max_output_bytes - output_offset,
                        "ELF32 merged section exceeds output limit", ErrorCode::resource_limit);
                require(local_offset <= limits.max_output_bytes && section.size <= limits.max_output_bytes - local_offset,
                        "ELF32 per-object section storage exceeds output limit", ErrorCode::resource_limit);
                object.sections.emplace(section.index, Placement{*output_section, output_offset, local_offset, section.size});
                if (*output_section == 4) {
                    ends[output_index] = output_offset + section.size;
                    object.local_ends[output_index] = local_offset + section.size;
                } else {
                    require(section.size <= std::numeric_limits<std::size_t>::max(),
                            "ELF32 input section exceeds host address space", ErrorCode::resource_limit);
                    auto view = input->read_at({section.offset}, static_cast<std::size_t>(section.size));
                    if (!view) throw Failure{view.error()};
                    require(view.value().bytes.size() == section.size, "Incomplete ELF32 input section read", ErrorCode::io);
                    auto &destination = object.bytes[output_index];
                    require(local_offset <= std::numeric_limits<std::size_t>::max() &&
                                section.size <= std::numeric_limits<std::size_t>::max() - local_offset,
                            "ELF32 object section storage exceeds host address space", ErrorCode::resource_limit);
                    destination.resize(static_cast<std::size_t>(local_offset), std::byte{0});
                    destination.insert(destination.end(), view.value().bytes.begin(), view.value().bytes.end());
                    ends[output_index] = output_offset + section.size;
                    object.local_ends[output_index] = local_offset + section.size;
                }
            }
            require(std::any_of(object.sections.begin(), object.sections.end(), [](const auto &row) { return row.second.output_section == 1; }),
                    "ELF32 link input has no allocated .text section", ErrorCode::unsupported);
            objects.push_back(std::move(object));
        }

        std::map<std::string, Definition, std::less<>> definitions;
        for (std::size_t oi = 0; oi < objects.size(); ++oi) {
            for (std::size_t si = 0; si < objects[oi].elf.symbols.size(); ++si) {
                canceled(stop);
                const auto &symbol = objects[oi].elf.symbols[si];
                if (symbol.binding == 0 || symbol.name.empty()) continue;
                const bool common = symbol.state == ElfSymbolState::common;
                if (symbol.state != ElfSymbolState::defined && symbol.state != ElfSymbolState::absolute && !common) continue;
                if (symbol.state == ElfSymbolState::defined && !objects[oi].sections.contains(symbol.section_index)) continue;
                Definition candidate{oi, static_cast<std::uint32_t>(si), symbol.binding != 2, common,
                                     symbol.size, common ? std::max<std::uint64_t>(1, symbol.value) : 1, 0};
                auto [it, inserted] = definitions.emplace(symbol.name, candidate);
                if (inserted) continue;
                auto &current = it->second;
                if (candidate.common && current.common) {
                    current.common_size = std::max(current.common_size, candidate.common_size);
                    current.common_alignment = std::max(current.common_alignment, candidate.common_alignment);
                } else if (candidate.strong && current.strong) {
                    return Error{ErrorCode::conflict, "Duplicate strong ELF32 definition: " + symbol.name};
                } else if (candidate.strong || (candidate.common && !current.common)) {
                    current = candidate;
                }
            }
        }
        for (auto &[name, definition] : definitions) {
            (void)name;
            if (!definition.common) continue;
            auto &bss_end = ends[3];
            bss_end = align_up(bss_end, definition.common_alignment);
            require(bss_end <= limits.max_output_bytes && definition.common_size <= limits.max_output_bytes - bss_end,
                    "ELF32 common symbol storage exceeds output limit", ErrorCode::resource_limit);
            definition.common_offset = bss_end;
            bss_end += definition.common_size;
            alignments[3] = std::max(alignments[3], definition.common_alignment);
        }

        const auto mapped_symbol = [&](std::size_t oi, const ElfSymbol &symbol) -> std::pair<std::uint64_t, std::uint16_t> {
            if (symbol.state == ElfSymbolState::absolute) return {symbol.value, std::uint16_t{0xfff1}};
            const auto placement = objects[oi].sections.find(symbol.section_index);
            require(placement != objects[oi].sections.end() && symbol.value <= placement->second.size,
                    "ELF32 symbol lies outside supported merged sections: " + symbol.name, ErrorCode::unsupported);
            return {placement->second.offset + symbol.value, placement->second.output_section};
        };
        const auto resolve = [&](std::size_t oi, std::uint32_t relocation_symbol_index,
                                 std::uint32_t symbol_table_section) -> std::pair<std::uint64_t, std::uint16_t> {
            if (relocation_symbol_index == 0) return {0, 0};
            const auto table = std::find_if(objects[oi].elf.symbol_tables.begin(), objects[oi].elf.symbol_tables.end(),
                [&](const auto &candidate) { return candidate.source.section && *candidate.source.section == symbol_table_section; });
            require(table != objects[oi].elf.symbol_tables.end() && table->symbol_begin && table->count &&
                        relocation_symbol_index < *table->count,
                    "ELF32 relocation symbol index is unavailable", ErrorCode::malformed);
            const auto symbol_position = static_cast<std::size_t>(*table->symbol_begin + relocation_symbol_index);
            require(symbol_position < objects[oi].elf.symbols.size(), "ELF32 relocation symbol exceeds loaded table", ErrorCode::malformed);
            const auto &symbol = objects[oi].elf.symbols[symbol_position];
            if (symbol.binding == 0) {
                require(symbol.state == ElfSymbolState::defined || symbol.state == ElfSymbolState::absolute,
                        "Unresolved local ELF32 relocation symbol: " + symbol.name, ErrorCode::unsupported);
                return mapped_symbol(oi, symbol);
            }
            const auto found = definitions.find(symbol.name);
            if (found == definitions.end()) {
                require(symbol.binding == 2, "Unresolved strong ELF32 relocation symbol: " + symbol.name, ErrorCode::unsupported);
                return {0, 0};
            }
            const auto &definition = found->second;
            if (definition.common) return {definition.common_offset, 4};
            return mapped_symbol(definition.object, objects[definition.object].elf.symbols[definition.symbol_index]);
        };
        for (std::size_t oi = 0; oi < objects.size(); ++oi) {
            auto &object = objects[oi];
            for (const auto &relocation : object.elf.relocations) {
                canceled(stop);
                require(++relocation_count <= limits.max_relocations, "ELF32 relocation limit exceeded", ErrorCode::resource_limit);
                require(relocation.target_section.has_value(), "ELF32 relocation has no target section", ErrorCode::unsupported);
                const auto source_target_section = std::find_if(object.elf.sections.begin(), object.elf.sections.end(),
                    [&](const auto &section) { return section.index == *relocation.target_section; });
                require(source_target_section != object.elf.sections.end(), "ELF32 relocation target section is unavailable", ErrorCode::malformed);
                // Debug and other non-allocated sections are omitted from this output, together with their relocations.
                if (!(source_target_section->flags & 2)) continue;
                const auto placement = object.sections.find(*relocation.target_section);
                require(placement != object.sections.end() && placement->second.output_section != 4,
                        "ELF32 relocations into unsupported sections are rejected", ErrorCode::unsupported);
                require(!relocation.explicit_addend, "ELF32 link subset expects SHT_REL implicit addends", ErrorCode::unsupported);
                const auto type = relocation.type;
                require(type == 0 || type == 1 || type == 2 || type == 4 ||
                            (type >= 20 && type <= 23),
                        "Unsupported i386 ELF relocation type " + std::to_string(type), ErrorCode::unsupported);
                if (type == 0) continue;
                require(relocation.symbol_table.has_value() && relocation.symbol_table->section.has_value() &&
                            relocation.symbol_index_validated,
                        "ELF32 relocation symbol table/index is unavailable", ErrorCode::unsupported);
                auto &bytes = object.bytes[placement->second.output_section - 1];
                const auto width = type == 20 || type == 21 ? std::size_t{2} :
                                   type == 22 || type == 23 ? std::size_t{1} : std::size_t{4};
                require(relocation.offset <= placement->second.size && width <= placement->second.size - relocation.offset,
                        "ELF32 relocation field exceeds target section", ErrorCode::malformed);
                const auto local_offset = placement->second.local_offset + relocation.offset;
                require(local_offset <= std::numeric_limits<std::size_t>::max(),
                        "ELF32 relocation local offset exceeds host address space", ErrorCode::resource_limit);
                const auto offset = static_cast<std::size_t>(local_offset);
                require(offset <= bytes.size() && width <= bytes.size() - offset,
                        "ELF32 relocation field exceeds merged output", ErrorCode::malformed);
                std::int64_t addend = 0;
                if (width == 4)
                    addend = static_cast<std::int32_t>(read32(std::span<const std::byte>(bytes).subspan(offset, width)));
                else if (width == 2)
                    addend = static_cast<std::int16_t>(read16(std::span<const std::byte>(bytes).subspan(offset, width)));
                else
                    addend = static_cast<std::int8_t>(std::to_integer<std::uint8_t>(bytes[offset]));
                const auto resolved_symbol = resolve(oi, relocation.symbol_index, *relocation.symbol_table->section);
                const auto symbol = resolved_symbol.first;
                std::int64_t result = static_cast<std::int64_t>(symbol) + addend;
                const bool pc_relative = type == 2 || type == 4 || type == 21 || type == 23;
                if (type == 21 || type == 23)
                    require(resolved_symbol.second == placement->second.output_section,
                            "R_386_PC16/R_386_PC8 cross-section targets have no known linked section base",
                            ErrorCode::unsupported);
                if (pc_relative) result -= static_cast<std::int64_t>(placement->second.offset + relocation.offset);
                if (type == 2 || type == 4) {
                    require(result >= INT32_MIN && result <= INT32_MAX,
                            "R_386_PC32/R_386_PLT32 relocation overflows", ErrorCode::unsupported);
                } else if (type == 21) {
                    require(result >= INT16_MIN && result <= INT16_MAX,
                            "R_386_PC16 relocation overflows signed 16-bit field", ErrorCode::unsupported);
                } else if (type == 23) {
                    require(result >= INT8_MIN && result <= INT8_MAX,
                            "R_386_PC8 relocation overflows signed 8-bit field", ErrorCode::unsupported);
                }
                put(bytes, offset, static_cast<std::uint64_t>(result), width);
            }
        }

        std::vector<OutputSymbol> output_symbols;
        for (std::size_t oi = 0; oi < objects.size(); ++oi) {
            canceled(stop);
            for (const auto &symbol : objects[oi].elf.symbols) {
                canceled(stop);
                if (symbol.binding != 0 || symbol.name.empty() ||
                    (symbol.state != ElfSymbolState::defined && symbol.state != ElfSymbolState::absolute)) continue;
                if (symbol.state == ElfSymbolState::defined && !objects[oi].sections.contains(symbol.section_index)) continue;
                const auto [value, section] = mapped_symbol(oi, symbol);
                require(value <= UINT32_MAX && symbol.size <= UINT32_MAX, "ELF32 local symbol exceeds output range", ErrorCode::resource_limit);
                output_symbols.push_back({symbol.name, static_cast<std::uint8_t>((symbol.binding << 4) | symbol.type),
                                          symbol.other, section, static_cast<std::uint32_t>(value),
                                          static_cast<std::uint32_t>(symbol.size)});
            }
        }
        for (const auto &[name, definition] : definitions) {
            const auto &symbol = objects[definition.object].elf.symbols[definition.symbol_index];
            std::uint64_t value = 0;
            std::uint16_t section = 0;
            if (definition.common) { value = definition.common_offset; section = 4; }
            else std::tie(value, section) = mapped_symbol(definition.object, symbol);
            require(value <= UINT32_MAX && symbol.size <= UINT32_MAX,
                    "ELF32 output symbol exceeds 32-bit range", ErrorCode::resource_limit);
            output_symbols.push_back({name, static_cast<std::uint8_t>((symbol.binding << 4) | symbol.type),
                                      symbol.other, section, static_cast<std::uint32_t>(value),
                                      static_cast<std::uint32_t>(definition.common ? definition.common_size : symbol.size)});
        }
        std::stable_sort(output_symbols.begin(), output_symbols.end(), [](const auto &left, const auto &right) {
            return (left.info >> 4) == 0 && (right.info >> 4) != 0;
        });

        std::array<std::vector<std::byte>, 4> output_sections;
        // Copy relocation-mutated object slices into the final merged sections.
        for (const auto &object : objects) {
            for (const auto &[source_index, placement] : object.sections) {
                (void)source_index;
                if (placement.output_section == 4) continue;
                auto &destination = output_sections[placement.output_section - 1];
                const auto &source = object.bytes[placement.output_section - 1];
                // Each object stores source sections in its own aligned local buffer.
                require(placement.local_offset <= source.size() && placement.size <= source.size() - placement.local_offset,
                        "ELF32 object section copy exceeds its buffer", ErrorCode::malformed);
                if (destination.size() < placement.offset) destination.resize(static_cast<std::size_t>(placement.offset));
                const auto begin = source.begin() + static_cast<std::ptrdiff_t>(placement.local_offset);
                destination.insert(destination.end(), begin,
                                   begin + static_cast<std::ptrdiff_t>(placement.size));
            }
        }
        canceled(stop);
        return make_output(output_sections, ends[3], alignments, output_symbols, limits.max_output_bytes);
    } catch (const Failure &failure) { return failure.error; }
      catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "Cannot allocate ELF32 linked output"}; }
}
} // namespace hexlab
