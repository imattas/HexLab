#include "elf_internal.hpp"
#include <algorithm>
#include <map>

namespace hexlab::elf_detail {
namespace {
constexpr std::uint32_t sht_gnu_versym = 0x6fffffff;
constexpr std::uint32_t sht_gnu_verdef = 0x6ffffffd;
constexpr std::uint32_t sht_gnu_verneed = 0x6ffffffe;
constexpr std::uint16_t version_definition_base = 0x0001;
constexpr std::uint16_t version_hidden_mask = 0x8000;
constexpr std::uint16_t version_index_mask = 0x7fff;

struct VersionName {
    std::string name;
    std::optional<std::string> file;
    std::uint16_t flags = 0;
    std::uint32_t hash = 0;
    bool operator==(const VersionName &) const = default;
};

using StringCache = std::map<std::uint32_t, ByteView>;
std::string string_at(const Reader &reader, const ElfSection &strings, std::uint64_t index, Budget &budget,
                      StringCache &cache) {
    require(index < strings.size, "ELF symbol version name is outside linked string table");
    auto found = cache.find(strings.index);
    if (found == cache.end()) {
        require(strings.size <= SIZE_MAX, "ELF version string table exceeds addressable size",
                ErrorCode::resource_limit);
        budget.include(strings.size);
        budget.include(sizeof(ByteView) + 3 * sizeof(void *));
        found = cache.emplace(strings.index, reader.bytes(strings.offset, static_cast<std::size_t>(strings.size))).first;
    }
    const auto text = std::span<const std::byte>(found->second.bytes).subspan(static_cast<std::size_t>(index));
    const auto end = std::find(text.begin(), text.end(), std::byte{0});
    require(end != text.end(), "Unterminated ELF symbol version name");
    const auto length = static_cast<std::size_t>(end - text.begin());
    budget.include(length);
    return {reinterpret_cast<const char *>(text.data()), length};
}

ByteView virtual_at(const Reader &reader, const Image &image, std::uint64_t base, std::uint64_t offset,
                   std::size_t size, Budget &budget, std::stop_token stop) {
    return read_virtual(reader, image, {{0}, add(base, offset)}, size, budget, stop);
}

std::string virtual_string(const Reader &reader, const Image &image, std::uint64_t base, std::uint64_t size,
                           std::uint64_t index, Budget &budget, std::stop_token stop,
                           std::map<std::uint64_t, std::string> &cache) {
    require(index < size, "GNU ELF dynamic version name is outside DT_STRTAB");
    if (const auto found = cache.find(index); found != cache.end())
        return found->second;
    constexpr std::size_t maximum_name = 4096;
    const auto request = static_cast<std::size_t>(std::min<std::uint64_t>(size - index, maximum_name + 1));
    const auto bytes = virtual_at(reader, image, base, index, request, budget, stop);
    const auto end = std::find(bytes.bytes.begin(), bytes.bytes.end(), std::byte{0});
    require(end != bytes.bytes.end(), "GNU ELF dynamic version name is unterminated or exceeds 4096 bytes",
            ErrorCode::resource_limit);
    const auto length = static_cast<std::size_t>(end - bytes.bytes.begin());
    std::string value(reinterpret_cast<const char *>(bytes.bytes.data()), length);
    budget.include(length);
    cache.emplace(index, value);
    return value;
}

void insert_version(std::map<std::uint16_t, VersionName> &versions, std::uint16_t index, VersionName value,
                    bool allow_base = false) {
    require(index > 1 || (allow_base && index == 1 && (value.flags & version_definition_base)),
            "Invalid GNU ELF version index");
    const auto found = versions.find(index);
    if (found != versions.end()) {
        require(found->second == value, "Conflicting GNU ELF version indexes");
        return;
    }
    versions.emplace(index, std::move(value));
}

std::map<std::uint16_t, VersionName> read_dynamic_definitions(
    const Reader &reader, const Image &image, std::uint64_t address, std::uint64_t count,
    std::uint64_t string_address, std::uint64_t string_size, Budget &budget, std::stop_token stop,
    std::map<std::uint64_t, std::string> &strings) {
    require(count <= 65536, "GNU ELF dynamic version definitions exceed bound", ErrorCode::resource_limit);
    std::map<std::uint16_t, VersionName> result;
    std::uint64_t offset = 0;
    for (std::uint64_t record_index = 0; record_index < count; ++record_index) {
        canceled(stop);
        const auto record = virtual_at(reader, image, address, offset, 20, budget, stop);
        const auto version = reader.value(record.bytes, 0, 2);
        const auto flags = static_cast<std::uint16_t>(reader.value(record.bytes, 2, 2));
        const auto index = static_cast<std::uint16_t>(reader.value(record.bytes, 4, 2) & version_index_mask);
        const auto aux_count = reader.value(record.bytes, 6, 2);
        const auto hash = static_cast<std::uint32_t>(reader.value(record.bytes, 8, 4));
        const auto aux_offset = reader.value(record.bytes, 12, 4);
        const auto next = reader.value(record.bytes, 16, 4);
        require(version == 1 && aux_count && aux_offset >= 20,
                "Invalid GNU ELF dynamic version definition header");
        auto aux_cursor = add(offset, aux_offset);
        std::string primary_name;
        for (std::uint64_t aux_index = 0; aux_index < aux_count; ++aux_index) {
            canceled(stop);
            const auto aux = virtual_at(reader, image, address, aux_cursor, 8, budget, stop);
            const auto name_index = reader.value(aux.bytes, 0, 4);
            auto name = virtual_string(reader, image, string_address, string_size, name_index, budget, stop, strings);
            if (!aux_index)
                primary_name = std::move(name);
            const auto aux_next = reader.value(aux.bytes, 4, 4);
            if (aux_index + 1 < aux_count) {
                require(aux_next >= 8, "Invalid GNU ELF dynamic version definition auxiliary link");
                aux_cursor = add(aux_cursor, aux_next);
            } else
                require(aux_next == 0, "GNU ELF dynamic version definition has extra auxiliary records");
        }
        budget.include(sizeof(VersionName) + sizeof(std::pair<const std::uint16_t, VersionName>) + 3 * sizeof(void *));
        insert_version(result, index, {std::move(primary_name), {}, flags, hash}, true);
        if (record_index + 1 < count) {
            require(next >= 20, "Invalid GNU ELF dynamic version definition link");
            offset = add(offset, next);
        } else
            require(next == 0, "GNU ELF dynamic version definition count omits linked records");
    }
    return result;
}

std::map<std::uint16_t, VersionName> read_dynamic_requirements(
    const Reader &reader, const Image &image, std::uint64_t address, std::uint64_t count,
    std::uint64_t string_address, std::uint64_t string_size, Budget &budget, std::stop_token stop,
    std::map<std::uint64_t, std::string> &strings) {
    require(count <= 65536, "GNU ELF dynamic version requirements exceed bound", ErrorCode::resource_limit);
    std::map<std::uint16_t, VersionName> result;
    std::uint64_t offset = 0;
    for (std::uint64_t record_index = 0; record_index < count; ++record_index) {
        canceled(stop);
        const auto record = virtual_at(reader, image, address, offset, 16, budget, stop);
        const auto version = reader.value(record.bytes, 0, 2);
        const auto aux_count = reader.value(record.bytes, 2, 2);
        const auto file_index = reader.value(record.bytes, 4, 4);
        const auto aux_offset = reader.value(record.bytes, 8, 4);
        const auto next = reader.value(record.bytes, 12, 4);
        require(version == 1 && (!aux_count || aux_offset >= 16),
                "Invalid GNU ELF dynamic version requirement header");
        auto file = virtual_string(reader, image, string_address, string_size, file_index, budget, stop, strings);
        auto aux_cursor = aux_count ? add(offset, aux_offset) : 0;
        for (std::uint64_t aux_index = 0; aux_index < aux_count; ++aux_index) {
            canceled(stop);
            const auto aux = virtual_at(reader, image, address, aux_cursor, 16, budget, stop);
            const auto hash = static_cast<std::uint32_t>(reader.value(aux.bytes, 0, 4));
            const auto flags = static_cast<std::uint16_t>(reader.value(aux.bytes, 4, 2));
            const auto other = static_cast<std::uint16_t>(reader.value(aux.bytes, 6, 2));
            const auto name_index = reader.value(aux.bytes, 8, 4);
            const auto aux_next = reader.value(aux.bytes, 12, 4);
            auto name = virtual_string(reader, image, string_address, string_size, name_index, budget, stop, strings);
            budget.include(sizeof(VersionName) + sizeof(std::pair<const std::uint16_t, VersionName>) + 3 * sizeof(void *));
            insert_version(result, other & version_index_mask, {std::move(name), file, flags, hash});
            if (aux_index + 1 < aux_count) {
                require(aux_next >= 16, "Invalid GNU ELF dynamic version requirement auxiliary link");
                aux_cursor = add(aux_cursor, aux_next);
            } else
                require(aux_next == 0, "GNU ELF dynamic version requirement has extra auxiliary records");
        }
        if (record_index + 1 < count) {
            require(next >= 16, "Invalid GNU ELF dynamic version requirement link");
            offset = add(offset, next);
        } else
            require(next == 0, "GNU ELF dynamic version requirement count omits linked records");
    }
    return result;
}

void attach_version(ElfSymbol &symbol, std::uint16_t raw, const std::map<std::uint16_t, VersionName> &versions) {
    const auto index = static_cast<std::uint16_t>(raw & version_index_mask);
    const bool hidden = (raw & version_hidden_mask) != 0;
    std::optional<std::string> name, file;
    std::optional<std::uint16_t> flags;
    std::optional<std::uint32_t> hash;
    if (index > 1) {
        const auto version = versions.find(index);
        require(version != versions.end(), "GNU ELF symbol version index has no definition/requirement");
        name = version->second.name;
        file = version->second.file;
        flags = version->second.flags;
        hash = version->second.hash;
    }
    if (symbol.version_index || symbol.version_hidden || symbol.version_name || symbol.version_file ||
        symbol.version_flags || symbol.version_hash)
        require(symbol.version_index == index && symbol.version_hidden == hidden && symbol.version_name == name &&
                    symbol.version_file == file && symbol.version_flags == flags && symbol.version_hash == hash,
                "GNU ELF section and dynamic symbol-version metadata conflict");
    symbol.version_index = index;
    symbol.version_hidden = hidden;
    symbol.version_name = std::move(name);
    symbol.version_file = std::move(file);
    symbol.version_flags = flags;
    symbol.version_hash = hash;
}

std::map<std::uint16_t, VersionName> read_definitions(const Reader &reader, const ElfMetadata &metadata,
                                                      const ElfSection &section, Budget &budget,
                                                      StringCache &cache, std::stop_token stop) {
    require(section.link < metadata.sections.size() && metadata.sections[section.link].type == 3,
            "GNU ELF version definition must link to STRTAB");
    require(section.entry_size == 0 || section.entry_size == 20, "Invalid GNU ELF version definition stride");
    const auto &strings = metadata.sections[section.link];
    std::map<std::uint16_t, VersionName> result;
    std::uint64_t offset = 0;
    std::uint32_t records = 0;
    while (offset < section.size) {
        canceled(stop);
        require(++records <= 65536, "GNU ELF version definitions exceed bound", ErrorCode::resource_limit);
        require(section.size - offset >= 20, "Truncated GNU ELF version definition");
        const auto record = reader.bytes(section.offset + offset, 20);
        const auto version = reader.value(record.bytes, 0, 2);
        const auto flags = static_cast<std::uint16_t>(reader.value(record.bytes, 2, 2));
        const auto index = static_cast<std::uint16_t>(reader.value(record.bytes, 4, 2) & version_index_mask);
        const auto count = reader.value(record.bytes, 6, 2);
        const auto hash = static_cast<std::uint32_t>(reader.value(record.bytes, 8, 4));
        const auto aux_offset = reader.value(record.bytes, 12, 4);
        const auto next = reader.value(record.bytes, 16, 4);
        require(version == 1 && count && aux_offset >= 20 && aux_offset <= section.size - offset - 8,
                "Invalid GNU ELF version definition header");
        const auto aux = reader.bytes(section.offset + offset + aux_offset, 8);
        const auto name_index = reader.value(aux.bytes, 0, 4);
        budget.include(sizeof(VersionName) + sizeof(std::pair<const std::uint16_t, VersionName>) +
                       3 * sizeof(void *));
        insert_version(result, index, {string_at(reader, strings, name_index, budget, cache), {}, flags, hash}, true);
        auto aux_cursor = offset + aux_offset;
        for (std::uint64_t i = 1; i < count; ++i) {
            require(aux_cursor <= section.size && section.size - aux_cursor >= 8,
                    "Truncated GNU ELF version definition auxiliary");
            const auto aux_next = reader.value(reader.bytes(section.offset + aux_cursor, 8).bytes, 4, 4);
            require(aux_next >= 8 && aux_next <= section.size - aux_cursor,
                    "GNU ELF version definition auxiliary link is outside section");
            aux_cursor += aux_next;
        }
        if (!next)
            break;
        require(next >= 20 && next <= section.size - offset, "GNU ELF version definition link is outside section");
        offset += next;
    }
    return result;
}

std::map<std::uint16_t, VersionName> read_requirements(const Reader &reader, const ElfMetadata &metadata,
                                                       const ElfSection &section, Budget &budget,
                                                       StringCache &cache, std::stop_token stop) {
    require(section.link < metadata.sections.size() && metadata.sections[section.link].type == 3,
            "GNU ELF version requirement must link to STRTAB");
    require(section.entry_size == 0 || section.entry_size == 16, "Invalid GNU ELF version requirement stride");
    const auto &strings = metadata.sections[section.link];
    std::map<std::uint16_t, VersionName> result;
    std::uint64_t offset = 0;
    std::uint32_t records = 0;
    while (offset < section.size) {
        canceled(stop);
        require(++records <= 65536, "GNU ELF version requirements exceed bound", ErrorCode::resource_limit);
        require(section.size - offset >= 16, "Truncated GNU ELF version requirement");
        const auto record = reader.bytes(section.offset + offset, 16);
        const auto version = reader.value(record.bytes, 0, 2);
        const auto count = reader.value(record.bytes, 2, 2);
        const auto file_index = reader.value(record.bytes, 4, 4);
        const auto aux_offset = reader.value(record.bytes, 8, 4);
        const auto next = reader.value(record.bytes, 12, 4);
        require(version == 1 && aux_offset >= 16 && aux_offset <= section.size - offset,
                "Invalid GNU ELF version requirement header");
        const auto file = string_at(reader, strings, file_index, budget, cache);
        auto aux_cursor = offset + aux_offset;
        require(count <= 65536, "GNU ELF version auxiliaries exceed bound", ErrorCode::resource_limit);
        for (std::uint32_t i = 0; i < count; ++i) {
            canceled(stop);
            require(aux_cursor <= section.size && section.size - aux_cursor >= 16,
                    "Truncated GNU ELF version requirement auxiliary");
            const auto aux = reader.bytes(section.offset + aux_cursor, 16);
            const auto hash = static_cast<std::uint32_t>(reader.value(aux.bytes, 0, 4));
            const auto flags = static_cast<std::uint16_t>(reader.value(aux.bytes, 4, 2));
            const auto name_index = reader.value(aux.bytes, 8, 4);
            const auto other = static_cast<std::uint16_t>(reader.value(aux.bytes, 6, 2));
            const auto aux_next = reader.value(aux.bytes, 12, 4);
            budget.include(sizeof(VersionName) + sizeof(std::pair<const std::uint16_t, VersionName>) +
                           3 * sizeof(void *));
            insert_version(result, other & version_index_mask,
                           {string_at(reader, strings, name_index, budget, cache), file, flags, hash});
            if (i + 1 < count) {
                require(aux_next >= 16 && aux_next <= section.size - aux_cursor,
                        "GNU ELF version auxiliary link is outside section");
                aux_cursor += aux_next;
            }
        }
        if (!next)
            break;
        require(next >= 16 && next <= section.size - offset,
                "GNU ELF version requirement link is outside section");
        offset += next;
    }
    return result;
}
} // namespace

void read_symbol_versions(const ByteStorage &storage, const Image &image, ElfMetadata &metadata, Budget &budget,
                          std::stop_token stop) {
    const bool present = std::any_of(metadata.sections.begin(), metadata.sections.end(), [](const auto &section) {
        return section.type == sht_gnu_versym || section.type == sht_gnu_verdef || section.type == sht_gnu_verneed;
    });
    const bool dynamic_present = std::any_of(metadata.dynamic_tables.begin(), metadata.dynamic_tables.end(),
        [](const auto &dynamic) {
            return std::any_of(dynamic.entries.begin(), dynamic.entries.end(), [](const auto &entry) {
                return entry.tag == 0x6ffffff0 || entry.tag == 0x6ffffffc || entry.tag == 0x6ffffffd ||
                       entry.tag == 0x6ffffffe || entry.tag == 0x6fffffff;
            });
        });
    if (!present && !dynamic_present)
        return;
    Reader reader(storage, metadata.header.order, stop);
    StringCache strings;

    // Version definitions and requirements share the linked dynamic string table.
    // Merge per linked STRTAB so each versym section can bind its own dynsym.
    std::map<std::uint32_t, std::map<std::uint16_t, VersionName>> by_strings;
    for (const auto &section : metadata.sections) {
        canceled(stop);
        if (section.type != sht_gnu_verdef && section.type != sht_gnu_verneed)
            continue;
        auto found = section.type == sht_gnu_verdef
                         ? read_definitions(reader, metadata, section, budget, strings, stop)
                         : read_requirements(reader, metadata, section, budget, strings, stop);
        auto &versions = by_strings[section.link];
        for (auto &[index, value] : found) {
            const auto existing = versions.find(index);
            if (existing == versions.end())
                versions.emplace(index, std::move(value));
            else
                require(existing->second == value, "GNU ELF version definition/requirement conflict");
        }
    }

    for (const auto &section : metadata.sections) {
        canceled(stop);
        if (section.type != sht_gnu_versym)
            continue;
        require(section.link < metadata.sections.size() &&
                    (metadata.sections[section.link].type == 2 || metadata.sections[section.link].type == 11),
                "GNU ELF version indexes must link to a symbol table");
        const auto &symtab = metadata.sections[section.link];
        require((section.entry_size == 0 || section.entry_size == 2) && section.size % 2 == 0 &&
                    section.size / 2 <= UINT32_MAX,
                "Invalid GNU ELF version index table size");
        const auto table = std::find_if(metadata.symbol_tables.begin(), metadata.symbol_tables.end(),
                                        [&](const auto &candidate) { return candidate.source.section == section.link; });
        require(table != metadata.symbol_tables.end() && table->count && table->symbol_begin,
                "GNU ELF version indexes have no bounded symbol table");
        require(section.size / 2 == *table->count, "GNU ELF version index count differs from symbols");
        const auto &versions = by_strings[symtab.link];
        const bool dynamic_version_table = std::any_of(metadata.dynamic_tables.begin(), metadata.dynamic_tables.end(),
            [&](const auto &dynamic) {
                if (dynamic.symbol_table != std::optional<ElfTableSource>{table->source})
                    return false;
                return std::any_of(dynamic.entries.begin(), dynamic.entries.end(),
                                   [](const auto &entry) { return entry.tag == 0x6ffffff0; });
            });
        for (std::uint32_t i = 0; i < *table->count; ++i) {
            canceled(stop);
            const auto raw = static_cast<std::uint16_t>(reader.value(reader.bytes(section.offset + std::uint64_t{i} * 2, 2).bytes, 0, 2));
            auto &symbol = metadata.symbols[static_cast<std::size_t>(*table->symbol_begin + i)];
            const auto index = static_cast<std::uint16_t>(raw & version_index_mask);
            if (index > 1 && !versions.contains(index) && dynamic_version_table)
                continue; // The dynamic version records below provide the names.
            attach_version(symbol, raw, versions);
        }
    }

    // Dynamic tags are the authoritative path for stripped images, where GNU
    // version sections are absent but their virtual-address tables remain.
    for (const auto &dynamic : metadata.dynamic_tables) {
        canceled(stop);
        const auto tag = [&](std::int64_t wanted) -> std::optional<std::uint64_t> {
            const auto found = std::find_if(dynamic.entries.begin(), dynamic.entries.end(),
                                            [&](const auto &entry) { return entry.tag == wanted; });
            return found == dynamic.entries.end() ? std::optional<std::uint64_t>{}
                                                   : std::optional<std::uint64_t>{found->value};
        };
        constexpr std::int64_t dt_versym = 0x6ffffff0;
        constexpr std::int64_t dt_verdef = 0x6ffffffc;
        constexpr std::int64_t dt_verdefnum = 0x6ffffffd;
        constexpr std::int64_t dt_verneed = 0x6ffffffe;
        constexpr std::int64_t dt_verneednum = 0x6fffffff;
        const auto versym = tag(dt_versym);
        const auto verdef = tag(dt_verdef);
        const auto verdef_count = tag(dt_verdefnum);
        const auto verneed = tag(dt_verneed);
        const auto verneed_count = tag(dt_verneednum);
        if (!versym && !verdef && !verdef_count && !verneed && !verneed_count)
            continue;
        require(versym.has_value(), "ELF GNU version metadata lacks DT_VERSYM");
        require(verdef.has_value() == verdef_count.has_value(), "ELF DT_VERDEF and DT_VERDEFNUM must appear together");
        require(verneed.has_value() == verneed_count.has_value(), "ELF DT_VERNEED and DT_VERNEEDNUM must appear together");
        require(dynamic.symbol_table.has_value(), "ELF DT_VERSYM lacks a bounded dynamic symbol table");
        const auto symbol_table = std::find_if(metadata.symbol_tables.begin(), metadata.symbol_tables.end(),
                                               [&](const auto &candidate) {
                                                   return candidate.source == *dynamic.symbol_table;
                                               });
        require(symbol_table != metadata.symbol_tables.end() && symbol_table->count && symbol_table->symbol_begin,
                "ELF DT_VERSYM has no bounded dynamic symbol rows");
        require(*symbol_table->count <= SIZE_MAX / sizeof(std::uint16_t),
                "ELF DT_VERSYM extent exceeds host size", ErrorCode::resource_limit);
        const auto string_address = tag(5);
        const auto string_size = tag(10);
        require(string_address && string_size, "ELF dynamic symbol versions require DT_STRTAB and DT_STRSZ");
        std::map<std::uint64_t, std::string> dynamic_strings;
        auto versions = std::map<std::uint16_t, VersionName>{};
        if (verdef) {
            require(*verdef_count > 0, "ELF DT_VERDEFNUM must be nonzero when DT_VERDEF is present");
            versions = read_dynamic_definitions(reader, image, *verdef, *verdef_count, *string_address,
                                                *string_size, budget, stop, dynamic_strings);
        }
        if (verneed) {
            require(*verneed_count > 0, "ELF DT_VERNEEDNUM must be nonzero when DT_VERNEED is present");
            auto requirements = read_dynamic_requirements(reader, image, *verneed, *verneed_count, *string_address,
                                                          *string_size, budget, stop, dynamic_strings);
            for (auto &[index, value] : requirements) {
                const auto existing = versions.find(index);
                if (existing == versions.end())
                    versions.emplace(index, std::move(value));
                else
                    require(existing->second == value, "GNU ELF dynamic version definition/requirement conflict");
            }
        }
        if (symbol_table->source.section) {
            const auto section_index = *symbol_table->source.section;
            require(section_index < metadata.sections.size(), "ELF dynamic symbol table section is invalid");
            const auto string_section = metadata.sections[section_index].link;
            if (const auto section_versions = by_strings.find(string_section); section_versions != by_strings.end()) {
                for (const auto &[index, value] : section_versions->second) {
                    const auto existing = versions.find(index);
                    if (existing == versions.end())
                        versions.emplace(index, value);
                    else
                        require(existing->second == value, "GNU ELF section and dynamic version records conflict");
                }
            }
        }
        const auto count = *symbol_table->count;
        require(count <= UINT32_MAX, "ELF DT_VERSYM symbol count exceeds 32-bit symbol indexes",
                ErrorCode::resource_limit);
        const auto table_bytes = static_cast<std::size_t>(count * sizeof(std::uint16_t));
        const auto indexes = read_virtual(reader, image, {{0}, *versym}, table_bytes, budget, stop);
        for (std::uint32_t index = 0; index < count; ++index) {
            canceled(stop);
            const auto raw = static_cast<std::uint16_t>(reader.value(indexes.bytes, std::size_t{index} * 2, 2));
            auto &symbol = metadata.symbols[static_cast<std::size_t>(*symbol_table->symbol_begin + index)];
            attach_version(symbol, raw, versions);
        }
    }
}
} // namespace hexlab::elf_detail
