#include "elf_internal.hpp"
#include <algorithm>
#include <bit>
#include <map>
namespace hexlab::elf_detail {
namespace {
struct Source {
    ElfTableSource source;
    std::optional<std::uint32_t> program;
    std::uint64_t size = 0, stride = 0;
    const ElfSection *strings = nullptr;
};
bool string_tag(std::int64_t tag) {
    return tag == 1 || tag == 14 || tag == 15 || tag == 29 || tag == 0x6ffffefa || tag == 0x6ffffefb ||
           tag == 0x6ffffefc || tag == 0x7ffffffd || tag == 0x7fffffff;
}
bool repeatable_string_tag(std::int64_t tag) {
    // DT_NEEDED and the GNU/Solaris filter/audit lists may have multiple rows.
    return tag == 1 || tag == 0x6ffffefb || tag == 0x6ffffefc || tag == 0x7ffffffd || tag == 0x7fffffff;
}
bool understood(std::int64_t tag) {
    return tag == 0 || tag == 2 || tag == 4 || tag == 5 || tag == 6 || tag == 7 || tag == 8 || tag == 9 || tag == 10 ||
           tag == 11 || tag == 17 || tag == 18 || tag == 19 || tag == 20 || tag == 23 || tag == 30 || tag == 34 ||
           tag == 35 ||
           tag == 36 || tag == 37 || tag == 39 ||
           tag == 0x6000000f || tag == 0x60000010 || tag == 0x60000011 || tag == 0x60000012 ||
           tag == 0x6ffffef5 || tag == 0x6ffffefa || tag == 0x6ffffefb || tag == 0x6ffffefc ||
           tag == 0x6ffffff0 || tag == 0x6ffffffc || tag == 0x6ffffffd ||
           tag == 0x6ffffffe || tag == 0x6fffffff || tag == 0x6ffffffb || string_tag(tag);
}
std::string text(ByteView view, std::uint64_t index, Budget &budget) {
    if (index == 0)
        return {};
    require(index < view.bytes.size(), "ELF dynamic string index is outside table");
    const auto tail = view.bytes.subspan(static_cast<std::size_t>(index));
    const auto end = std::find(tail.begin(), tail.end(), std::byte{0});
    require(end != tail.end(), "Unterminated ELF dynamic string");
    const auto count = static_cast<std::size_t>(end - tail.begin());
    budget.include(count);
    return {reinterpret_cast<const char *>(tail.data()), count};
}
} // namespace
void read_dynamic(const ByteStorage &storage, const Image &image, ElfMetadata &metadata, Budget &budget,
                  RelocationRegistry &registry, std::stop_token stop) {
    Reader reader(storage, metadata.header.order, stop);
    const auto word = metadata.header.is_64 ? 8u : 4u;
    std::map<std::uint64_t, Source> sources;
    for (const auto &section : metadata.sections) {
        canceled(stop);
        if (section.type != 6 || (section.flags & 0x800))
            continue;
        require(section.entry_size == 2 * word && section.size % section.entry_size == 0,
                "Invalid ELF dynamic array stride/extent");
        Source source{{section.index, section.offset, {}}, {}, section.size, section.entry_size, {}};
        if (section.link) {
            require(section.link < metadata.sections.size() && metadata.sections[section.link].type == 3,
                    "ELF dynamic link must name STRTAB");
            source.strings = &metadata.sections[section.link];
        }
        require(sources.emplace(section.offset, std::move(source)).second, "Duplicate ELF dynamic section source");
        budget.include(sizeof(Source) + 3 * sizeof(void *));
    }
    for (const auto &program : metadata.programs) {
        canceled(stop);
        if (program.type == 3) {
            require(!metadata.interpreter, "Multiple ELF interpreters");
            require(program.file_size && program.file_size <= 65536, "ELF interpreter extent exceeds limit",
                    ErrorCode::resource_limit);
            budget.include(program.file_size + sizeof(ElfInterpreter));
            const auto bytes = reader.bytes(program.offset, static_cast<std::size_t>(program.file_size));
            const auto end = std::find(bytes.bytes.begin(), bytes.bytes.end(), std::byte{0});
            require(end != bytes.bytes.end(), "ELF interpreter is not terminated");
            const auto n = static_cast<std::size_t>(end - bytes.bytes.begin());
            budget.include(n);
            metadata.interpreter = ElfInterpreter{program.index,
                                                  program.offset,
                                                  program.file_size,
                                                  {reinterpret_cast<const char *>(bytes.bytes.data()), n}};
        }
        if (program.type != 2)
            continue;
        require(program.file_size && program.file_size % (2 * word) == 0, "Invalid ELF dynamic program extent");
        require(program.file_size <= program.memory_size, "ELF dynamic file size exceeds memory extent");
        const auto at = Address{{0}, program.address};
        const auto first = image.to_file_offset(at);
        require(first && first.value().value == program.offset, "ELF dynamic program disagrees with load mapping");
        validate_virtual_file(image, at, program.file_size, {program.offset}, stop);
        // Reading the array itself uses its declared file extent. Individual
        // dynamic pointers are translated against authoritative load mappings.
        Source source{{{}, program.offset, at}, program.index, program.file_size, 2 * word, {}};
        if (auto found = sources.find(program.offset); found != sources.end()) {
            require(found->second.size == source.size && found->second.stride == source.stride &&
                        !found->second.program,
                    "ELF dynamic section/program extents conflict");
            found->second.program = program.index;
            found->second.source.address = at;
        } else {
            sources.emplace(program.offset, std::move(source));
            budget.include(sizeof(Source) + 3 * sizeof(void *));
        }
    }
    for (const auto &[offset, source] : sources) {
        canceled(stop);
        reader.extent(offset, source.size);
        require(source.size <= metadata_limit, "ELF dynamic array extent exceeds budget", ErrorCode::resource_limit);
        ElfDynamicTable table{source.source, source.program, source.size, source.stride, {}};
        budget.include(sizeof(ElfDynamicTable));
        std::map<std::int64_t, std::uint64_t> values;
        bool terminated = false, needs_strings = false;
        for (std::uint32_t index = 0; index < source.size / source.stride; ++index) {
            require(index < 1000000, "ELF dynamic record count exceeds budget", ErrorCode::resource_limit);
            const auto bytes = reader.bytes(offset + source.stride * index, 2 * word);
            auto raw = reader.value(bytes.bytes, 0, word);
            if (word == 4 && (raw & UINT64_C(0x80000000)))
                raw |= UINT64_C(0xffffffff00000000);
            ElfDynamicEntry entry{index, std::bit_cast<std::int64_t>(raw), reader.value(bytes.bytes, word, word), {}};
            budget.include(sizeof(ElfDynamicEntry));
            if (entry.tag != 0 && !repeatable_string_tag(entry.tag) && understood(entry.tag))
                require(values.emplace(entry.tag, entry.value).second, "Duplicate singleton ELF dynamic tag");
            if (!understood(entry.tag))
                metadata.dynamic_complete = false;
            needs_strings = needs_strings || string_tag(entry.tag) || entry.tag == 6;
            table.entries.push_back(std::move(entry));
            if (table.entries.back().tag == 0) {
                terminated = true;
                break;
            }
        }
        require(terminated, "ELF dynamic array has no bounded NULL terminator");
        ByteView strings;
        if (needs_strings) {
            if (metadata.header.object_type == 1 && source.strings) {
                require(!(source.strings->flags & 0x800), "Compressed dynamic strings are unsupported",
                        ErrorCode::unsupported);
                budget.include(source.strings->size);
                strings = reader.bytes(source.strings->offset, static_cast<std::size_t>(source.strings->size));
            } else {
                require(values.contains(5) && values.contains(10), "ELF dynamic strings need STRTAB and STRSZ");
                require(values.at(10) <= SIZE_MAX, "ELF dynamic string table exceeds host size",
                        ErrorCode::resource_limit);
                strings = read_virtual(reader, image, {{0}, values.at(5)}, static_cast<std::size_t>(values.at(10)),
                                       budget, stop);
            }
            require(strings.bytes.empty() ||
                        (strings.bytes.front() == std::byte{0} && strings.bytes.back() == std::byte{0}),
                    "ELF dynamic string table requires boundary terminators");
            for (auto &entry : table.entries) {
                canceled(stop);
                if (string_tag(entry.tag))
                    entry.string_value = text(strings, entry.value, budget);
            }
        }
        read_dynamic_symbols(reader, image, metadata, table, values, strings, budget, stop);
        read_dynamic_relocations(reader, image, metadata, table, values, budget, registry, stop);
        metadata.dynamic_tables.push_back(std::move(table));
    }
}
} // namespace hexlab::elf_detail
