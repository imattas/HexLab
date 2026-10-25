#include "elf_internal.hpp"
#include <algorithm>
namespace hexlab::elf_detail {
void read_tables(const ByteStorage &storage, ElfMetadata &metadata, Budget &budget, std::stop_token stop) {
    const auto &h = metadata.header;
    const auto wide = h.is_64;
    Reader reader(storage, h.order, stop);
    budget.include(h.programs.count * sizeof(ElfProgram));
    budget.include(h.sections.count * sizeof(ElfSection));
    metadata.programs.reserve(static_cast<std::size_t>(h.programs.count));
    metadata.sections.reserve(static_cast<std::size_t>(h.sections.count));
    for (std::uint32_t i = 0; i < h.programs.count; ++i) {
        const auto view = reader.bytes(h.programs.offset + h.programs.stride * i, wide ? 56 : 32);
        const auto get = [&](std::size_t at, std::size_t n) { return reader.value(view.bytes, at, n); };
        ElfProgram p;
        p.index = i;
        p.type = static_cast<std::uint32_t>(get(0, 4));
        p.flags = static_cast<std::uint32_t>(get(wide ? 4 : 24, 4));
        p.offset = get(wide ? 8 : 4, wide ? 8 : 4);
        p.address = get(wide ? 16 : 8, wide ? 8 : 4);
        p.physical_address = get(wide ? 24 : 12, wide ? 8 : 4);
        p.file_size = get(wide ? 32 : 16, wide ? 8 : 4);
        p.memory_size = get(wide ? 40 : 20, wide ? 8 : 4);
        p.alignment = get(wide ? 48 : 28, wide ? 8 : 4);
        if (p.type == 1) {
            require(p.file_size <= p.memory_size, "ELF load file size exceeds memory size");
            if (p.file_size)
                reader.extent(p.offset, p.file_size);
            require(aligned(p.alignment), "ELF load alignment is not a power of two");
            require(p.alignment <= 1 || p.offset % p.alignment == p.address % p.alignment,
                    "ELF load file/address alignment mismatch");
            const auto end = add(p.address, p.memory_size);
            require(wide || end <= UINT64_C(0x100000000), "ELF32 mapping exceeds address domain");
        }
        metadata.programs.push_back(p);
    }
    // PT_NOTE records are byte-order-aware and independently bounded by their
    // containing program segment. Do not assume that note names are strings:
    // retain exactly the bytes preceding the ABI-mandated NUL terminator.
    for (const auto &program : metadata.programs) {
        if (program.type != 4 || program.file_size == 0)
            continue;
        std::uint64_t cursor = program.offset;
        const auto end = add(cursor, program.file_size);
        while (cursor < end) {
            canceled(stop);
            require(end - cursor >= 12, "Truncated ELF note header");
            const auto header = reader.bytes(cursor, 12);
            const auto name_size = reader.value(header.bytes, 0, 4);
            const auto description_size = reader.value(header.bytes, 4, 4);
            const auto type = static_cast<std::uint32_t>(reader.value(header.bytes, 8, 4));
            const auto padded_name = add(name_size, (4 - (name_size & 3)) & 3);
            const auto padded_description = add(description_size, (4 - (description_size & 3)) & 3);
            const auto payload_size = add(padded_name, padded_description);
            require(payload_size <= end - cursor - 12, "ELF note payload exceeds PT_NOTE extent");
            require(name_size <= metadata_limit && description_size <= metadata_limit,
                    "ELF note exceeds metadata allocation limit", ErrorCode::resource_limit);
            const auto name_view = reader.bytes(cursor + 12, static_cast<std::size_t>(name_size));
            const auto description_at = add(cursor + 12, padded_name);
            const auto description_view = reader.bytes(description_at, static_cast<std::size_t>(description_size));
            ElfNote note;
            note.program = program.index;
            note.file_offset = cursor;
            note.description_file_offset = description_at;
            note.type = type;
            if (name_size) {
                const auto bytes = name_view.bytes;
                const auto length = bytes.back() == std::byte{0} ? bytes.size() - 1 : bytes.size();
                budget.include(length);
                note.name.assign(reinterpret_cast<const char *>(bytes.data()), length);
            }
            budget.include(sizeof(ElfNote) + description_size);
            note.description.assign(description_view.bytes.begin(), description_view.bytes.end());
            metadata.notes.push_back(std::move(note));
            cursor = add(cursor, add(12, payload_size));
        }
        require(cursor == end, "ELF note segment has an invalid trailing extent");
    }
    for (std::uint32_t i = 0; i < h.sections.count; ++i) {
        const auto view = reader.bytes(h.sections.offset + h.sections.stride * i, wide ? 64 : 40);
        const auto get = [&](std::size_t at, std::size_t n) { return reader.value(view.bytes, at, n); };
        ElfSection s;
        s.index = i;
        s.name_index = static_cast<std::uint32_t>(get(0, 4));
        s.type = static_cast<std::uint32_t>(get(4, 4));
        s.flags = get(8, wide ? 8 : 4);
        s.address = get(wide ? 16 : 12, wide ? 8 : 4);
        s.offset = get(wide ? 24 : 16, wide ? 8 : 4);
        s.size = get(wide ? 32 : 20, wide ? 8 : 4);
        s.link = static_cast<std::uint32_t>(get(wide ? 40 : 24, 4));
        s.info = static_cast<std::uint32_t>(get(wide ? 44 : 28, 4));
        s.alignment = get(wide ? 48 : 32, wide ? 8 : 4);
        s.entry_size = get(wide ? 56 : 36, wide ? 8 : 4);
        if (i == 0)
            require(s.type == 0, "ELF section0 must be SHT_NULL");
        else if (s.type != 0) {
            if (s.type != 8 && s.size)
                reader.extent(s.offset, s.size);
            require(aligned(s.alignment), "ELF section alignment is not a power of two");
            if (s.flags & 2) {
                const auto end = add(h.object_type == 1 ? 0 : s.address, s.size);
                require(wide || end <= UINT64_C(0x100000000), "ELF32 section exceeds address domain");
            }
        }
        metadata.sections.push_back(std::move(s));
    }
    if (h.section_names) {
        const auto &table = metadata.sections[static_cast<std::size_t>(h.section_names)];
        require(table.type == 3, "ELF section names require STRTAB");
        if (table.size == 0) {
            for (const auto &section : metadata.sections)
                require(section.name_index == 0, "Nonempty ELF name index in an empty string table");
            return;
        }
        budget.include(table.size);
        const auto strings = reader.bytes(table.offset, static_cast<std::size_t>(table.size));
        require(strings.bytes.front() == std::byte{0} && strings.bytes.back() == std::byte{0},
                "ELF string table must begin and end with an empty terminator");
        for (auto &section : metadata.sections) {
            canceled(stop);
            require(section.name_index < strings.bytes.size(), "ELF section name is outside string table");
            const auto tail = strings.bytes.subspan(section.name_index);
            const auto end = std::find(tail.begin(), tail.end(), std::byte{0});
            require(end != tail.end(), "Unterminated ELF section name");
            const auto length = static_cast<std::size_t>(end - tail.begin());
            budget.include(length);
            section.name.assign(reinterpret_cast<const char *>(tail.data()), length);
        }
    } else {
        for (const auto &section : metadata.sections)
            require(section.name_index == 0, "ELF section has a name without a string table");
    }
}
} // namespace hexlab::elf_detail
