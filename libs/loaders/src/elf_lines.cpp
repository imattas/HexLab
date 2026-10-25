#include "elf_internal.hpp"
#include "hexlab/symbols/dwarf.hpp"

namespace hexlab::elf_detail {
namespace {
const ElfSection *find_debug_section(const ElfMetadata &metadata, std::string_view name) {
    const ElfSection *found = nullptr;
    for (const auto &section : metadata.sections) {
        if (section.name != name) continue;
        if (found) throw Failure{{ErrorCode::malformed,
            "ELF contains duplicate " + std::string(name) + " sections"}};
        found = &section;
    }
    return found;
}

std::vector<std::uint8_t> read_line_section(const ByteStorage &storage,
    const ElfMetadata &metadata, const ElfSection &section, Budget &budget, std::stop_token stop) {
    if (section.type == 8) throw Failure{{ErrorCode::unsupported,
        section.name + " is SHT_NOBITS and has no file contents"}};
    if (section.flags & 0x800) throw Failure{{ErrorCode::unsupported,
        "Compressed " + section.name + " is not interpreted"}};
    if (section.size > metadata_limit) throw Failure{{ErrorCode::resource_limit,
        section.name + " exceeds ELF metadata budget"}};
    budget.include(section.size);
    Reader reader(storage, metadata.header.order, stop);
    const auto view = reader.bytes(section.offset, static_cast<std::size_t>(section.size));
    std::vector<std::uint8_t> bytes;
    bytes.reserve(view.bytes.size());
    for (auto byte : view.bytes) { canceled(stop); bytes.push_back(std::to_integer<std::uint8_t>(byte)); }
    return bytes;
}
}
Result<bool> read_source_lines(const ByteStorage &storage, ElfMetadata &metadata, Budget &budget, std::stop_token stop) {
    const auto *found = find_debug_section(metadata, ".debug_line");
    if (!found || found->size == 0) return false;
    canceled(stop);
    auto data = read_line_section(storage, metadata, *found, budget, stop);
    std::vector<std::uint8_t> strings, line_strings;
    if (const auto *section = find_debug_section(metadata, ".debug_str"); section && section->size)
        strings = read_line_section(storage, metadata, *section, budget, stop);
    if (const auto *section = find_debug_section(metadata, ".debug_line_str"); section && section->size)
        line_strings = read_line_section(storage, metadata, *section, budget, stop);
    symbols::DwarfLineSections sections{"ELF .debug_line", data,
        static_cast<std::uint8_t>(metadata.header.is_64 ? 8 : 4),
        metadata.header.order == ByteOrder::little, 4'000'000, stop, strings, line_strings};
    auto parsed = symbols::import_dwarf_line_v2_v5(sections);
    if(!parsed)return parsed.error();
    for(const auto&unit:parsed.value())for(const auto&row:unit.rows){
        canceled(stop);std::string file;
        if(row.file&&row.file<=unit.files.size()){
            const auto&f=unit.files[static_cast<std::size_t>(row.file-1)];
            if(f.directory&&f.directory<=unit.directories.size())file=unit.directories[static_cast<std::size_t>(f.directory-1)]+"/";
            file+=f.name;
        }
        budget.include(sizeof(ElfSourceLine)+file.size());
        metadata.source_lines.push_back({{{0},row.address},std::move(file),row.line,row.column,row.end_sequence});
    }
    return true;
}
} // namespace hexlab::elf_detail
