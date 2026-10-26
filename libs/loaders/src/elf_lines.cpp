#include "elf_internal.hpp"
#include "hexlab/symbols/dwarf.hpp"

namespace hexlab::elf_detail {
namespace {
const ElfSection *find_debug_section(const ElfMetadata &metadata, std::string_view name) {
    const ElfSection *found = nullptr;
    for (const auto &section : metadata.sections) {
        const bool canonical = section.name == name;
        const bool gnu_alias = name.starts_with(".debug_") &&
            section.name.size() == name.size() + 1 && section.name.starts_with(".zdebug_") &&
            section.name.substr(2) == name.substr(1);
        if (!canonical && !gnu_alias) continue;
        if (found) throw Failure{{ErrorCode::malformed,
            "ELF contains duplicate " + std::string(name) + " sections"}};
        found = &section;
    }
    return found;
}

std::vector<std::uint8_t> read_line_section(const ByteStorage &storage,
    const ElfMetadata &metadata, const ElfSection &section, Budget &budget, std::stop_token stop) {
    return read_debug_section_bytes(storage, metadata, section, budget, stop);
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
