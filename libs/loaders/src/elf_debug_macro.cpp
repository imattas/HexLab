#include "elf_internal.hpp"

#include <algorithm>
#include <iterator>
#include <set>

namespace hexlab::elf_detail {
namespace {
std::uint64_t fixed(std::span<const std::uint8_t> bytes, std::size_t &at, unsigned width,
                    ByteOrder order) {
    require(width <= 8 && at <= bytes.size() && width <= bytes.size() - at,
            "Truncated DWARF macro-unit field");
    std::uint64_t value = 0;
    for (unsigned i = 0; i < width; ++i) {
        const unsigned shift = 8u * (order == ByteOrder::little ? i : width - 1 - i);
        value |= std::uint64_t(bytes[at + i]) << shift;
    }
    at += width;
    return value;
}
std::uint64_t uleb(std::span<const std::uint8_t> bytes, std::size_t &at) {
    std::uint64_t result = 0;
    unsigned shift = 0;
    for (unsigned i = 0; i < 10; ++i) {
        require(at < bytes.size(), "Truncated DWARF macro ULEB128 operand");
        const auto byte = bytes[at++];
        const auto payload = static_cast<std::uint8_t>(byte & 0x7f);
        if (i == 9) {
            require(!(byte & 0x80) && payload <= 1, "DWARF macro ULEB128 operand overflows");
            result |= std::uint64_t(payload) << 63;
            return result;
        }
        result |= std::uint64_t(payload) << shift;
        if (!(byte & 0x80)) return result;
        shift += 7;
    }
    require(false, "DWARF macro ULEB128 operand exceeds ten bytes");
    return 0;
}
std::string cstring(std::span<const std::uint8_t> bytes, std::size_t &at, Budget &budget) {
    require(at <= bytes.size(), "Invalid DWARF macro string offset");
    const auto begin = at;
    while (at < bytes.size() && bytes[at] != 0) ++at;
    require(at < bytes.size(), "Unterminated inline DWARF macro string");
    const auto length = at - begin;
    budget.include(length);
    std::string value(reinterpret_cast<const char *>(bytes.data() + begin), length);
    ++at;
    return value;
}
void parse_section(const ByteStorage &storage, ElfMetadata &metadata, const ElfSection &section,
                   Budget &budget, std::stop_token stop) {
    const bool compressed = (section.flags & 0x800) != 0 || section.name.starts_with(".zdebug_");
    const auto data = read_debug_section_bytes(storage, metadata, section, budget, stop);
    const auto all = std::span<const std::uint8_t>(data);
    std::vector<ElfDwarfMacroUnit> parsed_units;
    std::uint64_t total_records = 0;
    std::size_t cursor = 0;
    while (cursor < all.size()) {
        canceled(stop);
        const auto unit_begin = cursor;
        auto initial_length = fixed(all, cursor, 4, metadata.header.order);
        unsigned offset_size = 4;
        if (initial_length == UINT32_MAX) {
            offset_size = 8;
            initial_length = fixed(all, cursor, 8, metadata.header.order);
        } else if (initial_length >= 0xfffffff0u) {
            require(false, "Reserved DWARF macro initial length");
        }
        require(initial_length <= all.size() - cursor, "DWARF macro unit exceeds its section");
        const auto unit_end = cursor + static_cast<std::size_t>(initial_length);
        require(unit_end - cursor >= 3, "DWARF macro unit header is truncated");
        const auto version = static_cast<std::uint16_t>(fixed(all, cursor, 2, metadata.header.order));
        require(version == 5, "Only DWARF v5 macro units are supported", ErrorCode::unsupported);
        const auto flags = static_cast<std::uint8_t>(fixed(all, cursor, 1, metadata.header.order));
        require((flags & 0xf8u) == 0, "DWARF macro unit has reserved flag bits");
        const auto unit_offset_size = (flags & 1u) ? 8u : 4u;
        require(unit_offset_size == offset_size, "DWARF macro offset-size flag disagrees with initial length");
        std::set<std::uint8_t> vendor_opcodes;
        std::optional<std::uint64_t> line_offset;
        if (flags & 2u) {
            require(cursor <= unit_end && offset_size <= unit_end - cursor,
                    "DWARF macro line-table offset exceeds its unit");
            line_offset = fixed(all, cursor, offset_size, metadata.header.order);
        }
        if (flags & 4u) {
            require(cursor < unit_end, "DWARF macro opcode table is truncated");
            const auto count = static_cast<std::uint8_t>(fixed(all, cursor, 1, metadata.header.order));
            std::uint64_t operands = 0;
            for (unsigned i = 0; i < count; ++i) {
                require(unit_end - cursor >= 2, "DWARF macro opcode table entry is truncated");
                const auto opcode = static_cast<std::uint8_t>(fixed(all, cursor, 1, metadata.header.order));
                require(opcode >= 0xe0 && vendor_opcodes.insert(opcode).second,
                        "DWARF macro opcode table has a reserved or duplicate opcode");
                const auto operand_count = uleb(all.first(unit_end), cursor);
                require(operand_count <= 4096 - operands,
                        "DWARF macro opcode table exceeds its operand limit", ErrorCode::resource_limit);
                operands += operand_count;
                for (std::uint64_t j = 0; j < operand_count; ++j) {
                    const auto form = fixed(all.first(unit_end), cursor, 1, metadata.header.order);
                    const bool known_form = form == 0x03 || form == 0x04 || form == 0x05 || form == 0x06 ||
                        form == 0x07 || form == 0x08 || form == 0x09 || form == 0x0a || form == 0x0b ||
                        form == 0x0c || form == 0x0d || form == 0x0e || form == 0x0f || form == 0x17 ||
                        form == 0x1a || form == 0x1d || form == 0x1e || form == 0x1f ||
                        (form >= 0x25 && form <= 0x28);
                    require(known_form, "DWARF macro opcode table contains an unsupported operand form",
                            ErrorCode::unsupported);
                }
            }
        }
        require(cursor <= unit_end, "DWARF macro header exceeds unit extent");
        ElfDwarfMacroUnit unit;
        unit.section = section.index;
        unit.section_name = section.name;
        unit.section_offset = unit_begin;
        unit.file_offset = compressed ? section.offset : add(section.offset, unit_begin);
        unit.length = unit_end - unit_begin;
        unit.version = version;
        unit.offset_size = static_cast<std::uint8_t>(offset_size);
        unit.compressed = compressed;
        unit.line_table_offset = line_offset;
        for (;;) {
            canceled(stop);
            require(cursor < unit_end, "DWARF macro unit is missing its terminator");
            const auto op_offset = cursor;
            const auto opcode = static_cast<std::uint8_t>(fixed(all, cursor, 1, metadata.header.order));
            if (!opcode) break;
            require(++total_records <= 1'000'000,
                    "DWARF macro record count exceeds one million", ErrorCode::resource_limit);
            budget.include(sizeof(ElfDwarfMacroRecord));
            ElfDwarfMacroRecord record;
            record.section_offset = op_offset;
            record.file_offset = compressed ? section.offset : add(section.offset, op_offset);
            record.opcode = opcode;
            switch (opcode) {
            case 1: case 2:
                record.line = uleb(all.first(unit_end), cursor);
                record.text = cstring(all.first(unit_end), cursor, budget);
                break;
            case 3:
                record.line = uleb(all.first(unit_end), cursor);
                record.file_index = uleb(all.first(unit_end), cursor);
                break;
            case 4:
                break;
            case 5: case 6:
                record.line = uleb(all.first(unit_end), cursor);
                record.string_offset = fixed(all.first(unit_end), cursor, offset_size, metadata.header.order);
                break;
            case 7:
                record.import_offset = fixed(all.first(unit_end), cursor, offset_size, metadata.header.order);
                break;
            case 8: case 9:
                record.line = uleb(all.first(unit_end), cursor);
                record.string_offset = fixed(all.first(unit_end), cursor, offset_size, metadata.header.order);
                record.supplementary_string = true;
                break;
            case 10:
                record.supplementary_import_offset = fixed(all.first(unit_end), cursor, offset_size,
                                                          metadata.header.order);
                break;
            case 11: case 12:
                record.line = uleb(all.first(unit_end), cursor);
                record.string_index = uleb(all.first(unit_end), cursor);
                break;
            default:
                require(vendor_opcodes.contains(opcode), "Unknown DWARF macro opcode has no operand description",
                        ErrorCode::unsupported);
                require(false, "DWARF vendor macro opcodes are not interpreted", ErrorCode::unsupported);
            }
            require(cursor <= unit_end, "DWARF macro opcode operands exceed unit extent");
            unit.records.push_back(std::move(record));
        }
        require(cursor == unit_end, "DWARF macro unit has trailing bytes after its terminator");
        budget.include(sizeof(ElfDwarfMacroUnit) + unit.section_name.size());
        parsed_units.push_back(std::move(unit));
    }
    std::set<std::uint64_t> starts;
    for (const auto &unit : parsed_units) starts.insert(unit.section_offset);
    for (const auto &unit : parsed_units) {
        for (const auto &record : unit.records)
            if (record.import_offset)
                require(starts.contains(*record.import_offset),
                        "DWARF macro import does not target a unit boundary");
    }
    metadata.dwarf_macro_units.insert(metadata.dwarf_macro_units.end(),
                                      std::make_move_iterator(parsed_units.begin()),
                                      std::make_move_iterator(parsed_units.end()));
}

// DWARF 2-4 store macro operations in .debug_macinfo without a unit header.
// A zero opcode ends one compilation unit's contribution; subsequent bytes may
// begin another contribution. Keep this parser deliberately conservative:
// vendor extensions need a length description and are not safe to skip.
void parse_legacy_macinfo(const ByteStorage &storage, ElfMetadata &metadata,
                          const ElfSection &section, Budget &budget,
                          std::stop_token stop) {
    const bool compressed = (section.flags & 0x800) != 0 || section.name.starts_with(".zdebug_");
    const auto data = read_debug_section_bytes(storage, metadata, section, budget, stop);
    const auto all = std::span<const std::uint8_t>(data);
    std::vector<ElfDwarfMacroUnit> units;
    std::uint64_t total_records = 0;
    std::size_t cursor = 0;
    while (cursor < all.size()) {
        canceled(stop);
        const auto unit_begin = cursor;
        ElfDwarfMacroUnit unit;
        unit.section = section.index;
        unit.section_name = section.name;
        unit.section_offset = unit_begin;
        unit.file_offset = compressed ? section.offset : add(section.offset, unit_begin);
        unit.version = 0; // Legacy macinfo carries no version field.
        unit.offset_size = 0;
        unit.compressed = compressed;
        bool terminated = false;
        while (cursor < all.size()) {
            canceled(stop);
            const auto op_offset = cursor;
            const auto opcode = static_cast<std::uint8_t>(fixed(all, cursor, 1, metadata.header.order));
            if (opcode == 0) {
                terminated = true;
                break;
            }
            require(++total_records <= 1'000'000,
                    "Legacy DWARF macro record count exceeds one million", ErrorCode::resource_limit);
            budget.include(sizeof(ElfDwarfMacroRecord));
            ElfDwarfMacroRecord record;
            record.section_offset = op_offset;
            record.file_offset = compressed ? section.offset : add(section.offset, op_offset);
            record.opcode = opcode;
            switch (opcode) {
            case 1: case 2:
                record.line = uleb(all, cursor);
                record.text = cstring(all, cursor, budget);
                break;
            case 3:
                record.line = uleb(all, cursor);
                record.file_index = uleb(all, cursor);
                break;
            case 4:
                break;
            case 255: // DW_MACINFO_vendor_ext: constant followed by a string.
                record.line = uleb(all, cursor);
                record.text = cstring(all, cursor, budget);
                break;
            default:
                require(false, "Legacy DWARF vendor macro opcode is unsupported", ErrorCode::unsupported);
            }
            unit.records.push_back(std::move(record));
        }
        require(terminated, "Legacy DWARF macro contribution is missing its terminator");
        unit.length = cursor - unit_begin;
        budget.include(sizeof(ElfDwarfMacroUnit) + unit.section_name.size());
        units.push_back(std::move(unit));
    }
    metadata.dwarf_macro_units.insert(metadata.dwarf_macro_units.end(),
                                      std::make_move_iterator(units.begin()),
                                      std::make_move_iterator(units.end()));
}
} // namespace

Result<bool> read_dwarf_macros(const ByteStorage &storage, ElfMetadata &metadata, Budget &budget,
                               std::stop_token stop) {
    try {
        for (const auto &section : metadata.sections) {
            canceled(stop);
            if (section.name == ".debug_macinfo" || section.name == ".zdebug_macinfo")
                parse_legacy_macinfo(storage, metadata, section, budget, stop);
            else if (section.name == ".debug_macro" || section.name == ".debug_macro.dwo" ||
                section.name == ".zdebug_macro" || section.name == ".zdebug_macro.dwo")
                parse_section(storage, metadata, section, budget, stop);
        }
        return true;
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate ELF DWARF macro metadata"};
    }
}
} // namespace hexlab::elf_detail
