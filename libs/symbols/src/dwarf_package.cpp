#include "hexlab/symbols/dwarf.hpp"

#include <algorithm>
#include <limits>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace hexlab::symbols {
namespace {
hexlab::Error malformed(std::string message) {
    return {hexlab::ErrorCode::malformed, std::move(message)};
}
hexlab::Error too_large(std::string message) {
    return {hexlab::ErrorCode::resource_limit, std::move(message)};
}

std::uint64_t read_unsigned(std::span<const std::uint8_t> bytes, std::size_t offset,
                            std::size_t width, bool little_endian) {
    std::uint64_t value = 0;
    if (little_endian) {
        for (std::size_t i = 0; i < width; ++i)
            value |= std::uint64_t(bytes[offset + i]) << (i * 8);
    } else {
        for (std::size_t i = 0; i < width; ++i)
            value = (value << 8) | bytes[offset + i];
    }
    return value;
}

bool checked_add(std::size_t left, std::size_t right, std::size_t &result) {
    if (right > std::numeric_limits<std::size_t>::max() - left) return false;
    result = left + right;
    return true;
}
bool checked_product(std::size_t left, std::size_t right, std::size_t &result) {
    if (left && right > std::numeric_limits<std::size_t>::max() / left) return false;
    result = left * right;
    return true;
}

bool valid_section_id(DwarfPackageIndexKind kind, std::uint32_t version, std::uint32_t id) {
    if (version == 2)
        return kind == DwarfPackageIndexKind::compile_units
            ? id == 1 || id == 2 || id == 3 || id == 4 || id == 5 || id == 6 || id == 7 || id == 8
            : id == 2 || id == 3 || id == 6;
    if (kind == DwarfPackageIndexKind::compile_units)
        return id == 1 || id == 3 || id == 4 || id == 5 || id == 6 || id == 7 || id == 8 || id == 9;
    return id == 1 || id == 3 || id == 4 || id == 6;
}

} // namespace

hexlab::Result<DwarfPackageIndex> parse_dwarf_package_index(
    std::span<const std::uint8_t> bytes, DwarfPackageIndexKind kind, bool little_endian,
    std::stop_token stop, DwarfPackageIndexLimits limits) {
    if (kind != DwarfPackageIndexKind::compile_units && kind != DwarfPackageIndexKind::type_units)
        return hexlab::Error{hexlab::ErrorCode::invalid_argument, "invalid DWARF package index kind"};
    if (bytes.size() > limits.max_index_bytes)
        return too_large("DWARF package index exceeds configured byte limit");
    if (bytes.size() < 16)
        return malformed("truncated DWARF package index header");
    if (stop.stop_requested())
        return hexlab::Error{hexlab::ErrorCode::canceled, "DWARF package index parsing canceled"};

    const auto version = read_unsigned(bytes, 0, 2, little_endian);
    const auto padding = read_unsigned(bytes, 2, 2, little_endian);
    const auto column_count = static_cast<std::uint32_t>(read_unsigned(bytes, 4, 4, little_endian));
    const auto unit_count = static_cast<std::uint32_t>(read_unsigned(bytes, 8, 4, little_endian));
    const auto slot_count = static_cast<std::uint32_t>(read_unsigned(bytes, 12, 4, little_endian));
    const auto actual_version = version == 2 && padding == 0 ? 2u : version;
    if (actual_version != 2 && actual_version != 5)
        return hexlab::Error{hexlab::ErrorCode::unsupported, "only DWARF package index versions 2 and 5 are supported"};
    if (actual_version == 5 && padding != 0)
        return malformed("DWARF v5 package index padding is nonzero");
    if (column_count > limits.max_columns || unit_count > limits.max_units || slot_count > limits.max_slots)
        return too_large("DWARF package index dimensions exceed configured limits");
    if (!column_count || !slot_count || (slot_count & (slot_count - 1)) != 0)
        return malformed("DWARF package index requires columns and a power-of-two slot count");
    if (unit_count > slot_count || (actual_version == 5 && std::uint64_t(slot_count) * 2 <= std::uint64_t(unit_count) * 3))
        return malformed("DWARF package index slot count violates the v5 load-factor bound");

    std::size_t hash_bytes = 0, row_index_bytes = 0, id_bytes = 0, value_cells = 0, value_bytes = 0;
    if (!checked_product(slot_count, 8, hash_bytes) || !checked_product(slot_count, 4, row_index_bytes) ||
        !checked_product(column_count, 4, id_bytes) ||
        !checked_product(unit_count, column_count, value_cells) || !checked_product(value_cells, 8, value_bytes))
        return too_large("DWARF package index dimensions overflow addressable size");
    std::size_t expected = 16;
    for (const auto amount : {hash_bytes, row_index_bytes, id_bytes, value_bytes}) {
        if (!checked_add(expected, amount, expected))
            return too_large("DWARF package index extent overflows addressable size");
    }
    if (expected > limits.max_index_bytes || expected > bytes.size())
        return malformed("DWARF package index tables exceed section extent");
    // The section is conventionally aligned to eight bytes. Permit only zero
    // alignment padding, so the parser never treats another table as padding.
    if (bytes.size() - expected > 7 ||
        std::any_of(bytes.begin() + static_cast<std::ptrdiff_t>(expected), bytes.end(),
                    [](std::uint8_t byte) { return byte != 0; }))
        return malformed("DWARF package index has unexpected trailing bytes");

    DwarfPackageIndex output;
    output.kind = kind;
    output.version = actual_version;
    output.slot_signatures.reserve(slot_count);
    output.slot_rows.reserve(slot_count);
    std::set<std::uint32_t> used_rows;
    std::set<std::uint64_t> signatures;
    std::size_t offset = 16;
    for (std::uint32_t slot = 0; slot < slot_count; ++slot) {
        if ((slot & 0x3fff) == 0 && stop.stop_requested())
            return hexlab::Error{hexlab::ErrorCode::canceled, "DWARF package index parsing canceled"};
        output.slot_signatures.push_back(read_unsigned(bytes, offset, 8, little_endian));
        offset += 8;
    }
    for (std::uint32_t slot = 0; slot < slot_count; ++slot) {
        const auto row = static_cast<std::uint32_t>(read_unsigned(bytes, offset, 4, little_endian));
        offset += 4;
        output.slot_rows.push_back(row);
        const auto signature = output.slot_signatures[slot];
        if (!row) {
            if (signature != 0) return malformed("unused DWARF package hash slot has a nonzero signature");
            continue;
        }
        if (row > unit_count) return malformed("DWARF package hash slot has an out-of-range row index");
        if (!used_rows.insert(row).second) return malformed("DWARF package row is indexed by multiple hash slots");
        if (!signatures.insert(signature).second) return malformed("duplicate signature in DWARF package index");
    }
    if (used_rows.size() != unit_count)
        return malformed("DWARF package index does not reference every declared row");

    output.section_ids.reserve(column_count);
    std::set<std::uint32_t> unique_section_ids;
    for (std::uint32_t column = 0; column < column_count; ++column) {
        const auto id = static_cast<std::uint32_t>(read_unsigned(bytes, offset, 4, little_endian));
        offset += 4;
        if (!valid_section_id(kind, actual_version, id))
            return hexlab::Error{hexlab::ErrorCode::unsupported,
                                 "unsupported DWARF package section ID " + std::to_string(id)};
        if (!unique_section_ids.insert(id).second)
            return malformed("duplicate section ID in DWARF package index");
        output.section_ids.push_back(id);
    }
    const auto required_info_id = actual_version == 2 && kind == DwarfPackageIndexKind::type_units ? 2u : 1u;
    if (!unique_section_ids.contains(required_info_id) || !unique_section_ids.contains(3))
        return malformed("DWARF package index lacks required INFO or ABBREV columns");

    output.rows.resize(unit_count);
    for (std::uint32_t row = 0; row < unit_count; ++row) {
        if ((row & 0x3fff) == 0 && stop.stop_requested())
            return hexlab::Error{hexlab::ErrorCode::canceled, "DWARF package index parsing canceled"};
        output.rows[row].sections.resize(column_count);
        for (std::uint32_t column = 0; column < column_count; ++column) {
            auto &contribution = output.rows[row].sections[column];
            contribution.section_id = output.section_ids[column];
            contribution.offset = static_cast<std::uint32_t>(read_unsigned(bytes, offset, 4, little_endian));
            offset += 4;
        }
    }
    for (std::uint32_t row = 0; row < unit_count; ++row) {
        if ((row & 0x3fff) == 0 && stop.stop_requested())
            return hexlab::Error{hexlab::ErrorCode::canceled, "DWARF package index parsing canceled"};
        for (std::uint32_t column = 0; column < column_count; ++column) {
            output.rows[row].sections[column].size = static_cast<std::uint32_t>(read_unsigned(bytes, offset, 4, little_endian));
            offset += 4;
        }
        const auto has_section = [&](std::uint32_t id) {
            const auto found = std::find(output.section_ids.begin(), output.section_ids.end(), id);
            if (found == output.section_ids.end()) return false;
            const auto column = static_cast<std::size_t>(found - output.section_ids.begin());
            return output.rows[row].sections[column].size != 0;
        };
        if (!has_section(required_info_id) || !has_section(3))
            return malformed("DWARF package row has an empty required INFO or ABBREV contribution");
    }
    if (offset != expected) return malformed("DWARF package index parser extent mismatch");

    // Recover each row signature using the 1-based hash-table row mapping.
    for (std::uint32_t slot = 0; slot < slot_count; ++slot) {
        const auto row = output.slot_rows[slot];
        if (!row) continue;
        auto &entry = output.rows[row - 1];
        entry.signature = output.slot_signatures[slot];
    }
    return output;
}

hexlab::Result<DwarfPackageContribution> find_dwarf_package_contribution(
    const DwarfPackageIndex &index, std::uint64_t signature,
    std::span<const DwarfPackageSectionData> section_data, std::stop_token stop) {
    if ((index.kind != DwarfPackageIndexKind::compile_units && index.kind != DwarfPackageIndexKind::type_units) ||
        index.slot_signatures.empty() || index.slot_signatures.size() != index.slot_rows.size() ||
        index.rows.size() > UINT32_MAX)
        return hexlab::Error{hexlab::ErrorCode::invalid_argument, "invalid parsed DWARF package index"};
    const auto slots = index.slot_signatures.size();
    if ((slots & (slots - 1)) != 0)
        return hexlab::Error{hexlab::ErrorCode::invalid_argument, "invalid DWARF package hash table size"};
    std::size_t columns = index.section_ids.size();
    std::set<std::uint32_t> unique_ids;
    for (const auto id : index.section_ids) {
        if (!valid_section_id(index.kind, index.version, id) || !unique_ids.insert(id).second)
            return hexlab::Error{hexlab::ErrorCode::invalid_argument, "invalid section ID table in DWARF package index"};
    }
    const auto required_info_id = index.version == 2 && index.kind == DwarfPackageIndexKind::type_units ? 2u : 1u;
    if (!unique_ids.contains(required_info_id) || !unique_ids.contains(3))
        return hexlab::Error{hexlab::ErrorCode::invalid_argument, "DWARF package index lacks required sections"};
    for (const auto &row : index.rows)
        if (row.sections.size() != columns)
            return hexlab::Error{hexlab::ErrorCode::invalid_argument, "invalid DWARF package row shape"};
    if (section_data.size() > 32)
        return too_large("too many source sections supplied for DWARF package lookup");
    std::set<std::uint32_t> supplied_ids;
    for (const auto &section : section_data)
        if (!supplied_ids.insert(section.section_id).second)
            return hexlab::Error{hexlab::ErrorCode::invalid_argument, "duplicate supplied DWARF package section ID"};

    const auto mask = static_cast<std::uint64_t>(slots - 1);
    auto slot = static_cast<std::size_t>(signature & mask);
    const auto step = static_cast<std::size_t>(((signature >> 32) & mask) | 1u);
    std::optional<std::uint32_t> row_index;
    for (std::size_t probe = 0; probe < slots; ++probe) {
        if ((probe & 0x3fff) == 0 && stop.stop_requested())
            return hexlab::Error{hexlab::ErrorCode::canceled, "DWARF package lookup canceled"};
        const auto candidate_row = index.slot_rows[slot];
        const auto candidate_signature = index.slot_signatures[slot];
        if (!candidate_row) {
            if (candidate_signature != 0)
                return malformed("invalid empty slot in parsed DWARF package index");
            break;
        }
        if (candidate_row > index.rows.size())
            return malformed("parsed DWARF package index contains an invalid row index");
        if (candidate_signature == signature) {
            row_index = candidate_row;
            break;
        }
        slot = (slot + step) & (slots - 1);
    }
    if (!row_index)
        return hexlab::Error{hexlab::ErrorCode::unsupported, "signature is absent from DWARF package index"};

    const auto &row = index.rows[*row_index - 1];
    if (row.signature != signature)
        return malformed("DWARF package signature-to-row mapping is inconsistent");
    DwarfPackageContribution output;
    output.signature = signature;
    output.sections.reserve(columns);
    for (std::size_t column = 0; column < columns; ++column) {
        const auto &range = row.sections[column];
        if (range.section_id != index.section_ids[column])
            return malformed("DWARF package row section ID does not match its column");
        const auto section = std::find_if(section_data.begin(), section_data.end(), [&](const auto &candidate) {
            return candidate.section_id == range.section_id;
        });
        if (section == section_data.end()) {
            if (range.size) return hexlab::Error{hexlab::ErrorCode::invalid_argument,
                                                 "missing source section for nonempty DWARF package contribution"};
            output.sections.push_back({range.section_id, {}, range.offset});
            continue;
        }
        const auto begin = static_cast<std::size_t>(range.offset);
        const auto length = static_cast<std::size_t>(range.size);
        if (begin > section->bytes.size() || length > section->bytes.size() - begin)
            return hexlab::Error{hexlab::ErrorCode::out_of_bounds,
                                 "DWARF package contribution exceeds its source section"};
        output.sections.push_back({range.section_id, section->bytes.subspan(begin, length), range.offset});
    }
    return output;
}

hexlab::Result<ImportResult> import_dwarf_package_unit(
    const DwarfPackageIndex &index, std::uint64_t dwo_id,
    std::span<const DwarfPackageSectionData> section_data,
    std::span<const std::uint8_t> strings, std::stop_token stop,
    std::span<const std::uint8_t> line_strings, std::uint8_t address_size,
    bool little_endian, DwarfTypeSignatureResolver type_signature_resolver) {
    return import_dwarf_package_unit(index,dwo_id,section_data,strings,stop,line_strings,address_size,
                                     little_endian,std::move(type_signature_resolver),{});
}

hexlab::Result<ImportResult> import_dwarf_package_unit(
    const DwarfPackageIndex &index, std::uint64_t dwo_id,
    std::span<const DwarfPackageSectionData> section_data,
    std::span<const std::uint8_t> strings, std::stop_token stop,
    std::span<const std::uint8_t> line_strings, std::uint8_t address_size,
    bool little_endian, DwarfTypeSignatureResolver type_signature_resolver,
    DwarfCrossContributionDieResolver cross_contribution_die_resolver) {
    if (index.kind != DwarfPackageIndexKind::compile_units)
        return hexlab::Error{hexlab::ErrorCode::invalid_argument,
                             "DWP split-unit import requires a CU package index"};
    auto contribution = find_dwarf_package_contribution(index, dwo_id, section_data, stop);
    if (!contribution) return contribution.error();

    DwarfSections dwarf;
    dwarf.source_id = "DWARF v" + std::to_string(index.version) + " DWP compile-unit contribution";
    dwarf.strings = strings;
    dwarf.line_strings = line_strings;
    dwarf.stop = stop;
    dwarf.expected_split_dwo_id = dwo_id;
    dwarf.type_signature_resolver = std::move(type_signature_resolver);
    dwarf.cross_contribution_die_resolver = std::move(cross_contribution_die_resolver);
    std::uint64_t info_section_offset = 0;
    std::span<const std::uint8_t> line_contribution;
    for (const auto &section : contribution.value().sections) {
        switch (section.section_id) {
        case 1: dwarf.info = section.bytes; info_section_offset = section.section_offset; break; // DW_SECT_INFO
        case 3: dwarf.abbrev = section.bytes; break;         // DW_SECT_ABBREV
        case 4: line_contribution = section.bytes; break;    // DW_SECT_LINE
        case 5: if(index.version==2) dwarf.locations = section.bytes; else dwarf.location_lists = section.bytes; break;
        case 6: dwarf.string_offsets = section.bytes; break; // DW_SECT_STR_OFFSETS
        case 8: if(index.version==5) dwarf.range_lists = section.bytes; break;
        case 9: dwarf.addresses = section.bytes; break;      // DW_SECT_ADDR
        default:
            // Macro contributions remain available to callers through the
            // bounded lookup API; this importer does not interpret them.
            break;
        }
    }
    dwarf.info_section_offset = info_section_offset;
    auto imported = import_dwarf(dwarf);
    if (!imported) return imported.error();
    if (!line_contribution.empty()) {
        DwarfLineSections line;
        line.source_id = "DWARF v5 DWP line contribution";
        line.line = line_contribution;
        line.address_size = address_size;
        line.little_endian = little_endian;
        line.max_rows = 4'000'000;
        line.stop = stop;
        line.strings = strings;
        line.line_strings = line_strings;
        auto line_units = import_dwarf_line_v2_v5(line);
        if (!line_units) return line_units.error();
        imported.value().line_units = std::move(line_units.value());
    }
    return imported;
}

DwarfTypeSignatureResolver make_dwarf_package_type_signature_resolver(
    std::shared_ptr<const DwarfPackageIndex> index,
    std::vector<DwarfPackageSectionData> sections,
    std::span<const std::uint8_t> strings,
    std::span<const std::uint8_t> line_strings,
    std::stop_token stop, DwarfPackageTypeResolutionLimits limits) {
    return make_dwarf_package_type_signature_resolver(std::move(index),std::move(sections),strings,line_strings,
                                                       stop,limits,{});
}

DwarfTypeSignatureResolver make_dwarf_package_type_signature_resolver(
    std::shared_ptr<const DwarfPackageIndex> index,
    std::vector<DwarfPackageSectionData> sections,
    std::span<const std::uint8_t> strings,
    std::span<const std::uint8_t> line_strings,
    std::stop_token stop, DwarfPackageTypeResolutionLimits limits,
    DwarfCrossContributionDieResolver cross_contribution_die_resolver) {
    if (!index || index->kind != DwarfPackageIndexKind::type_units)
        return [](std::uint64_t) -> hexlab::Result<types::TypePtr> {
            return hexlab::Error{hexlab::ErrorCode::invalid_argument,
                                 "invalid DWARF package type-signature resolver configuration"};
        };

    struct State {
        std::shared_ptr<const DwarfPackageIndex> index;
        std::vector<DwarfPackageSectionData> sections;
        std::span<const std::uint8_t> strings, line_strings;
        std::stop_token stop;
        DwarfPackageTypeResolutionLimits limits;
        DwarfCrossContributionDieResolver cross_contribution_die_resolver;
        std::uint64_t bytes_used = 0;
        std::uint32_t requests = 0;
        std::set<std::uint64_t> active;
        std::unordered_map<std::uint64_t, types::TypePtr> resolved;
        DwarfTypeSignatureResolver resolver;
    };
    auto state = std::make_shared<State>();
    state->index = std::move(index);
    state->sections = std::move(sections);
    state->strings = strings;
    state->line_strings = line_strings;
    state->stop = stop;
    state->limits = limits;
    state->cross_contribution_die_resolver = std::move(cross_contribution_die_resolver);
    const std::weak_ptr<State> weak_state = state;
    state->resolver = [weak_state](std::uint64_t signature) -> hexlab::Result<types::TypePtr> {
        const auto state = weak_state.lock();
        if (!state)
            return hexlab::Error{hexlab::ErrorCode::canceled, "DWP type-signature resolver is no longer available"};
        if (state->stop.stop_requested())
            return hexlab::Error{hexlab::ErrorCode::canceled, "DWARF package type resolution canceled"};
        if (auto found = state->resolved.find(signature); found != state->resolved.end()) return found->second;
        if (!state->active.insert(signature).second)
            return malformed("cyclic DW_FORM_ref_sig8 dependency across DWP type-unit contributions");
        struct ActiveGuard {
            std::set<std::uint64_t> &active;
            std::uint64_t signature;
            ~ActiveGuard() { active.erase(signature); }
        } active_guard{state->active, signature};
        if (state->requests >= state->limits.max_requests)
            return too_large("DWP type-signature request limit exceeded");
        ++state->requests;
        auto contribution = find_dwarf_package_contribution(*state->index, signature,
                                                             state->sections, state->stop);
        if (!contribution) return contribution.error();
        std::uint64_t contribution_bytes = 0;
        std::span<const std::uint8_t> info, abbrev, string_offsets;
        std::uint64_t info_section_offset = 0;
        for (const auto &section : contribution.value().sections) {
            if (section.bytes.size() > state->limits.max_bytes -
                                           std::min(state->limits.max_bytes, contribution_bytes))
                return too_large("DWP type-unit contribution exceeds the configured resolution byte limit");
            contribution_bytes += section.bytes.size();
            switch (section.section_id) {
            case 1: info = section.bytes; info_section_offset = section.section_offset; break;
            case 2: if(state->index->version==2){info=section.bytes;info_section_offset=section.section_offset;} break;
            case 3: abbrev = section.bytes; break;
            case 6: string_offsets = section.bytes; break;
            default: break;
            }
        }
        if (contribution_bytes > state->limits.max_bytes - state->bytes_used)
            return too_large("DWP type-signature byte budget exceeded");
        state->bytes_used += contribution_bytes;
        const bool dwarf4 = state->index->version == 2;
        if (info.size() < 4 || abbrev.empty())
            return malformed("truncated DWP type-unit contribution");
        const auto initial_length = read_unsigned(info, 0, 4, true);
        std::size_t initial_length_size = 4;
        std::size_t offset_size = 4;
        std::uint64_t unit_length = initial_length;
        if (initial_length == 0xffffffffu) {
            if (info.size() < 12)
                return malformed("truncated DWARF64 DWP type-unit length");
            unit_length = read_unsigned(info, 4, 8, true);
            initial_length_size = 12;
            offset_size = 8;
        } else if (initial_length >= 0xfffffff0u) {
            return malformed("DWP type-unit contribution uses a reserved initial length");
        }
        if (unit_length != info.size() - initial_length_size)
            return malformed("DWP type-unit contribution has an invalid or out-of-contribution unit extent");
        if (info.size() - initial_length_size < 2)
            return malformed("truncated DWP type-unit version");

        const auto version = read_unsigned(info, initial_length_size, 2, true);
        std::size_t signature_offset = 0;
        if (dwarf4) {
            // DWARF4 type-unit header: version, abbrev offset, address size,
            // signature, and type DIE offset. The latter follows the unit's
            // DWARF32/64 offset width.
            signature_offset = initial_length_size + 3 + offset_size;
        } else {
            // DWARF5 header: version, unit type, address size, abbrev offset,
            // signature, and type DIE offset.
            if (info.size() <= initial_length_size + 2)
                return malformed("truncated DWARF5 DWP type-unit header");
            signature_offset = initial_length_size + 4 + offset_size;
        }
        const auto type_offset_field = signature_offset + 8;
        const auto header_size = type_offset_field + offset_size;
        if (header_size > info.size())
            return malformed("DWP type-unit header exceeds its contribution");
        const auto unit_type = dwarf4 ? 0u : info[initial_length_size + 2];
        const auto header_signature = read_unsigned(info, signature_offset, 8, true);
        const auto type_die_offset = read_unsigned(info, type_offset_field, offset_size, true);
        if ((dwarf4 && version != 4) || (!dwarf4 && (version != 5 || (unit_type != 2 && unit_type != 6))))
            return hexlab::Error{hexlab::ErrorCode::unsupported,
                                 "DWP TU-index contribution has an unsupported type-unit header"};
        if (header_signature != signature || contribution.value().signature != signature)
            return malformed("DWP type-unit signature does not match its TU-index row");
        if (type_die_offset < header_size || type_die_offset >= info.size())
            return malformed("DWP type-unit target offset is outside its indexed contribution");

        DwarfSections dwarf;
        dwarf.source_id = dwarf4 ? "DWARF v2 DWP type-signature contribution" : "DWARF v5 DWP type-signature contribution";
        dwarf.info = info;
        dwarf.abbrev = abbrev;
        dwarf.strings = state->strings;
        dwarf.string_offsets = string_offsets;
        dwarf.line_strings = state->line_strings;
        dwarf.stop = state->stop;
        dwarf.info_section_offset = info_section_offset;
        dwarf.dwarf4_type_units = dwarf4;
        dwarf.type_signature_resolver = state->resolver;
        dwarf.cross_contribution_die_resolver = state->cross_contribution_die_resolver;
        auto imported = import_dwarf(dwarf);
        if (!imported) return imported.error();
        types::TypePtr result;
        for (const auto &type : imported.value().types) {
            if (type.origin.record_offset != info_section_offset + type_die_offset) continue;
            if (result && result->id() != type.type->id())
                return malformed("DWP type-unit target offset resolves to conflicting type records");
            result = type.type;
        }
        if (!result)
            return hexlab::Error{hexlab::ErrorCode::unsupported,
                                 "DWP TU-index type offset does not identify an imported type DIE"};
        auto encoded = types::encode(*result);
        if (!encoded) return encoded.error();
        if (encoded.value().size() > state->limits.max_bytes - state->bytes_used)
            return too_large("DWP resolved type graph exceeds the configured byte limit");
        state->bytes_used += encoded.value().size();
        state->resolved.emplace(signature, result);
        return result;
    };
    return [state](std::uint64_t signature) { return state->resolver(signature); };
}

DwarfTypeSignatureResolver make_dwarf_package_catalog_type_signature_resolver(
    std::vector<DwarfTypeUnitPackage> packages, std::stop_token stop,
    DwarfPackageTypeResolutionLimits limits) {
    struct State {
        std::vector<DwarfTypeUnitPackage> packages;
        std::unordered_map<std::uint64_t, std::size_t> owners;
        std::unordered_set<std::uint64_t> ambiguous;
        std::unordered_set<std::uint64_t> active;
        std::unordered_map<std::uint64_t, types::TypePtr> resolved;
        std::unordered_set<std::string> source_ids;
        std::stop_token stop;
        DwarfPackageTypeResolutionLimits limits;
        std::uint64_t bytes_used = 0;
        std::uint32_t requests = 0;
        std::uint64_t signature_rows = 0;
        std::optional<hexlab::Error> configuration_error;
        DwarfTypeSignatureResolver resolver;
    };
    auto state = std::make_shared<State>();
    state->stop = stop;
    state->limits = limits;
    if (packages.empty() || packages.size() > 64) {
        state->configuration_error = hexlab::Error{hexlab::ErrorCode::invalid_argument,
            "DWARF package catalog must contain 1..64 selected packages"};
    } else {
        state->packages = std::move(packages);
        for (std::size_t package_index = 0; package_index < state->packages.size(); ++package_index) {
            auto &package = state->packages[package_index];
            if (!package.identity_verified || package.source_id.empty() || package.source_id.size() > 4096 ||
                !state->source_ids.insert(package.source_id).second || !package.index ||
                package.index->kind != DwarfPackageIndexKind::type_units) {
                state->configuration_error = hexlab::Error{hexlab::ErrorCode::invalid_argument,
                    "DWARF package catalog contains an unverified, duplicate, or invalid type-unit package"};
                break;
            }
            if (package.index->rows.size() > 1'000'000 -
                    std::min<std::uint64_t>(1'000'000, state->signature_rows)) {
                state->configuration_error = too_large("DWARF package catalog exceeds 1,000,000 type signatures");
                break;
            }
            state->signature_rows += package.index->rows.size();
            std::unordered_set<std::uint64_t> package_signatures;
            for (const auto &row : package.index->rows) {
                if (stop.stop_requested()) {
                    state->configuration_error = hexlab::Error{hexlab::ErrorCode::canceled,
                        "DWARF package catalog construction canceled"};
                    break;
                }
                if (!package_signatures.insert(row.signature).second) {
                    state->configuration_error = malformed(
                        "DWARF package catalog index contains a duplicate type signature");
                    break;
                }
                auto [found, inserted] = state->owners.emplace(row.signature, package_index);
                if (!inserted && found->second != package_index) state->ambiguous.insert(row.signature);
            }
            if (state->configuration_error) break;
        }
    }

    const std::weak_ptr<State> weak_state = state;
    state->resolver = [weak_state](std::uint64_t signature) -> hexlab::Result<types::TypePtr> {
        const auto state = weak_state.lock();
        if (!state)
            return hexlab::Error{hexlab::ErrorCode::canceled,
                "DWARF package-catalog resolver is no longer available"};
        if (state->configuration_error) return *state->configuration_error;
        if (state->stop.stop_requested())
            return hexlab::Error{hexlab::ErrorCode::canceled,
                "DWARF package-catalog type resolution canceled"};
        if (auto found = state->resolved.find(signature); found != state->resolved.end())
            return found->second;
        if (state->ambiguous.contains(signature))
            return malformed("DWARF type signature is present in multiple selected packages");
        const auto owner = state->owners.find(signature);
        if (owner == state->owners.end())
            return hexlab::Error{hexlab::ErrorCode::unsupported,
                "DWARF type signature is absent from all selected package indexes"};
        if (!state->active.insert(signature).second)
            return malformed("cyclic DW_FORM_ref_sig8 dependency across selected DWP packages");
        struct ActiveGuard {
            std::unordered_set<std::uint64_t> &active;
            std::uint64_t signature;
            ~ActiveGuard() { active.erase(signature); }
        } active_guard{state->active, signature};
        if (state->requests >= state->limits.max_requests)
            return too_large("DWARF package-catalog type-signature request limit exceeded");
        ++state->requests;

        const auto &package = state->packages[owner->second];
        auto contribution = find_dwarf_package_contribution(*package.index, signature,
                                                              package.sections, state->stop);
        if (!contribution) return contribution.error();
        std::uint64_t contribution_bytes = 0;
        std::span<const std::uint8_t> info, abbrev, string_offsets;
        std::uint64_t info_section_offset = 0;
        for (const auto &section : contribution.value().sections) {
            if (section.bytes.size() > state->limits.max_bytes -
                    std::min(state->limits.max_bytes, contribution_bytes))
                return too_large("DWARF type contribution exceeds catalog resolution byte limit");
            contribution_bytes += section.bytes.size();
            switch (section.section_id) {
            case 1: info = section.bytes; info_section_offset = section.section_offset; break;
            case 2:
                if (package.index->version == 2) {
                    info = section.bytes;
                    info_section_offset = section.section_offset;
                }
                break;
            case 3: abbrev = section.bytes; break;
            case 6: string_offsets = section.bytes; break;
            default: break;
            }
        }
        if (contribution_bytes > state->limits.max_bytes -
                std::min(state->limits.max_bytes, state->bytes_used))
            return too_large("DWARF package-catalog aggregate byte budget exceeded");
        state->bytes_used += contribution_bytes;
        const bool dwarf4 = package.index->version == 2;
        if (info.size() < 4 || abbrev.empty())
            return malformed("truncated DWARF package-catalog type-unit contribution");
        const auto initial_length = read_unsigned(info, 0, 4, true);
        std::size_t initial_length_size = 4;
        std::size_t offset_size = 4;
        std::uint64_t unit_length = initial_length;
        if (initial_length == 0xffffffffu) {
            if (info.size() < 12)
                return malformed("truncated DWARF64 package-catalog type-unit length");
            unit_length = read_unsigned(info, 4, 8, true);
            initial_length_size = 12;
            offset_size = 8;
        } else if (initial_length >= 0xfffffff0u) {
            return malformed("package-catalog type unit uses a reserved initial length");
        }
        if (unit_length != info.size() - initial_length_size)
            return malformed("package-catalog type-unit extent is invalid");
        if (info.size() - initial_length_size < 2)
            return malformed("truncated package-catalog type-unit version");
        const auto version = read_unsigned(info, initial_length_size, 2, true);
        std::size_t signature_offset = 0;
        if (dwarf4) {
            signature_offset = initial_length_size + 3 + offset_size;
        } else {
            if (info.size() <= initial_length_size + 2)
                return malformed("truncated DWARF5 package-catalog type-unit header");
            signature_offset = initial_length_size + 4 + offset_size;
        }
        const auto type_offset_field = signature_offset + 8;
        const auto header_size = type_offset_field + offset_size;
        if (header_size > info.size())
            return malformed("package-catalog type-unit header exceeds its contribution");
        const auto unit_type = dwarf4 ? 0u : info[initial_length_size + 2];
        const auto header_signature = read_unsigned(info, signature_offset, 8, true);
        const auto type_die_offset = read_unsigned(info, type_offset_field, offset_size, true);
        if ((dwarf4 && version != 4) || (!dwarf4 && (version != 5 || (unit_type != 2 && unit_type != 6))))
            return hexlab::Error{hexlab::ErrorCode::unsupported,
                "selected DWP type-unit contribution uses an unsupported header"};
        if (header_signature != signature || contribution.value().signature != signature)
            return malformed("package-catalog type-unit signature does not match its index row");
        if (type_die_offset < header_size || type_die_offset >= info.size())
            return malformed("package-catalog type-unit target DIE is outside its contribution");

        DwarfSections dwarf;
        dwarf.source_id = package.source_id;
        dwarf.info = info;
        dwarf.abbrev = abbrev;
        dwarf.strings = package.strings;
        dwarf.string_offsets = string_offsets;
        dwarf.line_strings = package.line_strings;
        dwarf.stop = state->stop;
        dwarf.info_section_offset = info_section_offset;
        dwarf.dwarf4_type_units = dwarf4;
        dwarf.type_signature_resolver = state->resolver;
        dwarf.cross_contribution_die_resolver = package.cross_contribution_die_resolver;
        auto imported = import_dwarf(dwarf);
        if (!imported) return imported.error();
        types::TypePtr result;
        for (const auto &type : imported.value().types) {
            if (type.origin.record_offset != info_section_offset + type_die_offset) continue;
            if (result && result->id() != type.type->id())
                return malformed("package-catalog type-unit offset resolves to conflicting records");
            result = type.type;
        }
        if (!result)
            return hexlab::Error{hexlab::ErrorCode::unsupported,
                "package-catalog type-unit offset does not identify an imported type DIE"};
        auto encoded = types::encode(*result);
        if (!encoded) return encoded.error();
        if (encoded.value().size() > state->limits.max_bytes -
                std::min(state->limits.max_bytes, state->bytes_used))
            return too_large("DWARF package-catalog type graph exceeds aggregate byte budget");
        state->bytes_used += encoded.value().size();
        state->resolved.emplace(signature, result);
        return result;
    };
    return [state](std::uint64_t signature) { return state->resolver(signature); };
}

DwarfSourceCrossContributionDieResolver make_dwarf_package_catalog_cross_contribution_die_resolver(
    std::vector<DwarfCompileUnitPackage> packages, std::stop_token stop,
    DwarfPackageTypeResolutionLimits limits) {
    struct Entry { std::string source_id; DwarfCrossContributionDieResolver resolver; };
    auto entries = std::make_shared<std::vector<Entry>>();
    auto error = std::make_shared<std::optional<hexlab::Error>>();
    std::unordered_set<std::string> ids;
    if (packages.empty() || packages.size() > 64) {
        *error = hexlab::Error{hexlab::ErrorCode::invalid_argument,
            "DWARF CU package catalog must contain 1..64 selected packages"};
    } else {
        for (auto &package : packages) {
            if (!package.identity_verified || package.source_id.empty() || package.source_id.size() > 4096 ||
                !ids.insert(package.source_id).second || !package.index ||
                package.index->kind != DwarfPackageIndexKind::compile_units) {
                *error = hexlab::Error{hexlab::ErrorCode::invalid_argument,
                    "DWARF CU package catalog contains an unverified, duplicate, or invalid package"};
                break;
            }
            entries->push_back({package.source_id, make_dwarf_package_cross_contribution_die_resolver(
                std::move(package.index), std::move(package.sections), package.strings,
                package.line_strings, stop, limits)});
        }
    }
    return [entries, error, stop](std::string_view source_id, std::uint64_t offset)
        -> hexlab::Result<DwarfCrossContributionDie> {
        if (*error) return **error;
        if (stop.stop_requested()) return hexlab::Error{hexlab::ErrorCode::canceled,
            "DWARF CU package-catalog resolution canceled"};
        const Entry *match = nullptr;
        for (const auto &entry : *entries) if (entry.source_id == source_id) {
            if (match) return malformed("DWARF CU package catalog has ambiguous source identity");
            match = &entry;
        }
        if (!match) return hexlab::Error{hexlab::ErrorCode::unsupported,
            "DW_FORM_ref_addr source identity is absent from selected CU packages"};
        return match->resolver(offset);
    };
}

DwarfCrossContributionDieResolver make_dwarf_package_cross_contribution_die_resolver(
    std::shared_ptr<const DwarfPackageIndex> index,
    std::vector<DwarfPackageSectionData> sections,
    std::span<const std::uint8_t> strings,
    std::span<const std::uint8_t> line_strings,
    std::stop_token stop, DwarfPackageTypeResolutionLimits limits) {
    if (!index || index->kind != DwarfPackageIndexKind::compile_units)
        return [](std::uint64_t) -> hexlab::Result<DwarfCrossContributionDie> {
            return hexlab::Error{hexlab::ErrorCode::invalid_argument,
                                 "invalid DWARF package cross-contribution resolver configuration"};
        };
    struct State {
        std::shared_ptr<const DwarfPackageIndex> index;
        std::vector<DwarfPackageSectionData> sections;
        std::span<const std::uint8_t> strings, line_strings;
        std::stop_token stop;
        DwarfPackageTypeResolutionLimits limits;
        std::uint64_t bytes = 0;
        std::uint32_t requests = 0;
    };
    auto state = std::make_shared<State>();
    state->index = std::move(index); state->sections = std::move(sections);
    state->strings = strings; state->line_strings = line_strings;
    state->stop = stop; state->limits = limits;
    return [state](std::uint64_t absolute_offset) -> hexlab::Result<DwarfCrossContributionDie> {
        if (state->stop.stop_requested()) return hexlab::Error{hexlab::ErrorCode::canceled, "DWARF package reference resolution canceled"};
        if (state->requests >= state->limits.max_requests) return too_large("DWP cross-contribution request limit exceeded");
        ++state->requests;
        std::optional<std::uint64_t> owner;
        for (const auto &row : state->index->rows) {
            const auto info = std::find_if(row.sections.begin(), row.sections.end(), [](const auto &s) { return s.section_id == 1; });
            if (info == row.sections.end() || !info->size || absolute_offset < info->offset || absolute_offset - info->offset >= info->size) continue;
            if (owner) return malformed("DWARF package reference offset maps to multiple CU-index rows");
            owner = row.signature;
        }
        if (!owner) return hexlab::Error{hexlab::ErrorCode::unsupported, "DW_FORM_ref_addr target is absent from the selected DWP CU index"};
        auto contribution = find_dwarf_package_contribution(*state->index, *owner, state->sections, state->stop);
        if (!contribution) return contribution.error();
        std::uint64_t cost = 0;
        for (const auto &section : contribution.value().sections) {
            if (section.bytes.size() > state->limits.max_bytes - std::min(state->limits.max_bytes, cost)) return too_large("DWP target contribution exceeds the cross-reference byte limit");
            cost += section.bytes.size();
        }
        if (cost > state->limits.max_bytes - state->bytes) return too_large("DWP cross-contribution byte budget exceeded");
        state->bytes += cost;
        auto imported = import_dwarf_package_unit(*state->index, *owner, state->sections, state->strings,
                                                   state->stop, state->line_strings);
        if (!imported) return imported.error();
        DwarfCrossContributionDie result;
        result.info_section_offset = absolute_offset;
        result.contribution_signature = *owner;
        result.contribution_size = cost;
        result.index_kind = DwarfPackageIndexKind::compile_units;
        result.bytes_examined = cost;
        result.identity_verified = true;
        for (const auto &type : imported.value().types) {
            if (type.origin.record_offset != absolute_offset) continue;
            if (result.type && result.type->id() != type.type->id()) return malformed("DWP target offset resolves to conflicting type DIEs");
            result.kind = DwarfReferencedDieKind::type; result.name = type.source_name; result.type = type.type;
        }
        for (const auto &symbol : imported.value().symbols) {
            if (symbol.kind != SymbolKind::function || symbol.origin.record_offset != absolute_offset) continue;
            if (result.type) return malformed("DWP target offset resolves to conflicting DIE kinds");
            result.kind = DwarfReferencedDieKind::subprogram; result.name = symbol.name; result.type = symbol.type;
        }
        for (const auto &variable : imported.value().variables) {
            if (variable.is_parameter || variable.origin.record_offset != absolute_offset) continue;
            if (result.type) return malformed("DWP target offset resolves to conflicting DIE kinds");
            result.kind = DwarfReferencedDieKind::variable; result.name = variable.name; result.type = variable.type;
        }
        if (!result.type) return hexlab::Error{hexlab::ErrorCode::unsupported, "DWP reference target offset does not identify a supported type, subprogram, or variable DIE"};
        return result;
    };
}

} // namespace hexlab::symbols
