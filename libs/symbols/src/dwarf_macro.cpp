#include "hexlab/symbols/dwarf.hpp"

#include <algorithm>
#include <limits>
#include <set>

namespace hexlab::symbols {
namespace {
using hexlab::Error;
using hexlab::ErrorCode;
template <class T> using R = hexlab::Result<T>;

Error malformed(const char *message) { return {ErrorCode::malformed, message}; }

class Reader {
  public:
    Reader(std::span<const std::uint8_t> bytes, bool little, std::size_t begin = 0,
           std::size_t end = static_cast<std::size_t>(-1))
        : bytes_(bytes), little_(little), at_(begin), end_(std::min(end, bytes.size())) {}

    std::size_t pos() const { return at_; }
    std::size_t end() const { return end_; }
    bool done() const { return at_ == end_; }
    bool can(std::size_t count) const { return at_ <= end_ && count <= end_ - at_; }

    R<std::uint64_t> fixed(std::size_t width) {
        if (width > 8 || !can(width)) return malformed("Truncated DWARF macro fixed-width field");
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < width; ++i) {
            const auto shift = 8 * (little_ ? i : width - 1 - i);
            value |= std::uint64_t(bytes_[at_++]) << shift;
        }
        return value;
    }

    R<std::uint64_t> uleb() {
        std::uint64_t value = 0;
        unsigned shift = 0;
        for (unsigned i = 0; i < 10; ++i) {
            if (!can(1)) return malformed("Truncated DWARF macro ULEB128 operand");
            const auto byte = bytes_[at_++];
            const auto payload = static_cast<std::uint8_t>(byte & 0x7f);
            if (i == 9) {
                if ((byte & 0x80) || payload > 1) return malformed("DWARF macro ULEB128 operand overflows");
                value |= std::uint64_t(payload) << 63;
                return value;
            }
            value |= std::uint64_t(payload) << shift;
            if (!(byte & 0x80)) return value;
            shift += 7;
        }
        return malformed("DWARF macro ULEB128 exceeds ten bytes");
    }

    R<std::string> cstring(std::size_t max_length) {
        const auto begin = at_;
        while (at_ < end_ && bytes_[at_] != 0) {
            if (at_ - begin >= max_length)
                return Error{ErrorCode::resource_limit, "DWARF macro string exceeds configured limit"};
            ++at_;
        }
        if (at_ == end_) return malformed("Unterminated DWARF macro string");
        std::string value(reinterpret_cast<const char *>(bytes_.data() + begin), at_ - begin);
        ++at_;
        return value;
    }

    void seek(std::size_t pos) { at_ = pos; }

  private:
    std::span<const std::uint8_t> bytes_;
    bool little_;
    std::size_t at_;
    std::size_t end_;
};

R<std::string> referenced_string(const DwarfMacroSections &sections, std::uint64_t offset,
                                 std::size_t &text_bytes) {
    if (sections.strings.empty())
        return Error{ErrorCode::unsupported, "DWARF macro strp opcode requires shared .debug_str"};
    if (offset >= sections.strings.size()) return malformed("DWARF macro string offset is out of bounds");
    Reader reader(sections.strings, sections.little_endian, static_cast<std::size_t>(offset));
    auto value = reader.cstring(sections.max_text_bytes - std::min(text_bytes, sections.max_text_bytes));
    if (!value) return value.error();
    if (value.value().size() > sections.max_text_bytes - std::min(text_bytes, sections.max_text_bytes))
        return Error{ErrorCode::resource_limit, "DWARF macro text budget exceeded"};
    text_bytes += value.value().size();
    return value;
}

R<std::string> indexed_string(const DwarfMacroSections &sections, std::uint64_t index,
                              std::size_t &text_bytes) {
    if (sections.string_offsets.empty())
        return Error{ErrorCode::unsupported, "DWARF macro strx opcode requires .debug_str_offsets.dwo"};
    if (!sections.string_offsets_base)
        return Error{ErrorCode::unsupported, "DWARF macro strx opcode requires the split unit's DW_AT_str_offsets_base"};
    const auto base = *sections.string_offsets_base;
    std::optional<std::pair<std::size_t, std::size_t>> contribution;
    std::optional<std::size_t> selected_width;
    for (const std::size_t offset_size : {std::size_t{4}, std::size_t{8}}) {
        const auto header_size = offset_size == 4 ? std::size_t{8} : std::size_t{16};
        if (base < header_size || base > sections.string_offsets.size()) continue;
        const auto begin = static_cast<std::size_t>(base) - header_size;
        Reader header(sections.string_offsets, sections.little_endian, begin);
        auto initial_length = header.fixed(4);
        if (!initial_length) continue;
        std::size_t actual_width = 4;
        if (initial_length.value() == UINT32_MAX) {
            auto extended = header.fixed(8);
            if (!extended) continue;
            initial_length = extended;
            actual_width = 8;
        } else if (initial_length.value() >= 0xfffffff0u) {
            continue;
        }
        if (actual_width != offset_size || initial_length.value() > header.end() - header.pos()) continue;
        const auto end = header.pos() + static_cast<std::size_t>(initial_length.value());
        if (end < base || end > header.end()) continue;
        auto version = header.fixed(2);
        auto padding = header.fixed(2);
        if (!version || !padding || version.value() != 5 || padding.value() != 0 || header.pos() != base)
            continue;
        if ((end - static_cast<std::size_t>(base)) % offset_size != 0) continue;
        if (contribution)
            return malformed("DWARF macro strx base identifies multiple string-offset contributions");
        contribution = std::pair{static_cast<std::size_t>(base), end};
        selected_width = offset_size;
    }
    if (!contribution || !selected_width)
        return malformed("DWARF macro strx base does not identify a DWARF v5 string-offset contribution");
    const auto [entries, end] = *contribution;
    const auto count = (end - entries) / *selected_width;
    if (index >= count) return malformed("DWARF macro strx index is outside its contribution");
    if (index > (std::numeric_limits<std::size_t>::max() - entries) / *selected_width)
        return malformed("DWARF macro strx entry offset overflows");
    const auto entry = entries + static_cast<std::size_t>(index) * *selected_width;
    Reader offset_reader(sections.string_offsets, sections.little_endian, entry, entry + *selected_width);
    auto string_offset = offset_reader.fixed(*selected_width);
    if (!string_offset) return string_offset.error();
    return referenced_string(sections, string_offset.value(), text_bytes);
}

struct FileContext {
    std::optional<std::uint64_t> index;
    std::optional<std::string> name;
    std::string source_id;
};

R<FileContext> resolve_file_context(const DwarfMacroUnit &unit, std::uint64_t index,
                                    std::span<const DwarfLineUnit> line_units) {
    FileContext context;
    context.index = index;
    if (!unit.line_table_offset) return context;
    const auto line = std::find_if(line_units.begin(), line_units.end(), [&](const auto &candidate) {
        return candidate.section_offset == *unit.line_table_offset;
    });
    if (line == line_units.end()) return context;
    context.source_id = line->source_id;
    std::size_t file_slot = 0;
    if (line->version == 5) {
        if (index >= line->files.size())
            return malformed("DWARF v5 macro file index is outside its matching line table");
        file_slot = static_cast<std::size_t>(index);
    } else {
        if (index == 0 || index > line->files.size())
            return malformed("Legacy DWARF macro file index is outside its matching line table");
        file_slot = static_cast<std::size_t>(index - 1);
    }
    context.name = line->files[file_slot].name;
    return context;
}

void apply_file_context(DwarfMacroRecord &record, const FileContext &context) {
    record.file_index = context.index;
    record.file_name = context.name;
    record.file_source_id = context.source_id;
}
} // namespace

R<std::vector<DwarfMacroUnit>> import_dwarf_macro_v5(const DwarfMacroSections &sections) {
    if (sections.source_id.empty() || sections.macro.empty())
        return Error{ErrorCode::invalid_argument, "DWARF macro source ID and contribution bytes are required"};
    if (sections.macro.size() > 64u * 1024u * 1024u ||
        sections.string_offsets.size() > 64u * 1024u * 1024u ||
        sections.max_text_bytes > 64u * 1024u * 1024u)
        return Error{ErrorCode::resource_limit, "DWARF macro input exceeds 64 MiB"};
    constexpr std::size_t hard_unit_limit = 65536;
    constexpr std::size_t hard_record_limit = 1'000'000;
    constexpr std::size_t hard_scope_limit = 65536;
    const auto unit_limit = std::min(sections.max_units, hard_unit_limit);
    const auto record_limit = std::min(sections.max_records, hard_record_limit);

    Reader all(sections.macro, sections.little_endian);
    std::vector<DwarfMacroUnit> units;
    std::size_t total_records = 0;
    std::size_t total_text_bytes = 0;
    while (!all.done()) {
        if (sections.stop.stop_requested()) return Error{ErrorCode::canceled, "DWARF macro import canceled"};
        if (units.size() >= unit_limit)
            return Error{ErrorCode::resource_limit, "DWARF macro unit count exceeds configured limit"};

        const auto local_unit_start = all.pos();
        auto initial_length = all.fixed(4);
        if (!initial_length) return initial_length.error();
        unsigned offset_size = 4;
        if (initial_length.value() == UINT32_MAX) {
            auto extended = all.fixed(8);
            if (!extended) return extended.error();
            initial_length = extended;
            offset_size = 8;
        } else if (initial_length.value() >= 0xfffffff0u) {
            return malformed("Reserved DWARF macro initial length");
        }
        if (initial_length.value() > all.end() - all.pos())
            return malformed("DWARF macro unit exceeds contribution extent");
        const auto unit_end = all.pos() + static_cast<std::size_t>(initial_length.value());
        Reader unit_reader(sections.macro, sections.little_endian, all.pos(), unit_end);
        if (!unit_reader.can(3)) return malformed("DWARF macro unit header is truncated");
        auto version = unit_reader.fixed(2);
        auto flags = unit_reader.fixed(1);
        if (!version) return version.error();
        if (!flags) return flags.error();
        if (version.value() != 5)
            return Error{ErrorCode::unsupported, "Only DWARF v5 macro units are supported"};
        if (flags.value() & 0xf8u) return malformed("DWARF macro unit has reserved flag bits");
        const auto declared_offset_size = (flags.value() & 1u) ? 8u : 4u;
        if (declared_offset_size != offset_size)
            return malformed("DWARF macro offset-size flag disagrees with unit length format");

        DwarfMacroUnit unit;
        unit.source_id = sections.source_id;
        unit.version = 5;
        unit.section_offset = sections.section_offset + local_unit_start;
        if (unit.section_offset < sections.section_offset) return malformed("DWARF macro source offset overflows");
        if (flags.value() & 2u) {
            auto line_offset = unit_reader.fixed(offset_size);
            if (!line_offset) return line_offset.error();
            unit.line_table_offset = line_offset.value();
        }
        if (flags.value() & 4u) {
            auto opcode_count = unit_reader.fixed(1);
            if (!opcode_count) return opcode_count.error();
            std::set<std::uint8_t> vendor_opcodes;
            std::uint64_t operand_count_total = 0;
            for (std::uint64_t i = 0; i < opcode_count.value(); ++i) {
                auto opcode = unit_reader.fixed(1);
                auto operand_count = unit_reader.uleb();
                if (!opcode) return opcode.error();
                if (!operand_count) return operand_count.error();
                if (opcode.value() < 0xe0 || !vendor_opcodes.insert(static_cast<std::uint8_t>(opcode.value())).second)
                    return malformed("DWARF macro opcode table has reserved or duplicate opcode");
                if (operand_count.value() > 4096 - operand_count_total)
                    return Error{ErrorCode::resource_limit, "DWARF macro opcode table exceeds operand limit"};
                operand_count_total += operand_count.value();
                for (std::uint64_t j = 0; j < operand_count.value(); ++j) {
                    auto form = unit_reader.uleb();
                    if (!form) return form.error();
                    if (form.value() > UINT8_MAX)
                        return malformed("DWARF macro opcode-table form is not representable");
                    // The table is consumed to bound the header. Vendor opcodes
                    // themselves remain unsupported and are never skipped.
                }
            }
        }

        bool terminated = false;
        std::vector<FileContext> file_scopes;
        while (!unit_reader.done()) {
            if (sections.stop.stop_requested()) return Error{ErrorCode::canceled, "DWARF macro import canceled"};
            const auto record_local_offset = unit_reader.pos();
            auto opcode_value = unit_reader.fixed(1);
            if (!opcode_value) return opcode_value.error();
            const auto opcode = static_cast<std::uint8_t>(opcode_value.value());
            if (opcode == 0) { terminated = true; break; }
            if (++total_records > record_limit)
                return Error{ErrorCode::resource_limit, "DWARF macro record count exceeds configured limit"};
            DwarfMacroRecord record;
            switch (opcode) {
            case 1: case 2: // DW_MACRO_define / DW_MACRO_undef, inline string
                record.kind = opcode == 1 ? DwarfMacroRecordKind::define : DwarfMacroRecordKind::undefine;
                if (auto line = unit_reader.uleb(); !line) return line.error(); else record.line = line.value();
                if (auto text = unit_reader.cstring(sections.max_text_bytes -
                        std::min(total_text_bytes, sections.max_text_bytes)); !text) return text.error();
                else { total_text_bytes += text.value().size(); record.text = std::move(text.value()); }
                break;
            case 3: // DW_MACRO_start_file
                record.kind = DwarfMacroRecordKind::start_file;
                if (auto line = unit_reader.uleb(); !line) return line.error(); else record.line = line.value();
                if (auto file = unit_reader.uleb(); !file) return file.error();
                else record.file_index = file.value();
                {
                    auto context = resolve_file_context(unit, *record.file_index, sections.line_units);
                    if (!context) return context.error();
                    apply_file_context(record, context.value());
                    if (file_scopes.size() >= hard_scope_limit)
                        return Error{ErrorCode::resource_limit, "DWARF macro file-scope nesting exceeds 65,536"};
                    file_scopes.push_back(std::move(context.value()));
                }
                break;
            case 4: // DW_MACRO_end_file
                record.kind = DwarfMacroRecordKind::end_file;
                if (file_scopes.empty()) return malformed("DWARF macro end_file has no matching start_file");
                apply_file_context(record, file_scopes.back());
                file_scopes.pop_back();
                break;
            case 5: case 6: { // DW_MACRO_define_strp / DW_MACRO_undef_strp
                record.kind = opcode == 5 ? DwarfMacroRecordKind::define : DwarfMacroRecordKind::undefine;
                if (auto line = unit_reader.uleb(); !line) return line.error(); else record.line = line.value();
                auto offset = unit_reader.fixed(offset_size);
                if (!offset) return offset.error();
                auto text = referenced_string(sections, offset.value(), total_text_bytes);
                if (!text) return text.error();
                record.text = std::move(text.value());
                break;
            }
            case 7:
                return Error{ErrorCode::unsupported, "DW_MACRO_import is unsupported for DWP contributions"};
            case 8: case 9:
                return Error{ErrorCode::unsupported, "DW_MACRO_define_sup/undef_sup require supplementary strings"};
            case 10:
                return Error{ErrorCode::unsupported, "DW_MACRO_import_sup requires a supplementary macro unit"};
            case 11: case 12: {
                record.kind = opcode == 11 ? DwarfMacroRecordKind::define : DwarfMacroRecordKind::undefine;
                if (auto line = unit_reader.uleb(); !line) return line.error(); else record.line = line.value();
                auto index = unit_reader.uleb();
                if (!index) return index.error();
                auto text = indexed_string(sections, index.value(), total_text_bytes);
                if (!text) return text.error();
                record.text = std::move(text.value());
                break;
            }
            default:
                return Error{ErrorCode::unsupported, "Unsupported DWARF macro opcode " + std::to_string(opcode)};
            }

            record.origin.source_id = sections.source_id;
            record.origin.section = ".debug_macro.dwo";
            record.origin.unit_offset = unit.section_offset;
            record.origin.record_offset = sections.section_offset + record_local_offset;
            if (record.origin.record_offset < sections.section_offset)
                return malformed("DWARF macro record source offset overflows");
            record.origin.record_size = unit_reader.pos() - record_local_offset;
            if (record.kind != DwarfMacroRecordKind::start_file &&
                record.kind != DwarfMacroRecordKind::end_file && !file_scopes.empty())
                apply_file_context(record, file_scopes.back());
            unit.records.push_back(std::move(record));
        }
        if (!terminated)
            return malformed("DWARF macro unit is missing its terminator");
        if (!unit_reader.done()) return malformed("DWARF macro unit has trailing bytes after its terminator");
        if (!file_scopes.empty()) return malformed("DWARF macro unit has unterminated file scopes");
        all.seek(unit_end);
        units.push_back(std::move(unit));
    }
    return units;
}
} // namespace hexlab::symbols
