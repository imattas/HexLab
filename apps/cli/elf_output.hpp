#pragma once
#include "hexlab/workspace/navigation.hpp"
#include "demangle_output.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
namespace hexlab::cli {
inline std::string elf_hex(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}
inline std::string elf_text(std::string_view value) {
    std::ostringstream out;
    for (unsigned char ch : value) {
        if (ch >= 32 && ch < 127)
            out << static_cast<char>(ch);
        else
            out << "\\x" << std::hex << std::setw(2) << std::setfill('0') << unsigned(ch);
    }
    return out.str();
}
inline const char *elf_state(ElfSymbolState value) {
    switch (value) {
    case ElfSymbolState::undefined:
        return "undefined";
    case ElfSymbolState::defined:
        return "defined";
    case ElfSymbolState::absolute:
        return "absolute";
    case ElfSymbolState::common:
        return "common";
    case ElfSymbolState::tls:
        return "tls";
    case ElfSymbolState::reserved:
        return "reserved";
    }
    return "unknown";
}
inline void elf_description(std::ostream &out, const ImageMetadata &metadata, const Image *image) {
    if (!metadata.elf)
        return;
    const auto &elf = *metadata.elf;
    const auto &header = elf.header;
    out << "ELF: class=" << (header.is_64 ? 64 : 32)
        << " endian=" << (header.order == ByteOrder::little ? "little" : "big") << " type="
        << (header.object_type == 1   ? "REL"
            : header.object_type == 2 ? "EXEC"
            : header.object_type == 3 ? "DYN"
            : header.object_type == 4 ? "CORE"
                                      : "unknown")
        << " OSABI=" << unsigned(header.os_abi) << " flags=" << elf_hex(header.flags) << '\n';
    if (elf.interpreter)
        out << "Interpreter: " << elf_text(elf.interpreter->path) << '\n';
    constexpr std::size_t max_debug_companion_rows = 128;
    out << "ELF GNU debuglink records: " << elf.gnu_debug_links.size() << '\n';
    for (std::size_t index = 0; index < std::min(elf.gnu_debug_links.size(), max_debug_companion_rows); ++index) {
        const auto &link = elf.gnu_debug_links[index];
        out << "  section=" << link.section << " filename=\"" << elf_text(link.filename)
            << "\" crc32=" << elf_hex(link.crc32) << " file=" << elf_hex(link.file_offset)
            << " crc-file=" << elf_hex(link.crc_file_offset) << '\n';
    }
    if (elf.gnu_debug_links.size() > max_debug_companion_rows)
        out << "  debuglink-output-capped=true omitted=" << elf.gnu_debug_links.size() - max_debug_companion_rows << '\n';
    out << "ELF GNU debugaltlink records: " << elf.gnu_debug_altlinks.size() << '\n';
    for (std::size_t index = 0; index < std::min(elf.gnu_debug_altlinks.size(), max_debug_companion_rows); ++index) {
        const auto &link = elf.gnu_debug_altlinks[index];
        out << "  section=" << link.section << " filename=\"" << elf_text(link.filename)
            << "\" build-id-bytes=" << link.build_id.size() << " build-id=";
        const auto shown = std::min<std::size_t>(link.build_id.size(), 32);
        const auto previous_fill = out.fill();
        for (std::size_t byte = 0; byte < shown; ++byte)
            out << std::hex << std::setw(2) << std::setfill('0')
                << std::to_integer<unsigned>(link.build_id[byte]);
        out.fill(previous_fill);
        out << " file=" << elf_hex(link.file_offset) << " build-id-file="
            << elf_hex(link.build_id_file_offset) << '\n';
    }
    if (elf.gnu_debug_altlinks.size() > max_debug_companion_rows)
        out << "  debugaltlink-output-capped=true omitted=" << elf.gnu_debug_altlinks.size() - max_debug_companion_rows << '\n';
    out << "ELF programs: " << elf.programs.size() << " sections=" << elf.sections.size() << '\n';
    constexpr std::size_t max_program_rows = 256;
    const auto shown_programs = std::min(elf.programs.size(), max_program_rows);
    for (std::size_t index = 0; index < shown_programs; ++index) {
        const auto &program = elf.programs[index];
        const char *type = program.type == 0 ? "NULL" : program.type == 1 ? "LOAD" :
                           program.type == 2 ? "DYNAMIC" : program.type == 3 ? "INTERP" :
                           program.type == 4 ? "NOTE" : program.type == 5 ? "SHLIB" :
                           program.type == 6 ? "PHDR" : program.type == 7 ? "TLS" :
                           program.type == 0x6474e551 ? "GNU_STACK" :
                           program.type == 0x6474e552 ? "GNU_RELRO" :
                           program.type == 0x6474e553 ? "GNU_PROPERTY" : "unknown";
        out << "  program #" << program.index << " type=" << type << '(' << program.type << ") flags="
            << elf_hex(program.flags) << "["
            << ((program.flags & 4) ? 'R' : '-') << ((program.flags & 2) ? 'W' : '-')
            << ((program.flags & 1) ? 'X' : '-') << "] file=" << elf_hex(program.offset)
            << '+' << elf_hex(program.file_size) << " address=" << elf_hex(program.address)
            << '+' << elf_hex(program.memory_size) << " align=" << elf_hex(program.alignment);
        if (program.type == 0x6474e551)
            out << " executable-stack-request=" << ((program.flags & 1) ? "yes" : "no");
        else if (program.type == 0x6474e552)
            out << " relro-candidate=yes";
        out << '\n';
    }
    if (shown_programs < elf.programs.size())
        out << "  program headers omitted: " << (elf.programs.size() - shown_programs)
            << " (limit " << max_program_rows << ")\n";
    if (!elf.eh_frame_headers.empty()) {
        std::size_t total_entries = 0;
        for (const auto &header : elf.eh_frame_headers) total_entries += header.entries.size();
        out << "ELF .eh_frame_hdr indexes: " << elf.eh_frame_headers.size()
            << " entries=" << total_entries << '\n';
        constexpr std::size_t max_rows = 128;
        const auto shown_headers = std::min(elf.eh_frame_headers.size(), max_rows);
        std::size_t rows = 0, shown_entries = 0;
        for (std::size_t hi = 0; hi < shown_headers; ++hi) {
            const auto &header = elf.eh_frame_headers[hi];
            out << "  program=" << header.program << " file=" << elf_hex(header.file_offset)
                << " bytes=" << header.file_size << " eh-frame=" << elf_hex(header.eh_frame_address)
                << " encodings=" << elf_hex(header.eh_frame_pointer_encoding) << '/'
                << elf_hex(header.fde_count_encoding) << '/' << elf_hex(header.table_encoding)
                << " entries=" << header.entries.size() << '\n';
            for (const auto &entry : header.entries) {
                if (rows++ >= max_rows) continue;
                ++shown_entries;
                out << "    initial=" << elf_hex(entry.initial_location) << " fde=" << elf_hex(entry.fde_address)
                    << " initial-file=" << elf_hex(entry.initial_location_file_offset)
                    << " fde-file=" << elf_hex(entry.fde_file_offset) << '\n';
            }
        }
        if (shown_headers < elf.eh_frame_headers.size())
            out << "  .eh_frame_hdr headers omitted: " << (elf.eh_frame_headers.size() - shown_headers)
                << " (limit " << max_rows << ")\n";
        if (total_entries > shown_entries)
            out << "  .eh_frame_hdr rows omitted: " << (total_entries - shown_entries) << " (limit " << max_rows << ")\n";
    }
    for (const auto &section : elf.sections)
        out << "  section #" << section.index << " name=" << elf_text(section.name) << " type=" << section.type
            << " flags=" << elf_hex(section.flags) << " file=" << elf_hex(section.offset)
            << " size=" << elf_hex(section.size) << " link=" << section.link << '\n';
    out << "ELF section groups: " << elf.section_groups.size() << '\n';
    for (const auto &group : elf.section_groups) {
        out << "  group-section=" << group.section << " flags=" << elf_hex(group.flags)
            << " signature-table=" << group.signature_symbol_table
            << " signature-symbol=" << group.signature_symbol
            << " signature-name=\"" << elf_text(group.signature_name) << "\" members=";
        for (std::size_t index = 0; index < group.members.size(); ++index) {
            if (index) out << ',';
            out << group.members[index];
        }
        out << '\n';
    }
    constexpr std::size_t max_gnu_abi_tag_rows = 256;
    out << "ELF GNU ABI tags: " << elf.gnu_abi_tags.size() << '\n';
    const auto shown_gnu_abi_tags = std::min(elf.gnu_abi_tags.size(), max_gnu_abi_tag_rows);
    for (std::size_t index = 0; index < shown_gnu_abi_tags; ++index) {
        const auto &tag = elf.gnu_abi_tags[index];
        const char *os = tag.os == 0 ? "linux" : tag.os == 1 ? "gnu" :
                         tag.os == 2 ? "solaris2" : tag.os == 3 ? "freebsd" : "unknown";
        out << "  os=" << os << '(' << tag.os << ") version=" << tag.major << '.'
            << tag.minor << '.' << tag.subminor << " note-file=" << elf_hex(tag.note_file_offset)
            << " desc-file=" << elf_hex(tag.description_file_offset)
            << " extension-size=" << tag.extension.size();
        if (tag.program) out << " program=" << *tag.program;
        if (tag.section) out << " section=" << *tag.section;
        out << '\n';
    }
    if (shown_gnu_abi_tags < elf.gnu_abi_tags.size())
        out << "  abi-tag-output-capped=true omitted=" << elf.gnu_abi_tags.size() - shown_gnu_abi_tags << '\n';
    constexpr std::size_t max_gnu_hwcap_notes = 128;
    constexpr std::size_t max_gnu_hwcap_entries = 64;
    constexpr std::size_t max_gnu_hwcap_name_preview = 64;
    out << "ELF GNU HWCAP notes: " << elf.gnu_hwcaps.size() << '\n';
    const auto shown_hwcap_notes = std::min(elf.gnu_hwcaps.size(), max_gnu_hwcap_notes);
    for (std::size_t index = 0; index < shown_hwcap_notes; ++index) {
        const auto &hwcap = elf.gnu_hwcaps[index];
        out << "  mask=" << elf_hex(hwcap.mask) << " entries=" << hwcap.entries.size()
            << " note-file=" << elf_hex(hwcap.note_file_offset)
            << " desc-file=" << elf_hex(hwcap.description_file_offset);
        if (hwcap.program) out << " program=" << *hwcap.program;
        if (hwcap.section) out << " section=" << *hwcap.section;
        out << '\n';
        const auto shown_entries = std::min(hwcap.entries.size(), max_gnu_hwcap_entries);
        for (std::size_t entry = 0; entry < shown_entries; ++entry) {
            const auto &value = hwcap.entries[entry];
            const auto name_preview = std::string_view(value.name).substr(0, max_gnu_hwcap_name_preview);
            out << "    bit=" << static_cast<unsigned>(value.bit)
                << " enabled=" << (value.enabled ? "true" : "false")
                << " name=\"" << elf_text(name_preview) << '\"'
                << " entry-file=" << elf_hex(value.entry_file_offset)
                << " name-file=" << elf_hex(value.name_file_offset);
            if (name_preview.size() < value.name.size()) out << "...";
            out << '\n';
        }
        if (shown_entries < hwcap.entries.size())
            out << "    entries-output-capped=true omitted=" << hwcap.entries.size() - shown_entries << '\n';
    }
    if (shown_hwcap_notes < elf.gnu_hwcaps.size())
        out << "  hwcap-output-capped=true omitted=" << elf.gnu_hwcaps.size() - shown_hwcap_notes << '\n';
    constexpr std::size_t max_gnu_property_rows = 512;
    constexpr std::size_t max_gnu_property_preview = 32;
    out << "ELF GNU properties: " << elf.gnu_properties.size() << '\n';
    const auto shown_gnu_properties = std::min(elf.gnu_properties.size(), max_gnu_property_rows);
    for (std::size_t index = 0; index < shown_gnu_properties; ++index) {
        const auto &property = elf.gnu_properties[index];
        out << "  property=" << elf_hex(property.type) << " size=" << property.data.size()
            << " note-file=" << elf_hex(property.note_file_offset)
            << " property-file=" << elf_hex(property.property_file_offset)
            << " data-file=" << elf_hex(property.data_file_offset);
        if (property.program)
            out << " program=" << *property.program;
        if (property.section)
            out << " section=" << *property.section;
        out << " data-prefix=0x";
        const auto previous_fill = out.fill();
        const auto preview = std::min(property.data.size(), max_gnu_property_preview);
        for (std::size_t byte = 0; byte < preview; ++byte)
            out << std::hex << std::setw(2) << std::setfill('0')
                << std::to_integer<unsigned>(property.data[byte]);
        out << std::dec << std::setfill(previous_fill);
        if (preview < property.data.size())
            out << "...";
        if (property.value32) {
            const auto value = *property.value32;
            const auto emit_feature = [&](std::string_view feature, bool &first) {
                if (!first)
                    out << ',';
                out << feature;
                first = false;
            };
            if ((header.machine == 3 || header.machine == 62) && property.type == 0xc0000002) {
                out << " x86-feature-1-and=";
                bool first = true;
                if (value & 1) emit_feature("IBT", first);
                if (value & 2) emit_feature("SHSTK", first);
                if (value & ~3U) emit_feature("unknown-bits=" + elf_hex(value & ~3U), first);
                if (first) out << "none";
            } else if ((header.machine == 3 || header.machine == 62) &&
                       (property.type == 0xc0008002 || property.type == 0xc0010002)) {
                out << (property.type == 0xc0008002 ? " x86-isa-1-needed=" : " x86-isa-1-used=");
                bool first = true;
                if (value & 1) emit_feature("baseline", first);
                if (value & 2) emit_feature("v2", first);
                if (value & 4) emit_feature("v3", first);
                if (value & 8) emit_feature("v4", first);
                if (value & ~15U) emit_feature("unknown-bits=" + elf_hex(value & ~15U), first);
                if (first) out << "none";
            } else if (header.machine == 183 && property.type == 0xc0000000) {
                out << " aarch64-feature-1-and=";
                bool first = true;
                if (value & 1) emit_feature("BTI", first);
                if (value & 2) emit_feature("PAC", first);
                if (value & 4) emit_feature("GCS", first);
                if (value & ~7U) emit_feature("unknown-bits=" + elf_hex(value & ~7U), first);
                if (first) out << "none";
            }
        }
        out << '\n';
    }
    if (shown_gnu_properties < elf.gnu_properties.size())
        out << "  property-output-capped=true omitted=" << elf.gnu_properties.size() - shown_gnu_properties << '\n';
    out << "ELF symbol tables: " << elf.symbol_tables.size() << '\n';
    for (const auto &table : elf.symbol_tables) {
        out << "  symbol-table file:" << elf_hex(table.source.file_offset)
            << " count=" << (table.count ? std::to_string(*table.count) : "unavailable")
            << " stride=" << elf_hex(table.stride);
        if (table.source.section)
            out << " section=" << *table.source.section;
        if (table.source.address)
            out << " address=" << format_location(*table.source.address, image);
        out << '\n';
    }
    out << "ELF symbols: " << elf.symbols.size() << '\n';
    for (const auto &symbol : elf.symbols) {
        out << "  symbol table=file:" << elf_hex(symbol.table_offset) << " index=" << symbol.index
            << " name=" << elf_text(symbol.name) << " state=" << elf_state(symbol.state);
        if (symbol.version_index || symbol.version_name || symbol.version_hidden) {
            out << " version-index=" << symbol.version_index;
            if (symbol.version_name)
                out << " version=\"" << elf_text(*symbol.version_name) << '\"';
            if (symbol.version_file)
                out << " version-file=\"" << elf_text(*symbol.version_file) << '\"';
            if (symbol.version_flags)
                out << " version-flags=" << elf_hex(*symbol.version_flags);
            if (symbol.version_flags && (*symbol.version_flags & 0x0002))
                out << " version-weak=true";
            if (symbol.version_hash)
                out << " version-hash=" << elf_hex(*symbol.version_hash);
            if (symbol.version_hidden)
                out << " version-hidden=true";
        }
        if (auto rendered = demangled_name(symbol.name); !rendered.empty()) out << " demangled=\"" << elf_text(rendered) << '\"';
        if (symbol.address)
            out << " address=" << format_location(*symbol.address, image);
        if (symbol.table)
            out << " table-section=" << *symbol.table;
        if (symbol.table_address)
            out << " table-address=" << format_location(*symbol.table_address, image);
        out << " value=" << elf_hex(symbol.value) << " size=" << elf_hex(symbol.size)
            << " binding=" << unsigned(symbol.binding) << " type=" << unsigned(symbol.type)
            << " visibility=" << unsigned(symbol.visibility) << '\n';
    }
    out << "ELF dynamic: " << (elf.dynamic_complete ? "complete" : "partial") << '\n';
    for (const auto &table : elf.dynamic_tables)
        for (const auto &entry : table.entries) {
            const char *label = entry.tag == 1    ? "NEEDED"
                                : entry.tag == 14 ? "SONAME"
                                : entry.tag == 15 ? "RPATH"
                                : entry.tag == 29 ? "RUNPATH"
                                : entry.tag == 0x6ffffefa ? "CONFIG"
                                : entry.tag == 0x6ffffefb ? "DEPAUDIT"
                                : entry.tag == 0x6ffffefc ? "AUDIT"
                                : entry.tag == 0x7ffffffd ? "AUXILIARY"
                                : entry.tag == 0x7fffffff ? "FILTER"
                                                  : nullptr;
            if (label && entry.string_value)
                out << "  " << label << ": " << elf_text(*entry.string_value) << '\n';
            else
                out << "  dynamic table=file:" << elf_hex(table.source.file_offset) << " index=" << entry.index
                    << " tag=" << entry.tag << " value=" << elf_hex(entry.value) << '\n';
        }
    if (elf.core) {
        constexpr std::size_t max_core_threads = 256, max_core_registers = 4096;
        const auto thread_count = std::min(elf.core->threads.size(), max_core_threads);
        std::size_t floating_point_states_printed = 0;
        bool floating_point_output_capped = false;
        std::size_t registers_printed = 0;
        out << "ELF core threads: " << elf.core->threads.size() << '\n';
        for (std::size_t index = 0; index < thread_count; ++index) {
            const auto &thread = elf.core->threads[index];
            const auto *status = thread.status == ElfCoreThreadStatus::decoded ? "decoded" :
                thread.status == ElfCoreThreadStatus::malformed ? "malformed" : "unsupported";
            out << "  thread=" << thread.process_id << " parent=" << thread.parent_process_id
                << " group=" << thread.process_group_id << " session=" << thread.session_id << " status=" << status;
            if (thread.current_signal) out << " signal=" << *thread.current_signal;
            out << " note-file=" << elf_hex(thread.note_file_offset)
                << " payload-file=" << elf_hex(thread.payload_file_offset);
            if (!thread.register_layout.empty())
                out << " layout=" << elf_text(thread.register_layout) << " gregset-slots=" << thread.gregset_slots
                    << " word-bits=" << thread.register_word_bits << " endian="
                    << (thread.register_byte_order == ByteOrder::little ? "little" : "big");
            if (thread.gregset_file_offset) out << " gregset-file=" << elf_hex(*thread.gregset_file_offset);
            if (thread.floating_point_valid) out << " pr-fpvalid=" << *thread.floating_point_valid;
            out << " named-registers=" << thread.registers.size() << '\n';
            if (!thread.diagnostic.empty()) out << "    diagnostic=" << elf_text(thread.diagnostic) << '\n';
            const auto shown = std::min(thread.registers.size(), max_core_registers - registers_printed);
            for (std::size_t i = 0; i < shown; ++i) {
                const auto &reg = thread.registers[i];
                out << "    register=" << elf_text(reg.name) << " value=" << elf_hex(reg.value)
                    << " bits=" << reg.bits << " gregset-index=" << reg.gregset_index
                    << " field-file=" << elf_hex(reg.file_offset);
                if (reg.kernel_placeholder) out << " kernel-placeholder=true";
                out << '\n';
            }
            registers_printed += shown;
            if (shown < thread.registers.size())
                out << "    register-output-capped=true omitted=" << thread.registers.size() - shown << '\n';
            for (const auto &state : thread.floating_point) {
                if (floating_point_states_printed >= 64) {
                    if (!floating_point_output_capped)
                        out << "  FPREGSET output capped at 64 thread states\n";
                    floating_point_output_capped = true;
                    break;
                }
                ++floating_point_states_printed;
                out << "  FPREGSET: layout=" << elf_text(state.layout)
                    << " note-file=" << elf_hex(state.note_file_offset)
                    << " payload-file=" << elf_hex(state.payload_file_offset) << '\n';
                for (const auto &reg : state.registers) {
                    out << "    " << elf_text(reg.name) << '=';
                    if (reg.bytes.size() <= sizeof(std::uint64_t)) {
                        std::uint64_t value = 0;
                        for (std::size_t i = 0; i < reg.bytes.size(); ++i)
                            value |= std::to_integer<std::uint64_t>(reg.bytes[i]) << (i * 8);
                        out << elf_hex(value);
                    } else {
                        out << "0x";
                        for (const auto byte : reg.bytes)
                            out << std::hex << std::setw(2) << std::setfill('0')
                                << std::to_integer<unsigned>(byte);
                        out << std::dec;
                    }
                    out << " file=" << elf_hex(reg.file_offset) << '\n';
                }
            }
        }
        if (thread_count < elf.core->threads.size())
            out << "  thread-output-capped=true omitted=" << elf.core->threads.size() - thread_count << '\n';
        out << "ELF core signal info: " << elf.core->signal_info.size() << '\n';
        for (const auto &info : elf.core->signal_info) {
            out << "  signal=" << info.signal << " error=" << info.error << " code=" << info.code;
            if (info.fault_address)
                out << " fault-address=" << elf_hex(*info.fault_address);
            out << " note-file=" << elf_hex(info.note_file_offset)
                << " payload-file=" << elf_hex(info.payload_file_offset) << '\n';
        }
        out << "ELF AArch64 control notes: " << elf.core->arm64_control_notes.size() << '\n';
        constexpr std::size_t arm64_note_limit = 128;
        for (std::size_t i = 0; i < std::min(elf.core->arm64_control_notes.size(), arm64_note_limit); ++i) {
            const auto &note = elf.core->arm64_control_notes[i];
            const auto label = note.type == 0x406 ? "NT_ARM_PAC_MASK"
                : note.type == 0x409 ? "NT_ARM_TAGGED_ADDR_CTRL" : "NT_ARM_PAC_ENABLED_KEYS";
            out << "  " << label;
            if (note.type == 0x406) {
                out << " data-mask=0x" << std::hex << note.first_value;
                if (note.second_value) out << " instruction-mask=0x" << *note.second_value;
                else out << " instruction-mask=unavailable";
            }
            else if (note.type == 0x409) out << " control=0x" << std::hex << note.first_value;
            else out << " enabled-keys=0x" << std::hex << note.first_value;
            out << " note-file=" << note.note_file_offset
                << " payload-file=" << note.payload_file_offset << std::dec << '\n';
        }
        if (elf.core->arm64_control_notes.size() > arm64_note_limit)
            out << "  AArch64 control notes omitted="
                << (elf.core->arm64_control_notes.size() - arm64_note_limit) << '\n';
    }
    if (!elf.dwarf_macro_units.empty()) {
        out << "ELF DWARF macro units: " << elf.dwarf_macro_units.size() << '\n';
        constexpr std::size_t macro_record_limit = 256, macro_operand_limit = 512;
        std::size_t shown_records = 0, omitted_records = 0, shown_operands = 0, omitted_operands = 0;
        for (const auto &unit : elf.dwarf_macro_units) {
            for (const auto &record : unit.records) {
                if (!record.vendor_defined) continue;
                if (shown_records >= macro_record_limit) { ++omitted_records; continue; }
                ++shown_records;
                out << "  vendor macro opcode=0x" << std::hex << unsigned(record.opcode) << std::dec
                    << " section=\"" << elf_text(unit.section_name) << "\" section-offset="
                    << elf_hex(record.section_offset) << " file=" << elf_hex(record.file_offset)
                    << " operands=" << record.vendor_operands.size() << '\n';
                for (const auto &operand : record.vendor_operands) {
                    if (shown_operands >= macro_operand_limit) { ++omitted_operands; continue; }
                    ++shown_operands;
                    out << "    form=0x" << std::hex << unsigned(operand.form) << std::dec
                        << " section-offset=" << elf_hex(operand.section_offset);
                    if (operand.unsigned_value) out << " value=" << elf_hex(*operand.unsigned_value);
                    if (operand.signed_value) out << " signed=" << *operand.signed_value;
                    if (!operand.text.empty()) out << " text=\"" << elf_text(operand.text.substr(0, 256)) << '"';
                    if (!operand.bytes.empty()) {
                        out << " bytes=";
                        const auto byte_count = std::min<std::size_t>(operand.bytes.size(), 32);
                        const auto previous_fill = out.fill();
                        for (std::size_t i = 0; i < byte_count; ++i)
                            out << std::hex << std::setw(2) << std::setfill('0')
                                << std::to_integer<unsigned>(operand.bytes[i]);
                        out << std::dec;
                        out.fill(previous_fill);
                        if (operand.bytes.size() > byte_count) out << "...";
                    }
                    out << '\n';
                }
            }
        }
        if (omitted_records) out << "  vendor macro records omitted=" << omitted_records << '\n';
        if (omitted_operands) out << "  vendor macro operands omitted=" << omitted_operands << '\n';
    }
    out << "ELF relocations: " << elf.relocations.size() << ' ' << (elf.relocations_complete ? "complete" : "partial")
        << '\n';
    for (const auto &row : elf.relocations) {
        out << "  relocation record=file:" << elf_hex(row.record_file_offset) << " type=" << row.type
            << " symbol=" << row.symbol_index;
        if (!elf.header.is_64 && elf.header.machine == 8 && row.type == 3)
            out << " name=R_MIPS_REL32";
        if (row.symbol_table)
            out << " symbol-table=file:" << elf_hex(row.symbol_table->file_offset);
        if (row.symbol_table && row.symbol_table->section)
            out << " symbol-table-section=" << *row.symbol_table->section;
        if (row.symbol_table && row.symbol_table->address)
            out << " symbol-table-address=" << format_location(*row.symbol_table->address, image);
        if (row.place)
            out << " address=" << format_location(*row.place, image);
        if (row.addend)
            out << " addend=" << *row.addend;
        else
            out << " addend=unavailable";
        out << '\n';
    }
}
} // namespace hexlab::cli
