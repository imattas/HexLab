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
    out << "ELF programs: " << elf.programs.size() << " sections=" << elf.sections.size() << '\n';
    for (const auto &section : elf.sections)
        out << "  section #" << section.index << " name=" << elf_text(section.name) << " type=" << section.type
            << " flags=" << elf_hex(section.flags) << " file=" << elf_hex(section.offset)
            << " size=" << elf_hex(section.size) << " link=" << section.link << '\n';
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
    }
    out << "ELF relocations: " << elf.relocations.size() << ' ' << (elf.relocations_complete ? "complete" : "partial")
        << '\n';
    for (const auto &row : elf.relocations) {
        out << "  relocation record=file:" << elf_hex(row.record_file_offset) << " type=" << row.type
            << " symbol=" << row.symbol_index;
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
