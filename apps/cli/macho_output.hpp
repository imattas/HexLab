#pragma once
#include "hexlab/workspace/navigation.hpp"
#include "hexlab/analysis/macho_objc.hpp"
#include "hexlab/analysis/macho_objc_types.hpp"
#include "demangle_output.hpp"
#include <iomanip>
#include <sstream>
namespace hexlab::cli {
inline std::string macho_hex(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}
inline const char *macho_pac_key(std::uint8_t key) {
    constexpr const char *names[] = {"IA", "IB", "DA", "DB"};
    return key < 4 ? names[key] : "unknown";
}
inline std::string macho_text(std::string_view text) {
    std::ostringstream out;
    for (unsigned char ch : text) {
        if (ch == '\\')
            out << "\\\\";
        else if (ch >= 32 && ch < 127)
            out << char(ch);
        else
            out << "\\x" << std::hex << std::setw(2) << std::setfill('0') << unsigned(ch);
    }
    return out.str();
}
inline std::string macho_version(std::uint32_t value) {
    return std::to_string(value >> 16) + "." + std::to_string((value >> 8) & 0xff) + "." +
           std::to_string(value & 0xff);
}
inline const char *macho_symbol_state(MachOSymbolState state) {
    switch (state) {
    case MachOSymbolState::undefined:
        return "undefined";
    case MachOSymbolState::defined:
        return "defined";
    case MachOSymbolState::absolute:
        return "absolute";
    case MachOSymbolState::common:
        return "common";
    case MachOSymbolState::indirect:
        return "indirect";
    case MachOSymbolState::prebound_undefined:
        return "prebound-undefined";
    case MachOSymbolState::debug:
        return "debug";
    case MachOSymbolState::unknown:
        return "unknown";
    }
    return "unknown";
}
inline const char *macho_stream_kind(MachODyldStreamKind kind) {
    switch (kind) {
    case MachODyldStreamKind::rebase:
        return "rebase";
    case MachODyldStreamKind::bind:
        return "bind";
    case MachODyldStreamKind::weak_bind:
        return "weak-bind";
    case MachODyldStreamKind::lazy_bind:
        return "lazy-bind";
    case MachODyldStreamKind::exports:
        return "exports";
    case MachODyldStreamKind::chained:
        return "chained";
    }
    return "unknown";
}
inline void macho_objc_method_line(std::ostream &out, const MachOObjCMethod &method,
                                   const Image *image, std::string_view kind) {
    out << "    " << kind << " entry=" << format_location(method.entry, image)
        << " selector=" << (method.selector ? macho_text(*method.selector) : "-")
        << " selector-status=" << macho_text(method.selector_status)
        << " types=" << (method.type_encoding ? macho_text(*method.type_encoding) : "-")
        << " types-status=" << macho_text(method.type_status)
        << " imp=" << (method.implementation ? format_location(*method.implementation, image) : "-")
        << " imp-status=" << macho_text(method.implementation_status)
        << " signature=" << (method.signature ? macho_text(types::format(*method.signature)) : "-")
        << " signature-status=" << macho_text(method.signature_status)
        << " encoding=" << (method.relative_encoding ? "relative" : "pointer") << '\n';
}
inline void macho_objc_property_line(std::ostream &out, const MachOObjCProperty &property,
                                     const Image *image, std::string_view kind) {
    out << "    " << kind << " entry=" << format_location(property.entry, image)
        << " name=" << (property.name ? macho_text(*property.name) : "-")
        << " attributes=" << (property.attributes ? macho_text(*property.attributes) : "-")
        << " type-encoding=" << (property.type_encoding ? macho_text(*property.type_encoding) : "-")
        << " type=" << (property.type ? macho_text(types::format(*property.type)) : "-")
        << " status=" << macho_text(property.name_status) << '/' << macho_text(property.attributes_status)
        << '/' << macho_text(property.type_status) << '\n';
}
inline void macho_description(std::ostream &out, const ImageMetadata &metadata, const Image *image) {
    if (!metadata.macho)
        return;
    const auto &m = *metadata.macho;
    if (m.selected_slice >= m.container.slices.size()) {
        out << "Mach-O: unavailable selection\n";
        return;
    }
    const auto &selected = m.container.slices[m.selected_slice];
    const auto &header = selected.header;
    out << "Mach-O: class=" << (header.is_64 ? 64 : 32)
        << " endian=" << (header.order == ByteOrder::little ? "little" : "big") << " type=" << header.file_type
        << " cpu=" << macho_hex(header.cpu_type) << " subtype=" << macho_hex(header.cpu_subtype)
        << " flags=" << macho_hex(header.flags) << " reserved=" << macho_hex(header.reserved)
        << " container=" << (m.container.universal ? "universal" : "thin") << " selected=" << m.selected_slice << '\n';
    out << "Mach-O slices: " << m.container.slices.size();
    if (m.container.universal)
        out << " fat-class=" << (m.container.fat_64 ? 64 : 32)
            << " endian=" << (m.container.order == ByteOrder::little ? "little" : "big");
    out << '\n';
    for (const auto &row : m.container.slices)
        out << "  slice #" << row.index << " cpu=" << macho_hex(row.cpu_type)
            << " subtype=" << macho_hex(row.cpu_subtype) << " file=" << macho_hex(row.offset)
            << " size=" << macho_hex(row.size) << " alignment=" << row.alignment
            << " reserved=" << macho_hex(row.reserved) << " selected=" << (row.index == m.selected_slice) << '\n';
    out << "Mach-O commands: " << header.commands.size() << " complete=" << m.commands_complete
        << " entries-conflict=" << m.entries_conflict << '\n';
    for (const auto &row : header.commands)
        out << "  command #" << row.index << " type=" << macho_hex(row.command)
            << " record=file:" << macho_hex(row.file_offset) << " size=" << row.size << '\n';
    for (const auto &row : m.build_versions) {
        out << "  build-version command=" << row.command_index << " platform=" << row.platform
            << " minimum-os=" << macho_version(row.minimum_os) << " sdk=" << macho_version(row.sdk)
            << " tools=" << row.tools.size() << " record=file:" << macho_hex(row.record_file_offset) << '\n';
        for (const auto &tool : row.tools)
            out << "    tool id=" << tool.tool << " version=" << macho_version(tool.version) << '\n';
    }
    for (const auto &row : m.segments)
        out << "  segment command=" << row.command_index << " name=" << macho_text(row.name)
            << " address=" << macho_hex(row.address) << " size=" << macho_hex(row.memory_size)
            << " file=" << macho_hex(row.file_offset.value) << " raw-file=" << macho_hex(row.raw_file_offset)
            << " initialized=" << macho_hex(row.file_size) << " max-protection=" << macho_hex(row.maximum_protection)
            << " protection=" << macho_hex(row.initial_protection) << " flags=" << macho_hex(row.flags) << '\n';
    for (const auto &row : m.sections) {
        out << "  section #" << row.ordinal << " name=" << macho_text(row.name)
            << " segment=" << macho_text(row.segment_name) << " address=" << macho_hex(row.address)
            << " size=" << macho_hex(row.size) << " flags=" << macho_hex(row.flags)
            << " record=file:" << macho_hex(row.record_file_offset);
        if (row.file_offset)
            out << " file=" << macho_hex(row.file_offset->value);
        else
            out << " file=uninitialized";
        out << " alignment=" << row.alignment << " relocations=" << row.relocation_count
            << " reserved=" << macho_hex(row.reserved1) << ',' << macho_hex(row.reserved2) << ','
            << macho_hex(row.reserved3) << '\n';
    }
    out << "Mach-O symbols: " << m.symbols.size() << " complete=" << m.symbols_complete << '\n';
    for (const auto &row : m.symbol_tables)
        out << "  symbol-table command=" << row.command_index << " file=" << macho_hex(row.symbol_offset.value)
            << " count=" << row.count << " stride=" << row.stride << " strings=" << macho_hex(row.string_offset.value)
            << " string-size=" << row.string_size << '\n';
    for (const auto &row : m.symbols) {
        out << "  symbol table=" << row.table_command << " index=" << row.index << " name=" << macho_text(row.name)
            << " state=" << macho_symbol_state(row.state) << " value=" << macho_hex(row.value)
            << " record=file:" << macho_hex(row.record_file_offset) << " type=" << macho_hex(row.type)
            << " section=" << unsigned(row.section) << " descriptor=" << macho_hex(row.descriptor);
        if (auto rendered = demangled_name(row.name); !rendered.empty()) out << " demangled=\"" << macho_text(rendered) << '\"';
        if (row.address)
            out << " address=" << format_location(*row.address, image);
        if (row.indirect_name)
            out << " indirect=" << macho_text(*row.indirect_name);
        if (row.library_ordinal)
            out << " ordinal=" << unsigned(*row.library_ordinal);
        out << " code=" << row.code << '\n';
    }
    for (const auto &row : m.libraries) {
        out << "  library command=" << row.command_index << " type=" << macho_hex(row.command)
            << " name=" << macho_text(row.name) << " record=file:" << macho_hex(row.record_file_offset);
        if (row.ordinal)
            out << " ordinal=" << *row.ordinal;
        out << " timestamp=" << macho_hex(row.timestamp) << " current=" << macho_hex(row.current_version)
            << " compatibility=" << macho_hex(row.compatibility_version) << '\n';
    }
    for (const auto &row : m.paths)
        out << "  path command=" << row.command_index << " type=" << macho_hex(row.command)
            << " name=" << macho_text(row.name) << " record=file:" << macho_hex(row.record_file_offset) << '\n';
    for (const auto &row : m.entries) {
        out << "  entry command=" << row.command_index << " type=" << macho_hex(row.command) << " flavor=" << row.flavor
            << " count=" << row.count << " record=file:" << macho_hex(row.record_file_offset);
        if (row.value)
            out << " value=" << macho_hex(*row.value);
        if (row.address)
            out << " address=" << format_location(*row.address, image);
        out << " stack=" << macho_hex(row.stack_size) << '\n';
    }
    for (const auto &row : m.function_starts) {
        out << "  function-start command=" << row.command_index << " record=file:" << macho_hex(row.record_file_offset)
            << " delta=" << macho_hex(row.delta);
        if (row.address)
            out << " address=" << format_location(*row.address, image);
        out << '\n';
    }
    for (const auto &row : m.dynamic_symbol_tables) {
        out << "  dynamic-symbols command=" << row.command_index
            << " record=file:" << macho_hex(row.record_file_offset);
        if (row.symbol_table)
            out << " symbol-table=" << *row.symbol_table;
        out << '\n';
        for (std::size_t n = 0; n < row.ranges.size(); ++n)
            out << "    symbol-range #" << n << " begin=" << row.ranges[n].begin << " count=" << row.ranges[n].count
                << '\n';
        for (std::size_t n = 0; n < row.tables.size(); ++n)
            out << "    data-table #" << n << " file=" << macho_hex(row.tables[n].offset.value)
                << " count=" << row.tables[n].count << " stride=" << row.tables[n].stride << '\n';
        for (std::size_t n = 0; n < row.indirect_symbols.size(); ++n)
            out << "    indirect-symbol #" << n << " value=" << macho_hex(row.indirect_symbols[n]) << '\n';
    }
    out << "Mach-O relocations: " << m.relocations.size() << " complete=" << m.relocations_complete << '\n';
    for (std::size_t n = 0; n < m.relocation_tables.size(); ++n) {
        const auto &row = m.relocation_tables[n];
        out << "  relocation-table #" << n << " kind=" << unsigned(row.kind) << " owner=" << row.owner
            << " file=" << macho_hex(row.offset.value) << " count=" << row.count << '\n';
    }
    for (const auto &row : m.relocations) {
        out << "  relocation table=" << row.table << " index=" << row.index
            << " record=file:" << macho_hex(row.record_file_offset) << " raw=" << macho_hex(row.raw_address) << ','
            << macho_hex(row.raw_info) << " type=" << unsigned(row.type) << " width=" << unsigned(row.field_size)
            << " symbol=" << row.symbol_number << " external=" << row.external << " pc-relative=" << row.pc_relative
            << " scattered=" << row.scattered << " retained=" << row.retained << " auxiliary=" << row.auxiliary;
        if (row.place)
            out << " address=" << format_location(*row.place, image);
        if (row.file_place)
            out << " field=file:" << macho_hex(row.file_place->value);
        if (row.pair)
            out << " pair=" << *row.pair;
        if (row.encoded_value)
            out << " encoded=" << macho_hex(*row.encoded_value);
        out << '\n';
    }
    out << "Mach-O dyld: complete=" << m.dyld_complete << " streams=" << m.dyld_streams.size() << '\n';
    for (std::size_t n = 0; n < m.dyld_streams.size(); ++n) {
        const auto &row = m.dyld_streams[n];
        out << "  stream #" << n << " command=" << row.command_index << " kind=" << macho_stream_kind(row.kind)
            << " file=" << macho_hex(row.offset.value) << " size=" << row.size << " complete=" << row.complete << '\n';
    }
    for (const auto &row : m.dyld_operations) {
        out << "  operation stream=" << row.stream << " index=" << row.index
            << " record=file:" << macho_hex(row.record_file_offset) << " byte=" << macho_hex(row.byte)
            << " size=" << row.encoded_size;
        if (row.first)
            out << " first=" << macho_hex(*row.first);
        if (row.second)
            out << " second=" << macho_hex(*row.second);
        if (row.signed_value)
            out << " signed=" << *row.signed_value;
        if (row.symbol)
            out << " symbol=" << macho_text(*row.symbol);
        out << '\n';
    }
    for (const auto &row : m.dyld_fixups) {
        out << "  fixup stream=" << row.stream << " operation=" << row.operation << " repeat=" << row.repeat_index
            << " type=" << unsigned(row.type) << " width=" << unsigned(row.field_size)
            << " segment=" << row.segment_index << " offset=" << macho_hex(row.segment_offset)
            << " symbol=" << macho_text(row.symbol);
        if (row.library_ordinal)
            out << " ordinal=" << *row.library_ordinal;
        out << " addend=" << row.addend << " record=file:" << macho_hex(row.record_file_offset);
        if (row.place)
            out << " address=" << format_location(*row.place, image);
        if (row.file_place)
            out << " field=file:" << macho_hex(row.file_place->value);
        if (row.encoded_value)
            out << " encoded=" << macho_hex(*row.encoded_value);
        out << '\n';
    }
    for (const auto &row : m.dyld_exports) {
        out << "  export stream=" << row.stream << " index=" << row.index << " name=" << macho_text(row.name)
            << " flags=" << macho_hex(row.flags) << " record=file:" << macho_hex(row.record_file_offset)
            << " complete=" << row.complete;
        if (row.value)
            out << " value=" << macho_hex(*row.value);
        if (row.address)
            out << " address=" << format_location(*row.address, image);
        if (row.resolver)
            out << " resolver=" << macho_hex(*row.resolver);
        if (row.resolver_address)
            out << " resolver-address=" << format_location(*row.resolver_address, image);
        if (row.library_ordinal)
            out << " ordinal=" << *row.library_ordinal;
        if (row.import_name)
            out << " import=" << macho_text(*row.import_name);
        out << '\n';
    }
    for (std::size_t n = 0; n < m.chained_headers.size(); ++n) {
        const auto &row = m.chained_headers[n];
        out << "  chain-header #" << n << " stream=" << row.stream << " version=" << row.version
            << " imports=" << row.imports_count << " import-format=" << row.imports_format
            << " symbols-format=" << row.symbols_format << " record=file:" << macho_hex(row.record_file_offset)
            << " imports-available=" << row.imports_available << " complete=" << row.complete
            << " starts-offset=" << macho_hex(row.starts_offset) << " imports-offset=" << macho_hex(row.imports_offset)
            << " symbols-offset=" << macho_hex(row.symbols_offset) << '\n';
    }
    for (const auto &row : m.chained_imports) {
        out << "  chain-import header=" << row.header << " index=" << row.index
            << " name=" << (row.name ? macho_text(*row.name) : "<unavailable>") << " ordinal=" << row.library_ordinal
            << " weak=" << row.weak_import << " addend=" << row.addend << " raw=" << macho_hex(row.raw_info) << ','
            << macho_hex(row.raw_addend) << " record=file:" << macho_hex(row.record_file_offset)
            << " complete=" << row.complete << '\n';
    }
    for (std::size_t n = 0; n < m.chained_starts.size(); ++n) {
        const auto &row = m.chained_starts[n];
        out << "  chain-start #" << n << " header=" << row.header << " segment=" << row.segment_index
            << " offset=" << macho_hex(row.segment_offset) << " format=" << row.pointer_format
            << " page-size=" << row.page_size << " pages=" << row.page_count
            << " max-valid=" << macho_hex(row.max_valid_pointer) << " record=file:" << macho_hex(row.record_file_offset)
            << " complete=" << row.complete << '\n';
        for (std::size_t p = 0; p < row.page_starts.size(); ++p)
            out << "    page-start #" << p << " value=" << macho_hex(row.page_starts[p]) << '\n';
    }
    for (const auto &row : m.chained_pointers) {
        out << "  chain-pointer header=" << row.header << " starts=" << row.starts << " page=" << row.page_index
            << " node=" << row.node_index << " raw=" << macho_hex(row.raw) << " next=" << row.next
            << " width=" << unsigned(row.field_size) << " stride=" << unsigned(row.stride) << " bind=" << row.bind
            << " authenticated=" << row.authenticated << " non-pointer=" << row.non_pointer
            << " complete=" << row.complete;
        if (row.place)
            out << " address=" << format_location(*row.place, image);
        if (row.file_place)
            out << " field=file:" << macho_hex(row.file_place->value);
        if (row.target) {
            out << " payload=" << macho_hex(*row.target) << " header-relative=" << row.target_is_offset;
            if (m.chained_starts[row.starts].pointer_format == 13)
                out << " shared-cache-relative=1";
            out << " high8=" << macho_hex(row.high8);
        }
        if (row.import_index)
            out << " import-index=" << *row.import_index;
        if (row.import_row)
            out << " import-row=" << *row.import_row;
        if (row.scalar_value)
            out << " scalar=" << macho_hex(*row.scalar_value);
        out << " addend=" << row.addend;
        if (row.authenticated)
            out << " pac-key=" << macho_pac_key(row.key) << '(' << unsigned(row.key) << ')'
                << " diversity=" << row.diversity << " address-diversity=" << row.address_diversity;
        out << '\n';
    }
    out << "Mach-O protections: complete=" << m.protections_complete << '\n';
    for (std::size_t n = 0; n < m.data_in_code_tables.size(); ++n) {
        const auto &row = m.data_in_code_tables[n];
        out << "  data-in-code-table #" << n << " command=" << row.command_index
            << " file=" << macho_hex(row.offset.value) << " raw-offset=" << macho_hex(row.raw_offset)
            << " size=" << row.size << " first-row=" << row.first_row << '\n';
    }
    for (const auto &row : m.encryption)
        out << "  encryption command=" << row.command_index << " type=" << macho_hex(row.command)
            << " file=" << macho_hex(row.offset.value) << " size=" << row.size << " cryptid=" << row.cryptid
            << " pad=" << macho_hex(row.pad) << " record=file:" << macho_hex(row.record_file_offset) << '\n';
    for (const auto &row : m.data_in_code) {
        out << "  data-in-code table=" << row.table << " index=" << row.index
            << " raw-offset=" << macho_hex(row.raw_offset) << " length=" << row.length << " kind=" << row.kind
            << " record=file:" << macho_hex(row.record_file_offset);
        if (row.offset)
            out << " field=file:" << macho_hex(row.offset->value);
        else
            out << " field=ambiguous-or-unavailable";
        out << '\n';
    }
    for (const auto &row : m.code_signatures)
        out << "  signature command=" << row.command_index << " file=" << macho_hex(row.offset.value)
            << " size=" << row.size << " authentication=unavailable\n";
    if (image) {
        auto objc = scan_macho_objc_classes(*image, metadata);
        if (!objc) {
            out << "Objective-C classes: unavailable reason=" << macho_text(objc.error().message) << '\n';
        } else {
            out << "Objective-C classes: " << objc.value().classes.size()
                << " metadata-bytes=" << objc.value().metadata_bytes
                << " complete=" << objc.value().complete;
            if (!objc.value().reason.empty()) out << " reason=" << macho_text(objc.value().reason);
            out << "\n";
            for (const auto &row : objc.value().classes) {
                out << "  objc-class section=#" << row.classlist_section << " index=" << row.classlist_index
                    << " slot=" << format_location(row.classlist_slot, image)
                    << " class=" << (row.class_address ? format_location(*row.class_address, image) : "-")
                    << " pointer=" << macho_text(row.class_pointer_status)
                    << " name=" << (row.name ? macho_text(*row.name) : "-")
                    << " name-status=" << macho_text(row.name_status)
                    << " superclass=" << (row.superclass_address ? format_location(*row.superclass_address, image) : "-")
                    << " superclass-pointer=" << macho_text(row.superclass_pointer_status)
                    << " superclass-name=" << (row.superclass_name ? macho_text(*row.superclass_name) : "-")
                    << " class-ro=" << (row.class_ro_address ? format_location(*row.class_ro_address, image) : "-")
                    << " class-ro-pointer=" << macho_text(row.class_ro_pointer_status)
                    << " flags=" << (row.flags ? macho_hex(*row.flags) : "-")
                    << " instance-start=" << (row.instance_start ? macho_hex(*row.instance_start) : "-")
                    << " instance-size=" << (row.instance_size ? macho_hex(*row.instance_size) : "-")
                    << " methods=" << macho_text(row.methods.status);
                if (row.methods.address) out << ':' << format_location(*row.methods.address, image);
                if (row.methods.count) out << " count=" << *row.methods.count << " stride=" << *row.methods.stride;
                out << " protocols=" << macho_text(row.protocols.status);
                if (row.protocols.count) out << " count=" << *row.protocols.count;
                out << " ivars=" << macho_text(row.ivars.status);
                if (row.ivars.count) out << " count=" << *row.ivars.count << " stride=" << *row.ivars.stride;
                out << " properties=" << macho_text(row.properties.status);
                if (row.properties.count) out << " count=" << *row.properties.count << " stride=" << *row.properties.stride;
                out << " complete=" << row.complete << '\n';
                for (const auto category_index : row.category_indices)
                    if (category_index < objc.value().categories.size()) {
                        const auto &category = objc.value().categories[category_index];
                        out << "    objc-category-reference index=" << category_index
                            << " name=" << (category.name ? macho_text(*category.name) : "-")
                            << " address=" << (category.address ? format_location(*category.address, image) : "-")
                            << " status=" << macho_text(category.target_class_link_status) << '\n';
                    }
                for (const auto &method : row.methods.methods)
                    macho_objc_method_line(out, method, image, "objc-method");
                for (const auto &ivar : row.ivars.ivars)
                    out << "    objc-ivar entry=" << format_location(ivar.entry, image)
                        << " name=" << (ivar.name ? macho_text(*ivar.name) : "-")
                        << " type=" << (ivar.type_encoding ? macho_text(*ivar.type_encoding) : "-")
                        << " offset=" << (ivar.offset ? macho_hex(*ivar.offset) : "-")
                        << " size=" << (ivar.size ? macho_hex(*ivar.size) : "-")
                        << " alignment=" << (ivar.alignment ? macho_hex(*ivar.alignment) : "-")
                        << " status=" << macho_text(ivar.offset_status) << '/' << macho_text(ivar.name_status)
                        << '/' << macho_text(ivar.type_status) << '\n';
                for (const auto &property : row.properties.properties)
                    macho_objc_property_line(out, property, image, "objc-property");
                for (const auto &protocol : row.protocols.protocol_references)
                    out << "    objc-protocol slot=" << format_location(protocol.slot, image)
                        << " target=" << (protocol.address ? format_location(*protocol.address, image) : "-")
                        << " name=" << (protocol.name ? macho_text(*protocol.name) : "-")
                        << " status=" << macho_text(protocol.pointer_status) << '/' << macho_text(protocol.name_status) << '\n';
            }
            out << "Objective-C categories: " << objc.value().categories.size() << '\n';
            for (const auto &category : objc.value().categories) {
                out << "  objc-category section=#" << category.categorylist_section << " index=" << category.categorylist_index
                    << " slot=" << format_location(category.categorylist_slot, image)
                    << " address=" << (category.address ? format_location(*category.address, image) : "-")
                    << " name=" << (category.name ? macho_text(*category.name) : "-")
                    << " target=" << (category.target_class ? format_location(*category.target_class, image) : "-")
                    << " target-name=" << (category.target_class_name ? macho_text(*category.target_class_name) : "-")
                    << " target-status=" << macho_text(category.target_class_status)
                    << " target-link-status=" << macho_text(category.target_class_link_status)
                    << " instance-methods=" << macho_text(category.instance_methods.status)
                    << " class-methods=" << macho_text(category.class_methods.status)
                    << " protocols=" << macho_text(category.protocols.status)
                    << " properties=" << macho_text(category.instance_properties.status)
                    << " complete=" << category.complete << '\n';
                for (const auto &method : category.instance_methods.methods)
                    macho_objc_method_line(out, method, image, "objc-category-method");
                for (const auto &method : category.class_methods.methods)
                    macho_objc_method_line(out, method, image, "objc-category-class-method");
                for (const auto &protocol : category.protocols.protocol_references)
                    out << "    objc-category-protocol slot=" << format_location(protocol.slot, image)
                        << " target=" << (protocol.address ? format_location(*protocol.address, image) : "-")
                        << " name=" << (protocol.name ? macho_text(*protocol.name) : "-")
                        << " status=" << macho_text(protocol.pointer_status) << '/' << macho_text(protocol.name_status) << '\n';
                for (const auto &property : category.instance_properties.properties)
                    macho_objc_property_line(out, property, image, "objc-category-property");
            }
            out << "Objective-C protocols: " << objc.value().protocols.size() << '\n';
            for (std::size_t i = 0; i < objc.value().protocols.size(); ++i) {
                const auto &protocol = objc.value().protocols[i];
                out << "  objc-protocol index=" << i
                    << " section=#" << protocol.protolist_section << " entry=" << protocol.protolist_index
                    << " slot=" << format_location(protocol.protolist_slot, image)
                    << " address=" << (protocol.address ? format_location(*protocol.address, image) : "-")
                    << " name=" << (protocol.name ? macho_text(*protocol.name) : "-")
                    << " status=" << macho_text(protocol.pointer_status) << '/' << macho_text(protocol.name_status)
                    << " complete=" << protocol.complete << '\n';
                const auto emit_methods = [&](const MachOObjCList &list, std::string_view label) {
                    for (const auto &method : list.methods)
                        macho_objc_method_line(out, method, image, label);
                };
                emit_methods(protocol.required_instance_methods, "objc-protocol-required-instance-method");
                emit_methods(protocol.required_class_methods, "objc-protocol-required-class-method");
                emit_methods(protocol.optional_instance_methods, "objc-protocol-optional-instance-method");
                emit_methods(protocol.optional_class_methods, "objc-protocol-optional-class-method");
                for (const auto &property : protocol.instance_properties.properties)
                    macho_objc_property_line(out, property, image, "objc-protocol-property");
                for (const auto &adopted : protocol.adopted_protocols.protocol_references)
                    out << "    objc-protocol-adopts slot=" << format_location(adopted.slot, image)
                        << " target=" << (adopted.address ? format_location(*adopted.address, image) : "-")
                        << " name=" << (adopted.name ? macho_text(*adopted.name) : "-")
                        << " definition-index=" << (adopted.definition_index ? std::to_string(*adopted.definition_index) : "-")
                        << " status=" << macho_text(adopted.pointer_status) << '/' << macho_text(adopted.name_status) << '\n';
            }
        }
    } else {
        out << "Objective-C classes: unavailable image-not-loaded\n";
    }
    if (image) {
        for (const auto &row : image->layout().code_exclusions)
            out << "  code-exclusion address=" << format_location(row.begin, image) << " size=" << macho_hex(row.size)
                << '\n';
        for (const auto &row : image->layout().encrypted_ranges)
            out << "  encrypted-mapping address=" << format_location(row.begin, image)
                << " size=" << macho_hex(row.size) << '\n';
    }
}
} // namespace hexlab::cli
