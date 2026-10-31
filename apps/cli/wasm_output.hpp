#pragma once
#include "hexlab/image/metadata.hpp"
#include <algorithm>
#include <iomanip>
#include <numeric>
#include <ostream>
#include <sstream>
#include <string>

namespace hexlab::cli {
inline std::string wasm_hex(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}
inline std::string wasm_escape_name(const std::string &value) {
    constexpr char hex[] = "0123456789abcdef";
    std::string escaped;
    escaped.reserve(value.size());
    for (const unsigned char byte : value) {
        if (byte == '"' || byte == '\\') {
            escaped.push_back('\\');
            escaped.push_back(static_cast<char>(byte));
        } else if (byte == '\n') escaped += "\\n";
        else if (byte == '\r') escaped += "\\r";
        else if (byte == '\t') escaped += "\\t";
        else if (byte < 0x20 || byte == 0x7f) {
            escaped += "\\x";
            escaped.push_back(hex[byte >> 4]);
            escaped.push_back(hex[byte & 0xf]);
        } else escaped.push_back(static_cast<char>(byte));
    }
    return escaped;
}
inline const char *wasm_external_kind_name(WasmExternalKind kind) {
    switch (kind) {
    case WasmExternalKind::function: return "function";
    case WasmExternalKind::table: return "table";
    case WasmExternalKind::memory: return "memory";
    case WasmExternalKind::global: return "global";
    }
    return "unknown";
}

inline const char *wasm_import_resolution_status_name(WasmImportResolutionStatus status) {
    switch (status) {
    case WasmImportResolutionStatus::unresolved: return "unresolved";
    case WasmImportResolutionStatus::compatible_host_facts: return "compatible-host-facts";
    case WasmImportResolutionStatus::symbolic_host_binding: return "symbolic-host-binding";
    case WasmImportResolutionStatus::supplied_global_value: return "supplied-global-value";
    }
    return "unresolved";
}
inline const char *wasm_value_type_name(std::uint8_t type) {
    switch (type) {
    case 0x7f: return "i32";
    case 0x7e: return "i64";
    case 0x7d: return "f32";
    case 0x7c: return "f64";
    case 0x70: return "funcref";
    default: return "unknown";
    }
}
inline void wasm_limits(std::ostream &out, const WasmLimits &limits) {
    out << " minimum=" << limits.minimum;
    if (limits.maximum) out << " maximum=" << *limits.maximum;
    else out << " maximum=unbounded";
    if (limits.shared) out << " shared=true";
}
inline void wasm_description(std::ostream &out, const ImageMetadata &metadata) {
    if (!metadata.wasm) return;
    const auto &wasm = *metadata.wasm;
    constexpr std::size_t display_limit = 128;
    out << "WebAssembly: types=" << wasm.type_count
        << " functions=" << wasm.function_type_indices.size()
        << " imports=" << wasm.imports.size()
        << " exports=" << wasm.exports.size()
        << " globals=" << wasm.globals.size()
        << " data-segments=" << wasm.data_segments.size()
        << " element-segments=" << wasm.element_segments.size()
        << " named-functions=" << wasm.function_names.size()
        << " named-locals=" << wasm.local_names.size()
        << " named-labels=" << wasm.label_names.size()
        << " named-indices=" << wasm.index_names.size()
        << " linking-segments=" << wasm.linking_segments.size()
        << " linking-symbols=" << wasm.linking_symbols.size()
        << " relocation-sections=" << wasm.relocation_sections.size()
        << " custom-sections=" << wasm.custom_sections.size()
        << " named-module=" << (wasm.module_name ? "yes" : "no") << '\n';
    if (wasm.module_name)
        out << "Module name: name=\"" << wasm_escape_name(wasm.module_name->name)
            << "\" entry-file=" << wasm_hex(wasm.module_name->entry_file_offset.value) << '\n';
    for (std::size_t i = 0; i < std::min(display_limit, wasm.linking_segments.size()); ++i) {
        const auto &segment = wasm.linking_segments[i];
        out << "Linking segment: index=" << segment.segment_index << " name=\""
            << wasm_escape_name(segment.name) << "\" alignment-log2=" << segment.alignment_log2
            << " flags=" << wasm_hex(segment.flags)
            << " strings=" << ((segment.flags & 1) ? "yes" : "no")
            << " tls=" << ((segment.flags & 2) ? "yes" : "no")
            << " retain=" << ((segment.flags & 4) ? "yes" : "no")
            << " entry-file=" << wasm_hex(segment.entry_file_offset.value) << '\n';
    }
    if (wasm.linking_segments.size() > display_limit)
        out << "Linking segments omitted: " << (wasm.linking_segments.size() - display_limit) << '\n';
    const auto relocation_name = [](std::uint8_t type) -> const char * {
        static constexpr const char *names[] = {
            "FUNCTION_INDEX_LEB", "TABLE_INDEX_SLEB", "TABLE_INDEX_I32", "MEMORY_ADDR_LEB",
            "MEMORY_ADDR_SLEB", "MEMORY_ADDR_I32", "TYPE_INDEX_LEB", "GLOBAL_INDEX_LEB",
            "FUNCTION_OFFSET_I32", "SECTION_OFFSET_I32", "EVENT_INDEX_LEB"
        };
        if (type <= 10) return names[type];
        return type == 13 ? "GLOBAL_INDEX_I32" : "UNKNOWN";
    };
    std::size_t relocation_rows = 0, relocation_sections_shown = 0;
    for (const auto &relocation_section : wasm.relocation_sections) {
        if (relocation_sections_shown >= display_limit || relocation_rows >= display_limit) break;
        ++relocation_sections_shown;
        out << "Relocation section: name=\"" << wasm_escape_name(relocation_section.name)
            << "\" target-section=" << relocation_section.target_section_index
            << " entries=" << relocation_section.entries.size()
            << " source=" << wasm_hex(relocation_section.section_file_offset.value) << '\n';
        for (const auto &row : relocation_section.entries) {
            if (relocation_rows >= display_limit) break;
            ++relocation_rows;
            out << "  Relocation: type=" << relocation_name(row.type) << '(' << unsigned(row.type)
                << ") offset=" << wasm_hex(row.offset) << " index=" << row.index;
            if (row.addend) out << " addend=" << *row.addend;
            out << " source=" << wasm_hex(row.entry_file_offset.value) << '\n';
        }
    }
    const auto relocation_count = std::accumulate(wasm.relocation_sections.begin(), wasm.relocation_sections.end(),
        std::size_t{0}, [](std::size_t count, const WasmRelocationSection &section) {
            return count + section.entries.size();
        });
    if (relocation_count > relocation_rows)
        out << "Relocation rows omitted: " << (relocation_count - relocation_rows) << '\n';
    if (wasm.relocation_sections.size() > relocation_sections_shown)
        out << "Relocation sections omitted: " << (wasm.relocation_sections.size() - relocation_sections_shown) << '\n';
    if (wasm.linking_symbol_table_present) {
        constexpr std::size_t symbol_display_limit = 128;
        const auto symbol_count = std::min(symbol_display_limit, wasm.linking_symbols.size());
        for (std::size_t i = 0; i < symbol_count; ++i) {
            const auto &symbol = wasm.linking_symbols[i];
            static constexpr const char *symbol_kinds[] = {"function", "data", "global", "section", "event", "table"};
            out << "Linking symbol: kind=" << symbol_kinds[symbol.kind]
                << " index=" << symbol.index << " flags=" << wasm_hex(symbol.flags);
            if (symbol.name) out << " name=\"" << wasm_escape_name(*symbol.name) << '"';
            if (symbol.import_module && symbol.import_name)
                out << " import=\"" << wasm_escape_name(*symbol.import_module) << "!"
                    << wasm_escape_name(*symbol.import_name) << '"';
            if (symbol.data_segment_index)
                out << " segment=" << *symbol.data_segment_index << " offset=" << wasm_hex(*symbol.data_offset)
                    << " size=" << wasm_hex(*symbol.data_size);
            if (symbol.common_alignment_log2)
                out << " common-size=" << wasm_hex(*symbol.data_size)
                    << " alignment-log2=" << unsigned(*symbol.common_alignment_log2);
            out << " entry-file=" << wasm_hex(symbol.entry_file_offset.value) << '\n';
        }
        if (symbol_count < wasm.linking_symbols.size())
            out << "Linking symbols omitted: " << (wasm.linking_symbols.size() - symbol_count) << '\n';
    }
    if (wasm.linear_memory_space) {
        out << "Linear memory image: space=" << wasm.linear_memory_space->value
            << " size=" << wasm_hex(wasm.linear_memory_size)
            << " coverage=" << (wasm.linear_memory_complete ? "complete" : "initialized-ranges-only") << '\n';
    }
    if (wasm.initial_table_element_count != 0 || !wasm.initial_table_elements.empty()) {
        out << "Initial table: slots=" << wasm.initial_table_element_count
            << " coverage=" << (wasm.initial_table_complete ? "complete" : "known-active-slots-only") << '\n';
        constexpr std::size_t table_display_limit = 128;
        for (std::size_t i = 0; i < std::min(table_display_limit, wasm.initial_table_elements.size()); ++i) {
            const auto &element = wasm.initial_table_elements[i];
            out << "Table element: slot=" << element.slot << " function=" << element.function_index << '\n';
        }
        if (wasm.initial_table_elements.size() > table_display_limit)
            out << "Table elements omitted: " << (wasm.initial_table_elements.size() - table_display_limit) << '\n';
    }
    if (wasm.start_function) {
        const auto &start = *wasm.start_function;
        out << "Start function: index=" << start.function_index
            << " type=" << start.function_type_index
            << " section-file=" << wasm_hex(start.section_file_offset.value)
            << " entry-file=" << wasm_hex(start.entry_file_offset.value) << '\n';
    }
    constexpr std::size_t external_display_limit = 128;
    for (std::size_t i = 0; i < std::min(external_display_limit, wasm.imports.size()); ++i) {
        const auto &entry = wasm.imports[i];
        out << "Import: module=\"" << wasm_escape_name(entry.module) << "\" name=\""
            << wasm_escape_name(entry.name) << "\" kind=" << wasm_external_kind_name(entry.kind)
            << " index=" << entry.index;
        if (entry.function_type_index) out << " type=" << *entry.function_type_index;
        if (entry.limits) wasm_limits(out, *entry.limits);
        if (entry.global_value_type)
            out << " value-type=" << wasm_value_type_name(*entry.global_value_type)
                << " mutable=" << (entry.global_mutable ? "true" : "false");
        out << " resolution=" << wasm_import_resolution_status_name(entry.resolution_status);
        if (entry.host_binding) out << " host-binding=\"" << wasm_escape_name(*entry.host_binding) << "\"";
        out << " entry=" << entry.entry_index
            << " section-file=" << wasm_hex(entry.section_file_offset.value)
            << " entry-file=" << wasm_hex(entry.entry_file_offset.value) << '\n';
    }
    if (wasm.imports.size() > external_display_limit)
        out << "Imports omitted: " << (wasm.imports.size() - external_display_limit) << '\n';
    for (std::size_t i = 0; i < std::min(external_display_limit, wasm.exports.size()); ++i) {
        const auto &entry = wasm.exports[i];
        out << "Export: name=\"" << wasm_escape_name(entry.name) << "\" kind="
            << wasm_external_kind_name(entry.kind) << " index=" << entry.index;
        if (entry.function_type_index) out << " type=" << *entry.function_type_index;
        if (entry.limits) wasm_limits(out, *entry.limits);
        if (entry.global_value_type)
            out << " value-type=" << wasm_value_type_name(*entry.global_value_type)
                << " mutable=" << (entry.global_mutable ? "true" : "false");
        out << " entry=" << entry.entry_index
            << " section-file=" << wasm_hex(entry.section_file_offset.value)
            << " entry-file=" << wasm_hex(entry.entry_file_offset.value) << '\n';
    }
    if (wasm.exports.size() > external_display_limit)
        out << "Exports omitted: " << (wasm.exports.size() - external_display_limit) << '\n';
    for (std::size_t i = 0; i < std::min(display_limit, wasm.globals.size()); ++i) {
        const auto &global = wasm.globals[i];
        out << "Global: index=" << i << " value-type=" << wasm_value_type_name(global.value_type)
            << " mutable=" << (global.mutable_value ? "true" : "false")
            << " imported=" << (global.imported ? "true" : "false");
        if (global.initializer) {
            const auto &initializer = *global.initializer;
            switch (initializer.kind) {
            case WasmGlobalInitializerKind::numeric_constant:
                out << " initializer=" << wasm_value_type_name(global.value_type) << ".const bits=" << wasm_hex(initializer.value);
                break;
            case WasmGlobalInitializerKind::global_get:
                out << " initializer=global.get global=" << initializer.value;
                if (initializer.evaluated_value_bits)
                    out << " resolved-bits=" << wasm_hex(*initializer.evaluated_value_bits);
                else
                    out << " value=host-supplied";
                break;
            case WasmGlobalInitializerKind::ref_null:
                out << " initializer=ref.null funcref";
                break;
            case WasmGlobalInitializerKind::ref_func:
                out << " initializer=ref.func function=" << initializer.value;
                break;
            case WasmGlobalInitializerKind::extended_integer:
                out << " initializer=extended-integer instructions=" << initializer.instructions.size();
                if(initializer.evaluated_value_bits)out<<" evaluated-bits="<<wasm_hex(*initializer.evaluated_value_bits);
                else out<<" evaluated-bits=unresolved-host-global";
                break;
            }
            out << " expression-file=" << wasm_hex(initializer.expression_file_offset.value);
        } else if (global.imported) out << " value=host-supplied";
        out << " section-file=" << wasm_hex(global.section_file_offset.value)
            << " entry-file=" << wasm_hex(global.entry_file_offset.value) << '\n';
    }
    if (wasm.globals.size() > display_limit)
        out << "Globals omitted: " << (wasm.globals.size() - display_limit) << '\n';
    for (std::size_t i = 0; i < std::min(display_limit, wasm.function_names.size()); ++i) {
        const auto &name = wasm.function_names[i];
        out << "Function name: index=" << name.function_index << " name=\"" << wasm_escape_name(name.name)
            << "\" entry-file=" << wasm_hex(name.entry_file_offset.value) << '\n';
    }
    if (wasm.function_names.size() > display_limit)
        out << "Function names omitted: " << (wasm.function_names.size() - display_limit) << '\n';
    for (std::size_t i = 0; i < std::min(display_limit, wasm.local_names.size()); ++i) {
        const auto &name = wasm.local_names[i];
        out << "Local name: function=" << name.function_index << " local=" << name.local_index
            << " name=\"" << wasm_escape_name(name.name) << "\" entry-file=" << wasm_hex(name.entry_file_offset.value) << '\n';
    }
    if (wasm.local_names.size() > display_limit)
        out << "Local names omitted: " << (wasm.local_names.size() - display_limit) << '\n';
    for (std::size_t i = 0; i < std::min(display_limit, wasm.label_names.size()); ++i) {
        const auto &name = wasm.label_names[i];
        out << "Label name: function=" << name.function_index << " label=" << name.label_index
            << " name=\"" << wasm_escape_name(name.name) << "\" entry-file="
            << wasm_hex(name.entry_file_offset.value) << '\n';
    }
    if (wasm.label_names.size() > display_limit)
        out << "Label names omitted: " << (wasm.label_names.size() - display_limit) << '\n';
    const auto index_name_kind = [](std::uint8_t subsection) {
        switch (subsection) {
        case 4: return "type";
        case 5: return "table";
        case 6: return "memory";
        case 7: return "global";
        case 8: return "element";
        case 9: return "data";
        default: return "unknown";
        }
    };
    for (std::size_t i = 0; i < std::min(display_limit, wasm.index_names.size()); ++i) {
        const auto &name = wasm.index_names[i];
        out << "Index name: kind=" << index_name_kind(name.subsection_id) << " index=" << name.index
            << " name=\"" << wasm_escape_name(name.name) << "\" entry-file="
            << wasm_hex(name.entry_file_offset.value) << '\n';
    }
    if (wasm.index_names.size() > display_limit)
        out << "Index names omitted: " << (wasm.index_names.size() - display_limit) << '\n';
    for (std::size_t i = 0; i < std::min(display_limit, wasm.custom_sections.size()); ++i) {
        const auto &section = wasm.custom_sections[i];
        out << "Custom section: name=\"" << wasm_escape_name(section.name) << "\" section-file="
            << wasm_hex(section.section_file_offset.value) << " section-bytes=" << section.section_size
            << " payload-file=" << wasm_hex(section.payload_file_offset.value)
            << " payload-bytes=" << section.payload_size << "\n";
    }
    if (wasm.custom_sections.size() > display_limit)
        out << "Custom sections omitted: " << (wasm.custom_sections.size() - display_limit) << '\n';
}
} // namespace hexlab::cli
