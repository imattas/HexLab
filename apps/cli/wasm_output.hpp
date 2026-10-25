#pragma once
#include "hexlab/image/metadata.hpp"
#include <algorithm>
#include <iomanip>
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
inline void wasm_description(std::ostream &out, const ImageMetadata &metadata) {
    if (!metadata.wasm) return;
    const auto &wasm = *metadata.wasm;
    out << "WebAssembly: types=" << wasm.type_count
        << " functions=" << wasm.function_type_indices.size()
        << " imports=" << wasm.imports.size()
        << " exports=" << wasm.exports.size()
        << " data-segments=" << wasm.data_segments.size()
        << " element-segments=" << wasm.element_segments.size()
        << " named-functions=" << wasm.function_names.size()
        << " named-locals=" << wasm.local_names.size() << '\n';
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
    constexpr std::size_t display_limit = 128;
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
}
} // namespace hexlab::cli
