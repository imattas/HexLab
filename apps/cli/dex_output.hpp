#pragma once
#include "hexlab/image/metadata.hpp"
#include <algorithm>
#include <iomanip>
#include <ostream>
#include <string_view>

namespace hexlab::cli {
inline std::string dex_safe(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const unsigned char c : value) {
        if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (c < 0x20 || c == 0x7f) out += '?';
        else out += static_cast<char>(c);
    }
    return out;
}
inline void dex_description(std::ostream &out, const ImageMetadata &metadata) {
    if (!metadata.dex) return;
    const auto &dex = *metadata.dex;
    constexpr std::size_t max_classes = 256;
    constexpr std::size_t max_members_per_class = 128;
    out << "DEX class definitions: " << dex.classes.size() << '\n';
    const auto class_count = std::min(dex.classes.size(), max_classes);
    for (std::size_t i = 0; i < class_count; ++i) {
        const auto &definition = dex.classes[i];
        out << "  class type#" << definition.class_index << " flags=0x" << std::hex
            << definition.access_flags << std::dec;
        if (definition.superclass_index) out << " superclass=type#" << *definition.superclass_index;
        else out << " superclass=<none>";
        out << " interfaces=" << definition.interface_indices.size()
            << " static-fields=" << definition.static_fields.size()
            << " instance-fields=" << definition.instance_fields.size()
            << " direct-methods=" << definition.direct_methods.size()
            << " virtual-methods=" << definition.virtual_methods.size() << '\n';
        const auto fields = [&](std::string_view label, const auto &items) {
            const auto shown = std::min(items.size(), max_members_per_class);
            for (std::size_t member = 0; member < shown; ++member)
                out << "    " << label << " field#" << items[member].field_index
                    << " flags=0x" << std::hex << items[member].access_flags << std::dec << '\n';
            if (shown < items.size()) out << "    " << label << " fields omitted=" << (items.size() - shown) << '\n';
        };
        const auto methods = [&](std::string_view label, const auto &items) {
            const auto shown = std::min(items.size(), max_members_per_class);
            for (std::size_t member = 0; member < shown; ++member) {
                const auto &method = items[member];
                out << "    " << label << " method#" << method.method_index
                    << " flags=0x" << std::hex << method.access_flags << std::dec
                    << " code-offset=0x" << std::hex << method.code_offset << std::dec << '\n';
            }
            if (shown < items.size()) out << "    " << label << " methods omitted=" << (items.size() - shown) << '\n';
        };
        fields("static", definition.static_fields);
        fields("instance", definition.instance_fields);
        methods("direct", definition.direct_methods);
        methods("virtual", definition.virtual_methods);
    }
    if (class_count < dex.classes.size()) out << "  classes omitted=" << (dex.classes.size() - class_count) << '\n';
    out << "DEX debug methods: " << dex.methods.size() << '\n';
    for (const auto &method : dex.methods) {
        out << "  method #" << method.method_index << " line-start=" << method.line_start
            << " parameters=" << method.parameter_names.size() << " lines=" << method.lines.size()
            << " locals=" << method.locals.size() << '\n';
        for (std::size_t i = 0; i < method.parameter_names.size(); ++i) {
            out << "    parameter " << i << " name=";
            if (method.parameter_names[i]) out << dex_safe(*method.parameter_names[i]);
            else out << "<unnamed>";
            out << '\n';
        }
        for (std::size_t i = 0; i < method.lines.size() && i < 256; ++i) {
            const auto &line = method.lines[i];
            out << "    line +0x" << std::hex << line.address << std::dec << '=' << line.line;
            if (!line.source_file.empty()) out << " file=" << dex_safe(line.source_file);
            out << '\n';
        }
        for (std::size_t i = 0; i < method.locals.size() && i < 256; ++i) {
            const auto &local = method.locals[i];
            out << "    local v" << local.register_index << " [+0x" << std::hex << local.begin
                << ",+0x" << local.end << ")" << std::dec;
            if (local.name) out << " name=" << dex_safe(*local.name);
            if (local.type) out << " type=" << dex_safe(*local.type);
            if (local.signature) out << " signature=" << dex_safe(*local.signature);
            out << '\n';
        }
        if (method.lines.size() > 256 || method.locals.size() > 256)
            out << "    display truncated at 256 rows per category\n";
    }
}
} // namespace hexlab::cli
