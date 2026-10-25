#pragma once
#include "hexlab/image/metadata.hpp"
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
