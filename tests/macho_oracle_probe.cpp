#include "hexlab/loaders/macho.hpp"
#include <iostream>
#include <string>
using namespace hexlab;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
void string(std::string_view value) {
    constexpr char hex[] = "0123456789abcdef";
    std::cout << '"';
    for (unsigned char ch : value) {
        if (ch == '"' || ch == '\\')
            std::cout << '\\' << char(ch);
        else if (ch < 32 || ch >= 127)
            std::cout << "\\u00" << hex[ch >> 4] << hex[ch & 15];
        else
            std::cout << char(ch);
    }
    std::cout << '"';
}
template <class R, class F> void array(const R &rows, F emit) {
    std::cout << '[';
    bool first = true;
    for (const auto &row : rows) {
        if (!first)
            std::cout << ',';
        first = false;
        emit(row);
    }
    std::cout << ']';
}
template <class T> void optional(const std::optional<T> &value) {
    if (value)
        std::cout << *value;
    else
        std::cout << "null";
}
void address(const std::optional<Address> &value) {
    if (value)
        std::cout << '[' << value->space.value << ',' << value->offset << ']';
    else
        std::cout << "null";
}
} // namespace
int main(int argc, char **argv) {
    try {
        if (argc < 2 || argc > 3)
            throw std::runtime_error("Expected input and optional slice index");
        MachOOptions options;
        if (argc == 3)
            options.slice_index = static_cast<std::uint32_t>(std::stoul(argv[2]));
        auto storage = take(FileStorage::open(argv[1]));
        const auto loaded = take(load_macho(storage, options, {}));
        const auto &m = *loaded.metadata.macho;
        const auto &s = m.container.slices.at(m.selected_slice);
        const auto &h = s.header;
        std::cout << "{\"selected\":" << m.selected_slice << ",\"complete\":" << loaded.metadata_complete
                  << ",\"universal\":" << m.container.universal << ",\"fat64\":" << m.container.fat_64
                  << ",\"header\":{\"class\":" << (h.is_64 ? 64 : 32)
                  << ",\"order\":" << (h.order == ByteOrder::little ? 1 : 2) << ",\"cpu\":" << h.cpu_type
                  << ",\"subtype\":" << h.cpu_subtype << ",\"type\":" << h.file_type
                  << ",\"commands\":" << h.command_count << ",\"command_bytes\":" << h.command_bytes
                  << ",\"flags\":" << h.flags << ",\"reserved\":" << h.reserved << "},\"slices\":";
        array(m.container.slices, [](const auto &r) {
            std::cout << '[' << r.index << ',' << r.cpu_type << ',' << r.cpu_subtype << ',' << r.offset << ',' << r.size
                      << ',' << r.alignment << ',' << r.reserved << ']';
        });
        std::cout << ",\"commands\":";
        array(h.commands, [](const auto &r) {
            std::cout << '[' << r.index << ',' << r.command << ',' << r.size << ',' << r.file_offset << ']';
        });
        std::cout << ",\"segments\":";
        array(m.segments, [](const auto &r) {
            std::cout << "{\"name\":";
            string(r.name);
            std::cout << ",\"fields\":[" << r.address << ',' << r.memory_size << ',' << r.raw_file_offset << ','
                      << r.file_size << ',' << r.maximum_protection << ',' << r.initial_protection << ',' << r.flags
                      << ',' << r.section_count << "]}";
        });
        std::cout << ",\"sections\":";
        array(m.sections, [](const auto &r) {
            std::cout << "{\"name\":";
            string(r.name);
            std::cout << ",\"segment\":";
            string(r.segment_name);
            std::cout << ",\"fields\":[" << r.ordinal << ',' << r.address << ',' << r.size << ',' << r.raw_file_offset
                      << ',' << r.alignment << ',' << r.relocation_offset << ',' << r.relocation_count << ',' << r.flags
                      << ',' << r.reserved1 << ',' << r.reserved2 << ',' << r.reserved3
                      << "],\"source\":" << r.record_file_offset << '}';
        });
        std::cout << ",\"symbols\":";
        array(m.symbols, [](const auto &r) {
            std::cout << "{\"name\":";
            string(r.name);
            std::cout << ",\"fields\":[" << r.index << ',' << r.string_index << ',' << unsigned(r.type) << ','
                      << unsigned(r.section) << ',' << r.descriptor << ',' << r.value
                      << "],\"source\":" << r.record_file_offset << ",\"address\":";
            address(r.address);
            std::cout << '}';
        });
        std::cout << ",\"relocations\":";
        array(m.relocations, [&m](const auto &r) {
            const auto &table = m.relocation_tables.at(r.table);
            std::cout << "{\"owner\":" << table.owner << ",\"source_kind\":" << unsigned(table.kind) << ",\"fields\":["
                      << r.index << ',' << r.offset << ',' << unsigned(r.type) << ',' << unsigned(r.length) << ','
                      << r.pc_relative << ',' << r.external << ',' << r.scattered << ',' << r.symbol_number << ','
                      << r.raw_address << ',' << r.raw_info << "],\"value\":";
            optional(r.value);
            std::cout << ",\"source\":" << r.record_file_offset << ",\"place\":";
            address(r.place);
            std::cout << '}';
        });
        std::cout << ",\"dynamic\":";
        array(m.dynamic_symbol_tables, [](const auto &r) {
            std::cout << "{\"ranges\":";
            array(r.ranges, [](const auto &v) { std::cout << '[' << v.begin << ',' << v.count << ']'; });
            std::cout << ",\"tables\":";
            array(r.tables,
                  [](const auto &v) { std::cout << '[' << v.raw_offset << ',' << v.count << ',' << v.stride << ']'; });
            std::cout << ",\"indirect\":";
            array(r.indirect_symbols, [](auto v) { std::cout << v; });
            std::cout << '}';
        });
        std::cout << ",\"libraries\":";
        array(m.libraries, [](const auto &r) {
            std::cout << "{\"name\":";
            string(r.name);
            std::cout << ",\"fields\":[" << r.command << ',' << r.timestamp << ',' << r.current_version << ','
                      << r.compatibility_version << "],\"ordinal\":";
            optional(r.ordinal);
            std::cout << '}';
        });
        std::cout << ",\"fixups\":";
        array(m.dyld_fixups, [&m](const auto &r) {
            std::cout << "{\"kind\":" << unsigned(m.dyld_streams.at(r.stream).kind) << ",\"address\":";
            address(r.place);
            std::cout << ",\"type\":" << unsigned(r.type) << ",\"symbol\":";
            string(r.symbol);
            std::cout << ",\"ordinal\":";
            optional(r.library_ordinal);
            std::cout << ",\"addend\":" << r.addend << '}';
        });
        std::cout << ",\"exports\":";
        array(m.dyld_exports, [](const auto &r) {
            std::cout << "{\"name\":";
            string(r.name);
            std::cout << ",\"flags\":" << r.flags << ",\"value\":";
            optional(r.value);
            std::cout << ",\"address\":";
            address(r.address);
            std::cout << ",\"resolver\":";
            optional(r.resolver);
            std::cout << '}';
        });
        std::cout << ",\"chain_headers\":";
        array(m.chained_headers, [](const auto &r) {
            std::cout << '[' << r.version << ',' << r.starts_offset << ',' << r.imports_offset << ','
                      << r.symbols_offset << ',' << r.imports_count << ',' << r.imports_format << ','
                      << r.symbols_format << ']';
        });
        std::cout << ",\"chain_imports\":";
        array(m.chained_imports, [](const auto &r) {
            std::cout << "{\"name\":";
            if (r.name)
                string(*r.name);
            else
                std::cout << "null";
            std::cout << ",\"fields\":[" << r.index << ',' << r.library_ordinal << ',' << r.weak_import << ','
                      << r.addend << "]}";
        });
        std::cout << ",\"chain_starts\":";
        array(m.chained_starts, [](const auto &r) {
            std::cout << "{\"fields\":[" << r.segment_index << ',' << r.segment_offset << ',' << r.page_size << ','
                      << r.pointer_format << ',' << r.page_count << ',' << r.max_valid_pointer << "],\"pages\":";
            array(r.page_starts, [](auto p) { std::cout << p; });
            std::cout << '}';
        });
        std::cout << ",\"chain_pointers\":";
        array(m.chained_pointers, [&m](const auto &r) {
            std::cout << "{\"address\":";
            address(r.place);
            std::cout << ",\"raw\":" << r.raw << ",\"bind\":" << r.bind << ",\"authenticated\":" << r.authenticated
                      << ",\"non_pointer\":" << r.non_pointer << ",\"target\":";
            optional(r.target);
            std::cout << ",\"format\":" << m.chained_starts.at(r.starts).pointer_format
                      << ",\"high8\":" << unsigned(r.high8);
            std::cout << ",\"import\":";
            optional(r.import_row);
            std::cout << ",\"addend\":" << r.addend << '}';
        });
        std::cout << ",\"data_in_code\":";
        array(m.data_in_code, [](const auto &r) {
            std::cout << '[' << r.index << ',' << r.raw_offset << ',' << r.length << ',' << r.kind << ',';
            if (r.offset)
                std::cout << r.offset->value;
            else
                std::cout << "null";
            std::cout << ']';
        });
        std::cout << ",\"code_exclusions\":";
        array(loaded.image->layout().code_exclusions, [](const auto &r) {
            std::cout << '[' << r.begin.space.value << ',' << r.begin.offset << ',' << r.size << ']';
        });
        std::cout << ",\"diagnostics\":";
        array(loaded.diagnostics, [](const auto &r) { string(r.message); });
        std::cout << "}\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
