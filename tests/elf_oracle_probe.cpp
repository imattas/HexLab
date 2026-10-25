#include "hexlab/loaders/elf.hpp"
#include "hexlab/analysis/functions.hpp"
#include "hexlab/analysis/references.hpp"
#include <iostream>
#include <set>
using namespace hexlab;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
void text(std::string_view value) {
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
template <class Range, class F> void array(const Range &values, F emit) {
    std::cout << '[';
    bool first = true;
    for (const auto &value : values) {
        if (!first)
            std::cout << ',';
        first = false;
        emit(value);
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
void source(const ElfTableSource &value) {
    std::cout << "\"section\":";
    optional(value.section);
    std::cout << ",\"file\":" << value.file_offset << ",\"address\":";
    address(value.address);
}
} // namespace
int wmain(int argc, wchar_t **argv) {
    try {
        if (argc != 2)
            throw std::runtime_error("Supply one ELF input to inspect");
        auto storage = take(FileStorage::open(argv[1]));
        auto loaded = take(load_elf(storage, {}));
        const auto &elf = *loaded.metadata.elf;
        const auto &h = elf.header;
        std::cout << "{\"header\":{\"class\":" << (h.is_64 ? 64 : 32)
                  << ",\"order\":" << (h.order == ByteOrder::little ? 1 : 2) << ",\"type\":" << h.object_type
                  << ",\"machine\":" << h.machine << ",\"entry\":" << h.entry << ",\"flags\":" << h.flags
                  << ",\"program_offset\":" << h.programs.offset << ",\"section_offset\":" << h.sections.offset
                  << ",\"section_names\":" << h.section_names << "},\"programs\":";
        array(elf.programs, [](const auto &p) {
            std::cout << '[' << p.type << ',' << p.offset << ',' << p.address << ',' << p.physical_address << ','
                      << p.file_size << ',' << p.memory_size << ',' << p.flags << ',' << p.alignment << ']';
        });
        std::cout << ",\"sections\":";
        array(elf.sections, [](const auto &s) {
            std::cout << '[' << s.index << ',';
            text(s.name);
            std::cout << ',' << s.type << ',' << s.flags << ',' << s.address << ',' << s.offset << ',' << s.size << ','
                      << s.link << ',' << s.info << ',' << s.alignment << ',' << s.entry_size << ']';
        });
        std::cout << ",\"symbol_tables\":";
        array(elf.symbol_tables, [](const auto &t) {
            std::cout << '{';
            source(t.source);
            std::cout << ",\"stride\":" << t.stride << ",\"count\":";
            optional(t.count);
            std::cout << '}';
        });
        std::cout << ",\"symbols\":";
        array(elf.symbols, [](const auto &s) {
            std::cout << "{\"section\":";
            optional(s.table);
            std::cout << ",\"file\":" << s.table_offset << ",\"table_address\":";
            address(s.table_address);
            std::cout << ",\"index\":" << s.index << ",\"name\":";
            text(s.name);
            std::cout << ",\"fields\":[" << s.name_index << ',' << s.value << ',' << s.size << ','
                      << unsigned(s.binding) << ',' << unsigned(s.type) << ',' << unsigned(s.other) << ','
                      << s.section_index << "],\"address\":";
            address(s.address);
            std::cout << '}';
        });
        std::cout << ",\"relocation_tables\":";
        array(elf.relocation_tables, [](const auto &t) {
            std::cout << '{';
            source(t.source);
            std::cout << ",\"rela\":" << (t.explicit_addend ? "true" : "false") << ",\"symbol_table\":";
            if (t.symbol_table) {
                std::cout << '{';
                source(*t.symbol_table);
                std::cout << '}';
            } else
                std::cout << "null";
            std::cout << ",\"target_section\":";
            optional(t.target_section);
            std::cout << ",\"rows\":";
            array(t.rows, [](auto n) { std::cout << n; });
            std::cout << '}';
        });
        std::cout << ",\"relocations\":";
        array(elf.relocations, [](const auto &r) {
            std::cout << "{\"offset\":" << r.offset << ",\"type\":" << r.type << ",\"symbol\":" << r.symbol_index
                      << ",\"rela\":" << (r.explicit_addend ? "true" : "false") << ",\"addend_bits\":";
            if (r.addend)
                std::cout << static_cast<std::uint64_t>(*r.addend);
            else
                std::cout << "null";
            std::cout << ",\"width\":";
            optional(r.field_size);
            std::cout << ",\"place\":";
            address(r.place);
            std::cout << ",\"file_place\":";
            if (r.file_place)
                std::cout << r.file_place->value;
            else
                std::cout << "null";
            std::cout << '}';
        });
        std::set<std::uint64_t> dynamic_rows;
        std::cout << ",\"dynamic\":";
        array(elf.dynamic_tables, [&](const auto &t) {
            std::cout << '{';
            source(t.source);
            std::cout << ",\"entries\":";
            array(t.entries, [](const auto &e) {
                std::cout << '[' << e.tag << ',' << e.value << ',';
                if (e.string_value)
                    text(*e.string_value);
                else
                    std::cout << "null";
                std::cout << ']';
            });
            std::cout << '}';
            for (const auto &role : t.relocation_tables)
                for (auto row : elf.relocation_tables.at(static_cast<std::size_t>(role.table_index)).rows)
                    dynamic_rows.insert(row);
        });
        std::cout << ",\"dynamic_rows\":";
        array(dynamic_rows, [](auto n) { std::cout << n; });
        std::cout << ",\"functions\":";
        std::shared_ptr<const FunctionSnapshot> functions;
        std::shared_ptr<const ReferenceIndex> references;
        if (processor_capabilities(loaded.image->decode_context()).can_decode) {
            functions = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
            references = take(derive_references(*loaded.image, *functions, loaded.metadata, {}, {}));
        }
        if (functions)
            array(functions->functions, [](const auto &f) { address(f->entry); });
        else
            std::cout << "[]";
        std::cout << ",\"control_origins\":[";
        bool first = true;
        if (references)
            for (const auto &r : references->all())
                if ((r.kind == ReferenceKind::call || r.kind == ReferenceKind::jump ||
                     r.kind == ReferenceKind::conditional_jump) &&
                    r.provenance.elf) {
                    if (!first)
                        std::cout << ',';
                    first = false;
                    std::cout << "{\"unresolved\":"
                              << (std::holds_alternative<UnresolvedTarget>(r.target) ? "true" : "false")
                              << ",\"external\":"
                              << (std::holds_alternative<ExternalIdentity>(r.target) ? "true" : "false")
                              << ",\"origins\":";
                    array(r.provenance.elf->origins, [](const auto &origin) {
                        std::cout << "{\"type\":" << origin.relocation.type
                                  << ",\"symbol\":" << origin.relocation.symbol_index << ",\"name\":";
                        if (origin.symbol)
                            text(origin.symbol->name);
                        else
                            std::cout << "null";
                        std::cout << '}';
                    });
                    std::cout << '}';
                }
        std::cout << "]}\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
