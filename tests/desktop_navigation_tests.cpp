#include "jump_resolver.hpp"
#include "marker_navigation.hpp"
#include "support/checks.hpp"

using namespace hexlab;
using namespace hexlab::desktop;

int main() {
    return hexlab_test::run([] {
        std::vector<Location> marks{Address{{0}, 0x30}, Address{{0}, 0x10},
                                    Address{{0}, 0x20}, Address{{0}, 0x20}};
        hexlab_test::check(adjacent_marker(marks, Address{{0}, 0x10}, true) == Location{Address{{0}, 0x20}} &&
                               adjacent_marker(marks, Address{{0}, 0x20}, true) == Location{Address{{0}, 0x30}},
                           "next marker walks sorted unique marker locations");
        hexlab_test::check(adjacent_marker(marks, Address{{0}, 0x20}, false) == Location{Address{{0}, 0x10}} &&
                               !adjacent_marker(marks, Address{{0}, 0x30}, true) &&
                               !adjacent_marker(marks, Address{{0}, 0x10}, false),
                           "previous and next marker navigation stop at the ends");
        hexlab_test::check(adjacent_marker(marks, {}, true) == Location{Address{{0}, 0x10}} &&
                               adjacent_marker(marks, {}, false) == Location{Address{{0}, 0x30}},
                           "marker navigation starts at the nearest end without a selection");
        ImageMetadata metadata;
        metadata.exports.push_back({1, std::string("public_api"), Address{{0}, 0x401000}, {}});
        metadata.exports.push_back({2, std::string("ambiguous_api"), Address{{0}, 0x401100}, {}});
        metadata.exports.push_back({3, std::string("ambiguous_api"), Address{{0}, 0x401200}, {}});
        metadata.imports.push_back({"libc.so", std::string("puts"), {}, {}, Address{{0}, 0x404018}});
        metadata.imports.push_back({"libc.so", std::string("conflict"), {}, {}, Address{{0}, 0x404028}});
        metadata.imports.push_back({"libc.so", {}, std::uint16_t{7}, {}, Address{{0}, 0x404020}});
        metadata.exports.push_back({4, {}, Address{{0}, 0x401300}, {}});
        metadata.exports.push_back({5, std::string("conflict"), Address{{0}, 0x401400}, {}});
        metadata.elf.emplace();
        ElfSymbol defined{};
        defined.name = "global_data";
        defined.state = ElfSymbolState::defined;
        defined.address = Address{{0}, 0x402008};
        metadata.elf->symbols.push_back(defined);
        ElfSymbol alias{};
        alias.name = "public_api";
        alias.state = ElfSymbolState::defined;
        alias.address = Address{{0}, 0x401000};
        metadata.elf->symbols.push_back(alias);
        ElfSymbol undefined{};
        undefined.name = "unresolved_elf";
        undefined.state = ElfSymbolState::undefined;
        metadata.elf->symbols.push_back(undefined);
        metadata.macho.emplace();
        MachOSymbol mach{};
        mach.name = "macho_function";
        mach.state = MachOSymbolState::defined;
        mach.address = Address{{0}, 0x403000};
        metadata.macho->symbols.push_back(mach);
        MachODyldExport dyld{};
        dyld.name = "dyld_export";
        dyld.address = Address{{0}, 0x403100};
        metadata.macho->dyld_exports.push_back(dyld);
        metadata.pe.emplace();
        PePdbSymbol procedure{};
        procedure.name = "pdb_procedure";
        procedure.procedure = true;
        procedure.address = Address{{0}, 0x405000};
        metadata.pe->pdb_symbols.push_back(procedure);
        PePdbSymbol data{};
        data.name = "pdb_data";
        data.address = Address{{0}, 0x405100};
        metadata.pe->pdb_symbols.push_back(data);

        const auto entries = image_symbol_locations(metadata);
        const auto check_candidate = [&](const char *name, Address address) {
            const auto candidates = named_location_candidates(entries, wxString::FromUTF8(name));
            return candidates.size() == 1 && candidates.front().location == Location{address};
        };
        hexlab_test::check(check_candidate("public_api", {{0}, 0x401000}) &&
                               check_candidate("ordinal 4", {{0}, 0x401300}),
                           "named and ordinal exports resolve to their virtual addresses");
        const auto public_match = resolve_named_location(entries, "PUBLIC_API");
        hexlab_test::check(public_match.location == Location{Address{{0}, 0x401000}} && !public_match.ambiguous,
                           "the Jump resolver navigates directly to a unique metadata symbol");
        hexlab_test::check(check_candidate("puts", {{0}, 0x404018}),
                           "named imported symbols resolve to their IAT slot");
        hexlab_test::check(check_candidate("ordinal 7", {{0}, 0x404020}),
                           "ordinal imports resolve to their IAT slot");
        hexlab_test::check(check_candidate("global_data", {{0}, 0x402008}),
                           "defined ELF symbols resolve while undefined symbols are omitted");
        hexlab_test::check(check_candidate("macho_function", {{0}, 0x403000}) &&
                               check_candidate("dyld_export", {{0}, 0x403100}),
                           "defined Mach-O symbols and dyld exports resolve");
        hexlab_test::check(check_candidate("pdb_procedure", {{0}, 0x405000}) &&
                               check_candidate("pdb_data", {{0}, 0x405100}),
                           "address-bearing PDB procedure and data symbols resolve");

        const auto duplicate_exports = named_location_candidates(entries, "AMBIGUOUS_API");
        hexlab_test::check(duplicate_exports.size() == 2 &&
                               duplicate_exports[0].location == Location{Address{{0}, 0x401100}} &&
                               duplicate_exports[1].location == Location{Address{{0}, 0x401200}},
                           "case-insensitive duplicate symbol names retain every distinct destination");
        hexlab_test::check(resolve_named_location(entries, "conflict").ambiguous &&
                               named_location_candidates(entries, "conflict").size() == 2,
                           "an imported symbol and export sharing a name surface both jump destinations");
        hexlab_test::check(named_location_candidates(entries, "public_api").size() == 1,
                           "aliases for one symbol address do not create duplicate destinations");
    });
}
