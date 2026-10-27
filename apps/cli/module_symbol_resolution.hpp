#pragma once
#include "hexlab/image/metadata.hpp"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <map>
#include <ostream>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace hexlab::cli {
struct SuppliedModule {
    std::string path;
    const ImageMetadata *metadata = nullptr;
};

inline std::string module_leaf(std::string value) {
    const auto slash = value.find_last_of("/\\");
    if (slash != std::string::npos) value.erase(0, slash + 1);
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

inline bool is_pe_module(const ImageMetadata &metadata) {
    return metadata.format == "PE32" || metadata.format == "PE32+";
}

inline bool elf_abi_compatible(const ElfHeader &importer, const ElfHeader &provider) {
    // ELF's generic loader model is not enough to prove that an address from
    // one object is meaningful in another architecture's process image.
    return importer.is_64 == provider.is_64 && importer.order == provider.order &&
           importer.machine == provider.machine;
}

inline std::vector<std::size_t> elf_dynamic_symbol_table_indices(const ElfMetadata &elf) {
    std::vector<std::size_t> indices;
    for (std::size_t table_index = 0; table_index < elf.symbol_tables.size(); ++table_index) {
        const auto &source = elf.symbol_tables[table_index].source;
        if (std::any_of(elf.dynamic_tables.begin(), elf.dynamic_tables.end(), [&](const auto &table) {
                return table.symbol_table && *table.symbol_table == source;
            })) indices.push_back(table_index);
    }
    return indices;
}

// Resolve undefined ELF dynamic symbols against explicitly supplied objects.
// We intentionally require a unique DT_NEEDED basename when available; no
// ambient loader search path or filesystem probing is performed.
inline void print_elf_import_resolutions(const std::vector<SuppliedModule> &modules, std::ostream &out) {
    constexpr std::size_t row_cap = 100000;
    std::vector<std::vector<std::size_t>> dynamic_tables_by_module(modules.size());
    for (std::size_t module_index = 0; module_index < modules.size(); ++module_index)
        if (modules[module_index].metadata && modules[module_index].metadata->elf)
            dynamic_tables_by_module[module_index] = elf_dynamic_symbol_table_indices(*modules[module_index].metadata->elf);
    auto needed_names = [](const ImageMetadata &m) {
        std::vector<std::string> names;
        if (!m.elf) return names;
        for (const auto &table : m.elf->dynamic_tables)
            for (const auto &entry : table.entries)
                if (entry.tag == 1 && entry.string_value) names.push_back(*entry.string_value);
        return names;
    };
    out << "ELF imported-symbol resolution (only supplied files are considered):\n";
    for (std::size_t importer_index = 0; importer_index < modules.size(); ++importer_index) {
        const auto &importer = modules[importer_index];
        if (!importer.metadata || !importer.metadata->elf) continue;
        const auto &elf = *importer.metadata->elf;
        std::vector<const ElfSymbol *> imports;
        for (const auto &symbol : elf.symbols) {
            if (symbol.state == ElfSymbolState::undefined && symbol.binding != 0 &&
                symbol.table && std::find(dynamic_tables_by_module[importer_index].begin(),
                                          dynamic_tables_by_module[importer_index].end(), *symbol.table) !=
                                    dynamic_tables_by_module[importer_index].end())
                imports.push_back(&symbol);
        }
        out << "  " << importer.path << "\n";
        const auto names = needed_names(*importer.metadata);
        const auto count = std::min(imports.size(), row_cap);
        for (std::size_t i = 0; i < count; ++i) {
            const auto &wanted = *imports[i];
            out << "    " << (wanted.name.empty() ? "<empty>" : wanted.name);
            if (wanted.version_name) out << "@" << *wanted.version_name;
            out << " -> ";
            if (wanted.name.empty()) { out << "unsupported (empty symbol name)\n"; continue; }
            if (wanted.type == 6 || wanted.type == 10) { out << "unsupported (TLS/IFUNC import semantics)\n"; continue; }
            std::vector<std::size_t> providers;
            for (std::size_t candidate_index = 0; candidate_index < modules.size(); ++candidate_index) {
                const auto &candidate = modules[candidate_index];
                if (candidate_index == importer_index || !candidate.metadata || !candidate.metadata->elf) continue;
                if (names.empty() || std::any_of(names.begin(), names.end(), [&](const auto &n) {
                    return module_leaf(n) == module_leaf(candidate.path);
                })) providers.push_back(candidate_index);
            }
            if (providers.empty()) { out << "unresolved (no supplied DT_NEEDED provider)\n"; continue; }
            std::vector<std::pair<const SuppliedModule *, const ElfSymbol *>> matches;
            bool has_abi_compatible_provider = false;
            bool has_unsupported_provider_symbol = false;
            bool has_symbol_type_mismatch = false;
            for (const auto provider_index : providers) {
                const auto *provider = &modules[provider_index];
                const auto &pe = *provider->metadata->elf;
                if (!elf_abi_compatible(elf.header, pe.header)) continue;
                has_abi_compatible_provider = true;
                if (wanted.version_file && module_leaf(*wanted.version_file) != module_leaf(provider->path))
                    continue;
                for (const auto &candidate : pe.symbols) {
                    if (!candidate.table ||
                        std::find(dynamic_tables_by_module[provider_index].begin(),
                                  dynamic_tables_by_module[provider_index].end(), *candidate.table) ==
                            dynamic_tables_by_module[provider_index].end() ||
                        candidate.name != wanted.name ||
                        (candidate.state != ElfSymbolState::defined && candidate.state != ElfSymbolState::absolute) ||
                        (candidate.binding != 1 && candidate.binding != 2 && candidate.binding != 10) ||
                        candidate.visibility == 1 || candidate.visibility == 2) continue;
                    if (wanted.version_name) {
                        if (candidate.version_name != wanted.version_name) continue;
                    } else if (candidate.version_name && candidate.version_hidden) continue;
                    if (candidate.type == 6 || candidate.type == 10) {
                        has_unsupported_provider_symbol = true;
                        continue;
                    }
                    // STT_NOTYPE carries no useful type constraint. When both
                    // sides provide a concrete type, avoid claiming a match
                    // across different ELF symbol kinds (for example FUNC vs
                    // OBJECT).
                    if (wanted.type != 0 && candidate.type != 0 && wanted.type != candidate.type) {
                        has_symbol_type_mismatch = true;
                        continue;
                    }
                    matches.emplace_back(provider, &candidate);
                }
            }
            if (!has_abi_compatible_provider) {
                out << "unsupported (supplied DT_NEEDED providers have incompatible ELF class, byte order, or machine)\n";
                continue;
            }
            if (has_unsupported_provider_symbol) {
                out << "unsupported (matching provider export requires TLS/IFUNC semantics)\n";
                continue;
            }
            if (matches.empty() && has_symbol_type_mismatch) {
                out << "unsupported (matching provider export has incompatible ELF symbol type)\n";
                continue;
            }
            if (matches.empty()) { out << "unresolved (no exact eligible export)\n"; continue; }
            if (matches.size() != 1) { out << "ambiguous (" << matches.size() << " matching exports)\n"; continue; }
            const auto &[provider, symbol] = matches.front();
            out << "resolved " << provider->path;
            if (symbol->address) out << " at 0x" << std::hex << symbol->address->offset << std::dec;
            else out << " (address unavailable)";
            out << "\n";
        }
        if (imports.size() > count) out << "    ... omitted " << imports.size() - count << " rows (100000 row cap)\n";
    }
}

// Resolve PE imports only against explicitly supplied files. Module names are
// matched case-insensitively as Windows does; exported names are byte-exact and
// case-sensitive. Forwarders remain explicit terminal results rather than
// being guessed through additional module-name aliases.
inline void print_pe_import_resolutions(const std::vector<SuppliedModule> &modules, std::ostream &out) {
    constexpr std::size_t max_imports_per_module = 100000;
    out << "PE imported-symbol resolution (only supplied files are considered):\n";
    for (const auto &importer : modules) {
        if (!importer.metadata || !is_pe_module(*importer.metadata)) continue;
        const auto &imports = importer.metadata->imports;
        out << "  " << importer.path << "\n";
        const auto count = std::min(imports.size(), max_imports_per_module);
        for (std::size_t index = 0; index < count; ++index) {
            const auto &symbol = imports[index];
            out << "    " << (symbol.delay_load ? "delay " : "") << symbol.library << "!";
            if (symbol.name) out << *symbol.name;
            else if (symbol.ordinal) out << "ordinal #" << *symbol.ordinal;
            else out << "<invalid import identity>";
            out << " -> ";

            if (symbol.name.has_value() == symbol.ordinal.has_value()) {
                out << "unresolved (import must have exactly one name or ordinal)\n";
                continue;
            }
            const auto wanted_module = module_leaf(symbol.library);
            std::vector<const SuppliedModule *> providers;
            for (const auto &candidate : modules)
                if (candidate.metadata && module_leaf(candidate.path) == wanted_module)
                    providers.push_back(&candidate);
            if (providers.empty()) {
                out << "unresolved (provider module not supplied)\n";
                continue;
            }
            if (providers.size() != 1) {
                out << "ambiguous provider modules:";
                for (const auto *provider : providers) out << " " << provider->path;
                out << "\n";
                continue;
            }
            const auto &provider = *providers.front();
            if (!is_pe_module(*provider.metadata)) {
                out << "unsupported provider format " << provider.metadata->format << " (" << provider.path << ")\n";
                continue;
            }

            std::vector<const ExportSymbol *> matches;
            for (const auto &exported : provider.metadata->exports) {
                const bool matches_name = symbol.name && exported.name && *symbol.name == *exported.name;
                const bool matches_ordinal = symbol.ordinal && *symbol.ordinal == exported.ordinal;
                if (matches_name || matches_ordinal) matches.push_back(&exported);
            }
            if (matches.empty()) {
                out << "unresolved (no exact export in " << provider.path << ")\n";
                continue;
            }
            if (matches.size() != 1) {
                out << "ambiguous matching exports in " << provider.path << " (" << matches.size() << ")\n";
                continue;
            }
            const auto &exported = *matches.front();
            if (exported.forwarder) {
                out << "forwarded by " << provider.path << " to " << *exported.forwarder << "\n";
            } else if (exported.address) {
                out << "resolved " << provider.path << " at 0x" << std::hex << exported.address->offset
                    << std::dec << " (ordinal #" << exported.ordinal << ")\n";
            } else {
                out << "unresolved (export has no concrete address)\n";
            }
        }
        if (imports.size() > count)
            out << "    ... omitted " << (imports.size() - count) << " imports (100000 row cap)\n";
    }
}

// Resolve Mach-O bind names only against explicitly supplied images and the
// export trie of the selected provider slice. Ordinals and install-name
// basenames remain authoritative; special flat/weak lookup namespaces are not
// guessed as a search order.
inline void print_macho_import_resolutions(const std::vector<SuppliedModule> &modules, std::ostream &out) {
    constexpr std::size_t max_imports = 100000;
    struct ImportUse {
        std::int32_t library_ordinal = 0;
        std::string name;
        bool weak = false;
        std::size_t classic_sites = 0, chained_sites = 0;
    };
    using ImportKey = std::tuple<std::int32_t, std::string, bool>;
    out << "Mach-O imported-symbol resolution (only supplied files and selected export slices are considered):\n";
    for (const auto &importer : modules) {
        if (!importer.metadata || !importer.metadata->macho) continue;
        const auto &metadata = *importer.metadata->macho;
        if (metadata.selected_slice >= metadata.container.slices.size()) continue;
        std::map<ImportKey, ImportUse> imports;
        std::size_t omitted = 0;
        const auto add_import = [&](std::int32_t ordinal, const std::string &name, bool weak, bool chained,
                                    std::size_t sites = 1) {
            if (name.empty()) return;
            const ImportKey key{ordinal, name, weak};
            auto found = imports.find(key);
            if (found == imports.end()) {
                if (imports.size() >= max_imports) { ++omitted; return; }
                found = imports.emplace(key, ImportUse{ordinal, name, weak, 0, 0}).first;
            }
            if (chained) found->second.chained_sites += sites;
            else found->second.classic_sites += sites;
        };
        for (const auto &fixup : metadata.dyld_fixups) {
            if (!fixup.library_ordinal || fixup.symbol.empty() || fixup.stream >= metadata.dyld_streams.size()) continue;
            const auto kind = metadata.dyld_streams[fixup.stream].kind;
            if (kind != MachODyldStreamKind::bind && kind != MachODyldStreamKind::weak_bind &&
                kind != MachODyldStreamKind::lazy_bind) continue;
            add_import(*fixup.library_ordinal, fixup.symbol, (fixup.symbol_flags & 1u) != 0, false);
        }
        std::map<std::uint64_t, std::size_t> chained_sites;
        for (const auto &pointer : metadata.chained_pointers)
            if (pointer.bind && pointer.import_row) ++chained_sites[*pointer.import_row];
        for (std::size_t index = 0; index < metadata.chained_imports.size(); ++index) {
            const auto &import = metadata.chained_imports[index];
            if (!import.complete || !import.name) continue;
            const auto sites = chained_sites.find(index);
            const auto count = sites == chained_sites.end() ? 0 : sites->second;
            if (!count) continue;
            add_import(import.library_ordinal, *import.name, import.weak_import, true, count);
        }
        out << "  " << importer.path << " (dyld metadata "
            << (metadata.dyld_complete ? "complete" : "partial") << ")\n";
        if (imports.empty()) {
            out << "    (no bounded external bind rows in parsed metadata)\n";
            if (omitted) out << "    ... omitted " << omitted << " additional bind rows (100000 identity cap)\n";
            continue;
        }
        const auto &importer_slice = metadata.container.slices[metadata.selected_slice];
        for (const auto &[key, use] : imports) {
            (void)key;
            out << "    " << use.name << " [library ordinal " << use.library_ordinal;
            if (use.weak) out << ", weak";
            out << ", classic sites " << use.classic_sites << ", chained sites " << use.chained_sites << "] -> ";

            const SuppliedModule *provider = nullptr;
            std::string provider_name;
            if (use.library_ordinal == 0) {
                provider = &importer;
                provider_name = "self";
            } else if (use.library_ordinal == -1) {
                for (const auto &candidate : modules) {
                    if (!candidate.metadata || !candidate.metadata->macho) continue;
                    const auto &candidate_meta = *candidate.metadata->macho;
                    if (candidate_meta.selected_slice >= candidate_meta.container.slices.size() ||
                        candidate_meta.container.slices[candidate_meta.selected_slice].header.file_type != 2) continue;
                    if (provider) { provider = nullptr; break; }
                    provider = &candidate;
                }
                provider_name = "main executable";
            } else if (use.library_ordinal > 0) {
                const MachOLibrary *library = nullptr;
                for (const auto &row : metadata.libraries)
                    if (row.ordinal && *row.ordinal == static_cast<std::uint32_t>(use.library_ordinal)) {
                        if (library) { library = nullptr; break; }
                        library = &row;
                    }
                if (!library) {
                    out << "unresolved (library ordinal does not name one parsed load command)\n";
                    continue;
                }
                provider_name = library->name;
                std::vector<const SuppliedModule *> candidates;
                for (const auto &candidate : modules)
                    if (&candidate != &importer && candidate.metadata && candidate.metadata->macho &&
                        module_leaf(candidate.path) == module_leaf(library->name))
                        candidates.push_back(&candidate);
                if (candidates.size() == 1) provider = candidates.front();
                else if (candidates.empty()) {
                    out << "unresolved (provider not supplied for " << library->name << ")\n";
                    continue;
                } else {
                    out << "ambiguous provider files for " << library->name << ":";
                    for (const auto *candidate : candidates) out << " " << candidate->path;
                    out << "\n";
                    continue;
                }
            } else {
                out << "unresolved (special flat/weak lookup ordinal is not modeled)\n";
                continue;
            }
            if (!provider || !provider->metadata || !provider->metadata->macho) {
                out << "unresolved (" << provider_name << " provider is not uniquely supplied)\n";
                continue;
            }
            const auto &provider_meta = *provider->metadata->macho;
            if (provider_meta.selected_slice >= provider_meta.container.slices.size()) {
                out << "unresolved (provider slice is invalid)\n";
                continue;
            }
            const auto &provider_slice = provider_meta.container.slices[provider_meta.selected_slice];
            if (provider_slice.header.cpu_type != importer_slice.header.cpu_type) {
                out << "incompatible architecture (" << provider->path << ")\n";
                continue;
            }
            std::vector<const MachODyldExport *> matches;
            for (const auto &exported : provider_meta.dyld_exports)
                if (exported.name == use.name) matches.push_back(&exported);
            if (matches.empty()) {
                out << "unresolved (no exact export in " << provider->path;
                if (!provider_meta.dyld_complete) out << "; provider export metadata is partial";
                out << ")\n";
                continue;
            }
            if (matches.size() != 1) {
                out << "ambiguous exports in " << provider->path << " (" << matches.size() << ")\n";
                continue;
            }
            const auto &exported = *matches.front();
            if (!exported.is_definition()) {
                if (exported.import_name)
                    out << "reexported by " << provider->path << " as " << *exported.import_name << " (not followed)\n";
                else
                    out << "unsupported export kind in " << provider->path << "\n";
                continue;
            }
            out << "resolved " << provider->path;
            if (exported.address) out << " at 0x" << std::hex << exported.address->offset << std::dec;
            else out << " (preferred address unavailable)";
            out << "\n";
        }
        if (omitted) out << "    ... omitted " << omitted << " additional bind rows (100000 identity cap)\n";
    }
}
} // namespace hexlab::cli
