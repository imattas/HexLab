#include "hexlab/loaders/elf.hpp"
#include <algorithm>
#include <map>
#include <set>
#include <tuple>

namespace hexlab {
namespace {
bool symbol_uses_dynamic_table(const ElfSymbol &symbol,
                               const std::set<std::uint32_t> &section_tables,
                               const std::set<std::pair<std::uint64_t, std::uint64_t>> &address_tables) {
    if (symbol.table && section_tables.contains(*symbol.table)) return true;
    return symbol.table_address && address_tables.contains(
        {symbol.table_address->offset, symbol.table_offset});
}

std::vector<ElfTableSource> dynamic_symbol_sources(const ElfMetadata &metadata) {
    std::vector<ElfTableSource> result;
    for (const auto &table : metadata.dynamic_tables) {
        if (!table.symbol_table) continue;
        if (std::find(result.begin(), result.end(), *table.symbol_table) == result.end())
            result.push_back(*table.symbol_table);
    }
    return result;
}

bool import_matches_export(const ElfSymbol &import, const ElfSymbol &exported,
                           std::string_view dependency_name) {
    if (import.name != exported.name) return false;
    if (import.version_name) {
        return import.version_file && *import.version_file == dependency_name &&
               exported.version_name && *exported.version_name == *import.version_name;
    }
    if (import.version_file) return false;
    return !exported.version_name || !exported.version_hidden;
}
}

Result<ElfRuntimeBindingSet> resolve_elf_runtime_symbol_bindings(
    const LoadedImage &requester, std::span<const ElfRuntimeDependencyImage> dependencies,
    std::stop_token stop, ElfRuntimeBindingLimits limits) {
    if (!requester.metadata.elf || !requester.image)
        return Error{ErrorCode::invalid_argument, "ELF runtime binding resolution requires a loaded requester"};
    if (requester.metadata.elf->header.object_type != 3)
        return Error{ErrorCode::unsupported, "ELF runtime binding resolution requires an ET_DYN requester"};
    if (!limits.max_dependency_images || !limits.max_symbols_scanned || !limits.max_bindings ||
        !limits.max_issues || !limits.max_name_bytes)
        return Error{ErrorCode::invalid_argument, "ELF runtime binding limits must be positive"};
    if (dependencies.size() > limits.max_dependency_images)
        return Error{ErrorCode::resource_limit, "ELF runtime dependency image count exceeds limit"};
    try {
        std::vector<ElfLibraryManifestEntry> manifest;
        manifest.reserve(dependencies.size());
        for (const auto &dependency : dependencies) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF runtime binding resolution canceled"};
            if (!dependency.loaded || !dependency.loaded->image || !dependency.loaded->metadata.elf ||
                dependency.needed_name.empty() || dependency.needed_name.size() > limits.max_name_bytes)
                return Error{ErrorCode::invalid_argument, "ELF runtime dependency image or name is invalid"};
            if (dependency.loaded->metadata.elf->header.object_type != 3)
                return Error{ErrorCode::unsupported, "ELF runtime dependency image is not ET_DYN"};
            ElfLibraryManifestEntry entry{dependency.needed_name, dependency.aliases};
            for (const auto &alias : entry.aliases)
                if (alias.empty() || alias.size() > limits.max_name_bytes)
                    return Error{ErrorCode::invalid_argument, "ELF dependency alias is empty or exceeds limit"};
            manifest.push_back(std::move(entry));
        }
        ElfLibraryResolutionLimits library_limits;
        library_limits.max_manifest_entries = limits.max_dependency_images;
        library_limits.max_manifest_names = limits.max_dependency_images * 8;
        library_limits.max_name_bytes = limits.max_name_bytes;
        auto needed = resolve_elf_needed_libraries(requester, manifest, stop, library_limits);
        if (!needed) return needed.error();

        ElfRuntimeBindingSet result;
        std::vector<std::size_t> needed_provider;
        needed_provider.reserve(needed.value().size());
        for (const auto &resolution : needed.value()) {
            if (resolution.state != ElfLibraryResolutionState::resolved || !resolution.manifest_index) {
                result.complete = false;
                result.unresolved_dependencies.push_back(resolution);
                continue;
            }
            needed_provider.push_back(*resolution.manifest_index);
        }
        // Do not claim symbol-provider precedence from an incomplete or
        // ambiguous dependency set: an omitted earlier DSO could interpose.
        if (!result.unresolved_dependencies.empty()) return result;

        struct Exported {
            const ElfSymbol *symbol = nullptr;
            std::uint64_t runtime_address = 0;
        };
        std::vector<std::map<std::string, std::vector<Exported>, std::less<>>> exports(dependencies.size());
        std::size_t scanned_symbols = 0;
        const auto collect_symbols = [&](const LoadedImage &loaded, auto &&callback) -> Result<bool> {
            const auto &metadata = *loaded.metadata.elf;
            const auto sources = dynamic_symbol_sources(metadata);
            std::set<std::uint32_t> section_tables;
            std::set<std::pair<std::uint64_t, std::uint64_t>> address_tables;
            for (const auto &source : sources) {
                if (source.section) section_tables.insert(*source.section);
                else if (source.address) address_tables.emplace(source.address->offset, source.file_offset);
            }
            for (const auto &symbol : metadata.symbols) {
                if (!symbol_uses_dynamic_table(symbol, section_tables, address_tables)) continue;
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF dynamic symbol scan canceled"};
                if (++scanned_symbols > limits.max_symbols_scanned)
                    return Error{ErrorCode::resource_limit, "ELF dynamic symbol scan exceeds limit"};
                callback(symbol);
            }
            return true;
        };
        for (std::size_t dependency_index = 0; dependency_index < dependencies.size(); ++dependency_index) {
            const auto &dependency = dependencies[dependency_index];
            const auto collected = collect_symbols(*dependency.loaded, [&](const ElfSymbol &symbol) {
                if ((symbol.binding != 1 && symbol.binding != 2) ||
                    (symbol.visibility != 0 && symbol.visibility != 3) ||
                    (symbol.type == 6 || symbol.type == 10) ||
                    (symbol.state != ElfSymbolState::defined && symbol.state != ElfSymbolState::absolute) ||
                    symbol.name.empty() || symbol.name.size() > limits.max_name_bytes)
                    return;
                std::uint64_t address = symbol.value;
                if (symbol.state != ElfSymbolState::absolute) {
                    if (!dependency.loaded->image->segment_at({{0}, symbol.value}) ||
                        symbol.value > UINT64_MAX - dependency.load_bias)
                        return;
                    address += dependency.load_bias;
                }
                if (!dependency.loaded->metadata.elf->header.is_64 && address > UINT32_MAX) return;
                exports[dependency_index][symbol.name].push_back({&symbol, address});
            });
            if (!collected) return collected.error();
        }

        const auto &requester_metadata = *requester.metadata.elf;
        const auto requester_sources = dynamic_symbol_sources(requester_metadata);
        std::set<std::uint32_t> requester_sections;
        std::set<std::pair<std::uint64_t, std::uint64_t>> requester_addresses;
        for (const auto &source : requester_sources) {
            if (source.section) requester_sections.insert(*source.section);
            else if (source.address) requester_addresses.emplace(source.address->offset, source.file_offset);
        }
        std::set<std::tuple<std::string, std::optional<std::string>, std::optional<std::string>>> seen_imports;
        std::set<std::tuple<std::string, std::string, std::optional<std::string>, std::uint64_t>> seen_bindings;
        for (const auto &import : requester_metadata.symbols) {
            if (!symbol_uses_dynamic_table(import, requester_sections, requester_addresses) ||
                import.state != ElfSymbolState::undefined || (import.binding != 1 && import.binding != 2))
                continue;
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF import symbol scan canceled"};
            if (++scanned_symbols > limits.max_symbols_scanned)
                return Error{ErrorCode::resource_limit, "ELF dynamic symbol scan exceeds limit"};
            if (import.name.empty() || import.name.size() > limits.max_name_bytes)
                return Error{ErrorCode::resource_limit, "ELF import symbol name is empty or exceeds limit"};
            const auto import_key = std::tuple{import.name, import.version_name, import.version_file};
            if (!seen_imports.insert(import_key).second) continue;

            std::optional<ElfRuntimeSymbolBinding> selected;
            std::optional<std::string> selected_dependency;
            bool ambiguous = false;
            for (std::size_t needed_index = 0; needed_index < needed.value().size(); ++needed_index) {
                const auto &needed_name = needed.value()[needed_index].needed_name;
                if (import.version_name && import.version_file && needed_name != *import.version_file) continue;
                const auto provider_index = needed_provider[needed_index];
                const auto found = exports[provider_index].find(import.name);
                if (found == exports[provider_index].end()) continue;
                std::vector<const Exported *> matches;
                for (const auto &candidate : found->second)
                    if (import_matches_export(import, *candidate.symbol, needed_name)) matches.push_back(&candidate);
                if (matches.empty()) continue;
                if (matches.size() != 1) { ambiguous = true; selected_dependency = needed_name; break; }
                const auto &exported = *matches.front();
                selected = ElfRuntimeSymbolBinding{needed_name, import.name,
                    exported.symbol->version_name, exported.runtime_address,
                    exported.symbol->version_name.has_value() && !exported.symbol->version_hidden,
                    exported.symbol->size};
                selected_dependency = needed_name;
                break;
            }
            if (!selected || ambiguous) {
                if (result.unresolved_symbols.size() == limits.max_issues)
                    return Error{ErrorCode::resource_limit, "ELF unresolved symbol issue limit exceeded"};
                result.complete = false;
                result.unresolved_symbols.push_back({import.name, import.version_name,
                    import.version_file ? import.version_file : selected_dependency,
                    ambiguous ? "multiple matching exports in one dependency image" :
                    import.binding == 2 ? "weak import has no supplied matching export" :
                    "no supplied DT_NEEDED image exports the requested name and version"});
                continue;
            }
            const auto key = std::tuple{selected->library_name, selected->symbol_name,
                                        selected->version_name, selected->runtime_address};
            if (seen_bindings.insert(key).second) {
                if (result.bindings.size() == limits.max_bindings)
                    return Error{ErrorCode::resource_limit, "ELF derived symbol binding limit exceeded"};
                result.bindings.push_back(std::move(*selected));
            }
        }
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate bounded ELF runtime binding data"};
    }
}
} // namespace hexlab
