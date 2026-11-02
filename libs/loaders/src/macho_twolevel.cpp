#include "hexlab/loaders/macho.hpp"
#include <algorithm>
#include <map>
#include <set>

namespace hexlab {
Result<std::vector<MachOTwoLevelResolution>> resolve_macho_two_level_hints(
    const MachOMetadata &importer, std::span<const MachOTwoLevelProvider> providers,
    std::stop_token stop, MachOTwoLevelResolutionLimits limits) {
    if (importer.two_level_hints.size() > limits.max_rows || limits.max_rows > 1'000'000 || providers.size() > 65'536 ||
        importer.symbols.size() > 1'000'000 || importer.libraries.size() > 65'536)
        return Error{ErrorCode::resource_limit, "Mach-O two-level resolution exceeds its row limit"};
    if (importer.selected_slice >= importer.container.slices.size())
        return Error{ErrorCode::invalid_argument, "Mach-O two-level importer has an invalid selected slice"};
    try {
        using ProviderKey = std::pair<std::uint32_t, std::uint8_t>;
        std::map<ProviderKey, const MachOTwoLevelProvider *> provider_index;
        std::set<ProviderKey> ambiguous_providers;
        std::map<std::pair<std::uint32_t, std::uint32_t>, const MachOSymbol *> importer_symbols;
        std::map<std::uint32_t, std::size_t> library_ordinal_counts;
        for (const auto &symbol : importer.symbols)
            importer_symbols.emplace(std::pair{symbol.table_command, symbol.index}, &symbol);
        for (const auto &library : importer.libraries)
            if (library.ordinal) ++library_ordinal_counts[*library.ordinal];
        for (const auto &provider : providers) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Mach-O two-level resolution canceled"};
            const ProviderKey key{provider.library_ordinal, provider.sub_image_index};
            if (!provider_index.emplace(key, &provider).second) ambiguous_providers.insert(key);
        }
        std::vector<MachOTwoLevelResolution> rows;
        rows.reserve(importer.two_level_hints.size());
        for (const auto &hint : importer.two_level_hints) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Mach-O two-level resolution canceled"};
            MachOTwoLevelResolution row;
            row.hint_index = hint.index;
            row.sub_image_index = hint.sub_image_index;
            const auto importer_symbol_at = hint.symbol_index
                ? importer_symbols.find({hint.symbol_table_command.value_or(UINT32_MAX), *hint.symbol_index})
                : importer_symbols.end();
            if (importer_symbol_at == importer_symbols.end() || !importer_symbol_at->second->library_ordinal) {
                row.status = MachOTwoLevelStatus::unassociated_hint;
                rows.push_back(std::move(row));
                continue;
            }
            const auto *importer_symbol = importer_symbol_at->second;
            row.library_ordinal = *importer_symbol->library_ordinal;
            if (!(importer.container.slices[importer.selected_slice].header.flags & 0x80)) {
                row.status = MachOTwoLevelStatus::non_two_level_image;
                rows.push_back(std::move(row));
                continue;
            }
            if (!row.library_ordinal || row.library_ordinal > 253) {
                row.status = MachOTwoLevelStatus::special_library_ordinal;
                rows.push_back(std::move(row));
                continue;
            }
            if (library_ordinal_counts[row.library_ordinal] != 1) {
                row.status = MachOTwoLevelStatus::missing_library_ordinal;
                rows.push_back(std::move(row));
                continue;
            }
            const ProviderKey key{row.library_ordinal, row.sub_image_index};
            const auto provider_at = provider_index.find(key);
            if (provider_at == provider_index.end()) { row.status = MachOTwoLevelStatus::missing_provider; rows.push_back(std::move(row)); continue; }
            if (ambiguous_providers.contains(key)) { row.status = MachOTwoLevelStatus::ambiguous_provider; rows.push_back(std::move(row)); continue; }
            const auto &provider = *provider_at->second;
            row.provider_source = provider.source;
            if (!provider.metadata || provider.source.empty()) {
                row.status = MachOTwoLevelStatus::missing_provider;
                rows.push_back(std::move(row));
                continue;
            }
            const auto &metadata = *provider.metadata;
            if (metadata.dynamic_symbol_tables.size() != 1 || metadata.symbol_tables.size() != 1) {
                row.status = MachOTwoLevelStatus::missing_provider_tables;
                rows.push_back(std::move(row));
                continue;
            }
            const auto &dynamic = metadata.dynamic_symbol_tables.front();
            const auto &symbols = metadata.symbol_tables.front();
            if (hint.table_of_contents_index >= dynamic.toc_entries.size()) {
                row.status = MachOTwoLevelStatus::toc_index_out_of_range;
                rows.push_back(std::move(row));
                continue;
            }
            const auto &toc = dynamic.toc_entries[hint.table_of_contents_index];
            row.provider_symbol_index = toc.symbol_index;
            row.provider_module_index = toc.module_index;
            if (toc.module_index >= dynamic.modules.size()) {
                row.status = MachOTwoLevelStatus::module_index_out_of_range;
                rows.push_back(std::move(row));
                continue;
            }
            if (!dynamic.symbol_table || *dynamic.symbol_table != symbols.command_index || toc.symbol_index >= symbols.count ||
                symbols.first_symbol > metadata.symbols.size() || symbols.count > metadata.symbols.size() - symbols.first_symbol) {
                row.status = MachOTwoLevelStatus::invalid_provider_symbol;
                rows.push_back(std::move(row));
                continue;
            }
            const auto &definition = metadata.symbols[symbols.first_symbol + toc.symbol_index];
            const auto &module = dynamic.modules[toc.module_index];
            if (definition.table_command != symbols.command_index || definition.index != toc.symbol_index ||
                (definition.type & 0xe0) != 0 || !(definition.type & 1) || definition.state != MachOSymbolState::defined ||
                toc.symbol_index < module.external_definition_start ||
                toc.symbol_index - module.external_definition_start >= module.external_definition_count) {
                row.status = MachOTwoLevelStatus::invalid_provider_symbol;
            } else if (definition.name.empty() || definition.name != importer_symbol->name) {
                row.status = MachOTwoLevelStatus::symbol_name_mismatch;
            } else {
                row.status = MachOTwoLevelStatus::resolved;
            }
            rows.push_back(std::move(row));
        }
        return rows;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate Mach-O two-level resolution rows"};
    }
}
} // namespace hexlab
