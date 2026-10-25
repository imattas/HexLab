#include "project_internal.hpp"
#include "hexlab/workspace/macho_presentation.hpp"
#include "hexlab/symbols/demangle.hpp"
#include <charconv>
#include <string_view>
#include <map>
namespace hexlab {
namespace {
using LocationKey = std::tuple<unsigned, uint32_t, uint64_t>;
LocationKey location_key(Location location) {
    if (auto address = std::get_if<Address>(&location))
        return {0, address->space.value, address->offset};
    return {1, 0, std::get<FileOffset>(location).value};
}
bool less(Address a, Address b) { return a.space.value < b.space.value || (a.space == b.space && a.offset < b.offset); }
} // namespace
class ProjectPresentationIndex {
    enum class SymbolSource { pe, elf, macho, macho_export };
    struct AnnotationRef {
        Location location;
        std::size_t row;
    };
    struct ExportRef {
        Address address;
        std::size_t row;
        SymbolSource source = SymbolSource::pe;
    };
    struct NameUse {
        Address address;
        std::string_view name;
        bool multiple = false;
    };
    std::shared_ptr<const database::UserState> user_;
    std::shared_ptr<const LoadedImage> loaded_;
    std::vector<AnnotationRef> annotations_;
    std::vector<ExportRef> exports_;
    std::vector<NameUse> names_;
    std::vector<std::optional<FileOffset>> elf_symbol_records_;
    std::vector<std::uint64_t> elf_dynamic_ends_;
    using EhFrameRowRef = std::pair<std::size_t, std::size_t>;
    std::vector<EhFrameRowRef> eh_frame_call_site_rows_, eh_frame_action_rows_, eh_frame_type_info_rows_;
    std::array<std::uint64_t, static_cast<std::size_t>(MachOMetadataKind::count)> macho_ends_{};
    static auto name_key(const NameUse &value) { return std::pair{value.address.space.value, value.name}; }

  public:
    ProjectPresentationIndex(std::shared_ptr<const database::UserState> user, std::shared_ptr<const LoadedImage> loaded,
                             std::stop_token stop)
        : user_(std::move(user)), loaded_(std::move(loaded)) {
        using namespace project_detail;
        const auto elf_count = loaded_ && loaded_->metadata.elf ? loaded_->metadata.elf->symbols.size() : 0;
        const auto macho_count = loaded_ && loaded_->metadata.macho ? loaded_->metadata.macho->symbols.size() : 0;
        const auto export_count = loaded_ && loaded_->metadata.macho ? loaded_->metadata.macho->dyld_exports.size() : 0;
        require(user_ && user_->annotations.size() <= database::project_record_limit && export_count <= 1000000 &&
                    macho_count <= 1000000 - export_count && elf_count <= 1000000 - macho_count - export_count &&
                    (!loaded_ || loaded_->metadata.exports.size() <= 1000000 - elf_count - macho_count - export_count),
                "Presentation record budget exceeded", ErrorCode::resource_limit);
        annotations_.reserve(user_->annotations.size());
        if (loaded_ && loaded_->metadata.macho) {
            const auto &m = *loaded_->metadata.macho;
            const auto &header = m.container.slices.at(m.selected_slice).header;
            std::uint64_t exception_rows = take(checked_multiply(m.eh_frame_functions.size(), 2));
            for (std::size_t fde_index = 0; fde_index < m.eh_frame_functions.size(); ++fde_index) {
                canceled(stop);
                const auto &fde = m.eh_frame_functions[fde_index];
                exception_rows = take(checked_add(exception_rows, fde.call_sites.size()));
                exception_rows = take(checked_add(exception_rows, fde.actions.size()));
                exception_rows = take(checked_add(exception_rows, fde.type_infos.size()));
                require(exception_rows <= 1000000,
                        "Mach-O exception metadata presentation exceeds one million rows", ErrorCode::resource_limit);
                for (std::size_t item = 0; item < fde.call_sites.size(); ++item)
                    eh_frame_call_site_rows_.emplace_back(fde_index, item);
                for (std::size_t item = 0; item < fde.actions.size(); ++item)
                    eh_frame_action_rows_.emplace_back(fde_index, item);
                for (std::size_t item = 0; item < fde.type_infos.size(); ++item)
                    eh_frame_type_info_rows_.emplace_back(fde_index, item);
            }
            const std::array<std::uint64_t, static_cast<std::size_t>(MachOMetadataKind::count)> counts{
                1,
                m.container.slices.size(),
                header.commands.size(),
                m.segments.size(),
                m.sections.size(),
                m.symbol_tables.size(),
                m.symbols.size(),
                m.libraries.size(),
                m.paths.size(),
                m.entries.size(),
                m.function_starts.size(),
                m.dynamic_symbol_tables.size(),
                m.relocation_tables.size(),
                m.relocations.size(),
                m.dyld_streams.size(),
                m.dyld_operations.size(),
                m.dyld_fixups.size(),
                m.dyld_exports.size(),
                m.chained_headers.size(),
                m.chained_imports.size(),
                m.chained_starts.size(),
                m.chained_pointers.size(),
                m.data_in_code_tables.size(),
                m.data_in_code.size(),
                m.encryption.size(),
                m.code_signatures.size(),
                m.eh_frame_functions.size(),
                m.eh_frame_functions.size(),
                eh_frame_call_site_rows_.size(),
                eh_frame_action_rows_.size(),
                eh_frame_type_info_rows_.size()};
            std::uint64_t end = 0;
            for (std::size_t n = 0; n < counts.size(); ++n) {
                canceled(stop);
                end = take(checked_add(end, counts[n]));
                macho_ends_[n] = end;
            }
        }
        if (loaded_ && loaded_->metadata.elf) {
            const auto &elf = *loaded_->metadata.elf;
            using TableKey =
                std::tuple<std::optional<std::uint32_t>, std::uint64_t, bool, std::uint32_t, std::uint64_t>;
            const auto key = [](auto section, auto offset, const std::optional<Address> &address) -> TableKey {
                return {section, offset, address.has_value(), address ? address->space.value : 0,
                        address ? address->offset : 0};
            };
            std::map<TableKey, const ElfSymbolTable *> tables;
            for (const auto &table : elf.symbol_tables) {
                canceled(stop);
                tables.emplace(key(table.source.section, table.source.file_offset, table.source.address), &table);
            }
            elf_symbol_records_.resize(elf_count);
            for (std::size_t n = 0; n < elf_count; ++n) {
                canceled(stop);
                const auto &symbol = elf.symbols[n];
                const auto found = tables.find(key(symbol.table, symbol.table_offset, symbol.table_address));
                if (found == tables.end() || !found->second->count || symbol.index >= *found->second->count)
                    continue;
                const auto delta = take(checked_multiply(symbol.index, found->second->stride));
                const auto offset = symbol.table_address
                                        ? take(loaded_->image->to_file_offset(
                                                   Address{symbol.table_address->space,
                                                           take(checked_add(symbol.table_address->offset, delta))}))
                                              .value
                                        : take(checked_add(symbol.table_offset, delta));
                if (offset < loaded_->image->storage()->size())
                    elf_symbol_records_[n] = FileOffset{offset};
            }
            std::uint64_t count = 0;
            elf_dynamic_ends_.reserve(elf.dynamic_tables.size());
            for (const auto &table : elf.dynamic_tables) {
                canceled(stop);
                count = take(checked_add(count, table.entries.size()));
                elf_dynamic_ends_.push_back(count);
            }
        }
        names_.reserve(user_->annotations.size() +
                       (loaded_ ? loaded_->metadata.exports.size() + elf_count + macho_count + export_count : 0));
        for (std::size_t n = 0; n < user_->annotations.size(); ++n) {
            canceled(stop);
            auto &row = user_->annotations[n];
            annotations_.push_back({row.location, n});
            if (auto address = std::get_if<Address>(&row.location); address && !row.name.empty())
                names_.push_back({*address, row.name, false});
        }
        if (loaded_) {
            exports_.reserve(loaded_->metadata.exports.size() + elf_count + macho_count + export_count);
            for (std::size_t n = 0; n < loaded_->metadata.exports.size(); ++n) {
                canceled(stop);
                auto &row = loaded_->metadata.exports[n];
                if (row.address && row.name && !row.name->empty()) {
                    exports_.push_back({*row.address, n});
                    names_.push_back({*row.address, *row.name, false});
                }
            }
            if (loaded_->metadata.elf)
                for (std::size_t n = 0; n < elf_count; ++n) {
                    canceled(stop);
                    const auto &row = loaded_->metadata.elf->symbols[n];
                    if (row.address && !row.name.empty()) {
                        exports_.push_back({*row.address, n, SymbolSource::elf});
                        names_.push_back({*row.address, row.name, false});
                    }
                }
            if (loaded_->metadata.macho) {
                for (std::size_t n = 0; n < macho_count; ++n) {
                    canceled(stop);
                    const auto &row = loaded_->metadata.macho->symbols[n];
                    if (row.address && !row.name.empty()) {
                        exports_.push_back({*row.address, n, SymbolSource::macho});
                        names_.push_back({*row.address, row.name, false});
                    }
                }
                for (std::size_t n = 0; n < export_count; ++n) {
                    canceled(stop);
                    const auto &row = loaded_->metadata.macho->dyld_exports[n];
                    if (row.is_definition() && !row.name.empty()) {
                        exports_.push_back({*row.address, n, SymbolSource::macho_export});
                        names_.push_back({*row.address, row.name, false});
                    }
                }
            }
        }
        std::sort(annotations_.begin(), annotations_.end(),
                  [](auto &a, auto &b) { return location_key(a.location) < location_key(b.location); });
        std::sort(exports_.begin(), exports_.end(), [](auto &a, auto &b) {
            if (a.address != b.address)
                return less(a.address, b.address);
            if (a.source != b.source)
                return a.source < b.source;
            return a.row < b.row;
        });
        std::sort(names_.begin(), names_.end(), [](auto &a, auto &b) {
            if (name_key(a) != name_key(b))
                return name_key(a) < name_key(b);
            return a.address.offset < b.address.offset;
        });
        std::size_t used = 0;
        for (std::size_t n = 0; n < names_.size(); ++n) {
            canceled(stop);
            if (used && name_key(names_[used - 1]) == name_key(names_[n])) {
                if (names_[used - 1].address != names_[n].address)
                    names_[used - 1].multiple = true;
            } else
                names_[used++] = names_[n];
        }
        names_.resize(used);
        canceled(stop);
    }
    std::optional<FileOffset> symbol_record(std::size_t row) const noexcept {
        return row < elf_symbol_records_.size() ? elf_symbol_records_[row] : std::nullopt;
    }
    std::uint64_t macho_count() const noexcept { return macho_ends_.back(); }
    std::optional<MachOMetadataRow> macho_row(std::uint64_t row) const noexcept {
        if (row >= macho_count())
            return {};
        const auto found = std::upper_bound(macho_ends_.begin(), macho_ends_.end(), row);
        const auto group = static_cast<std::size_t>(found - macho_ends_.begin());
        const auto index = row - (group ? macho_ends_[group - 1] : 0);
        const auto kind = static_cast<MachOMetadataKind>(group);
        const auto &m = *loaded_->metadata.macho;
        const auto &slice = m.container.slices[m.selected_slice];
        std::uint64_t source = 0;
        std::uint64_t owner_index = 0, item_index = 0;
        switch (kind) {
        case MachOMetadataKind::header:
            source = slice.offset;
            break;
        case MachOMetadataKind::slice:
            source = m.container.slices[index].offset;
            break;
        case MachOMetadataKind::command:
            source = slice.header.commands[index].file_offset;
            break;
        case MachOMetadataKind::segment:
            source = slice.header.commands[m.segments[index].command_index].file_offset;
            break;
        case MachOMetadataKind::section:
            source = m.sections[index].record_file_offset;
            break;
        case MachOMetadataKind::symbol_table:
            source = m.symbol_tables[index].symbol_offset.value;
            break;
        case MachOMetadataKind::symbol:
            source = m.symbols[index].record_file_offset;
            break;
        case MachOMetadataKind::library:
            source = m.libraries[index].record_file_offset;
            break;
        case MachOMetadataKind::path:
            source = m.paths[index].record_file_offset;
            break;
        case MachOMetadataKind::entry:
            source = m.entries[index].record_file_offset;
            break;
        case MachOMetadataKind::function_start:
            source = m.function_starts[index].record_file_offset;
            break;
        case MachOMetadataKind::dynamic_symbols:
            source = m.dynamic_symbol_tables[index].record_file_offset;
            break;
        case MachOMetadataKind::relocation_table:
            source = m.relocation_tables[index].offset.value;
            break;
        case MachOMetadataKind::relocation:
            source = m.relocations[index].record_file_offset;
            break;
        case MachOMetadataKind::dyld_stream:
            source = m.dyld_streams[index].offset.value;
            break;
        case MachOMetadataKind::dyld_operation:
            source = m.dyld_operations[index].record_file_offset;
            break;
        case MachOMetadataKind::dyld_fixup:
            source = m.dyld_fixups[index].record_file_offset;
            break;
        case MachOMetadataKind::dyld_export:
            source = m.dyld_exports[index].record_file_offset;
            break;
        case MachOMetadataKind::chain_header:
            source = m.chained_headers[index].record_file_offset;
            break;
        case MachOMetadataKind::chain_import:
            source = m.chained_imports[index].record_file_offset;
            break;
        case MachOMetadataKind::chain_start:
            source = m.chained_starts[index].record_file_offset;
            break;
        case MachOMetadataKind::chain_pointer:
            source = m.chained_pointers[index].file_place
                         ? m.chained_pointers[index].file_place->value
                         : m.chained_starts[m.chained_pointers[index].starts].record_file_offset;
            break;
        case MachOMetadataKind::data_in_code_table:
            source = m.data_in_code_tables[index].offset.value;
            break;
        case MachOMetadataKind::data_in_code:
            source = m.data_in_code[index].record_file_offset;
            break;
        case MachOMetadataKind::encryption:
            source = m.encryption[index].record_file_offset;
            break;
        case MachOMetadataKind::signature:
            source = m.code_signatures[index].offset.value;
            break;
        case MachOMetadataKind::eh_frame_function:
            if (index >= m.eh_frame_functions.size()) return {};
            source = m.eh_frame_functions[index].record_file_offset;
            owner_index = index;
            break;
        case MachOMetadataKind::eh_frame_personality: {
            if (index >= m.eh_frame_functions.size()) return {};
            const auto &fde = m.eh_frame_functions[index];
            source = fde.personality_source ? fde.personality_source->value : fde.record_file_offset;
            if (source >= loaded_->image->storage()->size()) return {};
            if (fde.personality_source_size > loaded_->image->storage()->size() - source) return {};
            owner_index = index;
            break;
        }
        case MachOMetadataKind::eh_frame_call_site: {
            if (index >= eh_frame_call_site_rows_.size()) return {};
            const auto [fde_index, item] = eh_frame_call_site_rows_[index];
            if (fde_index >= m.eh_frame_functions.size()) return {};
            const auto &fde = m.eh_frame_functions[fde_index];
            if (!fde.lsda_file_offset || item >= fde.call_sites.size()) return {};
            const auto &entry = fde.call_sites[item];
            if (*fde.lsda_file_offset > UINT64_MAX - slice.offset) return {};
            source = slice.offset + *fde.lsda_file_offset;
            if (entry.record_offset > UINT64_MAX - source) return {};
            source += entry.record_offset;
            if (source > loaded_->image->storage()->size() ||
                entry.encoded_size > loaded_->image->storage()->size() - source) return {};
            owner_index = fde_index;
            item_index = item;
            break;
        }
        case MachOMetadataKind::eh_frame_action: {
            if (index >= eh_frame_action_rows_.size()) return {};
            const auto [fde_index, item] = eh_frame_action_rows_[index];
            if (fde_index >= m.eh_frame_functions.size()) return {};
            const auto &fde = m.eh_frame_functions[fde_index];
            if (!fde.lsda_file_offset || item >= fde.actions.size()) return {};
            const auto &entry = fde.actions[item];
            if (*fde.lsda_file_offset > UINT64_MAX - slice.offset) return {};
            source = slice.offset + *fde.lsda_file_offset;
            if (entry.record_offset > UINT64_MAX - source) return {};
            source += entry.record_offset;
            if (source > loaded_->image->storage()->size() ||
                entry.encoded_size > loaded_->image->storage()->size() - source) return {};
            owner_index = fde_index;
            item_index = item;
            break;
        }
        case MachOMetadataKind::eh_frame_type_info: {
            if (index >= eh_frame_type_info_rows_.size()) return {};
            const auto [fde_index, item] = eh_frame_type_info_rows_[index];
            if (fde_index >= m.eh_frame_functions.size()) return {};
            const auto &fde = m.eh_frame_functions[fde_index];
            if (!fde.lsda_file_offset || item >= fde.type_infos.size()) return {};
            const auto &entry = fde.type_infos[item];
            if (*fde.lsda_file_offset > UINT64_MAX - slice.offset) return {};
            source = slice.offset + *fde.lsda_file_offset;
            if (entry.record_offset > UINT64_MAX - source) return {};
            source += entry.record_offset;
            if (source > loaded_->image->storage()->size() ||
                entry.encoded_size > loaded_->image->storage()->size() - source) return {};
            owner_index = fde_index;
            item_index = item;
            break;
        }
        case MachOMetadataKind::count:
            return {};
        }
        if (source >= loaded_->image->storage()->size()) return {};
        return MachOMetadataRow{kind, index, FileOffset{source}, owner_index, item_index};
    }
    std::uint64_t dynamic_count() const noexcept { return elf_dynamic_ends_.empty() ? 0 : elf_dynamic_ends_.back(); }
    std::optional<ElfDynamicRow> dynamic_row(std::uint64_t row) const noexcept {
        if (row >= dynamic_count())
            return {};
        const auto found = std::upper_bound(elf_dynamic_ends_.begin(), elf_dynamic_ends_.end(), row);
        const auto index = static_cast<std::size_t>(found - elf_dynamic_ends_.begin());
        const auto &table = loaded_->metadata.elf->dynamic_tables[index];
        return ElfDynamicRow{
            &table, &table.entries[static_cast<std::size_t>(row - (index ? elf_dynamic_ends_[index - 1] : 0))]};
    }
    const database::Annotation *annotation(Location location) const noexcept {
        auto key = location_key(location);
        auto found = std::lower_bound(annotations_.begin(), annotations_.end(), key,
                                      [](auto &row, auto at) { return location_key(row.location) < at; });
        return found != annotations_.end() && found->location == location ? &user_->annotations[found->row] : nullptr;
    }
    std::string_view symbol(Address address) const {
        auto found = std::lower_bound(exports_.begin(), exports_.end(), address,
                                      [](auto &row, auto at) { return less(row.address, at); });
        if (found == exports_.end() || found->address != address)
            return {};
        switch (found->source) {
        case SymbolSource::pe:
            return *loaded_->metadata.exports[found->row].name;
        case SymbolSource::elf:
            return loaded_->metadata.elf->symbols[found->row].name;
        case SymbolSource::macho:
            return loaded_->metadata.macho->symbols[found->row].name;
        case SymbolSource::macho_export:
            return loaded_->metadata.macho->dyld_exports[found->row].name;
        }
        return {};
    }
    bool occupied(Address address, std::string_view name) const {
        auto key = std::pair{address.space.value, name};
        auto found =
            std::lower_bound(names_.begin(), names_.end(), key, [](auto &row, auto at) { return name_key(row) < at; });
        return found != names_.end() && name_key(*found) == key && (found->multiple || found->address != address);
    }
};
namespace project_detail {
std::shared_ptr<const ProjectPresentationIndex> make_presentation_index(std::shared_ptr<const database::UserState> user,
                                                                        std::shared_ptr<const LoadedImage> loaded,
                                                                        std::stop_token stop) {
    return std::make_shared<const ProjectPresentationIndex>(std::move(user), std::move(loaded), stop);
}
} // namespace project_detail
std::optional<FileOffset> elf_symbol_record_at(const ProjectSnapshot &snapshot, std::size_t row) noexcept {
    return snapshot.presentation ? snapshot.presentation->symbol_record(row) : std::nullopt;
}
std::uint64_t macho_metadata_row_count(const ProjectSnapshot &snapshot) noexcept {
    return snapshot.presentation ? snapshot.presentation->macho_count() : 0;
}
std::optional<MachOMetadataRow> macho_metadata_row_at(const ProjectSnapshot &snapshot, std::uint64_t row) noexcept {
    return snapshot.presentation ? snapshot.presentation->macho_row(row) : std::nullopt;
}
Result<MachOMetadataPage> make_macho_metadata_page(const ProjectSnapshot &snapshot, std::uint64_t begin,
                                                   std::size_t count, std::stop_token stop) {
    return project_detail::guarded([&]() -> Result<MachOMetadataPage> {
        project_detail::canceled(stop);
        const auto total = macho_metadata_row_count(snapshot);
        project_detail::require(count <= 256 && begin <= total, "Invalid Mach-O metadata page");
        MachOMetadataPage result{begin, total, {}};
        const auto size = std::min<std::uint64_t>(count, total - begin);
        result.rows.reserve(static_cast<std::size_t>(size));
        for (std::uint64_t n = 0; n < size; ++n) {
            project_detail::canceled(stop);
            result.rows.push_back(*macho_metadata_row_at(snapshot, begin + n));
        }
        return result;
    });
}
std::uint64_t elf_dynamic_row_count(const ProjectSnapshot &snapshot) noexcept {
    return snapshot.presentation ? snapshot.presentation->dynamic_count() : 0;
}
std::optional<ElfDynamicRow> elf_dynamic_row_at(const ProjectSnapshot &snapshot, std::uint64_t row) noexcept {
    return snapshot.presentation ? snapshot.presentation->dynamic_row(row) : std::nullopt;
}
const database::Annotation *annotation_at(const ProjectSnapshot &snapshot, Location location) noexcept {
    if (snapshot.presentation)
        return snapshot.presentation->annotation(location);
    if (snapshot.state && snapshot.state->user)
        for (auto &row : snapshot.state->user->annotations)
            if (row.location == location)
                return &row;
    return nullptr;
}
std::string presentation_name(const ProjectSnapshot &snapshot, Location location) {
    if (auto annotation = annotation_at(snapshot, location); annotation && !annotation->name.empty())
        return annotation->name;
    std::string name;
    auto address = std::get_if<Address>(&location);
    if (address) {
        if (snapshot.presentation)
            name = snapshot.presentation->symbol(*address);
        else if (snapshot.loaded) {
            for (auto &symbol : snapshot.loaded->metadata.exports)
                if (symbol.address == *address && symbol.name && !symbol.name->empty()) {
                    name = *symbol.name;
                    break;
                }
            if (name.empty() && snapshot.loaded->metadata.elf)
                for (const auto &symbol : snapshot.loaded->metadata.elf->symbols)
                    if (symbol.address == *address && !symbol.name.empty()) {
                        name = symbol.name;
                        break;
                    }
            if (name.empty() && snapshot.loaded->metadata.macho) {
                for (const auto &symbol : snapshot.loaded->metadata.macho->symbols)
                    if (symbol.address == *address && !symbol.name.empty()) {
                        name = symbol.name;
                        break;
                    }
                if (name.empty())
                    for (const auto &symbol : snapshot.loaded->metadata.macho->dyld_exports)
                        if (symbol.is_definition() && symbol.address == *address && !symbol.name.empty()) {
                            name = symbol.name;
                            break;
                        }
            }
        }
    }
    std::array<char, 16> digits{};
    auto offset = address ? address->offset : std::get<FileOffset>(location).value;
    auto end = std::to_chars(digits.data(), digits.data() + digits.size(), offset, 16).ptr;
    std::string suffix(digits.data(), end);
    if (name.empty())
        name = address ? "sub_" + std::to_string(address->space.value) + "_" + suffix : "file_" + suffix;
    auto occupied = [&](std::string_view candidate) {
        if (!address)
            return false;
        if (snapshot.presentation)
            return snapshot.presentation->occupied(*address, candidate);
        if (snapshot.state && snapshot.state->user)
            for (auto &row : snapshot.state->user->annotations)
                if (row.location != location && row.name == candidate)
                    if (auto other = std::get_if<Address>(&row.location); other && other->space == address->space)
                        return true;
        if (snapshot.loaded) {
            for (auto &row : snapshot.loaded->metadata.exports)
                if (row.address && *row.address != *address && row.address->space == address->space && row.name &&
                    *row.name == candidate)
                    return true;
            if (snapshot.loaded->metadata.elf)
                for (const auto &row : snapshot.loaded->metadata.elf->symbols)
                    if (row.address && *row.address != *address && row.address->space == address->space &&
                        row.name == candidate)
                        return true;
            if (snapshot.loaded->metadata.macho) {
                for (const auto &row : snapshot.loaded->metadata.macho->symbols)
                    if (row.address && *row.address != *address && row.address->space == address->space &&
                        row.name == candidate)
                        return true;
                for (const auto &row : snapshot.loaded->metadata.macho->dyld_exports)
                    if (row.is_definition() && *row.address != *address && row.address->space == address->space &&
                        row.name == candidate)
                        return true;
            }
        }
        return false;
    };
    if (occupied(name)) {
        name += "_" + std::to_string(address->space.value) + "_" + suffix;
        while (occupied(name))
            name += "_";
    }
    auto rendered = hexlab::symbols::demangle_cpp_name(name);
    return rendered.status == hexlab::symbols::DemangleStatus::demangled ? rendered.text : name;
}
LocationPresentation presentation_at(const ProjectSnapshot &snapshot, Location location) {
    LocationPresentation result;
    result.orphaned = !project_detail::mapped_location(snapshot, location);
    if (auto row = annotation_at(snapshot, location)) {
        result.comment = row->comment;
        result.user_name = !row->name.empty();
    }
    result.name = presentation_name(snapshot, location);
    return result;
}
std::vector<SymbolCandidate> importable_symbols(const ProjectSnapshot& snapshot) {
    std::vector<SymbolCandidate> rows;
    if(!snapshot.loaded||!snapshot.loaded->image)return rows;
    const auto add=[&](std::optional<Address> address,std::string_view name){if(address&&!name.empty()&&snapshot.loaded->image->segment_at(*address))rows.push_back({*address,std::string(name)});};
    for(const auto& row:snapshot.loaded->metadata.exports)if(row.name)add(row.address,*row.name);
    if(snapshot.loaded->metadata.elf)for(const auto& row:snapshot.loaded->metadata.elf->symbols)add(row.address,row.name);
    if(snapshot.loaded->metadata.macho){for(const auto& row:snapshot.loaded->metadata.macho->symbols)add(row.address,row.name);for(const auto& row:snapshot.loaded->metadata.macho->dyld_exports)if(row.is_definition())add(row.address,row.name);}
    std::sort(rows.begin(),rows.end(),[](const auto& a,const auto& b){return std::tie(a.address.space.value,a.address.offset,a.name)<std::tie(b.address.space.value,b.address.offset,b.name);});
    rows.erase(std::unique(rows.begin(),rows.end(),[](const auto& a,const auto& b){return a.address==b.address;}),rows.end());
    return rows;
}
const database::TypeDefinition* type_definition(const ProjectSnapshot& snapshot,std::uint64_t id) noexcept {
    if(!snapshot.state||!snapshot.state->user)return nullptr;
    for(const auto& row:snapshot.state->user->types)if(row.id==id)return &row;
    return nullptr;
}
Result<types::TypeLayout> calculate_type_layout(const ProjectSnapshot &snapshot, std::uint64_t type_id,
                                                types::Abi abi, types::LayoutOptions options) {
    const auto *definition = type_definition(snapshot, type_id);
    if (!definition || !definition->type)
        return Error{ErrorCode::invalid_argument, "project type definition is unavailable"};
    const auto state = snapshot.state;
    options.resolve_named_type = [state](std::string_view name) -> Result<types::TypePtr> {
        if (!state || !state->user)
            return Error{ErrorCode::unsupported, "project type definitions are unavailable"};
        const database::TypeDefinition *match = nullptr;
        for (const auto &candidate : state->user->types) {
            if (candidate.name != name) continue;
            if (match)
                return Error{ErrorCode::conflict, "named type reference is ambiguous: " + std::string(name)};
            match = &candidate;
        }
        if (!match || !match->type)
            return Error{ErrorCode::unsupported, "named type definition is unavailable: " + std::string(name)};
        return match->type;
    };
    return types::layout(*definition->type, abi, std::move(options));
}
const database::TypeAssignment* type_assignment(const ProjectSnapshot& snapshot,Address address) noexcept {
    if(!snapshot.state||!snapshot.state->user)return nullptr;
    for(const auto& row:snapshot.state->user->type_assignments)if(row.location==Location{address})return &row;
    return nullptr;
}
} // namespace hexlab
