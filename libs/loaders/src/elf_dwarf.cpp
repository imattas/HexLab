#include "elf_internal.hpp"
#include "hexlab/symbols/dwarf.hpp"
#include <algorithm>
#include <iterator>
#include <map>
#include <mutex>
#include <set>
#include <unordered_set>

namespace hexlab::elf_detail {
namespace {
symbols::DwarfSupplementaryIdentity read_supplementary_identity(std::span<const std::uint8_t> bytes) {
    require(bytes.size() >= 5, "truncated DWARF .debug_sup header");
    const auto version = std::uint16_t(bytes[0] | (std::uint16_t(bytes[1]) << 8));
    require(version == 5, "unsupported DWARF .debug_sup version", ErrorCode::unsupported);
    const auto flag = bytes[2];
    require(flag <= 1, "invalid .debug_sup is_supplementary flag");
    std::size_t pos = 3;
    const auto name_begin = pos;
    while (pos < bytes.size() && bytes[pos]) ++pos;
    require(pos < bytes.size(), "unterminated .debug_sup filename");
    std::string filename(reinterpret_cast<const char *>(bytes.data() + name_begin), pos - name_begin);
    ++pos;
    // The checksum length is a bounded ULEB128 following the filename.
    std::uint64_t length = 0; unsigned shift = 0; bool terminated = false;
    for (unsigned i = 0; i < 10 && pos < bytes.size(); ++i) {
        const auto b = bytes[pos++];
        if (shift == 63 && (b & 0x7e)) throw Failure{{ErrorCode::malformed, "overflowing .debug_sup checksum length"}};
        length |= std::uint64_t(b & 0x7f) << shift;
        if (!(b & 0x80)) { terminated = true; break; }
        shift += 7;
    }
    require(terminated, "truncated .debug_sup checksum length");
    require(length <= 64 && length == bytes.size() - pos, "invalid .debug_sup checksum extent");
    require(flag != 1 || filename.empty(), "supplementary .debug_sup object must have an empty filename");
    symbols::DwarfSupplementaryIdentity result; result.present = true; result.version = version; result.supplementary = flag != 0;
    result.filename = std::move(filename); result.checksum.assign(bytes.begin() + static_cast<std::ptrdiff_t>(pos), bytes.end());
    return result;
}
const ElfSection *debug_section(const ElfMetadata &metadata, std::string_view name) {
    const ElfSection *found = nullptr;
    for (const auto &section : metadata.sections) {
        const bool canonical = section.name == name;
        const bool gnu_alias = name.starts_with(".debug_") &&
            section.name.size() == name.size() + 1 && section.name.starts_with(".zdebug_") &&
            section.name.substr(2) == name.substr(1);
        if (!canonical && !gnu_alias) continue;
        require(found == nullptr, "ELF contains duplicate DWARF section declarations");
        found = &section;
    }
    return found;
}
const ElfSection *optional_debug_section(const ElfMetadata &metadata, std::string_view a,
                                          std::string_view b = {}) {
    const auto *first = debug_section(metadata, a);
    const auto *second = b.empty() ? nullptr : debug_section(metadata, b);
    require(!(first && second), "ELF contains duplicate DWARF package section aliases");
    return first ? first : second;
}
std::vector<std::uint8_t> read_debug_bytes(const ByteStorage &storage, const ElfMetadata &metadata,
                                          const ElfSection &section, Budget &budget, std::stop_token stop) {
    return read_debug_section_bytes(storage, metadata, section, budget, stop);
}

struct DwarfPackage {
    std::shared_ptr<const symbols::DwarfPackageIndex> index;
    std::shared_ptr<const symbols::DwarfPackageIndex> type_index;
    std::map<std::uint32_t, std::vector<std::uint8_t>> sections;
    std::vector<std::uint8_t> strings, line_strings;
    std::vector<std::uint64_t> type_signatures;
};
struct DwarfPackageResolvers {
    symbols::DwarfSupplementaryTypeResolver supplementary;
    symbols::DwarfTypeSignatureResolver type_signature;
    std::shared_ptr<const DwarfPackage> type_package;
};

// Charge the decoded tables before the parser allocates them. The public
// parser still validates hash slots, row mappings, and all on-disk extents.
std::shared_ptr<const symbols::DwarfPackageIndex> read_package_index(
    const ByteStorage &storage, const ElfMetadata &metadata, const ElfSection &section,
    symbols::DwarfPackageIndexKind kind, Budget &budget, std::stop_token stop) {
    const auto bytes = read_debug_bytes(storage, metadata, section, budget, stop);
    require(bytes.size() >= 16, "truncated DWARF package index header");
    const auto word = [&](std::size_t offset) {
        std::uint32_t value = 0;
        for (unsigned i = 0; i < 4; ++i) {
            const auto shift = metadata.header.order == ByteOrder::little ? i : 3 - i;
            value |= std::uint32_t(bytes[offset + i]) << (8 * shift);
        }
        return value;
    };
    const auto columns = word(4), units = word(8), slots = word(12);
    symbols::DwarfPackageIndexLimits limits;
    require(columns <= limits.max_columns && units <= limits.max_units && slots <= limits.max_slots,
            "DWARF package index dimensions exceed configured limits", ErrorCode::resource_limit);
    // Dimension limits above keep these products representable in uint64_t.
    budget.include(std::uint64_t(units) * sizeof(symbols::DwarfPackageIndexRow));
    budget.include(std::uint64_t(units) * columns * sizeof(symbols::DwarfPackageSectionContribution));
    budget.include(std::uint64_t(columns) * sizeof(std::uint32_t));
    budget.include(std::uint64_t(slots) * (sizeof(std::uint32_t) + sizeof(std::uint64_t)));
    limits.max_index_bytes = bytes.size();
    limits.max_columns = columns;
    limits.max_units = units;
    limits.max_slots = slots;
    auto parsed = symbols::parse_dwarf_package_index(bytes, kind,
        metadata.header.order == ByteOrder::little, stop, limits);
    if (!parsed) throw Failure{parsed.error()};
    return std::make_shared<symbols::DwarfPackageIndex>(std::move(parsed.value()));
}

struct DwarfEmbeddedPackageResolvers {
    symbols::DwarfSplitUnitResolver split;
    symbols::DwarfTypeSignatureResolver type_signature;
    std::shared_ptr<const DwarfPackage> package;
};

symbols::DwarfTypeSignatureResolver make_cross_package_type_signature_resolver(
    const std::vector<std::pair<std::string, std::shared_ptr<const DwarfPackage>>> &sources,
    Budget &budget, std::stop_token stop) {
    std::vector<symbols::DwarfTypeUnitPackage> catalog;
    std::unordered_set<std::uint64_t> signatures;
    std::vector<std::shared_ptr<const DwarfPackage>> owners;
    for (const auto &[source_id, package] : sources) {
        if (!package) continue;
        const auto index = package->type_index ? package->type_index : package->index;
        if (!index || index->kind != symbols::DwarfPackageIndexKind::type_units) continue;
        // A duplicate signature across independently selected packages is
        // ambiguous here. Keep the loader's established selected/embedded/
        // supplementary precedence resolver for that case instead of
        // weakening the catalog's exact-identity rule.
        for (const auto &row : index->rows) {
            canceled(stop);
            if (!signatures.insert(row.signature).second) return {};
        }
        budget.include(index->rows.size() * 64u + package->sections.size() * sizeof(symbols::DwarfPackageSectionData));
        symbols::DwarfTypeUnitPackage item;
        item.source_id = source_id;
        item.index = index;
        item.strings = package->strings;
        item.line_strings = package->line_strings;
        item.identity_verified = true; // Explicitly selected or embedded in the input ELF.
        item.sections.reserve(package->sections.size());
        for (const auto &[id, bytes] : package->sections) item.sections.push_back({id, bytes});
        catalog.push_back(std::move(item));
        owners.push_back(package);
    }
    if (catalog.size() < 2) return {};
    auto resolver = symbols::make_dwarf_package_catalog_type_signature_resolver(
        std::move(catalog), stop, {budget.limit - budget.used, 4096});
    return [resolver = std::move(resolver), owners = std::move(owners)](std::uint64_t signature) {
        // The spans in catalog entries borrow package section storage.
        (void)owners;
        return resolver(signature);
    };
}

DwarfEmbeddedPackageResolvers read_dwp_resolvers(const ByteStorage &storage, const ElfMetadata &metadata,
                                                 Budget &budget, std::stop_token stop,
                                                 bool include_compile_units) {
    const auto *index_section = include_compile_units
        ? optional_debug_section(metadata, ".debug_cu_index", ".debug_cu_index.dwo") : nullptr;
    const auto *type_index_section = optional_debug_section(metadata, ".debug_tu_index", ".debug_tu_index.dwo");
    const bool has_compile_units = index_section && index_section->size;
    const bool has_type_units = type_index_section && type_index_section->size;
    if (!has_compile_units && !has_type_units) return {};
    auto package = std::make_shared<DwarfPackage>();
    if (has_compile_units)
        package->index = read_package_index(storage, metadata, *index_section,
            symbols::DwarfPackageIndexKind::compile_units, budget, stop);
    if (has_type_units) {
        package->type_index = read_package_index(storage, metadata, *type_index_section,
            symbols::DwarfPackageIndexKind::type_units, budget, stop);
        budget.include(package->type_index->rows.size() * sizeof(std::uint64_t));
        package->type_signatures.reserve(package->type_index->rows.size());
        for (const auto &row : package->type_index->rows) {
            canceled(stop);
            package->type_signatures.push_back(row.signature);
        }
        std::sort(package->type_signatures.begin(), package->type_signatures.end());
    }

    if (package->index && package->type_index && package->index->version != package->type_index->version)
        throw Failure{{ErrorCode::unsupported, "DWARF CU and TU package indexes use different versions"}};

    const auto package_version = package->index ? package->index->version : package->type_index->version;
    const std::vector<std::pair<std::uint32_t, std::string_view>> names = package_version == 2
        ? std::vector<std::pair<std::uint32_t, std::string_view>>{
            {1, ".debug_info.dwo"}, {2, ".debug_types.dwo"}, {3, ".debug_abbrev.dwo"},
            {4, ".debug_line.dwo"}, {5, ".debug_loc.dwo"}, {6, ".debug_str_offsets.dwo"},
            {7, ".debug_macinfo.dwo"}, {8, ".debug_macro.dwo"}}
        : std::vector<std::pair<std::uint32_t, std::string_view>>{
            {1, ".debug_info.dwo"}, {3, ".debug_abbrev.dwo"}, {4, ".debug_line.dwo"},
            {5, ".debug_loclists.dwo"}, {6, ".debug_str_offsets.dwo"}, {7, ".debug_macro.dwo"},
            {8, ".debug_rnglists.dwo"}, {9, ".debug_addr.dwo"}};
    for (const auto &[id, name] : names) {
        canceled(stop);
        if (!has_compile_units && id != 1 && id != 2 && id != 3 && id != 4 && id != 6) continue;
        if (const auto *section = debug_section(metadata, name); section && section->size)
            package->sections.emplace(id, read_debug_bytes(storage, metadata, *section, budget, stop));
    }
    if (const auto *strings = optional_debug_section(metadata, ".debug_str.dwo")) {
        if (strings->size) package->strings = read_debug_bytes(storage, metadata, *strings, budget, stop);
    }
    if (const auto *strings = optional_debug_section(metadata, ".debug_line_str.dwo")) {
        if (strings->size) package->line_strings = read_debug_bytes(storage, metadata, *strings, budget, stop);
    }

    DwarfEmbeddedPackageResolvers result;
    result.package = package;
    // Construct this once, outside the split-CU callback. Its cache, active
    // signatures, and request/byte limits cover every use in this ELF import.
    if (package->type_index) {
        std::vector<symbols::DwarfPackageSectionData> source_sections;
        source_sections.reserve(package->sections.size());
        for (const auto &[id, bytes] : package->sections) source_sections.push_back({id, bytes});
        auto resolver = symbols::make_dwarf_package_type_signature_resolver(
            package->type_index, std::move(source_sections), package->strings, package->line_strings, stop,
            {budget.limit - budget.used, 4096});
        result.type_signature = [package, resolver = std::move(resolver)](std::uint64_t signature) {
            return resolver(signature);
        };
    }
    if (!package->index) return result;
    const auto address_size = static_cast<std::uint8_t>(metadata.header.is_64 ? 8 : 4);
    const auto little_endian = metadata.header.order == ByteOrder::little;
    result.split = [package = std::move(package), type_signature = result.type_signature,
                    stop, address_size, little_endian](const symbols::DwarfSplitUnitRequest &request)
               -> Result<std::shared_ptr<symbols::ImportResult>> {
        std::vector<symbols::DwarfPackageSectionData> source_sections;
        source_sections.reserve(package->sections.size());
        for (const auto &[id, bytes] : package->sections)
            source_sections.push_back({id, bytes});
        auto imported = symbols::import_dwarf_package_unit(*package->index, request.dwo_id, source_sections,
                                                            package->strings, stop, package->line_strings,
                                                            address_size, little_endian,
                                                            type_signature);
        if (!imported) return imported.error();
        return std::make_shared<symbols::ImportResult>(std::move(imported.value()));
    };
    return result;
}

DwarfEmbeddedPackageResolvers read_selected_dwp_resolvers(
    const ByteStorage &storage, const ElfMetadata &application_metadata, Budget &budget,
    std::stop_token stop, bool include_compile_units) {
    ElfMetadata package_metadata;
    package_metadata.header = take(read_elf_header(storage, stop));
    require(package_metadata.header.object_type == 1,
            "Selected DWARF split package is not an ELF relocatable object", ErrorCode::unsupported);
    require(package_metadata.header.is_64 == application_metadata.header.is_64 &&
                package_metadata.header.order == application_metadata.header.order,
            "Selected DWARF split package class or byte order differs from the application ELF");
    read_tables(storage, package_metadata, budget, stop);
    auto resolvers = read_dwp_resolvers(storage, package_metadata, budget, stop, include_compile_units);
    require(!include_compile_units || static_cast<bool>(resolvers.split),
            "Selected DWARF split package has no compile-unit index", ErrorCode::unsupported);
    return resolvers;
}

DwarfPackageResolvers read_dwp_supplementary_resolver(
    std::shared_ptr<const ByteStorage> storage, const symbols::DwarfSupplementaryIdentity &application_identity,
    bool application_is_64, ByteOrder application_order, std::uint64_t max_bytes,
    std::uint32_t max_requests, std::stop_token stop) {
    if (!storage) return {};
    require(application_identity.present && !application_identity.supplementary &&
                !application_identity.checksum.empty(),
            "DWP supplementary package requires an application .debug_sup checksum", ErrorCode::unsupported);
    auto tracking = take(TrackingStorage::create(storage));
    ElfMetadata metadata;
    metadata.header = take(read_elf_header(*tracking, stop));
    require(metadata.header.is_64 == application_is_64 && metadata.header.order == application_order,
            "DWP supplementary package class or byte order differs from the application ELF");
    Budget budget;
    budget.limit = std::min(max_bytes, metadata_limit);
    read_tables(*tracking, metadata, budget, stop);
    const auto *sup = debug_section(metadata, ".debug_sup");
    require(sup && sup->size, "DWP supplementary package has no .debug_sup descriptor", ErrorCode::unsupported);
    const auto sup_bytes = read_debug_bytes(*tracking, metadata, *sup, budget, stop);
    const auto package_identity = read_supplementary_identity(sup_bytes);
    require(package_identity.supplementary && package_identity.checksum == application_identity.checksum,
            "DWP package identity/checksum does not match the application .debug_sup descriptor");
    const auto *index_section = debug_section(metadata, ".debug_tu_index");
    require(index_section && index_section->size, "DWP supplementary package has no .debug_tu_index", ErrorCode::unsupported);
    auto package = std::make_shared<DwarfPackage>();
    package->index = read_package_index(*tracking, metadata, *index_section,
        symbols::DwarfPackageIndexKind::type_units, budget, stop);
    constexpr std::pair<std::uint32_t, std::string_view> names[] = {
        {1, ".debug_info.dwo"}, {3, ".debug_abbrev.dwo"}, {4, ".debug_line.dwo"},
        {6, ".debug_str_offsets.dwo"},
    };
    for (const auto &[id, name] : names) {
        canceled(stop);
        const auto *section = debug_section(metadata, name);
        if (section && section->size)
            package->sections.emplace(id, read_debug_bytes(*tracking, metadata, *section, budget, stop));
        else if (id == 1 || id == 3)
            throw Failure{{ErrorCode::unsupported, "DWP supplementary package lacks INFO or ABBREV data"}};
    }
    if (const auto *strings = debug_section(metadata, ".debug_str.dwo"))
        if (strings->size) package->strings = read_debug_bytes(*tracking, metadata, *strings, budget, stop);
    if (const auto *strings = debug_section(metadata, ".debug_line_str.dwo"))
        if (strings->size) package->line_strings = read_debug_bytes(*tracking, metadata, *strings, budget, stop);
    require(budget.used <= max_bytes, "DWP supplementary package exceeds configured byte limit", ErrorCode::resource_limit);
    const auto examined = budget.used;
    std::vector<symbols::DwarfPackageSectionData> package_sections;
    package_sections.reserve(package->sections.size());
    for (const auto &[id, bytes] : package->sections) package_sections.push_back({id, bytes});
    auto type_signature = symbols::make_dwarf_package_type_signature_resolver(
        package->index, std::move(package_sections), package->strings, package->line_strings, stop,
        {budget.used < max_bytes ? max_bytes - budget.used : 0,
         std::min<std::uint32_t>(max_requests, 4096)});
    auto retained_package = package;
    auto catalog_package = package;
    symbols::DwarfTypeSignatureResolver retained_type_signature =
        [type_signature = std::move(type_signature), retained_package = std::move(retained_package)](std::uint64_t signature) {
            return type_signature(signature);
        };
    auto supplementary = [package = std::move(package), type_signature = retained_type_signature,
                          application_identity, stop, examined]
        (const symbols::DwarfSupplementaryIdentity &requested_identity, std::uint64_t die_offset)
        -> Result<symbols::DwarfSupplementaryType> {
        try {
        require(requested_identity == application_identity,
                "supplementary request identity differs from selected DWP package");
        const auto info_column = std::find(package->index->section_ids.begin(), package->index->section_ids.end(), 1u);
        require(info_column != package->index->section_ids.end(), "DWP type index has no INFO column");
        const auto column = static_cast<std::size_t>(info_column - package->index->section_ids.begin());
        const symbols::DwarfPackageIndexRow *match = nullptr;
        for (const auto &row : package->index->rows) {
            canceled(stop);
            if (column >= row.sections.size()) throw Failure{{ErrorCode::malformed, "invalid DWP type-index row"}};
            const auto &range = row.sections[column];
            if (die_offset < range.offset || die_offset - range.offset >= range.size) continue;
            if (match) throw Failure{{ErrorCode::malformed, "supplementary DIE offset belongs to ambiguous DWP contributions"}};
            match = &row;
        }
        require(match != nullptr, "supplementary DIE offset is absent from DWP type contributions", ErrorCode::unsupported);
        std::vector<symbols::DwarfPackageSectionData> section_data;
        for (const auto &[id, bytes] : package->sections) section_data.push_back({id, bytes});
        auto contribution = symbols::find_dwarf_package_contribution(*package->index, match->signature, section_data, stop);
        if (!contribution) throw Failure{contribution.error()};
        symbols::DwarfSections dwarf;
        dwarf.source_id = "DWARF v5 DWP supplementary type contribution";
        dwarf.strings = package->strings;
        dwarf.line_strings = package->line_strings;
        dwarf.stop = stop;
        dwarf.type_signature_resolver = type_signature;
        dwarf.info_section_offset = match->sections[column].offset;
        for (const auto &section : contribution.value().sections) {
            switch (section.section_id) {
            case 1: dwarf.info = section.bytes; break;
            case 3: dwarf.abbrev = section.bytes; break;
            case 4: dwarf.line_strings = package->line_strings; break;
            case 6: dwarf.string_offsets = section.bytes; break;
            default: break;
            }
        }
        const auto info_bytes = dwarf.info;
        require(info_bytes.size() >= 20, "truncated DWP supplementary type-unit header");
        const auto initial_length = std::uint32_t(info_bytes[0]) | (std::uint32_t(info_bytes[1]) << 8) |
                                   (std::uint32_t(info_bytes[2]) << 16) | (std::uint32_t(info_bytes[3]) << 24);
        require(initial_length != 0xffffffffu && initial_length <= info_bytes.size() - 4,
                "unsupported or truncated DWP supplementary type-unit extent", ErrorCode::unsupported);
        const auto version = std::uint16_t(info_bytes[4] | (std::uint16_t(info_bytes[5]) << 8));
        const auto unit_type = info_bytes[6];
        require(version == 5 && (unit_type == 2 || unit_type == 6),
                "DWP supplementary index contribution is not a DWARF v5 type unit", ErrorCode::unsupported);
        std::uint64_t signature = 0;
        for (unsigned i = 0; i < 8; ++i) signature |= std::uint64_t(info_bytes[12 + i]) << (8 * i);
        require(signature == match->signature, "DWP type-unit signature does not match its TU-index row");
        auto imported = symbols::import_dwarf(dwarf);
        if (!imported) throw Failure{imported.error()};
        types::TypePtr found_type;
        for (const auto &type : imported.value().types) {
            if (type.origin.record_offset != die_offset) continue;
            if (found_type && found_type->id() != type.type->id())
                throw Failure{{ErrorCode::malformed, "supplementary DIE offset resolves to conflicting types"}};
            found_type = type.type;
        }
        require(bool(found_type), "supplementary DIE offset does not identify an imported type", ErrorCode::unsupported);
        symbols::DwarfSupplementaryType result;
        result.identity = requested_identity;
        result.type = std::move(found_type);
        result.die_offset = die_offset;
        result.bytes_examined = examined;
        result.identity_verified = true;
        return result;
        } catch (const Failure &failure) { return failure.error; }
    };
    return {std::move(supplementary), std::move(retained_type_signature), std::move(catalog_package)};
}
} // namespace

Result<bool> read_dwarf_info(const ByteStorage &storage, ElfMetadata &metadata, Budget &budget,
                             std::stop_token stop, const symbols::DwarfSplitUnitResolver &split_resolver,
                             const symbols::DwarfSupplementaryTypeResolver &supplementary_resolver,
                             std::uint64_t supplementary_max_bytes,
                             std::uint32_t supplementary_max_requests,
                             std::shared_ptr<const ByteStorage> supplementary_package,
                             std::shared_ptr<const ByteStorage> split_debug_package) {
    try {
        const auto *info = debug_section(metadata, ".debug_info");
        if (!info || info->size == 0) return false;
        require(metadata.header.order == ByteOrder::little,
                "DWARF type/symbol import currently supports little-endian ELF only", ErrorCode::unsupported);
        const auto *abbrev = debug_section(metadata, ".debug_abbrev");
        const auto *strings = debug_section(metadata, ".debug_str");
        const auto *string_offsets = debug_section(metadata, ".debug_str_offsets");
        const auto *addresses = debug_section(metadata, ".debug_addr");
        const auto *line_strings = debug_section(metadata, ".debug_line_str");
        const auto *location_lists = debug_section(metadata, ".debug_loclists");
        const auto *locations = debug_section(metadata, ".debug_loc");
        const auto *supplementary_strings = debug_section(metadata, ".debug_str_sup");
        const auto *supplementary = debug_section(metadata, ".debug_sup");
        require(abbrev && abbrev->size != 0, ".debug_info has no usable .debug_abbrev section");
        auto info_bytes = read_debug_bytes(storage, metadata, *info, budget, stop);
        auto abbrev_bytes = read_debug_bytes(storage, metadata, *abbrev, budget, stop);
        std::vector<std::uint8_t> string_bytes;
        if (strings && strings->size) string_bytes = read_debug_bytes(storage, metadata, *strings, budget, stop);
        std::vector<std::uint8_t> string_offset_bytes, address_bytes, line_string_bytes, supplementary_string_bytes, location_list_bytes, location_bytes;
        if (string_offsets && string_offsets->size) string_offset_bytes = read_debug_bytes(storage, metadata, *string_offsets, budget, stop);
        if (addresses && addresses->size) address_bytes = read_debug_bytes(storage, metadata, *addresses, budget, stop);
        if (line_strings && line_strings->size) line_string_bytes = read_debug_bytes(storage, metadata, *line_strings, budget, stop);
        if (supplementary_strings && supplementary_strings->size) supplementary_string_bytes = read_debug_bytes(storage, metadata, *supplementary_strings, budget, stop);
        std::vector<std::uint8_t> supplementary_bytes;
        if (supplementary && supplementary->size) supplementary_bytes = read_debug_bytes(storage, metadata, *supplementary, budget, stop);
        if (location_lists && location_lists->size) location_list_bytes = read_debug_bytes(storage, metadata, *location_lists, budget, stop);
        if (locations && locations->size) location_bytes = read_debug_bytes(storage, metadata, *locations, budget, stop);
        canceled(stop);
        symbols::DwarfSections dwarf_sections;
        dwarf_sections.source_id = "ELF .debug_info";
        dwarf_sections.info = info_bytes;
        dwarf_sections.abbrev = abbrev_bytes;
        dwarf_sections.strings = string_bytes;
        dwarf_sections.string_offsets = string_offset_bytes;
        dwarf_sections.addresses = address_bytes;
        dwarf_sections.line_strings = line_string_bytes;
        dwarf_sections.stop = stop;
        dwarf_sections.supplementary_strings = supplementary_string_bytes;
        dwarf_sections.location_lists = location_list_bytes;
        dwarf_sections.locations = location_bytes;
        dwarf_sections.split_unit_resolver = split_resolver;
        dwarf_sections.supplementary_resolution_max_bytes = supplementary_max_bytes;
        dwarf_sections.supplementary_resolution_max_requests = supplementary_max_requests;
        auto selected_package = split_debug_package
            ? read_selected_dwp_resolvers(*split_debug_package, metadata, budget, stop,
                                          !dwarf_sections.split_unit_resolver)
            : DwarfEmbeddedPackageResolvers{};
        auto embedded_package = read_dwp_resolvers(storage, metadata, budget, stop,
                                                   !dwarf_sections.split_unit_resolver && !selected_package.split);
        if (!dwarf_sections.split_unit_resolver)
            dwarf_sections.split_unit_resolver = selected_package.split
                ? std::move(selected_package.split) : std::move(embedded_package.split);
        if (selected_package.type_signature && embedded_package.type_signature) {
            dwarf_sections.type_signature_resolver =
                [selected_index = selected_package.package, selected = selected_package.type_signature,
                 embedded_index = embedded_package.package, embedded = embedded_package.type_signature,
                 stop](std::uint64_t signature) -> Result<types::TypePtr> {
                    canceled(stop);
                    if (selected_index && std::binary_search(selected_index->type_signatures.begin(),
                                                             selected_index->type_signatures.end(), signature))
                        return selected(signature);
                    if (embedded_index && std::binary_search(embedded_index->type_signatures.begin(),
                                                             embedded_index->type_signatures.end(), signature))
                        return embedded(signature);
                    return Error{ErrorCode::unsupported, "DWARF type signature is absent from selected DWP indexes"};
                };
        } else {
            dwarf_sections.type_signature_resolver = selected_package.type_signature
                ? selected_package.type_signature : embedded_package.type_signature;
        }
        if (!supplementary_bytes.empty()) dwarf_sections.supplementary_identity = read_supplementary_identity(supplementary_bytes);
        require(!supplementary_package || dwarf_sections.supplementary_identity.present,
                "Explicit supplementary DWP was supplied but the ELF has no .debug_sup descriptor",
                ErrorCode::unsupported);
        auto selected_supplementary_resolver = supplementary_resolver;
        std::shared_ptr<const DwarfPackage> supplementary_type_package;
        if (supplementary_package && dwarf_sections.supplementary_identity.present) {
            auto package_resolvers = read_dwp_supplementary_resolver(
                std::move(supplementary_package), dwarf_sections.supplementary_identity,
                metadata.header.is_64, metadata.header.order, supplementary_max_bytes,
                supplementary_max_requests, stop);
            if (!selected_supplementary_resolver)
                selected_supplementary_resolver = std::move(package_resolvers.supplementary);
            supplementary_type_package = std::move(package_resolvers.type_package);
            if (dwarf_sections.type_signature_resolver && package_resolvers.type_signature) {
                // Dispatch by exact package-index membership, rather than
                // retrying an error: malformed/cyclic local types fail closed.
                dwarf_sections.type_signature_resolver =
                    [selected_package = selected_package.package,
                     selected = std::move(selected_package.type_signature),
                     embedded_package = embedded_package.package,
                     embedded = std::move(embedded_package.type_signature),
                     supplementary = std::move(package_resolvers.type_signature), stop](std::uint64_t signature)
                    -> Result<types::TypePtr> {
                        canceled(stop);
                        if (selected_package && selected &&
                            std::binary_search(selected_package->type_signatures.begin(),
                                               selected_package->type_signatures.end(), signature))
                            return selected(signature);
                        if (embedded_package && embedded &&
                            std::binary_search(embedded_package->type_signatures.begin(),
                                               embedded_package->type_signatures.end(), signature))
                            return embedded(signature);
                        return supplementary(signature);
                    };
            } else if (package_resolvers.type_signature) {
                dwarf_sections.type_signature_resolver = std::move(package_resolvers.type_signature);
            }
        }
        dwarf_sections.supplementary_type_resolver = std::move(selected_supplementary_resolver);
        auto cross_package_types = make_cross_package_type_signature_resolver(
            {{"ELF selected DWP type index", selected_package.package},
             {"ELF embedded DWP type index", embedded_package.package},
             {"ELF supplementary DWP type index", supplementary_type_package}},
            budget, stop);
        if (cross_package_types) dwarf_sections.type_signature_resolver = std::move(cross_package_types);
        auto imported = symbols::import_dwarf(dwarf_sections);
        if (!imported) return imported.error();
        std::uint64_t result_bytes = 0;
        std::vector<ElfSourceLine> imported_lines;
        const auto charge = [&](std::uint64_t amount) {
            require(amount <= metadata_limit - result_bytes, "Imported DWARF metadata exceeds ELF budget",
                    ErrorCode::resource_limit);
            result_bytes += amount;
        };
        std::unordered_set<const types::Type *> charged_types;
        const auto charge_type = [&](const types::TypePtr &type) {
            if (!type || !charged_types.insert(type.get()).second) return;
            auto encoded = types::encode(*type);
            if (!encoded) throw Failure{encoded.error()};
            charge(encoded.value().size());
        };
        for (const auto &symbol : imported.value().symbols) {
            canceled(stop);
            charge(sizeof(symbol) + symbol.name.size() + symbol.ranges.size() * sizeof(symbols::ImportedSymbol::Range));
            charge_type(symbol.type);
        }
        for (const auto &type : imported.value().types) {
            canceled(stop);
            charge(sizeof(type) + type.source_name.size());
            charge_type(type.type);
        }
        for (const auto &variable : imported.value().variables) {
            canceled(stop);
            charge(sizeof(variable) + variable.name.size() + variable.location_expression.size() +
                   variable.location_operations.size() * sizeof(symbols::LocationOperation));
            for (const auto& range : variable.location_ranges)
                charge(sizeof(range) + range.expression.size() + range.operations.size() * sizeof(symbols::LocationOperation));
            charge_type(variable.type);
        }
        for (const auto &enumerator : imported.value().enumerators) {
            canceled(stop);
            charge(sizeof(enumerator) + enumerator.name.size() + enumerator.enum_type_name.size());
        }
        for (const auto &unit : imported.value().line_units) {
            canceled(stop);
            charge(sizeof(unit));
            for (const auto &directory : unit.directories) charge(sizeof(directory) + directory.size());
            for (const auto &entry : unit.files) charge(sizeof(entry) + entry.name.size());
            for (const auto &row : unit.rows) {
                canceled(stop);
                std::string file;
                if (row.file && row.file <= unit.files.size()) {
                    const auto &entry = unit.files[static_cast<std::size_t>(row.file - 1)];
                    if (entry.directory && entry.directory <= unit.directories.size())
                        file = unit.directories[static_cast<std::size_t>(entry.directory - 1)] + "/";
                    file += entry.name;
                }
                charge(sizeof(ElfSourceLine) + file.size());
                imported_lines.push_back({{{0}, row.address}, std::move(file), row.line,
                                           row.column, row.end_sequence});
            }
        }
        imported.value().line_units.clear();
        budget.include(result_bytes);
        metadata.source_lines.insert(metadata.source_lines.end(),
            std::make_move_iterator(imported_lines.begin()), std::make_move_iterator(imported_lines.end()));
        metadata.dwarf_info = std::move(imported.value());
        return true;
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate ELF DWARF metadata"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "ELF DWARF metadata exceeds container limit"};
    }
}
} // namespace hexlab::elf_detail

namespace hexlab {
Result<symbols::ImportResult> import_elf_dwo(const ByteStorage &storage,
                                              const symbols::DwarfSplitUnitRequest &request,
                                              std::stop_token stop,
                                              std::uint64_t max_metadata_bytes,
                                              symbols::DwarfTypeSignatureResolver type_signature_resolver) {
    using namespace elf_detail;
    try {
        require(max_metadata_bytes != 0, "ELF DWO metadata budget must be nonzero", ErrorCode::invalid_argument);
        ElfMetadata metadata;
        metadata.header = take(read_elf_header(storage, stop));
        require(metadata.header.order == ByteOrder::little,
                "DWARF DWO import currently supports little-endian ELF only", ErrorCode::unsupported);
        Budget budget;
        budget.limit = std::min(max_metadata_bytes, metadata_limit);
        read_tables(storage, metadata, budget, stop);

        const auto *info = debug_section(metadata, ".debug_info.dwo");
        const auto *abbrev = debug_section(metadata, ".debug_abbrev.dwo");
        require(info && info->size, "ELF DWO has no .debug_info.dwo section", ErrorCode::unsupported);
        require(abbrev && abbrev->size, "ELF DWO has no .debug_abbrev.dwo section", ErrorCode::unsupported);
        symbols::DwarfSections dwarf;
        dwarf.source_id = "ELF .debug_info.dwo";
        auto info_bytes = read_debug_bytes(storage, metadata, *info, budget, stop);
        auto abbrev_bytes = read_debug_bytes(storage, metadata, *abbrev, budget, stop);
        std::vector<std::uint8_t> strings, string_offsets, addresses, line_strings,
            location_lists, range_lists, line_bytes;
        dwarf.info = info_bytes;
        dwarf.abbrev = abbrev_bytes;
        dwarf.stop = stop;
        dwarf.expected_split_dwo_id = request.dwo_id;
        if (request.address_size) dwarf.expected_split_address_size = request.address_size;
        dwarf.type_signature_resolver = std::move(type_signature_resolver);
        const auto copy_optional = [&](std::string_view name, std::vector<std::uint8_t> &target) {
            if (const auto *section = debug_section(metadata, name); section && section->size)
                target = read_debug_bytes(storage, metadata, *section, budget, stop);
        };
        copy_optional(".debug_str.dwo", strings);
        copy_optional(".debug_str_offsets.dwo", string_offsets);
        copy_optional(".debug_addr.dwo", addresses);
        copy_optional(".debug_line_str.dwo", line_strings);
        copy_optional(".debug_loclists.dwo", location_lists);
        copy_optional(".debug_rnglists.dwo", range_lists);
        copy_optional(".debug_line.dwo", line_bytes);
        dwarf.strings = strings;
        dwarf.string_offsets = string_offsets;
        dwarf.addresses = addresses;
        dwarf.line_strings = line_strings;
        dwarf.location_lists = location_lists;
        dwarf.range_lists = range_lists;

        auto imported = symbols::import_dwarf(dwarf);
        if (!imported) return imported.error();
        if (!line_bytes.empty()) {
            symbols::DwarfLineSections line;
            line.source_id = "ELF .debug_line.dwo";
            line.line = line_bytes;
            line.address_size = request.address_size ? request.address_size
                                                     : static_cast<std::uint8_t>(metadata.header.is_64 ? 8 : 4);
            line.little_endian = true;
            line.stop = stop;
            line.strings = dwarf.strings;
            line.line_strings = dwarf.line_strings;
            auto units = symbols::import_dwarf_line_v2_v5(line);
            if (!units) return units.error();
            imported.value().line_units = std::move(units.value());
        }

        std::uint64_t result_bytes = 0;
        const auto charge = [&](std::uint64_t amount) {
            require(amount <= budget.limit - result_bytes,
                    "Imported ELF DWO metadata exceeds configured budget", ErrorCode::resource_limit);
            result_bytes += amount;
        };
        std::unordered_set<const types::Type *> charged_types;
        const auto charge_type = [&](const types::TypePtr &type) {
            if (!type || !charged_types.insert(type.get()).second) return;
            auto encoded = types::encode(*type);
            if (!encoded) throw Failure{encoded.error()};
            charge(encoded.value().size());
        };
        for (const auto &symbol : imported.value().symbols) {
            charge(sizeof(symbol) + symbol.name.size() + symbol.ranges.size() * sizeof(symbols::ImportedSymbol::Range));
            charge_type(symbol.type);
        }
        for (const auto &type : imported.value().types) {
            charge(sizeof(type) + type.source_name.size());
            charge_type(type.type);
        }
        for (const auto &signature : imported.value().type_signatures) {
            charge(sizeof(signature));
            charge_type(signature.type);
        }
        for (const auto &variable : imported.value().variables) {
            charge(sizeof(variable) + variable.name.size() + variable.location_expression.size() +
                   variable.location_operations.size() * sizeof(symbols::LocationOperation));
            for (const auto &range : variable.location_ranges)
                charge(sizeof(range) + range.expression.size() + range.operations.size() * sizeof(symbols::LocationOperation));
            charge_type(variable.type);
        }
        for (const auto &enumerator : imported.value().enumerators)
            charge(sizeof(enumerator) + enumerator.name.size() + enumerator.enum_type_name.size());
        for (const auto &unit : imported.value().line_units) {
            charge(sizeof(unit));
            for (const auto &directory : unit.directories) charge(sizeof(directory) + directory.size());
            for (const auto &file : unit.files) charge(sizeof(file) + file.name.size());
            charge(unit.rows.size() * sizeof(symbols::DwarfLineRow));
        }
        budget.include(result_bytes);
        return std::move(imported.value());
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate ELF DWO metadata"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "ELF DWO metadata exceeds container limit"};
    }
}

symbols::DwarfSplitUnitResolver make_elf_dwo_resolver(ElfDwoStorageResolver resolver,
                                                       std::stop_token stop,
                                                       std::uint64_t max_metadata_bytes,
                                                       symbols::DwarfTypeSignatureResolver type_signature_resolver) {
    return [resolver = std::move(resolver), stop, max_metadata_bytes,
            type_signature_resolver = std::move(type_signature_resolver)]
           (const symbols::DwarfSplitUnitRequest &request)
               -> Result<std::shared_ptr<symbols::ImportResult>> {
        if (!resolver)
            return Error{ErrorCode::invalid_argument, "ELF DWO storage resolver is not configured"};
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF DWO import canceled"};
        auto storage = resolver(request);
        if (!storage) return storage.error();
        if (!storage.value()) return Error{ErrorCode::invalid_argument, "ELF DWO resolver returned null storage"};
        auto imported = import_elf_dwo(*storage.value(), request, stop, max_metadata_bytes,
                                       type_signature_resolver);
        if (!imported) return imported.error();
        return std::make_shared<symbols::ImportResult>(std::move(imported.value()));
    };
}

symbols::DwarfTypeSignatureResolver make_elf_dwo_type_signature_resolver(
    std::vector<ElfDwoTypeSource> sources, std::stop_token stop, ElfDwoTypeResolverLimits limits) {
    struct State {
        std::vector<ElfDwoTypeSource> sources;
        std::vector<std::shared_ptr<symbols::ImportResult>> cache;
        std::set<std::uint64_t> active;
        std::set<std::uint64_t> active_dwo_ids;
        std::uint64_t bytes = 0;
        std::uint32_t requests = 0;
        std::mutex mutex;
        std::recursive_mutex invocation_mutex;
        ElfDwoTypeResolverLimits limits;
        std::stop_token stop;
        std::optional<Error> catalog_error;
    };
    auto state = std::make_shared<State>();
    state->sources = std::move(sources);
    state->cache.resize(state->sources.size());
    state->limits = limits;
    state->stop = stop;
    if (state->sources.size() > limits.max_sources)
        state->catalog_error = Error{ErrorCode::resource_limit, "Cross-DWO source count exceeds configured limit"};
    std::set<std::uint64_t> source_ids;
    for (const auto &source : state->sources) {
        if (state->catalog_error) break;
        if (!source.storage || !source.identity.dwo_id ||
            (source.identity.address_size != 4 && source.identity.address_size != 8)) {
            state->catalog_error = Error{ErrorCode::invalid_argument,
                "Cross-DWO source requires storage, exact DWO ID, and 4- or 8-byte address size"};
            break;
        }
        if (!source_ids.insert(source.identity.dwo_id).second) {
            state->catalog_error = Error{ErrorCode::malformed, "Ambiguous duplicate DWO identity in cross-DWO catalog"};
            break;
        }
    }
    auto self = std::make_shared<symbols::DwarfTypeSignatureResolver>();
    const std::weak_ptr<symbols::DwarfTypeSignatureResolver> weak_self = self;
    *self = [state, weak_self](std::uint64_t signature) -> Result<types::TypePtr> {
        std::lock_guard invocation_lock(state->invocation_mutex);
        if (state->catalog_error) return *state->catalog_error;
        if (state->stop.stop_requested()) return Error{ErrorCode::canceled, "Cross-DWO type resolution canceled"};
        {
            std::lock_guard lock(state->mutex);
            if (state->active.contains(signature))
                return Error{ErrorCode::malformed, "Cycle in cross-DWO type-signature dependencies"};
            if (state->requests >= state->limits.max_requests)
                return Error{ErrorCode::resource_limit, "Cross-DWO type request limit exceeded"};
            ++state->requests;
            state->active.insert(signature);
        }
        struct ActiveGuard { std::shared_ptr<State> state; std::uint64_t signature;
            ~ActiveGuard() { std::lock_guard lock(state->mutex); state->active.erase(signature); }
        } guard{state, signature};
        std::vector<symbols::ImportedTypeSignature> matches;
        bool skipped_active_dwo = false;
        for (std::size_t i = 0; i < state->sources.size(); ++i) {
            if (state->stop.stop_requested()) return Error{ErrorCode::canceled, "Cross-DWO type resolution canceled"};
            const auto &source = state->sources[i];
            std::shared_ptr<symbols::ImportResult> imported;
            {
                std::lock_guard lock(state->mutex);
                imported = state->cache[i];
            }
            if (!imported) {
                {
                    std::lock_guard lock(state->mutex);
                    if (!state->active_dwo_ids.insert(source.identity.dwo_id).second) {
                        skipped_active_dwo = true;
                        continue;
                    }
                }
                struct DwoGuard { std::shared_ptr<State> state; std::uint64_t id;
                    ~DwoGuard() { std::lock_guard lock(state->mutex); state->active_dwo_ids.erase(id); }
                } dwo_guard{state, source.identity.dwo_id};
                const auto size = source.storage->size();
                {
                    std::lock_guard lock(state->mutex);
                    if (size > state->limits.max_bytes - state->bytes)
                        return Error{ErrorCode::resource_limit, "Cross-DWO aggregate byte limit exceeded"};
                    state->bytes += size;
                }
                auto resolver = weak_self.lock();
                if (!resolver) return Error{ErrorCode::canceled, "Cross-DWO resolver expired during import"};
                auto parsed = import_elf_dwo(*source.storage, source.identity, state->stop,
                                             state->limits.max_bytes_per_dwo, *resolver);
                if (!parsed) return parsed.error();
                imported = std::make_shared<symbols::ImportResult>(std::move(parsed.value()));
                if (!imported->split_unit || imported->split_dwo_id != source.identity.dwo_id)
                    return Error{ErrorCode::malformed, "Cross-DWO import did not preserve the selected skeleton identity"};
                std::uint64_t result_cost = 0;
                const auto add_cost = [&](std::uint64_t amount) {
                    if (amount > UINT64_MAX - result_cost) return false;
                    result_cost += amount;
                    return true;
                };
                std::unordered_set<const types::Type *> charged_types;
                const auto charge_type = [&](const types::TypePtr &type) {
                    if (!type || !charged_types.insert(type.get()).second) return true;
                    auto encoded = types::encode(*type);
                    return encoded && add_cost(encoded.value().size());
                };
                bool cost_valid = true;
                for (const auto &row : imported->symbols)
                    cost_valid = cost_valid && add_cost(sizeof(row) + row.name.size() + row.ranges.size() * sizeof(symbols::ImportedSymbol::Range)) && charge_type(row.type);
                for (const auto &row : imported->types)
                    cost_valid = cost_valid && add_cost(sizeof(row) + row.source_name.size()) && charge_type(row.type);
                for (const auto &row : imported->variables) {
                    cost_valid = cost_valid && add_cost(sizeof(row) + row.name.size() + row.location_expression.size() +
                        row.location_operations.size() * sizeof(symbols::LocationOperation)) && charge_type(row.type);
                    for (const auto &range : row.location_ranges)
                        cost_valid = cost_valid && add_cost(sizeof(range) + range.expression.size() +
                            range.operations.size() * sizeof(symbols::LocationOperation));
                }
                for (const auto &row : imported->enumerators)
                    cost_valid = cost_valid && add_cost(sizeof(row) + row.name.size() + row.enum_type_name.size());
                for (const auto &row : imported->type_signatures)
                    cost_valid = cost_valid && add_cost(sizeof(row)) && charge_type(row.type);
                for (const auto &unit : imported->line_units) {
                    cost_valid = cost_valid && add_cost(sizeof(unit) + unit.rows.size() * sizeof(symbols::DwarfLineRow));
                    for (const auto &directory : unit.directories) cost_valid = cost_valid && add_cost(sizeof(directory) + directory.size());
                    for (const auto &file : unit.files) cost_valid = cost_valid && add_cost(sizeof(file) + file.name.size());
                }
                if (!cost_valid) return Error{ErrorCode::resource_limit, "Cross-DWO result size overflowed accounting"};
                {
                    std::lock_guard lock(state->mutex);
                    if (result_cost > state->limits.max_bytes - state->bytes)
                        return Error{ErrorCode::resource_limit, "Cross-DWO aggregate byte limit exceeded"};
                    state->bytes += result_cost;
                }
                std::lock_guard lock(state->mutex);
                if (!state->cache[i]) state->cache[i] = imported;
                else imported = state->cache[i];
            }
            for (const auto &entry : imported->type_signatures) {
                if (entry.signature != signature) continue;
                if (!entry.type || entry.origin.source_id != "ELF .debug_info.dwo" ||
                    entry.origin.section != ".debug_info" || entry.origin.record_size == 0)
                    return Error{ErrorCode::malformed, "Cross-DWO type signature lacks type or source provenance"};
                if (std::find(matches.begin(), matches.end(), entry) == matches.end()) matches.push_back(entry);
            }
        }
        if (matches.empty()) {
            if (skipped_active_dwo)
                return Error{ErrorCode::malformed, "Cross-DWO signature could not be resolved without reimporting an active object"};
            return Error{ErrorCode::unsupported, "Cross-DWO type signature was not found"};
        }
        if (matches.size() != 1) return Error{ErrorCode::malformed, "Ambiguous type signature across selected DWO objects"};
        auto encoded = types::encode(*matches.front().type);
        if (!encoded) return encoded.error();
        {
            std::lock_guard lock(state->mutex);
            if (encoded.value().size() > state->limits.max_bytes - state->bytes)
                return Error{ErrorCode::resource_limit, "Cross-DWO aggregate byte limit exceeded"};
            state->bytes += encoded.value().size();
        }
        return matches.front().type;
    };
    return *self;
}
} // namespace hexlab
