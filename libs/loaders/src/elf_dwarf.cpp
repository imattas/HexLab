#include "elf_internal.hpp"
#include "hexlab/image/file_storage.hpp"
#include "hexlab/symbols/dwarf.hpp"
#include <algorithm>
#include <bit>
#include <cctype>
#include <filesystem>
#include <iterator>
#include <map>
#include <mutex>
#include <set>
#include <string_view>
#include <tuple>
#include <unordered_set>

namespace hexlab::symbols {
HEXLAB_SYMBOLS_EXPORT DwarfCrossContributionDieResolver make_dwarf_package_cross_contribution_die_resolver(
    std::shared_ptr<const DwarfPackageIndex>, std::vector<DwarfPackageSectionData>,
    std::span<const std::uint8_t>, std::span<const std::uint8_t>, std::stop_token,
    DwarfPackageTypeResolutionLimits, bool little_endian);
}

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

// Apply only bounded scalar data relocations into DWARF sections. These
// sections contain data fields; instruction relocations are deliberately not
// decoded or rewritten here. ET_REL symbol values are section-relative.
void relocate_dwarf_data(const ElfMetadata &metadata,
                         const std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t> *>> &buffers,
                         std::stop_token stop) {
    struct Patch {
        std::uint32_t section;
        std::uint64_t offset, value;
        std::uint8_t width;
    };
    std::vector<Patch> patches;
    const auto bytes_for = [&](std::uint32_t section) -> std::vector<std::uint8_t> * {
        for (const auto &[index, bytes] : buffers) if (index == section) return bytes;
        return nullptr;
    };
    const auto put = [&](std::vector<std::uint8_t> &bytes, std::uint64_t offset,
                         std::uint8_t width, std::uint64_t value) {
        require(offset <= bytes.size() && width <= bytes.size() - offset,
                "DWARF relocation field exceeds target section");
        for (std::uint8_t i = 0; i < width; ++i)
            bytes[static_cast<std::size_t>(offset) + i] = static_cast<std::uint8_t>(value >> (8 * i));
    };
    std::size_t relocation_index = 0;
    for (const auto &rel : metadata.relocations) {
        if ((relocation_index++ & 0x3ffu) == 0) canceled(stop);
        if (!rel.target_section || !bytes_for(*rel.target_section)) continue;
        require(metadata.header.object_type == 1, "DWARF section relocations are supported only for ET_REL objects", ErrorCode::unsupported);
        require(*rel.target_section < metadata.sections.size(), "DWARF relocation target section is unavailable");
        const auto &target_section = metadata.sections[*rel.target_section];
        require((target_section.flags & 0x800u) == 0 && !target_section.name.starts_with(".zdebug_"),
                "Relocations into compressed DWARF sections are unsupported", ErrorCode::unsupported);
        const bool x64 = metadata.header.machine == 62;
        const bool a64 = metadata.header.machine == 183;
        const bool riscv = metadata.header.machine == 243;
        const bool i386 = metadata.header.machine == 3;
        const bool arm32 = metadata.header.machine == 40;
        std::uint8_t width = 0;
        if (x64 && rel.type == 1) width = 8;          // R_X86_64_64
        else if (x64 && rel.type == 2) width = 4;     // bounded same-section R_X86_64_PC32
        else if (x64 && (rel.type == 10 || rel.type == 11)) width = 4; // R_X86_64_32/32S
        else if (a64 && rel.type == 257) width = 8;  // R_AARCH64_ABS64
        else if (a64 && rel.type == 258) width = 4;  // R_AARCH64_ABS32
        else if (a64 && rel.type == 260) width = 8;  // bounded same-section R_AARCH64_PREL64
        else if (a64 && rel.type == 261) width = 4;  // bounded same-section R_AARCH64_PREL32
        else if (i386 && rel.type == 1) width = 4;   // R_386_32
        else if (i386 && rel.type == 2) width = 4;   // bounded same-section R_386_PC32
        else if (arm32 && rel.type == 2) width = 4;  // R_ARM_ABS32
        else if (arm32 && rel.type == 3) width = 4;  // bounded same-section R_ARM_REL32
        else if (riscv && rel.type == 1) width = 4;  // R_RISCV_32
        else if (riscv && rel.type == 2 && metadata.header.is_64) width = 8; // R_RISCV_64
        else if (riscv && rel.type == 57) width = 4; // bounded same-section R_RISCV_32_PCREL
        else throw Failure{{ErrorCode::unsupported, "unsupported ELF relocation in DWARF section (type " + std::to_string(rel.type) + ")"}};
        require(metadata.header.order == ByteOrder::little, "big-endian DWARF relocation is unsupported", ErrorCode::unsupported);
        require(rel.field_size && *rel.field_size == width, "DWARF relocation width is not proven");
        require(rel.symbol_index_validated && rel.symbol_table.has_value(), "DWARF relocation symbol provenance is unavailable", ErrorCode::unsupported);
        const ElfSymbol *symbol = nullptr;
        std::size_t symbol_matches = 0;
        for (const auto &candidate : metadata.symbols) {
            if (!candidate.table || *candidate.table >= metadata.symbol_tables.size()) continue;
            const auto &table = metadata.symbol_tables[*candidate.table];
            if (table.source.section == rel.symbol_table->section && candidate.index == rel.symbol_index) {
                symbol = &candidate; ++symbol_matches;
            }
        }
        require(symbol_matches == 1 && symbol && symbol->state == ElfSymbolState::defined && symbol->section_index < metadata.sections.size(),
                "DWARF relocation symbol is not a uniquely defined symbol in a valid section", ErrorCode::unsupported);
        auto &target = *bytes_for(*rel.target_section);
        require(rel.offset <= target.size() && width <= target.size() - rel.offset, "DWARF relocation field exceeds target section");
        std::int64_t addend = 0;
        if (rel.explicit_addend) {
            require(rel.addend.has_value(), "DWARF RELA relocation has no explicit addend");
            addend = *rel.addend;
        } else {
            // Sample original section bytes. Writes are deferred until all
            // rows are validated, so another relocation cannot change A.
            const bool unsigned_word_rel = width == 4 &&
                ((i386 && rel.type == 1) || (arm32 && rel.type == 2));
            const bool signed_word_rel = width == 4 &&
                ((x64 && (rel.type == 2 || rel.type == 10 || rel.type == 11)) ||
                 (i386 && rel.type == 2) || (arm32 && rel.type == 3) ||
                 (a64 && (rel.type == 258 || rel.type == 261)) ||
                 (riscv && (rel.type == 1 || rel.type == 57)));
            const bool signed_wide_rel = width == 8 &&
                ((x64 && rel.type == 1) || (a64 && (rel.type == 257 || rel.type == 260)) ||
                 (riscv && metadata.header.is_64 && rel.type == 2));
            require(unsigned_word_rel || signed_word_rel || signed_wide_rel,
                    "unsupported implicit-addend DWARF relocation", ErrorCode::unsupported);
            std::uint64_t value = 0;
            for (std::uint8_t i = 0; i < width; ++i)
                value |= std::uint64_t(target[static_cast<std::size_t>(rel.offset) + i]) << (8 * i);
            addend = signed_wide_rel ? std::bit_cast<std::int64_t>(value)
                     : signed_word_rel && value > INT32_MAX
                         ? -1 - static_cast<std::int64_t>(UINT32_MAX - value)
                         : static_cast<std::int64_t>(value);
        }
        const auto max_value = width == 8 ? UINT64_MAX : std::uint64_t(UINT32_MAX);
        std::uint64_t sum = symbol->value;
        if ((x64 && rel.type == 2) || (i386 && rel.type == 2) ||
            (arm32 && rel.type == 3) || (a64 && (rel.type == 260 || rel.type == 261)) ||
            (riscv && rel.type == 57)) {
            // Without final section placement, a cross-section PC-relative
            // value cannot be proven. Same-section offsets cancel P's base.
            require(symbol->section_index == *rel.target_section && symbol->value <= INT64_MAX &&
                    rel.offset <= static_cast<std::uint64_t>(INT64_MAX),
                    "PC-relative DWARF relocation is not same-section or representable", ErrorCode::unsupported);
            const auto displacement = static_cast<std::int64_t>(symbol->value) -
                                      static_cast<std::int64_t>(rel.offset);
            require((addend >= 0 && displacement <= INT64_MAX - addend) ||
                    (addend < 0 && displacement >= INT64_MIN - addend),
                    "R_X86_64_PC32 DWARF relocation arithmetic overflows");
            const auto result = displacement + addend;
            if (width == 8) {
                sum = static_cast<std::uint64_t>(result);
            } else {
                require(result >= INT32_MIN && result <= INT32_MAX,
                        "PC-relative DWARF relocation result overflows signed 32-bit field");
                sum = static_cast<std::uint32_t>(static_cast<std::int32_t>(result));
            }
        } else if ((x64 && rel.type == 1) || (a64 && rel.type == 257) || (riscv && rel.type == 2)) {
            // These 64-bit absolute relocations store the ABI-defined low
            // 64 bits of S+A.
            sum += static_cast<std::uint64_t>(addend);
        } else if (x64 && rel.type == 11 && addend < 0) {
            const auto magnitude = static_cast<std::uint64_t>(-(addend + 1)) + 1;
            require(symbol->value >= magnitude || magnitude - symbol->value <= (std::uint64_t{1} << 31),
                    "R_X86_64_32S DWARF relocation result overflows signed field");
            if (symbol->value >= magnitude) {
                sum = symbol->value - magnitude;
                require(sum <= INT32_MAX, "R_X86_64_32S DWARF relocation result overflows signed field");
            } else {
                const auto negative_magnitude = magnitude - symbol->value;
                require(negative_magnitude <= (std::uint64_t{1} << 31),
                        "R_X86_64_32S DWARF relocation result overflows signed field");
                sum = std::uint32_t(0u - static_cast<std::uint32_t>(negative_magnitude));
            }
        } else if (a64 && rel.type == 258 && addend < 0) {
            // AAELF64 ABS32 accepts either a signed or unsigned 32-bit
            // result: -2^31 <= S+A < 2^32.
            const auto magnitude = static_cast<std::uint64_t>(-(addend + 1)) + 1;
            if (sum >= magnitude) {
                sum -= magnitude;
                require(sum <= UINT32_MAX, "R_AARCH64_ABS32 DWARF relocation result overflows field");
            } else {
                const auto negative_magnitude = magnitude - sum;
                require(negative_magnitude <= (std::uint64_t{1} << 31),
                        "R_AARCH64_ABS32 DWARF relocation result overflows field");
                sum = std::uint32_t(0u - static_cast<std::uint32_t>(negative_magnitude));
            }
        } else if (addend >= 0) {
            const auto add = static_cast<std::uint64_t>(addend);
            require(sum <= max_value && add <= max_value - sum, "DWARF absolute relocation result overflows field");
            sum += add;
            if (x64 && rel.type == 11)
                require(sum <= INT32_MAX, "R_X86_64_32S DWARF relocation result overflows signed field");
        } else {
            const auto magnitude = static_cast<std::uint64_t>(-(addend + 1)) + 1;
            require(sum >= magnitude, "DWARF absolute relocation result is negative");
            sum -= magnitude;
            require(sum <= max_value, "DWARF absolute relocation result overflows field");
        }
        require(patches.size() < 1'000'000, "DWARF relocation patch count exceeds limit", ErrorCode::resource_limit);
        patches.push_back({*rel.target_section, rel.offset, sum, width});
    }
    std::sort(patches.begin(), patches.end(), [](const Patch &a, const Patch &b) {
        return std::tie(a.section, a.offset) < std::tie(b.section, b.offset);
    });
    for (std::size_t i = 1; i < patches.size(); ++i) {
        if ((i & 0x3ffu) == 0) canceled(stop);
        const auto &previous = patches[i - 1], &current = patches[i];
        require(previous.section != current.section || current.offset - previous.offset >= previous.width,
                "Overlapping or composed DWARF relocations are unsupported", ErrorCode::unsupported);
    }
    for (std::size_t i = 0; i < patches.size(); ++i) {
        if ((i & 0x3ffu) == 0) canceled(stop);
        const auto &patch = patches[i];
        put(*bytes_for(patch.section), patch.offset, patch.width, patch.value);
    }
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
    symbols::DwarfCrossContributionDieResolver cross_contribution;
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

    const auto package_version = package->index ? package->index->version : package->type_index->version;
    std::vector<std::pair<std::uint32_t, std::string_view>> names = package_version == 2
        ? std::vector<std::pair<std::uint32_t, std::string_view>>{
            {1, ".debug_info.dwo"}, {2, ".debug_types.dwo"}, {3, ".debug_abbrev.dwo"},
            {4, ".debug_line.dwo"}, {5, ".debug_loc.dwo"}, {6, ".debug_str_offsets.dwo"},
            {7, ".debug_macinfo.dwo"}, {8, ".debug_macro.dwo"}}
        : std::vector<std::pair<std::uint32_t, std::string_view>>{
            {1, ".debug_info.dwo"}, {3, ".debug_abbrev.dwo"}, {4, ".debug_line.dwo"},
            {5, ".debug_loclists.dwo"}, {6, ".debug_str_offsets.dwo"}, {7, ".debug_macro.dwo"},
            {8, ".debug_rnglists.dwo"}, {9, ".debug_addr.dwo"}};
    const auto indexed_section_name=[](std::uint32_t version,std::uint32_t id)->std::optional<std::string_view>{
        if(version==2){
            switch(id){
            case 1:return ".debug_info.dwo"; case 2:return ".debug_types.dwo";
            case 3:return ".debug_abbrev.dwo"; case 4:return ".debug_line.dwo";
            case 5:return ".debug_loc.dwo"; case 6:return ".debug_str_offsets.dwo";
            case 7:return ".debug_macinfo.dwo"; case 8:return ".debug_macro.dwo";
            default:return {};
            }
        }
        if(version==5){
            switch(id){
            case 1:return ".debug_info.dwo"; case 3:return ".debug_abbrev.dwo";
            case 4:return ".debug_line.dwo"; case 5:return ".debug_loclists.dwo";
            case 6:return ".debug_str_offsets.dwo"; case 7:return ".debug_macro.dwo";
            case 8:return ".debug_rnglists.dwo"; case 9:return ".debug_addr.dwo";
            default:return {};
            }
        }
        return {};
    };
    if (package->type_index) {
        for(const auto id:package->type_index->section_ids){
            const auto type_name=indexed_section_name(package->type_index->version,id);
            const auto selected_name=package->index?indexed_section_name(package_version,id):type_name;
            require(type_name.has_value(),"DWP TU index uses an unsupported section ID",ErrorCode::unsupported);
            if(selected_name&&*selected_name!=*type_name)
                throw Failure{{ErrorCode::unsupported,"Mixed-version DWP indexes assign different meanings to a shared section ID"}};
            if(!selected_name)names.emplace_back(id,*type_name);
        }
    }
    // REL/RELA offsets in a DWP refer to the containing ELF section, not to an
    // individual CU/TU contribution. Keep full package-section buffers and
    // apply relocations before the package resolver slices contributions.
    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t> *>> relocation_buffers;
    const auto add_relocation_buffer = [&](const ElfSection *section, std::vector<std::uint8_t> &bytes) {
        if (!section || bytes.empty()) return;
        const auto index = static_cast<std::uint32_t>(section - metadata.sections.data());
        relocation_buffers.emplace_back(index, &bytes);
    };
    for (const auto &[id, name] : names) {
        canceled(stop);
        if (!has_compile_units && id != 1 && id != 2 && id != 3 && id != 4 && id != 6) continue;
        if (const auto *section = debug_section(metadata, name); section && section->size) {
            auto [entry, inserted] = package->sections.emplace(
                id, read_debug_bytes(storage, metadata, *section, budget, stop));
            require(inserted, "duplicate DWP package section ID");
            add_relocation_buffer(section, entry->second);
        }
    }
    if (const auto *strings = optional_debug_section(metadata, ".debug_str.dwo")) {
        if (strings->size) {
            package->strings = read_debug_bytes(storage, metadata, *strings, budget, stop);
            add_relocation_buffer(strings, package->strings);
        }
    }
    if (const auto *strings = optional_debug_section(metadata, ".debug_line_str.dwo")) {
        if (strings->size) {
            package->line_strings = read_debug_bytes(storage, metadata, *strings, budget, stop);
            add_relocation_buffer(strings, package->line_strings);
        }
    }
    relocate_dwarf_data(metadata, relocation_buffers, stop);

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
    if (package->index) {
        std::vector<symbols::DwarfPackageSectionData> source_sections;
        source_sections.reserve(package->sections.size());
        for (const auto &[id, bytes] : package->sections) source_sections.push_back({id, bytes});
        auto resolver = symbols::make_dwarf_package_cross_contribution_die_resolver(
            package->index, std::move(source_sections), package->strings, package->line_strings,
            stop, {budget.limit - budget.used, 4096}, metadata.header.order == ByteOrder::little);
        result.cross_contribution = [package, resolver = std::move(resolver)](std::uint64_t offset) {
            (void)package; // Keep the package buffers borrowed by the resolver alive.
            return resolver(offset);
        };
    }
    if (!package->index) return result;
    const auto address_size = static_cast<std::uint8_t>(metadata.header.is_64 ? 8 : 4);
    const auto little_endian = metadata.header.order == ByteOrder::little;
    result.split = [package = std::move(package), type_signature = result.type_signature,
                    cross_contribution = result.cross_contribution,
                    stop, address_size, little_endian](const symbols::DwarfSplitUnitRequest &request)
               -> Result<std::shared_ptr<symbols::ImportResult>> {
        std::vector<symbols::DwarfPackageSectionData> source_sections;
        source_sections.reserve(package->sections.size());
        for (const auto &[id, bytes] : package->sections)
            source_sections.push_back({id, bytes});
        auto imported = symbols::import_dwarf_package_unit(*package->index, request.dwo_id, source_sections,
                                                            package->strings, stop, package->line_strings,
                                                            address_size, little_endian,
                                                            type_signature, cross_contribution);
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

DwarfPackageResolvers read_supplementary_object_resolver(
    std::shared_ptr<const ByteStorage> storage, const symbols::DwarfSupplementaryIdentity &application_identity,
    bool application_is_64, ByteOrder application_order, std::uint64_t max_bytes,
    std::uint32_t max_requests, std::stop_token stop) {
    if (!storage) return {};
    require(application_identity.present && !application_identity.supplementary &&
                !application_identity.checksum.empty(),
            "Supplementary source requires an application .debug_sup checksum", ErrorCode::unsupported);
    auto tracking = take(TrackingStorage::create(storage));
    ElfMetadata metadata;
    metadata.header = take(read_elf_header(*tracking, stop));
    require(metadata.header.is_64 == application_is_64 && metadata.header.order == application_order,
            "Supplementary source class or byte order differs from the application ELF");
    Budget budget;
    budget.limit = std::min(max_bytes, metadata_limit);
    read_tables(*tracking, metadata, budget, stop);
    const auto *sup = debug_section(metadata, ".debug_sup");
    require(sup && sup->size, "Supplementary source has no .debug_sup descriptor", ErrorCode::unsupported);
    const auto sup_bytes = read_debug_bytes(*tracking, metadata, *sup, budget, stop);
    const auto package_identity = read_supplementary_identity(sup_bytes);
    require(package_identity.supplementary && package_identity.checksum == application_identity.checksum,
            "Supplementary source identity/checksum does not match the application .debug_sup descriptor");
    auto package = std::make_shared<DwarfPackage>();
    if (const auto *index = debug_section(metadata, ".debug_tu_index"); index && index->size)
        package->type_index = read_package_index(*tracking, metadata, *index,
            symbols::DwarfPackageIndexKind::type_units, budget, stop);
    if (const auto *index = debug_section(metadata, ".debug_cu_index"); index && index->size)
        package->index = read_package_index(*tracking, metadata, *index,
            symbols::DwarfPackageIndexKind::compile_units, budget, stop);
        if (!package->index && !package->type_index) {
        // A non-packaged supplementary ELF addresses DIEs directly in its
        // .debug_info section. Retain one bounded parse for all references.
        struct DirectSupplementaryState {
            std::mutex mutex;
            std::optional<symbols::ImportResult> imported;
            std::optional<Error> failure;
            std::vector<std::uint8_t> info, abbrev, strings, string_offsets, addresses,
                line_strings, location_lists, locations, range_lists, ranges;
        };
        auto state = std::make_shared<DirectSupplementaryState>();
        const auto load_section = [&](std::string_view name, std::vector<std::uint8_t> &destination) {
            if (const auto *section = debug_section(metadata, name); section && section->size)
                destination = read_debug_bytes(*tracking, metadata, *section, budget, stop);
        };
        load_section(".debug_info", state->info);
        load_section(".debug_abbrev", state->abbrev);
        load_section(".debug_str", state->strings);
        load_section(".debug_str_offsets", state->string_offsets);
        load_section(".debug_addr", state->addresses);
        load_section(".debug_line_str", state->line_strings);
        load_section(".debug_loclists", state->location_lists);
        load_section(".debug_loc", state->locations);
        load_section(".debug_rnglists", state->range_lists);
        load_section(".debug_ranges", state->ranges);
        require(!state->info.empty() && !state->abbrev.empty(),
                "Supplementary ELF has neither DWP indexes nor ordinary DWARF info/abbrev", ErrorCode::unsupported);
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t> *>> direct_relocations;
        const auto add_direct_relocation = [&](std::string_view name, std::vector<std::uint8_t> &bytes) {
            if (const auto *section = debug_section(metadata, name); section && !bytes.empty())
                direct_relocations.emplace_back(static_cast<std::uint32_t>(section - metadata.sections.data()), &bytes);
        };
        add_direct_relocation(".debug_info", state->info);
        add_direct_relocation(".debug_abbrev", state->abbrev);
        add_direct_relocation(".debug_str", state->strings);
        add_direct_relocation(".debug_str_offsets", state->string_offsets);
        add_direct_relocation(".debug_addr", state->addresses);
        add_direct_relocation(".debug_line_str", state->line_strings);
        add_direct_relocation(".debug_loclists", state->location_lists);
        add_direct_relocation(".debug_loc", state->locations);
        add_direct_relocation(".debug_rnglists", state->range_lists);
        add_direct_relocation(".debug_ranges", state->ranges);
        relocate_dwarf_data(metadata, direct_relocations, stop);
        const auto examined = budget.used;
        symbols::DwarfSections dwarf;
        dwarf.source_id = "ELF supplementary .debug_info";
        dwarf.info = state->info;
        dwarf.abbrev = state->abbrev;
        dwarf.strings = state->strings;
        dwarf.string_offsets = state->string_offsets;
        dwarf.addresses = state->addresses;
        dwarf.line_strings = state->line_strings;
        dwarf.location_lists = state->location_lists;
        dwarf.locations = state->locations;
        dwarf.range_lists = state->range_lists;
        dwarf.ranges = state->ranges;
        dwarf.stop = stop;
        dwarf.supplementary_identity = package_identity;
        auto supplementary = [state, dwarf, application_identity, package_identity, stop, examined]
            (const symbols::DwarfSupplementaryIdentity &requested_identity,
                                            std::uint64_t die_offset)
            -> Result<symbols::DwarfSupplementaryType> {
            try {
                require(requested_identity == application_identity &&
                            package_identity.checksum == application_identity.checksum,
                        "supplementary request identity differs from selected ELF object");
                require(die_offset < dwarf.info.size(),
                        "supplementary DIE offset is outside .debug_info", ErrorCode::unsupported);
                std::lock_guard lock(state->mutex);
                if (!state->imported && !state->failure) {
                    auto parsed = symbols::import_dwarf(dwarf);
                    if (parsed) state->imported = std::move(parsed.value());
                    else state->failure = parsed.error();
                }
                if (state->failure) throw Failure{*state->failure};
                const symbols::ImportedType *matched = nullptr;
                for (const auto &type : state->imported->types) {
                    canceled(stop);
                    if (type.origin.record_offset != die_offset) continue;
                    if (matched && matched->type->id() != type.type->id())
                        throw Failure{{ErrorCode::malformed, "supplementary DIE offset resolves to conflicting types"}};
                    matched = &type;
                }
                require(matched && matched->type,
                        "supplementary DIE offset does not identify an imported type", ErrorCode::unsupported);
                return symbols::DwarfSupplementaryType{
                    requested_identity, matched->type, die_offset, examined, true};
            } catch (const Failure &failure) {
                return failure.error;
            } catch (const std::exception &error) {
                return Error{ErrorCode::malformed, error.what()};
            }
        };
        return {std::move(supplementary), {}};
    }
    require((!package->index || package->index->version == 5) &&
                (!package->type_index || package->type_index->version == 5),
            "DWP supplementary references require version-5 package indexes", ErrorCode::unsupported);
    constexpr std::pair<std::uint32_t, std::string_view> names[] = {
        {1, ".debug_info.dwo"}, {3, ".debug_abbrev.dwo"}, {4, ".debug_line.dwo"},
        {5, ".debug_loclists.dwo"}, {6, ".debug_str_offsets.dwo"}, {7, ".debug_macro.dwo"},
        {8, ".debug_rnglists.dwo"}, {9, ".debug_addr.dwo"},
    };
    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t> *>> relocation_buffers;
    const auto add_relocation_buffer = [&](const ElfSection *section, std::vector<std::uint8_t> &bytes) {
        if (!section || bytes.empty()) return;
        const auto index = static_cast<std::uint32_t>(section - metadata.sections.data());
        relocation_buffers.emplace_back(index, &bytes);
    };
    for (const auto &[id, name] : names) {
        canceled(stop);
        if (!package->index && id != 1 && id != 3 && id != 4 && id != 6) continue;
        const auto *section = debug_section(metadata, name);
        if (section && section->size) {
            auto [entry, inserted] = package->sections.emplace(
                id, read_debug_bytes(*tracking, metadata, *section, budget, stop));
            require(inserted, "duplicate DWP supplementary package section ID");
            add_relocation_buffer(section, entry->second);
        } else if (id == 1 || id == 3) {
            throw Failure{{ErrorCode::unsupported, "DWP supplementary package lacks INFO or ABBREV data"}};
        }
    }
    if (const auto *strings = debug_section(metadata, ".debug_str.dwo")) {
        if (strings->size) {
            package->strings = read_debug_bytes(*tracking, metadata, *strings, budget, stop);
            add_relocation_buffer(strings, package->strings);
        }
    }
    if (const auto *strings = debug_section(metadata, ".debug_line_str.dwo")) {
        if (strings->size) {
            package->line_strings = read_debug_bytes(*tracking, metadata, *strings, budget, stop);
            add_relocation_buffer(strings, package->line_strings);
        }
    }
    // Supplementary DWARF forms can point into relocated package sections too.
    // Apply REL/RELA to complete section buffers before the index resolver slices
    // individual CU/TU contributions, exactly as for selected DWP packages.
    relocate_dwarf_data(metadata, relocation_buffers, stop);
    require(budget.used <= max_bytes, "DWP supplementary package exceeds configured byte limit", ErrorCode::resource_limit);
    const auto examined = budget.used;
    std::vector<symbols::DwarfPackageSectionData> package_sections;
    package_sections.reserve(package->sections.size());
    for (const auto &[id, bytes] : package->sections) package_sections.push_back({id, bytes});
    const symbols::DwarfPackageTypeResolutionLimits limits{
        budget.used < max_bytes ? max_bytes - budget.used : 0,
        std::min<std::uint32_t>(max_requests, 4096)};
    symbols::DwarfCrossContributionDieResolver compile_die;
    if (package->index)
        compile_die = symbols::make_dwarf_package_cross_contribution_die_resolver(
            package->index, package_sections, package->strings, package->line_strings, stop,
            limits, metadata.header.order == ByteOrder::little);
    symbols::DwarfTypeSignatureResolver type_signature;
    if (package->type_index)
        type_signature = symbols::make_dwarf_package_type_signature_resolver(
            package->type_index, std::move(package_sections), package->strings, package->line_strings,
            stop, limits);
    auto retained_package = package;
    auto catalog_package = package;
    symbols::DwarfTypeSignatureResolver retained_type_signature;
    if (type_signature) retained_type_signature =
        [type_signature = std::move(type_signature), retained_package = std::move(retained_package)](std::uint64_t signature) {
            return type_signature(signature);
        };
    auto supplementary = [package = std::move(package), type_signature = retained_type_signature,
                          compile_die = std::move(compile_die),
                          application_identity, stop, examined]
        (const symbols::DwarfSupplementaryIdentity &requested_identity, std::uint64_t die_offset)
        -> Result<symbols::DwarfSupplementaryType> {
        try {
        require(requested_identity == application_identity,
                "supplementary request identity differs from selected DWP package");
        // A section offset has meaning only within this checksum-verified
        // supplementary object. Require one owner across both indexes before
        // invoking either bounded resolver; never fall back by error category.
        const symbols::DwarfPackageIndex *owner = nullptr;
        const symbols::DwarfPackageIndexRow *match = nullptr;
        std::size_t column = 0;
        for (const auto &index : {package->index, package->type_index}) {
            if (!index) continue;
            const auto info_column = std::find(index->section_ids.begin(), index->section_ids.end(), 1u);
            require(info_column != index->section_ids.end(), "DWP supplementary index has no INFO column");
            const auto candidate_column = static_cast<std::size_t>(info_column - index->section_ids.begin());
            for (const auto &row : index->rows) {
                canceled(stop);
                if (candidate_column >= row.sections.size()) throw Failure{{ErrorCode::malformed, "invalid DWP supplementary-index row"}};
                const auto &range = row.sections[candidate_column];
                if (die_offset < range.offset || die_offset - range.offset >= range.size) continue;
                if (match) throw Failure{{ErrorCode::malformed, "supplementary DIE offset belongs to ambiguous DWP contributions"}};
                match = &row; owner = index.get(); column = candidate_column;
            }
        }
        require(match != nullptr, "supplementary DIE offset is absent from DWP indexed contributions", ErrorCode::unsupported);
        if (owner->kind == symbols::DwarfPackageIndexKind::compile_units) {
            auto resolved = compile_die(die_offset);
            if (!resolved) throw Failure{resolved.error()};
            const auto &die = resolved.value();
            const auto &range = match->sections[column];
            require(die.identity_verified && die.index_kind == symbols::DwarfPackageIndexKind::compile_units &&
                        die.contribution_signature == match->signature && die.info_section_offset == range.offset &&
                        die.contribution_size == range.size && die.die_offset == die_offset - range.offset,
                    "supplementary CU resolver returned a different contribution or DIE offset");
            require(die.kind == symbols::DwarfReferencedDieKind::type && bool(die.type),
                    "supplementary DIE offset does not identify an imported type", ErrorCode::unsupported);
            return symbols::DwarfSupplementaryType{
                requested_identity, die.type, die_offset, examined, true};
        }
        std::vector<symbols::DwarfPackageSectionData> section_data;
        for (const auto &[id, bytes] : package->sections) section_data.push_back({id, bytes});
        auto contribution = symbols::find_dwarf_package_contribution(*owner, match->signature, section_data, stop);
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
        const auto *range_lists = debug_section(metadata, ".debug_rnglists");
        const auto *ranges = debug_section(metadata, ".debug_ranges");
        const auto *supplementary_strings = debug_section(metadata, ".debug_str_sup");
        const auto *supplementary = debug_section(metadata, ".debug_sup");
        require(abbrev && abbrev->size != 0, ".debug_info has no usable .debug_abbrev section");
        auto info_bytes = read_debug_bytes(storage, metadata, *info, budget, stop);
        auto abbrev_bytes = read_debug_bytes(storage, metadata, *abbrev, budget, stop);
        std::vector<std::uint8_t> string_bytes;
        if (strings && strings->size) string_bytes = read_debug_bytes(storage, metadata, *strings, budget, stop);
        std::vector<std::uint8_t> string_offset_bytes, address_bytes, line_string_bytes, supplementary_string_bytes, location_list_bytes, location_bytes, range_list_bytes, range_bytes;
        if (string_offsets && string_offsets->size) string_offset_bytes = read_debug_bytes(storage, metadata, *string_offsets, budget, stop);
        if (addresses && addresses->size) address_bytes = read_debug_bytes(storage, metadata, *addresses, budget, stop);
        if (line_strings && line_strings->size) line_string_bytes = read_debug_bytes(storage, metadata, *line_strings, budget, stop);
        if (supplementary_strings && supplementary_strings->size) supplementary_string_bytes = read_debug_bytes(storage, metadata, *supplementary_strings, budget, stop);
        std::vector<std::uint8_t> supplementary_bytes;
        if (supplementary && supplementary->size) supplementary_bytes = read_debug_bytes(storage, metadata, *supplementary, budget, stop);
        if (location_lists && location_lists->size) location_list_bytes = read_debug_bytes(storage, metadata, *location_lists, budget, stop);
        if (locations && locations->size) location_bytes = read_debug_bytes(storage, metadata, *locations, budget, stop);
        if (range_lists && range_lists->size) range_list_bytes = read_debug_bytes(storage, metadata, *range_lists, budget, stop);
        if (ranges && ranges->size) range_bytes = read_debug_bytes(storage, metadata, *ranges, budget, stop);
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t> *>> relocation_buffers;
        const auto add_reloc_buffer = [&](const ElfSection *section, std::vector<std::uint8_t> &bytes) {
            if (section && !bytes.empty()) {
                const auto index = static_cast<std::uint32_t>(section - metadata.sections.data());
                relocation_buffers.emplace_back(index, &bytes);
            }
        };
        add_reloc_buffer(info, info_bytes); add_reloc_buffer(abbrev, abbrev_bytes);
        add_reloc_buffer(strings, string_bytes); add_reloc_buffer(string_offsets, string_offset_bytes);
        add_reloc_buffer(addresses, address_bytes); add_reloc_buffer(line_strings, line_string_bytes);
        add_reloc_buffer(location_lists, location_list_bytes); add_reloc_buffer(locations, location_bytes);
        add_reloc_buffer(range_lists, range_list_bytes); add_reloc_buffer(ranges, range_bytes);
        relocate_dwarf_data(metadata, relocation_buffers, stop);
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
        dwarf_sections.range_lists = range_list_bytes;
        dwarf_sections.ranges = range_bytes;
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
        if (dwarf_sections.supplementary_identity.present)
            metadata.dwarf_supplementary_identity = dwarf_sections.supplementary_identity;
        require(!supplementary_package || dwarf_sections.supplementary_identity.present,
                "Explicit supplementary DWP was supplied but the ELF has no .debug_sup descriptor",
                ErrorCode::unsupported);
        auto selected_supplementary_resolver = supplementary_resolver;
        std::shared_ptr<const DwarfPackage> supplementary_type_package;
        if (supplementary_package && dwarf_sections.supplementary_identity.present) {
            auto package_resolvers = read_supplementary_object_resolver(
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
Result<ElfDwpSectionContribution> read_elf_dwp_section_contribution(
    const ByteStorage &storage, symbols::DwarfPackageIndexKind index_kind,
    std::uint64_t signature, std::uint32_t section_id, std::stop_token stop,
    std::uint64_t max_bytes) {
    using namespace elf_detail;
    try {
        require(max_bytes != 0, "DWP contribution byte budget must be nonzero", ErrorCode::invalid_argument);
        ElfMetadata metadata;
        metadata.header = take(read_elf_header(storage, stop));
        require(metadata.header.object_type == 1, "DWP input is not an ELF relocatable object", ErrorCode::unsupported);
        Budget budget;
        budget.limit = std::min(max_bytes, metadata_limit);
        read_tables(storage, metadata, budget, stop);

        const bool compile_units = index_kind == symbols::DwarfPackageIndexKind::compile_units;
        require(compile_units || index_kind == symbols::DwarfPackageIndexKind::type_units,
                "invalid DWP package index kind", ErrorCode::invalid_argument);
        const auto *index_section = compile_units
            ? optional_debug_section(metadata, ".debug_cu_index", ".debug_cu_index.dwo")
            : optional_debug_section(metadata, ".debug_tu_index", ".debug_tu_index.dwo");
        require(index_section && index_section->size, "DWP input has no requested package index", ErrorCode::unsupported);
        auto index = read_package_index(storage, metadata, *index_section, index_kind, budget, stop);

        std::string_view section_name;
        if (index->version == 2) {
            switch (section_id) {
            case 1: section_name = ".debug_info.dwo"; break;
            case 2: section_name = ".debug_types.dwo"; break;
            case 3: section_name = ".debug_abbrev.dwo"; break;
            case 4: section_name = ".debug_line.dwo"; break;
            case 5: section_name = ".debug_loc.dwo"; break;
            case 6: section_name = ".debug_str_offsets.dwo"; break;
            case 7: section_name = ".debug_macinfo.dwo"; break;
            case 8: section_name = ".debug_macro.dwo"; break;
            default: throw Failure{{ErrorCode::unsupported, "unsupported DWP v2 section ID"}};
            }
        } else if (index->version == 5) {
            switch (section_id) {
            case 1: section_name = ".debug_info.dwo"; break;
            case 3: section_name = ".debug_abbrev.dwo"; break;
            case 4: section_name = ".debug_line.dwo"; break;
            case 5: section_name = ".debug_loclists.dwo"; break;
            case 6: section_name = ".debug_str_offsets.dwo"; break;
            case 7: section_name = ".debug_macro.dwo"; break;
            case 8: section_name = ".debug_rnglists.dwo"; break;
            case 9: section_name = ".debug_addr.dwo"; break;
            default: throw Failure{{ErrorCode::unsupported, "unsupported DWP v5 section ID"}};
            }
        } else {
            throw Failure{{ErrorCode::unsupported, "unsupported DWP package index version"}};
        }

        const auto column_it = std::find(index->section_ids.begin(), index->section_ids.end(), section_id);
        require(column_it != index->section_ids.end(), "DWP index has no requested contribution column", ErrorCode::unsupported);
        const auto column = static_cast<std::size_t>(column_it - index->section_ids.begin());
        const symbols::DwarfPackageIndexRow *row = nullptr;
        for (std::size_t i = 0; i < index->rows.size(); ++i) {
            if ((i & 0x3fffu) == 0) canceled(stop);
            if (index->rows[i].signature != signature) continue;
            require(row == nullptr, "DWP index contains duplicate package key rows");
            row = &index->rows[i];
        }
        require(row != nullptr, "requested key is absent from DWP package index", ErrorCode::unsupported);
        require(column < row->sections.size(), "DWP contribution row has invalid shape");
        const auto &range = row->sections[column];
        require(range.section_id == section_id && range.size != 0,
                "requested DWP row has no contribution", ErrorCode::unsupported);

        const auto *contribution_section = optional_debug_section(metadata, section_name);
        require(contribution_section && contribution_section->size,
                "DWP contribution section is absent", ErrorCode::unsupported);
        auto section_bytes = read_debug_bytes(storage, metadata, *contribution_section, budget, stop);
        require(range.offset <= section_bytes.size() && range.size <= section_bytes.size() - range.offset,
                "DWP contribution exceeds its package section", ErrorCode::malformed);

        std::vector<std::uint8_t> strings, line_strings;
        const auto *string_section = optional_debug_section(metadata, ".debug_str.dwo");
        const auto *line_string_section = optional_debug_section(metadata, ".debug_line_str.dwo");
        if (string_section && string_section->size)
            strings = read_debug_bytes(storage, metadata, *string_section, budget, stop);
        if (line_string_section && line_string_section->size)
            line_strings = read_debug_bytes(storage, metadata, *line_string_section, budget, stop);
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t> *>> relocation_buffers;
        relocation_buffers.emplace_back(static_cast<std::uint32_t>(contribution_section - metadata.sections.data()), &section_bytes);
        if (string_section && !strings.empty())
            relocation_buffers.emplace_back(static_cast<std::uint32_t>(string_section - metadata.sections.data()), &strings);
        if (line_string_section && !line_strings.empty())
            relocation_buffers.emplace_back(static_cast<std::uint32_t>(line_string_section - metadata.sections.data()), &line_strings);
        relocate_dwarf_data(metadata, relocation_buffers, stop);

        budget.include(range.size);
        budget.include(strings.size());
        budget.include(line_strings.size());
        ElfDwpSectionContribution result;
        result.signature = signature;
        result.index_kind = index_kind;
        result.package_index_version = index->version;
        result.section_id = section_id;
        result.package_section_offset = range.offset;
        const auto begin = static_cast<std::size_t>(range.offset);
        const auto end = begin + static_cast<std::size_t>(range.size);
        result.bytes.assign(section_bytes.begin() + static_cast<std::ptrdiff_t>(begin),
                            section_bytes.begin() + static_cast<std::ptrdiff_t>(end));
        result.strings = std::move(strings);
        result.line_strings = std::move(line_strings);
        return result;
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate bounded DWP contribution"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "DWP contribution exceeds container limit"};
    }
}

Result<ElfDwpMacroContribution> read_elf_dwp_macro_contribution(
    const ByteStorage &storage, symbols::DwarfPackageIndexKind index_kind,
    std::uint64_t signature, std::stop_token stop, std::uint64_t max_bytes) {
    using namespace elf_detail;
    try {
        require(max_bytes != 0, "DWP macro contribution byte budget must be nonzero", ErrorCode::invalid_argument);
        ElfMetadata metadata;
        metadata.header = take(read_elf_header(storage, stop));
        require(metadata.header.object_type == 1, "DWP input is not an ELF relocatable object", ErrorCode::unsupported);
        Budget budget;
        budget.limit = std::min(max_bytes, metadata_limit);
        read_tables(storage, metadata, budget, stop);

        const bool compile_units = index_kind == symbols::DwarfPackageIndexKind::compile_units;
        require(compile_units || index_kind == symbols::DwarfPackageIndexKind::type_units,
                "invalid DWP package index kind", ErrorCode::invalid_argument);
        const auto *index_section = compile_units
            ? optional_debug_section(metadata, ".debug_cu_index", ".debug_cu_index.dwo")
            : optional_debug_section(metadata, ".debug_tu_index", ".debug_tu_index.dwo");
        require(index_section && index_section->size, "DWP input has no requested package index", ErrorCode::unsupported);
        auto index = read_package_index(storage, metadata, *index_section, index_kind, budget, stop);
        const auto macro_id = index->version == 2 ? 8u : 7u;
        const auto macro_column = std::find(index->section_ids.begin(), index->section_ids.end(), macro_id);
        require(macro_column != index->section_ids.end(), "DWP index has no indexed macro contribution column",
                ErrorCode::unsupported);
        const auto column = static_cast<std::size_t>(macro_column - index->section_ids.begin());
        const symbols::DwarfPackageIndexRow *row = nullptr;
        for (std::size_t i = 0; i < index->rows.size(); ++i) {
            if ((i & 0x3fffu) == 0) canceled(stop);
            if (index->rows[i].signature != signature) continue;
            require(row == nullptr, "DWP index contains duplicate package key rows");
            row = &index->rows[i];
        }
        require(row != nullptr, "requested key is absent from DWP package index", ErrorCode::unsupported);
        require(column < row->sections.size(), "DWP macro contribution row has invalid shape");
        const auto &range = row->sections[column];
        require(range.section_id == macro_id && range.size != 0, "requested DWP row has no macro contribution",
                ErrorCode::unsupported);

        const auto macro_name = ".debug_macro.dwo";
        const auto *macro_section = debug_section(metadata, macro_name);
        require(macro_section && macro_section->size, "DWP macro section is absent", ErrorCode::unsupported);
        auto macro_bytes = read_debug_bytes(storage, metadata, *macro_section, budget, stop);
        require(range.offset <= macro_bytes.size() && range.size <= macro_bytes.size() - range.offset,
                "DWP macro contribution exceeds its package section", ErrorCode::malformed);

        std::vector<std::uint8_t> strings, line_strings;
        const auto *string_section = optional_debug_section(metadata, ".debug_str.dwo");
        const auto *line_string_section = optional_debug_section(metadata, ".debug_line_str.dwo");
        if (string_section && string_section->size)
            strings = read_debug_bytes(storage, metadata, *string_section, budget, stop);
        if (line_string_section && line_string_section->size)
            line_strings = read_debug_bytes(storage, metadata, *line_string_section, budget, stop);
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t> *>> relocation_buffers;
        const auto add_relocation_buffer = [&](const ElfSection *section, std::vector<std::uint8_t> &bytes) {
            if (!section || bytes.empty()) return;
            relocation_buffers.emplace_back(static_cast<std::uint32_t>(section - metadata.sections.data()), &bytes);
        };
        add_relocation_buffer(macro_section, macro_bytes);
        add_relocation_buffer(string_section, strings);
        add_relocation_buffer(line_string_section, line_strings);
        relocate_dwarf_data(metadata, relocation_buffers, stop);

        budget.include(range.size);
        budget.include(strings.size());
        budget.include(line_strings.size());
        ElfDwpMacroContribution result;
        result.signature = signature;
        result.index_kind = index_kind;
        result.package_index_version = index->version;
        result.section_id = macro_id;
        result.package_section_offset = range.offset;
        const auto begin = static_cast<std::size_t>(range.offset);
        const auto end = begin + static_cast<std::size_t>(range.size);
        result.bytes.assign(macro_bytes.begin() + static_cast<std::ptrdiff_t>(begin),
                            macro_bytes.begin() + static_cast<std::ptrdiff_t>(end));
        result.strings = std::move(strings);
        result.line_strings = std::move(line_strings);
        return result;
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate DWP macro contribution"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "DWP macro contribution exceeds container limit"};
    }
}

Result<ElfDwpLineContribution> read_elf_dwp_line_contribution(
    const ByteStorage &storage, symbols::DwarfPackageIndexKind index_kind,
    std::uint64_t signature, std::stop_token stop, std::uint64_t max_bytes) {
    using namespace elf_detail;
    try {
        require(max_bytes != 0, "DWP line contribution byte budget must be nonzero", ErrorCode::invalid_argument);
        ElfMetadata metadata;
        metadata.header = take(read_elf_header(storage, stop));
        require(metadata.header.object_type == 1, "DWP input is not an ELF relocatable object", ErrorCode::unsupported);
        Budget budget;
        budget.limit = std::min(max_bytes, metadata_limit);
        read_tables(storage, metadata, budget, stop);

        const bool compile_units = index_kind == symbols::DwarfPackageIndexKind::compile_units;
        require(compile_units || index_kind == symbols::DwarfPackageIndexKind::type_units,
                "invalid DWP package index kind", ErrorCode::invalid_argument);
        const auto *index_section = compile_units
            ? optional_debug_section(metadata, ".debug_cu_index", ".debug_cu_index.dwo")
            : optional_debug_section(metadata, ".debug_tu_index", ".debug_tu_index.dwo");
        require(index_section && index_section->size, "DWP input has no requested package index", ErrorCode::unsupported);
        auto index = read_package_index(storage, metadata, *index_section, index_kind, budget, stop);
        constexpr std::uint32_t line_id = 4;
        const auto line_column = std::find(index->section_ids.begin(), index->section_ids.end(), line_id);
        require(line_column != index->section_ids.end(), "DWP index has no indexed line contribution column",
                ErrorCode::unsupported);
        const auto column = static_cast<std::size_t>(line_column - index->section_ids.begin());
        const symbols::DwarfPackageIndexRow *row = nullptr;
        for (std::size_t i = 0; i < index->rows.size(); ++i) {
            if ((i & 0x3fffu) == 0) canceled(stop);
            if (index->rows[i].signature != signature) continue;
            require(row == nullptr, "DWP index contains duplicate package key rows");
            row = &index->rows[i];
        }
        require(row != nullptr, "requested key is absent from DWP package index", ErrorCode::unsupported);
        require(column < row->sections.size(), "DWP line contribution row has invalid shape");
        const auto &range = row->sections[column];
        require(range.section_id == line_id && range.size != 0, "requested DWP row has no line contribution",
                ErrorCode::unsupported);

        const auto *line_section = optional_debug_section(metadata, ".debug_line.dwo");
        require(line_section && line_section->size, "DWP line section is absent", ErrorCode::unsupported);
        auto line_bytes = read_debug_bytes(storage, metadata, *line_section, budget, stop);
        require(range.offset <= line_bytes.size() && range.size <= line_bytes.size() - range.offset,
                "DWP line contribution exceeds its package section", ErrorCode::malformed);

        std::vector<std::uint8_t> strings, line_strings;
        const auto *string_section = optional_debug_section(metadata, ".debug_str.dwo");
        const auto *line_string_section = optional_debug_section(metadata, ".debug_line_str.dwo");
        if (string_section && string_section->size)
            strings = read_debug_bytes(storage, metadata, *string_section, budget, stop);
        if (line_string_section && line_string_section->size)
            line_strings = read_debug_bytes(storage, metadata, *line_string_section, budget, stop);
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t> *>> relocation_buffers;
        relocation_buffers.emplace_back(static_cast<std::uint32_t>(line_section - metadata.sections.data()), &line_bytes);
        if (string_section && !strings.empty())
            relocation_buffers.emplace_back(static_cast<std::uint32_t>(string_section - metadata.sections.data()), &strings);
        if (line_string_section && !line_strings.empty())
            relocation_buffers.emplace_back(static_cast<std::uint32_t>(line_string_section - metadata.sections.data()), &line_strings);
        relocate_dwarf_data(metadata, relocation_buffers, stop);

        budget.include(range.size);
        budget.include(strings.size());
        budget.include(line_strings.size());
        ElfDwpLineContribution result;
        result.signature = signature;
        result.index_kind = index_kind;
        result.package_index_version = index->version;
        result.section_id = line_id;
        result.package_section_offset = range.offset;
        const auto begin = static_cast<std::size_t>(range.offset);
        const auto end = begin + static_cast<std::size_t>(range.size);
        result.bytes.assign(line_bytes.begin() + static_cast<std::ptrdiff_t>(begin),
                            line_bytes.begin() + static_cast<std::ptrdiff_t>(end));
        result.strings = std::move(strings);
        result.line_strings = std::move(line_strings);
        return result;
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate DWP line contribution"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "DWP line contribution exceeds container limit"};
    }
}

Result<std::vector<ElfDwpSourceLine>> parse_elf_dwp_line_contribution(
    const ElfDwpLineContribution &contribution, std::uint8_t address_size, bool little_endian,
    std::stop_token stop, std::size_t max_rows, std::uint64_t max_bytes) {
    using namespace elf_detail;
    try {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "DWP line import canceled"};
        require(contribution.section_id == 4, "DWP source-line input is not a DW_SECT_LINE contribution",
                ErrorCode::invalid_argument);
        require(contribution.package_index_version == 2 || contribution.package_index_version == 5,
                "unsupported DWP source-line package index version", ErrorCode::unsupported);
        require(address_size == 4 || address_size == 8,
                "DWP source-line address size must be 4 or 8", ErrorCode::invalid_argument);
        require(max_rows != 0 && max_rows <= 1'000'000,
                "DWP source-line row limit must be 1 through one million", ErrorCode::resource_limit);
        require(max_bytes != 0 && max_bytes <= 64u * 1024u * 1024u,
                "DWP source-line byte limit exceeds 64 MiB", ErrorCode::resource_limit);
        std::uint64_t input_bytes = 0;
        for (const auto size : {contribution.bytes.size(), contribution.strings.size(),
                                contribution.line_strings.size()}) {
            require(size <= max_bytes - input_bytes,
                    "DWP line contribution and shared strings exceed byte limit", ErrorCode::resource_limit);
            input_bytes += size;
        }
        symbols::DwarfLineSections sections;
        sections.source_id = "ELF DWP line contribution " + std::to_string(contribution.signature);
        sections.line = contribution.bytes;
        sections.address_size = address_size;
        sections.little_endian = little_endian;
        sections.max_rows = max_rows;
        sections.stop = stop;
        sections.strings = contribution.strings;
        sections.line_strings = contribution.line_strings;
        auto units = symbols::import_dwarf_line_v2_v5(sections);
        if (!units) return units.error();

        std::vector<ElfDwpSourceLine> result;
        std::uint64_t output_bytes = 0;
        std::size_t row_count = 0;
        for (std::size_t unit_index = 0; unit_index < units.value().size(); ++unit_index) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "DWP line import canceled"};
            const auto &unit = units.value()[unit_index];
            require(unit_index <= UINT32_MAX, "DWP line unit index exceeds 32-bit range", ErrorCode::resource_limit);
            for (const auto &row : unit.rows) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "DWP line import canceled"};
                require(row_count < max_rows, "DWP source-line output exceeds row limit", ErrorCode::resource_limit);
                require(row.file != 0 && row.file <= unit.files.size(),
                        "DWP source-line row refers to an absent file", ErrorCode::malformed);
                const auto &file = unit.files[static_cast<std::size_t>(row.file - 1)];
                const auto record_size = sizeof(ElfDwpSourceLine) + file.name.size();
                require(output_bytes <= max_bytes - input_bytes &&
                            record_size <= max_bytes - input_bytes - output_bytes,
                        "DWP source-line output exceeds byte limit", ErrorCode::resource_limit);
                output_bytes += record_size;
                result.push_back({contribution.signature, contribution.index_kind,
                    contribution.package_index_version, contribution.package_section_offset,
                    static_cast<std::uint32_t>(unit_index), unit.version, row.address, file.directory,
                    row.column, row.line, file.name, row.end_sequence});
                ++row_count;
            }
        }
        return result;
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate bounded DWP source-line rows"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "DWP source-line output exceeds container limit"};
    }
}

Result<symbols::ImportResult> import_elf_dwo(const ByteStorage &storage,
                                              const symbols::DwarfSplitUnitRequest &request,
                                              std::stop_token stop,
                                              std::uint64_t max_metadata_bytes,
                                              symbols::DwarfTypeSignatureResolver type_signature_resolver,
                                              symbols::DwarfSupplementaryIdentity supplementary_identity,
                                              symbols::DwarfSupplementaryTypeResolver supplementary_type_resolver) {
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
            location_lists, range_lists, ranges, line_bytes;
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t> *>> relocation_buffers;
        const auto add_reloc_buffer = [&](const ElfSection *section, std::vector<std::uint8_t> &bytes) {
            if (section && !bytes.empty()) {
                const auto index = static_cast<std::uint32_t>(section - metadata.sections.data());
                relocation_buffers.emplace_back(index, &bytes);
            }
        };
        add_reloc_buffer(info, info_bytes);
        add_reloc_buffer(abbrev, abbrev_bytes);
        dwarf.info = info_bytes;
        dwarf.abbrev = abbrev_bytes;
        dwarf.stop = stop;
        dwarf.expected_split_dwo_id = request.dwo_id;
        if (request.address_size) dwarf.expected_split_address_size = request.address_size;
        dwarf.type_signature_resolver = std::move(type_signature_resolver);
        dwarf.supplementary_identity = std::move(supplementary_identity);
        dwarf.supplementary_type_resolver = std::move(supplementary_type_resolver);
        const auto copy_optional = [&](std::string_view name, std::vector<std::uint8_t> &target) {
            if (const auto *section = debug_section(metadata, name); section && section->size) {
                target = read_debug_bytes(storage, metadata, *section, budget, stop);
                add_reloc_buffer(section, target);
            }
        };
        copy_optional(".debug_str.dwo", strings);
        copy_optional(".debug_str_offsets.dwo", string_offsets);
        copy_optional(".debug_addr.dwo", addresses);
        copy_optional(".debug_line_str.dwo", line_strings);
        copy_optional(".debug_loclists.dwo", location_lists);
        copy_optional(".debug_rnglists.dwo", range_lists);
        copy_optional(".debug_ranges.dwo", ranges);
        copy_optional(".debug_line.dwo", line_bytes);
        relocate_dwarf_data(metadata, relocation_buffers, stop);
        dwarf.info = info_bytes;
        dwarf.abbrev = abbrev_bytes;
        dwarf.strings = strings;
        dwarf.string_offsets = string_offsets;
        dwarf.addresses = addresses;
        dwarf.line_strings = line_strings;
        dwarf.location_lists = location_lists;
        dwarf.range_lists = range_lists;
        dwarf.ranges = ranges;

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
                                                       symbols::DwarfTypeSignatureResolver type_signature_resolver,
                                                       symbols::DwarfSupplementaryIdentity supplementary_identity,
                                                       symbols::DwarfSupplementaryTypeResolver supplementary_type_resolver) {
    return [resolver = std::move(resolver), stop, max_metadata_bytes,
            type_signature_resolver = std::move(type_signature_resolver),
            supplementary_identity = std::move(supplementary_identity),
            supplementary_type_resolver = std::move(supplementary_type_resolver)]
           (const symbols::DwarfSplitUnitRequest &request)
               -> Result<std::shared_ptr<symbols::ImportResult>> {
        if (!resolver)
            return Error{ErrorCode::invalid_argument, "ELF DWO storage resolver is not configured"};
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF DWO import canceled"};
        auto storage = resolver(request);
        if (!storage) return storage.error();
        if (!storage.value()) return Error{ErrorCode::invalid_argument, "ELF DWO resolver returned null storage"};
        auto imported = import_elf_dwo(*storage.value(), request, stop, max_metadata_bytes,
                                       type_signature_resolver, supplementary_identity,
                                       supplementary_type_resolver);
        if (!imported) return imported.error();
        return std::make_shared<symbols::ImportResult>(std::move(imported.value()));
    };
}

Result<symbols::DwarfSplitUnitResolver> make_elf_dwo_directory_resolver(
    std::filesystem::path directory, std::stop_token stop, ElfDwoDirectoryResolverLimits limits) {
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF DWO directory resolver creation canceled"};
    if (directory.empty() || !limits.max_requests || !limits.max_file_bytes ||
        !limits.max_total_file_bytes || !limits.max_metadata_bytes_per_dwo)
        return Error{ErrorCode::invalid_argument, "ELF DWO directory resolver requires a directory and nonzero limits"};

    std::error_code ec;
    const auto root_status = std::filesystem::status(directory, ec);
    if (ec || !std::filesystem::is_directory(root_status))
        return Error{ErrorCode::invalid_argument, "ELF DWO search root is not an accessible directory"};
    const auto canonical_root = std::filesystem::canonical(directory, ec);
    if (ec) return Error{ErrorCode::io, "Cannot canonicalize ELF DWO search root: " + ec.message()};

    struct DirectoryState {
        std::mutex mutex;
        std::uint32_t requests = 0;
        std::uint64_t total_file_bytes = 0;
        std::set<std::uint64_t> dwo_ids;
    };
    auto state = std::make_shared<DirectoryState>();
    ElfDwoStorageResolver storage_resolver =
        [canonical_root, stop, limits, state](const symbols::DwarfSplitUnitRequest &request)
            -> Result<std::shared_ptr<const ByteStorage>> {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "ELF DWO discovery canceled"};
        if (!request.dwo_id || (request.address_size != 4 && request.address_size != 8))
            return Error{ErrorCode::invalid_argument, "ELF DWO lookup requires an exact ID and 4- or 8-byte address size"};
        {
            std::lock_guard lock(state->mutex);
            if (state->requests >= limits.max_requests)
                return Error{ErrorCode::resource_limit, "ELF DWO directory resolver request limit exceeded"};
            ++state->requests;
            if (!state->dwo_ids.insert(request.dwo_id).second)
                return Error{ErrorCode::malformed, "ELF DWO directory resolver received a duplicate DWO ID"};
        }
        const auto separator = request.dwo_name.find_last_of("/\\");
        const std::string_view leaf = separator == std::string::npos
            ? std::string_view(request.dwo_name)
            : std::string_view(request.dwo_name).substr(separator + 1);
        if (leaf.empty() || leaf == "." || leaf == ".." || leaf.find(':') != std::string_view::npos ||
            leaf.find('\0') != std::string_view::npos)
            return Error{ErrorCode::unsupported, "DW_AT_dwo_name has no safe basename for caller-scoped discovery"};
        auto extension = leaf.substr(leaf.find_last_of('.') == std::string_view::npos
            ? leaf.size() : leaf.find_last_of('.'));
        std::string normalized_extension(extension);
        std::transform(normalized_extension.begin(), normalized_extension.end(), normalized_extension.begin(),
            [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        if (normalized_extension != ".dwo")
            return Error{ErrorCode::unsupported, "Caller-scoped ELF DWO discovery accepts only `.dwo` basenames"};

        std::filesystem::path leaf_path;
        try { leaf_path = std::filesystem::u8path(leaf.begin(), leaf.end()); }
        catch (const std::filesystem::filesystem_error &error) {
            return Error{ErrorCode::invalid_argument, "Invalid DW_AT_dwo_name basename: " + std::string(error.what())};
        }
        if (leaf_path.has_root_name() || leaf_path.has_root_directory() || leaf_path.has_parent_path() ||
            leaf_path.filename() != leaf_path)
            return Error{ErrorCode::unsupported, "DW_AT_dwo_name basename is not a single path component"};

        const auto candidate = canonical_root / leaf_path;
        std::error_code file_error;
        const auto status = std::filesystem::symlink_status(candidate, file_error);
        if (file_error == std::errc::no_such_file_or_directory ||
            (!file_error && status.type() == std::filesystem::file_type::not_found))
            return Error{ErrorCode::unsupported, "No matching `.dwo` file exists in the caller-selected directory"};
        if (file_error) return Error{ErrorCode::io, "Cannot inspect ELF DWO candidate: " + file_error.message()};
        if (std::filesystem::is_symlink(status) || !std::filesystem::is_regular_file(status))
            return Error{ErrorCode::unsupported, "ELF DWO candidate must be a regular non-symlink file"};
        const auto size = std::filesystem::file_size(candidate, file_error);
        if (file_error) return Error{ErrorCode::io, "Cannot size ELF DWO candidate: " + file_error.message()};
        if (size > limits.max_file_bytes)
            return Error{ErrorCode::resource_limit, "ELF DWO candidate exceeds the configured file-size limit"};
        const auto canonical_candidate = std::filesystem::canonical(candidate, file_error);
        if (file_error || canonical_candidate.parent_path() != canonical_root)
            return Error{ErrorCode::unsupported, "ELF DWO candidate resolves outside the caller-selected directory"};
        auto opened = FileStorage::open(canonical_candidate);
        if (!opened) return opened.error();
        if (opened.value()->size() > limits.max_file_bytes)
            return Error{ErrorCode::resource_limit, "Opened ELF DWO exceeds the configured file-size limit"};
        {
            std::lock_guard lock(state->mutex);
            if (opened.value()->size() > limits.max_total_file_bytes - state->total_file_bytes)
                return Error{ErrorCode::resource_limit, "ELF DWO aggregate file-size limit exceeded"};
            state->total_file_bytes += opened.value()->size();
        }
        return std::static_pointer_cast<const ByteStorage>(opened.value());
    };
    return make_elf_dwo_resolver(std::move(storage_resolver), stop, limits.max_metadata_bytes_per_dwo);
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
