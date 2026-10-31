#pragma once
#include "hexlab/analysis/pe_module_dependencies.hpp"
#include "hexlab/image/metadata.hpp"
#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <map>
#include <ostream>
#include <set>
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

// A PE import can only bind to a module with the same process ABI. Keep the
// check conservative: unknown machine IDs remain unresolved by this filter,
// while known concrete machine/optional-header mismatches are not presented
// as valid symbol providers. Mixed ARM64EC/ARM64X compatibility needs loader
// metadata beyond the single COFF machine value and is therefore not inferred.
inline std::optional<std::string> pe_abi_incompatibility(const ImageMetadata &importer,
                                                        const ImageMetadata &provider) {
    switch (classify_pe_module_compatibility(importer, provider)) {
    case PeModuleCompatibility::compatible: return std::nullopt;
    case PeModuleCompatibility::not_pe: return "PE format";
    case PeModuleCompatibility::machine_mismatch: return "different COFF machine types";
    case PeModuleCompatibility::optional_header_mismatch: return "PE32/PE32+ optional-header mismatch";
    }
    return "PE compatibility could not be classified";
}

struct PeExportResolution {
    enum class Status { resolved, missing_module, ambiguous_module, unsupported_module,
                        incompatible_module, missing_export, ambiguous_export,
                        malformed_forwarder, cycle, depth_limit } status;
    const SuppliedModule *provider = nullptr;
    const ExportSymbol *symbol = nullptr;
    std::vector<std::string> route;
    std::string incompatibility;
};

inline PeExportResolution resolve_pe_export(const std::vector<SuppliedModule> &modules,
                                            const SuppliedModule &initial_provider,
                                            const ImageMetadata &importer_metadata,
                                            const std::optional<std::string> &initial_name,
                                            const std::optional<std::uint16_t> &initial_ordinal) {
    constexpr std::size_t max_forwarder_hops = 32;
    PeExportResolution result{PeExportResolution::Status::missing_export};
    const SuppliedModule *provider = &initial_provider;
    auto name = initial_name;
    std::optional<std::uint32_t> ordinal = initial_ordinal
        ? std::optional<std::uint32_t>(*initial_ordinal) : std::nullopt;
    std::set<std::pair<std::size_t, std::string>> visited;
    for (std::size_t hop = 0; hop <= max_forwarder_hops; ++hop) {
        if (!provider->metadata || !is_pe_module(*provider->metadata)) {
            result.status = PeExportResolution::Status::unsupported_module;
            return result;
        }
        const auto provider_index = static_cast<std::size_t>(provider - modules.data());
        const std::string symbol_key = name ? "n:" + *name : "o:" + std::to_string(ordinal.value_or(0));
        if (!visited.emplace(provider_index, symbol_key).second) {
            result.status = PeExportResolution::Status::cycle;
            return result;
        }
        result.route.push_back(module_leaf(provider->path) + "!" +
            (name ? *name : "#" + std::to_string(ordinal.value_or(0))));
        std::vector<const ExportSymbol *> matches;
        for (const auto &exported : provider->metadata->exports) {
            if ((name && exported.name && *name == *exported.name) ||
                (ordinal && *ordinal == exported.ordinal)) matches.push_back(&exported);
        }
        if (matches.empty()) {
            result.status = PeExportResolution::Status::missing_export;
            return result;
        }
        if (matches.size() != 1) {
            result.status = PeExportResolution::Status::ambiguous_export;
            return result;
        }
        const auto *exported = matches.front();
        if (!exported->forwarder) {
            result.status = PeExportResolution::Status::resolved;
            result.provider = provider;
            result.symbol = exported;
            return result;
        }
        if (hop == max_forwarder_hops) {
            result.status = PeExportResolution::Status::depth_limit;
            return result;
        }

        const auto &forwarder = *exported->forwarder;
        // A module component can itself contain ".dll". Prefer that delimiter
        // before falling back to the first dot in "module.symbol".
        std::size_t delimiter = std::string::npos;
        for (std::size_t pos = 0; pos + 5 <= forwarder.size(); ++pos) {
            if (forwarder[pos] == '.' &&
                std::tolower(static_cast<unsigned char>(forwarder[pos + 1])) == 'd' &&
                std::tolower(static_cast<unsigned char>(forwarder[pos + 2])) == 'l' &&
                std::tolower(static_cast<unsigned char>(forwarder[pos + 3])) == 'l' &&
                forwarder[pos + 4] == '.') {
                delimiter = pos + 4;
                break;
            }
        }
        if (delimiter == std::string::npos) delimiter = forwarder.find('.');
        if (delimiter == std::string::npos || delimiter == 0 || delimiter + 1 >= forwarder.size() ||
            forwarder.find_first_of("/\\:") != std::string::npos || forwarder.find('\0') != std::string::npos) {
            result.status = PeExportResolution::Status::malformed_forwarder;
            return result;
        }
        auto target_leaf = module_leaf(forwarder.substr(0, delimiter));
        if (target_leaf.find('.') == std::string::npos) target_leaf += ".dll";
        std::vector<const SuppliedModule *> targets;
        for (const auto &candidate : modules)
            if (candidate.metadata && module_leaf(candidate.path) == target_leaf)
                targets.push_back(&candidate);
        if (targets.empty()) {
            result.status = PeExportResolution::Status::missing_module;
            return result;
        }
        if (targets.size() != 1) {
            result.status = PeExportResolution::Status::ambiguous_module;
            return result;
        }
        provider = targets.front();
        if (is_pe_module(*provider->metadata)) {
            const auto mismatch = pe_abi_incompatibility(importer_metadata, *provider->metadata);
            if (mismatch) {
                result.status = PeExportResolution::Status::incompatible_module;
                result.incompatibility = *mismatch;
                return result;
            }
        }
        const auto target = std::string_view(forwarder).substr(delimiter + 1);
        name.reset();
        ordinal.reset();
        if (target.front() == '#') {
            std::uint32_t value = 0;
            const auto digits = target.substr(1);
            const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), value);
            if (digits.empty() || parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size()) {
                result.status = PeExportResolution::Status::malformed_forwarder;
                return result;
            }
            ordinal = value;
        } else {
            name = std::string(target);
        }
    }
    result.status = PeExportResolution::Status::depth_limit;
    return result;
}

inline std::optional<std::string> elf_abi_incompatibility(const ElfHeader &importer,
                                                          const ElfHeader &provider) {
    if (importer.is_64 != provider.is_64 || importer.order != provider.order ||
        importer.machine != provider.machine)
        return "ELF class, byte order, or machine";
    // OSABI 0 is the generic System V value used by many Linux and BSD
    // binaries. Treat it as unspecified; two conflicting concrete tags are
    // strong evidence that these objects target different runtime ABIs.
    if (importer.os_abi != 0 && provider.os_abi != 0 && importer.os_abi != provider.os_abi)
        return "conflicting concrete OSABI tags";
    // The RISC-V psABI requires matching FLOAT_ABI, RVE, and RV64ILP32
    // fields when objects are combined. RVC and TSO are mergeable fields,
    // so differing values there do not make supplied modules incompatible.
    constexpr std::uint16_t em_riscv = 243;
    if (importer.machine == em_riscv) {
        constexpr std::uint32_t float_abi_mask = 0x0006;
        constexpr std::uint32_t rve_mask = 0x0008;
        constexpr std::uint32_t rv64ilp32_mask = 0x0020;
        if ((importer.flags & float_abi_mask) != (provider.flags & float_abi_mask))
            return "conflicting RISC-V floating-point ABI flags";
        if ((importer.flags & rve_mask) != (provider.flags & rve_mask))
            return "conflicting RISC-V RVE ABI flags";
        if ((importer.flags & rv64ilp32_mask) != (provider.flags & rv64ilp32_mask))
            return "conflicting RISC-V RV64ILP32 ABI flags";
    }
    constexpr std::uint16_t em_arm = 40;
    if (importer.machine == em_arm) {
        constexpr std::uint32_t eabi_version_mask = 0xff000000;
        constexpr std::uint32_t arm_float_mask = 0x00000600;
        const auto importer_eabi = importer.flags & eabi_version_mask;
        const auto provider_eabi = provider.flags & eabi_version_mask;
        if (importer_eabi && provider_eabi && importer_eabi != provider_eabi)
            return "conflicting ARM EABI versions";
        // AAELF32 assigns the hard/soft procedure-call flags for EABI v5+.
        // With neither bit set, the base (soft-float) calling standard is
        // implied. Unknown and pre-v5 ABI versions stay conservatively open.
        constexpr std::uint32_t eabi_v5 = 0x05000000;
        if (importer_eabi >= eabi_v5 && provider_eabi >= eabi_v5) {
            const auto importer_float = importer.flags & arm_float_mask;
            const auto provider_float = provider.flags & arm_float_mask;
            if (importer_float == arm_float_mask || provider_float == arm_float_mask)
                return "invalid ARM floating-point ABI flags";
            const auto normalized_float = [](std::uint32_t flags) {
                return (flags & 0x00000400) ? 2u : 1u; // hard-float, otherwise base/soft-float
            };
            if (normalized_float(importer_float) != normalized_float(provider_float))
                return "conflicting ARM floating-point procedure-call ABIs";
        }
    }
    constexpr std::uint16_t em_ppc64 = 21;
    if (importer.machine == em_ppc64 && importer.is_64 && provider.is_64) {
        constexpr std::uint32_t ppc64_abi_mask = 0x3;
        const auto importer_abi = importer.flags & ppc64_abi_mask;
        const auto provider_abi = provider.flags & ppc64_abi_mask;
        if (importer_abi && provider_abi && importer_abi != provider_abi)
            return "conflicting PPC64 ELF ABI versions";
    }
    constexpr std::uint16_t em_mips = 8;
    if (importer.machine == em_mips) {
        constexpr std::uint32_t mips_abi2 = 0x00000020; // N32
        constexpr std::uint32_t mips_abi_mask = 0x0000f000;
        const auto mips_abi_id = [](std::uint32_t flags) -> std::optional<std::uint32_t> {
            if (flags & mips_abi2) return 0x10000; // Keep N32 distinct from EF_MIPS_ABI tags.
            const auto abi = flags & mips_abi_mask;
            return abi ? std::optional<std::uint32_t>{abi} : std::nullopt;
        };
        const auto importer_abi = mips_abi_id(importer.flags);
        const auto provider_abi = mips_abi_id(provider.flags);
        if (importer_abi && provider_abi && importer_abi != provider_abi)
            return "conflicting MIPS ABI flags";
    }
    constexpr std::uint16_t em_loongarch = 258;
    if (importer.machine == em_loongarch) {
        // The LoongArch ABI identifies the ABI type with ELF class and the
        // low byte of e_flags (version, extension, and base-ABI modifier).
        // Class has already been checked above; zero remains unspecified.
        constexpr std::uint32_t abi_selector_mask = 0xff;
        const auto importer_abi = importer.flags & abi_selector_mask;
        const auto provider_abi = provider.flags & abi_selector_mask;
        if (importer_abi && provider_abi && importer_abi != provider_abi)
            return "conflicting LoongArch ABI flags";
    }
    return std::nullopt;
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
            const bool weak_undefined = wanted.binding == 2; // STB_WEAK
            if (providers.empty()) {
                if (weak_undefined)
                    out << "resolved zero (unresolved STB_WEAK import; no supplied DT_NEEDED provider)\n";
                else
                    out << "unresolved (no supplied DT_NEEDED provider)\n";
                continue;
            }
            std::vector<std::pair<const SuppliedModule *, const ElfSymbol *>> matches;
            bool has_abi_compatible_provider = false;
            std::string abi_mismatch;
            bool has_unsupported_provider_symbol = false;
            bool has_symbol_type_mismatch = false;
            for (const auto provider_index : providers) {
                const auto *provider = &modules[provider_index];
                const auto &pe = *provider->metadata->elf;
                if (const auto mismatch = elf_abi_incompatibility(elf.header, pe.header)) {
                    if (abi_mismatch.empty()) abi_mismatch = *mismatch;
                    continue;
                }
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
                out << "unsupported (supplied DT_NEEDED providers have incompatible "
                    << (abi_mismatch.empty() ? "ELF ABI" : abi_mismatch) << ")\n";
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
            if (matches.empty()) {
                if (weak_undefined)
                    out << "resolved zero (unresolved STB_WEAK import; no exact eligible supplied definition)\n";
                else
                    out << "unresolved (no exact eligible export)\n";
                continue;
            }
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
            std::vector<const SuppliedModule *> name_matches;
            for (const auto &candidate : modules)
                if (candidate.metadata && module_leaf(candidate.path) == wanted_module)
                    name_matches.push_back(&candidate);
            if (name_matches.empty()) {
                out << "unresolved (provider module not supplied)\n";
                continue;
            }
            // A same-name file with a different PE ABI must not make a valid
            // supplied provider ambiguous. Keep only compatible PE candidates
            // for symbol resolution, and retain deterministic failure details
            // when every same-name candidate is unusable.
            std::vector<const SuppliedModule *> providers;
            bool saw_pe = false;
            std::string incompatibility;
            for (const auto *candidate : name_matches) {
                if (!is_pe_module(*candidate->metadata)) continue;
                saw_pe = true;
                const auto mismatch = pe_abi_incompatibility(*importer.metadata, *candidate->metadata);
                if (!mismatch) providers.push_back(candidate);
                else if (incompatibility.empty()) incompatibility = *mismatch;
            }
            if (providers.empty()) {
                if (!saw_pe) {
                    out << "unsupported provider format " << name_matches.front()->metadata->format
                        << " (" << name_matches.front()->path << ")\n";
                } else {
                    out << "unsupported (no ABI-compatible supplied provider; " << incompatibility << ")\n";
                }
                continue;
            }
            if (providers.size() != 1) {
                out << "ambiguous provider modules:";
                for (const auto *provider : providers) out << " " << provider->path;
                out << "\n";
                continue;
            }
            const auto &provider = *providers.front();

            const auto resolution = resolve_pe_export(modules, provider, *importer.metadata,
                                                      symbol.name, symbol.ordinal);
            using ResolutionStatus = PeExportResolution::Status;
            switch (resolution.status) {
            case ResolutionStatus::missing_module:
                out << "unresolved (forwarder module not supplied)\n";
                continue;
            case ResolutionStatus::ambiguous_module:
                out << "ambiguous forwarder provider modules\n";
                continue;
            case ResolutionStatus::unsupported_module:
                out << "unsupported forwarder provider format\n";
                continue;
            case ResolutionStatus::incompatible_module:
                out << "unsupported (incompatible forwarded provider: "
                    << resolution.incompatibility << ")\n";
                continue;
            case ResolutionStatus::missing_export:
                out << "unresolved (no exact export in supplied forwarder chain)\n";
                continue;
            case ResolutionStatus::ambiguous_export:
                out << "ambiguous matching exports in supplied forwarder chain\n";
                continue;
            case ResolutionStatus::malformed_forwarder:
                out << "unsupported (malformed PE forwarder string)\n";
                continue;
            case ResolutionStatus::cycle:
                out << "unresolved (PE forwarder cycle detected)\n";
                continue;
            case ResolutionStatus::depth_limit:
                out << "unresolved (PE forwarder depth exceeds 32 hops)\n";
                continue;
            case ResolutionStatus::resolved:
                break;
            }
            const auto &exported = *resolution.symbol;
            if (!exported.address) {
                out << "unresolved (export has no concrete address)\n";
                continue;
            }
            if (resolution.route.size() > 1) {
                out << "resolved through supplied forwarder chain ";
                for (std::size_t route = 0; route < resolution.route.size(); ++route) {
                    if (route) out << " -> ";
                    out << resolution.route[route];
                }
                out << " to " << resolution.provider->path << " at 0x" << std::hex << exported.address->offset
                    << std::dec << " (ordinal #" << exported.ordinal << ")\n";
            } else {
                out << "resolved " << resolution.provider->path << " at 0x" << std::hex << exported.address->offset
                    << std::dec << " (ordinal #" << exported.ordinal << ")\n";
            }
        }
        if (imports.size() > count)
            out << "    ... omitted " << (imports.size() - count) << " imports (100000 row cap)\n";
    }
}

struct MachOExportResolution {
    enum class Status { resolved, missing_library, ambiguous_library, missing_export,
                        ambiguous_export, cycle, depth_limit, unsupported } status = Status::missing_export;
    const SuppliedModule *provider = nullptr;
    const MachODyldExport *symbol = nullptr;
    std::vector<std::string> route;
};

// Follow only explicit dyld re-export terminals through supplied images. The
// original load-command ordinal selects each next image; no basename aliases,
// flat lookup, or host loader state is inferred. A repeated (image, symbol)
// pair and a fixed hop ceiling bound cycles and malformed chains.
inline MachOExportResolution resolve_macho_export(const std::vector<SuppliedModule> &modules,
                                                   const SuppliedModule &initial_provider,
                                                   std::int32_t importer_cpu_type,
                                                   std::string name) {
    constexpr std::size_t max_reexport_hops = 32;
    MachOExportResolution result;
    const SuppliedModule *provider = &initial_provider;
    std::set<std::pair<std::size_t, std::string>> visited;
    for (std::size_t hop = 0; hop <= max_reexport_hops; ++hop) {
        if (!provider->metadata || !provider->metadata->macho) {
            result.status = MachOExportResolution::Status::unsupported;
            return result;
        }
        const auto &metadata = *provider->metadata->macho;
        if (metadata.selected_slice >= metadata.container.slices.size() ||
            metadata.container.slices[metadata.selected_slice].header.cpu_type != importer_cpu_type) {
            result.status = MachOExportResolution::Status::unsupported;
            return result;
        }
        const auto owner = std::find_if(modules.begin(), modules.end(), [&](const auto &candidate) {
            return &candidate == provider;
        });
        if (owner == modules.end()) { result.status = MachOExportResolution::Status::unsupported; return result; }
        const auto module_index = static_cast<std::size_t>(owner - modules.begin());
        if (!visited.emplace(module_index, name).second) {
            result.status = MachOExportResolution::Status::cycle;
            return result;
        }
        std::vector<const MachODyldExport *> matches;
        for (const auto &exported : metadata.dyld_exports)
            if (exported.name == name) matches.push_back(&exported);
        if (matches.empty()) { result.status = MachOExportResolution::Status::missing_export; return result; }
        if (matches.size() != 1) { result.status = MachOExportResolution::Status::ambiguous_export; return result; }
        const auto *exported = matches.front();
        result.route.push_back(module_leaf(provider->path) + "!" + name + " (export terminal file offset " +
            std::to_string(exported->terminal_file_offset) + ")");
        constexpr std::uint64_t export_reexport = 0x08;
        if (!(exported->flags & export_reexport)) {
            if (!exported->is_definition()) { result.status = MachOExportResolution::Status::unsupported; return result; }
            result.status = MachOExportResolution::Status::resolved;
            result.provider = provider;
            result.symbol = exported;
            return result;
        }
        if (hop == max_reexport_hops || !exported->library_ordinal || *exported->library_ordinal == 0) {
            result.status = hop == max_reexport_hops ? MachOExportResolution::Status::depth_limit
                                                     : MachOExportResolution::Status::unsupported;
            return result;
        }
        const MachOLibrary *library = nullptr;
        for (const auto &row : metadata.libraries)
            if (row.ordinal && *row.ordinal == *exported->library_ordinal) {
                if (library) { library = nullptr; break; }
                library = &row;
            }
        if (!library) { result.status = MachOExportResolution::Status::missing_library; return result; }
        std::vector<const SuppliedModule *> candidates;
        for (const auto &candidate : modules)
            if (candidate.metadata && candidate.metadata->macho &&
                module_leaf(candidate.path) == module_leaf(library->name)) candidates.push_back(&candidate);
        if (candidates.empty()) { result.status = MachOExportResolution::Status::missing_library; return result; }
        if (candidates.size() != 1) { result.status = MachOExportResolution::Status::ambiguous_library; return result; }
        provider = candidates.front();
        name = exported->import_name && !exported->import_name->empty()
            ? *exported->import_name : exported->name;
    }
    result.status = MachOExportResolution::Status::depth_limit;
    return result;
}

// Resolve Mach-O bind names only against explicitly supplied images and the
// selected export slice. Ordinals and install-name basenames remain authoritative;
// re-export chains are followed only through matching supplied load-command ordinals.
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
            const auto resolution = resolve_macho_export(modules, *provider,
                importer_slice.header.cpu_type, use.name);
            using MachOStatus = MachOExportResolution::Status;
            switch (resolution.status) {
            case MachOStatus::missing_library:
                out << "unresolved (re-export library not supplied or ordinal unavailable)\n"; continue;
            case MachOStatus::ambiguous_library:
                out << "ambiguous supplied re-export libraries\n"; continue;
            case MachOStatus::missing_export:
                out << "unresolved (no exact export in supplied re-export chain)\n"; continue;
            case MachOStatus::ambiguous_export:
                out << "ambiguous exports in supplied re-export chain\n"; continue;
            case MachOStatus::cycle:
                out << "unresolved (Mach-O re-export cycle detected)\n"; continue;
            case MachOStatus::depth_limit:
                out << "unresolved (Mach-O re-export depth exceeds 32 hops)\n"; continue;
            case MachOStatus::unsupported:
                out << "unsupported export kind or incompatible re-export image\n"; continue;
            case MachOStatus::resolved: break;
            }
            const auto &exported = *resolution.symbol;
            out << "resolved ";
            if (resolution.route.size() > 1) {
                out << "through re-export chain ";
                for (std::size_t index = 0; index < resolution.route.size(); ++index) {
                    if (index) out << " -> ";
                    out << resolution.route[index];
                }
                out << " to " << resolution.provider->path;
            } else out << resolution.provider->path;
            if (exported.address) out << " at 0x" << std::hex << exported.address->offset << std::dec;
            else out << " (preferred address unavailable)";
            out << "\n";
        }
        if (omitted) out << "    ... omitted " << omitted << " additional bind rows (100000 identity cap)\n";
    }
}
} // namespace hexlab::cli
