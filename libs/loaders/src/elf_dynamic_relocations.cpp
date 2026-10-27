#include "elf_internal.hpp"
#include "hexlab/image/patches.hpp"
#include <algorithm>
#include <bit>
#include <map>
#include <set>
#include <string_view>
namespace hexlab::elf_detail {
void read_dynamic_relocations(const Reader &reader, const Image &image, ElfMetadata &metadata, ElfDynamicTable &dynamic,
                              const std::map<std::int64_t, std::uint64_t> &values, Budget &budget,
                              RelocationRegistry &registry, std::stop_token stop) {
    const ElfSymbolTable *symbols = nullptr;
    if (dynamic.symbol_table)
        for (const auto &table : metadata.symbol_tables) {
            canceled(stop);
            if (table.source == *dynamic.symbol_table) {
                symbols = &table;
                break;
            }
        }
    const auto consume = [&](std::int64_t tag, std::uint64_t address, std::uint64_t size, std::uint64_t stride,
                             bool rela) {
        const auto minimum = (rela ? 3u : 2u) * (metadata.header.is_64 ? 8u : 4u);
        require(stride >= minimum && size % stride == 0, "Invalid dynamic ELF relocation stride/extent");
        if (!size)
            return;
        require(size <= metadata_limit, "Dynamic ELF relocation extent exceeds budget", ErrorCode::resource_limit);
        validate_virtual_initialized(image, {{0}, address}, size, stop);
        const auto first = image.to_file_offset({{0}, address});
        require(bool(first), "Dynamic ELF relocation table is not initialized");
        RelocationInput input{{{}, first.value().value, Address{{0}, address}}, size, stride, rela, {}, symbols};
        for (const auto &section : metadata.sections) {
            canceled(stop);
            if (section.type != (rela ? 4u : 9u) || (section.flags & 0x800) ||
                section.offset != input.source.file_offset || section.size != size || section.entry_size != stride)
                continue;
            const bool matching = symbols ? (symbols->source.section == section.link) : section.link == 0;
            if (!matching)
                continue;
            validate_virtual_file(image, {{0}, address}, size, {section.offset}, stop);
            input.source = {section.index, section.offset, {}};
            input.target = section.info ? std::optional{section.info} : std::nullopt;
            break;
        }
        const auto table = read_relocation_table(reader, image, metadata, input, budget, registry, stop);
        budget.include(sizeof(ElfDynamicRelocationTable));
        dynamic.relocation_tables.push_back({tag, table});
    };
    const auto consume_relr = [&] {
        if (!(values.contains(35) || values.contains(36) || values.contains(37)))
            return;
        require(values.contains(35) && values.contains(36) && values.contains(37),
                "Dynamic ELF RELR pointers need size and entry bounds");
        const auto word = metadata.header.is_64 ? 8u : 4u;
        const auto address = values.at(36), size = values.at(35), stride = values.at(37);
        require(stride == word && size % word == 0, "Invalid dynamic ELF RELR entry width or extent");
        if (!size)
            return;
        require(size <= metadata_limit, "Dynamic ELF RELR extent exceeds budget", ErrorCode::resource_limit);
        validate_virtual_initialized(image, {{0}, address}, size, stop);
        const auto first = image.to_file_offset({{0}, address});
        require(bool(first), "Dynamic ELF RELR table is not initialized");
        ElfTableSource source{{}, first.value().value, Address{{0}, address}};
        for (const auto &section : metadata.sections) {
            canceled(stop);
            if (section.type != 19 || section.offset != source.file_offset || section.size != size ||
                section.entry_size != stride)
                continue;
            require(!(section.flags & 0x800), "Compressed ELF RELR sections are unsupported", ErrorCode::unsupported);
            require(section.link == 0 && section.info == 0,
                    "ELF RELR section must not link a symbol or target section");
            validate_virtual_file(image, {{0}, address}, size, {section.offset}, stop);
            source = {section.index, section.offset, {}};
            break;
        }
        const auto table = read_relr_table(reader, image, metadata, source, size, stride, {}, budget, registry, stop);
        budget.include(sizeof(ElfDynamicRelocationTable));
        dynamic.relocation_tables.push_back({36, table});
    };
    // The generic ABI requires packed relative relocations to be processed
    // before REL and RELA entries from the same object.
    consume_relr();
    for (const bool rela : {false, true}) {
        const std::int64_t pointer = rela ? 7 : 17, size = rela ? 8 : 18, entry = rela ? 9 : 19;
        if (values.contains(pointer) || values.contains(size)) {
            require(values.contains(pointer) && values.contains(size) && values.contains(entry),
                    "Dynamic ELF relocation pointers need size and entry bounds");
            consume(pointer, values.at(pointer), values.at(size), values.at(entry), rela);
        }
    }
    for (const bool rela : {false, true}) {
        const std::int64_t pointer = rela ? 0x60000011 : 0x6000000f;
        const std::int64_t size_tag = rela ? 0x60000012 : 0x60000010;
        if (!values.contains(pointer) && !values.contains(size_tag)) continue;
        require(values.contains(pointer) && values.contains(size_tag),
                "Android packed ELF relocations require pointer and size tags");
        const auto address = values.at(pointer), size = values.at(size_tag);
        require(size >= 5 && size <= metadata_limit,
                "Android packed ELF relocation extent exceeds budget", ErrorCode::resource_limit);
        validate_virtual_initialized(image, {{0}, address}, size, stop);
        const auto first = image.to_file_offset({{0}, address});
        require(bool(first), "Android packed ELF relocation table is not initialized");
        ElfTableSource source{{}, first.value().value, Address{{0}, address}};
        const auto packed_section_type = rela ? UINT32_C(0x60000002) : UINT32_C(0x60000001);
        for (const auto &section : metadata.sections) {
            canceled(stop);
            if (section.type != packed_section_type || section.offset != source.file_offset || section.size != size)
                continue;
            validate_virtual_file(image, {{0}, address}, size, {section.offset}, stop);
            source = {section.index, section.offset, {}};
            break;
        }
        const auto table = read_android_packed_relocation_table(reader, image, metadata, source, size,
                                                                 rela, symbols, budget, registry, stop);
        budget.include(sizeof(ElfDynamicRelocationTable));
        dynamic.relocation_tables.push_back({pointer, table});
    }
    if (values.contains(23) || values.contains(2) || values.contains(20)) {
        require(values.contains(23) && values.contains(2) && values.contains(20),
                "ELF JMPREL requires PLTRELSZ and PLTREL");
        const auto type = values.at(20);
        require(type == 7 || type == 17, "ELF PLTREL must select REL or RELA");
        const auto entry = (type == 7 ? 3u : 2u) * (metadata.header.is_64 ? 8u : 4u);
        consume(23, values.at(23), values.at(2), entry, type == 7);
    }
}
} // namespace hexlab::elf_detail

namespace hexlab {
namespace {
struct RuntimeRelocationFailure { Error error; };
void runtime_require(bool value, std::string message, ErrorCode code = ErrorCode::unsupported) {
    if (!value) throw RuntimeRelocationFailure{{code, std::move(message)}};
}
std::uint64_t shifted(std::uint64_t value, std::uint64_t bias) {
    runtime_require(value <= UINT64_MAX - bias, "ELF runtime address overflows when applying load bias",
                    ErrorCode::overflow);
    return value + bias;
}
std::uint64_t relative_value(std::uint64_t load_bias, std::int64_t addend) {
    if (addend >= 0)
        return shifted(static_cast<std::uint64_t>(addend), load_bias);
    // Avoid negating INT64_MIN in the signed domain.
    const auto magnitude = static_cast<std::uint64_t>(-(addend + 1)) + 1;
    runtime_require(load_bias >= magnitude, "ELF relative relocation underflows address space",
                    ErrorCode::overflow);
    return load_bias - magnitude;
}
bool add_signed_to_unsigned(std::uint64_t base, std::int64_t addend, std::uint64_t &result) {
    if (addend >= 0) {
        const auto amount = static_cast<std::uint64_t>(addend);
        if (base > UINT64_MAX - amount) return false;
        result = base + amount;
    } else {
        const auto amount = static_cast<std::uint64_t>(-(addend + 1)) + 1;
        if (base < amount) return false;
        result = base - amount;
    }
    return true;
}
bool ppc64_addr32_result(std::uint64_t symbol, std::int64_t addend, std::uint32_t &result) {
    if (addend >= 0) {
        const auto amount = static_cast<std::uint64_t>(addend);
        if (symbol > UINT64_MAX - amount) return false;
        const auto sum = symbol + amount;
        if (sum > UINT32_MAX) return false;
        result = static_cast<std::uint32_t>(sum);
        return true;
    }
    const auto magnitude = static_cast<std::uint64_t>(-(addend + 1)) + 1;
    if (symbol >= magnitude) {
        const auto sum = symbol - magnitude;
        if (sum > UINT32_MAX) return false;
        result = static_cast<std::uint32_t>(sum);
        return true;
    }
    const auto negative_magnitude = magnitude - symbol;
    if (negative_magnitude > UINT64_C(0x80000000)) return false;
    result = static_cast<std::uint32_t>(0u - static_cast<std::uint32_t>(negative_magnitude));
    return true;
}
bool pc32_result(std::uint64_t symbol, std::int64_t addend, std::uint64_t place, std::uint32_t &encoded) {
    bool negative = symbol < place;
    std::uint64_t magnitude = negative ? place - symbol : symbol - place;
    const bool addend_negative = addend < 0;
    const auto addend_magnitude = addend_negative
        ? static_cast<std::uint64_t>(-(addend + 1)) + 1
        : static_cast<std::uint64_t>(addend);
    if (addend_magnitude) {
        if (negative == addend_negative) {
            const auto limit = negative ? UINT64_C(2147483648) : static_cast<std::uint64_t>(INT32_MAX);
            if (magnitude > limit || addend_magnitude > limit - magnitude) return false;
            magnitude += addend_magnitude;
        } else if (magnitude >= addend_magnitude) {
            magnitude -= addend_magnitude;
            if (!magnitude) negative = false;
        } else {
            magnitude = addend_magnitude - magnitude;
            negative = addend_negative;
        }
    }
    if (negative ? magnitude > UINT64_C(2147483648) : magnitude > static_cast<std::uint64_t>(INT32_MAX))
        return false;
    encoded = static_cast<std::uint32_t>(negative ? std::uint64_t{0} - magnitude : magnitude);
    return true;
}
bool aarch64_absolute_result(std::uint64_t symbol, std::int64_t addend, unsigned bits,
                             std::uint64_t &encoded) {
    if (bits == 64) {
        encoded = symbol + static_cast<std::uint64_t>(addend);
        return true;
    }
    const auto upper = (UINT64_C(1) << bits) - 1;
    if (addend >= 0) {
        const auto amount = static_cast<std::uint64_t>(addend);
        if (symbol > UINT64_MAX - amount) return false;
        encoded = symbol + amount;
        return encoded <= upper;
    }
    const auto amount = static_cast<std::uint64_t>(-(addend + 1)) + 1;
    if (symbol >= amount) {
        encoded = symbol - amount;
        return encoded <= upper;
    }
    const auto magnitude = amount - symbol;
    if (magnitude > (UINT64_C(1) << (bits - 1))) return false;
    encoded = std::uint64_t{0} - magnitude;
    encoded &= upper;
    return true;
}
bool signed_prel_result(std::uint64_t symbol, std::int64_t addend, std::uint64_t place,
                        unsigned bits, std::uint64_t &encoded) {
    if (bits == 64) {
        encoded = symbol + static_cast<std::uint64_t>(addend) - place;
        return true;
    }
    const auto negative_limit = UINT64_C(1) << (bits - 1);
    const auto positive_limit = negative_limit - 1;
    bool negative = symbol < place;
    auto magnitude = negative ? place - symbol : symbol - place;
    const bool addend_negative = addend < 0;
    const auto addend_magnitude = addend_negative
        ? static_cast<std::uint64_t>(-(addend + 1)) + 1
        : static_cast<std::uint64_t>(addend);
    if (addend_magnitude) {
        if (negative == addend_negative) {
            const auto limit = negative ? negative_limit : positive_limit;
            if (magnitude > limit || addend_magnitude > limit - magnitude) return false;
            magnitude += addend_magnitude;
        } else if (magnitude >= addend_magnitude) {
            magnitude -= addend_magnitude;
            if (!magnitude) negative = false;
        } else {
            magnitude = addend_magnitude - magnitude;
            negative = addend_negative;
        }
    }
    if (negative ? magnitude > negative_limit : magnitude > positive_limit) return false;
    encoded = negative ? std::uint64_t{0} - magnitude : magnitude;
    encoded &= (UINT64_C(1) << bits) - 1;
    return true;
}
void shift_address(Address &address, std::uint64_t bias, bool elf32) {
    runtime_require(address.space.value == 0, "Runtime rebasing supports only the ELF primary address domain");
    address.offset = shifted(address.offset, bias);
    runtime_require(!elf32 || address.offset <= UINT32_MAX,
                    "ELF32 runtime address exceeds the 32-bit address space", ErrorCode::overflow);
}
void shift_layout(ImageLayout &layout, std::uint64_t bias, bool elf32) {
    runtime_require(layout.domains.empty(), "Runtime rebasing does not support section-domain ELF objects");
    for (auto &segment : layout.segments) {
        shift_address(segment.begin, bias, elf32);
        runtime_require(segment.size <= UINT64_MAX - segment.begin.offset,
                        "ELF runtime segment extent overflows after load bias", ErrorCode::overflow);
        runtime_require(!elf32 || segment.size <= UINT32_MAX - segment.begin.offset,
                        "ELF32 runtime segment exceeds the 32-bit address space", ErrorCode::overflow);
    }
    for (auto &entry : layout.entries) shift_address(entry, bias, elf32);
    for (auto &range : layout.code_exclusions) {
        shift_address(range.begin, bias, elf32);
        runtime_require(range.size <= UINT64_MAX - range.begin.offset,
                        "ELF runtime code exclusion overflows after load bias", ErrorCode::overflow);
        runtime_require(!elf32 || range.size <= UINT32_MAX - range.begin.offset,
                        "ELF32 runtime code exclusion exceeds the 32-bit address space", ErrorCode::overflow);
    }
    for (auto &range : layout.encrypted_ranges) {
        shift_address(range.begin, bias, elf32);
        runtime_require(range.size <= UINT64_MAX - range.begin.offset,
                        "ELF runtime encrypted range overflows after load bias", ErrorCode::overflow);
        runtime_require(!elf32 || range.size <= UINT32_MAX - range.begin.offset,
                        "ELF32 runtime encrypted range exceeds the 32-bit address space", ErrorCode::overflow);
    }
    if (layout.arm_profile) {
        for (auto &range : layout.arm_profile->ranges) shift_address(range.begin, bias, elf32);
        for (auto &root : layout.arm_profile->roots) shift_address(root.at, bias, elf32);
    }
}
const ElfSymbol *runtime_symbol(const ElfMetadata &metadata, const ElfRelocation &relocation) {
    if (!relocation.symbol_table || relocation.symbol_index == 0) return nullptr;
    const auto table = std::find_if(metadata.symbol_tables.begin(), metadata.symbol_tables.end(),
        [&](const ElfSymbolTable &candidate) { return candidate.source == *relocation.symbol_table; });
    if (table == metadata.symbol_tables.end()) return nullptr;
    for (const auto &symbol : metadata.symbols) {
        if (symbol.index != relocation.symbol_index) continue;
        if (table->source.section) {
            if (symbol.table == table->source.section) return &symbol;
        } else if (symbol.table_address == table->source.address &&
                   symbol.table_offset == table->source.file_offset) {
            return &symbol;
        }
    }
    return nullptr;
}
std::optional<std::uint64_t> symbol_value(const LoadedImage &source, const ElfSymbol &symbol,
                                         std::uint64_t load_bias) {
    if (symbol.type == 6 || symbol.type == 10) return std::nullopt;
    if (symbol.state == ElfSymbolState::absolute) return symbol.value;
    if (symbol.state != ElfSymbolState::defined) return std::nullopt;
    auto runtime_address = shifted(symbol.value, load_bias);
    const Address address{{0}, symbol.value};
    if (!source.image->segment_at(address)) return std::nullopt;
    return runtime_address;
}
struct RuntimePatch {
    std::uint64_t index = 0;
    PatchSpan patch;
    std::optional<ElfRuntimeImage::ResolvedSymbol> resolved_symbol;
};
struct ExternalSymbolMatch {
    std::optional<ElfRuntimeImage::ResolvedSymbol> resolution;
    bool ambiguous = false;
};
ExternalSymbolMatch resolve_external_symbol(
    std::uint64_t relocation_index, const ElfSymbol &symbol,
    const std::set<std::string, std::less<>> &needed,
    std::span<const ElfRuntimeSymbolBinding> bindings,
    const std::map<std::string_view, std::vector<std::size_t>, std::less<>> &by_name) {
    ExternalSymbolMatch result;
    const auto candidates = by_name.find(symbol.name);
    if (candidates == by_name.end()) return result;
    for (const auto binding_index : candidates->second) {
        const auto &binding = bindings[binding_index];
        if (!needed.contains(binding.library_name)) continue;
        bool eligible = false;
        if (symbol.version_name) {
            eligible = symbol.version_file && binding.library_name == *symbol.version_file &&
                       binding.version_name == symbol.version_name;
        } else {
            // Unversioned imports may use an unversioned export or the
            // dependency's default version, but never a non-default version.
            eligible = !symbol.version_file &&
                       ((!binding.version_name && !binding.default_version) || binding.default_version);
        }
        if (!eligible) continue;
        if (result.resolution) {
            result.resolution.reset();
            result.ambiguous = true;
            continue;
        }
        if (result.ambiguous) continue;
        result.resolution = ElfRuntimeImage::ResolvedSymbol{relocation_index, binding_index,
                                                             binding.runtime_address};
    }
    return result;
}
} // namespace

Result<ElfRuntimeImage> apply_elf_runtime_relocations(const LoadedImage &source, std::uint64_t load_bias,
                                                     std::stop_token stop, ElfRuntimeRelocationLimits limits) {
    return apply_elf_runtime_relocations(source, load_bias, std::span<const ElfRuntimeSymbolBinding>{}, stop,
                                         limits);
}

Result<ElfRuntimeImage> apply_elf_runtime_relocations(const LoadedImage &source, std::uint64_t load_bias,
                                                     std::span<const ElfRuntimeSymbolBinding> bindings,
                                                     std::stop_token stop, ElfRuntimeRelocationLimits limits) {
    try {
        runtime_require(!stop.stop_requested(), "ELF runtime relocation canceled", ErrorCode::canceled);
        runtime_require(source.image && source.metadata.elf.has_value(),
                        "ELF runtime relocation requires a loaded ELF image", ErrorCode::invalid_argument);
        const auto &metadata = *source.metadata.elf;
        runtime_require(metadata.header.object_type == 3, "Runtime relocation application requires ET_DYN");
        runtime_require(limits.max_records > 0, "ELF runtime relocation record limit must be positive",
                        ErrorCode::invalid_argument);
        runtime_require(bindings.size() <= limits.max_symbol_bindings &&
                            limits.max_symbol_bindings <= 65'536,
                        "ELF runtime symbol binding limit exceeded", ErrorCode::resource_limit);
        runtime_require(metadata.relocations.size() <= limits.max_records,
                        "ELF runtime relocation record limit exceeded", ErrorCode::resource_limit);

        std::set<std::string, std::less<>> needed;
        for (const auto &dynamic : metadata.dynamic_tables)
            for (const auto &entry : dynamic.entries)
                if (entry.tag == 1 && entry.string_value) needed.insert(*entry.string_value);
        std::map<std::string_view, std::vector<std::size_t>, std::less<>> bindings_by_name;
        for (std::size_t index = 0; index < bindings.size(); ++index) {
            const auto &binding = bindings[index];
            runtime_require(!binding.library_name.empty() && binding.library_name.size() <= 4096 &&
                                !binding.symbol_name.empty() && binding.symbol_name.size() <= 4096 &&
                                (!binding.version_name || (!binding.version_name->empty() &&
                                                           binding.version_name->size() <= 4096)) &&
                                (!binding.default_version || binding.version_name.has_value()),
                            "Invalid ELF runtime symbol binding", ErrorCode::invalid_argument);
            bindings_by_name[binding.symbol_name].push_back(index);
        }

        ElfRuntimeImage result;
        result.load_bias = load_bias;
        std::set<std::uint64_t> dynamic_rows;
        std::set<std::uint64_t> relr_rows;
        for (const auto &dynamic : metadata.dynamic_tables) {
            if (stop.stop_requested())
                throw RuntimeRelocationFailure{{ErrorCode::canceled, "ELF runtime relocation canceled"}};
            for (const auto &table_ref : dynamic.relocation_tables) {
                runtime_require(table_ref.table_index < metadata.relocation_tables.size(),
                                "ELF dynamic relocation table reference is invalid", ErrorCode::malformed);
                const auto &table = metadata.relocation_tables[static_cast<std::size_t>(table_ref.table_index)];
                for (const auto row : table.rows) {
                    runtime_require(row < metadata.relocations.size(), "ELF dynamic relocation row is invalid",
                                    ErrorCode::malformed);
                    dynamic_rows.insert(row);
                    if (table_ref.tag == 36)
                        relr_rows.insert(row);
                }
            }
        }

        std::vector<RuntimePatch> candidates;
        candidates.reserve(dynamic_rows.size());
        const auto skip = [&](std::uint64_t index, std::string reason) {
            result.complete = false;
            result.skipped.push_back({index, std::move(reason)});
        };
        for (const auto index : dynamic_rows) {
            if (stop.stop_requested())
                throw RuntimeRelocationFailure{{ErrorCode::canceled, "ELF runtime relocation canceled"}};
            const auto &relocation = metadata.relocations[static_cast<std::size_t>(index)];
            const bool packed_relative = relr_rows.contains(index);
            const bool arm32 = !metadata.header.is_64 && metadata.header.machine == 40 &&
                               metadata.header.order == ByteOrder::little;
            const bool i386 = !metadata.header.is_64 && metadata.header.machine == 3 &&
                              metadata.header.order == ByteOrder::little;
            const bool x64 = metadata.header.machine == 62;
            const bool x32 = !metadata.header.is_64 && x64 && metadata.header.order == ByteOrder::little;
            const bool ppc64 = metadata.header.machine == 21;
            const bool s390x = metadata.header.is_64 && metadata.header.machine == 22;
            const bool riscv = metadata.header.machine == 243;
            const bool riscv64 = riscv && metadata.header.is_64;
            const bool riscv32 = riscv && !metadata.header.is_64;
            const auto relative_type = i386 || x64 ? 8u : arm32 ? 23u : ppc64 ? 22u :
                                       s390x ? 12u : riscv ? 3u : 1027u;
            const auto jump_slot_type = i386 || x64 ? 7u : arm32 ? 22u : ppc64 ? 21u :
                                        s390x ? 11u : riscv ? 5u : 1026u;
            const bool x32_relative = x32 && relocation.type == 8 &&
                                      relocation.kind == ElfRelocationKind::base_relative;
            const bool x32_relative64 = x32 && relocation.type == 38 &&
                                        relocation.kind == ElfRelocationKind::base_relative;
            const bool ordinary_subset = metadata.header.order == ByteOrder::little &&
                                         ((metadata.header.is_64 &&
                                           (metadata.header.machine == 62 || metadata.header.machine == 183 || ppc64 || riscv64)) ||
                                          i386 || arm32 || riscv32 || x32_relative || x32_relative64);
            const bool s390x_subset = s390x && metadata.header.order == ByteOrder::big;
            const bool supported_architecture = ordinary_subset || s390x_subset;
            if (!packed_relative && !supported_architecture) {
                skip(index, "Ordinary REL/RELA runtime relocations are unsupported for this ELF class, byte order, or architecture");
                continue;
            }
            if (!packed_relative && ppc64 && !relocation.explicit_addend) {
                skip(index, "PPC64 runtime relocation support requires RELA explicit addends");
                continue;
            }
            if (!packed_relative && s390x && !relocation.explicit_addend) {
                skip(index, "s390x runtime relocation support requires big-endian RELA explicit addends");
                continue;
            }
            const bool relative = relocation.kind == ElfRelocationKind::base_relative &&
                                  (packed_relative || relocation.type == relative_type || x32_relative64);
            const bool symbol_slot = (!riscv &&
                                      ((relocation.type == (arm32 ? 21u : s390x ? 10u : i386 || x64 ? 6u : 1025u) &&
                                        relocation.kind == ElfRelocationKind::global_data) ||
                                       (relocation.type == jump_slot_type &&
                                        relocation.kind == ElfRelocationKind::jump_slot))) ||
                                     (riscv && relocation.type == jump_slot_type &&
                                      relocation.kind == ElfRelocationKind::jump_slot);
            const bool ppc64_glob_dat = ppc64 && relocation.type == 20 &&
                                        relocation.kind == ElfRelocationKind::global_data;
            const bool ppc64_abs64 = ppc64 && relocation.type == 38 &&
                                     relocation.kind == ElfRelocationKind::absolute;
            const bool ppc64_abs32 = ppc64 && relocation.type == 1 &&
                                     relocation.kind == ElfRelocationKind::absolute;
            const bool s390x_abs64 = s390x && relocation.type == 22 &&
                                     relocation.kind == ElfRelocationKind::absolute;
            const bool s390x_pc32 = s390x && relocation.type == 5 &&
                                    relocation.kind == ElfRelocationKind::pc_relative;
            const bool s390x_glob_dat = s390x && relocation.type == 10 &&
                                        relocation.kind == ElfRelocationKind::global_data;
            const bool riscv_32 = riscv && relocation.type == 1 &&
                                  relocation.kind == ElfRelocationKind::absolute;
            const bool riscv_64 = riscv64 && relocation.type == 2 &&
                                  relocation.kind == ElfRelocationKind::absolute;
            const bool symbol_with_addend = riscv_32 || riscv_64;
            const bool aarch64_abs64 = metadata.header.machine == 183 && relocation.type == 257 &&
                                       relocation.kind == ElfRelocationKind::absolute;
            const bool aarch64_abs32 = metadata.header.machine == 183 && relocation.type == 258 &&
                                       relocation.kind == ElfRelocationKind::absolute;
            const bool aarch64_abs16 = metadata.header.machine == 183 && relocation.type == 259 &&
                                       relocation.kind == ElfRelocationKind::absolute;
            const bool aarch64_prel64 = metadata.header.machine == 183 && relocation.type == 260 &&
                                        relocation.kind == ElfRelocationKind::pc_relative;
            const bool aarch64_prel32 = metadata.header.machine == 183 && relocation.type == 261 &&
                                        relocation.kind == ElfRelocationKind::pc_relative;
            const bool aarch64_prel16 = metadata.header.machine == 183 && relocation.type == 262 &&
                                        relocation.kind == ElfRelocationKind::pc_relative;
            const bool i386_absolute = i386 && relocation.type == 1 &&
                                       relocation.kind == ElfRelocationKind::absolute;
            const bool i386_pc_relative = i386 && relocation.type == 2 &&
                                          relocation.kind == ElfRelocationKind::pc_relative;
            const bool arm32_absolute = arm32 && relocation.type == 2 &&
                                        relocation.kind == ElfRelocationKind::absolute;
            const bool arm32_pc_relative = arm32 && relocation.type == 3 &&
                                           relocation.kind == ElfRelocationKind::pc_relative;
            const bool arm32_prel31 = arm32 && relocation.type == 42 &&
                                      relocation.kind == ElfRelocationKind::pc_relative;
            const bool arm32_abs32_noi = arm32 && relocation.type == 55 &&
                                         relocation.kind == ElfRelocationKind::absolute;
            const bool arm32_rel32_noi = arm32 && relocation.type == 56 &&
                                         relocation.kind == ElfRelocationKind::pc_relative;
            const bool arm32_glob_dat = arm32 && relocation.type == 21 &&
                                        relocation.kind == ElfRelocationKind::global_data;
            const bool arm32_jump_slot = arm32 && relocation.type == 22 &&
                                         relocation.kind == ElfRelocationKind::jump_slot;
            const bool x64_64 = x64 && relocation.type == 1 && relocation.kind == ElfRelocationKind::absolute;
            const bool x64_pc32 = x64 && relocation.type == 2 && relocation.kind == ElfRelocationKind::pc_relative;
            const bool x64_32 = x64 && relocation.type == 10 && relocation.kind == ElfRelocationKind::absolute;
            const bool x64_32s = x64 && relocation.type == 11 && relocation.kind == ElfRelocationKind::absolute;
            if (!relative && !symbol_slot && !symbol_with_addend && !i386_absolute && !i386_pc_relative &&
                !arm32_absolute && !arm32_pc_relative && !arm32_prel31 && !arm32_abs32_noi &&
                !arm32_rel32_noi && !arm32_glob_dat && !arm32_jump_slot &&
                !x64_64 && !x64_pc32 && !x64_32 && !x64_32s &&
                !aarch64_abs64 && !aarch64_abs32 && !aarch64_abs16 &&
                !aarch64_prel64 && !aarch64_prel32 && !aarch64_prel16 &&
                !ppc64_glob_dat && !ppc64_abs64 && !ppc64_abs32 && !s390x_glob_dat && !s390x_abs64 && !s390x_pc32) {
                skip(index, i386
                    ? "Supported dynamic types are R_386_32, R_386_PC32, R_386_RELATIVE, R_386_GLOB_DAT, and R_386_JMP_SLOT"
                    : arm32
                    ? "Supported dynamic types are R_ARM_ABS32/REL32/PREL31/ABS32_NOI/REL32_NOI, RELATIVE, GLOB_DAT, and JUMP_SLOT"
                    : riscv
                    ? (riscv64 ? "Supported dynamic types are R_RISCV_RELATIVE, R_RISCV_64, and R_RISCV_JUMP_SLOT"
                               : "Supported dynamic types are R_RISCV_RELATIVE, R_RISCV_32, and R_RISCV_JUMP_SLOT")
                    : x64
                    ? "Supported dynamic types are R_X86_64_64, PC32, 32, 32S, RELATIVE, GLOB_DAT, and JUMP_SLOT"
                    : s390x
                    ? "Supported dynamic types are big-endian R_390_PC32, R_390_RELATIVE, R_390_64, R_390_GLOB_DAT, and R_390_JMP_SLOT"
                    : ppc64
                    ? "Supported dynamic types are R_PPC64_RELATIVE, ADDR32/ADDR64, GLOB_DAT, and JMP_SLOT"
                    : "Supported dynamic types are R_AARCH64_ABS64/32/16, PREL64/32/16, RELATIVE, GLOB_DAT, and JUMP_SLOT");
                continue;
            }
            if (i386 && relocation.explicit_addend) {
                skip(index, "ELF32 i386 runtime relocation support requires REL implicit addends");
                continue;
            }
            if (relative && !relocation.addend) {
                skip(index, relocation.explicit_addend
                                ? "Relative RELA relocation addend is unavailable"
                                : "Relative REL relocation's implicit addend is unavailable");
                continue;
            }
            if (relative && relocation.symbol_index != 0) {
                skip(index, "Relative relocation requires symbol index zero");
                continue;
            }
            std::uint64_t value = 0;
            std::optional<ElfRuntimeImage::ResolvedSymbol> external_resolution;
            if (relative) {
                try {
                    // REL addends are unsigned ELF32 words. The parser keeps
                    // the sampled word in a signed carrier; recover its exact
                    // 32-bit pattern before applying B + A.
                    if (i386 || arm32 || (riscv32 && !relocation.explicit_addend) ||
                        (x32_relative && !relocation.explicit_addend)) {
                        const auto addend = static_cast<std::uint64_t>(
                            static_cast<std::uint32_t>(*relocation.addend));
                        value = shifted(addend, load_bias);
                    } else {
                        value = relative_value(load_bias, *relocation.addend);
                    }
                } catch (const RuntimeRelocationFailure &) {
                    skip(index, "Relative relocation result overflows the runtime address space");
                    continue;
                }
                if ((i386 || arm32 || riscv32 || x32_relative) && value > UINT32_MAX) {
                    skip(index, "ELF32 relative relocation result exceeds the 32-bit address space");
                    continue;
                }
            } else {
                if (relocation.symbol_index == 0 || !relocation.symbol_index_validated) {
                    skip(index, "Symbol relocation has no validated nonzero symbol index");
                    continue;
                }
                const auto *symbol = runtime_symbol(metadata, relocation);
                if (!symbol) {
                    skip(index, "Symbol relocation does not map to its dynamic symbol table entry");
                    continue;
                }
                if (symbol->state == ElfSymbolState::undefined) {
                    if (symbol->binding != 1 && symbol->binding != 2) {
                        skip(index, "External symbol relocation requires a global or weak import");
                        continue;
                    }
                    if (symbol->type == 6 || symbol->type == 10) {
                        skip(index, "External TLS and GNU IFUNC symbol relocations are unsupported");
                        continue;
                    }
                    const auto resolved = resolve_external_symbol(index, *symbol, needed, bindings, bindings_by_name);
                    if (resolved.ambiguous) {
                        skip(index, "External symbol has multiple exact dependency/version bindings");
                        continue;
                    }
                    if (!resolved.resolution) {
                        skip(index, symbol->version_name
                                        ? "No exact dependency, symbol, and GNU version binding was supplied"
                                        : "No exact DT_NEEDED unversioned/default-version binding was supplied");
                        continue;
                    }
                    external_resolution = resolved.resolution;
                    value = external_resolution->runtime_address;
                } else {
                    try {
                        const auto resolved = symbol_value(source, *symbol, load_bias);
                        if (!resolved) {
                            skip(index, "Symbol relocation requires a defined non-TLS, non-IFUNC in-image symbol");
                            continue;
                        }
                        value = *resolved;
                    } catch (const RuntimeRelocationFailure &) {
                        skip(index, "Symbol relocation result overflows the runtime address space");
                        continue;
                    }
                }
                if ((i386 || riscv32) && value > UINT32_MAX) {
                    skip(index, "ELF32 symbol address exceeds the 32-bit address space");
                    continue;
                }
                if (arm32 && value > UINT32_MAX) {
                    skip(index, "ELF32 ARM symbol address exceeds the 32-bit address space");
                    continue;
                }
                const bool arm_thumb_symbol = arm32 && (value & 1u) != 0;
                if (i386_absolute || i386_pc_relative) {
                    if (!relocation.addend) {
                        skip(index, "i386 symbol relocation's implicit addend is unavailable");
                        continue;
                    }
                    const auto addend = static_cast<std::uint32_t>(*relocation.addend);
                    std::uint64_t place = 0;
                    if (i386_pc_relative) {
                        if (!relocation.place) {
                            skip(index, "R_386_PC32 relocation place is unavailable");
                            continue;
                        }
                        try {
                            place = shifted(relocation.place->offset, load_bias);
                        } catch (const RuntimeRelocationFailure &) {
                            skip(index, "R_386_PC32 runtime place overflows the address space");
                            continue;
                        }
                        if (place > UINT32_MAX) {
                            skip(index, "R_386_PC32 runtime place exceeds the 32-bit address space");
                            continue;
                        }
                    }
                    // The ABI defines these results as word32 fields. Preserve
                    // the specified low 32 bits, including negative addends.
                    value = static_cast<std::uint32_t>(
                        static_cast<std::uint32_t>(value) + addend - static_cast<std::uint32_t>(place));
                } else if (arm32_absolute || arm32_pc_relative || arm32_prel31 || arm32_abs32_noi ||
                           arm32_rel32_noi || arm32_glob_dat || arm32_jump_slot) {
                    // ARM ELF32 dynamic relocations write a 32-bit word. Preserve
                    // the Thumb function bit from S after arithmetic on S + A.
                    std::uint32_t addend = 0;
                    if (arm32_jump_slot && !relocation.explicit_addend) {
                        addend = 0; // R_ARM_JUMP_SLOT REL always uses A = 0.
                    } else {
                        if (!relocation.addend) {
                            skip(index, "ARM symbol relocation addend is unavailable");
                            continue;
                        }
                        addend = static_cast<std::uint32_t>(*relocation.addend);
                    }
                    const bool preserve_thumb = !arm32_abs32_noi && !arm32_rel32_noi;
                    const auto tagged_symbol = (static_cast<std::uint32_t>(value) + addend) |
                        static_cast<std::uint32_t>(preserve_thumb && arm_thumb_symbol);
                    if (arm32_pc_relative || arm32_rel32_noi || arm32_prel31) {
                        if (!relocation.place) {
                            skip(index, "R_ARM_REL32 relocation place is unavailable");
                            continue;
                        }
                        std::uint64_t place = 0;
                        try { place = shifted(relocation.place->offset, load_bias); }
                        catch (const RuntimeRelocationFailure &) {
                            skip(index, "R_ARM_REL32 runtime place overflows the address space");
                            continue;
                        }
                        if (place > UINT32_MAX) {
                            skip(index, "ARM PC-relative runtime place exceeds the 32-bit address space");
                            continue;
                        }
                        const auto difference = static_cast<std::uint32_t>(
                            tagged_symbol - static_cast<std::uint32_t>(place));
                        if (arm32_prel31) {
                            const auto signed_difference = std::bit_cast<std::int32_t>(difference);
                            if (signed_difference < -(INT32_C(1) << 30) ||
                                signed_difference > (INT32_C(1) << 30) - 1) {
                                skip(index, "R_ARM_PREL31 result does not fit signed 31 bits");
                                continue;
                            }
                            value = difference & UINT32_C(0x7fffffff);
                        } else {
                            value = difference;
                        }
                    } else {
                        value = tagged_symbol;
                    }
                } else if (symbol_with_addend || aarch64_abs64 || aarch64_abs32 || aarch64_abs16 ||
                           aarch64_prel64 || aarch64_prel32 || aarch64_prel16 || ppc64_glob_dat || ppc64_abs64 || ppc64_abs32 ||
                           s390x_glob_dat || s390x_abs64 || s390x_pc32) {
                    if (!relocation.addend) {
                        const auto relocation_name = aarch64_abs64 ? "R_AARCH64_ABS64" :
                            aarch64_abs32 ? "R_AARCH64_ABS32" : aarch64_abs16 ? "R_AARCH64_ABS16" :
                            aarch64_prel64 ? "R_AARCH64_PREL64" : aarch64_prel32 ? "R_AARCH64_PREL32" :
                            aarch64_prel16 ? "R_AARCH64_PREL16" :
                            ppc64_glob_dat ? "R_PPC64_GLOB_DAT" : ppc64_abs64 ? "R_PPC64_ADDR64" :
                            ppc64_abs32 ? "R_PPC64_ADDR32" :
                            s390x_glob_dat ? "R_390_GLOB_DAT" : s390x_abs64 ? "R_390_64" : s390x_pc32 ? "R_390_PC32" :
                            riscv_32 ? "R_RISCV_32" : "R_RISCV_64";
                        skip(index, std::string(relocation_name) +
                                        (relocation.explicit_addend ? " relocation addend is unavailable"
                                                                    : " implicit addend is unavailable"));
                        continue;
                    }
                    if (aarch64_abs64 || aarch64_abs32 || aarch64_abs16) {
                        const auto bits = aarch64_abs64 ? 64u : aarch64_abs32 ? 32u : 16u;
                        if (!aarch64_absolute_result(value, *relocation.addend, bits, value)) {
                            skip(index, "AArch64 ABS relocation result does not fit its ABI range");
                            continue;
                        }
                    } else if (aarch64_prel64 || aarch64_prel32 || aarch64_prel16) {
                        if (!relocation.place) {
                            skip(index, "AArch64 PREL relocation place is unavailable");
                            continue;
                        }
                        std::uint64_t place = 0;
                        try { place = shifted(relocation.place->offset, load_bias); }
                        catch (const RuntimeRelocationFailure &) {
                            skip(index, "AArch64 PREL runtime place overflows the address space");
                            continue;
                        }
                        const auto bits = aarch64_prel64 ? 64u : aarch64_prel32 ? 32u : 16u;
                        if (!signed_prel_result(value, *relocation.addend, place, bits, value)) {
                            skip(index, "AArch64 PREL result does not fit its signed ABI range");
                            continue;
                        }
                    } else if (riscv_32) {
                        std::uint64_t sum = 0;
                        if (!add_signed_to_unsigned(value, *relocation.addend, sum) || sum > UINT32_MAX) {
                            skip(index, "R_RISCV_32 result does not fit unsigned 32 bits");
                            continue;
                        }
                        value = sum;
                    } else if (ppc64_abs32) {
                        std::uint32_t encoded = 0;
                        if (!ppc64_addr32_result(value, *relocation.addend, encoded)) {
                            skip(index, "R_PPC64_ADDR32 result does not fit signed-or-unsigned 32 bits");
                            continue;
                        }
                        value = encoded;
                    } else if (s390x_pc32) {
                        if (!relocation.place) {
                            skip(index, "R_390_PC32 relocation place is unavailable");
                            continue;
                        }
                        std::uint64_t place = 0;
                        try { place = shifted(relocation.place->offset, load_bias); }
                        catch (const RuntimeRelocationFailure &) {
                            skip(index, "R_390_PC32 runtime place overflows the address space");
                            continue;
                        }
                        std::uint64_t encoded = 0;
                        if (!signed_prel_result(value, *relocation.addend, place, 32, encoded)) {
                            skip(index, "R_390_PC32 result does not fit its signed 32-bit ABI range");
                            continue;
                        }
                        if (encoded & 1) {
                            skip(index, "R_390_PC32 result is not halfword aligned");
                            continue;
                        }
                        value = encoded;
                    } else {
                        value += static_cast<std::uint64_t>(*relocation.addend);
                    }
                } else if (x64_64 || x64_pc32 || x64_32 || x64_32s) {
                    if (!relocation.addend) {
                        skip(index, "x86-64 symbol-addend relocation addend is unavailable");
                        continue;
                    }
                    const auto addend = *relocation.addend;
                    if (x64_64) {
                        // R_X86_64_64 stores the 64-bit S + A result.
                        value += static_cast<std::uint64_t>(addend);
                    } else if (x64_pc32) {
                        if (!relocation.place) {
                            skip(index, "R_X86_64_PC32 relocation place is unavailable");
                            continue;
                        }
                        std::uint64_t place = 0;
                        try { place = shifted(relocation.place->offset, load_bias); }
                        catch (const RuntimeRelocationFailure &) {
                            skip(index, "R_X86_64_PC32 runtime place overflows the address space");
                            continue;
                        }
                        std::uint32_t encoded = 0;
                        if (!pc32_result(value, addend, place, encoded)) {
                            skip(index, "R_X86_64_PC32 result does not fit signed 32 bits");
                            continue;
                        }
                        value = encoded;
                    } else if (x64_32) {
                        std::uint64_t sum = 0;
                        if (!add_signed_to_unsigned(value, addend, sum) || sum > UINT32_MAX) {
                            skip(index, "R_X86_64_32 result does not fit unsigned 32 bits");
                            continue;
                        }
                        value = sum;
                    } else if (x64_32s) {
                        bool fits = false;
                        std::uint32_t low = 0;
                        if (addend >= 0) {
                            const auto amount = static_cast<std::uint64_t>(addend);
                            fits = value <= static_cast<std::uint64_t>(INT32_MAX) &&
                                   amount <= static_cast<std::uint64_t>(INT32_MAX) - value;
                            low = static_cast<std::uint32_t>(value + amount);
                        } else {
                            const auto amount = static_cast<std::uint64_t>(-(addend + 1)) + 1;
                            if (value >= amount) {
                                const auto positive = value - amount;
                                fits = positive <= static_cast<std::uint64_t>(INT32_MAX);
                            } else {
                                fits = amount - value <= UINT64_C(2147483648);
                            }
                            low = static_cast<std::uint32_t>(value - amount);
                        }
                        if (!fits) {
                            skip(index, "R_X86_64_32S result does not fit signed 32 bits");
                            continue;
                        }
                        value = low;
                    }
                }
            }
            const auto word = metadata.header.is_64 ? UINT64_C(8) : UINT64_C(4);
            const auto expected_width = packed_relative || i386 || arm32 || riscv32 || x32_relative ? word :
                (riscv_32 || x64_pc32 || x64_32 || x64_32s || ppc64_abs32 || aarch64_abs32 || aarch64_prel32 || s390x_pc32)
                    ? UINT64_C(4)
                    : (aarch64_abs16 || aarch64_prel16) ? UINT64_C(2) : UINT64_C(8);
            if (!relocation.place || !relocation.file_place || relocation.field_size != expected_width) {
                skip(index, "Relocation target is not a complete file-backed field of the supported width");
                continue;
            }
            if (!packed_relative && ppc64 && !ppc64_abs32 && (relocation.place->offset & 7) != 0) {
                skip(index, "PPC64 dynamic relocation target is not 8-byte aligned");
                continue;
            }
            if (!packed_relative && ppc64_abs32 && (relocation.place->offset & 3) != 0) {
                skip(index, "R_PPC64_ADDR32 target is not 4-byte aligned");
                continue;
            }
            if (!packed_relative && s390x && !s390x_pc32 && (relocation.place->offset & 7) != 0) {
                skip(index, "s390x dynamic relocation target is not 8-byte aligned");
                continue;
            }
            if (arm32 && (relocation.place->offset & 3) != 0) {
                skip(index, "ARM dynamic relocation target is not 4-byte aligned");
                continue;
            }
            const auto *segment = source.image->segment_at(*relocation.place);
            if (!segment || !segment->writable || relocation.place->offset < segment->begin.offset ||
                relocation.place->offset - segment->begin.offset > segment->file_size ||
                expected_width > segment->file_size - (relocation.place->offset - segment->begin.offset)) {
                skip(index, "Relocation target is outside writable initialized load memory");
                continue;
            }
            const auto mapped_file = source.image->to_file_offset(*relocation.place);
            if (!mapped_file || mapped_file.value() != *relocation.file_place) {
                skip(index, "Relocation target file provenance does not match the loaded image");
                continue;
            }
            auto original = source.image->storage()->read_at(*relocation.file_place,
                                                             static_cast<std::size_t>(expected_width));
            if (!original || original.value().bytes.size() != expected_width) {
                skip(index, "Relocation target bytes are unavailable");
                continue;
            }
            std::vector<std::byte> replacement(static_cast<std::size_t>(expected_width));
            if (arm32_prel31) {
                std::uint32_t old_word = 0;
                for (std::size_t byte = 0; byte < 4; ++byte) {
                    const auto shift = 8 * (metadata.header.order == ByteOrder::little ? byte : 3 - byte);
                    old_word |= std::to_integer<std::uint32_t>(original.value().bytes[byte]) << shift;
                }
                value |= old_word & UINT32_C(0x80000000);
            }
            for (std::size_t byte = 0; byte < replacement.size(); ++byte) {
                const auto shift = 8 * (metadata.header.order == ByteOrder::little
                    ? byte : replacement.size() - byte - 1);
                replacement[byte] = static_cast<std::byte>((value >> shift) & 0xff);
            }
            candidates.push_back({index, {*relocation.file_place,
                                          {original.value().bytes.begin(), original.value().bytes.end()},
                                          std::move(replacement)}, external_resolution});
        }
        std::sort(candidates.begin(), candidates.end(), [](const auto &a, const auto &b) {
            return a.patch.begin.value < b.patch.begin.value;
        });
        std::vector<bool> overlapping(candidates.size(), false);
        for (std::size_t first = 0; first < candidates.size();) {
            std::size_t last = first + 1;
            std::uint64_t end = candidates[first].patch.begin.value + candidates[first].patch.original.size();
            while (last < candidates.size() && candidates[last].patch.begin.value < end) {
                end = std::max(end, candidates[last].patch.begin.value + candidates[last].patch.original.size());
                ++last;
            }
            if (last - first > 1)
                for (std::size_t i = first; i < last; ++i) overlapping[i] = true;
            first = last;
        }
        std::vector<PatchSpan> patches;
        for (std::size_t i = 0; i < candidates.size(); ++i) {
            if (overlapping[i])
                skip(candidates[i].index, "Relocation field overlaps another supported dynamic relocation");
            else {
                result.applied_indices.push_back(candidates[i].index);
                if (candidates[i].resolved_symbol)
                    result.resolved_symbols.push_back(*candidates[i].resolved_symbol);
                patches.push_back(std::move(candidates[i].patch));
            }
        }
        if (!metadata.relocations_complete)
            skip(UINT64_MAX, "ELF relocation metadata is incomplete; additional records may be unapplied");
        auto overlay = make_overlay(source.image->storage(), patches);
        if (!overlay) return overlay.error();
        auto layout = source.image->layout();
        shift_layout(layout, load_bias, !metadata.header.is_64);
        auto image = Image::create(std::move(overlay.value()), std::move(layout));
        if (!image) return image.error();
        result.image = std::move(image.value());
        return result;
    } catch (const RuntimeRelocationFailure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate ELF runtime relocation view"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "ELF runtime relocation view exceeds container limits"};
    }
}
} // namespace hexlab
