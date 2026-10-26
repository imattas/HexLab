#include "functions_internal.hpp"
#include "instruction_flow.hpp"
#include "dex_switch_internal.hpp"
#include "control_target.hpp"
#include "hexlab/analysis/relocations.hpp"
#include "hexlab/core/byte_reader.hpp"
#include "hexlab/analysis/switches.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <map>
namespace hexlab::function_detail {
namespace {
const char *seed_kind_name(FunctionSeedKind kind) {
    switch (kind) {
    case FunctionSeedKind::entry: return "image entry";
    case FunctionSeedKind::export_symbol: return "export";
    case FunctionSeedKind::direct_call: return "direct call";
    case FunctionSeedKind::user_function: return "user function decision";
    case FunctionSeedKind::user_code: return "user code decision";
    case FunctionSeedKind::symbol: return "symbol";
    case FunctionSeedKind::unwind: return "unwind metadata";
    case FunctionSeedKind::arm_context_root: return "ARM context root";
    case FunctionSeedKind::tls_callback: return "TLS callback";
    case FunctionSeedKind::initializer: return "initializer metadata";
    case FunctionSeedKind::guard_cf: return "Guard CF metadata";
    }
    return "unknown function evidence";
}
std::string seed_provenance_text(const FunctionSeed &seed) {
    std::string text = seed_kind_name(seed.kind);
    if (seed.unwind_evidence)
        text += " (section " + std::to_string(seed.unwind_evidence->section) + ", record @ file offset " +
                std::to_string(seed.unwind_evidence->file_offset) + ")";
    if (seed.initializer_evidence) {
        const auto &evidence = *seed.initializer_evidence;
        text += " (initializer slot";
        if (evidence.file_offset)
            text += " @ file offset " + std::to_string(*evidence.file_offset);
        for (const auto *rows : {&evidence.relocation_rows, &evidence.dyld_classic_rows,
                                 &evidence.dyld_chained_rows})
            for (const auto row : *rows)
                text += ", fixup row " + std::to_string(row);
        text += ")";
    }
    return text;
}
std::string it_state_text(ThumbITState state) {
    if (!state.known)
        return "unknown";
    if (state.bits == 0)
        return "clear";
    return "mask " + std::to_string(state.bits);
}
} // namespace
uint64_t Ids::make(FactKind kind, Address address, std::span<const std::byte> extra) {
    std::vector<std::byte> key{std::byte(static_cast<unsigned>(kind))};
    for (auto value : {uint64_t(address.space.value), address.offset}) {
        const auto encoded = encode_u64(value);
        key.insert(key.end(), encoded.begin(), encoded.end());
    }
    key.insert(key.end(), extra.begin(), extra.end());
    Sha256 hash;
    take(hash.update(key));
    const auto digest = hash.digest();
    auto id = take(decode_u64(std::span(digest).first(8)));
    if (!id)
        id = 1;
    auto [found, inserted] = assigned_.emplace(FactKey{kind, id}, key);
    if (!inserted && found->second != key)
        throw Failure{{ErrorCode::conflict, "Stable analysis ID collision"}};
    return id;
}
const RegionDecision *Recovery::region_at(Address address) const {
    auto found = std::upper_bound(regions.begin(), regions.end(), address, [](Address value, const auto *region) {
        return AddressLess{}(value, region->begin);
    });
    if (found == regions.begin())
        return nullptr;
    const auto *region = *std::prev(found);
    return region->begin.space == address.space && address.offset >= region->begin.offset &&
                   address.offset - region->begin.offset < region->size
               ? region
               : nullptr;
}
std::optional<FunctionStopReason> Recovery::permission(Address address, bool instruction_start) const {
    const auto *segment = image.segment_at(address);
    if (!segment)
        return FunctionStopReason::unmapped;
    if (address.offset - segment->begin.offset >= segment->file_size)
        return FunctionStopReason::uninitialized;
    if (!image.code_window(address, 1))
        return FunctionStopReason::image_exclusion;
    const auto *region = region_at(address);
    if (region && region->kind == RegionKind::data)
        return FunctionStopReason::manual_data;
    if (instruction_start && !take(relocations.code_start(address, stop)))
        return FunctionStopReason::macho_dyld;
    if (!segment->executable && (!region || region->kind != RegionKind::code))
        return FunctionStopReason::non_executable;
    return {};
}
bool Recovery::within_chunks(Address entry, Address at, uint64_t size) const {
    const auto contains = [&](const auto &chunks) {
        for (const auto &chunk : chunks)
            if (chunk.begin.space == at.space && at.offset >= chunk.begin.offset &&
                at.offset - chunk.begin.offset < chunk.size && size <= chunk.size - (at.offset - chunk.begin.offset))
                return true;
        return false;
    };
    auto found = definitions.find(entry);
    if (found != definitions.end() && !found->second->chunks.empty())
        return contains(found->second->chunks);
    if (auto bounds = metadata_chunks.find(entry); bounds != metadata_chunks.end())
        return contains(bounds->second);
    return true;
}
bool Recovery::add_seed(AddressMap<std::vector<FunctionSeed>> &seeds, FunctionSeed seed, bool enforce_budget) {
    if (suppressed.contains(seed.entry))
        return false;
    auto found = seeds.find(seed.entry);
    if (found == seeds.end()) {
        if (enforce_budget && seeds.size() >= options.function_budget) {
            if (omitted_entries.insert(seed.entry).second)
                ++output->omitted_functions;
            output->complete = false;
            return false;
        }
        seeds.emplace(seed.entry, std::vector<FunctionSeed>{std::move(seed)});
        return true;
    }
    if (std::find(found->second.begin(), found->second.end(), seed) == found->second.end())
        found->second.push_back(std::move(seed));
    return false;
}
void Recovery::validate_decisions() {
    std::set<uint64_t> ids_seen;
    for (const auto &region : decisions.regions) {
        canceled();
        require(region.id != 0 && ids_seen.insert(region.id).second && region.size > 0 &&
                    bool(AddressRange::create(region.begin, region.size)),
                "Invalid region decision");
        require(region.kind == RegionKind::code || region.kind == RegionKind::data, "Unknown region kind");
        regions.push_back(&region);
    }
    std::sort(regions.begin(), regions.end(),
              [](const auto *a, const auto *b) { return AddressLess{}(a->begin, b->begin); });
    for (size_t i = 1; i < regions.size(); ++i)
        if (regions[i - 1]->begin.space == regions[i]->begin.space)
            require(regions[i - 1]->begin.offset + regions[i - 1]->size <= regions[i]->begin.offset,
                    "Overlapping code/data decisions must be resolved before recovery");
    for (const auto &function : decisions.functions) {
        canceled();
        require(function.id != 0 && ids_seen.insert(function.id).second &&
                    definitions.emplace(function.entry, &function).second,
                "Invalid or duplicate function decision");
        if (function.suppressed)
            suppressed.insert(function.entry);
        auto chunks = function.chunks;
        std::sort(chunks.begin(), chunks.end(),
                  [](const auto &a, const auto &b) { return AddressLess{}(a.begin, b.begin); });
        bool entry = chunks.empty();
        for (size_t i = 0; i < chunks.size(); ++i) {
            require(chunks[i].size > 0 && bool(AddressRange::create(chunks[i].begin, chunks[i].size)),
                    "Invalid explicit function chunk");
            if (i && chunks[i - 1].begin.space == chunks[i].begin.space)
                require(chunks[i - 1].begin.offset + chunks[i - 1].size <= chunks[i].begin.offset,
                        "Overlapping explicit function chunks");
            if (chunks[i].begin.space == function.entry.space && function.entry.offset >= chunks[i].begin.offset &&
                function.entry.offset - chunks[i].begin.offset < chunks[i].size)
                entry = true;
        }
        require(entry, "Explicit function entry lies outside its declared chunks");
    }
}
void Recovery::seed_roots() {
    const auto root = [&](FunctionSeed seed, bool report_invalid) {
        if (suppressed.contains(seed.entry))
            return;
        if (auto denied = permission(seed.entry)) {
            // A user data region is an explicit boundary decision. Preserve
            // metadata evidence that would otherwise have seeded code there
            // so callers can see why that candidate was rejected.
            if (*denied == FunctionStopReason::manual_data && seed.kind != FunctionSeedKind::user_function &&
                seed.kind != FunctionSeedKind::user_code)
                output->candidates.push_back({seed.entry, seed.source, *denied,
                    seed_provenance_text(seed) + " root conflicts with an explicit data decision"});
            else if (report_invalid)
                output->candidates.push_back(
                    {seed.entry, seed.source, *denied, "Function seed has no permitted initialized code"});
            return;
        }
        const auto context = take(image.context_at(seed.entry));
        if (context.architecture == Architecture::arm && context.mode == ExecutionMode::thumb) {
            const auto &profile = image.layout().arm_profile;
            const bool clear = profile && std::any_of(profile->roots.begin(), profile->roots.end(), [&](const auto &r) {
                return r.at == seed.entry && r.mode == ExecutionMode::thumb && r.known_thumb_it_clear;
            });
            if (!clear) {
                if (report_invalid)
                    output->candidates.push_back({seed.entry, seed.source, FunctionStopReason::unsupported,
                                                  "Thumb function root lacks source-backed known-clear IT state"});
                return;
            }
        }
        root_entries.insert(seed.entry);
        add_seed(roots, std::move(seed));
    };
    // Explicit user decisions consume the bounded function budget before
    // metadata-derived guesses. These roots are authoritative analysis input;
    // allowing a long symbol table to exhaust the budget first could silently
    // omit the user's selected functions or code regions.
    for (const auto &[entry, function] : definitions)
        if (!function->suppressed)
            root({FunctionSeedKind::user_function, entry, {}, function->id}, true);
    for (const auto *region : regions)
        if (region->kind == RegionKind::code)
            root({FunctionSeedKind::user_code, region->begin, {}, region->id}, true);

    for (auto entry : image.layout().entries) {
        canceled();
        root({FunctionSeedKind::entry, entry, {}, {}}, true);
    }
    // ARM code-profile roots carry source-backed execution-state declarations
    // that may not also appear in the image's generic entry list. Preserve
    // them as independent function-seed evidence for mixed A32/Thumb images.
    if (image.layout().arm_profile)
        for (const auto &profile_root : image.layout().arm_profile->roots) {
            canceled();
            root({FunctionSeedKind::arm_context_root, profile_root.at, {}, {}}, true);
        }
    for (const auto &symbol : metadata.exports) {
        canceled();
        if (symbol.address)
            root({FunctionSeedKind::export_symbol, *symbol.address, {}, {}}, false);
    }
    AddressMap<std::uint64_t> elf_symbol_sizes;
    AddressSet conflicting_elf_symbol_sizes;
    if (metadata.elf)
        for (const auto &symbol : metadata.elf->symbols) {
            canceled();
            // STT_GNU_IFUNC symbols name resolver code, not the implementation
            // address returned by the resolver. The resolver is executable
            // entry code in its own right and may be the only surviving root
            // evidence in stripped binaries.
            if ((symbol.type == 2 || symbol.type == 10) && symbol.state == ElfSymbolState::defined &&
                symbol.address) {
                root({FunctionSeedKind::symbol, *symbol.address, {}, {}}, false);
                // A nonzero STT_FUNC size can bound an entry when no unwind
                // range is available. Multiple symbol tables commonly carry
                // aliases for the same address; conflicting extents are not
                // resolved by choosing one table arbitrarily. IFUNC sizes are
                // deliberately ignored because they describe resolver symbols
                // whose runtime implementation is selected indirectly.
                if (symbol.type == 2 && symbol.size) {
                    auto [found, inserted] = elf_symbol_sizes.emplace(*symbol.address, symbol.size);
                    if (!inserted && found->second != symbol.size)
                        conflicting_elf_symbol_sizes.insert(*symbol.address);
                }
            }
        }
    // DT_INIT and DT_FINI identify runtime initializer/finalizer routines even
    // when the ordinary symbol table has been stripped. These tags carry
    // virtual addresses rather than file offsets, so normal executable and
    // initialized-byte validation still happens in root().
    if (metadata.elf && metadata.elf->header.object_type != 1 && metadata.elf->header.object_type != 4)
        for (const auto &table : metadata.elf->dynamic_tables)
            for (const auto &entry : table.entries) {
                canceled();
                if ((entry.tag == 12 || entry.tag == 13) && entry.value) {
                    FunctionSeed seed{FunctionSeedKind::initializer, {image.layout().space.id, entry.value},
                                      table.source.address, {}};
                    FunctionSeedInitializerEvidence evidence;
                    evidence.source = entry.tag == 12 ? FunctionInitializerSource::elf_init
                                                      : FunctionInitializerSource::elf_fini;
                    evidence.index = entry.index;
                    evidence.dynamic_tag = entry.tag;
                    if (table.stride && entry.index <= (UINT64_MAX - table.source.file_offset) / table.stride)
                        evidence.file_offset = table.source.file_offset + entry.index * table.stride;
                    seed.initializer_evidence = std::move(evidence);
                    root(std::move(seed), false);
                }
            }
    // Dynamic initializer arrays contain pointer-sized slots. Resolve slots
    // through the format relocation index first; opaque or ambiguous fixups
    // are never interpreted as raw pointers. This also handles RELATIVE
    // relocations explicitly, whose result depends on the current image bias.
    if (metadata.elf && metadata.elf->header.object_type != 1 && metadata.elf->header.object_type != 4) {
        struct DynamicValue { std::optional<std::uint64_t> value; bool conflict = false; };
        std::map<std::int64_t, DynamicValue> tags;
        for (const auto &table : metadata.elf->dynamic_tables) {
            canceled();
            for (const auto &entry : table.entries) {
                canceled();
                if (entry.tag != 25 && entry.tag != 26 && entry.tag != 27 && entry.tag != 28 &&
                    entry.tag != 32 && entry.tag != 33)
                    continue;
                auto &slot = tags[entry.tag];
                if (slot.value && *slot.value != entry.value)
                    slot.conflict = true;
                else
                    slot.value = entry.value;
            }
        }
        std::uint64_t load_bias = 0;
        if (!image.layout().segments.empty()) {
            const auto mapped_base = std::min_element(image.layout().segments.begin(), image.layout().segments.end(),
                [](const auto &a, const auto &b) { return a.begin.offset < b.begin.offset; })->begin.offset;
            if (mapped_base >= metadata.preferred_base)
                load_bias = mapped_base - metadata.preferred_base;
            else
                output->complete = false;
        }
        const auto width = metadata.elf->header.is_64 ? std::uint8_t{8} : std::uint8_t{4};
        auto resolver_result = RelocationResolver::create(image, metadata, stop);
        if (!resolver_result)
            output->complete = false;
        else {
            const auto &resolver = resolver_result.value();
            constexpr std::array<std::pair<std::int64_t, std::int64_t>, 3> array_tags{{{32, 33}, {25, 27}, {26, 28}}};
            for (const auto [address_tag, size_tag] : array_tags) {
                canceled();
                const auto address = tags.find(address_tag), size = tags.find(size_tag);
                if (address == tags.end() || size == tags.end() || address->second.conflict || size->second.conflict ||
                    !address->second.value || !size->second.value) {
                    if ((address != tags.end()) != (size != tags.end()) ||
                        (address != tags.end() && address->second.conflict) ||
                        (size != tags.end() && size->second.conflict)) output->complete = false;
                    continue;
                }
                const auto array_size = *size->second.value;
                if (!array_size) continue;
                if (array_size % width || array_size / width > 65536) {
                    output->complete = false;
                    continue;
                }
                const auto array_offset = checked_add(*address->second.value, load_bias);
                if (!array_offset) { output->complete = false; continue; }
                for (std::uint64_t offset = 0; offset < array_size; offset += width) {
                    canceled();
                    if (offset > UINT64_MAX - array_offset.value()) { output->complete = false; break; }
                    const Address slot{image.layout().space.id, array_offset.value() + offset};
                    const auto *segment = image.segment_at(slot);
                    if (!segment || !segment->readable || slot.offset < segment->begin.offset) {
                        output->complete = false;
                        continue;
                    }
                    const auto relative = slot.offset - segment->begin.offset;
                    if (relative >= segment->file_size || width > segment->file_size - relative) {
                        output->complete = false;
                        continue;
                    }
                    auto resolved = resolver.data_at(image, slot, width, stop);
                    if (!resolved) {
                        output->complete = false;
                        continue;
                    }
                    std::optional<Address> target = resolved.value().address;
                    if (target && metadata.elf->header.object_type == 3 && load_bias) {
                        const auto rebased = checked_add(target->offset, load_bias);
                        if (rebased) target->offset = rebased.value();
                        else target.reset();
                    }
                    bool opaque_relocation = resolved.value().relocated() && !target;
                    // The general resolver intentionally leaves base-relative
                    // relocations opaque. Their exact ELF equation is B + A.
                    if (!target && metadata.elf) {
                        const ElfRelocation *match = nullptr;
                        for (const auto index : resolved.value().relocations) {
                            canceled();
                            if (index >= metadata.elf->relocations.size()) {
                                output->complete = false;
                                opaque_relocation = true;
                                continue;
                            }
                            const auto &relocation = metadata.elf->relocations[static_cast<std::size_t>(index)];
                            if (relocation.field_size.value_or(0) != width)
                                continue;
                            if (match) { match = nullptr; opaque_relocation = true; break; }
                            match = &relocation;
                        }
                        if (match && match->kind == ElfRelocationKind::base_relative && match->addend) {
                            const auto addend = *match->addend;
                            std::optional<std::uint64_t> value;
                            if (addend >= 0) {
                                const auto sum = checked_add(load_bias, static_cast<std::uint64_t>(addend));
                                if (sum) value = sum.value();
                            }
                            else {
                                const auto magnitude = static_cast<std::uint64_t>(-(addend + 1)) + 1;
                                if (load_bias >= magnitude) value = load_bias - magnitude;
                            }
                            if (value) { target = Address{image.layout().space.id, *value}; opaque_relocation = false; }
                        }
                    }
                    if (!target && !opaque_relocation) {
                        auto bytes = image.read(slot, width);
                        if (!bytes) { output->complete = false; continue; }
                        ByteReader reader(bytes.value());
                        std::optional<std::uint64_t> value;
                        if (width == 8) {
                            auto decoded = reader.read_u64(image.layout().space.order);
                            if (decoded) value = decoded.value();
                        } else {
                            auto decoded = reader.read_u32(image.layout().space.order);
                            if (decoded) value = decoded.value();
                        }
                        if (!value) { output->complete = false; continue; }
                        if (*value) {
                            auto target_offset = *value;
                            if (metadata.elf->header.object_type == 3 && load_bias) {
                                const auto rebased = checked_add(target_offset, load_bias);
                                const auto executable_initialized = [&](std::uint64_t candidate) {
                                    const Address at{image.layout().space.id, candidate};
                                    const auto *mapped = image.segment_at(at);
                                    return mapped && mapped->executable && candidate >= mapped->begin.offset &&
                                        candidate - mapped->begin.offset < mapped->file_size &&
                                        image.code_window(at, 1) != 0;
                                };
                                const bool raw_valid = executable_initialized(target_offset);
                                const bool rebased_valid = rebased && executable_initialized(rebased.value());
                                if (raw_valid == rebased_valid) {
                                    if (raw_valid) output->complete = false; // Both address interpretations are plausible.
                                    continue;
                                }
                                if (rebased_valid) target_offset = rebased.value();
                            }
                            target = Address{image.layout().space.id, target_offset};
                        }
                    }
                    if (opaque_relocation) output->complete = false;
                    if (target) {
                        FunctionSeed seed{FunctionSeedKind::initializer, *target, slot, {}};
                        FunctionSeedInitializerEvidence evidence;
                        evidence.source = address_tag == 32 ? FunctionInitializerSource::elf_preinit_array
                                          : address_tag == 25 ? FunctionInitializerSource::elf_init_array
                                                              : FunctionInitializerSource::elf_fini_array;
                        evidence.index = offset / width;
                        evidence.dynamic_tag = address_tag;
                        if (const auto file = image.to_file_offset(slot); file)
                            evidence.file_offset = file.value().value;
                        evidence.relocation_rows = resolved.value().relocations;
                        seed.initializer_evidence = std::move(evidence);
                        root(std::move(seed), false);
                    }
                }
            }
        }
    }
    // Validated DWARF FDE ranges are compiler/linker function-boundary evidence.
    // The ELF metadata row retains the exact source section and FDE byte extent.
    if (metadata.elf)
        for (const auto &range : metadata.elf->unwind_ranges) {
            canceled();
            metadata_chunks[range.begin].push_back({range.begin, range.size, {}});
            FunctionSeed seed{FunctionSeedKind::unwind, range.begin, {}, {}};
            seed.unwind_evidence = FunctionSeedUnwindEvidence{range.section, range.file_offset, range.record_size};
            root(std::move(seed), false);
        }
    if (metadata.macho) {
        const bool valid_slice = metadata.macho->selected_slice < metadata.macho->container.slices.size();
        if (!valid_slice) output->complete = false;
        const auto pointer_width = valid_slice && metadata.macho->container.slices[metadata.macho->selected_slice].header.is_64
            ? std::uint8_t{8} : std::uint8_t{4};
        auto resolver_result = RelocationResolver::create(image, metadata, stop);
        if (!valid_slice || !resolver_result) output->complete = false;
        else for (const auto &section : metadata.macho->sections) {
            canceled();
            // S_MOD_INIT_FUNC_POINTERS is the Mach-O section type used for
            // __mod_init_func. Resolve each slot through relocation/dyld data
            // before considering an unrelocated pointer word.
            if (section.name != "__mod_init_func" || (section.flags & 0xffu) != 9u)
                continue;
            if (!section.file_offset) { output->complete = false; continue; }
            if (section.size % pointer_width || section.size / pointer_width > 65536) {
                output->complete = false;
                continue;
            }
            for (std::uint64_t offset = 0; offset < section.size; offset += pointer_width) {
                canceled();
                if (offset > UINT64_MAX - section.file_offset->value) { output->complete = false; break; }
                const FileOffset file{section.file_offset->value + offset};
                const auto slot_address = image.to_address(file);
                if (!slot_address) { output->complete = false; continue; }
                const Address slot = slot_address.value();
                const auto *segment = image.segment_at(slot);
                if (!segment || !segment->readable || slot.offset < segment->begin.offset) {
                    output->complete = false;
                    continue;
                }
                const auto relative = slot.offset - segment->begin.offset;
                if (relative >= segment->file_size || pointer_width > segment->file_size - relative) {
                    output->complete = false;
                    continue;
                }
                auto resolved = resolver_result.value().data_at(image, slot, pointer_width, stop);
                if (!resolved) { output->complete = false; continue; }
                std::optional<Address> target = resolved.value().address;
                if (resolved.value().relocated() && !target) output->complete = false;
                if (!target && !resolved.value().relocated()) {
                    auto bytes = image.read(slot, pointer_width);
                    if (!bytes) { output->complete = false; continue; }
                    ByteReader reader(bytes.value());
                    std::optional<std::uint64_t> value;
                    if (pointer_width == 8) {
                        auto decoded = reader.read_u64(image.layout().space.order);
                        if (decoded) value = decoded.value();
                    } else {
                        auto decoded = reader.read_u32(image.layout().space.order);
                        if (decoded) value = decoded.value();
                    }
                    if (!value) { output->complete = false; continue; }
                    if (*value) target = Address{image.layout().space.id, *value};
                }
                if (target) {
                    FunctionSeed seed{FunctionSeedKind::initializer, *target, slot, {}};
                    FunctionSeedInitializerEvidence evidence;
                    evidence.source = FunctionInitializerSource::macho_mod_init_func;
                    evidence.section = section.ordinal;
                    evidence.index = offset / pointer_width;
                    evidence.file_offset = file.value;
                    evidence.relocation_rows = resolved.value().relocations;
                    if (resolved.value().dyld)
                        for (const auto origin : resolved.value().dyld->resolution.origins)
                            (origin.source == MachODyldSource::classic ? evidence.dyld_classic_rows
                                                                      : evidence.dyld_chained_rows)
                                .push_back(origin.row);
                    seed.initializer_evidence = std::move(evidence);
                    root(std::move(seed), false);
                }
            }
        }
        for (const auto &initializer : metadata.macho->initializers) {
            canceled();
            if (initializer.address) {
                FunctionSeed seed{FunctionSeedKind::initializer, *initializer.address, {}, {}};
                FunctionSeedInitializerEvidence evidence;
                evidence.source = FunctionInitializerSource::macho_routines;
                evidence.index = initializer.command_index;
                evidence.file_offset = initializer.record_file_offset;
                seed.initializer_evidence = std::move(evidence);
                root(std::move(seed), false);
            }
        }
        for (const auto &symbol : metadata.macho->dyld_exports) {
            canceled();
            if (symbol.is_definition()) {
                root({FunctionSeedKind::export_symbol, *symbol.address, {}, {}}, false);
                if (symbol.resolver_address)
                    root({FunctionSeedKind::export_symbol, *symbol.resolver_address, {}, {}}, false);
            }
        }
        for (const auto &symbol : metadata.macho->symbols) {
            canceled();
            if (symbol.code && symbol.address)
                root({FunctionSeedKind::symbol, *symbol.address, {}, {}}, false);
        }
        for (const auto &start : metadata.macho->function_starts) {
            canceled();
            if (start.address)
                root({FunctionSeedKind::symbol, *start.address, {}, {}}, false);
        }
        // Validated __eh_frame FDE ranges carry function-boundary evidence,
        // even when the binary has no symbol or compact-unwind entry for the
        // function. Retain the range as a metadata chunk so fallthrough cannot
        // merge adjacent functions when the FDE gives us an exact extent.
        for (const auto &function : metadata.macho->eh_frame_functions) {
            canceled();
            if (!function.address || function.size == 0 ||
                !AddressRange::create(*function.address, function.size))
                continue;
            metadata_chunks[*function.address].push_back({*function.address, function.size, {}});
            root({FunctionSeedKind::unwind, *function.address, {}, {}}, false);
        }
    }
    // PDB procedures are compiler-declared function boundaries. Consume them
    // only when the PDB identity was verified against this PE image; stale or
    // partially matched debug data must not split trusted code ownership.
    if (metadata.pe && metadata.pe->pdb_status == PePdbStatus::matched)
        for (const auto &symbol : metadata.pe->pdb_symbols) {
            canceled();
            if (symbol.procedure && symbol.address)
                root({FunctionSeedKind::symbol, *symbol.address, {}, {}}, false);
        }
    // PE TLS callbacks are invoked by the loader independently of the image
    // entry point, so they are execution roots even when no symbol names them.
    if (metadata.pe && metadata.pe->tls) {
        auto load_base = metadata.preferred_base;
        for (const auto &segment : image.layout().segments)
            if (segment.name == "headers") {
                load_base = segment.begin.offset;
                break;
            }
        for (const auto &callback : metadata.pe->tls->callbacks) {
            canceled();
            const auto offset = checked_add(load_base, callback.rva);
            if (!offset)
                continue;
            root({FunctionSeedKind::tls_callback, {image.layout().space.id, offset.value()}, {}, {}}, false);
        }
    }
    // The validated Guard CF function table is linker-provided evidence for
    // address-taken entry points. Treat these RVAs as roots so functions that
    // are only reached through indirect calls are still analyzed. The normal
    // root checks reject entries outside initialized executable code.
    if (metadata.pe && metadata.pe->load_configuration &&
        !metadata.pe->load_configuration->guard_functions.empty()) {
        auto load_base = metadata.preferred_base;
        for (const auto &segment : image.layout().segments)
            if (segment.name == "headers") {
                load_base = segment.begin.offset;
                break;
            }
        for (const auto &function : metadata.pe->load_configuration->guard_functions) {
            canceled();
            const auto offset = checked_add(load_base, function.rva);
            if (!offset) {
                output->complete = false;
                continue;
            }
            root({FunctionSeedKind::guard_cf, {image.layout().space.id, offset.value()}, {}, {}}, false);
        }
    }
    // AMD64 exception-directory entries are linker-emitted function bounds.
    // Translate their RVAs using the image's actual mapped base so rebased PE
    // images receive roots at their current virtual addresses.
    if (metadata.pe && metadata.machine == 0x8664) {
        auto load_base = metadata.preferred_base;
        for (const auto &segment : image.layout().segments)
            if (segment.name == "headers") {
                load_base = segment.begin.offset;
                break;
            }
        const auto &runtime_functions = metadata.pe->exception_functions;
        // A chained AMD64 runtime-function row describes a discontiguous
        // fragment that shares the primary function's unwind state. Fold it
        // into the matching primary function's ownership chunks and avoid
        // inventing a second function entry for that fragment. Require the
        // complete chained tuple to identify a real row in this table; if it
        // does not, retain the row as an ordinary independently rooted range.
        std::vector<bool> chained_fragments(runtime_functions.size(), false);
        for (std::size_t i = 0; i < runtime_functions.size(); ++i) {
            const auto &fragment = runtime_functions[i];
            if (!fragment.unwind_info || !fragment.unwind_info->chained_function)
                continue;
            const auto &parent = *fragment.unwind_info->chained_function;
            const auto found = std::find_if(runtime_functions.begin(), runtime_functions.end(), [&](const auto &row) {
                return row.begin_rva == parent.begin_rva && row.end_rva == parent.end_rva &&
                       row.unwind_info_rva == parent.unwind_info_rva;
            });
            if (found == runtime_functions.end() || found->begin_rva == fragment.begin_rva)
                continue;
            const auto parent_offset = checked_add(load_base, parent.begin_rva);
            const auto fragment_offset = checked_add(load_base, fragment.begin_rva);
            if (!parent_offset || !fragment_offset)
                continue;
            const Address parent_entry{image.layout().space.id, parent_offset.value()};
            const Address fragment_entry{image.layout().space.id, fragment_offset.value()};
            metadata_chunks[parent_entry].push_back({fragment_entry, fragment.end_rva - fragment.begin_rva, {}});
            chained_fragments[i] = true;
        }
        for (std::size_t index = 0; index < runtime_functions.size(); ++index) {
            canceled();
            const auto &function = runtime_functions[index];
            if (chained_fragments[index])
                continue;
            const auto offset = checked_add(load_base, function.begin_rva);
            if (!offset)
                continue;
            const Address entry{image.layout().space.id, offset.value()};
            if (function.end_rva > function.begin_rva)
                metadata_chunks[entry].push_back({entry, function.end_rva - function.begin_rva, {}});
            FunctionSeed seed{FunctionSeedKind::unwind, entry, {}, {}};
            std::uint64_t record_size = 0;
            for (const auto &span : function.source.spans) {
                if (span.size > std::numeric_limits<std::uint64_t>::max() - record_size) {
                    record_size = 0;
                    break;
                }
                record_size += span.size;
            }
            if (!function.source.spans.empty() && record_size != 0)
                seed.unwind_evidence = FunctionSeedUnwindEvidence{function.source.index,
                    function.source.spans.front().offset.value, record_size};
            if (seed.unwind_evidence)
                root(std::move(seed), false);
        }
    }
    // ARM64 .pdata starts are linker-provided unwind boundaries. Keep the
    // table row as the seed evidence and translate its RVA against the image's
    // current mapped base so rebased images retain correct virtual roots.
    if (metadata.pe && metadata.machine == 0xaa64) {
        auto load_base = metadata.preferred_base;
        for (const auto &segment : image.layout().segments)
            if (segment.name == "headers") {
                load_base = segment.begin.offset;
                break;
            }
        for (const auto &function : metadata.pe->arm64_exception_functions) {
            canceled();
            const auto offset = checked_add(load_base, function.begin_rva);
            if (!offset) continue;
            const Address entry{image.layout().space.id, offset.value()};
            FunctionSeed seed{FunctionSeedKind::unwind, entry, {}, {}};
            std::uint64_t record_size = 0;
            bool valid_source = !function.source.spans.empty();
            for (const auto &span : function.source.spans) {
                if (span.size == 0 || span.size > std::numeric_limits<std::uint64_t>::max() - record_size) {
                    valid_source = false;
                    break;
                }
                record_size += span.size;
            }
            // ARM64 .pdata rows are exactly eight bytes. Do not turn a
            // normalized row without complete source provenance into a root.
            if (!valid_source || record_size != 8) {
                output->complete = false;
                continue;
            }
            seed.unwind_evidence = FunctionSeedUnwindEvidence{function.source.index,
                function.source.spans.front().offset.value, record_size};
            if (function.function_length)
                metadata_chunks[entry].push_back({entry, function.function_length, {}});
            root(std::move(seed), false);
        }
    }
    // Use a symbol-table extent only as a conservative ownership bound when
    // its aliases agree, the complete range is initialized executable code,
    // and no stronger unwind or explicit user range is already available.
    for (const auto &[entry, size] : elf_symbol_sizes) {
        canceled();
        if (conflicting_elf_symbol_sizes.contains(entry) || !root_entries.contains(entry) ||
            definitions.contains(entry) || metadata_chunks.contains(entry) || !size ||
            !AddressRange::create(entry, size))
            continue;
        const auto *segment = image.segment_at(entry);
        if (!segment || !segment->executable || entry.offset < segment->begin.offset)
            continue;
        const auto relative = entry.offset - segment->begin.offset;
        if (relative >= segment->file_size || size > segment->file_size - relative ||
            relative >= segment->size || size > segment->size - relative || image.code_window(entry, size) != size)
            continue;
        metadata_chunks[entry].push_back({entry, size, {}});
    }
    all_seeds = roots;
}
Node &Recovery::node(Address address, ThumbITState incoming_it) {
    auto found = nodes.find(address);
    if (found != nodes.end()) {
        if (found->second.fact && found->second.fact->instruction.context.mode == ExecutionMode::thumb &&
            found->second.incoming_it != incoming_it) {
            found->second.fact.reset();
            found->second.edges.clear();
            found->second.stop = FunctionStop{address, FunctionStopReason::unsupported,
                                               "Thumb address reached with incompatible IT states: existing " +
                                                   it_state_text(found->second.incoming_it) + ", incoming " +
                                                   it_state_text(incoming_it)};
            output->complete = false;
        }
        return found->second;
    }
    canceled();
    Node value;
    value.at = address;
    value.incoming_it = incoming_it;
    thumb_states.emplace(address, incoming_it);
    const auto finish = [&]() -> Node & { return nodes.emplace(address, std::move(value)).first->second; };
    if (auto denied = permission(address)) {
        value.stop = FunctionStop{address, *denied, "Control flow has no permitted initialized bytes"};
        if (auto region = region_at(address))
            value.decisions.push_back(region->id);
        return finish();
    }
    if (discovery_exhausted || attempts >= options.instruction_budget) {
        value.stop = FunctionStop{address, FunctionStopReason::budget, "Instruction/discovery budget reached"};
        return finish();
    }
    ++attempts;
    auto cached = reusable_instructions.find(address);
    bool reuse = cached != reusable_instructions.end();
    if (reuse && cached->second->instruction.context != take(image.context_at(address)))
        reuse = false;
    if (reuse && cached->second->instruction.context.mode == ExecutionMode::thumb &&
        (!cached->second->instruction.arm || cached->second->instruction.arm->it_before != incoming_it))
        reuse = false;
    if (reuse) {
        for (size_t i = 0; i < cached->second->instruction.length; ++i) {
            auto at = advance(address, i);
            if (!at || permission(at.value(), false)) {
                reuse = false;
                break;
            }
        }
    }
    if (reuse) {
        value.fact = cached->second;
        value.window = value.fact->reads;
        const auto &instruction = value.fact->instruction;
        require(ids.make(FactKind::instruction, address, instruction.encoded_bytes()) ==
                    value.fact->id,
                "Reusable instruction identity does not match bytes");
        for (size_t i = 0; i < instruction.byte_length(); ++i) {
            auto at = take(advance(address, i));
            if (const auto *region = region_at(at))
                if (std::find(value.decisions.begin(), value.decisions.end(), region->id) == value.decisions.end())
                    value.decisions.push_back(region->id);
        }
        ++reused_instructions;
    } else {
        ++decoded_instructions;
        const auto context = take(image.context_at(address));
        std::vector<std::byte> input;
        size_t available = 0;
        std::optional<FunctionStopReason> boundary;
        const auto read_window = [&](size_t limit) {
            input.clear();
            available = 0;
            boundary.reset();
            input.reserve(limit);
            for (; available < limit; ++available) {
                const auto at = advance(address, available);
                if (!at) break;
                boundary = permission(at.value(), false);
                if (boundary) break;
                const auto offset = take(image.to_file_offset(at.value()));
                const auto view = take(image.storage()->read_at(offset, 1));
                require(view.bytes.size() == 1, "Incomplete source read while decoding");
                input.push_back(view.bytes[0]);
                take(value.window.include(offset, 1));
            }
        };
        const auto decode_window = [&]() {
            return context.mode == ExecutionMode::thumb
                       ? decode_thumb(input, address, incoming_it)
                       : take(decode_analysis_instruction(context, input, address, options));
        };
        read_window(context.architecture == Architecture::jvm ? 16 : 15);
        auto decoded = decode_window();
        if (context.architecture == Architecture::jvm && decoded.status == DecodeStatus::truncated &&
            available && (input[0] == std::byte{0xaa} || input[0] == std::byte{0xab}) && available >= 16) {
            const auto read_u32 = [&](size_t offset) {
                return std::bit_cast<std::int32_t>((std::uint32_t(std::to_integer<std::uint8_t>(input[offset])) << 24) |
                                                   (std::uint32_t(std::to_integer<std::uint8_t>(input[offset + 1])) << 16) |
                                                   (std::uint32_t(std::to_integer<std::uint8_t>(input[offset + 2])) << 8) |
                                                   std::uint32_t(std::to_integer<std::uint8_t>(input[offset + 3])));
            };
            const auto padding = static_cast<size_t>((4 - ((address.offset + 1) & 3)) & 3);
            const auto switch_header = 1 + padding;
            std::optional<size_t> required;
            if (input[0] == std::byte{0xaa} && available >= switch_header + 12) {
                const auto low = read_u32(switch_header + 4);
                const auto high = read_u32(switch_header + 8);
                if (high >= low) {
                    const auto count = std::uint64_t(std::int64_t(high) - low) + 1;
                    if (count <= 1024) required = switch_header + 12 + static_cast<size_t>(count) * 4;
                }
            } else if (input[0] == std::byte{0xab} && available >= switch_header + 8) {
                const auto pairs = read_u32(switch_header + 4);
                if (pairs >= 0 && pairs <= 1024)
                    required = switch_header + 8 + static_cast<size_t>(pairs) * 8;
            }
            if (required && *required > available && *required <= 65535) {
                read_window(*required);
                decoded = decode_window();
            }
        }
        if (!decoded.instruction) {
            for (size_t i = 0; i < available; ++i) {
                const auto at = take(advance(address, i));
                if (const auto *region = region_at(at))
                    if (std::find(value.decisions.begin(), value.decisions.end(), region->id) == value.decisions.end())
                        value.decisions.push_back(region->id);
            }
            if (boundary) {
                auto at = advance(address, available);
                if (at)
                    if (const auto *region = region_at(at.value()))
                        if (std::find(value.decisions.begin(), value.decisions.end(), region->id) ==
                            value.decisions.end())
                            value.decisions.push_back(region->id);
            }
            auto reason = decoded.status == DecodeStatus::unsupported ? FunctionStopReason::unsupported
                          : decoded.status == DecodeStatus::invalid   ? FunctionStopReason::invalid
                                                                      : FunctionStopReason::truncated;
            if (reason == FunctionStopReason::truncated && boundary == FunctionStopReason::manual_data)
                reason = FunctionStopReason::manual_data;
            if (reason == FunctionStopReason::truncated && boundary == FunctionStopReason::image_exclusion)
                reason = FunctionStopReason::image_exclusion;
            value.stop = FunctionStop{address, reason, std::move(decoded.reason)};
            return finish();
        }
        auto fact = std::make_shared<InstructionFact>();
        fact->instruction = std::move(*decoded.instruction);
        const auto &instruction = fact->instruction;
        fact->id = ids.make(FactKind::instruction, address, instruction.encoded_bytes());
        for (size_t i = 0; i < instruction.byte_length(); ++i) {
            const auto at = take(advance(address, i));
            take(fact->reads.include(take(image.to_file_offset(at)), 1));
            if (const auto *region = region_at(at))
                if (std::find(value.decisions.begin(), value.decisions.end(), region->id) == value.decisions.end())
                    value.decisions.push_back(region->id);
        }
        if (fact->instruction.opcode == Opcode::dex_switch) {
            auto table = function_detail::populate_dex_switch_table(image, fact->instruction, &fact->reads, stop);
            if (!table) {
                if (table.error().code == ErrorCode::canceled)
                    throw Failure{table.error()};
                value.stop = FunctionStop{address, FunctionStopReason::unsupported,
                                          "DEX switch payload rejected: " + table.error().message};
                output->complete = false;
            }
            value.window = fact->reads;
        }
        value.fact = std::move(fact);
    }
    const auto &instruction = value.fact->instruction;
    if (delayed_slots.contains(address)) {
        if ((instruction.opcode == Opcode::opaque && instruction.operands.empty()) || instruction.opcode == Opcode::x86_opaque ||
            instruction.flow != FlowKind::fallthrough || instruction.delay_slots) {
            value.stop = FunctionStop{address, FunctionStopReason::unsupported,
                                      "Control transfer in a MIPS delay slot is unsupported"};
        }
        if (const auto delayed_edge = delayed_edges.find(address); delayed_edge != delayed_edges.end())
            value.edges = delayed_edge->second;
        return finish();
    }
    if (instruction.opcode == Opcode::x86_opaque ||
        (instruction.opcode == Opcode::opaque && instruction.operands.empty())) {
        value.stop = FunctionStop{address, FunctionStopReason::unsupported,
                                  "Instruction length is known, but typed operand/control-flow semantics are unavailable"};
        return finish();
    }
    if (take(relocations.instruction_fixup(instruction, stop))) {
        value.stop =
            FunctionStop{address, FunctionStopReason::macho_dyld, "Runtime fixup affects instruction opcode bytes"};
        return finish();
    }
    const auto target = take(relocations.control_target(image, instruction, stop));
    if (analysis_detail::has_delay_slot(instruction)) {
        const auto slot = take(analysis_detail::delay_slot_address(instruction));
        delayed_slots.insert(slot);
        value.edges.push_back({slot, BlockEdgeKind::delay_slot});
    }
    const auto continuation = [&](BlockEdgeKind kind) {
        auto next = analysis_detail::continuation_address(instruction);
        if (next) {
            const auto next_context = image.context_at(next.value());
            if (!next_context || next_context.value() != instruction.context) {
                value.stop = FunctionStop{address, FunctionStopReason::unsupported,
                                          "Fallthrough crosses a declared execution-context boundary"};
                return;
            }
        }
        if (next)
            value.edges.push_back({next.value(), kind,
                                   instruction.context.mode == ExecutionMode::thumb && instruction.arm
                                       ? instruction.arm->it_after
                                       : ThumbITState{}});
        else
            value.stop =
                FunctionStop{address, FunctionStopReason::target_overflow, "Continuation exceeds address model"};
    };
    const auto unresolved = [&]() {
        if (!instruction.operands.empty()) {
            const auto resolution = take(relocations.operand(instruction, 0, stop));
            if (resolution.dyld)
                return FunctionStopReason::macho_dyld;
            if (resolution.relocated())
                return relocations.format() == RelocationFormat::macho ? FunctionStopReason::macho_relocation
                                                                       : FunctionStopReason::elf_relocation;
        }
        return std::any_of(instruction.operands.begin(), instruction.operands.end(),
                           [](const auto &operand) { return std::holds_alternative<RelativeOperand>(operand); })
                   ? FunctionStopReason::target_overflow
                   : FunctionStopReason::indirect;
    };
    const auto arm_target_matches = [&]() {
        if (instruction.context.architecture != Architecture::arm || !target)
            return true;
        if (!instruction.arm)
            return false;
        const auto target_context = image.context_at(*target);
        if (!instruction.arm->target_mode)
            return analysis_detail::is_arm_literal_pc_load(instruction) && target_context &&
                   (target_context.value().mode == ExecutionMode::a32 || target_context.value().mode == ExecutionMode::thumb);
        return target_context && target_context.value().mode == *instruction.arm->target_mode;
    };
    const auto target_it = [&]() {
        if (instruction.context.mode == ExecutionMode::thumb && instruction.arm)
            return instruction.arm->it_after;
        if (instruction.arm && instruction.arm->target_mode == ExecutionMode::thumb)
            return ThumbITState{true, 0};
        if (target && analysis_detail::is_arm_literal_pc_load(instruction)) {
            const auto context = image.context_at(*target);
            if (context && context.value().mode == ExecutionMode::thumb)
                return ThumbITState{true, 0};
        }
        return ThumbITState{};
    };
    switch (instruction.flow) {
    case FlowKind::ret:
        value.stop = FunctionStop{address, FunctionStopReason::ret, "Return"};
        if (instruction.arm && (instruction.arm->predicate == ArmPredicate::condition ||
                                instruction.arm->predicate == ArmPredicate::unknown_it))
            continuation(BlockEdgeKind::conditional_false);
        break;
    case FlowKind::trap:
        value.stop = FunctionStop{address, FunctionStopReason::trap, "Trap"};
        if (instruction.context.architecture == Architecture::arm && instruction.arm &&
            instruction.arm->predicate == ArmPredicate::condition)
            continuation(BlockEdgeKind::conditional_false);
        break;
    case FlowKind::fallthrough:
        continuation(BlockEdgeKind::fallthrough);
        break;
    case FlowKind::call:
        value.call = true;
        value.call_target = arm_target_matches() ? target : std::nullopt;
        if (value.call_target && target_it().known)
            thumb_states.emplace(*value.call_target, target_it());
        if (!value.call_target)
            value.call_issue = FunctionStop{
                address,
                instruction.context.architecture == Architecture::arm && target ? FunctionStopReason::unsupported
                                                                                 : unresolved(),
                instruction.context.architecture == Architecture::arm && target
                    ? "ARM call target conflicts with source-backed execution-state metadata"
                    : "Call target remains unresolved"};
        else if (auto denied = permission(*value.call_target))
            value.call_issue = FunctionStop{address, *denied, "Call target has no permitted initialized code"};
        continuation(BlockEdgeKind::call_continuation);
        if (instruction.context.architecture == Architecture::arm && instruction.arm &&
            (instruction.arm->predicate == ArmPredicate::condition ||
             instruction.arm->predicate == ArmPredicate::unknown_it))
            continuation(BlockEdgeKind::conditional_false);
        break;
    case FlowKind::conditional_branch:
        if (instruction.context.architecture == Architecture::arm) {
            if (!arm_target_matches()) {
                value.stop = FunctionStop{address, FunctionStopReason::unsupported,
                                          "ARM branch target conflicts with source-backed execution-state metadata"};
                break;
            }
        }
        value.edges.push_back({target, target ? BlockEdgeKind::conditional_true : BlockEdgeKind::unresolved,
                               target_it()});
        if (!target)
            value.stop = FunctionStop{address, unresolved(), "Conditional target remains unresolved"};
        continuation(BlockEdgeKind::conditional_false);
        break;
    case FlowKind::jump:
    {
        const bool predicated_arm_transfer = instruction.context.architecture == Architecture::arm && instruction.arm &&
                                            (instruction.arm->predicate == ArmPredicate::condition ||
                                             instruction.arm->predicate == ArmPredicate::unknown_it);
        if (instruction.context.architecture == Architecture::arm) {
            if (!arm_target_matches()) {
                value.stop = FunctionStop{address, FunctionStopReason::unsupported,
                                          "ARM branch target conflicts with source-backed execution-state metadata"};
                if (predicated_arm_transfer)
                    continuation(BlockEdgeKind::conditional_false);
                break;
            }
        }
        value.edges.push_back({target, target ? BlockEdgeKind::jump : BlockEdgeKind::unresolved, target_it()});
        if (!target)
            value.stop = FunctionStop{address, unresolved(), "Jump target remains unresolved"};
        if (predicated_arm_transfer)
            continuation(BlockEdgeKind::conditional_false);
        break;
        }
    case FlowKind::switch_dispatch:
        if (instruction.context.architecture == Architecture::dex && instruction.dex_switch &&
            instruction.dex_switch->validated) {
            for (const auto &item : instruction.dex_switch->cases)
                value.edges.push_back({item.target, BlockEdgeKind::jump});
            continuation(BlockEdgeKind::fallthrough);
        } else if (instruction.context.architecture == Architecture::jvm && instruction.jvm_switch) {
            for (const auto &item : instruction.jvm_switch->cases)
                value.edges.push_back({item.target, BlockEdgeKind::jump});
            value.edges.push_back({instruction.jvm_switch->default_target, BlockEdgeKind::jump});
        } else {
            if (!value.stop)
                value.stop = FunctionStop{address, FunctionStopReason::unsupported,
                                          "Bytecode switch metadata is unavailable or unvalidated"};
            output->complete = false;
            value.edges.push_back({{}, BlockEdgeKind::unresolved});
        }
        break;
    }
    // JVM Code attributes carry an ordered exception table. Recovery uses it
    // as conservative exceptional CFG edges for bytecodes with observable
    // exception behavior. Keeping the handler order and table ranges here
    // lets the decompiler distinguish proven handlers from opaque effects.
    if (instruction.context.architecture == Architecture::jvm && metadata.jvm &&
        !instruction.encoded_bytes().empty()) {
        const auto raw = std::to_integer<std::uint8_t>(instruction.encoded_bytes().front());
        // Treat all constant-pool loads conservatively: reference and dynamic
        // constants can trigger resolution/bootstrap behavior, and unknown
        // constant kinds must not silently lose exceptional edges.
        const bool may_throw = (raw >= 0x12 && raw <= 0x14) ||
                               (raw >= 0x2e && raw <= 0x35) || (raw >= 0x4f && raw <= 0x56) ||
                               raw == 0x6c || raw == 0x6d || raw == 0x70 || raw == 0x71 ||
                               (raw >= 0xb2 && raw <= 0xc3) || raw == 0xc5 || raw == 0xbf;
        if (may_throw) {
            std::size_t examined = 0;
            for (const auto &method : metadata.jvm->methods) {
                if (!method.code || method.code->begin.space != address.space)
                    continue;
                for (const auto &handler : method.code->exception_table) {
                    if (++examined > 4096) {
                        output->complete = false;
                        value.stop = FunctionStop{address, FunctionStopReason::unsupported,
                            "JVM exception table exceeds the bounded CFG handler budget"};
                        break;
                    }
                    if (address.offset >= method.code->begin.offset + handler.start_pc &&
                        address.offset < method.code->begin.offset + handler.end_pc)
                        value.edges.push_back({Address{address.space, method.code->begin.offset + handler.handler_pc},
                                               BlockEdgeKind::exception});
                }
                break;
            }
        }
    }
    if (analysis_detail::has_delay_slot(instruction)) {
        const auto slot = take(analysis_detail::delay_slot_address(instruction));
        auto &after_slot = delayed_edges[slot];
        for (const auto &edge : value.edges)
            if (edge.kind != BlockEdgeKind::delay_slot &&
                !(analysis_detail::is_mips_branch_likely(instruction) &&
                  edge.kind == BlockEdgeKind::conditional_false))
                after_slot.push_back(edge);
        value.edges.erase(std::remove_if(value.edges.begin(), value.edges.end(), [&](const auto &edge) {
            return edge.kind != BlockEdgeKind::delay_slot &&
                   !(analysis_detail::is_mips_branch_likely(instruction) &&
                     edge.kind == BlockEdgeKind::conditional_false);
        }), value.edges.end());
    }
    return finish();
}
void Recovery::discover() {
    using Work = std::pair<Address, ThumbITState>;
    const auto initial_state = [&](Address at) {
        const auto context = take(image.context_at(at));
        return context.mode == ExecutionMode::thumb ? ThumbITState{true, 0} : ThumbITState{};
    };
    std::deque<Address> pending_functions;
    for (const auto &[entry, seeds] : all_seeds)
        pending_functions.push_back(entry);
    AddressSet done;
    AddressSet switch_scanned;
    size_t memberships = 0;
    while (!pending_functions.empty() && !discovery_exhausted) {
        canceled();
        const auto entry = pending_functions.front();
        pending_functions.pop_front();
        if (!done.insert(entry).second)
            continue;
        std::deque<Work> pending{{entry, thumb_states.contains(entry) ? thumb_states.at(entry) : initial_state(entry)}};
        if (auto definition = definitions.find(entry); definition != definitions.end())
            for (const auto &chunk : definition->second->chunks)
                pending.push_back({chunk.begin, initial_state(chunk.begin)});
        AddressSet visited;
        while (!pending.empty()) {
            canceled();
            const auto [address, incoming_it] = pending.front();
            pending.pop_front();
            if (!within_chunks(entry, address))
                continue;
            if (!visited.insert(address).second) {
                if (thumb_states.contains(address) && thumb_states.at(address) != incoming_it)
                    (void)node(address, incoming_it);
                continue;
            }
            if (memberships++ >= options.membership_budget) {
                discovery_exhausted = true;
                output->complete = false;
                break;
            }
            auto &current = node(address, incoming_it);
            if (!current.fact || !within_chunks(entry, address, current.fact->instruction.length))
                continue;
            const auto &dispatch = current.fact->instruction;
            if (dispatch.flow == FlowKind::jump && switch_scanned.insert(address).second) {
                FunctionRecord temporary_function;
                temporary_function.id = {1};
                temporary_function.entry = address;
                temporary_function.blocks = {{1}};
                auto temporary_block = std::make_shared<BasicBlock>();
                temporary_block->id = {1};
                temporary_block->begin = address;
                std::vector<std::shared_ptr<const InstructionFact>> dispatch_window{current.fact};
                auto expected = address;
                // Retain a directly preceding CMP/Jcc guard as well as the
                // three-instruction table-base/load/add sequence. Switch
                // recovery can then use a proven selector bound without
                // scanning later executable-looking table data.
                for (std::size_t predecessor_count = 0; predecessor_count < 5; ++predecessor_count) {
                    auto previous = nodes.lower_bound(expected);
                    if (previous == nodes.begin())
                        break;
                    --previous;
                    if (!previous->second.fact)
                        break;
                    const auto &prior = previous->second.fact->instruction;
                    auto end = analysis_detail::continuation_address(prior);
                    if (!end || end.value() != expected ||
                        (prior.flow != FlowKind::fallthrough && prior.flow != FlowKind::conditional_branch))
                        break;
                    dispatch_window.insert(dispatch_window.begin(), previous->second.fact);
                    expected = prior.address;
                }
                temporary_block->instructions = std::move(dispatch_window);
                FunctionSnapshot temporary_snapshot;
                temporary_snapshot.blocks.push_back(std::move(temporary_block));
                auto switches = analyze_switch_tables(image, relocations, temporary_function, temporary_snapshot,
                                                      stop);
                if (!switches)
                    throw Failure{switches.error()};
                for (const auto &site : switches.value().sites) {
                    auto unresolved = std::find_if(current.edges.begin(), current.edges.end(), [](const auto &edge) {
                        return edge.kind == BlockEdgeKind::unresolved && !edge.target;
                    });
                    if (unresolved != current.edges.end())
                        current.edges.erase(unresolved);
                    for (const auto &item : site.cases)
                        current.edges.push_back({item.target, BlockEdgeKind::jump});
                    if (site.complete)
                        current.stop.reset();
                }
            }
            if (current.call_target && !permission(*current.call_target) &&
                add_seed(all_seeds, {FunctionSeedKind::direct_call, *current.call_target, address, {}}))
                pending_functions.push_back(*current.call_target);
            for (const auto &edge : current.edges)
                if (edge.target)
                    pending.push_back({*edge.target, edge.target_it});
        }
    }
}
void Recovery::find_conflicts() {
    for (auto first = nodes.begin(); first != nodes.end(); ++first) {
        canceled();
        if (!first->second.fact)
            continue;
        const auto end = first->first.offset + first->second.fact->instruction.length;
        for (auto second = std::next(first);
             second != nodes.end() && second->first.space == first->first.space && second->first.offset < end;
             ++second) {
            if (!second->second.fact)
                continue;
            ambiguous.insert(first->first);
            ambiguous.insert(second->first);
            output->conflicts.push_back({FunctionConflictKind::instruction_overlap, first->first, second->first,
                                         "Decoded instruction streams overlap", first->second.fact,
                                         second->second.fact});
        }
    }
    // The current node cache models an address once. A MIPS delay-slot
    // instruction therefore cannot also be entered as an ordinary branch,
    // fallthrough, call-continuation, or function-root target: that would give
    // the same bytes path-dependent successor semantics. Stop ownership there.
    AddressMap<Address> slot_sources;
    AddressSet ordinary_targets;
    for (const auto &[at, node] : nodes) {
        canceled();
        for (const auto &edge : node.edges) {
            if (!edge.target)
                continue;
            if (edge.kind == BlockEdgeKind::delay_slot)
                slot_sources.try_emplace(*edge.target, at);
            else
                ordinary_targets.insert(*edge.target);
        }
    }
    for (const auto &[slot, source] : slot_sources) {
        if (!ordinary_targets.contains(slot) && !root_entries.contains(slot))
            continue;
        ambiguous.insert(slot);
        output->conflicts.push_back({FunctionConflictKind::decision_overlap, source, slot,
                                     "MIPS delay-slot address is also reached as an ordinary CFG target or function root",
                                     nodes.contains(source) ? nodes.at(source).fact : nullptr,
                                     nodes.contains(slot) ? nodes.at(slot).fact : nullptr});
    }
    // Empty conflict blocks depend on the entire attempted decode window,
    // rather than only consumed bytes. Memoized facts must retain that same
    // conservative dependency even though their bytes need no second read.
    for (auto at : ambiguous)
        if (reusable_instructions.contains(at)) {
            canceled();
            auto &window = nodes.at(at).window;
            window = {};
            for (size_t i = 0; i < 15; ++i) {
                auto cursor = advance(at, i);
                if (!cursor || permission(cursor.value()))
                    break;
                take(window.include(take(image.to_file_offset(cursor.value())), 1));
            }
        }
}
void Recovery::trusted_seeds() {
    valid_seeds = roots;
    std::deque<Address> pending_functions;
    for (const auto &[entry, seeds] : roots)
        pending_functions.push_back(entry);
    AddressSet done;
    size_t memberships = 0;
    while (!pending_functions.empty()) {
        canceled();
        auto entry = pending_functions.front();
        pending_functions.pop_front();
        if (!done.insert(entry).second)
            continue;
        std::deque<std::pair<Address, ThumbITState>> pending{{
            entry, thumb_states.contains(entry) ? thumb_states.at(entry) : ThumbITState{true, 0}}};
        if (auto definition = definitions.find(entry); definition != definitions.end())
            for (const auto &chunk : definition->second->chunks)
                pending.push_back({chunk.begin, thumb_states.contains(chunk.begin) ? thumb_states.at(chunk.begin)
                                                                                   : ThumbITState{true, 0}});
        AddressSet visited;
        while (!pending.empty()) {
            canceled();
            const auto [at, incoming_it] = pending.front();
            pending.pop_front();
            if (!within_chunks(entry, at))
                continue;
            if (!visited.insert(at).second) {
                if (thumb_states.contains(at) && thumb_states.at(at) != incoming_it)
                    (void)node(at, incoming_it);
                continue;
            }
            if (memberships++ >= options.membership_budget) {
                output->complete = false;
                return;
            }
            auto &current = node(at, incoming_it);
            if (ambiguous.contains(at) || !current.fact || !within_chunks(entry, at, current.fact->instruction.length))
                continue;
            if (current.call_target && !suppressed.contains(*current.call_target)) {
                if (auto denied = permission(*current.call_target))
                    output->candidates.push_back(
                        {*current.call_target, at, *denied, "Direct call cannot seed permitted initialized code"});
                else if (all_seeds.contains(*current.call_target) &&
                         add_seed(valid_seeds, {FunctionSeedKind::direct_call, *current.call_target, at, {}}))
                    pending_functions.push_back(*current.call_target);
            }
            for (const auto &edge : current.edges)
                if (edge.target)
                    pending.push_back({*edge.target, edge.target_it});
        }
    }
}
void Recovery::assign_owners() {
    functions.clear();
    owners.clear();
    function_nodes.clear();
    output->calls.clear();
    for (const auto &[entry, seeds] : valid_seeds) {
        auto function = std::make_shared<FunctionRecord>();
        function->id = {ids.make(FactKind::function, entry)};
        function->entry = entry;
        function->seeds = seeds;
        functions.emplace(entry, std::move(function));
    }
    for (auto &[entry, function] : functions) {
        std::deque<std::pair<Address, ThumbITState>> pending{{
            entry, thumb_states.contains(entry) ? thumb_states.at(entry) : ThumbITState{true, 0}}};
        if (auto definition = definitions.find(entry); definition != definitions.end())
            for (const auto &chunk : definition->second->chunks)
                pending.push_back({chunk.begin, thumb_states.contains(chunk.begin) ? thumb_states.at(chunk.begin)
                                                                                   : ThumbITState{true, 0}});
        AddressSet visited;
        const auto record = [&](FunctionStop issue) {
            if (!terminal_complete(issue.reason))
                function->complete = false;
            function->stops.push_back(std::move(issue));
        };
        while (!pending.empty()) {
            canceled();
            const auto [at, incoming_it] = pending.front();
            pending.pop_front();
            if (!visited.insert(at).second) {
                if (thumb_states.contains(at) && thumb_states.at(at) != incoming_it)
                    (void)node(at, incoming_it);
                continue;
            }
            if (owner_steps++ >= options.membership_budget) {
                record({at, FunctionStopReason::budget, "Function ownership budget reached"});
                break;
            }
            if (!within_chunks(entry, at)) {
                record({at, FunctionStopReason::chunk_boundary,
                        "Flow leaves the function's declared or metadata-proven chunks"});
                continue;
            }
            auto &current = node(at, incoming_it);
            if (current.fact && !within_chunks(entry, at, current.fact->instruction.length)) {
                record({at, FunctionStopReason::chunk_boundary,
                        "Instruction crosses the function's declared or metadata-proven chunk boundary"});
                continue;
            }
            owners[at].push_back(function->id);
            function_nodes[function->id].insert(at);
            if (current.stop)
                record(*current.stop);
            if (ambiguous.contains(at)) {
                record({at, FunctionStopReason::overlap, "Conflicting instruction streams stop trusted ownership"});
                continue;
            }
            if (current.call_issue)
                record(*current.call_issue);
            if (current.call) {
                std::optional<FunctionId> callee;
                if (current.call_target) {
                    auto target = functions.find(*current.call_target);
                    if (target != functions.end())
                        callee = target->second->id;
                }
                output->calls.push_back({function->id, at, current.call_target, callee, false});
            }
            for (const auto &edge : current.edges) {
                if (!edge.target)
                    continue;
                const bool call_continuation_entry = current.call && current.call_target == edge.target &&
                                                     !permission(*edge.target) && !suppressed.contains(*edge.target);
                if (*edge.target != entry && (functions.contains(*edge.target) || root_entries.contains(*edge.target) ||
                                              call_continuation_entry)) {
                    if (!functions.contains(*edge.target)) {
                        record(
                            {*edge.target, FunctionStopReason::budget, "Established entry omitted by function budget"});
                        continue;
                    }
                    if (edge.kind == BlockEdgeKind::jump) {
                        output->calls.push_back({function->id, at, edge.target, functions.at(*edge.target)->id, true});
                        record({at, FunctionStopReason::tail_candidate,
                                "Transfer reaches another established function entry"});
                    } else
                        record({*edge.target, FunctionStopReason::chunk_boundary,
                                "Continuation reaches another established function entry"});
                    continue;
                }
                const auto target_context = image.context_at(*edge.target);
                const auto source_node = nodes.find(at);
                if (!target_context || source_node == nodes.end() || !source_node->second.fact ||
                    target_context.value() != source_node->second.fact->instruction.context) {
                    record({*edge.target, FunctionStopReason::chunk_boundary,
                            "Flow crosses a declared execution-context boundary"});
                    continue;
                }
                    pending.push_back({*edge.target, edge.target_it});
            }
        }
        const auto owned = function_nodes.find(function->id);
        if (owned != function_nodes.end() && owned->second.size() == 1 && *owned->second.begin() == entry) {
            const auto decoded = nodes.find(entry);
            const bool is_jump = decoded != nodes.end() && decoded->second.fact &&
                                 decoded->second.fact->instruction.flow == FlowKind::jump;
            const bool transfers_to_function = std::any_of(output->calls.begin(), output->calls.end(),
                [&](const auto &call) {
                    return call.owner == function->id && call.source == entry && call.tail_candidate && call.callee;
                });
            function->thunk = is_jump && transfers_to_function;
        }
    }
}
void Recovery::prune_unowned_seeds() {
    // Discovery is deliberately conservative. Retain direct-call roots only when
    // their source survives the final manual-chunk and entry ownership rules.
    for (size_t pass = 0; pass < 32; ++pass) {
        canceled();
        bool changed = false;
        for (auto entry = valid_seeds.begin(); entry != valid_seeds.end();) {
            auto &seeds = entry->second;
            std::optional<Address> rejected_source;
            auto first = std::remove_if(seeds.begin(), seeds.end(), [&](const auto &seed) {
                const bool rejected =
                    seed.kind == FunctionSeedKind::direct_call &&
                    (!seed.source || !owners.contains(*seed.source) || ambiguous.contains(*seed.source));
                if (rejected) {
                    changed = true;
                    rejected_source = seed.source;
                }
                return rejected;
            });
            seeds.erase(first, seeds.end());
            if (seeds.empty()) {
                output->candidates.push_back({entry->first, rejected_source, FunctionStopReason::chunk_boundary,
                                              "Speculative call source is not in trusted owned code"});
                entry = valid_seeds.erase(entry);
            } else
                ++entry;
        }
        if (!changed)
            return;
        assign_owners();
    }
    // A pathological ownership chain stays partial rather than consuming an
    // unbounded fixed-point walk; concrete entry/export/user roots remain.
    output->complete = false;
    for (auto entry = valid_seeds.begin(); entry != valid_seeds.end();) {
        auto &seeds = entry->second;
        seeds.erase(std::remove_if(seeds.begin(), seeds.end(),
                                   [](const auto &seed) { return seed.kind == FunctionSeedKind::direct_call; }),
                    seeds.end());
        if (seeds.empty())
            entry = valid_seeds.erase(entry);
        else
            ++entry;
    }
    assign_owners();
}
std::shared_ptr<const FunctionSnapshot> Recovery::run() {
    canceled();
    require(analysis_detail::supports_automatic_flow(image),
            "Function recovery requires a supported processor mode");
    validate_decisions();
    seed_roots();
    discover();
    find_conflicts();
    trusted_seeds();
    assign_owners();
    prune_unowned_seeds();
    build_blocks(*this);
    finish_functions(*this);
    build_dependencies(*this);
    output->complete = output->complete && output->candidates.empty() && output->conflicts.empty() &&
                       output->omitted_functions == 0 && output->omitted_blocks == 0;
    for (const auto &function : output->functions)
        output->complete = output->complete && function->complete;
    canceled();
    return output;
}
} // namespace hexlab::function_detail
namespace hexlab {
Sha256Digest function_engine_fingerprint(const AnalysisOptions &options) {
    Sha256 hash;
    constexpr std::string_view version =
        "hexlab-functions-v50/nonx86-reference-producer-graph-v1/dataflow-reference-producer-graph-v3/dex-switch-flow-v1/jvm-switch-flow-v1/jvm-exception-flow-v1/pe-guard-cf-function-roots-v1/pe-chpe-execution-ranges-v1/pe-amd64-chained-function-chunks-v1/runtime-initializer-roots-v1/runtime-initializer-array-roots-v2/initializer-source-relocation-provenance-v1/string-scan-work-budget-v1/mips64-delay-slot-ownership-v1/explicit-root-budget-priority-v1/arm-profile-roots-and-predicated-thumb-pc-flow-v3/arm-a32-predicate-thumb-it-flow-v3/zydis-opaque-stop-v1/multiarc-flow-v1/switch-cfg-targets-v3/guard-multiblock-v1/unicode-strings-v1/x86-scalar-context-v5/elf-symbol-roots-v1/elf-symbol-extents-v1/operand-encoding-v1/elf-relocation-flow-v2/"
        "elf-reference-provenance-v1/elf-arithmetic-v2/macho-symbol-roots-v1/macho-relocation-flow-v1/"
        "macho-reference-provenance-v1/macho-dyld-data-provenance-v1/macho-dyld-flow-v1/macho-export-roots-v1/macho-code-policy-v1/elf-unwind-roots-v1/macho-eh-frame-roots-v1/pe-tls-callback-roots-v1/pe-arm64-pdata-provenance-v1/mips64-cop1-condition-predicates-v1/riscv-v-vector-comparisons-v1/x86-vex128-zero-upper-v1/powerpc-xform-logical-clz-signext-v1/x87-status-control-tag-effects-v1";
    (void)hash.update(std::as_bytes(std::span(version)));
    for (auto value : {options.min_string_characters, options.instruction_budget, options.string_budget,
                       options.string_scan_work_budget,
                       options.function_budget, options.block_budget, options.membership_budget})
        (void)hash.update(encode_u64(value));
    if (options.semantic_decoder_identity) {
        try {
            const auto identity = options.semantic_decoder_identity();
            (void)hash.update(encode_u64(identity.size()));
            (void)hash.update(identity);
        } catch (...) {
            constexpr std::string_view failed_identity = "semantic-decoder-identity-unavailable";
            (void)hash.update(std::as_bytes(std::span(failed_identity)));
        }
    } else {
        (void)hash.update(encode_u64(0));
    }
    return hash.digest();
}
Sha256Digest function_engine_fingerprint() { return function_engine_fingerprint(AnalysisOptions{}); }
namespace {
Result<std::shared_ptr<const FunctionSnapshot>> recover(const Image &image, const ImageMetadata &metadata,
                                                        const AnalysisDecisions &decisions,
                                                        const AnalysisOptions &options, std::optional<AnalysisKey> key,
                                                        std::stop_token stop) {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Function recovery canceled"};
    if (!analysis_detail::supports_automatic_flow(image)) {
        const auto context = image.decode_context();
        if (context.architecture == Architecture::arm && context.mode == ExecutionMode::thumb)
            return Error{ErrorCode::unsupported,
                         "Thumb function recovery requires edge-specific IT-state propagation"};
        if (context.architecture == Architecture::arm && context.mode == ExecutionMode::a32)
            return Error{ErrorCode::unsupported,
                         "A32 function recovery requires predicate-aware PC-write and return modeling"};
        if (context.architecture == Architecture::mips32)
            return Error{ErrorCode::unsupported,
                         "MIPS32 function recovery requires delay-slot-aware block ownership"};
        return Error{ErrorCode::unsupported, "Function recovery requires a supported processor mode"};
    }
    if (key &&
        (key->input.size != image.storage()->size() || key->engine_fingerprint != function_engine_fingerprint(options)))
        return Error{ErrorCode::invalid_argument, "Analysis key does not match input extent or engine configuration"};
    try {
        function_detail::Recovery recovery(image, metadata, decisions, options, stop);
        recovery.output->key = std::move(key);
        return recovery.run();
    } catch (const function_detail::Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate recovered function facts"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Function facts exceed allocation limits"};
    }
}
} // namespace
Result<std::shared_ptr<const FunctionSnapshot>> recover_functions(const Image &image, const ImageMetadata &metadata,
                                                                  const AnalysisDecisions &decisions,
                                                                  const AnalysisOptions &options,
                                                                  std::stop_token stop) {
    return recover(image, metadata, decisions, options, {}, stop);
}
Result<std::shared_ptr<const FunctionSnapshot>> recover_functions(const Image &image, const ImageMetadata &metadata,
                                                                  const AnalysisDecisions &decisions,
                                                                  const AnalysisOptions &options,
                                                                  const AnalysisKey &key, std::stop_token stop) {
    return recover(image, metadata, decisions, options, key, stop);
}
} // namespace hexlab
