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
#include <set>
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
    case FunctionSeedKind::dex_method: return "DEX defined method";
    case FunctionSeedKind::safe_seh: return "PE SafeSEH handler";
    case FunctionSeedKind::pogo: return "PE POGO function profile";
    case FunctionSeedKind::wasm_export: return "WebAssembly function export";
    case FunctionSeedKind::wasm_start: return "WebAssembly start function";
    case FunctionSeedKind::wasm_element: return "WebAssembly element function reference";
    case FunctionSeedKind::wasm_defined: return "WebAssembly defined function body";
    case FunctionSeedKind::dwarf_subprogram: return "DWARF subprogram";
    case FunctionSeedKind::m6502_nmi_vector: return "6502 NMI vector";
    case FunctionSeedKind::m6502_reset_vector: return "6502 reset vector";
    case FunctionSeedKind::m6502_irq_vector: return "6502 IRQ/BRK vector";
    case FunctionSeedKind::dwarf_entry_point: return "DWARF alternate entry point";
    case FunctionSeedKind::jvm_method: return "JVM method with Code attribute";
    }
    return "unknown function evidence";
}
std::string seed_provenance_text(const FunctionSeed &seed) {
    std::string text = seed_kind_name(seed.kind);
    if (seed.unwind_evidence)
        text += " (section " + std::to_string(seed.unwind_evidence->section) + ", record @ file offset " +
                std::to_string(seed.unwind_evidence->file_offset) + ")";
    if (seed.pogo_evidence)
        text += " (profile " + std::to_string(seed.pogo_evidence->profile_index) + ", row " +
                std::to_string(seed.pogo_evidence->entry_index) + " @ file offset " +
                std::to_string(seed.pogo_evidence->file_offset) + ")";
    if (seed.wasm_export_evidence)
        text += " (function " + std::to_string(seed.wasm_export_evidence->function_index) +
                ", export " + std::to_string(seed.wasm_export_evidence->export_index) +
                " @ file offset " + std::to_string(seed.wasm_export_evidence->entry_file_offset) + ")";
    if (seed.wasm_start_evidence)
        text += " (function " + std::to_string(seed.wasm_start_evidence->function_index) +
                ", type " + std::to_string(seed.wasm_start_evidence->type_index) +
                " @ file offset " + std::to_string(seed.wasm_start_evidence->entry_file_offset) + ")";
    if (seed.wasm_element_evidence)
        text += " (function " + std::to_string(seed.wasm_element_evidence->function_index) +
                ", element " + std::to_string(seed.wasm_element_evidence->segment_index) + ":" +
                std::to_string(seed.wasm_element_evidence->element_index) + " @ file offset " +
                std::to_string(seed.wasm_element_evidence->entry_file_offset) + ")";
    if (seed.wasm_defined_evidence)
        text += " (function " + std::to_string(seed.wasm_defined_evidence->function_index) +
                ", type " + std::to_string(seed.wasm_defined_evidence->type_index) +
                ", body @ file offset " + std::to_string(seed.wasm_defined_evidence->body_file_offset) + ")";
    if (seed.dwarf_evidence)
        text += " (unit @ " + std::to_string(seed.dwarf_evidence->unit_offset) +
                ", DIE @ " + std::to_string(seed.dwarf_evidence->die_offset) +
                ", size " + std::to_string(seed.dwarf_evidence->record_size) + ")";
    if (seed.jvm_method_evidence)
        text += " (method " + std::to_string(seed.jvm_method_evidence->method_index) +
                ", Code @ file offset " + std::to_string(seed.jvm_method_evidence->code_file_offset) + ")";
    if (seed.initializer_evidence) {
        const auto &evidence = *seed.initializer_evidence;
        const char *source_name = "initializer";
        switch (evidence.source) {
        case FunctionInitializerSource::elf_init: source_name = "ELF DT_INIT"; break;
        case FunctionInitializerSource::elf_fini: source_name = "ELF DT_FINI"; break;
        case FunctionInitializerSource::elf_preinit_array: source_name = "ELF DT_PREINIT_ARRAY"; break;
        case FunctionInitializerSource::elf_init_array: source_name = "ELF DT_INIT_ARRAY"; break;
        case FunctionInitializerSource::elf_fini_array: source_name = "ELF DT_FINI_ARRAY"; break;
        case FunctionInitializerSource::elf_init_array_section: source_name = "ELF SHT_INIT_ARRAY"; break;
        case FunctionInitializerSource::elf_fini_array_section: source_name = "ELF SHT_FINI_ARRAY"; break;
        case FunctionInitializerSource::elf_ctors_section: source_name = "ELF .ctors"; break;
        case FunctionInitializerSource::elf_dtors_section: source_name = "ELF .dtors"; break;
        case FunctionInitializerSource::macho_mod_init_func: source_name = "Mach-O __mod_init_func"; break;
        case FunctionInitializerSource::macho_routines: source_name = "Mach-O LC_ROUTINES"; break;
        case FunctionInitializerSource::macho_mod_term_func: source_name = "Mach-O __mod_term_func"; break;
        }
        text += " (" + std::string(source_name) + " slot";
        if (evidence.section)
            text += " in section " + std::to_string(*evidence.section);
        if (evidence.index)
            text += " index " + std::to_string(*evidence.index);
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
constexpr std::uint16_t all_nzcv = 0xffff;
bool arm_condition_holds(std::uint8_t condition, std::uint8_t nzcv) {
    const bool n = (nzcv & 8) != 0, z = (nzcv & 4) != 0, c = (nzcv & 2) != 0, v = (nzcv & 1) != 0;
    switch (condition) {
    case 0: return z;
    case 1: return !z;
    case 2: return c;
    case 3: return !c;
    case 4: return n;
    case 5: return !n;
    case 6: return v;
    case 7: return !v;
    case 8: return c && !z;
    case 9: return !c || z;
    case 10: return n == v;
    case 11: return n != v;
    case 12: return !z && n == v;
    case 13: return z || n != v;
    default: return true;
    }
}
std::uint16_t arm_condition_mask(std::uint8_t condition) {
    if (condition >= 14) return all_nzcv;
    std::uint16_t result = 0;
    for (std::uint8_t nzcv = 0; nzcv < 16; ++nzcv)
        if (arm_condition_holds(condition, nzcv)) result |= std::uint16_t(1u << nzcv);
    return result;
}
std::uint16_t predicate_guard(const Instruction &instruction) {
    if (instruction.context.architecture == Architecture::arm64 && instruction.opcode == Opcode::a64_b_cond)
        return arm_condition_mask(instruction.condition);
    if (!instruction.arm || instruction.arm->predicate != ArmPredicate::condition) return all_nzcv;
    return arm_condition_mask(instruction.condition);
}
std::uint16_t skipped_predicate_guard(const Instruction &instruction) {
    if (!instruction.arm || instruction.arm->predicate == ArmPredicate::always) return 0;
    if (instruction.arm->predicate == ArmPredicate::unknown_it) return all_nzcv;
    return static_cast<std::uint16_t>(all_nzcv & ~arm_condition_mask(instruction.condition));
}
std::optional<Address> dex_direct_call_target(const Instruction &instruction, const Image &image,
                                               const ImageMetadata &metadata) {
    if (instruction.context.architecture != Architecture::dex || instruction.flow != FlowKind::call ||
        !metadata.dex) return {};
    const auto bytes = instruction.encoded_bytes();
    if (bytes.size() < 4) return {};
    const auto opcode = std::to_integer<std::uint8_t>(bytes[0]);
    // Virtual/interface dispatch depends on the receiver, and invoke-super
    // requires superclass lookup. Only direct/static method IDs are exact.
    if (opcode != 0x70 && opcode != 0x71 && opcode != 0x76 && opcode != 0x77) return {};
    const auto method_index = static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[2])) |
                              (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[3])) << 8);
    const auto &code = metadata.dex->code;
    const auto method = std::lower_bound(code.begin(), code.end(), method_index,
        [](const DexMethodCode &candidate, std::uint32_t index) { return candidate.method_index < index; });
    if (method == code.end() || method->method_index != method_index || method_index == UINT32_MAX) return {};
    const Address target{AddressSpaceId{method_index + 1}, 0};
    const auto *segment = image.segment_at(target);
    const auto context = image.context_at(target);
    if (!segment || !segment->executable || !context || context.value().architecture != Architecture::dex ||
        context.value().mode != ExecutionMode::dex) return {};
    return target;
}
std::optional<Address> wasm_direct_call_target(const Instruction &instruction, const Image &image,
                                                const ImageMetadata &metadata) {
    if (instruction.context.architecture != Architecture::wasm ||
        instruction.context.mode != ExecutionMode::wasm32 || instruction.flow != FlowKind::call ||
        instruction.mnemonic_override != "call" || instruction.operands.size() != 1 || !metadata.wasm)
        return {};
    const auto *index = std::get_if<ImmediateOperand>(&instruction.operands.front());
    const auto &wasm = *metadata.wasm;
    const auto total_functions = static_cast<std::uint64_t>(wasm.imported_functions) + wasm.defined_functions;
    if (!index || index->is_signed || index->effective_width != 32 || index->value < wasm.imported_functions ||
        index->value >= total_functions || index->value >= wasm.function_type_indices.size())
        return {}; // Imported calls have no local machine-code address.
    const auto type_index = wasm.function_type_indices[static_cast<std::size_t>(index->value)];
    if (type_index >= wasm.function_types.size() || index->value > UINT32_MAX)
        return {};
    const Address target{AddressSpaceId{static_cast<std::uint32_t>(index->value)}, 0};
    const auto *segment = image.segment_at(target);
    const auto context = image.context_at(target);
    const auto storage_size = image.storage()->size();
    if (!segment || segment->begin != target || !segment->executable || !segment->size ||
        segment->file_begin.value > storage_size || segment->file_size > storage_size - segment->file_begin.value ||
        segment->file_size != segment->size || image.code_window(target, segment->size) != segment->size ||
        !context || context.value().architecture != Architecture::wasm ||
        context.value().mode != ExecutionMode::wasm32)
        return {};
    return target;
}
std::optional<ExternalIdentity> wasm_import_call_target(const Instruction &instruction,
                                                        const ImageMetadata &metadata) {
    if (instruction.context.architecture != Architecture::wasm ||
        instruction.context.mode != ExecutionMode::wasm32 || instruction.flow != FlowKind::call ||
        instruction.mnemonic_override != "call" || instruction.operands.size() != 1 || !metadata.wasm)
        return {};
    const auto *index = std::get_if<ImmediateOperand>(&instruction.operands.front());
    const auto &wasm = *metadata.wasm;
    if (!index || index->is_signed || index->effective_width != 32 || index->value >= wasm.imported_functions ||
        index->value >= wasm.function_type_indices.size())
        return {};
    const auto type_index = wasm.function_type_indices[static_cast<std::size_t>(index->value)];
    if (type_index >= wasm.function_types.size())
        return {};
    const auto imported = std::find_if(wasm.imports.begin(), wasm.imports.end(), [&](const WasmImport &entry) {
        return entry.kind == WasmExternalKind::function && entry.index == index->value &&
               entry.function_type_index == type_index;
    });
    if (imported == wasm.imports.end())
        return {};
    ExternalIdentity identity;
    identity.library = imported->module;
    identity.name = imported->name;
    identity.wasm_function_index = static_cast<std::uint32_t>(index->value);
    identity.host_binding = imported->host_binding;
    return identity;
}
std::optional<Address> local_x64_indirect_call_target(const Image &image, const RelocationResolver &relocations,
                                                       const Instruction &instruction, std::stop_token stop) {
    if (instruction.context.architecture != Architecture::x86_64 ||
        instruction.context.mode != ExecutionMode::x86_64 || instruction.opcode != Opcode::call ||
        instruction.flow != FlowKind::call || instruction.operands.size() != 1 ||
        instruction.access != std::vector<OperandAccess>{OperandAccess::read})
        return {};
    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands.front());
    if (!memory || memory->data_width != 64 || memory->address_width != 64 || memory->segment ||
        memory->base || memory->index || memory->scale != 1 || !memory->ip_relative ||
        !memory->resolved_address || !memory->displacement_encoding ||
        memory->displacement_encoding->size != 4 ||
        memory->displacement_encoding->offset > instruction.length ||
        memory->displacement_encoding->size > instruction.length - memory->displacement_encoding->offset)
        return {};
    const auto next = advance(instruction.address, instruction.length);
    if (!next)
        return {};
    auto computed_slot = next.value().offset;
    if (memory->displacement < 0) {
        const auto magnitude = static_cast<std::uint64_t>(-(memory->displacement + 1)) + 1;
        if (magnitude > computed_slot)
            return {};
        computed_slot -= magnitude;
    } else {
        const auto magnitude = static_cast<std::uint64_t>(memory->displacement);
        if (magnitude > UINT64_MAX - computed_slot)
            return {};
        computed_slot += magnitude;
    }
    if (memory->resolved_address->space != next.value().space ||
        memory->resolved_address->offset != computed_slot)
        return {};
    if (take(relocations.operand(instruction, 0, stop)).relocated())
        return {};
    const auto slot = *memory->resolved_address;
    if (slot.space != instruction.address.space)
        return {};
    const auto *space = image.space(slot.space);
    const auto *slot_segment = image.segment_at(slot);
    if (!space || space->width_bits != 64 || !slot_segment || !slot_segment->readable || slot_segment->writable ||
        slot.offset < slot_segment->begin.offset)
        return {};
    const auto relative = slot.offset - slot_segment->begin.offset;
    if (relative > slot_segment->file_size || 8 > slot_segment->file_size - relative ||
        image.plaintext_window(slot, 8) != 8)
        return {};
    (void)take(image.to_file_offset(slot));
    if (take(relocations.data_at(image, slot, 8, stop)).relocated())
        return {};
    const auto bytes = take(image.read(slot, 8));
    if (bytes.size() != 8)
        return {};
    ByteReader reader(bytes);
    const auto raw_target = reader.read_u64(space->order);
    if (!raw_target)
        return {};
    const Address target{slot.space, raw_target.value()};
    const auto *target_segment = image.segment_at(target);
    const auto target_context = image.context_at(target);
    if (!target_segment || !target_segment->executable || target.offset < target_segment->begin.offset ||
        target.offset - target_segment->begin.offset >= target_segment->file_size ||
        image.plaintext_window(target, 1) != 1 || !target_context || target_context.value() != instruction.context)
        return {};
    return target;
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
        const ElfArmEhabiFunction *ehabi_function_entry = nullptr;
        if (seed.kind == FunctionSeedKind::unwind && seed.unwind_evidence && metadata.elf) {
            const auto found = std::find_if(metadata.elf->arm_ehabi_functions.begin(),
                metadata.elf->arm_ehabi_functions.end(), [&](const auto &row) {
                    return row.begin == seed.entry && row.section == seed.unwind_evidence->section &&
                           row.file_offset == seed.unwind_evidence->file_offset;
                });
            if (found != metadata.elf->arm_ehabi_functions.end())
                ehabi_function_entry = &*found;
        }
        const bool has_ehabi_entry = ehabi_function_entry != nullptr;
        if (ehabi_function_entry) {
            const auto expected_mode = (ehabi_function_entry->raw_start & 1u) ? ExecutionMode::thumb : ExecutionMode::a32;
            if (context.architecture != Architecture::arm || context.mode != expected_mode) {
                if (report_invalid)
                    output->candidates.push_back({seed.entry, seed.source, FunctionStopReason::unsupported,
                                                  "EHABI entry state conflicts with mapped ARM code context"});
                return;
            }
        }
        if (context.architecture == Architecture::arm && context.mode == ExecutionMode::thumb) {
            const auto &profile = image.layout().arm_profile;
            const bool clear = profile && std::any_of(profile->roots.begin(), profile->roots.end(), [&](const auto &r) {
                return r.at == seed.entry && r.mode == ExecutionMode::thumb && r.known_thumb_it_clear;
            });
            if (!clear && !has_ehabi_entry) {
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
    // A flat NMOS 6502 address space stores its NMI, reset, and IRQ/BRK
    // vectors at fixed little-endian CPU addresses. Treat them as independent
    // roots only when the vector bytes and their targets are mapped in the
    // same 6502 execution context; this does not model bank-switching carts.
    const std::array<std::pair<std::uint16_t, FunctionSeedKind>, 3> m6502_vectors{{
        {0xfffa, FunctionSeedKind::m6502_nmi_vector},
        {0xfffc, FunctionSeedKind::m6502_reset_vector},
        {0xfffe, FunctionSeedKind::m6502_irq_vector},
    }};
    for (const auto &[offset, kind] : m6502_vectors) {
        canceled();
        const Address slot{image.layout().space.id, offset};
        const auto vector_context = image.context_at(slot);
        if (!vector_context || vector_context.value().architecture != Architecture::mos6502 ||
            vector_context.value().mode != ExecutionMode::m6502)
            continue;
        const auto bytes = image.read(slot, 2);
        if (!bytes) continue;
        ByteReader reader(bytes.value());
        const auto vector_target = reader.read_u16(ByteOrder::little);
        if (!vector_target || vector_target.value() == 0) continue;
        const Address entry{slot.space, vector_target.value()};
        const auto target_context = image.context_at(entry);
        if (!target_context || target_context.value().architecture != Architecture::mos6502 ||
            target_context.value().mode != ExecutionMode::m6502)
            continue;
        root({kind, entry, slot, {}}, false);
    }
    // ARM code-profile roots carry source-backed execution-state declarations
    // that may not also appear in the image's generic entry list. Preserve
    // them as independent function-seed evidence for mixed A32/Thumb images.
    if (image.layout().arm_profile)
        for (const auto &profile_root : image.layout().arm_profile->roots) {
            canceled();
            root({FunctionSeedKind::arm_context_root, profile_root.at, {}, {}}, true);
        }
    if (metadata.dex)
        for (const auto &method : metadata.dex->code) {
            canceled();
            if (method.method_index == UINT32_MAX) continue;
            root({FunctionSeedKind::dex_method,
                  Address{AddressSpaceId{method.method_index + 1}, 0}, {}, {}}, false);
        }
    if (metadata.jvm) {
        for (std::size_t method_index = 0; method_index < metadata.jvm->methods.size(); ++method_index) {
            canceled();
            const auto &method = metadata.jvm->methods[method_index];
            if (!method.code) continue; // Abstract and native methods have no local bytecode body.
            const auto &code = *method.code;
            const auto *segment = image.segment_at(code.begin);
            const auto context = image.context_at(code.begin);
            const auto storage_size = image.storage()->size();
            if (method_index > UINT32_MAX || code.code_size == 0 || !segment || !segment->executable ||
                !context || context.value().architecture != Architecture::jvm ||
                image.code_window(code.begin, code.code_size) != code.code_size ||
                code.file_begin.value > storage_size || code.code_size > storage_size - code.file_begin.value) {
                output->complete = false;
                output->candidates.push_back({code.begin, {}, FunctionStopReason::unsupported,
                    "JVM method Code attribute has no complete executable bytecode mapping"});
                continue;
            }
            FunctionSeed seed{FunctionSeedKind::jvm_method, code.begin, {}, {}};
            seed.jvm_method_evidence = FunctionSeedJvmMethodEvidence{
                static_cast<std::uint32_t>(method_index), code.file_begin.value};
            root(std::move(seed), false);
        }
    }
    if (metadata.wasm) {
        const auto &wasm = *metadata.wasm;
        const auto total_functions = static_cast<std::uint64_t>(wasm.imported_functions) + wasm.defined_functions;
        // A validated local body is independently discoverable even when no
        // export, start entry, element, or direct call refers to it.
        for (std::uint64_t function_index = wasm.imported_functions;
             function_index < total_functions; ++function_index) {
            canceled();
            if (function_index > UINT32_MAX) {
                output->complete = false;
                continue;
            }
            const Address entry{AddressSpaceId{static_cast<std::uint32_t>(function_index)}, 0};
            const auto reject = [&] {
                output->complete = false;
                output->candidates.push_back({entry, {}, FunctionStopReason::unsupported,
                    "WebAssembly defined function lacks a validated local code body and type record"});
            };
            if (function_index >= wasm.function_type_indices.size()) {
                reject();
                continue;
            }
            const auto type_index = static_cast<std::uint64_t>(wasm.function_type_indices[function_index]);
            if (type_index > UINT32_MAX) {
                reject();
                continue;
            }
            const auto *segment = image.segment_at(entry);
            const auto context = image.context_at(entry);
            const auto storage_size = image.storage()->size();
            const bool body_source_valid = segment && segment->file_begin.value <= storage_size &&
                segment->file_size <= storage_size - segment->file_begin.value;
            if (type_index >= wasm.function_types.size() || !segment || segment->begin != entry ||
                !segment->executable || !body_source_valid || segment->file_size != segment->size ||
                !segment->size || image.code_window(entry, segment->size) != segment->size || !context ||
                context.value().architecture != Architecture::wasm ||
                context.value().mode != ExecutionMode::wasm32) {
                reject();
                continue;
            }
            FunctionSeed seed{FunctionSeedKind::wasm_defined, entry, {}, {}};
            seed.wasm_defined_evidence = FunctionSeedWasmDefinedEvidence{
                static_cast<std::uint32_t>(function_index), static_cast<std::uint32_t>(type_index),
                segment->file_begin.value};
            root(std::move(seed), false);
        }
        for (std::size_t export_index = 0; export_index < wasm.exports.size(); ++export_index) {
            canceled();
            const auto &exported = wasm.exports[export_index];
            if (exported.kind != WasmExternalKind::function || exported.index < wasm.imported_functions)
                continue; // Imported functions are host-provided and have no local code root.
            const Address entry{AddressSpaceId{exported.index}, 0};
            const auto reject = [&] {
                output->complete = false;
                output->candidates.push_back({entry, {}, FunctionStopReason::unsupported,
                    "WebAssembly function export lacks a validated local code body and type record"});
            };
            const bool index_valid = exported.index < total_functions &&
                exported.index < wasm.function_type_indices.size() && exported.function_type_index &&
                *exported.function_type_index < wasm.function_types.size() &&
                wasm.function_type_indices[exported.index] == *exported.function_type_index &&
                export_index <= UINT32_MAX && exported.entry_index == export_index;
            const auto *segment = image.segment_at(entry);
            const auto context = image.context_at(entry);
            const auto storage_size = image.storage()->size();
            const bool source_valid = exported.section_file_offset.value < storage_size &&
                exported.entry_file_offset.value >= exported.section_file_offset.value &&
                exported.entry_file_offset.value < storage_size;
            const bool body_source_valid = segment && segment->file_begin.value <= storage_size &&
                segment->file_size <= storage_size - segment->file_begin.value;
            if (!index_valid || !source_valid || !segment || segment->begin != entry || !segment->executable ||
                !body_source_valid || segment->file_size != segment->size || !segment->size ||
                image.code_window(entry, segment->size) != segment->size || !context ||
                context.value().architecture != Architecture::wasm || context.value().mode != ExecutionMode::wasm32) {
                reject();
                continue;
            }
            FunctionSeed seed{FunctionSeedKind::wasm_export, entry, {}, {}};
            seed.wasm_export_evidence = FunctionSeedWasmExportEvidence{
                exported.index, static_cast<std::uint32_t>(export_index), *exported.function_type_index,
                exported.section_file_offset.value, exported.entry_file_offset.value};
            root(std::move(seed), false);
        }
        // Element segments are explicit references to functions that can be
        // reached through table dispatch. They remain possible callees even
        // when the table is imported, passive, or later mutated, so root each
        // validated locally defined function referenced by any segment.
        std::set<std::uint32_t> seeded_element_functions;
        for (std::size_t segment_index = 0; segment_index < wasm.element_segments.size(); ++segment_index) {
            canceled();
            const auto &element_segment = wasm.element_segments[segment_index];
            for (std::size_t element_index = 0;
                 element_index < element_segment.function_indices.size(); ++element_index) {
                canceled();
                const auto function_index = element_segment.function_indices[element_index];
                if (!function_index || *function_index < wasm.imported_functions ||
                    *function_index >= total_functions || seeded_element_functions.contains(*function_index))
                    continue;
                const Address entry{AddressSpaceId{*function_index}, 0};
                const auto type_index = *function_index < wasm.function_type_indices.size()
                    ? wasm.function_type_indices[*function_index] : UINT32_MAX;
                const auto *segment = image.segment_at(entry);
                const auto context = image.context_at(entry);
                const auto storage_size = image.storage()->size();
                const bool source_valid = element_segment.section_file_offset.value < storage_size &&
                    element_segment.entry_file_offset.value >= element_segment.section_file_offset.value &&
                    element_segment.entry_file_offset.value < storage_size;
                const bool body_source_valid = segment && segment->file_begin.value <= storage_size &&
                    segment->file_size <= storage_size - segment->file_begin.value;
                if (type_index >= wasm.function_types.size() || !source_valid || !segment ||
                    segment->begin != entry || !segment->executable || !body_source_valid ||
                    segment->file_size != segment->size || !segment->size ||
                    image.code_window(entry, segment->size) != segment->size || !context ||
                    context.value().architecture != Architecture::wasm ||
                    context.value().mode != ExecutionMode::wasm32) {
                    output->complete = false;
                    output->candidates.push_back({entry, {}, FunctionStopReason::unsupported,
                        "WebAssembly element function reference lacks a validated local code body and type record"});
                    continue;
                }
                if (segment_index > UINT32_MAX || element_index > UINT32_MAX) {
                    output->complete = false;
                    output->candidates.push_back({entry, {}, FunctionStopReason::budget,
                        "WebAssembly element provenance index exceeds the function-seed format"});
                    continue;
                }
                seeded_element_functions.insert(*function_index);
                FunctionSeed seed{FunctionSeedKind::wasm_element, entry, {}, {}};
                seed.wasm_element_evidence = FunctionSeedWasmElementEvidence{
                    *function_index, type_index, static_cast<std::uint32_t>(segment_index),
                    static_cast<std::uint32_t>(element_index), element_segment.section_file_offset.value,
                    element_segment.entry_file_offset.value, segment->file_begin.value};
                root(std::move(seed), false);
            }
        }
        // A WebAssembly start function executes automatically when the module
        // is instantiated; it need not also be exported. Imported starts have
        // no local body and are intentionally not treated as code roots.
        if (wasm.start_function) {
            canceled();
            const auto &start = *wasm.start_function;
            const auto index = start.function_index;
            const Address entry{AddressSpaceId{index}, 0};
            if (index >= wasm.imported_functions && index < total_functions &&
                index < wasm.function_type_indices.size() &&
                start.function_type_index < wasm.function_types.size() &&
                wasm.function_type_indices[index] == start.function_type_index) {
                const auto *segment = image.segment_at(entry);
                const auto context = image.context_at(entry);
                const auto storage_size = image.storage()->size();
                const bool source_valid = start.section_file_offset.value < storage_size &&
                    start.entry_file_offset.value >= start.section_file_offset.value &&
                    start.entry_file_offset.value < storage_size;
                const bool body_source_valid = segment && segment->file_begin.value <= storage_size &&
                    segment->file_size <= storage_size - segment->file_begin.value;
                if (segment && segment->begin == entry && segment->executable && body_source_valid &&
                    segment->file_size == segment->size && segment->size &&
                    image.code_window(entry, segment->size) == segment->size && context && source_valid &&
                    context.value().architecture == Architecture::wasm &&
                    context.value().mode == ExecutionMode::wasm32) {
                    FunctionSeed seed{FunctionSeedKind::wasm_start, entry, {}, {}};
                    seed.wasm_start_evidence = FunctionSeedWasmStartEvidence{
                        index, start.function_type_index, start.section_file_offset.value,
                        start.entry_file_offset.value};
                    root(std::move(seed), false);
                } else {
                    output->complete = false;
                    output->candidates.push_back({entry, {}, FunctionStopReason::unsupported,
                        "WebAssembly start function lacks a validated local code body and type record"});
                }
            } else if (index >= wasm.imported_functions) {
                output->complete = false;
                output->candidates.push_back({entry, {}, FunctionStopReason::unsupported,
                    "WebAssembly start function index or type does not resolve to a defined local function"});
            }
        }
    }
    for (const auto &symbol : metadata.exports) {
        canceled();
        if (symbol.address)
            root({FunctionSeedKind::export_symbol, *symbol.address, {}, {}}, false);
    }
    AddressMap<std::uint64_t> elf_symbol_sizes;
    AddressSet conflicting_elf_symbol_sizes;
    std::size_t ppc64_descriptor_symbols = 0;
    if (metadata.elf)
        for (const auto &symbol : metadata.elf->symbols) {
            canceled();
            // STT_GNU_IFUNC symbols name resolver code, not the implementation
            // address returned by the resolver. The resolver is executable
            // entry code in its own right and may be the only surviving root
            // evidence in stripped binaries.
            if ((symbol.type == 2 || symbol.type == 10) && symbol.state == ElfSymbolState::defined &&
                symbol.address) {
                // In the PPC64 ELFv1 ABI, STT_FUNC values point into the
                // non-executable .opd table. The first word of each 24-byte
                // descriptor is the code entry; root that mode-validated
                // target instead of treating the descriptor as instructions.
                const auto abi_version = metadata.elf->header.flags & 0x3u;
                if (metadata.elf->header.machine == 21 && metadata.elf->header.is_64 &&
                    metadata.elf->header.object_type != 1 && metadata.elf->header.object_type != 4 &&
                    abi_version != 2 && abi_version != 3 && symbol.type == 2 &&
                    symbol.section_index < metadata.elf->sections.size()) {
                    const auto &section = metadata.elf->sections[symbol.section_index];
                    if (section.name == ".opd") {
                        constexpr std::size_t descriptor_size = 24;
                        constexpr std::size_t max_descriptor_symbols = 65536;
                        if (++ppc64_descriptor_symbols > max_descriptor_symbols) {
                            output->complete = false;
                            break;
                        }
                        if (section.type != 1 || !(section.flags & 0x2) ||
                            symbol.address->offset < section.address || section.size < descriptor_size ||
                            symbol.address->offset - section.address > section.size - descriptor_size ||
                            (symbol.address->offset - section.address) % descriptor_size != 0) {
                            output->complete = false;
                            continue;
                        }
                        auto bytes = image.read(*symbol.address, sizeof(std::uint64_t));
                        if (!bytes || bytes.value().size() != sizeof(std::uint64_t)) {
                            output->complete = false;
                            continue;
                        }
                        ByteReader descriptor(bytes.value());
                        auto target = descriptor.read_u64(metadata.elf->header.order);
                        if (!target || !target.value()) {
                            output->complete = false;
                            continue;
                        }
                        const Address code_entry{symbol.address->space, target.value()};
                        root({FunctionSeedKind::symbol, code_entry, *symbol.address, {}}, false);
                        continue;
                    }
                }
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
    // Static ET_EXEC images can retain initializer arrays as allocated ELF
    // sections without carrying the corresponding dynamic tags. Treat these
    // as section-derived evidence only when that array's dynamic tag is absent;
    // this keeps section fallback distinct from dynamic-table interpretation.
    if (metadata.elf && metadata.elf->header.object_type == 2) {
        const auto has_dynamic_tag = [&](std::int64_t tag) {
            for (const auto &table : metadata.elf->dynamic_tables)
                for (const auto &entry : table.entries)
                    if (entry.tag == tag) return true;
            return false;
        };
        const auto width = metadata.elf->header.is_64 ? std::uint64_t{8} : std::uint64_t{4};
        for (const auto &section : metadata.elf->sections) {
            canceled();
            const bool init_array = section.type == 14 && !has_dynamic_tag(25);
            const bool fini_array = section.type == 15 && !has_dynamic_tag(26);
            if ((!init_array && !fini_array) || !(section.flags & 0x2) || !section.size ||
                section.size % width || section.address % width || section.offset % width ||
                (section.entry_size && section.entry_size != width) ||
                section.size > UINT64_MAX - section.offset || section.size / width > 65536) {
                if ((init_array || fini_array) && section.size / width > 65536)
                    output->complete = false;
                continue;
            }
            for (std::uint64_t offset = 0; offset < section.size; offset += width) {
                canceled();
                if (offset > UINT64_MAX - section.address) break;
                const Address slot{image.layout().space.id, section.address + offset};
                const auto file = image.to_file_offset(slot);
                if (!file || file.value().value != section.offset + offset ||
                    image.plaintext_window(slot, width) != width) {
                    output->complete = false;
                    continue;
                }
                auto bytes = image.read(slot, width);
                if (!bytes || bytes.value().size() != width) {
                    output->complete = false;
                    continue;
                }
                ByteReader reader(bytes.value());
                std::optional<std::uint64_t> target_value;
                if (width == 8) {
                    auto value = reader.read_u64(metadata.elf->header.order);
                    if (value) target_value = value.value();
                } else {
                    auto value = reader.read_u32(metadata.elf->header.order);
                    if (value) target_value = value.value();
                }
                if (!target_value) { output->complete = false; continue; }
                if (!*target_value) continue;
                const Address target{image.layout().space.id, *target_value};
                const auto *segment = image.segment_at(target);
                if (!segment || !segment->executable || target.offset < segment->begin.offset ||
                    target.offset - segment->begin.offset >= segment->file_size ||
                    image.code_window(target, 1) != 1 || image.plaintext_window(target, 1) != 1)
                    continue;
                FunctionSeed seed{FunctionSeedKind::initializer, target, slot, {}};
                FunctionSeedInitializerEvidence evidence;
                evidence.source = init_array ? FunctionInitializerSource::elf_init_array_section
                                             : FunctionInitializerSource::elf_fini_array_section;
                evidence.section = section.index;
                evidence.index = offset / width;
                evidence.file_offset = section.offset + offset;
                seed.initializer_evidence = std::move(evidence);
                root(std::move(seed), false);
            }
        }
        // Older toolchains emit legacy .ctors/.dtors pointer lists as
        // allocated PROGBITS sections. These are only interpreted for ET_EXEC
        // so the stored absolute pointers need no guessed load bias. The
        // all-ones and null sentinels are ignored; every other slot is resolved
        // through relocation metadata before raw bytes can be considered.
        auto resolver_result = RelocationResolver::create(image, metadata, stop);
        if (!resolver_result) {
            output->complete = false;
        } else {
            const auto &resolver = resolver_result.value();
            const auto width = metadata.elf->header.is_64 ? std::uint64_t{8} : std::uint64_t{4};
            const auto all_ones = width == 8 ? UINT64_MAX : UINT32_MAX;
            for (const auto &section : metadata.elf->sections) {
                canceled();
                const bool constructors = section.name == ".ctors";
                const bool destructors = section.name == ".dtors";
                if ((!constructors && !destructors) || section.type != 1 || !(section.flags & 0x2) ||
                    !section.size)
                    continue;
                if (section.size % width || section.size / width > 65536 ||
                    (section.entry_size && section.entry_size != width) || section.size > UINT64_MAX - section.address ||
                    section.size > UINT64_MAX - section.offset) {
                    output->complete = false;
                    continue;
                }
                for (std::uint64_t offset = 0; offset < section.size; offset += width) {
                    canceled();
                    const Address slot{image.layout().space.id, section.address + offset};
                    const auto file = image.to_file_offset(slot);
                    const auto *slot_segment = image.segment_at(slot);
                    const bool file_backed_slot = slot_segment && slot_segment->readable &&
                        !slot_segment->writable && slot.offset >= slot_segment->begin.offset &&
                        slot.offset - slot_segment->begin.offset <= slot_segment->file_size &&
                        width <= slot_segment->file_size - (slot.offset - slot_segment->begin.offset);
                    if (!file || file.value().value != section.offset + offset ||
                        !file_backed_slot || image.plaintext_window(slot, width) != width) {
                        output->complete = false;
                        continue;
                    }
                    auto resolved = resolver.data_at(image, slot, static_cast<std::uint8_t>(width), stop);
                    if (!resolved) {
                        output->complete = false;
                        continue;
                    }
                    std::optional<std::uint64_t> target_value;
                    if (resolved.value().address) {
                        target_value = resolved.value().address->offset;
                        if (resolved.value().address->space != image.layout().space.id) {
                            output->complete = false;
                            continue;
                        }
                    } else if (resolved.value().relocated()) {
                        output->complete = false;
                        continue;
                    } else {
                        auto bytes = image.read(slot, static_cast<std::size_t>(width));
                        if (!bytes || bytes.value().size() != width) {
                            output->complete = false;
                            continue;
                        }
                        ByteReader reader(bytes.value());
                        if (width == 8) {
                            const auto value = reader.read_u64(metadata.elf->header.order);
                            if (value) target_value = value.value();
                        } else {
                            const auto value = reader.read_u32(metadata.elf->header.order);
                            if (value) target_value = value.value();
                        }
                    }
                    if (!target_value) {
                        output->complete = false;
                        continue;
                    }
                    if (*target_value == 0 || *target_value == all_ones)
                        continue;
                    const Address target{image.layout().space.id, *target_value};
                    const auto *segment = image.segment_at(target);
                    if (!segment || !segment->executable || target.offset < segment->begin.offset ||
                        target.offset - segment->begin.offset >= segment->file_size ||
                        image.code_window(target, 1) != 1 || image.plaintext_window(target, 1) != 1)
                        continue;
                    FunctionSeed seed{FunctionSeedKind::initializer, target, slot, {}};
                    FunctionSeedInitializerEvidence evidence;
                    evidence.source = constructors ? FunctionInitializerSource::elf_ctors_section
                                                   : FunctionInitializerSource::elf_dtors_section;
                    evidence.section = section.index;
                    evidence.index = offset / width;
                    evidence.file_offset = section.offset + offset;
                    evidence.relocation_rows = resolved.value().relocations;
                    seed.initializer_evidence = std::move(evidence);
                    root(std::move(seed), false);
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
    // Ordered EHABI rows identify successive function starts. Use a successor
    // as an ownership bound only when both starts lie in the same initialized
    // executable segment and the complete interval is backed by file bytes.
    // The final row has no inferred extent because its successor may be a
    // linker sentinel or lie beyond this image's mapped code.
    if (metadata.elf) {
        const auto &functions = metadata.elf->arm_ehabi_functions;
        for (std::size_t i = 0; i < functions.size(); ++i) {
            canceled();
            const auto &function = functions[i];
            if (i + 1 < functions.size()) {
                const auto &next = functions[i + 1];
                if (next.begin.space == function.begin.space && next.begin.offset > function.begin.offset) {
                    const auto *segment = image.segment_at(function.begin);
                    if (segment && segment->executable && image.segment_at(next.begin) == segment &&
                        function.begin.offset >= segment->begin.offset && next.begin.offset >= segment->begin.offset) {
                        const auto relative = function.begin.offset - segment->begin.offset;
                        const auto size = next.begin.offset - function.begin.offset;
                        if (relative < segment->file_size && size <= segment->file_size - relative &&
                            relative < segment->size && size <= segment->size - relative &&
                            image.code_window(function.begin, size) == size)
                            metadata_chunks[function.begin].push_back({function.begin, size, {}});
                    }
                }
            }
            FunctionSeed seed{FunctionSeedKind::unwind, function.begin, {}, {}};
            seed.unwind_evidence = FunctionSeedUnwindEvidence{function.section, function.file_offset, 8};
            root(std::move(seed), false);
        }
        // A directly decoded CIE personality is called by the runtime during
        // exception handling and may have no ordinary code reference. Use the
        // encoded pointer's own source bytes as unwind provenance. Indirect
        // encodings remain unresolved metadata and never become roots here.
        for (const auto &function : metadata.elf->eh_frame_functions) {
            canceled();
            if (!function.personality || !function.personality->target ||
                !function.personality->encoded_size) continue;
            FunctionSeed seed{FunctionSeedKind::unwind, *function.personality->target, {}, {}};
            seed.unwind_evidence = FunctionSeedUnwindEvidence{function.section,
                function.personality->file_offset, function.personality->encoded_size};
            root(std::move(seed), false);
        }
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
            // S_MOD_INIT_FUNC_POINTERS and S_MOD_TERM_FUNC_POINTERS contain
            // loader-invoked routines. Resolve each slot through relocation/
            // dyld data before considering an unrelocated pointer word.
            const auto section_type = section.flags & 0xffu;
            const bool is_initializer = section.name == "__mod_init_func" && section_type == 9u;
            const bool is_terminator = section.name == "__mod_term_func" && section_type == 10u;
            if (!is_initializer && !is_terminator)
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
                    evidence.source = is_initializer ? FunctionInitializerSource::macho_mod_init_func
                                                     : FunctionInitializerSource::macho_mod_term_func;
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
            if (function.personality && function.personality_source && function.personality_source_size) {
                FunctionSeed personality{FunctionSeedKind::unwind, *function.personality, {}, {}};
                personality.unwind_evidence = FunctionSeedUnwindEvidence{function.section,
                    function.personality_source->value, function.personality_source_size};
                root(std::move(personality), false);
            }
        }
        // The compact-unwind index maps each entry to the next entry (or the
        // next index-row boundary for the final page entry). Use that linker
        // interval as a recovery boundary only after rechecking its complete
        // initialized executable backing. A stronger extent already attached
        // to the same root remains authoritative.
        for (const auto &function : metadata.macho->compact_unwind_functions) {
            canceled();
            if (!function.address || function.size == 0 ||
                !AddressRange::create(*function.address, function.size)) {
                output->complete = false;
                continue;
            }
            const auto *segment = image.segment_at(*function.address);
            if (!segment || !segment->executable || function.address->offset < segment->begin.offset) {
                output->complete = false;
                continue;
            }
            const auto relative = function.address->offset - segment->begin.offset;
            if (relative >= segment->file_size || function.size > segment->file_size - relative ||
                relative >= segment->size || function.size > segment->size - relative ||
                image.code_window(*function.address, function.size) != function.size) {
                output->complete = false;
                continue;
            }
            if (metadata_chunks.contains(*function.address))
                continue;
            const auto interval_end = function.address->offset + function.size;
            const auto conflicting_root = root_entries.upper_bound(*function.address);
            if (conflicting_root != root_entries.end() && conflicting_root->space == function.address->space &&
                conflicting_root->offset < interval_end) {
                output->complete = false;
                continue;
            }
            metadata_chunks[*function.address].push_back({*function.address, function.size, {}});
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
    // Legacy x86 IMAGE_DEBUG_TYPE_FPO records identify function starts and
    // exact code extents. The loader has already validated their record
    // encoding and executable image-relative range; translate against the
    // mapped base here and recheck initialized executable backing before they
    // constrain ownership.
    if (metadata.pe && metadata.machine == 0x14c && !metadata.pe->fpo_records.empty()) {
        auto load_base = metadata.preferred_base;
        for (const auto &segment : image.layout().segments)
            if (segment.name == "headers") {
                load_base = segment.begin.offset;
                break;
            }
        for (const auto &record : metadata.pe->fpo_records) {
            canceled();
            const auto offset = checked_add(load_base, record.begin_rva);
            if (!offset || record.code_size == 0) {
                output->complete = false;
                continue;
            }
            const Address entry{image.layout().space.id, offset.value()};
            if (!AddressRange::create(entry, record.code_size)) {
                output->complete = false;
                continue;
            }
            const auto *segment = image.segment_at(entry);
            if (!segment || !segment->executable || entry.offset < segment->begin.offset) {
                output->complete = false;
                continue;
            }
            const auto relative = entry.offset - segment->begin.offset;
            if (relative >= segment->file_size || record.code_size > segment->file_size - relative ||
                image.code_window(entry, record.code_size) != record.code_size) {
                output->complete = false;
                continue;
            }
            if (record.source.spans.size() != 1 || record.source.spans.front().size != 16) {
                output->complete = false;
                continue;
            }
            metadata_chunks[entry].push_back({entry, record.code_size, {}});
            FunctionSeed seed{FunctionSeedKind::unwind, entry, {}, {}};
            seed.unwind_evidence = FunctionSeedUnwindEvidence{record.source.index,
                record.source.spans.front().offset.value, record.source.spans.front().size};
            root(std::move(seed), false);
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
    // A validated PE32 SafeSEH table names executable exception handlers.
    // Treat its entries as function roots so handlers reached only through
    // the OS exception dispatcher are not lost from the recovered graph.
    if (metadata.pe && metadata.machine == 0x14c && metadata.pe->load_configuration) {
        auto load_base = metadata.preferred_base;
        for (const auto &segment : image.layout().segments)
            if (segment.name == "headers") {
                load_base = segment.begin.offset;
                break;
            }
        for (const auto &handler : metadata.pe->load_configuration->safe_seh_handlers) {
            canceled();
            const auto offset = checked_add(load_base, handler.rva);
            if (!offset) {
                output->complete = false;
                continue;
            }
            root({FunctionSeedKind::safe_seh, {image.layout().space.id, offset.value()}, {}, {}}, false);
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
        const auto &arm64_functions = metadata.pe->arm64_exception_functions;
        std::vector<bool> linked_jump_islands(arm64_functions.size(), false);
        // ARM64 pdata links describe jump islands that inherit unwind state
        // from a parent function. Keep those islands as chunks of the parent
        // instead of inventing separate function roots for linker veneers.
        for (std::size_t index = 0; index < arm64_functions.size(); ++index) {
            canceled();
            const auto &fragment = arm64_functions[index];
            if (fragment.kind != PeArm64UnwindKind::pdata_link) continue;
            std::array<std::size_t, 32> visited{};
            std::size_t visited_count = 0;
            const PeArm64RuntimeFunction *parent = &fragment;
            bool valid_parent = true;
            for (std::size_t depth = 0; parent->kind == PeArm64UnwindKind::pdata_link; ++depth) {
                if (depth >= 32 || !parent->linked_record_index ||
                    *parent->linked_record_index >= arm64_functions.size()) {
                    valid_parent = false;
                    break;
                }
                const auto parent_index = *parent->linked_record_index;
                const auto visited_end = visited.begin() + visited_count;
                if (std::find(visited.begin(), visited_end, parent_index) != visited_end) {
                    valid_parent = false;
                    break;
                }
                visited[visited_count++] = parent_index;
                parent = &arm64_functions[parent_index];
            }
            const auto fragment_offset = checked_add(load_base, fragment.begin_rva);
            if (!valid_parent || !fragment_offset || parent == &fragment) {
                output->complete = false;
                linked_jump_islands[index] = true;
                continue;
            }
            const auto parent_offset = checked_add(load_base, parent->begin_rva);
            if (!parent_offset || parent_offset.value() == fragment_offset.value()) {
                output->complete = false;
                linked_jump_islands[index] = true;
                continue;
            }
            // A pdata link does not carry an extent. Its source-backed extent
            // is the interval up to the next strictly sorted runtime-function
            // row, matching the interval used by the PE unwinder. An unbounded
            // final row cannot be safely assigned to the parent.
            if (index + 1 >= arm64_functions.size() ||
                arm64_functions[index + 1].begin_rva <= fragment.begin_rva) {
                output->complete = false;
                linked_jump_islands[index] = true;
                continue;
            }
            const auto fragment_size = std::uint64_t{arm64_functions[index + 1].begin_rva} - fragment.begin_rva;
            const Address fragment_entry{image.layout().space.id, fragment_offset.value()};
            const Address parent_entry{image.layout().space.id, parent_offset.value()};
            const auto *segment = image.segment_at(fragment_entry);
            if (!segment || !segment->executable || (fragment_entry.offset & 3u) != 0 ||
                (fragment_size & 3u) != 0 || fragment_entry.offset < segment->begin.offset) {
                output->complete = false;
                linked_jump_islands[index] = true;
                continue;
            }
            const auto relative = fragment_entry.offset - segment->begin.offset;
            if (relative >= segment->file_size || fragment_size > segment->file_size - relative ||
                relative >= segment->size || fragment_size > segment->size - relative ||
                image.code_window(fragment_entry, fragment_size) != fragment_size ||
                image.segment_at(Address{fragment_entry.space, fragment_entry.offset + fragment_size - 1}) != segment) {
                output->complete = false;
                linked_jump_islands[index] = true;
                continue;
            }
            std::uint64_t source_size = 0;
            std::optional<std::uint64_t> next_source_offset;
            bool source_valid = !fragment.source.spans.empty();
            for (const auto &span : fragment.source.spans) {
                if (span.size == 0 || span.size > std::numeric_limits<std::uint64_t>::max() - span.offset.value ||
                    span.size > std::numeric_limits<std::uint64_t>::max() - source_size ||
                    (next_source_offset && span.offset.value != *next_source_offset)) {
                    source_valid = false;
                    break;
                }
                source_size += span.size;
                next_source_offset = span.offset.value + span.size;
            }
            if (!source_valid || source_size != 8) {
                output->complete = false;
                linked_jump_islands[index] = true;
                continue;
            }
            metadata_chunks[parent_entry].push_back({fragment_entry, fragment_size, {}});
            FunctionSeed link_evidence{FunctionSeedKind::unwind, parent_entry, {}, {}};
            link_evidence.unwind_evidence = FunctionSeedUnwindEvidence{
                fragment.source.index, fragment.source.spans.front().offset.value, source_size};
            root(std::move(link_evidence), false);
            linked_jump_islands[index] = true;
        }
        for (std::size_t index = 0; index < arm64_functions.size(); ++index) {
            canceled();
            const auto &function = arm64_functions[index];
            if (linked_jump_islands[index])
                continue;
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
    // Linker POGO profile rows name function starts and code lengths. Treat
    // those starts as symbol-like roots, but only use their extent when the
    // complete range is initialized executable input and no stronger
    // user/unwind boundary already owns the entry.
    if (metadata.pe && !metadata.pe->pogo_data.empty()) {
        auto load_base = metadata.preferred_base;
        for (const auto &segment : image.layout().segments)
            if (segment.name == "headers") {
                load_base = segment.begin.offset;
                break;
            }
        AddressMap<std::uint64_t> extents;
        AddressMap<FunctionSeedPogoEvidence> evidence;
        AddressSet conflicting_extents;
        for (std::size_t profile_index = 0; profile_index < metadata.pe->pogo_data.size(); ++profile_index) {
            const auto &profile = metadata.pe->pogo_data[profile_index];
            if (profile_index > UINT32_MAX) {
                output->complete = false;
                break;
            }
            for (std::size_t entry_index = 0; entry_index < profile.entries.size(); ++entry_index) {
                const auto &function = profile.entries[entry_index];
                if (entry_index > UINT32_MAX) {
                    output->complete = false;
                    break;
                }
                canceled();
                if (function.size == 0 || function.source.spans.empty()) {
                    output->complete = false;
                    continue;
                }
                const auto offset = checked_add(load_base, function.rva);
                if (!offset) {
                    output->complete = false;
                    continue;
                }
                const Address entry{image.layout().space.id, offset.value()};
                if (!AddressRange::create(entry, function.size)) {
                    output->complete = false;
                    continue;
                }
                const auto *segment = image.segment_at(entry);
                if (!segment || !segment->executable || entry.offset < segment->begin.offset) {
                    output->complete = false;
                    continue;
                }
                const auto relative = entry.offset - segment->begin.offset;
                if (relative >= segment->file_size || function.size > segment->file_size - relative ||
                    relative >= segment->size || function.size > segment->size - relative ||
                    image.code_window(entry, function.size) != function.size) {
                    output->complete = false;
                    continue;
                }
                bool valid_source = true;
                for (const auto &span : function.source.spans) {
                    if (span.size == 0) {
                        valid_source = false;
                        break;
                    }
                }
                if (!valid_source) {
                    output->complete = false;
                    continue;
                }
                auto [found, inserted] = extents.emplace(entry, function.size);
                if (!inserted && found->second != function.size) {
                    conflicting_extents.insert(entry);
                    output->complete = false;
                }
                if (inserted)
                    evidence.emplace(entry, FunctionSeedPogoEvidence{static_cast<std::uint32_t>(profile_index),
                        function.source.index, function.source.spans.front().offset.value,
                        function.source.spans.front().size});
            }
        }
        // POGO entries can describe identical roots in multiple profiles. If
        // distinct entries overlap, retain their roots but avoid choosing
        // either extent as an ownership boundary.
        std::optional<std::pair<Address, std::uint64_t>> active_extent;
        for (const auto &[entry, size] : extents) {
            if (active_extent && active_extent->first.space == entry.space &&
                entry.offset < active_extent->first.offset + active_extent->second) {
                conflicting_extents.insert(active_extent->first);
                conflicting_extents.insert(entry);
                output->complete = false;
                const auto end = entry.offset + size;
                if (end > active_extent->first.offset + active_extent->second)
                    active_extent = std::pair{entry, size};
            } else {
                active_extent = std::pair{entry, size};
            }
        }
        for (const auto &[entry, size] : extents) {
            FunctionSeed seed{FunctionSeedKind::pogo, entry, {}, {}};
            if (const auto found = evidence.find(entry); found != evidence.end())
                seed.pogo_evidence = found->second;
            if (!seed.pogo_evidence) {
                output->complete = false;
                continue;
            }
            root(std::move(seed), false);
            if (!conflicting_extents.contains(entry) && !definitions.contains(entry) &&
                !metadata_chunks.contains(entry))
                metadata_chunks[entry].push_back({entry, size, {}});
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
    // Imported DWARF subprogram ranges can recover stripped ELF function
    // entries and discontiguous chunks; alternate entry-point DIEs add only
    // their exact code PCs. Keep subprogram bounds subordinate to explicit,
    // unwind, POGO, and ELF symbol extents already accepted above. The loader
    // structurally validates each DIE; rebase virtual addresses to the current
    // image and validate complete ranges before trusting ownership boundaries.
    if (metadata.elf && metadata.elf->dwarf_info && metadata.elf->header.object_type != 1 &&
        metadata.elf->header.object_type != 4) {
        std::uint64_t load_bias = 0;
        bool load_bias_valid = true;
        if (!image.layout().segments.empty()) {
            const auto mapped_base = std::min_element(image.layout().segments.begin(), image.layout().segments.end(),
                [](const auto &a, const auto &b) { return a.begin.offset < b.begin.offset; })->begin.offset;
            if (mapped_base >= metadata.preferred_base)
                load_bias = mapped_base - metadata.preferred_base;
            else {
                output->complete = false;
                load_bias_valid = false;
            }
        }
        AddressMap<std::vector<FunctionChunk>> candidate_ranges;
        AddressSet conflicting_ranges;
        for (const auto &symbol : metadata.elf->dwarf_info->symbols) {
            canceled();
            if (symbol.kind == symbols::SymbolKind::entry_point) {
                if (symbol.origin.record_size == 0 || !symbol.ranges.empty() || !load_bias_valid) {
                    output->complete = false;
                    continue;
                }
                const auto mapped_entry = checked_add(symbol.address, load_bias);
                if (!mapped_entry) {
                    output->complete = false;
                    continue;
                }
                FunctionSeed seed{FunctionSeedKind::dwarf_entry_point,
                    Address{image.layout().space.id, mapped_entry.value()}, {}, {}};
                seed.dwarf_evidence = FunctionSeedDwarfEvidence{symbol.origin.unit_offset,
                    symbol.origin.record_offset, symbol.origin.record_size};
                root(std::move(seed), false);
                continue;
            }
            if (symbol.kind != symbols::SymbolKind::function || symbol.ranges.empty() ||
                symbol.origin.record_size == 0 || !load_bias_valid)
                continue;
            std::vector<FunctionChunk> chunks;
            chunks.reserve(symbol.ranges.size());
            bool valid = true;
            for (const auto &range : symbol.ranges) {
                canceled();
                if (range.begin >= range.end) { valid = false; break; }
                const auto begin_offset = checked_add(range.begin, load_bias);
                const auto end_offset = checked_add(range.end, load_bias);
                if (!begin_offset || !end_offset || end_offset.value() <= begin_offset.value()) {
                    valid = false;
                    break;
                }
                const Address begin{image.layout().space.id, begin_offset.value()};
                const auto size = end_offset.value() - begin_offset.value();
                if (!AddressRange::create(begin, size)) { valid = false; break; }
                const auto *segment = image.segment_at(begin);
                const Address last{begin.space, end_offset.value() - 1};
                if (!segment || !segment->executable || image.segment_at(last) != segment ||
                    begin.offset < segment->begin.offset) { valid = false; break; }
                const auto relative = begin.offset - segment->begin.offset;
                if (relative >= segment->file_size || size > segment->file_size - relative ||
                    relative >= segment->size || size > segment->size - relative ||
                    image.code_window(begin, size) != size) { valid = false; break; }
                chunks.push_back({begin, size, {}});
            }
            if (!valid || chunks.empty()) {
                output->complete = false;
                continue;
            }
            std::sort(chunks.begin(), chunks.end(), [](const auto &a, const auto &b) {
                if (AddressLess{}(a.begin, b.begin)) return true;
                if (AddressLess{}(b.begin, a.begin)) return false;
                return a.size < b.size;
            });
            chunks.erase(std::unique(chunks.begin(), chunks.end(), [](const auto &a, const auto &b) {
                return a.begin == b.begin && a.size == b.size;
            }), chunks.end());
            for (std::size_t i = 1; i < chunks.size(); ++i) {
                if (chunks[i - 1].begin.space == chunks[i].begin.space &&
                    chunks[i].begin.offset < chunks[i - 1].begin.offset + chunks[i - 1].size) {
                    valid = false;
                    break;
                }
            }
            const Address entry = chunks.front().begin;
            const auto context = image.context_at(entry);
            const auto mapped_symbol = checked_add(symbol.address, load_bias);
            if (!valid || !context || !mapped_symbol || mapped_symbol.value() != chunks.front().begin.offset) {
                output->complete = false;
                continue;
            }
            for (const auto &chunk : chunks) {
                const Address last{chunk.begin.space, chunk.begin.offset + chunk.size - 1};
                const auto chunk_context = image.context_at(chunk.begin);
                const auto last_context = image.context_at(last);
                if (!chunk_context || !last_context || chunk_context.value() != context.value() ||
                    last_context.value() != context.value()) {
                    valid = false;
                    break;
                }
            }
            if (!valid) {
                output->complete = false;
                continue;
            }
            FunctionSeed seed{FunctionSeedKind::dwarf_subprogram, entry, {}, {}};
            seed.dwarf_evidence = FunctionSeedDwarfEvidence{symbol.origin.unit_offset,
                symbol.origin.record_offset, symbol.origin.record_size};
            root(std::move(seed), false);
            if (!roots.contains(entry) || definitions.contains(entry) || metadata_chunks.contains(entry))
                continue;
            if (const auto found = candidate_ranges.find(entry); found == candidate_ranges.end())
                candidate_ranges.emplace(entry, std::move(chunks));
            else if (found->second != chunks)
                conflicting_ranges.insert(entry);
        }
        for (auto &[entry, chunks] : candidate_ranges) {
            canceled();
            if (conflicting_ranges.contains(entry)) {
                output->complete = false;
                continue;
            }
            if (!metadata_chunks.contains(entry))
                metadata_chunks.emplace(entry, std::move(chunks));
        }
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
            constexpr size_t max_jvm_instruction_extent = 65535;
            std::optional<size_t> required;
            if (input[0] == std::byte{0xaa} && available >= switch_header + 12) {
                const auto low = read_u32(switch_header + 4);
                const auto high = read_u32(switch_header + 8);
                if (high >= low) {
                    const auto count = std::uint64_t(std::int64_t(high) - low) + 1;
                    const auto header_extent = switch_header + 12;
                    if (header_extent <= max_jvm_instruction_extent &&
                        count <= (max_jvm_instruction_extent - header_extent) / 4)
                        required = header_extent + static_cast<size_t>(count) * 4;
                }
            } else if (input[0] == std::byte{0xab} && available >= switch_header + 8) {
                const auto pairs = read_u32(switch_header + 4);
                const auto header_extent = switch_header + 8;
                if (pairs >= 0 && header_extent <= max_jvm_instruction_extent &&
                    static_cast<std::uint64_t>(pairs) <=
                        (max_jvm_instruction_extent - header_extent) / 8)
                    required = header_extent + static_cast<size_t>(pairs) * 8;
            }
            if (required && *required > available && *required <= max_jvm_instruction_extent) {
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
        fact->semantic_decoder_used = decoded.semantic_decoder_used;
        const auto &instruction = fact->instruction;
        fact->id = ids.make(FactKind::instruction, address, instruction.encoded_bytes());
        for (size_t i = 0; i < instruction.byte_length(); ++i) {
            const auto at = take(advance(address, i));
            take(fact->reads.include(take(image.to_file_offset(at)), 1));
            if (const auto *region = region_at(at))
                if (std::find(value.decisions.begin(), value.decisions.end(), region->id) == value.decisions.end())
                    value.decisions.push_back(region->id);
        }
        if (fact->semantic_decoder_used)
            for (const auto &range : semantic_decoder_image_ranges)
                take(fact->reads.include(range.begin, range.size));
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
    const auto fact_owner = value.fact;
    const auto &instruction = fact_owner->instruction;
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
    auto flow_target = take(relocations.control_target(image, instruction, stop));
    if (!flow_target) flow_target = dex_direct_call_target(instruction, image, metadata);
    if (!flow_target) flow_target = wasm_direct_call_target(instruction, image, metadata);
    auto external_call_target = wasm_import_call_target(instruction, metadata);
    if (!flow_target && !external_call_target && instruction.flow == FlowKind::call) {
        const auto operand_index = analysis_detail::control_operand_index(instruction);
        if (operand_index < instruction.operands.size()) {
            if (const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[operand_index]);
                memory && memory->resolved_address) {
                const auto imported = imported_call_slots.find(*memory->resolved_address);
                if (imported != imported_call_slots.end()) {
                    external_call_target = imported->second;
                } else if (auto local = local_x64_indirect_call_target(image, relocations, instruction, stop);
                           local && !permission(*local)) {
                    flow_target = *local;
                    const auto file = take(image.to_file_offset(*memory->resolved_address));
                    take(value.window.include(file, 8));
                    auto dependent_fact = std::make_shared<InstructionFact>(*value.fact);
                    take(dependent_fact->reads.include(file, 8));
                    value.fact = std::move(dependent_fact);
                }
            }
        }
    }
    if (analysis_detail::has_delay_slot(instruction)) {
        const auto slot = take(analysis_detail::delay_slot_address(instruction));
        delayed_slots.insert(slot);
        value.edges.push_back({slot, BlockEdgeKind::delay_slot});
    }
    const auto continuation = [&](BlockEdgeKind kind, std::uint16_t flags_guard = all_nzcv,
                                  bool flags_unknown_after = false) {
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
                                       : ThumbITState{},
                                   flags_guard, flags_unknown_after});
        else
            value.stop =
                FunctionStop{address, FunctionStopReason::target_overflow, "Continuation exceeds address model"};
    };
    const auto executes_with = predicate_guard(instruction);
    const auto skips_with = skipped_predicate_guard(instruction);
    const bool writes_nzcv = (instruction.arm &&
                             (instruction.arm->flags_written != 0 || !instruction.arm->flags_known)) ||
                            (instruction.context.architecture == Architecture::arm64 &&
                             (instruction.opcode == Opcode::opaque ||
                              std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                                          [](const auto &reg) { return reg.bank == RegisterBank::arm_flags; })));
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
        if (instruction.context.architecture != Architecture::arm || !flow_target)
            return true;
        if (!instruction.arm)
            return false;
        const auto target_context = image.context_at(*flow_target);
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
        if (flow_target && analysis_detail::is_arm_literal_pc_load(instruction)) {
            const auto context = image.context_at(*flow_target);
            if (context && context.value().mode == ExecutionMode::thumb)
                return ThumbITState{true, 0};
        }
        return ThumbITState{};
    };
    switch (instruction.flow) {
    case FlowKind::ret:
        value.stop = FunctionStop{address, FunctionStopReason::ret, "Return"};
        value.stop_guard = executes_with;
        if (skips_with) continuation(BlockEdgeKind::conditional_false, skips_with);
        break;
    case FlowKind::trap:
        value.stop = FunctionStop{address, FunctionStopReason::trap, "Trap"};
        value.stop_guard = executes_with;
        if (instruction.context.architecture == Architecture::arm && skips_with)
            continuation(BlockEdgeKind::conditional_false, skips_with);
        break;
    case FlowKind::fallthrough:
        if (instruction.context.architecture == Architecture::arm && instruction.arm && instruction.arm->writes_pc) {
            value.stop = FunctionStop{address, FunctionStopReason::unsupported,
                                      "ARM instruction writes PC without a modeled control-flow edge"};
            value.stop_guard = executes_with;
            if (skips_with) continuation(BlockEdgeKind::conditional_false, skips_with);
        } else if (instruction.arm && instruction.arm->predicate != ArmPredicate::always) {
            continuation(BlockEdgeKind::fallthrough, executes_with, writes_nzcv);
            if (skips_with) continuation(BlockEdgeKind::fallthrough, skips_with);
        } else
            continuation(BlockEdgeKind::fallthrough, all_nzcv, writes_nzcv);
        break;
    case FlowKind::call:
        value.call = true;
        value.call_guard = executes_with;
        value.call_target = arm_target_matches() ? flow_target : std::nullopt;
        value.external_call_target = std::move(external_call_target);
        if (value.call_target && target_it().known)
            thumb_states.emplace(*value.call_target, target_it());
        if (!value.call_target && !value.external_call_target)
            value.call_issue = FunctionStop{
                address,
                instruction.context.architecture == Architecture::arm && flow_target ? FunctionStopReason::unsupported
                                                                                 : unresolved(),
                instruction.context.architecture == Architecture::arm && flow_target
                    ? "ARM call target conflicts with source-backed execution-state metadata"
                    : instruction.context.architecture == Architecture::wasm &&
                              instruction.mnemonic_override == "call"
                          ? "WebAssembly direct call does not resolve to a validated local body or function import"
                          : "Call target remains unresolved"};
        else if (value.call_target) {
            if (auto denied = permission(*value.call_target))
                value.call_issue = FunctionStop{address, *denied, "Call target has no permitted initialized code"};
        }
        continuation(BlockEdgeKind::call_continuation, executes_with, true);
        if (instruction.context.architecture == Architecture::arm && skips_with)
            continuation(BlockEdgeKind::conditional_false, skips_with);
        break;
    case FlowKind::conditional_branch: {
        if (instruction.context.architecture == Architecture::arm) {
            if (!arm_target_matches()) {
                value.stop = FunctionStop{address, FunctionStopReason::unsupported,
                                          "ARM branch target conflicts with source-backed execution-state metadata"};
                value.stop_guard = executes_with;
                if (skips_with) continuation(BlockEdgeKind::conditional_false, skips_with);
                break;
            }
        }
        const bool conditional_call = analysis_detail::is_mips_conditional_link_branch(instruction);
        value.edges.push_back({flow_target, flow_target ? (conditional_call ? BlockEdgeKind::conditional_call : BlockEdgeKind::conditional_true) : BlockEdgeKind::unresolved,
                               target_it(), executes_with, writes_nzcv});
        if (conditional_call) {
            value.call = true;
            value.call_guard = executes_with;
            value.call_target = flow_target;
            if (!flow_target)
                value.call_issue = FunctionStop{address, unresolved(), "Conditional call target remains unresolved"};
            else if (auto denied = permission(*flow_target))
                value.call_issue = FunctionStop{address, *denied, "Conditional call target has no permitted initialized code"};
        }
        if (!flow_target) {
            value.stop = FunctionStop{address, unresolved(), "Conditional target remains unresolved"};
            value.stop_guard = executes_with;
        }
        const auto branch_not_taken = ((instruction.context.architecture == Architecture::arm && instruction.arm &&
                                              instruction.arm->predicate == ArmPredicate::condition) ||
                                       (instruction.context.architecture == Architecture::arm64 &&
                                        instruction.opcode == Opcode::a64_b_cond))
                                          ? static_cast<std::uint16_t>(all_nzcv & ~executes_with)
                                          : all_nzcv;
        continuation(BlockEdgeKind::conditional_false, branch_not_taken);
        break;
    }
    case FlowKind::jump:
    {
        const bool predicated_arm_transfer = instruction.context.architecture == Architecture::arm && instruction.arm &&
                                             instruction.arm->predicate != ArmPredicate::always;
        if (instruction.context.architecture == Architecture::arm) {
            if (!arm_target_matches()) {
                value.stop = FunctionStop{address, FunctionStopReason::unsupported,
                                          "ARM branch target conflicts with source-backed execution-state metadata"};
                value.stop_guard = executes_with;
                if (predicated_arm_transfer && skips_with)
                    continuation(BlockEdgeKind::conditional_false, skips_with);
                break;
            }
        }
        value.edges.push_back({flow_target, flow_target ? BlockEdgeKind::jump : BlockEdgeKind::unresolved, target_it(),
                               executes_with, writes_nzcv});
        if (!flow_target) {
            value.stop = FunctionStop{address, unresolved(), "Jump target remains unresolved"};
            value.stop_guard = executes_with;
        }
        if (predicated_arm_transfer)
            continuation(BlockEdgeKind::conditional_false, skips_with);
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
    case FlowKind::data:
        if (!value.stop)
            value.stop = FunctionStop{address, FunctionStopReason::invalid,
                                      "DEX payload data is not an executable instruction"};
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
    // DEX code_items carry half-open protected ranges and ordered encoded
    // catch handlers. Add conservative exceptional successors only from
    // opcodes with observable Dalvik exception behavior; catch matching is
    // intentionally not guessed here, so every handler for the active try is
    // retained in table order.
    if (instruction.context.architecture == Architecture::dex && metadata.dex &&
        !instruction.encoded_bytes().empty() && address.space.value != 0) {
        const auto raw = std::to_integer<std::uint8_t>(instruction.encoded_bytes().front());
        const bool may_throw = raw == 0x1a || raw == 0x1b || raw == 0x1c ||
                               (raw >= 0x1d && raw <= 0x27) ||
                               (raw >= 0x44 && raw <= 0x78) || raw == 0x93 || raw == 0x94 ||
                               raw == 0x9e || raw == 0x9f || raw == 0xb3 || raw == 0xb4 ||
                               raw == 0xbe || raw == 0xbf || raw == 0xd3 || raw == 0xd4 ||
                               raw == 0xdb || raw == 0xdc || (raw >= 0xfa && raw <= 0xff);
        if (may_throw) {
            const auto method_index = static_cast<std::uint64_t>(address.space.value) - 1;
            const auto &methods = metadata.dex->code;
            const auto method = std::lower_bound(methods.begin(), methods.end(), method_index,
                [](const DexMethodCode &candidate, std::uint64_t index) {
                    return candidate.method_index < index;
                });
            if (method != methods.end() && method->method_index == method_index) {
                const auto &regions = method->exception_regions;
                const auto after = std::upper_bound(regions.begin(), regions.end(), address.offset,
                    [](std::uint64_t offset, const DexExceptionRegion &region) {
                        return offset < region.begin;
                    });
                if (after != regions.begin()) {
                    const auto &region = *std::prev(after);
                    if (address.offset >= region.begin && address.offset < region.end) {
                        constexpr std::size_t max_dex_handlers_per_instruction = 4096;
                        if (region.handlers.size() > max_dex_handlers_per_instruction) {
                            output->complete = false;
                            value.stop = FunctionStop{address, FunctionStopReason::unsupported,
                                "DEX try/catch handler list exceeds the bounded CFG successor budget"};
                        } else {
                            for (const auto &handler : region.handlers) {
                                const Address target{address.space, handler.address};
                                if (std::none_of(value.edges.begin(), value.edges.end(), [&](const NodeEdge &edge) {
                                        return edge.kind == BlockEdgeKind::exception && edge.target == target;
                                    }))
                                    value.edges.push_back({target, BlockEdgeKind::exception});
                            }
                        }
                    }
                }
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
    struct Work { Address address; ThumbITState it; std::uint16_t flags = all_nzcv; };
    const auto initial_state = [&](Address at) {
        const auto context = take(image.context_at(at));
        return context.mode == ExecutionMode::thumb ? ThumbITState{true, 0} : ThumbITState{};
    };
    std::deque<Address> pending_functions;
    for (const auto &[entry, seeds] : all_seeds)
        pending_functions.push_back(entry);
    auto &done = discovered_functions;
    auto &switch_scanned = discovered_switches;
    auto &memberships = discovery_memberships;
    while (!pending_functions.empty() && !discovery_exhausted) {
        canceled();
        const auto entry = pending_functions.front();
        pending_functions.pop_front();
        if (!done.insert(entry).second)
            continue;
        std::deque<Work> pending{{entry, thumb_states.contains(entry) ? thumb_states.at(entry) : initial_state(entry), all_nzcv}};
        if (auto definition = definitions.find(entry); definition != definitions.end())
            for (const auto &chunk : definition->second->chunks)
                pending.push_back({chunk.begin, initial_state(chunk.begin), all_nzcv});
        AddressMap<PathVisitState> visited;
        while (!pending.empty()) {
            canceled();
            const auto work = pending.front();
            pending.pop_front();
            const auto address = work.address;
            const auto incoming_it = work.it;
            bool it_conflict = false;
            const auto fresh_flags = add_new_path_flags(visited, address, incoming_it, work.flags, it_conflict);
            if (it_conflict) {
                if (thumb_states.contains(address) && thumb_states.at(address) != incoming_it)
                    (void)node(address, incoming_it);
                continue;
            }
            if (!fresh_flags) continue;
            reachable_flags[address] = static_cast<std::uint16_t>(reachable_flags[address] | fresh_flags);
            if (!within_chunks(entry, address))
                continue;
            if (memberships++ >= options.membership_budget) {
                discovery_exhausted = true;
                output->complete = false;
                break;
            }
            auto &current = node(address, incoming_it);
            if (attempts - last_progress_attempts >= 1024) {
                last_progress_attempts = attempts;
                report_progress("instruction-discovery", attempts, options.instruction_budget);
            }
            if (!current.fact || !within_chunks(entry, address, current.fact->instruction.length))
                continue;
            const auto &dispatch = current.fact->instruction;
            if (dispatch.flow == FlowKind::jump && (fresh_flags & predicate_guard(dispatch)) &&
                switch_scanned.insert(address).second) {
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
            if (current.call_target && (fresh_flags & current.call_guard) && !permission(*current.call_target) &&
                add_seed(all_seeds, {FunctionSeedKind::direct_call, *current.call_target, address, {}}))
                pending_functions.push_back(*current.call_target);
            for (const auto &edge : current.edges)
                if (edge.target) {
                    auto next_flags = edge_flags(current, edge, fresh_flags);
                    if (!next_flags) continue;
                    pending.push_back({*edge.target, edge.target_it, next_flags});
                }
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
            if (!edge.target || (reachable_flags.contains(at) &&
                                 !(reachable_flags.at(at) & edge.flags_guard)))
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
        struct Work { Address address; ThumbITState it; std::uint16_t flags = all_nzcv; };
        std::deque<Work> pending{{entry, thumb_states.contains(entry) ? thumb_states.at(entry) : ThumbITState{true, 0}, all_nzcv}};
        if (auto definition = definitions.find(entry); definition != definitions.end())
            for (const auto &chunk : definition->second->chunks)
                pending.push_back({chunk.begin, thumb_states.contains(chunk.begin) ? thumb_states.at(chunk.begin)
                                                                                   : ThumbITState{true, 0}, all_nzcv});
        AddressMap<PathVisitState> visited;
        while (!pending.empty()) {
            canceled();
            const auto work = pending.front();
            pending.pop_front();
            const auto at = work.address;
            const auto incoming_it = work.it;
            bool it_conflict = false;
            const auto fresh_flags = add_new_path_flags(visited, at, incoming_it, work.flags, it_conflict);
            if (it_conflict) {
                if (thumb_states.contains(at) && thumb_states.at(at) != incoming_it) (void)node(at, incoming_it);
                continue;
            }
            if (!fresh_flags) continue;
            if (!within_chunks(entry, at))
                continue;
            if (memberships++ >= options.membership_budget) {
                output->complete = false;
                return;
            }
            auto &current = node(at, incoming_it);
            if (ambiguous.contains(at) || !current.fact || !within_chunks(entry, at, current.fact->instruction.length))
                continue;
            if (current.call_target && (fresh_flags & current.call_guard) && !suppressed.contains(*current.call_target)) {
                if (auto denied = permission(*current.call_target))
                    output->candidates.push_back(
                        {*current.call_target, at, *denied, "Direct call cannot seed permitted initialized code"});
                else if (all_seeds.contains(*current.call_target) &&
                         add_seed(valid_seeds, {FunctionSeedKind::direct_call, *current.call_target, at, {}}))
                    pending_functions.push_back(*current.call_target);
            }
            for (const auto &edge : current.edges)
                if (edge.target) {
                    auto next_flags = edge_flags(current, edge, fresh_flags);
                    if (!next_flags) continue;
                    pending.push_back({*edge.target, edge.target_it, next_flags});
                }
        }
    }
}
void Recovery::assign_owners() {
    functions.clear();
    owners.clear();
    function_nodes.clear();
    reachable_flags.clear();
    output->calls.clear();
    for (const auto &[entry, seeds] : valid_seeds) {
        auto function = std::make_shared<FunctionRecord>();
        function->id = {ids.make(FactKind::function, entry)};
        function->entry = entry;
        function->seeds = seeds;
        functions.emplace(entry, std::move(function));
    }
    for (auto &[entry, function] : functions) {
        struct Work { Address address; ThumbITState it; std::uint16_t flags = all_nzcv; };
        std::deque<Work> pending{{entry, thumb_states.contains(entry) ? thumb_states.at(entry) : ThumbITState{true, 0}, all_nzcv}};
        if (auto definition = definitions.find(entry); definition != definitions.end())
            for (const auto &chunk : definition->second->chunks)
                pending.push_back({chunk.begin, thumb_states.contains(chunk.begin) ? thumb_states.at(chunk.begin)
                                                                                   : ThumbITState{true, 0}, all_nzcv});
        AddressMap<PathVisitState> visited;
        const auto record = [&](FunctionStop issue) {
            if (!terminal_complete(issue.reason))
                function->complete = false;
            const auto duplicate = std::any_of(function->stops.begin(), function->stops.end(), [&](const auto &old) {
                return old.address == issue.address && old.reason == issue.reason && old.detail == issue.detail;
            });
            if (!duplicate) function->stops.push_back(std::move(issue));
        };
        const auto record_call = [&](FunctionCall call) {
            const auto duplicate = std::any_of(output->calls.begin(), output->calls.end(), [&](const auto &old) {
                return old.owner == call.owner && old.source == call.source && old.tail_candidate == call.tail_candidate &&
                       old.external_target == call.external_target;
            });
            if (!duplicate) output->calls.push_back(std::move(call));
        };
        while (!pending.empty()) {
            canceled();
            const auto work = pending.front();
            pending.pop_front();
            const auto at = work.address;
            const auto incoming_it = work.it;
            bool it_conflict = false;
            const auto fresh_flags = add_new_path_flags(visited, at, incoming_it, work.flags, it_conflict);
            if (it_conflict) {
                if (thumb_states.contains(at) && thumb_states.at(at) != incoming_it) (void)node(at, incoming_it);
                continue;
            }
            if (!fresh_flags)
                continue;
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
            auto &address_owners = owners[at];
            if (std::find(address_owners.begin(), address_owners.end(), function->id) == address_owners.end())
                address_owners.push_back(function->id);
            function_nodes[function->id].insert(at);
            reachable_flags[at] = static_cast<std::uint16_t>(reachable_flags[at] | fresh_flags);
            if (current.stop && (fresh_flags & current.stop_guard))
                record(*current.stop);
            if (ambiguous.contains(at)) {
                record({at, FunctionStopReason::overlap, "Conflicting instruction streams stop trusted ownership"});
                continue;
            }
            const bool call_reachable = current.call && (fresh_flags & current.call_guard);
            if (call_reachable && current.call_issue)
                record(*current.call_issue);
            if (call_reachable) {
                std::optional<FunctionId> callee;
                if (current.call_target) {
                    auto target = functions.find(*current.call_target);
                    if (target != functions.end())
                        callee = target->second->id;
                }
                record_call({function->id, at, current.call_target, callee, false, current.external_call_target});
            }
            for (const auto &edge : current.edges) {
                if (!edge.target)
                    continue;
                auto next_flags = edge_flags(current, edge, fresh_flags);
                if (!next_flags) continue;
                const bool call_continuation_entry = call_reachable && edge.kind == BlockEdgeKind::call_continuation &&
                                                     current.call_target == edge.target && !permission(*edge.target) &&
                                                     !suppressed.contains(*edge.target);
                if (*edge.target != entry && (functions.contains(*edge.target) || root_entries.contains(*edge.target) ||
                                              call_continuation_entry)) {
                    if (!functions.contains(*edge.target)) {
                        record(
                            {*edge.target, FunctionStopReason::budget, "Established entry omitted by function budget"});
                        continue;
                    }
                    if (edge.kind == BlockEdgeKind::jump) {
                        record_call({function->id, at, edge.target, functions.at(*edge.target)->id, true});
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
                    pending.push_back({*edge.target, edge.target_it, next_flags});
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
void Recovery::resolve_wasm_indirect_calls() {
    if (!metadata.wasm || !output->complete || output->omitted_functions || output->omitted_blocks ||
        !output->candidates.empty() || !output->conflicts.empty())
        return;
    const auto &wasm = *metadata.wasm;
    if (wasm.imported_tables != 0 || wasm.defined_tables != 1 || !wasm.initial_table_complete ||
        std::any_of(wasm.exports.begin(), wasm.exports.end(), [](const WasmExport &entry) {
            return entry.kind == WasmExternalKind::table;
        }))
        return;
    for (const auto &[entry, function] : functions) {
        (void)entry;
        canceled();
        if (!function || !function->complete) return;
    }

    std::map<std::uint32_t, std::uint32_t> table_elements;
    for (const auto &element : wasm.initial_table_elements) {
        canceled();
        if (element.function_index >= wasm.function_type_indices.size()) return;
        const auto [found, inserted] = table_elements.emplace(element.slot, element.function_index);
        if (!inserted && found->second != element.function_index) return;
    }

    std::set<std::uint32_t> defined_spaces;
    std::map<Address, const InstructionFact *, AddressLess> instruction_ends;
    AddressSet ambiguous_ends;
    for (const auto &[address, node] : nodes) {
        canceled();
        const auto &fact = node.fact;
        if (!fact || fact->instruction.context.architecture != Architecture::wasm ||
            fact->instruction.context.mode != ExecutionMode::wasm32)
            continue;
        const auto &instruction = fact->instruction;
        if (instruction.address.space.value >= wasm.imported_functions &&
            instruction.address.space.value - wasm.imported_functions < wasm.defined_functions)
            defined_spaces.insert(instruction.address.space.value);
        const auto &mnemonic = instruction.mnemonic_override;
        if (instruction.opcode == Opcode::opaque || mnemonic == "table.set" || mnemonic == "table.init" ||
            mnemonic == "table.copy" || mnemonic == "table.grow" || mnemonic == "table.fill")
            return;
        if (!instruction.length || instruction.address.offset > UINT64_MAX - instruction.length) return;
        const Address end{instruction.address.space, instruction.address.offset + instruction.length};
        const auto [found, inserted] = instruction_ends.emplace(end, fact.get());
        if (!inserted) ambiguous_ends.insert(end);
    }
    if (defined_spaces.size() != wasm.defined_functions) return;
    for (std::uint64_t index = wasm.imported_functions;
         index < std::uint64_t{wasm.imported_functions} + wasm.defined_functions; ++index) {
        canceled();
        if (!defined_spaces.contains(static_cast<std::uint32_t>(index))) return;
    }

    for (auto &call : output->calls) {
        canceled();
        if (call.target || call.external_target || call.tail_candidate) continue;
        const auto node = nodes.find(call.source);
        if (node == nodes.end() || !node->second.fact) continue;
        const auto &instruction = node->second.fact->instruction;
        if (instruction.context.architecture != Architecture::wasm ||
            instruction.context.mode != ExecutionMode::wasm32 || instruction.flow != FlowKind::call ||
            instruction.mnemonic_override != "call_indirect" || instruction.operands.size() != 2)
            continue;
        const auto *required_type = std::get_if<ImmediateOperand>(&instruction.operands[0]);
        const auto *table_index = std::get_if<ImmediateOperand>(&instruction.operands[1]);
        if (!required_type || required_type->is_signed || required_type->effective_width != 32 ||
            required_type->value >= wasm.function_types.size() || !table_index || table_index->is_signed ||
            table_index->effective_width != 32 || table_index->value != 0)
            continue;
        if (ambiguous_ends.contains(call.source)) continue;
        const auto previous = instruction_ends.find(call.source);
        if (previous == instruction_ends.end()) continue;
        const auto &constant = previous->second->instruction;
        if (constant.address.space != call.source.space || constant.mnemonic_override != "i32.const" ||
            constant.operands.size() != 1)
            continue;
        const auto *slot_operand = std::get_if<ImmediateOperand>(&constant.operands.front());
        if (!slot_operand || !slot_operand->is_signed || slot_operand->effective_width != 32) continue;
        const auto slot = static_cast<std::uint32_t>(slot_operand->value);
        if (slot >= wasm.initial_table_element_count) continue;
        const auto element = table_elements.find(slot);
        if (element == table_elements.end()) continue;
        const auto function_index = element->second;
        if (wasm.function_type_indices[function_index] != required_type->value) continue;
        if (function_index < wasm.imported_functions) {
            const auto imported = std::find_if(wasm.imports.begin(), wasm.imports.end(), [&](const WasmImport &entry) {
                return entry.kind == WasmExternalKind::function && entry.index == function_index &&
                       entry.function_type_index == required_type->value;
            });
            if (imported == wasm.imports.end()) continue;
            ExternalIdentity identity;
            identity.library = imported->module;
            identity.name = imported->name;
            identity.wasm_function_index = function_index;
            identity.host_binding = imported->host_binding;
            call.external_target = std::move(identity);
            continue;
        }
        const Address target{AddressSpaceId{function_index}, 0};
        const auto *segment = image.segment_at(target);
        const auto context = image.context_at(target);
        if (!segment || segment->begin != target || !segment->executable || !segment->size ||
            segment->file_size != segment->size || !context || context.value().architecture != Architecture::wasm ||
            context.value().mode != ExecutionMode::wasm32)
            continue;
        const auto callee = functions.find(target);
        if (callee == functions.end()) continue;
        call.target = target;
        call.callee = callee->second->id;
    }
}
std::shared_ptr<const FunctionSnapshot> Recovery::run() {
    canceled();
    report_progress("instruction-discovery", 0, options.instruction_budget);
    require(analysis_detail::supports_automatic_flow(image),
            "Function recovery requires a supported processor mode");
    validate_decisions();
    seed_roots();
    discover();
    refine_a64_flow();
    find_conflicts();
    trusted_seeds();
    assign_owners();
    prune_unowned_seeds();
    resolve_wasm_indirect_calls();
    build_blocks(*this);
    finish_functions(*this);
    build_dependencies(*this);
    output->complete = output->complete && output->candidates.empty() && output->conflicts.empty() &&
                       output->omitted_functions == 0 && output->omitted_blocks == 0;
    for (const auto &function : output->functions)
        output->complete = output->complete && function->complete;
    report_progress("complete", 1, 1);
    canceled();
    return output;
}
} // namespace hexlab::function_detail
namespace hexlab {
namespace {
struct SemanticDecoderManifest {
    std::vector<std::byte> identity;
    std::vector<AnalysisOptions::SemanticDecoderInput> inputs;
};

std::optional<SemanticDecoderManifest> capture_semantic_decoder_manifest(const AnalysisOptions &options) noexcept {
    if (!options.semantic_decoder || !options.semantic_decoder_identity || !options.semantic_decoder_read_set)
        return {};
    try {
        SemanticDecoderManifest manifest{options.semantic_decoder_identity(), options.semantic_decoder_read_set()};
        if (manifest.identity.size() > 1024 * 1024 || manifest.inputs.size() > 4096)
            return {};
        std::sort(manifest.inputs.begin(), manifest.inputs.end(), [](const auto &a, const auto &b) {
            return a.identity < b.identity;
        });
        std::size_t total = 0;
        std::size_t total_ranges = 0;
        for (std::size_t i = 0; i < manifest.inputs.size(); ++i) {
            auto &input = manifest.inputs[i];
            const bool digest_missing = std::all_of(input.sha256.begin(), input.sha256.end(),
                                                    [](std::byte value) { return value == std::byte{}; });
            if (input.identity.empty() || input.identity.size() > 4096 ||
                input.identity.find('\0') != std::string::npos ||
                digest_missing ||
                input.identity.size() > 1024 * 1024 - total ||
                (i && manifest.inputs[i - 1].identity == input.identity))
                return {};
            total += input.identity.size();
            if (input.image_reads.size() > 65536 - total_ranges)
                return {};
            total_ranges += input.image_reads.size();
            ReadSet normalized;
            for (const auto &range : input.image_reads) {
                if (!range.size || !normalized.include(range.begin, range.size))
                    return {};
            }
            input.image_reads.assign(normalized.ranges().begin(), normalized.ranges().end());
        }
        return manifest;
    } catch (...) {
        return {};
    }
}
} // namespace

bool semantic_decoder_read_set_complete(const AnalysisOptions &options) noexcept {
    if (!options.semantic_decoder)
        return true;
    return capture_semantic_decoder_manifest(options).has_value();
}
std::vector<FileRange> semantic_decoder_image_read_ranges(const AnalysisOptions &options) noexcept {
    if (!options.semantic_decoder)
        return {};
    const auto manifest = capture_semantic_decoder_manifest(options);
    if (!manifest)
        return {};
    try {
        ReadSet reads;
        for (const auto &input : manifest->inputs)
            for (const auto &range : input.image_reads)
                if (!reads.include(range.begin, range.size))
                    return {};
        return {reads.ranges().begin(), reads.ranges().end()};
    } catch (...) {
        return {};
    }
}
bool semantic_decoder_image_reads_intersect(const AnalysisOptions &options,
                                             std::span<const FileRange> changed_ranges,
                                             std::uint64_t image_size) noexcept {
    if (!options.semantic_decoder)
        return false;
    const auto manifest = capture_semantic_decoder_manifest(options);
    if (!manifest)
        return true;
    try {
        ReadSet declared;
        for (const auto &input : manifest->inputs)
            for (const auto &range : input.image_reads) {
                if (range.begin.value > image_size || range.size > image_size - range.begin.value ||
                    !declared.include(range.begin, range.size))
                    return true;
            }
        ReadSet changed;
        for (const auto &range : changed_ranges) {
            if (!range.size || range.begin.value > image_size || range.size > image_size - range.begin.value ||
                !changed.include(range.begin, range.size))
                return true;
        }
        std::size_t read_index = 0, changed_index = 0;
        const auto reads = declared.ranges();
        const auto changes = changed.ranges();
        while (read_index < reads.size() && changed_index < changes.size()) {
            const auto &read = reads[read_index];
            const auto &change = changes[changed_index];
            const auto read_end = read.begin.value + read.size;
            const auto changed_end = change.begin.value + change.size;
            if (read.begin.value < changed_end && change.begin.value < read_end)
                return true;
            if (read_end <= change.begin.value)
                ++read_index;
            else
                ++changed_index;
        }
        return false;
    } catch (...) {
        return true;
    }
}
Sha256Digest function_engine_fingerprint(const AnalysisOptions &options) {
    Sha256 hash;
    constexpr std::string_view version =
        "hexlab-functions-v97-jvm-local-code-method-roots-v1/mips32-regimm-conditional-call-edges-v1/semantic-decoder-manifest-single-capture-v2/x64-rip-indirect-call-slot-target-v1/riscv64-lw-signed-pointer-load-v1/mips64-bitfield-relocation-guard-v1/m6502-vector-roots-v1/wasm-direct-call-edges-v1/wasm-constant-call-indirect-function-edges-v1/a64-add-sub-carry-v1/riscv-masked-integer-reductions-v1/dex-register-index-16-v1/x64-loop-counter-alias-v1/elf-et-exec-section-init-fini-array-roots-v1/elf-legacy-ctors-dtors-roots-v1/windows-x64-shadow-store-call-provenance-v1/mips32-gpr-conditional-moves-v1/ppc-popcntb-v1/ppc-addze-addme-lift-v1/x86-implicit-multiply-lift-v1/x86-bit-scan-lift-v1/x86-bit-test-lift-v1/x86-movemask-lift-v2/x86-palignr-fallthrough-v1/x86-ssse3-pabs-lift-v1/ppc64-rldic-reference-v1/ppc64-rldcl-rldcr-reference-v1/a64-extr-reference-v1/a64-madd-msub-reference-v1/a64-conditional-select-nzcv-v1/mips32-cop1-conditional-moves-v1/riscv-bitwise-stack-copies-v1/mips32-cop1-branch-likely-v1/mips64-eh-frame-roots-v1/pe-x86-fpo-roots-and-extents-v1/riscv-bitwise-immediate-addresses-v1/dex-method-roots-call-edges-v2/dex-relative-control-operands-v1/dex-payload-data-v1/riscv-vfrsqrt7-vfrec7-v1/a64-preserving-bitfield-v1/a64-ubfm-sbfm-address-reference-v1/a64-nzcv-constant-flow-v1/nonx86-reference-producer-graph-v1/dataflow-reference-producer-graph-v4/reference-immediate-origin-v1/x86-vdivps-vdivpd-vex-evex-mxcsr-effects-v1/mips64-arithmetic-reference-v1/mips64-shift-rotate-reference-v1/mips64-special-conditional-traps-v1/evex-packed-fp-broadcast-v1/wasm-br-table-12-case-v1/dex-switch-flow-v1/dex-exception-flow-v1/jvm-switch-flow-v2/jvm-exception-flow-v1/pe-guard-cf-function-roots-v1/pe-chpe-execution-ranges-v1/pe-amd64-chained-function-chunks-v1/runtime-initializer-roots-v1/runtime-initializer-array-roots-v2/initializer-source-relocation-provenance-v1/string-scan-work-budget-v1/mips64-delay-slot-ownership-v1/explicit-root-budget-priority-v1/arm-predicate-nzcv-reachability-v1/thumb-it-condition-edges-v1/arm-a32-predicate-thumb-it-flow-v4/zydis-opaque-stop-v1/multiarc-flow-v1/switch-cfg-targets-v4/guard-multiblock-v1/unicode-strings-v3/windows1253-1255-strings-v1/iso8859-10-13-14-16-strings-v1/x86-scalar-context-v5/elf-symbol-roots-v1/elf-symbol-extents-v1/operand-encoding-v1/elf-relocation-flow-v2/pe-pogo-function-roots-v1/elf-powerpc-eh-frame-roots-v1/macho-compact-unwind-extents-v1/ppc64-elfv1-opd-symbol-roots-v1/wasm-export-function-roots-v1/wasm-start-function-root-v1/wasm-element-function-roots-v1/wasm-all-defined-function-roots-v1/m6502-reference-producer-graph-v1/riscv64-lwu-pointer-load-v1/riscv-zbb-count-reference-v1/mips64-dclz-dclo-reference-v1/elf-dwarf-entrypoint-roots-v1"
        "mips64-word-shift-reference-v1/wasm-import-call-identities-v1/wasm-constant-call-indirect-reference-v1/"
        "elf-reference-provenance-v1/elf-arithmetic-v2/macho-symbol-roots-v1/macho-relocation-flow-v1/"
        "macho-reference-provenance-v1/macho-dyld-data-provenance-v1/macho-dyld-flow-v1/macho-export-roots-v1/macho-code-policy-v1/elf-unwind-personality-roots-v1/elf-unwind-roots-v1/macho-eh-frame-roots-v1/pe-tls-callback-roots-v1/pe-arm64-pdata-provenance-v1/mips64-cop1-condition-predicates-v1/riscv-v-vector-comparisons-v1/riscv-vfclass-vfsqrt-v1/x86-vex128-zero-upper-v1/powerpc-xform-logical-clz-signext-v1/x87-status-control-tag-effects-v1/pe-safe-seh-function-roots-v1/macho-mod-term-function-roots-v1/elf-dwarf-subprogram-roots-v1/thumb2-movw-movt-reference-v1/riscv-addiw-address-reference-v1/aapcs32-stack-argument-slots-v1/mips-o32-stack-argument-slots-v1/mips-n64-stack-argument-slots-v1/a64-32bit-pointer-load-references-v1/ebcdic-cp037-string-candidates-v1/mips64-special2-mul-address-reference-v1/ppc32-rlwinm-address-reference-v1/ppc64-rldimi-address-reference-v1/riscv-outgoing-stack-store-provenance-v1/thumb-tbb-aligned-pc-target-v1/mips64-word-rotr-address-reference-v1/native-import-slot-call-identities-v1/windows932-string-candidates-v1/m6502-decimal-stack-alias-guard-v1";
    (void)hash.update(std::as_bytes(std::span(version)));
    for (auto value : {options.min_string_characters, options.instruction_budget, options.string_budget,
                       options.string_scan_work_budget,
                       options.function_budget, options.block_budget, options.membership_budget})
        (void)hash.update(encode_u64(value));
    std::optional<SemanticDecoderManifest> decoder_manifest;
    if (options.semantic_decoder) {
        decoder_manifest = capture_semantic_decoder_manifest(options);
        if (decoder_manifest) {
            (void)hash.update(encode_u64(decoder_manifest->identity.size()));
            (void)hash.update(decoder_manifest->identity);
        } else {
            constexpr std::string_view failed_identity = "semantic-decoder-identity-unavailable";
            (void)hash.update(std::as_bytes(std::span(failed_identity)));
        }
    } else if (options.semantic_decoder_identity) {
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
    constexpr std::string_view read_set_domain = "semantic-decoder-external-read-set-v3";
    (void)hash.update(std::as_bytes(std::span(read_set_domain)));
    if (!options.semantic_decoder) {
        (void)hash.update(encode_u64(0));
    } else if (!decoder_manifest) {
        // A stable marker makes the fingerprint deterministic, while callers
        // separately prohibit cache/incremental reuse for this uncertified case.
        (void)hash.update(encode_u64(2));
    } else {
        try {
            (void)hash.update(encode_u64(1));
            (void)hash.update(encode_u64(decoder_manifest->inputs.size()));
            for (const auto &input : decoder_manifest->inputs) {
                (void)hash.update(encode_u64(input.identity.size()));
                (void)hash.update(std::as_bytes(std::span(input.identity)));
                (void)hash.update(input.sha256);
                (void)hash.update(encode_u64(input.image_reads.size()));
                for (const auto &range : input.image_reads) {
                    (void)hash.update(encode_u64(range.begin.value));
                    (void)hash.update(encode_u64(range.size));
                }
            }
        } catch (...) {
            (void)hash.update(encode_u64(2));
        }
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
        auto result = recovery.run();
        if (result->key && result->key->engine_fingerprint != function_engine_fingerprint(options))
            return Error{ErrorCode::conflict, "Semantic decoder set changed during function recovery"};
        return result;
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
