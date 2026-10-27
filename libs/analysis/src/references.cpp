#include "references_internal.hpp"
#include "control_target.hpp"
#include "mips64_reference_helpers.hpp"
#include "hexlab/analysis/relocations.hpp"
#include "hexlab/processors/arm32_semantics.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <deque>
#include <functional>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
namespace hexlab {
ReferenceIndex::LocationKey ReferenceIndex::location_key(Location location) noexcept {
    if (auto address = std::get_if<Address>(&location))
        return {0, address->space.value, address->offset};
    return {1, 0, std::get<FileOffset>(location).value};
}
Result<std::shared_ptr<const ReferenceIndex>> ReferenceIndex::create(std::vector<Reference> references,
                                                                     std::optional<AnalysisKey> key, bool complete,
                                                                     std::stop_token stop) {
    return reference_detail::guarded([&]() -> Result<std::shared_ptr<const ReferenceIndex>> {
        using namespace reference_detail;
        canceled(stop);
        require(references.size() <= reference_record_limit, "Reference count exceeds budget");
        std::map<uint64_t, size_t> identities;
        size_t text_bytes = 0;
        for (size_t i = 0; i < references.size(); ++i) {
            canceled(stop);
            auto &reference = references[i];
            validate_reference(reference);
            if (auto external = std::get_if<ExternalIdentity>(&reference.target)) {
                const auto size = external->library.size() + (external->name ? external->name->size() : 0);
                require(size <= reference_payload_limit - text_bytes, "Reference label bytes exceed budget");
                text_bytes += size;
            }
            if (reference.provenance.elf) {
                const auto size = elf_provenance_weight(*reference.provenance.elf);
                require(size <= reference_payload_limit - text_bytes, "Reference provenance bytes exceed budget");
                text_bytes += size;
            }
            const auto producer_bytes = reference.provenance.producer_instruction_ids.size() * sizeof(std::uint64_t);
            require(producer_bytes <= reference_payload_limit - text_bytes,
                    "Reference producer chains exceed payload budget");
            text_bytes += producer_bytes;
            const auto graph_bytes = reference.provenance.producer_graph.dependencies.size() *
                                     sizeof(ReferenceProducerDependency);
            require(graph_bytes <= reference_payload_limit - text_bytes,
                    "Reference producer graph exceeds payload budget");
            text_bytes += graph_bytes;
            const auto immediate_bytes = reference.provenance.producer_graph.immediates.size() *
                                         sizeof(ReferenceProducerImmediate);
            require(immediate_bytes <= reference_payload_limit - text_bytes,
                    "Reference producer immediates exceed payload budget");
            text_bytes += immediate_bytes;
            if (reference.provenance.elf_vtable) {
                const auto size = reference.provenance.elf_vtable->type_name
                                      ? reference.provenance.elf_vtable->type_name->size()
                                      : 0;
                require(size <= reference_payload_limit - text_bytes,
                        "ELF vtable provenance bytes exceed budget");
                text_bytes += size;
            }
            if (reference.provenance.macho) {
                const auto size = macho_provenance_weight(*reference.provenance.macho);
                require(size <= reference_payload_limit - text_bytes, "Mach-O provenance bytes exceed budget");
                text_bytes += size;
            }
            if (reference.provenance.dyld) {
                const auto size = dyld_provenance_weight(*reference.provenance.dyld);
                require(size <= reference_payload_limit - text_bytes, "Dyld reference provenance bytes exceed budget");
                text_bytes += size;
                // Freeze our own value after validation/budget checks: a caller
                // may retain a mutable alias behind a shared_ptr<const T>.
                reference.provenance.dyld =
                    std::make_shared<const MachODyldReferenceProvenance>(*reference.provenance.dyld);
            }
            const auto canonical = reference_key(reference);
            const auto digest = checked_hash(canonical, stop);
            auto id = take(decode_u64(std::span(digest).first(8)));
            if (!id)
                id = 1;
            require(reference.id.value == 0 || reference.id.value == id,
                    "Reference identity does not match its canonical content");
            reference.id = {id};
            auto [found, inserted] = identities.emplace(id, i);
            if (!inserted) {
                if (reference_key(references[found->second]) != canonical)
                    return Error{ErrorCode::conflict, "Stable reference ID collision"};
                return Error{ErrorCode::invalid_argument, "Duplicate reference identity"};
            }
        }
        std::sort(references.begin(), references.end(), [stop](const auto &a, const auto &b) {
            reference_detail::canceled(stop);
            return std::tuple{location_key(a.source), a.operand_index, a.kind, a.id} <
                   std::tuple{location_key(b.source), b.operand_index, b.kind, b.id};
        });
        auto index = std::shared_ptr<ReferenceIndex>(new ReferenceIndex);
        index->references_ = std::move(references);
        index->key_ = std::move(key);
        index->complete_ = complete;
        for (size_t i = 0; i < index->references_.size(); ++i) {
            canceled(stop);
            const auto &reference = index->references_[i];
            index->identities_.emplace(reference.id.value, i);
            index->outgoing_[location_key(reference.source)].push_back(i);
            const auto *numeric = std::get_if<Location>(&reference.target);
            if (numeric)
                index->incoming_[location_key(*numeric)].push_back(i);
            if (reference.association && (!numeric || *numeric != *reference.association))
                index->incoming_[location_key(*reference.association)].push_back(i);
            if (auto external = std::get_if<ExternalIdentity>(&reference.target))
                index->external_[external_key(*external)].push_back(i);
            if (reference.provenance.elf) {
                std::set<std::string> seen;
                for (const auto &origin : reference.provenance.elf->origins)
                    if (origin.relocation.symbol_table) {
                        const auto symbol =
                            elf_symbol_key({*origin.relocation.symbol_table, origin.relocation.symbol_index});
                        if (seen.insert(symbol).second)
                            index->elf_symbols_[symbol].push_back(i);
                    }
            }
            if (std::holds_alternative<UnresolvedTarget>(reference.target))
                ++index->unresolved_;
            if (reference.provenance.macho) {
                const auto &p = *reference.provenance.macho;
                std::set<std::string> seen;
                for (const auto &origin : p.origins)
                    if (origin.symbol_table && origin.relocation.symbol_index_validated) {
                        const auto symbol_identity_key = macho_symbol_key({p.context.slice_index,
                                                                           {p.context.slice_offset},
                                                                           origin.symbol_table->command_index,
                                                                           origin.symbol_table->symbol_offset,
                                                                           origin.relocation.symbol_number});
                        if (seen.insert(symbol_identity_key).second)
                            index->macho_symbols_[symbol_identity_key].push_back(i);
                    }
            }
        }
        return std::shared_ptr<const ReferenceIndex>(std::move(index));
    });
}
Result<ReferencePage> ReferenceIndex::page(const std::vector<size_t> *rows, PageRequest request) const {
    if (request.limit == 0 || request.limit > 4096)
        return Error{ErrorCode::invalid_argument, "Reference page size must be between 1 and 4096"};
    return reference_detail::guarded([&]() -> Result<ReferencePage> {
        ReferencePage page;
        page.total = rows ? rows->size() : 0;
        if (!rows || request.offset >= rows->size())
            return page;
        const auto begin = static_cast<size_t>(request.offset), count = std::min(request.limit, rows->size() - begin);
        page.rows.reserve(count);
        for (size_t i = 0; i < count; ++i)
            page.rows.push_back(references_[(*rows)[begin + i]]);
        if (begin + count < rows->size())
            page.next_offset = begin + count;
        return page;
    });
}
Result<ReferencePage> ReferenceIndex::incoming(Location location, PageRequest request) const {
    auto found = incoming_.find(location_key(location));
    return page(found == incoming_.end() ? nullptr : &found->second, request);
}
Result<ReferencePage> ReferenceIndex::outgoing(Location location, PageRequest request) const {
    auto found = outgoing_.find(location_key(location));
    return page(found == outgoing_.end() ? nullptr : &found->second, request);
}
std::span<const Reference> ReferenceIndex::outgoing_view(Location location) const noexcept {
    auto found = outgoing_.find(location_key(location));
    if (found == outgoing_.end() || found->second.empty())
        return {};
    return std::span(references_).subspan(found->second.front(), found->second.size());
}
Result<ReferencePage> ReferenceIndex::incoming_external(const ExternalIdentity &external, PageRequest request) const {
    return reference_detail::guarded([&]() -> Result<ReferencePage> {
        reference_detail::require(reference_detail::valid_external(external), "Invalid external identity query");
        auto found = external_.find(reference_detail::external_key(external));
        return page(found == external_.end() ? nullptr : &found->second, request);
    });
}
Result<ReferencePage> ReferenceIndex::incoming_elf_symbol(const ElfSymbolIdentity &symbol, PageRequest request) const {
    return reference_detail::guarded([&]() -> Result<ReferencePage> {
        const auto found = elf_symbols_.find(reference_detail::elf_symbol_key(symbol));
        return page(found == elf_symbols_.end() ? nullptr : &found->second, request);
    });
}
Result<ReferencePage> ReferenceIndex::incoming_macho_symbol(const MachOSymbolIdentity &symbol,
                                                            PageRequest request) const {
    return reference_detail::guarded([&]() -> Result<ReferencePage> {
        const auto found = macho_symbols_.find(reference_detail::macho_symbol_key(symbol));
        return page(found == macho_symbols_.end() ? nullptr : &found->second, request);
    });
}
Result<ReferenceProducerGraph> ReferenceIndex::producer_graph(ReferenceId id) const {
    return reference_detail::guarded([&]() -> Result<ReferenceProducerGraph> {
        const auto found = identities_.find(id.value);
        reference_detail::require(found != identities_.end(), "Unknown reference identity");
        return references_[found->second].provenance.producer_graph;
    });
}
namespace {
using ReferenceOperandKey = std::pair<std::uint64_t, std::uint32_t>;
struct RegisterReferenceFacts {
    std::map<ReferenceOperandKey, Address> immediate_targets;
    std::map<ReferenceOperandKey, ExecutionMode> target_modes;
    std::map<ReferenceOperandKey, Address> memory_targets;
    std::set<ReferenceOperandKey> relocation_pair_targets;
    std::set<std::uint64_t> address_definitions;
    std::map<ReferenceOperandKey, std::vector<std::uint64_t>> producer_instruction_ids;
    std::map<ReferenceOperandKey, ReferenceProducerGraph> producer_graphs;
};
struct RelocationCoverage;
std::optional<Address> static_m6502_indirect_target(const Image &, const RelocationCoverage &, Address);
std::optional<Address> dex_invoke_code_target(const Instruction &, const Image &, const ImageMetadata &);
RegisterReferenceFacts m6502_reference_facts(const Image *image, const RelocationCoverage &relocations,
                                              const FunctionSnapshot &functions, std::stop_token stop) {
    RegisterReferenceFacts result;
    if (!image)
        return result;
    for (const auto &fact : functions.instructions) {
        reference_detail::canceled(stop);
        if (!fact || fact->instruction.context.architecture != Architecture::mos6502 ||
            fact->instruction.context.mode != ExecutionMode::m6502 ||
            fact->instruction.opcode != Opcode::m6502_jmp || fact->instruction.operands.size() != 1)
            continue;
        const auto *pointer = std::get_if<MemoryOperand>(&fact->instruction.operands.front());
        if (!pointer || pointer->base || pointer->index || pointer->ip_relative || pointer->displacement < 0 ||
            pointer->displacement > UINT16_MAX)
            continue;
        const Address slot{fact->instruction.address.space,
                           static_cast<std::uint16_t>(pointer->displacement)};
        const auto target = static_m6502_indirect_target(*image, relocations, slot);
        if (!target)
            continue;
        result.memory_targets[{fact->id, 0}] = slot;
        result.immediate_targets[{fact->id, 0}] = *target;
    }
    return result;
}
std::optional<std::int64_t> riscv_signed_immediate(const Instruction &instruction, std::size_t index,
                                                    std::uint8_t width) {
    if (index >= instruction.operands.size()) return {};
    const auto *value = std::get_if<ImmediateOperand>(&instruction.operands[index]);
    if (!value || value->encoded_width != width || !value->is_signed) return {};
    return std::bit_cast<std::int64_t>(value->value);
}
const RegisterOperand *riscv_register(const Instruction &instruction, std::size_t index) {
    if (index >= instruction.operands.size()) return nullptr;
    const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[index]);
    return reg && reg->bank == RegisterBank::riscv_gpr && (reg->width == 32 || reg->width == 64) ? reg : nullptr;
}
std::uint64_t riscv_add(std::uint64_t base, std::int64_t displacement, std::uint8_t width) {
    const auto value = base + static_cast<std::uint64_t>(displacement);
    return width == 32 ? value & UINT64_C(0xffffffff) : value;
}
const Segment *riscv_target_segment(const Image &image, Address target, OperandAccess access,
                                   std::uint64_t access_width = 1) {
    const auto *segment = image.segment_at(target);
    if (!segment) return nullptr;
    const auto relative = target.offset - segment->begin.offset;
    if (!access_width || access_width > segment->size - relative) return nullptr;
    if ((access == OperandAccess::read || access == OperandAccess::read_write) && !segment->readable) return nullptr;
    if ((access == OperandAccess::write || access == OperandAccess::read_write) && !segment->writable) return nullptr;
    if (access == OperandAccess::address && !(segment->readable || segment->writable || segment->executable)) return nullptr;
    return segment;
}
struct RelocationCoverage {
    struct Range { std::uint64_t begin = 0, size = 0, prefix_end = 0; };
    std::map<std::uint64_t, std::vector<Range>> by_space;
    void add(Address place, std::uint64_t size) {
        if (size)
            by_space[place.space.value].push_back({place.offset, size, 0});
    }
    void add_unknown_width(Address place, const Image *image) {
        if (image) {
            if (const auto *segment = image->segment_at(place);
                segment && place.offset >= segment->begin.offset &&
                segment->size <= UINT64_MAX - segment->begin.offset) {
                const auto end = segment->begin.offset + segment->size;
                if (place.offset < end) {
                    add(place, end - place.offset);
                    return;
                }
            }
        }
        add(place, UINT64_MAX - place.offset);
    }
    void finalize() {
        for (auto &[space, ranges] : by_space) {
            (void)space;
            std::sort(ranges.begin(), ranges.end(), [](const Range &a, const Range &b) {
                return std::tie(a.begin, a.size) < std::tie(b.begin, b.size);
            });
            std::uint64_t prefix_end = 0;
            for (auto &range : ranges) {
                const auto end = range.size > UINT64_MAX - range.begin ? UINT64_MAX : range.begin + range.size;
                prefix_end = std::max(prefix_end, end);
                range.prefix_end = prefix_end;
            }
        }
    }
    bool overlaps(Address slot, std::uint64_t slot_size) const {
        const auto found = by_space.find(slot.space.value);
        if (found == by_space.end() || !slot_size)
            return false;
        const auto &ranges = found->second;
        const auto slot_end = slot_size > UINT64_MAX - slot.offset ? UINT64_MAX : slot.offset + slot_size;
        auto next = std::lower_bound(ranges.begin(), ranges.end(), slot.offset,
                                     [](const Range &range, std::uint64_t offset) { return range.begin < offset; });
        if (next != ranges.end() && next->begin < slot_end)
            return true;
        return next != ranges.begin() && std::prev(next)->prefix_end > slot.offset;
    }
};
RelocationCoverage relocation_coverage(const ImageMetadata &metadata, const Image *image, std::stop_token stop) {
    RelocationCoverage result;
    for (const auto &relocation : metadata.relocations) {
        reference_detail::canceled(stop);
        result.add(relocation.address, 8);
    }
    if (metadata.elf)
        for (const auto &relocation : metadata.elf->relocations) {
            reference_detail::canceled(stop);
            if (relocation.place) {
                if (relocation.field_size)
                    result.add(*relocation.place, *relocation.field_size);
                else
                    result.add_unknown_width(*relocation.place, image);
            }
        }
    if (metadata.macho) {
        for (const auto &relocation : metadata.macho->relocations) {
            reference_detail::canceled(stop);
            if (relocation.place) {
                if (relocation.field_size) result.add(*relocation.place, relocation.field_size);
                else result.add_unknown_width(*relocation.place, image);
            }
        }
        for (const auto &fixup : metadata.macho->dyld_fixups) {
            reference_detail::canceled(stop);
            if (fixup.place) {
                if (fixup.field_size) result.add(*fixup.place, fixup.field_size);
                else result.add_unknown_width(*fixup.place, image);
            }
        }
        for (const auto &pointer : metadata.macho->chained_pointers) {
            reference_detail::canceled(stop);
            if (pointer.place) {
                if (pointer.field_size) result.add(*pointer.place, pointer.field_size);
                else result.add_unknown_width(*pointer.place, image);
            }
        }
    }
    result.finalize();
    return result;
}
std::optional<Address> static_pointer_load(const Image &image, const RelocationCoverage &relocations,
                                           Address source, std::uint8_t pointer_width) {
    if (pointer_width != 32 && pointer_width != 64)
        return {};
    const auto *space = image.space(source.space);
    const auto *segment = image.segment_at(source);
    if (!space || !segment || !segment->readable || source.offset < segment->begin.offset)
        return {};
    const auto relative = source.offset - segment->begin.offset;
    const auto byte_width = static_cast<std::uint64_t>(pointer_width / 8);
    if (relative > segment->file_size || byte_width > segment->file_size - relative)
        return {};
    if (relocations.overlaps(source, byte_width))
        return {};
    const auto bytes = image.read(source, static_cast<std::size_t>(byte_width));
    if (!bytes || bytes.value().size() != byte_width)
        return {};
    std::uint64_t value = 0;
    if (space->order == ByteOrder::little) {
        for (std::size_t i = 0; i < bytes.value().size(); ++i)
            value |= std::uint64_t(std::to_integer<std::uint8_t>(bytes.value()[i])) << (i * 8);
    } else {
        for (const auto byte : bytes.value())
            value = (value << 8) | std::to_integer<std::uint8_t>(byte);
    }
    if (space->width_bits < pointer_width ||
        (space->width_bits < 64 && value >= (UINT64_C(1) << space->width_bits)))
        return {};
    const Address target{source.space, value};
    if (!riscv_target_segment(image, target, OperandAccess::address))
        return {};
    return target;
}
std::optional<Address> static_m6502_indirect_target(const Image &image, const RelocationCoverage &relocations,
                                                    Address pointer) {
    const auto *space = image.space(pointer.space);
    if (!space || space->width_bits != 16 || pointer.offset > UINT16_MAX)
        return {};
    // NMOS 6502 JMP ($xxFF) fetches the high byte from $xx00, due to the
    // original processor's page-boundary wrap bug.
    const Address high{pointer.space, (pointer.offset & UINT64_C(0xff00)) |
                                          ((pointer.offset + 1) & UINT64_C(0x00ff))};
    const auto read_byte = [&](Address at) -> std::optional<std::uint8_t> {
        const auto *segment = image.segment_at(at);
        if (!segment || !segment->readable || at.offset < segment->begin.offset ||
            relocations.overlaps(at, 1))
            return {};
        const auto relative = at.offset - segment->begin.offset;
        if (relative >= segment->file_size)
            return {};
        const auto bytes = image.read(at, 1);
        if (!bytes || bytes.value().size() != 1)
            return {};
        return std::to_integer<std::uint8_t>(bytes.value().front());
    };
    const auto low_byte = read_byte(pointer);
    const auto high_byte = read_byte(high);
    if (!low_byte || !high_byte)
        return {};
    const Address target{pointer.space, std::uint64_t(*low_byte) | (std::uint64_t(*high_byte) << 8)};
    const auto *segment = image.segment_at(target);
    if (!segment || !segment->executable || target.offset < segment->begin.offset ||
        target.offset - segment->begin.offset >= segment->size)
        return {};
    return target;
}
std::optional<Address> dex_invoke_code_target(const Instruction &instruction, const Image &image,
                                              const ImageMetadata &metadata) {
    if (instruction.context.architecture != Architecture::dex || instruction.flow != FlowKind::call ||
        !metadata.dex) return {};
    const auto bytes = instruction.encoded_bytes();
    if (bytes.size() < 4) return {};
    const auto opcode = std::to_integer<std::uint8_t>(bytes[0]);
    // The referenced method ID is an exact callee only for direct/static
    // invokes. Virtual/interface/super invokes require dispatch evidence.
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
bool mapped_data_range(const Image &image, Address target, OperandAccess access, std::uint64_t size) {
    const auto *space = image.space(target.space);
    if (!space || !size || target.offset > UINT64_MAX - size ||
        (space->width_bits < 64 && target.offset + size > (UINT64_C(1) << space->width_bits)))
        return false;
    auto cursor = target.offset;
    auto remaining = size;
    while (remaining) {
        const auto *segment = image.segment_at({target.space, cursor});
        if (!segment || (access == OperandAccess::read && !segment->readable) ||
            (access == OperandAccess::write && !segment->writable) ||
            (access == OperandAccess::read_write && (!segment->readable || !segment->writable)))
            return false;
        const auto relative = cursor - segment->begin.offset;
        const auto amount = std::min(remaining, segment->size - relative);
        if (!amount) return false;
        cursor += amount;
        remaining -= amount;
    }
    return true;
}
std::optional<Address> checked_ip_memory_target(const Instruction &instruction, const MemoryOperand &memory) {
    if (!memory.ip_relative || (instruction.context.architecture != Architecture::x86 &&
                                instruction.context.architecture != Architecture::x86_64))
        return memory.resolved_address;
    if (instruction.address.offset > UINT64_MAX - instruction.length) return {};
    const auto next = instruction.address.offset + instruction.length;
    std::uint64_t target = 0;
    if (memory.displacement < 0) {
        const auto magnitude = static_cast<std::uint64_t>(-(memory.displacement + 1)) + 1;
        if (next < magnitude) return {};
        target = next - magnitude;
    } else {
        const auto magnitude = static_cast<std::uint64_t>(memory.displacement);
        if (next > UINT64_MAX - magnitude) return {};
        target = next + magnitude;
    }
    if (memory.address_width < 64 && target >= (UINT64_C(1) << memory.address_width)) return {};
    return Address{instruction.address.space, target};
}
RegisterReferenceFacts riscv_reference_facts(const Image *, const ElfMetadata *, const RelocationCoverage &, const FunctionSnapshot &,
                                             std::stop_token);
const RegisterOperand *architecture_register(const Instruction &instruction, std::size_t index, RegisterBank bank,
                                             std::uint8_t width) {
    if (index >= instruction.operands.size())
        return nullptr;
    const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[index]);
    return reg && reg->bank == bank && reg->width == width ? reg : nullptr;
}
std::optional<std::uint64_t> immediate_value(const Instruction &instruction, std::size_t index) {
    if (index >= instruction.operands.size())
        return {};
    const auto *value = std::get_if<ImmediateOperand>(&instruction.operands[index]);
    return value ? std::optional<std::uint64_t>{value->value} : std::nullopt;
}
RegisterReferenceFacts x86_register_reference_facts(const Image *image, const RelocationCoverage &relocations,
                                                     const FunctionSnapshot &functions,
                                                     const RelocationResolver &resolver, std::stop_token stop) {
    RegisterReferenceFacts result;
    if (!image)
        return result;
    using RegisterState = std::unordered_map<std::uint32_t, std::uint64_t>;
    using ProducerState = std::unordered_map<std::uint32_t, std::vector<std::uint64_t>>;
    using ProducerTailState = std::unordered_map<std::uint32_t, std::vector<std::uint64_t>>;
    using MemoryKey = std::pair<std::uint32_t, std::uint64_t>;
    struct StoredPointer {
        std::uint64_t value = 0;
        std::uint8_t width = 0;
        std::vector<std::uint64_t> producers;
        std::vector<std::uint64_t> tails;
        bool ambiguous = false;
        bool operator==(const StoredPointer &) const = default;
    };
    struct DataflowState {
        RegisterState registers;
        ProducerState producers;
        ProducerTailState tails;
        std::unordered_set<std::uint32_t> ambiguous_tails;
        std::map<MemoryKey, StoredPointer> memory;
        // Image bytes are valid initial memory only until any path writes to
        // memory. At joins this bit is intersected, so a static read cannot
        // resurrect a value after a path-dependent store.
        bool image_memory_unchanged = true;
    };
    const auto x86_width = [](const Instruction &instruction) -> std::uint8_t {
        if (instruction.context.architecture == Architecture::x86_64 &&
            instruction.context.mode == ExecutionMode::x86_64)
            return 64;
        // The flat 32-bit model has a single address space and no hidden
        // segment-base contribution. Protected/real-mode segment addressing
        // remains deliberately unresolved here.
        if (instruction.context.architecture == Architecture::x86 &&
            instruction.context.mode == ExecutionMode::x86_32 && !instruction.context.segmented_memory)
            return 32;
        return 0;
    };
    const auto x86_register = [](const Instruction &instruction, std::size_t operand, std::uint8_t width) {
        return architecture_register(instruction, operand, RegisterBank::gpr, width);
    };
    const auto truncate = [](std::uint64_t value, std::uint8_t width) {
        return width == 32 ? value & UINT64_C(0xffffffff) : value;
    };
    const auto memory_address = [&](const Instruction &instruction, const MemoryOperand &memory,
                                    const RegisterState &registers, std::uint8_t width) -> std::optional<Address> {
        if (memory.segment || (memory.address_width != width && (memory.base || memory.index)))
            return {};
        if (memory.ip_relative)
            return checked_ip_memory_target(instruction, memory);
        if (!memory.base && !memory.index)
            return memory.resolved_address;
        std::uint64_t result = 0;
        bool has_term = false;
        if (memory.base) {
            if (memory.base->bank != RegisterBank::gpr || memory.base->width != width)
                return {};
            const auto found = registers.find(memory.base->index);
            if (found == registers.end())
                return {};
            result = found->second;
            has_term = true;
        }
        if (memory.index) {
            if (memory.index->bank != RegisterBank::gpr || memory.index->width != width)
                return {};
            const auto found = registers.find(memory.index->index);
            if (found == registers.end())
                return {};
            const auto scale = std::max<std::uint8_t>(1, memory.scale);
            result += found->second * scale;
            has_term = true;
        }
        if (!has_term)
            return memory.resolved_address;
        return Address{instruction.address.space,
                       truncate(result + static_cast<std::uint64_t>(memory.displacement), width)};
    };
    const auto read_word = [&](Address address, std::uint8_t width) -> std::optional<std::uint64_t> {
        const auto bytes_count = static_cast<std::uint64_t>(width / 8);
        if (riscv_target_segment(*image, address, OperandAccess::read, bytes_count) == nullptr)
            return {};
        auto bytes = image->read(address, bytes_count);
        if (!bytes)
            return {};
        const auto *space = image->space(address.space);
        if (!space)
            return {};
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < bytes.value().size(); ++i) {
            const auto shift = space->order == ByteOrder::little ? i * 8 : (bytes.value().size() - 1 - i) * 8;
            value |= std::uint64_t(std::to_integer<unsigned>(bytes.value()[i])) << shift;
        }
        return value;
    };
    const auto pointer_value = [&](Address address, std::uint8_t width, const DataflowState &state)
        -> std::optional<std::uint64_t> {
        const MemoryKey key{address.space.value, address.offset};
        const auto byte_width = static_cast<std::uint8_t>(width / 8);
        if (address.offset > UINT64_MAX - byte_width)
            return {};
        if (const auto found = state.memory.find(key); found != state.memory.end()) {
            if (found->second.width == width)
                return found->second.value;
            return {};
        }
        const auto this_end = address.offset + byte_width;
        const auto next = state.memory.lower_bound(key);
        if (next != state.memory.end() && next->first.first == key.first && next->first.second < this_end)
            return {};
        if (next != state.memory.begin()) {
            const auto previous = std::prev(next);
            const auto previous_width = static_cast<std::uint64_t>(previous->second.width / 8);
            if (previous->first.first == key.first && previous->first.second <= UINT64_MAX - previous_width &&
                previous->first.second + previous_width > address.offset)
                return {};
        }
        if (!state.image_memory_unchanged)
            return {};
        if (relocations.overlaps(address, byte_width))
            return {};
        return read_word(address, width);
    };
    const auto append_producers = [](std::vector<std::uint64_t> &target,
                                     const std::vector<std::uint64_t> &source, std::size_t limit) {
        for (const auto producer : source)
            if (std::find(target.begin(), target.end(), producer) == target.end() && target.size() < limit)
                target.push_back(producer);
    };
    constexpr std::size_t max_producer_parent_nodes = 65536;
    constexpr std::size_t max_producer_parent_edges = 262144;
    std::map<std::uint64_t, std::vector<std::uint64_t>> producer_parent_ids;
    std::size_t producer_parent_edge_count = 0;
    bool producer_parent_budget_exhausted = false;
    struct GraphRoot { std::uint64_t instruction = 0; std::vector<std::uint64_t> parents; bool ambiguous = false; };
    std::map<ReferenceOperandKey, GraphRoot> graph_roots;
    const auto record_producer_parents = [&](std::uint64_t instruction, const std::vector<std::uint64_t> &parents) {
        if (parents.empty()) return;
        auto found = producer_parent_ids.find(instruction);
        if (found == producer_parent_ids.end()) {
            if (producer_parent_ids.size() >= max_producer_parent_nodes) {
                producer_parent_budget_exhausted = true;
                return;
            }
            found = producer_parent_ids.emplace(instruction, std::vector<std::uint64_t>{}).first;
        }
        auto &stored = found->second;
        for (const auto parent : parents) {
            if (!parent || std::find(stored.begin(), stored.end(), parent) != stored.end()) continue;
            if (stored.size() >= 32 || producer_parent_edge_count >= max_producer_parent_edges) {
                producer_parent_budget_exhausted = true;
                continue;
            }
            stored.push_back(parent);
            ++producer_parent_edge_count;
        }
    };
    const auto add_register_tails = [](const DataflowState &state, const std::optional<RegisterOperand> &reg,
                                       std::vector<std::uint64_t> &target, bool &ambiguous) {
        if (!reg) return;
        if (const auto found = state.tails.find(reg->index); found != state.tails.end())
            for (const auto id : found->second)
                if (id && std::find(target.begin(), target.end(), id) == target.end() && target.size() < 32)
                    target.push_back(id);
        ambiguous = ambiguous || state.ambiguous_tails.contains(reg->index);
    };
    const auto record_graph_root = [&](ReferenceOperandKey key, std::uint64_t instruction,
                                       std::vector<std::uint64_t> parents, bool ambiguous) {
        if (!parents.empty()) graph_roots[key] = {instruction, std::move(parents), ambiguous};
    };
    std::map<BlockId, const BasicBlock *> blocks;
    std::map<BlockId, std::set<BlockId>> predecessors;
    std::set<BlockId> entries;
    for (const auto &block : functions.blocks)
        if (block)
            blocks.emplace(block->id, block.get());
    for (const auto &[id, block] : blocks) {
        reference_detail::canceled(stop);
        for (const auto &successor : block->successors)
            if (successor.block && blocks.contains(*successor.block))
                predecessors[*successor.block].insert(id);
    }
    for (const auto &function : functions.functions) {
        if (!function)
            continue;
        for (const auto &id : function->blocks) {
            const auto block = blocks.find(id);
            if (block != blocks.end() && block->second->begin == function->entry)
                entries.insert(id);
        }
    }
    std::map<BlockId, DataflowState> outputs;
    std::set<BlockId> pending;
    for (const auto &[id, block] : blocks) {
        (void)block;
        pending.insert(id);
    }
    constexpr std::size_t max_tracked_memory_slots = 1024;
    constexpr std::size_t max_total_memory_facts = 65536;
    bool memory_budget_exhausted = false;
    const auto process_block = [&](const BasicBlock &block, DataflowState state) {
        for (const auto &fact : block.instructions) {
            reference_detail::canceled(stop);
            if (!fact)
                continue;
            if (memory_budget_exhausted) {
                state.memory.clear();
                state.image_memory_unchanged = false;
            }
            const auto &instruction = fact->instruction;
            auto &registers = state.registers;
            const auto width = x86_width(instruction);
            if (!width) {
                registers.clear();
                state.producers.clear();
                state.tails.clear();
                state.ambiguous_tails.clear();
                state.memory.clear();
                state.image_memory_unchanged = false;
                continue;
            }
            const auto control_index = analysis_detail::control_operand_index(instruction);
            if (instruction.flow == FlowKind::call || instruction.flow == FlowKind::jump) {
                if (const auto *reg = x86_register(instruction, control_index, width)) {
                    const auto known = registers.find(reg->index);
                    if (known != registers.end()) {
                        const Address target{instruction.address.space, truncate(known->second, width)};
                        const auto *segment = image->segment_at(target);
                        if (segment && segment->executable) {
                            const ReferenceOperandKey key{fact->id, static_cast<std::uint32_t>(control_index)};
                            result.immediate_targets[key] = target;
                            if (const auto producer = state.producers.find(reg->index);
                                producer != state.producers.end())
                                result.producer_instruction_ids[key] = producer->second;
                            std::vector<std::uint64_t> tails;
                            bool ambiguous = false;
                            add_register_tails(state, std::optional<RegisterOperand>{*reg}, tails, ambiguous);
                            record_graph_root(key, fact->id, std::move(tails), ambiguous);
                        }
                    }
                } else if (control_index < instruction.operands.size()) {
                    if (const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[control_index])) {
                        const auto resolution = reference_detail::take(
                            resolver.operand(instruction, static_cast<std::uint32_t>(control_index), stop));
                        if (memory->data_width == width && !resolution.relocated()) {
                            const auto slot = memory_address(instruction, *memory, registers, width);
                            if (slot) {
                                const auto pointer = pointer_value(*slot, width, state);
                                if (pointer) {
                                    const Address target{instruction.address.space, truncate(*pointer, width)};
                                    const auto *segment = image->segment_at(target);
                                    if (segment && segment->executable) {
                                        const ReferenceOperandKey key{fact->id, static_cast<std::uint32_t>(control_index)};
                                        result.immediate_targets[key] = target;
                                        std::vector<std::uint64_t> producers;
                                        if (memory->base)
                                            if (const auto found = state.producers.find(memory->base->index);
                                                found != state.producers.end())
                                                append_producers(producers, found->second, 32);
                                        if (memory->index)
                                            if (const auto found = state.producers.find(memory->index->index);
                                                found != state.producers.end())
                                                append_producers(producers, found->second, 32);
                                        if (const auto stored = state.memory.find({slot->space.value, slot->offset});
                                            stored != state.memory.end() && stored->second.width == width)
                                            append_producers(producers, stored->second.producers, 32);
                                        if (!producers.empty())
                                            result.producer_instruction_ids[key] = std::move(producers);
                                        std::vector<std::uint64_t> tails;
                                        bool ambiguous = false;
                                        add_register_tails(state, memory->base, tails, ambiguous);
                                        add_register_tails(state, memory->index, tails, ambiguous);
                                        if (const auto stored = state.memory.find({slot->space.value, slot->offset});
                                            stored != state.memory.end() && stored->second.width == width) {
                                            append_producers(tails, stored->second.tails, 32);
                                            ambiguous = ambiguous || stored->second.ambiguous;
                                        }
                                        record_graph_root(key, fact->id, std::move(tails), ambiguous);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            for (std::size_t index = 0; index < instruction.operands.size() && index < instruction.access.size(); ++index) {
                const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[index]);
                if (!memory)
                    continue;
                const auto address = memory_address(instruction, *memory, registers, width);
                if (!address)
                    continue;
                const auto access = instruction.access[index];
                const auto access_bytes = std::max<std::uint64_t>(1, (memory->data_width + 7) / 8);
                if (mapped_data_range(*image, *address, access, access_bytes))
                {
                    const ReferenceOperandKey key{fact->id, static_cast<std::uint32_t>(index)};
                    result.memory_targets[key] = *address;
                    std::vector<std::uint64_t> producers;
                    const auto add_register_chain = [&](const std::optional<RegisterOperand> &reg) {
                        if (!reg) return;
                        if (const auto found = state.producers.find(reg->index); found != state.producers.end())
                            for (const auto producer : found->second)
                                if (std::find(producers.begin(), producers.end(), producer) == producers.end() &&
                                    producers.size() < 32)
                                    producers.push_back(producer);
                    };
                    add_register_chain(memory->base);
                    add_register_chain(memory->index);
                    if (!producers.empty()) result.producer_instruction_ids[key] = std::move(producers);
                    std::vector<std::uint64_t> tails;
                    bool ambiguous = false;
                    add_register_tails(state, memory->base, tails, ambiguous);
                    add_register_tails(state, memory->index, tails, ambiguous);
                    record_graph_root(key, fact->id, std::move(tails), ambiguous);
                }
            }

            std::optional<std::pair<std::uint32_t, std::uint64_t>> definition;
            if (instruction.opcode == Opcode::mov && instruction.operands.size() == 2) {
                const auto *destination = x86_register(instruction, 0, width);
                if (destination) {
                    std::optional<std::uint64_t> value;
                    if (const auto *source = x86_register(instruction, 1, width)) {
                        const auto found = registers.find(source->index);
                        if (found != registers.end())
                            value = found->second;
                    } else if (const auto *immediate =
                                   std::get_if<ImmediateOperand>(&instruction.operands[1]);
                               immediate && immediate->effective_width == width &&
                               (width == 32 || immediate->encoded_width == 64 ||
                                (immediate->encoded_width == 32 && immediate->is_signed))) {
                        value = truncate(immediate->value, width);
                    } else if (const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
                               memory && memory->data_width == width) {
                        const auto resolution = reference_detail::take(resolver.operand(instruction, 1, stop));
                        if (!resolution.relocated())
                            if (const auto slot = memory_address(instruction, *memory, registers, width))
                                value = pointer_value(*slot, width, state);
                    }
                    if (value)
                        definition = std::pair{destination->index, *value};
                }
            } else if (instruction.opcode == Opcode::lea && instruction.operands.size() == 2) {
                const auto *destination = x86_register(instruction, 0, width);
                const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
                const auto address = memory ? memory_address(instruction, *memory, registers, width) : std::nullopt;
                if (destination && address)
                    definition = std::pair{destination->index, address->offset};
            } else if ((instruction.opcode == Opcode::add || instruction.opcode == Opcode::sub) &&
                       instruction.operands.size() == 2) {
                const auto *destination = x86_register(instruction, 0, width);
                std::optional<std::uint64_t> base;
                if (destination) {
                    const auto found = registers.find(destination->index);
                    if (found != registers.end())
                        base = found->second;
                }
                std::optional<std::uint64_t> value;
                if (base) {
                    if (const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[1]);
                        immediate && immediate->effective_width == width) {
                        const auto displacement = std::bit_cast<std::int64_t>(immediate->value);
                        if (instruction.opcode == Opcode::add) {
                            value = truncate(*base + static_cast<std::uint64_t>(displacement), width);
                        } else
                            value = truncate(*base - static_cast<std::uint64_t>(displacement), width);
                    } else if (const auto *source = x86_register(instruction, 1, width)) {
                        const auto found = registers.find(source->index);
                        if (found != registers.end())
                            value = truncate(instruction.opcode == Opcode::add ? *base + found->second
                                                                               : *base - found->second,
                                             width);
                    }
                }
                if (destination && value)
                    definition = std::pair{destination->index, *value};
            } else if ((instruction.opcode == Opcode::movzx || instruction.opcode == Opcode::movsx ||
                        instruction.opcode == Opcode::movsxd) && instruction.operands.size() == 2) {
                const auto *destination = x86_register(instruction, 0, width);
                const auto *source = std::get_if<RegisterOperand>(&instruction.operands[1]);
                if (destination && source && source->bank == RegisterBank::gpr && source->width > 0 &&
                    source->width < width) {
                    const auto found = registers.find(source->index);
                    if (found != registers.end()) {
                        const auto mask = source->width == 64 ? UINT64_MAX
                                                              : ((UINT64_C(1) << source->width) - 1);
                        const auto source_bits = source->high_byte ? found->second >> 8 : found->second;
                        auto value = source_bits & mask;
                        if (instruction.opcode != Opcode::movzx &&
                            (value & (UINT64_C(1) << (source->width - 1))))
                            value |= ~mask;
                        definition = std::pair{destination->index, truncate(value, width)};
                    }
                }
            }

            // In long mode, writes to a 32-bit GPR zero-extend into its
            // 64-bit parent. The main transfer above intentionally models
            // only full pointer-width operands, so handle these well-defined
            // aliases explicitly. This is common for compiler-generated
            // address materialization such as `mov eax, imm32` or `lea eax`.
            if (!definition && instruction.context.architecture == Architecture::x86_64 &&
                instruction.context.mode == ExecutionMode::x86_64 && width == 64 &&
                instruction.operands.size() >= 2) {
                const auto *destination = architecture_register(instruction, 0, RegisterBank::gpr, 32);
                if (destination) {
                    const auto low32 = [](std::uint64_t value) { return value & UINT64_C(0xffffffff); };
                    std::optional<std::uint64_t> value;
                    if (instruction.opcode == Opcode::mov) {
                        if (const auto *source = architecture_register(instruction, 1, RegisterBank::gpr, 32)) {
                            if (const auto found = registers.find(source->index); found != registers.end())
                                value = low32(found->second);
                        } else if (const auto *immediate =
                                       std::get_if<ImmediateOperand>(&instruction.operands[1]);
                                   immediate && immediate->effective_width == 32) {
                            value = low32(immediate->value);
                        } else if (const auto *memory =
                                       std::get_if<MemoryOperand>(&instruction.operands[1]);
                                   memory && memory->data_width == 32 &&
                                   !reference_detail::take(
                                       resolver.operand(instruction, 1, stop)).relocated()) {
                            if (const auto slot = memory_address(instruction, *memory, registers, width))
                                if (const auto loaded = pointer_value(*slot, 32, state))
                                    value = low32(*loaded);
                        }
                    } else if (instruction.opcode == Opcode::lea) {
                        if (const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]))
                            if (const auto address = memory_address(instruction, *memory, registers, width))
                                value = low32(address->offset);
                    } else if (instruction.opcode == Opcode::add || instruction.opcode == Opcode::sub) {
                        if (const auto found = registers.find(destination->index); found != registers.end()) {
                            const auto base = low32(found->second);
                            if (const auto *immediate =
                                    std::get_if<ImmediateOperand>(&instruction.operands[1]);
                                immediate && immediate->effective_width == 32) {
                                const auto displacement = static_cast<std::uint32_t>(immediate->value);
                                value = instruction.opcode == Opcode::add ? low32(base + displacement)
                                                                          : low32(base - displacement);
                            } else if (const auto *source =
                                           architecture_register(instruction, 1, RegisterBank::gpr, 32)) {
                                if (const auto source_value = registers.find(source->index);
                                    source_value != registers.end()) {
                                    value = instruction.opcode == Opcode::add
                                                ? low32(base + low32(source_value->second))
                                                : low32(base - low32(source_value->second));
                                }
                            }
                        }
                    } else if (instruction.opcode == Opcode::movzx || instruction.opcode == Opcode::movsx ||
                               instruction.opcode == Opcode::movsxd) {
                        const auto *source = std::get_if<RegisterOperand>(&instruction.operands[1]);
                        if (source && source->bank == RegisterBank::gpr && source->width > 0 && source->width < 32) {
                            if (const auto found = registers.find(source->index); found != registers.end()) {
                                const auto mask = (UINT64_C(1) << source->width) - 1;
                                const auto source_bits = source->high_byte ? found->second >> 8 : found->second;
                                auto extended = source_bits & mask;
                                if (instruction.opcode != Opcode::movzx &&
                                    (extended & (UINT64_C(1) << (source->width - 1))))
                                    extended |= ~mask;
                                value = low32(extended);
                            }
                        }
                    } else if ((instruction.opcode == Opcode::bit_xor || instruction.opcode == Opcode::sub) &&
                               architecture_register(instruction, 1, RegisterBank::gpr, 32) &&
                               architecture_register(instruction, 1, RegisterBank::gpr, 32)->index ==
                                   destination->index) {
                        value = 0;
                    }
                    if (value)
                        definition = std::pair{destination->index, low32(*value)};
                }
            }

            // Preserve only full pointer-width values stored to a resolved,
            // writable image slot. All other writes invalidate overlapping
            // facts; an unknown write invalidates the whole abstract memory.
            std::optional<std::pair<Address, StoredPointer>> stored_pointer;
            bool explicit_memory_write = false;
            for (std::size_t index = 0; index < instruction.operands.size() && index < instruction.access.size(); ++index) {
                if (instruction.access[index] != OperandAccess::write &&
                    instruction.access[index] != OperandAccess::read_write)
                    continue;
                const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[index]);
                if (!memory)
                    continue;
                explicit_memory_write = true;
                state.image_memory_unchanged = false;
                const auto address = memory_address(instruction, *memory, registers, width);
                if (!address) {
                    state.memory.clear();
                    continue;
                }
                const auto written_bytes = std::max<std::uint64_t>(1, (memory->data_width + 7) / 8);
                if (address->offset > UINT64_MAX - written_bytes) {
                    state.memory.clear();
                    continue;
                }
                const auto write_end = address->offset + written_bytes;
                for (auto stored = state.memory.begin(); stored != state.memory.end();) {
                    const auto fact_bytes = static_cast<std::uint64_t>(stored->second.width / 8);
                    const auto fact_end = stored->first.second <= UINT64_MAX - fact_bytes
                                              ? stored->first.second + fact_bytes : UINT64_MAX;
                    if (stored->first.first == address->space.value && address->offset < fact_end &&
                        stored->first.second < write_end)
                        stored = state.memory.erase(stored);
                    else
                        ++stored;
                }
                if (index != 0 || memory->data_width != width || written_bytes != width / 8 ||
                    !mapped_data_range(*image, *address, OperandAccess::write, written_bytes))
                    continue;
                const auto resolution = reference_detail::take(
                    resolver.operand(instruction, static_cast<std::uint32_t>(index), stop));
                if (resolution.relocated())
                    continue;
                std::optional<std::uint64_t> stored;
                std::vector<std::uint64_t> stored_producers;
                std::vector<std::uint64_t> stored_parents;
                bool stored_ambiguous = false;
                add_register_tails(state, memory->base, stored_parents, stored_ambiguous);
                add_register_tails(state, memory->index, stored_parents, stored_ambiguous);
                if (instruction.opcode == Opcode::mov && instruction.operands.size() == 2) {
                    if (const auto *source = x86_register(instruction, 1, width)) {
                        if (const auto found = registers.find(source->index); found != registers.end())
                            stored = found->second;
                        if (const auto found = state.producers.find(source->index); found != state.producers.end())
                            append_producers(stored_producers, found->second, 31);
                        add_register_tails(state, std::optional<RegisterOperand>{*source}, stored_parents,
                                           stored_ambiguous);
                    } else if (const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[1]);
                               immediate && immediate->effective_width == width &&
                               (width == 32 || immediate->encoded_width == 64 ||
                                (immediate->encoded_width == 32 && immediate->is_signed))) {
                        stored = truncate(immediate->value, width);
                    }
                }
                if (stored) {
                    record_producer_parents(fact->id, stored_parents);
                    if (std::find(stored_producers.begin(), stored_producers.end(), fact->id) == stored_producers.end())
                        stored_producers.push_back(fact->id);
                    stored_pointer = std::pair{
                        *address, StoredPointer{truncate(*stored, width), width, std::move(stored_producers),
                                                {fact->id}, stored_ambiguous}};
                }
            }
            if (instruction.memory_write && !explicit_memory_write) {
                // String and implicit-stack operations can write without an
                // addressable MemoryOperand. Their aliases are not modeled.
                state.memory.clear();
                state.image_memory_unchanged = false;
            }
            if (instruction.memory_write && instruction.x86_repeat != X86RepeatPrefix::none) {
                // A repeated store can cover a runtime-counted range, not just
                // the single element represented by its MemoryOperand.
                state.memory.clear();
                state.image_memory_unchanged = false;
            }
            std::vector<std::uint64_t> definition_producers;
            std::vector<std::uint64_t> definition_parents;
            bool definition_ambiguous = false;
            if (definition) {
                const auto add_source_chain = [&](std::size_t operand_index) {
                    if (operand_index >= instruction.operands.size()) return;
                    const auto *source = std::get_if<RegisterOperand>(&instruction.operands[operand_index]);
                    if (!source || source->bank != RegisterBank::gpr) return;
                    if (const auto found = state.producers.find(source->index); found != state.producers.end())
                        for (const auto producer : found->second)
                            if (std::find(definition_producers.begin(), definition_producers.end(), producer) ==
                                    definition_producers.end() && definition_producers.size() < 31)
                                definition_producers.push_back(producer);
                    add_register_tails(state, std::optional<RegisterOperand>{*source}, definition_parents,
                                       definition_ambiguous);
                };
                const auto add_address_chain = [&](std::size_t operand_index) {
                    if (operand_index >= instruction.operands.size()) return;
                    if (const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[operand_index])) {
                        for (const auto *reg : {memory->base ? &*memory->base : nullptr,
                                                memory->index ? &*memory->index : nullptr})
                            if (reg)
                                if (const auto found = state.producers.find(reg->index); found != state.producers.end())
                                    for (const auto producer : found->second)
                                        if (std::find(definition_producers.begin(), definition_producers.end(), producer) ==
                                                definition_producers.end() && definition_producers.size() < 31)
                                            definition_producers.push_back(producer);
                        for (const auto *reg : {memory->base ? &*memory->base : nullptr,
                                                memory->index ? &*memory->index : nullptr})
                            if (reg)
                                add_register_tails(state, std::optional<RegisterOperand>{*reg}, definition_parents,
                                                   definition_ambiguous);
                    }
                };
                const auto add_memory_value_chain = [&](std::size_t operand_index) {
                    if (operand_index >= instruction.operands.size()) return;
                    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[operand_index]);
                    if (!memory || memory->data_width != width ||
                        reference_detail::take(resolver.operand(instruction,
                            static_cast<std::uint32_t>(operand_index), stop)).relocated()) return;
                    const auto slot = memory_address(instruction, *memory, registers, width);
                    if (!slot) return;
                    const auto stored = state.memory.find({slot->space.value, slot->offset});
                    if (stored != state.memory.end() && stored->second.width == width)
                        append_producers(definition_producers, stored->second.producers, 31);
                    if (stored != state.memory.end() && stored->second.width == width) {
                        append_producers(definition_parents, stored->second.tails, 32);
                        definition_ambiguous = definition_ambiguous || stored->second.ambiguous;
                    }
                };
                if (instruction.opcode == Opcode::mov || instruction.opcode == Opcode::movzx ||
                    instruction.opcode == Opcode::movsx || instruction.opcode == Opcode::movsxd) {
                    add_source_chain(1);
                    add_address_chain(1);
                    if (instruction.opcode == Opcode::mov) add_memory_value_chain(1);
                } else if (instruction.opcode == Opcode::lea) add_address_chain(1);
                else if (instruction.opcode == Opcode::add || instruction.opcode == Opcode::sub) {
                    add_source_chain(0);
                    add_source_chain(1);
                }
                if (std::find(definition_producers.begin(), definition_producers.end(), fact->id) ==
                        definition_producers.end() && definition_producers.size() < 32)
                    definition_producers.push_back(fact->id);
                record_producer_parents(fact->id, definition_parents);
            }
            for (const auto &written : instruction.register_writes)
                if (written.bank == RegisterBank::gpr) {
                    registers.erase(written.index);
                    state.producers.erase(written.index);
                    state.tails.erase(written.index);
                    state.ambiguous_tails.erase(written.index);
                }
            if (instruction.flow == FlowKind::call) {
                // An unknown callee may write any global memory even when its
                // register clobbers are ABI-bounded.
                state.memory.clear();
                state.image_memory_unchanged = false;
            }
            if (instruction.flow == FlowKind::call && width == 32) {
                // The active 32-bit ABI is not known from the instruction
                // stream alone, so conservatively discard all tracked values.
                registers.clear();
                state.producers.clear();
                state.tails.clear();
                state.ambiguous_tails.clear();
            } else if (instruction.flow == FlowKind::call) {
                // System V and Windows x64 both permit callees to clobber
                // these integer registers. Keep only values protected by the
                // shared callee-saved set, rather than carrying stale targets
                // across an unknown call.
                for (const auto index : {0u, 1u, 2u, 6u, 7u, 8u, 9u, 10u, 11u})
                {
                    registers.erase(index);
                    state.producers.erase(index);
                    state.tails.erase(index);
                    state.ambiguous_tails.erase(index);
                }
            }
            if (definition) {
                registers[definition->first] = definition->second;
                state.producers[definition->first] = std::move(definition_producers);
                state.tails[definition->first] = {fact->id};
                if (definition_ambiguous) state.ambiguous_tails.insert(definition->first);
                else state.ambiguous_tails.erase(definition->first);
            }
            if (stored_pointer && !memory_budget_exhausted)
                state.memory[{stored_pointer->first.space.value, stored_pointer->first.offset}] = stored_pointer->second;
            if (state.memory.size() > max_tracked_memory_slots) {
                state.memory.clear();
                state.image_memory_unchanged = false;
            }
        }
        return state;
    };
    std::size_t total_memory_facts = 0;
    while (!pending.empty()) {
        reference_detail::canceled(stop);
        bool progress = false;
        for (auto current = pending.begin(); current != pending.end();) {
            const auto id = *current;
            const auto *block = blocks.at(id);
            const auto found_predecessors = predecessors.find(id);
            const bool has_predecessors = found_predecessors != predecessors.end() &&
                                          !found_predecessors->second.empty();
            DataflowState incoming;
            bool ready = !has_predecessors;
            if (!has_predecessors && !entries.contains(id))
                incoming.image_memory_unchanged = false;
            if (has_predecessors) {
                ready = std::all_of(found_predecessors->second.begin(), found_predecessors->second.end(),
                                    [&](BlockId predecessor) { return outputs.contains(predecessor); });
                if (ready) {
                    // A function-entry block has an implicit path with no
                    // incoming register facts. Include that seed in the
                    // predecessor intersection so a loop edge cannot make a
                    // value appear definitely initialized on first entry.
                    bool first = !entries.contains(id);
                    for (const auto predecessor : found_predecessors->second) {
                        const auto &state = outputs.at(predecessor);
                        if (first) {
                            incoming = state;
                            first = false;
                            continue;
                        }
                        for (auto value = incoming.registers.begin(); value != incoming.registers.end();) {
                            const auto matching = state.registers.find(value->first);
                            if (matching == state.registers.end() || matching->second != value->second) {
                                incoming.producers.erase(value->first);
                                incoming.tails.erase(value->first);
                                incoming.ambiguous_tails.erase(value->first);
                                value = incoming.registers.erase(value);
                            } else {
                                auto &chain = incoming.producers[value->first];
                                if (const auto other = state.producers.find(value->first); other != state.producers.end())
                                    for (const auto producer : other->second)
                                        if (std::find(chain.begin(), chain.end(), producer) == chain.end() &&
                                            chain.size() < 32)
                                            chain.push_back(producer);
                                const auto other_tails = state.tails.find(value->first);
                                const bool had_tails = incoming.tails.contains(value->first);
                                if (other_tails != state.tails.end()) {
                                    auto &tails = incoming.tails[value->first];
                                    const auto before = tails;
                                    append_producers(tails, other_tails->second, 32);
                                    if (other_tails->second != before || state.ambiguous_tails.contains(value->first))
                                        incoming.ambiguous_tails.insert(value->first);
                                } else if (had_tails) {
                                    incoming.ambiguous_tails.insert(value->first);
                                }
                                ++value;
                            }
                        }
                        for (auto value = incoming.memory.begin(); value != incoming.memory.end();) {
                            const auto matching = state.memory.find(value->first);
                            if (matching == state.memory.end() || matching->second.width != value->second.width ||
                                matching->second.value != value->second.value)
                                value = incoming.memory.erase(value);
                            else {
                                append_producers(value->second.producers, matching->second.producers, 32);
                                const auto before = value->second.tails;
                                append_producers(value->second.tails, matching->second.tails, 32);
                                value->second.ambiguous = value->second.ambiguous || matching->second.ambiguous ||
                                                          value->second.tails != before;
                                ++value;
                            }
                        }
                        incoming.image_memory_unchanged =
                            incoming.image_memory_unchanged && state.image_memory_unchanged;
                    }
                }
            }
            if (!ready) {
                ++current;
                continue;
            }
            auto output = process_block(*block, std::move(incoming));
            if (!memory_budget_exhausted && output.memory.size() <= max_total_memory_facts - total_memory_facts) {
                total_memory_facts += output.memory.size();
            } else if (!memory_budget_exhausted) {
                memory_budget_exhausted = true;
                for (auto &[output_id, prior] : outputs) {
                    (void)output_id;
                    prior.memory.clear();
                    prior.image_memory_unchanged = false;
                }
                output.memory.clear();
                output.image_memory_unchanged = false;
                total_memory_facts = 0;
            }
            outputs.emplace(id, std::move(output));
            current = pending.erase(current);
            progress = true;
        }
        if (!progress) {
            // Cyclic/incomplete predecessor graphs cannot prove an entry value.
            for (const auto id : pending) {
                DataflowState unknown;
                unknown.image_memory_unchanged = false;
                outputs.emplace(id, process_block(*blocks.at(id), std::move(unknown)));
            }
            pending.clear();
        }
    }
    constexpr std::size_t max_graph_nodes = 64;
    constexpr std::size_t max_graph_edges = 128;
    constexpr std::size_t max_graph_depth = 32;
    for (const auto &[key, root] : graph_roots) {
        reference_detail::canceled(stop);
        ReferenceProducerGraph graph;
        graph.ambiguous = root.ambiguous;
        graph.truncated = producer_parent_budget_exhausted;
        std::set<std::uint64_t> visited, active;
        std::function<void(std::uint64_t, std::size_t)> visit_producer;
        visit_producer = [&](std::uint64_t producer, std::size_t depth) {
            if (active.contains(producer)) { graph.cycle = true; graph.truncated = true; return; }
            if (visited.contains(producer)) return;
            if (depth >= max_graph_depth || visited.size() >= max_graph_nodes) {
                graph.truncated = true;
                return;
            }
            visited.insert(producer);
            active.insert(producer);
            if (const auto parents = producer_parent_ids.find(producer); parents != producer_parent_ids.end()) {
                for (const auto parent : parents->second) {
                    if (graph.dependencies.size() >= max_graph_edges) { graph.truncated = true; break; }
                    if (active.contains(parent)) { graph.cycle = true; graph.truncated = true; continue; }
                    graph.dependencies.push_back({producer, parent});
                    visit_producer(parent, depth + 1);
                }
            }
            active.erase(producer);
        };
        active.insert(root.instruction);
        visited.insert(root.instruction);
        for (const auto parent : root.parents) {
            if (graph.dependencies.size() >= max_graph_edges) { graph.truncated = true; break; }
            if (active.contains(parent)) { graph.cycle = true; graph.truncated = true; continue; }
            graph.dependencies.push_back({root.instruction, parent});
            visit_producer(parent, 1);
        }
        if (!graph.dependencies.empty() || graph.truncated || graph.ambiguous || graph.cycle)
            result.producer_graphs.emplace(key, std::move(graph));
    }
    return result;
}
struct RiscvAddressValue {
    Address address;
    ReferenceProducerGraph graph;
    std::vector<std::uint64_t> tails;
    bool operator==(const RiscvAddressValue &) const = default;
};

void riscv_add_dependency(ReferenceProducerGraph &graph, std::uint64_t child, std::uint64_t parent) {
    const ReferenceProducerDependency edge{child, parent};
    if (std::find(graph.dependencies.begin(), graph.dependencies.end(), edge) != graph.dependencies.end()) return;
    std::set<std::uint64_t> nodes{child, parent};
    for (const auto &existing : graph.dependencies) {
        nodes.insert(existing.consumer_instruction_id);
        nodes.insert(existing.producer_instruction_id);
    }
    if (nodes.size() > 64 || graph.dependencies.size() >= 128) {
        graph.truncated = true;
        return;
    }
    graph.dependencies.push_back(edge);
}

RiscvAddressValue riscv_definition(Address address, std::uint64_t instruction,
                                    const RiscvAddressValue *source = nullptr) {
    RiscvAddressValue result{address};
    if (source) {
        result.graph = source->graph;
        for (const auto parent : source->tails)
            riscv_add_dependency(result.graph, instruction, parent);
    }
    result.tails.push_back(instruction);
    return result;
}

bool merge_register_value(RiscvAddressValue &into, const RiscvAddressValue &other) {
    if (into.address != other.address) return false;
    into.graph.ambiguous = into.graph.ambiguous || other.graph.ambiguous ||
                           into.tails != other.tails || into.graph.dependencies != other.graph.dependencies;
    into.graph.truncated = into.graph.truncated || other.graph.truncated;
    into.graph.cycle = into.graph.cycle || other.graph.cycle;
    for (const auto &edge : other.graph.dependencies)
        riscv_add_dependency(into.graph, edge.consumer_instruction_id, edge.producer_instruction_id);
    for (const auto tail : other.tails)
        if (std::find(into.tails.begin(), into.tails.end(), tail) == into.tails.end()) {
            if (into.tails.size() == 32) into.graph.truncated = true;
            else into.tails.push_back(tail);
        }
    return true;
}

template <class Value>
bool merge_register_value(Value &into, const Value &other) { return into == other; }

ReferenceProducerGraph riscv_reference_graph(std::uint64_t instruction, const RiscvAddressValue &value) {
    ReferenceProducerGraph graph;
    graph.ambiguous = value.graph.ambiguous;
    graph.truncated = value.graph.truncated;
    std::map<std::uint64_t, std::vector<std::uint64_t>> parents;
    for (const auto &edge : value.graph.dependencies)
        parents[edge.consumer_instruction_id].push_back(edge.producer_instruction_id);
    for (const auto tail : value.tails)
        parents[instruction].push_back(tail);
    std::set<std::uint64_t> visited, active;
    std::function<void(std::uint64_t, std::size_t)> visit = [&](std::uint64_t child, std::size_t depth) {
        if (active.contains(child)) { graph.cycle = true; graph.truncated = true; return; }
        if (visited.contains(child)) return;
        if (depth >= 32 || visited.size() >= 64) { graph.truncated = true; return; }
        visited.insert(child);
        active.insert(child);
        if (const auto found = parents.find(child); found != parents.end())
            for (const auto parent : found->second) {
                if (graph.dependencies.size() >= 128) { graph.truncated = true; break; }
                if (active.contains(parent)) { graph.cycle = true; graph.truncated = true; continue; }
                if (!visited.contains(parent) && (visited.size() >= 64 || depth + 1 >= 32)) {
                    graph.truncated = true;
                    continue;
                }
                graph.dependencies.push_back({child, parent});
                visit(parent, depth + 1);
            }
        active.erase(child);
    };
    visit(instruction, 0);
    return graph;
}

template <class RegisterState, class Transfer, class EdgeTransfer>
void propagate_cfg_register_values(const FunctionSnapshot &functions, std::stop_token stop,
                                  RegisterReferenceFacts &result, Transfer &&transfer,
                                  EdgeTransfer &&edge_transfer) {
    constexpr std::size_t max_propagation_blocks = 100000;
    constexpr std::size_t max_propagation_edges = 1000000;
    // Keep local facts useful when a very large or malformed CFG exceeds the
    // graph-propagation budget. Cross-block values remain unknown.
    if (functions.blocks.size() > max_propagation_blocks) {
        for (const auto &block : functions.blocks) {
            reference_detail::canceled(stop);
            if (block) (void)transfer(*block, RegisterState{});
        }
        return;
    }
    std::map<BlockId, const BasicBlock *> blocks;
    std::map<BlockId, std::set<BlockId>> predecessors;
    std::map<BlockId, std::set<BlockId>> successors;
    std::map<BlockId, std::vector<std::pair<BlockId, const BlockSuccessor *>>> predecessor_edges;
    std::set<BlockId> entries;
    std::map<BlockId, std::set<FunctionId>> owners;
    std::map<FunctionId, bool> complete_functions;
    for (const auto &function : functions.functions)
        if (function) complete_functions[function->id] = function->complete;
    for (const auto &block : functions.blocks)
        if (block) {
            blocks.emplace(block->id, block.get());
            owners.emplace(block->id, std::set<FunctionId>(block->owners.begin(), block->owners.end()));
        }
    std::size_t edge_count = 0;
    for (const auto &[id, block] : blocks) {
        reference_detail::canceled(stop);
        for (const auto &successor : block->successors)
            if (successor.block && blocks.contains(*successor.block) &&
                successor.kind != BlockEdgeKind::unresolved &&
                std::any_of(owners[id].begin(), owners[id].end(), [&](const FunctionId owner) {
                    return owners[*successor.block].contains(owner);
                })) {
                if (++edge_count > max_propagation_edges) {
                    for (const auto &[fallback_id, fallback_block] : blocks) {
                        (void)fallback_id;
                        reference_detail::canceled(stop);
                        (void)transfer(*fallback_block, RegisterState{});
                    }
                    return;
                }
                predecessors[*successor.block].insert(id);
                successors[id].insert(*successor.block);
                predecessor_edges[*successor.block].push_back({id, &successor});
            }
    }
    for (const auto &function : functions.functions) {
        if (!function)
            continue;
        for (const auto &id : function->blocks) {
            const auto block = blocks.find(id);
            if (block != blocks.end() && block->second->begin == function->entry)
                entries.insert(id);
        }
    }
    std::map<BlockId, RegisterState> outputs;
    std::map<BlockId, std::size_t> remaining_predecessors;
    std::deque<BlockId> ready;
    for (const auto &[id, block] : blocks) {
        (void)block;
        const auto found = predecessors.find(id);
        const auto count = found == predecessors.end() ? 0 : found->second.size();
        remaining_predecessors.emplace(id, count);
        if (entries.contains(id) || count == 0)
            ready.push_back(id);
    }
    while (!ready.empty()) {
        reference_detail::canceled(stop);
        const auto id = ready.front();
        ready.pop_front();
        if (outputs.contains(id))
            continue;
        RegisterState incoming;
        const auto found_predecessors = predecessors.find(id);
        if (!entries.contains(id) && found_predecessors != predecessors.end() &&
            !found_predecessors->second.empty()) {
            bool first = true;
            for (const auto &[predecessor, edge] : predecessor_edges[id]) {
                const auto state = outputs.find(predecessor);
                if (state == outputs.end()) {
                    incoming.clear();
                    first = false;
                    break;
                }
                auto edge_state = edge_transfer(*blocks.at(predecessor), *edge, state->second);
                if (first) {
                    incoming = std::move(edge_state);
                    first = false;
                    continue;
                }
                for (auto value = incoming.begin(); value != incoming.end();) {
                    const auto matching = edge_state.find(value->first);
                    if (matching == edge_state.end() ||
                        !merge_register_value(value->second, matching->second))
                        value = incoming.erase(value);
                    else
                        ++value;
                }
            }
        }
        outputs.emplace(id, transfer(*blocks.at(id), std::move(incoming)));
        const auto found_successors = successors.find(id);
        if (found_successors != successors.end()) {
            for (const auto successor : found_successors->second) {
                auto remaining = remaining_predecessors.find(successor);
                if (remaining != remaining_predecessors.end() && remaining->second &&
                    --remaining->second == 0)
                    ready.push_back(successor);
            }
        }
    }
    // Solve rooted cyclic regions with a bounded must-analysis. A fact is
    // retained only when every incoming path agrees, so loops cannot invent
    // register values. Incomplete ownership or unresolved edges still use
    // local-only transfer below.
    std::set<BlockId> cyclic;
    std::deque<BlockId> work;
    for (const auto &[id, block] : blocks) {
        (void)block;
        if (!outputs.contains(id)) work.push_back(id);
    }
    while (!work.empty()) {
        const auto id = work.front(); work.pop_front();
        if (!cyclic.insert(id).second) continue;
        const auto next = successors.find(id);
        if (next != successors.end()) for (const auto target : next->second)
            if (!outputs.contains(target)) work.push_back(target);
    }
    const auto safe_block = [&](BlockId id) {
        if (owners[id].empty()) return false;
        for (const auto owner : owners[id]) {
            const auto complete = complete_functions.find(owner);
            if (complete == complete_functions.end() || !complete->second) return false;
        }
        const auto *block = blocks.at(id);
        return std::none_of(block->successors.begin(), block->successors.end(),
            [&](const BlockSuccessor &edge) { return !edge.block || edge.kind == BlockEdgeKind::unresolved; });
    };
    bool safe = !cyclic.empty();
    for (const auto id : cyclic) safe = safe && safe_block(id);
    std::map<BlockId, RegisterState> states;
    for (const auto id : cyclic) states.emplace(id, RegisterState{});
    const auto same_state = [](const RegisterState &a, const RegisterState &b) {
        if (a.size() != b.size()) return false;
        for (const auto &[key, value] : a) {
            const auto found = b.find(key);
            if (found == b.end() || found->second != value) return false;
        }
        return true;
    };
    bool converged = false;
    if (safe) {
        constexpr std::size_t max_rounds = 32;
        constexpr std::size_t max_transfers = 1000000;
        std::size_t transfers = 0;
        const auto base_immediate = result.immediate_targets;
        const auto base_target_modes = result.target_modes;
        const auto base_memory = result.memory_targets;
        const auto base_producers = result.producer_instruction_ids;
        const auto base_graphs = result.producer_graphs;
        // Seed each cyclic node from its solved external predecessors. This
        // is the optimistic starting point for a must-analysis; starting at
        // empty would permanently discard loop-invariant values.
        for (const auto id : cyclic) {
            transfers += blocks.at(id)->instructions.size();
            if (transfers > max_transfers) { safe = false; break; }
            RegisterState incoming;
            bool first = true;
            bool entry_path = entries.contains(id);
            for (const auto &[source, edge] : predecessor_edges[id]) {
                if (cyclic.contains(source)) continue;
                const auto state = outputs.find(source);
                if (state == outputs.end()) { safe = false; break; }
                auto edge_state = edge_transfer(*blocks.at(source), *edge, state->second);
                if (first) { incoming = std::move(edge_state); first = false; }
                else for (auto it = incoming.begin(); it != incoming.end();) {
                    const auto match = edge_state.find(it->first);
                    if (match == edge_state.end() || !merge_register_value(it->second, match->second))
                        it = incoming.erase(it);
                    else ++it;
                }
            }
            if (!safe) break;
            if (entry_path) incoming.clear();
            if (first && !entry_path) { safe = false; break; }
            states[id] = transfer(*blocks.at(id), std::move(incoming));
        }
        for (std::size_t round = 0; round < max_rounds; ++round) {
            if (!safe) break;
            reference_detail::canceled(stop);
            result.immediate_targets = base_immediate;
            result.target_modes = base_target_modes;
            result.memory_targets = base_memory;
            result.producer_instruction_ids = base_producers;
            result.producer_graphs = base_graphs;
            auto next_states = states;
            for (const auto id : cyclic) {
                reference_detail::canceled(stop);
                RegisterState incoming;
                bool first = true;
                bool has_entry_path = entries.contains(id);
                for (const auto &[source, edge] : predecessor_edges[id]) {
                    const RegisterState *state = nullptr;
                    if (cyclic.contains(source)) state = &states.at(source);
                    else if (outputs.contains(source)) state = &outputs.at(source);
                    if (!state) { safe = false; break; }
                    auto edge_state = edge_transfer(*blocks.at(source), *edge, *state);
                    if (first) { incoming = std::move(edge_state); first = false; }
                    else for (auto it = incoming.begin(); it != incoming.end();) {
                        auto match = edge_state.find(it->first);
                        if (match == edge_state.end() || !merge_register_value(it->second, match->second))
                            it = incoming.erase(it);
                        else ++it;
                    }
                }
                if (!safe) break;
                if (has_entry_path) incoming.clear();
                if (first && !has_entry_path) { safe = false; break; }
                transfers += blocks.at(id)->instructions.size();
                if (transfers > max_transfers) { safe = false; break; }
                next_states[id] = transfer(*blocks.at(id), std::move(incoming));
            }
            if (!safe) break;
            bool unchanged = true;
            for (const auto id : cyclic)
                unchanged = unchanged && same_state(states.at(id), next_states.at(id));
            states.swap(next_states);
            if (unchanged) { converged = true; break; }
        }
        if (converged) outputs.insert(states.begin(), states.end());
        else {
            result.immediate_targets = base_immediate;
            result.target_modes = base_target_modes;
            result.memory_targets = base_memory;
            result.producer_instruction_ids = base_producers;
            result.producer_graphs = base_graphs;
        }
    }
    if (!converged)
        for (const auto &[id, block] : blocks) if (!outputs.contains(id)) {
            (void)id;
            reference_detail::canceled(stop);
            (void)transfer(*block, RegisterState{});
        }
}

template <class RegisterState, class Transfer>
void propagate_cfg_register_values(const FunctionSnapshot &functions, std::stop_token stop,
                                  RegisterReferenceFacts &result, Transfer &&transfer) {
    propagate_cfg_register_values<RegisterState>(functions, stop, result, transfer,
        [](const BasicBlock &, const BlockSuccessor &, RegisterState incoming) {
            return incoming;
        });
}
using ProducerRegisterKey = std::tuple<RegisterBank, std::uint8_t, std::uint32_t>;
using ProducerRegisterState = std::map<ProducerRegisterKey, std::vector<std::uint64_t>>;

bool is_producer_architecture(Architecture architecture) {
    return architecture == Architecture::arm || architecture == Architecture::arm64 ||
           architecture == Architecture::mips32 || architecture == Architecture::mips64 ||
           architecture == Architecture::powerpc;
}

bool is_producer_gpr(Architecture architecture, RegisterBank bank) {
    switch (architecture) {
    case Architecture::riscv32:
    case Architecture::riscv64: return bank == RegisterBank::riscv_gpr;
    case Architecture::arm: return bank == RegisterBank::arm32_gpr;
    case Architecture::arm64: return bank == RegisterBank::arm64_gpr;
    case Architecture::mips32:
    case Architecture::mips64: return bank == RegisterBank::mips_gpr;
    case Architecture::powerpc: return bank == RegisterBank::ppc_gpr;
    default: return false;
    }
}

void append_unique_producers(std::vector<std::uint64_t> &target,
                             const std::vector<std::uint64_t> &source,
                             std::size_t limit = 32) {
    for (const auto producer : source)
        if (std::find(target.begin(), target.end(), producer) == target.end() && target.size() < limit)
            target.push_back(producer);
}

RegisterReferenceFacts non_x86_producer_facts(
    const Image &image, const RelocationCoverage &relocations, const FunctionSnapshot &functions,
    std::span<const RegisterReferenceFacts *const> target_facts, std::stop_token stop) {
    RegisterReferenceFacts result;
    const auto has_fact = [&](const std::vector<const RegisterReferenceFacts *> &facts,
                              ReferenceOperandKey key, bool memory) {
        return std::any_of(facts.begin(), facts.end(), [&](const RegisterReferenceFacts *facts_for_arch) {
            if (!facts_for_arch) return false;
            return memory ? facts_for_arch->memory_targets.contains(key)
                          : facts_for_arch->immediate_targets.contains(key);
        });
    };
    std::vector<const RegisterReferenceFacts *> facts(target_facts.begin(), target_facts.end());
    const auto is_address_target = [&](std::uint64_t instruction, std::size_t operand) {
        return has_fact(facts, {instruction, static_cast<std::uint32_t>(operand)}, false);
    };
    const auto is_memory_target = [&](std::uint64_t instruction, std::size_t operand) {
        return has_fact(facts, {instruction, static_cast<std::uint32_t>(operand)}, true);
    };
    const auto register_key = [](const RegisterOperand &reg) -> ProducerRegisterKey {
        return {reg.bank, reg.width, reg.index};
    };
    const auto append_register_producers = [&](std::vector<std::uint64_t> &into,
                                               const RegisterOperand *reg,
                                               const ProducerRegisterState &state,
                                               Architecture architecture) {
        if (!reg || !is_producer_gpr(architecture, reg->bank)) return;
        if (const auto found = state.find(register_key(*reg)); found != state.end())
            append_unique_producers(into, found->second);
    };
    const auto memory_registers = [](const Operand &operand) {
        std::vector<RegisterOperand> registers;
        if (const auto *memory = std::get_if<MemoryOperand>(&operand)) {
            if (memory->base) registers.push_back(*memory->base);
            if (memory->index) registers.push_back(*memory->index);
        } else if (const auto *memory = std::get_if<ArmMemoryOperand>(&operand)) {
            registers.push_back(memory->base);
            if (const auto *offset = std::get_if<ArmShiftedRegisterOperand>(&memory->offset)) {
                registers.push_back(offset->source);
                if (offset->amount_register) registers.push_back(*offset->amount_register);
            }
        }
        return registers;
    };
    const auto transfer = [&](const BasicBlock &block, ProducerRegisterState state) {
        for (const auto &fact : block.instructions) {
            reference_detail::canceled(stop);
            if (!fact) continue;
            const auto &instruction = fact->instruction;
            const auto architecture = instruction.context.architecture;
            if (!is_producer_architecture(architecture)) {
                state.clear();
                continue;
            }

            // Consumer provenance is captured before any writes at this
            // instruction. The instruction's own ID is the graph root; its
            // register producers remain a compact ordered list here.
            for (std::size_t operand = 0; operand < instruction.operands.size(); ++operand) {
                const ReferenceOperandKey key{fact->id, static_cast<std::uint32_t>(operand)};
                if (is_memory_target(fact->id, operand)) {
                    std::vector<std::uint64_t> producers;
                    for (const auto &reg : memory_registers(instruction.operands[operand]))
                        append_register_producers(producers, &reg, state, architecture);
                    if (!producers.empty()) result.producer_instruction_ids[key] = std::move(producers);
                } else if (is_address_target(fact->id, operand)) {
                    std::vector<std::uint64_t> producers;
                    for (const auto &reg : instruction.register_reads)
                        append_register_producers(producers, &reg, state, architecture);
                    if (!producers.empty()) result.producer_instruction_ids[key] = std::move(producers);
                }
            }

            if (instruction.flow == FlowKind::call) {
                state.clear(); // Unknown callees can clobber every caller-saved address fact.
                continue;
            }

            std::vector<RegisterOperand> reads, writes;
            for (const auto &reg : instruction.register_reads)
                if (is_producer_gpr(architecture, reg.bank)) reads.push_back(reg);
            for (const auto &reg : instruction.register_writes)
                if (is_producer_gpr(architecture, reg.bank)) writes.push_back(reg);
            if (writes.empty()) continue;

            std::vector<std::uint64_t> parents;
            for (const auto &reg : reads) append_register_producers(parents, &reg, state, architecture);

            // Propagate through definitions the architecture-specific address
            // evaluator has already recognized. A single-source GPR operation
            // is also safe to retain as a causal producer: consumers still
            // require an independently resolved target from that evaluator.
            bool address_definition = std::any_of(facts.begin(), facts.end(), [&](const auto *facts_for_arch) {
                return facts_for_arch && facts_for_arch->address_definitions.contains(fact->id);
            });
            for (std::size_t operand = 0; operand < instruction.operands.size(); ++operand)
                if (std::holds_alternative<ImmediateOperand>(instruction.operands[operand]) &&
                    is_address_target(fact->id, operand)) {
                    address_definition = true;
                    break;
                }
            const bool one_source_transform = reads.size() == 1 && writes.size() == 1 &&
                                              !instruction.memory_read && !instruction.memory_write &&
                                              instruction.flow == FlowKind::fallthrough;
            std::map<ProducerRegisterKey, std::vector<std::uint64_t>> definitions;
            if (address_definition || one_source_transform || (reads.empty() && writes.size() == 1)) {
                auto chain = parents;
                if (std::find(chain.begin(), chain.end(), fact->id) == chain.end() && chain.size() < 32)
                    chain.push_back(fact->id);
                if (!chain.empty())
                    for (const auto &destination : writes)
                        definitions[register_key(destination)] = chain;
            }

            // Full-width static pointer loads produce another address value.
            // Require the independent target analysis to have resolved the
            // slot, then validate the stored pointer against image mappings.
            const auto *destination = instruction.operands.empty()
                                          ? nullptr
                                          : std::get_if<RegisterOperand>(&instruction.operands.front());
            if (destination && is_producer_gpr(architecture, destination->bank) &&
                std::find(writes.begin(), writes.end(), *destination) != writes.end()) {
                for (std::size_t operand = 0; operand < instruction.operands.size() &&
                                              operand < instruction.access.size(); ++operand) {
                    if (instruction.access[operand] != OperandAccess::read ||
                        !is_memory_target(fact->id, operand)) continue;
                    const auto address = std::find_if(facts.begin(), facts.end(), [&](const auto *candidate) {
                        return candidate && candidate->memory_targets.contains(
                            {fact->id, static_cast<std::uint32_t>(operand)});
                    });
                    if (address == facts.end()) continue;
                    const auto memory_target = (*address)->memory_targets.find(
                        {fact->id, static_cast<std::uint32_t>(operand)});
                    if (memory_target == (*address)->memory_targets.end()) continue;
                    const auto data_width = std::visit([](const auto &value) -> std::uint16_t {
                        using T = std::decay_t<decltype(value)>;
                        if constexpr (std::is_same_v<T, MemoryOperand> || std::is_same_v<T, ArmMemoryOperand>)
                            return static_cast<std::uint16_t>(value.data_width);
                        else
                            return std::uint16_t{0};
                    }, instruction.operands[operand]);
                    if (data_width != destination->width || (data_width != 32 && data_width != 64)) continue;
                    if (!static_pointer_load(image, relocations, memory_target->second,
                                             static_cast<std::uint8_t>(data_width))) continue;
                    auto chain = parents;
                    for (const auto &reg : memory_registers(instruction.operands[operand]))
                        append_register_producers(chain, &reg, state, architecture);
                    if (std::find(chain.begin(), chain.end(), fact->id) == chain.end() && chain.size() < 32)
                        chain.push_back(fact->id);
                    if (!chain.empty()) definitions[register_key(*destination)] = std::move(chain);
                    break;
                }
            }

            for (const auto &reg : writes) state.erase(register_key(reg));
            // A redefinition replaces the old chain rather than retaining it.
            for (const auto &[key, chain] : definitions) state[key] = chain;
        }
        return state;
    };
    propagate_cfg_register_values<ProducerRegisterState>(functions, stop, result, transfer);
    // Preserve the ordered non-x86 producer chain as a compact dependency DAG.
    // The first dependency is from the referenced instruction to its latest
    // register producer; subsequent edges follow the bounded causal chain.
    // Target validation remains owned by each architecture's address analysis.
    for (const auto &[key, producers] : result.producer_instruction_ids) {
        reference_detail::canceled(stop);
        if (producers.empty()) continue;
        ReferenceProducerGraph graph;
        const auto add_edge = [&](std::uint64_t consumer, std::uint64_t producer) {
            if (consumer == producer) return;
            if (graph.dependencies.size() >= 128) { graph.truncated = true; return; }
            graph.dependencies.push_back({consumer, producer});
        };
        add_edge(key.first, producers.back());
        for (std::size_t i = producers.size(); i > 1; --i)
            add_edge(producers[i - 1], producers[i - 2]);
        // Producer state is capped at 32 IDs during transfer. Reaching the
        // cap may mean older ancestry was dropped, so surface that uncertainty.
        if (producers.size() >= 32) graph.truncated = true;
        if (!graph.dependencies.empty() || graph.truncated)
            result.producer_graphs.emplace(key, std::move(graph));
    }
    return result;
}

RegisterReferenceFacts riscv_reference_facts(const Image *image, const ElfMetadata *elf, const RelocationCoverage &relocations,
                                            const FunctionSnapshot &functions, std::stop_token stop) {
    RegisterReferenceFacts result;
    if (!image)
        return result;
    struct PairedMemoryTarget {
        Address target;
        std::uint64_t high_instruction = 0;
    };
    std::map<ReferenceOperandKey, PairedMemoryTarget> paired_memory_targets;
    // Resolve PCREL_HI20/LO12 pairs from their local label relationship. The
    // LO label must identify one unique HI relocation, and the decoded base
    // register must match the AUIPC destination. Memory references additionally
    // require the CFG-propagated register value to reach that access unchanged.
    if (elf && elf->header.machine == 243 && elf->header.order == ByteOrder::little) {
        using SourceKey = std::tuple<std::optional<std::uint32_t>, std::uint64_t, bool, std::uint32_t, std::uint64_t>;
        const auto source_key = [](const ElfTableSource &s) -> SourceKey {
            return {s.section, s.file_offset, bool(s.address), s.address ? s.address->space.value : 0,
                    s.address ? s.address->offset : 0};
        };
        std::map<SourceKey, const ElfSymbolTable *> tables;
        bool unique_symbol_tables = true;
        for (const auto &table : elf->symbol_tables)
            if (!tables.emplace(source_key(table.source), &table).second) unique_symbol_tables = false;
        if (!unique_symbol_tables) tables.clear();
        const auto symbol_for = [&](const ElfRelocation &row) -> const ElfSymbol * {
            if (!row.symbol_table || !row.symbol_index_validated) return nullptr;
            const auto it = tables.find(source_key(*row.symbol_table));
            if (it == tables.end() || !it->second->count || !it->second->symbol_begin ||
                row.symbol_index >= *it->second->count) return nullptr;
            return &elf->symbols[static_cast<std::size_t>(*it->second->symbol_begin + row.symbol_index)];
        };
        using PlaceKey = std::pair<std::uint32_t, std::uint64_t>;
        std::map<PlaceKey, std::vector<const ElfRelocation *>> highs;
        for (const auto &row : elf->relocations)
            if (row.type == 23 && row.place && row.field_size == 4 && row.symbol_table &&
                row.symbol_index_validated && row.explicit_addend && row.addend)
                highs[{row.place->space.value, row.place->offset}].push_back(&row);
        for (const auto &low : elf->relocations) {
            if ((low.type != 24 && low.type != 25) || !low.place || low.field_size != 4 ||
                !low.explicit_addend || !low.addend ||
                *low.addend != 0) continue;
            const auto *label = symbol_for(low);
            if (!label || label->state != ElfSymbolState::defined || label->binding != 0 || !label->address ||
                label->address->space != low.place->space) continue;
            const auto low_matches = std::count_if(elf->relocations.begin(), elf->relocations.end(), [&](const auto &candidate) {
                if ((candidate.type != 24 && candidate.type != 25) || !candidate.place ||
                    *candidate.place != *low.place) return false;
                const auto *candidate_label = symbol_for(candidate);
                return candidate_label && candidate_label->address && *candidate_label->address == *label->address;
            });
            if (low_matches != 1) continue;
            const auto hi_it = highs.find({label->address->space.value, label->address->offset});
            if (hi_it == highs.end() || hi_it->second.size() != 1) continue;
            const auto &high = *hi_it->second.front();
            if (high.place->space != low.place->space || !high.target_section || !low.target_section ||
                high.target_section != low.target_section) continue;
            const auto *target_symbol = symbol_for(high);
            if (!target_symbol || !target_symbol->address || target_symbol->state != ElfSymbolState::defined ||
                target_symbol->address->space != high.place->space ||
                (elf->header.object_type == 3 && target_symbol->binding != 0 && target_symbol->visibility == 0)) continue;
            std::uint64_t target_offset = 0;
            if (*high.addend >= 0) {
                const auto add = static_cast<std::uint64_t>(*high.addend);
                if (add > UINT64_MAX - target_symbol->address->offset) continue;
                target_offset = target_symbol->address->offset + add;
            } else {
                const auto subtract = static_cast<std::uint64_t>(-(*high.addend + 1)) + 1;
                if (subtract > target_symbol->address->offset) continue;
                target_offset = target_symbol->address->offset - subtract;
            }
            if (!elf->header.is_64 && target_offset > UINT32_MAX) continue;
            const auto target = Address{high.place->space, target_offset};
            if (!riscv_target_segment(*image, target, OperandAccess::address)) continue;
            const auto hi_fact = std::find_if(functions.instructions.begin(), functions.instructions.end(),
                [&](const auto &f) { return f && f->instruction.address == *high.place; });
            const auto lo_fact = std::find_if(functions.instructions.begin(), functions.instructions.end(),
                [&](const auto &f) { return f && f->instruction.address == *low.place; });
            if (hi_fact == functions.instructions.end() || lo_fact == functions.instructions.end()) continue;
            const auto &hi = (*hi_fact)->instruction;
            const auto &lo = (*lo_fact)->instruction;
            const auto expected_width = static_cast<std::uint8_t>(elf->header.is_64 ? 64 : 32);
            if (hi.opcode != Opcode::rv_auipc || hi.length != 4 || hi.operands.size() != 2) continue;
            const auto *hi_dst = riscv_register(hi, 0);
            if (!hi_dst || !hi_dst->index || hi_dst->width != expected_width) continue;
            bool matched_low = false;
            if (low.type == 24 && lo.opcode == Opcode::rv_addi && lo.length == 4 && lo.operands.size() == 3) {
                const auto *lo_dst = riscv_register(lo, 0), *lo_src = riscv_register(lo, 1);
                if (lo_dst && lo_src && lo_dst->width == expected_width && lo_src->width == expected_width &&
                    hi_dst->index == lo_src->index) {
                    result.immediate_targets[{(*lo_fact)->id, 2}] = target;
                    matched_low = true;
                }
            } else {
                const bool load_i = low.type == 24 &&
                    (lo.opcode == Opcode::rv_lb || lo.opcode == Opcode::rv_lbu || lo.opcode == Opcode::rv_lh ||
                     lo.opcode == Opcode::rv_lhu || lo.opcode == Opcode::rv_lw || lo.opcode == Opcode::rv_lwu ||
                     lo.opcode == Opcode::rv_ld || lo.opcode == Opcode::rv_flw || lo.opcode == Opcode::rv_fld);
                const bool store_s = low.type == 25 &&
                    (lo.opcode == Opcode::rv_sb || lo.opcode == Opcode::rv_sh || lo.opcode == Opcode::rv_sw ||
                     lo.opcode == Opcode::rv_sd || lo.opcode == Opcode::rv_fsw || lo.opcode == Opcode::rv_fsd);
                const auto memory_index = 1u;
                const auto *memory = lo.operands.size() > memory_index
                    ? std::get_if<MemoryOperand>(&lo.operands[memory_index]) : nullptr;
                if ((load_i || store_s) && lo.length == 4 && memory && memory->base &&
                    memory->base->bank == RegisterBank::riscv_gpr &&
                    memory->base->width == expected_width && memory->address_width == expected_width &&
                    memory->base->index == hi_dst->index) {
                    paired_memory_targets[{(*lo_fact)->id, memory_index}] = {target, (*hi_fact)->id};
                    matched_low = true;
                }
            }
            if (matched_low)
                result.immediate_targets[{(*hi_fact)->id, 1}] = target;
        }
    }
    using RegisterState = std::unordered_map<std::uint32_t, RiscvAddressValue>;
    const auto record_producers = [&](ReferenceOperandKey key, std::uint64_t instruction,
                                      const RiscvAddressValue &source) {
        auto graph = riscv_reference_graph(instruction, source);
        std::vector<std::uint64_t> producers;
        for (const auto &edge : graph.dependencies)
            if (std::find(producers.begin(), producers.end(), edge.producer_instruction_id) == producers.end() &&
                producers.size() < 32)
                producers.push_back(edge.producer_instruction_id);
        if (!producers.empty()) result.producer_instruction_ids[key] = std::move(producers);
        if (!graph.dependencies.empty() || graph.ambiguous || graph.truncated || graph.cycle)
            result.producer_graphs[key] = std::move(graph);
    };
    const auto process_block = [&](const BasicBlock &block, RegisterState registers) {
        for (const auto &fact : block.instructions) {
            reference_detail::canceled(stop);
            if (!fact)
                continue;
            const auto &instruction = fact->instruction;
            const auto architecture = instruction.context.architecture;
            const bool rv32 = architecture == Architecture::riscv32 &&
                              instruction.context.mode == ExecutionMode::rv32;
            const bool rv64 = architecture == Architecture::riscv64 &&
                              instruction.context.mode == ExecutionMode::rv64;
            if (!rv32 && !rv64) {
                registers.clear();
                continue;
            }
            const auto width = static_cast<std::uint8_t>(rv32 ? 32 : 64);
            const auto erase_written = [&] {
                for (const auto &reg : instruction.register_writes)
                    if (reg.bank == RegisterBank::riscv_gpr && reg.index != 0)
                        registers.erase(reg.index);
            };

            bool propagated = false;
            if (instruction.opcode == Opcode::rv_lui && instruction.operands.size() == 2) {
                const auto *dst = riscv_register(instruction, 0);
                const auto immediate = riscv_signed_immediate(instruction, 1, 20);
                erase_written();
                if (dst && dst->index && dst->width == width && immediate) {
                    const auto value = static_cast<std::uint64_t>(*immediate);
                    const Address target{instruction.address.space,
                                         width == 32 ? value & UINT64_C(0xffffffff) : value};
                    registers[dst->index] = riscv_definition(target, fact->id);
                    if (riscv_target_segment(*image, target, OperandAccess::address))
                        result.immediate_targets[{fact->id, 1}] = target;
                }
                propagated = true;
            } else if (instruction.opcode == Opcode::rv_auipc && instruction.operands.size() == 2) {
                const auto *dst = riscv_register(instruction, 0);
                const auto immediate = riscv_signed_immediate(instruction, 1, 20);
                erase_written();
                if (dst && dst->index && dst->width == width && immediate) {
                    const Address target{instruction.address.space,
                                         riscv_add(instruction.address.offset, *immediate, width)};
                    const auto paired = result.immediate_targets.find({fact->id, 1});
                    const auto resolved = paired == result.immediate_targets.end() ? target : paired->second;
                    registers[dst->index] = riscv_definition(resolved, fact->id);
                    if (riscv_target_segment(*image, resolved, OperandAccess::address))
                        result.immediate_targets[{fact->id, 1}] = resolved;
                }
                propagated = true;
            } else if ((instruction.opcode == Opcode::rv_addi || instruction.opcode == Opcode::rv_ori) &&
                       instruction.operands.size() == 3) {
                const auto *dst = riscv_register(instruction, 0);
                const auto *src = riscv_register(instruction, 1);
                const auto immediate = riscv_signed_immediate(instruction, 2, 12);
                std::optional<Address> target;
                std::optional<RiscvAddressValue> definition;
                if (src && src->width == width && immediate) {
                    if (!src->index) {
                        const auto value = static_cast<std::uint64_t>(*immediate);
                        target = Address{instruction.address.space,
                                         width == 32 ? value & UINT64_C(0xffffffff) : value};
                        definition = riscv_definition(*target, fact->id);
                    } else if (const auto base = registers.find(src->index); base != registers.end()) {
                        const auto value = instruction.opcode == Opcode::rv_ori
                                               ? (base->second.address.offset | static_cast<std::uint64_t>(*immediate))
                                               : riscv_add(base->second.address.offset, *immediate, width);
                        target = Address{base->second.address.space,
                                         width == 32 ? value & UINT64_C(0xffffffff) : value};
                        definition = riscv_definition(*target, fact->id, &base->second);
                        if (dst && dst->index && dst->width == width &&
                            riscv_target_segment(*image, *target, OperandAccess::address))
                            record_producers({fact->id, 2}, fact->id, base->second);
                    }
                }
                if (const auto paired = result.immediate_targets.find({fact->id, 2});
                    paired != result.immediate_targets.end()) {
                    target = paired->second;
                    definition = riscv_definition(*target, fact->id);
                }
                erase_written();
                if (dst && dst->index && dst->width == width && target && definition) {
                    registers[dst->index] = std::move(*definition);
                    if (riscv_target_segment(*image, *target, OperandAccess::address))
                        result.immediate_targets[{fact->id, 2}] = *target;
                }
                propagated = true;
            } else if (instruction.operands.size() == 3 &&
                       (instruction.opcode == Opcode::rv_sh1add || instruction.opcode == Opcode::rv_sh2add ||
                        instruction.opcode == Opcode::rv_sh3add || instruction.opcode == Opcode::rv_add_uw ||
                        instruction.opcode == Opcode::rv_sh1add_uw || instruction.opcode == Opcode::rv_sh2add_uw ||
                        instruction.opcode == Opcode::rv_sh3add_uw || instruction.opcode == Opcode::rv_slli_uw)) {
                const auto *dst = riscv_register(instruction, 0);
                const auto *lhs = riscv_register(instruction, 1);
                const auto *rhs = instruction.opcode == Opcode::rv_slli_uw ? nullptr : riscv_register(instruction, 2);
                std::optional<Address> target;
                std::optional<RiscvAddressValue> definition;
                // Address facts track mapped pointers, not arbitrary integer
                // indices. Propagate only the exact zero-index form where the
                // shifted operand is architectural x0 and rs2 is a known base.
                if (lhs && !lhs->index && lhs->width == width && rhs && rhs->index && rhs->width == width) {
                    if (const auto base = registers.find(rhs->index); base != registers.end() &&
                        base->second.address.space == instruction.address.space &&
                        riscv_target_segment(*image, base->second.address, OperandAccess::address)) {
                        target = base->second.address;
                        definition = riscv_definition(*target, fact->id, &base->second);
                    }
                }
                erase_written();
                if (dst && dst->index && dst->width == width && target && definition)
                    registers[dst->index] = std::move(*definition);
                propagated = true;
            }

            // JALR expresses its register-relative destination as a memory-shaped
            // operand in the decoder, but it computes a code address; it does not
            // load a pointer from that address.
            if (instruction.opcode == Opcode::rv_jalr && instruction.operands.size() > 1) {
                const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
                if (memory && memory->base && memory->base->bank == RegisterBank::riscv_gpr &&
                    memory->base->index != 0 && memory->base->width == width) {
                    const auto base = registers.find(memory->base->index);
                    if (base != registers.end()) {
                        auto target = Address{base->second.address.space,
                                              riscv_add(base->second.address.offset, memory->displacement, width)};
                        target.offset &= ~UINT64_C(1); // JALR clears the low target bit.
                        const auto *segment = image->segment_at(target);
                        if (segment && segment->executable && target.offset >= segment->begin.offset &&
                            target.offset - segment->begin.offset < segment->size) {
                            result.immediate_targets[{fact->id, 1}] = target;
                            record_producers({fact->id, 1}, fact->id, base->second);
                        }
                    }
                }
            }

            if (!propagated) {
                std::optional<std::pair<std::uint32_t, RiscvAddressValue>> loaded_pointer;
                for (std::size_t i = 0; i < instruction.operands.size(); ++i) {
                    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[i]);
                    if (!memory || !memory->base || memory->base->bank != RegisterBank::riscv_gpr ||
                        memory->base->index == 0 || memory->base->width != width || i >= instruction.access.size())
                        continue;
                    const auto base = registers.find(memory->base->index);
                    if (base == registers.end())
                        continue;
                    const auto access = instruction.access[i];
                    Address target{base->second.address.space,
                                   riscv_add(base->second.address.offset, memory->displacement, width)};
                    const auto paired = paired_memory_targets.find({fact->id, static_cast<std::uint32_t>(i)});
                    if (paired != paired_memory_targets.end() && !base->second.graph.ambiguous &&
                        base->second.address == paired->second.target &&
                        std::find(base->second.tails.begin(), base->second.tails.end(),
                                  paired->second.high_instruction) != base->second.tails.end()) {
                        target = paired->second.target;
                        result.relocation_pair_targets.insert({fact->id, static_cast<std::uint32_t>(i)});
                    }
                    const auto access_width = std::max<std::uint64_t>(1, (memory->data_width + 7) / 8);
                    if (riscv_target_segment(*image, target, access, access_width)) {
                        result.memory_targets[{fact->id, static_cast<std::uint32_t>(i)}] = target;
                        record_producers({fact->id, static_cast<std::uint32_t>(i)}, fact->id, base->second);
                        const auto *destination = architecture_register(instruction, 0, RegisterBank::riscv_gpr, width);
                        const bool destination_written = destination && destination->index != 0 &&
                            std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                                [&](const RegisterOperand &written) {
                                    return written.bank == destination->bank && written.index == destination->index;
                                });
                        if (access == OperandAccess::read && memory->data_width == width && destination_written)
                            if (const auto value = static_pointer_load(*image, relocations, target, width))
                                loaded_pointer = std::pair{destination->index,
                                    riscv_definition(*value, fact->id, &base->second)};
                    }
                }
                erase_written();
                if (loaded_pointer)
                    registers[loaded_pointer->first] = loaded_pointer->second;
            }
            if (instruction.flow == FlowKind::call)
                registers.clear(); // Unknown callees may clobber any propagated GPR.
        }
        return registers;
    };
    propagate_cfg_register_values<RegisterState>(functions, stop, result, process_block);
    return result;
}
RegisterReferenceFacts a64_reference_facts(const Image *image, const RelocationCoverage &relocations,
                                           const FunctionSnapshot &functions, std::stop_token stop) {
    RegisterReferenceFacts result;
    if (!image)
        return result;
    using RegisterState = std::unordered_map<std::uint32_t, Address>;
    const auto process_block = [&](const BasicBlock &block, RegisterState registers) {
        for (const auto &fact : block.instructions) {
            reference_detail::canceled(stop);
            if (!fact)
                continue;
            const auto &instruction = fact->instruction;
            if (instruction.context.architecture != Architecture::arm64 ||
                instruction.context.mode != ExecutionMode::a64) {
                registers.clear();
                continue;
            }
            if (instruction.flow == FlowKind::call || instruction.flow == FlowKind::jump) {
                const auto control = analysis_detail::control_operand_index(instruction);
                if (control < instruction.operands.size()) {
                    const auto *target_register = std::get_if<RegisterOperand>(&instruction.operands[control]);
                    if (target_register && target_register->bank == RegisterBank::arm64_gpr &&
                        target_register->width == 64 && target_register->index != 31) {
                        const auto target = registers.find(target_register->index);
                        if (target != registers.end()) {
                            const auto *segment = image->segment_at(target->second);
                            if (segment && segment->executable && target->second.offset >= segment->begin.offset &&
                                target->second.offset - segment->begin.offset < segment->size)
                                result.immediate_targets[{fact->id, static_cast<std::uint32_t>(control)}] =
                                    target->second;
                        }
                    }
                }
            }
            const auto erase_written = [&] {
                for (const auto &reg : instruction.register_writes)
                    if (reg.bank == RegisterBank::arm64_gpr && reg.index != 31)
                        registers.erase(reg.index);
            };
            bool propagated = false;
            const bool move_wide = instruction.opcode == Opcode::a64_movz ||
                                   instruction.opcode == Opcode::a64_movn ||
                                   instruction.opcode == Opcode::a64_movk;
            if (move_wide) {
                const auto *destination = instruction.operands.empty() ? nullptr :
                    std::get_if<RegisterOperand>(&instruction.operands[0]);
                const auto immediate = immediate_value(instruction, 1);
                const auto shift = instruction.operands.size() >= 3 ? immediate_value(instruction, 2) :
                    std::optional<std::uint64_t>{0};
                const bool width_valid = destination && destination->bank == RegisterBank::arm64_gpr &&
                    (destination->width == 32 || destination->width == 64) && destination->index != 31;
                std::optional<Address> value;
                if (width_valid && immediate && shift && *shift < destination->width && (*shift % 16) == 0) {
                    const auto width_mask = destination->width == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
                    const auto lane = (UINT64_C(0xffff) << *shift) & width_mask;
                    const auto part = ((*immediate & UINT64_C(0xffff)) << *shift) & width_mask;
                    if (instruction.opcode == Opcode::a64_movz) {
                        value = Address{instruction.address.space, part};
                    } else if (instruction.opcode == Opcode::a64_movn) {
                        value = Address{instruction.address.space, (~part) & width_mask};
                    } else if (const auto previous = registers.find(destination->index);
                               previous != registers.end() && previous->second.space == instruction.address.space) {
                        value = Address{instruction.address.space,
                            ((previous->second.offset & ~lane) | part) & width_mask};
                    }
                }
                erase_written();
                if (value) {
                    registers[destination->index] = *value;
                    if (riscv_target_segment(*image, *value, OperandAccess::address))
                        result.immediate_targets[{fact->id, 1}] = *value;
                }
                // MOVK without a proven prior value and malformed width/shift
                // combinations invalidate the destination rather than guessing.
                propagated = true;
            } else if ((instruction.opcode == Opcode::a64_adr || instruction.opcode == Opcode::a64_adrp) &&
                instruction.operands.size() == 2) {
                const auto *dst = architecture_register(instruction, 0, RegisterBank::arm64_gpr, 64);
                const auto *address = std::get_if<MemoryOperand>(&instruction.operands[1]);
                erase_written();
                if (dst && dst->index != 31 && address && address->resolved_address) {
                    registers[dst->index] = *address->resolved_address;
                    if (riscv_target_segment(*image, *address->resolved_address, OperandAccess::address))
                        result.immediate_targets[{fact->id, 1}] = *address->resolved_address;
                }
                propagated = true;
            } else if ((instruction.opcode == Opcode::a64_add || instruction.opcode == Opcode::a64_sub) &&
                       instruction.operands.size() == 3) {
                const auto *dst_operand = std::get_if<RegisterOperand>(&instruction.operands[0]);
                const auto *src_operand = std::get_if<RegisterOperand>(&instruction.operands[1]);
                const auto *dst = dst_operand && dst_operand->bank == RegisterBank::arm64_gpr &&
                    (dst_operand->width == 32 || dst_operand->width == 64) ? dst_operand : nullptr;
                const auto *src = src_operand && src_operand->bank == RegisterBank::arm64_gpr &&
                    (src_operand->width == 32 || src_operand->width == 64) ? src_operand : nullptr;
                const auto immediate = immediate_value(instruction, 2);
                const auto *register_offset = std::get_if<RegisterOperand>(&instruction.operands[2]);
                std::optional<Address> target;
                if (dst && dst->index != 31 && src && src->index != 31 && dst->width == src->width && immediate) {
                    const auto base = registers.find(src->index);
                    if (base != registers.end() && base->second.space == instruction.address.space) {
                        auto value = base->second.offset;
                        if (dst->width == 32) {
                            const auto lhs = static_cast<std::uint32_t>(value);
                            const auto rhs = static_cast<std::uint32_t>(*immediate);
                            const auto result = instruction.opcode == Opcode::a64_add
                                ? static_cast<std::uint32_t>(lhs + rhs)
                                : static_cast<std::uint32_t>(lhs - rhs);
                            target = Address{base->second.space, result};
                        } else if (instruction.opcode == Opcode::a64_add) {
                            if (value <= UINT64_MAX - *immediate)
                                target = Address{base->second.space, value + *immediate};
                        } else if (value >= *immediate) {
                            target = Address{base->second.space, value - *immediate};
                        }
                    }
                } else if (instruction.operands.size() == 3 && dst && dst->index != 31 &&
                           src && src->index != 31 && register_offset &&
                           register_offset->bank == RegisterBank::arm64_gpr && register_offset->index != 31 &&
                           register_offset->width == dst->width && dst->width == src->width) {
                    // Register ADD/SUB is useful for address construction when
                    // both inputs are already proven constants/addresses. Keep
                    // this to the unshifted three-operand form; shifted operands
                    // and SP/XZR forms require additional semantics.
                    const auto base = registers.find(src->index);
                    const auto offset = registers.find(register_offset->index);
                    if (base != registers.end() && offset != registers.end() &&
                        base->second.space == instruction.address.space &&
                        offset->second.space == instruction.address.space &&
                        base->second.space == offset->second.space) {
                        const auto lhs = base->second.offset;
                        const auto rhs = offset->second.offset;
                        if (dst->width == 32) {
                            const auto left = static_cast<std::uint32_t>(lhs);
                            const auto right = static_cast<std::uint32_t>(rhs);
                            target = Address{base->second.space,
                                instruction.opcode == Opcode::a64_add
                                    ? static_cast<std::uint32_t>(left + right)
                                    : static_cast<std::uint32_t>(left - right)};
                        } else if (instruction.opcode == Opcode::a64_add) {
                            if (lhs <= UINT64_MAX - rhs)
                                target = Address{base->second.space, lhs + rhs};
                        } else if (lhs >= rhs) {
                            target = Address{base->second.space, lhs - rhs};
                        }
                    }
                }
                erase_written();
                if (dst && dst->index != 31 && target) {
                    registers[dst->index] = *target;
                    if (riscv_target_segment(*image, *target, OperandAccess::address))
                        result.immediate_targets[{fact->id, 2}] = *target;
                }
                propagated = true;
            } else if (instruction.opcode == Opcode::a64_orr &&
                       (instruction.operands.size() == 3 || instruction.operands.size() == 4)) {
                // The common MOV register alias is ORR Rd, ZR, Rm, LSL #0.
                // Accept the symmetric zero-register form as well, but do not
                // approximate shifted ORR as a pointer copy.
                const auto *destination = std::get_if<RegisterOperand>(&instruction.operands[0]);
                const auto *left = std::get_if<RegisterOperand>(&instruction.operands[1]);
                const auto *right = std::get_if<RegisterOperand>(&instruction.operands[2]);
                const auto no_shift = instruction.operands.size() == 3 ||
                                      immediate_value(instruction, 3) == std::optional<std::uint64_t>{0};
                const auto valid_gpr = [](const RegisterOperand *reg) {
                    return reg && reg->bank == RegisterBank::arm64_gpr && reg->index != 31 &&
                           (reg->width == 32 || reg->width == 64);
                };
                const RegisterOperand *source = nullptr;
                if (destination && left && left->bank == RegisterBank::arm64_zero && valid_gpr(right))
                    source = right;
                else if (destination && right && right->bank == RegisterBank::arm64_zero && valid_gpr(left))
                    source = left;
                std::optional<Address> value;
                if (valid_gpr(destination) && source && destination->width == source->width && no_shift) {
                    if (const auto found = registers.find(source->index); found != registers.end() &&
                        found->second.space == instruction.address.space) {
                        auto offset = found->second.offset;
                        if (destination->width == 32)
                            offset &= UINT64_C(0xffffffff);
                        value = Address{found->second.space, offset};
                    }
                }
                erase_written();
                if (destination && value)
                    registers[destination->index] = *value;
                propagated = true;
            }
            if (!propagated) {
                std::optional<std::pair<std::uint32_t, Address>> loaded_pointer;
                for (std::size_t i = 0; i < instruction.operands.size(); ++i) {
                    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[i]);
                    if (!memory || !memory->base || memory->base->bank != RegisterBank::arm64_gpr ||
                        memory->base->index == 31 || memory->base->width != 64 || i >= instruction.access.size())
                        continue;
                    const auto base = registers.find(memory->base->index);
                    if (base == registers.end() || base->second.space != instruction.address.space)
                        continue;
                    const auto add_magnitude = [](std::uint64_t value, std::uint64_t magnitude,
                                                  bool subtract) -> std::optional<std::uint64_t> {
                        if (subtract) {
                            if (magnitude > value) return {};
                            return value - magnitude;
                        }
                        if (magnitude > UINT64_MAX - value) return {};
                        return value + magnitude;
                    };
                    const auto add_displacement = [&](std::uint64_t value, std::int64_t displacement) {
                        const bool subtract = displacement < 0;
                        const auto magnitude = subtract
                            ? static_cast<std::uint64_t>(-(displacement + 1)) + 1
                            : static_cast<std::uint64_t>(displacement);
                        return add_magnitude(value, magnitude, subtract);
                    };
                    auto target_offset = add_displacement(base->second.offset, memory->displacement);
                    if (!target_offset)
                        continue;
                    if (memory->index) {
                        const auto &index = *memory->index;
                        if (memory->scale != 1 || memory->index_shift_amount >= 64 ||
                            (index.bank != RegisterBank::arm64_gpr && index.bank != RegisterBank::arm64_zero) ||
                            (index.width != 32 && index.width != 64) ||
                            (index.bank == RegisterBank::arm64_zero && index.index != 31) ||
                            (index.bank == RegisterBank::arm64_gpr && index.index == 31))
                            continue;
                        std::uint64_t raw_index = 0;
                        if (index.bank == RegisterBank::arm64_gpr) {
                            const auto known = registers.find(index.index);
                            if (known == registers.end() || known->second.space != instruction.address.space)
                                continue;
                            raw_index = known->second.offset;
                        }
                        bool negative_index = false;
                        std::uint64_t index_magnitude = 0;
                        if (memory->index_extend == "sxtw") {
                            if (index.width != 32) continue;
                            const auto signed_index = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(raw_index));
                            negative_index = signed_index < 0;
                            index_magnitude = negative_index
                                ? static_cast<std::uint64_t>(-(static_cast<std::int64_t>(signed_index) + 1)) + 1
                                : static_cast<std::uint64_t>(signed_index);
                        } else if (memory->index_extend == "sxtx") {
                            if (index.width != 64) continue;
                            const auto signed_index = std::bit_cast<std::int64_t>(raw_index);
                            negative_index = signed_index < 0;
                            index_magnitude = negative_index
                                ? static_cast<std::uint64_t>(-(signed_index + 1)) + 1
                                : static_cast<std::uint64_t>(signed_index);
                        } else if (memory->index_extend == "uxtw") {
                            if (index.width != 32) continue;
                            index_magnitude = static_cast<std::uint32_t>(raw_index);
                        } else if (memory->index_extend.empty()) {
                            if (index.width != 64) continue; // UXTX
                            index_magnitude = raw_index;
                        } else {
                            continue;
                        }
                        if (index_magnitude > (UINT64_MAX >> memory->index_shift_amount))
                            continue;
                        index_magnitude <<= memory->index_shift_amount;
                        target_offset = add_magnitude(*target_offset, index_magnitude, negative_index);
                        if (!target_offset)
                            continue;
                    }
                    const auto target = *target_offset;
                    const auto access_width = std::max<std::uint64_t>(1, (memory->data_width + 7) / 8);
                    const Address address{base->second.space, target};
                    if (riscv_target_segment(*image, address, instruction.access[i], access_width)) {
                        result.memory_targets[{fact->id, static_cast<std::uint32_t>(i)}] = address;
                        const auto *destination = architecture_register(instruction, 0, RegisterBank::arm64_gpr, 64);
                        const bool destination_written = destination && destination->index != 31 &&
                            std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                                [&](const RegisterOperand &written) {
                                    return written.bank == destination->bank && written.index == destination->index;
                                });
                        if (instruction.opcode == Opcode::a64_ldr && instruction.access[i] == OperandAccess::read &&
                            memory->data_width == 64 && destination_written)
                            if (const auto value = static_pointer_load(*image, relocations, address, 64))
                                loaded_pointer = std::pair{destination->index, *value};
                    }
                }
                erase_written();
                if (loaded_pointer)
                    registers[loaded_pointer->first] = loaded_pointer->second;
            }
            if (instruction.flow == FlowKind::call)
                registers.clear(); // BL/BLR callees may clobber every propagated GPR.
        }
        return registers;
    };
    propagate_cfg_register_values<RegisterState>(functions, stop, result, process_block);
    return result;
}
RegisterReferenceFacts mips_reference_facts(const Image *image, const RelocationCoverage &relocations,
                                            const FunctionSnapshot &functions, std::stop_token stop) {
    RegisterReferenceFacts result;
    if (!image)
        return result;
    using RegisterState = std::unordered_map<std::uint32_t, Address>;
    const auto process_block = [&](const BasicBlock &block, RegisterState registers) {
        for (const auto &fact : block.instructions) {
            reference_detail::canceled(stop);
            if (!fact)
                continue;
            const auto &instruction = fact->instruction;
            const bool mips32 = instruction.context.architecture == Architecture::mips32 &&
                                instruction.context.mode == ExecutionMode::mips32;
            const bool mips64 = instruction.context.architecture == Architecture::mips64 &&
                                instruction.context.mode == ExecutionMode::mips64;
            if (!mips32 && !mips64) {
                registers.clear();
                continue;
            }
            const auto width = static_cast<std::uint8_t>(mips64 ? 64 : 32);
            const auto *address_space = image->space(instruction.address.space);
            if (!address_space || address_space->width_bits < width) {
                registers.clear();
                continue;
            }
            const auto erase_written = [&] {
                for (const auto &reg : instruction.register_writes)
                    if (reg.bank == RegisterBank::mips_gpr && reg.index != 0)
                        registers.erase(reg.index);
            };
            // MIPS HI16/LO16 and other instruction relocations are not
            // currently solved as semantic pairs. Never treat their encoded
            // immediate bits as a complete address; unsupported, incomplete,
            // or ambiguous relocation records remain opaque.
            if (mips64 && relocations.overlaps(instruction.address, instruction.length)) {
                erase_written();
                if (instruction.flow == FlowKind::call) registers.clear();
                if (mips64)
                    if (const auto link = reference_detail::mips64_link_value(*image, instruction))
                        registers[link->first] = link->second;
                continue;
            }
            std::optional<Address> indirect_target;
            if (instruction.opcode == Opcode::mips_jr || instruction.opcode == Opcode::mips_jalr) {
                const auto *target_register = architecture_register(instruction, 0, RegisterBank::mips_gpr, width);
                if (target_register) {
                    const auto target = registers.find(target_register->index);
                    if (target != registers.end() && target->second.space == instruction.address.space &&
                        (target->second.offset & 3) == 0) {
                        const auto *segment = image->segment_at(target->second);
                        if (segment && segment->executable && target->second.offset >= segment->begin.offset &&
                            target->second.offset - segment->begin.offset < segment->size)
                            indirect_target = target->second;
                    }
                }
            }
            bool propagated = false;
            if (instruction.opcode == Opcode::mips_lui && instruction.operands.size() == 2) {
                const auto *dst = architecture_register(instruction, 0, RegisterBank::mips_gpr, width);
                const auto immediate = immediate_value(instruction, 1);
                erase_written();
                if (dst && dst->index != 0 && immediate) {
                    auto value = (*immediate << 16) & UINT64_C(0xffffffff);
                    if (mips64) value = static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(value)));
                    const Address target{instruction.address.space, value};
                    registers[dst->index] = target;
                    if (riscv_target_segment(*image, target, OperandAccess::address))
                        result.immediate_targets[{fact->id, 1}] = target;
                }
                propagated = true;
            } else if (((!mips64 && (instruction.opcode == Opcode::mips_addi ||
                                     instruction.opcode == Opcode::mips_addiu || instruction.opcode == Opcode::mips_ori)) ||
                        (mips64 && (instruction.opcode == Opcode::mips64_addi || instruction.opcode == Opcode::mips64_addiu ||
                                    instruction.opcode == Opcode::mips64_daddiu || instruction.opcode == Opcode::mips_ori))) &&
                       instruction.operands.size() == 3) {
                const auto *dst = architecture_register(instruction, 0, RegisterBank::mips_gpr, width);
                const auto *src = architecture_register(instruction, 1, RegisterBank::mips_gpr, width);
                const auto immediate = immediate_value(instruction, 2);
                std::optional<Address> target;
                if (dst && dst->index != 0 && src && immediate) {
                    const auto base = src->index ? registers.find(src->index) : registers.end();
                    if ((base != registers.end() && base->second.space == instruction.address.space) || src->index == 0) {
                        const auto base_value = base == registers.end() ? std::uint64_t{0} : base->second.offset;
                        const auto space = base == registers.end() ? instruction.address.space : base->second.space;
                        const auto displacement = std::bit_cast<std::int64_t>(*immediate);
                        std::optional<std::uint64_t> address;
                        if (instruction.opcode == Opcode::mips_ori) {
                            address = base_value | *immediate;
                        } else if (mips64 && (instruction.opcode == Opcode::mips64_addi ||
                                              instruction.opcode == Opcode::mips64_addiu)) {
                            const auto base_word = static_cast<std::int32_t>(base_value);
                            const bool sign_extended_word =
                                static_cast<std::uint64_t>(static_cast<std::int64_t>(base_word)) == base_value;
                            const auto sum = static_cast<std::int64_t>(base_word) + displacement;
                            if (sign_extended_word &&
                                (instruction.opcode == Opcode::mips_addiu ||
                                 (sum >= INT32_MIN && sum <= INT32_MAX))) {
                                const auto word = static_cast<std::uint32_t>(sum);
                                address = static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(word)));
                            }
                        } else if (!mips64 && instruction.opcode == Opcode::mips_addi) {
                            const auto sum = static_cast<std::int64_t>(static_cast<std::int32_t>(base_value)) + displacement;
                            if (sum >= INT32_MIN && sum <= INT32_MAX)
                                address = static_cast<std::uint32_t>(sum);
                        } else {
                            address = riscv_add(base_value, displacement, width);
                        }
                        if (address) target = Address{space, width == 32 ? *address & UINT64_C(0xffffffff) : *address};
                    }
                }
                erase_written();
                if (dst && dst->index != 0 && target) {
                    registers[dst->index] = *target;
                    if (riscv_target_segment(*image, *target, OperandAccess::address))
                        result.immediate_targets[{fact->id, 2}] = *target;
                }
                propagated = true;
            } else if (mips64 && instruction.operands.size() == 3 &&
                       (instruction.opcode == Opcode::mips64_add || instruction.opcode == Opcode::mips64_addu ||
                        instruction.opcode == Opcode::mips64_sub || instruction.opcode == Opcode::mips64_subu ||
                        instruction.opcode == Opcode::mips64_daddu || instruction.opcode == Opcode::mips64_dsubu)) {
                const auto *dst = architecture_register(instruction, 0, RegisterBank::mips_gpr, 64);
                const auto *left = architecture_register(instruction, 1, RegisterBank::mips_gpr, 64);
                const auto *right = architecture_register(instruction, 2, RegisterBank::mips_gpr, 64);
                std::optional<Address> target;
                if (dst && dst->index != 0 && left && right) {
                    std::optional<Address> left_value, right_value;
                    if (left->index == 0) left_value = Address{instruction.address.space, 0};
                    else if (const auto found = registers.find(left->index); found != registers.end())
                        left_value = found->second;
                    if (right->index == 0) right_value = Address{instruction.address.space, 0};
                    else if (const auto found = registers.find(right->index); found != registers.end())
                        right_value = found->second;
                    if (left_value && right_value && left_value->space == instruction.address.space &&
                        right_value->space == instruction.address.space) {
                        const bool subtract = instruction.opcode == Opcode::mips64_sub ||
                                              instruction.opcode == Opcode::mips64_subu ||
                                              instruction.opcode == Opcode::mips64_dsubu;
                        const bool word = instruction.opcode == Opcode::mips64_add ||
                                          instruction.opcode == Opcode::mips64_addu ||
                                          instruction.opcode == Opcode::mips64_sub ||
                                          instruction.opcode == Opcode::mips64_subu;
                        if (word) {
                            const auto lhs = static_cast<std::int32_t>(left_value->offset);
                            const auto rhs = static_cast<std::int32_t>(right_value->offset);
                            const auto wide = subtract ? static_cast<std::int64_t>(lhs) - rhs :
                                                        static_cast<std::int64_t>(lhs) + rhs;
                            const bool trapping = instruction.opcode == Opcode::mips64_add ||
                                                  instruction.opcode == Opcode::mips64_sub;
                            if (!trapping || (wide >= INT32_MIN && wide <= INT32_MAX)) {
                                const auto low = static_cast<std::uint32_t>(wide);
                                target = Address{instruction.address.space,
                                    static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(low)))};
                            }
                        } else {
                            const auto lhs = left_value->offset, rhs = right_value->offset;
                            if (!subtract && lhs <= UINT64_MAX - rhs)
                                target = Address{instruction.address.space, lhs + rhs};
                            else if (subtract && lhs >= rhs)
                                target = Address{instruction.address.space, lhs - rhs};
                        }
                    }
                }
                erase_written();
                if (dst && dst->index != 0 && target) {
                    registers[dst->index] = *target;
                    if (riscv_target_segment(*image, *target, OperandAccess::address))
                        result.immediate_targets[{fact->id, 2}] = *target;
                }
                propagated = true;
            } else if (mips64 && (instruction.opcode == Opcode::mips64_dsll ||
                                  instruction.opcode == Opcode::mips64_dsll32) && instruction.operands.size() == 3) {
                const auto *dst = architecture_register(instruction, 0, RegisterBank::mips_gpr, 64);
                const auto *src = architecture_register(instruction, 1, RegisterBank::mips_gpr, 64);
                const auto shift = immediate_value(instruction, 2);
                std::optional<Address> target;
                if (dst && dst->width == 64 && dst->index != 0 && src && src->width == 64 &&
                    shift && *shift < 64) {
                    const auto base = registers.find(src->index);
                    if (base != registers.end() && base->second.space == instruction.address.space &&
                        (*shift == 0 || base->second.offset <= (UINT64_MAX >> *shift)))
                        target = Address{base->second.space, base->second.offset << *shift};
                }
                erase_written();
                if (dst && dst->index != 0 && target) {
                    registers[dst->index] = *target;
                    if (riscv_target_segment(*image, *target, OperandAccess::address))
                        result.immediate_targets[{fact->id, 2}] = *target;
                }
                propagated = true;
            }
            if (!propagated) {
                std::optional<std::pair<std::uint32_t, Address>> loaded_pointer;
                for (std::size_t i = 0; i < instruction.operands.size(); ++i) {
                    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[i]);
                    if (!memory || !memory->base || memory->base->bank != RegisterBank::mips_gpr ||
                        memory->base->index == 0 || memory->base->width != width || i >= instruction.access.size())
                        continue;
                    const auto base = registers.find(memory->base->index);
                    if (base == registers.end() || base->second.space != instruction.address.space)
                        continue;
                    const Address target{base->second.space, riscv_add(base->second.offset, memory->displacement, width)};
                    const auto access_width = std::max<std::uint64_t>(1, (memory->data_width + 7) / 8);
                    if (riscv_target_segment(*image, target, instruction.access[i], access_width)) {
                        result.memory_targets[{fact->id, static_cast<std::uint32_t>(i)}] = target;
                        const auto *destination = architecture_register(instruction, 0, RegisterBank::mips_gpr, width);
                        const bool destination_written = destination && destination->index != 0 &&
                            std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                                [&](const RegisterOperand &written) {
                                    return written.bank == destination->bank && written.index == destination->index;
                                });
                        const bool pointer_load = (mips32 && instruction.opcode == Opcode::mips_lw) ||
                                                  (mips64 && instruction.opcode == Opcode::mips64_ld);
                        if (pointer_load && instruction.access[i] == OperandAccess::read &&
                            memory->data_width == width && destination_written)
                            if (const auto value = static_pointer_load(*image, relocations, target, width))
                                loaded_pointer = std::pair{destination->index, *value};
                    }
                }
                erase_written();
                if (loaded_pointer)
                    registers[loaded_pointer->first] = loaded_pointer->second;
            }
            if (indirect_target) result.immediate_targets[{fact->id, 0}] = *indirect_target;
            if (instruction.flow == FlowKind::call) registers.clear();
            if (mips64)
                if (const auto link = reference_detail::mips64_link_value(*image, instruction))
                    registers[link->first] = link->second;
        }
        return registers;
    };
    propagate_cfg_register_values<RegisterState>(functions, stop, result, process_block);
    return result;
}

RegisterReferenceFacts powerpc_reference_facts(const Image *image, const RelocationCoverage &relocations,
                                               const FunctionSnapshot &functions, std::stop_token stop) {
    RegisterReferenceFacts result;
    if (!image) return result;
    using RegisterState = std::unordered_map<std::uint32_t, Address>;
    const auto add = [](std::uint64_t base, std::uint64_t index, std::int64_t displacement, std::uint8_t width) {
        const auto value = base + index + static_cast<std::uint64_t>(displacement);
        return width == 32 ? value & UINT64_C(0xffffffff) : value;
    };
    const auto process_block = [&](const BasicBlock &block, RegisterState registers) {
        for (const auto &fact : block.instructions) {
            reference_detail::canceled(stop);
            if (!fact) continue;
            const auto &instruction = fact->instruction;
            const bool ppc32 = instruction.context.architecture == Architecture::powerpc &&
                               instruction.context.mode == ExecutionMode::ppc32;
            const bool ppc64 = instruction.context.architecture == Architecture::powerpc &&
                               instruction.context.mode == ExecutionMode::ppc64;
            if (!ppc32 && !ppc64) { registers.clear(); continue; }
            const auto width = static_cast<std::uint8_t>(ppc64 ? 64 : 32);
            const auto *address_space = image->space(instruction.address.space);
            if (!address_space || address_space->width_bits < width) { registers.clear(); continue; }
            const auto erase_written = [&] {
                for (const auto &reg : instruction.register_writes)
                    if (reg.bank == RegisterBank::ppc_gpr) registers.erase(reg.index);
            };
            bool propagated = false;
            if ((instruction.opcode == Opcode::ppc_addi || instruction.opcode == Opcode::ppc_addis) &&
                instruction.operands.size() == 3) {
                const auto *dst = architecture_register(instruction, 0, RegisterBank::ppc_gpr, width);
                const auto immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
                std::optional<Address> target;
                if (dst && dst->width == width && immediate && immediate->is_signed &&
                    immediate->encoded_width == 16 && immediate->effective_width == width) {
                    std::uint64_t base_value = 0;
                    AddressSpaceId space = instruction.address.space;
                    bool known = false;
                    if (const auto *src = std::get_if<RegisterOperand>(&instruction.operands[1])) {
                        if (src->bank == RegisterBank::ppc_gpr && src->width == width) {
                            if (const auto base = registers.find(src->index); base != registers.end()) {
                                if (base->second.space == instruction.address.space) {
                                    base_value = base->second.offset; space = base->second.space; known = true;
                                }
                            }
                        }
                    } else if (const auto *zero = std::get_if<ImmediateOperand>(&instruction.operands[1]);
                               zero && zero->value == 0) known = true;
                    if (known) {
                        // Decoder immediates are normalized to their semantic
                        // values, including ADDIS's 16-bit shift.
                        target = Address{space, add(base_value, 0,
                            std::bit_cast<std::int64_t>(immediate->value), width)};
                    }
                }
                erase_written();
                if (dst && target) {
                    registers[dst->index] = *target;
                    if (riscv_target_segment(*image, *target, OperandAccess::address))
                        result.immediate_targets[{fact->id, 2}] = *target;
                }
                propagated = true;
            } else if ((instruction.opcode == Opcode::ppc_add || instruction.opcode == Opcode::ppc_add_dot ||
                        instruction.opcode == Opcode::ppc_subf || instruction.opcode == Opcode::ppc_subf_dot) &&
                       instruction.operands.size() == 3) {
                const auto *dst = architecture_register(instruction, 0, RegisterBank::ppc_gpr, width);
                const auto *left = architecture_register(instruction, 1, RegisterBank::ppc_gpr, width);
                const auto *right = architecture_register(instruction, 2, RegisterBank::ppc_gpr, width);
                std::optional<Address> target;
                if (dst && dst->width == width && left && left->width == width &&
                    right && right->width == width) {
                    const auto lhs = registers.find(left->index);
                    const auto rhs = registers.find(right->index);
                    if (lhs != registers.end() && rhs != registers.end() &&
                        lhs->second.space == instruction.address.space &&
                        rhs->second.space == instruction.address.space) {
                        const bool subtract = instruction.opcode == Opcode::ppc_subf ||
                                              instruction.opcode == Opcode::ppc_subf_dot;
                        // SUBF computes RB - RA. PowerPC integer arithmetic
                        // wraps at the active GPR width.
                        const auto value = subtract ? rhs->second.offset - lhs->second.offset :
                                                      lhs->second.offset + rhs->second.offset;
                        target = Address{instruction.address.space,
                                         width == 32 ? value & UINT64_C(0xffffffff) : value};
                    }
                }
                erase_written();
                if (dst && target) {
                    registers[dst->index] = *target;
                    result.address_definitions.insert(fact->id);
                }
                propagated = true;
            } else if ((instruction.opcode == Opcode::ppc_ori || instruction.opcode == Opcode::ppc_oris) &&
                       instruction.operands.size() == 3) {
                const auto *dst = architecture_register(instruction, 0, RegisterBank::ppc_gpr, width);
                const auto *src = architecture_register(instruction, 1, RegisterBank::ppc_gpr, width);
                const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
                std::optional<Address> target;
                if (dst && dst->width == width && src && src->width == width &&
                    immediate && !immediate->is_signed && immediate->encoded_width == 16 &&
                    immediate->effective_width == width) {
                    if (const auto base = registers.find(src->index);
                        base != registers.end() && base->second.space == instruction.address.space)
                        // ORIS is likewise decoded with its immediate already
                        // shifted into the high halfword.
                        target = Address{base->second.space, base->second.offset | immediate->value};
                }
                erase_written();
                if (dst && target) {
                    registers[dst->index] = *target;
                    if (riscv_target_segment(*image, *target, OperandAccess::address))
                        result.immediate_targets[{fact->id, 2}] = *target;
                }
                propagated = true;
            }

            std::optional<std::pair<std::uint32_t, Address>> loaded_pointer;
            std::optional<std::pair<std::uint32_t, Address>> update_base;
            if (!propagated) {
                for (std::size_t i = 0; i < instruction.operands.size(); ++i) {
                    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[i]);
                    if (!memory || i >= instruction.access.size() || memory->address_width != width ||
                        memory->scale != 1 || memory->data_width == 0 || memory->data_width > width)
                        continue;
                    std::uint64_t base_value = 0, index_value = 0;
                    AddressSpaceId space = instruction.address.space;
                    bool known = true;
                    if (memory->base) {
                        if (memory->base->bank != RegisterBank::ppc_gpr || memory->base->width != width) known = false;
                        else if (const auto base = registers.find(memory->base->index); base != registers.end()) {
                            if (base->second.space == instruction.address.space) {
                                base_value = base->second.offset; space = base->second.space;
                            } else known = false;
                        } else known = false;
                    }
                    if (memory->index) {
                        if (memory->index->bank != RegisterBank::ppc_gpr || memory->index->width != width) known = false;
                        else if (const auto index = registers.find(memory->index->index); index != registers.end()) {
                            if (index->second.space != instruction.address.space ||
                                (memory->base && index->second.space != space)) known = false;
                            index_value = index->second.offset;
                        } else known = false;
                    }
                    if (!known) continue;
                    const Address address{space, add(base_value, index_value, memory->displacement, width)};
                    const auto access_width = std::max<std::uint64_t>(1, (memory->data_width + 7) / 8);
                    const auto access = instruction.memory_read && instruction.memory_write
                        ? OperandAccess::read_write
                        : instruction.memory_read ? OperandAccess::read
                        : instruction.memory_write ? OperandAccess::write : instruction.access[i];
                    if (!riscv_target_segment(*image, address, access, access_width)) continue;
                    result.memory_targets[{fact->id, static_cast<std::uint32_t>(i)}] = address;

                    const bool full_load = instruction.memory_read && !instruction.memory_write &&
                                           memory->data_width == width;
                    const auto *destination = architecture_register(instruction, 0, RegisterBank::ppc_gpr, width);
                    const bool destination_written = destination &&
                        std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                            [&](const RegisterOperand &written) {
                                return written.bank == RegisterBank::ppc_gpr && written.index == destination->index;
                            });
                    if (full_load && destination_written)
                        if (const auto value = static_pointer_load(*image, relocations, address, width))
                            loaded_pointer = std::pair{destination->index, *value};

                    if (memory->base) {
                        const bool update = std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                            [&](const RegisterOperand &written) {
                                return written.bank == RegisterBank::ppc_gpr && written.index == memory->base->index;
                            });
                        if (update) update_base = std::pair{memory->base->index, address};
                    }
                }
                erase_written();
                if (update_base) registers[update_base->first] = update_base->second;
                if (loaded_pointer) registers[loaded_pointer->first] = loaded_pointer->second;
            } else {
                // The arithmetic above already removed stale destination facts.
            }
            if (instruction.flow == FlowKind::call) registers.clear();
        }
        return registers;
    };
    propagate_cfg_register_values<RegisterState>(functions, stop, result, process_block);
    return result;
}
RegisterReferenceFacts arm_reference_facts(const Image *image, const RelocationCoverage &relocations,
                                           const FunctionSnapshot &functions, std::stop_token stop) {
    RegisterReferenceFacts result;
    if (!image)
        return result;
    using RegisterKey = std::pair<ExecutionMode, std::uint32_t>;
    using RegisterState = std::map<RegisterKey, Address>;
    constexpr std::uint32_t carry_fact_register = 16;
    constexpr std::uint32_t negative_fact_register = 17;
    constexpr std::uint32_t zero_fact_register = 18;
    constexpr std::uint32_t overflow_fact_register = 19;
    constexpr std::array<std::pair<std::uint8_t, std::uint32_t>, 4> arm_flag_facts{{
        {std::uint8_t{8}, negative_fact_register}, {std::uint8_t{4}, zero_fact_register},
        {std::uint8_t{2}, carry_fact_register}, {std::uint8_t{1}, overflow_fact_register}}};
    const auto arm_flag_value = [&](const RegisterState &state, ExecutionMode mode, Address at,
                                    std::uint8_t mask) -> std::optional<bool> {
        const auto fact_key = std::find_if(arm_flag_facts.begin(), arm_flag_facts.end(),
            [&](const auto &entry) { return entry.first == mask; });
        if (fact_key == arm_flag_facts.end()) return {};
        const auto found = state.find({mode, fact_key->second});
        if (found == state.end() || found->second.space != at.space || found->second.offset > 1)
            return {};
        return found->second.offset != 0;
    };
    const auto arm_condition_from_flags = [](std::uint8_t condition, const Arm32Nzcv &flags)
        -> std::optional<bool> {
        switch (condition) {
        case 0: return flags.z;                          // EQ
        case 1: return !flags.z;                         // NE
        case 2: return flags.c;                          // CS/HS
        case 3: return !flags.c;                         // CC/LO
        case 4: return flags.n;                          // MI
        case 5: return !flags.n;                         // PL
        case 6: return flags.v;                          // VS
        case 7: return !flags.v;                         // VC
        case 8: return flags.c && !flags.z;              // HI
        case 9: return !flags.c || flags.z;              // LS
        case 10: return flags.n == flags.v;              // GE
        case 11: return flags.n != flags.v;              // LT
        case 12: return !flags.z && flags.n == flags.v;  // GT
        case 13: return flags.z || flags.n != flags.v;   // LE
        default: return {};
        }
    };
    const auto arm_condition_value = [&](const Instruction &instruction, const RegisterState &state)
        -> std::optional<bool> {
        if (!instruction.arm || instruction.arm->predicate != ArmPredicate::condition ||
            instruction.condition >= 14)
            return {};
        const std::array<std::optional<bool>, 4> known{
            arm_flag_value(state, instruction.context.mode, instruction.address, 8),
            arm_flag_value(state, instruction.context.mode, instruction.address, 4),
            arm_flag_value(state, instruction.context.mode, instruction.address, 2),
            arm_flag_value(state, instruction.context.mode, instruction.address, 1)};
        std::optional<bool> outcome;
        for (unsigned candidate = 0; candidate < 16; ++candidate) {
            const Arm32Nzcv flags{(candidate & 8) != 0, (candidate & 4) != 0,
                                  (candidate & 2) != 0, (candidate & 1) != 0};
            const std::array<bool, 4> values{flags.n, flags.z, flags.c, flags.v};
            bool compatible = true;
            for (std::size_t bit = 0; bit < known.size(); ++bit)
                if (known[bit] && *known[bit] != values[bit]) { compatible = false; break; }
            if (!compatible) continue;
            const auto candidate_outcome = arm_condition_from_flags(instruction.condition, flags);
            if (!candidate_outcome || (outcome && *outcome != *candidate_outcome)) return {};
            outcome = candidate_outcome;
        }
        return outcome;
    };
    const auto arm_pc_target = [&](const Instruction &instruction, std::uint32_t raw_value)
        -> std::optional<std::pair<Address, ExecutionMode>> {
        if (!instruction.arm) return {};
        auto target_mode = instruction.arm->target_mode.value_or(instruction.context.mode);
        switch (instruction.arm->exchange) {
        case ArmExchange::address_bit0:
            // BXWritePC reserves 0b10 for an unpredictable A32 target.
            if ((raw_value & 3u) == 2u) return {};
            target_mode = (raw_value & 1u) ? ExecutionMode::thumb : ExecutionMode::a32;
            break;
        case ArmExchange::forced_a32: target_mode = ExecutionMode::a32; break;
        case ArmExchange::forced_thumb: target_mode = ExecutionMode::thumb; break;
        case ArmExchange::none: break;
        }
        if (target_mode != ExecutionMode::a32 && target_mode != ExecutionMode::thumb) return {};
        const auto aligned = target_mode == ExecutionMode::thumb
                                 ? (raw_value & ~UINT32_C(1))
                                 : (raw_value & ~UINT32_C(3));
        const Address target{instruction.address.space, aligned};
        const auto *segment = image->segment_at(target);
        if (!segment || !segment->executable || target.offset < segment->begin.offset ||
            target.offset - segment->begin.offset >= segment->size)
            return {};
        const auto context = image->context_at(target);
        if (!context || context.value().mode != target_mode) return {};
        return std::pair{target, target_mode};
    };
    const auto process_block = [&](const BasicBlock &block, RegisterState registers) {
        for (const auto &fact : block.instructions) {
            reference_detail::canceled(stop);
            if (!fact)
                continue;
            const auto &instruction = fact->instruction;
            const bool arm_mode = instruction.context.architecture == Architecture::arm &&
                                  (instruction.context.mode == ExecutionMode::a32 ||
                                   instruction.context.mode == ExecutionMode::thumb);
            if (!arm_mode) {
                registers.clear();
                continue;
            }
            const auto mode = instruction.context.mode;
            for (auto value = registers.begin(); value != registers.end();) {
                if (value->first.first != mode)
                    value = registers.erase(value);
                else
                    ++value;
            }
            const RegisterKey carry_key{mode, carry_fact_register};
            const auto current_carry = [&]() -> std::optional<bool> {
                const auto found = registers.find(carry_key);
                if (found == registers.end() || found->second.space != instruction.address.space ||
                    found->second.offset > 1)
                    return {};
                return found->second.offset != 0;
            };
            const auto current_flag = [&](std::uint8_t mask) {
                return arm_flag_value(registers, mode, instruction.address, mask);
            };
            std::optional<bool> predicate_executes;
            if (instruction.arm) {
                if (instruction.arm->predicate == ArmPredicate::always) {
                    predicate_executes = true;
                } else if (instruction.arm->predicate == ArmPredicate::condition)
                    predicate_executes = arm_condition_value(instruction, registers);
            }
            // A known-false predicated instruction has no architectural effects.
            // Preserve all facts through it; unknown predicates retain the
            // conservative write invalidation below.
            if (predicate_executes == false)
                continue;
            if ((instruction.flow == FlowKind::call || instruction.flow == FlowKind::jump) &&
                (instruction.opcode == Opcode::a32_bx || instruction.opcode == Opcode::a32_blx ||
                 instruction.opcode == Opcode::t32_bx || instruction.opcode == Opcode::t32_blx)) {
                const auto control = analysis_detail::control_operand_index(instruction);
                const auto *target_register = control < instruction.operands.size()
                                                  ? std::get_if<RegisterOperand>(&instruction.operands[control])
                                                  : nullptr;
                if (target_register && target_register->bank == RegisterBank::arm32_gpr &&
                    target_register->width == 32 && target_register->index != 15) {
                    const auto found = registers.find({mode, target_register->index});
                    if (found != registers.end() && found->second.space == instruction.address.space) {
                        if (const auto target = arm_pc_target(instruction,
                                static_cast<std::uint32_t>(found->second.offset))) {
                            const ReferenceOperandKey key{fact->id, control};
                            result.immediate_targets[key] = target->first;
                            result.target_modes[key] = target->second;
                        }
                    }
                }
            }
            std::optional<std::pair<std::uint32_t, Address>> definition;
            const bool arm_instruction_unconditional = predicate_executes == true;
            const auto arm_register_value = [&](const RegisterOperand &reg) -> std::optional<std::uint32_t> {
                if (reg.bank != RegisterBank::arm32_gpr || reg.width != 32 || reg.index == 15)
                    return {};
                const auto found = registers.find({mode, reg.index});
                if (found == registers.end() || found->second.space != instruction.address.space)
                    return {};
                return static_cast<std::uint32_t>(found->second.offset);
            };
            const auto arm_operand2_value = [&](const Operand &operand) -> std::optional<std::uint32_t> {
                if (const auto *immediate = std::get_if<ImmediateOperand>(&operand)) {
                    if (immediate->effective_width > 32)
                        return {};
                    return static_cast<std::uint32_t>(immediate->value);
                }
                if (const auto *reg = std::get_if<RegisterOperand>(&operand))
                    return arm_register_value(*reg);
                const auto *shifted = std::get_if<ArmShiftedRegisterOperand>(&operand);
                if (!shifted)
                    return {};
                auto value = arm_register_value(shifted->source);
                if (!value)
                    return {};
                const bool register_shift = shifted->amount_register.has_value();
                std::uint32_t amount = shifted->amount;
                if (register_shift) {
                    const auto runtime = arm_register_value(*shifted->amount_register);
                    if (!runtime)
                        return {};
                    amount = *runtime & 0xff;
                    if (!amount)
                        return value;
                }
                switch (shifted->shift) {
                case ArmShift::lsl:
                    return amount >= 32 ? 0u : static_cast<std::uint32_t>(*value << amount);
                case ArmShift::lsr:
                    if (!amount) {
                        if (register_shift)
                            return value;
                        amount = 32;
                    }
                    return amount >= 32 ? 0u : static_cast<std::uint32_t>(*value >> amount);
                case ArmShift::asr:
                    if (!amount) {
                        if (register_shift)
                            return value;
                        amount = 32;
                    }
                    if (amount >= 32)
                        return (*value & 0x80000000u) ? UINT32_MAX : 0u;
                    return static_cast<std::uint32_t>(std::bit_cast<std::int32_t>(*value) >> amount);
                case ArmShift::ror: {
                    const auto rotate = amount & 31;
                    return rotate ? std::rotr(*value, static_cast<int>(rotate)) : *value;
                }
                case ArmShift::rrx:
                    if (const auto carry = current_carry())
                        return (static_cast<std::uint32_t>(*carry) << 31) | (*value >> 1);
                    return {};
                }
                return {};
            };
            const auto tracked = [&](std::uint32_t index) -> std::optional<Address> {
                const auto found = registers.find({mode, index});
                if (found == registers.end() || found->second.space != instruction.address.space)
                    return {};
                return found->second;
            };
            const bool known_pc_predicate = instruction.arm &&
                (instruction.arm->predicate == ArmPredicate::always ||
                 (instruction.arm->predicate == ArmPredicate::condition && instruction.condition < 14));
            const bool pc_write_may_execute = instruction.arm && instruction.arm->writes_pc &&
                known_pc_predicate && predicate_executes != false;
            if (instruction.opcode == Opcode::t32_adr && instruction.operands.size() >= 2) {
                const auto *destination = architecture_register(instruction, 0, RegisterBank::arm32_gpr, 32);
                const auto *literal = std::get_if<ArmMemoryOperand>(&instruction.operands[1]);
                if (arm_instruction_unconditional && destination && destination->index != 15 && literal && literal->resolved_address &&
                    riscv_target_segment(*image, *literal->resolved_address, OperandAccess::address))
                    definition = {{destination->index, *literal->resolved_address}};
            } else if (instruction.opcode == Opcode::a32_mov && instruction.operands.size() == 2) {
                const auto *destination = architecture_register(instruction, 0, RegisterBank::arm32_gpr, 32);
                if (destination) {
                    if (const auto operand2 = arm_operand2_value(instruction.operands[1])) {
                        if (destination->index == 15 && pc_write_may_execute) {
                            if (const auto target = arm_pc_target(instruction, *operand2)) {
                                const ReferenceOperandKey key{fact->id,
                                    analysis_detail::control_operand_index(instruction)};
                                result.immediate_targets[key] = target->first;
                                result.target_modes[key] = target->second;
                            }
                        } else if (arm_instruction_unconditional && destination->index != 15) {
                            definition = {{destination->index, Address{instruction.address.space, *operand2}}};
                            const Address target{instruction.address.space, *operand2};
                            if (std::holds_alternative<ImmediateOperand>(instruction.operands[1]) &&
                                riscv_target_segment(*image, target, OperandAccess::address))
                                result.immediate_targets[{fact->id, 1}] = target;
                        }
                    }
                }
            } else if (instruction.opcode == Opcode::a32_mvn && instruction.operands.size() == 2) {
                const auto *destination = architecture_register(instruction, 0, RegisterBank::arm32_gpr, 32);
                if (destination) {
                    if (const auto operand2 = arm_operand2_value(instruction.operands[1])) {
                        const auto value = static_cast<std::uint32_t>(~*operand2);
                        if (destination->index == 15 && pc_write_may_execute) {
                            if (const auto target = arm_pc_target(instruction, value)) {
                                const ReferenceOperandKey key{fact->id,
                                    analysis_detail::control_operand_index(instruction)};
                                result.immediate_targets[key] = target->first;
                                result.target_modes[key] = target->second;
                            }
                        } else if (arm_instruction_unconditional && destination->index != 15) {
                            definition = {{destination->index, Address{instruction.address.space, value}}};
                            const Address target{instruction.address.space, value};
                            if (std::holds_alternative<ImmediateOperand>(instruction.operands[1]) &&
                                riscv_target_segment(*image, target, OperandAccess::address))
                                result.immediate_targets[{fact->id, 1}] = target;
                        }
                    }
                }
            } else if (instruction.operands.size() == 3 &&
                       (instruction.opcode == Opcode::a32_add || instruction.opcode == Opcode::a32_sub ||
                        instruction.opcode == Opcode::a32_rsb || instruction.opcode == Opcode::a32_and ||
                        instruction.opcode == Opcode::a32_eor || instruction.opcode == Opcode::a32_orr ||
                        instruction.opcode == Opcode::a32_bic || instruction.opcode == Opcode::a32_adc ||
                        instruction.opcode == Opcode::a32_sbc || instruction.opcode == Opcode::a32_rsc)) {
                const auto *destination = architecture_register(instruction, 0, RegisterBank::arm32_gpr, 32);
                const auto *source = architecture_register(instruction, 1, RegisterBank::arm32_gpr, 32);
                const auto operand2 = arm_operand2_value(instruction.operands[2]);
                const auto carry = current_carry();
                const bool carry_arithmetic = instruction.opcode == Opcode::a32_adc ||
                                               instruction.opcode == Opcode::a32_sbc ||
                                               instruction.opcode == Opcode::a32_rsc;
                const bool pc_target_only = destination && destination->index == 15 && pc_write_may_execute;
                if ((arm_instruction_unconditional || pc_target_only) && destination && source && operand2 &&
                    (!carry_arithmetic || carry)) {
                    std::optional<Address> target;
                    if (carry_arithmetic && source->index != 15 && carry) {
                        const auto base = tracked(source->index);
                        if (base) {
                            const auto lhs = static_cast<std::uint32_t>(base->offset);
                            const std::uint32_t rhs = *operand2;
                            std::uint32_t value = 0;
                            switch (instruction.opcode) {
                            case Opcode::a32_adc: value = lhs + rhs + static_cast<std::uint32_t>(*carry); break;
                            case Opcode::a32_sbc: value = lhs - rhs - static_cast<std::uint32_t>(!*carry); break;
                            case Opcode::a32_rsc: value = rhs - lhs - static_cast<std::uint32_t>(!*carry); break;
                            default: continue;
                            }
                            target = Address{base->space, value};
                        }
                    } else if (source->index == 15 &&
                        (instruction.opcode == Opcode::a32_add || instruction.opcode == Opcode::a32_sub)) {
                        const auto pc_bias = instruction.context.mode == ExecutionMode::a32
                                                 ? UINT64_C(8)
                                                 : UINT64_C(4);
                        const auto pc = static_cast<std::uint32_t>(instruction.address.offset + pc_bias);
                        const auto value = instruction.opcode == Opcode::a32_add
                                               ? static_cast<std::uint32_t>(pc + *operand2)
                                               : static_cast<std::uint32_t>(pc - *operand2);
                        target = Address{instruction.address.space, value};
                    } else if (source->index != 15 && operand2) {
                        const auto base = tracked(source->index);
                        if (base) {
                            const auto lhs = static_cast<std::uint32_t>(base->offset);
                            std::uint32_t value = 0;
                            switch (instruction.opcode) {
                            case Opcode::a32_add: value = lhs + *operand2; break;
                            case Opcode::a32_sub: value = lhs - *operand2; break;
                            case Opcode::a32_rsb: value = *operand2 - lhs; break;
                            case Opcode::a32_and: value = lhs & *operand2; break;
                            case Opcode::a32_eor: value = lhs ^ *operand2; break;
                            case Opcode::a32_orr: value = lhs | *operand2; break;
                            case Opcode::a32_bic: value = lhs & ~*operand2; break;
                            default: continue;
                            }
                            target = Address{base->space, value};
                        }
                    }
                    if (target && destination->index == 15 && instruction.arm->writes_pc) {
                        if (const auto resolved = arm_pc_target(instruction,
                                static_cast<std::uint32_t>(target->offset))) {
                            const ReferenceOperandKey key{fact->id,
                                analysis_detail::control_operand_index(instruction)};
                            result.immediate_targets[key] = resolved->first;
                            result.target_modes[key] = resolved->second;
                        }
                    } else if (target && destination->index != 15 &&
                               riscv_target_segment(*image, *target, OperandAccess::address)) {
                        definition = {{destination->index, *target}};
                        if (std::holds_alternative<ImmediateOperand>(instruction.operands[2]))
                            result.immediate_targets[{fact->id, 2}] = *target;
                    }
                }
            }
            std::optional<std::pair<std::uint32_t, Address>> writeback_definition;
            std::optional<std::pair<std::uint32_t, Address>> loaded_pointer;
            if (instruction.opcode == Opcode::a32_ldm && instruction.arm && instruction.arm->writes_pc &&
                instruction.operands.size() >= 2) {
                const auto *base_register = architecture_register(
                    instruction, 0, RegisterBank::arm32_gpr, 32);
                const auto *list = std::get_if<ArmRegisterListOperand>(&instruction.operands[1]);
                if (base_register && list && (list->mask & 0x8000u)) {
                    const auto base = tracked(base_register->index);
                    if (base && base->offset <= UINT32_MAX) {
                        const auto count = std::popcount(list->mask);
                        std::int64_t pc_word_delta = 0;
                        switch (instruction.arm->multiple_mode) {
                        case ArmMultipleMode::ia: pc_word_delta = static_cast<std::int64_t>(count) - 1; break;
                        case ArmMultipleMode::ib: pc_word_delta = static_cast<std::int64_t>(count); break;
                        case ArmMultipleMode::da: pc_word_delta = 0; break;
                        case ArmMultipleMode::db: pc_word_delta = -1; break;
                        }
                        const auto slot_offset = static_cast<std::int64_t>(base->offset) + pc_word_delta * 4;
                        if (slot_offset >= 0 && slot_offset <= UINT32_MAX) {
                            const Address slot{base->space, static_cast<std::uint64_t>(slot_offset)};
                            if (const auto pointer = static_pointer_load(*image, relocations, slot, 32))
                                loaded_pointer = std::pair{std::uint32_t{15}, *pointer};
                        }
                    }
                }
            }
            for (std::size_t i = 0; i < instruction.operands.size() && i < instruction.access.size(); ++i) {
                const auto *memory = std::get_if<ArmMemoryOperand>(&instruction.operands[i]);
                if (!memory || memory->base.bank != RegisterBank::arm32_gpr || memory->base.width != 32)
                    continue;
                if (memory->base.index == 15) {
                    if (!memory->resolved_address)
                        continue;
                    const auto target = *memory->resolved_address;
                    const auto access_width = std::max<std::uint64_t>(1, (memory->data_width + 7) / 8);
                    if (mapped_data_range(*image, target, instruction.access[i], access_width))
                        result.memory_targets[{fact->id, static_cast<std::uint32_t>(i)}] = target;
                    const auto *destination = architecture_register(instruction, 0, RegisterBank::arm32_gpr, 32);
                    const bool destination_written = destination &&
                        std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                            [&](const RegisterOperand &written) {
                                return written.bank == RegisterBank::arm32_gpr && written.index == destination->index;
                            });
                    if (instruction.opcode == Opcode::a32_ldr && instruction.access[i] == OperandAccess::read &&
                        memory->data_width == 32 && !memory->sign_extend && destination_written)
                        if (const auto pointer = static_pointer_load(*image, relocations, target, 32))
                            loaded_pointer = std::pair{destination->index, *pointer};
                    continue;
                }
                const auto base = registers.find({mode, memory->base.index});
                if (base == registers.end())
                    continue;
                std::optional<std::uint32_t> displacement;
                if (const auto *immediate = std::get_if<std::uint32_t>(&memory->offset)) {
                    displacement = *immediate;
                } else if (const auto *shifted = std::get_if<ArmShiftedRegisterOperand>(&memory->offset)) {
                    const auto source = registers.find({mode, shifted->source.index});
                    if (shifted->source.bank != RegisterBank::arm32_gpr || shifted->source.width != 32 ||
                        source == registers.end())
                        continue;
                    auto value = static_cast<std::uint32_t>(source->second.offset);
                    std::uint32_t amount = shifted->amount;
                    if (shifted->amount_register) {
                        const auto amount_value = registers.find({mode, shifted->amount_register->index});
                        if (shifted->amount_register->bank != RegisterBank::arm32_gpr ||
                            amount_value == registers.end())
                            continue;
                        amount = static_cast<std::uint32_t>(amount_value->second.offset) & 0xff;
                    }
                    switch (shifted->shift) {
                    case ArmShift::lsl:
                        value = amount >= 32 ? 0 : static_cast<std::uint32_t>(value << amount);
                        break;
                    case ArmShift::lsr:
                        value = amount >= 32 ? 0 : value >> amount;
                        break;
                    case ArmShift::asr:
                        if (amount >= 32)
                            value = (value & 0x80000000u) ? UINT32_MAX : 0;
                        else if (amount)
                            value = static_cast<std::uint32_t>(static_cast<std::int32_t>(value) >> amount);
                        break;
                    case ArmShift::ror:
                        if (shifted->amount_register) {
                            if (amount) value = std::rotr(value, amount & 31);
                        } else {
                            if (!amount) continue; // ROR #0 is RRX and needs a proven carry flag.
                            value = std::rotr(value, amount & 31);
                        }
                        break;
                    case ArmShift::rrx:
                        if (const auto carry = current_carry())
                            value = (static_cast<std::uint32_t>(*carry) << 31) | (value >> 1);
                        else
                            continue;
                        break;
                    }
                    displacement = value;
                }
                if (!displacement)
                    continue;
                const auto low = static_cast<std::uint32_t>(base->second.offset);
                const auto offset = memory->add ? *displacement : static_cast<std::uint32_t>(0u - *displacement);
                const auto effective = static_cast<std::uint32_t>(low + offset);
                const Address target{base->second.space,
                                     memory->pre_index ? effective : low};
                const auto access_width = std::max<std::uint64_t>(1, (memory->data_width + 7) / 8);
                if (mapped_data_range(*image, target, instruction.access[i], access_width))
                    result.memory_targets[{fact->id, static_cast<std::uint32_t>(i)}] = target;
                const auto *destination = architecture_register(instruction, 0, RegisterBank::arm32_gpr, 32);
                const bool destination_written = destination &&
                    std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                        [&](const RegisterOperand &written) {
                            return written.bank == RegisterBank::arm32_gpr && written.index == destination->index;
                        });
                if (instruction.opcode == Opcode::a32_ldr && instruction.access[i] == OperandAccess::read &&
                    memory->data_width == 32 && !memory->sign_extend && destination_written)
                    if (const auto pointer = static_pointer_load(*image, relocations, target, 32))
                        loaded_pointer = std::pair{destination->index, *pointer};
                if (memory->writeback &&
                    riscv_target_segment(*image, {base->second.space, effective}, OperandAccess::address))
                    writeback_definition = {{memory->base.index,
                                             Address{base->second.space, effective}}};
            }
            std::array<std::optional<bool>, 4> updated_flags{};
            const bool flags_may_change = instruction.flow != FlowKind::call && instruction.arm &&
                (!instruction.arm->flags_known || instruction.arm->flags_written != 0);
            if (flags_may_change && instruction.arm->flags_known && instruction.arm->flags_written &&
                arm_instruction_unconditional && !instruction.arm->writes_pc) {
                const auto read_register = [&](const RegisterOperand &reg) { return arm_register_value(reg); };
                const std::array<std::optional<bool>, 4> known_flags{
                    current_flag(8), current_flag(4), current_flag(2), current_flag(1)};
                std::array<bool, 4> first_values{};
                std::array<bool, 4> have_values{};
                std::array<bool, 4> invariant{true, true, true, true};
                bool evaluated_any = false;
                for (unsigned candidate = 0; candidate < 16; ++candidate) {
                    const Arm32Nzcv incoming{
                        (candidate & 8) != 0, (candidate & 4) != 0,
                        (candidate & 2) != 0, (candidate & 1) != 0};
                    const std::array<bool, 4> candidate_flags{
                        incoming.n, incoming.z, incoming.c, incoming.v};
                    bool compatible = true;
                    for (std::size_t bit = 0; bit < known_flags.size(); ++bit)
                        if (known_flags[bit] && *known_flags[bit] != candidate_flags[bit]) {
                            compatible = false;
                            break;
                        }
                    if (!compatible) continue;
                    const auto evaluated = evaluate_arm32_nzcv_instruction(instruction, incoming, read_register);
                    evaluated_any = true;
                    const std::array<bool, 4> output_flags{
                        evaluated && evaluated->flags.n, evaluated && evaluated->flags.z,
                        evaluated && evaluated->flags.c, evaluated && evaluated->flags.v};
                    for (std::size_t bit = 0; bit < arm_flag_facts.size(); ++bit) {
                        if (!(instruction.arm->flags_written & arm_flag_facts[bit].first) ||
                            !evaluated || !(evaluated->flags_written & arm_flag_facts[bit].first)) {
                            invariant[bit] = false;
                            continue;
                        }
                        if (!have_values[bit]) {
                            first_values[bit] = output_flags[bit];
                            have_values[bit] = true;
                        } else if (first_values[bit] != output_flags[bit]) {
                            invariant[bit] = false;
                        }
                    }
                }
                if (evaluated_any)
                    for (std::size_t bit = 0; bit < arm_flag_facts.size(); ++bit)
                        if (invariant[bit] && have_values[bit]) updated_flags[bit] = first_values[bit];
            }
            for (const auto &written : instruction.register_writes)
                if (written.bank == RegisterBank::arm32_gpr && written.index != 15)
                    registers.erase({mode, written.index});
            if (instruction.flow == FlowKind::call)
                registers.clear();
            if (flags_may_change) {
                for (std::size_t bit = 0; bit < arm_flag_facts.size(); ++bit) {
                    const auto [mask, index] = arm_flag_facts[bit];
                    if (!instruction.arm->flags_known || (instruction.arm->flags_written & mask)) {
                        const RegisterKey key{mode, index};
                        registers.erase(key);
                        if (updated_flags[bit])
                            registers[key] = Address{instruction.address.space, *updated_flags[bit] ? 1u : 0u};
                    }
                }
            }
            if (definition) {
                registers[{mode, definition->first}] = definition->second;
                result.address_definitions.insert(fact->id);
            }
            if (writeback_definition)
                registers[{mode, writeback_definition->first}] = writeback_definition->second;
            if (loaded_pointer) {
                if (loaded_pointer->first == 15 && instruction.arm->writes_pc) {
                    if (const auto target = arm_pc_target(instruction,
                            static_cast<std::uint32_t>(loaded_pointer->second.offset))) {
                        const ReferenceOperandKey key{fact->id, 1};
                        result.immediate_targets[key] = target->first;
                        result.target_modes[key] = target->second;
                    }
                } else {
                    registers[{mode, loaded_pointer->first}] = loaded_pointer->second;
                }
            }
        }
        return registers;
    };
    const auto refine_arm_edge = [&](const BasicBlock &block, const BlockSuccessor &edge,
                                     RegisterState incoming) {
        if (edge.kind != BlockEdgeKind::conditional_true &&
            edge.kind != BlockEdgeKind::conditional_false)
            return incoming;
        const Instruction *branch = nullptr;
        for (const auto &fact : block.instructions)
            if (fact && fact->instruction.address == edge.source) {
                branch = &fact->instruction;
                break;
            }
        if (!branch || !branch->arm || branch->arm->predicate != ArmPredicate::condition ||
            branch->condition >= 14)
            return incoming;

        const std::array<std::uint8_t, 4> masks{8, 4, 2, 1};
        std::array<std::optional<bool>, 4> known{};
        for (std::size_t i = 0; i < masks.size(); ++i)
            known[i] = arm_flag_value(incoming, branch->context.mode, branch->address, masks[i]);

        std::array<bool, 4> first_values{};
        std::array<bool, 4> invariant{true, true, true, true};
        bool found_path = false;
        for (unsigned candidate = 0; candidate < 16; ++candidate) {
            const Arm32Nzcv flags{(candidate & 8) != 0, (candidate & 4) != 0,
                                  (candidate & 2) != 0, (candidate & 1) != 0};
            const std::array<bool, 4> values{flags.n, flags.z, flags.c, flags.v};
            bool compatible = true;
            for (std::size_t i = 0; i < known.size(); ++i)
                if (known[i] && *known[i] != values[i]) { compatible = false; break; }
            if (!compatible) continue;
            const auto taken = arm_condition_from_flags(branch->condition, flags);
            if (!taken || *taken != (edge.kind == BlockEdgeKind::conditional_true)) continue;
            if (!found_path) {
                first_values = values;
                found_path = true;
            } else {
                for (std::size_t i = 0; i < invariant.size(); ++i)
                    if (first_values[i] != values[i]) invariant[i] = false;
            }
        }
        // An impossible or unsupported edge is left untouched; only refine
        // when at least one consistent NZCV assignment reaches it.
        if (!found_path) return incoming;
        for (std::size_t i = 0; i < masks.size(); ++i) {
            if (!invariant[i]) continue;
            const auto fact = std::find_if(arm_flag_facts.begin(), arm_flag_facts.end(),
                [&](const auto &entry) { return entry.first == masks[i]; });
            if (fact != arm_flag_facts.end())
                incoming[{branch->context.mode, fact->second}] =
                    Address{branch->address.space, first_values[i] ? 1u : 0u};
        }
        return incoming;
    };
    propagate_cfg_register_values<RegisterState>(functions, stop, result, process_block, refine_arm_edge);
    return result;
}
}
static Result<std::shared_ptr<const ReferenceIndex>>
derive_reference_values(const Image *image, const FunctionSnapshot &functions, const ImageMetadata &metadata,
                        const AnalysisDecisions &decisions, std::stop_token stop) {
    return reference_detail::guarded([&]() -> Result<std::shared_ptr<const ReferenceIndex>> {
        using namespace reference_detail;
        canceled(stop);
        const auto resolver = take(image ? RelocationResolver::create(*image, metadata, stop)
                                         : RelocationResolver::create(metadata, stop));
        const bool macho = resolver.format() == RelocationFormat::macho;
        const auto relocation_spans = relocation_coverage(metadata, image, stop);
        const auto riscv_facts = riscv_reference_facts(image, metadata.elf ? &*metadata.elf : nullptr,
                                                       relocation_spans, functions, stop);
        const auto x86_facts = x86_register_reference_facts(image, relocation_spans, functions, resolver, stop);
        const auto a64_facts = a64_reference_facts(image, relocation_spans, functions, stop);
        const auto arm_facts = arm_reference_facts(image, relocation_spans, functions, stop);
        const auto mips_facts = mips_reference_facts(image, relocation_spans, functions, stop);
        const auto ppc_facts = powerpc_reference_facts(image, relocation_spans, functions, stop);
        const auto m6502_facts = m6502_reference_facts(image, relocation_spans, functions, stop);
        const std::array<const RegisterReferenceFacts *, 5> non_x86_target_facts{
            &riscv_facts, &a64_facts, &arm_facts, &mips_facts, &ppc_facts};
        const RegisterReferenceFacts non_x86_producers = image
            ? non_x86_producer_facts(*image, relocation_spans, functions, non_x86_target_facts, stop)
            : RegisterReferenceFacts{};
        std::unordered_map<std::uint64_t, const Instruction *> instructions_by_id;
        instructions_by_id.reserve(functions.instructions.size());
        for (const auto &fact : functions.instructions) {
            canceled(stop);
            if (fact)
                instructions_by_id.emplace(fact->id, &fact->instruction);
        }
        const auto producer_ids_for = [&](ReferenceOperandKey key) {
            std::vector<std::uint64_t> ids;
            if (const auto found = x86_facts.producer_instruction_ids.find(key);
                found != x86_facts.producer_instruction_ids.end())
                append_unique_producers(ids, found->second);
            if (const auto found = riscv_facts.producer_instruction_ids.find(key);
                found != riscv_facts.producer_instruction_ids.end())
                append_unique_producers(ids, found->second);
            if (const auto found = non_x86_producers.producer_instruction_ids.find(key);
                found != non_x86_producers.producer_instruction_ids.end())
                append_unique_producers(ids, found->second);
            return ids;
        };
        const auto producer_graph_for = [&](ReferenceOperandKey key) {
            ReferenceProducerGraph graph;
            if (const auto found = x86_facts.producer_graphs.find(key);
                found != x86_facts.producer_graphs.end()) graph = found->second;
            else if (const auto found = riscv_facts.producer_graphs.find(key);
                     found != riscv_facts.producer_graphs.end()) graph = found->second;
            else if (const auto found = non_x86_producers.producer_graphs.find(key);
                     found != non_x86_producers.producer_graphs.end()) graph = found->second;

            std::set<std::pair<std::uint64_t, std::uint32_t>> seen;
            const auto retain_immediates = [&](std::uint64_t instruction_id) {
                const auto instruction = instructions_by_id.find(instruction_id);
                if (instruction == instructions_by_id.end())
                    return;
                for (std::size_t index = 0; index < instruction->second->operands.size(); ++index) {
                    canceled(stop);
                    const auto *immediate = std::get_if<ImmediateOperand>(&instruction->second->operands[index]);
                    if (!immediate || index >= 16 || !seen.emplace(instruction_id,
                            static_cast<std::uint32_t>(index)).second)
                        continue;
                    if (graph.immediates.size() == 32) {
                        graph.truncated = true;
                        return;
                    }
                    graph.immediates.push_back({instruction_id, static_cast<std::uint32_t>(index), immediate->value,
                                                immediate->encoded_width, immediate->effective_width,
                                                immediate->is_signed});
                }
            };
            retain_immediates(key.first);
            for (const auto producer : producer_ids_for(key))
                retain_immediates(producer);
            return graph;
        };
        const auto relocation_reason = macho ? UnresolvedReason::macho_relocation : UnresolvedReason::elf_relocation;
        const auto reason_for = [&](const OperandResolution &value) {
            return value.dyld ? UnresolvedReason::macho_dyld : relocation_reason;
        };
        std::map<std::uint32_t, const MachOSymbolTable *> macho_tables;
        if (metadata.macho)
            for (const auto &table : metadata.macho->symbol_tables) {
                canceled(stop);
                macho_tables.emplace(table.command_index, &table);
            }
        using AddressKey = std::pair<std::uint32_t, std::uint64_t>;
        const auto address_key = [](Address address) { return AddressKey{address.space.value, address.offset}; };
        struct Slot {
            const ImportSymbol *first = nullptr;
            bool ambiguous = false;
        };
        std::map<AddressKey, Slot> imports;
        for (const auto &symbol : metadata.imports) {
            canceled(stop);
            auto &slot = imports[address_key(symbol.iat)];
            if (!slot.first)
                slot.first = &symbol;
            else if (slot.first->library != symbol.library || slot.first->name != symbol.name ||
                     slot.first->ordinal != symbol.ordinal)
                slot.ambiguous = true;
        }
        std::vector<bool> claimed(metadata.elf     ? metadata.elf->relocations.size()
                                  : metadata.macho ? metadata.macho->relocations.size()
                                                   : 0);
        std::vector<Reference> references;
        std::set<std::uint64_t> instruction_ids, user_ids;
        std::size_t provenance_bytes = 0;
        const auto append = [&](Reference reference) {
            require(references.size() < reference_record_limit, "Reference count exceeds budget");
            if (reference.provenance.elf) {
                const auto size = elf_provenance_weight(*reference.provenance.elf);
                if (size > reference_payload_limit - provenance_bytes)
                    throw Failure{{ErrorCode::resource_limit, "ELF reference provenance budget exhausted"}};
                provenance_bytes += size;
            }
            if (reference.provenance.dyld) {
                const auto size = dyld_provenance_weight(*reference.provenance.dyld);
                if (size > reference_payload_limit - provenance_bytes)
                    throw Failure{{ErrorCode::resource_limit, "Dyld reference provenance budget exhausted"}};
                provenance_bytes += size;
            }
            if (reference.provenance.macho) {
                const auto size = macho_provenance_weight(*reference.provenance.macho);
                if (size > reference_payload_limit - provenance_bytes)
                    throw Failure{{ErrorCode::resource_limit, "Mach-O reference provenance budget exhausted"}};
                provenance_bytes += size;
            }
            references.push_back(std::move(reference));
        };
        const auto provenance = [&](const OperandResolution &resolution, std::uint64_t instruction_id) {
            ReferenceProvenance value{ReferenceProvenanceKind::decoded, instruction_id, 0};
            if (resolution.dyld) {
                require(metadata.macho.has_value(), "Missing decoded dyld metadata");
                value.kind = ReferenceProvenanceKind::macho_dyld;
                auto owned = own_dyld_provenance(*metadata.macho, resolution.dyld->resolution,
                                                 resolver.preferred_header(), stop);
                owned.use = resolution.dyld->use;
                owned.queries = resolution.dyld->queries;
                value.dyld = std::make_shared<const MachODyldReferenceProvenance>(std::move(owned));
                return value;
            }
            if (!resolution.relocated())
                return value;
            if (macho) {
                require(metadata.macho.has_value(), "Missing authoritative Mach-O metadata");
                const auto &m = *metadata.macho;
                const auto &slice = m.container.slices[m.selected_slice];
                const auto &h = slice.header;
                value.kind = ReferenceProvenanceKind::macho_relocation;
                value.macho = MachOReferenceProvenance{std::get<MachOResolutionReason>(resolution.reason),
                                                       {m.selected_slice, slice.offset, slice.size, h.cpu_type,
                                                        h.cpu_subtype, h.file_type, h.flags, h.is_64, h.order},
                                                       resolution.constant,
                                                       {}};
                for (const auto index : resolution.relocations) {
                    canceled(stop);
                    require(index < m.relocations.size(), "Mach-O reference origin exceeds metadata");
                    claimed[static_cast<std::size_t>(index)] = true;
                    const auto &row = m.relocations[static_cast<std::size_t>(index)];
                    require(row.table < m.relocation_tables.size(), "Mach-O reference table exceeds metadata");
                    MachOReferenceOrigin origin{row, m.relocation_tables[row.table], {}, {}};
                    if (row.symbol_table) {
                        const auto found = macho_tables.find(*row.symbol_table);
                        if (found != macho_tables.end())
                            origin.symbol_table = *found->second;
                    }
                    if (const auto *symbol = resolver.macho_symbol(index))
                        origin.symbol = *symbol;
                    value.macho->origins.push_back(std::move(origin));
                }
                return value;
            }
            value.kind = ReferenceProvenanceKind::elf_relocation;
            value.elf = ElfReferenceProvenance{std::get<ElfResolutionReason>(resolution.reason), {}};
            for (const auto index : resolution.relocations) {
                canceled(stop);
                require(metadata.elf && index < metadata.elf->relocations.size(),
                        "ELF reference origin exceeds metadata");
                claimed[static_cast<std::size_t>(index)] = true;
                ElfReferenceOrigin origin{metadata.elf->relocations[static_cast<std::size_t>(index)], {}};
                if (const auto *symbol = resolver.elf_symbol(index))
                    origin.symbol = *symbol;
                value.elf->origins.push_back(std::move(origin));
            }
            return value;
        };
        for (const auto &fact : functions.instructions) {
            canceled(stop);
            require(fact && fact->id && instruction_ids.insert(fact->id).second,
                    "Invalid or duplicate instruction fact for references");
            const auto &instruction = fact->instruction;
            require(!image || image->code_window(instruction.address, instruction.length) == instruction.length,
                    "Instruction reference facts cross declared data/encrypted bytes");
            require(instruction.length && (instruction.context.architecture == Architecture::jvm || instruction.length <= 15) &&
                        instruction.operands.size() == instruction.access.size() && instruction.operands.size() <= 16,
                    "Invalid instruction operand facts");
            const ReferenceProvenance decoded{ReferenceProvenanceKind::decoded, fact->id, 0};
            const auto opaque = take(resolver.instruction_fixup(instruction, stop));
            if (opaque) {
                OperandResolution resolution;
                resolution.dyld = *opaque;
                append({{0},
                        instruction.address,
                        {},
                        UnresolvedTarget{UnresolvedReason::macho_dyld, std::monostate{}},
                        ReferenceKind::dyld_fixup,
                        OperandAccess::address,
                        provenance(resolution, fact->id),
                        {}});
                continue;
            }
            for (std::size_t i = 0; i < instruction.operands.size(); ++i) {
                const auto &operand = instruction.operands[i];
                    if (instruction.opcode != Opcode::nop && instruction.opcode != Opcode::rv_jalr)
                    if (const auto *memory = std::get_if<MemoryOperand>(&operand)) {
                        auto access = instruction.access[i];
                        if (instruction.context.architecture == Architecture::powerpc &&
                            access == OperandAccess::address && (instruction.memory_read || instruction.memory_write))
                            access = instruction.memory_read && instruction.memory_write ? OperandAccess::read_write
                                : instruction.memory_read ? OperandAccess::read : OperandAccess::write;
                        if (instruction.context.architecture == Architecture::mos6502 && instruction.memory_read &&
                            access == OperandAccess::address)
                            access = OperandAccess::read;
                        ReferenceKind kind = ReferenceKind::memory_address;
                        if (access == OperandAccess::read)
                            kind = ReferenceKind::memory_read;
                        else if (access == OperandAccess::write)
                            kind = ReferenceKind::memory_write;
                        else if (access == OperandAccess::read_write)
                            kind = ReferenceKind::memory_read_write;
                        const auto resolution =
                            take(resolver.operand(instruction, static_cast<std::uint32_t>(i), stop));
                        auto expression = *memory;
                        bool dataflow_target = false;
                        const ReferenceOperandKey operand_key{fact->id, static_cast<std::uint32_t>(i)};
                        if (riscv_facts.relocation_pair_targets.contains(operand_key)) {
                            if (const auto target = riscv_facts.memory_targets.find(operand_key);
                                target != riscv_facts.memory_targets.end()) {
                                expression.resolved_address = target->second;
                                dataflow_target = true;
                            }
                        } else if (resolution.relocated())
                            expression.resolved_address = resolution.address;
                        else if (const auto x86_target =
                                     x86_facts.memory_targets.find({fact->id, static_cast<std::uint32_t>(i)});
                                 x86_target != x86_facts.memory_targets.end()) {
                            expression.resolved_address = x86_target->second;
                            dataflow_target = true;
                        }
                        else if (const auto riscv_target =
                                     riscv_facts.memory_targets.find({fact->id, static_cast<std::uint32_t>(i)});
                                 riscv_target != riscv_facts.memory_targets.end()) {
                            expression.resolved_address = riscv_target->second;
                            dataflow_target = true;
                        }
                        else if (const auto a64_target =
                                     a64_facts.memory_targets.find({fact->id, static_cast<std::uint32_t>(i)});
                                 a64_target != a64_facts.memory_targets.end()) {
                            expression.resolved_address = a64_target->second;
                            dataflow_target = true;
                        }
                        else if (const auto mips_target =
                                     mips_facts.memory_targets.find({fact->id, static_cast<std::uint32_t>(i)});
                                 mips_target != mips_facts.memory_targets.end()) {
                            expression.resolved_address = mips_target->second;
                            dataflow_target = true;
                        }
                        else if (const auto ppc_target =
                                     ppc_facts.memory_targets.find({fact->id, static_cast<std::uint32_t>(i)});
                                 ppc_target != ppc_facts.memory_targets.end()) {
                            expression.resolved_address = ppc_target->second;
                            dataflow_target = true;
                        }
                        else if (const auto m6502_target =
                                     m6502_facts.memory_targets.find({fact->id, static_cast<std::uint32_t>(i)});
                                 m6502_target != m6502_facts.memory_targets.end())
                            expression.resolved_address = m6502_target->second;
                        else if (const auto target = checked_ip_memory_target(instruction, *memory))
                            expression.resolved_address = target;
                        else if (memory->ip_relative)
                            expression.resolved_address.reset();
                        const bool static_absolute = !memory->segment && !memory->base && !memory->index &&
                                                     !memory->ip_relative;
                        const auto width = std::max<std::uint64_t>(1, (memory->data_width + 7) / 8);
                        if (image && !static_absolute && expression.resolved_address &&
                            (access == OperandAccess::read || access == OperandAccess::write ||
                             access == OperandAccess::read_write) &&
                            !mapped_data_range(*image, *expression.resolved_address, access, width))
                            expression.resolved_address.reset();
                        ReferenceTarget target = expression.resolved_address
                                                     ? ReferenceTarget{Location{*expression.resolved_address}}
                                                     : ReferenceTarget{UnresolvedTarget{
                                                           resolution.relocated() ? reason_for(resolution)
                                                                                  : UnresolvedReason::memory_address,
                                                           expression}};
                        auto reference_provenance = provenance(resolution, fact->id);
                        if (dataflow_target && !resolution.relocated()) {
                            reference_provenance.kind = ReferenceProvenanceKind::dataflow;
                            reference_provenance.producer_instruction_ids =
                                producer_ids_for({fact->id, static_cast<std::uint32_t>(i)});
                            reference_provenance.producer_graph =
                                producer_graph_for({fact->id, static_cast<std::uint32_t>(i)});
                        }
                        append({{0},
                                instruction.address,
                                static_cast<std::uint32_t>(i),
                                std::move(target),
                                kind,
                                access,
                                std::move(reference_provenance),
                                {}});
                    }
                if (const auto *arm = std::get_if<ArmMemoryOperand>(&operand)) {
                    const auto access = instruction.access[i];
                    const auto kind = access == OperandAccess::read        ? ReferenceKind::memory_read
                                      : access == OperandAccess::write      ? ReferenceKind::memory_write
                                      : access == OperandAccess::read_write ? ReferenceKind::memory_read_write
                                                                            : ReferenceKind::memory_address;
                    auto expression = *arm;
                    const auto arm_target = arm_facts.memory_targets.find({fact->id, static_cast<std::uint32_t>(i)});
                    if (arm_target != arm_facts.memory_targets.end())
                        expression.resolved_address = arm_target->second;
                    const auto width = std::max<std::uint64_t>(1, (arm->data_width + 7) / 8);
                    if (image && expression.resolved_address &&
                        (access == OperandAccess::read || access == OperandAccess::write ||
                         access == OperandAccess::read_write) &&
                        !mapped_data_range(*image, *expression.resolved_address, access, width))
                        expression.resolved_address.reset();
                    ReferenceTarget target = expression.resolved_address
                                                 ? ReferenceTarget{Location{*expression.resolved_address}}
                                                 : ReferenceTarget{UnresolvedTarget{UnresolvedReason::memory_address,
                                                                                   expression}};
                    auto reference_provenance = decoded;
                    if (arm_target != arm_facts.memory_targets.end()) {
                        reference_provenance.kind = ReferenceProvenanceKind::dataflow;
                        reference_provenance.producer_instruction_ids =
                            producer_ids_for({fact->id, static_cast<std::uint32_t>(i)});
                        reference_provenance.producer_graph =
                            producer_graph_for({fact->id, static_cast<std::uint32_t>(i)});
                    }
                    append({{0}, instruction.address, static_cast<std::uint32_t>(i), std::move(target), kind, access,
                            std::move(reference_provenance), {}});
                }
                if (const auto *far = std::get_if<FarMemoryOperand>(&operand)) {
                    const auto resolution = take(resolver.operand(instruction, static_cast<std::uint32_t>(i), stop));
                    auto expression = *far;
                    if (resolution.relocated())
                        expression.address.resolved_address = resolution.address;
                    ReferenceTarget target =
                        expression.address.resolved_address
                            ? ReferenceTarget{Location{*expression.address.resolved_address}}
                            : ReferenceTarget{UnresolvedTarget{
                                  resolution.relocated() ? reason_for(resolution) : UnresolvedReason::memory_address,
                                  expression}};
                    append({{0},
                            instruction.address,
                            static_cast<std::uint32_t>(i),
                            std::move(target),
                            ReferenceKind::memory_read,
                            OperandAccess::read,
                            provenance(resolution, fact->id),
                            {}});
                }
                if (std::holds_alternative<ImmediateOperand>(operand)) {
                    const auto resolution = take(resolver.operand(instruction, static_cast<std::uint32_t>(i), stop));
                    const auto computed = riscv_facts.immediate_targets.find({fact->id, static_cast<std::uint32_t>(i)});
                    const auto a64_computed = a64_facts.immediate_targets.find({fact->id, static_cast<std::uint32_t>(i)});
                    const auto arm_computed = arm_facts.immediate_targets.find({fact->id, static_cast<std::uint32_t>(i)});
                    const auto mips_computed = mips_facts.immediate_targets.find({fact->id, static_cast<std::uint32_t>(i)});
                    const auto ppc_computed = ppc_facts.immediate_targets.find({fact->id, static_cast<std::uint32_t>(i)});
                    const bool has_computed = computed != riscv_facts.immediate_targets.end() ||
                                              a64_computed != a64_facts.immediate_targets.end() ||
                                              arm_computed != arm_facts.immediate_targets.end() ||
                                              mips_computed != mips_facts.immediate_targets.end() ||
                                              ppc_computed != ppc_facts.immediate_targets.end();
                    const bool paired_riscv_target = computed != riscv_facts.immediate_targets.end() &&
                        (instruction.context.architecture == Architecture::riscv32 ||
                         instruction.context.architecture == Architecture::riscv64) &&
                        (instruction.opcode == Opcode::rv_auipc || instruction.opcode == Opcode::rv_addi);
                    if (resolution.relocated() || has_computed) {
                        ReferenceTarget target;
                        if (paired_riscv_target)
                            target = Location{computed->second};
                        else if (resolution.relocated())
                            target = resolution.address
                                         ? ReferenceTarget{Location{*resolution.address}}
                                         : ReferenceTarget{UnresolvedTarget{reason_for(resolution), std::monostate{}}};
                        else if (computed != riscv_facts.immediate_targets.end())
                            target = Location{computed->second};
                        else if (a64_computed != a64_facts.immediate_targets.end())
                            target = Location{a64_computed->second};
                        else if (arm_computed != arm_facts.immediate_targets.end())
                            target = Location{arm_computed->second};
                        else if (mips_computed != mips_facts.immediate_targets.end())
                            target = Location{mips_computed->second};
                        else if (ppc_computed != ppc_facts.immediate_targets.end())
                            target = Location{ppc_computed->second};
                        else
                            target = UnresolvedTarget{reason_for(resolution), std::monostate{}};
                        auto reference_provenance = provenance(resolution, fact->id);
                        if (has_computed && !resolution.relocated()) {
                            reference_provenance.kind = ReferenceProvenanceKind::dataflow;
                            reference_provenance.producer_instruction_ids =
                                producer_ids_for({fact->id, static_cast<std::uint32_t>(i)});
                            reference_provenance.producer_graph =
                                producer_graph_for({fact->id, static_cast<std::uint32_t>(i)});
                        }
                        append({{0},
                                instruction.address,
                                static_cast<std::uint32_t>(i),
                                std::move(target),
                                resolution.relocated()
                                    ? (resolution.dyld ? ReferenceKind::dyld_fixup : ReferenceKind::relocation)
                                    : ReferenceKind::memory_address,
                                OperandAccess::address,
                                std::move(reference_provenance),
                                {}});
                    }
                }
            }
            if (instruction.flow != FlowKind::call && instruction.flow != FlowKind::jump &&
                instruction.flow != FlowKind::conditional_branch)
                continue;
            const auto kind = instruction.flow == FlowKind::call   ? ReferenceKind::call
                              : instruction.flow == FlowKind::jump ? ReferenceKind::jump
                                                                   : ReferenceKind::conditional_jump;
            auto control_index = instruction.opcode == Opcode::rv_jalr && instruction.operands.size() > 1
                                     ? 1u
                                     : analysis_detail::control_operand_index(instruction);
            if (instruction.context.architecture == Architecture::dex) {
                if (instruction.flow == FlowKind::call) {
                    for (std::size_t i = 0; i < instruction.operands.size(); ++i)
                        if (const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[i]);
                            immediate && immediate->encoded_width == 16 && immediate->effective_width == 16 &&
                            !immediate->is_signed)
                            control_index = static_cast<std::uint32_t>(i);
                } else {
                    const auto relative = std::find_if(instruction.operands.begin(), instruction.operands.end(),
                        [](const auto &operand) { return std::holds_alternative<RelativeOperand>(operand); });
                    if (relative == instruction.operands.end()) {
                        // Incomplete/unsupported branch facts must not turn a
                        // source vreg into an indirect control expression.
                        append({{0}, instruction.address, {},
                                UnresolvedTarget{UnresolvedReason::missing_operand, std::monostate{}},
                                kind, OperandAccess::address, decoded, {}});
                        continue;
                    }
                    control_index = static_cast<std::uint32_t>(relative - instruction.operands.begin());
                }
            }
            Reference reference{{0},  instruction.address,    {},      Location{Address{{0}, 0}},
                                kind, OperandAccess::address, decoded, {}};
            if (!instruction.operands.empty())
                reference.operand_index = control_index;
            const auto resolution =
                instruction.operands.empty()
                    ? OperandResolution{}
                    : take(resolver.operand(instruction, control_index, stop));
            reference.provenance = provenance(resolution, fact->id);
            if (resolution.dyld && resolution.dyld->use == MachODyldUse::memory_slot)
                reference.association = Location{resolution.dyld->queries.front().at};
            auto target =
                resolution.constant ? std::optional<Address>{}
                : image ? take(resolver.control_target(*image, instruction, stop))
                : resolution.relocated()
                    ? (!instruction.operands.empty() &&
                               std::holds_alternative<RelativeOperand>(
                                   instruction.operands[control_index])
                           ? resolution.address
                           : std::nullopt)
                    : instruction.direct_target;
            if (!target && image && instruction.context.architecture == Architecture::dex &&
                instruction.flow == FlowKind::call)
                target = dex_invoke_code_target(instruction, *image, metadata);
            if (!target && !resolution.constant && !resolution.relocated()) {
                bool dataflow_target = false;
                const auto computed = x86_facts.immediate_targets.find(
                    {fact->id, control_index});
                if (computed != x86_facts.immediate_targets.end()) {
                    target = computed->second;
                    dataflow_target = true;
                }
                else if (const auto computed_riscv = riscv_facts.immediate_targets.find({fact->id, control_index});
                         computed_riscv != riscv_facts.immediate_targets.end()) {
                    target = computed_riscv->second;
                    dataflow_target = true;
                }
                else if (const auto computed_a64 = a64_facts.immediate_targets.find({fact->id, control_index});
                         computed_a64 != a64_facts.immediate_targets.end()) {
                    target = computed_a64->second;
                    dataflow_target = true;
                }
                else if (const auto computed_arm = arm_facts.immediate_targets.find({fact->id, control_index});
                         computed_arm != arm_facts.immediate_targets.end()) {
                    target = computed_arm->second;
                    dataflow_target = true;
                }
                else if (const auto computed_mips = mips_facts.immediate_targets.find({fact->id, control_index});
                         computed_mips != mips_facts.immediate_targets.end()) {
                    target = computed_mips->second;
                    dataflow_target = true;
                }
                else if (const auto computed_ppc = ppc_facts.immediate_targets.find({fact->id, control_index});
                         computed_ppc != ppc_facts.immediate_targets.end()) {
                    target = computed_ppc->second;
                    dataflow_target = true;
                }
                else if (const auto computed_m6502 = m6502_facts.immediate_targets.find({fact->id, control_index});
                         computed_m6502 != m6502_facts.immediate_targets.end()) {
                    target = computed_m6502->second;
                    dataflow_target = true;
                }
                if (dataflow_target)
                    reference.provenance.kind = ReferenceProvenanceKind::dataflow;
                if (dataflow_target)
                    reference.provenance.producer_instruction_ids =
                        producer_ids_for({fact->id, static_cast<std::uint32_t>(control_index)});
                if (dataflow_target)
                    reference.provenance.producer_graph =
                        producer_graph_for({fact->id, static_cast<std::uint32_t>(control_index)});
            }
            if (target && instruction.context.architecture == Architecture::arm && instruction.arm &&
                (instruction.context.mode == ExecutionMode::a32 ||
                 instruction.context.mode == ExecutionMode::thumb)) {
                const ReferenceOperandKey key{fact->id, control_index};
                if (const auto proven = arm_facts.target_modes.find(key);
                    proven != arm_facts.target_modes.end())
                    reference.provenance.target_mode = proven->second;
                else
                    reference.provenance.target_mode = instruction.arm->target_mode.value_or(instruction.context.mode);
            }
            if (target)
                reference.target = Location{*target};
            else if (resolution.relocated()) {
                const auto &operand = instruction.operands[control_index];
                if (const auto *memory = std::get_if<MemoryOperand>(&operand)) {
                    auto expression = *memory;
                    expression.resolved_address = resolution.address;
                    reference.target = UnresolvedTarget{resolution.dyld      ? UnresolvedReason::macho_dyld
                                                        : resolution.address ? UnresolvedReason::memory_value
                                                                             : relocation_reason,
                                                        expression};
                    if (resolution.address)
                        reference.association = Location{*resolution.address};
                } else if (const auto *far_memory = std::get_if<FarMemoryOperand>(&operand)) {
                    auto expression = *far_memory;
                    expression.address.resolved_address = resolution.address;
                    reference.target = UnresolvedTarget{resolution.dyld      ? UnresolvedReason::macho_dyld
                                                        : resolution.address ? UnresolvedReason::memory_value
                                                                             : relocation_reason,
                                                        expression};
                    if (resolution.address)
                        reference.association = Location{*resolution.address};
                } else if (const auto *relative = std::get_if<RelativeOperand>(&operand))
                    reference.target = UnresolvedTarget{reason_for(resolution), *relative};
                else if (const auto *far_pointer = std::get_if<FarPointerOperand>(&operand))
                    reference.target = UnresolvedTarget{reason_for(resolution), *far_pointer};
                else
                    reference.target = UnresolvedTarget{reason_for(resolution), std::monostate{}};
            } else if (!instruction.operands.empty()) {
                const auto &operand = instruction.operands[control_index];
                if (const auto *memory = std::get_if<MemoryOperand>(&operand)) {
                    bool external = false, ambiguous = false;
                    if (memory->resolved_address) {
                        reference.association = Location{*memory->resolved_address};
                        const auto slot = imports.find(address_key(*memory->resolved_address));
                        if (slot != imports.end()) {
                            const auto &symbol = *slot->second.first;
                            ExternalIdentity identity{symbol.library, symbol.name, symbol.ordinal};
                            ambiguous = slot->second.ambiguous || !valid_external(identity);
                            if (!ambiguous) {
                                reference.target = std::move(identity);
                                reference.kind = instruction.flow == FlowKind::call ? ReferenceKind::imported_call
                                                                                    : ReferenceKind::imported_jump;
                                reference.provenance.kind = ReferenceProvenanceKind::import_slot;
                                external = true;
                            }
                        }
                    }
                    if (!external)
                        reference.target = UnresolvedTarget{
                            ambiguous ? UnresolvedReason::ambiguous_import : UnresolvedReason::memory_value, *memory};
                } else if (const auto *far_pointer = std::get_if<FarPointerOperand>(&operand))
                    reference.target = UnresolvedTarget{UnresolvedReason::far_selector, *far_pointer};
                else if (const auto *far_memory = std::get_if<FarMemoryOperand>(&operand)) {
                    reference.target = UnresolvedTarget{UnresolvedReason::memory_value, *far_memory};
                    if (far_memory->address.resolved_address)
                        reference.association = Location{*far_memory->address.resolved_address};
                } else if (const auto *reg = std::get_if<RegisterOperand>(&operand))
                    reference.target = UnresolvedTarget{UnresolvedReason::register_value, *reg};
                else if (const auto *relative = std::get_if<RelativeOperand>(&operand))
                    reference.target = UnresolvedTarget{UnresolvedReason::relative_overflow, *relative};
                else
                    reference.target = UnresolvedTarget{UnresolvedReason::missing_operand, std::monostate{}};
            } else
                reference.target = UnresolvedTarget{UnresolvedReason::missing_operand, std::monostate{}};
            append(std::move(reference));
        }
        if (metadata.elf)
            for (std::uint64_t i = 0; i < metadata.elf->relocations.size(); ++i) {
                canceled(stop);
                const auto &row = metadata.elf->relocations[static_cast<std::size_t>(i)];
                if (claimed[static_cast<std::size_t>(i)] || row.kind == ElfRelocationKind::none ||
                    (!row.place && !row.file_place))
                    continue;
                const auto resolution = take(resolver.data(i, stop));
                if (!resolution.relocated())
                    continue;
                const Location source = row.place ? Location{*row.place} : Location{*row.file_place};
                ReferenceTarget target =
                    resolution.address ? ReferenceTarget{Location{*resolution.address}}
                                       : ReferenceTarget{UnresolvedTarget{reason_for(resolution), std::monostate{}}};
                append({{0},
                        source,
                        {},
                        std::move(target),
                        ReferenceKind::relocation,
                        OperandAccess::address,
                        provenance(resolution, 0),
                        {}});
            }
        if (metadata.elf) {
            std::set<std::tuple<std::uint32_t, std::uint64_t, std::uint32_t, std::uint64_t>> emitted_vtable_slots;
            for (const auto &table : metadata.elf->vtable_headers) {
                canceled(stop);
                if (!table.slots_scanned || table.offset_to_top != 0 || !table.type_info ||
                    table.address_point.space != table.symbol_begin.space ||
                    table.symbol_begin.offset > UINT64_MAX - 16 ||
                    table.address_point.offset != table.symbol_begin.offset + 16)
                    continue;
                for (const auto &slot : table.slots) {
                    canceled(stop);
                    if (slot.state != ElfVTableSlotState::resolved_executable || !slot.target ||
                        slot.slot.space != table.address_point.space || slot.target->space != slot.slot.space ||
                        slot.slot.offset < table.address_point.offset ||
                        ((slot.slot.offset - table.address_point.offset) % 8) != 0 ||
                        (slot.slot.offset - table.address_point.offset) / 8 != slot.index || slot.index >= 65536)
                        continue;
                    const auto key = std::tuple{slot.slot.space.value, slot.slot.offset,
                                                slot.target->space.value, slot.target->offset};
                    if (!emitted_vtable_slots.insert(key).second)
                        continue;
                    ReferenceProvenance origin{ReferenceProvenanceKind::elf_vtable_slot, 0, 0};
                    origin.elf_vtable = ElfVTableReferenceProvenance{
                        table.symbol_begin, table.address_point, *table.type_info, slot.slot, slot.index,
                        table.symbol_index, table.type_name};
                    append({{0}, Location{slot.slot}, {}, Location{*slot.target}, ReferenceKind::memory_address,
                            OperandAccess::address, std::move(origin), {}});
                }
            }
        }
        if (metadata.macho)
            for (std::uint64_t i = 0; i < metadata.macho->relocations.size(); ++i) {
                canceled(stop);
                const auto &row = metadata.macho->relocations[static_cast<std::size_t>(i)];
                if (claimed[static_cast<std::size_t>(i)] || row.auxiliary || (!row.place && !row.file_place))
                    continue;
                const auto resolution = take(resolver.data(i, stop));
                const Location source = row.place ? Location{*row.place} : Location{*row.file_place};
                ReferenceTarget target =
                    resolution.address ? ReferenceTarget{Location{*resolution.address}}
                                       : ReferenceTarget{UnresolvedTarget{reason_for(resolution), std::monostate{}}};
                append({{0},
                        source,
                        {},
                        std::move(target),
                        ReferenceKind::relocation,
                        OperandAccess::address,
                        provenance(resolution, 0),
                        {}});
            }
        if (metadata.macho && (!metadata.macho->dyld_fixups.empty() || !metadata.macho->chained_pointers.empty())) {
            require(image != nullptr, "Dyld references require the source image overload");
            const auto dyld = take(MachODyldResolver::create(*image, metadata, stop));
            const auto &m = *metadata.macho;
            std::set<std::tuple<std::uint32_t, std::uint64_t>> seen;
            const auto emit = [&](MachODyldIdentity id, const std::optional<Address> &place) {
                canceled(stop);
                if (!place || !seen.emplace(place->space.value, place->offset).second)
                    return;
                const auto resolution = take(dyld.data(id, stop));
                ReferenceProvenance origin{ReferenceProvenanceKind::macho_dyld, 0, 0};
                origin.dyld = std::make_shared<const MachODyldReferenceProvenance>(
                    own_dyld_provenance(m, resolution, dyld.preferred_header(), stop));
                ReferenceTarget target =
                    resolution.address
                        ? ReferenceTarget{Location{*resolution.address}}
                        : ReferenceTarget{UnresolvedTarget{UnresolvedReason::macho_dyld, std::monostate{}}};
                append({{0},
                        *place,
                        {},
                        std::move(target),
                        ReferenceKind::dyld_fixup,
                        OperandAccess::address,
                        std::move(origin),
                        {}});
            };
            for (std::uint64_t i = 0; i < m.dyld_fixups.size(); ++i)
                emit({MachODyldSource::classic, i}, m.dyld_fixups[static_cast<std::size_t>(i)].place);
            for (std::uint64_t i = 0; i < m.chained_pointers.size(); ++i)
                emit({MachODyldSource::chained, i}, m.chained_pointers[static_cast<std::size_t>(i)].place);
        }
        for (const auto &user : decisions.references) {
            canceled(stop);
            require(user.id && user_ids.insert(user.id).second, "Invalid or duplicate user reference ID");
            ReferenceKind kind;
            OperandAccess access = OperandAccess::address;
            switch (user.kind) {
            case UserReferenceKind::code:
                kind = ReferenceKind::user_code;
                break;
            case UserReferenceKind::data:
                kind = ReferenceKind::user_data;
                break;
            case UserReferenceKind::call:
                kind = ReferenceKind::call;
                break;
            case UserReferenceKind::jump:
                kind = ReferenceKind::jump;
                break;
            case UserReferenceKind::read:
                kind = ReferenceKind::memory_read;
                access = OperandAccess::read;
                break;
            case UserReferenceKind::write:
                kind = ReferenceKind::memory_write;
                access = OperandAccess::write;
                break;
            case UserReferenceKind::address:
                kind = ReferenceKind::memory_address;
                break;
            default:
                throw Failure{{ErrorCode::invalid_argument, "Unknown user reference kind"}};
            }
            append({{0},
                    user.source,
                    {},
                    Location{user.target},
                    kind,
                    access,
                    {ReferenceProvenanceKind::user, 0, user.id},
                    {}});
        }
        const bool metadata_complete =
            (!metadata.elf || (metadata.elf->relocations_complete && metadata.elf->dynamic_complete &&
                                metadata.elf->rtti_complete)) &&
            (!metadata.macho || (metadata.macho->symbols_complete && metadata.macho->relocations_complete &&
                                 metadata.macho->dyld_complete));
        return ReferenceIndex::create(std::move(references), functions.key, functions.complete && metadata_complete,
                                      stop);
    });
}
Result<std::shared_ptr<const ReferenceIndex>> derive_references(const FunctionSnapshot &functions,
                                                                const ImageMetadata &metadata,
                                                                const AnalysisDecisions &decisions,
                                                                std::stop_token stop) {
    return derive_reference_values(nullptr, functions, metadata, decisions, stop);
}
Result<std::shared_ptr<const ReferenceIndex>> derive_references(const Image &image, const FunctionSnapshot &functions,
                                                                const ImageMetadata &metadata,
                                                                const AnalysisDecisions &decisions,
                                                                std::stop_token stop) {
    return derive_reference_values(&image, functions, metadata, decisions, stop);
}
} // namespace hexlab
