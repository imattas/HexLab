#include "hexlab/analysis/relocations.hpp"
#include "control_target.hpp"
#include "instruction_flow.hpp"
#include <algorithm>
#include <array>
#include <bit>
namespace hexlab {
namespace {
template <class F> auto guarded(F action) -> decltype(action()) {
    try {
        return action();
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate shared fixup resolution"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Shared fixup allocation limit"};
    }
}
std::array<std::optional<EncodedField>, 2> fields(const Operand &operand) {
    if (const auto *relative = std::get_if<RelativeOperand>(&operand))
        return {relative->encoding, {}};
    if (const auto *immediate = std::get_if<ImmediateOperand>(&operand))
        return {immediate->encoding, {}};
    if (const auto *memory = std::get_if<MemoryOperand>(&operand))
        return {memory->displacement_encoding, {}};
    if (const auto *far = std::get_if<FarPointerOperand>(&operand))
        return {far->offset_encoding, far->selector_encoding};
    if (const auto *far = std::get_if<FarMemoryOperand>(&operand))
        return {far->address.displacement_encoding, {}};
    return {};
}
bool address_ranges_overlap(Address begin, std::uint64_t size, Address place, std::uint64_t place_size) {
    if (begin.space != place.space || !size || !place_size)
        return false;
    return place.offset <= begin.offset ? begin.offset - place.offset < place_size
                                        : place.offset - begin.offset < size;
}
bool relocation_overlaps(const Image &image, const ImageMetadata &metadata, Address begin, std::uint64_t size) {
    const auto file_byte_matches = [&](FileOffset place, std::uint64_t place_size) {
        for (std::uint64_t n = 0; n < size; ++n) {
            const auto at = advance(begin, n);
            if (!at)
                return true;
            const auto file = image.to_file_offset(at.value());
            if (file && (place.value <= file.value().value ? file.value().value - place.value < place_size
                                                             : place.value - file.value().value < 1))
                return true;
        }
        return false;
    };
    if (metadata.elf)
        for (const auto &row : metadata.elf->relocations) {
            const auto width = row.field_size.value_or(1);
            if ((row.place && address_ranges_overlap(begin, size, *row.place, width)) ||
                (row.file_place && file_byte_matches(*row.file_place, width)) || (!row.place && !row.file_place))
                return true;
        }
    if (metadata.macho)
        for (const auto &row : metadata.macho->relocations) {
            const auto width = row.field_size ? row.field_size : 1;
            if ((row.place && address_ranges_overlap(begin, size, *row.place, width)) ||
                (row.file_place && file_byte_matches(*row.file_place, width)) || (!row.place && !row.file_place))
                return true;
        }
    return false;
}
Result<std::optional<Instruction>> preceding_riscv_instruction(const Image &image, const Instruction &instruction,
                                                               std::stop_token stop) {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "RISC-V PC-relative target lookup canceled"};
    if (instruction.address.offset < 4)
        return std::optional<Instruction>{};
    const Address at{instruction.address.space, instruction.address.offset - 4};
    const auto context = image.context_at(at);
    if (!context || context.value() != instruction.context || image.code_window(at, 4) != 4)
        return std::optional<Instruction>{};
    const auto offset = image.to_file_offset(at);
    if (!offset)
        return std::optional<Instruction>{};
    const auto view = image.storage()->read_at(offset.value(), 4);
    if (!view)
        return view.error();
    if (view.value().bytes.size() != 4)
        return std::optional<Instruction>{};
    const auto decoded = decode_instruction(instruction.context, view.value().bytes, at);
    if (decoded.status != DecodeStatus::decoded || !decoded.instruction)
        return std::optional<Instruction>{};
    return std::optional<Instruction>{std::move(*decoded.instruction)};
}
std::optional<std::int64_t> signed_immediate(const Instruction &instruction, std::size_t index,
                                             std::uint8_t expected_width) {
    if (index >= instruction.operands.size())
        return {};
    const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[index]);
    if (!immediate || immediate->encoded_width != expected_width || !immediate->is_signed)
        return {};
    return std::bit_cast<std::int64_t>(immediate->value);
}
const RegisterOperand *gpr(const Instruction &instruction, std::size_t index, std::uint8_t width) {
    if (index >= instruction.operands.size())
        return nullptr;
    const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[index]);
    return reg && reg->bank == RegisterBank::riscv_gpr && reg->width == width ? reg : nullptr;
}
Result<std::optional<Address>> riscv_pcrel_jalr_target(const RelocationResolver &resolver, const Image &image,
                                                       const ImageMetadata *metadata,
                                                       const Instruction &instruction, std::stop_token stop) {
    const bool rv32 = instruction.context.architecture == Architecture::riscv32 &&
                      instruction.context.mode == ExecutionMode::rv32;
    const bool rv64 = instruction.context.architecture == Architecture::riscv64 &&
                      instruction.context.mode == ExecutionMode::rv64;
    if ((!rv32 && !rv64) || instruction.opcode != Opcode::rv_jalr || instruction.flow == FlowKind::ret ||
        (instruction.flow != FlowKind::call && instruction.flow != FlowKind::jump) || instruction.operands.size() != 2 ||
        !metadata)
        return std::optional<Address>{};
    const auto width = static_cast<std::uint8_t>(rv32 ? 32 : 64);
    const auto *link = gpr(instruction, 0, width);
    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
    const auto *base = memory && memory->base ? &*memory->base : nullptr;
    if (!link || !memory || !base || base->bank != RegisterBank::riscv_gpr || base->width != width || base->index == 0)
        return std::optional<Address>{};
    if (relocation_overlaps(image, *metadata, instruction.address, instruction.length))
        return std::optional<Address>{};
    const auto current_fixup = resolver.instruction_fixup(instruction, stop);
    if (!current_fixup)
        return current_fixup.error();
    if (current_fixup.value())
        return std::optional<Address>{};
    auto previous = preceding_riscv_instruction(image, instruction, stop);
    if (!previous)
        return previous.error();
    if (!previous.value())
        return std::optional<Address>{};
    const auto reject_relocated = [&](const Instruction &candidate) -> Result<bool> {
        if (relocation_overlaps(image, *metadata, candidate.address, candidate.length))
            return true;
        const auto fixup = resolver.instruction_fixup(candidate, stop);
        if (!fixup)
            return fixup.error();
        return fixup.value().has_value();
    };
    auto previous_relocated = reject_relocated(*previous.value());
    if (!previous_relocated)
        return previous_relocated.error();
    if (previous_relocated.value())
        return std::optional<Address>{};
    std::uint64_t sum = previous.value()->address.offset;
    std::uint8_t auipc_reg = 0;
    std::optional<std::int64_t> high;
    if (previous.value()->opcode == Opcode::rv_auipc && previous.value()->operands.size() == 2) {
        const auto *dst = gpr(*previous.value(), 0, width);
        high = signed_immediate(*previous.value(), 1, 20);
        if (dst && dst->index == base->index)
            auipc_reg = dst->index;
    } else if (previous.value()->opcode == Opcode::rv_addi && previous.value()->operands.size() == 3) {
        const auto *dst = gpr(*previous.value(), 0, width);
        const auto *src = gpr(*previous.value(), 1, width);
        const auto low = signed_immediate(*previous.value(), 2, 12);
        if (dst && src && dst->index == base->index && src->index == base->index && low) {
            sum += static_cast<std::uint64_t>(*low);
            const Address addi_at = previous.value()->address;
            Instruction prior_probe = *previous.value();
            prior_probe.address = addi_at;
            auto auipc = preceding_riscv_instruction(image, prior_probe, stop);
            if (!auipc)
                return auipc.error();
            if (!auipc.value() || auipc.value()->opcode != Opcode::rv_auipc || auipc.value()->operands.size() != 2)
                return std::optional<Address>{};
            auto auipc_relocated = reject_relocated(*auipc.value());
            if (!auipc_relocated)
                return auipc_relocated.error();
            if (auipc_relocated.value())
                return std::optional<Address>{};
            const auto *auipc_dst = gpr(*auipc.value(), 0, width);
            high = signed_immediate(*auipc.value(), 1, 20);
            if (!auipc_dst || auipc_dst->index != base->index || !high)
                return std::optional<Address>{};
            sum = auipc.value()->address.offset + static_cast<std::uint64_t>(*high) + static_cast<std::uint64_t>(*low);
            sum += static_cast<std::uint64_t>(memory->displacement);
            const auto mask = rv32 ? UINT64_C(0xffffffff) : UINT64_MAX;
            return std::optional<Address>{Address{instruction.address.space, (sum & mask) & ~UINT64_C(1)}};
        }
    }
    if (!auipc_reg || !high)
        return std::optional<Address>{};
    sum += static_cast<std::uint64_t>(*high);
    sum += static_cast<std::uint64_t>(memory->displacement);
    const auto mask = rv32 ? UINT64_C(0xffffffff) : UINT64_MAX;
    return std::optional<Address>{Address{instruction.address.space, (sum & mask) & ~UINT64_C(1)}};
}
void unresolved(MachODyldResolution &value, MachODyldResolutionReason reason) {
    value.reason = reason;
    value.address.reset();
    value.constant.reset();
    value.binding.reset();
}
void merge(MachODyldResolution &into, const MachODyldResolution &from) {
    into.origins.insert(into.origins.end(), from.origins.begin(), from.origins.end());
    std::sort(into.origins.begin(), into.origins.end());
    into.origins.erase(std::unique(into.origins.begin(), into.origins.end()), into.origins.end());
}
template <class T> Result<OperandResolution> common(Result<T> value) {
    if (!value)
        return value.error();
    OperandResolution out;
    out.address = value.value().address;
    if constexpr (std::is_same_v<T, MachOOperandResolution>)
        out.constant = value.value().constant;
    out.reason = value.value().reason;
    out.relocations = std::move(value.value().relocations);
    return out;
}
} // namespace
Result<RelocationResolver> RelocationResolver::create(const ImageMetadata &metadata, std::stop_token stop) {
    if (metadata.macho && (!metadata.macho->dyld_fixups.empty() || !metadata.macho->chained_pointers.empty() ||
                           !metadata.macho->data_in_code.empty() ||
                           std::any_of(metadata.macho->encryption.begin(), metadata.macho->encryption.end(),
                                       [](const auto &row) { return row.cryptid && row.size; })))
        return Error{ErrorCode::invalid_argument, "Dyld-aware resolution requires the source image overload"};
    return create_base(metadata, stop);
}
Result<RelocationResolver> RelocationResolver::create(const Image &image, const ImageMetadata &metadata,
                                                      std::stop_token stop) {
    auto created = create_base(metadata, stop);
    if (!created)
        return created.error();
    auto out = std::move(created.value());
    out.source_image_ = &image;
    out.source_macho_ = metadata.macho ? &*metadata.macho : nullptr;
    out.source_metadata_ = &metadata;
    if (metadata.macho && (!metadata.macho->dyld_fixups.empty() || !metadata.macho->chained_pointers.empty())) {
        auto dyld = MachODyldResolver::create(image, metadata, stop);
        if (!dyld)
            return dyld.error();
        out.dyld_ = std::move(dyld.value());
        out.source_image_ = &image;
        out.source_macho_ = &*metadata.macho;
    }
    return out;
}
Result<RelocationResolver> RelocationResolver::create_base(const ImageMetadata &metadata, std::stop_token stop) {
    if (metadata.elf && metadata.macho)
        return Error{ErrorCode::invalid_argument, "Multiple authoritative relocation formats"};
    if (metadata.macho) {
        auto created = MachORelocationResolver::create(metadata, stop);
        if (!created)
            return created.error();
        return RelocationResolver{std::move(created.value())};
    }
    auto created = ElfRelocationResolver::create(metadata, stop);
    if (!created)
        return created.error();
    return RelocationResolver{std::move(created.value())};
}
Result<OperandResolution> RelocationResolver::operand(const Instruction &instruction, std::uint32_t index,
                                                      std::stop_token stop) const {
    return guarded([&]() -> Result<OperandResolution> {
        auto result = std::visit(
            [&](const auto &resolver) { return common(resolver.operand(instruction, index, stop)); }, value_);
        if (!result || !dyld_)
            return result;
        auto out = std::move(result.value());
        auto opaque = instruction_fixup(instruction, stop);
        if (!opaque)
            return opaque.error();
        if (opaque.value()) {
            out.address.reset();
            out.constant.reset();
            out.dyld = std::move(*opaque.value());
            return out;
        }
        const auto &op = instruction.operands[index];
        MachODyldOperand use;
        bool found = false;
        for (const auto field : fields(op)) {
            if (!field)
                continue;
            const auto at = advance(instruction.address, field->offset);
            if (!at)
                return at.error();
            auto value = dyld_->slot(at.value(), field->size, stop);
            if (!value)
                return value.error();
            if (!value.value().associated())
                continue;
            use.queries.push_back({at.value(), field->size, field});
            if (!found)
                use.resolution = std::move(value.value());
            else {
                merge(use.resolution, value.value());
                unresolved(use.resolution, MachODyldResolutionReason::ambiguous);
            }
            found = true;
        }
        if (found) {
            if (use.resolution.origins.size() > 4096)
                return Error{ErrorCode::resource_limit, "Combined dyld match limit"};
            if (!out.relocations.empty())
                unresolved(use.resolution, MachODyldResolutionReason::ambiguous);
            out.address.reset();
            out.constant.reset();
            if (std::holds_alternative<ImmediateOperand>(op)) {
                out.address = use.resolution.address;
                out.constant = use.resolution.constant;
            }
            if (const auto *memory = std::get_if<MemoryOperand>(&op);
                memory && !memory->segment && !memory->ip_relative && !memory->base && !memory->index)
                out.address = use.resolution.address;
            out.dyld = std::move(use);
            return out;
        }
        const auto *memory = std::get_if<MemoryOperand>(&op);
        if (!memory || memory->segment || memory->data_width > 64 || (memory->data_width % 8))
            return out;
        const auto slot = out.relocated() ? out.address : memory->resolved_address;
        if (!slot)
            return out;
        const auto width = static_cast<std::uint8_t>(memory->data_width ? memory->data_width / 8 : 1);
        auto value = dyld_->slot(*slot, width, stop);
        if (!value)
            return value.error();
        if (value.value().associated()) {
            out.address = slot;
            out.constant.reset();
            out.dyld = MachODyldOperand{MachODyldUse::memory_slot, std::move(value.value()), {{*slot, width, {}}}};
        }
        return out;
    });
}
Result<bool> RelocationResolver::code_start(Address at, std::stop_token stop) const {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Code start lookup canceled"};
    if (source_image_ && !source_image_->code_window(at, 1))
        return false;
    if (!dyld_)
        return true;
    auto value = dyld_->slot(at, 1, stop);
    if (!value)
        return value.error();
    return !value.value().associated();
}
std::optional<Address> RelocationResolver::preferred_header() const noexcept {
    return dyld_ ? dyld_->preferred_header() : std::nullopt;
}
Result<std::optional<MachODyldOperand>> RelocationResolver::instruction_fixup(const Instruction &instruction,
                                                                              std::stop_token stop) const {
    return guarded([&]() -> Result<std::optional<MachODyldOperand>> {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "Instruction fixup lookup canceled"};
        if (!dyld_)
            return std::optional<MachODyldOperand>{};
        if (!instruction.length || instruction.length > 15)
            return Error{ErrorCode::invalid_argument, "Invalid dyld instruction length"};
        const auto context = source_image_->context_at(instruction.address);
        if (!context)
            return context.error();
        if (context.value() != instruction.context)
            return Error{ErrorCode::invalid_argument, "Dyld instruction context differs from source image"};
        std::uint16_t covered = 0;
        for (const auto &op : instruction.operands)
            for (const auto field : fields(op)) {
                if (!field)
                    continue;
                if (!field->size || field->size > 8 || field->offset >= instruction.length ||
                    field->size > instruction.length - field->offset)
                    return Error{ErrorCode::invalid_argument, "Dyld operand field exceeds instruction"};
                for (unsigned i = 0; i < field->size; ++i)
                    covered |= static_cast<std::uint16_t>(1u << (field->offset + i));
            }
        MachODyldOperand out;
        out.use = MachODyldUse::instruction_bytes;
        for (std::uint8_t offset = 0; offset < instruction.length;) {
            const auto width = static_cast<std::uint8_t>(std::min<unsigned>(8, instruction.length - offset));
            const auto at = advance(instruction.address, offset);
            if (!at)
                return at.error();
            auto value = dyld_->slot(at.value(), width, stop);
            if (!value)
                return value.error();
            if (value.value().associated()) {
                merge(out.resolution, value.value());
                out.queries.push_back({at.value(), width, EncodedField{offset, width}});
            }
            offset += width;
        }
        if (out.resolution.origins.size() > 4096)
            return Error{ErrorCode::resource_limit, "Instruction dyld match limit"};
        bool opaque = false;
        for (const auto id : out.resolution.origins) {
            std::optional<Address> place;
            std::uint8_t width = 0;
            if (id.source == MachODyldSource::classic) {
                const auto &row = source_macho_->dyld_fixups[static_cast<std::size_t>(id.row)];
                place = row.place;
                width = row.field_size;
            } else {
                const auto &row = source_macho_->chained_pointers[static_cast<std::size_t>(id.row)];
                place = row.place;
                width = row.field_size;
            }
            if (!place)
                continue;
            const auto size = width ? width : 1;
            for (unsigned byte = 0; byte < instruction.length; ++byte) {
                if (byte > UINT64_MAX - instruction.address.offset)
                    return Error{ErrorCode::overflow, "Instruction range overflow"};
                const auto at = instruction.address.offset + byte;
                if (place->space == instruction.address.space && at >= place->offset && at - place->offset < size &&
                    !(covered & (1u << byte)))
                    opaque = true;
            }
        }
        if (!opaque)
            return std::optional<MachODyldOperand>{};
        unresolved(out.resolution, MachODyldResolutionReason::unsupported);
        return std::optional<MachODyldOperand>{std::move(out)};
    });
}
Result<OperandResolution> RelocationResolver::data(std::uint64_t row, std::stop_token stop) const {
    auto result = std::visit([&](const auto &resolver) { return common(resolver.data(row, stop)); }, value_);
    if (result && source_image_ && source_macho_)
        for (const auto id : result.value().relocations) {
            const auto &record = source_macho_->relocations[static_cast<std::size_t>(id)];
            const auto width = record.field_size ? record.field_size : 1;
            if (record.place && source_image_->plaintext_window(*record.place, width) != width) {
                result.value().address.reset();
                result.value().constant.reset();
                result.value().reason = MachOResolutionReason::unsupported;
                break;
            }
        }
    return result;
}
Result<OperandResolution> RelocationResolver::data_at(const Image &image, Address place, std::uint8_t width,
                                                       std::stop_token stop) const {
    return guarded([&]() -> Result<OperandResolution> {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "Data slot resolution canceled"};
        if (!width || width > 8)
            return Error{ErrorCode::invalid_argument, "Invalid relocation-backed data slot width"};
        if (source_image_ && source_image_ != &image)
            return Error{ErrorCode::conflict, "Data slot resolver belongs to another image"};
        std::optional<FileOffset> file_place;
        {
            const auto mapped = image.to_file_offset(place);
            if (mapped)
                file_place = mapped.value();
        }
        if (dyld_) {
            auto slot = dyld_->slot(place, width, stop);
            if (!slot)
                return slot.error();
            if (slot.value().associated()) {
                OperandResolution output;
                if (slot.value().reason == MachODyldResolutionReason::resolved) {
                    output.address = slot.value().address;
                    output.constant = slot.value().constant;
                }
                output.dyld = MachODyldOperand{MachODyldUse::memory_slot, std::move(slot.value()),
                                               {{place, width, {}}}};
                return output;
            }
        }
        auto result = std::visit([&](const auto &resolver) {
            return common(resolver.data_at(place, file_place, width, stop));
        }, value_);
        if (!result || !source_image_ || !source_macho_)
            return result;
        for (const auto id : result.value().relocations) {
            if (id >= source_macho_->relocations.size())
                return Error{ErrorCode::malformed, "Mach-O data relocation index outside metadata"};
            const auto &record = source_macho_->relocations[static_cast<std::size_t>(id)];
            const auto size = record.field_size ? record.field_size : 1;
            if (record.place && source_image_->plaintext_window(*record.place, size) != size) {
                result.value().address.reset();
                result.value().constant.reset();
                result.value().reason = MachOResolutionReason::unsupported;
                break;
            }
        }
        return result;
    });
}
Result<std::optional<Address>> RelocationResolver::control_target(const Image &image, const Instruction &instruction,
                                                                  std::stop_token stop) const {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Control resolution canceled"};
    if (source_image_ && source_image_ != &image)
        return Error{ErrorCode::conflict, "Control policy belongs to another image"};
    if (image.code_window(instruction.address, instruction.length) != instruction.length)
        return std::optional<Address>{};
    if (dyld_) {
        if (&image != source_image_)
            return Error{ErrorCode::conflict, "Control fixups belong to another image"};
        if (instruction.flow != FlowKind::call && instruction.flow != FlowKind::jump &&
            instruction.flow != FlowKind::conditional_branch)
            return std::optional<Address>{};
        auto opaque = instruction_fixup(instruction, stop);
        if (!opaque)
            return opaque.error();
        if (opaque.value())
            return std::optional<Address>{};
        if (!instruction.operands.empty()) {
            auto value = operand(instruction, analysis_detail::control_operand_index(instruction), stop);
            if (!value)
                return value.error();
            if (value.value().dyld) {
                const auto &use = *value.value().dyld;
                if (use.use != MachODyldUse::memory_slot || !use.resolution.address ||
                    !std::holds_alternative<MemoryOperand>(
                        instruction.operands[analysis_detail::control_operand_index(instruction)]))
                    return std::optional<Address>{};
                const auto target = *use.resolution.address;
                const auto *segment = image.segment_at(target);
                if (!segment || !segment->executable || target.offset - segment->begin.offset >= segment->file_size)
                    return std::optional<Address>{};
                const auto allowed = code_start(target, stop);
                if (!allowed)
                    return allowed.error();
                return allowed.value() ? std::optional<Address>{target} : std::nullopt;
            }
        }
    }
    auto resolved = std::visit([&](const auto &resolver) { return resolver.control_target(image, instruction, stop); }, value_);
    if (!resolved || resolved.value())
        return resolved;
    if (analysis_detail::is_arm_literal_pc_load(instruction)) {
        const auto &memory = std::get<ArmMemoryOperand>(instruction.operands[1]);
        const auto slot = *memory.resolved_address;
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "ARM literal control resolution canceled"};
        if (!source_metadata_ || instruction.context.order != ByteOrder::little || image.plaintext_window(slot, 4) != 4 ||
            (source_metadata_ && relocation_overlaps(image, *source_metadata_, slot, 4)))
            return std::optional<Address>{};
        const auto bytes = image.read(slot, 4);
        if (!bytes)
            return bytes.error();
        const auto value = std::uint32_t(std::to_integer<unsigned>(bytes.value()[0])) |
                           (std::uint32_t(std::to_integer<unsigned>(bytes.value()[1])) << 8) |
                           (std::uint32_t(std::to_integer<unsigned>(bytes.value()[2])) << 16) |
                           (std::uint32_t(std::to_integer<unsigned>(bytes.value()[3])) << 24);
        const bool thumb = (value & 1) != 0;
        const auto target = Address{instruction.address.space, std::uint64_t(value & (thumb ? ~1u : ~3u))};
        const auto context = image.context_at(target);
        if (!context || context.value().architecture != Architecture::arm ||
            context.value().mode != (thumb ? ExecutionMode::thumb : ExecutionMode::a32))
            return std::optional<Address>{};
        return std::optional<Address>{target};
    }
    if (instruction.opcode != Opcode::rv_jalr)
        return resolved;
    return riscv_pcrel_jalr_target(*this, image, source_metadata_, instruction, stop);
}
const ElfSymbol *RelocationResolver::elf_symbol(std::uint64_t row) const noexcept {
    const auto *resolver = std::get_if<ElfRelocationResolver>(&value_);
    return resolver ? resolver->symbol(row) : nullptr;
}
const MachOSymbol *RelocationResolver::macho_symbol(std::uint64_t row) const noexcept {
    const auto *resolver = std::get_if<MachORelocationResolver>(&value_);
    return resolver ? resolver->symbol(row) : nullptr;
}
} // namespace hexlab
