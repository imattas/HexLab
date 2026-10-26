#include "references_internal.hpp"
#include "arm_operand_codec.hpp"
#include <algorithm>
#include <cstring>
#include <functional>
#include <set>
namespace hexlab::reference_detail {
namespace {
struct Writer {
    std::vector<std::byte> bytes;
    void append(std::span<const std::byte> value) {
        require(value.size() <= reference_payload_limit - bytes.size(), "Reference payload exceeds 64 MiB budget");
        bytes.insert(bytes.end(), value.begin(), value.end());
    }
    void number(uint64_t value, size_t width) {
        std::array<std::byte, 8> encoded{};
        for (size_t i = 0; i < width; ++i)
            encoded[width - i - 1] = std::byte(value >> (8 * i));
        append(std::span(encoded).first(width));
    }
    void signed_number(int64_t value) { number(value < 0 ? uint64_t(-(value + 1)) * 2 + 1 : uint64_t(value) * 2, 8); }
    void text(std::string_view value) {
        require(value.size() <= 65536, "Reference text exceeds field budget");
        number(value.size(), 4);
        append(std::as_bytes(std::span(value)));
    }
    void address(Address value) {
        number(value.space.value, 4);
        number(value.offset, 8);
    }
    void location(Location value) {
        if (auto numeric = std::get_if<Address>(&value)) {
            number(0, 1);
            address(*numeric);
        } else {
            number(1, 1);
            number(std::get<FileOffset>(value).value, 8);
        }
    }
    void optional_location(const std::optional<Location> &value) {
        number(value ? 1 : 0, 1);
        if (value)
            location(*value);
    }
    void reg(const RegisterOperand &value) {
        number(static_cast<unsigned>(value.bank), 1);
        number(value.index, 1);
        number(value.width, 2);
        number(value.high_byte, 1);
    }
    void optional_reg(const std::optional<RegisterOperand> &value) {
        number(value ? 1 : 0, 1);
        if (value)
            reg(*value);
    }
    void field(const std::optional<EncodedField> &value) {
        number(bool(value), 1);
        if (value) {
            number(value->offset, 1);
            number(value->size, 1);
        }
    }
    void memory(const MemoryOperand &value) {
        number(value.data_width, 2);
        number(value.address_width, 2);
        optional_reg(value.segment);
        optional_reg(value.base);
        optional_reg(value.index);
        number(value.scale, 1);
        signed_number(value.displacement);
        number(value.ip_relative, 1);
        number(value.writeback, 1);
        number(value.post_index, 1);
        signed_number(value.writeback_displacement);
        number(value.resolved_address ? 1 : 0, 1);
        if (value.resolved_address)
            address(*value.resolved_address);
        field(value.displacement_encoding);
    }
    void external(const ExternalIdentity &value) {
        text(value.library);
        number(value.name ? 0 : 1, 1);
        if (value.name)
            text(*value.name);
        else
            number(*value.ordinal, 2);
    }
    void elf_vtable(const ElfVTableReferenceProvenance &value) {
        address(value.table_begin);
        address(value.address_point);
        address(value.type_info);
        address(value.slot);
        number(value.slot_index, 4);
        number(value.symbol_index, 4);
        number(value.type_name ? 1 : 0, 1);
        if (value.type_name)
            text(*value.type_name);
    }
    void expression(const ReferenceExpression &value) {
        number(value.index(), 1);
        std::visit(
            [&](const auto &part) {
                using T = std::decay_t<decltype(part)>;
                if constexpr (std::is_same_v<T, RegisterOperand>)
                    reg(part);
                else if constexpr (std::is_same_v<T, MemoryOperand>)
                    memory(part);
                else if constexpr (std::is_same_v<T, RelativeOperand>) {
                    signed_number(part.displacement);
                    number(part.encoded_width, 2);
                    number(part.effective_width, 2);
                    field(part.encoding);
                } else if constexpr (std::is_same_v<T, FarPointerOperand>) {
                    number(part.selector, 2);
                    number(part.offset, 4);
                    number(part.offset_width, 2);
                    field(part.offset_encoding);
                    field(part.selector_encoding);
                } else if constexpr (std::is_same_v<T, FarMemoryOperand>) {
                    memory(part.address);
                    number(part.offset_width, 2);
                } else if constexpr (std::is_same_v<T, ArmMemoryOperand>) {
                    arm_operand_detail::write_memory(*this, part);
                } else if constexpr (std::is_same_v<T, ThumbRelativeOperand>) {
                    signed_number(part.displacement);
                    number(part.encoded_width, 2);
                }
            },
            value);
    }
    void record(const Reference &value, bool include_producer_graph = false) {
        number(2, 1);
        location(value.source);
        number(value.operand_index ? 1 : 0, 1);
        if (value.operand_index)
            number(*value.operand_index, 4);
        number(value.target.index(), 1);
        std::visit(
            [&](const auto &target) {
                using T = std::decay_t<decltype(target)>;
                if constexpr (std::is_same_v<T, Location>)
                    location(target);
                else if constexpr (std::is_same_v<T, ExternalIdentity>)
                    external(target);
                else {
                    number(static_cast<unsigned>(target.reason), 1);
                    expression(target.expression);
                }
            },
            value.target);
        number(static_cast<unsigned>(value.kind), 1);
        number(static_cast<unsigned>(value.access), 1);
        number(static_cast<unsigned>(value.provenance.kind), 1);
        number(value.provenance.instruction_id, 8);
        number(value.provenance.user_id, 8);
        optional_location(value.association);
        require(value.provenance.producer_instruction_ids.size() <= 32,
                "Reference producer chain exceeds 32 instruction IDs");
        number(value.provenance.producer_instruction_ids.size(), 1);
        for (const auto producer : value.provenance.producer_instruction_ids) number(producer, 8);
        if (include_producer_graph) {
            const auto &graph = value.provenance.producer_graph;
            require(graph.dependencies.size() <= 128, "Reference producer graph exceeds 128 dependencies");
            number((graph.truncated ? 1u : 0u) | (graph.ambiguous ? 2u : 0u) | (graph.cycle ? 4u : 0u), 1);
            number(graph.dependencies.size(), 2);
            for (const auto &edge : graph.dependencies) {
                number(edge.consumer_instruction_id, 8);
                number(edge.producer_instruction_id, 8);
            }
            require(graph.immediates.size() <= 32, "Reference producer immediates exceed 32 operands");
            number(graph.immediates.size(), 1);
            for (const auto &immediate : graph.immediates) {
                number(immediate.instruction_id, 8);
                number(immediate.operand_index, 1);
                number(immediate.value, 8);
                number(immediate.encoded_width, 2);
                number(immediate.effective_width, 2);
                number(immediate.is_signed ? 1 : 0, 1);
            }
        }
        if (value.provenance.kind == ReferenceProvenanceKind::elf_relocation) {
            const auto encoded = elf_provenance_bytes(*value.provenance.elf);
            number(encoded.size(), 4);
            append(encoded);
        }
        if (value.provenance.kind == ReferenceProvenanceKind::elf_vtable_slot)
            elf_vtable(*value.provenance.elf_vtable);
        if (value.provenance.kind == ReferenceProvenanceKind::macho_relocation) {
            const auto encoded = macho_provenance_bytes(*value.provenance.macho);
            number(encoded.size(), 4);
            append(encoded);
        }
        if (value.provenance.kind == ReferenceProvenanceKind::macho_dyld) {
            const auto encoded = dyld_provenance_bytes(*value.provenance.dyld);
            number(encoded.size(), 4);
            append(encoded);
        }
    }
    void key(const AnalysisKey &value) {
        number(value.input.size, 8);
        append(value.input.sha256);
        number(value.byte_revision, 8);
        number(value.decision_revision, 8);
        append(value.recipe_fingerprint);
        append(value.engine_fingerprint);
    }
};
struct Reader {
    std::span<const std::byte> bytes;
    size_t cursor = 0;
    unsigned payload_version = 0;
    std::span<const std::byte> read(size_t count) {
        require(count <= bytes.size() - cursor, "Truncated reference payload");
        auto result = bytes.subspan(cursor, count);
        cursor += count;
        return result;
    }
    uint64_t number(size_t width) {
        uint64_t value = 0;
        for (auto byte : read(width))
            value = (value << 8) | std::to_integer<unsigned>(byte);
        return value;
    }
    bool flag() {
        const auto value = number(1);
        require(value <= 1, "Invalid reference flag");
        return value != 0;
    }
    int64_t signed_number() {
        const auto value = number(8);
        return value & 1 ? -static_cast<int64_t>(value >> 1) - 1 : static_cast<int64_t>(value >> 1);
    }
    std::string text() {
        const auto size = number(4);
        require(size <= 65536, "Reference text exceeds field budget");
        const auto value = read(static_cast<size_t>(size));
        if (value.empty())
            return {};
        return {reinterpret_cast<const char *>(value.data()), value.size()};
    }
    Address address() {
        const auto space = number(4);
        return {{static_cast<uint32_t>(space)}, number(8)};
    }
    Location location() {
        const auto tag = number(1);
        if (tag == 0)
            return address();
        require(tag == 1, "Unknown reference location domain");
        return FileOffset{number(8)};
    }
    std::optional<Location> optional_location() {
        if (!flag())
            return {};
        return location();
    }
    RegisterOperand reg() {
        const auto bank = static_cast<RegisterBank>(number(1));
        const auto index = static_cast<uint8_t>(number(1));
        const auto width = static_cast<uint16_t>(number(2));
        return {bank, index, width, flag()};
    }
    std::optional<RegisterOperand> optional_reg() {
        if (!flag())
            return {};
        return reg();
    }
    std::optional<EncodedField> field() {
        if (!flag())
            return {};
        const auto offset = static_cast<std::uint8_t>(number(1));
        return EncodedField{offset, static_cast<std::uint8_t>(number(1))};
    }
    MemoryOperand memory() {
        MemoryOperand value;
        value.data_width = static_cast<uint16_t>(number(2));
        value.address_width = static_cast<uint16_t>(number(2));
        value.segment = optional_reg();
        value.base = optional_reg();
        value.index = optional_reg();
        value.scale = static_cast<uint8_t>(number(1));
        value.displacement = signed_number();
        value.ip_relative = flag();
        if (payload_version >= 10) {
            value.writeback = flag();
            value.post_index = flag();
            value.writeback_displacement = signed_number();
        }
        if (flag())
            value.resolved_address = address();
        value.displacement_encoding = field();
        return value;
    }
    ExternalIdentity external() {
        ExternalIdentity value;
        value.library = text();
        const auto kind = number(1);
        if (kind == 0)
            value.name = text();
        else {
            require(kind == 1, "Unknown external symbol selector");
            value.ordinal = static_cast<uint16_t>(number(2));
        }
        return value;
    }
    ElfVTableReferenceProvenance elf_vtable() {
        ElfVTableReferenceProvenance value;
        value.table_begin = address();
        value.address_point = address();
        value.type_info = address();
        value.slot = address();
        value.slot_index = static_cast<std::uint32_t>(number(4));
        value.symbol_index = static_cast<std::uint32_t>(number(4));
        if (flag())
            value.type_name = text();
        return value;
    }
    ReferenceExpression expression() {
        const auto tag = number(1);
        if (tag == 0)
            return std::monostate{};
        if (tag == 1)
            return reg();
        if (tag == 2)
            return memory();
        if (tag == 4) {
            const auto selector = static_cast<std::uint16_t>(number(2));
            const auto offset = static_cast<std::uint32_t>(number(4));
            const auto width = static_cast<std::uint16_t>(number(2));
            const auto offset_field = field(), selector_field = field();
            return FarPointerOperand{selector, offset, width, offset_field, selector_field};
        }
        if (tag == 5) {
            auto address = memory();
            return FarMemoryOperand{std::move(address), static_cast<std::uint16_t>(number(2))};
        }
        if (tag == 6) {
            require(payload_version >= 8, "ARM memory expression requires reference payload8");
            return arm_operand_detail::read_memory(*this, require);
        }
        if (tag == 7) {
            require(payload_version >= 9, "Thumb relative expression requires reference payload9");
            const auto displacement = signed_number();
            return ThumbRelativeOperand{displacement, static_cast<std::uint16_t>(number(2))};
        }
        require(tag == 3, "Unknown reference expression kind");
        const auto displacement = signed_number();
        const auto encoded = static_cast<uint16_t>(number(2));
        const auto effective = static_cast<std::uint16_t>(number(2));
        return RelativeOperand{displacement, encoded, effective, field()};
    }
    Reference record() {
        Reference value{};
        require(number(1) == 2, "Unknown reference record version");
        value.source = location();
        if (flag())
            value.operand_index = static_cast<uint32_t>(number(4));
        const auto tag = number(1);
        if (tag == 0)
            value.target = location();
        else if (tag == 1)
            value.target = external();
        else {
            require(tag == 2, "Unknown reference target kind");
            auto reason = static_cast<UnresolvedReason>(number(1));
            value.target = UnresolvedTarget{reason, expression()};
        }
        value.kind = static_cast<ReferenceKind>(number(1));
        value.access = static_cast<OperandAccess>(number(1));
        value.provenance.kind = static_cast<ReferenceProvenanceKind>(number(1));
        value.provenance.instruction_id = number(8);
        value.provenance.user_id = number(8);
        value.association = optional_location();
        if (payload_version >= 12) {
            const auto producer_count = number(1);
            require(producer_count <= 32, "Reference producer chain exceeds bound");
            value.provenance.producer_instruction_ids.reserve(static_cast<std::size_t>(producer_count));
            for (std::uint64_t i = 0; i < producer_count; ++i)
                value.provenance.producer_instruction_ids.push_back(number(8));
        }
        if (payload_version >= 13) {
            const auto flags = number(1);
            require((flags & ~7u) == 0, "Invalid reference producer graph flags");
            auto &graph = value.provenance.producer_graph;
            graph.truncated = (flags & 1u) != 0;
            graph.ambiguous = (flags & 2u) != 0;
            graph.cycle = (flags & 4u) != 0;
            const auto count = number(2);
            require(count <= 128, "Reference producer graph exceeds bound");
            graph.dependencies.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i)
                graph.dependencies.push_back({number(8), number(8)});
        }
        if (payload_version >= 15) {
            auto &graph = value.provenance.producer_graph;
            const auto count = number(1);
            require(count <= 32, "Reference producer immediates exceed bound");
            graph.immediates.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                ReferenceProducerImmediate immediate;
                immediate.instruction_id = number(8);
                immediate.operand_index = static_cast<std::uint32_t>(number(1));
                immediate.value = number(8);
                immediate.encoded_width = static_cast<std::uint16_t>(number(2));
                immediate.effective_width = static_cast<std::uint16_t>(number(2));
                const auto is_signed = number(1);
                require(is_signed <= 1, "Invalid reference producer immediate signed flag");
                immediate.is_signed = is_signed != 0;
                graph.immediates.push_back(immediate);
            }
        }
        if (value.provenance.kind == ReferenceProvenanceKind::elf_relocation) {
            const auto size = number(4);
            require(size <= reference_payload_limit, "ELF provenance record exceeds bound");
            value.provenance.elf = read_elf_provenance(read(static_cast<std::size_t>(size)));
        }
        if (value.provenance.kind == ReferenceProvenanceKind::elf_vtable_slot) {
            require(payload_version >= 11, "ELF vtable provenance requires reference payload11");
            value.provenance.elf_vtable = elf_vtable();
        }
        if (value.provenance.kind == ReferenceProvenanceKind::macho_relocation) {
            const auto size = number(4);
            require(size <= reference_payload_limit, "Mach-O provenance record exceeds bound");
            value.provenance.macho = read_macho_provenance(read(static_cast<std::size_t>(size)));
        }
        if (value.provenance.kind == ReferenceProvenanceKind::macho_dyld) {
            const auto size = number(4);
            require(size <= reference_payload_limit, "Dyld provenance record exceeds bound");
            value.provenance.dyld = std::make_shared<const MachODyldReferenceProvenance>(
                read_dyld_provenance(read(static_cast<std::size_t>(size))));
        }
        return value;
    }
    AnalysisKey key() {
        AnalysisKey value;
        value.input.size = number(8);
        auto digest = read(32);
        std::copy(digest.begin(), digest.end(), value.input.sha256.begin());
        value.byte_revision = number(8);
        value.decision_revision = number(8);
        digest = read(32);
        std::copy(digest.begin(), digest.end(), value.recipe_fingerprint.begin());
        digest = read(32);
        std::copy(digest.begin(), digest.end(), value.engine_fingerprint.begin());
        return value;
    }
};
bool width(uint16_t value) { return value == 8 || value == 16 || value == 32 || value == 64; }
void validate_reg(const RegisterOperand &value) {
    if (value.bank == RegisterBank::riscv_gpr) {
        require(value.index < 32 && (value.width == 32 || value.width == 64) && !value.high_byte, "Invalid RISC-V register expression");
        return;
    }
    if (value.bank == RegisterBank::mos6502) {
        require(value.index < 5 && value.width == 8 && !value.high_byte, "Invalid MOS 6502 register expression");
        return;
    }
    if (value.bank == RegisterBank::mips_gpr || value.bank == RegisterBank::mips_hilo ||
        value.bank == RegisterBank::mips_cp0) {
        const auto limit = value.bank == RegisterBank::mips_hilo ? 2 : 32;
        require(value.index < limit && value.width == 32 && !value.high_byte, "Invalid MIPS register expression");
        return;
    }
    if (value.bank == RegisterBank::ppc_gpr || value.bank == RegisterBank::ppc_fpr) {
        require(value.index < 32 && (value.width == 32 || value.width == 64) && !value.high_byte,
                "Invalid PowerPC scalar register expression");
        return;
    }
    if (value.bank == RegisterBank::ppc_cr) {
        require(!value.high_byte && ((value.width == 4 && value.index < 8) ||
                (value.width == 32 && value.index == 0)), "Invalid PowerPC condition register expression");
        return;
    }
    if (value.bank == RegisterBank::ppc_lr || value.bank == RegisterBank::ppc_ctr) {
        require(value.index == 0 && (value.width == 32 || value.width == 64) && !value.high_byte,
                "Invalid PowerPC control register expression");
        return;
    }
    if (value.bank == RegisterBank::ppc_xer || value.bank == RegisterBank::ppc_fpscr) {
        require(value.index == 0 && value.width == 32 && !value.high_byte,
                "Invalid PowerPC status register expression");
        return;
    }
    if (value.bank >= RegisterBank::arm32_gpr && value.bank <= RegisterBank::arm_flags) {
        const bool general =
            value.bank == RegisterBank::arm64_gpr && value.index < 31 && (value.width == 32 || value.width == 64);
        const bool special = (value.bank == RegisterBank::arm64_sp || value.bank == RegisterBank::arm64_zero) &&
                             value.index == 31 && (value.width == 32 || value.width == 64);
        const bool flags = value.bank == RegisterBank::arm_flags && value.index == 0 && value.width == 4;
        const bool arm32 = value.bank == RegisterBank::arm32_gpr && value.index < 16 && value.width == 32;
        require(!value.high_byte && (general || special || flags || arm32), "Invalid ARM register expression");
        return;
    }
    require(static_cast<unsigned>(value.bank) <= static_cast<unsigned>(RegisterBank::segment) && width(value.width),
            "Invalid register expression");
    require(value.index < (value.bank == RegisterBank::gpr       ? 16
                           : value.bank == RegisterBank::segment ? 6
                                                                 : 1),
            "Register index exceeds bank");
    require(!value.high_byte || (value.bank == RegisterBank::gpr && value.width == 8 && value.index < 8),
            "Invalid high-byte register expression");
}
void validate_field(const std::optional<EncodedField> &field, unsigned size = 0) {
    if (!field)
        return;
    require(field->size && field->offset < 15 && field->size <= 15 - field->offset &&
                (size ? field->size == size
                      : (field->size == 1 || field->size == 2 || field->size == 4 || field->size == 8)),
            "Invalid reference operand field extent");
}
void validate_memory(const MemoryOperand &value) {
    validate_field(value.displacement_encoding);
    require((value.data_width == 0 || width(value.data_width) || value.data_width == 80 || value.data_width == 128 ||
             value.data_width == 256 || value.data_width == 512) &&
                (value.address_width == 16 || value.address_width == 32 || value.address_width == 64),
            "Invalid memory widths");
    require(value.scale == 1 || value.scale == 2 || value.scale == 4 || value.scale == 8, "Invalid memory scale");
    require((value.writeback || (!value.post_index && value.writeback_displacement == 0)) &&
                (!value.post_index || value.writeback) && (!value.writeback || value.base.has_value()),
            "Invalid memory writeback metadata");
    for (const auto *reg : {&value.segment, &value.base, &value.index})
        if (*reg)
            validate_reg(**reg);
    if (value.segment)
        require(value.segment->bank == RegisterBank::segment && value.segment->width == 16,
                "Invalid segment expression");
    if (value.base)
        require(value.base->bank == RegisterBank::gpr || value.base->bank == RegisterBank::ip ||
                    (value.base->bank == RegisterBank::riscv_gpr && (value.base->width == 32 || value.base->width == 64)) ||
                    (value.base->bank == RegisterBank::mips_gpr && value.base->width == 32) ||
                    (value.base->bank == RegisterBank::arm32_gpr && value.base->width == 32) ||
                    ((value.base->bank == RegisterBank::arm64_gpr || value.base->bank == RegisterBank::arm64_sp) &&
                     value.base->width == 64),
                "Invalid memory base bank");
    if (value.index)
        require(value.index->bank == RegisterBank::gpr || value.index->bank == RegisterBank::riscv_gpr ||
                    value.index->bank == RegisterBank::arm32_gpr ||
                    value.index->bank == RegisterBank::arm64_gpr || value.index->bank == RegisterBank::mos6502,
                "Invalid memory index bank");
    require(!value.segment || !value.resolved_address, "Segment-dependent memory cannot claim a flat address");
}
} // namespace
bool valid_external(const ExternalIdentity &value) {
    const auto valid_text = [](const std::string &text) {
        return !text.empty() && text.size() <= 65536 && text.find('\0') == std::string::npos;
    };
    return valid_text(value.library) && value.name.has_value() != value.ordinal.has_value() &&
           (!value.name || valid_text(*value.name));
}
std::string external_key(const ExternalIdentity &value) {
    require(valid_external(value), "Invalid external identity");
    Writer out;
    out.external(value);
    return {reinterpret_cast<const char *>(out.bytes.data()), out.bytes.size()};
}
void validate_dyld_reference(const Reference &value) {
    const auto &p = *value.provenance.dyld;
    validate_dyld_provenance(p);
    require(!value.provenance.user_id && value.kind != ReferenceKind::imported_call &&
                value.kind != ReferenceKind::imported_jump,
            "Dyld reference claims user/host import identity");
    const auto *location = std::get_if<Location>(&value.target);
    const auto *unknown = std::get_if<UnresolvedTarget>(&value.target);
    const auto unresolved = [&] {
        require(unknown && unknown->reason == UnresolvedReason::macho_dyld, "Dyld unresolved target reason mismatch");
    };
    const auto matches_source = [&](Location source) {
        return std::any_of(p.origins.begin(), p.origins.end(), [&](const auto &origin) {
            return std::visit(
                [&](const auto &record) {
                    const auto &row = [&]() -> const auto & {
                        if constexpr (std::is_same_v<std::decay_t<decltype(record)>, MachODyldClassicOrigin>)
                            return record.fixup;
                        else
                            return record.pointer;
                    }();
                    return (row.place && source == Location{*row.place}) ||
                           (row.file_place && source == Location{*row.file_place});
                },
                origin.record);
        });
    };
    if (p.use == MachODyldUse::raw_data) {
        require(value.kind == ReferenceKind::dyld_fixup && value.access == OperandAccess::address &&
                    !value.provenance.instruction_id && !value.operand_index && !value.association &&
                    matches_source(value.source),
                "Raw dyld source/identity mismatch");
        if (p.resolution.address)
            require(location && *location == Location{*p.resolution.address},
                    "Raw dyld target differs from stored pointer");
        else {
            unresolved();
            require(std::holds_alternative<std::monostate>(unknown->expression),
                    "Raw dyld result claims operand expression");
        }
        return;
    }
    const auto *source = std::get_if<Address>(&value.source);
    require(source && source->space.value == 0 && value.provenance.instruction_id,
            "Decoded dyld source lacks instruction identity");
    for (const auto &query : p.queries) {
        if (query.field)
            require(query.field->offset <= UINT64_MAX - source->offset &&
                        query.at == Address{source->space, source->offset + query.field->offset},
                    "Dyld instruction query differs from encoded span");
        require(
            std::any_of(
                p.origins.begin(), p.origins.end(),
                [&](const auto &origin) {
                    return std::visit(
                        [&](const auto &record) {
                            const auto &row = [&]() -> const auto & {
                                if constexpr (std::is_same_v<std::decay_t<decltype(record)>, MachODyldClassicOrigin>)
                                    return record.fixup;
                                else
                                    return record.pointer;
                            }();
                            return row.place && row.place->space == query.at.space &&
                                   (query.at.offset >= row.place->offset
                                        ? query.at.offset - row.place->offset < (row.field_size ? row.field_size : 1)
                                        : row.place->offset - query.at.offset < query.width);
                        },
                        origin.record);
                }),
            "Dyld query has no original overlapping field");
    }
    if (p.use == MachODyldUse::instruction_bytes) {
        require(value.kind == ReferenceKind::dyld_fixup && value.access == OperandAccess::address &&
                    !value.operand_index && !value.association &&
                    p.resolution.reason == MachODyldResolutionReason::unsupported,
                "Opaque instruction claims decoded control/data meaning");
        unresolved();
        require(std::holds_alternative<std::monostate>(unknown->expression),
                "Opaque instruction claims operand meaning");
        return;
    }
    require(value.operand_index.has_value(), "Decoded dyld use lacks operand index");
    const bool control = value.kind == ReferenceKind::call || value.kind == ReferenceKind::jump ||
                         value.kind == ReferenceKind::conditional_jump;
    const bool memory = value.kind == ReferenceKind::memory_read || value.kind == ReferenceKind::memory_write ||
                        value.kind == ReferenceKind::memory_read_write || value.kind == ReferenceKind::memory_address;
    if (p.use == MachODyldUse::memory_slot) {
        const Location slot{p.queries.front().at};
        if (control) {
            require(value.association == slot, "Dyld control association differs from read storage");
            if (location)
                require(p.resolution.address && *location == Location{*p.resolution.address},
                        "Dyld callee is a slot instead of its proven value");
            else {
                unresolved();
                const auto *expression = std::get_if<MemoryOperand>(&unknown->expression);
                require(expression && expression->resolved_address == p.queries.front().at,
                        "Dyld control expression differs from source slot");
            }
        } else
            require(memory && location && *location == slot && !value.association,
                    "Dyld memory access must target storage, not stored value");
    } else {
        require(p.use == MachODyldUse::encoded_field, "Unknown decoded dyld usage");
        if (control) {
            unresolved();
            if (value.association) {
                const auto *expression = std::get_if<MemoryOperand>(&unknown->expression);
                require(expression && expression->resolved_address &&
                            value.association == Location{*expression->resolved_address},
                        "Encoded dyld memory association mismatch");
            }
        } else {
            require(memory || value.kind == ReferenceKind::dyld_fixup,
                    "Encoded dyld reference has unknown operand role");
            require(!value.association, "Encoded data reference claims control association");
            if (location)
                require(p.resolution.address && *location == Location{*p.resolution.address},
                        "Encoded dyld address differs from field value");
            else
                unresolved();
        }
    }
}
void validate_reference(const Reference &value) {
    require(!value.target.valueless_by_exception() &&
                static_cast<unsigned>(value.kind) <= static_cast<unsigned>(ReferenceKind::dyld_fixup) &&
                static_cast<unsigned>(value.access) <= static_cast<unsigned>(OperandAccess::address) &&
                static_cast<unsigned>(value.provenance.kind) <=
                    static_cast<unsigned>(ReferenceProvenanceKind::elf_vtable_slot),
            "Unknown reference kind/access/provenance");
    require(value.provenance.producer_instruction_ids.size() <= 32,
            "Reference producer chain exceeds bound");
    if (!value.provenance.producer_instruction_ids.empty()) {
        require(value.provenance.kind == ReferenceProvenanceKind::dataflow,
                "Producer chain requires dataflow provenance");
        std::set<std::uint64_t> producers;
        for (const auto producer : value.provenance.producer_instruction_ids)
            require(producer && producer != value.provenance.instruction_id && producers.insert(producer).second,
                    "Invalid or duplicate dataflow producer ID");
    }
    const auto &producer_graph = value.provenance.producer_graph;
    require(producer_graph.dependencies.size() <= 128, "Reference producer graph exceeds bound");
    require(producer_graph.immediates.size() <= 32, "Reference producer immediates exceed bound");
    const bool has_graph = !producer_graph.dependencies.empty() || producer_graph.truncated ||
                           producer_graph.ambiguous || producer_graph.cycle || !producer_graph.immediates.empty();
    require(!has_graph || value.provenance.kind == ReferenceProvenanceKind::dataflow,
            "Producer graph requires dataflow provenance");
    std::set<std::pair<std::uint64_t, std::uint32_t>> immediate_identities;
    for (const auto &immediate : producer_graph.immediates)
        require(immediate.instruction_id && immediate.operand_index < 16 &&
                    immediate.encoded_width <= 512 && immediate.effective_width <= 512 &&
                    immediate_identities.emplace(immediate.instruction_id, immediate.operand_index).second,
                "Invalid or duplicate producer immediate");
    std::map<std::uint64_t, std::set<std::uint64_t>> dependency_graph;
    for (const auto &edge : producer_graph.dependencies) {
        require(edge.consumer_instruction_id && edge.producer_instruction_id &&
                    edge.consumer_instruction_id != edge.producer_instruction_id &&
                    dependency_graph[edge.consumer_instruction_id].insert(edge.producer_instruction_id).second,
                "Invalid or duplicate producer dependency");
    }
    std::map<std::uint64_t, std::uint8_t> visit;
    std::function<void(std::uint64_t)> check_acyclic = [&](std::uint64_t node) {
        require(visit[node] != 1, "Cyclic reference producer graph");
        if (visit[node] == 2) return;
        visit[node] = 1;
        if (auto edges = dependency_graph.find(node); edges != dependency_graph.end())
            for (const auto producer : edges->second) check_acyclic(producer);
        visit[node] = 2;
    };
    for (const auto &[node, edges] : dependency_graph) { (void)edges; check_acyclic(node); }
    require(!value.operand_index || *value.operand_index < 16, "Reference operand index exceeds model bounds");
    const bool imported = value.kind == ReferenceKind::imported_call || value.kind == ReferenceKind::imported_jump;
    const bool control = imported || value.kind == ReferenceKind::call || value.kind == ReferenceKind::jump ||
                         value.kind == ReferenceKind::conditional_jump;
    const bool memory_kind = value.kind == ReferenceKind::memory_read || value.kind == ReferenceKind::memory_write ||
                             value.kind == ReferenceKind::memory_read_write ||
                             value.kind == ReferenceKind::memory_address;
    const bool elf = value.provenance.kind == ReferenceProvenanceKind::elf_relocation;
    const bool elf_vtable = value.provenance.kind == ReferenceProvenanceKind::elf_vtable_slot;
    const bool macho = value.provenance.kind == ReferenceProvenanceKind::macho_relocation;
    const bool dyld = value.provenance.kind == ReferenceProvenanceKind::macho_dyld;
    require(elf == value.provenance.elf.has_value(), "ELF reference origin/kind mismatch");
    require(elf_vtable == value.provenance.elf_vtable.has_value(), "ELF vtable reference origin/kind mismatch");
    require(macho == value.provenance.macho.has_value(), "Mach-O reference origin/kind mismatch");
    require(dyld == bool(value.provenance.dyld), "Dyld reference origin/kind mismatch");
    if (dyld)
        validate_dyld_reference(value);
    require(value.kind != ReferenceKind::dyld_fixup || dyld, "Dyld fixup lacks original provenance");
    require(value.kind != ReferenceKind::relocation || elf || macho, "Relocation reference lacks original provenance");
    require(value.kind != ReferenceKind::relocation || value.access == OperandAccess::address,
            "Relocation reference has memory access semantics");
    if (elf) {
        validate_elf_provenance(*value.provenance.elf);
        require(value.provenance.user_id == 0 && !imported, "ELF reference cannot claim user/import provenance");
        if (value.provenance.instruction_id)
            require(std::holds_alternative<Address>(value.source) && value.operand_index,
                    "Decoded ELF reference lacks instruction operand identity");
        else {
            require(value.kind == ReferenceKind::relocation && !value.operand_index && !value.association,
                    "Raw ELF reference has decoded/control identity");
            require(std::any_of(value.provenance.elf->origins.begin(), value.provenance.elf->origins.end(),
                                [&](const auto &origin) {
                                    return (origin.relocation.place &&
                                            value.source == Location{*origin.relocation.place}) ||
                                           (origin.relocation.file_place &&
                                            value.source == Location{*origin.relocation.file_place});
                                }),
                    "Raw ELF reference source differs from original field");
        }
        const auto *unresolved = std::get_if<UnresolvedTarget>(&value.target);
        if (value.provenance.elf->resolution == ElfResolutionReason::resolved) {
            require(std::holds_alternative<Location>(value.target) ||
                        (control && unresolved && unresolved->reason == UnresolvedReason::memory_value &&
                         value.association),
                    "Resolved ELF address lacks numeric target or stored-value association");
        } else
            require(unresolved && unresolved->reason == UnresolvedReason::elf_relocation,
                    "Unresolved ELF origin claims a numeric target");
    } else if (macho) {
        const auto &p = *value.provenance.macho;
        validate_macho_provenance(p);
        require(value.provenance.user_id == 0 && !imported, "Mach-O reference cannot claim user/import provenance");
        if (value.provenance.instruction_id)
            require(std::holds_alternative<Address>(value.source) && value.operand_index,
                    "Decoded Mach-O reference lacks instruction operand identity");
        else {
            require(value.kind == ReferenceKind::relocation && !value.operand_index && !value.association,
                    "Raw Mach-O reference has decoded/control identity");
            require(std::any_of(p.origins.begin(), p.origins.end(),
                                [&](const auto &origin) {
                                    return (origin.relocation.place &&
                                            value.source == Location{*origin.relocation.place}) ||
                                           (origin.relocation.file_place &&
                                            value.source == Location{*origin.relocation.file_place});
                                }),
                    "Raw Mach-O reference source differs from original field");
        }
        const auto *unresolved = std::get_if<UnresolvedTarget>(&value.target);
        if (p.resolution == MachOResolutionReason::resolved && !p.constant)
            require(std::holds_alternative<Location>(value.target) ||
                        (control && unresolved && unresolved->reason == UnresolvedReason::memory_value &&
                         value.association),
                    "Resolved Mach-O address lacks numeric target or stored-value association");
        else {
            require(unresolved && unresolved->reason == UnresolvedReason::macho_relocation,
                    p.constant ? "Mach-O scalar constant emitted as pointer target"
                               : "Mach-O unresolved address claims pointer target");
            require(!value.association, "Mach-O unresolved relocation has pointer association");
        }
    } else if (dyld) {
        // The owned dyld branch validates raw, operand and opcode-window uses.
    } else if (elf_vtable) {
        const auto &p = *value.provenance.elf_vtable;
        require(value.provenance.user_id == 0 && value.provenance.instruction_id == 0 &&
                    !value.operand_index && !value.association && value.kind == ReferenceKind::memory_address &&
                    value.access == OperandAccess::address && std::holds_alternative<Address>(value.source),
                "Invalid ELF vtable reference role");
        require(p.table_begin.space == p.address_point.space && p.table_begin.space == p.type_info.space &&
                    p.table_begin.space == p.slot.space && p.table_begin.offset <= UINT64_MAX - 16 &&
                    p.address_point.offset == p.table_begin.offset + 16 && p.type_info.offset != 0 &&
                    p.slot.offset >= p.address_point.offset && ((p.slot.offset - p.address_point.offset) % 8) == 0 &&
                    (p.slot.offset - p.address_point.offset) / 8 == p.slot_index && p.slot_index < 65536 &&
                    p.symbol_index != 0 && (!p.type_name || p.type_name->size() <= 1024),
                "Invalid ELF vtable slot provenance");
        const auto *target = std::get_if<Location>(&value.target);
        const auto *target_address = target ? std::get_if<Address>(target) : nullptr;
        require(value.source == Location{p.slot} && target_address && target_address->space == p.slot.space,
                "ELF vtable xref differs from validated slot metadata");
    } else if (value.provenance.kind == ReferenceProvenanceKind::user)
        require(value.provenance.user_id != 0 && value.provenance.instruction_id == 0 && !value.operand_index &&
                    !value.association && !imported && std::holds_alternative<Location>(value.target),
                "Invalid user reference provenance");
    else
        require(value.provenance.user_id == 0 && value.provenance.instruction_id != 0 &&
                    std::holds_alternative<Address>(value.source),
                "Invalid decoded reference provenance");
    if (value.kind == ReferenceKind::user_code || value.kind == ReferenceKind::user_data)
        require(value.provenance.kind == ReferenceProvenanceKind::user && value.access == OperandAccess::address,
                "Explicit reference kind has no user provenance");
    if (value.provenance.kind != ReferenceProvenanceKind::user)
        if (auto location = std::get_if<Location>(&value.target))
            require(std::holds_alternative<Address>(*location), "Decoded references require an address target domain");
    require(imported == (value.provenance.kind == ReferenceProvenanceKind::import_slot),
            "Import provenance/kind mismatch");
    if (value.kind == ReferenceKind::memory_read)
        require(value.access == OperandAccess::read, "Memory read access mismatch");
    if (value.kind == ReferenceKind::memory_write)
        require(value.access == OperandAccess::write, "Memory write access mismatch");
    if (value.kind == ReferenceKind::memory_read_write)
        require(value.access == OperandAccess::read_write, "Memory read-write access mismatch");
    if (value.kind == ReferenceKind::memory_address || imported || value.kind == ReferenceKind::call ||
        value.kind == ReferenceKind::jump || value.kind == ReferenceKind::conditional_jump)
        require(value.access == OperandAccess::address, "Control/address access mismatch");
    if (imported)
        require(std::holds_alternative<ExternalIdentity>(value.target) && value.operand_index && value.association &&
                    std::holds_alternative<Address>(*value.association),
                "Import reference needs external identity and numeric slot association");
    if (const auto *external = std::get_if<ExternalIdentity>(&value.target))
        require(imported && valid_external(*external), "Invalid external reference identity");
    if (const auto *unresolved = std::get_if<UnresolvedTarget>(&value.target)) {
        require(static_cast<unsigned>(unresolved->reason) <= static_cast<unsigned>(UnresolvedReason::macho_dyld),
                "Unknown unresolved reference reason");
        require(unresolved->reason != UnresolvedReason::macho_dyld || dyld,
                "Dyld unresolved target lacks original provenance");
        require(unresolved->reason != UnresolvedReason::elf_relocation || elf,
                "ELF unresolved target lacks original provenance");
        require(unresolved->reason != UnresolvedReason::macho_relocation || macho,
                "Mach-O unresolved target lacks original provenance");
        if (memory_kind)
            require(unresolved->reason == UnresolvedReason::memory_address ||
                        (unresolved->reason == UnresolvedReason::elf_relocation ||
                         unresolved->reason == UnresolvedReason::macho_relocation ||
                         unresolved->reason == UnresolvedReason::macho_dyld),
                    "Data reference must describe an address expression");
        if (control)
            require(unresolved->reason != UnresolvedReason::memory_address,
                    "Indirect control reference must describe a target value");
        if (const auto *reg = std::get_if<RegisterOperand>(&unresolved->expression)) {
            require(unresolved->reason == UnresolvedReason::register_value, "Register target reason mismatch");
            validate_reg(*reg);
        } else if (const auto *memory = std::get_if<MemoryOperand>(&unresolved->expression)) {
            require(unresolved->reason == UnresolvedReason::memory_address ||
                        unresolved->reason == UnresolvedReason::memory_value ||
                        (unresolved->reason == UnresolvedReason::elf_relocation ||
                         unresolved->reason == UnresolvedReason::macho_relocation ||
                         unresolved->reason == UnresolvedReason::macho_dyld) ||
                        unresolved->reason == UnresolvedReason::ambiguous_import,
                    "Memory target reason mismatch");
            validate_memory(*memory);
        } else if (const auto *relative = std::get_if<RelativeOperand>(&unresolved->expression)) {
            validate_field(relative->encoding, relative->encoded_width / 8);
            const bool packed_a64 =
                !relative->encoding && relative->effective_width == 64 && control &&
                (relative->encoded_width == 14 || relative->encoded_width == 19 || relative->encoded_width == 26) &&
                relative->displacement % 4 == 0 &&
                relative->displacement >= -(INT64_C(1) << (relative->encoded_width + 1)) &&
                relative->displacement < (INT64_C(1) << (relative->encoded_width + 1));
            require(
                (unresolved->reason == UnresolvedReason::relative_overflow ||
                 (unresolved->reason == UnresolvedReason::elf_relocation ||
                  unresolved->reason == UnresolvedReason::macho_relocation ||
                  unresolved->reason == UnresolvedReason::macho_dyld)) &&
                    (width(relative->encoded_width) || packed_a64 ||
                     (!relative->encoding && control && relative->effective_width == 32 &&
                      (relative->encoded_width == 24 || relative->encoded_width == 25) &&
                      relative->displacement % (relative->encoded_width == 24 ? 4 : 2) == 0 &&
                      relative->displacement >= -(INT64_C(1) << 25) && relative->displacement < (INT64_C(1) << 25))) &&
                    (relative->effective_width == 0 || relative->effective_width == 16 ||
                     relative->effective_width == 32 || relative->effective_width == 64),
                "Invalid relative target expression");
        } else if (const auto *thumb = std::get_if<ThumbRelativeOperand>(&unresolved->expression)) {
            require(control && arm_operand_detail::valid_thumb_relative(*thumb), "Invalid Thumb relative expression");
            require(unresolved->reason == UnresolvedReason::relative_overflow ||
                        unresolved->reason == UnresolvedReason::elf_relocation ||
                        unresolved->reason == UnresolvedReason::macho_relocation ||
                        unresolved->reason == UnresolvedReason::macho_dyld,
                    "Thumb relative reason mismatch");
        } else if (const auto *far = std::get_if<FarPointerOperand>(&unresolved->expression)) {
            validate_field(far->offset_encoding, far->offset_width / 8);
            validate_field(far->selector_encoding, 2);
            require(control &&
                        (unresolved->reason == UnresolvedReason::far_selector ||
                         (unresolved->reason == UnresolvedReason::elf_relocation ||
                          unresolved->reason == UnresolvedReason::macho_relocation ||
                          unresolved->reason == UnresolvedReason::macho_dyld)) &&
                        (far->offset_width == 16 || far->offset_width == 32) &&
                        (far->offset_width == 32 || far->offset <= 0xffff),
                    "Invalid far pointer target expression");
        } else if (const auto *far_memory = std::get_if<FarMemoryOperand>(&unresolved->expression)) {
            require((unresolved->reason == UnresolvedReason::memory_address ||
                     (unresolved->reason == UnresolvedReason::elf_relocation ||
                      unresolved->reason == UnresolvedReason::macho_relocation ||
                      unresolved->reason == UnresolvedReason::macho_dyld) ||
                     unresolved->reason == UnresolvedReason::memory_value) &&
                        (far_memory->offset_width == 16 || far_memory->offset_width == 32) &&
                        far_memory->address.data_width == far_memory->offset_width + 16,
                    "Invalid stored far pointer expression");
            auto address = far_memory->address;
            address.data_width = 0;
            validate_memory(address);
        } else if (const auto *arm = std::get_if<ArmMemoryOperand>(&unresolved->expression)) {
            require(arm_operand_detail::valid_memory(*arm), "Invalid ARM memory reference expression");
            require(unresolved->reason == UnresolvedReason::memory_address ||
                        unresolved->reason == UnresolvedReason::memory_value ||
                        unresolved->reason == UnresolvedReason::elf_relocation ||
                        unresolved->reason == UnresolvedReason::macho_relocation ||
                        unresolved->reason == UnresolvedReason::macho_dyld,
                    "Invalid ARM memory reference reason");
            require(unresolved->reason != UnresolvedReason::memory_address || !arm->resolved_address,
                    "Resolved ARM address cannot claim unavailable address");
            require(!arm->sign_extend || value.access != OperandAccess::write,
                    "ARM store cannot sign extend its source");
        } else
            require(unresolved->reason == UnresolvedReason::missing_operand ||
                        (unresolved->reason == UnresolvedReason::elf_relocation ||
                         unresolved->reason == UnresolvedReason::macho_relocation ||
                         unresolved->reason == UnresolvedReason::macho_dyld),
                    "Missing target reason mismatch");
    }
    if (value.association) {
        require(control && std::holds_alternative<Address>(*value.association),
                "Only indirect control references have numeric slot associations");
        if (!imported && !dyld) {
            const auto *unresolved = std::get_if<UnresolvedTarget>(&value.target);
            require(unresolved != nullptr, "Resolved control target cannot have an indirect slot association");
            const auto *memory = std::get_if<MemoryOperand>(&unresolved->expression);
            if (const auto *far = std::get_if<FarMemoryOperand>(&unresolved->expression))
                memory = &far->address;
            const auto *arm = std::get_if<ArmMemoryOperand>(&unresolved->expression);
            const auto address = memory ? memory->resolved_address : arm ? arm->resolved_address : std::nullopt;
            require(address && Location{*address} == *value.association,
                    "Control slot association differs from its memory expression");
        }
    }
}
std::vector<std::byte> reference_key(const Reference &value) {
    validate_reference(value);
    Writer out;
    out.record(value, false);
    return std::move(out.bytes);
}
Sha256Digest checked_hash(std::span<const std::byte> bytes, std::stop_token stop) {
    Sha256 hash;
    for (size_t cursor = 0; cursor < bytes.size();) {
        canceled(stop);
        const auto amount = std::min<size_t>(65536, bytes.size() - cursor);
        take(hash.update(bytes.subspan(cursor, amount)));
        cursor += amount;
    }
    canceled(stop);
    return hash.digest();
}
} // namespace hexlab::reference_detail
namespace hexlab {
Result<std::vector<std::byte>> encode_reference_index(const ReferenceIndex &index, std::stop_token stop) {
    return reference_detail::guarded([&]() -> Result<std::vector<std::byte>> {
        using namespace reference_detail;
        canceled(stop);
        Writer out;
        out.number(15, 1);
        out.number(0, 1);
        out.number(index.key() ? 1 : 0, 1);
        if (index.key())
            out.key(*index.key());
        out.number(index.complete(), 1);
        out.number(index.all().size(), 4);
        for (const auto &reference : index.all()) {
            canceled(stop);
            out.number(reference.id.value, 8);
            out.record(reference, true);
        }
        const auto digest = checked_hash(out.bytes, stop);
        out.append(digest);
        return std::move(out.bytes);
    });
}
Result<std::shared_ptr<const ReferenceIndex>> decode_reference_index(std::span<const std::byte> bytes,
                                                                     std::stop_token stop) {
    return reference_detail::guarded([&]() -> Result<std::shared_ptr<const ReferenceIndex>> {
        using namespace reference_detail;
        canceled(stop);
        require(bytes.size() >= 40 && bytes.size() <= reference_payload_limit, "Invalid reference payload extent");
        const auto payload = bytes.first(bytes.size() - 32);
        const auto digest = checked_hash(payload, stop);
        require(std::equal(digest.begin(), digest.end(), bytes.last(32).begin()),
                "Reference payload checksum mismatch");
        Reader in{payload};
        in.payload_version = static_cast<unsigned>(in.number(1));
        require((in.payload_version == 7 || in.payload_version == 8 || in.payload_version == 9 ||
                 in.payload_version == 10 || in.payload_version == 11 || in.payload_version == 12 ||
                 in.payload_version == 13 || in.payload_version == 14 || in.payload_version == 15) && in.number(1) == 0,
                "Unknown reference payload version");
        std::optional<AnalysisKey> key;
        if (in.flag())
            key = in.key();
        const bool complete = in.flag();
        const auto count = in.number(4);
        require(count <= reference_record_limit && count <= (payload.size() - in.cursor) / 32,
                "Invalid reference record count");
        std::vector<Reference> references;
        references.reserve(static_cast<size_t>(std::min<uint64_t>(count, 4096)));
        for (uint64_t i = 0; i < count; ++i) {
            canceled(stop);
            const auto id = in.number(8);
            require(id != 0, "Zero cached reference identity");
            auto reference = in.record();
            // Older record versions have no producer-chain field. Their IDs
            // were hashed from the older canonical record shape, so migrate
            // the identity from decoded content while upgrading in memory.
            reference.id = in.payload_version >= 12 ? ReferenceId{id} : ReferenceId{};
            references.push_back(std::move(reference));
        }
        require(in.cursor == payload.size(), "Trailing reference payload bytes");
        return ReferenceIndex::create(std::move(references), std::move(key), complete, stop);
    });
}
} // namespace hexlab
