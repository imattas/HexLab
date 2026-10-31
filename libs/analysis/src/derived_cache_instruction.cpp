#include "derived_cache_internal.hpp"
#include "arm_operand_codec.hpp"
#include "dex_switch_internal.hpp"
namespace hexlab::derived_detail {
namespace {
void arm_info(Writer &out, const std::optional<ArmInstructionInfo> &value) {
    out.flag(value.has_value());
    if (!value)
        return;
    const auto &a = *value;
    require(static_cast<unsigned>(a.predicate) <= static_cast<unsigned>(ArmPredicate::unknown_it) &&
                static_cast<unsigned>(a.exchange) <= static_cast<unsigned>(ArmExchange::forced_thumb) &&
                a.flags_written <= 15 &&
                static_cast<unsigned>(a.multiple_mode) <= static_cast<unsigned>(ArmMultipleMode::db),
            "Invalid ARM control metadata");
    out.number(static_cast<unsigned>(a.predicate), 1);
    out.number(static_cast<unsigned>(a.exchange), 1);
    out.number(a.flags_written, 1);
    out.flag(a.flags_known);
    out.flag(a.q_flag_may_set);
    out.flag(a.writes_pc);
    out.flag(a.writeback);
    out.number(static_cast<unsigned>(a.multiple_mode), 1);
    for (const auto state : {a.it_before, a.it_after}) {
        require(state.known || !state.bits, "Unknown IT state carries invented bits");
        out.flag(state.known);
        out.number(state.bits, 1);
    }
    for (const auto mode : {a.target_mode, a.return_mode}) {
        out.flag(mode.has_value());
        if (mode)
            require(*mode == ExecutionMode::a32 || *mode == ExecutionMode::thumb, "Invalid ARM control state");
        if (mode)
            out.number(static_cast<unsigned>(*mode), 1);
    }
    out.optional_address(a.link_address);
}
ThumbITState read_arm_info(Reader &in, DecodeContext context) {
    const bool present = in.flag();
    require(present == (context.architecture == Architecture::arm), "ARM control metadata/context mismatch");
    if (!present)
        return {};
    require(in.number(1) <= static_cast<unsigned>(ArmPredicate::unknown_it), "Invalid ARM predicate");
    require(in.number(1) <= static_cast<unsigned>(ArmExchange::forced_thumb), "Invalid ARM exchange");
    require(in.number(1) <= 15, "Invalid ARM flags mask");
    in.flag();
    in.flag();
    in.flag();
    in.flag();
    require(in.number(1) <= static_cast<unsigned>(ArmMultipleMode::db), "Invalid ARM multiple addressing mode");
    ThumbITState before;
    for (unsigned n = 0; n < 2; ++n) {
        const auto known = in.flag();
        const auto bits = in.number(1);
        require(known || !bits, "Unknown IT state carries invented bits");
        if (n == 0)
            before = {known, static_cast<std::uint8_t>(bits)};
    }
    for (unsigned n = 0; n < 2; ++n)
        if (in.flag()) {
            const auto mode = static_cast<ExecutionMode>(in.number(1));
            require(mode == ExecutionMode::a32 || mode == ExecutionMode::thumb, "Invalid ARM control state");
        }
    in.optional_address();
    // This is framing, not authority: canonical decoding below validates every
    // field against source bytes. Thumb state provenance is added with Task4.
    return before;
}
void field(Writer &out, const std::optional<EncodedField> &value) {
    out.flag(bool(value));
    if (value) {
        require(value->size && value->offset < 15 && value->size <= 15 - value->offset,
                "Invalid cached operand field extent");
        out.number(value->offset, 1);
        out.number(value->size, 1);
    }
}
void reg(Writer &out, const RegisterOperand &value) {
    out.number(static_cast<unsigned>(value.bank), 1);
    out.number(value.index, 2);
    out.number(value.width, 2);
    out.flag(value.high_byte);
}
void optional_reg(Writer &out, const std::optional<RegisterOperand> &value) {
    out.flag(value.has_value());
    if (value)
        reg(out, *value);
}
void memory(Writer &out, const MemoryOperand &value) {
    out.number(value.data_width, 2);
    out.number(value.address_width, 2);
    optional_reg(out, value.segment);
    optional_reg(out, value.base);
    optional_reg(out, value.index);
    out.number(value.scale, 1);
    out.signed_number(value.displacement);
    out.flag(value.ip_relative);
    out.flag(value.writeback);
    out.flag(value.post_index);
    out.signed_number(value.writeback_displacement);
    out.optional_address(value.resolved_address);
    field(out, value.displacement_encoding);
}
} // namespace
std::vector<std::byte> instruction_bytes(const Instruction &value, std::stop_token stop) {
    const auto encoded = value.encoded_bytes();
    require(value.byte_length() > 0 && value.byte_length() == encoded.size() && value.operands.size() <= 16 &&
                value.operands.size() == value.access.size() && value.register_reads.size() <= 64 &&
                value.register_writes.size() <= 64,
            "Invalid cached instruction shape");
    Writer out{{}, stop};
    out.context(value.context);
    out.address(value.address);
    arm_info(out, value.arm);
    out.number(value.byte_length(), 4);
    out.append(encoded);
    out.number(static_cast<unsigned>(value.opcode), 2);
    out.number(value.operands.size(), 1);
    for (auto &operand : value.operands) {
        out.number(operand.index(), 1);
        std::visit(
            [&](auto &part) {
                using T = std::decay_t<decltype(part)>;
                if constexpr (std::is_same_v<T, RegisterOperand>)
                    reg(out, part);
                else if constexpr (std::is_same_v<T, MemoryOperand>)
                    memory(out, part);
                else if constexpr (std::is_same_v<T, ImmediateOperand>) {
                    out.number(part.value);
                    out.number(part.encoded_width, 2);
                    out.number(part.effective_width, 2);
                    out.flag(part.is_signed);
                    field(out, part.encoding);
                } else if constexpr (std::is_same_v<T, RelativeOperand>) {
                    out.signed_number(part.displacement);
                    out.number(part.encoded_width, 2);
                    out.number(part.effective_width, 2);
                    field(out, part.encoding);
                } else if constexpr (std::is_same_v<T, FarPointerOperand>) {
                    out.number(part.selector, 2);
                    out.number(part.offset, 4);
                    out.number(part.offset_width, 2);
                    field(out, part.offset_encoding);
                    field(out, part.selector_encoding);
                } else if constexpr (std::is_same_v<T, FarMemoryOperand>) {
                    memory(out, part.address);
                    out.number(part.offset_width, 2);
                } else if constexpr (std::is_same_v<T, ArmShiftedRegisterOperand>) {
                    require(arm_operand_detail::valid_shift(part), "Invalid cached ARM shifter");
                    arm_operand_detail::write_shift(out, part);
                } else if constexpr (std::is_same_v<T, ArmMemoryOperand>) {
                    require(arm_operand_detail::valid_memory(part), "Invalid cached ARM memory");
                    arm_operand_detail::write_memory(out, part);
                } else if constexpr (std::is_same_v<T, ArmRegisterListOperand>) {
                    require(part.mask != 0, "Empty cached ARM register list");
                    out.number(part.mask, 2);
                } else if constexpr (std::is_same_v<T, ThumbRelativeOperand>) {
                    require(arm_operand_detail::valid_thumb_relative(part), "Invalid cached Thumb relative");
                    out.signed_number(part.displacement);
                    out.number(part.encoded_width, 2);
                }
            },
            operand);
    }
    out.number(value.access.size(), 1);
    for (auto access : value.access)
        out.number(static_cast<unsigned>(access), 1);
    out.number(value.register_reads.size(), 1);
    for (auto &r : value.register_reads)
        reg(out, r);
    out.number(value.register_writes.size(), 1);
    for (auto &r : value.register_writes)
        reg(out, r);
    out.number(static_cast<unsigned>(value.flow), 1);
    out.optional_address(value.direct_target);
    out.number(value.condition, 1);
    out.flag(value.memory_read);
    out.flag(value.memory_write);
    out.number(value.stack_value_width, 2);
    out.number(value.stack_slot_count, 1);
    out.flag(value.lock_prefix);
    out.flag(value.dex_switch.has_value());
    if (value.dex_switch) {
        const auto &table = *value.dex_switch;
        require(value.context.architecture == Architecture::dex && value.opcode == Opcode::dex_switch &&
                    value.flow == FlowKind::switch_dispatch && table.validated &&
                    table.payload.space == value.address.space && table.cases.size() <= 1024,
                "Invalid cached DEX switch table");
        out.flag(table.packed);
        out.address(table.payload);
        out.count(table.cases.size(), 1024);
        for (const auto &item : table.cases) {
            require(item.target.space == value.address.space,
                    "Cached DEX switch case escapes its method address space");
            out.signed_number(item.value);
            out.address(item.target);
        }
    }
    out.flag(value.jvm_switch.has_value());
    if (value.jvm_switch) {
        const auto &table = *value.jvm_switch;
        require(value.context.architecture == Architecture::jvm && value.opcode == Opcode::jvm &&
                    value.flow == FlowKind::switch_dispatch && value.direct_target == table.default_target &&
                    table.cases.size() <= 1024,
                "Invalid cached JVM switch table");
        out.flag(table.dense);
        out.address(table.default_target);
        out.count(table.cases.size(), 1024);
        for (const auto &item : table.cases) {
            require(item.target.space == value.address.space,
                    "Cached JVM switch case escapes its method address space");
            out.signed_number(item.value);
            out.address(item.target);
        }
    }
    return std::move(out.bytes);
}
CheckedInstruction checked_instruction(std::span<const std::byte> payload, std::span<const DomainContext> domains,
                                       const Image *image, const AnalysisOptions& options, std::stop_token stop) {
    require(payload.size() <= 32768, "Cached instruction record exceeds field budget");
    Reader in{payload, stop};
    auto context = in.context();
    auto at = in.address();
    const auto thumb_state = read_arm_info(in, context);
    require(context == context_for(domains, at), "Cached instruction domain context differs from its declared source");
    if (image)
        require(take(image->context_at(at)) == context,
                "Cached instruction context differs from authoritative image domain");
    auto length = in.number(4);
    require(length > 0 && length <= 65535, "Invalid cached instruction length");
    require(!image || image->code_window(at, length) == length,
            "Cached instruction crosses authoritative data/encryption policy");
    auto raw = in.read(static_cast<size_t>(length));
    auto decoded = context.mode == ExecutionMode::thumb ? decode_thumb(raw, at, thumb_state)
                                                        : take(decode_analysis_instruction(context, raw, at, options));
    require(decoded.status == DecodeStatus::decoded && decoded.instruction && decoded.instruction->byte_length() == length,
            "Cached instruction bytes cannot be decoded by this engine");
    if (decoded.instruction->opcode == Opcode::dex_switch) {
        if (!image) {
            // Proposal validation has no image handle. Verify the canonical
            // instruction prefix; the cache reader reconstructs and verifies
            // all case facts against the bound image before reuse.
            auto base = *decoded.instruction;
            base.dex_switch.reset();
            auto prefix = instruction_bytes(base, stop);
            require(!prefix.empty(), "Invalid cached DEX switch instruction");
            prefix.resize(prefix.size() - 2); // optional DEX and JVM switch presence bytes
            require(payload.size() >= prefix.size() &&
                        std::equal(prefix.begin(), prefix.end(), payload.begin()),
                    "Cached DEX switch instruction bytes differ from canonical decoding");
            return {std::move(*decoded.instruction), decoded.semantic_decoder_used};
        }
        auto table = function_detail::populate_dex_switch_table(*image, *decoded.instruction, nullptr, stop);
        if (!table)
            throw Failure{table.error()};
        require(table.value(), "Cached DEX switch payload is unavailable");
    }
    auto canonical = instruction_bytes(*decoded.instruction, stop);
    require(canonical.size() == payload.size() && std::equal(canonical.begin(), canonical.end(), payload.begin()),
            "Cached typed operands/modifiers differ from decoded bytes");
    return {std::move(*decoded.instruction), decoded.semantic_decoder_used};
}
Sha256Digest checksum(std::span<const std::byte> bytes, std::stop_token stop) {
    Sha256 hash;
    for (size_t offset = 0; offset < bytes.size();) {
        canceled(stop);
        auto amount = std::min<size_t>(65536, bytes.size() - offset);
        take(hash.update(bytes.subspan(offset, amount)));
        offset += amount;
    }
    canceled(stop);
    return hash.digest();
}
} // namespace hexlab::derived_detail
