#include "x64_internal.hpp"

namespace hexlab::x64_detail {
ModRM modrm(State &s, std::uint16_t rm_width, std::uint16_t reg_width) {
    if (!reg_width)
        reg_width = rm_width;
    const auto byte = static_cast<std::uint8_t>(s.take(1));
    const auto mode = static_cast<std::uint8_t>(byte >> 6);
    const auto raw_reg = static_cast<std::uint8_t>((byte >> 3) & 7);
    const auto raw_rm = static_cast<std::uint8_t>(byte & 7);
    const auto reg = s.reg(raw_reg, reg_width, (s.rex & 4) != 0);
    if (mode == 3)
        return {raw_reg, mode, reg, s.reg(raw_rm, rm_width, (s.rex & 1) != 0)};
    MemoryOperand memory;
    memory.data_width = rm_width;
    memory.address_width = s.rules.address_width(s.address_override);
    memory.segment = s.segment;
    if (memory.address_width == 16) {
        constexpr int bases[] = {3, 3, 5, 5, 6, 7, 5, 3}, indexes[] = {6, 7, 6, 7, -1, -1, -1, -1};
        if (mode == 0 && raw_rm == 6)
            memory.displacement = static_cast<std::int64_t>(s.encoded(2, memory.displacement_encoding));
        else {
            memory.base = s.reg(static_cast<unsigned>(bases[raw_rm]), 16, false);
            if (indexes[raw_rm] >= 0)
                memory.index = s.reg(static_cast<unsigned>(indexes[raw_rm]), 16, false);
            if (mode == 1)
                memory.displacement = sign_value(s.encoded(1, memory.displacement_encoding), 8);
            else if (mode == 2)
                memory.displacement = sign_value(s.encoded(2, memory.displacement_encoding), 16);
        }
        if (s.rules.segmented_memory() && !memory.segment)
            memory.segment =
                RegisterOperand{RegisterBank::segment,
                                static_cast<std::uint8_t>(memory.base && memory.base->index == 5 ? 2 : 3), 16, false};
        return {raw_reg, mode, reg, memory};
    }
    bool displacement32 = false;
    if (raw_rm == 4) {
        const auto sib = static_cast<std::uint8_t>(s.take(1));
        const auto index = static_cast<std::uint8_t>((sib >> 3) & 7), base = static_cast<std::uint8_t>(sib & 7);
        memory.scale = static_cast<std::uint8_t>(1u << (sib >> 6));
        if (index != 4 || (s.rex & 2))
            memory.index = s.reg(index, memory.address_width, (s.rex & 2) != 0);
        if (mode == 0 && base == 5)
            displacement32 = true;
        else
            memory.base = s.reg(base, memory.address_width, (s.rex & 1) != 0);
    } else if (mode == 0 && raw_rm == 5) {
        if (s.rules.long_mode()) {
            memory.base = RegisterOperand{RegisterBank::ip, 0, memory.address_width, false};
            memory.ip_relative = true;
        }
        displacement32 = true;
    } else
        memory.base = s.reg(raw_rm, memory.address_width, (s.rex & 1) != 0);
    if (mode == 1)
        memory.displacement = sign_value(s.encoded(1, memory.displacement_encoding), 8);
    else if (mode == 2 || displacement32)
        memory.displacement = sign_value(s.encoded(4, memory.displacement_encoding), 32);
    if (s.rules.segmented_memory() && !memory.segment)
        memory.segment = RegisterOperand{
            RegisterBank::segment,
            static_cast<std::uint8_t>(memory.base && (memory.base->index == 4 || memory.base->index == 5) ? 2 : 3), 16,
            false};
    return {raw_reg, mode, reg, memory};
}
namespace {
void add_register(std::vector<RegisterOperand> &set, RegisterOperand reg) {
    if (std::find(set.begin(), set.end(), reg) == set.end())
        set.push_back(reg);
}
std::optional<Address> relative(Address next, std::int64_t displacement) {
    if (displacement < 0) {
        const auto amount = static_cast<std::uint64_t>(-(displacement + 1)) + 1;
        if (amount > next.offset)
            return {};
        return Address{next.space, next.offset - amount};
    }
    const auto result = checked_add(next.offset, static_cast<std::uint64_t>(displacement));
    return result ? std::optional<Address>(Address{next.space, result.value()}) : std::nullopt;
}
} // namespace
void finish(State &s, std::string &reason) {
    s.i.length = static_cast<std::uint8_t>(s.position);
    std::copy_n(s.input.begin(), s.position, s.i.bytes.begin());
    if (s.group1 == 0xf0 && !s.lock_allowed)
        invalid("LOCK is not valid for this instruction/operand form");
    s.i.lock_prefix = s.group1 == 0xf0;
    const auto next =
        s.rules.long_mode()
            ? advance(s.i.address, s.position)
            : Result<Address>{Address{s.i.address.space, static_cast<std::uint32_t>(s.i.address.offset + s.position)}};
    if (!next)
        reason = "Instruction end exceeds address space";
    for (std::size_t n = 0; n < s.i.operands.size(); ++n) {
        auto &operand = s.i.operands[n];
        const auto access = s.i.access[n];
        const bool reads = access == OperandAccess::read || access == OperandAccess::read_write;
        const bool writes = access == OperandAccess::write || access == OperandAccess::read_write;
        auto *memory_operand = std::get_if<MemoryOperand>(&operand);
        if (auto *far = std::get_if<FarMemoryOperand>(&operand))
            memory_operand = &far->address;
        if (auto *reg = std::get_if<RegisterOperand>(&operand)) {
            if (reads)
                add_register(s.i.register_reads, *reg);
            if (writes)
                add_register(s.i.register_writes, *reg);
        } else if (auto *memory = memory_operand) {
            if (s.i.opcode == Opcode::nop)
                continue;
            if (memory->segment)
                add_register(s.i.register_reads, *memory->segment);
            if (memory->base)
                add_register(s.i.register_reads, *memory->base);
            if (memory->index)
                add_register(s.i.register_reads, *memory->index);
            s.i.memory_read |= reads;
            s.i.memory_write |= writes;
            if (!memory->segment && !s.rules.segmented_memory()) {
                if (memory->ip_relative && next) {
                    if (memory->address_width == 32) {
                        const auto address =
                            static_cast<std::int64_t>(static_cast<std::uint32_t>(next.value().offset)) +
                            memory->displacement;
                        memory->resolved_address = Address{next.value().space, static_cast<std::uint32_t>(address)};
                    } else
                        memory->resolved_address = relative(next.value(), memory->displacement);
                } else if (!memory->base && !memory->index)
                    memory->resolved_address =
                        Address{s.i.address.space, memory->address_width == 32
                                                       ? static_cast<std::uint32_t>(memory->displacement)
                                                       : static_cast<std::uint64_t>(memory->displacement)};
            }
        } else if (const auto *rel = std::get_if<RelativeOperand>(&operand)) {
            if (next) {
                if (rel->effective_width == 16 || rel->effective_width == 32) {
                    auto value = next.value().offset + static_cast<std::uint64_t>(rel->displacement);
                    s.i.direct_target =
                        Address{next.value().space, rel->effective_width == 16 ? static_cast<std::uint16_t>(value)
                                                                               : static_cast<std::uint32_t>(value)};
                } else
                    s.i.direct_target = relative(next.value(), rel->displacement);
            }
            if (!s.i.direct_target)
                reason = "Relative target exceeds address model";
        }
    }
    if (s.flags_read)
        add_register(s.i.register_reads, {RegisterBank::flags, 0, s.rules.pointer_width(), false});
    if (s.flags_write)
        add_register(s.i.register_writes, {RegisterBank::flags, 0, s.rules.pointer_width(), false});
}
} // namespace hexlab::x64_detail
