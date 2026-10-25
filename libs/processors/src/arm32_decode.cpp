#include "arm32_internal.hpp"
#include <algorithm>
#include <limits>
namespace hexlab {
namespace {
RegisterOperand gpr(unsigned n) { return {RegisterBank::arm32_gpr, static_cast<std::uint8_t>(n), 32, false}; }
std::optional<Address> offset(Address at, std::int64_t displacement) {
    const auto result = static_cast<std::int64_t>(at.offset) + displacement;
    if (result < 0 || result > UINT32_MAX)
        return {};
    return Address{at.space, static_cast<std::uint64_t>(result)};
}
void link(Instruction &i) {
    i.register_writes.push_back(gpr(14));
    i.arm->return_mode = ExecutionMode::a32;
    i.arm->link_address = offset(i.address, 4);
}
void branch(Instruction &i, std::uint32_t word, bool exchange) {
    auto imm = static_cast<std::int64_t>(word & 0xffffff) * 4;
    if (word & 0x800000)
        imm -= INT64_C(1) << 26;
    if (exchange)
        imm += (word >> 23) & 2;
    const bool call = exchange || (word & 0x1000000);
    i.opcode = exchange ? Opcode::a32_blx : call ? Opcode::a32_bl : Opcode::a32_b;
    i.flow = call ? FlowKind::call : i.condition < 14 ? FlowKind::conditional_branch : FlowKind::jump;
    i.operands.emplace_back(RelativeOperand{imm, static_cast<std::uint16_t>(exchange ? 25 : 24), 32, {}});
    i.access.push_back(OperandAccess::read);
    i.direct_target = offset(i.address, 8 + imm);
    i.arm->writes_pc = true;
    i.arm->target_mode = exchange ? ExecutionMode::thumb : ExecutionMode::a32;
    i.arm->exchange = exchange ? ArmExchange::forced_thumb : ArmExchange::none;
    if (call)
        link(i);
}
} // namespace
DecodeResult decode_a32(std::span<const std::byte> bytes, Address at) {
    if ((at.offset & 3) || at.offset > UINT32_MAX)
        return {DecodeStatus::invalid, {}, "A32 requires an aligned 32-bit address"};
    if (bytes.size() < 4)
        return {DecodeStatus::truncated, {}, "A32 instruction requires four bytes"};
    std::uint32_t word = 0;
    for (unsigned n = 0; n < 4; ++n)
        word |= std::to_integer<std::uint32_t>(bytes[n]) << (8 * n);
    Instruction i;
    i.context = {Architecture::arm, ExecutionMode::a32, ByteOrder::little};
    i.address = at;
    i.length = 4;
    std::copy_n(bytes.begin(), 4, i.bytes.begin());
    i.arm.emplace();
    i.condition = static_cast<std::uint8_t>(word >> 28);
    const bool immediate_exchange = (word & 0xfe000000) == 0xfa000000;
    if (immediate_exchange)
        i.condition = 14; // COND=1111 is an encoding space, not a predicate.
    if (i.condition == 15)
        return {DecodeStatus::unsupported, {}, "Unconditional A32 extension encoding is not enabled"};
    if (i.condition < 14) {
        i.arm->predicate = ArmPredicate::condition;
        i.register_reads.push_back({RegisterBank::arm_flags, 0, 4, false});
    }
    if (immediate_exchange || (word & 0x0e000000) == 0x0a000000) {
        branch(i, word, immediate_exchange);
    } else if ((word & 0x0ffffff0) == 0x012fff10 || (word & 0x0ffffff0) == 0x012fff30) {
        const auto rm = word & 15;
        if (rm == 15)
            return {DecodeStatus::unsupported, {}, "A32 PC exchange operand is not enabled"};
        const bool call = (word & 0x20) != 0;
        i.opcode = call ? Opcode::a32_blx : Opcode::a32_bx;
        i.flow = call ? FlowKind::call : rm == 14 ? FlowKind::ret : FlowKind::jump;
        i.operands.emplace_back(gpr(rm));
        i.access.push_back(OperandAccess::read);
        i.register_reads.push_back(gpr(rm));
        i.arm->exchange = ArmExchange::address_bit0;
        i.arm->writes_pc = true;
        if (call)
            link(i);
    } else if ((word & 0x0fffffff) == 0x0320f000) {
        i.opcode = Opcode::a32_nop;
    } else if ((word & 0x0ff000f0) == 0x01200070 && i.condition == 14) {
        i.opcode = Opcode::a32_bkpt;
        i.flow = FlowKind::trap;
        i.operands.emplace_back(ImmediateOperand{((word >> 4) & 0xfff0) | (word & 15), 16, 32, false, {}});
        i.access.push_back(OperandAccess::read);
    } else if ((word & 0x0f000000) == 0x0f000000) {
        i.opcode = Opcode::a32_svc;
        i.flow = FlowKind::trap;
        i.operands.emplace_back(ImmediateOperand{word & 0xffffff, 24, 32, false, {}});
        i.access.push_back(OperandAccess::read);
    } else if (!arm32_detail::memory(i, word) && !arm32_detail::data(i, word)) {
        return {DecodeStatus::unsupported, {}, "A32 encoding has no enabled decoder"};
    }
    if (i.arm->writes_pc && i.flow == FlowKind::jump && i.condition < 14)
        i.flow = FlowKind::conditional_branch;
    return {DecodeStatus::decoded, std::move(i), {}};
}
} // namespace hexlab
