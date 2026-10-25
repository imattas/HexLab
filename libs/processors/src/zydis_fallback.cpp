#include "x64_internal.hpp"
#include <Zydis/Decoder.h>
#include <Zydis/Formatter.h>
#include <array>

namespace hexlab::x64_detail {
DecodeResult decode_zydis_fallback(std::span<const std::byte> bytes, Address address, DecodeContext context) {
    const auto mode = context.mode == ExecutionMode::x86_64 ? ZYDIS_MACHINE_MODE_LONG_64
                    : context.mode == ExecutionMode::x86_16 ? ZYDIS_MACHINE_MODE_LEGACY_16
                                                            : ZYDIS_MACHINE_MODE_LEGACY_32;
    const auto stack_width = context.stack_address_width ? context.stack_address_width
                              : context.mode == ExecutionMode::x86_64 ? 64
                              : context.mode == ExecutionMode::x86_16 ? 16 : 32;
    const auto stack = stack_width == 16 ? ZYDIS_STACK_WIDTH_16
                       : stack_width == 64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;
    ZydisDecoder decoder{};
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, mode, stack)))
        return {DecodeStatus::unsupported, {}, "Zydis could not initialize for this x86 context"};
    ZydisDecodedInstruction decoded{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
    const auto status = ZydisDecoderDecodeFull(&decoder, bytes.data(), bytes.size(), &decoded, operands.data());
    if (!ZYAN_SUCCESS(status)) {
        if (status == ZYDIS_STATUS_NO_MORE_DATA)
            return {DecodeStatus::truncated, {}, "Truncated x86 instruction"};
        return {DecodeStatus::unsupported, {}, "No supported x86 instruction encoding"};
    }

    ZydisFormatter formatter{};
    std::array<char, 256> text{};
    if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)) ||
        !ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter, &decoded, operands.data(), decoded.operand_count_visible,
                                                      text.data(), text.size(), address.offset, nullptr)))
        return {DecodeStatus::unsupported, {}, "Zydis could not format the decoded x86 instruction"};

    Instruction instruction;
    instruction.context = context;
    instruction.address = address;
    instruction.length = decoded.length;
    instruction.opcode = Opcode::x86_opaque;
    instruction.mnemonic_override = text.data();
    std::copy_n(bytes.begin(), decoded.length, instruction.bytes.begin());
    switch (decoded.meta.category) {
    case ZYDIS_CATEGORY_CALL: instruction.flow = FlowKind::call; break;
    case ZYDIS_CATEGORY_COND_BR: instruction.flow = FlowKind::conditional_branch; break;
    case ZYDIS_CATEGORY_UNCOND_BR: instruction.flow = FlowKind::jump; break;
    case ZYDIS_CATEGORY_RET: instruction.flow = FlowKind::ret; break;
    case ZYDIS_CATEGORY_INTERRUPT: instruction.flow = FlowKind::trap; break;
    default: instruction.flow = FlowKind::fallthrough; break;
    }
    return {DecodeStatus::decoded, std::move(instruction), {}};
}
} // namespace hexlab::x64_detail
