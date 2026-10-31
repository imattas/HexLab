#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <algorithm>
#include <utility>
#include <vector>

using namespace hexlab;
using namespace hexlab_test;

namespace {
constexpr DecodeContext x64{Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little};
constexpr DecodeContext x32{Architecture::x86, ExecutionMode::x86_32, ByteOrder::little};

DecodeResult decode(DecodeContext context, const std::vector<std::byte> &input, Address at = {{0}, 0x1000}) {
    if (context.mode == ExecutionMode::x86_64)
        return decode_x64(input, at);
    if (context.mode == ExecutionMode::x86_16)
        return decode_x86_16(input, at);
    return decode_x86_32(input, at);
}
DecodeResult decode(DecodeContext context, std::initializer_list<unsigned> bytes_, Address at = {{0}, 0x1000}) {
    const auto input = bytes(bytes_);
    return decode(context, input, at);
}

bool has(std::span<const RegisterOperand> registers, RegisterOperand value) {
    return std::find(registers.begin(), registers.end(), value) != registers.end();
}

void packed_forms() {
    auto result = decode(x64, {0x66, 0x0f, 0xfe, 0xc1});
    check(result.status == DecodeStatus::decoded && result.instruction, "PADD D decodes");
    if (!result.instruction)
        return;
    const auto &paddd = *result.instruction;
    check(paddd.opcode == Opcode::paddd && paddd.length == 4 &&
              std::get<RegisterOperand>(paddd.operands[0]) == RegisterOperand{RegisterBank::xmm, 0, 128, false} &&
              std::get<RegisterOperand>(paddd.operands[1]) == RegisterOperand{RegisterBank::xmm, 1, 128, false},
          "PADD D operands are typed 128-bit XMM registers");
    check(paddd.access == std::vector{OperandAccess::read_write, OperandAccess::read} &&
              has(paddd.register_reads, {RegisterBank::xmm, 0, 128, false}) &&
              has(paddd.register_reads, {RegisterBank::xmm, 1, 128, false}) &&
              has(paddd.register_writes, {RegisterBank::xmm, 0, 128, false}) && !paddd.memory_read &&
              !paddd.memory_write,
          "packed arithmetic records destination read/write and source read effects");
    check(format_instruction(paddd) == "paddd xmm0, xmm1", "PADD D formatting names both XMM operands");

    result = decode(x64, {0x66, 0x0f, 0xd4, 0x05, 0x20, 0, 0, 0});
    check(result.instruction && result.instruction->opcode == Opcode::paddq,
          "PADD Q memory form decodes");
    if (result.instruction) {
        const auto &paddq = *result.instruction;
        const auto &memory = std::get<MemoryOperand>(paddq.operands[1]);
        check(memory.data_width == 128 && memory.address_width == 64 && memory.ip_relative &&
                  memory.resolved_address == Address{{0}, 0x1028} && paddq.memory_read && !paddq.memory_write,
              "packed memory source is 128-bit and retains RIP-relative address effects");
    }

    result = decode(x64, {0x66, 0x0f, 0x7f, 0x08});
    check(result.instruction && result.instruction->opcode == Opcode::movdqa,
          "MOVDQA store form decodes");
    if (result.instruction) {
        const auto &mov = *result.instruction;
        check(std::holds_alternative<MemoryOperand>(mov.operands[0]) &&
                  std::get<MemoryOperand>(mov.operands[0]).data_width == 128 &&
                  std::get<RegisterOperand>(mov.operands[1]) == RegisterOperand{RegisterBank::xmm, 1, 128, false} &&
                  mov.memory_write && !mov.memory_read &&
                  mov.access == std::vector{OperandAccess::write, OperandAccess::read},
              "MOVDQA store has correctly directed 128-bit memory effects");
    }

    result = decode(x64, {0xf3, 0x0f, 0x6f, 0x04, 0x24});
    check(result.instruction && result.instruction->opcode == Opcode::movdqu,
          "MOVDQU load form decodes");
    if (result.instruction) {
        const auto &mov = *result.instruction;
        const auto &memory = std::get<MemoryOperand>(mov.operands[1]);
        check(memory.data_width == 128 && memory.base == RegisterOperand{RegisterBank::gpr, 4, 64, false} &&
                  mov.memory_read && !mov.memory_write && format_instruction(mov) == "movdqu xmm0, xmmword ptr [rsp]",
              "MOVDQU load preserves SIB stack addressing and 128-bit width");
    }

    const std::vector<std::pair<std::vector<std::byte>, Opcode>> packed_ops{
        {bytes({0x66, 0x0f, 0xfa, 0xc1}), Opcode::psubd},
        {bytes({0x66, 0x0f, 0xfb, 0xc1}), Opcode::psubq},
        {bytes({0x66, 0x0f, 0xdb, 0xc1}), Opcode::pand},
        {bytes({0x66, 0x0f, 0xeb, 0xc1}), Opcode::por},
        {bytes({0x66, 0x0f, 0xef, 0xc1}), Opcode::pxor}};
    for (const auto &[encoding, expected] : packed_ops) {
        result = decode(x64, encoding);
        check(result.instruction && result.instruction->opcode == expected,
              "packed integer operations decode to their distinct typed opcode");
    }

    const std::vector<std::pair<std::vector<std::byte>, std::string>> compares{
        {bytes({0x66, 0x0f, 0x74, 0xc1}), "pcmpeqb"},
        {bytes({0x66, 0x0f, 0x75, 0xc1}), "pcmpeqw"},
        {bytes({0x66, 0x0f, 0x76, 0xc1}), "pcmpeqd"},
        {bytes({0x66, 0x0f, 0x64, 0xc1}), "pcmpgtb"},
        {bytes({0x66, 0x0f, 0x65, 0xc1}), "pcmpgtw"},
        {bytes({0x66, 0x0f, 0x66, 0xc1}), "pcmpgtd"},
    };
    for (const auto &[encoding, expected] : compares) {
        result = decode(x64, encoding);
        check(result.instruction && opcode_name(result.instruction->opcode) == expected &&
                  result.instruction->access == std::vector{OperandAccess::read_write, OperandAccess::read} &&
                  has(result.instruction->register_reads, {RegisterBank::xmm, 0, 128, false}) &&
                  has(result.instruction->register_reads, {RegisterBank::xmm, 1, 128, false}) &&
                  has(result.instruction->register_writes, {RegisterBank::xmm, 0, 128, false}) &&
                  !has(result.instruction->register_reads, {RegisterBank::flags, 0, 64, false}) &&
                  !has(result.instruction->register_writes, {RegisterBank::flags, 0, 64, false}) &&
                  format_instruction(*result.instruction) == expected + " xmm0, xmm1",
              "packed compare decodes with a typed destructive XMM destination and stable rendering");
    }
    result = decode(x64, {0x66, 0x0f, 0x76, 0x05, 0x20, 0, 0, 0});
    check(result.instruction && opcode_name(result.instruction->opcode) == "pcmpeqd" &&
              std::get<MemoryOperand>(result.instruction->operands[1]).data_width == 128 &&
              result.instruction->memory_read && !result.instruction->memory_write,
          "packed compare memory source records a full-vector read only");
    result = decode(x32, {0x66, 0x0f, 0x74, 0xc1});
    check(result.instruction && opcode_name(result.instruction->opcode) == "pcmpeqb",
          "packed compare is available through the shared 32-bit decoder");
    result = decode({Architecture::x86, ExecutionMode::x86_16, ByteOrder::little},
                    {0x66, 0x0f, 0x65, 0xc1});
    check(result.instruction && opcode_name(result.instruction->opcode) == "pcmpgtw",
          "packed compare is available through the shared 16-bit decoder");
}

void scalar_forms() {
    auto result = decode(x64, {0xf3, 0x0f, 0x10, 0x05, 0x20, 0, 0, 0});
    check(result.instruction && result.instruction->opcode == Opcode::movss,
          "MOVSS memory load decodes");
    if (result.instruction) {
        const auto &mov = *result.instruction;
        const auto &memory = std::get<MemoryOperand>(mov.operands[1]);
        check(memory.data_width == 32 && mov.memory_read && !mov.memory_write &&
                  mov.access == std::vector{OperandAccess::write, OperandAccess::read},
              "MOVSS uses scalar 32-bit memory and load effects");
    }

    result = decode(x64, {0xf2, 0x0f, 0x11, 0x08});
    check(result.instruction && result.instruction->opcode == Opcode::movsd,
          "MOVSD memory store decodes");
    if (result.instruction) {
        const auto &mov = *result.instruction;
        check(std::get<MemoryOperand>(mov.operands[0]).data_width == 64 && mov.memory_write &&
                  !mov.memory_read && format_instruction(mov) == "movsd qword ptr [rax], xmm1",
              "MOVSD uses scalar 64-bit memory and store effects");
    }

    const std::vector<std::pair<std::vector<std::byte>, Opcode>> scalar_ops{
        {bytes({0xf3, 0x0f, 0x58, 0xc1}), Opcode::addss},
        {bytes({0xf2, 0x0f, 0x58, 0xc1}), Opcode::addsd},
        {bytes({0xf3, 0x0f, 0x5c, 0xc1}), Opcode::subss},
        {bytes({0xf2, 0x0f, 0x5c, 0xc1}), Opcode::subsd},
        {bytes({0xf3, 0x0f, 0x59, 0xc1}), Opcode::mulss},
        {bytes({0xf2, 0x0f, 0x59, 0xc1}), Opcode::mulsd},
        {bytes({0xf3, 0x0f, 0x5e, 0xc1}), Opcode::divss},
        {bytes({0xf2, 0x0f, 0x5e, 0xc1}), Opcode::divsd}};
    for (const auto &[encoding, expected] : scalar_ops) {
        result = decode(x64, encoding);
        check(result.instruction && result.instruction->opcode == expected &&
                  result.instruction->access == std::vector{OperandAccess::read_write, OperandAccess::read},
              "scalar floating operation preserves precision and read/write access");
    }
}

void mode_and_prefix_boundaries() {
    auto result = decode(x32, {0x66, 0x0f, 0xfe, 0xc1});
    check(result.instruction && result.instruction->opcode == Opcode::paddd &&
              std::get<RegisterOperand>(result.instruction->operands[0]).bank == RegisterBank::xmm,
          "SSE2 packed integer form decodes in legacy 32-bit mode");
    result = decode({Architecture::x86, ExecutionMode::x86_16, ByteOrder::little},
                    {0x66, 0x0f, 0xfe, 0xc1});
    check(result.instruction && result.instruction->opcode == Opcode::paddd,
          "SSE2 packed integer form decodes in legacy 16-bit mode");

    result = decode(x64, {0x66, 0x45, 0x0f, 0xfe, 0xc1});
    check(result.instruction &&
              std::get<RegisterOperand>(result.instruction->operands[0]) == RegisterOperand{RegisterBank::xmm, 8, 128, false} &&
              std::get<RegisterOperand>(result.instruction->operands[1]) == RegisterOperand{RegisterBank::xmm, 9, 128, false},
          "REX.R and REX.B select XMM8 and XMM9 in long mode");

    result = decode(x64, {0xf3, 0x44, 0x0f, 0x58, 0xc1});
    check(result.instruction &&
              std::get<RegisterOperand>(result.instruction->operands[0]) == RegisterOperand{RegisterBank::xmm, 8, 128, false},
          "REX.R remains effective when placed after the mandatory legacy prefix");

    result = decode(x64, {0x66, 0xf3, 0x0f, 0xfe, 0xc1});
    check(result.status == DecodeStatus::invalid && !result.instruction,
          "conflicting mandatory packed prefixes are invalid");
    result = decode(x64, {0xf2, 0x0f, 0xfe, 0xc1});
    check(result.status == DecodeStatus::invalid && !result.instruction,
          "wrong group-one prefix on a packed operation is invalid");
    result = decode(x64, {0xf0, 0x66, 0x0f, 0x74, 0xc1});
    check(result.status == DecodeStatus::invalid && !result.instruction,
          "LOCK is rejected for a register-destination packed compare");
    result = decode(x64, {0x0f, 0x58, 0xc1});
    check(result.status == DecodeStatus::unsupported && !result.instruction,
          "unimplemented packed floating ADDPS stays unsupported");
    result = decode(x32, {0x44, 0x0f, 0xfe, 0xc1});
    check(result.instruction && result.instruction->opcode == Opcode::inc && result.instruction->length == 1,
          "legacy x86 treats a REX-looking byte as its one-byte INC instruction");
}

void truncation_and_formatting() {
    const std::vector<std::vector<std::byte>> truncated_forms{
        bytes({0x66, 0x0f}), bytes({0x66, 0x0f, 0xfe}), bytes({0x66, 0x0f, 0xfe, 0x04}),
        bytes({0x66, 0x0f, 0xfe, 0x05, 0, 0}), bytes({0x66, 0x0f, 0x74})};
    for (const auto &bytes_ : truncated_forms) {
        const auto result = decode(x64, bytes_);
        check(result.status == DecodeStatus::truncated && !result.instruction,
              "truncated SIMD opcode, ModRM, SIB, and displacement are reported distinctly");
    }
    check(register_name({RegisterBank::xmm, 15, 128, false}) == "xmm15",
          "XMM register formatting supports the highest long-mode register");
}

void vex_avx_forms() {
    auto result = decode(x64, {0xc5, 0xf8, 0x58, 0xc1}); // vaddps xmm0,xmm0,xmm1
    check(result.instruction && result.instruction->opcode == Opcode::vaddps && result.instruction->length == 4 &&
              result.instruction->access == std::vector{OperandAccess::write, OperandAccess::read, OperandAccess::read} &&
              std::get<RegisterOperand>(result.instruction->operands[0]) == RegisterOperand{RegisterBank::xmm, 0, 128, false} &&
              has(result.instruction->register_reads, {RegisterBank::xmm, 0, 128, false}) &&
              has(result.instruction->register_reads, {RegisterBank::xmm, 1, 128, false}) &&
              has(result.instruction->register_writes, {RegisterBank::xmm, 0, 128, false}),
          "VEX.128 VADDPS decodes three typed operands with non-destructive destination effects");
    if (result.instruction)
        check(format_instruction(*result.instruction) == "vaddps xmm0, xmm0, xmm1",
              "VEX arithmetic formatting preserves three-operand order");
    result = decode(x64, {0xc5, 0xfd, 0x59, 0x44, 0x8b, 0x10}); // vmulpd ymm0,ymm0,[rbx+rcx*4+10h]
    check(result.instruction && result.instruction->opcode == Opcode::vmulpd && result.instruction->length == 6 &&
              std::get<RegisterOperand>(result.instruction->operands[0]) == RegisterOperand{RegisterBank::ymm, 0, 256, false} &&
              std::get<MemoryOperand>(result.instruction->operands[2]).data_width == 256 && result.instruction->memory_read,
          "VEX.256 VMULPD validates L, operand width, memory addressing, and exact length");
    result = decode(x64, {0xc5, 0xf8, 0x10, 0x05, 0x20, 0, 0, 0});
    check(result.instruction && result.instruction->opcode == Opcode::vmovups && result.instruction->length == 8 &&
              std::get<MemoryOperand>(result.instruction->operands[1]).data_width == 128 &&
              result.instruction->memory_read && !result.instruction->memory_write,
          "VEX.128 VMOVUPS load has vector-sized memory effects");
    result = decode(x64, {0x67, 0xc5, 0xf8, 0x10, 0x00});
    check(result.instruction && result.instruction->opcode == Opcode::vmovups && result.instruction->length == 5 &&
              std::get<MemoryOperand>(result.instruction->operands[1]).address_width == 32 &&
              std::get<MemoryOperand>(result.instruction->operands[1]).base == RegisterOperand{RegisterBank::gpr, 0, 32, false},
          "VEX accepts address-size override and preserves 32-bit memory addressing");
    result = decode(x64, {0xc5, 0xfc, 0x11, 0x08});
    check(result.instruction && result.instruction->opcode == Opcode::vmovups &&
              std::get<MemoryOperand>(result.instruction->operands[0]).data_width == 256 &&
              result.instruction->memory_write && !result.instruction->memory_read,
          "VEX.256 VMOVUPS store directs the 256-bit memory write");

    const std::vector<std::pair<std::vector<std::byte>, Opcode>> operations{
        {bytes({0xc5, 0xf8, 0x58, 0xc1}), Opcode::vaddps}, {bytes({0xc5, 0xf9, 0x58, 0xc1}), Opcode::vaddpd},
        {bytes({0xc5, 0xf8, 0x5c, 0xc1}), Opcode::vsubps}, {bytes({0xc5, 0xf9, 0x5c, 0xc1}), Opcode::vsubpd},
        {bytes({0xc5, 0xf8, 0x59, 0xc1}), Opcode::vmulps}, {bytes({0xc5, 0xf9, 0x59, 0xc1}), Opcode::vmulpd},
        {bytes({0xc5, 0xf8, 0x57, 0xc1}), Opcode::vxorps}, {bytes({0xc5, 0xf9, 0x57, 0xc1}), Opcode::vxorpd},
        {bytes({0xc5, 0xf8, 0x54, 0xc1}), Opcode::vandps}, {bytes({0xc5, 0xf9, 0x54, 0xc1}), Opcode::vandpd}};
    for (const auto &[encoding, opcode] : operations) {
        result = decode(x64, encoding);
        check(result.instruction && result.instruction->opcode == opcode,
              "VEX map/pp selection decodes the selected packed arithmetic/logical operation");
    }
    result = decode(x64, {0xc5, 0x78, 0x58, 0xc1});
    check(result.instruction && result.instruction->opcode == Opcode::vaddps &&
              std::get<RegisterOperand>(result.instruction->operands[0]) == RegisterOperand{RegisterBank::xmm, 8, 128, false},
          "VEX.R extends ModRM.reg while vvvv remains a distinct source");
    result = decode(x64, {0xc4, 0x61, 0x78, 0x58, 0xc1});
    check(result.instruction && result.instruction->opcode == Opcode::vaddps &&
              std::get<RegisterOperand>(result.instruction->operands[0]) == RegisterOperand{RegisterBank::xmm, 8, 128, false} &&
              result.instruction->length == 5,
          "VEX3 map-1 parsing applies R extension and exact prefix length");
    result = decode(x64, {0xc4, 0xe1, 0xf8, 0x58, 0xc1});
    check(result.instruction && result.instruction->opcode == Opcode::vaddps && result.instruction->length == 5,
          "VEX.W is accepted as ignored for the selected WIG packed floating forms");
    result = decode(x64, {0xc5, 0xe8, 0x58, 0xc1});
    check(result.instruction &&
              std::get<RegisterOperand>(result.instruction->operands[1]) == RegisterOperand{RegisterBank::xmm, 2, 128, false},
          "inverted VEX.vvvv selects the encoded third source register");
    result = decode(x64, {0xc5, 0xfa, 0x58, 0xc1});
    check(result.status == DecodeStatus::invalid && !result.instruction,
          "reserved VEX.pp values are rejected rather than aliased");
    result = decode(x64, {0xc5, 0xf0, 0x10, 0xc1});
    check(result.status == DecodeStatus::invalid && !result.instruction,
          "VMOVUPS rejects a non-reserved VEX.vvvv field");
    result = decode(x64, {0x66, 0xc5, 0xf8, 0x58, 0xc1});
    check(result.status == DecodeStatus::invalid && !result.instruction,
          "legacy mandatory prefixes preceding VEX are invalid");
    result = decode(x64, {0x48, 0xc5, 0xf8, 0x58, 0xc1});
    check(result.status == DecodeStatus::invalid && !result.instruction,
          "REX preceding VEX is invalid");
    result = decode(x64, {0xc4, 0xe0, 0x78, 0x58, 0xc1});
    check(result.status == DecodeStatus::invalid && !result.instruction,
          "VEX map zero is rejected");
    result = decode(x64, {0xc4, 0xe2, 0x78, 0x58, 0xc1});
    check(result.status == DecodeStatus::unsupported && !result.instruction,
          "unsupported VEX opcode map is not misdecoded as an instruction");
    result = decode(x64, {0xc5, 0xf8, 0x58});
    check(result.status == DecodeStatus::truncated && !result.instruction, "truncated VEX opcode is reported");

    const std::vector<std::pair<unsigned, Opcode>> evex_unpack = {
        {0x60, Opcode::vpunpcklbw}, {0x61, Opcode::vpunpcklwd},
        {0x62, Opcode::vpunpckldq}, {0x6c, Opcode::vpunpcklqdq},
        {0x68, Opcode::vpunpckhbw}, {0x69, Opcode::vpunpckhwd},
        {0x6a, Opcode::vpunpckhdq}, {0x6d, Opcode::vpunpckhqdq}};
    for (const auto &[opcode_byte, opcode] : evex_unpack) {
        result = decode(x64, {0x62, 0xf1, 0x7d, 0x49, opcode_byte, 0xc1});
        check(result.instruction && result.instruction->opcode == opcode &&
                  result.instruction->x86_evex && result.instruction->vector_bits == 512 &&
                  result.instruction->operands.size() == 3 &&
                  result.instruction->access == std::vector{OperandAccess::read_write, OperandAccess::read,
                                                             OperandAccess::read} &&
                  result.instruction->x86_opmask == 1 && !result.instruction->x86_opmask_zeroing &&
                  std::find(result.instruction->register_reads.begin(), result.instruction->register_reads.end(),
                            RegisterOperand{RegisterBank::opmask, 1, 64, false}) != result.instruction->register_reads.end(),
              "EVEX unpack models three-operand ZMM dataflow and merging writemask reads");
    }
}

} // namespace

int main() {
    return run([] {
        packed_forms();
        scalar_forms();
        mode_and_prefix_boundaries();
        truncation_and_formatting();
        vex_avx_forms();
    });
}
